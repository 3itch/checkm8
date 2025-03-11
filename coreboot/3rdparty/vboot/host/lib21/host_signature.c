/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host functions for signatures.
 */

#include <openssl/rsa.h>

#include "2common.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_misc.h"
#include "host_p11.h"
#include "host_signature21.h"

vb2_error_t vb2_digest_info(enum vb2_hash_algorithm hash_alg,
			    const uint8_t **buf_ptr, uint32_t *size_ptr)
{
	*buf_ptr = NULL;
	*size_ptr = 0;

	switch (hash_alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		{
			static const uint8_t info[] = {
				0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
				0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
			};
			*buf_ptr = info;
			*size_ptr = sizeof(info);
			return VB2_SUCCESS;
		}
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA256:
		{
			static const uint8_t info[] = {
				0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
				0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
				0x00, 0x04, 0x20
			};
			*buf_ptr = info;
			*size_ptr = sizeof(info);
			return VB2_SUCCESS;
		}
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA512:
		{
			static const uint8_t info[] = {
				0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
				0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
				0x00, 0x04, 0x40
			};
			*buf_ptr = info;
			*size_ptr = sizeof(info);
			return VB2_SUCCESS;
		}
#endif
	default:
		return VB2_ERROR_DIGEST_INFO;
	}
}

vb2_error_t vb21_sign_data(struct vb21_signature **sig_ptr, const uint8_t *data,
			   uint32_t size, const struct vb2_private_key *key,
			   const char *desc)
{
	struct vb21_signature s = {
		.c.magic = VB21_MAGIC_SIGNATURE,
		.c.struct_version_major = VB21_SIGNATURE_VERSION_MAJOR,
		.c.struct_version_minor = VB21_SIGNATURE_VERSION_MINOR,
		.c.fixed_size = sizeof(s),
		.sig_alg = key->sig_alg,
		.hash_alg = key->hash_alg,
		.data_size = size,
		.id = key->id,
	};

	vb2_error_t rv;
	struct vb2_digest_context dc;
	uint32_t digest_size;
	const uint8_t *info = NULL;
	uint32_t info_size = 0;
	uint32_t sig_digest_size;
	uint8_t *sig_digest = NULL;
	uint8_t *buf = NULL;

	*sig_ptr = NULL;

	/* Use key description if no description supplied */
	if (!desc)
		desc = key->desc;

	s.c.desc_size = vb2_desc_size(desc);

	s.sig_offset = s.c.fixed_size + s.c.desc_size;
	s.sig_size = vb2_sig_size(key->sig_alg, key->hash_alg);
	if (!s.sig_size) {
		rv = VB2_SIGN_DATA_SIG_SIZE;
		goto done;
	}

	s.c.total_size = s.sig_offset + s.sig_size;
	/* Allocate signature buffer and copy header */
	buf = calloc(1, s.c.total_size);
	if (!buf) {
		rv = VB2_ERROR_UNKNOWN;
		goto done;
	}
	memcpy(buf, &s, sizeof(s));

	/* strcpy() is ok because we allocated buffer based on desc length */
	if (desc)
		strcpy((char *)buf + s.c.fixed_size, desc);

	/* If it is PKCS11#11 key, we could sign with pkcs11_sign instead */
	if (key->key_location == PRIVATE_KEY_P11) {
		/* RSA-encrypt the signature */
		rv = pkcs11_sign(key->p11_key, key->hash_alg, data, size,
				 buf + s.sig_offset, s.sig_size);
		goto done;
	}

	/* Determine digest size and allocate buffer */
	if (s.sig_alg != VB2_SIG_NONE) {
		if (vb2_digest_info(s.hash_alg, &info, &info_size)) {
			rv = VB2_SIGN_DATA_DIGEST_INFO;
			goto done;
		}
	}

	digest_size = vb2_digest_size(key->hash_alg);
	if (!digest_size) {
		rv = VB2_SIGN_DATA_DIGEST_SIZE;
		goto done;
	}

	sig_digest_size = info_size + digest_size;
	sig_digest = malloc(sig_digest_size);
	if (!sig_digest) {
		rv = VB2_SIGN_DATA_DIGEST_ALLOC;
		goto done;
	}

	/* Prepend digest info, if any */
	if (info_size)
		memcpy(sig_digest, info, info_size);

	/* Calculate hash digest */
	if (vb2_digest_init(&dc, false, s.hash_alg, 0)) {
		rv = VB2_SIGN_DATA_DIGEST_INIT;
		goto done;
	}

	if (vb2_digest_extend(&dc, data, size)) {
		rv = VB2_SIGN_DATA_DIGEST_EXTEND;
		goto done;
	}

	if (vb2_digest_finalize(&dc, sig_digest + info_size, digest_size)) {
		rv = VB2_SIGN_DATA_DIGEST_FINALIZE;
		goto done;
	}

	if (s.sig_alg == VB2_SIG_NONE) {
		/* Bare hash signature is just the digest */
		memcpy(buf + s.sig_offset, sig_digest, sig_digest_size);
	} else {
		/* RSA-encrypt the signature */
		if (RSA_private_encrypt(sig_digest_size,
					sig_digest,
					buf + s.sig_offset,
					key->rsa_private_key,
					RSA_PKCS1_PADDING) == -1) {
			rv = VB2_SIGN_DATA_RSA_ENCRYPT;
			goto done;
		}
	}
	rv = VB2_SUCCESS;
done:
	free(sig_digest);
	if (rv == VB2_SUCCESS)
		*sig_ptr = (struct vb21_signature *)buf;
	else
		free(buf);
	return rv;
}

vb2_error_t vb21_sig_size_for_key(uint32_t *size_ptr,
				  const struct vb2_private_key *key,
				  const char *desc)
{
	uint32_t size = vb2_sig_size(key->sig_alg, key->hash_alg);

	if (!size)
		return VB2_ERROR_SIG_SIZE_FOR_KEY;

	size += sizeof(struct vb21_signature);
	size += vb2_desc_size(desc ? desc : key->desc);

	*size_ptr = size;
	return VB2_SUCCESS;
}

vb2_error_t vb21_sig_size_for_keys(uint32_t *size_ptr,
				   const struct vb2_private_key **key_list,
				   uint32_t key_count)
{
	uint32_t total = 0, size = 0;
	vb2_error_t rv, i;

	*size_ptr = 0;

	for (i = 0; i < key_count; i++) {
		rv = vb21_sig_size_for_key(&size, key_list[i], NULL);
		if (rv)
			return rv;
		total += size;
	}

	*size_ptr = total;
	return VB2_SUCCESS;
}

vb2_error_t vb21_sign_object(uint8_t *buf, uint32_t sig_offset,
			     const struct vb2_private_key *key,
			     const char *desc)
{
	struct vb21_struct_common *c = (struct vb21_struct_common *)buf;
	struct vb21_signature *sig = NULL;
	vb2_error_t rv;

	rv = vb21_sign_data(&sig, buf, sig_offset, key, desc);
	if (rv)
		return rv;

	if (sig_offset + sig->c.total_size > c->total_size) {
		free(sig);
		return VB2_SIGN_OBJECT_OVERFLOW;
	}

	memcpy(buf + sig_offset, sig, sig->c.total_size);
	free(sig);

	return VB2_SUCCESS;
}

vb2_error_t vb21_sign_object_multiple(uint8_t *buf, uint32_t sig_offset,
				      const struct vb2_private_key **key_list,
				      uint32_t key_count)
{
	struct vb21_struct_common *c = (struct vb21_struct_common *)buf;
	uint32_t sig_next = sig_offset;
	vb2_error_t rv, i;

	for (i = 0; i < key_count; i++)	{
		struct vb21_signature *sig = NULL;

		rv = vb21_sign_data(&sig, buf, sig_offset, key_list[i], NULL);
		if (rv)
			return rv;

		if (sig_next + sig->c.total_size > c->total_size) {
			free(sig);
			return VB2_SIGN_OBJECT_OVERFLOW;
		}

		memcpy(buf + sig_next, sig, sig->c.total_size);
		sig_next += sig->c.total_size;
		free(sig);
	}

	return VB2_SUCCESS;
}
