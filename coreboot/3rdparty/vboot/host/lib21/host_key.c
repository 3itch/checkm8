/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host functions for keys.
 */

#include <stdio.h>

#include <openssl/pem.h>

#include "2common.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_misc.h"
#include "host_p11.h"
#include "openssl_compat.h"
#include "util_misc.h"

vb2_error_t vb21_private_key_unpack_raw(const uint8_t *buf, uint32_t size,
					       struct vb2_private_key *key)
{
	const struct vb21_packed_private_key *pkey =
		(const struct vb21_packed_private_key *)buf;
	const unsigned char *start;
	uint32_t min_offset = 0;

	/*
	 * Check magic number.
	 *
	 * TODO: If it doesn't match, pass through to the old packed key format.
	 */
	if (pkey->c.magic != VB21_MAGIC_PACKED_PRIVATE_KEY)
		return VB2_ERROR_UNPACK_PRIVATE_KEY_MAGIC;

	if (vb21_verify_common_header(buf, size))
		return VB2_ERROR_UNPACK_PRIVATE_KEY_HEADER;

	/* Make sure key data is inside */
	if (vb21_verify_common_member(pkey, &min_offset,
				     pkey->key_offset, pkey->key_size))
		return VB2_ERROR_UNPACK_PRIVATE_KEY_DATA;

	/*
	 * Check for compatible version.  No need to check minor version, since
	 * that's compatible across readers matching the major version, and we
	 * haven't added any new fields.
	 */
	if (pkey->c.struct_version_major !=
	    VB21_PACKED_PRIVATE_KEY_VERSION_MAJOR)
		return VB2_ERROR_UNPACK_PRIVATE_KEY_STRUCT_VERSION;

	/* Copy key algorithms and ID */
	key->key_location = PRIVATE_KEY_LOCAL;
	key->sig_alg = pkey->sig_alg;
	key->hash_alg = pkey->hash_alg;
	key->id = pkey->id;

	/* Unpack RSA key */
	if (pkey->sig_alg == VB2_SIG_NONE) {
		if (pkey->key_size != 0)
			return VB2_ERROR_UNPACK_PRIVATE_KEY_HASH;
	} else {
		start = (const unsigned char *)(buf + pkey->key_offset);
		key->rsa_private_key = d2i_RSAPrivateKey(0, &start,
							 pkey->key_size);
		if (!key->rsa_private_key)
			return VB2_ERROR_UNPACK_PRIVATE_KEY_RSA;
	}

	/* Key description */
	if (pkey->c.desc_size) {
		if (vb2_private_key_set_desc(key, (const char *)(buf + pkey->c.fixed_size)))
			return VB2_ERROR_UNPACK_PRIVATE_KEY_DESC;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb21_private_key_unpack(struct vb2_private_key **key_ptr, const uint8_t *buf,
				    uint32_t size)
{
	*key_ptr = NULL;
	struct vb2_private_key *key = (struct vb2_private_key *)calloc(sizeof(*key), 1);
	if (!key)
		return VB2_ERROR_UNPACK_PRIVATE_KEY_ALLOC;

	vb2_error_t rv = vb21_private_key_unpack_raw(buf, size, key);
	if (rv != VB2_SUCCESS) {
		vb2_free_private_key(key);
		return rv;
	}
	*key_ptr = key;
	return VB2_SUCCESS;
}

vb2_error_t vb2_private_key_read_pem(struct vb2_private_key **key_ptr,
				     const char *filename)
{
	struct vb2_private_key *key;
	FILE *f;

	*key_ptr = NULL;

	/* Allocate the new key */
	key = calloc(1, sizeof(*key));
	if (!key)
		return VB2_ERROR_READ_PEM_ALLOC;

	/* Read private key */
	f = fopen(filename, "rb");
	if (!f) {
		free(key);
		return VB2_ERROR_READ_PEM_FILE_OPEN;
	}

	key->rsa_private_key = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	fclose(f);

	if (!key->rsa_private_key) {
		free(key);
		return VB2_ERROR_READ_PEM_RSA;
	}

	*key_ptr = key;
	return VB2_SUCCESS;
}

vb2_error_t vb2_private_key_set_desc(struct vb2_private_key *key,
				     const char *desc)
{
	if (key->desc)
		free(key->desc);

	if (desc) {
		key->desc = strdup(desc);
		if (!key->desc)
			return VB2_ERROR_PRIVATE_KEY_SET_DESC;
	} else {
		key->desc = NULL;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb21_private_key_write(const struct vb2_private_key *key,
				   const char *filename)
{
	struct vb21_packed_private_key pkey = {
		.c.magic = VB21_MAGIC_PACKED_PRIVATE_KEY,
		.c.struct_version_major = VB21_PACKED_PRIVATE_KEY_VERSION_MAJOR,
		.c.struct_version_minor = VB21_PACKED_PRIVATE_KEY_VERSION_MINOR,
		.c.fixed_size = sizeof(pkey),
		.sig_alg = key->sig_alg,
		.hash_alg = key->hash_alg,
		.id = key->id,
	};
	uint8_t *buf;
	uint8_t *rsabuf = NULL;
	int rsalen = 0;
	vb2_error_t rv;

	memcpy(&pkey.id, &key->id, sizeof(pkey.id));

	pkey.c.desc_size = vb2_desc_size(key->desc);

	if (key->sig_alg != VB2_SIG_NONE) {
		/* Pack RSA key */
		rsalen = i2d_RSAPrivateKey(key->rsa_private_key, &rsabuf);
		if (rsalen <= 0 || !rsabuf)
			return VB2_ERROR_PRIVATE_KEY_WRITE_RSA;
	}

	pkey.key_offset = pkey.c.fixed_size + pkey.c.desc_size;
	pkey.key_size = roundup32(rsalen);
	pkey.c.total_size = pkey.key_offset + pkey.key_size;

	/* Pack private key */
	buf = calloc(1, pkey.c.total_size);
	if (!buf) {
		free(rsabuf);
		return VB2_ERROR_PRIVATE_KEY_WRITE_ALLOC;
	}

	memcpy(buf, &pkey, sizeof(pkey));

	/* strcpy() is ok here because we checked the length above */
	if (pkey.c.desc_size)
		strcpy((char *)buf + pkey.c.fixed_size, key->desc);

	if (rsabuf) {
		memcpy(buf + pkey.key_offset, rsabuf, rsalen);
		free(rsabuf);
	}

	rv = vb21_write_object(filename, buf);
	free(buf);

	return rv ? VB2_ERROR_PRIVATE_KEY_WRITE_FILE : VB2_SUCCESS;
}

vb2_error_t vb2_private_key_hash(const struct vb2_private_key **key_ptr,
				 enum vb2_hash_algorithm hash_alg)
{
	*key_ptr = NULL;

	switch (hash_alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		{
			static const struct vb2_private_key key = {
				.hash_alg = VB2_HASH_SHA1,
				.sig_alg = VB2_SIG_NONE,
				.desc = (char *)"Unsigned SHA1",
				.id = VB2_ID_NONE_SHA1,
			};
			*key_ptr = &key;
			return VB2_SUCCESS;
		}
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA256:
		{
			static const struct vb2_private_key key = {
				.hash_alg = VB2_HASH_SHA256,
				.sig_alg = VB2_SIG_NONE,
				.desc = (char *)"Unsigned SHA-256",
				.id = VB2_ID_NONE_SHA256,
			};
			*key_ptr = &key;
			return VB2_SUCCESS;
		}
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA512:
		{
			static const struct vb2_private_key key = {
				.hash_alg = VB2_HASH_SHA512,
				.sig_alg = VB2_SIG_NONE,
				.desc = (char *)"Unsigned SHA-512",
				.id = VB2_ID_NONE_SHA512,
			};
			*key_ptr = &key;
			return VB2_SUCCESS;
		}
#endif
	default:
		return VB2_ERROR_PRIVATE_KEY_HASH;
	}
}

vb2_error_t vb2_public_key_alloc(struct vb2_public_key **key_ptr,
				 enum vb2_signature_algorithm sig_alg)
{
	struct vb2_public_key *key;
	uint32_t key_data_size = vb2_packed_key_size(sig_alg);

	/* The buffer contains the key, its ID, and its packed data */
	uint32_t buf_size = sizeof(*key) + sizeof(struct vb2_id) +
		key_data_size;

	if (!key_data_size)
		return VB2_ERROR_PUBLIC_KEY_ALLOC_SIZE;

	key = calloc(1, buf_size);
	if (!key)
		return VB2_ERROR_PUBLIC_KEY_ALLOC;

	key->id = (struct vb2_id *)(key + 1);
	key->sig_alg = sig_alg;

	*key_ptr = key;

	return VB2_SUCCESS;
}

void vb2_public_key_free(struct vb2_public_key *key)
{
	if (!key)
		return;

	if (key->desc)
		free((void *)key->desc);

	free(key);
}

uint8_t *vb2_public_key_packed_data(struct vb2_public_key *key)
{
	return (uint8_t *)(key->id + 1);
}

vb2_error_t vb2_public_key_read_keyb(struct vb2_public_key **key_ptr,
				     const char *filename)
{
	struct vb2_public_key *key = NULL;
	uint8_t *key_data, *key_buf;
	uint32_t key_size;
	enum vb2_signature_algorithm sig_alg;

	*key_ptr = NULL;

	if (vb2_read_file(filename, &key_data, &key_size))
		return VB2_ERROR_READ_KEYB_DATA;

	/* Guess the signature algorithm from the key size
	 * Note: This only considers exponent F4 keys, as there is no way to
	 * distinguish between exp 3 and F4 based on size. Vboot API 2.1 is
	 * required to make proper use of exp 3 keys. */
	for (sig_alg = VB2_SIG_RSA1024; sig_alg <= VB2_SIG_RSA8192; sig_alg++) {
		if (key_size == vb2_packed_key_size(sig_alg))
			break;
	}
	if (sig_alg > VB2_SIG_RSA8192) {
		free(key_data);
		return VB2_ERROR_READ_KEYB_SIZE;
	}

	if (vb2_public_key_alloc(&key, sig_alg)) {
		free(key_data);
		return VB2_ERROR_READ_KEYB_ALLOC;
	}

	/* Copy data from the file buffer to the public key buffer */
	key_buf = vb2_public_key_packed_data(key);
	memcpy(key_buf, key_data, key_size);
	free(key_data);

	if (vb2_unpack_key_data(key, key_buf, key_size)) {
		vb2_public_key_free(key);
		return VB2_ERROR_READ_KEYB_UNPACK;
	}

	*key_ptr = key;

	return VB2_SUCCESS;
}

vb2_error_t vb2_public_key_set_desc(struct vb2_public_key *key,
				    const char *desc)
{
	if (key->desc)
		free((void *)key->desc);

	if (desc) {
		key->desc = strdup(desc);
		if (!key->desc)
			return VB2_ERROR_PUBLIC_KEY_SET_DESC;
	} else {
		key->desc = NULL;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb21_packed_key_read(struct vb21_packed_key **key_ptr,
				 const char *filename)
{
	struct vb2_public_key key;
	uint8_t *buf;
	uint32_t size;

	*key_ptr = NULL;

	if (vb2_read_file(filename, &buf, &size))
		return VB2_ERROR_READ_PACKED_KEY_DATA;

	/* Validity check: make sure key unpacks properly */
	if (vb21_unpack_key(&key, buf, size))
		return VB2_ERROR_READ_PACKED_KEY;

	*key_ptr = (struct vb21_packed_key *)buf;

	return VB2_SUCCESS;
}

vb2_error_t vb21_public_key_pack(struct vb21_packed_key **key_ptr,
				 const struct vb2_public_key *pubk)
{
	struct vb21_packed_key key = {
		.c.magic = VB21_MAGIC_PACKED_KEY,
		.c.struct_version_major = VB21_PACKED_KEY_VERSION_MAJOR,
		.c.struct_version_minor = VB21_PACKED_KEY_VERSION_MINOR,
	};
	uint8_t *buf;
	uint32_t *buf32;

	*key_ptr = NULL;

	/* Calculate sizes and offsets */
	key.c.fixed_size = sizeof(key);
	key.c.desc_size = vb2_desc_size(pubk->desc);
	key.key_offset = key.c.fixed_size + key.c.desc_size;

	if (pubk->sig_alg != VB2_SIG_NONE) {
		key.key_size = vb2_packed_key_size(pubk->sig_alg);
		if (!key.key_size)
			return VB2_ERROR_PUBLIC_KEY_PACK_SIZE;
	}

	key.c.total_size = key.key_offset + key.key_size;

	/* Copy/initialize fields */
	key.key_version = pubk->version;
	key.sig_alg = pubk->sig_alg;
	key.hash_alg = pubk->hash_alg;
	key.id = *pubk->id;

	/* Allocate the new buffer */
	buf = calloc(1, key.c.total_size);

	/* Copy data into the buffer */
	memcpy(buf, &key, sizeof(key));

	/* strcpy() is safe because we allocated above based on strlen() */
	if (pubk->desc && *pubk->desc) {
		strcpy((char *)(buf + key.c.fixed_size), pubk->desc);
		buf[key.c.fixed_size + key.c.desc_size - 1] = 0;
	}

	if (pubk->sig_alg != VB2_SIG_NONE) {
		/* Re-pack the key arrays */
		buf32 = (uint32_t *)(buf + key.key_offset);
		buf32[0] = pubk->arrsize;
		buf32[1] = pubk->n0inv;
		memcpy(buf32 + 2, pubk->n, pubk->arrsize * sizeof(uint32_t));
		memcpy(buf32 + 2 + pubk->arrsize, pubk->rr,
		       pubk->arrsize * sizeof(uint32_t));
	}

	*key_ptr = (struct vb21_packed_key *)buf;

	return VB2_SUCCESS;
}

vb2_error_t vb2_public_key_hash(struct vb2_public_key *key,
				enum vb2_hash_algorithm hash_alg)
{
	switch (hash_alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		key->desc = "Unsigned SHA1";
		break;
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA256:
		key->desc = "Unsigned SHA-256";
		break;
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA512:
		key->desc = "Unsigned SHA-512";
		break;
#endif
	default:
		return VB2_ERROR_PUBLIC_KEY_HASH;
	}

	key->sig_alg = VB2_SIG_NONE;
	key->hash_alg = hash_alg;
	key->id = vb2_hash_id(hash_alg);
	return VB2_SUCCESS;
}

enum vb2_signature_algorithm vb2_rsa_sig_alg(struct rsa_st *rsa)
{
	const BIGNUM *e, *n;
	uint32_t exp, bits;

	RSA_get0_key(rsa, &n, &e, NULL);
	exp = BN_get_word(e);
	bits = BN_num_bits(n);

	return vb2_get_sig_alg(exp, bits);
}

vb2_error_t vb21_public_key_write(const struct vb2_public_key *key,
				  const char *filename)
{
	struct vb21_packed_key *pkey;
	int ret;

	ret = vb21_public_key_pack(&pkey, key);
	if (ret)
		return ret;

	ret = vb21_write_object(filename, pkey);

	free(pkey);
	return ret;
}

vb2_error_t vb21_unpack_key(struct vb2_public_key *key, const uint8_t *buf,
			    uint32_t size)
{
	const struct vb21_packed_key *pkey =
		(const struct vb21_packed_key *)buf;
	uint32_t sig_size;
	uint32_t min_offset = 0;
	vb2_error_t rv;

	/* Check magic number */
	if (pkey->c.magic != VB21_MAGIC_PACKED_KEY)
		return VB2_ERROR_UNPACK_KEY_MAGIC;

	rv = vb21_verify_common_header(buf, size);
	if (rv)
		return rv;

	/* Make sure key data is inside */
	rv = vb21_verify_common_member(pkey, &min_offset,
				       pkey->key_offset, pkey->key_size);
	if (rv)
		return rv;

	/*
	 * Check for compatible version.  No need to check minor version, since
	 * that's compatible across readers matching the major version, and we
	 * haven't added any new fields.
	 */
	if (pkey->c.struct_version_major != VB21_PACKED_KEY_VERSION_MAJOR)
		return VB2_ERROR_UNPACK_KEY_STRUCT_VERSION;

	/* Copy key algorithms */
	key->hash_alg = pkey->hash_alg;
	if (!vb2_digest_size(key->hash_alg))
		return VB2_ERROR_UNPACK_KEY_HASH_ALGORITHM;

	key->sig_alg = pkey->sig_alg;
	if (key->sig_alg != VB2_SIG_NONE) {
		sig_size = vb2_rsa_sig_size(key->sig_alg);
		if (!sig_size)
			return VB2_ERROR_UNPACK_KEY_SIG_ALGORITHM;
		rv = vb2_unpack_key_data(
				key,
				(const uint8_t *)pkey + pkey->key_offset,
				pkey->key_size);
		if (rv)
			return rv;
	}

	/* Key description */
	key->desc = vb21_common_desc(pkey);
	key->version = pkey->key_version;
	key->id = &pkey->id;

	return VB2_SUCCESS;
}
