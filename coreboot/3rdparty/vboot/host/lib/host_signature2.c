/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host functions for signature generation.
 */

#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "2sysincludes.h"

#include "2common.h"
#include "2rsa.h"
#include "2sha.h"
#include "file_keys.h"
#include "host_common.h"
#include "host_key21.h"
#include "host_signature21.h"
#include "host_p11.h"

struct vb2_signature *vb2_alloc_signature(uint32_t sig_size,
					  uint32_t data_size)
{
	struct vb2_signature *sig = (struct vb2_signature *)
		calloc(sizeof(*sig) + sig_size, 1);
	if (!sig)
		return NULL;

	sig->sig_offset = sizeof(*sig);
	sig->sig_size = sig_size;
	sig->data_size = data_size;

	return sig;
}

void vb2_init_signature(struct vb2_signature *sig, uint8_t *sig_data,
			uint32_t sig_size, uint32_t data_size)
{
	memset(sig, 0, sizeof(*sig));
	sig->sig_offset = vb2_offset_of(sig, sig_data);
	sig->sig_size = sig_size;
	sig->data_size = data_size;
}

vb2_error_t vb2_copy_signature(struct vb2_signature *dest,
			       const struct vb2_signature *src)
{
	if (dest->sig_size < src->sig_size)
		return VB2_ERROR_SIG_SIZE;

	dest->sig_size = src->sig_size;
	dest->data_size = src->data_size;

	memcpy(vb2_signature_data_mutable(dest),
	       vb2_signature_data(src),
	       src->sig_size);

	return VB2_SUCCESS;
}

struct vb2_signature *vb2_sha512_signature(const uint8_t *data, uint32_t size)
{
	struct vb2_hash hash;
	if (VB2_SUCCESS != vb2_hash_calculate(false, data, size,
					      VB2_HASH_SHA512, &hash))
		return NULL;

	struct vb2_signature *sig =
		vb2_alloc_signature(sizeof(hash.sha512), size);
	if (!sig)
		return NULL;

	memcpy(vb2_signature_data_mutable(sig), hash.sha512,
	       sizeof(hash.sha512));
	return sig;
}

struct vb2_signature *vb2_calculate_signature(
		const uint8_t *data, uint32_t size,
		const struct vb2_private_key *key)
{
	if (key->key_location == PRIVATE_KEY_P11) {
		const uint32_t sig_size = vb2_rsa_sig_size(key->sig_alg);
		struct vb2_signature *sig =
			(struct vb2_signature *)vb2_alloc_signature(sig_size, size);
		if (!sig)
			return NULL;
		if (pkcs11_sign(key->p11_key, key->hash_alg, data, size,
				vb2_signature_data_mutable(sig), sig_size) != VB2_SUCCESS) {
			fprintf(stderr, "%s: pkcs11_sign failed\n", __func__);
			free(sig);
			return NULL;
		}
		return sig;
	}

	struct vb2_hash hash;
	uint32_t digest_size = vb2_digest_size(key->hash_alg);

	uint32_t digest_info_size = 0;
	const uint8_t *digest_info = NULL;
	if (VB2_SUCCESS != vb2_digest_info(key->hash_alg,
					   &digest_info, &digest_info_size))
		return NULL;

	/* Calculate the digest */
	if (VB2_SUCCESS != vb2_hash_calculate(false, data, size, key->hash_alg,
					      &hash))
		return NULL;

	/* Prepend the digest info to the digest */
	int signature_digest_len = digest_size + digest_info_size;
	uint8_t *signature_digest = malloc(signature_digest_len);
	if (!signature_digest)
		return NULL;

	memcpy(signature_digest, digest_info, digest_info_size);
	memcpy(signature_digest + digest_info_size, hash.raw, digest_size);

	/* Allocate output signature */
	struct vb2_signature *sig = (struct vb2_signature *)
		vb2_alloc_signature(vb2_rsa_sig_size(key->sig_alg), size);
	if (!sig) {
		free(signature_digest);
		return NULL;
	}

	/* Sign the signature_digest into our output buffer */
	int rv = RSA_private_encrypt(signature_digest_len,    /* Input length */
				     signature_digest,        /* Input data */
				     vb2_signature_data_mutable(sig),  /* Output sig */
				     key->rsa_private_key,    /* Key to use */
				     RSA_PKCS1_PADDING);      /* Padding */
	free(signature_digest);

	if (-1 == rv) {
		fprintf(stderr, "%s: RSA_private_encrypt() failed\n", __func__);
		free(sig);
		return NULL;
	}

	/* Return the signature */
	return sig;
}

struct vb2_signature *
vb2_create_signature_from_hash(const struct vb2_hash *hash)
{
	const uint32_t hsize = vb2_digest_size(hash->algo);

	/* Unsupported algorithm */
	if (!hsize)
		return NULL;

	const uint32_t full_hsize = offsetof(struct vb2_hash, raw) + hsize;

	/* The body size is unknown, so set it to zero */
	struct vb2_signature *sig =
		(struct vb2_signature *)vb2_alloc_signature(full_hsize, 0);
	if (!sig)
		return NULL;

	if (!memcpy(vb2_signature_data_mutable(sig), hash, full_hsize)) {
		free(sig);
		return NULL;
	}

	return sig;
}
