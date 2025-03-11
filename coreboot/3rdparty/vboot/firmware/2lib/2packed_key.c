/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Key unpacking functions
 */

#include "2common.h"
#include "2packed_key.h"
#include "2rsa.h"
#include "2sysincludes.h"

test_mockable
vb2_error_t vb2_unpack_key_buffer(struct vb2_public_key *key,
				  const uint8_t *buf, uint32_t size)
{
	const struct vb2_packed_key *packed_key =
		(const struct vb2_packed_key *)buf;
	const uint32_t *buf32;
	uint32_t expected_key_size;

	/* Make sure passed buffer is big enough for the packed key */
	VB2_TRY(vb2_verify_packed_key_inside(buf, size, packed_key));

	/* Unpack key algorithm */
	key->sig_alg = vb2_crypto_to_signature(packed_key->algorithm);
	if (key->sig_alg == VB2_SIG_INVALID) {
		VB2_DEBUG("Unsupported signature algorithm.\n");
		return VB2_ERROR_UNPACK_KEY_SIG_ALGORITHM;
	}

	key->hash_alg = vb2_crypto_to_hash(packed_key->algorithm);
	if (key->hash_alg == VB2_HASH_INVALID) {
		VB2_DEBUG("Unsupported hash algorithm.\n");
		return VB2_ERROR_UNPACK_KEY_HASH_ALGORITHM;
	}

	expected_key_size = vb2_packed_key_size(key->sig_alg);
	if (!expected_key_size || expected_key_size != packed_key->key_size) {
		VB2_DEBUG("Wrong key size for algorithm\n");
		return VB2_ERROR_UNPACK_KEY_SIZE;
	}

	/* Make sure source buffer is 32-bit aligned */
	buf32 = (const uint32_t *)vb2_packed_key_data(packed_key);
	if (!vb2_aligned(buf32, sizeof(uint32_t)))
		return VB2_ERROR_UNPACK_KEY_ALIGN;

	/* Validity check key array size */
	key->arrsize = buf32[0];
	if ((uint64_t)key->arrsize * sizeof(uint32_t) != vb2_rsa_sig_size(key->sig_alg))
		return VB2_ERROR_UNPACK_KEY_ARRAY_SIZE;

	key->n0inv = buf32[1];

	/* Arrays point inside the key data */
	key->n = buf32 + 2;
	key->rr = buf32 + 2 + key->arrsize;

	/* disable hwcrypto for RSA by default */
	key->allow_hwcrypto = 0;

#ifdef __COVERITY__
	__coverity_tainted_data_sanitize__(key);
	__coverity_tainted_data_sanitize__(buf);
#endif
	return VB2_SUCCESS;
}

vb2_error_t vb2_unpack_key(struct vb2_public_key *key,
			   const struct vb2_packed_key *packed_key)
{
	if (!packed_key)
		return VB2_ERROR_UNPACK_KEY_BUFFER;

	return vb2_unpack_key_buffer(key,
				     (const uint8_t *)packed_key,
				     packed_key->key_offset +
				     packed_key->key_size);
}
