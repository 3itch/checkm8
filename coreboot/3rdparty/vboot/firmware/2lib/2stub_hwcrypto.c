/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Stub hwcrypto API implementations which should be implemented by the caller.
 */

#include "2api.h"

#if !defined(X86_SHA_EXT) && !defined(ARMV8_CRYPTO_EXT)
__attribute__((weak))
vb2_error_t vb2ex_hwcrypto_digest_init(enum vb2_hash_algorithm hash_alg,
				       uint32_t data_size)
{
	return VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;
}

__attribute__((weak))
vb2_error_t vb2ex_hwcrypto_digest_extend(const uint8_t *buf, uint32_t size)
{
	return VB2_ERROR_SHA_EXTEND_ALGORITHM;  /* Should not be called. */
}

__attribute__((weak))
vb2_error_t vb2ex_hwcrypto_digest_finalize(uint8_t *digest,
					   uint32_t digest_size)
{
	return VB2_ERROR_SHA_FINALIZE_ALGORITHM;  /* Should not be called. */
}
#endif

__attribute__((weak))
vb2_error_t vb2ex_hwcrypto_rsa_verify_digest(const struct vb2_public_key *key,
					     const uint8_t *sig, const uint8_t *digest)
{
	return VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;
}

#if !defined(VB2_X86_RSA_ACCELERATION) && !defined(ARM64_RSA_ACCELERATION)
__attribute__((weak))
vb2_error_t vb2ex_hwcrypto_modexp(const struct vb2_public_key *key, uint8_t *inout,
				  void *workbuf, size_t workbuf_size, int exp)
{
	return VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;
}
#endif
