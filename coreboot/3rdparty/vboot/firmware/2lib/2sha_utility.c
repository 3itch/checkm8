/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utility functions for message digest functions.
 */

#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"

size_t vb2_digest_size(enum vb2_hash_algorithm hash_alg)
{
	switch (hash_alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		return VB2_SHA1_DIGEST_SIZE;
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA224:
		return VB2_SHA224_DIGEST_SIZE;
	case VB2_HASH_SHA256:
		return VB2_SHA256_DIGEST_SIZE;
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA384:
		return VB2_SHA384_DIGEST_SIZE;
	case VB2_HASH_SHA512:
		return VB2_SHA512_DIGEST_SIZE;
#endif
	default:
		return 0;
	}
}

size_t vb2_hash_block_size(enum vb2_hash_algorithm alg)
{
	switch (alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		return VB2_SHA1_BLOCK_SIZE;
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA224:	/* SHA224 reuses SHA256 internal structures */
	case VB2_HASH_SHA256:
		return VB2_SHA256_BLOCK_SIZE;
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA384:	/* SHA384 reuses SHA512 internal structures */
	case VB2_HASH_SHA512:
		return VB2_SHA512_BLOCK_SIZE;
#endif
	default:
		return 0;
	}
}

test_mockable
vb2_error_t vb2_digest_init(struct vb2_digest_context *dc, bool allow_hwcrypto,
			    enum vb2_hash_algorithm algo, uint32_t data_size)
{
	const char msg[] = "%u bytes, hash algo %d, HW acceleration %s";

	dc->hash_alg = algo;
	dc->using_hwcrypto = 0;

	if (allow_hwcrypto) {
		vb2_error_t rv = vb2ex_hwcrypto_digest_init(algo, data_size);
		if (rv == VB2_SUCCESS) {
			VB2_DEBUG(msg, data_size, algo, "enabled\n");
			dc->using_hwcrypto = 1;
			return VB2_SUCCESS;
		}
		if (rv != VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED) {
			VB2_DEBUG(msg, data_size, algo, "initialization error");
			VB2_DEBUG_RAW(": %#x\n", rv);
			return rv;
		}
		VB2_DEBUG(msg, data_size, algo, "unsupported\n");
	} else {
		VB2_DEBUG(msg, data_size, algo, "forbidden\n");
	}

	switch (algo) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		vb2_sha1_init(&dc->sha1);
		return VB2_SUCCESS;
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA224:
	case VB2_HASH_SHA256:
		vb2_sha256_init(&dc->sha256, algo);
		return VB2_SUCCESS;
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA384:
	case VB2_HASH_SHA512:
		vb2_sha512_init(&dc->sha512, algo);
		return VB2_SUCCESS;
#endif
	default:
		return VB2_ERROR_SHA_INIT_ALGORITHM;
	}
}

test_mockable
vb2_error_t vb2_digest_extend(struct vb2_digest_context *dc, const uint8_t *buf,
			      uint32_t size)
{
	if (dc->using_hwcrypto)
		return vb2ex_hwcrypto_digest_extend(buf, size);

	switch (dc->hash_alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		vb2_sha1_update(&dc->sha1, buf, size);
		return VB2_SUCCESS;
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA224:
	case VB2_HASH_SHA256:
		vb2_sha256_update(&dc->sha256, buf, size);
		return VB2_SUCCESS;
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA384:
	case VB2_HASH_SHA512:
		vb2_sha512_update(&dc->sha512, buf, size);
		return VB2_SUCCESS;
#endif
	default:
		return VB2_ERROR_SHA_EXTEND_ALGORITHM;
	}
}

test_mockable
vb2_error_t vb2_digest_finalize(struct vb2_digest_context *dc, uint8_t *digest,
				uint32_t digest_size)
{
	if (dc->using_hwcrypto)
		return vb2ex_hwcrypto_digest_finalize(digest, digest_size);

	if (digest_size < vb2_digest_size(dc->hash_alg))
		return VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE;

	switch (dc->hash_alg) {
#if VB2_SUPPORT_SHA1
	case VB2_HASH_SHA1:
		vb2_sha1_finalize(&dc->sha1, digest);
		return VB2_SUCCESS;
#endif
#if VB2_SUPPORT_SHA256
	case VB2_HASH_SHA224:
	case VB2_HASH_SHA256:
		vb2_sha256_finalize(&dc->sha256, digest, dc->hash_alg);
		return VB2_SUCCESS;
#endif
#if VB2_SUPPORT_SHA512
	case VB2_HASH_SHA384:
	case VB2_HASH_SHA512:
		vb2_sha512_finalize(&dc->sha512, digest, dc->hash_alg);
		return VB2_SUCCESS;
#endif
	default:
		return VB2_ERROR_SHA_FINALIZE_ALGORITHM;
	}
}

vb2_error_t vb2_hash_calculate(bool allow_hwcrypto, const void *buf,
			       uint32_t size, enum vb2_hash_algorithm algo,
			       struct vb2_hash *hash)
{
	struct vb2_digest_context dc;
	hash->algo = algo;

	VB2_TRY(vb2_digest_init(&dc, allow_hwcrypto, algo, size));
	VB2_TRY(vb2_digest_extend(&dc, buf, size));

	return vb2_digest_finalize(&dc, hash->raw, vb2_digest_size(algo));
}

vb2_error_t vb2_hash_verify(bool allow_hwcrypto, const void *buf, uint32_t size,
			    const struct vb2_hash *hash)
{
	struct vb2_hash tmp;

	VB2_TRY(vb2_hash_calculate(allow_hwcrypto, buf, size, hash->algo, &tmp));
	if (memcmp(tmp.raw, hash->raw, vb2_digest_size(hash->algo)))
		return VB2_ERROR_SHA_MISMATCH;
	else
		return VB2_SUCCESS;
}
