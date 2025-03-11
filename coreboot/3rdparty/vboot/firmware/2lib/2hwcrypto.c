/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * SHA256 implementation using the hardware crypto accelerator.
 */

#include "2common.h"
#include "2sha.h"
#include "2sha_private.h"
#include "2api.h"

struct vb2_sha256_context vb2_sha_ctx;

vb2_error_t vb2ex_hwcrypto_digest_init(enum vb2_hash_algorithm hash_alg,
				       uint32_t data_size)
{
	int i;

	if (hash_alg != VB2_HASH_SHA256)
		return VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;

	for (i = 0; i < ARRAY_SIZE(vb2_hash_seq); i++) {
		VB2_ASSERT(vb2_hash_seq[i] < ARRAY_SIZE(vb2_sha_ctx.h));
		vb2_sha_ctx.h[vb2_hash_seq[i]] = vb2_sha256_h0[i];
	}

	vb2_sha_ctx.size = 0;
	vb2_sha_ctx.total_size = 0;
	memset(vb2_sha_ctx.block, 0, sizeof(vb2_sha_ctx.block));

	return VB2_SUCCESS;
}

vb2_error_t vb2ex_hwcrypto_digest_extend(const uint8_t *buf, uint32_t size)
{
	unsigned int remaining_blocks;
	unsigned int new_size, rem_size, tmp_size;
	const uint8_t *shifted_data;

	tmp_size = VB2_SHA256_BLOCK_SIZE - vb2_sha_ctx.size;
	rem_size = size < tmp_size ? size : tmp_size;

	memcpy(&vb2_sha_ctx.block[vb2_sha_ctx.size], buf, rem_size);

	if (vb2_sha_ctx.size + size < VB2_SHA256_BLOCK_SIZE) {
		vb2_sha_ctx.size += size;
		return VB2_SUCCESS;
	}

	new_size = size - rem_size;
	remaining_blocks = new_size / VB2_SHA256_BLOCK_SIZE;

	shifted_data = buf + rem_size;

	vb2_sha256_transform_hwcrypto(vb2_sha_ctx.block, 1);
	if (remaining_blocks)
		vb2_sha256_transform_hwcrypto(shifted_data, remaining_blocks);

	rem_size = new_size % VB2_SHA256_BLOCK_SIZE;

	memcpy(vb2_sha_ctx.block,
	       &shifted_data[remaining_blocks * VB2_SHA256_BLOCK_SIZE],
	       rem_size);

	vb2_sha_ctx.size = rem_size;
	vb2_sha_ctx.total_size += (remaining_blocks + 1) * VB2_SHA256_BLOCK_SIZE;
	return VB2_SUCCESS;
}

vb2_error_t vb2ex_hwcrypto_digest_finalize(uint8_t *digest,
					   uint32_t digest_size)
{
	unsigned int block_nb;
	unsigned int pm_size;
	unsigned int size_b;
	int i;

	if (digest_size != VB2_SHA256_DIGEST_SIZE) {
		VB2_DEBUG("ERROR: Digest size does not match expected length.\n");
		return VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE;
	}

	block_nb = (1 + ((VB2_SHA256_BLOCK_SIZE - SHA256_MIN_PAD_LEN)
			 < (vb2_sha_ctx.size % VB2_SHA256_BLOCK_SIZE)));

	size_b = (vb2_sha_ctx.total_size + vb2_sha_ctx.size) * 8;
	pm_size = block_nb * VB2_SHA256_BLOCK_SIZE;

	memset(vb2_sha_ctx.block + vb2_sha_ctx.size, 0,
	       pm_size - vb2_sha_ctx.size);
	vb2_sha_ctx.block[vb2_sha_ctx.size] = SHA256_PAD_BEGIN;
	UNPACK32(size_b, vb2_sha_ctx.block + pm_size - 4);

	vb2_sha256_transform_hwcrypto(vb2_sha_ctx.block, block_nb);

	for (i = 0; i < ARRAY_SIZE(vb2_hash_seq); i++) {
		VB2_ASSERT(vb2_hash_seq[i] < ARRAY_SIZE(vb2_sha_ctx.h));
		UNPACK32(vb2_sha_ctx.h[vb2_hash_seq[i]], &digest[i * 4]);
	}
	return VB2_SUCCESS;
}
