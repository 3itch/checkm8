/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2hmac.h"
#include "2sha.h"
#include "2sysincludes.h"

int vb2_hmac_calculate(bool allow_hwcrypto, enum vb2_hash_algorithm alg, const void *key,
		       uint32_t key_size, const void *msg, uint32_t msg_size,
		       struct vb2_hash *mac)
{
	uint32_t block_size;
	uint32_t digest_size;
	uint8_t k[VB2_MAX_BLOCK_SIZE];
	uint8_t o_pad[VB2_MAX_BLOCK_SIZE];
	uint8_t i_pad[VB2_MAX_BLOCK_SIZE];
	uint8_t b[VB2_MAX_DIGEST_SIZE];
	struct vb2_digest_context dc;
	int i;

	if (!key | !msg | !mac)
		return -1;

	digest_size = vb2_digest_size(alg);
	block_size = vb2_hash_block_size(alg);
	if (!digest_size || !block_size)
		return -1;

	if (key_size > block_size) {
		vb2_digest_init(&dc, allow_hwcrypto, alg, 0);
		vb2_digest_extend(&dc, (uint8_t *)key, key_size);
		vb2_digest_finalize(&dc, k, block_size);
		key_size = digest_size;
	} else {
		memcpy(k, key, key_size);
	}
	if (key_size < block_size)
		memset(k + key_size, 0, block_size - key_size);

	for (i = 0; i < block_size; i++) {
		o_pad[i] = 0x5c ^ k[i];
		i_pad[i] = 0x36 ^ k[i];
	}

	vb2_digest_init(&dc, allow_hwcrypto, alg, 0);
	vb2_digest_extend(&dc, i_pad, block_size);
	vb2_digest_extend(&dc, msg, msg_size);
	vb2_digest_finalize(&dc, b, digest_size);

	vb2_digest_init(&dc, allow_hwcrypto, alg, 0);
	vb2_digest_extend(&dc, o_pad, block_size);
	vb2_digest_extend(&dc, b, digest_size);
	vb2_digest_finalize(&dc, mac->raw, digest_size);
	mac->algo = alg;

	return 0;
}
