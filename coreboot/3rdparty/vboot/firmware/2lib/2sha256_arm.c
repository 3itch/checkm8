/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * SHA256 implementation using ARMv8 Cryptography Extension.
 */

#include "2common.h"
#include "2sha.h"
#include "2sha_private.h"
#include "2api.h"

const uint32_t vb2_hash_seq[8] = {0, 1, 2, 3, 4, 5, 6, 7};

int sha256_ce_transform(uint32_t *state, const unsigned char *buf, int blocks);

void vb2_sha256_transform_hwcrypto(const uint8_t *message,
				   unsigned int block_nb)
{
	if (block_nb)
		sha256_ce_transform(vb2_sha_ctx.h, message, block_nb);
}
