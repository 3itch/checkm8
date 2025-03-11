/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_2HMAC_H_
#define VBOOT_REFERENCE_2HMAC_H_

#include <stdint.h>
#include "2crypto.h"
#include "2sha.h"

/**
 * Compute HMAC
 *
 * @param allow_hwcrypto	false to forbid HW crypto by policy; true to allow.
 * @param alg			Hash algorithm ID
 * @param key			HMAC key
 * @param key_size		HMAC key size
 * @param msg			Message to compute HMAC for
 * @param msg_size		Message size
 * @param mac			vb2_hash structure to fill with the mac of |msg|
 * @return
 */
int vb2_hmac_calculate(bool allow_hwcrypto, enum vb2_hash_algorithm alg, const void *key,
		       uint32_t key_size, const void *msg, uint32_t msg_size,
		       struct vb2_hash *mac);

#endif  /* VBOOT_REFERENCE_2HMAC_H_ */
