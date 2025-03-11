/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Internal functions from 2rsa.c that have error conditions we can't trigger
 * from the public APIs.  These include checks for bad algorithms where the
 * next call level up already checks for bad algorithms, etc.
 *
 * These functions aren't in 2rsa.h because they're not part of the public
 * APIs.
 */

#ifndef VBOOT_REFERENCE_2RSA_PRIVATE_H_
#define VBOOT_REFERENCE_2RSA_PRIVATE_H_

struct vb2_public_key;
int vb2_mont_ge(const struct vb2_public_key *key, uint32_t *a);
vb2_error_t vb2_check_padding(const uint8_t *sig,
			      const struct vb2_public_key *key);

#endif  /* VBOOT_REFERENCE_2RSA_PRIVATE_H_ */
