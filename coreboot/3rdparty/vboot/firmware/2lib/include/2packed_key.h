/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions related to unpacking keys and key buffers.
 */

#ifndef VBOOT_REFERENCE_2PACKED_KEY_H_
#define VBOOT_REFERENCE_2PACKED_KEY_H_

/**
 * Unpack a vboot1-format key buffer for use in verification
 *
 * The elements of the unpacked key will point into the source buffer, so don't
 * free the source buffer until you're done with the key.
 *
 * @param key		Destintion for unpacked key
 * @param buf		Source buffer containing packed key
 * @param size		Size of buffer in bytes
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_unpack_key_buffer(struct vb2_public_key *key,
				  const uint8_t *buf, uint32_t size);

/**
 * Unpack a vboot1-format key for use in verification
 *
 * The elements of the unpacked key will point into the source packed key, so
 * don't free the source until you're done with the public key.
 *
 * @param key		Destintion for unpacked key
 * @param packed_key	Source packed key
 * @param size		Size of buffer in bytes
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_unpack_key(struct vb2_public_key *key,
			   const struct vb2_packed_key *packed_key);

#endif  /* VBOOT_REFERENCE_2PACKED_KEY_H_ */
