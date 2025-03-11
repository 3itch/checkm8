/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Common functions between firmware and kernel verified boot.
 */

#ifndef VBOOT_REFERENCE_VB21_COMMON_H_
#define VBOOT_REFERENCE_VB21_COMMON_H_

#include "2common.h"
#include "2return_codes.h"
#include "2struct.h"
#include "host_struct21.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/**
 * Return the description of an object starting with a vb21_struct_common
 * header.
 *
 * Does not validity-check the buffer; merely returns the pointer.
 *
 * @param buf		Pointer to common object
 * @return A pointer to description or an empty string if none.
 */
const char *vb21_common_desc(const void *buf);

/**
 * Verify the common struct header is fully contained in its parent data
 *
 * Also verifies the description is either zero-length or null-terminated.
 *
 * @param parent	Parent data
 * @param parent_size	Parent size in bytes
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb21_verify_common_header(const void *parent, uint32_t parent_size);

/**
 * Verify a member is within the data for a parent object
 *
 * @param parent	Parent data (starts with struct vb21_struct_common)
 * @param min_offset	Pointer to minimum offset where member can be located.
 *			If this offset is 0 on input, uses the size of the
 *			fixed header (and description, if any).  This will be
 *			updated on return to the end of the passed member.  On
 *			error, the value of min_offset is undefined.
 * @param member_offset Offset of member data from start of parent, in bytes
 * @param member_size	Size of member data, in bytes
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb21_verify_common_member(const void *parent, uint32_t *min_offset,
				      uint32_t member_offset,
				      uint32_t member_size);

/**
 * Verify a member which starts with a common header is within the parent
 *
 * This does not verify the contents of the member or its header, only that the
 * member's claimed total size fits within the parent's claimed total size at
 * the specified offset.
 *
 * @param parent	Parent data (starts with struct vb21_struct_common)
 * @param min_offset	Pointer to minimum offset where member can be located.
 *			If this offset is 0 on input, uses the size of the
 *			fixed header (and description, if any).  This will be
 *			updated on return to the end of the passed member.  On
 *			error, the value of min_offset is undefined.
 * @param member_offset Offset of member data from start of parent, in bytes.
 *                      This should be the start of the common header of the
 *                      member.
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb21_verify_common_subobject(const void *parent,
					 uint32_t *min_offset,
					 uint32_t member_offset);

/**
 * Verify the integrity of a signature struct
 * @param sig		Signature struct
 * @param size		Size of buffer containing signature struct
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb21_verify_signature(const struct vb21_signature *sig,
				  uint32_t size);

/**
 * Verify a signature against an expected hash digest.
 *
 * @param key		Key to use in signature verification
 * @param sig		Signature to verify (may be destroyed in process)
 * @param digest	Digest of signed data
 * @param wb		Work buffer
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb21_verify_digest(const struct vb2_public_key *key,
			       struct vb21_signature *sig,
			       const uint8_t *digest,
			       const struct vb2_workbuf *wb);

/**
 * Verify data matches signature.
 *
 * @param data		Data to verify
 * @param size		Size of data buffer.  Note that amount of data to
 *			actually validate is contained in sig->data_size.
 * @param sig		Signature of data (destroyed in process)
 * @param key		Key to use to validate signature
 * @param wb		Work buffer
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb21_verify_data(const void *data, uint32_t size,
			     struct vb21_signature *sig,
			     const struct vb2_public_key *key,
			     const struct vb2_workbuf *wb);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* VBOOT_REFERENCE_VB21_COMMON_H_ */
