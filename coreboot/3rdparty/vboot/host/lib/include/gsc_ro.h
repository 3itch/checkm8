/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __VBOOT_REFERENCE_HOST_LIB_INCLUDE_GSC_RO_H
#define __VBOOT_REFERENCE_HOST_LIB_INCLUDE_GSC_RO_H

#include <stddef.h>
#include <stdint.h>

#include "2sha.h"

struct gscvd_ro_range {
	uint32_t offset;
	uint32_t size; /* Use uint32_t as opposed to size_to be portable. */
};

#define GSC_VD_MAGIC 0x65666135 /* Little endian '5 a f e' */
#define GSC_VD_ROLLBACK_COUNTER 1

struct gsc_verification_data {
	uint32_t gv_magic;
	/*
	 * Size of this structure in bytes, including the ranges array,
	 * signature and root key bodies.
	 */
	uint16_t size;
	uint16_t major_version; /* Version of this struct layout. Starts at 0 */
	uint16_t minor_version;
	/*
	 * GSC will cache the counter value and will not accept verification
	 * data blobs with a lower value.
	 */
	uint16_t rollback_counter;
	uint32_t gsc_board_id; /* Locks blob to certain platform. */
	uint32_t gsc_flags; /* A field for future enhancements. */
	/*
	 * The location of fmap that points to this blob. This location must
	 * also be in one of the verified sections, expressed as offset in
	 * flash
	 */
	uint32_t fmap_location;
	uint32_t hash_alg; /* one of enum vb2_hash_algorithm alg. */
	struct vb2_signature sig_header;
	struct vb2_packed_key root_key_header;
	/*
	 * SHAxxx(ranges[0].offset..ranges[0].size || ... ||
	 *        ranges[n].offset..ranges[n].size)
	 *
	 * Let the digest space allow to accommodate the largest possible one.
	 */
	uint8_t ranges_digest[VB2_SHA512_DIGEST_SIZE];
	uint32_t range_count; /* Number of gscvd_ro_range entries. */
	struct gscvd_ro_range ranges[0];
};

#endif /* ! __VBOOT_REFERENCE_HOST_LIB_INCLUDE_GSC_RO_H */
