/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_FILE_TYPE_BIOS_H_
#define VBOOT_REFERENCE_FILE_TYPE_BIOS_H_

#include <stdint.h>

#include "futility.h"

/*
 * The Chrome OS BIOS must contain specific FMAP areas, which we want to look
 * at in a certain order.
 */
enum bios_component {
	BIOS_FMAP_GBB,
	BIOS_FMAP_FW_MAIN_A,
	BIOS_FMAP_FW_MAIN_B,
	BIOS_FMAP_VBLOCK_A,
	BIOS_FMAP_VBLOCK_B,

	NUM_BIOS_COMPONENTS
};

static const char *const fmap_name[] = {
	"GBB",	     /* BIOS_FMAP_GBB */
	"FW_MAIN_A", /* BIOS_FMAP_FW_MAIN_A */
	"FW_MAIN_B", /* BIOS_FMAP_FW_MAIN_B */
	"VBLOCK_A",  /* BIOS_FMAP_VBLOCK_A */
	"VBLOCK_B",  /* BIOS_FMAP_VBLOCK_B */
};
_Static_assert(ARRAY_SIZE(fmap_name) == NUM_BIOS_COMPONENTS,
	       "Size of fmap_name[] should match NUM_BIOS_COMPONENTS");

/* Location information for each component */
struct bios_area_s {
	uint32_t offset; /* to avoid pointer math */
	uint8_t *buf;
	uint32_t len;
	uint32_t is_valid;

	/* VBLOCK only */
	uint32_t flags;
	uint32_t version;

	/* FW_MAIN only */
	size_t fw_size; /* effective size from cbfstool (if available) */
	struct vb2_hash metadata_hash;
};

/* State to track as we visit all components */
struct bios_state_s {
	/* Current component */
	enum bios_component c;
	/* Other activites, possibly before or after the current one */
	struct bios_area_s area[NUM_BIOS_COMPONENTS];
	struct bios_area_s recovery_key;
	struct bios_area_s rootkey;
};

int show_fw_preamble_buf(const char *fname, uint8_t *buf, uint32_t len,
			 struct bios_state_s *state);

#endif /* VBOOT_REFERENCE_FILE_TYPE_BIOS_H_ */
