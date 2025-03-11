/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host utilites to execute flashrom command.
 */

#include <stdint.h>

#include "2return_codes.h"
#include "fmap.h"

#define FLASHROM_PROGRAMMER_INTERNAL_AP "internal"
#define FLASHROM_PROGRAMMER_INTERNAL_EC "ec"

/* Utilities for firmware images and (FMAP) sections */
struct firmware_image {
	/**
	 * programmer	The name of the programmer to use. Use either
	 *		FLASHROM_PROGRAMMER_INTERNAL_AP or,
	 *		FLASHROM_PROGRAMMER_INTERNAL_EC
	 *		for the AP and EC respectively.
	 */
	const char *programmer;
	uint32_t size; /* buffer size. */
	uint8_t *data; /* data allocated buffer to read/write with. */
	char *file_name;
	char *ro_version, *rw_version_a, *rw_version_b;
	/* AP RW sections may contain a special ECRW binary for syncing EC
	   firmware on boot. These 2 fields are valid only for AP image. */
	char *ecrw_version_a, *ecrw_version_b;
	FmapHeader *fmap_header;
};

/**
 * Read using flashrom into an allocated buffer.
 *
 * flashrom_read subprocesses the flashrom binary and returns a buffer truncated
 * to the region.
 *
 * flashrom_read_image reads the returns a full sized buffer with only the
 * regions filled with data.
 *
 * flashrom_read_region returns the buffer truncated to the region.
 *
 * @param image		The parameter that contains the programmer, buffer and
 *			size to use in the read operation.
 * @param regions	A list of the names of the fmap regions to read. Must
 *			be non-null if regions_len is non-zero. Otherwise, must
 *			be at least regions_len items long.
 * @param regions_len	The size of regions, or 0 to read the entire flash
 *			chip.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_read(struct firmware_image *image, const char *region);
int flashrom_read_image(struct firmware_image *image,
			const char *const regions[], size_t regions_len,
			int verbosity);
int flashrom_read_region(struct firmware_image *image, const char *region,
			 int verbosity);

/**
 * Write using flashrom from a buffer.
 *
 * @param image		The parameter that contains the programmer, buffer and
 *			size to use in the write operation.
 * @param regions	A list of the names of the fmap regions to write. Must
 *			be non-null if regions_len is non-zero. Otherwise, must
 *			be at least regions_len items long.
 * @param regions_len	The size of regions, or 0 to write the entire flash
 *			chip.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_write(struct firmware_image *image, const char *region);
int flashrom_write_image(const struct firmware_image *image,
			 const char *const regions[], size_t regions_len,
			 const struct firmware_image *diff_image, int do_verify,
			 int verbosity);

/**
 * Get wp state using flashrom.
 *
 * @param programmer	The name of the programmer to use for reading the
 *                      writeprotect state.
 * @param wp_mode       Pointer to a bool to store the WP mode. Will be set to
 *                      false if WP is disabled, true if WP is enabled.
 *                      NULL can be passed if not needed.
 * @param wp_start      Pointer to a uint32_t to store the WP start addr.
 *                      NULL can be passed if not needed.
 * @param wp_len        Pointer to a uint32_t to store the WP region length.
 *                      NULL can be passed if not needed.
 *
 * @return 0 on success, or a relevant error.
 */
int flashrom_get_wp(const char *programmer, bool *wp_mode,
		    uint32_t *wp_start, uint32_t *wp_len, int verbosity);

/**
 * Set wp state using flashrom.
 *
 * @param programmer	The name of the programmer to use for writing the
 *                      writeprotect state.
 * @param wp_mode       WP mode to set. true to enable, false disable WP.
 * @param wp_start      WP start addr to set
 * @param wp_len        WP region length set
 *
 * @return 0 on success, or a relevant error.
 */
int flashrom_set_wp(const char *programmer, bool wp_mode,
		    uint32_t wp_start, uint32_t wp_len, int verbosity);

/**
 * Get flash info using flashrom.
 *
 * @param programmer	The name of the programmer to use.
 * @param vendor        The chip vendor name, non-NULLable.
 * @param name          The chip product name, non-NULLable.
 * @param vid           The chip vendor id, non-NULLable.
 * @param pid           The chip product id, non-NULLable.
 * @param flash_len     Pointer to a uint32_t to store chip length, non-NULLable.
 *
 * @return 0 on success, or a relevant error.
 */
int flashrom_get_info(const char *prog_with_params,
		      char **vendor, char **name,
		      uint32_t *vid, uint32_t *pid,
		      uint32_t *flash_len, int verbosity);

/**
 * Get flash size using flashrom.
 *
 * @param programmer	The name of the programmer to use.
 * @param flash_len     Pointer to a uint32_t to store chip length.
 *
 * @return 0 on success, or a relevant error.
 */
int flashrom_get_size(const char *programmer, uint32_t *flash_len,
		      int verbosity);
