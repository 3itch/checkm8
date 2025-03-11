/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>

#include "2return_codes.h"
#include "2sha.h"

#define ENV_CBFSTOOL "CBFSTOOL"
#define DEFAULT_CBFSTOOL "cbfstool"

/*
 * Check the existence of a CBFS file.
 *
 * @param image_file	Firmware image file.
 * @param region	FMAP region (section). If `region` is NULL, then the
 *			region option will not be passed to cbfstool, and hence
 *			opterations will be performed on the default "COREBOOT"
 *			region.
 * @param name		CBFS file name.
 * @return true if the CBFS file exists; false otherwise.
 */
bool cbfstool_file_exists(const char *image_file, const char *region,
			  const char *name);

/*
 * Extract a CBFS file from a firmware image file.
 *
 * @param image_file	Firmware image file.
 * @param region	FMAP region (section). If `region` is NULL, then the
 *			region option will not be passed to cbfstool, and hence
 *			opterations will be performed on the default "COREBOOT"
 *			region.
 * @param name		CBFS file name to extract.
 * @param file		File path to store the extracted file to.
 * @return 0 on success; non-zero on failure.
 */
int cbfstool_extract(const char *image_file, const char *region,
		     const char *name, const char *file);

/* Truncate CBFS region and store the new CBFS size to `new_size`. */
vb2_error_t cbfstool_truncate(const char *file, const char *region,
			      size_t *new_size);

/*
 * Check whether image under `file` path supports CBFS_VERIFICATION,
 * and contains metadata hash. Hash found is available under *hash. If it was
 * not found, then hash type will be set to VB2_HASH_INVALID.
 *
 * If `region` is NULL, then region option will not be passed to cbfstool.
 * Operations will be performed on default `COREBOOT` region.
 */
vb2_error_t cbfstool_get_metadata_hash(const char *file, const char *region,
				       struct vb2_hash *hash);

/*
 * Get value of a bool Kconfig option from "config" file in CBFS.
 *
 * This function extracts "config" file from selected region, parses it to find
 * value of `config_field`, and stores it in `value`. On failure, `value` will
 * be false.
 *
 * If `region` is NULL, then region option will not be passed to cbfstool.
 * Operations will be performed on default `COREBOOT` region.
 */
vb2_error_t cbfstool_get_config_bool(const char *file, const char *region,
				     const char *config_field, bool *value);

/*
 * Get value of a str Kconfig option from "config" file in CBFS.
 *
 * This is similar to cbfstool_get_config_bool(). On success, the extracted
 * value is stored in `value` as an allocated string (which has to be freed by
 * the caller). If the value is not found, an error will be returned, and
 * `value` will be NULL.
 */
vb2_error_t cbfstool_get_config_string(const char *file, const char *region,
				       const char *config_field, char **value);
