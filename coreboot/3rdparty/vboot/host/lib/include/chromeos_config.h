/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_CHROMEOS_CONFIG_H_
#define VBOOT_REFERENCE_CHROMEOS_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>

#include "2common.h"
#include "2return_codes.h"

/**
 * Get a value from the model configuration on the device as a string.
 *
 * Note: this function allocates memory by its use of vb2_read_file, and relies
 * on the caller to free the allocated memory. The output parameter will be set
 * to NULL upon failure, so free can be safely called on this parameter.
 *
 * @param path          The path in the config schema to the object containing
 *                      the requested property.
 * @param property      The name of the requested property.
 * @param val_out       Output parameter which gets assigned to a
 *                      null-terminated string.
 * @return VB2_SUCCESS on success, or a relevant error upon error.
 */
vb2_error_t chromeos_config_get_string(const char *path, const char *property,
				       char **val_out);

/**
 * Get a value from the model configuration on the device as a boolean.
 *
 * @param path          The path in the config schema to the object containing
 *                      the requested property.
 * @param property      The name of the requested property.
 * @param val_out       Output parameter which gets assigned to a boolean.
 * @return VB2_SUCCESS on success, or a relevant error upon error.
 */
vb2_error_t chromeos_config_get_boolean(const char *path, const char *property,
					bool *val_out);

/**
 * Get a value from the model configuration on the device as an integer.
 *
 * @param path          The path in the config schema to the object containing
 *                      the requested property.
 * @param property      The name of the requested property.
 * @param val_out       Output parameter which gets assigned to an integer.
 * @return VB2_SUCCESS on success, or a relevant error upon error.
 */
vb2_error_t chromeos_config_get_integer(const char *path, const char *property,
					int *val_out);

#endif /* VBOOT_REFERENCE_CHROMEOS_CONFIG_H_ */
