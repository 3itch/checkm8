/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "2common.h"
#include "2return_codes.h"
#include "chromeos_config.h"
#include "host_misc.h"

#define CHROMEOS_CONFIG_BASE "/run/chromeos-config/v1"

vb2_error_t chromeos_config_get_string(const char *path, const char *property,
				       char **val_out)
{
	vb2_error_t rv;
	uint32_t size;
	char filepath[PATH_MAX];

	*val_out = NULL;

	if (!path || path[0] != '/') {
		VB2_DEBUG("Path parameter must begin with /");
		return VB2_ERROR_INVALID_PARAMETER;
	}

	if (strstr(path, "//")) {
		VB2_DEBUG("Path cannot contain //");
		return VB2_ERROR_INVALID_PARAMETER;
	}

	if (strchr(property, '/')) {
		VB2_DEBUG("Property cannot contain /");
		return VB2_ERROR_INVALID_PARAMETER;
	}

	snprintf(filepath, sizeof(filepath), CHROMEOS_CONFIG_BASE "%s/%s", path,
		 property);
	rv = vb2_read_file(filepath, (uint8_t **)val_out, &size);

	if (rv == VB2_SUCCESS) {
		*val_out = realloc(*val_out, size + 1);
		(*val_out)[size] = '\0';
	}

	return rv;
}

vb2_error_t chromeos_config_get_boolean(const char *path, const char *property,
					bool *val_out)
{
	char *val_string;
	vb2_error_t rv;

	*val_out = false;
	if ((rv = chromeos_config_get_string(path, property, &val_string)) !=
	    VB2_SUCCESS)
		return rv;

	if (!strcmp(val_string, "false"))
		goto exit;

	if (!strcmp(val_string, "true")) {
		*val_out = true;
		goto exit;
	}

	VB2_DEBUG("Config entry is not a boolean: %s:%s", path, property);
	rv = VB2_ERROR_INVALID_PARAMETER;

 exit:
	free(val_string);
	return rv;
}

vb2_error_t chromeos_config_get_integer(const char *path, const char *property,
					int *val_out)
{
	char *endptr;
	char *val_string;
	vb2_error_t rv;

	*val_out = -1;
	if ((rv = chromeos_config_get_string(path, property, &val_string)) !=
	    VB2_SUCCESS)
		goto exit;

	errno = 0;
	*val_out = strtol(val_string, &endptr, 10);
	if (errno || endptr) {
		VB2_DEBUG("Config entry is not an integer: %s:%s", path,
			  property);
		rv = VB2_ERROR_INVALID_PARAMETER;
		goto exit;
	}

 exit:
	free(val_string);
	return rv;
}
