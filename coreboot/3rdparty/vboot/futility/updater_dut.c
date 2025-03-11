/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The DUT interface helper functions for the firmware updater.
 */

#include <assert.h>
#ifdef HAVE_CROSID
#include <crosid.h>
#endif
#include <limits.h>
#include "crossystem.h"
#include "updater.h"

int dut_get_manifest_key(char **manifest_key_out, struct updater_config *cfg)
{
	if (cfg->dut_is_remote) {
		WARN("Cannot retrieve the remote DUT manifest info. "
		     "Please specify the DUT type by --model.\n");
		return -1;
	}
#ifdef HAVE_CROSID
	return crosid_get_firmware_manifest_key(manifest_key_out);
#else
	ERROR("This version of futility was compiled without libcrosid "
	      "(perhaps compiled outside of the Chrome OS build system?) and "
	      "the update command is not fully supported.  Either compile "
	      "from the Chrome OS build, or pass --model to manually specify "
	      "the machine model.\n");
	return -1;
#endif
}

int dut_set_property_string(const char *key, const char *value,
			    struct updater_config *cfg)
{
	if (cfg->dut_is_remote) {
		WARN("Ignored setting property %s on a remote DUT.\n", key);
		return -1;
	}
	return VbSetSystemPropertyString(key, value);
}

int dut_get_property_string(const char *key, char *dest, size_t size,
			    struct updater_config *cfg)
{
	if (cfg->dut_is_remote) {
		WARN("Ignored getting property %s on a remote DUT.\n", key);
		return -1;
	}
	return VbGetSystemPropertyString(key, dest, size);
}

int dut_set_property_int(const char *key, const int value,
			 struct updater_config *cfg)
{
	if (cfg->dut_is_remote) {
		WARN("Ignored setting property %s on a remote DUT.\n", key);
		return -1;
	}
	return VbSetSystemPropertyInt(key, value);
}

int dut_get_property_int(const char *key, struct updater_config *cfg)
{
	if (cfg->dut_is_remote) {
		WARN("Ignored getting property %s on a remote DUT.\n", key);
		return -1;
	}
	return VbGetSystemPropertyInt(key);
}

/* An helper function to return "mainfw_act" system property.  */
static int dut_get_mainfw_act(struct updater_config *cfg)
{
	char buf[VB_MAX_STRING_PROPERTY];

	if (dut_get_property_string("mainfw_act", buf, sizeof(buf), cfg) != 0)
		return SLOT_UNKNOWN;

	if (strcmp(buf, FWACT_A) == 0)
		return SLOT_A;
	else if (strcmp(buf, FWACT_B) == 0)
		return SLOT_B;

	return SLOT_UNKNOWN;
}

/* A helper function to return the "tpm_fwver" system property. */
static int dut_get_tpm_fwver(struct updater_config *cfg)
{
	return dut_get_property_int("tpm_fwver", cfg);
}

/* A helper function to return the "hardware write protection" status. */
static int dut_get_wp_hw(struct updater_config *cfg)
{
	/* wpsw refers to write protection 'switch', not 'software'. */
	return dut_get_property_int("wpsw_cur", cfg);
}

static int dut_get_platform_version(struct updater_config *cfg)
{
	long rev = dut_get_property_int("board_id", cfg);
	/* Assume platform version = 0 on error. */
	if (rev < 0)
		rev = 0;
	if (rev > INT_MAX)
		rev = INT_MAX;
	return rev;
}

/* Helper function to return host software write protection status. */
static int dut_get_wp_sw(const char *programmer)
{
	assert(programmer);
	bool mode;

	if (flashrom_get_wp(programmer, &mode, NULL, NULL, -1)) {
		/* Read WP status error */
		return -1;
	}
	return mode;
}

/* Helper function to return host AP software write protection status. */
static inline int dut_get_wp_sw_ap(struct updater_config *cfg)
{
	return dut_get_wp_sw(cfg->image.programmer);
}

/* Helper function to return host EC software write protection status. */
static inline int dut_get_wp_sw_ec(struct updater_config *cfg)
{
	return dut_get_wp_sw(cfg->ec_image.programmer);
}

/* Helper functions to use or configure the DUT properties. */

int dut_get_property(enum dut_property_type property_type,
		     struct updater_config *cfg)
{
	struct dut_property *prop;

	assert(property_type < DUT_PROP_MAX);
	prop = &cfg->dut_properties[property_type];
	if (!prop->initialized) {
		prop->initialized = 1;
		prop->value = prop->getter(cfg);
	}
	return prop->value;
}

void dut_init_properties(struct dut_property *props, int num)
{
	memset(props, 0, num * sizeof(*props));
	assert(num >= DUT_PROP_MAX);
	props[DUT_PROP_MAINFW_ACT].getter = dut_get_mainfw_act;
	props[DUT_PROP_TPM_FWVER].getter = dut_get_tpm_fwver;
	props[DUT_PROP_PLATFORM_VER].getter = dut_get_platform_version;
	props[DUT_PROP_WP_HW].getter = dut_get_wp_hw;
	props[DUT_PROP_WP_SW_AP].getter = dut_get_wp_sw_ap;
	props[DUT_PROP_WP_SW_EC].getter = dut_get_wp_sw_ec;
}
