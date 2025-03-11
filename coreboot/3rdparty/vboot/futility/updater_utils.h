/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utilities for firmware updater.
 */

#ifndef VBOOT_REFERENCE_FUTILITY_UPDATER_UTILS_H_
#define VBOOT_REFERENCE_FUTILITY_UPDATER_UTILS_H_

#include <stdbool.h>
#include <stdio.h>
#include "fmap.h"

#define ASPRINTF(strp, ...) do { if (asprintf(strp, __VA_ARGS__) >= 0) break; \
	ERROR("Failed to allocate memory, abort.\n"); exit(1); } while (0)

/* Structure(s) declared in updater_archive */
struct u_archive;

/* Firmware slots */
static const char * const FWACT_A = "A",
		  * const FWACT_B = "B";

enum active_slot {
	SLOT_UNKNOWN = -1,
	SLOT_A = 0,
	SLOT_B,
};

/* Utilities for managing temporary files. */
struct tempfile {
	char *filepath;
	struct tempfile *next;
};

/*
 * Create a new temporary file.
 *
 * The parameter head refers to a linked list dummy head.
 * Returns the path of new file, or NULL on failure.
 */
const char *create_temp_file(struct tempfile *head);

/*
 * Remove all files created by create_temp_file().
 *
 * The parameter head refers to the dummy head of linked list.
 * This is intended to be called only once at end of program execution.
 */
void remove_all_temp_files(struct tempfile *head);

/* Include definition of 'struct firmware_image;' */
#include "flashrom.h"

enum {
	IMAGE_LOAD_SUCCESS = 0,
	IMAGE_READ_FAILURE = -1,
	IMAGE_PARSE_FAILURE = -2,
};

/*
 * Loads a firmware image from file.
 * If archive is provided and file_name is a relative path, read the file from
 * archive.
 * Returns IMAGE_LOAD_SUCCESS on success, IMAGE_READ_FAILURE on file I/O
 * failure, or IMAGE_PARSE_FAILURE for non-vboot images.
 */
int load_firmware_image(struct firmware_image *image, const char *file_name,
			struct u_archive *archive);

/* Structure(s) declared in updater.h */
struct updater_config;

/*
 * Loads the active system firmware image (usually from SPI flash chip).
 * Returns 0 if success. Returns IMAGE_PARSE_FAILURE for non-vboot images.
 * Returns other values for error.
 */
int load_system_firmware(struct updater_config *cfg,
			 struct firmware_image *image);

/* Frees the allocated resource from a firmware image object. */
void free_firmware_image(struct firmware_image *image);

/* Preserves meta data and reloads image contents from given file path. */
int reload_firmware_image(const char *file_path, struct firmware_image *image);

/* Checks the consistency of RW A and B firmware versions. */
void check_firmware_versions(const struct firmware_image *image);

/*
 * Generates a temporary file for snapshot of firmware image contents.
 *
 * Returns a file path if success, otherwise NULL.
 */
const char *get_firmware_image_temp_file(const struct firmware_image *image,
					 struct tempfile *tempfiles);

/*
 * Writes sections from a given firmware image to the system firmware.
 * regions_len should be zero for writing the whole image; otherwise, regions
 * should contain a list of FMAP section names of at least regions_len size.
 * Returns 0 if success, non-zero if error.
 */
int write_system_firmware(struct updater_config *cfg,
			  const struct firmware_image *image,
			  const char *const regions[], size_t regions_len);

struct firmware_section {
	uint8_t *data;
	size_t size;
};

/*
 * Returns true if the given FMAP section exists in the firmware image.
 */
int firmware_section_exists(const struct firmware_image *image,
			    const char *section_name);

/*
 * Finds a firmware section by given name in the firmware image.
 * If successful, return zero and *section argument contains the address and
 * size of the section; otherwise failure.
 */
int find_firmware_section(struct firmware_section *section,
			  const struct firmware_image *image,
			  const char *section_name);

/*
 * Preserves (copies) the given section (by name) from image_from to image_to.
 * The offset may be different, and the section data will be directly copied.
 * If the section does not exist on either images, return as failure.
 * If the source section is larger, contents on destination be truncated.
 * If the source section is smaller, the remaining area is not modified.
 * Returns 0 if success, non-zero if error.
 */
int preserve_firmware_section(const struct firmware_image *image_from,
			      struct firmware_image *image_to,
			      const char *section_name);

/*
 * Overwrite the given offset of a section in the firmware image with the
 * given values.
 * Returns 0 on success, otherwise failure.
 */
int overwrite_section(struct firmware_image *image,
			     const char *fmap_section, size_t offset,
			     size_t size, const uint8_t *new_values);

/*
 * Returns rootkey hash of firmware image, or NULL on failure.
 */
const char *get_firmware_rootkey_hash(const struct firmware_image *image);

/*
 * Finds the GBB (Google Binary Block) header on a given firmware image.
 * Returns a pointer to valid GBB header, or NULL on not found.
 */
struct vb2_gbb_header;
const struct vb2_gbb_header *find_gbb(const struct firmware_image *image);

/*
 * Strips a string (usually from shell execution output) by removing all the
 * trailing characters in pattern. If pattern is NULL, match by space type
 * characters (space, new line, tab, ... etc).
 */
void strip_string(char *s, const char *pattern);

/*
 * Saves everything from stdin to given output file.
 * Returns 0 on success, otherwise failure.
 */
int save_file_from_stdin(const char *output);

/*
 * Returns true if the AP write protection is enabled on current system.
 */
bool is_ap_write_protection_enabled(struct updater_config *cfg);

/*
 * Returns true if the EC write protection is enabled on current system.
 */
bool is_ec_write_protection_enabled(struct updater_config *cfg);

/*
 * Executes a command on current host and returns stripped command output.
 * If the command has failed (exit code is not zero), returns an empty string.
 * The caller is responsible for releasing the returned string.
 */
char *host_shell(const char *command);

/* The environment variable name for setting servod port. */
#define ENV_SERVOD_PORT	"SERVOD_PORT"

/* The environment variable name for setting servod name. */
#define ENV_SERVOD_NAME	"SERVOD_NAME"

/*
 * Helper function to detect type of Servo board attached to host.
 * Returns a string as programmer parameter on success, otherwise NULL.
 */
char *host_detect_servo(const char **prepare_ctrl_name);

/*
 * Makes a dut-control request for control_name.
 * Sets control_name to "on" if on is non zero, else "off".
 * Does not check for failure.
 */
void prepare_servo_control(const char *control_name, bool on);

/* DUT related functions (implementations in updater_dut.c) */

struct dut_property {
	int (*getter)(struct updater_config *cfg);
	int value;
	int initialized;
};

enum dut_property_type {
	DUT_PROP_MAINFW_ACT,
	DUT_PROP_TPM_FWVER,
	DUT_PROP_PLATFORM_VER,
	DUT_PROP_WP_HW,
	DUT_PROP_WP_SW_AP,
	DUT_PROP_WP_SW_EC,
	DUT_PROP_MAX
};

/* Helper function to initialize DUT properties. */
void dut_init_properties(struct dut_property *props, int num);

/* Gets the DUT system property by given type. Returns the property value. */
int dut_get_property(enum dut_property_type property_type,
		     struct updater_config *cfg);

int dut_set_property_string(const char *key, const char *value,
			    struct updater_config *cfg);
int dut_get_property_string(const char *key, char *dest, size_t size,
			    struct updater_config *cfg);
int dut_set_property_int(const char *key, const int value,
			 struct updater_config *cfg);
int dut_get_property_int(const char *key, struct updater_config *cfg);

/* Gets the 'firmware manifest key' on the DUT. */
int dut_get_manifest_key(char **manifest_key_out, struct updater_config *cfg);

#endif  /* VBOOT_REFERENCE_FUTILITY_UPDATER_UTILS_H_ */
