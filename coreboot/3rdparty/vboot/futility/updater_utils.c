/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The utility functions for firmware updater.
 */

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#if defined (__FreeBSD__) || defined(__OpenBSD__)
#include <sys/wait.h>
#endif

#include "2common.h"
#include "cbfstool.h"
#include "host_misc.h"
#include "util_misc.h"
#include "updater.h"

#define COMMAND_BUFFER_SIZE 256

void strip_string(char *s, const char *pattern)
{
	int len;
	assert(s);

	len = strlen(s);
	while (len-- > 0) {
		if (pattern) {
			if (!strchr(pattern, s[len]))
				break;
		} else {
			if (!isascii(s[len]) || !isspace(s[len]))
				break;
		}
		s[len] = '\0';
	}
}

int save_file_from_stdin(const char *output)
{
	FILE *in = stdin, *out = fopen(output, "wb");
	char buffer[4096];
	size_t sz;

	assert(in);
	if (!out)
		return -1;

	while (!feof(in)) {
		sz = fread(buffer, 1, sizeof(buffer), in);
		if (fwrite(buffer, 1, sz, out) != sz) {
			fclose(out);
			return -1;
		}
	}
	fclose(out);
	return 0;
}

/*
 * Loads the firmware information from an FMAP section in loaded firmware image.
 * The section should only contain ASCIIZ string as firmware version.
 * Returns 0 if a non-empty version string is stored in *version, otherwise -1.
 */
static int load_firmware_version(struct firmware_image *image,
				 const char *section_name,
				 char **version)
{
	struct firmware_section fwid;
	int len = 0;

	/*
	 * section_name is NULL when parsing the RW versions on a non-vboot
	 * image (and already warned in load_firmware_image). We still need to
	 * initialize *version with empty string.
	 */
	if (section_name) {
		find_firmware_section(&fwid, image, section_name);
		if (fwid.size)
			len = fwid.size;
		else
			WARN("No valid section '%s', missing version info.\n",
			     section_name);
	}

	if (!len) {
		*version = strdup("");
		return -1;
	}

	/*
	 * For 'system current' images, the version string may contain
	 * invalid characters that we do want to strip.
	 */
	*version = strndup((const char *)fwid.data, len);
	strip_string(*version, "\xff");
	return 0;
}

static bool has_printable_ecrw_version(const struct firmware_image *image)
{
	/*
	 * Wilco family (sarien & drallion) has binary ecrw version which may
	 * contain non-printable characters. Those images can be identified by
	 * checking if the DIAG_NVRAM FMAP section exists or not.
	 */
	return !firmware_section_exists(image, FMAP_RW_DIAG_NVRAM);
}

/*
 * Loads the version of "ecrw" CBFS file within `section_name` of `image_file`.
 * Returns the version string on success; otherwise an empty string.
 */
static char *load_ecrw_version(const struct firmware_image *image,
			       const char *image_file,
			       const char *section_name)
{
	char *version = NULL;
	struct tempfile tempfile_head = {0};

	/* EC image or older AP images may not have the section. */
	if (!firmware_section_exists(image, section_name))
		goto done;

	if (!has_printable_ecrw_version(image))
		goto done;

	const char *ecrw_version_file = create_temp_file(&tempfile_head);
	if (!ecrw_version_file)
		goto done;

	/* "ecrw.version" doesn't exist in old images. */
	const char *ecrw_version_name = "ecrw.version";
	if (!cbfstool_file_exists(image_file, section_name, ecrw_version_name))
		goto done;

	if (cbfstool_extract(image_file, section_name, ecrw_version_name,
			     ecrw_version_file)) {
		ERROR("Failed to extract %s from %s\n",
		      ecrw_version_name, section_name);
		goto done;
	}

	uint8_t *data;
	uint32_t size;
	if (vb2_read_file(ecrw_version_file, &data, &size) != VB2_SUCCESS)
		goto done;

	version = strndup((const char *)data, size);

done:
	if (!version)
		version = strdup("");
	remove_all_temp_files(&tempfile_head);
	return version;
}

/* Loads the version of "ecrw" CBFS file for FW_MAIN_A and FW_MAIN_B. */
static void load_ecrw_versions(struct firmware_image *image)
{
	struct tempfile tempfile_head = {0};
	const char *image_file = get_firmware_image_temp_file(
			image, &tempfile_head);

	if (image_file) {
		image->ecrw_version_a = load_ecrw_version(
				image, image_file, FMAP_RW_FW_MAIN_A);
		image->ecrw_version_b = load_ecrw_version(
				image, image_file, FMAP_RW_FW_MAIN_B);
	}

	remove_all_temp_files(&tempfile_head);
}

/*
 * Fills in the other fields of image using image->data.
 * Returns IMAGE_LOAD_SUCCESS or IMAGE_PARSE_FAILURE.
 */
static int parse_firmware_image(struct firmware_image *image)
{
	int ret = IMAGE_LOAD_SUCCESS;
	const char *section_a = NULL, *section_b = NULL;

	VB2_DEBUG("Image size: %d\n", image->size);
	assert(image->data);

	image->fmap_header = fmap_find(image->data, image->size);

	if (!image->fmap_header) {
		ERROR("Invalid image file (missing FMAP): %s\n", image->file_name);
		ret = IMAGE_PARSE_FAILURE;
	}

	if (load_firmware_version(image, FMAP_RO_FRID, &image->ro_version))
		ret = IMAGE_PARSE_FAILURE;

	if (firmware_section_exists(image, FMAP_RW_FWID_A)) {
		section_a = FMAP_RW_FWID_A;
		section_b = FMAP_RW_FWID_B;
	} else if (firmware_section_exists(image, FMAP_RW_FWID)) {
		section_a = FMAP_RW_FWID;
		section_b = FMAP_RW_FWID;
	} else if (!ret) {
		ERROR("Unsupported VBoot firmware (no RW ID): %s\n", image->file_name);
		ret = IMAGE_PARSE_FAILURE;
	}

	/*
	 * Load and initialize both RW A and B sections.
	 * Note some unit tests will create only RW A.
	 */
	load_firmware_version(image, section_a, &image->rw_version_a);
	load_firmware_version(image, section_b, &image->rw_version_b);

	load_ecrw_versions(image);

	return ret;
}

int load_firmware_image(struct firmware_image *image, const char *file_name,
			struct u_archive *archive)
{
	if (!file_name) {
		ERROR("No file name given\n");
		return IMAGE_READ_FAILURE;
	}

	VB2_DEBUG("Load image file from %s...\n", file_name);

	if (!archive_has_entry(archive, file_name)) {
		ERROR("Does not exist: %s\n", file_name);
		return IMAGE_READ_FAILURE;
	}
	if (archive_read_file(archive, file_name, &image->data, &image->size,
			      NULL) != VB2_SUCCESS) {
		ERROR("Failed to load %s\n", file_name);
		return IMAGE_READ_FAILURE;
	}

	image->file_name = strdup(file_name);

	return parse_firmware_image(image);
}

void check_firmware_versions(const struct firmware_image *image)
{
	if (strcmp(image->rw_version_a, image->rw_version_b))
		WARN("Different versions in %s (%s) and %s (%s).\n",
		     FMAP_RW_FWID_A, image->rw_version_a,
		     FMAP_RW_FWID_B, image->rw_version_b);
	if (image->ecrw_version_a && image->ecrw_version_b &&
	    strcmp(image->ecrw_version_a, image->ecrw_version_b))
		WARN("Different ecrw versions in %s (%s) and %s (%s).\n",
		     FMAP_RW_FW_MAIN_A, image->ecrw_version_a,
		     FMAP_RW_FW_MAIN_B, image->ecrw_version_b);
}

const char *get_firmware_image_temp_file(const struct firmware_image *image,
					 struct tempfile *tempfiles)
{
	const char *tmp_path = create_temp_file(tempfiles);
	if (!tmp_path)
		return NULL;

	if (vb2_write_file(tmp_path, image->data, image->size) != VB2_SUCCESS) {
		ERROR("Failed writing %s firmware image (%u bytes) to %s.\n",
		      image->programmer ? image->programmer : "temp",
		      image->size, tmp_path);
		return NULL;
	}
	return tmp_path;
}

void free_firmware_image(struct firmware_image *image)
{
	/*
	 * The programmer is not allocated by load_firmware_image and must be
	 * preserved explicitly.
	 */
	const char *programmer = image->programmer;

	free(image->data);
	free(image->file_name);
	free(image->ro_version);
	free(image->rw_version_a);
	free(image->rw_version_b);
	free(image->ecrw_version_a);
	free(image->ecrw_version_b);
	memset(image, 0, sizeof(*image));
	image->programmer = programmer;
}

int reload_firmware_image(const char *file_path, struct firmware_image *image)
{
	free_firmware_image(image);
	return load_firmware_image(image, file_path, NULL);
}

int find_firmware_section(struct firmware_section *section,
			  const struct firmware_image *image,
			  const char *section_name)
{
	FmapAreaHeader *fah = NULL;
	uint8_t *ptr;

	section->data = NULL;
	section->size = 0;
	ptr = fmap_find_by_name(
			image->data, image->size, image->fmap_header,
			section_name, &fah);
	if (!ptr)
		return -1;
	section->data = (uint8_t *)ptr;
	section->size = fah->area_size;
	return 0;
}

int firmware_section_exists(const struct firmware_image *image,
			    const char *section_name)
{
	struct firmware_section section;
	find_firmware_section(&section, image, section_name);
	return section.data != NULL;
}

int preserve_firmware_section(const struct firmware_image *image_from,
			      struct firmware_image *image_to,
			      const char *section_name)
{
	struct firmware_section from, to;

	find_firmware_section(&from, image_from, section_name);
	find_firmware_section(&to, image_to, section_name);
	if (!from.data || !to.data) {
		VB2_DEBUG("Cannot find section %.*s: from=%p, to=%p\n",
			  FMAP_NAMELEN, section_name, from.data, to.data);
		return -1;
	}
	if (from.size > to.size) {
		WARN("Section %.*s is truncated after updated.\n",
		     FMAP_NAMELEN, section_name);
	}
	/* Use memmove in case if we need to deal with sections that overlap. */
	memmove(to.data, from.data, VB2_MIN(from.size, to.size));
	return 0;
}

const struct vb2_gbb_header *find_gbb(const struct firmware_image *image)
{
	struct firmware_section section;
	struct vb2_gbb_header *gbb_header;

	find_firmware_section(&section, image, FMAP_RO_GBB);
	gbb_header = (struct vb2_gbb_header *)section.data;
	if (!futil_valid_gbb_header(gbb_header, section.size, NULL)) {
		ERROR("Cannot find GBB in image: %s.\n", image->file_name);
		return NULL;
	}
	return gbb_header;
}

/*
 * Different settings may have different SWWP programmers.
 */
static bool is_write_protection_enabled(struct updater_config *cfg,
					const char *programmer,
					enum dut_property_type swwp_type)
{
	/* Assume HW/SW WP are enabled if -1 error code is returned */
	bool hwwp = !!dut_get_property(DUT_PROP_WP_HW, cfg);
	bool swwp = !!dut_get_property(swwp_type, cfg);
	bool wp_enabled = hwwp && swwp;
	STATUS("Write protection (%s): %d (%s; HW=%d, SW=%d).\n", programmer,
	       wp_enabled, wp_enabled ? "enabled" : "disabled", hwwp, swwp);
	return wp_enabled;
}

inline bool is_ap_write_protection_enabled(struct updater_config *cfg)
{
	return is_write_protection_enabled(cfg, cfg->image.programmer, DUT_PROP_WP_SW_AP);
}

inline bool is_ec_write_protection_enabled(struct updater_config *cfg)
{
	return is_write_protection_enabled(cfg, cfg->ec_image.programmer, DUT_PROP_WP_SW_EC);
}

char *host_shell(const char *command)
{
	/* Currently all commands we use do not have large output. */
	char buf[COMMAND_BUFFER_SIZE];

	int result;
	FILE *fp = popen(command, "r");

	VB2_DEBUG("%s\n", command);
	buf[0] = '\0';
	if (!fp) {
		VB2_DEBUG("Execution error for %s.\n", command);
		return strdup(buf);
	}

	if (fgets(buf, sizeof(buf), fp))
		strip_string(buf, NULL);
	result = pclose(fp);
	if (!WIFEXITED(result) || WEXITSTATUS(result) != 0) {
		VB2_DEBUG("Execution failure with exit code %d: %s\n",
			  WEXITSTATUS(result), command);
		/*
		 * Discard all output if command failed, for example command
		 * syntax failure may lead to garbage in stdout.
		 */
		buf[0] = '\0';
	}
	return strdup(buf);
}

void prepare_servo_control(const char *control_name, bool on)
{
	char *cmd;
	if (!control_name)
		return;

	ASPRINTF(&cmd, "dut-control %s:%s", control_name, on ? "on" : "off");
	free(host_shell(cmd));
	free(cmd);
}

char *host_detect_servo(const char **prepare_ctrl_name)
{
	const char *servo_port = getenv(ENV_SERVOD_PORT);
	const char *servo_name = getenv(ENV_SERVOD_NAME);
	const char *servo_id = servo_port, *servo_id_type = ENV_SERVOD_PORT;
	char *servo_type = host_shell("dut-control -o servo_type 2>/dev/null");
	const char *programmer = NULL;
	char *ret = NULL;
	char *servo_serial = NULL;

	static const char * const raiden_debug_spi = "raiden_debug_spi";
	static const char * const cpu_fw_spi = "cpu_fw_spi";
	static const char * const ccd_cpu_fw_spi = "ccd_cpu_fw_spi";
	const char *serial_cmd = "dut-control -o serialname 2>/dev/null";

	/* By default, no control is needed. */
	*prepare_ctrl_name = NULL;
	VB2_DEBUG("servo_type: %s\n", servo_type);

	/* dut-control defaults to port 9999, or non-empty servo_name. */
	if (!servo_id || !*servo_id) {
		if (servo_name && *servo_name) {
			servo_id = servo_name;
			servo_id_type = ENV_SERVOD_NAME;
		} else {
			servo_id = "9999";
		}
	}
	assert(servo_id && *servo_id);

	/* servo_type names: chromite/lib/firmware/servo_lib.py */
	if (!*servo_type) {
		ERROR("Failed to get servo type. Check servod.\n");
	} else if (strcmp(servo_type, "servo_v2") == 0) {
		VB2_DEBUG("Selected Servo V2.\n");
		programmer = "ft2232_spi:type=google-servo-v2";
		*prepare_ctrl_name = cpu_fw_spi;
	} else if (strstr(servo_type, "servo_micro")) {
		VB2_DEBUG("Selected Servo Micro.\n");
		programmer = raiden_debug_spi;
		*prepare_ctrl_name = cpu_fw_spi;
		serial_cmd = ("dut-control -o servo_micro_serialname"
			" 2>/dev/null");
	} else if (strstr(servo_type, "ccd_cr50") ||
		   strstr(servo_type, "ccd_gsc") ||
		   strstr(servo_type, "ccd_ti50")) {
		VB2_DEBUG("Selected CCD.\n");
		programmer = "raiden_debug_spi:target=AP,custom_rst=true";
		*prepare_ctrl_name = ccd_cpu_fw_spi;
		serial_cmd = "dut-control -o ccd_serialname 2>/dev/null";
	} else if (strstr(servo_type, "c2d2")) {
		/* Most C2D2 devices don't support flashing AP, so this must
		 * come after CCD.
		 */
		VB2_DEBUG("Selected C2D2.\n");
		programmer = raiden_debug_spi;
		*prepare_ctrl_name = cpu_fw_spi;
		serial_cmd = ("dut-control -o c2d2_serialname"
			" 2>/dev/null");
	} else {
		WARN("Unknown servo: %s\nAssuming debug header.\n", servo_type);
		programmer = raiden_debug_spi;
		*prepare_ctrl_name = cpu_fw_spi;
	}

	/*
	 * To support "multiple servos connected but only one servod running" we
	 * should always try to get the serial number.
	 */
	VB2_DEBUG("Select servod by %s=%s\n", servo_id_type, servo_id);
	servo_serial = host_shell(serial_cmd);
	VB2_DEBUG("Servo SN=%s (serial cmd: %s)\n", servo_serial, serial_cmd);
	if (!(servo_serial && *servo_serial)) {
		ERROR("Failed to get serial: %s=%s\n", servo_id_type, servo_id);
		/* If there is no servo serial, undo the prepare_ctrl_name. */
		*prepare_ctrl_name = NULL;
	} else if (programmer) {
		if (!servo_serial) {
			ret = strdup(programmer);
		} else {
			const char prefix = strchr(programmer, ':') ? ',' : ':';
			ASPRINTF(&ret, "%s%cserial=%s", programmer, prefix,
				 servo_serial);
		}
		VB2_DEBUG("Servo programmer: %s\n", ret);
	}

	free(servo_type);
	free(servo_serial);

	return ret;
}

/*
 * Returns 1 if the programmers in image1 and image2 are the same.
 */
static int is_the_same_programmer(const struct firmware_image *image1,
				  const struct firmware_image *image2)
{
	assert(image1 && image2);

	/* Including if both are NULL. */
	if (image1->programmer == image2->programmer)
		return 1;

	/* Not the same if either one is NULL. */
	if (!image1->programmer || !image2->programmer)
		return 0;

	return strcmp(image1->programmer, image2->programmer) == 0;
}

int load_system_firmware(struct updater_config *cfg,
			 struct firmware_image *image)
{
	if (!strcmp(image->programmer, FLASHROM_PROGRAMMER_INTERNAL_EC))
		WARN("%s: flashrom support for CrOS EC is EOL.\n", __func__);

	int r, i;
	const int tries = 1 + get_config_quirk(QUIRK_EXTRA_RETRIES, cfg);

	int verbose = cfg->verbosity + 1; /* libflashrom verbose 1 = WARN. */

	for (i = 1, r = -1; i <= tries && r != 0; i++, verbose++) {
		if (i > 1)
			WARN("Retry reading firmware (%d/%d)...\n", i, tries);
		INFO("Reading SPI Flash..\n");
		r = flashrom_read_image(image, NULL, 0, verbose);
	}
	if (r) {
		/* Read failure, the content cannot be trusted. */
		free_firmware_image(image);
	} else {
		/*
		 * Parse the contents. Note the image->data will remain even
		 * if parsing failed - this is important for system firmware
		 * because we may be trying to recover a device with corrupted
		 * firmware.
		 */
		r = parse_firmware_image(image);
	}
	return r;
}

int write_system_firmware(struct updater_config *cfg,
			  const struct firmware_image *image,
			  const char * const regions[],
				const size_t regions_len)
{
	if (!strcmp(image->programmer, FLASHROM_PROGRAMMER_INTERNAL_EC)) {
		WARN("%s: flashrom support for CrOS EC is EOL.\n", __func__);
	}

	int r = 0, i;
	const int tries = 1 + get_config_quirk(QUIRK_EXTRA_RETRIES, cfg);
	struct firmware_image *flash_contents = NULL;

	if (cfg->use_diff_image && cfg->image_current.data &&
	    is_the_same_programmer(&cfg->image_current, image))
		flash_contents = &cfg->image_current;

	int verbose = cfg->verbosity + 1; /* libflashrom verbose 1 = WARN. */

	for (i = 1, r = -1; i <= tries && r != 0; i++, verbose++) {
		if (i > 1)
			WARN("Retry writing firmware (%d/%d)...\n", i, tries);
		INFO("Writing SPI Flash..\n");
		r = flashrom_write_image(image, regions, regions_len,
					 flash_contents, cfg->do_verify,
					 verbose);
		/*
		 * Force a newline to flush stdout in case if
		 * flashrom_write_image left some messages in the buffer.
		 */
		fprintf(stdout, "\n");

	}
	return r;
}

const char *create_temp_file(struct tempfile *head)
{
	struct tempfile *new_temp;
	char new_path[] = VBOOT_TMP_DIR "/fwupdater.XXXXXX";

	int fd;
	mode_t umask_save;

	/* Set the umask before mkstemp for security considerations. */
	umask_save = umask(077);
	fd = mkstemp(new_path);
	umask(umask_save);
	if (fd < 0) {
		ERROR("Failed to create new temp file in %s\n", new_path);
		return NULL;
	}
	close(fd);
	new_temp = (struct tempfile *)malloc(sizeof(*new_temp));
	if (new_temp)
		new_temp->filepath = strdup(new_path);
	if (!new_temp || !new_temp->filepath) {
		remove(new_path);
		free(new_temp);
		ERROR("Failed to allocate buffer for new temp file.\n");
		return NULL;
	}
	VB2_DEBUG("Created new temporary file: %s.\n", new_path);
	new_temp->next = NULL;
	while (head->next)
		head = head->next;
	head->next = new_temp;
	return new_temp->filepath;
}

void remove_all_temp_files(struct tempfile *head)
{
	/* head itself is dummy and should not be removed. */
	assert(!head->filepath);
	struct tempfile *next = head->next;
	head->next = NULL;
	while (next) {
		head = next;
		next = head->next;
		assert(head->filepath);
		VB2_DEBUG("Remove temporary file: %s.\n", head->filepath);
		remove(head->filepath);
		free(head->filepath);
		free(head);
	}
}

const char *get_firmware_rootkey_hash(const struct firmware_image *image)
{
	const struct vb2_gbb_header *gbb = NULL;
	const struct vb2_packed_key *rootkey = NULL;

	assert(image->data);

	gbb = find_gbb(image);
	if (!gbb) {
		WARN("No GBB found in image.\n");
		return NULL;
	}

	rootkey = get_rootkey(gbb);
	if (!rootkey) {
		WARN("No rootkey found in image.\n");
		return NULL;
	}

	return packed_key_sha1_string(rootkey);
}

int overwrite_section(struct firmware_image *image,
			     const char *fmap_section, size_t offset,
			     size_t size, const uint8_t *new_values)
{
	struct firmware_section section;

	find_firmware_section(&section, image, fmap_section);
	if (section.size < offset + size) {
		ERROR("Section smaller than given offset + size\n");
		return -1;
	}

	if (memcmp(section.data + offset, new_values, size) == 0) {
		VB2_DEBUG("Section already contains given values.\n");
		return 0;
	}

	memcpy(section.data + offset, new_values, size);
	return 0;
}
