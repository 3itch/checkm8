/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * A reference implementation for AP (and supporting images) firmware updater.
 */

#include <assert.h>
#include <ctype.h>
#include <sys/stat.h>

#include "2rsa.h"
#include "cbfstool.h"
#include "futility.h"
#include "host_misc.h"
#include "platform_csme.h"
#include "updater.h"
#include "util_misc.h"

static const char ROOTKEY_HASH_DEV[] =
		"b11d74edd286c144e1135b49e7f0bc20cf041f10";

enum target_type {
	TARGET_SELF,
	TARGET_UPDATE,
};

enum rootkey_compat_result {
	ROOTKEY_COMPAT_OK,
	ROOTKEY_COMPAT_ERROR,
	ROOTKEY_COMPAT_REKEY,
	ROOTKEY_COMPAT_REKEY_TO_DEV,
};

static void print_dut_properties(struct updater_config *cfg)
{
	int i;

	/*
	 * There may be error messages when fetching properties from active
	 * system, so we want to peek at them first and then print out.
	 */
	VB2_DEBUG("Scanning system properties...\n");
	for (i = 0; i < DUT_PROP_MAX; i++)
		dut_get_property((enum dut_property_type)i, cfg);

	printf("System properties: [");
	for (i = 0; i < DUT_PROP_MAX; i++) {
		printf("%d,",
		       dut_get_property((enum dut_property_type)i, cfg));
	}
	printf("]\n");
}

/*
 * Overrides the return value of a system property.
 * After invoked, next call to dut_get_property(type, cfg) will return
 * the given value.
 */
static void override_dut_property(enum dut_property_type property_type,
				  struct updater_config *cfg, int value)
{
	struct dut_property *prop;

	assert(property_type < DUT_PROP_MAX);
	prop = &cfg->dut_properties[property_type];
	prop->initialized = 1;
	prop->value = value;
}

/*
 * Overrides DUT properties with default values.
 * With emulation, dut_get_property() calls would fail without specifying the
 * fake DUT properties via --sys_props. Therefore, this function provides
 * reasonable default values for emulation.
 */
static void override_properties_with_default(struct updater_config *cfg)
{
	assert(cfg->emulation);

	override_dut_property(DUT_PROP_MAINFW_ACT, cfg, SLOT_A);
	override_dut_property(DUT_PROP_TPM_FWVER, cfg, 0x10001);
	override_dut_property(DUT_PROP_PLATFORM_VER, cfg, 0);
	override_dut_property(DUT_PROP_WP_HW, cfg, 0);
	override_dut_property(DUT_PROP_WP_SW_AP, cfg, 0);
	override_dut_property(DUT_PROP_WP_SW_EC, cfg, 0);
}

/*
 * Overrides DUT properties from a given list.
 * The list should be string of integers eliminated by comma and/or space.
 * For example, "1 2 3" and "1,2,3" both overrides first 3 properties.
 * To skip some properties you have to use comma, for example
 * "1, , 3" will only override the first and 3rd properties.
 * Invalid characters and fields will be ignored.
 *
 * The current implementation is only for unit testing.
 * In future we may extend this with name=value so users can use it easily on
 * actual systems.
 */
static void override_properties_from_list(const char *override_list,
					  struct updater_config *cfg)
{
	const char *s = override_list;
	char *e, c;
	int i = 0, wait_comma = 0;
	long int v;

	VB2_DEBUG("Input is <%s>\n", override_list);
	for (c = *s; c; c = *++s) {
		if (c == ',') {
			if (!wait_comma)
				i++;
			wait_comma = 0;
		}
		if (!isascii(c) || !(isdigit(c) || c == '-'))
			continue;
		if (i >= DUT_PROP_MAX) {
			ERROR("Too many fields (max is %d): %s.\n",
			      DUT_PROP_MAX, override_list);
			return;
		}
		v = strtol(s, &e, 0);
		s = e - 1;
		VB2_DEBUG("property[%d].value = %ld\n", i, v);
		override_dut_property((enum dut_property_type)i, cfg, v);
		wait_comma = 1;
		i++;
	}
}

int get_config_quirk(enum quirk_types quirk, const struct updater_config *cfg)
{
	assert(quirk < QUIRK_MAX);
	return cfg->quirks[quirk].value;
}

void updater_list_config_quirks(const struct updater_config *cfg)
{
	const struct quirk_entry *entry = cfg->quirks;
	int i;

	printf("Supported quirks:\n");
	for (i = 0; i < QUIRK_MAX; i++, entry++) {
		printf(" '%s': %s (default: %d)\n", entry->name,
		       entry->help ? entry->help : "(no description)",
		       get_config_quirk((enum quirk_types)i, cfg));
	}
}

/*
 * Applies a quirk if applicable (the value should be non-zero).
 * Returns 0 on success, otherwise failure.
 */
static int try_apply_quirk(enum quirk_types quirk, struct updater_config *cfg)
{
	const struct quirk_entry *entry = cfg->quirks + quirk;
	assert(quirk < QUIRK_MAX);

	if (!entry->value)
		return 0;

	if (!entry->apply) {
		ERROR("<%s> not implemented.\n", entry->name);
		return -1;
	}
	VB2_DEBUG("Applying quirk <%s>.\n", entry->name);
	return entry->apply(cfg);
}

/*
 * Initialize the updater_config quirks from a list of settings.
 * Returns 0 on success, otherwise failure.
 */
static int setup_config_quirks(const char *quirks, struct updater_config *cfg)
{
	/*
	 * The list should be in NAME[=VALUE],...
	 * Value defaults to 1 if not specified.
	 */
	int r = 0;
	char *buf = strdup(quirks);
	char *token;
	const char *delimiters = ", \n\r\t";

	token = strtok(buf, delimiters);
	for (; token; token = strtok(NULL, delimiters)) {
		const char *name = token;
		char *equ = strchr(token, '=');
		int i, value = 1;
		struct quirk_entry *entry = cfg->quirks;

		if (!*name)
			continue;

		if (equ) {
			*equ = '\0';
			value = strtol(equ + 1, NULL, 0);
		}

		VB2_DEBUG("Looking for quirk <%s=%d>.\n", name, value);
		for (i = 0; i < QUIRK_MAX; i++, entry++) {
			if (strcmp(name, entry->name))
				continue;
			entry->value = value;
			VB2_DEBUG("Set quirk %s to %d.\n", entry->name, value);
			break;
		}
		if (i >= QUIRK_MAX) {
			ERROR("Unknown quirk: %s\n", name);
			r++;
		}
	}
	free(buf);
	return r;
}

/*
 * Checks if the section is filled with given character.
 * If section size is 0, return 0. If section is not empty, return non-zero if
 * the section is filled with same character c, otherwise 0.
 */
static int section_is_filled_with(const struct firmware_section *section,
				  uint8_t c)
{
	uint32_t i;
	if (!section->size)
		return 0;
	for (i = 0; i < section->size; i++)
		if (section->data[i] != c)
			return 0;
	return 1;
}

/*
 * Decides which target in RW firmware to manipulate.
 * The `target` argument specifies if we want to know "the section to be
 * update" (TARGET_UPDATE), or "the (active) section * to check" (TARGET_SELF).
 * Returns the section name if success, otherwise NULL.
 */
static const char *decide_rw_target(struct updater_config *cfg,
				    enum target_type target)
{
	const char *a = FMAP_RW_SECTION_A, *b = FMAP_RW_SECTION_B;
	int slot = dut_get_property(DUT_PROP_MAINFW_ACT, cfg);

	switch (slot) {
	case SLOT_A:
		return target == TARGET_UPDATE ? b : a;

	case SLOT_B:
		return target == TARGET_UPDATE ? a : b;
	}

	return NULL;
}

/*
 * Sets any needed DUT properties to indicate system should try the new
 * firmware on next boot.
 * The `target` argument is an FMAP section name indicating which to try.
 * Returns 0 if success, non-zero if error.
 */
static int set_try_cookies(struct updater_config *cfg, const char *target,
			   int has_update)
{
	int tries = 13;
	const char *slot;

	if (!has_update)
		tries = 0;

	/* Find new slot according to target (section) name. */
	if (strcmp(target, FMAP_RW_SECTION_A) == 0)
		slot = FWACT_A;
	else if (strcmp(target, FMAP_RW_SECTION_B) == 0)
		slot = FWACT_B;
	else {
		ERROR("Unknown target: %s\n", target);
		return -1;
	}

	if (cfg->emulation) {
		INFO("(emulation) %s slot %s on next boot, try_count=%d.\n",
		     has_update ? "Try" : "Keep", slot, tries);
		return 0;
	}

	if (dut_set_property_string("fw_try_next", slot, cfg)) {
		ERROR("Failed to set fw_try_next to %s.\n", slot);
		return -1;
	}
	if (!has_update &&
	    dut_set_property_string("fw_result", "success", cfg)) {
		ERROR("Failed to set fw_result to success.\n");
		return -1;
	}

	if (dut_set_property_int("fw_try_count", tries, cfg)) {
		ERROR("Failed to set fw_try_count to %d.\n", tries);
		return -1;
	}

	return 0;
}

/*
 * Returns True if we should start the update process for given image.
 */
static int has_valid_update(struct updater_config *cfg,
			const struct firmware_image *image,
			const char *section_name,
			int is_host)
{
	if (!image->data) {
		VB2_DEBUG("No data in <%s> image.\n", image->programmer);
		return 0;
	}
	if (section_name && !firmware_section_exists(image, section_name)) {
		VB2_DEBUG("Image %s<%s> does not have section %s.\n",
			  image->file_name, image->programmer, section_name);
		return 0;
	}
	/* Currently only host emulation is supported. */
	if (cfg->emulation && !is_host) {
		INFO("(emulation) Update %s from %s to %s (%d bytes), "
		     "skipped for non-host targets in emulation.\n",
		     section_name ? section_name : "whole image",
		     image->file_name, image->programmer, image->size);
		return 0;
	}
	return 1;
}

/*
 * Preserve the GBB contents from image_from to image_to.
 * HWID is always preserved, and flags are preserved only if preserve_flags set.
 * Returns 0 if success, otherwise -1 if GBB header can't be found or if HWID is
 * too large.
 */
static int preserve_gbb(const struct firmware_image *image_from,
			struct firmware_image *image_to,
			int preserve_flags, int override_flags,
			uint64_t override_value)
{
	const struct vb2_gbb_header *gbb_from;
	struct vb2_gbb_header *gbb_to;

	/* Cast to non-const because we do want to change GBB contents later. */
	gbb_to = (struct vb2_gbb_header *)find_gbb(image_to);

	/*
	 * For all cases, we need a valid gbb_to. Note for 'override GBB flags
	 * on a erased device', we only need gbb_to, not gbb_from.
	 */
	if (!gbb_to)
		return -1;

	gbb_from = find_gbb(image_from);

	/* Preserve (for non-factory mode) or override flags. */
	if (override_flags)
		gbb_to->flags = override_value;
	else if (preserve_flags && gbb_from)
		gbb_to->flags = gbb_from->flags;

	if (!gbb_from)
		return -1;

	/* Preserve HWID. */
	return futil_set_gbb_hwid(
			gbb_to, (const char *)gbb_from + gbb_from->hwid_offset);
}

/*
 * Preserves the regions locked by Intel management engine.
 */
static int preserve_management_engine(struct updater_config *cfg,
				      const struct firmware_image *image_from,
				      struct firmware_image *image_to)
{
	struct firmware_section section;

	find_firmware_section(&section, image_from, FMAP_SI_ME);
	if (!section.data) {
		VB2_DEBUG("Skipped because no section %s.\n", FMAP_SI_ME);
		return 0;
	}
	if (section_is_filled_with(&section, 0xFF)) {
		VB2_DEBUG("ME is probably locked - preserving %s.\n",
			  FMAP_SI_DESC);
		return preserve_firmware_section(
				image_from, image_to, FMAP_SI_DESC);
	}

	if (!strcmp(cfg->original_programmer, FLASHROM_PROGRAMMER_INTERNAL_AP)) {
		if (try_apply_quirk(QUIRK_PRESERVE_ME, cfg) > 0) {
			VB2_DEBUG("ME needs to be preserved - preserving %s.\n",
				  FMAP_SI_ME);
			return preserve_firmware_section(image_from, image_to,
							 FMAP_SI_ME);
		}
	} else {
		VB2_DEBUG("Flashing via non-host programmer %s - no need to "
			  "preserve ME.\n", image_from->programmer);
	}

	return 0;
}

/* Preserve firmware sections by FMAP area flags. */
static int preserve_fmap_sections(struct firmware_image *from,
				  struct firmware_image *to,
				  int *count)
{
	int i, errcnt = 0;
	FmapHeader *fmap = to->fmap_header;
	FmapAreaHeader *ah = (FmapAreaHeader*)(
			(uint8_t *)fmap + sizeof(FmapHeader));
	*count = 0;

	for (i = 0; i < fmap->fmap_nareas; i++, ah++) {
		if (!(ah->area_flags & FMAP_AREA_PRESERVE))
			continue;
		/* Warning: area_name 'may' not end with NUL. */
		if (!firmware_section_exists(from, ah->area_name)) {
			VB2_DEBUG("FMAP area does not exist in source: %.*s\n",
				  FMAP_NAMELEN, ah->area_name);
			continue;
		}
		VB2_DEBUG("Preserve FMAP area: %.*s\n", FMAP_NAMELEN,
			  ah->area_name);
		errcnt += preserve_firmware_section(from, to, ah->area_name);
		(*count)++;
	}

	return errcnt;
}

/*
 * Preserve old images without "preserve" information in FMAP.
 * We have to use the legacy hard-coded list of names.
 */
static int preserve_known_sections(struct firmware_image *from,
				   struct firmware_image *to)
{
	int errcnt = 0, i;
	const char * const names[] = {
		"RW_PRESERVE",  /* Only octopus fw branch is using this. */
		FMAP_RO_VPD,
		FMAP_RW_VPD,
		"SMMSTORE",
		"RW_NVRAM",
		"RW_ELOG",
	};

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (!firmware_section_exists(from, names[i]))
			continue;
		VB2_DEBUG("Preserve firmware section: %s\n", names[i]);
		errcnt += preserve_firmware_section(from, to, names[i]);
	}
	return errcnt;
}

/*
 * Preserves the critical sections from the current (active) firmware.
 * Currently preserved sections: GBB (HWID and flags), x86 ME, and any firmware
 * sections with FMAP_AREA_PRESERVE flag set (or a list of known names).
 * Returns 0 if success, non-zero if error.
 */
static int preserve_images(struct updater_config *cfg)
{
	int errcnt = 0, found;
	struct firmware_image *from = &cfg->image_current, *to = &cfg->image;

	errcnt += preserve_gbb(from, to, !cfg->factory_update,
			       cfg->override_gbb_flags, cfg->gbb_flags);
	errcnt += preserve_management_engine(cfg, from, to);
	errcnt += preserve_fmap_sections(from, to, &found);

	if (!found)
		errcnt += preserve_known_sections(from, to);

	return errcnt;
}

/*
 * Compares if two sections have same size and data.
 * Returns 0 if given sections are the same, otherwise non-zero.
 */
static int compare_section(const struct firmware_section *a,
			   const struct firmware_section *b)
{
	if (a->size != b->size)
		return a->size - b->size;
	return memcmp(a->data, b->data, a->size);
}

/*
 * Returns if the images are different (should be updated) in given section.
 * If the section contents are the same or if the section does not exist on both
 * images, return value is 0 (no need to update). Otherwise the return value is
 * non-zero, indicating an update should be performed.
 * If section_name is NULL, compare whole images.
 */
static int section_needs_update(const struct firmware_image *image_from,
				const struct firmware_image *image_to,
				const char *section_name)
{
	struct firmware_section from, to;

	if (!section_name) {
		if (image_from->size != image_to->size)
			return -1;
		return memcmp(image_from->data, image_to->data, image_to->size);
	}

	find_firmware_section(&from, image_from, section_name);
	find_firmware_section(&to, image_to, section_name);

	return compare_section(&from, &to);
}

/*
 * Checks if the system has locked AP RO (SI_DESC + Ti50 AP RO Verification).

 * b/284913015: When running on a DUT with SI_DESC, the SI_DESC may reject CPU
 * (AP) from changing itself. And if we keep updating (and skipped SI_DESC and
 * ME sections), the Ti50 AP RO verification via RO_GSCVD would fail because the
 * hash was from a different SI_DESC (and not updated).
 *
 * As a result, we don't want to do full update in this case. However
 * It is OK to do a full update if we are updating a remote DUT (via servo or
 * other programmers).
 *
 * Returns:
 *   True if AP is locked + verification enabled and we should skip updating RO.
 *   Otherwise false.
 */
static bool is_ap_ro_locked_with_verification(struct updater_config *cfg)
{
	struct firmware_image *current = &cfg->image_current;
	VB2_DEBUG("Checking if the system has locked AP RO (+verif).\n");

	if (cfg->dut_is_remote) {
		VB2_DEBUG("Remote DUT, assume the AP RO can be reflashed.\n");
		return false;
	}
	if (!firmware_section_exists(current, FMAP_RO_GSCVD)) {
		VB2_DEBUG("No %s, AP RO can be updated even if locked.\n", FMAP_RO_GSCVD);
		return false;
	}
	if (!firmware_section_exists(current, FMAP_SI_DESC)) {
		VB2_DEBUG("No %s, AP RO won't be locked.\n", FMAP_SI_DESC);
		return false;
	}
	if (!section_needs_update(&cfg->image, current, FMAP_SI_DESC)) {
		VB2_DEBUG("%s is exactly the same. RO update should be fine.\n", FMAP_SI_DESC);
		return false;
	}
	return is_flash_descriptor_locked(current);
}

/* Returns true if the UNLOCK_CSME_* quirks were requested, otherwise false. */
static bool is_unlock_csme_requested(struct updater_config *cfg)
{
	if (get_config_quirk(QUIRK_UNLOCK_CSME, cfg) ||
	    get_config_quirk(QUIRK_UNLOCK_CSME_EVE, cfg))
		return true;
	return false;
}

/*
 * Checks if the given firmware images are compatible with current platform.
 * In current implementation (following Chrome OS style), we assume the platform
 * is identical to the name before a dot (.) in firmware version.
 * Returns 0 for success, otherwise failure.
 */
static int check_compatible_platform(struct updater_config *cfg)
{
	int len;
	struct firmware_image *image_from = &cfg->image_current,
			      *image_to = &cfg->image;
	const char *from_dot = strchr(image_from->ro_version, '.'),
	           *to_dot = strchr(image_to->ro_version, '.');

	if (!from_dot || !to_dot) {
		VB2_DEBUG("Missing dot (from=%p, to=%p)\n", from_dot, to_dot);
		return -1;
	}
	len = from_dot - image_from->ro_version + 1;
	VB2_DEBUG("Platform: %*.*s\n", len, len, image_from->ro_version);
	return strncasecmp(image_from->ro_version, image_to->ro_version, len);
}

const struct vb2_packed_key *get_rootkey(
		const struct vb2_gbb_header *gbb)
{
	struct vb2_packed_key *key = NULL;

	key = (struct vb2_packed_key *)((uint8_t *)gbb + gbb->rootkey_offset);
	if (vb2_packed_key_looks_ok(key, gbb->rootkey_size)) {
		ERROR("Invalid root key.\n");
		return NULL;
	}
	return key;
}

/*
 * Returns a keyblock key from given image section, or NULL on failure.
 */
static const struct vb2_keyblock *get_keyblock(
		const struct firmware_image *image,
		const char *section_name)
{
	struct firmware_section section;

	if (find_firmware_section(&section, image, section_name) != 0) {
		ERROR("Section %s not found", section_name);
		return NULL;
	}
	const struct vb2_keyblock *block = (const struct vb2_keyblock *)section.data;
	if (vb2_check_keyblock(block, section.size, &block->keyblock_signature)) {
		ERROR("Invalid keyblock in %s\n", section_name);
		return NULL;
	}
	/* A keyblock must be followed by a vb2_fw_preamble. */
	if (section.size < block->keyblock_size + sizeof(struct vb2_fw_preamble)) {
		ERROR("Invalid section: %s\n", section_name);
		return NULL;
	}
	return block;
}

/*
 * Duplicates a keyblock and returns the duplicated block.
 * The caller must free the returned keyblock after being used.
 */
static struct vb2_keyblock *dupe_keyblock(const struct vb2_keyblock *block)
{
	struct vb2_keyblock *new_block;

	new_block = (struct vb2_keyblock *)malloc(block->keyblock_size);
	assert(new_block);
	memcpy(new_block, block, block->keyblock_size);
	return new_block;
}

/*
 * Verifies if keyblock is signed with given key.
 * Returns 0 on success, otherwise failure.
 */
static int verify_keyblock(const struct vb2_keyblock *block,
			   const struct vb2_packed_key *sign_key) {
	int r;
	uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
		__attribute__((aligned(VB2_WORKBUF_ALIGN)));
	struct vb2_workbuf wb;
	struct vb2_public_key key;
	struct vb2_keyblock *new_block;

	if (block->keyblock_signature.sig_size == 0) {
		ERROR("Keyblock is not signed.\n");
		return -1;
	}
	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));
	if (VB2_SUCCESS != vb2_unpack_key(&key, sign_key)) {
		ERROR("Invalid signing key.\n");
		return -1;
	}

	/*
	 * vb2_verify_keyblock will destroy the signature inside keyblock
	 * so we have to verify with a local copy.
	 */
	new_block = dupe_keyblock(block);
	r = vb2_verify_keyblock(new_block, new_block->keyblock_size, &key, &wb);
	free(new_block);

	if (r != VB2_SUCCESS) {
		ERROR("Failed verifying keyblock.\n");
		return -1;
	}
	return 0;
}

/*
 * Gets the data key and firmware version from a section on firmware image.
 * The section should contain a vb2_keyblock and a vb2_fw_preamble immediately
 * after keyblock so we can decode and save the data key and firmware version
 * into argument `data_key_version` and `firmware_version`.
 * Returns 0 for success, otherwise failure.
 */
static int get_key_versions(const struct firmware_image *image,
			    const char *section_name,
			    unsigned int *data_key_version,
			    unsigned int *firmware_version)
{
	const struct vb2_keyblock *keyblock = get_keyblock(image, section_name);
	const struct vb2_fw_preamble *pre;

	if (!keyblock)
		return -1;
	*data_key_version = keyblock->data_key.key_version;
	pre = (struct vb2_fw_preamble *)((uint8_t*)keyblock +
					 keyblock->keyblock_size);
	*firmware_version = pre->firmware_version;
	VB2_DEBUG("%s: data key version = %d, firmware version = %d\n",
		  image->file_name, *data_key_version, *firmware_version);
	return 0;
}

/*
 * Checks if the root key in ro_image can verify vblocks in rw_image.
 * Returns 0 for success, otherwise failure.
 */
static enum rootkey_compat_result check_compatible_root_key(
		const struct firmware_image *ro_image,
		const struct firmware_image *rw_image)
{
	const struct vb2_gbb_header *gbb = find_gbb(ro_image);
	const struct vb2_packed_key *rootkey;
	const struct vb2_keyblock *keyblock;

	if (!gbb)
		return ROOTKEY_COMPAT_ERROR;

	rootkey = get_rootkey(gbb);
	if (!rootkey)
		return ROOTKEY_COMPAT_ERROR;

	/* Assume VBLOCK_A and VBLOCK_B are signed in same way. */
	keyblock = get_keyblock(rw_image, FMAP_RW_VBLOCK_A);
	if (!keyblock)
		return ROOTKEY_COMPAT_ERROR;

	if (verify_keyblock(keyblock, rootkey) != 0) {
		const struct vb2_gbb_header *gbb_rw = find_gbb(rw_image);
		const struct vb2_packed_key *rootkey_rw = NULL;
		int is_same_key = 0, to_dev = 0;
		/*
		 * Try harder to provide more info.
		 * packed_key_sha1_string uses static buffer so don't call
		 * it twice in args list of one expression.
		 */
		if (gbb_rw)
			rootkey_rw = get_rootkey(gbb_rw);
		if (rootkey_rw) {
			if (rootkey->key_offset == rootkey_rw->key_offset &&
			    rootkey->key_size == rootkey_rw->key_size &&
			    memcmp(rootkey, rootkey_rw, rootkey->key_size +
				   rootkey->key_offset) == 0)
				is_same_key = 1;
			if (strcmp(packed_key_sha1_string(rootkey_rw),
				   ROOTKEY_HASH_DEV) == 0)
				to_dev = 1;
		}
		INFO("Current (RO) firmware image has root key: %s\n",
		     packed_key_sha1_string(rootkey));
		if (is_same_key) {
			ERROR("Rootkey is same as target (RW) image. \n"
			      "Maybe RW corrupted?");
			return ROOTKEY_COMPAT_ERROR;
		}
		WARN("Target (RW) image is signed by root key: %s%s\n",
		     rootkey_rw ? packed_key_sha1_string(rootkey_rw) :
		     "<invalid>", to_dev ? " (DEV/unsigned)" : "");
		return to_dev ? ROOTKEY_COMPAT_REKEY_TO_DEV :
				ROOTKEY_COMPAT_REKEY;
	}
	return ROOTKEY_COMPAT_OK;
}

/*
 * Returns non-zero if the RW_LEGACY needs to be updated, otherwise 0.
 */
static int legacy_needs_update(struct updater_config *cfg)
{
	bool has_from, has_to;
	const char * const tag = "cros_allow_auto_update";
	const char *section = FMAP_RW_LEGACY;
	const char *tmp_to, *tmp_from;

	VB2_DEBUG("Checking %s contents...\n", FMAP_RW_LEGACY);

	tmp_to = get_firmware_image_temp_file(&cfg->image, &cfg->tempfiles);
	tmp_from = get_firmware_image_temp_file(&cfg->image_current,
						&cfg->tempfiles);
	if (!tmp_from || !tmp_to)
		return 0;

	has_to = cbfstool_file_exists(tmp_to, section, tag);
	has_from = cbfstool_file_exists(tmp_from, section, tag);

	if (!has_from || !has_to) {
		VB2_DEBUG("Current legacy firmware has%s updater tag (%s) and "
			  "target firmware has%s updater tag, won't update.\n",
			  has_from ? "" : " no", tag, has_to ? "" : " no");
		return 0;
	}

	return section_needs_update(
			&cfg->image_current, &cfg->image, FMAP_RW_LEGACY);
}

/*
 * Checks if the given firmware image is signed with a key that won't be
 * blocked by TPM's anti-rollback detection.
 * Returns 0 for success, otherwise failure.
 */
static int do_check_compatible_tpm_keys(struct updater_config *cfg,
					const struct firmware_image *rw_image)
{
	unsigned int data_key_version = 0, firmware_version = 0,
		     tpm_data_key_version = 0, tpm_firmware_version = 0;
	int tpm_fwver = 0;

	/* Fail if the given image does not look good. */
	if (get_key_versions(rw_image, FMAP_RW_VBLOCK_A, &data_key_version,
			     &firmware_version) != 0)
		return -1;

	/* The stored tpm_fwver can be 0 (b/116298359#comment3). */
	tpm_fwver = dut_get_property(DUT_PROP_TPM_FWVER, cfg);
	if (tpm_fwver < 0) {
		/*
		 * tpm_fwver is commonly misreported in --ccd mode, so allow
		 * force_update to ignore the reported value.
		 */
		if (!cfg->force_update)
			ERROR("Invalid tpm_fwver: %d.\n", tpm_fwver);
		return -1;
	}

	tpm_data_key_version = tpm_fwver >> 16;
	tpm_firmware_version = tpm_fwver & 0xffff;
	VB2_DEBUG("TPM: data_key_version = %d, firmware_version = %d\n",
		  tpm_data_key_version, tpm_firmware_version);

	if (tpm_data_key_version > data_key_version) {
		ERROR("Data key version rollback detected (%d->%d).\n",
		      tpm_data_key_version, data_key_version);
		return -1;
	}
	if (tpm_firmware_version > firmware_version) {
		ERROR("Firmware version rollback detected (%d->%d).\n",
		      tpm_firmware_version, firmware_version);
		return -1;
	}
	return 0;
}

/*
 * Wrapper for do_check_compatible_tpm_keys.
 * Will return 0 if do_check_compatible_tpm_keys success or if cfg.force_update
 * is set; otherwise non-zero.
 */
static int check_compatible_tpm_keys(struct updater_config *cfg,
				     const struct firmware_image *rw_image)
{
	int r = do_check_compatible_tpm_keys(cfg, rw_image);
	if (!r)
		return r;
	if (!cfg->force_update) {
		ERROR("Add --force if you want to waive TPM checks.\n");
		return r;
	}
	WARN("TPM KEYS CHECK IS WAIVED BY --force. YOU ARE ON YOUR OWN.\n");
	return 0;
}


/*
 * Update EC (RO+RW) firmware if possible.
 * If the image has no data or if the section does not exist, ignore and return success.
 * Returns 0 if success, non-zero if error.
 */
static int update_ec_firmware(struct updater_config *cfg)
{
	struct firmware_image *ec_image = &cfg->ec_image;
	if (!has_valid_update(cfg, ec_image, NULL, 0))
		return 0;

	const char *sections[] = {"WP_RO"};
	size_t num_sections = 0;
	int r = try_apply_quirk(QUIRK_EC_PARTIAL_RECOVERY, cfg);
	switch (r) {
	case EC_RECOVERY_FULL:
		break; /* 0 num_sections implies write whole image. */

	case EC_RECOVERY_RO: {
		num_sections = ARRAY_SIZE(sections);
		break;
	}

	case EC_RECOVERY_DONE:
		/* Done by some quirks, for example EC RO software sync. */
		return 0;

	default:
		return r;
	}

	if (is_ec_write_protection_enabled(cfg)) {
		ERROR("Target ec is write protected, skip updating.\n");
		return 0;
	}

	/* TODO(quasisec): Uses cros_ec to program the EC. */
	return write_system_firmware(cfg, ec_image, sections, num_sections);
}

const char * const updater_error_messages[] = {
	[UPDATE_ERR_DONE] = "Done (no error)",
	[UPDATE_ERR_NEED_RO_UPDATE] = "RO changed and no WP. Need full update.",
	[UPDATE_ERR_NO_IMAGE] = "No image to update; try specify with -i.",
	[UPDATE_ERR_SYSTEM_IMAGE] = "Cannot load system active firmware.",
	[UPDATE_ERR_INVALID_IMAGE] = "The given firmware image is not valid.",
	[UPDATE_ERR_SET_COOKIES] = "Failed writing system flags to try update.",
	[UPDATE_ERR_WRITE_FIRMWARE] = "Failed writing firmware.",
	[UPDATE_ERR_PLATFORM] = "Your system platform is not compatible.",
	[UPDATE_ERR_TARGET] = "No valid RW target to update. Abort.",
	[UPDATE_ERR_ROOT_KEY] = "RW signed by incompatible root key "
			        "(different from RO).",
	[UPDATE_ERR_TPM_ROLLBACK] = "RW not usable due to TPM anti-rollback.",
	[UPDATE_ERR_UNLOCK_CSME] = "The CSME was already locked (b/284913015).",
	[UPDATE_ERR_UNKNOWN] = "Unknown error.",
};

/*
 * The main updater for "Legacy update".
 * This is equivalent to --mode=legacy.
 * Returns UPDATE_ERR_DONE if success, otherwise error.
 */
static enum updater_error_codes update_legacy_firmware(
		struct updater_config *cfg,
		struct firmware_image *image_to)
{
	STATUS("LEGACY UPDATE: Updating firmware %s.\n", FMAP_RW_LEGACY);

	const char *sections[] = {FMAP_RW_LEGACY};
	if (write_system_firmware(cfg, image_to, sections,
				  ARRAY_SIZE(sections)))
		return UPDATE_ERR_WRITE_FIRMWARE;

	return UPDATE_ERR_DONE;
}

/*
 * The main updater for "Try-RW update", to update only one RW section
 * and try if it can boot properly on reboot.
 * This was also known as --mode=autoupdate,--wp=1 in legacy updater.
 * Returns UPDATE_ERR_DONE if success, otherwise error.
 */
static enum updater_error_codes update_try_rw_firmware(
		struct updater_config *cfg,
		struct firmware_image *image_from,
		struct firmware_image *image_to,
		bool wp_enabled)
{
	const char *target, *self_target;
	int has_update = 1;

	preserve_gbb(image_from, image_to, 1, 0, 0);
	if (!wp_enabled && section_needs_update(
			image_from, image_to, FMAP_RO_SECTION))
		return UPDATE_ERR_NEED_RO_UPDATE;

	INFO("Checking compatibility...\n");
	if (check_compatible_root_key(image_from, image_to))
		return UPDATE_ERR_ROOT_KEY;
	if (check_compatible_tpm_keys(cfg, image_to))
		return UPDATE_ERR_TPM_ROLLBACK;

	self_target = target = decide_rw_target(cfg, TARGET_SELF);
	if (target == NULL) {
		ERROR("TRY-RW update needs system to boot in RW firmware.\n");
		return UPDATE_ERR_TARGET;
	}

	INFO("Checking %s contents...\n", target);
	if (!firmware_section_exists(image_to, target)) {
		ERROR("Cannot find section '%s' on firmware image: %s\n",
		      target, image_to->file_name);
		return UPDATE_ERR_INVALID_IMAGE;
	}
	if (!(cfg->force_update || cfg->try_update == TRY_UPDATE_DEFERRED_HOLD))
		has_update = section_needs_update(image_from, image_to, target);

	if (has_update) {
		target = decide_rw_target(cfg, TARGET_UPDATE);
		STATUS("TRY-RW UPDATE: Updating %s to try on reboot.\n",
		       target);

		const char *sections[] = {target};
		if (write_system_firmware(cfg, image_to, sections,
					  ARRAY_SIZE(sections)))
			return UPDATE_ERR_WRITE_FIRMWARE;

		/*
		 * If the firmware update requested is part of a deferred update
		 * HOLD action, the autoupdater/postinstall will later call
		 * defer update APPLY action to set the correct cookies. So here
		 * it is valid to keep the self slot as the active firmware even
		 * though the target slot is always updated (whether the current
		 * active firmware is the same version or not).
		 */
		if (cfg->try_update == TRY_UPDATE_DEFERRED_HOLD) {
			STATUS(
			    "DEFERRED UPDATE: Defer setting cookies for %s\n",
			    target);
			target = self_target;
			has_update = 0;
		}
	} else {
		STATUS("NO RW UPDATE: No update for RW firmware.\n");
	}

	/* Always set right cookies for next boot. */
	if (set_try_cookies(cfg, target, has_update))
		return UPDATE_ERR_SET_COOKIES;

	/* Do not fail on updating legacy. */
	if (legacy_needs_update(cfg)) {
		has_update = 1;
		update_legacy_firmware(cfg, image_to);
	}

	return UPDATE_ERR_DONE;
}

/*
 * The main updater for "RW update".
 * This was also known as --mode=recovery, --wp=1 in legacy updater.
 * Returns UPDATE_ERR_DONE if success, otherwise error.
 */
static enum updater_error_codes update_rw_firmware(
		struct updater_config *cfg,
		struct firmware_image *image_from,
		struct firmware_image *image_to)
{
	int i, num = 0;
	static const char * const required_sections[] = {
		FMAP_RW_SECTION_A,
		FMAP_RW_SECTION_B,
	};
	static const char * const optional_sections[] = {
		FMAP_RW_LEGACY,
		FMAP_RW_SHARED,
	};
	const char *sections[ARRAY_SIZE(required_sections) +
			     ARRAY_SIZE(optional_sections)];

	STATUS("RW UPDATE: Updating RW sections (%s, %s, %s, and %s).\n",
	       FMAP_RW_SECTION_A, FMAP_RW_SECTION_B, FMAP_RW_SHARED,
	       FMAP_RW_LEGACY);

	INFO("Checking compatibility...\n");
	if (check_compatible_root_key(image_from, image_to))
		return UPDATE_ERR_ROOT_KEY;
	if (check_compatible_tpm_keys(cfg, image_to))
		return UPDATE_ERR_TPM_ROLLBACK;

	for (i = 0; i < ARRAY_SIZE(required_sections); i++)
		sections[num++] = required_sections[i];

	/*
	 * The FMAP_RW_LEGACY is a special optional section.
	 * We may also consider only updating legacy if legacy_needs_update()
	 * returns true. However, given this is for 'recovery', it is probably
	 * better to restore everything to the default states. We may revisit
	 * this if a new scenario is found.
	 */
	for (i = 0; i < ARRAY_SIZE(optional_sections); i++) {
		const char *name = optional_sections[i];
		if (!firmware_section_exists(image_from, name) ||
		    !firmware_section_exists(image_to, name)) {
			VB2_DEBUG("Skipped optional section: %s\n", name);
			continue;
		}
		sections[num++] = name;
	}
	assert(num <= ARRAY_SIZE(sections));

	if (write_system_firmware(cfg, image_to, sections, num))
		return UPDATE_ERR_WRITE_FIRMWARE;

	return UPDATE_ERR_DONE;
}

/*
 * The main updater for "Full update".
 * This was also known as "--mode=factory" or "--mode=recovery, --wp=0" in
 * legacy updater.
 * Returns UPDATE_ERR_DONE if success, otherwise error.
 */
static enum updater_error_codes update_whole_firmware(
		struct updater_config *cfg,
		struct firmware_image *image_to)
{
	STATUS("FULL UPDATE: Updating whole firmware image(s), RO+RW.\n");

	if (preserve_images(cfg))
		VB2_DEBUG("Failed to preserve some sections - ignore.\n");

	INFO("Checking compatibility...\n");
	if (!cfg->force_update) {
		/* Check if the image_to itself is broken */
		enum rootkey_compat_result r = check_compatible_root_key(
				image_to, image_to);
		if (r != ROOTKEY_COMPAT_OK) {
			ERROR("Target image does not look valid. \n"
			      "Add --force if you really want to use it.");
			return UPDATE_ERR_ROOT_KEY;
		}

		/* Check if the system is going to re-key. */
		r = check_compatible_root_key(&cfg->image_current, image_to);
		/* We only allow re-key to non-dev keys. */
		switch (r) {
		case ROOTKEY_COMPAT_OK:
			break;
		case ROOTKEY_COMPAT_REKEY:
			INFO("Will change firmware signing key.\n");
			break;
		case ROOTKEY_COMPAT_REKEY_TO_DEV:
			ERROR("Re-key to DEV is not allowed. \n"
			      "Add --force if you really want to do that.");
			return UPDATE_ERR_ROOT_KEY;
		default:
			return UPDATE_ERR_ROOT_KEY;
		}
	}
	if (check_compatible_tpm_keys(cfg, image_to))
		return UPDATE_ERR_TPM_ROLLBACK;

	/* FMAP may be different so we should just update all. */
	if (write_system_firmware(cfg, image_to, NULL, 0) ||
	    update_ec_firmware(cfg))
		return UPDATE_ERR_WRITE_FIRMWARE;

	return UPDATE_ERR_DONE;
}

enum updater_error_codes update_firmware(struct updater_config *cfg)
{
	bool done = false;
	enum updater_error_codes r = UPDATE_ERR_UNKNOWN;

	/*
	 * For deferred update APPLY action, the only requirement is to set the
	 * correct cookies to the update target slot.
	 */
	if (cfg->try_update == TRY_UPDATE_DEFERRED_APPLY) {
		INFO("Apply deferred updates, only setting cookies for the "
		     "next boot slot.\n");
		if (set_try_cookies(cfg, decide_rw_target(cfg, TARGET_UPDATE),
				    /*has_update=*/1))
			return UPDATE_ERR_SET_COOKIES;
		return UPDATE_ERR_DONE;
	}

	struct firmware_image *image_from = &cfg->image_current,
			      *image_to = &cfg->image;
	if (!image_to->data)
		return UPDATE_ERR_NO_IMAGE;

	STATUS("Target image: %s (RO:%s, RW/A:%s (w/ECRW:%s), RW/B:%s (w/ECRW:%s)).\n",
	       image_to->file_name, image_to->ro_version,
	       image_to->rw_version_a, image_to->ecrw_version_a,
	       image_to->rw_version_b, image_to->ecrw_version_b);
	check_firmware_versions(image_to);

	try_apply_quirk(QUIRK_NO_VERIFY, cfg);
	if (try_apply_quirk(QUIRK_MIN_PLATFORM_VERSION, cfg)) {
		if (!cfg->force_update) {
			ERROR("Add --force to waive checking the version.\n");
			return UPDATE_ERR_PLATFORM;
		}
	}
	if (!image_from->data) {
		int ret;

		INFO("Loading current system firmware...\n");
		ret = load_system_firmware(cfg, image_from);
		if (ret == IMAGE_PARSE_FAILURE && cfg->force_update) {
			WARN("No compatible firmware in system.\n");
			cfg->check_platform = 0;
		} else if (ret)
			return UPDATE_ERR_SYSTEM_IMAGE;
	}
	STATUS("Current system: %s (RO:%s, RW/A:%s (w/ECRW:%s), RW/B:%s (w/ECRW:%s)).\n",
	       image_from->file_name, image_from->ro_version,
	       image_from->rw_version_a, image_from->ecrw_version_a,
	       image_from->rw_version_b, image_from->ecrw_version_b);

	try_apply_quirk(QUIRK_NO_CHECK_PLATFORM, cfg);
	if (cfg->check_platform && check_compatible_platform(cfg)) {
		ERROR("The firmware image is not compatible with your system. "
		      "If you really want to proceed, please run again with: "
		      "--quirks=no_check_platform\n");
		return UPDATE_ERR_PLATFORM;
	}

	bool wp_enabled = is_ap_write_protection_enabled(cfg);

	if (try_apply_quirk(QUIRK_ENLARGE_IMAGE, cfg))
		return UPDATE_ERR_SYSTEM_IMAGE;

	if (try_apply_quirk(QUIRK_EVE_SMM_STORE, cfg))
		return UPDATE_ERR_INVALID_IMAGE;

	if (try_apply_quirk(QUIRK_CLEAR_MRC_DATA, cfg))
		return UPDATE_ERR_SYSTEM_IMAGE;

	if (debugging_enabled)
		print_dut_properties(cfg);

	if (cfg->legacy_update)
		return update_legacy_firmware(cfg, image_to);

	if (cfg->try_update) {
		r = update_try_rw_firmware(cfg, image_from, image_to,
					   wp_enabled);
		if (r == UPDATE_ERR_NEED_RO_UPDATE)
			WARN("%s\n", updater_error_messages[r]);
		else
			done = true;
	}

	if (!done) {
		if (!wp_enabled && is_ap_ro_locked_with_verification(cfg)) {
			if (is_unlock_csme_requested(cfg))
				return UPDATE_ERR_UNLOCK_CSME;
			WARN("The AP RO is locked with verification turned on so we can't do "
			     "full update (b/284913015). Fall back to RW-only update.\n");
			wp_enabled = 1;
		}

		r = wp_enabled ? update_rw_firmware(cfg, image_from, image_to) :
				 update_whole_firmware(cfg, image_to);
	}

	/* Providing more hints for what to do on failure. */
	if (r == UPDATE_ERR_ROOT_KEY && wp_enabled)
		ERROR("To change keys in RO area, you must first remove "
		      "write protection.\n");

	return r;
}

struct updater_config *updater_new_config(void)
{
	struct updater_config *cfg = (struct updater_config *)calloc(
			1, sizeof(struct updater_config));
	if (!cfg)
		return cfg;
	cfg->image.programmer = FLASHROM_PROGRAMMER_INTERNAL_AP;
	cfg->image_current.programmer = FLASHROM_PROGRAMMER_INTERNAL_AP;
	cfg->original_programmer = FLASHROM_PROGRAMMER_INTERNAL_AP;
	cfg->ec_image.programmer = FLASHROM_PROGRAMMER_INTERNAL_EC;

	cfg->check_platform = 1;
	cfg->do_verify = 1;

	dut_init_properties(&cfg->dut_properties[0],
			    ARRAY_SIZE(cfg->dut_properties));
	updater_register_quirks(cfg);
	return cfg;
}

/*
 * Setup quirks for updating current image.
 *
 * Quirks must be loaded after image loaded because we use image contents to
 * decide default quirks to load. Also, we have to load default quirks first so
 * user can override them using command line.
 *
 * Returns 0 on success, otherwise number of failures.
 */
static int updater_setup_quirks(struct updater_config *cfg,
				const struct updater_config_arguments *arg)
{
	int errorcnt = 0;
	const char *model_quirks = updater_get_model_quirks(cfg);
	char *cbfs_quirks = updater_get_cbfs_quirks(cfg);

	if (model_quirks)
		errorcnt += !!setup_config_quirks(model_quirks, cfg);
	if (cbfs_quirks) {
		errorcnt += !!setup_config_quirks(cbfs_quirks, cfg);
		free(cbfs_quirks);
	}
	if (arg->quirks)
		errorcnt += !!setup_config_quirks(arg->quirks, cfg);
	return errorcnt;
}

/*
 * Loads images into updater configuration.
 * Returns 0 on success, otherwise number of failures.
 */
static int updater_load_images(struct updater_config *cfg,
			       const struct updater_config_arguments *arg,
			       const char *image,
			       const char *ec_image)
{
	int errorcnt = 0;
	struct u_archive *ar = cfg->archive;

	if (!cfg->image.data && image) {
		if (image && strcmp(image, "-") == 0) {
			INFO("Reading image from stdin...\n");
			image = create_temp_file(&cfg->tempfiles);
			if (image)
				errorcnt += !!save_file_from_stdin(image);
		}
		errorcnt += !!load_firmware_image(&cfg->image, image, ar);
		if (!errorcnt)
			errorcnt += updater_setup_quirks(cfg, arg);
	}

	/*
	 * In emulation mode, we want to prevent unexpected writing to EC
	 * so we should not load EC; however in output mode that is fine.
	 */
	if (arg->host_only || (arg->emulation && !cfg->output_only))
		return errorcnt;

	if (!cfg->ec_image.data && ec_image)
		errorcnt += !!load_firmware_image(&cfg->ec_image, ec_image, ar);

	return errorcnt;
}

/*
 * Writes a firmware image to specified file.
 * Returns 0 on success, otherwise failure.
 */
static int updater_output_image(const struct firmware_image *image,
				const char *fname, const char *root)
{
	int r = 0;
	char *fpath;

	if (!image->data)
		return 0;

	ASPRINTF(&fpath, "%s/%s", root, fname);
	r = vb2_write_file(fpath, image->data, image->size);
	if (r)
		ERROR("Failed writing firmware image to: %s\n", fpath);
	else
		printf("Firmware image saved in: %s\n", fpath);

	free(fpath);
	return !!r;
}

/*
 * Setup what the updater has to do against an archive.
 * Returns number of failures, or 0 on success.
 */
static int updater_setup_archive(
		struct updater_config *cfg,
		const struct updater_config_arguments *arg,
		struct manifest *manifest,
		int is_factory)
{
	int errorcnt = 0;
	struct u_archive *ar = cfg->archive;
	const struct model_config *model;

	if (cfg->detect_model)
		model = manifest_detect_model_from_frid(cfg, manifest);
	else
		model = manifest_find_model(cfg, manifest, arg->model);

	if (!model)
		return ++errorcnt;

	if (arg->detect_model_only) {
		puts(model->name);
		/* No additional error. */
		return errorcnt;
	}

	/* Load images now so we can get quirks in custom label checks. */
	errorcnt += updater_load_images(
			cfg, arg, model->image, model->ec_image);

	/*
	 * For custom label devices, we have to read the system firmware
	 * (image_current) to get the tag from VPD. Some quirks may also need
	 * the system firmware to identify if they should override the tags.
	 *
	 * The only exception is `--mode=output` (cfg->output_only), which we
	 * usually add `--model=MODEL` to specify the target model (note some
	 * people may still run without `--model` to get "the image to update
	 * when running on this device"). The MODEL can be either the BASEMODEL
	 * (has_custom_label=true) or BASEMODEL-TAG (has_custom_label=false).
	 * So the only case we have to warn the user that they may forget to
	 * provide the TAG is when has_custom_label=true (only BASEMODEL).
	 */
	if (cfg->output_only && arg->model && model->has_custom_label) {
		printf(">> Generating output for a custom label device without tags (e.g., base model). "
		       "The firmware images will be signed using the base model (or DEFAULT) keys. "
		       "To get the images signed by the LOEM keys, "
		       "add the corresponding tag from one of the following list: \n");

		size_t len = strlen(arg->model);
		bool printed = false;
		int i;

		for (i = 0; i < manifest->num; i++) {
			const struct model_config *m = &manifest->models[i];
			if (strncmp(m->name, arg->model, len) || m->name[len] != '-')
				continue;
			printf("%s `--model=%s`", printed ? "," : "", m->name);
			printed = true;
		}
		printf("\n\n");
	} else if (model->has_custom_label) {
		if (!cfg->image_current.data) {
			INFO("Loading system firmware for custom label...\n");
			load_system_firmware(cfg, &cfg->image_current);
		}

		if (!cfg->image_current.data) {
			ERROR("Cannot read the system firmware for tags.\n");
			return ++errorcnt;
		}
		/*
		 * For custom label devices, manifest_find_model may return the
		 * base model instead of the custom label ones so we have to
		 * look up again.
		 */
		const struct model_config *base_model = model;
		model = manifest_find_custom_label_model(cfg, manifest, base_model);
		if (!model)
			return ++errorcnt;
		/*
		 * All custom label models should share the same image, so we
		 * don't need to reload again - just pick up the new config and
		 * patch later. We don't care about EC images because that will
		 * be updated by software sync in the end.
		 * Here we want to double check if that assumption is correct.
		 */
		if (base_model->image) {
			if (!model->image ||
			    strcmp(base_model->image, model->image)) {
				ERROR("The firmware image for custom label [%s] "
				      "does not match its base model [%s]\n",
				      base_model->name, model->name);
				return ++errorcnt;
			}
		}
	}
	errorcnt += patch_image_by_model(&cfg->image, model, ar);
	return errorcnt;
}

static int check_arg_compatibility(
			 const struct updater_config_arguments *arg)
{
	/*
	 * The following args are mutually exclusive:
	 * - detect_model_only
	 * - do_manifest
	 * - repack
	 * - unpack
	 */
	if (arg->detect_model_only) {
		if (arg->do_manifest || arg->repack || arg->unpack) {
			ERROR("--manifest/--parseable-manifest/--repack/--unpack"
			      " is not compatible with --detect-model-only.\n");
			return -1;
		}
		if (!arg->archive) {
			ERROR("--detect-model-only needs --archive.\n");
			return -1;
		}
	} else if (arg->do_manifest) {
		if (arg->repack || arg->unpack) {
			ERROR("--repack/--unpack"
			      " is not compatible with --manifest/--parseable-manifest.\n");
			return -1;
		}
		if (!arg->archive && !(arg->image || arg->ec_image)) {
			ERROR("--manifest needs -a, -i or -e.\n");
			return -1;
		} else if (arg->archive && (arg->image || arg->ec_image)) {
			ERROR("--manifest for archive (-a) does not accept"
			      " additional images (--image, --ec_image).\n");
			return -1;
		}
	} else if (arg->repack || arg->unpack) {
		if (arg->repack && arg->unpack) {
			ERROR("--unpack is incompatible with --repack.\n");
			return -1;
		}
		if (!arg->archive) {
			ERROR("--{re,un}pack needs --archive.\n");
			return -1;
		}
	}

	return 0;
}

static int parse_arg_mode(struct updater_config *cfg,
			  const struct updater_config_arguments *arg)
{
	if (!arg->mode)
		return 0;

	if (strcmp(arg->mode, "autoupdate") == 0) {
		cfg->try_update = TRY_UPDATE_AUTO;
	} else if (strcmp(arg->mode, "deferupdate_hold") == 0) {
		cfg->try_update = TRY_UPDATE_DEFERRED_HOLD;
	} else if (strcmp(arg->mode, "deferupdate_apply") == 0) {
		cfg->try_update = TRY_UPDATE_DEFERRED_APPLY;
	} else if (strcmp(arg->mode, "recovery") == 0) {
		cfg->try_update = TRY_UPDATE_OFF;
	} else if (strcmp(arg->mode, "legacy") == 0) {
		cfg->legacy_update = 1;
	} else if (strcmp(arg->mode, "factory") == 0 ||
		   strcmp(arg->mode, "factory_install") == 0) {
		cfg->factory_update = 1;
	} else if (strcmp(arg->mode, "output") == 0) {
		cfg->output_only = true;
	} else {
		ERROR("Invalid mode: %s\n", arg->mode);
		return -1;
	}

	return 0;
}

static void prog_arg_setup(struct updater_config *cfg,
			   const struct updater_config_arguments *arg,
			   bool *check_single_image)
{
	if (!arg->programmer || !strcmp(arg->programmer, cfg->image.programmer))
		return;

	*check_single_image = true;
	/* DUT should be remote if the programmer is changed. */
	cfg->dut_is_remote = 1;
	INFO("Configured to update a remote DUT%s.\n",
	     arg->detect_servo ? " via Servo" : "");
	cfg->image.programmer = arg->programmer;
	cfg->image_current.programmer = arg->programmer;
	cfg->original_programmer = arg->programmer;
	VB2_DEBUG("AP (host) programmer changed to %s.\n",
		  arg->programmer);

	if (arg->archive && !arg->model)
		cfg->detect_model = true;
}

static int prog_arg_emulation(struct updater_config *cfg,
			      const struct updater_config_arguments *arg,
			      bool *check_single_image)
{
	if (!arg->emulation)
		return 0;

	VB2_DEBUG("Using file %s for emulation.\n", arg->emulation);
	*check_single_image = true;
	struct stat statbuf;
	if (stat(arg->emulation, &statbuf)) {
		ERROR("Failed to stat emulation file %s\n",
		      arg->emulation);
		return -1;
	}

	cfg->emulation = arg->emulation;
	/* Store ownership of the dummy programmer string in
	   cfg->emulation_programmer. */
	ASPRINTF(&cfg->emulation_programmer,
		 "dummy:emulate=VARIABLE_SIZE,size=%d,image=%s,bus=prog",
		 (int)statbuf.st_size, arg->emulation);

	cfg->image.programmer = cfg->emulation_programmer;
	cfg->image_current.programmer = cfg->emulation_programmer;

	return 0;
}

bool updater_should_update(const struct updater_config_arguments *arg)
{
	const bool do_output = arg->mode && !strcmp(arg->mode, "output");
	if (arg->detect_model_only || arg->do_manifest
		|| arg->repack || arg->unpack || do_output) {
		return false;
	}
	return true;
}

/*
 * Prints manifest.
 *
 * Returns number of errors on failure, or zero on success.
 */
static int print_manifest(const struct updater_config_arguments *arg)
{
	assert(arg->do_manifest);

	if (!arg->archive) {
		char name[] = "default";
		struct model_config model = {
			.name = name,
			.image = arg->image,
			.ec_image = arg->ec_image,
		};
		struct manifest manifest = {
			.num = 1,
			.models = &model,
		};
		if (arg->manifest_format == MANIFEST_PRINT_FORMAT_JSON) {
			print_json_manifest(&manifest);
		} else if (arg->manifest_format == MANIFEST_PRINT_FORMAT_PARSEABLE) {
			print_parseable_manifest(&manifest);
		} else {
			ERROR("Unknown manifest format requested: %d", arg->manifest_format);
			return 1;
		}
		return 0;
	}

	struct u_archive *archive = archive_open(arg->archive);
	if (!archive) {
		ERROR("Failed to open archive: %s\n", arg->archive);
		return 1;
	}

	if (arg->fast_update) {
		/* Quickly load and dump the manifest file from the archive. */
		const char *manifest_name = "manifest.json";
		uint8_t *data = NULL;
		uint32_t size = 0;

		if (arg->manifest_format != MANIFEST_PRINT_FORMAT_JSON) {
			ERROR("Only manifest format supported in fast mode is JSON.\n");
			return 1;
		}

		if (!archive_has_entry(archive, manifest_name) ||
		    archive_read_file(archive, manifest_name, &data, &size,
				      NULL)) {
			ERROR("Failed to read the cached manifest: %s\n",
			      manifest_name);
			return 1;
		}
		/* data is NUL-terminated. */
		printf("%s\n", data);
		free(data);
	} else {
		struct manifest *manifest =
			new_manifest_from_archive(archive);
		if (!manifest) {
			ERROR("Failed to read manifest from archive: %s\n",
			      arg->archive);
			return 1;
		}
		if (arg->manifest_format == MANIFEST_PRINT_FORMAT_JSON) {
			print_json_manifest(manifest);
		} else if (arg->manifest_format == MANIFEST_PRINT_FORMAT_PARSEABLE) {
			print_parseable_manifest(manifest);
		} else {
			ERROR("Unknown manifest format requested: %d", arg->manifest_format);
			delete_manifest(manifest);
			return 1;
		}
		delete_manifest(manifest);
	}

	return 0;
}

int updater_setup_config(struct updater_config *cfg,
			 const struct updater_config_arguments *arg)
{
	int errorcnt = 0;
	int check_wp_disabled = 0;
	bool check_single_image = false;
	const char *archive_path = arg->archive;

	/* Setup values that may change output or decision of other argument. */
	cfg->verbosity = arg->verbosity;
	cfg->use_diff_image = arg->fast_update;
	cfg->do_verify = !arg->fast_update;
	cfg->factory_update = arg->is_factory;
	if (arg->force_update)
		cfg->force_update = 1;

	/* Check incompatible options and return early. */
	if (check_arg_compatibility(arg) < 0)
		return 1;

	if (arg->detect_model_only) {
		cfg->detect_model = true;
	}

	/* Setup update mode. */
	if (arg->try_update)
		cfg->try_update = TRY_UPDATE_AUTO;

	if (parse_arg_mode(cfg, arg) < 0)
		return 1;

	if (cfg->factory_update) {
		/* factory_update must be processed after arg->mode. */
		check_wp_disabled = 1;
		cfg->try_update = TRY_UPDATE_OFF;
	}
	cfg->gbb_flags = arg->gbb_flags;
	cfg->override_gbb_flags = arg->override_gbb_flags;

	/* Setup properties and fields that do not have external dependency. */
	prog_arg_setup(cfg, arg, &check_single_image);
	if (prog_arg_emulation(cfg, arg, &check_single_image) < 0)
		return 1;

	if (arg->emulation)
		override_properties_with_default(cfg);
	if (arg->sys_props)
		override_properties_from_list(arg->sys_props, cfg);
	if (arg->write_protection) {
		/* arg->write_protection must be done after arg->sys_props. */
		int r = strtol(arg->write_protection, NULL, 0);
		override_dut_property(DUT_PROP_WP_HW, cfg, r);
		override_dut_property(DUT_PROP_WP_SW_AP, cfg, r);
	}

	/* Process the manifest. */
	if (arg->do_manifest) {
		errorcnt += print_manifest(arg);
		return errorcnt;
	}

	/* Always load images specified from command line directly. */
	errorcnt += updater_load_images(
			cfg, arg, arg->image, arg->ec_image);

	/* Set up archive. */
	if (!archive_path)
		archive_path = ".";
	cfg->archive = archive_open(archive_path);
	if (!cfg->archive) {
		ERROR("Failed to open archive: %s\n", archive_path);
		return ++errorcnt;
	}

	/* Process archives which may not have valid contents. */
	if (arg->repack || arg->unpack) {
		const char *work_name = arg->repack ? arg->repack : arg->unpack;
		struct u_archive *from, *to, *work;

		work = archive_open(work_name);
		if (arg->repack) {
			from = work;
			to = cfg->archive;
		} else {
			to = work;
			from = cfg->archive;
		}
		if (!work) {
			ERROR("Failed to open: %s\n", work_name);
			return ++errorcnt;
		}
		errorcnt += !!archive_copy(from, to);
		/* TODO(hungte) Update manifest after copied. */
		archive_close(work);
		return errorcnt;
	}

	/* Load images from the archive. */
	if (arg->archive) {
		struct manifest *m = new_manifest_from_archive(cfg->archive);
		if (m) {
			errorcnt += updater_setup_archive(
					cfg, arg, m, cfg->factory_update);
			delete_manifest(m);
		} else {
			ERROR("Failure in archive: %s\n", arg->archive);
			++errorcnt;
		}
	}

	/*
	 * Images should be loaded now (either in first updater_load_images or
	 * second call from updater_setup_archive) and quirks should be loaded.
	 * For invocation without image, we want to get quirks now.
	 */
	if (!cfg->image.data && arg->quirks)
		errorcnt += !!setup_config_quirks(arg->quirks, cfg);

	/* Additional checks. */
	if (check_single_image && !cfg->output_only && cfg->ec_image.data) {
		errorcnt++;
		ERROR("EC/PD images are not supported in current mode.\n");
	}
	if (check_wp_disabled && is_ap_write_protection_enabled(cfg)) {
		errorcnt++;
		ERROR("Please remove write protection for factory mode\n");
	}

	if (cfg->image.data) {
		/* Apply any quirks to modify the image before updating. */
		if (arg->unlock_me)
			cfg->quirks[QUIRK_UNLOCK_CSME].value = 1;
		errorcnt += try_apply_quirk(QUIRK_UNLOCK_CSME_EVE, cfg);
		errorcnt += try_apply_quirk(QUIRK_UNLOCK_CSME, cfg);
	}

	/* The images are ready for updating. Output if needed. */
	if (!errorcnt && cfg->output_only) {
		const char *r = arg->output_dir;
		if (!r)
			r = ".";

		/* TODO(hungte) Remove bios.bin when migration is done. */
		errorcnt += updater_output_image(&cfg->image, "bios.bin", r);
		errorcnt += updater_output_image(&cfg->image, "image.bin", r);
		errorcnt += updater_output_image(&cfg->ec_image, "ec.bin", r);
	}
	return errorcnt;
}

/* Enough to hold standard CCD programmer options plus serial number */
static char ccd_programmer[128];

int handle_flash_argument(struct updater_config_arguments *args, int opt,
			  char *optarg)
{
	int ret;
	switch (opt) {
	case 'p':
		args->use_flash = 1;
		args->programmer = optarg;
		break;
	case OPT_CCD:
		args->use_flash = 1;
		args->fast_update = 1;
		args->force_update = 1;
		args->write_protection = "0";
		ret = snprintf(ccd_programmer, sizeof(ccd_programmer),
			       "raiden_debug_spi:target=AP%s%s",
			       optarg ? ",serial=" : "", optarg ?: "");
		if (ret >= sizeof(ccd_programmer)) {
			ERROR("%s: CCD serial number was too long\n", __func__);
			return 0;
		}
		args->programmer = ccd_programmer;
		break;
	case OPT_EMULATE:
		args->use_flash = 1;
		args->emulation = optarg;
		break;
	case OPT_SERVO:
		args->use_flash = 1;
		args->detect_servo = 1;
		args->fast_update = 1;
		args->force_update = 1;
		args->write_protection = "0";
		args->host_only = 1;
		break;
	case OPT_SERVO_PORT:
		setenv(ENV_SERVOD_PORT, optarg, 1);
		args->use_flash = 1;
		args->detect_servo = 1;
		args->fast_update = 1;
		args->force_update = 1;
		args->write_protection = "0";
		args->host_only = 1;
		break;
	default:
		return 0;
	}
	return 1;
}

void updater_delete_config(struct updater_config *cfg)
{
	assert(cfg);
	free_firmware_image(&cfg->image);
	free_firmware_image(&cfg->image_current);
	free_firmware_image(&cfg->ec_image);
	cfg->image.programmer = cfg->original_programmer;
	cfg->image_current.programmer = cfg->original_programmer;
	free(cfg->emulation_programmer);
	remove_all_temp_files(&cfg->tempfiles);
	if (cfg->archive)
		archive_close(cfg->archive);
	free(cfg);
}
