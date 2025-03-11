/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Build up the list of updater resources from an archive.
 */

#include <assert.h>
#if defined(__OpenBSD__)
#include <sys/types.h>
#endif

#include "updater.h"
#include "util_misc.h"

/*
 * The updater reads image files from a package. The package is usually an
 * archive (see updater_archive.c) with image files and configuration files, and
 * the meta data is maintained by a "manifest" that described below.
 *
 * A package for a single board (i.e., not Unified Build) will have all the
 * image files in the top folder:
 *  - host: 'image.bin'
 *  - ec: 'ec.bin'
 *
 * A package for Unified Build is more complicated.
 *
 * You need to look at the signer_config.csv file to find the columns of
 * model_name, image files (firmware_image, ec_image) and then search for
 * patch files (root key, vblock files, GSC verification data, ...) in the
 * keyset/ folder:
 *
 *  - rootkey.$MODEL_NAME
 *  - vblock_A.$MODEL_NAME
 *  - vblock_B.$MODEL_NAME
 *  - gscvd.$MODEL_NAME
 *
 * In the runtime, the updater should query for firmware manifest key (
 * `crosid -f FIRMWARE_MANIFEST_KEY`) and use that to match the 'model_name'
 * in the manifest database.
 *
 * If the model_name in `signer_config.csv` contains '-' then it is a custom
 * label device. Today the FIRMWARE_MANIFEST_KEY from crosid won't handle custom
 * label information and we have to add the custom label tag in the matching
 * process.
 *
 * To do that, find the custom label tag from the VPD.
 * - Newer devices: model_name = FIRMWARE_MANIFEST_KEY-$custom_label_tag
 * - Old devices: model_name = FIRMWARE_MANIFEST_KEY-$whitelabel_tag
 *
 * For legacy devices manufactured before Unified Build, they have the VPD
 * 'customization_id' in a special format: LOEM[-VARIANT].
 * For example: "A-B" => LOEM="A".
 * - Legacy devices: model_name = FIRMWARE_MANIFEST_KEY-$LOEM
 */

static const char * const DEFAULT_MODEL_NAME = "default",
		  * const VPD_CUSTOM_LABEL_TAG = "custom_label_tag",
		  * const VPD_CUSTOM_LABEL_TAG_LEGACY = "whitelabel_tag",
		  * const VPD_CUSTOMIZATION_ID = "customization_id",
		  * const PATH_KEYSET_FOLDER = "keyset/",
		  * const PATH_SIGNER_CONFIG = "signer_config.csv";

/* Utility function to convert a string. */
static void str_convert(char *s, int (*convert)(int c))
{
	int c;

	for (; *s; s++) {
		c = *s;
		if (!isascii(c))
			continue;
		*s = convert(c);
	}
}

/* Returns the VPD value by given key name, or NULL on error (or no value). */
static char *vpd_get_value(const char *fpath, const char *key)
{
	char *command, *result;

	assert(fpath);
	ASPRINTF(&command, "vpd -g %s -f %s 2>/dev/null", key, fpath);
	result = host_shell(command);
	free(command);

	if (result && !*result) {
		free(result);
		result = NULL;
	}
	return result;
}

/*
 * Changes the rootkey in firmware GBB to given new key.
 * Returns 0 on success, otherwise failure.
 */
static int change_gbb_rootkey(struct firmware_image *image,
			      const char *section_name,
			      const uint8_t *rootkey, uint32_t rootkey_len)
{
	const struct vb2_gbb_header *gbb = find_gbb(image);
	uint8_t *gbb_rootkey;
	if (!gbb) {
		ERROR("Cannot find GBB in image %s.\n", image->file_name);
		return -1;
	}
	if (gbb->rootkey_size < rootkey_len) {
		ERROR("New root key (%u bytes) larger than GBB (%u bytes).\n",
		      rootkey_len, gbb->rootkey_size);
		return -1;
	}

	gbb_rootkey = (uint8_t *)gbb + gbb->rootkey_offset;
	/* See cmd_gbb_utility: root key must be first cleared with zero. */
	memset(gbb_rootkey, 0, gbb->rootkey_size);
	memcpy(gbb_rootkey, rootkey, rootkey_len);
	return 0;
}

/*
 * Changes the firmware section (for example vblock or GSCVD) to new data.
 * Returns 0 on success, otherwise failure.
 */
static int change_section(struct firmware_image *image,
			  const char *section_name,
			  const uint8_t *data, uint32_t data_len)
{
	struct firmware_section section;

	find_firmware_section(&section, image, section_name);
	if (!section.data) {
		ERROR("Need section %s in image %s.\n", section_name,
		      image->file_name);
		return -1;
	}
	if (section.size < data_len) {
		ERROR("'%s' is too small (%zu bytes) for patching %u bytes.\n",
		      section_name, section.size, data_len);
		return -1;
	}
	/* First erase (0xff) the section in case the new data is smaller. */
	memset(section.data, 0xff, section.size);
	memcpy(section.data, data, data_len);
	return 0;
}

/*
 * Applies a key file to firmware image.
 * Returns 0 on success, otherwise failure.
 */
static int apply_key_file(
		struct firmware_image *image, const char *path,
		struct u_archive *archive, const char *section_name,
		int (*apply)(struct firmware_image *image, const char *section,
			     const uint8_t *data, uint32_t len))
{
	int r = 0;
	uint8_t *data = NULL;
	uint32_t len;

	r = archive_read_file(archive, path, &data, &len, NULL);
	if (r == 0) {
		VB2_DEBUG("Loaded file: %s\n", path);
		r = apply(image, section_name, data, len);
		if (r)
			ERROR("Failed applying %s to %s\n", path, section_name);
	} else {
		ERROR("Failed reading: %s\n", path);
	}
	free(data);
	return r;
}

/*
 * Modifies a firmware image from patch information specified in model config.
 * Returns 0 on success, otherwise number of failures.
 */
int patch_image_by_model(
		struct firmware_image *image, const struct model_config *model,
		struct u_archive *archive)
{
	int err = 0;
	if (model->patches.rootkey)
		err += !!apply_key_file(
				image, model->patches.rootkey, archive,
				FMAP_RO_GBB, change_gbb_rootkey);
	if (model->patches.vblock_a)
		err += !!apply_key_file(
				image, model->patches.vblock_a, archive,
				FMAP_RW_VBLOCK_A, change_section);
	if (model->patches.vblock_b)
		err += !!apply_key_file(
				image, model->patches.vblock_b, archive,
				FMAP_RW_VBLOCK_B, change_section);
	if (model->patches.gscvd)
		err += !!apply_key_file(
				image, model->patches.gscvd, archive,
				FMAP_RO_GSCVD, change_section);
	return err;
}

/*
 * Finds available patch files by given model.
 * Updates `model` argument with path of patch files.
 */
static void find_patches_for_model(struct model_config *model,
				   struct u_archive *archive)
{
	char *path;
	int i;

	const char * const names[] = {
		"rootkey",
		"vblock_A",
		"vblock_B",
		"gscvd",
	};

	char **targets[] = {
		&model->patches.rootkey,
		&model->patches.vblock_a,
		&model->patches.vblock_b,
		&model->patches.gscvd,
	};

	assert(ARRAY_SIZE(names) == ARRAY_SIZE(targets));
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		ASPRINTF(&path, "%s%s.%s", PATH_KEYSET_FOLDER, names[i], model->name);
		if (archive_has_entry(archive, path))
			*targets[i] = path;
		else
			free(path);
	}
}

/*
 * Adds and copies one new model config to the existing list of given manifest.
 * Returns a pointer to the newly allocated config, or NULL on failure.
 */
static struct model_config *manifest_add_model(
		struct manifest *manifest,
		const struct model_config *cfg)
{
	struct model_config *model;
	manifest->num++;
	manifest->models = (struct model_config *)realloc(
			manifest->models, manifest->num * sizeof(*model));
	if (!manifest->models) {
		ERROR("Internal error: failed to allocate buffer.\n");
		return NULL;
	}
	model = &manifest->models[manifest->num - 1];
	memcpy(model, cfg, sizeof(*model));
	return model;
}

/*
 * A callback function for manifest to scan files in raw /firmware archive.
 * Returns 0 to keep scanning, or non-zero to stop.
 */
static int manifest_scan_raw_entries(const char *name, void *arg)
{
	struct manifest *manifest = (struct manifest *)arg;
	struct u_archive *archive = manifest->archive;
	struct model_config model = {0};
	char *ec_name = NULL;
	int chars_read = 0;

	/*
	 * /build/$BOARD/firmware (or CPFE firmware archives) layout:
	 * - image-${MODEL}{,.serial,.dev...}.bin
	 * - ${MODEL}/ec.bin
	 */

	if (sscanf(name, "image-%m[^.].bin%n", &model.name, &chars_read) != 1)
		return 0;

	/* Ignore the names with extra modifiers like image-$MODEL.serial.bin */
	if (!chars_read || name[chars_read]) {
		free(model.name);
		return 0;
	}

	VB2_DEBUG("Found model <%s>: %s\n", model.name, name);
	model.image = strdup(name);

	ASPRINTF(&ec_name, "%s/ec.bin", model.name);
	if (archive_has_entry(archive, ec_name))
		model.ec_image = strdup(ec_name);
	free(ec_name);

	return !manifest_add_model(manifest, &model);
}

/* Returns the matched model config from the manifest, or NULL if not found. */
static struct model_config *manifest_get_model_config(
		const struct manifest *manifest, const char *name)
{
	int i = 0;

	for (i = 0; i < manifest->num; i++) {
		if (!strcmp(name, manifest->models[i].name))
			return &manifest->models[i];
	}
	return NULL;
}

/* Releases (and zeros) the data inside a patch config. */
static void clear_patch_config(struct patch_config *patch)
{
	free(patch->rootkey);
	free(patch->vblock_a);
	free(patch->vblock_b);
	free(patch->gscvd);
	memset(patch, 0, sizeof(*patch));
}

/*
 * Creates the manifest from the 'signer_config.csv' file.
 * Returns 0 on success (loaded), otherwise failure.
 */
static int manifest_from_signer_config(struct manifest *manifest)
{
	struct u_archive *archive = manifest->archive;
	uint32_t size;
	uint8_t *data;
	char *s, *tok_ptr = NULL;

	VB2_DEBUG("Try to build the manifest from %s\n", PATH_SIGNER_CONFIG);

	if (!archive_has_entry(archive, PATH_SIGNER_CONFIG))
		return -1;

	/*
	 * CSV format: model_name,firmware_image,key_id,ec_image
	 *
	 * Note the key_id is for signer and won't be used by the updater,
	 * and ec_image may be optional (for example sarien).
	 */

	if (archive_read_file(archive, PATH_SIGNER_CONFIG, &data, &size,NULL)) {
		ERROR("Failed reading: %s\n", PATH_SIGNER_CONFIG);
		return -1;
	}

	/* Skip headers. */
	s = strtok_r((char *)data, "\n", &tok_ptr);
	if (!s || !strchr(s, ',')) {
		ERROR("Invalid %s: missing header.\n", PATH_SIGNER_CONFIG);
		free(data);
		return -1;
	}

	for (s = strtok_r(NULL, "\n", &tok_ptr); s != NULL;
	     s = strtok_r(NULL, "\n", &tok_ptr)) {

		struct model_config model = {0};

		/*
		 * Both keyid (%3) and ec_image (%4) are optional so we want to
		 * read at least 2 fields.
		 */
		if (sscanf(s, "%m[^,],%m[^,],%*[^,],%m[^,]",
		    &model.name, &model.image, &model.ec_image) < 2) {
			ERROR("Invalid entry(%s): %s\n", PATH_SIGNER_CONFIG, s);
			free(model.name);
			free(model.image);
			free(model.ec_image);
			continue;
		}

		if (strchr(model.name, '-')) {
			/* format: BaseModelName-CustomLabelTag */
			struct model_config *base_model;
			char *tok_dash;
			char *base_name = strdup(model.name);

			VB2_DEBUG("Found custom-label: %s\n", model.name);
			base_name = strtok_r(base_name, "-", &tok_dash);
			assert(base_name);

			/*
			 * Currently we assume the base model (e.g., base_name)
			 * is always listed before CL models in the CSV file -
			 * this is based on how the signerbot and the
			 * chromeos-config works today (validated on octopus).
			 */
			base_model = manifest_get_model_config(manifest, base_name);

			if (!base_model) {
				ERROR("Invalid base model for custom label: %s\n", base_name);
			} else if (!base_model->has_custom_label) {
				base_model->has_custom_label = true;
			}

			free(base_name);
		}

		/* Find patch files. */
		find_patches_for_model(&model, archive);

		if (!manifest_add_model(manifest, &model))
			break;
	}
	free(data);
	return 0;
}

/*
 * Creates the manifest from a simple (legacy) folder with only 1 set of
 * firmware images.
 * Returns 0 on success (loaded), otherwise failure.
 */
static int manifest_from_simple_folder(struct manifest *manifest)
{
	const char * const host_image_name = "image.bin",
		   * const old_host_image_name = "bios.bin",
		   * const ec_name = "ec.bin";
	struct u_archive *archive = manifest->archive;
	const char *image_name = NULL;
	struct firmware_image image = {0};
	struct model_config model = {0};

	VB2_DEBUG("Try to build the manifest from a simple folder\n");

	/* Try to load from current folder. */
	if (archive_has_entry(archive, old_host_image_name))
		image_name = old_host_image_name;
	else if (archive_has_entry(archive, host_image_name))
		image_name = host_image_name;
	else
		return 1;

	model.image = strdup(image_name);
	if (archive_has_entry(archive, ec_name))
		model.ec_image = strdup(ec_name);
	/* Extract model name from FWID: $Vendor_$Platform.$Version */
	if (!load_firmware_image(&image, image_name, archive)) {
		char *token = NULL;
		if (strtok(image.ro_version, "_"))
			token = strtok(NULL, ".");
		if (token && *token) {
			str_convert(token, tolower);
			model.name = strdup(token);
		}
		free_firmware_image(&image);
	}
	if (!model.name)
		model.name = strdup(DEFAULT_MODEL_NAME);
	manifest_add_model(manifest, &model);
	manifest->default_model = manifest->num - 1;

	return 0;
}

/*
 * Finds the existing model_config from manifest that best matches current
 * system (as defined by model_name).
 * Returns a model_config from manifest, or NULL if not found.
 */
const struct model_config *manifest_find_model(struct updater_config *cfg,
					       const struct manifest *manifest,
					       const char *model_name)
{
	char *manifest_key = NULL;
	const struct model_config *model = NULL;
	int i;
	int matched_index;

	/*
	 * For manifest with single model defined, we should just return because
	 * there are other mechanisms like platform name check to double confirm
	 * if the firmware is valid.
	 */
	if (manifest->num == 1)
		return &manifest->models[0];

	if (!model_name) {
		matched_index = dut_get_manifest_key(&manifest_key, cfg);
		if (matched_index < 0) {
			ERROR("Failed to get device identity.  "
			      "Run \"crosid -v\" for explanation.\n");
			return NULL;
		}

		INFO("Identified the device using libcrosid, "
		     "matched chromeos-config index: %d, "
		     "manifest key (model): %s\n",
		     matched_index, manifest_key);
		model_name = manifest_key;
	}

	model = manifest_get_model_config(manifest, model_name);

	if (!model) {
		ERROR("Unsupported model: '%s'.\n", model_name);

		fprintf(stderr,
			"The firmware manifest key '%s' is not present in this "
			"updater archive. The known keys to this updater "
			"archive are:\n", model_name);

		for (i = 0; i < manifest->num; i++)
			fprintf(stderr, " %s", manifest->models[i].name);
		fprintf(stderr, "\n\n");
		fprintf(stderr,
			"Perhaps you are trying to use an updater archive for "
			"the wrong board, or designed for an older OS version "
			"before this model was supported.\n");
		fprintf(stderr,
			"Hint: Read the FIRMWARE_MANIFEST_KEY from the output "
			"of the crosid command.\n");
	}


	free(manifest_key);
	return model;
}

const struct model_config *
manifest_detect_model_from_frid(struct updater_config *cfg,
				struct manifest *manifest)
{
	const struct model_config *result = NULL;
	struct firmware_image current_ro_frid = {0};
	current_ro_frid.programmer = cfg->image_current.programmer;
	int error = flashrom_read_region(&current_ro_frid, FMAP_RO_FRID,
					 cfg->verbosity + 1);
	const char *from_dot;
	int len;

	if (error)
		return NULL;

	current_ro_frid.data[current_ro_frid.size - 1] = '\0';
	from_dot = strchr((const char *)current_ro_frid.data, '.');
	if (!from_dot) {
		VB2_DEBUG("Missing dot (%s)\n",
			  (const char *)current_ro_frid.data);
		goto cleanup;
	}
	len = from_dot - (const char *)current_ro_frid.data + 1;

	for (int i = 0; i < manifest->num && !result; ++i) {
		struct model_config *m = &manifest->models[i];
		struct firmware_image image = {0};

		if (load_firmware_image(&image, m->image, manifest->archive))
			return NULL;

		VB2_DEBUG("Comparing '%*.*s' with '%*.*s'\n", len, len,
			  (const char *)current_ro_frid.data, len, len,
			  image.ro_version);
		if (strncasecmp((const char *)current_ro_frid.data,
				image.ro_version, len) == 0) {
			result = m;
		}
		free_firmware_image(&image);
	}
	if (result) {
		INFO("Detected model: '%s'\n", result->name);
	} else {
		ERROR("Unsupported FRID: '%*.*s'.\n", len - 1, len - 1,
		      (const char *)current_ro_frid.data);
	}
cleanup:
	free_firmware_image(&current_ro_frid);

	return result;
}

/*
 * Determines the custom label tag.
 * Returns the tag string, or NULL if not found.
 * Caller must free the returned string.
 */
static char *get_custom_label_tag(const char *image_file)
{
	/* TODO(hungte) Switch to look at /sys/firmware/vpd/ro/$KEY. */
	char *tag;

	tag = vpd_get_value(image_file, VPD_CUSTOM_LABEL_TAG);
	if (tag)
		return tag;

	tag = vpd_get_value(image_file, VPD_CUSTOM_LABEL_TAG_LEGACY);
	if (tag)
		return tag;

	tag = vpd_get_value(image_file, VPD_CUSTOMIZATION_ID);
	/* VPD_CUSTOMIZATION_ID is complicated and can't be returned directly. */
	if (!tag)
		return NULL;

	/* For VPD_CUSTOMIZATION_ID=LOEM[-VARIANT], we need only capitalized LOEM. */
	INFO("Using deprecated custom label tag: %s=%s\n", VPD_CUSTOMIZATION_ID, tag);
	char *dash = strchr(tag, '-');
	if (dash)
		*dash = '\0';
	str_convert(tag, toupper);
	VB2_DEBUG("Applied tag from %s: %s\n", tag, VPD_CUSTOMIZATION_ID);
	return tag;
}

const struct model_config *manifest_find_custom_label_model(
		struct updater_config *cfg,
		const struct manifest *manifest,
		const struct model_config *base_model)
{
	const struct model_config *model;

	/*
	 * Some custom label devices shipped with wrong key and must change
	 * their model names to match the right data.
	 */
	if (get_config_quirk(QUIRK_OVERRIDE_CUSTOM_LABEL, cfg)) {
		model = quirk_override_custom_label(cfg, manifest, base_model);
		if (model)
			return model;
	}

	assert(cfg->image_current.data);
	const char *tmp_image = get_firmware_image_temp_file(
			&cfg->image_current, &cfg->tempfiles);
	if (!tmp_image) {
		ERROR("Failed to save the system firmware to a file.\n");
		return NULL;
	}

	char *tag = get_custom_label_tag(tmp_image);
	if (!tag) {
		WARN("No custom label tag (VPD '%s'). "
		     "Use default keys from the base model '%s'.\n",
		     VPD_CUSTOM_LABEL_TAG, base_model->name);
		return base_model;
	}

	VB2_DEBUG("Found custom label tag: %s (base=%s)\n", tag, base_model->name);
	char *name;
	ASPRINTF(&name, "%s-%s", base_model->name, tag);
	free(tag);

	INFO("Find custom label model info using '%s'...\n", name);
	model = manifest_find_model(cfg, manifest, name);

	if (model) {
		INFO("Applied custom label model: %s\n", name);
	} else {
		ERROR("Invalid custom label model: %s\n", name);
	}
	free(name);
	return model;
}

static int manifest_from_build_artifacts(struct manifest *manifest) {
	VB2_DEBUG("Try to build the manifest from a */firmware folder\n");
	return archive_walk(manifest->archive, manifest, manifest_scan_raw_entries);
}

/*
 * Creates a new manifest object by scanning files in archive.
 * Returns the manifest on success, otherwise NULL for failure.
 */
struct manifest *new_manifest_from_archive(struct u_archive *archive)
{
	int i;
	struct manifest manifest = {0}, *new_manifest;
	int (*manifest_builders[])(struct manifest *) = {
		manifest_from_signer_config,
		manifest_from_build_artifacts,
		manifest_from_simple_folder,
	};

	manifest.archive = archive;
	manifest.default_model = -1;

	for (i = 0; !manifest.num && i < ARRAY_SIZE(manifest_builders); i++) {
		/*
		 * For archives manually updated (for testing), it is possible a
		 * builder can successfully scan the archive but no valid models
		 * were found, so here we don't need to check the return value.
		 * Only stop when manifest.num is non-zero.
		 */
		(void) manifest_builders[i](&manifest);
	}

	VB2_DEBUG("%d model(s) loaded.\n", manifest.num);
	if (!manifest.num) {
		ERROR("No valid configurations found from the archive.\n");
		return NULL;
	}

	new_manifest = (struct manifest *)malloc(sizeof(manifest));
	if (!new_manifest) {
		ERROR("Internal error: memory allocation error.\n");
		return NULL;
	}
	memcpy(new_manifest, &manifest, sizeof(manifest));
	return new_manifest;
}

/* Releases all resources allocated by given manifest object. */
void delete_manifest(struct manifest *manifest)
{
	int i;
	assert(manifest);
	for (i = 0; i < manifest->num; i++) {
		struct model_config *model = &manifest->models[i];
		free(model->name);
		free(model->image);
		free(model->ec_image);
		clear_patch_config(&model->patches);
	}
	free(manifest->models);
	free(manifest);
}

static const char *get_gbb_key_hash(const struct vb2_gbb_header *gbb,
				    int32_t offset, int32_t size)
{
	struct vb2_packed_key *key;

	if (!gbb)
		return "<No GBB>";
	key = (struct vb2_packed_key *)((uint8_t *)gbb + offset);
	if (vb2_packed_key_looks_ok(key, size))
		return "<Invalid key>";
	return packed_key_sha1_string(key);
}

/* Prints the information of given image file in JSON format. */
static void print_json_image(
		const char *name, const char *fpath, struct model_config *m,
		struct u_archive *archive, int indent, int is_host,
		bool is_first)
{
	struct firmware_image image = {0};
	const struct vb2_gbb_header *gbb = NULL;
	if (!fpath)
		return;
	if (load_firmware_image(&image, fpath, archive))
		return;
	if (!is_first)
		printf(",\n");
	printf("%*s\"%s\": {", indent, "", name);
	indent += 2;
	printf("\n%*s\"versions\": {", indent, "");
	indent += 2;
	printf("\n%*s\"ro\": \"%s\"", indent, "", image.ro_version);
	printf(",\n%*s\"rw\": \"%s\"", indent, "", image.rw_version_a);
	if (is_host && image.ecrw_version_a[0] != '\0')
		printf(",\n%*s\"ecrw\": \"%s\"", indent, "",
		       image.ecrw_version_a);
	indent -= 2;
	printf("\n%*s},", indent, "");
	if (is_host) {
		if (patch_image_by_model(&image, m, archive))
			ERROR("Failed to patch images by model: %s\n", m->name);
		else
			gbb = find_gbb(&image);
	}
	if (gbb != NULL) {
		printf("\n%*s\"keys\": { \"root\": \"%s\", ",
		       indent, "",
		       get_gbb_key_hash(gbb, gbb->rootkey_offset,
					gbb->rootkey_size));
		printf("\"recovery\": \"%s\" },",
		       get_gbb_key_hash(gbb, gbb->recovery_key_offset,
					gbb->recovery_key_size));
	}
	printf("\n%*s\"image\": \"%s\"", indent, "", fpath);
	indent -= 2;
	printf("\n%*s}", indent, "");
	check_firmware_versions(&image);
	free_firmware_image(&image);
}

/* Prints the information of objects in manifest (models and images) in JSON. */
void print_json_manifest(const struct manifest *manifest)
{
	int i, j, indent;
	struct u_archive *ar = manifest->archive;

	printf("{\n");
	for (i = 0, indent = 2; i < manifest->num; i++) {
		struct model_config *m = &manifest->models[i];
		struct {
			const char *name;
			const char *fpath;
			bool is_host;
		} images[] = {
			{"host", m->image, true},
			{"ec", m->ec_image},
		};
		bool is_first = true;
		printf("%s%*s\"%s\": {\n", i ? ",\n" : "", indent, "", m->name);
		indent += 2;
		for (j = 0; j < ARRAY_SIZE(images); j++) {
			if (!images[j].fpath)
				continue;
			print_json_image(images[j].name, images[j].fpath, m, ar,
					 indent, images[j].is_host, is_first);
			is_first = false;
		}
		if (m->patches.rootkey) {
			struct patch_config *p = &m->patches;
			printf(",\n%*s\"patches\": { \"rootkey\": \"%s\", "
			       "\"vblock_a\": \"%s\", \"vblock_b\": \"%s\"",
			       indent, "", p->rootkey, p->vblock_a,
			       p->vblock_b);
			if (p->gscvd)
				printf(", \"gscvd\": \"%s\"", p->gscvd);
			printf(" }");
		}
		printf("\n  }");
		indent -= 2;
		assert(indent == 2);
	}
	printf("\n}\n");
}

static void print_parseable_image(const char *name, const char *fpath, struct model_config *m,
				 struct u_archive *archive, bool is_host)
{
	struct firmware_image image = {0};
	const struct vb2_gbb_header *gbb = NULL;

	if (!fpath)
		return;
	if (load_firmware_image(&image, fpath, archive))
		return;

	printf("%s::%s::versions::ro::%s\n", m->name, name, image.ro_version);
	printf("%s::%s::versions::rw::%s\n", m->name, name, image.rw_version_a);
	if (is_host) {
		if (image.ecrw_version_a[0] != '\0')
			printf("%s::%s::versions::ecrw::%s\n", m->name, name,
			       image.ecrw_version_a);

		if (patch_image_by_model(&image, m, archive))
			ERROR("Failed to patch images by model: %s\n", m->name);
		else
			gbb = find_gbb(&image);

		if (gbb != NULL) {
			printf("%s::%s::keys::root::%s\n", m->name, name,
			       get_gbb_key_hash(gbb, gbb->rootkey_offset, gbb->rootkey_size));
			printf("%s::%s::keys::recovery::%s\n", m->name, name,
			       get_gbb_key_hash(gbb, gbb->recovery_key_offset,
						gbb->recovery_key_size));
		}
	}
	printf("%s::%s::image::%s\n", m->name, name, fpath);
	check_firmware_versions(&image);
	free_firmware_image(&image);
}

void print_parseable_manifest(const struct manifest *manifest)
{
	struct u_archive *ar = manifest->archive;

	for (int i = 0; i < manifest->num; ++i) {
		struct model_config *m = &manifest->models[i];
		if (m->image)
			print_parseable_image("host", m->image, m, ar, true);

		if (m->ec_image)
			print_parseable_image("ec", m->ec_image, m, ar, false);

		if (m->patches.rootkey) {
			struct patch_config *p = &m->patches;
			printf("%s::patches::rootkey::%s\n", m->name, p->rootkey);
			printf("%s::patches::vblock_a::%s\n", m->name, p->vblock_a);
			printf("%s::patches::vblock_b::%s\n", m->name, p->vblock_b);
			if (p->gscvd)
				printf("%s::gscvd::%s\n", m->name, p->gscvd);
		}
	}
}
