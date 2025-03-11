/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The utility functions for firmware updater.
 */

#include <libflashrom.h>

#include "2common.h"
#include "crossystem.h"
#include "host_misc.h"
#include "util_misc.h"
//#include "updater.h"
#include "../../futility/futility.h"
#include "flashrom.h"

// global to allow verbosity level to be injected into callback.
static enum flashrom_log_level g_verbose_screen = FLASHROM_MSG_INFO;

static int flashrom_print_cb(enum flashrom_log_level level, const char *fmt,
			     va_list ap)
{
	int ret = 0;
	FILE *output_type = (level < FLASHROM_MSG_INFO) ? stderr : stdout;

	if (level > g_verbose_screen)
		return ret;

	ret = vfprintf(output_type, fmt, ap);
	/* msg_*spew often happens inside chip accessors
	 * in possibly time-critical operations.
	 * Don't slow them down by flushing.
	 */
	if (level != FLASHROM_MSG_SPEW)
		fflush(output_type);

	return ret;
}

static char *flashrom_extract_params(const char *str, char **prog, char **params)
{
	char *tmp = strdup(str);
	*prog = strtok(tmp, ":");
	*params = strtok(NULL, "");
	return tmp;
}

/*
 * NOTE: When `regions` contains multiple regions, `region_start` and
 * `region_len` will be filled with the data of the first region.
 */
static int flashrom_read_image_impl(struct firmware_image *image,
				    const char * const regions[],
						const size_t regions_len,
				    unsigned int *region_start,
				    unsigned int *region_len, int verbosity)
{
	int r = 0;
	size_t len = 0;
	*region_start = 0;
	*region_len = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(image->programmer, &programmer, &params);

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1)
		|| flashrom_programmer_init(&prog, programmer, params)) {
		r = -1;
		goto err_init;
	}
	if (flashrom_flash_probe(&flashctx, prog, NULL)) {
		r = -1;
		goto err_probe;
	}

	len = flashrom_flash_getsize(flashctx);
	if (!len) {
		ERROR("Chip found had zero length, probing probably failed.\n");
		r = -1;
		goto err_probe;
	}

	flashrom_flag_set(flashctx, FLASHROM_FLAG_SKIP_UNREADABLE_REGIONS, true);

	if (regions_len) {
		int i;
		r = flashrom_layout_read_fmap_from_rom(
			&layout, flashctx, 0, len);
		if (r > 0) {
			ERROR("could not read fmap from rom, r=%d\n", r);
			r = -1;
			goto err_cleanup;
		}
		for (i = 0; i < regions_len; i++) {
			// empty region causes seg fault in API.
			r |= flashrom_layout_include_region(layout, regions[i]);
			if (r > 0) {
				ERROR("could not include region = '%s'\n",
				      regions[i]);
				r = -1;
				goto err_cleanup;
			}
		}
		flashrom_layout_set(flashctx, layout);
	}

	image->data = calloc(1, len);
	image->size = len;
	image->file_name = strdup("<sys-flash>");

	r |= flashrom_image_read(flashctx, image->data, len);

	if (r == 0 && regions_len)
		r |= flashrom_layout_get_region_range(layout, regions[0],
						      region_start, region_len);

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);

err_probe:
	r |= flashrom_programmer_shutdown(prog);

err_init:
	free(tmp);
	return r;
}

int flashrom_read_image(struct firmware_image *image,
			const char * const regions[],
			const size_t regions_len,
			int verbosity)
{
	unsigned int start, len;
	return flashrom_read_image_impl(image, regions, regions_len, &start,
					&len, verbosity);
}

int flashrom_read_region(struct firmware_image *image, const char *region,
			 int verbosity)
{
	const char * const regions[] = {region};
	unsigned int start, len;
	int r = flashrom_read_image_impl(image, regions, ARRAY_SIZE(regions),
					 &start, &len, verbosity);
	if (r != 0)
		return r;

	memmove(image->data, image->data + start, len);
	image->size = len;
	return 0;
}

int flashrom_write_image(const struct firmware_image *image,
			const char * const regions[],
			const size_t regions_len,
			const struct firmware_image *diff_image,
			int do_verify, int verbosity)
{
	int r = 0;
	size_t len = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(image->programmer, &programmer, &params);

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1)
		|| flashrom_programmer_init(&prog, programmer, params)) {
		r = -1;
		goto err_init;
	}
	if (flashrom_flash_probe(&flashctx, prog, NULL)) {
		r = -1;
		goto err_probe;
	}

	len = flashrom_flash_getsize(flashctx);
	if (!len) {
		ERROR("Chip found had zero length, probing probably failed.\n");
		r = -1;
		goto err_cleanup;
	}

	if (diff_image) {
		if (diff_image->size != image->size) {
			ERROR("diff_image->size != image->size");
			r = -1;
			goto err_cleanup;
		}
	}

	/* Must occur before attempting to read FMAP from SPI flash. */
	flashrom_flag_set(flashctx, FLASHROM_FLAG_SKIP_UNREADABLE_REGIONS, true);

	if (regions_len) {
		int i;
		r = flashrom_layout_read_fmap_from_buffer(
			&layout, flashctx, (const uint8_t *)image->data,
			image->size);
		if (r > 0) {
			WARN("could not read fmap from image, r=%d, "
				"falling back to read from rom\n", r);
			r = flashrom_layout_read_fmap_from_rom(
				&layout, flashctx, 0, len);
			if (r > 0) {
				ERROR("could not read fmap from rom, r=%d\n", r);
				r = -1;
				goto err_cleanup;
			}
		}
		for (i = 0; i < regions_len; i++) {
			INFO(" including region '%s'\n", regions[i]);
			// empty region causes seg fault in API.
			r |= flashrom_layout_include_region(layout, regions[i]);
			if (r > 0) {
				ERROR("could not include region = '%s'\n",
				      regions[i]);
				r = -1;
				goto err_cleanup;
			}
		}
		flashrom_layout_set(flashctx, layout);
	} else if (image->size != len) {
		r = -1;
		goto err_cleanup;
	}

	flashrom_flag_set(flashctx, FLASHROM_FLAG_SKIP_UNWRITABLE_REGIONS, true);
	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_WHOLE_CHIP, false);
	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_AFTER_WRITE,
			  do_verify);

	r |= flashrom_image_write(flashctx, image->data, image->size,
				  diff_image ? diff_image->data : NULL);

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);

err_probe:
	r |= flashrom_programmer_shutdown(prog);

err_init:
	free(tmp);
	return r;
}

int flashrom_get_wp(const char *prog_with_params, bool *wp_mode,
		    uint32_t *wp_start, uint32_t *wp_len, int verbosity)
{
	int ret = -1;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;

	struct flashrom_wp_cfg *cfg = NULL;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(prog_with_params, &programmer,
					    &params);

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1)
		|| flashrom_programmer_init(&prog, programmer, params))
		goto err_init;

	if (flashrom_flash_probe(&flashctx, prog, NULL))
		goto err_probe;

	if (flashrom_wp_cfg_new(&cfg) != FLASHROM_WP_OK)
		goto err_cleanup;

	if (flashrom_wp_read_cfg(cfg, flashctx) != FLASHROM_WP_OK)
		goto err_read_cfg;

	/* size_t tmp variables for libflashrom compatibility */
	size_t tmp_wp_start, tmp_wp_len;
	flashrom_wp_get_range(&tmp_wp_start, &tmp_wp_len, cfg);

	if (wp_start != NULL)
		*wp_start = tmp_wp_start;
	if (wp_start != NULL)
		*wp_len = tmp_wp_len;
	if (wp_mode != NULL)
		*wp_mode = flashrom_wp_get_mode(cfg) != FLASHROM_WP_MODE_DISABLED;

	ret = 0;

err_read_cfg:
	flashrom_wp_cfg_release(cfg);

err_cleanup:
	flashrom_flash_release(flashctx);

err_probe:
	if (flashrom_programmer_shutdown(prog))
		ret = -1;

err_init:
	free(tmp);

	return ret;
}

int flashrom_set_wp(const char *prog_with_params, bool wp_mode,
		    uint32_t wp_start, uint32_t wp_len, int verbosity)
{
	int ret = 1;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;

	struct flashrom_wp_cfg *cfg = NULL;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(prog_with_params, &programmer,
					    &params);

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1)
		|| flashrom_programmer_init(&prog, programmer, params))
		goto err_init;

	if (flashrom_flash_probe(&flashctx, prog, NULL))
		goto err_probe;

	if (flashrom_wp_cfg_new(&cfg) != FLASHROM_WP_OK)
		goto err_cleanup;

	enum flashrom_wp_mode mode = wp_mode ?
			FLASHROM_WP_MODE_HARDWARE : FLASHROM_WP_MODE_DISABLED;
	flashrom_wp_set_mode(cfg, mode);
	flashrom_wp_set_range(cfg, wp_start, wp_len);

	if (flashrom_wp_write_cfg(flashctx, cfg) != FLASHROM_WP_OK)
		goto err_write_cfg;

	ret = 0;

err_write_cfg:
	flashrom_wp_cfg_release(cfg);

err_cleanup:
	flashrom_flash_release(flashctx);

err_probe:
	if (flashrom_programmer_shutdown(prog))
		ret = 1;

err_init:
	free(tmp);

	return ret;
}

int flashrom_get_info(const char *prog_with_params,
		      char **vendor, char **name,
		      uint32_t *vid, uint32_t *pid,
		      uint32_t *flash_len, int verbosity)
{
	int r = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(prog_with_params,
					    &programmer, &params);

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1) ||
	    flashrom_programmer_init(&prog, programmer, params)) {
		r = -1;
		goto err_init;
	}
	if (flashrom_flash_probe(&flashctx, prog, NULL)) {
		r = -1;
		goto err_probe;
	}

	struct flashrom_flashchip_info info;
	flashrom_flash_getinfo(flashctx, &info);

	*vendor = strdup(info.vendor);
	*name = strdup(info.name);
	*vid = info.manufacture_id;
	*pid = info.model_id;
	*flash_len = info.total_size * 1024;

	flashrom_flash_release(flashctx);

err_probe:
	r |= flashrom_programmer_shutdown(prog);

err_init:
	free(tmp);
	return r;
}

int flashrom_get_size(const char *prog_with_params,
		      uint32_t *flash_len, int verbosity)
{
	int r = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(prog_with_params,
					    &programmer, &params);

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1) ||
	    flashrom_programmer_init(&prog, programmer, params)) {
		r = -1;
		goto err_init;
	}
	if (flashrom_flash_probe(&flashctx, prog, NULL)) {
		r = -1;
		goto err_probe;
	}

	*flash_len = flashrom_flash_getsize(flashctx);

	flashrom_flash_release(flashctx);

err_probe:
	r |= flashrom_programmer_shutdown(prog);

err_init:
	free(tmp);
	return r;
}
