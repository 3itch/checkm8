/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "flash_helpers.h"
#include "futility.h"
#include "updater.h"

#ifdef USE_FLASHROM

/* Command line options */
static struct option const long_opts[] = {
	SHARED_FLASH_ARGS_LONGOPTS
	/* name  has_arg *flag val */
	{"help", 0, NULL, 'h'},
	{"debug", 0, NULL, 'd'},
	{"region", 1, NULL, 'r'},
	{"split-output", 0, NULL, 's'},
	{"verbose", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const char *const short_opts = "hdsr:v" SHARED_FLASH_ARGS_SHORTOPTS;

static void print_help(int argc, char *argv[])
{
	printf("\n"
	       "Usage:  " MYNAME " %s [OPTIONS] FILE\n"
	       "\n"
	       "Reads AP firmware to the FILE\n"
	       "-d, --debug            \tPrint debugging messages\n"
	       "-r, --region=REGIONS   \tComma delimited regions to read (optional)\n"
	       "-v, --verbose          \tPrint verbose messages\n"
	       "-s, --split-output     \tOutput each comma delimited regions to own {FILE}_{region_name} (optional)\n"
	       SHARED_FLASH_ARGS_HELP,
	       argv[0]);
}

static int append_to_str_array(const char ***arr, const char *str, size_t *len)
{
	const char **expanded_arr = realloc(*arr, sizeof(char *) * ((*len) + 1));
	if (!expanded_arr) {
		WARN("Failed to allocate memory for string array");
		return -1;
	}

	*arr = expanded_arr;
	(*arr)[*len] = str;
	(*len)++;
	return 0;
}

static int parse_region_string(const char ***regions, char *str, size_t *rlen)
{
	if (!str)
		return -1; /* no regions to parse. */

	char *savedptr;
	const char *delim = ",";
	char *region = strtok_r(str, delim, &savedptr);

	while (region) {
		if (append_to_str_array(regions, region, rlen))
			return -1;
		region = strtok_r(NULL, delim, &savedptr);
	}

	return 0;
}

static int read_flash_regions_to_file(struct updater_config *cfg,
				      const char *path, char *str,
				      bool do_split)
{
	int ret = 0;
	size_t rlen = 0;
	const char **regions = NULL;

	if (parse_region_string(&regions, str, &rlen) || !regions || !rlen) {
		WARN("No parsable regions to process.\n");
		ret = -1;
		goto out_free;
	}

	/* Need to read the FMAP to find regions if we are going to write each
	 * region to a separate file. */
	if (do_split) {
		if (append_to_str_array(&regions, FMAP_RO_FMAP, &rlen)) {
			ret = -1;
			goto out_free;
		}
	}

	/* Read only the specified regions */
	if (flashrom_read_image(&cfg->image_current, regions,
				rlen, cfg->verbosity + 1)) {
		ret = -1;
		goto out_free;
	}

	if (!do_split) {
		if (write_to_file("Wrote AP firmware region to", path,
				  cfg->image_current.data,
				  cfg->image_current.size)) {
			return -1;
		}
		return 0;
	}

	/*
	 * The last element of regions is FMAP_RO_FMAP, stop at (rlen-1) to
	 * only process the user-specified regions.
	 */
	for (size_t i = 0; i < rlen - 1; i++) {
		const char *region = regions[i];

		struct firmware_section section;
		if (find_firmware_section(&section, &cfg->image_current, region)) {
			ERROR("Region '%s' not found in image.\n", region);
			ret = -1;
			goto out_free;
		}
		const char *separator = "_";
		const size_t fpath_sz = strlen(path) +
					strlen(separator) +
					strlen(region) +
					1; /* +1 for null termination. */
		char *fpath = calloc(1, fpath_sz);
		if (!fpath) {
			ret = -1;
			goto out_free;
		}
		snprintf(fpath, fpath_sz, "%s%s%s", path, separator, region);
		if (write_to_file("Wrote AP firmware region to",
				  fpath, section.data, section.size)) {
			free(fpath);
			ret = -1;
			goto out_free;
		}
		free(fpath);
	}

out_free:
	free(regions);
	return ret;
}

static int do_read(int argc, char *argv[])
{
	struct updater_config *cfg = NULL;
	struct updater_config_arguments args = {0};
	int i, errorcnt = 0;
	char *regions = NULL;
	bool do_split = false;

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		if (handle_flash_argument(&args, i, optarg))
			continue;
		switch (i) {
		case 'h':
			print_help(argc, argv);
			return 0;
		case 'd':
			debugging_enabled = 1;
			args.verbosity++;
			break;
		case 'r':
			regions = strdup(optarg);
			if (!regions) {
				ERROR("strdup() returned NULL\n");
				return 1;
			}
			break;
		case 's':
			do_split = true;
			break;
		case 'v':
			args.verbosity++;
			break;
		case '?':
			errorcnt++;
			if (optopt)
				ERROR("Unrecognized option: -%c\n", optopt);
			else if (argv[optind - 1])
				ERROR("Unrecognized option (possibly '%s')\n",
				      argv[optind - 1]);
			else
				ERROR("Unrecognized option.\n");
			break;
		default:
			errorcnt++;
			ERROR("Failed parsing options.\n");
		}
	}
	if (argc - optind < 1) {
		ERROR("Missing output filename\n");
		print_help(argc, argv);
		return 1;
	}
	const char *output_file_name = argv[optind++];
	if (optind < argc) {
		ERROR("Unexpected arguments.\n");
		print_help(argc, argv);
		return 1;
	}
	if (do_split && !regions) {
		ERROR("Cannot split read of regions without list of regions.\n");
		print_help(argc, argv);
		return 1;
	}

	if (setup_flash(&cfg, &args)) {
		ERROR("While preparing flash\n");
		return 1;
	}

	if (!regions) {
		/* full image read. */
		int r = load_system_firmware(cfg, &cfg->image_current);
		/*
		 * Ignore a parse error as we still want to write the file
		 * out in that case
		 */
		if (r && r != IMAGE_PARSE_FAILURE) {
			errorcnt++;
			goto err;
		}
		if (write_to_file("Wrote AP firmware to", output_file_name,
				  cfg->image_current.data,
				  cfg->image_current.size)) {
			errorcnt++;
			goto err;
		}
	} else {
		if (read_flash_regions_to_file(cfg, output_file_name, regions, do_split))
			errorcnt++;
		free(regions);
	}

err:
	teardown_flash(cfg);
	return !!errorcnt;
}
#define CMD_HELP_STR "Read AP firmware"

#else /* USE_FLASHROM */

static int do_read(int argc, char *argv[])
{
	FATAL(MYNAME " was built without flashrom support, `read` command unavailable!\n");
	return -1;
}
#define CMD_HELP_STR "Read system firmware (unavailable in this build)"

#endif /* !USE_FLASHROM */

DECLARE_FUTIL_COMMAND(read, do_read, VBOOT_VERSION_ALL, CMD_HELP_STR);
