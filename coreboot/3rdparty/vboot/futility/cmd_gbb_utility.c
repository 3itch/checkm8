/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "flash_helpers.h"
#include "futility.h"
#include "updater.h"
#include "updater_utils.h"
#include "2gbb_flags.h"

#ifdef USE_FLASHROM
#define FLASH_ARG_HELP                                                         \
	"     --flash         \tRead from and write to flash"                  \
	", ignore file arguments.\n"
#define FLASH_MORE_HELP                                                        \
	"In GET and SET mode, the following options modify the "               \
	"behaviour of flashing. Presence of any of these implies "             \
	"--flash.\n"                                                           \
	SHARED_FLASH_ARGS_HELP                                                 \
	"\n"
#else
#define FLASH_ARG_HELP
#define FLASH_MORE_HELP
#endif /* USE_FLASHROM */

static void print_help(int argc, char *argv[])
{
	printf("\n"
		"Usage:  " MYNAME " %s [-g|-s|-c] [OPTIONS] "
		"[image_file] [output_file]\n"
		"\n"
		"GET MODE:\n"
		"-g, --get   (default)\tGet (read) from image_file or flash, "
		"with following options:\n"
		FLASH_ARG_HELP
		"     --hwid          \tReport hardware id (default).\n"
		"     --flags         \tReport header flags.\n"
		"     --digest        \tReport digest of hwid (>= v1.2)\n"
		" -k, --rootkey=FILE  \tFile name to export Root Key.\n"
		" -b, --bmpfv=FILE    \tFile name to export Bitmap FV.\n"
		" -r  --recoverykey=FILE\tFile name to export Recovery Key.\n"
		" -e  --explicit      \tReport header flags by name.\n"
		"\n"
		"SET MODE:\n"
		"-s, --set            \tSet (write) to flash or file, "
		"with following options:\n"
		FLASH_ARG_HELP
		" -o, --output=FILE   \tNew file name for ouptput.\n"
		"     --hwid=HWID     \tThe new hardware id to be changed.\n"
		"     --flags=FLAGS   \tThe new (numeric) flags value or +/- diff value.\n"
		" -k, --rootkey=FILE  \tFile name of new Root Key.\n"
		" -b, --bmpfv=FILE    \tFile name of new Bitmap FV.\n"
		" -r  --recoverykey=FILE\tFile name of new Recovery Key.\n"
		"\n"
		"CREATE MODE:\n"
		"-c, --create=hwid_size,rootkey_size,bmpfv_size,"
		"recoverykey_size\n"
		"                     \tCreate a GBB blob by given size list.\n\n"
		FLASH_MORE_HELP
		"SAMPLE:\n"
		"  %s -g image.bin\n"
		"  %s --set --hwid='New Model' -k key.bin"
		" image.bin newimage.bin\n"
		"  %s -c 0x100,0x1000,0x03DE80,0x1000 gbb.blob\n\n"
		"GBB Flags:\n"
		" To get a developer-friendly device, try 0x18 (dev_mode boot_usb).\n"
		" For early bringup development, try 0x40b9.\n",
		argv[0], argv[0], argv[0], argv[0]);
	for (vb2_gbb_flags_t flag = 1; flag; flag <<= 1) {
		const char *name;
		const char *description;
		if (vb2_get_gbb_flag_description(flag, &name, &description) !=
		    VB2_SUCCESS)
			break;
		printf(" 0x%08x\t%s\n"
		       "                     \t%s\n",
		       flag, name, description);
	}
}

enum {
	OPT_HWID = 0x1000,
	OPT_FLAGS,
	OPT_DIGEST,
	OPT_FLASH,
	OPT_HELP,
};

/* Command line options */
static struct option long_opts[] = {
	SHARED_FLASH_ARGS_LONGOPTS
	/* name  has_arg *flag val */
	{"get", 0, NULL, 'g'},
	{"set", 0, NULL, 's'},
	{"create", 1, NULL, 'c'},
	{"output", 1, NULL, 'o'},
	{"rootkey", 1, NULL, 'k'},
	{"bmpfv", 1, NULL, 'b'},
	{"recoverykey", 1, NULL, 'r'},
	{"hwid", 0, NULL, OPT_HWID},
	{"flags", 0, NULL, OPT_FLAGS},
	{"explicit", 0, NULL, 'e'},
	{"digest", 0, NULL, OPT_DIGEST},
	{"flash", 0, NULL, OPT_FLASH},
	{"help", 0, NULL, OPT_HELP},
	{NULL, 0, NULL, 0},
};

static const char *short_opts = ":gsc:o:k:b:r:e" SHARED_FLASH_ARGS_SHORTOPTS;

/* Change the has_arg field of a long_opts entry */
static void opt_has_arg(const char *name, int val)
{
	for (struct option *p = long_opts; p->name; p++) {
		if (!strcmp(name, p->name)) {
			p->has_arg = val;
			break;
		}
	}
}

#define GBB_SEARCH_STRIDE 4
static struct vb2_gbb_header *FindGbbHeader(uint8_t *ptr, size_t size)
{
	size_t i;
	struct vb2_gbb_header *tmp, *gbb_header = NULL;
	int count = 0;

	for (i = 0; i <= size - GBB_SEARCH_STRIDE; i += GBB_SEARCH_STRIDE) {
		if (memcmp(ptr + i, VB2_GBB_SIGNATURE, VB2_GBB_SIGNATURE_SIZE))
			continue;

		/* Found something. See if it's any good. */
		tmp = (struct vb2_gbb_header *) (ptr + i);
		if (futil_valid_gbb_header(tmp, size - i, NULL))
			if (!count++)
				gbb_header = tmp;
	}

	switch (count) {
	case 0:
		return NULL;
	case 1:
		return gbb_header;
	default:
		ERROR("Multiple GBB headers found\n");
		return NULL;
	}
}

static uint8_t *create_gbb(const char *desc, off_t *sizeptr)
{
	char *param, *e = NULL;
	size_t size = EXPECTED_VB2_GBB_HEADER_SIZE;
	int i = 0;
	/* Danger Will Robinson! four entries ==> four paramater blocks */
	uint32_t val[] = { 0, 0, 0, 0 };

	char *sizes = strdup(desc);
	if (!sizes) {
		ERROR("strdup() failed: %s\n", strerror(errno));
		return NULL;
	}

	for (char *str = sizes; (param = strtok(str, ", ")) != NULL; str = NULL) {
		val[i] = (uint32_t) strtoul(param, &e, 0);
		if (e && *e) {
			ERROR("Invalid creation parameter: \"%s\"\n", param);
			free(sizes);
			return NULL;
		}
		size += val[i++];
		if (i > ARRAY_SIZE(val))
			break;
	}

	uint8_t *buf = (uint8_t *) calloc(1, size);
	if (!buf) {
		ERROR("Can't malloc %zu bytes: %s\n", size, strerror(errno));
		free(sizes);
		return NULL;
	}
	if (sizeptr)
		*sizeptr = size;

	struct vb2_gbb_header *gbb = (struct vb2_gbb_header *) buf;
	memcpy(gbb->signature, VB2_GBB_SIGNATURE, VB2_GBB_SIGNATURE_SIZE);
	gbb->major_version = VB2_GBB_MAJOR_VER;
	gbb->minor_version = VB2_GBB_MINOR_VER;
	gbb->header_size = EXPECTED_VB2_GBB_HEADER_SIZE;
	gbb->flags = 0;

	i = EXPECTED_VB2_GBB_HEADER_SIZE;
	gbb->hwid_offset = i;
	gbb->hwid_size = val[0];
	i += val[0];

	gbb->rootkey_offset = i;
	gbb->rootkey_size = val[1];
	i += val[1];

	gbb->bmpfv_offset = i;
	gbb->bmpfv_size = val[2];
	i += val[2];

	gbb->recovery_key_offset = i;
	gbb->recovery_key_size = val[3];
	i += val[1];

	free(sizes);
	return buf;
}

static uint8_t *read_entire_file(const char *filename, off_t *sizeptr)
{
	uint8_t *buf = NULL;
	struct stat sb;

	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		ERROR("Unable to open %s for reading: %s\n", filename,
		      strerror(errno));
		goto fail;
	}

	if (fstat(fileno(fp), &sb)) {
		ERROR("Can't fstat %s: %s\n", filename, strerror(errno));
		goto fail;
	}
	if (sizeptr)
		*sizeptr = sb.st_size;

	buf = (uint8_t *) malloc(sb.st_size);
	if (!buf) {
		ERROR("Can't malloc %" PRIi64 " bytes: %s\n", sb.st_size,
		      strerror(errno));
		goto fail;
	}

	if (1 != fread(buf, sb.st_size, 1, fp)) {
		ERROR("Unable to read from %s: %s\n", filename,
		      strerror(errno));
		goto fail;
	}

	if (fclose(fp)) {
		ERROR("Unable to close %s: %s\n", filename, strerror(errno));
		fp = NULL;  /* Don't try to close it again */
		goto fail;
	}

	return buf;

fail:
	if (buf)
		free(buf);

	if (fp && fclose(fp))
		ERROR("Unable to close %s: %s\n", filename, strerror(errno));
	return NULL;
}

static int read_from_file(const char *msg, const char *filename,
			  uint8_t *start, uint32_t size)
{
	struct stat sb;
	size_t count;
	int r = 0;

	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		r = errno;
		ERROR("Unable to open %s for reading: %s\n", filename, strerror(r));
		return r;
	}

	if (fstat(fileno(fp), &sb)) {
		r = errno;
		ERROR("Can't fstat %s: %s\n", filename, strerror(r));
		goto done_close;
	}

	if (sb.st_size > size) {
		ERROR("File %s exceeds capacity (%" PRIu32 ")\n", filename, size);
		r = -1;
		goto done_close;
	}

	/* Wipe existing data. */
	memset(start, 0, size);

	/* It's okay if we read less than size. That's just the max. */
	count = fread(start, 1, size, fp);
	if (ferror(fp)) {
		r = errno;
		ERROR("Read %zu/%" PRIi64 " bytes from %s: %s\n", count,
		      sb.st_size, filename, strerror(r));
	}

done_close:
	if (fclose(fp)) {
		int e = errno;
		ERROR("Unable to close %s: %s\n", filename, strerror(e));
		if (!r)
			r = e;
	}

	if (!r && msg)
		printf(" - import %s from %s: success\n", msg, filename);

	return r;
}

/* Read firmware from flash. */
static uint8_t *read_from_flash(struct updater_config *cfg, off_t *filesize)
{
#ifdef USE_FLASHROM
	/*
	 * Read the FMAP region as well, so that a subsequet write won't
	 * require another read of FMAP.
	 */
	const char * const regions[] = {FMAP_RO_FMAP, FMAP_RO_GBB};
	if (flashrom_read_image(&cfg->image_current, regions,
				ARRAY_SIZE(regions), cfg->verbosity + 1))
		return NULL;
	uint8_t *ret = cfg->image_current.data;
	cfg->image_current.data = NULL;
	*filesize = cfg->image_current.size;
	cfg->image_current.size = 0;
	return ret;
#else
	return NULL;
#endif /* USE_FLASHROM */
}

/* Write firmware to flash. Takes ownership of inbuf and outbuf data. */
static int write_to_flash(struct updater_config *cfg, uint8_t *outbuf,
			  off_t filesize)
{
#ifdef USE_FLASHROM
	if (is_ap_write_protection_enabled(cfg)) {
		ERROR("You must disable write protection before setting flags.\n");
		return -1;
	}
	cfg->image.data = outbuf;
	cfg->image.size = filesize;

	const char *sections[] = {FMAP_RO_GBB};
	int ret = write_system_firmware(cfg, &cfg->image, sections,
					ARRAY_SIZE(sections));

	cfg->image.data = NULL;
	cfg->image.size = 0;
	return ret;
#else
	return 1;
#endif /* USE_FLASHROM */
}

static int parse_flag_value(const char *s, vb2_gbb_flags_t *val)
{
	int sign = 0;

	if (!strlen(s))
		return -1;

	if (s[0] == '+')
		sign = 1;
	else if (s[0] == '-')
		sign = 2;

	const char *ss = !sign ? s : &s[1];
	char *e = NULL;
	*val = strtoul(ss, &e, 0);
	if (e && *e) {
		ERROR("Invalid flags value: %s\n", ss);
		return -1;
	}

	return sign;
}

static int do_gbb(int argc, char *argv[])
{
	enum do_what_now { DO_GET, DO_SET, DO_CREATE } mode = DO_GET;
	char *infile = NULL;
	char *outfile = NULL;
	char *opt_create = NULL;
	char *opt_rootkey = NULL;
	char *opt_bmpfv = NULL;
	char *opt_recoverykey = NULL;
	char *opt_hwid = NULL;
	char *opt_flags = NULL;
	bool sel_hwid = false;
	bool sel_digest = false;
	bool sel_flags = false;
	int explicit_flags = 0;
	uint8_t *inbuf = NULL;
	off_t filesize;
	uint8_t *outbuf = NULL;
	int i;
	struct updater_config *cfg = NULL;
	struct updater_config_arguments args = {0};
	int errorcnt = 0;


	opterr = 0;		/* quiet, you */
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
#ifdef USE_FLASHROM
		if (handle_flash_argument(&args, i, optarg))
			continue;
#endif
		switch (i) {
		case 'g':
			mode = DO_GET;
			opt_has_arg("flags", 0);
			opt_has_arg("hwid", 0);
			break;
		case 's':
			mode = DO_SET;
			opt_has_arg("flags", 1);
			opt_has_arg("hwid", 1);
			break;
		case 'c':
			mode = DO_CREATE;
			opt_create = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'k':
			opt_rootkey = optarg;
			break;
		case 'b':
			opt_bmpfv = optarg;
			break;
		case 'r':
			opt_recoverykey = optarg;
			break;
		case OPT_HWID:
			/* --hwid is optional: null might be okay */
			opt_hwid = optarg;
			sel_hwid = true;
			break;
		case OPT_FLAGS:
			/* --flags is optional: null might be okay */
			opt_flags = optarg;
			sel_flags = true;
			break;
		case 'e':
			sel_flags = true;
			explicit_flags = 1;
			break;
		case OPT_DIGEST:
			sel_digest = true;
			break;
		case OPT_FLASH:
#ifndef USE_FLASHROM
			ERROR("futility was built without flashrom support\n");
			return 1;
#endif
			args.use_flash = 1;
			break;
		case OPT_HELP:
			print_help(argc, argv);
			return !!errorcnt;

		case '?':
			errorcnt++;
			if (optopt)
				ERROR("Unrecognized option: -%c\n", optopt);
			else if (argv[optind - 1])
				ERROR("Unrecognized option (possibly \"%s\")\n",
				      argv[optind - 1]);
			else
				ERROR("Unrecognized option\n");
			break;
		case ':':
			errorcnt++;
			if (argv[optind - 1])
				ERROR("Missing argument to -%c (%s)\n", optopt,
				      argv[optind - 1]);
			else
				ERROR("Missing argument to -%c\n", optopt);
			break;
		default:
			errorcnt++;
			ERROR("While parsing options\n");
		}
	}

	/* Problems? */
	if (errorcnt) {
		print_help(argc, argv);
		return 1;
	}

	if (args.use_flash) {
		if (setup_flash(&cfg, &args)) {
			ERROR("While preparing flash\n");
			return 1;
		}
	}

	/* Now try to do something */
	switch (mode) {
	case DO_GET:
		if (args.use_flash) {
			inbuf = read_from_flash(cfg, &filesize);
		} else {
			if (argc - optind < 1) {
				ERROR("Missing input filename\n");
				print_help(argc, argv);
				errorcnt++;
				break;
			}
			infile = argv[optind++];
			inbuf = read_entire_file(infile, &filesize);
		}
		if (!inbuf) {
			errorcnt++;
			break;
		}

		/* With no args, show the HWID */
		if (!opt_rootkey && !opt_bmpfv && !opt_recoverykey
		    && !sel_flags && !sel_digest)
			sel_hwid = true;

		struct vb2_gbb_header *gbb = FindGbbHeader(inbuf, filesize);
		if (!gbb) {
			ERROR("No GBB found in %s\n", infile);
			errorcnt++;
			break;
		}
		uint8_t *gbb_base = (uint8_t *) gbb;

		/* Get the stuff */
		if (sel_hwid)
			printf("hardware_id: %s\n",
			       gbb->hwid_size ? (char *)(gbb_base +
							 gbb->
							 hwid_offset) : "");
		if (sel_digest)
			print_hwid_digest(gbb, "digest: ");

		if (sel_flags)
			printf("flags: 0x%08x\n", gbb->flags);
		if (opt_rootkey)
			if (write_to_file(" - exported root_key to file:",
					  opt_rootkey,
					  gbb_base + gbb->rootkey_offset,
					  gbb->rootkey_size)) {
				errorcnt++;
				break;
			}
		if (opt_bmpfv)
			if (write_to_file(
				    " - exported bmp_fv to file:", opt_bmpfv,
				    gbb_base + gbb->bmpfv_offset,
				    gbb->bmpfv_size)) {
				errorcnt++;
				break;
			}
		if (opt_recoverykey)
			if (write_to_file(" - exported recovery_key to file:",
					  opt_recoverykey,
					  gbb_base + gbb->recovery_key_offset,
					  gbb->recovery_key_size)) {
				errorcnt++;
				break;
			}
		if (explicit_flags) {
			vb2_gbb_flags_t remaining_flags = gbb->flags;
			while (remaining_flags) {
				vb2_gbb_flags_t lsb_flag =
					remaining_flags & -remaining_flags;
				remaining_flags &= ~lsb_flag;
				const char *name;
				const char *description;
				if (vb2_get_gbb_flag_description(
					    lsb_flag, &name, &description) ==
				    VB2_SUCCESS) {
					printf("%s\n", name);
				} else {
					printf("unknown set flag: 0x%08x\n",
					       lsb_flag);
				}
			}
		}
		break;

	case DO_SET:
		if (args.use_flash) {
			inbuf = read_from_flash(cfg, &filesize);
		} else {
			if (argc - optind < 1) {
				ERROR("Missing input filename\n");
				print_help(argc, argv);
				errorcnt++;
				break;
			}
			infile = argv[optind++];
			inbuf = read_entire_file(infile, &filesize);
			if (!outfile)
				outfile = (argc - optind < 1) ? infile
							      : argv[optind++];
		}
		if (!inbuf) {
			errorcnt++;
			break;
		}

		if (sel_hwid && !opt_hwid) {
			ERROR("Missing new HWID value\n");
			print_help(argc, argv);
			errorcnt++;
			break;
		}
		if (sel_flags && (!opt_flags || !*opt_flags)) {
			ERROR("Missing new flags value\n");
			print_help(argc, argv);
			errorcnt++;
			break;
		}

		gbb = FindGbbHeader(inbuf, filesize);
		if (!gbb) {
			ERROR("No GBB found in %s\n", infile);
			errorcnt++;
			break;
		}
		gbb_base = (uint8_t *) gbb;

		outbuf = (uint8_t *) malloc(filesize);
		if (!outbuf) {
			ERROR("Can't malloc %" PRIi64 " bytes: %s\n", filesize,
			      strerror(errno));
			errorcnt++;
			break;
		}

		/* Switch pointers to outbuf */
		memcpy(outbuf, inbuf, filesize);
		gbb = FindGbbHeader(outbuf, filesize);
		if (!gbb) {
			ERROR("INTERNAL ERROR: No GBB found in outbuf\n");
			errorcnt++;
			break;
		}
		gbb_base = (uint8_t *) gbb;

		if (opt_hwid) {
			if (strlen(opt_hwid) + 1 > gbb->hwid_size) {
				ERROR("null-terminated HWID exceeds capacity (%d)\n",
					gbb->hwid_size);
				errorcnt++;
				break;
			}
			/* Wipe data before writing new value. */
			memset(gbb_base + gbb->hwid_offset, 0,
				gbb->hwid_size);
			strcpy((char *)(gbb_base + gbb->hwid_offset),
				opt_hwid);
			update_hwid_digest(gbb);
		}

		if (opt_flags) {
			vb2_gbb_flags_t val;
			const int flag_sign = parse_flag_value(opt_flags, &val);
			if (flag_sign < 0) {
				errorcnt++;
				break;
			}
			if (flag_sign > 0)
				/* flag_sign := 1 => +ve and flag_sign := 2 => -ve. */
				gbb->flags = flag_sign == 1 ? (gbb->flags | val) : (gbb->flags & ~val);
			else
				gbb->flags = val;
		}

		if (opt_rootkey) {
			if (read_from_file("root_key", opt_rootkey,
					   gbb_base + gbb->rootkey_offset,
					   gbb->rootkey_size)) {
				errorcnt++;
				break;
			}
		}
		if (opt_bmpfv)
			if (read_from_file("bmp_fv", opt_bmpfv,
					   gbb_base + gbb->bmpfv_offset,
					   gbb->bmpfv_size)) {
				errorcnt++;
				break;
			}
		if (opt_recoverykey)
			if (read_from_file("recovery_key", opt_recoverykey,
					   gbb_base + gbb->recovery_key_offset,
					   gbb->recovery_key_size)) {
				errorcnt++;
				break;
			}

		/* Write it out if there are no problems. */
		if (!errorcnt) {
			if (args.use_flash) {
				if (write_to_flash(cfg, outbuf, filesize)) {
					errorcnt++;
					break;
				}
			} else if (write_to_file(
					   "successfully saved new image to:",
					   outfile, outbuf, filesize)) {
				errorcnt++;
				break;
			}
		}
		break;

	case DO_CREATE:
		if (!outfile) {
			if (argc - optind < 1) {
				ERROR("Missing output filename\n");
				print_help(argc, argv);
				errorcnt++;
				break;
			}
			outfile = argv[optind++];
		}
		/* Parse the creation args */
		outbuf = create_gbb(opt_create, &filesize);
		if (!outbuf) {
			ERROR("Unable to parse creation spec (%s)\n", opt_create);
			print_help(argc, argv);
			errorcnt++;
			break;
		}
		if (!errorcnt)
			if (write_to_file("successfully created new GBB to:",
					  outfile, outbuf, filesize)) {
				errorcnt++;
				break;
			}
		break;
	}

	if (args.use_flash)
		teardown_flash(cfg);
	if (inbuf)
		free(inbuf);
	if (outbuf)
		free(outbuf);
	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(gbb, do_gbb, VBOOT_VERSION_ALL,
		      "Manipulate the Google Binary Block (GBB)");
DECLARE_FUTIL_COMMAND(gbb_utility, do_gbb, VBOOT_VERSION_ALL,
		      "Legacy name for `gbb` command");
