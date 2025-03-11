/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fmap.h"
#include "futility.h"

static const char usage[] = "\n"
	"Usage:  " MYNAME " %s [OPTIONS] FILE AREA:file [AREA:file ...]\n"
	"\n"
	"Replace the contents of specific FMAP areas. This is the complement\n"
	"of " MYNAME " dump_fmap -x FILE AREA [AREA ...]\n"
	"\n"
	"Options:\n"
	"  -o OUTFILE     Write the result to this file, instead of modifying\n"
	"                   the input file. This is safer, since there are no\n"
	"                   safeguards against doing something stupid.\n"
	"\n"
	"Example:\n"
	"\n"
	"  This will clear the RO_VPD area, and scramble VBLOCK_B:\n"
	"\n"
	"  " MYNAME " %s image.bin RO_VPD:/dev/zero VBLOCK_B:/dev/urandom\n"
	"\n";

static void print_help(int argc, char *argv[])
{
	printf(usage, argv[0], argv[0]);
}

enum {
	OPT_HELP = 1000,
};
static const struct option long_opts[] = {
	/* name    hasarg *flag  val */
	{"help",        0, NULL, OPT_HELP},
	{NULL,          0, NULL, 0},
};
static const char *short_opts = ":o:";


static int copy_to_area(const char *file, uint8_t *buf,
			const uint32_t len, const char *area)
{
	int retval = 0;

	FILE *fp = fopen(file, "r");
	if (!fp) {
		ERROR("area %s: can't open %s for reading: %s\n",
			area, file, strerror(errno));
		return 1;
	}

	size_t n = fread(buf, 1, len, fp);
	if (!n) {
		if (feof(fp))
			ERROR("area %s: unexpected EOF on %s\n", area, file);
		if (ferror(fp))
			ERROR("area %s: can't read from %s: %s\n",
				area, file, strerror(errno));
		retval = 1;
	} else if (n < len) {
		WARN("area %s: %s size (%zu) smaller than area size %u; "
		     "erasing remaining data to 0xff\n",
		     area, file, n, len);
		memset(buf + n, 0xff, len - n);
	}

	if (fclose(fp)) {
		ERROR("area %s: error closing %s: %s\n",
			area, file, strerror(errno));
		retval = 1;
	}

	return retval;
}


static int do_load_fmap(int argc, char *argv[])
{
	char *outfile = NULL;
	int errorcnt = 0;
	int i;

	opterr = 0;		/* quiet, you */
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		switch (i) {
		case 'o':
			outfile = optarg;
			break;
		case OPT_HELP:
			print_help(argc, argv);
			return !!errorcnt;
		case '?':
			if (optopt)
				ERROR("Unrecognized option: -%c\n",
					optopt);
			else
				ERROR("Unrecognized option\n");
			errorcnt++;
			break;
		case ':':
			ERROR("Missing argument to -%c\n", optopt);
			errorcnt++;
			break;
		default:
			FATAL("Unrecognized getopt output: %d\n", i);
		}
	}

	if (errorcnt) {
		print_help(argc, argv);
		return 1;
	}

	if (argc - optind < 2) {
		ERROR("You must specify an input file"
			" and at least one AREA:file argument\n");
		print_help(argc, argv);
		return 1;
	}

	const char *infile = argv[optind++];

	/* okay, let's do it ... */
	if (!outfile)
		outfile = (char *)infile;
	else
		if (futil_copy_file(infile, outfile) < 0)
			exit(1);

	int fd;
	uint8_t *buf;
	uint32_t len;
	errorcnt |= futil_open_and_map_file(outfile, &fd, FILE_RW, &buf, &len);
	if (errorcnt)
		goto done;

	FmapHeader *fmap = fmap_find(buf, len);
	if (!fmap) {
		ERROR("Can't find an FMAP in %s\n", infile);
		errorcnt++;
		goto done;
	}

	for (i = optind; i < argc; i++) {
		char *a = argv[i];
		char *f = strchr(a, ':');

		if (!f || a == f || *(f+1) == '\0') {
			ERROR("argument \"%s\" is bogus\n", a);
			errorcnt++;
			break;
		}
		*f++ = '\0';

		FmapAreaHeader *ah;
		uint8_t *area_buf = fmap_find_by_name(buf, len, fmap, a, &ah);
		if (!area_buf) {
			ERROR("Can't find area \"%s\" in FMAP\n", a);
			errorcnt++;
			break;
		}

		if (copy_to_area(f, area_buf, ah->area_size, a)) {
			errorcnt++;
			break;
		}
	}

done:
	errorcnt |= futil_unmap_and_close_file(fd, FILE_RW, buf, len);
	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(load_fmap, do_load_fmap, VBOOT_VERSION_ALL,
		      "Replace the contents of specified FMAP areas");
