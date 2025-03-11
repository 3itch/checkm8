/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Verified boot key utility
 */

#include <getopt.h>
#include <inttypes.h>		/* For PRIu64 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "futility.h"
#include "host_common.h"
#include "host_key21.h"
#include "util_misc.h"
#include "vb1_helper.h"

/* Command line options */
enum {
	OPT_INKEY = 1000,
	OPT_KEY_VERSION,
	OPT_ALGORITHM,
	OPT_MODE_PACK,
	OPT_MODE_UNPACK,
	OPT_COPYTO,
	OPT_HELP,
};

static const struct option long_opts[] = {
	{"key", 1, 0, OPT_INKEY},
	{"version", 1, 0, OPT_KEY_VERSION},
	{"algorithm", 1, 0, OPT_ALGORITHM},
	{"pack", 1, 0, OPT_MODE_PACK},
	{"unpack", 1, 0, OPT_MODE_UNPACK},
	{"copyto", 1, 0, OPT_COPYTO},
	{"help", 0, 0, OPT_HELP},
	{NULL, 0, 0, 0}
};

static void print_help(int argc, char *argv[])
{
	printf("\n"
	       "Usage:  " MYNAME " %s --pack <outfile> [PARAMETERS]\n"
	       "\n"
	       "  Required parameters:\n"
	       "    --key <infile>              RSA key file (.keyb or .pem)\n"
	       "    --version <number>          Key version number "
	       "(required for .keyb,\n"
	       "                                  ignored for .pem)\n"
	       "    --algorithm <number>        "
	       "Signing algorithm to use with key:\n", argv[0]);

	for (enum vb2_crypto_algorithm i = 0; i < VB2_ALG_COUNT; i++) {
		printf("                                  %d = (%s)\n",
		       i, vb2_get_crypto_algorithm_name(i));
	}

	printf("\nOR\n\n"
	       "Usage:  " MYNAME " %s --unpack <infile>\n"
	       "\n"
	       "  Optional parameters:\n"
	       "    --copyto <file>             "
	       "Write a copy of the key to this file.\n\n", argv[0]);
}

/* Pack a .keyb file into a .vbpubk, or a .pem into a .vbprivk */
static int do_pack(const char *infile, const char *outfile, uint32_t algorithm,
		   uint32_t version)
{
	if (!infile || !outfile) {
		ERROR("vbutil_key: Must specify --in and --out\n");
		return 1;
	}

	struct vb2_packed_key *pubkey =
		vb2_read_packed_keyb(infile, algorithm, version);
	if (pubkey) {
		if (vb2_write_packed_key(outfile, pubkey)) {
			ERROR("vbutil_key: Error writing key.\n");
			free(pubkey);
			return 1;
		}
		free(pubkey);
		return 0;
	}

	struct vb2_private_key *privkey =
		vb2_read_private_key_pem(infile, algorithm);
	if (privkey) {
		if (VB2_SUCCESS != vb2_write_private_key(outfile, privkey)) {
			ERROR("vbutil_key: Error writing key.\n");
			free(privkey);
			return 1;
		}
		free(privkey);
		return 0;
	}

	FATAL("Unable to parse either .keyb or .pem from %s\n", infile);
	return 1;
}

/* Unpack a .vbpubk, .vbprivk, or .vbprik2 */
static int do_unpack(const char *infile, const char *outfile)
{
	struct vb2_packed_key *pubkey;

	if (!infile) {
		ERROR("Need file to unpack\n");
		return 1;
	}

	pubkey = vb2_read_packed_key(infile);
	if (pubkey) {
		printf("Public Key file:   %s\n", infile);
		printf("Algorithm:         %u %s\n", pubkey->algorithm,
		       vb2_get_crypto_algorithm_name(pubkey->algorithm));
		printf("Key Version:       %u\n", pubkey->key_version);
		printf("Key sha1sum:       %s\n",
		       packed_key_sha1_string(pubkey));
		if (outfile &&
		    VB2_SUCCESS != vb2_write_packed_key(outfile, pubkey)) {
			ERROR("butil_key: Error writing key copy\n");
			free(pubkey);
			return 1;
		}
		free(pubkey);
		return 0;
	}

	struct vb2_private_key *privkey = vb2_read_private_key(infile);
	if (privkey) {
		printf("Private Key file:  %s\n", infile);

		enum vb2_crypto_algorithm alg =
			vb2_get_crypto_algorithm(privkey->hash_alg,
						 privkey->sig_alg);
		printf("Algorithm:         %u %s\n", alg,
		       vb2_get_crypto_algorithm_name(alg));
		if (outfile &&
		    VB2_SUCCESS != vb2_write_private_key(outfile, privkey)) {
			ERROR("vbutil_key: Error writing key copy\n");
			free(privkey);
			return 1;
		}
		free(privkey);
		return 0;
	}

	FATAL("Unable to parse either .vbpubk or vbprivk from %s\n", infile);
	return 1;
}

static int do_vbutil_key(int argc, char *argv[])
{

	char *infile = NULL;
	char *outfile = NULL;
	int mode = 0;
	int parse_error = 0;
	uint32_t version = 1;
	uint32_t algorithm = VB2_ALG_COUNT;
	char *e;
	int i;

	while ((i = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (i) {
		case '?':
			/* Unhandled option */
			FATAL("Unknown option\n");
			parse_error = 1;
			break;
		case OPT_HELP:
			print_help(argc, argv);
			return !!parse_error;

		case OPT_INKEY:
			infile = optarg;
			break;

		case OPT_KEY_VERSION:
			version = strtoul(optarg, &e, 0);
			if (!*optarg || (e && *e)) {
				FATAL("Invalid --version\n");
				parse_error = 1;
			}
			break;

		case OPT_ALGORITHM:
			algorithm = strtoul(optarg, &e, 0);
			if (!*optarg || (e && *e)) {
				FATAL("Invalid --algorithm\n");
				parse_error = 1;
			}
			break;

		case OPT_MODE_PACK:
			mode = i;
			outfile = optarg;
			break;

		case OPT_MODE_UNPACK:
			mode = i;
			infile = optarg;
			break;

		case OPT_COPYTO:
			outfile = optarg;
			break;
		}
	}

	if (parse_error) {
		print_help(argc, argv);
		return 1;
	}

	switch (mode) {
	case OPT_MODE_PACK:
		return do_pack(infile, outfile, algorithm, version);
	case OPT_MODE_UNPACK:
		return do_unpack(infile, outfile);
	default:
		printf("Must specify a mode.\n");
		print_help(argc, argv);
		return 1;
	}
}

DECLARE_FUTIL_COMMAND(vbutil_key, do_vbutil_key, VBOOT_VERSION_1_0,
		      "Wraps RSA keys with vboot headers");
