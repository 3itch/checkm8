/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <openssl/pem.h>

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "2common.h"
#include "2id.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common21.h"
#include "host_key.h"
#include "host_key21.h"
#include "host_misc21.h"
#include "openssl_compat.h"
#include "util_misc.h"
#include "vboot_host.h"

/* Command line options */
enum {
	OPT_OUTFILE = 1000,
	OPT_VERSION,
	OPT_DESC,
	OPT_ID,
	OPT_HASH_ALG,
	OPT_HELP,
};

#define DEFAULT_VERSION 1
#define DEFAULT_HASH VB2_HASH_SHA256;

static const struct option long_opts[] = {
	{"version",  1, 0, OPT_VERSION},
	{"desc",     1, 0, OPT_DESC},
	{"id",       1, 0, OPT_ID},
	{"hash_alg", 1, 0, OPT_HASH_ALG},
	{"help",     0, 0, OPT_HELP},
	{NULL, 0, 0, 0}
};

static void print_help(int argc, char *argv[])
{
	enum vb2_hash_algorithm alg;

	printf("\n"
"Usage:  " MYNAME " %s [options] <INFILE> [<BASENAME>]\n", argv[0]);
	printf("\n"
"Create a keypair from an RSA key (.pem file).\n"
"\n"
"Options:\n"
"\n"
"  --version <number>          Key version (default %d)\n"
"  --hash_alg <number>         Hashing algorithm to use:\n",
		DEFAULT_VERSION);
	for (alg = 0; alg < VB2_HASH_ALG_COUNT; alg++) {
		const char *name = vb2_get_hash_algorithm_name(alg);
		if (strcmp(name, VB2_INVALID_ALG_NAME) != 0)
			printf("                                %d / %s%s\n",
			       alg, name,
			       alg == VB2_HASH_SHA256 ? " (default)" : "");
	}
	printf(
"  --id <id>                   Identifier for this keypair (vb21 only)\n"
"  --desc <text>               Human-readable description (vb21 only)\n"
"\n");

}

static int vb1_make_keypair(const char *infile, const char *outfile,
			    char *outext, uint32_t version,
			    enum vb2_hash_algorithm hash_alg)
{
	struct vb2_private_key *privkey = NULL;
	struct vb2_packed_key *pubkey = NULL;
	struct rsa_st *rsa_key = NULL;
	uint8_t *keyb_data = 0;
	uint32_t keyb_size;
	int ret = 1;

	FILE *fp = fopen(infile, "rb");
	if (!fp) {
		ERROR("Unable to open %s\n", infile);
		goto done;
	}

	/* TODO: this is very similar to vb2_read_private_key_pem() */

	rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!rsa_key) {
		ERROR("Unable to read RSA key from %s\n", infile);
		goto done;
	}

	enum vb2_signature_algorithm sig_alg = vb2_rsa_sig_alg(rsa_key);
	if (sig_alg == VB2_SIG_INVALID) {
		ERROR("Unsupported sig algorithm in RSA key\n");
		goto done;
	}

	/* Combine the sig_alg with the hash_alg to get the vb1 algorithm */
	uint64_t vb1_algorithm = vb2_get_crypto_algorithm(hash_alg, sig_alg);

	/* Create the private key */
	privkey = (struct vb2_private_key *)calloc(sizeof(*privkey), 1);
	if (!privkey)
		goto done;

	privkey->rsa_private_key = rsa_key;
	privkey->sig_alg = sig_alg;
	privkey->hash_alg = hash_alg;

	/* Write it out */
	strcpy(outext, ".vbprivk");
	if (vb2_write_private_key(outfile, privkey)) {
		ERROR("Unable to write private key\n");
		goto done;
	}
	printf("wrote %s\n", outfile);

	/* Create the public key */
	ret = vb_keyb_from_rsa(rsa_key, &keyb_data, &keyb_size);
	if (ret) {
		ERROR("Couldn't extract the public key\n");
		goto done;
	}

	pubkey = vb2_alloc_packed_key(keyb_size, vb1_algorithm, version);
	if (!pubkey)
		goto done;
	memcpy((uint8_t *)vb2_packed_key_data(pubkey), keyb_data, keyb_size);

	/* Write it out */
	strcpy(outext, ".vbpubk");
	if (VB2_SUCCESS != vb2_write_packed_key(outfile, pubkey)) {
		ERROR("Unable to write public key\n");
		goto done;
	}
	printf("wrote %s\n", outfile);

	ret = 0;

done:
	free(privkey);
	free(pubkey);
	free(keyb_data);
	RSA_free(rsa_key);
	return ret;
}

static int vb2_make_keypair(const char *infile, const char *outfile,
			    char *outext, char *desc, struct vb2_id *id,
			    bool force_id, uint32_t version,
			    enum vb2_hash_algorithm hash_alg)
{
	struct vb2_private_key *privkey = 0;
	struct vb2_public_key *pubkey = 0;
	RSA *rsa_key = 0;
	uint8_t *keyb_data = 0;
	uint32_t keyb_size;
	enum vb2_signature_algorithm sig_alg;
	uint8_t *pubkey_buf = 0;
	int has_priv = 0;
	const BIGNUM *rsa_d;

	FILE *fp;
	int ret = 1;

	fp = fopen(infile, "rb");
	if (!fp) {
		ERROR("Unable to open %s\n", infile);
		goto done;
	}

	rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

	if (!rsa_key) {
		/* Check if the PEM contains only a public key */
		if (fseek(fp, 0, SEEK_SET)) {
			ERROR("Seeking in %s\n", infile);
			goto done;
		}
		rsa_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	}
	fclose(fp);
	if (!rsa_key) {
		ERROR("Unable to read RSA key from %s\n", infile);
		goto done;
	}
	/* Public keys doesn't have the private exponent */
	RSA_get0_key(rsa_key, NULL, NULL, &rsa_d);
	has_priv = !!rsa_d;
	if (!has_priv)
		ERROR("%s has a public key only.\n", infile);

	sig_alg = vb2_rsa_sig_alg(rsa_key);
	if (sig_alg == VB2_SIG_INVALID) {
		ERROR("Unsupported sig algorithm in RSA key\n");
		goto done;
	}

	if (has_priv) {
		/* Create the private key */
		privkey = calloc(1, sizeof(*privkey));
		if (!privkey) {
			ERROR("Unable to allocate the private key\n");
			goto done;
		}

		privkey->rsa_private_key = rsa_key;
		privkey->sig_alg = sig_alg;
		privkey->hash_alg = hash_alg;
		if (desc && vb2_private_key_set_desc(privkey, desc)) {
			ERROR("Unable to set the private key description\n");
			goto done;
		}
	}

	/* Create the public key */
	if (vb2_public_key_alloc(&pubkey, sig_alg)) {
		ERROR("Unable to allocate the public key\n");
		goto done;
	}

	/* Extract the keyb blob */
	if (vb_keyb_from_rsa(rsa_key, &keyb_data, &keyb_size)) {
		ERROR("Couldn't extract the public key\n");
		goto done;
	}

	/*
	 * Copy the keyb blob to the public key's buffer, because that's where
	 * vb2_unpack_key_data() and vb2_public_key_pack() expect to find it.
	 */
	pubkey_buf = vb2_public_key_packed_data(pubkey);
	memcpy(pubkey_buf, keyb_data, keyb_size);

	/* Fill in the internal struct pointers */
	if (vb2_unpack_key_data(pubkey, pubkey_buf, keyb_size)) {
		ERROR("Unable to unpack the public key blob\n");
		goto done;
	}

	pubkey->hash_alg = hash_alg;
	pubkey->version = version;
	if (desc && vb2_public_key_set_desc(pubkey, desc)) {
		ERROR("Unable to set pubkey description\n");
		goto done;
	}

	/* Update the IDs */
	if (!force_id) {
		struct vb2_hash hash;
		vb2_hash_calculate(false, keyb_data, keyb_size, VB2_HASH_SHA1,
				   &hash);
		memcpy(id->raw, hash.raw, sizeof(id->raw));
	}

	memcpy((struct vb2_id *)pubkey->id, id, sizeof(*id));

	/* Write them out */
	if (has_priv) {
		privkey->id = *id;
		strcpy(outext, ".vbprik2");
		if (vb21_private_key_write(privkey, outfile)) {
			ERROR("Unable to write private key\n");
			goto done;
		}
		printf("wrote %s\n", outfile);
	}

	strcpy(outext, ".vbpubk2");
	if (vb21_public_key_write(pubkey, outfile)) {
		ERROR("Unable to write public key\n");
		goto done;
	}
	printf("wrote %s\n", outfile);

	ret = 0;

done:
	RSA_free(rsa_key);
	if (privkey)				/* prevent double-free */
		privkey->rsa_private_key = 0;
	vb2_free_private_key(privkey);
	vb2_public_key_free(pubkey);
	free(keyb_data);
	return ret;
}

static int do_create(int argc, char *argv[])
{
	int errorcnt = 0;
	int i;
	char *e;
	char *opt_desc = NULL;
	struct vb2_id opt_id;
	bool force_id = false;
	uint32_t opt_version = DEFAULT_VERSION;
	enum vb2_hash_algorithm opt_hash_alg = DEFAULT_HASH;


	while ((i = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (i) {

		case OPT_VERSION:
			opt_version = strtoul(optarg, &e, 0);
			if (!*optarg || (e && *e)) {
				ERROR("Invalid version \"%s\"\n", optarg);
				errorcnt = 1;
			}
			break;

		case OPT_DESC:
			opt_desc = optarg;
			break;

		case OPT_ID:
			if (VB2_SUCCESS != vb2_str_to_id(optarg, &opt_id)) {
				ERROR("Invalid id \"%s\"\n", optarg);
				errorcnt = 1;
			}
			force_id = true;
			break;

		case OPT_HASH_ALG:
			if (!vb2_lookup_hash_alg(optarg, &opt_hash_alg)) {
				ERROR("Invalid hash_alg \"%s\"\n", optarg);
				errorcnt++;
			}
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
		case 0:				/* handled option */
			break;
		default:
			FATAL("Unrecognized getopt output: %d\n", i);
		}
	}

	if (argc - optind <= 0) {
		ERROR("Missing input filename\n");
		errorcnt++;
	}
	if (errorcnt) {
		print_help(argc, argv);
		return 1;
	}
	char *infile = argv[optind++];

	/* Decide how to determine the output filenames. */
	bool remove_ext = false;
	char *s;
	if (argc > optind) {
		s = argv[optind++];		/* just use this */
	} else {
		s = infile;			/* based on pem file name */
		remove_ext = true;
	}

	/* Make an extra-large copy to leave room for filename extensions */
	char *outfile = (char *)malloc(strlen(s) + 20);
	if (!outfile) {
		ERROR("malloc() failed\n");
		return 1;
	}
	strcpy(outfile, s);

	if (remove_ext) {
		/* Find the last '/' if any, then the last '.' before that. */
		s = strrchr(outfile, '/');
		if (!s)
			s = outfile;
		s = strrchr(s, '.');
		/* Cut off the extension */
		if (s)
			*s = '\0';
	}
	/* Remember that spot for later */
	char *outext = outfile + strlen(outfile);

	/* Okay, do it */
	int r;
	if (vboot_version == VBOOT_VERSION_1_0)
		r = vb1_make_keypair(infile, outfile, outext, opt_version,
				     opt_hash_alg);
	else
		r = vb2_make_keypair(infile, outfile, outext, opt_desc, &opt_id,
				     force_id, opt_version, opt_hash_alg);

	free(outfile);
	return r;
}

DECLARE_FUTIL_COMMAND(create, do_create, VBOOT_VERSION_ALL,
		      "Create a keypair from an RSA .pem file");
