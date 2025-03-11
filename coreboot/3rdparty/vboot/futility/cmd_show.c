/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <openssl/rsa.h>

#include <errno.h>
#include <fcntl.h>
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

#include "2api.h"
#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "cbfstool.h"
#include "file_type_bios.h"
#include "file_type.h"
#include "fmap.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common.h"
#include "host_key21.h"
#include "host_misc.h"
#include "util_misc.h"
#include "vb1_helper.h"

/* Options */
struct show_option_s show_option = {
	.type = FILE_TYPE_UNKNOWN,
};

/* Shared work buffer */
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_workbuf wb;

void show_pubkey(const struct vb2_packed_key *pubkey, const char *sp)
{
	// Clear out formatting if we are in parseable mode.
	if (show_option.parseable)
		sp = "\0";
	FT_PRINT("%sVboot API:           1.0\n", "%sapi::1.0\n", sp);
	FT_PRINT("%sAlgorithm:           %d %s\n",
		 "%salgorithm::%d::%s\n",
		 sp, pubkey->algorithm,
		 vb2_get_crypto_algorithm_name(pubkey->algorithm));
	FT_PRINT("%sKey Version:         %d\n", "%sversion::%d\n",
		 sp, pubkey->key_version);
	FT_PRINT("%sKey sha1sum:         %s\n", "%ssha1_sum::%s\n",
		 sp, packed_key_sha1_string(pubkey));
}

static void show_keyblock(struct vb2_keyblock *keyblock, const char *print_name,
			  int sign_key, int good_sig)
{
	const struct vb2_signature *sig = &keyblock->keyblock_signature;

	if (print_name)
		FT_READABLE_PRINT("Keyblock:                %s\n", print_name);
	else
		FT_READABLE_PRINT("Keyblock:\n");

	FT_PRINT("  Size:                  %#x\n",
		 "size::%d\n", keyblock->keyblock_size);
	FT_PRINT("  Signature:             %s\n", "signature::%s\n",
		 sign_key ? (good_sig ? "valid" : "invalid") : "ignored");
	FT_PRINT("    Size:                %#x\n", "signature::size::%u\n",
		 sig->sig_size);
	FT_PRINT("    Data size:           %#x\n", "signature::data_size::%u\n",
		 sig->data_size);
	FT_PRINT("  Flags:                 %d ",
		 "flags::%d:", keyblock->keyblock_flags);
	if (keyblock->keyblock_flags & VB2_KEYBLOCK_FLAG_DEVELOPER_0)
		FT_PRINT_RAW(" !DEV", ":!DEV");
	if (keyblock->keyblock_flags & VB2_KEYBLOCK_FLAG_DEVELOPER_1)
		FT_PRINT_RAW(" DEV", ":DEV");
	if (keyblock->keyblock_flags & VB2_KEYBLOCK_FLAG_RECOVERY_0)
		FT_PRINT_RAW(" !REC", ":!REC");
	if (keyblock->keyblock_flags & VB2_KEYBLOCK_FLAG_RECOVERY_1)
		FT_PRINT_RAW(" REC", ":REC");
	if (keyblock->keyblock_flags & VB2_KEYBLOCK_FLAG_MINIOS_0)
		FT_PRINT_RAW(" !MINIOS", ":!MINIOS");
	if (keyblock->keyblock_flags & VB2_KEYBLOCK_FLAG_MINIOS_1)
		FT_PRINT_RAW(" MINIOS", ":MINIOS");
	printf("\n");

	struct vb2_packed_key *data_key = &keyblock->data_key;
	FT_PRINT("  Data key algorithm:    %d %s\n",
		 "data_key::algorithm::%d::%s\n", data_key->algorithm,
		 vb2_get_crypto_algorithm_name(data_key->algorithm));
	FT_PRINT("  Data key version:      %d\n", "data_key::version::%d\n",
		 data_key->key_version);
	FT_PRINT("  Data key sha1sum:      %s\n", "data_key::sha1_sum::%s\n",
		 packed_key_sha1_string(data_key));
}

int ft_show_pubkey(const char *fname)
{
	int fd = -1;
	struct vb2_packed_key *pubkey;
	uint32_t len;
	int rv = 0;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, (uint8_t **)&pubkey,
				     &len))
		return 1;

	if (vb2_packed_key_looks_ok(pubkey, len)) {
		ERROR("Invalid public key: %s\n", fname);
		rv = 1;
		goto done;
	}
	FT_READABLE_PRINT("Public Key file:       %s\n", fname);

	ft_print_header = "pubkey";
	show_pubkey(pubkey, "  ");

done:
	futil_unmap_and_close_file(fd, FILE_RO, (uint8_t *)pubkey, len);
	return rv;
}

int ft_show_privkey(const char *fname)
{
	int fd = -1;
	int rv = 0;
	struct vb2_packed_private_key *pkey = NULL;
	uint32_t len;
	struct vb2_private_key key;
	const unsigned char *start;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, (uint8_t **)&pkey,
				     &len))
		return 1;

	start = pkey->key_data;
	if (len <= sizeof(*pkey)) {
		ERROR("Invalid private key: %s\n", fname);
		rv = 1;
		goto done;
	}
	len -= sizeof(*pkey);
	key.rsa_private_key = d2i_RSAPrivateKey(NULL, &start, len);


	ft_print_header = "prikey";
	FT_READABLE_PRINT("Private Key file:      %s\n", fname);
	FT_PRINT("  Vboot API:           1.0\n", "api::1.0\n");
	FT_PRINT("  Algorithm:           %u %s\n",
		 "algorithm::%d::%s\n", pkey->algorithm,
		 vb2_get_crypto_algorithm_name(pkey->algorithm));
	FT_PRINT("  Key sha1sum:         %s\n", "sha1_sum::%s\n",
		 private_key_sha1_string(&key));

done:
	futil_unmap_and_close_file(fd, FILE_RO, (uint8_t *)pkey, len);
	return rv;
}

int ft_show_keyblock(const char *fname)
{
	struct vb2_keyblock *block;
	struct vb2_public_key *sign_key = show_option.k;
	int good_sig = 0;
	int retval = 0;
	int fd = -1;
	uint32_t len;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, (uint8_t **)&block, &len))
		return 1;

	ft_print_header = "keyblock";

	/* Check the hash only first */
	if (vb2_verify_keyblock_hash(block, len, &wb)) {
		ERROR("%s is invalid\n", fname);
		FT_PARSEABLE_PRINT("invalid\n");
		retval = 1;
		goto done;
	} else {
		FT_PARSEABLE_PRINT("valid\n");
	}

	/* Check the signature if we have one */
	if (sign_key &&
	    VB2_SUCCESS == vb2_verify_keyblock(block, len, sign_key, &wb))
		good_sig = 1;
	else if (show_option.strict)
		retval = 1;

	show_keyblock(block, fname, !!sign_key, good_sig);

done:
	futil_unmap_and_close_file(fd, FILE_RO, (uint8_t *)block, len);
	return retval;
}

static int fw_show_metadata_hash(const char *fname, enum bios_component body_c,
				 struct vb2_fw_preamble *pre)
{
	struct vb2_hash real_hash;
	struct vb2_hash *body_hash =
		(struct vb2_hash *)vb2_signature_data(&pre->body_signature);
	const uint32_t bhsize = vb2_digest_size(body_hash->algo);

	if (!bhsize || pre->body_signature.sig_size <
			       offsetof(struct vb2_hash, raw) + bhsize) {
		ERROR("Body signature data is too small to fit metadata hash.\n");
		return 1;
	}

	FT_READABLE_PRINT("  Body metadata hash:    %s ",
			  vb2_get_hash_algorithm_name(body_hash->algo));
	FT_PARSEABLE_PRINT("body::metadata_hash::algorithm::%d::%s\n",
			   body_hash->algo,
			   vb2_get_hash_algorithm_name(body_hash->algo));
	if (vb2_digest_size(body_hash->algo)) {
		FT_PARSEABLE_PRINT("body::metadata_hash::hex::");
		print_bytes((uint8_t *)body_hash->raw,
			    vb2_digest_size(body_hash->algo));
		putchar('\n');
	}

	if (cbfstool_get_metadata_hash(fname, fmap_name[body_c], &real_hash) !=
		    VB2_SUCCESS ||
	    real_hash.algo == VB2_HASH_INVALID) {
		ERROR("Failed to get metadata hash. Firmware body is"
			" corrupted or is not a valid CBFS.\n");
		FT_PARSEABLE_PRINT("body::metadata_hash::invalid\n");
		FT_PARSEABLE_PRINT("body::signature::invalid\n");
		return 1;
	}

	if (body_hash->algo != real_hash.algo ||
	    !vb2_digest_size(body_hash->algo) ||
	    memcmp(body_hash->raw, real_hash.raw,
		   vb2_digest_size(body_hash->algo))) {
		FT_READABLE_PRINT("  MISMATCH! Real hash:   %s:",
		       vb2_get_hash_algorithm_name(real_hash.algo));
		FT_PARSEABLE_PRINT("body::metadata_hash::invalid\n");
		FT_PARSEABLE_PRINT(
			"body::metadata_hash::expected::algorithm::%d::%s\n",
			real_hash.algo,
			vb2_get_hash_algorithm_name(real_hash.algo));

		FT_PARSEABLE_PRINT("body::metadata_hash::expected::hex::");

		print_bytes(&real_hash.raw, vb2_digest_size(real_hash.algo));
		putchar('\n');
		ERROR("Signature hash does not match with"
			" real metadata hash.\n");

		/* To balance out signature::valid otherwise printed by caller. */
		FT_PARSEABLE_PRINT("body::signature::invalid\n");
		return 1;
	} else {
		FT_PRINT("  Body metadata hash valid!\n",
			 "body::metadata_hash::valid\n");
	}
	return 0;
}

int show_fw_preamble_buf(const char *fname, uint8_t *buf, uint32_t len,
			 struct bios_state_s *state)
{
	const char *print_name = state ? fmap_name[state->c] : fname;
	struct vb2_keyblock *keyblock = (struct vb2_keyblock *)buf;
	struct vb2_public_key *sign_key = show_option.k;
	uint8_t *fv_data = show_option.fv;
	uint64_t fv_size = show_option.fv_size;
	struct bios_area_s *fw_body_area = 0;
	enum bios_component body_c = BIOS_FMAP_FW_MAIN_A;
	int good_sig = 0;
	int retval = 0;

	ft_print_header2 = "keyblock";
	/* Check the hash... */
	if (VB2_SUCCESS != vb2_verify_keyblock_hash(keyblock, len, &wb)) {
		ERROR("%s keyblock component is invalid\n", print_name);
		FT_PARSEABLE_PRINT("invalid\n");
		return 1;
	} else {
		FT_PARSEABLE_PRINT("valid\n");
	}

	/*
	 * If we're being invoked while poking through a BIOS, we should
	 * be given the keys and data to verify as part of the state. If we
	 * have no state, then we're just looking at a standalone fw_preamble,
	 * so we'll have to get any keys or data from options.
	 */
	struct vb2_public_key root_key;
	if (state) {
		if (!sign_key &&
		    state->rootkey.is_valid &&
		    VB2_SUCCESS == vb2_unpack_key_buffer(&root_key,
							 state->rootkey.buf,
							 state->rootkey.len)) {
			/* BIOS should have a rootkey in the GBB */
			sign_key = &root_key;
		}

		/* Identify the firmware body for this VBLOCK */
		body_c = state->c == BIOS_FMAP_VBLOCK_A ? BIOS_FMAP_FW_MAIN_A
							: BIOS_FMAP_FW_MAIN_B;
		fw_body_area = &state->area[body_c];
	}

	/* If we have a key, check the signature too */
	if (sign_key && VB2_SUCCESS ==
	    vb2_verify_keyblock(keyblock, len, sign_key, &wb))
		good_sig = 1;
	else if (show_option.strict)
		retval = 1;

	show_keyblock(keyblock, print_name, !!sign_key, good_sig);

	struct vb2_public_key data_key;
	if (VB2_SUCCESS != vb2_unpack_key(&data_key, &keyblock->data_key)) {
		ERROR("Parsing data key in %s\n", print_name);
		FT_PARSEABLE_PRINT("data_key::invalid\n");
		return 1;
	}

	ft_print_header2 = "preamble";
	uint32_t more = keyblock->keyblock_size;
	struct vb2_fw_preamble *pre2 = (struct vb2_fw_preamble *)(buf + more);
	if (VB2_SUCCESS != vb2_verify_fw_preamble(pre2, len - more,
						  &data_key, &wb)) {
		ERROR("%s is invalid\n", print_name);
		FT_PARSEABLE_PRINT("invalid\n");
		FT_PARSEABLE_PRINT("signature::invalid\n");
		return 1;
	} else {
		FT_PARSEABLE_PRINT("valid\n");
		FT_PARSEABLE_PRINT("signature::valid\n");
	}

	uint32_t flags = pre2->flags;
	if (pre2->header_version_minor < 1)
		flags = 0;  /* Old 2.0 structure didn't have flags */

	FT_READABLE_PRINT("Firmware Preamble:\n");
	FT_PRINT("  Size:                  %d\n", "size::%d\n",
		 pre2->preamble_size);
	FT_PRINT("  Header version:        %d.%d\n",
		 "header_version::%d.%d\n",
		 pre2->header_version_major,
		 pre2->header_version_minor);
	FT_PRINT("  Firmware version:      %d\n", "firmware_version::%d\n",
		 pre2->firmware_version);

	struct vb2_packed_key *kernel_subkey = &pre2->kernel_subkey;
	FT_PRINT("  Kernel key algorithm:  %d %s\n",
		"kernel_subkey::algorithm::%d::%s\n",
		kernel_subkey->algorithm,
		vb2_get_crypto_algorithm_name(kernel_subkey->algorithm));
	if (kernel_subkey->algorithm >= VB2_ALG_COUNT)
		retval = 1;
	FT_PRINT("  Kernel key version:    %d\n",
		 "kernel_subkey::version::%d\n",
		 kernel_subkey->key_version);
	FT_PRINT("  Kernel key sha1sum:    %s\n",
		 "kernel_subkey::sha1_sum::%s\n",
		 packed_key_sha1_string(kernel_subkey));
	FT_READABLE_PRINT("  Firmware body size:    %d\n",
			  pre2->body_signature.data_size);
	FT_PRINT("  Preamble flags:        %d\n",
		 "flags::%d\n", flags);
	ft_print_header2 = NULL;

	FT_PARSEABLE_PRINT("body::size::%d\n", pre2->body_signature.data_size);


	if (flags & VB2_FIRMWARE_PREAMBLE_USE_RO_NORMAL) {
		FT_PRINT("Preamble requests USE_RO_NORMAL;"
			 " skipping body verification.\n",
			 "body::signature::ignored\n");
		goto done;
	}

	/* We'll need to get the firmware body from somewhere... */
	if (fw_body_area && fw_body_area->is_valid) {
		fv_data = fw_body_area->buf;
		fv_size = fw_body_area->len;
	}

	if (!fv_data) {
		FT_PRINT("No firmware body available to verify.\n",
			 "body::signature::ignored\n");
		if (show_option.strict)
			return 1;
		return 0;
	}

	if (pre2->body_signature.data_size) {
		if (vb2_verify_data(fv_data, fv_size, &pre2->body_signature,
				    &data_key, &wb) != VB2_SUCCESS) {
			ERROR("Verifying firmware body.\n");
			FT_PARSEABLE_PRINT("body::signature::invalid\n");
			return show_option.strict ? 1 : 0;
		}
	} else if (state) { /* Only works if `fname` is a BIOS image */
		if (fw_show_metadata_hash(fname, body_c, pre2))
			return show_option.strict ? 1 : 0;
	} else {
		WARN("Metadata hash verification not supported.\n");
		FT_PARSEABLE_PRINT("body::metadata_hash::ignored\n");
		FT_PARSEABLE_PRINT("body::signature::ignored\n");
		return show_option.strict ? 1 : 0;
	}

	FT_PRINT("Body verification succeeded.\n",
		 "body::signature::valid\n");

done:
	/* Can't trust the BIOS unless everything is signed. */
	if (good_sig) {
		if (state)
			state->area[state->c].is_valid = 1;
		FT_PARSEABLE_PRINT("verified\n");
	}

	return retval;
}

int ft_show_fw_preamble(const char *fname)
{
	int rv = 0;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;
	ft_print_header = "fw_pre";
	rv = show_fw_preamble_buf(fname, buf, len, NULL);

	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return rv;
}

int ft_show_kernel_preamble(const char *fname)
{
	struct vb2_keyblock *keyblock;
	struct vb2_public_key *sign_key = show_option.k;
	int retval = 0;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;

	keyblock = (struct vb2_keyblock *)buf;
	ft_print_header = "kernel";
	ft_print_header2 = "keyblock";
	/* Check the hash... */
	if (VB2_SUCCESS != vb2_verify_keyblock_hash(keyblock, len, &wb)) {
		ERROR("%s keyblock component is invalid\n", fname);
		FT_PARSEABLE_PRINT("invalid\n");
		retval = 1;
		goto done;
	} else {
		FT_PARSEABLE_PRINT("valid\n");
	}

	/* If we have a key, check the signature too */
	int good_sig = 0;
	if (sign_key && VB2_SUCCESS ==
	    vb2_verify_keyblock(keyblock, len, sign_key, &wb))
		good_sig = 1;
	else if (show_option.strict)
		retval = 1;

	FT_READABLE_PRINT("Kernel partition:        %s\n", fname);
	show_keyblock(keyblock, NULL, !!sign_key, good_sig);

	struct vb2_public_key data_key;
	if (VB2_SUCCESS != vb2_unpack_key(&data_key, &keyblock->data_key)) {
		ERROR("Parsing data key in %s\n", fname);
		retval = 1;
		goto done;
	}

	ft_print_header2 = NULL;
	uint32_t more = keyblock->keyblock_size;
	struct vb2_kernel_preamble *pre2 =
		(struct vb2_kernel_preamble *)(buf + more);

	if (VB2_SUCCESS != vb2_verify_kernel_preamble(pre2, len - more,
						      &data_key, &wb)) {
		ERROR("%s is invalid\n", fname);
		FT_PARSEABLE_PRINT("preamble::invalid\n");
		FT_PARSEABLE_PRINT("preamble::signature::invalid\n");
		retval = 1;
		goto done;
	}

	more += pre2->preamble_size;
	FT_PARSEABLE_PRINT("preamble::valid\n");
	FT_PARSEABLE_PRINT("preamble::signature::valid\n");
	FT_READABLE_PRINT("Kernel Preamble:\n");
	FT_PRINT("  Size:                  %#x\n",
		 "preamble::size::%d\n", pre2->preamble_size);
	FT_PRINT("  Header version:        %d.%d\n",
		 "preamble::header_version::%d.%d\n",
		 pre2->header_version_major,
		 pre2->header_version_minor);
	FT_PRINT("  Kernel version:        %u\n",
		 "preamble::kernel_version::%u\n",
		 pre2->kernel_version);
	FT_PRINT("  Flags:                 %#x\n",
		 "preamble::flags::%d\n", vb2_kernel_get_flags(pre2));

	FT_PRINT("  Body load address:     0x%" PRIx64 "\n",
		 "body::address::%" PRIu64 "\n",
		 pre2->body_load_address);
	FT_PRINT("  Body size:             %#x\n",
		 "body::size::%d\n",
		 pre2->body_signature.data_size);
	FT_PRINT("  Bootloader address:    0x%" PRIx64 "\n",
		 "bootloader::address::%" PRIu64 "\n",
		 pre2->bootloader_address);
	FT_PRINT("  Bootloader size:       %#x\n",
		 "bootloader::size::%d\n",
		 pre2->bootloader_size);

	uint64_t vmlinuz_header_address = 0;
	uint32_t vmlinuz_header_size = 0;
	vb2_kernel_get_vmlinuz_header(pre2,
				      &vmlinuz_header_address,
				      &vmlinuz_header_size);
	if (vmlinuz_header_size) {
		FT_PRINT("  Vmlinuz_header address:    0x%" PRIx64 "\n",
			 "vmlinuz_header::address::%" PRIu64 "\n",
			 vmlinuz_header_address);
		FT_PRINT("  Vmlinuz header size:       %#x\n",
			 "vmlinuz_header::size::%d\n",
			 vmlinuz_header_size);
	}

	/* Verify kernel body */
	uint8_t *kernel_blob;
	uint64_t kernel_size;
	if (show_option.fv) {
		/* It's in a separate file, which we've already read in */
		kernel_blob = show_option.fv;
		kernel_size = show_option.fv_size;
	} else {
		/* It should be at an offset within the input file. */
		kernel_blob = buf + more;
		kernel_size = len - more;
	}

	if (!kernel_size) {
		FT_PRINT("No kernel blob available to verify.\n",
			 "body::signature::ignored\n");
		if (show_option.strict)
			retval = 1;
		goto done;
	}

	if (VB2_SUCCESS !=
	    vb2_verify_data(kernel_blob, kernel_size, &pre2->body_signature,
			    &data_key, &wb)) {
		ERROR("Verifying kernel body.\n");
		FT_PARSEABLE_PRINT("body::signature::invalid\n");
		if (show_option.strict)
			retval = 1;
		goto done;
	}

	FT_PRINT("Body verification succeeded.\n",
		 "body::signature::valid\n");
	if (good_sig)
		FT_PARSEABLE_PRINT("verified\n");

	FT_READABLE_PRINT("Config:\n%s\n",
			  kernel_blob + kernel_cmd_line_offset(pre2));

done:
	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return retval;
}

enum no_short_opts {
	OPT_TYPE = 1000,
	OPT_PUBKEY,
	OPT_HELP,
};

static const char usage[] = "\n"
	"Usage:  " MYNAME " %s [OPTIONS] FILE [...]\n"
	"\n"
	"Where FILE could be\n"
	"\n"
	"  a boot descriptor block (BDB)\n"
	"  a keyblock (.keyblock)\n"
	"  a firmware preamble signature (VBLOCK_A/B)\n"
	"  a firmware image (image.bin)\n"
	"  a kernel partition (/dev/sda2, /dev/mmcblk0p2)\n"
	"  keys in various formats (.vbpubk, .vbprivk, .pem)\n"
	"  several other file types related to verified boot\n"
	"\n"
	"Options:\n"
	"  -t                               Just show the type of each file\n"
	"  --type           TYPE            Override the detected file type\n"
	"                                     Use \"--type help\" for a list\n"
	"  -P|--parseable                   Machine friendly output format\n"
	"Type-specific options:\n"
	"  -k|--publickey   FILE.vbpubk     Public key in vb1 format\n"
	"  --pubkey         FILE.vpubk2     Public key in vb2 format\n"
	"  -f|--fv          FILE            Verify this payload (FW_MAIN_A/B)\n"
	"  --strict                         "
	"Fail unless all signatures are valid\n"
	"\n";

static void print_help(int argc, char *argv[])
{
	if (!strcmp(argv[0], "verify"))
		printf("\nUsage:  " MYNAME " %s [OPTIONS] FILE [...]\n\n"
		       "This is just an alias for\n\n"
		       "  " MYNAME " show --strict\n\n",
		       argv[0]);

	printf(usage, "show");
}

static const struct option long_opts[] = {
	/* name    hasarg *flag val */
	{"publickey",   1, 0, 'k'},
	{"fv",          1, 0, 'f'},
	{"type",        1, NULL, OPT_TYPE},
	{"strict",      0, &show_option.strict, 1},
	{"pubkey",      1, NULL, OPT_PUBKEY},
	{"parseable",   0, NULL, 'P'},
	{"help",        0, NULL, OPT_HELP},
	{NULL, 0, NULL, 0},
};
static const char *short_opts = ":f:k:Pt";


static int show_type(char *filename)
{
	enum futil_file_err err;
	enum futil_file_type type;
	err = futil_file_type(filename, &type);
	switch (err) {
	case FILE_ERR_NONE:
		printf("%s:\t%s\n", filename, futil_file_type_name(type));
		/* Only our recognized types return success */
		return 0;
	case FILE_ERR_DIR:
		printf("%s:\t%s\n", filename, "directory");
		break;
	case FILE_ERR_CHR:
		printf("%s:\t%s\n", filename, "character special");
		break;
	case FILE_ERR_FIFO:
		printf("%s:\t%s\n", filename, "FIFO");
		break;
	case FILE_ERR_SOCK:
		printf("%s:\t%s\n", filename, "socket");
		break;
	default:
		break;
	}
	/* Everything else is an error */
	return 1;
}

static int load_publickey(const char *fname, uint8_t **buf_ptr,
			  struct vb2_public_key *pubkey)
{
	uint32_t len = 0;
	if (vb2_read_file(fname, buf_ptr, &len) != VB2_SUCCESS) {
		ERROR("Reading publickey %s\n", fname);
		return 1;
	}

	struct vb2_keyblock *keyblock;
	uint8_t *buf = *buf_ptr;
	enum futil_file_type type = futil_file_type_buf(buf, len);
	switch (type) {
	case FILE_TYPE_FW_PREAMBLE:
		keyblock = (struct vb2_keyblock *)buf;
		if (vb2_check_keyblock(keyblock, len, &keyblock->keyblock_hash)
		    != VB2_SUCCESS) {
			ERROR("Checking publickey keyblock\n");
			return 1;
		}
		struct vb2_fw_preamble *pre =
			(struct vb2_fw_preamble *)(buf + keyblock->keyblock_size);
		if (vb2_unpack_key(pubkey, &pre->kernel_subkey) != VB2_SUCCESS) {
			ERROR("Unpacking publickey from preamble %s\n", fname);
			return 1;
		}
		break;
	case FILE_TYPE_PUBKEY:
		if (vb2_unpack_key_buffer(pubkey, buf, len) != VB2_SUCCESS) {
			ERROR("Unpacking publickey %s\n", fname);
			return 1;
		}
		break;
	default:
		ERROR("Unsupported file type '%s' for publickey %s\n",
		      futil_file_type_name(type), fname);
		return 1;
	}

	return 0;
}

static int do_show(int argc, char *argv[])
{
	uint8_t *pubkbuf = NULL;
	struct vb2_public_key pubk2;
	char *infile = 0;
	int i;
	int errorcnt = 0;
	int type_override = 0;
	enum futil_file_type type;

	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

	opterr = 0;		/* quiet, you */
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		switch (i) {
		case 'f':
			show_option.fv = ReadFile(optarg,
						  &show_option.fv_size);
			if (!show_option.fv) {
				ERROR("Reading %s: %s\n",
					optarg, strerror(errno));
				errorcnt++;
			}
			break;
		case 'k':
			if (load_publickey(optarg, &pubkbuf, &pubk2)) {
				ERROR("Loading publickey %s\n", optarg);
				errorcnt++;
				break;
			}
			show_option.k = &pubk2;
			break;
		case 't':
			show_option.t_flag = 1;
			break;
		case 'P':
			show_option.parseable = true;
			break;
		case OPT_TYPE:
			if (!futil_str_to_file_type(optarg,
						    &show_option.type)) {
				if (!strcasecmp("help", optarg))
					print_file_types_and_exit(errorcnt);
				ERROR("Invalid --type \"%s\"\n", optarg);
				errorcnt++;
			}
			type_override = 1;
			break;
		case OPT_PUBKEY:
			if (vb21_packed_key_read(&show_option.pkey, optarg)) {
				ERROR("Reading %s\n", optarg);
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

	if (errorcnt) {
		print_help(argc, argv);
		return 1;
	}

	if (argc - optind < 1) {
		ERROR("Missing input filename\n");
		print_help(argc, argv);
		return 1;
	}

	if (show_option.t_flag) {
		for (i = optind; i < argc; i++)
			errorcnt += show_type(argv[i]);
		goto done;
	}

	for (i = optind; i < argc; i++) {
		infile = argv[i];

		/* Allow the user to override the type */
		if (type_override)
			type = show_option.type;
		else
			futil_file_type(infile, &type);

		errorcnt += futil_file_type_show(type, infile);
	}

done:
	if (pubkbuf)
		free(pubkbuf);
	if (show_option.fv)
		free(show_option.fv);

	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(show, do_show, VBOOT_VERSION_ALL,
		      "Display the content of various binary components");

static int do_verify(int argc, char *argv[])
{
	show_option.strict = 1;
	return do_show(argc, argv);
}

DECLARE_FUTIL_COMMAND(verify, do_verify,
		      VBOOT_VERSION_ALL,
		      "Verify the signatures of various binary components. "
		      "This does not verify GSCVD contents.");
