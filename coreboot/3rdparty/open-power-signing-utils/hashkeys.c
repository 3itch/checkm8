/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#ifndef _AIX
#include <getopt.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include "container.c"
#include "container.h"

#define BINARY_OUT 0
#define ASCII_OUT 1

char *progname;

bool verbose, debug;
int wrap = 100;

void usage(int status);

void getPublicKeyRaw(ecc_key_t *pubkeyraw, char *inFile)
{
	EVP_PKEY* pkey;
	unsigned char pubkeyData[1 + 2 * EC_COORDBYTES];

	FILE *fp = fopen(inFile, "r");
	if (!fp)
		die(EX_NOINPUT, "Cannot open key file: %s: %s", inFile, strerror(errno));

	if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) {
		debug_msg("File \"%s\" is a PEM private key", inFile);
		fclose(fp);
	} else {
		fclose(fp);
		fp = fopen(inFile, "r");
		if ((pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL))) {
			debug_msg("File \"%s\" is a PEM public key", inFile);
		}
		fclose(fp);
	}

	if (pkey) {
		EC_KEY *key;
		const EC_GROUP *ecgrp;
		const EC_POINT *ecpoint;
		BIGNUM *pubkeyBN;

		key = EVP_PKEY_get1_EC_KEY(pkey);
		if (!key)
			die(EX_SOFTWARE, "%s", "Cannot EVP_PKEY_get1_EC_KEY");

		ecgrp = EC_KEY_get0_group(key);
		if (!ecgrp)
			die(EX_SOFTWARE, "%s", "Cannot EC_KEY_get0_group");

		ecpoint = EC_KEY_get0_public_key(key);
		if (!ecpoint)
			die(EX_SOFTWARE, "%s", "Cannot EC_KEY_get0_public_key");

		pubkeyBN = EC_POINT_point2bn(ecgrp, ecpoint, POINT_CONVERSION_UNCOMPRESSED,
				NULL, NULL);
		BN_bn2bin(pubkeyBN, pubkeyData);

		BN_free(pubkeyBN);
		EC_KEY_free(key);
		EVP_PKEY_free(pkey);
	}
	else {
		/* The file is not a public or private key in PEM format. So we check if
		 * it is a p521 pubkey in RAW format, in which case it will be 133 bytes
		 * with a leading byte of 0x04, indicating an uncompressed key. */
		int fdin, r;
		struct stat s;
		void *infile = NULL;

		fdin = open(inFile, O_RDONLY);
		if (fdin <= 0)
			die(EX_NOINPUT, "Cannot open key file: %s: %s", inFile, strerror(errno));

		r = fstat(fdin, &s);
		if (r != 0)
			die(EX_NOINPUT, "Cannot stat key file: %s", inFile);

		if (s.st_size == 1 + 2 * EC_COORDBYTES) {
			infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
			if (infile == MAP_FAILED)
				die(EX_OSERR, "Cannot mmap file at fd: %d, size: %lu (%s)",
						fdin, s.st_size, strerror(errno));
		}
		close(fdin);

		if (!infile || (*(unsigned char*) infile != 0x04)) {
			die(EX_DATAERR,
					"File \"%s\" is not in expected format (private or public key in PEM, or public key RAW)",
					inFile);
		} else
			debug_msg("File \"%s\" is a RAW public key", inFile);

		memcpy(pubkeyData, infile, sizeof(ecc_key_t) + 1);
	}

	// Remove the leading byte
	memcpy(*pubkeyraw, &pubkeyData[1], sizeof(ecc_key_t));

	return;
}

__attribute__((__noreturn__)) void usage (int status)
{
	if (status != 0) {
		fprintf(stderr, "Try '%s --help' for more information.\n", progname);
	}
	else {
		printf("Usage: %s [options]\n", progname);
		printf(
			"\n"
			"Options:\n"
			" -h, --help              display this message and exit\n"
			" -v, --verbose           show verbose output\n"
			" -d, --debug             show additional debug output\n"
			" -w, --wrap              column to wrap long output in verbose mode\n"
			" -a, --hw_key_a          file containing HW key A key in PEM or RAW format\n"
			" -b, --hw_key_b          file containing HW key B key in PEM or RAW format\n"
			" -c, --hw_key_c          file containing HW key C key in PEM or RAW format\n"
			" -o, --outfile           file to write HW keys hash (default is stdout)\n"
			"     --ascii             output in hexascii (default)\n"
			"     --binary            output in binary\n"
			"     --pretty            add 0x the start of the string, for --ascii\n"
			"\n");
	};
	exit(status);
}

#ifndef _AIX
static struct option const opts[] = {
	{ "help",             no_argument,       0,  'h' },
	{ "verbose",          no_argument,       0,  'v' },
	{ "debug",            no_argument,       0,  'd' },
	{ "wrap",             required_argument, 0,  'w' },
	{ "hw_key_a",         required_argument, 0,  'a' },
	{ "hw_key_b",         required_argument, 0,  'b' },
	{ "hw_key_c",         required_argument, 0,  'c' },
	{ "outfile",          required_argument, 0,  'o' },
	{ "ascii",            no_argument,       0,  '0' },
	{ "binary",           no_argument,       0,  '1' },
	{ "pretty",           no_argument,       0,  '2' },
	{ NULL, 0, NULL, 0 }
};
#endif

static struct {
	char *hw_keyfn_a;
	char *hw_keyfn_b;
	char *hw_keyfn_c;
	char *outfile;
	bool pretty;
} params;


int main(int argc, char* argv[])
{
	FILE *fp;
	int outform = ASCII_OUT;
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	ROM_container_raw *c = (ROM_container_raw*) container;

	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;
	ecc_key_t pubkeyraw;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	memset(container, 0, SECURE_BOOT_HEADERS_SIZE);

#ifdef _AIX
	for (int i = 1; i < argc; i++) {
		if (!strcmp(*(argv + i), "--help")) {
			*(argv + i) = "-h";
		} else if (!strcmp(*(argv + i), "--verbose")) {
			*(argv + i) = "-v";
		} else if (!strcmp(*(argv + i), "--debug")) {
			*(argv + i) = "-d";
		} else if (!strcmp(*(argv + i), "--wrap")) {
			*(argv + i) = "-w";
		} else if (!strcmp(*(argv + i), "--hw_key_a")) {
			*(argv + i) = "-a";
		} else if (!strcmp(*(argv + i), "--hw_key_b")) {
			*(argv + i) = "-b";
		} else if (!strcmp(*(argv + i), "--hw_key_c")) {
			*(argv + i) = "-c";
		} else if (!strcmp(*(argv + i), "--outfile")) {
			*(argv + i) = "-o";
		} else if (!strcmp(*(argv + i), "--ascii")) {
			*(argv + i) = "-0";
		} else if (!strcmp(*(argv + i), "--binary")) {
			*(argv + i) = "-1";
		} else if (!strcmp(*(argv + i), "--pretty")) {
			*(argv + i) = "-2";
		} else if (!strncmp(*(argv + i), "--", 2)) {
			fprintf(stderr, "%s: unrecognized option \'%s\'\n", progname,
					*(argv + i));
			usage(EX_OK);
		}
	}
#endif

	while (1) {
		int opt;
#ifdef _AIX
		opt = getopt(argc, argv, "?hvdw:a:b:c:o:012");
#else
		opt = getopt_long(argc, argv, "?hvdw:a:b:c:o:012", opts, NULL);
#endif

		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			usage(EX_OK);
			break;
		case '?':
			usage(EX_USAGE);
			break;
		case 'v':
			verbose = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'w':
			wrap = atoi(optarg);
			wrap = (wrap < 2) ? INT_MAX : wrap;
			break;
		case 'a':
			params.hw_keyfn_a = optarg;
			break;
		case 'b':
			params.hw_keyfn_b = optarg;
			break;
		case 'c':
			params.hw_keyfn_c = optarg;
			break;
		case 'o':
			params.outfile = optarg;
			break;
		case '0':
			outform = ASCII_OUT;
			break;
		case '1':
			outform = BINARY_OUT;
			break;
		case '2':
			params.pretty = true;
			break;
		default:
			usage(EX_USAGE);
		}
	}

	if (params.outfile) {
		fp = fopen(params.outfile, "w");
		if (!fp)
			die(EX_CANTCREAT, "Cannot create output file: %s: %s",
					params.outfile, strerror(errno));
	} else {
		fp = stdout;
	}

	memset(c->hw_pkey_a, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_b, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_c, 0, sizeof(ecc_key_t));

	if (params.hw_keyfn_a) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_a);
		verbose_print((char *) "pubkey A = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(c->hw_pkey_a, pubkeyraw, sizeof(ecc_key_t));
	}
	if (params.hw_keyfn_b) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_b);
		verbose_print((char *) "pubkey B = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(c->hw_pkey_b, pubkeyraw, sizeof(ecc_key_t));
	}
	if (params.hw_keyfn_c) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_c);
		verbose_print((char *) "pubkey C = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(c->hw_pkey_c, pubkeyraw, sizeof(ecc_key_t));
	}

	p = SHA512(c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	verbose_print((char *) "HW keys hash = ", md, sizeof(md));

	if (outform == BINARY_OUT) {

		fwrite(md, SHA512_DIGEST_LENGTH, 1, fp);

	} else if (outform == ASCII_OUT) {

		if (params.pretty)
			fprintf(fp, "%s", "0x");

		for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
			fprintf(fp, "%02x", md[i]);

		fprintf(fp, "\n");
	}

	fclose(fp);
	free(container);
	return 0;
}
