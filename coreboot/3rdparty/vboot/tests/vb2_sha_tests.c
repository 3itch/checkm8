/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* FIPS 180-2 Tests for message digest functions. */

#include <stdio.h>

#include "2return_codes.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "common/tests.h"
#include "sha_test_vectors.h"

static void sha1_tests(void)
{
	struct vb2_hash hash;
	uint8_t *test_inputs[3];
	int i;

	test_inputs[0] = (uint8_t *) oneblock_msg;
	test_inputs[1] = (uint8_t *) multiblock_msg1;
	test_inputs[2] = (uint8_t *) long_msg;

	for (i = 0; i < 3; i++) {
		TEST_SUCC(vb2_hash_calculate(false, test_inputs[i],
					     strlen((const char *)test_inputs[i]),
					     VB2_HASH_SHA1, &hash),
			  "vb2_hash_calculate() SHA-1");
		TEST_EQ(memcmp(hash.sha1, sha1_results[i],
			sizeof(sha1_results[i])), 0, "  SHA-1 digest");
	}

	struct vb2_digest_context dc;
	vb2_digest_init(&dc, false, VB2_HASH_SHA1, 0);
	vb2_digest_extend(&dc, test_inputs[0],
			  strlen((const char *)test_inputs[0]));
	TEST_EQ(vb2_digest_finalize(&dc, hash.sha1, sizeof(hash.sha1) - 1),
		VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE,
		"vb2_digest_finalize() SHA-1 too small");

	TEST_EQ(vb2_hash_block_size(VB2_HASH_SHA1), VB2_SHA1_BLOCK_SIZE,
		"vb2_hash_block_size(VB2_HASH_SHA1)");
}

static void sha256_tests(void)
{
	struct vb2_hash hash;
	uint8_t *test_inputs[3];
	struct vb2_sha256_context ctx;
	const uint8_t expect_multiple[VB2_SHA256_DIGEST_SIZE] = {
			0x07, 0x08, 0xb4, 0xca, 0x46, 0x4c, 0x40, 0x39,
			0x07, 0x06, 0x88, 0x80, 0x30, 0x55, 0x5d, 0x86,
			0x0e, 0x4a, 0x0d, 0x2b, 0xc6, 0xc4, 0x87, 0x39,
			0x2c, 0x16, 0x55, 0xb0, 0x82, 0x13, 0x16, 0x29 };
	const uint8_t extend_from[VB2_SHA256_DIGEST_SIZE] = { 0x00, };
	const uint8_t extend_by[VB2_SHA256_BLOCK_SIZE] = { 0x00, };
	const uint8_t expected_extend[VB2_SHA256_DIGEST_SIZE] = {
		0x7c, 0xa5, 0x16, 0x14, 0x42, 0x5c, 0x3b, 0xa8, 0xce, 0x54,
		0xdd, 0x2f, 0xc2, 0x02, 0x0a, 0xe7, 0xb6, 0xe5, 0x74, 0xd1,
		0x98, 0x13, 0x6d, 0x0f, 0xae, 0x7e, 0x26, 0xcc, 0xbf, 0x0b,
		0xe7, 0xa6 };
	int i;

	test_inputs[0] = (uint8_t *) oneblock_msg;
	test_inputs[1] = (uint8_t *) multiblock_msg1;
	test_inputs[2] = (uint8_t *) long_msg;

	for (i = 0; i < 3; i++) {
		TEST_SUCC(vb2_hash_calculate(false, test_inputs[i],
					    strlen((const char *)test_inputs[i]),
					    VB2_HASH_SHA256, &hash),
			  "vb2_hash_calculate() SHA-256");
		TEST_EQ(memcmp(hash.sha256, sha256_results[i],
			sizeof(sha256_results[i])), 0, "  SHA-256 digest");
	}

	struct vb2_digest_context dc;
	vb2_digest_init(&dc, false, VB2_HASH_SHA256, 0);
	vb2_digest_extend(&dc, test_inputs[0], strlen((const char *)test_inputs[0]));
	TEST_EQ(vb2_digest_finalize(&dc, hash.sha256, sizeof(hash.sha256) - 1),
		VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE,
		"vb2_digest_finalize() SHA-256 too small");

	/* Test multiple small extends */
	vb2_sha256_init(&ctx, VB2_HASH_SHA256);
	vb2_sha256_update(&ctx, (uint8_t *)"test1", 5);
	vb2_sha256_update(&ctx, (uint8_t *)"test2", 5);
	vb2_sha256_update(&ctx, (uint8_t *)"test3", 5);
	vb2_sha256_finalize(&ctx, hash.sha256, VB2_HASH_SHA256);
	TEST_EQ(memcmp(hash.sha256, expect_multiple, sizeof(hash.sha256)), 0,
		"SHA-256 multiple extends");

	TEST_EQ(vb2_hash_block_size(VB2_HASH_SHA256), VB2_SHA256_BLOCK_SIZE,
		"vb2_hash_block_size(VB2_HASH_SHA256)");

	/* Test SHA256 hash extend */
	vb2_sha256_extend(extend_from, extend_by, hash.sha256);
	TEST_SUCC(memcmp(hash.sha256, expected_extend, sizeof(hash.sha256)), NULL);
}

static void sha512_tests(void)
{
	struct vb2_hash hash;
	uint8_t *test_inputs[3];
	int i;

	test_inputs[0] = (uint8_t *) oneblock_msg;
	test_inputs[1] = (uint8_t *) multiblock_msg2;
	test_inputs[2] = (uint8_t *) long_msg;

	for (i = 0; i < 3; i++) {
		TEST_SUCC(vb2_hash_calculate(false, test_inputs[i],
					     strlen((const char *)test_inputs[i]),
					     VB2_HASH_SHA512, &hash),
			  "vb2_hash_calculate() SHA512");
		TEST_EQ(memcmp(hash.sha512, sha512_results[i],
			sizeof(sha512_results[i])), 0, "  SHA-512 digest");
	}

	struct vb2_digest_context dc;
	vb2_digest_init(&dc, false, VB2_HASH_SHA512, 0);
	vb2_digest_extend(&dc, test_inputs[0], strlen((const char *)test_inputs[0]));
	TEST_EQ(vb2_digest_finalize(&dc, hash.sha512, sizeof(hash.sha512) - 1),
		VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE,
		"vb2_digest_finalize() SHA-512 too small");

	TEST_EQ(vb2_hash_block_size(VB2_HASH_SHA512), VB2_SHA512_BLOCK_SIZE,
		"vb2_hash_block_size(VB2_HASH_SHA512)");
}

static void misc_tests(void)
{
	uint8_t digest[VB2_SHA512_DIGEST_SIZE];
	struct vb2_digest_context dc;

	/* Crypto algorithm to hash algorithm mapping */
	TEST_EQ(vb2_crypto_to_hash(VB2_ALG_RSA1024_SHA1), VB2_HASH_SHA1,
		"Crypto map to SHA1");
	TEST_EQ(vb2_crypto_to_hash(VB2_ALG_RSA2048_SHA256), VB2_HASH_SHA256,
		"Crypto map to SHA256");
	TEST_EQ(vb2_crypto_to_hash(VB2_ALG_RSA4096_SHA256), VB2_HASH_SHA256,
		"Crypto map to SHA256 2");
	TEST_EQ(vb2_crypto_to_hash(VB2_ALG_RSA8192_SHA512), VB2_HASH_SHA512,
		"Crypto map to SHA512");
	TEST_EQ(vb2_crypto_to_hash(VB2_ALG_COUNT), VB2_HASH_INVALID,
		"Crypto map to invalid");

	TEST_EQ(vb2_digest_size(VB2_HASH_INVALID), 0,
		"digest size invalid alg");

	TEST_EQ(vb2_hash_block_size(VB2_HASH_INVALID), 0,
		"vb2_hash_block_size(VB2_HASH_INVALID)");

	/* Test bad algorithm inside extend and finalize */
	vb2_digest_init(&dc, false, VB2_HASH_SHA256, 0);
	dc.hash_alg = VB2_HASH_INVALID;
	TEST_EQ(vb2_digest_extend(&dc, digest, sizeof(digest)),
		VB2_ERROR_SHA_EXTEND_ALGORITHM,
		"vb2_digest_extend() invalid alg");
	TEST_EQ(vb2_digest_finalize(&dc, digest, sizeof(digest)),
		VB2_ERROR_SHA_FINALIZE_ALGORITHM,
		"vb2_digest_finalize() invalid alg");
}

static void known_value_tests(void)
{
	const char sentinel[] = "keepme";
	union {
		struct vb2_hash hash;
		char overflow[sizeof(struct vb2_hash) + 8];
	} test;


#define TEST_KNOWN_VALUE(algo, str, value) \
	TEST_EQ(vb2_digest_size(algo), sizeof(value) - 1, \
		"Known hash size " #algo ": " #str); \
	{								\
		char *sent_base = test.overflow + \
			offsetof(struct vb2_hash, raw) + sizeof(value) - 1; \
		strcpy(sent_base, sentinel);				\
		TEST_SUCC(vb2_hash_calculate(false, str, sizeof(str) - 1, \
					     algo, &test.hash),		\
			  "Calculate known hash " #algo ": " #str);	\
		TEST_EQ(memcmp(test.hash.raw, value, sizeof(value) - 1), 0, \
			"Known hash " #algo ": " #str);			\
		TEST_EQ(strcmp(sent_base, sentinel), 0,			\
			"Overflow known hash " #algo ": " #str);	\
	}

	TEST_KNOWN_VALUE(VB2_HASH_SHA1, "",
		"\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18"
		"\x90\xaf\xd8\x07\x09");
	TEST_KNOWN_VALUE(VB2_HASH_SHA256, "",
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9"
		"\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52"
		"\xb8\x55");
	TEST_KNOWN_VALUE(VB2_HASH_SHA512, "",
		"\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80"
		"\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c"
		"\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87"
		"\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a"
		"\xf9\x27\xda\x3e");
	TEST_KNOWN_VALUE(VB2_HASH_SHA224, "",
		"\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9\x47\x61\x02\xbb\x28\x82\x34"
		"\xc4\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a\xc5\xb3\xe4\x2f");
	TEST_KNOWN_VALUE(VB2_HASH_SHA384, "",
		"\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3"
		"\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6"
		"\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48"
		"\x98\xb9\x5b");

	const char long_test_string[] = "abcdefghbcdefghicdefghijdefghijkefgh"
		"ijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
		"mnopqrstnopqrstu";
	TEST_KNOWN_VALUE(VB2_HASH_SHA1, long_test_string,
		"\xa4\x9b\x24\x46\xa0\x2c\x64\x5b\xf4\x19\xf9\x95\xb6\x70\x91"
		"\x25\x3a\x04\xa2\x59");
	TEST_KNOWN_VALUE(VB2_HASH_SHA256, long_test_string,
		"\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92"
		"\x37\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe"
		"\xe9\xd1");
	TEST_KNOWN_VALUE(VB2_HASH_SHA512, long_test_string,
		"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14"
		"\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88"
		"\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4"
		"\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b"
		"\x87\x4b\xe9\x09");
	TEST_KNOWN_VALUE(VB2_HASH_SHA224, long_test_string,
		"\xc9\x7c\xa9\xa5\x59\x85\x0c\xe9\x7a\x04\xa9\x6d\xef\x6d\x99"
		"\xa9\xe0\xe0\xe2\xab\x14\xe6\xb8\xdf\x26\x5f\xc0\xb3");
	TEST_KNOWN_VALUE(VB2_HASH_SHA384, long_test_string,
		"\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b"
		"\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0"
		"\xf7\x12\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91"
		"\x74\x60\x39");

	/* vim helper to escape hex: <Shift+V>:s/\([a-f0-9]\{2\}\)/\\x\1/g */
#undef TEST_KNOWN_VALUE
}

int main(int argc, char *argv[])
{
	/* Initialize long_msg with 'a' x 1,000,000 */
	long_msg = (char *) malloc(1000001);
	memset(long_msg, 'a', 1000000);
	long_msg[1000000]=0;

	sha1_tests();
	sha256_tests();
	sha512_tests();
	misc_tests();
	known_value_tests();

	free(long_msg);

	return gTestSuccess ? 0 : 255;
}
