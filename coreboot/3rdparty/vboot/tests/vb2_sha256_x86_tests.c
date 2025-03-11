/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* FIPS 180-2 Tests for message digest functions. */

#include <cpuid.h>
#include <stdio.h>

#include "2api.h"
#include "2sha.h"
#include "common/tests.h"
#include "sha_test_vectors.h"

static vb2_error_t vb2_digest_buffer(const uint8_t *buf, uint32_t size,
				     enum vb2_hash_algorithm hash_alg,
				     uint8_t *digest, uint32_t digest_size)
{
	VB2_TRY(vb2ex_hwcrypto_digest_init(hash_alg, size));
	VB2_TRY(vb2ex_hwcrypto_digest_extend(buf, size));

	return vb2ex_hwcrypto_digest_finalize(digest, digest_size);

}

static void sha256_tests(void)
{
	uint8_t digest[VB2_SHA256_DIGEST_SIZE];
	uint8_t *test_inputs[3];
	const uint8_t expect_multiple[VB2_SHA256_DIGEST_SIZE] = {
			0x07, 0x08, 0xb4, 0xca, 0x46, 0x4c, 0x40, 0x39,
			0x07, 0x06, 0x88, 0x80, 0x30, 0x55, 0x5d, 0x86,
			0x0e, 0x4a, 0x0d, 0x2b, 0xc6, 0xc4, 0x87, 0x39,
			0x2c, 0x16, 0x55, 0xb0, 0x82, 0x13, 0x16, 0x29 };
	int i;

	test_inputs[0] = (uint8_t *) oneblock_msg;
	test_inputs[1] = (uint8_t *) multiblock_msg1;
	test_inputs[2] = (uint8_t *) long_msg;

	for (i = 0; i < 3; i++) {
		TEST_SUCC(vb2_digest_buffer(test_inputs[i],
					    strlen((char *)test_inputs[i]),
					    VB2_HASH_SHA256,
					    digest, sizeof(digest)),
			  "vb2_digest_buffer() SHA256");
		TEST_EQ(memcmp(digest, sha256_results[i], sizeof(digest)),
			0, "SHA-256 digest");
	}

	TEST_EQ(vb2_digest_buffer(test_inputs[0],
				  strlen((char *)test_inputs[0]),
				  VB2_HASH_SHA256, digest, sizeof(digest) - 1),
		VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE,
		"vb2_digest_buffer() too small");

	/* Test multiple small extends */
	vb2ex_hwcrypto_digest_init(VB2_HASH_SHA256, 15);
	vb2ex_hwcrypto_digest_extend((uint8_t *)"test1", 5);
	vb2ex_hwcrypto_digest_extend((uint8_t *)"test2", 5);
	vb2ex_hwcrypto_digest_extend((uint8_t *)"test3", 5);
	vb2ex_hwcrypto_digest_finalize(digest, VB2_SHA256_DIGEST_SIZE);
	TEST_EQ(memcmp(digest, expect_multiple, sizeof(digest)), 0,
		"SHA-256 multiple extends");

	TEST_EQ(vb2_hash_block_size(VB2_HASH_SHA256), VB2_SHA256_BLOCK_SIZE,
		"vb2_hash_block_size(VB2_HASH_SHA256)");

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
		"Known hash size " #algo ": " #str);			\
	{								\
		char *sent_base = test.overflow +			\
			offsetof(struct vb2_hash, raw) + sizeof(value) - 1; \
		strcpy(sent_base, sentinel);				\
		strcpy(sent_base, sentinel);				\
		TEST_SUCC(vb2_digest_buffer((const uint8_t *)str,	\
					    sizeof(str) - 1,		\
					    algo, test.hash.raw,	\
					    vb2_digest_size(algo)),	\
			  "Calculate known hash " #algo ": " #str);	\
		TEST_EQ(memcmp(test.hash.raw, value, sizeof(value) - 1), 0, \
			"Known hash " #algo ": " #str);			\
		TEST_EQ(strcmp(sent_base, sentinel), 0,			\
			"Overflow known hash " #algo ": " #str);	\
	}

	TEST_KNOWN_VALUE(VB2_HASH_SHA256, "",
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9"
		"\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52"
		"\xb8\x55");

	const char long_test_string[] = "abcdefghbcdefghicdefghijdefghijkefgh"
		"ijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
		"mnopqrstnopqrstu";
	TEST_KNOWN_VALUE(VB2_HASH_SHA256, long_test_string,
		"\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92"
		"\x37\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe"
		"\xe9\xd1");

	/* vim helper to escape hex: <Shift+V>:s/\([a-f0-9]\{2\}\)/\\x\1/g */
#undef TEST_KNOWN_VALUE
}

int main(int argc, char *argv[])
{
	uint32_t a, b = 0, c, d;
	/* EAX = 07H, sub-leaf 0 */
	__get_cpuid_count(7, 0, &a, &b, &c, &d);
	if ((b & bit_SHA) == 0) {
		fprintf(stderr, "SHA-NI not supported.\n");
		return 254;
	}

	/* Initialize long_msg with 'a' x 1,000,000 */
	long_msg = (char *) malloc(1000001);
	memset(long_msg, 'a', 1000000);
	long_msg[1000000]=0;

	sha256_tests();
	known_value_tests();

	free(long_msg);

	return gTestSuccess ? 0 : 255;
}
