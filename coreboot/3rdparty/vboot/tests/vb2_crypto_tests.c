/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for generic crypto algorithm helper stuff.
 */

#include <stdio.h>

#include "2crypto.h"
#include "2return_codes.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "common/tests.h"
#include "vboot_host.h"

static void hash_algorithm_name_tests(void)
{
	enum vb2_hash_algorithm alg;
	char test_name[256];

	for (alg = 0; alg < VB2_HASH_ALG_COUNT; alg++) {
		sprintf(test_name, "%s (alg=%d)",
			vb2_get_hash_algorithm_name(alg), alg);
		TEST_STR_NEQ(vb2_get_hash_algorithm_name(alg),
			     VB2_INVALID_ALG_NAME, test_name);
	}

	TEST_STR_EQ(vb2_get_hash_algorithm_name(VB2_HASH_ALG_COUNT),
		    VB2_INVALID_ALG_NAME, "hash alg name out of range");
}

static void sig_algorithm_name_tests(void)
{
	enum vb2_signature_algorithm alg;
	char test_name[256];

	for (alg = 1; alg < VB2_SIG_ALG_COUNT; alg++) {
		sprintf(test_name, "%s (alg=%d)",
			vb2_get_sig_algorithm_name(alg), alg);
		TEST_STR_NEQ(vb2_get_sig_algorithm_name(alg),
			     VB2_INVALID_ALG_NAME, test_name);
	}

	TEST_STR_EQ(vb2_get_sig_algorithm_name(VB2_SIG_INVALID),
		    VB2_INVALID_ALG_NAME, "sig alg name invalid");
	TEST_STR_EQ(vb2_get_sig_algorithm_name(VB2_SIG_ALG_COUNT),
		    VB2_INVALID_ALG_NAME, "sig alg name out of range");
}

static void hash_algorithm_lookup_tests(void)
{
	enum vb2_hash_algorithm alg, out;
	char test_name[256];

	for (alg = 1; alg < VB2_HASH_ALG_COUNT; alg++) {
		sprintf(test_name, "%s (alg=%d)",
			vb2_get_hash_algorithm_name(alg), alg);
		TEST_EQ(vb2_lookup_hash_alg(vb2_get_hash_algorithm_name(alg),
			&out), 1, test_name);
		TEST_EQ(out, alg, "  algorithm correct");
	}

	TEST_EQ(vb2_lookup_hash_alg(VB2_INVALID_ALG_NAME, &out), 0,
		"invalid algorithm cannot be parsed");
	TEST_EQ(vb2_lookup_hash_alg("RSA1024", &out), 0,
		"cannot parse hash  as signature");
	TEST_EQ(vb2_lookup_hash_alg("shA512", &out), 1,
		"case insensitivity spot check");
	TEST_EQ(out, VB2_HASH_SHA512, "  algorithm correct");
}

static void sig_algorithm_lookup_tests(void)
{
	enum vb2_signature_algorithm alg, out;
	char test_name[256];

	for (alg = 1; alg < VB2_SIG_ALG_COUNT; alg++) {
		sprintf(test_name, "%s (alg=%d)",
			vb2_get_sig_algorithm_name(alg), alg);
		TEST_EQ(vb2_lookup_sig_alg(vb2_get_sig_algorithm_name(alg),
			&out), 1, test_name);
		TEST_EQ(out, alg, "  algorithm correct");
	}

	TEST_EQ(vb2_lookup_sig_alg(VB2_INVALID_ALG_NAME, &out), 0,
		"invalid algorithm cannot be parsed");
	TEST_EQ(vb2_lookup_sig_alg("SHA256", &out), 0,
		"cannot parse signature as hash");
	TEST_EQ(vb2_lookup_sig_alg("rSa2048", &out), 1,
		"case insensitivity spot check");
	TEST_EQ(out, VB2_SIG_RSA2048, "  algorithm correct");
}

int main(int argc, char *argv[])
{
	hash_algorithm_name_tests();
	sig_algorithm_name_tests();
	hash_algorithm_lookup_tests();
	sig_algorithm_lookup_tests();

	return gTestSuccess ? 0 : 255;
}
