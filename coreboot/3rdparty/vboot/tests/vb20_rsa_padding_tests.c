/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>

#include "2common.h"
#include "2rsa.h"
#include "2sysincludes.h"
#include "common/tests.h"
#include "file_keys.h"
#include "host_key.h"
#include "rsa_padding_test.h"

#if defined(ENABLE_HWCRYPTO_RSA_TESTS)
void vb2_modexp(const struct vb2_public_key *key, uint8_t *inout,
		void *workbuf, int exp) {
	TEST_TRUE(0, "vb2_modexp() unexpectedly executed");
}
#else
vb2_error_t hwcrypto_modexp_return_value = VB2_SUCCESS;
vb2_error_t vb2ex_hwcrypto_modexp(const struct vb2_public_key *key,
				  uint8_t *inout, void *workbuf,
				  size_t workbuf_size, int exp) {
	return hwcrypto_modexp_return_value;
}
#endif


/**
 * Test valid and invalid signatures.
 */
static void test_signatures(struct vb2_public_key *key)
{
	uint8_t workbuf[VB2_VERIFY_DIGEST_WORKBUF_BYTES]
		 __attribute__((aligned(VB2_WORKBUF_ALIGN)));
	uint8_t sig[RSA1024NUMBYTES];
	struct vb2_workbuf wb;
	int unexpected_success;
	int i;

	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

#if defined(ENABLE_HWCRYPTO_RSA_TESTS)
	key->allow_hwcrypto = 1;
#endif

	/* The first test signature is valid. */
	memcpy(sig, signatures[0], sizeof(sig));
	TEST_SUCC(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		  "RSA Padding Test valid sig");

	/* All other signatures should fail verification. */
	unexpected_success = 0;
	for (i = 1; i < sizeof(signatures) / sizeof(signatures[0]); i++) {
		memcpy(sig, signatures[i], sizeof(sig));
		if (!vb2_rsa_verify_digest(key, sig,
					   test_message_sha1_hash, &wb)) {
			fprintf(stderr,
				"RSA Padding Test vector %d FAILED!\n", i);
			unexpected_success++;
		}
	}
	TEST_EQ(unexpected_success, 0, "RSA Padding Test invalid sigs");
}


/**
 * Test other error conditions in vb2_rsa_verify_digest().
 */
static void test_verify_digest(struct vb2_public_key *key) {
	uint8_t workbuf[VB2_VERIFY_DIGEST_WORKBUF_BYTES]
		 __attribute__((aligned(VB2_WORKBUF_ALIGN)));
	uint8_t sig[RSA1024NUMBYTES];
	struct vb2_workbuf wb;
	enum vb2_signature_algorithm orig_key_alg = key->sig_alg;

	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

	memcpy(sig, signatures[0], sizeof(sig));
	TEST_SUCC(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		  "vb2_rsa_verify_digest() good");

	TEST_EQ(vb2_rsa_verify_digest(key, NULL, test_message_sha1_hash, &wb),
		VB2_ERROR_RSA_VERIFY_PARAM, "vb2_rsa_verify_digest() bad arg");

	key->allow_hwcrypto = 1;
	memcpy(sig, signatures[0], sizeof(sig));
	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));
#if defined(ENABLE_HWCRYPTO_RSA_TESTS)
	TEST_SUCC(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		"vb2_rsa_verify_digest() hwcrypto modexp");
#else
	hwcrypto_modexp_return_value = VB2_SUCCESS;
	TEST_NEQ(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		VB2_SUCCESS, "vb2_rsa_verify_digest() hwcrypto modexp fails");

	memcpy(sig, signatures[0], sizeof(sig));
	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));
	hwcrypto_modexp_return_value = VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;
	TEST_SUCC(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		"vb2_rsa_verify_digest() hwcrypto modexp fallback to sw");
	key->allow_hwcrypto = 0;
#endif

	memcpy(sig, signatures[0], sizeof(sig));
	vb2_workbuf_init(&wb, workbuf, sizeof(sig) * 3 - 1);
	TEST_EQ(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		VB2_ERROR_RSA_VERIFY_WORKBUF,
		"vb2_rsa_verify_digest() small workbuf");
	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

	key->sig_alg = VB2_SIG_INVALID;
	memcpy(sig, signatures[0], sizeof(sig));
	TEST_EQ(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		VB2_ERROR_RSA_VERIFY_ALGORITHM,
		"vb2_rsa_verify_digest() bad key alg");
	key->sig_alg = orig_key_alg;

	key->arrsize *= 2;
	memcpy(sig, signatures[0], sizeof(sig));
	TEST_EQ(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		VB2_ERROR_RSA_VERIFY_SIG_LEN,
		"vb2_rsa_verify_digest() bad sig len");
	key->arrsize /= 2;

	/* Corrupt the signature near start and end */
	memcpy(sig, signatures[0], sizeof(sig));
	sig[3] ^= 0x42;
	TEST_EQ(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		VB2_ERROR_RSA_PADDING, "vb2_rsa_verify_digest() bad sig");

	memcpy(sig, signatures[0], sizeof(sig));
	sig[RSA1024NUMBYTES - 3] ^= 0x56;
	TEST_EQ(vb2_rsa_verify_digest(key, sig, test_message_sha1_hash, &wb),
		VB2_ERROR_RSA_PADDING, "vb2_rsa_verify_digest() bad sig end");
}

int main(int argc, char *argv[])
{
	struct vb2_public_key k2;
	struct vb2_packed_key *pk;

	/* Read test key */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <test public key>\n", argv[0]);
		return 1;
	}
	pk = vb2_read_packed_keyb(argv[1], VB2_ALG_RSA1024_SHA1, 0);
	if (!pk) {
		fprintf(stderr, "Couldn't read RSA public key for the test.\n");
		return 1;
	}
	if (VB2_SUCCESS != vb2_unpack_key(&k2, pk)) {
		fprintf(stderr, "Couldn't unpack RSA public key.\n");
		free(pk);
		return 1;
	}

	/* Run tests */
	test_signatures(&k2);
	test_verify_digest(&k2);

	/* Clean up and exit */
	free(pk);
	return gTestSuccess ? 0 : 255;
}
