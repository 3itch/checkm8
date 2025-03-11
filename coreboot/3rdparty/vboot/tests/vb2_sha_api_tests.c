/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vb2_hash_(calculate|verify) functions, and hwcrypto handling
 * of vb2_digest_*.
 */

#include "2api.h"
#include "2return_codes.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "common/tests.h"

uint8_t mock_sha1[] = {0x1, 0x3, 0x5, 0x2, 0x4, 0x6, 0xa, 0xb, 0xc, 0xd,
		       0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf, 0x0, 0xf0};
_Static_assert(sizeof(mock_sha1) == VB2_SHA1_DIGEST_SIZE, "");

struct vb2_hash mock_hash;
uint8_t mock_buffer[] = "Mock Buffer";

static enum hwcrypto_state {
	HWCRYPTO_OK,
	HWCRYPTO_NOTSUPPORTED,
	HWCRYPTO_ERROR,
	HWCRYPTO_ABORT,
} hwcrypto_state;

static vb2_error_t hwcrypto_mock(enum hwcrypto_state *state)
{
	switch (*state) {
	case HWCRYPTO_OK:
		return VB2_SUCCESS;
	case HWCRYPTO_NOTSUPPORTED:
		return VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;
	case HWCRYPTO_ERROR:
		return VB2_ERROR_MOCK;
	case HWCRYPTO_ABORT:
		vb2ex_abort();
		/* shouldn't reach here but added for compiler */
		return VB2_ERROR_MOCK;
	}
	return VB2_ERROR_MOCK;
}

static void reset_common_data(enum hwcrypto_state state)
{
	hwcrypto_state = state;
	memset(&mock_hash, 0xaa, sizeof(mock_hash));
}

void vb2_sha1_init(struct vb2_sha1_context *ctx)
{
	TEST_TRUE(hwcrypto_state == HWCRYPTO_NOTSUPPORTED ||
		  hwcrypto_state == HWCRYPTO_ABORT,
		  "    hwcrypto_state in SW init");
}

void vb2_sha1_update(struct vb2_sha1_context *ctx,
		     const uint8_t *data,
		     uint32_t size)
{
	TEST_TRUE(hwcrypto_state == HWCRYPTO_NOTSUPPORTED ||
		  hwcrypto_state == HWCRYPTO_ABORT,
		  "    hwcrypto_state in SW extend");
	TEST_PTR_EQ(data, mock_buffer, "    digest_extend buf");
	TEST_EQ(size, sizeof(mock_buffer), "    digest_extend size");
}

void vb2_sha1_finalize(struct vb2_sha1_context *ctx, uint8_t *digest)
{
	TEST_TRUE(hwcrypto_state == HWCRYPTO_NOTSUPPORTED ||
		  hwcrypto_state == HWCRYPTO_ABORT,
		  "    hwcrypto_state in SW finalize");
	memcpy(digest, mock_sha1, sizeof(mock_sha1));
}

vb2_error_t vb2ex_hwcrypto_digest_init(enum vb2_hash_algorithm hash_alg,
				       uint32_t data_size)
{
	if (data_size)
		TEST_EQ(data_size, sizeof(mock_buffer),
			"    hwcrypto_digest_init size");
	return hwcrypto_mock(&hwcrypto_state);
}

vb2_error_t vb2ex_hwcrypto_digest_extend(const uint8_t *buf, uint32_t size)
{
	TEST_PTR_EQ(buf, mock_buffer, "    hwcrypto_digest_extend buf");
	TEST_EQ(size, sizeof(mock_buffer), "    hwcrypto_digest_extend size");
	return hwcrypto_mock(&hwcrypto_state);
}

vb2_error_t vb2ex_hwcrypto_digest_finalize(uint8_t *digest,
					   uint32_t digest_size)
{
	memcpy(digest, mock_sha1, sizeof(mock_sha1));
	return hwcrypto_mock(&hwcrypto_state);
}

static void vb2_hash_cbfs_compatibility_test(void)
{
	/* 'algo' used to be represented as a 4-byte big-endian in CBFS. Confirm
	   that the new representation is binary compatible for small values. */
	union {
		struct vb2_hash hash;
		struct {
			uint32_t be32;
			uint8_t bytes[0];
		};
	} test = {0};

	test.be32 = htobe32(0xa5);
	TEST_EQ(test.hash.algo, 0xa5, "vb2_hash algo compatible to CBFS attr");
	TEST_PTR_EQ(&test.hash.raw, &test.bytes, "  digest offset matches");
}

static void vb2_hash_calculate_tests(void)
{
	reset_common_data(HWCRYPTO_ABORT);
	TEST_SUCC(vb2_hash_calculate(false, &mock_buffer, sizeof(mock_buffer),
				     VB2_HASH_SHA1, &mock_hash),
		  "hash_calculate success");
	TEST_SUCC(memcmp(mock_hash.sha1, mock_sha1, sizeof(mock_sha1)),
		  "  got the right hash");
	TEST_EQ(mock_hash.algo, VB2_HASH_SHA1, "  set algo correctly");

	reset_common_data(HWCRYPTO_ABORT);
	TEST_EQ(vb2_hash_calculate(false, mock_buffer, sizeof(mock_buffer),
				   -1, &mock_hash),
		VB2_ERROR_SHA_INIT_ALGORITHM, "hash_calculate wrong algo");
}

static void vb2_hash_verify_tests(void)
{
	reset_common_data(HWCRYPTO_ABORT);

	memcpy(mock_hash.sha1, mock_sha1, sizeof(mock_sha1));
	mock_hash.algo = VB2_HASH_SHA1;
	TEST_SUCC(vb2_hash_verify(false, mock_buffer, sizeof(mock_buffer),
				  &mock_hash), "hash_verify success");

	memcpy(mock_hash.sha1, mock_sha1, sizeof(mock_sha1));
	mock_hash.algo = -1;
	TEST_EQ(vb2_hash_verify(false, mock_buffer, sizeof(mock_buffer),
				&mock_hash), VB2_ERROR_SHA_INIT_ALGORITHM,
		"hash_verify wrong algo");

	memcpy(mock_hash.sha1, mock_sha1, sizeof(mock_sha1));
	mock_hash.sha1[5] = 0xfe;
	mock_hash.algo = VB2_HASH_SHA1;
	TEST_EQ(vb2_hash_verify(false, mock_buffer, sizeof(mock_buffer),
				&mock_hash), VB2_ERROR_SHA_MISMATCH,
		"hash_verify mismatch");
}

static void vb2_hash_hwcrypto_tests(void)
{
	struct vb2_digest_context dc;

	reset_common_data(HWCRYPTO_OK);
	TEST_SUCC(vb2_digest_init(&dc, true, VB2_HASH_SHA1,
				  sizeof(mock_buffer)),
		  "digest_init, HW enabled");
	TEST_EQ(dc.using_hwcrypto, 1, "  using_hwcrypto set");
	TEST_SUCC(vb2_digest_extend(&dc, mock_buffer, sizeof(mock_buffer)),
		  "digest_extend, HW enabled");
	TEST_SUCC(vb2_digest_finalize(&dc, mock_hash.raw, VB2_SHA1_DIGEST_SIZE),
		  "digest_finalize, HW enabled ");
	TEST_SUCC(memcmp(mock_hash.sha1, mock_sha1, sizeof(mock_sha1)),
		  "  got the right hash");

	reset_common_data(HWCRYPTO_OK);
	TEST_SUCC(vb2_hash_calculate(true, mock_buffer, sizeof(mock_buffer),
				     VB2_HASH_SHA1, &mock_hash),
		  "hash_calculate, HW enabled");
	TEST_SUCC(memcmp(mock_hash.sha1, mock_sha1, sizeof(mock_sha1)),
		  "  got the right hash");
	TEST_EQ(mock_hash.algo, VB2_HASH_SHA1, "  algo set");

	reset_common_data(HWCRYPTO_ERROR);
	TEST_EQ(vb2_hash_calculate(true, mock_buffer, sizeof(mock_buffer),
				   VB2_HASH_SHA1, &mock_hash),
		VB2_ERROR_MOCK, "hash_calculate, HW error");

	reset_common_data(HWCRYPTO_NOTSUPPORTED);
	TEST_SUCC(vb2_hash_calculate(true, mock_buffer, sizeof(mock_buffer),
				     VB2_HASH_SHA1, &mock_hash),
		  "hash_calculate, HW unsupported");
	TEST_SUCC(memcmp(mock_hash.sha1, mock_sha1, sizeof(mock_sha1)),
		  "  got the right hash");

	reset_common_data(HWCRYPTO_OK);
	memcpy(mock_hash.sha1, mock_sha1, sizeof(mock_sha1));
	mock_hash.algo = VB2_HASH_SHA1;
	TEST_SUCC(vb2_hash_verify(true, mock_buffer, sizeof(mock_buffer),
				  &mock_hash), "hash_verify, HW enabled");

	memcpy(mock_hash.sha1, mock_sha1, sizeof(mock_sha1));
	mock_hash.sha1[5] = 0xfe;
	mock_hash.algo = VB2_HASH_SHA1;
	TEST_EQ(vb2_hash_verify(true, mock_buffer, sizeof(mock_buffer),
				&mock_hash), VB2_ERROR_SHA_MISMATCH,
		"hash_verify HW mismatch");
}

int main(int argc, char *argv[])
{
	TEST_EQ(sizeof(mock_hash),
		offsetof(struct vb2_hash, raw) + VB2_SHA512_DIGEST_SIZE,
		"tests run with all SHA algorithms enabled");

	vb2_hash_cbfs_compatibility_test();
	vb2_hash_calculate_tests();
	vb2_hash_verify_tests();
	vb2_hash_hwcrypto_tests();

	return gTestSuccess ? 0 : 255;
}
