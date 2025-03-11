/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for firmware 2common.c
 */

#include "2common.h"
#include "2rsa.h"
#include "2sysincludes.h"
#include "common/tests.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_signature21.h"

static const uint8_t test_data[] = "This is some test data to sign.";

/*
 * Test struct packing for vboot_struct.h structs which are passed between
 * firmware and OS, or passed between different phases of firmware.
 */
static void test_struct_packing(void)
{
	/* Test new struct sizes */
	TEST_EQ(EXPECTED_ID_SIZE,
		sizeof(struct vb2_id),
		"sizeof(vb2_id)");
	TEST_EQ(EXPECTED_VB21_STRUCT_COMMON_SIZE,
		sizeof(struct vb21_struct_common),
		"sizeof(vb21_struct_common)");
	TEST_EQ(EXPECTED_VB21_PACKED_KEY_SIZE,
		sizeof(struct vb21_packed_key),
		"sizeof(vb21_packed_key)");
	TEST_EQ(EXPECTED_VB21_SIGNATURE_SIZE,
		sizeof(struct vb21_signature),
		"sizeof(vb21_signature)");
}

/**
 * Common header functions
 */
static void test_common_header_functions(void)
{
	uint8_t cbuf[sizeof(struct vb21_struct_common) + 128];
	uint8_t cbufgood[sizeof(cbuf)];
	struct vb21_struct_common *c = (struct vb21_struct_common *)cbuf;
	struct vb21_struct_common *c2;
	const char test_desc[32] = "test desc";
	uint32_t desc_end, m;

	c->total_size = sizeof(cbuf);
	c->fixed_size = sizeof(*c);
	c->desc_size = sizeof(test_desc);
	memcpy(cbuf + c->fixed_size, test_desc, sizeof(test_desc));
	desc_end = c->fixed_size + c->desc_size;

	c2 = (struct vb21_struct_common *)(cbuf + desc_end);
	c2->total_size = c->total_size - desc_end;
	c2->fixed_size = sizeof(*c2);
	c2->desc_size = 0;

	/* Description helper */
	TEST_EQ(0, strcmp(vb21_common_desc(c), test_desc), "vb21_common_desc()");
	TEST_EQ(0, strcmp(vb21_common_desc(c2), ""), "vb21_common_desc() empty");

	TEST_SUCC(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		  "vb21_verify_common_header() good");
	memcpy(cbufgood, cbuf, sizeof(cbufgood));

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->total_size += 4;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_TOTAL_SIZE,
		"vb21_verify_common_header() total size");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->fixed_size = c->total_size + 4;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_FIXED_SIZE,
		"vb21_verify_common_header() fixed size");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->desc_size = c->total_size - c->fixed_size + 4;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_DESC_SIZE,
		"vb21_verify_common_header() desc size");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->total_size--;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_TOTAL_UNALIGNED,
		"vb21_verify_common_header() total unaligned");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->fixed_size++;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_FIXED_UNALIGNED,
		"vb21_verify_common_header() fixed unaligned");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->desc_size--;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_DESC_UNALIGNED,
		"vb21_verify_common_header() desc unaligned");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	c->desc_size = -4;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_DESC_WRAPS,
		"vb21_verify_common_header() desc wraps");

	memcpy(cbuf, cbufgood, sizeof(cbuf));
	cbuf[desc_end - 1] = 1;
	TEST_EQ(vb21_verify_common_header(cbuf, sizeof(cbuf)),
		VB2_ERROR_COMMON_DESC_TERMINATOR,
		"vb21_verify_common_header() desc not terminated");

	/* Member checking function */
	memcpy(cbuf, cbufgood, sizeof(cbuf));
	m = 0;
	TEST_SUCC(vb21_verify_common_member(cbuf, &m, c->total_size - 8, 4),
		  "vb21_verify_common_member()");
	TEST_EQ(m, c->total_size - 4, "  new minimum");

	m = desc_end;
	TEST_SUCC(vb21_verify_common_member(cbuf, &m, desc_end, 4),
		  "vb21_verify_common_member() good offset");
	TEST_EQ(m, desc_end + 4, "  new minimum");

	m = 0;
	TEST_EQ(vb21_verify_common_member(cbuf, &m, c->total_size - 8, -4),
		VB2_ERROR_COMMON_MEMBER_WRAPS,
		"vb21_verify_common_member() wraps");

	m = 0;
	TEST_EQ(vb21_verify_common_member(cbuf, &m, c->total_size - 7, 4),
		VB2_ERROR_COMMON_MEMBER_UNALIGNED,
		"vb21_verify_common_member() offset unaligned");

	m = 0;
	TEST_EQ(vb21_verify_common_member(cbuf, &m, c->total_size - 8, 5),
		VB2_ERROR_COMMON_MEMBER_UNALIGNED,
		"vb21_verify_common_member() size unaligned");

	m = 0;
	TEST_EQ(vb21_verify_common_member(cbuf, &m, desc_end - 4, 4),
		VB2_ERROR_COMMON_MEMBER_OVERLAP,
		"vb21_verify_common_member() overlap");

	m = desc_end + 4;
	TEST_EQ(vb21_verify_common_member(cbuf, &m, desc_end, 4),
		VB2_ERROR_COMMON_MEMBER_OVERLAP,
		"vb21_verify_common_member() overlap 2");

	m = 0;
	TEST_EQ(vb21_verify_common_member(cbuf, &m, c->total_size - 4, 8),
		VB2_ERROR_COMMON_MEMBER_SIZE,
		"vb21_verify_common_member() size");

	/* Subobject checking */
	m = 0;
	TEST_SUCC(vb21_verify_common_subobject(cbuf, &m, desc_end),
		  "vb21_verify_common_subobject() good offset");
	TEST_EQ(m, sizeof(cbuf), "  new minimum");

	m = desc_end + 4;
	TEST_EQ(vb21_verify_common_subobject(cbuf, &m, desc_end),
		VB2_ERROR_COMMON_MEMBER_OVERLAP,
		"vb21_verify_common_subobject() overlap");

	m = 0;
	c2->total_size += 4;
	TEST_EQ(vb21_verify_common_subobject(cbuf, &m, desc_end),
		VB2_ERROR_COMMON_TOTAL_SIZE,
		"vb21_verify_common_subobject() size");
}

/**
 * Signature size
 */
static void test_sig_size(void)
{
	TEST_EQ(vb2_sig_size(VB2_SIG_INVALID, VB2_HASH_SHA256), 0,
		"vb2_sig_size() sig invalid");

	TEST_EQ(vb2_sig_size(VB2_SIG_RSA2048, VB2_HASH_INVALID), 0,
		"vb2_sig_size() hash invalid");

	TEST_EQ(vb2_sig_size(VB2_SIG_RSA2048, VB2_HASH_SHA256), 2048 / 8,
		"vb2_sig_size() RSA2048");
	TEST_EQ(vb2_sig_size(VB2_SIG_RSA4096, VB2_HASH_SHA256), 4096 / 8,
		"vb2_sig_size() RSA4096");
	TEST_EQ(vb2_sig_size(VB2_SIG_RSA8192, VB2_HASH_SHA512), 8192 / 8,
		"vb2_sig_size() RSA8192");

	TEST_EQ(vb2_sig_size(VB2_SIG_NONE, VB2_HASH_SHA1),
		VB2_SHA1_DIGEST_SIZE, "vb2_sig_size() SHA1");
	TEST_EQ(vb2_sig_size(VB2_SIG_NONE, VB2_HASH_SHA256),
		VB2_SHA256_DIGEST_SIZE, "vb2_sig_size() SHA256");
	TEST_EQ(vb2_sig_size(VB2_SIG_NONE, VB2_HASH_SHA512),
		VB2_SHA512_DIGEST_SIZE, "vb2_sig_size() SHA512");
}

/**
 * Verify data on bare hash
 */
static void test_verify_hash(void)
{
	struct vb21_signature *sig;
	const struct vb2_private_key *prik;
	struct vb2_public_key pubk;
	uint8_t workbuf[VB2_VERIFY_DATA_WORKBUF_BYTES]
		 __attribute__((aligned(VB2_WORKBUF_ALIGN)));
	struct vb2_workbuf wb;

	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

	TEST_SUCC(vb2_private_key_hash(&prik, VB2_HASH_SHA256),
		  "create private hash key");
	TEST_SUCC(vb2_public_key_hash(&pubk, VB2_HASH_SHA256),
		  "create hash key");

	/* Create the signature */
	TEST_SUCC(vb21_sign_data(&sig, test_data, sizeof(test_data),
				 prik, NULL),
		  "create hash sig");

	TEST_SUCC(vb21_verify_data(test_data, sizeof(test_data),
				   sig, &pubk, &wb),
		  "vb21_verify_data() hash ok");

	*((uint8_t *)sig + sig->sig_offset) ^= 0xab;
	TEST_EQ(vb21_verify_data(test_data, sizeof(test_data), sig, &pubk, &wb),
		VB2_ERROR_VDATA_VERIFY_DIGEST, "vb21_verify_data() hash bad");

	free(sig);
}

int main(int argc, char* argv[])
{
	test_struct_packing();
	test_common_header_functions();
	test_sig_size();
	test_verify_hash();

	return gTestSuccess ? 0 : 255;
}
