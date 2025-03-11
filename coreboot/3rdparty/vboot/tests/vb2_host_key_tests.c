/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for host library vboot2 key functions
 */

#include "2common.h"
#include "common/tests.h"
#include "host_common.h"

/* Public key utility functions */
static void public_key_tests(void)
{
	struct vb2_packed_key k[3];
	struct vb2_packed_key j[5];

	/* Fill some bits of the public key data */
	memset(j, 0, sizeof(j));
	memset(k, 0x42, sizeof(k));
	k[1].key_size = 12345;
	k[2].key_version = 67;

	vb2_init_packed_key(k, (uint8_t*)(k + 1),
			    2 * sizeof(struct vb2_packed_key));
	TEST_EQ(k->key_offset, sizeof(struct vb2_packed_key),
		"vb2_init_packed_key key_offset");
	TEST_EQ(k->key_size, 2 * sizeof(struct vb2_packed_key),
		"vb2_init_packed_key key_size");
	TEST_EQ(k->algorithm, VB2_ALG_COUNT, "vb2_init_packed_key algorithm");
	TEST_EQ(k->key_version, 0, "vb2_init_packed_key key_version");

	/* Set algorithm and version, so we can tell if they get copied */
	k->algorithm = 3;
	k->key_version = 21;

	/* Copying to a smaller destination should fail */
	vb2_init_packed_key(j, (uint8_t*)(j + 1),
		      2 * sizeof(struct vb2_packed_key) - 1);
	TEST_NEQ(0, vb2_copy_packed_key(j, k), "vb2_copy_packed_key too small");

	/* Copying to same or larger size should succeed */
	vb2_init_packed_key(j, (uint8_t*)(j + 2),
		      2 * sizeof(struct vb2_packed_key) + 1);
	TEST_EQ(0, vb2_copy_packed_key(j, k), "vb2_copy_packed_key same");
	/* Offset in destination shouldn't have been modified */
	TEST_EQ(j->key_offset, 2 * sizeof(struct vb2_packed_key),
		"vb2_copy_packed_key key_offset");
	/* Size should have been reduced to match the source */
	TEST_EQ(k->key_size, 2 * sizeof(struct vb2_packed_key),
		"vb2_copy_packed_key key_size");
	/* Other fields should have been copied */
	TEST_EQ(k->algorithm, j->algorithm, "vb2_copy_packed_key algorithm");
	TEST_EQ(k->key_version, j->key_version,
		"vb2_copy_packed_key key_version");
	/* Data should have been copied */
	TEST_EQ(0,
		memcmp(vb2_packed_key_data(k),
		       vb2_packed_key_data(j), k->key_size),
		"vb2_copy_packed_key data");
}

int main(int argc, char* argv[])
{
	public_key_tests();

	return gTestSuccess ? 0 : 255;
}
