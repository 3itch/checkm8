/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for kernel secure storage library.
 */

#include "2api.h"
#include "2common.h"
#include "2crc8.h"
#include "2misc.h"
#include "2secdata.h"
#include "2secdata_struct.h"
#include "2sysincludes.h"
#include "common/tests.h"

static uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_secdata_kernel_v0 *sec02;
static struct vb2_secdata_kernel_v1 *sec10;

static void reset_common_data(void)
{
	memset(workbuf, 0xaa, sizeof(workbuf));
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	sd = vb2_get_sd(ctx);

	/* Most tests assume we have passed fw_phase1() */
	sd->status |= VB2_SD_STATUS_RECOVERY_DECIDED;

	sec02 = (struct vb2_secdata_kernel_v0 *)ctx->secdata_kernel;
	sec10 = (struct vb2_secdata_kernel_v1 *)ctx->secdata_kernel;
}

static void test_init(struct vb2_shared_data *s, int init, const char *why)
{
	if (init)
		TEST_NEQ(s->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT, 0, why);
	else
		TEST_EQ(s->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT, 0, why);
}

static void test_changed(struct vb2_context *c, int changed, const char *why)
{
	if (changed)
		TEST_NEQ(c->flags & VB2_CONTEXT_SECDATA_KERNEL_CHANGED, 0, why);
	else
		TEST_EQ(c->flags & VB2_CONTEXT_SECDATA_KERNEL_CHANGED, 0, why);

	c->flags &= ~VB2_CONTEXT_SECDATA_KERNEL_CHANGED;
}

/*
 * Version-independent tests
 */
static void secdata_kernel_test(void)
{
	uint8_t size;

	reset_common_data();

	/* Blank data is invalid */
	size = VB2_SECDATA_KERNEL_MIN_SIZE;
	memset(&ctx->secdata_kernel, 0xa6, size);
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Check blank bad version");
	TEST_EQ(vb2_secdata_kernel_init(ctx),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Init blank bad version");
	test_init(sd, 0, "Init set SD status");

	/* Ensure zeroed buffers are invalid */
	size = VB2_SECDATA_KERNEL_MIN_SIZE;
	memset(&ctx->secdata_kernel, 0, size);
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Check zero bad version");
	TEST_EQ(vb2_secdata_kernel_init(ctx),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Init zero incomplete");
	test_init(sd, 0, "Init set SD status");

	/* Read data less than minimum size */
	size = VB2_SECDATA_KERNEL_MIN_SIZE - 1;
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_INCOMPLETE, "Check incomplete");
	TEST_EQ(size, VB2_SECDATA_KERNEL_MIN_SIZE, "Return minimum size");
}

static void secdata_kernel_test_v10(void)
{
	uint8_t size;

	reset_common_data();

	/* Create good data */
	size = VB2_SECDATA_KERNEL_SIZE_V10;
	TEST_EQ(vb2api_secdata_kernel_create(ctx),
		VB2_SECDATA_KERNEL_SIZE_V10, "Create v1.0");
	TEST_SUCC(vb2api_secdata_kernel_check(ctx, &size), "Check created CRC");
	TEST_SUCC(vb2_secdata_kernel_init(ctx), "Init created CRC");
	test_init(sd, 1, "Init set SD status");
	test_changed(ctx, 1, "Create changes data");

	/* Check excessive data */
	size = VB2_SECDATA_KERNEL_SIZE_V10 + 1;
	TEST_SUCC(vb2api_secdata_kernel_check(ctx, &size),
		  "Check large v1.0 data");
	TEST_EQ(size, VB2_SECDATA_KERNEL_SIZE_V10, "Return expected size");

	/* Check incomplete data */
	size = VB2_SECDATA_KERNEL_SIZE_V10 - 1;
	vb2api_secdata_kernel_create(ctx);
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_INCOMPLETE, "Check incomplete");
	TEST_EQ(size, VB2_SECDATA_KERNEL_SIZE_V10, "Return expected size");

	reset_common_data();

	/* Bad version */
	size = VB2_SECDATA_KERNEL_SIZE_V10;
	vb2api_secdata_kernel_create(ctx);
	sec10->struct_version -= 1;
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Check invalid version");
	TEST_EQ(vb2_secdata_kernel_init(ctx),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Init invalid version");
	test_init(sd, 0, "Init set SD status");

	/* Higher minor version */
	vb2api_secdata_kernel_create(ctx);
	sec10->struct_version += 1;
	TEST_SUCC(vb2api_secdata_kernel_check(ctx, &size), "Check v1.1 data");
	TEST_SUCC(vb2_secdata_kernel_init(ctx), "Init v1.1 data");
	test_init(sd, 1, "Init set SD status");

	reset_common_data();

	/* Higher major version */
	vb2api_secdata_kernel_create(ctx);
	sec10->struct_version += 0x10;
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Check v2.0 data");
	TEST_EQ(vb2_secdata_kernel_init(ctx),
		VB2_ERROR_SECDATA_KERNEL_VERSION, "Init v2.0 data");
	test_init(sd, 0, "Init set SD status");

	reset_common_data();

	/* Corrupt data */
	size = VB2_SECDATA_KERNEL_SIZE_V10;
	vb2api_secdata_kernel_create(ctx);
	sec10->kernel_versions++;
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_CRC, "Check invalid CRC");
	TEST_EQ(vb2_secdata_kernel_init(ctx),
		VB2_ERROR_SECDATA_KERNEL_CRC, "Init invalid CRC");
	test_init(sd, 0, "Init set SD status");
}

static void secdata_kernel_test_v02(void)
{
	uint8_t size;

	reset_common_data();

	/* Create good data */
	size = VB2_SECDATA_KERNEL_SIZE_V02;
	TEST_EQ(vb2api_secdata_kernel_create_v0(ctx), size, "Create v0.2");
	TEST_SUCC(vb2api_secdata_kernel_check(ctx, &size), "Check v0.2");
	TEST_SUCC(vb2_secdata_kernel_init(ctx), "Init created CRC");
	test_init(sd, 1, "Init set SD status");

	/* Check excessive data */
	size = VB2_SECDATA_KERNEL_SIZE_V02 + 1;
	TEST_SUCC(vb2api_secdata_kernel_check(ctx, &size),
		  "Check large v0.2 data");
	TEST_EQ(size, VB2_SECDATA_KERNEL_SIZE_V02, "Return expected size");

	/* Check incomplete data */
	size = VB2_SECDATA_KERNEL_SIZE_V02 - 1;
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_INCOMPLETE, "Check small v0.2 data");
	TEST_EQ(size, VB2_SECDATA_KERNEL_SIZE_V02, "Return expected size");
	reset_common_data();

	/* Corrupt data */
	vb2api_secdata_kernel_create_v0(ctx);
	sec02->kernel_versions++;
	TEST_EQ(vb2api_secdata_kernel_check(ctx, &size),
		VB2_ERROR_SECDATA_KERNEL_CRC, "Check invalid CRC");
	TEST_EQ(vb2_secdata_kernel_init(ctx),
		VB2_ERROR_SECDATA_KERNEL_CRC, "Init invalid CRC");
}

static void secdata_kernel_access_test_v10(void)
{
	uint32_t v = 1;
	const uint8_t *p;
	uint8_t ec_hash[VB2_SHA256_DIGEST_SIZE];

	reset_common_data();

	/* Read/write versions */
	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);
	ctx->flags = 0;
	v = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);
	TEST_EQ(v, 0, "Versions created 0");
	test_changed(ctx, 0, "Get doesn't change data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS, 0x123456ff);
	test_changed(ctx, 1, "Set changes data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS, 0x123456ff);
	test_changed(ctx, 0, "Set again doesn't change data");
	v = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);
	TEST_EQ(v, 0x123456ff, "Versions changed");

	/* Read/write flags */
	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);
	ctx->flags = 0;
	v = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS);
	TEST_EQ(v, 0, "Flags created 0");
	test_changed(ctx, 0, "Get doesn't change data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_FLAGS, 0x12);
	test_changed(ctx, 1, "Set changes data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_FLAGS, 0x12);
	test_changed(ctx, 0, "Set again doesn't change data");
	v = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS);
	TEST_EQ(v, 0x12, "Flags changed");
	TEST_ABORT(vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_FLAGS, 0x100),
		   "Bad flags");

	/* Invalid field fails */
	TEST_ABORT(vb2_secdata_kernel_get(ctx, -1), "Get invalid");
	TEST_ABORT(vb2_secdata_kernel_set(ctx, -1, 456), "Set invalid");
	test_changed(ctx, 0, "Set invalid field doesn't change data");

	/* Read/write uninitialized data fails */
	sd->status &= ~VB2_SD_STATUS_SECDATA_KERNEL_INIT;
	TEST_ABORT(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS),
		   "Get uninitialized");
	test_changed(ctx, 0, "Get uninitialized doesn't change data");
	TEST_ABORT(vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS,
					  0x123456ff),
		   "Set uninitialized");
	test_changed(ctx, 0, "Set uninitialized doesn't change data");

	/* Read/write uninitialized in recovery mode */
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	TEST_EQ(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS), 0,
		"Get uninitialized (recmode)");
	test_changed(ctx, 0, "Get uninitialized (recmode) doesn't change data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS,
				 0x123456ff);
	test_changed(ctx, 0, "Set uninitialized (recmode) doesn't change data");

	/* Read/write early in fw_phase1 */
	ctx->flags &= ~VB2_CONTEXT_RECOVERY_MODE;
	sd->status &= ~VB2_SD_STATUS_RECOVERY_DECIDED;
	TEST_EQ(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS), 0,
		"Get uninitialized (phase1)");
	test_changed(ctx, 0, "Get uninitialized (phase1) doesn't change data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS,
				 0x123456ff);
	test_changed(ctx, 0, "Set uninitialized (phase1) doesn't change data");

	/* Test EC hash set */
	reset_common_data();
	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);
	memset(ec_hash, 0xaa, sizeof(ec_hash));
	vb2_secdata_kernel_set_ec_hash(ctx, ec_hash);
	TEST_EQ(memcmp(ec_hash, sec10->ec_hash, sizeof(ec_hash)), 0,
		       "Check EC hash");
	test_changed(ctx, 1, "Set EC hash changes data");

	sec10->struct_version = VB2_SECDATA_KERNEL_VERSION_V02;
	TEST_ABORT(vb2_secdata_kernel_set_ec_hash(ctx, ec_hash),
		   "Can't set EC hash for v0.2");
	test_changed(ctx, 0, "Failing to set EC hash doesn't change data");
	sec10->struct_version = VB2_SECDATA_KERNEL_VERSION_V10;

	sd->status &= ~VB2_SD_STATUS_SECDATA_KERNEL_INIT;
	TEST_ABORT(vb2_secdata_kernel_set_ec_hash(ctx, ec_hash),
		   "Can't set EC hash before init");
	sd->status |= VB2_SD_STATUS_SECDATA_KERNEL_INIT;

	/* Test EC hash get */
	p = vb2_secdata_kernel_get_ec_hash(ctx);
	TEST_PTR_EQ(p, sec10->ec_hash, "Get EC hash returns pointer");
	test_changed(ctx, 0, "Get EC hash doesn't change data");

	sec10->struct_version = VB2_SECDATA_KERNEL_VERSION_V02;
	TEST_PTR_EQ(vb2_secdata_kernel_get_ec_hash(ctx), NULL,
		    "Can't get EC hash for v0.2");
	sec10->struct_version = VB2_SECDATA_KERNEL_VERSION_V10;

	sd->status &= ~VB2_SD_STATUS_SECDATA_KERNEL_INIT;
	TEST_ABORT(vb2_secdata_kernel_get_ec_hash(ctx),
		   "Can't get EC hash before init");
	sd->status |= VB2_SD_STATUS_SECDATA_KERNEL_INIT;
}

static void secdata_kernel_access_test_v02(void)
{
	uint32_t v = 1;
	reset_common_data();

	/* Read/write versions */
	vb2api_secdata_kernel_create_v0(ctx);
	vb2_secdata_kernel_init(ctx);
	ctx->flags = 0;
	v = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);
	TEST_EQ(v, 0, "Versions created 0");
	test_changed(ctx, 0, "Get doesn't change data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS, 0x123456ff);
	test_changed(ctx, 1, "Set changes data");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS, 0x123456ff);
	test_changed(ctx, 0, "Set again doesn't change data");
	v = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);
	TEST_EQ(v, 0x123456ff, "Versions changed");

	/* Read/write flags: should be no-op for v0 */
	TEST_EQ(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS), 0,
		"Get flags");
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_FLAGS, 0x1);
	TEST_EQ(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS), 0,
		"Get flags again");

	/* Invalid field fails */
	TEST_ABORT(vb2_secdata_kernel_get(ctx, -1), "Get invalid");
	TEST_ABORT(vb2_secdata_kernel_set(ctx, -1, 456), "Set invalid");
	test_changed(ctx, 0, "Set invalid field doesn't change data");

	/* Read/write uninitialized data fails */
	sd->status &= ~VB2_SD_STATUS_SECDATA_KERNEL_INIT;
	TEST_ABORT(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS),
		   "Get uninitialized");
	test_changed(ctx, 0, "Get uninitialized doesn't change data");
	TEST_ABORT(vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS,
					  0x123456ff),
		   "Set uninitialized");
	test_changed(ctx, 0, "Set uninitialized doesn't change data");
}

int main(int argc, char* argv[])
{
	secdata_kernel_test();
	secdata_kernel_test_v10();
	secdata_kernel_test_v02();
	secdata_kernel_access_test_v10();
	secdata_kernel_access_test_v02();

	return gTestSuccess ? 0 : 255;
}
