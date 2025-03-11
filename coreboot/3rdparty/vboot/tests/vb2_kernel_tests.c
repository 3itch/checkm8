/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for kernel selection, loading, verification, and booting.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "common/boot_mode.h"
#include "common/tests.h"

/* Common context for tests */
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_fw_preamble *fwpre;
static const char fw_kernel_key_data[36] = "Test kernel key data";
static struct vb2_kernel_params kparams;

/* Mocked function data */

static struct {
	struct vb2_gbb_header h;
	struct vb2_packed_key recovery_key;
	char recovery_key_data[32];
} mock_gbb;

static int mock_read_res_fail_on_call;
static int mock_secdata_fwmp_check_retval;
static int mock_commit_data_called;
static int mock_ec_sync_called;
static int mock_ec_sync_retval;
static int mock_battery_cutoff_called;
static int mock_kernel_flag;
static int mock_kernel_flag_set;
static int mock_kernel_version_secdata;

/* Type of test to reset for */
enum reset_type {
	FOR_PHASE1,
	FOR_PHASE2,
	FOR_FINALIZE,
};

static void reset_common_data(enum reset_type t)
{
	struct vb2_packed_key *k;

	memset(workbuf, 0xaa, sizeof(workbuf));

	memset(&kparams, 0, sizeof(kparams));

	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	sd = vb2_get_sd(ctx);
	vb2_nv_init(ctx);

	mock_read_res_fail_on_call = 0;
	mock_secdata_fwmp_check_retval = VB2_SUCCESS;
	mock_commit_data_called = 0;
	mock_ec_sync_called = 0;
	mock_ec_sync_retval = VB2_SUCCESS;
	mock_battery_cutoff_called = 0;
	mock_kernel_flag = 0;
	mock_kernel_flag_set = 0;
	mock_kernel_version_secdata = 0x10002;

	/* Recovery key in mock GBB */
	memset(&mock_gbb, 0, sizeof(mock_gbb));
	mock_gbb.recovery_key.algorithm = 11;
	mock_gbb.recovery_key.key_offset =
		vb2_offset_of(&mock_gbb.recovery_key,
			      &mock_gbb.recovery_key_data);
	mock_gbb.recovery_key.key_size = sizeof(mock_gbb.recovery_key_data);
	strcpy(mock_gbb.recovery_key_data, "The recovery key");
	mock_gbb.h.recovery_key_offset =
		vb2_offset_of(&mock_gbb, &mock_gbb.recovery_key);
	mock_gbb.h.recovery_key_size =
		mock_gbb.recovery_key.key_offset +
		mock_gbb.recovery_key.key_size;
	mock_gbb.h.major_version = VB2_GBB_MAJOR_VER;
	mock_gbb.h.minor_version = VB2_GBB_MINOR_VER;

	if (t == FOR_PHASE1) {
		uint8_t *kdata;

		/* Create mock firmware preamble in the context */
		sd->preamble_offset = sd->workbuf_used;
		fwpre = (struct vb2_fw_preamble *)
			vb2_member_of(sd, sd->preamble_offset);
		k = &fwpre->kernel_subkey;
		kdata = (uint8_t *)fwpre + sizeof(*fwpre);
		memcpy(kdata, fw_kernel_key_data, sizeof(fw_kernel_key_data));
		k->algorithm = 7;
		k->key_offset = vb2_offset_of(k, kdata);
		k->key_size = sizeof(fw_kernel_key_data);
		sd->preamble_size = sizeof(*fwpre) + k->key_size;
		vb2_set_workbuf_used(ctx,
				     sd->preamble_offset + sd->preamble_size);
	} else if (t == FOR_FINALIZE) {
		SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
		vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0xffffffff);
		sd->kernel_version_secdata = mock_kernel_version_secdata;
	}
};

/* Mocked functions */

vb2_error_t vb2api_secdata_fwmp_check(struct vb2_context *c, uint8_t *size)
{
	return mock_secdata_fwmp_check_retval;
}

vb2_error_t vb2api_ec_sync(struct vb2_context *c)
{
	mock_ec_sync_called = 1;
	return mock_ec_sync_retval;
}

vb2_error_t vb2api_auxfw_sync(struct vb2_context *c)
{
	TEST_EQ(mock_ec_sync_called, 1,
		"  auxfw sync must happen after EC sync");
	return VB2_SUCCESS;
}

vb2_error_t vb2ex_ec_battery_cutoff(void)
{
	TEST_EQ(mock_ec_sync_called, 1,
		"  battery cutoff must happen after EC sync");
	mock_battery_cutoff_called = 1;
	return VB2_SUCCESS;
}

const uint8_t *vb2_secdata_kernel_get_ec_hash(struct vb2_context *c)
{
	/*
	 * Return NULL to prevent EC reboot due to
	 * VB2_SD_FLAG_ECSYNC_HMIR_UPDATED.
	 */
	return NULL;
}

struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &mock_gbb.h;
}

vb2_error_t vb2ex_read_resource(struct vb2_context *c,
				enum vb2_resource_index index, uint32_t offset,
				void *buf, uint32_t size)
{
	uint8_t *rptr;
	uint32_t rsize;

	if (--mock_read_res_fail_on_call == 0)
		return VB2_ERROR_MOCK;

	switch(index) {
	case VB2_RES_GBB:
		rptr = (uint8_t *)&mock_gbb;
		rsize = sizeof(mock_gbb);
		break;
	default:
		return VB2_ERROR_EX_READ_RESOURCE_INDEX;
	}

	if (offset > rsize || offset + size > rsize)
		return VB2_ERROR_EX_READ_RESOURCE_SIZE;

	memcpy(buf, rptr + offset, size);
	return VB2_SUCCESS;
}

vb2_error_t vb2ex_commit_data(struct vb2_context *c)
{
	mock_commit_data_called = 1;
	return VB2_SUCCESS;
}

void vb2_secdata_kernel_set(struct vb2_context *c,
			    enum vb2_secdata_kernel_param param,
			    uint32_t value)
{
	switch (param) {
	case VB2_SECDATA_KERNEL_FLAGS:
		mock_kernel_flag = value;
		mock_kernel_flag_set = 1;
		break;
	case VB2_SECDATA_KERNEL_VERSIONS:
		mock_kernel_version_secdata = value;
		break;
	default:
		vb2ex_abort();
	}
}

uint32_t vb2_secdata_kernel_get(struct vb2_context *c,
				enum vb2_secdata_kernel_param param)
{
	switch (param) {
	case VB2_SECDATA_KERNEL_FLAGS:
		return mock_kernel_flag;
	case VB2_SECDATA_KERNEL_VERSIONS:
		return mock_kernel_version_secdata;
	default:
		vb2ex_abort();
	}
	return 0;
}

/* Tests */

static void phase1_tests(void)
{
	struct vb2_packed_key *k;
	uint32_t wb_used_before;

	/* Test successful call */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 good");
	/* Make sure normal key was loaded */
	TEST_EQ(sd->kernel_key_offset, sd->preamble_offset +
		offsetof(struct vb2_fw_preamble, kernel_subkey),
		"  workbuf key offset");
	k = vb2_member_of(sd, sd->kernel_key_offset);
	TEST_EQ(sd->kernel_key_size, k->key_offset + k->key_size,
		"  workbuf key size");
	TEST_EQ(sd->workbuf_used,
		vb2_wb_round_up(sd->kernel_key_offset +
				sd->kernel_key_size),
		"  workbuf used");
	TEST_EQ(k->algorithm, 7, "  key algorithm");
	TEST_EQ(k->key_size, sizeof(fw_kernel_key_data), "  key_size");
	TEST_EQ(memcmp((uint8_t *)k + k->key_offset, fw_kernel_key_data,
		       k->key_size), 0, "  key data");
	TEST_EQ(sd->kernel_version_secdata, 0x10002,
		"  secdata_kernel version");

	/* Test successful call in recovery mode */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_BROKEN_SCREEN, 123);
	/* No preamble needed in recovery mode */
	sd->workbuf_used = sd->preamble_offset;
	sd->preamble_offset = sd->preamble_size = 0;
	wb_used_before = sd->workbuf_used;
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 rec good");
	/* Make sure recovery key was loaded */
	TEST_EQ(sd->kernel_key_offset, wb_used_before,
		"  workbuf key offset");
	k = vb2_member_of(sd, sd->kernel_key_offset);
	TEST_EQ(sd->kernel_key_size, k->key_offset + k->key_size,
		"  workbuf key size");
	TEST_EQ(sd->workbuf_used,
		vb2_wb_round_up(sd->kernel_key_offset +
				sd->kernel_key_size),
		"  workbuf used");
	TEST_EQ(k->algorithm, 11, "  key algorithm");
	TEST_EQ(k->key_size, sizeof(mock_gbb.recovery_key_data), "  key_size");
	TEST_EQ(memcmp((uint8_t *)k + k->key_offset,
		       mock_gbb.recovery_key_data, k->key_size), 0,
		"  key data");
	TEST_EQ(sd->kernel_version_secdata, 0x10002,
		"  secdata_kernel version");

	/* Test flags for experimental features in non-recovery path */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 non-rec good");
	/* Make sure diagnostic UI is enabled */
	TEST_EQ(vb2api_diagnostic_ui_enabled(ctx), 1,
		"  diagnostic ui enabled");

	/*
	 * Test flags are unchanged for experimental features in recovery path
	 */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_BROKEN_SCREEN, 123);
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 rec good");
	TEST_EQ(mock_kernel_flag_set, 0,
		"VB2_SECDATA_KERNEL_FLAGS remains unchanged in recovery path");

	/* Bad secdata_fwmp causes failure in normal mode only */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	mock_secdata_fwmp_check_retval = VB2_ERROR_SECDATA_FWMP_CRC;
	TEST_EQ(vb2api_kernel_phase1(ctx), mock_secdata_fwmp_check_retval,
		"phase1 bad secdata_fwmp");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_SECDATA_FWMP_INIT, "  recovery reason");

	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_BROKEN_SCREEN, 123);
	mock_secdata_fwmp_check_retval = VB2_ERROR_SECDATA_FWMP_CRC;
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 bad secdata_fwmp rec");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_NOT_REQUESTED, "  no recovery");

	/* Failures while reading recovery key */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_BROKEN_SCREEN, 123);
	mock_gbb.h.recovery_key_size = sd->workbuf_size - 1;
	mock_gbb.recovery_key.key_size =
		mock_gbb.h.recovery_key_size - sizeof(mock_gbb.recovery_key);
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_SUCCESS,
		"phase1 rec workbuf key");
	TEST_EQ(sd->kernel_key_offset, 0, "  workbuf key offset");
	TEST_EQ(sd->kernel_key_size, 0, "  workbuf key size");
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	TEST_ABORT(vb2api_kernel_phase1(ctx), "  fatal for manual recovery");

	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_BROKEN_SCREEN, 123);
	mock_read_res_fail_on_call = 1;
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_SUCCESS,
		"phase1 rec gbb read key");
	TEST_EQ(sd->kernel_key_offset, 0, "  workbuf key offset");
	TEST_EQ(sd->kernel_key_size, 0, "  workbuf key size");
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	mock_read_res_fail_on_call = 1;
	TEST_ABORT(vb2api_kernel_phase1(ctx), "  fatal for manual recovery");

	/* Failures while parsing subkey from firmware preamble */
	reset_common_data(FOR_PHASE1);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	sd->preamble_size = 0;
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_ERROR_API_KPHASE1_PREAMBLE,
		"phase1 fw preamble");
}

static void phase2_tests(void)
{
	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Normal mode");
	TEST_EQ(mock_ec_sync_called, 1, "  EC sync");

	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 1);
	TEST_EQ(vb2api_kernel_phase2(ctx), VB2_REQUEST_REBOOT,
		"Normal mode with display request: rebooting");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_DISPLAY_REQUEST), 0,
		"  display request reset");

	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Developer mode");
	TEST_EQ(mock_ec_sync_called, 1, "  EC sync");

	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DIAGNOSTICS);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Diagnostics mode");
	TEST_EQ(mock_ec_sync_called, 1, "  EC sync");

	/* Commit data for recovery mode */
	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Manual recovery mode");
	TEST_EQ(mock_commit_data_called, 1, "  commit data");
	TEST_EQ(mock_ec_sync_called, 0, "  EC sync");

	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_BROKEN_SCREEN, 123);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Broken screen mode");
	TEST_EQ(mock_commit_data_called, 1, "  commit data");
	TEST_EQ(mock_ec_sync_called, 0, "  EC sync");

	/* Boot recovery - memory retraining */
	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_TRAIN_AND_REBOOT);
	TEST_EQ(vb2api_kernel_phase2(ctx), VB2_REQUEST_REBOOT,
		"Recovery train and reboot");

	/* Clear VB2_NV_DIAG_REQUEST */
	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Normal mode with DIAG_REQUEST");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST), 0,
		"  clear VB2_NV_DIAG_REQUEST");
	TEST_EQ(mock_commit_data_called, 1, "  commit data");

	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DIAGNOSTICS);
	vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
	TEST_SUCC(vb2api_kernel_phase2(ctx), "Diagnostics mode");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST), 0,
		"  clear VB2_NV_DIAG_REQUEST");
	TEST_EQ(mock_commit_data_called, 1, "  commit data");

	/* Battery cutoff called after EC sync */
	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	vb2_nv_set(ctx, VB2_NV_BATTERY_CUTOFF_REQUEST, 1);
	TEST_EQ(vb2api_kernel_phase2(ctx), VB2_REQUEST_SHUTDOWN,
		"Set VB2_NV_BATTERY_CUTOFF_REQUEST");
	TEST_EQ(mock_battery_cutoff_called, 1,
		"  battery_cutoff called after EC sync");

	/* Return EC sync error */
	reset_common_data(FOR_PHASE2);
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
	mock_ec_sync_retval = VB2_ERROR_MOCK;
	TEST_EQ(vb2api_kernel_phase2(ctx), VB2_ERROR_MOCK,
		"Return EC sync error");

	/* Undefined boot mode */
	reset_common_data(FOR_PHASE2);
	TEST_EQ(vb2api_kernel_phase2(ctx), VB2_ERROR_ESCAPE_NO_BOOT,
		"Undefined boot mode");
}

static void finalize_tests(void)
{
	/* Kernel version roll forward */
	reset_common_data(FOR_FINALIZE);
	sd->kernel_version_secdata = 0x20003;
	TEST_EQ(vb2api_kernel_finalize(ctx), VB2_SUCCESS,
		"Kernel version roll forward");
	TEST_EQ(mock_kernel_version_secdata, 0x20003, "  kernel version");

	reset_common_data(FOR_FINALIZE);
	vb2_nv_set(ctx, VB2_NV_FW_RESULT, VB2_FW_RESULT_TRYING);
	sd->kernel_version_secdata = 0x20003;
	TEST_EQ(vb2api_kernel_finalize(ctx), VB2_SUCCESS,
		"Don't roll forward kernel when trying new FW");
	TEST_EQ(mock_kernel_version_secdata, 0x10002, "  kernel version");

	reset_common_data(FOR_FINALIZE);
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0x30005);
	sd->kernel_version_secdata = 0x40006;
	TEST_EQ(vb2api_kernel_finalize(ctx), VB2_SUCCESS,
		"Limit max roll forward");
	TEST_EQ(mock_kernel_version_secdata, 0x30005, "  kernel version");

	reset_common_data(FOR_FINALIZE);
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0x10001);
	sd->kernel_version_secdata = 0x40006;
	TEST_EQ(vb2api_kernel_finalize(ctx), VB2_SUCCESS,
		"Max roll forward can't rollback");
	TEST_EQ(mock_kernel_version_secdata, 0x10002, "  kernel version");

	/* NO_BOOT with EC sync support */
	reset_common_data(FOR_FINALIZE);
	ctx->flags |= VB2_CONTEXT_NO_BOOT;
	ctx->flags |= VB2_CONTEXT_EC_SYNC_SUPPORTED;
	TEST_EQ(vb2api_kernel_finalize(ctx), VB2_ERROR_ESCAPE_NO_BOOT,
		"Recovery for NO_BOOT escape");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_ESCAPE_NO_BOOT, "  recovery_reason");

	/* NO_BOOT with EC sync disabled */
	reset_common_data(FOR_FINALIZE);
	ctx->flags |= VB2_CONTEXT_NO_BOOT;
	ctx->flags |= VB2_CONTEXT_EC_SYNC_SUPPORTED;
	mock_gbb.h.flags |= VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC;
	TEST_SUCC(vb2api_kernel_finalize(ctx),
		  "NO_BOOT ignored with gbb DISABLE_EC_SOFTWARE_SYNC");

	/* Normal case with EC sync support */
	reset_common_data(FOR_FINALIZE);
	ctx->flags |= VB2_CONTEXT_EC_SYNC_SUPPORTED;
	TEST_SUCC(vb2api_kernel_finalize(ctx), "Disable VB2_CONTEXT_NO_BOOT");

	/* NO_BOOT without EC sync support */
	reset_common_data(FOR_FINALIZE);
	ctx->flags |= VB2_CONTEXT_NO_BOOT;
	TEST_SUCC(vb2api_kernel_finalize(ctx),
		  "Disable VB2_CONTEXT_EC_SYNC_SUPPORTED");
}

int main(int argc, char* argv[])
{
	phase1_tests();
	phase2_tests();
	finalize_tests();

	return gTestSuccess ? 0 : 255;
}
