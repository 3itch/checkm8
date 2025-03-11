/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vb2_set_boot_mode.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "common/tests.h"

/* Mock data */

static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_gbb_header gbb;

static int mock_diagnostic_ui_enabled;

/* Mock functions */

struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

int vb2api_diagnostic_ui_enabled(struct vb2_context *c)
{
	return mock_diagnostic_ui_enabled;
}

static void reset_common_data(void)
{
	memset(workbuf, 0xaa, sizeof(workbuf));

	memset(&gbb, 0, sizeof(gbb));

	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");
	sd = vb2_get_sd(ctx);

	vb2_nv_init(ctx);

	mock_diagnostic_ui_enabled = 0;
}

static void set_boot_mode_tests(void)
{
	/* Normal boot */
	reset_common_data();
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_NORMAL, "Normal boot");

	/* Check that NV_DIAG_REQUEST triggers diagnostic mode */
	reset_common_data();
	mock_diagnostic_ui_enabled = 1;
	vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_DIAGNOSTICS,
		"Normal boot with diag UI enabled");

	reset_common_data();
	vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_NORMAL,
		"Normal boot with diag UI disabled");

	/* Developer boot */
	reset_common_data();
	ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;
	sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_DEVELOPER, "Dev boot");

	/* Recovery boot */
	reset_common_data();
	sd->recovery_reason = 123;
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_BROKEN_SCREEN, "Broken screen");

	reset_common_data();
	sd->recovery_reason = VB2_RECOVERY_RO_MANUAL;
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	gbb.flags |= VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY;
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_MANUAL_RECOVERY,
		"Manual recovery: forced by GBB flags");

	reset_common_data();
	sd->recovery_reason = VB2_RECOVERY_RO_MANUAL;
	ctx->flags |= VB2_CONTEXT_FORCE_RECOVERY_MODE;
	ctx->flags |= VB2_CONTEXT_EC_TRUSTED;
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, VB2_BOOT_MODE_MANUAL_RECOVERY,
		"Manual recovery: physical rec switch");

	reset_common_data();
	ctx->flags |= VB2_CONTEXT_EC_TRUSTED;
	vb2_set_boot_mode(ctx);
	TEST_NEQ(ctx->boot_mode, VB2_BOOT_MODE_MANUAL_RECOVERY,
		 "VB2_CONTEXT_FORCE_RECOVERY_MODE is not set");

	reset_common_data();
	ctx->flags |= VB2_CONTEXT_FORCE_RECOVERY_MODE;
	ctx->flags |= VB2_CONTEXT_NO_BOOT;
	ctx->flags |= VB2_CONTEXT_EC_TRUSTED;
	vb2_set_boot_mode(ctx);
	TEST_NEQ(ctx->boot_mode, VB2_BOOT_MODE_MANUAL_RECOVERY,
		 "Block manual recovery if NO_BOOT");

	reset_common_data();
	ctx->flags |= VB2_CONTEXT_FORCE_RECOVERY_MODE;
	vb2_set_boot_mode(ctx);
	TEST_NEQ(ctx->boot_mode, VB2_BOOT_MODE_MANUAL_RECOVERY,
		 "Block manual recovery for untrusted EC");
}

int main(void)
{
	set_boot_mode_tests();

	return gTestSuccess ? 0 : 255;
}
