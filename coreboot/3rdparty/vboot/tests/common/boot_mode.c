/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Some helper function related to boot mode.
 */

#include "2api.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "common/boot_mode.h"
#include "common/tests.h"

void _set_boot_mode(struct vb2_context *ctx, enum vb2_boot_mode boot_mode,
		    uint32_t recovery_reason, ...)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	switch (boot_mode) {
	case VB2_BOOT_MODE_MANUAL_RECOVERY:
		TEST_NEQ(recovery_reason, 0,
			 "recovery_reason should be set in recovery mode");
		ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
		sd->recovery_reason = recovery_reason;
		ctx->flags |= VB2_CONTEXT_FORCE_RECOVERY_MODE;
		ctx->flags |= VB2_CONTEXT_EC_TRUSTED;
		break;
	case VB2_BOOT_MODE_BROKEN_SCREEN:
		TEST_NEQ(recovery_reason, 0,
			 "recovery_reason should be set in recovery mode");
		ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
		sd->recovery_reason = recovery_reason;
		break;
	case VB2_BOOT_MODE_DIAGNOSTICS:
		vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
		break;
	case VB2_BOOT_MODE_DEVELOPER:
		ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;
		break;
	case VB2_BOOT_MODE_NORMAL:
		break;
	default:
		TEST_TRUE(0, "SET_BOOT_MODE: Undefined boot mode");
		return;
	}
	vb2_set_boot_mode(ctx);
	TEST_EQ(ctx->boot_mode, boot_mode, "Validity check for set boot mode");
}
