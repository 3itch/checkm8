/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Kernel selection, loading, verification, and booting.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"

int vb2api_is_developer_signed(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	if (!sd->kernel_key_offset || !sd->kernel_key_size) {
		VB2_DEBUG("ERROR: Cannot call this before kernel_phase1!\n");
		return 0;
	}

	struct vb2_public_key key;
	if (vb2_unpack_key(&key, vb2_member_of(sd, sd->kernel_key_offset)))
		return 0;

	/* This is a debugging aid, not a security-relevant feature. There's no
	   reason to hardcode the whole key or waste time computing a hash. Just
	   spot check the starting bytes of the pseudorandom part of the key. */
	uint32_t devkey_n0inv = ctx->flags & VB2_CONTEXT_RECOVERY_MODE ?
		0x18cebcf5 :	/*  recovery_key.vbpubk @0x24 */
		0xe0cd87d9;	/* kernel_subkey.vbpubk @0x24 */

	if (key.n0inv == devkey_n0inv)
		return 1;

	return 0;
}

test_mockable
vb2_error_t vb2api_kernel_phase1(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_workbuf wb;
	struct vb2_packed_key *packed_key;
	uint32_t flags;
	vb2_error_t rv;

	vb2_workbuf_from_ctx(ctx, &wb);

	/*
	 * Init secdata_fwmp spaces. No need to init secdata_firmware or
	 * secdata_kernel, since they were already read during firmware
	 * verification.  Ignore errors in recovery mode.
	 */
	rv = vb2_secdata_fwmp_init(ctx);
	if (rv && !(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		VB2_DEBUG("TPM: init secdata_fwmp returned %#x\n", rv);
		vb2api_fail(ctx, VB2_RECOVERY_SECDATA_FWMP_INIT, rv);
		return rv;
	}

	/* Initialize experimental feature flags while in normal RW path. */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		flags = vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS);
		flags &= ~VB2_SECDATA_KERNEL_FLAG_DIAGNOSTIC_UI_DISABLED;
		flags |= VB2_SECDATA_KERNEL_FLAG_HWCRYPTO_ALLOWED;
		vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_FLAGS, flags);
	}

	/* Read kernel version from secdata. */
	sd->kernel_version_secdata =
		vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);

	vb2_fill_dev_boot_flags(ctx);

	/* Find the key to use to verify the kernel keyblock */
	if ((ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		/* Load recovery key from GBB. */
		rv = vb2_gbb_read_recovery_key(ctx, &packed_key, NULL, &wb);
		if (rv) {
			if (ctx->boot_mode != VB2_BOOT_MODE_BROKEN_SCREEN)
				VB2_DIE("GBB read recovery key failed.\n");
			else
				/*
				 * If we're headed for the BROKEN screen,
				 * we won't need the recovery key.  Just
				 * short-circuit with success.
				 */
				return VB2_SUCCESS;
		}
	} else {
		/* Kernel subkey from firmware preamble */
		struct vb2_fw_preamble *pre;

		/* Make sure we have a firmware preamble loaded */
		if (!sd->preamble_size)
			return VB2_ERROR_API_KPHASE1_PREAMBLE;

		pre = (struct vb2_fw_preamble *)
			vb2_member_of(sd, sd->preamble_offset);
		packed_key = &pre->kernel_subkey;
	}

	sd->kernel_key_offset = vb2_offset_of(sd, packed_key);
	sd->kernel_key_size = packed_key->key_offset + packed_key->key_size;

	vb2_set_workbuf_used(ctx, vb2_offset_of(sd, wb.buf));

	if (vb2api_is_developer_signed(ctx))
		VB2_DEBUG("This is developer-signed firmware.\n");

	return VB2_SUCCESS;
}

static vb2_error_t handle_battery_cutoff(struct vb2_context *ctx)
{
	/*
	 * Check if we need to cut-off battery. This should be done after EC
	 * FW and auxfw are updated, and before the kernel is started.  This
	 * is to make sure all firmware is up-to-date before shipping (which
	 * is the typical use-case for cutoff).
	 */
	if (vb2_nv_get(ctx, VB2_NV_BATTERY_CUTOFF_REQUEST)) {
		VB2_DEBUG("Request to cut-off battery\n");
		vb2_nv_set(ctx, VB2_NV_BATTERY_CUTOFF_REQUEST, 0);

		/* May lose power immediately, so commit our update now. */
		VB2_TRY(vb2ex_commit_data(ctx));

		vb2ex_ec_battery_cutoff();
		return VB2_REQUEST_SHUTDOWN;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb2api_kernel_phase2(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	vb2_gbb_flags_t gbb_flags = vb2api_gbb_get_flags(ctx);

	VB2_DEBUG("GBB flags are %#x\n", gbb_flags);

	/*
	 * Do EC and auxfw software sync unless we're in recovery mode. This
	 * has UI but it's just a single non-interactive WAIT screen.
	 */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		VB2_TRY(vb2api_ec_sync(ctx));
		VB2_TRY(vb2api_auxfw_sync(ctx));
		VB2_TRY(handle_battery_cutoff(ctx));
	}

	/*
	 * If in the broken screen, save the recovery reason as subcode.
	 * Otherwise, clear any leftover recovery requests or subcodes.
	 */
	vb2api_clear_recovery(ctx);

	/*
	 * Clear the diagnostic request flag and commit nvdata to prevent
	 * booting back into diagnostic mode when a forced system reset occurs.
	 */
	if (vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST)) {
		vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 0);
		/*
		 * According to current FAFT design (firmware_MiniDiag), we
		 * need an AP reset after MiniDiag test items to preserve the
		 * CBMEM console logs. So we need to commit nvdata immediately
		 * to prevent booting back to VB2_BOOT_MODE_DIAGNOSTICS.
		 */
		vb2ex_commit_data(ctx);
	}

	/* Select boot path */
	switch (ctx->boot_mode) {
	case VB2_BOOT_MODE_MANUAL_RECOVERY:
	case VB2_BOOT_MODE_BROKEN_SCREEN:
		/* If we're in recovery mode just to do memory retraining, all
		   we need to do is reboot. */
		if (sd->recovery_reason == VB2_RECOVERY_TRAIN_AND_REBOOT) {
			VB2_DEBUG("Reboot after retraining in recovery\n");
			return VB2_REQUEST_REBOOT;
		}

		/*
		 * Need to commit nvdata changes immediately, since we will be
		 * entering either manual recovery UI or BROKEN screen shortly.
		 */
		vb2ex_commit_data(ctx);
		break;
	case VB2_BOOT_MODE_DIAGNOSTICS:
	case VB2_BOOT_MODE_DEVELOPER:
		break;
	case VB2_BOOT_MODE_NORMAL:
		if (vb2_nv_get(ctx, VB2_NV_DISPLAY_REQUEST)) {
			vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 0);
			VB2_DEBUG("Normal mode: "
				  "reboot to unset display request\n");
			return VB2_REQUEST_REBOOT;
		}
		break;
	default:
		return VB2_ERROR_ESCAPE_NO_BOOT;
	}

	return VB2_SUCCESS;
}

static void update_kernel_version(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint32_t max_rollforward =
		vb2_nv_get(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD);

	VB2_DEBUG("Checking if TPM kernel version needs advancing\n");

	/*
	 * Special case for when we're trying a slot with new firmware.
	 * Firmware updates also usually change the kernel key, which means
	 * that the new firmware can only boot a new kernel, and the old
	 * firmware in the previous slot can only boot the previous kernel.
	 *
	 * Don't roll-forward the kernel version, because we don't yet know if
	 * the new kernel will successfully boot.
	 */
	if (vb2_nv_get(ctx, VB2_NV_FW_RESULT) == VB2_FW_RESULT_TRYING) {
		VB2_DEBUG("Trying new FW; "
			  "skip kernel version roll-forward.\n");
		return;
	}

	/*
	 * Limit kernel version rollforward if needed.  Can't limit kernel
	 * version to less than the version currently in the TPM.  That is,
	 * we're limiting rollforward, not allowing rollback.
	 */
	uint32_t original_kernel_version =
		vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);

	if (max_rollforward < original_kernel_version)
		max_rollforward = original_kernel_version;

	if (sd->kernel_version_secdata > max_rollforward) {
		VB2_DEBUG("Limiting TPM kernel version roll-forward "
			  "to %#x < %#x\n",
			  max_rollforward, sd->kernel_version_secdata);

		sd->kernel_version_secdata = max_rollforward;
	}

	if (sd->kernel_version_secdata > original_kernel_version) {
		vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS,
				       sd->kernel_version_secdata);
	} else {
		sd->kernel_version_secdata = original_kernel_version;
	}
}

vb2_error_t vb2api_kernel_finalize(struct vb2_context *ctx)
{
	vb2_gbb_flags_t gbb_flags = vb2api_gbb_get_flags(ctx);

	/*
	 * Disallow booting to kernel when NO_BOOT flag is set, except when
	 * GBB flag disables software sync.
	 */
	if (!(gbb_flags & VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC)
	    && (ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED)
	    && (ctx->flags & VB2_CONTEXT_NO_BOOT)) {
		VB2_DEBUG("Blocking escape from NO_BOOT mode.\n");
		vb2api_fail(ctx, VB2_RECOVERY_ESCAPE_NO_BOOT, 0);
		return VB2_ERROR_ESCAPE_NO_BOOT;
	}

	if (ctx->boot_mode == VB2_BOOT_MODE_NORMAL)
		update_kernel_version(ctx);

	return VB2_SUCCESS;
}
