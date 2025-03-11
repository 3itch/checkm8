/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Misc functions which need access to vb2_context but are not public APIs
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2recovery_reasons.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sha.h"
#include "2struct.h"
#include "2sysincludes.h"
#include "vboot_api.h"
#include "vboot_struct.h"

vb2_error_t vb2_validate_gbb_signature(uint8_t *sig)
{
	static const uint8_t sig_xor[VB2_GBB_SIGNATURE_SIZE] =
			VB2_GBB_XOR_SIGNATURE;
	int i;
	for (i = 0; i < VB2_GBB_SIGNATURE_SIZE; i++) {
		if (sig[i] != (sig_xor[i] ^ VB2_GBB_XOR_CHARS[i]))
			return VB2_ERROR_GBB_MAGIC;
	}
	return VB2_SUCCESS;
}

test_mockable
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	if (sd->gbb_offset == 0)
		VB2_DIE("gbb_offset is not initialized\n");
	return (struct vb2_gbb_header *)((void *)sd + sd->gbb_offset);
}

uint32_t vb2api_get_firmware_size(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	if (!sd->preamble_size)
		VB2_DIE("Firmware preamble size is zero\n");

	const struct vb2_fw_preamble *pre = (const struct vb2_fw_preamble *)
		vb2_member_of(sd, sd->preamble_offset);

	if (!pre->body_signature.data_size)
		VB2_DIE("Firmware body data size in signature is zero\n");

	return pre->body_signature.data_size;
}

test_mockable
vb2_error_t vb2_read_gbb_header(struct vb2_context *ctx,
				struct vb2_gbb_header *gbb)
{
	/* Read the entire header */
	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_GBB, 0, gbb, sizeof(*gbb)));

	/* Make sure it's really a GBB */
	VB2_TRY(vb2_validate_gbb_signature(gbb->signature));

	/* Check for compatible version */
	if (gbb->major_version != VB2_GBB_MAJOR_VER)
		return VB2_ERROR_GBB_VERSION;

	/* Current code is not backwards-compatible to 1.1 headers or older */
	if (gbb->minor_version < VB2_GBB_MINOR_VER)
		return VB2_ERROR_GBB_TOO_OLD;

	/*
	 * Header size should be at least as big as we expect.  It could be
	 * bigger, if the header has grown.
	 */
	if (gbb->header_size < sizeof(*gbb))
		return VB2_ERROR_GBB_HEADER_SIZE;

	return VB2_SUCCESS;
}

static void fail_impl(struct vb2_context *ctx,
		      uint8_t reason, uint8_t subcode, bool previous_boot)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint32_t last_fw_slot, last_fw_result, fw_slot;

	/* If NV data hasn't been initialized, initialize it now */
	if (!(sd->status & VB2_SD_STATUS_NV_INIT))
		vb2_nv_init(ctx);

	/*
	 * Donot overwrite any existing failure with a new failure reported
	 * through vb2api_previous_boot_fail(). Existing failure might have
	 * been set through vb2api_fail() in the previous boot and the new
	 * failure can stand.
	 */
	if (previous_boot &&
	    vb2_nv_get(ctx, VB2_NV_FW_RESULT) == VB2_FW_RESULT_FAILURE)
		return;

	/* See if we were far enough in the boot process to choose a slot */
	if (previous_boot || (sd->status & VB2_SD_STATUS_CHOSE_SLOT)) {
		last_fw_slot = vb2_nv_get(ctx, VB2_NV_FW_PREV_TRIED);
		last_fw_result = vb2_nv_get(ctx, VB2_NV_FW_PREV_RESULT);
		fw_slot = vb2_nv_get(ctx, VB2_NV_FW_TRIED);

		/* Boot failed */
		vb2_nv_set(ctx, VB2_NV_FW_RESULT, VB2_FW_RESULT_FAILURE);

		/* Use up remaining tries */
		vb2_nv_set(ctx, VB2_NV_TRY_COUNT, 0);

		if (!(ctx->flags & VB2_CONTEXT_SLOT_A_ONLY)) {
			/*
			 * Try the other slot next time.  We'll alternate
			 * between slots, which may help if one or both slots
			 * is flaky.
			 */
			vb2_nv_set(ctx, VB2_NV_TRY_NEXT, 1 - fw_slot);

			/*
			 * If we didn't try the other slot last boot, or we
			 * tried it and it didn't fail, try it next boot.
			 */
			if (last_fw_slot != 1 - fw_slot ||
			    last_fw_result != VB2_FW_RESULT_FAILURE)
				return;
		}
	}

	/*
	 * If we're still here, we failed before choosing a slot, or both
	 * this slot and the other slot failed in successive boots.  So we
	 * need to go to recovery.
	 *
	 * Set a recovery reason and subcode only if they're not already set.
	 * If recovery is already requested, it's a more specific error code
	 * than later code is providing and we shouldn't overwrite it.
	 */
	VB2_DEBUG("Need recovery, reason: %#x / %#x\n", reason, subcode);
	if (!vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST)) {
		vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST, reason);
		vb2_nv_set(ctx, VB2_NV_RECOVERY_SUBCODE, subcode);
	}
}

test_mockable
void vb2api_fail(struct vb2_context *ctx, uint8_t reason, uint8_t subcode)
{
	fail_impl(ctx, reason, subcode, false);
}

test_mockable
void vb2api_previous_boot_fail(struct vb2_context *ctx,
			       uint8_t reason, uint8_t subcode)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	VB2_ASSERT(!(sd->status & VB2_SD_STATUS_NV_INIT) &&
		   !(sd->status & VB2_SD_STATUS_CHOSE_SLOT));

	fail_impl(ctx, reason, subcode, true);
}

void vb2_check_recovery(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint32_t reason = vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST);
	uint32_t subcode = vb2_nv_get(ctx, VB2_NV_RECOVERY_SUBCODE);

	VB2_DEBUG("Recovery reason from previous boot: %#x / %#x\n",
		  reason, subcode);

	/*
	 * Sets the current recovery request, unless there's already been a
	 * failure earlier in the boot process.
	 */
	if (!sd->recovery_reason)
		sd->recovery_reason = reason;

	if (ctx->flags & VB2_CONTEXT_FORCE_RECOVERY_MODE) {
		VB2_DEBUG("Recovery was requested manually\n");
		if (subcode && !sd->recovery_reason &&
		    subcode != VB2_RECOVERY_TRAIN_AND_REBOOT)
			/*
			 * Recovery was requested at 'broken' screen.
			 * Promote subcode to reason.
			 */
			sd->recovery_reason = subcode;
		else
			/* Recovery was forced. Override recovery reason */
			sd->recovery_reason = VB2_RECOVERY_RO_MANUAL;
	}

	/* If recovery reason is non-zero, tell caller we need recovery mode */
	if (sd->recovery_reason) {
		ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
		VB2_DEBUG("We have a recovery request: %#x / %#x\n",
			  sd->recovery_reason,
			  vb2_nv_get(ctx, VB2_NV_RECOVERY_SUBCODE));
	}

	sd->status |= VB2_SD_STATUS_RECOVERY_DECIDED;
}

test_mockable
vb2_error_t vb2_fw_init_gbb(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_gbb_header *gbb;
	struct vb2_workbuf wb;

	vb2_workbuf_from_ctx(ctx, &wb);

	/* Read GBB into next chunk of work buffer */
	gbb = vb2_workbuf_alloc(&wb, sizeof(*gbb));
	if (!gbb)
		return VB2_ERROR_GBB_WORKBUF;

	VB2_TRY(vb2_read_gbb_header(ctx, gbb));

	/* Keep on the work buffer permanently */
	sd->gbb_offset = vb2_offset_of(sd, gbb);
	vb2_set_workbuf_used(ctx, vb2_offset_of(sd, wb.buf));

	/* Set any context flags based on GBB flags */
	if (gbb->flags & VB2_GBB_FLAG_DISABLE_FWMP)
		ctx->flags |= VB2_CONTEXT_NO_SECDATA_FWMP;

	return VB2_SUCCESS;
}

test_mockable
vb2_error_t vb2_check_dev_switch(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	uint32_t flags = 0;
	uint32_t old_flags;
	int is_dev = 0;
	int valid_secdata = 1;
	vb2_error_t rv;

	/* Check whether secdata_firmware is initialized */
	if (!(sd->status & VB2_SD_STATUS_SECDATA_FIRMWARE_INIT))
		valid_secdata = 0;

	/* Read secure flags */
	flags = vb2_secdata_firmware_get(ctx, VB2_SECDATA_FIRMWARE_FLAGS);
	old_flags = flags;

	/* Handle dev disable request */
	if (valid_secdata && vb2_nv_get(ctx, VB2_NV_DISABLE_DEV_REQUEST)) {
		flags &= ~VB2_SECDATA_FIRMWARE_FLAG_DEV_MODE;

		/* Clear the request */
		vb2_nv_set(ctx, VB2_NV_DISABLE_DEV_REQUEST, 0);
	}

	/*
	 * Check if we've been asked by the caller to disable dev mode.  Note
	 * that GBB flag will take precedence over this.
	 */
	if (ctx->flags & VB2_CONTEXT_DISABLE_DEVELOPER_MODE)
		flags &= ~VB2_SECDATA_FIRMWARE_FLAG_DEV_MODE;

	/* Check virtual dev switch */
	if (flags & VB2_SECDATA_FIRMWARE_FLAG_DEV_MODE)
		is_dev = 1;

	/* Check if GBB is forcing dev mode */
	if (gbb->flags & VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON)
		is_dev = 1;

	/* Handle whichever mode we end up in */
	if (is_dev) {
		/* Developer mode */
		sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
		ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;

		flags |= VB2_SECDATA_FIRMWARE_FLAG_LAST_BOOT_DEVELOPER;
	} else {
		/* Normal mode */
		flags &= ~VB2_SECDATA_FIRMWARE_FLAG_LAST_BOOT_DEVELOPER;

		/*
		 * Disable dev_boot_* flags.  This ensures they will be
		 * initially disabled if the user later transitions back into
		 * developer mode.
		 */
		vb2_nv_set(ctx, VB2_NV_DEV_BOOT_EXTERNAL, 0);
		vb2_nv_set(ctx, VB2_NV_DEV_BOOT_ALTFW, 0);
		vb2_nv_set(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY, 0);
		vb2_nv_set(ctx, VB2_NV_DEV_DEFAULT_BOOT, 0);
	}

	if (ctx->flags & VB2_CONTEXT_FORCE_WIPEOUT_MODE)
		vb2_nv_set(ctx, VB2_NV_REQ_WIPEOUT, 1);

	if (flags != old_flags) {
		/*
		 * Just changed dev mode state.  Clear TPM owner.  This must be
		 * done here instead of simply passing a flag to
		 * vb2_check_tpm_clear(), because we don't want to update
		 * last_boot_developer and then fail to clear the TPM owner.
		 *
		 * Note that we do this even if secdata_firmware is having
		 * issues, since the TPM owner and secdata_firmware may be
		 * independent, and we want the owner to be cleared if *this
		 * boot* is different than the last one (perhaps due to GBB flag
		 * override).
		 */
		rv = vb2ex_tpm_clear_owner(ctx);
		/* Check for failure to clear owner */
		if (valid_secdata && rv) {
			/*
			 * Note that this truncates rv to 8 bit.  Which
			 * is not as useful as the full error code, but
			 * we don't have NVRAM space to store the full
			 * 32-bit code.
			 */
			vb2api_fail(ctx, VB2_RECOVERY_TPM_CLEAR_OWNER, rv);
			return rv;
		}

		/* Save new flags */
		vb2_secdata_firmware_set(ctx, VB2_SECDATA_FIRMWARE_FLAGS,
					 flags);
	}

	return VB2_SUCCESS;
}

test_mockable
vb2_error_t vb2_check_tpm_clear(struct vb2_context *ctx)
{
	vb2_error_t rv;

	/* Check if we've been asked to clear the owner */
	if (!vb2_nv_get(ctx, VB2_NV_CLEAR_TPM_OWNER_REQUEST))
		return VB2_SUCCESS;  /* No need to clear */

	/* Request applies one time only */
	vb2_nv_set(ctx, VB2_NV_CLEAR_TPM_OWNER_REQUEST, 0);

	/* Try clearing */
	rv = vb2ex_tpm_clear_owner(ctx);
	if (rv) {
		/*
		 * Note that this truncates rv to 8 bit.  Which is not as
		 * useful as the full error code, but we don't have NVRAM space
		 * to store the full 32-bit code.
		 */
		vb2api_fail(ctx, VB2_RECOVERY_TPM_CLEAR_OWNER, rv);
		return rv;
	}

	/* Clear successful */
	vb2_nv_set(ctx, VB2_NV_CLEAR_TPM_OWNER_DONE, 1);
	return VB2_SUCCESS;
}

test_mockable
vb2_error_t vb2_select_fw_slot(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint32_t tries;

	/* Get result of last boot */
	sd->last_fw_slot = vb2_nv_get(ctx, VB2_NV_FW_TRIED);
	sd->last_fw_result = vb2_nv_get(ctx, VB2_NV_FW_RESULT);

	/* Save to the previous result fields in NV storage */
	vb2_nv_set(ctx, VB2_NV_FW_PREV_TRIED, sd->last_fw_slot);
	vb2_nv_set(ctx, VB2_NV_FW_PREV_RESULT, sd->last_fw_result);

	/* Clear result, since we don't know what will happen this boot */
	vb2_nv_set(ctx, VB2_NV_FW_RESULT, VB2_FW_RESULT_UNKNOWN);

	/* If there is only one slot, next try should always be slot A */
	if (ctx->flags & VB2_CONTEXT_SLOT_A_ONLY)
		vb2_nv_set(ctx, VB2_NV_TRY_NEXT, 0);

	/* Get slot to try */
	sd->fw_slot = vb2_nv_get(ctx, VB2_NV_TRY_NEXT);

	/* Check try count */
	tries = vb2_nv_get(ctx, VB2_NV_TRY_COUNT);

	if (sd->last_fw_result == VB2_FW_RESULT_TRYING &&
	    sd->last_fw_slot == sd->fw_slot &&
	    tries == 0) {
		/*
		 * If there is only RW A slot available, we have no other slot
		 * to fall back to.
		 */
		if (ctx->flags & VB2_CONTEXT_SLOT_A_ONLY)
			return VB2_ERROR_API_NEXT_SLOT_UNAVAILABLE;
		/*
		 * We used up our last try on the previous boot, so fall back
		 * to the other slot this boot.
		 */
		sd->fw_slot = 1 - sd->fw_slot;
		vb2_nv_set(ctx, VB2_NV_TRY_NEXT, sd->fw_slot);
	}

	if (tries > 0) {
		/* Still trying this firmware */
		vb2_nv_set(ctx, VB2_NV_FW_RESULT, VB2_FW_RESULT_TRYING);

		/* Decrement non-zero try count, unless told not to */
		if (!(ctx->flags & VB2_CONTEXT_NOFAIL_BOOT))
			vb2_nv_set(ctx, VB2_NV_TRY_COUNT, tries - 1);
	}

	/* Store the slot we're trying */
	vb2_nv_set(ctx, VB2_NV_FW_TRIED, sd->fw_slot);

	/* Set context flag if we're using slot B */
	if (sd->fw_slot)
		ctx->flags |= VB2_CONTEXT_FW_SLOT_B;

	/* Set status flag */
	sd->status |= VB2_SD_STATUS_CHOSE_SLOT;

	return VB2_SUCCESS;
}

vb2_error_t vb2api_enable_developer_mode(struct vb2_context *ctx)
{
	if (ctx->boot_mode != VB2_BOOT_MODE_MANUAL_RECOVERY) {
		VB2_DEBUG("ERROR: Can only enable developer mode from manual "
			  "recovery mode\n");
		return VB2_ERROR_API_ENABLE_DEV_NOT_ALLOWED;
	}

	uint32_t flags;

	VB2_DEBUG("Enabling developer mode...\n");

	flags = vb2_secdata_firmware_get(ctx, VB2_SECDATA_FIRMWARE_FLAGS);
	flags |= VB2_SECDATA_FIRMWARE_FLAG_DEV_MODE;
	vb2_secdata_firmware_set(ctx, VB2_SECDATA_FIRMWARE_FLAGS, flags);

	VB2_DEBUG("Mode change will take effect on next reboot\n");

	return VB2_SUCCESS;
}

vb2_error_t vb2api_disable_developer_mode(struct vb2_context *ctx)
{
	if (vb2api_gbb_get_flags(ctx) & VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON) {
		VB2_DEBUG("ERROR: dev mode forced by GBB flag\n");
		return VB2_ERROR_API_DISABLE_DEV_NOT_ALLOWED;
	}

	VB2_DEBUG("Leaving dev mode\n");
	vb2_nv_set(ctx, VB2_NV_DISABLE_DEV_REQUEST, 1);
	return VB2_SUCCESS;
}

void vb2api_request_diagnostics(struct vb2_context *ctx) {
	vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
	VB2_DEBUG("Diagnostics requested\n");
}

void vb2api_clear_recovery(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint32_t reason = vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST);
	uint32_t subcode = vb2_nv_get(ctx, VB2_NV_RECOVERY_SUBCODE);

	if (reason || subcode)
		VB2_DEBUG("Clearing recovery request: %#x / %#x  %s\n",
			  reason, subcode,
			  vb2_get_recovery_reason_string(reason));

	/* Clear recovery request for both the manual recovery and the broken
	   screen. */
	vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST, VB2_RECOVERY_NOT_REQUESTED);
	vb2_nv_set(ctx, VB2_NV_RECOVERY_SUBCODE, 0);

	/* But stow recovery reason as subcode for the broken screen. */
	if (ctx->boot_mode == VB2_BOOT_MODE_BROKEN_SCREEN) {
		VB2_DEBUG("Stow recovery reason as subcode (%#x)\n",
			  sd->recovery_reason);
		vb2_nv_set(ctx, VB2_NV_RECOVERY_SUBCODE, sd->recovery_reason);
	}
}

test_mockable
int vb2api_need_reboot_for_display(struct vb2_context *ctx)
{
	if (!(vb2_get_sd(ctx)->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE)) {
		VB2_DEBUG("Need reboot to initialize display\n");
		vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 1);
		return 1;
	}
	return 0;
}

uint32_t vb2api_get_recovery_reason(struct vb2_context *ctx)
{
	return vb2_get_sd(ctx)->recovery_reason;
}

uint32_t vb2api_get_locale_id(struct vb2_context *ctx)
{
	return vb2_nv_get(ctx, VB2_NV_LOCALIZATION_INDEX);
}

void vb2api_set_locale_id(struct vb2_context *ctx, uint32_t locale_id)
{
	vb2_nv_set(ctx, VB2_NV_LOCALIZATION_INDEX, locale_id);
}

void vb2api_export_vbsd(struct vb2_context *ctx, void *dest)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbSharedDataHeader *vbsd = (void *)dest;

	/* Initialize with boilerplate fields. */
	memset(vbsd, 0, VB2_VBSD_SIZE);
	vbsd->magic = VB_SHARED_DATA_MAGIC;
	vbsd->struct_version = VB_SHARED_DATA_VERSION;
	vbsd->struct_size = VB2_VBSD_SIZE;
	vbsd->data_size = VB2_VBSD_SIZE;
	vbsd->data_used = VB2_VBSD_SIZE;
	vbsd->flags |= VBSD_BOOT_FIRMWARE_VBOOT2;

	/* Translate vboot2 flags and fields into vboot1. */
	if (ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED)
		vbsd->flags |= VBSD_EC_SOFTWARE_SYNC;
	if (ctx->flags & VB2_CONTEXT_NVDATA_V2)
		vbsd->flags |= VBSD_NVDATA_V2;
	if (ctx->flags & VB2_CONTEXT_DEVELOPER_MODE)
		vbsd->flags |= VBSD_BOOT_DEV_SWITCH_ON;
	if (ctx->flags & VB2_CONTEXT_FORCE_RECOVERY_MODE)
		vbsd->flags |= VBSD_BOOT_REC_SWITCH_ON;
	if (sd->flags & VB2_SD_FLAG_KERNEL_SIGNED)
		vbsd->flags |= VBSD_KERNEL_KEY_VERIFIED;

	vbsd->fw_version_tpm = sd->fw_version_secdata;
	vbsd->fw_version_act = sd->fw_version;
	vbsd->kernel_version_tpm = sd->kernel_version_secdata;
	vbsd->kernel_version_act = sd->kernel_version;

	vbsd->recovery_reason = sd->recovery_reason;
	if (sd->recovery_reason)
		vbsd->firmware_index = 0xff;
	else
		vbsd->firmware_index = sd->fw_slot;
}
_Static_assert(VB2_VBSD_SIZE == sizeof(VbSharedDataHeader),
	       "VB2_VBSD_SIZE incorrect");

test_mockable
int vb2api_diagnostic_ui_enabled(struct vb2_context *ctx)
{
	return !(vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS) &
		 VB2_SECDATA_KERNEL_FLAG_DIAGNOSTIC_UI_DISABLED);
}

enum vb2_dev_default_boot_target vb2api_get_dev_default_boot_target(
	struct vb2_context *ctx)
{
	if (vb2api_gbb_get_flags(ctx) & VB2_GBB_FLAG_DEFAULT_DEV_BOOT_ALTFW)
		return VB2_DEV_DEFAULT_BOOT_TARGET_ALTFW;

	switch (vb2_nv_get(ctx, VB2_NV_DEV_DEFAULT_BOOT)) {
		case VB2_DEV_DEFAULT_BOOT_TARGET_EXTERNAL:
			if (ctx->flags & VB2_CONTEXT_DEV_BOOT_EXTERNAL_ALLOWED)
				return VB2_DEV_DEFAULT_BOOT_TARGET_EXTERNAL;
			break;

		case VB2_DEV_DEFAULT_BOOT_TARGET_ALTFW:
			if (ctx->flags & VB2_CONTEXT_DEV_BOOT_ALTFW_ALLOWED)
				return VB2_DEV_DEFAULT_BOOT_TARGET_ALTFW;
			break;
	}

	return VB2_DEV_DEFAULT_BOOT_TARGET_INTERNAL;
}

void vb2_fill_dev_boot_flags(struct vb2_context *ctx)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);

	if (!vb2_secdata_fwmp_get_flag(ctx,
				       VB2_SECDATA_FWMP_DEV_DISABLE_BOOT) ||
	    (gbb->flags & VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON))
		ctx->flags |= VB2_CONTEXT_DEV_BOOT_ALLOWED;

	if (vb2_nv_get(ctx, VB2_NV_DEV_BOOT_EXTERNAL) ||
	    (gbb->flags & VB2_GBB_FLAG_FORCE_DEV_BOOT_USB) ||
	    vb2_secdata_fwmp_get_flag(ctx,
				      VB2_SECDATA_FWMP_DEV_ENABLE_EXTERNAL))
		ctx->flags |= VB2_CONTEXT_DEV_BOOT_EXTERNAL_ALLOWED;

	if (vb2_nv_get(ctx, VB2_NV_DEV_BOOT_ALTFW) ||
	    (gbb->flags & VB2_GBB_FLAG_FORCE_DEV_BOOT_ALTFW) ||
	    vb2_secdata_fwmp_get_flag(ctx, VB2_SECDATA_FWMP_DEV_ENABLE_ALTFW))
		ctx->flags |= VB2_CONTEXT_DEV_BOOT_ALTFW_ALLOWED;
}

int vb2api_use_short_dev_screen_delay(struct vb2_context *ctx)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	return gbb->flags & VB2_GBB_FLAG_DEV_SCREEN_SHORT_DELAY;
}

static void snprint_sha1_sum(struct vb2_context *ctx,
			     struct vb2_packed_key *key,
			     char *dest, size_t dest_size)
{
	uint8_t *buf = ((uint8_t *)key) + key->key_offset;
	uint64_t buflen = key->key_size;
	struct vb2_hash hash;
	int32_t used = 0;
	int i;

	vb2_hash_calculate(vb2api_hwcrypto_allowed(ctx), buf, buflen,
			   VB2_HASH_SHA1, &hash);
	for (i = 0; i < sizeof(hash.sha1); i++)
		if (used < dest_size)
			used += snprintf(dest + used, dest_size - used,
					 "%02x", hash.sha1[i]);
	dest[dest_size - 1] = '\0';
}

#define DEBUG_INFO_MAX_LENGTH 1024

#define DEBUG_INFO_APPEND(format, args...) do { \
	if (used < DEBUG_INFO_MAX_LENGTH) \
		used += snprintf(buf + used, DEBUG_INFO_MAX_LENGTH - used, \
				 format, ## args); \
} while (0)

char *vb2api_get_debug_info(struct vb2_context *ctx)
{
	char *buf;
	uint32_t used = 0;

	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_gbb_header *gbb = NULL;
	struct vb2_workbuf wb;
	char sha1sum[VB2_SHA1_DIGEST_SIZE * 2 + 1];

	vb2_error_t rv;
	uint32_t i;

	buf = malloc(DEBUG_INFO_MAX_LENGTH + 1);
	if (buf == NULL)
		return NULL;

	vb2_workbuf_from_ctx(ctx, &wb);

	if (sd->gbb_offset == 0) {
		DEBUG_INFO_APPEND("GBB: {INVALID}");
	} else {
		gbb = vb2_get_gbb(ctx);
	}

	/* Add hardware ID */
	if (gbb) {
		char hwid[VB2_GBB_HWID_MAX_SIZE];
		uint32_t size = sizeof(hwid);
		rv = vb2api_gbb_read_hwid(ctx, hwid, &size);
		if (rv)
			strcpy(hwid, "{INVALID}");
		DEBUG_INFO_APPEND("HWID: %s", hwid);
	}

	/* Add recovery reason and subcode */
	i = vb2_nv_get(ctx, VB2_NV_RECOVERY_SUBCODE);
	DEBUG_INFO_APPEND("\nrecovery_reason: %#.2x / %#.2x  %s",
			  sd->recovery_reason, i,
			  vb2_get_recovery_reason_string(sd->recovery_reason));

	/* Add vb2_context and vb2_shared_data flags */
	DEBUG_INFO_APPEND("\ncontext.flags: %#.16" PRIx64, ctx->flags);
	DEBUG_INFO_APPEND("\nshared_data.flags: %#.8x", sd->flags);
	DEBUG_INFO_APPEND("\nshared_data.status: %#.8x", sd->status);

	/* Add raw contents of nvdata */
	DEBUG_INFO_APPEND("\nnvdata:");
	if (vb2_nv_get_size(ctx) > 16)  /* Multi-line starts on next line */
		DEBUG_INFO_APPEND("\n  ");
	for (i = 0; i < vb2_nv_get_size(ctx); i++) {
		/* Split into 16-byte blocks */
		if (i > 0 && i % 16 == 0)
			DEBUG_INFO_APPEND("\n  ");
		DEBUG_INFO_APPEND(" %02x", ctx->nvdata[i]);
	}

	/* Add dev_boot_usb flag */
	i = vb2_nv_get(ctx, VB2_NV_DEV_BOOT_EXTERNAL);
	DEBUG_INFO_APPEND("\ndev_boot_usb: %d", i);

	/* Add dev_boot_altfw flag */
	i = vb2_nv_get(ctx, VB2_NV_DEV_BOOT_ALTFW);
	DEBUG_INFO_APPEND("\ndev_boot_altfw: %d", i);

	/* Add dev_default_boot flag */
	i = vb2_nv_get(ctx, VB2_NV_DEV_DEFAULT_BOOT);
	DEBUG_INFO_APPEND("\ndev_default_boot: %d", i);

	/* Add dev_boot_signed_only flag */
	i = vb2_nv_get(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY);
	DEBUG_INFO_APPEND("\ndev_boot_signed_only: %d", i);

	/* Add TPM versions */
	DEBUG_INFO_APPEND("\nTPM: fwver=%#.8x kernver=%#.8x",
			  sd->fw_version_secdata, sd->kernel_version_secdata);

	/* Add GBB flags */
	if (gbb) {
		DEBUG_INFO_APPEND("\ngbb.flags: %#.8x", gbb->flags);
	}

	/* Add sha1sum for Root & Recovery keys */
	if (gbb) {
		struct vb2_packed_key *key;
		struct vb2_workbuf wblocal = wb;
		rv = vb2_gbb_read_root_key(ctx, &key, NULL, &wblocal);
		if (rv == VB2_SUCCESS) {
			snprint_sha1_sum(ctx, key, sha1sum, sizeof(sha1sum));
			DEBUG_INFO_APPEND("\ngbb.rootkey: %s", sha1sum);
		}
	}

	if (gbb) {
		struct vb2_packed_key *key;
		struct vb2_workbuf wblocal = wb;
		rv = vb2_gbb_read_recovery_key(ctx, &key, NULL, &wblocal);
		if (rv == VB2_SUCCESS) {
			snprint_sha1_sum(ctx, key, sha1sum, sizeof(sha1sum));
			DEBUG_INFO_APPEND("\ngbb.recovery_key: %s", sha1sum);
		}
	}

	/* If we're in dev-mode, show the kernel subkey that we expect, too. */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE) &&
	    sd->kernel_key_offset) {
		struct vb2_packed_key *key =
			vb2_member_of(sd, sd->kernel_key_offset);
		snprint_sha1_sum(ctx, key, sha1sum, sizeof(sha1sum));
		DEBUG_INFO_APPEND("\nkernel_subkey: %s", sha1sum);
	}

	buf[DEBUG_INFO_MAX_LENGTH] = '\0';
	return buf;
}

void vb2_set_boot_mode(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	/* Cast boot mode to non-constant and assign */
	enum vb2_boot_mode *boot_mode = (enum vb2_boot_mode *)&ctx->boot_mode;
	*boot_mode = VB2_BOOT_MODE_NORMAL;

	/*
	 * The only way to pass this check and proceed to the recovery process
	 * is to physically request a recovery (a.k.a. manual recovery).  All
	 * other recovery requests including manual recovery requested by a
	 * (compromised) host will end up with 'broken' screen.
	 */
	if ((ctx->flags & VB2_CONTEXT_FORCE_RECOVERY_MODE) &&
	    !(ctx->flags & VB2_CONTEXT_NO_BOOT) &&
	    (ctx->flags & VB2_CONTEXT_EC_TRUSTED)) {
		*boot_mode = VB2_BOOT_MODE_MANUAL_RECOVERY;
	} else if (sd->recovery_reason) {
		vb2_gbb_flags_t gbb_flags = vb2api_gbb_get_flags(ctx);
		if (gbb_flags & VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY)
			*boot_mode = VB2_BOOT_MODE_MANUAL_RECOVERY;
		else
			*boot_mode = VB2_BOOT_MODE_BROKEN_SCREEN;
	} else if (vb2api_diagnostic_ui_enabled(ctx) &&
		   vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST)) {
		*boot_mode = VB2_BOOT_MODE_DIAGNOSTICS;
	} else if (ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) {
		*boot_mode = VB2_BOOT_MODE_DEVELOPER;
	}
}

test_mockable
bool vb2api_hwcrypto_allowed(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	/* disable hwcrypto in recovery mode */
	if (ctx->flags & VB2_CONTEXT_RECOVERY_MODE)
		return 0;

	/* disable hwcrypto if secdata isn't initialized */
	if (!(sd->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT))
		return 0;

	/* enable hwcrypto only if RW firmware set the flag */
	return vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_FLAGS) &
		VB2_SECDATA_KERNEL_FLAG_HWCRYPTO_ALLOWED;
}
