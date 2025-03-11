/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Externally-callable APIs
 * (Firmware portion)
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "2tpm_bootmode.h"

vb2_error_t vb2api_inject_kernel_subkey(
	struct vb2_context *ctx,
	const uint8_t *kernel_packed_key_data,
	uint32_t kernel_packed_key_data_size)
{
	struct vb2_shared_data *sd;
	enum vb2_boot_mode *boot_mode;
	struct vb2_workbuf wb;
	struct vb2_packed_key *kernel_packed_key;
	uint32_t kernel_packed_key_size;
	void *dst_packed_key;

	sd = vb2_get_sd(ctx);
	vb2_workbuf_from_ctx(ctx, &wb);

	/* Fully initialize the context and shared data. */
	sd->flags = 0;
	/* Not in recovery. */
	sd->recovery_reason = 0;
	/* FW not used. */
	sd->last_fw_slot = VB2_FW_SLOT_A;
	sd->last_fw_result = VB2_FW_RESULT_UNKNOWN;
	sd->fw_slot = VB2_FW_SLOT_A;
	sd->fw_version = 0;
	sd->fw_version_secdata = 0;
	/* Clear status field. */
	sd->status = 0;
	/* Invalid offset indicating GBB data is not available. */
	sd->gbb_offset = 0;
	sd->kernel_version = 0;
	sd->kernel_version_secdata = 0;
	ctx->flags = 0;
	boot_mode = (enum vb2_boot_mode *)&ctx->boot_mode;
	*boot_mode = VB2_BOOT_MODE_NORMAL;

	/* Make sure passed buffer is big enough for the packed key. */
	kernel_packed_key = (struct vb2_packed_key *)kernel_packed_key_data;
	VB2_TRY(vb2_verify_packed_key_inside(kernel_packed_key_data,
					     kernel_packed_key_data_size,
					     kernel_packed_key));

	/* Allocate space in the workbuf in which to copy the key. */
	kernel_packed_key_size =
		kernel_packed_key->key_offset + kernel_packed_key->key_size;
	dst_packed_key = vb2_workbuf_alloc(&wb, kernel_packed_key_size);
	if (!dst_packed_key)
		return VB2_ERROR_WORKBUF_SMALL;

	/* Copy the packed key data into the workbuf. */
	memcpy(dst_packed_key, kernel_packed_key_data, kernel_packed_key_size);

	/* Set the location of the kernel key data in the context. */
	sd->kernel_key_offset = vb2_offset_of(sd, dst_packed_key);
	sd->kernel_key_size = kernel_packed_key_size;

	vb2_set_workbuf_used(ctx,
			     sd->kernel_key_offset + kernel_packed_key_size);

	return VB2_SUCCESS;
}

vb2_error_t vb2api_fw_phase1(struct vb2_context *ctx)
{
	vb2_error_t rv;
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	/* Initialize NV context */
	vb2_nv_init(ctx);

	/*
	 * Handle caller-requested reboot due to secdata.  Do this before we
	 * even look at secdata.  If we fail because of a reboot loop we'll be
	 * the first failure so will get to set the recovery reason.
	 */
	if (!(ctx->flags & VB2_CONTEXT_SECDATA_WANTS_REBOOT)) {
		/* No reboot requested */
		vb2_nv_set(ctx, VB2_NV_TPM_REQUESTED_REBOOT, 0);
	} else if (vb2_nv_get(ctx, VB2_NV_TPM_REQUESTED_REBOOT)) {
		/*
		 * Reboot requested... again.  Fool me once, shame on you.
		 * Fool me twice, shame on me.  Fail into recovery to avoid
		 * a reboot loop.
		 */
		vb2api_fail(ctx, VB2_RECOVERY_RO_TPM_REBOOT, 0);
	} else {
		/* Reboot requested for the first time */
		vb2_nv_set(ctx, VB2_NV_TPM_REQUESTED_REBOOT, 1);
		return VB2_ERROR_API_PHASE1_SECDATA_REBOOT;
	}

	/* Initialize firmware & kernel secure data */
	rv = vb2_secdata_firmware_init(ctx);
	if (rv)
		vb2api_fail(ctx, VB2_RECOVERY_SECDATA_FIRMWARE_INIT, rv);

	rv = vb2_secdata_kernel_init(ctx);
	if (rv)
		vb2api_fail(ctx, VB2_RECOVERY_SECDATA_KERNEL_INIT, rv);

	/* Load and parse the GBB header */
	rv = vb2_fw_init_gbb(ctx);
	if (rv)
		vb2api_fail(ctx, VB2_RECOVERY_GBB_HEADER, rv);

	/* Check for dev switch */
	rv = vb2_check_dev_switch(ctx);
	if (rv)
		vb2api_fail(ctx, VB2_RECOVERY_DEV_SWITCH, rv);

	/*
	 * Check for recovery.  Note that this function returns void, since any
	 * errors result in requesting recovery.  That's also why we don't
	 * return error from failures in the preceding steps; those failures
	 * simply cause us to detect recovery mode here.
	 */
	vb2_check_recovery(ctx);

	/* Decide the boot mode */
	vb2_set_boot_mode(ctx);

	/*
	 * Initialize display if VB2_NV_DISPLAY_REQUEST is set or in non-normal
	 * boot mode.
	 */
	if (vb2_nv_get(ctx, VB2_NV_DISPLAY_REQUEST) ||
	    ctx->boot_mode != VB2_BOOT_MODE_NORMAL)
		ctx->flags |= VB2_CONTEXT_DISPLAY_INIT;

	/* Mark display as available for downstream vboot and vboot callers. */
	if (ctx->flags & VB2_CONTEXT_DISPLAY_INIT)
		sd->flags |= VB2_SD_FLAG_DISPLAY_AVAILABLE;

	/* Return error if recovery is needed */
	if (ctx->flags & VB2_CONTEXT_RECOVERY_MODE) {
		/* Always clear RAM when entering recovery mode */
		ctx->flags |= VB2_CONTEXT_CLEAR_RAM;
		return VB2_ERROR_API_PHASE1_RECOVERY;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb2api_fw_phase2(struct vb2_context *ctx)
{
	/*
	 * Use the slot from the last boot if this is a resume.  Do not set
	 * VB2_SD_STATUS_CHOSE_SLOT so the try counter is not decremented on
	 * failure as we are explicitly not attempting to boot from a new slot.
	 */
	if (ctx->flags & VB2_CONTEXT_S3_RESUME) {
		struct vb2_shared_data *sd = vb2_get_sd(ctx);

		/* Set the current slot to the last booted slot */
		sd->fw_slot = vb2_nv_get(ctx, VB2_NV_FW_TRIED);

		/* Set context flag if we're using slot B */
		if (sd->fw_slot)
			ctx->flags |= VB2_CONTEXT_FW_SLOT_B;

		return VB2_SUCCESS;
	}

	/* Always clear RAM when entering developer mode */
	if (ctx->flags & VB2_CONTEXT_DEVELOPER_MODE)
		ctx->flags |= VB2_CONTEXT_CLEAR_RAM;

	/* Check for explicit request to clear TPM */
	VB2_TRY(vb2_check_tpm_clear(ctx), ctx, VB2_RECOVERY_TPM_CLEAR_OWNER);

	/* Decide which firmware slot to try this boot */
	VB2_TRY(vb2_select_fw_slot(ctx), ctx, VB2_RECOVERY_FW_SLOT);

	return VB2_SUCCESS;
}

vb2_error_t vb2api_extend_hash(struct vb2_context *ctx,
		       const void *buf,
		       uint32_t size)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_digest_context *dc = (struct vb2_digest_context *)
		vb2_member_of(sd, sd->hash_offset);

	/* Must have initialized hash digest work area */
	if (!sd->hash_size)
		return VB2_ERROR_API_EXTEND_HASH_WORKBUF;

	/* Don't extend past the data we expect to hash */
	if (!size || size > sd->hash_remaining_size)
		return VB2_ERROR_API_EXTEND_HASH_SIZE;

	sd->hash_remaining_size -= size;

	return vb2_digest_extend(dc, buf, size);
}

vb2_error_t vb2api_get_pcr_digest(struct vb2_context *ctx,
			  enum vb2_pcr_digest which_digest,
			  uint8_t *dest,
			  uint32_t *dest_size)
{
	const uint8_t *digest;
	uint32_t digest_size;
	struct vb2_shared_data *sd;

	switch (which_digest) {
	case BOOT_MODE_PCR:
		digest = vb2_get_boot_state_digest(ctx);
		digest_size = VB2_SHA1_DIGEST_SIZE;
		break;
	case HWID_DIGEST_PCR:
		digest = vb2_get_gbb(ctx)->hwid_digest;
		digest_size = VB2_GBB_HWID_DIGEST_SIZE;
		break;
	case FIRMWARE_VERSION_PCR:
		sd = vb2_get_sd(ctx);
		digest = (uint8_t *)&sd->fw_version;
		digest_size = sizeof(sd->fw_version);
		break;
	case KERNEL_VERSION_PCR:
		sd = vb2_get_sd(ctx);
		digest = (uint8_t *)&sd->kernel_version;
		digest_size = sizeof(sd->kernel_version);
		break;
	default:
		return VB2_ERROR_API_PCR_DIGEST;
	}

	if (digest == NULL || *dest_size < digest_size)
		return VB2_ERROR_API_PCR_DIGEST_BUF;

	memcpy(dest, digest, digest_size);
	if (digest_size < *dest_size)
		memset(dest + digest_size, 0, *dest_size - digest_size);

	*dest_size = digest_size;

	return VB2_SUCCESS;
}

vb2_error_t vb2api_fw_phase3(struct vb2_context *ctx)
{
	/* Verify firmware keyblock */
	VB2_TRY(vb2_load_fw_keyblock(ctx), ctx, VB2_RECOVERY_RO_INVALID_RW);

	/* Verify firmware preamble */
	VB2_TRY(vb2_load_fw_preamble(ctx), ctx, VB2_RECOVERY_RO_INVALID_RW);

	return VB2_SUCCESS;
}

vb2_error_t vb2api_init_hash(struct vb2_context *ctx, uint32_t tag)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	const struct vb2_fw_preamble *pre;
	struct vb2_digest_context *dc;
	struct vb2_public_key key;
	struct vb2_workbuf wb;

	vb2_workbuf_from_ctx(ctx, &wb);

	if (tag == VB2_HASH_TAG_INVALID)
		return VB2_ERROR_API_INIT_HASH_TAG;

	/* Get preamble pointer */
	if (!sd->preamble_size)
		return VB2_ERROR_API_INIT_HASH_PREAMBLE;
	pre = (const struct vb2_fw_preamble *)
		vb2_member_of(sd, sd->preamble_offset);

	/* For now, we only support the firmware body tag */
	if (tag != VB2_HASH_TAG_FW_BODY)
		return VB2_ERROR_API_INIT_HASH_TAG;

	/* Allocate workbuf space for the hash */
	if (sd->hash_size) {
		dc = (struct vb2_digest_context *)
			vb2_member_of(sd, sd->hash_offset);
	} else {
		uint32_t dig_size = sizeof(*dc);

		dc = vb2_workbuf_alloc(&wb, dig_size);
		if (!dc)
			return VB2_ERROR_API_INIT_HASH_WORKBUF;

		sd->hash_offset = vb2_offset_of(sd, dc);
		sd->hash_size = dig_size;
		vb2_set_workbuf_used(ctx, sd->hash_offset + dig_size);
	}

	/*
	 * Work buffer now contains:
	 *   - vb2_shared_data
	 *   - packed firmware data key
	 *   - firmware preamble
	 *   - hash data
	 */

	/*
	 * Unpack the firmware data key to see which hashing algorithm we
	 * should use. Zero body data size means, that signature contains
	 * metadata hash, so vb2api_get_metadata_hash() should be used instead.
	 */
	if (!sd->data_key_size || !pre->body_signature.data_size)
		return VB2_ERROR_API_INIT_HASH_DATA_KEY;

	VB2_TRY(vb2_unpack_key_buffer(&key,
				      vb2_member_of(sd, sd->data_key_offset),
				      sd->data_key_size));

	sd->hash_tag = tag;
	sd->hash_remaining_size = pre->body_signature.data_size;

	return vb2_digest_init(dc, vb2api_hwcrypto_allowed(ctx),
			       key.hash_alg, pre->body_signature.data_size);
}

vb2_error_t vb2api_check_hash_get_digest(struct vb2_context *ctx,
					 void *digest_out,
					 uint32_t digest_out_size)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_digest_context *dc = (struct vb2_digest_context *)
		vb2_member_of(sd, sd->hash_offset);
	struct vb2_workbuf wb;

	uint8_t *digest;
	uint32_t digest_size = vb2_digest_size(dc->hash_alg);

	struct vb2_fw_preamble *pre;
	struct vb2_public_key key;

	vb2_workbuf_from_ctx(ctx, &wb);

	/* Get preamble pointer */
	if (!sd->preamble_size)
		return VB2_ERROR_API_CHECK_HASH_PREAMBLE;
	pre = vb2_member_of(sd, sd->preamble_offset);

	/* Must have initialized hash digest work area */
	if (!sd->hash_size)
		return VB2_ERROR_API_CHECK_HASH_WORKBUF;

	/* Should have hashed the right amount of data */
	if (sd->hash_remaining_size)
		return VB2_ERROR_API_CHECK_HASH_SIZE;

	/* Allocate the digest */
	digest = vb2_workbuf_alloc(&wb, digest_size);
	if (!digest)
		return VB2_ERROR_API_CHECK_HASH_WORKBUF_DIGEST;

	/* Finalize the digest */
	VB2_TRY(vb2_digest_finalize(dc, digest, digest_size));

	/* The code below is specific to the body signature */
	if (sd->hash_tag != VB2_HASH_TAG_FW_BODY)
		return VB2_ERROR_API_CHECK_HASH_TAG;

	/*
	 * In case of verifying a whole memory region the body signature
	 * is a *signature* of the body data, not just its hash.
	 * So we need to verify the signature.
	 */

	/* Unpack the data key */
	if (!sd->data_key_size)
		return VB2_ERROR_API_CHECK_HASH_DATA_KEY;

	VB2_TRY(vb2_unpack_key_buffer(&key,
				      vb2_member_of(sd, sd->data_key_offset),
				      sd->data_key_size));

	key.allow_hwcrypto = vb2api_hwcrypto_allowed(ctx);

	/*
	 * Check digest vs. signature.  Note that this destroys the signature.
	 * That's ok, because we only check each signature once per boot.
	 */
	VB2_TRY(vb2_verify_digest(&key, &pre->body_signature, digest, &wb),
		ctx, VB2_RECOVERY_FW_BODY);

	if (digest_out != NULL) {
		if (digest_out_size < digest_size)
			return VB2_ERROR_API_CHECK_DIGEST_SIZE;
		memcpy(digest_out, digest, digest_size);
	}

	return VB2_SUCCESS;
}

int vb2api_check_hash(struct vb2_context *ctx)
{
	return vb2api_check_hash_get_digest(ctx, NULL, 0);
}

union vb2_fw_boot_info vb2api_get_fw_boot_info(struct vb2_context *ctx)
{
	union vb2_fw_boot_info info;

	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	info.tries = vb2_nv_get(ctx, VB2_NV_TRY_COUNT);
	info.slot = sd->fw_slot;
	info.prev_slot = sd->last_fw_slot;
	info.prev_result = sd->last_fw_result;
	info.boot_mode = ctx->boot_mode;

	VB2_DEBUG("boot_mode=`%s`\n", vb2_boot_mode_string(info.boot_mode));

	if (ctx->flags & VB2_CONTEXT_RECOVERY_MODE) {
		info.recovery_reason = sd->recovery_reason;
		info.recovery_subcode = vb2_nv_get(ctx, VB2_NV_RECOVERY_SUBCODE);
		VB2_DEBUG("recovery_reason: %#x / %#x\n",
			  info.recovery_reason, info.recovery_subcode);
	}

	VB2_DEBUG("fw_tried=`%s` fw_try_count=%d "
		  "fw_prev_tried=`%s` fw_prev_result=`%s`.\n",
		  vb2_slot_string(info.slot), info.tries,
		  vb2_slot_string(info.prev_slot),
		  vb2_result_string(info.prev_result));

	return info;
}

vb2_error_t vb2api_get_metadata_hash(struct vb2_context *ctx,
				     struct vb2_hash **hash_ptr_out)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_workbuf wb;
	struct vb2_fw_preamble *pre;

	vb2_workbuf_from_ctx(ctx, &wb);

	if (!sd->preamble_size)
		return VB2_ERROR_API_CHECK_HASH_PREAMBLE;
	pre = vb2_member_of(sd, sd->preamble_offset);

	/* Zero size of body signature indicates, that signature holds
	   vb2_hash inside. */
	if (pre->body_signature.data_size)
		return VB2_ERROR_API_INIT_HASH_DATA_KEY;

	struct vb2_hash *hash =
		(struct vb2_hash *)vb2_signature_data(&pre->body_signature);
	const uint32_t hsize = vb2_digest_size(hash->algo);
	if (!hsize || pre->body_signature.sig_size <
			      offsetof(struct vb2_hash, raw) + hsize)
		return VB2_ERROR_API_CHECK_HASH_SIG_SIZE;

	*hash_ptr_out = hash;

	return VB2_SUCCESS;
}
