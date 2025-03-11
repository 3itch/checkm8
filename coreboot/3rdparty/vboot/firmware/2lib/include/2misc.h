/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Misc functions which need access to vb2_context but are not public APIs
 */

#ifndef VBOOT_REFERENCE_2MISC_H_
#define VBOOT_REFERENCE_2MISC_H_

#include "2api.h"
#include "2struct.h"

struct vb2_gbb_header;
struct vb2_workbuf;

#define vb2_container_of(ptr, type, member) ({                     \
	const typeof(((type *)0)->member) *__mptr = (ptr);         \
	(type *)((uint8_t *)__mptr - offsetof(type, member) );})   \

/**
 * Get the shared data pointer from the vboot context
 *
 * @param ctx		Vboot context
 * @return The shared data pointer.
 */
static inline struct vb2_shared_data *vb2_get_sd(struct vb2_context *ctx)
{
	return vb2_container_of(ctx, struct vb2_shared_data, ctx);
}

/**
 * Get the GBB header pointer from a vboot context's shared data
 *
 * @param ctx		Vboot context
 * @return The GBB header pointer.
 */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *ctx);

/**
 * Validate gbb signature (the magic number)
 *
 * @param sig		Pointer to the signature bytes to validate
 * @return VB2_SUCCESS if valid or non-zero if error.
 */
vb2_error_t vb2_validate_gbb_signature(uint8_t *sig);

/**
 * Initialize a work buffer from the vboot context.
 *
 * This sets the work buffer to the unused portion of the context work buffer.
 *
 * @param ctx		Vboot context
 * @param wb		Work buffer to initialize
 */
void vb2_workbuf_from_ctx(struct vb2_context *ctx, struct vb2_workbuf *wb);

/**
 * Set the amount of work buffer used in the vboot context.
 *
 * This will round up to VB2_WORKBUF_ALIGN, so that the next allocation will
 * be aligned as expected.
 *
 * @param ctx		Vboot context
 * @param used		Number of bytes used
 */
void vb2_set_workbuf_used(struct vb2_context *ctx, uint32_t used);

/**
 * Read the GBB header.
 *
 * @param ctx		Vboot context
 * @param gbb		Destination for header
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb2_read_gbb_header(struct vb2_context *ctx,
				struct vb2_gbb_header *gbb);

/**
 * Check for recovery reasons we can determine early in the boot process.
 *
 * On exit, check ctx->flags for VB2_CONTEXT_RECOVERY_MODE; if present, jump to
 * the recovery path instead of continuing with normal boot.  This is the only
 * direct path to recovery mode.  All other errors later in the boot process
 * should induce a reboot instead of jumping to recovery, so that recovery mode
 * starts from a consistent firmware state.
 *
 * @param ctx		Vboot context
 */
void vb2_check_recovery(struct vb2_context *ctx);

/**
 * Parse the GBB header.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_fw_init_gbb(struct vb2_context *ctx);

/**
 * Check developer switch position.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_check_dev_switch(struct vb2_context *ctx);

/**
 * Check if we need to clear the TPM owner.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_check_tpm_clear(struct vb2_context *ctx);

/**
 * Decide which firmware slot to try this boot.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_select_fw_slot(struct vb2_context *ctx);

/**
 * Verify the firmware keyblock using the root key.
 *
 * After this call, the data key is stored in the work buffer.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_load_fw_keyblock(struct vb2_context *ctx);

/**
 * Verify the firmware preamble using the data subkey from the keyblock.
 *
 * After this call, the preamble is stored in the work buffer.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_load_fw_preamble(struct vb2_context *ctx);

/**
 * Verify the kernel keyblock using the previously-loaded kernel key.
 *
 * After this call, the data key is stored in the work buffer.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_load_kernel_keyblock(struct vb2_context *ctx);

/**
 * Verify the kernel preamble using the data subkey from the keyblock.
 *
 * After this call, the preamble is stored in the work buffer.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2_load_kernel_preamble(struct vb2_context *ctx);

/**
 * Fill VB2_CONTEXT_DEV_BOOT_ALLOWED, VB2_CONTEXT_DEV_BOOT_EXTERNAL_ALLOWED and
 * VB2_CONTEXT_DEV_BOOT_ALTFW_ALLOWED flags in ctx->flags.
 *
 * @param ctx		Vboot context.
 */
void vb2_fill_dev_boot_flags(struct vb2_context *ctx);

/**
 * Determine and set a mutually exclusive boot mode in the vboot context.
 *
 * Determine the most relevant boot mode for current boot, store into
 * ctx->boot_mode, which is a ctx field introduced in struct version 3.1.
 *
 * This function should be only called by vb2api_fw_phase1.
 * The vb2api_fw_phase1 should call this function at its end phase once and all
 * the following steps should directly access ctx->boot_mode to retrieve the
 * most relevant boot mode.
 *
 * @param ctx		Vboot context.
 */
void vb2_set_boot_mode(struct vb2_context *ctx);

#endif  /* VBOOT_REFERENCE_2MISC_H_ */
