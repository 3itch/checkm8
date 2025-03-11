/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Kernel verified boot functions
 */

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sha.h"
#include "2sysincludes.h"

/**
 * Returns non-zero if the kernel needs to have a valid signature, instead of
 * just a valid hash.
 */
static int vb2_need_signed_kernel(struct vb2_context *ctx)
{
	/* Recovery kernels are always signed */
	if (ctx->flags & VB2_CONTEXT_RECOVERY_MODE)
		return 1;

	/* Normal mode kernels are always signed */
	if (!(ctx->flags & VB2_CONTEXT_DEVELOPER_MODE))
		return 1;

	/* Developers may require signed kernels */
	if (vb2_nv_get(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY))
		return 1;

	return 0;
}

vb2_error_t vb2_load_kernel_keyblock(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_workbuf wb;

	uint8_t *key_data;
	uint32_t key_size;
	struct vb2_packed_key *packed_key;
	struct vb2_public_key kernel_key;

	struct vb2_keyblock *kb;
	uint32_t block_size;

	int rec_switch = (ctx->flags & VB2_CONTEXT_RECOVERY_MODE) != 0;
	int dev_switch = (ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) != 0;
	int need_keyblock_valid = vb2_need_signed_kernel(ctx);
	int keyblock_is_valid = 1;

	vb2_error_t rv;

	vb2_workbuf_from_ctx(ctx, &wb);

	/*
	 * Clear any previous keyblock-valid flag (for example, from a previous
	 * kernel where the keyblock was signed but the preamble failed
	 * verification).
	 */
	sd->flags &= ~VB2_SD_FLAG_KERNEL_SIGNED;

	/* Unpack the kernel key */
	key_data = vb2_member_of(sd, sd->kernel_key_offset);
	key_size = sd->kernel_key_size;
	VB2_TRY(vb2_unpack_key_buffer(&kernel_key, key_data, key_size));

	/* Load the kernel keyblock header after the root key */
	kb = vb2_workbuf_alloc(&wb, sizeof(*kb));
	if (!kb)
		return VB2_ERROR_KERNEL_KEYBLOCK_WORKBUF_HEADER;

	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_KERNEL_VBLOCK, 0, kb,
				    sizeof(*kb)));

	block_size = kb->keyblock_size;

	/*
	 * Load the entire keyblock, now that we know how big it is.  Note that
	 * we're loading the entire keyblock instead of just the piece after
	 * the header.  That means we re-read the header.  But that's a tiny
	 * amount of data, and it makes the code much more straightforward.
	 */
	kb = vb2_workbuf_realloc(&wb, sizeof(*kb), block_size);
	if (!kb)
		return VB2_ERROR_KERNEL_KEYBLOCK_WORKBUF;

	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_KERNEL_VBLOCK, 0, kb,
				    block_size));

	/* Verify the keyblock */
	rv = vb2_verify_keyblock(kb, block_size, &kernel_key, &wb);
	if (rv) {
		keyblock_is_valid = 0;
		if (need_keyblock_valid)
			return rv;

		/* Signature is invalid, but hash may be fine */
		VB2_TRY(vb2_verify_keyblock_hash(kb, block_size, &wb));
	}

	/* Check the keyblock flags against the current boot mode */
	if (!(kb->keyblock_flags &
	      (dev_switch ? VB2_KEYBLOCK_FLAG_DEVELOPER_1 :
	       VB2_KEYBLOCK_FLAG_DEVELOPER_0))) {
		VB2_DEBUG("Keyblock developer flag mismatch.\n");
		keyblock_is_valid = 0;
		if (need_keyblock_valid)
			return VB2_ERROR_KERNEL_KEYBLOCK_DEV_FLAG;
	}
	if (!(kb->keyblock_flags &
	      (rec_switch ? VB2_KEYBLOCK_FLAG_RECOVERY_1 :
	       VB2_KEYBLOCK_FLAG_RECOVERY_0))) {
		VB2_DEBUG("Keyblock recovery flag mismatch.\n");
		keyblock_is_valid = 0;
		if (need_keyblock_valid)
			return VB2_ERROR_KERNEL_KEYBLOCK_REC_FLAG;
	}

	/* Check for keyblock rollback if not in recovery mode */
	/* Key version is the upper 16 bits of the composite version */
	if (!rec_switch && kb->data_key.key_version > VB2_MAX_KEY_VERSION) {
		keyblock_is_valid = 0;
		if (need_keyblock_valid)
			return VB2_ERROR_KERNEL_KEYBLOCK_VERSION_RANGE;
	}
	if (!rec_switch && kb->data_key.key_version <
	    (sd->kernel_version_secdata >> 16)) {
		keyblock_is_valid = 0;
		if (need_keyblock_valid)
			return VB2_ERROR_KERNEL_KEYBLOCK_VERSION_ROLLBACK;
	}

	sd->kernel_version = kb->data_key.key_version << 16;

	/*
	 * At this point, we've checked everything.  The kernel keyblock is at
	 * least self-consistent, and has either a valid signature or a valid
	 * hash.  Track if it had a valid signature (that is, would we have
	 * been willing to boot it even if developer mode was off).
	 */
	if (keyblock_is_valid)
		sd->flags |= VB2_SD_FLAG_KERNEL_SIGNED;

	/* Preamble follows the keyblock in the vblock */
	sd->vblock_preamble_offset = kb->keyblock_size;

	/*
	 * Keep just the data key from the vblock.  This follows the kernel key
	 * (which we might still need to verify the next kernel, if the
	 * assoiciated kernel preamble and data don't verify).
	 */
	sd->data_key_offset = sd->workbuf_used;
	key_data = vb2_member_of(sd, sd->data_key_offset);
	packed_key = (struct vb2_packed_key *)key_data;
	memmove(packed_key, &kb->data_key, sizeof(*packed_key));
	packed_key->key_offset = sizeof(*packed_key);
	memmove(key_data + packed_key->key_offset,
		(uint8_t*)&kb->data_key + kb->data_key.key_offset,
		packed_key->key_size);

	/* Save the packed key size */
	sd->data_key_size =
		packed_key->key_offset + packed_key->key_size;

	/*
	 * Data key will persist in the workbuf after we return.
	 *
	 * Work buffer now contains:
	 *   - vb2_shared_data
	 *   - kernel key
	 *   - packed kernel data key
	 */
	vb2_set_workbuf_used(ctx, sd->data_key_offset + sd->data_key_size);

	return VB2_SUCCESS;
}

vb2_error_t vb2_load_kernel_preamble(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_workbuf wb;

	uint8_t *key_data = vb2_member_of(sd, sd->data_key_offset);
	uint32_t key_size = sd->data_key_size;
	struct vb2_public_key data_key;

	/* Preamble goes in the next unused chunk of work buffer */
	/* TODO: what's the minimum workbuf size?  Kernel preamble is usually
	 * padded to around 64KB. */
	struct vb2_kernel_preamble *pre;
	uint32_t pre_size;

	vb2_workbuf_from_ctx(ctx, &wb);

	/* Unpack the kernel data key */
	if (!sd->data_key_size)
		return VB2_ERROR_KERNEL_PREAMBLE2_DATA_KEY;

	VB2_TRY(vb2_unpack_key_buffer(&data_key, key_data, key_size));

	/* Load the kernel preamble header */
	pre = vb2_workbuf_alloc(&wb, sizeof(*pre));
	if (!pre)
		return VB2_ERROR_KERNEL_PREAMBLE2_WORKBUF_HEADER;

	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_KERNEL_VBLOCK,
				    sd->vblock_preamble_offset,
				    pre, sizeof(*pre)));

	pre_size = pre->preamble_size;

	/* Load the entire preamble, now that we know how big it is */
	pre = vb2_workbuf_realloc(&wb, sizeof(*pre), pre_size);
	if (!pre)
		return VB2_ERROR_KERNEL_PREAMBLE2_WORKBUF;

	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_KERNEL_VBLOCK,
				    sd->vblock_preamble_offset,
				    pre, pre_size));

	/*
	 * Work buffer now contains:
	 *   - vb2_shared_data
	 *   - kernel key
	 *   - packed kernel data key
	 *   - kernel preamble
	 */

	/* Verify the preamble */
	VB2_TRY(vb2_verify_kernel_preamble(pre, pre_size, &data_key, &wb));

	/*
	 * Kernel preamble version is the lower 16 bits of the composite kernel
	 * version.
	 */
	if (pre->kernel_version > VB2_MAX_PREAMBLE_VERSION)
		return VB2_ERROR_KERNEL_PREAMBLE_VERSION_RANGE;

	/* Combine with the key version from vb2_load_kernel_keyblock() */
	sd->kernel_version |= pre->kernel_version;

	if (vb2_need_signed_kernel(ctx) &&
	    sd->kernel_version < sd->kernel_version_secdata)
		return VB2_ERROR_KERNEL_PREAMBLE_VERSION_ROLLBACK;

	/* Keep track of where we put the preamble */
	sd->preamble_offset = vb2_offset_of(sd, pre);
	sd->preamble_size = pre_size;

	/*
	 * Preamble will persist in work buffer after we return.
	 *
	 * Work buffer now contains:
	 *   - vb2_shared_data
	 *   - vb2_gbb_header
	 *   - kernel key
	 *   - packed kernel data key
	 *   - kernel preamble
	 *
	 * TODO: we could move the preamble down over the kernel data key
	 * since we don't need it anymore.
	 */
	vb2_set_workbuf_used(ctx, sd->preamble_offset + pre_size);

	return VB2_SUCCESS;
}
