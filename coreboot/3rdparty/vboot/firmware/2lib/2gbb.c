/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * GBB accessor functions.
 */

#include "2common.h"
#include "2misc.h"

static vb2_error_t vb2_gbb_read_key(struct vb2_context *ctx, uint32_t offset,
				    uint32_t *size,
				    struct vb2_packed_key **keyp,
				    struct vb2_workbuf *wb)
{
	struct vb2_workbuf wblocal = *wb;

	/* Check offset and size. */
	if (offset < sizeof(struct vb2_gbb_header))
		return VB2_ERROR_GBB_INVALID;
	if (*size < sizeof(**keyp))
		return VB2_ERROR_GBB_INVALID;

	/* GBB header might be padded.  Retrieve the vb2_packed_key
	   header so we can find out what the real size is. */
	*keyp = vb2_workbuf_alloc(&wblocal, sizeof(**keyp));
	if (!*keyp)
		return VB2_ERROR_GBB_WORKBUF;
	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_GBB, offset, *keyp,
				    sizeof(**keyp)));

	VB2_TRY(vb2_verify_packed_key_inside(*keyp, *size, *keyp));

	/* Deal with a zero-size key (used in testing). */
	*size = (*keyp)->key_offset + (*keyp)->key_size;
	*size = VB2_MAX(*size, sizeof(**keyp));

	/* Now that we know the real size of the key, retrieve the key
	   data, and write it on the workbuf, directly after vb2_packed_key. */
	*keyp = vb2_workbuf_realloc(&wblocal, sizeof(**keyp), *size);
	if (!*keyp)
		return VB2_ERROR_GBB_WORKBUF;

	VB2_TRY(vb2ex_read_resource(ctx, VB2_RES_GBB,
				    offset + sizeof(**keyp),
				    (void *)*keyp + sizeof(**keyp),
				    *size - sizeof(**keyp)));
	*wb = wblocal;
	return VB2_SUCCESS;
}

test_mockable
vb2_error_t vb2_gbb_read_root_key(struct vb2_context *ctx,
				  struct vb2_packed_key **keyp, uint32_t *size,
				  struct vb2_workbuf *wb)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	uint32_t size_in = gbb->rootkey_size;
	vb2_error_t ret = vb2_gbb_read_key(ctx, gbb->rootkey_offset,
					   &size_in, keyp, wb);
	if (size)
		*size = size_in;
	return ret;
}

test_mockable
vb2_error_t vb2_gbb_read_recovery_key(struct vb2_context *ctx,
				      struct vb2_packed_key **keyp,
				      uint32_t *size, struct vb2_workbuf *wb)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	uint32_t size_in = gbb->recovery_key_size;
	vb2_error_t ret = vb2_gbb_read_key(ctx, gbb->recovery_key_offset,
					   &size_in, keyp, wb);
	if (size)
		*size = size_in;
	return ret;
}

vb2_error_t vb2api_gbb_read_hwid(struct vb2_context *ctx, char *hwid,
				 uint32_t *size)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	uint32_t i;
	vb2_error_t ret;

	if (gbb->hwid_size == 0) {
		VB2_DEBUG("invalid HWID size %d\n", gbb->hwid_size);
		return VB2_ERROR_GBB_INVALID;
	}

	*size = VB2_MIN(*size, VB2_GBB_HWID_MAX_SIZE);
	*size = VB2_MIN(*size, gbb->hwid_size);

	ret = vb2ex_read_resource(ctx, VB2_RES_GBB, gbb->hwid_offset,
				  hwid, *size);
	if (ret) {
		VB2_DEBUG("read resource failure: %d\n", ret);
		return ret;
	}

	/* Count HWID size, and ensure that it fits in the given buffer. */
	for (i = 0; i < *size; i++) {
		if (hwid[i] == '\0') {
			*size = i + 1;
			break;
		}
	}
	if (hwid[*size - 1] != '\0')
		return VB2_ERROR_INVALID_PARAMETER;

	return VB2_SUCCESS;
}

vb2_gbb_flags_t vb2api_gbb_get_flags(struct vb2_context *ctx)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	return gbb->flags;
}

vb2_error_t vb2_get_gbb_flag_description(enum vb2_gbb_flag flag,
					 const char **name,
					 const char **description)
{
	switch (flag) {
	case VB2_GBB_FLAG_DEV_SCREEN_SHORT_DELAY:
		*name = "VB2_GBB_FLAG_DEV_SCREEN_SHORT_DELAY";
		*description = "Reduce the dev screen delay to 2 sec from 30 sec.";
		break;
	case VB2_GBB_FLAG_LOAD_OPTION_ROMS:
		*name = "VB2_GBB_FLAG_LOAD_OPTION_ROMS";
		*description = "BIOS should load option ROMs from arbitrary PCI devices.";
		break;
	case VB2_GBB_FLAG_ENABLE_ALTERNATE_OS:
		*name = "VB2_GBB_FLAG_ENABLE_ALTERNATE_OS";
		*description = "Boot a non-ChromeOS kernel.";
		break;
	case VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON:
		*name = "VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON";
		*description = "Force dev switch on, regardless of physical/keyboard dev switch.";
		break;
	case VB2_GBB_FLAG_FORCE_DEV_BOOT_USB:
		*name = "VB2_GBB_FLAG_FORCE_DEV_BOOT_USB";
		*description = "Allow booting from external disk even if dev_boot_usb=0.";
		break;
	case VB2_GBB_FLAG_DISABLE_FW_ROLLBACK_CHECK:
		*name = "VB2_GBB_FLAG_DISABLE_FW_ROLLBACK_CHECK";
		*description = "Disable firmware rollback protection.";
		break;
	case VB2_GBB_FLAG_ENTER_TRIGGERS_TONORM:
		*name = "VB2_GBB_FLAG_ENTER_TRIGGERS_TONORM";
		*description = "Allow Enter key to trigger dev->tonorm screen transition.";
		break;
	case VB2_GBB_FLAG_FORCE_DEV_BOOT_ALTFW:
		*name = "VB2_GBB_FLAG_FORCE_DEV_BOOT_ALTFW";
		*description =
			"Allow booting Legacy OSes even if dev_boot_altfw=0.";
		break;
	case VB2_GBB_FLAG_DEPRECATED_RUNNING_FAFT:
		*name = "VB2_GBB_FLAG_DEPRECATED_RUNNING_FAFT";
		*description = "Deprecated, do not use.";
		break;
	case VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC:
		*name = "VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC";
		*description = "Disable EC software sync.";
		break;
	case VB2_GBB_FLAG_DEFAULT_DEV_BOOT_ALTFW:
		*name = "VB2_GBB_FLAG_DEFAULT_DEV_BOOT_ALTFW";
		*description = "Default to booting legacy OS when dev screen times out.";
		break;
	case VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC:
		*name = "VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC";
		*description =
			"Disable auxiliary firmware (auxfw) software sync.";
		break;
	case VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN:
		*name = "VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN";
		*description = "Disable shutdown on lid closed.";
		break;
	case VB2_GBB_FLAG_DEPRECATED_FORCE_DEV_BOOT_FASTBOOT_FULL_CAP:
		*name = "VB2_GBB_FLAG_DEPRECATED_FORCE_DEV_BOOT_FASTBOOT_FULL_CAP";
		*description = "Allow full fastboot capability in firmware even if dev_boot_fastboot_full_cap=0.";
		break;
	case VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY:
		*name = "VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY";
		*description = "Recovery mode always assumes manual recovery, even if EC_IN_RW=1.";
		break;
	case VB2_GBB_FLAG_DISABLE_FWMP:
		*name = "VB2_GBB_FLAG_DISABLE_FWMP";
		*description = "Disable FWMP.";
		break;
	case VB2_GBB_FLAG_ENABLE_UDC:
		*name = "VB2_GBB_FLAG_ENABLE_UDC";
		*description = "Enable USB Device Controller.";
		break;
	case VB2_GBB_FLAG_FORCE_CSE_SYNC:
		*name = "VB2_GBB_FLAG_FORCE_CSE_SYNC";
		*description = "Always sync CSE, even if it is same as CBFS CSE";
		break;
	default:
		*name = NULL;
		*description = NULL;
		return VB2_ERROR_UNKNOWN;
	}
	return VB2_SUCCESS;
}
