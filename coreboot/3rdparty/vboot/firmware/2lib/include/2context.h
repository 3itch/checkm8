/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Definition of the vb2_context structure and related constants.
 */

#ifndef VBOOT_REFERENCE_2CONTEXT_H_
#define VBOOT_REFERENCE_2CONTEXT_H_

#include "2constants.h"

/* Flags for vb2_context.
 *
 * Unless otherwise noted, flags are set by verified boot and may be read (but
 * not set or cleared) by the caller.
 */
enum vb2_context_flags {

	/*
	 * Verified boot has changed nvdata[].  Caller must save nvdata[] back
	 * to its underlying storage, then may clear this flag.
	 */
	VB2_CONTEXT_NVDATA_CHANGED = (1 << 0),

	/*
	 * Verified boot has changed secdata_firmware[].  Caller must save
	 * secdata_firmware[] back to its underlying storage, then may clear
	 * this flag.
	 */
	VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED = (1 << 1),

	/* Recovery mode is requested this boot */
	VB2_CONTEXT_RECOVERY_MODE = (1 << 2),

	/* Developer mode is requested this boot */
	VB2_CONTEXT_DEVELOPER_MODE = (1 << 3),

	/*
	 * Force recovery mode due to physical user request.  Caller may set
	 * this flag when initializing the context.
	 */
	VB2_CONTEXT_FORCE_RECOVERY_MODE = (1 << 4),

	/*
	 * Force developer mode enabled.  Caller may set this flag when
	 * initializing the context.  Previously used for forcing developer
	 * mode with physical dev switch.
	 *
	 * Deprecated as part of chromium:942901.
	 */
	VB2_CONTEXT_DEPRECATED_FORCE_DEVELOPER_MODE = (1 << 5),

	/* Using firmware slot B.  If this flag is clear, using slot A. */
	VB2_CONTEXT_FW_SLOT_B = (1 << 6),

	/* RAM should be cleared by caller this boot */
	VB2_CONTEXT_CLEAR_RAM = (1 << 7),

	/* Wipeout by the app should be requested. */
	VB2_CONTEXT_FORCE_WIPEOUT_MODE = (1 << 8),

	/* Erase developer mode state if it is enabled. */
	VB2_CONTEXT_DISABLE_DEVELOPER_MODE = (1 << 9),

	/*
	 * Verified boot has changed secdata_kernel[].  Caller must save
	 * secdata_kernel[] back to its underlying storage, then may clear
	 * this flag.
	 */
	VB2_CONTEXT_SECDATA_KERNEL_CHANGED = (1 << 10),

	/*
	 * Allow kernel verification to roll forward the version in
	 * secdata_kernel[].  Caller may set this flag before calling
	 * vb2api_kernel_phase3().
	 */
	VB2_CONTEXT_ALLOW_KERNEL_ROLL_FORWARD = (1 << 11),

	/*
	 * Boot optimistically: don't touch failure counters.  Caller may set
	 * this flag when initializing the context.
	 */
	VB2_CONTEXT_NOFAIL_BOOT = (1 << 12),

	/*
	 * secdata is not ready this boot, but should be ready next boot.  It
	 * would like to reboot.  The decision whether to reboot or not must be
	 * deferred until vboot, because rebooting all the time before then
	 * could cause a device with malfunctioning secdata to get stuck in an
	 * unrecoverable crash loop.
	 */
	VB2_CONTEXT_SECDATA_WANTS_REBOOT = (1 << 13),

	/*
	 * Boot is S3->S0 resume, not S5->S0 normal boot.  Caller may set this
	 * flag when initializing the context.
	 */
	VB2_CONTEXT_S3_RESUME = (1 << 14),

	/*
	 * System supports EC software sync.  Caller may set this flag at any
	 * time before calling vb2api_kernel_phase2().
	 */
	VB2_CONTEXT_EC_SYNC_SUPPORTED = (1 << 15),

	/*
	 * EC software sync is slow to update; warning screen should be
	 * displayed.  Caller may set this flag at any time before calling
	 * vb2api_kernel_phase2().
	 */
	VB2_CONTEXT_EC_SYNC_SLOW = (1 << 16),

	/*
	 * EC firmware supports early firmware selection; two EC images exist,
	 * and EC may have already verified and jumped to EC-RW prior to EC
	 * software sync.  Deprecated as part of chromium:1038259.
	 */
	VB2_CONTEXT_DEPRECATED_EC_EFS = (1 << 17),

	/*
	 * NV storage uses data format V2.  Data is size VB2_NVDATA_SIZE_V2,
	 * not VB2_NVDATA_SIZE.
	 *
	 * Caller must set this flag when initializing the context to use V2.
	 * (Vboot cannot infer the data size from the data itself, because the
	 * data provided by the caller could be uninitialized.)
	 */
	VB2_CONTEXT_NVDATA_V2 = (1 << 18),

	/*
	 * Allow vendor data to be set via the vendor data ui.
	 *
	 * Deprecated with CL:2512740.
	 */
	VB2_CONTEXT_DEPRECATED_VENDOR_DATA_SETTABLE = (1 << 19),

	/*
	 * Caller may set this before running vb2api_fw_phase1.  In this case,
	 * it means: "Display is available on this boot.  Please advertise
	 * as such to downstream vboot code and users."
	 *
	 * vboot may also set this before returning from vb2api_fw_phase1.
	 * In this case, it means: "Please initialize display so that it is
	 * available to downstream vboot code and users."  This is used when
	 * vboot encounters some internally-generated request for display
	 * support.
	 */
	VB2_CONTEXT_DISPLAY_INIT = (1 << 20),

	/*
	 * Caller may set this before running vb2api_kernel_phase1.  It means
	 * that there is no FWMP on this system, and thus default values should
	 * be used instead.
	 *
	 * Caller should *not* set this when FWMP is available but invalid.
	 */
	VB2_CONTEXT_NO_SECDATA_FWMP = (1 << 21),

	/*
	 * Enable detachable menu ui (volume up/down + power).
	 *
	 * Deprecated with CL:1975390.
	 */
	VB2_CONTEXT_DEPRECATED_DETACHABLE_UI = (1 << 22),

	/*
	 * NO_BOOT means the OS is not allowed to boot. Only relevant for EFS2.
	 */
	VB2_CONTEXT_NO_BOOT = (1 << 23),

	/*
	 * TRUSTED means EC is running an RO copy and PD isn't enabled. At
	 * least that was last known to the GSC. If EC RO is correctly behaving,
	 * it doesn't jump to RW when this flag is set.
	 */
	VB2_CONTEXT_EC_TRUSTED = (1 << 24),

	/*
	 * Boot into developer mode is allowed by FWMP or GBB flags.
	 */
	VB2_CONTEXT_DEV_BOOT_ALLOWED = (1 << 25),

	/*
	 * Boot into developer mode from external disk is allowed by nvdata,
	 * FWMP or GBB flags.
	 */
	VB2_CONTEXT_DEV_BOOT_EXTERNAL_ALLOWED = (1 << 26),

	/*
	 * Boot into developer mode from alternate bootloader is allowed by
	 * nvdata, FWMP or GBB flags.
	 */
	VB2_CONTEXT_DEV_BOOT_ALTFW_ALLOWED = (1 << 27),

	/*
	 * If this is set after kernel verification, caller should disable the
	 * TPM before jumping to kernel.
	 */
	VB2_CONTEXT_DISABLE_TPM = (1 << 28),

	/*
	 * Indicates there is only one RW slot present. Caller should set this
	 * flag when initializing the context if the flash layout does not
	 * support two RW slots.
	 */
	VB2_CONTEXT_SLOT_A_ONLY = (1 << 29),
};

/* Helper for aligning fields in vb2_context. */
#define VB2_PAD_STRUCT3(size, align, count) \
	uint8_t _pad##count[align - (((size - 1) % align) + 1)]
#define VB2_PAD_STRUCT2(size, align, count) VB2_PAD_STRUCT3(size, align, count)
#define VB2_PAD_STRUCT(size, align) VB2_PAD_STRUCT2(size, align, __COUNTER__)

/*
 * Context for firmware verification.  Pass this to all vboot APIs.
 *
 * Context is stored as part of vb2_shared_data, initialized with vb2api_init().
 * Subsequent retrieval of the context object should be done by calling
 * vb2api_reinit(), e.g. if switching firmware applications.
 *
 * The context struct can be seen as the "publicly accessible" portion of
 * vb2_shared_data, and thus does not require its own magic and version fields.
 */
struct vb2_context {

	/**********************************************************************
	 * Fields caller must initialize before calling any API functions.
	 */

	/*
	 * Flags; see vb2_context_flags.  Some flags may only be set by caller
	 * prior to calling vboot functions.
	 */
	uint64_t flags;

	/*
	 * Non-volatile data.  Caller must fill this from some non-volatile
	 * location before calling vb2api_fw_phase1.  If the
	 * VB2_CONTEXT_NVDATA_CHANGED flag is set when a vb2api function
	 * returns, caller must save the data back to the non-volatile location
	 * and then clear the flag.
	 */
	uint8_t nvdata[VB2_NVDATA_SIZE_V2];
	VB2_PAD_STRUCT(VB2_NVDATA_SIZE_V2, 8);

	/*
	 * Secure data for firmware verification stage.  Caller must fill this
	 * from some secure non-volatile location before calling
	 * vb2api_fw_phase1.  If the VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED flag
	 * is set when a function returns, caller must save the data back to the
	 * secure non-volatile location and then clear the flag.
	 */
	uint8_t secdata_firmware[VB2_SECDATA_FIRMWARE_SIZE];
	VB2_PAD_STRUCT(VB2_SECDATA_FIRMWARE_SIZE, 8);

	/**********************************************************************
	 * Fields caller must initialize before calling vb2api_kernel_phase1().
	 */

	/*
	 * Secure data for kernel verification stage.  Caller must fill this
	 * from some secure non-volatile location before calling
	 * vb2api_kernel_phase1.  If the VB2_CONTEXT_SECDATA_KERNEL_CHANGED
	 * flag is set when a function returns, caller must save the data back
	 * to the secure non-volatile location and then clear the flag.
	 */
	uint8_t secdata_kernel[VB2_SECDATA_KERNEL_MAX_SIZE];
	VB2_PAD_STRUCT(VB2_SECDATA_KERNEL_MAX_SIZE, 8);

	/*
	 * Firmware management parameters (FWMP) secure data.  Caller must fill
	 * this from some secure non-volatile location before calling
	 * vb2api_kernel_phase1.  Since FWMP is a variable-size space, caller
	 * should initially fill in VB2_SECDATA_FWMP_MIN_SIZE bytes, and call
	 * vb2_secdata_fwmp_check() to see whether more should be read.  If the
	 * VB2_CONTEXT_SECDATA_FWMP_CHANGED flag is set when a function
	 * returns, caller must save the data back to the secure non-volatile
	 * location and then clear the flag.
	 */
	uint8_t secdata_fwmp[VB2_SECDATA_FWMP_MAX_SIZE];
	VB2_PAD_STRUCT(VB2_SECDATA_FWMP_MAX_SIZE, 8);

	/**********************************************************************
	 * Fields below added in struct version 3.1.
	 */

	/*
	 * Mutually exclusive boot mode (from enum vb2_boot_mode).
	 * This constant is initialized after calling vb2api_fw_phase1().
	 */
	const uint8_t boot_mode;
};

#endif  /* VBOOT_REFERENCE_2CONTEXT_H_ */
