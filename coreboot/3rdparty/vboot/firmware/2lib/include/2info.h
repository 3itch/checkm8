/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Helper functions to retrieve vboot firmware information.
 */

#ifndef VBOOT_REFERENCE_2INFO_H_
#define VBOOT_REFERENCE_2INFO_H_

/* Boot mode decided in vb2api_fw_phase1.
 *
 * Boot mode is a constant set by verified boot and may be read (but should not
 * be set or cleared) by the caller.
 * The boot modes are mutually exclusive. If a boot fulfill more than one
 * constraints of the listing boot modes, it will be set to the most important
 * one. The priority is the same as the listing order.
 */
enum vb2_boot_mode {
	/* Undefined, The boot mode is not set. */
	VB2_BOOT_MODE_UNDEFINED = 0,

	/*
	 * Manual recovery boot, regardless of dev mode state.
	 *
	 * VB2_CONTEXT_RECOVERY_MODE is set and the recovery is physically
	 * requested (a.k.a. Manual recovery).  All other recovery requests
	 * including manual recovery requested by a (compromised) host will end
	 * up with a broken screen.
	 */
	VB2_BOOT_MODE_MANUAL_RECOVERY = 1,

	/*
	 * Broken screen.
	 *
	 * If a recovery boot is not a manual recovery (a.k.a. not requested
	 * physically), the recovery is not allowed and will end up with
	 * broken screen.
	 */
	VB2_BOOT_MODE_BROKEN_SCREEN = 2,

	/*
	 * Diagnostic boot.
	 *
	 * If diagnostic boot is enabled (a.k.a. vb2api_diagnostic_ui_enabled)
	 * and the nvdata contains VB2_NV_DIAG_REQUEST from previous boot, it
	 * will boot to diagnostic mode.
	 */
	VB2_BOOT_MODE_DIAGNOSTICS = 3,

	/*
	 * Developer boot: self-signed kernel okay.
	 *
	 * The developer mode switch is set (a.k.a. VB2_CONTEXT_DEVELOPER_MODE)
	 * and we are in the developer boot mode.
	 */
	VB2_BOOT_MODE_DEVELOPER = 4,

	/* Normal boot: kernel must be verified. */
	VB2_BOOT_MODE_NORMAL = 5,
};

/* Firmware slot codes */
enum vb2_fw_slot {
	/* Slot A */
	VB2_FW_SLOT_A = 0,

	/* Slot B */
	VB2_FW_SLOT_B = 1,
};

/* Firmware result codes for VB2_NV_FW_RESULT and VB2_NV_FW_PREV_RESULT */
enum vb2_fw_result {
	/* Unknown */
	VB2_FW_RESULT_UNKNOWN = 0,

	/* Trying a new slot, but haven't reached success/failure */
	VB2_FW_RESULT_TRYING = 1,

	/* Successfully booted to the OS */
	VB2_FW_RESULT_SUCCESS = 2,

	/* Known failure */
	VB2_FW_RESULT_FAILURE = 3,
};

/**
 * Convert Firmware Boot Mode into supported string
 *
 * @return char*   firmware boot mode string
 */
static inline const char *vb2_boot_mode_string(uint8_t boot_mode)
{
	switch ((enum vb2_boot_mode)boot_mode) {
	/* 0x00 */ case VB2_BOOT_MODE_UNDEFINED:
		return "Undefined";
	/* 0x01 */ case VB2_BOOT_MODE_MANUAL_RECOVERY:
		return "Manual recovery";
	/* 0x02 */ case VB2_BOOT_MODE_BROKEN_SCREEN:
		return "Broken screen";
	/* 0x03 */ case VB2_BOOT_MODE_DIAGNOSTICS:
		return "Diagnostic";
	/* 0x04 */ case VB2_BOOT_MODE_DEVELOPER:
		return "Developer";
	/* 0x05 */ case VB2_BOOT_MODE_NORMAL:
		return "Secure";
	}

	return "Unknown";
}

/**
 * Convert Firmware Slot result into supported string
 *
 * @return char*   firmware slot result string
 */
static inline const char *vb2_result_string(uint8_t result)
{
	switch ((enum vb2_fw_result)result) {
	/* 0x00 */ case VB2_FW_RESULT_UNKNOWN:
		return "Unknown";
	/* 0x01 */ case VB2_FW_RESULT_TRYING:
		return "Trying";
	/* 0x02 */ case VB2_FW_RESULT_SUCCESS:
		return "Success";
	/* 0x03 */ case VB2_FW_RESULT_FAILURE:
		return "Failure";
	}

	return "Unknown";
}

/**
 * Convert Firmware Slot into supported string
 *
 * @return char*   firmware slot name string
 */
static inline const char *vb2_slot_string(uint8_t slot)
{
	if ((enum vb2_fw_slot)slot == VB2_FW_SLOT_A)
	/* 0x00 */ return "A";
	else
	/* 0x01 */ return "B";
}

#endif  /* VBOOT_REFERENCE_2INFO_H_ */
