/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Recovery reason string mapping.
 */

#include "2recovery_reasons.h"
#include "2sysincludes.h"

const char *vb2_get_recovery_reason_string(uint8_t code)
{
	switch ((enum vb2_nv_recovery)code) {
	/* 0x00 */ case VB2_RECOVERY_NOT_REQUESTED:
		return "Recovery not requested";
	/* 0x01 */ case VB2_RECOVERY_LEGACY:
		return "Recovery requested from legacy utility";
	/* 0x02 */ case VB2_RECOVERY_RO_MANUAL:
		return "Recovery button pressed";
	/* 0x03 */ case VB2_RECOVERY_RO_INVALID_RW:
		return "RW firmware failed signature check";
	/* 0x04 */ case VB2_RECOVERY_DEPRECATED_RO_S3_RESUME:
		return "S3 resume failed";
	/* 0x05 */ case VB2_RECOVERY_DEPRECATED_RO_TPM_ERROR:
		return "TPM error in read-only firmware";
	/* 0x06 */ case VB2_RECOVERY_RO_SHARED_DATA:
		return "Shared data error in read-only firmware";
	/* 0x07 */ case VB2_RECOVERY_DEPRECATED_RO_TEST_S3:
		return "Test error from S3Resume()";
	/* 0x08 */ case VB2_RECOVERY_DEPRECATED_RO_TEST_LFS:
		return "Test error from LoadFirmwareSetup()";
	/* 0x09 */ case VB2_RECOVERY_DEPRECATED_RO_TEST_LF:
		return "Test error from LoadFirmware()";
	/* 0x10 */ case VB2_RECOVERY_DEPRECATED_RW_NOT_DONE:
		return "RW firmware check not done";
	/* 0x11 */ case VB2_RECOVERY_DEPRECATED_RW_DEV_FLAG_MISMATCH:
		return "RW firmware developer flag mismatch";
	/* 0x12 */ case VB2_RECOVERY_DEPRECATED_RW_REC_FLAG_MISMATCH:
		return "RW firmware recovery flag mismatch";
	/* 0x13 */ case VB2_RECOVERY_FW_KEYBLOCK:
		return "RW firmware unable to verify keyblock";
	/* 0x14 */ case VB2_RECOVERY_FW_KEY_ROLLBACK:
		return "RW firmware key version rollback detected";
	/* 0x15 */ case VB2_RECOVERY_DEPRECATED_RW_DATA_KEY_PARSE:
		return "RW firmware unable to parse data key";
	/* 0x16 */ case VB2_RECOVERY_FW_PREAMBLE:
		return "RW firmware unable to verify preamble";
	/* 0x17 */ case VB2_RECOVERY_FW_ROLLBACK:
		return "RW firmware version rollback detected";
	/* 0x18 */ case VB2_RECOVERY_DEPRECATED_FW_HEADER_VALID:
		return "RW firmware header is valid";
	/* 0x19 */ case VB2_RECOVERY_FW_GET_FW_BODY:
		return "RW firmware error when accessing firmware body";
	/* 0x1a */ case VB2_RECOVERY_DEPRECATED_FW_HASH_WRONG_SIZE:
		return "RW firmware hash is wrong size";
	/* 0x1b */ case VB2_RECOVERY_FW_BODY:
		return "RW firmware unable to verify firmware body";
	/* 0x1c */ case VB2_RECOVERY_DEPRECATED_FW_VALID:
		return "RW firmware is valid";
	/* 0x1d */ case VB2_RECOVERY_DEPRECATED_FW_NO_RO_NORMAL:
		return "RW firmware read-only normal path is not supported";
	/* 0x1e */ case VB2_RECOVERY_FW_VENDOR_BLOB:
		return "RW firmware vendor blob verification failure";
	/* 0x20 */ case VB2_RECOVERY_RO_FIRMWARE:
		return "Firmware problem outside of verified boot";
	/* 0x21 */ case VB2_RECOVERY_RO_TPM_REBOOT:
		return "TPM requires a system reboot (should be transient)";
	/* 0x22 */ case VB2_RECOVERY_EC_SOFTWARE_SYNC:
		return "EC software sync error";
	/* 0x23 */ case VB2_RECOVERY_EC_UNKNOWN_IMAGE:
		return "EC software sync unable to determine active EC image";
	/* 0x24 */ case VB2_RECOVERY_DEPRECATED_EC_HASH:
		return "EC software sync error obtaining EC image hash";
	/* 0x25 */ case VB2_RECOVERY_DEPRECATED_EC_EXPECTED_IMAGE:
		return "EC software sync error "
			"obtaining expected EC image from BIOS";
	/* 0x26 */ case VB2_RECOVERY_EC_UPDATE:
		return "EC software sync error updating EC";
	/* 0x27 */ case VB2_RECOVERY_EC_JUMP_RW:
		return "EC software sync unable to jump to EC-RW";
	/* 0x28 */ case VB2_RECOVERY_EC_PROTECT:
		return "EC software sync protection error";
	/* 0x29 */ case VB2_RECOVERY_EC_EXPECTED_HASH:
		return "EC software sync error "
			"obtaining expected EC hash from BIOS";
	/* 0x2a */ case VB2_RECOVERY_DEPRECATED_EC_HASH_MISMATCH:
		return "EC software sync error "
			"comparing expected EC hash and image";
	/* 0x2b */ case VB2_RECOVERY_SECDATA_FIRMWARE_INIT:
		return "Firmware secure NVRAM (TPM) initialization error";
	/* 0x2c */ case VB2_RECOVERY_GBB_HEADER:
		return "Error parsing GBB header";
	/* 0x2d */ case VB2_RECOVERY_TPM_CLEAR_OWNER:
		return "Error trying to clear TPM owner";
	/* 0x2e */ case VB2_RECOVERY_DEV_SWITCH:
		return "Error reading or updating developer switch";
	/* 0x2f */ case VB2_RECOVERY_FW_SLOT:
		return "Error selecting RW firmware slot";
	/* 0x30 */ case VB2_RECOVERY_AUXFW_UPDATE:
		return "Error updating auxiliary firmware";
	/* 0x31 */ case VB2_RECOVERY_INTEL_CSE_LITE_SKU:
		return "Intel CSE Lite SKU firmware failure";
	/* 0x3f */ case VB2_RECOVERY_RO_UNSPECIFIED:
		return "Unspecified/unknown error in RO firmware";
	/* 0x41 */ case VB2_RECOVERY_DEPRECATED_RW_DEV_SCREEN:
		return "User requested recovery from dev-mode warning screen";
	/* 0x42 */ case VB2_RECOVERY_DEPRECATED_RW_NO_OS:
		return "No OS kernel detected (or kernel rollback attempt?)";
	/* 0x43 */ case VB2_RECOVERY_RW_INVALID_OS:
		return "OS kernel or rootfs failed signature check";
	/* 0x44 */ case VB2_RECOVERY_DEPRECATED_RW_TPM_ERROR:
		return "TPM error in rewritable firmware";
	/* 0x45 */ case VB2_RECOVERY_DEPRECATED_RW_DEV_MISMATCH:
		return "RW firmware in dev mode, but dev switch is off";
	/* 0x46 */ case VB2_RECOVERY_RW_SHARED_DATA:
		return "Shared data error in rewritable firmware";
	/* 0x47 */ case VB2_RECOVERY_DEPRECATED_RW_TEST_LK:
		return "Test error from vb2api_load_kernel()";
	/* 0x48 */ case VB2_RECOVERY_DEPRECATED_RW_NO_DISK:
		return "No bootable storage device in system";
	/* 0x49 */ case VB2_RECOVERY_TPM_E_FAIL:
		return "TPM error that was not fixed by reboot";
	/* 0x50 */ case VB2_RECOVERY_RO_TPM_S_ERROR:
		return "TPM setup error in read-only firmware";
	/* 0x51 */ case VB2_RECOVERY_RO_TPM_W_ERROR:
		return "TPM write error in read-only firmware";
	/* 0x52 */ case VB2_RECOVERY_RO_TPM_L_ERROR:
		return "TPM lock error in read-only firmware";
	/* 0x53 */ case VB2_RECOVERY_RO_TPM_U_ERROR:
		return "TPM update error in read-only firmware";
	/* 0x54 */ case VB2_RECOVERY_RW_TPM_R_ERROR:
		return "TPM read error in rewritable firmware";
	/* 0x55 */ case VB2_RECOVERY_RW_TPM_W_ERROR:
		return "TPM write error in rewritable firmware";
	/* 0x56 */ case VB2_RECOVERY_RW_TPM_L_ERROR:
		return "TPM lock error in rewritable firmware";
	/* 0x57 */ case VB2_RECOVERY_EC_HASH_FAILED:
		return "EC software sync unable to get EC image hash";
	/* 0x58 */ case VB2_RECOVERY_EC_HASH_SIZE:
		return "EC software sync invalid image hash size";
	/* 0x59 */ case VB2_RECOVERY_LK_UNSPECIFIED:
		return "Unspecified error while trying to load kernel";
	/* 0x5a */ case VB2_RECOVERY_RW_NO_DISK:
		return "No bootable storage device in system";
	/* 0x5b */ case VB2_RECOVERY_RW_NO_KERNEL:
		return "No bootable kernel found on disk";
	/* 0x5c */ case VB2_RECOVERY_DEPRECATED_RW_BCB_ERROR:
		return "BCB partition error on disk";
	/* 0x5d */ case VB2_RECOVERY_SECDATA_KERNEL_INIT:
		return "Kernel secure NVRAM (TPM) initialization error";
	/* 0x5e */ case VB2_RECOVERY_DEPRECATED_FW_FASTBOOT:
		return "Fastboot-mode requested in firmware";
	/* 0x5f */ case VB2_RECOVERY_RO_TPM_REC_HASH_L_ERROR:
		return "Recovery hash space lock error in RO firmware";
	/* 0x60 */ case VB2_RECOVERY_TPM_DISABLE_FAILED:
		return "Failed to disable TPM before running untrusted code";
	/* 0x61 */ case VB2_RECOVERY_ALTFW_HASH_MISMATCH:
		return "Verification of alternate bootloader payload failed";
	/* 0x62 */ case VB2_RECOVERY_SECDATA_FWMP_INIT:
		return "FWMP secure NVRAM (TPM) initialization error";
	/* 0x63 */ case VB2_RECOVERY_GSC_BOOT_MODE:
		return "Failed to get boot mode from GSC";
	/* 0x64 */ case VB2_RECOVERY_ESCAPE_NO_BOOT:
		return "Attempt to escape from NO_BOOT mode was detected";
	/* 0x65 */ case VB2_RECOVERY_WIDEVINE_PREPARE:
		return "Failed to prepare widevine";
	/* 0x7f */ case VB2_RECOVERY_RW_UNSPECIFIED:
		return "Unspecified/unknown error in RW firmware";
	/* 0x81 */ case VB2_RECOVERY_DEPRECATED_KE_DM_VERITY:
		return "DM-verity error";
	/* 0xbf */ case VB2_RECOVERY_DEPRECATED_KE_UNSPECIFIED:
		return "Unspecified/unknown error in kernel";
	/* 0xc1 */ case VB2_RECOVERY_US_TEST:
		return "Recovery mode test from user-mode";
	/* 0xc2 */ case VB2_RECOVERY_DEPRECATED_BCB_USER_MODE:
		return "User-mode requested recovery via BCB";
	/* 0xc3 */ case VB2_RECOVERY_DEPRECATED_US_FASTBOOT:
		return "User-mode requested fastboot mode";
	/* 0xc4 */ case VB2_RECOVERY_TRAIN_AND_REBOOT:
		return "User-mode requested DRAM train and reboot";
	/* 0xff */ case VB2_RECOVERY_US_UNSPECIFIED:
		return "Unspecified/unknown error in user-mode";
	}
	return "Unknown error code";
}
