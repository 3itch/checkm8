/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Flags for vb2_gbb_header.flags.
 *
 * Should be imported externally via vb2_api.h.
 */

#ifndef VBOOT_REFERENCE_2GBB_FLAGS_H_
#define VBOOT_REFERENCE_2GBB_FLAGS_H_

#include "2return_codes.h"

enum vb2_gbb_flag {
	/*
	 * Reduce the dev screen delay to 2 sec from 30 sec to speed up
	 * factory.
	 */
	VB2_GBB_FLAG_DEV_SCREEN_SHORT_DELAY = 1 << 0,

	/*
	 * BIOS should load option ROMs from arbitrary PCI devices. We'll never
	 * enable this ourselves because it executes non-verified code, but if
	 * a customer wants to void their warranty and set this flag in the
	 * read-only flash, they should be able to do so.
	 *
	 * (TODO: Currently not supported. Mark as deprecated/unused?)
	 */
	VB2_GBB_FLAG_LOAD_OPTION_ROMS = 1 << 1,

	/*
	 * The factory flow may need the BIOS to boot a non-ChromeOS kernel if
	 * the dev-switch is on. This flag allows that.
	 *
	 * (TODO: Currently not supported. Mark as deprecated/unused?)
	 */
	VB2_GBB_FLAG_ENABLE_ALTERNATE_OS = 1 << 2,

	/*
	 * Force dev switch on, regardless of physical/keyboard dev switch
	 * position.
	 */
	VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON = 1 << 3,

	/*
	 * Allow booting from external disk in dev mode even if
	 * dev_boot_usb=0.
	 */
	VB2_GBB_FLAG_FORCE_DEV_BOOT_USB = 1 << 4,

	/* Disable firmware rollback protection. */
	VB2_GBB_FLAG_DISABLE_FW_ROLLBACK_CHECK = 1 << 5,

	/* Allow Enter key to trigger dev->tonorm screen transition */
	VB2_GBB_FLAG_ENTER_TRIGGERS_TONORM = 1 << 6,

	/* Allow booting Legacy OSes in dev mode even if dev_boot_altfw=0. */
	VB2_GBB_FLAG_FORCE_DEV_BOOT_ALTFW = 1 << 7,

	/*
	 * This flag must never be used by anyone for any reason. It was created to
	 * disable certain debugging features in vendor provided blobs so that they
	 * could be used while running FAFT, but the flag has been misused elsewhere
	 * and is now deprecated.
	 * TODO: Remove VB2_GBB_FLAG_RUNNING_FAFT
	 */
	VB2_GBB_FLAG_DEPRECATED_RUNNING_FAFT = 1 << 8,
	VB2_GBB_FLAG_RUNNING_FAFT = 1 << 8,

	/* Disable EC software sync */
	VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC = 1 << 9,

	/* Default to booting legacy OS when dev screen times out */
	VB2_GBB_FLAG_DEFAULT_DEV_BOOT_ALTFW = 1 << 10,

	/* Disable auxiliary firmware (auxfw) software sync */
	VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC = 1 << 11,

	/* Disable shutdown on lid closed */
	VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN = 1 << 12,

	/*
	 * Allow full fastboot capability in firmware even if
	 * dev_boot_fastboot_full_cap=0.  Deprecated; see chromium:995172.
	 */
	VB2_GBB_FLAG_DEPRECATED_FORCE_DEV_BOOT_FASTBOOT_FULL_CAP = 1 << 13,

	/* Recovery mode always assumes manual recovery, even if EC_IN_RW=1 */
	VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY = 1 << 14,

	/* Disable FWMP */
	VB2_GBB_FLAG_DISABLE_FWMP = 1 << 15,

	/* Enable USB Device Controller */
	VB2_GBB_FLAG_ENABLE_UDC = 1 << 16,

	/* Enforce CSE SYNC, even if current CSE is same as CBFS CSE */
	VB2_GBB_FLAG_FORCE_CSE_SYNC = 1 << 17,
};

vb2_error_t vb2_get_gbb_flag_description(enum vb2_gbb_flag flag,
					 const char **name,
					 const char **description);

#endif  /* VBOOT_REFERENCE_2GBB_FLAGS_H_ */
