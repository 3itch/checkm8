/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "2api.h"
#include "2common.h"
#include "2nvstorage.h"
#include "2sysincludes.h"
#include "chromeos_config.h"
#include "crossystem_arch.h"
#include "crossystem.h"
#include "crossystem_vbnv.h"
#include "host_common.h"
#include "flashrom.h"
#include "subprocess.h"
#include "vboot_struct.h"

/* Filename for crossystem lock */
#define CROSSYSTEM_LOCK_PATH (CROSSYSTEM_LOCK_DIR "/crossystem.lock")

/* Filename for kernel command line */
#define KERNEL_CMDLINE_PATH "/proc/cmdline"

/* Filename for the tpm_clear_request executable. */
#define TPM_CLEAR_REQUEST_EXEC_NAME "/usr/sbin/tpm_clear_request"

/* Fields that GetVdatString() can get */
typedef enum VdatStringField {
	VDAT_STRING_DEPRECATED_TIMERS = 0,  /* Timer values */
	VDAT_STRING_LOAD_FIRMWARE_DEBUG,  /* LoadFirmware() debug info */
	VDAT_STRING_DEPRECATED_LOAD_KERNEL_DEBUG,  /* vb2api_load_kernel()
						      debug info */
	VDAT_STRING_MAINFW_ACT  /* Active main firmware */
} VdatStringField;


/* Fields that GetVdatInt() can get */
typedef enum VdatIntField {
	VDAT_INT_FLAGS = 0,           /* Flags */
	VDAT_INT_HEADER_VERSION,      /* Header version for VbSharedData */
	VDAT_INT_DEVSW_BOOT,          /* Dev switch position at boot */
	VDAT_INT_RECSW_BOOT,          /* Recovery switch position at boot */
	VDAT_INT_HW_WPSW_BOOT,        /* Hardware WP switch position at boot */

	VDAT_INT_FW_VERSION_TPM,      /* Current firmware version in TPM */
	VDAT_INT_KERNEL_VERSION_TPM,  /* Current kernel version in TPM */
	VDAT_INT_KERNEL_KEY_VERIFIED, /* Kernel key verified using
				       * signature, not just hash */
	VDAT_INT_RECOVERY_REASON,     /* Recovery reason for current boot */
	VDAT_INT_FW_BOOT2,            /* Firmware selection by vboot2 */
	VDAT_INT_FW_VERSION_ACT,      /* Current active firmware version */
	VDAT_INT_KERNEL_VERSION_ACT,  /* Current active kernel version */
} VdatIntField;


/* Description of build options that may be specified on the
 * kernel command line. */
typedef enum VbBuildOption {
	VB_BUILD_OPTION_UNKNOWN,
	VB_BUILD_OPTION_DEBUG,
	VB_BUILD_OPTION_NODEBUG
} VbBuildOption;

static const char *fw_results[] = {"unknown", "trying", "success", "failure"};
static const char *default_boot[] = {"disk", "usb", "altfw"};

/* Masks for kern_nv usage by kernel. */
#define KERN_NV_FWUPDATE_TRIES_MASK 0x000F
#define KERN_NV_BLOCK_DEVMODE_FLAG  0x0010
#define KERN_NV_TPM_ATTACK_FLAG     0x0020
/* If you want to use the remaining currently-unused bits in kern_nv
 * for something kernel-y, define a new field (the way we did for
 * fwupdate_tries).  Don't just modify kern_nv directly, because that
 * makes it too easy to accidentally corrupt other sub-fields. */
#define KERN_NV_CURRENTLY_UNUSED    0xFFC0

/* Return true if the FWID starts with the specified string. */
int FwidStartsWith(const char *start)
{
	char fwid[VB_MAX_STRING_PROPERTY];
	if (VbGetSystemPropertyString("fwid", fwid, sizeof(fwid)) != 0)
		return 0;

	return 0 == strncmp(fwid, start, strlen(start));
}

/* Acquire the lock for crossystem SetSystemProperty call. */
static int AcquireCrossystemLock(void)
{
	int lock_fd;

	lock_fd = open(CROSSYSTEM_LOCK_PATH, O_RDWR | O_CREAT, 0600);
	if (lock_fd < 0)
		return -1;

	if (flock(lock_fd, LOCK_EX) < 0)
		return -1;

	return lock_fd;
}

/* Release the lock for crossystem SetSystemProperty call. */
static int ReleaseCrossystemLock(int lock_fd)
{
	if (flock(lock_fd, F_UNLCK) < 0)
		return -1;

	close(lock_fd);

	return 0;
}

/* Check if system FW type is equivalent to a given name */
static bool CheckFwType(const char *name)
{
	char fwtype_buf[VB_MAX_STRING_PROPERTY];
	int fwtype_ret;

	fwtype_ret = VbGetSystemPropertyString("mainfw_type",
		fwtype_buf, sizeof(fwtype_buf));

	if (fwtype_ret == 0 && !strcasecmp(fwtype_buf, name))
		return true;

	return false;
}

static struct vb2_context *get_fake_context(void)
{
	static uint8_t fake_workbuf[sizeof(struct vb2_shared_data) + 16]
		__attribute__((aligned(VB2_WORKBUF_ALIGN)));
	static struct vb2_context *fake_ctx;

	if (fake_ctx)
		return fake_ctx;

	vb2api_init(fake_workbuf, sizeof(fake_workbuf), &fake_ctx);

	return fake_ctx;
}

static int vnc_read;

int vb2_get_nv_storage(enum vb2_nv_param param)
{
	VbSharedDataHeader* sh = VbSharedDataRead();
	struct vb2_context *ctx = get_fake_context();

	if (!sh)
		return -1;

	/* TODO: locking around NV access */
	if (!vnc_read) {
		if (sh && sh->flags & VBSD_NVDATA_V2)
			ctx->flags |= VB2_CONTEXT_NVDATA_V2;
		if (0 != vb2_read_nv_storage(ctx)) {
			free(sh);
			return -1;
		}
		vb2_nv_init(ctx);

		/* TODO: If vnc.raw_changed, attempt to reopen NVRAM for write
		 * and save the new defaults.  If we're able to, log. */

		vnc_read = 1;
	}

	free(sh);
	return (int)vb2_nv_get(ctx, param);
}

int vb2_set_nv_storage(enum vb2_nv_param param, int value)
{
	VbSharedDataHeader* sh = VbSharedDataRead();
	struct vb2_context *ctx = get_fake_context();

	if (!sh)
		return -1;

	/* TODO: locking around NV access */
	if (sh && sh->flags & VBSD_NVDATA_V2)
		ctx->flags |= VB2_CONTEXT_NVDATA_V2;
	if (0 != vb2_read_nv_storage(ctx)) {
		free(sh);
		return -1;
	}
	vb2_nv_init(ctx);
	vb2_nv_set(ctx, param, (uint32_t)value);

	if (ctx->flags & VB2_CONTEXT_NVDATA_CHANGED) {
		vnc_read = 0;
		if (0 != vb2_write_nv_storage(ctx)) {
			free(sh);
			return -1;
		}
		ctx->flags &= ~VB2_CONTEXT_NVDATA_CHANGED;
	}

	/* Success */
	free(sh);
	return 0;
}

/*
 * Set a param value, and try to flag it for persistent backup.  It's okay if
 * backup isn't supported (which it isn't, in current designs). It's
 * best-effort only.
 */
static int vb2_set_nv_storage_with_backup(enum vb2_nv_param param, int value)
{
	int retval;
	retval = vb2_set_nv_storage(param, value);
	if (!retval)
		vb2_set_nv_storage(VB2_NV_BACKUP_NVRAM_REQUEST, 1);
	return retval;
}

/* Find what build/debug status is specified on the kernel command
 * line, if any. */
static VbBuildOption VbScanBuildOption(void)
{
	FILE* f = NULL;
	char buf[4096] = "";
	char *t, *saveptr;
	const char *delimiters = " \r\n";

	f = fopen(KERNEL_CMDLINE_PATH, "r");
	if (NULL != f) {
		if (NULL == fgets(buf, sizeof(buf), f))
			buf[0] = 0;
		fclose(f);
	}
	for (t = strtok_r(buf, delimiters, &saveptr); t;
	     t = strtok_r(NULL, delimiters, &saveptr)) {
		if (0 == strcmp(t, "cros_debug"))
			return VB_BUILD_OPTION_DEBUG;
		else if (0 == strcmp(t, "cros_nodebug"))
			return VB_BUILD_OPTION_NODEBUG;
	}

	return VB_BUILD_OPTION_UNKNOWN;
}

/* Determine whether the running OS image was built for debugging.
 * Returns 1 if yes, 0 if no or indeterminate. */
static vb2_error_t VbGetDebugBuild(void)
{
	return VB_BUILD_OPTION_DEBUG == VbScanBuildOption();
}

/* Determine whether OS-level debugging should be allowed.
 * Returns 1 if yes, 0 if no or indeterminate. */
static int VbGetCrosDebug(void)
{
	/* If the currently running system specifies its debug status, use
	 * that in preference to other indicators. */
	VbBuildOption option = VbScanBuildOption();
	if (VB_BUILD_OPTION_DEBUG == option) {
		return 1;
	} else if (VB_BUILD_OPTION_NODEBUG == option) {
		return 0;
	}

	/* Command line is silent; allow debug if this was a developer boot.
	 * NOTE: This should intentionally never be true in recovery mode,
	 * since the recovery initramfs is supposed to remain trusted even when
	 * the developer switch is on. */
	if (CheckFwType("developer"))
		return 1;

	/* All other cases disallow debug. */
	return 0;
}

static int GetVdatLoadFirmwareDebug(char *dest, int size,
				    const VbSharedDataHeader *sh)
{
	snprintf(dest, size,
		 "Check A result=%d\n"
		 "Check B result=%d\n"
		 "Firmware index booted=0x%02x\n"
		 "Active firmware version=0x%08x\n"
		 "Firmware version in TPM =0x%08x\n"
		 "Lowest combined version from firmware=0x%08x\n",
		 sh->check_fw_a_result,
		 sh->check_fw_b_result,
		 sh->firmware_index,
		 sh->fw_version_act,
		 sh->fw_version_tpm,
		 sh->fw_version_lowest);
	return 0;
}

static int GetVdatString(char *dest, int size, VdatStringField field)
{
	VbSharedDataHeader *sh = VbSharedDataRead();
	int value = 0;

	if (!sh)
		return -1;

	switch (field) {
		case VDAT_STRING_LOAD_FIRMWARE_DEBUG:
			value = GetVdatLoadFirmwareDebug(dest, size, sh);
			break;

		case VDAT_STRING_MAINFW_ACT:
			switch(sh->firmware_index) {
				case 0:
					StrCopy(dest, "A", size);
					break;
				case 1:
					StrCopy(dest, "B", size);
					break;
				case 0xFF:
					StrCopy(dest, "recovery", size);
					break;
				default:
					value = -1;
			}
			break;

		default:
			value = -1;
			break;
	}

	free(sh);
	return value;
}

static int FwidMajorVersion(void)
{
	char fwid[VB_MAX_STRING_PROPERTY];
	int version;

	if (VbGetSystemPropertyString("fwid", fwid, sizeof(fwid)) != 0)
		return -1;

	if (sscanf(fwid, "%*[^.].%d", &version) != 1 || version <= 0) {
		fprintf(stderr, "WARNING: Cannot parse major version from %s\n",
			fwid);
		return -1;
	}

	return version;
}

static int GetVdatInt(VdatIntField field)
{
	VbSharedDataHeader* sh = VbSharedDataRead();
	int value = -1;

	if (!sh)
		return -1;

	/* Fields supported in version 1 */
	switch (field) {
		case VDAT_INT_FLAGS:
			value = (int)sh->flags;
			break;
		case VDAT_INT_HEADER_VERSION:
			value = sh->struct_version;
			break;
		case VDAT_INT_KERNEL_KEY_VERIFIED:
			value = (sh->flags & VBSD_KERNEL_KEY_VERIFIED ? 1 : 0);
			break;
		case VDAT_INT_FW_VERSION_TPM:
			/* b/269204332#comment5: Before CL:2054270 and CL:2056343,
			   fw_version_tpm was always 0. */
			if (sh->struct_version <= 2 && FwidMajorVersion() < 12935)
				value = (int)sh->fw_version_act;
			else
				value = (int)sh->fw_version_tpm;
			break;
		case VDAT_INT_KERNEL_VERSION_TPM:
			value = (int)sh->kernel_version_tpm;
			break;
		case VDAT_INT_FW_BOOT2:
			value = (sh->flags & VBSD_BOOT_FIRMWARE_VBOOT2 ? 1 : 0);
			break;
		case VDAT_INT_FW_VERSION_ACT:
			value = (int)sh->fw_version_act;
			break;
		default:
			break;
	}

	/* Fields added in struct version 2 */
	if (sh->struct_version >= 2) {
		switch(field) {
			case VDAT_INT_DEVSW_BOOT:
				value = (sh->flags &
					 VBSD_BOOT_DEV_SWITCH_ON ? 1 : 0);
				break;
			case VDAT_INT_RECSW_BOOT:
				value = (sh->flags &
					 VBSD_BOOT_REC_SWITCH_ON ? 1 : 0);
				break;
			case VDAT_INT_HW_WPSW_BOOT:
				value = (sh->flags &
					 VBSD_BOOT_FIRMWARE_WP_ENABLED ? 1 : 0);
				break;
			case VDAT_INT_RECOVERY_REASON:
				value = sh->recovery_reason;
				break;
			default:
				break;
		}
	}

	/* Fields added in struct version 3 */
	if (sh->struct_version >= 3) {
		switch(field) {
			case VDAT_INT_KERNEL_VERSION_ACT:
				value = (int)sh->kernel_version_act;
				break;
			default:
				break;
		}
	}

	free(sh);
	return value;
}

/* Return version of VbSharedData struct or -1 if not found. */
int VbSharedDataVersion(void)
{
	return GetVdatInt(VDAT_INT_HEADER_VERSION);
}

int VbGetSystemPropertyInt(const char *name)
{
	int value = -1;

	/* Check architecture-dependent properties first */
	value = VbGetArchPropertyInt(name);
	if (-1 != value)
		return value;

	/* NV storage values */
	else if (!strcasecmp(name,"kern_nv")) {
		value = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
	} else if (!strcasecmp(name,"nvram_cleared")) {
		value = vb2_get_nv_storage(VB2_NV_KERNEL_SETTINGS_RESET);
	} else if (!strcasecmp(name,"recovery_request")) {
		value = vb2_get_nv_storage(VB2_NV_RECOVERY_REQUEST);
	} else if (!strcasecmp(name,"diagnostic_request")) {
		value = vb2_get_nv_storage(VB2_NV_DIAG_REQUEST);
	} else if (!strcasecmp(name,"dbg_reset")) {
		value = vb2_get_nv_storage(VB2_NV_DEBUG_RESET_MODE);
	} else if (!strcasecmp(name,"disable_dev_request")) {
		value = vb2_get_nv_storage(VB2_NV_DISABLE_DEV_REQUEST);
	} else if (!strcasecmp(name,"clear_tpm_owner_request")) {
		if (EXTERNAL_TPM_CLEAR_REQUEST && CheckFwType("nonchrome")) {
			const char *const argv[] = {
				TPM_CLEAR_REQUEST_EXEC_NAME,
				NULL,
			};
			value = subprocess_run(argv, &subprocess_null, &subprocess_null,
					       &subprocess_null);
		} else {
			value = vb2_get_nv_storage(VB2_NV_CLEAR_TPM_OWNER_REQUEST);
		}
	} else if (!strcasecmp(name,"clear_tpm_owner_done")) {
		value = vb2_get_nv_storage(VB2_NV_CLEAR_TPM_OWNER_DONE);
	} else if (!strcasecmp(name,"tpm_rebooted")) {
		value = vb2_get_nv_storage(VB2_NV_TPM_REQUESTED_REBOOT);
	} else if (!strcasecmp(name,"fw_try_count")) {
		value = vb2_get_nv_storage(VB2_NV_TRY_COUNT);
	} else if (!strcasecmp(name,"fw_vboot2")) {
		value = GetVdatInt(VDAT_INT_FW_BOOT2);
	} else if (!strcasecmp(name,"fwupdate_tries")) {
		value = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
		if (value != -1)
			value &= KERN_NV_FWUPDATE_TRIES_MASK;
	} else if (!strcasecmp(name,"block_devmode")) {
		value = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
		if (value != -1) {
			value &= KERN_NV_BLOCK_DEVMODE_FLAG;
			value = !!value;
		}
	} else if (!strcasecmp(name,"tpm_attack")) {
		value = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
		if (value != -1) {
			value &= KERN_NV_TPM_ATTACK_FLAG;
			value = !!value;
		}
	} else if (!strcasecmp(name,"loc_idx")) {
		value = vb2_get_nv_storage(VB2_NV_LOCALIZATION_INDEX);
	} else if (!strcasecmp(name,"backup_nvram_request")) {
		value = vb2_get_nv_storage(VB2_NV_BACKUP_NVRAM_REQUEST);
	} else if (!strcasecmp(name,"dev_boot_usb")) {
		value = vb2_get_nv_storage(VB2_NV_DEV_BOOT_EXTERNAL);
	} else if (!strcasecmp(name,"dev_boot_altfw") ||
		   !strcasecmp(name,"dev_boot_legacy")) {
		value = vb2_get_nv_storage(VB2_NV_DEV_BOOT_ALTFW);
	} else if (!strcasecmp(name,"dev_boot_signed_only")) {
		value = vb2_get_nv_storage(VB2_NV_DEV_BOOT_SIGNED_ONLY);
	} else if (!strcasecmp(name,"dev_enable_udc")) {
		value = vb2_get_nv_storage(VB2_NV_DEV_ENABLE_UDC);
	} else if (!strcasecmp(name,"display_request")) {
		value = vb2_get_nv_storage(VB2_NV_DISPLAY_REQUEST);
	} else if (!strcasecmp(name,"recovery_subcode")) {
		value = vb2_get_nv_storage(VB2_NV_RECOVERY_SUBCODE);
	} else if (!strcasecmp(name,"wipeout_request")) {
		value = vb2_get_nv_storage(VB2_NV_REQ_WIPEOUT);
	} else if (!strcasecmp(name,"kernel_max_rollforward")) {
		value = vb2_get_nv_storage(VB2_NV_KERNEL_MAX_ROLLFORWARD);
	}
	/* Other parameters */
	else if (!strcasecmp(name,"cros_debug")) {
		value = VbGetCrosDebug();
	} else if (!strcasecmp(name,"debug_build")) {
		value = VbGetDebugBuild();
	} else if (!strcasecmp(name,"devsw_boot")) {
		value = GetVdatInt(VDAT_INT_DEVSW_BOOT);
	} else if (!strcasecmp(name, "recoverysw_boot")) {
		value = GetVdatInt(VDAT_INT_RECSW_BOOT);
	} else if (!strcasecmp(name, "wpsw_cur")) {
		/* Use "write-protect at boot" as a fallback value. */
		value = GetVdatInt(VDAT_INT_HW_WPSW_BOOT);
		fprintf(stderr,
			"Fallback to WPSW_BOOT (%d), which may be invalid\n",
			value);
	} else if (!strcasecmp(name,"vdat_flags")) {
		value = GetVdatInt(VDAT_INT_FLAGS);
	} else if (!strcasecmp(name,"tpm_fwver")) {
		value = GetVdatInt(VDAT_INT_FW_VERSION_TPM);
	} else if (!strcasecmp(name,"tpm_kernver")) {
		value = GetVdatInt(VDAT_INT_KERNEL_VERSION_TPM);
	} else if (!strcasecmp(name,"act_fwver")) {
		value = GetVdatInt(VDAT_INT_FW_VERSION_ACT);
	} else if (!strcasecmp(name,"act_kernver")) {
		value = GetVdatInt(VDAT_INT_KERNEL_VERSION_ACT);
	} else if (!strcasecmp(name,"recovery_reason")) {
		value = GetVdatInt(VDAT_INT_RECOVERY_REASON);
	} else if (!strcasecmp(name, "boot_on_ac_detect")) {
		value = vb2_get_nv_storage(VB2_NV_BOOT_ON_AC_DETECT);
	} else if (!strcasecmp(name, "try_ro_sync")) {
		value = vb2_get_nv_storage(VB2_NV_TRY_RO_SYNC);
	} else if (!strcasecmp(name, "battery_cutoff_request")) {
		value = vb2_get_nv_storage(VB2_NV_BATTERY_CUTOFF_REQUEST);
	} else if (!strcasecmp(name, "inside_vm")) {
		/* Detect if the host is a VM. If there is no HWID and the
		 * firmware type is "nonchrome", then assume it is a VM. If
		 * HWID is present, it is a baremetal Chrome OS machine. Other
		 * cases are errors. */
		char hwid[VB_MAX_STRING_PROPERTY];
		if (VbGetSystemPropertyString("hwid", hwid,
					      sizeof(hwid)) != 0) {
			char fwtype_buf[VB_MAX_STRING_PROPERTY];
			int fwtype_ret = VbGetSystemPropertyString(
				"mainfw_type", fwtype_buf, sizeof(fwtype_buf));
			if (fwtype_ret == 0 &&
			    !strcasecmp(fwtype_buf, "nonchrome")) {
				value = 1;
			}
		} else {
			value = 0;
		}
	} else if (!strcasecmp(name, "post_ec_sync_delay")) {
		value = vb2_get_nv_storage(VB2_NV_POST_EC_SYNC_DELAY);
	}

	return value;
}

int VbGetSystemPropertyString(const char *name, char *dest, size_t size)
{
	if (dest == NULL || size == 0)
	{
		fprintf(stderr, "invalid dest buffer\n");
		return -1;
	}
	/* Check for HWID override via cros_config */
	if (!strcasecmp(name, "hwid")) {
		char *hwid_override;

		if (chromeos_config_get_string("/", "hwid-override",
					       &hwid_override) == VB2_SUCCESS) {
			StrCopy(dest, hwid_override, size);
			free(hwid_override);
			return 0;
		}
	}

	/* Check architecture-dependent properties */
	if (VbGetArchPropertyString(name, dest, size))
		return 0;

	if (!strcasecmp(name,"kernkey_vfy")) {
		switch(GetVdatInt(VDAT_INT_KERNEL_KEY_VERIFIED)) {
			case 0:
				StrCopy(dest, "hash", size);
				return 0;
			case 1:
				StrCopy(dest, "sig", size);
				return 0;
			default:
				return -1;
		}
	} else if (!strcasecmp(name, "mainfw_act")) {
		return GetVdatString(dest, size, VDAT_STRING_MAINFW_ACT);
	} else if (!strcasecmp(name, "vdat_lfdebug")) {
		return GetVdatString(dest, size,
				VDAT_STRING_LOAD_FIRMWARE_DEBUG);
	} else if (!strcasecmp(name, "fw_try_next")) {
		StrCopy(dest,
			vb2_get_nv_storage(VB2_NV_TRY_NEXT) ? "B" : "A",
			size);
		return 0;
	} else if (!strcasecmp(name, "fw_tried")) {
		StrCopy(dest,
			vb2_get_nv_storage(VB2_NV_FW_TRIED) ? "B" : "A",
			size);
		return 0;
	} else if (!strcasecmp(name, "fw_result")) {
		int v = vb2_get_nv_storage(VB2_NV_FW_RESULT);
		if (v < ARRAY_SIZE(fw_results))
			StrCopy(dest, fw_results[v], size);
		else
			StrCopy(dest, "unknown", size);
		return 0;
	} else if (!strcasecmp(name, "fw_prev_tried")) {
		StrCopy(dest,
			vb2_get_nv_storage(VB2_NV_FW_PREV_TRIED) ? "B" : "A",
			size);
		return 0;
	} else if (!strcasecmp(name, "fw_prev_result")) {
		int v = vb2_get_nv_storage(VB2_NV_FW_PREV_RESULT);
		if (v < ARRAY_SIZE(fw_results))
			StrCopy(dest, fw_results[v], size);
		else
			StrCopy(dest, "unknown", size);
		return 0;
	} else if (!strcasecmp(name,"dev_default_boot")) {
		int v = vb2_get_nv_storage(VB2_NV_DEV_DEFAULT_BOOT);
		if (v < ARRAY_SIZE(default_boot))
			StrCopy(dest, default_boot[v], size);
		else
			StrCopy(dest, "unknown", size);
		return 0;
	} else if (!strcasecmp(name, "minios_priority")) {
		StrCopy(dest,
			vb2_get_nv_storage(VB2_NV_MINIOS_PRIORITY) ?"B" : "A",
			size);
		return 0;
	}

	return -1;
}

static int VbSetSystemPropertyIntInternal(const char *name, int value)
{
	/* Check architecture-dependent properties first */

	if (0 == VbSetArchPropertyInt(name, value))
		return 0;

	/* NV storage values */
	if (!strcasecmp(name,"nvram_cleared")) {
		/* Can only clear this flag; it's set inside the NV storage
		 * library. */
		return vb2_set_nv_storage(VB2_NV_KERNEL_SETTINGS_RESET, 0);
	} else if (!strcasecmp(name,"recovery_request")) {
		return vb2_set_nv_storage(VB2_NV_RECOVERY_REQUEST, value);
	} else if (!strcasecmp(name,"diagnostic_request")) {
		return vb2_set_nv_storage(VB2_NV_DIAG_REQUEST, value);
	} else if (!strcasecmp(name,"recovery_subcode")) {
		return vb2_set_nv_storage(VB2_NV_RECOVERY_SUBCODE, value);
	} else if (!strcasecmp(name,"dbg_reset")) {
		return vb2_set_nv_storage(VB2_NV_DEBUG_RESET_MODE, value);
	} else if (!strcasecmp(name,"disable_dev_request")) {
		return vb2_set_nv_storage(VB2_NV_DISABLE_DEV_REQUEST, value);
	} else if (!strcasecmp(name,"clear_tpm_owner_request")) {
		if (EXTERNAL_TPM_CLEAR_REQUEST && CheckFwType("nonchrome")) {
			const char *const argv[] = {
				TPM_CLEAR_REQUEST_EXEC_NAME,
				value ? "1" : "0",
				NULL,
			};
			return subprocess_run(argv, &subprocess_null, &subprocess_null,
					      &subprocess_null);
		} else {
			return vb2_set_nv_storage(
				VB2_NV_CLEAR_TPM_OWNER_REQUEST, value);
		}
	} else if (!strcasecmp(name,"clear_tpm_owner_done")) {
		/* Can only clear this flag; it's set by firmware. */
		return vb2_set_nv_storage(VB2_NV_CLEAR_TPM_OWNER_DONE, 0);
	} else if (!strcasecmp(name,"fw_try_count")) {
		return vb2_set_nv_storage(VB2_NV_TRY_COUNT, value);
	} else if (!strcasecmp(name,"display_request")) {
		return vb2_set_nv_storage(VB2_NV_DISPLAY_REQUEST, value);
	} else if (!strcasecmp(name,"wipeout_request")) {
		/* Can only clear this flag, set only by firmware. */
		return vb2_set_nv_storage(VB2_NV_REQ_WIPEOUT, 0);
	} else if (!strcasecmp(name,"backup_nvram_request")) {
		/* Best-effort only, since it requires firmware and TPM
		 * support. */
		return vb2_set_nv_storage(VB2_NV_BACKUP_NVRAM_REQUEST, value);
	} else if (!strcasecmp(name,"fwupdate_tries")) {
		int kern_nv = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
		if (kern_nv == -1)
			return -1;
		kern_nv &= ~KERN_NV_FWUPDATE_TRIES_MASK;
		kern_nv |= (value & KERN_NV_FWUPDATE_TRIES_MASK);
		return vb2_set_nv_storage_with_backup(
			VB2_NV_KERNEL_FIELD, kern_nv);
	} else if (!strcasecmp(name,"block_devmode")) {
		int kern_nv = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
		if (kern_nv == -1)
			return -1;
		kern_nv &= ~KERN_NV_BLOCK_DEVMODE_FLAG;
		if (value)
			kern_nv |= KERN_NV_BLOCK_DEVMODE_FLAG;
		return vb2_set_nv_storage_with_backup(
			VB2_NV_KERNEL_FIELD, kern_nv);
	} else if (!strcasecmp(name,"tpm_attack")) {
		/* This value should only be read and cleared, but we allow
		 * setting it to 1 for testing. */
		int kern_nv = vb2_get_nv_storage(VB2_NV_KERNEL_FIELD);
		if (kern_nv == -1)
			return -1;
		kern_nv &= ~KERN_NV_TPM_ATTACK_FLAG;
		if (value)
			kern_nv |= KERN_NV_TPM_ATTACK_FLAG;
		return vb2_set_nv_storage_with_backup(
			VB2_NV_KERNEL_FIELD, kern_nv);
	} else if (!strcasecmp(name,"loc_idx")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_LOCALIZATION_INDEX, value);
	} else if (!strcasecmp(name,"dev_boot_usb")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_DEV_BOOT_EXTERNAL, value);
	} else if (!strcasecmp(name,"dev_boot_altfw") ||
		   !strcasecmp(name,"dev_boot_legacy")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_DEV_BOOT_ALTFW, value);
	} else if (!strcasecmp(name,"dev_boot_signed_only")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_DEV_BOOT_SIGNED_ONLY, value);
	} else if (!strcasecmp(name, "dev_enable_udc")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_DEV_ENABLE_UDC, value);
	} else if (!strcasecmp(name, "boot_on_ac_detect")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_BOOT_ON_AC_DETECT, value);
	} else if (!strcasecmp(name, "try_ro_sync")) {
		return vb2_set_nv_storage_with_backup(
			VB2_NV_TRY_RO_SYNC, value);
	} else if (!strcasecmp(name, "battery_cutoff_request")) {
		return vb2_set_nv_storage(VB2_NV_BATTERY_CUTOFF_REQUEST, value);
	} else if (!strcasecmp(name,"kernel_max_rollforward")) {
		return vb2_set_nv_storage(VB2_NV_KERNEL_MAX_ROLLFORWARD, value);
	} else if (!strcasecmp(name, "post_ec_sync_delay")) {
		return vb2_set_nv_storage(VB2_NV_POST_EC_SYNC_DELAY, value);
	}

	return -1;
}

int VbSetSystemPropertyInt(const char *name, int value)
{
	int result = -1;
	int lock_fd;

	lock_fd = AcquireCrossystemLock();
	if (lock_fd < 0)
		return -1;

	result = VbSetSystemPropertyIntInternal(name, value);

	if (ReleaseCrossystemLock(lock_fd) < 0)
		return -1;

	return result;
}

static int VbSetSystemPropertyStringInternal(const char *name,
					     const char *value)
{
	/* Chain to architecture-dependent properties */
	if (0 == VbSetArchPropertyString(name, value))
		return 0;

	if (!strcasecmp(name, "fw_try_next")) {
		if (!strcasecmp(value, "A"))
			return vb2_set_nv_storage(VB2_NV_TRY_NEXT, 0);
		else if (!strcasecmp(value, "B"))
			return vb2_set_nv_storage(VB2_NV_TRY_NEXT, 1);
		else
			return -1;
	} else if (!strcasecmp(name, "minios_priority")) {
		if (!strcasecmp(value, "A"))
			return vb2_set_nv_storage(VB2_NV_MINIOS_PRIORITY, 0);
		else if (!strcasecmp(value, "B"))
			return vb2_set_nv_storage(VB2_NV_MINIOS_PRIORITY, 1);
		else
			return -1;
	} else if (!strcasecmp(name, "fw_result")) {
		int i;

		for (i = 0; i < ARRAY_SIZE(fw_results); i++) {
			if (!strcasecmp(value, fw_results[i]))
				return vb2_set_nv_storage(VB2_NV_FW_RESULT, i);
		}
		return -1;
	} else if (!strcasecmp(name, "dev_default_boot")) {
		int i;

		/* "legacy" term deprecated in favour of "altfw"
		   (see: b/179458327) */
		if (!strcasecmp(value, "legacy")) {
			fprintf(stderr,
				"!!!\n"
				"!!! PLEASE USE 'altfw' INSTEAD OF 'legacy'\n"
				"!!!\n");
			value = "altfw";
		}

		for (i = 0; i < ARRAY_SIZE(default_boot); i++) {
			if (!strcasecmp(value, default_boot[i]))
				return vb2_set_nv_storage(
					VB2_NV_DEV_DEFAULT_BOOT, i);
		}
		return -1;
	}

	return -1;
}

int VbSetSystemPropertyString(const char *name, const char *value)
{
	int result = -1;
	int lock_fd;

	lock_fd = AcquireCrossystemLock();
	if (lock_fd < 0)
		return -1;

	result = VbSetSystemPropertyStringInternal(name, value);

	if (ReleaseCrossystemLock(lock_fd) < 0)
		return -1;

	return result;
}

/**
 * Get index of the last valid VBNV entry.
 *
 * @param buf		Pointer to the buffer containing VBNV entries.
 * @param buf_sz	Size of the buffer.
 * @param vbnv_size	The size of a single VBNV entry for this device.
 *
 * @return The index of the last valid VBNV entry found by binary search,
 * or -1 if not found. When the FMAP region is corrupted (used entries occurring
 * after blank ones), the returned index may not point to the last VBNV
 * entry.
 */
static int vb2_nv_index(const uint8_t *buf, uint32_t buf_sz, int vbnv_size)
{
	int used_below, blank_above;
	uint8_t blank[VB2_NVDATA_SIZE_V2];

	/* The size of the buffer should be an even multiple of the
	   VBNV size. */
	if (buf_sz % vbnv_size != 0) {
		VB2_DIE("The VBNV in flash (%u bytes) is not an even multiple "
			"of the VBNV size (%u bytes).  This is likely a "
			"firmware bug.\n", buf_sz, vbnv_size);
	}

	memset(blank, 0xff, sizeof(blank));

	/* To match the searching algorithm in firmware, perform binary search
	   instead of linear search to find the last used index. */
	used_below = 0;
	blank_above = buf_sz / vbnv_size;
	while (used_below + 1 < blank_above) {
		int mid = (used_below + blank_above) / 2;
		if (!memcmp(blank, &buf[mid * vbnv_size], vbnv_size))
			blank_above = mid;
		else
			used_below = mid;
	}

	/* Check the all blank case. */
	if (used_below == 0 &&
	    !memcmp(blank, &buf[used_below * vbnv_size], vbnv_size)) {
		fprintf(stderr, "VBNV is uninitialized.\n");
		return -1;
	}

	return used_below;
}

/**
 * Check whether the VBNV entries are corrupted.
 *
 * @param buf		Pointer to the buffer containing VBNV entries.
 * @param buf_sz	Size of the buffer.
 * @param vbnv_size	The size of a single VBNV entry for this device.
 *
 * @return True if there are used entries occurring after blank ones, or false
 * otherwise.
 */
static bool is_corrupted(const uint8_t *buf, uint32_t buf_sz, int vbnv_size)
{
	uint8_t blank[VB2_NVDATA_SIZE_V2];
	bool found_blank = false;

	memset(blank, 0xff, sizeof(blank));

	for (int i = 0; i < buf_sz / vbnv_size; i++) {
		if (!memcmp(blank, &buf[i * vbnv_size], vbnv_size))
			found_blank = true;
		else if (found_blank)
			return true;
	}

	return false;
}

#define VBNV_FMAP_REGION "RW_NVRAM"

int vb2_read_nv_storage_flashrom(struct vb2_context *ctx)
{
	int index;
	int vbnv_size = vb2_nv_get_size(ctx);

	struct firmware_image image = {
		.programmer = FLASHROM_PROGRAMMER_INTERNAL_AP,
	};
	if (flashrom_read(&image, VBNV_FMAP_REGION))
		return -1;

	index = vb2_nv_index(image.data, image.size, vbnv_size);
	if (index < 0) {
		free(image.data);
		return -1;
	}

	memcpy(ctx->nvdata, &image.data[index * vbnv_size], vbnv_size);
	free(image.data);
	return 0;
}

int vb2_write_nv_storage_flashrom(struct vb2_context *ctx)
{
	int rv = 0;
	int index;
	bool corrupted;
	int vbnv_size = vb2_nv_get_size(ctx);

	struct firmware_image image = {
		.programmer = FLASHROM_PROGRAMMER_INTERNAL_AP,
	};
	if (flashrom_read(&image, VBNV_FMAP_REGION))
		return -1;

	index = vb2_nv_index(image.data, image.size, vbnv_size) + 1;
	corrupted = is_corrupted(image.data, image.size, vbnv_size);

	if (corrupted || index * vbnv_size == image.size) {
		/* VBNV is corrupted or full.  Erase and write at beginning. */
		if (corrupted)
			fprintf(stderr, "VBNV is corrupted; erasing %s\n",
				VBNV_FMAP_REGION);
		memset(image.data, 0xff, image.size);
		index = 0;
	}

	memcpy(&image.data[index * vbnv_size], ctx->nvdata, vbnv_size);
	if (flashrom_write(&image, VBNV_FMAP_REGION)) {
		rv = -1;
		goto exit;
	}

 exit:
	free(image.data);
	return rv;
}
