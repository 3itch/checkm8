/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Vboot data structures.
 *
 * Note: Many of the structs have pairs of 32-bit fields and reserved fields.
 * This is to be backwards-compatible with older verified boot data which used
 * 64-bit fields (when we thought that hey, UEFI is 64-bit so all our fields
 * should be too).
 *
 * Offsets should be padded to 32-bit boundaries, since some architectures
 * have trouble with accessing unaligned integers.
 */

#ifndef VBOOT_REFERENCE_2STRUCT_H_
#define VBOOT_REFERENCE_2STRUCT_H_

#include "2api.h"
#include "2constants.h"
#include "2crypto.h"
#include "2sysincludes.h"

/* Flags for vb2_shared_data.flags */
enum vb2_shared_data_flags {
	/*
	 * VB2_SD_FLAG_MANUAL_RECOVERY (1 << 0) is deprecated. This flag is not
	 * necessary since the introduction of persistent context (CL:1716351).
	 * With introducing vb2_boot_mode and differentiating between manual
	 * recovery and broken screen (CL:3274699), it is suggested to leverage
	 * the vb2_boot_mode instead to determine if the user has physically
	 * requested recovery.
	 */

	/* Developer mode is enabled */
	VB2_SD_FLAG_DEV_MODE_ENABLED = (1 << 1),

	/*
	 * TODO: might be nice to add flags for why dev mode is enabled - via
	 * gbb, virtual dev switch, or forced on for testing.
	 */

	/* Kernel keyblock was verified by signature (not just hash) */
	VB2_SD_FLAG_KERNEL_SIGNED = (1 << 2),

	/* Software sync needs to update EC-RO or EC-RW */
	VB2_SD_FLAG_ECSYNC_EC_RO = (1 << 3),
	VB2_SD_FLAG_ECSYNC_EC_RW = (1 << 4),

	/*
	 * VB2_SD_FLAG_ECSYNC_PD_RW (1 << 5) is deprecated. Vboot no
	 * longer supports updating "PD" devices running CrOS EC code.
	 */

	/* Software sync says EC running RW */
	VB2_SD_FLAG_ECSYNC_EC_IN_RW = (1 << 6),

	/*
	 * VB2_SD_FLAG_ECSYNC_PD_IN_RW (1 << 7) is deprecated. Vboot
	 * no longer supports updating "PD" devices running CrOS EC
	 * code.
	 */

	/* Display is available on this boot */
	VB2_SD_FLAG_DISPLAY_AVAILABLE = (1 << 8),

	/* Mirrored hash (Hmir) is updated. */
	VB2_SD_FLAG_ECSYNC_HMIR_UPDATED = (1 << 9),
};

/* Flags for vb2_shared_data.status */
enum vb2_shared_data_status {
	/* Reinitialized NV data due to invalid checksum */
	VB2_SD_STATUS_NV_REINIT = (1 << 0),

	/* NV data has been initialized */
	VB2_SD_STATUS_NV_INIT = (1 << 1),

	/* Secure data initialized */
	VB2_SD_STATUS_SECDATA_FIRMWARE_INIT = (1 << 2),

	/* Chose a firmware slot */
	VB2_SD_STATUS_CHOSE_SLOT = (1 << 3),

	/* Secure data kernel version space initialized */
	VB2_SD_STATUS_SECDATA_KERNEL_INIT = (1 << 4),

	/* FWMP secure data initialized */
	VB2_SD_STATUS_SECDATA_FWMP_INIT = (1 << 5),

	/* EC Sync completed successfully */
	VB2_SD_STATUS_EC_SYNC_COMPLETE = (1 << 6),

	/* Have checked whether we are booting into recovery mode or not. */
	VB2_SD_STATUS_RECOVERY_DECIDED = (1 << 7),
};

/* "V2SD" = vb2_shared_data.magic */
#define VB2_SHARED_DATA_MAGIC 0x44533256

/* Current version of vb2_shared_data struct */
#define VB2_SHARED_DATA_VERSION_MAJOR 3
#define VB2_SHARED_DATA_VERSION_MINOR 2

/* MAX_SIZE should not be changed without bumping up DATA_VERSION_MAJOR. */
#define VB2_CONTEXT_MAX_SIZE 384

/*
 * Data shared between vboot API calls.  Stored at the start of the work
 * buffer.
 */
struct vb2_shared_data {
	/* Magic number for struct (VB2_SHARED_DATA_MAGIC) */
	uint32_t magic;

	/* Version of this structure */
	uint16_t struct_version_major;
	uint16_t struct_version_minor;

	/* Public fields are stored in the context object */
	struct vb2_context ctx;

	/* Padding for adding future vb2_context fields */
	uint8_t padding[VB2_CONTEXT_MAX_SIZE - sizeof(struct vb2_context)];

	/* Work buffer length in bytes. */
	uint32_t workbuf_size;

	/*
	 * Amount of work buffer used so far.  Verified boot sub-calls use
	 * this to know where the unused work area starts.
	 */
	uint32_t workbuf_used;

	/* Flags; see enum vb2_shared_data_flags */
	uint32_t flags;

	/*
	 * Reason we are in recovery mode this boot (enum vb2_nv_recovery), or
	 * 0 if we aren't.
	 */
	uint32_t recovery_reason;

	/* Firmware slot used last boot (0=A, 1=B) */
	uint32_t last_fw_slot;

	/* Result of last boot (enum vb2_fw_result) */
	uint32_t last_fw_result;

	/* Firmware slot used this boot */
	uint32_t fw_slot;

	/*
	 * Version for this slot (top 16 bits = key, lower 16 bits = firmware).
	 *
	 * TODO: Make this a union to allow getting/setting those versions
	 * separately?
	 */
	uint32_t fw_version;

	/* Version from secdata_firmware (must be <= fw_version to boot). */
	uint32_t fw_version_secdata;

	/*
	 * Status flags for this boot; see enum vb2_shared_data_status.  Status
	 * is "what we've done"; flags above are "decisions we've made".
	 */
	uint32_t status;

	/* Offset from start of this struct to GBB header */
	uint32_t gbb_offset;

	/**********************************************************************
	 * Data from kernel verification stage.
	 *
	 * TODO: shouldn't be part of the main struct, since that needlessly
	 * uses more memory during firmware verification.
	 */

	/*
	 * Version for the current kernel (top 16 bits = key, lower 16 bits =
	 * kernel preamble).
	 *
	 * TODO: Make this a union to allow getting/setting those versions
	 * separately?
	 */
	uint32_t kernel_version;

	/* Version from secdata_kernel (must be <= kernel_version to boot) */
	uint32_t kernel_version_secdata;

	/**********************************************************************
	 * Temporary variables used during firmware verification.  These don't
	 * really need to persist through to the OS, but there's nowhere else
	 * we can put them.
	 */

	/* Offset of preamble from start of vblock */
	uint32_t vblock_preamble_offset;

	/*
	 * Offset and size of packed data key in work buffer.  Size is 0 if
	 * data key is not stored in the work buffer.
	 */
	uint32_t data_key_offset;
	uint32_t data_key_size;

	/*
	 * Offset and size of firmware preamble in work buffer.  Size is 0 if
	 * preamble is not stored in the work buffer.
	 */
	uint32_t preamble_offset;
	uint32_t preamble_size;

	/*
	 * Offset and size of hash context in work buffer.  Size is 0 if
	 * hash context is not stored in the work buffer.
	 */
	uint32_t hash_offset;
	uint32_t hash_size;

	/*
	 * Current tag we're hashing
	 *
	 * For new structs, this is the offset of the vb2_signature struct
	 * in the work buffer.
	 *
	 * TODO: rename to hash_sig_offset when vboot1 structs are deprecated.
	 */
	uint32_t hash_tag;

	/* Amount of data we still expect to hash */
	uint32_t hash_remaining_size;

	/**********************************************************************
	 * Temporary variables used during kernel verification.  These don't
	 * really need to persist through to the OS, but there's nowhere else
	 * we can put them.
	 *
	 * TODO: make a union with the firmware verification temp variables,
	 * or make both of them workbuf-allocated sub-structs, so that we can
	 * overlap them so kernel variables don't bloat firmware verification
	 * stage memory requirements.
	 */

	/*
	 * Formerly a pointer to vboot1 shared data header ("VBSD").  Caller
	 * may now export a copy of VBSD via vb2api_export_vbsd().
	 * TODO: Remove this field and bump struct_version_major.
	 */
	uintptr_t reserved0;

	/*
	 * Offset and size of packed kernel key in work buffer.  Size is 0 if
	 * subkey is not stored in the work buffer.  Note that kernel key may
	 * be inside the firmware preamble.
	 */
	uint32_t kernel_key_offset;
	uint32_t kernel_key_size;
} __attribute__((packed));

/****************************************************************************/

/* Signature at start of the GBB
 * Note that if you compile in the signature as is, you are likely to break any
 * tools that search for the signature. */
#define VB2_GBB_SIGNATURE "$GBB"
#define VB2_GBB_SIGNATURE_SIZE 4
#define VB2_GBB_XOR_CHARS "****"
/* TODO: can we write a macro to produce this at compile time? */
#define VB2_GBB_XOR_SIGNATURE { 0x0e, 0x6d, 0x68, 0x68 }

#define VB2_GBB_HWID_DIGEST_SIZE 32

/* VB2 GBB struct version */
#define VB2_GBB_MAJOR_VER 1
#define VB2_GBB_MINOR_VER 2
/* v1.2 - added fields for sha256 digest of the HWID */

struct vb2_gbb_header {
	/* Fields present in version 1.1 */
	uint8_t  signature[VB2_GBB_SIGNATURE_SIZE]; /* VB2_GBB_SIGNATURE */
	uint16_t major_version;   /* See VB2_GBB_MAJOR_VER */
	uint16_t minor_version;   /* See VB2_GBB_MINOR_VER */
	uint32_t header_size;     /* Size of GBB header in bytes */

	/* Flags (see enum vb2_gbb_flag in 2gbb_flags.h) */
	vb2_gbb_flags_t flags;

	/* Offsets (from start of header) and sizes (in bytes) of components */
	uint32_t hwid_offset;		/* HWID */
	uint32_t hwid_size;
	uint32_t rootkey_offset;	/* Root key */
	uint32_t rootkey_size;
	uint32_t bmpfv_offset;		/* BMP FV; deprecated in current FW */
	uint32_t bmpfv_size;
	uint32_t recovery_key_offset;	/* Recovery key */
	uint32_t recovery_key_size;

	/* Added in version 1.2 */
	uint8_t  hwid_digest[VB2_GBB_HWID_DIGEST_SIZE];	/* SHA-256 of HWID */

	/* Pad to match EXPECTED_VB2_GBB_HEADER_SIZE.  Initialize to 0. */
	uint8_t  pad[48];
} __attribute__((packed));

#define EXPECTED_VB2_GBB_HEADER_SIZE 128

/* VB2_GBB_FLAGS_OFFSET exposed in 2constants.h */
_Static_assert(VB2_GBB_FLAGS_OFFSET == offsetof(struct vb2_gbb_header, flags),
	       "VB2_GBB_FLAGS_OFFSET set incorrectly");

/****************************************************************************/

/* Packed public key data */
struct vb2_packed_key {
	/* Offset of key data from start of this struct */
	uint32_t key_offset;
	uint32_t reserved0;

	/* Size of key data in bytes (NOT strength of key in bits) */
	uint32_t key_size;
	uint32_t reserved1;

	/* Signature algorithm used by the key (enum vb2_crypto_algorithm) */
	uint32_t algorithm;
	uint32_t reserved2;

	/* Key version */
	uint32_t key_version;
	uint32_t reserved3;

	/* TODO: when redoing this struct, add a text description of the key */
} __attribute__((packed));

#define EXPECTED_VB2_PACKED_KEY_SIZE 32

/****************************************************************************/

/* Signature data (a secure hash, possibly signed) */
struct vb2_signature {
	/* Offset of signature data from start of this struct */
	uint32_t sig_offset;
	uint32_t reserved0;

	/* Size of signature data in bytes */
	uint32_t sig_size;
	uint32_t reserved1;

	/* Size of the data block which was signed in bytes */
	uint32_t data_size;
	uint32_t reserved2;
} __attribute__((packed));

#define EXPECTED_VB2_SIGNATURE_SIZE 24

/****************************************************************************/

#define VB2_KEYBLOCK_MAGIC "CHROMEOS"
#define VB2_KEYBLOCK_MAGIC_SIZE 8

#define VB2_KEYBLOCK_VERSION_MAJOR 2
#define VB2_KEYBLOCK_VERSION_MINOR 1

/*
 * Keyblock flags.
 *
 * The following flags set where the key is valid.  Not used by firmware
 * verification; only kernel verification.
 */
#define VB2_KEYBLOCK_FLAG_DEVELOPER_0 0x1  /* Developer switch off */
#define VB2_KEYBLOCK_FLAG_DEVELOPER_1 0x2  /* Developer switch on */
#define VB2_KEYBLOCK_FLAG_RECOVERY_0 0x4  /* Not recovery mode */
#define VB2_KEYBLOCK_FLAG_RECOVERY_1 0x8  /* Recovery mode */
#define VB2_KEYBLOCK_FLAG_MINIOS_0 0x10  /* Not miniOS boot */
#define VB2_KEYBLOCK_FLAG_MINIOS_1 0x20  /* miniOS boot */

/*
 * Keyblock, containing the public key used to sign some other chunk of data.
 *
 * This should be followed by:
 *   1) The data_key key data, pointed to by data_key.key_offset.
 *   2) The checksum data for (vb2_keyblock + data_key data), pointed to
 *      by keyblock_checksum.sig_offset.
 *   3) The signature data for (vb2_keyblock + data_key data), pointed to
 *      by keyblock_signature.sig_offset.
 */
struct vb2_keyblock {
	/* Magic number */
	uint8_t magic[VB2_KEYBLOCK_MAGIC_SIZE];

	/* Version of this header format */
	uint32_t header_version_major;
	uint32_t header_version_minor;

	/*
	 * Length of this entire keyblock, including keys, signatures, and
	 * padding, in bytes
	 */
	uint32_t keyblock_size;
	uint32_t reserved0;

	/*
	 * Signature for this keyblock (header + data pointed to by data_key)
	 * For use with signed data keys
	 */
	struct vb2_signature keyblock_signature;

	/*
	 * SHA-512 hash for this keyblock (header + data pointed to by
	 * data_key) For use with unsigned data keys.
	 *
	 * Only supported for kernel keyblocks, not firmware keyblocks.
	 */
	struct vb2_signature keyblock_hash;

	/* Flags for key (VB2_KEYBLOCK_FLAG_*) */
	uint32_t keyblock_flags;
	uint32_t reserved1;

	/* Key to verify the chunk of data */
	struct vb2_packed_key data_key;
} __attribute__((packed));

#define EXPECTED_VB2_KEYBLOCK_SIZE 112

/****************************************************************************/

/*
 * Rollback protection currently uses a 32-bit value comprised of the bottom 16
 * bits of the (firmware or kernel) preamble version and the bottom 16 bits of
 * the key version.  So each of those versions is effectively limited to 16
 * bits even though they get stored in 32-bit fields.
 */
#define VB2_MAX_KEY_VERSION 0xffff
#define VB2_MAX_PREAMBLE_VERSION 0xffff

/****************************************************************************/

/* Firmware preamble header */
#define VB2_FIRMWARE_PREAMBLE_HEADER_VERSION_MAJOR 2
#define VB2_FIRMWARE_PREAMBLE_HEADER_VERSION_MINOR 1

/* Flags for vb2_fw_preamble.flags */
/* Use RO-normal firmware (deprecated; do not use) */
#define VB2_FIRMWARE_PREAMBLE_USE_RO_NORMAL 0x00000001
/* Do not allow use of any hardware crypto accelerators.
 * (deprecated; use VB2_SECDATA_KERNEL_FLAG_HWCRYPTO_ALLOWED instead)
 */
#define VB2_FIRMWARE_PREAMBLE_DISALLOW_HWCRYPTO 0x00000002

/* Premable block for rewritable firmware, vboot1 version 2.1.
 *
 * The firmware preamble header should be followed by:
 *   1) The kernel_subkey key data, pointed to by kernel_subkey.key_offset.
 *   2) The signature data for the firmware body, pointed to by
 *      body_signature.sig_offset.
 *   3) The signature data for (header + kernel_subkey data + body signature
 *      data), pointed to by preamble_signature.sig_offset.
 */
struct vb2_fw_preamble {
	/*
	 * Size of this preamble, including keys, signatures, and padding, in
	 * bytes
	 */
	uint32_t preamble_size;
	uint32_t reserved0;

	/*
	 * Signature for this preamble (header + kernel subkey + body
	 * signature)
	 */
	struct vb2_signature preamble_signature;

	/* Version of this header format */
	uint32_t header_version_major;
	uint32_t header_version_minor;

	/* Firmware version */
	uint32_t firmware_version;
	uint32_t reserved1;

	/* Key to verify kernel keyblock */
	struct vb2_packed_key kernel_subkey;

	/* Signature for the firmware body */
	struct vb2_signature body_signature;

	/*
	 * Fields added in header version 2.1.  You must verify the header
	 * version before reading these fields!
	 */

	/*
	 * Flags; see VB2_FIRMWARE_PREAMBLE_*.  Readers should return 0 for
	 * header version < 2.1.
	 */
	uint32_t flags;
} __attribute__((packed));

#define EXPECTED_VB2_FW_PREAMBLE_SIZE 108

_Static_assert(EXPECTED_VB2_FW_PREAMBLE_SIZE == sizeof(struct vb2_fw_preamble),
	       "EXPECTED_VB2_FW_PREAMBLE_SIZE incorrect");

/****************************************************************************/

/* Kernel preamble header */
#define VB2_KERNEL_PREAMBLE_HEADER_VERSION_MAJOR 2
#define VB2_KERNEL_PREAMBLE_HEADER_VERSION_MINOR 2

/* Flags for vb2_kernel_preamble.flags */
/* Kernel image type = bits 1:0 */
#define VB2_KERNEL_PREAMBLE_KERNEL_TYPE_MASK 0x00000003
#define VB2_KERNEL_PREAMBLE_KERNEL_TYPE_CROS      0
#define VB2_KERNEL_PREAMBLE_KERNEL_TYPE_BOOTIMG   1
#define VB2_KERNEL_PREAMBLE_KERNEL_TYPE_MULTIBOOT 2
/* Kernel type 3 is reserved for future use */

/*
 * Preamble block for kernel, version 2.2
 *
 * This should be followed by:
 *   1) The signature data for the kernel body, pointed to by
 *      body_signature.sig_offset.
 *   2) The signature data for (vb2_kernel_preamble + body signature data),
 *       pointed to by preamble_signature.sig_offset.
 *   3) The 16-bit vmlinuz header, which is used for reconstruction of
 *      vmlinuz image.
 */
struct vb2_kernel_preamble {
	/*
	 * Size of this preamble, including keys, signatures, vmlinuz header,
	 * and padding, in bytes
	 */
	uint32_t preamble_size;
	uint32_t reserved0;

	/* Signature for this preamble (header + body signature) */
	struct vb2_signature preamble_signature;

	/* Version of this header format */
	uint32_t header_version_major;
	uint32_t header_version_minor;

	/* Kernel version */
	uint32_t kernel_version;
	uint32_t reserved1;

	/* Load address for kernel body */
	uint64_t body_load_address;
	/* TODO (vboot 2.1): we never used that */

	/* Address of bootloader, after body is loaded at body_load_address */
	uint64_t bootloader_address;
	/* TODO (vboot 2.1): should be a 32-bit offset */

	/* Size of bootloader in bytes */
	uint32_t bootloader_size;
	uint32_t reserved2;

	/* Signature for the kernel body */
	struct vb2_signature body_signature;

	/*
	 * TODO (vboot 2.1): fields for kernel offset and size.  Right now the
	 * size is implicitly the same as the size of data signed by the body
	 * signature, and the offset is implicitly at the end of the preamble.
	 * But that forces us to pad the preamble to 64KB rather than just
	 * having a tiny preamble and an offset field.
	 */

	/*
	 * Fields added in header version 2.1.  You must verify the header
	 * version before reading these fields!
	 */

	/*
	 * Address of 16-bit header for vmlinuz reassembly.  Readers should
	 * return 0 for header version < 2.1.
	 */
	uint64_t vmlinuz_header_address;

	/* Size of 16-bit header for vmlinuz in bytes.  Readers should return 0
	   for header version < 2.1 */
	uint32_t vmlinuz_header_size;
	uint32_t reserved3;

	/*
	 * Fields added in header version 2.2.  You must verify the header
	 * version before reading these fields!
	 */

	/*
	 * Flags; see VB2_KERNEL_PREAMBLE_*.  Readers should return 0 for
	 * header version < 2.2.  Flags field is currently defined as:
	 * [31:2] - Reserved (for future use)
	 * [1:0]  - Kernel image type (0b00 - CrOS,
	 *                             0b01 - bootimg,
	 *                             0b10 - multiboot)
	 */
	uint32_t flags;
} __attribute__((packed));

#define EXPECTED_VB2_KERNEL_PREAMBLE_2_0_SIZE 96
#define EXPECTED_VB2_KERNEL_PREAMBLE_2_1_SIZE 112
#define EXPECTED_VB2_KERNEL_PREAMBLE_2_2_SIZE 116

_Static_assert(EXPECTED_VB2_KERNEL_PREAMBLE_2_0_SIZE
	       == offsetof(struct vb2_kernel_preamble, vmlinuz_header_address),
	       "EXPECTED_VB2_KERNEL_PREAMBLE_2_0_SIZE incorrect");

_Static_assert(EXPECTED_VB2_KERNEL_PREAMBLE_2_1_SIZE
	       == offsetof(struct vb2_kernel_preamble, flags),
	       "EXPECTED_VB2_KERNEL_PREAMBLE_2_1_SIZE incorrect");

_Static_assert(EXPECTED_VB2_KERNEL_PREAMBLE_2_2_SIZE
	       == sizeof(struct vb2_kernel_preamble),
	       "EXPECTED_VB2_KERNEL_PREAMBLE_2_2_SIZE incorrect");

#endif  /* VBOOT_REFERENCE_2STRUCT_H_ */
