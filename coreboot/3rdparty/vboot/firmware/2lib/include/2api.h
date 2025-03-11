/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * APIs between calling firmware and vboot_reference
 *
 * General notes:
 *
 * TODO: split this file into a vboot_entry_points.h file which contains the
 * entry points for the firmware to call vboot_reference, and a
 * vboot_firmware_exports.h which contains the APIs to be implemented by the
 * calling firmware and exported to vboot_reference.
 *
 * Notes:
 *    * Assumes this code is never called in the S3 resume path.  TPM resume
 *      must be done elsewhere, and VB2_NV_DEBUG_RESET_MODE is ignored.
 */

#ifndef VBOOT_REFERENCE_2API_H_
#define VBOOT_REFERENCE_2API_H_

#include "2constants.h"
#include "2context.h"
#include "2crypto.h"
#include "2fw_hash_tags.h"
#include "2gbb_flags.h"
#include "2hmac.h"
#include "2id.h"
#include "2info.h"
#include "2recovery_reasons.h"
#include "2return_codes.h"
#include "2rsa.h"
#include "2secdata_struct.h"

#define _VB2_TRY_IMPL(expr, ctx, recovery_reason, ...) do { \
	vb2_error_t _vb2_try_rv = (expr); \
	struct vb2_context *_vb2_try_ctx = (ctx); \
	uint8_t _vb2_try_reason = (recovery_reason); \
	if (_vb2_try_rv != VB2_SUCCESS) { \
		vb2ex_printf(__func__, \
			     "%s returned %#x\n", #expr, _vb2_try_rv); \
		if (_vb2_try_rv >= VB2_REQUEST_END && \
		    (_vb2_try_ctx) && \
		    (_vb2_try_reason) != VB2_RECOVERY_NOT_REQUESTED) \
			vb2api_fail(_vb2_try_ctx, _vb2_try_reason, \
				    _vb2_try_rv); \
		return _vb2_try_rv; \
	} \
} while (0)

/*
 * Evaluate an expression and return *from the caller* on failure or if an
 * action (such as reboot) is requested.
 *
 * This macro supports two forms of usage:
 * 1. VB2_TRY(expr)
 * 2. VB2_TRY(expr, ctx, recovery_reason)
 *
 * When the second form is used, vb2api_fail() will be called on failure before
 * return. Note that nvdata only holds one byte for recovery subcode, so any
 * other more significant bytes will be truncated.
 *
 * @param expr			An expression (such as a function call) of type
 *				vb2_error_t.
 * @param ctx			Vboot context.
 * @param recovery_reason	Recovery reason passed to vb2api_fail().
 */
#define VB2_TRY(expr, ...) _VB2_TRY_IMPL(expr, ##__VA_ARGS__, NULL, 0)

/**
 * Check if the return value is an error.
 *
 * @param rv	The return value.
 * @return True if the value is an error.
 */
static inline int vb2_is_error(vb2_error_t rv)
{
	return rv >= VB2_ERROR_BASE && rv <= VB2_ERROR_MAX;
}

/* Resource index for vb2ex_read_resource() */
enum vb2_resource_index {

	/* Google binary block */
	VB2_RES_GBB,

	/*
	 * Firmware verified boot block (keyblock+preamble).  Use
	 * VB2_CONTEXT_FW_SLOT_B to determine whether this refers to slot A or
	 * slot B; vboot will set that flag to the proper state before reading
	 * the vblock.
	 */
	VB2_RES_FW_VBLOCK,

	/*
	 * Kernel verified boot block (keyblock+preamble) for the current
	 * kernel partition.  Used only by vb2api_kernel_load_vblock().
	 * Contents are allowed to change between calls to that function (to
	 * allow multiple kernels to be examined).
	 */
	VB2_RES_KERNEL_VBLOCK,
};

/* Digest ID for vbapi_get_pcr_digest() */
enum vb2_pcr_digest {
	/* Digest based on current developer and recovery mode flags */
	BOOT_MODE_PCR,

	/* SHA-256 hash digest of HWID, from GBB */
	HWID_DIGEST_PCR,

	/* The firmware version values. */
	FIRMWARE_VERSION_PCR,

	/* The kernel version values. */
	KERNEL_VERSION_PCR,
};

/******************************************************************************
 * APIs provided by verified boot.
 *
 * At a high level, call functions in the order described below.  After each
 * call, examine vb2_context.flags to determine whether nvdata or secdata
 * needs to be written.
 *
 * If you need to cause the boot process to fail at any point, call
 * vb2api_fail().  Then check vb2_context.flags to see what data needs to be
 * written.  Then reboot.
 *
 *	Load nvdata from wherever you keep it.
 *
 *	Load secdata_firmware from wherever you keep it.
 *
 *      	If it wasn't there at all (for example, this is the first boot
 *		of a new system in the factory), call
 *		vb2api_secdata_firmware_create() to initialize the data.
 *
 *		If access to your storage is unreliable (reads/writes may
 *		contain corrupt data), you may call
 *		vb2api_secdata_firmware_check() to determine if the data was
 *		valid, and retry reading if it wasn't.  (In that case, you
 *		should also read back and check the data after any time you
 *		write it, to make sure it was written correctly.)
 *
 *	Call vb2api_fw_phase1().  At present, this nominally decides whether
 *	recovery mode is needed this boot.
 *
 *	Call vb2api_fw_phase2().  At present, this nominally decides which
 *	firmware slot will be attempted (A or B).
 *
 *	Call vb2api_fw_phase3().  At present, this nominally verifies the
 *	firmware keyblock and preamble.
 *
 *	Lock down wherever you keep secdata_firmware.  It should no longer be
 *	writable this boot.
 *
 *	Verify the hash of each section of code/data you need to boot the RW
 *	firmware.  For each section:
 *
 *	1) Normal verification:
 *
 *		Call vb2api_init_hash() to see if the hash exists.
 *
 *		Load the data for the section.  Call vb2api_extend_hash() on the
 *		data as you load it.  You can load it all at once and make one
 *		call, or load and hash-extend a block at a time.
 *
 *		Call vb2api_check_hash() to see if the hash is valid.
 *
 *			If it is valid, you may use the data and/or execute
 *			code from that section.
 *
 *			If the hash was invalid, you must reboot.
 *
 *	2) Verification with CBFS integration:
 *
 *		Call vb2api_get_metadata_hash() to get hash of CBFS metadata.
 *
 *		Initialize CBFS using stored hash as correct metadata hash.
 *
 *			If CBFS initialization fails because of metadata hash
 *			mismatch, you must reboot.
 *
 *			If CBFS initialization succeeds, you may use the data
 *			and/or execute code from that section.
 *			IMPORTANT: Be aware, that to have full section
 *			verification, the CBFS_VERIFICATION has to be enabled.
 *			Initialization of CBFS volume only checks hash of files
 *			metadata, not their contents!
 *
 * At this point, firmware verification is done, and vb2_context contains the
 * kernel key needed to verify the kernel.  That context should be preserved
 * and passed on to kernel selection.  The kernel selection process may be
 * done by the same firmware image, or may be done by the RW firmware.  The
 * recommended order is:
 *
 *	Load secdata_kernel from wherever you keep it.
 *
 *      	If it wasn't there at all (for example, this is the first boot
 *		of a new system in the factory), call
 *		vb2api_secdata_kernel_create() to initialize the data.
 *
 *		If access to your storage is unreliable (reads/writes may
 *		contain corrupt data), you may call
 *		vb2api_secdata_kernel_check() to determine if the data was
 *		valid, and retry reading if it wasn't.  (In that case, you
 *		should also read back and check the data after any time you
*		write it, to make sure it was written correctly.)
 *
 *	Call vb2api_kernel_phase1().  At present, this decides which key to
 *	use to verify kernel data - the recovery key from the GBB, or the
 *	kernel subkey from the firmware verification stage.
 *
 *	Call vb2api_kernel_phase2().  Do EC and auxfw software sync, clear
 *	recovery and commit nvdata if needed.
 *
 *	Find a boot device (you're on your own here).
 *
 *	Call vb2api_load_kernel_vblock() for each kernel partition on the
 *	boot device, until one succeeds.
 *
 *	When that succeeds, call vb2api_get_kernel_size() to determine where
 *	the kernel is located in the stream and how big it is.  Load or map
 *	the kernel.  (Again, you're on your own.  This is the responsibility of
 *	the caller so that the caller can choose whether to allocate a buffer,
 *	load the kernel data into a predefined area of RAM, or directly map a
 *	kernel file into the address space.  Note that technically it doesn't
 *	matter whether the kernel data is even in the same file or stream as
 *	the vblock, as long as the caller loads the right data.
 *
 *	Call vb2api_verify_kernel_data() on the kernel data.
 *
 *	If you ran out of kernels before finding a good one, call vb2api_fail()
 *	with an appropriate recovery reason.
 *
 *	Set the VB2_CONTEXT_ALLOW_KERNEL_ROLL_FORWARD flag if the current
 *	kernel partition has the successful flag (that is, it's already known
 *	or assumed to be a functional kernel partition).
 *
 *	Call vb2api_kernel_phase3().  This cleans up from kernel verification
 *	and updates the secure data if needed.
 *
 *	Lock down wherever you keep secdata_kernel.  It should no longer be
 *	writable this boot.
 */

/**
 * Initialize verified boot data structures.
 *
 * Needs to be called once per boot, before using any API functions that
 * accept a vb2_context object.  Sets up the vboot work buffer, as well as
 * vb2_shared_data and vb2_context.  A pointer to the context object is
 * written to ctxptr.  After transitioning between different firmware
 * applications, or any time the context pointer is lost, vb2api_reinit()
 * should be used to restore access to the context and data on the workbuf.
 *
 * If the workbuf needs to be relocated, call vb2api_relocate() instead
 * of copying memory manually.
 *
 * @param workbuf	Workbuf memory location to initialize
 * @param size		Size of workbuf being initialized
 * @param ctxptr	Pointer to a context pointer to be filled in
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2api_init(void *workbuf, uint32_t size,
			struct vb2_context **ctxptr);

/**
 * Reinitialize vboot data structures.
 *
 * After transitioning between different firmware applications, or any time the
 * context pointer is lost, this function should be called to restore access to
 * the workbuf.  A pointer to the context object is written to ctxptr.  Returns
 * an error if the vboot work buffer is inconsistent.
 *
 * If the workbuf needs to be relocated, call vb2api_relocate() instead
 * of copying memory manually.
 *
 * @param workbuf	Workbuf memory location to check
 * @param ctxptr	Pointer to a context pointer to be filled in
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2api_reinit(void *workbuf, struct vb2_context **ctxptr);

/**
 * Relocate vboot data structures.
 *
 * Move the vboot work buffer from one memory location to another, and expand
 * or contract the workbuf to fit.  The target memory location may be the same
 * as the original (used for a "resize" operation), and it is safe to call this
 * function with overlapping memory regions.
 *
 * A pointer to the context object is written to ctxptr.  Returns an error if
 * the vboot work buffer is inconsistent, or if the new memory space is too
 * small to contain the work buffer.
 *
 * @param new_workbuf	Target workbuf memory location
 * @param cur_workbuf	Original workbuf memory location to relocate
 * @param size		Target size of relocated workbuf
 * @param ctxptr	Pointer to a context pointer to be filled in
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2api_relocate(void *new_workbuf, const void *cur_workbuf,
			    uint32_t size, struct vb2_context **ctxptr);

/**
 * Export "VBSD" vboot1 data structure.
 *
 * Copy relevant fields from vboot2 data structures to VbSharedDataHeader
 * format.  Takes a pointer to the memory space to be filled in.  Expects
 * the memory available to be of size VB2_VBSD_SIZE.
 *
 * @param ctx		Context pointer
 * @param dest		Target memory to store VbSharedDataHeader
 */
void vb2api_export_vbsd(struct vb2_context *ctx, void *dest);

/**
 * Check the validity of firmware secure storage context.
 *
 * Checks version and CRC.
 *
 * @param ctx		Context pointer
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2api_secdata_firmware_check(struct vb2_context *ctx);

/**
 * Create fresh data in firmware secure storage context.
 *
 * Use this only when initializing the secure storage context on a new machine
 * the first time it boots.  Do NOT simply use this if
 * vb2api_secdata_firmware_check() (or any other API in this library) fails;
 * that could allow the secure data to be rolled back to an insecure state.
 *
 * @param ctx		Context pointer
 * @return size of created firmware secure storage data in bytes
 */
uint32_t vb2api_secdata_firmware_create(struct vb2_context *ctx);

/**
 * Check the validity of kernel secure storage context (ctx->secdata_kernel).
 *
 * Checks version, UID, and CRC.
 *
 * @param ctx		Context pointer
 * @param size		(IN) Size of data to be checked
 * 			(OUT) Expected size of data
 * @return VB2_SUCCESS, or non-zero error code if error. If data is missing,
 * 	   it returns VB2_ERROR_SECDATA_KERNEL_INCOMPLETE and informs the caller
 * 	   of the expected size.
 */
vb2_error_t vb2api_secdata_kernel_check(struct vb2_context *ctx, uint8_t *size);

/**
 * Create fresh data in kernel secure storage context.
 *
 * Use this only when initializing the secure storage context on a new machine
 * the first time it boots.  Do NOT simply use this if
 * vb2api_secdata_kernel_check() (or any other API in this library) fails; that
 * could allow the secure data to be rolled back to an insecure state.
 *
 * vb2api_secdata_kernel_create always creates secdata kernel using the latest
 * revision.
 *
 * @param ctx		Context pointer
 * @return size of created kernel secure storage data in bytes
 */
uint32_t vb2api_secdata_kernel_create(struct vb2_context *ctx);
uint32_t vb2api_secdata_kernel_create_v0(struct vb2_context *ctx);

/**
 * Create an empty Firmware Management Parameters (FWMP) in secure storage
 * context.
 *
 * @param ctx		Context pointer
 * @return size of created FWMP secure storage data in bytes
 */
uint32_t vb2api_secdata_fwmp_create(struct vb2_context *ctx);

/**
 * Check the validity of firmware management parameters (FWMP) space.
 *
 * Checks size, version, and CRC.  If the struct size is larger than the size
 * passed in, the size pointer is set to the expected full size of the struct,
 * and VB2_ERROR_SECDATA_FWMP_INCOMPLETE is returned.  The caller should
 * re-read the returned number of bytes, and call this function again.
 *
 * @param ctx		Context pointer
 * @param size		Amount of struct which has been read
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2api_secdata_fwmp_check(struct vb2_context *ctx, uint8_t *size);

/**
 * Report firmware failure to vboot.
 *
 * If the failure occurred after choosing a firmware slot, and the other
 * firmware slot is not known-bad, try the other firmware slot after reboot.
 *
 * If the failure occurred before choosing a firmware slot, or both slots have
 * failed in successive boots, request recovery.
 *
 * This may be called before vb2api_phase1() to indicate errors in the boot
 * process prior to the start of vboot.  On return, the calling firmware should
 * check for updates to secdata and/or nvdata, then reboot.
 *
 * @param reason	Recovery reason
 * @param subcode	Recovery subcode
 */
void vb2api_fail(struct vb2_context *ctx, uint8_t reason, uint8_t subcode);

/**
 * Report firmware failure from previous boot to vboot.
 *
 * This function can only be called before vb2api_fw_phase1 (nvdata is
 * initialized). Otherwise an assert is raised. This function is required to be
 * called in the following environment:
 * - Context has to be initialized using vb2api_init
 * - NV data has to be read into context
 * - Secdata may or may not have been read
 * - vb2api_fw_phase1 must not have been called.
 *
 * If the other slot is not known bad then try the other firmware slot.
 * If both the slots are known bad, then request recovery.
 *
 * @param reason	Recovery reason
 * @param subcode	Recovery subcode
 */
void vb2api_previous_boot_fail(struct vb2_context *ctx,
			       uint8_t reason, uint8_t subcode);

/**
 * Entry point for setting up a context that can only load and verify a kernel.
 *
 * The only allowed usage is to call vb2api_init, then this entry point,
 * then vb2api_load_kernel.
 *
 * @param ctx				Vboot context
 * @param kernel_packed_key_data	Packed public key for kernel
 *					verification
 * @param kernel_packed_key_data_size	Size in bytes of kernel_packed_key_data
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_inject_kernel_subkey(struct vb2_context *ctx,
					const uint8_t *kernel_packed_key_data,
					uint32_t kernel_packed_key_data_size);

/**
 * Firmware selection, phase 1.
 *
 * If the returned error is VB2_ERROR_API_PHASE1_RECOVERY, the calling firmware
 * should jump directly to recovery-mode firmware without rebooting.
 *
 * For other errors, the calling firmware should check for updates to secdata
 * and/or nvdata, then reboot.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_fw_phase1(struct vb2_context *ctx);

/**
 * Firmware selection, phase 2.
 *
 * On error, the calling firmware should check for updates to secdata and/or
 * nvdata, then reboot.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_fw_phase2(struct vb2_context *ctx);

/**
 * Firmware selection, phase 3.
 *
 * On error, the calling firmware should check for updates to secdata and/or
 * nvdata, then reboot.
 *
 * On success, the calling firmware should lock down secdata before continuing
 * with the boot process.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_fw_phase3(struct vb2_context *ctx);

/**
 * Initialize hashing data for the specified tag.
 * This function is not legal when running from a coreboot image that has
 * CONFIG_VBOOT_CBFS_INTEGRATION=y set. In that case, vb2api_get_metadata_hash()
 * must be used instead.
 *
 * @param ctx		Vboot context
 * @param tag		Tag to start hashing (enum vb2_hash_tag)
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_init_hash(struct vb2_context *ctx, uint32_t tag);

/**
 * Extend the hash started by vb2api_init_hash() with additional data.
 *
 * (This is the same for both old and new style structs.)
 *
 * @param ctx		Vboot context
 * @param buf		Data to hash
 * @param size		Size of data in bytes
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_extend_hash(struct vb2_context *ctx, const void *buf,
			       uint32_t size);

/**
 * Check the hash value started by vb2api_init_hash().
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
int vb2api_check_hash(struct vb2_context *ctx);

/**
 * Check the hash value started by vb2api_init_hash() while retrieving
 * calculated digest.
 *
 * @param ctx			Vboot context
 * @param digest_out		optional pointer to buffer to store digest
 * @param digest_out_size	optional size of buffer to store digest
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_check_hash_get_digest(struct vb2_context *ctx,
					 void *digest_out,
					 uint32_t digest_out_size);

/**
 * Get pointer to metadata hash from body signature in preamble.
 * Body signature data size has to be zero to indicate that it contains
 * metadata hash. This is only legal to call after vb2api_fw_phase3() has
 * returned successfully, and will return with error otherwise.
 * This function is only legal to call from coreboot with
 * CONFIG_VBOOT_CBFS_INTEGRATION=y. `futility sign` will automatically detect
 * the presence of that option in an image and prepare the correct kind
 * of signature.
 *
 * @param ctx			Vboot context
 * @param hash_ptr_out		pointer to output hash to
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_get_metadata_hash(struct vb2_context *ctx,
				     struct vb2_hash **hash_ptr_out);

/**
 * Get a PCR digest
 *
 * @param ctx		Vboot context
 * @param which_digest	PCR index of the digest
 * @param dest		Destination where the digest is copied.
 * 			Recommended size is VB2_PCR_DIGEST_RECOMMENDED_SIZE.
 * @param dest_size	IN: size of the buffer pointed by dest
 * 			OUT: size of the copied digest
 * @return VB2_SUCCESS, or error code on error
 */
vb2_error_t vb2api_get_pcr_digest(struct vb2_context *ctx,
				  enum vb2_pcr_digest which_digest,
				  uint8_t *dest, uint32_t *dest_size);

/**
 * Prepare for kernel verification stage.
 *
 * Must be called before other vb2api kernel functions.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_kernel_phase1(struct vb2_context *ctx);

/**
 * Do kernel verification.
 *
 * Must be called after vb2api_kernel_phase1.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_kernel_phase2(struct vb2_context *ctx);

/**
 * Finalize for kernel verification stage.
 *
 * Handle NO_BOOT flag. Also, check and roll forward kernel version.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_kernel_finalize(struct vb2_context *ctx);

struct vb2_kernel_params {
	/* Inputs to vb2api_load_kernel(). */
	/* Destination buffer for kernel (normally at 0x100000 on x86). */
	void *kernel_buffer;
	/* Size of kernel buffer in bytes. */
	uint32_t kernel_buffer_size;

	/*
	 * Outputs from vb2api_load_kernel(); valid only if it returns success.
	 */
	/* Handle of disk containing loaded kernel. */
	vb2ex_disk_handle_t disk_handle;
	/* Partition number on disk to boot (1...M). */
	uint32_t partition_number;
	/* Offset of bootloader image from `kernel_buffer` address. */
	uint64_t bootloader_offset;
	/* Size of bootloader image in bytes. */
	uint32_t bootloader_size;
	/* UniquePartitionGuid for boot partition. */
	uint8_t partition_guid[16];
	/* Flags set by signer. */
	uint32_t flags;
};

/*****************************************************************************/
/* Disk access */

/* Flags for vb2_disk_info */

/*
 * Disk selection in the lower 16 bits (where the disk lives), and disk
 * attributes in the higher 16 bits (extra information about the disk
 * needed to access it correctly).
 */
#define VB2_DISK_FLAG_SELECT_MASK 0xffff
#define VB2_DISK_FLAG_ATTRIBUTE_MASK (0xffff << 16)

/*
 * Disks are used in two ways:
 * - As a random-access device to read and write the GPT
 * - As a streaming device to read the kernel
 * These are implemented differently on raw NAND vs eMMC/SATA/USB
 * - On eMMC/SATA/USB, both of these refer to the same underlying
 *   storage, so they have the same size and LBA size. In this case,
 *   the GPT should not point to the same address as itself.
 * - On raw NAND, the GPT is held on a portion of the SPI flash.
 *   Random access GPT operations refer to the SPI and streaming
 *   operations refer to NAND. The GPT may therefore point into
 *   the same offsets as itself.
 * These types are distinguished by the following flag and vb2_disk_info
 * has separate fields to describe the random-access ("GPT") and
 * streaming aspects of the disk. If a disk is random-access (i.e.
 * not raw NAND) then these fields are equal.
 */
#define VB2_DISK_FLAG_EXTERNAL_GPT (1 << 16)

/* Information on a single disk. */
struct vb2_disk_info {
	/* Disk handle. */
	vb2ex_disk_handle_t handle;
	/* Size of a random-access LBA sector in bytes. */
	uint64_t bytes_per_lba;
	/* Number of random-access LBA sectors on the device.
	 * If streaming_lba_count is 0, this stands in for the size of the
	 * randomly accessed portion as well as the streaming portion.
	 * Otherwise, this is only the randomly-accessed portion. */
	uint64_t lba_count;
	/* Number of streaming sectors on the device. */
	uint64_t streaming_lba_count;
	/* Flags (see VB2_DISK_FLAG_* constants). */
	uint32_t flags;
	/*
	 * Optional name string, for use in debugging.  May be empty or null if
	 * not available.
	 */
	const char *name;
};

/**
 * Attempt to load kernel from the specified device. On success, the output
 * fields of params will be filled. The caller should set the input fields of
 * params.
 *
 *
 * @param ctx		Vboot context
 * @param params	Params specific to loading the kernel
 * @param disk_info	Disk from which to read kernel
 *
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2api_load_kernel(struct vb2_context *ctx,
			       struct vb2_kernel_params *params,
			       struct vb2_disk_info *disk_info);

/* miniOS flags */

/* Boot from non-active miniOS partition only. */
#define VB2_MINIOS_FLAG_NON_ACTIVE (1 << 0)

/**
 * Attempt to load miniOS kernel from the specified device. On success, the
 * output fields of params will be filled. The caller should set the input
 * fields of params.
 *
 * @param ctx		Vboot context
 * @param params	Params specific to loading the kernel
 * @param disk_info	Disk from which to read kernel
 * @param minios_flags	Flags for miniOS
 *
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2api_load_minios_kernel(struct vb2_context *ctx,
				      struct vb2_kernel_params *params,
				      struct vb2_disk_info *disk_info,
				      uint32_t minios_flags);

/**
 * Load the verified boot block (vblock) for a kernel.
 *
 * This function may be called multiple times, to load and verify the
 * vblocks from multiple kernel partitions.
 *
 * @param ctx		Vboot context
 * @param stream	Kernel stream
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_load_kernel_vblock(struct vb2_context *ctx);

/**
 * Get the size and offset of the kernel data for the most recent vblock.
 *
 * Valid after a successful call to vb2api_load_kernel_vblock().
 *
 * @param ctx		Vboot context
 * @param offset_ptr	Destination for offset in bytes of kernel data as
 *			reported by vblock.
 * @param size_ptr      Destination for size of kernel data in bytes.
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_get_kernel_size(struct vb2_context *ctx,
				   uint32_t *offset_ptr, uint32_t *size_ptr);

/**
 * Verify kernel data using the previously loaded kernel vblock.
 *
 * Valid after a successful call to vb2api_load_kernel_vblock().  This allows
 * the caller to load or map the kernel data, as appropriate, and pass the
 * pointer to the kernel data into vboot.
 *
 * @param ctx		Vboot context
 * @param buf		Pointer to kernel data
 * @param size		Size of kernel data in bytes
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_verify_kernel_data(struct vb2_context *ctx, const void *buf,
				      uint32_t size);

/**
 * Clean up after kernel verification.
 *
 * Call this after successfully loading a vblock and verifying kernel data,
 * or if you've run out of boot devices and/or kernel partitions.
 *
 * This cleans up intermediate data structures in the vboot context, and
 * updates the version in the secure data if necessary.
 */
vb2_error_t vb2api_kernel_phase3(struct vb2_context *ctx);

/**
 * Read the hardware ID from the GBB, and store it onto the given buffer.
 *
 * @param ctx		Vboot context.
 * @param hwid		Buffer to store HWID, which will be null-terminated.
 * @param size		Maximum size of HWID including null terminator.  HWID
 * 			length may not exceed 256 (VB2_GBB_HWID_MAX_SIZE), so
 * 			this value is suggested.  If size is too small, then
 * 			VB2_ERROR_INVALID_PARAMETER is returned.  Actual size
 * 			of the output HWID string is returned in this pointer,
 * 			also including null terminator.
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2api_gbb_read_hwid(struct vb2_context *ctx, char *hwid,
				 uint32_t *size);

/**
 * Retrieve current GBB flags.
 *
 * See enum vb2_gbb_flag in 2gbb_flags.h for a list of all GBB flags.
 *
 * @param ctx		Vboot context.
 *
 * @return vb2_gbb_flags_t representing current GBB flags.
 */
vb2_gbb_flags_t vb2api_gbb_get_flags(struct vb2_context *ctx);

/**
 * Get the size of the signed firmware body.
 *
 * This is only legal to call after vb2api_fw_phase3() has returned
 * successfully, and will die otherwise. This should never be called when
 * running from a coreboot image that has CONFIG_VBOOT_CBFS_INTEGRATION=y set,
 * or it will also die (with data size in signature being 0). In that case,
 * vb2api_get_metadata_hash() should be used instead.
 *
 * @param ctx		Vboot context
 *
 * @return The firmware body size in bytes (or 0 if called too early).
 */
uint32_t vb2api_get_firmware_size(struct vb2_context *ctx);

/**
 * Check if this firmware was bundled with the well-known public developer key
 * set (more specifically, checks the recovery key in recovery mode and the
 * kernel subkey from the firmware preamble in other modes). This is a best
 * effort check that could be misled by a specifically crafted key.
 *
 * May only be called after vb2api_kernel_phase1() has run.
 *
 * @param ctx		Vboot context
 *
 * @return 1 for developer keys, 0 for any others.
 */
int vb2api_is_developer_signed(struct vb2_context *ctx);

/**
 * Return the current kernel rollback version from secdata.
 *
 * @param ctx		Vboot context
 *
 * @return The rollback version number.
 */
uint32_t vb2api_get_kernel_rollback_version(struct vb2_context *ctx);

/**
 * If no display is available, set DISPLAY_REQUEST in nvdata.
 *
 * @param ctx           Vboot2 context
 * @return 1 if DISPLAY_REQUEST is set and a reboot is required, or 0 otherwise.
 */
int vb2api_need_reboot_for_display(struct vb2_context *ctx);

/**
 * Get the current recovery reason.
 *
 * See enum vb2_nv_recovery in 2recovery_reasons.h.
 *
 * @param ctx		Vboot context
 * @return Current recovery reason.
 */
uint32_t vb2api_get_recovery_reason(struct vb2_context *ctx);

/**
 * Get the current locale id from nvdata.
 *
 * @param ctx		Vboot context
 * @return Current locale id.
 */
uint32_t vb2api_get_locale_id(struct vb2_context *ctx);

/**
 * Set the locale id in nvdata.
 *
 * @param ctx		Vboot context
 * @param locale_id 	The locale id to be set
 */
void vb2api_set_locale_id(struct vb2_context *ctx, uint32_t locale_id);

/**
 * Whether diagnostic UI functionality is enabled or not.
 *
 * @param ctx		Vboot context
 * @return 1 if enabled, 0 if disabled.
 */
int vb2api_diagnostic_ui_enabled(struct vb2_context *ctx);

/* Default boot target in developer mode. */
enum vb2_dev_default_boot_target {
	/* Default to boot from internal disk. */
	VB2_DEV_DEFAULT_BOOT_TARGET_INTERNAL = 0,

	/* Default to boot from external disk. */
	VB2_DEV_DEFAULT_BOOT_TARGET_EXTERNAL = 1,

	/* Default to boot altfw. */
	VB2_DEV_DEFAULT_BOOT_TARGET_ALTFW = 2,
};

/**
 * Get the default boot target in developer mode. This function must be called
 * after vb2api_kernel_phase1.
 *
 * @param ctx		Vboot context
 * @return The developer mode default boot target.
 */
enum vb2_dev_default_boot_target vb2api_get_dev_default_boot_target(
	struct vb2_context *ctx);

/**
 * Whether to use short delay instead of the normal delay in developer screens.
 *
 * @param ctx		Vboot context
 * @return 1 for short delay and 0 otherwise.
 */
int vb2api_use_short_dev_screen_delay(struct vb2_context *ctx);

/**
 * Request to enable developer mode.
 *
 * Enables the developer flag in vb2_context firmware secdata.  Note that
 * modified secdata must be saved for change to apply on reboot.
 *
 * NOTE: Doesn't update the LAST_BOOT_DEVELOPER secdata flag.  That should be
 * done on the next boot.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS if success; error if enabling developer mode is not
 * allowed.
 */
vb2_error_t vb2api_enable_developer_mode(struct vb2_context *ctx);

/**
 * Request to disable developer mode by setting VB2_NV_DISABLE_DEV_REQUEST.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS if success; other errors if the check of
 * VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON failed.
 */
vb2_error_t vb2api_disable_developer_mode(struct vb2_context *ctx);

/**
 * Request diagnostics by setting VB2_NV_DIAG_REQUEST.
 *
 * @param ctx		Vboot context
 */
void vb2api_request_diagnostics(struct vb2_context *ctx);

/*****************************************************************************/
/* APIs provided by the caller to verified boot */

/**
 * Read a verified boot resource.
 *
 * @param ctx		Vboot context
 * @param index		Resource index to read
 * @param offset	Byte offset within resource to start at
 * @param buf		Destination for data
 * @param size		Amount of data to read
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_read_resource(struct vb2_context *ctx,
				enum vb2_resource_index index, uint32_t offset,
				void *buf, uint32_t size);

/**
 * Print debug output.
 *
 * This should work like printf().  If func!=NULL, it will be a string with
 * the current function name; that can be used to generate prettier debug
 * output.  If func==NULL, don't print any extra header/trailer so that this
 * can be used to composite a bigger output string from several calls - for
 * example, when doing a hex dump.
 *
 * @param func		Function name generating output, or NULL.
 * @param fmt		Printf format string
 */
__attribute__((format(printf, 2, 3)))
void vb2ex_printf(const char *func, const char *fmt, ...);

/**
 * Initialize the hardware crypto engine to calculate a block-style digest.
 *
 * @param hash_alg	Hash algorithm to use
 * @param data_size	Expected total size of data to hash, or 0. If 0, the
 *			total size is not known in advance. Implementations that
 *			cannot handle unknown sizes should return UNSUPPORTED
 *			in that case. If the value is non-zero, implementations
 *			can trust it to be accurate.
 * @return VB2_SUCCESS, or non-zero error code (HWCRYPTO_UNSUPPORTED not fatal).
 */
vb2_error_t vb2ex_hwcrypto_digest_init(enum vb2_hash_algorithm hash_alg,
				       uint32_t data_size);

/**
 * Extend the hash in the hardware crypto engine with another block of data.
 *
 * @param buf		Next data block to hash
 * @param size		Length of data block in bytes
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_hwcrypto_digest_extend(const uint8_t *buf, uint32_t size);

/**
 * Finalize the digest in the hardware crypto engine and extract the result.
 *
 * @param digest	Destination buffer for resulting digest
 * @param digest_size	Length of digest buffer in bytes
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_hwcrypto_digest_finalize(uint8_t *digest,
					   uint32_t digest_size);

/**
 * Verify a RSA PKCS1.5 signature in hardware crypto engine
 * against an expected hash digest.
 *
 * @param key		Key to use in signature verification
 * @param sig		Signature to verify (destroyed in process)
 * @param digest	Digest of signed data
 * @return VB2_SUCCESS, or non-zero error code (HWCRYPTO_UNSUPPORTED not fatal).
 */
vb2_error_t vb2ex_hwcrypto_rsa_verify_digest(const struct vb2_public_key *key,
					     const uint8_t *sig,
					     const uint8_t *digest);

/**
 * Calculate modexp using hardware crypto engine.
 *
 * @param key		Key to use in signing
 * @param inout		Input and output big-endian byte array
 * @param workbuf	Work buffer
 * @param workbuf_size	Work buffer size
 * @param exp		RSA public exponent: either 65537 (F4) or 3
 * @return VB2_SUCCESS, HWCRYPTO_UNSUPPORTED or WORKBUF_SMALL.
 */
vb2_error_t vb2ex_hwcrypto_modexp(const struct vb2_public_key *key,
				  uint8_t *inout,
				  void *workbuf, size_t workbuf_size,
				  int exp);

/*
 * Report if hardware crypto is allowed in the current context. It may be
 * disabled by TPM flag and is categorically disallowed in recovery mode.
 *
 * @param ctx		Vboot context
 * @returns 1 if hardware crypto is allowed, 0 if it is forbidden.
 */
bool vb2api_hwcrypto_allowed(struct vb2_context *ctx);

/*
 * Abort vboot flow due to a failed assertion or broken assumption.
 *
 * Likely due to caller misusing vboot (e.g. calling API functions
 * out-of-order, filling in vb2_context fields inappropriately).
 * Implementation should reboot or halt the machine, or fall back to some
 * alternative boot flow.  Retrying vboot is unlikely to succeed.
 */
void vb2ex_abort(void);

/**
 * Commit any pending data to disk.
 *
 * Commit nvdata and secdata spaces if modified.  Normally this should be
 * performed after vboot has completed executing and control has been passed
 * back to the caller.  However, in certain kernel verification cases (e.g.
 * right before attempting to boot an OS; from a UI screen which requires
 * user-initiated shutdown; just prior to triggering battery cut-off), the
 * caller may not get a chance to commit this data.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_commit_data(struct vb2_context *ctx);

/*****************************************************************************/
/* TPM functionality */

/**
 * Initialize the TPM.
 *
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_tpm_init(void);

/**
 * Close and open the TPM.
 *
 * This is needed for running more complex commands at user level, such as
 * TPM_TakeOwnership, since the TPM device can be opened only by one process at
 * a time.
 *
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_tpm_close(void);
vb2_error_t vb2ex_tpm_open(void);

/**
 * Send request to TPM and receive response
 *
 * Send a request_length-byte request to the TPM and receive a response.  On
 * input, response_length is the size of the response buffer in bytes.  On
 * exit, response_length is set to the actual received response length in
 * bytes.
 *
 * @param request		Pointer to request buffer
 * @param request_length	Number of bytes to send
 * @param response		Pointer to response buffer
 * @param response_length	Size of response buffer; on return,
 * 				set to number of received bytes
 * @return TPM_SUCCESS, or non-zero if error.
 */
uint32_t vb2ex_tpm_send_recv(const uint8_t *request, uint32_t request_length,
			     uint8_t *response, uint32_t *response_length);

#ifdef CHROMEOS_ENVIRONMENT

/**
 * Obtain cryptographically secure random bytes.
 *
 * This function is used to generate random nonces for TPM auth sessions for
 * example. As an implication, the generated random bytes should not be
 * predictable for a TPM communication interception attack. This implies a
 * local source of randomness should be used, i.e. this should not be wired to
 * the TPM RNG directly. Otherwise, an attacker with communication interception
 * abilities could launch replay attacks by reusing previous nonces.
 *
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_tpm_get_random(uint8_t *buf, uint32_t length);

#endif  /* CHROMEOS_ENVIRONMENT */

/* Modes for vb2ex_tpm_set_mode. */
enum vb2_tpm_mode {
	/*
	 * TPM is enabled tentatively, and may be set to either
	 * ENABLED or DISABLED mode.
	 */
	VB2_TPM_MODE_ENABLED_TENTATIVE = 0,

	/* TPM is enabled, and mode may not be changed. */
	VB2_TPM_MODE_ENABLED = 1,

	/* TPM is disabled, and mode may not be changed. */
	VB2_TPM_MODE_DISABLED = 2,
};

/**
 * Set the current TPM mode value, and validate that it was changed.  If one
 * of the following occurs, the function call fails:
 *   - TPM does not understand the instruction (old version)
 *   - TPM has already left the TpmModeEnabledTentative mode
 *   - TPM responds with a mode other than the requested mode
 *   - Some other communication error occurs
 *  Otherwise, the function call succeeds.
 *
 * @param mode_val       Desired TPM mode to set.  May be one of ENABLED
 *                       or DISABLED from vb2_tpm_mode enum.
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2ex_tpm_set_mode(enum vb2_tpm_mode mode_val);

/**
 * Clear the TPM owner.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_tpm_clear_owner(struct vb2_context *ctx);

/*****************************************************************************/
/* Auxiliary firmware (auxfw) */

/**
 * Sync all auxiliary firmware to the expected versions.
 *
 * This function will first check if an auxfw update is needed and
 * what the "severity" of that update is (i.e., if any auxfw devices
 * exist and the relative quickness of updating it.  If the update is
 * deemed slow, it may display a screen to notify the user.  The
 * platform is then instructed to perform the update.  Finally, an EC
 * reboot to its RO section is performed to ensure that auxfw devices
 * are also reset and running the new firmware.
 *
 * @param ctx           Vboot2 context
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2api_auxfw_sync(struct vb2_context *ctx);

/*
 * severity levels for an auxiliary firmware update request
 */
enum vb2_auxfw_update_severity {
	/* no update needed and no protection needed */
	VB2_AUXFW_NO_DEVICE = 0,
	/* no update needed */
	VB2_AUXFW_NO_UPDATE = 1,
	/* update needed, can be done quickly */
	VB2_AUXFW_FAST_UPDATE = 2,
	/* update needed, "this would take a while..." */
	VB2_AUXFW_SLOW_UPDATE = 3,
};

/*
 * Check if any auxiliary firmware needs updating.
 *
 * This is called after the EC has been updated and is intended to
 * version-check additional firmware blobs such as TCPCs.
 *
 * @param severity	return parameter for health of auxiliary firmware
 *			(see vb2_auxfw_update_severity above)
 * @return VBERROR_... error, VB2_SUCCESS on success.
 */
vb2_error_t vb2ex_auxfw_check(enum vb2_auxfw_update_severity *severity);

/*
 * Perform auxiliary firmware update(s).
 *
 * This is called after the EC has been updated and is intended to
 * update additional firmware blobs such as TCPCs.
 *
 * @return VBERROR_... error, VB2_SUCCESS on success.
 */
vb2_error_t vb2ex_auxfw_update(void);

/*
 * Notify client that vboot is done with auxfw.
 *
 * If auxfw sync was successful, this will be called at the end so that
 * the client may perform actions that require the auxfw to be in its
 * final state.  This may include protecting the communcations tunnels that
 * allow auxiliary firmware updates from the OS.
 *
 * @param ctx		Vboot context
 * @return VBERROR_... error, VB2_SUCCESS on success.
 */
vb2_error_t vb2ex_auxfw_finalize(struct vb2_context *ctx);

/*****************************************************************************/
/* Embedded controller (EC) */

/*
 * Firmware selection type for EC software sync logic.  Note that we store
 * these in a uint32_t because enum maps to int, which isn't fixed-size.
 */
enum vb2_firmware_selection {
	/* Read only firmware for normal or developer path. */
	VB_SELECT_FIRMWARE_READONLY = 3,
	/* Rewritable EC firmware currently set active */
	VB_SELECT_FIRMWARE_EC_ACTIVE = 4,
	/* Rewritable EC firmware currently not set active thus updatable */
	VB_SELECT_FIRMWARE_EC_UPDATE = 5,
	/* Keep this at the end */
	VB_SELECT_FIRMWARE_COUNT,
};

/**
 * Sync the Embedded Controller device to the expected version.
 *
 * This function will check if EC software sync is allowed, and if it
 * is, it will compare the expected image hash to the actual image
 * hash.  If they are the same, the EC will simply jump to its RW
 * firwmare.  Otherwise, the specified flash image will be updated to
 * the new version, and the EC will reboot into its new firmware.
 *
 * @param ctx		Vboot context
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb2api_ec_sync(struct vb2_context *ctx);

/**
 * Check if the EC is currently running rewritable code.
 *
 * If the EC is in RO code, sets *in_rw=0.
 * If the EC is in RW code, sets *in_rw non-zero.
 * If the current EC image is unknown, returns error. */
vb2_error_t vb2ex_ec_running_rw(int *in_rw);

/**
 * Request the EC jump to its rewritable code.  If successful, returns when the
 * EC has booting its RW code far enough to respond to subsequent commands.
 * Does nothing if the EC is already in its rewritable code.
 */
vb2_error_t vb2ex_ec_jump_to_rw(void);

/**
 * Tell the EC to refuse another jump until it reboots. Subsequent calls to
 * vb2ex_ec_jump_to_rw() in this boot will fail.
 */
vb2_error_t vb2ex_ec_disable_jump(void);

/**
 * Read the SHA-256 hash of the selected EC image.
 *
 * @param select    Image to get hash of. RO or RW.
 * @param hash      Pointer to the hash.
 * @param hash_size Pointer to the hash size.
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_ec_hash_image(enum vb2_firmware_selection select,
				const uint8_t **hash, int *hash_size);

/**
 * Read the SHA-256 hash of the expected contents of the EC image associated
 * with the main firmware specified by the "select" argument.
 *
 * @param select	Image to get expected hash for (RO or RW).
 * @param hash		Pointer to the hash.
 * @param hash_size	Pointer to the hash size (in bytes).
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_ec_get_expected_image_hash(enum vb2_firmware_selection select,
					     const uint8_t **hash,
					     int *hash_size);

/**
 * Update the selected EC image to the expected version.
 *
 * @param select	Image to get expected hash for (RO or RW).
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_ec_update_image(enum vb2_firmware_selection select);

/**
 * Lock the EC code to prevent updates until the EC is rebooted.
 * Subsequent calls to vb2ex_ec_update_image() during boot will fail.
 *
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_ec_protect(void);

/**
 * Perform EC post-verification / updating / jumping actions.
 *
 * This routine is called to perform certain actions that must wait until
 * after the EC resides in its `final` image (the image the EC will
 * run for the duration of boot). These actions include verifying that
 * enough power is available to continue with boot.
 *
 * @param ctx		Pointer to vboot context.
 * @return VB2_SUCCESS, or error code on error.
 */
vb2_error_t vb2ex_ec_vboot_done(struct vb2_context *ctx);

/**
 * Request EC to stop discharging and cut-off battery.
 */
vb2_error_t vb2ex_ec_battery_cutoff(void);

/*****************************************************************************/
/* Functions for firmware UI. */

/**
 * Get the vboot debug info.
 *
 * Return a pointer to the vboot debug info string which is guaranteed to be
 * null-terminated.  The caller owns the string and should call free() when
 * finished with it.
 *
 * @param ctx		Vboot context
 * @return The pointer to the vboot debug info string.  NULL on error.
 */
char *vb2api_get_debug_info(struct vb2_context *ctx);

/*****************************************************************************/
/* Timer. */

/**
 * Read a millisecond timer.
 *
 * This should have a sufficient number of bits to avoid wraparound for at
 * least 10 minutes.
 *
 * @return Current timer value in milliseconds.
 */
uint32_t vb2ex_mtime(void);

/*****************************************************************************/
/* Firmware slot information. */

union vb2_fw_boot_info {
	uint8_t raw[4];
	struct {
		uint8_t tries       : 4;
		uint8_t slot        : 1;
		uint8_t prev_slot   : 1;
		uint8_t prev_result : 2;
		uint8_t boot_mode;
		/* The following 2 bytes only exist for recovery mode */
		uint8_t recovery_reason;
		uint8_t recovery_subcode;
	};
};

/**
 * Return `vb2_fw_boot_info` and can be used
 * to log information about the current boot in a compact format.
 *
 * Note: Only call this API at minimum after `vb2api_fw_phase2` function
 * returns.
 *
 * @param ctx          Vboot context
 * @return filled out vb2 info as per `union vb2_fw_boot_info`.
 */
union vb2_fw_boot_info vb2api_get_fw_boot_info(struct vb2_context *ctx);

/**
 * Clear recovery request appropriately.
 *
 * To avoid the recovery request "sticking" and the user being in a permanent
 * recovery loop, the recovery request must be cleared and committed to nvdata.
 * Note that this should be done at some point after we are certain the system
 * does not require any reboots for non-vboot-related reasons (e.g. FSP
 * initialization), and before triggering a reboot to exit a transient recovery
 * mode (e.g. memory retraining request).
 *
 * In BROKEN cases, the recovery reason will be stowed away as subcode, to be
 * retrieved after the user reboots in manual recovery.  In manual recovery,
 * subcode will be left alone to keep available for subsequent manual recovery
 * requests, or for accessing from userspace on the next boot.
 *
 * This function modifies nvdata in vb2_context, but the caller is still
 * expected to call vb2_commit_data.
 *
 * @param ctx		Vboot context
 */
void vb2api_clear_recovery(struct vb2_context *ctx);

#endif  /* VBOOT_REFERENCE_2API_H_ */
