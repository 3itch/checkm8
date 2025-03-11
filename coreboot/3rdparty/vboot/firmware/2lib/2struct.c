/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions for reading, checking and verifying firmware and
 * kernel data structures.
 */

#include "2common.h"

vb2_error_t vb2_check_keyblock(const struct vb2_keyblock *block, uint32_t size,
			       const struct vb2_signature *sig)
{
	if (size < sizeof(*block)) {
		VB2_DEBUG("Not enough space for keyblock header.\n");
		return VB2_ERROR_KEYBLOCK_TOO_SMALL_FOR_HEADER;
	}

	if (memcmp(block->magic, VB2_KEYBLOCK_MAGIC, VB2_KEYBLOCK_MAGIC_SIZE)) {
		VB2_DEBUG("Not a valid verified boot keyblock.\n");
		return VB2_ERROR_KEYBLOCK_MAGIC;
	}

	if (block->header_version_major != VB2_KEYBLOCK_VERSION_MAJOR) {
		VB2_DEBUG("Incompatible keyblock header version.\n");
		return VB2_ERROR_KEYBLOCK_HEADER_VERSION;
	}

	if (size < block->keyblock_size) {
		VB2_DEBUG("Not enough data for keyblock.\n");
		return VB2_ERROR_KEYBLOCK_SIZE;
	}

	if (vb2_verify_signature_inside(block, block->keyblock_size, sig)) {
		VB2_DEBUG("Keyblock signature off end of block\n");
		return VB2_ERROR_KEYBLOCK_SIG_OUTSIDE;
	}

	/* Make sure advertised signature data sizes are valid. */
	if (block->keyblock_size < sig->data_size) {
		VB2_DEBUG("Signature calculated past end of block\n");
		return VB2_ERROR_KEYBLOCK_SIGNED_TOO_MUCH;
	}

	/* Verify we signed enough data */
	if (sig->data_size < sizeof(struct vb2_keyblock)) {
		VB2_DEBUG("Didn't sign enough data\n");
		return VB2_ERROR_KEYBLOCK_SIGNED_TOO_LITTLE;
	}

	/* Verify data key is inside the block and inside signed data */
	if (vb2_verify_packed_key_inside(block, block->keyblock_size,
					 &block->data_key)) {
		VB2_DEBUG("Data key off end of keyblock\n");
		return VB2_ERROR_KEYBLOCK_DATA_KEY_OUTSIDE;
	}
	if (vb2_verify_packed_key_inside(block, sig->data_size,
					 &block->data_key)) {
		VB2_DEBUG("Data key off end of signed data\n");
		return VB2_ERROR_KEYBLOCK_DATA_KEY_UNSIGNED;
	}

	return VB2_SUCCESS;
}

test_mockable
vb2_error_t vb2_verify_keyblock(struct vb2_keyblock *block, uint32_t size,
				const struct vb2_public_key *key,
				const struct vb2_workbuf *wb)
{
	struct vb2_signature *sig = &block->keyblock_signature;
	vb2_error_t rv;

	/* Validity check keyblock before attempting signature check of data */
	VB2_TRY(vb2_check_keyblock(block, size, sig));

	VB2_DEBUG("Checking keyblock signature...\n");
	rv = vb2_verify_data((const uint8_t *)block, size, sig, key, wb);
	if (rv) {
		VB2_DEBUG("Invalid keyblock signature.\n");
		return VB2_ERROR_KEYBLOCK_SIG_INVALID;
	}

	/* Success */
	return VB2_SUCCESS;
}

vb2_error_t vb2_verify_fw_preamble(struct vb2_fw_preamble *preamble,
				   uint32_t size,
				   const struct vb2_public_key *key,
				   const struct vb2_workbuf *wb)
{
	struct vb2_signature *sig = &preamble->preamble_signature;

	VB2_DEBUG("Verifying preamble.\n");

	/* Validity checks before attempting signature of data */
	if (size < sizeof(*preamble)) {
		VB2_DEBUG("Not enough data for preamble header\n");
		return VB2_ERROR_PREAMBLE_TOO_SMALL_FOR_HEADER;
	}
	if (preamble->header_version_major !=
	    VB2_FIRMWARE_PREAMBLE_HEADER_VERSION_MAJOR) {
		VB2_DEBUG("Incompatible firmware preamble header version.\n");
		return VB2_ERROR_PREAMBLE_HEADER_VERSION;
	}

	if (preamble->header_version_minor < 1) {
		VB2_DEBUG("Only preamble header 2.1+ supported\n");
		return VB2_ERROR_PREAMBLE_HEADER_OLD;
	}

	if (size < preamble->preamble_size) {
		VB2_DEBUG("Not enough data for preamble.\n");
		return VB2_ERROR_PREAMBLE_SIZE;
	}

	/* Check signature */
	if (vb2_verify_signature_inside(preamble, preamble->preamble_size,
					sig)) {
		VB2_DEBUG("Preamble signature off end of preamble\n");
		return VB2_ERROR_PREAMBLE_SIG_OUTSIDE;
	}

	/* Make sure advertised signature data sizes are valid. */
	if (preamble->preamble_size < sig->data_size) {
		VB2_DEBUG("Signature calculated past end of the block\n");
		return VB2_ERROR_PREAMBLE_SIGNED_TOO_MUCH;
	}

	if (vb2_verify_data((const uint8_t *)preamble, size, sig, key, wb)) {
		VB2_DEBUG("Preamble signature validation failed\n");
		return VB2_ERROR_PREAMBLE_SIG_INVALID;
	}

	/* Verify we signed enough data */
	if (sig->data_size < sizeof(struct vb2_fw_preamble)) {
		VB2_DEBUG("Didn't sign enough data\n");
		return VB2_ERROR_PREAMBLE_SIGNED_TOO_LITTLE;
	}

	/* Verify body signature is inside the signed data */
	if (vb2_verify_signature_inside(preamble, sig->data_size,
					&preamble->body_signature)) {
		VB2_DEBUG("Firmware body signature off end of preamble\n");
		return VB2_ERROR_PREAMBLE_BODY_SIG_OUTSIDE;
	}

	/* Verify kernel subkey is inside the signed data */
	if (vb2_verify_packed_key_inside(preamble, sig->data_size,
					 &preamble->kernel_subkey)) {
		VB2_DEBUG("Kernel subkey off end of preamble\n");
		return VB2_ERROR_PREAMBLE_KERNEL_SUBKEY_OUTSIDE;
	}

	/* Success */
	return VB2_SUCCESS;
}

uint32_t vb2_kernel_get_flags(const struct vb2_kernel_preamble *preamble)
{
	if (preamble->header_version_minor < 2)
		return 0;

	return preamble->flags;
}

test_mockable
vb2_error_t vb2_verify_keyblock_hash(const struct vb2_keyblock *block,
				     uint32_t size,
				     const struct vb2_workbuf *wb)
{
	const struct vb2_signature *sig = &block->keyblock_hash;
	struct vb2_hash hash;

	/* Validity check keyblock before attempting hash check of data */
	VB2_TRY(vb2_check_keyblock(block, size, sig));

	VB2_DEBUG("Checking keyblock hash...\n");

	/* This is only used in developer mode, so hwcrypto not important. */
	VB2_TRY(vb2_hash_calculate(false, block, sig->data_size,
				   VB2_HASH_SHA512, &hash));

	if (vb2_safe_memcmp(vb2_signature_data(sig), hash.sha512,
			    sizeof(hash.sha512)) != 0) {
		VB2_DEBUG("Invalid keyblock hash.\n");
		return VB2_ERROR_KEYBLOCK_HASH_INVALID_IN_DEV_MODE;
	}

	/* Success */
	return VB2_SUCCESS;
}

test_mockable
vb2_error_t vb2_verify_kernel_preamble(struct vb2_kernel_preamble *preamble,
				       uint32_t size,
				       const struct vb2_public_key *key,
				       const struct vb2_workbuf *wb)
{
	struct vb2_signature *sig = &preamble->preamble_signature;
	uint32_t min_size = EXPECTED_VB2_KERNEL_PREAMBLE_2_0_SIZE;

	VB2_DEBUG("Verifying kernel preamble.\n");

	/* Make sure it's even safe to look at the struct */
	if (size < min_size) {
		VB2_DEBUG("Not enough data for preamble header.\n");
		return VB2_ERROR_PREAMBLE_TOO_SMALL_FOR_HEADER;
	}
	if (preamble->header_version_major !=
	    VB2_KERNEL_PREAMBLE_HEADER_VERSION_MAJOR) {
		VB2_DEBUG("Incompatible kernel preamble header version.\n");
		return VB2_ERROR_PREAMBLE_HEADER_VERSION;
	}

	if (preamble->header_version_minor >= 2)
		min_size = EXPECTED_VB2_KERNEL_PREAMBLE_2_2_SIZE;
	else if (preamble->header_version_minor == 1)
		min_size = EXPECTED_VB2_KERNEL_PREAMBLE_2_1_SIZE;
	if (preamble->preamble_size < min_size) {
		VB2_DEBUG("Preamble size too small for header.\n");
		return VB2_ERROR_PREAMBLE_TOO_SMALL_FOR_HEADER;
	}
	if (size < preamble->preamble_size) {
		VB2_DEBUG("Not enough data for preamble.\n");
		return VB2_ERROR_PREAMBLE_SIZE;
	}

	/* Check signature */
	if (vb2_verify_signature_inside(preamble, preamble->preamble_size,
					sig)) {
		VB2_DEBUG("Preamble signature off end of preamble\n");
		return VB2_ERROR_PREAMBLE_SIG_OUTSIDE;
	}

	/* Make sure advertised signature data sizes are valid. */
	if (preamble->preamble_size < sig->data_size) {
		VB2_DEBUG("Signature calculated past end of the block\n");
		return VB2_ERROR_PREAMBLE_SIGNED_TOO_MUCH;
	}

	if (vb2_verify_data((const uint8_t *)preamble, size, sig, key, wb)) {
		VB2_DEBUG("Preamble signature validation failed\n");
		return VB2_ERROR_PREAMBLE_SIG_INVALID;
	}

	/* Verify we signed enough data */
	if (sig->data_size < sizeof(struct vb2_fw_preamble)) {
		VB2_DEBUG("Didn't sign enough data\n");
		return VB2_ERROR_PREAMBLE_SIGNED_TOO_LITTLE;
	}

	/* Verify body signature is inside the signed data */
	if (vb2_verify_signature_inside(preamble, sig->data_size,
					&preamble->body_signature)) {
		VB2_DEBUG("Body signature off end of preamble\n");
		return VB2_ERROR_PREAMBLE_BODY_SIG_OUTSIDE;
	}

	/*
	 * If bootloader is present, verify it's covered by the body
	 * signature.
	 */
	if (preamble->bootloader_size) {
		const void *body_ptr =
			(const void *)(uintptr_t)preamble->body_load_address;
		const void *bootloader_ptr =
			(const void *)(uintptr_t)preamble->bootloader_address;
		if (vb2_verify_member_inside(body_ptr,
					     preamble->body_signature.data_size,
					     bootloader_ptr,
					     preamble->bootloader_size,
					     0, 0)) {
			VB2_DEBUG("Bootloader off end of signed data\n");
			return VB2_ERROR_PREAMBLE_BOOTLOADER_OUTSIDE;
		}
	}

	/*
	 * If vmlinuz header is present, verify it's covered by the body
	 * signature.
	 */
	if (preamble->header_version_minor >= 1 &&
	    preamble->vmlinuz_header_size) {
		const void *body_ptr =
			(const void *)(uintptr_t)preamble->body_load_address;
		const void *vmlinuz_header_ptr = (const void *)
			(uintptr_t)preamble->vmlinuz_header_address;
		if (vb2_verify_member_inside(body_ptr,
					     preamble->body_signature.data_size,
					     vmlinuz_header_ptr,
					     preamble->vmlinuz_header_size,
					     0, 0)) {
			VB2_DEBUG("Vmlinuz header off end of signed data\n");
			return VB2_ERROR_PREAMBLE_VMLINUZ_HEADER_OUTSIDE;
		}
	}

	/* Success */
	return VB2_SUCCESS;
}
