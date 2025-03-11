/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_HOST_P11_H_
#define VBOOT_REFERENCE_HOST_P11_H_

#include "2id.h"
#include "2return_codes.h"
#include "2struct.h"

/* Pkcs11 key for the signing */
struct pkcs11_key;

/**
 * Initialize the pkcs11 library. Note that there is only one pkcs11 module can be loaded
 * at a time.
 *
 * @param pkcs11_lib	Path of the Pkcs11 library to be initialized
 *
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t pkcs11_init(const char *pkcs11_lib);

/**
 * Get the pkcs11 key by the slot id and label.
 *
 * @param slot_id	Slot id of the pkcs11 key
 * @param label		Label of the pkcs11 key
 *
 * @return Pointer to pkcs11 key, or NULL on error.
 */
struct pkcs11_key *pkcs11_get_key(int slot_id, char *label);

/**
 * Get the signature algorithm of the pkcs11 key.
 *
 * @param p11_key	Pkcs11 Key
 *
 * @return  The hash algorithm of pkcs11 key
 */
enum vb2_hash_algorithm pkcs11_get_hash_alg(struct pkcs11_key *p11_key);

/**
 * Get the signature algorithm of the pkcs11 key.
 *
 * @param p11_key	Pkcs11 Key
 *
 * @return  The signature algorithm of pkcs11 key
 */
enum vb2_signature_algorithm pkcs11_get_sig_alg(struct pkcs11_key *p11_key);

/**
 * Get the signature algorithm of the pkcs11 key.
 *
 * @param p11_key	Pkcs11 Key
 * @param sizeptr	Pointer of size of modulus returned.
 *
 * @return The modulus of the pkcs11 key. Caller must free() it.
 */
uint8_t *pkcs11_get_modulus(struct pkcs11_key *p11_key, uint32_t *sizeptr);

/**
 * Calculate a signature for the data using pkcs11 key.
 *
 * @param p11_key	Private key to use to sign data
 * @param hash_alg Hash algorithm used for pkcs11 signing
 * @param data		Pointer to data to sign
 * @param data_size	Size of data in bytes
 * @param sig		Pointer to the output signature
 * @param sig_size	Size of sig in bytes
 *
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t pkcs11_sign(struct pkcs11_key *p11_key, enum vb2_hash_algorithm hash_alg,
			const uint8_t *data, int data_size, uint8_t *sig, uint32_t sig_size);

/**
 * Free a pkcs11 key.
 *
 * @param key		Pkcs11 key to free.
 */
void pkcs11_free_key(struct pkcs11_key *p11_key);

#endif /* VBOOT_REFERENCE_HOST_P11_H_ */
