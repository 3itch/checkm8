/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_2RSA_H_
#define VBOOT_REFERENCE_2RSA_H_

#include "2crypto.h"
#include "2return_codes.h"

struct vb2_workbuf;

/* Public key structure in RAM */
struct vb2_public_key {
	uint32_t arrsize;    /* Length of n[] and rr[] in number of uint32_t */
	uint32_t n0inv;      /* -1 / n[0] mod 2^32 */
	const uint32_t *n;   /* Modulus as little endian array */
	const uint32_t *rr;  /* R^2 as little endian array */
	enum vb2_signature_algorithm sig_alg;	/* Signature algorithm */
	enum vb2_hash_algorithm hash_alg;	/* Hash algorithm */
	const char *desc;			/* Description */
	uint32_t version;			/* Key version */
	const struct vb2_id *id;		/* Key ID */
	bool allow_hwcrypto;			/* Is hwcrypto allowed for key */
};

/**
 * Return the size of a RSA signature
 *
 * @param sig_alg	Signature algorithm
 * @return The size of the signature in bytes, or 0 if error.
 */
uint32_t vb2_rsa_sig_size(enum vb2_signature_algorithm sig_alg);

/**
 * Return the size of a pre-processed RSA public key.
 *
 * @param sig_alg	Signature algorithm
 * @return The size of the preprocessed key in bytes, or 0 if error.
 */
uint32_t vb2_packed_key_size(enum vb2_signature_algorithm sig_alg);

/* Size of work buffer sufficient for vb2_rsa_verify_digest() worst case */
#if defined(ENABLE_HWCRYPTO_RSA_TESTS)
#define VB2_VERIFY_RSA_DIGEST_WORKBUF_BYTES ((11 * 1024) + 8)
#else
#define VB2_VERIFY_RSA_DIGEST_WORKBUF_BYTES (3 * 1024)
#endif

/**
 * Verify a RSA PKCS1.5 signature against an expected hash digest.
 *
 * @param key		Key to use in signature verification
 * @param sig		Signature to verify (destroyed in process)
 * @param digest	Digest of signed data
 * @param wb		Work buffer
 * @return VB2_SUCCESS, or non-zero if error.
 */
vb2_error_t vb2_rsa_verify_digest(const struct vb2_public_key *key,
				  uint8_t *sig, const uint8_t *digest,
				  const struct vb2_workbuf *wb);

/**
 * In-place public exponentiation.
 *
 * @param key		Key to use in signing
 * @param inout		Input and output big-endian byte array
 * @param workbuf	Work buffer; caller must verify this is
 *			(3 * key->arrsize) elements long.
 * @param exp		RSA public exponent: either 65537 (F4) or 3
 */
void vb2_modexp(const struct vb2_public_key *key, uint8_t *inout,
		void *workbuf, int exp);

#endif  /* VBOOT_REFERENCE_2RSA_H_ */
