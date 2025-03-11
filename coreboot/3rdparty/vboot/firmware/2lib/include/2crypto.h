/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Crypto constants for verified boot
 */

#ifndef VBOOT_REFERENCE_2CRYPTO_H_
#define VBOOT_REFERENCE_2CRYPTO_H_

#include "2sysincludes.h"

/* Verified boot crypto algorithms */
enum vb2_crypto_algorithm {
	VB2_ALG_RSA1024_SHA1   = 0,
	VB2_ALG_RSA1024_SHA256 = 1,
	VB2_ALG_RSA1024_SHA512 = 2,
	VB2_ALG_RSA2048_SHA1   = 3,
	VB2_ALG_RSA2048_SHA256 = 4,
	VB2_ALG_RSA2048_SHA512 = 5,
	VB2_ALG_RSA4096_SHA1   = 6,
	VB2_ALG_RSA4096_SHA256 = 7,
	VB2_ALG_RSA4096_SHA512 = 8,
	VB2_ALG_RSA8192_SHA1   = 9,
	VB2_ALG_RSA8192_SHA256 = 10,
	VB2_ALG_RSA8192_SHA512 = 11,
	VB2_ALG_RSA2048_EXP3_SHA1   = 12,
	VB2_ALG_RSA2048_EXP3_SHA256 = 13,
	VB2_ALG_RSA2048_EXP3_SHA512 = 14,
	VB2_ALG_RSA3072_EXP3_SHA1   = 15,
	VB2_ALG_RSA3072_EXP3_SHA256 = 16,
	VB2_ALG_RSA3072_EXP3_SHA512 = 17,
	/* Number of algorithms */
	VB2_ALG_COUNT
};

/* Algorithm types for signatures */
enum vb2_signature_algorithm {
	/* Invalid or unsupported signature type */
	VB2_SIG_INVALID = 0,

	/*
	 * No signature algorithm.  The digest is unsigned.  See
	 * VB2_ID_NONE_* for key IDs to use with this algorithm.
	 */
	VB2_SIG_NONE = 1,

	/* RSA algorithms of the given length in bits (1024-8192) */
	VB2_SIG_RSA1024 = 2,  /* Warning!  This is likely to be deprecated! */
	VB2_SIG_RSA2048 = 3,
	VB2_SIG_RSA4096 = 4,
	VB2_SIG_RSA8192 = 5,
	VB2_SIG_RSA2048_EXP3 = 6,
	VB2_SIG_RSA3072_EXP3 = 7,

	/* Last index. Don't add anything below. */
	VB2_SIG_ALG_COUNT,
};

/* Algorithm types for hash digests */
enum vb2_hash_algorithm {
	/* Invalid or unsupported digest type */
	VB2_HASH_INVALID = 0,
	/* For some applications, it's more useful that 0 means "no hash". */
	VB2_HASH_NONE = VB2_HASH_INVALID,

	/* SHA-1.  Warning: This is likely to be deprecated soon! */
	VB2_HASH_SHA1 = 1,

	/* SHA-256 and SHA-512 */
	VB2_HASH_SHA256 = 2,
	VB2_HASH_SHA512 = 3,

	/* SHA-224/SHA-384 are variants of SHA-256/SHA-512, respectively. */
	VB2_HASH_SHA224 = 4,
	VB2_HASH_SHA384 = 5,

	/* Last index. Don't add anything below. */
	VB2_HASH_ALG_COUNT,
};

/* Arrays mapping signature/hash types to their string representations. */
extern const char *vb2_sig_names[VB2_SIG_ALG_COUNT];
extern const char *vb2_hash_names[VB2_HASH_ALG_COUNT];

/**
 * Convert vb2_crypto_algorithm to vb2_signature_algorithm.
 *
 * @param algorithm	Crypto algorithm (vb2_crypto_algorithm)
 *
 * @return The signature algorithm for that crypto algorithm, or
 * VB2_SIG_INVALID if the crypto algorithm or its corresponding signature
 * algorithm is invalid or not supported.
 */
enum vb2_signature_algorithm vb2_crypto_to_signature(
					enum vb2_crypto_algorithm algorithm);

/**
 * Convert vb2_crypto_algorithm to vb2_hash_algorithm.
 *
 * @param algorithm	Crypto algorithm (vb2_crypto_algorithm)
 *
 * @return The hash algorithm for that crypto algorithm, or VB2_HASH_INVALID if
 * the crypto algorithm or its corresponding hash algorithm is invalid or not
 * supported.
 */
enum vb2_hash_algorithm vb2_crypto_to_hash(enum vb2_crypto_algorithm algorithm);

/**
 * Return the name of a signature algorithm.
 *
 * @param sig_alg	Signature algorithm to look up
 * @return The corresponding name, or VB2_INVALID_ALG_NAME if no match.
 */
const char *vb2_get_sig_algorithm_name(enum vb2_signature_algorithm sig_alg);

/**
 * Return the name of a hash algorithm
 *
 * @param alg	Hash algorithm ID
 * @return The corresponding name, or VB2_INVALID_ALG_NAME if no match.
 */
const char *vb2_get_hash_algorithm_name(enum vb2_hash_algorithm alg);

/**
 * Return the name of a crypto algorithm.
 *
 * @param alg		Crypto algorithm to look up
 * @return The corresponding name, or VB2_INVALID_ALG_NAME if no match.
 */
const char *vb2_get_crypto_algorithm_name(enum vb2_crypto_algorithm alg);

/**
 * Return the name of a crypto algorithm.
 *
 * @param alg		Crypto algorithm to look up
 * @return The corresponding stem filename, or VB2_INVALID_ALG_NAME if no match.
 */
const char *vb2_get_crypto_algorithm_file(enum vb2_crypto_algorithm alg);

#endif  /* VBOOT_REFERENCE_2CRYPTO_H_ */
