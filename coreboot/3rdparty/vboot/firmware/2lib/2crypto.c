/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Hash and signature algorithm parsing helpers for host utilities.
 */

#include "2common.h"
#include "2crypto.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"

/*
 * These two need to be exported for host/lib/crypto.c, but they also need to be
 * in .rodata to make coreboot XIP stages happy. We know they are immutable but
 * there is no C language way to guarantee that, so we have to manually force
 * the compiler to place them in .rodata. Also inject custom section flags so
 * they are only allocatable (a) but not writeable (w).
 */

#ifndef CHROMEOS_ENVIRONMENT
__attribute__((section(".rodata.vb2_sig_names,\"a\"\n# ")))
#endif
const char *vb2_sig_names[VB2_SIG_ALG_COUNT] = {
	[VB2_SIG_NONE]		= "none",
	[VB2_SIG_RSA1024]	= "RSA1024",
	[VB2_SIG_RSA2048]	= "RSA2048",
	[VB2_SIG_RSA4096]	= "RSA4096",
	[VB2_SIG_RSA8192]	= "RSA8192",
	[VB2_SIG_RSA2048_EXP3]	= "RSA2048EXP3",
	[VB2_SIG_RSA3072_EXP3]	= "RSA3072EXP3",
};

#ifndef CHROMEOS_ENVIRONMENT
__attribute__((section(".rodata.vb2_hash_names,\"a\"\n# ")))
#endif
const char *vb2_hash_names[VB2_HASH_ALG_COUNT] = {
	[VB2_HASH_NONE]		= "none",
#if VB2_SUPPORT_SHA1
	[VB2_HASH_SHA1]		= VB2_SHA1_ALG_NAME,
#endif
#if VB2_SUPPORT_SHA256
	[VB2_HASH_SHA224]	= VB2_SHA224_ALG_NAME,
	[VB2_HASH_SHA256]	= VB2_SHA256_ALG_NAME,
#endif
#if VB2_SUPPORT_SHA512
	[VB2_HASH_SHA384]	= VB2_SHA384_ALG_NAME,
	[VB2_HASH_SHA512]	= VB2_SHA512_ALG_NAME,
#endif
};

/* The others are internal to this file. */

static const char *crypto_names[] = {
#if VB2_SUPPORT_SHA1
	[VB2_ALG_RSA1024_SHA1]		= "RSA1024 SHA1",
	[VB2_ALG_RSA2048_SHA1]		= "RSA2048 SHA1",
	[VB2_ALG_RSA4096_SHA1]		= "RSA4096 SHA1",
	[VB2_ALG_RSA8192_SHA1]		= "RSA8192 SHA1",
	[VB2_ALG_RSA2048_EXP3_SHA1]	= "RSA2048 EXP3 SHA1",
	[VB2_ALG_RSA3072_EXP3_SHA1]	= "RSA3072 EXP3 SHA1",
#endif
#if VB2_SUPPORT_SHA256
	[VB2_ALG_RSA1024_SHA256]	= "RSA1024 SHA256",
	[VB2_ALG_RSA2048_SHA256]	= "RSA2048 SHA256",
	[VB2_ALG_RSA4096_SHA256]	= "RSA4096 SHA256",
	[VB2_ALG_RSA8192_SHA256]	= "RSA8192 SHA256",
	[VB2_ALG_RSA2048_EXP3_SHA256]	= "RSA2048 EXP3 SHA256",
	[VB2_ALG_RSA3072_EXP3_SHA256]	= "RSA3072 EXP3 SHA256",
#endif
#if VB2_SUPPORT_SHA512
	[VB2_ALG_RSA1024_SHA512]	= "RSA1024 SHA512",
	[VB2_ALG_RSA2048_SHA512]	= "RSA2048 SHA512",
	[VB2_ALG_RSA4096_SHA512]	= "RSA4096 SHA512",
	[VB2_ALG_RSA8192_SHA512]	= "RSA8192 SHA512",
	[VB2_ALG_RSA2048_EXP3_SHA512]	= "RSA2048 EXP3 SHA512",
	[VB2_ALG_RSA3072_EXP3_SHA512]	= "RSA3072 EXP3 SHA512",
#endif
};

static const char *crypto_filenames[] = {
#if VB2_SUPPORT_SHA1
	[VB2_ALG_RSA1024_SHA1]		= "rsa1024",
	[VB2_ALG_RSA2048_SHA1]		= "rsa2048",
	[VB2_ALG_RSA4096_SHA1]		= "rsa4096",
	[VB2_ALG_RSA8192_SHA1]		= "rsa8192",
	[VB2_ALG_RSA2048_EXP3_SHA1]	= "rsa2048_exp3",
	[VB2_ALG_RSA3072_EXP3_SHA1]	= "rsa3072_exp3",
#endif
#if VB2_SUPPORT_SHA256
	[VB2_ALG_RSA1024_SHA256]	= "rsa1024",
	[VB2_ALG_RSA2048_SHA256]	= "rsa2048",
	[VB2_ALG_RSA4096_SHA256]	= "rsa4096",
	[VB2_ALG_RSA8192_SHA256]	= "rsa8192",
	[VB2_ALG_RSA2048_EXP3_SHA256]	= "rsa2048_exp3",
	[VB2_ALG_RSA3072_EXP3_SHA256]	= "rsa3072_exp3",
#endif
#if VB2_SUPPORT_SHA512
	[VB2_ALG_RSA1024_SHA512]	= "rsa1024",
	[VB2_ALG_RSA2048_SHA512]	= "rsa2048",
	[VB2_ALG_RSA4096_SHA512]	= "rsa4096",
	[VB2_ALG_RSA8192_SHA512]	= "rsa8192",
	[VB2_ALG_RSA2048_EXP3_SHA512]	= "rsa2048_exp3",
	[VB2_ALG_RSA3072_EXP3_SHA512]	= "rsa3072_exp3",
#endif
};

static const uint8_t crypto_to_sig[] = {
#if VB2_SUPPORT_SHA1
	[VB2_ALG_RSA1024_SHA1]		= VB2_SIG_RSA1024,
	[VB2_ALG_RSA2048_SHA1]		= VB2_SIG_RSA2048,
	[VB2_ALG_RSA4096_SHA1]		= VB2_SIG_RSA4096,
	[VB2_ALG_RSA8192_SHA1]		= VB2_SIG_RSA8192,
	[VB2_ALG_RSA2048_EXP3_SHA1]	= VB2_SIG_RSA2048_EXP3,
	[VB2_ALG_RSA3072_EXP3_SHA1]	= VB2_SIG_RSA3072_EXP3,
#endif
#if VB2_SUPPORT_SHA256
	[VB2_ALG_RSA1024_SHA256]	= VB2_SIG_RSA1024,
	[VB2_ALG_RSA2048_SHA256]	= VB2_SIG_RSA2048,
	[VB2_ALG_RSA4096_SHA256]	= VB2_SIG_RSA4096,
	[VB2_ALG_RSA8192_SHA256]	= VB2_SIG_RSA8192,
	[VB2_ALG_RSA2048_EXP3_SHA256]	= VB2_SIG_RSA2048_EXP3,
	[VB2_ALG_RSA3072_EXP3_SHA256]	= VB2_SIG_RSA3072_EXP3,
#endif
#if VB2_SUPPORT_SHA512
	[VB2_ALG_RSA1024_SHA512]	= VB2_SIG_RSA1024,
	[VB2_ALG_RSA2048_SHA512]	= VB2_SIG_RSA2048,
	[VB2_ALG_RSA4096_SHA512]	= VB2_SIG_RSA4096,
	[VB2_ALG_RSA8192_SHA512]	= VB2_SIG_RSA8192,
	[VB2_ALG_RSA2048_EXP3_SHA512]	= VB2_SIG_RSA2048_EXP3,
	[VB2_ALG_RSA3072_EXP3_SHA512]	= VB2_SIG_RSA3072_EXP3,
#endif
};

static const uint8_t crypto_to_hash[] = {
#if VB2_SUPPORT_SHA1
	[VB2_ALG_RSA1024_SHA1]		= VB2_HASH_SHA1,
	[VB2_ALG_RSA2048_SHA1]		= VB2_HASH_SHA1,
	[VB2_ALG_RSA4096_SHA1]		= VB2_HASH_SHA1,
	[VB2_ALG_RSA8192_SHA1]		= VB2_HASH_SHA1,
	[VB2_ALG_RSA2048_EXP3_SHA1]	= VB2_HASH_SHA1,
	[VB2_ALG_RSA3072_EXP3_SHA1]	= VB2_HASH_SHA1,
#endif
#if VB2_SUPPORT_SHA256
	[VB2_ALG_RSA1024_SHA256]	= VB2_HASH_SHA256,
	[VB2_ALG_RSA2048_SHA256]	= VB2_HASH_SHA256,
	[VB2_ALG_RSA4096_SHA256]	= VB2_HASH_SHA256,
	[VB2_ALG_RSA8192_SHA256]	= VB2_HASH_SHA256,
	[VB2_ALG_RSA2048_EXP3_SHA256]	= VB2_HASH_SHA256,
	[VB2_ALG_RSA3072_EXP3_SHA256]	= VB2_HASH_SHA256,
#endif
#if VB2_SUPPORT_SHA512
	[VB2_ALG_RSA1024_SHA512]	= VB2_HASH_SHA512,
	[VB2_ALG_RSA2048_SHA512]	= VB2_HASH_SHA512,
	[VB2_ALG_RSA4096_SHA512]	= VB2_HASH_SHA512,
	[VB2_ALG_RSA8192_SHA512]	= VB2_HASH_SHA512,
	[VB2_ALG_RSA2048_EXP3_SHA512]	= VB2_HASH_SHA512,
	[VB2_ALG_RSA3072_EXP3_SHA512]	= VB2_HASH_SHA512,
#endif
};

#if VB2_SUPPORT_SHA512
_Static_assert(ARRAY_SIZE(crypto_names) == VB2_ALG_COUNT, "");
_Static_assert(ARRAY_SIZE(crypto_filenames) == VB2_ALG_COUNT, "");
_Static_assert(ARRAY_SIZE(crypto_to_sig) == VB2_ALG_COUNT, "");
_Static_assert(ARRAY_SIZE(crypto_to_hash) == VB2_ALG_COUNT, "");
#endif

const char *vb2_get_hash_algorithm_name(enum vb2_hash_algorithm hash_alg)
{	if (hash_alg < ARRAY_SIZE(vb2_hash_names) && vb2_hash_names[hash_alg])
		return vb2_hash_names[hash_alg];
	else
		return VB2_INVALID_ALG_NAME;
}

const char *vb2_get_sig_algorithm_name(enum vb2_signature_algorithm sig_alg)
{
	if (sig_alg < ARRAY_SIZE(vb2_sig_names) && vb2_sig_names[sig_alg])
		return vb2_sig_names[sig_alg];
	else
		return VB2_INVALID_ALG_NAME;
}

const char *vb2_get_crypto_algorithm_name(enum vb2_crypto_algorithm alg)
{
	if (alg < ARRAY_SIZE(crypto_names) && crypto_names[alg])
		return crypto_names[alg];
	else
		return VB2_INVALID_ALG_NAME;
}

const char *vb2_get_crypto_algorithm_file(enum vb2_crypto_algorithm alg)
{
	if (alg < ARRAY_SIZE(crypto_filenames) && crypto_filenames[alg])
		return crypto_filenames[alg];
	else
		return VB2_INVALID_ALG_NAME;
}

enum vb2_signature_algorithm vb2_crypto_to_signature(
		enum vb2_crypto_algorithm algorithm)
{
	if (algorithm < ARRAY_SIZE(crypto_to_sig))
		return crypto_to_sig[algorithm];
	else
		return VB2_SIG_INVALID;
}

enum vb2_hash_algorithm vb2_crypto_to_hash(enum vb2_crypto_algorithm algorithm)
{
	if (algorithm < ARRAY_SIZE(crypto_to_hash))
		return crypto_to_hash[algorithm];
	else
		return VB2_HASH_INVALID;
}
