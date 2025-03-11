/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Miscellaneous functions for userspace vboot utilities.
 */

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "host_key21.h"
#include "host_p11.h"
#include "openssl_compat.h"
#include "util_misc.h"

const char *packed_key_sha1_string(const struct vb2_packed_key *key)
{
	uint8_t *buf = ((uint8_t *)key) + key->key_offset;
	uint32_t buflen = key->key_size;
	struct vb2_hash hash;
	static char dest[VB2_SHA1_DIGEST_SIZE * 2 + 1];

	vb2_hash_calculate(false, buf, buflen, VB2_HASH_SHA1, &hash);

	char *dnext = dest;
	int i;
	for (i = 0; i < sizeof(hash.sha1); i++)
		dnext += sprintf(dnext, "%02x", hash.sha1[i]);

	return dest;
}

const char *private_key_sha1_string(const struct vb2_private_key *key)
{
	uint8_t *buf;
	uint32_t buflen;
	struct vb2_hash hash;
	static char dest[VB2_SHA1_DIGEST_SIZE * 2 + 1];

	if (!key->rsa_private_key ||
	    vb_keyb_from_rsa(key->rsa_private_key, &buf, &buflen)) {
		return "<error>";
	}

	vb2_hash_calculate(false, buf, buflen, VB2_HASH_SHA1, &hash);

	char *dnext = dest;
	int i;
	for (i = 0; i < sizeof(hash.sha1); i++)
		dnext += sprintf(dnext, "%02x", hash.sha1[i]);

	free(buf);
	return dest;
}

static int vb_keyb_from_modulus(const BIGNUM *rsa_private_key_n, uint32_t modulus_size,
				uint8_t **keyb_data, uint32_t *keyb_size)
{
	uint32_t i;
	uint32_t nwords = modulus_size / 4;
	BIGNUM *N = NULL;
	BIGNUM *Big1 = NULL, *Big2 = NULL, *Big32 = NULL, *BigMinus1 = NULL;
	BIGNUM *B = NULL;
	BIGNUM *N0inv = NULL, *R = NULL, *RR = NULL;
	BIGNUM *RRTemp = NULL, *NnumBits = NULL;
	BIGNUM *n = NULL, *rr = NULL;
	BN_CTX *bn_ctx = BN_CTX_new();
	uint32_t n0invout;
	uint32_t bufsize;
	uint32_t *outbuf;
	int retval = 1;

	bufsize = (2 + nwords + nwords) * sizeof(uint32_t);
	outbuf = malloc(bufsize);
	if (!outbuf)
		goto done;

	*keyb_data = (uint8_t *)outbuf;
	*keyb_size = bufsize;

	*outbuf++ = nwords;

	/* Initialize BIGNUMs */
#define NEW_BIGNUM(x) do { x = BN_new(); if (!x) goto done; } while (0)
	NEW_BIGNUM(N);
	NEW_BIGNUM(Big1);
	NEW_BIGNUM(Big2);
	NEW_BIGNUM(Big32);
	NEW_BIGNUM(BigMinus1);
	NEW_BIGNUM(N0inv);
	NEW_BIGNUM(R);
	NEW_BIGNUM(RR);
	NEW_BIGNUM(RRTemp);
	NEW_BIGNUM(NnumBits);
	NEW_BIGNUM(n);
	NEW_BIGNUM(rr);
	NEW_BIGNUM(B);
#undef NEW_BIGNUM

	BN_copy(N, rsa_private_key_n);
	BN_set_word(Big1, 1L);
	BN_set_word(Big2, 2L);
	BN_set_word(Big32, 32L);
	BN_sub(BigMinus1, Big1, Big2);

	BN_exp(B, Big2, Big32, bn_ctx); /* B = 2^32 */

	/* Calculate and output N0inv = -1 / N[0] mod 2^32 */
	BN_mod_inverse(N0inv, N, B, bn_ctx);
	BN_sub(N0inv, B, N0inv);
	n0invout = BN_get_word(N0inv);

	*outbuf++ = n0invout;

	/* Calculate R = 2^(# of key bits) */
	BN_set_word(NnumBits, BN_num_bits(N));
	BN_exp(R, Big2, NnumBits, bn_ctx);

	/* Calculate RR = R^2 mod N */
	BN_copy(RR, R);
	BN_mul(RRTemp, RR, R, bn_ctx);
	BN_mod(RR, RRTemp, N, bn_ctx);


	/* Write out modulus as little endian array of integers. */
	for (i = 0; i < nwords; ++i) {
		uint32_t nout;

		BN_mod(n, N, B, bn_ctx); /* n = N mod B */
		nout = BN_get_word(n);
		*outbuf++ = nout;

		BN_rshift(N, N, 32); /*  N = N/B */
	}

	/* Write R^2 as little endian array of integers. */
	for (i = 0; i < nwords; ++i) {
		uint32_t rrout;

		BN_mod(rr, RR, B, bn_ctx); /* rr = RR mod B */
		rrout = BN_get_word(rr);
		*outbuf++ = rrout;

		BN_rshift(RR, RR, 32); /* RR = RR/B */
	}

	outbuf = NULL;
	retval = 0;

done:
	free(outbuf);
	/* Free BIGNUMs. */
	BN_free(Big1);
	BN_free(Big2);
	BN_free(Big32);
	BN_free(BigMinus1);
	BN_free(N0inv);
	BN_free(R);
	BN_free(RRTemp);
	BN_free(NnumBits);
	BN_free(n);
	BN_free(rr);

	return retval;
}

static int vb_keyb_from_p11_key(struct pkcs11_key *p11_key, uint8_t **keyb_data,
				uint32_t *keyb_size)
{
	int ret = 1;
	uint32_t modulus_size = 0;
	BIGNUM *N = NULL;
	uint8_t *modulus = pkcs11_get_modulus(p11_key, &modulus_size);
	if (!modulus) {
		fprintf(stderr, "Failed to get modulus from PKCS#11 key\n");
		goto done;
	}

	N = BN_bin2bn(modulus, modulus_size, NULL);
	if (!N) {
		fprintf(stderr, "Failed to call BN_bin2bn()\n");
		goto done;
	}
	ret = vb_keyb_from_modulus(N, modulus_size, keyb_data, keyb_size);
done:
	BN_free(N);
	free(modulus);
	return ret;
}

int vb_keyb_from_rsa(struct rsa_st *rsa_private_key, uint8_t **keyb_data, uint32_t *keyb_size)
{
	const BIGNUM *N;
	RSA_get0_key(rsa_private_key, &N, NULL, NULL);
	if (!N) {
		fprintf(stderr, "Failed to get N from RSA private key\n");
		return 1;
	}
	return vb_keyb_from_modulus(N, RSA_size(rsa_private_key), keyb_data, keyb_size);
}

int vb_keyb_from_private_key(struct vb2_private_key *private_key, uint8_t **keyb_data,
			     uint32_t *keyb_size)
{
	switch (private_key->key_location) {
	case PRIVATE_KEY_P11:
		return vb_keyb_from_p11_key(private_key->p11_key, keyb_data, keyb_size);
	case PRIVATE_KEY_LOCAL:
		return vb_keyb_from_rsa(private_key->rsa_private_key, keyb_data, keyb_size);
	}
	return 1;
}

enum vb2_signature_algorithm vb2_get_sig_alg(uint32_t exp, uint32_t bits)
{
	switch (exp) {
	case RSA_3:
		switch (bits) {
		case 2048:
			return VB2_SIG_RSA2048_EXP3;
		case 3072:
			return VB2_SIG_RSA3072_EXP3;
		}
		break;
	case RSA_F4:
		switch (bits) {
		case 1024:
			return VB2_SIG_RSA1024;
		case 2048:
			return VB2_SIG_RSA2048;
		case 4096:
			return VB2_SIG_RSA4096;
		case 8192:
			return VB2_SIG_RSA8192;
		}
	}

	/* no clue */
	return VB2_SIG_INVALID;
}
