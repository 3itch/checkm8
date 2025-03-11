/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Authors: Muhammad Monir Hossain <muhammad.monir.hossain@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 */

/*
 * The algorithm implemented below is described in Montgomery Multiplication
 * Using Vector Instructions document from Microsoft Research, August 20, 2013
 * (cf. https://eprint.iacr.org/2013/519.pdf).
 *
 * This implementation leverages SSE2 instructions to perform arithmetic
 * operations in parallel.
 *
 * This algorithm uses the modulus positive inverse (1 / N mod 2^32) which can
 * be easily computed from the modulus negative inverse provided by the public
 * key data structure `n0inv' field.
 */

#include "2api.h"
#include "2common.h"
#include "2return_codes.h"
#include "2rsa.h"

typedef long long vb2_m128i __attribute__((__vector_size__(16), __may_alias__));
typedef int vb2_v4si __attribute__((__vector_size__(16)));
typedef unsigned long long vb2_v2du __attribute__((__vector_size__(16)));

static inline vb2_m128i __attribute__((__always_inline__))
vb2_set_epi32 (int q3, int q2, int q1, int q0)
{
	return (vb2_m128i)(vb2_v4si){ q0, q1, q2, q3 };
}

static inline vb2_m128i __attribute__((__always_inline__))
vb2_setzero_si128 (void)
{
	return (vb2_m128i)(vb2_v4si){ 0, 0, 0, 0 };
}

static inline vb2_m128i __attribute__((__always_inline__))
vb2_add_epi64 (vb2_m128i a, vb2_m128i b)
{
	return (vb2_m128i)((vb2_v2du)a + (vb2_v2du)b);
}

static inline vb2_m128i __attribute__((__always_inline__))
vb2_srli_epi64 (vb2_m128i a, int b)
{
	return (vb2_m128i)__builtin_ia32_psrlqi128(a, b);
}

static inline vb2_m128i __attribute__((__always_inline__))
vb2_mul_epu32 (vb2_m128i a, vb2_m128i b)
{
	return (vb2_m128i)__builtin_ia32_pmuludq128((vb2_v4si)a, (vb2_v4si)b);
}

static inline vb2_m128i __attribute__((__always_inline__))
vb2_and_si128 (vb2_m128i a, vb2_m128i b)
{
	return (vb2_m128i)((vb2_v2du)a & (vb2_v2du)b);
}

/**
 * Montgomery c[] = d[] - e[] if d[] > e[], c[] = d[] - e[] + mod[] otherwise.
 *
 * de[] has d[] in lower 64 bits (effectively lower 32 bits) and e[] in upper
 * 64 bits (effectively lower 32 bits)
 * de[] is used as a temporary buffer and therefore its content will be lost.
 */
static void sub_mod(const struct vb2_public_key *key, vb2_m128i *de, uint32_t *c)
{
	uint32_t i, borrow = 0, carry = 0, d, e;
	uint64_t sum, *de_i;

	for (i = 0; i < key->arrsize; i++) {
		de_i = (uint64_t *)&de[i];
		d = (uint32_t)de_i[1];
		e = (uint32_t)de_i[0];

		/* Use de_i[0] as temporary storage of d[] - e[]. */
		de_i[0] = (uint32_t)d - e - borrow;

		borrow = d ^ ((d ^ e) | (d ^ (uint32_t)de_i[0]));
		borrow >>= 31;
	}

	/* To keep the code running in constant-time for side-channel
	 * resistance, D − E + mod is systematically computed even if we do not
	 * need it. */
	for (i = 0; i < key->arrsize; i++) {
		de_i = (uint64_t *)&de[i];
		sum = de_i[0] + key->n[i] + carry;
		carry = sum >> 32;

		/* Use de_i[1] as temporary storage. */
		de_i[1] = (uint32_t)sum;
	}

	int index = borrow ? 1 : 0;
	for (i = 0; i < key->arrsize; i++) {
		de_i = (uint64_t *)&de[i];
		c[i] = (uint32_t)de_i[index];
	}
}

/**
 * Montgomery c[] = a[] * b[] / R % mod
 */
static void mont_mult(const struct vb2_public_key *key,
		      uint32_t *c,
		      const uint32_t *a,
		      const uint32_t *b,
		      const uint32_t mu,
		      vb2_m128i *de,
		      vb2_m128i *b_modulus)
{
	const uint32_t mub0 = mu * b[0];
	const vb2_m128i mask = vb2_set_epi32(0,  0xffffffff, 0, 0xffffffff);
	const uint64_t *de0 = (uint64_t *)de;
	uint32_t i, j, q, muc0;
	vb2_m128i p01, t01, mul;

	for (i = 0; i < key->arrsize; i++) {
		b_modulus[i] = vb2_set_epi32(0, b[i], 0, key->n[i]);
		de[i] = vb2_setzero_si128();
	}

	for (j = 0; j < key->arrsize; j++) {
		c[0] = (uint32_t)de0[1] - de0[0];
		muc0 = mu * c[0];

		q = muc0 + mub0 * a[j];

		mul = vb2_set_epi32(0, a[j], 0, q);

		p01 = vb2_add_epi64(de[0], vb2_mul_epu32(mul, b_modulus[0]));

		t01 = vb2_srli_epi64(p01, 32);

		for (i = 1; i < key->arrsize; i++) {
			p01 = vb2_add_epi64(vb2_add_epi64(t01, de[i]),
					    vb2_mul_epu32(mul, b_modulus[i]));

			t01 = vb2_srli_epi64(p01, 32);

			de[i - 1] = vb2_and_si128(mask, p01);
		}

		de[key->arrsize - 1] = t01;
	}

	sub_mod(key, de, c);
}

static void swap_endianness(const uint32_t *in, uint32_t *out, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		out[i] = __builtin_bswap32(in[size - 1 - i]);
}

vb2_error_t vb2ex_hwcrypto_modexp(const struct vb2_public_key *key,
				  uint8_t *inout, void *workbuf,
				  size_t workbuf_size, int exp)
{
	const uint32_t mu = -key->n0inv;
	uint32_t *a = workbuf;
	uint32_t *aR = a + key->arrsize;
	uint32_t *aaR = aR + key->arrsize;
	uint32_t *aaa = aaR;  /* Re-use location. */
	vb2_m128i *de = (vb2_m128i *)(((uintptr_t)(aaa + key->arrsize) + 0xf) & ~0xf);
	vb2_m128i *b_modulus = de + key->arrsize;
	size_t i;

	if ((void *)&b_modulus[key->arrsize] - workbuf > workbuf_size) {
		VB2_DEBUG("ERROR - HW modexp work buffer too small!\n");
		return VB2_ERROR_WORKBUF_SMALL;
	}

	/* Convert big endian to little endian. */
	swap_endianness((uint32_t *)inout, a, key->arrsize);

	/* aR = a * RR / R mod M  */
	mont_mult(key, aR, a, key->rr, mu, de, b_modulus);
	if (exp == 3) {
		/* aaR = aR * aR / R mod M */
		mont_mult(key, aaR, aR, aR, mu, de, b_modulus);
		/* a = aaR * aR / R mod M */
		mont_mult(key, a, aaR, aR, mu, de, b_modulus);

		/* To multiply with 1, prepare aR with first element 1 and
		 * others as 0. */
		aR[0] = 1;
		for (i = 1; i < key->arrsize; i++)
			aR[i] = 0;

		/* aaa = a * aR / R mod M = a * 1 / R mod M*/
		mont_mult(key, aaa, a, aR, mu, de, b_modulus);
	} else {
		/* Exponent 65537 */
		for (i = 0; i < 16; i += 2) {
			/* aaR = aR * aR / R mod M */
			mont_mult(key, aaR, aR, aR, mu, de, b_modulus);
			/* aR = aaR * aaR / R mod M */
			mont_mult(key, aR, aaR, aaR, mu, de, b_modulus);
		}
		/* aaa = aR * a / R mod M */
		mont_mult(key, aaa, aR, a, mu, de, b_modulus);
	}

	/* Convert little endian to big endian. */
	swap_endianness(aaa, (uint32_t *)inout, key->arrsize);

	return VB2_SUCCESS;
}
