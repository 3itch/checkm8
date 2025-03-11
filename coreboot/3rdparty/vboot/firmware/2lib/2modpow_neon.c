/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2common.h"
#include "2rsa.h"

/**
 * Montgomery c[] = d[] - e[] if d[] > e[], c[] = d[] - e[] + n[] otherwise.
 * Uses "Subtract with Carry" and "Add with Carry" instructions to optimize BigNum
 * arithmetic. e[] will be overwritten with intermediate results.
 */
static void sub_mod(uint32_t *c, uint32_t *ed, const uint32_t *n, const uint32_t arrsize)
{
	uint32_t borrow, tmp1, tmp2, i;

	/* e[] = d[] - e[] */
	uint32_t size_clobber = arrsize;
	uint32_t *ed_clobber = ed;
	asm (
		"subs	wzr, wzr, wzr\n\t"	/* init carry flag for subtraction */
		"1:\n\t"
		"ldp	%w[e], %w[d], [%[ed_ptr]]\n\t"
		"sbcs	%w[e], %w[d], %w[e]\n\t"
		"str	%w[e], [%[ed_ptr]], #8\n\t"
		"sub	%w[size], %w[size], #1\n\t"
		"cbnz	%w[size], 1b\n\t"
		"cset	%w[e], cc\n\t"		/* "borrow" = carry flag is 0 (cleared) */
		: [e] "=r" (borrow),
		  [d] "=r" (tmp1),
		  [size] "+r" (size_clobber),
		  [ed_ptr] "+r" (ed_clobber)
		:: "cc", "memory"
	);

	if (borrow) {
		/* e[] = e[] + n[] */
		size_clobber = arrsize;
		ed_clobber = ed;
		asm volatile (
			"adds	wzr, wzr, wzr\n\t"	/* init carry flag for addition */
			"1:\n\t"
			"ldr	%w[e], [%[ed_ptr]]\n\t"
			"ldr	%w[n], [%[n_ptr]], #4\n\t"
			"adcs	%w[e], %w[e], %w[n]\n\t"
			"str	%w[e], [%[ed_ptr]], #8\n\t"
			"sub	%w[size], %w[size], #1\n\t"
			"cbnz	%w[size], 1b\n\t"
			: [e] "=r" (tmp1),
			  [n] "=r" (tmp2),
			  [size] "+r" (size_clobber),
			  [ed_ptr] "+r" (ed_clobber),
			  [n_ptr] "+r" (n)
			:: "cc", "memory"
		);
	}

	/* c[] = e[] */
	for (i = 0; i < arrsize; i++)
		c[i] = ed[i * 2];
}

/**
 * Montgomery c[] = a[] * b[] / R % mod	(`ed` is a local scratch buffer)
 *
 * Algorithm according to https://eprint.iacr.org/2013/519.pdf and
 * https://chromium-review.googlesource.com/5055251.
 */
static void mont_mult(uint32_t *c,
		      const uint32_t *a,
		      const uint32_t *b,
		      const uint32_t *n,
		      uint32_t *ed,
		      const uint32_t mu,
		      const uint32_t arrsize)
{
	const uint32_t mub0 = mu * b[0];
	uint32_t i;

	memset(ed, 0, arrsize * sizeof(uint32_t) * 2);

	for (i = 0; i < arrsize; i++) {
		const uint32_t c0 = ed[1] - ed[0];
		const uint32_t muc0 = mu * c0;
		const uint32_t a_i = a[i];
		const uint32_t q = muc0 + mub0 * a_i;
		const uint32_t *n_clobber = n;
		const uint32_t *b_clobber = b;
		void *ed_clobber = ed;
		uint32_t size_clobber = arrsize - 1;
		asm volatile (
			/* v4.2d = always contains [0, 0] (for idempotent Add High Narrow) */
			"movi	v4.2d, #0\n\t"
			/* v3.2s = "mul" = [q, a[i]] */
			"fmov	s3, %w[q]\n\t"
			"mov	v3.s[1], %w[a_i]\n\t"
			/* v1.2s = "bmod" = [n[0], b[0]] */
			"ldr	s1, [%[n]], #4\n\t"
			"ld1	{v1.s}[1], [%[b]], #4\n\t"
			/* v2.2s = [e, d] */
			"ldr	d2, [%[ed]]\n\t"
			"uxtl	v2.2d, v2.2s\n\t"
			/* v2.2d = "p01" = ed + bmod * mul */
			"umlal	v2.2d, v1.2s, v3.2s\n\t"
			/* v2.2d = "t01" = MSB-half(p01) */
			"addhn	v2.2s, v2.2d, v4.2d\n\t"
			/* for (j = 1; j < arrsize - 1; j++) */
			"1:"
			/* v0.2d = zero-extend(ed + t01) */
			"ldr	d0, [%[ed], #8]\n\t"
			"uaddl	v0.2d, v0.2s, v2.2s\n\t"
			/* v1.2s = "bmod" = [n[j], b[j]] */
			"ldr	s1, [%[n]], #4\n\t"
			"ld1	{v1.s}[1], [%[b]], #4\n\t"
			/* v0.2d = "p01" = ed[j] + t01 + bmod * mul */
			"umlal	v0.2d, v1.2s, v3.2s\n\t"
			/* v2.2s = "t01" = MSB-half(p01) */
			"addhn	v2.2s, v0.2d, v4.2d\n\t"
			/* store ed[j - 1] = LSB-half(p01) */
			"xtn	v0.2s, v0.2d\n\t"
			"str	d0, [%[ed]], #8\n\t"
			"subs	%w[size], %w[size], #1\n\t"
			"b.hi	1b\n\t"
			/* store ed[arrsize - 1] = final t01 */
			"str	d2, [%[ed]]\n\t"
			: [ed] "+r" (ed_clobber),
			  [n] "+r" (n_clobber),
			  [b] "+r" (b_clobber),
			  [size] "+r" (size_clobber)
			: [q] "r" (q),
			  [a_i] "r" (a_i)
			: "v0", "v1","v2", "v3", "v4", "cc", "memory"
		);
	}

	sub_mod(c, ed, n, arrsize);
}

static void swap_bignumber_endianness(const void *in, void *out, size_t size_bytes)
{
	const void *in_end = in + size_bytes;

	/* REV64 can only swap within each 8-byte half of the 16-byte register, so use a
	   transposed STP to do the final swap of the two halves afterwards. */
	asm volatile (
		"1:\n\t"
		"ldr	q0, [%[in], #-16]!\n\t"
		"rev64	v0.16b, v0.16b\n\t"
		"mov	d1, v0.d[1]\n\t"
		"stp	d1, d0, [%[out]], #16\n\t"
		"subs	%[size], %[size], #16\n\t"
		"b.hi	1b\n\t"
		: [in] "+r" (in_end),
		  [out] "+r" (out),
		  [size] "+r" (size_bytes)
		:: "v0", "v1", "cc", "memory"
	);
}

vb2_error_t vb2ex_hwcrypto_modexp(const struct vb2_public_key *key,
				  uint8_t *inout, void *workbuf,
				  size_t workbuf_size, int exp)
{
	const uint32_t mu = -key->n0inv;
	const uint32_t *n = key->n;
	const uint32_t arrsize = key->arrsize;
	uint32_t *a = workbuf;
	uint32_t *aR = (void *)inout;	/* Re-use location. */
	uint32_t *aaR = a + arrsize;
	uint32_t *aaa = aaR;	/* Re-use location. */
	uint32_t *ed = aaR + arrsize;	/* 8-byte align guaranteed by VB2_WORKBUF_ALIGN */
	uint32_t i;

	if (exp != 65537 || arrsize % 16 != 0 ||
	    (void *)&ed[arrsize * 2] - workbuf > workbuf_size)
		return VB2_ERROR_EX_HWCRYPTO_UNSUPPORTED;

	/* Convert from big endian byte array to little endian word array. */
	swap_bignumber_endianness(inout, a, arrsize * sizeof(uint32_t));

	mont_mult(aR, a, key->rr, n, ed, mu, arrsize);	/* aR = a * RR / R mod M   */
	for (i = 0; i < 16; i += 2) {
		mont_mult(aaR, aR, aR, n, ed, mu, arrsize);	/* aaR = aR * aR / R mod M */
		mont_mult(aR, aaR, aaR, n, ed, mu, arrsize);	/* aR = aaR * aaR / R mod M */
	}
	mont_mult(aaa, aR, a, n, ed, mu, arrsize);	/* aaa = aR * a / R mod M */

	/* Convert back to bigendian byte array */
	swap_bignumber_endianness(aaa, inout, arrsize * sizeof(uint32_t));

	return VB2_SUCCESS;
}
