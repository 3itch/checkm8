/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * SHA256 implementation using x86 SHA extension.
 * Mainly from https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c,
 * Written and place in public domain by Jeffrey Walton
 * Based on code from Intel, and by Sean Gulley for
 * the miTLS project.
 */
#include "2common.h"
#include "2sha.h"
#include "2sha_private.h"
#include "2api.h"

const uint32_t vb2_hash_seq[8] = {3, 2, 7, 6, 1, 0, 5, 4};

typedef int vb2_m128i __attribute__ ((vector_size(16)));

static inline vb2_m128i vb2_loadu_si128(vb2_m128i *ptr)
{
	vb2_m128i result;
	asm volatile ("movups %1, %0" : "=x"(result) : "m"(*ptr));
	return result;
}

static inline void vb2_storeu_si128(vb2_m128i *to, vb2_m128i from)
{
	asm volatile ("movups %1, %0" : "=m"(*to) : "x"(from));
}

static inline vb2_m128i vb2_add_epi32(vb2_m128i a, vb2_m128i b)
{
	return a + b;
}

static inline vb2_m128i vb2_shuffle_epi8(vb2_m128i value, vb2_m128i mask)
{
	asm ("pshufb %1, %0" : "+x"(value) : "xm"(mask));
	return value;
}

static inline vb2_m128i vb2_shuffle_epi32(vb2_m128i value, int mask)
{
	vb2_m128i result;
	asm ("pshufd %2, %1, %0" : "=x"(result) : "xm"(value), "i" (mask));
	return result;
}

static inline vb2_m128i vb2_alignr_epi8(vb2_m128i a, vb2_m128i b, int imm8)
{
	asm ("palignr %2, %1, %0" : "+x"(a) : "xm"(b), "i"(imm8));
	return a;
}

static inline vb2_m128i vb2_sha256msg1_epu32(vb2_m128i a, vb2_m128i b)
{
	asm ("sha256msg1 %1, %0" : "+x"(a) : "xm"(b));
	return a;
}

static inline vb2_m128i vb2_sha256msg2_epu32(vb2_m128i a, vb2_m128i b)
{
	asm ("sha256msg2 %1, %0" : "+x"(a) : "xm"(b));
	return a;
}

static inline vb2_m128i vb2_sha256rnds2_epu32(vb2_m128i a, vb2_m128i b,
                                              vb2_m128i k)
{
	asm ("sha256rnds2 %1, %0" : "+x"(a) : "xm"(b), "Yz"(k));
	return a;
}

#define SHA256_X86_PUT_STATE1(j, i) 					\
	{								\
		msgtmp[j] = vb2_loadu_si128((vb2_m128i *)			\
				(message + (i << 6) + (j * 16)));	\
		msgtmp[j] = vb2_shuffle_epi8(msgtmp[j], shuf_mask);	\
		msg = vb2_add_epi32(msgtmp[j],				\
			vb2_loadu_si128((vb2_m128i *)&vb2_sha256_k[j * 4]));	\
		state1 = vb2_sha256rnds2_epu32(state1, state0, msg);	\
	}

#define SHA256_X86_PUT_STATE0()						\
	{								\
		msg    = vb2_shuffle_epi32(msg, 0x0E);			\
		state0 = vb2_sha256rnds2_epu32(state0, state1, msg);	\
	}

#define SHA256_X86_LOOP(j)						\
	{								\
		int k = j & 3;						\
		int prev_k = (k + 3) & 3;				\
		int next_k = (k + 1) & 3;				\
		msg = vb2_add_epi32(msgtmp[k],				\
			vb2_loadu_si128((vb2_m128i *)&vb2_sha256_k[j * 4]));	\
		state1 = vb2_sha256rnds2_epu32(state1, state0, msg);	\
		tmp = vb2_alignr_epi8(msgtmp[k], msgtmp[prev_k], 4);	\
		msgtmp[next_k] = vb2_add_epi32(msgtmp[next_k], tmp);	\
		msgtmp[next_k] = vb2_sha256msg2_epu32(msgtmp[next_k],	\
					msgtmp[k]);			\
		SHA256_X86_PUT_STATE0();				\
		msgtmp[prev_k] = vb2_sha256msg1_epu32(msgtmp[prev_k],	\
				msgtmp[k]);				\
	}

static void vb2_sha256_transform_x86ext(const uint8_t *message,
					unsigned int block_nb)
{
	vb2_m128i state0, state1, msg, abef_save, cdgh_save;
	vb2_m128i msgtmp[4];
	vb2_m128i tmp;
	int i;
	const vb2_m128i shuf_mask = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};

	state0 = vb2_loadu_si128((vb2_m128i *)&vb2_sha_ctx.h[0]);
	state1 = vb2_loadu_si128((vb2_m128i *)&vb2_sha_ctx.h[4]);
	for (i = 0; i < (int) block_nb; i++) {
		abef_save = state0;
		cdgh_save = state1;

		SHA256_X86_PUT_STATE1(0, i);
		SHA256_X86_PUT_STATE0();

		SHA256_X86_PUT_STATE1(1, i);
		SHA256_X86_PUT_STATE0();
		msgtmp[0] = vb2_sha256msg1_epu32(msgtmp[0], msgtmp[1]);

		SHA256_X86_PUT_STATE1(2, i);
		SHA256_X86_PUT_STATE0();
		msgtmp[1] = vb2_sha256msg1_epu32(msgtmp[1], msgtmp[2]);

		SHA256_X86_PUT_STATE1(3, i);
		tmp = vb2_alignr_epi8(msgtmp[3], msgtmp[2], 4);
		msgtmp[0] = vb2_add_epi32(msgtmp[0], tmp);
		msgtmp[0] = vb2_sha256msg2_epu32(msgtmp[0], msgtmp[3]);
		SHA256_X86_PUT_STATE0();
		msgtmp[2] = vb2_sha256msg1_epu32(msgtmp[2], msgtmp[3]);

		SHA256_X86_LOOP(4);
		SHA256_X86_LOOP(5);
		SHA256_X86_LOOP(6);
		SHA256_X86_LOOP(7);
		SHA256_X86_LOOP(8);
		SHA256_X86_LOOP(9);
		SHA256_X86_LOOP(10);
		SHA256_X86_LOOP(11);
		SHA256_X86_LOOP(12);
		SHA256_X86_LOOP(13);
		SHA256_X86_LOOP(14);

		msg = vb2_add_epi32(msgtmp[3],
			vb2_loadu_si128((vb2_m128i *)&vb2_sha256_k[15 * 4]));
		state1 = vb2_sha256rnds2_epu32(state1, state0, msg);
		SHA256_X86_PUT_STATE0();

		state0 = vb2_add_epi32(state0, abef_save);
		state1 = vb2_add_epi32(state1, cdgh_save);

	}

	vb2_storeu_si128((vb2_m128i *)&vb2_sha_ctx.h[0], state0);
	vb2_storeu_si128((vb2_m128i *)&vb2_sha_ctx.h[4], state1);
}

void vb2_sha256_transform_hwcrypto(const uint8_t *message,
				   unsigned int block_nb)
{
	vb2_sha256_transform_x86ext(message, block_nb);
}
