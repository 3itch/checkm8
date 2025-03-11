/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 The ChromiumOS Authors
 * Copyright (c) 2015-2020, Linaro Limited
 * Copyright (C) 2014 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

/* Core SHA-224/SHA-256 transform using v8 Crypto Extensions */

	.arch		armv8-a+crypto

	dga		.req	q20
	dgav		.req	v20
	dgb		.req	q21
	dgbv		.req	v21

	t0		.req	v22
	t1		.req	v23

	dg0q		.req	q24
	dg0v		.req	v24
	dg1q		.req	q25
	dg1v		.req	v25
	dg2q		.req	q26
	dg2v		.req	v26

	.macro		add_only, ev, rc, s0
	mov		dg2v.16b, dg0v.16b
	.ifeq		\ev
	add		t1.4s, v\s0\().4s, \rc\().4s
	sha256h		dg0q, dg1q, t0.4s
	sha256h2	dg1q, dg2q, t0.4s
	.else
	.ifnb		\s0
	add		t0.4s, v\s0\().4s, \rc\().4s
	.endif
	sha256h		dg0q, dg1q, t1.4s
	sha256h2	dg1q, dg2q, t1.4s
	.endif
	.endm

	.macro		add_update, ev, rc, s0, s1, s2, s3
	sha256su0	v\s0\().4s, v\s1\().4s
	add_only	\ev, \rc, \s1
	sha256su1	v\s0\().4s, v\s2\().4s, v\s3\().4s
	.endm

	.macro FUNC name colon
	.section .text.\name , "ax" , %progbits
	.global \name
	.type \name , %function
	.balign 4
	\name \colon
	.endm

	.macro END_FUNC name
	.size \name , .-\name
	.endm

	.extern vb2_sha256_k /* Defined in 2sha256.c */

	/*
	 * void sha2_ce_transform(struct sha256_ce_state *sst, u8 const *src,
	 *			  int blocks)
	 */
FUNC sha256_ce_transform , :
	/* load round constants */
	adr		x8, vb2_sha256_k
	ld1		{ v0.4s- v3.4s}, [x8], #64
	ld1		{ v4.4s- v7.4s}, [x8], #64
	ld1		{ v8.4s-v11.4s}, [x8], #64
	ld1		{v12.4s-v15.4s}, [x8]

	/* load state */
	mov		x9, x0
	ld1		{dgav.4s}, [x9], #16
	ld1             {dgbv.4s}, [x9]

	/* load input */
0:	ld1		{v16.16b-v19.16b}, [x1], #64
	sub		w2, w2, #1

	rev32		v16.16b, v16.16b
	rev32		v17.16b, v17.16b
	rev32		v18.16b, v18.16b
	rev32		v19.16b, v19.16b

1:	add		t0.4s, v16.4s, v0.4s
	mov		dg0v.16b, dgav.16b
	mov		dg1v.16b, dgbv.16b

	add_update	0,  v1, 16, 17, 18, 19
	add_update	1,  v2, 17, 18, 19, 16
	add_update	0,  v3, 18, 19, 16, 17
	add_update	1,  v4, 19, 16, 17, 18

	add_update	0,  v5, 16, 17, 18, 19
	add_update	1,  v6, 17, 18, 19, 16
	add_update	0,  v7, 18, 19, 16, 17
	add_update	1,  v8, 19, 16, 17, 18

	add_update	0,  v9, 16, 17, 18, 19
	add_update	1, v10, 17, 18, 19, 16
	add_update	0, v11, 18, 19, 16, 17
	add_update	1, v12, 19, 16, 17, 18

	add_only	0, v13, 17
	add_only	1, v14, 18
	add_only	0, v15, 19
	add_only	1

	/* update state */
	add		dgav.4s, dgav.4s, dg0v.4s
	add		dgbv.4s, dgbv.4s, dg1v.4s

	/* handled all input blocks? */
	cbnz		w2, 0b

	/* store new state */
3:	mov		x9, x0
	st1		{dgav.16b}, [x9], #16
	st1		{dgbv.16b}, [x9]
	ret
END_FUNC sha256_ce_transform
