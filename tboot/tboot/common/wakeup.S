/*
 * wakeup.S: assembly S3 wakeup support
 *
 * Copyright (c) 2006-2007, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * s3 resume entry called from BIOS
 */
        .code16
        .align PAGE_SIZE, 0

ENTRY(s3_wakeup_16)
	cli
	cld
	mov     %cs, %ax
	mov     %ax, %ds
	lgdtl   real_gdt_desc - s3_wakeup_16
	mov     $1, %eax
	mov     %eax, %cr0
	ljmpl   $(cs_sel), $(s3_wakeup_32)

	.align 8
/*
 * descriptors and descriptor tables
 */
real_gdt_desc:
	.word	real_gdt_table_end - real_gdt_table - 1
	.long	TBOOT_S3_WAKEUP_ADDR + real_gdt_table - s3_wakeup_16

        .align 8

real_gdt_table:
		/* unused */
        .quad	0x0000000000000000
real_cs_desc:	/* cs */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9a00		/* read + exec */
	.word	0x00cf		/* granularity = 4096 */
real_ds_desc:	/* ds */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9200		/* read + write */
	.word	0x00cf		/* granularity = 4096 */
		/* end (unused) */
        .quad	0x0000000000000000
real_gdt_table_end:
ENTRY(s3_wakeup_end)

        .code32

s3_wakeup_32:
	mov     $(ds_sel), %ecx
	mov     %ecx, %ds
	mov     $1, %eax
	mov     %eax, s3_flag
	jmp     __start
