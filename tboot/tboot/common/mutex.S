/*	$OpenBSD: mutex.S,v 1.6 2009/04/27 21:48:56 kettenis Exp $	*/

/*
 * Copyright (c) 2004 Artur Grabowski <art@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL  DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

#include <config.h>

.code32

/* stack offset of mutex pointer parameter */
#define SOFF	8

ENTRY(mtx_init)
	pushl	%ebp
	movl	%esp, %ebp
	movl	SOFF(%ebp), %eax
	xorl	%edx, %edx
	movl	%edx, (%eax)
	leave
	ret

ENTRY(mtx_enter)
	pushl	%ebp
	movl	%esp, %ebp	
1:	movl	SOFF(%ebp), %ecx
	/*
	 * %ecx contains the mtx.
	 */
	movl	$1, %eax
	xchgl	%eax, (%ecx)	# test_and_set(mtx->mtx_lock)
	testl	%eax, %eax	# if (already held)
	jnz	2f
	leave
	ret
2:	pause
	movl	(%ecx), %eax
	testl	%eax, %eax
	jz	1b
	jmp	2b

ENTRY(mtx_leave)
	pushl	%ebp
	movl	%esp, %ebp
	movl	SOFF(%ebp), %ecx
	xorl	%eax, %eax
	movl	%eax, (%ecx)
	leave
	ret
