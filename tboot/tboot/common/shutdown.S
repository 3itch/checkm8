/*
 * shutdown.S: assembly extry points for shutdown
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

compat_mode_entry:
        /* Disable PCID */
        movl %cr4, %eax
        andl $~CR4_PCIDE, %eax
        movl %eax, %cr4


	/* Disable paging and therefore leave 64 bit mode. */
        movl %cr0, %eax
        andl $~CR0_PG, %eax
        movl %eax, %cr0

        /* Clear MSR_EFER[LME], disabling long mode */
        movl    $MSR_EFER,%ecx
        rdmsr
        btcl    $_EFER_LME,%eax
        wrmsr

        jmp 1f
1:      /* fall through to shutdown_entry32 */

shutdown_entry32:
	/* restore tboot context */
        lgdt    %cs:gdt_descr
        mov     $(ds_sel),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss
        ljmp    $(cs_sel),$(1f)
1:      leal	bsp_stack,%esp	# default to BSP stack

	# BSP has separate stack (above)
        movl	$MSR_APICBASE,%ecx
        rdmsr
        andl	$APICBASE_BSP,%eax
	jnz	3f

	# get initial APIC ID for this processor
	mov	$0x01, %eax
	xor	%ebx, %ebx
	cpuid
	shr	$24, %ebx

	# set stack as id-based offset from AP stack base
	# "truncate" if too big so that we at least have a stack
	# (even if shared with another AP)
	cmp	$NR_CPUS, %ebx
	jl	2f
	mov	$NR_CPUS-1, %ebx
2:	mov	$AP_STACK_SIZE, %eax
	mul	%ebx
	mov	$ap_stacks, %ecx
	sub	%eax, %ecx
	mov	%ecx, %esp

3:	/* Reset EFLAGS (subsumes CLI and CLD). */
        pushl   $0x0
        popf

        /* Load IDT */
        lidt    idt_descr

        /* disable paging */
        mov %cr0, %eax
        and $~CR0_PG, %eax
        mov %eax, %cr0
        jmp 1f

1:      /* clear cr4 except for SMXE */
        mov     $0x4000, %eax
        mov     %eax, %cr4

        /* true shutdown work for tboot */
        call shutdown
        ud2

/*
 * unified (32b/64b) shutdown entry point
 */
ENTRY(shutdown_entry)
	.code64
	cli
	wbinvd

	movl    $MSR_EFER,%ecx
	rdmsr
	bt      $_EFER_LME,%eax
	jnc     shutdown_entry32

	lgdt    gdt_descr(%rip)
        mov     $(ds_sel),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss

1:      /* Jump to low identity mapping in compatibility mode. */
        ljmp *compatibility_mode_far(%rip)
        ud2

compatibility_mode_far:
        .long     compat_mode_entry
        .word     cs_sel

	.code32
