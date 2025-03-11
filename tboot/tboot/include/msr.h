/*-
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * Portions copyright (c) 2010-2011, Intel Corporation
 */


#ifndef __MSR_H__
#define __MSR_H__

#ifndef __ASSEMBLY__

/* from:
 * $FreeBSD: src/sys/i386/include/cpufunc.h,v 1.155.2.3 2009/11/25 01:52:36 kmacy Exp $
 */

static inline uint64_t rdmsr(uint32_t msr)
{
    uint64_t rv;

    __asm__ __volatile__ ("rdmsr" : "=A" (rv) : "c" (msr));
    return (rv);
}

static inline void wrmsr(uint32_t msr, uint64_t newval)
{
    __asm__ __volatile__ ("wrmsr" : : "A" (newval), "c" (msr));
}

#endif /* !__ASSEMBLY__ */

/*
 * from: @(#)specialreg.h     7.1 (Berkeley) 5/9/91
 * $FreeBSD: src/sys/i386/include/specialreg.h,v 1.53.2.1.2.2 2009/11/06 17:09:04 attilio Exp $
 */

#define MSR_IA32_PLATFORM_ID                   0x017
#define MSR_APICBASE                           0x01b
#define MSR_IA32_FEATURE_CONTROL               0x03a
#define MSR_IA32_SMM_MONITOR_CTL               0x09b
#define MSR_MTRRcap                            0x0fe
#define MSR_MCG_CAP                            0x179
#define MSR_MCG_STATUS                         0x17a
#define MSR_IA32_MISC_ENABLE                   0x1a0
#define MSR_IA32_MISC_ENABLE_MONITOR_FSM       (1<<18)
#define MSR_MTRRdefType                        0x2ff
#define MSR_MC0_STATUS                         0x401
#define MSR_IA32_VMX_BASIC_MSR                 0x480
#define MSR_IA32_VMX_PINBASED_CTLS_MSR         0x481
#define MSR_IA32_VMX_PROCBASED_CTLS_MSR        0x482
#define MSR_IA32_VMX_EXIT_CTLS_MSR             0x483
#define MSR_IA32_VMX_ENTRY_CTLS_MSR            0x484
#define MSR_IA32_SE_SVN_STATUS                 0x500
/*
 * Constants related to MSR's.
 */
#define APICBASE_BSP                                  0x00000100

#define MSR_IA32_SMM_MONITOR_CTL_VALID                1
#define MSR_IA32_SMM_MONITOR_CTL_MSEG_BASE(x)         (x>>12)

/* MSRs & bits used for VMX enabling */
#define IA32_FEATURE_CONTROL_MSR_LOCK                 0x1
#define IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX    0x2
#define IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL     0x7f00
#define IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER        0x8000

/* AMD64 MSR's */
#define MSR_EFER        0xc0000080      /* extended features */

/* EFER bits */
#define _EFER_LME     8               /* Long mode enable */

#define MTRR_TYPE_UNCACHABLE     0
#define MTRR_TYPE_WRTHROUGH      4
#define MTRR_TYPE_WRBACK         6


#endif /* __MSR_H__ */
