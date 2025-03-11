/*
 * tb_error.h: error code definitions
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

#ifndef __TB_ERROR_H__
#define __TB_ERROR_H__

typedef enum {
    TB_ERR_NONE                = 0,         /* succeed */
    TB_ERR_FIXED               = 1,         /* previous error has been fixed */
    TB_ERR_GENERIC,                         /* non-fatal generic error */
    TB_ERR_TPM_NOT_READY,                   /* tpm not ready */
    TB_ERR_SMX_NOT_SUPPORTED,               /* smx not supported */
    TB_ERR_VMX_NOT_SUPPORTED,               /* vmx not supported */
    TB_ERR_VTD_NOT_SUPPORTED,               /* Vt-D not enabled in BIOS */
    TB_ERR_TXT_NOT_SUPPORTED,               /* txt not supported */
    TB_ERR_MODULE_VERIFICATION_FAILED,      /* module failed to verify against
                                               policy */
    TB_ERR_MODULES_NOT_IN_POLICY,           /* modules in mbi but not in
                                               policy */
    TB_ERR_POLICY_INVALID,                  /* policy is invalid */
    TB_ERR_POLICY_NOT_PRESENT,              /* no policy in TPM NV */
    TB_ERR_SINIT_NOT_PRESENT,               /* SINIT ACM not provided */
    TB_ERR_ACMOD_VERIFY_FAILED,             /* verifying AC module failed */
    TB_ERR_POST_LAUNCH_VERIFICATION,        /* verification of post-launch
                                               failed */
    TB_ERR_S3_INTEGRITY,                    /* creation or verification of
                                               S3 integrity measurements
                                               failed */
    TB_ERR_FATAL,                           /* generic fatal error */
    TB_ERR_NV_VERIFICATION_FAILED,          /* NV failed to verify against
                                               policy */
    TB_ERR_PREV_TXT_ERROR,                  /* previous measured launch
                                               failed */
    TB_ERR_MAX
} tb_error_t;


extern void print_tb_error_msg(tb_error_t error);
extern bool read_tb_error_code(tb_error_t *error);
extern bool write_tb_error_code(tb_error_t error);
extern bool was_last_boot_error(void);


#endif /* __TB_ERROR_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
