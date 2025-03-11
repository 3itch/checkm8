/*
 * errorcode.h: Intel(r) TXT error definitions for ERRORCODE config register
 *
 * Copyright (c) 2003-2011, Intel Corporation
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

#ifndef __TXT_ERRORCODE_H__
#define __TXT_ERRORCODE_H__

/*
 * error values for processor error codes (ERRORCODE.external = 0)
 */
#define TXT_ERR_PROC_LEGACY_SHUTDOWN          0
#define TXT_ERR_PROC_INVALID_ACM_MEM_TYPE     5
#define TXT_ERR_PROC_UNSUPPORTED_ACM          6
#define TXT_ERR_PROC_AUTH_FAIL                7
#define TXT_ERR_PROC_INVALID_ACM_FORMAT       8
#define TXT_ERR_PROC_UNEXPECTED_HITM          9
#define TXT_ERR_PROC_INVALID_EVENT           10
#define TXT_ERR_PROC_INVALID_JOIN_FORMAT     11
#define TXT_ERR_PROC_UNRECOVERABLE_MCE       12
#define TXT_ERR_PROC_VMX_ABORT               13
#define TXT_ERR_PROC_ACM_CORRUPT             14
#define TXT_ERR_PROC_INVALID_VIDB_RATIO      15

/*
 * for SW errors (ERRORCODE.external = 1)
 */
typedef union {
    uint32_t _raw;
    struct {
        uint32_t  err1     : 15;     /* specific to src */
        uint32_t  src      : 1;      /* 0=ACM, 1=other */
        uint32_t  err2     : 14;     /* specific to src */
        uint32_t  external : 1;      /* always 1 for this type */
        uint32_t  valid    : 1;      /* always 1 */
    };
} txt_errorcode_sw_t;

/*
 * ACM errors (txt_errorcode_sw_t.src=0), format of err1+src+err2 fields
 */
typedef union __attribute__((packed)){
    uint32_t _raw;
    struct __attribute__((packed)){
        uint32_t acm_type  : 4;  /* 0000=BIOS ACM, 0001=SINIT, */
                                 /* 0010-1111=reserved */
        uint32_t progress  : 6;
        uint32_t error     : 5;
        uint32_t src       : 1;  /* above value */
        union __attribute__((packed)){
            struct __attribute__((packed)) {  /* progress=0x0d, error=1010 */
                uint32_t tpm_err    : 9;
                uint32_t reserved1  : 5;
            };
            struct __attribute__((packed)) {  /* progress=0x10 */
                uint32_t lcp_minor  : 6;
                uint32_t lcp_index  : 3;
                uint32_t reserved2  : 5;
            };
        }; /* sub-error */
    };
} acmod_error_t;

#endif    /* __TXT_ERRORCODE_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
