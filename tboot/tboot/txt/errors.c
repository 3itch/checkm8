/*
 * errors.c: parse and return status of Intel(r) TXT error codes
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

#include <config.h>
#include <stdbool.h>
#include <types.h>
#include <string.h>
#include <printk.h>
#include <uuid.h>
#include <loader.h>
#include <tb_error.h>
#include <txt/txt.h>
#include <txt/config_regs.h>
#include <txt/errorcode.h>

void txt_display_errors(void)
{
    txt_errorcode_t err;
    txt_ests_t ests;
    txt_e2sts_t e2sts;
    txt_errorcode_sw_t sw_err;
    acmod_error_t acmod_err;

    /*
     * display TXT.ERRORODE error
     */
    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    if (txt_has_error() == false)
        printk(TBOOT_INFO"TXT.ERRORCODE: 0x%Lx\n", err._raw);
    else
        printk(TBOOT_ERR"TXT.ERRORCODE: 0x%Lx\n", err._raw);

    /* AC module error (don't know how to parse other errors) */
    if ( err.valid ) {
        if ( err.external == 0 )       /* processor error */
            printk(TBOOT_ERR"\t processor error 0x%x\n", (uint32_t)err.type);
        else {                         /* external SW error */
            sw_err._raw = err.type;
            if ( sw_err.src == 1 )     /* unknown SW error */
                printk(TBOOT_ERR"unknown SW error 0x%x:0x%x\n", sw_err.err1, sw_err.err2);
            else {                     /* ACM error */
                acmod_err._raw = sw_err._raw;
                if ( acmod_err._raw == 0x0 || acmod_err._raw == 0x1 ||
                     acmod_err._raw == 0x9 )
                    printk(TBOOT_INFO"AC module error : acm_type=0x%x, progress=0x%02x, "
                           "error=0x%x\n", acmod_err.acm_type, acmod_err.progress,
                           acmod_err.error);
                else
                    printk(TBOOT_ERR"AC module error : acm_type=0x%x, progress=0x%02x, "
                           "error=0x%x\n", acmod_err.acm_type, acmod_err.progress,
                           acmod_err.error);
                /* error = 0x0a, progress = 0x0d => TPM error */
                if ( acmod_err.error == 0x0a && acmod_err.progress == 0x0d )
                    printk(TBOOT_ERR"TPM error code = 0x%x\n", acmod_err.tpm_err);
                /* progress = 0x10 => LCP2 error */
                else if ( acmod_err.progress == 0x10 && acmod_err.lcp_minor != 0 )
                    printk(TBOOT_ERR"LCP2 error:  minor error = 0x%x, index = %u\n",
                           acmod_err.lcp_minor, acmod_err.lcp_index);
            }
        }
    }

    /*
     * display TXT.ESTS error
     */
    ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    if (ests._raw == 0)
        printk(TBOOT_INFO"TXT.ESTS: 0x%Lx\n", ests._raw);
    else
        printk(TBOOT_ERR"TXT.ESTS: 0x%Lx\n", ests._raw);

    /*
     * display TXT.E2STS error
     */
    e2sts = (txt_e2sts_t)read_pub_config_reg(TXTCR_E2STS);
    if (e2sts._raw == 0 || e2sts._raw == 0x200000000)
        printk(TBOOT_INFO"TXT.E2STS: 0x%Lx\n", e2sts._raw);
    else
        printk(TBOOT_ERR"TXT.E2STS: 0x%Lx\n", e2sts._raw);
}

bool txt_has_error(void)
{
    txt_errorcode_t err;
    
    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    if (err._raw == 0 || err._raw == 0xc0000001 || err._raw == 0xc0000009) {
        return false;
    } 
    else {   
        return true;
    }
}

#define CLASS_ACM_ENTRY 0x1
enum ENUM_ACM_ENTRY {
    ERR_LAUNCH = 1,
    ERR_NEM_ENABLED,
    ERR_CPU_LT_TYPE,
    ERR_DEV_ID,
    ERR_CPU_ID,
    ERR_NO_UCODE_UPDATE ,
    ERR_DEBUG_MCU,
    ERR_DMI_LINK_DOWN,
    ERR_ACM_REVOKED,	
    ERR_TPM_DOUBLE_AUX
};
#define CLASS_TPM_ACCESS 0x4
enum ENUM_TPM_ACCESS {
    ERR_OK,                  /* Indicator of successful execution of the function.*/
    ERR_TPM_ERROR,           /* TPM returned an error */
    ERR_LOCALITY,
    ERR_ACC_INVLD,
    ERR_NV_UNLOCKED,          /* TPM NV RAM not locked */
    ERR_TPM_DISABLED,         /* TPM is disabled */
    ERR_TPM_DEACTIVATED,      /* TPM is deactivated */
    ERR_TPM_NV_INDEX_INVALID, /* TPM NV indices incorrectly defined */
    ERR_TPM_INCOMPET_BIOSAC,  /* Incompatible BIOS ACM */
    ERR_TPM_INCOMPET_AUXREV,  /* Incompatible AUX revision */
    ERR_TPM_INBUF_TOO_SHORT,  /* Input buffer is too short */
    ERR_TPM_OUTBUF_TOO_SHORT, /* Output buffer is too short */
    ERR_TPM_NV_PO_INDEX_INVALID = 0x10,

    /*
     *  Errors returned by TPM driver
     */
    ERR_OUTPUT_BUFFER_TOO_SHORT = 0x1B, /* Output buffer for the TPM response to short */
    ERR_INVALID_INPUT_PARA = 0x1C,      /* Input parameter for the function invalid */
    ERR_INVALID_RESPONSE_WR = 0x1D,     /* The response from the TPM was invalid */
    ERR_INVALID_RESPONSE_RD = 0x1E,     /* The response from the TPM was invalid */
    ERR_RESPONSE_TIMEOUT = 0x1F         /* Time out for TPM response */
};     
#define CLASS_MISC_CONFIG 0x8
enum ENUM_MISC_CONFIG {
    ERR_INTERRUPT = 1,
    ERR_FORBIDDEN_BY_OWNER  = 0x10,
    ERR_TOOL_LAUNCH,
    ERR_CANNOT_REVERSE,
    ERR_ALREADY_REVOKED,
    ERR_INVALID_RETURN_ADDR,
    ERR_NO_TPM,
};

void txt_get_racm_error(void)
{
    txt_errorcode_t err;
    acmod_error_t acmod_err;

    /*
     * display TXT.ERRORODE error
     */
    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);

    /* AC module error (don't know how to parse other errors) */
    if ( err.valid == 0 ) {
        printk(TBOOT_ERR
               "Cannot retrieve status - ERRORSTS register is not valid.\n");
        return;
    } 

    if ( err.external == 0 ) {      /* processor error */
        printk(TBOOT_ERR"CPU generated error 0x%x\n", (uint32_t)err.type);
        return;
    }

    acmod_err._raw = err.type;
    if ( acmod_err.src == 1 ) {
        printk(TBOOT_ERR"Unknown SW error.\n");
        return;
    }

    if ( acmod_err.acm_type != 0x9 ) {
        printk(TBOOT_ERR
               "Cannot retrieve status - wrong ACM type in ERRORSTS register.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_ACM_ENTRY &&
         acmod_err.error == ERR_TPM_DOUBLE_AUX ) {
        printk(TBOOT_ERR
               "Nothing to do: double AUX index is not valid TXT configuration.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_TPM_ACCESS &&
         acmod_err.error == ERR_TPM_NV_INDEX_INVALID ) {
        printk(TBOOT_ERR
               "Nothing to do: invalid AUX index attributes.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_TPM_ACCESS &&
         acmod_err.error == ERR_TPM_NV_PO_INDEX_INVALID ) {
        printk(TBOOT_ERR
               "Error: invalid PO index attributes.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_MISC_CONFIG &&
         acmod_err.error == ERR_ALREADY_REVOKED ) {
        printk(TBOOT_ERR
               "Nothing to do: already revoked.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_MISC_CONFIG &&
         acmod_err.error == ERR_FORBIDDEN_BY_OWNER ) {
        printk(TBOOT_ERR
               "Error: revocation forbidden by owner.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_MISC_CONFIG &&
         acmod_err.error == ERR_CANNOT_REVERSE ) {
        printk(TBOOT_ERR
               "Error: cannot decrement revocation version.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_MISC_CONFIG &&
         acmod_err.error == ERR_INVALID_RETURN_ADDR ) {
        printk(TBOOT_ERR
               "Error: invalid input address of return point.\n");
        return;
    }

    if ( acmod_err.progress == CLASS_MISC_CONFIG &&
         acmod_err.error == ERR_NO_TPM ) {
        printk(TBOOT_ERR
               "Nothing to do: No TPM present.\n");
        return;
    }

    if ( acmod_err.progress == 0 && acmod_err.error == 0 ) {
        printk(TBOOT_INFO
               "Success: Revocation completed.\n");
        return;
    }

    printk(TBOOT_ERR"RACM generated error 0x%Lx.\n", err._raw);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
