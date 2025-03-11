/*
 * parse_err.c: Linux app that will parse a TXT.ERRORCODE value
 *
 * Copyright (c) 2010-2011, Intel Corporation
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>

#define printk   printf
#include "../tboot/include/txt/config_regs.h"
#include "../tboot/include/txt/errorcode.h"

static inline uint64_t read_txt_config_reg(void *config_regs_base,
                                           uint32_t reg)
{
    /* these are MMIO so make sure compiler doesn't optimize */
    return *(volatile uint64_t *)(config_regs_base + reg);
}

int main(int argc, char *argv[])
{
    txt_errorcode_t err;

    if ( argc > 2 ) {
        printf("usage:  %s [<TXT.ERRORCODE value>]\n", argv[0]);
        return 1;
    }

    if ( argc == 2 ) {
        err._raw = strtoul(argv[1], NULL, 0);
        if ( errno != 0 ) {
            printf("Error:  TXT.ERRORCODE value is not a valid number\n");
            return 1;
        }
    }
    else {
        int fd_mem = open("/dev/mem", O_RDONLY);
        if ( fd_mem == -1 ) {
            printf("ERROR: cannot open /dev/mem\n");
            return 1;
        }
        void *txt_pub = mmap(NULL, TXT_CONFIG_REGS_SIZE, PROT_READ,
                             MAP_PRIVATE, fd_mem, TXT_PUB_CONFIG_REGS_BASE);
        if ( txt_pub == MAP_FAILED ) {
            printf("ERROR: cannot map config regs\n");
            close(fd_mem);
            return 1;
        }

        err._raw = read_txt_config_reg(txt_pub, TXTCR_ERRORCODE);

        munmap(txt_pub, TXT_CONFIG_REGS_SIZE);
        close(fd_mem);
    }

    printf("ERRORCODE: 0x%08jx\n", err._raw);

    /* AC module error (don't know how to parse other errors) */
    if ( err.valid ) {
        if ( err.external == 0 )       /* processor error */
            printk("\t processor error 0x%x\n", (uint32_t)err.type);
        else {                         /* external SW error */
            txt_errorcode_sw_t sw_err;
            sw_err._raw = err.type;
            if ( sw_err.src == 1 )     /* unknown SW error */
                printk("unknown SW error 0x%x:0x%x\n", sw_err.err1, sw_err.err2);
            else {                     /* ACM error */
                acmod_error_t acmod_err;
                acmod_err._raw = sw_err._raw;
                printk("AC module error : acm_type=0x%x, progress=0x%02x, "
                       "error=0x%x\n", acmod_err.acm_type, acmod_err.progress,
                       acmod_err.error);
                /* error = 0x0a, progress = 0x0d => TPM error */
                if ( acmod_err.error == 0x0a && acmod_err.progress == 0x0d )
                    printk("TPM error code = 0x%x\n", acmod_err.tpm_err);
                /* progress = 0x10 => LCP2 error */
                else if ( acmod_err.progress == 0x10 && acmod_err.lcp_minor != 0 )
                    printk("LCP2 error:  minor error = 0x%x, index = %u\n",
                           acmod_err.lcp_minor, acmod_err.lcp_index);
            }
        }
    }
    else
        printk("no error\n");

    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
