/*
 * Copyright 2001 - 2007 Intel Corporation. All Rights Reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *   nvlock.c
 *
 *   Command: tpmnv_lock.
 *
 *   This command can lock the TPM NV Storage.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#define PRINT   printf
#include "../../include/uuid.h"
#include "../../include/lcp.h"
#include "lcptools.h"
#include "lcputils.h"

static int force = 0;
static int help_input = 0;

static const char *short_option = "hf";
static const char *usage_string = "tpmnv_lock [-f] [-h]";

static const char * option_strings[] ={
        "-f force to lock.\n",
        "-h help. Will print out this help message.\n"
        ,0
};

/* function: parse_cmdline
 * description: parse the input of commandline
 */
static int
parse_cmdline(int argc, const char * argv[])
{
    int c;
    while (((c = getopt(argc, (char ** const)argv, short_option)) != -1))
        switch (c){
            case 'f':
                force = 1;
                break;

            case 'h':
                help_input = 1;
                break;

            default:
                return  LCP_E_NO_SUCH_PARAMETER;
        }
    if ( optind < argc )
        return LCP_E_INVALID_PARAMETER;

    return LCP_SUCCESS;
}

int
main (int argc, char *argv[])
{
    char c;
    in_nv_definespace_t in_defspace;
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

    ret_value =  parse_cmdline(argc, (const char **)argv);
    if ( ret_value )
        goto _error_end;

    /*
     * If user input -h(help), just print guide to
     * users and ignore other parameters.
     */
    if (help_input) {
        print_help(usage_string, option_strings);
        return LCP_SUCCESS;
    }

    /*
     * Check whether force to lock.
     */
    if ( force == 0 ) {
        /*
         * If haven't input force to lock, reminder to confirm
         * whether lock or not.
         */
        do {
            log_info("Really want to lock TPM NV? (Y/N) ");
            c = getchar() | ' ';
        } while ( (c != 'n') && (c != 'y') );
        if ( c == 'n') {
            ret_value = LCP_SUCCESS;
            return ret_value;
        }
    }
    /*
     * Set index as TPM_NV_INDEX_LOCK, datasize as 0 to lock TPM NV
     */
    in_defspace.index = TPM_NV_INDEX_LOCK;
    in_defspace.permission = 0;
    in_defspace.size = 0;

    ret_value = lcp_define_index(&in_defspace,
                    NULL, 0, NULL, 0, NULL, NULL);

    if ( ret_value == LCP_SUCCESS ) {
        /*
         * Execute successfully.
         */
        log_info("Successfully locked TPM NV!\n");
        return ret_value;
    }

_error_end:
    /*
     * Error when execute.
     */
    log_error("\nCommand NvLock failed:\n");
    print_error(ret_value);
    return ret_value;
}
