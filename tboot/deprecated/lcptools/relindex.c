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
 *   relindex.c
 *
 *   Command: tpmnv_relindex.
 *
 *   This command can release the index defined in TPM NV Storage.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../../include/uuid.h"
#include "../../include/lcp.h"
#include "lcptools.h"
#include "lcputils.h"


static uint32_t index_value = 0;
static char *password = NULL;
static uint32_t passwd_length = 0;
static int help_input = 0;

static const char *short_option = " hi:p:";
static const char *usage_string = "tpmnv_relindex -i index -p passwd [-h]";

static const char * option_strings[] ={
        "-i index value: uint32/string.\n"\
        "\tINDEX_LCP_DEF:0x50000001 or \"default\",\n"\
        "\tINDEX_LCP_OWN:0x40000001 or \"owner\",\n"\
        "\tINDEX_AUX:0x50000002 or \"aux\"\n",
        "-p password: string. \n",
        "-h help. Will print out this help message.\n",
        0
};

static param_option_t index_option_table[] = {
    {"default", INDEX_LCP_DEF},
    {"owner", INDEX_LCP_OWN},
    {"aux", INDEX_AUX},
    {NULL, -1}
};


/* function: parse_cmdline
 * description: parse the input of commandline
 */
static int
parse_cmdline(int argc, const char * argv[])
{
    int c;
    while (((c = getopt(argc,(char ** const)argv, short_option)) != -1))
        switch (c){
            case 'i':
                 /* check whether user inputs the string for reserved indices */
                index_value = parse_input_option(index_option_table, optarg);

                /*
                 * if not, then the users should input the non-0 number,
                 * 0 is not allowed for index
                 */
                if ( index_value == (uint32_t)-1 )
                    if ( strtonum(optarg, &index_value) || (index_value == 0) )
                        return LCP_E_INVALID_PARAMETER;
                break;

            case 'p':
                password = optarg;
                passwd_length = strnlen_s(password, 4096);
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
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

    /*
     * No parameter input will print out the help message.
     */
    if ( argc == 1 ) {
        print_help(usage_string, option_strings);
        return LCP_SUCCESS;
    }

    /*
     * Parse the parameters input to decide
     * what parameters will be passed to TSS API.
     */
    ret_value =  parse_cmdline(argc, (const char **)argv);
    if ( ret_value )
        goto _error_end;

    /*
     * If user input -h(help), just print guide to
     * users and ignore other parameters.
     */
    if ( help_input ) {
        print_help(usage_string, option_strings);
        return LCP_SUCCESS;
    }

    if ( index_value == 0 ) {
        ret_value = LCP_E_NO_INDEXVALUE;
        goto _error_end;
    }

    if ( password == NULL ) {
        ret_value = LCP_E_AUTH_FAIL;
        log_error("No password input! Password is needed to release index.\n");
        goto _error_end;
    }

    ret_value = lcp_release_index(index_value, password, passwd_length);

    if ( ret_value == LCP_SUCCESS ) {
        /*
         * Execute successfully.
         */
        log_info("Successfully released index 0x%08x \n", index_value);
        return ret_value;
    }

_error_end:
    /*
     * Error when execute.
     */
    log_error("\nCommand RelIndex failed:\n");
    print_error(ret_value);
    return ret_value;
}

