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
 * writepol.c
 * Command: lcp_writepol.
 * This command can write LCP policy into TPM NV Storage.
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
static char *file_arg=NULL;
static uint32_t fLeng;
static unsigned char *policy_data = NULL;
static char *password = NULL;
static uint32_t passwd_length = 0;
static int help_input = 0;
static unsigned char empty_pol_data[] = {0};

static const char *short_option = "ehi:f:p:";
static const char *usage_string = "lcp_writepol -i index_value "
                                  "[-f policy_file] [-e] [-p passwd] [-h]";

static const char *option_strings[] = {
    "-i index value: uint32/string.\n"
    "\tINDEX_LCP_DEF:0x50000001 or \"default\",\n"
    "\tINDEX_LCP_OWN:0x40000001 or \"owner\",\n"
    "\tINDEX_AUX:0x50000002 or \"aux\"\n",
    "-f file_name: string. File name of the policy data is stored. \n",
    "-p password: string. \n",
    "-e write 0 length data to the index.\n"
    "\tIt will be used for some special index.\n"
    "\tFor example, the index with permission WRITEDEFINE.\n",
    "-h help. Will print out this help message.\n",
    NULL
};

static param_option_t index_option_table[] = {
    {"default", INDEX_LCP_DEF},
    {"owner", INDEX_LCP_OWN},
    {"aux", INDEX_AUX},
    {NULL, -1}
};

/*
 * function: parse_cmdline
 * description: parse the input of commandline
 */
static int
parse_cmdline(int argc, const char * argv[])
{
    int c;
    while (((c = getopt(argc, (char ** const)argv, short_option)) != -1))
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

            case 'f':
                file_arg = optarg;
                break;

            case 'p':
                password = optarg;
                passwd_length = strnlen_s(password, 4096);
                break;

            case 'e':
	        policy_data = empty_pol_data;
                fLeng = 0;
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
    char *file = NULL;
    FILE *p_file = NULL;

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
        goto exit;

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
        goto exit;
    }

    if ( file_arg && (policy_data == NULL) )
        file = file_arg;
    else if ( file_arg && (policy_data == empty_pol_data) ) {
        log_error("Cannot use '-f' and '-e' option at the same time!\n");
        ret_value = LCP_E_INVALID_PARAMETER;
        goto exit;
    }

    if ( (file_arg == NULL) && (policy_data == NULL) ) {
        log_error("Must specify policy file name or use -e option! \n");
        ret_value = LCP_E_INVALID_PARAMETER;
        goto exit;
    }

    if ( policy_data == NULL ) {
        p_file = fopen(file, "rb");
        if ( !p_file ) {
            log_error("Open file %s error!\n", file);
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto exit;
        }
        /*
         * Get length of file.
         */
        fseek(p_file, 0, SEEK_END);
        fLeng = ftell(p_file);
        fseek(p_file, 0, SEEK_SET);

        policy_data = (unsigned char *)malloc(fLeng);
        if ( !policy_data ) {
            log_error("Memory alloc error!\n");
            ret_value = LCP_E_OUTOFMEMORY;
            goto exit;
        }

        /*
         * Read policy data from file.
         */
        if ( fLeng != fread(policy_data, 1, fLeng, p_file) ) {
            log_error("Read policy data from file error!\n");
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto exit;
        }
    }

    ret_value = lcp_write_index(index_value,
                    password, passwd_length, 0, fLeng, policy_data);

exit:
    if ( ret_value != LCP_SUCCESS ) {
        log_error("\nCommand WritePol failed:\n");
        print_error(ret_value);
    } else {
        log_info("\nSuccessfully write policy into index 0x%08x \n",
                 index_value);
    }

    if ( (policy_data != NULL) && (policy_data != empty_pol_data) )
        free(policy_data);
    if ( p_file != NULL )
        fclose(p_file);

    return ret_value;
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
