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
 * readpol.c
 * Command: lcp_readpol.
 * This command can read LCP policy from TPM NV Storage.
 */
#include <stddef.h>
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

#define BUFFER_SIZE 1024

static uint32_t index_value = 0;
static char* file = NULL;
static uint32_t size = 0;
static char *password = NULL;
static uint32_t passwd_length = 0;
static int help_input = 0;

static const char *short_option = "hi:f:s:p:";
static const char *usage_string = "lcp_readpol -i index_value "
                                  "[-s read_size] [-f output_file] [-p passwd] [-h]";

static const char *option_strings[] = {
    "-i index value: uint32/string.\n"
    "\tINDEX_LCP_DEF:0x50000001 or \"default\",\n"
    "\tINDEX_LCP_OWN:0x40000001 or \"owner\",\n"
    "\tINDEX_AUX:0x50000002 or \"aux\"\n",
    "-f file_name: string. Name of file to store the policy data in. \n",
    "-s size to read: uint32. Value size to read from NV store.\n",
    "-p password: string. \n",
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
                file = optarg;
                break;

            case 'p':
                password = optarg;
                passwd_length = strnlen_s(password, 4096);
                break;

            case 's':
                if ( strtonum(optarg, &size) )
                    return LCP_E_INVALID_PARAMETER;
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

static void print_hash(lcp_hash_t *hash)
{
    unsigned int i;

    for ( i = 0; i < sizeof(hash->sha1)/sizeof(hash->sha1[0]); i++ )
        log_info("%02x ", hash->sha1[i]);
    log_info("\n");
}

static void print_policy(unsigned char* pol_buf, uint32_t buf_len)
{
    lcp_policy_t pol;
    unsigned char *pdata = pol_buf;
    static const char *pol_types[] = {"LCP_POLTYPE_HASHONLY",
                                      "LCP_POLTYPE_UNSIGNED",
                                      "LCP_POLTYPE_SIGNED", "LCP_POLTYPE_ANY",
                                      "LCP_POLTYPE_FORCEOWNERPOLICY"};

    if ( buf_len < (offsetof(lcp_policy_t, policy_hash) +
                    sizeof(pol.policy_hash.sha1) + 1) ) {
        log_error("policy buffer is too small\n");
        return;
    }
    lcp_unloaddata_byte(&pol.version, &pdata);
    lcp_unloaddata_byte(&pol.hash_alg, &pdata);
    lcp_unloaddata_byte(&pol.policy_type, &pdata);
    lcp_unloaddata_byte(&pol.sinit_revocation_counter, &pdata);
    lcp_unloaddata_uint32(&pol.policy_control, &pdata, 1);
    lcp_unloaddata_uint16(&pol.reserved[0], &pdata, 1);
    lcp_unloaddata_uint16(&pol.reserved[1], &pdata, 1);
    lcp_unloaddata_uint16(&pol.reserved[2], &pdata, 1);
    lcp_unloaddata(sizeof(pol.policy_hash.sha1), &pdata,
		   (unsigned char *)&pol.policy_hash);

    log_info("version: %d\n", (int)pol.version);
    log_info("hash_alg: %d\n", (int)pol.hash_alg);
    log_info("policy_type: %d", (int)pol.policy_type);
    if ( pol.policy_type < sizeof(pol_types)/sizeof(pol_types[0]) )
        log_info(" - %s\n", pol_types[pol.policy_type]);
    else
        log_info(" - unknown\n");
    log_info("sinit_revocation_counter: %d\n",
	     (int)pol.sinit_revocation_counter);
    log_info("policy_control: %x\n", pol.policy_control);
    log_info("policy_hash: "); print_hash(&pol.policy_hash);
}

int
main (int argc, char *argv[])
{
    FILE *p_file = NULL;
    unsigned char policy_data[BUFFER_SIZE];
    uint32_t data_length = BUFFER_SIZE;
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

    /*
     * No parameter input will print out the help message.
     */
    if ( argc == 1 ) {
        print_help(usage_string, option_strings);
        return LCP_SUCCESS;
    }

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

    /*
     * Check whether parameter of index value has been input.
     */
    if ( index_value == 0 ) {
        ret_value = LCP_E_NO_INDEXVALUE;
        goto exit;
     }

    if ( size == 0 )
        log_info("No size has been specified. Will read all index data.\n");

    /*
     * Read NV data from TPM NV store.
     */
    ret_value = lcp_read_index(index_value, password, passwd_length,
                                   0, size, &data_length, policy_data);

    if ( ret_value )
        goto exit;

    if ( file != NULL ) {
        /*
         * Write policy data into file.
         */
        p_file = fopen(file, "wb");
        if ( !p_file ) {
            log_error("Open file %s error!\n", file);
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto exit;
        }

        if ( data_length != fwrite(policy_data, 1, data_length, p_file) ) {
            log_error("Write policy data into file error!\n");
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto exit;
        }
    }
    else {
        print_hexmsg("the policy is:\n", data_length, policy_data);
        print_policy(policy_data, data_length);
    }

exit:
    if ( p_file != NULL )
        fclose(p_file);
    if ( ret_value != LCP_SUCCESS ) {
        log_error("\nCommand ReadPol failed:\n");
        print_error(ret_value);
    }
    else
        log_info("Successfully read value from index: 0x%08x.\n", index_value);

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
