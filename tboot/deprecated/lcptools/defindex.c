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
 *   defindex.c
 *
 *   Command: tpmnv_defindex.
 *
 *   This command can define the index in TPM NV Storage.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../../include/uuid.h"
#include "../../include/lcp2.h"
#include "lcptools.h"
#include "lcputils.h"


static uint32_t index_value = 0;
static uint32_t per_value = 0xffff;
static uint32_t data_size = 0;
static char *auth_value = NULL;
static uint32_t auth_length = 0;
static uint8_t r_loc_arg = 0;
static uint8_t w_loc_arg = 0;
static char *password = NULL;
static uint32_t password_len = 0;
static int help_input = 0;

static const char *short_option = "hi:s:p:";
static struct option longopts[] = {
            {"pv", 1, 0, 'v'},
            {"av", 1, 0, 'a'},
            {"wl", 1, 0, 'w'},
            {"rl", 1, 0, 'r'},
            {0, 0, 0, 0}};

static const char *usage_string = "tpmnv_defindex -i index [-s size] "
                                  "[-pv permission_value] "
                                  "[-p passwd] [-av authentication_value] "
                                  "[-wl write_locality] [-rl read_locality] [-h]";

static const char * option_strings[] = {
    "-i index value: uint32/string.\n"\
    "\tINDEX_LCP_DEF:0x50000001 or \"default\",\n"\
    "\tINDEX_LCP_OWN:0x40000001 or \"owner\",\n"\
    "\tINDEX_AUX:0x50000002 or \"aux\"\n",
    "-pv permission value: uint32.\n"\
    "\tOptional for indices INDEX_LCP_DEF, INDEX_LCP_OWN, INDEX_AUX.\n"\
    "\tDefault value for indices: INDEX_LCP_DEF:0x00002000;\n"\
    "\tINDEX_LCP_OWN:0x00000002; INDEX_AUX:0x0; Othr:0x0\n",
    "-s data size: UNIT32. \n"\
    "\tOptional for indices INDEX_LCP_DEF, INDEX_LCP_OWN and INDEX_AUX.\n"\
    "\tDefault value for indices:\n"\
    "\tINDEX_LCP_DEF and INDEX_LCP_OWN:54; INDEX_AUX:64. Unit is byte\n",
    "-av auth value: string. Auth value for defined index.\n",
    "-p password: string. \n",
    "-rl read locality value: uint8. There are 5 localities:0~4.\n"\
    "\tFor example, locality value is 0x18 if locality 3 or 4. \n",
    "-wl write locality value: uint8. The same as read locality value.\n",
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
parse_cmdline(int argc, const char* argv[])
{
    int c;
    uint32_t temp = 0;

    while ((c = getopt_long_only(argc,(char ** const)argv,
                       short_option, longopts, NULL)) != -1)
        switch (c) {
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

            case 's':
                if ( strtonum(optarg, &data_size) )
                    return LCP_E_INVALID_PARAMETER;
                break;

            case 'p':
                password = optarg;
                password_len = strnlen_s(password, 4096);
                break;

            case 'h':
                help_input = 1;
                break;

            case 'v':
                if ( strtonum(optarg, &per_value) )
                    return LCP_E_INVALID_PARAMETER;
                break;

            case 'a':
                auth_value = optarg;
                auth_length = strnlen_s(auth_value, 4096);
                break;

            case 'w':
                if ( strtonum(optarg, &temp) )
                    return LCP_E_INVALID_PARAMETER;
                if (temp > 0x1f || temp < 1)
                    return LCP_E_INVALID_PARAMETER;
                w_loc_arg = temp;
                break;

            case 'r':
                if ( strtonum(optarg, &temp) )
                    return LCP_E_INVALID_PARAMETER;
                if ( temp > 0x1f || temp < 1 )
                    return LCP_E_INVALID_PARAMETER;
                r_loc_arg = temp;
                break;

            default:
                return  LCP_E_NO_SUCH_PARAMETER;
        }
    if ( optind < argc )
        return LCP_E_INVALID_PARAMETER;

    return LCP_SUCCESS;
}

int
main (int argc, char* argv[])
{
    in_nv_definespace_t in_defspace;
    uint32_t per_authwrite = 0;
    uint32_t per_authread = 0;
    /*
     * Currently assume pcr selection size is 3.
     */
    uint16_t pcr_size = 3;
    /*
     * PCR short info size is 2+3+1+20 = 26.
     */
    unsigned char rd_pcrcom[26] = {0};
    unsigned char *pdata;
    unsigned char wrt_pcrcom[26] = {0};
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
        goto _error_end;

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
        goto _error_end;
    }
    in_defspace.index = index_value;
    /*
     * Check whether parameter of permission value has been input.
     */
    if ( per_value == 0xffff ) {
        switch (in_defspace.index) {
            case INDEX_LCP_DEF:
                in_defspace.permission = PERMISSION_DEF;
                log_info("Haven't input permission value, "\
                         "use default value 0x%x\n",
                         in_defspace.permission);
                break;

            case INDEX_LCP_OWN:
                in_defspace.permission = PERMISSION_OWN;
                log_info("Haven't input permission value, "\
                         "use default value 0x%x\n",
                         in_defspace.permission);
                break;

            case INDEX_AUX:
                in_defspace.permission = PERMISSION_AUX;
                log_info("Haven't input permission value, "\
                         "use default value 0x%x\n",
                         in_defspace.permission);
                break;

            default:
                ret_value = LCP_E_NO_PER_VALUE;
                goto _error_end;
            }
    } else
        in_defspace.permission = per_value;

    /*
     * Check whether parameter of datasize has been input.
     */
    if ( data_size == 0 ) {
        switch (in_defspace.index) {
            case INDEX_LCP_DEF:
                in_defspace.size = DATASIZE_POL;
                log_info("Haven't input data size, "\
                         "use default value %d\n",\
                         in_defspace.size);
                break;

            case INDEX_LCP_OWN:
                in_defspace.size = DATASIZE_POL;
                log_info("Haven't input data size, "\
                         "use default value %d\n",\
                         in_defspace.size);
                break;

            case INDEX_AUX:
                in_defspace.size = DATASIZE_AUX;
                log_info("Haven't input data size, "\
                         "use default value %d\n",\
                         in_defspace.size);
                break;

            default :
                ret_value = LCP_E_NO_DATASIZE;
                goto _error_end;
            }
    } else
        in_defspace.size = data_size;

    /*
     * Check whether authentication value has been input.
     */
    if ( auth_value == NULL ) {
        /*
         * Check the permission value,
         * if it needs authorization to read or write,
         * the authentication value should be inputted.
         */
        per_authwrite = (in_defspace.permission & 0x4) >> 2;
        per_authread = (in_defspace.permission & 0x40000) >> 18;
        if ( per_authwrite || per_authread ) {
            ret_value = LCP_E_NO_AUTH;
            goto _error_end;
        }
    }

    /*
     * Check whether read locality value has been input.
     *  If user hasn't input, set as default value: 0x1f.
     */
    if ( r_loc_arg != 0 && r_loc_arg <= 0x1f ) {
        in_defspace.r_loc = r_loc_arg;
    } else if ( r_loc_arg == 0 ) {
        in_defspace.r_loc = LOCALITY_DEFAULT;
    } else {
        ret_value = LCP_E_INVALID_PARAMETER;
        goto _error_end;
    }

    /*
     * Check whether write locality value has been input.
     * If user hasn't input, set as default value: 0x1f.
     */
     if ( w_loc_arg != 0 ) {
         in_defspace.w_loc = w_loc_arg;
         if ( (in_defspace.index == INDEX_AUX)
                && (in_defspace.w_loc != WR_LOCALITY_AUX) ) {
            ret_value = LCP_E_INVALID_PARAMETER;
            goto _error_end;
        }
    } else {
        if ( in_defspace.index == INDEX_AUX )
            in_defspace.w_loc = WR_LOCALITY_AUX;
        else
            in_defspace.w_loc = LOCALITY_DEFAULT;
    }

    /* build the pcr_short_info for read_pcrcomposite*/
    pdata = rd_pcrcom;
    lcp_loaddata_uint16(pcr_size, &pdata, 1);
    pdata += pcr_size;
    lcp_loaddata_byte((unsigned char)in_defspace.r_loc, &pdata);

    /* build the pcr_short_info for write_pcrcomposite*/
    pdata = wrt_pcrcom;
    lcp_loaddata_uint16(pcr_size, &pdata, 1);
    pdata += pcr_size;
    lcp_loaddata_byte((unsigned char)in_defspace.w_loc, &pdata);

    ret_value = lcp_define_index(&in_defspace, auth_value, auth_length,
                    password, password_len, rd_pcrcom, wrt_pcrcom);

    if ( ret_value == LCP_SUCCESS ) {
        log_info("\nSuccessfully defined index 0x%08x "\
                 "as permission 0x%x, data size is %d \n", in_defspace.index,
                 in_defspace.permission, in_defspace.size);
        return ret_value;
    }

_error_end:
    /*
     * Error when execute.
     */
    log_error("\nCommand DefIndex failed:\n");
    print_error(ret_value);
    return ret_value;
}
