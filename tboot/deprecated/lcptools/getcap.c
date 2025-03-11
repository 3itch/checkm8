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
 *   getcap.c
 *
 *  Command: tpmnv_getcap.
 *
 *   This command can get basic information from TPM like the the PCR number,
 *   the indices have been defined and the public data associated with the
 *   specified index.
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

#define BUFFER_SIZE 1024

static unsigned int index_value = 0;
static int help_input = 0;
static int perm_flags = 0;
static char *password = NULL;
static uint32_t passwd_length = 0;

static const char *short_option = "hi:f:";
static const char *usage_string = "tpmnv_getcap [-i index] [-f password] [-h]";

static const char * option_strings[] ={
    "-i index value: uint32/string. To get the public data of this index.\n"\
    "\tINDEX_LCP_DEF:0x50000001 or \"default\",\n"\
    "\tINDEX_LCP_OWN:0x40000001 or \"owner\",\n"\
    "\tINDEX_AUX:0x50000002 or \"aux\"\n",
    "-f password: string  displays TPM_PERMANENT_FLAGS.\n",
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
static int parse_cmdline(int argc, const char * argv[])
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
	        perm_flags = 1;
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

/* print the message return by getcap command */
static void print_nv_caps_msg(int datasize, const unsigned char *data,
                              const char *msg)
{
    uint16_t i = 0;
    uint32_t ibyte;
    for (i = 0; i < datasize; i++) {
        if ( (i % 32) == 0 ) {
            if ( datasize > 32 ) {
                log_info("\n\t");
            }
            log_info("%s", msg);
        } else if ( (i % 4) == 0 ) {
            log_info(" %s", msg);
        }
        ibyte = *(data + i);
        ibyte &= 0x000000ff;
        log_info("%02x", ibyte);
    }
    log_info("\n");
}

typedef struct {
    uint32_t disable                         : 1;
    uint32_t ownership                       : 1;
    uint32_t deactivated                     : 1;
    uint32_t readPubek                       : 1;
    uint32_t disableOwnerClear               : 1;
    uint32_t allowMaintenance                : 1;
    uint32_t physicalPresenceLifetimeLock    : 1;
    uint32_t physicalPresenceHWEnable        : 1;
    uint32_t physicalPresenceCMDEnable       : 1;
    uint32_t CEKPUsed                        : 1;
    uint32_t TPMpost                         : 1;
    uint32_t TPMpostLock                     : 1;
    uint32_t FIPS                            : 1;
    uint32_t Operator                        : 1;
    uint32_t enableRevokeEK                  : 1;
    uint32_t nvLocked                        : 1;
    uint32_t readSRKPub                      : 1;
    uint32_t tpmEstablished                  : 1;
    uint32_t maintenanceDone                 : 1;
} tpm_perm_flags_t;

typedef struct {
    uint32_t deactivated             : 1;
    uint32_t disableForceClear       : 1;
    uint32_t physicalPresence        : 1;
    uint32_t physicalPresenceLock    : 1;
    uint32_t bGlobalLock             : 1;
} tpm_stclear_flags_t;

static lcp_result_t display_flags(void)
{
    uint32_t subcap = 0;
    unsigned char buffer[BUFFER_SIZE], *pbuf;
    uint32_t datasize = 0;
    lcp_result_t result = LCP_E_COMD_INTERNAL_ERR;
    tpm_perm_flags_t perm_flags;
    tpm_stclear_flags_t stclear_flags;

    subcap = TPM_CAP_FLAG_PERMANENT;
    result = lcp_get_tpmcap_auth(password, passwd_length, TSS_TPMCAP_FLAG,
				 4, (unsigned char *)&subcap, &datasize,
				 buffer);

    if ( result != LCP_SUCCESS ) {
        log_error("Error getting TPM_PERMANENT_FLAGS.\n");
        return result;
    }
    else if ( datasize != 2*sizeof(uint32_t) ) {
        log_error("Error getting TPM_PERMANENT_FLAGS.\n");
        return LCP_E_GETCAP_REP_ERROR;
    }

    pbuf = buffer;
    lcp_unloaddata_uint32((uint32_t *)&perm_flags, &pbuf, 1);
    lcp_unloaddata_uint32((uint32_t *)&stclear_flags, &pbuf, 1);

    log_info("TPM_PERMANENT_FLAGS:\n");
    log_info("\t disable: %s\n", bool_to_str(perm_flags.disable));
    log_info("\t ownership: %s\n", bool_to_str(perm_flags.ownership));
    log_info("\t deactivated: %s\n", bool_to_str(perm_flags.deactivated));
    log_info("\t readPubek: %s\n", bool_to_str(perm_flags.readPubek));
    log_info("\t disableOwnerClear: %s\n",
	     bool_to_str(perm_flags.disableOwnerClear));
    log_info("\t allowMaintenance: %s\n",
	     bool_to_str(perm_flags.allowMaintenance));
    log_info("\t physicalPresenceLifetimeLock: %s\n",
	     bool_to_str(perm_flags.physicalPresenceLifetimeLock));
    log_info("\t physicalPresenceHWEnable: %s\n",
	     bool_to_str(perm_flags.physicalPresenceHWEnable));
    log_info("\t physicalPresenceCMDEnable: %s\n",
	     bool_to_str(perm_flags.physicalPresenceCMDEnable));
    log_info("\t CEKPUsed: %s\n", bool_to_str(perm_flags.CEKPUsed));
    log_info("\t TPMpost: %s\n", bool_to_str(perm_flags.TPMpost));
    log_info("\t TPMpostLock: %s\n", bool_to_str(perm_flags.TPMpostLock));
    log_info("\t FIPS: %s\n", bool_to_str(perm_flags.FIPS));
    log_info("\t Operator: %s\n", bool_to_str(perm_flags.Operator));
    log_info("\t enableRevokeEK: %s\n",
	     bool_to_str(perm_flags.enableRevokeEK));
    log_info("\t nvLocked: %s\n", bool_to_str(perm_flags.nvLocked));
    log_info("\t readSRKPub: %s\n", bool_to_str(perm_flags.readSRKPub));
    log_info("\t tpmEstablished: %s\n",
	     bool_to_str(perm_flags.tpmEstablished));
    log_info("\t maintenanceDone: %s\n",
	     bool_to_str(perm_flags.maintenanceDone));

    log_info("\nTPM_STCLEAR_FLAGS:\n");
    log_info("\t deactivated: %s\n", bool_to_str(stclear_flags.deactivated));
    log_info("\t disableForceClear: %s\n",
             bool_to_str(stclear_flags.disableForceClear));
    log_info("\t physicalPresence: %s\n",
             bool_to_str(stclear_flags.physicalPresence));
    log_info("\t physicalPresenceLock: %s\n",
             bool_to_str(stclear_flags.physicalPresenceLock));
    log_info("\t bGlobalLock: %s\n", bool_to_str(stclear_flags.bGlobalLock));

    return LCP_SUCCESS;
}


/* function: get_pubdata
 *
 * get public data of the index
 * public data format is:
 * {
 *     TPM_STRUCTURE_TAG tag;
 *     TPM_NV_INDEX nvIndex;
 *     TPM_PCR_INFO_SHORT pcrInfoRead;
 *     TPM_PCR_INFO_SHORT pcrInfoWrite;
 *     TPM_NV_ATTRIBUTES permission;
 *     TPM_BOOL bReadSTClear;
 *     TPM_BOOL bWriteSTClear;
 *     TPM_BOOL bWriteDefine;
 *     UINT32 dataSize;
 * }
 */
static lcp_result_t get_pubdata(uint32_t index)
{
    uint32_t index_retrieve = 0;
    uint16_t pcrread_sizeofselect = 0;
    uint16_t pcrwrite_sizeofselect = 0;
    uint32_t permission;
    uint32_t datasize = 0;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char *pbuffer;
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

    ret_value = lcp_get_tpmcap(TSS_TPMCAP_NV_INDEX, 4,
                    (unsigned char *)&index,
                    &datasize, buffer);

    if ( ret_value != LCP_SUCCESS )
        return ret_value;

    if ( datasize != 0 ) {
        /* start to parse public data of the index */
        pbuffer = buffer + sizeof(TPM_STRUCTURE_TAG);
        /* get the index value */
        lcp_unloaddata_uint32(&index_retrieve, &pbuffer, 1);

        /*
         * If the index retrieved correctly,
         * print the public data to the screen.
         */
        if ( index_retrieve == index ) {
            log_info("\nThe public data value of index 0x%08x is: \n", index);
            /* print the public data to the screen */
            print_nv_caps_msg(datasize, buffer, "");

            /* parse pcrInfoRead */
            lcp_unloaddata_uint16(&pcrread_sizeofselect, &pbuffer, 1);
            pbuffer += pcrread_sizeofselect;
            log_info("\n\tRead locality: ");
            print_locality(*pbuffer);
            log_info(".\n");

            /* move the pbuffer to the start of pcrInfoWrite */
            pbuffer += pcrread_sizeofselect
                       + sizeof(TPM_LOCALITY_SELECTION)
                       + sizeof(TPM_COMPOSITE_HASH);

            /* parse pcrInfoWrite */
            lcp_unloaddata_uint16(&pcrwrite_sizeofselect, &pbuffer, 1);
            pbuffer += pcrwrite_sizeofselect;
            log_info("\n\tWrite locality: ");
            print_locality(*pbuffer);
            log_info(".\n");

            /* move the pointer and get permission value */
            pbuffer += pcrwrite_sizeofselect
                     + sizeof(TPM_LOCALITY_SELECTION)
                     + sizeof(TPM_COMPOSITE_HASH)
                     + sizeof(TPM_STRUCTURE_TAG);
            lcp_unloaddata_uint32(&permission, &pbuffer, 1);
            log_info("\n\tPermission value is 0x%x:\n", permission);
            print_permissions(permission, "\t\t");

            /* move the pointer and get data size */
            pbuffer += sizeof(unsigned char) + sizeof(unsigned char)
                     + sizeof(unsigned char);
            lcp_unloaddata_uint32(&datasize, &pbuffer, 1);
            log_info("\n\tData size is %d.\n", datasize);
        }
	else
            return LCP_E_NV_AREA_NOT_EXIST;
    }
    else
        return LCP_E_NV_AREA_NOT_EXIST;

    return LCP_SUCCESS;
}

/* get the pcr number and nv index list of the TPM device */
static lcp_result_t get_common(void)
{
    uint16_t tmplen = 0;
    unsigned char buffer[BUFFER_SIZE];
    uint32_t datasize = 0;
    lcp_result_t result = LCP_E_COMD_INTERNAL_ERR;

    /*
     * Get the NV list.
     */
    result = lcp_get_tpmcap(TSS_TPMCAP_NV_LIST, 0, NULL, &datasize, buffer);

    if ( result != LCP_SUCCESS ) {
        log_error("Error get NV index list. \n");
        return result;
    }
    if ( datasize != 0 ) {
        tmplen = datasize/4;
        log_info("\n%d indices have been defined\n", tmplen);
        log_info("list of indices for defined NV storage areas:\n");
        print_nv_caps_msg(datasize, buffer, "0x");
    } else
        log_info("No index has been defined. \n");

    return LCP_SUCCESS;
}

int main (int argc, char *argv[])
{
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

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

    if ( perm_flags ) {
        if ( password == NULL ) {
            ret_value = LCP_E_AUTH_FAIL;
            log_error("No password input! Password is needed to "
                      "display flags.\n");
            goto _error_end;
        }
        ret_value = display_flags();
        if ( ret_value != LCP_SUCCESS )
            goto _error_end;
        return LCP_SUCCESS;
    }

    if ( index_value != 0 ) {
        if ( (ret_value = get_pubdata(index_value)) != LCP_SUCCESS )
            goto _error_end;
    }
    else if ( (ret_value = get_common()) != LCP_SUCCESS )
        goto _error_end;

    return LCP_SUCCESS;

_error_end:
    /*
     * Error when execute.
     */
    log_error("\nCommand TpmCap failed:\n");
    print_error(ret_value);
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
