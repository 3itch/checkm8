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
 *   lcputils.c
 *
 *   This file implements all common functions used by the commands
 *   and key functions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <safe_lib.h>
#include <snprintf_s.h>
#define PRINT   printf
#include "../../include/uuid.h"
#include "../../include/lcp.h"
#include "lcptools.h"
#include "lcputils.h"

static const char *ret_info[] =
{
    NULL,    /* 0-LCP_SUCCESS, Each command will has its own success message.*/
    "Incorrect parameter input.",               /* 1-LCP_E_INVALID_PARAMETER */
    "Please input the index value",             /* 2-LCP_E_NO_INDEXVALUE     */
    "Please input the data size to be defined", /* 3-LCP_E_NO_DATASIZE       */
    "TSS API failed",                           /* 4-LCP_E_TSS_ERROR         */
    "Index has already been defined.",          /* 5-LCP_E_NV_AREA_EXIST     */
    "The index is incorrect or wrong "\
        "permission value.",                    /* 6-LCP_E_TPM_BADINDEX      */
    "The size of the data parameter is bad or "\
        "inconsistent with the referenced key.",/* 7-LCP_E_TPM_BAD_DATASIZE  */
    "The maximum number of NV writes without an owner has been reached.",
                                                /* 8-LCP_E_TPM_MAXNVWRITES   */
    "Please input authentication value.",       /* 9-LCP_E_NO_AUTH           */
    "Index does not exist.",                    /* 10-LCP_E_NV_AREA_NOT_EXIST*/
    "TPM_AREA_LOCKED. The index has been locked.",
                                                /* 11-LCP_E_TPM_AREA_LOCKED  */
    "Incorrect response when getting capability.",
                                                /* 12-LCP_E_GETCAP_REP_ERROR */
    "Please input the permission value for the index to be defined!",
                                                /* 13-LCP_E_NO_PER_VALUE     */
    "Invalid handler is returned.",             /* 14-LCP_E_INVALID_HANDLER  */
    "Authentication method conflict.",          /* 15-LCP_E_AUTH_CONFLICT    */
    "Authentication failed. Password or authencation value not match",
                                                /* 16-LCP_E_AUTH_FAIL        */
    "TPM owner set error!",                     /* 17-LCP_E_OWNER_SET        */
    "Wrong PCR value!",                         /* 18-LCP_E_TPM_WRONGPCRVALUE*/
    "Invalid structure!",                       /* 19-LCP_E_INVALID_STRUCTURE*/
    "TPM No Write error!",                      /* 20-LCP_E_NOWRITE          */
    "Bad locality error!",                      /* 21-LCP_E_TPM_BAD_LOCALITY */
    "Bad presence error!",                      /* 22-LCP_E_TPM_BAD_PRESENCE */
    "TPM disabled command error!",              /* 23-LCP_E_TPM_DISABLED_CMD */
    "TPM no space error!",                      /* 24-LCP_E_TPM_NOSPACE      */
    "TPM not full write error!",                /* 25-LCP_E_TPM_NOT_FULLWRITE*/
    "Incorrect parameter input.",               /* 26-LCP_E_NO_SUCH_PARAMETER*/
    "Creat policy_list error",                  /* 27-LCP_E_CREATE_POLLIST   */
    "Failed assign memory!",                    /* 28-LCP_E_OUTOFMEMORY      */
    "Hash failed!",                             /* 29-LCP_E_HASH_ERROR       */
    "Haven't input any parameter, please use -h for help",
                                                /* 30-LCP_E_NO_INPUTPARA     */
    "Internal error when executing the command",/* 31-LCP_E_COMD_INTERNAL_ERR*/
    NULL
};

/*
 * Parse the input param and return the corresponding option value
 * If the parameter is not correct, it will return -1
 */
uint32_t
parse_input_option(param_option_t *table, const char *arg)
{
    param_option_t *p = table;
    uint32_t ret_value = -1;

    while (p && p->param){
        if ( strcasecmp(arg, p->param) == 0 ) {
            ret_value = p->option;
            break;
        }
        p++;
    }
    return ret_value;
}

/*
 * Convert the string input into number.
 * This function can support both decimalist and hex
 */
int
strtonum(const char *in_para,  unsigned int *num_out)
{
    int ret_value = -1;
    char* endptr;
    uint64_t test_value;

    if( in_para == NULL || num_out == NULL )
        return -1;

    errno = 0;
    *num_out = (unsigned int)strtoul(in_para, &endptr, 0);
    if ( (*endptr == '\0') && (*in_para != '\0') && (errno == 0) ){
        test_value = (uint64_t)strtoull(in_para, &endptr, 0);
        if ( test_value == (uint64_t)(*num_out) )
            ret_value = 0;
    }

    return ret_value;
}

const char *
bool_to_str(int b)
{
    return b ? "TRUE" : "FALSE";
}

void
print_help(const char *usage_str, const char * option_string[])
{
    uint16_t i = 0;
    if ( usage_str == NULL || option_string == NULL )
        return;

    printf("\nUsage: %s\n", usage_str);

    for (; option_string[i] != 0; i++)
        printf("%s", option_string[i]);
}

void
print_error(lcp_result_t ret_value)
{
    log_error("\t%s\n", ret_info[ret_value]);
}

/*
 * Convert TSS error codes to our defined error codes.
 */
lcp_result_t
convert_error(TSS_RESULT result)
{
    lcp_result_t ret;
    switch (result & 0xfff) {
        case TSS_SUCCESS:              ret = LCP_SUCCESS; break;
        case TSS_E_INVALID_HANDLE:     ret = LCP_E_INVALID_HANDLER; break;
        case TSS_E_NV_AREA_EXIST:      ret = LCP_E_NV_AREA_EXIST; break;
        case TSS_E_NV_AREA_NOT_EXIST:  ret = LCP_E_NV_AREA_NOT_EXIST; break;
        case TSS_E_BAD_PARAMETER:      ret = LCP_E_INVALID_PARAMETER; break;
        case TSS_E_INTERNAL_ERROR:     ret = LCP_E_COMD_INTERNAL_ERR; break;
        case TPM_E_BADINDEX:           ret = LCP_E_TPM_BADINDEX; break;
        case TPM_E_AUTH_CONFLICT:      ret = LCP_E_AUTH_CONFLICT; break;
        case TPM_E_AUTHFAIL:           ret = LCP_E_AUTH_FAIL; break;
        case TPM_E_OWNER_SET:          ret = LCP_E_OWNER_SET; break;
        case TPM_E_BAD_DATASIZE:       ret = LCP_E_TPM_BAD_DATASIZE; break;
        case TPM_E_MAXNVWRITES:        ret = LCP_E_TPM_MAXNVWRITES; break;
        case TPM_E_INVALID_STRUCTURE:  ret = LCP_E_INVALID_STRUCTURE; break;
        case TPM_E_PER_NOWRITE:        ret = LCP_E_NOWRITE; break;
        case TPM_E_AREA_LOCKED:        ret = LCP_E_TPM_AREA_LOCKED; break;
        case TPM_E_BAD_LOCALITY:       ret = LCP_E_TPM_BAD_LOCALITY; break;
        case TPM_E_BAD_PRESENCE:       ret = LCP_E_TPM_BAD_PRESENCE; break;
        case TPM_E_DISABLED_CMD:       ret = LCP_E_TPM_DISABLED_CMD; break;
        case TPM_E_NOSPACE:            ret = LCP_E_TPM_NOSPACE; break;
        case TPM_E_NOT_FULLWRITE:      ret = LCP_E_TPM_NOT_FULLWRITE; break;
        case TPM_E_WRONGPCRVAL:        ret = LCP_E_TPM_WRONGPCRVALUE; break;
        default:                       ret = LCP_E_TSS_ERROR;
    } 

    return ret;
}

void
print_hexmsg(const char *header_msg, int datalength, const unsigned char *data)
{
    int i;

    log_info("%s", header_msg);

    for (i = 0; i < datalength; i++) {
        log_info("%02x ", *(data + i));
        if ( i % 16 == 15 )
            log_info("\n");
    }

    log_info("\n");
}

/* split the input string in the format: num1,num2,...,numN
 * into the numeric array = {num1, num2, ... , numN}
*/
void
str_split(char *str_in, uint32_t ints[], unsigned int *nr_ints)
{
    unsigned int nr = 0;
    char *str = NULL;

    while ( true ) {
        str = strsep(&str_in, ",");
        if ( str == NULL || nr == *nr_ints )
            break;
        ints[nr++] = strtoul(str, NULL, 0);
    }
    if ( nr == *nr_ints && str != NULL )
        log_error("Error: too many items in list\n");
    *nr_ints = nr;
}

uint16_t
lcp_decode_uint16(const unsigned char *in, uint8_t big_endian)
{
    uint16_t temp = 0;
    if ( in == NULL )
        return 0;
    if ( big_endian ) {
        temp = (in[1] & 0xFF);
        temp |= (in[0] << 8);
    } else {
        temp = (in[0] & 0xFF);
        temp |= (in[1] << 8);
    }
    return temp;
}

void
lcp_uint32toarray(uint32_t i, unsigned char *out, uint8_t big_endian)
{
    if ( out == NULL )
        return;

    if ( big_endian ) {
        out[0] = (unsigned char) ((i >> 24) & 0xFF);
        out[1] = (unsigned char) ((i >> 16) & 0xFF);
        out[2] = (unsigned char) ((i >> 8) & 0xFF);
        out[3] = (unsigned char) (i & 0xFF);
    } else {
        out[3] = (unsigned char) ((i >> 24) & 0xFF);
        out[2] = (unsigned char) ((i >> 16) & 0xFF);
        out[1] = (unsigned char) ((i >> 8) & 0xFF);
        out[0] = (unsigned char) (i & 0xFF);
    }
}

void
lcp_uint16toarray(uint16_t i, unsigned char *out, uint8_t big_endian)
{
    if ( out == NULL )
        return;

    if ( big_endian ) {
        out[0] = (unsigned char) ((i >> 8) & 0xFF);
        out[1] = (unsigned char) (i & 0xFF);
    } else {
        out[1] = (unsigned char) ((i >> 8) & 0xFF);
        out[0] = (unsigned char) (i & 0xFF);
    }
}

uint32_t
lcp_decode_uint32(const unsigned char *y, uint8_t big_endian)
{
    uint32_t x = 0;
    if ( y == NULL )
        return 0;

    if ( big_endian ) {
        x = y[0];
        x = ((x << 8) | (y[1] & 0xFF));
        x = ((x << 8) | (y[2] & 0xFF));
        x = ((x << 8) | (y[3] & 0xFF));
    } else {
        x = y[3];
        x = ((x << 8) | (y[2] & 0xFF));
        x = ((x << 8) | (y[1] & 0xFF));
        x = ((x << 8) | (y[0] & 0xFF));
    }

    return x;
}

void
lcp_loaddata_uint32(uint32_t in, unsigned char **blob, uint8_t big_endian)
{
    if ( blob == NULL )
        return;

    if ( *blob != NULL )
        lcp_uint32toarray(in, *blob, big_endian);
    *blob += sizeof(in);
}

void
lcp_loaddata_uint16(uint16_t in, unsigned char **blob, uint8_t big_endian)
{
    if ( blob == NULL )
        return;

    if ( *blob != NULL )
        lcp_uint16toarray(in, *blob, big_endian);
    *blob += sizeof(in);
}

void
lcp_unloaddata_uint32(uint32_t *out, unsigned char **blob, uint8_t big_endian)
{
    if ( blob == NULL || out == NULL )
        return;

    *out = lcp_decode_uint32(*blob, big_endian);
    *blob += sizeof(*out);
}

void
lcp_unloaddata_uint16(uint16_t *out, unsigned char **blob, uint8_t big_endian)
{
    if ( blob == NULL || out == NULL )
        return;

    *out = lcp_decode_uint16(*blob, big_endian);
    *blob += sizeof(*out);
}

void
lcp_loaddata_byte(unsigned char data, unsigned char **blob)
{
    if ( blob == NULL )
        return;

    if ( *blob != NULL )
        **blob = data;
    (*blob)++;
}

void
lcp_unloaddata_byte(unsigned char *dataout, unsigned char **blob)
{
    if ( blob == NULL || dataout == NULL )
        return;

    *dataout = **blob;
    (*blob)++;
}

void
lcp_loaddata(uint32_t size, unsigned char **container, unsigned char *object)
{
    if ( container == NULL || object == NULL )
        return;

    if ( *container )
        memcpy_s(*container, size, object, size);
    (*container) += size;
}

void
lcp_unloaddata(uint32_t size, unsigned char **container, unsigned char *object)
{
    if ( *container == NULL || object == NULL )
        return;

    memcpy_s(object, size, *container, size);
    (*container) += size;
}

/* init the context in the TSS */
TSS_RESULT
init_tss_context(TSS_HCONTEXT *hcontext)
{
    TSS_RESULT result;
    result = Tspi_Context_Create(hcontext);
    if ( (result) != TSS_SUCCESS )
        return result;

    result = Tspi_Context_Connect(*hcontext, NULL);
    return result;
}

/* close the TSS context */
void
close_tss_context(TSS_HCONTEXT hcontext)
{
    if ( hcontext != NULL_HCONTEXT ) {
        Tspi_Context_FreeMemory(hcontext, NULL);
        Tspi_Context_Close(hcontext);
    }
}

/* Set the password to the tpm object of the tss context */
TSS_RESULT
set_tpm_secret(TSS_HCONTEXT hcontext,
               TSS_HTPM *htpm,
               TSS_HPOLICY *hpolicy,
               const char *passwd,
               uint32_t passwd_length)
{
    TSS_RESULT result;
    /*
     * Get TPM object
     */
    result = Tspi_Context_GetTpmObject(hcontext, htpm);
    if ( result != TSS_SUCCESS )
        return result;

    result = Tspi_GetPolicyObject(*htpm, TSS_POLICY_USAGE, hpolicy);
    if ( result != TSS_SUCCESS )
        return result;

    /*
     * Set password
     */
    result = Tspi_Policy_SetSecret(*hpolicy, TSS_SECRET_MODE_PLAIN,
                                   passwd_length, (unsigned char *)passwd);
    return result;
}

/* Create the NV policy object and assign it to the NV object */
TSS_RESULT
set_nv_secret(TSS_HCONTEXT hcontext,
              TSS_HNVSTORE hnvstore,
              TSS_HPOLICY *hpolobj,
              const char *auth,
              uint32_t auth_len)
{
    TSS_RESULT result;
    /*
     * Create policy object for the NV object
     */
    result = Tspi_Context_CreateObject(hcontext,
                         TSS_OBJECT_TYPE_POLICY,
                         TSS_POLICY_USAGE, hpolobj);
    if ( result != TSS_SUCCESS )
        return result;

    /*
     * Set password
     */
    result = Tspi_Policy_SetSecret(*hpolobj, TSS_SECRET_MODE_PLAIN,
                                   auth_len, (unsigned char *)auth);
    if ( result != TSS_SUCCESS )
        return result;

    /*
     * Set password
     */
    result = Tspi_Policy_AssignToObject(*hpolobj, hnvstore);
    return result;
}

/* calculate the size of select for the pcr selection */
lcp_result_t
calc_sizeofselect(uint32_t num_indices,
                  uint32_t *indices,
                  TPM_PCR_SELECTION *pselect)
{
    uint32_t i;
    uint32_t idx;
    uint16_t bytes_to_hold;
    lcp_result_t ret;

    idx = indices[0];
    bytes_to_hold = (idx / 8) + 1;

    log_debug("bytes to hold is %d.\n", bytes_to_hold);
    /*
     * Create selection index first.
     */
    if ( (pselect->pcrSelect = malloc(bytes_to_hold)) == NULL ) {
        ret = LCP_E_OUTOFMEMORY;
        return ret;
    }
    pselect->sizeOfSelect = bytes_to_hold;
    memset_s(pselect->pcrSelect, bytes_to_hold, 0);

    /*
     * set the bit in the selection structure
     */
    pselect->pcrSelect[idx / 8] |= (1 << (idx % 8));

    for (i = 1; i < num_indices; i++) {
        idx = indices[i];
        bytes_to_hold = (idx / 8) + 1;
        log_debug("bytes to hold is %d.\n", bytes_to_hold);
        log_debug("size of select is %d.\n", pselect->sizeOfSelect);
        if ( pselect->sizeOfSelect < bytes_to_hold ) {
            if ( (pselect->pcrSelect = realloc(pselect->pcrSelect, bytes_to_hold))
                    == NULL ) {
                ret = LCP_E_OUTOFMEMORY;
                return ret;
            }
            /*
             * set the newly allocated bytes to 0
             */
            memset_s(&pselect->pcrSelect[pselect->sizeOfSelect],
                   bytes_to_hold - pselect->sizeOfSelect, 0);
            pselect->sizeOfSelect = bytes_to_hold;

        }
        pselect->pcrSelect[idx / 8] |= (1 << (idx % 8));
    }
    return LCP_SUCCESS;
}

void print_locality(unsigned char loc)
{
    char s[32] = "";

    if ( loc & ~0x1f )
        snprintf_s_i(s, sizeof(s), "unknown (%x)", loc);
    else {
        if ( !(loc & 0x1f) )
	    strcat_s(s, sizeof(s), "--, ");
	if ( loc & TPM_LOC_ZERO )
	    strcat_s(s, sizeof(s), "0, ");
	if ( loc & TPM_LOC_ONE )
	    strcat_s(s, sizeof(s), "1, ");
	if ( loc & TPM_LOC_TWO )
	    strcat_s(s, sizeof(s), "2, ");
	if ( loc & TPM_LOC_THREE )
	    strcat_s(s, sizeof(s), "3, ");
	if ( loc & TPM_LOC_FOUR )
	    strcat_s(s, sizeof(s), "4, ");
	/* remove trailing ", " */
	s[strnlen_s(s, sizeof(s)) - 2] = '\0';
    }

    log_info("%s", s);
}

void print_permissions(UINT32 perms, const char *prefix)
{
    if ( perms == 0 )
        log_info("%s --\n", prefix);
    if ( perms & TPM_NV_PER_READ_STCLEAR )
        log_info("%s TPM_NV_PER_READ_STCLEAR\n", prefix);
    if ( perms & TPM_NV_PER_AUTHREAD )
        log_info("%s TPM_NV_PER_AUTHREAD\n", prefix);
    if ( perms & TPM_NV_PER_OWNERREAD )
        log_info("%s TPM_NV_PER_OWNERREAD\n", prefix);
    if ( perms & TPM_NV_PER_PPREAD )
        log_info("%s TPM_NV_PER_PPREAD\n", prefix);
    if ( perms & TPM_NV_PER_GLOBALLOCK )
        log_info("%s TPM_NV_PER_GLOBALLOCK\n", prefix);
    if ( perms & TPM_NV_PER_WRITE_STCLEAR )
        log_info("%s TPM_NV_PER_WRITE_STCLEAR\n", prefix);
    if ( perms & TPM_NV_PER_WRITEDEFINE )
        log_info("%s TPM_NV_PER_WRITEDEFINE\n", prefix);
    if ( perms & TPM_NV_PER_WRITEALL )
        log_info("%s TPM_NV_PER_WRITEALL\n", prefix);
    if ( perms & TPM_NV_PER_AUTHWRITE )
        log_info("%s TPM_NV_PER_AUTHWRITE\n", prefix);
    if ( perms & TPM_NV_PER_OWNERWRITE )
        log_info("%s TPM_NV_PER_OWNERWRITE\n", prefix);
    if ( perms & TPM_NV_PER_PPWRITE )
        log_info("%s TPM_NV_PER_PPWRITE\n", prefix);
}
