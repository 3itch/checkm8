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
 * lcptools.c
 *
 * This file implements all key functions used by LCP tools commands.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../../include/uuid.h"
#include "../../include/lcp.h"
#include "lcptools.h"
#include "lcputils.h"

#define MAX_POLICY_LIST_SIZE 1024

/* Define the index
 * parameters:
 *     p_in_defspace: contain the attributes of the index,
 *                        for example, datasize, permission
 *     auth: password for the index with AUTHREAD/AUTHWRITE
 *     auth_length: the length of auth password
 *     passwd: the owner password
 *     passwd_length: the length of the passwd
 *     pcr_info_read: the pcr_short_info for pcrInfoRead
 *     pcr_info_write: the pcr_short_info for pcrInfoWrite
 */
lcp_result_t
lcp_define_index(in_nv_definespace_t *p_in_defspace,
                 const char *auth,
                 uint32_t auth_length,
                 const char *passwd,
                 uint32_t passwd_length,
                 const unsigned char *pcr_info_read,
                 const unsigned char *pcr_info_write)
{
    TSS_HCONTEXT hcontext             = NULL_HCONTEXT;
    TSS_HNVSTORE hnvstore             = NULL_HNVSTORE;
    TSS_HPOLICY hpolobj               = NULL_HOBJECT;
    TSS_HPCRS hwrtpcrcomp             = NULL_HPCRS;
    TSS_HPCRS hrdpcrcomp              = NULL_HPCRS;
    TSS_HPOLICY hpolicy               = NULL_HPOLICY;
    TSS_HTPM htpm                     = NULL_HTPM;

    TSS_RESULT result;

    uint16_t pcr_size                 = 0;
    unsigned char *pdata;
    unsigned char rd_locality         = 0;
    unsigned char wrt_locality        = 0;

    lcp_result_t ret                  = LCP_E_COMD_INTERNAL_ERR;

    result = init_tss_context(&hcontext);
    CHECK_TSS_RETURN_VALUE("init_tss_context", result, ret);

    if ( passwd != NULL ) {
        result = set_tpm_secret(hcontext, &htpm, &hpolicy,
                                passwd, passwd_length);
        CHECK_TSS_RETURN_VALUE("set_tpm_secret", result, ret);
    }

    /*
     * Create TPM NV object
     */
    result = Tspi_Context_CreateObject(hcontext, TSS_OBJECT_TYPE_NV,
                                       0,&hnvstore);
    CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject", result, ret);

    /*
     * if the nv object need authentication
     */
    if ( auth != NULL ) {
        result = set_nv_secret(hcontext, hnvstore, &hpolobj,
                               auth, auth_length);
        CHECK_TSS_RETURN_VALUE("set_nv_secret", result, ret);
    }

    /*
     * Set the index to be defined.
     */
    result = Tspi_SetAttribUint32(hnvstore, TSS_TSPATTRIB_NV_INDEX,
                                  0, p_in_defspace->index);
    CHECK_TSS_RETURN_VALUE("Tspi_SetAttribUint32 index", result, ret);

    /*
     * Set the permission for the index.
     */
    result = Tspi_SetAttribUint32(hnvstore, TSS_TSPATTRIB_NV_PERMISSIONS,
                                  0, p_in_defspace->permission);
    CHECK_TSS_RETURN_VALUE("Tspi_SetAttribUint32 permission", result, ret);

    /*
     * Set the data size to be defined.
     */
    result = Tspi_SetAttribUint32(hnvstore, TSS_TSPATTRIB_NV_DATASIZE,
                                  0, p_in_defspace->size);
    CHECK_TSS_RETURN_VALUE("Tspi_SetAttribUint32 data size", result, ret);

    /*
     * Define the space according to the parameters: index,
     * permission and datasize.
     * If the index is INDEX_AUX, the third parameter of
     * Tspi_NV_DefineSpace should be set.
     */
    if ( p_in_defspace->index == INDEX_AUX ) {
        /*
         * Set PCR composite object.
         */
        result = Tspi_Context_CreateObject(hcontext, TSS_OBJECT_TYPE_PCRS,
                                           3,&hwrtpcrcomp);
        CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject", result, ret);

        /*
         * Set LocalityAtRelease inside the PCR composite object.
         * Locality Write for INDEX_AUX should be 3 or 4.
         */
        result = Tspi_PcrComposite_SetPcrLocality(hwrtpcrcomp, WR_LOCALITY_AUX);
        CHECK_TSS_RETURN_VALUE("Tspi_PcrComposite_SetPcrLocality",
                result, ret);

        result = Tspi_NV_DefineSpace(hnvstore, 0, hwrtpcrcomp);
        CHECK_TSS_RETURN_VALUE("Tspi_NV_DefineSpace failed", result, ret);
    } else {
        /*
         * Set the locality number.
         */
        if ( pcr_info_read ) {
            /* parse the pcr_info_read which is pcr_short_info format */
            pdata = (unsigned char *)pcr_info_read;
            lcp_unloaddata_uint16(&pcr_size, &pdata, 1);
            pdata += pcr_size;
            lcp_unloaddata_byte(&rd_locality, &pdata);
            if ( rd_locality == 0 || rd_locality > 0x1f ) {
                log_error("Wrong read locality number!\n");
                ret = LCP_E_TPM_BAD_LOCALITY;
                goto exit;
            }
            /*
             * Set PCR composite object.
             */
            result = Tspi_Context_CreateObject(hcontext,
                        TSS_OBJECT_TYPE_PCRS, 3, &hrdpcrcomp);
            CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject",
                        result, ret);

            /*
             * Set LocalityAtRelease inside the PCR composite object.
             * Locality Write for INDEX_AUX should be 3 or 4.
             */
            result = Tspi_PcrComposite_SetPcrLocality(hrdpcrcomp, rd_locality);
            CHECK_TSS_RETURN_VALUE("Tspi_PcrComposite_SetPcrLocality",
                    result, ret);
        }

        if ( pcr_info_write != NULL ) {
            /* parse the pcr_info_write which is pcr_short_info format */
            pdata = (unsigned char *)pcr_info_write;
            lcp_unloaddata_uint16(&pcr_size, &pdata, 1);
            pdata += pcr_size;
            lcp_unloaddata_byte(&wrt_locality, &pdata);
            if ( wrt_locality == 0 || wrt_locality > 0x1f ) {
                log_error("Wrong read locality number!\n");
                ret = LCP_E_TPM_BAD_LOCALITY;
                goto exit;
            }
            /*
             * Set PCR composite object.
             */
            result = Tspi_Context_CreateObject(hcontext,
                    TSS_OBJECT_TYPE_PCRS, 3, &hwrtpcrcomp);
            CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject",
                    result, ret);

            /*
             * Set LocalityAtRelease inside the PCR composite object.
             * Locality Write for INDEX_AUX should be 3 or 4.
             */
            result = Tspi_PcrComposite_SetPcrLocality(hwrtpcrcomp,
                         wrt_locality);
            CHECK_TSS_RETURN_VALUE("Tspi_PcrComposite_SetPcrLocality",
                    result, ret);
        }

        result = Tspi_NV_DefineSpace(hnvstore, hrdpcrcomp, hwrtpcrcomp);
	CHECK_TSS_RETURN_VALUE("Tspi_NV_DefineSpace failed", result, ret);
    }

    ret = convert_error(result);

exit:
    /*
     * Close context for the operation.
     */
    close_tss_context(hcontext);

    return ret;
}

/* Release the index
 * Parameters:
 *     index: the index to be release
 *     passwd: the owner password
 *     passwd_length: the length of the passwd
 */
lcp_result_t
lcp_release_index(uint32_t index,
                  const char *passwd,
                  uint32_t passwd_length)
{
    TSS_HCONTEXT hcontext           = NULL_HCONTEXT;
    TSS_HNVSTORE hnvstore           = NULL_HNVSTORE;
    TSS_HPOLICY hpolicy             = NULL_HPOLICY;
    TSS_HTPM htpm                   = NULL_HTPM;

    TSS_RESULT result;
    lcp_result_t ret                  = LCP_E_COMD_INTERNAL_ERR;

    result = init_tss_context(&hcontext);
    CHECK_TSS_RETURN_VALUE("init_tss_context", result, ret);


    if ( passwd != NULL ) {
        result = set_tpm_secret(hcontext, &htpm, &hpolicy,
                                passwd, passwd_length);
        CHECK_TSS_RETURN_VALUE("set_tpm_secret", result, ret);
    }

    /*
     * Create TPM NV object
     */
    result = Tspi_Context_CreateObject(hcontext, TSS_OBJECT_TYPE_NV,
                                       0,&hnvstore);
    CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject", result, ret);

    /*
     * Set the index to be released.
     */
    result = Tspi_SetAttribUint32(hnvstore, TSS_TSPATTRIB_NV_INDEX,
                                  0, index);
    CHECK_TSS_RETURN_VALUE("Tspi_SetAttribUint32 for setting NV index",
            result, ret);

    /*
     * Release the space according to the parameters: index and datasize.
     */
    result = Tspi_NV_ReleaseSpace(hnvstore);
    CHECK_TSS_RETURN_VALUE("Tspi_NV_ReleaseSpace for deleting NV index",
            result, ret);

    ret = convert_error(result);

exit:
    /*
     * Close context for the operation.
     */
    close_tss_context(hcontext);

    return ret;
}

/* Read the content from the specified index
 * Parameters:
 *     index: the index to be release
 *     password: the owner password or the auth password of the index
 *     passwd_length: the length of the passwd
 *     read_offset: the offset to read
 *     read_length: the length to read
 *     data_length: the length of the data
 *     data: the data read from the index
 */
lcp_result_t
lcp_read_index(uint32_t index,
               const char *password,
               uint32_t pass_length,
               uint32_t read_offset,
               uint32_t read_length,
               uint32_t *data_length,
               unsigned char *data)
{
    TSS_HCONTEXT hcontext           = NULL_HCONTEXT;
    TSS_HNVSTORE hnvstore           = NULL_HNVSTORE;
    TSS_HTPM htpm                   = NULL_HOBJECT;

    TSS_RESULT result;
    TSS_HPOLICY hnvpol;
    lcp_result_t ret                  = LCP_E_COMD_INTERNAL_ERR;
    uint32_t retlen;
    unsigned char *presult                   = NULL;
    unsigned char *policydata                = NULL;

    uint32_t pwd_length               = pass_length;
    uint32_t read_space               = 0;

    result = init_tss_context(&hcontext);
    CHECK_TSS_RETURN_VALUE("init_tss_context", result, ret);

    /*
     * Create TPM NV object
     */
    result = Tspi_Context_CreateObject(hcontext, TSS_OBJECT_TYPE_NV,
                                       0,&hnvstore);
    CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject for nv object",
            result, ret);

    /*
     * Set the index to read
     */
    result = Tspi_SetAttribUint32(hnvstore, TSS_TSPATTRIB_NV_INDEX,
                                  0, index);
    CHECK_TSS_RETURN_VALUE("Tspi_SetAttribUint32 for setting NV index",
            result, ret);

    if ( password != NULL ) {
        result = set_nv_secret(hcontext, hnvstore, &hnvpol,
                               password, pwd_length);
        CHECK_TSS_RETURN_VALUE("set_nv_secret", result, ret);
    }

    /*
     * Data length to read.
     */
    read_space = read_length;
    if ( (read_length == 0)&&(read_offset == 0) ) {
        result = Tspi_Context_GetTpmObject(hcontext, &htpm);
        CHECK_TSS_RETURN_VALUE("Tspi_Context_GetTpmObject", result, ret);

        result = Tspi_TPM_GetCapability(htpm,
                     TSS_TPMCAP_NV_INDEX,
                     4, (unsigned char *)&index,
                     &retlen, &presult);
        CHECK_TSS_RETURN_VALUE("Tspi_TPM_GetCapability", result, ret);

        presult += retlen - 4;
        if ( retlen != 0 )
            lcp_unloaddata_uint32(&read_space, &presult, 1);
        else {
            ret = LCP_E_TPM_BADINDEX;
            goto exit;
        }
    }

    if ( data == NULL || read_space > *data_length ) {
        log_info("Data size to read is %d.\n", read_space);
        log_info("Not enough memory allocated for output data! "\
                "Max size allocated is %d.\n",
                *data_length);
        ret = LCP_E_INVALID_PARAMETER;
        goto exit;
    }

    /*
     * Read policy data from NV store.
     */
    log_debug("begin to call the tss Tspi_NV_ReadValue\n");
    result = Tspi_NV_ReadValue(hnvstore, read_offset, &read_space, &policydata);

    /*
     * Print error massage.
     */
    if ( result != TSS_SUCCESS ) {
        ret = convert_error(result);
        goto exit;
    }

    ret = LCP_SUCCESS;
    memcpy_s(data, *data_length, policydata, read_space);
    *data_length = read_space;

exit:
    close_tss_context(hcontext);
    return ret;
}

/* Write the data into the specified index
 * Parameters:
 *     index: the index to be release
 *     password: the owner password or the auth password of the index
 *     passwd_length: the length of the passwd
 *     write_offset: the offset to write
 *     length: the length of the data
 *     data: the data to write
 */
lcp_result_t
lcp_write_index(uint32_t index,
                const char *password,
                uint32_t passwd_length,
                uint32_t write_offset,
                uint32_t length,
                const unsigned char *data)
{

    TSS_HCONTEXT hcontext           = NULL_HCONTEXT;
    TSS_HNVSTORE hnvstore           = NULL_HNVSTORE;
    TSS_RESULT result;
    TSS_HPOLICY hnvpol;
    lcp_result_t ret                  = LCP_E_COMD_INTERNAL_ERR;
    uint32_t pwd_length               = passwd_length;

    result = init_tss_context(&hcontext);
    CHECK_TSS_RETURN_VALUE("init_tss_context", result, ret);

    /*
     * Create TPM NV object
     */
    result = Tspi_Context_CreateObject(hcontext, TSS_OBJECT_TYPE_NV,
                                       0,&hnvstore);
    CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject", result, ret);

    /*
     * Set the index to write
     */
    result = Tspi_SetAttribUint32(hnvstore, TSS_TSPATTRIB_NV_INDEX,
                                  0, index);
    CHECK_TSS_RETURN_VALUE("Tspi_SetAttribUint32 for setting NV index",
            result, ret);

    if ( password != NULL ) {
        result = set_nv_secret(hcontext, hnvstore, &hnvpol,
                               password, pwd_length);
        CHECK_TSS_RETURN_VALUE("set_nv_secret", result, ret);
    }

    /*
     * Write data value to the NV store area.
     */
    result = Tspi_NV_WriteValue(hnvstore,
                     write_offset, length, (unsigned char *)data);

    /*
     * Print error massage.
     */
    if ( result != TSS_SUCCESS ) {
        ret = convert_error(result);
        goto exit;
    }
    ret = LCP_SUCCESS;

exit:
    close_tss_context(hcontext);
    return ret;
}

/* create the platform configuration
 * parameters:
 *     num_indices: the count of the pcr_number
 *     indices: the array of the pcr_numbers
 *     pcr_len: the length of the pcr_hash_value
 *     pcr_hash_val: the array of the pcr_values
 *     locality: the locality value for the pcr_short_info
 *     datalen: the length of produced pconf data
 *     data: the produced pconf data
 */
lcp_result_t
lcp_create_pconf(uint32_t num_indices,
                 uint32_t *indices,
                 uint32_t pcr_len,
                 const unsigned char *pcr_hash_val,
                 unsigned char locality,
                 uint32_t *datalen,
                 unsigned char **data)
{
    TSS_HCONTEXT hcontext               = NULL_HCONTEXT;
    TSS_HPCRS hpcrs                     = NULL_HPCRS;
    TSS_HTPM htpm                       = NULL_HOBJECT;
    TPM_PCR_SELECTION pselect;

    TSS_RESULT result                   = TSS_SUCCESS;
    lcp_result_t ret                      = LCP_E_COMD_INTERNAL_ERR;
    uint32_t idx;
    unsigned char *pcrval                        = NULL;
    uint32_t pcrlen;
    unsigned char hpcrhash[SHA1_HASH_LEN];
    uint32_t hashlen                      = SHA1_HASH_LEN;
    uint64_t offset = 0;
    unsigned char *pdata;
    unsigned char *pcr_info                      = NULL;
    uint32_t pcr_info_size                = 0;
    uint32_t size, index;
    unsigned char mask;
    unsigned char *pcr_read                      = NULL;
    uint32_t pcr_hash_size                = 0;

    if ( (num_indices == 0) || (indices == NULL) )
        return LCP_E_INVALID_PARAMETER;

    /* calculate the sizeofselect for the pconf*/
    ret = calc_sizeofselect(num_indices, indices, &pselect);
    if ( ret != LCP_SUCCESS )
        goto free_memory;

    /* decide whether need to read the pcr_value from the TPM */
    if ( pcr_hash_val != NULL ) {
        /* use the pcr values from the input */
        if ( pcr_len != num_indices * SHA1_HASH_LEN ) {
            log_error("Hash value length is not correct!\n");
            ret = LCP_E_INVALID_PARAMETER;
            return ret;
        }

        if ( Trspi_Hash(TSS_HASH_SHA1, pcr_len, (unsigned char *)pcr_hash_val,
                        hpcrhash) != TSS_SUCCESS ) {
            log_error("Calculate Hash value for Policy Data error!\n");
            ret = LCP_E_HASH_ERROR;
            return ret;
        }
    } else {
        /* get the pcr value from the tpm*/
        result = init_tss_context(&hcontext);
        CHECK_TSS_RETURN_VALUE("init_tss_context", result, ret);
        /*
         * Get the TPM object.
         */
        result = Tspi_Context_GetTpmObject(hcontext, &htpm);
        CHECK_TSS_RETURN_VALUE("Tspi_Context_GetTpmObject", result, ret);

        /*
         * Create PCR Composite object
         */
        result = Tspi_Context_CreateObject(hcontext, TSS_OBJECT_TYPE_PCRS,
                     TSS_PCRS_STRUCT_INFO_SHORT,&hpcrs);
        CHECK_TSS_RETURN_VALUE("Tspi_Context_CreateObject", result, ret);

        /* malloc the data buffer for the pcr value*/
        pcr_hash_size = num_indices * SHA1_HASH_LEN;
        pcr_read = (unsigned char *)malloc(pcr_hash_size);
        if ( pcr_read == NULL ) {
            log_error("Out of memory!\n");
            ret = LCP_E_OUTOFMEMORY;
            return ret;
        }

        /* read the pcr value for each pcr_number in the pselect */
        pdata = pcr_read;
        for (size = 0; size < pselect.sizeOfSelect; size++) {
            for (index = 0, mask = 1; index < 8; index++, mask = mask << 1) {
                if ( pselect.pcrSelect[size] & mask ) {
                    idx = index + (size << 3);
                    /*
                     * Read the PCR value.
                     */
                    if ( (result = Tspi_TPM_PcrRead(htpm, idx, &pcrlen,
                                    &pcrval)) != TSS_SUCCESS ) {
                        log_error("Read PCR value error! PCR Index = %d\n",
                                   idx);
                        log_error("TSS API returns error.\n");
                        ret = LCP_E_TSS_ERROR;
                        goto exit;
                    }
                    /*
                     * Load the PCR value read from TPM.
                     */
                    lcp_loaddata(SHA1_HASH_LEN, &pdata, pcrval);
                }
            }
        }

        if ( Trspi_Hash(TSS_HASH_SHA1, pcr_hash_size,
                       pcr_read, hpcrhash) != TSS_SUCCESS ) {
            log_error("Calculate Hash value for Policy Data error!\n");
            ret = LCP_E_HASH_ERROR;
            return ret;
        }
    }
    /*
     * Caculate return length and allocate memory.
     */
    pcr_info_size = sizeof(pselect.sizeOfSelect)
                    + pselect.sizeOfSelect + 1 + hashlen;
    if ( (pcr_info = calloc(1, pcr_info_size)) == NULL ) {
        log_error("Out of memory!\n");
        ret = LCP_E_OUTOFMEMORY;
        goto exit;
    }

    /*
     *Create the PCR_INFO_SHORT structure.
     */
    offset = 0;
    Trspi_LoadBlob_PCR_SELECTION(&offset, pcr_info, &pselect);
    Trspi_LoadBlob_BYTE(&offset, locality, pcr_info);
    Trspi_LoadBlob(&offset, hashlen, pcr_info, hpcrhash);

    *data = pcr_info;
    *datalen = pcr_info_size;

    /*
     * Execute successfully.
     */
    log_info("Successfully Created PConf data!\n");
    if ( pcr_read != NULL )
        free(pcr_read);

    return LCP_SUCCESS;
exit:
    close_tss_context(hcontext);

free_memory:
    if ( ret != LCP_SUCCESS ) {
        if ( pcr_info != NULL )
            free(pcr_info);
    }
    if ( pselect.pcrSelect != NULL )
        free(pselect.pcrSelect);
    if ( pcr_read != NULL )
        free(pcr_read);
    return ret;
}

/* Create the policy list for the policy data
 * the list format is :
 *     {
 *         uint16_t listtype;
 *         uint8_t list_version;
 *         uint8_t listsize;
 *         union {
 *             LCP_HASH HashList[listsize];
 *             TPM_PCR_INFO_SHORT PCRInfoList[listsize];
 *         }
 * Parameters:
 *     src: the input of the data, type, version
 *     data_length: the length of produced policy list
 *     data: the produced policy list
 *     big_endian: create the big or little endian policy list
 */
lcp_result_t
lcp_create_policy_list(pdlist_src_t src,
                   uint32_t *data_length,
                   unsigned char *data,
                   uint8_t big_endian)
{
    uint8_t ver                = src.list_version;
    uint8_t hashlen            = SHA1_HASH_LEN;
    uint8_t listsize           = 0;
    uint32_t read_offset       = 0;
    unsigned char *pdata = data;
    unsigned char *pread_data;
    uint16_t select;
    uint16_t pcr_length;
    uint16_t list_type;
    uint32_t len               = sizeof(src.type) + sizeof(src.list_version)
                                 + sizeof(listsize) + src.listdata_length;

    lcp_result_t result        = LCP_E_COMD_INTERNAL_ERR;

    if ( data == NULL ) {
        log_error("Pass in NULL pointer when creating LCP Policy List!\n");
        result = LCP_E_COMD_INTERNAL_ERR;
        return result;
    }

    if ( *data_length < len ) {
        log_error("the data have no enough space\n");
        result = LCP_E_COMD_INTERNAL_ERR;
        return result;
    }

    switch (src.type) {
        case LCP_POLDESC_MLE_UNSIGNED:
            list_type = LCP_POLDESC_MLE_UNSIGNED;
            /*
             * allow the 1 more data length in the file
             */
            if ( (src.listdata_length % hashlen > 1)
                ||(src.listdata_length / hashlen > 255) ) {
                log_error("the policy list data is not correct\n");
                result = LCP_E_COMD_INTERNAL_ERR;
                return result;
            }

            listsize = src.listdata_length / hashlen;
            lcp_loaddata_uint16(list_type, &pdata, big_endian);

            lcp_loaddata_byte(ver, &pdata);
            lcp_loaddata_byte(listsize, &pdata);
            lcp_loaddata(listsize*hashlen, &pdata, src.listdata);
            *data_length = len - (src.listdata_length % hashlen);

            break;

        case LCP_POLDESC_PCONF_UNSIGNED:
            list_type = LCP_POLDESC_PCONF_UNSIGNED;

            lcp_loaddata_uint16(list_type, &pdata, big_endian);
            lcp_loaddata_byte(ver, &pdata);
            pdata += 1;
            /*
             * we will write the list size value
             * after parse data finished, just skip 1 byte now.
             * Parse the pconf list first
             */
            pread_data = (unsigned char *)src.listdata;
            read_offset = 0;
            listsize =0;
            for ( ; read_offset < src.listdata_length - 1; listsize++) {
                /*
                 * we need to read at least 2 byte to get the sizeof select
                 */
                lcp_unloaddata_uint16(&select, &pread_data, 1);
                log_debug("the select of list [%d] is %d\n", listsize, select);
                pcr_length = select + sizeof(select)
                             + sizeof(TPM_LOCALITY_SELECTION) + SHA1_HASH_LEN;
                /* check whether the data input is long enough */
                if ( (pcr_length + (size_t)(pread_data - src.listdata) -2)
                        > src.listdata_length ) {
                    log_error("the policy list data is not correct\n");
                    result = LCP_E_COMD_INTERNAL_ERR;
                    return result;
                }

                /* load the data into the policy list */
                lcp_loaddata_uint16(select, &pdata, big_endian);
                lcp_loaddata(pcr_length - 2, &pdata, pread_data);
                pread_data += pcr_length - 2;

                read_offset = (uint32_t)(pread_data - src.listdata);
                /* check whether the data input is too long*/
                if ( (listsize == 255)
                    && ((src.listdata_length - read_offset) > 1) ){
                    log_error("the policy list data is too big\n");
                    result = LCP_E_COMD_INTERNAL_ERR;
                    return result;
                }
            }

            /*
             * check whether the input is correct, allow 1 more char
             */
            if ( src.listdata_length - read_offset > 1 ) {
                log_error("the policy list data is not correct\n");
                result = LCP_E_COMD_INTERNAL_ERR;
                return result;
            }

            /*
             * reset the offset value after parsing data finished.
             */
            pdata = data + 3;
            lcp_loaddata_byte(listsize, &pdata);

            *data_length = len - (src.listdata_length - read_offset);

            break;

        default:
            log_error("the policy list type is not supported\n");
            result = LCP_E_COMD_INTERNAL_ERR;
            return result;
    }
    return LCP_SUCCESS;
}

/* Create the unsigned lcp policy data in little endian format
 * Parameters:
 *     version: the policy data version
 *     list_number: the count of the policy list
 *     listdata: the plicylist array
 *     data_length: the length of produced policy data
 *     data: the produced policy data
*/
lcp_result_t
lcp_create_unsigned_poldata(uint8_t version,
                            uint8_t list_number,
                            pdlist_src_t *listdata,
                            uint32_t *data_length,
                            unsigned char *data)
{
    unsigned char policylist[MAX_POLICY_LIST_SIZE];
    uint32_t policy_list_len                  = MAX_POLICY_LIST_SIZE;
    uint32_t i                                = 0;
    unsigned char *pdata = data;
    lcp_result_t ret                          = LCP_E_COMD_INTERNAL_ERR;
    uuid_t uuid = LCP_POLICY_DATA_UUID;

    if ( *data_length <
            (sizeof(uuid_t) + sizeof(version) + sizeof(list_number)) ) {
        log_error("the policy data buf is not enough\n");
        ret = LCP_E_INVALID_PARAMETER;
        return ret;
    }
    /* begin to produce the header of the policy data */
    lcp_loaddata_uint32(uuid.data1, &pdata, 0);
    lcp_loaddata_uint16(uuid.data2, &pdata, 0);
    lcp_loaddata_uint16(uuid.data3, &pdata, 0);
    lcp_loaddata_uint16(uuid.data4, &pdata, 0);
    lcp_loaddata(6, &pdata, uuid.data5);
    lcp_loaddata_byte(version, &pdata);
    lcp_loaddata_byte(list_number, &pdata);

    for (i = 0; i < list_number; i++ ) {
        log_debug("create the policy list %d\n", i);
        policy_list_len = MAX_POLICY_LIST_SIZE;
        if ( lcp_create_policy_list(*(listdata+i), &policy_list_len,
                              policylist, 0) ) {
            ret = LCP_E_CREATE_POLLIST;
            return ret;
        }
        /* check whether the return buffer is enough */
        if ( ((pdata -data) + policy_list_len) > *data_length ) {
            log_error("the policy data buf is not enough\n");
            ret = LCP_E_INVALID_PARAMETER;
            return ret;
        }
        lcp_loaddata(policy_list_len, &pdata, policylist);
    }
    *data_length = (uint32_t)(pdata -data);
    return LCP_SUCCESS;
}

/* Create the lcp policy in big endian format
 * Parameters:
 *     policy: the input infoes for policy, for example, the version, type...
 *     length: the length of the policy data or the mle hash value
 *     policy_dataorhash: the policy data or the mle hash value
 *     data_length: the length of the produced policy
 *     data: the length of the produced policy
 */
lcp_result_t
lcp_create_policy(lcp_policy_t *policy,
                  uint32_t length,
                  const unsigned char *policy_dataorhash,
                  uint32_t *data_length,
                  unsigned char *data)
{
    unsigned char polhash[SHA1_HASH_LEN]       = { 0 };
    uint32_t policy_length                     = DATASIZE_POL;
    unsigned char hashval[SHA1_HASH_LEN];
    uint32_t hash_len                          = SHA1_HASH_LEN;
    unsigned char *pdata = data;
    lcp_result_t result                        = LCP_E_COMD_INTERNAL_ERR;

    if ( policy->policy_type == LCP_POLTYPE_SIGNED ) {
        log_error("signed policy is not support\n");
        result = LCP_E_INVALID_PARAMETER;
        return result;
    }

    if ( *data_length < policy_length ) {
        log_error("the data buf is not enough\n");
        result = LCP_E_COMD_INTERNAL_ERR;
        return result;
    }

    lcp_loaddata_byte(policy->version, &pdata);
    lcp_loaddata_byte(policy->hash_alg, &pdata);
    lcp_loaddata_byte(policy->policy_type, &pdata);
    lcp_loaddata_byte(policy->sinit_revocation_counter, &pdata);
    lcp_loaddata_uint32(policy->policy_control, &pdata, 1);
    lcp_loaddata_uint16(policy->reserved[0], &pdata, 1);
    lcp_loaddata_uint16(policy->reserved[1], &pdata, 1);
    lcp_loaddata_uint16(policy->reserved[2], &pdata, 1);

    if ( policy->policy_type == LCP_POLTYPE_UNSIGNED ) {

        if ( Trspi_Hash(TSS_HASH_SHA1, length,
                       (unsigned char *)policy_dataorhash,
                       hashval) != TSS_SUCCESS ) {
            log_error("Calculate Hash value for Policy Data error!\n");
            result = LCP_E_HASH_ERROR;
            return result;
        }
        lcp_loaddata(hash_len, &pdata, hashval);
    } else if ( policy->policy_type == LCP_POLTYPE_HASHONLY ) {
        if ( length != (policy_length - (DATASIZE_POL - SHA1_HASH_LEN)) ) {
            log_error("the hash length is not correct\n");
            result = LCP_E_COMD_INTERNAL_ERR;
            return result;
        }
        lcp_loaddata(length, &pdata, (unsigned char *)policy_dataorhash);
    } else {
        lcp_loaddata(SHA1_HASH_LEN, &pdata, polhash);
    }

    *data_length = policy_length;
    return LCP_SUCCESS;
}

/* get the tpm capibilities
 * Parameters:
 *     caparea: the capability to get
 *     subcaplen: the length of the sub capablity value
 *     subcap: the sub capolibity to get
 *     outlen: the length of return value
 *     resp_data: the response data
 */
lcp_result_t
lcp_get_tpmcap(uint32_t caparea,
               uint32_t subcaplen,
               const unsigned char *subcap,
               uint32_t *outlen,
               unsigned char *resp_data)
{
    return lcp_get_tpmcap_auth(NULL, 0, caparea, subcaplen, subcap, outlen,
			       resp_data);
}

/* get the tpm capibilities
 * Parameters:
 *     password: ownerauth
 *     psswd_length: length of ownerauth
 *     caparea: the capability to get
 *     subcaplen: the length of the sub capablity value
 *     subcap: the sub capolibity to get
 *     outlen: the length of return value
 *     resp_data: the response data
 */
lcp_result_t
lcp_get_tpmcap_auth(const char *password,
		    uint32_t passwd_length,
		    uint32_t caparea,
		    uint32_t subcaplen,
		    const unsigned char *subcap,
		    uint32_t *outlen,
		    unsigned char *resp_data)
{
    TSS_HCONTEXT hcontext       = NULL_HCONTEXT;
    TSS_HTPM htpm               = NULL_HTPM;
    TSS_HPOLICY hpolicy         = NULL_HPOLICY;

    TSS_RESULT result;
    uint32_t i                  = 0;
    lcp_result_t ret            = LCP_E_COMD_INTERNAL_ERR;
    unsigned char *resp;

    result = init_tss_context(&hcontext);
    CHECK_TSS_RETURN_VALUE("init_tss_context", result, ret);


    if ( password != NULL ) {
        result = set_tpm_secret(hcontext, &htpm, &hpolicy,
                                password, passwd_length);
        CHECK_TSS_RETURN_VALUE("set_tpm_secret", result, ret);
    }
    else {
        /*
	 * Get the TPM object.
	 */
        result = Tspi_Context_GetTpmObject(hcontext, &htpm);
	CHECK_TSS_RETURN_VALUE("Tspi_Context_GetTpmObject", result, ret);
    }

    result = Tspi_TPM_GetCapability(htpm, caparea, subcaplen,
				    (unsigned char *)subcap, outlen, &resp);
    CHECK_TSS_RETURN_VALUE("Tspi_TPM_GetCapability", result, ret);

    log_debug("The response data is:\n" );
    for (i = 0; i < *outlen; i++) {
        log_debug("%02x ", resp[i]);

        if ( i%16 == 15 )
            log_debug("\n");
    }
    log_debug("\n");

    memcpy_s(resp_data,*outlen, resp, *outlen);
    ret = LCP_SUCCESS;

exit:
    close_tss_context(hcontext);
    return ret;
}
