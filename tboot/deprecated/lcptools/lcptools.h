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

#ifndef __LCPTOOLS_H__
#define __LCPTOOLS_H__

#define NULL_HCONTEXT     0
#define NULL_HOBJECT      0
#define NULL_HNVSTORE     0
#define NULL_HPCRS        NULL_HOBJECT
#define NULL_HPOLICY      NULL_HOBJECT
#define NULL_HTPM         NULL_HOBJECT

/* 
 * Define the return value of the commands.
 */
typedef uint16_t          lcp_result_t;

#define LCP_SUCCESS                 0   /* The command execute successful */
#define LCP_E_INVALID_PARAMETER     1   /* The input parameter not match
                                     the requirement */
#define LCP_E_NO_INDEXVALUE         2   /* Haven't input index value */
#define LCP_E_NO_DATASIZE           3   /* Haven't input data size value */
#define LCP_E_TSS_ERROR             4   /* TSS API revoke failed */
#define LCP_E_NV_AREA_EXIST         5   /* NV area reference have been defined,
                                     can't be defined again */
#define LCP_E_TPM_BADINDEX          6   /* Index value is invalid */
#define LCP_E_TPM_BAD_DATASIZE      7   /* The data size is invalid */
#define LCP_E_TPM_MAXNVWRITES       8   /* Exceed the max write time of NV */
#define LCP_E_NO_AUTH               9   /* Haven't input authentication value */
#define LCP_E_NV_AREA_NOT_EXIST    10   /* NV area reference haven't been
                                     defined before, can't be released */
#define LCP_E_TPM_AREA_LOCKED      11   /* The NV area is locked
                                     and not writeable */
#define LCP_E_GETCAP_REP_ERROR     12   /* Get capability returns
                                     incorrect response */
#define LCP_E_NO_PER_VALUE         13   /* Haven't input permission value */
#define LCP_E_INVALID_HANDLER      14   /* Invalid handler is returned */
#define LCP_E_AUTH_CONFLICT        15   /* Authentication method conflict */
#define LCP_E_AUTH_FAIL            16   /* Authentication failed */
#define LCP_E_OWNER_SET            17   /* TSS return error */
#define LCP_E_TPM_WRONGPCRVALUE    18   /* TSS return error */
#define LCP_E_INVALID_STRUCTURE    19   /* TSS return error */
#define LCP_E_NOWRITE              20   /* TSS return error */
#define LCP_E_TPM_BAD_LOCALITY     21   /* TSS return error */
#define LCP_E_TPM_BAD_PRESENCE     22   /* TSS return error */
#define LCP_E_TPM_DISABLED_CMD     23   /* TSS return error */
#define LCP_E_TPM_NOSPACE          24   /* TSS return error */
#define LCP_E_TPM_NOT_FULLWRITE    25   /* TSS return error */
#define LCP_E_NO_SUCH_PARAMETER    26   /* Can't find such kind of parameter */
#define LCP_E_CREATE_POLLIST       27   /* Create Polict List error */
#define LCP_E_OUTOFMEMORY          28   /* Failed memory assign */
#define LCP_E_HASH_ERROR           29   /* Failed when hash */
#define LCP_E_NO_INPUTPARA         30   /* No parameter has been input */
#define LCP_E_COMD_INTERNAL_ERR    31   /* Other err when run the command */

#define SHA1_HASH_LEN    20
#define SHA256_HASH_LEN  32

typedef struct {
    uint32_t index;
    uint32_t permission;
    uint32_t size;
    uint8_t  r_loc;
    uint8_t  w_loc;
} in_nv_definespace_t;

typedef struct {
    uint8_t algorithm;
    uint8_t list_version;
    uint16_t type;
    uint32_t listdata_length;
    unsigned char *listdata;
} pdlist_src_t;

lcp_result_t lcp_define_index(in_nv_definespace_t *p_in_defspace,
                              const char *auth,
                              uint32_t auth_length,
                              const char *passwd,
                              uint32_t passwd_length,
                              const unsigned char *read_srtm,
                              const unsigned char *write_srtm);
lcp_result_t lcp_release_index(uint32_t index_value,
                               const char *passwd,
                               uint32_t passwd_length);
lcp_result_t lcp_read_index(uint32_t index_value,
                            const char* password,
                            uint32_t pass_length,
                            uint32_t read_offset,
                            uint32_t read_length,
                            uint32_t* datalength,
                            unsigned char* data);
lcp_result_t lcp_write_index(uint32_t index_value,
                             const char* password,
                             uint32_t passwd_length,
                             uint32_t write_offset,
                             uint32_t fleng,
                             const unsigned char* policydata);
lcp_result_t lcp_create_pconf(uint32_t num_indices,
                              uint32_t* indices,
                              uint32_t pcr_len,
                              const unsigned char* pcr_hash_val,
                              unsigned char locality,
                              uint32_t* dataLen,
                             unsigned char** srtmdata);
lcp_result_t lcp_create_policy_list(pdlist_src_t policylist_src,
                                    uint32_t* policy_list_length,
                                    unsigned char* policy_list,
                                    uint8_t big_endian);
lcp_result_t lcp_create_unsigned_poldata(uint8_t policydata_version,
                                         uint8_t list_number,
                                         pdlist_src_t * listdata,
                                         uint32_t* data_length,
                                         unsigned char* data);
lcp_result_t lcp_create_policy(lcp_policy_t *policy,
                               uint32_t length,
                               const unsigned char* policy_dataorhash,
                               uint32_t* data_length,
                               unsigned char* data);
lcp_result_t lcp_get_tpmcap(uint32_t caparea,
                            uint32_t subcaplen,
                            const unsigned char *subcap,
                            uint32_t *outlen,
                            unsigned char *respdata);
lcp_result_t lcp_get_tpmcap_auth(const char *password,
				 uint32_t passwd_length,
				 uint32_t caparea,
				 uint32_t subcaplen,
				 const unsigned char *subcap,
				 uint32_t *outlen,
				 unsigned char *respdata);

#endif
