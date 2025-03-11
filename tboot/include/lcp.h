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

#ifndef __TXT_LCP_H__
#define __TXT_LCP_H__

#ifndef __packed
#define __packed   __attribute__ ((packed))
#endif

/*--------- LCP UUID ------------*/
#define LCP_POLICY_DATA_UUID   {0xab0d1925, 0xeee7, 0x48eb, 0xa9fc, \
                               {0xb, 0xac, 0x5a, 0x26, 0x2d, 0xe}}

/*--------- LCP Policy Algorithm ------------*/
#define LCP_POLHALG_SHA1    0

/*--------- LCP Policy Type ------------*/
#define LCP_POLTYPE_HASHONLY          0
#define LCP_POLTYPE_UNSIGNED          1
#define LCP_POLTYPE_SIGNED            2
#define LCP_POLTYPE_ANY               3
#define LCP_POLTYPE_FORCEOWNERPOLICY  4

/*--------- LCP Policy List type ------------*/
#define LCP_POLDESC_MLE_UNSIGNED      0x0001
#define LCP_POLDESC_PCONF_UNSIGNED    0x0002

/*--------- LCP reserved Indices------------*/
#define INDEX_LCP_DEF   0x50000001
#define INDEX_LCP_OWN   0x40000001
#define INDEX_AUX       0x50000002

/*------ Default Permission, size and locality for reserved Indices--------*/
#define PERMISSION_DEF  0x00002000
#define PERMISSION_OWN  0x00000002
#define PERMISSION_AUX  0x0

#define DATASIZE_POL    34
#define DATASIZE_AUX    64

#define LOCALITY_DEFAULT  0x1f
#define WR_LOCALITY_AUX   0x18


/*--------- Other data structures of LCP Policy ------------*/
#define SHA1_LENGTH        20
#define SHA256_LENGTH      32

typedef union {
    uint8_t    sha1[SHA1_LENGTH];
    uint8_t    sha256[SHA256_LENGTH];
} lcp_hash_t;

typedef struct __packed {
    uint8_t     version;
    uint8_t     hash_alg;        /* one of LCP_POLHALG_* */
    uint8_t     policy_type;     /* one of LCP_POLTYPE_* */
    uint8_t     sinit_revocation_counter;
    uint32_t    policy_control;
    uint16_t    reserved[3];
    lcp_hash_t  policy_hash;
} lcp_policy_t;

typedef struct __packed {
    uint8_t version;
    uint8_t count;
    union{
        lcp_hash_t*          hashes;
        TPM_PCR_INFO_SHORT*  pcrs;
    };
} lcp_unsigned_list_t;

typedef struct __packed {
    uint16_t             type;               /* One of LCP_POLDESC_*  */
    lcp_unsigned_list_t  unsigned_list;
} lcp_policy_list_t;

typedef struct __packed {
    uint8_t            version;
    uint8_t            policy_data_listsize;
    lcp_policy_list_t  policy_data_list[];
} lcp_unsigned_policy_data_t;

typedef struct __packed {
    uuid_t                      uuid;
    lcp_unsigned_policy_data_t  unsigned_data;
} lcp_policy_data_t;

#endif    /*  __TXT_LCP_H__ */
