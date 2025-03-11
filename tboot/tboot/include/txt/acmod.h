/*
 * acmod.c: support functions for use of Intel(r) TXT Authenticated
 *          Code (AC) Modules
 *
 * Copyright (c) 2003-2011, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __TXT_ACMOD_H__
#define __TXT_ACMOD_H__

typedef void   txt_heap_t;

/*
 * authenticated code (AC) module header (ver 0.0)
 */

typedef union {
    uint16_t _raw;
    struct {
        uint16_t  reserved          : 14;
        uint16_t  pre_production    : 1;
        uint16_t  debug_signed      : 1;
    };
} acm_flags_t;

typedef struct {
    uint16_t     module_type;
    uint16_t     module_subtype;
    uint32_t     header_len;
    uint32_t     header_ver;          /* currently 0.0 */
    uint16_t     chipset_id;
    acm_flags_t  flags;
    uint32_t     module_vendor;
    uint32_t     date;
    uint32_t     size;
    uint16_t     txt_svn;
    uint16_t     se_svn;
    uint32_t     code_control;
    uint32_t     error_entry_point;
    uint32_t     gdt_limit;
    uint32_t     gdt_base;
    uint32_t     seg_sel;
    uint32_t     entry_point;
    uint8_t      reserved2[64];
    uint32_t     key_size;
    uint32_t     scratch_size;
    uint8_t      rsa2048_pubkey[256];
    uint32_t     pub_exp;
    uint8_t      rsa2048_sig[256];
    uint32_t     scratch[143];//
    uint8_t      user_area[];
} acm_hdr_t;
extern acm_hdr_t *g_sinit;

/* value of module_type field */
#define ACM_TYPE_CHIPSET        0x02

/* value of module_subtype field */
#define ACM_SUBTYPE_RESET       0x01

/* value of module_vendor field */
#define ACM_VENDOR_INTEL        0x8086

/* ranges of padding present in TXTCR_SINIT_SIZE reg */
#define ACM_SIZE_MIN_PADDING    0x10000
#define ACM_SIZE_MAX_PADDING    0x40000

typedef union {
    uint32_t _raw;
    struct {
        uint32_t  ext_policy        : 2;
        uint32_t  tpm_family        : 4;
        uint32_t  tpm_nv_index_set  : 1;
        uint32_t  reserved          : 25;
    };
} tpm_cap_t;

/* ext_policy field values */
#define TPM_EXT_POLICY_ILLEGAL          0x00
#define TPM_EXT_POLICY_ALG_AGILE_CMD    0x01
#define TPM_EXT_POLICY_EMBEDED_ALGS     0x10
#define TPM_EXT_POLICY_BOTH             0x11

/* tpm_family field values */
#define TPM_FAMILY_ILLEGAL      0x0000
#define TPM_FAMILY_DTPM_12      0x0001
#define TPM_FAMILY_DTPM_20      0x0010
#define TPM_FAMILY_DTPM_BOTH    0x0011
#define TPM_FAMILY_PTT_20       0x1000

typedef struct {
    tpm_cap_t   capabilities;
    uint16_t    count;
    uint16_t    alg_id[];
} tpm_info_list_t;

typedef struct __packed {
    uuid_t      uuid;
    uint8_t     chipset_acm_type;
    uint8_t     version;             /* currently 7 */
    uint16_t    length;
    uint32_t    chipset_id_list;
    uint32_t    os_sinit_data_ver;
    uint32_t    min_mle_hdr_ver;
    txt_caps_t  capabilities;
    uint8_t     acm_ver;
    uint8_t     acm_revision[3];
    /* versions >= 4 */
    uint32_t    processor_id_list;
    /* versions >= 5 */
    uint32_t    tpm_info_list_off;
} acm_info_table_t;

/* ACM UUID value */
#define ACM_UUID_V3        {0x7fc03aaa, 0x46a7, 0x18db, 0xac2e, \
                                {0x69, 0x8f, 0x8d, 0x41, 0x7f, 0x5a}}

/* chipset_acm_type field values */
#define ACM_CHIPSET_TYPE_BIOS         0x00
#define ACM_CHIPSET_TYPE_SINIT        0x01
#define ACM_CHIPSET_TYPE_BIOS_REVOC   0x08
#define ACM_CHIPSET_TYPE_SINIT_REVOC  0x09

/* flexible ACM info table list IDs */
#define CPUL 0x4350554C
#define CS1L 0x4353314C
#define CS2L 0x4353324C
#define TERM 0x4E554C4C
#define TPML 0x54504D4C
#define VERL 0x5645524C

typedef struct __packed {
    uint32_t id;
    uint32_t size;
    uint32_t rev;
} list_header_t;

typedef struct __packed {
    uint32_t  flags;
    uint16_t  vendor_id;
    uint16_t  device_id;
    uint16_t  revision_id;
    uint16_t  register_mask;  //  reserved if ACM info table version < 9
    uint32_t  extended_id;
} acm_chipset_id_t;

typedef struct __packed {
    uint32_t           count;
    acm_chipset_id_t   chipset_ids[];
} acm_chipset_id_list_t;

typedef struct __packed {
    uint32_t  fms;
    uint32_t  fms_mask;
    uint64_t  platform_id;
    uint64_t  platform_mask;
} acm_processor_id_t;

typedef struct __packed {
    uint32_t             count;
    acm_processor_id_t   processor_ids[];
} acm_processor_id_list_t;

extern void print_txt_caps(const char *prefix, txt_caps_t caps);
extern bool is_racm_acmod(const void *acmod_base, uint32_t acmod_size, bool quiet);
extern acm_hdr_t *copy_racm(const acm_hdr_t *racm);
extern bool verify_racm(const acm_hdr_t *acm_hdr);
extern bool is_sinit_acmod(const void *acmod_base, uint32_t acmod_size, bool quiet);
extern bool does_acmod_match_platform(const acm_hdr_t* hdr, const txt_heap_t* txt_heap);
extern acm_hdr_t *copy_sinit(const acm_hdr_t *sinit);
extern bool verify_acmod(const acm_hdr_t *acm_hdr);
extern uint32_t get_supported_os_sinit_data_ver(const acm_hdr_t* hdr);
extern txt_caps_t get_sinit_capabilities(const acm_hdr_t* hdr);
extern tpm_info_list_t *get_tpm_info_list(const acm_hdr_t* hdr);
extern void verify_IA32_se_svn_status(const acm_hdr_t *acm_hdr);
#endif /* __TXT_ACMOD_H__ */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
