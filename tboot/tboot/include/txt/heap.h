/*
 * heap.h: Intel(r) TXT heap definitions
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

#ifndef __TXT_HEAP_H__
#define __TXT_HEAP_H__
/*
 * Extensible TXT heap data structure
 */

typedef struct __packed {
    uint32_t   type;
    uint32_t   size;
    uint8_t    data[];
} heap_ext_data_element_t;

/*
 * HEAP_END_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_END             0

/* size == 8; there is no data[] */

/*
 * HEAP_BIOS_SPEC_VER_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_BIOS_SPEC_VER   1

typedef struct __packed {
    uint16_t   spec_ver_major;
    uint16_t   spec_ver_minor;
    uint16_t   spec_ver_rev;
} heap_bios_spec_ver_elt_t;

/*
 * HEAP_ACM_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_ACM             2

typedef struct __packed {
    uint32_t   num_acms;
    uint64_t   acm_addrs[];
} heap_acm_elt_t;

/*
 * HEAP_CUSTOM_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_CUSTOM          4

typedef struct __packed {
    uuid_t     uuid;
    uint8_t    data[];
} heap_custom_elt_t;

/*
 * HEAP_EVENT_LOG_POINTER_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR   5

typedef struct __packed {
    uint64_t   event_log_phys_addr;
} heap_event_log_ptr_elt_t;

typedef struct __packed {
    uint32_t pcr_index;
    uint32_t type;
    sha1_hash_t digest;
    uint32_t data_size;
    uint8_t data[];
} tpm12_pcr_event_t;


//Event Log Header

/*
To allow parsers to identify the log format based on the content of the log, the first event
of the log is formatted as a TCG_PCR_EVENT structure independent of the format for
the rest of the log. A parser may read the first event of type TCG_PCR_EVENT and
because of its fixed size, easily find the event data. The fields of the event log header are
defined to be PCRIndex of 0, EventType of EV_NO_ACTION, Digest of 20 bytes of 0, and
Event content defined as TCG_EfiSpecIDEventStruct. This first event is the event log
header.
*/

typedef struct __packed {
    uint32_t pcr_index; //pcr_index event extended to
    uint32_t event_type;  //Type of event (see EFI specs)
    uint8_t digest[20];//Value extended into pcr_index
    uint32_t event_data_size; //Size of the event data 
    uint8_t event_data[]; //The event data Structure to be added to the Event Log
} tcg_pcr_event;

typedef struct {
    uint16_t       hash_alg;
    uint8_t        digest[];
} TPMT_HA_1;

typedef struct {
    uint32_t         count;
    TPMT_HA_1     digests[5];
} TPML_DIGEST_VALUES_1;

//TCG compliant TPM event log
typedef struct __packed {
    uint32_t pcr_index;
    uint32_t event_type;
    TPML_DIGEST_VALUES_1 digest; //List of digests extended to pcr_index banks
    uint32_t event_size;
    uint8_t event[];
} tcg_pcr_event2;


typedef struct __packed {
    uint16_t algorithm_id;
    uint16_t digest_size;
} tcg_efi_spec_id_event_algorithm_size;


typedef struct __packed {
    uint8_t signature[16];
    uint32_t platform_class;
    uint8_t spec_version_minor;
    uint8_t spec_version_major;
    uint8_t spec_errata;
    uint8_t uintn_size;
    uint32_t number_of_algorithms;
    tcg_efi_spec_id_event_algorithm_size  digestSizes[5];
    uint8_t vendor_info_size;
    uint8_t vendor_info[];    
} tcg_efi_specid_event_strcut;

#define EVTLOG_SIGNATURE "TXT Event Container\0"
#define EVTLOG_CNTNR_MAJOR_VER 1
#define EVTLOG_CNTNR_MINOR_VER 0
#define EVTLOG_EVT_MAJOR_VER 1
#define EVTLOG_EVT_MINOR_VER 0
typedef struct __packed {
    uint8_t signature[20];
    uint8_t reserved[12];
    uint8_t container_ver_major;
    uint8_t container_ver_minor;
    uint8_t pcr_event_ver_major;
    uint8_t pcr_event_ver_minor;
    uint32_t size;
    uint32_t pcr_events_offset;
    uint32_t next_event_offset; 
    tpm12_pcr_event_t pcr_events[];
} event_log_container_t;

/*
 * HEAP_EVENT_LOG_POINTER_ELEMENT2
 */
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2  7 
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2_1  8

#define DIGEST_ALG_ID_SHA_1       0x00000001
#define DIGEST_ALG_ID_SHA_256     0x00000002
#define DIGEST_ALG_ID_SHA_384     0x00000003
#define DIGEST_ALG_ID_SHA_512     0x00000004
#define DIGEST_ALG_ID_SM3         0x00000005
static inline unsigned int get_evtlog_digest_id(uint16_t hash_alg)
{
    if ( hash_alg == TB_HALG_SHA1 )
        return DIGEST_ALG_ID_SHA_1;
    else if ( hash_alg == TB_HALG_SHA256 )
        return DIGEST_ALG_ID_SHA_256;
    else if ( hash_alg == TB_HALG_SM3 )
        return DIGEST_ALG_ID_SM3;
    else if ( hash_alg == TB_HALG_SHA384 )
        return DIGEST_ALG_ID_SHA_384;
    else if ( hash_alg == TB_HALG_SHA512 )
        return DIGEST_ALG_ID_SHA_512;
    else
        return 0;
}

typedef struct __packed {
    uint8_t    signature[16];
    uint32_t   revision;
    uint32_t   digest_id;
    uint32_t   digest_size;
} tpm20_log_descr_t;

typedef struct __packed {
    uint16_t   alg;
    uint16_t   reserved;
    uint64_t   phys_addr;
    uint32_t   size;
    uint32_t   pcr_events_offset;
    uint32_t   next_event_offset;
} heap_event_log_descr_t;

typedef struct __packed {
    uint32_t   count;
    heap_event_log_descr_t event_log_descr[];
} heap_event_log_ptr_elt2_t;

typedef struct {
	uint64_t phys_addr;
	uint32_t allcoated_event_container_size;
	uint32_t first_record_offset;
	uint32_t next_record_offset;
} heap_event_log_ptr_elt2_1_t;

#define HEAP_EXTDATA_TYPE_TPR_REQ 13
typedef struct __packed {
    uint64_t tpr_range_base; //Physical address of the TPR base
    uint64_t tpr_range_size; //Size of the requested TPR
} tpr_range_t;

typedef struct __packed {
    uint32_t tpr_cnt; //How many TPRs in the request area. Max value of tpr_cnt is HW-specific.
    tpr_range_t tpr_req_arr[]; //array of tpr ranges (tpr_cnt * tpr_range_t)
} heap_tpr_req_element_t;

/*
 * data-passing structures contained in TXT heap:
 *   - BIOS
 *   - OS/loader to MLE
 *   - OS/loader to SINIT
 *   - SINIT to MLE
 */

/*
 * BIOS structure
 */

#define PLATFORM_TYPE_CLIENT 0x01
#define PLATFORM_TYPE_SERVER 0x02

typedef struct __packed {
    uint32_t sinit;
    struct {
        /* versions >= 5 */
        uint32_t ppi_supported : 1;
        /* versions >= 6 */
        uint32_t platform_type : 2;
        uint32_t reserved      : 29;
    } mle;
} bios_data_flags_t;

typedef struct __packed {
    uint32_t  version;              /* currently 2-6 */
    uint32_t  bios_sinit_size;
    uint64_t  lcp_pd_base;
    uint64_t  lcp_pd_size;
    uint32_t  num_logical_procs;
    /* versions >= 3 */
    union {
        uint64_t raw;
        bios_data_flags_t bits; /* For TPM2, it is divided into sinit_flag and mle_flag */
    } flags;
    /* versions >= 4 */
    heap_ext_data_element_t  ext_data_elts[];
} bios_data_t;

/*
 * OS/loader to MLE structure
 *   - private to tboot (so can be any format we need)
 */
#define MAX_LCP_PO_DATA_SIZE     64*1024  /* 64k */
#define MAX_EVENT_LOG_SIZE       5*4*1024   /* 4k*5 */

typedef struct __packed {
    uint32_t          version;           /* currently 3 */
    mtrr_state_t      saved_mtrr_state;  /* saved prior to changes for SINIT */
    void 			 *lctx_addr;         /* needs to be restored to ebx */
    uint32_t          saved_misc_enable_msr;  /* saved prior to SENTER */
                                         /* PO policy data */
    uint8_t           lcp_po_data[MAX_LCP_PO_DATA_SIZE];
                                         /* buffer for tpm event log */
    uint8_t           event_log_buffer[MAX_EVENT_LOG_SIZE];
} os_mle_data_t;

#define MIN_OS_SINIT_DATA_VER    4
#define MAX_OS_SINIT_DATA_VER    7
#define OS_SINIT_FLAGS_EXTPOL_MASK  0x00000001
#define OS_SINIT_DATA_WITH_TPR_SIZE 144 //92 bytes for struct, 44 for tpr_req_elt, 8 for end elt
/*
 * OS/loader to SINIT structure
 */
typedef struct __packed {
    uint32_t    version;           /* currently 4-7 */
    uint32_t    flags;  /* For TPM2: BIT0:= PCR Extend Policy Control */
    uint64_t    mle_ptab;
    uint64_t    mle_size;
    uint64_t    mle_hdr_base;
    uint64_t    vtd_pmr_lo_base;
    uint64_t    vtd_pmr_lo_size;
    uint64_t    vtd_pmr_hi_base;
    uint64_t    vtd_pmr_hi_size;
    uint64_t    lcp_po_base;
    uint64_t    lcp_po_size;
    txt_caps_t  capabilities;
    /* versions >= 5 */
    uint64_t    efi_rsdt_ptr;
    /* versions >= 6 */
    heap_ext_data_element_t  ext_data_elts[];
} os_sinit_data_t;

/*
 * SINIT to MLE structure
 */
#define MDR_MEMTYPE_GOOD                0x00
#define MDR_MEMTYPE_SMM_OVERLAY         0x01
#define MDR_MEMTYPE_SMM_NONOVERLAY      0x02
#define MDR_MEMTYPE_PCIE_CONFIG_SPACE   0x03
#define MDR_MEMTYPE_PROTECTED           0x04

typedef struct __packed {
    uint64_t  base;
    uint64_t  length;
    uint8_t   mem_type;
    uint8_t   reserved[7];
} sinit_mdr_t;

typedef struct __packed {
    uint32_t     version;             /* currently 6-9 */
    sha1_hash_t  bios_acm_id;         /* only for tpm1.2 */
    uint32_t     edx_senter_flags;    /* only for tpm1.2 */
    uint64_t     mseg_valid;          /* only for tpm1.2 */
    sha1_hash_t  sinit_hash;          /* only for tpm1.2 */
    sha1_hash_t  mle_hash;            /* only for tpm1.2 */
    sha1_hash_t  stm_hash;            /* only for tpm1.2 */
    sha1_hash_t  lcp_policy_hash;     /* only for tpm1.2 */
    uint32_t     lcp_policy_control;  /* only for tpm1.2 */
    uint32_t     rlp_wakeup_addr;
    uint32_t     reserved;
    uint32_t     num_mdrs;
    uint32_t     mdrs_off;
    uint32_t     num_vtd_dmars;
    uint32_t     vtd_dmars_off;
    /* versions >= 8 */
    uint32_t     proc_scrtm_status;   /* only for tpm1.2 */
    /* versions >= 9 */
    heap_ext_data_element_t  ext_data_elts[];
} sinit_mle_data_t;


/*
 * TXT heap data format and field accessor fns
 */

/*
 * offset                 length                      field
 * ------                 ------                      -----
 *  0                      8                          bios_data_size
 *  8                      bios_data_size - 8      bios_data
 *
 *  bios_data_size      8                          os_mle_data_size
 *  bios_data_size +    os_mle_data_size - 8       os_mle_data
 *   8
 *
 *  bios_data_size +    8                          os_sinit_data_size
 *   os_mle_data_size
 *  bios_data_size +    os_sinit_data_size - 8     os_sinit_data
 *   os_mle_data_size +
 *   8
 *
 *  bios_data_size +    8                          sinit_mle_data_size
 *   os_mle_data_size +
 *   os_sinit_data_size
 *  bios_data_size +    sinit_mle_data_size - 8    sinit_mle_data
 *   os_mle_data_size +
 *   os_sinit_data_size +
 *   8
 */

typedef void   txt_heap_t;

/* this is a common use with annoying casting, so make it an inline */
static inline txt_heap_t *get_txt_heap(void)
{
    return (txt_heap_t *)(unsigned long)read_pub_config_reg(TXTCR_HEAP_BASE);
}

static inline uint64_t get_bios_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)heap;
}

static inline bios_data_t *get_bios_data_start(const txt_heap_t *heap)
{
    return (bios_data_t *)((char*)heap + sizeof(uint64_t));
}

static inline uint64_t get_os_mle_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_data_size(heap));
}

static inline os_mle_data_t *get_os_mle_data_start(const txt_heap_t *heap)
{
    return (os_mle_data_t *)(heap + get_bios_data_size(heap) +
                              sizeof(uint64_t));
}

static inline uint64_t get_os_sinit_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_data_size(heap) +
                         get_os_mle_data_size(heap));
}

static inline os_sinit_data_t *get_os_sinit_data_start(const txt_heap_t *heap)
{
    return (os_sinit_data_t *)(heap + get_bios_data_size(heap) +
                               get_os_mle_data_size(heap) +
                               sizeof(uint64_t));
}

static inline uint64_t get_sinit_mle_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_data_size(heap) +
                         get_os_mle_data_size(heap) +
                         get_os_sinit_data_size(heap));
}

static inline sinit_mle_data_t *get_sinit_mle_data_start(const txt_heap_t *heap)
{
    return (sinit_mle_data_t *)(heap + get_bios_data_size(heap) +
                                get_os_mle_data_size(heap) +
                                get_os_sinit_data_size(heap) +
                                sizeof(uint64_t));
}

extern uint64_t calc_os_sinit_data_size(uint32_t version);
extern bool verify_txt_heap(const txt_heap_t *txt_heap, bool bios_data_only);
extern bool verify_bios_data(const txt_heap_t *txt_heap);
extern void print_os_sinit_data(const os_sinit_data_t *os_sinit_data);
extern void print_os_sinit_data_vtdpmr(const os_sinit_data_t *os_sinit_data);
extern heap_tpr_req_element_t *get_tpr_req_element(const os_sinit_data_t *os_sinit_data);

#endif      /* __TXT_HEAP_H__ */


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
