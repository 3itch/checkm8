/*
 * integrity.h: routines for memory integrity measurement &
 *          verification. Memory integrity is protected with tpm seal
 *
 * Copyright (c) 2007-2009, Intel Corporation
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

#ifndef _TBOOT_INTEGRITY_H_
#define _TBOOT_INTEGRITY_H_

#include <poly1305.h>

/*
 * state that must be saved across S3 and will be sealed for integrity
 * before extending PCRs and launching kernel
 */
#define MAX_VL_HASHES 32
#define MAX_ALG_NUM 5 

typedef struct {
    uint16_t  alg;
    tb_hash_t hash;
} hash_entry_t;

typedef struct {
    uint32_t  count;
    hash_entry_t entries[MAX_ALG_NUM];
} hash_list_t;

typedef struct {
    /* low and high memory regions to protect w/ VT-d PMRs or TPRs*/
    uint64_t dma_protection_lo_base;
    uint64_t dma_protection_lo_size;
    uint64_t dma_protection_hi_base;
    uint64_t dma_protection_hi_size;
    /* VL policy at time of sealing */
    tb_hash_t pol_hash;
    /* verified launch measurements to be re-extended in DRTM PCRs
     * a given PCR may have more than one hash and will get extended in the
     * order it appears in the list */
    uint8_t num_vl_entries;
    struct {
        uint8_t pcr;
        hash_list_t hl;
    } vl_entries[MAX_VL_HASHES];
} pre_k_s3_state_t;

/*
 * state that must be saved across S3 and will be sealed for integrity
 * just before entering S3 (after kernel shuts down)
 */
typedef struct {
    uint64_t kernel_s3_resume_vector;
    uint8_t  kernel_integ[POLY1305_DIGEST_SIZE];
} post_k_s3_state_t;


extern pre_k_s3_state_t g_pre_k_s3_state;
extern post_k_s3_state_t g_post_k_s3_state;

extern bool seal_pre_k_state(void);
extern bool seal_post_k_state(void);
extern bool verify_integrity(void);

#endif /* _TBOOT_INTEGRITY_H_ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
