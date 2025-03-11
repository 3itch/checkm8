/*
 * integrity.c: routines for memory integrity measurement &
 *          verification. Memory integrity is protected with tpm seal
 *
 * Copyright (c) 2007-2010, Intel Corporation
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

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <misc.h>
#include <compiler.h>
#include <string.h>
#include <hash.h>
#include <tboot.h>
#include <tb_policy.h>
#include <tb_error.h>
#include <poly1305.h>
#include <integrity.h>
#include <tpm.h>
#include <processor.h>

#include <page.h>
#include <paging.h>
extern char _end[];

/* put in .data section to that they aren't cleared on S3 resume */

/* state whose integrity needs to be maintained across S3 */
__data pre_k_s3_state_t g_pre_k_s3_state;
__data post_k_s3_state_t g_post_k_s3_state;

/* state sealed before extending PCRs and launching kernel */
static __data uint8_t  sealed_pre_k_state[2048];
static __data uint32_t sealed_pre_k_state_size;

/* state sealed just before entering S3 (after kernel shuts down) */
static __data uint8_t  sealed_post_k_state[2048];
static __data uint32_t sealed_post_k_state_size;

/* PCR 17+18 values post-launch and before extending (used to seal verified
   launch hashes and memory integrity UMAC) */
__data tpm_pcr_value_t post_launch_pcr17, post_launch_pcr18;

extern tboot_shared_t _tboot_shared;

extern bool hash_policy(tb_hash_t *hash, uint16_t hash_alg);
extern void apply_policy(tb_error_t error);

#define EVTTYPE_TB_MEASUREMENT (0x400 + 0x101)
extern bool evtlog_append(uint8_t pcr, hash_list_t *hl, uint32_t type);

typedef struct {
    uint8_t mac_key[POLY1305_KEY_SIZE];
    uint8_t shared_key[sizeof(_tboot_shared.s3_key)];
} sealed_secrets_t;


static bool extend_pcrs(void)
{
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();
    for ( int i = 0; i < g_pre_k_s3_state.num_vl_entries; i++ ) {
        if ( !tpm_fp->pcr_extend(tpm, 2, g_pre_k_s3_state.vl_entries[i].pcr,
                    &g_pre_k_s3_state.vl_entries[i].hl) )
            return false;
        if ( !evtlog_append(g_pre_k_s3_state.vl_entries[i].pcr,
                            &g_pre_k_s3_state.vl_entries[i].hl,
                            EVTTYPE_TB_MEASUREMENT) )
            return false;
    }

    return true;
}

static void print_pre_k_s3_state(void)
{
    struct tpm_if *tpm = get_tpm();
    
    printk(TBOOT_DETA"pre_k_s3_state:\n");
    printk(TBOOT_DETA"\t dma_protection_lo_base: 0x%Lx\n", g_pre_k_s3_state.dma_protection_lo_base);
    printk(TBOOT_DETA"\t dma_protection_lo_size: 0x%Lx\n", g_pre_k_s3_state.dma_protection_lo_size);
    printk(TBOOT_DETA"\t dma_protection_hi_base: 0x%Lx\n", g_pre_k_s3_state.dma_protection_hi_base);
    printk(TBOOT_DETA"\t dma_protection_hi_size: 0x%Lx\n", g_pre_k_s3_state.dma_protection_hi_size);
    printk(TBOOT_DETA"\t pol_hash: ");
    print_hash(&g_pre_k_s3_state.pol_hash, tpm->cur_alg);
    printk(TBOOT_DETA"\t VL measurements:\n");
    for ( unsigned int i = 0; i < g_pre_k_s3_state.num_vl_entries; i++ ) {
        printk(TBOOT_DETA"\t   PCR %d (alg count %d):\n",
                g_pre_k_s3_state.vl_entries[i].pcr,
                g_pre_k_s3_state.vl_entries[i].hl.count);
        for ( unsigned int j = 0; j < g_pre_k_s3_state.vl_entries[i].hl.count; j++ ) {
            printk(TBOOT_DETA"\t\t   alg %04X: ",
                    g_pre_k_s3_state.vl_entries[i].hl.entries[j].alg);
            print_hash(&g_pre_k_s3_state.vl_entries[i].hl.entries[j].hash,
                    g_pre_k_s3_state.vl_entries[i].hl.entries[j].alg);
        }
    }
}

static void print_post_k_s3_state(void)
{
    printk(TBOOT_DETA"post_k_s3_state:\n");
    printk(TBOOT_DETA"\t kernel_s3_resume_vector: 0x%Lx\n",
           g_post_k_s3_state.kernel_s3_resume_vector);
    printk(TBOOT_DETA"\t kernel_integ: ");
    print_hex(NULL, &g_post_k_s3_state.kernel_integ,
              sizeof(g_post_k_s3_state.kernel_integ));
}

static bool seal_data(const void *data, size_t data_size, const void *secrets, size_t secrets_size, uint8_t *sealed_data, uint32_t *sealed_data_size)
{
    /* TPM_Seal can only seal small data (like key or hash), so hash data */
    struct __packed {
        sha256_hash_t data_hash;
        uint8_t   secrets[secrets_size];
    } blob;
    uint32_t err;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    tb_memset(&blob, 0, sizeof(blob));
    if ( !hash_buffer(data, data_size, (tb_hash_t *)&blob.data_hash, TB_HALG_SHA256) ) {
        printk(TBOOT_ERR"failed to hash data\n");
        return false;
    }

    if ( secrets != NULL && secrets_size > 0 )  tb_memcpy(blob.secrets, secrets, secrets_size);

    err = tpm_fp->seal(tpm, 2, sizeof(blob), (const uint8_t *)&blob, sealed_data_size, sealed_data);
    if ( !err )  printk(TBOOT_WARN"failed to seal data\n");

    /* since blob might contain secret, clear it */
    tb_memset(&blob, 0, sizeof(blob));

    return err;
}

static bool verify_sealed_data(const uint8_t *sealed_data,  uint32_t sealed_data_size, const void *curr_data, size_t curr_data_size, void *secrets, size_t secrets_size)
{
    /* sealed data is hash of state data and optional secret */
    struct __packed {
        sha256_hash_t data_hash;
        uint8_t   secrets[secrets_size];
    } blob;
    bool err = true;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    uint32_t data_size = sizeof(blob);
    if ( !tpm_fp->unseal(tpm, tpm->cur_loc, sealed_data_size, sealed_data, &data_size, (uint8_t *)&blob) ) {
        printk(TBOOT_ERR"failed to unseal blob\n");
        return false;
    }
    if ( data_size != sizeof(blob) ) {
        printk(TBOOT_WARN"unsealed state data size mismatch\n");
        goto done;
    }

    /* verify that (hash of) current data matches sealed hash */
    tb_hash_t curr_data_hash;
    tb_memset(&curr_data_hash, 0, sizeof(curr_data_hash));
    if ( !hash_buffer(curr_data, curr_data_size, &curr_data_hash, TB_HALG_SHA256) ) {
        printk(TBOOT_WARN"failed to hash state data\n");
        goto done;
    }
    if ( !are_hashes_equal((tb_hash_t *)&blob.data_hash, &curr_data_hash, TB_HALG_SHA256) ) {
        printk(TBOOT_WARN"sealed hash does not match current hash\n");
        goto done;
    }

    if ( secrets != NULL && secrets_size > 0 )
        tb_memcpy(secrets, &blob.secrets, secrets_size);

    err = false;

 done:
    /* clear secret from local memory */
    tb_memset(&blob, 0, sizeof(blob));

    return !err;
}

/*
 * pre- PCR extend/kernel launch S3 data are sealed to PCRs 17+18 with
 * post-launch values (i.e. before extending)
 */
bool seal_pre_k_state(void)
{
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();
    
    /* save hash of current policy into g_pre_k_s3_state */
    tb_memset(&g_pre_k_s3_state.pol_hash, 0, sizeof(g_pre_k_s3_state.pol_hash));
    if ( !hash_policy(&g_pre_k_s3_state.pol_hash, tpm->cur_alg) ) {
        printk(TBOOT_ERR"failed to hash policy\n");
        goto error;
    }

    print_pre_k_s3_state();

    /* read PCR 17/18, only for tpm1.2 */
    if ( tpm->major == TPM12_VER_MAJOR ) {
        if ( !tpm_fp->pcr_read(tpm, 2, 17, &post_launch_pcr17) ||
             !tpm_fp->pcr_read(tpm, 2, 18, &post_launch_pcr18) )
            goto error;
    }

    sealed_pre_k_state_size = sizeof(sealed_pre_k_state);
    if ( !seal_data(&g_pre_k_s3_state, sizeof(g_pre_k_s3_state),
                    NULL, 0,
                    sealed_pre_k_state, &sealed_pre_k_state_size) )
        goto error;

    /* we can't leave the system in a state without valid measurements of
       about-to-execute code in the PCRs, so this is a fatal error */
    if ( !extend_pcrs() ) {
        apply_policy(TB_ERR_FATAL);
        return false;
    }

    return true;

    /* even if sealing fails, we must extend PCRs to represent valid
       measurements of about-to-execute code */
 error:
    if ( !extend_pcrs() )
        apply_policy(TB_ERR_FATAL);
    return false;
}

static bool measure_memory_integrity(uint8_t* mac, uint8_t* key)
{
    POLY1305 ctx;
    unsigned long virt = MAC_VIRT_START;

/* we require memory is 4K page aligned in tboot */
#define MAC_ALIGN PAGE_SIZE
    COMPILE_TIME_ASSERT(MAC_VIRT_SIZE >= MAC_PAGE_SIZE);
    COMPILE_TIME_ASSERT((unsigned long)(-1) - MAC_VIRT_START > MAC_VIRT_SIZE );
    COMPILE_TIME_ASSERT(PAGE_SIZE % POLY1305_BLOCK_SIZE == 0);

    /* enable paging */
    if ( !enable_paging() )
        return false;

    sse_enable();

    Poly1305_Init(&ctx, key);
    for ( unsigned int i = 0; i < _tboot_shared.num_mac_regions; i++ ) {
        uint64_t start = _tboot_shared.mac_regions[i].start;

        /* overflow? */
        if ( plus_overflow_u64(start, _tboot_shared.mac_regions[i].size) ) {
            printk(TBOOT_ERR"start plus size overflows during MACing\n");
            return false;
        }

        /* if not overflow, we get end */
        uint64_t end = start + _tboot_shared.mac_regions[i].size;

        start = start & ~(MAC_ALIGN - 1);
        end = (end - 1) | (MAC_ALIGN - 1);

        /* overflow? */
        if ( plus_overflow_u64(end, 1) ) {
            printk(TBOOT_ERR"end up to the alignment overflows during MACing\n");
            return false;
        }

        /* if not overflow, we get end aligned */
        end++;

        printk(TBOOT_DETA"MACing region %u:  0x%Lx - 0x%Lx\n", i, start, end);

        /*
         * spfn: start pfn in 2-Mbyte page
         * epfn: end pfn in 2-Mbyte page
         * align_base: start physical address, which is 2-Mbyte page aligned
         */
        /* check overflow? */
        if ( plus_overflow_u64(end, MAC_PAGE_SIZE) ) {
            printk(TBOOT_ERR"end plus MAC_PAGE_SIZE overflows during MACing\n");
            return false;
        }

        unsigned long spfn;
        unsigned long epfn = (unsigned long)((end + MAC_PAGE_SIZE - 1)
                                            >> TB_L1_PAGETABLE_SHIFT);
        unsigned long nr_pfns, nr_virt_pfns;

        uint64_t align_base;
        unsigned long valign_base, vstart, vend;

        do {
            spfn = (unsigned long)(start >> TB_L1_PAGETABLE_SHIFT);
            align_base = (uint64_t)spfn << TB_L1_PAGETABLE_SHIFT;

            valign_base = virt;
            vstart = valign_base + (unsigned long)(start - align_base);

            nr_pfns = epfn - spfn;
            nr_virt_pfns = (MAC_VIRT_END - virt) >> TB_L1_PAGETABLE_SHIFT;

            if ( nr_virt_pfns >= nr_pfns ) {
                /* region can fit into the rest virtual space */
                map_pages_to_tboot(valign_base, spfn, nr_pfns);

                vend = valign_base + (unsigned long)(end - align_base);
                virt += nr_pfns << TB_L1_PAGETABLE_SHIFT;
                start = end;
            }
            else {
                /* region cannot fit into the rest virtual space, will trunc */
                map_pages_to_tboot(valign_base, spfn, nr_virt_pfns);

                vend = MAC_VIRT_END;
                virt = MAC_VIRT_START;
                start = align_base + (nr_virt_pfns << TB_L1_PAGETABLE_SHIFT);
            }

            /* MAC the 2-Mbyte pages */
            while ( (vend > vstart) && ((vend - vstart) >= MAC_PAGE_SIZE) ) {
                Poly1305_Update(&ctx, (uint8_t *)(uintptr_t)vstart, MAC_PAGE_SIZE);
                vstart += MAC_PAGE_SIZE;
            }
            /* MAC the rest */
            if ( vend > vstart )
                Poly1305_Update(&ctx, (uint8_t *)(uintptr_t)vstart, vend - vstart);

            /* destroy the mapping */
            if ( virt == MAC_VIRT_START )
                destroy_tboot_mapping(MAC_VIRT_START, MAC_VIRT_END);
        } while ( start < end );
    }
    Poly1305_Final(&ctx, mac);

    /* return to protected mode without paging */
    if (!disable_paging())
        return false;

    return true;
}

/*
 * verify memory integrity and sealed VL hashes, then re-extend hashes
 *
 * this must be called post-launch but before extending any modules or other
 * measurements into PCRs
 */
bool verify_integrity(void)
{
    tpm_pcr_value_t pcr17, pcr18;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    /* read PCR 17/18, only for tpm1.2 */
    if ( tpm->major == TPM12_VER_MAJOR ) {
        if ( !tpm_fp->pcr_read(tpm, 2, 17, &pcr17) ||
             !tpm_fp->pcr_read(tpm, 2, 18, &pcr18) )
            goto error;
        printk(TBOOT_DETA"PCRs before unseal:\n");
        printk(TBOOT_DETA"  PCR 17: ");
        print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
        printk(TBOOT_DETA"  PCR 18: ");
        print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);
    }

    /* verify integrity of pre-kernel state data */
    printk(TBOOT_INFO"verifying pre_k_s3_state\n");
    if ( !verify_sealed_data(sealed_pre_k_state, sealed_pre_k_state_size,
                             &g_pre_k_s3_state, sizeof(g_pre_k_s3_state),
                             NULL, 0) )
        goto error;

    if ( !tpm_fp->verify_creation(tpm, sealed_post_k_state_size,  sealed_post_k_state) ) {
        printk(TBOOT_ERR"extended PCR values don't match creation values in sealed blob.\n");
        goto error;
    }

    /* verify integrity of post-kernel state data */
    printk(TBOOT_INFO"verifying post_k_s3_state\n");
    sealed_secrets_t secrets;
    if ( !verify_sealed_data(sealed_post_k_state, sealed_post_k_state_size,
                             &g_post_k_s3_state, sizeof(g_post_k_s3_state),
                             &secrets, sizeof(secrets)) )
        goto error;

    /* Verify memory integrity against sealed value */
    uint8_t mac[POLY1305_DIGEST_SIZE];
    if ( !measure_memory_integrity(mac, secrets.mac_key) )
        goto error;
    if ( tb_memcmp(&mac, &g_post_k_s3_state.kernel_integ, sizeof(mac)) ) {
        printk(TBOOT_INFO"memory integrity lost on S3 resume\n");
        printk(TBOOT_DETA"MAC of current image is: ");
        print_hex(NULL, &mac, sizeof(mac));
        printk(TBOOT_DETA"MAC of pre-S3 image is: ");
        print_hex(NULL, &g_post_k_s3_state.kernel_integ,
                  sizeof(g_post_k_s3_state.kernel_integ));
        goto error;
    }
    printk(TBOOT_INFO"memory integrity OK\n");

    /* re-extend PCRs with VL measurements
       we can't leave the system in a state without valid measurements of
       about-to-execute code in the PCRs, so this is a fatal error */
    if ( !extend_pcrs() ) {
        apply_policy(TB_ERR_FATAL);
        return false;
    }

    /* copy sealed shared key back to _tboot_shared.s3_key */
    tb_memcpy(_tboot_shared.s3_key, secrets.shared_key,
           sizeof(_tboot_shared.s3_key));

    /* wipe secrets from memory */
    tb_memset(&secrets, 0, sizeof(secrets));

    return true;

 error:
    /* since we can't leave the system without any measurments representing the
       code-about-to-execute, and yet there is no integrity of that code,
       just cap PCR 18 */
    if ( !tpm_fp->cap_pcrs(tpm, tpm->cur_loc, 18) )
        apply_policy(TB_ERR_FATAL);
    return false;
}

/*
 * post- kernel launch S3 state is sealed to PCRs 17+18 with post-launch
 * values (i.e. before extending with VL hashes)
 */
bool seal_post_k_state(void)
{
    sealed_secrets_t secrets;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    /* since tboot relies on the module it launches for resource protection,
       that module should have at least one region for itself, otherwise
       it will not be protected against S3 resume attacks */
    if ( _tboot_shared.num_mac_regions == 0 ) {
        printk(TBOOT_ERR"no memory regions to MAC\n");
        return false;
    }

    /* calculate the memory integrity hash */
    uint32_t key_size = sizeof(secrets.mac_key);
    /* key must be random and secret even though auth not necessary */
    if ( !tpm_fp->get_random(tpm, tpm->cur_loc, secrets.mac_key, &key_size) ||key_size != sizeof(secrets.mac_key) ) return false;
    if ( !measure_memory_integrity(g_post_k_s3_state.kernel_integ, secrets.mac_key) ) return false;

    /* copy s3_key into secrets to be sealed */
    tb_memcpy(secrets.shared_key, _tboot_shared.s3_key, sizeof(secrets.shared_key));

    print_post_k_s3_state();

    sealed_post_k_state_size = sizeof(sealed_post_k_state);
    if ( !seal_data(&g_post_k_s3_state, sizeof(g_post_k_s3_state), &secrets, sizeof(secrets), sealed_post_k_state, &sealed_post_k_state_size) ) return false;

    /* wipe secrets from memory */
    tb_memset(&secrets, 0, sizeof(secrets));

    return true;
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
