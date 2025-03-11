/*
 * txt.c: Intel(r) TXT support functions, including initiating measured
 *        launch, post-launch, AP wakeup, etc.
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

#include <config.h>
#include <stdbool.h>
#include <types.h>
#include <tb_error.h>
#include <msr.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <processor.h>
#include <printk.h>
#include <atomic.h>
#include <mutex.h>
#include <tpm.h>
#include <uuid.h>
#include <loader.h>
#include <e820.h>
#include <tboot.h>
#include <mle.h>
#include <hash.h>
#include <cmdline.h>
#include <acpi.h>
#include <vtd.h>
#include <efi_memmap.h>
#include <txt/txt.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/heap.h>
#include <txt/acmod.h>
#include <txt/smx.h>
#include <txt/verify.h>
#include <txt/vmcs.h>
#include <io.h>

/* counter timeout for waiting for all APs to enter wait-for-sipi */
#define AP_WFS_TIMEOUT     0x10000000

__data struct acpi_rsdp g_rsdp;
extern char _start[];             /* start of module */
extern char _end[];               /* end of module */
extern char _mle_start[];         /* start of text section */
extern char _mle_end[];           /* end of text section */
extern char _post_launch_entry[]; /* entry point post SENTER, in boot.S */
extern char _txt_wakeup[];        /* RLP join address for GETSEC[WAKEUP] */

extern long s3_flag;

extern struct mutex ap_lock;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;
extern void apply_policy(tb_error_t error);
extern void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec);
extern void print_event(const tpm12_pcr_event_t *evt);
extern void print_event_2(void *evt, uint16_t alg);
extern uint32_t print_event_2_1(void *evt);

extern void __enable_nmi(void);

/*
 * this is the structure whose addr we'll put in TXT heap
 * it needs to be within the MLE pages, so force it to the .text section
 */
static __text const mle_hdr_t g_mle_hdr = {
    uuid              :  MLE_HDR_UUID,
    length            :  sizeof(mle_hdr_t),
    version           :  MLE_HDR_VER,
    entry_point       :  (uint32_t)&_post_launch_entry - TBOOT_START,
    first_valid_page  :  0,
    mle_start_off     :  (uint32_t)&_mle_start - TBOOT_BASE_ADDR,
    mle_end_off       :  (uint32_t)&_mle_end - TBOOT_BASE_ADDR,
    capabilities      :  { MLE_HDR_CAPS },
    cmdline_start_off :  (uint32_t)g_cmdline - TBOOT_BASE_ADDR,
    cmdline_end_off   :  (uint32_t)g_cmdline + CMDLINE_SIZE - 1 -
                                                       TBOOT_BASE_ADDR,
};

/*
 * counts of APs going into wait-for-sipi
 */
/* count of APs in WAIT-FOR-SIPI */
atomic_t ap_wfs_count;

static void print_file_info(void)
{
    printk(TBOOT_DETA"file addresses:\n");
    printk(TBOOT_DETA"\t &_start=%p\n", &_start);
    printk(TBOOT_DETA"\t &_end=%p\n", &_end);
    printk(TBOOT_DETA"\t &_mle_start=%p\n", &_mle_start);
    printk(TBOOT_DETA"\t &_mle_end=%p\n", &_mle_end);
    printk(TBOOT_DETA"\t &_post_launch_entry=%p\n", &_post_launch_entry);
    printk(TBOOT_DETA"\t &_txt_wakeup=%p\n", &_txt_wakeup);
    printk(TBOOT_DETA"\t &g_mle_hdr=%p\n", &g_mle_hdr);
}

static void print_mle_hdr(const mle_hdr_t *mle_hdr)
{
    printk(TBOOT_DETA"MLE header:\n");
    printk(TBOOT_DETA"\t uuid="); print_uuid(&mle_hdr->uuid); 
    printk(TBOOT_DETA"\n");
    printk(TBOOT_DETA"\t length=%x\n", mle_hdr->length);
    printk(TBOOT_DETA"\t version=%08x\n", mle_hdr->version);
    printk(TBOOT_DETA"\t entry_point=%08x\n", mle_hdr->entry_point);
    printk(TBOOT_DETA"\t first_valid_page=%08x\n", mle_hdr->first_valid_page);
    printk(TBOOT_DETA"\t mle_start_off=%x\n", mle_hdr->mle_start_off);
    printk(TBOOT_DETA"\t mle_end_off=%x\n", mle_hdr->mle_end_off);
    print_txt_caps("\t ", mle_hdr->capabilities);
}

/*
 * build_mle_pagetable()
 */

/* page dir/table entry is phys addr + P + R/W + PWT */
#define MAKE_PDTE(addr)  (((uint64_t)(unsigned long)(addr) & PAGE_MASK) | 0x01)

/* we assume/know that our image is <2MB and thus fits w/in a single */
/* PT (512*4KB = 2MB) and thus fixed to 1 pg dir ptr and 1 pgdir and */
/* 1 ptable = 3 pages and just 1 loop loop for ptable MLE page table */
/* can only contain 4k pages */

static __mlept uint8_t g_mle_pt[3 * PAGE_SIZE];  
/* pgdir ptr + pgdir + ptab = 3 */

static void *build_mle_pagetable(uint32_t mle_start, uint32_t mle_size)
{
    void *ptab_base;
    uint32_t ptab_size, mle_off;
    void *pg_dir_ptr_tab, *pg_dir, *pg_tab;
    uint64_t *pte;

    printk(TBOOT_DETA"MLE start=0x%x, end=0x%x, size=0x%x\n", 
           mle_start, mle_start+mle_size, mle_size);
    if ( mle_size > 512*PAGE_SIZE ) {
        printk(TBOOT_ERR"MLE size too big for single page table\n");
        return NULL;
    }


    /* should start on page boundary */
    if ( mle_start & ~PAGE_MASK ) {
        printk(TBOOT_ERR"MLE start is not page-aligned\n");
        return NULL;
    }

    /* place ptab_base below MLE */
    ptab_size = sizeof(g_mle_pt);
    ptab_base = &g_mle_pt;
    tb_memset(ptab_base, 0, ptab_size);
    printk(TBOOT_DETA"ptab_size=%x, ptab_base=%p\n", ptab_size, ptab_base);

    pg_dir_ptr_tab = ptab_base;
    pg_dir         = pg_dir_ptr_tab + PAGE_SIZE;
    pg_tab         = pg_dir + PAGE_SIZE;

    /* only use first entry in page dir ptr table */
    *(uint64_t *)pg_dir_ptr_tab = MAKE_PDTE(pg_dir);

    /* only use first entry in page dir */
    *(uint64_t *)pg_dir = MAKE_PDTE(pg_tab);

    pte = pg_tab;
    mle_off = 0;
    do {
        *pte = MAKE_PDTE(mle_start + mle_off);

        pte++;
        mle_off += PAGE_SIZE;
    } while ( mle_off < mle_size );

    return ptab_base;
}


static __data event_log_container_t *g_elog = NULL;
static __data heap_event_log_ptr_elt2_t *g_elog_2 = NULL;
static __data heap_event_log_ptr_elt2_1_t *g_elog_2_1 = NULL;

/* should be called after os_mle_data initialized */
static void *init_event_log(void)
{
    os_mle_data_t *os_mle_data = get_os_mle_data_start(get_txt_heap());
    g_elog = (event_log_container_t *)&os_mle_data->event_log_buffer;

    tb_memcpy((void *)g_elog->signature, EVTLOG_SIGNATURE,
           sizeof(g_elog->signature));
    g_elog->container_ver_major = EVTLOG_CNTNR_MAJOR_VER;
    g_elog->container_ver_minor = EVTLOG_CNTNR_MINOR_VER;
    g_elog->pcr_event_ver_major = EVTLOG_EVT_MAJOR_VER;
    g_elog->pcr_event_ver_minor = EVTLOG_EVT_MINOR_VER;
    g_elog->size = sizeof(os_mle_data->event_log_buffer);
    g_elog->pcr_events_offset = sizeof(*g_elog);
    g_elog->next_event_offset = sizeof(*g_elog);

    return (void *)g_elog;
}

/* initialize TCG compliant TPM 2.0 event log descriptor */
static void init_evtlog_desc_1(heap_event_log_ptr_elt2_1_t *evt_log)
{
    os_mle_data_t *os_mle_data = get_os_mle_data_start(get_txt_heap());
   
    evt_log->phys_addr = (uint64_t)(unsigned long)(os_mle_data->event_log_buffer);
    evt_log->allcoated_event_container_size = 2*PAGE_SIZE;
    evt_log->first_record_offset = 0;
    evt_log->next_record_offset = 0;
    printk(TBOOT_DETA"TCG compliant TPM 2.0 event log descriptor:\n");
    printk(TBOOT_DETA"\t phys_addr = 0x%LX\n",  evt_log->phys_addr);
    printk(TBOOT_DETA"\t allcoated_event_container_size = 0x%x \n", evt_log->allcoated_event_container_size);
    printk(TBOOT_DETA"\t first_record_offset = 0x%x \n", evt_log->first_record_offset);
    printk(TBOOT_DETA"\t next_record_offset = 0x%x \n", evt_log->next_record_offset);
}

static void init_evtlog_desc(heap_event_log_ptr_elt2_t *evt_log)
{
    unsigned int i;
    os_mle_data_t *os_mle_data = get_os_mle_data_start(get_txt_heap());
    struct tpm_if *tpm = get_tpm();
    switch (tpm->extpol) {
    case TB_EXTPOL_EMBEDDED:
        for (i=0; i<evt_log->count; i++) {
            evt_log->event_log_descr[i].alg = tpm->algs[i];
            evt_log->event_log_descr[i].phys_addr =
                    (uint64_t)(unsigned long)(os_mle_data->event_log_buffer + i*4096);
            evt_log->event_log_descr[i].size = 4096;
            evt_log->event_log_descr[i].pcr_events_offset = 0;
            evt_log->event_log_descr[i].next_event_offset = 0;
        }
        break;
    case TB_EXTPOL_FIXED:
        evt_log->event_log_descr[0].alg = tpm->cur_alg;
        evt_log->event_log_descr[0].phys_addr =
                    (uint64_t)(unsigned long)os_mle_data->event_log_buffer;
        evt_log->event_log_descr[0].size = 4096;
        evt_log->event_log_descr[0].pcr_events_offset = 0;
        evt_log->event_log_descr[0].next_event_offset = 0;
        break;
    default:
        return;
    }
}

int get_evtlog_type(void)
{
    struct tpm_if *tpm = get_tpm();

    if (tpm->major == TPM12_VER_MAJOR) {
        return EVTLOG_TPM12;
    } else if (tpm->major == TPM20_VER_MAJOR) {
        /*
         * Force use of legacy TPM2 log format to deal with a bug in some SINIT
         * ACMs that where they don't log the MLE hash to the event log.
         */
        if (get_tboot_force_tpm2_legacy_log()) {
            return EVTLOG_TPM2_LEGACY;
        }
        if (g_sinit) {
            txt_caps_t sinit_caps = get_sinit_capabilities(g_sinit);
            return sinit_caps.tcg_event_log_format ? EVTLOG_TPM2_TCG : EVTLOG_TPM2_LEGACY;
        } else {
            printk(TBOOT_ERR"SINIT not found\n");
        }
    } else {
        printk(TBOOT_ERR"Unknown TPM major version: %d\n", tpm->major);
    }
    printk(TBOOT_ERR"Unable to determine log type\n");
    return EVTLOG_UNKNOWN;
}

static void init_os_sinit_ext_data(heap_ext_data_element_t* elts)
{
    heap_ext_data_element_t* elt = elts;
    heap_event_log_ptr_elt_t* evt_log;
    heap_tpr_req_element_t* tpr_elt = NULL;
    struct tpm_if *tpm = get_tpm();
 
    int log_type = get_evtlog_type();
    if ( log_type == EVTLOG_TPM12 ) {
        evt_log = (heap_event_log_ptr_elt_t *)elt->data;
        evt_log->event_log_phys_addr = (uint64_t)(unsigned long)init_event_log();
        elt->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR;
        elt->size = sizeof(*elt) + sizeof(*evt_log);
    } else if ( log_type == EVTLOG_TPM2_TCG ) {
        g_elog_2_1 = (heap_event_log_ptr_elt2_1_t *)elt->data;
        init_evtlog_desc_1(g_elog_2_1);
        elt->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2_1;
        elt->size = sizeof(*elt) + sizeof(heap_event_log_ptr_elt2_1_t);
        printk(TBOOT_DETA"heap_ext_data_element TYPE = %d \n", elt->type);
        printk(TBOOT_DETA"heap_ext_data_element SIZE = %d \n", elt->size);
    }  else if ( log_type == EVTLOG_TPM2_LEGACY ) {
        g_elog_2 = (heap_event_log_ptr_elt2_t *)elt->data;
        if ( tpm->extpol == TB_EXTPOL_EMBEDDED )
            g_elog_2->count = tpm->alg_count;
        else
            g_elog_2->count = 1;
        init_evtlog_desc(g_elog_2);
        elt->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2;
        elt->size = sizeof(*elt) + sizeof(u32) +
            g_elog_2->count * sizeof(heap_event_log_descr_t);
        printk(TBOOT_DETA"INTEL TXT LOG elt SIZE = %d \n", elt->size);
    }
    if (g_tpr_support) {
        //Go to next elt
        elt = (void *)elt + elt->size;
        //Allocate space for 2 TPR ranges, one in LO RAM and the other in HI RAM
        elt->type = HEAP_EXTDATA_TYPE_TPR_REQ;
        elt->size = sizeof(*elt) + offsetof(heap_tpr_req_element_t, tpr_req_arr) + (2 * sizeof(tpr_range_t));
        printk(TBOOT_DETA"heap_ext_data_element TYPE = %d \n", elt->type);
        printk(TBOOT_DETA"heap_ext_data_element SIZE = %d \n", elt->size);
        tpr_elt = (heap_tpr_req_element_t *) &elt->data;
        tpr_elt->tpr_cnt = 2;
    }
    //Update END element
    elt = (void *)elt + elt->size;
    elt->type = HEAP_EXTDATA_TYPE_END;
    elt->size = sizeof(*elt);
}

bool evtlog_append_tpm12(uint8_t pcr, tb_hash_t *hash, uint32_t type)
{
    if ( g_elog == NULL )
        return true;

    tpm12_pcr_event_t *next = (tpm12_pcr_event_t *)
                              ((void*)g_elog + g_elog->next_event_offset);
    
    if ( g_elog->next_event_offset + sizeof(*next) > g_elog->size )
        return false;

    next->pcr_index = pcr;
    next->type = type;
    tb_memcpy(next->digest, hash, sizeof(next->digest));
    next->data_size = 0;

    g_elog->next_event_offset += sizeof(*next) + next->data_size;

    print_event(next);
    return true;
}

void dump_event_2(void)
{
    heap_event_log_descr_t *log_descr;

    for ( unsigned int i=0; i<g_elog_2->count; i++ ) {
        log_descr = &g_elog_2->event_log_descr[i];
        printk(TBOOT_DETA"\t\t\t Log Descrption:\n");
        printk(TBOOT_DETA"\t\t\t             Alg: %u\n", log_descr->alg);
        printk(TBOOT_DETA"\t\t\t            Size: %u\n", log_descr->size);
        printk(TBOOT_DETA"\t\t\t    EventsOffset: [%u,%u)\n",
                log_descr->pcr_events_offset,
                log_descr->next_event_offset);

        uint32_t hash_size, data_size; 
        hash_size = get_hash_size(log_descr->alg); 
        if ( hash_size == 0 )
            return;

        void *curr, *next;
        *((u64 *)(&curr)) = log_descr->phys_addr +
                log_descr->pcr_events_offset;
        *((u64 *)(&next)) = log_descr->phys_addr +
                log_descr->next_event_offset;

        if ( log_descr->alg != TB_HALG_SHA1 ) {
            print_event_2(curr, TB_HALG_SHA1);
            curr += sizeof(tpm12_pcr_event_t) + sizeof(tpm20_log_descr_t);
        }

        while ( curr < next ) {
            print_event_2(curr, log_descr->alg);
            data_size = *(uint32_t *)(curr + 2*sizeof(uint32_t) + hash_size);
            curr += 3*sizeof(uint32_t) + hash_size + data_size;
        }
    }
}

bool evtlog_append_tpm2_legacy(uint8_t pcr, uint16_t alg, tb_hash_t *hash, uint32_t type)
{
    heap_event_log_descr_t *cur_desc = NULL;
    uint32_t hash_size; 
    void *cur, *next;

    for ( unsigned int i=0; i<g_elog_2->count; i++ ) {
        if ( g_elog_2->event_log_descr[i].alg == alg ) {
            cur_desc = &g_elog_2->event_log_descr[i];
            break;
        }
    }
    if ( !cur_desc )
        return false;

    hash_size = get_hash_size(alg); 
    if ( hash_size == 0 )
        return false;

    if ( cur_desc->next_event_offset + 32 > cur_desc->size )
        return false;

    cur = next = (void *)(unsigned long)cur_desc->phys_addr +
                     cur_desc->next_event_offset;
    *((u32 *)next) = pcr;
    next += sizeof(u32);
    *((u32 *)next) = type;
    next += sizeof(u32);
    tb_memcpy((uint8_t *)next, hash, hash_size);
    next += hash_size;
    *((u32 *)next) = 0;
    cur_desc->next_event_offset += 3*sizeof(uint32_t) + hash_size; 

    print_event_2(cur, alg);
    return true;
}

bool evtlog_append_tpm2_tcg(uint8_t pcr, uint32_t type, hash_list_t *hl)
{
    uint32_t i, event_size;
    unsigned int hash_size;
    tcg_pcr_event2 *event;
    uint8_t *hash_entry;
    tcg_pcr_event2 dummy;

    /*
     * Dont't use sizeof(tcg_pcr_event2) since that has TPML_DIGESTV_VALUES_1.digests
     * set to 5. Compute the static size as pcr_index + event_type +
     * digest.count + event_size. Then add the space taken up by the hashes.
     */
    event_size = sizeof(dummy.pcr_index) + sizeof(dummy.event_type) +
        sizeof(dummy.digest.count) + sizeof(dummy.event_size);

    for (i = 0; i < hl->count; i++) {
        hash_size = get_hash_size(hl->entries[i].alg);
        if (hash_size == 0) {
            return false;
        }
        event_size += sizeof(uint16_t); // hash_alg field
        event_size += hash_size;
    }

    // Check if event will fit in buffer.
    if (event_size + g_elog_2_1->next_record_offset >
        g_elog_2_1->allcoated_event_container_size) {
        return false;
    }

    event = (tcg_pcr_event2*)(void *)(unsigned long)(g_elog_2_1->phys_addr +
        g_elog_2_1->next_record_offset);
    event->pcr_index = pcr;
    event->event_type = type;
    event->event_size = 0;  // No event data passed by tboot.
    event->digest.count = hl->count;

    hash_entry = (uint8_t *)&event->digest.digests[0];
    for (i = 0; i < hl->count; i++) {
        // Populate individual TPMT_HA_1 structs.
        *((uint16_t *)hash_entry) = hl->entries[i].alg; // TPMT_HA_1.hash_alg
        hash_entry += sizeof(uint16_t);
        hash_size = get_hash_size(hl->entries[i].alg);  // already checked above
        tb_memcpy(hash_entry, &(hl->entries[i].hash), hash_size);
        hash_entry += hash_size;
    }

    g_elog_2_1->next_record_offset += event_size;
    print_event_2_1(event);
    return true;
}

bool evtlog_append(uint8_t pcr, hash_list_t *hl, uint32_t type)
{
    int log_type = get_evtlog_type();
    switch (log_type) {
    case EVTLOG_TPM12:
        if ( !evtlog_append_tpm12(pcr, &hl->entries[0].hash, type) )
            return false;
        break;
    case EVTLOG_TPM2_LEGACY:
        for (unsigned int i=0; i<hl->count; i++) {
            if ( !evtlog_append_tpm2_legacy(pcr, hl->entries[i].alg,
                &hl->entries[i].hash, type))
                return false;
	    }
        break;
    case EVTLOG_TPM2_TCG:
        if ( !evtlog_append_tpm2_tcg(pcr, type, hl) )
            return false;
        break;
    default:
        return false;
    }

    return true;
}

__data uint32_t g_using_da = 0;
__data acm_hdr_t *g_sinit = 0;
__data bool g_tpr_support = 0;

static void configure_vtd(void)
{
    uint32_t remap_length;
    struct dmar_remapping *dmar_remap = vtd_get_dmar_remap(&remap_length);

    if (dmar_remap == NULL) {
        printk("cannot get DMAR remapping structures, skipping configuration\n");
        return;
    } else {
        printk("configuring DMAR remapping\n");
    }

    struct dmar_remapping *iter, *next;
    struct dmar_remapping *end = ((void *)dmar_remap) + remap_length;

    for (iter = dmar_remap; iter < end; iter = next) {
        next = (void *)iter + iter->length;
        if (iter->length == 0) {
            /* Avoid looping forever on bad ACPI tables */
            printk("    invalid 0-length structure\n");
            break;
        } else if (next > end) {
            /* Avoid passing table end */
            printk("    record passes table end\n");
            break;
        }

        if (iter->type == DMAR_REMAPPING_DRHD) {
            if (!vtd_disable_dma_remap(iter)) {
                printk("    vtd_disable_dma_remap failed!\n");
            }
        }
    }

}

/*
 * sets up TXT heap
 */
static txt_heap_t *init_txt_heap(void *ptab_base, acm_hdr_t *sinit, loader_ctx *lctx)
{
    txt_heap_t *txt_heap;
    uint64_t *size;
    struct tpm_if *tpm = get_tpm();

    txt_heap = get_txt_heap();

    /*
     * BIOS data already setup by BIOS
     */
    if ( !verify_txt_heap(txt_heap, true) )
        return NULL;

    /*
     * OS/loader to MLE data
     */
    os_mle_data_t *os_mle_data = get_os_mle_data_start(txt_heap);
    size = (uint64_t *)((uint32_t)os_mle_data - sizeof(uint64_t));
    *size = sizeof(*os_mle_data) + sizeof(uint64_t);
    tb_memset(os_mle_data, 0, sizeof(*os_mle_data));
    os_mle_data->version = 3;
    os_mle_data->lctx_addr = lctx->addr;
    os_mle_data->saved_misc_enable_msr = rdmsr(MSR_IA32_MISC_ENABLE);

    /*
     * OS/loader to SINIT data
     */
    /* check sinit supported os_sinit_data version */
    uint32_t version = get_supported_os_sinit_data_ver(sinit);
    if ( version < MIN_OS_SINIT_DATA_VER ) {
        printk(TBOOT_ERR"unsupported OS to SINIT data version(%u) in sinit\n",
               version);
        return NULL;
    }
    if ( version > MAX_OS_SINIT_DATA_VER )
        version = MAX_OS_SINIT_DATA_VER;

    os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);
    size = (uint64_t *)((uint32_t)os_sinit_data - sizeof(uint64_t));
    *size = calc_os_sinit_data_size(version);
    tb_memset(os_sinit_data, 0, *size);
    os_sinit_data->version = version;

    /* this is phys addr */
    os_sinit_data->mle_ptab = (uint64_t)(unsigned long)ptab_base;
    os_sinit_data->mle_size = g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off;
    /* this is linear addr (offset from MLE base) of mle header */
    os_sinit_data->mle_hdr_base = (uint64_t)(unsigned long)&g_mle_hdr -
        (uint64_t)(unsigned long)&_mle_start;
    /* VT-d PMRs / TPRs */
    uint64_t min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram;
    
    if ( !get_ram_ranges(&min_lo_ram, &max_lo_ram, &min_hi_ram, &max_hi_ram) )
        return NULL;

    /* Extended elements initialization for TPM elog and TPRs*/
    if ( os_sinit_data->version >= 6 ) {
        init_os_sinit_ext_data(os_sinit_data->ext_data_elts);
    }

    set_dma_protection(os_sinit_data, min_lo_ram, max_lo_ram, min_hi_ram,
                 max_hi_ram);

    /* LCP owner policy data */
    void *lcp_base = NULL;
    uint32_t lcp_size = 0;

    if ( find_lcp_module(lctx, &lcp_base, &lcp_size) && lcp_size > 0 ) {
        /* copy to heap */
        if ( lcp_size > sizeof(os_mle_data->lcp_po_data) ) {
            printk(TBOOT_ERR"LCP owner policy data file is too large (%u)\n",
                   lcp_size);
            return NULL;
        }
        tb_memcpy(os_mle_data->lcp_po_data, lcp_base, lcp_size);
        os_sinit_data->lcp_po_base = (unsigned long)&os_mle_data->lcp_po_data;
        os_sinit_data->lcp_po_size = lcp_size;
    }
    /* capabilities : choose monitor wake mechanism first */
    txt_caps_t sinit_caps = get_sinit_capabilities(sinit);
    txt_caps_t caps_mask = { 0 };
    caps_mask.rlp_wake_getsec = 1;
    caps_mask.rlp_wake_monitor = 1;
    caps_mask.pcr_map_da = 1;
    caps_mask.tcg_event_log_format = 1;
    caps_mask.tcg_event_log_format = 1;
    os_sinit_data->capabilities._raw = MLE_HDR_CAPS & ~caps_mask._raw;
    if ( sinit_caps.rlp_wake_monitor )
        os_sinit_data->capabilities.rlp_wake_monitor = 1;
    else if ( sinit_caps.rlp_wake_getsec )
        os_sinit_data->capabilities.rlp_wake_getsec = 1;
    else {     /* should have been detected in verify_acmod() */
        printk(TBOOT_ERR"SINIT capabilities are incompatible (0x%x)\n", sinit_caps._raw);
        return NULL;
    }
    if ( get_evtlog_type() == EVTLOG_TPM2_TCG ) {
        printk(TBOOT_INFO"SINIT ACM supports TCG compliant TPM 2.0 event log format, tcg_event_log_format = %d \n", 
              sinit_caps.tcg_event_log_format);
        os_sinit_data->capabilities.tcg_event_log_format = 1;
    }
    /* capabilities : require MLE pagetable in ECX on launch */
    /* TODO: when SINIT ready
     * os_sinit_data->capabilities.ecx_pgtbl = 1;
     */
    os_sinit_data->capabilities.ecx_pgtbl = 0;
    if (is_loader_launch_efi(lctx)){
        /* we were launched EFI, set efi_rsdt_ptr */
        struct acpi_rsdp *rsdp = get_rsdp(lctx);
        if (rsdp != NULL){
            if (version < 6){
                /* rsdt */
                /* NOTE: Winston Wang says this doesn't work for v5 */
                os_sinit_data->efi_rsdt_ptr = (uint64_t) rsdp->rsdp1.rsdt;
            } else {
                /* rsdp */
                tb_memcpy((void *)&g_rsdp, rsdp, sizeof(struct acpi_rsdp));
                os_sinit_data->efi_rsdt_ptr = (uint64_t)((uint32_t)&g_rsdp);
            }
        } else {
            /* per discussions--if we don't have an ACPI pointer, die */
            printk(TBOOT_ERR"Failed to find RSDP for EFI launch\n");
            return NULL;
        }
    }
        
    /* capabilities : choose DA/LG */
    os_sinit_data->capabilities.pcr_map_no_legacy = 1;
    if ( sinit_caps.pcr_map_da && (get_tboot_prefer_da() || sinit_caps.cbnt_supported) )
        os_sinit_data->capabilities.pcr_map_da = 1;
    else if ( !sinit_caps.pcr_map_no_legacy )
        os_sinit_data->capabilities.pcr_map_no_legacy = 0;
    else if ( sinit_caps.pcr_map_da ) {
        printk(TBOOT_INFO
               "DA is the only supported PCR mapping by SINIT, use it\n");
        os_sinit_data->capabilities.pcr_map_da = 1;
    }
    else {
        printk(TBOOT_ERR"SINIT capabilities are incompatible (0x%x)\n", 
               sinit_caps._raw);
        return NULL;
    }
    g_using_da = os_sinit_data->capabilities.pcr_map_da;

    /* PCR mapping selection MUST be zero in TPM2.0 mode
     * since D/A mapping is the only supported by TPM2.0 */
    if ( tpm->major >= TPM20_VER_MAJOR ) {
        os_sinit_data->flags = 1;
        os_sinit_data->capabilities.pcr_map_no_legacy = 0;
        os_sinit_data->capabilities.pcr_map_da = 0;
        g_using_da = 1;
    }

    print_os_sinit_data(os_sinit_data);

    /*
     * SINIT to MLE data will be setup by SINIT
     */

    return txt_heap;
}

static void txt_wakeup_cpus(void)
{
    uint16_t cs;
    mle_join_t mle_join;
    unsigned int ap_wakeup_count;

    if ( !verify_stm(get_apicid()) )
        apply_policy(TB_ERR_POST_LAUNCH_VERIFICATION);

    /* enable SMIs on BSP before waking APs (which will enable them on APs)
       because some SMM may take immediate SMI and hang if AP gets in first */
    printk(TBOOT_DETA"enabling SMIs and NMI on BSP\n");
    __getsec_smctrl();
    __enable_nmi();

    atomic_set(&ap_wfs_count, 0);

    /* RLPs will use our GDT and CS */
    extern char gdt_table[], gdt_table_end[];
    __asm__ __volatile__ ("mov %%cs, %0\n" : "=r"(cs));

    mle_join.entry_point = (uint32_t)(unsigned long)&_txt_wakeup;
    mle_join.seg_sel = cs;
    mle_join.gdt_base = (uint32_t)gdt_table;
    mle_join.gdt_limit = gdt_table_end - gdt_table - 1;

    printk(TBOOT_DETA"mle_join.entry_point = %x\n", mle_join.entry_point);
    printk(TBOOT_DETA"mle_join.seg_sel = %x\n", mle_join.seg_sel);
    printk(TBOOT_DETA"mle_join.gdt_base = %x\n", mle_join.gdt_base);
    printk(TBOOT_DETA"mle_join.gdt_limit = %x\n", mle_join.gdt_limit);

    write_priv_config_reg(TXTCR_MLE_JOIN, (uint64_t)(unsigned long)&mle_join);

    mtx_init(&ap_lock);

    txt_heap_t *txt_heap = get_txt_heap();
    sinit_mle_data_t *sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);

    /* choose wakeup mechanism based on capabilities used */
    if ( os_sinit_data->capabilities.rlp_wake_monitor ) {
        printk(TBOOT_INFO"joining RLPs to MLE with MONITOR wakeup\n");
        printk(TBOOT_DETA"rlp_wakeup_addr = 0x%x\n", sinit_mle_data->rlp_wakeup_addr);
        *((uint32_t *)(unsigned long)(sinit_mle_data->rlp_wakeup_addr)) = 0x01;
    }
    else {
        printk(TBOOT_INFO"joining RLPs to MLE with GETSEC[WAKEUP]\n");
        __getsec_wakeup();
        printk(TBOOT_INFO"GETSEC[WAKEUP] completed\n");
    }

    /* assume BIOS isn't lying to us about # CPUs, else some CPUS may not */
    /* have entered wait-for-sipi before we launch *or* we have to wait */
    /* for timeout before launching */
    /* (all TXT-capable CPUs have at least 2 cores) */
    bios_data_t *bios_data = get_bios_data_start(txt_heap);
    ap_wakeup_count = bios_data->num_logical_procs - 1;
    if ( ap_wakeup_count >= NR_CPUS ) {
        printk(TBOOT_INFO"there are too many CPUs (%u)\n", ap_wakeup_count);
        ap_wakeup_count = NR_CPUS - 1;
    }

    printk(TBOOT_INFO"waiting for all APs (%d) to enter wait-for-sipi...\n",
           ap_wakeup_count);
    /* wait for all APs that woke up to have entered wait-for-sipi */
    uint32_t timeout = AP_WFS_TIMEOUT;
    do {
        if ( timeout % 0x8000 == 0 )
            printk(TBOOT_INFO".");
        else
            cpu_relax();
        if ( timeout % 0x200000 == 0 )
            printk(TBOOT_INFO"\n");
        timeout--;
    } while ( ( atomic_read(&ap_wfs_count) < ap_wakeup_count ) &&
              timeout > 0 );
    printk(TBOOT_INFO"\n");
    if ( timeout == 0 )
        printk(TBOOT_INFO"wait-for-sipi loop timed-out\n");
    else
        printk(TBOOT_INFO"all APs in wait-for-sipi\n");
}

bool txt_is_launched(void)
{
    txt_sts_t sts;

    sts._raw = read_pub_config_reg(TXTCR_STS);

    return sts.senter_done_sts;
}

bool is_tpr_supported(void)
{
    //Reads SINIT ACM capabilities field and returns tpr_support bit
    //Needs g_sinit to be set.
    txt_caps_t sinit_caps;

    sinit_caps._raw = 0;

    if (g_sinit != NULL) {
        sinit_caps = get_sinit_capabilities(g_sinit);
    }

    return sinit_caps.tpr_support;
}

tb_error_t txt_launch_environment(loader_ctx *lctx)
{
    void *mle_ptab_base;
    os_mle_data_t *os_mle_data;
    txt_heap_t *txt_heap;

    /*
     * find correct SINIT AC module in modules list
     */
    // find_platform_sinit_module(lctx, (void **)&g_sinit, NULL);
    /* if it is newer than BIOS-provided version, then copy it to */
    /* BIOS reserved region */
    // g_sinit = copy_sinit(g_sinit);
    // if ( g_sinit == NULL )
    //    return TB_ERR_SINIT_NOT_PRESENT;
    /* do some checks on it */
    // if ( !verify_acmod(g_sinit) )
     //   return TB_ERR_ACMOD_VERIFY_FAILED;

    /* print some debug info */
    print_file_info();
    print_mle_hdr(&g_mle_hdr);

    /* create MLE page table */
    mle_ptab_base = build_mle_pagetable(
                             g_mle_hdr.mle_start_off + TBOOT_BASE_ADDR,
                             g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off);
    if ( mle_ptab_base == NULL )
        return TB_ERR_FATAL;

    configure_vtd();

    /* initialize TXT heap */
    txt_heap = init_txt_heap(mle_ptab_base, g_sinit, lctx);
    if ( txt_heap == NULL )
        return TB_ERR_TXT_NOT_SUPPORTED;

    /* save MTRRs before we alter them for SINIT launch */
    os_mle_data = get_os_mle_data_start(txt_heap);
    save_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* 
     * Disable VGA logging when using framebuffer. Writing to it will be
     * extreme slow when memory is set to UC.
     */
    if (get_framebuffer_info(g_ldr_ctx) != NULL) {
        printk(TBOOT_INFO"Disabling VGA logging before GETSEC[SENTER]\n");
        printk_disable_vga();
    }

    /*
    * If memlog decide to compress logs after setting MTRRs,
    * it will take very much time. Better do it now.
    */
    printk_flush();

    /* set MTRRs properly for AC module (SINIT) */
    if ( !set_mtrrs_for_acmod(g_sinit) )
        return TB_ERR_FATAL;

   /*{
   tpm_reg_loc_ctrl_t    reg_loc_ctrl;
   tpm_reg_loc_state_t  reg_loc_state;
   
   reg_loc_ctrl._raw[0] = 0;
   reg_loc_ctrl.relinquish = 1;
   write_tpm_reg(0, TPM_REG_LOC_CTRL, &reg_loc_ctrl);
   printk(TBOOT_INFO"Relinquish CRB localility 0 before executing GETSEC[SENTER]...\n");
   read_tpm_reg(0, TPM_REG_LOC_STATE, &reg_loc_state);
   printk(TBOOT_INFO"CRB reg_loc_state.active_locality is 0x%x \n", reg_loc_state.active_locality);
   printk(TBOOT_INFO"CRB reg_loc_state.loc_assigned is 0x%x \n", reg_loc_state.loc_assigned);
   }*/
   
   printk(TBOOT_INFO"executing GETSEC[SENTER]...\n");
    /* (optionally) pause before executing GETSEC[SENTER] */
    if ( g_vga_delay > 0 )
        delay(g_vga_delay * 1000);
    __getsec_senter((uint32_t)g_sinit, (g_sinit->size)*4);
    printk(TBOOT_INFO"ERROR--we should not get here!\n");
    return TB_ERR_FATAL;
}

bool txt_s3_launch_environment(void)
{
    /* initial launch's TXT heap data is still in place and assumed valid */
    /* so don't re-create; this is OK because it was untrusted initially */
    /* and would be untrusted now */
    int log_type = get_evtlog_type();
    /* get sinit binary loaded */
    g_sinit = (acm_hdr_t *)(uint32_t)read_pub_config_reg(TXTCR_SINIT_BASE);
    if ( g_sinit == NULL ){
        return false;
    }
	/* initialize event log in os_sinit_data, so that events will not */
	/* repeat when s3 */
	if ( log_type == EVTLOG_TPM12 && g_elog ) {
		g_elog = (event_log_container_t *)init_event_log();
    } else if ( log_type == EVTLOG_TPM2_TCG && g_elog_2_1)  {
        init_evtlog_desc_1(g_elog_2_1);
    } else if ( log_type == EVTLOG_TPM2_LEGACY && g_elog_2)  {
        init_evtlog_desc(g_elog_2);
    }

    /*
    * If memlog decide to compress logs after setting MTRRs,
    * it will take very much time. Better do it now.
    */
    printk_flush();

    /* set MTRRs properly for AC module (SINIT) */
    set_mtrrs_for_acmod(g_sinit);

    printk(TBOOT_INFO"executing GETSEC[SENTER]...\n");
    /* (optionally) pause before executing GETSEC[SENTER] */
    if ( g_vga_delay > 0 )
        delay(g_vga_delay * 1000);
    __getsec_senter((uint32_t)g_sinit, (g_sinit->size)*4);
    printk(TBOOT_ERR"ERROR--we should not get here!\n");
    return false;
}

tb_error_t txt_launch_racm(loader_ctx *lctx)
{
    acm_hdr_t *racm = NULL;

    /*
     * find correct revocation AC module in modules list
     */
    find_platform_racm(lctx, (void **)&racm, NULL);
    if ( racm == NULL )
        return TB_ERR_SINIT_NOT_PRESENT;
    /* copy it to a 32KB aligned memory address */
    racm = copy_racm(racm);
    if ( racm == NULL )
        return TB_ERR_SINIT_NOT_PRESENT;
    /* do some checks on it */
    if ( !verify_racm(racm) )
        return TB_ERR_ACMOD_VERIFY_FAILED;

    /* save MTRRs before we alter them for RACM launch */
    /*  - not needed by far since always reboot after RACM launch */
    //save_mtrrs(...);

    /*
    * If memlog decide to compress logs after setting MTRRs,
    * it will take very much time. Better do it now.
    */
    printk_flush();

    /* set MTRRs properly for AC module (RACM) */
    if ( !set_mtrrs_for_acmod(racm) )
        return TB_ERR_FATAL;

    /* clear MSEG_BASE/SIZE registers */
    write_pub_config_reg(TXTCR_MSEG_BASE, 0);
    write_pub_config_reg(TXTCR_MSEG_SIZE, 0);

    printk(TBOOT_INFO"executing GETSEC[ENTERACCS]...\n");
    /* (optionally) pause before executing GETSEC[ENTERACCS] */
    if ( g_vga_delay > 0 )
        delay(g_vga_delay * 1000);
    __getsec_enteraccs((uint32_t)racm, (racm->size)*4, 0xF0);
    /* powercycle by writing 0x0a+0x0e to port 0xcf9, */
    /* warm reset by write 0x06 to port 0xcf9 */
    //outb(0xcf9, 0x0a);
    //outb(0xcf9, 0x0e);
    outb(0xcf9, 0x06);
    
    printk(TBOOT_ERR"ERROR--we should not get here!\n");
    return TB_ERR_FATAL;
}

bool txt_prepare_cpu(void)
{
    unsigned long eflags, cr0;
    uint64_t mcg_cap, mcg_stat;

    /* must be running at CPL 0 => this is implicit in even getting this far */
    /* since our bootstrap code loads a GDT, etc. */

    cr0 = read_cr0();

    /* must be in protected mode */
    if ( !(cr0 & CR0_PE) ) {
        printk(TBOOT_ERR"ERR: not in protected mode\n");
        return false;
    }

    /* cache must be enabled (CR0.CD = CR0.NW = 0) */
    if ( cr0 & CR0_CD ) {
        printk(TBOOT_INFO"CR0.CD set\n");
        cr0 &= ~CR0_CD;
    }
    if ( cr0 & CR0_NW ) {
        printk(TBOOT_INFO"CR0.NW set\n");
        cr0 &= ~CR0_NW;
    }

    /* native FPU error reporting must be enabled for proper */
    /* interaction behavior */
    if ( !(cr0 & CR0_NE) ) {
        printk(TBOOT_INFO"CR0.NE not set\n");
        cr0 |= CR0_NE;
    }

    write_cr0(cr0);

    /* cannot be in virtual-8086 mode (EFLAGS.VM=1) */
    eflags = read_eflags();
    if ( eflags & X86_EFLAGS_VM ) {
        printk(TBOOT_INFO"EFLAGS.VM set\n");
        write_eflags(eflags | ~X86_EFLAGS_VM);
    }

    printk(TBOOT_INFO"CR0 and EFLAGS OK\n");

    /*
     * verify that we're not already in a protected environment
     */
    if ( txt_is_launched() ) {
        printk(TBOOT_ERR"already in protected environment\n");
        return false;
    }

    /*
     * verify all machine check status registers are clear (unless
     * support preserving them)
     */

    /* no machine check in progress (IA32_MCG_STATUS.MCIP=1) */
    mcg_stat = rdmsr(MSR_MCG_STATUS);
    if ( mcg_stat & 0x04 ) {
        printk(TBOOT_ERR"machine check in progress\n");
        return false;
    }

    getsec_parameters_t params;
    if ( !get_parameters(&params) ) {
        printk(TBOOT_ERR"get_parameters() failed\n");
        return false;
    }

    /* check if all machine check regs are clear */
    mcg_cap = rdmsr(MSR_MCG_CAP);
    for ( unsigned int i = 0; i < (mcg_cap & 0xff); i++ ) {
        mcg_stat = rdmsr(MSR_MC0_STATUS + 4*i);
        if ( mcg_stat & (1ULL << 63) ) {
            printk(TBOOT_ERR"MCG[%u] = %Lx ERROR\n", i, mcg_stat);
            if ( !params.preserve_mce )
                return false;
        }
    }

    if ( params.preserve_mce )
        printk(TBOOT_INFO"supports preserving machine check errors\n");
    else
        printk(TBOOT_INFO"no machine check errors\n");

    if ( params.proc_based_scrtm )
        printk(TBOOT_INFO"CPU support processor-based S-CRTM\n");

    /* all is well with the processor state */
    printk(TBOOT_INFO"CPU is ready for SENTER\n");

    return true;
}

void txt_post_launch(void)
{
    txt_heap_t *txt_heap;
    os_mle_data_t *os_mle_data;
    tb_error_t err;

    /* verify MTRRs, VT-d settings, TXT heap, etc. */
    err = txt_post_launch_verify_platform();
    /* don't return the error yet, because we need to restore settings */
    if ( err != TB_ERR_NONE )
        printk(TBOOT_ERR"failed to verify platform\n");

    /* get saved OS state (os_mvmm_data_t) from LT heap */
    txt_heap = get_txt_heap();
    os_mle_data = get_os_mle_data_start(txt_heap);

    /* clear error registers so that we start fresh */
    write_priv_config_reg(TXTCR_ERRORCODE, 0x00000000);
    write_priv_config_reg(TXTCR_ESTS, 0xffffffff);  /* write 1's to clear */

    /* bring RLPs into environment (do this before restoring MTRRs to ensure */
    /* SINIT area is mapped WB for MONITOR-based RLP wakeup) */
    txt_wakeup_cpus();

    /* restore pre-SENTER IA32_MISC_ENABLE_MSR (no verification needed)
       (do after AP wakeup so that if restored MSR has MWAIT clear it won't
       prevent wakeup) */
    printk(TBOOT_DETA"saved IA32_MISC_ENABLE = 0x%08x\n", os_mle_data->saved_misc_enable_msr);
    wrmsr(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);
    if ( use_mwait() ) {
        /* set MONITOR/MWAIT support */
        uint64_t misc;
        misc = rdmsr(MSR_IA32_MISC_ENABLE);
        misc |= MSR_IA32_MISC_ENABLE_MONITOR_FSM;
        wrmsr(MSR_IA32_MISC_ENABLE, misc);
    }

    /* restore pre-SENTER MTRRs that were overwritten for SINIT launch */
    restore_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* now, if there was an error, apply policy */
    apply_policy(err);

    /* always set the TXT.CMD.SECRETS flag */
    write_priv_config_reg(TXTCR_CMD_SECRETS, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
    printk(TBOOT_INFO"set TXT.CMD.SECRETS flag\n");

    /* open TPM locality 1 */
    write_priv_config_reg(TXTCR_CMD_OPEN_LOCALITY1, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
    printk(TBOOT_INFO"opened TPM locality 1\n");
}

void ap_wait(unsigned int cpuid)
{
    if ( cpuid >= NR_CPUS ) {
        printk(TBOOT_ERR"cpuid (%u) exceeds # supported CPUs\n", cpuid);
        apply_policy(TB_ERR_FATAL);
        mtx_leave(&ap_lock);
        return;
    }

    /* ensure MONITOR/MWAIT support is set */
    uint64_t misc;
    misc = rdmsr(MSR_IA32_MISC_ENABLE);
    misc |= MSR_IA32_MISC_ENABLE_MONITOR_FSM;
    wrmsr(MSR_IA32_MISC_ENABLE, misc);

    /* this is close enough to entering monitor/mwait loop, so inc counter */
    atomic_inc((atomic_t *)&_tboot_shared.num_in_wfs);
    mtx_leave(&ap_lock);

    printk(TBOOT_INFO"cpu %u mwait'ing\n", cpuid);
    while ( _tboot_shared.ap_wake_trigger != cpuid ) {
        cpu_monitor(&_tboot_shared.ap_wake_trigger, 0, 0);
        mb();
        if ( _tboot_shared.ap_wake_trigger == cpuid )
            break;
        cpu_mwait(0, 0);
    }

    uint32_t sipi_vec = (uint32_t)_tboot_shared.ap_wake_addr;
    atomic_dec(&ap_wfs_count);
    atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
    cpu_wakeup(cpuid, sipi_vec);
}

void txt_cpu_wakeup(void)
{
    txt_heap_t *txt_heap;
    os_mle_data_t *os_mle_data;
    uint64_t madt_apicbase, msr_apicbase;
    unsigned int cpuid = get_apicid();

    if ( cpuid >= NR_CPUS ) {
        printk(TBOOT_ERR"cpuid (%u) exceeds # supported CPUs\n", cpuid);
        apply_policy(TB_ERR_FATAL);
        return;
    }

    printk(TBOOT_INFO"Mutex lock cpu %u\n", cpuid);
    mtx_enter(&ap_lock);

    printk(TBOOT_INFO"cpu %u waking up from TXT sleep\n", cpuid);

    /* restore LAPIC base address for AP */
    madt_apicbase = (uint64_t)get_madt_apic_base();
    if ( madt_apicbase == 0 ) {
        printk(TBOOT_ERR"not able to get apci base from MADT\n");
        apply_policy(TB_ERR_FATAL);
        return;
    }
    msr_apicbase = rdmsr(MSR_APICBASE);
    if ( madt_apicbase != (msr_apicbase & ~0xFFFULL) ) {
        printk(TBOOT_INFO"cpu %u restore apic base to %llx\n", cpuid, madt_apicbase);
        wrmsr(MSR_APICBASE, (msr_apicbase & 0xFFFULL) | madt_apicbase);
    }

    txt_heap = get_txt_heap();
    os_mle_data = get_os_mle_data_start(txt_heap);

    /* apply (validated) (pre-SENTER) MTRRs from BSP to each AP */
    restore_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* restore pre-SENTER IA32_MISC_ENABLE_MSR */
    wrmsr(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);

    if ( !verify_stm(cpuid) )
        apply_policy(TB_ERR_POST_LAUNCH_VERIFICATION);

    /* enable SMIs and NMI */
    printk(TBOOT_DETA"enabling SMIs and NMI on cpu %u\n", cpuid);
    __getsec_smctrl();
    __enable_nmi();

    atomic_inc(&ap_wfs_count);
    if ( use_mwait() )
        ap_wait(cpuid);
    else
        handle_init_sipi_sipi(cpuid);
}

tb_error_t txt_protect_mem_regions(void)
{
    uint64_t base, size;

    /*
     * TXT has 2 regions of RAM that need to be reserved for use by only the
     * hypervisor; not even dom0 should have access:
     *   TXT heap, SINIT AC module
     */

    /* TXT heap */
    base = read_pub_config_reg(TXTCR_HEAP_BASE);
    size = read_pub_config_reg(TXTCR_HEAP_SIZE);
    printk(TBOOT_INFO"protecting TXT heap (%Lx - %Lx) in e820 table\n", base,
           (base + size - 1));
    if ( !e820_protect_region(base, size, E820_RESERVED) )
        return TB_ERR_FATAL;
    if (!efi_memmap_reserve(base, size)) {
        return TB_ERR_FATAL;
    }

    /* SINIT */
    base = read_pub_config_reg(TXTCR_SINIT_BASE);
    size = read_pub_config_reg(TXTCR_SINIT_SIZE);
    printk(TBOOT_INFO"protecting SINIT (%Lx - %Lx) in e820 table\n", base,
           (base + size - 1));
    if ( !e820_protect_region(base, size, E820_RESERVED) )
        return TB_ERR_FATAL;
    if (!efi_memmap_reserve(base, size)) {
        return TB_ERR_FATAL;
    }

    /* TXT private space */
    base = TXT_PRIV_CONFIG_REGS_BASE;
    size = TXT_CONFIG_REGS_SIZE;
    printk(TBOOT_INFO
           "protecting TXT Private Space (%Lx - %Lx) in e820 table\n",
           base, (base + size - 1));
    if ( !e820_protect_region(base, size, E820_RESERVED) )
        return TB_ERR_FATAL;
    if (!efi_memmap_reserve(base, size)) {
        return TB_ERR_FATAL;
    }

    /* ensure that memory not marked as good RAM by the MDRs is RESERVED in
       the e820 table */
    txt_heap_t* txt_heap = get_txt_heap();
    sinit_mle_data_t *sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    uint32_t num_mdrs = sinit_mle_data->num_mdrs;
    sinit_mdr_t *mdrs_base = (sinit_mdr_t *)(((void *)sinit_mle_data
                                              - sizeof(uint64_t)) +
                                             sinit_mle_data->mdrs_off);
    printk(TBOOT_INFO"verifying e820 table against SINIT MDRs: ");
    if ( !verify_e820_map(mdrs_base, num_mdrs) ) {
        printk(TBOOT_ERR"verification failed.\n");
        return TB_ERR_POST_LAUNCH_VERIFICATION;
    }
    printk(TBOOT_INFO"verification succeeded.\n");

    return TB_ERR_NONE;
}

void txt_shutdown(void)
{
    unsigned long apicbase;

    /* shutdown shouldn't be called on APs, but if it is then just hlt */
    apicbase = rdmsr(MSR_APICBASE);
    if ( !(apicbase & APICBASE_BSP) ) {
        printk(TBOOT_INFO"calling txt_shutdown on AP\n");
        while ( true )
            halt();
    }

    /* set TXT.CMD.NO-SECRETS flag (i.e. clear SECRETS flag) */
    write_priv_config_reg(TXTCR_CMD_NO_SECRETS, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* fence */
    printk(TBOOT_INFO"secrets flag cleared\n");

    /* unlock memory configuration */
    write_priv_config_reg(TXTCR_CMD_UNLOCK_MEM_CONFIG, 0x01);
    read_pub_config_reg(TXTCR_E2STS);    /* fence */
    printk(TBOOT_INFO"memory configuration unlocked\n");

    /* if some APs are still in wait-for-sipi then SEXIT will hang */
    /* so TXT reset the platform instead, expect mwait case */
    if ( (!use_mwait()) && atomic_read(&ap_wfs_count) > 0 ) {
        printk(TBOOT_INFO
               "exiting with some APs still in wait-for-sipi state (%u)\n",
               atomic_read(&ap_wfs_count));
        write_priv_config_reg(TXTCR_CMD_RESET, 0x01);
    }

    /* close TXT private config space */
    /* implicitly closes TPM localities 1 + 2 */
    read_priv_config_reg(TXTCR_E2STS);   /* fence */
    write_priv_config_reg(TXTCR_CMD_CLOSE_PRIVATE, 0x01);
    read_pub_config_reg(TXTCR_E2STS);    /* fence */
    printk(TBOOT_INFO"private config space closed\n");

    /* SMXE may not be enabled any more, so set it to make sure */
    write_cr4(read_cr4() | CR4_SMXE);

    /* call GETSEC[SEXIT] */
    printk(TBOOT_INFO"executing GETSEC[SEXIT]...\n");
    __getsec_sexit();
    printk(TBOOT_INFO"measured environment torn down\n");
}

bool txt_is_powercycle_required(void)
{
    /* a powercycle is required to clear the TXT_RESET.STS flag */
    txt_ests_t ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    return ests.txt_reset_sts;
}

#define ACM_MEM_TYPE_UC                 0x0100
#define ACM_MEM_TYPE_WC                 0x0200
#define ACM_MEM_TYPE_WT                 0x1000
#define ACM_MEM_TYPE_WP                 0x2000
#define ACM_MEM_TYPE_WB                 0x4000

#define DEF_ACM_MAX_SIZE                0x8000
#define DEF_ACM_VER_MASK                0xffffffff
#define DEF_ACM_VER_SUPPORTED           0x00
#define DEF_ACM_MEM_TYPES               ACM_MEM_TYPE_UC
#define DEF_SENTER_CTRLS                0x00

bool get_parameters(getsec_parameters_t *params)
{
    unsigned long cr4;
    uint32_t index, eax, ebx, ecx;
    int param_type;

    /* sanity check because GETSEC[PARAMETERS] will fail if not set */
    cr4 = read_cr4();
    if ( !(cr4 & CR4_SMXE) ) {
        printk(TBOOT_ERR"SMXE not enabled, can't read parameters\n");
        return false;
    }

    tb_memset(params, 0, sizeof(*params));
    params->acm_max_size = DEF_ACM_MAX_SIZE;
    params->acm_mem_types = DEF_ACM_MEM_TYPES;
    params->senter_controls = DEF_SENTER_CTRLS;
    params->proc_based_scrtm = false;
    params->preserve_mce = false;

    index = 0;
    do {
        __getsec_parameters(index++, &param_type, &eax, &ebx, &ecx);
        /* the code generated for a 'switch' statement doesn't work in this */
        /* environment, so use if/else blocks instead */

        /* NULL - all reserved */
        if ( param_type == 0 )
            ;
        /* supported ACM versions */
        else if ( param_type == 1 ) {
            if ( params->n_versions == MAX_SUPPORTED_ACM_VERSIONS )
                printk(TBOOT_WARN"number of supported ACM version exceeds "
                       "MAX_SUPPORTED_ACM_VERSIONS\n");
            else {
                params->acm_versions[params->n_versions].mask = ebx;
                params->acm_versions[params->n_versions].version = ecx;
                params->n_versions++;
            }
        }
        /* max size AC execution area */
        else if ( param_type == 2 )
            params->acm_max_size = eax & 0xffffffe0;
        /* supported non-AC mem types */
        else if ( param_type == 3 )
            params->acm_mem_types = eax & 0xffffffe0;
        /* SENTER controls */
        else if ( param_type == 4 )
            params->senter_controls = (eax & 0x00007fff) >> 8;
        /* TXT extensions support */
        else if ( param_type == 5 ) {
            params->proc_based_scrtm = (eax & 0x00000020) ? true : false;
            params->preserve_mce = (eax & 0x00000040) ? true : false;
        }
        else {
            printk(TBOOT_WARN"unknown GETSEC[PARAMETERS] type: %d\n", 
                   param_type);
            param_type = 0;    /* set so that we break out of the loop */
        }
    } while ( param_type != 0 );

    if ( params->n_versions == 0 ) {
        params->acm_versions[0].mask = DEF_ACM_VER_MASK;
        params->acm_versions[0].version = DEF_ACM_VER_SUPPORTED;
        params->n_versions = 1;
    }

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
