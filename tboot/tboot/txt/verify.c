/*
 * verify.c: verify that platform and processor supports Intel(r) TXT
 *
 * Copyright (c) 2003-2010, Intel Corporation
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
#include <msr.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <processor.h>
#include <page.h>
#include <printk.h>
#include <uuid.h>
#include <loader.h>
#include <tb_error.h>
#include <e820.h>
#include <tboot.h>
#include <acpi.h>
#include <mle.h>
#include <hash.h>
#include <integrity.h>
#include <cmdline.h>
#include <vtd.h>
#include <efi_memmap.h>
#include <txt/txt.h>
#include <txt/smx.h>
#include <txt/mtrrs.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#include <txt/verify.h>

extern long s3_flag;

/*
 * CPUID extended feature info
 */
static unsigned int g_cpuid_ext_feat_info;

/*
 * IA32_FEATURE_CONTROL_MSR
 */
static unsigned long g_feat_ctrl_msr;


static bool read_processor_info(void)
{
    unsigned long f1, f2;
     /* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
    uint32_t regs[4];

    /* is CPUID supported? */
    /* (it's supported if ID flag in EFLAGS can be set and cleared) */
    asm("pushf\n\t"
        "pushf\n\t"
        "pop %0\n\t"
        "mov %0,%1\n\t"
        "xor %2,%0\n\t"
        "push %0\n\t"
        "popf\n\t"
        "pushf\n\t"
        "pop %0\n\t"
        "popf\n\t"
        : "=&r" (f1), "=&r" (f2)
        : "ir" (X86_EFLAGS_ID));
    if ( ((f1^f2) & X86_EFLAGS_ID) == 0 ) {
        g_cpuid_ext_feat_info = 0;
        printk(TBOOT_ERR"CPUID instruction is not supported.\n");
        return false;
    }

    do_cpuid(0, regs);
    if ( regs[1] != 0x756e6547        /* "Genu" */
         || regs[2] != 0x6c65746e     /* "ntel" */
         || regs[3] != 0x49656e69 ) { /* "ineI" */
        g_cpuid_ext_feat_info = 0;
        printk(TBOOT_ERR"Non-Intel CPU detected.\n");
        return false;
    }
    g_cpuid_ext_feat_info = cpuid_ecx(1);

    /* read feature control msr only if processor supports VMX or SMX instructions */
    if ( (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_VMX) ||
         (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_SMX) ) {
        g_feat_ctrl_msr = rdmsr(MSR_IA32_FEATURE_CONTROL);
        printk(TBOOT_DETA"IA32_FEATURE_CONTROL_MSR: %08lx\n", g_feat_ctrl_msr);        
    }

    return true;
}

static bool supports_vmx(void)
{
    /* check that processor supports VMX instructions */
    if ( !(g_cpuid_ext_feat_info & CPUID_X86_FEATURE_VMX) ) {
        printk(TBOOT_ERR"ERR: CPU does not support VMX\n");
        return false;
    }
    printk(TBOOT_INFO"CPU is VMX-capable\n");

    /* and that VMX is enabled in the feature control MSR */
    if ( !(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX) ) {
        printk(TBOOT_ERR"ERR: VMXON disabled by feature control MSR (%lx)\n",
               g_feat_ctrl_msr);
        return false;
    }

    return true;
}

static bool supports_smx(void)
{
    /* check that processor supports SMX instructions */
    if ( !(g_cpuid_ext_feat_info & CPUID_X86_FEATURE_SMX) ) {
        printk(TBOOT_ERR"ERR: CPU does not support SMX\n");
        return false;
    }
    printk(TBOOT_INFO"CPU is SMX-capable\n");

    /*
     * and that SMX is enabled in the feature control MSR
     */

    /* check that the MSR is locked -- BIOS should always lock it */
    if ( !(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_LOCK) ) {
        printk(TBOOT_ERR"ERR: IA32_FEATURE_CONTROL_MSR_LOCK is not locked\n");
        /* this should not happen, as BIOS is required to lock the MSR */
#ifdef PERMISSIVE_BOOT
        /* we enable VMX outside of SMX as well so that if there was some */
        /* error in the TXT boot, VMX will continue to work */
        g_feat_ctrl_msr |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX |
                           IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_OUT_SMX |
                           IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
                           IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL |
                           IA32_FEATURE_CONTROL_MSR_LOCK;
        wrmsrl(MSR_IA32_FEATURE_CONTROL, g_feat_ctrl_msr);
        return true;
#else
        return false;
#endif
    }

    /* check that SENTER (w/ full params) is enabled */
    if ( !(g_feat_ctrl_msr & (IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
                              IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL)) ) {
        printk(TBOOT_ERR"ERR: SENTER disabled by feature control MSR (%lx)\n",
               g_feat_ctrl_msr);
        return false;
    }

    return true;
}

bool use_mwait(void)
{
    return get_tboot_mwait() && (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_XMM3);
}

tb_error_t supports_txt(void)
{
    capabilities_t cap;

    /* processor must support cpuid and must be Intel CPU */
    if ( !read_processor_info() )
        return TB_ERR_SMX_NOT_SUPPORTED;

    /* processor must support SMX */
    if ( !supports_smx() )
        return TB_ERR_SMX_NOT_SUPPORTED;

    if ( use_mwait() ) {
        /* set MONITOR/MWAIT support (SENTER will clear, so always set) */
        uint64_t misc;
        misc = rdmsr(MSR_IA32_MISC_ENABLE);
        misc |= MSR_IA32_MISC_ENABLE_MONITOR_FSM;
        wrmsr(MSR_IA32_MISC_ENABLE, misc);
    }
    else if ( !supports_vmx() ) {
        return TB_ERR_VMX_NOT_SUPPORTED;
    }

    /* testing for chipset support requires enabling SMX on the processor */
    write_cr4(read_cr4() | CR4_SMXE);
    printk(TBOOT_INFO"SMX is enabled\n");

    /*
     * verify that an TXT-capable chipset is present and
     * check that all needed SMX capabilities are supported
     */

    cap = __getsec_capabilities(0);
    if ( cap.chipset_present ) {
        if ( cap.senter && cap.sexit && cap.parameters && cap.smctrl &&
             cap.wakeup ) {
            printk(TBOOT_INFO"TXT chipset and all needed capabilities present\n");
            return TB_ERR_NONE;
        }
        else
            printk(TBOOT_ERR"ERR: insufficient SMX capabilities (%x)\n", cap._raw);
    }
    else
        printk(TBOOT_ERR"ERR: TXT-capable chipset not present\n");

    /* since we are failing, we should clear the SMX flag */
    write_cr4(read_cr4() & ~CR4_SMXE);

    return TB_ERR_TXT_NOT_SUPPORTED;
}

#define LO_RANGE 0
#define HI_RANGE 1
static dma_protected_range_t get_dma_protect_info(uint8_t range /*HI or LO*/, os_sinit_data_t* os_sinit_data_start_override /*Can be NULL*/)
{
    /* Reads HI or LO DMA protection base from TPR or VT-d PMR */
    dma_protected_range_t range_info = {0};
    txt_heap_t* txt_heap = get_txt_heap();
    os_sinit_data_t *os_sinit_data = NULL; 
    heap_tpr_req_element_t *tpr_req_elt = NULL;

    if (range != LO_RANGE && range != HI_RANGE) {
        return range_info;
    }

    //Override os_sinit_data start
    if (os_sinit_data_start_override != NULL) {
        os_sinit_data = os_sinit_data_start_override;
    }
    //Else set it to the beginning of os_sinit_data in heap
    else {
        os_sinit_data = get_os_sinit_data_start(txt_heap);
    }

    if (g_tpr_support) {
        tpr_req_elt = get_tpr_req_element(os_sinit_data);
        if (g_tpr_support == true && tpr_req_elt == NULL) {
            printk(TBOOT_ERR"failed to read TPR_REQ_ELEMENT from TXT HEAP.\n");
            return  range_info;
        }
        if (g_tpr_support == true && tpr_req_elt->tpr_cnt != 2) {
            printk(TBOOT_ERR"TPR_REQ_ELEMENT count is not 2.\n");
            return range_info;
        }
        range_info.base = tpr_req_elt->tpr_req_arr[range].tpr_range_base;
        range_info.size = tpr_req_elt->tpr_req_arr[range].tpr_range_size;
    } else {
        if (range == HI_RANGE) {
            range_info.base = os_sinit_data->vtd_pmr_hi_base;
            range_info.size = os_sinit_data->vtd_pmr_hi_size;
        }
        else {
            range_info.base = os_sinit_data->vtd_pmr_lo_base;
            range_info.size = os_sinit_data->vtd_pmr_lo_size;
        }
    }
    return range_info;
}

static bool reserve_dma_protected_delta_mem(uint64_t min_lo_ram, uint64_t max_lo_ram,
                                  uint64_t min_hi_ram, uint64_t max_hi_ram)
{
    uint64_t base, length;
    (void)min_lo_ram; (void)min_hi_ram;/* portably suppress compiler warning */
    dma_protected_range_t lo_range;
    dma_protected_range_t hi_range;

    lo_range = get_dma_protect_info(LO_RANGE, NULL);
    hi_range = get_dma_protect_info(HI_RANGE, NULL);

    if ( max_lo_ram != (lo_range.base +
                        lo_range.size) ) {
        base = lo_range.base + lo_range.size;
        length = max_lo_ram - base;
        printk(TBOOT_INFO"reserving 0x%Lx - 0x%Lx, which was truncated for DMA protection\n",
               base, base + length);
        if ( !e820_reserve_ram(base, length) )
            return false;
        if (!efi_memmap_reserve(base, length)) {
           return false;
        }
    }
    if ( max_hi_ram != (hi_range.base +
                        hi_range.size) ) {
        base = hi_range.base + hi_range.size;
        length = max_hi_ram - base;
        printk(TBOOT_INFO"reserving 0x%Lx - 0x%Lx, which was truncated for DMA protection\n",
               base, base + length);
        if ( !e820_reserve_ram(base, length) )
            return false;
        if (!efi_memmap_reserve(base, length)) {
           return false;
        }
    }

    return true;
}

static bool verify_dma_protection(txt_heap_t *txt_heap)
{
    os_sinit_data_t *os_sinit_data;
    os_sinit_data_t *tmp_os_sinit_data;
    //If TPR is supported we'd need to add ext elements (tpr_req and end element)
    uint8_t buffer[OS_SINIT_DATA_WITH_TPR_SIZE] = {0};
    uint64_t min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram;
    dma_protected_range_t tmp_hi_range;
    dma_protected_range_t tmp_lo_range;
    dma_protected_range_t orig_hi_range;
    dma_protected_range_t orig_lo_range;

    os_sinit_data = get_os_sinit_data_start(txt_heap);

    /*
     * make sure the VT-d PMRs were actually set to cover what
     * we expect
     */

    /* calculate what they should have been */
    /* no e820 table on S3 resume, so use saved (sealed) values */
    if ( s3_flag ) {
        min_lo_ram = g_pre_k_s3_state.dma_protection_lo_base;
        max_lo_ram = min_lo_ram + g_pre_k_s3_state.dma_protection_lo_size;
        min_hi_ram = g_pre_k_s3_state.dma_protection_hi_base;
        max_hi_ram = min_hi_ram + g_pre_k_s3_state.dma_protection_hi_size;
    }
    else {
        if ( !get_ram_ranges(&min_lo_ram, &max_lo_ram, &min_hi_ram, &max_hi_ram) ) {
            return false;
        }
        
        /* if vtd_pmr_lo/hi sizes rounded to 2MB granularity are less than the
           max_lo/hi_ram values determined from the e820 table, then we must
           reserve the differences in e820 table so that unprotected memory is
           not used by the kernel */
        if ( !reserve_dma_protected_delta_mem(min_lo_ram, max_lo_ram, min_hi_ram,
                                    max_hi_ram) ) {
            printk(TBOOT_ERR"failed to reserve DMA protection delta memory\n");
            return false;
        }
    }

    /* compare to current values */
    tmp_os_sinit_data = (os_sinit_data_t *) buffer;
    tmp_os_sinit_data->version = os_sinit_data->version;
    //Add TPR element and END element:
    if (g_tpr_support) {
        heap_ext_data_element_t *elt = (heap_ext_data_element_t *) &tmp_os_sinit_data->ext_data_elts;
        heap_tpr_req_element_t *tpr_req_elt = NULL;
        elt->type = HEAP_EXTDATA_TYPE_TPR_REQ;
        elt->size = sizeof(*elt) + offsetof(heap_tpr_req_element_t, tpr_req_arr) + (2 * sizeof(tpr_range_t));
        tpr_req_elt = (heap_tpr_req_element_t *) elt->data;
        tpr_req_elt->tpr_cnt = 2;
        //Type, size and tpr count is enough, move to end element
        elt = (void *) elt + elt->size;
        elt->type = HEAP_EXTDATA_TYPE_END;
        elt->size = sizeof(heap_ext_data_element_t); 
    }
    set_dma_protection(tmp_os_sinit_data, min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram);
    //Get DMA protected ranges from tmp_os_sinit_data
    tmp_lo_range = get_dma_protect_info(LO_RANGE, tmp_os_sinit_data);
    tmp_hi_range = get_dma_protect_info(HI_RANGE, tmp_os_sinit_data);
    //Get ranges from os_sinit_data in heap
    orig_lo_range = get_dma_protect_info(LO_RANGE, NULL);
    orig_hi_range = get_dma_protect_info(HI_RANGE, NULL);

    //Compare ranges
    if (
        tmp_lo_range.base != orig_lo_range.base ||
        tmp_lo_range.size != orig_lo_range.size ||
        tmp_hi_range.base != orig_hi_range.base ||
        tmp_hi_range.size != orig_hi_range.size
        ) {
            printk(TBOOT_ERR"OS to SINIT data DMA protection settings do not match:\n");
            printk(TBOOT_DETA"Current low range base: 0x%Lx | Original low range base: 0x%LX\n", 
                tmp_lo_range.base, orig_lo_range.base);
            printk(TBOOT_DETA"Current low range size: 0x%Lx | Original low range size: 0x%LX\n", 
                tmp_lo_range.size, orig_lo_range.size);
            printk(TBOOT_DETA"Current high range base: 0x%Lx | Original high range base: 0x%LX\n", 
                tmp_hi_range.base, orig_hi_range.base);
            printk(TBOOT_DETA"Current high range size: 0x%Lx | Original high range size: 0x%LX\n", 
                tmp_hi_range.size, orig_hi_range.size);
            return false;
    }

    if ( !s3_flag ) {
        /* save the verified values so that they can be sealed for S3 */
        g_pre_k_s3_state.dma_protection_lo_base = orig_lo_range.base;
        g_pre_k_s3_state.dma_protection_lo_size = orig_lo_range.size;
        g_pre_k_s3_state.dma_protection_hi_base = orig_hi_range.base;
        g_pre_k_s3_state.dma_protection_hi_size = orig_hi_range.size;
    }

    return true;
}

void set_dma_protection(os_sinit_data_t *os_sinit_data,
                  uint64_t min_lo_ram, uint64_t max_lo_ram,
                  uint64_t min_hi_ram, uint64_t max_hi_ram)
{
    printk(TBOOT_DETA"Setting DMA protection\n");
    printk(TBOOT_DETA"min_lo_ram: 0x%Lx, max_lo_ram: 0x%Lx\n", min_lo_ram, max_lo_ram);
    printk(TBOOT_DETA"min_hi_ram: 0x%Lx, max_hi_ram: 0x%Lx\n", min_hi_ram, max_hi_ram);

    /*
     * base must be 2M-aligned and size must be multiple of 2M
     * (so round bases and sizes down--rounding size up might conflict
     *  with a BIOS-reserved region and cause problems; in practice, rounding
     *  base down doesn't)
     * we want to protect all of usable mem so that any kernel allocations
     * before VT-d remapping is enabled are protected
     */
    heap_tpr_req_element_t *tpr_req_elt = NULL;
    tpr_req_elt = get_tpr_req_element(os_sinit_data);
    if (g_tpr_support == true && tpr_req_elt == NULL) {
        printk(TBOOT_ERR"failed to read TPR_REQ_ELEMENT from TXT HEAP.\n");
        return;
    }
    if (g_tpr_support == true && tpr_req_elt->tpr_cnt != 2) {
        printk(TBOOT_ERR"TPR_REQ_ELEMENT count is not 2.\n");
        return;
    }
    min_lo_ram &= ~0x1fffffULL;
    uint64_t lo_size = (max_lo_ram - min_lo_ram) & ~0x1fffffULL;
    if (g_tpr_support) {
        tpr_req_elt->tpr_req_arr[0].tpr_range_base = min_lo_ram;
        tpr_req_elt->tpr_req_arr[0].tpr_range_size = lo_size;
    } else {
        os_sinit_data->vtd_pmr_lo_base = min_lo_ram;
        os_sinit_data->vtd_pmr_lo_size = lo_size;
    }

    min_hi_ram &= ~0x1fffffULL;
    uint64_t hi_size = (max_hi_ram - min_hi_ram) & ~0x1fffffULL;
    if (g_tpr_support) {
        tpr_req_elt->tpr_req_arr[1].tpr_range_base = min_hi_ram;
        tpr_req_elt->tpr_req_arr[1].tpr_range_size = hi_size;
    } else {
        os_sinit_data->vtd_pmr_hi_base = min_hi_ram;
        os_sinit_data->vtd_pmr_hi_size = hi_size;
    }
}

tb_error_t txt_verify_platform(void)
{
    txt_heap_t *txt_heap;
    tb_error_t err;

    /* check TXT supported */
    err = supports_txt();
    if ( err != TB_ERR_NONE )
        return err;

    if ( !vtd_bios_enabled() ) {
        return TB_ERR_VTD_NOT_SUPPORTED;
    }

    /* check is TXT_RESET.STS is set, since if it is SENTER will fail */
    txt_ests_t ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    if ( ests.txt_reset_sts ) {
        printk(TBOOT_ERR"TXT_RESET.STS is set and SENTER is disabled (0x%02Lx)\n",
               ests._raw);
        return TB_ERR_SMX_NOT_SUPPORTED;
    }

    /* verify BIOS to OS data */
    txt_heap = get_txt_heap();
    if ( !verify_bios_data(txt_heap) )
        return TB_ERR_TXT_NOT_SUPPORTED;

    return TB_ERR_NONE;
}

static bool verify_saved_mtrrs(txt_heap_t *txt_heap)
{
    os_mle_data_t *os_mle_data;
    os_mle_data = get_os_mle_data_start(txt_heap);

    return validate_mtrrs(&(os_mle_data->saved_mtrr_state));
}

tb_error_t txt_post_launch_verify_platform(void)
{
    txt_heap_t *txt_heap;

    /*
     * verify some of the heap structures
     */
    txt_heap = get_txt_heap();

    if ( !verify_txt_heap(txt_heap, false) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;

    /* verify the saved MTRRs */
    if ( !verify_saved_mtrrs(txt_heap) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;

    /* verify that VT-d PMRs were really set as required */
    if ( !verify_dma_protection(txt_heap) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;

    return TB_ERR_NONE;
}

bool verify_e820_map(sinit_mdr_t* mdrs_base, uint32_t num_mdrs)
{
    sinit_mdr_t* mdr_entry;
    sinit_mdr_t tmp_entry;
    uint64_t base, length;
    uint32_t i, j, pos;

    if ( (mdrs_base == NULL) || (num_mdrs == 0) )
        return false;

    /* sort mdrs */
    for( i = 0; i < num_mdrs; i++ ) {
        tb_memcpy(&tmp_entry, &mdrs_base[i], sizeof(sinit_mdr_t));
        pos = i;
        for ( j = i + 1; j < num_mdrs; j++ ) {
            if ( ( tmp_entry.base > mdrs_base[j].base )
                 || (( tmp_entry.base == mdrs_base[j].base ) &&
                     ( tmp_entry.length > mdrs_base[j].length )) ) {
                tb_memcpy(&tmp_entry, &mdrs_base[j], sizeof(sinit_mdr_t));
                pos = j;
            }
        }
        if ( pos > i ) {
            tb_memcpy(&mdrs_base[pos], &mdrs_base[i], sizeof(sinit_mdr_t));
            tb_memcpy(&mdrs_base[i], &tmp_entry, sizeof(sinit_mdr_t));
        }
    }

    /* verify e820 map against mdrs */
    /* find all ranges *not* in MDRs:
       if any of it is in e820 as RAM then set that to RESERVED. */
    i = 0;
    base = 0;
    while ( i < num_mdrs ) {
        mdr_entry = &mdrs_base[i];
        i++;
        if ( mdr_entry->mem_type > MDR_MEMTYPE_GOOD )
            continue;
        length = mdr_entry->base - base;
        if ( (length > 0) && (!e820_reserve_ram(base, length)) )
            return false;
        base = mdr_entry->base + mdr_entry->length;
    }

    /* deal with the last gap */
    length = (uint64_t)-1 - base;
    return e820_reserve_ram(base, length);
}

static void print_mseg_hdr(mseg_hdr_t *mseg_hdr)
{
    printk(TBOOT_DETA"MSEG header dump for 0x%x:\n", (uint32_t)mseg_hdr);
    printk(TBOOT_DETA"\t revision_id = 0x%x\n", mseg_hdr->revision_id);
    printk(TBOOT_DETA"\t smm_monitor_features = 0x%x\n", mseg_hdr->smm_mon_feat);
    printk(TBOOT_DETA"\t gdtr_limit = 0x%x\n", mseg_hdr->gdtr_limit);
    printk(TBOOT_DETA"\t gdtr_base_offset = 0x%x\n", mseg_hdr->gdtr_base_offset);
    printk(TBOOT_DETA"\t cs_sel = 0x%x\n", mseg_hdr->cs_sel);
    printk(TBOOT_DETA"\t eip_offset = 0x%x\n", mseg_hdr->eip_offset);
    printk(TBOOT_DETA"\t esp_offset = 0x%x\n", mseg_hdr->esp_offset);
    printk(TBOOT_DETA"\t cr3_offset = 0x%x\n", mseg_hdr->cr3_offset);
}

static bool are_mseg_hdrs_equal(void *mseg_base1, void *mseg_base2)
{
    mseg_hdr_t *mseg_hdr1, *mseg_hdr2;

    mseg_hdr1 = (mseg_hdr_t *)mseg_base1;
    mseg_hdr2 = (mseg_hdr_t *)mseg_base2;

    print_mseg_hdr(mseg_hdr1);
    print_mseg_hdr(mseg_hdr2);

    if ( mseg_hdr1->revision_id != mseg_hdr2->revision_id ) {
        printk(TBOOT_ERR"revision id is not consistent.\n");
        return false;
    }

    if ( (mseg_hdr1->smm_mon_feat & 0xfffffffe)
        || (mseg_hdr2->smm_mon_feat & 0xfffffffe) ) {
        printk(TBOOT_ERR"bits 1:31 of SMM-monitor features field should be zero.\n");
        return false;
    }

    if ( mseg_hdr1->smm_mon_feat != mseg_hdr2->smm_mon_feat ) {
        printk(TBOOT_ERR"SMM-monitor features are not consistent.\n");
        return false;
    }

    if ( (mseg_hdr1->gdtr_limit != mseg_hdr2->gdtr_limit)
        || (mseg_hdr1->gdtr_base_offset != mseg_hdr2->gdtr_base_offset)
        || (mseg_hdr1->cs_sel != mseg_hdr2->cs_sel)
        || (mseg_hdr1->eip_offset != mseg_hdr2->eip_offset)
        || (mseg_hdr1->esp_offset != mseg_hdr2->esp_offset)
        || (mseg_hdr1->cr3_offset != mseg_hdr2->cr3_offset) ) {
        printk(TBOOT_ERR"states for SMM activation are not consistent.\n");
        return false;
    }

    return true;
}

static bool verify_mseg(uint64_t smm_mon_ctl)
{
    txt_heap_t *txt_heap = get_txt_heap();
    sinit_mle_data_t *sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    void *mseg_base, *txt_mseg_base;

    /* opt-out */
    if ( !(smm_mon_ctl & MSR_IA32_SMM_MONITOR_CTL_VALID) ) {
        printk(TBOOT_INFO"\topt-out\n");
        return true;
    }

    if ( !sinit_mle_data->mseg_valid ) {
        printk(TBOOT_INFO"\topt-out\n");
        return true;
    }

    /* opt-in */
    printk(TBOOT_INFO"\topt-in ");
    mseg_base = (void *)(unsigned long)
        MSR_IA32_SMM_MONITOR_CTL_MSEG_BASE(smm_mon_ctl);
    txt_mseg_base = (void *)(uint32_t)read_pub_config_reg(TXTCR_MSEG_BASE);

    if ( are_mseg_hdrs_equal(mseg_base, txt_mseg_base) ) {
        printk(TBOOT_INFO"and same MSEG header\n");
        return true;
    }

    printk(TBOOT_ERR"but different MSEG headers\n");
    return false;
}

bool verify_stm(unsigned int cpuid)
{
    static uint64_t ilp_smm_mon_ctl;
    uint64_t smm_mon_ctl, apicbase;

    smm_mon_ctl = rdmsr(MSR_IA32_SMM_MONITOR_CTL);
    apicbase = rdmsr(MSR_APICBASE);
    if ( apicbase & APICBASE_BSP ) {
        ilp_smm_mon_ctl = smm_mon_ctl;
        printk(TBOOT_DETA"MSR for SMM monitor control on BSP is 0x%Lx.\n",
               ilp_smm_mon_ctl);

        /* verify ILP's MSEG == TXT.MSEG.BASE */
        printk(TBOOT_INFO"verifying ILP is opt-out "
               "or has the same MSEG header with TXT.MSEG.BASE\n\t");
        if ( !verify_mseg(ilp_smm_mon_ctl) ) {
            printk(TBOOT_ERR" : failed.\n");
            return false;
        }
        printk(TBOOT_INFO" : succeeded.\n");
    }
    else {
        printk(TBOOT_DETA"MSR for SMM monitor control on cpu %u is 0x%Lx\n",
               cpuid, smm_mon_ctl);

        /* verify ILP's SMM MSR == RLP's SMM MSR */
        printk(TBOOT_INFO"verifying ILP's MSR_IA32_SMM_MONITOR_CTL with cpu %u\n\t",
               cpuid);
        if ( smm_mon_ctl != ilp_smm_mon_ctl ) {
            printk(TBOOT_ERR" : failed.\n");
            return false;
        }
        printk(TBOOT_INFO" : succeeded.\n");

        /* since the RLP's MSR is the same. No need to verify MSEG header */
    }

    return true;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
