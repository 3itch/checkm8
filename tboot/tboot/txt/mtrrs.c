/*
 * mtrrs.c: support functions for manipulating MTRRs
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
#include <compiler.h>
#include <string.h>
#include <processor.h>
#include <msr.h>
#include <printk.h>
#include <misc.h>
#include <page.h>
#include <tboot.h>
#include <loader.h>
#include <acpi.h>
#include <mle.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/acmod.h>
#include <tpm.h>

#define MTRR_TYPE_MIXED         -1
#define MMIO_APIC_BASE          0xFEE00000
#define NR_MMIO_APIC_PAGES      1
#define NR_MMIO_IOAPIC_PAGES    1
#define NR_MMIO_PCICFG_PAGES    1
#define SINIT_MTRR_MASK         0xFFFFFF  /* SINIT requires 36b mask */

/* saved MTRR state or NULL if orig. MTRRs have not been changed */
static __data mtrr_state_t *g_saved_mtrrs = NULL;

static uint64_t get_maxphyaddr_mask(void)
{
    static bool printed_msg = false;
    union {
        uint32_t raw;
        struct {
	    uint32_t num_pa_bits  : 8;
	    uint32_t num_la_bits  : 8;
	    uint32_t reserved     : 16;
	};
    } num_addr_bits;

    /* does CPU support 0x80000008 CPUID leaf? (all TXT CPUs should) */
    uint32_t max_ext_fn = cpuid_eax(0x80000000);
    if ( max_ext_fn < 0x80000008 )
        return 0xffffff;      /* if not, default is 36b support */

    num_addr_bits.raw = cpuid_eax(0x80000008);
    if ( !printed_msg ) {
        printk(TBOOT_DETA"CPU supports %u phys address bits\n", num_addr_bits.num_pa_bits);
	printed_msg = true;
    }
    return ((1ULL << num_addr_bits.num_pa_bits) - 1) >> PAGE_SHIFT;
}

/*
 * this must be done for each processor so that all have the same
 * memory types
 */
bool set_mtrrs_for_acmod(const acm_hdr_t *hdr)
{
    unsigned long eflags;
    unsigned long cr0, cr4;

    /*
     * need to do some things before we start changing MTRRs
     *
     * since this will modify some of the MTRRs, they should be saved first
     * so that they can be restored once the AC mod is done
     */

    /* disable interrupts */
    eflags = read_eflags();
    disable_intr();

    /* save CR0 then disable cache (CRO.CD=1, CR0.NW=0) */
    cr0 = read_cr0();
    write_cr0((cr0 & ~CR0_NW) | CR0_CD);

    /* flush caches */
    wbinvd();

    /* save CR4 and disable global pages (CR4.PGE=0) */
    cr4 = read_cr4();
    write_cr4(cr4 & ~CR4_PGE);

    /* disable MTRRs */
    set_all_mtrrs(false);

    /*
     * now set MTRRs for AC mod and rest of memory
     */
    if ( !set_mem_type(hdr, hdr->size*4, MTRR_TYPE_WRBACK) )
        return false;

    /*
     * now undo some of earlier changes and enable our new settings
     */

    /* flush caches */
    wbinvd();

    /* enable MTRRs */
    set_all_mtrrs(true);

    /* restore CR0 (cacheing) */
    write_cr0(cr0);

    /* restore CR4 (global pages) */
    write_cr4(cr4);

    /* enable interrupts */
    write_eflags(eflags);

    return true;
}

void save_mtrrs(mtrr_state_t *saved_state)
{
    mtrr_cap_t mtrr_cap;

    /* IA32_MTRR_DEF_TYPE MSR */
    saved_state->mtrr_def_type.raw = rdmsr(MSR_MTRRdefType);

    /* number variable MTTRRs */
    mtrr_cap.raw = rdmsr(MSR_MTRRcap);
    if ( mtrr_cap.vcnt > MAX_VARIABLE_MTRRS ) {
        /* print warning but continue saving what we can */
        /* (set_mem_type() won't exceed the array, so we're safe doing this) */
        printk(TBOOT_WARN"actual # var MTRRs (%d) > MAX_VARIABLE_MTRRS (%d)\n",
               mtrr_cap.vcnt, MAX_VARIABLE_MTRRS);
        saved_state->num_var_mtrrs = MAX_VARIABLE_MTRRS;
    }
    else
        saved_state->num_var_mtrrs = mtrr_cap.vcnt;

    /* physmask's and physbase's */
    for ( unsigned int ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        saved_state->mtrr_physmasks[ndx].raw =
            rdmsr(MTRR_PHYS_MASK0_MSR + ndx*2);
        saved_state->mtrr_physbases[ndx].raw =
            rdmsr(MTRR_PHYS_BASE0_MSR + ndx*2);
    }

    g_saved_mtrrs = saved_state;
}

static void print_mtrrs(const mtrr_state_t *saved_state)
{
    printk(TBOOT_DETA"mtrr_def_type: e = %d, fe = %d, type = %x\n",
           saved_state->mtrr_def_type.e, saved_state->mtrr_def_type.fe,
           saved_state->mtrr_def_type.type );
    printk(TBOOT_DETA"mtrrs:\n");
    printk(TBOOT_DETA"\t\t    base          mask      type  v\n");
    for ( unsigned int i = 0; i < saved_state->num_var_mtrrs; i++ ) {
        printk(TBOOT_DETA"\t\t%13.13Lx %13.13Lx  %2.2x  %d\n",
               (uint64_t)saved_state->mtrr_physbases[i].base,
               (uint64_t)saved_state->mtrr_physmasks[i].mask,
               saved_state->mtrr_physbases[i].type,
               saved_state->mtrr_physmasks[i].v );
    }
}

/* base should be 4k-bytes aligned, no invalid overlap combination */
static int get_page_type(const mtrr_state_t *saved_state, uint32_t base)
{
    int type = -1;
    bool wt = false;
    uint64_t maxphyaddr_mask = get_maxphyaddr_mask();

    /* omit whether the fix mtrrs are enabled, just check var mtrrs */

    base >>= PAGE_SHIFT;
    for ( unsigned int i = 0; i < saved_state->num_var_mtrrs; i++ ) {
        const mtrr_physbase_t *base_i = &saved_state->mtrr_physbases[i];
        const mtrr_physmask_t *mask_i = &saved_state->mtrr_physmasks[i];

        if ( mask_i->v == 0 )
            continue;
        if ( (base & mask_i->mask & maxphyaddr_mask) !=
             (base_i->base & mask_i->mask & maxphyaddr_mask) )
            continue;

        type = base_i->type;
        if ( type == MTRR_TYPE_UNCACHABLE )
            return MTRR_TYPE_UNCACHABLE;
        if ( type == MTRR_TYPE_WRTHROUGH )
            wt = true;
    }
    if ( wt )
        return MTRR_TYPE_WRTHROUGH;
    if ( type != -1 )
        return type;

    return saved_state->mtrr_def_type.type;
}

static int get_region_type(const mtrr_state_t *saved_state,
                           uint32_t base, uint32_t pages)
{
    int type;
    uint32_t end;

    if ( pages == 0 )
        return MTRR_TYPE_MIXED;

    /* wrap the 4G address space */
    if ( ((uint32_t)(~0) - base) < (pages << PAGE_SHIFT) )
        return MTRR_TYPE_MIXED;

    if ( saved_state->mtrr_def_type.e == 0 )
        return MTRR_TYPE_UNCACHABLE;

    /* align to 4k page boundary */
    base &= PAGE_MASK;
    end = base + (pages << PAGE_SHIFT);

    type = get_page_type(saved_state, base);
    base += PAGE_SIZE;
    for ( ; base < end; base += PAGE_SIZE )
        if ( type != get_page_type(saved_state, base) )
            return MTRR_TYPE_MIXED;

    return type;
}

static bool validate_mmio_regions(const mtrr_state_t *saved_state)
{
    acpi_table_mcfg_t *acpi_table_mcfg;
    acpi_table_ioapic_t *acpi_table_ioapic;

    /* mmio space for TXT private config space should be UC */
    if ( get_region_type(saved_state, TXT_PRIV_CONFIG_REGS_BASE,
                         TXT_CONFIG_REGS_SIZE >> PAGE_SHIFT)
           != MTRR_TYPE_UNCACHABLE ) {
        printk(TBOOT_ERR"MMIO space for TXT private config space should be UC\n");
        return false;
    }

    /* mmio space for TXT public config space should be UC */
    if ( get_region_type(saved_state, TXT_PUB_CONFIG_REGS_BASE,
                         TXT_CONFIG_REGS_SIZE >> PAGE_SHIFT)
           != MTRR_TYPE_UNCACHABLE ) {
        printk(TBOOT_ERR"MMIO space for TXT public config space should be UC\n");
        return false;
    }

    /* mmio space for TPM should be UC */
    if ( get_region_type(saved_state, TPM_LOCALITY_BASE,
                         NR_TPM_LOCALITY_PAGES * TPM_NR_LOCALITIES)
           != MTRR_TYPE_UNCACHABLE ) {
        printk(TBOOT_ERR"MMIO space for TPM should be UC\n");
        return false;
    }

    /* mmio space for APIC should be UC */
    if ( get_region_type(saved_state, MMIO_APIC_BASE, NR_MMIO_APIC_PAGES)
           != MTRR_TYPE_UNCACHABLE ) {
        printk(TBOOT_ERR"MMIO space for APIC should be UC\n");
        return false;
    }

    /* TBD: is this check useful if we aren't DMA protecting ACPI? */
    /* mmio space for IOAPIC should be UC */
    acpi_table_ioapic = (acpi_table_ioapic_t *)get_acpi_ioapic_table();
    if ( acpi_table_ioapic == NULL) {
        printk(TBOOT_ERR"acpi_table_ioapic == NULL\n");
        return false;
    }
    printk(TBOOT_DETA"acpi_table_ioapic @ %p, .address = %x\n",
           acpi_table_ioapic, acpi_table_ioapic->address);
    if ( get_region_type(saved_state, acpi_table_ioapic->address,
                         NR_MMIO_IOAPIC_PAGES)
           != MTRR_TYPE_UNCACHABLE ) {
        printk(TBOOT_ERR"MMIO space(%x) for IOAPIC should be UC\n",
               acpi_table_ioapic->address);
        return false;
    }

    /* TBD: is this check useful if we aren't DMA protecting ACPI? */
    /* mmio space for PCI config space should be UC */
    acpi_table_mcfg = (acpi_table_mcfg_t *)get_acpi_mcfg_table();
    if ( acpi_table_mcfg == NULL) {
        printk(TBOOT_ERR"acpi_table_mcfg == NULL\n");
        return false;
    }
    printk(TBOOT_DETA"acpi_table_mcfg @ %p, .base_address = %x\n",
           acpi_table_mcfg, acpi_table_mcfg->base_address);
    if ( get_region_type(saved_state, acpi_table_mcfg->base_address,
                         NR_MMIO_PCICFG_PAGES)
           != MTRR_TYPE_UNCACHABLE ) {
        printk(TBOOT_ERR"MMIO space(%x) for PCI config space should be UC\n",
               acpi_table_mcfg->base_address);
        return false;
    }

    return true;
}

bool validate_mtrrs(const mtrr_state_t *saved_state)
{
    mtrr_cap_t mtrr_cap;
    uint64_t maxphyaddr_mask = get_maxphyaddr_mask();
    uint64_t max_pages = maxphyaddr_mask + 1;  /* max # 4k pages supported */

    /* check is meaningless if MTRRs were disabled */
    if ( saved_state->mtrr_def_type.e == 0 )
        return true;

    /* number variable MTRRs */
    mtrr_cap.raw = rdmsr(MSR_MTRRcap);
    if ( mtrr_cap.vcnt < saved_state->num_var_mtrrs ) {
        printk(TBOOT_ERR"actual # var MTRRs (%d) < saved # (%d)\n",
               mtrr_cap.vcnt, saved_state->num_var_mtrrs);
        return false;
    }

    /* variable MTRRs describing non-contiguous memory regions */
    for ( unsigned int ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        uint64_t tb;

        if ( saved_state->mtrr_physmasks[ndx].v == 0 )
            continue;

        for ( tb = 1; tb != max_pages; tb = tb << 1 ) {
            if ( (tb & saved_state->mtrr_physmasks[ndx].mask & maxphyaddr_mask)
                 != 0 )
                break;
        }
        for ( ; tb != max_pages; tb = tb << 1 ) {
            if ( (tb & saved_state->mtrr_physmasks[ndx].mask & maxphyaddr_mask)
                 == 0 )
                break;
        }
        if ( tb != max_pages ) {
	    printk(TBOOT_ERR"var MTRRs with non-contiguous regions: base=0x%Lx, mask=0x%Lx\n",
                   (uint64_t)saved_state->mtrr_physbases[ndx].base
                                  & maxphyaddr_mask,
                   (uint64_t)saved_state->mtrr_physmasks[ndx].mask
                                  & maxphyaddr_mask);
            print_mtrrs(saved_state);
            return false;
        }
    }

    /* overlaping regions with invalid memory type combinations */
    for ( unsigned int ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        const mtrr_physbase_t *base_ndx = &saved_state->mtrr_physbases[ndx];
        const mtrr_physmask_t *mask_ndx = &saved_state->mtrr_physmasks[ndx];

        if ( mask_ndx->v == 0 )
            continue;

        for ( unsigned int i = ndx + 1; i < saved_state->num_var_mtrrs; i++ ) {
            const mtrr_physbase_t *base_i = &saved_state->mtrr_physbases[i];
            const mtrr_physmask_t *mask_i = &saved_state->mtrr_physmasks[i];

            if ( mask_i->v == 0 )
                continue;

            if ( (base_ndx->base & mask_ndx->mask & mask_i->mask & maxphyaddr_mask)
                    != (base_i->base & mask_i->mask & maxphyaddr_mask) &&
                 (base_i->base & mask_i->mask & mask_ndx->mask & maxphyaddr_mask)
                    != (base_ndx->base & mask_ndx->mask & maxphyaddr_mask) )
                continue;

            if ( base_ndx->type == base_i->type )
                continue;
            if ( base_ndx->type == MTRR_TYPE_UNCACHABLE
                 || base_i->type == MTRR_TYPE_UNCACHABLE )
                continue;
            if ( base_ndx->type == MTRR_TYPE_WRTHROUGH
                 && base_i->type == MTRR_TYPE_WRBACK )
                continue;
            if ( base_ndx->type == MTRR_TYPE_WRBACK
                 && base_i->type == MTRR_TYPE_WRTHROUGH )
                continue;

            /* 2 overlapped regions have invalid mem type combination, */
            /* need to check whether there is a third region which has type */
            /* of UNCACHABLE and contains at least one of these two regions. */
            /* If there is, then the combination of these 3 region is valid */
            unsigned int j;
            for ( j = 0; j < saved_state->num_var_mtrrs; j++ ) {
                const mtrr_physbase_t *base_j
                        = &saved_state->mtrr_physbases[j];
                const mtrr_physmask_t *mask_j
                        = &saved_state->mtrr_physmasks[j];

                if ( mask_j->v == 0 )
                    continue;

                if ( base_j->type != MTRR_TYPE_UNCACHABLE )
                    continue;

                if ( (base_ndx->base & mask_ndx->mask & mask_j->mask & maxphyaddr_mask)
                        == (base_j->base & mask_j->mask & maxphyaddr_mask)
                     && (mask_j->mask & ~mask_ndx->mask & maxphyaddr_mask) == 0 )
                    break;

                if ( (base_i->base & mask_i->mask & mask_j->mask & maxphyaddr_mask)
                        == (base_j->base & mask_j->mask & maxphyaddr_mask)
                     && (mask_j->mask & ~mask_i->mask & maxphyaddr_mask) == 0 )
                    break;
            }
            if ( j < saved_state->num_var_mtrrs )
                continue;

            printk(TBOOT_ERR"var MTRRs overlaping regions, invalid type combinations\n");
            print_mtrrs(saved_state);
            return false;
        }
    }

    if ( !validate_mmio_regions(saved_state) ) {
        printk(TBOOT_ERR"Some mmio region should be UC type\n");
        print_mtrrs(saved_state);
        return false;
    }

    print_mtrrs(saved_state);
    return true;
}

void restore_mtrrs(const mtrr_state_t *saved_state)
{
    /* called by apply_policy() so use saved ptr */
    if ( saved_state == NULL )
        saved_state = g_saved_mtrrs;
    /* haven't saved them yet, so return */
    if ( saved_state == NULL )
        return;

    /* disable all MTRRs first */
    set_all_mtrrs(false);

    /* physmask's and physbase's */
    for ( unsigned int ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        wrmsr(MTRR_PHYS_MASK0_MSR + ndx*2,
              saved_state->mtrr_physmasks[ndx].raw);
        wrmsr(MTRR_PHYS_BASE0_MSR + ndx*2,
              saved_state->mtrr_physbases[ndx].raw);
    }

    /* IA32_MTRR_DEF_TYPE MSR */
    wrmsr(MSR_MTRRdefType, saved_state->mtrr_def_type.raw);
}

/*
 * set the memory type for specified range (base to base+size)
 * to mem_type and everything else to UC
 */
bool set_mem_type(const void *base, uint32_t size, uint32_t mem_type)
{
    int num_pages;
    int ndx;
    mtrr_def_type_t mtrr_def_type;
    mtrr_cap_t mtrr_cap;
    mtrr_physmask_t mtrr_physmask;
    mtrr_physbase_t mtrr_physbase;

    /*
     * disable all fixed MTRRs
     * set default type to UC
     */
    mtrr_def_type.raw = rdmsr(MSR_MTRRdefType);
    mtrr_def_type.fe = 0;
    mtrr_def_type.type = MTRR_TYPE_UNCACHABLE;
    wrmsr(MSR_MTRRdefType, mtrr_def_type.raw);

    /*
     * initially disable all variable MTRRs (we'll enable the ones we use)
     */
    mtrr_cap.raw = rdmsr(MSR_MTRRcap);
    for ( ndx = 0; ndx < mtrr_cap.vcnt; ndx++ ) {
        mtrr_physmask.raw = rdmsr(MTRR_PHYS_MASK0_MSR + ndx*2);
        mtrr_physmask.v = 0;
        wrmsr(MTRR_PHYS_MASK0_MSR + ndx*2, mtrr_physmask.raw);
    }

    /*
     * map all AC module pages as mem_type
     */

    num_pages = PAGE_UP(size) >> PAGE_SHIFT;
    ndx = 0;

    printk(TBOOT_DETA"setting MTRRs for acmod: base=%p, size=%x, num_pages=%d\n",
           base, size, num_pages);
    /*
     * Each VAR MTRR base must be a multiple if that MTRR's Size
    */
    unsigned long base_v;
    base_v = (unsigned long) base;
    int i =0;   
    // mtrr size in pages
    int mtrr_s = 1;
    while ((base_v & 0x01) == 0) {
          i++;
          base_v = base_v >>1 ;

    }
    for (int j=i-12; j>0; j--) mtrr_s =mtrr_s*2; //mtrr_s = mtrr_s << 1
    printk(TBOOT_DETA"The maximum allowed MTRR range size=%d Pages \n", mtrr_s);
	
    while (num_pages >= mtrr_s){
	
	/* set the base of the current MTRR */
        mtrr_physbase.raw = rdmsr(MTRR_PHYS_BASE0_MSR + ndx*2);
        mtrr_physbase.base = ((unsigned long)base >> PAGE_SHIFT) &
	                     SINIT_MTRR_MASK;
        mtrr_physbase.type = mem_type;
        wrmsr(MTRR_PHYS_BASE0_MSR + ndx*2, mtrr_physbase.raw);

        mtrr_physmask.raw = rdmsr(MTRR_PHYS_MASK0_MSR + ndx*2);
        mtrr_physmask.mask = ~(mtrr_s - 1) & SINIT_MTRR_MASK;
        mtrr_physmask.v = 1;
        wrmsr(MTRR_PHYS_MASK0_MSR + ndx*2, mtrr_physmask.raw);
		
        base += (mtrr_s * PAGE_SIZE);
        num_pages -= mtrr_s;
        ndx++;
        if ( ndx == mtrr_cap.vcnt ) {
            printk(TBOOT_ERR"exceeded number of var MTRRs when mapping range\n");
            return false;
        }
    }
    while ( num_pages > 0 ) {
        uint32_t pages_in_range;

        /* set the base of the current MTRR */
        mtrr_physbase.raw = rdmsr(MTRR_PHYS_BASE0_MSR + ndx*2);
        mtrr_physbase.base = ((unsigned long)base >> PAGE_SHIFT) &
	                     SINIT_MTRR_MASK;
        mtrr_physbase.type = mem_type;
        wrmsr(MTRR_PHYS_BASE0_MSR + ndx*2, mtrr_physbase.raw);

        /*
         * calculate MTRR mask
         * MTRRs can map pages in power of 2
         * may need to use multiple MTRRS to map all of region
         */
        pages_in_range = 1 << (fls(num_pages) - 1);

        mtrr_physmask.raw = rdmsr(MTRR_PHYS_MASK0_MSR + ndx*2);
        mtrr_physmask.mask = ~(pages_in_range - 1) & SINIT_MTRR_MASK;
        mtrr_physmask.v = 1;
        wrmsr(MTRR_PHYS_MASK0_MSR + ndx*2, mtrr_physmask.raw);

        /*prepare for the next loop depending on number of pages
         * We figure out from the above how many pages could be used in this
         * mtrr. Then we decrement the count, increment the base,
         * increment the mtrr we are dealing with, and if num_pages is
         * still not zero, we do it again.
         */
        base += (pages_in_range * PAGE_SIZE);
        num_pages -= pages_in_range;
        ndx++;
        if ( ndx == mtrr_cap.vcnt ) {
            printk(TBOOT_ERR"exceeded number of var MTRRs when mapping range\n");
            return false;
        }
    }
    return true;
}

/* enable/disable all MTRRs */
void set_all_mtrrs(bool enable)
{
    mtrr_def_type_t mtrr_def_type;

    mtrr_def_type.raw = rdmsr(MSR_MTRRdefType);
    mtrr_def_type.e = enable ? 1 : 0;
    wrmsr(MSR_MTRRdefType, mtrr_def_type.raw);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil * End:
 */
