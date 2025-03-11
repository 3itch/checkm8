/*
 * paging.c: enable PAE paging and map pages in tboot
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <stdbool.h>
#include <types.h>
#include <compiler.h>
#include <printk.h>
#include <processor.h>
#include <tb_error.h>
#include <paging.h>
#include <misc.h>
#include <string.h>

/* Page-Directory-Pointer Table */
uint64_t __attribute__ ((__section__ (".bss.page_aligned")))
    pdptr_table[TB_L2_PAGETABLE_ENTRIES];

/* Page Directory */
uint64_t __attribute__ ((__section__ (".bss.page_aligned")))
    pd_table[4*TB_L1_PAGETABLE_ENTRIES];

extern char _start[];
extern char _end[];

extern void apply_policy(tb_error_t error);

static uint64_t *get_pdptre(unsigned long virt)
{
    return pdptr_table + pdptr_table_offset(virt);
}

/* get the Page-Directory Entry according to the virtual address */
static uint64_t *get_pde(unsigned long virt)
{
    unsigned long pdptr_tab_offset;
    uint64_t *ppde, *ppdptre;
    uint64_t *p;

    ppdptre = get_pdptre(virt);

    if ( !(get_pdptre_flags(*ppdptre) & _PAGE_PRESENT) ) {
        /* If not present, create Page Directory */
        pdptr_tab_offset = pdptr_table_offset(virt);

        p = pd_table + pdptr_tab_offset * TB_L1_PAGETABLE_ENTRIES;
        tb_memset(p, 0, sizeof(uint64_t) * TB_L1_PAGETABLE_ENTRIES);
        *ppdptre = MAKE_TB_PDPTE((unsigned long)p);
    }

    ppde = (uint64_t *)(unsigned long)get_pdptre_paddr(*ppdptre);
    ppde += pd_table_offset(virt);

    return ppde;
}

static inline void flush_tlb(void)
{
    write_cr3(read_cr3());
}

/*
 * map 2-Mbyte pages to tboot:
 * tboot pages are mapped into DIRECTMAP_VIRT_START ~ DIRECTMAP_VIRT_END;
 * other pages for MACing are mapped into MAC_VIRT_START ~ MAC_VIRT_END.
 */
void map_pages_to_tboot(unsigned long vstart,
                        unsigned long pfn,
                        unsigned long nr_pfns)
{
    uint64_t start, end;
    uint64_t *ppde;

    start = (uint64_t)pfn << TB_L1_PAGETABLE_SHIFT;
    end = (uint64_t)(pfn + nr_pfns) << TB_L1_PAGETABLE_SHIFT;

    do {
        ppde = get_pde(vstart);
        *ppde = MAKE_TB_PDE(start);
        start += MAC_PAGE_SIZE;
        vstart += MAC_PAGE_SIZE;
    } while ( start < end );

    flush_tlb();
}

/* map tboot pages into tboot */
static void map_tboot_pages(unsigned long pfn, unsigned long nr_pfns)
{
    uint64_t start, end;

    start = (uint64_t)pfn << TB_L1_PAGETABLE_SHIFT;
    end = (uint64_t)(pfn + nr_pfns) << TB_L1_PAGETABLE_SHIFT;

    /* older gcc versions don't understand '#pragma GCC diagnostic ignored'
       and thus won't disable the 'unsinged comparison against 0' warning,
       so assert that DIRECTMAP_VIRT_START == 0 and then we don't need to
       compare 'start >= DIRECTMAP_VIRT_START' */
    COMPILE_TIME_ASSERT(DIRECTMAP_VIRT_START == 0);
    if ( end > DIRECTMAP_VIRT_END ) {
        printk(TBOOT_ERR"0x%llx ~ 0x%llx cannot be mapped as direct map\n", start, end);
        disable_paging();
        apply_policy(TB_ERR_FATAL);
    }

    map_pages_to_tboot(start, pfn, nr_pfns);
}

/* destroy the map */
void destroy_tboot_mapping(unsigned long vstart, unsigned long vend)
{
    unsigned long virt;
    uint64_t *ppdptre, *ppde;

    if (((vstart & ~MAC_PAGE_MASK) == 0 ) || ((vend & ~MAC_PAGE_MASK) == 0 ))
        return;

    virt = vstart;
    while ( virt < vend ) {
        ppdptre = get_pdptre(virt);

        if ( !(get_pdptre_flags(*ppdptre) & _PAGE_PRESENT) ) {
            virt += 1UL << TB_L2_PAGETABLE_SHIFT;
            virt &= ~((1UL << TB_L2_PAGETABLE_SHIFT) - 1);
            continue;
        }

        ppde = get_pde(virt);
        if ( get_pde_flags(*ppde) & _PAGE_PRESENT )
            *ppde = 0;

        virt += MAC_PAGE_SIZE;
        virt &= MAC_PAGE_MASK;
    }

    flush_tlb();
}

static unsigned long build_directmap_pagetable(void)
{
    unsigned int i;
    uint64_t *ppdptre;
    unsigned long tboot_spfn, tboot_epfn;

    tb_memset(pdptr_table, 0, sizeof(pdptr_table));
    tb_memset(pd_table, 0, sizeof(pd_table));

    for ( i = 0; i < ARRAY_SIZE(pd_table)/TB_L1_PAGETABLE_ENTRIES; i++ ) {
        ppdptre = &pdptr_table[i];
        *ppdptre = MAKE_TB_PDPTE((unsigned long)(
                      pd_table + i * TB_L1_PAGETABLE_ENTRIES));
    }

    /* map serial log address ~ kernel command address */
    tboot_spfn = (unsigned long)TBOOT_SERIAL_LOG_ADDR >> TB_L1_PAGETABLE_SHIFT;
    tboot_epfn = ((unsigned long)(TBOOT_KERNEL_CMDLINE_ADDR
                     + TBOOT_KERNEL_CMDLINE_SIZE + MAC_PAGE_SIZE - 1))
                     >> TB_L1_PAGETABLE_SHIFT;
    map_tboot_pages(tboot_spfn, tboot_epfn - tboot_spfn);

    /* map tboot */
    tboot_spfn = (unsigned long)&_start >> TB_L1_PAGETABLE_SHIFT;
    tboot_epfn = ((unsigned long)&_end + MAC_PAGE_SIZE - 1)
                     >> TB_L1_PAGETABLE_SHIFT;
    map_tboot_pages(tboot_spfn, tboot_epfn - tboot_spfn);

    return (unsigned long)pdptr_table;
}

static unsigned long cr0, cr4;

bool enable_paging(void)
{
    unsigned long eflags;

    /* disable interrupts */
    eflags = read_eflags();
    disable_intr();

    /* flush caches */
    wbinvd();

    /* save old cr0 & cr4 */
    cr0 = read_cr0();
    cr4 = read_cr4();

    write_cr4((cr4 | CR4_PAE | CR4_PSE) & ~CR4_PGE);

    write_cr3(build_directmap_pagetable());
    write_cr0(cr0 | CR0_PG);

    /* enable interrupts */
    write_eflags(eflags);

    return (read_cr0() & CR0_PG);
}

bool disable_paging(void)
{
    /* restore cr0 & cr4 */
    write_cr0(cr0);
    write_cr4(cr4);

    return !(read_cr0() & CR0_PG);
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

