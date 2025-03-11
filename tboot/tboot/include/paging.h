/*
 * paging.h: Definitions for paging in tboot (PAE+PSE)
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

#ifndef __PAGING_H__
#define __PAGING_H__

/* direct map starts from 0, size 128M */
#define DIRECTMAP_VIRT_START	0
#define DIRECTMAP_VIRT_ORDER	27
#define DIRECTMAP_VIRT_SIZE	(1UL << DIRECTMAP_VIRT_ORDER)
#define DIRECTMAP_VIRT_END	(DIRECTMAP_VIRT_START + DIRECTMAP_VIRT_SIZE)

/* MAC window starts from 0x80000000, size 1G */
#define MAC_VIRT_START		0x80000000
#define MAC_VIRT_ORDER		30
#define MAC_VIRT_SIZE		(1UL << MAC_VIRT_ORDER)
#define MAC_VIRT_END		(MAC_VIRT_START + MAC_VIRT_SIZE)

/* PAE with 2-Mbyte Pages */
#define TB_PAGETABLE_ORDER		9
#define TB_L1_PAGETABLE_ENTRIES		(1 << TB_PAGETABLE_ORDER)
#define TB_L2_PAGETABLE_ENTRIES		(1 << TB_PAGETABLE_ORDER)

#define TB_L1_PAGETABLE_SHIFT		21
#define TB_L2_PAGETABLE_SHIFT		30

#define MAC_PAGE_SIZE			(1UL << TB_L1_PAGETABLE_SHIFT)
#define MAC_PAGE_MASK			(~(MAC_PAGE_SIZE - 1))

#define _PAGE_PRESENT                   0x01
#define _PAGE_RW			0x02
#define _PAGE_SIZE			0x80


#define MAKE_TB_PDE(paddr)	\
	(((uint64_t)(paddr) & ~0x00000000001FFFFF) | _PAGE_PRESENT \
			| _PAGE_RW | _PAGE_SIZE)
#define MAKE_TB_PDPTE(paddr)	\
	(((uint64_t)(paddr) & ~0x0000000000000FFF) | _PAGE_PRESENT)

/* Given a virtual address, get an entry offset into a page table. */
#define pd_table_offset(a)	\
	(((a) >> TB_L1_PAGETABLE_SHIFT) & (TB_L1_PAGETABLE_ENTRIES - 1))
#define pdptr_table_offset(a)	\
	(((a) >> TB_L2_PAGETABLE_SHIFT) & (TB_L2_PAGETABLE_ENTRIES - 1))

/* PAE: 52 bit physical address */
#define PADDR_BIT			52
#define PADDR_MASK			((1ULL << PADDR_BIT) - 1)

/*
 * PDE entry
 * 31-bit pfn = pde[51:21]
 * 13-bit flags = pde[12:0]
 */
#define PDE_FLAG_BIT			13
#define PDE_FLAG_MASK			((1UL << PDE_FLAG_BIT) - 1)
#define PDE_PADDR_MASK			(PADDR_MASK & (~PDE_FLAG_MASK))
#define get_pde_flags(pde)		((int)(pde) & PDE_FLAG_MASK)
#define get_pde_paddr(pde)		((pde) & PDE_PADDR_MASK)

/*
 * PDPTE entry
 * 40-bit pfn = pdptre[51:12]
 * 12-bit flags = pdptre[11:0]
 */
#define PDPTE_FLAG_BIT			12
#define PDPTE_FLAG_MASK			((1UL << PDPTE_FLAG_BIT) - 1)
#define PDPTE_PADDR_MASK		(PADDR_MASK & (~PDPTE_FLAG_MASK))
#define get_pdptre_flags(pdptre)	((int)(pdptre) & PDPTE_FLAG_MASK)
#define get_pdptre_paddr(pdptre)	((pdptre) & PDPTE_PADDR_MASK)

void map_pages_to_tboot(unsigned long vstart,
                        unsigned long pfn,
                        unsigned long nr_pfns);
void destroy_tboot_mapping(unsigned long vstart, unsigned long vend);
bool enable_paging(void);
bool disable_paging(void);

#endif /* __PAGING_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
