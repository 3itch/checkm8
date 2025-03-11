/*
 * e820.h: support functions for manipulating the e820 table
 *
 * Copyright (c) 2006-2009, Intel Corporation
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

#ifndef __E820_H__
#define __E820_H__

#ifndef E820_RAM
#define E820_RAM            1
#endif

#ifndef E820_RESERVED
#define E820_RESERVED       2
#endif

#ifndef E820_ACPI
#define E820_ACPI           3
#endif

#ifndef E820_NVS
#define E820_NVS            4
#endif

#ifndef E820_UNUSABLE
#define E820_UNUSABLE       5
#endif

#ifndef E820_PMEM
#define E820_PMEM           7
#endif

/* these are only used by e820_check_region() */
#define E820_MIXED          ((uint32_t)-1 - 1)
#define E820_GAP            ((uint32_t)-1)

#define E820MAX             128

typedef struct __packed {
    uint64_t addr;    /* start of memory segment */
    uint64_t size;    /* size of memory segment */
    uint32_t type;    /* type of memory segment */
} e820entry_t;

typedef struct {
	uint32_t type;
	uint32_t pad;
	uint64_t phys_addr;
	uint64_t virt_addr;
	uint64_t num_pages;
	uint64_t attribute;
} efi_memory_desc_t;

extern memory_map_t *get_e820_copy(void);
extern unsigned int get_nr_map(void);
extern bool copy_e820_map(loader_ctx *lctx);
extern bool e820_protect_region(uint64_t addr, uint64_t size, uint32_t type);
extern bool e820_reserve_ram(uint64_t base, uint64_t length);
extern void print_e820_map(void);
extern uint32_t e820_check_region(uint64_t base, uint64_t length);
extern bool get_ram_ranges(uint64_t *min_lo_ram, uint64_t *max_lo_ram,
                           uint64_t *min_hi_ram, uint64_t *max_hi_ram);
extern bool e820_get_highest_sized_ram(uint64_t size, uint64_t limit,
                                       uint64_t *ram_base, uint64_t *ram_size);

#endif    /* __E820_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
