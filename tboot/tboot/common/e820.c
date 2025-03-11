/*
 * e820.c: support functions for manipulating the e820 table
 *
 * Copyright (c) 2006-2012, Intel Corporation
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
#include <cmdline.h>
#include <string.h>
#include <uuid.h>
#include <loader.h>
#include <stdarg.h>
#include <misc.h>
#include <pci_cfgreg.h>
#include <efi_memmap.h>
#include <e820.h>
#include <txt/config_regs.h>

/* minimum size of RAM (type 1) region that cannot be marked as reserved even
   if it comes after a reserved region; 0 for no minimum (i.e. current
   behavior) */
uint32_t g_min_ram = 0;

/*
 * copy of bootloader/BIOS e820 table with adjusted entries
 * this version will replace original in mbi
 */
#define MAX_E820_ENTRIES      (TBOOT_E820_COPY_SIZE / sizeof(memory_map_t))
static unsigned int g_nr_map;
static memory_map_t *g_copy_e820_map = (memory_map_t *)TBOOT_E820_COPY_ADDR;

static inline void split64b(uint64_t val, uint32_t *val_lo, uint32_t *val_hi)  {
     *val_lo = (uint32_t)(val & 0xffffffff); 
     *val_hi = (uint32_t)(val >> 32);
 }

static inline uint64_t combine64b(uint32_t val_lo, uint32_t val_hi)
{
    return ((uint64_t)val_hi << 32) | (uint64_t)val_lo;
}

static inline uint64_t e820_base_64(memory_map_t *entry)
{
    return combine64b(entry->base_addr_low, entry->base_addr_high);
}

static inline uint64_t e820_length_64(memory_map_t *entry)
{
    return combine64b(entry->length_low, entry->length_high);
}

static const char *e820_mem_type_to_str(uint32_t type)
{
    switch (type)
    {
    case E820_RAM:
        return "E820_RAM";
    case E820_RESERVED:
        return "E820_RESERVED";
    case E820_ACPI:
        return "E820_ACPI";
    case E820_NVS:
        return "E820_NVS";
    case E820_UNUSABLE:
        return "E820_UNUSABLE";
    case E820_PMEM:
        return "E820_PMEM";
    default:
        return "unknown type";
    }
}



/*
 * print_e820_map
 *
 * Prints copied e820 map w/o any header (i.e. just entries, indented by a tab)
 *
 */
static void print_map(memory_map_t *e820, int nr_map)
{
    for ( int i = 0; i < nr_map; i++ ) {
        memory_map_t *entry = &e820[i];
        uint64_t base_addr, length;

        base_addr = e820_base_64(entry);
        length = e820_length_64(entry);

        printk(TBOOT_DETA"\t%016Lx - %016Lx  (%d - %s)\n",
               (unsigned long long)base_addr,
               (unsigned long long)(base_addr + length),
               entry->type,
               e820_mem_type_to_str(entry->type));
    }
}

static bool insert_after_region(memory_map_t *e820map, unsigned int *nr_map,
                                unsigned int pos, uint64_t addr, uint64_t size,
                                uint32_t type)
{
    /* no more room */
    if ( *nr_map + 1 > MAX_E820_ENTRIES )
        return false;

    /* shift (copy) everything up one entry */
    for ( unsigned int i = *nr_map - 1; i > pos; i--)
        e820map[i+1] = e820map[i];

    /* now add our entry */
    split64b(addr, &(e820map[pos+1].base_addr_low),
             &(e820map[pos+1].base_addr_high));
    split64b(size, &(e820map[pos+1].length_low),
             &(e820map[pos+1].length_high));
    e820map[pos+1].type = type;
    e820map[pos+1].size = sizeof(memory_map_t) - sizeof(uint32_t);

    (*nr_map)++;

    return true;
}

static void remove_region(memory_map_t *e820map, unsigned int *nr_map,
                          unsigned int pos)
{
    /* shift (copy) everything down one entry */
    for ( unsigned int i = pos; i < *nr_map - 1; i++)
        e820map[i] = e820map[i+1];

    (*nr_map)--;
}

static bool protect_region(memory_map_t *e820map, unsigned int *nr_map,
                           uint64_t new_addr, uint64_t new_size,
                           uint32_t new_type)
{
    uint64_t addr, tmp_addr, size, tmp_size;
    uint32_t type;
    unsigned int i;

    if ( new_size == 0 )
        return true;
    /* check for wrap */
    if ( new_addr + new_size < new_addr )
        return false;

    /* find where our region belongs in the table and insert it */
    for ( i = 0; i < *nr_map; i++ ) {
        addr = e820_base_64(&e820map[i]);
        size = e820_length_64(&e820map[i]);
        type = e820map[i].type;
        /* is our region at the beginning of the current map region? */
        if ( new_addr == addr ) {
            if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                      new_type) )
                return false;
            break;
        }
        /* are we w/in the current map region? */
        else if ( new_addr > addr && new_addr < (addr + size) ) {
            if ( !insert_after_region(e820map, nr_map, i, new_addr, new_size,
                                      new_type) )
                return false;
            /* fixup current region */
            tmp_addr = e820_base_64(&e820map[i]);
            split64b(new_addr - tmp_addr, &(e820map[i].length_low),
                     &(e820map[i].length_high));
            i++;   /* adjust to always be that of our region */
            /* insert a copy of current region (before adj) after us so */
            /* that rest of code can be common with previous case */
            if ( !insert_after_region(e820map, nr_map, i, addr, size, type) )
                return false;
            break;
        }
        /* is our region in a gap in the map? */
        else if ( addr > new_addr ) {
            if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                      new_type) )
                return false;
            break;
        }
    }
    /* if we reached the end of the map without finding an overlapping */
    /* region, insert us at the end (note that this test won't trigger */
    /* for the second case above because the insert() will have incremented */
    /* nr_map and so i++ will still be less) */
    if ( i == *nr_map ) {
        if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                  new_type) )
            return false;
        return true;
    }

    i++;     /* move to entry after our inserted one (we're not at end yet) */

    tmp_addr = e820_base_64(&e820map[i]);
    tmp_size = e820_length_64(&e820map[i]);

    /* did we split the (formerly) previous region? */
    if ( (new_addr >= tmp_addr) &&
         ((new_addr + new_size) < (tmp_addr + tmp_size)) ) {
        /* then adjust the current region (adj size first) */
        split64b((tmp_addr + tmp_size) - (new_addr + new_size),
                 &(e820map[i].length_low), &(e820map[i].length_high));
        split64b(new_addr + new_size,
                 &(e820map[i].base_addr_low), &(e820map[i].base_addr_high));
        return true;
    }

    /* if our region completely covers any existing regions, delete them */
    while ( (i < *nr_map) && ((new_addr + new_size) >=
                              (tmp_addr + tmp_size)) ) {
        remove_region(e820map, nr_map, i);
        tmp_addr = e820_base_64(&e820map[i]);
        tmp_size = e820_length_64(&e820map[i]);
    }

    /* finally, if our region partially overlaps an existing region, */
    /* then truncate the existing region */
    if ( i < *nr_map ) {
        tmp_addr = e820_base_64(&e820map[i]);
        tmp_size = e820_length_64(&e820map[i]);
        if ( (new_addr + new_size) > tmp_addr ) {
            split64b((tmp_addr + tmp_size) - (new_addr + new_size),
                        &(e820map[i].length_low), &(e820map[i].length_high));
            split64b(new_addr + new_size, &(e820map[i].base_addr_low),
                        &(e820map[i].base_addr_high));
        }
    }

    return true;
}

/*
 * is_overlapped
 *
 * Detect whether two ranges are overlapped.
 *
 * return: true = overlapped
 */
static bool is_overlapped(uint64_t base, uint64_t end, uint64_t e820_base,
                          uint64_t e820_end)
{
    uint64_t length = end - base, e820_length = e820_end - e820_base;
    uint64_t min, max;

    min = (base < e820_base)?base:e820_base;
    max = (end > e820_end)?end:e820_end;

    /* overlapping */
    if ( (max - min) < (length + e820_length) )
        return true;

    if ( (max - min) == (length + e820_length)
         && ( ((length == 0) && (base > e820_base) && (base < e820_end))
              || ((e820_length == 0) && (e820_base > base) &&
                  (e820_base < end)) ) )
        return true;

    return false;
}

/* helper funcs for loader.c */
memory_map_t *get_e820_copy()
{
    return g_copy_e820_map;
}

unsigned int get_nr_map()
{
    return g_nr_map;
}

/*
 * copy_e820_map
 *
 * Copies the raw e820 map from bootloader to new table with room for expansion
 *
 * return:  false = error (no table or table too big for new space)
 */
bool copy_e820_map(loader_ctx *lctx)
{
    get_tboot_min_ram();

    g_nr_map = 0;

    if (have_loader_memmap(lctx)){
        uint32_t memmap_length = get_loader_memmap_length(lctx);
        memory_map_t *memmap = get_loader_memmap(lctx);
        //printk(TBOOT_DETA"original e820 map:\n");
        //print_map(memmap, memmap_length/sizeof(memory_map_t));

        uint32_t entry_offset = 0;

        while ( entry_offset < memmap_length &&
                g_nr_map < MAX_E820_ENTRIES ) {
            memory_map_t *entry = (memory_map_t *)
                (((uint32_t) memmap) + entry_offset);

            /* we want to support unordered and/or overlapping entries */
            /* so use protect_region() to insert into existing map, since */
            /* it handles these cases */
            if ( !protect_region(g_copy_e820_map, &g_nr_map,
                                 e820_base_64(entry), e820_length_64(entry),
                                 entry->type) )
                return false;
            if (lctx->type == 1)
                entry_offset += entry->size + sizeof(entry->size);
            if (lctx->type == 2)
                /* the MB2 memory map entries don't have a size--
                 * they have a "zero" with a value of zero. Additionally,
                 * because they *end* with a size and the MB1 guys *start*
                 * with a size, we get into trouble if we try to use them,
                 */
                entry_offset += sizeof(memory_map_t);

        }
        if ( g_nr_map == MAX_E820_ENTRIES ) {
            printk(TBOOT_ERR"Too many e820 entries\n");
            return false;
        }
    }
    else if ( have_loader_memlimits(lctx) ) {
        printk(TBOOT_DETA"no e820 map, mem_lower=%x, mem_upper=%x\n",
               get_loader_mem_lower(lctx), get_loader_mem_upper(lctx));

        /* lower limit is 0x00000000 - <mem_lower>*0x400 (i.e. in kb) */
        g_copy_e820_map[0].base_addr_low = 0;
        g_copy_e820_map[0].base_addr_high = 0;
        g_copy_e820_map[0].length_low = (get_loader_mem_lower(lctx)) << 10;
        g_copy_e820_map[0].length_high = 0;
        g_copy_e820_map[0].type = E820_RAM;
        g_copy_e820_map[0].size = sizeof(memory_map_t) - sizeof(uint32_t);

        /* upper limit is 0x00100000 - <mem_upper>*0x400 */
        g_copy_e820_map[1].base_addr_low = 0x100000;
        g_copy_e820_map[1].base_addr_high = 0;
        split64b((uint64_t)(get_loader_mem_upper(lctx)) << 10,
                 &(g_copy_e820_map[1].length_low),
                 &(g_copy_e820_map[1].length_high));
        g_copy_e820_map[1].type = E820_RAM;
        g_copy_e820_map[1].size = sizeof(memory_map_t) - sizeof(uint32_t);

        g_nr_map = 2;
    }
    else {
        printk(TBOOT_ERR"no e820 map nor memory limits provided\n");
        return false;
    }

    return true;
}

bool e820_protect_region(uint64_t addr, uint64_t size, uint32_t type)
{
    return protect_region(g_copy_e820_map, &g_nr_map, addr, size, type);
}

/*
 * e820_check_region
 *
 * Given a range, check which kind of range it covers
 *
 * return: E820_GAP, it covers gap in e820 map;
 *         E820_MIXED, it covers at least two different kinds of ranges;
 *         E820_XXX, it covers E820_XXX range only;
 *         it will not return 0.
 */
uint32_t e820_check_region(uint64_t base, uint64_t length)
{
    memory_map_t* e820_entry;
    uint64_t end = base + length, e820_base, e820_end, e820_length;
    uint32_t type;
    uint32_t ret = 0;
    bool gap = true; /* suppose there is always a virtual gap at first */

    e820_base = 0;
    e820_length = 0;

    for ( unsigned int i = 0; i < g_nr_map; i = gap ? i : i+1, gap = !gap ) {
        e820_entry = &g_copy_e820_map[i];
        if ( gap ) {
            /* deal with the gap in e820 map */
            e820_base = e820_base + e820_length;
            e820_length = e820_base_64(e820_entry) - e820_base;
            type = E820_GAP;
        }
        else {
            /* deal with the normal item in e820 map */
            e820_base = e820_base_64(e820_entry);
            e820_length = e820_length_64(e820_entry);
            type = e820_entry->type;
        }

        if ( e820_length == 0 )
            continue; /* if the range is zero, then skip */

        e820_end = e820_base + e820_length;

        if ( !is_overlapped(base, end, e820_base, e820_end) )
            continue; /* if no overlapping, then skip */

        /* if the value of ret is not assigned before,
           then set ret to type directly */
        if ( ret == 0 ) {
            ret = type;
            continue;
        }

        /* if the value of ret is assigned before but ret is equal to type,
           then no need to do anything */
        if ( ret == type )
            continue;

        /* if the value of ret is assigned before but it is GAP,
           then no need to do anything since any type merged with GAP is GAP */
        if ( ret == E820_GAP )
            continue;

        /* if the value of ret is assigned before but it is not GAP and type
           is GAP now this time, then set ret to GAP since any type merged
           with GAP is GAP. */
        if ( type == E820_GAP ) {
            ret = E820_GAP;
            continue;
        }

        /* if the value of ret is assigned before but both ret and type are
           not GAP and their values are not equal, then set ret to MIXED
           since any two non-GAP values are merged into MIXED if they are
           not equal. */
        ret = E820_MIXED;
    }

    /* deal with the last gap */
    if ( is_overlapped(base, end, e820_base + e820_length, (uint64_t)-1) )
        ret = E820_GAP;

    /* print the result */
    printk(TBOOT_DETA" (range from %016Lx to %016Lx is in ", base, base + length);
    switch (ret) {
        case E820_RAM:
            printk(TBOOT_INFO"E820_RAM)\n"); break;
        case E820_RESERVED:
            printk(TBOOT_INFO"E820_RESERVED)\n"); break;
        case E820_ACPI:
            printk(TBOOT_INFO"E820_ACPI)\n"); break;
        case E820_NVS:
            printk(TBOOT_INFO"E820_NVS)\n"); break;
        case E820_UNUSABLE:
            printk(TBOOT_INFO"E820_UNUSABLE)\n"); break;
        case E820_GAP:
            printk(TBOOT_INFO"E820_GAP)\n"); break;
        case E820_MIXED:
            printk(TBOOT_INFO"E820_MIXED)\n"); break;
        default:
            printk(TBOOT_INFO"UNKNOWN)\n");
    }

    return ret;
}

/*
 * e820_reserve_ram
 *
 * Given the range, any ram range in e820 is in it, change type to reserved.
 *
 * return:  false = error
 */
bool e820_reserve_ram(uint64_t base, uint64_t length)
{
    memory_map_t* e820_entry;
    uint64_t e820_base, e820_length, e820_end;
    uint64_t end;

    if ( length == 0 )
        return true;

    end = base + length;

    /* find where our region should cover the ram in e820 */
    for ( unsigned int i = 0; i < g_nr_map; i++ ) {
        e820_entry = &g_copy_e820_map[i];
        e820_base = e820_base_64(e820_entry);
        e820_length = e820_length_64(e820_entry);
        e820_end = e820_base + e820_length;

        /* if not ram, no need to deal with */
        if ( e820_entry->type != E820_RAM )
            continue;

        /* if the range is before the current ram range, skip the ram range */
        if ( end <= e820_base )
            continue;
        /* if the range is after the current ram range, skip the ram range */
        if ( base >= e820_end )
            continue;

        /* case 1: the current ram range is within the range:
           base, e820_base, e820_end, end */
        if ( (base <= e820_base) && (e820_end <= end) )
            e820_entry->type = E820_RESERVED;
        /* case 2: overlapping:
           base, e820_base, end, e820_end */
        else if ( (e820_base >= base) && (end > e820_base) &&
                  (e820_end > end) ) {
            /* split the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i-1,
                                      e820_base, (end - e820_base),
                                      E820_RESERVED) )
                return false;
            /* fixup the current ram map */
            i++;
            split64b(end, &(g_copy_e820_map[i].base_addr_low),
                     &(g_copy_e820_map[i].base_addr_high));
            split64b(e820_end - end, &(g_copy_e820_map[i].length_low),
                     &(g_copy_e820_map[i].length_high));
            /* no need to check more */
            break;
        }
        /* case 3: overlapping:
           e820_base, base, e820_end, end */
        else if ( (base > e820_base) && (e820_end > base) &&
                  (end >= e820_end) ) {
            /* fixup the current ram map */
            split64b((base - e820_base), &(g_copy_e820_map[i].length_low),
                     &(g_copy_e820_map[i].length_high));
            /* split the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i, base,
                                      (e820_end - base), E820_RESERVED) )
                return false;
            i++;
        }
        /* case 4: the range is within the current ram range:
           e820_base, base, end, e820_end */
        else if ( (base > e820_base) && (e820_end > end) ) {
            /* fixup the current ram map */
            split64b((base - e820_base), &(g_copy_e820_map[i].length_low),
                     &(g_copy_e820_map[i].length_high));
            /* split the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i, base,
                                      length, E820_RESERVED) )
                return false;
            i++;
            /* fixup the rest of the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i, end,
                                      (e820_end - end), e820_entry->type) )
                return false;
            i++;
            /* no need to check more */
            break;
        }
        else {
            printk(TBOOT_ERR"we should never get here\n");
            return false;
        }
    }

    return true;
}

void print_e820_map(void)
{
    print_map(g_copy_e820_map, g_nr_map);
}

bool get_ram_ranges(uint64_t *min_lo_ram, uint64_t *max_lo_ram,
                    uint64_t *min_hi_ram, uint64_t *max_hi_ram)
{
    if ( min_lo_ram == NULL || max_lo_ram == NULL ||
         min_hi_ram == NULL || max_hi_ram == NULL )
        return false;

    *min_lo_ram = *min_hi_ram = ~0ULL;
    *max_lo_ram = *max_hi_ram = 0;
    bool found_reserved_region = false;
    uint64_t last_min_ram_base = 0, last_min_ram_size = 0;

    /* 
     * if g_min_ram > 0, we will never mark a region > g_min_ram in size
     * as reserved even if it is after a reserved region (effectively
     * we ignore reserved regions below the last type 1 region
     * > g_min_ram in size)
     * so in order to reserve RAM regions above this last region, we need
     * to find it first so that we can tell when we have passed it
     */
    if ( g_min_ram > 0 ) {
        e820_get_highest_sized_ram(g_min_ram, 0x100000000ULL,
                                   &last_min_ram_base, &last_min_ram_size);
        printk(TBOOT_DETA"highest min_ram (0x%x) region found: base=0x%Lx, size=0x%Lx\n",
               g_min_ram, last_min_ram_base, last_min_ram_size);
    }

    for ( unsigned int i = 0; i < g_nr_map; i++ ) {
        memory_map_t *entry = &g_copy_e820_map[i];
        uint64_t base = e820_base_64(entry);
        uint64_t limit = base + e820_length_64(entry);

        if ( entry->type == E820_RAM ) {
            /* if range straddles 4GB boundary, that is an error */
            if ( base < 0x100000000ULL && limit > 0x100000000ULL ) {
                printk(TBOOT_ERR"e820 memory range straddles 4GB boundary\n");
                return false;
            }

            /*
             * some BIOSes put legacy USB buffers in reserved regions <4GB,
             * which if DMA protected cause SMM to hang, so make sure that
             * we don't overlap any of these even if that wastes RAM
             * ...unless min_ram was specified
             */
            if ( !found_reserved_region || base <= last_min_ram_base ) {
                if ( base < 0x100000000ULL && base < *min_lo_ram )
                    *min_lo_ram = base;
                if ( limit <= 0x100000000ULL && limit > *max_lo_ram )
                    *max_lo_ram = limit;
            }
            else {     /* need to reserve low RAM above reserved regions */
                if ( base < 0x100000000ULL ) {
                    printk(TBOOT_DETA"discarding RAM above reserved regions: 0x%Lx - 0x%Lx\n", base, limit);
                    if ( !e820_reserve_ram(base, limit - base) )
                        return false;
                    if (!efi_memmap_reserve(base, limit - base)) {
                        return false;
                    }
                }
            }

            if ( base >= 0x100000000ULL && base < *min_hi_ram )
                *min_hi_ram = base;
            if ( limit > 0x100000000ULL && limit > *max_hi_ram )
                *max_hi_ram = limit;
        }
        else {
            /* parts of low memory may be reserved for cseg, ISA hole,
               etc. but these seem OK to DMA protect, so ignore reserved
               regions <0x100000 */
            if ( *min_lo_ram != ~0ULL && limit > 0x100000ULL )
                found_reserved_region = true;
        }
    }

    /* no low RAM found */
    if ( *min_lo_ram >= *max_lo_ram ) {
        printk(TBOOT_ERR"no low ram in e820 map\n");
        return false;
    }
    /* no high RAM found */
    if ( *min_hi_ram >= *max_hi_ram )
        *min_hi_ram = *max_hi_ram = 0;

    return true;
}

/* find highest (< <limit>) RAM region of at least <size> bytes */
bool e820_get_highest_sized_ram(uint64_t size, uint64_t limit,
                                uint64_t *ram_base, uint64_t *ram_size)
{
    uint64_t last_fit_base = 0, last_fit_size = 0;

    if ( ram_base == NULL || ram_size == NULL )
        return false;

    for ( unsigned int i = 0; i < g_nr_map; i++ ) {
        memory_map_t *entry = &g_copy_e820_map[i];

        if ( entry->type == E820_RAM ) {
            uint64_t base = e820_base_64(entry);
            uint64_t length = e820_length_64(entry);

            /* over 4GB so use the last region that fit */
            if ( base + length > limit )
                break;
            if ( size <= length ) {
                last_fit_base = base;
                last_fit_size = length;
            }
        }
    }

    if (last_fit_size == 0) {
        return false;
    } else {
        *ram_base = last_fit_base;
        *ram_size = last_fit_size;
        return true;
    }
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
