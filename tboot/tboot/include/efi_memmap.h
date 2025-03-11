/*
 * efi_memmap.h: EFI memory map parsing functions
 *
 * Copyright (c) 2006-2020, Intel Corporation
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

#ifndef _EFI_MEMMAP_H_
#define _EFI_MEMMAP_H_

#include <types.h>
#include <config.h>

/* Memory types: */
#define EFI_RESERVED_TYPE               0
#define EFI_LOADER_CODE                 1
#define EFI_LOADER_DATA                 2
#define EFI_BOOT_SERVICES_CODE          3
#define EFI_BOOT_SERVICES_DATA          4
#define EFI_RUNTIME_SERVICES_CODE       5
#define EFI_RUNTIME_SERVICES_DATA       6
#define EFI_CONVENTIONAL_MEMORY         7
#define EFI_UNUSABLE_MEMORY             8
#define EFI_ACPI_RECLAIM_MEMORY         9
#define EFI_ACPI_MEMORY_NVS             10
#define EFI_MEMORY_MAPPED_IO            11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                    13
#define EFI_PERSISTENT_MEMORY           14
#define EFI_MAX_MEMORY_TYPE             15

/* Attribute values: */
#define EFI_MEMORY_UC      ((u64)0x0000000000000001ULL)	/* uncached */
#define EFI_MEMORY_WC      ((u64)0x0000000000000002ULL)	/* write-coalescing */
#define EFI_MEMORY_WT      ((u64)0x0000000000000004ULL)	/* write-through */
#define EFI_MEMORY_WB      ((u64)0x0000000000000008ULL)	/* write-back */
#define EFI_MEMORY_WP      ((u64)0x0000000000001000ULL)	/* write-protect */
#define EFI_MEMORY_RP      ((u64)0x0000000000002000ULL)	/* read-protect */
#define EFI_MEMORY_XP      ((u64)0x0000000000004000ULL)	/* execute-protect */
#define EFI_MEMORY_RUNTIME ((u64)0x8000000000000000ULL)	/* requires runtime mapping */
#define EFI_MEMORY_DESCRIPTOR_VERSION 1

#define EFI_PAGE_SHIFT 12
#define EFI_MEMMAP_MAX_ENTRIES 682 /* limited by TBOOT_EFI_MEMMAP_COPY_SIZE */

typedef struct __packed
{
    uint32_t size;
    uint32_t descr_size;
    uint8_t  descr[0]; /**< array of efi_mem_descr_t,
                            each element has descr_size bytes */
} efi_memmap_t;

typedef struct __packed
{
    uint32_t type;
    uint32_t padding;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t num_pages;
    uint64_t attribute;
} efi_mem_descr_t;

bool efi_memmap_copy(loader_ctx *lctx);
uint32_t efi_memmap_get_addr(uint32_t *descr_size, uint32_t *descr_vers,
                             uint32_t *mmap_size);
efi_mem_descr_t* efi_memmap_walk(efi_mem_descr_t* prev);
bool efi_memmap_is_free(uint32_t region_type);
bool efi_memmap_reserve(uint64_t base, uint64_t length);
bool efi_memmap_get_highest_sized_ram(uint64_t size, uint64_t limit,
                                      uint64_t *ram_base, uint64_t *ram_size);
void efi_memmap_dump(void);

#endif