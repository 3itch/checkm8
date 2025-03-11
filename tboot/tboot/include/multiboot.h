/*
 * multiboot.h:  definitions for the multiboot bootloader specification
 *
 * Copyright (c) 2013, Intel Corporation
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

#ifndef __MULTIBOOT_H__
#define __MULTIBOOT_H__

#include <config.h>

/* Multiboot2 tag alignment. */
#define MULTIBOOT2_TAG_ALIGN        8

/* Multiboot Header Definitions of OS image*/
#define MULTIBOOT_HEADER_MAGIC			0x1BADB002
#define MULTIBOOT_HEADER_SEARCH_LIMIT 8192

/* Bit definitions of flags field of multiboot header*/
#define MULTIBOOT_HEADER_MODS_ALIGNED	0x1
#define MULTIBOOT_HEADER_WANT_MEMORY	0x2

/* bit definitions of flags field of multiboot information */
#define MBI_MEMLIMITS    (1<<0)
#define MBI_BOOTDEV      (1<<1)
#define MBI_CMDLINE      (1<<2)
#define MBI_MODULES      (1<<3)
#define MBI_AOUT         (1<<4)
#define MBI_ELF          (1<<5)
#define MBI_MEMMAP       (1<<6)
#define MBI_DRIVES       (1<<7)
#define MBI_CONFIG       (1<<8)
#define MBI_BTLDNAME     (1<<9)
#define MBI_APM          (1<<10)
#define MBI_VBE          (1<<11)

/* multiboot 2 constants */
#define MB2_HEADER_MAGIC		0xe85250d6
#define MB2_LOADER_MAGIC		0x36d76289
#define MB2_HEADER_SEARCH_LIMIT 32768

#define MB2_ARCH_X86  0

#define MB2_HDR_TAG_END               0
#define MB2_HDR_TAG_INFO_REQ		  1
#define MB2_HDR_TAG_ADDR			  2
#define MB2_HDR_TAG_ENTRY_ADDR		  3
#define MB2_HDR_TAG_CONSOLE_FLAGS	  4
#define MB2_HDR_TAG_FRAMEBUFFER		  5
#define MB2_HDR_TAG_MOD_ALIGN		  6

#define MB2_HDR_TAG_REQUIRED      0
#define MB2_HDR_TAG_OPTIONAL		  1

#define MB2_CONS_FLAGS_CONS_REQ		  1
#define MB2_CONS_FLAGS_EGA_TEXT_SUP	  2


#define MB2_TAG_TYPE_END 			  0
#define MB2_TAG_TYPE_CMDLINE          1
#define MB2_TAG_TYPE_LOADER_NAME      2
#define MB2_TAG_TYPE_MODULE           3
#define MB2_TAG_TYPE_MEMLIMITS        4
#define MB2_TAG_TYPE_BOOTDEV          5
#define MB2_TAG_TYPE_MMAP             6
#define MB2_TAG_TYPE_VBE              7
#define MB2_TAG_TYPE_FRAMEBUFFER      8
#define MB2_TAG_TYPE_ELF_SECTIONS     9
#define MB2_TAG_TYPE_APM              10
#define MB2_TAG_TYPE_EFI32            11
#define MB2_TAG_TYPE_EFI64            12
#define MB2_TAG_TYPE_SMBIOS           13
#define MB2_TAG_TYPE_ACPI_OLD         14
#define MB2_TAG_TYPE_ACPI_NEW         15
#define MB2_TAG_TYPE_NETWORK          16
#define MB2_TAG_TYPE_EFI_MMAP         17
#define MB2_TAG_TYPE_EFI_BS           18

#ifndef __ASSEMBLY__

/* mb2 header flags */
struct mb2_hdr_tag_info_req
{
  uint16_t type;
  uint16_t flags;
  uint32_t size;
  uint32_t requests[0];
};

struct mb2_hdr_tag_addr
{
  uint16_t type;
  uint16_t flags;
  uint32_t size;
  uint32_t header_addr;
  uint32_t load_addr;
  uint32_t load_end_addr;
  uint32_t bss_end_addr;
};

struct mb2_hdr_tag_entry_addr
{
  uint16_t type;
  uint16_t flags;
  uint32_t size;
  uint32_t entry_addr;
};

struct mb2_hdr_tag_console_flags
{
  uint16_t type;
  uint16_t flags;
  uint32_t size;
  uint32_t console_flags;
};

struct mb2_hdr_tag_framebuffer
{
  uint16_t type;
  uint16_t flags;
  uint32_t size;
  uint32_t width;
  uint32_t height;
  uint32_t depth;
};

struct mb2_hdr_tag_mod_align
{
  uint16_t type;
  uint16_t flags;
  uint32_t size;
  uint32_t width;
  uint32_t height;
  uint32_t depth;
};

/* MB2 info tags */

struct mb2_tag
{
  uint32_t type;
  uint32_t size;
};

struct mb2_tag_string
{
  uint32_t type;
  uint32_t size;
  char string[0];
};

struct mb2_tag_memlimits
{
  uint32_t type;
  uint32_t size;
  uint32_t mem_lower;
  uint32_t mem_upper;
};

struct mb2_tag_bootdev
{
  uint32_t type;
  uint32_t size;
  uint32_t biosdev;
  uint32_t slice;
  uint32_t part;
};

struct mb2_mmap_entry
{
  uint64_t addr;
  uint64_t len;
#define MULTIBOOT_MEMORY_AVAILABLE		1
#define MULTIBOOT_MEMORY_RESERVED		2
#define MULTIBOOT_MEMORY_ACPI_RECLAIMABLE       3
#define MULTIBOOT_MEMORY_NVS                    4
#define MULTIBOOT_MEMORY_BADRAM                 5
  uint32_t type;
  uint32_t zero;
} __attribute__((packed));

struct mb2_tag_mmap
{
  uint32_t type;
  uint32_t size;
  uint32_t entry_size;
  uint32_t entry_version;
  struct mb2_mmap_entry entries[0];  
};

struct mb2_tag_module
{
  uint32_t type;
  uint32_t size;
  uint32_t mod_start;
  uint32_t mod_end;
  char cmdline[0];
};

struct mb2_tag_old_acpi
{
  uint32_t type;
  uint32_t size;
  uint8_t rsdp[0];
};

struct mb2_tag_new_acpi
{
  uint32_t type;
  uint32_t size;
  uint8_t rsdp[0];
};

struct mb2_tag_efi32
{
  uint32_t type;
  uint32_t size;
  uint32_t pointer;
};

struct mb2_tag_efi64
{
  uint32_t type;
  uint32_t size;
  uint64_t pointer;
};

struct mb2_tag_network
{
  uint32_t type;
  uint32_t size;
  uint8_t dhcpack[0];
};

struct mb2_tag_smbios
{
  uint32_t type;
  uint32_t size;
  uint8_t major;
  uint8_t minor;
  uint8_t reserved[6];
  uint8_t tables[0];
};

struct mb2_tag_elf_sections
{
  uint32_t type;
  uint32_t size;
  uint32_t num;
  uint32_t entsize;
  uint32_t shndx;
  char sections[0];
};

struct mb2_tag_apm
{
  uint32_t type;
  uint32_t size;
  uint16_t version;
  uint16_t cseg;
  uint32_t offset;
  uint16_t cseg_16;
  uint16_t dseg;
  uint16_t flags;
  uint16_t cseg_len;
  uint16_t cseg_16_len;
  uint16_t dseg_len;
};

struct mb2_vbe_info_block
{
  uint8_t external_specification[512];
};

struct mb2_vbe_mode_info_block
{
  uint8_t external_specification[256];
};

struct mb2_tag_vbe
{
  uint32_t type;
  uint32_t size;

  uint16_t vbe_mode;
  uint16_t vbe_interface_seg;
  uint16_t vbe_interface_off;
  uint16_t vbe_interface_len;

  struct mb2_vbe_info_block vbe_control_info;
  struct mb2_vbe_mode_info_block vbe_mode_info;
};

struct mb2_tag_efi_mmap
{
    uint32_t type;
    uint32_t size;
    uint32_t descr_size;
    uint32_t descr_vers;
    uint8_t efi_mmap[0];
};



struct mb2_fb_common
{
  uint32_t type;
  uint32_t size;

  uint64_t fb_addr;
  uint32_t fb_pitch;
  uint32_t fb_width;
  uint32_t fb_height;
  uint8_t fb_bpp;
#define MB2_FB_TYPE_INDEXED 0
#define MB2_FB_TYPE_RGB     1
#define MB2_FB_TYPE_EGA_TEXT	2
  uint8_t fb_type;
  uint16_t reserved;
};

struct mb2_color
{
  uint8_t red;
  uint8_t green;
  uint8_t blue;
};

struct mb2_fb
{
  struct mb2_fb_common common;

  union
  {
    struct
    {
      uint16_t fb_palette_num_colors;
      struct mb2_color fb_palette[0];
    };
    struct
    {
      uint8_t fb_red_field_position;
      uint8_t fb_red_mask_size;
      uint8_t fb_green_field_position;
      uint8_t fb_green_mask_size;
      uint8_t fb_blue_field_position;
      uint8_t fb_blue_mask_size;
    };
  };
};

/* MB1 */
typedef struct {
    uint32_t tabsize;
    uint32_t strsize;
    uint32_t addr;
    uint32_t reserved;
} aout_t; /* a.out kernel image */

typedef struct {
    uint32_t num;
    uint32_t size;
    uint32_t addr;
    uint32_t shndx;
} elf_t; /* elf kernel */

typedef struct {
    uint8_t bios_driver;
    uint8_t top_level_partition;
    uint8_t sub_partition;
    uint8_t third_partition;
} boot_device_t;

typedef struct {
    uint32_t flags;

    /* valid if flags[0] (MBI_MEMLIMITS) set */
    uint32_t mem_lower;
    uint32_t mem_upper;

    /* valid if flags[1] set */
    boot_device_t boot_device;

    /* valid if flags[2] (MBI_CMDLINE) set */
    uint32_t cmdline;

    /* valid if flags[3] (MBI_MODS) set */
    uint32_t mods_count;
    uint32_t mods_addr;

    /* valid if flags[4] or flags[5] set */
    union {
        aout_t aout_image;
        elf_t  elf_image;
    } syms;

    /* valid if flags[6] (MBI_MEMMAP) set */
    uint32_t mmap_length;
    uint32_t mmap_addr;

    /* valid if flags[7] set */
    uint32_t drives_length;
    uint32_t drives_addr;

    /* valid if flags[8] set */
    uint32_t config_table;

    /* valid if flags[9] set */
    uint32_t boot_loader_name;

    /* valid if flags[10] set */
    uint32_t apm_table;

    /* valid if flags[11] set */
    uint32_t vbe_control_info;
    uint32_t vbe_mode_info;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
} multiboot_info_t;

typedef struct {
	uint32_t mod_start;
	uint32_t mod_end;
	uint32_t string;
	uint32_t reserved;
} module_t;

typedef struct {
	uint32_t size;
	uint32_t base_addr_low;
	uint32_t base_addr_high;
	uint32_t length_low;
	uint32_t length_high;
	uint32_t type;
} memory_map_t;


#endif /* __ASSEMBLY__ */

#endif /* __MULTIBOOT_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
