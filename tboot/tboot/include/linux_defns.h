/*
 * linux_defns.h: Linux kernel type definitions
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

#ifndef __LINUX_DEFNS_H__
#define __LINUX_DEFNS_H__

#define SECTOR_SIZE (1 << 9)      /* 0x200 = 512B */

#define KERNEL_HEADER_OFFSET    0x1F1

/* linux kernel header */
typedef struct __attribute__ ((packed)) {
    uint8_t  setup_sects;    /* The size of the setup in sectors */
        #define DEFAULT_SECTOR_NUM   4   /* default sector number 4 */
        #define MAX_SECTOR_NUM       64  /* max sector number 64 */

    uint16_t root_flags;     /* If set, the root is mounted readonly */
    uint32_t syssize;        /* The size of the 32-bit code in 16-byte paras */
    uint16_t ram_size;       /* DO NOT USE - for bootsect.S use only */
    uint16_t vid_mode;       /* Video mode control */
    uint16_t root_dev;       /* Default root device number */
    uint16_t boot_flag;      /* 0xAA55 magic number */
    uint16_t jump;           /* Jump instruction */

    uint32_t header;         /* Magic signature "HdrS" */
        #define HDRS_MAGIC          0x53726448

    uint16_t version;        /* Boot protocol version supported */
    uint32_t realmode_swtch; /* Boot loader hook */
    uint16_t start_sys;      /* The load-low segment (0x1000) (obsolete) */
    uint16_t kernel_version; /* Points to kernel version string */

    uint8_t  type_of_loader; /* Boot loader identifier */
        #define LOADER_TYPE_LILO            0x01
        #define LOADER_TYPE_LOADLIN         0x10
        #define LOADER_TYPE_BOOTSECT_LOADER 0x20
        #define LOADER_TYPE_SYSLINUX        0x30
        #define LOADER_TYPE_ETHERBOOT       0x40
        #define LOADER_TYPE_ELILO           0x50
        #define LOADER_TYPE_GRUB            0x71
        #define LOADER_TYPE_U_BOOT          0x80
        #define LOADER_TYPE_XEN             0x90
        #define LOADER_TYPE_UNKNOWN         0xFF

    uint8_t  loadflags;      /* Boot protocol option flags */
        #define FLAG_LOAD_HIGH      0x01
        #define FLAG_CAN_USE_HEAP   0x80

    uint16_t setup_move_size;/* Move to high memory size (used with hooks) */
    uint32_t code32_start;   /* Boot loader hook */
    uint32_t ramdisk_image;  /* initrd load address (set by boot loader) */
    uint32_t ramdisk_size;   /* initrd size (set by boot loader) */
    uint32_t bootsect_kludge;/* DO NOT USE - for bootsect.S use only */
    uint16_t heap_end_ptr;   /* Free memory after setup end */
    uint8_t  ext_loader_ver; /* Boot Protocol: 2.02+ */
    uint8_t  ext_loader_type;/* Boot Protocol: 2.02+ */
    uint32_t cmd_line_ptr;   /* 32-bit pointer to the kernel command line */
    uint32_t initrd_addr_max;/* Highest legal initrd address */
    uint32_t kernel_alignment;         /* Physical addr alignment
                                          required for kernel */
    uint8_t  relocatable_kernel;       /* Whether kernel is relocatable
                                          or not */
    uint8_t  min_alignment;            /* Boot Protocol: 2.10+ */
    uint16_t xloadflags;               /* Boot Protocol: 2.12+ */  
    uint32_t cmdline_size;             /* Maximum size of the kernel
                                          command line */
    uint32_t hardware_subarch;         /* Hardware subarchitecture */
    uint64_t hardware_subarch_data;    /* Subarchitecture-specific data */
    uint32_t payload_offset;
    uint32_t payload_length;
    uint64_t setup_data;
    uint64_t pref_address;
    uint32_t init_size;
    uint32_t handover_offset;
} linux_kernel_header_t;

typedef struct __attribute__ ((packed)) {
    uint8_t               screen_info[0x040-0x000];                 /* 0x000 */
    uint8_t               apm_bios_info[0x054-0x040];               /* 0x040 */
    uint8_t               _pad2[4];                                 /* 0x054 */
    uint8_t               tboot_shared_addr[8];                     /* 0x058 */
    uint8_t               ist_info[0x070-0x060];                    /* 0x060 */
    uint8_t               _pad3[16];                                /* 0x070 */
    uint8_t               hd0_info[16];     /* obsolete! */         /* 0x080 */
    uint8_t               hd1_info[16];     /* obsolete! */         /* 0x090 */
    uint8_t               sys_desc_table[0x0b0-0x0a0];              /* 0x0a0 */
    uint8_t               _pad4[144];                               /* 0x0b0 */
    uint8_t               edid_info[0x1c0-0x140];                   /* 0x140 */
    uint8_t               efi_info[0x1e0-0x1c0];                    /* 0x1c0 */
    uint8_t               alt_mem_k[0x1e4-0x1e0];                   /* 0x1e0 */
    uint8_t               scratch[0x1e8-0x1e4];                     /* 0x1e4 */
    uint8_t               e820_entries;                             /* 0x1e8 */
    uint8_t               eddbuf_entries;                           /* 0x1e9 */
    uint8_t               edd_mbr_sig_buf_entries;                  /* 0x1ea */
    uint8_t               _pad6[6];                                 /* 0x1eb */
    linux_kernel_header_t hdr;    /* setup header */                /* 0x1f1 */
    uint8_t               _pad7[0x290-0x1f1-sizeof(linux_kernel_header_t)];
    uint8_t               edd_mbr_sig_buffer[0x2d0-0x290];          /* 0x290 */
    e820entry_t           e820_map[E820MAX];                        /* 0x2d0 */
    uint8_t               _pad8[48];                                /* 0xcd0 */
    uint8_t               eddbuf[0xeec-0xd00];                      /* 0xd00 */
    uint8_t               _pad9[276];                               /* 0xeec */
} boot_params_t;

typedef struct __attribute__ ((packed)) {
        u8  orig_x;                                                 /* 0x00 */
        u8  orig_y;                                                 /* 0x01 */
        u16 ext_mem_k;          /* extended memory size in kb */    /* 0x02 */
        u16 orig_video_page;                                        /* 0x04 */
        u8  orig_video_mode;    /* representing the specific mode
                                that was in effect when booting */  /* 0x06 */
        u8  orig_video_cols;                                        /* 0x07 */
        u16 unused2;                                                /* 0x08 */
        u16 orig_video_ega_bx;  /* video state and installed
                                memory */                           /* 0x0a */
        u16 unused3;                                                /* 0x0c */
        u8  orig_video_lines;                                       /* 0x0e */
        u8  orig_video_isVGA;   /* distinguish between VGA text
                                and vesa lfb based screen setups */ /* 0x0f */
        u16 orig_video_points;  /* font height */                   /* 0x10 */

        u16 lfb_width;												/* 0x12 */
        u16 lfb_height;												/* 0x14 */
        u16 lfb_depth;												/* 0x16 */
        u32 lfb_base;												/* 0x18 */
        u32 lfb_size;												/* 0x1c */
        
        u16 cl_magic;												/* 0x20 */
        u16 cl_offset;												/* 0x22 */

        u16 lfb_line_len;											/* 0x24 */
        u8  red_mask_size;											/* 0x26 */
        u8  red_field_pos;											/* 0x27 */
        u8  green_mask_size;										/* 0x28 */
        u8  green_field_pos;										/* 0x29 */
        u8  blue_mask_size;											/* 0x2a */
        u8  blue_field_pos;											/* 0x2b */
        u8  reserved_mask_size;										/* 0x2c */
        u8  reserved_field_pos;										/* 0x2d */
        u16 vesapm_segment;											/* 0x2e */
        u16 vesapm_offset;											/* 0x30 */
        u16 lfb_pages;												/* 0x32 */
        u16 vesa_attrib;											/* 0x34 */
        u32 capabilities;											/* 0x36 */
            #define VIDEO_CAPABILITY_64BIT_BASE	(1 << 1)	/* Frame buffer base is 64-bit. */
        u32 ext_lfb_base;											/* 0x3a */
        /* padding out to 0x40 */
} screen_info_t;

/* recommended layout
        |  Protected-mode kernel    |  The kernel protected-mode code.
100000  +---------------------------+
        |  I/O memory hole          |
0A0000  +---------------------------+
        |  Reserved for BIOS        |  Do not use.  Reserved for BIOS EBDA.
099100  +---------------------------+
        |  cmdline                  |
099000  +---------------------------+
        |  Stack/heap               |  For use by the kernel real-mode code.
098000  +---------------------------+
        |  Kernel setup             |  The kernel real-mode code.
090200  +---------------------------+
        |  Kernel boot sector       |  The kernel legacy boot sector.
090000  +---------------------------+
        |  Boot loader              |  <- Boot sector entry point 0000:7C00
001000  +---------------------------+
        |  Reserved for MBR/BIOS    |
000800  +---------------------------+
        |  Typically used by MBR    |
000600  +---------------------------+
        |  BIOS use only            |
000000  +---------------------------+
*/

#define BZIMAGE_PROTECTED_START 0x100000
#define LEGACY_REAL_START       0x90000

#define REAL_KERNEL_OFFSET      0x0000
#define BOOT_SECTOR_OFFSET      0x0200
#define KERNEL_CMDLINE_OFFSET   0x8D00
#define REAL_END_OFFSET         0x9100

#define REAL_MODE_SIZE          REAL_END_OFFSET - REAL_KERNEL_OFFSET

struct efi_info {
	uint32_t efi_ldr_sig;
	uint32_t efi_systable;
	uint32_t efi_memdescr_size;
	uint32_t efi_memdescr_ver;
	uint32_t efi_memmap;
	uint32_t efi_memmap_size;
	uint32_t efi_systable_hi;
	uint32_t efi_memmap_hi;
};



#endif /* __LINUX_DEFNS_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
