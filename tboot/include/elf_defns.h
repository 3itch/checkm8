/*
 * elf_defns.h: ELF file type definitions
 *
 * Copyright (c) 2006-2007, Intel Corporation
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

#ifndef __ELF_DEFNS_H__
#define __ELF_DEFNS_H__

/* Elf header */
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsz;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf_header_t;

/* elf64_header_t */
typedef struct {
unsigned char e_ident[16]; /* ELF identification */
uint16_t e_type; /* Object file type */
uint16_t e_machine; /* Machine type */
uint32_t e_version; /* Object file version */
uint64_t e_entry; /* Entry point address */
uint64_t e_phoff; /* Program header offset */
uint64_t e_shoff; /* Section header offset */
uint32_t e_flags; /* Processor-specific flags */
uint16_t e_ehsize; /* ELF header size */
uint16_t e_phentsize; /* Size of program header entry */
uint16_t e_phnum; /* Number of program header entries */
uint16_t e_shentsize; /* Size of section header entry */
uint16_t e_shnum; /* Number of section header entries */
uint16_t e_shstrndx; /* Section name string table index */
} elf64_header_t;






/* e_ident[] Identification Indexes */
#define EI_MAG0        0         /* File identification */
#define EI_MAG1        1         /* File identification */
#define EI_MAG2        2         /* File identification */
#define EI_MAG3        3         /* File identification */
#define EI_CLASS       4         /* File class */
#define EI_DATA        5         /* Data encoding */
#define EI_VERSION     6         /* File version */
#define EI_PAD         7         /* Start of padding bytes */
#define EI_NIDENT      8         /* Size of e_ident[] */

/* Magic number */
#define ELFMAG0        0x7f      /* e_ident[EI_MAG0] */
#define ELFMAG1        'E'       /* e_ident[EI_MAG1] */
#define ELFMAG2        'L'       /* e_ident[EI_MAG2] */
#define ELFMAG3        'F'       /* e_ident[EI_MAG3] */

/* e_ident[EI_CLASS] */
#define ELFCLASSNONE   0         /* Invalid class */
#define ELFCLASS32     1         /* 32-bit objects */
#define ELFCLASS64     2         /* 64-bit objects */

/* e_ident[EI_DATA] */
#define ELFDATANONE    0         /* Invalid data encoding */
#define ELFDATA2LSB    1         /* Least significant byte */
#define ELFDATA2MSB    2         /* Most significant byte */

/* e_type */
#define ET_NONE        0         /* No file type */
#define ET_REL         1         /* Relocatable file */
#define ET_EXEC        2         /* Executable file */
#define ET_DYN         3         /* Shared object file */
#define ET_CORE        4         /* Core file */
#define ET_LOPROC      0xff00    /* Processor-specific */
#define ET_HIPROC      0xffff    /* Processor-specific */

/* e_machine */
#define ET_NONE        0         /* No machine */
#define EM_M32         1         /* At&t We 32100 */
#define EM_SPARC       2         /* SPARC */
#define EM_386         3         /* Intel architecture */
#define EM_68K         4         /* Motorola 68000 */
#define EM_88K         5         /* Motorola 88000 */
#define EM_860         7         /* Intel 80860 */
#define EM_MIPS        8         /* MIPS RS3000 Big-Endian */
#define EM_MIPS_RS4_BE 10        /* MIPS RS4000 Big-Endian */
#define EM_AMD64	62		/* AMDs x86-64 architecture */

/* e_version */
#define EV_NONE        0         /* Invalid version */
#define EV_CURRENT     1         /* Current version */

/* Program header */
typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf_program_header_t;

typedef struct{
uint32_t p_type; /* Type of segment */
uint32_t p_flags; /* Segment attributes */
uint64_t p_offset; /* Offset in file */
uint64_t p_vaddr; /* Virtual address in memory */
uint64_t p_paddr; /* Reserved */
uint64_t p_filesz; /* Size of segment in file */
uint64_t p_memsz; /* Size of segment in memory */
uint64_t p_align; /* Alignment of segment */
} elf64_program_header_t;

/* p_type */
#define PT_NULL        0
#define PT_LOAD        1
#define PT_DYNAMIC     2
#define PT_INTERP      3
#define PT_NOTE        4
#define PT_SHLIB       5
#define PT_PHDR        6
#define PT_LOPROC      0x70000000
#define PT_HIPROC      0x7fffffff

/* multiboot magic */
#define MB_MAGIC       0x2badb002

#endif /* __ELF_DEFNS_H__ */



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
