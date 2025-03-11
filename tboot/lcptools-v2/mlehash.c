/*
 * mlehash.c: tool to determine the hash of a Intel(R) TXT MLE
 *
 * Copyright (c) 2006-2014, Intel Corporation
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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <zlib.h>
#include <memory.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "../include/elf_defns.h"
#include "../include/mle.h"
#include "lcputils.h"


#define TOOL_VER_MAJOR 0x1
#define TOOL_VER_MINOR 0x1

#define MAX_HELP_TEXT       4096
static char help[MAX_HELP_TEXT] =
    "Usage: lcp2_mlehash <COMMAND> [OPTION]\n"
    "Create an Intel(R) TXT policy mlehash.\n"
    "--create\n"
    "       --cmdline <cmdline> cmdline\n"
    "       --alg <sha1|sha256|sha384|sha512> hashalg   "
    "--help                 print out help message\n"
    "--verbose              display progress indications.\n"
    "--version              show tool version.\n";


bool        verbose = false;
char        alg_name[32] = "sha256";
uint16_t    alg_type = TPM_ALG_SHA256;

static struct option long_opts[] =
{
    /* commands */
    {"help",           no_argument,          NULL,     'H'},
    {"version",        no_argument,          NULL,     'V'},
    {"create",         no_argument,          NULL,     'C'},

    /* options */
    {"cmdline",        required_argument,    NULL,     'c'},
    {"alg",            required_argument,    NULL,     'a'},
    {"verbose",        no_argument,          (int *)&verbose, true},
    {0, 0, 0, 0}
};

/*
 * is_elf_image
 *
 * check an image is elf or not?
 *
 */
static bool is_elf_image(const void *image, const size_t size)
{
    LOG("[is_elf_image]\n");
    elf_header_t *elf;

    LOG("checking whether image is an elf image ... ");
    if ( image == NULL ) {
        LOG(": failed! - Pointer is zero.\n");
        return false;
    }

    /* check size */
    if ( sizeof(elf_header_t) > size ) {
        LOG(": failed! - Image size is smaller than ELF header size.\n");
        return false;
    }

    elf = (elf_header_t *)image;

    /* check magic number for ELF */
    if (( elf->e_ident[EI_MAG0] != ELFMAG0 )
            || ( elf->e_ident[EI_MAG1] != ELFMAG1 )
            || ( elf->e_ident[EI_MAG2] != ELFMAG2 )
            || ( elf->e_ident[EI_MAG3] != ELFMAG3 )) {
        LOG(": failed! - ELF magic number is not matched.\n");
        return false;
    }

    /* check data encoding in ELF */
    if ( elf->e_ident[EI_DATA] != ELFDATA2LSB ) {
        LOG(": failed! - ELF data encoding is not the least significant "
                "byte occupying the lowest address.\n");
        return false;
    }

    /* check ELF image is executable? */
    if ( elf->e_type != ET_EXEC ) {
        LOG(": failed! - ELF image is not executable.\n");
        return false;
    }

    /* check ELF image is for IA? */
    if ( elf->e_machine != EM_386 ) {
        LOG(": failed! - ELF image is not for IA.\n");
        return false;
    }

    /* check ELF version is valid? */
    if ( elf->e_version != EV_CURRENT ) {
        LOG(": failed! - ELF version is invalid.\n");
        return false;
    }

    if ( sizeof(elf_program_header_t) > elf->e_phentsize ) {
        LOG(": failed! - Program size is smaller than program "
                "header size.\n");
        return false;
    }

    LOG(": succeeded!\n");
    return true;
}

static bool get_elf_image_range(const elf_header_t *elf,
        void **start, void **end)
{
    LOG("[get_elf_image_range]\n");
    int i;
    unsigned long u_start, u_end;

    if (elf == NULL) {
        LOG("Error: ELF header pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    if ((start == NULL) || (end == NULL)) {
        LOG("Error: Output pointers are zero.\n");
        return false;
    }

    u_start = 0;
    u_end = 0;
    for (i = 0; i < elf->e_phnum; i++) {
        elf_program_header_t *ph = (elf_program_header_t *)
            ((void *)elf + elf->e_phoff + i*elf->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            if (u_start > ph->p_paddr)
                u_start = ph->p_paddr;
            if (u_end < ph->p_paddr+ph->p_memsz)
                u_end = ph->p_paddr+ph->p_memsz;
        }
    }

    if (u_start >= u_end) {
        *start = NULL;
        *end = NULL;
        return false;
    }
    else {
        *start = (void *)u_start;
        *end = (void *)u_end;
        LOG("get range succeed!\n");
        return true;
    }
}

/*
 *
 * expand entire file into memory
 *
 */
static bool expand_elf_image(const elf_header_t *elf, void *base, size_t size)
{
    int i;

    LOG("[expand_elf_image]\n");
    LOG("expanding elf image ... ");
    if ( elf == NULL ) {
        LOG(": failed! - ELF header pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    /* load elf image into memory */
    for (i = 0; i < elf->e_phnum; i++) {
        elf_program_header_t *ph = (elf_program_header_t *)
            ((void *)elf + elf->e_phoff + i*elf->e_phentsize);

        if (ph->p_type == PT_LOAD) {
            if ( ph->p_memsz > size ) {
                LOG("expanded image exceeded allocated size\n");
                return false;
            }
            memcpy_s(base, size, (void *)elf + ph->p_offset, ph->p_filesz);
            memset_s(base + ph->p_filesz, ph->p_memsz - ph->p_filesz, 0);
            base += ph->p_memsz;
            size -= ph->p_memsz;
        }
    }

    LOG(": succeeded!.\n");
    return true;
}

/*
 * print_dump
 *
 * dump the memory
 *
 */
#if 0
#define log_info(fmt, ...)     verbose ? printf(fmt, ##__VA_ARGS__) : 0

static void print_dump(uint32_t s, uint32_t e)
{
    uint32_t i,j;
    unsigned char* p;
    for ( i = s, j = 0; i < e; i++, j++ ) {
        p = (unsigned char*)i;
        log_info("%02x ", *p);
        if ( j % 20 == 0 )
            log_info("\n");
    }
    log_info("\n");
}
#endif

/*
 * read_mle_file
 *
 * read file from disk, if compressed, uncompress it
 *
 */
static bool read_mle_file(const char *filename, void **buffer, size_t *length)
{
    LOG("[read_mle_file]\n");
    gzFile fcompressed = NULL;
    FILE *fdecompressed = NULL;
    struct stat filestat;
    char tmpbuffer[1024];
    unsigned long i;

    *length = 0;
    *buffer = NULL;

    /* check the file exists or not */
    LOG("checking whether the file exists or not ... ");
    if ( stat(filename, &filestat))
        goto error;
    LOG(": existed!\n");

    /* try uncompress the file (gzopen will handle uncompressed files too) */
    LOG("trying to uncompress the file ... ");
    fcompressed = gzopen(filename, "rb");
    if ( !fcompressed ) {
        LOG(": failed!\n");
        return false;
    }
    LOG(": succeeded!\n");

    LOG("creating a temporary file to uncompress ... ");
    fdecompressed = tmpfile();
    if ( !fdecompressed )
        goto error;
    LOG(": succeeded!\n");

    LOG("opening the decompressed file ... ");
    while ( !gzeof(fcompressed) ) {
        i = gzread(fcompressed, tmpbuffer, 1024);
        *length += i;
        if ( fwrite(tmpbuffer, 1, i, fdecompressed) != i )
            goto error;
    }
    LOG(": succeeded!\n");
    gzclose(fcompressed);
    fcompressed = NULL;

    LOG("testing decompression is ... ");
    if ( *length <= 0 ) 
        goto error;
    LOG(": succeeded!\n");
    /* uncompression succeeded */
    fseek(fdecompressed, 0, SEEK_SET);

    /* read file into buffer */
    LOG("reading the decompressed file ... ");
    *buffer = malloc(*length);
    if ( *buffer == NULL )
        goto error;
    memset_s(*buffer, *length, 0);
    if ( fread(*buffer, 1, *length, fdecompressed) != *length )
        goto error2;
    fclose(fdecompressed);
    LOG(": succeeded!\n");
    return true;

error:
    if ( *buffer )
        free( *buffer );

error2:
    LOG(": failed!\n");
    if ( fcompressed )
        gzclose(fcompressed);
    if ( fdecompressed )
        fclose(fdecompressed);
    return false;
}

static mle_hdr_t *find_mle_hdr(void *start, size_t size)
{
    LOG("[find_mle_hdr]\n");
    void *end;

    end = start + size - sizeof(uuid_t);
    while ( start <= end ) {
        if ( are_uuids_equal((const uuid_t *)start, &((uuid_t)MLE_HDR_UUID)) ){
            LOG("find mle hdr succeed!\n");
            return (mle_hdr_t *)start;
        }
        start += sizeof(uuid_t);
    }
    return NULL;
}

/*
 * main
 */
int main(int argc, char* argv[])
{
    void *elf_start=NULL, *elf_end=NULL;
    void *exp_start=NULL;
    void *base=NULL;
    size_t size, exp_size;
    elf_header_t *base_as_elf;
    mle_hdr_t *mle_hdr;
    int c, ret = 1;
    char mle_file[MAX_PATH] = "";
    extern int optind;    /* current index of get_opt() */
    char *cmdline = NULL;
    bool prev_cmd = false;
    int cmd = 0;

    while ((c = getopt_long_only(argc, (char ** const)argv,
                        "", long_opts, NULL)) != -1) {
        switch (c) {
        case 'H':
        case 'C':
        case 'V':
            if ( prev_cmd ) {
                ERROR("Error: only one command can be specified\n");
                return 1;
            }
            prev_cmd = true;
            cmd = c;
            LOG("cmdline opt: command: %c\n", cmd);
            break;

        case 'c':
            cmdline = malloc(strnlen_s(optarg, 4096) + 1);
            if ( cmdline == NULL ) {
                printf("Out of memory\n");
                return 1;
            }
            strcpy_s(cmdline, strnlen_s(optarg, 4096) + 1, optarg);
            break;

        case 'a':
            strlcpy(alg_name, optarg, sizeof(alg_name));
            LOG("cmdline opt: alg: %s\n",alg_name);
            break;

        case 0:
        case -1:
            break;

        default:
            printf("Unknown command line option\n");
            break;
        }
    }

    if ( optind < argc ) {
        LOG("cmdline opt: mlefile:%s\n", argv[optind]);
        strlcpy(mle_file,argv[optind],sizeof(mle_file));
    }

    if ( cmd == 0 ) {
        ERROR("Error: no command was specified\n");
        goto out;
    }
    else if ( cmd == 'H' ) {           /* --help */
        DISPLAY("%s", help);
        ret = 0;
        goto out;
    }
    else if ( cmd == 'C' ) {    
        if ( *mle_file == '\0' ) {
            ERROR("Error: no output file specified\n");
            goto out;
        }
        alg_type = str_to_hash_alg(alg_name);

        /* read file */
        if ( !read_mle_file(mle_file, &base, &size) )
            goto out;

        /* expand image */
        if ( !is_elf_image(base, size) )
            goto out;
        base_as_elf = (elf_header_t *)base;

        /* get expanded size and allocate memory for it */
        if ( !get_elf_image_range(base_as_elf, &elf_start, &elf_end) )
            goto out;
        exp_size = elf_end - elf_start;
        exp_start = malloc(exp_size);
        if ( exp_start == NULL ) {
            LOG("not enough memory for expanded image\n");
            goto out;
        }

        /* expand the image */
        if ( !expand_elf_image(base_as_elf, exp_start, exp_size) )
            goto out;

        /* find the MLE header in the expanded image */
        mle_hdr = find_mle_hdr(exp_start, exp_size);
        if ( mle_hdr == NULL ) {
            LOG("no MLE header found in image\n");
            goto out;
        }

        /* before hashing, find command line area in MLE then zero-fill and copy
           command line param to it */
        if ( mle_hdr->cmdline_end_off > mle_hdr->cmdline_start_off &&
                cmdline != NULL ) {
            memset_s(exp_start + mle_hdr->cmdline_start_off,
                    mle_hdr->cmdline_end_off - mle_hdr->cmdline_start_off, '\0');
            strcpy_s(exp_start + mle_hdr->cmdline_start_off,
                     mle_hdr->cmdline_end_off - mle_hdr->cmdline_start_off,
                     cmdline);
        }

        /* hash the MLE portion of the image */
        LOG("begin to hash (%s) the mle portion of the image\n", alg_name);
        size_t hash_size = mle_hdr->mle_end_off - mle_hdr->mle_start_off;
        void *hash_buf = exp_start + mle_hdr->mle_start_off;
        lcp_hash_t2 *hash = malloc(sizeof(lcp_hash_t2));
        hash_buffer(hash_buf, hash_size, (tb_hash_t *)hash, alg_type);
        print_hash((tb_hash_t *)hash, alg_type);
    }

    else if ( cmd == 'V' ) /* --version */ {
        DISPLAY("lcp2_mlehash version: %i.%i", TOOL_VER_MAJOR,
                                               TOOL_VER_MINOR);
        ret = 0;
        goto out;
    }

    ret = 0;

out:
    if (cmdline)
        free(cmdline);
    if (base)
        free(base);
    if (exp_start)
        free(exp_start);
    return ret;
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
