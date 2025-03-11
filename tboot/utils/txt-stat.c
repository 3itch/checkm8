/*
 * txt-stat: Linux app that will display various information about
 *           the status of TXT.
 *
 * Copyright (c) 2006-2011, Intel Corporation
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

#include <features.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>
#include <safe_lib.h>

#define printk   printf
#include "../include/config.h"
#include "../include/uuid.h"
#include "../include/tboot.h"

#define IS_INCLUDED    /* disable some codes in included files */
static inline uint64_t read_config_reg(uint32_t config_regs_base, uint32_t reg);
#include "../tboot/include/txt/config_regs.h"
typedef uint8_t mtrr_state_t;
typedef uint8_t txt_caps_t;
typedef uint8_t multiboot_info_t;
void print_hex(const char* prefix, const void *start, size_t len);
#include "../include/hash.h"
#include "../tboot/include/txt/heap.h"
#include "../tboot/txt/heap.c"
#include "../tboot/include/lz.h"
#include "../tboot/common/lz.c"

static inline uint64_t read_txt_config_reg(void *config_regs_base,
                                           uint32_t reg)
{
    /* these are MMIO so make sure compiler doesn't optimize */
    return *(volatile uint64_t *)(config_regs_base + reg);
}

static inline const char * bit_to_str(uint64_t b)
{
    return b ? "TRUE" : "FALSE";
}

void print_hex(const char* prefix, const void *start, size_t len)
{
    const void *end = start + len;
    while ( start < end ) {
        printf("%s", prefix);
        for ( int i = 0; i < 16; i++ ) {
            if ( start < end )
                printf("%02x ", *(uint8_t *)start);
            start++;
        }
        printf("\n");
    }
}

void print_hash(const tb_hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL ) {
        printk("NULL");
        return;
    }

    if ( hash_alg == TB_HALG_SHA1 )
        print_hex(NULL, (uint8_t *)hash->sha1, sizeof(hash->sha1));
    else {
        printk("unsupported hash alg (%u)\n", hash_alg);
        return;
    }
}

void print_help(const char *usage_str, const char *option_string[])
{
    uint16_t i = 0;
    if ( usage_str == NULL || option_string == NULL )
        return;

    printf("\nUsage: %s\n", usage_str);

    for ( ; option_string[i] != NULL; i++ )
        printf("%s", option_string[i]);
}

static void display_config_regs(void *txt_config_base)
{
    printf("Intel(r) TXT Configuration Registers:\n");

    /* STS */
    txt_sts_t sts;
    sts._raw = read_txt_config_reg(txt_config_base, TXTCR_STS);
    printf("\tSTS: 0x%08jx\n", sts._raw);
    printf("\t    senter_done: %s\n", bit_to_str(sts.senter_done_sts));
    printf("\t    sexit_done: %s\n", bit_to_str(sts.sexit_done_sts));
    printf("\t    mem_config_lock: %s\n", bit_to_str(sts.mem_config_lock_sts));
    printf("\t    private_open: %s\n", bit_to_str(sts.private_open_sts));
    printf("\t    locality_1_open: %s\n", bit_to_str(sts.locality_1_open_sts));
    printf("\t    locality_2_open: %s\n", bit_to_str(sts.locality_2_open_sts));

    /* ESTS */
    txt_ests_t ests;
    ests._raw = read_txt_config_reg(txt_config_base, TXTCR_ESTS);
    printf("\tESTS: 0x%02jx\n", ests._raw);
    printf("\t    txt_reset: %s\n", bit_to_str(ests.txt_reset_sts));

    /* E2STS */
    txt_e2sts_t e2sts;
    e2sts._raw = read_txt_config_reg(txt_config_base, TXTCR_E2STS);
    printf("\tE2STS: 0x%016jx\n", e2sts._raw);
    printf("\t    secrets: %s\n", bit_to_str(e2sts.secrets_sts));

    /* ERRORCODE */
    printf("\tERRORCODE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_ERRORCODE));

    /* DIDVID */
    txt_didvid_t didvid;
    didvid._raw = read_txt_config_reg(txt_config_base, TXTCR_DIDVID);
    printf("\tDIDVID: 0x%016jx\n", didvid._raw);
    printf("\t    vendor_id: 0x%x\n", didvid.vendor_id);
    printf("\t    device_id: 0x%x\n", didvid.device_id);
    printf("\t    revision_id: 0x%x\n", didvid.revision_id);

    /* FSBIF */
    uint64_t fsbif;
    fsbif = read_txt_config_reg(txt_config_base, TXTCR_VER_FSBIF);
    printf("\tFSBIF: 0x%016jx\n", fsbif);

    /* QPIIF */
    uint64_t qpiif;
    qpiif = read_txt_config_reg(txt_config_base, TXTCR_VER_QPIIF);
    printf("\tQPIIF: 0x%016jx\n", qpiif);

    /* SINIT.BASE/SIZE */
    printf("\tSINIT.BASE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
                                                        TXTCR_SINIT_BASE));
    printf("\tSINIT.SIZE: %juB (0x%jx)\n",
           read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE),
           read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE));

    /* HEAP.BASE/SIZE */
    printf("\tHEAP.BASE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_HEAP_BASE));
    printf("\tHEAP.SIZE: %juB (0x%jx)\n",
           read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE),
           read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE));

    /* DPR.BASE/SIZE */
    txt_dpr_t dpr;
    dpr._raw = read_txt_config_reg(txt_config_base, TXTCR_DPR);
    printf("\tDPR: 0x%016jx\n", dpr._raw);
    printf("\t    lock: %s\n", bit_to_str(dpr.lock));
    printf("\t    top: 0x%08x\n", (uint32_t)dpr.top << 20);
    printf("\t    size: %uMB (%uB)\n", dpr.size, dpr.size*1024*1024);

    /* PUBLIC.KEY */
    uint8_t key[256/8];
    unsigned int i = 0;
    do {
        *(uint64_t *)&key[i] = read_txt_config_reg(txt_config_base,
                                                   TXTCR_PUBLIC_KEY + i);
        i += sizeof(uint64_t);
    } while ( i < sizeof(key) );
    printf("\tPUBLIC.KEY:\n");
    print_hex("\t    ", key, sizeof(key)); printf("\n");

    /* easy-to-see status of TXT and secrets */
    printf("***********************************************************\n");
    printf("\t TXT measured launch: %s\n", bit_to_str(sts.senter_done_sts));
    printf("\t secrets flag set: %s\n", bit_to_str(e2sts.secrets_sts));
    printf("***********************************************************\n");
}

static void display_heap(txt_heap_t *heap)
{
    uint64_t size = get_bios_data_size(heap);
    bios_data_t *bios_data = get_bios_data_start(heap);
    print_bios_data(bios_data, size);
}

static void display_tboot_log(void *log_base)
{
    static char buf[512];
    char pbuf[64*1024];
    char *out = pbuf;
    tboot_log_t *log = (tboot_log_t *)log_base;
    char *log_buf = log->buf;
    uint8_t i = 0;
    if ( !are_uuids_equal(&(log->uuid), &((uuid_t)TBOOT_LOG_UUID)) ) {
        printf("unable to find TBOOT log\n");
        return;
    }

    printf("TBOOT log:\n");
    printf("\t max_size=%d\n", log->max_size);
    printf("\t zip_count=%d\n", log->zip_count);
    while ( i < log->zip_count) {
        printf("\t zip_pos[%d] = %d\n", i, log->zip_pos[i]);
        printf("\t zip_size[%d] = %d\n", i, log->zip_size[i]);
          i++;
    }
    
    printf("\t curr_pos=%d\n", log->curr_pos);
    printf("\t buf:\n");
    /* log->buf is phys addr of buf, which will not match where mmap has */
    /* map'ed us, but since it is always just past end of struct, use that */
    /* to uncompress tboot log */ 
    if (log->zip_count > 0) {
        for ( i = 0; i< log->zip_count; i++) {
            int length = LZ_Uncompress(&log_buf[log->zip_pos[i]], out, log->zip_size[i], sizeof(pbuf));
            if ( length < 0 )
               continue;
            /* log is too big for single printk(), so break it up */
            /* print out the uncompressed log */
            for ( int curr_pos = 0; curr_pos < length; curr_pos += sizeof(buf)-1 ) {
                if ( length - curr_pos >= (int)sizeof(buf) - 1 ) {
                    strncpy_s(buf, sizeof(buf), out + curr_pos, sizeof(buf)-1);
                }
                else {
                    strncpy_s(buf, sizeof(buf), out + curr_pos, length - curr_pos);
                }
                printf("%s", buf);
            }
        }
    } 

    for ( unsigned int curr_pos = log->zip_pos[log->zip_count]; curr_pos < log->curr_pos; curr_pos += sizeof(buf)-1 ) {
        strncpy_s(buf, sizeof(buf), log_buf + curr_pos, sizeof(buf)-1);
        printf("%s", buf);
    }
    printf("\n");
}

static bool is_txt_supported(void)
{
    return true;
}

static int fd_mem;
static void *buf_config_regs_read;
static void *buf_config_regs_mmap;

static inline uint64_t read_config_reg(uint32_t config_regs_base, uint32_t reg)
{
    uint64_t reg_val;
    void *buf;

    (void)config_regs_base;

    buf = buf_config_regs_read;
    if ( buf == NULL )
        buf = buf_config_regs_mmap;
    if ( buf == NULL )
        return 0;

    reg_val = read_txt_config_reg(buf, reg);
    return reg_val;
}

bool display_heap_optin = false;
static const char *short_option = "h";
static struct option longopts[] = {
    {"heap", 0, 0, 'p'},
    {"help", 0, 0, 'h'},
    {0, 0, 0, 0}
};
static const char *usage_string = "txt-stat [--heap] [-h]";
static const char *option_strings[] = {
    "--heap:\t\tprint out heap info.\n",
    "-h, --help:\tprint out this help message.\n",
    NULL
};

int main(int argc, char *argv[])
{
    uint64_t heap = 0;
    uint64_t heap_size = 0;
    void *buf = NULL;
    off_t seek_ret = -1;
    size_t read_ret = 0;

    int c;
    while ( (c = getopt_long(argc, (char **const)argv,
                    short_option, longopts, NULL)) != -1 ) 
        switch ( c ) {
        case 'h':
            print_help(usage_string, option_strings);
            return 0;

        case 'p':
            display_heap_optin = true;
            break;

        default:
            return 1;
        }

    if ( !is_txt_supported() ) {
        printf("Intel(r) TXT is not supported\n");
        return 1;
    }

    fd_mem = open("/dev/mem", O_RDONLY);
    if ( fd_mem == -1 ) {
        printf("ERROR: cannot open /dev/mem\n");
        return 1;
    }

    /*
     * display public config regs
     */
    seek_ret = lseek(fd_mem, TXT_PUB_CONFIG_REGS_BASE, SEEK_SET);
    if ( seek_ret == -1 )
        printf("ERROR: seeking public config registers failed: %s, try mmap\n",
               strerror(errno));
    else {
        buf = malloc(TXT_CONFIG_REGS_SIZE);
        if ( buf == NULL )
            printf("ERROR: out of memory, try mmap\n");
        else {
            read_ret = read(fd_mem, buf, TXT_CONFIG_REGS_SIZE);
            if ( read_ret != TXT_CONFIG_REGS_SIZE ) {
                printf("ERROR: reading public config registers failed: %s,"
                       "try mmap\n", strerror(errno));
                free(buf);
                buf = NULL;
            }
            else
                buf_config_regs_read = buf;
        }
    }

    /*
     * try mmap to display public config regs,
     * since public config regs should be displayed always.
     */
    if ( buf == NULL ) {
        buf = mmap(NULL, TXT_CONFIG_REGS_SIZE, PROT_READ,
                   MAP_PRIVATE, fd_mem, TXT_PUB_CONFIG_REGS_BASE);
        if ( buf == MAP_FAILED ) {
            printf("ERROR: cannot map config regs by mmap()\n");
            buf = NULL;
        }
        else
            buf_config_regs_mmap = buf;
    }

    if ( buf ) {
        display_config_regs(buf);
        heap = read_txt_config_reg(buf, TXTCR_HEAP_BASE);
        heap_size = read_txt_config_reg(buf, TXTCR_HEAP_SIZE);
    }

    /*
     * display heap
     */
    if ( heap && heap_size && display_heap_optin ) {
        seek_ret = lseek(fd_mem, heap, SEEK_SET);
        if ( seek_ret == -1 ) {
            printf("ERROR: seeking TXT heap failed by lseek(): %s, try mmap\n",
                   strerror(errno));
            goto try_mmap_heap;
        }
        buf = malloc(heap_size);
        if ( buf == NULL ) {
            printf("ERROR: out of memory, try mmap\n");
            goto try_mmap_heap;
        }
        read_ret = read(fd_mem, buf, heap_size);
        if ( read_ret != heap_size ) {
            printf("ERROR: reading TXT heap failed by read(): %s, try mmap\n",
                   strerror(errno));
            free(buf);
            goto try_mmap_heap;
        }
        display_heap((txt_heap_t *)buf);
        free(buf);
        goto try_display_log;

    try_mmap_heap:

        buf = mmap(NULL, heap_size, PROT_READ, MAP_PRIVATE, fd_mem, heap);
        if ( buf == MAP_FAILED )
            printf("ERROR: cannot map TXT heap by mmap()\n");
        else {
            display_heap((txt_heap_t *)buf);
            munmap(buf, heap_size);
        }
    }

try_display_log:
    if ( buf_config_regs_read )
        free(buf_config_regs_read);
    if ( buf_config_regs_mmap )
        munmap(buf_config_regs_mmap, TXT_CONFIG_REGS_SIZE);

    /*
     * display serial log from tboot memory (if exists)
     */
    seek_ret = lseek(fd_mem, TBOOT_SERIAL_LOG_ADDR, SEEK_SET);
    if ( seek_ret == -1 ) {
        printf("ERROR: seeking TBOOT log failed by lseek()\n");
        close(fd_mem);
        return 1;
    }
    buf = malloc(TBOOT_SERIAL_LOG_SIZE);
    if ( buf == NULL ) {
        printf("ERROR: out of memory\n");
        close(fd_mem);
        return 1;
    }
    read_ret = read(fd_mem, buf, TBOOT_SERIAL_LOG_SIZE);
    if ( read_ret != TBOOT_SERIAL_LOG_SIZE ) {
        printf("ERROR: reading TBOOT log failed by read()\n");
        free(buf);
        close(fd_mem);
        return 1;
    }
    display_tboot_log(buf);
    free(buf);
    close(fd_mem);

    return 0;
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
