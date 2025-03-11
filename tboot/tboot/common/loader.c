/*
 * loader.c: support functions for manipulating ELF/Linux kernel
 *           binaries
 *
 * Copyright (c) 2006-2013, Intel Corporation
 * Copyright (c) 2016 Real-Time Systems GmbH
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
#include <stdbool.h>
#include <types.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <multiboot.h>
#include <uuid.h>
#include <loader.h>
#include <e820.h>
#include <tboot.h>
#include <lcp3.h>
#include <elf_defns.h>
#include <linux_defns.h>
#include <tb_error.h>
#include <txt/txt.h>
#include <mle.h>
#include <txt/acmod.h>
#include <cmdline.h>
#include <tpm.h>
#include <efi_memmap.h>

/* copy of kernel/VMM command line so that can append 'tboot=0x1234' */
static char * volatile new_cmdline = (char *)TBOOT_KERNEL_CMDLINE_ADDR;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/* multiboot struct saved so that post_launch() can use it (in tboot.c) */
extern loader_ctx *g_ldr_ctx;
extern bool get_elf_image_range(const elf_header_t *elf, void **start, void **end);
extern bool is_elf_image(const void *image, size_t size);
extern bool expand_elf_image(const elf_header_t *elf, void **entry_point);
extern bool expand_linux_image(const void *linux_image, size_t linux_size,
                               const void *initrd_image, size_t initrd_size,
                               void **entry_point, bool is_measured_launch);
extern bool jump_elf_image(const void *entry_point, uint32_t magic);
extern bool jump_linux_image(const void *entry_point);
extern bool is_sinit_acmod(const void *acmod_base, uint32_t acmod_size, 
                           bool quiet);
extern void apply_policy(tb_error_t error);
extern uint32_t g_mb_orig_size;

#define LOADER_CTX_BAD(xctx) \
    xctx == NULL ? true : \
        xctx->addr == NULL ? true : \
        xctx->type != 1 && xctx->type != 2 ? true : false

#define MB_NONE 0
#define MB1_ONLY 1
#define MB2_ONLY 2
#define MB_BOTH 3

static void
printk_long(char *what)
{
    /* chunk the command line into 70 byte chunks */
#define CHUNK_SIZE 70
    int      cmdlen = tb_strlen(what);
    char    *cptr = what;
    char     cmdchunk[CHUNK_SIZE+1];
    while (cmdlen > 0) {
        tb_strncpy(cmdchunk, cptr, CHUNK_SIZE);
        cmdchunk[CHUNK_SIZE] = 0;
        printk(TBOOT_INFO"\t%s\n", cmdchunk);
        cmdlen -= CHUNK_SIZE;
        cptr += CHUNK_SIZE;
    }
}

static module_t 
*get_module_mb1(const multiboot_info_t *mbi, unsigned int i)
{
    if ( mbi == NULL ) {
        printk(TBOOT_ERR"Error: mbi pointer is zero.\n");
        return NULL;
    }

    if ( i >= mbi->mods_count ) {
        printk(TBOOT_ERR"invalid module #\n");
        return NULL;
    }

    return (module_t *)(mbi->mods_addr + i * sizeof(module_t));
}

static struct mb2_tag
*next_mb2_tag(struct mb2_tag *start)
{
    /* given "start", what's the beginning of the next tag */
    void *addr = (void *) start;
    if (start == NULL)
        return NULL;
    if (start->type == MB2_TAG_TYPE_END)
        return NULL;
    addr += ((start->size + 7) & ~7);
    return (struct mb2_tag *) addr;
}

static struct mb2_tag 
*find_mb2_tag_type(struct mb2_tag *start, uint32_t tag_type)
{
    while (start != NULL){
        if (start->type == tag_type)
            return start;
        start = next_mb2_tag(start);
    }
    return start;
}

static module_t 
*get_module_mb2(loader_ctx *lctx, unsigned int i)
{
    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    unsigned int ii;
    struct mb2_tag_module *tag_mod = NULL;
    module_t *mt = NULL;
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
    if (start != NULL){
        for (ii = 1; ii <= i; ii++){
            if (start == NULL)
                return NULL;
            else {
                /* nudge off this hit */
                start = next_mb2_tag(start);
                start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
            }
        }
        /* if we're here, we have the tag struct for the desired module */
        tag_mod = (struct mb2_tag_module *) start;
        mt = (module_t *) &(tag_mod->mod_start);
    }
    return mt;
}

#if 0
void print_mbi(const multiboot_info_t *mbi)
{
    /* print mbi for debug */
    unsigned int i;

    printk(TBOOT_DETA"print mbi@%p ...\n", mbi);
    printk(TBOOT_DETA"\t flags: 0x%x\n", mbi->flags);
    if ( mbi->flags & MBI_MEMLIMITS )
        printk(TBOOT_DETA"\t mem_lower: %uKB, mem_upper: %uKB\n", 
               mbi->mem_lower, mbi->mem_upper);
    if ( mbi->flags & MBI_BOOTDEV ) {
        printk(TBOOT_DETA"\t boot_device.bios_driver: 0x%x\n",
               mbi->boot_device.bios_driver);
        printk(TBOOT_DETA"\t boot_device.top_level_partition: 0x%x\n",
               mbi->boot_device.top_level_partition);
        printk(TBOOT_DETA"\t boot_device.sub_partition: 0x%x\n",
               mbi->boot_device.sub_partition);
        printk(TBOOT_DETA"\t boot_device.third_partition: 0x%x\n",
               mbi->boot_device.third_partition);
    }
    if ( mbi->flags & MBI_CMDLINE ) {
# define CHUNK_SIZE 72 
        /* Break the command line up into 72 byte chunks */
        int   cmdlen = tb_strlen(mbi->cmdline);
        char *cmdptr = (char *)mbi->cmdline;
        char  chunk[CHUNK_SIZE+1];
        printk(TBOOT_DETA"\t cmdline@0x%x: ", mbi->cmdline);
        chunk[CHUNK_SIZE] = '\0';
        while (cmdlen > 0) {
            tb_strncpy(chunk, cmdptr, CHUNK_SIZE); 
            printk(TBOOT_DETA"\n\t\"%s\"", chunk);
            cmdptr += CHUNK_SIZE;
            cmdlen -= CHUNK_SIZE;
        }
        printk(TBOOT_DETA"\n");
    }

    if ( mbi->flags & MBI_MODULES ) {
        printk(TBOOT_DETA"\t mods_count: %u, mods_addr: 0x%x\n", 
               mbi->mods_count, mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
            printk(TBOOT_DETA"\t     %d : mod_start: 0x%x, mod_end: 0x%x\n", i,
                   p->mod_start, p->mod_end);
            printk(TBOOT_DETA"\t         string (@0x%x): \"%s\"\n", p->string,
                   (char *)p->string);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        printk(TBOOT_DETA
               "\t aout :: tabsize: 0x%x, strsize: 0x%x, addr: 0x%x\n",
               p->tabsize, p->strsize, p->addr);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        printk(TBOOT_DETA
               "\t elf :: num: %u, size: 0x%x, addr: 0x%x, shndx: 0x%x\n",
               p->num, p->size, p->addr, p->shndx);
    }
    if ( mbi->flags & MBI_MEMMAP ) {
        memory_map_t *p;
        printk(TBOOT_DETA
               "\t mmap_length: 0x%x, mmap_addr: 0x%x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
	        printk(TBOOT_DETA"\t     size: 0x%x, base_addr: 0x%04x%04x, "
                   "length: 0x%04x%04x, type: %u\n", p->size,
                   p->base_addr_high, p->base_addr_low,
                   p->length_high, p->length_low, p->type);
        }
    }
    if ( mbi->flags & MBI_DRIVES ) {
        printk(TBOOT_DETA"\t drives_length: %u, drives_addr: 0x%x\n", 
               mbi->drives_length, mbi->drives_addr);
    }
    if ( mbi->flags & MBI_CONFIG ) {
        printk(TBOOT_DETA"\t config_table: 0x%x\n", mbi->config_table);
    }
    if ( mbi->flags & MBI_BTLDNAME ) {
        printk(TBOOT_DETA"\t boot_loader_name@0x%x: %s\n",
               mbi->boot_loader_name, (char *)mbi->boot_loader_name);
    }
    if ( mbi->flags & MBI_APM ) {
        printk(TBOOT_DETA"\t apm_table: 0x%x\n", mbi->apm_table);
    }
    if ( mbi->flags & MBI_VBE ) {
        printk(TBOOT_DETA"\t vbe_control_info: 0x%x\n"
               "\t vbe_mode_info: 0x%x\n"
               "\t vbe_mode: 0x%x\n"
               "\t vbe_interface_seg: 0x%x\n"
               "\t vbe_interface_off: 0x%x\n"
               "\t vbe_interface_len: 0x%x\n",
               mbi->vbe_control_info,
               mbi->vbe_mode_info,
               mbi->vbe_mode,
               mbi->vbe_interface_seg,
               mbi->vbe_interface_off,
               mbi->vbe_interface_len
              );
    }
}
#endif


bool verify_loader_context(loader_ctx *lctx)
{
    unsigned int count;
    if (LOADER_CTX_BAD(lctx))
        return false;
    count = get_module_count(lctx);
    if (count < 1){
        printk(TBOOT_ERR"Error: no MB%d modules\n", lctx->type);
        return false;
    } else {
        for (uint32_t i = 0; i < count; ++i) {
            module_t *m = get_module(lctx, i);
            if (m->mod_end < m->mod_start) {
                return false;
            }
        }
        return true;
    }
}

static bool remove_mb2_tag(loader_ctx *lctx, struct mb2_tag *cur)
{
    uint8_t *s, *d, *e;
    struct mb2_tag *next, *end;
    next = next_mb2_tag(cur);
    if (next == NULL){
        printk(TBOOT_ERR"missing next tag in remove_mb2_tag\n");
        return false;
    }
    /* where do we stop? */
    end = (struct mb2_tag *)(lctx->addr + 8);
    end = find_mb2_tag_type(end, MB2_TAG_TYPE_END);
    if (end == NULL){
        printk(TBOOT_ERR"remove_mb2_tag, no end tag!!!!\n");
        return false;
    }
    e = (uint8_t *) end + end->size;
    /* we'll do this byte-wise */
    s = (uint8_t *) next; d = (uint8_t *) cur;
            
    while (s <= e){
        *d = *s; d++; s++;
    }                
    /* adjust MB2 length */
    *((unsigned long *) lctx->addr) -= 
        (uint8_t *)next - (uint8_t *)cur;
    /* sanity check */
    /* print_loader_ctx(lctx); */
    return true;
}

static bool
grow_mb2_tag(loader_ctx *lctx, struct mb2_tag *which, uint32_t how_much)
{
    struct mb2_tag *next, *new_next, *end;
    int growth, slack;
    uint8_t *s, *d;
    // uint32_t old_size = which->size;

    /* we're holding the tag struct to grow, get its successor */
    next = next_mb2_tag(which);

    /* find the end--we will need it */
    end = (struct mb2_tag *)(lctx->addr + 8);
    end = find_mb2_tag_type(end, MB2_TAG_TYPE_END);
    if ( end == NULL )
        return false;

    /* How much bigger does it need to be? */
    /* NOTE: this breaks the MBI 2 structure for walking
     * until we're done copying.
     */
    which->size += how_much;

    /* what's the new growth for its successor? */
    new_next = next_mb2_tag(which);
    growth = ((void *) new_next) - ((void *) next);

    /* check to make sure there's actually room for the growth */
    slack = g_mb_orig_size - *(uint32_t *) (lctx->addr);
    if (growth > slack){
        printk(TBOOT_ERR"YIKES!!! grow_mb2_tag slack %d < growth %d\n",
               slack, growth);
        apply_policy(TB_ERR_FATAL);
    }

    /* now we copy down from the bottom, going up */
    s = ((uint8_t *) end) + end->size;
    d = s + growth;
    while (s >= (uint8_t *)next){
        *d = *s;
        d--; s--;
    }
    /* adjust MB2 length */
    *((uint32_t *) lctx->addr) += growth;
    return true;
}

static void *remove_module(loader_ctx *lctx, void *mod_start)
{
    module_t *m = NULL;
    unsigned int i;

    if ( !verify_loader_context(lctx))
        return NULL;

    for ( i = 0; i < get_module_count(lctx); i++ ) {
        m = get_module(lctx, i);
        if ( mod_start == NULL || (void *)m->mod_start == mod_start )
            break;
    }

    /* not found */
    if ( m == NULL ) {
        printk(TBOOT_ERR"could not find module to remove\n");
        return NULL;
    }

    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        /* if we're removing the first module (i.e. the "kernel") then */
        /* need to adjust some mbi fields as well */
        multiboot_info_t *mbi = (multiboot_info_t *) lctx->addr;
        if ( mod_start == NULL ) {
            mbi->cmdline = m->string;
            mbi->flags |= MBI_CMDLINE;
            mod_start = (void *)m->mod_start;
        }

        /* copy remaing mods down by one */
        tb_memmove(m, m + 1, (mbi->mods_count - i - 1)*sizeof(module_t));

        mbi->mods_count--;

        return mod_start;
    }
    if (lctx->type == MB2_ONLY){
        /* multiboot 2 */
        /* if we're removing the first module (i.e. the "kernel") then */
        /* need to adjust some mbi fields as well */
        char cmdbuf[TBOOT_KERNEL_CMDLINE_SIZE];
        cmdbuf[0] = '\0';
        if ( mod_start == NULL ) {
            char *cmdline = get_cmdline(lctx);
            char *mod_string = get_module_cmd(lctx, m);
            if ( cmdline == NULL ) {
                printk(TBOOT_ERR"could not find cmdline\n");
                return NULL;
            }
            if ( mod_string == NULL ) {
                printk(TBOOT_ERR"could not find module cmdline\n");
                return NULL;
            }
            if ((tb_strlen(mod_string)) > (tb_strlen(cmdline))){
                if (tb_strlen(mod_string) >= TBOOT_KERNEL_CMDLINE_SIZE){
                    printk(TBOOT_ERR"No room to copy MB2 cmdline [%d < %d]\n",
                           (int)(tb_strlen(cmdline)), (int)(tb_strlen(mod_string)));
                } else {
                    char *s = mod_string;
                    char *d = cmdbuf;
                    while (*s){
                        *d = *s;
                        d++; s++;
                    }
                    *d = *s;
                    // strcpy(cmdbuf, mod_string);
                }
            } else {
                // strcpy(cmdline,mod_string);
                char *s = mod_string;
                char *d = cmdline;
                while (*s){
                    *d = *s;
                    d++; s++;
                }
                *d = *s;
                /* note: we didn't adjust the "size" field, since it didn't
                 * grow and this saves us the pain of shuffling everything
                 * after cmdline (which is usually first)
                 */
            }
            mod_start = (void *)m->mod_start;
        }
        /* so MB2 is a different beast.  The modules aren't necessarily
         * adjacent, first, last, anything.  What we can do is bulk copy
         * everything after the thing we're killing over the top of it,
         * and shorten the total length of the MB2 structure.
         */
        {
            struct mb2_tag *cur;
            struct mb2_tag_module *mod = NULL;
            module_t *cur_mod = NULL;
            cur = (struct mb2_tag *)(lctx->addr + 8);
            cur = find_mb2_tag_type(cur, MB2_TAG_TYPE_MODULE);
            mod = (struct mb2_tag_module *) cur;
            if (mod != NULL)
                cur_mod = (module_t *)&(mod->mod_start);

            while (cur_mod != NULL && cur_mod != m){
                /* nudge off current record */
                cur = next_mb2_tag(cur);
                cur = find_mb2_tag_type(cur, MB2_TAG_TYPE_MODULE);
                mod = (struct mb2_tag_module *) cur;
                if (mod != NULL)
                    cur_mod = (module_t *)&(mod->mod_start);
                else
                    cur_mod = NULL;
            }
            if (cur_mod == NULL){
                printk(TBOOT_ERR"remove_module() for MB2 failed\n");
                return NULL;
            }

            /* we're here.  cur is the MB2 tag we need to overwrite. */
            if (false == remove_mb2_tag(lctx, cur))
                return NULL;
        }
        if (cmdbuf[0] != '\0'){
            /* we need to grow the mb2_tag_string that holds the cmdline.
             * we know there's room, since we've shortened the MB2 by the
             * length of the module_tag we've removed, which contained 
             * the longer string.
             */
            struct mb2_tag *cur = (struct mb2_tag *)(lctx->addr + 8);
            struct mb2_tag_string *cmd;

            cur = find_mb2_tag_type(cur, MB2_TAG_TYPE_CMDLINE);
            cmd = (struct mb2_tag_string *) cur;
            if (cmd == NULL){
                printk(TBOOT_ERR"remove_modules MB2 shuffle NULL cmd\n");
                return NULL;
            }

            grow_mb2_tag(lctx, cur, tb_strlen(cmdbuf) - tb_strlen(cmd->string));

            /* now we're all good, except for fixing up cmd */
            {
                char * s = cmdbuf; 
                char *d = cmd->string;
                while (*s){
                    *d = *s;
                    d++; s++;
                }
                *d = *s;
            }
        }
        return mod_start;
    }
    return NULL;
}

static bool adjust_kernel_cmdline(loader_ctx *lctx,
                                  const void *tboot_shared_addr)
{
    const char *old_cmdline;

    if (lctx == NULL)
        return false;
    if (lctx->addr == NULL)
        return false;
    if (lctx->type == MB1_ONLY || lctx->type == MB2_ONLY){
        old_cmdline = get_cmdline(lctx);
        if (old_cmdline == NULL)
            old_cmdline = "";

        tb_snprintf(new_cmdline, TBOOT_KERNEL_CMDLINE_SIZE, "%s tboot=%p",
                 old_cmdline, tboot_shared_addr);
        new_cmdline[TBOOT_KERNEL_CMDLINE_SIZE - 1] = '\0';

        if (lctx->type == MB1_ONLY){
            /* multiboot 1 */
            multiboot_info_t *mbi = (multiboot_info_t *) lctx->addr;
            /* assumes mbi is valid */
            mbi->cmdline = (u32)new_cmdline;
            mbi->flags |= MBI_CMDLINE;
            return true;
        }
        if (lctx->type == MB2_ONLY){
            /* multiboot 2 */
            /* this is harder, since the strings sit inline */
            /* we need to grow the mb2_tag_string that holds the cmdline.
             * TODO: should be checking that we're not running off the
             * end of the original MB2 space.
             */
            struct mb2_tag *cur = (struct mb2_tag *)(lctx->addr + 8);
            struct mb2_tag_string *cmd;
            cur = find_mb2_tag_type(cur, MB2_TAG_TYPE_CMDLINE);
            cmd = (struct mb2_tag_string *) cur;
            if (cmd == NULL){
                printk(TBOOT_ERR"adjust_kernel_cmdline() NULL MB2 cmd\n");
                return NULL;
            }
            uint32_t new_cmdline_tag_size = 2 * sizeof(uint32_t) + tb_strlen(new_cmdline) + 1;
            if ( new_cmdline_tag_size > cmd->size ){
                if (false ==
                    grow_mb2_tag(lctx, cur,
                                 (new_cmdline_tag_size - cmd->size)))
                    return false;
            }

            /* now we're all good, except for fixing up cmd */
            {
                char *s = new_cmdline;
                char *d = cmd->string;
                while (*s){
                    *d = *s;
                    d++; s++;
                }
                *d = *s;
            }
            // strcpy(cmd->string, cmdbuf);
        }
        return true;
    }
    return false;
}

bool is_kernel_linux(void)
{
    if ( !verify_loader_context(g_ldr_ctx) )
        return false;

    // module_t *m = (module_t *)g_mbi->mods_addr;
    module_t *m = get_module(g_ldr_ctx, 0);
    void *kernel_image = (void *)m->mod_start;
    size_t kernel_size = m->mod_end - m->mod_start;

    return !is_elf_image(kernel_image, kernel_size);
}

static bool 
find_module(loader_ctx *lctx, void **base, size_t *size,
            const void *data, size_t len)
{
    if ( lctx == NULL || lctx->addr == NULL) {
        printk(TBOOT_ERR"Error: context pointer is zero.\n");
        return false;
    }

    if ( base == NULL ) {
        printk(TBOOT_ERR"Error: base is NULL.\n");
        return false;
    }

    *base = NULL;
    if ( size != NULL )
        *size = 0;

    if ( 0 == get_module_count(lctx)) {
        printk(TBOOT_ERR"Error: no module.\n");
        return false;
    }

    for ( unsigned int i = get_module_count(lctx) - 1; i > 0; i-- ) {
        module_t *m = get_module(lctx, i);
        /* check size */
        size_t mod_size = m->mod_end - m->mod_start;
        if ( len > mod_size ) {
            printk(TBOOT_ERR"Error: image size is smaller than data size.\n");
            return false;
        }
        if ( tb_memcmp((void *)m->mod_start, data, len) == 0 ) {
            *base = (void *)m->mod_start;
            if ( size != NULL )
                *size = mod_size;
            return true;
        }
    }

    return false;
}

bool 
find_lcp_module(loader_ctx *lctx, void **base, uint32_t *size)
{
    size_t size2 = 0;
    void *base2 = NULL;

    if ( base != NULL )
        *base = NULL;
    if ( size != NULL )
        *size = 0;

    /* try policy data file for old version (0x00 or 0x01) */
    find_module_by_uuid(lctx, &base2, &size2, &((uuid_t)LCP_POLICY_DATA_UUID));

    /* not found */
    if ( base2 == NULL ) {
        /* try policy data file for new version (0x0202) */
        find_module_by_file_signature(lctx, &base2, &size2,
                                      LCP_POLICY_DATA_FILE_SIGNATURE);

        if ( base2 == NULL ) {
            printk(TBOOT_WARN"no LCP module found\n");
            return false;
        }
        else
            printk(TBOOT_INFO"v2 LCP policy data found\n");
    }
    else
        printk(TBOOT_INFO"v1 LCP policy data found\n");


    if ( base != NULL )
        *base = base2;
    if ( size != NULL )
        *size = size2;
    return true;
}

/*
 * remove (all) SINIT and LCP policy data modules (if present)
 */
bool 
remove_txt_modules(loader_ctx *lctx)
{
    if ( 0 == get_module_count(lctx)) {
        printk(TBOOT_ERR"Error: no module.\n");
        return false;
    }

    /* start at end of list so that we can remove w/in the loop */
    for ( unsigned int i = get_module_count(lctx) - 1; i > 0; i-- ) {
        module_t *m = get_module(lctx, i);
        void *base = (void *)m->mod_start;

        if ( is_sinit_acmod(base, m->mod_end - (unsigned long)base, true) ) {
            printk(TBOOT_INFO"got sinit match on module #%d\n", i);
            if ( remove_module(lctx, base) == NULL ) {
                printk(TBOOT_ERR
                       "failed to remove SINIT module from module list\n");
                return false;
            }
        }
    }

    void *base = NULL;
    if ( find_lcp_module(lctx, &base, NULL) ) {
        if ( remove_module(lctx, base) == NULL ) {
            printk(TBOOT_ERR"failed to remove LCP module from module list\n");
            return false;
        }
    }

    return true;
}

extern unsigned long get_tboot_mem_end(void);

static bool below_tboot(unsigned long addr)
{
    return addr < TBOOT_BASE_ADDR;
}

static unsigned long max(unsigned long a, unsigned long b)
{
    return (a > b) ? a : b;
}

static 
unsigned long get_mbi_mem_end_mb1(const multiboot_info_t *mbi)
{
    unsigned long end = (unsigned long)(mbi + 1);

    if ( mbi->flags & MBI_CMDLINE )
        end = max(end, mbi->cmdline + tb_strlen((char *)mbi->cmdline) + 1);
    if ( mbi->flags & MBI_MODULES ) {
        end = max(end, mbi->mods_addr + mbi->mods_count * sizeof(module_t));
        unsigned int i;
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = get_module_mb1(mbi, i);
            if ( p == NULL )
                break;
            end = max(end, p->string + tb_strlen((char *)p->string) + 1);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        end = max(end, p->addr + p->tabsize
                       + sizeof(unsigned long) + p->strsize);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        end = max(end, p->addr + p->num * p->size);
    }
    if ( mbi->flags & MBI_MEMMAP )
        end = max(end, mbi->mmap_addr + mbi->mmap_length);
    if ( mbi->flags & MBI_DRIVES )
        end = max(end, mbi->drives_addr + mbi->drives_length);
    /* mbi->config_table field should contain */
    /*  "the address of the rom configuration table returned by the */
    /*  GET CONFIGURATION bios call", so skip it */
    if ( mbi->flags & MBI_BTLDNAME )
        end = max(end, mbi->boot_loader_name
                       + tb_strlen((char *)mbi->boot_loader_name) + 1);
    if ( mbi->flags & MBI_APM )
        /* per Grub-multiboot-Main Part2 Rev94-Structures, apm size is 20 */
        end = max(end, mbi->apm_table + 20);
    if ( mbi->flags & MBI_VBE ) {
        /* VBE2.0, VBE Function 00 return 512 bytes*/
        end = max(end, mbi->vbe_control_info + 512);
        /* VBE2.0, VBE Function 01 return 256 bytes*/
        end = max(end, mbi->vbe_mode_info + 256);
    }

    return PAGE_UP(end);
}

/*
 * Move all mbi components/modules/mbi to end of memory
 */
static bool move_modules_to_high_memory(loader_ctx  *lctx)
{
    uint32_t memRequired;
    uint64_t max_ram_base = 0, max_ram_size = 0, ld_ceiling;

    uint32_t module_count, mod_i, mods_remaining;
    module_t *m;

    if (LOADER_CTX_BAD(lctx))
        return false;

    /*  Determine the size of memory required to pack all modules together */
    module_count = get_module_count(lctx);
    for( memRequired=0, mod_i=0; mod_i < module_count; mod_i++ ){
        m = get_module(lctx, mod_i);
        memRequired += PAGE_UP(m->mod_end - m->mod_start);
    }

    /*  NOTE: the memory maps have been modified already to reserve critical
        memory regions (tboot memory, etc ...). get_highest_sized_ram
        will return a range that excludes critical memory regions. */
    if (!efi_memmap_get_highest_sized_ram(memRequired, 0x100000000ULL,
                                          &max_ram_base, &max_ram_size)) {
        if (!e820_get_highest_sized_ram(memRequired, 0x100000000ULL,
                                        &max_ram_base, &max_ram_size)) {
            printk(TBOOT_INFO"ERROR No memory area found for image"
                             "relocation!\n");
            printk(TBOOT_INFO"required 0x%X\n", memRequired);
            return false;
        }
    }

    printk(TBOOT_INFO"highest suitable area @ 0x%llX (size 0x%llX)\n",
            max_ram_base, max_ram_size);
    ld_ceiling = PAGE_DOWN(max_ram_base + max_ram_size);

    /*  Move modules below the load ceiling upto the ceiling:
        Prevent module corruption:
        - Move modules in order of highest to lowest.
        - Only move modules completely below the load ceiling.
     */
    for( mods_remaining=module_count; mods_remaining > 0; mods_remaining--){
        uint32_t    highest_mod_i = 0,
                    highest_mod_base = 0,
                    highest_mod_end = 0;
        bool mod_found = false;
        for( mod_i=0; mod_i<module_count; mod_i++){
            m = get_module(lctx, mod_i);
            if( (m->mod_start < ld_ceiling) ){
                if( (m->mod_end > highest_mod_end) || !mod_found ){
                    highest_mod_i   = mod_i;
                    highest_mod_base= m->mod_start;
                    highest_mod_end = m->mod_end;
                    mod_found = true;
                }
            }
        }

        /* If no modules found, all modules are above ld_ceiling, We're done. */
        if( !mod_found )
            break;

        m = get_module(lctx, highest_mod_i);
        /* only move the highest module if explicitly below the ceiling */
        if(highest_mod_end < ld_ceiling){
            uint32_t size = highest_mod_end - highest_mod_base;
            uint32_t highest_mod_newbase = PAGE_DOWN(ld_ceiling-size);
            printk(TBOOT_INFO"moving module %u (%u B) from 0x%08X to 0x%08X\n",
                    highest_mod_i, size, highest_mod_base, highest_mod_newbase);
            tb_memcpy((void *)highest_mod_newbase, (void *)highest_mod_base, size);
            m->mod_start= highest_mod_newbase;
            m->mod_end  = highest_mod_newbase+size;
        }
        /* lower the celing to the base address of the highest module */
        ld_ceiling = PAGE_DOWN(m->mod_start);
    }
    return true;
}

/*
 * Move any mbi components/modules/mbi that just above the kernel
 */
static bool move_modules_above_elf_kernel(  loader_ctx      *lctx,
                                            elf_header_t    *kernel_image)
{
    void *elf_start, *elf_end;
    uint32_t ld_floor, ld_ceiling;

    uint32_t module_count, mod_i, mods_remaining;
    module_t *m;

    if (LOADER_CTX_BAD(lctx))
        return false;

    /* get end address of loaded elf image */
    if ( !get_elf_image_range(kernel_image, &elf_start, &elf_end) ){
        printk(TBOOT_INFO"ERROR: failed to get elf image range\n");
        return false;
    }
    printk(TBOOT_INFO"ELF kernel top is at 0x%X\n", (uint32_t)elf_end);

    /*  compute the lowest base address of all the modules: the ld ceiling */
    module_count = get_module_count(lctx);
    for( mod_i=0, ld_ceiling=0; mod_i < module_count; mod_i++ ){
        m = get_module(lctx,mod_i);
        ld_ceiling = (ld_ceiling < m->mod_start)? m->mod_start : ld_ceiling;
    }

    /*  set ld_floor to the highest of tboot end address or the ELF-image
        end address, and then page align */
    ld_floor = get_tboot_mem_end();
    ld_floor = (ld_floor < (uint32_t)elf_end)? (uint32_t)elf_end : ld_floor;
    ld_floor = PAGE_UP(ld_floor);

    /*  Ensures all modules are above ld_floor: only move mods down, never up.
        Failing this check is an indication ELF-loading may have corrupted one
        of the modules. */
    if( (uint32_t)ld_floor > ld_ceiling ){
        printk( TBOOT_INFO"Load floor (0x%08X) > load ceiling (0x%08X)\n",
                ld_floor, ld_ceiling);
        return false;
    }

    /*  the i-th iteration of this loop will
    move the i-th lowest module in memory to ld_floor
    and raise ld_floor to the new end address of the i-th lowest module */
    for( mods_remaining = module_count; mods_remaining > 0; mods_remaining--){
        uint32_t    lowest_mod_i = 0,
                    lowest_mod_base = 0,
                    lowest_mod_end = 0;
        bool mod_found = false;
        /* find the lowest module above the floor */
        for( mod_i=0; mod_i<module_count; mod_i++){
            m = get_module(lctx, mod_i);
            if(m->mod_start >= ld_floor){
                if( (m->mod_start < lowest_mod_base) || !mod_found  ){
                    lowest_mod_i   = mod_i;
                    lowest_mod_base= m->mod_start;
                    lowest_mod_end = m->mod_end;
                    mod_found = true;
                }
            }
        }
        m = get_module(lctx, lowest_mod_i);

        /* only move the lowest module if not already at the floor */
        if(lowest_mod_base > ld_floor){
            uint32_t size = lowest_mod_end - lowest_mod_base;
            uint32_t lowest_mod_newbase = ld_floor; /* already page aligned */
            printk(TBOOT_INFO"moving module %u (%u B) from 0x%08X to 0x%08X\n",
                    lowest_mod_i, size, lowest_mod_base, lowest_mod_newbase);
            tb_memcpy((void *)lowest_mod_newbase, (void *)lowest_mod_base, size);
            m->mod_start= lowest_mod_newbase;
            m->mod_end  = lowest_mod_newbase+size;
        }
        /* raise the floor to the end address of the lowest module */
        ld_floor = PAGE_UP(m->mod_end);
    }
    return true;
}

static void fixup_modules(loader_ctx *lctx, size_t offset)
{
    unsigned int module_count = get_module_count(lctx);
    for ( unsigned int i = 0; i < module_count; i++ ) {
        module_t *m = get_module(lctx, i);
        if ( below_tboot(m->mod_start) ) {
            m->mod_start += offset;
            m->mod_end += offset;
        }
        /* MB2 module strings are inline, not addresses */
        if (lctx->type == 1)
            if ( below_tboot(m->string) )
                m->string += offset;
    }
}

/*
 * fixup_loader_ctx() is to be called after modules and/or mbi are moved from 
 * below tboot memory to above tboot. It will fixup all pointers in mbi if 
 * mbi was moved; fixup modules table if any modules are moved. If mbi was 
 * moved, adjust the addr field in context, otherwise, leave alone.
 */
static 
void fixup_loader_ctx(loader_ctx *lctx, size_t offset)
{
    if (LOADER_CTX_BAD(lctx))
        return;

    bool moving_ctx = below_tboot((unsigned long)lctx->addr);
    multiboot_info_t *mbi = lctx->addr;

    if ( moving_ctx ) {
        printk(TBOOT_INFO"loader context was moved from %p to ", lctx->addr);
        lctx->addr += offset;
        printk(TBOOT_INFO"%p\n", lctx->addr);
    }

    if (0 < get_module_count(lctx)) {
        if (lctx->type == MB1_ONLY)
            if ( below_tboot(mbi->mods_addr) )
                mbi->mods_addr += offset;
        /* not required for MB2--if we moved the pile, we moved this too */
        fixup_modules(lctx, offset);
    }

    if (lctx->type == MB1_ONLY){
        /* RLM change.  There's no use passing these on to Xen or whatever,
         * since they will be tboot's addrs, not the target's!  We don't
         * want the thing we launch using tboot image addresses to deduce
         * anything about itself!
         */
        if (mbi->flags & MBI_AOUT){
            mbi->syms.aout_image.addr = 0;
            mbi->flags &= ~MBI_AOUT;
        }
        if (mbi->flags & MBI_ELF){
            mbi->syms.elf_image.addr = 0;
            mbi->flags &= ~MBI_ELF;
        }
    }

    if (lctx->type == MB2_ONLY){
        struct mb2_tag *start, *victim;
        /* as above, we need to remove ELF tag if we have it */
        start = (struct mb2_tag *) (lctx->addr + 8);
        victim = find_mb2_tag_type(start, MB2_TAG_TYPE_ELF_SECTIONS);
        if (victim != NULL)
            (void) remove_mb2_tag(lctx,victim);
        /* and that's all, folks! */
        return;
    }
    if ( !moving_ctx)
        return;

    /* tboot replace mmap_addr w/ a copy, and make a copy of cmdline
     * because we modify it. Those pointers don't need offset adjustment.
     * To make it general and depend less on such kind of changes, just 
     * check whether we need to adjust offset before trying to do it for 
     * each field 
     */
    if ( (mbi->flags & MBI_CMDLINE) && below_tboot(mbi->cmdline) )
        mbi->cmdline += offset;

    if ( (mbi->flags & MBI_MEMMAP) && below_tboot(mbi->mmap_addr) )
        mbi->mmap_addr += offset;

    if ( (mbi->flags & MBI_DRIVES) && below_tboot(mbi->drives_addr) )
        mbi->drives_addr += offset;

    if ( (mbi->flags & MBI_CONFIG) && below_tboot(mbi->config_table) )
        mbi->config_table += offset;

    if ( (mbi->flags & MBI_BTLDNAME) && below_tboot(mbi->boot_loader_name) )
        mbi->boot_loader_name += offset;

    if ( (mbi->flags & MBI_APM) && below_tboot(mbi->apm_table) )
        mbi->apm_table += offset;

    if ( mbi->flags & MBI_VBE ) {
        if ( below_tboot(mbi->vbe_control_info) )
            mbi->vbe_control_info += offset;
        if ( below_tboot(mbi->vbe_mode_info) )
            mbi->vbe_mode_info += offset;
    }
    return;
}

static uint32_t get_lowest_mod_start_below_tboot(loader_ctx *lctx)
{
    uint32_t lowest = 0xffffffff;
    unsigned int mod_count = get_module_count(lctx);
    for ( unsigned int i = 0; i < mod_count; i++ ) {
        module_t *m = get_module(lctx, i);
        if ( m->mod_start < lowest &&
                below_tboot(m->mod_start))
            lowest = m->mod_start;
    }

    return lowest;
}

static uint32_t get_highest_mod_end(loader_ctx *lctx)
{
    uint32_t highest = 0;
    unsigned int mod_count = get_module_count(lctx);
    for ( unsigned int i = 0; i < mod_count; i++ ) {
        module_t *m = get_module(lctx, i);
        if ( m->mod_end > highest )
            highest = m->mod_end;
    }

    return highest;
}

/*
 * Move any mbi components/modules/mbi that are below tboot to just above tboot
 */
void move_modules(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return;

    unsigned long lowest = get_lowest_mod_start_below_tboot(lctx);
    unsigned long from = 0;
    unsigned long tboot_mem_end = 0;

    if ( below_tboot(lowest) )
        from = lowest;
    else
    {
        if ( below_tboot((unsigned long)lctx->addr) )
            from = (unsigned long)lctx->addr;
        else
        {
            printk(TBOOT_INFO"No module below tboot, all good.\n");
            return;
        }
    }

    unsigned long highest = get_highest_mod_end(lctx);
    printk(TBOOT_INFO"Highest mod end: 0x%lx\n", highest);
    unsigned long to = PAGE_UP(highest);
    printk(TBOOT_INFO"Initial mod destination: 0x%lx\n", to);


    tboot_mem_end = get_tboot_mem_end();
    printk(TBOOT_INFO"TBOOT memory end: 0x%lx\n", tboot_mem_end);
    if ( to < tboot_mem_end )
    {
        to = tboot_mem_end;
        printk(TBOOT_INFO"New module destination: 0x%lx\n", to);
    }
    
    /*
     * assuming that all of the members of mbi (e.g. cmdline, 
     * syms.aout_image.addr, etc.) are contiguous with the mbi structure
     */
    if ( to < get_loader_ctx_end(lctx) )
        to = get_loader_ctx_end(lctx);

    tb_memcpy((void *)to, (void *)from, TBOOT_BASE_ADDR - from);
    
    printk(TBOOT_DETA"0x%lx bytes copied from 0x%lx to 0x%lx\n",
           TBOOT_BASE_ADDR - from, from, to);
    fixup_loader_ctx(lctx, to - from);
    return;
}

module_t *get_module(loader_ctx *lctx, unsigned int i)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;
    if (lctx->type == MB1_ONLY){
        return(get_module_mb1((multiboot_info_t *) lctx->addr, i));
    } else {
        /* so currently, must be type 2 */
        return(get_module_mb2(lctx, i));
    }
}

static void *remove_first_module(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;
    return(remove_module(lctx, NULL));
}

/* a shame this has to be so big, but if we get an MB2 VBE struct,
 * those are pretty close to 1K on their own.
 */
#define MB2_TEMP_SIZE 512
static uint32_t mb2_temp[MB2_TEMP_SIZE];

static bool convert_mb2_to_mb1(void)
{
    /* it's too hard to do this in place.  MB2 "data" is all inline, so
     * it can be copied to a new location, as is, and still be intact.  MB1
     * has pointers in the info struct to other stuff further along in its
     * stuff, so it doesn't copy/move well.  We'll make a copy of the MB2
     * info, and then build the MB1 in place where the MB2 we started with was.
     */
    uint32_t mb2_size;
    multiboot_info_t *mbi;
    uint32_t i, obd;
    
    if (LOADER_CTX_BAD(g_ldr_ctx))
        return false;
    if (g_ldr_ctx->type != MB2_ONLY)
        return false;
    mb2_size = *((uint32_t *)g_ldr_ctx->addr);
    if (mb2_size >= MB2_TEMP_SIZE * 4)
        return false;
    /* copy it all to temp */
    {
        uint8_t *s, *d;
        s = (uint8_t *) g_ldr_ctx->addr;
        d = (uint8_t *) mb2_temp;
        for (i = 0; i < mb2_size; i++)
            d[i] = s[i];
        mbi = (multiboot_info_t *) g_ldr_ctx->addr;
        g_ldr_ctx->addr = mb2_temp;
        for (i = 0; i < mb2_size; i++)
            ((uint8_t *)mbi)[i] = 0;
    }

    /* out of band data pointer */
    obd = (uint32_t) mbi + sizeof(multiboot_info_t);
    /* uint32 align it, just in case */
    obd = (obd + 3) & ~3;

    /* do we have mem_limits? */
    if (have_loader_memlimits(g_ldr_ctx)){
        mbi->flags |= MBI_MEMLIMITS;
        mbi->mem_lower = get_loader_mem_lower(g_ldr_ctx);
        mbi->mem_upper = get_loader_mem_upper(g_ldr_ctx);
    }

    /* do we have a boot device? */
    {
        struct mb2_tag *start = (struct mb2_tag *)(g_ldr_ctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_BOOTDEV);
        if (start != NULL){
            struct mb2_tag_bootdev *bd = (struct mb2_tag_bootdev *) start;
            mbi->flags |= MBI_BOOTDEV;
            mbi->boot_device.bios_driver = bd->biosdev;
            mbi->boot_device.top_level_partition = bd->part;
            mbi->boot_device.sub_partition = bd->slice;
            mbi->boot_device.third_partition = 0xff;
        }
    }
    /* command line */
    {
        const char *mb2_cmd = get_cmdline(g_ldr_ctx);
        if (mb2_cmd){
            char *mb1_cmd = (char *) obd;
            while (*mb2_cmd){
                *mb1_cmd = *mb2_cmd;
                mb1_cmd++; mb2_cmd++; obd++;
            }
            /* uint32_t align it again */
            obd = (obd + 3) & ~3;
            mbi->flags |= MBI_CMDLINE;
        }
    }
    /* modules--in MB1, this is a count and a pointer to an array of module_t */
    mbi->mods_count = get_module_count(g_ldr_ctx);
    if (mbi->mods_count > 0){
        /* for mb1, the modulke strings are out-of-band */
        uint32_t obd_str = obd + (mbi->mods_count * sizeof(module_t));

        mbi->mods_addr = obd;
        
        for (i = 0; i < mbi->mods_count; i++){
            module_t *mb1_mt = (module_t *) obd;
            module_t *mb2_mt = get_module(g_ldr_ctx, i);
            char *s = (char *)&mb2_mt->string;
            mb1_mt->mod_start = mb2_mt->mod_start;
            mb1_mt->mod_end = mb2_mt->mod_end;
            mb1_mt->reserved = 0;
            if (*s){
                char *d = (char *) obd_str;
                mb1_mt->string = obd_str;
                while (*s){
                    *d = *s;
                    d++; s++; obd_str++;
                }
                *d = *s; obd_str++;
            } else {
                mb1_mt->string = 0;
            }
        }
        /* uint32_t align past the strings */
        obd = (obd_str + 3) & ~3;
        mbi->flags |= MBI_MODULES;
    }

    /* a.out/elf sections--we know these are not there */
    
    /* memory map--we can just use the modified copy for this one */
    if (have_loader_memmap(g_ldr_ctx)){
        mbi->mmap_addr = (uint32_t)get_e820_copy();
        mbi->mmap_length = (get_nr_map()) * sizeof(memory_map_t);
        mbi->flags |= MBI_MEMMAP;
    }

    /* drives info --there's no equivalent in MB2 */

    /* config table -- again, nothing equivalent? */

    /* boot loader name */
    {
        struct mb2_tag *start = (struct mb2_tag *)(g_ldr_ctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_LOADER_NAME);
        if (start){
            struct mb2_tag_string *bload = (struct mb2_tag_string *) start;
            char *s, *d;
            mbi->boot_loader_name = obd;
            s = (char *) &bload->string[0];
            d = (char *) obd;
            while (*s){
                *d = *s;
                s++; d++; obd++;
            }
            *d = *s; obd++;
            obd = (obd + 3) & ~3;
            mbi->flags |= MBI_BTLDNAME;
        }
    }

    /* apm table */
    {
        struct mb2_tag *start = (struct mb2_tag *)(g_ldr_ctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_APM);
        if (start){
            struct mb2_tag_apm *apm = (struct mb2_tag_apm *) start;
            uint8_t *s, *d;
            s = (uint8_t *)&apm->version;
            d = (uint8_t *) obd;  mbi->apm_table = obd;
            for (i = 0; 
                 i < sizeof(struct mb2_tag_apm) - 2*sizeof(uint32_t);
                 i++){
                *d = *s;
                d++; s++; obd++;
            }
            obd = (obd + 3) & ~3;
            mbi->flags |= MBI_APM;
        }
    }

    /* vbe poop, if we can get these to map across */
    {
        struct mb2_tag *start = (struct mb2_tag *)(g_ldr_ctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_VBE);
        if (start){
            struct mb2_tag_vbe *vbe = (struct mb2_tag_vbe *) start;
            uint8_t *s, *d;
            mbi->vbe_mode = vbe->vbe_mode;
            mbi->vbe_interface_seg = vbe->vbe_interface_seg;
            mbi->vbe_interface_off = vbe->vbe_interface_off;
            mbi->vbe_interface_len = vbe->vbe_interface_len;
            mbi->vbe_control_info = obd;
            d = (uint8_t *) obd;
            s = &vbe->vbe_control_info.external_specification[0];
            for (i = 0; i < 512; i++){
                *d = *s;
                d++; s++; obd++;
            }
            /* if obd was aligned before, it still is */
            mbi->vbe_mode_info = obd;
            d = (uint8_t *) obd;
            s = &vbe->vbe_mode_info.external_specification[0];
            for (i = 0; i < 256; i++){
                *d = *s;
                d++; s++; obd++;
            }
            mbi->flags |= MBI_VBE;
        }
    }
    /* all good--point g_ldr_ctx addr to new, fix type */
    g_ldr_ctx->addr = (void *)&mbi;
    g_ldr_ctx->type = MB1_ONLY;
    return true;
}


static uint32_t
determine_multiboot_type(void *image)
{
    /* walk through the allowed region looking for multiboot header magic */
    /* note that we're going low-tech--we're not verifying a valid header,
     * and probably should.
     */
    int result = MB_NONE;
    void *walker;
    for (walker = image; walker < image + MULTIBOOT_HEADER_SEARCH_LIMIT;
         walker += sizeof(uint32_t)){
        if (*((uint32_t *)walker) == MULTIBOOT_HEADER_MAGIC){
            result += MB1_ONLY;
            break;
        }
    }
    for (walker = image; walker < image + MB2_HEADER_SEARCH_LIMIT;
         walker += sizeof(uint64_t)){
        if (*((uint32_t *)walker) == MB2_HEADER_MAGIC){
            result += MB2_ONLY;
            break;
        }
    }
    return result;
}

bool launch_kernel(bool is_measured_launch)
{
    enum { ELF, LINUX } kernel_type;

    void *kernel_entry_point;
    uint32_t mb_type = MB_NONE;
    struct tpm_if *tpm = get_tpm();

    if (g_tpm_family != TPM_IF_20_CRB ) {
        if (!release_locality(tpm->cur_loc))
            printk(TBOOT_ERR"Release TPM FIFO locality %d failed \n", tpm->cur_loc);
    }
    else {
        if (!tpm_relinquish_locality_crb(tpm->cur_loc))
            printk(TBOOT_ERR"Relinquish TPM CRB locality %d failed \n", tpm->cur_loc);
        if (!tpm_workaround_crb())
            printk(TBOOT_ERR"CRB workaround failed \n");
    }

    /* if using memory logging, reserve log area */
    if ( g_log_targets & TBOOT_LOG_TARGET_MEMORY ) {
        uint64_t base = TBOOT_SERIAL_LOG_ADDR;
        uint64_t size = TBOOT_SERIAL_LOG_SIZE;
        printk(TBOOT_INFO"reserving tboot memory log (%Lx - %Lx) in e820 table\n", base, (base + size - 1));
        if ( !e820_protect_region(base, size, E820_RESERVED) )
            apply_policy(TB_ERR_FATAL);
        if (!efi_memmap_reserve(base, size)) {
            apply_policy(TB_ERR_FATAL);
        }
    }

    /* replace map in loader context with copy */
    replace_e820_map(g_ldr_ctx);

    if (get_tboot_dump_memmap()) {
        printk(TBOOT_DETA"adjusted e820 map:\n");
        print_e820_map();
    }

    if ( !verify_loader_context(g_ldr_ctx) )
        return false;

    /* remove all SINIT and LCP modules since kernel may not handle */
    remove_txt_modules(g_ldr_ctx);

    module_t *m = get_module(g_ldr_ctx,0);

    void *kernel_image = (void *)m->mod_start;
    size_t kernel_size = m->mod_end - m->mod_start;

    if ( is_elf_image(kernel_image, kernel_size) ) {
        printk(TBOOT_INFO"kernel is ELF format\n");
        kernel_type = ELF;
        mb_type = determine_multiboot_type(kernel_image);
        switch (mb_type){
        case MB1_ONLY:
            /* if this is an EFI boot, this is not sufficient */
            if (is_loader_launch_efi(g_ldr_ctx)){
                printk(TBOOT_ERR"Target kernel only supports multiboot1 ");
                printk(TBOOT_ERR"which will not suffice for EFI launch\n");
                return false;
            }
            /* if we got MB2 and they want MB1 and this is trad BIOS,
             * we can downrev the MB data to MB1 and pass that along.
             */
            if (g_ldr_ctx->type == MB2_ONLY){
                if (false == convert_mb2_to_mb1())
                    return false;
            }
            break;
        case MB2_ONLY:
            /* if we got MB1, we need to die here */
            if (g_ldr_ctx->type == MB1_ONLY){
                printk(TBOOT_ERR"Target requires multiboot 2, loader only ");
                printk(TBOOT_ERR"supplied multiboot 1m giving up\n");
                return false;
            }
            break;
        case MB_BOTH:
            /* we'll pass through whichever we got, and hope */
            mb_type = g_ldr_ctx->type;
            break;
        default:
            printk(TBOOT_INFO"but kernel does not have multiboot header\n");
            return false;
        }
        
        /* fix for GRUB2, which may load modules into memory before tboot */
        move_modules(g_ldr_ctx);

        /* move modules out of the way (to top og memory below 4G) */
        printk(TBOOT_INFO"move modules to high memory\n");
        if(!move_modules_to_high_memory(g_ldr_ctx))
            return false;
    }
    else {
        printk(TBOOT_INFO"assuming kernel is Linux format\n");
        kernel_type = LINUX;
    }

    /* print_mbi(g_mbi); */

    kernel_image = remove_first_module(g_ldr_ctx);
    if ( kernel_image == NULL )
        return false;

    if ( kernel_type == ELF ) {
        if ( is_measured_launch )
            adjust_kernel_cmdline(g_ldr_ctx, &_tboot_shared);
        if ( !expand_elf_image((elf_header_t *)kernel_image,
                               &kernel_entry_point) )
            return false;

        /* move modules on top of expanded kernel */
        if(!move_modules_above_elf_kernel(g_ldr_ctx, (elf_header_t *)kernel_image))
            return false;

        printk(TBOOT_INFO"transfering control to kernel @%p...\n", 
               kernel_entry_point);
        /* (optionally) pause when transferring to kernel */
        if ( g_vga_delay > 0 )
            delay(g_vga_delay * 1000);
        return jump_elf_image(kernel_entry_point, 
                              mb_type == MB1_ONLY ?
                              MB_MAGIC : MB2_LOADER_MAGIC);
    }
    else if ( kernel_type == LINUX ) {
        void *initrd_image;
        size_t initrd_size;

        if ( get_module_count(g_ldr_ctx) == 0 ) {
            initrd_size = 0;
            initrd_image = 0;
        }
        else {
            m = get_module(g_ldr_ctx,0);
            initrd_image = (void *)m->mod_start;
            initrd_size = m->mod_end - m->mod_start;
        }

        expand_linux_image(kernel_image, kernel_size,
                           initrd_image, initrd_size,
                           &kernel_entry_point, is_measured_launch);
        printk(TBOOT_INFO"transfering control to kernel @%p...\n", 
               kernel_entry_point);
        /* (optionally) pause when transferring to kernel */
        if ( g_vga_delay > 0 )
            delay(g_vga_delay * 1000);
        return jump_linux_image(kernel_entry_point);
    }

    printk(TBOOT_ERR"unknown kernel type\n");
    return false;
}

/*
 * find_module_by_uuid
 *
 * find a module by its uuid
 *
 */
bool find_module_by_uuid(loader_ctx *lctx, void **base, size_t *size,
                         const uuid_t *uuid)
{
    return find_module(lctx, base, size, uuid, sizeof(*uuid));
}

/*
 * find_module_by_file_signature
 *
 * find a module by its file signature
 *
 */
bool 
find_module_by_file_signature(loader_ctx *lctx, void **base,
                              size_t *size, const char* file_signature)
{
    return find_module(lctx, base, size, 
                       file_signature, tb_strlen(file_signature));
}

bool 
verify_modules(loader_ctx *lctx)
{
    uint64_t base, size;
    module_t *m;
    uint32_t module_count;

    if (LOADER_CTX_BAD(lctx))
        return false;
        
    module_count = get_module_count(lctx);
        
    /* verify e820 map to make sure each module is OK in e820 map */
    /* check modules in mbi should be in RAM */
    for ( unsigned int i = 0; i < module_count; i++ ) {
        m = get_module(lctx,i);
        base = m->mod_start;
        size = m->mod_end - m->mod_start;
        printk(TBOOT_INFO
               "verifying module %d of mbi (%Lx - %Lx) in e820 table\n\t",
               i, base, (base + size - 1));
        if ( e820_check_region(base, size) != E820_RAM ) {
            printk(TBOOT_ERR": failed.\n");
            return false;
        }
        else
            printk(TBOOT_INFO": succeeded.\n");
    }
    return true;
}

char *get_module_cmd(loader_ctx *lctx, module_t *mod)
{
    if (LOADER_CTX_BAD(lctx) || mod == NULL)
        return NULL;

    if (lctx->type == MB1_ONLY)
        return (char *) mod->string;
    else /* currently must be type 2 */
        return (char *)&(mod->string);
}

char *get_first_module_cmd(loader_ctx *lctx)
{
    module_t *mod = get_module(lctx, 0);
    return get_module_cmd(lctx, mod);
}

char *get_cmdline(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;

    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        if (((multiboot_info_t *)lctx->addr)->flags & MBI_CMDLINE){
            return (char *) ((multiboot_info_t *)lctx->addr)->cmdline;
        } else {
            return NULL;
        }
    } else { 
        /* currently must be type  2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_CMDLINE);
        if (start != NULL){
            struct mb2_tag_string *cmd = (struct mb2_tag_string *) start;
            return (char *) &(cmd->string);
        }
        return NULL;
    }
}

bool have_loader_memlimits(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return false;
    if (lctx->type == MB1_ONLY){
        return (((multiboot_info_t *)lctx->addr)->flags & MBI_MEMLIMITS) != 0;
    } else {
        /* currently must be type 2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_MEMLIMITS);
        return (start != NULL);
    }
}

uint32_t get_loader_mem_lower(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        return ((multiboot_info_t *)lctx->addr)->mem_lower;
    }
    /* currently must be type 2 */
    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_MEMLIMITS);
    if (start != NULL){
        struct mb2_tag_memlimits *lim = (struct mb2_tag_memlimits *) start;
        return lim->mem_lower;
    }
    return 0;
}

uint32_t get_loader_mem_upper(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        return ((multiboot_info_t *)lctx->addr)->mem_upper;
    }
    /* currently must be type 2 */
    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_MEMLIMITS);
    if (start != NULL){
        struct mb2_tag_memlimits *lim = (struct mb2_tag_memlimits *) start;
        return lim->mem_upper;
    }
    return 0;
}

unsigned int get_module_count(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        return(((multiboot_info_t *) lctx->addr)->mods_count);
    } else {
        /* currently must be type 2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        unsigned int count = 0;
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
        while (start != NULL){
            count++;
            /* nudge off this guy */
            start = next_mb2_tag(start);
            start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
        }
        return count;
    }
}

bool have_loader_memmap(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return false;
    if (lctx->type == MB1_ONLY){
        return (((multiboot_info_t *) lctx->addr)->flags & MBI_MEMMAP) != 0;
    } else {
        /* currently must be type 2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_MMAP);
        return (start != NULL);
    }
}

memory_map_t *get_loader_memmap(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;
    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        return (memory_map_t *)((multiboot_info_t *) lctx->addr)->mmap_addr;
    } else {
        /* currently must be type 2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_MMAP);
        if (start != NULL){
            struct mb2_tag_mmap *mmap = (struct mb2_tag_mmap *) start;
            /* note here: the MB2 mem entries start with the 64-bit address.
             * the memory_map_t starts with four bytes of dummy "size".
             * Pointing to the MB2 mmap "entry_version" instead of the entries
             * lines the two tables up.
             */
            return (memory_map_t *) &(mmap->entry_version);
        }
        return NULL;
    }
}

uint32_t get_loader_memmap_length(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        return (uint32_t)((multiboot_info_t *) lctx->addr)->mmap_length;
    } else {
        /* currently must be type 2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_MMAP);
        if (start != NULL){
            struct mb2_tag_mmap *mmap = (struct mb2_tag_mmap *) start;
            /* mmap->size is the size of the whole tag.  We have 16 bytes
             * ahead of the entries
             */
            return mmap->size - 16;
        }
        return 0;
    }
}

unsigned long
get_loader_ctx_end(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == 1){
        /* multiboot 1 */
        return (get_mbi_mem_end_mb1((multiboot_info_t *) lctx->addr));
    } else {
        /* currently must be type 2 */
        unsigned long mb2_size = *((unsigned long *) lctx->addr);
        return PAGE_UP(mb2_size + (unsigned long) lctx->addr);
    }
}

/*
 * will go through all modules to find an RACM that matches the platform
 * (size can be NULL)
 */
bool 
find_platform_racm(loader_ctx *lctx, void **base, uint32_t *size)
{
    if ( base != NULL )
        *base = NULL;
    if ( size != NULL )
        *size = 0;

    if ( 0 == get_module_count(lctx)) {
        printk(TBOOT_ERR"no module info\n");
        return false;
    }

    for ( int i = get_module_count(lctx) - 1; i >= 0; i-- ) {
        module_t *m = get_module(lctx, i);
        printk(TBOOT_DETA
               "checking if module %s is an RACM for this platform...\n",
               get_module_cmd(lctx, m));
        void *base2 = (void *)m->mod_start;
        uint32_t size2 = m->mod_end - (unsigned long)(base2);
        if ( is_racm_acmod(base2, size2, false) &&
             does_acmod_match_platform((acm_hdr_t *)base2, NULL) ) {
            if ( base != NULL )
                *base = base2;
            if ( size != NULL )
                *size = size2;
            printk(TBOOT_DETA"RACM matches platform\n");
            return true;
        }
    }
    /* no RACM found for this platform */
    printk(TBOOT_ERR"no RACM found\n");
    return false;
}

/*
 * Check if two memory regions overlap
 */
static bool
regions_overlap(const void *base1, size_t size1, const void *base2, size_t size2) {
    /*
      11111
        22222
    */
    if (base1 <= base2 && base2 < base1 + size1) {
        return true;
    }
    /*
        11111
      22222
    */
    if (base2 <= base1 && base1 < base2 + size2) {
        return true;
    }
    /*
        1
      22222
    */
    if (base2 <= base1 && base1 + size1 < base2 + size2) {
        return true;
    }
    /*
      11111
        2
    */
    if (base1 <= base2 && base2 + size2 < base1 + size1) {
        return true;
    }
    return false;
}

/*
 * will go through all modules to find an SINIT that matches the platform
 * (size can be NULL)
 */
bool 
find_platform_sinit_module(loader_ctx *lctx, void **base, uint32_t *size)
{
    if ( base != NULL )
        *base = NULL;
    if ( size != NULL )
        *size = 0;

    if ( 0 == get_module_count(lctx)) {
        printk(TBOOT_ERR"no module info\n");
        return false;
    }

    for ( unsigned int i = get_module_count(lctx) - 1; i > 0; i-- ) {
        module_t *m = get_module(lctx, i);
        if (lctx->type == 1)
            printk(TBOOT_DETA
                   "checking if module %s is an SINIT for this platform...\n",
                   (const char *)m->string);
        if (lctx->type == 2)
            printk(TBOOT_DETA
                   "checking if module %s is an SINIT for this platform...\n",
                   (const char *)&(m->string));

        void *base2 = (void *)m->mod_start;
        uint32_t size2 = m->mod_end - (unsigned long)(base2);
        if (regions_overlap(base2, size2,
                            (void*)TBOOT_LOWMEM_START, TBOOT_LOWMEM_END - TBOOT_LOWMEM_START)) {
            printk(TBOOT_DETA "Ignoring module as it overlaps with tboot's internal data structures\n");
            continue;
        }
        if ( is_sinit_acmod(base2, size2, false) &&
             does_acmod_match_platform((acm_hdr_t *)base2, NULL) ) {
            if ( base != NULL )
                *base = base2;
            if ( size != NULL )
                *size = size2;
            printk(TBOOT_DETA"SINIT matches platform\n");
            return true;
        }
    }
    /* no SINIT found for this platform */
    printk(TBOOT_ERR"no SINIT AC module found\n");
    return false;
}

void 
replace_e820_map(loader_ctx *lctx)
{
    /* replace original with the copy */
    if (LOADER_CTX_BAD(lctx))
        return;
    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        multiboot_info_t *mbi = (multiboot_info_t *) lctx->addr;
        mbi->mmap_addr = (uint32_t)get_e820_copy();
        mbi->mmap_length = (get_nr_map()) * sizeof(memory_map_t);
        mbi->flags |= MBI_MEMMAP;   /* in case only MBI_MEMLIMITS was set */
        return;
    } else {
        /* currently must be type 2 */
        memory_map_t *old, *new;
        uint32_t i;
        uint32_t old_memmap_size = get_loader_memmap_length(lctx);
        uint32_t old_memmap_entry_count = 
            old_memmap_size / sizeof(memory_map_t);
        if (old_memmap_entry_count < (get_nr_map())){
            /* we have to grow */
            struct mb2_tag *map = (struct mb2_tag *)(lctx->addr + 8);
            map = find_mb2_tag_type(map, MB2_TAG_TYPE_MMAP);
            if (map == NULL){
                printk(TBOOT_ERR"MB2 map not found\n");
                return;
            }
            if (false ==
                grow_mb2_tag(lctx, map, 
                             sizeof(memory_map_t) *
                             ((get_nr_map()) - old_memmap_entry_count))){
                printk(TBOOT_ERR"MB2 failed to grow e820 map tag\n");
                return;
            }
        }
        /* copy in new data */
        {
            /* RLM: for now, we'll leave the entries in MB1 format (with real
             * size).  That may need revisited.
             */
            new = get_e820_copy();
            old = get_loader_memmap(lctx);
            if ( old == NULL ) {
                printk(TBOOT_ERR"old memory map not found\n");
                return;
            }
            for (i = 0; i < (get_nr_map()); i++){
                *old = *new;
                old++, new++;
            }
        }
        return;
    }
    return;
}

void print_loader_ctx(loader_ctx *lctx)
{
    if (lctx->type != MB2_ONLY){
        printk(TBOOT_ERR"this routine only prints out multiboot 2\n");
        return;
    } else {
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        printk(TBOOT_INFO"MB2 dump: addr %p, size %d\n", lctx->addr,
               *(uint32_t *)lctx->addr);
        while (start != NULL){
            printk(TBOOT_INFO"MB2 tag found of type %d size %d ", 
                   start->type, start->size);
            switch (start->type){
            case MB2_TAG_TYPE_CMDLINE:
            case MB2_TAG_TYPE_LOADER_NAME:
                {
                    struct mb2_tag_string *ts = 
                        (struct mb2_tag_string *) start;
                    printk(TBOOT_INFO"%s", ts->string);
                }
                break;
            case MB2_TAG_TYPE_MODULE:
                {
                    struct mb2_tag_module *ts =
                        (struct mb2_tag_module *) start;
                    printk(TBOOT_INFO"mod_start: 0x%x, mod_end: 0x%x",
                           ts->mod_start, ts->mod_end);
                    printk_long(ts->cmdline);
                }
                break;
            default:
                break;
            }
            printk(TBOOT_INFO"\n");
            start = next_mb2_tag(start);
        }
        return;
    }
}

uint8_t
*get_loader_rsdp(loader_ctx *lctx, uint32_t *length)
{
    struct mb2_tag *start;
    struct mb2_tag_new_acpi *new_acpi;

    if (LOADER_CTX_BAD(lctx))
        return NULL;
    if (lctx->type != MB2_ONLY)
        return NULL;
    if (length == NULL)
        return NULL;

    start = (struct mb2_tag *) (lctx->addr + 8);
    new_acpi = (struct mb2_tag_new_acpi *) 
        find_mb2_tag_type(start, MB2_TAG_TYPE_ACPI_NEW);
    if (new_acpi == NULL){
        /* we'll try the old type--the tag structs are the same */
        new_acpi = (struct mb2_tag_new_acpi *) 
            find_mb2_tag_type(start, MB2_TAG_TYPE_ACPI_OLD);
        if (new_acpi == NULL)
            return NULL;
    }
    *length = new_acpi->size - 8;
    return new_acpi->rsdp;
}

bool
get_loader_efi_ptr(loader_ctx *lctx, uint32_t *address, uint64_t *long_address)
{
    struct mb2_tag *start, *hit;
    struct mb2_tag_efi32 *efi32;
    struct mb2_tag_efi64 *efi64;
    if (LOADER_CTX_BAD(lctx))
        return false;
    if (lctx->type != MB2_ONLY)
        return false;
    start = (struct mb2_tag *)(lctx->addr + 8);
    hit = find_mb2_tag_type(start, MB2_TAG_TYPE_EFI32);
    if (hit != NULL){
        efi32 = (struct mb2_tag_efi32 *) hit;
        *address = (uint32_t) efi32->pointer;
        *long_address = 0;
        return true;
    }
    hit = find_mb2_tag_type(start, MB2_TAG_TYPE_EFI64);
    if (hit != NULL){
        efi64 = (struct mb2_tag_efi64 *) hit;
        *long_address = (uint64_t) efi64->pointer;
        *address = 0;
        return true;
    }
    return false;
}


uint32_t
find_efi_memmap(loader_ctx *lctx, uint32_t *descr_size,
                uint32_t *descr_vers, uint32_t *mmap_size) {
    struct mb2_tag *start = NULL, *hit = NULL;
    struct mb2_tag_efi_mmap *efi_mmap = NULL;

    if (LOADER_CTX_BAD(lctx) || lctx->type != MB2_ONLY) {
        return 0;
    }
    if (descr_size == NULL || descr_vers == NULL || mmap_size == NULL) {
        return 0;
    }

    start = (struct mb2_tag *)(lctx->addr + 8);
    hit = find_mb2_tag_type(start, MB2_TAG_TYPE_EFI_MMAP);
    if (hit == NULL) {
       return 0;
    }

    efi_mmap = (struct mb2_tag_efi_mmap *)hit;
    *descr_size = efi_mmap->descr_size;
    *descr_vers = efi_mmap->descr_vers;
    *mmap_size = efi_mmap->size - sizeof(struct mb2_tag_efi_mmap);
    if (*mmap_size % *descr_size) {
        printk(TBOOT_WARN "EFI memmmap (0x%x) should be a multiple of descriptor size (0x%x)\n",
	       *mmap_size, *descr_size);
    }
    return (uint32_t)(&efi_mmap->efi_mmap);
}

bool
is_loader_launch_efi(loader_ctx *lctx)
{
    uint32_t addr = 0; uint64_t long_addr = 0;
    if (LOADER_CTX_BAD(lctx))
        return false;
    return (get_loader_efi_ptr(lctx, &addr, &long_addr));
}

bool load_framebuffer_info(loader_ctx *lctx, void *vscr, bool efifb)
{
    screen_info_t *scr = (screen_info_t *) vscr;
    struct mb2_tag *start;

    if (scr == NULL)
        return false;
    if (LOADER_CTX_BAD(lctx) || lctx->type != MB2_ONLY)
        return false;
    start = (struct mb2_tag *)(lctx->addr + 8);
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_FRAMEBUFFER);
    if (start != NULL){
        u32 ext_lfb_base;
        struct mb2_fb *mbf = (struct mb2_fb *) start;

        scr->lfb_base = (uint32_t) mbf->common.fb_addr;
        ext_lfb_base = (u64)mbf->common.fb_addr >> 32;
        if (ext_lfb_base != 0) {
            scr->capabilities |= VIDEO_CAPABILITY_64BIT_BASE;
            scr->ext_lfb_base = ext_lfb_base;
        }
        scr->lfb_width = mbf->common.fb_width;
        scr->lfb_height = mbf->common.fb_height;
        scr->lfb_depth =  mbf->common.fb_bpp;
        scr->lfb_line_len = mbf->common.fb_pitch;
        scr->red_mask_size = mbf->fb_red_mask_size; 
        scr->red_field_pos = mbf->fb_red_field_position; 
        scr->blue_mask_size = mbf->fb_blue_mask_size; 
        scr->blue_field_pos = mbf->fb_blue_field_position; 
        scr->green_mask_size = mbf->fb_green_mask_size; 
        scr->green_field_pos = mbf->fb_green_field_position; 

        scr->lfb_size = scr->lfb_line_len * scr->lfb_height;
        /* round up to next 64k */
        scr->lfb_size = (scr->lfb_size + 65535) & 65535;
        
        if (efifb) {
            scr->orig_video_isVGA = 0x70; /* EFI FB */
        } else {
            scr->orig_video_isVGA = 0x23; /* VESA VGA */
        }
        scr->orig_y = 24;
        return true;
    } else {
        return false;
    }

}

struct mb2_fb* get_framebuffer_info(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx) || lctx->type != MB2_ONLY) {
        return NULL;
    }

    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    return (struct mb2_fb*)find_mb2_tag_type(start, MB2_TAG_TYPE_FRAMEBUFFER);
}

void determine_loader_type(void *addr, uint32_t magic)
{
    if (g_ldr_ctx->addr == NULL){
        /* brave new world */
        g_ldr_ctx->addr = addr;  /* save for post launch */
        switch (magic){
        case MB_MAGIC:
            g_ldr_ctx->type = MB1_ONLY;
            { 
                /* we may as well do this here--if we received an ELF
                 * sections tag, we won't use it, and it's useless to
                 * Xen downstream, since it's OUR ELF sections, not Xen's
                 */
                multiboot_info_t *mbi = 
                    (multiboot_info_t *) addr;
                if (mbi->flags & MBI_AOUT){
                    mbi->flags &= ~MBI_AOUT;
                }
                if (mbi->flags & MBI_ELF){
                    mbi->flags &= ~MBI_ELF;
                }
            }
            break;
        case MB2_LOADER_MAGIC:
            g_ldr_ctx->type = MB2_ONLY;
            /* save the original MB2 info size, since we have
             * to put updates inline
             */
            g_mb_orig_size = *(uint32_t *) addr;
            {
                /* we may as well do this here--if we received an ELF
                 * sections tag, we won't use it, and it's useless to
                 * Xen downstream, since it's OUR ELF sections, not Xen's
                 */
                struct mb2_tag *start =
                    (struct mb2_tag *)(addr + 8);
                start = find_mb2_tag_type(start, MB2_TAG_TYPE_ELF_SECTIONS);
                if (start != NULL)
                    (void) remove_mb2_tag(g_ldr_ctx, start);
            }
            break;
        default:
            g_ldr_ctx->type = 0;
            break;
        }
    }
    /* so at this point, g_ldr_ctx->type has one of three values:
     * 0: not a multiboot launch--we're doomed
     * 1: MB1 launch
     * 2: MB2 launch
     */
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
