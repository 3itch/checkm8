/*
 * loader.h: support functions for manipulating ELF and AOUT binaries
 *
 * Copyright (c) 2006-2013, Intel Corporation
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

#ifndef __LOADER_H__
#define __LOADER_H__

typedef struct {
    void *addr;
    uint32_t type;
} loader_ctx;

extern loader_ctx *g_ldr_ctx;

#ifndef __MULTIBOOT_H__
/* a few useful utility types */
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
#endif

extern void print_loader_ctx(loader_ctx *lctx);
extern bool find_module_by_uuid(loader_ctx *lctx, void **base,
                                size_t *size, const uuid_t *uuid);
extern bool find_module_by_file_signature(loader_ctx *lctx,
                                          void **base, size_t *size,
                                          const char* file_signature);
extern bool find_platform_racm(loader_ctx *lctx, void **base, uint32_t *size);
extern bool find_platform_sinit_module(loader_ctx *lctx, void **base, 
                                       uint32_t *size);
extern bool find_lcp_module(loader_ctx *lctx, void **base, uint32_t *size);


extern bool is_kernel_linux(void);

extern uint32_t find_efi_memmap(loader_ctx *lctx, uint32_t *descr_size,
                                uint32_t *descr_vers, uint32_t *mmap_size);

extern bool launch_kernel(bool is_measured_launch);
extern bool verify_loader_context(loader_ctx *lctx);
extern bool verify_modules(loader_ctx *lctx);
extern module_t *get_module(loader_ctx *lctx, unsigned int i);
extern unsigned int get_module_count(loader_ctx *lctx);
extern bool remove_txt_modules(loader_ctx *lctx);

extern bool	have_loader_memlimits(loader_ctx *lctx);
extern bool have_loader_memmap(loader_ctx *lctx);
extern memory_map_t *get_loader_memmap(loader_ctx *lctx);
extern uint32_t get_loader_memmap_length(loader_ctx *lctx);
extern uint32_t get_loader_mem_lower(loader_ctx *lctx);
extern uint32_t	get_loader_mem_upper(loader_ctx *lctx);
extern char *get_module_cmd(loader_ctx *lctx, module_t *mod);
extern char *get_cmdline(loader_ctx *lctx);
extern void determine_loader_type(void *addr, uint32_t magic);
extern unsigned long get_loader_ctx_end(loader_ctx *lctx);
extern void replace_e820_map(loader_ctx *lctx);
extern uint8_t *get_loader_rsdp(loader_ctx *lctx, uint32_t *length);
extern bool is_loader_launch_efi(loader_ctx *lctx);
extern bool get_loader_efi_ptr(loader_ctx *lctx, uint32_t *address, 
                               uint64_t *long_address);
extern bool load_framebuffer_info(loader_ctx *lctx, void *vscr, bool efifb);
extern char *get_first_module_cmd(loader_ctx *lctx);
extern struct mb2_fb* get_framebuffer_info(loader_ctx *lctx);
extern void move_modules(loader_ctx *lctx);

#endif /* __LOADER_H__ */



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
