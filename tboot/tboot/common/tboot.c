/*
 * tboot.c: main entry point and "generic" routines for measured launch
 *          support
 *
 * Copyright (c) 2006-2010, Intel Corporation
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
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <printk.h>
#include <uuid.h>
#include <loader.h>
#include <processor.h>
#include <misc.h>
#include <page.h>
#include <msr.h>
#include <atomic.h>
#include <io.h>
#include <mutex.h>
#include <e820.h>
#include <uuid.h>
#include <loader.h>
#include <hash.h>
#include <mle.h>
#include <tpm.h>
#include <tb_error.h>
#include <txt/txt.h>
#include <txt/vmcs.h>
#include <txt/smx.h>
#include <txt/mtrrs.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#include <txt/verify.h>
#include <tb_policy.h>
#include <tboot.h>
#include <acpi.h>
#include <integrity.h>
#include <cmdline.h>
#include <tpm_20.h>
#include <vtd.h>
#include <efi_memmap.h>

extern void _prot_to_real(uint32_t dist_addr);
extern bool set_policy(void);
extern void verify_all_modules(loader_ctx *lctx);
extern void verify_all_nvindices(void);
extern void apply_policy(tb_error_t error);
extern void verify_IA32_se_svn_status(const acm_hdr_t *acm_hdr);
void s3_launch(void);
extern __data u32 handle2048;
extern __data tpm_contextsave_out tpm2_context_saved;
/* counter timeout for waiting for all APs to exit guests */
#define AP_GUEST_EXIT_TIMEOUT     0x01000000

extern long s3_flag;

extern char s3_wakeup_16[];
extern char s3_wakeup_end[];

extern atomic_t ap_wfs_count;

extern struct mutex ap_lock;

/* loader context struct saved so that post_launch() can use it */
__data loader_ctx g_loader_ctx = { NULL, 0 };
__data loader_ctx *g_ldr_ctx = &g_loader_ctx;
__data uint32_t g_mb_orig_size = 0;


/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/*
 * caution: must make sure the total wakeup entry code length
 * (s3_wakeup_end - s3_wakeup_16) can fit into one page.
 */
static __data uint8_t g_saved_s3_wakeup_page[PAGE_SIZE];

unsigned long get_tboot_mem_end(void)
{
    return PAGE_UP((unsigned long)&_end);
}

static tb_error_t verify_platform(void)
{
    return txt_verify_platform();
}

static bool is_launched(void)
{
    if ( supports_txt() == TB_ERR_NONE )
        return txt_is_launched();
    else return false;
}

static bool prepare_cpu(void)
{
    return txt_prepare_cpu();
}

static void copy_s3_wakeup_entry(void)
{
    if ( s3_wakeup_end - s3_wakeup_16 > PAGE_SIZE ) {
        printk(TBOOT_ERR"S3 entry is too large to be copied into one page!\n");
        return;
    }

    /* backup target address space first */
    tb_memcpy(g_saved_s3_wakeup_page, (void *)TBOOT_S3_WAKEUP_ADDR,
           s3_wakeup_end - s3_wakeup_16);

    /* copy s3 entry into target mem */
    tb_memcpy((void *)TBOOT_S3_WAKEUP_ADDR, s3_wakeup_16,
           s3_wakeup_end - s3_wakeup_16);
}

static void restore_saved_s3_wakeup_page(void)
{
    /* restore saved page */
    tb_memcpy((void *)TBOOT_S3_WAKEUP_ADDR, g_saved_s3_wakeup_page,
           s3_wakeup_end - s3_wakeup_16);
}

static inline void print_tboot_shared(const tboot_shared_t *tboot_shared)
{
    printk(TBOOT_DETA"tboot_shared data:\n");
    printk(TBOOT_DETA"\t version: %d\n", tboot_shared->version);
    printk(TBOOT_DETA"\t log_addr: 0x%08x\n", tboot_shared->log_addr);
    printk(TBOOT_DETA"\t shutdown_entry: 0x%08x\n", tboot_shared->shutdown_entry);
    printk(TBOOT_DETA"\t shutdown_type: %d\n", tboot_shared->shutdown_type);
    printk(TBOOT_DETA"\t tboot_base: 0x%08x\n", tboot_shared->tboot_base);
    printk(TBOOT_DETA"\t tboot_size: 0x%x\n", tboot_shared->tboot_size);
    printk(TBOOT_DETA"\t num_in_wfs: %u\n", tboot_shared->num_in_wfs);
    printk(TBOOT_DETA"\t flags: 0x%8.8x\n", tboot_shared->flags);
    printk(TBOOT_DETA"\t ap_wake_addr: 0x%08x\n", (uint32_t)tboot_shared->ap_wake_addr);
    printk(TBOOT_DETA"\t ap_wake_trigger: %u\n", tboot_shared->ap_wake_trigger);
}

static void post_launch(void)
{
    uint64_t base, size;
    tb_error_t err;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();
    extern tboot_log_t *g_log;
    extern void shutdown_entry(void);

    printk(TBOOT_INFO"measured launch succeeded\n");

    /* init MLE/kernel shared data page early, .num_in_wfs used in ap wakeup*/
    _tboot_shared.num_in_wfs = 0;

    txt_post_launch();

    /* backup DMAR table */
    if ( get_tboot_save_vtd() )
        vtd_save_dmar_table();

    if ( s3_flag  )    
         s3_launch();

    printk(TBOOT_INFO"Post SINIT ACM check loader context:\n");
    printk(TBOOT_INFO"g_ldr_ctx: %p\n", g_ldr_ctx);
    print_loader_ctx(g_ldr_ctx);

    printk(TBOOT_INFO"Post SINIT ACM E820 map:\n");
    print_e820_map();
    printk(TBOOT_INFO"Post SINIT ACM EFI memory map:\n");
    efi_memmap_dump();


    /* remove all TXT sinit acm modules before verifying modules */
    remove_txt_modules(g_ldr_ctx);

    /*
     * verify e820 table and adjust it to protect our memory regions
     */

    /* marked mem regions used by TXT (heap, SINIT, etc.) as E820_RESERVED */
    err = txt_protect_mem_regions();
    apply_policy(err);

    /* ensure all modules are in RAM */
    if ( !verify_modules(g_ldr_ctx) )     apply_policy(TB_ERR_POST_LAUNCH_VERIFICATION);

    /* verify that tboot is in valid RAM (i.e. E820_RAM) */
    base = (uint64_t)TBOOT_BASE_ADDR;
    size = (uint64_t)((unsigned long)&_end - base);
    printk(TBOOT_INFO"verifying tboot and its page table (%Lx - %Lx) in e820 table\n\t",  base, (base + size - 1));
    if ( e820_check_region(base, size) != E820_RAM ) {
        printk(TBOOT_ERR": failed.\n");
        apply_policy(TB_ERR_FATAL);
    }
    else
        printk(TBOOT_INFO": succeeded.\n");

    /* protect ourselves, MLE page table, and MLE/kernel shared page */
    base = (uint64_t)TBOOT_BASE_ADDR;
    size = (uint64_t)get_tboot_mem_end() - base;
    uint32_t mem_type = is_kernel_linux() ? E820_RESERVED : E820_UNUSABLE;
    printk(TBOOT_INFO"protecting tboot (%Lx - %Lx) in e820 table\n", base,      (base + size - 1));
    if ( !e820_protect_region(base, size, mem_type) )      
        apply_policy(TB_ERR_FATAL);
    if (!efi_memmap_reserve(base, size)) {
        apply_policy(TB_ERR_FATAL);
    }

    /*
     * verify modules against policy
     */
    verify_all_modules(g_ldr_ctx);

    /*
     * verify nv indices against policy
     */
    if ( (tpm->major == TPM12_VER_MAJOR) &&  get_tboot_measure_nv() ) 
	verify_all_nvindices();

    /*
     * seal hashes of modules and VL policy to current value of PCR17 & 18
     */
    if ( !seal_pre_k_state() )        
	apply_policy(TB_ERR_S3_INTEGRITY);

	
    if ( tpm->major == TPM20_VER_MAJOR ) {
	tpm_fp->context_save(tpm, tpm->cur_loc, handle2048, &tpm2_context_saved);
    }

	/*
     * init MLE/kernel shared data page
     */
    tb_memset(&_tboot_shared, 0, PAGE_SIZE);
    _tboot_shared.uuid = (uuid_t)TBOOT_SHARED_UUID;
    _tboot_shared.version = 6;
    _tboot_shared.log_addr = (uint32_t)g_log;
    _tboot_shared.shutdown_entry = (uint32_t)shutdown_entry;
    _tboot_shared.tboot_base = (uint32_t)&_start;
    _tboot_shared.tboot_size = (uint32_t)&_end - (uint32_t)&_start;
    uint32_t key_size = sizeof(_tboot_shared.s3_key);
    if ( !tpm_fp->get_random(tpm, 2, _tboot_shared.s3_key, &key_size) || key_size != sizeof(_tboot_shared.s3_key) )
        apply_policy(TB_ERR_S3_INTEGRITY);
    _tboot_shared.num_in_wfs = atomic_read(&ap_wfs_count);
    if ( use_mwait() ) {
        _tboot_shared.flags |= TB_FLAG_AP_WAKE_SUPPORT;
        _tboot_shared.ap_wake_trigger = AP_WAKE_TRIGGER_DEF;
    }
    else if ( get_tboot_mwait() ) {
        printk(TBOOT_ERR"ap_wake_mwait specified but the CPU doesn't support it.\n");
    }

    print_tboot_shared(&_tboot_shared);

    launch_kernel(true);
    apply_policy(TB_ERR_FATAL);
}

void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec)
{
    printk(TBOOT_INFO"cpu %u waking up, SIPI vector=%x\n", cpuid, sipi_vec);

    /* change to real mode and then jump to SIPI vector */
    _prot_to_real(sipi_vec);
}

#define ICR_LOW 0x300

void startup_rlps(void)
{
    uint32_t rlp_count = ((cpuid_ecx(1) >> 16) & 0xff) - 1;
    uint32_t apicbase = (uint32_t)rdmsr(MSR_APICBASE) & 0xfffffffffffff000;

    if ( rlp_count == 0 )
        return;

    /* send init ipi to all rlp -- Dest Shorthand: 11, Delivery Mode: 101 */
    writel(apicbase + ICR_LOW, 0xc0500);
}

void launch_racm(void)
{
    tb_error_t err;

    /* bsp check & tpm check done by caller */
    /* SMX must be supported */
    if ( !(cpuid_ecx(1) & CPUID_X86_FEATURE_SMX) )
        apply_policy(TB_ERR_SMX_NOT_SUPPORTED);
        
    /* Enable SMX */
    write_cr4(read_cr4() | CR4_SMXE);

    /* prepare cpu */
    if ( !prepare_cpu() )
        apply_policy(TB_ERR_FATAL);

    /* prepare tpm */
    if ( !prepare_tpm() )
        apply_policy(TB_ERR_TPM_NOT_READY);

    /* Place RLPs in Wait for SIPI state */
    startup_rlps();

    /* Verify loader context */
    if ( !verify_loader_context(g_ldr_ctx) )
        apply_policy(TB_ERR_FATAL);
    
    /* load racm */
    err = txt_launch_racm(g_ldr_ctx);
    apply_policy(err);
}

static void shutdown_system(uint32_t);
void check_racm_result(void)
{
    txt_get_racm_error();
    shutdown_system(TB_SHUTDOWN_HALT); 
}

void begin_launch(void *addr, uint32_t magic)
{
    tb_error_t err;

    if (g_ldr_ctx->type == 0)        
        determine_loader_type(addr, magic);

    /* on pre-SENTER boot, copy command line to buffer in tboot image
       (so that it will be measured); buffer must be 0 -filled */
    if ( !is_launched() && !s3_flag ) {

        const char *cmdline_orig = get_cmdline(g_ldr_ctx);
        const char *cmdline = NULL;
        if (cmdline_orig){
           // cmdline = skip_filename(cmdline_orig);
            cmdline = cmdline_orig;
        }
        tb_memset(g_cmdline, '\0', sizeof(g_cmdline));
        if (cmdline)
            tb_strncpy(g_cmdline, cmdline, sizeof(g_cmdline)-1);
    }

    /* always parse cmdline */
    tboot_parse_cmdline();

    /* initialize all logging targets */
    if ((is_launched() && get_framebuffer_info(g_ldr_ctx) != NULL) || s3_flag) {
        /* 
         * We are using framebuffer method for printing VGA logs. It does not
         * when PMRs are programmed, so in post-launch we have to disable VGA
         * logging.
         */
        printk_init(true);
    } else {
        printk_init(false);
    }
    //TBOOT_CHANGESET is defined in CFLAGS in config.mk
    printk(TBOOT_INFO"*********************** TBOOT ***********************\n");
    printk(TBOOT_INFO"   %s\n", TBOOT_CHANGESET);
    printk(TBOOT_INFO"*****************************************************\n");
    printk(TBOOT_INFO"This tboot version supports TPR.\n");
    printk(TBOOT_INFO"This tboot version tries to move SINIT in ldr_ctx v3.\n");
    printk(TBOOT_INFO"This tboot version disables DMA remapping.\n");

    printk(TBOOT_INFO"command line: %s\n", g_cmdline);
    /* if telled to check revocation acm result, go with simplified path */
    if ( get_tboot_call_racm_check() )
        check_racm_result(); /* never return */

    if (is_launched()) printk(TBOOT_INFO"SINIT ACM successfully returned...\n");
    if ( s3_flag ) printk(TBOOT_INFO"Resume from S3...\n");
    
    /* RLM scaffolding
       if (g_ldr_ctx->type == 2)
       print_loader_ctx(g_ldr_ctx);
    */

    printk(TBOOT_INFO"Loader context at: %p\n", g_ldr_ctx);
    print_loader_ctx(g_ldr_ctx);

    /* 
        GRUB can put SINIT.bin in memory before tboot, it should be moved to avoid 
        overwriting tboot's memory
    */
    if (!is_launched()) {
        printk(TBOOT_INFO"move modules above tboot.\n");
        move_modules(g_ldr_ctx);
        printk(TBOOT_INFO"Loader context after moving modules%p\n", g_ldr_ctx);
        print_loader_ctx(g_ldr_ctx);
    }

    /* clear resume vector on S3 resume so any resets will not use it */
    if ( !is_launched() && s3_flag )        set_s3_resume_vector(&_tboot_shared.acpi_sinfo, 0);

    /* we should only be executing on the BSP */
    if ( !(rdmsr(MSR_APICBASE) & APICBASE_BSP) ) {
        printk(TBOOT_INFO"entry processor is not BSP\n");
        apply_policy(TB_ERR_FATAL);
    }
    printk(TBOOT_INFO"BSP is cpu %u\n", get_apicid());

    /* make copy of e820 map that we will use and adjust */
    if ( !s3_flag ) {
        if ( !copy_e820_map(g_ldr_ctx) )  apply_policy(TB_ERR_FATAL);
        if (efi_memmap_copy(g_ldr_ctx)) {
            printk(TBOOT_INFO"Original EFI memory map:\n");
            efi_memmap_dump();
            printk(TBOOT_INFO"Original E820 memory map:\n");    
            print_e820_map();
        }
    }

    /* we need to make sure this is a (TXT-) capable platform before using */
    /* any of the features, incl. those required to check if the environment */
    /* has already been launched */

    if (g_sinit == NULL) {
       find_platform_sinit_module(g_ldr_ctx, (void **)&g_sinit, NULL);
       /* check if it is newer than BIOS provided version, then copy it to BIOS reserved region */
       g_sinit = copy_sinit(g_sinit); 
       if (g_sinit == NULL) 
           apply_policy(TB_ERR_SINIT_NOT_PRESENT);
       if (!verify_acmod(g_sinit)) 
           apply_policy(TB_ERR_ACMOD_VERIFY_FAILED);
    }
    
    //We need to have g_sinit point to SINIT ACM before we can run is_tpr_supported
    //This global variable decides whether PMR or TPR is used
    g_tpr_support = is_tpr_supported();

    /* make TPM ready for measured launch */
    if (!tpm_detect())
       apply_policy(TB_ERR_TPM_NOT_READY);

    /* verify SE enablement status */
    verify_IA32_se_svn_status(g_sinit);

    /* read tboot verified launch control policy from TPM-NV (will use default if none in TPM-NV) */
    err = set_policy();
    apply_policy(err);

    /* if telled to call revocation acm, go with simplified path */
    if ( get_tboot_call_racm() )
        launch_racm(); /* never return */

    /* need to verify that platform supports TXT before we can check error */
    /* (this includes TPM support) */
    err = supports_txt();
    apply_policy(err);

    /* print any errors on last boot, which must be from TXT launch */
    txt_display_errors();
    if (txt_has_error() && get_tboot_ignore_prev_err() == false) {
        apply_policy(TB_ERR_PREV_TXT_ERROR);
    }

    /* need to verify that platform can perform measured launch */
    err = verify_platform();
    apply_policy(err);

    /* ensure there are modules */
    if (is_launched()) {
        printk(TBOOT_INFO"Post SINIT ACM check loader context:\n");
        printk(TBOOT_INFO"g_ldr_ctx: %p\n", g_ldr_ctx);
        print_loader_ctx(g_ldr_ctx);
    }
    if ( !s3_flag && !verify_loader_context(g_ldr_ctx) )
        apply_policy(TB_ERR_FATAL);

    /* this is being called post-measured launch */
    if ( is_launched() ){
        printk(TBOOT_INFO"Post_launch started ...\n");
        post_launch();
    }

    /* make the CPU ready for measured launch */
    if ( !prepare_cpu() )
        apply_policy(TB_ERR_FATAL);

    /* do s3 launch directly, if is a s3 resume */
    if ( s3_flag ) {
        if ( !prepare_tpm() )
            apply_policy(TB_ERR_TPM_NOT_READY);
        txt_s3_launch_environment();
        printk(TBOOT_ERR"we should never get here\n");
        apply_policy(TB_ERR_FATAL);
    }

    /* check for error from previous boot */
    printk(TBOOT_INFO"checking previous errors on the last boot.\n\t");
    if ( was_last_boot_error() )
        printk(TBOOT_INFO"last boot has error.\n");
    else
        printk(TBOOT_INFO"last boot has no error.\n");

    if ( !prepare_tpm() )
        apply_policy(TB_ERR_TPM_NOT_READY);

    /* launch the measured environment */
    err = txt_launch_environment(g_ldr_ctx);
    apply_policy(err);
}

void s3_launch(void)
{
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();
    /* restore backed-up s3 wakeup page */
    restore_saved_s3_wakeup_page();
    /* load saved tpm2 context for unseal */
    if ( tpm->major == TPM20_VER_MAJOR ) {
        tpm_fp->context_flush(tpm, tpm->cur_loc, handle2048);
        tpm_fp->context_load(tpm, tpm->cur_loc, &tpm2_context_saved, &handle2048);
    }

    /* remove DMAR table if necessary */
    if ( get_tboot_save_vtd() )
        vtd_remove_dmar_table();

    if ( !is_launched() )
        apply_policy(TB_ERR_S3_INTEGRITY);
    else {
        /* this is being called post-measured launch */
        /* verify saved hash integrity and re-extend PCRs */
        if ( !verify_integrity() )
            apply_policy(TB_ERR_S3_INTEGRITY);
    }

    print_tboot_shared(&_tboot_shared);
    
    if (g_tpm_family != TPM_IF_20_CRB ) {
        if (!release_locality(tpm->cur_loc))
            printk(TBOOT_ERR"Release TPM FIFO locality %d failed \n", tpm->cur_loc);
    }
    else {
        if (!tpm_relinquish_locality_crb(tpm->cur_loc))
            printk(TBOOT_ERR"Relinquish TPM CRB locality %d failed \n", tpm->cur_loc);
    }

    /* (optionally) pause when transferring kernel resume */
    if ( g_vga_delay > 0 )
        delay(g_vga_delay * 1000);

    _prot_to_real(g_post_k_s3_state.kernel_s3_resume_vector);
}

static void shutdown_system(uint32_t shutdown_type)
{
    static const char *types[] = { "TB_SHUTDOWN_REBOOT", "TB_SHUTDOWN_S5",
                                   "TB_SHUTDOWN_S4", "TB_SHUTDOWN_S3",
                                   "TB_SHUTDOWN_HALT" };
    char type[32];

    if ( shutdown_type >= ARRAY_SIZE(types) )
        tb_snprintf(type, sizeof(type), "unknown: %u", shutdown_type);
    else {
        tb_strncpy(type, types[shutdown_type], sizeof(type));
        type[sizeof(type) - 1] = '\0';
    }
    printk(TBOOT_INFO"shutdown_system() called for shutdown_type: %s\n", type);

    switch( shutdown_type ) {
        case TB_SHUTDOWN_S3:
            copy_s3_wakeup_entry();
            /* write our S3 resume vector to ACPI resume addr */
            set_s3_resume_vector(&_tboot_shared.acpi_sinfo,  TBOOT_S3_WAKEUP_ADDR);
            /* fall through for rest of Sx handling */
        /* FALLTHROUGH */
        case TB_SHUTDOWN_S4:
        case TB_SHUTDOWN_S5:
            machine_sleep(&_tboot_shared.acpi_sinfo);
            /* if machine_sleep() fails, fall through to reset */

        /* FALLTHROUGH */
        case TB_SHUTDOWN_REBOOT:
            if ( txt_is_powercycle_required() ) {
                /* powercycle by writing 0x0a+0x0e to port 0xcf9 */
                /* (supported by all TXT-capable chipsets) */
                outb(0xcf9, 0x0a);
                outb(0xcf9, 0x0e);
            }
            else {
                /* soft reset by writing 0xfe to keyboard reset vector 0x64 */
                /* BIOSes (that are not performing some special operation, */
                /* such as update) will turn this into a platform reset as */
                /* expected. */
                outb(0x64, 0xfe);
                /* fall back to soft reset by writing 0x06 to port 0xcf9 */
                /* (supported by all TXT-capable chipsets) */
                outb(0xcf9, 0x06);
            }

        /* FALLTHROUGH */
        case TB_SHUTDOWN_HALT:
        default:
            while ( true )
                halt();
    }
}

void shutdown(void)
{
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();
   
    /* wait-for-sipi only invoked for APs, so skip all BSP shutdown code */
    if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_WFS ) {
        atomic_inc(&ap_wfs_count);
        _tboot_shared.ap_wake_trigger = 0;
        mtx_enter(&ap_lock);
        printk(TBOOT_INFO"shutdown(): TB_SHUTDOWN_WFS\n");
        if ( use_mwait() )
            ap_wait(get_apicid());
        else
            handle_init_sipi_sipi(get_apicid());
        apply_policy(TB_ERR_FATAL);
    }

    printk(TBOOT_INFO"wait until all APs ready for txt shutdown\n");
    while( atomic_read(&_tboot_shared.num_in_wfs)
           < atomic_read(&ap_wfs_count) )
        cpu_relax();

    /* ensure localities 0, 1 are inactive (in case kernel used them) */
    /* request TPM current locality to be active */
    if (g_tpm_family != TPM_IF_20_CRB ) {
        if (!release_locality(0))
            printk(TBOOT_ERR"Release TPM FIFO locality 0 failed \n");
        if (!release_locality(1))
            printk(TBOOT_ERR"Release TPM FIFO locality 1 failed \n");
        if (!tpm_wait_cmd_ready(tpm->cur_loc))
            printk(TBOOT_ERR"Request TPM FIFO locality %d failed \n", tpm->cur_loc);
    }
    else {
        if (!tpm_relinquish_locality_crb(0))
            printk(TBOOT_ERR"Release TPM CRB locality 0 failed \n");
        if (!tpm_relinquish_locality_crb(1))			 
            printk(TBOOT_ERR"Release TPM CRB locality 1 failed \n");
        if (!tpm_request_locality_crb(tpm->cur_loc))
            printk(TBOOT_ERR"Request TPM CRB locality %d failed \n", tpm->cur_loc);
    }

    if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_S3 ) {
        /* restore DMAR table if needed */
        if ( get_tboot_save_vtd() )
            vtd_restore_dmar_table();
	if ( tpm->major == TPM20_VER_MAJOR ) {
	    tpm_fp->context_flush(tpm, tpm->cur_loc, handle2048);
	    tpm_fp->context_load(tpm, tpm->cur_loc, &tpm2_context_saved, &handle2048);
 	}

		
	/* save kernel/VMM resume vector for sealing */
        g_post_k_s3_state.kernel_s3_resume_vector =  _tboot_shared.acpi_sinfo.kernel_s3_resume_vector;
        
        /* create and seal memory integrity measurement */
        if ( !seal_post_k_state() )   
	    apply_policy(TB_ERR_S3_INTEGRITY);
            /* OK to leave key in memory on failure since if user cared they
               would have policy that doesn't continue for TB_ERR_S3_INTEGRITY
               error */
        else
            /* wipe S3 key from memory now that it is sealed */
            tb_memset(_tboot_shared.s3_key, 0, sizeof(_tboot_shared.s3_key));
    }

    /* cap dynamic PCRs extended as part of launch (17, 18, ...) */
    if ( is_launched() ) {

        /* cap PCRs to ensure no follow-on code can access sealed data */
        if (!tpm_fp->cap_pcrs(tpm, tpm->cur_loc, -1)) {
            printk(TBOOT_ERR"failed to cap PCRs\n");
            apply_policy(TB_ERR_FATAL);
        }

        /* have TPM save static PCRs (in case VMM/kernel didn't) */
        /* per TCG spec, TPM can invalidate saved state if any other TPM
           operation is performed afterwards--so do this last */
        if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_S3 ) {
            if (tpm_fp->save_state(tpm, tpm->cur_loc) != 0) {
                printk(TBOOT_ERR"failed to save TPM state\n");
            }
        }

        /* scrub any secrets by clearing their memory, then flush cache */
        /* we don't have any secrets to scrub, however */
        ;

        /* in mwait "mode", APs will be in MONITOR/MWAIT and can be left there */
        if ( !use_mwait() ) {
            /* force APs to exit mini-guests if any are in and wait until */
            /* all are out before shutting down TXT */
            printk(TBOOT_INFO"waiting for APs (%u) to exit guests...\n", atomic_read(&ap_wfs_count));
            force_aps_exit();
            uint32_t timeout = AP_GUEST_EXIT_TIMEOUT;
            do {
                if ( timeout % 0x8000 == 0 )
                    printk(TBOOT_INFO".");
                else
                    cpu_relax();
                if ( timeout % 0x200000 == 0 )
                    printk(TBOOT_INFO"\n");
                timeout--;
            } while ( ( atomic_read(&ap_wfs_count) > 0 ) && timeout > 0 );
            printk(TBOOT_INFO"\n");
            if ( timeout == 0 )
                printk(TBOOT_INFO"AP guest exit loop timed-out\n");
            else
                printk(TBOOT_INFO"all APs exited guests\n");
        } else {
            /* reset ap_wfs_count to avoid tboot hash changing in S3 case */
            atomic_set(&ap_wfs_count, 0);
        }

        /* turn off TXT (GETSEC[SEXIT]) */
        txt_shutdown();
    }

    /* machine shutdown */
    shutdown_system(_tboot_shared.shutdown_type);
}

void handle_exception(void)
{
    printk(TBOOT_INFO"received exception; shutting down...\n");
    _tboot_shared.shutdown_type = TB_SHUTDOWN_REBOOT;
    shutdown();
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
