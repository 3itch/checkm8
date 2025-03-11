/*
 * vmcs.c: create and manage mini-VT VM for APs to handle INIT-SIPI-SIPI
 *
 * Copyright (c) 2003-2010, Intel Corporation
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
#include <msr.h>
#include <tb_error.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <processor.h>
#include <printk.h>
#include <uuid.h>
#include <loader.h>
#include <mutex.h>
#include <atomic.h>
#include <tboot.h>
#include <txt/txt.h>
#include <txt/vmcs.h>


/* no vmexit on external intr as mini guest only handle INIT & SIPI */
#define MONITOR_PIN_BASED_EXEC_CONTROLS                 \
    ( PIN_BASED_NMI_EXITING )

/* no vmexit on hlt as guest only run this instruction */
#define MONITOR_CPU_BASED_EXEC_CONTROLS                 \
    ( CPU_BASED_INVDPG_EXITING |                        \
      CPU_BASED_MWAIT_EXITING )

#define MONITOR_VM_EXIT_CONTROLS                        \
    ( VM_EXIT_ACK_INTR_ON_EXIT )

/* Basic flags for VM-Entry controls. */
#define MONITOR_VM_ENTRY_CONTROLS                       0x00000000

#define EXCEPTION_BITMAP_BP     (1 << 3)        /* Breakpoint */
#define EXCEPTION_BITMAP_PG     (1 << 14)       /* Page Fault */
#define MONITOR_DEFAULT_EXCEPTION_BITMAP        \
    ( EXCEPTION_BITMAP_PG |                     \
      EXCEPTION_BITMAP_BP )

#define load_TR(n)  __asm__ __volatile__ ("ltr  %%ax" : : "a" ((n)<<3) )
extern char gdt_table[];
#define RESET_TSS_DESC(n)   gdt_table[((n)<<3)+5] = 0x89

/* lock that protects APs against race conditions on wakeup and shutdown */
struct mutex ap_lock;

/* counter for APs entering/exiting wait-for-sipi */
extern atomic_t ap_wfs_count;

/* flag for (all APs) exiting mini guest (1 = exit) */
uint32_t aps_exit_guest;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

extern char _end[];

extern void print_cr0(const char *s);
extern void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec);

extern void apply_policy(tb_error_t error);

static uint32_t vmcs_rev_id;
static uint32_t pin_based_vm_exec_ctrls;
static uint32_t proc_based_vm_exec_ctrls;
static uint32_t vm_exit_ctrls;
static uint32_t vm_entry_ctrls;

static void init_vmx_ctrl(uint32_t msr, uint32_t ctrl_val, uint32_t *ctrl)
{
    uint32_t lo, hi;
    uint64_t val;

    val = rdmsr(msr);
    lo = (uint32_t)(val & 0xffffffffUL);
    hi = (uint32_t)(val >> 32);
    *ctrl = (ctrl_val & hi) | lo;

    /* make sure that the conditions we want are actually allowed */
    if ( (*ctrl & ctrl_val) != ctrl_val )
        apply_policy(TB_ERR_FATAL);
}

static void init_vmcs_config(void)
{
    uint64_t val;

    val = rdmsr(MSR_IA32_VMX_BASIC_MSR);
    vmcs_rev_id = (uint32_t)(val & 0xffffffffUL);

    init_vmx_ctrl(MSR_IA32_VMX_PINBASED_CTLS_MSR,
                  MONITOR_PIN_BASED_EXEC_CONTROLS, &pin_based_vm_exec_ctrls);

    init_vmx_ctrl(MSR_IA32_VMX_PROCBASED_CTLS_MSR,
                  MONITOR_CPU_BASED_EXEC_CONTROLS, &proc_based_vm_exec_ctrls);

    init_vmx_ctrl(MSR_IA32_VMX_EXIT_CTLS_MSR,
                  MONITOR_VM_EXIT_CONTROLS, &vm_exit_ctrls);

    init_vmx_ctrl(MSR_IA32_VMX_ENTRY_CTLS_MSR,
                  MONITOR_VM_ENTRY_CONTROLS, &vm_entry_ctrls);
}

extern uint32_t idle_pg_table[PAGE_SIZE / 4];

/* build a 1-level identity-map page table [0, _end] on AP for vmxon */
static void build_ap_pagetable(void)
{
#define PTE_FLAGS   0xe3 /* PRESENT+RW+A+D+4MB */
    uint32_t pt_entry = PTE_FLAGS;
    uint32_t *pte = &idle_pg_table[0];

    while ( pt_entry <= (uint32_t)&_end + PTE_FLAGS ) {
        *pte = pt_entry;
        /* Incriments 4MB page at a time */ 
        pt_entry += 1 << FOURMB_PAGE_SHIFT;
        pte++;
    }
}

extern char host_vmcs[PAGE_SIZE];
extern char ap_vmcs[NR_CPUS][PAGE_SIZE];

static bool start_vmx(unsigned int cpuid)
{
    struct vmcs_struct *vmcs;
    static bool init_done = false;

    write_cr4(read_cr4() | CR4_VMXE);

    vmcs = (struct vmcs_struct *)host_vmcs;

    /* TBD: it would be good to check VMX config is same on all CPUs */
    /* only initialize this data the first time */
    if ( !init_done ) {
        /*printk(TBOOT_INFO"one-time initializing VMX mini-guest\n");*/
        tb_memset(vmcs, 0, PAGE_SIZE);

        init_vmcs_config();
        vmcs->vmcs_revision_id = vmcs_rev_id;

        /* enable paging as required by vmentry */
        build_ap_pagetable();

        init_done = true;
    }

    /*printk(TBOOT_INFO"per-cpu initializing VMX mini-guest on cpu %u\n", cpuid);*/

    /* enable paging using 1:1 page table [0, _end] */
    /* addrs outside of tboot (e.g. MMIO) are not mapped) */
    write_cr3((unsigned long)idle_pg_table);
    write_cr4(read_cr4() | CR4_PSE);
    write_cr0(read_cr0() | CR0_PG);

    if ( __vmxon((unsigned long)vmcs) ) {
        write_cr4(read_cr4() & ~CR4_VMXE);
        write_cr4(read_cr4() & ~CR4_PSE);
        write_cr0(read_cr0() & ~CR0_PG);
        printk(TBOOT_ERR"VMXON failed for cpu %u\n", cpuid);
        return false;
    }

    printk(TBOOT_DETA"VMXON done for cpu %u\n", cpuid);
    return true;
}

static void stop_vmx(unsigned int cpuid)
{
    struct vmcs_struct *vmcs = NULL;

    if ( !(read_cr4() & CR4_VMXE) ) {
        printk(TBOOT_DETA"stop_vmx() called when VMX not enabled\n");
        return;
    }

    __vmptrst((unsigned long)vmcs);

    __vmpclear((unsigned long)vmcs);

    __vmxoff();

    write_cr4(read_cr4() & ~CR4_VMXE);

    /* diable paging to restore AP's state to boot xen */
    write_cr0(read_cr0() & ~CR0_PG);
    write_cr4(read_cr4() & ~CR4_PSE);

    printk(TBOOT_DETA"VMXOFF done for cpu %u\n", cpuid);
}

/* in tboot/common/boot.S */
extern void vmx_asm_vmexit_handler(void);
extern void _mini_guest(void);

/* consturct guest/host vmcs:
 * make guest vmcs from physical environment,
 * so only one binary switch between root and non-root
 */
static void construct_vmcs(void)
{
    struct __packed {
        uint16_t  limit;
        uint32_t  base;
    } xdt;
    unsigned long cr0, cr3, cr4, eflags, rsp;
    unsigned int tr;
    union vmcs_arbytes arbytes;
    uint16_t seg;

    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_ctrls);
    __vmwrite(VM_EXIT_CONTROLS, vm_exit_ctrls);
    __vmwrite(VM_ENTRY_CONTROLS, vm_entry_ctrls);
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, proc_based_vm_exec_ctrls);

    /* segments selectors. */
    __asm__ __volatile__ ("mov %%ss, %0\n" : "=r"(seg));
    __vmwrite(HOST_SS_SELECTOR, seg);
    __vmwrite(GUEST_SS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%ds, %0\n" : "=r"(seg));
    __vmwrite(HOST_DS_SELECTOR, seg);
    __vmwrite(GUEST_DS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%es, %0\n" : "=r"(seg));
    __vmwrite(HOST_ES_SELECTOR, seg);
    __vmwrite(GUEST_ES_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%fs, %0\n" : "=r"(seg));
    __vmwrite(HOST_FS_SELECTOR, seg);
    __vmwrite(GUEST_FS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%gs, %0\n" : "=r"(seg));
    __vmwrite(HOST_GS_SELECTOR, seg);
    __vmwrite(GUEST_GS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%cs, %0\n" : "=r"(seg));
    __vmwrite(GUEST_CS_SELECTOR, seg);
    __vmwrite(GUEST_RIP, (uint32_t)&_mini_guest);

    __vmwrite(HOST_CS_SELECTOR, seg);
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* segment limits */
#define GUEST_SEGMENT_LIMIT     0xffffffff
    __vmwrite(GUEST_ES_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_SS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_DS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_FS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_GS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_CS_LIMIT, GUEST_SEGMENT_LIMIT);

    /* segment AR bytes, see boot.S for details */
    arbytes.bytes = 0;
    arbytes.fields.seg_type = 0x3;          /* type = 3 */
    arbytes.fields.s = 1;                   /* code or data, i.e. not system */
    arbytes.fields.dpl = 0;                 /* DPL = 0 */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 1;    /* 32-bit */
    arbytes.fields.g = 1;

    arbytes.fields.null_bit = 0;            /* not null */
    __vmwrite(GUEST_ES_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_SS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_DS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_FS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_GS_AR_BYTES, arbytes.bytes);

    arbytes.fields.seg_type = 0xb;          /* type = 0xb */
    __vmwrite(GUEST_CS_AR_BYTES, arbytes.bytes);

    /* segment BASE */
    __vmwrite(GUEST_ES_BASE, 0);
    __vmwrite(GUEST_SS_BASE, 0);
    __vmwrite(GUEST_DS_BASE, 0);
    __vmwrite(GUEST_FS_BASE, 0);
    __vmwrite(GUEST_GS_BASE, 0);
    __vmwrite(GUEST_CS_BASE, 0);

    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);

    /* Guest LDT and TSS */
    __vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmwrite(GUEST_LDTR_BASE, 0);
    __vmwrite(GUEST_LDTR_LIMIT, 0xffff);

    __asm__ __volatile__ ("str  (%0) \n" :: "a"(&tr) : "memory");
    if ( tr == 0 )
        printk(TBOOT_ERR"tr is 0 on ap, may vmlaunch fail.\n");
    __vmwrite(GUEST_TR_SELECTOR, tr);
    __vmwrite(GUEST_TR_BASE, 0);
    __vmwrite(GUEST_TR_LIMIT, 0xffff);

    __vmwrite(HOST_TR_SELECTOR, tr);
    __vmwrite(HOST_TR_BASE, 0);


    /* tboot does not use ldt */
    arbytes.bytes = 0;
    arbytes.fields.s = 0;                   /* not code or data segement */
    arbytes.fields.seg_type = 0x2;          /* LDT */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 0;    /* 16-bit */
    arbytes.fields.g = 1;
    __vmwrite(GUEST_LDTR_AR_BYTES, arbytes.bytes);

    /* setup a TSS for vmentry as zero TR is not allowed */
    arbytes.bytes = 0;
    arbytes.fields.s = 0;          /* not code or data seg */
    arbytes.fields.seg_type = 0xb;          /* 32-bit TSS (busy) */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 0;    /* 16-bit */
    arbytes.fields.g = 1;
    __vmwrite(GUEST_TR_AR_BYTES, arbytes.bytes);

    /* GDT */
    __asm__ __volatile__ ("sgdt (%0) \n" :: "a"(&xdt) : "memory");
    __vmwrite(GUEST_GDTR_BASE, xdt.base);
    __vmwrite(GUEST_GDTR_LIMIT, xdt.limit);

    __vmwrite(HOST_GDTR_BASE, xdt.base);

    /* IDT */
    __asm__ __volatile__ ("sidt (%0) \n" :: "a"(&xdt) : "memory");
    /*printk(TBOOT_INFO"idt.base=0x%x, limit=0x%x.\n", xdt.base, xdt.limit);*/
    __vmwrite(GUEST_IDTR_BASE, xdt.base);
    __vmwrite(GUEST_IDTR_LIMIT, xdt.limit);

    __vmwrite(HOST_IDTR_BASE, xdt.base);

    /* control registers. */
    cr0 = read_cr0();
    cr3 = read_cr3();
    cr4 = read_cr4();
    __vmwrite(HOST_CR0, cr0);
    __vmwrite(HOST_CR4, cr4);
    __vmwrite(HOST_CR3, cr3);

    __vmwrite(GUEST_CR0, cr0);
    __vmwrite(CR0_READ_SHADOW, cr0);
    __vmwrite(GUEST_CR4, cr4);
    __vmwrite(CR4_READ_SHADOW, cr4);
    __vmwrite(GUEST_CR3, cr3);

    /* debug register */
    __vmwrite(GUEST_DR7, 0);

    /* rflags & rsp */
    eflags = read_eflags();
    __vmwrite(GUEST_RFLAGS, eflags);

    __asm__ __volatile__ ("mov %%esp,%0\n\t" :"=r" (rsp));
    __vmwrite(GUEST_RSP, rsp);
    __vmwrite(HOST_RSP, rsp);

    /* MSR intercepts. */
    __vmwrite(VM_EXIT_MSR_LOAD_ADDR, 0);
    __vmwrite(VM_EXIT_MSR_STORE_ADDR, 0);
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    __vmwrite(CR0_GUEST_HOST_MASK, ~0UL);
    __vmwrite(CR4_GUEST_HOST_MASK, ~0UL);

    __vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmwrite(CR3_TARGET_COUNT, 0);

    __vmwrite(GUEST_ACTIVITY_STATE, GUEST_STATE_ACTIVE);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmwrite(VMCS_LINK_POINTER, ~0UL);

    __vmwrite(VMCS_LINK_POINTER_HIGH, ~0UL);

    __vmwrite(EXCEPTION_BITMAP, MONITOR_DEFAULT_EXCEPTION_BITMAP);

    /*printk(TBOOT_INFO"vmcs setup done.\n");*/
}

static bool vmx_create_vmcs(unsigned int cpuid)
{
    struct vmcs_struct *vmcs = (struct vmcs_struct *)&ap_vmcs[cpuid];

    tb_memset(vmcs, 0, PAGE_SIZE);

    vmcs->vmcs_revision_id = vmcs_rev_id;

    /* vir addr equal to phy addr as we setup identity page table */
    __vmpclear((unsigned long)vmcs);

    __vmptrld((unsigned long)vmcs);

    construct_vmcs();

    return true;
}

static void launch_mini_guest(unsigned int cpuid)
{
    unsigned long error;

    printk(TBOOT_DETA"launching mini-guest for cpu %u\n", cpuid);

    /* this is close enough to entering wait-for-sipi, so inc counter */
    atomic_inc((atomic_t *)&_tboot_shared.num_in_wfs);

    __vmlaunch();

    /* should not reach here */
    atomic_dec(&ap_wfs_count);
    atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
    error = __vmread(VM_INSTRUCTION_ERROR);
    printk(TBOOT_ERR"vmlaunch failed for cpu %u, error code %lx\n", cpuid, error);
    apply_policy(TB_ERR_FATAL);
}

static void print_failed_vmentry_reason(unsigned int exit_reason)
{
    unsigned long exit_qualification;

    exit_qualification = __vmread(EXIT_QUALIFICATION);
    printk(TBOOT_ERR"Failed vm entry (exit reason 0x%x) ", exit_reason);
    switch ( (uint16_t)exit_reason )
        {
        case EXIT_REASON_INVALID_GUEST_STATE:
            printk(TBOOT_ERR"caused by invalid guest state (%ld).\n",
                   exit_qualification);
            break;
        case EXIT_REASON_MSR_LOADING:
            printk(TBOOT_ERR"caused by MSR entry %ld loading.\n", exit_qualification);
            break;
        case EXIT_REASON_MACHINE_CHECK:
            printk(TBOOT_ERR"caused by machine check.\n");
            break;
        default:
            printk(TBOOT_ERR"reason not known yet!");
            break;
        }
}

/* Vmexit handler for physical INIT-SIPI-SIPI from the BSP
 * Do not use printk in this critical path as BSP only
 * wait for a short time
 */
void vmx_vmexit_handler(void)
{
    unsigned int apicid = get_apicid();

    unsigned int exit_reason = __vmread(VM_EXIT_REASON);
    /*printk("vmx_vmexit_handler, cpu= %d,  exit_reason=%x.\n", apicid, exit_reason);*/

    if ( (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) ) {
        print_failed_vmentry_reason(exit_reason);
        stop_vmx(apicid);
        atomic_dec(&ap_wfs_count);
        atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
        apply_policy(TB_ERR_FATAL);
    }
    else if ( exit_reason == EXIT_REASON_INIT ) {
        __vmwrite(GUEST_ACTIVITY_STATE, GUEST_STATE_WAIT_SIPI);
        __vmresume();
    }
    else if ( exit_reason == EXIT_REASON_SIPI ) {
        /* even though standard MP sequence is INIT-SIPI-SIPI */
        /* there is no need to wait for second SIPI (which may not */
        /* always be delivered) */
        /* but we should expect there to already have been INIT */
        /* disable VT then jump to xen code */
        unsigned long exit_qual = __vmread(EXIT_QUALIFICATION);
        uint32_t sipi_vec = (exit_qual & 0xffUL) << PAGE_SHIFT;
        /*printk("exiting due to SIPI: vector=%x\n", sipi_vec); */
        stop_vmx(apicid);
        atomic_dec(&ap_wfs_count);
        atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
        cpu_wakeup(apicid, sipi_vec);

        /* cpu_wakeup() doesn't return, so we should never get here */
        printk(TBOOT_ERR"cpu_wakeup() failed\n");
        apply_policy(TB_ERR_FATAL);
    }
    else if ( exit_reason == EXIT_REASON_VMCALL ) {
        stop_vmx(apicid);
        atomic_dec(&ap_wfs_count);
        atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
        /* spin */
        while ( true )
            __asm__ __volatile__("cli; hlt;");
    }
    else {
        printk(TBOOT_ERR"can't handle vmexit due to 0x%x.\n", exit_reason);
        __vmresume();
    }
}

/* Launch a mini guest to handle the physical INIT-SIPI-SIPI from BSP */
void handle_init_sipi_sipi(unsigned int cpuid)
{
    if ( cpuid >= NR_CPUS ) {
        printk(TBOOT_ERR"cpuid (%u) exceeds # supported CPUs\n", cpuid);
        apply_policy(TB_ERR_FATAL);
        mtx_leave(&ap_lock);
        return;
    }

    /* setup a dummy tss as vmentry require a non-zero host TR */
    load_TR(3);

    /* clear the tss busy flag to avoid blocking other APs */
    RESET_TSS_DESC(3);

    /* prepare a guest for INIT-SIPI-SIPI handling */
    /* 1: setup VMX environment and VMXON */
    if ( !start_vmx(cpuid) ) {
        apply_policy(TB_ERR_FATAL);
        mtx_leave(&ap_lock);
        return;
    }

    /* 2: setup VMCS */
    if ( vmx_create_vmcs(cpuid) ) {
        mtx_leave(&ap_lock);

        /* 3: launch VM */
        launch_mini_guest(cpuid);
    }

    printk(TBOOT_ERR"control should not return here from launch_mini_guest\n");
    apply_policy(TB_ERR_FATAL);
    return;
}

void force_aps_exit(void)
{
    aps_exit_guest = 1;
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
