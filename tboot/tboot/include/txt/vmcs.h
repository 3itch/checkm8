/*
 * vmcs.h: VMCS definitions for creation of APs mini-guests
 *
 * Copyright (c) 2003-2009, Intel Corporation
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

#ifndef __TXT_VMCS_H__
#define __TXT_VMCS_H__

struct vmcs_struct {
    uint32_t        vmcs_revision_id;
    unsigned char   data[0];          /* vmcs size is read from MSR */
};

union vmcs_arbytes {
    struct arbyte_fields {
        unsigned int seg_type : 4,
            s         : 1,
            dpl       : 2,
            p         : 1,
            reserved0 : 4,
            avl       : 1,
            reserved1 : 1,
            default_ops_size: 1,
            g         : 1,
            null_bit  : 1,
            reserved2 : 15;
    } fields;
    unsigned int bytes;
};

#define CPU_BASED_HLT_EXITING           0x00000080
#define CPU_BASED_INVDPG_EXITING        0x00000200
#define CPU_BASED_MWAIT_EXITING         0x00000400

#define PIN_BASED_EXT_INTR_MASK         0x00000001
#define PIN_BASED_NMI_EXITING           0x00000008

#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000

#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800


/* VMCS Encordings */
enum vmcs_field {
    GUEST_ES_SELECTOR               = 0x00000800,
    GUEST_CS_SELECTOR               = 0x00000802,
    GUEST_SS_SELECTOR               = 0x00000804,
    GUEST_DS_SELECTOR               = 0x00000806,
    GUEST_FS_SELECTOR               = 0x00000808,
    GUEST_GS_SELECTOR               = 0x0000080a,
    GUEST_LDTR_SELECTOR             = 0x0000080c,
    GUEST_TR_SELECTOR               = 0x0000080e,
    HOST_ES_SELECTOR                = 0x00000c00,
    HOST_CS_SELECTOR                = 0x00000c02,
    HOST_SS_SELECTOR                = 0x00000c04,
    HOST_DS_SELECTOR                = 0x00000c06,
    HOST_FS_SELECTOR                = 0x00000c08,
    HOST_GS_SELECTOR                = 0x00000c0a,
    HOST_TR_SELECTOR                = 0x00000c0c,
    IO_BITMAP_A                     = 0x00002000,
    IO_BITMAP_A_HIGH                = 0x00002001,
    IO_BITMAP_B                     = 0x00002002,
    IO_BITMAP_B_HIGH                = 0x00002003,
    VM_EXIT_MSR_STORE_ADDR          = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH     = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH      = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH     = 0x0000200b,
    TSC_OFFSET                      = 0x00002010,
    TSC_OFFSET_HIGH                 = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH     = 0x00002013,
    VMCS_LINK_POINTER               = 0x00002800,
    VMCS_LINK_POINTER_HIGH          = 0x00002801,
    GUEST_IA32_DEBUGCTL             = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH        = 0x00002803,
    PIN_BASED_VM_EXEC_CONTROL       = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL       = 0x00004002,
    EXCEPTION_BITMAP                = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK      = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH     = 0x00004008,
    CR3_TARGET_COUNT                = 0x0000400a,
    VM_EXIT_CONTROLS                = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT         = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT          = 0x00004010,
    VM_ENTRY_CONTROLS               = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT         = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD        = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN        = 0x0000401a,
    TPR_THRESHOLD                   = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL       = 0x0000401e,
    VM_INSTRUCTION_ERROR            = 0x00004400,
    VM_EXIT_REASON                  = 0x00004402,
    VM_EXIT_INTR_INFO               = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE         = 0x00004406,
    IDT_VECTORING_INFO_FIELD        = 0x00004408,
    IDT_VECTORING_ERROR_CODE        = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN         = 0x0000440c,
    VMX_INSTRUCTION_INFO            = 0x0000440e,
    GUEST_ES_LIMIT                  = 0x00004800,
    GUEST_CS_LIMIT                  = 0x00004802,
    GUEST_SS_LIMIT                  = 0x00004804,
    GUEST_DS_LIMIT                  = 0x00004806,
    GUEST_FS_LIMIT                  = 0x00004808,
    GUEST_GS_LIMIT                  = 0x0000480a,
    GUEST_LDTR_LIMIT                = 0x0000480c,
    GUEST_TR_LIMIT                  = 0x0000480e,
    GUEST_GDTR_LIMIT                = 0x00004810,
    GUEST_IDTR_LIMIT                = 0x00004812,
    GUEST_ES_AR_BYTES               = 0x00004814,
    GUEST_CS_AR_BYTES               = 0x00004816,
    GUEST_SS_AR_BYTES               = 0x00004818,
    GUEST_DS_AR_BYTES               = 0x0000481a,
    GUEST_FS_AR_BYTES               = 0x0000481c,
    GUEST_GS_AR_BYTES               = 0x0000481e,
    GUEST_LDTR_AR_BYTES             = 0x00004820,
    GUEST_TR_AR_BYTES               = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO     = 0x00004824,
    GUEST_ACTIVITY_STATE            = 0x00004826,
    GUEST_SYSENTER_CS               = 0x0000482A,
    HOST_IA32_SYSENTER_CS           = 0x00004c00,
    CR0_GUEST_HOST_MASK             = 0x00006000,
    CR4_GUEST_HOST_MASK             = 0x00006002,
    CR0_READ_SHADOW                 = 0x00006004,
    CR4_READ_SHADOW                 = 0x00006006,
    CR3_TARGET_VALUE0               = 0x00006008,
    CR3_TARGET_VALUE1               = 0x0000600a,
    CR3_TARGET_VALUE2               = 0x0000600c,
    CR3_TARGET_VALUE3               = 0x0000600e,
    EXIT_QUALIFICATION              = 0x00006400,
    GUEST_LINEAR_ADDRESS            = 0x0000640a,
    GUEST_CR0                       = 0x00006800,
    GUEST_CR3                       = 0x00006802,
    GUEST_CR4                       = 0x00006804,
    GUEST_ES_BASE                   = 0x00006806,
    GUEST_CS_BASE                   = 0x00006808,
    GUEST_SS_BASE                   = 0x0000680a,
    GUEST_DS_BASE                   = 0x0000680c,
    GUEST_FS_BASE                   = 0x0000680e,
    GUEST_GS_BASE                   = 0x00006810,
    GUEST_LDTR_BASE                 = 0x00006812,
    GUEST_TR_BASE                   = 0x00006814,
    GUEST_GDTR_BASE                 = 0x00006816,
    GUEST_IDTR_BASE                 = 0x00006818,
    GUEST_DR7                       = 0x0000681a,
    GUEST_RSP                       = 0x0000681c,
    GUEST_RIP                       = 0x0000681e,
    GUEST_RFLAGS                    = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS    = 0x00006822,
    GUEST_SYSENTER_ESP              = 0x00006824,
    GUEST_SYSENTER_EIP              = 0x00006826,
    HOST_CR0                        = 0x00006c00,
    HOST_CR3                        = 0x00006c02,
    HOST_CR4                        = 0x00006c04,
    HOST_FS_BASE                    = 0x00006c06,
    HOST_GS_BASE                    = 0x00006c08,
    HOST_TR_BASE                    = 0x00006c0a,
    HOST_GDTR_BASE                  = 0x00006c0c,
    HOST_IDTR_BASE                  = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP          = 0x00006c10,
    HOST_IA32_SYSENTER_EIP          = 0x00006c12,
    HOST_RSP                        = 0x00006c14,
    HOST_RIP                        = 0x00006c16,
};

enum guest_activity_state {
    GUEST_STATE_ACTIVE          = 0,
    GUEST_STATE_HALT            = 1,
    GUEST_STATE_SHUTDOWN        = 2,
    GUEST_STATE_WAIT_SIPI       = 3,
};

#define VMCALL_OPCODE   ".byte 0x0f,0x01,0xc1\n"
#define VMCLEAR_OPCODE  ".byte 0x66,0x0f,0xc7\n"        /* reg/opcode: /6 */
#define VMLAUNCH_OPCODE ".byte 0x0f,0x01,0xc2\n"
#define VMPTRLD_OPCODE  ".byte 0x0f,0xc7\n"             /* reg/opcode: /6 */
#define VMPTRST_OPCODE  ".byte 0x0f,0xc7\n"             /* reg/opcode: /7 */
#define VMREAD_OPCODE   ".byte 0x0f,0x78\n"
#define VMRESUME_OPCODE ".byte 0x0f,0x01,0xc3\n"
#define VMWRITE_OPCODE  ".byte 0x0f,0x79\n"
#define VMXOFF_OPCODE   ".byte 0x0f,0x01,0xc4\n"
#define VMXON_OPCODE    ".byte 0xf3,0x0f,0xc7\n"

#define MODRM_EAX_06    ".byte 0x30\n" /* [EAX], with reg/opcode: /6 */
#define MODRM_EAX_07    ".byte 0x38\n" /* [EAX], with reg/opcode: /7 */
#define MODRM_EAX_ECX   ".byte 0xc1\n" /* [EAX], [ECX] */

/*
 * Exit Reasons
 */
#define VMX_EXIT_REASONS_FAILED_VMENTRY 0x80000000

#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MACHINE_CHECK       41

static inline void __vmptrld(uint64_t addr)
{
    /* TBD: do not crash on failure */
    __asm__ __volatile__ ( VMPTRLD_OPCODE
                           MODRM_EAX_06
                           /* CF==1 or ZF==1 --> crash (ud2) */
                           "ja 1f ; ud2 ; 1:\n"
                           :
                           : "a" (&addr)
                           : "memory");
}

static inline void __vmptrst(uint64_t addr)
{
    __asm__ __volatile__ ( VMPTRST_OPCODE
                           MODRM_EAX_07
                           :
                           : "a" (&addr)
                           : "memory");
}

static inline void __vmpclear(uint64_t addr)
{
    /* TBD: do not crash on failure */
    __asm__ __volatile__ ( VMCLEAR_OPCODE
                           MODRM_EAX_06
                           /* CF==1 or ZF==1 --> crash (ud2) */
                           "ja 1f ; ud2 ; 1:\n"
                           :
                           : "a" (&addr)
                           : "memory");
}

static inline unsigned long __vmread(unsigned long field)
{
    unsigned long ecx;

    /* TBD: do not crash on failure */
    __asm__ __volatile__ ( VMREAD_OPCODE
                           MODRM_EAX_ECX
                           /* CF==1 or ZF==1 --> crash (ud2) */
                           "ja 1f ; ud2 ; 1:\n"
                           : "=c" (ecx)
                           : "a" (field)
                           : "memory");

    return ecx;
}

static inline void __vmwrite(unsigned long field, unsigned long value)
{
    /* TBD: do not crash on failure */
    __asm__ __volatile__ ( VMWRITE_OPCODE
                           MODRM_EAX_ECX
                           /* CF==1 or ZF==1 --> crash (ud2) */
                           "ja 1f ; ud2 ; 1:\n"
                           :
                           : "a" (field) , "c" (value)
                           : "memory");
}

static inline void __vmlaunch (void)
{
    __asm__ __volatile__ ( VMLAUNCH_OPCODE
                           ::: "memory");
}

static inline void __vmresume (void)
{
    __asm__ __volatile__ ( VMRESUME_OPCODE
                           ::: "memory");
}

static inline void __vmxoff (void)
{
    __asm__ __volatile__ ( VMXOFF_OPCODE
                           ::: "memory");
}

static inline int __vmxon (uint64_t addr)
{
    int rc;

    __asm__ __volatile__ ( VMXON_OPCODE
                           MODRM_EAX_06
                           /* CF==1 or ZF==1 --> rc = -1 */
                           "setna %b0 ; neg %0"
                           : "=q" (rc)
                           : "0" (0), "a" (&addr)
                           : "memory");

    return rc;
}

extern void handle_init_sipi_sipi(unsigned int cpuid);
extern void force_aps_exit(void);

#endif      /* __TXT_VMCS_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
