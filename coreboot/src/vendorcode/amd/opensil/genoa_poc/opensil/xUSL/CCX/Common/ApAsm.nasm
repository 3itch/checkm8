;
; @file ApAsm.nasm
; @brief AP startup code.
; @details
;

;
; Copyright 2021-2023 Advanced Micro Devices, Inc. All rights reserved.
; SPDX-License-Identifier: MIT
;

%include "Porting.h"

BspMsrLocationOffset                    EQU 0
AP_STACK_SIZE                           EQU 600h

extern ASM_TAG(RegSettingBeforeLaunchingNextThread)
extern ASM_TAG(ApEntryPointInC)
extern ASM_TAG(mApLaunchGlobalData)
extern ASM_TAG(gBspCr3Value)
extern ASM_TAG(gApSyncFlag)

SECTION .bss
align 16
_ApStack:
resb AP_STACK_SIZE
_eApStack:

SECTION .text
global ASM_TAG(ApAsmCode) ; ApAsmCode Address is updated at offset 0x53 in ApStartupCode,
                          ; and ApStartupCode is copied temporarily into reset vector.

;------------------------------------------------------------------------------
; ApAsmCode
;
; @brief    AP startup code
;
; @details  ASM code executed by APs, called at end of ApStartupCode,
;           which syncs MSRs to BSP values, sets up GDT, calls
;           ApEntryPointInC, then allows the next AP to launch
;
;------------------------------------------------------------------------------
bits 32
ASM_TAG(ApAsmCode):
  mov edi, ASM_TAG(mApLaunchGlobalData)
  mov ax, 18h
  mov ds, ax
  mov es, ax
  mov ss, ax
%if IS64BIT == 1
  mov eax, cr4
  bts eax, 5                    ; Set PAE (bit #5)
  mov cr4, eax

  mov ecx, 0x0C0000080          ; Read EFER MSR
  rdmsr
  bts eax, 8                    ; Set LME (bit #8)
  wrmsr

  mov ecx, [ASM_TAG(gBspCr3Value)]        ; Load CR3 with value from BSP
  mov cr3, ecx

  mov eax, cr0
  bts eax, 31                   ; Set PG bit (bit #31)
  mov cr0, eax
  jmp 0x38:FarJump64   ; Set far jump to set code segment to 64bit

bits 64
FarJump64:
  mov ax, 30h
  mov ds, ax
  mov es, ax
  mov ss, ax

  mov rsp, _eApStack

%else

  mov esp, _eApStack

%endif

  ; Enable Fixed MTRR modification
  mov ecx, 0C0010010h
  rdmsr
  or  eax, 00080000h
  wrmsr

  ; Setup MSRs to BSP values
  mov esi, [edi + BspMsrLocationOffset]
MsrStart:
  mov ecx, [esi]
  cmp ecx, 0FFFFFFFFh
  jz MsrDone
  add esi, 4
  mov eax, [esi]
  add esi, 4
  mov edx, [esi]
  wrmsr
  add esi, 4
  jmp MsrStart

MsrDone:
  ; Disable Fixed MTRR modification and enable MTRRs
  mov ecx, 0C0010010h
  rdmsr
  and eax, 0FFF7FFFFh
  or  eax, 00140000h
  bt  eax, 21           ;SYS_CFG_MTRR_TOM2_EN
  jnc Tom2Disabled
  bts eax, 22           ;SYS_CFG_TOM2_FORCE_MEM_TYPE_WB
Tom2Disabled:
  wrmsr

%if IS64BIT == 1
  ; Enable caching
  mov rax, cr0
  btr eax, 30
  btr eax, 29
  mov cr0, rax
%else
  ; Enable caching
  mov eax, cr0
  btr eax, 30
  btr eax, 29
  mov cr0, eax
%endif

  and esp, ~0xf
  ; Call into C code before next thread is launched
  call ASM_TAG(RegSettingBeforeLaunchingNextThread)

  ; Call into C code
 call ASM_TAG(ApEntryPointInC)

ApDone:
  ; Increment call count to allow to launch next thread, after stack usage is done
  mov eax, ASM_TAG(gApSyncFlag)
  lock inc DWORD [eax]

  ; Hlt
Hlt_loop:
  cli
  hlt
  jmp Hlt_loop
