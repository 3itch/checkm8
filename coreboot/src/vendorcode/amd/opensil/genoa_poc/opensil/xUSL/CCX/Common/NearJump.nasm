;
; @file NearJump.nasm
; @brief 16-bit Reset vector.
; @details
;

;
;Copyright 2021-2023 Advanced Micro Devices, Inc. All rights reserved.
;

%include "Porting.h"

global ASM_TAG(Jump16Bit)
global ASM_TAG(ResetVector)
global ASM_TAG(eResetVector)
extern ASM_TAG(ApAsmCode)

SECTION .text

align 16
Gdt:
  dq 0x0000000000000000 ; [00h] Null descriptor
  dq 0x00CF92000000FFFF ; [08h] Linear data segment descriptor
  dq 0x00CF9A000000FFFF ; [10h] Linear code segment descriptor
  dq 0x00CF92000000FFFF ; [18h] System data segment descriptor
  dq 0x00CF9A000000FFFF ; [20h] System code segment descriptor
  dq 0x0000000000000000 ; [28h] Spare segment descriptor
  dq 0x00CF93000000FFFF ; [30h] System data segment descriptor
  dq 0x00AF9B000000FFFF ; [38h] System code segment descriptor
  dq 0x0000000000000000 ; [40h] Spare segment descriptor
eGdt:

align 16
bits 16
ASM_TAG(Jump16Bit):
 ; The gdtaddr needs to be be relative to the data segment in order
 ; in order to properly dereference it. Since we know _ResetVector
 ; will be at CS:IP=0xfff0 we can use that as a reference.
 ;
 ; Quote from: "AMD Platform Security Processor BIOS Implementation Guide for
 ; Server EPYC Processors"
 ; On x86, the CPU fetches from the DRAM location per BootSaveArea and BIOS reset binary
 ; image’s destination. The reset vector is calculated as:
 ; – BiosResetVector[Physical address] = BIOS image destination + BIOS image size – 0x10
 ; – BiosResetVector[Segment] = BIOS image destination + BIOS image size – 0x10000
 ; – BiosResetVector[Offset] = 0xFFF0

 ; workaround: older nasm versions can't do 'o32' here.
 ; This is fixed in nasm 2.16
 ; o32 lgdt cs:[GdtPtr - (ASM_TAG(ResetVector) - 0xfff0)]
 db 0x2e ; CS override
 db 0x66 ; Operand prefix override
 db 0x0f, 0x01 ; LGDT
 db 0x16
 dw GdtPtr - (ASM_TAG(ResetVector) - 0xfff0)

 mov	eax, cr0	; Get control register 0
 or	eax, 0x3 	; Set PE bit (bit #0)
 mov	cr0, eax

 mov	eax, cr4
 or	eax, 0x600
 mov	cr4, eax

 mov	ax, 0x18
 mov	ds, eax
 mov	es, ax
 mov	fs, ax
 mov	gs, ax
 mov	ss, ax

 o32 a32 jmp dword 0x10:ASM_TAG(ApAsmCode)

align 4
GdtPtr:
	dw eGdt - Gdt -1 	; Limit
	dd Gdt            ; Base

align 16

ASM_TAG(ResetVector):
 nop
 jmp word	ASM_TAG(Jump16Bit)
ASM_TAG(eResetVector):
