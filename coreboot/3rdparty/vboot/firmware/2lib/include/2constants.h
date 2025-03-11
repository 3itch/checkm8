/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * General vboot-related constants.
 *
 * Constants that need to be exposed to assembly files or linker scripts
 * may be placed here and imported via vb2_constants.h.
 */

#ifndef VBOOT_REFERENCE_2CONSTANTS_H_
#define VBOOT_REFERENCE_2CONSTANTS_H_

/*
 * Size of non-volatile data used by vboot.
 *
 * If you only support non-volatile data format V1, then use VB2_NVDATA_SIZE.
 * If you support V2, use VB2_NVDATA_SIZE_V2 and set context flag
 * VB2_CONTEXT_NVDATA_V2.
 */
#define VB2_NVDATA_SIZE 16
#define VB2_NVDATA_SIZE_V2 64

/* Size of secure data spaces used by vboot */
#define VB2_SECDATA_FIRMWARE_SIZE 10
#define VB2_SECDATA_KERNEL_SIZE_V02 13
#define VB2_SECDATA_KERNEL_SIZE_V10 40
#define VB2_SECDATA_KERNEL_MIN_SIZE 13
#define VB2_SECDATA_KERNEL_MAX_SIZE 64
#define VB2_SECDATA_FWMP_MIN_SIZE 40
#define VB2_SECDATA_FWMP_MAX_SIZE 64

/* Size of current secdata_kernel revision. Referenced by external projects. */
#define VB2_SECDATA_KERNEL_SIZE VB2_SECDATA_KERNEL_SIZE_V10

/*
 * Recommended size of work buffer for firmware verification stage.
 *
 * TODO: The recommended size really depends on which key algorithms are
 * used.  Should have a better / more accurate recommendation than this.
 */
#ifdef VB2_X86_RSA_ACCELERATION
#define VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE (20 * 1024)
#else
#define VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE (12 * 1024)
#endif

/*
 * Recommended size of work buffer for kernel verification stage.
 *
 * This is bigger because vboot 2.0 kernel preambles are usually padded to
 * 64 KB.
 *
 * TODO: The recommended size really depends on which key algorithms are
 * used.  Should have a better / more accurate recommendation than this.
 */
#define VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE (80 * 1024)

/* Recommended buffer size for vb2api_get_pcr_digest. */
#define VB2_PCR_DIGEST_RECOMMENDED_SIZE 32

/*
 * Alignment for work buffer pointers/allocations should be useful for any
 * data type. When declaring workbuf buffers on the stack, the caller should
 * use explicit alignment to avoid run-time errors. For example:
 *
 *    int foo(void)
 *    {
 *        struct vb2_workbuf wb;
 *        uint8_t buf[NUM] __attribute__((aligned(VB2_WORKBUF_ALIGN)));
 *        wb.buf = buf;
 *        wb.size = sizeof(buf);
 */

/* We want consistent alignment across all architectures.
   8-byte should work for all of them. */
#define VB2_WORKBUF_ALIGN 8

/* Maximum length of a HWID in bytes, counting terminating null. */
#define VB2_GBB_HWID_MAX_SIZE 256

/* Type and offset of flags member in vb2_gbb_header struct. */
#define VB2_GBB_FLAGS_OFFSET 12
#ifndef __ASSEMBLER__
#include <stdint.h>
typedef uint32_t vb2_gbb_flags_t;
/*
 * We use disk handles rather than indices.  Using indices causes problems if
 * a disk is removed/inserted in the middle of processing.
 *
 * TODO(b/181739551): move this to 2api.h when the VbExDisk* functions are
 * removed from vboot_api.h.
 */
typedef void *vb2ex_disk_handle_t;
#endif

/* Size of legacy VbSharedDataHeader struct.  Defined here to avoid including
   the struct definition as part of a vb2_api.h include. */
#define VB2_VBSD_SIZE 1096

#endif  /* VBOOT_REFERENCE_2CONSTANTS_H_ */
