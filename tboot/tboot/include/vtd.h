/*
 * vtd.c: VT-d support functions
 *
 * Copyright (c) 2019, Intel Corporation
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

#ifndef __VTD_H__
#define __VTD_H__

#define VTD_OPERATION_TIMEOUT 0x10000000
 
#define VTD_GCMD_OFFSET        0x18
  #define TE_EN                (1 << 31)
  #define QIE_EN               (1 << 26)
  #define IRE_EN               (1 << 25)
 
#define VTD_GSTS_OFFSET        0x1C
  #define TE_STAT              (1 << 31)
  #define QIE_STAT             (1 << 26)
  #define IRE_STAT             (1 << 25)

#define VTD_IQH_OFFSET         0x80
#define VTD_IQT_OFFSET         0x88

bool vtd_bios_enabled(void);
bool vtd_save_dmar_table(void);
bool vtd_restore_dmar_table(void);
bool vtd_remove_dmar_table(void);

struct dmar_remapping *vtd_get_dmar_remap(uint32_t *remap_length);
bool vtd_disable_dma_remap(struct dmar_remapping *rs);
bool vtd_disable_qie(struct dmar_remapping *rs);
bool vtd_disable_ire(struct dmar_remapping *rs);

#endif