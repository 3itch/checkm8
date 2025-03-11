/*
 * txt.h: Intel(r) TXT support functions
 *
 * Copyright (c) 2003-2008, Intel Corporation
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

#ifndef __TXT_TXT_H__
#define __TXT_TXT_H__

// #include <multiboot.h>

/* TPM event log types */
#define EVTLOG_UNKNOWN       0
#define EVTLOG_TPM12         1
#define EVTLOG_TPM2_LEGACY   2
#define EVTLOG_TPM2_TCG      3

extern bool txt_is_launched(void);
extern void txt_display_errors(void);
extern bool txt_has_error(void);
extern void txt_get_racm_error(void);
extern tb_error_t supports_txt(void);
extern tb_error_t txt_verify_platform(void);
extern bool txt_prepare_cpu(void);
extern tb_error_t txt_launch_environment(loader_ctx *lctx);
extern tb_error_t txt_launch_racm(loader_ctx *lctx);
extern void txt_post_launch(void);
extern tb_error_t txt_protect_mem_regions(void);
extern tb_error_t txt_post_launch_verify_platform(void);
extern bool txt_s3_launch_environment(void);
extern void txt_shutdown(void);
extern bool txt_is_powercycle_required(void);
extern void ap_wait(unsigned int cpuid);
extern int get_evtlog_type(void);
extern bool is_tpr_supported(void);

extern uint32_t g_using_da;
extern bool     g_tpr_support;
#endif      /* __TXT_TXT_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

