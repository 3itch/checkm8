/*
 * polelt_plugin.h: policy element plugin support
 *
 * Copyright (c) 2014, Intel Corporation
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

#ifndef __POLELT_PLUGIN_H__
#define __POLELT_PLUGIN_H__

#define MAX_ELT_TYPE_STR_LEN     32

typedef struct {
    const char *type_string;
    struct option *cmdline_opts;
    const char *help_txt;
    uint32_t type;

    /* c = option char (or 0 for non-option args) */
    bool (*cmdline_handler)(int c, const char *opt);
    /* uses state from cmdline_handler */
    lcp_policy_element_t *(*create_elt)(void);
    void (*display)(const char *prefix, const lcp_policy_element_t *elt);
} polelt_plugin_t;

extern unsigned int     nr_polelt_plugins;
extern polelt_plugin_t *polelt_plugins[];

#define REG_POLELT_PLUGIN(plugin)                               \
    static void reg_plugin(void) __attribute__ ((constructor)); \
    static void reg_plugin(void)                                \
    {                                                           \
        polelt_plugins[nr_polelt_plugins++] = plugin;           \
    }

/* users must define these: */
extern void ERROR(const char *fmt, ...);
extern void LOG(const char *fmt, ...);
extern void DISPLAY(const char *fmt, ...);

#endif    /* __POLELT_PLUGIN_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
