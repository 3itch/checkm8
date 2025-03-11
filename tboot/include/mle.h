/*
 * mle.h: Intel(r) TXT MLE header definition
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

#ifndef __MLE_H__
#define __MLE_H__

/*
 * SINIT/MLE capabilities
 */
typedef union {
    uint32_t  _raw;
    struct {
        uint32_t  rlp_wake_getsec     : 1;
        uint32_t  rlp_wake_monitor    : 1;
        uint32_t  ecx_pgtbl           : 1;
        uint32_t  stm                 : 1;
        uint32_t  pcr_map_no_legacy   : 1;
        uint32_t  pcr_map_da          : 1;
        uint32_t  platform_type       : 2;
        uint32_t  max_phy_addr        : 1;
        uint32_t  tcg_event_log_format: 1;
        uint32_t  cbnt_supported      : 1;
        uint32_t  reserved1           : 3;
        uint32_t  tpr_support         : 1;
        uint32_t  reserved2           : 17;
    };
} txt_caps_t;


/*
 * MLE header structure
 *   describes an MLE for SINIT and OS/loader SW
 */
typedef struct {
    uuid_t      uuid;
    uint32_t    length;
    uint32_t    version;
    uint32_t    entry_point;
    uint32_t    first_valid_page;
    uint32_t    mle_start_off;
    uint32_t    mle_end_off;
    txt_caps_t  capabilities;
    uint32_t    cmdline_start_off;
    uint32_t    cmdline_end_off;
} mle_hdr_t;

#define MLE_HDR_UUID      {0x9082ac5a, 0x476f, 0x74a7, 0x5c0f, \
                              {0x55, 0xa2, 0xcb, 0x51, 0xb6, 0x42}}

/*
 * values supported by current version of tboot
 */
#define MLE_HDR_VER       0x00020003     /* 2.3 */

#define MLE_HDR_CAPS      0x000004627 /* rlp_wake_{getsec, monitor} = 1
                                       * ecx_pgtbl = 1, nolg = 0, da = 1
                                       *  tcg_event_log_format = 1, cbnt_supported = 1 
                                       *  tpr_supported = 1 
                                       */

#endif      /* __MLE_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
