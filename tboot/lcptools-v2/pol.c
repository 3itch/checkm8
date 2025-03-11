/*
 * pol.c:
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <safe_lib.h>
#include <snprintf_s.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "polelt_plugin.h"
#include "pol.h"
#include "lcputils.h"

size_t get_policy_size(const lcp_policy_t2 *pol)
{
    return offsetof(lcp_policy_t2, policy_hash) +
           get_lcp_hash_size(pol->hash_alg);
}

bool verify_legacy_policy(const lcp_policy_t *pol, size_t size)
{
    LOG("[verify_legacy_policy]");
    size_t expected_size = offsetof(lcp_policy_t, policy_hash) + SHA1_DIGEST_SIZE;
    if (size != expected_size) {
        ERROR("Error: incorrect policy size. Expected %d.\n", expected_size);
        return false;
    }

    if (pol->version > LCP_VER_2_4 || pol->version < LCP_VER_2_0) {
        ERROR("Error: policy version incorrect.\n");
        return false;
    }

    if (pol->hash_alg != LCP_POLHALG_SHA1) { //Legacy value for TPM 1.2
        ERROR("Error: policy hash alg incorrect.\n");
        return false;
    }

    if (pol->policy_type != LCP_POLTYPE_ANY && pol->policy_type != LCP_POLTYPE_LIST) {
        ERROR("Error: policy type incorrect.\n");
        return false;
    }

    if ( pol->reserved1 != 0 || pol->reserved2 != 0 || 
         pol->reserved3 != 0 || pol->reserved4 != 0 ) {
             ERROR("Error: one of reserved fields not 0.\n");
             return false;
    }
    LOG("verify policy succeed!\n");
    return true;
}

bool verify_policy(const lcp_policy_t2 *pol, size_t size, bool silent)
{
    LOG("[verify_policy]\n");
    if ( get_policy_size(pol) > size ) {
        if ( !silent ) ERROR("Error: policy too big\n");
        return false;
    }

    if ( pol->version < LCP_DEFAULT_POLICY_VERSION ||
         MAJOR_VER(pol->version) != MAJOR_VER(LCP_DEFAULT_POLICY_VERSION) ) {
        if ( !silent ) ERROR("Error: invalid policy version: 0x%x\n",
                             pol->version);
        return false;
    }

    if ( !get_lcp_hash_size(pol->hash_alg) ) {
        if ( !silent ) ERROR("Error: invalid policy hash alg: %u\n",
                             pol->hash_alg);
        return false;
    }

    if ( pol->policy_type != LCP_POLTYPE_ANY &&
         pol->policy_type != LCP_POLTYPE_LIST ) {
        if ( !silent ) ERROR("Error: invlaid policy type: %u\n",
                             pol->policy_type);
        return false;
    }
    if ( pol->reserved2!= 0 ) {
        if ( !silent ) ERROR("Error: reserved fields not 0: %u\n",
                             pol->reserved2);
        return false;
    }
    LOG("verify policy succeed!\n");
    return true;
}

void display_legacy_policy(const char *prefix, const lcp_policy_t *pol)
{
    if (pol == NULL) {
        return;
    }
    DISPLAY("%s version: 0x%x\n", prefix, pol->version);
    DISPLAY("%s hash_alg: 0x%x (%s)\n", prefix, pol->hash_alg, hash_alg_to_str(pol->hash_alg));
    DISPLAY("%s policy_type: %s\n", prefix, policy_type_to_str(pol->policy_type));
    DISPLAY("%s sinit_min_version: 0x%x\n", prefix, pol->sinit_min_version);
    DISPLAY("%s data_revocation_counters: ", prefix);
    for ( unsigned int i = 0; i <  LCP_MAX_LISTS; i++ )
        DISPLAY("%u, ", pol->data_revocation_counters[i]);
    DISPLAY("\n");
    DISPLAY("%s policy_control: 0x%x\n", prefix, pol->policy_control);
    DISPLAY("%s max_sinit_min_ver: 0x%x\n", prefix, pol->max_sinit_min_version);
    if (pol->version < LCP_VER_2_4) {
        DISPLAY("%s max_biosac_min_ver: 0x%x\n", prefix, pol->reserved2);
    }
    DISPLAY("%s policy_hash: ", prefix);
    print_hex("", &pol->policy_hash, SHA1_DIGEST_SIZE);
}

void display_policy(const char *prefix, const lcp_policy_t2 *pol, bool brief)
{
    (void)brief;        /* quiet compiler warning portably */
    if ( pol == NULL )
        return;

    if ( prefix == NULL )
        prefix = "";

    DISPLAY("%s version: 0x%x\n", prefix, pol->version);
    DISPLAY("%s hash_alg: 0x%x (%s)\n", prefix, pol->hash_alg, hash_alg_to_str(pol->hash_alg));
    DISPLAY("%s policy_type: %s\n", prefix, policy_type_to_str(pol->policy_type));
    DISPLAY("%s sinit_min_version: 0x%x\n", prefix, pol->sinit_min_version);
    DISPLAY("%s data_revocation_counters: ", prefix);
    for ( unsigned int i = 0; i <  ARRAY_SIZE(pol->data_revocation_counters); i++ )
        DISPLAY("%u, ", pol->data_revocation_counters[i]);
    DISPLAY("\n");
    DISPLAY("%s policy_control: 0x%x\n", prefix, pol->policy_control);
    DISPLAY("%s max_sinit_min_ver: 0x%x\n", prefix, pol->max_sinit_min_ver);
    if (pol->version == LCP_VER_3_0) {
        DISPLAY("%s max_biosac_min_ver: 0x%x\n", prefix, pol->max_biosac_min_ver);  
    }
    else {
        DISPLAY("%s reserved: 0x%x\n", prefix, pol->max_biosac_min_ver);
    }
    
    DISPLAY("%s lcp_hash_alg_mask: 0x%x\n", prefix, pol->lcp_hash_alg_mask);
    DISPLAY("%s lcp_sign_alg_mask: 0x%x\n", prefix, pol->lcp_sign_alg_mask);
    if (pol->version == LCP_VER_3_0) {
        DISPLAY("%s aux_hash_alg_mask: 0x%x\n", prefix, pol->aux_hash_alg_mask);
    }
    else {
        DISPLAY("%s reserved2: 0x%x\n", prefix, pol->aux_hash_alg_mask);
    }
    DISPLAY("%s policy_hash: ", prefix);
    print_hex("", &pol->policy_hash, get_lcp_hash_size(pol->hash_alg));
}

const char *policy_type_to_str(uint8_t type)
{
    static const char *types[] = { "list", "any" };
    static char buf[32] = "";

    if ( type >= ARRAY_SIZE(types) ) {
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", type);
        return buf;
    }

    return types[type];
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
