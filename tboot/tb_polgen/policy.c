/*
 * policy.c: policy support functions
 *
 * Copyright (c) 2006-2008, Intel Corporation
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
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

/* buffer for policy read/written from/to policy file */
static uint8_t _policy_buf[MAX_TB_POLICY_SIZE];

tb_policy_t *g_policy = (tb_policy_t *)_policy_buf;

void *read_elt_file(const char *elt_filename, size_t *length)
{
    FILE *fp = fopen(elt_filename, "rb");
    if ( fp == NULL ) {
        error_msg("fopen %s failed, errno %s\n", elt_filename, strerror(errno));
        return NULL;
    }

    /* find size */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len <= 0) {
        error_msg("failed to get file len\n");
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    void *data = malloc(len);
    if ( data == NULL ) {
        error_msg("failed to allocate %ld bytes memory\n", len);
        fclose(fp);
        return NULL;
    }

    if ( fread(data, len, 1, fp) != 1 ) {
        error_msg("reading file %s failed, errono %s\n",
                  elt_filename, strerror(errno));
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    if ( length != NULL )
        *length = len;
    return data;
}

bool read_policy_file(const char *policy_filename, bool *file_exists)
{
    FILE *f = fopen(policy_filename, "r");
    if ( f == NULL ) {
        if ( file_exists != NULL )
            *file_exists = (errno != ENOENT);
        info_msg("fopen failed, errno %s\n", strerror(errno));
        return false;
    }
    if ( file_exists != NULL )
        *file_exists = true;

    /* clear for good measure */
    memset_s(_policy_buf, sizeof(_policy_buf), 0);

    size_t read_cnt = fread(_policy_buf, 1, sizeof(_policy_buf), f);
    if ( ferror(f) ) {
        error_msg("fread failed, errno %s\n", strerror(errno));
        fclose(f);
        return false;
    }
    if ( read_cnt == 0 ) {
        error_msg("Policy file %s is empty\n", policy_filename);
        fclose(f);
        return false;
    }

    fclose(f);
    
    if ( !verify_policy(g_policy, read_cnt, verbose) ) {
        error_msg("Policy file %s is corrupt\n", policy_filename);
        return false;
    }

    return true;
}

bool write_policy_file(const char *policy_filename)
{
    verify_policy(g_policy, sizeof(_policy_buf), verbose);

    FILE *f = fopen(policy_filename, "w");
    if ( f == NULL ) {
        info_msg("fopen failed, errno %s\n", strerror(errno));
        return false;
    }

    size_t pol_size = calc_policy_size(g_policy);
    size_t write_cnt = fwrite(_policy_buf, 1, pol_size, f);
    if ( write_cnt != pol_size ) {
        info_msg("error writing policy, errno %s\n", strerror(errno));
        fclose(f);
        return false;
    }

    fclose(f);

    return true;
}

void new_policy(int policy_type, int policy_control, int hash_alg)
{
    /* current version is 2 */
    g_policy->version = 2;

    g_policy->hash_alg = hash_alg;

    g_policy->num_entries = 0;

    modify_policy(policy_type, policy_control);
}

void modify_policy(int policy_type, int policy_control)
{
    if ( policy_type != -1 )
        g_policy->policy_type = policy_type;

    g_policy->policy_control = (uint32_t)policy_control;
}

tb_policy_entry_t *add_pol_entry(uint8_t mod_num, uint8_t pcr,
                                 uint8_t hash_type)
{
    /* assumes check for existing mod_num already done */

    info_msg("adding new policy entry for mod_num %u (pcr: %u, "
             "hash_type: %u)\n", mod_num, pcr, hash_type);

    /* TODO:  if there is already a MOD_NUM_ANY entry then insert this */
    /* new one before it */

    /* always goes at end of policy, so no need to make space, */
    /* just find end of policy data */
    size_t size = calc_policy_size(g_policy);
    if ( size + sizeof(tb_policy_entry_t) > sizeof(_policy_buf) )
        return NULL;
    tb_policy_entry_t *pol_entry = (tb_policy_entry_t *)(_policy_buf + size);

    pol_entry->mod_num = mod_num;
    pol_entry->pcr = pcr;
    pol_entry->hash_type = hash_type;
    pol_entry->num_hashes = 0;

    g_policy->num_entries++;

    return pol_entry;
}

void modify_pol_entry(tb_policy_entry_t *pol_entry, uint8_t pcr,
                      uint8_t hash_type)
{
    if ( pol_entry == NULL )
        return;

    info_msg("modifying policy entry for mod_num %u\n", pol_entry->mod_num);

    pol_entry->pcr = pcr;
    pol_entry->hash_type = hash_type;
}

bool add_hash(tb_policy_entry_t *pol_entry, const tb_hash_t *hash)
{
    if ( pol_entry == NULL )
        return false;

    /* since pol_entry may not be last in policy, need to make space */
    size_t pol_size = calc_policy_size(g_policy);
    size_t hash_size = get_hash_size(g_policy->hash_alg);
    if ( pol_size + hash_size > sizeof(_policy_buf) )
        return false;
    unsigned char *entry_end = (unsigned char *)pol_entry + sizeof(*pol_entry)
                               + (pol_entry->num_hashes * hash_size);
    unsigned char *pol_end = _policy_buf + pol_size;
    memmove_s(entry_end + hash_size, pol_end - entry_end,
            entry_end, pol_end - entry_end);

    copy_hash((tb_hash_t *)entry_end, hash, g_policy->hash_alg);
    pol_entry->num_hashes++;

    return true;
}

bool del_hash(tb_policy_entry_t *pol_entry, int i)
{
    if ( pol_entry == NULL )
        return false;
    if ( i < 0 || i >= pol_entry->num_hashes )
        return false;

    void *start = get_policy_entry_hash(pol_entry, g_policy->hash_alg, i);
    size_t size = get_hash_size(g_policy->hash_alg);
    memmove_s(start, calc_policy_size(g_policy), 
            start + size, calc_policy_size(g_policy) - size);

    pol_entry->num_hashes--;

    return true;
}

bool del_entry(tb_policy_entry_t *pol_entry)
{
    if ( pol_entry == NULL )
        return false;

    void *start = pol_entry;
    size_t size = calc_policy_entry_size(pol_entry, g_policy->hash_alg);
    memmove_s(start, calc_policy_size(g_policy),
            start + size, calc_policy_size(g_policy) - size);

    g_policy->num_entries--;

    return true;
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
