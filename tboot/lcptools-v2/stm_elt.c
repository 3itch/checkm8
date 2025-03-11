/*
 * mle_elt.c: MLE policy element (LCP_MLE_ELEMENT) plugin
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"

#define MAX_HASHES       32

static unsigned int nr_hashes;
static tb_hash_t hashes[MAX_HASHES];
static char alg_name[32] = "sha1";
static uint16_t alg_type = TPM_ALG_SHA1;

static bool parse_stm_line(const char *line)
{
    if ( nr_hashes == MAX_HASHES )
        return false;

    return parse_line_hashes(line, &hashes[nr_hashes++], alg_type);
}

static bool cmdline_handler(int c, const char *opt)
{
    if (c == 'a') {
        strlcpy(alg_name, opt,sizeof(alg_name));
        alg_type = str_to_hash_alg(alg_name);
        LOG("cmdline opt: hash alg: %s\n",alg_name);
        return true;
    }
    else if ( c != 0 ) {
        ERROR("Error: unknown option for mle type\n");
        return false;
    }

    /* MLE hash files */
    LOG("cmdline opt: mle hash file: %s\n", opt);
    if ( !parse_file(opt, parse_stm_line) )
        return false;

    return true;
}

static lcp_policy_element_t *create(void)
{
    LOG("[create]\n");
    size_t data_size =  sizeof(lcp_stm_element_t2) +
        nr_hashes * get_hash_size(alg_type);
    lcp_policy_element_t *elt = malloc(sizeof(*elt) + data_size);
    if ( elt == NULL ) {
        ERROR("Error: failed to allocate element\n");
        return NULL;
    }

    memset_s(elt, sizeof(*elt) + data_size, 0);
    elt->size = sizeof(*elt) + data_size;
    lcp_stm_element_t2 *stm = (lcp_stm_element_t2 *)&elt->data;
    stm->hash_alg = alg_type;
    stm->num_hashes = nr_hashes;
    lcp_hash_t2 *hash = stm->hashes;
    for ( unsigned int i = 0; i < nr_hashes; i++ ) {
        memcpy_s(hash, get_hash_size(alg_type), &hashes[i], get_hash_size(alg_type));
        hash = (void *)hash + get_hash_size(alg_type);
    }
    LOG("create stm element succeed!\n");
    return elt;
}

static void display(const char *prefix, const lcp_policy_element_t *elt)
{
    lcp_stm_element_t2 *stm = (lcp_stm_element_t2 *)elt->data;

    DISPLAY("%s hash_alg: %s\n", prefix, hash_alg_to_str(stm->hash_alg));
    DISPLAY("%s num_hashes: %u\n", prefix, stm->num_hashes);

    uint8_t *hash = (uint8_t *)&stm->hashes;
    unsigned int hash_size = get_hash_size(stm->hash_alg);
    for ( unsigned int i = 0; i < stm->num_hashes; i++ ) {
        DISPLAY("%s hashes[%u]: ", prefix, i);
        print_hex("", hash, hash_size);
        hash += hash_size;
    }
}


static struct option opts[] = {
    {"alg",            required_argument,    NULL,     'a'},
    {0, 0, 0, 0}
};

static polelt_plugin_t plugin = {
    "stm",
    opts,
    "      stm\n"
    "        [--alg <sha1|sha256|sha384|sha512>]    hash alg of element\n"
    "        <FILE1> [FILE2] ...         one or more files containing STM\n"
    "                                    hash(es); each file can contain\n"
    "                                    multiple hashes\n",
    LCP_POLELT_TYPE_STM2,
    &cmdline_handler,
    &create,
    &display
};

REG_POLELT_PLUGIN(&plugin)


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
