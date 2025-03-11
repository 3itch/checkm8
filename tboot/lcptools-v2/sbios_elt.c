/*
 * sbios_elt.c: SBIOS policy element (LCP_SBIOS_ELEMENT) plugin
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

#define MAX_HASHES       33     /* +1 for fallback_hash */

static unsigned int nr_hashes;
static tb_hash_t hashes[MAX_HASHES];
static char alg_name[32] = "sha1";
static uint16_t alg_type = TPM_ALG_SHA1;

static uint16_t *get_num_hashes(lcp_sbios_element_t2 *sbios)
{
    /* because fallback_hash is variable size, need to calculate this */
    return (void *)&sbios->fallback_hash + get_hash_size(sbios->hash_alg) +
           sizeof(sbios->reserved2);
}

static lcp_hash_t2 *get_hashes(lcp_sbios_element_t2 *sbios)
{
    /* because fallback_hash is variable size, need to calculate this */
    return (void *)get_num_hashes(sbios) + sizeof(sbios->num_hashes);
}

static bool parse_sbios_line(const char *line)
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
        ERROR("Error: unknown option for sbios type\n");
        return false;
    }

    /* BIOS hash files */
    LOG("cmdline opt: sbios hash file: %s\n", opt);
    if ( !parse_file(opt, parse_sbios_line) )
        return false;
    if ( nr_hashes == 0 ) {
        ERROR("Error: no hashes provided\n");
        return false;
    }

    return true;
}

static lcp_policy_element_t *create(void)
{
    LOG("[create]\n");
    /* take entire struct size and subtract size of fallback_hash because
       sizeof(lcp_hash_t) is not accurate (hence get_hash_size()), then
       add it back in w/ 'nr_hashes' */
    size_t data_size =  sizeof(lcp_sbios_element_t2) - sizeof(lcp_hash_t2) +
                        nr_hashes * get_hash_size(alg_type);

    lcp_policy_element_t *elt = malloc(sizeof(*elt) + data_size);
    if ( elt == NULL ) {
        ERROR("Error: failed to allocate element\n");
        return NULL;
    }

    memset_s(elt, sizeof(*elt) + data_size, 0);
    elt->size = sizeof(*elt) + data_size;

    lcp_sbios_element_t2 *sbios = (lcp_sbios_element_t2 *)&elt->data;
    sbios->hash_alg = alg_type;
    memcpy_s(&sbios->fallback_hash, get_hash_size(alg_type), &hashes[0], get_hash_size(alg_type));
    *get_num_hashes(sbios) = nr_hashes - 1;
    lcp_hash_t2 *hash = get_hashes(sbios);
    for ( unsigned int i = 1; i < nr_hashes; i++ ) {
        memcpy_s(hash, get_hash_size(alg_type), &hashes[i], get_hash_size(alg_type));
        hash = (void *)hash + get_hash_size(alg_type);
    }

    LOG("create SBIOS element succeed!\n");
    return elt;
}

static void display(const char *prefix, const lcp_policy_element_t *elt)
{
    lcp_sbios_element_t2 *sbios = (lcp_sbios_element_t2 *)elt->data;
    unsigned int hash_size = get_lcp_hash_size(sbios->hash_alg);

    DISPLAY("%s hash_alg: %s\n", prefix, hash_alg_to_str(sbios->hash_alg));
    DISPLAY("%s fallback_hash: ", prefix);
    print_hex("", (tb_hash_t *)&sbios->fallback_hash, hash_size);
    DISPLAY("%s num_hashes: %u\n", prefix, *get_num_hashes(sbios));

    uint8_t *hash = (uint8_t *)get_hashes(sbios);
    for ( unsigned int i = 0; i < *get_num_hashes(sbios); i++ ) {
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
    "sbios",
    opts,
    "      sbios\n"
    "        [--alg <sha1|sha256|sha384|sha512>]    hash alg of element\n"
    "        <FILE1> [FILE2] ...         one or more files containing BIOS\n"
    "                                    hash(es); each file can contain\n"
    "                                    multiple hashes; the first hash in\n"
    "                                    the first file will be the fallback\n"
    "                                    hash\n",
    LCP_POLELT_TYPE_SBIOS2,
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
