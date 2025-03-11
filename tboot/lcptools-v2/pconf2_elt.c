/*
 * PCONF2 policy element (LCP_PCONF_ELEMENT2) plugin
 *
 * Copyright (c) 2020 Cisco Systems, Inc. <pmoore2@cisco.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <arpa/inet.h>

#include <safe_lib.h>

#define PRINT printf

#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"

struct pcr_data {
    uint16_t alg;
    struct {
        bool valid;
        tb_hash_t value;
    } pcr[8];
};

static struct pcr_data pcrs;

static bool cmdline_handler(int c, const char *opt)
{
    int pcr;

    switch (c) {
    case 'a':
        /* hash algorithm */
        pcrs.alg = str_to_hash_alg(opt);
        if (pcrs.alg == TPM_ALG_NULL) {
            ERROR("Error: invalid hash algorithm\n");
            return false;
        }
        break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
        pcr = c - '0';
        /* convert the hash value into a tb_hash_t */
        if (!import_hash(opt, &pcrs.pcr[pcr].value, pcrs.alg)) {
            ERROR("Error: unable to parse the hash value\n");
            return false;
        }
        /* mark the pcr as valid for the pconf element and cleanup */
        pcrs.pcr[pcr].valid = true;
        break;
    default:
        /* invalid arg */
        return false;
    }

    return true;
}

static lcp_policy_element_t *create(void)
{
    unsigned int iter_a, iter_b;
    unsigned int pcr_count;
    size_t pcr_alg_size;

    size_t tpml_select_size;
    tpms_pcr_selection_t *tpms_select;
    tpml_pcr_selection_t *tpml_select = NULL;

    size_t pcr_comp_size;
    uint8_t *pcr_comp = NULL;

    size_t pcr_digest_size;
    tpm2b_digest_t *pcr_digest = NULL;

    uint8_t *tpm_quote;

    size_t pconf_size;
    lcp_pconf_element_t2 *pconf;

    size_t elt_size;
    lcp_policy_element_t *elt = NULL;

    /* NOTE: the intel txt sdk isn't very good when it comes to the pconf
     *       policy element format so we are basing much of this code on the
     *       lcp-gen2 python code */

    /* NOTE: this whole function could be written much better, but it was
     *       hacked on quite a bit while i was trying to get a valid pconf
     *       that the acm would accept */

    /* sanity checks */
    pcr_count = 0;
    for (iter_a = 0; iter_a <= 7; iter_a++) {
        if (pcrs.pcr[iter_a].valid)
            pcr_count++;
    }
    if (pcr_count == 0) {
        ERROR("Error: no PCRs specified for the pconf element\n");
        goto err;
    }
    if (pcrs.alg == 0) {
        /* do we want to default to sha1 instead of error? */
        ERROR("Error: no PCR has algorithm specified\n");
        goto err;
    }

    pcr_alg_size = get_hash_size(pcrs.alg);

    /* generate a TPMS_PCR_SELECTION and TPML_PCR_SELECTION */
    tpml_select_size = sizeof(*tpml_select) + 3; /* 24 pcrs */
    tpml_select = malloc(tpml_select_size);
    if (!tpml_select) {
        ERROR("Error: failed to allocate a TPMS_PCR_SELECTION\n");
        goto err;
    }
    tpml_select->count = htonl(1); /* txt requries this to be 1 */
    tpms_select = &tpml_select->pcr_selections;
    tpms_select->hash_alg = htons(pcrs.alg);
    tpms_select->size_of_select = 3;
    memset(tpms_select->pcr_select, 0x00, 3);
    for (iter_a = 0; iter_a <= 7; iter_a++) {
        /* TODO: why is this pcr_select[0] and not pcr_select[2]? python
         *       oddity? txt spec oddity? endian issue? */
        if (pcrs.pcr[iter_a].valid)
            tpms_select->pcr_select[0] |= (0x01 << iter_a);
    }

    /* generate a pcr composite */
    pcr_comp_size = pcr_alg_size * pcr_count;
    pcr_comp = malloc(pcr_comp_size);
    if (!pcr_comp) {
        ERROR("Error: failed to allocate a PCR composite buffer\n");
        goto err;
    }
    for (iter_a = 0, iter_b = 0; iter_a < 7 && iter_b < pcr_count; iter_a++) {
        if (pcrs.pcr[iter_a].valid) {
            memcpy(&pcr_comp[iter_b * pcr_alg_size],
                   &pcrs.pcr[iter_a].value, pcr_alg_size);
            iter_b++;
        }
    }

    /* generate a TPM2B_DIGEST using the pcr composite */
    /* TODO: not sure if this is correct, but reuse the pcr hash alg */
    pcr_digest_size = sizeof(*pcr_digest) + pcr_alg_size;
    pcr_digest = malloc(pcr_digest_size);
    if (!pcr_digest) {
        ERROR("Error: failed to allocate a TPM2B_DIGEST\n");
        goto err;
    }
    pcr_digest->size = htons(pcr_alg_size);
    if (!hash_buffer((void *)pcr_comp, pcr_comp_size,
                    (void *)pcr_digest->buffer, pcrs.alg)) {
        ERROR("Error: TPM2B_DIGEST hash operation failed\n");
        goto err;
    }

    /* generate TPMS_QUOTE_INFO, LCP_PCONF_ELEMENT2, and LCP_POLICY_ELEMENT */
    /* NOTE: we can't use tpms_quote_info_t since both fields are variable */
    pconf_size = sizeof(*pconf) + tpml_select_size + pcr_digest_size;
    elt_size = sizeof(*elt) + pconf_size;
    elt = malloc(elt_size);
    if (!elt) {
        ERROR("Error: failed to allocate a LCP_POLICY_ELEMENT\n");
        goto err;
    }
    elt->size = elt_size;
    elt->type = LCP_POLELT_TYPE_PCONF2;
    elt->policy_elt_control = 0;
    pconf = (void *)elt->data;
    pconf->hash_alg = pcrs.alg;
    pconf->num_pcr_infos = 1;
    tpm_quote = (void *)pconf->pcr_infos;
    memcpy(tpm_quote, tpml_select, tpml_select_size);
    memcpy(tpm_quote + tpml_select_size, pcr_digest, pcr_digest_size);

    /* cleanup and return a pointer to LCP_POLICY_ELEMENT */
    free(tpml_select);
    free(pcr_comp);
    free(pcr_digest);
    return elt;

err:
    if (tpml_select)
        free(tpml_select);
    if (pcr_comp)
        free(pcr_comp);
    if (pcr_digest)
        free(pcr_digest);
    if (elt)
        free(elt);
    return NULL;
}

static void display(const char *prefix, const lcp_policy_element_t *elt)
{
    unsigned int iter_a;
    uint8_t val;
    char prefix_nested[80];

    lcp_pconf_element_t2 *pconf;

    tpms_pcr_selection_t *tpms_select;
    tpml_pcr_selection_t *tpml_select;

    tpm2b_digest_t *pcr_digest;

    pconf = (void *)elt->data;

    snprintf(prefix_nested, sizeof(prefix_nested), "%s   ", prefix);

    DISPLAY("%salg: %s\n", prefix, hash_alg_to_string(pconf->hash_alg));

    /* TODO: we only show the first pcr_info right now, fix this (?) */
    tpml_select = &pconf->pcr_infos[0].pcr_selection;
    tpms_select = &tpml_select->pcr_selections;
    DISPLAY("%spcrs:", prefix);
    val = tpms_select->pcr_select[0];
    for (iter_a = 0; iter_a < 8; iter_a++) {
        if (val & 0x01)
            DISPLAY(" %d", iter_a);
        val >>= 1;
    }
    DISPLAY("\n");

    pcr_digest = (void *)(((uint8_t *)tpml_select) +
                          sizeof(*tpml_select) + tpms_select->size_of_select);
    DISPLAY("%squote:\n", prefix);
    print_hex(prefix_nested,
              pcr_digest->buffer, get_hash_size(pconf->hash_alg));
    DISPLAY("\n");
}

static struct option opts[] = {
    {"alg", required_argument, NULL, 'a'},
    {"pcr0", required_argument, NULL, '0'},
    {"pcr1", required_argument, NULL, '1'},
    {"pcr2", required_argument, NULL, '2'},
    {"pcr3", required_argument, NULL, '3'},
    {"pcr4", required_argument, NULL, '4'},
    {"pcr5", required_argument, NULL, '5'},
    {"pcr6", required_argument, NULL, '6'},
    {"pcr7", required_argument, NULL, '7'},
    {0, 0, 0, 0}
};

static polelt_plugin_t plugin = {
    "pconf2",
    opts,
    "      pconf2\n"
    "        --alg <sha1|sha256|sha384|sha512>      PCR hash alg\n"
    "        [--pcr0 <hash_value>]       PCR0 value\n"
    "        [--pcr1 <hash_value>]       PCR1 value\n"
    "        [--pcr2 <hash_value>]       PCR2 value\n"
    "        [--pcr3 <hash_value>]       PCR3 value\n"
    "        [--pcr4 <hash_value>]       PCR4 value\n"
    "        [--pcr5 <hash_value>]       PCR5 value\n"
    "        [--pcr6 <hash_value>]       PCR6 value\n"
    "        [--pcr7 <hash_value>]       PCR7 value\n",
    LCP_POLELT_TYPE_PCONF2,
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
