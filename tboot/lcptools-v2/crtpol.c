/*
 * crtpol.c: Intel(R) TXT policy (LCP_POLICY) creation tool
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
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/uuid.h"
#include "../../include/lcp3.h"
#include "polelt_plugin.h"
#include "pol.h"
#include "poldata.h"
#include "lcputils.h"
#include "pollist2.h"
#include "pollist2_1.h"
#include "pollist1.h"

#define TOOL_VER_MAJOR 0x1
#define TOOL_VER_MINOR 0x1

static const char help[] =
    "Usage: lcp2_crtpol <COMMAND> [OPTION]\n"
    "Create an Intel(R) TXT policy (and policy data file)\n\n"
    "--create\n"
    "        --alg <sha1|sha256|sha384|sm3>    hash algorithm for the policy\n"
    "                                   if polver < 3 - alg is always sha1\n"
    "        --type <any|list>          type\n"
    "        [--minver <ver>]           SINITMinVersion\n"
    "        [--max_sinit_min]          MaxSINITMinVersion\n"
    "        [--rev <ctr1>[,ctrN]       8 revocation values (comma separated,\n"
    "                                   no spaces)\n"
    "        [--ctrl <pol ctrl]         policy control\n"
    "        --pol <FILE>               policy file\n"
    "        [--data <FILE>]            policy data file\n"
    "        [FILE]...                  policy list files\n"
    "        [--mask] <sha1|sha256|sha384|sm3>\n"
    "                                   Allowed policy hash algorithm(s)\n"
    "                                   Can be used more than once\n"
    "        [--auxalg]                 AUX allowed hash algorithm(s)\n"
    "                                   Not applicable for current LCP_POLICY v. 3.2\n"
    "        --sign                     <rsa-2048-sha1|rsa-2048-sha256|rsa-3072-sha256|\n"
    "                                   rsa-3072-sha384|ecdsa-p256|ecdsa-p384|sm2>\n"
    "                                   LCP allowed signing algorithm(s)\n"
    "                                   Can be used more than once\n"
    "        [--polver]                 LCP version:\n"
    "                                     TPM1.2: 2.0, 2.1, 2.2, 2.3, 2.4 \n"
    "                                     TPM2.0: 3.0, 3.1, 3.2>\n"
    "                                   If not set policy ver will be 3.0\n"
    "--show\n"
    "        [--brief]                  brief format output\n"
    "        [policy file]              policy file\n"
    "        [policy data file]         policy data file\n"
    "--help\n"
    "--verbose                          enable verbose output; can be\n"
    "                                   specified with any command\n"
    "--version                          show tool version.\n\n";

bool verbose = false;

static struct option long_opts[] =
{
    /* commands */
    {"help",           no_argument,          NULL,     'H'},
    {"version",        no_argument,          NULL,     'V'},
    {"create",         no_argument,          NULL,     'C'},
    {"show",           no_argument,          NULL,     'S'},

    /* options */
    {"alg",            required_argument,    NULL,     'a'},
    {"type",           required_argument,    NULL,     't'},
    {"minver",         required_argument,    NULL,     'm'},
    {"max_sinit_min",  required_argument,    NULL,     'n'},
    {"rev",            required_argument,    NULL,     'r'},
    {"ctrl",           required_argument,    NULL,     'c'},
    {"pol",            required_argument,    NULL,     'p'},
    {"data",           required_argument,    NULL,     'd'},
    {"brief",          no_argument,          NULL,     'b'},
    {"mask",           required_argument,    NULL,     'k'},
    {"auxalg",         required_argument,    NULL,     'x'},
    {"sign",           required_argument,    NULL,     's'},
    {"polver",         required_argument,    NULL,     'e'},

    {"verbose",        no_argument,          (int *)&verbose, true},
    {0, 0, 0, 0}
};

uint16_t       pol_ver = LCP_DEFAULT_POLICY_VERSION;
char           policy_file[MAX_PATH] = "";
char           poldata_file[MAX_PATH] = "";

char           lcp_alg_name[32] = "";
char           aux_alg_name[32] = "";
char           sign_alg_name[32] = "";
char           pol_ver_name[32] = "";
char           lcp_hash_mask_name[32] = "";
uint16_t       lcp_hash_alg = TPM_ALG_NULL;
uint16_t       aux_hash_alg = TPM_ALG_MASK_NULL;
uint16_t       lcp_hash_mask = TPM_ALG_MASK_NULL;

char           type[32] = "";
uint8_t        sinit_min_ver = 0;
unsigned int   nr_rev_ctrs = 0;
uint16_t       rev_ctrs[LCP_MAX_LISTS] = { 0 };
uint32_t       policy_ctrl = LCP_DEFAULT_POLICY_CONTROL;
uint32_t       lcp_sign_alg_mask = SIGN_ALG_MASK_NULL;
bool           brief = false;
unsigned int   nr_files = 0;
char           files[LCP_MAX_LISTS][MAX_PATH];
size_t         list_21_sizes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t        pol_type = LCP_POLTYPE_ANY;
uint8_t        max_sinit_min_version = 0xFF;
uint8_t        max_biosac_min_version = 0;

//Prototypes:
static int create_legacy(void);
static lcp_policy_data_t2 *create_poldata(void);
static int create(void);
static int show(void);

int create_legacy(void)
/*Attempt to create legacy policy for TPM 1.2*/
{
    lcp_policy_data_t2 *poldata = NULL;
    lcp_policy_t *pol = NULL;

    size_t policy_size = offsetof(lcp_policy_t, policy_hash) + SHA1_DIGEST_SIZE; //54 bytes
    LOG("[create_legacy]\n");
    pol = malloc(policy_size);
    if (pol == NULL) {
        ERROR("Error: failed to allocate policy.\n");
    }
    memset_s(pol, policy_size, 0x00);
    pol->version = pol_ver;
    pol->hash_alg = LCP_POLHALG_SHA1; //Legacy value for TPM 1.2
    pol->policy_type = pol_type;
    pol->sinit_min_version = sinit_min_ver;
    for ( unsigned int i = 0; i < nr_rev_ctrs; i++ )
        pol->data_revocation_counters[i] = rev_ctrs[i];
    pol->policy_control = policy_ctrl;
    pol->max_sinit_min_version = max_sinit_min_version;
    if (pol->policy_type == LCP_POLTYPE_LIST) {
        poldata = create_poldata();
        if (poldata == NULL) {
            ERROR("Error: failed to create policy data.\n");
            free(pol);
            return 1;
        }
        calc_policy_data_hash(poldata, (lcp_hash_t2 *) &pol->policy_hash, pol->hash_alg);
    }

    bool ok;
    ok = write_file(policy_file, pol, policy_size);
    if ( ok && pol->policy_type == LCP_POLTYPE_LIST )
        ok = write_file(poldata_file, poldata, get_policy_data_size(poldata));

    free(pol);
    if (poldata != NULL)
        free(poldata);
    return ok ? 0 : 1;
}

lcp_policy_data_t2 *create_poldata(void)
{
    lcp_policy_data_t2 *poldata = NULL;
    lcp_policy_list_t2_1 *pollist21 = NULL;
    void *file_data = NULL;
    lcp_list_t *pollist = NULL;

    bool no_sigblock_ok = false;
    size_t file_len;
    size_t list_size;
    uint16_t version;
    uint16_t use_only_version = 0; //Sets the version of list to use

    poldata = malloc(sizeof(*poldata));
    if ( poldata == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        return NULL;
    }
    memset_s(poldata, sizeof(*poldata), 0);
    strlcpy(poldata->file_signature, LCP_POLICY_DATA_FILE_SIGNATURE,
            sizeof(poldata->file_signature));
    poldata->num_lists = 0;

    for ( unsigned int i = 0; i < nr_files; i++ ) {
        file_data = read_file(files[i], &file_len, false);
        if ( file_data == NULL ) {
            free(poldata);
            return NULL;
        }
        memcpy_s((void*)&version, sizeof(uint16_t), file_data, sizeof(uint16_t));
        if (i == 0) {
            use_only_version = version; //Read version of first list
        }
        free(file_data);
        if ( use_only_version != version ) { //If version differs, that's error
            ERROR("ERROR: Mixing list versions is not supported.\n");
            free(poldata);
            return NULL;
        }
        if ( MAJOR_VER(version) == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION) ) {
                pollist = read_policy_list_file(files[i], false, &no_sigblock_ok);
                if ( pollist == NULL ) {
                    free(poldata);
                    return NULL;
                }
                poldata = add_tpm12_policy_list(poldata, (lcp_policy_list_t *)pollist);
                free(pollist);
                pollist = NULL;
        }
        else if( MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION) ) {
                pollist = read_policy_list_file(files[i], false, &no_sigblock_ok);
                if ( pollist == NULL ) {
                    free(poldata);
                    return NULL;
                }
                poldata = add_tpm20_policy_list(poldata, (lcp_policy_list_t2 *)pollist);
                free(pollist);
                pollist = NULL;
        }
        else if ( MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) ) {
            bool result;
            pollist21 = read_policy_list_2_1_file(false, files[i]);
            if (pollist21 == NULL) {
                free(poldata);
                return NULL;
            }
            if (pollist21->KeySignatureOffset != 0) { //list is signed
                result = verify_tpm20_pollist_2_1_sig(pollist21);
                if (!result) {
                    free(poldata);
                    return NULL;
                }
            }
            poldata = add_tpm20_policy_list2_1(poldata, &list_size, pollist21);
            if (poldata == NULL) {
                free(pollist21);
                return NULL;
            }
            list_21_sizes[i] = list_size;
            free(pollist21);
            pollist21 = NULL;
        }
        if ( poldata == NULL ) {
            return NULL;
        }
    }
    return poldata;
}

int create(void)
{
    lcp_policy_data_t2 *poldata = NULL;

    lcp_policy_t2 *pol = malloc(sizeof(*pol));
    if ( pol == NULL ) {
        ERROR("Error: failed to allocate policy\n");
        return 1;
    }
    memset_s(pol, sizeof(*pol), 0);
    pol->version = pol_ver;
    pol->hash_alg = lcp_hash_alg;
    pol->sinit_min_version = sinit_min_ver;
    for ( unsigned int i = 0; i < nr_rev_ctrs; i++ ) {
        pol->data_revocation_counters[i] = rev_ctrs[i];
    }
    pol->max_sinit_min_ver = max_sinit_min_version;
    pol->policy_control = policy_ctrl;

    if (aux_hash_alg == TPM_ALG_MASK_NULL && pol->version == LCP_VER_3_0) {
        pol->aux_hash_alg_mask = convert_hash_alg_to_mask(pol->hash_alg);
    }
    else {
        pol->aux_hash_alg_mask = aux_hash_alg;
    }

    if (lcp_hash_mask == TPM_ALG_MASK_NULL) {
        pol->lcp_hash_alg_mask = convert_hash_alg_to_mask(pol->hash_alg);
    }
    else{
        pol->lcp_hash_alg_mask = lcp_hash_mask;
    }
    pol->lcp_sign_alg_mask = lcp_sign_alg_mask;

    if ( strcmp(type, "any") == 0 ) {
        pol->policy_type = LCP_POLTYPE_ANY;
    }
    else if ( strcmp(type, "list") == 0 ) {
        pol->policy_type = LCP_POLTYPE_LIST;
        poldata = create_poldata();
        if (poldata == NULL) {
            poldata = malloc(sizeof(*poldata));
            if ( poldata == NULL ) {
                ERROR("Error: failed to allocate memory\n");
                free(pol);
                return 1;
            }
            memset_s(poldata, sizeof(*poldata), 0);
            strlcpy(poldata->file_signature, LCP_POLICY_DATA_FILE_SIGNATURE,
                    sizeof(poldata->file_signature));
            poldata->num_lists = 0;

            for ( unsigned int i = 0; i < nr_files; i++ ) {
                bool no_sigblock_ok = false;
                size_t file_len;
                uint16_t version;
                uint16_t use_only_version; //Sets the version of list to use
                lcp_list_t *pollist = NULL;
                void *file_data = read_file(files[i], &file_len, false);
                if ( file_data == NULL ) {
                    free(pol);
                    free(poldata);
                    return 1;
                }
                memcpy_s((void*)&version, sizeof(uint16_t), file_data, sizeof(uint16_t));
                if (i == 0) {
                    use_only_version = version; //Read version of first list
                }
                free(file_data);
                if ( use_only_version != version ) { //If version differs, that's error
                    ERROR("ERROR: Mixing list versions is not supported.\n");
                    free(pol);
                    free(poldata);
                    return 1;
                }
                if ( MAJOR_VER(version) == 1 ) {
                    pollist = read_policy_list_file(files[i], false, &no_sigblock_ok);
                    if ( pollist == NULL ) {
                        free(pol);
                        free(poldata);
                        return 1;
                    }
                    poldata = add_tpm12_policy_list(poldata,
                                (lcp_policy_list_t *)pollist);
                    free(pollist);
                    pollist = NULL;
                }
                else if( MAJOR_VER(version) == 2 ) {
                    pollist = read_policy_list_file(files[i], false, &no_sigblock_ok);
                    if ( pollist == NULL ) {
                        free(pol);
                        free(poldata);
                        return 1;
                    }
                    poldata = add_tpm20_policy_list(poldata,
                                (lcp_policy_list_t2 *)pollist);
                    free(pollist);
                    pollist = NULL;
                }
                else if ( MAJOR_VER(version) == 3 ) {
                    bool result;
                    lcp_policy_list_t2_1 *pollist21 = read_policy_list_2_1_file(false, files[i]);
                    if (pollist21 == NULL) {
                        free(pol);
                        free(poldata);
                        return 1;
                    }
                    if (pollist21->KeySignatureOffset != 0) { //list is signed
                        result = verify_tpm20_pollist_2_1_sig(pollist21);
                        if (!result) {
                            free(pol);
                            free(poldata);
                            return 1;
                        }
                    }
                    size_t list_size;
                    poldata = add_tpm20_policy_list2_1(poldata, &list_size ,pollist21);
                    if (poldata == NULL) {
                        free(pol);
                        free(pollist21);
                        return 1;
                    }
                    list_21_sizes[i] = list_size;
                    free(pollist21);
                    pollist21 = NULL;
                }
                if ( poldata == NULL ) {
                    free(pol);
                    return 1;
                }
            }
        }
        calc_policy_data_hash(poldata, &pol->policy_hash, pol->hash_alg);
    }
    else {
        ERROR("Error: unknown policy type\n");
        free(pol);
        return 1;
    }

    LOG("pol alg=0x%x, mask=0x%x, aux_mask=0x%x, sign_mask=0x%x\n", pol->hash_alg, pol->lcp_hash_alg_mask, pol->aux_hash_alg_mask, pol->lcp_sign_alg_mask);

    bool ok;
    ok = write_file(policy_file, pol, get_policy_size(pol));
    if ( ok && pol->policy_type == LCP_POLTYPE_LIST )
        ok = write_file(poldata_file, poldata, get_policy_data_size(poldata));

    free(pol);
    free(poldata);
    return ok ? 0 : 1;
}

int show(void)
{
    size_t len, pol_len = 0, poldata_len = 0;
    void *data;
    const char *pol_file = "", *poldata_file = "";
    lcp_policy_t2 *pol = NULL;
    lcp_policy_t *pol_legacy = NULL;
    lcp_policy_data_t2 *poldata = NULL;
    int err = 1;

    data = read_file(files[0], &len, false);
    if ( data == NULL )
        return 1;
    /*
     * files may be in any order or only one, so assume that if the
     * first file is not for policy then it must be for policy data
     */
    if ( verify_policy(data, len, true) ) {
        pol = data;
        pol_len = len;
        pol_file = files[0];
    }
    else if (verify_legacy_policy(data, len)) {
        pol_legacy = data;
        pol_len = len;
        pol_file = files[0];
    }
    else {
        poldata = (lcp_policy_data_t2 *)data;
        poldata_len = len;
        poldata_file = files[0];
    }

    if ( nr_files == 2 ) {
        data = read_file(files[1], &len, false);
        if ( data == NULL )
            goto done;
        if ( pol == NULL && pol_legacy == NULL ) {
            pol = data;
            pol_len = len;
            pol_file = files[1];
        }
        else {
            poldata = data;
            poldata_len = len;
            poldata_file = files[1];
        }
    }

    if ( pol != NULL ) {
        DISPLAY("policy file: %s\n", pol_file);
        if ( verify_policy(pol, pol_len, false) )
            display_policy("    ", pol, brief);
    }
    else {
        DISPLAY("policy file: %s\n", pol_file);
        if ( verify_legacy_policy(pol_legacy, pol_len) )
            display_legacy_policy("    ", pol_legacy);
    }

    if ( poldata != NULL ) {
        DISPLAY("\npolicy data file: %s\n", poldata_file);
        if ( !verify_policy_data(poldata, poldata_len) ) {
            goto done;
        }
        display_policy_data("    ", poldata, brief);
        if ( (pol && (pol->policy_type == LCP_POLTYPE_LIST)) ||
             (pol_legacy && (pol_legacy->policy_type == LCP_POLTYPE_LIST)) ) {
            lcp_hash_t2 hash;
            int diff;
            if (pol != NULL) {
                calc_policy_data_hash(poldata, &hash, pol->hash_alg);
                if ( 0 == memcmp_s(&hash, sizeof(hash), &pol->policy_hash,
                        get_lcp_hash_size(pol->hash_alg), &diff) && diff == 0 )
                    DISPLAY("\npolicy data hash matches policy hash\n");
                else {
                    ERROR("\nError: policy data hash does not match policy hash\n");
                    goto done;
                    }
                }
            else {
                calc_policy_data_hash(poldata, &hash, pol_legacy->hash_alg);
                if ( 0 == memcmp_s(&hash, sizeof(hash), &pol_legacy->policy_hash,
                                SHA1_DIGEST_SIZE, &diff) && diff == 0 )
                    DISPLAY("\npolicy data hash matches policy hash\n");
                else {
                    ERROR("\nError: policy data hash does not match policy hash\n");
                    goto done;
                }
            }
        }
        else
            goto done;
    }
    err = 0;

done:
    if (pol) {
        free(pol);
    }
        
    if (pol_legacy) {
        free(pol_legacy);
    }
        
    if (poldata) {
        free(poldata);
    }
        
    return err;
}

int main (int argc, char *argv[])
{
    int cmd = 0;
    bool prev_cmd = false;
    int c;

    do {
        c = getopt_long_only(argc, argv, "", long_opts, NULL);
        /*LOG("getopt: %c %s\n", c, optarg);*/
        switch (c) {
            /* commands */
        case 'H':          /* help */
        case 'C':          /* create */
        case 'S':          /* show */
        case 'V':          /* version */
            if ( prev_cmd ) {
                ERROR("Error: only one command can be specified\n");
                return 1;
            }
            prev_cmd = true;
            cmd = c;
            LOG("cmdline opt: command: %c\n", cmd);
            break;

	    case 'a':
            strlcpy(lcp_alg_name, optarg, sizeof(lcp_alg_name));
            lcp_hash_alg = str_to_hash_alg(lcp_alg_name);
            LOG("cmdline opt: alg: %s\n", lcp_alg_name);
            break;

    	    case 'p':            /* policy file */
            strlcpy(policy_file, optarg, sizeof(policy_file));
            LOG("cmdline opt: pol: %s\n", policy_file);
            break;

        case 'd':            /* policy data file */
            strlcpy(poldata_file, optarg, sizeof(poldata_file));
            LOG("cmdline opt: data: %s\n", poldata_file);
            break;

        case 't':            /* type */
            strlcpy(type, optarg, sizeof(type));
            LOG("cmdline opt: type: %s\n", type);
            if ( strcmp(type, "any") == 0 ) {
                pol_type = LCP_POLTYPE_ANY;
            }
            else if ( strcmp(type, "list") == 0 ) {
                pol_type = LCP_POLTYPE_LIST;
            }
            else {
                ERROR("Error: unsupported policy type.\n");
                return 1;
            }
            break;

        case 'r':            /* revocation counters */
            nr_rev_ctrs = ARRAY_SIZE(rev_ctrs);
            parse_comma_sep_ints(optarg, rev_ctrs, &nr_rev_ctrs);
            LOG("cmdline opt: rev: ");
            for ( unsigned int i = 0; i < nr_rev_ctrs; i++ )
                LOG("%u, ", rev_ctrs[i]);
            LOG("\n");
            break;

        case 'm':            /* SINITMinVersion */
            sinit_min_ver = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: minver: 0x%x (%u)\n", sinit_min_ver, sinit_min_ver);
            break;

        case 'n':           /*MaxSINITMinVersion*/
            max_sinit_min_version = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: max_sinit_min: 0x%x (%u)\n",
                                  max_sinit_min_version, max_sinit_min_version);
            break;

        case 'c':            /* PolicyControl */
            policy_ctrl = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: ctrl: 0x%x\n", policy_ctrl);
            break;

        case 'b':            /* brief */
            brief = true;
            LOG("cmdline opt: brief: %u\n", brief);
            break;

        case 'k':           /* policy hash algorithm mask */
            strlcpy(lcp_hash_mask_name, optarg, sizeof(lcp_hash_mask_name));
            lcp_hash_mask |= str_to_lcp_hash_mask(lcp_hash_mask_name);
            LOG("cmdline opt: hash alg mask: %s\n", lcp_hash_mask_name);
            LOG("approved hash algorithm mask value: = 0x%04X\n", lcp_hash_mask);
            if ( lcp_hash_mask == TPM_ALG_MASK_NULL ) {
                 ERROR("Error: LCP hash alg not supported\n");
                 return 1;
            }
            break;

        case 'x':           /* AUX hash algorithm */
            if ( pol_ver == 0x0302 ) {
                LOG("AUX hash alg not supported for LCP policy 3.x");
                break;
            }
            strlcpy(aux_alg_name, optarg, sizeof(aux_alg_name));
            LOG("cmdline opt: auxalg: %s\n", aux_alg_name);
            aux_hash_alg = str_to_lcp_hash_mask(aux_alg_name);
            if ( aux_hash_alg == TPM_ALG_MASK_NULL) {
                 ERROR("Error: AUX hash alg not supported\n");
                 return 1;
            }
            break;

        case 's':           /* LCP signing algorithm */
            if (MAJOR_VER(pol_ver) == MAJOR_VER(LCP_VER_2_0))
                break; //Option not supported for legacy policy
            else {
                strlcpy(sign_alg_name, optarg, sizeof(sign_alg_name));
                LOG("cmdline opt: sign: %s\n", sign_alg_name);
                lcp_sign_alg_mask |= str_to_sig_alg_mask(sign_alg_name, pol_ver, sizeof(sign_alg_name));
                LOG("approved signature alg mask value: 0x%04X\n", lcp_sign_alg_mask);
                if ( lcp_sign_alg_mask == SIGN_ALG_MASK_NULL) {
                    ERROR("Error: signing alg not supported\n");
                    return 1;
                }
            break;
            }
        case 'e':           /* LCP version */
            strlcpy(pol_ver_name, optarg, sizeof(pol_ver_name));
            LOG("cmdline opt: sign: %s\n", pol_ver_name);

            pol_ver = str_to_pol_ver(pol_ver_name);
            if ( pol_ver == LCP_VER_NULL) {
                 ERROR("Error: Invalid policy version\n");
                 return 1;
            }
            break;

        case 0:
        case -1:
            break;

        default:
            ERROR("Error: unrecognized option\n");
            return 1;
        }
    } while ( c != -1 );

    /* process any remaining argv[] items */
    while ( optind < argc && nr_files < ARRAY_SIZE(files) ) {
        LOG("cmdline opt: file: %s\n", argv[optind]);
        strlcpy(files[nr_files++], argv[optind], sizeof(files[0]));
        optind++;
    }

    if ( cmd == 0 ) {
        ERROR("Error: no command option was specified\n");
        return 1;
    }
    else if ( cmd == 'H' ) {      /* --help */
        DISPLAY("%s", help);
        return 0;
    }
    else if ( cmd == 'C' ) {      /* --create */
	uint16_t lcp_major_version = pol_ver & 0xFF00;

        if ( lcp_hash_alg == TPM_ALG_NULL && lcp_major_version == LCP_VER_3_0) {
            ERROR("Error: alg not supported or not specified.\n");
            return 1;
        }
        LOG("pol_ver & 0xFF00 is 0x%x\n", lcp_major_version);
        if ( lcp_major_version == LCP_VER_2_0 ){
            if ( lcp_sign_alg_mask != SIGN_ALG_MASK_NULL) {
                LOG("Info: Signature algorithm mask not defined for LCPv2, specified mask is ignored.\n");
            }
        }
        else if ( lcp_sign_alg_mask == SIGN_ALG_MASK_NULL) {
            ERROR("Error: LCPv3 signing alg mask not supported or not specified\n");
            return 1;
        }

        if ( *type == '\0' ) {
            ERROR("Error: no type specified\n");
            return 1;
        }
        if ( strcmp(type, "list") != 0 && strcmp(type, "any") != 0 ) {
            ERROR("Error: unknown type\n");
            return 1;
        }
        if ( *policy_file == '\0' ) {
            ERROR("Error: no policy file specified\n");
            return 1;
        }
        if ( strcmp(type, "list") == 0 && *poldata_file == '\0' ) {
            ERROR("Error: list type but no policy data file specified\n");
            return 1;
        }
        if ( strcmp(type, "list") == 0 && nr_files == 0 ) {
            ERROR("Error: list type but no policy lists specified\n");
            return 1;
        }
        if (lcp_major_version == LCP_VER_3_0) {
            return create();
        }
        else if (lcp_major_version == LCP_VER_2_0) {
            return create_legacy();
        }
        else {
            ERROR("Error: policy must be version 3.x or 2.x\n");
            return 1;
        }
    }
    else if ( cmd == 'S' ) {      /* --show */
        if ( nr_files == 0 ) {
            ERROR("Error: no policy or policy data file specified\n");
            return 1;
        }
        if ( nr_files > 2 ) {
            ERROR("Error: too many files specified\n");
            return 1;
        }
        return show();
    }

    else if ( cmd == 'V' ) /* --version */ {
        DISPLAY("lcp2_crtpol version: %i.%i", TOOL_VER_MAJOR,
                                              TOOL_VER_MINOR);
        return 0;
    }

    ERROR("Error: unknown command\n");
    return 1;
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
