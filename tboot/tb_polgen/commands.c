/*
 * commands.c: handlers for commands
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp2.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

extern tb_policy_t *g_policy;

static bool hash_file(const char *filename, bool unzip, tb_hash_t *hash, uint16_t hash_alg)
{
    FILE *f;
    static char buf[1024];
    int read_cnt;

    if ( unzip )
        f = (FILE *)gzopen(filename, "rb");
    else
        f = fopen(filename, "rb");

    if ( f == NULL ) {
        error_msg("File %s does not exist\n", filename);
        return false;
    }

    const EVP_MD *md;
    uint8_t* hash_out;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

     switch (hash_alg) {
        case TB_HALG_SHA1:
            md = EVP_sha1();
            hash_out = hash->sha1;
            break;
        case TB_HALG_SHA256:
            md = EVP_sha256();
            hash_out = hash->sha256;
            break;
        case TB_HALG_SHA384:
            md = EVP_sha384();
            hash_out = hash->sha384;
            break;
        case TB_HALG_SHA512:
            md = EVP_sha512();
            hash_out = hash->sha512;
            break;
        default:
            error_msg("unsupported hash alg (%d)\n", hash_alg);
            EVP_MD_CTX_destroy(ctx);
            if ( unzip ) {
                gzclose((gzFile)f);
            } else {
                fclose(f);
            }
            return false;
    }

    EVP_DigestInit(ctx, md);
    do {
        if ( unzip )
            read_cnt = gzread((gzFile)f, buf, sizeof(buf));
        else
            read_cnt = fread(buf, 1, sizeof(buf), f);
        if ( read_cnt == 0 )
            break;

        EVP_DigestUpdate(ctx, buf, read_cnt);
    } while ( true );
    EVP_DigestFinal(ctx, hash_out, NULL);

    if ( unzip )
        gzclose((gzFile)f);
    else
        fclose(f);
    
    EVP_MD_CTX_destroy(ctx);
    return true;
}

bool do_show(const param_data_t *params)
{
    /* read the policy file */
    if ( !read_policy_file(params->policy_file, NULL) ) {
        error_msg("Error reading policy file %s\n", params->policy_file);
        return false;
    }

    /* this also displays it */
    verify_policy(g_policy, calc_policy_size(g_policy), true);

    return true;
}

bool do_create(const param_data_t *params)
{
    bool existing_policy = false;

    /* read the policy file, if it exists */
    info_msg("reading existing policy file %s...\n", params->policy_file);
    if ( !read_policy_file(params->policy_file, &existing_policy) ) {
        /* this means there was an error reading an existing file */
        if ( existing_policy ) {
            error_msg("Error reading policy file %s\n", params->policy_file);
            return false;
        }
    }
    
    /* policy_type must be specified for new policy */
    if ( !existing_policy && params->policy_type == -1 ) {
        error_msg("Must specify --policy_type for new policy\n");
        return false;
    }

    /* if file does not exist then create empty policy */
    if ( !existing_policy )
        new_policy(params->policy_type, params->policy_control, params->hash_alg);
    else {
        error_msg("warning: modifying existing policy file, hash algorithm "
                  "will not be changed\n");
        modify_policy(params->policy_type, params->policy_control);
    }

    info_msg("writing new policy file...\n");
    if ( !write_policy_file(params->policy_file) )
        return false;

    return true;
}

bool do_add(const param_data_t *params)
{
    /* read the policy file, if it exists */
    info_msg("reading existing policy file %s...\n", params->policy_file);
    if ( !read_policy_file(params->policy_file, NULL) ) {
        error_msg("Error reading policy file %s\n", params->policy_file);
        return false;
    }

    /* see if there is already an entry for this module */
    tb_policy_entry_t *pol_entry = find_policy_entry(g_policy,
                                                     params->mod_num);
    if ( pol_entry == NULL || pol_entry->mod_num != params->mod_num ) {
        /* since existing entry whose mod_num is TB_POL_MOD_NUM_ANY will */
        /* match, exclude it unless that is what is being added */
        pol_entry = add_pol_entry(params->mod_num, params->pcr,
                                  params->hash_type);
        if ( pol_entry == NULL ) {
            error_msg("cannot add another entry\n");
            return false;
        }
    }
    else
        modify_pol_entry(pol_entry, params->pcr, params->hash_type);

    /* hash command line and files */
    if ( params->hash_type == TB_HTYPE_IMAGE ) {
        tb_hash_t final_hash, hash;

        /* hash command line */
        info_msg("hashing command line \"%s\"...\n", params->cmdline);
        hash_buffer((unsigned char *)params->cmdline,
                    strnlen_s(params->cmdline, sizeof(params->cmdline)),
                    &final_hash, g_policy->hash_alg);
        if ( verbose ) {
            info_msg("hash is...");
            print_hash(&final_hash, g_policy->hash_alg);
        }

        /* hash file */
        info_msg("hashing image file %s...\n", params->image_file);
	if ( !hash_file(params->image_file, true, &hash, g_policy->hash_alg) ) {
            return false;
	}
        if ( verbose ) {
            info_msg("hash is...");
            print_hash(&hash, g_policy->hash_alg);
        }

        if ( !extend_hash(&final_hash, &hash, g_policy->hash_alg) ){
            return false;
	}

        if ( verbose ) {
            info_msg("cumulative hash is...");
            print_hash(&final_hash, g_policy->hash_alg);
        }

        if ( !add_hash(pol_entry, &final_hash) ) {
            error_msg("cannot add another hash\n");
            return false;
        }
    }

    info_msg("writing new policy file...\n");
    if ( !write_policy_file(params->policy_file) )
        return false;

    return true;
}

bool do_del(const param_data_t *params)
{
    /* read the policy file, if it exists */
    info_msg("reading existing policy file %s...\n", params->policy_file);
    if ( !read_policy_file(params->policy_file, NULL) ) {
        error_msg("Error reading policy file %s\n", params->policy_file);
        return false;
    }

    /* see if there is an entry for this module */
    tb_policy_entry_t *pol_entry = find_policy_entry(g_policy,
                                                     params->mod_num);
    if ( pol_entry == NULL ) {
        error_msg("specified mod_num does not exist\n");
        return false;
    }

    /* if pos was specified, find it */
    if ( params->pos != -1 ) {
        if ( params->pos >= pol_entry->num_hashes ) {
            error_msg("specified pos does not exist\n");
            return false;
        }
        /* if entry only has 1 hash, then delete the entire entry */
        if ( pol_entry->num_hashes == 1 ) {
            if ( !del_entry(pol_entry) ) {
                error_msg("failed to delete entry\n");
                return false;
            }
        }
        else {
            if ( !del_hash(pol_entry, params->pos) ) {
                error_msg("failed to delete hash\n");
                return false;
            }
        }
    }
    else {
        if ( !del_entry(pol_entry) ) {
            error_msg("failed to delete entry\n");
            return false;
        }
    }

    info_msg("writing new policy file...\n");
    if ( !write_policy_file(params->policy_file) )
        return false;

    return true;
}

bool do_unwrap(const param_data_t *params)
{
    bool ret = false;

    /* read the elt file */
    info_msg("reading existing elt file %s...\n", params->elt_file);
    size_t file_len;
    void *file = read_elt_file(params->elt_file, &file_len);
    if ( file == NULL ) {
        error_msg("Error reading elt file %s\n", params->elt_file);
        return false;
    }

    if ( sizeof(lcp_policy_element_t) > file_len ) {
        error_msg("data is too small\n");
        goto exit;
    }

    lcp_policy_element_t *elt = (lcp_policy_element_t *)file;
    if ( file_len != elt->size ) {
        error_msg("data is too small\n");
        goto exit;
    }

    if ( elt->type != LCP_POLELT_TYPE_CUSTOM ) {
        error_msg("Bad element type %u (i.e. non-custom)\n", elt->type);
        goto exit;
    }

    lcp_custom_element_t *custom = (lcp_custom_element_t *)&elt->data;
    tb_policy_t *pol = (tb_policy_t *)&custom->data;

    memcpy_s(g_policy, MAX_TB_POLICY_SIZE, pol, calc_policy_size(pol));

    info_msg("writing/overwriting policy file...\n");
    if ( !write_policy_file(params->policy_file) )
        goto exit;

    ret = true;

exit:
    free(file);
    file = NULL;

    return ret;
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
