/*
 * pollist1.c:
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
#define PRINT   printf
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "../include/lcp3_hlp.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist1.h"
#include "pollist2.h"
#include "polelt.h"

bool verify_tpm12_policy_list(const lcp_policy_list_t *pollist, size_t size,
        bool *no_sigblock, bool size_is_exact)
{
    if ( pollist == NULL )
        return false;

    if ( size < sizeof(*pollist) ) {
        ERROR("Error: data is too small (%u)\n", size);
        return false;
    }

    if ( pollist->version != LCP_TPM12_POLICY_LIST_VERSION ) {
        ERROR("Error: unsupported version 0x%04x\n", pollist->version);
        return false;
    }

    if ( pollist->reserved != 0 ) {
        ERROR("Error: reserved field must be 0: %u\n", pollist->reserved);
        return false;
    }

    if ( pollist->sig_alg != LCP_POLSALG_NONE &&
            pollist->sig_alg != LCP_POLSALG_RSA_PKCS_15 ) {
        ERROR("Error: unsupported sig_alg %u\n", pollist->sig_alg);
        return false;
    }

    /* verify policy_elements_size */
    size_t base_size = offsetof(lcp_policy_list_t, policy_elements);
    /* no sig, so size should be exact */
    if ( pollist->sig_alg == LCP_POLSALG_NONE ) {
        if ( size_is_exact &&
                base_size + pollist->policy_elements_size != size ) {
            ERROR("Error: size incorrect (no sig): 0x%x != 0x%x\n",
                    base_size + pollist->policy_elements_size, size);
            return false;
        }
        else if ( !size_is_exact &&
                base_size + pollist->policy_elements_size > size ) {
            ERROR("Error: size incorrect (no sig): 0x%x > 0x%x\n",
                    base_size + pollist->policy_elements_size, size);
            return false;
        }
    }
    /* verify size exactly later, after check sig field */
    else if ( base_size + sizeof(lcp_signature_t) +
            pollist->policy_elements_size  > size ) {
        ERROR("Error: size incorrect (sig min): 0x%x > 0x%x\n",
                base_size + sizeof(lcp_signature_t) +
                pollist->policy_elements_size, size);
        return false;
    }

    /* verify sum of policy elements' sizes */
    uint32_t elts_size = 0;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size < pollist->policy_elements_size ) {
        if ( elts_size + elt->size > pollist->policy_elements_size ) {
            ERROR("Error: size incorrect (elt size): 0x%x > 0x%x\n",
                    elts_size + elt->size, pollist->policy_elements_size);
            return false;
        }
        elts_size += elt->size;
        elt = (void *)elt + elt->size;
    }
    if ( elts_size != pollist->policy_elements_size ) {
        ERROR("Error: size incorrect (elt size): 0x%x != 0x%x\n",
                elts_size, pollist->policy_elements_size);
        return false;
    }

    /* verify sig */
    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 ) {
        lcp_signature_t *sig = (lcp_signature_t *)
            ((void *)&pollist->policy_elements + pollist->policy_elements_size);

        /* check size w/ sig_block */
        if ( !size_is_exact && base_size + pollist->policy_elements_size +
                get_tpm12_signature_size(sig) > size + sig->pubkey_size ) {
            ERROR("Error: size incorrect (sig): 0x%x > 0x%x\n",
                    base_size + pollist->policy_elements_size +
                    get_tpm12_signature_size(sig), size + sig->pubkey_size);
            return false;
        }
        else if ( size_is_exact && base_size + pollist->policy_elements_size +
                get_tpm12_signature_size(sig) != size ) {
            /* check size w/o sig_block */
            if ( base_size + pollist->policy_elements_size +
                    get_tpm12_signature_size(sig) != size + sig->pubkey_size ) {
                ERROR("Error: size incorrect (sig exact): 0x%x != 0x%x\n",
                        base_size + pollist->policy_elements_size +
                        get_tpm12_signature_size(sig), size + sig->pubkey_size);
                return false;
            }
            else {
                if ( no_sigblock != NULL )
                    *no_sigblock = true;
            }
        }
        else {
            if ( no_sigblock != NULL )
                *no_sigblock = false;
            if ( !verify_tpm12_pollist_sig(pollist) ) {
                ERROR("Error: signature does not verify\n");
                return false;
            }
        }
    }
    else {
        if ( no_sigblock != NULL )
            *no_sigblock = false;
    }

    return true;
}

void display_tpm12_policy_list(const char *prefix, const lcp_policy_list_t *pollist,
        bool brief)
{
    static const char *sig_alg_str[] =
    { "LCP_POLSALG_NONE", "LCP_POLSALG_RSA_PKCS_15" };

    if ( pollist == NULL )
        return;

    if ( prefix == NULL )
        prefix = "";

    DISPLAY("%s version: 0x%x\n", prefix, pollist->version);
    DISPLAY("%s sig_alg: 0x%x, %s\n", prefix, pollist->sig_alg, sig_alg_str[pollist->sig_alg]);
    DISPLAY("%s policy_elements_size: 0x%x (%u)\n", prefix,
            pollist->policy_elements_size, pollist->policy_elements_size);

    char new_prefix[strnlen_s(prefix, 20)+8];
    strcpy_s(new_prefix, sizeof(new_prefix), prefix);
    strcat_s(new_prefix, sizeof(new_prefix), "    ");
    unsigned int i = 0;
    size_t elts_size = pollist->policy_elements_size;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        DISPLAY("%s policy_element[%u]:\n", prefix, i++);
        display_policy_element(new_prefix, elt, brief);
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }

    lcp_signature_t *sig = get_tpm12_signature(pollist);
    if ( sig != NULL ) {
        DISPLAY("%s signature:\n", prefix);
        display_tpm12_signature(new_prefix, sig, brief);
    }
}

lcp_policy_list_t *create_empty_tpm12_policy_list(void)
{
    lcp_policy_list_t *pollist = malloc(offsetof(lcp_policy_list_t,
                policy_elements));
    if ( pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        return NULL;
    }
    pollist->version = LCP_TPM12_POLICY_LIST_VERSION;
    pollist->reserved = 0;
    pollist->sig_alg = LCP_POLSALG_NONE;
    pollist->policy_elements_size = 0;

    return pollist;
}

lcp_policy_list_t *add_tpm12_policy_element(lcp_policy_list_t *pollist,
        const lcp_policy_element_t *elt)
{
    if ( pollist == NULL || elt == NULL )
        return NULL;

    /* adding a policy element requires growing the policy list */
    size_t old_size = get_tpm12_policy_list_size(pollist);
    lcp_policy_list_t *new_pollist = realloc(pollist, old_size + elt->size);
    if ( new_pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(pollist);
        return NULL;
    }

    /* realloc() copies over previous contents */
    /* we add at the beginning of the elements list (don't want to overwrite
       a signature) */

    memmove_s((void *) &new_pollist->policy_elements + elt->size,
              old_size - offsetof(lcp_policy_list_t, policy_elements),
              &new_pollist->policy_elements,
              old_size - offsetof(lcp_policy_list_t, policy_elements));
    memcpy_s(&new_pollist->policy_elements, elt->size, elt, elt->size);
    new_pollist->policy_elements_size += elt->size;

    return new_pollist;
}

bool del_tpm12_policy_element(lcp_policy_list_t *pollist, uint32_t type)
{
    if ( pollist == NULL )
        return false;

    /* find first element of specified type (there should only be one) */
    size_t elts_size = pollist->policy_elements_size;
    lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        if ( elt->type == type ) {
            /* move everything up */
            size_t tot_size = get_tpm12_policy_list_size(pollist);
            size_t elt_size = elt->size;
            memmove_s(elt, pollist->policy_elements_size, (void *)elt + elt_size,
                    tot_size - ((void *)elt + elt_size - (void *)pollist));
            pollist->policy_elements_size -= elt_size;

            return true;
        }
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }
    return false;
}

bool verify_tpm12_pollist_sig(const lcp_policy_list_t *pollist)
{
    LOG("[verify_tpm12_pollist_sig]\n");
    sized_buffer *list_data = NULL;
    sized_buffer *public_key = NULL;
    sized_buffer *signature = NULL;
    bool result;

    if (pollist == NULL) {
        ERROR("Error: policy list is not defined.\n");
        return false;
    }
    if (pollist->sig_alg != LCP_POLSALG_RSA_PKCS_15) {
        ERROR("Error: signature alg not supported.\n");
        return false;
    }

    lcp_signature_t *sig = get_tpm12_signature(pollist);
    if ( sig == NULL ) {
        ERROR("Error: failed to allocate signature.\n");
        return false;
    }
    if (sig->pubkey_size!=256&&sig->pubkey_size!=384) {
        ERROR("Error: pubkey size not supported.\n");
        return false;
    }

    list_data = allocate_sized_buffer(get_tpm12_policy_list_size(pollist));
    if (list_data == NULL) {
        ERROR("Error: failed to allocate buffer for list_data.\n");
        return false;
    }

    public_key = allocate_sized_buffer(sig->pubkey_size);
    if (public_key == NULL) {
        ERROR("Error: failed to allocate buffer for public_key.\n");
        free(list_data);
        return false;
    }

    signature = allocate_sized_buffer(sig->pubkey_size);
    if (signature == NULL) {
        ERROR("Error: failed to allocate buffer for signature.\n");
        free(list_data);
        free(public_key);
        return false;
    }

    list_data->size = get_tpm12_policy_list_size(pollist) - sig->pubkey_size;
    public_key->size = sig->pubkey_size;
    signature->size = sig->pubkey_size;

    memcpy_s((void *) list_data->data, list_data->size,
                                       (const void *) pollist, list_data->size);
    memcpy_s((void *) public_key->data, public_key->size,
                            (const void *) sig->pubkey_value, sig->pubkey_size);
    memcpy_s((void *) signature->data, signature->size,
                 (const void *) get_tpm12_sig_block(pollist), sig->pubkey_size);

    //Key and sig must be BE for openssl, and are LE in list, so reverse:
    buffer_reverse_byte_order((uint8_t *) public_key->data, public_key->size);
    buffer_reverse_byte_order((uint8_t *) signature->data, signature->size);

    result = verify_rsa_signature(list_data, public_key, signature, TPM_ALG_NULL,
                                            pollist->sig_alg, pollist->version);

    free(signature);
    free(list_data);
    free(public_key);
    if (result) {
        LOG("List signature verified successfully.\n");
    }
    else {
        LOG("Signature did not verify.\n");
    }
    return result;
}

void display_tpm12_signature(const char *prefix, const lcp_signature_t *sig,
        bool brief)
{
    char new_prefix[strnlen_s(prefix, 20)+8];
    strcpy_s(new_prefix, sizeof(new_prefix), prefix);
    strcat_s(new_prefix, sizeof(new_prefix), "\t");

    DISPLAY("%s revocation_counter: 0x%x (%u)\n", prefix,
            sig->revocation_counter, sig->revocation_counter);
    DISPLAY("%s pubkey_size: 0x%x (%u)\n", prefix, sig->pubkey_size,
            sig->pubkey_size);

    if ( brief )
        return;

    DISPLAY("%s pubkey_value:\n", prefix);
    print_hex(new_prefix, sig->pubkey_value, sig->pubkey_size);
    DISPLAY("%s sig_block:\n", prefix);
    print_hex(new_prefix, (void *)&sig->pubkey_value + sig->pubkey_size,
            sig->pubkey_size);
}

lcp_policy_list_t *add_tpm12_signature(lcp_policy_list_t *pollist,
        const lcp_signature_t *sig)
{
    LOG("add_tpm12_signature\n");
    if ( pollist == NULL || sig == NULL )
        return NULL;

    /* adding a signature requires growing the policy list */
    size_t old_size = get_tpm12_policy_list_size(pollist);
    size_t sig_size = sizeof(*sig) + 2*sig->pubkey_size;
    lcp_policy_list_t *new_pollist = realloc(pollist, old_size + sig_size);
    if ( new_pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(pollist);
        return NULL;
    }

    /* realloc() copies over previous contents */

    size_t sig_begin = old_size;
    /* if a signature already exists, replace it */
    lcp_signature_t *curr_sig = get_tpm12_signature(new_pollist);
    if ( curr_sig != NULL )
        sig_begin = (void *)curr_sig - (void *)new_pollist;
    memcpy_s((void *)new_pollist + sig_begin, sig_size, sig, sig_size);

    return new_pollist;
}

unsigned char *get_tpm12_sig_block(const lcp_policy_list_t *pollist)
{
    lcp_signature_t *sig = get_tpm12_signature(pollist);
    if ( sig == NULL )
        return NULL;
    return (unsigned char *)&sig->pubkey_value + sig->pubkey_size;
}

void calc_tpm12_policy_list_hash(const lcp_policy_list_t *pollist, lcp_hash_t2 *hash,
        uint16_t hash_alg)
{
    uint8_t *buf_start = (uint8_t *)pollist;
    size_t len = get_tpm12_policy_list_size(pollist);

    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 ) {
        lcp_signature_t *sig = get_tpm12_signature(pollist);
        if ( sig == NULL )
            return;
        buf_start = sig->pubkey_value;
        len = sig->pubkey_size;
    }

    hash_buffer(buf_start, len, (tb_hash_t *)hash, hash_alg);
}

bool write_tpm12_policy_list_file(const char *file, const lcp_policy_list_t *pollist)
{
    size_t len = get_tpm12_policy_list_size(pollist);

    /* check if sig_block all 0's--if so then means there was no sig_block
       when file was read but empty one was added, so don't write it */
    lcp_signature_t *sig = get_tpm12_signature(pollist);
    if ( sig != NULL ) {
        uint8_t *sig_block = (uint8_t *)&sig->pubkey_value + sig->pubkey_size;
        while ( sig_block < ((uint8_t *)pollist + len) ) {
            if ( *sig_block++ != 0 )
                break;
        }
        /* all 0's */
        if ( sig_block == ((uint8_t *)pollist + len) ) {
            LOG("output file has no sig_block\n");
            len -= sig->pubkey_size;
        }
    }

    return write_file(file, pollist, len);
}

bool rsa_sign_list1_data(lcp_policy_list_t *pollist, const char *privkey_file)
{
    lcp_signature_t *sig = NULL;
    size_t list_data_len;
    sized_buffer *signature_block = NULL;
    sized_buffer *digest = NULL;
    EVP_PKEY_CTX *private_key_context = NULL;

    bool status;

    LOG("rsa_sign_list1_data\n");
    if (pollist == NULL || privkey_file == NULL) {
        ERROR("Pollist or privkey undefined.\n");
        return false;
    }
    sig = get_tpm12_signature(pollist);
    if (sig == NULL) {
        ERROR("Error: failed to get signature.\n");
        return false;
    }

    list_data_len = get_tpm12_policy_list_size(pollist) - sig->pubkey_size;
    digest = allocate_sized_buffer(SHA1_DIGEST_SIZE);
    if (digest == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        goto ERROR;
    }
    signature_block = allocate_sized_buffer(sig->pubkey_size);
    if (signature_block == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        goto ERROR;
    }
    digest->size = SHA1_DIGEST_SIZE;
    signature_block->size = sig->pubkey_size;
    if (verbose) {
        DISPLAY("Data to hash:\n");
        print_hex("       ", (const unsigned char *) pollist, list_data_len);
    }
    status = hash_buffer((const unsigned char *) pollist, list_data_len,
                                      (tb_hash_t *) digest->data, TPM_ALG_SHA1);
    if ( !status ) {
        ERROR("Error: failed to hash list\n");
        goto ERROR;
    }
    if ( verbose ) {
        LOG("digest:\n");
        print_hex("", (const void *) digest->data, SHA1_DIGEST_SIZE);
    }

    private_key_context = rsa_get_sig_ctx(privkey_file, sig->pubkey_size);
    if (private_key_context == NULL) {
        ERROR("Error: failed to initialize EVP context.\n");
        goto ERROR;
    }
    //Now do the signing
    status = rsa_ssa_pss_sign(signature_block, digest, pollist->sig_alg, TPM_ALG_SHA1,
                                                           private_key_context);
    if (!status) {
        ERROR("Error: failed to sign list data.\n");
        goto ERROR;
    }
    buffer_reverse_byte_order((uint8_t *) signature_block->data, signature_block->size);
    memcpy_s((void *) sig->pubkey_value + sig->pubkey_size, sig->pubkey_size,
                    (const void *) signature_block->data, signature_block->size);
    if ( verbose ) {
        LOG("Signature: \n");
        display_tpm12_signature("    ", sig, false);
    }
    //Free allocated memory
    if (signature_block != NULL) {
        free(signature_block);
    }
    if (digest != NULL) {
        free(digest);
    }
    OPENSSL_free((void *) private_key_context);
    return true;
    ERROR:
        if (signature_block != NULL) {
            free(signature_block);
        }
        if (digest != NULL) {
            free(digest);
        }
        OPENSSL_free((void *) private_key_context);
        return false;
}

bool sign_lcp_policy_list_t(sign_user_input user_input)
{
    bool no_sigblock_ok = false;
    bool result;
    lcp_policy_list_t *pollist = NULL;
    lcp_signature_t2 *sig = NULL;

    pollist = (lcp_policy_list_t *) read_policy_list_file(user_input.list_file,
                                                        false, &no_sigblock_ok);
    if (pollist == NULL) {
        ERROR("Error: failed to read policy list file.\n");
        return false;
    }
    pollist->sig_alg = LCP_POLSALG_RSA_PKCS_15;
    sig = read_rsa_pubkey_file(user_input.pubkey_file);
    if (sig == NULL) {
        ERROR("Error: failed to read public key.\n");
        free(pollist);
        return NULL;
    }
    if ( (sig->rsa_signature.pubkey_size != 128 /* 1024 bits */)
        && (sig->rsa_signature.pubkey_size != 256 /* 2048 bits */)
        && (sig->rsa_signature.pubkey_size != 384 /* 3072 bits */) ) {
        ERROR("Error: public key size is not 1024/2048/3072 bits\n");
        free(sig);
        free(pollist);
        return NULL;
    }

    sig->rsa_signature.revocation_counter = user_input.rev_ctr;
    pollist = add_tpm12_signature(pollist, (const lcp_signature_t *) &sig->rsa_signature);
    if (pollist == NULL) {
        free(sig);
        free(pollist);
        return NULL;
    }
    result = rsa_sign_list1_data(pollist, user_input.privkey_file);
    if (!result) {
        free(sig);
        free(pollist);
        return NULL;
    }
    
    result = write_tpm12_policy_list_file(user_input.list_file, pollist);
    free(pollist);
    free(sig);
    return result ? 1 : 0;
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
