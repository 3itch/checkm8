/*
 * pollist2_1.c:
 *
 * Copyright (c) 2020, Intel Corporation
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
#define PRINT printf
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    #include <openssl/decoder.h>
    #include <openssl/core.h>
#endif
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "../include/lcp3_hlp.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist2_1.h"
#include "polelt.h"

//Function prototypes:

static size_t get_tpm20_key_and_signature_2_1_real_size(const lcp_signature_2_1 *sig);
static size_t get_tpm20_list_2_1_signature_size(const lcp_signature_2_1 *sig);
static bool get_rsa_signature_2_1_data(lcp_signature_2_1 *sig, void *data);
static bool get_ecc_signature_2_1_data(lcp_signature_2_1 *sig, void *data);
static bool verify_tpm20_pollist_2_1_rsa_sig(lcp_policy_list_t2_1 *pollist);
static bool verify_tpm20_pollist_2_1_ec_sig(const lcp_policy_list_t2_1 *pollist);
static void display_tpm20_signature_2_1(const char *prefix, const lcp_signature_2_1 *sig,
                                                        const uint16_t sig_alg);
static lcp_policy_list_t2_1 *add_tpm20_signature_2_1(lcp_policy_list_t2_1 *pollist,
                                lcp_signature_2_1 *sig, const uint16_t sig_alg);
static lcp_signature_2_1 *read_rsa_pubkey_file_2_1(const char *pubkey_file);
static lcp_signature_2_1 *read_ecdsa_pubkey_file_2_1(const char *pubkey_file);
static bool ec_sign_list_2_1_data(lcp_policy_list_t2_1 *pollist, const char *privkey_file);
static bool rsa_sign_list_2_1_data(lcp_policy_list_t2_1 *pollist, const char *privkey_file);
static lcp_policy_list_t2_1 *policy_list2_1_rsa_sign(lcp_policy_list_t2_1 *pollist,
uint16_t rev_ctr, uint16_t hash_alg, uint16_t sig_alg, const char *pubkey_file,
                                                      const char *privkey_file);
static lcp_policy_list_t2_1 *policy_list2_1_ec_sign(lcp_policy_list_t2_1 *pollist,
uint16_t rev_ctr, uint16_t sig_alg, const char *pubkey_file, const char *privkey_file);

  /////////////////////////////////////////////
 /* FUNCTIONS TO WORK WITH POLICY LISTS 2.1 */
/////////////////////////////////////////////
lcp_policy_list_t2_1 *get_policy_list_2_1_data(const void *raw_data, size_t base_size,
                                                  uint16_t key_signature_offset)
{
    /*
    This function: takes in raw policy list data and aligns it to lcp_policy_list_t2_1
    structures.

    In: Pointer to contiguous policy list data buffer, base size of the list i.e.
    offset of PolicyElements and size of policy elements, key signature offset.

    Out: Pointer to aligned lcp_policy_list_t2_1 structure
    */
    size_t sig_offset_in_data;
    lcp_policy_list_t2_1 *new_pollist = NULL; //Will return this
    sig_key_2_1_header *header;
    lcp_signature_2_1 *sig = NULL;
    int status;

    LOG("[get_policy_list_2_1_data]\n");

    if (raw_data == NULL) {
        ERROR("Error: list data not defined.\n");
        return NULL;
    }

    if (key_signature_offset == 0) {
        //No signature
        new_pollist = malloc(base_size);
        if (new_pollist == NULL) {
            ERROR("Error: failed to allocate policy list structure.\n");
            return NULL;
        }
        //If no signature, just copy data to new_pollist
        status = memcpy_s(new_pollist, base_size, raw_data, base_size);
        if (status == EOK)
            return new_pollist;
        else {
            free(new_pollist);
            return NULL;
        }
    }

    new_pollist = malloc(key_signature_offset);
    sig = create_empty_rsa_signature_2_1();
    if (sig == NULL || new_pollist == NULL ) {
        ERROR("ERROR: unable to create signature.\n");
        return NULL;
    }
    //Remember that Revocation Counter size is added to to key signature offset
    sig_offset_in_data = key_signature_offset - offsetof(lcp_signature_2_1, KeyAndSignature);
    status = memcpy_s(new_pollist, key_signature_offset, raw_data, key_signature_offset);
    if (status != EOK) {
        ERROR("Error: failed to copy list data.\n");
        return NULL;
    }

    header = (sig_key_2_1_header *) (raw_data+sig_offset_in_data);
    switch (header->key_alg)
    {
    case TPM_ALG_RSA:
        if (!get_rsa_signature_2_1_data(sig, (void *) raw_data+sig_offset_in_data)) {
            ERROR("ERROR: failed to get signature data.\n");
            free(sig);
            free(new_pollist);
            return NULL;
        }
        new_pollist->KeySignatureOffset = 0x0; // Reset keysignatureoffset
        new_pollist = add_tpm20_signature_2_1(new_pollist, sig, TPM_ALG_RSAPSS);
        if (new_pollist == NULL ) {
            ERROR("ERROR: Cannot add TPM_signature_2_1");
            free(sig);
            return NULL;
        }
        break;
    case TPM_ALG_ECC:
        if (!get_ecc_signature_2_1_data(sig, (void *) raw_data+sig_offset_in_data)) {
            ERROR("ERROR: failed to get signature data.\n");
            free(sig);
            return NULL;
        }
        new_pollist->KeySignatureOffset = 0x0; // Reset keysignatureoffset
        new_pollist = add_tpm20_signature_2_1(new_pollist, sig, TPM_ALG_ECDSA);
        if (new_pollist == NULL ) {
            ERROR("ERROR: Cannot add TPM_signature_2_1");
            free(sig);
            return NULL;
        }
        break;
    default:
        ERROR("Error: unknown key algorithm.\n");
        free(sig);
        free(new_pollist);
        return NULL;
    }
    free(sig);
    return new_pollist;
}

lcp_policy_list_t2_1 *read_policy_list_2_1_file(bool sign_it, const char *list_file)
{
    /*
    This function: reads policy list data from a file.

    In: sign_it to indicate whether we want the list to be later signed or not,
    path to list file (string)

    Out: Pointer to aligned lcp_policy_list_t2_1 structure
    */
    LOG("read_policy_list_file: version 0x0300\n");
    size_t file_length; //This is NOT always list size
    size_t elts_size;
    lcp_policy_list_t2_1 *pollist = NULL; //Helper - will be discarded
    lcp_policy_list_t2_1 *new_pollist = NULL; //Will be returned
    bool result;
    bool has_sig;

    size_t base_size = offsetof(lcp_policy_list_t2_1, PolicyElements);
    pollist = read_file(list_file, &file_length, false);

    if (pollist==NULL) {
        ERROR("ERROR: failed to read policy list file.\n");
        return NULL;
    }

    result = verify_tpm20_policy_list_2_1(pollist, file_length, &has_sig);
    if (!result) {
        free(pollist);
        return NULL;
    }

    elts_size = pollist->PolicyElementsSize;

    if ( has_sig && !sign_it ) {
        //List has sig, but we don't want to sign it again.
        new_pollist = get_policy_list_2_1_data((const void *) pollist, base_size+
                                        elts_size, pollist->KeySignatureOffset);
        if ( new_pollist == NULL ) {
            ERROR("ERROR: failed to read policy list structure.\n");
            free(pollist);
            return NULL;
        }
        free(pollist);
        return new_pollist;
    }
    //List has signature and we want to sign it, disregard the signature it has
    //and return it without it.
    else {
        //Pass 0 as last arg to get_data func, this way we don't get sig.
        new_pollist = get_policy_list_2_1_data((const void *) pollist, base_size+
                                                                  elts_size, 0);
        if ( new_pollist == NULL ) {
            ERROR("ERROR: failed to read policy list structure.\n");
            free(pollist);
            return NULL;
        }
        free(pollist);
        return new_pollist;
    }
}

lcp_signature_2_1 *create_empty_ecc_signature_2_1(void)
/*
This function: returns empty ecc sig structure. Empty == just 0s inside

In: None
Out: Pointer to an empty structure

*/
{
    //Size of structure + size of revocation counter
    size_t sig_size = sizeof(ecc_key_and_signature) + offsetof(lcp_signature_2_1,
                                                                KeyAndSignature);
    lcp_signature_2_1 *sig = malloc(sig_size);
    if (sig == NULL) {
        return NULL;
    }
    if (memset_s(sig, sig_size, 0x00) == EOK) {
        return sig;
    }
    else {
        return NULL;
    }
}

lcp_signature_2_1 *create_empty_rsa_signature_2_1(void)
/*
This function: returns empty rsa signature structure. Empty == just 0s inside

In: None
Out: Pointer to empty structure

*/
{
    //Size of structure + size of revocation counter
    size_t sig_size = sizeof(rsa_key_and_signature) + offsetof(lcp_signature_2_1,
                                                                KeyAndSignature);
    lcp_signature_2_1 *sig = malloc(sig_size);
    if ( sig == NULL ) {
        return NULL;
    }
    if (memset_s(sig, sig_size, 0x00) == EOK) {
        return sig;
    }
    else {
        return NULL;
    }
}

size_t get_tpm20_list_2_1_signature_size(const lcp_signature_2_1 *sig)
/*
This function: calculates size of lcp_signature_2_1 structure

In: pointer to signature structure whose size we want to calculate
Out: Size
*/
{
    if ( sig == NULL ){
        return 0;
    }
    //We need to know what type of key was used to sign it
    uint16_t key_alg = get_signature_2_1_key_alg(sig);
    switch ( key_alg )
    {
    case TPM_ALG_RSA:
        return sizeof(sig->RevocationCounter) + sizeof(rsa_key_and_signature);
    case TPM_ALG_ECC:
        return sizeof(sig->RevocationCounter) + sizeof(ecc_key_and_signature);
    default:
        break;
    }
    return 0;
}

size_t get_tpm20_policy_list_2_1_size(const lcp_policy_list_t2_1 *pollist)
/*
This function: calculates size of lcp_policy_list_t2_1 structure

In: pointer to the list structure whose size we want to calculate
Out: lcp policy list size
*/
{
    size_t size = 0;

    if (pollist == NULL) {
        return 0;
    }

    size = offsetof(lcp_policy_list_t2_1, PolicyElements)+pollist->PolicyElementsSize;

    /* add signature size if it's present */
    if ( pollist->KeySignatureOffset ) {
        size += get_tpm20_list_2_1_signature_size(get_tpm20_signature_2_1(pollist));
    }

    return size;
}

bool verify_tpm20_policy_list_2_1(const lcp_policy_list_t2_1 *pollist, size_t size,
                                                                  bool *has_sig)
/*
This function: checks if policy list is correct. Verifies the list up to but
not including the signature

In: pointer to policy list structure, policy list file size, pointer to bool var
that gets info whether list is signed.
Out: True on success, false on error

*/
{
    size_t base_size;
    uint32_t elts_size;
    const lcp_policy_element_t *elt = NULL;

    LOG("[verify_tpm20_policy_list_2_1]\n");

    if ( pollist == NULL ) {
        ERROR("Error: list is not defined.\n");
        return false;
    }
    //Size read from file must not be smaller than the size of structure pointed to
    if ( size < sizeof(*pollist) ) {
        ERROR("Error: data is too small (%u)\n", size);
        return false;
    }
    if (verbose) {
        DISPLAY("Raw policy list data:\n");
        print_hex("        ", (const void *) pollist, size);
    }
    //Major ver must be 3, minor ver must be 0
    if ( MAJOR_VER(pollist->Version) != \
         MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) || \
         MINOR_VER(pollist->Version) > MINOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) ) {
        ERROR("Error: unsupported version 0x%04x\n", pollist->Version);
        return false;
    }
    base_size = offsetof(lcp_policy_list_t2_1, PolicyElements);
    //KeySignatureOffset 0 means no signature in list file
    elts_size = 0;
    elt = pollist->PolicyElements;
    while ( elts_size < pollist->PolicyElementsSize) {
        if (elts_size + elt->size > pollist->PolicyElementsSize) {
            ERROR("Error: size is incorrect (elements size): 0x%x > 0x%x\n",
                elts_size+elt->size, pollist->PolicyElementsSize);
            return false;
        }
        elts_size += elt->size;
        elt = (void *) elt + elt->size; //go to the next one
    }
    if ( elts_size != pollist->PolicyElementsSize ) {
        ERROR("Error: size incorrect (elt size): 0x%x != 0x%x\n",
                elts_size, pollist->PolicyElementsSize);
        return false;
    }

    if ( pollist->KeySignatureOffset == 0) {
        //List isn't signed so base size and elements size must be the same number
        //of bytes as the file
        LOG("LCP list has no signature - skipping signature verification.\n");
        if (base_size + pollist->PolicyElementsSize != size) {
            ERROR("Error: incorrect KeySignatureOffset == 0 (no sig): 0x%x != 0x%x\n",
                    base_size + pollist->PolicyElementsSize, size);
            return false;
        }
        else {
            DISPLAY("Verify TPM2.0 Policy List 2.1 success\n");
            if (has_sig != NULL)
                *has_sig = false;
            return true; //list unsigned, function enc
        }
    }
    else {
        if (has_sig != NULL)
            *has_sig = true;
        return true; //list signed, func end
    }
    return false;
}

void display_tpm20_policy_list_2_1(const char *prefix,
                                const lcp_policy_list_t2_1 *pollist, bool brief)
/*
This function: Displays contents of a policy list in a readable form

In: Prefix, pointer to a policy list, brief: if true only short info is shown
Out: Nothing

*/
{
    sig_key_2_1_header *sig_header;
    size_t elts_size;
    const lcp_policy_element_t *elt = NULL;
    lcp_signature_2_1 *sig = NULL;
    size_t new_prefix_size;
    if (prefix == NULL)
        prefix = "";
    new_prefix_size = strnlen_s(prefix, 20) + 8;
    char new_prefix[new_prefix_size];

    if ( pollist == NULL ) {
        ERROR("Error: policy list is not defined.\n");
        return;
    }

    DISPLAY("LCP_POLICY_LIST_2_1 structure:\n");
    DISPLAY("%s Version: 0x%x\n", prefix, pollist->Version);
    DISPLAY("%s KeySignatureOffset: 0x%x\n", prefix, pollist->KeySignatureOffset);
    DISPLAY("%s PolicyElementsSize: 0x%x\n", prefix, pollist->PolicyElementsSize);
    strcpy_s(new_prefix, sizeof(new_prefix), prefix);
    strcat_s(new_prefix, sizeof(new_prefix), "    ");
    elts_size = pollist->PolicyElementsSize;
    elt = pollist->PolicyElements;
    uint16_t i = 0;
    while ( elts_size > 0 ) {
        DISPLAY("%s policy_element[%u]:\n", prefix, i++);
        display_policy_element(new_prefix, elt, brief);
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }

    if ( pollist->KeySignatureOffset == 0 ) {
        return;
    }

    sig = get_tpm20_signature_2_1(pollist);
    if (sig == NULL) {
        return;
    }

    sig_header = (sig_key_2_1_header*) sig;

    if ( sig_header->key_alg == TPM_ALG_RSA) {
        display_tpm20_signature_2_1("        ", sig, TPM_ALG_RSASSA);
        return;
    }
    if (sig_header->key_alg == TPM_ALG_ECC) {
        display_tpm20_signature_2_1("        ", sig, TPM_ALG_ECDSA);
        return;
    }
    return;
}

lcp_policy_list_t2_1 *create_empty_tpm20_policy_list_2_1(void)
/*
This function: Creates lcp list 2.1 base and returns it

In: No args
Out: Returns a pointer to an empty policy list version 2.1

*/
{
    LOG("[create_empty_tpm20_policy_list_2_1]\n");
    lcp_policy_list_t2_1 *pollist = malloc(offsetof(lcp_policy_list_t2_1,
                                                    PolicyElements));
    if (pollist == NULL) {
        ERROR("Error: failed to allocate memory\n");
        return NULL;
    }
    pollist->Version = LCP_TPM20_POLICY_LIST2_1_VERSION_300;
    pollist->KeySignatureOffset = 0;
    pollist->PolicyElementsSize = 0;

    LOG("Create empty policy list 2.1 success\n");
    return pollist;
}

lcp_policy_list_t2_1 *add_tpm20_policy_element_2_1(lcp_policy_list_t2_1 *pollist,
                                                const lcp_policy_element_t *elt)
/*
This function: adds element elt to a list 2.1 - pollist

In: pointer to an lcp list 2.1 and element
Out: Pointer to a copy of the original list with the element appended.

*/
{
    LOG("[add_tpm20_policy_element_2_1]\n");
    if ( pollist == NULL || elt == NULL )
        return NULL;
    size_t old_size = get_tpm20_policy_list_2_1_size(pollist);
    lcp_policy_list_t2_1 *new_pollist = realloc(pollist, old_size + elt->size);
    if ( new_pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(pollist);
        return NULL;
    }

    memmove_s(
        (void *) &new_pollist->PolicyElements + elt->size, // dest
        old_size - offsetof(lcp_policy_list_t2_1, PolicyElements), // dmax
        &new_pollist->PolicyElements, // src
        old_size - offsetof(lcp_policy_list_t2_1, PolicyElements) // smax
        );

    memcpy_s (&new_pollist->PolicyElements,elt->size, elt, elt->size);

    new_pollist->PolicyElementsSize += elt->size;
    LOG("Add tpm20 policy element successful\n");
    return new_pollist;
}

bool get_ecc_signature_2_1_data(lcp_signature_2_1 *empty_sig, void *raw_data)
{
    size_t sigscheme_offset;
    size_t signature_struct_offset;
    size_t key_size_bytes;
    uint16_t sig_scheme;
    size_t key_and_sig_offset = offsetof(lcp_signature_2_1, KeyAndSignature);
    size_t key_struct_offset = key_and_sig_offset + offsetof(ecc_key_and_signature, Key);
    size_t qx_qy_offset = key_struct_offset + offsetof(ecc_public_key, QxQy);

    if (empty_sig == NULL || raw_data == NULL) {
        ERROR("Error: signature or signature data not allocated.\n");
        return false;
    }
    sig_key_2_1_header *sig_header = (sig_key_2_1_header *) raw_data;
    
    key_size_bytes = sig_header->key_size / 8;

    sigscheme_offset = qx_qy_offset+(2*key_size_bytes);
    signature_struct_offset = sigscheme_offset +
                sizeof(empty_sig->KeyAndSignature.RsaKeyAndSignature.SigScheme);

    if ( key_size_bytes != 32 && key_size_bytes != 48 ) {
        ERROR("ERROR: Key size not supported.\n");
        return false;
    }
    empty_sig->RevocationCounter = sig_header->revoc_counter;
    empty_sig->KeyAndSignature.EccKeyAndSignature.Version = sig_header->version;
    empty_sig->KeyAndSignature.EccKeyAndSignature.KeyAlg = sig_header->key_alg;
    empty_sig->KeyAndSignature.EccKeyAndSignature.Key.Version = sig_header->key_ver;
    empty_sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize = sig_header->key_size;

    memcpy_s(empty_sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy,
                           2*MAX_ECC_KEY_SIZE, raw_data+qx_qy_offset, 2*key_size_bytes);

    memcpy_s((void*)&sig_scheme, sizeof(sig_scheme),
                                 raw_data+sigscheme_offset, sizeof(sig_scheme));
    empty_sig->KeyAndSignature.EccKeyAndSignature.SigScheme = sig_scheme;

    memcpy_s(
        (void *)&empty_sig->KeyAndSignature.EccKeyAndSignature.Signature,
        sizeof(ecc_signature),raw_data+signature_struct_offset,sizeof(ecc_signature)
    );

    return true;
}

bool get_rsa_signature_2_1_data(lcp_signature_2_1 *empty_sig, void *raw_data)
{
    size_t sigscheme_offset;
    size_t signature_struct_offset;
    size_t key_size_bytes;
    uint32_t exponent;
    uint16_t sig_scheme;
    size_t key_and_sig_offset = offsetof(lcp_signature_2_1, KeyAndSignature);
    size_t key_struct_offset = key_and_sig_offset + offsetof(rsa_key_and_signature, Key);
    size_t exponent_offset = key_struct_offset + offsetof(rsa_public_key, Exponent);
    size_t mod_offset = key_struct_offset + offsetof(rsa_public_key, Modulus);

    if (empty_sig == NULL || raw_data == NULL) {
        ERROR("Error: signature or signature data not allocated.\n");
        return false;
    }
    sig_key_2_1_header *sig_header = (sig_key_2_1_header *) raw_data;

    key_size_bytes = sig_header->key_size / 8;

    sigscheme_offset = mod_offset+key_size_bytes;
    signature_struct_offset = sigscheme_offset +
                sizeof(empty_sig->KeyAndSignature.RsaKeyAndSignature.SigScheme);

    if ( key_size_bytes != 256 && key_size_bytes != 384 ) {
        ERROR("ERROR: Key size not supported.\n");
        return false;
    }
    empty_sig->RevocationCounter = sig_header->revoc_counter;
    empty_sig->KeyAndSignature.RsaKeyAndSignature.Version = sig_header->version;
    empty_sig->KeyAndSignature.RsaKeyAndSignature.KeyAlg = sig_header->key_alg;
    empty_sig->KeyAndSignature.RsaKeyAndSignature.Key.Version = sig_header->key_ver;
    empty_sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize = sig_header->key_size;

    memcpy_s((void *)&exponent, sizeof(exponent), raw_data+exponent_offset,
                                                              sizeof(exponent));
    empty_sig->KeyAndSignature.RsaKeyAndSignature.Key.Exponent = exponent;

    memcpy_s(empty_sig->KeyAndSignature.RsaKeyAndSignature.Key.Modulus,
                           MAX_RSA_KEY_SIZE, raw_data+mod_offset, key_size_bytes);

    memcpy_s((void*)&sig_scheme, sizeof(sig_scheme),
                                 raw_data+sigscheme_offset, sizeof(sig_scheme));
    empty_sig->KeyAndSignature.RsaKeyAndSignature.SigScheme = sig_scheme;

    memcpy_s(
        (void *)&empty_sig->KeyAndSignature.RsaKeyAndSignature.Signature,
        sizeof(rsa_signature),raw_data+signature_struct_offset,sizeof(rsa_signature)
    );

    return true;
}
bool verify_tpm20_pollist_2_1_sig(lcp_policy_list_t2_1 *pollist)
{
    bool result;
    sig_key_2_1_header *header;
    size_t base_size = offsetof(lcp_policy_list_t2_1, PolicyElements);
    size_t elts_size;
    lcp_signature_2_1 *sig;

    LOG("[verify_tpm20_pollist_2_1_sig]\n");
    if (pollist == NULL) {
        ERROR("Error: failed to get policy list structure.\n");
        return false;
    }

    elts_size = pollist->PolicyElementsSize;

    sig = get_tpm20_signature_2_1(pollist);
    if (sig == NULL) {
        ERROR("Error: failed to get list signature.\n");
        return false;
    }
    header = (sig_key_2_1_header *) sig;
    uint16_t expected_sig_offset = base_size + elts_size +
                                offsetof(lcp_signature_2_1, KeyAndSignature);

    if (expected_sig_offset != pollist->KeySignatureOffset) {
        ERROR("Error: KeySignatureOffset incorrect. Expected: 0x%x, found: 0x%x\n",
        expected_sig_offset, pollist->KeySignatureOffset);
        return false;
    }
    if ( header->key_alg == TPM_ALG_RSA ) {
        LOG("Verifying signature against list data.\n");
        result = verify_tpm20_pollist_2_1_rsa_sig(pollist);
    }
    else if ( header->key_alg == TPM_ALG_ECC ) {
        //This works with SM2 too.
        result = verify_tpm20_pollist_2_1_ec_sig(pollist);
    }
    else {
        //Function end
        ERROR("Error: signature verification failed - unknown key algorithm\n");
        result = false;
    }
    return result;
}

bool verify_tpm20_pollist_2_1_ec_sig(const lcp_policy_list_t2_1 *pollist) 
{
    /*
        This functions prepares lcp policy list for verification, i.e.
        generates buffers for list data, public key components, signature
        components and passes all of it to ec_verify in lcputils

        In: pointer to properly allocated lcp_policy_list_t2_1 structure
            containing list and signature.

        Out: True on success, false on failure
    */
    sized_buffer *pollist_data = NULL;
    sized_buffer *pubkey_x = NULL;
    sized_buffer *pubkey_y = NULL;
    sized_buffer *sig_r = NULL;
    sized_buffer *sig_s = NULL;
    lcp_signature_2_1 *sig = NULL;
    size_t keysize, data_size; //Keysize is in bytes
    bool result;
    uint16_t sigalg;
    uint16_t hashalg;
    LOG("[verify_tpm20_pollist_2_1_ec_sig]\n");
    if (pollist == NULL) {
        ERROR("Error: policy list not defined.\n");
        return false;
    }
    //Set size of signed data:
    data_size = pollist->KeySignatureOffset;
    //Get sig;
    sig = get_tpm20_signature_2_1(pollist);
    if (sig == NULL) {
        ERROR("Error: failed to get signature 2.1.\n");
        return false;
    }

    //Read data from sig structure:
    keysize = sig->KeyAndSignature.EccKeyAndSignature.Signature.KeySize / 8;
    sigalg = sig->KeyAndSignature.EccKeyAndSignature.SigScheme;
    hashalg = sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg;

    //Verify signature components:
    if ( sig->KeyAndSignature.EccKeyAndSignature.Version != SIGNATURE_VERSION) {
        ERROR("ERROR: KeyAndSignature struct version not 0x%x.\n", SIGNATURE_VERSION);
        return false;
    }

    if ( sig->KeyAndSignature.EccKeyAndSignature.KeyAlg != TPM_ALG_ECC ) {
        ERROR("ERROR: KeyAlg not TPM_ALG_ECC 0x%x.\n", TPM_ALG_ECC);
        return false;
    }

    if ( sigalg != TPM_ALG_ECDSA && sigalg != TPM_ALG_SM2) {
        ERROR("ERROR: signature scheme 0x%x not supported.\nExpected 0x18 or 0x1B\n",
                             sig->KeyAndSignature.EccKeyAndSignature.SigScheme);
        return false;
    }

    if ( sig->KeyAndSignature.EccKeyAndSignature.Signature.Version != SIGNATURE_VERSION) {
        ERROR("ERROR: signature structure version not supported. Expected 0x%x, found: 0x%x\n",
        SIGNATURE_VERSION, sig->KeyAndSignature.RsaKeyAndSignature.Signature.Version);
        return false;
    }

    if ( hashalg != TPM_ALG_SHA256 && hashalg != TPM_ALG_SHA384 && 
         hashalg != TPM_ALG_SM3_256) {
        ERROR("ERROR: hash alg not supported. Expected 0x0B, 0x0C or 0x12, found: 0x%x\n",
                                                                  hashalg);
        return false;
    }
    if ( keysize != MIN_ECC_KEY_SIZE && keysize != MAX_ECC_KEY_SIZE) {
        ERROR("Error: incorrect keysize, must be 256 or 384 bits. Found: 0x%x.\n",
                                                                    keysize * 8);
        return false;
    }
    if ( keysize != sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize / 8 ) {
        ERROR("ERROR: keysize mismatch between key and signature. Expected:"
                          " 0x%x, found: 0x%x\n", keysize*8, keysize);
        return false;
    }
    //Allocate buffers:
    pollist_data = allocate_sized_buffer(data_size);
    pubkey_x = allocate_sized_buffer(keysize);
    pubkey_y = allocate_sized_buffer(keysize);
    sig_r = allocate_sized_buffer(keysize);
    sig_s = allocate_sized_buffer(keysize);

    if (pollist_data == NULL || pubkey_x == NULL || pubkey_y == NULL || 
        sig_r == NULL || sig_s == NULL) {
        ERROR("Error: failed to allocate data structure.\n");
        result = false;
        goto EXIT;
    }
    pollist_data->size = data_size;
    pubkey_x->size = keysize;
    pubkey_y->size = keysize;
    sig_r->size = keysize;
    sig_s->size = keysize;

    //Copy data to buffers
    memcpy_s(
        (void *) pollist_data->data, pollist_data->size,
        (const void *) pollist, data_size
        );
    memcpy_s( 
        (void *) pubkey_x->data, pubkey_x->size,
        (const void *) sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy,
        keysize
        );
    memcpy_s( 
        (void *) pubkey_y->data, pubkey_y->size,
        (const void *) sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy + keysize,
        keysize
        );
    memcpy_s( 
        (void *) sig_r->data, sig_r->size,
        (const void *) sig->KeyAndSignature.EccKeyAndSignature.Signature.sigRsigS,
        keysize
        );
    memcpy_s( 
        (void *) sig_s->data, sig_s->size,
        (const void *) sig->KeyAndSignature.EccKeyAndSignature.Signature.sigRsigS + keysize,
        keysize
        );
    //r, s, x, y are LE in lcp but openssl needs them BE, so we will flip them.
    buffer_reverse_byte_order((uint8_t *) pubkey_x->data, pubkey_x->size);
    buffer_reverse_byte_order((uint8_t *) pubkey_y->data, pubkey_y->size);
    buffer_reverse_byte_order((uint8_t *) sig_r->data, sig_r->size);
    buffer_reverse_byte_order((uint8_t *) sig_s->data, sig_s->size);

    //Now verify:
    result = verify_ec_signature(pollist_data, pubkey_x, pubkey_y, sig_r, sig_s, sigalg, hashalg);
    if (!result) {
        ERROR("Error: failed to verify SM2 signature.\n");
    }
    EXIT:
        if (pollist_data != NULL) {
            free(pollist_data);
        }
        if (pubkey_x != NULL) {
            free(pubkey_x);
        }
        if (pubkey_y != NULL) {
            free(pubkey_y);
        }
        if (sig_r != NULL) {
            free(sig_r);
        }
        if (sig_s != NULL) {
            free(sig_s);
        }
        return result;
}

bool verify_tpm20_pollist_2_1_rsa_sig(lcp_policy_list_t2_1 *pollist)
/*
This function: verifies rsa signature block in policy list

In: policy list data that was signed, data size, signature 2.1 structure
Out: true if verifies false if not

*/
{
    LOG("[verify_tpm20_pollist_2_1_rsa_sig]\n");
    bool result;
    size_t key_size_bytes;
    size_t sig_key_size;
    uint16_t sig_alg;
    uint16_t hash_alg_sig;
    lcp_signature_2_1 *sig = NULL;
    //Dynamic buffers:
    sized_buffer *list_data = NULL; //Free before return
    sized_buffer *key_buffer = NULL; //Free before return
    sized_buffer *signature_buffer = NULL; //Free before return

    if (pollist == NULL) {
        ERROR("Error: failed to get list data.\n");
        return false;
    }

    sig = get_tpm20_signature_2_1(pollist);
    if (sig == NULL) {
        ERROR("Error: failed to get signature.\n");
        return false;
    }

    key_size_bytes = sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8;
    if ( sig->KeyAndSignature.RsaKeyAndSignature.Version != SIGNATURE_VERSION) {
        ERROR("ERROR: KeyAndSignature struct version not 0x%x.", SIGNATURE_VERSION);
        return false;
    }

    if ( sig->KeyAndSignature.RsaKeyAndSignature.KeyAlg != TPM_ALG_RSA ) {
        ERROR("ERROR: KeyAlg not TPM_ALG_RSA 0x%x.", TPM_ALG_RSA);
        return false;
    }

    if (key_size_bytes != 256 && key_size_bytes != 384) {
        ERROR("ERROR: key size %d not supported.\n", key_size_bytes);
        return false;
    }

    if ( sig->KeyAndSignature.RsaKeyAndSignature.Key.Exponent != LCP_SIG_EXPONENT ) {
        ERROR("ERROR: RSA exponent not 0x%x.", LCP_SIG_EXPONENT);
        return false;
    }

    sig_alg = sig->KeyAndSignature.RsaKeyAndSignature.SigScheme;
    if ( sig_alg != TPM_ALG_RSASSA && sig_alg != TPM_ALG_RSAPSS ) {
        ERROR("ERROR: signature scheme 0x%x not supported.\nExpected 0x14 or 0x16",
                             sig_alg);
        return false;
    }

    if ( sig->KeyAndSignature.RsaKeyAndSignature.Signature.Version != SIGNATURE_VERSION) {
        ERROR("ERROR: signature structure version not supported. Expected 0x%x, found: 0x%x",
        SIGNATURE_VERSION, sig->KeyAndSignature.RsaKeyAndSignature.Signature.Version);
        return false;
    }

    hash_alg_sig = sig->KeyAndSignature.RsaKeyAndSignature.Signature.HashAlg;
    if ( hash_alg_sig != TPM_ALG_SHA256 && hash_alg_sig != TPM_ALG_SHA384 ) {
        ERROR("ERROR: hash alg not supported. Expected 0x0B or 0x0C, found: 0x%x\n",
                                                                  hash_alg_sig);
        return false;
    }
    sig_key_size = sig->KeyAndSignature.RsaKeyAndSignature.Signature.KeySize;
    if ( sig_key_size != sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize ) {
        ERROR("ERROR: keysize mismatch between key and signature. Expected:"
                          " 0x%x, found: 0x%x", key_size_bytes, sig_key_size/8);
        return false;
    }

    list_data = allocate_sized_buffer(pollist->KeySignatureOffset);
    if (list_data == NULL) {
        ERROR("Error: failed to allocate memory for list data.\n");
        return false;
    }
    key_buffer = allocate_sized_buffer(key_size_bytes);
    if (key_buffer == NULL){
        ERROR("Error: failed to allocate memory for buffer.\n");
        free(list_data);
        return false;
    }
    signature_buffer = allocate_sized_buffer(key_size_bytes);
    if (signature_buffer == NULL ){
        ERROR("Error: failed to allocate memory for buffer.\n");
        free(list_data);
        free(key_buffer);
        return false;
    }
    list_data->size = pollist->KeySignatureOffset;
    key_buffer->size = key_size_bytes;
    signature_buffer->size = key_size_bytes;

    memcpy_s( (void *) list_data->data,
              list_data->size,
              (const void *) pollist,
              pollist->KeySignatureOffset);
    memcpy_s( (void *) key_buffer->data,
              key_size_bytes,
              (const void *) sig->KeyAndSignature.RsaKeyAndSignature.Key.Modulus,
              key_size_bytes);
    memcpy_s( (void *)signature_buffer->data,
              key_size_bytes,
              (const void *) sig->KeyAndSignature.RsaKeyAndSignature.Signature.Signature,
              key_size_bytes);

    //Remember that key and sig are LE in pollist file, must be BE for openssll
    buffer_reverse_byte_order((uint8_t *) signature_buffer->data, signature_buffer->size);
    buffer_reverse_byte_order((uint8_t *) key_buffer->data, key_buffer->size);
    
    result = verify_rsa_signature(list_data, key_buffer, signature_buffer,
                   hash_alg_sig, sig_alg, LCP_TPM20_POLICY_LIST2_1_VERSION_300);
    if (result) {
        DISPLAY("List signature verified positively.\n");
    }
    else {
        DISPLAY("List signature did not verify.\n");
    }
    free(key_buffer);
    free(signature_buffer);
    free(list_data);
    return result;
}

void display_tpm20_signature_2_1(const char *prefix, const lcp_signature_2_1 *sig,
                                                         const uint16_t sig_alg)
/*
This function: prints sigblock nicely formatted

In:
Out:

*/
{
    LOG("[display_tpm20_signature_2_1]\n");
    size_t new_prefix_len = 0;
    if (sig == NULL) {
        ERROR("Error: failed to get list signature.\n");
        return;
    }
    if (*prefix == '\0')
        new_prefix_len = 8;
    else
        new_prefix_len = strnlen_s(prefix, 20) + 8;
    char new_prefix[new_prefix_len]; //To make digests indented.
    strcpy_s(new_prefix, sizeof(new_prefix), prefix);
    strcat_s(new_prefix, sizeof(new_prefix), "\t");

    size_t keysize;

    DISPLAY ("%s revocation_counter: 0x%x (%u)\n", prefix,
                sig->RevocationCounter, sig->RevocationCounter);

    switch ( sig_alg )
    {
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS: ;
        DISPLAY("RSA_KEY_AND_SIGNATURE:\n");
        keysize = sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8;
        DISPLAY ("%s Version: 0x%x\n", prefix,
                               sig->KeyAndSignature.RsaKeyAndSignature.Version);

        DISPLAY ("%s KeyAlg: 0x%x (%s)\n",
            prefix,
            sig->KeyAndSignature.RsaKeyAndSignature.KeyAlg,
            key_alg_to_str(sig->KeyAndSignature.RsaKeyAndSignature.KeyAlg)
        );

        DISPLAY("RSA_PUBLIC_KEY:\n");
        DISPLAY ("%s Version: 0x%x\n", prefix,
                            sig->KeyAndSignature.RsaKeyAndSignature.Key.Version);
        DISPLAY ("%s KeySize: 0x%x", prefix,
                        sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize);
        DISPLAY(" (%u)\n", sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize);
        DISPLAY ("%s Exponent: 0x%x\n", prefix,
                        sig->KeyAndSignature.RsaKeyAndSignature.Key.Exponent);
        DISPLAY ("%s Modulus:\n", prefix);
        print_hex(
            new_prefix, sig->KeyAndSignature.RsaKeyAndSignature.Key.Modulus, keysize
            );
        DISPLAY("End of RSA_PUBLIC_KEY\n");

        DISPLAY (
            "%s SigScheme: 0x%x (%s)\n",
            prefix,
            sig->KeyAndSignature.RsaKeyAndSignature.SigScheme,
            sig_alg_to_str(sig->KeyAndSignature.RsaKeyAndSignature.SigScheme)
        );

        DISPLAY("RSA_SIGNATURE:\n");
        DISPLAY ("%s Version: 0x%x\n", prefix,
                            sig->KeyAndSignature.RsaKeyAndSignature.Signature.Version);
        DISPLAY ("%s KeySize: 0x%x", prefix,
                            sig->KeyAndSignature.RsaKeyAndSignature.Signature.KeySize);
        DISPLAY(" (%u)\n", sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize);

        DISPLAY (
            "%s HashAlg: 0x%x (%s)\n",
            prefix,
            sig->KeyAndSignature.RsaKeyAndSignature.Signature.HashAlg,
            hash_alg_to_str(sig->KeyAndSignature.RsaKeyAndSignature.Signature.HashAlg)
        );

        DISPLAY("%s sig_block:\n", prefix);
        print_hex(
            new_prefix, sig->KeyAndSignature.RsaKeyAndSignature.Signature.Signature,
            keysize
        );
        break;
    case TPM_ALG_SM2: //Process is the same as for ECDSA
    case TPM_ALG_ECDSA:
        DISPLAY("ECC_KEY_AND_SIGNATURE:\n");
        keysize = sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize / 8;
        DISPLAY ("%s Version: 0x%x\n", prefix,
                               sig->KeyAndSignature.EccKeyAndSignature.Version);

        DISPLAY (
            "%s KeyAlg: 0x%x (%s)\n",
            prefix,
            sig->KeyAndSignature.EccKeyAndSignature.KeyAlg,
            key_alg_to_str(sig->KeyAndSignature.EccKeyAndSignature.KeyAlg)
        );

        DISPLAY("ECC_PUBLIC_KEY:\n");
        DISPLAY ("%s Version: 0x%x\n", prefix,
                            sig->KeyAndSignature.EccKeyAndSignature.Key.Version);
        DISPLAY ("%s KeySize: 0x%x", prefix,
                        sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize);
        DISPLAY(" (%u)\n", sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize);
        DISPLAY ("Public key Qx: \n");
        print_hex(new_prefix, (const void *) sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy,
                                                                       keysize);
        DISPLAY ("Public key Qy: \n");
        print_hex(new_prefix, (const void *) sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy+
                                                              keysize, keysize);
        DISPLAY("End of ECC_PUBLIC_KEY\n");

        DISPLAY (
            "%s SigScheme: 0x%x (%s)\n",
            prefix,
            sig->KeyAndSignature.EccKeyAndSignature.SigScheme,
            sig_alg_to_str(sig->KeyAndSignature.EccKeyAndSignature.SigScheme)
        );

        DISPLAY("ECC_SIGNATURE:\n");
        DISPLAY ("%s Version: 0x%x\n", prefix,
                            sig->KeyAndSignature.EccKeyAndSignature.Signature.Version);
        DISPLAY ("%s KeySize: 0x%x", prefix,
                            sig->KeyAndSignature.EccKeyAndSignature.Signature.KeySize);
        DISPLAY(" (%u)\n", sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize);

        DISPLAY (
            "%s HashAlg: 0x%x (%s)\n",
            prefix,
            sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg,
            hash_alg_to_str(sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg)
        );

        DISPLAY ("Signature R part: \n");
        print_hex(new_prefix, (const void *)
           sig->KeyAndSignature.EccKeyAndSignature.Signature.sigRsigS, keysize);
        DISPLAY ("Signature S part: \n");
        print_hex(new_prefix, (const void *)
           sig->KeyAndSignature.EccKeyAndSignature.Signature.sigRsigS+keysize,
                                                                       keysize);
        break;
    default:
        break;
    }
}

lcp_policy_list_t2_1 *add_tpm20_signature_2_1(lcp_policy_list_t2_1 *pollist,
                            lcp_signature_2_1 *sig, const uint16_t sig_alg)
/*
This function: Adds signature fields to the list that hasn't got them

In: pointer to LCP list, pointer to signature, signature alg
Out: copy of a list with signature added
*/
{
    size_t old_size;
    size_t sig_size;
    size_t sig_begin;
    lcp_policy_list_t2_1 *new_pollist;
    LOG("[add_tpm20_signature_2_1]\n");
    if ( pollist == NULL || sig == NULL ) {
        LOG("add_tpm20_signature_2_1 pollist or signature == NULL");
        return NULL;
    }
    switch (sig_alg)
    {
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS:
        old_size = get_tpm20_policy_list_2_1_size(pollist);
        if ( old_size != offsetof(lcp_policy_list_t2_1, PolicyElements) +
                                                  pollist->PolicyElementsSize) {
            DISPLAY("List already signed");
            return pollist;
        }
        sig_size = offsetof(lcp_signature_2_1, KeyAndSignature) +
                                                  sizeof(rsa_key_and_signature);
        pollist->KeySignatureOffset = old_size + offsetof(lcp_signature_2_1,
                                                               KeyAndSignature);
        new_pollist = realloc(pollist, old_size + sig_size);

        if ( new_pollist == NULL ){
            ERROR("Error: failed to allocate memory\n");
            free(pollist);
            return NULL;
        }
        sig_begin = old_size;
        memcpy_s((void *)new_pollist + sig_begin, sig_size, sig, sig_size);
        return new_pollist;
    case TPM_ALG_SM2: // Process is the same as for ECDSA
    case TPM_ALG_ECDSA:
        old_size = get_tpm20_policy_list_2_1_size(pollist);
        if ( old_size != offsetof(lcp_policy_list_t2_1, PolicyElements) +
                                                  pollist->PolicyElementsSize) {
            DISPLAY("ERROR: List already signed");
            return pollist;
        }
        sig_size = offsetof(lcp_signature_2_1, KeyAndSignature) +
                                                  sizeof(ecc_key_and_signature);
        pollist->KeySignatureOffset = old_size + offsetof(lcp_signature_2_1,
                                                               KeyAndSignature);
        new_pollist = realloc(pollist, old_size + sig_size);
        if ( new_pollist == NULL ){
            ERROR("Error: failed to allocate memory\n");
            free(pollist);
            return NULL;
        }
        sig_begin = old_size;
        memcpy_s((void *)new_pollist + sig_begin, sig_size, sig, sig_size);
        return new_pollist;
    default:
        return NULL;
    }
}

bool calc_tpm20_policy_list_2_1_hash(const lcp_policy_list_t2_1 *pollist,
                                     lcp_hash_t2 *hash, uint16_t hash_alg)
/*
This function: Hashes LCP_POLICY_LIST_2_1 data. If unsigned: entire list, else:
modulus or qx qy 

In: policy list, hash t2 structure and hashalg
Out: void

*/
{
    uint16_t key_alg;
    size_t buff_size;
    bool result;

    if (pollist == NULL) {
        ERROR("ERROR: LCP list not defined.\n");
        return false;
    }

    if (hash == NULL) {
        ERROR("ERROR: Hash buffer not defined.\n");
        return false;
    }
    LOG("[calc_tpm20_policy_list_2_1_hash]\n");
    if (pollist->KeySignatureOffset == 0) {
        //Not signed
        buff_size = get_tpm20_policy_list_2_1_size(pollist);
        if (!hash_buffer((const unsigned char *) pollist, buff_size, (tb_hash_t *) hash, hash_alg)) {
            ERROR("ERROR: failed to hash list data.\n");
            return false;
        }
        else {
            return true;
        }
    }
    else if ( pollist->KeySignatureOffset > 0 ) {
        lcp_signature_2_1 *sig = get_tpm20_signature_2_1(pollist);
        if (sig == NULL) {
            ERROR("ERROR: failed to load LCP policy signature\n");
            return false;
        }
        key_alg = get_signature_2_1_key_alg(sig);
        switch (key_alg)
        {
        case TPM_ALG_RSA:
            LOG("List signed: RSA\n");
            //keysize in lcp signature 2.1 is in bits
            buff_size = sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8;
            result = hash_buffer(
            (const unsigned char *) sig->KeyAndSignature.RsaKeyAndSignature.Key.Modulus,
            buff_size, (tb_hash_t *) hash, hash_alg);
            if (!result) {
                ERROR("ERROR: failed to allocate buffer\n");
                return false;
            }
            else {
                return true;
            }
        case TPM_ALG_ECC:
            LOG("List signed: ECC\n");
            //keysize in lcp signature 2.1 is in bits
            //Qx and Qy are each KeySize
            buff_size = 2 * (sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize / 8);
            result = hash_buffer(
            (const unsigned char *) sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy,
            buff_size, (tb_hash_t *) hash, hash_alg);
            if (!result) {
                ERROR("ERROR: failed to allocate buffer\n");
                return false;
            }
            else {
                return true;
            }
        default:
            ERROR("ERROR: unknown key_alg.\n");
            return false;
        }
    }
    else {
        ERROR("KeySignatureOffset must be equal to or greater than zero.\n");
        return false;
    }
}

unsigned char *fill_tpm20_policy_list_2_1_buffer(const lcp_policy_list_t2_1 *pollist, size_t *len)
/*
This function: writes LCP policy list 2.1 with or without signature to a buffer

In: policy list 2.1 structure, pointer to var that will hold filled buffer size
Out: handle to buffer containing contiguous policy list data.

*/
{
    int result;
    size_t list_size, buffer_size, key_size, bytes_written, bytes_to_copy;
    //Buffer_size will be decremented by amount of bytes_written each time we copy mem.
    uint16_t key_alg;

    lcp_signature_2_1 *sig;
    unsigned char *to_buffer;

    bytes_written = 0;

    LOG("[fill_tpm20_policy_list_2_1_buffer]\n");
    if ( pollist == NULL ) {
        ERROR("Error: policy list not defined.\n");
        return NULL;
    }

    list_size = get_tpm20_list_2_1_real_size(pollist); //NOT structure size but actual size
    if (!list_size) {
        ERROR("Error: failed to get list size.\n");
        return NULL;
    }
    buffer_size = list_size; //They are the same
    *len = buffer_size;
    to_buffer = malloc(buffer_size);
    if (to_buffer == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        return NULL;
    }
    if ( pollist->KeySignatureOffset == 0 ) { //No signature
        if (memcpy_s((void *)to_buffer, buffer_size, (const void*) pollist, list_size) != EOK)
        {
            ERROR("Error: failed to copy list data.\n");
            free(to_buffer);
            return NULL;
        }
        return to_buffer;
    }
    sig = get_tpm20_signature_2_1(pollist);
    if (sig == NULL) {
        ERROR("Error: signature not defined.\n");
        free(to_buffer);
        return NULL;
    }
    key_alg = get_signature_2_1_key_alg(sig);
    //First copy list without signature
    bytes_to_copy = pollist->KeySignatureOffset - offsetof(lcp_signature_2_1, KeyAndSignature);
    result = memcpy_s((void *) to_buffer, buffer_size, (const void *)pollist, bytes_to_copy);
    if (result != EOK) {
        ERROR("Error: failed to copy list data.\n");
        free(to_buffer);
        return NULL;
    }
    bytes_written += bytes_to_copy;
    buffer_size -= bytes_to_copy;
    //Signature:
    switch (key_alg)
    {
    case TPM_ALG_RSA:
        //Copy key part of the sig.
        key_size = sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8;
        bytes_to_copy = offsetof(lcp_signature_2_1, KeyAndSignature) +
                        offsetof(rsa_key_and_signature, Key) +
                        sizeof(rsa_public_key) - (MAX_RSA_KEY_SIZE - key_size);
        result = memcpy_s((void *)to_buffer+bytes_written, buffer_size, (const void *) sig, bytes_to_copy);
        if (result != EOK) {
            ERROR("Error: failed to copy list data.\n");
            free(to_buffer);
            return NULL;
        }
        sig = (void *)sig + offsetof(lcp_signature_2_1, KeyAndSignature); //Move over revoc_counter
        sig = (void *)sig + offsetof(rsa_key_and_signature, SigScheme); //Move to sig scheme
        bytes_written += bytes_to_copy;
        buffer_size -= bytes_to_copy;
        //Copy rest of the sig
        bytes_to_copy = sizeof(sig->KeyAndSignature.RsaKeyAndSignature.SigScheme) +
                        sizeof(rsa_signature) - (MAX_RSA_KEY_SIZE - key_size);
        result = memcpy_s((void *)to_buffer+bytes_written, buffer_size, (const void *) sig, bytes_to_copy);
        if (result != EOK) {
            ERROR("Error: failed to copy list data.\n");
            free(to_buffer);
            return NULL;
        }
        break;
    case TPM_ALG_ECC:
        //Copy key part of the sig.
        key_size = sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize / 8;
        bytes_to_copy = offsetof(lcp_signature_2_1, KeyAndSignature) +
                        offsetof(ecc_key_and_signature, Key) +
                        sizeof(ecc_public_key) - 2*(MAX_ECC_KEY_SIZE - key_size);
        result = memcpy_s((void *)to_buffer+bytes_written, buffer_size, (const void *) sig, bytes_to_copy);
        if (result != EOK) {
            ERROR("Error: failed to copy list data.\n");
            free(to_buffer);
            return NULL;
        }
        sig = (void *)sig + offsetof(lcp_signature_2_1, KeyAndSignature); //Move over revoc_counter
        sig = (void *)sig + offsetof(ecc_key_and_signature, SigScheme); //Move to sig scheme
        bytes_written += bytes_to_copy;
        buffer_size -= bytes_to_copy;
        //Copy rest of the sig
        bytes_to_copy = sizeof(sig->KeyAndSignature.EccKeyAndSignature.SigScheme) +
                        sizeof(ecc_signature) - 2*(MAX_ECC_KEY_SIZE - key_size);
        result = memcpy_s((void *)to_buffer+bytes_written, buffer_size, (const void *) sig, bytes_to_copy);
        if (result != EOK) {
            ERROR("Error: failed to copy list data.\n");
            free(to_buffer);
            return NULL;
        }
        break;
    default:
        ERROR("Error: unsupported key algorithm.\n");
        free(to_buffer);
        return NULL;
    }
    return to_buffer;
}

uint16_t get_signature_2_1_key_alg(const lcp_signature_2_1 *sig)
{
    return *(uint16_t *) ((void *)sig + SIG_KEY_SIG_KEY_ALG_OFFSET);
}

size_t get_tpm20_key_and_signature_2_1_real_size(const lcp_signature_2_1 *sig)
/*
This function: calculates real size of the signature structure

In: signature structure handle
Out: signature size, or 0 on error.

*/
{
    uint16_t key_alg;
    size_t key_size_bytes;
    size_t sig_size = 0;
    LOG("[get_tpm20_key_and_signature_2_1_real_size]\n");
    if (sig == NULL) {
        return 0;
    }
    key_alg = get_signature_2_1_key_alg(sig);
    switch (key_alg)
    {
    case TPM_ALG_RSA:
        key_size_bytes = sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8;
        sig_size = sizeof(rsa_key_and_signature) - 2 * (MAX_RSA_KEY_SIZE - key_size_bytes);
        return sig_size;
    case TPM_ALG_ECC:
        key_size_bytes = sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize / 8;
        sig_size = sizeof(ecc_key_and_signature) - 4 * (MAX_ECC_KEY_SIZE - key_size_bytes);
        return sig_size;
    default:
        ERROR("Error: unknown key algorithm.\n");
        return 0;
    }
}

size_t get_tpm20_list_2_1_real_size(const lcp_policy_list_t2_1 *pollist)
/*
This function: lcp list 2.1 has dynamic size, especially with signature. This 
calculates size of lcp list as if it is supposed to be written to a file

In: pointer to a list structure
Out: real size of a list, or 0 on failure

*/
{
    size_t size = 0;
    size_t sig_size = 0;
    LOG("[get_tpm20_list_2_1_real_size]\n");
    if (pollist == NULL) {
        return size;
    }
    if (pollist->KeySignatureOffset == 0) //Not signed
        size = offsetof(lcp_policy_list_t2_1, PolicyElements)+pollist->PolicyElementsSize;
    else { //list signed
        lcp_signature_2_1 *sig = get_tpm20_signature_2_1(pollist);
        if ( sig == NULL ) {
            ERROR("Failed to get signature.\n");
            size = 0;
            return size;
        }
        sig_size = get_tpm20_key_and_signature_2_1_real_size(sig);
        if (sig_size == 0) {
            ERROR("Failed to calculate signature size.\n");
            return sig_size;
        }
        size = pollist->KeySignatureOffset + sig_size;
        return size;
    }
    return size;
}

bool write_tpm20_policy_list_2_1_file(const char *file,
                                      const lcp_policy_list_t2_1 *pollist)
/*
This function: writes LCP policy list 2.1 to a file

In: file handle, list structure handle
Out: true/false write success or failure

*/
{
    unsigned char *buffer = NULL;
    size_t buffer_size; //For unsigned list

    LOG("[write_tpm20_policy_list_2_1_file]\n");
    if (pollist == NULL) {
        ERROR("Error: policy list undefined.\n");
        return false;
    }

    //No sig:
    if ( pollist->KeySignatureOffset == 0 ) {
        if (!write_file(file, (const void *) pollist, get_tpm20_policy_list_2_1_size(pollist))) {
            ERROR("ERROR: Failed to write.\n");
            return false;
        }
        else {
            return true;
        }
    }
    buffer = fill_tpm20_policy_list_2_1_buffer(pollist, &buffer_size);
    if ( buffer == NULL ) {
        ERROR("ERROR: Failed to allocate buffer.\n");
        return false;
    }
    if (!write_file(file, buffer, buffer_size)) {
        ERROR("ERROR: Failed to write.\n");
        free(buffer);
        return false;
    }
    else {
        LOG("Write successful.\n");
        free(buffer);
        return true;
    }
}

static lcp_signature_2_1 *read_rsa_pubkey_file_2_1(const char *file)
/*
This function: extracts rsa data to a lcp_signature_2_1 structure

In: path to file containing RSA public key
Out: Pointer to signature structure.
*/
{
    FILE *fp = NULL;
    BIGNUM *modulus = NULL;
    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_PKEY *pubkey = NULL;
    #else
        RSA *pubkey = NULL;
    #endif
    lcp_signature_2_1 *sig = NULL;
    unsigned char *key = NULL;

    int keysize = 0;
    int result = 0;

    LOG("read_rsa_pubkey_file_2_1\n");
    fp = fopen(file, "rb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open .pem file %s: %s\n", file,
                strerror(errno));
        return NULL;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        OSSL_DECODER_CTX *dctx;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&pubkey, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
        if ( dctx == NULL ) {
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_DECODER_from_fp(dctx, fp) ) {
            goto OPENSSL_ERROR;
        }
        OSSL_DECODER_CTX_free(dctx);
    #else
        pubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    #endif
    if ( pubkey == NULL ) {
        goto OPENSSL_ERROR;
    }
    //Close the file, won't need it anymore
    fclose(fp);
    fp = NULL;

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        keysize = EVP_PKEY_get_size(pubkey);
    #else
        keysize = RSA_size(pubkey);
    #endif
    if ( keysize != 256 && keysize != 384 ) {
        ERROR("Error: public key size %d is not supported\n", keysize);
        goto ERROR;
    }

    sig = create_empty_rsa_signature_2_1(); //Sig has all 0-s
    if ( sig == NULL ) {
        ERROR("Error: failed to create empty lcp signature 2.1\n");
        goto ERROR;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_PKEY_get_bn_param(pubkey, "n", &modulus);
    #elif OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_get0_key(pubkey, (const BIGNUM **) &modulus, NULL, NULL);
    #else
        modulus = pubkey->n;
    #endif
    if (modulus == NULL) {
        goto OPENSSL_ERROR;
    }

    //Allocate for the key
    key = malloc(keysize);
    if (key == NULL) {
        ERROR("Error: failed to allocate memory for public key.\n");
        goto ERROR;
    }
    //Save mod into key array
    result = BN_bn2bin(modulus, key);
    if (result <= 0 || result != keysize) {
        goto OPENSSL_ERROR;
    }

    /* openssl key is big-endian and policy requires little-endian, so reverse
       bytes and append to sig*/

    for ( int i = 0; i < keysize; i++ ) {
        sig->KeyAndSignature.RsaKeyAndSignature.Key.Modulus[i] = key[keysize -i -1];
    }

    sig->KeyAndSignature.RsaKeyAndSignature.KeyAlg = TPM_ALG_RSA;
    sig->KeyAndSignature.RsaKeyAndSignature.Version = SIGNATURE_VERSION;
    sig->KeyAndSignature.RsaKeyAndSignature.Key.Version= SIGNATURE_VERSION;
    sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize = keysize*8; //Must be in bits
    sig->KeyAndSignature.RsaKeyAndSignature.Key.Exponent = LCP_SIG_EXPONENT;
    sig->KeyAndSignature.RsaKeyAndSignature.Signature.Version = SIGNATURE_VERSION;
    sig->KeyAndSignature.RsaKeyAndSignature.Signature.KeySize = keysize*8; //Must be bits

    if ( verbose ) {
        LOG("read_rsa_pubkey_file: signature:\n");
        display_tpm20_signature_2_1("    ", sig, TPM_ALG_RSAPSS);
    }
    //SUCCESS:
        OPENSSL_free((void *) pubkey);
        OPENSSL_free((void * )modulus);
        free(key);
        return sig;
    OPENSSL_ERROR:
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto ERROR;
    ERROR:
        if (fp != NULL)
            fclose(fp);
        if (key != NULL)
            free(key);
        if (sig != NULL)
            free(sig);
        if (modulus == NULL)
            OPENSSL_free((void *) modulus);
        if (pubkey != NULL)
            OPENSSL_free((void *) pubkey);
        return NULL;
}

bool rsa_sign_list_2_1_data(lcp_policy_list_t2_1 *pollist, const char *privkey_file)
{
    /*
    This function: prepares policy list 2.1 for signing using either RSASSA PKCS1.5
    or RSA-PSS algorithm.

    In: pointer to a policy list, path to a private key

    Out: True on success, false on failure
    */
    uint16_t hashalg;
    uint16_t keysize;
    uint16_t sig_alg;
    bool status;

    lcp_signature_2_1 *sig = NULL;
    sized_buffer *digest = NULL;
    sized_buffer *sig_block = NULL;  //Buffer for generated sig
    EVP_PKEY_CTX *context = NULL;  //Context for openssl functions

    LOG("rsa_sign_list_2_1_data\n");
    if ( pollist == NULL || privkey_file == NULL )
        return false;
    //Get signature
    sig = get_tpm20_signature_2_1(pollist);
    if ( sig == NULL) {
        return false;
    }

    hashalg = sig->KeyAndSignature.RsaKeyAndSignature.Signature.HashAlg;
    //keysize var is in bytes, the one in structure is bits
    keysize = sig->KeyAndSignature.RsaKeyAndSignature.Signature.KeySize / 8;
    sig_alg = sig->KeyAndSignature.RsaKeyAndSignature.SigScheme;

    //Hash list data up to - but not including - keySignature structure.
    //KeySignatureOffset tells us how many bytes to hash

    if (verbose) {
        DISPLAY("Data to hash:\n");
        print_hex("       ", (const unsigned char *) pollist, pollist->KeySignatureOffset);
    }

    digest = allocate_sized_buffer(get_lcp_hash_size(hashalg));
    if (digest == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        goto ERROR;
    }
    digest->size = get_lcp_hash_size(hashalg);

    status = hash_buffer((const unsigned char *) pollist, pollist->KeySignatureOffset,
                                           (tb_hash_t *) digest->data, hashalg);
    if ( !status ) {
        ERROR("Error: failed to hash list\n");
        goto ERROR;
    }

    if ( verbose ) {
        LOG("digest:\n");
        print_hex("", &digest, get_hash_size(hashalg));
    }

    //Create context using key
    context = rsa_get_sig_ctx(privkey_file, keysize);
    if ( context == NULL) {
        ERROR("ERROR: failed to initialize EVP context.\n");
        goto ERROR;
    }

    //Allocate mem for signature block:
    sig_block = allocate_sized_buffer(keysize);
    if (sig_block == NULL) {
        ERROR("ERROR: failed to allocate memory for signature block.\n");
        goto ERROR;
    }
    sig_block->size = keysize;

    //Sign
    status = rsa_ssa_pss_sign(sig_block, digest, sig_alg, hashalg, context);
    if (!status) {
        ERROR("ERROR: failed to sign list data.");
        goto ERROR;
    }

    //Copy sig_block to signature, flip endianness
    buffer_reverse_byte_order((uint8_t *) sig_block->data, sig_block->size);
    memcpy_s((void *) sig->KeyAndSignature.RsaKeyAndSignature.Signature.Signature,
                      keysize, (const void *) sig_block->data, sig_block->size);
    if ( verbose ) {
        LOG("Signature: \n");
        display_tpm20_signature_2_1("    ", sig, sig_alg);
    }
    if (sig_block != NULL) {
        free(sig_block);
    }
    if (digest != NULL) {
        free(digest);
    }
    if (context != NULL)
        OPENSSL_free(context);
    return true;
    ERROR:
        if (sig_block != NULL) {
            free(sig_block);
        }
        if (digest != NULL) {
            free(digest);
        }
        if (context != NULL)
            OPENSSL_free(context);
        return false;
}

static lcp_signature_2_1 *read_ecdsa_pubkey_file_2_1(const char *pubkey_file)
{
    int result;
    lcp_signature_2_1 *sig = NULL;
    FILE *fp = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    uint16_t bytes_in_x;
    uint16_t bytes_in_y;
    uint16_t keySize;
    uint16_t keySizeBytes;
    uint8_t qx[MAX_ECC_KEY_SIZE];
    uint8_t qy[MAX_ECC_KEY_SIZE];
    uint8_t qx_le[MAX_ECC_KEY_SIZE];
    uint8_t qy_le[MAX_ECC_KEY_SIZE];
    #if OPENSSL_VERSION_NUMBER < 0x30000000L
        const EC_KEY *pubkey = NULL;
        const EC_POINT *pubpoint = NULL;
        const EC_GROUP *pubgroup = NULL;
        BN_CTX *ctx = NULL;
    #else
        EVP_PKEY *pubkey = NULL;
    #endif

    fp = fopen(pubkey_file, "rb");
    if ( fp == NULL) {
        ERROR("ERROR: cannot open file.\n");
        goto ERROR;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        OSSL_DECODER_CTX *dctx;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&pubkey, "PEM", NULL, "EC", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
        if ( dctx == NULL ) {
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_DECODER_from_fp(dctx, fp) ) {
            goto OPENSSL_ERROR;
        }
        OSSL_DECODER_CTX_free(dctx);

        if ( pubkey == NULL ) {
            goto OPENSSL_ERROR;
        }

        EVP_PKEY_get_bn_param(pubkey, "qx", &x);
        EVP_PKEY_get_bn_param(pubkey, "qy", &y);
        if ( x == NULL|| y == NULL ) {
            goto OPENSSL_ERROR;
        }
    #else
        pubkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
        if ( pubkey == NULL ) {
            goto OPENSSL_ERROR;
        }

        pubpoint = EC_KEY_get0_public_key(pubkey);
        if ( pubpoint == NULL ) {
            goto OPENSSL_ERROR;
        }
        pubgroup = EC_KEY_get0_group(pubkey);
        if ( pubgroup == NULL ) {
            goto OPENSSL_ERROR;
        }

        x = BN_new();
        y = BN_new();
        if ( x == NULL|| y == NULL ) {
            goto OPENSSL_ERROR;
        }
        ctx = BN_CTX_new();
        if ( ctx == NULL ) {
            goto OPENSSL_ERROR;
        }
        result = EC_POINT_get_affine_coordinates_GFp(pubgroup, pubpoint, x, y, ctx);
        if (result <= 0) {
            goto OPENSSL_ERROR;
        }
    #endif    
    //Close the file
    fclose(fp);
    fp = NULL;

    bytes_in_x = BN_num_bytes(x);
    bytes_in_y = BN_num_bytes(y);

    keySize = bytes_in_x*8;
    if (bytes_in_x != bytes_in_y) {
        ERROR("ERROR: key coordinates are not the same length.");
        goto ERROR;
    }
    if ( keySize != 256 && keySize != 384 ) {
        ERROR("ERROR: keySize 0x%X is not 0x%X or 0x%X.\n", keySize/8, MIN_ECC_KEY_SIZE,
                                                              MAX_ECC_KEY_SIZE);
        goto ERROR;
    }

    keySizeBytes = bytes_in_x;
    if ( keySize/8 != bytes_in_x || keySize/8 != bytes_in_y ) {
        ERROR("ERROR: keySize 0x%X is not 0x%X or 0x%X.\n", keySizeBytes,
                                            MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE);
        goto ERROR;
    }
    sig = create_empty_ecc_signature_2_1();
    if ( sig == NULL ) {
        ERROR("ERROR: failed to generate ecc signature 2.1.\n");
        goto ERROR;
    }

    sig->KeyAndSignature.EccKeyAndSignature.Version = SIGNATURE_VERSION;
    sig->KeyAndSignature.EccKeyAndSignature.KeyAlg = TPM_ALG_ECC;
    sig->KeyAndSignature.EccKeyAndSignature.Key.Version = SIGNATURE_VERSION;
    sig->KeyAndSignature.EccKeyAndSignature.Key.KeySize = keySize; //In bits!
    sig->KeyAndSignature.EccKeyAndSignature.Signature.Version = SIGNATURE_VERSION;
    sig->KeyAndSignature.EccKeyAndSignature.Signature.KeySize = keySize;

    if (keySize == 256) { //256 bit key with sha256
        sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg = TPM_ALG_SHA256;
    }
    else { //384 bit key with sha384
        sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg = TPM_ALG_SHA384;
    }

    if (!BN_bn2bin(x, qx)) {
        goto OPENSSL_ERROR;
    }
    if (!BN_bn2bin(y, qy)) {
        goto OPENSSL_ERROR;
    }

    for (uint8_t i = 0; i < keySizeBytes; i++) { //reverse
        qx_le[i] = qx[keySizeBytes-1-i];
        qy_le[i] = qy[keySizeBytes-1-i];
    }

    result = memcpy_s(
        (void*)sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy,
        2*MAX_ECC_KEY_SIZE, qx_le, bytes_in_x
    );
    if ( result != EOK ) {
        ERROR("ERROR: Cannot copy key data to LCP list\n");
        goto ERROR;
    }
    result = memcpy_s(
        (void*)sig->KeyAndSignature.EccKeyAndSignature.Key.QxQy + bytes_in_x,
        (2*MAX_ECC_KEY_SIZE)-bytes_in_x, qy_le, bytes_in_y
    );
    if ( result != EOK ) {
        ERROR("ERROR: Cannot copy key data to LCP list\n");
        goto ERROR;
    }
//Free resources:
    OPENSSL_free((void *) pubkey);
    OPENSSL_free((void *) x);
    OPENSSL_free((void *) y);
    #if OPENSSL_VERSION_NUMBER < 0x30000000L
        OPENSSL_free((void *) pubpoint);
        OPENSSL_free((void *) pubgroup);
        OPENSSL_free((void *) ctx);
    #endif
    return sig;
//ERROR handling:
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
    ERROR:
        //Free all OPENSSL stuff
        if (fp != NULL)
            fclose(fp);
        if (sig != NULL)
            free(sig);
        if (pubkey != NULL)
            OPENSSL_free((void *) pubkey);
        if (x != NULL)
            OPENSSL_free((void *) x);
        if (y != NULL)
            OPENSSL_free((void *) y);
        #if OPENSSL_VERSION_NUMBER < 0x30000000L
            if (pubpoint != NULL)
                OPENSSL_free((void *) pubpoint);
            if (pubgroup != NULL)
                OPENSSL_free((void *) pubgroup);
            if (ctx != NULL)
                OPENSSL_free((void *) ctx);
        #endif
        return NULL;
}

bool ec_sign_list_2_1_data(lcp_policy_list_t2_1 *pollist, const char *privkey_file)
{
    /*
        This function: prepares lcp_policy_list_t2_1 structure for signing
        using private key file. Signing in ecdsa or sm2

        In: pointer to correctly allocated policy list structure, path to private
        key

        Out: true on success, false on failure.
    */
    sized_buffer *sig_r = NULL;
    sized_buffer *sig_s = NULL;
    sized_buffer *pollist_data = NULL;
    lcp_signature_2_1 *sig = NULL;
    bool result;
    size_t data_len;
    size_t keysize;
    uint16_t hashalg;
    uint16_t sigalg;

    LOG("[ec_sign_list_2_1_data]\n");
    if (pollist == NULL) {
        ERROR("Error: lcp policy list is not defined.\n");
        return false;
    }
    sig = get_tpm20_signature_2_1(pollist);
    if (sig == NULL) {
        ERROR("Error: failed to get signature structure.\n");
        return false;
    }
    sigalg = sig->KeyAndSignature.EccKeyAndSignature.SigScheme;
    hashalg = sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg;
    data_len = pollist->KeySignatureOffset; //This is how much data will be signed
    //Key size must be in bytes and is in bits in sig structure:
    keysize = sig->KeyAndSignature.EccKeyAndSignature.Signature.KeySize / 8;

    //Allocate buffers:
    sig_r = allocate_sized_buffer(keysize);
    sig_s = allocate_sized_buffer(keysize);
    pollist_data = allocate_sized_buffer(data_len);
    if (sig_r == NULL || sig_s == NULL || pollist_data == NULL) {
        ERROR("Error: failed to allocate one or more data buffers.\n");
        result = false;
        goto EXIT;
    }
    sig_r->size = keysize; 
    sig_s->size = keysize;
    pollist_data->size = data_len;
    //Copy list contents to buffer:
    memcpy_s((void *) pollist_data->data, pollist_data->size, 
                                              (const void *) pollist, data_len);
    if (verbose) {
        LOG("Data to be signed:\n");
        print_hex("    ", pollist_data->data, pollist_data->size);
    }

    //Do the signing
    result = ec_sign_data(pollist_data, sig_r, sig_s, sigalg, hashalg, privkey_file);

    if (!result) {
        ERROR("Error: failed to sign pollist data.\n");
        result = false;
        goto EXIT;
    }
    //Openssl return data in BE, lcp needs LE so we change endianness of buffers:
    buffer_reverse_byte_order((uint8_t *)sig_r->data, sig_r->size);
    buffer_reverse_byte_order((uint8_t *)sig_s->data, sig_s->size);

    //And copy buffers to signature structure
    memcpy_s((void *) sig->KeyAndSignature.EccKeyAndSignature.Signature.sigRsigS,
                   2*MAX_ECC_KEY_SIZE, (const void *) sig_r->data, sig_r->size);
    memcpy_s((void *) sig->KeyAndSignature.EccKeyAndSignature.Signature.sigRsigS + 
    keysize, (2*MAX_ECC_KEY_SIZE) - keysize, (const void *) sig_s->data, sig_s->size);
    if (verbose) {
        display_tpm20_signature_2_1("    ", sig, sigalg);
    }
    EXIT:
        if (sig_r != NULL) {
            free(sig_r);
        }
        if (sig_s != NULL) {
            free(sig_s);
        }
        if (pollist_data != NULL) {
            free(pollist_data);
        }
        return result;
}

lcp_policy_list_t2_1 *policy_list2_1_rsa_sign(lcp_policy_list_t2_1 *pollist,
                                             uint16_t rev_ctr,
                                             uint16_t hash_alg,
                                             uint16_t sig_alg,
                                             const char *pubkey_file,
                                             const char *privkey_file)
{
    lcp_signature_2_1 *sig = NULL;
    bool result;

    if (pollist == NULL) {
        ERROR("Error: policy list is NULL.\n");
        return NULL;
    }

    sig = read_rsa_pubkey_file_2_1(pubkey_file);
    if (sig == NULL) {
        ERROR("Error: cannot create lcp signature 2.1\n");
        free(pollist);
        return NULL;
    }
    sig->KeyAndSignature.RsaKeyAndSignature.SigScheme = sig_alg;
    sig->KeyAndSignature.RsaKeyAndSignature.Signature.HashAlg = hash_alg;
    sig->RevocationCounter = rev_ctr;

    if ( sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8 != 256 &&
         sig->KeyAndSignature.RsaKeyAndSignature.Key.KeySize / 8 != 384 ) {
            ERROR("Error: public key size is not 2048/3072 bits\n");
            free(sig);
            free(pollist);
            return NULL;
    }

    pollist = add_tpm20_signature_2_1(pollist, sig, sig_alg);
    if (pollist == NULL) {
        ERROR("Error: failed to add lcp_signature_2_1 to list.\n");
        free(sig);
        return NULL;
    }
    result = rsa_sign_list_2_1_data(pollist, privkey_file);
    if (!result) {
        ERROR("Error: failed to sign list data.\n");
        free(sig);
        free(pollist);
        return NULL;
    }
    return pollist;
}

static lcp_policy_list_t2_1 *policy_list2_1_ec_sign(lcp_policy_list_t2_1 *pollist,
                                               uint16_t rev_ctr,
                                               uint16_t sig_alg,
                                               const char *pubkey_file,
                                               const char *privkey_file)
{
    lcp_signature_2_1 *sig = NULL;
    bool result;

    if (pollist == NULL) {
        ERROR("Error: cannot create lcp signature 2.1.\n");
        return NULL;
    }

    sig = read_ecdsa_pubkey_file_2_1(pubkey_file);
    if (sig == NULL) {
        ERROR("Error: failed to read ecc key.\n");
        return NULL;
    }
    sig->RevocationCounter = rev_ctr;
    sig->KeyAndSignature.EccKeyAndSignature.SigScheme = sig_alg;
    if (sig_alg == TPM_ALG_SM2) {
        sig->KeyAndSignature.EccKeyAndSignature.Signature.HashAlg = TPM_ALG_SM3_256;
    }
    pollist = add_tpm20_signature_2_1(pollist, sig, sig_alg);
    if (pollist == NULL) {
        ERROR("Error: failed to add lcp_signature_2_1 to list.\n");
        free(sig);
        return NULL;
    }
    result = ec_sign_list_2_1_data(pollist, privkey_file);
    if (!result) {
        ERROR("Error: failed to sign list data.\n");
        free(sig);
        free(pollist);
        return NULL;
    }
    return pollist;
}

bool sign_lcp_policy_list_t2_1(sign_user_input user_input)
{
    lcp_policy_list_t2_1 *pollist = NULL;
    bool result;

    pollist = read_policy_list_2_1_file(true, user_input.list_file);
    if (pollist == NULL) {
        ERROR("Error: failed to read policy list file.\n");
        free(pollist);
        return false;
    }
    if (user_input.sig_alg == TPM_ALG_RSAPSS) {
        pollist = policy_list2_1_rsa_sign(pollist,
                                          user_input.rev_ctr,
                                          user_input.hash_alg,
                                          user_input.sig_alg,
                                          user_input.pubkey_file,
                                          user_input.privkey_file);
    }
    else if (user_input.sig_alg == TPM_ALG_RSASSA) {
        DISPLAY("TPM_ALG_RSASSA is not supported with policy list version 0x300."
                                                       "Use TPM_ALG_RSAPSS.\n");
        free(pollist);
        return false;
        
    }
    else if (user_input.sig_alg == TPM_ALG_ECDSA ||
             user_input.sig_alg == TPM_ALG_SM2) {
        pollist = policy_list2_1_ec_sign(pollist,
                                            user_input.rev_ctr,
                                            user_input.sig_alg,
                                            user_input.pubkey_file,
                                            user_input.privkey_file);
    }
    else {
        DISPLAY("Signature algorithm not supported or not specified.\n");
        free(pollist);
        return false;
    }

    if (pollist == NULL) {
        ERROR("Error: failed to sign policy list.\n");
        return false;
    }
    result = write_tpm20_policy_list_2_1_file(user_input.list_file, pollist);
    free(pollist);

    return result;
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
