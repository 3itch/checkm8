/*
 * Copyright 2014 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TXT_LCP2_HELPER_H__
#define __TXT_LCP2_HELPER_H__

static inline lcp_signature_t *get_tpm12_signature(const lcp_policy_list_t *pollist)
{
    if ( pollist == NULL )
        return NULL;

    if ( pollist->sig_alg != LCP_POLSALG_RSA_PKCS_15 )
        return NULL;

    return (lcp_signature_t *)((const void *)&pollist->policy_elements +
                               pollist->policy_elements_size);
}

static inline size_t get_tpm12_signature_size(const lcp_signature_t *sig)
{
    if ( sig == NULL )
        return 0;

    return offsetof(lcp_signature_t, pubkey_value) + 2*sig->pubkey_size;
}

static inline size_t get_tpm12_policy_list_size(const lcp_policy_list_t *pollist)
{
    size_t size = 0;

    if ( pollist == NULL )
        return 0;

    size = offsetof(lcp_policy_list_t, policy_elements) +
           pollist->policy_elements_size;

    /* add sig size */
    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 )
        size += get_tpm12_signature_size(get_tpm12_signature(pollist));

    return size;
}

static inline lcp_signature_t2 *get_tpm20_signature(const lcp_policy_list_t2 *pollist)
{
    if ( pollist == NULL || pollist->sig_alg == TPM_ALG_NULL )
        return NULL;

    return (lcp_signature_t2 *)((const void *)&pollist->policy_elements +
                               pollist->policy_elements_size);
}

static inline lcp_signature_2_1 *get_tpm20_signature_2_1(
                                            const lcp_policy_list_t2_1 *pollist)
{
    if (pollist == NULL || pollist->KeySignatureOffset == 0)
        return NULL;

    return (lcp_signature_2_1 *) ((const void *)&pollist->PolicyElements +
                                    pollist->PolicyElementsSize);
}

static inline size_t get_tpm20_signature_size(const lcp_signature_t2 *sig,
                                              const uint16_t sig_alg)
{
    if ( sig == NULL )
         return 0;

    if ( sig_alg == TPM_ALG_RSASSA)
        return offsetof(lcp_rsa_signature_t, pubkey_value) +
                        2*sig->rsa_signature.pubkey_size;
    else if ( sig_alg == TPM_ALG_ECDSA || sig_alg == TPM_ALG_SM2)
        return offsetof(lcp_ecc_signature_t, qx) +
                        4*sig->ecc_signature.pubkey_size;

    return 0;
}

static inline size_t get_tpm20_policy_list_size(const lcp_policy_list_t2 *pollist)
{
    size_t size = 0;

    if ( pollist == NULL )
        return 0;

    size = offsetof(lcp_policy_list_t2, policy_elements) +
           pollist->policy_elements_size;

    /* add sig size */
    if ( pollist->sig_alg == TPM_ALG_RSASSA ||
         pollist->sig_alg == TPM_ALG_ECDSA ||
         pollist->sig_alg == TPM_ALG_SM2 )
        size += get_tpm20_signature_size(get_tpm20_signature(pollist),
                        pollist->sig_alg);

    return size;
}

static inline size_t get_raw_tpm20_sig_2_1_size(const lcp_key_and_sig *key_and_sig) {

    /*
        Calculate key and signature size treating it as a contigous buffer (
        i.e. read from file). Will return physical size of signature and key,
        not size of lcp_key_and_sig structure.
    */
    typedef struct __packed {
        uint8_t     Version;
        uint16_t    KeyAlg;
        uint8_t     Version2;
        uint16_t    KeySize;
    } sig_hdr;

    sig_hdr *this_hdr = NULL;

    if (key_and_sig == NULL) {
        return 0;
    }
    
    this_hdr = (sig_hdr *) key_and_sig;
    if (this_hdr->KeyAlg == TPM_ALG_RSA) {
        return sizeof(rsa_key_and_signature) -
                                   2*(MAX_RSA_KEY_SIZE - (this_hdr->KeySize/8));
    }
    else if (this_hdr->KeyAlg == TPM_ALG_ECC) {
        return sizeof(ecc_key_and_signature) -
                                   4*(MAX_ECC_KEY_SIZE - (this_hdr->KeySize/8));
    }
    else {
        return 0;
    }
}

static inline size_t get_raw_tpm20_list_2_1_size(const lcp_policy_list_t2_1 *pollist)
{
    /*
        Calculate size of a list in a contiguous buffer (i.e. read from file).
    */
    size_t size = 0;

    if (pollist == NULL) {
        return 0;
    } 
    if (pollist->KeySignatureOffset != 0) {
        size = pollist->KeySignatureOffset +
        get_raw_tpm20_sig_2_1_size((const lcp_key_and_sig *) ((void *) pollist+pollist->KeySignatureOffset));
    }
    else {
        size = offsetof(lcp_policy_list_t2_1, PolicyElements) + pollist->PolicyElementsSize;
    }
    return size;
}


#endif    /*  __TXT_LCP3_HELPER_H__ */
