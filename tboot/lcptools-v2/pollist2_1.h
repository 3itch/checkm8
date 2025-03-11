/*
 * pollist2_1.h:
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

#ifndef __POLLIST2_1_H__
#define __POLLIST2_1_H__


extern uint16_t signature_alg;  //Set by user in CLI

//Useful offsets
#define SIG_REV_CNT_OFFSET         0x0
#define SIG_KEY_SIG_VER_OFFSET     0x2
#define SIG_KEY_SIG_KEY_ALG_OFFSET 0x3


typedef struct __packed {
    uint16_t  revoc_counter;
    uint8_t   version;
    uint16_t  key_alg;
    uint8_t   key_ver;
    uint16_t  key_size;
} sig_key_2_1_header;

unsigned char *fill_tpm20_policy_list_2_1_buffer(const lcp_policy_list_t2_1 *pollist,
                                                                   size_t *len);
size_t get_tpm20_list_2_1_real_size(const lcp_policy_list_t2_1 *pollist);
uint16_t get_signature_2_1_key_alg(const lcp_signature_2_1 *sig);
size_t get_tpm20_policy_list_2_1_size(const lcp_policy_list_t2_1 *pollist);
lcp_policy_list_t2_1 *read_policy_list_2_1_file(bool sign_it,
                                                  const char *list_file);
bool verify_tpm20_policy_list_2_1(const lcp_policy_list_t2_1 *pollist,
                                             size_t size, bool *has_sig);
void display_tpm20_policy_list_2_1(const char *prefix,
                        const lcp_policy_list_t2_1 *pollist, bool brief);
lcp_policy_list_t2_1 *create_empty_tpm20_policy_list_2_1(void);
lcp_policy_list_t2_1 *add_tpm20_policy_element_2_1(lcp_policy_list_t2_1
                              *pollist, const lcp_policy_element_t *elt);
bool verify_tpm20_pollist_2_1_sig(lcp_policy_list_t2_1 *pollist);
bool calc_tpm20_policy_list_2_1_hash(const lcp_policy_list_t2_1 *pollist,
                                   lcp_hash_t2 *hash, uint16_t hash_alg);
bool write_tpm20_policy_list_2_1_file(const char *file,
                                    const lcp_policy_list_t2_1 *pollist);
lcp_signature_2_1 *create_empty_ecc_signature_2_1(void);
lcp_signature_2_1 *create_empty_rsa_signature_2_1(void);
lcp_policy_list_t2_1 *get_policy_list_2_1_data(const void *raw_data, size_t base_size,
                                             uint16_t key_signature_offset);
bool sign_lcp_policy_list_t2_1(sign_user_input user_input);

#endif

/*
 * Local variables:
 * Global variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */