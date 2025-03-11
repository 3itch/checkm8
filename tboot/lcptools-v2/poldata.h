/*
 * poldata.h:
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

#ifndef __POLDATA2_H__
#define __POLDATA2_H__

extern size_t list_21_sizes[LCP_MAX_LISTS];

extern size_t get_policy_data_size(const lcp_policy_data_t2 *poldata);
extern bool verify_policy_data(const lcp_policy_data_t2 *poldata, size_t size);
extern void display_policy_data(const char *prefix,
                                const lcp_policy_data_t2 *poldata, bool brief);

extern lcp_policy_data_t2 *add_tpm12_policy_list(lcp_policy_data_t2 *poldata,
                                          const lcp_policy_list_t *pollist);

extern lcp_policy_data_t2 *add_tpm20_policy_list(lcp_policy_data_t2 *poldata,
                                          const lcp_policy_list_t2 *pollist);

extern lcp_policy_data_t2 *add_tpm20_policy_list2_1(lcp_policy_data_t2 *poldata,
                        size_t *list_size, const lcp_policy_list_t2_1 *pollist);

extern void calc_policy_data_hash(const lcp_policy_data_t2 *poldata,
                                  lcp_hash_t2 *hash, uint16_t hash_alg);


#endif    /* __POLDATA_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
