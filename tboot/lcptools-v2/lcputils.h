/*
 * lcputils.h: LCP utility fns
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

#ifndef __LCPUTILS_H__
#define __LCPUTILS_H__

#define MAJOR_VER(v)      ((v) >> 8)
#define MINOR_VER(v)      ((v) & 0xff)

#define ARRAY_SIZE(a)     (sizeof(a) / sizeof((a)[0]))

#define MAX_PATH           256

#include <openssl/evp.h>

//Helper struct to pass user input data to functions in pollist2 and pollist2_1
typedef struct sign_user_input {
    uint16_t sig_alg;
    uint16_t hash_alg;
    uint16_t rev_ctr;
    char list_file[MAX_PATH];
    char pubkey_file[MAX_PATH];
    char privkey_file[MAX_PATH];
} sign_user_input;

/*
This will hold various dynamic buffers like keys, sigs, digests and such.
*/
typedef struct sized_buffer {
    size_t size;
    unsigned char data[];
} sized_buffer;

extern bool verbose;

extern void ERROR(const char *fmt, ...);
extern void LOG(const char *fmt, ...);
extern void DISPLAY(const char *fmt, ...);

extern size_t strlcpy(char *dst, const char *src, size_t siz);

extern void print_hex(const char *prefix, const void *data, size_t n);
extern void parse_comma_sep_ints(char *s, uint16_t ints[],
                                 unsigned int *nr_ints);
extern void *read_file(const char *file, size_t *length, bool fail_ok);
extern bool write_file(const char *file, const void *data, size_t size);
extern bool parse_line_hashes(const char *line, tb_hash_t *hash, uint16_t alg);
extern bool parse_file(const char *filename, bool (*parse_line)(const char *line));
extern const char *hash_alg_to_str(uint16_t alg);
extern const char *key_alg_to_str(uint16_t alg);
extern const char *sig_alg_to_str(uint16_t alg);
extern sized_buffer *allocate_sized_buffer(size_t size);
uint16_t str_to_hash_alg(const char *str);
uint16_t str_to_lcp_hash_mask(const char *str);
uint16_t convert_hash_alg_to_mask(uint16_t hash_alg);
uint16_t str_to_sig_alg(const char *str);
uint32_t str_to_sig_alg_mask(const char *str, const uint16_t version, size_t size);
uint16_t str_to_pol_ver(const char *str);
size_t get_lcp_hash_size(uint16_t hash_alg);
extern void buffer_reverse_byte_order(uint8_t *buffer, size_t length);
extern bool ec_sign_data(sized_buffer *data, sized_buffer *r, sized_buffer *s, 
                    uint16_t hashalg, uint16_t sigalg, const char *privkey_file);
extern bool rsa_ssa_pss_sign(sized_buffer *sig_block, sized_buffer *data,
        uint16_t sig_alg, uint16_t hash_alg, EVP_PKEY_CTX *private_key_context);
bool verify_ec_signature(sized_buffer *data, sized_buffer *pubkey_x, 
                         sized_buffer *pubkey_y, sized_buffer *sig_r,
                         sized_buffer *sig_s, uint16_t sigalg, uint16_t hashalg);
bool verify_rsa_signature(sized_buffer *data, sized_buffer *pubkey, sized_buffer *signature,
                          uint16_t hashAlg, uint16_t sig_alg, uint16_t list_ver);
EVP_PKEY_CTX *rsa_get_sig_ctx(const char *key_path, uint16_t key_size_bytes);
unsigned char *der_encode_sig_comps(sized_buffer *sig_r, sized_buffer *sig_s, int *length);


#endif    /* __LCPUTILS_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
