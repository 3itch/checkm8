/*
 * hash.c: support functions for tb_hash_t type
 *
 * Copyright (c) 2020 Cisco Systems, Inc. <pmoore2@cisco.com>
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
#include <openssl/evp.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../../include/config.h"
#include "../../include/hash.h"

/*
 * are_hashes_equal
 *
 * compare whether two hash values are equal.
 *
 */
bool are_hashes_equal(const tb_hash_t *hash1, const tb_hash_t *hash2,
		      uint16_t hash_alg)
{
    int diff;
    if ( ( hash1 == NULL ) || ( hash2 == NULL ) )
        return false;

    if ( hash_alg == TB_HALG_SHA1 )
        return (memcmp_s(hash1, SHA1_LENGTH, hash2, SHA1_LENGTH, &diff) == 0 && diff == 0);
    else if ( hash_alg == TB_HALG_SHA256 )
        return (memcmp_s(hash1, SHA256_LENGTH, hash2, SHA256_LENGTH, &diff) == 0 && diff == 0);
    else if ( hash_alg == TB_HALG_SM3 )
        return (memcmp_s(hash1, SM3_LENGTH, hash2, SM3_LENGTH, &diff) == 0 && diff == 0);
    else if ( hash_alg == TB_HALG_SHA384 )
        return (memcmp_s(hash1, SHA384_LENGTH, hash2, SHA384_LENGTH, &diff) == 0 && diff == 0);
    else if ( hash_alg == TB_HALG_SHA512 )
        return (memcmp_s(hash1, SHA512_LENGTH, hash2, SHA512_LENGTH, &diff) == 0 && diff == 0);
    else
        return false;
}

/*
 * hash_buffer
 *
 * hash the buffer according to the algorithm
 *
 */
bool hash_buffer(const unsigned char* buf, size_t size, tb_hash_t *hash,
		 uint16_t hash_alg)
{
    if ( hash == NULL )
        return false;

    if ( hash_alg == TB_HALG_SHA1 || hash_alg == TB_HALG_SHA1_LG ) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        const EVP_MD *md;

        md = EVP_sha1();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha1, NULL);
        EVP_MD_CTX_destroy(ctx);
        return true;
    }
    else if (hash_alg == TB_HALG_SHA256) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        const EVP_MD *md;

        md = EVP_sha256();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha256, NULL);
        EVP_MD_CTX_destroy(ctx);
        return true;
    }
    else if (hash_alg == TB_HALG_SHA384) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        const EVP_MD *md;

        md = EVP_sha384();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha384, NULL);
        EVP_MD_CTX_destroy(ctx);
        return true;
    }
    else if (hash_alg == TB_HALG_SHA512) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        const EVP_MD *md;

        md = EVP_sha512();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha512, NULL);
        EVP_MD_CTX_destroy(ctx);
        return true;
    }
    else if (hash_alg == TB_HALG_SM3) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        const EVP_MD *md;
        md = EVP_sm3();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sm3, NULL);
        EVP_MD_CTX_destroy(ctx);
        return true;
    }
    else
        return false;
}

/*
 * extend_hash
 *
 * perform "extend" of two hashes (i.e. hash1 = SHA(hash1 || hash2)
 *
 */
bool extend_hash(tb_hash_t *hash1, const tb_hash_t *hash2, uint16_t hash_alg)
{
    uint8_t buf[2*sizeof(tb_hash_t)];

    if ( hash1 == NULL || hash2 == NULL )
        return false;

    if ( hash_alg == TB_HALG_SHA1 ) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        const EVP_MD *md;

        memcpy_s(buf, sizeof(buf), &(hash1->sha1), sizeof(hash1->sha1));
        memcpy_s(buf + sizeof(hash1->sha1), sizeof(buf) - sizeof(hash1->sha1),
                 &(hash2->sha1), sizeof(hash1->sha1));
        md = EVP_sha1();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, 2*sizeof(hash1->sha1));
        EVP_DigestFinal(ctx, hash1->sha1, NULL);
        EVP_MD_CTX_destroy(ctx);
        return true;
    }
    else
        return false;
}

void print_hash(const tb_hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL )
        return;

    if ( hash_alg == TB_HALG_SHA1 ) {
        for ( unsigned int i = 0; i < SHA1_LENGTH; i++ ) {
            printf("%02x", hash->sha1[i]);
            if ( i < SHA1_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else if ( hash_alg == TB_HALG_SHA256 ) {
        for ( unsigned int i = 0; i < SHA256_LENGTH; i++ ) {
            printf("%02x", hash->sha256[i]);
            if ( i < SHA256_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else if ( hash_alg == TB_HALG_SHA384 ) {
        for ( unsigned int i = 0; i < SHA384_LENGTH; i++ ) {
            printf("%02x", hash->sha384[i]);
            if ( i < SHA384_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else if ( hash_alg == TB_HALG_SHA512 ) {
        for ( unsigned int i = 0; i < SHA512_LENGTH; i++ ) {
            printf("%02x", hash->sha512[i]);
            if ( i < SHA512_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else if ( hash_alg == TB_HALG_SM3) {
        for ( unsigned int i = 0; i < SM3_LENGTH; i++ ) {
            printf("%02x", hash->sm3[i]);
            if ( i < SM3_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else
        return;
}

/*
 * import a hash in the format "755567de6e0a3ee1b71a895b76..."
 */
bool import_hash(const char *string, tb_hash_t *hash, uint16_t alg)
{
    size_t hash_len = get_hash_size(alg);
    size_t string_len = strnlen(string, hash_len * 2 + 1);
    unsigned int iter_a, iter_b;
    char byte[3] = {0, 0, 0};

    for (iter_a = 0, iter_b = 0;
         iter_a < string_len && iter_b <= hash_len;
         iter_a += 2, iter_b++) {
        memcpy_s(byte, sizeof(byte), &string[iter_a], 2);
        hash->sha512[iter_b] = strtol(byte, NULL, 16);
    }
    if (iter_a != string_len || iter_b != hash_len)
        return false;

    return true;
}

void copy_hash(tb_hash_t *dest_hash, const tb_hash_t *src_hash,
               uint16_t hash_alg)
{
    if ( dest_hash == NULL || src_hash == NULL )
        return;

    if ( hash_alg == TB_HALG_SHA1 )
        memcpy_s(dest_hash, SHA1_LENGTH, src_hash, SHA1_LENGTH);
    else
        return;
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
