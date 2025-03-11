/*
 * lcputils.c: misc. LCP helper fns
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
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    #include <openssl/core.h>
    #include <openssl/decoder.h>
    #include <openssl/crypto.h>
    #include <openssl/param_build.h>
#endif
#include <safe_lib.h>
#include <snprintf_s.h>
#define PRINT   printf
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/uuid.h"
#include "../../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist2.h"

static uint16_t pkcs_get_hashalg(const unsigned char *data);

void ERROR(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void LOG(const char *fmt, ...)
{
    va_list ap;

    if ( verbose ) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

void DISPLAY(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    strcpy_s(dst, siz, src);
    return strnlen_s(dst, siz);
}

void print_hex(const char *prefix, const void *data, size_t n)
{
#define NUM_CHARS_PER_LINE 20
    unsigned int i = 0;
    while ( i < n ) {
        if ( i % NUM_CHARS_PER_LINE == 0 && prefix != NULL ) {
            DISPLAY("%s", prefix);
        }
        DISPLAY("%02x ", *(uint8_t *)data++);
        i++;
        if ( i % NUM_CHARS_PER_LINE == 0 ) {
            DISPLAY("\n");
        }
    }
    if ( i % NUM_CHARS_PER_LINE != 0 ) {
        DISPLAY("\n");
    }
}

void parse_comma_sep_ints(char *s, uint16_t ints[], unsigned int *nr_ints)
{
    unsigned int nr = 0;

    while ( true ) {
        char *str = strsep(&s, ",");
        if ( str == NULL || nr == *nr_ints )
            break;
        ints[nr++] = strtoul(str, NULL, 0);
    }
    *nr_ints = nr;
    return;
}

void *read_file(const char *file, size_t *length, bool fail_ok)
{
    LOG("[read_file]\n");
    LOG("read_file: filename=%s\n", file);
    FILE *fp = fopen(file, "rb");
    if ( fp == NULL ) {
        if ( !fail_ok )
            ERROR("Error: failed to open file %s: %s\n", file,
                    strerror(errno));
        return NULL;
    }

    /* find size */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len <= 0) {
        ERROR("Error: failed to get file length or file is empty.\n");
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    void *data = malloc(len);
    if ( data == NULL ) {
        ERROR("Error: failed to allocate %d bytes memory\n", len);
        fclose(fp);
        return NULL;
    }

    if ( fread(data, len, 1, fp) != 1 ) {
        ERROR("Error: reading file %s\n", file);
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    if ( length != NULL )
        *length = len;
    LOG("read file succeed!\n");
    return data;
}

bool write_file(const char *file, const void *data, size_t size)
{
    LOG("[write_file]\n");
    FILE *fp = fopen(file, "wb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s for writing: %s\n",
                file, strerror(errno));
        return false;
    }
    if ( fwrite(data, size, 1, fp) != 1 ) {
        ERROR("Error: writing file %s\n", file);
        fclose(fp);
        return false;
    }
    fclose(fp);
    LOG("write file succeed!\n");
    return true;
}

bool parse_line_hashes(const char *line, tb_hash_t *hash, uint16_t alg)
{
    /* skip any leading whitespace */
    while ( *line != '\0' && isspace(*line) )
        line++;

    /* rest of line is hex of hash */
    unsigned int i = 0;
    while ( *line != '\0' && *line != '\n' ) {
        char *next;
        switch (alg) {
        case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA1:
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA256:
            hash->sha256[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA384:
            hash->sha384[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        default:
            ERROR("Error: unsupported alg: 0x%x\n",alg);
            return false;
        }
        if ( next == line )      /* done */
            break;
        line = next;
        /* spaces at end cause strtoul() to interpret as 0, so skip them */
        while ( *line != '\0' && !isxdigit(*line) )
            line++;
    }

    if ( i != get_hash_size(alg) ) {
        ERROR("Error: incorrect number of chars for hash\n");
        return false;
    }

    return true;
}

bool parse_file(const char *filename, bool (*parse_line)(const char *line))
{
    if ( filename == NULL || parse_line == NULL )
        return false;

    LOG("reading hashes file %s...\n", filename);

    FILE *fp = fopen(filename, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s (%s)\n", filename, strerror(errno));
        return false;
    }

    static char line[1024];
    while ( true ) {
        char *s = fgets(line, sizeof(line), fp);

        if ( s == NULL ) {
            fclose(fp);
            return true;
        }

        LOG("read line: %s\n", line);

        if ( !(*parse_line)(line) ) {
            fclose(fp);
            return false;
        }
    }

    fclose(fp);
    return false;
}

const char *hash_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_SHA1:
        return "TPM_ALG_SHA1";
    case TPM_ALG_SHA256:
        return "TPM_ALG_SHA256";
    case TPM_ALG_SHA384:
        return "TPM_ALG_SHA384";
    case TPM_ALG_SHA512:
        return "TPM_ALG_SHA512";
    case TPM_ALG_SM3_256:
        return "TPM_ALG_SM3_256";
    case TPM_ALG_SM2:
        return "TPM_ALG_SM2";
    case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
        return "LCP_POLHALG_SHA1";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

const char *key_alg_to_str(uint16_t alg)
{
    switch (alg)
    {
    case TPM_ALG_RSA:
        return "TPM_ALG_RSA";
    case TPM_ALG_ECC:
        return "TPM_ALG_ECC";
    default:
        return "";
    }
}

const char *sig_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_RSASSA:
        return "TPM_ALG_RSASSA";
    case TPM_ALG_ECDSA:
        return "TPM_ALG_ECDSA";
    case TPM_ALG_SM2:
        return "TPM_ALG_SM2";
    case TPM_ALG_RSAPSS:
        return "TPM_ALG_RSAPSS";
    case TPM_ALG_SM3_256:
        return "TPM_ALG_SM3_256";
    case TPM_ALG_NULL:
        return "TPM_ALG_NULL";
    case LCP_POLSALG_RSA_PKCS_15:
        return "LCP_POLSALG_RSA_PKCS_15";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

uint16_t str_to_hash_alg(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_SM3_256;
    else
        return  TPM_ALG_NULL;
}

uint16_t str_to_lcp_hash_mask(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_MASK_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_MASK_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_MASK_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_MASK_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_MASK_SM3_256;
    else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2))
        return strtoul(str, NULL, 0);
    else
        return  TPM_ALG_MASK_NULL;
}

uint16_t str_to_sig_alg(const char *str) {
    if (strcmp(str,"rsa-pkcs15") == 0)
        return LCP_POLSALG_RSA_PKCS_15;
    if( strcmp(str,"rsa-ssa") == 0 || strcmp(str,"rsassa") == 0 || strcmp(str,"rsa") == 0  )
        return TPM_ALG_RSASSA;
    if ( strcmp(str,"ecdsa") == 0)
        return TPM_ALG_ECDSA;
    if ( strcmp(str,"sm2") == 0)
        return TPM_ALG_SM2;
    if( strcmp(str,"rsa-pss") == 0 || strcmp(str,"rsapss") == 0 )
        return TPM_ALG_RSAPSS;
    else {
        LOG("Unrecognized signature alg, assuming TPM_ALG_NULL");
        return TPM_ALG_NULL;
    }
}

uint32_t str_to_sig_alg_mask(const char *str, const uint16_t version, size_t size)
{
    uint16_t lcp_major_ver = version & 0xFF00;
    if( lcp_major_ver == LCP_VER_2_0 ) {
        //signature algorithm mask is undefined in LCPv2
        return SIGN_ALG_MASK_NULL;
    }
    else if( lcp_major_ver == LCP_VER_3_0 ) {
        if (strncmp(str, "rsa-2048-sha1", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_2048_SHA1;
        }
        else if (strncmp(str, "rsa-2048-sha256", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_2048_SHA256;
        }
        else if (strncmp(str, "rsa-3072-sha256", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_3072_SHA256;
        }
        else if (strncmp(str, "rsa-3072-sha384", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_3072_SHA384;
        }
        else if (strncmp(str, "ecdsa-p256", size) == 0) {
            return SIGN_ALG_MASK_ECDSA_P256;
        }
        else if (strncmp(str, "ecdsa-p384", size) == 0) {
            return SIGN_ALG_MASK_ECDSA_P384;
        }
        else if (strncmp(str, "sm2", size) == 0) {
            return SIGN_ALG_MASK_SM2;
        }
        else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2)){
            return strtoul(str, NULL, 0);
        }
        else{
            //Format unrecognized
            return SIGN_ALG_MASK_NULL;
        }
    }
    else
        return SIGN_ALG_MASK_NULL;
}
uint16_t str_to_pol_ver(const char *str)
{
    if( strcmp(str,"2.0") == 0)
       return LCP_VER_2_0;
    else if ( strcmp(str,"2.1") == 0)
        return LCP_VER_2_1;
    else if ( strcmp(str,"2.2") == 0)
        return LCP_VER_2_2;
    else if ( strcmp(str,"2.3") == 0)
        return LCP_VER_2_3;
    else if ( strcmp(str,"2.4") == 0)
        return LCP_VER_2_4;
    else if ( strcmp(str,"3.0") == 0)
        return LCP_VER_3_0;
    else if ( strcmp(str,"3.1") == 0)
        return LCP_VER_3_1;
    else if ( strcmp(str, "3.2") == 0)
        return LCP_VER_3_2;
    else
        return LCP_VER_NULL;
}

uint16_t convert_hash_alg_to_mask(uint16_t hash_alg)
{
    LOG("convert_hash_alg_to_mask hash_alg = 0x%x\n", hash_alg);
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return TPM_ALG_MASK_SHA1;
    case TPM_ALG_SHA256:
        return TPM_ALG_MASK_SHA256;
    case TPM_ALG_SHA384:
        return TPM_ALG_MASK_SHA384;
    case TPM_ALG_SHA512:
        return TPM_ALG_MASK_SHA512;
    case TPM_ALG_SM3_256:
        return TPM_ALG_MASK_SM3_256;
    default:
        return 0;
    }
    return 0;
}

size_t get_lcp_hash_size(uint16_t hash_alg)
{
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256:
        return SHA256_DIGEST_SIZE;
    case TPM_ALG_SHA384:
        return SHA384_DIGEST_SIZE;
    case TPM_ALG_SHA512:
        return SHA512_DIGEST_SIZE;
    case TPM_ALG_SM3_256:
        return SM3_256_DIGEST_SIZE;
    case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
        return SHA1_DIGEST_SIZE;
    default:
        return 0;
    }
    return 0;
}

bool verify_rsa_signature(sized_buffer *data, sized_buffer *pubkey, sized_buffer *signature,
                          uint16_t hashAlg, uint16_t sig_alg, uint16_t list_ver)
/*
This function: verifies policy list's rsapss and rsassa signatures using pubkey

In: Data - pointer to sized buffer with signed LCP policy list contents:
    LCP_POLICY_LIST2_1 - entire list up to KeyAndSignature field (that includes
    RevoCation counter) i.e. KeyAndSignatureOffset bytes of data from the list.
    LCP_POLICY_LIST and LCP_POLICY_LIST2 - entire list minus the signature field.

    pubkey - pointer to sized buffer containing public key in BE form
    signature - pointer to sized buffer containing signature in BE form

    hashAlg - LCP_SIGNATURE2_1->RsaKeyAndSignature.Signature.HashAlg i.e. hash
              alg defined for the list signature. Or TPM_HASHALG_NULL if hashalg
              is not a member of list structure (it will be read from signature)
    sig_alg - signature algorithm of the list
    list_ver - specify list version: LCP_POLICY_LIS, LCP_POLICY_LIST2 or 
    LCP_POLICY_LIST2_1

Out: true/false on verification success or failure
*/
{
    int status;
    EVP_PKEY_CTX *evp_context = NULL;
    EVP_PKEY *evp_key = NULL;
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;
    tb_hash_t *digest = NULL;
    unsigned char exp_arr[] = {0x01, 0x00, 0x01};
    unsigned char *decrypted_sig = NULL;
    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        size_t dcpt_sig_len;
    #else
        RSA *rsa_pubkey = NULL;
    #endif

    LOG("[verify_rsa_signature]\n");
    if (data == NULL || pubkey == NULL || signature == NULL) {
        ERROR("Error: list data, pubkey or signature buffer not defined.\n");
        return false;
    }
    
    modulus = BN_bin2bn(pubkey->data, pubkey->size, NULL);
    exponent = BN_bin2bn(exp_arr, 3, NULL);
    if ( modulus == NULL || exponent == NULL ) {
        ERROR("Error: failed to convert modulus and/or exponent.\n");
        goto OPENSSL_ERROR;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        evp_context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if ( evp_context == NULL) {
            ERROR("Error: failed to initialize CTX from name.\n");
            goto OPENSSL_ERROR;
        }    

        OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();
        if ( params_build == NULL ) {
            ERROR("Error: failed to set up parameter builder.\n");
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_PARAM_BLD_push_BN(params_build, "n", modulus) ) {
            ERROR("Error: failed to push modulus into param build.\n");
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_PARAM_BLD_push_BN(params_build, "e", exponent) ) {
            ERROR("Error: failed to push exponent into param build.\n");
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_PARAM_BLD_push_BN(params_build, "d", NULL) ) {
            ERROR("Error: failed to push NULL into param build.\n");
            goto OPENSSL_ERROR;
        }

        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(params_build);
        if ( params == NULL ) {
            ERROR("Error: failed to construct parameters from builder.\n");
            goto OPENSSL_ERROR;
        }

        if ( EVP_PKEY_fromdata_init(evp_context) <= 0 ) {
            ERROR("Error: failed to initialize key creation.\n");
            goto OPENSSL_ERROR;
        }

        if ( EVP_PKEY_fromdata(evp_context, &evp_key, EVP_PKEY_PUBLIC_KEY, params) <= 0 ) {
            ERROR("Error: failed to create key.\n");
            goto OPENSSL_ERROR;
        }
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(params_build);
        EVP_PKEY_CTX_free(evp_context);
        evp_context = NULL;
    #else
        rsa_pubkey = RSA_new();
        if ( rsa_pubkey == NULL ) {
            ERROR("Error: failed to allocate key\n");
            status = 0;
            goto EXIT;
        }

        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_set0_key(rsa_pubkey, modulus, exponent, NULL);
        #else
            rsa_pubkey->n = modulus;
            rsa_pubkey->e = exponent;
            rsa_pubkey->d = rsa_pubkey->p = rsa_pubkey->q = NULL;
        #endif
    #endif

    if (MAJOR_VER(list_ver) != MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300)) {
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L

            evp_context = EVP_PKEY_CTX_new(evp_key, NULL);
            if ( evp_context == NULL ) {
                ERROR("Error: failed to instatiate CTX.\n");
                goto OPENSSL_ERROR;
            }
            if ( EVP_PKEY_encrypt_init(evp_context) <= 0 ) {
                ERROR("Error: failed to initialize signature decryption.\n");
                goto OPENSSL_ERROR;
            }
            if ( EVP_PKEY_CTX_set_rsa_padding(evp_context, RSA_NO_PADDING) <= 0 ) {
                ERROR("Error: failed to set RSA padding.\n");
                goto OPENSSL_ERROR;
            }
            if ( EVP_PKEY_encrypt(evp_context, NULL, &dcpt_sig_len, signature->data, pubkey->size) <= 0 ) {
                ERROR("Error: failed to retrieve decrypted signature length.\n");
                goto OPENSSL_ERROR;
            }
            decrypted_sig = OPENSSL_malloc(dcpt_sig_len);
            if ( decrypted_sig == NULL ) {
                ERROR("Error: failed to allocate memory for decrypted signature.\n");
                status = 0;
                goto EXIT;
            }
            if ( EVP_PKEY_encrypt(evp_context, decrypted_sig, &dcpt_sig_len, signature->data, pubkey->size) <= 0 ) {
                ERROR("Error: failed to decrypt signature.\n");
                goto OPENSSL_ERROR;
            }
            if ( verbose ) {
                LOG("Decrypted signature: \n");
                print_hex("", decrypted_sig, dcpt_sig_len);
            }
            EVP_PKEY_CTX_free(evp_context);
            evp_context = NULL;
        #else
            decrypted_sig = OPENSSL_malloc(pubkey->size);
            status = RSA_public_decrypt(pubkey->size, signature->data, decrypted_sig, rsa_pubkey, RSA_NO_PADDING);
            if (status <= 0) {
                ERROR("Error: failed to decrypt signature.\n");
                goto OPENSSL_ERROR;
            }
            if ( verbose ) {
                LOG("Decrypted signature: \n");
                print_hex("", decrypted_sig, pubkey->size);
            }
        #endif
        //In older lists we need to get hashAlg from signature data.
        hashAlg = pkcs_get_hashalg((const unsigned char *) decrypted_sig);
        OPENSSL_free((void *) decrypted_sig);
    }

    #if OPENSSL_VERSION_NUMBER < 0x30000000L
        evp_key = EVP_PKEY_new();
        if ( evp_key == NULL) {
            goto OPENSSL_ERROR;
        }

        status = EVP_PKEY_set1_RSA(evp_key, rsa_pubkey);
        if (status <= 0) {
            goto OPENSSL_ERROR;
        }
    #endif

    evp_context = EVP_PKEY_CTX_new(evp_key, NULL);
    if ( evp_context == NULL ) {
        ERROR("Error: failed to initialize CTX from pkey.\n");
        goto OPENSSL_ERROR;
    }

    if ( EVP_PKEY_verify_init(evp_context) <= 0) {
        ERROR("Error: failed to initialize verification.");
        goto OPENSSL_ERROR;
    }

    if ( sig_alg == TPM_ALG_RSAPSS)
        status = EVP_PKEY_CTX_set_rsa_padding(evp_context, RSA_PKCS1_PSS_PADDING);
    else if (sig_alg == TPM_ALG_RSASSA || sig_alg == LCP_POLSALG_RSA_PKCS_15)
        status = EVP_PKEY_CTX_set_rsa_padding(evp_context, RSA_PKCS1_PADDING);
    else {
        ERROR("Error: unsupported signature algorithm.\n");
        status = 0;
        goto EXIT;
    }
    if ( status <= 0) {
        ERROR("Error: failed to set rsa padding.\n");
        goto OPENSSL_ERROR;
    }

    if ( hashAlg == TPM_ALG_SHA1 ) {
        status = EVP_PKEY_CTX_set_signature_md(evp_context, EVP_sha1());
    } else if ( hashAlg == TPM_ALG_SHA256 ) {
        status = EVP_PKEY_CTX_set_signature_md(evp_context, EVP_sha256());
    } else if ( hashAlg == TPM_ALG_SHA384 ) {
        status = EVP_PKEY_CTX_set_signature_md(evp_context, EVP_sha384());
    } else {
        ERROR("Error: Unknown hash alg.\n");
        status = 0;
        goto EXIT;
    }
    if ( status <= 0 ) {
        ERROR("Error: failed to set signature message digest.\n");
        goto OPENSSL_ERROR;
    }
    
    digest = malloc(get_lcp_hash_size(hashAlg));
    if (digest == NULL) {
        ERROR("Error: failed to allocate digest");
        status = 0;
        goto EXIT;
    }
    if ( !hash_buffer((const unsigned char *) data->data, data->size, digest, hashAlg) ) {
        ERROR("Error: failed to hash list contents.\n");
        status = 0;
        goto EXIT;
    }
    status = EVP_PKEY_verify(evp_context, signature->data, pubkey->size, (const unsigned char *) digest, get_lcp_hash_size(hashAlg));
    if (status < 0) { //Error occurred
        goto OPENSSL_ERROR;
    }
    else { //EVP_PKEY_verify executed successfully
        goto EXIT;
    }
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        status = 0;
    EXIT:
        #if OPENSSL_VERSION_NUMBER < 0x30000000L
            if (rsa_pubkey != NULL)
                OPENSSL_free((void *) rsa_pubkey);
        #endif
        if (evp_context != NULL)
            OPENSSL_free((void *) evp_context);
        if (evp_key != NULL)
            OPENSSL_free((void *) evp_key);
        if (modulus != NULL)
            OPENSSL_free((void *) modulus);
        if (exponent != NULL)
            OPENSSL_free((void *) exponent);
        if (digest != NULL)
            free(digest);
        return status ? true : false;
}

bool verify_ec_signature(sized_buffer *data, sized_buffer *pubkey_x, 
                         sized_buffer *pubkey_y, sized_buffer *sig_r,
                         sized_buffer *sig_s, uint16_t sigalg, uint16_t hashalg)
{
     /*
    This function: verifies ecdsa or SM2 signature using pubkey (lists 2.0 and 2.1 only!)

    In: Data - LCP policy list contents:

    LCP_LIST_2_1: entire list up to KeyAndSignature field (that includes 
        RevoCation counter) i.e. hash of KeyAndSignatureOffset bytes of the list.

    LCP_LIST_2: entire list up to the r member of the Signature field that is 
                sizeof list - 2 * keysize

    sized_buffers:
    pubkey_x - public key x coordinate (must be BE) 
    pubkey_y - public key y coordinate (must be BE)
    sig_r and sig_s - buffers containing signature bytes BE

    sigalg - signature algorithm used to sign list (must be ecdsa or sm2)
    hashAlg - hash algorithm used to create digest

    Out: true/false on verification success or failure
*/
    int result;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EVP_PKEY *evp_key = NULL;
    const EVP_MD *mdtype;
    const unsigned char *der_encoded_sig = NULL;
    int encoded_len;
    int curveId = 0;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    #if OPENSSL_VERSION_NUMBER >= 0x30000000L  
        const EC_GROUP *ec_group = NULL;
        EC_POINT *ec_point = NULL;
        unsigned char *point_buffer = NULL;
        size_t pt_buf_len;
        BN_CTX *bctx = NULL;
        const char *curveName = NULL;
    #else
        EC_KEY *ec_key = NULL;
        EC_GROUP *ec_group = NULL;
    #endif
    
    LOG("[verify_ec_signature]\n");
    if ( data == NULL || pubkey_x == NULL || pubkey_y == NULL || sig_r == NULL || sig_s == NULL ) {
        ERROR("Error: one or more buffers are not defined.\n");
        return false;
    }
    
    if ( hashalg == TPM_ALG_SM3_256 ) {
        curveId = NID_sm2;
        mdtype = EVP_sm3();
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            curveName = SN_sm2;
        #endif
    } else if ( hashalg == TPM_ALG_SHA256 ) {
        curveId = NID_secp256k1;
        mdtype = EVP_sha256();
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            curveName = SN_secp256k1;
        #endif
    } else if ( hashalg == TPM_ALG_SHA384 ) {
        curveId = NID_secp384r1;
        mdtype = EVP_sha384();
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            curveName = SN_secp384r1;
        #endif
    } else {
        ERROR("Error: unsupported hashalg.\n");
        result = 0;
        goto EXIT;
    }

    ec_group = EC_GROUP_new_by_curve_name(curveId);
    if ( ec_group == NULL ) {
        ERROR("Error: failed to create new EC group.\n");
        goto OPENSSL_ERROR;
    }

    x = BN_bin2bn(pubkey_x->data, pubkey_x->size, NULL);
    y = BN_bin2bn(pubkey_y->data, pubkey_y->size, NULL);
    if ( x == NULL || y == NULL ) {
        ERROR("Error: Failed to convert binary pubkey to BIGNUM x and/or y.\n");
        goto OPENSSL_ERROR;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        ec_point = EC_POINT_new(ec_group);
        if ( ec_point == NULL ) {
            ERROR("Error: failed to create new EC point.\n");
            goto OPENSSL_ERROR;
        }

        bctx = BN_CTX_new();
        if ( bctx == NULL ) {
            ERROR("Error: Failed to create BIGNUM context.\n");
            goto OPENSSL_ERROR;
        }
        
        if ( EC_POINT_set_affine_coordinates(ec_group, ec_point, x, y, bctx) <= 0 ) {
            ERROR("Error: failed to set affine coordinates.\n");
            goto OPENSSL_ERROR;
        }
        
        BN_CTX_free(bctx);
        bctx = NULL;
        bctx = BN_CTX_new();

        pt_buf_len = EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL, 0, bctx);
        point_buffer = OPENSSL_malloc(pt_buf_len);
        if ( point_buffer == NULL ) {
            ERROR("Error: failed to allocate point buffer.\n");
            goto OPENSSL_ERROR;
        }

        if ( EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, point_buffer, pt_buf_len, bctx) <= 0 ) {
            ERROR("Error: failed to convert EC point into octal string.\n");
            goto OPENSSL_ERROR;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if ( ctx == NULL ) {
            ERROR("Error: failed to initialize key creation CTX.\n");
            goto OPENSSL_ERROR;
        }

        OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();
        if ( params_build == NULL ) {
            ERROR("Error: failed to set up parameter builder.\n");
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_PARAM_BLD_push_utf8_string(params_build, "group", curveName, 0) ) {
            ERROR("Error: failed to push group into param build.\n");
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_PARAM_BLD_push_octet_string(params_build, "pub", point_buffer, pt_buf_len) ) {
            ERROR("Error: failed to push pubkey into param build.\n");
            goto OPENSSL_ERROR;
        }
        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(params_build);
        if ( params == NULL ) {
            ERROR("Error: failed to construct params from build.\n");
            goto OPENSSL_ERROR;
        }

        if ( EVP_PKEY_fromdata_init(ctx) <= 0 ) {
            ERROR("ERROR: failed to initialize key creation from data.\n");
            goto OPENSSL_ERROR;
        }
        if ( EVP_PKEY_fromdata(ctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            ERROR("Error: failed to create EC_KEY.\n");
            result = 0;
            goto EXIT;
        }
        OSSL_PARAM_BLD_free(params_build);
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(ctx);
        BN_CTX_free(bctx);
    #else
        ec_key = EC_KEY_new();
        if (ec_key == NULL) {
            ERROR("Error: failed to generate EC_KEY.\n");
            result = 0;
            goto EXIT;
        }
        evp_key = EVP_PKEY_new();
        if (evp_key == NULL) {
            ERROR("Error: failed to generate EC_KEY.\n");
            result = 0;
            goto EXIT;
        }
        if ( EC_KEY_set_group(ec_key, ec_group) <= 0) {
            ERROR("Failed to set EC Key group.\n");
            goto OPENSSL_ERROR;
        }
        if ( EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) <= 0) {
            ERROR("Failed to set key coordinates.\n");
            goto OPENSSL_ERROR;
        }
        
        if ( EVP_PKEY_assign_EC_KEY(evp_key, ec_key) <= 0) {
            ERROR("Error: failed to assign EC KEY to EVP structure.\n");
            goto OPENSSL_ERROR;
        }
        if (sigalg == TPM_ALG_SM2) {
            if ( EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2) <= 0 ) {
                ERROR("Error: failed to set EVP KEY alias to SM2.\n");
                goto OPENSSL_ERROR;
            }
        }
    #endif

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        ERROR("Error: failed to generate message digest context.\n");
        result = 0;
        goto EXIT;
    }
    pctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (pctx == NULL) {
        ERROR("Error: failed to generate key context.\n");
        result = 0;
        goto EXIT;
    }
    if (sigalg == TPM_ALG_SM2) {
        if ( EVP_PKEY_CTX_set1_id(pctx, SM2_ID, SM2_ID_LEN) <= 0 ) {
            ERROR("Error: failed to set sm2 id.\n");
            goto OPENSSL_ERROR;
        }
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    der_encoded_sig = der_encode_sig_comps(sig_r, sig_s, &encoded_len);
    if (der_encoded_sig == NULL) {
        ERROR("Error: failed to DER encode signature components.\n");
        result = 0;
        goto EXIT;
    }
    if ( EVP_DigestVerifyInit(mctx, NULL, mdtype, NULL, evp_key) <= 0 ) {
        ERROR("Error: error while verifying (init).\n");
        goto OPENSSL_ERROR;
    }
    if ( verbose ) {
        LOG("Data that was signed:\n");
        print_hex("    ", data->data, data->size);
    }
    if ( EVP_DigestVerifyUpdate(mctx, data->data, data->size) <= 0) {
        ERROR("Error: error while verifying (update).\n");
        goto OPENSSL_ERROR;
    }
    result = EVP_DigestVerifyFinal(mctx, der_encoded_sig, encoded_len);
    if (result < 0) {
        ERROR("Error: error while verifying (final)\tError code = %d.\n", result);
        goto OPENSSL_ERROR;
    }
    goto EXIT;
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n",ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        result = 0;
    EXIT:
    //cleanup:
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            if (ec_point != NULL) {
                OPENSSL_free((void *) ec_point);
            }
            if (point_buffer != NULL) {
                OPENSSL_free((void *) point_buffer);
            }
        #else
            if (ec_key != NULL) {
                OPENSSL_free((void *) ec_key);
            }
        #endif
        if (ec_group != NULL) {
            OPENSSL_free((void *) ec_group);
        }
        if (evp_key != NULL) {
            OPENSSL_free((void *) evp_key);
        }
        if (x != NULL) {
            OPENSSL_free((void *) x);
        }
        if (y != NULL) {
            OPENSSL_free((void *) y);
        }
        if (der_encoded_sig != NULL) {
            OPENSSL_free((void *) der_encoded_sig);
        }
        if (mctx != NULL) {
            OPENSSL_free(mctx);
        }
        if (pctx != NULL) {
            OPENSSL_free(pctx);
        }
        return result ? true : false;
}

bool ec_sign_data(sized_buffer *data, sized_buffer *r, sized_buffer *s, uint16_t sigalg,
                                        uint16_t hashalg, const char *privkey_file)
{
    /*
    This function: Performs the signing operation on the policy list data 
    using OpenSSL SM2 and ECDSA functions.

    In: pointer to data to sign, pointers to buffers for r and s parts (must be BE),
    sigalg to use (must be TPM_ALG_SM2/ECDSA), hashalg (must be 
    TPM_ALG_SHA256/SHA384/SM3_256) path to private key.

    Out: True on success, false on failure
    */
    int result;
    size_t sig_length;
    EVP_PKEY *evp_key = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    FILE *fp = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *sig_r = NULL; //Is freed when ECDSA_SIG is freed
    const BIGNUM *sig_s = NULL; //Is freed when ECDSA_SIG is freed
    const unsigned char *signature_block = NULL;
    #if OPENSSL_VERSION_NUMBER < 0x30000000L
        EC_KEY *ec_key = NULL;
    #endif

    LOG("[ec_sign_data]\n");
    if (data == NULL || r == NULL || s == NULL) {
        ERROR("Error: one or more data buffers not defined.\n");
        return false;
    }
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        ERROR("Error: failed to allocate message digest context.\n");
        goto OPENSSL_ERROR;
    }
    fp = fopen(privkey_file, "rb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s: %s\n", privkey_file, strerror(errno));
        result = 0;
        goto EXIT;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        OSSL_DECODER_CTX *dctx;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&evp_key, "PEM", NULL, "EC", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
        if ( dctx == NULL ) {
            goto OPENSSL_ERROR;
        }
        if ( !OSSL_DECODER_from_fp(dctx, fp) ) {
            goto OPENSSL_ERROR;
        }
        OSSL_DECODER_CTX_free(dctx);
    #else
        ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
        if (ec_key == NULL) {
            ERROR("Error: failed to allocate EC key.\n");
            goto OPENSSL_ERROR;
        }
        evp_key = EVP_PKEY_new();
        if (evp_key == NULL) {
            ERROR("Error: failed to allocate EVP key.\n");
            goto OPENSSL_ERROR;
        }
        result = EVP_PKEY_assign_EC_KEY(evp_key, ec_key);
        if (result <= 0) {
            ERROR("Error: failed to assign EC key to EVP structure.\n");
            goto OPENSSL_ERROR;
        }
        if (sigalg == TPM_ALG_SM2) {
            result = EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);
            if (result <= 0) {
                ERROR("Error: failed to assign SM2 alias to EVP key.\n");
                goto OPENSSL_ERROR;
            }
        }
    #endif
    fclose(fp);
    fp = NULL;
    
    pctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (pctx == NULL) {
        ERROR("Error: failed to allocate pkey context.\n");
        goto OPENSSL_ERROR;
    }
    if (sigalg == TPM_ALG_SM2) {
        result = EVP_PKEY_CTX_set1_id(pctx, SM2_ID, SM2_ID_LEN);
        if (result <= 0) {
            ERROR("Error: failed to allocate SM2 id.\n");
            goto OPENSSL_ERROR;
        }
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    switch (hashalg)
    {
    case TPM_ALG_SM3_256:
        result = EVP_DigestSignInit(mctx, &pctx, EVP_sm3(), NULL, evp_key);
        break;
    case TPM_ALG_SHA256:
        result = EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), NULL, evp_key);
        break;
    case TPM_ALG_SHA384:
        result = EVP_DigestSignInit(mctx, &pctx, EVP_sha384(), NULL, evp_key);
        break;
    default:
        ERROR("Error: unsupported hashalg.\n");
        return false;
    }
    if (result <= 0) {
        ERROR("Error: failed to initialize signature.\n");
        goto OPENSSL_ERROR;
    }
    result = EVP_DigestSignUpdate(mctx, data->data, data->size);
    if (result <= 0) {
        ERROR("Error: failed to update signature.\n");
        goto OPENSSL_ERROR;
    }
    // Dry run, calculate length:
    result = EVP_DigestSignFinal(mctx, NULL, &sig_length);
    if (result <= 0 ) {
        ERROR("Error: failed to comp=ute signature length.\n");
        goto OPENSSL_ERROR;
    }
    signature_block = OPENSSL_malloc(sig_length);
    if (signature_block == NULL) {
        ERROR("Error: failed to allocate signature block.\n");
        goto OPENSSL_ERROR;
    }
    result = EVP_DigestSignFinal(mctx, (unsigned char *) signature_block, &sig_length);
    if (result <= 0) {
        ERROR("Error: failed to comp=ute signature length.\n");
        goto OPENSSL_ERROR;
    }
    // signature_block is DER encoded, we decode it:
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &signature_block, sig_length);
    if (ecdsa_sig == NULL) {
        ERROR("Error: failed to decode signature.\n");
        goto OPENSSL_ERROR;
    }
    sig_r = ECDSA_SIG_get0_r(ecdsa_sig);
    sig_s = ECDSA_SIG_get0_s(ecdsa_sig);
    if (sig_r == NULL || sig_s == NULL ) {
        ERROR("Error: failed to extract signature components.\n");
        goto OPENSSL_ERROR;
    }
    BN_bn2bin(sig_r, r->data);
    BN_bn2bin(sig_s, s->data);

    goto EXIT;
    OPENSSL_ERROR:
        DISPLAY("Error.\n");
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        result = 0;
    EXIT:
        #if OPENSSL_VERSION_NUMBER < 0x30000000L
            if (ec_key != NULL) {
                OPENSSL_free((void *) ec_key);
            }
        #endif
        if (evp_key != NULL) {
            OPENSSL_free((void *) evp_key);
        }
        if (mctx != NULL) {
            OPENSSL_free((void *) mctx);
        }
        if (pctx != NULL) {
            OPENSSL_free((void *) pctx);
        }
        if (fp != NULL) {
            fclose(fp);
        }
        if (ecdsa_sig != NULL) {
            ECDSA_SIG_free(ecdsa_sig);
        }
        return result ? true : false;
}

EVP_PKEY_CTX *rsa_get_sig_ctx(const char *key_path, uint16_t key_size_bytes)
{
    FILE *fp = NULL;
    EVP_PKEY *evp_priv = NULL;
    EVP_PKEY_CTX *context = NULL; //This will be returned

    LOG("[rsa_get_sig_ctx]\n");
    fp = fopen(key_path, "r");
    if (fp == NULL)
        goto ERROR;

    evp_priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (evp_priv == NULL)
        goto OPENSSL_ERROR;
    fclose(fp);
    fp = NULL;

    if (EVP_PKEY_size(evp_priv) != key_size_bytes) {
        ERROR("ERROR: key size incorrect\n");
        goto ERROR;
    }

    context = EVP_PKEY_CTX_new(evp_priv, NULL);
    if (context == NULL)
        goto OPENSSL_ERROR;

    OPENSSL_free(evp_priv);
    return context;

    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
    ERROR:
        if (fp != NULL)
            fclose(fp);
        if (evp_priv != NULL)
            OPENSSL_free(evp_priv);
        if (context != NULL)
            OPENSSL_free(context);
        return NULL;
}

bool rsa_ssa_pss_sign(sized_buffer *signature_block, sized_buffer *data_to_sign,
uint16_t sig_alg, uint16_t hash_alg, EVP_PKEY_CTX *private_key_context)
/*
    This function: signs data using rsa private key context

    In: pointer to a correctly sized buffer to hold signature block, digest of 
    lcp list data, hash alg used to hash data, Openssl private key context

    Out: true on success, false on failure. Also signature_block gets signature block data

*/
{
    LOG("[rsa_ssa_pss_sign]\n");
    int result; //For openssl return codes
    size_t siglen; //Holds length of signature returned by openssl must be 256 or 384
    const EVP_MD *evp_hash_alg;

    if (signature_block == NULL || data_to_sign == NULL || private_key_context == NULL) {
        ERROR("Error: one or more data buffers is not defined.\n");
        return false;
    }

    //Init sig
    result = EVP_PKEY_sign_init(private_key_context);
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    //Set padding
    if (sig_alg == TPM_ALG_RSASSA || sig_alg == LCP_POLSALG_RSA_PKCS_15) {
        result = EVP_PKEY_CTX_set_rsa_padding(private_key_context, RSA_PKCS1_PADDING);
    }
    else if (sig_alg == TPM_ALG_RSAPSS) {
        result = EVP_PKEY_CTX_set_rsa_padding(private_key_context, RSA_PKCS1_PSS_PADDING);
    }
    else {
        ERROR("ERROR: unsupported signature algorithm.\n");
        return false;
    }
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }

    if (sig_alg == TPM_ALG_RSAPSS) {
        result = EVP_PKEY_CTX_set_rsa_pss_saltlen(private_key_context, -1);
        if (result <= 0) {
            goto OPENSSL_ERROR;
        }
    }
    switch (hash_alg) {
        case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
            evp_hash_alg = EVP_sha1();
            break;
        case TPM_ALG_SHA1:
            evp_hash_alg = EVP_sha1();
            break;
        case TPM_ALG_SHA256:
            evp_hash_alg = EVP_sha256();
            break;
        case TPM_ALG_SHA384:
            evp_hash_alg = EVP_sha384();
            break;
        default:
            ERROR("Unsupported hash alg.\n");
            return false;
    }
    //Set signature md parameter
    result = EVP_PKEY_CTX_set_signature_md(private_key_context, evp_hash_alg);
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    //Calculate signature size (dry run)
    result = EVP_PKEY_sign(private_key_context, NULL, &siglen, data_to_sign->data,
                                                   get_lcp_hash_size(hash_alg));
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    if (siglen != signature_block->size) {
        ERROR("ERROR: signature size incorrect.\n");
        return false;
    }
    //Do the signing
    result = EVP_PKEY_sign(private_key_context, signature_block->data, &siglen,
                               data_to_sign->data, get_lcp_hash_size(hash_alg));
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    //All good, function end
    return true;
    
    //Error handling
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        return false;
}

uint16_t pkcs_get_hashalg(const unsigned char *data)
/*
From:
http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=40
   EM=00∥01∥FF∥…∥FF∥00∥T - PKCS1.5 padding starts with 00 01 || 0xFF for padding ||
   00 || T - this is the DER encoded hash identifier and hash message
   T - SHA-1:       30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 ∥ H
   T - SHA-256:     30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 ∥ H
   T - SHA-384:     30 41 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 ∥ H
   T - SHA-512:     30 51 30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 ∥ H

   E.g.
   SHA-256
   30 31 - sequence 0x31 bytes
      30 0D - sequence 0x0D bytes
         06 09 - OID (object ID) - 9 bytes
            60 86 48 01 65 03 04 02 01 - OID: SHA-256: FIPS180-3
         05 00 - parameters and size
      04 20 - octet of strings size 0x20 bytes
         H  - hash of a secret message
*/
{
    uint8_t der_oid = 0x06;
    size_t oid_size;

    if (data == NULL) {
        return TPM_ALG_NULL;
    }

    data += 2; //Skip 00 01
    //Skip 0xFFs padding and 00 after it
    do {
        data++;
    } while (*data == 0xFF);
    //Then move to der_oid
    data += 5;
    if (*data != der_oid) {
        return TPM_ALG_NULL;
    }
    data += 1;
    //Read oid size:
    oid_size = *data;
    if (oid_size == 0x05)
        return TPM_ALG_SHA1; //Only Sha1 has this size
    //Move to the last byte to see what alg is used
    data += oid_size;
    switch (*data)
    {
    case 0x01:
        return TPM_ALG_SHA256;
    case 0x02:
        return TPM_ALG_SHA384;
    case 0x03:
        return TPM_ALG_SHA512;
    default:
        return TPM_ALG_NULL;
    }
}

void buffer_reverse_byte_order(uint8_t *buffer, size_t length)
/*Works in place, modifies passed buffer*/
{
    uint8_t temp;
    int left_index = 0;
    int right_index = length - 1;
    while (right_index > left_index) {
        temp = buffer[right_index];
        buffer[right_index] = buffer[left_index];
        buffer[left_index] = temp;
        left_index++;
        right_index--;
    }
}

sized_buffer *allocate_sized_buffer(size_t size) {
    /*
        Allocate size bytes of memory for a buffer and return it
        or NULL on failure.
    */
    sized_buffer *buffer = NULL;
    if (size == 0) {
        ERROR("Error: buffer size must be at least 1.\n");
        return NULL;
    }
    buffer = malloc(size + offsetof(sized_buffer, data));
    if (buffer == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        return NULL;
    }
    return buffer;
}

unsigned char *der_encode_sig_comps(sized_buffer *sig_r, sized_buffer *sig_s, int *length)
{
    //Buffers for signature (will be passed to EVP_Verify):
    unsigned char *der_encoded_sig = NULL;
    unsigned char *helper_ptr = NULL; //Will be adjusted by openssl api - orig value + sigsize
    ECDSA_SIG *sig = NULL;
    BIGNUM *r;
    BIGNUM *s;
    int encoded_size = 0;
    LOG("[der_encode_sig_comps]\n");
    r = BN_bin2bn(sig_r->data, sig_r->size, NULL);
    s = BN_bin2bn(sig_s->data, sig_s->size, NULL);
    if (r == NULL || s == NULL) {
        ERROR("Error: failed to allocate signature componenst.\n");
        goto EXIT;
    }
    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        ERROR("Error: failed to allocate signature structure.\n");
        goto EXIT;
    }
    if (!ECDSA_SIG_set0(sig, r, s)) {
        ERROR("Error: failed to set signature components.\n");
        goto EXIT;
    }
    encoded_size = i2d_ECDSA_SIG(sig, NULL);
    if (!encoded_size) {
        ERROR("Error: failed to calculate the size of encoded buffer.\n");
        goto EXIT;
    }
    helper_ptr = OPENSSL_malloc(encoded_size);
    der_encoded_sig = helper_ptr;
    *length = encoded_size;
    //i2d_ECDSA_SIG changes value of the pointer passed, that's why we first assigned
    //it to der_encoded_sig, which will hold the encoded_sig.
    if (!i2d_ECDSA_SIG(sig, &helper_ptr)) {
        ERROR("Error: failed to encode signature.\n");
        return NULL;
    }
    EXIT:
        if (sig != NULL) {
            ECDSA_SIG_free(sig);
            //SIG_free also frees r and s
            r = NULL;
            s = NULL;
        }
        if (r != NULL) {
            OPENSSL_free((void *) r);
        }
        if (s != NULL) {
            OPENSSL_free((void *) s);
        }
        return der_encoded_sig;
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
