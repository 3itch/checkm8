/*
 * tpm_20.c: TPM2.0-related support functions
 *
 * Copyright (c) 2006-2013, Intel Corporation
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

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <misc.h>
#include <compiler.h>
#include <processor.h>
#include <io.h>
#include <string.h>
#include <tpm.h>
#include <tpm_20.h>
#include <cmdline.h>
#include <uuid.h>
#include <mle.h>
#include <loader.h>
#include <txt/acmod.h>

static u8 cmd_buf[MAX_COMMAND_SIZE];
static u8 rsp_buf[MAX_RESPONSE_SIZE];

extern loader_ctx *g_ldr_ctx;

#define reverse_copy_in(out, var) {\
    _reverse_copy((uint8_t *)(out), (uint8_t *)&(var), sizeof(var));\
    out += sizeof(var);\
}

#define reverse_copy_out(var, out) {\
    _reverse_copy((uint8_t *)&(var), (uint8_t *)(out), sizeof(var));\
    out += sizeof(var);\
}

static void reverse_copy_header(u32 cmd_code, TPM_CMD_SESSIONS_IN *sessions_in)
{
    u16 tag;

    if (sessions_in == NULL || sessions_in->num_sessions == 0)
        tag = TPM_ST_NO_SESSIONS;
    else
        tag = TPM_ST_SESSIONS;

    reverse_copy(cmd_buf, &tag, sizeof(tag));
    reverse_copy(cmd_buf + CMD_CC_OFFSET, &cmd_code, sizeof(cmd_code));
}

static void reverse_copy_pcr_selection_in(void **other, TPML_PCR_SELECTION *pcr_selection)
{
    u32 i, k;

    /* Copy count of pcrs to be read. */
    reverse_copy_in(*other, pcr_selection->count);

    for (i=0; i<pcr_selection->count; i++) {
        /* Copy alg ID for PCR to be read. */
        reverse_copy_in(*other, pcr_selection->selections[i].hash);

        /* Copy size of select array. */
        reverse_copy_in(*other, pcr_selection->selections[i].size_of_select);

        /* Copy bit field of the PCRs selected. */
        for (k=0; k<pcr_selection->selections[i].size_of_select; k++)
            reverse_copy_in(*other, pcr_selection->selections[i].pcr_select[k]);
    }
}

static bool reverse_copy_pcr_selection_out(TPML_PCR_SELECTION *pcr_selection,
                                           void **other)
{
    u32 i, k;

    if (pcr_selection == NULL)
        return false;

    /* Copy count of pcrs to be read. */
    reverse_copy_out(pcr_selection->count, *other);

    if ( pcr_selection->count > HASH_COUNT )
        return false;

    for (i=0; i<pcr_selection->count; i++) {
        /* Copy alg ID for PCR to be read. */
        reverse_copy_out(pcr_selection->selections[i].hash, *other);

        /* Copy size of select array. */
        reverse_copy_out(pcr_selection->selections[i].size_of_select, *other);

        if ( pcr_selection->selections[i].size_of_select >
             sizeof(pcr_selection->selections[i].pcr_select) )
            return false;

        /* Copy bit field of the PCRs selected */
        for (k=0; k<pcr_selection->selections[i].size_of_select; k++)
            reverse_copy_out(pcr_selection->selections[i].pcr_select[k], *other);
    }

    return true;
}

/*
 * Copy sized byte buffer from source to destination and
 * twiddle the bytes in the size field.
 *
 * This can be used for the any of the following
 * TPM 2.0 data structures, but is not limited to these:
 *
 *      ENCRYPTED_SECRET_2B 
 *      TPM2B_DIGEST
 *      TPM2B_NONCE
 *      TPM2B_DATA
 *      etc. (any structures consisting of UINT16 followed by a
 *          byte buffer whose size is specified by the UINT16.
 *
 * Inputs:
 *
 *      dest -- pointer to SIZED_BYTE_BUFFER 
 *      src -- pointer to SIZED_BYTE_BUFFER 
 *
 * Outputs:
 *
 *      number of bytes copied
 */
static u16 reverse_copy_sized_buf_in(TPM2B *dest, TPM2B *src)
{
    int i;

    if (dest == NULL || src == NULL)
        return 0;

    reverse_copy(&dest->size, &src->size, sizeof(u16));
    for (i=0; i<src->size; i++)
        dest->buffer[i] = src->buffer[i];

    return sizeof(u16) + src->size;
}


/*
 * Inputs: dest->size should contain the buffer size of dest->buffer[]
 * Outputs: dest->size should contain the final copied data size
 *
 * Return: 0, failed; 2+, succeed.
 */
static u16 reverse_copy_sized_buf_out(TPM2B *dest, TPM2B *src)
{
    u16 i, size;

    if (dest == NULL || src == NULL)
        return 0;

    reverse_copy(&size, &src->size, sizeof(u16));
    if ( size > dest->size )
        return 0;

    dest->size = size;
    for (i=0; i<dest->size; i++)
        dest->buffer[i] = src->buffer[i];

    return sizeof(u16) + dest->size;
}

static bool reverse_copy_digest_out(TPML_DIGEST *tpml_digest, void **other)
{
    u32 i;
    u16 size;

    if (tpml_digest == NULL)
        return false;

    reverse_copy_out(tpml_digest->count, *other);
    if ( tpml_digest->count > 8 )
        return false;

    for (i=0; i<tpml_digest->count; i++) {
        tpml_digest->digests[i].t.size = sizeof(tpml_digest->digests[i].t.buffer);
        size = reverse_copy_sized_buf_out((TPM2B *)&(tpml_digest->digests[i]),
                (TPM2B *)*other);
        if ( size == 0 )
            return false;
        *other += size;
    }

    return true;
}

static void reverse_copy_session_data_in(void **other,
                                         TPM_CMD_SESSION_DATA_IN *session_data,
                                         u32 *session_size)
{
    *session_size += sizeof(u32) + sizeof( u16 ) +
        session_data->nonce.t.size + sizeof( u8 ) +
        sizeof( u16 ) + session_data->hmac.t.size;

    /* copy session handle */
    reverse_copy_in(*other, session_data->session_handle);

    /* Copy nonce */
    *other += reverse_copy_sized_buf_in((TPM2B *)*other, (TPM2B *)&session_data->nonce);

    /* Copy attributes */
    *((u8 *)*other) = *(u8 *)(void *)&(session_data->session_attr);
    *other += sizeof(u8);

    /* Copy hmac data */
    *other += reverse_copy_sized_buf_in((TPM2B *)*other, (TPM2B *)&session_data->hmac);
}

static void reverse_copy_sessions_in(void **other, TPM_CMD_SESSIONS_IN *sessions_in)
{
    int i;
    u32 session_size = 0;
    void *session_size_ptr = *other;

    if (sessions_in == NULL)
        return;

    if (sessions_in->num_sessions != 0) {
        *other += sizeof(u32);
        for (i=0; i<sessions_in->num_sessions; i++)
            reverse_copy_session_data_in(other,
                    &sessions_in->sessions[i], &session_size);
    }

    reverse_copy(session_size_ptr, &session_size, sizeof(u32));
}

static bool reverse_copy_session_data_out(TPM_CMD_SESSION_DATA_OUT *session_data,
                                          void **other)
{
    u16 size;

    if (session_data == NULL)
        return false;

    /* Copy nonce */
    session_data->nonce.t.size = sizeof(session_data->nonce.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(session_data->nonce),
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    /* Copy sessionAttributes */
    *(u8 *)(void *)&(session_data->session_attr) = *((u8 *)*other);
    *other += sizeof(u8);

    /* Copy hmac */
    session_data->hmac.t.size = sizeof(session_data->hmac.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(session_data->hmac),
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    return true;
}

static bool reverse_copy_sessions_out(TPM_CMD_SESSIONS_OUT *sessions_out,
                                      void *other, u16 rsp_tag,
                                      TPM_CMD_SESSIONS_IN *sessions_in)
{
    int i;

    if (sessions_in == NULL || sessions_out == NULL || rsp_tag != TPM_ST_SESSIONS)
        return false;

    sessions_out->num_sessions = sessions_in->num_sessions;
    for (i=0; i<sessions_in->num_sessions; i++)
        if ( !reverse_copy_session_data_out(&sessions_out->sessions[i], &other) )
            return false;

    return true;
}

typedef struct {
    u16         alg_id; 
    u16         size;  /* Size of digest */
} HASH_SIZE_INFO;

HASH_SIZE_INFO hash_sizes[] = {
    {TPM_ALG_SHA1,          SHA1_DIGEST_SIZE},
    {TPM_ALG_SHA256,        SHA256_DIGEST_SIZE},
    {TPM_ALG_SHA384,        SHA384_DIGEST_SIZE},
    {TPM_ALG_SHA512,        SHA512_DIGEST_SIZE},
    {TPM_ALG_SM3_256,       SM3_256_DIGEST_SIZE},
    {TPM_ALG_NULL,0}
};

u16 get_digest_size(u16 id)
{
    unsigned int i;
    for(i=0; i<(sizeof(hash_sizes)/sizeof(HASH_SIZE_INFO)); i++) {
        if(hash_sizes[i].alg_id == id)
            return hash_sizes[i].size;
    }

    /* If not found, return 0 size, and let TPM handle the error. */
    return 0 ;
}

static void reverse_copy_digest_value_in(void **other, TPML_DIGEST_VALUES *tpml_digest)
{
    unsigned int i, k, num_bytes;

    reverse_copy_in(*other, tpml_digest->count);

    for (i=0; i<tpml_digest->count; i++) {
        reverse_copy_in(*other, tpml_digest->digests[i].hash_alg);

        num_bytes = get_digest_size(tpml_digest->digests[i].hash_alg);

        for (k=0; k<num_bytes; k++) {
            *((u8 *)*other) = tpml_digest->digests[i].digest.sha1[k];
            *other += sizeof(u8);
        }
    }
}

static bool reverse_copy_digest_values_out(TPML_DIGEST_VALUES *tpml_digest,
                                           void **other)
{
    unsigned int i, k, num_bytes;

    if (tpml_digest == NULL)
        return false;

    reverse_copy_out(tpml_digest->count, *other);
    if ( tpml_digest->count > HASH_COUNT )
        return false;

    for (i=0; i<tpml_digest->count; i++) {
        reverse_copy_out(tpml_digest->digests[i].hash_alg, *other);

        num_bytes = get_digest_size(tpml_digest->digests[i].hash_alg);

        for (k=0; k<num_bytes; k++) {
            tpml_digest->digests[i].digest.sha1[k] = *((u8 *)*other);
            *other += sizeof(u8);
        }
    }

    return true;
}

/*
 * Copy public data from input data structure into output data stream
 * for commands that require it.
 *
 * Inputs:
 *
 *      pointer to pointer to TPM command area to fill in with public data
 *
 *      pointer to TPM2B_PUBLIC structure
 *
 * Outputs:
 *
 *      otherData pointer points to end byte past command buffer.  This allows
 *          caller to set the commandSize field for the command.
 */
static void reverse_copy_public_in(void **other, TPM2B_PUBLIC *public)
{
    TPMT_KEYEDHASH_SCHEME  *scheme;
    TPMT_RSA_SCHEME *rsa_scheme = &(public->t.public_area.param.rsa.scheme);
    TPMT_ECC_SCHEME *ecc_scheme = &(public->t.public_area.param.ecc.scheme);
    TPMT_KDF_SCHEME *kdf = &(public->t.public_area.param.ecc.kdf);
    TPMT_ASYM_SCHEME *asym_scheme = &(public->t.public_area.param.asym.scheme);
    void *size_ptr;
    u16 size;

    size_ptr = *other;
    *other += sizeof(u16);

    reverse_copy_in(*other, public->t.public_area.type);
    reverse_copy_in(*other, public->t.public_area.name_alg);

    /* Copy public->t.object_attr */
    reverse_copy(*other, (void *)&public->t.public_area.object_attr, sizeof(u32));
    *other += sizeof(u32);

    /* Copy public->t.auth_policy */
    *other += reverse_copy_sized_buf_in((TPM2B *)*other,
            (TPM2B *)&public->t.public_area.auth_policy);

    /* Copy public->t.param */
    switch(public->t.public_area.type) {
    case TPM_ALG_KEYEDHASH:
        scheme = &(public->t.public_area.param.keyed_hash.scheme);

        reverse_copy_in(*other, scheme->scheme);

        if(scheme->scheme != TPM_ALG_NULL) {
            /* copy details */
            if(scheme->scheme == TPM_ALG_HMAC) {
                reverse_copy_in(*other, scheme->details.hmac.hash_alg);
            } else {
                reverse_copy_in(*other, scheme->details.xor.hash_alg);
                reverse_copy_in(*other, scheme->details.xor.kdf);
            }
        }

        /* Copy public->t.public_area.unique */
        *other += reverse_copy_sized_buf_in((TPM2B *)*other,
                (TPM2B *)&public->t.public_area.unique.keyed_hash);

        break;

    case TPM_ALG_SYMCIPHER:
        reverse_copy_in(*other, public->t.public_area.param.sym.alg);

        if (public->t.public_area.param.sym.alg != TPM_ALG_NULL) {
            reverse_copy_in(*other, public->t.public_area.param.sym.key_bits.sym);

            reverse_copy_in(*other, public->t.public_area.param.sym.mode.sym);
        }

        /* Copy public->t.public_area.unique */
        *other += reverse_copy_sized_buf_in((TPM2B *)*other,
                (TPM2B *)&public->t.public_area.unique.sym);

        break;

    case TPM_ALG_RSA:
        /* Copy symmetric fields */
        reverse_copy_in(*other, public->t.public_area.param.rsa.symmetric.alg);

        if (public->t.public_area.param.rsa.symmetric.alg != TPM_ALG_NULL) {
            reverse_copy_in(*other, public->t.public_area.param.rsa.symmetric.key_bits.sym);

            reverse_copy_in(*other, public->t.public_area.param.rsa.symmetric.mode.sym);
        }

        /* Copy scheme */
        reverse_copy_in(*other, rsa_scheme->scheme);
        if (rsa_scheme->scheme != TPM_ALG_NULL) {
            switch (rsa_scheme->scheme) {
            case TPM_ALG_RSASSA:
                reverse_copy_in(*other, rsa_scheme->details.rsassa.hash_alg);
                break;

            case TPM_ALG_RSAPSS:
                reverse_copy_in(*other, rsa_scheme->details.rsapss.hash_alg);
                break;

            case TPM_ALG_OAEP:
                reverse_copy_in(*other, rsa_scheme->details.oaep.hash_alg);
                break;

            case TPM_ALG_ECDSA:
                reverse_copy_in(*other, rsa_scheme->details.ecdsa.hash_alg);
                break;

            case TPM_ALG_SM2:
                reverse_copy_in(*other, rsa_scheme->details.sm2.hash_alg);
                break;

            case TPM_ALG_ECDAA:
                reverse_copy_in(*other, rsa_scheme->details.ecdaa.hash_alg);
                reverse_copy_in(*other, rsa_scheme->details.ecdaa.count);
                break;

            case TPM_ALG_ECSCHNORR:
                reverse_copy_in(*other, rsa_scheme->details.ec_schnorr.hash_alg);
                break;

            default:
                reverse_copy_in(*other, rsa_scheme->details.any.hash_alg);
                break;
            }
        }

        /* Copy keybits */
        reverse_copy_in(*other, public->t.public_area.param.rsa.key_bits);

        /* Copy exponent  */
        reverse_copy_in(*other, public->t.public_area.param.rsa.exponent);

        /* Copy public->t.public_area.unique */
        *other += reverse_copy_sized_buf_in((TPM2B *)*other,
                (TPM2B *)&public->t.public_area.unique.rsa);

        break;

    case TPM_ALG_ECC:
        /* Copy symmetric fields */
        reverse_copy_in(*other, public->t.public_area.param.ecc.symmetric.alg);

        if (public->t.public_area.param.ecc.symmetric.alg != TPM_ALG_NULL) {
            reverse_copy_in(*other, public->t.public_area.param.ecc.symmetric.key_bits.sym);

            reverse_copy_in(*other, public->t.public_area.param.ecc.symmetric.mode.sym);
        }

        /* Copy ECC scheme */
        reverse_copy_in(*other, ecc_scheme->scheme);
        if (ecc_scheme->scheme != TPM_ALG_NULL) {
            switch (ecc_scheme->scheme) {
            case TPM_ALG_RSASSA:
                reverse_copy_in(*other, ecc_scheme->details.rsassa.hash_alg);
                break;

            case TPM_ALG_RSAPSS:
                reverse_copy_in(*other, ecc_scheme->details.rsapss.hash_alg);
                break;

            case TPM_ALG_ECDSA:
                reverse_copy_in(*other, ecc_scheme->details.ecdsa.hash_alg);
                break;

            case TPM_ALG_SM2:
                reverse_copy_in(*other, ecc_scheme->details.sm2.hash_alg);
                break;

            case TPM_ALG_ECDAA:
                reverse_copy_in(*other, ecc_scheme->details.ecdaa.hash_alg);
                reverse_copy_in(*other, ecc_scheme->details.ecdaa.count);
                break;

            case TPM_ALG_ECSCHNORR:
                reverse_copy_in(*other, ecc_scheme->details.ec_schnorr.hash_alg);
                break;

            case TPM_ALG_HMAC:
                reverse_copy_in(*other, ecc_scheme->details.hmac.hash_alg);
                break;

            default:
                reverse_copy_in(*other, ecc_scheme->details.any.hash_alg);
                break;
            }
        }

        /* Copy curve_id  */
        reverse_copy_in(*other, public->t.public_area.param.ecc.curve_id);

        /* Copy KDF scheme */
        reverse_copy_in(*other, kdf->scheme);
        switch (kdf->scheme) {
        case TPM_ALG_MGF1:
            reverse_copy_in(*other, kdf->details.mgf1.hash_alg);
            break;

        case TPM_ALG_KDF1_SP800_56a:
            reverse_copy_in(*other, kdf->details.kdf1_SP800_56a.hash_alg);
            break;

        case TPM_ALG_KDF1_SP800_108:
            reverse_copy_in(*other, kdf->details.kdf1_sp800_108.hash_alg);
            break;

        default:
            /* Copy something bogus and let TPM return error code */
            *((u16 *)*other) = 0xffff;
            *other += sizeof(u16);
            break;
        }

        /* Copy public->t.public_area.unique */
        *other += reverse_copy_sized_buf_in((TPM2B *)*other,
                (TPM2B *)&public->t.public_area.unique.ecc);

        break;

    default:
        /* Copy symmetric fields */
        reverse_copy_in(*other, public->t.public_area.param.asym.symmetric.alg);

        if (public->t.public_area.param.asym.symmetric.alg != TPM_ALG_NULL) {
            reverse_copy_in(*other, public->t.public_area.param.asym.symmetric.key_bits.sym);

            reverse_copy_in(*other, public->t.public_area.param.asym.symmetric.mode.sym);
        }

        /* Copy scheme */
        reverse_copy_in(*other, asym_scheme->scheme);
        if (asym_scheme->scheme != TPM_ALG_NULL) {
            switch (asym_scheme->scheme) {
            case TPM_ALG_RSASSA:
                reverse_copy_in(*other, asym_scheme->details.rsassa.hash_alg);
                break;

            case TPM_ALG_RSAPSS:
                reverse_copy_in(*other, asym_scheme->details.rsapss.hash_alg);
                break;

            case TPM_ALG_OAEP:
                reverse_copy_in(*other, asym_scheme->details.oaep.hash_alg);
                break;

            case TPM_ALG_ECDSA:
                reverse_copy_in(*other, asym_scheme->details.ecdsa.hash_alg);
                break;

            case TPM_ALG_SM2:
                reverse_copy_in(*other, asym_scheme->details.sm2.hash_alg);
                break;

            case TPM_ALG_ECDAA:
                reverse_copy_in(*other, asym_scheme->details.ecdaa.hash_alg);
                reverse_copy_in(*other, asym_scheme->details.ecdaa.count);
                break;

            case TPM_ALG_ECSCHNORR:
                reverse_copy_in(*other, asym_scheme->details.ec_schnorr.hash_alg);
                break;

            default:
                reverse_copy_in(*other, asym_scheme->details.any.hash_alg);
                break;
            }
        }

        break;
    }

    /* Now calculate and write the inPublic size; don't include size field in the size calc */
    size = (u8 *)*other - (u8 *)size_ptr - sizeof(u16);
    reverse_copy(size_ptr, &size, sizeof(u16));
}

/*
 * Copy public data from input data structure into output data stream
 * for commands that require it.
 *
 * Inputs:
 *
 *      pointer to TPM2B_PUBLIC structure for returned data
 *
 *      pointer to pointer to TPM command byte stream for the returned data
 *
 * Outputs:
 *
 *      public contains the de-canonicalized data extracted from the output data stream
 */
static bool reverse_copy_public_out(TPM2B_PUBLIC *public, void **other)
{
    TPMT_KEYEDHASH_SCHEME  *scheme;
    TPMT_RSA_SCHEME *rsa_scheme = &(public->t.public_area.param.rsa.scheme);
    TPMT_ECC_SCHEME *ecc_scheme = &(public->t.public_area.param.ecc.scheme);
    TPMT_KDF_SCHEME *kdf = &(public->t.public_area.param.ecc.kdf);
    TPMT_ASYM_SCHEME *asym_scheme = &(public->t.public_area.param.asym.scheme);
    u16 size;

    if (public == NULL)
        return false;

    reverse_copy_out(public->t.size, *other);
    reverse_copy_out(public->t.public_area.type, *other);
    reverse_copy_out(public->t.public_area.name_alg, *other);

    /* Copy public->t.object_attr */
    reverse_copy((void *)&public->t.public_area.object_attr, *other, sizeof(u32));
    *other += sizeof(u32);

    /* Copy public->t.auth_policy */
    public->t.public_area.auth_policy.t.size =
            sizeof(public->t.public_area.auth_policy.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&public->t.public_area.auth_policy,
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    /* Copy public->t.param */
    switch(public->t.public_area.type) {
    case TPM_ALG_KEYEDHASH:
        scheme = &(public->t.public_area.param.keyed_hash.scheme);

        reverse_copy_out(scheme->scheme, *other);

        if(scheme->scheme != TPM_ALG_NULL) {
            /* copy details */
            if(scheme->scheme == TPM_ALG_HMAC) {
                reverse_copy_out(scheme->details.hmac.hash_alg, *other);
            } else {
                reverse_copy_out(scheme->details.xor.hash_alg, *other);
                reverse_copy_out(scheme->details.xor.kdf, *other);
            }
        }

        /* Copy public->t.public_area.unique */
        public->t.public_area.unique.keyed_hash.t.size =
                sizeof(public->t.public_area.unique.keyed_hash.t.buffer);
        size = reverse_copy_sized_buf_out(
                (TPM2B *)&public->t.public_area.unique.keyed_hash,
                (TPM2B *)*other);
        if ( size == 0 )
            return false;
        *other += size;

        break;

    case TPM_ALG_SYMCIPHER:
        reverse_copy_out(public->t.public_area.param.sym.alg, *other);

        if (public->t.public_area.param.sym.alg != TPM_ALG_NULL) {
            reverse_copy_out(public->t.public_area.param.sym.key_bits.sym, *other);

            reverse_copy_out(public->t.public_area.param.sym.mode.sym, *other);
        }

        /* Copy public->t.public_area.unique */
        public->t.public_area.unique.sym.t.size =
                sizeof(public->t.public_area.unique.sym.t.buffer);
        size = reverse_copy_sized_buf_out(
                (TPM2B *)&public->t.public_area.unique.sym,
                (TPM2B *)*other);
        if ( size == 0 )
            return false;
        *other += size;

        break;

    case TPM_ALG_RSA:
        /* Copy symmetric fields */
        reverse_copy_out(public->t.public_area.param.rsa.symmetric.alg, *other);

        if (public->t.public_area.param.rsa.symmetric.alg != TPM_ALG_NULL) {
            reverse_copy_out(public->t.public_area.param.rsa.symmetric.key_bits.sym, *other);

            reverse_copy_out(public->t.public_area.param.rsa.symmetric.mode.sym, *other);
        }

        /* Copy scheme */
        reverse_copy_out(rsa_scheme->scheme, *other);
        if (rsa_scheme->scheme != TPM_ALG_NULL) {
            switch (rsa_scheme->scheme) {
            case TPM_ALG_RSASSA:
                reverse_copy_out(rsa_scheme->details.rsassa.hash_alg, *other);
                break;

            case TPM_ALG_RSAPSS:
                reverse_copy_out(rsa_scheme->details.rsapss.hash_alg, *other);
                break;

            case TPM_ALG_OAEP:
                reverse_copy_out(rsa_scheme->details.oaep.hash_alg, *other);
                break;

            case TPM_ALG_ECDSA:
                reverse_copy_out(rsa_scheme->details.ecdsa.hash_alg, *other);
                break;

            case TPM_ALG_SM2:
                reverse_copy_out(rsa_scheme->details.sm2.hash_alg, *other);
                break;

            case TPM_ALG_ECDAA:
                reverse_copy_out(rsa_scheme->details.ecdaa.hash_alg, *other);
                reverse_copy_out(rsa_scheme->details.ecdaa.count, *other);
                break;

            case TPM_ALG_ECSCHNORR:
                reverse_copy_out(rsa_scheme->details.ec_schnorr.hash_alg, *other);
                break;

            default:
                reverse_copy_out(rsa_scheme->details.any.hash_alg, *other);
                break;
            }
        }

        /* Copy keybits */
        reverse_copy_out(public->t.public_area.param.rsa.key_bits, *other);

        /* Copy exponent  */
        reverse_copy_out(public->t.public_area.param.rsa.exponent, *other);

        /* Copy public->t.public_area.unique */
        public->t.public_area.unique.rsa.t.size =
                sizeof(public->t.public_area.unique.rsa.t.buffer);
        size = reverse_copy_sized_buf_out((TPM2B *)&public->t.public_area.unique.rsa,
                (TPM2B *)*other);
        if ( size == 0 )
            return false;
        *other += size;

        break;

    case TPM_ALG_ECC:
        /* Copy symmetric fields */
        reverse_copy_out(public->t.public_area.param.ecc.symmetric.alg, *other);

        if (public->t.public_area.param.ecc.symmetric.alg != TPM_ALG_NULL) {
            reverse_copy_out(public->t.public_area.param.ecc.symmetric.key_bits.sym, *other);

            reverse_copy_out(public->t.public_area.param.ecc.symmetric.mode.sym, *other);
        }

        /* Copy ECC scheme */
        reverse_copy_out(ecc_scheme->scheme, *other);
        if (ecc_scheme->scheme != TPM_ALG_NULL) {
            switch (ecc_scheme->scheme) {
            case TPM_ALG_RSASSA:
                reverse_copy_out(ecc_scheme->details.rsassa.hash_alg, *other);
                break;

            case TPM_ALG_RSAPSS:
                reverse_copy_out(ecc_scheme->details.rsapss.hash_alg, *other);
                break;

            case TPM_ALG_ECDSA:
                reverse_copy_out(ecc_scheme->details.ecdsa.hash_alg, *other);
                break;

            case TPM_ALG_SM2:
                reverse_copy_out(ecc_scheme->details.sm2.hash_alg, *other);
                break;

            case TPM_ALG_ECDAA:
                reverse_copy_out(ecc_scheme->details.ecdaa.hash_alg, *other);
                reverse_copy_out(ecc_scheme->details.ecdaa.count, *other);
                break;

            case TPM_ALG_ECSCHNORR:
                reverse_copy_out(ecc_scheme->details.ec_schnorr.hash_alg, *other);
                break;

            case TPM_ALG_HMAC:
                reverse_copy_out(ecc_scheme->details.hmac.hash_alg, *other);
                break;

            default:
                reverse_copy_out(ecc_scheme->details.any.hash_alg, *other);
                break;
            }
        }

        /* Copy curve_id  */
        reverse_copy_out(public->t.public_area.param.ecc.curve_id, *other);

        /* Copy KDF scheme */
        reverse_copy_out(kdf->scheme, *other);
        switch (kdf->scheme) {
        case TPM_ALG_MGF1:
            reverse_copy_out(kdf->details.mgf1.hash_alg, *other);
            break;

        case TPM_ALG_KDF1_SP800_56a:
            reverse_copy_out(kdf->details.kdf1_SP800_56a.hash_alg, *other);
            break;

        case TPM_ALG_KDF1_SP800_108:
            reverse_copy_out(kdf->details.kdf1_sp800_108.hash_alg, *other);
            break;

        default:
            /* Copy something bogus and let TPM return error code */
            *((u16 *)*other) = 0xffff;
            *other += sizeof(u16);
            break;
        }

        /* Copy public->t.public_area.unique */
        public->t.public_area.unique.ecc.x.t.size =
                sizeof(public->t.public_area.unique.ecc.x.t.buffer);
        size = reverse_copy_sized_buf_out((TPM2B *)&public->t.public_area.unique.ecc.x,
                (TPM2B *)*other);
        if ( size == 0 )
            return false;
        *other += size;

        public->t.public_area.unique.ecc.y.t.size =
                sizeof(public->t.public_area.unique.ecc.y.t.buffer);
        size = reverse_copy_sized_buf_out((TPM2B *)&public->t.public_area.unique.ecc.y,
                (TPM2B *)*other);
        if ( size == 0 )
            return false;
        *other += size;

        break;

    default:
        /* Copy symmetric fields */
        reverse_copy_out(public->t.public_area.param.asym.symmetric.alg, *other);

        if (public->t.public_area.param.asym.symmetric.alg != TPM_ALG_NULL) {
            reverse_copy_out(public->t.public_area.param.asym.symmetric.key_bits.sym, *other);

            reverse_copy_out(public->t.public_area.param.asym.symmetric.mode.sym, *other);
        }

        /* Copy scheme */
        reverse_copy_out(asym_scheme->scheme, *other);
        if (asym_scheme->scheme != TPM_ALG_NULL) {
            switch (asym_scheme->scheme) {
            case TPM_ALG_RSASSA:
                reverse_copy_out(asym_scheme->details.rsassa.hash_alg, *other);
                break;

            case TPM_ALG_RSAPSS:
                reverse_copy_out(asym_scheme->details.rsapss.hash_alg, *other);
                break;

            case TPM_ALG_OAEP:
                reverse_copy_out(asym_scheme->details.oaep.hash_alg, *other);
                break;

            case TPM_ALG_ECDSA:
                reverse_copy_out(asym_scheme->details.ecdsa.hash_alg, *other);
                break;

            case TPM_ALG_SM2:
                reverse_copy_out(asym_scheme->details.sm2.hash_alg, *other);
                break;

            case TPM_ALG_ECDAA:
                reverse_copy_out(asym_scheme->details.ecdaa.hash_alg, *other);
                reverse_copy_out(asym_scheme->details.ecdaa.count, *other);
                break;

            case TPM_ALG_ECSCHNORR:
                reverse_copy_out(asym_scheme->details.ec_schnorr.hash_alg, *other);
                break;

            default:
                reverse_copy_out(asym_scheme->details.any.hash_alg, *other);
                break;
            }
        }

        break;
    }

    return true;
}

static bool reverse_copy_creation_data_out(TPM2B_CREATION_DATA *data, void **other)
{
    u16 size;

    if (data == NULL)
        return false;

    reverse_copy_out(data->t.size, *other);

    if ( !reverse_copy_pcr_selection_out(&data->t.data.pcr_select, other) )
        return false;

    data->t.data.pcr_digest.t.size = sizeof(data->t.data.pcr_digest.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(data->t.data.pcr_digest),
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    *((u8 *)(void *)&data->t.data.locality) = *((u8 *)*other);
    *other += sizeof(u8);

    reverse_copy_out(data->t.data.parent_name_alg, *other);

    data->t.data.parent_name.t.size = sizeof(data->t.data.parent_name.t.name);
    size = reverse_copy_sized_buf_out((TPM2B *)&(data->t.data.parent_name),
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    data->t.data.parent_qualified_name.t.size =
            sizeof(data->t.data.parent_qualified_name.t.name);
    size = reverse_copy_sized_buf_out((TPM2B *)&(data->t.data.parent_qualified_name),
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    data->t.data.outside_info.t.size = sizeof(data->t.data.outside_info.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(data->t.data.outside_info),
            (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    return true;
}

static bool reverse_copy_ticket_out(TPMT_TK_CREATION *ticket, void **other)
{
    u16 size;

    if (ticket == NULL)
        return false;

    reverse_copy_out(ticket->tag, *other);

    reverse_copy_out(ticket->hierarchy, *other);

    ticket->digest.t.size = sizeof(ticket->digest.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(ticket->digest), (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    return true;
}

static void reverse_copy_context_in(void **other, TPMS_CONTEXT *context)
{
    if (context == NULL)
	return;
	
    reverse_copy_in(*other, context->sequence);
    
    reverse_copy_in(*other, context->savedHandle);
    
    reverse_copy_in(*other, context->hierarchy);
    
    *other += reverse_copy_sized_buf_in((TPM2B *)*other, (TPM2B *)&context->contextBlob);

}

static bool reverse_copy_context_out(TPMS_CONTEXT *context, void **other)
{
    u16 size;

    if (context == NULL)
        return false;

    reverse_copy_out(context->sequence, *other);
    
    reverse_copy_out(context->savedHandle, *other);
    
    reverse_copy_out(context->hierarchy, *other);

    context->contextBlob.t.size = sizeof(context->contextBlob.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&context->contextBlob, (TPM2B *)*other);
    if ( size == 0 )
        return false;
    *other += size;

    return true;
}

static uint32_t _tpm20_pcr_read(u32 locality,
                                tpm_pcr_read_in *in,
                                tpm_pcr_read_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_PCR_Read, 0);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_pcr_selection_in(&other, &in->pcr_selection);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))  
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));

    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32); /* Skip past parameter size field */

    reverse_copy_out(out->pcr_update_counter, other);

    if ( !reverse_copy_pcr_selection_out(&out->pcr_selection, &other) )
        return TPM_RC_FAILURE;

    if ( !reverse_copy_digest_out(&out->pcr_values, &other) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_pcr_extend(uint32_t locality,
                                  tpm_pcr_extend_in *in,
                                  tpm_pcr_extend_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_PCR_Extend, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->pcr_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    reverse_copy_digest_value_in(&other, &in->digests);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_pcr_event(uint32_t locality,
                                 tpm_pcr_event_in *in,
                                 tpm_pcr_event_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_PCR_Event, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->pcr_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->data));

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);
    
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    if ( !reverse_copy_digest_values_out(&out->digests, &other) )
        return TPM_RC_FAILURE;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_pcr_reset(uint32_t locality,
                                 tpm_pcr_reset_in *in,
                                 tpm_pcr_reset_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_PCR_Reset, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy(other, &in->pcr_handle, sizeof(u32));

    other += sizeof(u32);
    reverse_copy_sessions_in(&other, &in->sessions);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_sequence_start(uint32_t locality,
                                      tpm_sequence_start_in *in,
                                      tpm_sequence_start_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_HashSequenceStart, 0);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->auth));

    reverse_copy_in(other, in->hash_alg);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = RSP_HEAD_SIZE + sizeof(*out);
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    reverse_copy_out(out->handle, other);

    return ret;
}

static uint32_t _tpm20_sequence_update(uint32_t locality,
                                       tpm_sequence_update_in *in,
                                       tpm_sequence_update_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_SequenceUpdate, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;

    reverse_copy_in(other, in->handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->buf));

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_sequence_complete(uint32_t locality,
                                         tpm_sequence_complete_in *in,
                                         tpm_sequence_complete_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_EventSequenceComplete, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;

    reverse_copy_in(other, in->pcr_handle);
    reverse_copy_in(other, in->seq_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->buf));

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    if ( !reverse_copy_digest_values_out(&out->results, &other) )
        return TPM_RC_FAILURE;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_nv_read(uint32_t locality,
                               tpm_nv_read_in *in,
                               tpm_nv_read_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_NV_Read, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->handle);
    reverse_copy_in(other, in->index);

    reverse_copy_sessions_in(&other, &in->sessions);

    reverse_copy_in(other, in->size);
    reverse_copy_in(other, in->offset);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(rsp_buf);
 
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    out->data.t.size = sizeof(out->data.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->data), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_nv_write(uint32_t locality,
                                tpm_nv_write_in *in,
                                tpm_nv_write_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    
    reverse_copy_header(TPM_CC_NV_Write, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->handle);
    reverse_copy_in(other, in->index);

    reverse_copy_sessions_in(&other, &in->sessions);

    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->data));

    reverse_copy_in(other, in->offset);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_nv_read_public(uint32_t locality,
                                      tpm_nv_read_public_in *in,
                                      tpm_nv_read_public_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_NV_ReadPublic, 0);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->index);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    reverse_copy_out(out->nv_public.t.size, other);
    reverse_copy_out(out->nv_public.t.nv_public.index, other);
    reverse_copy_out(out->nv_public.t.nv_public.name_alg, other);
    reverse_copy((void *)&(out->nv_public.t.nv_public.attr), other, sizeof(u32));
    other += sizeof(u32);

    out->nv_public.t.nv_public.auth_policy.t.size =
            sizeof(out->nv_public.t.nv_public.auth_policy.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->nv_public.t.nv_public.auth_policy),
            (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    reverse_copy_out(out->nv_public.t.nv_public.data_size, other);
 
    out->nv_name.t.size = sizeof(out->nv_name.t.name);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->nv_name), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    return ret;
}

static uint32_t _tpm20_get_random(uint32_t locality,
                                 tpm_get_random_in *in,
                                 tpm_get_random_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_GetRandom, 0);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->bytes_req);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);
 
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    out->random_bytes.t.size = sizeof(out->random_bytes.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->random_bytes), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    return ret;
}

static uint32_t _tpm20_shutdown(uint32_t locality, u16 type)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    void *other;
    
    reverse_copy_header(TPM_CC_Shutdown, 0);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, type);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = RSP_HEAD_SIZE; 

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    return ret;
}

__data u32 handle2048 = 0;
static const char auth_str[] = "test";
static uint32_t _tpm20_create_primary(uint32_t locality,
                                     tpm_create_primary_in *in,
                                     tpm_create_primary_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    u16 sensitive_size;
    void *sensitive_size_ptr;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_CreatePrimary, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->primary_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    /* Copy inSensitive */
    sensitive_size_ptr = other;
    other += sizeof(u16);
    other += reverse_copy_sized_buf_in((TPM2B *)other,
            (TPM2B *)&(in->sensitive.t.sensitive.user_auth));
    other += reverse_copy_sized_buf_in((TPM2B *)other,
            (TPM2B *)&(in->sensitive.t.sensitive.data));
    sensitive_size = (u8 *)other - (u8 *)sensitive_size_ptr - sizeof(u16);
    reverse_copy(sensitive_size_ptr, &sensitive_size, sizeof(u16));

    /* Copy inPublic */
    reverse_copy_public_in(&other, &in->public);

    /* Copy outsideInfo */
    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->outside_info));

    /* Copy creationPCR */
    reverse_copy_pcr_selection_in(&other, &in->creation_pcr);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }


    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;

    /* Save objHandle */
    reverse_copy_out(out->obj_handle, other);

    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    /* Save outPublic */
    if ( !reverse_copy_public_out(&out->public, &other) )
        return TPM_RC_FAILURE;

    /* Save creationData */
    if ( !reverse_copy_creation_data_out(&(out->creation_data), &other) )
        return TPM_RC_FAILURE;

    /* Save creationHash */
    out->creation_hash.t.size = sizeof(out->creation_hash.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->creation_hash),
            (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    /* Save creationTicket */
    if ( !reverse_copy_ticket_out(&(out->creation_ticket), &other) )
        return TPM_RC_FAILURE;

    out->name.t.size = sizeof(out->name.t.name);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->name), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}


static uint32_t _tpm20_create(uint32_t locality,
                              tpm_create_in *in,
                              tpm_create_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    u16 sensitive_size;
    void *sensitive_size_ptr;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_Create, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->parent_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    /* Copy inSensitive */
    sensitive_size_ptr = other;
    other += sizeof(u16);
    other += reverse_copy_sized_buf_in((TPM2B *)other,
            (TPM2B *)&(in->sensitive.t.sensitive.user_auth));
    other += reverse_copy_sized_buf_in((TPM2B *)other,
            (TPM2B *)&(in->sensitive.t.sensitive.data));
    sensitive_size = (u8 *)other - (u8 *)sensitive_size_ptr - sizeof(u16);
    reverse_copy(sensitive_size_ptr, &sensitive_size, sizeof(u16));

    /* Copy inPublic */
    reverse_copy_public_in(&other, &in->public);

    /* Copy outsideInfo */
    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->outside_info));

    /* Copy creationPCR */
    reverse_copy_pcr_selection_in(&other, &in->creation_pcr);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(rsp_buf);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    /* Save outPrivate */
    out->private.t.size = sizeof(out->private.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->private), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    /* Save outPublic */
    if ( !reverse_copy_public_out(&out->public, &other) )
        return TPM_RC_FAILURE;

    /* Save creationData */
    if ( !reverse_copy_creation_data_out(&(out->creation_data), &other) )
        return TPM_RC_FAILURE;

    /* Save creationHash */
    out->creation_hash.t.size = sizeof(out->creation_hash.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->creation_hash),
            (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    /* Save creationTicket */
    if ( !reverse_copy_ticket_out(&(out->creation_ticket), &other) )
        return TPM_RC_FAILURE;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_load(uint32_t locality,
                            tpm_load_in *in,
                            tpm_load_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_Load, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->parent_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    other += reverse_copy_sized_buf_in((TPM2B *)other, (TPM2B *)&(in->private));

    reverse_copy_public_in(&other, &in->public);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;

    reverse_copy_out(out->obj_handle, other);

    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    out->name.t.size = sizeof(out->name.t.name);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->name), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_unseal(uint32_t locality,
                             tpm_unseal_in *in,
                             tpm_unseal_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;
    u16 size;
    
    reverse_copy_header(TPM_CC_Unseal, &in->sessions);

    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->item_handle);

    reverse_copy_sessions_in(&other, &in->sessions);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);

    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
        }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));
    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32);

    out->data.t.size = sizeof(out->data.t.buffer);
    size = reverse_copy_sized_buf_out((TPM2B *)&(out->data), (TPM2B *)other);
    if ( size == 0 )
        return TPM_RC_FAILURE;
    other += size;

    if ( !reverse_copy_sessions_out(&out->sessions, other, rsp_tag, &in->sessions) )
        return TPM_RC_FAILURE;

    return ret;
}

static uint32_t _tpm20_context_save(uint32_t locality,
                             tpm_contextsave_in *in,
                             tpm_contextsave_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;

    reverse_copy_header(TPM_CC_ContextSave, 0);
    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->saveHandle);

    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = sizeof(*out);
    
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
    }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
    }

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));

    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32); /* Skip past parameter size field */
	   
    if ( !reverse_copy_context_out(&out->context, &other) )
        return TPM_RC_FAILURE;

    return ret;
    
}

static uint32_t _tpm20_context_load(uint32_t locality,
                             tpm_contextload_in *in,
                             tpm_contextload_out *out)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;

    reverse_copy_header(TPM_CC_ContextLoad, 0);
    other = (void *)cmd_buf + CMD_HEAD_SIZE;
	
    reverse_copy_context_in(&other, &in->context);
    
    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = RSP_HEAD_SIZE + sizeof(*out);
    
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
	    return TPM_RC_FAILURE;
    }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
    }
    
    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));

    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32); /* Skip past parameter size field */
	   
    reverse_copy_out(out->loadedHandle, other);

    return ret;
}

static uint32_t _tpm20_context_flush(uint32_t locality,
                             tpm_flushcontext_in *in)
{
    u32 ret;
    u32 cmd_size, rsp_size;
    u16 rsp_tag;
    void *other;

	
    reverse_copy_header(TPM_CC_FlushContext, 0);
    other = (void *)cmd_buf + CMD_HEAD_SIZE;
    reverse_copy_in(other, in->flushHandle);
	
    /* Now set the command size field, now that we know the size of the whole command */
    cmd_size = (u8 *)other - cmd_buf;
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));

    rsp_size = RSP_HEAD_SIZE;
    
    if (g_tpm_family == TPM_IF_20_FIFO) {
        if (!tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
    }
    if (g_tpm_family == TPM_IF_20_CRB) {
        if (!tpm_submit_cmd_crb(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size))
            return TPM_RC_FAILURE;
    }
    
    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(ret));
    
    if ( ret != TPM_RC_SUCCESS )
        return ret;

    other = (void *)rsp_buf + RSP_HEAD_SIZE;
    
    reverse_copy(&rsp_tag, rsp_buf, sizeof(rsp_tag));

    if (rsp_tag == TPM_ST_SESSIONS)
        other += sizeof(u32); 
	   
    return ret;
    
}

static bool tpm20_context_flush(struct tpm_if *ti, u32 locality, TPM_HANDLE handle)
{
    tpm_flushcontext_in in;
    u32 ret;
    
    if ( ti == NULL || locality >= TPM_NR_LOCALITIES )
        return false;
    if ( handle == 0 )
        return false;
    in.flushHandle = handle;
        ret = _tpm20_context_flush(locality, &in);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: tpm2 context flush returned , return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }
    else 
        printk(TBOOT_WARN"TPM: tpm2 context flush successful, return value = %08X\n", ret);
    return true;
}	


TPM_CMD_SESSION_DATA_IN pw_session;
static void create_pw_session(TPM_CMD_SESSION_DATA_IN *ses)
{
    ses->session_handle = TPM_RS_PW;
    ses->nonce.t.size = 0;
    *((u8 *)((void *)&ses->session_attr)) = 0;
    ses->hmac.t.size = 0;
}

#define SET_PCR_SELECT_BIT( pcr_selection, pcr ) \
    (pcr_selection).pcr_select[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );
static bool tpm20_pcr_read(struct tpm_if *ti, uint32_t locality,
                           uint32_t pcr, tpm_pcr_value_t *out)
{
    tpm_pcr_read_in read_in;
    tpm_pcr_read_out read_out;
    u32 ret;

    if ( ti == NULL || out == NULL )
        return false;

    read_in.pcr_selection.count = 1;
    read_in.pcr_selection.selections[0].hash = ti->cur_alg;
    read_in.pcr_selection.selections[0].size_of_select = 3;
    read_in.pcr_selection.selections[0].pcr_select[0] = 0;
    read_in.pcr_selection.selections[0].pcr_select[1] = 0;
    read_in.pcr_selection.selections[0].pcr_select[2] = 0;
    SET_PCR_SELECT_BIT( read_in.pcr_selection.selections[0], pcr );

    ret = _tpm20_pcr_read(locality, &read_in, &read_out);
    if (ret != TPM_RC_SUCCESS) {
        printk(TBOOT_WARN"TPM: Pcr %d Read return value = %08X\n", pcr, ret);
        ti->error = ret;
        return false;
    }

    copy_hash(out,
            (tb_hash_t *)&(read_out.pcr_values.digests[0].t.buffer[0]),
            ti->cur_alg);

    return true;
}

static bool tpm20_pcr_extend(struct tpm_if *ti, uint32_t locality,
                             uint32_t pcr, const hash_list_t *in)
{
    tpm_pcr_extend_in extend_in;
    tpm_pcr_extend_out extend_out;
    u32 ret, i;

    if ( ti == NULL || in == NULL )
        return false;

    extend_in.pcr_handle = pcr;
    extend_in.sessions.num_sessions = 1;
    extend_in.sessions.sessions[0] = pw_session;

    extend_in.digests.count = in->count;
    for (i=0; i<in->count; i++) {
        extend_in.digests.digests[i].hash_alg = in->entries[i].alg;
        copy_hash((tb_hash_t *)&extend_in.digests.digests[i].digest,
                &in->entries[i].hash, in->entries[i].alg);
    }

    ret = _tpm20_pcr_extend(locality, &extend_in, &extend_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: Pcr %d extend, return value = %08X\n", pcr, ret);
        ti->error = ret;
        return false;
    }

    return true;
}

static bool tpm20_pcr_reset(struct tpm_if *ti, uint32_t locality, uint32_t pcr)
{
    tpm_pcr_reset_in reset_in;
    tpm_pcr_reset_out reset_out;
    u32 ret;

    reset_in.pcr_handle = pcr;
    reset_in.sessions.num_sessions = 1;
    reset_in.sessions.sessions[0] = pw_session;

    ret = _tpm20_pcr_reset(locality, &reset_in, &reset_out);
    if (ret != TPM_RC_SUCCESS) {
        printk(TBOOT_WARN"TPM: Pcr %d Reset return value = %08X\n", pcr, ret);
        ti->error = ret;
        return false;
    }

    return true;
}

static bool tpm20_hash(struct tpm_if *ti, u32 locality, const u8 *data,
                       u32 data_size, hash_list_t *hl)
{
    tpm_sequence_start_in start_in;
    tpm_sequence_start_out start_out;
    tpm_sequence_update_in update_in;
    tpm_sequence_update_out update_out;
    tpm_sequence_complete_in complete_in;
    tpm_sequence_complete_out complete_out;
    TPM2B_MAX_BUFFER buffer;
    u32 ret, i, j, chunk_size;

    if ( ti == NULL || data == NULL )
        return false;

    start_in.auth.t.size = 2;
    start_in.auth.t.buffer[0] = 0;
    start_in.auth.t.buffer[1] = 0xff;
    start_in.hash_alg = TPM_ALG_NULL;

    ret = _tpm20_sequence_start(locality, &start_in, &start_out);
    if (ret != TPM_RC_SUCCESS) {
        printk(TBOOT_WARN"TPM: HashSequenceStart return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }

    update_in.sessions.num_sessions = 1;
    update_in.sessions.sessions[0] = pw_session;
    update_in.sessions.sessions[0].hmac = start_in.auth;
    update_in.handle = start_out.handle;

    complete_in.pcr_handle = TPM_RH_NULL;
    complete_in.seq_handle = start_out.handle;
    complete_in.sessions.num_sessions = 2;
    create_pw_session(&complete_in.sessions.sessions[0]);
    complete_in.sessions.sessions[1] = pw_session;
    complete_in.sessions.sessions[1].hmac = start_in.auth;

    for( i=0; i<data_size; i+=chunk_size ) {
        if( (data_size-i) > MAX_DIGEST_BUFFER ) {
            chunk_size = MAX_DIGEST_BUFFER;
        } else {
            chunk_size = data_size - i;
        }

        buffer.t.size = chunk_size;
        tb_memcpy( &(buffer.t.buffer[0]), &(data[i] ), chunk_size );

        update_in.buf = buffer;
        ret = _tpm20_sequence_update(locality, &update_in, &update_out);
        if (ret != TPM_RC_SUCCESS) {
            printk(TBOOT_WARN"TPM: SequenceUpdate return value = %08X\n", ret);
            ti->error = ret;
            return false;
        }
    }

    buffer.t.size = 0;
    complete_in.buf = buffer;
    ret = _tpm20_sequence_complete(locality, &complete_in, &complete_out);
    if (ret != TPM_RC_SUCCESS) {
        printk(TBOOT_WARN"TPM: EventSequenceComplete return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }

    hl->count = complete_out.results.count;
    if ( hl->count > MAX_ALG_NUM ) {
        printk(TBOOT_WARN"TPM: EventSequenceComplete return %d digests,"
               " keep first %d\n", hl->count, MAX_ALG_NUM);
        hl->count = MAX_ALG_NUM;
    }

    for ( j=0; j<hl->count; j++ ) {
        hl->entries[j].alg = complete_out.results.digests[j].hash_alg;
        tb_memcpy(&hl->entries[j].hash, &complete_out.results.digests[j].digest,
                sizeof(hl->entries[j].hash));
    }

    return true;
}

static bool tpm20_nv_read(struct tpm_if *ti, uint32_t locality,
                          uint32_t index, uint32_t offset,
                          uint8_t *data, uint32_t *data_size)
{
    tpm_nv_read_in read_in;
    tpm_nv_read_out read_out;
    u32 ret;

    if ( ti == NULL || data_size == NULL || *data_size == 0 )
        return false;

    if ( *data_size > MAX_NV_INDEX_SIZE )
        *data_size = MAX_NV_INDEX_SIZE;

    read_in.handle = index;
    read_in.index = index;
    read_in.sessions.num_sessions = 1;
    read_in.sessions.sessions[0] = pw_session;
    read_in.offset = offset;
    read_in.size = *data_size;

    ret = _tpm20_nv_read(locality, &read_in, &read_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: read NV index %08x from offset %08x, return value = %08X\n",
                index, offset, ret);
        ti->error = ret;
        return false;
    }

    if (read_out.data.t.size == 0 || read_out.data.t.size > *data_size) {
        printk(TBOOT_WARN"TPM: data_size %x too large for buffer\n", read_out.data.t.size);
        ti->error = TPM_RC_NV_SIZE;
        return false;
    }
    *data_size = read_out.data.t.size;
    tb_memcpy(data, &read_out.data.t.buffer[0], *data_size);

    return true;
}

static bool tpm20_nv_write(struct tpm_if *ti, uint32_t locality,
                           uint32_t index, uint32_t offset,
                           const uint8_t *data, uint32_t data_size)
{
    tpm_nv_write_in write_in;
    tpm_nv_write_out write_out;
    u32 ret;

    if ( ti == NULL || data == NULL || data_size == 0 
            || data_size > MAX_NV_INDEX_SIZE )
        return false;

    write_in.handle = index;
    write_in.index = index;
    write_in.sessions.num_sessions = 1;
    write_in.sessions.sessions[0] = pw_session;
    write_in.offset = offset;
    write_in.data.t.size = data_size;
    tb_memcpy(&write_in.data.t.buffer[0], data, data_size);

    ret = _tpm20_nv_write(locality, &write_in, &write_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: write NV %08x, offset %08x, %08x bytes, return value = %08X\n",
                index, offset, data_size, ret);
        ti->error = ret;
        return false;
    }

    return true;
}

static bool tpm20_get_nvindex_size(struct tpm_if *ti, uint32_t locality,
                                   uint32_t index, uint32_t *size)
{
    tpm_nv_read_public_in public_in;
    tpm_nv_read_public_out public_out;
    u32 ret;

    if ( ti == NULL || size == NULL )
        return false;

    public_in.index = index;

    ret = _tpm20_nv_read_public(locality, &public_in, &public_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: fail to get public data of 0x%08X in TPM NV\n", index);
        ti->error = ret;
        return false;
    }

    if (index != public_out.nv_public.t.nv_public.index) {
        printk(TBOOT_WARN"TPM: Index 0x%08X is not the one expected 0x%08X\n",
                index, index);
        ti->error = TPM_RC_FAILURE;
        return false;
    }

    *size = public_out.nv_public.t.nv_public.data_size;

    return true;
}

static bool tpm20_get_nvindex_permission(struct tpm_if *ti, uint32_t locality,
                                    uint32_t index, uint32_t *attribute)
{
    tpm_nv_read_public_in public_in;
    tpm_nv_read_public_out public_out;
    u32 ret;

    if ( ti == NULL || locality >= TPM_NR_LOCALITIES
         || index == 0 || attribute == NULL )
        return false;

    public_in.index = index;

    ret = _tpm20_nv_read_public(locality, &public_in, &public_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: fail to get public data of 0x%08X in TPM NV\n", index);
        ti->error = ret;
        return false;
    }

    if (index != public_out.nv_public.t.nv_public.index) {
        printk(TBOOT_WARN"TPM: Index 0x%08X is not the one expected 0x%08X\n",
                index, index);
        ti->error = TPM_RC_FAILURE;
        return false;
    }

    *attribute = *(uint32_t*)(&public_out.nv_public.t.nv_public.attr);

    return true;
}

static bool tpm20_seal(struct tpm_if *ti, uint32_t locality,
                       uint32_t in_data_size, const uint8_t *in_data,
                       uint32_t *sealed_data_size, uint8_t *sealed_data)
{
    tpm_create_in create_in; 
    tpm_create_out create_out; 
    u32 ret;

    create_in.parent_handle = handle2048;
    create_in.sessions.num_sessions = 1;
    create_in.sessions.sessions[0] = pw_session;
    create_in.sessions.sessions[0].hmac.t.size = 2;
    create_in.sessions.sessions[0].hmac.t.buffer[0] = 0x00;
    create_in.sessions.sessions[0].hmac.t.buffer[1] = 0xff;

    create_in.public.t.public_area.type = TPM_ALG_KEYEDHASH;
    create_in.public.t.public_area.name_alg = ti->cur_alg;
    create_in.public.t.public_area.auth_policy.t.size = 0;
    *(u32 *)&create_in.public.t.public_area.object_attr = 0;
    create_in.public.t.public_area.object_attr.userWithAuth = 1;
    create_in.public.t.public_area.object_attr.noDA = 1;
    create_in.public.t.public_area.param.keyed_hash.scheme.scheme = TPM_ALG_NULL;
    create_in.public.t.public_area.unique.keyed_hash.t.size = 0;

    COMPILE_TIME_ASSERT( sizeof(auth_str) - 1 <=
            sizeof(create_in.sensitive.t.sensitive.user_auth.t.buffer) );
    create_in.sensitive.t.sensitive.user_auth.t.size = sizeof(auth_str) - 1;
    tb_memcpy(&(create_in.sensitive.t.sensitive.user_auth.t.buffer[0]),
            auth_str, sizeof(auth_str)-1);
    if ( in_data_size >
            sizeof(create_in.sensitive.t.sensitive.data.t.buffer) ) {
        printk(TBOOT_WARN"TPM: input data size to seal is too large:"
               " %08X(%08x)\n",
               in_data_size,
               sizeof(create_in.sensitive.t.sensitive.data.t.buffer));
        return false;
    }
    create_in.sensitive.t.sensitive.data.t.size = in_data_size;
    tb_memcpy(&(create_in.sensitive.t.sensitive.data.t.buffer[0]),
            in_data, in_data_size); 

    create_in.outside_info.t.size = 0;
    create_in.creation_pcr.count = 0;
    tb_memset(&create_out, 0, sizeof(create_out));

    ret = _tpm20_create(locality, &create_in, &create_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: Create return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }
    *sealed_data_size = sizeof(create_out);
    tb_memcpy(sealed_data, &create_out, *sealed_data_size); 

    return true;
}

static bool tpm20_unseal(struct tpm_if *ti, uint32_t locality,
                         uint32_t sealed_data_size, const uint8_t *sealed_data,
                         uint32_t *secret_size, uint8_t *secret)
{
    tpm_load_in load_in; 
    tpm_load_out load_out; 
    tpm_unseal_in unseal_in; 
    tpm_unseal_out unseal_out; 
    u32 ret;

    if ( ti == NULL || locality >= TPM_NR_LOCALITIES
         || sealed_data_size == 0 || sealed_data == NULL )
        return false;

    /* For TPM 2.0, the object will need to be loaded before it may be used.*/
    load_in.parent_handle = handle2048;
    load_in.sessions.num_sessions = 1;
    load_in.sessions.sessions[0] = pw_session;
    load_in.sessions.sessions[0].hmac.t.size = 2;
    load_in.sessions.sessions[0].hmac.t.buffer[0] = 0x00;
    load_in.sessions.sessions[0].hmac.t.buffer[1] = 0xff;
    load_in.private = ((tpm_create_out *)sealed_data)->private;
    load_in.public = ((tpm_create_out *)sealed_data)->public;

    ret = _tpm20_load(locality, &load_in, &load_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: Load return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }

    unseal_in.sessions.num_sessions = 1;
    unseal_in.sessions.sessions[0] = pw_session;
    unseal_in.sessions.sessions[0].hmac.t.size = sizeof(auth_str) - 1;
    tb_memcpy(&(unseal_in.sessions.sessions[0].hmac.t.buffer[0]),
            auth_str, sizeof(auth_str)-1);
    unseal_in.item_handle = load_out.obj_handle;

    ret = _tpm20_unseal(locality, &unseal_in, &unseal_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: Unseal return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }

    *secret_size = unseal_out.data.t.size;
    tb_memcpy(secret, &(unseal_out.data.t.buffer[0]), *secret_size);

    if ( !tpm20_context_flush(ti, locality, load_out.obj_handle) ) {
        printk(TBOOT_WARN"TPM: Failed to flush context\n");
        ti->error = ret;
        return false;
    }

    return true;
}

static bool tpm20_verify_creation(struct tpm_if *ti, uint32_t sealed_data_size, uint8_t *sealed_data)
{
    if ( ti == NULL || sealed_data_size == 0 || sealed_data == NULL )
        return false;

    return true;
}

static bool tpm20_get_random(struct tpm_if *ti, uint32_t locality,
                             uint8_t *random_data, uint32_t *data_size)
{
    tpm_get_random_in random_in; 
    tpm_get_random_out random_out; 
    u32 ret, out_size, requested_size;
    static bool first_attempt;

    if ( random_data == NULL || data_size == NULL || *data_size == 0 )
        return false;

    first_attempt = true;
    requested_size = *data_size;

    random_in.bytes_req = *data_size;

    ret = _tpm20_get_random(locality, &random_in, &random_out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: get random 0x%x bytes, return value = %08X\n", *data_size, ret);
        ti->error = ret;
        return false;
    }

    out_size = random_out.random_bytes.t.size;
    if (out_size > 0)
        tb_memcpy(random_data, &(random_out.random_bytes.t.buffer[0]), out_size);
    *data_size = out_size;

    /* if TPM doesn't return all requested random bytes, try one more time */
    if ( out_size < requested_size ) {
        printk(TBOOT_WARN"requested 0x%x random bytes but only got 0x%x\n", requested_size, out_size);
        /* we're only going to try twice */
        if ( first_attempt ) {
            first_attempt = false;
            uint32_t second_size = requested_size - out_size;
            printk(TBOOT_WARN"trying one more time to get remaining 0x%x bytes\n", second_size);
            random_in.bytes_req = second_size;

            ret = _tpm20_get_random(locality, &random_in, &random_out);
            if ( ret != TPM_RC_SUCCESS ) {
                printk(TBOOT_WARN"TPM: get random 0x%x bytes, return value = %08X\n",
                        *data_size, ret);
                ti->error = ret;
                return false;
            }

            out_size = random_out.random_bytes.t.size;
            if (out_size > 0)
                tb_memcpy(random_data+*data_size, 
                        &(random_out.random_bytes.t.buffer[0]), out_size);
            *data_size += out_size;
        }
    }

    return true;
}

static uint32_t tpm20_save_state(struct tpm_if *ti, uint32_t locality)
{
    u32 ret;

    if ( ti == NULL )
        return false;

    ret = _tpm20_shutdown(locality, TPM_SU_STATE);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: Shutdown, return value = %08X\n", ret);
        ti->error = ret;
    }

    return ret;
}

#define TPM_NR_PCRS             24
#define TPM_PCR_RESETABLE_MIN   16
static bool tpm20_cap_pcrs(struct tpm_if *ti, u32 locality, int pcr)
{
    bool was_capped[TPM_NR_PCRS] = {false};
    hash_list_t cap_val;   /* use whatever val is on stack */

    if ( ti == NULL || locality >= TPM_NR_LOCALITIES || pcr == 0 )
        return false;

    cap_val.count = ti->banks;
    for (unsigned int i=0; i<ti->banks; i++)
        cap_val.entries[i].alg = ti->algs_banks[i];

    if (pcr >= 0) {
        tpm20_pcr_extend(ti, locality, pcr, &cap_val);
        return true;
    }

    /* ensure PCRs 17 + 18 are always capped */
    tpm20_pcr_extend(ti, locality, 17, &cap_val);
    tpm20_pcr_extend(ti, locality, 18, &cap_val);
    was_capped[17] = was_capped[18] = true;

    /* also cap every dynamic PCR we extended (only once) */
    /* don't cap static PCRs since then they would be wrong after S3 resume */
    tb_memset(&was_capped, true, TPM_PCR_RESETABLE_MIN*sizeof(bool));
    for ( int i = 0; i < g_pre_k_s3_state.num_vl_entries; i++ ) {
        if ( !was_capped[g_pre_k_s3_state.vl_entries[i].pcr] ) {
            tpm20_pcr_extend(ti, locality, g_pre_k_s3_state.vl_entries[i].pcr, &cap_val);
            was_capped[g_pre_k_s3_state.vl_entries[i].pcr] = true;
        }
    }

    printk(TBOOT_INFO"cap'ed dynamic PCRs\n");
    return true;
}

static bool alg_is_supported(u16 alg)
{
    for (int i = 0; i < tboot_alg_list_count; i++) {
        if (alg == tboot_alg_list[i])
            return true;
    }

    return false;
}
__data tpm_contextsave_out tpm2_context_saved;

static bool tpm20_context_save(struct tpm_if *ti, u32 locality, TPM_HANDLE handle, void *context_saved)
{
    tpm_contextsave_in in;
    tpm_contextsave_out out;
    u32 ret;

    if ( ti == NULL || locality >= TPM_NR_LOCALITIES ){
        return false;
    }
    if ( handle == 0 )
	return false;
    in.saveHandle = handle;
    ret =_tpm20_context_save(locality, &in, &out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: tpm2 context save failed, return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }
    else 
	 printk(TBOOT_WARN"TPM: tpm2 context save successful, return value = %08X\n", ret);
    tb_memcpy((tpm_contextsave_out *)context_saved, &out, sizeof(tpm_contextsave_out));
    return true;
}	

static bool tpm20_context_load(struct tpm_if *ti, u32 locality, void  *context_saved, TPM_HANDLE *handle)
{
    tpm_contextload_in in;
    tpm_contextload_out out;
    u32 ret;

    if ( ti == NULL || locality >= TPM_NR_LOCALITIES )
        return false;
	
    tb_memcpy(&in, (tpm_contextsave_out *)context_saved, sizeof(tpm_contextsave_out));

    ret = _tpm20_context_load(locality, &in, &out);
    if ( ret != TPM_RC_SUCCESS ) {
        printk(TBOOT_WARN"TPM: tpm2 context load failed, return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }
    else
	printk(TBOOT_WARN"TPM: tpm2 context load successful, return value = %08X\n", ret);
    *handle = out.loadedHandle;
    return true;
}	

static bool tpm20_init(struct tpm_if *ti)
{
    u32 ret;
    unsigned int i;
    tpm_info_list_t *info_list = get_tpm_info_list(g_sinit);

    if ( ti == NULL || info_list == NULL )
        return false;
   
    if (!txt_is_launched())
        ti->cur_loc = 0;
    else
        ti->cur_loc = 2;

    /* init version */
    ti->major = TPM20_VER_MAJOR;
    ti->minor = TPM20_VER_MINOR;

    /* init timeouts value */
    ti->timeout.timeout_a = TIMEOUT_A;
    ti->timeout.timeout_b = TIMEOUT_B;
    ti->timeout.timeout_c = TIMEOUT_C;
    ti->timeout.timeout_d = TIMEOUT_D;

    /* get pcr extend policy from cmdline */
    get_tboot_extpol();
    if (info_list->capabilities.tpm_nv_index_set == 0){
        /* init NV index */
        ti->tb_policy_index = 0x1200001;
        ti->lcp_own_index = 0x1400001;
        ti->tb_err_index = 0x1200002;
        ti->sgx_svn_index = 0x01800004;
    }
    else {
        ti->tb_policy_index = 0x01c10131;
        ti->lcp_own_index = 0x01c10106;
        ti->tb_err_index = 0x01c10132;
        ti->sgx_svn_index = 0x01c10104;
    }
    /* create one common password sesson*/
    create_pw_session(&pw_session);

    /* init supported alg list for banks */
    tpm_pcr_event_in event_in;
    tpm_pcr_event_out event_out;
    event_in.pcr_handle = 16;
    event_in.sessions.num_sessions = 1;
    event_in.sessions.sessions[0] = pw_session;
    event_in.data.t.size = 4;
    event_in.data.t.buffer[0] = 0;
    event_in.data.t.buffer[1] = 0xff;
    event_in.data.t.buffer[2] = 0x55;
    event_in.data.t.buffer[3] = 0xaa;
    ret = _tpm20_pcr_event(ti->cur_loc, &event_in, &event_out);
    if (ret != TPM_RC_SUCCESS) {
        printk(TBOOT_WARN"TPM: PcrEvent not successful, return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }
    ti->banks = event_out.digests.count;
    printk(TBOOT_INFO"TPM: supported bank count = %d\n", ti->banks);
    for (i=0; i<ti->banks; i++) {
        ti->algs_banks[i] = event_out.digests.digests[i].hash_alg;;
        printk(TBOOT_INFO"TPM: bank alg = %08x\n", ti->algs_banks[i]);
    }

    /* init supported alg list */
    ti->alg_count = 0;
    for (i=0; i<ti->banks; i++) {
        if (alg_is_supported(ti->algs_banks[i])) {
            ti->algs[ti->alg_count] = ti->algs_banks[i];
            ti->alg_count++;
        }
    }
    printk(TBOOT_INFO"tboot: supported alg count = %d\n", ti->alg_count);
    for (unsigned int i=0; i<ti->alg_count; i++)
        printk(TBOOT_INFO"tboot: hash alg = %08X\n", ti->algs[i]);

    /* reset debug PCR 16 */
    if (!tpm20_pcr_reset(ti, ti->cur_loc, 16)){
        printk(TBOOT_WARN"TPM: tpm20_pcr_reset failed...\n");
	return false;
    }

    if (handle2048 != 0)
        goto out;

    /* create primary object as parent obj for seal */
    tpm_create_primary_in primary_in;
    tpm_create_primary_out primary_out;
    primary_in.primary_handle = TPM_RH_NULL;
    primary_in.sessions.num_sessions = 1;
    primary_in.sessions.sessions[0].session_handle = TPM_RS_PW;
    primary_in.sessions.sessions[0].nonce.t.size = 0;
    primary_in.sessions.sessions[0].hmac.t.size = 0;
    *((u8 *)((void *)&primary_in.sessions.sessions[0].session_attr)) = 0;

    primary_in.sensitive.t.sensitive.user_auth.t.size = 2;
    primary_in.sensitive.t.sensitive.user_auth.t.buffer[0] = 0x00;
    primary_in.sensitive.t.sensitive.user_auth.t.buffer[1] = 0xff;
    primary_in.sensitive.t.sensitive.data.t.size = 0;

    primary_in.public.t.public_area.type = TPM_ALG_RSA;
    primary_in.public.t.public_area.name_alg = ti->cur_alg;
    *(u32 *)&primary_in.public.t.public_area.object_attr = 0;
    primary_in.public.t.public_area.object_attr.restricted = 1;
    primary_in.public.t.public_area.object_attr.userWithAuth = 1;
    primary_in.public.t.public_area.object_attr.decrypt = 1;
    primary_in.public.t.public_area.object_attr.fixedTPM = 1;
    primary_in.public.t.public_area.object_attr.fixedParent = 1;
    primary_in.public.t.public_area.object_attr.noDA = 1;
    primary_in.public.t.public_area.object_attr.sensitiveDataOrigin = 1;
    primary_in.public.t.public_area.auth_policy.t.size = 0;
    primary_in.public.t.public_area.param.rsa.symmetric.alg = TPM_ALG_AES;
    primary_in.public.t.public_area.param.rsa.symmetric.key_bits.aes= 128;
    primary_in.public.t.public_area.param.rsa.symmetric.mode.aes = TPM_ALG_CFB;
    primary_in.public.t.public_area.param.rsa.scheme.scheme = TPM_ALG_NULL;
    primary_in.public.t.public_area.param.rsa.key_bits = 2048;
    primary_in.public.t.public_area.param.rsa.exponent = 0;
    primary_in.public.t.public_area.unique.keyed_hash.t.size = 0;
    primary_in.outside_info.t.size = 0;
    primary_in.creation_pcr.count = 0;
    
    printk(TBOOT_DETA"TPM:CreatePrimary creating hierarchy handle = %08X\n", primary_in.primary_handle);
    ret = _tpm20_create_primary(ti->cur_loc, &primary_in, &primary_out);
    if (ret != TPM_RC_SUCCESS) {
        printk(TBOOT_WARN"TPM: CreatePrimary return value = %08X\n", ret);
        ti->error = ret;
        return false;
    }
    handle2048 = primary_out.obj_handle;
 
    printk(TBOOT_DETA"TPM:CreatePrimary created object handle = %08X\n", handle2048);
out:
    tpm_print(ti);
    return true;
}

const struct tpm_if_fp tpm_20_if_fp = {
    .init = tpm20_init,
    .pcr_read = tpm20_pcr_read,
    .pcr_extend = tpm20_pcr_extend,
    .hash = tpm20_hash,
    .pcr_reset = tpm20_pcr_reset,
    .nv_read = tpm20_nv_read,
    .nv_write = tpm20_nv_write,
    .get_nvindex_size = tpm20_get_nvindex_size,
    .get_nvindex_permission = tpm20_get_nvindex_permission,
    .seal = tpm20_seal,
    .unseal = tpm20_unseal,
    .verify_creation = tpm20_verify_creation,
    .get_random = tpm20_get_random,
    .save_state = tpm20_save_state,
    .cap_pcrs = tpm20_cap_pcrs,
    .context_save = tpm20_context_save,
    .context_load = tpm20_context_load,
    .context_flush = tpm20_context_flush,
};


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
