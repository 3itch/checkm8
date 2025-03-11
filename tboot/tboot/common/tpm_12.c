/*
 * tpm_12.c: TPM1.2-related support functions
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
#include <sha1.h>
#include <integrity.h>

/*
 * return code:
 * The TPM has five types of return code. One indicates successful operation
 * and four indicate failure.
 * TPM_SUCCESS (00000000) indicates successful execution.
 * The failure reports are:
 *      TPM defined fatal errors (00000001 to 000003FF)
 *      vendor defined fatal errors (00000400 to 000007FF)
 *      TPM defined non-fatal errors (00000800 to 00000BFF)
 *      vendor defined non-fatal errors (00000C00 to 00000FFF).
 * Here only give definitions for a few commonly used return code.
 */
#define TPM_BASE                0x00000000
#define TPM_NON_FATAL           0x00000800
#define TPM_SUCCESS             TPM_BASE
#define TPM_BADINDEX            (TPM_BASE + 2)
#define TPM_BAD_PARAMETER       (TPM_BASE + 3)
#define TPM_DEACTIVATED         (TPM_BASE + 6)
#define TPM_DISABLED            (TPM_BASE + 7)
#define TPM_FAIL                (TPM_BASE + 9)
#define TPM_BAD_ORDINAL         (TPM_BASE + 10)
#define TPM_NOSPACE             (TPM_BASE + 17)
#define TPM_NOTRESETABLE        (TPM_BASE + 50)
#define TPM_NOTLOCAL            (TPM_BASE + 51)
#define TPM_BAD_LOCALITY        (TPM_BASE + 61)
#define TPM_READ_ONLY           (TPM_BASE + 62)
#define TPM_NOT_FULLWRITE       (TPM_BASE + 70)
#define TPM_RETRY               (TPM_BASE + TPM_NON_FATAL)

typedef uint8_t tpm_locality_selection_t;
#define TPM_LOC_ZERO    0x01
#define TPM_LOC_ONE     0x02
#define TPM_LOC_TWO     0x04
#define TPM_LOC_THREE   0x08
#define TPM_LOC_FOUR    0x10
#define TPM_LOC_RSVD    0xE0

/* ~5 secs are required for Infineon that requires this, so leave some extra */
#define MAX_SAVESTATE_RETRIES       60

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND   0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND   0x00C3
#define TPM_ORD_PCR_EXTEND          0x00000014
#define TPM_ORD_PCR_READ            0x00000015
#define TPM_ORD_PCR_RESET           0x000000C8
#define TPM_ORD_NV_READ_VALUE       0x000000CF
#define TPM_ORD_NV_WRITE_VALUE      0x000000CD
#define TPM_ORD_GET_CAPABILITY      0x00000065
#define TPM_ORD_SEAL                0x00000017
#define TPM_ORD_UNSEAL              0x00000018
#define TPM_ORD_OSAP                0x0000000B
#define TPM_ORD_OIAP                0x0000000A
#define TPM_ORD_SAVE_STATE          0x00000098
#define TPM_ORD_GET_RANDOM          0x00000046

#define TPM_TAG_PCR_INFO_LONG       0x0006
#define TPM_TAG_STORED_DATA12       0x0016

/*
 * specified as minimum cmd buffer size should be supported by all 1.2 TPM
 * device in the TCG_PCClientTPMSpecification_1-20_1-00_FINAL.pdf
 */
#define TPM_CMD_SIZE_MAX        768
#define TPM_RSP_SIZE_MAX        768

/*
 * The _tpm12_submit_cmd function comes with 2 global buffers: cmd_buf & rsp_buf.
 * Before calling, caller should fill cmd arguements into cmd_buf via
 * WRAPPER_IN_BUF macro. After calling, caller should fetch result from
 * rsp_buffer via WRAPPER_OUT_BUF macro.
 * cmd_buf content:
 *  0   1   2   3   4   5   6   7   8   9   10  ...
 * -------------------------------------------------------------
 * |  TAG  |     SIZE      |    ORDINAL    |    arguments ...
 * -------------------------------------------------------------
 * rsp_buf content:
 *  0   1   2   3   4   5   6   7   8   9   10  ...
 * -------------------------------------------------------------
 * |  TAG  |     SIZE      |  RETURN CODE  |    other data ...
 * -------------------------------------------------------------
 *
 *   locality : TPM locality (0 - 4)
 *   tag      : The TPM command tag
 *   cmd      : The TPM command ordinal
 *   arg_size : Size of argument data.
 *   out_size : IN/OUT paramter. The IN is the expected size of out data;
 *              the OUT is the size of output data within out buffer.
 *              The out_size MUST NOT be NULL.
 *   return   : TPM_SUCCESS for success, for other error code, refer to the .h
 */
static uint8_t     cmd_buf[TPM_CMD_SIZE_MAX];
static uint8_t     rsp_buf[TPM_RSP_SIZE_MAX];
#define WRAPPER_IN_BUF          (cmd_buf + CMD_HEAD_SIZE)
#define WRAPPER_OUT_BUF         (rsp_buf + RSP_HEAD_SIZE)
#define WRAPPER_IN_MAX_SIZE     (TPM_CMD_SIZE_MAX - CMD_HEAD_SIZE)
#define WRAPPER_OUT_MAX_SIZE    (TPM_RSP_SIZE_MAX - RSP_HEAD_SIZE)

static uint32_t _tpm12_submit_cmd(uint32_t locality, uint16_t tag, uint32_t cmd,  uint32_t arg_size, uint32_t *out_size)
{
    uint32_t    ret;
    uint32_t    cmd_size, rsp_size = 0;

    if ( out_size == NULL ) {
        printk(TBOOT_WARN"TPM: invalid param for _tpm12_submit_cmd()\n");
        return TPM_BAD_PARAMETER;
    }

    /*
     * real cmd size should add 10 more bytes:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for ordinal
     */
    cmd_size = CMD_HEAD_SIZE + arg_size;

    if ( cmd_size > TPM_CMD_SIZE_MAX ) {
        printk(TBOOT_WARN"TPM: cmd exceeds the max supported size.\n");
        return TPM_BAD_PARAMETER;
    }

    /* copy tag, size & ordinal into buf in a reversed byte order */
    reverse_copy(cmd_buf, &tag, sizeof(tag));
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));
    reverse_copy(cmd_buf + CMD_CC_OFFSET, &cmd, sizeof(cmd));

    rsp_size = RSP_HEAD_SIZE + *out_size;
    rsp_size = (rsp_size > TPM_RSP_SIZE_MAX) ? TPM_RSP_SIZE_MAX: rsp_size;
    if ( !tpm_submit_cmd(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size) ) return TPM_FAIL;

    /*
     * should subtract 10 bytes from real response size:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for return code
     */
    rsp_size -= (rsp_size > RSP_HEAD_SIZE) ? RSP_HEAD_SIZE : rsp_size;

    reverse_copy(&ret, rsp_buf + RSP_RST_OFFSET, sizeof(uint32_t));
    if ( ret != TPM_SUCCESS )     return ret;

    if ( *out_size == 0 || rsp_size == 0 )        *out_size = 0;
    else
        *out_size = (rsp_size < *out_size) ? rsp_size : *out_size;

    return ret;
}

static inline uint32_t tpm12_submit_cmd(uint32_t locality, uint32_t cmd, uint32_t arg_size, uint32_t *out_size)
{
   return  _tpm12_submit_cmd(locality, TPM_TAG_RQU_COMMAND, cmd, arg_size, out_size);
}

static inline uint32_t tpm12_submit_cmd_auth1(uint32_t locality, uint32_t cmd,
                                            uint32_t arg_size, uint32_t *out_size)
{
   return  _tpm12_submit_cmd(locality, TPM_TAG_RQU_AUTH1_COMMAND, cmd,
                           arg_size, out_size);
}

static inline uint32_t tpm12_submit_cmd_auth2(uint32_t locality, uint32_t cmd,
                                            uint32_t arg_size, uint32_t *out_size)
{
   return  _tpm12_submit_cmd(locality, TPM_TAG_RQU_AUTH2_COMMAND, cmd,
                           arg_size, out_size);
}

typedef struct __packed {
    uint8_t     digest[SHA1_LENGTH];
} tpm12_digest_t;

#define TPM_NR_PCRS             24
static bool tpm12_pcr_read(struct tpm_if *ti, uint32_t locality,
                           uint32_t pcr, tpm_pcr_value_t *out)
{
    uint32_t ret, out_size = sizeof(*out);

    if ( out == NULL || pcr >= TPM_NR_PCRS) {
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    /* copy pcr into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));

    ret = tpm12_submit_cmd(locality, TPM_ORD_PCR_READ, sizeof(pcr), &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: Pcr %d Read return value = %08X\n", pcr, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: Pcr %d Read return value = %08X\n", pcr, ret);
        ti->error = ret;
        return false;
    }

    if ( out_size > sizeof(*out) )
        out_size = sizeof(*out);
    tb_memcpy((void *)out, WRAPPER_OUT_BUF, out_size);

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, ((tpm12_digest_t *)out)->digest, out_size);
    }
#endif

    return true;
}

static bool _tpm12_pcr_extend(struct tpm_if *ti, uint32_t locality,
                             uint32_t pcr, const tpm_digest_t* in)
{
    uint32_t ret, in_size = 0, out_size = 0;

    if ( ti == NULL )
        return false;

    if ( in == NULL || pcr >= TPM_NR_PCRS){
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    /* copy pcr into buf in reversed byte order, then copy in data */
    reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));
    in_size += sizeof(pcr);
    tb_memcpy(WRAPPER_IN_BUF + in_size, (void *)in, sizeof(*(tpm12_digest_t *)in));
    in_size += sizeof(*(tpm12_digest_t *)in);

    ret = tpm12_submit_cmd(locality, TPM_ORD_PCR_EXTEND, in_size, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: Pcr %d extend, return value = %08X\n", pcr, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: Pcr %d extend, return value = %08X\n", pcr, ret);
        ti->error = ret;
        return false;
    }

    return true;
}

static bool tpm12_pcr_extend(struct tpm_if *ti, uint32_t locality,
                             uint32_t pcr, const hash_list_t *in)
{
    tpm_digest_t digest;

    if ( ti == NULL )
        return false;

    if ( in == NULL || in->count != 1 ||
            in->entries[0].alg != TB_HALG_SHA1 ) {
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    digest = in->entries[0].hash;

    return _tpm12_pcr_extend(ti, locality, pcr, &digest);
}

typedef struct __packed {
    uint16_t    size_of_select;
    uint8_t     pcr_select[3];
} tpm_pcr_selection_t;

/* PCRs lower than 16 are not resetable */
#define TPM_PCR_RESETABLE_MIN           16
static bool tpm12_pcr_reset(struct tpm_if *ti, uint32_t locality, uint32_t pcr)
{
    uint32_t ret, in_size, out_size = 0;
    uint16_t size_of_select;
    tpm_pcr_selection_t pcr_sel = {0,{0,}};

    if ( ti == NULL )
        return false;

    if ( pcr >= TPM_NR_PCRS || pcr < TPM_PCR_RESETABLE_MIN ) {
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    /* the pcr_sel.pcr_select[size_of_select - 1] should not be 0 */
    size_of_select = pcr / 8 + 1;
    reverse_copy(&pcr_sel.size_of_select, &size_of_select,
                 sizeof(size_of_select));
    pcr_sel.pcr_select[pcr / 8] = 1 << (pcr % 8);

    in_size = sizeof(pcr_sel);
    tb_memcpy(WRAPPER_IN_BUF, (void *)&pcr_sel, in_size);

    ret = tpm12_submit_cmd(locality, TPM_ORD_PCR_RESET, in_size, &out_size);
    if ( ret != TPM_SUCCESS ) {
        ti->error = ret;
        return false;
    }

    printk(TBOOT_DETA"TPM: Pcr %d reset, return value = %08X\n", pcr, ret);

    return true;
}

#define TPM_NV_READ_VALUE_DATA_SIZE_MAX  (TPM_RSP_SIZE_MAX - 14)
static bool tpm12_nv_read_value(struct tpm_if *ti, uint32_t locality,
                                uint32_t index, uint32_t offset,
                                uint8_t *data, uint32_t *data_size)
{
    uint32_t ret, in_size = 0, out_size;

    if ( ti == NULL )
        return false;

    if ( data == NULL || data_size == NULL || *data_size == 0 ) {
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }
    if ( *data_size > TPM_NV_READ_VALUE_DATA_SIZE_MAX )
        *data_size = TPM_NV_READ_VALUE_DATA_SIZE_MAX;

    /* copy the index, offset and *data_size into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &index, sizeof(index));
    in_size += sizeof(index);
    reverse_copy(WRAPPER_IN_BUF + in_size, &offset, sizeof(offset));
    in_size += sizeof(offset);
    reverse_copy(WRAPPER_IN_BUF + in_size, data_size, sizeof(*data_size));
    in_size += sizeof(*data_size);

    out_size = *data_size + sizeof(*data_size);
    ret = tpm12_submit_cmd(locality, TPM_ORD_NV_READ_VALUE, in_size, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: read nv index %08x from offset %08x, return value = %08X\n",
           index, offset, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: read nv index %08x offset %08x, return value = %08X\n",
               index, offset, ret);
        ti->error = ret;
        return false;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if ( out_size <= sizeof(*data_size) ) {
        *data_size = 0;
        return true;
    }

    out_size -= sizeof(*data_size);
    reverse_copy(data_size, WRAPPER_OUT_BUF, sizeof(*data_size));
    *data_size = (*data_size > out_size) ? out_size : *data_size;
    if( *data_size > 0 )
        tb_memcpy(data, WRAPPER_OUT_BUF + sizeof(*data_size), *data_size);

    return true;
}

#define TPM_NV_WRITE_VALUE_DATA_SIZE_MAX (TPM_CMD_SIZE_MAX - 22)
static bool tpm12_nv_write_value(struct tpm_if *ti, uint32_t locality,
                                 uint32_t index, uint32_t offset,
                                 const uint8_t *data, uint32_t data_size)
{
    uint32_t ret, in_size = 0, out_size = 0;

    if ( ti == NULL )
        return false;

    if ( data == NULL || data_size == 0
         || data_size > TPM_NV_WRITE_VALUE_DATA_SIZE_MAX ) {
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    /* copy index, offset and *data_size into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &index, sizeof(index));
    in_size += sizeof(index);
    reverse_copy(WRAPPER_IN_BUF + in_size, &offset, sizeof(offset));
    in_size += sizeof(offset);
    reverse_copy(WRAPPER_IN_BUF + in_size, &data_size, sizeof(data_size));
    in_size += sizeof(data_size);
    tb_memcpy(WRAPPER_IN_BUF + in_size, data, data_size);
    in_size += data_size;

    ret = tpm12_submit_cmd(locality, TPM_ORD_NV_WRITE_VALUE,
                         in_size, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: write nv %08x, offset %08x, %08x bytes, return = %08X\n",
           index, offset, data_size, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: write nv %08x, offset %08x, %08x bytes, return = %08X\n",
               index, offset, data_size, ret);
        ti->error = ret;
        return false;
    }

    return true;
}

#define TPM_CAP_VERSION_VAL 0x1A

typedef uint16_t tpm_structure_tag_t;

typedef struct __packed {
   uint8_t  major;
   uint8_t  minor;
   uint8_t  rev_major;
   uint8_t  rev_minor;
} tpm_version_t;

typedef struct __packed {
    tpm_structure_tag_t tag;
    tpm_version_t       version;
    uint16_t            specLevel;
    uint8_t             errataRev;
    uint8_t             tpmVendorID[4];
    uint16_t            vendorSpecificSize;
    uint8_t             vendorSpecific[];
} tpm_cap_version_info_t;

#define HMAC_BLOCK_SIZE     64
#define HMAC_OUTPUT_SIZE    20

static bool hmac(const uint8_t key[HMAC_OUTPUT_SIZE], const uint8_t *msg,
                 uint32_t len, uint8_t md[HMAC_OUTPUT_SIZE])
{
    uint8_t ipad[HMAC_BLOCK_SIZE], opad[HMAC_BLOCK_SIZE];
    uint32_t i;
    SHA_CTX ctx;

    COMPILE_TIME_ASSERT(HMAC_OUTPUT_SIZE <= HMAC_BLOCK_SIZE);

    for ( i = 0; i < HMAC_BLOCK_SIZE; i++ ) {
        ipad[i] = 0x36;
        opad[i] = 0x5C;
    }

    for ( i = 0; i < HMAC_OUTPUT_SIZE; i++ ) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, ipad, HMAC_BLOCK_SIZE);
    SHA1_Update(&ctx, msg, len);
    SHA1_Final(md, &ctx);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, opad, HMAC_BLOCK_SIZE);
    SHA1_Update(&ctx, md, HMAC_OUTPUT_SIZE);
    SHA1_Final(md, &ctx);

    return true;
}

typedef uint16_t tpm_entity_type_t;
typedef uint32_t tpm_authhandle_t;
typedef struct __packed {
    uint8_t     nonce[20];
} tpm_nonce_t;

#define TPM_ET_SRK              0x0004
#define TPM_KH_SRK              0x40000000

typedef uint32_t tpm_key_handle_t;

typedef tpm12_digest_t tpm_composite_hash_t;
typedef struct __packed {
    tpm_structure_tag_t         tag;
    tpm_locality_selection_t    locality_at_creation;
    tpm_locality_selection_t    locality_at_release;
    tpm_pcr_selection_t         creation_pcr_selection;
    tpm_pcr_selection_t         release_pcr_selection;
    tpm_composite_hash_t        digest_at_creation;
    tpm_composite_hash_t        digest_at_release;
} tpm_pcr_info_long_t;

typedef uint8_t tpm_authdata_t[20];
typedef tpm_authdata_t tpm_encauth_t;

typedef struct __packed {
    tpm_structure_tag_t         tag;
    tpm_entity_type_t           et;
    uint32_t                    seal_info_size;
} tpm_stored_data12_header_t;

typedef struct __packed {
    tpm_stored_data12_header_t  header;
    uint32_t                    enc_data_size;
    uint8_t                     enc_data[];
} tpm_stored_data12_short_t;

typedef struct __packed {
    tpm_stored_data12_header_t  header;
    tpm_pcr_info_long_t         seal_info;
    uint32_t                    enc_data_size;
    uint8_t                     enc_data[];
} tpm_stored_data12_t;

#define UNLOAD_INTEGER(buf, offset, var) {\
    reverse_copy(buf + offset, &(var), sizeof(var));\
    offset += sizeof(var);\
}

#define UNLOAD_BLOB(buf, offset, blob, size) {\
    tb_memcpy(buf + offset, blob, size);\
    offset += size;\
}

#define UNLOAD_BLOB_TYPE(buf, offset, blob) \
    UNLOAD_BLOB(buf, offset, blob, sizeof(*(blob)))

#define UNLOAD_PCR_SELECTION(buf, offset, sel) {\
    UNLOAD_INTEGER(buf, offset, (sel)->size_of_select);\
    UNLOAD_BLOB(buf, offset, (sel)->pcr_select, (sel)->size_of_select);\
}

#define UNLOAD_PCR_INFO_LONG(buf, offset, info) {\
    UNLOAD_INTEGER(buf, offset, (info)->tag);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_creation);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_release);\
    UNLOAD_PCR_SELECTION(buf, offset, &(info)->creation_pcr_selection);\
    UNLOAD_PCR_SELECTION(buf, offset, &(info)->release_pcr_selection);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_creation);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_release);\
}

#define UNLOAD_STORED_DATA12(buf, offset, hdr) {\
   UNLOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->tag);\
   UNLOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->et);\
   UNLOAD_INTEGER(buf, offset,\
                  ((tpm_stored_data12_header_t *)(hdr))->seal_info_size);\
   if ( ((tpm_stored_data12_header_t *)(hdr))->seal_info_size == 0 ) {\
       UNLOAD_INTEGER(buf, offset,\
                      ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
       UNLOAD_BLOB(buf, offset,\
                   ((tpm_stored_data12_short_t *)hdr)->enc_data,\
                   ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
   }\
   else {\
       UNLOAD_PCR_INFO_LONG(buf, offset,\
                            &((tpm_stored_data12_t *)hdr)->seal_info);\
       UNLOAD_INTEGER(buf, offset,\
                      ((tpm_stored_data12_t *)hdr)->enc_data_size);\
       UNLOAD_BLOB(buf, offset,\
                   ((tpm_stored_data12_t *)hdr)->enc_data,\
                   ((tpm_stored_data12_t *)hdr)->enc_data_size);\
   }\
}

#define LOAD_INTEGER(buf, offset, var) {\
    reverse_copy(&(var), buf + offset, sizeof(var));\
    offset += sizeof(var);\
}

#define LOAD_BLOB(buf, offset, blob, size) {\
    tb_memcpy(blob, buf + offset, size);\
    offset += size;\
}

#define LOAD_BLOB_TYPE(buf, offset, blob) \
    LOAD_BLOB(buf, offset, blob, sizeof(*(blob)))

#define LOAD_PCR_SELECTION(buf, offset, sel, size) while (1) {\
    if ( size < sizeof(tpm_pcr_selection_t) ) {\
        size++;\
        break;\
    }\
    LOAD_INTEGER(buf, offset, (sel)->size_of_select);\
    if ( (sel)->size_of_select > sizeof((sel)->pcr_select) ) {\
        size++;\
        break;\
    }\
    LOAD_BLOB(buf, offset, (sel)->pcr_select, (sel)->size_of_select);\
    size = sizeof(tpm_pcr_selection_t);\
    break;\
}

#define LOAD_PCR_INFO_LONG(buf, offset, info, size) while (1) {\
    uint32_t ps_size = sizeof(tpm_pcr_selection_t);\
    if ( size < sizeof(tpm_pcr_info_long_t) ) {\
        size++;\
        break;\
    }\
    LOAD_INTEGER(buf, offset, (info)->tag);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_creation);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_release);\
    LOAD_PCR_SELECTION(buf, offset, &(info)->creation_pcr_selection, ps_size);\
    if ( ps_size > sizeof(tpm_pcr_selection_t) ) {\
        size++;\
        break;\
    }\
    ps_size = sizeof(tpm_pcr_selection_t);\
    LOAD_PCR_SELECTION(buf, offset, &(info)->release_pcr_selection, ps_size);\
    if ( ps_size > sizeof(tpm_pcr_selection_t) ) {\
        size++;\
        break;\
    }\
    LOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_creation);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_release);\
    size=sizeof(tpm_pcr_info_long_t);\
    break;\
}

#define LOAD_STORED_DATA12(buf, offset, hdr, size) while (1){\
    uint32_t pil_size = sizeof(tpm_pcr_info_long_t);\
    if ( size < sizeof(tpm_stored_data12_short_t) ) {\
        size++;\
        break;\
    }\
    LOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->tag);\
    LOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->et);\
    LOAD_INTEGER(buf, offset, \
                 ((tpm_stored_data12_header_t *)(hdr))->seal_info_size);\
    if ( ((tpm_stored_data12_header_t *)(hdr))->seal_info_size == 0 ) {\
        LOAD_INTEGER(buf, offset,\
                     ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
        if ( size - sizeof(tpm_stored_data12_short_t) <\
                    ((tpm_stored_data12_short_t *)hdr)->enc_data_size ) {\
            size++;\
            break;\
        }\
        LOAD_BLOB(buf, offset,\
                  ((tpm_stored_data12_short_t *)hdr)->enc_data,\
                  ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
        size = sizeof(tpm_stored_data12_short_t) +\
               ((tpm_stored_data12_short_t *)hdr)->enc_data_size;\
    }\
    else {\
        if ( size < sizeof(tpm_stored_data12_t) ) {\
            size++;\
            break;\
        }\
        LOAD_PCR_INFO_LONG(buf, offset,\
                           &((tpm_stored_data12_t *)hdr)->seal_info, pil_size);\
        if ( pil_size > sizeof(tpm_pcr_info_long_t) ) {\
            size++;\
            break;\
        }\
        LOAD_INTEGER(buf, offset,\
                     ((tpm_stored_data12_t *)hdr)->enc_data_size);\
        if ( size - sizeof(tpm_stored_data12_t) <\
                    ((tpm_stored_data12_t *)hdr)->enc_data_size ) {\
            size++;\
            break;\
        }\
        LOAD_BLOB(buf, offset,\
                  ((tpm_stored_data12_t *)hdr)->enc_data,\
                  ((tpm_stored_data12_t *)hdr)->enc_data_size);\
        size = sizeof(tpm_stored_data12_t) +\
               ((tpm_stored_data12_t *)hdr)->enc_data_size;\
    }\
    break;\
}

static uint32_t tpm12_oiap(uint32_t locality, tpm_authhandle_t *hauth,
                         tpm_nonce_t *nonce_even)
{
    uint32_t ret, offset, out_size;

    if ( hauth == NULL || nonce_even == NULL )
        return TPM_BAD_PARAMETER;

    offset = 0;

    out_size = sizeof(*hauth) + sizeof(*nonce_even);

    ret = tpm12_submit_cmd(locality, TPM_ORD_OIAP, offset, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: start OIAP, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: start OIAP, return value = %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    offset = 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *hauth);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);

    return ret;
}

static uint32_t tpm12_osap(uint32_t locality, tpm_entity_type_t ent_type,
                         uint32_t ent_value, const tpm_nonce_t *odd_osap,
                         tpm_authhandle_t *hauth, tpm_nonce_t *nonce_even,
                         tpm_nonce_t *even_osap)
{
    uint32_t ret, offset, out_size;

    if ( odd_osap == NULL || hauth == NULL ||
         nonce_even == NULL || even_osap == NULL )
        return TPM_BAD_PARAMETER;

    offset = 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ent_type);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ent_value);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, odd_osap);

    out_size = sizeof(*hauth) + sizeof(*nonce_even) + sizeof(*even_osap);
    ret = tpm12_submit_cmd(locality, TPM_ORD_OSAP, offset, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: start OSAP, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: start OSAP, return value = %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    offset = 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *hauth);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, even_osap);

    return ret;
}

static uint32_t _tpm12_seal(uint32_t locality, tpm_key_handle_t hkey,
                  const tpm_encauth_t *enc_auth, uint32_t pcr_info_size,
                  const tpm_pcr_info_long_t *pcr_info, uint32_t in_data_size,
                  const uint8_t *in_data,
                  tpm_authhandle_t hauth, const tpm_nonce_t *nonce_odd,
                  uint8_t *cont_session, const tpm_authdata_t *pub_auth,
                  uint32_t *sealed_data_size, uint8_t *sealed_data,
                  tpm_nonce_t *nonce_even, tpm_authdata_t *res_auth)
{
    uint32_t ret, offset, out_size, size;

    if ( enc_auth == NULL || pcr_info == NULL || in_data == NULL ||
         nonce_odd == NULL || cont_session == NULL || pub_auth == NULL ||
         sealed_data_size == NULL || sealed_data == NULL ||
         nonce_even == NULL || res_auth == NULL ) {
        printk(TBOOT_WARN"TPM: _tpm12_seal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset = 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hkey);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, enc_auth);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, pcr_info_size);
    UNLOAD_PCR_INFO_LONG(WRAPPER_IN_BUF, offset, pcr_info);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, in_data_size);
    UNLOAD_BLOB(WRAPPER_IN_BUF, offset, in_data, in_data_size);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, pub_auth);

    out_size = WRAPPER_OUT_MAX_SIZE;

    ret = tpm12_submit_cmd_auth1(locality, TPM_ORD_SEAL, offset, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: seal data, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: seal data, return value = %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if ( *sealed_data_size <
         ( out_size - sizeof(*nonce_even) - sizeof(*cont_session)
           - sizeof(*res_auth) ) ) {
        printk(TBOOT_WARN"TPM: sealed blob is too small\n");
        return TPM_NOSPACE;
    }

    offset = 0;
    size = *sealed_data_size;
    LOAD_STORED_DATA12(WRAPPER_OUT_BUF, offset, sealed_data, size);
    if ( *sealed_data_size < size ) {
        printk(TBOOT_WARN"TPM: sealed blob is too small\n");
        return TPM_NOSPACE;
    }
    *sealed_data_size = size;
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *cont_session);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, res_auth);

    return ret;
}

static uint32_t _tpm12_unseal(uint32_t locality, tpm_key_handle_t hkey,
                    const uint8_t *in_data,
                    tpm_authhandle_t hauth, const tpm_nonce_t *nonce_odd,
                    uint8_t *cont_session, const tpm_authdata_t *auth,
                    tpm_authhandle_t hauth_d, const tpm_nonce_t *nonce_odd_d,
                    uint8_t *cont_session_d, const tpm_authdata_t *auth_d,
                    uint32_t *secret_size, uint8_t *secret,
                    tpm_nonce_t *nonce_even, tpm_authdata_t *res_auth,
                    tpm_nonce_t *nonce_even_d, tpm_authdata_t *res_auth_d)
{
    uint32_t ret, offset, out_size, size;

    if ( in_data == NULL || nonce_odd == NULL || cont_session == NULL ||
         auth == NULL || nonce_odd_d == NULL || cont_session_d == NULL ||
         auth_d == NULL || secret_size == NULL || secret == NULL ||
         nonce_even == NULL || res_auth == NULL || nonce_even_d == NULL ||
         res_auth_d == NULL ) {
        printk(TBOOT_WARN"TPM: _tpm_unseal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset = 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hkey);
    UNLOAD_STORED_DATA12(WRAPPER_IN_BUF, offset, in_data);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, auth);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd_d);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, auth_d);

    out_size = WRAPPER_OUT_MAX_SIZE;

    ret = tpm12_submit_cmd_auth2(locality, TPM_ORD_UNSEAL, offset, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: unseal data, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: unseal data, return value = %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    offset = 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, size);
    if ( *secret_size < size ||
         size != 
         ( out_size - sizeof(*secret_size) - sizeof(*nonce_even)
           - sizeof(*cont_session) - sizeof(*res_auth) - sizeof(*nonce_even_d)
           - sizeof(*cont_session_d) - sizeof(*res_auth_d) ) ) {
        printk(TBOOT_WARN"TPM: unsealed data too small\n");
        return TPM_NOSPACE;
    }
    *secret_size = size;
    LOAD_BLOB(WRAPPER_OUT_BUF, offset, secret, *secret_size);

    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *cont_session);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, res_auth);

    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even_d);
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *cont_session_d);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, res_auth_d);

    return ret;
}

#define XOR_BLOB_TYPE(data, pad) {\
    for ( uint32_t i = 0; i < sizeof(*(data)); i++ ) \
        ((uint8_t *)data)[i] ^= ((uint8_t *)pad)[i % sizeof(*(pad))];\
}

static const tpm_authdata_t srk_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const tpm_authdata_t blob_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static uint32_t _tpm12_wrap_seal(uint32_t locality,
                              const tpm_pcr_info_long_t *pcr_info,
                              uint32_t in_data_size, const uint8_t *in_data,
                              uint32_t *sealed_data_size, uint8_t *sealed_data)
{
    uint32_t ret;
    tpm_nonce_t odd_osap, even_osap, nonce_even, nonce_odd;
    tpm_authhandle_t hauth;
    tpm_authdata_t shared_secret, pub_auth, res_auth;
    tpm_encauth_t enc_auth;
    uint8_t cont_session = false;
    tpm_key_handle_t hkey = TPM_KH_SRK;
    uint32_t pcr_info_size = sizeof(*pcr_info);
    uint32_t offset;
    uint32_t ordinal = TPM_ORD_SEAL;
    tpm12_digest_t digest;

    /* skip generate nonce for odd_osap, just use the random value in stack */

    /* establish a osap session */
    ret = tpm12_osap(locality, TPM_ET_SRK, TPM_KH_SRK, &odd_osap, &hauth,
                   &nonce_even, &even_osap);
    if ( ret != TPM_SUCCESS )
            return ret;

    /* calculate the shared secret
       shared-secret = HMAC(srk_auth, even_osap || odd_osap) */
    offset = 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &even_osap);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &odd_osap);
    hmac((uint8_t *)&srk_authdata, WRAPPER_IN_BUF, offset,
         (uint8_t *)&shared_secret);

    /* generate ecrypted authdata for data
       enc_auth = XOR(authdata, sha1(shared_secret || last_even_nonce)) */
    offset = 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &shared_secret);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    sha1_buffer(WRAPPER_IN_BUF, offset, (uint8_t *)&digest);
    tb_memcpy(&enc_auth, &blob_authdata, sizeof(blob_authdata));
    XOR_BLOB_TYPE(&enc_auth, &digest);

    /* skip generate nonce for nonce_odd, just use the random value in stack */

    /* calculate authdata */
    /* in_param_digest = sha1(1S ~ 6S) */
    offset = 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ordinal);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &enc_auth);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, pcr_info_size);
    UNLOAD_PCR_INFO_LONG(WRAPPER_IN_BUF, offset, pcr_info);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, in_data_size);
    UNLOAD_BLOB(WRAPPER_IN_BUF, offset, in_data, in_data_size);
    sha1_buffer(WRAPPER_IN_BUF, offset, (uint8_t *)&digest);

    /* authdata = hmac(key, in_param_digest || auth_params) */
    offset = 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session);
    hmac((uint8_t *)&shared_secret, WRAPPER_IN_BUF, offset,
         (uint8_t *)&pub_auth);

    /* call the simple seal function */
    ret = _tpm12_seal(locality, hkey, (const tpm_encauth_t *)&enc_auth,
                    pcr_info_size, pcr_info, in_data_size, in_data,
                    hauth, &nonce_odd, &cont_session,
                    (const tpm_authdata_t *)&pub_auth,
                    sealed_data_size, sealed_data,
                    &nonce_even, &res_auth);

    /* skip check for res_auth */

    return ret;
}

static uint32_t _tpm12_wrap_unseal(uint32_t locality, const uint8_t *in_data,
                                 uint32_t *secret_size, uint8_t *secret)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    uint32_t ret;
    tpm_nonce_t odd_osap, even_osap;
    tpm_nonce_t nonce_even, nonce_odd, nonce_even_d, nonce_odd_d;
    tpm_authhandle_t hauth, hauth_d;
    tpm_authdata_t shared_secret;
    tpm_authdata_t pub_auth, res_auth, pub_auth_d, res_auth_d;
    uint8_t cont_session = false, cont_session_d = false;
    tpm_key_handle_t hkey = TPM_KH_SRK;
    uint32_t offset;
    uint32_t ordinal = TPM_ORD_UNSEAL;
    tpm12_digest_t digest;

    /* skip generate nonce for odd_osap, just use the random value in stack */

    /* establish a osap session */
    ret = tpm12_osap(locality, TPM_ET_SRK, TPM_KH_SRK, &odd_osap, &hauth,
                   &nonce_even, &even_osap);
    if ( ret != TPM_SUCCESS )
            return ret;

    /* calculate the shared secret
       shared-secret = HMAC(auth, even_osap || odd_osap) */
    offset = 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &even_osap);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &odd_osap);
    hmac((uint8_t *)&srk_authdata, WRAPPER_IN_BUF, offset,
         (uint8_t *)&shared_secret);

    /* establish a oiap session */
    ret = tpm12_oiap(locality, &hauth_d, &nonce_even_d);
    if ( ret != TPM_SUCCESS )
            return ret;

    /* skip generate nonce_odd & nonce_odd_d, just use the random values */

    /* calculate authdata */
    /* in_param_digest = sha1(1S ~ 6S) */
    offset = 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ordinal);
    UNLOAD_STORED_DATA12(WRAPPER_IN_BUF, offset, in_data);
    sha1_buffer(WRAPPER_IN_BUF, offset, (uint8_t *)&digest);

    /* authdata1 = hmac(key, in_param_digest || auth_params1) */
    offset = 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session);
    hmac((uint8_t *)&shared_secret, WRAPPER_IN_BUF, offset,
         (uint8_t *)&pub_auth);

    /* authdata2 = hmac(key, in_param_digest || auth_params2) */
    offset = 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd_d);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session_d);
    hmac((uint8_t *)&blob_authdata, WRAPPER_IN_BUF, offset,
         (uint8_t *)&pub_auth_d);

    /* call the simple seal function */
    ret = _tpm12_unseal(locality, hkey, in_data,
                      hauth, &nonce_odd, &cont_session,
                      (const tpm_authdata_t *)&pub_auth,
                      hauth_d, &nonce_odd_d, &cont_session_d,
                      (const tpm_authdata_t *)&pub_auth_d,
                      secret_size, secret,
                      &nonce_even, &res_auth, &nonce_even_d, &res_auth_d);

    /* skip check for res_auth */

    return ret;
#pragma GCC diagnostic pop
}

static bool init_pcr_info(uint32_t locality,
                          tpm_locality_selection_t release_locs,
                          uint32_t nr_create, const uint8_t indcs_create[],
                          uint32_t nr_release, const uint8_t indcs_release[],
                          const tpm12_digest_t *values_release[],
                          tpm_pcr_info_long_t *pcr_info)
{
    uint32_t offset;
    uint32_t i, blob_size;
    static tpm_locality_selection_t localities[TPM_NR_LOCALITIES] = {
        TPM_LOC_ZERO, TPM_LOC_ONE, TPM_LOC_TWO, TPM_LOC_THREE, TPM_LOC_FOUR
    };


    if ( (release_locs & TPM_LOC_RSVD) != 0 )
        return false;
    if ( pcr_info == NULL )
        return false;
    if ( locality >= TPM_NR_LOCALITIES )
        return false;
    if ( indcs_create == NULL )
        nr_create = 0;
    if ( indcs_release == NULL || values_release == NULL )
        nr_release = 0;
    for ( i = 0; i < nr_create; i++ )
        if ( indcs_create[i] >= TPM_NR_PCRS )
            return false;
    for ( i = 0; i < nr_release; i++ ) {
        if ( indcs_release[i] >= TPM_NR_PCRS || values_release[i] == NULL )
            return false;
    }

    tb_memset(pcr_info, 0, sizeof(*pcr_info));
    pcr_info->tag = TPM_TAG_PCR_INFO_LONG;
    pcr_info->locality_at_creation = localities[locality];
    pcr_info->locality_at_release = release_locs;
    pcr_info->creation_pcr_selection.size_of_select = 3;
    for ( i = 0; i < nr_create; i++ )
        pcr_info->creation_pcr_selection.pcr_select[indcs_create[i]/8] |=
            1 << (indcs_create[i] % 8);
    pcr_info->release_pcr_selection.size_of_select = 3;
    for ( i = 0; i < nr_release; i++ )
        pcr_info->release_pcr_selection.pcr_select[indcs_release[i]/8] |=
            1 << (indcs_release[i] % 8);

    if ( nr_release > 0 ) {
        offset = 0;
        UNLOAD_PCR_SELECTION(WRAPPER_IN_BUF, offset,
                             &pcr_info->release_pcr_selection);
        blob_size = sizeof(tpm12_digest_t) * nr_release;
        UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, blob_size);
        for ( i = 0; i < nr_release; i++ )
            UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, values_release[i]);
        sha1_buffer(WRAPPER_IN_BUF, offset,
                    (uint8_t *)&pcr_info->digest_at_release);
    }

    return true;
}

static bool tpm12_seal(struct tpm_if *ti, uint32_t locality,
                       uint32_t in_data_size, const uint8_t *in_data,
                       uint32_t *sealed_data_size, uint8_t *sealed_data)
{
    const uint8_t pcr_indcs_create[]  = {17, 18};
    const uint8_t pcr_indcs_release[] = {17, 18};
    const tpm12_digest_t *pcr_values_release[] = {(tpm12_digest_t *)&post_launch_pcr17,
                                                  (tpm12_digest_t *)&post_launch_pcr18};
    uint32_t pcr_nr_create = ARRAY_SIZE(pcr_indcs_create);
    uint32_t pcr_nr_release = ARRAY_SIZE(pcr_indcs_release);
    uint32_t ret;
    tpm_pcr_info_long_t pcr_info;
    tpm_locality_selection_t release_locs = 1 << locality;

    if ( ti == NULL )
        return false;

    if ( locality >= TPM_NR_LOCALITIES ||
         in_data_size == 0 || in_data == NULL ||
         sealed_data_size == NULL || sealed_data == NULL ||
         *sealed_data_size == 0 ) {
        printk(TBOOT_WARN"TPM: tpm12_seal() bad parameter\n");
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    if ( !init_pcr_info(locality, release_locs, pcr_nr_create,
                        pcr_indcs_create, pcr_nr_release, pcr_indcs_release,
                        pcr_values_release, &pcr_info) ) {
        printk(TBOOT_WARN"TPM: tpm12_seal() bad parameter\n");
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    ret = _tpm12_wrap_seal(locality, &pcr_info, in_data_size, in_data,
                         sealed_data_size, sealed_data);
    if ( ret != TPM_SUCCESS ) {
        ti->error = ret;
        return false;
    }

    return true;
}

static bool check_sealed_data(uint32_t size, const uint8_t *data)
{
    if ( size < sizeof(tpm_stored_data12_header_t) )
        return false;
    if ( ((tpm_stored_data12_header_t *)data)->tag != TPM_TAG_STORED_DATA12 )
        return false;

    if ( ((tpm_stored_data12_header_t *)data)->seal_info_size == 0 ) {
        tpm_stored_data12_short_t *data12_s;

        if ( size < sizeof(*data12_s) )
            return false;
        data12_s = (tpm_stored_data12_short_t *)data;
        if ( size != sizeof(*data12_s) + data12_s->enc_data_size )
            return false;
    }
    else {
        tpm_stored_data12_t *data12;

        if ( size < sizeof(*data12) )
            return false;
        data12 = (tpm_stored_data12_t *)data;
        if ( size != sizeof(*data12) + data12->enc_data_size )
            return false;
    }

    return true;
}

static bool tpm12_unseal(struct tpm_if *ti, uint32_t locality,
                         uint32_t sealed_data_size, const uint8_t *sealed_data,
                         uint32_t *secret_size, uint8_t *secret)
{
    uint32_t ret;

    if ( ti == NULL )
        return false;

    if ( sealed_data == NULL ||
         secret_size == NULL || secret == NULL ) {
        printk(TBOOT_WARN"TPM: tpm12_unseal() bad parameter\n");
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    if ( !check_sealed_data(sealed_data_size, sealed_data) ) {
        printk(TBOOT_WARN"TPM: tpm12_unseal() blob invalid\n");
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    ret = _tpm12_wrap_unseal(locality, sealed_data, secret_size, secret);
    if ( ret != TPM_SUCCESS ) {
        ti->error = ret;
        return false;
    }

    return true;
}

static void calc_pcr_composition(uint32_t nr, const uint8_t indcs[],
                                 const tpm12_digest_t *values[],
                                 tpm_composite_hash_t *composite)
{
    uint32_t i, offset, blob_size;
    tpm_pcr_selection_t sel;

    if ( nr == 0 || indcs == NULL || values == NULL || composite == NULL)
        return;

    sel.size_of_select = 3;
    sel.pcr_select[0] = sel.pcr_select[1] = sel.pcr_select[2] = 0;
    for ( i = 0; i < nr; i++ )
        sel.pcr_select[indcs[i]/8] |= 1 << (indcs[i] % 8);

    offset = 0;
    UNLOAD_PCR_SELECTION(WRAPPER_IN_BUF, offset, &sel);
    blob_size = sizeof(tpm12_digest_t) * nr;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, blob_size);
    for ( i = 0; i < nr; i++ )
        UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, values[i]);
    sha1_buffer(WRAPPER_IN_BUF, offset, (uint8_t *)composite);
}

static tpm_composite_hash_t *get_cre_pcr_composite(uint8_t *data)
{
    if ( ((tpm_stored_data12_header_t *)data)->seal_info_size == 0 )
        return NULL;
    else
        return &((tpm_stored_data12_t *)data)->seal_info.digest_at_creation;
}

static bool tpm12_cmp_creation_pcrs(uint32_t pcr_nr_create,
                           const uint8_t pcr_indcs_create[],
                           const tpm12_digest_t *pcr_values_create[],
                           uint32_t sealed_data_size, uint8_t *sealed_data)
{
    uint32_t i;
    tpm_composite_hash_t composite = {{0,}}, *cre_composite;

    if ( pcr_indcs_create == NULL )
        pcr_nr_create = 0;
    for ( i = 0; i < pcr_nr_create; i++ ) {
        if ( pcr_indcs_create[i] >= TPM_NR_PCRS )
            return false;
    }
    if ( !check_sealed_data(sealed_data_size, sealed_data) ) {
        printk(TBOOT_WARN"TPM: Bad blob.\n");
        return false;
    }

    if ( pcr_nr_create > 0 )
        calc_pcr_composition(pcr_nr_create, pcr_indcs_create,
                             pcr_values_create, &composite);

    cre_composite = get_cre_pcr_composite(sealed_data);
    if ( cre_composite == NULL )
        return false;
    if ( tb_memcmp(&composite, cre_composite, sizeof(composite)) ) {
        printk(TBOOT_WARN"TPM: Not equal to creation composition:\n");
        print_hex(NULL, (uint8_t *)&composite, sizeof(composite));
        print_hex(NULL, (uint8_t *)cre_composite, sizeof(composite));
        return false;
    }

    return true;
}

static bool tpm12_verify_creation(struct tpm_if *ti, uint32_t sealed_data_size,
                            uint8_t *sealed_data)
{
    uint8_t pcr_indcs_create[] = {17, 18};
    tpm12_digest_t pcr17, pcr18;
    const tpm12_digest_t *pcr_values_create[] = {&pcr17, &pcr18};
    int i;

    if ( ti == NULL || sealed_data == NULL )
        return false;

    tpm12_pcr_read(ti, 2, 17, (tpm_pcr_value_t *)&pcr17);
    tpm12_pcr_read(ti, 2, 18, (tpm_pcr_value_t *)&pcr18);

    /* to prevent rollback attack using old sealed measurements,
       verify that (creation) PCRs at mem integrity seal time are same as
       if we extend current PCRs with unsealed VL measurements */
    /* TBD: we should check all DRTM PCRs */
    for ( i = 0; i < g_pre_k_s3_state.num_vl_entries; i++ ) {
        if ( g_pre_k_s3_state.vl_entries[i].pcr == 17 )
            extend_hash((tb_hash_t *)&pcr17,
                &g_pre_k_s3_state.vl_entries[i].hl.entries[0].hash, TB_HALG_SHA1);
        else if ( g_pre_k_s3_state.vl_entries[i].pcr == 18 )
            extend_hash((tb_hash_t *)&pcr18,
                &g_pre_k_s3_state.vl_entries[i].hl.entries[0].hash, TB_HALG_SHA1);
    }
    if ( !tpm12_cmp_creation_pcrs(ARRAY_SIZE(pcr_indcs_create),
                                pcr_indcs_create, pcr_values_create,
                                sealed_data_size,
                                sealed_data) ) {
        printk(TBOOT_WARN"extended PCR values don't match creation values in sealed blob.\n");
        return false;
    }

    return true;
}

typedef uint32_t tpm_capability_area_t;

#define TPM_CAP_NV_INDEX    0x00000011

static uint32_t tpm12_get_capability(uint32_t locality, tpm_capability_area_t cap_area,
                  uint32_t sub_cap_size, const uint8_t *sub_cap,
                  uint32_t *resp_size, uint8_t *resp)
{
    uint32_t ret, offset, out_size, size;

    if ( sub_cap == NULL || resp_size == NULL || resp == NULL ) {
        printk(TBOOT_WARN"TPM: tpm12_get_capability() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset = 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cap_area);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, sub_cap_size);
    UNLOAD_BLOB(WRAPPER_IN_BUF, offset, sub_cap, sub_cap_size);

    out_size = sizeof(*resp_size) + *resp_size;

    ret = tpm12_submit_cmd(locality, TPM_ORD_GET_CAPABILITY, offset, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get capability, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: get capability, return value = %08X\n", ret);
        return ret;
    }

    offset = 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, size);
    if ( *resp_size < size ||
         size != out_size - sizeof(*resp_size) ) {
        printk(TBOOT_WARN"TPM: capability response too small\n");
        return TPM_FAIL;
    }
    *resp_size = size;
    LOAD_BLOB(WRAPPER_OUT_BUF, offset, resp, *resp_size);

    return ret;
}

typedef struct __packed {
    tpm_pcr_selection_t         pcr_selection;
    tpm_locality_selection_t    locality_at_release;
    tpm_composite_hash_t        digest_at_release;
} tpm_pcr_info_short_t;

typedef struct __packed {
    tpm_structure_tag_t tag;
    uint32_t            attributes;
} tpm_nv_attributes_t;

typedef struct __packed {
    tpm_structure_tag_t     tag;
    uint32_t                nv_index;
    tpm_pcr_info_short_t    pcr_info_read;
    tpm_pcr_info_short_t    pcr_info_write;
    tpm_nv_attributes_t     permission;
    uint8_t                 b_read_st_clear;
    uint8_t                 b_write_st_clear;
    uint8_t                 b_write_define;
    uint32_t                data_size;
} tpm_nv_data_public_t;

static bool tpm12_get_nvindex_size(struct tpm_if *ti, uint32_t locality,
                                   uint32_t index, uint32_t *size)
{
    uint32_t ret, offset, resp_size;
    uint8_t sub_cap[sizeof(index)];
    uint8_t resp[sizeof(tpm_nv_data_public_t)];
    uint32_t idx;

    if ( ti == NULL )
        return false;

    if ( size == NULL ) {
        printk(TBOOT_WARN"TPM: tpm12_get_nvindex_size() bad parameter\n");
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    offset = 0;
    UNLOAD_INTEGER(sub_cap, offset, index);

    resp_size = sizeof(resp);
    ret = tpm12_get_capability(locality, TPM_CAP_NV_INDEX, sizeof(sub_cap),
                             sub_cap, &resp_size, resp);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get nvindex size, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_DETA"TPM: fail to get public data of 0x%08X in TPM NV\n", index);
        ti->error = ret;
        return false;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, resp, resp_size);
    }
#endif

    /* check size */
    if ( resp_size == 0 ) {
        printk(TBOOT_WARN"TPM: Index 0x%08X does not exist\n", index);
        ti->error = TPM_BADINDEX;
        return false;
    }

    /* check index */
    offset = sizeof(tpm_structure_tag_t);
    LOAD_INTEGER(resp, offset, idx);
#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get index value = %08X\n", idx);
#endif

    if ( idx != index ) {
        printk(TBOOT_DETA"TPM: Index 0x%08X is not the one expected 0x%08X\n",
               idx, index);
        ti->error = TPM_BADINDEX;
        return false;
    }

    if ( resp_size != sizeof(resp) ) {
        printk(TBOOT_WARN"TPM: public data size of Index 0x%08X responsed incorrect\n",
               index);
        ti->error = TPM_FAIL;
        return false;
    }

    offset = resp_size - sizeof(uint32_t);
    LOAD_INTEGER(resp, offset, *size);

    return true;
}

static bool tpm12_get_nvindex_permission(struct tpm_if *ti, uint32_t locality,
                                    uint32_t index, uint32_t *attribute)
{
    uint32_t ret, offset, resp_size;
    uint8_t sub_cap[sizeof(index)];
    uint8_t resp[sizeof(tpm_nv_data_public_t)];
    uint32_t idx;

    if ( ti == NULL )
        return false;

    if ( attribute == NULL ) {
        printk(TBOOT_WARN"TPM: tpm12_get_nvindex_permission() bad parameter\n");
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    offset = 0;
    UNLOAD_INTEGER(sub_cap, offset, index);

    resp_size = sizeof(resp);
    ret = tpm12_get_capability(locality, TPM_CAP_NV_INDEX, sizeof(sub_cap),
                             sub_cap, &resp_size, resp);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get nvindex permission, return value = %08X\n", ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_WARN"TPM: fail to get public data of 0x%08X in TPM NV\n", index);
        ti->error = ret;
        return false;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, resp, resp_size);
    }
#endif

    /* check size */
    if ( resp_size == 0 ) {
        printk(TBOOT_WARN"TPM: Index 0x%08X does not exist\n", index);
        ti->error = TPM_BADINDEX;
        return false;
    }

    /* check index */
    offset = sizeof(tpm_structure_tag_t);
    LOAD_INTEGER(resp, offset, idx);
#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get index value = %08X\n", idx);
#endif

    if ( idx != index ) {
        printk(TBOOT_WARN"TPM: Index 0x%08X is not the one expected 0x%08X\n",
               idx, index);
        ti->error = TPM_BADINDEX;
        return false;
    }

    if ( resp_size != sizeof(resp) ) {
        printk(TBOOT_ERR"TPM: public data size of Index 0x%08X responsed incorrect\n",
               index);
        ti->error = TPM_FAIL;
        return false;
    }

    offset = resp_size - sizeof(uint32_t) - 3 * sizeof(uint8_t) - sizeof(uint32_t);
    LOAD_INTEGER(resp, offset, *attribute);

    return true;
}

typedef struct __packed {
    tpm_structure_tag_t tag;
    uint8_t disable;
    uint8_t ownership;
    uint8_t deactivated;
    uint8_t read_pubek;
    uint8_t disable_owner_clear;
    uint8_t allow_maintenance;
    uint8_t physical_presence_lifetime_lock;
    uint8_t physical_presence_hw_enable;
    uint8_t physical_presence_cmd_enable;
    uint8_t cekp_used;
    uint8_t tpm_post;
    uint8_t tpm_post_lock;
    uint8_t fips;
    uint8_t operator;
    uint8_t enable_revoke_ek;
    uint8_t nv_locked;
    uint8_t read_srk_pub;
    uint8_t tpm_established;
    uint8_t maintenance_done;
    uint8_t disable_full_da_logic_info;
} tpm_permanent_flags_t;

typedef struct __packed {
    tpm_structure_tag_t tag;
    uint8_t deactivated;
    uint8_t disable_force_clear;
    uint8_t physical_presence;
    uint8_t phycical_presence_lock;
    uint8_t b_global_lock;
} tpm_stclear_flags_t;

#define TPM_CAP_FLAG            0x00000004
#define TPM_CAP_FLAG_PERMANENT  0x00000108
#define TPM_CAP_FLAG_VOLATILE   0x00000109

static uint32_t tpm12_get_flags(uint32_t locality, uint32_t flag_id,
                       uint8_t *flags, uint32_t flag_size)
{
    uint32_t ret, offset, resp_size;
    uint8_t sub_cap[sizeof(flag_id)];
    tpm_structure_tag_t tag;

    if ( flags == NULL ) {
        printk(TBOOT_WARN"TPM: tpm12_get_flags() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset = 0;
    UNLOAD_INTEGER(sub_cap, offset, flag_id);

    resp_size = flag_size;
    ret = tpm12_get_capability(locality, TPM_CAP_FLAG, sizeof(sub_cap),
                             sub_cap, &resp_size, flags);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get flags %08X, return value = %08X\n", flag_id, ret);
#endif
    if ( ret != TPM_SUCCESS )
        return ret;

    /* 1.2 spec, main part 2, rev 103 add one more byte to permanent flags, to
       be backward compatible, not assume all expected bytes can be gotten */
    if ( resp_size > flag_size ) {
        printk(TBOOT_WARN"TPM: tpm12_get_flags() response size too small\n");
        return TPM_FAIL;
    }

    offset = 0;
    LOAD_INTEGER(flags, offset, tag);
    offset = 0;
    UNLOAD_BLOB_TYPE(flags, offset, &tag);

    return ret;
}

#define TPM_CAP_PROPERTY          0x00000005
#define TPM_CAP_PROP_TIS_TIMEOUT  0x00000115

static uint32_t tpm12_get_timeout(uint32_t locality,
                       uint8_t *prop, uint32_t prop_size)
{
    uint32_t ret, offset, resp_size, prop_id = TPM_CAP_PROP_TIS_TIMEOUT;
    uint8_t sub_cap[sizeof(prop_id)];
    uint32_t resp[4];

    if ( (prop == NULL) || (prop_size < sizeof(resp)) ) {
        printk(TBOOT_WARN"TPM: tpm12_get_timeout() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset = 0;
    UNLOAD_INTEGER(sub_cap, offset, prop_id);

    resp_size = prop_size;
    ret = tpm12_get_capability(locality, TPM_CAP_PROPERTY, sizeof(sub_cap),
                             sub_cap, &resp_size, prop);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get prop %08X, return value = %08X\n", prop_id, ret);
#endif
    if ( ret != TPM_SUCCESS )
        return ret;

    if ( resp_size != prop_size ) {
        printk(TBOOT_WARN"TPM: tpm_get_property() response size incorrect\n");
        return TPM_FAIL;
    }

    offset = 0;
    LOAD_INTEGER(prop, offset, resp);
    offset = 0;
    UNLOAD_BLOB_TYPE(prop, offset, &resp);

    return ret;
}

/* ensure TPM is ready to accept commands */
static bool tpm12_init(struct tpm_if *ti)
{
    tpm_permanent_flags_t pflags;
    tpm_stclear_flags_t vflags;
    uint32_t timeout[4];
    uint32_t locality;
    uint32_t ret;

    if ( ti == NULL )
        return false;

    printk(TBOOT_WARN"Warning: TPM1.2 detected, SHA1 is selected as hashing algorithm.\n");

    if (!txt_is_launched())
        ti->cur_loc = 0;
    else
        ti->cur_loc = 2;

    locality = ti->cur_loc;
    if ( !tpm_validate_locality(locality) ) {
        printk(TBOOT_WARN"TPM is not available.\n");
        return false;
    }

    /* make sure tpm is not disabled/deactivated */
    tb_memset(&pflags, 0, sizeof(pflags));
    ret = tpm12_get_flags(locality, TPM_CAP_FLAG_PERMANENT,
                        (uint8_t *)&pflags, sizeof(pflags));
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_WARN"TPM is disabled or deactivated.\n");
        ti->error = ret;
        return false;
    }
    if ( pflags.disable ) {
        printk(TBOOT_WARN"TPM is disabled.\n");
        return false;
    }

    tb_memset(&vflags, 0, sizeof(vflags));
    ret = tpm12_get_flags(locality, TPM_CAP_FLAG_VOLATILE,
                        (uint8_t *)&vflags, sizeof(vflags));
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_WARN"TPM is disabled or deactivated.\n");
        ti->error = ret;
        return false;
    }
    if ( vflags.deactivated ) {
        printk(TBOOT_WARN"TPM is deactivated.\n");
        return false;
    }

    printk(TBOOT_INFO"TPM is ready\n");
    printk(TBOOT_DETA"TPM nv_locked: %s\n", (pflags.nv_locked != 0) ? "TRUE" : "FALSE");

    /* get tpm timeout values */
    ret = tpm12_get_timeout(locality, (uint8_t *)&timeout, sizeof(timeout));
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_WARN"TPM timeout values are not achieved, "
               "default values will be used.\n");
        ti->error = ret;
    } else {
        /*
         * timeout_x represents the number of milliseconds for the timeout
         * and timeout[x] represents the number of microseconds.
         */
        ti->timeout.timeout_a = timeout[0]/1000;
        ti->timeout.timeout_b = timeout[1]/1000;
        ti->timeout.timeout_c = timeout[2]/1000;
        ti->timeout.timeout_d = timeout[3]/1000;
        printk(TBOOT_DETA"TPM timeout values: A: %u, B: %u, C: %u, D: %u\n",
               ti->timeout.timeout_a, ti->timeout.timeout_b, ti->timeout.timeout_c,
               ti->timeout.timeout_d);
        /*
         * if any timeout values are less than default values, set to default
         * value (due to bug with some TPMs)
         */
        if ( ti->timeout.timeout_a < TIMEOUT_A ) {
            ti->timeout.timeout_a = TIMEOUT_A;
            printk(TBOOT_WARN"Wrong timeout A, fallback to %u\n", TIMEOUT_A);
        }
        if ( ti->timeout.timeout_b < TIMEOUT_B ) {
            ti->timeout.timeout_b = TIMEOUT_B;
            printk(TBOOT_WARN"Wrong timeout B, fallback to %u\n", TIMEOUT_B);
        }
        if ( ti->timeout.timeout_c < TIMEOUT_C ) {
            ti->timeout.timeout_c = TIMEOUT_C;
            printk(TBOOT_WARN"Wrong timeout C, fallback to %u\n", TIMEOUT_C);
        }
        if ( ti->timeout.timeout_d < TIMEOUT_D ) {
            ti->timeout.timeout_d = TIMEOUT_D;
            printk(TBOOT_WARN"Wrong timeout D, fallback to %u\n", TIMEOUT_D);
        }
    }

    /* init version */
    ti->major = TPM12_VER_MAJOR;
    ti->minor = TPM12_VER_MINOR;

    /* init supported alg list */
    ti->banks = 1;
    ti->alg_count = 1;
    ti->algs[0] = TB_HALG_SHA1; 
    ti->extpol = TB_EXTPOL_FIXED;
    ti->cur_alg = TB_HALG_SHA1;

    /* init NV index */
    ti->tb_policy_index = 0x20000001;
    ti->lcp_own_index = 0x40000001;
    ti->tb_err_index = 0x20000002;
    ti->sgx_svn_index = 0x50000004;
    
    return true;
}

static uint32_t tpm12_save_state(struct tpm_if *ti, uint32_t locality)
{
    uint32_t ret, offset, out_size;
    uint32_t retries = 0;

    if ( ti == NULL )
        return TPM_BAD_PARAMETER;

    do {
        offset = 0;
        out_size = 0;

        ret = tpm12_submit_cmd(locality, TPM_ORD_SAVE_STATE, offset, &out_size);
        if ( retries == 0 )
            printk(TBOOT_INFO"TPM: save state, return value = %08X\n", ret);
        else if ( retries == 1 )
            printk(TBOOT_INFO"retrying command: .");
        else
            printk(TBOOT_INFO".");

        if ( ret != TPM_RETRY )
            break;

        retries++;
        delay(100);
    } while ( retries < MAX_SAVESTATE_RETRIES );
    if ( retries >= MAX_SAVESTATE_RETRIES )
        printk(TBOOT_INFO"TIMEOUT!");
    if ( retries > 0 )
        printk(TBOOT_INFO"\n");

    return ret;
}

static bool tpm12_get_random(struct tpm_if *ti, uint32_t locality,
                             uint8_t *random_data, uint32_t *data_size)
{
    uint32_t ret, in_size = 0, out_size, requested_size;
    static bool first_attempt;

    if ( ti == NULL )
        return false;

    if ( random_data == NULL || data_size == NULL || *data_size == 0 ) {
        ti->error = TPM_BAD_PARAMETER;
        return false;
    }

    first_attempt = true;
    requested_size = *data_size;

    /* copy the *data_size into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF + in_size, data_size, sizeof(*data_size));
    in_size += sizeof(*data_size);

    out_size = *data_size + sizeof(*data_size);
    ret = tpm12_submit_cmd(locality, TPM_ORD_GET_RANDOM, in_size, &out_size);

#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: get random %u bytes, return value = %08X\n", *data_size, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(TBOOT_WARN"TPM: get random %u bytes, return value = %08X\n", *data_size, ret);
        ti->error = ret;
        return false;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if ( out_size <= sizeof(*data_size) ) {
        *data_size = 0;
        return true;
    }

    out_size -= sizeof(*data_size);
    reverse_copy(data_size, WRAPPER_OUT_BUF, sizeof(*data_size));
    if ( *data_size > requested_size ) {
        printk(TBOOT_WARN"Requeseted %x random bytes but got %x\n", requested_size, *data_size);
        ti->error = TPM_NOSPACE;
        return false;
    }
    if ( *data_size > 0 )
        tb_memcpy(random_data, WRAPPER_OUT_BUF + sizeof(*data_size), *data_size);

    /* data might be used as key, so clear from buffer memory */
    tb_memset(WRAPPER_OUT_BUF + sizeof(*data_size), 0, *data_size);

    /* if TPM doesn't return all requested random bytes, try one more time */
    if ( *data_size < requested_size ) {
        printk(TBOOT_WARN"requested %x random bytes but only got %x\n", requested_size,
               *data_size);
        /* we're only going to try twice */
        if ( first_attempt ) {
            first_attempt = false;
            uint32_t second_size = requested_size - *data_size;
            printk(TBOOT_INFO"trying one more time to get remaining %x bytes\n",
                   second_size);
            if (!tpm12_get_random(ti, locality, random_data + *data_size,
                                 &second_size))
                return false;
            *data_size += second_size;
        }
    }

    return true;
}

static bool tpm12_cap_pcrs(struct tpm_if *ti, u32 locality, int pcr)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    bool was_capped[TPM_NR_PCRS] = {false};
    tpm_pcr_value_t cap_val;   /* use whatever val is on stack */

    if ( ti == NULL )
        return false;

    if (pcr >= 0) {
        _tpm12_pcr_extend(ti, locality, pcr, &cap_val);
        return true;
    }

    /* ensure PCRs 17 + 18 are always capped */
    _tpm12_pcr_extend(ti, locality, 17, &cap_val);
    _tpm12_pcr_extend(ti, locality, 18, &cap_val);
    was_capped[17] = was_capped[18] = true;

    /* also cap every dynamic PCR we extended (only once) */
    /* don't cap static PCRs since then they would be wrong after S3 resume */
    tb_memset(&was_capped, true, TPM_PCR_RESETABLE_MIN*sizeof(bool));
    for ( int i = 0; i < g_pre_k_s3_state.num_vl_entries; i++ ) {
        if ( !was_capped[g_pre_k_s3_state.vl_entries[i].pcr] ) {
            _tpm12_pcr_extend(ti, locality, g_pre_k_s3_state.vl_entries[i].pcr, &cap_val);
            was_capped[g_pre_k_s3_state.vl_entries[i].pcr] = true;
        }
    }

    printk(TBOOT_INFO"cap'ed dynamic PCRs\n");
    return true;
#pragma GCC diagnostic pop
}

static bool tpm12_check(void)
{
    uint32_t ret, out_size = 0;

    ret = tpm12_submit_cmd(0, 0xFFFFFFFF, 0, &out_size);

    return ( ret == TPM_BAD_ORDINAL );
}
const struct tpm_if_fp tpm_12_if_fp = {
    .init = tpm12_init,
    .pcr_read = tpm12_pcr_read,
    .pcr_extend = tpm12_pcr_extend,
    .pcr_reset = tpm12_pcr_reset,
    .nv_read = tpm12_nv_read_value,
    .nv_write = tpm12_nv_write_value,
    .get_nvindex_size = tpm12_get_nvindex_size,
    .get_nvindex_permission = tpm12_get_nvindex_permission,
    .seal = tpm12_seal,
    .unseal = tpm12_unseal,
    .verify_creation = tpm12_verify_creation,
    .get_random = tpm12_get_random,
    .save_state = tpm12_save_state,
    .cap_pcrs = tpm12_cap_pcrs,
    .check = tpm12_check,
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
