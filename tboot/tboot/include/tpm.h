/*
 * tpm.h: TPM-related support functions
 *
 * Copyright (c) 2006-2009, Intel Corporation
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

#ifndef __TPM_H__
#define __TPM_H__

#include <types.h>
#include <io.h>
#include <hash.h>
#include <integrity.h>

/* un-comment to enable detailed command tracing */
//#define TPM_TRACE

#define TPM_IF_12 0
#define TPM_IF_20_FIFO 1
#define TPM_IF_20_CRB 2

#define TPM_VER_UNKNOWN 0
#define TPM_VER_12 1
#define TPM_VER_20 2

#define TPM_INTERFACE_ID_FIFO_20  0x0
#define TPM_INTERFACE_ID_CRB     0x1
#define TPM_INTERFACE_ID_FIFO_13   0xF

#define TPM_LOCALITY_BASE             0xfed40000
#define TPM_LOCALITY_0                TPM_LOCALITY_BASE
#define TPM_LOCALITY_1                (TPM_LOCALITY_BASE | 0x1000)
#define TPM_LOCALITY_2                (TPM_LOCALITY_BASE | 0x2000)
#define TPM_LOCALITY_3                (TPM_LOCALITY_BASE | 0x3000)
#define TPM_LOCALITY_4                (TPM_LOCALITY_BASE | 0x4000)
#define TPM_LOCALITY_BASE_N(n)        (TPM_LOCALITY_BASE | ((n) << 12))
#define TPM_NR_LOCALITIES             5
#define NR_TPM_LOCALITY_PAGES         ((TPM_LOCALITY_1 - TPM_LOCALITY_0) >> PAGE_SHIFT)

#define TPM_LOCALITY_CRB_BASE        0xfed40000
#define TPM_LOCALITY_CRB_0                TPM_LOCALITY_CRB_BASE
#define TPM_LOCALITY_CRB_1                (TPM_LOCALITY_CRB_BASE | 0x1000)
#define TPM_LOCALITY_CRB_2                (TPM_LOCALITY_CRB_BASE | 0x2000)
#define TPM_LOCALITY_CRB_3                (TPM_LOCALITY_CRB_BASE | 0x3000)
#define TPM_LOCALITY_CRB_4                (TPM_LOCALITY_CRB_BASE | 0x4000)
#define TPM_LOCALITY_CRB_BASE_N(n)        (TPM_LOCALITY_CRB_BASE | ((n) << 12))
#define TPM_NR_CRB_LOCALITIES             5
#define NR_TPM_LOCALITY_CRB_PAGES         ((TPM_LOCALITY_CRB_1 - TPM_LOCALITY_CRB_0) >> PAGE_SHIFT)
/*
 * Command Header Fields:
 *       0   1   2   3   4   5   6   7   8   9   10  ...
 *       -------------------------------------------------------------
 *       | TAG  |     SIZE      | COMMAND CODE  |    other ...
 *       -------------------------------------------------------------
 *
 * Response Header Fields:
 *       0   1   2   3   4   5   6   7   8   9   10  ...
 *       -------------------------------------------------------------
 *       | TAG  |     SIZE      |  RETURN CODE  |    other ...
 *       -------------------------------------------------------------
 */
#define CMD_HEAD_SIZE           10
#define RSP_HEAD_SIZE           10
#define CMD_SIZE_OFFSET         2
#define CMD_CC_OFFSET           6
#define RSP_SIZE_OFFSET         2
#define RSP_RST_OFFSET          6

/*
 * The term timeout applies to timings between various states
 * or transitions within the interface protocol.
 */
#define TIMEOUT_UNIT    (0x100000 / 330) /* ~1ms, 1 tpm r/w need > 330ns */
#define TIMEOUT_A       750  /* 750ms */
#define TIMEOUT_B       2000 /* 2s */
#define TIMEOUT_C       75000  /* 750ms */
#define TIMEOUT_D       750  /* 750ms */

typedef struct __packed {
    uint32_t timeout_a;
    uint32_t timeout_b;
    uint32_t timeout_c;
    uint32_t timeout_d;
} tpm_timeout_t;

/*
 * The TCG maintains a registry of all algorithms that have an
 * assigned algorithm ID. That registry is the definitive list
 * of algorithms that may be supported by a TPM.
 */
#define TPM_ALG_ERROR             0x0000
#define TPM_ALG_FIRST             0x0001
#define TPM_ALG_RSA               0x0001
#define TPM_ALG_DES               0x0002
#define TPM_ALG__3DES             0x0003
#define TPM_ALG_SHA               0x0004
#define TPM_ALG_SHA1              0x0004
#define TPM_ALG_HMAC              0x0005
#define TPM_ALG_AES               0x0006
#define TPM_ALG_MGF1              0x0007
#define TPM_ALG_KEYEDHASH         0x0008
#define TPM_ALG_XOR               0x000A
#define TPM_ALG_SHA256            0x000B
#define TPM_ALG_SHA384            0x000C
#define TPM_ALG_SHA512            0x000D
#define TPM_ALG_WHIRLPOOL512      0x000E
#define TPM_ALG_NULL              0x0010
#define TPM_ALG_SM3_256           0x0012
#define TPM_ALG_SM4               0x0013
#define TPM_ALG_RSASSA            0x0014
#define TPM_ALG_RSAES             0x0015
#define TPM_ALG_RSAPSS            0x0016
#define TPM_ALG_OAEP              0x0017
#define TPM_ALG_ECDSA             0x0018
#define TPM_ALG_ECDH              0x0019
#define TPM_ALG_ECDAA             0x001A
#define TPM_ALG_SM2               0x001B
#define TPM_ALG_ECSCHNORR         0x001C
#define TPM_ALG_KDF1_SP800_56a    0x0020
#define TPM_ALG_KDF2              0x0021
#define TPM_ALG_KDF1_SP800_108    0x0022
#define TPM_ALG_ECC               0x0023
#define TPM_ALG_SYMCIPHER         0x0025
#define TPM_ALG_CTR               0x0040
#define TPM_ALG_OFB               0x0041
#define TPM_ALG_CBC               0x0042
#define TPM_ALG_CFB               0x0043
#define TPM_ALG_ECB               0x0044
#define TPM_ALG_LAST              0x0044
#define TPM_ALG_MAX_NUM           (TPM_ALG_LAST - TPM_ALG_ERROR)


// move from tpm.c

/*
 * TPM registers and data structures
 *
 * register values are offsets from each locality base
 * see {read,write}_tpm_reg() for data struct format
 */

/* TPM_ACCESS_x */
#define TPM_REG_ACCESS           0x00
#define TPM_REG_STS              0x18

typedef union {
    u8 _raw[1];                      /* 1-byte reg */
    struct __packed {
        u8 tpm_establishment   : 1;  /* RO, 0=T/OS has been established
                                        before */
        u8 request_use         : 1;  /* RW, 1=locality is requesting TPM use */
        u8 pending_request     : 1;  /* RO, 1=other locality is requesting
                                        TPM usage */
        u8 seize               : 1;  /* WO, 1=seize locality */
        u8 been_seized         : 1;  /* RW, 1=locality seized while active */
        u8 active_locality     : 1;  /* RW, 1=locality is active */
        u8 reserved            : 1;
        u8 tpm_reg_valid_sts   : 1;  /* RO, 1=other bits are valid */
    };
} tpm_reg_access_t;

/* TPM_STS_x */

typedef union {
    u8 _raw[3];                  /* 3-byte reg */
    struct __packed {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 self_test_done  : 1;  /* RO, only for version 2 */
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are  valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
    };
} tpm12_reg_sts_t;

typedef union {
    u8 _raw[4];                  /* 4-byte reg */
    struct __packed {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 self_test_done  : 1;  /* RO, only for version 2 */
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are
                                    valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
        /* version >= 2 */
        u8 command_cancel       : 1;
        u8 reset_establishment  : 1;
        u8 tpm_family           : 2;
        u8 reserved2            : 4;
    };
} tpm20_reg_sts_t;

//-----------------------------------------------------------------------------
// CRB I/F related definitions, see TCG PC Client Platform TPM Profile (PTP) Specification, Level 00 Revision 00.43
//-----------------------------------------------------------------------------
#define TPM_REG_LOC_STATE           0x00
#define TPM_REG_LOC_CTRL              0x8
#define TPM_LOCALITY_STS         0x0C
#define TPM_INTERFACE_ID        0x30
#define TPM_CONTROL_AREA       0x40
#define TPM_CRB_CTRL_REQ              0x40
#define TPM_CRB_CTRL_STS  0x44
#define TPM_CRB_CTRL_CANCEL 0x48
#define TPM_CRB_CTRL_START 0x4C
#define TPM_CRB_CTRL_CMD_SIZE 0x58
#define TPM_CRB_CTRL_CMD_ADDR 0x5C
#define TPM_CRB_CTRL_CMD_HADDR 0x60
#define TPM_CRB_CTRL_RSP_SIZE 0x64
#define TPM_CRB_CTRL_RSP_ADDR 0x68
#define TPM_CRB_DATA_BUFFER 0x80
#define TPMCRBBUF_LEN      0xF80     //3968 Bytes

//#define CTRL_AREA_ADDR  (uint32_t) (TPM_CRB_BASE + 0x40) 
//#define DATA_BUF_ADDR   (uint32_t) (TPM_CRB_BASE + 0x80)
 
typedef union {
    u8 _raw[4];                      /* 4-byte reg */
    struct __packed {
        u8 tpm_establishment   : 1;  
        u8 loc_assigned         : 1;  
        u8 active_locality     : 3;  
        u8 reserved              : 2; 
        u8 tpm_reg_valid_sts   : 1;  /* RO, 1=other bits are valid */
	u8 reserved1                   :8;
        u16 reserved2                :16;	
    };
} tpm_reg_loc_state_t;

typedef union {
   uint8_t _raw[4];
   struct __packed {
   uint32_t  requestAccess:1;
   uint32_t  relinquish:1;
   uint32_t  seize:1;
   uint32_t  resetEstablishment:1;
   uint32_t  reserved1:28;
   };
} tpm_reg_loc_ctrl_t;

typedef union {
	uint8_t _raw[4];
	struct __packed{
		uint32_t  Granted:1;
		uint32_t  BeenSeized:1;
		uint32_t  R:30;
	};
} tpm_reg_loc_sts_t;

typedef union {
   uint8_t _raw[8];        // 8-byte reg
   struct __packed {
        uint64_t  interface_type:4;
        uint64_t  interface_version:4;
        uint64_t  interface_capability:4;
        uint64_t  interface_selector:4;
        uint64_t  rid:8;
        uint64_t  res:8;
        uint64_t  vid:16;
        uint64_t  did:16;
   };
} tpm_crb_interface_id_t;

typedef union {
   uint8_t _raw[4];
   struct __packed{
   	   uint32_t  cmdReady:1;   
	   uint32_t  goIdle:1;
	   uint32_t  Reserved:30;
   };
 } tpm_reg_ctrl_request_t;

typedef union {
	uint8_t _raw[4];
	struct  __packed{
		uint32_t  tpmsts:1;
		uint32_t  tpmidle:1;
		uint32_t  reserved:30;
	};
} tpm_reg_ctrl_sts_t;

typedef union {
	uint8_t _raw[4];
	struct  __packed{
		uint32_t  start;
	};
} tpm_reg_ctrl_start_t;

typedef union {
	uint8_t _raw[4];
	struct  __packed{
		uint32_t  cancel;
	};
} tpm_reg_ctrl_cancel_t;

typedef union {
	uint8_t _raw[8];
	struct  __packed{
		uint32_t  cmdladdr;
		uint32_t  cmdhaddr;
	};
} tpm_reg_ctrl_cmdaddr_t;

typedef union {
	uint8_t _raw[4];
	struct  __packed{
		uint32_t  cmdsize;
	};
} tpm_reg_ctrl_cmdsize_t;

typedef union {
	uint8_t _raw[8];
	struct  __packed{
		uint64_t  rspaddr;
	};
} tpm_reg_ctrl_rspaddr_t;

typedef union {
	uint8_t _raw[4];
	struct  __packed{
		uint32_t  rspsize;
	};
} tpm_reg_ctrl_rspsize_t;

typedef union {
	uint8_t _raw[48];
	struct __packed {
		tpm_reg_ctrl_request_t  Request;
		tpm_reg_ctrl_sts_t    Status;
		tpm_reg_ctrl_cancel_t    Cancel;
		tpm_reg_ctrl_start_t  Start;
		uint64_t  R;
		tpm_reg_ctrl_cmdsize_t  CmdSize;
		tpm_reg_ctrl_cmdaddr_t  CmdAddr;
		tpm_reg_ctrl_rspsize_t  RspSize;
		tpm_reg_ctrl_rspaddr_t  RspAddr;
	};
} tpm_ctrl_area_t;

// END OF CRB I/F 

/*
 * assumes that all reg types follow above format:
 *   - packed
 *   - member named '_raw' which is array whose size is that of data to read
 */
#define read_tpm_reg(locality, reg, pdata)   _read_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

#define write_tpm_reg(locality, reg, pdata)   _write_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

static inline void _read_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
    for ( size_t i = 0; i < size; i++ )   _raw[i] = readb((TPM_LOCALITY_BASE_N(locality) | reg) + i);
}

static inline void _write_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
    for ( size_t i = 0; i < size; i++ )  writeb((TPM_LOCALITY_BASE_N(locality) | reg) + i, _raw[i]);
}


/*
 * the following inline function reversely copy the bytes from 'in' to
 * 'out', the byte number to copy is given in count.
 */
#define reverse_copy(out, in, count)     _reverse_copy((uint8_t *)(out), (uint8_t *)(in), count)

static inline void _reverse_copy(uint8_t *out, uint8_t *in, uint32_t count)
{
    for ( uint32_t i = 0; i < count; i++ )
        out[i] = in[count - i - 1];
}

/* alg id list supported by Tboot */
extern u16 tboot_alg_list[];
extern const uint8_t tboot_alg_list_count;

typedef tb_hash_t tpm_digest_t;
typedef tpm_digest_t tpm_pcr_value_t;

/* only for tpm1.2 to (un)seal */
extern tpm_pcr_value_t post_launch_pcr17;
extern tpm_pcr_value_t post_launch_pcr18;

struct tpm_if;
struct tpm_if_fp;

struct tpm_if {
#define TPM12_VER_MAJOR   1
#define TPM12_VER_MINOR   2
#define TPM20_VER_MAJOR   2
#define TPM20_VER_MINOR   0
    u8 major;
    u8 minor;
    u16 family;

    tpm_timeout_t timeout;

    u32 error; /* last reported error */
    u32 cur_loc;

    u16 banks;
    u16 algs_banks[TPM_ALG_MAX_NUM];
    u16 alg_count;
    u16 algs[TPM_ALG_MAX_NUM];

    /*
     * Only for version>=2. PCR extend policy.
     */
#define TB_EXTPOL_AGILE         0  // deprecated
#define TB_EXTPOL_EMBEDDED      1
#define TB_EXTPOL_FIXED         2
    u8 extpol;
    u16 cur_alg;

    /* NV index to be used */
    u32 lcp_own_index;
    u32 tb_policy_index;
    u32 tb_err_index;
    u32 sgx_svn_index;
};

struct tpm_if_fp {

    bool (*init)(struct tpm_if *ti);

    bool (*pcr_read)(struct tpm_if *ti, u32 locality, u32 pcr, tpm_pcr_value_t *out);
    bool (*pcr_extend)(struct tpm_if *ti, u32 locality, u32 pcr, const hash_list_t *in);
    bool (*pcr_reset)(struct tpm_if *ti, u32 locality, u32 pcr);
    bool (*hash)(struct tpm_if *ti, u32 locality, const u8 *data, u32 data_size, hash_list_t *hl);

    bool (*nv_read)(struct tpm_if *ti, u32 locality, u32 index, u32 offset, u8 *data, u32 *data_size);
    bool (*nv_write)(struct tpm_if *ti, u32 locality, u32 index, u32 offset, const u8 *data, u32 data_size);
    bool (*get_nvindex_size)(struct tpm_if *ti, u32 locality, u32 index, u32 *size);

#define TPM_NV_PER_WRITE_STCLEAR  (1<<14) 
#define TPM_NV_PER_WRITEDEFINE    (1<<13)
#define TPM_NV_PER_WRITEALL       (1<<12)
#define TPM_NV_PER_AUTHWRITE      (1<<2)
#define TPM_NV_PER_OWNERWRITE     (1<<1)
#define TPM_NV_PER_PPWRITE        (1<<0)
    bool (*get_nvindex_permission)(struct tpm_if *ti, u32 locality, u32 index, u32 *attribute);

    bool (*seal)(struct tpm_if *ti, u32 locality, u32 in_data_size, const u8 *in_data, u32 *sealed_data_size, u8 *sealed_data);
    bool (*unseal)(struct tpm_if *ti, u32 locality, u32 sealed_data_size, const u8 *sealed_data, u32 *secret_size, u8 *secret);
    bool (*verify_creation)(struct tpm_if *ti, u32 sealed_data_size, u8 *sealed_data);

    bool (*get_random)(struct tpm_if *ti, u32 locality, u8 *random_data, u32 *data_size);

    uint32_t (*save_state)(struct tpm_if *ti, u32 locality);
    
    bool (*context_save)(struct tpm_if *ti, u32 locality, u32 handle, void *context_saved);
    bool (*context_load)(struct tpm_if *ti, u32 locality, void *context_saved, u32 *handle);
    bool (*context_flush)(struct tpm_if *ti, u32 locality, u32 handle);

    bool (*cap_pcrs)(struct tpm_if *ti, u32 locality, int pcr);
    bool (*check)(void);
};

extern struct tpm_if_data tpm_if_data;
extern const struct tpm_if_fp tpm_12_if_fp;
extern const struct tpm_if_fp tpm_20_if_fp;
extern uint8_t g_tpm_ver;
extern uint8_t g_tpm_family;

extern bool tpm_validate_locality(uint32_t locality);
extern bool tpm_validate_locality_crb(uint32_t locality);
extern bool release_locality(uint32_t locality);
extern bool prepare_tpm(void);
extern bool tpm_detect(void);
extern void tpm_print(struct tpm_if *ti);
extern bool tpm_submit_cmd(u32 locality, u8 *in, u32 in_size, u8 *out, u32 *out_size);
extern bool tpm_submit_cmd_crb(u32 locality, u8 *in, u32 in_size, u8 *out, u32 *out_size);
extern bool tpm_wait_cmd_ready(uint32_t locality);
extern bool tpm_request_locality_crb(uint32_t locality);
extern bool tpm_relinquish_locality_crb(uint32_t locality);
extern bool txt_is_launched(void);
extern bool tpm_workaround_crb(void);
extern struct tpm_if *get_tpm(void);
extern const struct tpm_if_fp *get_tpm_fp(void);


//#define TPM_UNIT_TEST 1

#ifdef TPM_UNIT_TEST
void tpm_unit_test(void);
#else
#define tpm_unit_test()
#endif   /* TPM_UNIT_TEST */


#endif   /* __TPM_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
