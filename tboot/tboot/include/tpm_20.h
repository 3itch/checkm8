/*
 * tpm_20.h: TPM2.0-related structure
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

#ifndef __TPM20_H__
#define __TPM20_H__

/*
 * tpm2.0 structure defined in spec.
 */

typedef struct {
    u16        size;
    u8         buffer[1];
} TPM2B;

// Table 205 -- SHA1 Hash Values
#define SHA1_DIGEST_SIZE    20
#define SHA1_BLOCK_SIZE     64
#define SHA1_DER_SIZE       15
#define SHA1_DER            {0x30,0x21,0x30,0x09,0x06, 0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14}

// Table 206 -- SHA256 Hash Values
#define SHA256_DIGEST_SIZE    32
#define SHA256_BLOCK_SIZE     64
#define SHA256_DER_SIZE       19
#define SHA256_DER            {0x30,0x31,0x30,0x0d,0x06, 0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01, 0x05,0x00,0x04,0x20}

// Table 207 -- SHA384 Hash Values
#define SHA384_DIGEST_SIZE    48
#define SHA384_BLOCK_SIZE     128
#define SHA384_DER_SIZE       19
#define SHA384_DER            {0x30,0x41,0x30,0x0d,0x06, 0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02, 0x05,0x00,0x04,0x30}


// Table 208 -- SHA512 Hash Values
#define SHA512_DIGEST_SIZE    64
#define SHA512_BLOCK_SIZE     128
#define SHA512_DER_SIZE       19
#define SHA512_DER            {0x30,0x51,0x30,0x0d,0x06, \
        0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,\
        0x05,0x00,0x04,0x40}

// Table 210 -- SM3_256 Hash Values
#define SM3_256_DIGEST_SIZE    32
#define SM3_256_BLOCK_SIZE     64
#define SM3_256_DER_SIZE       18
#define SM3_256_DER            {0x30,0x30,0x30,0x0c,0x06, \
        0x08,0x2A,0x81,0x1C,0x81,0x45,0x01,0x83,0x11,0x05,\
        0x00,0x04,0x20}

// Table 213 -- Logic Values
#define YES      1
#define NO       0
#define TRUE     1
#define FALSE    0
#define SET      1
#define CLEAR    0

// Table 215 -- Implemented Algorithms
#define ALG_RSA               YES    // 1
#define ALG_SHA1              YES    // 1
#define ALG_HMAC              YES    // 1
#define ALG_AES               YES    // 1
#define ALG_MGF1              YES    // 1
#define ALG_XOR               YES    // 1
#define ALG_KEYEDHASH         YES    // 1
#define ALG_SHA256            YES    // 1
#define ALG_SHA384            YES    // 0
#define ALG_SHA512            YES    // 0
#define ALG_SM3_256           YES    // 1
#define ALG_SM4               YES    // 1
#define ALG_RSASSA            YES    // 1
#define ALG_RSAES             YES    // 1
#define ALG_RSAPSS            YES    // 1
#define ALG_OAEP              YES    // 1
#define ALG_ECC               YES    // 1
#define ALG_ECDH              YES    // 1
#define ALG_ECDSA             YES    // 1
#define ALG_ECDAA             YES    // 1
#define ALG_SM2               YES    // 1
#define ALG_ECSCHNORR         YES    // 1
#define ALG_SYMCIPHER         YES    // 1
#define ALG_KDF1_SP800_56a    YES    // 1
#define ALG_KDF2              NO     // 0
#define ALG_KDF1_SP800_108    YES    // 1
#define ALG_CTR               YES    // 1
#define ALG_OFB               YES    // 1
#define ALG_CBC               YES    // 1
#define ALG_CFB               YES    // 1
#define ALG_ECB               YES    // 1

#define HASH_COUNT (ALG_SHA1+ALG_SHA256+ALG_SM3_256+ALG_SHA384+ALG_SHA512)

// Table 217 -- RSA Algorithm Constants
#define RSA_KEY_SIZES_BITS    {1024, 2048}    // {1024,2048}
#define MAX_RSA_KEY_BITS      2048
#define MAX_RSA_KEY_BYTES     ((MAX_RSA_KEY_BITS + 7) / 8)    // 256

// Table 218 -- ECC Algorithm Constants
#define ECC_CURVES            {TPM_ECC_NIST_P256,TPM_ECC_BN_P256,TPM_ECC_SM2_P256}
#define ECC_KEY_SIZES_BITS    {256}
#define MAX_ECC_KEY_BITS      256
#define MAX_ECC_KEY_BYTES     ((MAX_ECC_KEY_BITS + 7) / 8)    // 32

// Table 219 -- AES Algorithm Constants
#define AES_KEY_SIZES_BITS          {128}
#define MAX_AES_KEY_BITS            128
#define MAX_AES_BLOCK_SIZE_BYTES    16
#define MAX_AES_KEY_BYTES           ((MAX_AES_KEY_BITS + 7) / 8)    // 16

// Table 221 -- Symmetric Algorithm Constants
#define MAX_SYM_KEY_BITS      MAX_AES_KEY_BITS    // 128
#define MAX_SYM_KEY_BYTES     MAX_AES_KEY_BYTES    // 16
#define MAX_SYM_BLOCK_SIZE    MAX_AES_BLOCK_SIZE_BYTES    // 16

// Table 222 -- Implementation Values
#define FIELD_UPGRADE_IMPLEMENTED      NO    // 0
typedef u16                            BSIZE;
#define BUFFER_ALIGNMENT               4
#define IMPLEMENTATION_PCR             24
#define PLATFORM_PCR                   24
#define DRTM_PCR                       17
#define NUM_LOCALITIES                 5
#define MAX_HANDLE_NUM                 3
#define MAX_ACTIVE_SESSIONS            64
typedef u16                            CONTEXT_SLOT;
typedef u64                            CONTEXT_COUNTER;
#define MAX_LOADED_SESSIONS            3
#define MAX_SESSION_NUM                3
#define MAX_LOADED_OBJECTS             3
#define MIN_EVICT_OBJECTS              2
#define PCR_SELECT_MIN                 ((PLATFORM_PCR+7)/8)    // 3
#define PCR_SELECT_MAX                 ((IMPLEMENTATION_PCR+7)/8)    // 3
#define NUM_POLICY_PCR_GROUP           1
#define NUM_AUTHVALUE_PCR_GROUP        1
#define MAX_CONTEXT_SIZE               4000
#define MAX_DIGEST_BUFFER              1024
#define MAX_NV_INDEX_SIZE              1024
#define MAX_CAP_BUFFER                 1024
#define NV_MEMORY_SIZE                 16384
#define NUM_STATIC_PCR                 16
#define MAX_ALG_LIST_SIZE              64
#define TIMER_PRESCALE                 100000
#define PRIMARY_SEED_SIZE              32
#define CONTEXT_ENCRYPT_ALG            TPM_ALG_AES
#define CONTEXT_ENCRYPT_KEY_BITS       MAX_SYM_KEY_BITS    // 128
#define CONTEXT_ENCRYPT_KEY_BYTES      ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#define CONTEXT_INTEGRITY_HASH_ALG     TPM_ALG_SHA256
#define CONTEXT_INTEGRITY_HASH_SIZE    SHA256_DIGEST_SIZE    // 32
#define PROOF_SIZE                     CONTEXT_INTEGRITY_HASH_SIZE    // 32
#define NV_CLOCK_UPDATE_INTERVAL       12
#define NUM_POLICY_PCR                 1
#define MAX_COMMAND_SIZE               4096
#define MAX_RESPONSE_SIZE              4096
#define ORDERLY_BITS                   8
#define MAX_ORDERLY_COUNT              ((1 << ORDERLY_BITS) - 1)    // 255
#define ALG_ID_FIRST                   TPM_ALG_FIRST
#define ALG_ID_LAST                    TPM_ALG_LAST
#define MAX_SYM_DATA                   128
#define MAX_HASH_STATE_SIZE            512
#define MAX_RNG_ENTROPY_SIZE           64
#define RAM_INDEX_SPACE                512
#define RSA_DEFAULT_PUBLIC_EXPONENT    0x00010001
#define ENABLE_PCR_NO_INCREMENT        YES    // 1

// Table 11 -- TPM_CC Constants <I/O,S>
typedef u32 TPM_CC;

#define TPM_CC_FIRST                         (TPM_CC)(0x0000011F)    
#define TPM_CC_PP_FIRST                      (TPM_CC)(0x0000011F)    
#define TPM_CC_NV_UndefineSpaceSpecial       (TPM_CC)(0x0000011F)    
#define TPM_CC_EvictControl                  (TPM_CC)(0x00000120)    
#define TPM_CC_HierarchyControl              (TPM_CC)(0x00000121)    
#define TPM_CC_NV_UndefineSpace              (TPM_CC)(0x00000122)    
#define TPM_CC_ChangeEPS                     (TPM_CC)(0x00000124)    
#define TPM_CC_ChangePPS                     (TPM_CC)(0x00000125)    
#define TPM_CC_Clear                         (TPM_CC)(0x00000126)    
#define TPM_CC_ClearControl                  (TPM_CC)(0x00000127)    
#define TPM_CC_ClockSet                      (TPM_CC)(0x00000128)    
#define TPM_CC_HierarchyChangeAuth           (TPM_CC)(0x00000129)    
#define TPM_CC_NV_DefineSpace                (TPM_CC)(0x0000012A)    
#define TPM_CC_PCR_Allocate                  (TPM_CC)(0x0000012B)    
#define TPM_CC_PCR_SetAuthPolicy             (TPM_CC)(0x0000012C)    
#define TPM_CC_PP_Commands                   (TPM_CC)(0x0000012D)    
#define TPM_CC_SetPrimaryPolicy              (TPM_CC)(0x0000012E)    
#define TPM_CC_FieldUpgradeStart             (TPM_CC)(0x0000012F)    
#define TPM_CC_ClockRateAdjust               (TPM_CC)(0x00000130)    
#define TPM_CC_CreatePrimary                 (TPM_CC)(0x00000131)    
#define TPM_CC_NV_GlobalWriteLock            (TPM_CC)(0x00000132)    
#define TPM_CC_PP_LAST                       (TPM_CC)(0x00000132)    
#define TPM_CC_GetCommandAuditDigest         (TPM_CC)(0x00000133)    
#define TPM_CC_NV_Increment                  (TPM_CC)(0x00000134)    
#define TPM_CC_NV_SetBits                    (TPM_CC)(0x00000135)    
#define TPM_CC_NV_Extend                     (TPM_CC)(0x00000136)    
#define TPM_CC_NV_Write                      (TPM_CC)(0x00000137)    
#define TPM_CC_NV_WriteLock                  (TPM_CC)(0x00000138)    
#define TPM_CC_DictionaryAttackLockReset     (TPM_CC)(0x00000139)    
#define TPM_CC_DictionaryAttackParameters    (TPM_CC)(0x0000013A)    
#define TPM_CC_NV_ChangeAuth                 (TPM_CC)(0x0000013B)    
#define TPM_CC_PCR_Event                     (TPM_CC)(0x0000013C)    
#define TPM_CC_PCR_Reset                     (TPM_CC)(0x0000013D)    
#define TPM_CC_SequenceComplete              (TPM_CC)(0x0000013E)    
#define TPM_CC_SetAlgorithmSet               (TPM_CC)(0x0000013F)    
#define TPM_CC_SetCommandCodeAuditStatus     (TPM_CC)(0x00000140)    
#define TPM_CC_FieldUpgradeData              (TPM_CC)(0x00000141)    
#define TPM_CC_IncrementalSelfTest           (TPM_CC)(0x00000142)    
#define TPM_CC_SelfTest                      (TPM_CC)(0x00000143)    
#define TPM_CC_Startup                       (TPM_CC)(0x00000144)    
#define TPM_CC_Shutdown                      (TPM_CC)(0x00000145)    
#define TPM_CC_StirRandom                    (TPM_CC)(0x00000146)    
#define TPM_CC_ActivateCredential            (TPM_CC)(0x00000147)    
#define TPM_CC_Certify                       (TPM_CC)(0x00000148)    
#define TPM_CC_PolicyNV                      (TPM_CC)(0x00000149)    
#define TPM_CC_CertifyCreation               (TPM_CC)(0x0000014A)    
#define TPM_CC_Duplicate                     (TPM_CC)(0x0000014B)    
#define TPM_CC_GetTime                       (TPM_CC)(0x0000014C)    
#define TPM_CC_GetSessionAuditDigest         (TPM_CC)(0x0000014D)    
#define TPM_CC_NV_Read                       (TPM_CC)(0x0000014E)    
#define TPM_CC_NV_ReadLock                   (TPM_CC)(0x0000014F)    
#define TPM_CC_ObjectChangeAuth              (TPM_CC)(0x00000150)    
#define TPM_CC_PolicySecret                  (TPM_CC)(0x00000151)    
#define TPM_CC_Rewrap                        (TPM_CC)(0x00000152)    
#define TPM_CC_Create                        (TPM_CC)(0x00000153)    
#define TPM_CC_ECDH_ZGen                     (TPM_CC)(0x00000154)    
#define TPM_CC_HMAC                          (TPM_CC)(0x00000155)    
#define TPM_CC_Import                        (TPM_CC)(0x00000156)    
#define TPM_CC_Load                          (TPM_CC)(0x00000157)    
#define TPM_CC_Quote                         (TPM_CC)(0x00000158)    
#define TPM_CC_RSA_Decrypt                   (TPM_CC)(0x00000159)    
#define TPM_CC_HMAC_Start                    (TPM_CC)(0x0000015B)    
#define TPM_CC_SequenceUpdate                (TPM_CC)(0x0000015C)    
#define TPM_CC_Sign                          (TPM_CC)(0x0000015D)    
#define TPM_CC_Unseal                        (TPM_CC)(0x0000015E)    
#define TPM_CC_PolicySigned                  (TPM_CC)(0x00000160)    
#define TPM_CC_ContextLoad                   (TPM_CC)(0x00000161)    
#define TPM_CC_ContextSave                   (TPM_CC)(0x00000162)    
#define TPM_CC_ECDH_KeyGen                   (TPM_CC)(0x00000163)    
#define TPM_CC_EncryptDecrypt                (TPM_CC)(0x00000164)    
#define TPM_CC_FlushContext                  (TPM_CC)(0x00000165)    
#define TPM_CC_LoadExternal                  (TPM_CC)(0x00000167)    
#define TPM_CC_MakeCredential                (TPM_CC)(0x00000168)    
#define TPM_CC_NV_ReadPublic                 (TPM_CC)(0x00000169)    
#define TPM_CC_PolicyAuthorize               (TPM_CC)(0x0000016A)    
#define TPM_CC_PolicyAuthValue               (TPM_CC)(0x0000016B)    
#define TPM_CC_PolicyCommandCode             (TPM_CC)(0x0000016C)    
#define TPM_CC_PolicyCounterTimer            (TPM_CC)(0x0000016D)    
#define TPM_CC_PolicyCpHash                  (TPM_CC)(0x0000016E)    
#define TPM_CC_PolicyLocality                (TPM_CC)(0x0000016F)    
#define TPM_CC_PolicyNameHash                (TPM_CC)(0x00000170)    
#define TPM_CC_PolicyOR                      (TPM_CC)(0x00000171)    
#define TPM_CC_PolicyTicket                  (TPM_CC)(0x00000172)    
#define TPM_CC_ReadPublic                    (TPM_CC)(0x00000173)    
#define TPM_CC_RSA_Encrypt                   (TPM_CC)(0x00000174)    
#define TPM_CC_StartAuthSession              (TPM_CC)(0x00000176)    
#define TPM_CC_VerifySignature               (TPM_CC)(0x00000177)    
#define TPM_CC_ECC_Parameters                (TPM_CC)(0x00000178)    
#define TPM_CC_FirmwareRead                  (TPM_CC)(0x00000179)    
#define TPM_CC_GetCapability                 (TPM_CC)(0x0000017A)    
#define TPM_CC_GetRandom                     (TPM_CC)(0x0000017B)    
#define TPM_CC_GetTestResult                 (TPM_CC)(0x0000017C)    
#define TPM_CC_Hash                          (TPM_CC)(0x0000017D)    
#define TPM_CC_PCR_Read                      (TPM_CC)(0x0000017E)    
#define TPM_CC_PolicyPCR                     (TPM_CC)(0x0000017F)    
#define TPM_CC_PolicyRestart                 (TPM_CC)(0x00000180)    
#define TPM_CC_ReadClock                     (TPM_CC)(0x00000181)    
#define TPM_CC_PCR_Extend                    (TPM_CC)(0x00000182)    
#define TPM_CC_PCR_SetAuthValue              (TPM_CC)(0x00000183)    
#define TPM_CC_NV_Certify                    (TPM_CC)(0x00000184)    
#define TPM_CC_EventSequenceComplete         (TPM_CC)(0x00000185)    
#define TPM_CC_HashSequenceStart             (TPM_CC)(0x00000186)    
#define TPM_CC_PolicyPhysicalPresence        (TPM_CC)(0x00000187)    
#define TPM_CC_PolicyDuplicationSelect       (TPM_CC)(0x00000188)    
#define TPM_CC_PolicyGetDigest               (TPM_CC)(0x00000189)    
#define TPM_CC_TestParms                     (TPM_CC)(0x0000018A)    
#define TPM_CC_Commit                        (TPM_CC)(0x0000018B)    
#define TPM_CC_PolicyPassword                (TPM_CC)(0x0000018C)    
#define TPM_CC_SM2_ZGen                      (TPM_CC)(0x0000018D)    
#define TPM_CC_LAST                          (TPM_CC)(0x0000018D)    

// Table 15 -- TPM_RC Constants <O,S>
typedef u32 TPM_RCS;    // The 'safe' error codes
typedef u32 TPM_RC;

#define TPM_RC_SUCCESS              (TPM_RC)(0x000)    
#define TPM_RC_BAD_TAG              (TPM_RC)(0x030)    
#define RC_VER1                     (TPM_RC)(0x100)    
#define TPM_RC_INITIALIZE           (TPM_RC)(RC_VER1 + 0x000)    
#define TPM_RC_FAILURE              (TPM_RC)(RC_VER1 + 0x001)    
#define TPM_RC_SEQUENCE             (TPM_RC)(RC_VER1 + 0x003)    
#define TPM_RC_PRIVATE              (TPM_RC)(RC_VER1 + 0x00B)    
#define TPM_RC_HMAC                 (TPM_RC)(RC_VER1 + 0x019)    
#define TPM_RC_DISABLED             (TPM_RC)(RC_VER1 + 0x020)    
#define TPM_RC_EXCLUSIVE            (TPM_RC)(RC_VER1 + 0x021)    
#define TPM_RC_AUTH_TYPE            (TPM_RC)(RC_VER1 + 0x024)    
#define TPM_RC_AUTH_MISSING         (TPM_RC)(RC_VER1 + 0x025)    
#define TPM_RC_POLICY               (TPM_RC)(RC_VER1 + 0x026)    
#define TPM_RC_PCR                  (TPM_RC)(RC_VER1 + 0x027)    
#define TPM_RC_PCR_CHANGED          (TPM_RC)(RC_VER1 + 0x028)    
#define TPM_RC_UPGRADE              (TPM_RC)(RC_VER1 + 0x02D)    
#define TPM_RC_TOO_MANY_CONTEXTS    (TPM_RC)(RC_VER1 + 0x02E)    
#define TPM_RC_AUTH_UNAVAILABLE     (TPM_RC)(RC_VER1 + 0x02F)    
#define TPM_RC_REBOOT               (TPM_RC)(RC_VER1 + 0x030)    
#define TPM_RC_UNBALANCED           (TPM_RC)(RC_VER1 + 0x031)    
#define TPM_RC_COMMAND_SIZE         (TPM_RC)(RC_VER1 + 0x042)    
#define TPM_RC_COMMAND_CODE         (TPM_RC)(RC_VER1 + 0x043)    
#define TPM_RC_AUTHSIZE             (TPM_RC)(RC_VER1 + 0x044)    
#define TPM_RC_AUTH_CONTEXT         (TPM_RC)(RC_VER1 + 0x045)    
#define TPM_RC_NV_RANGE             (TPM_RC)(RC_VER1 + 0x046)    
#define TPM_RC_NV_SIZE              (TPM_RC)(RC_VER1 + 0x047)    
#define TPM_RC_NV_LOCKED            (TPM_RC)(RC_VER1 + 0x048)    
#define TPM_RC_NV_AUTHORIZATION     (TPM_RC)(RC_VER1 + 0x049)    
#define TPM_RC_NV_UNINITIALIZED     (TPM_RC)(RC_VER1 + 0x04A)    
#define TPM_RC_NV_SPACE             (TPM_RC)(RC_VER1 + 0x04B)    
#define TPM_RC_NV_DEFINED           (TPM_RC)(RC_VER1 + 0x04C)    
#define TPM_RC_BAD_CONTEXT          (TPM_RC)(RC_VER1 + 0x050)    
#define TPM_RC_CPHASH               (TPM_RC)(RC_VER1 + 0x051)    
#define TPM_RC_PARENT               (TPM_RC)(RC_VER1 + 0x052)    
#define TPM_RC_NEEDS_TEST           (TPM_RC)(RC_VER1 + 0x053)    
#define TPM_RC_NO_RESULT            (TPM_RC)(RC_VER1 + 0x054)    
#define TPM_RC_SENSITIVE            (TPM_RC)(RC_VER1 + 0x055)    
#define RC_MAX_FM0                  (TPM_RC)(RC_VER1 + 0x07F)    
#define RC_FMT1                     (TPM_RC)(0x080)    
#define TPM_RC_ASYMMETRIC           (TPM_RC)(RC_FMT1 + 0x001)    
#define TPM_RCS_ASYMMETRIC          (TPM_RCS)(RC_FMT1 + 0x001)
#define TPM_RC_ATTRIBUTES           (TPM_RC)(RC_FMT1 + 0x002)    
#define TPM_RCS_ATTRIBUTES          (TPM_RCS)(RC_FMT1 + 0x002)
#define TPM_RC_HASH                 (TPM_RC)(RC_FMT1 + 0x003)    
#define TPM_RCS_HASH                (TPM_RCS)(RC_FMT1 + 0x003)
#define TPM_RC_VALUE                (TPM_RC)(RC_FMT1 + 0x004)    
#define TPM_RCS_VALUE               (TPM_RCS)(RC_FMT1 + 0x004)
#define TPM_RC_HIERARCHY            (TPM_RC)(RC_FMT1 + 0x005)    
#define TPM_RCS_HIERARCHY           (TPM_RCS)(RC_FMT1 + 0x005)
#define TPM_RC_KEY_SIZE             (TPM_RC)(RC_FMT1 + 0x007)    
#define TPM_RCS_KEY_SIZE            (TPM_RCS)(RC_FMT1 + 0x007)
#define TPM_RC_MGF                  (TPM_RC)(RC_FMT1 + 0x008)    
#define TPM_RCS_MGF                 (TPM_RCS)(RC_FMT1 + 0x008)
#define TPM_RC_MODE                 (TPM_RC)(RC_FMT1 + 0x009)    
#define TPM_RCS_MODE                (TPM_RCS)(RC_FMT1 + 0x009)
#define TPM_RC_TYPE                 (TPM_RC)(RC_FMT1 + 0x00A)    
#define TPM_RCS_TYPE                (TPM_RCS)(RC_FMT1 + 0x00A)
#define TPM_RC_HANDLE               (TPM_RC)(RC_FMT1 + 0x00B)    
#define TPM_RCS_HANDLE              (TPM_RCS)(RC_FMT1 + 0x00B)
#define TPM_RC_KDF                  (TPM_RC)(RC_FMT1 + 0x00C)    
#define TPM_RCS_KDF                 (TPM_RCS)(RC_FMT1 + 0x00C)
#define TPM_RC_RANGE                (TPM_RC)(RC_FMT1 + 0x00D)    
#define TPM_RCS_RANGE               (TPM_RCS)(RC_FMT1 + 0x00D)
#define TPM_RC_AUTH_FAIL            (TPM_RC)(RC_FMT1 + 0x00E)    
#define TPM_RCS_AUTH_FAIL           (TPM_RCS)(RC_FMT1 + 0x00E)
#define TPM_RC_NONCE                (TPM_RC)(RC_FMT1 + 0x00F)    
#define TPM_RCS_NONCE               (TPM_RCS)(RC_FMT1 + 0x00F)
#define TPM_RC_PP                   (TPM_RC)(RC_FMT1 + 0x010)    
#define TPM_RCS_PP                  (TPM_RCS)(RC_FMT1 + 0x010)
#define TPM_RC_SCHEME               (TPM_RC)(RC_FMT1 + 0x012)    
#define TPM_RCS_SCHEME              (TPM_RCS)(RC_FMT1 + 0x012)
#define TPM_RC_SIZE                 (TPM_RC)(RC_FMT1 + 0x015)    
#define TPM_RCS_SIZE                (TPM_RCS)(RC_FMT1 + 0x015)
#define TPM_RC_SYMMETRIC            (TPM_RC)(RC_FMT1 + 0x016)    
#define TPM_RCS_SYMMETRIC           (TPM_RCS)(RC_FMT1 + 0x016)
#define TPM_RC_TAG                  (TPM_RC)(RC_FMT1 + 0x017)    
#define TPM_RCS_TAG                 (TPM_RCS)(RC_FMT1 + 0x017)
#define TPM_RC_SELECTOR             (TPM_RC)(RC_FMT1 + 0x018)    
#define TPM_RCS_SELECTOR            (TPM_RCS)(RC_FMT1 + 0x018)
#define TPM_RC_INSUFFICIENT         (TPM_RC)(RC_FMT1 + 0x01A)    
#define TPM_RCS_INSUFFICIENT        (TPM_RCS)(RC_FMT1 + 0x01A)
#define TPM_RC_SIGNATURE            (TPM_RC)(RC_FMT1 + 0x01B)    
#define TPM_RCS_SIGNATURE           (TPM_RCS)(RC_FMT1 + 0x01B)
#define TPM_RC_KEY                  (TPM_RC)(RC_FMT1 + 0x01C)    
#define TPM_RCS_KEY                 (TPM_RCS)(RC_FMT1 + 0x01C)
#define TPM_RC_POLICY_FAIL          (TPM_RC)(RC_FMT1 + 0x01D)    
#define TPM_RCS_POLICY_FAIL         (TPM_RCS)(RC_FMT1 + 0x01D)
#define TPM_RC_INTEGRITY            (TPM_RC)(RC_FMT1 + 0x01F)    
#define TPM_RCS_INTEGRITY           (TPM_RCS)(RC_FMT1 + 0x01F)
#define TPM_RC_TICKET               (TPM_RC)(RC_FMT1 + 0x020)    
#define TPM_RCS_TICKET              (TPM_RCS)(RC_FMT1 + 0x020)
#define TPM_RC_RESERVED_BITS        (TPM_RC)(RC_FMT1 + 0x021)    
#define TPM_RCS_RESERVED_BITS       (TPM_RCS)(RC_FMT1 + 0x021)
#define TPM_RC_BAD_AUTH             (TPM_RC)(RC_FMT1 + 0x022)    
#define TPM_RCS_BAD_AUTH            (TPM_RCS)(RC_FMT1 + 0x022)
#define TPM_RC_EXPIRED              (TPM_RC)(RC_FMT1 + 0x023)    
#define TPM_RCS_EXPIRED             (TPM_RCS)(RC_FMT1 + 0x023)
#define TPM_RC_POLICY_CC            (TPM_RC)(RC_FMT1 + 0x024 )    
#define TPM_RCS_POLICY_CC           (TPM_RCS)(RC_FMT1 + 0x024 )
#define TPM_RC_BINDING              (TPM_RC)(RC_FMT1 + 0x025)    
#define TPM_RCS_BINDING             (TPM_RCS)(RC_FMT1 + 0x025)
#define TPM_RC_CURVE                (TPM_RC)(RC_FMT1 + 0x026)    
#define TPM_RCS_CURVE               (TPM_RCS)(RC_FMT1 + 0x026)
#define TPM_RC_ECC_POINT            (TPM_RC)(RC_FMT1 + 0x027)    
#define TPM_RCS_ECC_POINT           (TPM_RCS)(RC_FMT1 + 0x027)
#define RC_WARN                     (TPM_RC)(0x900)    
#define TPM_RC_CONTEXT_GAP          (TPM_RC)(RC_WARN + 0x001)    
#define TPM_RC_OBJECT_MEMORY        (TPM_RC)(RC_WARN + 0x002)    
#define TPM_RC_SESSION_MEMORY       (TPM_RC)(RC_WARN + 0x003)    
#define TPM_RC_MEMORY               (TPM_RC)(RC_WARN + 0x004)    
#define TPM_RC_SESSION_HANDLES      (TPM_RC)(RC_WARN + 0x005)    
#define TPM_RC_OBJECT_HANDLES       (TPM_RC)(RC_WARN + 0x006)    
#define TPM_RC_LOCALITY             (TPM_RC)(RC_WARN + 0x007)    
#define TPM_RC_YIELDED              (TPM_RC)(RC_WARN + 0x008)    
#define TPM_RC_CANCELLED            (TPM_RC)(RC_WARN + 0x009)    
#define TPM_RC_TESTING              (TPM_RC)(RC_WARN + 0x00A)    
#define TPM_RC_REFERENCE_H0         (TPM_RC)(RC_WARN + 0x010)    
#define TPM_RC_REFERENCE_H1         (TPM_RC)(RC_WARN + 0x011)    
#define TPM_RC_REFERENCE_H2         (TPM_RC)(RC_WARN + 0x012)    
#define TPM_RC_REFERENCE_H3         (TPM_RC)(RC_WARN + 0x013)    
#define TPM_RC_REFERENCE_H4         (TPM_RC)(RC_WARN + 0x014)    
#define TPM_RC_REFERENCE_H5         (TPM_RC)(RC_WARN + 0x015)    
#define TPM_RC_REFERENCE_H6         (TPM_RC)(RC_WARN + 0x016)    
#define TPM_RC_REFERENCE_S0         (TPM_RC)(RC_WARN + 0x018)    
#define TPM_RC_REFERENCE_S1         (TPM_RC)(RC_WARN + 0x019)    
#define TPM_RC_REFERENCE_S2         (TPM_RC)(RC_WARN + 0x01A)    
#define TPM_RC_REFERENCE_S3         (TPM_RC)(RC_WARN + 0x01B)    
#define TPM_RC_REFERENCE_S4         (TPM_RC)(RC_WARN + 0x01C)    
#define TPM_RC_REFERENCE_S5         (TPM_RC)(RC_WARN + 0x01D)    
#define TPM_RC_REFERENCE_S6         (TPM_RC)(RC_WARN + 0x01E)    
#define TPM_RC_NV_RATE              (TPM_RC)(RC_WARN + 0x020)    
#define TPM_RC_LOCKOUT              (TPM_RC)(RC_WARN + 0x021)    
#define TPM_RC_RETRY                (TPM_RC)(RC_WARN + 0x022)    
#define TPM_RC_NV_UNAVAILABLE       (TPM_RC)(RC_WARN + 0x023)    
#define TPM_RC_NOT_USED             (TPM_RC)(RC_WARN + 0x7F)    
#define TPM_RC_H                    (TPM_RC)(0x000)    
#define TPM_RC_P                    (TPM_RC)(0x040)    
#define TPM_RC_S                    (TPM_RC)(0x800)    
#define TPM_RC_1                    (TPM_RC)(0x100)    
#define TPM_RC_2                    (TPM_RC)(0x200)    
#define TPM_RC_3                    (TPM_RC)(0x300)    
#define TPM_RC_4                    (TPM_RC)(0x400)    
#define TPM_RC_5                    (TPM_RC)(0x500)    
#define TPM_RC_6                    (TPM_RC)(0x600)    
#define TPM_RC_7                    (TPM_RC)(0x700)    
#define TPM_RC_8                    (TPM_RC)(0x800)    
#define TPM_RC_9                    (TPM_RC)(0x900)    
#define TPM_RC_A                    (TPM_RC)(0xA00)    
#define TPM_RC_B                    (TPM_RC)(0xB00)    
#define TPM_RC_C                    (TPM_RC)(0xC00)    
#define TPM_RC_D                    (TPM_RC)(0xD00)    
#define TPM_RC_E                    (TPM_RC)(0xE00)    
#define TPM_RC_F                    (TPM_RC)(0xF00)    
#define TPM_RC_N_MASK               (TPM_RC)(0xF00) 

// Table 18 -- TPM_ST Constants <I/O,S>
typedef u16 TPM_ST;

#define TPM_ST_RSP_COMMAND             (TPM_ST)(0x00C4)    
#define TPM_ST_NULL                    (TPM_ST)(0X8000)    
#define TPM_ST_NO_SESSIONS             (TPM_ST)(0x8001)    
#define TPM_ST_SESSIONS                (TPM_ST)(0x8002)    
#define TPM_ST_ATTEST_NV               (TPM_ST)(0x8014)    
#define TPM_ST_ATTEST_COMMAND_AUDIT    (TPM_ST)(0x8015)    
#define TPM_ST_ATTEST_SESSION_AUDIT    (TPM_ST)(0x8016)    
#define TPM_ST_ATTEST_CERTIFY          (TPM_ST)(0x8017)    
#define TPM_ST_ATTEST_QUOTE            (TPM_ST)(0x8018)    
#define TPM_ST_ATTEST_TIME             (TPM_ST)(0x8019)    
#define TPM_ST_ATTEST_CREATION         (TPM_ST)(0x801A)    
#define TPM_ST_CREATION                (TPM_ST)(0x8021)    
#define TPM_ST_VERIFIED                (TPM_ST)(0x8022)    
#define TPM_ST_AUTH_SECRET             (TPM_ST)(0x8023)    
#define TPM_ST_HASHCHECK               (TPM_ST)(0x8024)    
#define TPM_ST_AUTH_SIGNED             (TPM_ST)(0x8025)    
#define TPM_ST_FU_MANIFEST             (TPM_ST)(0x8029) 

// Table 19 -- TPM_SU Constants <I>
typedef u16 TPM_SU;

#define    TPM_SU_CLEAR     (TPM_SU)(0x0000)    
#define    TPM_SU_STATE     (TPM_SU)(0x0001) 

// Table 21 -- TPM_CAP Constants <I/O,S>
typedef u32 TPM_CAP;

#define TPM_CAP_FIRST              (TPM_CAP)(0x00000000)    
#define TPM_CAP_ALGS               (TPM_CAP)(0x00000000)    
#define TPM_CAP_HANDLES            (TPM_CAP)(0x00000001)    
#define TPM_CAP_COMMANDS           (TPM_CAP)(0x00000002)    
#define TPM_CAP_PP_COMMANDS        (TPM_CAP)(0x00000003)    
#define TPM_CAP_AUDIT_COMMANDS     (TPM_CAP)(0x00000004)    
#define TPM_CAP_PCRS               (TPM_CAP)(0x00000005)    
#define TPM_CAP_TPM_PROPERTIES     (TPM_CAP)(0x00000006)    
#define TPM_CAP_PCR_PROPERTIES     (TPM_CAP)(0x00000007)    
#define TPM_CAP_ECC_CURVES         (TPM_CAP)(0x00000008)    
#define TPM_CAP_LAST               (TPM_CAP)(0x00000008)    
#define TPM_CAP_VENDOR_PROPERTY    (TPM_CAP)(0x00000100) 

// Table 25 -- Handles Types <I/O>
typedef u32     TPM_HANDLE;
typedef u8      TPM_HT;

#define TPM_HT_PCR               (TPM_HT)(0x00)    
#define TPM_HT_NV_INDEX          (TPM_HT)(0x01)    
#define TPM_HT_HMAC_SESSION      (TPM_HT)(0x02)    
#define TPM_HT_LOADED_SESSION    (TPM_HT)(0x02)    
#define TPM_HT_POLICY_SESSION    (TPM_HT)(0x03)    
#define TPM_HT_ACTIVE_SESSION    (TPM_HT)(0x03)    
#define TPM_HT_PERMANENT         (TPM_HT)(0x40)    
#define TPM_HT_TRANSIENT         (TPM_HT)(0x80)    
#define TPM_HT_PERSISTENT        (TPM_HT)(0x81) 

// Table 27 -- TPM_RH Constants <I,S>
typedef u32 TPM_RH;

#define TPM_RH_FIRST          (TPM_RH)(0x40000000)    
#define TPM_RH_SRK            (TPM_RH)(0x40000000)    
#define TPM_RH_OWNER          (TPM_RH)(0x40000001)    
#define TPM_RH_REVOKE         (TPM_RH)(0x40000002)    
#define TPM_RH_TRANSPORT      (TPM_RH)(0x40000003)    
#define TPM_RH_OPERATOR       (TPM_RH)(0x40000004)    
#define TPM_RH_ADMIN          (TPM_RH)(0x40000005)    
#define TPM_RH_EK             (TPM_RH)(0x40000006)    
#define TPM_RH_NULL           (TPM_RH)(0x40000007)    
#define TPM_RH_UNASSIGNED     (TPM_RH)(0x40000008)    
#define TPM_RS_PW             (TPM_RH)(0x40000009)    
#define TPM_RH_LOCKOUT        (TPM_RH)(0x4000000A)    
#define TPM_RH_ENDORSEMENT    (TPM_RH)(0x4000000B)    
#define TPM_RH_PLATFORM       (TPM_RH)(0x4000000C)    
#define TPM_RH_LAST           (TPM_RH)(0x4000000C) 

#define RC_ContextSave_saveHandle      (TPM_RC_P + TPM_RC_1)
#define RC_ContextLoad_context         (TPM_RC_P + TPM_RC_1)
#define RC_FlushContext_flushHandle    (TPM_RC_P + TPM_RC_1)


// Table 29 -- TPMA_ALGORITHM Bits <I/O>
typedef struct {
    unsigned int asymmetric : 1;
    unsigned int symmetric  : 1;
    unsigned int hash       : 1;
    unsigned int object     : 1;
    unsigned int reserved5  : 4;
    unsigned int signing    : 1;
    unsigned int encrypting : 1;
    unsigned int method     : 1;
    unsigned int reserved9  : 21;
} TPMA_ALGORITHM ;

// Table 30 -- TPMA_OBJECT Bits <I/O>
typedef struct {
    unsigned int reserved1            : 1;
    unsigned int fixedTPM             : 1;
    unsigned int stClear              : 1;
    unsigned int reserved4            : 1;
    unsigned int fixedParent          : 1;
    unsigned int sensitiveDataOrigin  : 1;
    unsigned int userWithAuth         : 1;
    unsigned int adminWithPolicy      : 1;
    unsigned int reserved9            : 2;
    unsigned int noDA                 : 1;
    unsigned int encryptedDuplication : 1;
    unsigned int reserved12           : 4;
    unsigned int restricted           : 1; // Start of 2nd dword
    unsigned int decrypt              : 1;
    unsigned int sign                 : 1;
    unsigned int reserved16           : 13;
} TPMA_OBJECT ;

// Table 31 -- TPMA_SESSION Bits <I/O>
typedef struct {
    unsigned int continueSession : 1;
    unsigned int auditExclusive  : 1;
    unsigned int auditReset      : 1;
    unsigned int reserved4       : 2;
    unsigned int decrypt         : 1;
    unsigned int encrypt         : 1;
    unsigned int audit           : 1;
} TPMA_SESSION;

// Table 32 -- TPMA_LOCALITY Bits <I/O>
typedef struct {
    unsigned int TPM_LOC_ZERO  : 1;
    unsigned int TPM_LOC_ONE   : 1;
    unsigned int TPM_LOC_TWO   : 1;
    unsigned int TPM_LOC_THREE : 1;
    unsigned int TPM_LOC_FOUR  : 1;
    unsigned int reserved6     : 3;
} TPMA_LOCALITY;
// Table 47  Definition of TPMI_DH_CONTEXT Type
typedef TPM_HANDLE TPMI_DH_CONTEXT;
// Table 48  Definition of TPMI_RH_HIERARCHY Type
typedef TPM_HANDLE TPMI_RH_HIERARCHY;

// Table 66 -- TPMU_HA Union <I/O,S>
typedef union {
#ifdef TPM_ALG_SHA1
    u8  sha1[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    u8  sha256[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    u8  sm3_256[SM3_256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    u8  sha384[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    u8  sha512[SHA512_DIGEST_SIZE];
#endif
} TPMU_HA ;

// Table 67 -- TPMT_HA Structure <I/O>
typedef struct {
    u16         hash_alg;
    TPMU_HA     digest;
} TPMT_HA;

// Table 68 -- TPM2B_DIGEST Structure <I/O>
typedef struct {
    u16         size;
    u8          buffer[sizeof(TPMU_HA)];
} DIGEST_2B;

typedef union {
    DIGEST_2B    t;
    TPM2B        b;
} TPM2B_DIGEST;

// Table 69 -- TPM2B_DATA Structure <I/O>
typedef struct {
    u16         size;
    u8          buffer[sizeof(TPMT_HA)];
} DATA_2B;

typedef union {
    DATA_2B    t;
    TPM2B      b;
} TPM2B_DATA;

// Table 70 -- TPM2B_NONCE Types <I/O>
typedef TPM2B_DIGEST    TPM2B_NONCE;

// Table 71 -- TPM2B_AUTH Types <I/O>
typedef TPM2B_DIGEST    TPM2B_AUTH;

// Table 73 -- TPM2B_EVENT Structure <I/O>
typedef struct {
    u16     size;
    u8      buffer[1024];
} EVENT_2B;

typedef union {
    EVENT_2B    t;
    TPM2B       b;
} TPM2B_EVENT;

// Table 74 -- TPM2B_MAX_BUFFER Structure <I/O>
typedef struct {
    u16     size;
    u8      buffer[MAX_DIGEST_BUFFER];
} MAX_BUFFER_2B;

typedef union {
    MAX_BUFFER_2B    t;
    TPM2B            b;
} TPM2B_MAX_BUFFER;

// Table 75 -- TPM2B_MAX_NV_BUFFER Structure <I/O>
typedef struct {
    u16    size;
    u8     buffer[MAX_NV_INDEX_SIZE];
} MAX_NV_BUFFER_2B;

typedef union {
    MAX_NV_BUFFER_2B    t;
    TPM2B               b;
} TPM2B_MAX_NV_BUFFER;

// Table 79 -- TPMU_NAME Structure
typedef union {
    TPMT_HA digest;  
    u32     handle;  
} TPMU_NAME ;

// Table 79 -- TPM2B_NAME Structure <I/O>
typedef struct {
    u16     size;
    u8      name[sizeof(TPMU_NAME)];
} NAME_2B;

typedef union {
    NAME_2B    t;
    TPM2B      b;
} TPM2B_NAME;

// Table 80 -- TPMS_PCR_SELECTION Structure <I/O>
typedef struct {
    u16             hash;
    u8         	    size_of_select;
    u8              pcr_select[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

// Table 84 -- TPMT_TK_CREATION Structure <I/O>
typedef struct {
    u16                 tag;
    u32                 hierarchy;
    TPM2B_DIGEST        digest;
} TPMT_TK_CREATION;

// Table 86 -- TPMT_TK_HASHCHECK Structure <I/O>
typedef struct {
    u16                 tag;
    u32                 hierarchy;
    TPM2B_DIGEST        digest;
} TPMT_TK_HASHCHECK;

// Table 88 -- TPMS_ALG_PROPERTY Structure <O,S>
typedef struct {
    u16               alg;
    TPMA_ALGORITHM    alg_pro;
} TPMS_ALG_PROPERTY;

// Table 95 -- TPML_DIGEST Structure <I/O>
typedef struct {
    u32             count;
    TPM2B_DIGEST    digests[8];
} TPML_DIGEST;

// Table 96 -- TPML_DIGEST_VALUES Structure <I/O>
typedef struct {
    u32         count;
    TPMT_HA     digests[HASH_COUNT];
} TPML_DIGEST_VALUES;

// Table 98 -- TPML_PCR_SELECTION Structure <I/O>
typedef struct {
    u32                   count;
    TPMS_PCR_SELECTION    selections[HASH_COUNT];
} TPML_PCR_SELECTION;

#define MAX_CAP_DATA  (MAX_CAP_BUFFER-sizeof(u32)-sizeof(u32))
#define MAX_CAP_ALGS  (MAX_CAP_DATA/sizeof(TPMS_ALG_PROPERTY))
// Table 99 -- TPML_ALG_PROPERTY Structure <O,S>
typedef struct {
    u32                  count;
    TPMS_ALG_PROPERTY    alg_pros[MAX_CAP_ALGS];
} TPML_ALG_PROPERTY;

// Table 103 -- TPMU_CAPABILITIES Union <O,S>
typedef union {
    TPML_ALG_PROPERTY  algs;  
} TPMU_CAPABILITIES;

// Table 104 -- TPMS_CAPABILITY_DATA Structure <O,S>
typedef struct {
    u32                  capability;
    TPMU_CAPABILITIES    data;
} TPMS_CAPABILITY_DATA;

// Table 122 -- TPMU_SYM_KEY_BITS Union <I/O>
typedef union {
#ifdef TPM_ALG_AES
    u16     aes;
#endif
#ifdef TPM_ALG_SM4
    u16     sm4;
#endif
    u16     sym;
#ifdef TPM_ALG_XOR
    u16     xor;
#endif
} TPMU_SYM_KEY_BITS ;

// Table 122 -- TPMU_SYM_MODE Union <I/O>
typedef union {
#ifdef TPM_ALG_AES
    u16     aes;
#endif
#ifdef TPM_ALG_SM4
    u16     sm4;
#endif
    u16     sym;  
} TPMU_SYM_MODE ;

// Table 126 -- TPMT_SYM_DEF_OBJECT Structure <I/O>
typedef struct {
    u16                     alg;
    TPMU_SYM_KEY_BITS       key_bits;
    TPMU_SYM_MODE           mode;
} TPMT_SYM_DEF_OBJECT;

// Table 126 -- TPM2B_SYM_KEY Structure <I/O>
typedef struct {
    u16         size;
    u8          buffer[MAX_SYM_KEY_BYTES];
} SYM_KEY_2B;

typedef union {
    SYM_KEY_2B    t;
    TPM2B         b;
} TPM2B_SYM_KEY;

// Table 129 -- TPM2B_SENSITIVE_DATA Structure <I/O>
typedef struct {
    u16     size;
    u8      buffer[MAX_SYM_DATA];
} SENSITIVE_DATA_2B;

typedef union {
    SENSITIVE_DATA_2B    t;
    TPM2B                b;
} TPM2B_SENSITIVE_DATA;

// Table 130 -- TPMS_SENSITIVE_CREATE Structure <I>
typedef struct {
    TPM2B_AUTH              user_auth;
    TPM2B_SENSITIVE_DATA    data;
} TPMS_SENSITIVE_CREATE;

// Table 131 -- TPM2B_SENSITIVE_CREATE Structure <I,S>
typedef struct {
    u16                      size;
    TPMS_SENSITIVE_CREATE    sensitive;
} SENSITIVE_CREATE_2B;

typedef union {
    SENSITIVE_CREATE_2B    t;
    TPM2B                  b;
} TPM2B_SENSITIVE_CREATE;

// Table 132 -- TPMS_SCHEME_SIGHASH Structure <I/O>
typedef struct {
    u16         hash_alg;
} TPMS_SCHEME_SIGHASH;

// Table 134 -- HMAC_SIG_SCHEME Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_HMAC;

// Table 135 -- TPMS_SCHEME_XOR Structure <I/O>
typedef struct {
    u16             hash_alg;
    u16             kdf;
} TPMS_SCHEME_XOR;

// Table 136 -- TPMU_SCHEME_KEYEDHASH Union <I/O,S>
typedef union {
#ifdef TPM_ALG_HMAC
    TPMS_SCHEME_HMAC  hmac;  
#endif
#ifdef TPM_ALG_XOR
    TPMS_SCHEME_XOR  xor;  
#endif

} TPMU_SCHEME_KEYEDHASH;

// Table 137 -- TPMT_KEYEDHASH_SCHEME Structure <I/O>
typedef struct {
    u16                         scheme;
    TPMU_SCHEME_KEYEDHASH       details;
} TPMT_KEYEDHASH_SCHEME;

// Table 138 -- RSA_SIG_SCHEMES Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_RSASSA;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_RSAPSS;

// Table 139 -- ECC_SIG_SCHEMES Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_ECDSA;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_SM2;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_ECSCHNORR;

// Table 140 -- TPMS_SCHEME_ECDAA Structure <I/O>
typedef struct {
    u16         hash_alg;
    u16         count;
} TPMS_SCHEME_ECDAA;

// Table 141 -- TPMU_SIG_SCHEME Union <I/O,S>
typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SCHEME_RSASSA  rsassa;  
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SCHEME_RSAPSS  rsapss;  
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SCHEME_ECDSA  ecdsa;  
#endif
#ifdef TPM_ALG_SM2
    TPMS_SCHEME_SM2  sm2;  
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SCHEME_ECDAA  ecdaa;  
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SCHEME_ECSCHNORR  ec_schnorr;  
#endif
#ifdef TPM_ALG_HMAC
    TPMS_SCHEME_HMAC  hmac;
#endif
    TPMS_SCHEME_SIGHASH  any;

} TPMU_SIG_SCHEME ;

// Table 143 -- TPMS_SCHEME_OAEP Structure <I/O>
typedef struct {
    u16     hash_alg;
} TPMS_SCHEME_OAEP;

// Table 145 -- TPMS_SCHEME_MGF1 Structure <I/O>
typedef struct {
    u16     hash_alg;
} TPMS_SCHEME_MGF1;

// Table 146 -- TPMS_SCHEME_KDF1_SP800_56a Structure <I/O>
typedef struct {
    u16     hash_alg;
} TPMS_SCHEME_KDF1_SP800_56a;

// Table 147 -- TPMS_SCHEME_KDF2 Structure <I/O>
typedef struct {
    u16     hash_alg;
} TPMS_SCHEME_KDF2;

// Table 148 -- TPMS_SCHEME_KDF1_SP800_108 Structure <I/O>
typedef struct {
    u16     hash_alg;
} TPMS_SCHEME_KDF1_SP800_108;

// Table 149 -- TPMU_KDF_SCHEME Union <I/O,S>
typedef union {
#ifdef TPM_ALG_MGF1
    TPMS_SCHEME_MGF1  mgf1;  
#endif
#ifdef TPM_ALG_KDF1_SP800_56a
    TPMS_SCHEME_KDF1_SP800_56a  kdf1_SP800_56a;  
#endif
#ifdef TPM_ALG_KDF2
    TPMS_SCHEME_KDF2  kdf2;  
#endif
#ifdef TPM_ALG_KDF1_SP800_108
    TPMS_SCHEME_KDF1_SP800_108  kdf1_sp800_108;  
#endif
} TPMU_KDF_SCHEME ;

// Table 150 -- TPMT_KDF_SCHEME Structure <I/O>
typedef struct {
    u16                scheme;
    TPMU_KDF_SCHEME    details;
} TPMT_KDF_SCHEME;

// Table 152 -- TPMU_ASYM_SCHEME Union <I/O>
typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SCHEME_RSASSA  rsassa;  
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SCHEME_RSAPSS  rsapss;  
#endif
#ifdef TPM_ALG_OAEP
    TPMS_SCHEME_OAEP  oaep;  
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SCHEME_ECDSA  ecdsa;  
#endif
#ifdef TPM_ALG_SM2
    TPMS_SCHEME_SM2  sm2;  
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SCHEME_ECDAA  ecdaa;  
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SCHEME_ECSCHNORR  ec_schnorr;  
#endif
    TPMS_SCHEME_SIGHASH  any;  

} TPMU_ASYM_SCHEME;

// Table 153 -- TPMT_ASYM_SCHEME Structure <>
typedef struct {
    u16                 scheme;
    TPMU_ASYM_SCHEME    details;
} TPMT_ASYM_SCHEME;

// Table 155 -- TPMT_RSA_SCHEME Structure <I/O>
typedef struct {
    u16                 scheme;
    TPMU_ASYM_SCHEME    details;
} TPMT_RSA_SCHEME;

// Table 158 -- TPM2B_PUBLIC_KEY_RSA Structure <I/O>
typedef struct {
    u16         size;
    u8          buffer[MAX_RSA_KEY_BYTES];
} PUBLIC_KEY_RSA_2B;

typedef union {
    PUBLIC_KEY_RSA_2B    t;
    TPM2B                b;
} TPM2B_PUBLIC_KEY_RSA;

// Table 160 -- TPM2B_PRIVATE_KEY_RSA Structure <I/O>
typedef struct {
    u16         size;
    u8          buffer[MAX_RSA_KEY_BYTES/2];
} PRIVATE_KEY_RSA_2B;

typedef union {
    PRIVATE_KEY_RSA_2B    t;
    TPM2B                 b;
} TPM2B_PRIVATE_KEY_RSA;

// Table 161 -- TPM2B_ECC_PARAMETER Structure <I/O>
typedef struct {
    u16     size;
    u8      buffer[MAX_ECC_KEY_BYTES];
} ECC_PARAMETER_2B;

typedef union {
    ECC_PARAMETER_2B    t;
    TPM2B               b;
} TPM2B_ECC_PARAMETER;

// Table 162 -- TPMS_ECC_POINT Structure <I/O>
typedef struct {
    TPM2B_ECC_PARAMETER    x;
    TPM2B_ECC_PARAMETER    y;
} TPMS_ECC_POINT;

// Table 166 -- TPMT_ECC_SCHEME Structure <I/O>
typedef struct {
    u16                 scheme;
    TPMU_SIG_SCHEME     details;
} TPMT_ECC_SCHEME;

// Table 176 -- TPMU_PUBLIC_ID Union <I/O,S>
typedef union {
#ifdef TPM_ALG_KEYEDHASH
    TPM2B_DIGEST  keyed_hash;  
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPM2B_DIGEST  sym;  
#endif
#ifdef TPM_ALG_RSA
    TPM2B_PUBLIC_KEY_RSA  rsa;  
#endif
#ifdef TPM_ALG_ECC
    TPMS_ECC_POINT  ecc;  
#endif
} TPMU_PUBLIC_ID;

// Table 177 -- TPMS_KEYEDHASH_PARMS Structure <I/O>
typedef struct {
    TPMT_KEYEDHASH_SCHEME    scheme;
} TPMS_KEYEDHASH_PARMS;

// Table 178 -- TPMS_ASYM_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_ASYM_SCHEME       scheme;
} TPMS_ASYM_PARMS;

// Table 179 -- TPMS_RSA_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_RSA_SCHEME        scheme;
    u16                    key_bits;
    u32                    exponent;
} TPMS_RSA_PARMS;

// Table 180 -- TPMS_ECC_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_ECC_SCHEME        scheme;
    u16                    curve_id;
    TPMT_KDF_SCHEME        kdf;
} TPMS_ECC_PARMS;

// Table 181 -- TPMU_PUBLIC_PARMS Union <I/O,S>
typedef union {
#ifdef TPM_ALG_KEYEDHASH
    TPMS_KEYEDHASH_PARMS  keyed_hash;  
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPMT_SYM_DEF_OBJECT  sym;  
#endif
#ifdef TPM_ALG_RSA
    TPMS_RSA_PARMS  rsa;  
#endif
#ifdef TPM_ALG_ECC
    TPMS_ECC_PARMS  ecc;  
#endif
    TPMS_ASYM_PARMS  asym;  

} TPMU_PUBLIC_PARMS;

// Table 184 -- TPMT_PUBLIC Structure <I/O>
typedef struct {
    u16                  type;
    u16                  name_alg;
    TPMA_OBJECT          object_attr;
    TPM2B_DIGEST         auth_policy;
    TPMU_PUBLIC_PARMS    param;
    TPMU_PUBLIC_ID       unique;
} TPMT_PUBLIC;

// Table 185 -- TPM2B_PUBLIC Structure <I/O>
typedef struct {
    u16             size;
    TPMT_PUBLIC     public_area;
} PUBLIC_2B;

typedef union {
    PUBLIC_2B    t;
    TPM2B        b;
} TPM2B_PUBLIC;

// Table 186 -- TPMU_SENSITIVE_COMPOSITE Union <I/O,S>
typedef union {
#ifdef TPM_ALG_RSA
    TPM2B_PRIVATE_KEY_RSA  rsa;  
#endif
#ifdef TPM_ALG_ECC
    TPM2B_ECC_PARAMETER  ecc;  
#endif
#ifdef TPM_ALG_KEYEDHASH
    TPM2B_SENSITIVE_DATA  bits;  
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPM2B_SYM_KEY  sym;  
#endif
    TPM2B_SENSITIVE_DATA  any;  

} TPMU_SENSITIVE_COMPOSITE ;

// Table 187 -- TPMT_SENSITIVE Structure <I/O>
typedef struct {
    u16                         type;
    TPM2B_AUTH                  auth_value;
    TPM2B_DIGEST                seedValue;
    TPMU_SENSITIVE_COMPOSITE    sensitive;
} TPMT_SENSITIVE;

// Table 189 -- _PRIVATE Structure <>
typedef struct {
    TPM2B_DIGEST      integrity_outer;
    TPM2B_DIGEST      integrity_inner;
    TPMT_SENSITIVE    sensitive;
} _PRIVATE;

// Table 190 -- TPM2B_PRIVATE Structure <I/O,S>
typedef struct {
    u16         size;
    u8          buffer[sizeof(_PRIVATE)];
} PRIVATE_2B;

typedef union {
    PRIVATE_2B    t;
    TPM2B         b;
} TPM2B_PRIVATE;

// Table 195 -- TPMA_NV Bits <I/O>
typedef struct {
    unsigned int TPMA_NV_PPWRITE        : 1;
    unsigned int TPMA_NV_OWNERWRITE     : 1;
    unsigned int TPMA_NV_AUTHWRITE      : 1;
    unsigned int TPMA_NV_POLICYWRITE    : 1;
    unsigned int TPMA_NV_COUNTER        : 1;
    unsigned int TPMA_NV_BITS           : 1;
    unsigned int TPMA_NV_EXTEND         : 1;
    unsigned int reserved8              : 3;
    unsigned int TPMA_NV_POLICY_DELETE  : 1;
    unsigned int TPMA_NV_WRITELOCKED    : 1;
    unsigned int TPMA_NV_WRITEALL       : 1;
    unsigned int TPMA_NV_WRITEDEFINE    : 1;
    unsigned int TPMA_NV_WRITE_STCLEAR  : 1;
    unsigned int TPMA_NV_GLOBALLOCK     : 1;
    unsigned int TPMA_NV_PPREAD         : 1;
    unsigned int TPMA_NV_OWNERREAD      : 1;
    unsigned int TPMA_NV_AUTHREAD       : 1;
    unsigned int TPMA_NV_POLICYREAD     : 1;
    unsigned int reserved19             : 5;
    unsigned int TPMA_NV_NO_DA          : 1;
    unsigned int TPMA_NV_ORDERLY        : 1;
    unsigned int TPMA_NV_CLEAR_STCLEAR  : 1;
    unsigned int TPMA_NV_READLOCKED     : 1;
    unsigned int TPMA_NV_WRITTEN        : 1;
    unsigned int TPMA_NV_PLATFORMCREATE : 1;
    unsigned int TPMA_NV_READ_STCLEAR   : 1;
} TPMA_NV ;

// Table 196 -- TPMS_NV_PUBLIC Structure <I/O>
typedef struct {
    u32                 index;
    u16                 name_alg;
    TPMA_NV             attr;
    TPM2B_DIGEST        auth_policy;
    u16                 data_size;
} TPMS_NV_PUBLIC;

// Table 197 -- TPM2B_NV_PUBLIC Structure <I/O>
typedef struct {
    u16             size;
    TPMS_NV_PUBLIC  nv_public;
} NV_PUBLIC_2B;

typedef union {
    NV_PUBLIC_2B    t;
    TPM2B           b;
} TPM2B_NV_PUBLIC;

// Table 198  Definition of TPM2B_CONTEXT_SENSITIVE Structure <  IN/OUT>
typedef union {
  struct {
    u16  size;
    u8    buffer[MAX_CONTEXT_SIZE];
  } t;
  TPM2B b;
} TPM2B_CONTEXT_SENSITIVE;

// Table 199  Definition of TPMS_CONTEXT_DATA Structure <  IN/OUT, S>
typedef struct {
  TPM2B_DIGEST             integrity;
  TPM2B_CONTEXT_SENSITIVE  encrypted;
} TPMS_CONTEXT_DATA;

// Table 200  Definition of TPM2B_CONTEXT_DATA Structure <  IN/OUT>
typedef union {
  struct {
    u16  size;
    u8    buffer[sizeof(TPMS_CONTEXT_DATA)];
  } t;
  TPM2B b;
} TPM2B_CONTEXT_DATA;

// Table 201  Definition of TPMS_CONTEXT Structure
typedef struct {
  u64                 sequence;
  TPMI_DH_CONTEXT     savedHandle;
  TPMI_RH_HIERARCHY   hierarchy;
  TPM2B_CONTEXT_DATA  contextBlob;
} TPMS_CONTEXT;

// Table 203 -- TPMS_CREATION_DATA Structure <O,S>
typedef struct {
    TPML_PCR_SELECTION    pcr_select;
    TPM2B_DIGEST          pcr_digest;
    TPMA_LOCALITY         locality;
    u16                   parent_name_alg;
    TPM2B_NAME            parent_name;
    TPM2B_NAME            parent_qualified_name;
    TPM2B_DATA            outside_info;
} TPMS_CREATION_DATA;

// Table 204 -- TPM2B_CREATION_DATA Structure <O,S>
typedef struct {
    u16                   size;
    TPMS_CREATION_DATA    data;
} CREATION_DATA_2B;

typedef union {
    CREATION_DATA_2B    t;
    TPM2B               b;
} TPM2B_CREATION_DATA;


#define MAX_SESSIONS 3    

// Input structure for session data for a single session,
typedef struct {
    u32 session_handle;
    TPM2B_NONCE nonce;
    TPMA_SESSION session_attr;
    TPM2B_AUTH hmac;
} TPM_CMD_SESSION_DATA_IN ;

// Input structure for sessions data.
typedef struct {
    u8 num_sessions;
    TPM_CMD_SESSION_DATA_IN sessions[MAX_SESSION_NUM];
} TPM_CMD_SESSIONS_IN;

// Output structure for session data for a single session.
typedef struct {
    TPM2B_NONCE nonce;
    TPMA_SESSION session_attr;
    TPM2B_AUTH hmac;
} TPM_CMD_SESSION_DATA_OUT;

// Output structure for sessions data.
typedef struct {
    u8 num_sessions;
    TPM_CMD_SESSION_DATA_OUT sessions[MAX_SESSION_NUM];
} TPM_CMD_SESSIONS_OUT;


/*
 * command parameter related structure
 */

typedef struct {
    TPML_PCR_SELECTION  pcr_selection;
} tpm_pcr_read_in;

typedef struct {
    u32                 pcr_update_counter;
    TPML_PCR_SELECTION  pcr_selection;
    TPML_DIGEST         pcr_values;
} tpm_pcr_read_out;

typedef struct {
    u32 pcr_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPML_DIGEST_VALUES digests;
} tpm_pcr_extend_in;

typedef struct {
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_pcr_extend_out;

typedef struct {
    u32 pcr_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_EVENT data;
} tpm_pcr_event_in;

typedef struct {
    TPML_DIGEST_VALUES digests;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_pcr_event_out;

typedef struct {
    u32 pcr_handle;
    TPM_CMD_SESSIONS_IN sessions;
} tpm_pcr_reset_in;

typedef struct {
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_pcr_reset_out;

typedef struct {
    TPM2B_AUTH auth;
    u16 hash_alg;
} tpm_sequence_start_in;

typedef struct {
    u32 handle;
} tpm_sequence_start_out;

typedef struct {
    u32 handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_MAX_BUFFER buf;
} tpm_sequence_update_in;

typedef struct {
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_sequence_update_out;

typedef struct {
    u32 pcr_handle;
    u32 seq_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_MAX_BUFFER buf;
} tpm_sequence_complete_in;

typedef struct {
    TPML_DIGEST_VALUES results;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_sequence_complete_out;

typedef struct {
    u32 seq_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_MAX_BUFFER buf;
    u32 hierarchy;
} tpm_sequence_complete2_in;

typedef struct {
    TPML_DIGEST_VALUES results;
    TPMT_TK_HASHCHECK validation;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_sequence_complete2_out;

typedef struct {
    u32 handle;
    u32 index;
    TPM_CMD_SESSIONS_IN sessions;
    u16 size;
    u16 offset;
} tpm_nv_read_in;

typedef struct {
    TPM2B_MAX_NV_BUFFER data;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_nv_read_out;

typedef struct {
    u32 handle;
    u32 index;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_MAX_NV_BUFFER data;
    u16 offset;
} tpm_nv_write_in;

typedef struct {
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_nv_write_out;

typedef struct {
    u32 handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC public_info;
} tpm_nv_define_space_in;

typedef struct {
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_nv_define_space_out;

typedef struct {
    u32 handle;
    u32 index;
    TPM_CMD_SESSIONS_IN sessions;
} tpm_nv_undefine_space_in;

typedef struct {
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_nv_undefine_space_out;

typedef struct {
    u32 index;
} tpm_nv_read_public_in;

typedef struct {
    TPM2B_NV_PUBLIC nv_public;
    TPM2B_NAME nv_name;
} tpm_nv_read_public_out;

typedef struct {
    u16 bytes_req;
} tpm_get_random_in;

typedef struct {
    TPM2B_DIGEST    random_bytes;
} tpm_get_random_out;

typedef struct {
    u32 capability;
    u32 property;
    u32 property_count;
} tpm_get_capability_in;

typedef struct {
    u8 more_data;
    TPMS_CAPABILITY_DATA data;
} tpm_get_capability_out;

typedef struct {
    u32 primary_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_SENSITIVE_CREATE sensitive;
    TPM2B_PUBLIC public;
    TPM2B_DATA outside_info;
    TPML_PCR_SELECTION creation_pcr;
} tpm_create_primary_in;

typedef struct {
    u32 obj_handle;
    TPM2B_PUBLIC public;
    TPM2B_CREATION_DATA creation_data;
    TPM2B_DIGEST creation_hash;
    TPMT_TK_CREATION creation_ticket;
    TPM2B_NAME name;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_create_primary_out;

typedef struct {
    u32 parent_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_SENSITIVE_CREATE sensitive;
    TPM2B_PUBLIC public;
    TPM2B_DATA outside_info;
    TPML_PCR_SELECTION creation_pcr;
} tpm_create_in;

typedef struct {
    TPM2B_PRIVATE private;
    TPM2B_PUBLIC public;
    TPM2B_CREATION_DATA creation_data;
    TPM2B_DIGEST creation_hash;
    TPMT_TK_CREATION creation_ticket;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_create_out;

typedef struct {
    u32 parent_handle;
    TPM_CMD_SESSIONS_IN sessions;
    TPM2B_PRIVATE private;
    TPM2B_PUBLIC public;
} tpm_load_in;

typedef struct {
    u32 obj_handle;
    TPM2B_NAME name;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_load_out;

typedef struct {
    u32 item_handle;
    TPM_CMD_SESSIONS_IN sessions;
} tpm_unseal_in;

typedef struct {
    TPM2B_SENSITIVE_DATA data;
    TPM_CMD_SESSIONS_OUT sessions;
} tpm_unseal_out;

typedef struct { 
    TPMI_DH_CONTEXT saveHandle; 
} tpm_contextsave_in;

typedef struct { 
    TPMS_CONTEXT context; 
} tpm_contextsave_out;

typedef struct { 
    TPMS_CONTEXT context; 
} tpm_contextload_in;

typedef struct { 
    TPMI_DH_CONTEXT loadedHandle; 
} tpm_contextload_out;

typedef struct {
    TPMI_DH_CONTEXT flushHandle;
} tpm_flushcontext_in;

#endif   /* __TPM20_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
