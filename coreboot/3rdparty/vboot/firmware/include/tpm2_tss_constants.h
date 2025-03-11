/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Some TPM constants and type definitions for standalone compilation for use
 * in the firmware
 */

#ifndef VBOOT_REFERENCE_TPM2_TSS_CONSTANTS_H_
#define VBOOT_REFERENCE_TPM2_TSS_CONSTANTS_H_

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#define TPM_BUFFER_SIZE 512

/* Tpm2 command tags. */
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002

/* TPM2 command codes. */
#define TPM2_EvictControl      ((TPM_CC)0x00000120)
#define TPM2_Hierarchy_Control ((TPM_CC)0x00000121)
#define TPM2_NV_UndefineSpace  ((TPM_CC)0x00000122)
#define TPM2_Clear             ((TPM_CC)0x00000126)
#define TPM2_NV_DefineSpace    ((TPM_CC)0x0000012A)
#define TPM2_CreatePrimary     ((TPM_CC)0x00000131)
#define TPM2_NV_Write          ((TPM_CC)0x00000137)
#define TPM2_NV_WriteLock      ((TPM_CC)0x00000138)
#define TPM2_SelfTest          ((TPM_CC)0x00000143)
#define TPM2_Startup           ((TPM_CC)0x00000144)
#define TPM2_Shutdown          ((TPM_CC)0x00000145)
#define TPM2_NV_Read           ((TPM_CC)0x0000014E)
#define TPM2_NV_ReadLock       ((TPM_CC)0x0000014F)
#define TPM2_NV_ReadPublic     ((TPM_CC)0x00000169)
#define TPM2_ReadPublic        ((TPM_CC)0x00000173)
#define TPM2_GetCapability     ((TPM_CC)0x0000017A)
#define TPM2_GetRandom         ((TPM_CC)0x0000017B)
#define TPM2_PCR_Extend        ((TPM_CC)0x00000182)

#define TPM_HT_PCR             0x00
#define TPM_HT_NV_INDEX        0x01

#define HR_SHIFT               24
#define HR_PCR                (TPM_HT_PCR <<  HR_SHIFT)
#define HR_NV_INDEX           (TPM_HT_NV_INDEX <<  HR_SHIFT)
#define TPM_RH_OWNER        0x40000001
#define TPM_RH_NULL         0x40000007
#define TPM_RH_ENDORSEMENT  0x4000000B
#define TPM_RH_PLATFORM     0x4000000C
#define TPM_RS_PW           0x40000009

/* TPM2 capabilities. */
#define TPM_CAP_FIRST                   ((TPM_CAP)0x00000000)
#define TPM_CAP_TPM_PROPERTIES          ((TPM_CAP)0x00000006)

/* TPM properties */
#define TPM_PT_NONE                     ((TPM_PT)0x00000000)
#define PT_GROUP                        ((TPM_PT)0x00000100)
#define PT_FIXED                        PT_GROUP
#define TPM_PT_MANUFACTURER             (PT_FIXED + 5)
#define TPM_PT_VENDOR_STRING_1          (PT_FIXED + 6)
#define TPM_PT_VENDOR_STRING_4          (PT_FIXED + 9)
#define TPM_PT_FIRMWARE_VERSION_1       (PT_FIXED + 11)
#define TPM_PT_FIRMWARE_VERSION_2       (PT_FIXED + 12)
#define PT_VAR                          (PT_GROUP * 2)
#define TPM_PT_PERMANENT                (PT_VAR + 0)
#define TPM_PT_STARTUP_CLEAR            (PT_VAR + 1)

/* TPM startup types. */
#define TPM_SU_CLEAR                    ((TPM_SU)0x0000)
#define TPM_SU_STATE                    ((TPM_SU)0x0001)

/* TPM algorithm IDs. */
#define TPM_ALG_SHA1			((TPM_ALG_ID)0x0004)
#define TPM_ALG_SHA256			((TPM_ALG_ID)0x000B)
#define TPM_ALG_NULL			((TPM_ALG_ID)0x0010)

/* NV index attributes. */
#define TPMA_NV_PPWRITE			((TPMA_NV)(1UL << 0))
#define TPMA_NV_OWNERWRITE		((TPMA_NV)(1UL << 1))
#define TPMA_NV_AUTHWRITE		((TPMA_NV)(1UL << 2))
#define TPMA_NV_POLICYWRITE		((TPMA_NV)(1UL << 3))
#define TPMA_NV_COUNTER			((TPMA_NV)(1UL << 4))
#define TPMA_NV_BITS			((TPMA_NV)(1UL << 5))
#define TPMA_NV_EXTEND			((TPMA_NV)(1UL << 6))
#define TPMA_NV_POLICY_DELETE		((TPMA_NV)(1UL << 10))
#define TPMA_NV_WRITELOCKED		((TPMA_NV)(1UL << 11))
#define TPMA_NV_WRITEALL		((TPMA_NV)(1UL << 12))
#define TPMA_NV_WRITEDEFINE		((TPMA_NV)(1UL << 13))
#define TPMA_NV_WRITE_STCLEAR		((TPMA_NV)(1UL << 14))
#define TPMA_NV_GLOBALLOCK		((TPMA_NV)(1UL << 15))
#define TPMA_NV_PPREAD			((TPMA_NV)(1UL << 16))
#define TPMA_NV_OWNERREAD		((TPMA_NV)(1UL << 17))
#define TPMA_NV_AUTHREAD		((TPMA_NV)(1UL << 18))
#define TPMA_NV_POLICYREAD		((TPMA_NV)(1UL << 19))
#define TPMA_NV_NO_DA			((TPMA_NV)(1UL << 25))
#define TPMA_NV_ORDERLY			((TPMA_NV)(1UL << 26))
#define TPMA_NV_CLEAR_STCLEAR		((TPMA_NV)(1UL << 27))
#define TPMA_NV_READLOCKED		((TPMA_NV)(1UL << 28))
#define TPMA_NV_WRITTEN			((TPMA_NV)(1UL << 29))
#define TPMA_NV_PLATFORMCREATE		((TPMA_NV)(1UL << 30))
#define TPMA_NV_READ_STCLEAR		((TPMA_NV)(1UL << 31))

#define TPMA_NV_MASK_READ		(TPMA_NV_PPREAD | TPMA_NV_OWNERREAD |\
					 TPMA_NV_AUTHREAD | TPMA_NV_POLICYREAD)
#define TPMA_NV_MASK_WRITE		(TPMA_NV_PPWRITE | TPMA_NV_OWNERWRITE |\
					 TPMA_NV_AUTHWRITE |\
					 TPMA_NV_POLICYWRITE)

/* Starting indexes of NV index ranges, as defined in "Registry of reserved
 * TPM 2.0 handles and localities".
 */
#define TPMI_RH_NV_INDEX_TPM_START	((TPMI_RH_NV_INDEX)0x01000000)
#define TPMI_RH_NV_INDEX_PLATFORM_START	((TPMI_RH_NV_INDEX)0x01400000)
#define TPMI_RH_NV_INDEX_OWNER_START	((TPMI_RH_NV_INDEX)0x01800000)
#define TPMI_RH_NV_INDEX_TCG_OEM_START	((TPMI_RH_NV_INDEX)0x01C00000)
#define TPMI_RH_NV_INDEX_TCG_WG_START	((TPMI_RH_NV_INDEX)0x01C40000)
#define TPMI_RH_NV_INDEX_RESERVED_START	((TPMI_RH_NV_INDEX)0x01C90000)

#define HASH_COUNT 1 /* Only SHA-256 is supported */

/* Table 206 - Defines for SHA256 Hash Values */
#define SHA256_DIGEST_SIZE  32

typedef uint8_t TPMI_YES_NO;
typedef uint32_t TPM_CC;
typedef uint32_t TPM_HANDLE;
typedef TPM_HANDLE TPMI_DH_OBJECT;
typedef TPM_HANDLE TPMI_DH_PCR;
typedef TPM_HANDLE TPMI_DH_PERSISTENT;
typedef TPM_HANDLE TPMI_RH_ENABLES;
typedef TPM_HANDLE TPMI_RH_HIERARCHY;
typedef TPM_HANDLE TPMI_RH_NV_INDEX;
typedef TPM_HANDLE TPMI_RH_PROVISION;
typedef uint32_t TPM_CAP;
typedef uint32_t TPM_PT;
typedef uint16_t TPM_SU;
typedef uint16_t TPM_ALG_ID;
typedef TPM_ALG_ID TPMI_ALG_HASH;
typedef uint32_t TPMA_NV;

typedef struct {
	uint16_t      size;
	const uint8_t *buffer;
} TPM2B, TPM2B_DIGEST, TPM2B_AUTH, TPM2B_NAME;

typedef struct {
	TPM_PT property;
	uint32_t value;
} TPMS_TAGGED_PROPERTY;

typedef struct {
	uint32_t count;
	TPMS_TAGGED_PROPERTY tpm_property[1];
} TPML_TAGGED_TPM_PROPERTY;

typedef union {
	uint8_t sha256[SHA256_DIGEST_SIZE];
} TPMU_HA;

typedef struct {
	TPMI_ALG_HASH  hashAlg;
	TPMU_HA        digest;
} TPMT_HA;

typedef struct {
	uint32_t   count;
	TPMT_HA digests[HASH_COUNT];
} TPML_DIGEST_VALUES;

typedef union {
	TPML_TAGGED_TPM_PROPERTY tpm_properties;
} TPMU_CAPABILITIES;

typedef struct {
	TPM_CAP capability;
	TPMU_CAPABILITIES data;
} TPMS_CAPABILITY_DATA;

typedef struct {
	TPMI_RH_NV_INDEX nvIndex;
	TPMI_ALG_HASH nameAlg;
	TPMA_NV attributes;
	TPM2B authPolicy;
	uint16_t dataSize;
} TPMS_NV_PUBLIC;

struct tpm2_nv_define_space_cmd {
	TPM2B auth;
	TPMS_NV_PUBLIC publicInfo;
};

struct tpm2_nv_undefine_space_cmd {
	TPMI_RH_NV_INDEX nvIndex;
	uint8_t use_platform_auth;
};

struct tpm2_nv_read_cmd {
	TPMI_RH_NV_INDEX nvIndex;
	uint16_t size;
	uint16_t offset;
};

struct tpm2_nv_write_cmd {
	TPMI_RH_NV_INDEX nvIndex;
	TPM2B data;
	uint16_t offset;
};

struct tpm2_nv_read_lock_cmd {
	TPMI_RH_NV_INDEX nvIndex;
};

struct tpm2_nv_write_lock_cmd {
	TPMI_RH_NV_INDEX nvIndex;
};

struct tpm2_nv_read_public_cmd {
	TPMI_RH_NV_INDEX nvIndex;
};

struct tpm2_hierarchy_control_cmd {
	TPMI_RH_ENABLES enable;
	TPMI_YES_NO state;
};

struct tpm2_get_capability_cmd {
	TPM_CAP capability;
	uint32_t property;
	uint32_t property_count;
};

struct tpm2_get_random_cmd {
	uint16_t bytes_requested;
};

struct tpm2_self_test_cmd {
	TPMI_YES_NO full_test;
};

struct tpm2_startup_cmd {
	TPM_SU startup_type;
};

struct tpm2_shutdown_cmd {
	TPM_SU shutdown_type;
};

struct tpm2_pcr_extend_cmd {
	TPMI_DH_PCR pcrHandle;
	TPML_DIGEST_VALUES digests;
};

struct tpm2_read_public_cmd {
	TPMI_DH_OBJECT object_handle;
};

struct tpm2_evict_control_cmd {
	TPMI_RH_PROVISION auth;
	TPMI_DH_OBJECT object_handle;
	TPMI_DH_PERSISTENT persistent_handle;
};

struct tpm2_create_primary_cmd {
	TPMI_RH_HIERARCHY primary_handle;
	TPM2B in_sensitive;
	TPM2B in_public;
};

/* Common command/response header. */
struct tpm_header {
	uint16_t tpm_tag;
	uint32_t tpm_size;
	uint32_t tpm_code;
} __attribute__((packed));

struct nv_read_response {
	uint32_t params_size;
	TPM2B buffer;
};

struct read_public_response {
	TPM2B buffer;
};

struct tpm2_session_attrs {
	uint8_t continueSession : 1;
	uint8_t auditExclusive  : 1;
	uint8_t auditReset      : 1;
	uint8_t reserved3_4     : 2;
	uint8_t decrypt         : 1;
	uint8_t encrypt         : 1;
	uint8_t audit           : 1;
};

struct tpm2_session_header {
	uint32_t session_handle;
	uint16_t nonce_size;
	uint8_t *nonce;
	union {
		struct tpm2_session_attrs session_attr_bits;
		uint8_t session_attrs;
	}  __attribute__((packed));
	uint16_t auth_size;
	uint8_t *auth;
};

struct get_capability_response {
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA capability_data;
} __attribute__((packed));

struct get_random_response {
	TPM2B_DIGEST random_bytes;
} __attribute__((packed));

struct nv_read_public_response {
	TPMS_NV_PUBLIC nvPublic;
	TPM2B_NAME nvName;
} __attribute__((packed));

struct create_primary_response {
	TPM_HANDLE object_handle;
} __attribute__((packed));

struct tpm2_response {
	struct tpm_header hdr;
	union {
		struct nv_read_response nvr;
		struct tpm2_session_header def_space;
		struct get_capability_response cap;
		struct get_random_response random;
		struct nv_read_public_response nv_read_public;
		struct read_public_response read_pub;
		struct create_primary_response create_primary;
	};
};

typedef struct {
	uint32_t ownerAuthSet : 1;
	uint32_t endorsementAuthSet : 1;
	uint32_t lockoutAuthSet : 1;
	uint32_t reserved3_7 : 5;
	uint32_t disableClear : 1;
	uint32_t inLockout : 1;
	uint32_t tpmGeneratedEPS : 1;
	uint32_t reserved11_31 : 21;
} TPM_PERMANENT_FLAGS;

typedef struct {
	uint32_t phEnable : 1;
	uint32_t shEnable : 1;
	uint32_t ehEnable : 1;
	uint32_t phEnableNV : 1;
	uint32_t reserved4_30 : 27;
	uint32_t orderly : 1;
} TPM_STCLEAR_FLAGS;

typedef struct tdTPM_IFX_FIELDUPGRADEINFO
{
} TPM_IFX_FIELDUPGRADEINFO;

/* TODO(apronin): For TPM2 certain properties must be received using
 * TPM2_GetCapability instead of being hardcoded as they are now:
 * TPM_MAX_COMMAND_SIZE -> use TPM_PT_MAX_COMMAND_SIZE for TPM2.
 * TPM_PCR_DIGEST -> use TPM_PT_MAX_DIGEST for TPM2.
 */
#define TPM_MAX_COMMAND_SIZE	4096
#define TPM_PCR_DIGEST		32

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* VBOOT_REFERENCE_TPM2_TSS_CONSTANTS_H_ */
