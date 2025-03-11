/**
 * @file Ccx.h
 * @brief OpenSIL CCX IP initialization function declaration.
 *
 */

/* Copyright 2021-2023 Advanced Micro Devices, Inc. All rights reserved.    */
// SPDX-License-Identifier: MIT

#pragma once
#include "SilCommon.h"
#include <SMU/SmuIp2Ip.h>
#pragma pack (push, 1)

#include <CCX/CcxClass-api.h>
#include "CCX/Common/AmdTable.h"
#include <CCX/Common/CcxApic.h>

/**********************************************************************************************************************
 * Declare macros here
 *
 */

#define CCXCLASS_MAJOR_REV 0
#define CCXCLASS_MINOR_REV 1
#define CCXCLASS_INSTANCE  0

/**
 * Layout of ApStartupVector:
 * +--------------------------------+ +->
 *
 *  AllowToLaunchNextThreadLocation   // APs increment this to indicate they are done,
 *  2 bytes (UINT16)                  //  then we launch the next.
 *
 * +--------------------------------+ +-> ApStartupVector + E
 *  Near Jump to ApStartupCode
 *  4 bytes                           //  The AP starts executing right here.
 *
 * +--------------------------------+ +-> ApStartupVector (got from Host Firmware directory)
 *
 *  Code for ApStartupCode            // The code AT ApStartupVector simply
 *  AP_STARTUP_CODE_SIZE              // jumps here, where the ApStartupCode
 *  0x80 should be enough             // byte code gets copied.
 *
 * +--------------------------------+ +-> ApStartupVector - AP_STARTUP_CODE_OFFSET
 */


#define  AP_STARTUP_CODE_SIZE   0x80
#define  AP_TEMP_BUFFER_SIZE    (AP_STARTUP_CODE_SIZE + 0x10) // 0x250

#define  AP_STARTUP_CODE_OFFSET (AP_STARTUP_CODE_SIZE) // 0x240

#define CPU_LIST_TERMINAL       0xFFFFFFFFul

#define CCX_TRACEPOINT(MsgLevel, Message, ...)        \
  do {                \
    if (DEBUG_FILTER_CCX & SIL_DEBUG_MODULE_FILTER) {    \
      XUSL_TRACEPOINT(MsgLevel, Message, ##__VA_ARGS__);  \
        }\
  } while (0)




#define SIL_XAPIC_ID_MAX             0xFF  // moved from CcxClass-api.h (not needed by Host)

/**********************************************************************************************************************
 * variable declaration
 *
 */

typedef struct {
  uint32_t MsrAddr;     ///< Fixed-Sized MTRR address
  uint64_t MsrData;     ///< MTRR Settings
} AP_MTRR_SETTINGS;

/// AP MSR sync up
typedef struct {
  uint32_t MsrAddr;     ///< MSR address
  uint64_t MsrData;     ///< MSR Settings
  uint64_t MsrMask;     ///< MSR mask
} AP_MSR_SYNC;

/// GDT descriptor
typedef struct {
  uint16_t  Limit;        ///< Size
  uint64_t  Base;         ///< Pointer
} CCX_GDT_DESCRIPTOR;

typedef struct {
  volatile AP_MTRR_SETTINGS  *ApMtrrSyncList;
  uint8_t                    SleepType;
  uint32_t                   SizeOfApMtrr;
  volatile AP_MSR_SYNC       *ApMsrSyncList;
  uint64_t                   BspPatchLevel;
  uint64_t                   UcodePatchAddr;
  ENTRY_CRITERIA             ResetTableCriteria;
  uint64_t                   CacWeights[MAX_CAC_WEIGHT_NUM];
  const REGISTER_TABLE_AT_GIVEN_TP *CcxRegTableListAtGivenTP;
} AMD_CCX_AP_LAUNCH_GLOBAL_DATA;

/******************************************************************************
 * Declare Function prototypes
 *
 */

SIL_STATUS CcxClassSetInputBlk (void);
SIL_STATUS InitializeCcx (
  const REGISTER_TABLE_AT_GIVEN_TP  *CcxRegTableListAtGivenTP,
  uint32_t                          CcdDisMask,
  uint32_t                          DesiredCcdCount
  );
void CcxSetMca (void);
void CcxInitializeC6 (CCXCLASS_INPUT_BLK *CcxInputBlock);
void ApAsmCode (void);
void RegSettingBeforeLaunchingNextThread (void);
NASM_ABI void ApEntryPointInC (void);
void CcxSetMiscMsrs (
  CCXCLASS_INPUT_BLK *CcxInputBlock
  );
void CcxSyncMiscMsrs (
  volatile AMD_CCX_AP_LAUNCH_GLOBAL_DATA *ApLaunchGlobalData);
void UpdateApMtrrSettings (
  volatile AP_MTRR_SETTINGS *ApMtrrSettingsList,
  CCXCLASS_INPUT_BLK *CcxInputBlock
  );
void CcxEnableSmee (bool AmdSmee);
SIL_STATUS CcxGetCacWeights (uint64_t *CacWeights);
void CcxSetCacWeights (uint64_t *CacWeights);
void CcxInitializeCpb (uint8_t AmdCpbMode);

void
SetupApStartupRegion (
  volatile AMD_CCX_AP_LAUNCH_GLOBAL_DATA *ApLaunchGlobalData,
  uint64_t                               *ApStartupVector,
  uint8_t                                *MemoryContentCopy,
  CCXCLASS_DATA_BLK                      *CcxDataBlock
  );

#pragma pack (pop)
