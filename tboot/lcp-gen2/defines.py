#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

class DEFINES( object ):
  """ Defines Class"""

  def __init__( self ):
    pass

  LCP_VERSION = 2
  TOOL_VERSION = '0.5'
  BUILD_DATE = '2013-09-06'

  SUPPORTED_LCP_VERSION = {
    # Policy Version : List Verson
    '3.1'            : '2.1',
    '3.0'            : '2.0'
  }

  # Policy Type global values:
  LIST = 0
  ANY = 1

  # Policy Rules global values
  PsRules = 0
  PoRules = 1

  # max value for Min SINIT Version and BIOS & SINIT Revocation Limit fields
  maxVersion = 255

  # The PolicyControlField provides a number of control bits which are defined as:
  #   Bit31 AUXDeletionControl
  #   Bits30:4 Reserved and should set to zero
  #   Bit20 Ignore PS STM
  #   Bit17 Ignore PS PCONF
  #   Bit16 Ignore PS MLE
  #   Bit 3 Indicates Force Owner Policy
  #   Bit 2 Allow NPW.
  #   Bit 1 PCR 17
  #   Bit 0 Reserved and should set to zero
  #
  PolicyControlAUXDeletionControl   = 0x80000000   # bit 31
  PolicyControlIgnorePsStmBitMask   = 0x00100000   # bit 20
  PolicyControlIgnorePsPconfBitMask = 0x00020000   # bit 17
  PolicyControlIgnorePsMleBitMask   = 0x00010000   # bit 16
  PolicyControlForceOwnerBitMask    = 0x00000008   # bit 3
  PolicyControlPcr17BitMask         = 0x00000004   # bit 2
  PolicyControlAllowNpwBitMask      = 0x00000002   # bit 1

  # List Policy Signing Algorithm
  LCP_POLSALG_NONE        = 0   # list not signed
  LCP_POLSALG_RSA_PKCS_15 = 1   # list signed
  LCP_POLSALG_ECDSA       = 2
  LCP_POLSALG_SM2         = 3

  # Element types:  MLE, PCONF, SBIOS and STM
  LCP_POLELT_TYPE_MLE    = 0x00
  LCP_POLELT_TYPE_PCONF  = 0x01
  LCP_POLELT_TYPE_SBIOS  = 0x02
  LCP_POLELT_TYPE_MLE2   = 0x10
  LCP_POLELT_TYPE_PCONF2 = 0x11
  LCP_POLELT_TYPE_SBIOS2 = 0x12
  LCP_POLELT_TYPE_STM2   = 0x14

  # Each list can have each element with each possible hash algorithm
  # So Pdef_list.[Mle,Pconf,Sbios,Stm]DefData[x]  is now an array
  # where x is one of the indexes below which must be < MAX_ELEMENTS
  DEFDATA_INDEX = {
    'SHA1'      : 0,
    'SHA256'    : 1,
    'SHA384'    : 2,
    'SHA512'    : 3,
    #'SM3'       : 4
  }


  # Other than ELEMENT_NAME_NONE with no '-' character,
  # all other names must be <element>-<hash>
  # This is used in list.py to create new element of the hash type.
  # So the following element names are possible:
  ELEMENT_NAME_NONE          = "None"
  ELEMENT_NAME_MLE_SHA1      = "MLE-SHA1"
  ELEMENT_NAME_MLE_SHA256    = "MLE-SHA256"
  ELEMENT_NAME_MLE_SHA384   = "MLE-SHA384"
  ELEMENT_NAME_MLE_SHA512   = "MLE-SHA512"
  ELEMENT_NAME_MLE_SM3       = "MLE-SM3"

  ELEMENT_NAME_PCONF_SHA1    = "PCONF-SHA1"
  ELEMENT_NAME_PCONF_SHA256  = "PCONF-SHA256"
  ELEMENT_NAME_PCONF_SHA384 = "PCONF-SHA384"
  ELEMENT_NAME_PCONF_SHA512 = "PCONF-SHA512"
  ELEMENT_NAME_PCONF_SM3     = "PCONF-SM3"

  ELEMENT_NAME_SBIOS_SHA1    = "SBIOS-SHA1"
  ELEMENT_NAME_SBIOS_SHA256  = "SBIOS-SHA256"
  ELEMENT_NAME_SBIOS_SHA384 = "SBIOS-SHA384"
  ELEMENT_NAME_SBIOS_SHA512 = "SBIOS-SHA512"
  ELEMENT_NAME_SBIOS_SM3     = "SBIOS-SM3"

  ELEMENT_NAME_STM_SHA1      = "STM-SHA1"
  ELEMENT_NAME_STM_SHA256    = "STM-SHA256"
  ELEMENT_NAME_STM_SHA384   = "STM-SHA384"
  ELEMENT_NAME_STM_SHA512   = "STM-SHA512"
  ELEMENT_NAME_STM_SM3       = "STM-SM3"

  ELEMENT_NAME_MLE_LEGACY    = "MLE-LEGACY"
  ELEMENT_NAME_PCONF_LEGACY  = "PCONF-LEGACY"
  ELEMENT_NAME_SBIOS_LEGACY  = "SBIOS-LEGACY"

  # element name strings for PO rules
  ELEMENT_PO_RULES = [
    ELEMENT_NAME_STM_SHA512,   ELEMENT_NAME_STM_SHA384,
    ELEMENT_NAME_STM_SHA256,   ELEMENT_NAME_STM_SHA1,     #ELEMENT_NAME_STM_SM3,
    ELEMENT_NAME_PCONF_SHA512, ELEMENT_NAME_PCONF_SHA384,
    ELEMENT_NAME_PCONF_SHA256, ELEMENT_NAME_PCONF_SHA1,   #ELEMENT_NAME_PCONF_SM3,
    ELEMENT_NAME_PCONF_LEGACY,
    ELEMENT_NAME_MLE_SHA512,   ELEMENT_NAME_MLE_SHA384,
    ELEMENT_NAME_MLE_SHA256,   ELEMENT_NAME_MLE_SHA1,     #ELEMENT_NAME_MLE_SM3,
    ELEMENT_NAME_MLE_LEGACY
  ]

  """getElement - return array of element names strings"""
  ELEMENT = [
    ELEMENT_NAME_SBIOS_SHA512, ELEMENT_NAME_SBIOS_SHA384,
    ELEMENT_NAME_SBIOS_SHA256, ELEMENT_NAME_SBIOS_SHA1,   #ELEMENT_NAME_SBIOS_SM3,
    ELEMENT_NAME_SBIOS_LEGACY,
    ELEMENT_NAME_STM_SHA512,   ELEMENT_NAME_STM_SHA384,
    ELEMENT_NAME_STM_SHA256,   ELEMENT_NAME_STM_SHA1,     #ELEMENT_NAME_STM_SM3,
    ELEMENT_NAME_PCONF_SHA512, ELEMENT_NAME_PCONF_SHA384,
    ELEMENT_NAME_PCONF_SHA256, ELEMENT_NAME_PCONF_SHA1,   #ELEMENT_NAME_PCONF_SM3,
    ELEMENT_NAME_PCONF_LEGACY,
    ELEMENT_NAME_MLE_SHA512,   ELEMENT_NAME_MLE_SHA384,
    ELEMENT_NAME_MLE_SHA256,   ELEMENT_NAME_MLE_SHA1,     #ELEMENT_NAME_MLE_SM3,
    ELEMENT_NAME_MLE_LEGACY
  ]
  
  # This replaces util.getHashes()
  # supported hash algorithm names
  SUPPORTED_HASHES = [
    'SHA1', 'SHA256', 'SHA384', 'SHA512',
    #'SM3'
  ]
  
  # allowed hash algorithm names
  ALLOWED_HASHES = [
    'SHA1',
    #'SHA224', # not supported
    'SHA256', 'SHA384', 'SHA512',
    'SM3'
  ]
  
  # ALLOWED_SIGNATURE_SCHEMES is ordered list that references TPM_ALG_SIGN_MASK
  # allowed signing algorithm names
  ALLOWED_SIGNATURE_SCHEMES = [
    #'RSA-1024-SHA1', 'RSA-1024-SHA256', 'RSA-2048-SHA1',     # not supported
    'RSA-2048-SHA256',
    #'RSA-2048-SHA384', 'RSA-2048-SHA512',                    # not supported
    #'RSA-3072-SHA256', 'RSA-3072-SHA384', 'RSA-3072-SHA512', # not supported
    #'RSA-4096-SHA256', 'RSA-4096-SHA384', 'RSA-4096-SHA512', # not supported
    'ECDSA P-256', 'ECDSA P-384',
    'SM2'
  ]
  
  SIGNATURE_ALGORITHMS = [
    'None',
    #'RSA PKCS1.5/SHA1',
    'RSA PKCS1.5/SHA256',
    #'RSA PKCS1.5/SHA384',
    #'RSA PKCS1.5/SHA512',
    'ECDSA P-256/SHA256',
    'ECDSA P-384/SHA384',
    #'SM2/SM3'
  ]
  
  SIGNATURE_KEY_SIZE = {
    'None'                : [],
    'RSA PKCS1.5/SHA256'  : ['2048'],
    'ECDSA P-256/SHA256'  : ['256'],
    'ECDSA P-384/SHA384'  : ['384'],
    'SM2/SM3'             : ['256']
  }

  # Hash Algorithm defines for pdef.hashAlg
  TPM_ALG_HASH = {
    'SHA1_LEGACY'         : 0x0000,
    'SHA1'                : 0x0004,
    'SHA256'              : 0x000B,
    'SHA384'              : 0x000C,
    'SHA512'              : 0x000D,
    'NULL'                : 0x0010,
    'SM3'                 : 0x0012
  }

  # Signature Algorithm defined for LCP_POLICY_LIST2.SigAlgorithm
  TPM_ALG_SIGN = {
    'NULL'                : 0x0010,  # same as in Hash Algorithm
    'RSASSA'              : 0x0014,
    'ECDSA'               : 0x0018,
    'SM2'                 : 0x001B
  }

  # SHAXXXXX_DIGEST_SIZE
  DIGEST_SIZE = {
    'SHA1'                : 20,
    'SHA256'              : 32,
    'SHA384'              : 48,
    'SHA512'              : 64,
    'SM3'                 : 32
  }

  # TPM_ALG_HASH_MASK_XXXX
  TPM_ALG_HASH_MASK = {
    'SHA1'                : 0x0001,
    'SHA224'              : 0x0002,
    'SHA512_224'          : 0x0004,
    'SHA256'              : 0x0008,
    'SHA512_256'          : 0x0010,
    'SM3'                 : 0x0020,
    'SHA384'              : 0x0040,
    'SHA512'              : 0x0080,
    'WHIRLPOOL'           : 0x0100
  }

  # TPM_ALG_SIGN_MASK_XXXX
  TPM_ALG_SIGN_MASK = {
    'RSA-1024-SHA1'       : 0x00000001,
    'RSA-1024-SHA256'     : 0x00000002,
    'RSA-2048-SHA1'       : 0x00000004,
    'RSA-2048-SHA256'     : 0x00000008,
    'RSA-2048-SHA384'     : 0x00000010,
    'RSA-2048-SHA512'     : 0x00000020,
    'RSA-3072-SHA256'     : 0x00000040,
    'RSA-3072-SHA384'     : 0x00000080,
    'RSA-3072-SHA512'     : 0x00000100,
    'RSA-4096-SHA256'     : 0x00000200,
    'RSA-4096-SHA384'     : 0x00000400,
    'RSA-4096-SHA512'     : 0x00000800,
    'ECDSA P-256'         : 0x00001000,
    'ECDSA P-384'         : 0x00002000,
    'SM2'                 : 0x00010000
  }

  # Types of hash files - see util.verifyHashFile()

  HashFileMode = {
    'HdrNull'     : 0,
    'HdrSHA1'     : 1,
    'RawSHA1'     : 2,
    'RawSHA256'   : 3,
    'RawSHA384'   : 4,
    'RawSHA512'   : 5,
    'RawSM3'      : 6 #TODO: check the value
  }

  # Types of PCR dump Files - see util.verifyPcrFile()
  PcrFileMode = {
    'Null'         : 0,
    'Pcrd'         : 7,
    'Pcr2'         : 8
  }

  # key files are private or public keys for RSA or ECC
  KEY_FILE_TYPE = {
    'PRIVATE_RSASSA': 1,
    'PUBLIC_RSASSA' : 2,
    'PRIVATE_ECDSA' : 3,
    'PUBLIC_ECDSA'  : 4
  }

  PCRDFileHdrSize         = 16
  PCR2FileHdrSize         = 8
  PCRFileMinHdrSize       = 7   # 1st 6 bytes of PCRD or PCR2 file are enough to determine the type and check the HashAlg



