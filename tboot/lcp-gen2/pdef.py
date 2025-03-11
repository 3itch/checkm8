#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# using print() built infunction, disable print statement
from __future__ import print_function

import os
import time

from defines import DEFINES
from LcpPolicy import *
from util import UTILS
utilities = UTILS()


_GlobalHashData   = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

PCONF_ELEMENT2_HDR_SIZE = 16  # size of LCP_PCONF_ELEMENT2's fields except PcrInfo's
                              # i.e. sizeof(ElementSize+ElementType+
                              #      PolEltControl+HashAlg+NumPCRInfos)

PCR_INFO2_HDR_SIZE = 12       # size of TPMS_QUOTE_INFO's fileds except buffer
                              # i.e. sizeof(count+hash+sizeOfSelect+pcrSelect+size)

SHA1_PCR_INFO_SIZE = 26       # for PconfLegacyElement


# TXT Policy Generator Tool
# PDEF Class - Policy Definition File Structure
#
class PDEF( object ):
  """ PDEF Class"""

  def __init__( self ):
    """__init__() - PDEF class constructor"""
    self.WorkingDirectory = ""
    self.FileTypeSignature  = "TXT Policy Definition v2"       # CHAR8 array[24]
    self.DefCompany         = "Intel"                          # CHAR8 array[16]
    self.StructVersion      = 2                                # incremented for any change to structure
    #
    # Structure capacity - can change without incrementing StructVersion
    #
    self.MaxLists =          8                                 # UINT8  MAX_LISTS = 8      - Max lists per policy
    #self.MaxElements =       4                                 # UINT8  MAX_ELEMENTS = 4   - Max elements per list per element
    self.MaxElements =       2                                 # only support SHA1 & SHA256 so far, not yet SHA384 & SHA512

    self.MaxHashSize =       64                                # UINT8  MAX_HASH_SIZE = 64 - Max allowed HASH size
    self.MaxHashes =         16                                # UINT16 MAX_HASHES = 16    - Max hashes per element, 0=unlimited
    self.MaxFileNameSize =   32                                # UINT8  MAX_FILENAME_SIZE 32 - Max size for a filename
    # ReservedCap[6]    0,                                     # UINT8                       - reserved for future definition
    #
    # Start of variable data whose content can be changed by the tool
    #
    self.ToolDate =          time.strftime("%Y%m%d")           # UINT32   YYYYMMDD - Build date of the tool
    #self.ToolVersion =      0x0200                            # UINT16   Version of the tool
    self.ToolVersionMajor =  02
    self.ToolVersionMinor =  00
    self.Rules =             1                                 # UINT8    Type of rules: 0=PS, 1=PO
    self.Modified =          0                                 # BOOLEAN, True =changed since last 'BUILD'
    # ReservedTool                                             # UINT16
    #
    # Start of Policy Definition - same as NV Policy Structure
    #
    #self.PolVersion =        0x0301                           # UINT16
    self.PolVersionMajor =    03
    self.PolVersionMinor =    01
    self.HashAlg  =           DEFINES.TPM_ALG_HASH['SHA256']   # UINT16  TPM_ALG_XXXX
    self.PolicyType =         1                                # UINT8   0=LIST, 1=ANY
    self.SinitMinVersion =    0                                # UINT8
    self.DataRevocationCounters = [0,0,0,0,0,0,0,0]            # UINT16  DataRevocationCounters[MAX_LISTS] Default is 0's
    self.PolicyControl =      0                                # UINT32  Encoding of (NPW, PCR17, Force PO)
    self.MaxSinitMinVersion = 255                              # UINT8   reserved in PS Policy
    self.MaxBiosMinVersion =  255                              # UINT8   reserved in PS Policy
    # HashAlg is already defined above
    # LcpHashAlgMask should be the content of CheckListBox
    self.LcpHashAlgMask = DEFINES.TPM_ALG_HASH_MASK['SHA256']  # UINT16  TPM_ALG_HASH_MASK_XXXXX
    # Should AuxHashAlgMask be renamed to ApAlg?
    self.AuxHashAlgMask = DEFINES.TPM_ALG_HASH_MASK['SHA256']  # UINT16  TPM_ALG_HASH_MASK_XXXXX
    self.LcpSignAlgMask = DEFINES.TPM_ALG_HASH_MASK['SHA256']  # UINT32  TPM_ALG_SIGN_MASK_XXXXX

    # save both the raw and hex formatted versions of the SHA1 and SHA256 hashes
    #self.PolicyHashSha1       = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    #                             0,0,0,0]                          # MAX_HASH = 20 for SHA1,
    #self.PolicyHashSha1Hex    = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    #                             0,0,0,0]
    #self.PolicyHashSha256     = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    #                             0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]  # MAX_HASH = 32 for SHA256
    #self.PolicyHashSha256Hex  = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    #                             0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    # For Python, don't need multiple variable of different size to store hash values.
    # Going forward, there will be more hash algorithms.
    self.PolicyHash           = []
    self.PolicyHashHex        = []

    #
    # Start of Policy Data Structure Definition
    #
    #self.LastBuildDateStamp = 20000101                        # UINT32 - YYYYMMDD - date of last build
    self.LastBuildDateStampYear  = 2000                        #    UINT16 - YYYY  - year of last build
    self.LastBuildDateStampMonth = 01                          #    UINT8  - MM    - Month of last build
    self.LastBuildDateStampDay   = 01                          #    UINT8  - DD    - Day of last build
    #self.LastBuildTimeStamp = 00000000                        # UINT32 - HHMMSS00 - time of last build
    self.LastBuildTimeStampHour   = 00                         #    UINT8 - HH     - hour of last build
    self.LastBuildTimeStampMinute = 00                         #    UINT8 - MM     - minute of last build
    self.LastBuildTimeStampSecond = 00                         #    UINT8 - SS     - second of last build
    self.LastBuildTimeStampLowByte = 00                        #    UINT8 - 00     - read only
    # Reserved3                                                # UINT16
    self.CurrentListView =    0                                # UINT8    - saves user state, indicates list  to display
    self.NumLists =           0                                # UINT8    - Actual number of lists
    # PLIST_DEF PolListInfo[0-7]                               # PLIST_DEF - dictionary containing policy is populated in addPlistDef
    self.PolListInfo = {'0':None, '1':None,
                        '2':None, '3':None,
                        '4':None, '5':None,
                        '6':None, '7':None}

  #
  # add PolListInfo[0-7] to the PDEF
  #
  def addPlistDef(self, listNumber):
    """ addPlistDef - add a PLIST_DEF to the PDEF"""
    print("PLIST_DEF::addPlistDef - list %i" % (listNumber))

    if(listNumber > self.MaxLists):           # should never get here if caller checked MAX_LISTS correctly ...
      print("PLIST_DEF::addPlistDef - list %i > MAX=%i" % (listNumber, self.MaxLists))
    else:
      self.PolListInfo[str(listNumber-1)] = PLIST_DEF()
      #self.PolListInfo[str(listNumber-1)].append(PLIST_DEF())
      self.PolListInfo[str(listNumber-1)].ListValid = True
      #print("addPlistDef %d = %s" % (listNumber, self.PolListInfo[str(listNumber-1)])) # DBGDBG

      # at the time when adding the list to policy, sync policy version number to list version number
      policyversion = str(self.PolVersionMajor)+'.'+str(self.PolVersionMinor)
      listversion = DEFINES.SUPPORTED_LCP_VERSION[policyversion]
      majorstring, minorstring = listversion.split('.')
      self.PolListInfo[str(listNumber-1)].ListVersionMajor = int(majorstring)
      self.PolListInfo[str(listNumber-1)].ListVersionMinor = int(minorstring)


  def getCurrentListObject(self):
    """getCurrentListObject - return the current list object per CurrentListView"""
    listNumber = self.CurrentListView
    #print("getCurrentListObject - CurrentListView = %i" % (listNumber))

    if(listNumber > self.MaxLists):           # should never get here if CurrentListView was set correctly ...
      print("PLIST_DEF::getCurrentListObject - list %i > MAX_LISTS" % (listNumber))
    elif(listNumber <= 0):
      return self.PolListInfo[str(0)]
    else:
      return self.PolListInfo[str(listNumber-1)]


class PLIST_DEF( object ):
  """PLIST_DEF class"""

  def __init__(self):
    """___init__() = PLIST_DEF class constructor"""
    #print("constructing a PLIST_DEF")

    self.LdefSize                = 128                     # UINT32 - number of bytes in this LIST def
    self.Tag                     = "LIST"                  # UINT32 - confirms this is a LIST def struct
    #self.ListVersion             = 0x0201                 # UINT16 - version 2.1
    self.ListVersionMajor        = 02
    self.ListVersionMinor        = 01
    self.ListValid               = False                   # BOOLEAN - indicates if this list is to be included
    self.ListModified            = False                   # BOOLEAN - indicates if this list has changed since last build; only clear when building policy.
    # Reserved[3]           = 0                            # UINT8
    self.SigAlgorithm            = DEFINES.TPM_ALG_SIGN['NULL']    # UINT8 - USER: 0=Not signed, 1 = PSA PKCS15
    self.sigAlgorithmHash        = DEFINES.TPM_ALG_HASH['SHA1']    # corresponds to 1
    self.PolicyElementSize       = 0                       # UINT32 - total size of all elements in this list
    self.CurrentElementView      = "None"                  # UINT8 - saves user state: 0=MLE, 1=PCONF, 3=SBIOS, 0xFF=None
    # Reserved2[3]          = 0                            # UINT8

    # start of signature
    self.SyncRevCount            = True                    # BOOLEAN - if true, updates Policy with RevocationCounter value
    # Reserved3[3]          = 0                            # UINT8
    self.RevokeCounter           = 0                       # UINT16 - value to be populated in PDEF.RevocationCounter[n]
    self.RevocationCounter       = 0                       # UINT16
    self.KeySize                 = 2048                    # UINT16 -  1024, 2048 or 3072, default = 2048
    self.PubKeyFile              = ""                      # CHAR16[MAX_FILENAME_SIZE=32] - filename of signing key
    self.PvtKeyFile              = ""
    self.PubKeyData              = ""                      # PubKeyData[KeySize] for RSA - as a binary string
    # Not creating a separate class because the GUI will create and destroy when selecting between RSA and ECC signature algs
    self.PubKeyQx                = ""                      # PubKeyData[KeySize] for ECC x coord - as binary string
    self.PubKeyQy                = ""                      # PubKeyData[KeySize] for ECC y coord - as binary string
    self.PvtKeyFileIsSignature   = False                   # False: PvtKeyFile is a key file; True: PvtKeyFile is signature file

    # using one collection(list) to store all element definition data
    # Python list guarantees the order.
    self.ElementDefData = []


# MLE Element definition - TYPE=0
class MLE_DEF( object ):
  """MLE_DEF class"""

  def __init__(self, hashAlg):
    """__init__() = MLE_DEF class constructor"""
    #print("constructing a MLE_DEF")

    try:
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
    except StopIteration:
      hashAlgname = ""
      print("MLE_DEF::__init__ - invalid hashAlg=%d" % (hashAlg))

    self.Name                = "MLE-"+hashAlgName          # String - Name used for GUI identification
    self.InfoSize            = 24                          # UINT32 - number of bytes in this structure
    self.Tag                 = "MLE_"                      # UINT32 - confirms this is a MLE_DEF
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes an MLE element
    #Reserved3[5]            = 0                           # UINT8
    self.SinitMinVersion     = 0                           # UINT8 - USER
    self.HashAlg             = hashAlg                     # UINT16 - TPM_ALG_SHAXXXXX
    self.Control             = 0                           # UINT32 - USER: Bit0: Ignore PS MLE elements
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in MleHashFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last MleHashFiles[] selected
    self.HashFiles           = []                          # variable size array containing filenames of hashes

  # Build the MLE element and return its size
  # thisPdefList - is the list's source data from pdef.PolListInfo[list]
  # policyElement - is the destination LCP POLICY element
  # Return the elementSize built, or 0 if an error occurs
  #
  def build(self, thisPdefList, policyElements, cwd):
    """buildMleElement - build the MLE element"""
    func = 'buildMleElement'

    print("%s" %(func )) # DBGDBG
    elementSize = 18        # size all fields except Hashes[] in bytes

    # build the element's data
    #mleDefData = thisPdefList.MleDefData[index]
    policyElement = LCP_MLE_ELEMENT2()
    policyElement.PolEltControl = self.Control
    policyElement.SINITMinVersion = self.SinitMinVersion
    policyElement.HashAlg = self.HashAlg
    policyElement.NumHashes = self.NumbHashes
    print("%s - PolEltControl=%d, SINITMinVersion=%d from %d" %
          (func, policyElement.PolEltControl, policyElement.SINITMinVersion, self.SinitMinVersion)) # DBGDBG

    hashAlg = self.HashAlg
    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()
    except StopIteration:
      print ("HashAlg=%d is not supported, aborting build" % (hashAlg))
      return 0

    # Build the hashes from each HashFiles[]
    for file in self.HashFiles:
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), self.HashAlg)
      if(len(hashdata) != DEFINES.DIGEST_SIZE[hashAlgName]):
        #self.StatusBar.SetStatusText("Invalid hash file %s, aborting build" % (file))
        return 0

      #policyElement.Hashes += _GlobalHashData      # the hash data from the file
      policyElement.Hashes.append(hashdata)
      print("%s - policyElement.Hashes size=0x%x" % (func, len(policyElement.Hashes))) # DBGDBG

    # update elementSize
    elementSize += DEFINES.DIGEST_SIZE[hashAlgName] * self.NumbHashes

    # ElementSize = 16 +HashSize* (PDEF.PolListInfo[i].MleDefData[index].NumbHashes)
    # if HashAlg == SHA-1, HashSize=20
    policyElement.ElementSize = elementSize
    print("%s - done, size=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printDef - write the Mle Def to the specified human readable text file for printing"""

    #print("printMleDef - object: %s" % (mleDefData))     # DBGDBG
    print("***MLE_DEF***",                                      file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    #print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("SinitMinVersion",      " = ", self.SinitMinVersion,  file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)
    print("HashFiles",            " = ", self.HashFiles,        file=f)


class MLELEGACY_DEF( object ):
  """MLELEGACY_DEF class"""

  def __init__(self):
    """__init__() = MLELEGACY_DEF class constructor"""
    #print("constructing a MLELEGACY_DEF")

    self.Name                = DEFINES.ELEMENT_NAME_MLE_LEGACY  # String - Name used for GUI identification
    self.InfoSize            = 24                          # UINT32 - number of bytes in this structure
    self.Tag                 = "MLE_"                      # UINT32 - confirms this is a MLE_DEF
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes an MLE element
    #Reserved3[5]            = 0                           # UINT8
    self.SinitMinVersion     = 0                           # UINT8 - USER
    self.HashAlg             = 0                           # UINT8 - SHA1
    self.Control             = 0                           # UINT32 - USER: Bit0: Ignore PS MLE elements
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in MleHashFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last MleHashFiles[] selected
    self.HashFiles           = []                          # variable size array containing filenames of hashes

  # Build the MLE element and return its size
  # thisPdefList - is the list's source data from pdef.PolListInfo[list]
  # policyElement - is the destination LCP POLICY element
  # Return the elementSize built, or 0 if an error occurs
  #
  def build(self, thisPdefList, policyElements, cwd):
    """buildMleLegacyElement - build the MLE element"""

    func = "buildMleLegacyElement"
    print("%s" %(func)) # DBGDBG
    elementSize = 16        # size all fields except Hashes[] in bytes

    # build the element's data
    #mleDefData = thisPdefList.MleLegacyDefData[DEFINES.DEFDATA_INDEX['SHA1']]
    policyElement = LCP_MLE_ELEMENT()
    policyElement.PolEltControl = self.Control
    policyElement.SINITMinVersion = self.SinitMinVersion
    policyElement.HashAlg = self.HashAlg
    policyElement.NumHashes = self.NumbHashes
    print("%s - PolEltControl=%d, SINITMinVersion=%d from %d" %
          (func, policyElement.PolEltControl, policyElement.SINITMinVersion, self.SinitMinVersion)) # DBGDBG

    # Build the hashes from each HashFiles[]
    for file in self.HashFiles:
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), DEFINES.TPM_ALG_HASH['SHA1'])
      if(len(hashdata) != DEFINES.DIGEST_SIZE['SHA1']):
        print ("Invalid hash file %s, aborting build" % (file))
        return 0

      policyElement.Hashes.append(hashdata)      # the hash data from the file
      print("%s - policyElement.Hashes size=0x%x" % (func, len(policyElement.Hashes))) # DBGDBG

    if(self.HashAlg == DEFINES.TPM_ALG_HASH['SHA1_LEGACY']):
      # update elementSize
      elementSize += DEFINES.DIGEST_SIZE['SHA1'] * self.NumbHashes
    else:
      print ("HashAlg=%d is not supported, aborting build" % (thisPdefList.HashAlg))
      return 0

    # ElementSize = 16 +HashSize* (PDEF.PolListInfo[i].MleDefData.NumbHashes)
    # if HashAlg == SHA-1, HashSize=20
    policyElement.ElementSize = elementSize
    print("%s - done, size=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printMleDef - write the Mle Def to the specified human readable text file for printing"""

    #print("printMleDef - object: %s" % (mleDefData))     # DBGDBG

    print("***MLELEGACY_DEF***",                                file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    #print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("SinitMinVersion",      " = ", self.SinitMinVersion,  file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)
    print("HashFiles",            " = ", self.HashFiles,        file=f)


# STM Element definition - TYPE=0
class STM_DEF( object ):
  """STM_DEF class"""

  def __init__(self, hashAlg):
    """__init__() = STM_DEF class constructor"""
    #print("constructing a STM_DEF")

    try:
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
    except StopIteration:
      hashAlgname = ""
      print("STM_DEF::__init__ - invalid hashAlg=%d" % (hashAlg))

    self.Name                = "STM-"+hashAlgName          # String - Name used for GUI identification
    self.InfoSize            = 24                          # UINT32 - number of bytes in this structure
    self.Tag                 = "STM_"                      # UINT32 - confirms this is a MLE_DEF
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes an MLE element
    #Reserved3[5]            = 0                           # UINT8
    self.HashAlg             = hashAlg                     # UINT16 - TPM_ALG_SHAXXXXX
    self.Control             = 0                           # UINT32 - USER: Bit0: Ignore PS MLE elements
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in MleHashFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last MleHashFiles[] selected
    self.HashFiles           = []

  def build(self, thisPdefList, policyElements, cwd):
    """buildStmElement - build the STM element"""

    func='buildStmElement'
    print("%s" % (func)) # DBGDBG
    elementSize = 16        # size all fieds except Hashes[] in bytes

    # build the element's data
    #stmDefData = thisPdefList.StmDefData[index]
    policyElement = LCP_STM_ELEMENT2()
    policyElement.PolEltControl = self.Control
    policyElement.HashAlg = self.HashAlg
    policyElement.NumHashes = self.NumbHashes
    print("%s - PolEltControl=%d" % (func, policyElement.PolEltControl)) # DBGDBG


    hashAlg = self.HashAlg
    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()
    except StopIteration:
      print ("HashAlg=%d is not supported, aborting build" % (hashAlg))
      return 0

    # Build the hashes from each HashFiles[]
    for file in self.HashFiles:
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), self.HashAlg)
      if(len(hashdata) != DEFINES.DIGEST_SIZE[hashAlgName]):
        #self.StatusBar.SetStatusText("Invalid hash file %s, aborting build" % (file))
        return 0

      #policyElement.Hashes += _GlobalHashData      # the hash data from the file
      policyElement.Hashes.append(hashdata)
      print("%s - policyElement.Hashes size=0x%x" % (func, len(policyElement.Hashes))) # DBGDBG

    # update elementSize
    elementSize += DEFINES.DIGEST_SIZE[hashAlgName] * self.NumbHashes

    # ElementSize = 16 +HashSize* (PDEF.PolListInfo[i].StmDefData[index].NumbHashes)
    # if HashAlg == SHA-1, HashSize=20
    policyElement.ElementSize = elementSize
    print("%s - done, size=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printDef - write the Stm Def to the specified human readable text file for printing"""

    #print("printStmDef - object: %s" % (stmDefData))     # DBGDBG

    print("***STM_DEF***",                                      file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    #print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)
    print("HashFiles",            " = ", self.HashFiles,        file=f)


class PCONF_INFO( object ):
  """PCONF_INFO definition"""

  def __init__(self):
    """__init__() PCONF_INFO constructor"""

    self.pcrSelect            = [1, 0, 0]                  # UINT8 - pcrSelect[0]=1 => pcr0-7
    #reserved                 = 0                          # UINT8
    self.pcrFile                   = "myPcrFile.pcr"

    self.PCR0_BIT             = 0x01
    self.PCR1_BIT             = 0x02
    self.PCR2_BIT             = 0x04
    self.PCR3_BIT             = 0x08
    self.PCR4_BIT             = 0x10
    self.PCR5_BIT             = 0x20
    self.PCR6_BIT             = 0x40
    self.PCR7_BIT             = 0x80

class PCONF_DEF( object ):
  """PCONF_DEF class"""

  def __init__(self, hashAlg):
    """__init__() PCONF_DEF constructor"""
    #print("constructing a PCONF_DEF")

    hashAlgName = ""
    try:
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
    except StopIteration:
      print("PCONF_DEF::__init__ - invalid hashAlg=%d" % (hashAlg))

    self.Name                = "PCONF-"+hashAlgName        # String - Name used for GUI identification
    self.InfoSize            = 24                          # UINT32 - number of bytes in this struct
    self.Tag                 = "PCON"                      # UINT32 - confirms that this is a PCONF policy defintion element
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes a PCONF element
    # Reserved5[6]           = 0                           # UINT8
    self.HashAlg             = hashAlg                     # UINT16 - TPM_ALG_SHAXXXX ...
    self.Control             = 0                           # UINT32 - USER: Bit0: Ignore PS PCONF elements
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in PconfFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last PconfFiles[] selected
    #PCONF_INFO PcrInfoSrc[]                               # array of PCR selection and PCR dump file names
    self.PcrInfoSrc = []

  # Build the PCONF element and return its size
  # thisPdefList - is the list's source data from pdef.PolListInfo[list]
  # policyElement - is the destination LCP POLICY element
  # listCnt  - is the current list
  #
  def build(self, thisPdefList, policyElements, cwd):
    """buildPconfElement - build the PCONF element"""

    func = "buildPconfElement"
    print("%s" %(func)) # DBGDBG
    # build the element's data
    elementSize = PCONF_ELEMENT2_HDR_SIZE                   # size of all fields except PcrInfo's
    #pconfDefData = thisPdefList.PconfDefData[index]
    policyElement = LCP_PCONF_ELEMENT2()
    policyElement.PolEltControl = self.Control
    policyElement.HashAlg       = self.HashAlg
    policyElement.NumPCRInfos   = self.NumbHashes   # really number TPMS_QUOTE_INFO's

    # Build each policyElement.PCRInfos' TPMS_QUOTE_INFO
    # for each pcr
    i = 0                                                   # number of PcrInfoSrc's in LCP_PCONF_ELEMENT
    for pdefPcrInfo in self.PcrInfoSrc:
      thisTpmsQuoteInfo = TPMS_QUOTE_INFO()
      policyElement.PCRInfos.append(thisTpmsQuoteInfo)
      thisTpmsQuoteInfo = policyElement.PCRInfos[i]
      thisTpmlPcrSelection = thisTpmsQuoteInfo.pcrSelect    # TPML_PCR_SELECTION()
      thisTpm2bDigest      = thisTpmsQuoteInfo.pcrDigest    # TPM2B_DIGEST()
      # Set pcrSelections (which is type: TPMS_PCR_SELECTION) in a TPML_PCR_SELECTION to indicate the selected PCRs.
      # Hash is the same algorithm ID as HashAlg in LCP_PCONF_ELEMENT2 since TPML_PCR_SELECTION's count=1
      # Size of Select is always 3
      #   (because the TPM has 24 PCRs and thus requires 24-bits to indicate which PCR)
      # However the 2nd and 3rd bytes of pcrSelect[] are always 0x00 because the policy
      #   only selects between the first 8 PCRs.
      # pcrSelect[0] is a bit mask formed from thisPdefList.PconfDefData[index].PcrInfoSrc[i].pcrSelect[0]
      #   which is an 8 element list corresponding to each selected pcr from 0-7
      #
      thisTpmlPcrSelection.count = 1      # So 1 TPMS_PCR_SELECTION and HashAlg per PCONF, see Spec A.2.2.4 p31
      thisTpmsPcrSelection = thisTpmlPcrSelection.pcrSelections
      thisTpmsPcrSelection.hash = policyElement.HashAlg
      thisTpmsPcrSelection.sizeOfSelect = 0x0003

      pcr0to7SelectionBitMask = 0
      numSelectedPcrs = 0
      thisBit = 0x80
      pcr0to7SelectionList = pdefPcrInfo.pcrSelect[0]
      for eachBit in pcr0to7SelectionList:
        if(eachBit == 1):
            pcr0to7SelectionBitMask |= thisBit
            numSelectedPcrs += 1
        thisBit >>= 1

      thisTpmsPcrSelection.pcrSelect[0] =  pcr0to7SelectionBitMask
      thisTpmsPcrSelection.pcrSelect[1] =  0
      thisTpmsPcrSelection.pcrSelect[2] =  0
      print("%s - PCRInfos[%d], pcrSelect[0]=0x%x, numSelectedPcrs=%d" %
            (func, i, thisTpmsPcrSelection.pcrSelect[0], numSelectedPcrs)) # DBGDBG
      i += 1

      # determine if pcrFile is a PCRD or PCR2 formatted file
      file = pdefPcrInfo.pcrFile
      file = os.path.join(cwd, file)
      result = utilities.verifyPcrFile(file, policyElement.HashAlg)
      fileType = result[1]
      if(result[0] == False):
        print("%s - verifyPcrFile says PCR file %s is invalid!!!" % (func, file))  # Should NEVER get here
        return 0

      # calculate thisTpm2bDigest.size and build TPM2B_DIGEST.buffer from the PCR data
      # in this pdef list's selected pcrFiles
      hashAlg = self.HashAlg

      try:
        # reverse lookup of the hash algorithm name(key) for the given HashAlg value
        hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()
      except StopIteration:
        print ("HashAlg=%d is not supported, aborting build" % (hashAlg))
        return 0

      hashSize = DEFINES.DIGEST_SIZE[hashAlgName]

      # verify that the pcfFile contains numHashes PCR values. These checks weren't done by verifyPcrFile()
      result = utilities.verifyPcrInfoNumHashes(file, fileType, hashAlg, pcr0to7SelectionBitMask)
      if(result == False):
        print("%s - verifyPcrInfoNumHashes says PCR file %s is invalid!!!" % (func, file))
        return 0

      elementSize += PCR_INFO2_HDR_SIZE  #  includes thisTpm2bDigest.size  but not buffer
      if(pcr0to7SelectionBitMask == 0):                               # no pcr's selected
        thisTpm2bDigest.size = 0                                      # buffer is empty

      else:
        #thisTpm2bDigest.size = numSelectedPcrs * hashSize             # sizeof(buffer)
        thisTpm2bDigest.size = hashSize                                # There's only one composite hash

        # for each selected PCR from 0 to 7
        if(pcr0to7SelectionBitMask != 0):
          #  Build tpmPcrSelection.digestAtRelease from the PCR data in this pdef list's selected pcrFiles
          hashdata = utilities.hashPcrInfoFromFile(os.path.join(cwd, file), pcr0to7SelectionBitMask, numSelectedPcrs)
          if(len(hashdata) != hashSize):
            print("%s - Invalid PCR file %s, aborting build" % (func, file))
            return 0

          tempbuf = array('B')
          tempbuf.fromstring(hashdata)
          #thisTpm2bDigest.buffer += _GlobalPcrHash
          thisTpm2bDigest.buffer += tempbuf
          elementSize += thisTpm2bDigest.size
        else:
          print ("%s - Nothing to hash: pcr0to7SelectionBitMask=0" %(func))  # DBGDBG
          print ("Note: No PCR was selected. If desired, select PCR's and click Update")

      #print("buildPconfElement - next pcrInfo i=%d" % (i)) # DBGDBG
      # end of pcrInfo for loop
    # update this element's size
    policyElement.ElementSize = elementSize
    print("%s - done, elementSize=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printDef - write the PCONF_DEF to the specified file"""

    #print("printPconfDef - object: %s" % (pconfDefData))     # DBGDBG

    print("***PCONF_DEF***",                                    file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    #print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)

    i = 0
    for eachPconfInfo in self.PcrInfoSrc:
      print("\n", file=f)         # for readability
      self.printPconfInfo(eachPconfInfo, i, f)
      i += 1

  def printPconfInfo(self, pconfInfo, index, f):
    """printPconfInfo - write the PCONF_INFO to the specified human readable text file for printing"""

    #print("printPconfInfo %d object: %s" % (index, pconfInfo))     # DBGDBG

    print("***PCONF_INFO", index, "***",                              file=f)
    print("InfoSize",             " = ", pconfInfo.pcrSelect,         file=f)
    print("Tag",                  " = ", pconfInfo.pcrFile,           file=f)


class PCONFLEGACY_DEF( object ):
  """PCONFLEGACY_DEF class"""

  def __init__(self):
    """__init__() PCONFLEGACY_DEF constructor"""
    #print("constructing a PCONFLEGACY_DEF")

    self.Name                = DEFINES.ELEMENT_NAME_PCONF_LEGACY # String - Name used for GUI identification
    self.InfoSize            = 24                          # UINT32 - number of bytes in this struct
    self.Tag                 = "PCON"                      # UINT32 - confirms that this is a PCONF policy defintion element
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes a PCONF element
    # Reserved5[6]           = 0                           # UINT8
    self.HashAlg             = 0                           # UINT8 - 0 = SHA1, others reserved for future use ...
    self.Control             = 0                           # UINT32 - USER: Bit0: Ignore PS PCONF elements
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in PconfFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last PconfFiles[] selected
    #PCONF_INFO PcrInfoSrc[]                               # array of PCR selection and PCR dump file names
    self.PcrInfoSrc = []


  # Build the PCONF element and return its size
  # thisPdefList - is the list's source data from pdef.PolListInfo[list]
  # policyElement - is the destination LCP POLICY element
  #
  def build(self, thisPdefList, policyElements, cwd):
    """buildPconfLegacyElement - build the PCONF Legacy element"""

    func = "buildPconfLegacyElement"
    print("%s" %(func)) # DBGDBG
    elementSize = 14     # size of all fields except PcrInfo's

    # build the element's data
    #pconfDefData = thisPdefList.PconfLegacyDefData
    policyElement = LCP_PCONF_ELEMENT()
    policyElement.PolEltControl = self.Control
    policyElement.NumPCRInfos = self.NumbHashes

    # Build each policyElement.PCRInfos[NumPCRInfos]
    # for each hash to NumbHashes-1 i.e. to NumPCRInfos-1
    #
    i = 0     # number of PcrInfoSrc's in LCP_PCONF_ELEMENT
    for pdefPcrInfo in self.PcrInfoSrc:
        thisTpmPcrInfoShort = TPM_PCR_INFO_SHORT()
        policyElement.PCRInfos.append(thisTpmPcrInfoShort)
        thisTpmPcrInfoShort = policyElement.PCRInfos[i]
        thisTpmPcrInfoShort.localityAtRelease = 0x1f        # any locality

        # Set pcrSelection (which is type: TPM_PCR_SELECTION) to indicate the selected PCRs.
        # Size of Select is always 3
        #   (because the TPM has 24 PCRs and thus requires 24-bits to indicate which PCR)
        # However the 2nd and 3rd bytes of pcrSelect[] are always 0x00 because the policy
        #   only selects between the first 8 PCRs.
        # pcrSelect[0] is a bit mask formed from thisPdefList.PconfLegacyDefData[index].PcrInfoSrc[i].pcrSelect[0]
        #   which is an 8 element list corresponding to each selected pcr from 0-7
        #
        thisTpmPcrSelection = thisTpmPcrInfoShort.pcrSelection
        thisTpmPcrSelection.sizeOfSelect = 0x0003

        pcr0to7SelectionBitMask = 0
        numSelectedPcrs = 0
        thisBit = 0x80
        pcr0to7SelectionList = pdefPcrInfo.pcrSelect[0]
        for eachBit in pcr0to7SelectionList:
          if(eachBit == 1):
              pcr0to7SelectionBitMask |= thisBit
              numSelectedPcrs += 1

          thisBit >>= 1

        thisTpmPcrSelection.pcrSelect[0] =  pcr0to7SelectionBitMask
        thisTpmPcrSelection.pcrSelect[1] =  0
        thisTpmPcrSelection.pcrSelect[2] =  0

        print("%s - PCRInfos[%d], pcrSelect[0]=0x%x" % (func, i, thisTpmPcrSelection.pcrSelect[0])) # DBGDBG
        i += 1

        #  Build tpmPcrSelection.digestAtRelease from the PCR data in this pdef list's selected pcrFiles
        file = pdefPcrInfo.pcrFile
        hashdata = utilities.hashPcrInfoFromFile(os.path.join(cwd, file), pcr0to7SelectionBitMask, numSelectedPcrs)
        if(len(hashdata) != DEFINES.DIGEST_SIZE['SHA1']):
            print("%s - Invalid PCR file %s, aborting build" % (func, file))
            return 0

        thisTpmPcrInfoShort.digestAtRelease = hashdata      # hash of the selected PCR data from the file
        #print("buildPconfElement - digestAtRelease=%s, _GlobalPcrHash=%s" % ( thisTpmPcrInfoShort.digestAtRelease, _GlobalPcrHash))

    if(self.HashAlg == DEFINES.TPM_ALG_HASH['SHA1_LEGACY']):
      # ElementSize = 14 +PcrInfoSize* (PDEF.PolListInfo[i].PconfDefData[index].NumbHashes)
      # if HashAlg == SHA-1, PcrInfoSize=26
      elementSize += SHA1_PCR_INFO_SIZE * self.NumbHashes
    else:
      print ("HashAlg=%d is not supported, aborting build" % (thisPdefList.HashAlg))
      return 0

    # update this element's size
    policyElement.ElementSize = elementSize
    print("%s - done, size=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printPconfDef - write the PCONF_DEF to the specified file"""

    #print("printPconfDef - object: %s" % (pconfDefData))     # DBGDBG

    print("***PCONFLegacy_DEF***",                              file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)

    i = 0
    for eachPconfInfo in self.PcrInfoSrc:
      print("\n", file=f)         # for readability
      self.printPconfInfo(eachPconfInfo, i, f)
      i += 1

  def printPconfInfo(self, pconfInfo, index, f):
    """printPconfInfo - write the PCONF_INFO to the specified human readable text file for printing"""

    #print("printPconfInfo %d object: %s" % (index, pconfInfo))     # DBGDBG

    print("***PCONF_INFO", index, "***",                              file=f)
    print("InfoSize",             " = ", pconfInfo.pcrSelect,         file=f)
    print("Tag",                  " = ", pconfInfo.pcrFile,           file=f)


class SBIOS_DEF( object ):
  """SBIOS_DEF class"""

  def __init__(self, hashAlg):
    """__init__() SBIOS_DEF constructor"""
    #print("constructing a SBIOS_DEF")

    hashAlgName = ""
    try:
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
    except StopIteration:
      print("SBIOS_DEF::__init__ - invalid hashAlg=%d" % (hashAlg))

    self.Name                = "SBIOS-"+hashAlgName        # String - Name used for GUI identification
    self.InfoSize            = 56                          # UINT32 - number of bytes in this struct
    self.Tag                 = "SBIO"                      # UINT32 - confirms that this is a SBIOS policy defintion element
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes a SBIOS element
    # Reserved5[6]           = 0                           # UINT8
    self.HashAlg             = hashAlg                     # UINT16 - TPM_ALG_SHAXXXXX
    self.FallBackHashFile    = ""                          # FILEName - user - filename containing the fallback hash
    self.Control             = 0                           # UINT32 - USER: There are no defined controls at this time
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in SbiosFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last PconfFiles[] selected
    self.SbiosFiles          = []                          # variable size array containing filenames of hashes

  # Build the SBIOS element and return its size
  # thisPdefList - is the list's source data from pdef.PolListInfo[list]
  # policyElement - is the destination LCP POLICY element
  # Return the elementSize built, or 0 if an error occurs
  #
  def build(self, thisPdefList, policyElements, cwd):
    """buildSbiosElement - build the SBIOS element"""

    func = "buildSbiosElement"
    print("%s"%(func)) # DBGDBG
    elementSize = 20

    # build the element's data
    #sbiosDefData = thisPdefList.SbiosDefData[index]
    policyElement = LCP_SBIOS_ELEMENT2()
    policyElement.PolEltControl = self.Control
    policyElement.HashAlg   = self.HashAlg
    invalidMsg = "Invalid fallbackhash file, aborting build"
    noneMsg    = "No fallbackhash file was specified, aborting build"

    hashAlg = self.HashAlg
    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()
    except StopIteration:
      print ("HashAlg=%d is not supported, aborting build" % (hashAlg))
      return 0

    # open the FallbackHash file and get the hash data
    file = self.FallBackHashFile
    if(file != ""):
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), self.HashAlg)
      if(len(hashdata) != DEFINES.DIGEST_SIZE[hashAlgName]):
        print("%s" % (invalidMsg))    # also show in output window
        return 0
    else:
      print("%s" % (noneMsg))         # also show in output window
      return 0

    # if there was no fallback hash file specified, then hash 0's [the init value of _GlobalHashData
    # otherwise use the value from that file
    #policyElement.FallbackHash = _GlobalHashData      # the hash data from the file
    policyElement.FallbackHash = hashdata
    policyElement.NumHashes    = self.NumbHashes

    # print("buildSbiosElement: type=%d, Alg=%d, Fallback=%s, GlobalHash=%s, NumbHashes=%d" %
    #        (policyElement.ElementType, policyElement.HashAlg ,
    #         policyElement.FallbackHash, _GlobalHashData, policyElement.NumHashes))     # DBGDBG

    # Build the hashes from each SbiosFiles[]
    for file in self.SbiosFiles:
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), self.HashAlg)
      if(len(hashdata) != DEFINES.DIGEST_SIZE[hashAlgName]):
        #self.StatusBar.SetStatusText("Invalid hash file %s, aborting build" % (file))
        return 0

      #policyElement.Hashes += _GlobalHashData      # the hash data from the file
      policyElement.Hashes.append(hashdata)
      print("%s - policyElement.Hashes size=0x%x" % (func,len(policyElement.Hashes))) # DBGDBG

    # update elementSize
    elementSize += DEFINES.DIGEST_SIZE[hashAlgName] * (self.NumbHashes+1) # +1 for fallback hash

    # ElementSize = 20 +HashSize* (1+PDEF.PolListInfo[i].SbiosDefData[index].NumbHashes)
    # if HashAlg == SHA-1, HashSize=20
    policyElement.ElementSize = elementSize
    print("%s - done, size=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printDef - write the Sbios Def to the specified human readable text file for printing"""

    #print("printSbiosDef - object: %s" % (sbiosDefData))     # DBGDBG

    print("***SBIOS_DEF***",                                    file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    #print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("FallBackHashFile",     " = ", self.FallBackHashFile, file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)
    print("SbiosFiles",           " = ", self.SbiosFiles,       file=f)


class SBIOSLEGACY_DEF( object ):
  """SBIOS_DEF class"""

  def __init__(self):
    """__init__() SBIOSLEGACY_DEF constructor"""
    #print("constructing a SBIOSLEGACY_DEF")

    self.Name                = DEFINES.ELEMENT_NAME_SBIOS_LEGACY  # String - Name used for GUI identification
    self.InfoSize            = 56                          # UINT32 - number of bytes in this struct
    self.Tag                 = "SBIO"                      # UINT32 - confirms that this is a SBIOS policy defintion element
    self.IncludeInList       = False                       # BOOLEAN - indicates this LIST includes a SBIOS element
    # Reserved5[6]           = 0                           # UINT8
    self.HashAlg             = 0                           # UINT8 - 0 = SHA1, others reserved for future use ...
    self.FallBackHashFile    = ""                          # FILEName - user - filename containing the fallback hash
    self.Control             = 0                           # UINT32 - USER: There are no defined controls at this time
    self.NumbHashes          = 0                           # UINT16 - Tracks number of valid entries in SbiosFiles[]
    self.CurrentView         = 0                           # UINT16 - User state: last PconfFiles[] selected
    self.SbiosFiles          = []                          # variable size array containing filenames of hashes

  # Build the SBIOS element and return its size
  # thisPdefList - is the list's source data from pdef.PolListInfo[list]
  # policyElement - is the destination LCP POLICY element
  # Return the elementSize built, or 0 if an error occurs
  #
  def build(self, thisPdefList, policyElements, cwd):
    """buildSbiosElement - build the SBIOS element"""

    func = "buildSbiosLegacyElement"
    print("%s" %(func))
    elementSize = 20

    # build the element's data
    #sbiosDefData = thisPdefList.SbiosLegacyDefData[DEFINES.DEFDATA_INDEX_SHA1]
    policyElement = LCP_SBIOS_ELEMENT()
    policyElement.PolEltControl = self.Control
    policyElement.HashAlg   = self.HashAlg
    invalidMsg = "Invalid fallbackhash file, aborting build"
    noneMsg    = "No fallbackhash file was specified, aborting build"

    # open the FallbackHash file and get the hash data
    file = self.FallBackHashFile
    if(file != ""):
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), DEFINES.TPM_ALG_HASH['SHA1'])
      if(len(hashdata) != DEFINES.DIGEST_SIZE['SHA1']):
        print("%s" % (invalidMsg))    # also show in output window
        return 0
    else:
      print("%s" % (noneMsg))         # also show in output window
      return 0

    # if there was no fallback hash file specified, then hash 0's [the init value of _GlobalHashData
    # otherwise use the value from that file
    policyElement.FallbackHash = hashdata      # the hash data from the file
    #policyElement.Hashes.append(hashdata)

    # print("buildSbiosElement: type=%d, Alg=%d, Fallback=%s, GlobalHash=%s, NumbHashes=%d" %
    #        (policyElement.ElementType, policyElement.HashAlg ,
    #         policyElement.FallbackHash, _GlobalHashData, policyElement.NumHashes))     # DBGDBG

    policyElement.NumHashes    = self.NumbHashes
    # Build the hashes from each SbiosFiles[]
    for file in self.SbiosFiles:
      hashdata = utilities.getHashFromFile(os.path.join(cwd, file), DEFINES.TPM_ALG_HASH['SHA1'])
      if(len(hashdata) != DEFINES.DIGEST_SIZE['SHA1']):
        print ("Invalid hash file %s, aborting build" % (file))
        return 0

      policyElement.Hashes.append(hashdata)      # the hash data from the file
      print("%s - policyElement.Hashes size=0x%x" % (func, len(policyElement.Hashes))) # DBGDBG

    if(self.HashAlg == DEFINES.TPM_ALG_HASH['SHA1_LEGACY']):
      # update elementSize
      elementSize += DEFINES.DIGEST_SIZE['SHA1'] * (self.NumbHashes+1)   # +1 for fallback hash
    else:
      print("%s - HashAlg=%d is not supported, aborting build" % (func, thisPdefList.HashAlg))
      return 0

    # ElementSize = 20 +HashSize* (1+PDEF.PolListInfo[i].SbiosDefData.NumbHashes)
    # if HashAlg == SHA-1, HashSize=20
    policyElement.ElementSize = elementSize
    print("%s - done, size=0x%x" % (func, elementSize))

    policyElements.append(policyElement)
    return(elementSize)

  def printDef(self, f):
    """printSbiosDef - write the Sbios Def to the specified human readable text file for printing"""

    #print("printSbiosDef - object: %s" % (sbiosDefData))     # DBGDBG

    print("***SBIOSLEGACY_DEF***",                              file=f)
    print("InfoSize",             " = ", self.InfoSize,         file=f)
    print("Tag",                  " = ", self.Tag,              file=f)
    #print("IncludeInList",        " = ", self.IncludeInList,    file=f)
    print("HashAlg",              " = ", hex(self.HashAlg),     file=f)
    print("FallBackHashFile",     " = ", self.FallBackHashFile, file=f)
    print("Control",              " = ", self.Control,          file=f)
    print("NumbHashes",           " = ", self.NumbHashes,       file=f)
    print("CurrentView",          " = ", self.CurrentView,      file=f)
    print("SbiosFiles",           " = ", self.SbiosFiles,       file=f)
