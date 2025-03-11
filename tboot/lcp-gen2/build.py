#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# TXT Policy Generator Tool
# support for Building LCP_POLICY and LCP_POLICY_DATA Files

# using print() built in function, disable print statement
from __future__ import print_function

from struct import *
#import hashlib
import binascii

from defines import DEFINES
from pdef import PDEF

from util import UTILS
utilities = UTILS()

from LcpPolicy import *
LcpPolicy = LCP_POLICY2()
LcpPolicyData = LCP_POLICY_DATA2()

ListMeasurements = ListMeasurements()         # DIGEST ListMeasurements[PDEF.NumLists]

try:
  import os
  import sys
except ImportError:
  raise ImportError, "import OS failed"

import array
import M2Crypto

from asn1spec import *


class Build( object ):
  """build LCP_POLICY2 and LCP_POLICY_DATA2 Files"""

  filename = "MyPlatformXXXXXXXXXXXXX"
  dirname  = os.getcwd()

  def __init__( self ):
    """Build - constructor"""
    pass

  # Build the .pol file
  # returns True if all went ok
  # returns False on error
  def buildRawLcpPolicyFile(self, pdef, statusBar):
    """buildRawLcpPolicyFile - build the raw format LCP_POLICY2 file (.pol)"""

    self.StatusBar = statusBar

    # if policy version is 3.0, clear bit positions for ignore PS elements
    policyversion = str(pdef.PolVersionMajor)+'.'+str(pdef.PolVersionMinor)
    if policyversion == '3.0':
      mask = DEFINES.PolicyControlIgnorePsMleBitMask | DEFINES.PolicyControlIgnorePsPconfBitMask | DEFINES.PolicyControlIgnorePsStmBitMask
      pdef.PolicyControl &= ~mask

    # pack the LCP_POLICY2 struct [without the hash] into a binary string ready for the LCP_POLICY2 file
    packedLcpPolicy = pack(LcpPolicy.LcpPolicyFormatStringNoHash,
                     pdef.PolVersionMinor, pdef.PolVersionMajor,
                     pdef.HashAlg, pdef.PolicyType, pdef.SinitMinVersion,
                     pdef.DataRevocationCounters[0], pdef.DataRevocationCounters[1],
                     pdef.DataRevocationCounters[2], pdef.DataRevocationCounters[3],
                     pdef.DataRevocationCounters[4], pdef.DataRevocationCounters[5],
                     pdef.DataRevocationCounters[6], pdef.DataRevocationCounters[7],
                     pdef.PolicyControl,
                     pdef.MaxSinitMinVersion, pdef.MaxBiosMinVersion,
                     pdef.LcpHashAlgMask, pdef.LcpSignAlgMask, pdef.AuxHashAlgMask, 0)

    # reuse the base name [with .pol extension] and don't prompt for a file name again
    basefilename, ext = self.filename.rsplit('.', 1)
    #polfilename = utilities.formFileName(basefilename, "pol")
    polfilename = ".".join([basefilename, 'pol'])
    print("buildRawLcpPolicyFile:  creating Text LCP_POLICY file %s" % (polfilename))  # DBGDBG

    # write the raw LCP_POLICY file
    #   1st write the struct, then write the hash from pdef.PolicyHash
    try:
      f = open(os.path.join(self.dirname, polfilename), 'wb')
      print(packedLcpPolicy,     end='', file=f )             # suppress EOL (0x0a)

      try:
        # reverse lookup of the hash algorithm name(key) for the given HashAlg value
        hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == pdef.HashAlg)).next()

        # If PolicyType==ANY, haven't updated pdef.PolicyHash (since there were no lists to process)
        # In that case, write a hash of all 0's
        if(pdef.PolicyType == DEFINES.ANY):
          # Pack hash value which is 0 for PolicyType of ANY
          b = bytes()
          pdef.PolicyHash = b.join(pack('B', 0) for i in range(DEFINES.DIGEST_SIZE[hashAlgName]))
        else:
          # Write packed hash value to .pol file.
          print(pdef.PolicyHash, end='', file=f )

      except StopIteration:
        # pdef.HashAlg value is not found in DEFINES.TPM_ALG_HASH list
        self.StatusBar.SetStatusText("Aborting build, Hash Algorithm %d is not supported." % (pdef.HashAlg))
        print("buildRawLcpPolicyFile: ANY - aborting - Hash Algorithm %d is not supported." % (pdef.HashAlg))  # DBGDBG
        f.close()
        return False

      # If PolicyType==ANY, haven't updated pdef.PolicyHash (since there were no lists to process)
      # In that case, write a hash of all 0's
      #if(pdef.PolicyType == DEFINES.ANY):
      #  # Pack hash value which is 0 for PolicyType of ANY
      #  if (hashAlgName != None):
      #    b = bytes()
      #    pdef.PolicyHash = b.join(pack('B', 0) for i in range(DEFINES.DIGEST_SIZE[hashAlgName]))
      #  else:
      #    self.StatusBar.SetStatusText("Aborting build, Hash Algorithm %d is not supported." % (pdef.HashAlg))
      #    print("buildRawLcpPolicyFile: ANY - aborting - Hash Algorithm %d is not supported." % (pdef.HashAlg))  # DBGDBG
      #    f.close()
      #    return False
          
        #if(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA1']):
        #  pdef.PolicyHashSha1   = pack("20B", 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        #elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA256']):
        #  pdef.PolicyHashSha256 = pack("32B", 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        #elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA384']):
        #  pdef.PolicyHashSha384 = pack("40B", 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        #elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SM3']):
        #  pdef.PolicyHashSm3    = pack("32B", 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        #else:
        #  self.StatusBar.SetStatusText("Aborting build, Hash Algorithm %d is not supported." % (pdef.HashAlg))
        #  print("buildRawLcpPolicyFile: ANY - aborting - Hash Algorithm %d is not supported." % (pdef.HashAlg))  # DBGDBG
        #  f.close()
        #  return False

      
      # Pack hash value which is 0 for PolicyType of ANY
      #if (hashAlgName != None):
      #  # Write packed hash value to .pol file.
      #  print(pdef.PolicyHash, end='', file=f )
      #else:     # don't hit the above else case if policyType=LIST
      #    self.StatusBar.SetStatusText("Aborting build, Hash Algorithm %d is not supported." % (pdef.HashAlg))
      #    print("buildRawLcpPolicyFile: LIST - aborting - Hash Algorithm %d is not supported." % (pdef.HashAlg))  # DBGDBG
      #    f.close()
      #    return False
      #if(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA1']):
      #  print(pdef.PolicyHashSha1, end='', file=f )
      #elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA256']):
      #  print(pdef.PolicyHashSha256, end='', file=f )
      #else:     # don't hit the above else case if policyType=LIST
      #    self.StatusBar.SetStatusText("Aborting build, Hash Algorithm %d is not supported." % (pdef.HashAlg))
      #    print("buildRawLcpPolicyFile: LIST - aborting - Hash Algorithm %d is not supported." % (pdef.HashAlg))  # DBGDBG
      #    f.close()
      #    return False

    except IOError:
      print ("IOError writing raw LCP_POLICY file %s" % (polfilename))
    finally:
      f.close()

    print("buildRawLcpPolicyFile:  Raw LCP_POLICY file %s built" % (polfilename))  # DBGDBG

    # originally, filename had no extention so strip it off
    #self.filename, ext = self.filename.rsplit('.', 1)
    return True

  def buildTxtLcpPolicyFile(self, pdef):
    """buildTxtLcpPolicyFile - build the text format LCP_POLICY2 file"""

    # reuse the base name [with .txt extention] and don't prompt for a file name again
    basefilename, ext = self.filename.rsplit('.', 1)
    txtfilename = utilities.formFileName(basefilename, "txt")
    #self.filename = utilities.formFileName(self.filename, "txt")
    print("buildTxtLcpPolicyFile:  creating Text LCP_POLICY2 file %s" % (txtfilename))  # DBGDBG

    try:
      f = open(os.path.join(self.dirname, txtfilename), 'w')

      # suppress separator with sep=''
      # use 'fmt' % (value) to prepend 0's to value

      print("#Policy Data", file=f)

      version = '%02d%02d' % (pdef.PolVersionMajor, pdef.PolVersionMinor)
      print("word=", version, "\t\t# Version", sep='', file=f)

      hashAlg = '%04d' % (pdef.HashAlg)
      print("word=", hashAlg, "\t\t# Hash Alg (4=Sha1[20], 11=Sha256[32]", sep='', file=f)

      policyType = '%02d' % (pdef.PolicyType)
      print("byte=", policyType, "\t\t\t# PolicyType (0 = LIST, 1 = ANY)", sep='', file=f)

      sinitMinVersion = '%02d' % (pdef.SinitMinVersion)
      print("byte=", sinitMinVersion, "\t\t\t# SinitMinVersion", sep='', file=f)

      i = 0
      while(i < pdef.MaxLists):
        dataRevCnt = '%04d' % (pdef.DataRevocationCounters[i])
        print("word=", dataRevCnt, "\t\t# DataRevocationCounters[", i, "]", sep='', file=f)
        i += 1

      policyControl = '0x%08x' % (pdef.PolicyControl)
      print("dword=", policyControl, "\t# PolicyControl (Bit 1=Allow NPW, 2=PCR17, 3=Force Owner 15=Aux Delete)", sep='', file=f)

      maxSinitMinVersion = '%02d' % (pdef.MaxSinitMinVersion)
      print("byte=", maxSinitMinVersion, "\t\t\t# MaxSinitMinVersion", sep='', file=f)
      maxBiosMinVersion = '%02d' % (pdef.MaxBiosMinVersion)
      print("byte=", maxBiosMinVersion, "\t\t\t# MaxBiosMinVersion", sep='', file=f)
      
      lcpHashAlgMask = '%04d' % (pdef.LcpHashAlgMask)
      print("word=", lcpHashAlgMask, "\t\t# LcpHashAlgMask", sep='', file=f)
      lcpSignAlgMask = '%04d' % (pdef.LcpSignAlgMask)
      print("dword=", lcpSignAlgMask, "\t\t# LcpSignAlgMask", sep='', file=f)
      auxHashAlgMask = '%04d' % (pdef.AuxHashAlgMask)
      print("word=", auxHashAlgMask, "\t\t# AuxHashAlgMask", sep='', file=f)

      reserved = '%02d' % (0)
      print("byte=", reserved, "\t\t\t# Reserved", sep='', file=f)
      
      #if(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA256']):
      #  print("byte=", pdef.PolicyHashSha256Hex, " # Hash", sep='', file=f)   # need to print the hex hash
      #elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA1']):
      #  print("byte=", pdef.PolicyHashSha1Hex,   " # Hash", sep='', file=f)   # need to print the hex hash
      print("byte=", binascii.b2a_hex(pdef.PolicyHash), " # Hash", sep='', file=f)   # need to print the hex hash
      
    except IOError:
      print ("IOError writing file %s" % (txtfilename))
    finally:
      f.close()

    print("buildTxtLcpPolicyFile:  Text LCP_POLICY file %s built" % (txtfilename))  # DBGDBG

    # originally, filename had no extention so strip it off
    #self.filename, ext = self.filename.rsplit('.', 1)

  # LCP2 does not generate an XML output file - so no buildXmlLcpPolicyFile()

  # If no error, return True, else False
  # Build can fail reading hash or pcr files, or if no public or private key file was selected
  #
  def buildLcpPolicyDataStruct(self, pdef, statusBar):
    """buildLcpPolicyDataStruct - create a LCP_POLICY_DATA struct including calculating the PolicyHash"""

    global LcpPolicyData

    self.StatusBar = statusBar
    #LcpPolicy = LCP_POLICY2()
    LcpPolicyData = LCP_POLICY_DATA2()
    # ListMeasurements - object to hold ListMeasurements[pdef.NumLists]
    # LcpPolicyData    - object for LCP_POLICY_DATA
    # build file header: FileSignature,0,0,0,NumLists
    LcpPolicyData.NumLists = pdef.NumLists

    print("buildLcpPolicyDataStruct: LCP_POLICY_DATA: FileSignature=%s, NumLists=%d" %
          (LcpPolicyData.FileSignature, LcpPolicyData.NumLists)) # DBGDBG

    # For each list
    #   If 1st list, build the list header: ListVersion, 0, SigAlgorithm, PolicyElementsSize=0
    #   build the elements
    #   if List is unsigned, hash the list
    #   else list is signed so build the signature block   ie:
    #   Done with this list
    # Done with all the lists
    policyElementsSize = 0            # cumulative size of all the elements in this list
    listCnt = 0
    listCntStr = str(listCnt)
    while(listCnt < pdef.NumLists):
      thisPdefList = pdef.PolListInfo[listCntStr]
      thisPolicyList = LcpPolicyData.PolicyLists[listCntStr]

      # build the LCP_POLICY_LIST.PolicyList[N] header from pdef.PolListInfo[N]
      thisPolicyList.VersionMajor = thisPdefList.ListVersionMajor
      thisPolicyList.VersionMinor = thisPdefList.ListVersionMinor
      thisPolicyList.SigAlgorithm = thisPdefList.SigAlgorithm
      thisPolicyList.PolicyElementsSize = 0            # TBD

      # if the list is signed, make sure that a public and private key file was specified
      # otherwise abort the build
      #if(thisPdefList.SigAlgorithm == DEFINES.LCP_POLSALG_RSA_PKCS_15):     # TODO: add external signature support
      #if(thisPdefList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']):
      if thisPdefList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['NULL']:
        # Not Signing..
        pass
      elif thisPdefList.SigAlgorithm in DEFINES.TPM_ALG_SIGN.values():
        if((thisPdefList.PubKeyFile == "") or (thisPdefList.PvtKeyFile == "") and not thisPdefList.PvtKeyFileIsSignature):
          self.StatusBar.SetStatusText("Build failed: does not have both a public and private key file selected")
          print("buildLcpPolicyDataStruct failed - see status bar") # DBGDBG
          return False
      else:
        # What about invalid signature algorithms.
        print("ERROR: undefined signature algorithm")
        pass

      #IncludeElement = utilities.getIncludeElement(thisPdefList)
      #i=0
      #flag = False
      #while(i < len(IncludeElement)):
      #  if(IncludeElement[i] == True):
      #    flag = True
      #  i += 1

      # if there are elements to build, then build them and update PolicyElementsSize
      #if(flag == True):
      if len(thisPdefList.ElementDefData):
        thisPolicyList.PolicyElementsSize = self.buildListElements(pdef, thisPdefList, thisPolicyList, listCnt)
        # check for errors building the elements, i.e. reading the hash or pcr files
        if(thisPolicyList.PolicyElementsSize == 0):
          print("buildLcpPolicyDataStruct failed: PolicyElementsSize=0")  # DBGDBG
          return False

      if not self.hashListOrBuildSignatureBlock(pdef, thisPdefList, thisPolicyList, listCnt):
        return False
      print("buildLcpPolicyDataStruct: LCP_POLICY_LIST: Version=%x.%x, SigAlgorithm=%d, PolicyElementsSize=%d" %
          (thisPolicyList.VersionMajor, thisPolicyList.VersionMinor,
           thisPolicyList.SigAlgorithm, thisPolicyList.PolicyElementsSize)) # DBGDBG

      thisPdefList.ListModified = False
      listCnt += 1
      listCntStr = str(listCnt)

    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == pdef.HashAlg)).next()
    except StopIteration:
      print("Aborting build, Hash Algorithm %d is not supported" % (pdef.HashAlg))
      return False

    # Calculate list measurements - hash ListMeasurements[] using pdef.HashAlg

    hash = M2Crypto.EVP.MessageDigest(hashAlgName.lower())

    listCnt = 0
    while(listCnt < pdef.NumLists):
      #if(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA1']):
      #  thisHash = ListMeasurements.hashes[str(listCnt)]
      #elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH['SHA256']):
      #  thisHash = ListMeasurements.hashes32[str(listCnt)]
      thisHash = ListMeasurements.hashes[str(listCnt)]
      
      hash.update(bytes(thisHash))
      #print("buildLcpPolicyDataStruct: ListMeasurement[%d] hash=%s" % (listCnt, thisHash)) # DBGDBG
      print("buildLcpPolicyDataStruct: ListMeasurement[%d] hashed" % (listCnt)) # DBGDBG
      listCnt += 1

    # save to pdef.PolicyHash
    pdef.PolicyHash = hash.digest()

    #print("buildLcpPolicyDataStruct - hash size=%d hexdigest=%s" % (hash.digest_size, hash.hexdigest()))   # DBGDBG
    pdef.Modified = False
    return True

  # Build the elements and return their size
  # If an error occurred, size = 0
  # Build can fail reading hash or pcr files
  #
  def buildListElements(self, pdef, thisPdefList, thisPolicyList, listCnt):
    """buildElements - build this lists elements"""
    func = 'buildListElements'

    print("%s: list %d - MLE, PCONF then SBIOS" % (func, listCnt))  # DBGDBG
    policyElementsSize = 0
    thisElementSize = 0

    # Sort element in this order [MLE, STM, SBIOS, PCONF] from [SHA512... SHA1, SHA1-LEGACY]
    sortedPdefList = []
    mlelist = [element for element in thisPdefList.ElementDefData if 'MLE' in element.Name]
    sortedPdefList += sorted(mlelist, key=lambda x: x.HashAlg, reverse=True)
    stmlist = [element for element in thisPdefList.ElementDefData if 'STM' in element.Name]
    sortedPdefList += sorted(stmlist, key=lambda x: x.HashAlg, reverse=True)
    sbioslist = [element for element in thisPdefList.ElementDefData if 'SBIOS' in element.Name]
    sortedPdefList += sorted(sbioslist, key=lambda x: x.HashAlg, reverse=True)
    pconflist = [element for element in thisPdefList.ElementDefData if 'PCONF' in element.Name]
    sortedPdefList += sorted(pconflist, key=lambda x: x.HashAlg, reverse=True)

    elementCnt = 0
    for element in sortedPdefList:
      print("building Element %s" %(element.Name))
      # call the element's build function to build the elements of this policy
      thisElementSize = element.build(thisPdefList, thisPolicyList.PolicyElements, pdef.WorkingDirectory)
      policyElementsSize += thisElementSize
      elementCnt += 1

    print("%s: list %d - elementCnt=%d, policyElementsSize=0x%x" % (func, listCnt, elementCnt, policyElementsSize)) # DBGDBG
    return(policyElementsSize)


  # Build the .dat file
  def buildLcpPolicyDataFile(self, pdef):
    """buildLcpPolicyDataFile - build the LCP_POLICY_DATA2 file (.dat)"""
    func = 'buildLcpPolicyDataFile'

    # reuse the base name [with .dat extention] and don't prompt for a file name again
    basefilename, ext = self.filename.rsplit('.', 1)
    datfilename = utilities.formFileName(basefilename, "dat")
    #self.filename = utilities.formFileName(self.filename, "dat")
    #lcpPolicyDataHeader = self.packLcpPolicyDataHeader()
    lcpPolicyDataHeader = LcpPolicyData.pack()

    # write the LCP_POLICY_DATA header to the .dat file: f
    # write the data to be signed to tmpFile: tmp
    #
    tmpFile = "tmpLcpPolicyList.tmp"
    try:
      f   = open(os.path.join(self.dirname, datfilename), 'wb')
      print(lcpPolicyDataHeader, end='', file=f )             # suppress EOL (0x0a)
    except IOError:
      self.StatusBar.SetStatusText("IOError writing raw LCP_POLICY_DATA file %s" % (datfilename))
      return

    # For each List in LcpPolicyData.PolicyLists[]
    print("buildLcpPolicyDataFile:  creating LCP_POLICY_DATA file %s" % (datfilename))  # DBGDBG
    listCnt = 0
    listCntStr = str(listCnt)
    while(listCnt < pdef.NumLists):
      try:
        tmp = open(os.path.join(self.dirname, tmpFile), 'wb')
      except IOError:
        self.StatusBar.SetStatusText("IOError opening tempFile %s" % (tmpFile))
        return
      print("buildLcpPolicyDataFile: processing list %d of %d" % (listCnt, pdef.NumLists)) # DBGDBG
      thisPolicyList = LcpPolicyData.PolicyLists[listCntStr]
      #lcpPolicyListHeader = self.packLcpPolicyListHeader(thisPolicyList)
      lcpPolicyListHeader = thisPolicyList.pack()

      # There can be 1 element of each type of each hash algorithm, See LCP_POLICY_LIST2::PolicyElements[]
      lcpPolicyListElement = [None, None, None, None, None, None, None, None]

      # pack this list's elements, if they exist
      i=0
      numElements = len(thisPolicyList.PolicyElements)
      while(i < numElements):
        #print("%s - checking if PolicyElement %d of %d exists" % (func, i, numElements)) # DBGDBG
        if(thisPolicyList.PolicyElements[i] != None):
          print("%s - packing PolicyElement %d of %d" % (func, i, numElements)) # DBGDBG
          #lcpPolicyListElement[i] = self.packLcpPolicyElement(pdef, str(listCnt), i, thisPolicyList.PolicyElements[i])
          lcpPolicyListElement[i] = thisPolicyList.PolicyElements[i].pack()
        else:
          break             # done after all existing elements are packed
        i += 1

      # write this LCP_POLICY_LIST to the .dat file
      #   1st write the LcpPolicyListHeader,
      #   then write the elements and optionally the signature (if list is signed)
      #
      try:
        print(lcpPolicyListHeader, end='', file=f )
        print(lcpPolicyListHeader, end='', file=tmp )
        # print the this list's elements, if they exist
        i=0
        while(i < numElements):
          #print("%s - checking if PolicyElement %d of %d was packed" % (func, i, numElements)) # DBGDBG
          if(lcpPolicyListElement[i] != None):
            print("%s - writing PolicyElement %d of %d to the file" % (func, i, numElements)) # DBGDBG
            print(lcpPolicyListElement[i], end='', file=f )
            print(lcpPolicyListElement[i], end='', file=tmp )
          i += 1

      except IOError:
        print ("IOError writing raw LCP_POLICY_DATA file %s" % (datfilename))
        f.close()
        return

      # if list is signed, now that we have formed all the binary data, it can be signed
      # and the LCP_SIGNATURE object can be written to the file
      #
      # The RSA signature is calculated over the entire LCP_POLICY_LIST struct,
      # including the Signature member, EXCEPT for the SigBlock
      #
      #if(thisPolicyList.SigAlgorithm == DEFINES.LCP_POLSALG_RSA_PKCS_15):
      if(thisPolicyList.SigAlgorithm != DEFINES.TPM_ALG_SIGN['NULL']):
        print("buildLcpPolicyDataFile: sign list %d" % (listCnt)) # DBGDBG
        self.signThisList(pdef, listCntStr, thisPolicyList, f, tmp, tmpFile)

      listCnt += 1
      listCntStr = str(listCnt)

    f.close()
    print("buildLcpPolicyDataFile:  LCP_POLICY_DATA file %s built" % (datfilename))  # DBGDBG


  def signThisList(self, pdef, listCntStr, thisPolicyList, f, tmp, tmpFile):
    """signThisList - form the signature of the specified list and write it to the specified files"""

    # get the private key from its file
    thisPdefList = pdef.PolListInfo[listCntStr]

    signAlgStr = ""
    try:
      signAlgStr = (key for key,val in DEFINES.TPM_ALG_SIGN.items() if val == thisPdefList.SigAlgorithm).next()
    except StopIteration:
      print ("Unsupported signature algorithm (%d)" %(thisPdefList.SigAlgorithm))
      return

    # pack the LCP_SIGNATURE2 object except for the PublicKeyValue and SigBlock and write it to the file
    # those 2 member's size depends on keySize so they are written separately
    lcpSignature = thisPolicyList.Signature.pack()
    print(lcpSignature, end='', file=f )
    print(lcpSignature, end='', file=tmp )

    # Append Public key to signature block.
    if 'RSA' in signAlgStr:
      print(thisPolicyList.Signature.PubkeyValue, end='', file=f)
      print(thisPolicyList.Signature.PubkeyValue, end='', file=tmp)
    else:
      # ECC
      print(thisPolicyList.Signature.Qx, end='', file=f)
      print(thisPolicyList.Signature.Qx, end='', file=tmp)
      print(thisPolicyList.Signature.Qy, end='', file=f)
      print(thisPolicyList.Signature.Qy, end='', file=tmp)
    tmp.close()               # done writing to tmp

    # read back the list data from the tmp file so it can be hashed and signed
    tmp = open(os.path.join(self.dirname, tmpFile), 'rb')
    tmp.seek (0, os.SEEK_END)
    listFileSize = tmp.tell ()
    tmp.seek (0, os.SEEK_SET)           # back to the beginning
    tmpListData = array.array ("B")     # Load file into data array
    try:
      tmpListData.fromfile (tmp, listFileSize)
    except:
      self.StatusBar.SetStatusText("Error reading list data from tmp file")
      print("signThisList:  ******Error reading list data from tmp file!!!!!!" )  # DBGDBG ******
      tmp.close()
      return

    tmp.close()

    print("signThisList:  hashing %d bytes from %s" % (listFileSize, tmpFile))  # DBGDBG
    # hash the list and sign the hash
    signatureBE = None
    hashAlgName = ""
    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == thisPdefList.sigAlgorithmHash)).next()
    except StopIteration:
      self.StatusBar.SetStatusText("Aborting build, Hash Algorithm %d is not supported." % (thisPdefList.sigAlgorithmHash))
      print("signThisList: aborting - Hash Algorithm %d is not supported." % (thisPdefList.sigAlgorithmHash))  # DBGDBG
      return

    h = None      # set hash value to null first
    MsgDigest = M2Crypto.EVP.MessageDigest(hashAlgName.lower())
    MsgDigest.update(tmpListData)
    h = MsgDigest.digest()

    # Output hash for each list to a file for CA signing
    basefilename, ext = self.filename.rsplit('.', 1)
    hashfilename = basefilename + '_list' + listCntStr + '.hash'
    hashout = open(os.path.join(self.dirname, hashfilename), 'wb')
    hashout.write(h)
    hashout.close()
    # Output list raw binary output to a file for CA hashing and signing
    listbinfilename = basefilename + '_list' + listCntStr + '.bin'
    listbinout = open(os.path.join(self.dirname, listbinfilename), 'wb')
    listbinout.write(tmpListData)
    listbinout.close()


    # Write signature data.
    if thisPdefList.PvtKeyFileIsSignature:
      sig_str = ""
      if thisPdefList.PvtKeyFile != "":
        # Load signature using the file in private key
        fsig = open(os.path.join(self.dirname, thisPdefList.PvtKeyFile), 'rb')
        fsig.seek(0, 2)
        size = fsig.tell()
        fsig.seek(0, 0)
        sig_array = array.array('B')
        sig_array.fromfile(fsig, size)
        sig_str = sig_array.tostring()
        fsig.close()
      else:
        # if no file defined, then it's the first pass, before the list is signed by certificate authority(CA)
        pass

      if 'RSA' in signAlgStr:

        signatureBE = sig_str
        # byte reverse the signature, i.e. convert from big to little-endian
        signatureLE = signatureBE[::-1]
        thisPolicyList.Signature.SigBlock = signatureLE
        #print("signThisList:  LCP_POLICY_LIST %d sigLen=0x%x sig=\n%s" % (listCnt, len(signature), signature))  # DBGDBG

        # write the LCP_SIGNATURE.SigBlock object to the file
        print(signatureLE, end='', file=f )
        print("signThisList: Finished writing signature for list %d" % (int(listCntStr))) # DBGDBG
      else:
        # ECC signatures
        signature, substrate = der_decoder.decode(sig_str, asn1Spec=ECDSASignature())

        ri = signature.getComponentByName('r')
        si = signature.getComponentByName('s')

        roctet = univ.OctetString(hexValue=format(int(ri), '0x'))
        soctet = univ.OctetString(hexValue=format(int(si), '0x'))

        rBE = roctet.asNumbers()
        sBE = soctet.asNumbers()

        rLE = rBE[::-1]
        sLE = sBE[::-1]
        thisPolicyList.Signature.r = rLE
        thisPolicyList.Signature.s = sLE
        # write the LCP_SIGNATURE.SigBlock object to the file
        print(rLE, end='', file=f )
        print(sLE, end='', file=f )

    else:
      # Read Private Key from file
      # then sign the list
      #key = RSA.importKey(open(os.path.join(self.dirname, thisPdefList.PvtKeyFile)).read())
      key = None
      mb = None
      with open(os.path.join(self.dirname, thisPdefList.PvtKeyFile), 'rb') as kf:
        mb = M2Crypto.BIO.MemoryBuffer(kf.read())
      if mb:
        if 'RSA' in signAlgStr:
          key = M2Crypto.RSA.load_key_bio(mb)
        elif 'EC' in signAlgStr:
          # if ECC algorithm
          key = M2Crypto.EC.load_key_bio(mb)
      else:
        print("DEBUG: error load key")
      kf.close()

      #print("signThisList:  LCP_POLICY_LIST %s pvt key=\n%s" % (listCntStr, key))  # DBGDBG

      if 'RSA' in signAlgStr:
        #signer = PKCS1_v1_5.new(key)
        #signatureBE = signer.sign(h)
        signatureBE = key.sign(h, hashAlgName.lower())
        # byte reverse the signature, i.e. convert from big to little-endian
        signatureLE = signatureBE[::-1]
        thisPolicyList.Signature.SigBlock = signatureLE
        #print("signThisList:  LCP_POLICY_LIST %d sigLen=0x%x sig=\n%s" % (listCnt, len(signature), signature))  # DBGDBG

        # write the LCP_SIGNATURE.SigBlock object to the file
        print(signatureLE, end='', file=f )
      else:
        # ECC signatures
        r, s = key.sign_dsa(h)
        #print("DEBUG: ECC signature size r(%d) s(%d)" %(len(rBE), len(sBE)))

        length = int(thisPdefList.KeySize)/8
        rBE = r[-length:]
        sBE = s[-length:]
        rLE = rBE[::-1]
        sLE = sBE[::-1]
        thisPolicyList.Signature.r = rLE
        thisPolicyList.Signature.s = sLE
        # write the LCP_SIGNATURE.SigBlock object to the file
        print(rLE, end='', file=f )
        print(sLE, end='', file=f )

    print("signThisList: Finished writing signature for list %d" % (int(listCntStr))) # DBGDBG


  def packLcpSignatureHdr(self, lcpSignature):
    """packLcpSignature - pack this LCP_SIGNATURE object except its SigBlock member ad return the packed data"""

    # Note - The public key size in the pdef is the number of bits (1024, 2048, 3072)
    #        while LCP_SIGNATURE.PublicKeySize is the number if bytes, hence the /8 below
    return(pack(lcpSignature.LcpSignatureHdrFormatString,
                lcpSignature.RevocationCounter, lcpSignature.PubkeySize/8))

  def hashListOrBuildSignatureBlock(self, pdef, thisPdefList, thisPolicyList, listCnt)  :
    """hashListOrBuildSignatureBlock - if list unsigned then hash it, if signed build the signature block"""

    #print("hashListOrBuildSignatureBlock") # DBGDBG

    if(thisPdefList.SigAlgorithm in DEFINES.TPM_ALG_SIGN.values()):
      #if(thisPdefList.SigAlgorithm == DEFINES.LCP_POLSALG_NONE):
      if(thisPdefList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['NULL']):
        if(not self.hashThisList(pdef, thisPdefList, thisPolicyList, listCnt)):
           return False
      #elif(thisPdefList.SigAlgorithm == DEFINES.LCP_POLSALG_RSA_PKCS_15):
      #elif(thisPdefList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']):
      else:
        # Get the key from the file again in case it was replaced
        type = DEFINES.KEY_FILE_TYPE['PUBLIC_RSASSA']
        # once the entire file name is entered, verify it, else clear it
        if(thisPdefList.PubKeyFile.endswith(".pem")):
          if thisPdefList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']:
            type = DEFINES.KEY_FILE_TYPE['PUBLIC_RSASSA']
          elif thisPdefList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['ECDSA']:
            type = DEFINES.KEY_FILE_TYPE['PUBLIC_ECDSA']
        pubkeyfile = os.path.join(self.dirname, thisPdefList.PubKeyFile)
        if not utilities.verifyKeyFile(pubkeyfile, type, thisPdefList):
          print("Invalid Public Key file %s" %(thisPdefList.PubKeyFile))
          return False
        self.createSignatureBlock(pdef, thisPdefList, thisPolicyList, listCnt)
    else:
      self.StatusBar.SetStatusText("hashListOrBuildSignatureBlock: aborting unknown pdef.SigAlgorithm=%x" % (thisPdefList.SigAlgorithm))
      return False

    return True

  def hashThisList(self, pdef, thisPdefList, thisPolicyList, listCnt):
    """hashThisList - when building an unsigned list, calcuate its hash"""
    func = 'hashThisList'

    print("%s: list %d of %d" % (func, listCnt+1, pdef.NumLists))

    # for each list in PolicyLists[]
    #   hash the list header
    #   hash the list's PolicyElements[]
    #   copy the hash to ListMeasurements[i]
    # Note: hash of the 1st list does NOT include the hash of the LCP_POLICY_DATA header

    try:
      hashAlgString = (key for key,val in DEFINES.TPM_ALG_HASH.items() if val == pdef.HashAlg).next()
    except StopIteration:
      self.StatusBar.SetStatusText("Hash Algorithm %d is not supported." % (pdef.HashAlg))
      print("%s: HashAlg %d is not supported" % (func, pdef.HashAlg))
      return False

    if hashAlgString == 'NULL':
      # Nothing to do
      return True
    else:
      hash = M2Crypto.EVP.MessageDigest(hashAlgString.lower())

    #lcpPolicyListHeader = self.packLcpPolicyListHeader(thisPolicyList)
    lcpPolicyListHeader = thisPolicyList.pack()
    hash.update(lcpPolicyListHeader)

    # hash this list's PolicyElements[], if they exist
    # Note: if list has no elements just hash the PolicyList header
    i=0
    numElements = len(thisPolicyList.PolicyElements)
    while(i < numElements):
      print("%s - checking if PolicyElement %d of %d exists" % (func, i, numElements)) # DBGDBG
      if(thisPolicyList.PolicyElements[i] != None):
        print("%s - packing PolicyElement %d of %d" % (func, i, numElements)) # DBGDBG
        #lcpPolicyListElement = self.packLcpPolicyElement(pdef, str(listCnt), i, thisPolicyList.PolicyElements[i])
        lcpPolicyListElement = thisPolicyList.PolicyElements[i].pack()
        hash.update(lcpPolicyListElement)
      else:
        break             # done after all existing elements are packed
      i += 1

    ListMeasurements.hashes[str(listCnt)] = hash.digest()
    #print("hashThisList - ListMeasurements[%d] hash size=%d hexdigest=%s" %
    #         (listCnt, hash.digest_size, hash.hexdigest()))   # DBGDBG
    return True

  def createSignatureBlock(self, pdef, thisPdefList, thisPolicyList, listCnt):
    """createSignatureBlock - when building a signed list, form its signature block"""

    try:
      signAlgStr = (key for key,val in DEFINES.TPM_ALG_SIGN.items() if val == thisPolicyList.SigAlgorithm).next()
    except StopIteration:
      print ("ERROR, Signing algorithm not supported (%d)" %(thisPolicyList.SigAlgorithm))
      return

    if 'RSA' in signAlgStr:
      # Create signature block for RSA signature structure
      thisPolicyList.Signature = LCP_RSA_SIGNATURE()
      #  Copy public key to Policy data structure
      thisPolicyList.Signature.PubkeyValue = thisPdefList.PubKeyData
    else:
      # Create signature block for ECC signature structure
      thisPolicyList.Signature = LCP_ECC_SIGNATURE()
      #  Copy public key to Policy data structure
      thisPolicyList.Signature.Qx = thisPdefList.PubKeyQx
      thisPolicyList.Signature.Qy = thisPdefList.PubKeyQy

    # Copy other common parameters

    #  RevocationCounter = PDEF.PolListInfo[i].RevocationCounter
    #  Note: Code differs from the tool spec algorithm in section 5.3.1 p19 as follows:
    #       - List Revocation Counters are incremented on the 1st change after a build, not here
    #       - RevokeCounter is sync'd to Revocation counter in list.onBuildButtonClick() not here
    thisPolicyList.Signature.RevocationCounter = thisPdefList.RevocationCounter

    #  PubkeySize = PDEF.PolListInfo[i].PubkeySize
    thisPolicyList.Signature.PubkeySize = int(thisPdefList.KeySize)
    print("createSignatureBlock - RevocationCounter=%d, keySize=%d per PDEF KeySize=%s" %
          (thisPolicyList.Signature.RevocationCounter, thisPolicyList.Signature.PubkeySize, thisPdefList.KeySize))       # DBGDBG

    #  Calculate Hash of public key using PDEF,HashAlg
    #  Copy to ListMeasurements[i]

    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgStr = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == pdef.HashAlg)).next()
    except StopIteration:
      self.StatusBar.SetStatusText("Hash Algorithm is not supported, (pdef.HashAlg=%d)" % (pdef.HashAlg))
      return

    hash = M2Crypto.EVP.MessageDigest(hashAlgStr.lower())
    if 'RSA' in signAlgStr:
      hash.update(thisPolicyList.Signature.PubkeyValue)
    else:
      hash.update(thisPolicyList.Signature.Qx)
      hash.update(thisPolicyList.Signature.Qy)
    digest = hash.digest()
    ListMeasurements.hashes[str(listCnt)] = digest

    #  Build SigBlock[PubkeySize]
    #    Calculate hash of LIST using PDEF,HashAlg
    #    Encrypt hash using private key [ie Sign it]
    #       A.2.1 - For a signed list, the RSA signature is calculated over the entire LCP_POLICY_LIST struct,
    #         including the Signature member, EXCEPT for the SigBlock
    #    Copy encrypted hash to policy data structure LCP_SIGNATURE.SigBlock
    #  Done with signature

        # NOTE: The list is signed later, and the signature copied to LCP_SIGNATURE.SigBlock
        #       when the list is written to its .dat file in buildLcpPolicyDataFile()
        #       since that is when the 'signable' binary data is packed
        #       [vs. the Python object form of the data available here]


  # the last function in the file doesn't show up in the scope list in Understand for some reason!
  def stub(self):
    pass
