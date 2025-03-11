#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# using print() built infunction, disable print statement
from __future__ import print_function

try:
  import os, sys
except ImportError:
  raise ImportError, "import OS failed"

from defines import DEFINES
from struct import pack, unpack
import array
import M2Crypto

from asn1spec import *

# utility routines
class UTILS( object ):

  def checkFileTag(self, file, expectedTag):
    """checkFileTag - Return True if the specified file starts with the specified tag, else False"""

    # expectedTag either:
    #         PCRD+TAG = "PCRD" for .pcr files
    #         HASH_TAG = "HASH" for .hash files
    # read the 1st 4 bytes from the file (i.e. the actualTag) and compare that to the expectedTag
    #
    tagLength = 4
    myFile = open(file, "rb")
    actualTag = myFile.read(tagLength)
    myFile.close()
    #print("UTILS::checkFileTag: file=%s expectedTag=%s actualTag=%s" % (file, expectedTag, actualTag)) # DBGDBG

    if(actualTag == expectedTag):
      return True
    else:
      return False

  def invalidHashFileMsg(self, file, actHashAlg, expHashAlg, hashFileLength):
    """invalidHashFileMsg - display status bar msg if hash file is invalid"""

    print ("Invalid hash format for this element's HashAlg. file %s, Exp Alg=%d, Act Alg=%d, Length=%d" %
              (file, expHashAlg, actHashAlg, hashFileLength))

  # Some functions, such as Wx's ListBox.ChangeValue() takes a string
  # But the data is stored as a list of strins
  # so form a single string containing everything in list
  def formStringFromListOfStrings(self, list):
    """formStringFromListOfStrings - return a single string formed from a list of strings"""

    string = ''
    index = 0
    for eachString in list:
      if(index != 0):               # if not the 1st entry, need a LF before the new entry
        string += "\n"
      string += eachString
      index += 1
      #print("thisString=%s, string=%s" % (eachString, string))

    return string

  def formFileName(self, base, ext):
    """formFileName - return name formed from base.ext"""

    seperator = '.'
    filenameList = [base, ext]
    return(seperator.join(filenameList))


  # return True if file verified and key was extracted, else False
  def verifyKeyFile(self, file, type, currentList):
    """verifyKeyFile - verify the key file and extract the key"""

    # Need currentList.KeySize and currentList.PubKeyQx
    key = self.getKeyFromFile(file, type)
    expectedKeySize = int(currentList.KeySize) / 8

    if type == DEFINES.KEY_FILE_TYPE['PUBLIC_ECDSA']:
      # ECC public key is two value of the key size
      match = len(key) == expectedKeySize *2
      if match:
        # key is flipped for little endian so the latter half is the Qx
        currentList.PubKeyQx = key[expectedKeySize:expectedKeySize*2]
        currentList.PubKeyQy = key[0:expectedKeySize]

    elif type == DEFINES.KEY_FILE_TYPE['PUBLIC_RSASSA']:
      match = len(key) == expectedKeySize
      if match:
        currentList.PubKeyData = key
    else:
      keylength = len(key)
      match = len(key) == expectedKeySize

    if not match:
      print("Key size mismatch actual=%d expected=%d" %(len(key), expectedKeySize))
    #if(type == KEY_FILE_TYPE_PRIVATE):
    #  expectedHeader = "-----BEGIN RSA PRIVATE KEY-----"
    #  expectedFooter = "-----END RSA PRIVATE KEY-----"
    #  expectedType = "Private"
    #elif(type == KEY_FILE_TYPE_PUBLIC):
    #  expectedHeader = "-----BEGIN PUBLIC KEY-----"
    #  expectedFooter = "-----END PUBLIC KEY-----"
    #  expectedType = "Public"
    #else:
    #  print("invalid key file parameter = %d specified" % (type)) # DBGDBG
    #  return False
    #
    #expHdrLen = len(expectedHeader)
    #try:
    #  f = open(file, "rb")
    #  actualHeader = f.read(expHdrLen)
    #except:
    #  self.StatusBar.SetStatusText("Error opening key file %s"  % (file))
    #  # open failed, can't close
    #  return False
    #
    #if(actualHeader == expectedHeader):
    #  self.StatusBar.SetStatusText("")      # clear any previous error msgs
    #else:
    #  self.StatusBar.SetStatusText("File %s is not a %s key file. Expected header %s" % (file, expectedType, expectedHeader))
    #  f.close()
    #  return False
    #
    ## key file header is OK
    ## read the rest of the file, including line endings
    ## then strip out the line endings and the footer
    ##     Expect Unix style line emdings: 0x0A"  per openssl .pem format
    ##     but also handle Windows style line endings: 0x0D, 0x0A
    ## max file length for keySize=3072 is <3072 since could have different
    ## number of characters on each line and different len endings (0A or 0D0A)
    ## just don't want to read in a [potentially very large] user specified file size
    #maxLength = 3072
    #f.seek (0, os.SEEK_END)
    #actualFileSize = f.tell() - expHdrLen - 1   # size of the rest of the file
    #if(actualFileSize < maxLength):
    #  maxLength = actualFileSize
    #
    ## read the base64 encoded data from the key file into a binary string
    #f.seek (expHdrLen+1, os.SEEK_SET)     # back to just after the header
    #try:
    #  rawData = f.read(maxLength)
    #except:
    #  self.StatusBar.SetStatusText("Error reading key data from file %s" % (file))
    #  f.close()
    #  return False
    #
    ##print("verifyKeyFile: read %d bytes:\n%s" % (len(rawData), rawData)) # DBGDBG
    ##print("verifyKeyFile: read %d" % (len(rawData))) # DBGDBG
    ## Verify the footer
    #if expectedFooter in rawData:
    #  self.StatusBar.SetStatusText("")      # clear any previous error msgs
    #else:
    #  self.StatusBar.SetStatusText("File %s is not a %s key file. Expected footer %s" %
    #                               (file, expectedType, expectedFooter))
    #  f.close()
    #  return False
    #
    ## strip off the footer
    #footerPos = rawData.find('-')    # find 1st '-'
    #rawData = rawData[0:footerPos-1]
    ##print("verifyKeyFile: w/o footer %d bytes:\n%s" % (len(rawData), rawData)) # DBGDBG
    ##print("verifyKeyFile: w/o footer %d bytes" % (len(rawData))) # DBGDBG
    #
    ## Verify that the file matches the current KeySize
    ##
    ## Key File sizes:     1024            2048              3072       for key + footer incl. LR/CR
    ## public file range:  240-260         420-440           590-610
    ## private file range: 850-870         1640-1685         2390-2430
    ##
    #keySize = self.keySizeEdit.GetValue()
    ##print("verifyKeyFile: keySize = %s, type = %s, .pem's length = %d" % (keySize, expectedType, maxLength))  # DBGDBG
    #currentList = self.pdef.getCurrentListObject()
    #misMatch = False
    #if(expectedType == "Public"):
    #  if(keySize == "1024"):
    #    if not ((240 <= maxLength) and (maxLength <= 260)):
    #      print("verifyKeyFile: Public key file, size not 1024!")  # DBGDBG
    #      misMatch = True
    #  elif(keySize == "2048"):
    #    if not ((420 <= maxLength) and (maxLength <= 440)):
    #      print("verifyKeyFile: Public key file, size not 2048!")  # DBGDBG
    #      misMatch = True
    #  elif(keySize == "3072"):
    #    if not ((590 <= maxLength) and (maxLength <= 610)):
    #      print("verifyKeyFile: Public key file, size not 3072!")  # DBGDBG
    #      misMatch = True
    #  if(misMatch == True):
    #    self.StatusBar.SetStatusText("Key size mismatch. File %s is not %s." % (file, keySize))
    #    self.pubKeyFileEdit.SetValue("")
    #    f.close()
    #    return False
    #  else:
    #    keyData = self.decodePublicKeyModulus(file, keySize, expectedHeader, expectedFooter)
    #    currentList.PubKeyData = keyData      # save the public key modulus
    #    #print("verifyKeyFile: Public Key. Length: %d. Data:\n%s" % (len(keyData), currentList.PubKeyData)) # DBGDBG
    #
    #elif(expectedType == "Private"):
    #  if(keySize == "1024"):
    #    if not ((850 <= maxLength) and (maxLength <= 870)):
    #      print("verifyKeyFile: Private key file, size not 1024!")  # DBGDBG
    #      misMatch = True
    #  elif(keySize == "2048"):
    #    if not ((1640 <= maxLength) and (maxLength <= 1685)):
    #      print("verifyKeyFile: Private key file, size not 20481")  # DBGDBG
    #      misMatch = True
    #  elif(keySize == "3072"):
    #    if not ((2390 <= maxLength) and (maxLength <= 2430)):
    #      print("verifyKeyFile: Private key file, size not 3072!")  # DBGDBG
    #      misMatch = True
    #  if(misMatch == True):
    #    self.StatusBar.SetStatusText("Key size mismatch. File %s is not %s." % (file, keySize))
    #    self.pvtKeyFileEdit.SetValue("")
    #    f.close()
    #    return False
    #  # Note: Don't need to save the private key data, pycrypto reads it from the file directly
    #
    #f.close()
    return match


  # Verify that the file is a valid HASH_FILE with a HASH_TAG, hashAlg and hashSize
  #     [with 1 or more SHA1 hashes]  - legacy support from the TPM1.2 LCP1 Spec
  # or a raw data file [i.e. no header] with ONLY 1 20 bit SHA1 or 32 bit SHA256 hash
  #
  # if OK, return a list containing: [True, HashFileModeXXX]  defined in defines.py
  # else return a list containing:   [False, HashFileModeNull]
  #     if file format or length is invalid
  #     or if the length indicates the hash does not correspond to the elements.HashAlg
  #
  #TODO: Bill: verifyHashFile- LCP2 spec  deletes the HASH_FILE struct def for files with multiple hashes??
  #TODO: Bill: verifyHashFile- still supporting files with multiple SHA1 hashes [with the hdr] or raw SHA1 or 256 files
  #
  def verifyHashFile(self, file, hashAlg):
    """verifyHashFile - return a list indicating if the file is valid and its type"""

    # HASH_FILE's are structured as:
    #   - SHA1 or SHA256 hash data only, for raw SHA1 or SHA256 files with 1 hash
    #   - SHA1 hash files with a header [defined below] containing 1 or more SHA1 hashes
    #
    #  Where the header is:
    #     HASH_TAG = 0x48534148 = "HASH"
    #     typedef struct {
    #       UINT32 tag HASH_TAG;          # 4 bytes  "HASH"
    #       UINT8 hashAlg ;               # 1 byte   SHA1_ALG = 4
    #       UINT8 hashSize ;              # 1 byte   SHA1 = 20
    #       UINT8 reserve[10] ;           # 12 bytes
    #       SHA1 - SHA256 hash ;          # 20 bytes
    #     } HASH_FILE;                    # ________
    #     File Size                       # 36 bytes
    # read the 1st 4 bytes from the file (i.e. the actualTag) and compare that to the expectedTag
    #
    function = "verifyHashFile"
    mode = DEFINES.HashFileMode['RawSHA256']    # default

    hashFileLengthHdrSha1   = 36    # header + SHA1 hash data
    hashFileLengthRawSha1   = DEFINES.DIGEST_SIZE['SHA1']    # raw hash files have only the hash data, no header
    hashFileLengthRawSha256 = DEFINES.DIGEST_SIZE['SHA256']
    #hashFileLengthRawSha384 = 48
    #hashFileLengthRawSha512 = 64

    try:
      f = open(file, "rb")
    except:
      print("Error opening hash file %s"  % (file))
      return [False, DEFINES.HashFileMode['HdrNull']]

    try:
      hashAlgStr = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
      if hashAlgStr == 'SHA1_LEGACY':
          hashAlgStr = 'SHA1'
    except StopIteration:
      print("Unsupported hash algorithm (%d)" %(hashAlg))
      return [False, DEFINES.HashFileMode['HdrNull']]

    #
    # check the file size to determine the type of file being read
    #
    f.seek (0, os.SEEK_END)
    actualSize = f.tell()

    if(actualSize == hashFileLengthHdrSha1):
      mode = DEFINES.HashFileMode['HdrSHA1']
      hashFileLength = hashFileLengthHdrSha1

      # read the data
      #
      f.seek (0, os.SEEK_SET)     # back to the begininng
      data = array.array ("B")   # Load file into data array
      try:
        data.fromfile (f, hashFileLength)
      except:
        print ("Error reading hash from file %s" % (file))
        f.close()
        return [False, DEFINES.HashFileMode['HdrNull']]

      if(hashAlg != DEFINES.TPM_ALG_HASH['SHA1'] and hashAlg != DEFINES.TPM_ALG_HASH['SHA1_LEGACY']):
        self.invalidHashFileMsg(file, hashAlg, DEFINES.TPM_ALG_HASH['SHA1'], hashFileLength)
        return [False, DEFINES.HashFileMode['HdrNull']]

      expectedHashTag = "HASH"        # 0x48415348
      expectedSha1HashAlg =  4          # '\x04'
      expectedSha1HashSize = 20         # '\x14'

      actualHashTag  = data[0:4].tostring()          # 0:3 inclusive = 0:4 exclusive of 4
      actualHashAlg  = data[4]
      actualHashSize = data[5]

      if(actualHashTag != expectedHashTag):
        # check if a raw file matching the element's HashAlg length
        print ("File: %s invalid tag = %s, expected %s" % (file, actualHashTag, expectedHashTag))
        return [False, DEFINES.HashFileMode['HdrNull']]

      if(actualHashAlg != expectedSha1HashAlg):
        print ("File: %s invalid hashAlg = 0x%x, expected 0x%x" %
              (file, actualHashAlg, expectedSha1HashAlg))
        return [False, DEFINES.HashFileMode['HdrNull']]

      if(actualHashSize != expectedSha1HashSize):
        print ("File: %s invalid hashSize = 0x%x, expected 0x%x" %
              (file, actualHashSize, expectedSha1HashSize))
        return [False, DEFINES.HashFileMode['HdrNull']]

    elif actualSize == DEFINES.DIGEST_SIZE[hashAlgStr]:
      modeStr = 'Raw' + hashAlgStr
      mode = DEFINES.HashFileMode[modeStr]
      hashFileLength = DEFINES.DIGEST_SIZE[hashAlgStr]
    else:
      self.invalidHashFileMsg(file, hashAlg, DEFINES.TPM_ALG_HASH[hashAlgStr], actualSize)
      print ("File: %s invalid size = %d, expected %d" % (file, actualSize, DEFINES.DIGEST_SIZE[hashAlgStr]))
      return [False, DEFINES.HashFileMode['HdrNull']]

    print("verifyHashFile - HashAlg=%d, Mode=%d, Len=%d" % (hashAlg, mode, hashFileLength)) # DBGDBG

    f.close()
    # handle SHA1 files with headers
    #if(mode == DEFINES.HashFileMode['HdrSHA1']):
    #
    #else:
    #  print("verifyHashFile - Error: invalid mode = %d, aborting." % (mode))
    #  return [False, DEFINES.HashFileMode['HdrNull']]

    return [True, mode]


  #     Determine the type of and validate the pcrFile, except for the numHashes field
  #     This includes checking that the file's type and hashAlg matches the element's expected HashAlg
  #     Return [True, PcrFileModePcrXShaYYY if ok,   see defines.py
  #            [False, PcrFileModeNull]     othewise
  #
  def verifyPcrFile(self, file, elementExpAlg):
    """verifyPcrFile - Validate the pcrFile"""

    # 2 types of PCR dump files are supported: PCRD and PCR2
    # PCR Dump File format
    #     typedef struct {
    #       UINT32 tag PCRD_TAG;          # 4 bytes  "PCRD" = 0x44524350
    #       UINT8 hashAlg ;               # 1 byte   SHA1_ALG = 4 SHA256_ALG = 0x0b
    #       UINT8 hashSize ;              # 1 byte   SHA1 = 20  SHA256 = 32
    #       UINT8 numHashes ;             # 1 byte   number of hashes in the file
    #       UINT8 reserve[9] ;            # 9 bytes
    #       SHA1 pcrs[24] ;               # 20 bytes * numHashes
    #     } HASH_FILE;                    # ________
    #  File Size                       # 16  + (NumHashes * HashSize) bytes
    #  Typically all 24 PCRs included  so size for SHA1 = 16 + 24*20 = 496 = 0x1f0
    #  LCP tool only requires the 1st 8 PCRs, if they are selected via pcr0to7SelectionBitMask
    #  I.e. if the bit mask 0-7 = 1 then that PCR is required
    #

    # - PCR2 PCR dump File format  - from App. C.1.2
    #     typedef struct {
    #       UINT32 tag PCR2_TAG;          # 4 bytes  "PCR2" = 0x32524350
    #       UINT16 hashAlg ;              # 2 bytes  TPM_ALG_SHAXXXXX
    #       UINT8 count ;                 # 1 byte   number of valid digests
    #       UINT8 reserve ;               # 1 byte
    #       UINT16 size ;                 # 2 bytes size of hash
    #     union {
    #       HASH20 pcrs[24] ;             # 20 bytes * 24 of which count are used per the pcrSelection mash
    #       HASH32 pcrs[24] ;             # 32 bytes * 24 of which count are used per the pcrSelection mash
    #     } HASH_FILE;                    # ________
    #  File Size                       # 8 + (count * HashSize) bytes, assuming no holes in the mask
    function = "verifyPcrFile"
    expectedPcrdTag = "PCRD"        # 0x44524350
    expectedPcr2Tag = "PCR2"        # 0x32524350

    try:
      f = open(file, "rb")
    except:
      print ("Error opening PCR data file %s" % (file))
      return [False, DEFINES.PcrFileMode['Null']]

    # Determine if this is a PCRD or PCR2 file
    # Based on the type, ensure the file's HaskAlg matches the element's ExpAlg
    f.seek (0, os.SEEK_SET)     # back to the begininng
    data = array.array ("B")    # Load file into data array
    try:
      data.fromfile (f, DEFINES.PCRFileMinHdrSize)
    except:
      print ("Error reading PCR data from file %s" % (file))
      f.close()
      return [False, DEFINES.PcrFileMode['Null']]

    try:
      elementExpAlgStr = (key for key,val in DEFINES.TPM_ALG_HASH.items() if val == elementExpAlg).next()
    except StopIteration:
      print ("Unsupported hash algorithm %d" %(elementExpAlg))

    fileHashTag  = data[0:4].tostring()          # 0:3 inclusive = 0:4 exclusive of 4
    numHashes = data[6]                          # PCRD 'numHashes' same as PCR2 'count'
    fileType = DEFINES.PcrFileMode['Null']
    if(fileHashTag == expectedPcrdTag):          # PCRD file
      fileType = DEFINES.PcrFileMode['PcrdSHA1']
      fileActualHashAlg  = data[4]               # HashAlg is a UINT8
      if(elementExpAlg != DEFINES.TPM_ALG_HASH['SHA1']):
        print ("%s file %s SHA1 hash algorithm does not match the PCONF element's expected algorithm: 0x%x" %
            (expectedPcrdTag, file, elementExpAlg))
        return [False, DEFINES.PcrFileMode['Pcrd']]
      else:
        actAlg = DEFINES.TPM_ALG_HASH['SHA1']    # LCP2 PCRD format only supports SHA1 per C.1.1
        minFileLength   = DEFINES.PCRDFileHdrSize + (8*DEFINES.DIGEST_SIZE['SHA1'])   # min PCRD SHA1   file has 8 hash's

    elif(fileHashTag == expectedPcr2Tag):        # PCR2 file
      # HashAlg in [4:5] is little endian so for current algs high byte=data[5]=0 and low byte=hashAlg
      fileActualHashAlg = unpack('<H', bytearray(data[4:6]))[0]
      #print("verifyPcrFile - elementExpAlg=%d, fileActualHashAlg=%x%x" % (elementExpAlg, fileActualHashAlgHi,fileActualHashAlgLow))  # DBGDBG
      if(elementExpAlg == fileActualHashAlg):
        actAlg = fileActualHashAlg
        fileType = DEFINES.PcrFileMode['Pcr2']
        minFileLength   = DEFINES.PCR2FileHdrSize + (8*DEFINES.DIGEST_SIZE[elementExpAlgStr])   # min PCR2 SHA1   file has 8 hash's
      else:
        print("%s file: %s hashAlg: 0x%x%x does not match the PCONF element's expected algorithm: 0x%02x" %
            (expectedPcr2Tag, file, data[4], data[5], elementExpAlg))
        return [False, DEFINES.PcrFileMode['Null']]

    else:
      print ("File: %s invalid tag = %s, expected %s or %s" % (file, fileHashTag, expectedPcrdTag, expectedPcr2Tag))
      return [False, DEFINES.PcrFileMode['Null']]

    print("verifyPcrFile: %s, tag=%s alg=%i, numHashes=%i" % (file, fileHashTag, actAlg, numHashes))   # DBGDBG

    # check the min file size
    f.seek (0, os.SEEK_END)
    actualFileSize = f.tell ()
    if(actualFileSize < minFileLength):
      print ("File: %s invalid size = %d, expected >= %d" % (file, actualFileSize, minFileLength))
      f.close()
      return [False, DEFINES.PcrFileMode['Null']]

    # file looks ok, except for the numHashes field which is checked by  build.hashPcrInfoFromFile() when it reads the data
    # can't check that yet since don't know which PCRs will be selected
    f.close()
    return [True, fileType]

  #  Verify that the pcr file contains the expected number of pcr hashes
  #  Return True if ok or if no PCR's are selected, else return False
  #
  #  file - is the specified pcr file
  #  fileType - indicates the type of PCR data file per the PcrFileModeXXXXX defines
  #  pcr0to7SelectionBitMask - is a mask indicating the selected PCRs
  #
  def verifyPcrInfoNumHashes(self, file, fileType, hashAlg, pcr0to7SelectionBitMask):
    """verifyPcrInfoNumHashes - verify the pcr file contains enough hashes"""
    function = "verifyPcrInfoNumHashes"

    # check for case when no PCR's were selected
    # nothing to hash in that case
    if(pcr0to7SelectionBitMask == 0):
      print("Warning: No PCR was selected. Nothing to hash: pcr0to7SelectionBitMask=0")
      print ("Note: No PCR was selected. If desired, select PCR's and click 'Apply PCR Selection'")
      return True

    try:
      hashAlgStr = (key for key,val in DEFINES.TPM_ALG_HASH.items() if val == hashAlg).next()
    except StopIteration:
      print("verifyPcrInfoNumHashes - invalid fileType=%x hash alg!!!" % (file, fileType, hashAlg))  # Should NEVER get here

    if(fileType == DEFINES.PcrFileMode['Pcrd']):
      minFileLength   = DEFINES.PCRDFileHdrSize + (8*DEFINES.DIGEST_SIZE['SHA1'])   # min PCRD SHA1   file has 8 hash's
    elif(fileType == DEFINES.PcrFileMode['Pcr2']):
      minFileLength   = DEFINES.PCR2FileHdrSize + (8*DEFINES.DIGEST_SIZE[hashAlgStr])   # min PCR2 SHA1   file has 8 hash's
    else:
      print("verifyPcrInfoNumHashes - invalid fileType=%x!!!" % (file, fileType))  # Should NEVER get here

    print("verifyPcrInfoNumHashes %s, type %d, pcr0to7SelectionBitMask=0x%x" % (file, fileType, pcr0to7SelectionBitMask)) # DBGDBG
    try:
      f = open(file, "rb")
    except:
      print ("Error opening PCR data file %s" % (file))
      return False

    f.seek (0, os.SEEK_END)
    actualFileSize = f.tell ()
    f.seek (0, os.SEEK_SET)     # back to the begininng
    data = array.array ("B")    # Load file into data array
    try:
      data.fromfile (f, minFileLength)
    except:
      print ("Error reading PCR data from file %s" % (file))
      f.close()
      return False

    f.close()
    numHashes = data[6]  # same for both PCRD and PCR2 files

    # now that we have NumHashes, check the actual file size
    #print("verifyPcrInfoNumHashes - numHashes=%x" % (numHashes)) # DBGDBG
    if(numHashes == 0):
      print ("File: %s invalid numHashes = 0" % (file))
      return False

    if(fileType == DEFINES.PcrFileMode['Pcrd']):
      expectedFileSize = DEFINES.PCRDFileHdrSize + (numHashes * DEFINES.DIGEST_SIZE['SHA1'])
    elif(fileType == DEFINES.PcrFileMode['Pcr2']):
      expectedFileSize = DEFINES.PCR2FileHdrSize + (numHashes * DEFINES.DIGEST_SIZE[hashAlgStr])
    else:
      print("verifyPcrInfoNumHashes - invalid fileType=%d" % (fileType)) # DBGDBG Should NEVER get here
      return False

    if(actualFileSize < expectedFileSize):
      print ("File: %s invalid File size = 0x%x=%i, expected 0x%x" %
            (file, actualFileSize, actualFileSize, expectedFileSize))
      return False

    # verify that numHashes >= the largest selected hash
    # must have at least that many hashes in the PCR dump file
    #print("verifyPcrInfoNumHashes - verify numHashes are in the file") # DBGDBG
    mask = 0x80
    bit = 8
    while(bit > 0):
      if(mask & pcr0to7SelectionBitMask):
        break                                   # found the largest selected PCR
      else:
        bit -= 1
        mask >>= 1

    if(bit > numHashes):                        # not enough hashes in the PCR dump file, abort
      print ("Too few hashes in PCR dump file: %s, numHashes = 0x%x, but max selected hash = 0x%x" %
            (file, numHashes, bit))
      return False

    return True


  # Get hash data from the specified file and return it using global _GlobalHashData
  # Note: no file format checking is done here as files were validated when added to the list
  # Return False if the hash couldn't be extracted, else return True
  #
  def getHashFromFile(self, file, hashAlg):
    """getHashFromFile - validate the hash file and extract the hash data"""

    global _GlobalHashData

    print("getHashFromFile - file %s, HashAlg=%d" % (file, hashAlg))  # DBGDBG
    result = self.verifyHashFile(file, hashAlg)
    # verifyHashFile() returns a list with [status, fileType]
    fileType = result[1]
    if(result[0] == False):
      return []      # should have detected this when file was selected
    fileType = result[1]
    data = array.array ("B")   # Load file into data array

    try:
      hashAlgStr = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
    except StopIteration:
      print("Unsupported hash algorithm (%d)" %(hashAlg))

    if(fileType == DEFINES.HashFileMode['HdrNull']):
      print("getHashFromFile - Error: invalid mode = %d, aborting." % (result[1]))
      return []
    elif(fileType == DEFINES.HashFileMode['HdrSHA1']):
      hashFileLength = 36
    elif(fileType in DEFINES.HashFileMode.values()):  # All other raw modes
      hashFileLength = DEFINES.DIGEST_SIZE[hashAlgStr]
    else:
      print("getHashFromFile - Error: invalid mode = %d, aborting." % (result[1]))
      return []

    try:
      f = open(file, "rb")
      f.seek (0, os.SEEK_SET)       # beginning of file
      data.fromfile (f, hashFileLength)
    except:
      print("getHashFromFile - Error reading hash from file %s" % (file))
      f.close()
      return []

    f.close()
    #print("getHashFromFile - data = %s, len=%d" % (data, len(data))) # DBGDBG

    # handle all the flavors of hash files
    if(fileType == DEFINES.HashFileMode['HdrSHA1']):
      _GlobalHashData = data[16:36].tolist()        # 20 bytes 16:36 exclusive
      print("getHashFromFile: %s, Hdr tag=%s alg=%i, size=%i, hash=%s, len=%d" %
           (file, data[0:4].tostring(), data[4], data[5], _GlobalHashData, len(_GlobalHashData)))   # DBGDBG
    else:
      _GlobalHashData = data.tolist()
      assert len(data) == DEFINES.DIGEST_SIZE[hashAlgStr], "Error: File size (%d bytes) mismatch with %s size (%d bytes)" %(len(data), hashAlgStr, DEFINES.DIGEST_SIZE[hashAlgStr])
      print("getHashFromFile: %s, raw %s hash=%s, len=%d" % (file, hashAlgStr, _GlobalHashData, len(_GlobalHashData)))   # DBGDBG

    return _GlobalHashData;

  #  Get the specified PCR data (indicated by the thisPcr mask)
  #  Return False if couldn't read the hashes from the PCR file
  #  othewise return True
  #
  #  file - is the specified pcr file
  #  fileType - indicates the type of PCR data file per the PcrFileModeXXXXX defines
  #  thisPcr - the specified PCR data to find  [0 < thisPcr < 8]
  #  hashSize - is the size of the pcr data to extract
  #
  def getPcrInfoFromFile(self, file, fileType, thisPcr, hashSize, statusBar):
    """getPcrInfoFromFile - get the pcr data from the specified file"""

    global _GlobalPcrHash

    if(fileType == DEFINES.PcrFileMode['Pcrd']):
      hdrSize = DEFINES.PCRDFileHdrSize
    elif(fileType == DEFINES.PcrFileMode['Pcr2']):
      hdrSize = DEFINES.PCR2FileHdrSize
    else:
      print("verifyPcrInfoNumHashes - invalid fileType=%d" % (fileType)) # DBGDBG Should NEVER get here
      return False

    #print("getPcrInfoFromFile %s type %d, pcr %d, hashSize=%d" % (file, fileType, thisPcr, hashSize)) # DBGDBG
    pcrData = array.array ("B")
    try:
      f = open(file, "rb")
    except:
      print("getPcrInfoFromFile: open of file %s failed" % (file)) # should never get here, file's been opened for verif. earlier
      return False

    # read TPM1 or TPM2 PCR tag to determine the file format to use?
    tag = f.read(4)

    # read the selected pcr's hash data
    if tag == 'PCR2':
      # PCR2 file format
      pos = hdrSize + (thisPcr * (hashSize + 2))  # There's a 2 byte size field precedes each PCR value.
      f.seek (pos, os.SEEK_SET)
      # Read the size of the PCR value and compare to the expected hash size
      size = f.read(2)
      pcrSize = unpack("<H", size)[0]
      if pcrSize == hashSize:
        pos += 2
      else:
        print ("Error reading hash from file %s at position %d with size %d" % (file, pos, hashSize))
        f.close()
        return False
    elif tag == 'PCRD':
      # PCR1 file format
      pos = hdrSize + (thisPcr * hashSize)
    else:
      print ("Error invalid PCR tag format for file %s" % (file))

    print("getPcrInfoFromFile - Read hash %d @pos%d, size %d" % (thisPcr, pos, hashSize)) # DBGDBG
    try:
      # calculate the start of the selected pcr's data
      f.seek (pos, os.SEEK_SET)     # back to the next hash where pos depends on if PCRD or PCR2 file
      #print("getPcrInfoFromFile - Seek done") # DBGDBG
      pcrData.fromfile(f, hashSize)
    except:
      print ("Error reading hash from file %s at position %d with size %d" % (file, pos, hashSize))
      f.close()
      return False

    f.close()
    _GlobalPcrHash = pcrData[0:hashSize].tolist()    # extract the data
    #print("getPcrInfoFromFile: %s, _GlobalPcrHash=%s" % (file, _GlobalPcrHash)) # DBGDBG
    return _GlobalPcrHash


  #     Open pcrFile
  #     Copy selected PCR measurements (pcrSelect) to temp buffer
  #     calculate composite hash of temp buffer
  #     return the composite hash in _GlobalPcrHash
  #     return False if couldn't read the hashes from the PCR file
  #     othewise return True [including if pcr0to7SelectionBitMask = 0 so nothing to hash]
  #
  def hashPcrInfoFromFile(self, file, pcr0to7SelectionBitMask, numSelectedPcrs):
    """hashPcrInfoFromFile - hash the pcr data from the specified file and return the hash"""
    # TODO: This function is use by PCONF legacy only?

    # PCR Dump File format
    #     typedef struct {
    #       UINT32 tag PCRD_TAG;          # 4 bytes  "PCRD" = 0x44524340
    #       UINT8 hashAlg ;               # 1 byte   SHA1_ALG = 4 SHA256_ALG = 0x0b
    #       UINT8 hashSize ;              # 1 byte   SHA1 = 20  SHA256 = 32
    #       UINT8 numHashes ;             # 1 byte   number of hashes in the file
    #       UINT8 reserve[9] ;            # 9 bytes
    #       SHA1 pcrs[24] ;               # 20 bytes * numHashes
    #     } HASH_FILE;                    # ________
    #  File Size                       # 16  + (NumHashes * HashSize) bytes
    #  Typically all 24 PCRs included  so size for SHA1 = 16 + 24*20 = 496 = 0x1f0
    #  LCP tool only requires the 1st 8 PCRs, if they are selected via pcr0to7SelectionBitMask
    #  I.e. if the bit mask 0-7 = 1 then that PCR is required
    #

    global _GlobalPcrHash
    #_GlobalPcrHash   = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]  # DBGDBG
    _GlobalPcrHash   = b'0000000000000000000000000000000000000000'

    # check for case when no PCR's were selected
    # nothing to hash in that case
    if(pcr0to7SelectionBitMask == 0):
      print("Warning: No PCR was selected. Nothing to hash: pcr0to7SelectionBitMask=0")
      print ("Note: No PCR was selected. If desired, select PCR's and click Update")
      return True

    try:
      f = open(file, "rb")
    except:
      print ("Error opening PCR data file %s" % (file))
      return False

    # Get the file size of PCR dump
    f.seek (0, os.SEEK_END)
    actualFileSize = f.tell ()

    f.seek (0, os.SEEK_SET)     # back to the begininng
    header = array.array("B")   # Read PCR header to determine type
    data = array.array ("B")    # Load file into data array

    # Read the header portion.  16-bytes should cover current PCRD and PCR2 file format.
    try:
      header.fromfile (f, 16)   # PCRD header size is 16 bytes.  PCR2 header size is 8 bytes.
    except:
      print ("Error reading PCR data from file %s" % (file))
      f.close()
      return False

    # Read the number of valid hashes
    numHashes = header[6]

    # If there are no hash in the dump file, the PCR dump is not valid
    if(numHashes == 0):
      print ("File: %s invalid numHashes = 0" % (file))
      return False

    # now that we have NumHashes, check the actual file size
    # Check the tag in the PCR file
    tag = header[0:4].tostring()
    if tag == 'PCR2':
      expectedPcrHashSize = unpack("<H", header[8:10])[0]                       # every measurement in the PCR dump file should be the same size
      pcrStartPos = 8                                                           # position of the first PCR measurement in the file
      minFileLength = pcrStartPos + (8 * (2 + expectedPcrHashSize))             # PCR2 file structure has 8 bytes followed by size and value for each measurement. min file has 8 hash's
      expectedFileSize = pcrStartPos + (numHashes * (2 + expectedPcrHashSize))  # include the 2-byte size field for each PCR value
    elif tag == 'PCRD':
      expectedPcrHashSize = 0x14                                                # for TPM1 only SHA1 is supported which has length of 20 bytes.
      pcrStartPos = 16                                                          # position of the first PCR measurement in the file
      minFileLength = pcrStartPos + (8 * expectedPcrHashSize)                   # PCRD file structure has 16 bytes followed by value of each measurements. min file has 8 hash's
      expectedFileSize = pcrStartPos + (numHashes * expectedPcrHashSize)

    # Check PCR dump for valid file size
    if(actualFileSize < expectedFileSize):
      print ("File: %s invalid FileSize = 0x%x=%i, expected 0x%x" %
            (file, actualFileSize, actualFileSize, expectedFileSize))
      return False

    # read min pcr values
    try:
      f.seek (0, os.SEEK_SET)
      data.fromfile (f, minFileLength)
    except:
      print ("Error reading PCR data from file %s" % (file))
      f.close()
      return False
    f.close()

    # verify that numHashes >= the largest selected hash
    # must have at least that many hashes in the PCR dump file
    mask = 0x80
    bit = 8
    while(bit > 0):
      if(mask & pcr0to7SelectionBitMask):
        break                                   # found the largest selected PCR
      else:
        bit -= 1
        mask >>= 1

    if(bit > numHashes):                        # not enough hashes in the PCR dump file, abort
      print ("Too few hashes in PCR dump file: %s, numHashes = 0x%x, but max selected hash = 0x%x" %
            (file, numHashes, bit))
      return False

    # file looks ok, get the data
    temp = array.array ("B")      # temp array
    hashLength = expectedPcrHashSize
    numSelectedPcrs = 0

    mask = 0x01
    bit = 0
    pos = 0
    while(bit < 8):
      if(mask & pcr0to7SelectionBitMask):
        if tag == 'PCR2':
          pos = pcrStartPos + 2 + bit * (2 + hashLength)
        elif tag == 'PCRD':
          pos = pcrStartPos + bit * hashLength

        temp += data[pos:pos+hashLength]
        numSelectedPcrs += 1
        print("hashPcrInfoFromFile - Read hash %d, mask 0x%x from file %s, select=0x%x, numSelectedPcrs=%d, len(temp)=%d" %
              (bit, mask, file, pcr0to7SelectionBitMask, numSelectedPcrs, len(temp))) # DBGDBG

      mask <<= 1
      bit += 1
      pos += hashLength

    #print("hashPcrInfoFromFile TypeOf: tempList=%s, tempList[0]=%s, _GlobalPcrHash=%s, _GlobalPcrHash[0]=%s" %
    #        (type(tempList), type(tempList[0]), type(_GlobalPcrHash), type(_GlobalPcrHash[0])))  # DBGDBG
    #pcrHash = hashlib.sha1()
    hashAlg = header[4]   # TODO: is hashAlg determined by GUI or from PCR file.
    hashAlgStr = None
    try:
      hashAlgStr = (key for key,val in DEFINES.TPM_ALG_HASH.items() if hashAlg == val).next()
    except StopIteration:
      print ("Error unsupported hash algorithm (%d)" %(hashAlg))

    # Set hash algorithm
    pcrHash = None
    if 'SM3' in hashAlgStr:
      pcrHash = sm3()
    else:
      pcrHash = M2Crypto.EVP.MessageDigest(hashAlgStr.lower())

    if tag == 'PCR2':
      pcrHash.update(temp)
    elif tag == 'PCRD':
      #pcrHash = hashlib.sha1()
      pcrHash = M2Crypto.EVP.MessageDigest('sha1')
      # The PCR composite hash consists of:  TPM_PCR_COMPOSITE structure
      #     UINT16  sizeOfSelect              # BigEndian = 00 03
      #     UINT8   pcr_select[3]
      #     UINT32  valueSize                 # BigEndian = 20 * NumberOfSelectedHashes
      #     UINT8   pcrValue[]                # all the selected PCR hashes
      data = pack("<BBBBB", 0, 3, pcr0to7SelectionBitMask, 0, 0)  # pack sezeOfSelect and pcr_select[3]
      pcrHash.update(data)
      valueSize = numSelectedPcrs * DEFINES.DIGEST_SIZE['SHA1']
      data = pack(">L", valueSize)            # Note '>' for BigEndian packing of valueSize
      pcrHash.update(data)
      # pack pcrValue[]
      pcrHash.update(temp)

    # hash.digest() Returns the digest of the strings passed to the update() method so far.
    # This is a string of digest_size bytes [which may contain non-ASCII characters, including null bytes]
    # Note: cannot pass this string thru struct.pack() which takes ints
    _GlobalPcrHash = pcrHash.digest()

    #print("hashPcrInfoFromFile: %s, Generated hash: Length=%d HexData=%s " %
    #      (file, hashLength, pcrHash.hexdigest()))   # DBGDBG

    return _GlobalPcrHash


  def getKeyFromFile(self, file, type):
    # Read the key file from the
    with open(file, 'rb') as kf:
       mb = M2Crypto.BIO.MemoryBuffer(kf.read())

    kf.close()
    pem = mb.getvalue()
    pem_lines = pem.split('\n')
    key = None
    # Find line index of BEGIN and END header/footer
    der = ''
    foundbegin = False
    for line in pem_lines:
      if ('END' in line) and ('PUBLIC' in line or 'PRIVATE' in line):
        break
      if foundbegin:
        der += line.strip()
      if ('BEGIN' in line) and ('PUBLIC' in line or 'PRIVATE' in line):
        foundbegin = True

    try:  # in case ASN1 can't decode the ASN1 notation..
      if type == DEFINES.KEY_FILE_TYPE['PRIVATE_RSASSA']:
        asn, substrate = der_decoder.decode(der.decode('base64'), asn1Spec=RSAPrivateKey())
        rsapvt = asn.getComponentByName('privateExponent')   # returns univ.Integer()
        octet = univ.OctetString(hexValue=format(int(rsapvt), '0x'))  # convert to Octet
        key = octet.asOctets()
      elif type == DEFINES.KEY_FILE_TYPE['PUBLIC_RSASSA']:
        # This decodes DER encoded ASN1 public key
        asn, substrate = der_decoder.decode(der.decode('base64'), asn1Spec=SubjectPublicKeyInfo())
        bits = asn.getComponentByName('subjectPublicKey')

        # second level decode for RSAPublicKey()
        bits_string = ''.join(map(str, bits))
        octet = univ.OctetString(binValue=bits_string)

        rsaasn, substrate = der_decoder.decode(octet.asOctets(), asn1Spec=RSAPublicKey())
        rsapub = rsaasn.getComponentByName('modulus')     # returns univ.Integer()
        octet = univ.OctetString(hexValue=format(int(rsapub), '0x'))  # convert to Octet
        key = octet.asOctets()

      elif type == DEFINES.KEY_FILE_TYPE['PRIVATE_ECDSA']:
        asn, substrate = der_decoder.decode(der.decode('base64'), asn1Spec=ECPrivateKey())
        ecpvt = asn.getComponentByName('privateKey')      # returns univ.OctetString()
        key = ecpvt.asOctets()

      elif type == DEFINES.KEY_FILE_TYPE['PUBLIC_ECDSA']:
        # This decodes DER encoded ASN1 public key
        asn, substrate = der_decoder.decode(der.decode('base64'), asn1Spec=SubjectPublicKeyInfo())
        bits = asn.getComponentByName('subjectPublicKey') # returns univ.BitString()

        # DSAPublicKey is Integer() so no decoding is needed, but need to remove the prefix 0x04.
        bits_string = ''.join(map(str, bits[8:]))  # the first byte specifies the compress alg?
        octet = univ.OctetString(binValue=bits_string)
        key = octet.asOctets()

    except Exception as ex:
      print ("Exception: unable to decode pem file")
      print (ex)

    if key != None:
      keyLE = key[::-1]  # little endian
    else:
      keyLE = ''

    return keyLE


  # the last function in the file doesn't show up in the scope list in Understand for some reason!
  def stub(self):
    pass
