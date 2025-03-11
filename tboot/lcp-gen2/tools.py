#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

#  TXT Policy Generator Tool - tools invoked from tools menu
#     Hash image
#     Insert policy into image

# using print() built infunction, disable print statement
from __future__ import print_function

try:
  import wx
except ImportWxError:
  raise ImportWxError, "Please download the appropriate version of wxPython from www.wxpython.org"

try:
  import os
except ImportOsError:
  raise ImportOsError, "import OS failed"

import array
import M2Crypto
import struct

# Pycrypto module from: https://www.dlitz.net/software/pycrypto/ is required
#try:
#  from Crypto.Hash import SHA               # SHA1
#  from Crypto.Hash import SHA256            # SHA256
#except ImportError:
#  raise ImportError, "PyCrypto import failed. Please install PyCrypto ..."

from defines import DEFINES
from util import UTILS
utilities = UTILS()


class TOOLS(object):

  # hash a bios image 'file' [i.e. base.bin] from 'startOffset' for 'offsetSize' bytes,
  # and write the hash to base.hash, as a LCP2 raw hash file, and base.dat as an 'ascii coded binary'
  # I.e. if the image's hash starts with:  0xB0, 0x61, 0x52, ...
  # then  the    .hash file  starts with:  B0 61 52 ...   (i.e. the raw binary hash)
  # and   the    .dat  file  starts with:  42 30 20 36 31 20 35 32 20
  # (i.e. each hex digit is represented by its ascii equivalent with an ascii space after each hex pair

  # Parameters
  #   biosFileName - name of the bios file to be hashed
  #   startOffset  - offset into the file to start hashing from, aka base
  #   offsetSize   - size to hash from startOffset
  #   hashAlg      - hash algorithm to use, TPM_ALG_XXXX where XXXX is SHA1 or SHA256

  # Return True on success or
  #        False on any error
  #
  def hashImage(self, biosFileName, startOffsetStr, offsetSizeStr, hashAlgStr):
    """hashImage - generate the hash of the specified file from start address for size bytes"""
    function = 'hashImage'

    biosPath = os.path.abspath(os.path.normpath(biosFileName))
    startOffset = int(startOffsetStr, 16)
    offsetSize  = int(offsetSizeStr, 16)
    hashAlg     = int(hashAlgStr, 16)

    MAX_BIOS_SIZE = 0x1000000;
    print("%s - biosFile=%s, startOffset=0x%x, offsetSize=0x%x, hashAlg=%d" %
          (function, biosPath, startOffset, offsetSize, hashAlg))  # DBGDBG

    # use biosFile's base name for the .tmp and .hash files
    #   biosFile - file to be hashed, ie if biosFileName = biosXYZ.bin then base = biosXYZ
    #   tempFile - base.tmp - temp file containing the data to hash
    #     i.e. biosFile's data from startOffset to startOffset+offsetSize
    #   hashFile - base.hash - output file containg the hash of tempFile

    # verify that biosFile can be opened
    try:
      biosFile = open(biosPath, 'rb')
    except:
      print("Unable to open specified file: %s" % (biosPath))
      return False

    # strip off the .ext leaving the base
    if(biosFileName.endswith('.bin') == True):
      base = os.path.basename(biosFileName).split('.bin')
    else:
      print("Expected .bin extention for Bios File %s" % (biosPath))
      return False

    #TODO:  will all bios files have .bin extentions??????????????????????????????????????
    #print("%s - base=%s" % (function, base[0]))  # DBGDBG

    # verify that .tmp, .dat and .hash files can be created in the current dir, else exit
    tmpFileName  = utilities.formFileName(base[0], "tmp")
    hashFileName = utilities.formFileName(base[0], "hash")
    datFileName  = utilities.formFileName(base[0], "dat")
    #print("%s - tmpFileName=%s, hashFileName=%s" % (function, tmpFileName, hashFileName)) # DBGDBG
    try:
      tmpFile = open(tmpFileName, 'wb')
    except:
      print("Unable to create file: %s" % (tmpFileName))
      biosFile.close()
      return False

    try:
      hashFile = open(hashFileName, 'wb')
    except:
      print("Unable to create file: %s" % (hashFileName))
      tmpFile.close()
      biosFile.close()
      return False

    try:
      datFile = open(datFileName, 'wb')
    except:
      print("Unable to create file: %s" % (datFileName))
      tmpFile.close()
      biosFile.close()
      datFile.close()
      return False

    # Determine biosFile's size
    biosFile.seek (0, os.SEEK_END)
    biosFileSize = biosFile.tell()

    # if startOffset > MAX_BIOS_SIZE, then adjust startOffset to be relative to 4Gb
    if (startOffset > MAX_BIOS_SIZE):
      print("The specified StartOffset(0x%x) is > than the max bios size(%x) Assuming StartOffset is relative to 4Gb" %
        (startOffset, MAX_BIOS_SIZE))
      beginingOfBiosImage = 0x100000000 - biosFileSize;
      startOffset = startOffset - beginingOfBiosImage;
      print("%s - startOffset now 0x%x, MAX_BIOS_SIZE=0x%x" % (startOffset, MAX_BIOS_SIZE))

    # If startOffset + offsetSize > biosFile's size, adjust offsetSize
    if(startOffset + offsetSize > biosFileSize):
      print("%s - The specified StartOffset(0x%x) + offsetSize(0x%x) is larger than biosFileSize(0x%x)" %
        (function, startOffset, offsetSize, biosFileSize))
      offsetSize = biosFileSize - startOffset;
      print("StartOffset+OffsetSize > BiosFileSize. Resetting OffsetSize to 0x%x" % (offsetSize))

    #print("%s - biosFileSize=0x%x, startOffset+offsetSize=0x%x, MAX_BIOS_SIZE=0x%x" % (function, biosFileSize, startOffset+offsetSize, MAX_BIOS_SIZE)) # DBGDBG
    # buffer the part of the bios that will be hashed in base.tmp
    #   open the bios file,
    #   set the read pointer to: startOffset
    #   read offsetSize bytes into tempFile
    data = array.array ("B")
    biosFile.seek(startOffset, os.SEEK_SET)
    #print("%s - pos=0x%x" % (function, biosFile.tell())) # DBGDBG
    data.fromfile(biosFile, offsetSize)

    # Initialize to None to check for supported HashAlg.
    hashAlgName = None
    # reverse lookup of the hash algorithm name(key) for the given HashAlg value
    hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()

    if (hashAlgName != None):
      # This handles all SHA hash algorithms.
      hash = M2Crypto.EVP.MessageDigest(hashAlgName.lower())
    else:
      self.StatusBar.SetStatusText("Hash Algorithm %d is not supported" % (hashAlg))
      return False

    hash.update(data)
    hashdigest = hash.digest()  # cannot call this M2Crypto function twice.

    print(data, end='', file=tmpFile )        # for testing that the right data was hashed
    print(hashdigest, end='', file=hashFile )
    hexHash = hashdigest.encode('hex')
    print("Image's hash: %s" % (hexHash))
    print("Generated hash files: %s.hash and %s.dat" % (base[0],base[0]))

    # generate the .dat from hexHash: convert each hex byte to a ascii digit followed by a space
    i=0
    while(i < len(hexHash)):
      print(hexHash[i].upper(),   end='', file=datFile )    # 1st hexdigit as upper case ascii
      print(hexHash[i+1].upper(), end='', file=datFile )    # 2nd hexdigit as upper case ascii
      print(' ',          end='', file=datFile )            # space after each pair
      i += 2
    print('\n', end='', file=datFile )                      # final LF to match WinLCP

    biosFile.close()
    tmpFile.close()
    hashFile.close()
    datFile.close()
    return True
