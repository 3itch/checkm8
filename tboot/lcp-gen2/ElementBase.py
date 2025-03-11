
from struct import *
from array import *
from defines import DEFINES


class ElementBase(object):

  #MleDataSha1HashFormatString      = "<20B"
  #MleDataSha256HashFormatString    = "<32B"
  #MleDataSha384HashFormatString    = "<48B"
  #MleDataSha512HashFormatString    = "<64B"
  
  def __init__(self):
    pass


  # alg is a string that specifies hash algorithm
  # hash is the array of bytes of the hash value
  #
  def packHash(self, alg, hash):
    #hashFormatString = "<" + str(DEFINES.DIGEST_SIZE[alg]) + "B"  # Build the pack format string for different hash algorithms
    #hashData = pack(hashFormatString, array('B', hash))
    #print "DEBUG: hash format string = "+ HashFormatString
    
    # Check hash size vs. expected size for specified algorithm
    hashData = None
    if (DEFINES.DIGEST_SIZE[alg] == len(hash)):
      b = bytes()
      hashData = b.join(pack('B', val) for val in hash)
    else:
      print ("ERROR: Hash buffer size %d does not match required size for %s" %(len(hash), alg))

    return hashData



if __name__ == "__main__":
  sha1data = [val for val in range(DEFINES.DIGEST_SIZE['SHA1'])]
  sha256data = [val for val in range(DEFINES.DIGEST_SIZE['SHA256'])]
  e = ElementBase();
  packedHash = pack("<20B", sha1data[0], sha1data[1], sha1data[2], sha1data[3], sha1data[4], sha1data[5],
               sha1data[6], sha1data[7], sha1data[8], sha1data[9], sha1data[10], sha1data[11], sha1data[12],
               sha1data[13], sha1data[14], sha1data[15], sha1data[16], sha1data[17], sha1data[18], sha1data[19])
  joinedHash = e.packHash('SHA256', sha1data)
  
  if (packedHash == joinedHash):
    print "SUCCESS"
  else:
    print "FAILED"
  
  print packedHash
  print joinedHash
