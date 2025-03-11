/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include <string.h>
#include <sha2.h>

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha384_init(hash_state * md)
{
   if (md == NULL) {
      return -1;
   }

   md->sha512.curlen = 0;
   md->sha512.length = 0;
   md->sha512.state[0] = CONST64(0xcbbb9d5dc1059ed8);
   md->sha512.state[1] = CONST64(0x629a292a367cd507);
   md->sha512.state[2] = CONST64(0x9159015a3070dd17);
   md->sha512.state[3] = CONST64(0x152fecd8f70e5939);
   md->sha512.state[4] = CONST64(0x67332667ffc00b31);
   md->sha512.state[5] = CONST64(0x8eb44a8768581511);
   md->sha512.state[6] = CONST64(0xdb0c2e0d64f98fa7);
   md->sha512.state[7] = CONST64(0x47b5481dbefa4fa4);
   return 0;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha384_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];

   if (md == NULL || out == NULL) {
      return -1;
   }

    if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
      return -1;
   }

   sha512_done(md, buf);
   tb_memcpy(out, buf, 48);
   return 0;
}

int sha384_buffer(const unsigned char *buffer, size_t len,
                  unsigned char hash[48])
{
    hash_state md;
    int ret = 0;

    ret |= sha384_init(&md);
    ret |= sha384_process(&md, buffer, len);
    ret |= sha384_done(&md, hash);

    return ret;
}