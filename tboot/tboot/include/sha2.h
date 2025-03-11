/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#ifndef __SHA2_H__
#define __SHA2_H__

#include <types.h>

#define SHA256_BLOCK_SIZE   64
#define SHA512_BLOCK_SIZE   128

#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#define CONST64(n) n ## ULL

#define STORE64H(x, y)                                                                   \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);   \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);   \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);   \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while (0)
     
#define LOAD64H(x, y)                                              \
do { x = (((u64)((y)[0] & 255))<<56)|(((u64)((y)[1] & 255))<<48) | \
         (((u64)((y)[2] & 255))<<40)|(((u64)((y)[3] & 255))<<32) | \
         (((u64)((y)[4] & 255))<<24)|(((u64)((y)[5] & 255))<<16) | \
         (((u64)((y)[6] & 255))<<8)|(((u64)((y)[7] & 255))); } while(0)

#define STORE32H(x, y)                                                                   \
do   { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255); \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while (0)

#define LOAD32H(x, y)                  \
do   { x = ((u32)((y)[0] & 255)<<24) | \
           ((u32)((y)[1] & 255)<<16) | \
           ((u32)((y)[2] & 255)<<8)  | \
           ((u32)((y)[3] & 255)); } while (0)


struct sha512_state {
    u64 length, state[8];
    u32 curlen;
    unsigned char buf[128];
};

struct sha256_state {
    u64 length;
    u32 state[8], curlen;
    unsigned char buf[64];
};

typedef union Hash_state {
    char dummy[1];
    struct sha512_state sha512;
    struct sha256_state sha256;
    void *data;
} hash_state;

/* SHA 256 */
int sha256_init(hash_state * md);
int sha256_process(hash_state * md, const unsigned char *in, u32 inlen);
int sha256_done(hash_state * md, unsigned char *out);
int sha256_buffer(const unsigned char *buffer, size_t len,
                  unsigned char hash[32]);

/* SHA 384 */
int sha384_init(hash_state * md);
#define sha384_process sha512_process
int sha384_done(hash_state * md, unsigned char *out);
int sha384_buffer(const unsigned char *buffer, size_t len,
                  unsigned char hash[48]);

/* SHA 512 */
int sha512_init(hash_state * md);
int sha512_process(hash_state * md, const unsigned char *in, u32 inlen);
int sha512_done(hash_state * md, unsigned char *out);
int sha512_buffer(const unsigned char *buffer, size_t len,
                  unsigned char hash[64]);

#endif /* __SHA2_H__ */