#ifndef ___MD5_H___
#define ___MD5_H___

#include <string>
#include <sys/types.h>
#include <stddef.h>

typedef struct {
  u_int32_t i[2];                   /* Number of _bits_ handled mod 2^64 */
  u_int32_t buf[4];                                    /* Scratch buffer */
  unsigned char in[64];                              /* Input buffer */
  unsigned char digest[16];     /* Actual digest after MD5Final call */
} MD5_CTX;

void MD5Init(MD5_CTX *mdContext, u_int32_t pseudoRandomNumber = 0);
void MD5Update(MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen);
void MD5Final(MD5_CTX *mdContext);

bool md5file (const char *fn , u_int32_t seed, MD5_CTX *mdContext, char * result_buff, int result_buff_len);


#endif /* ___MD5_H___ included */
