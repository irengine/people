#ifndef _AES_H
#define _AES_H

#include <sys/types.h>

//#ifndef u_int8_t
//#define u_int8_t  unsigned char
//#endif
//
//#ifndef u_int32_t
//#define u_int32_t unsigned long int
//#endif

typedef struct
{
    u_int32_t erk[64];     /* encryption round keys */
    u_int32_t drk[64];     /* decryption round keys */
    int nr;             /* number of rounds */
}
aes_context;

int  aes_set_key( aes_context *ctx, u_int8_t *key, int nbits );
void aes_encrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] );
void aes_decrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] );

#endif /* aes.h */