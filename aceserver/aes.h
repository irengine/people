#ifndef _AES_H
#define _AES_H

#include <sys/types.h>

typedef struct
{
    u_int32_t erk[64];
    u_int32_t drk[64];
    int nr;
}
aes_context;

int  aes_set_key( aes_context *ctx, u_int8_t *key, int nbits );
void aes_encrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] );
void aes_decrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] );

#endif /* aes.h */
