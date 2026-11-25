/* AES (FIPS-197): the block cipher, for the `aes` operation of the decode
 * workbench. The modes (ECB, CBC, CTR) and the padding are in decode.c.
 *
 * It decrypts and encrypts with a key the user supplies; nothing here looks
 * for a key. Plain table lookups: no attempt is made to run in constant
 * time, which a tool for looking at data on one's own machine does not need. */
#ifndef VEX_AES_H
#define VEX_AES_H

#include "common.h"

typedef struct {
    unsigned rounds;                /* 10, 12 or 14 */
    uint8_t round_key[15][16];
} AesKey;

/* False unless the key is 16, 24 or 32 bytes long. */
bool aes_set_key(AesKey *k, const uint8_t *key, size_t length);
/* One block; `in` and `out` may be the same. */
void aes_encrypt_block(const AesKey *k, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(const AesKey *k, const uint8_t in[16], uint8_t out[16]);

#endif
