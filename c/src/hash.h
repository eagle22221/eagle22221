/* MD5, SHA-1 and SHA-256 of a byte buffer, as lowercase hex strings. */
#ifndef VEX_HASH_H
#define VEX_HASH_H

#include "common.h"

void md5_hex(const uint8_t *data, uint64_t size, char out[33]);
void sha1_hex(const uint8_t *data, uint64_t size, char out[41]);
void sha256_hex(const uint8_t *data, uint64_t size, char out[65]);

#endif
