/* MD5 (RFC 1321), SHA-1 and SHA-256 (FIPS 180-4). The three share the same
 * Merkle-Damgard framing: 64-byte blocks, a 0x80 byte, zero padding and the
 * message length in bits in the last eight bytes. */
#include "hash.h"

static uint32_t rotl(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

typedef void (*BlockFn)(uint32_t *state, const uint8_t block[64]);

/* Feed the whole message, padded, through `compress`. */
static void run_hash(const uint8_t *data, uint64_t size, uint32_t *state, BlockFn compress,
                     bool big_endian_length) {
    uint64_t full = size / 64;
    for (uint64_t i = 0; i < full; i++)
        compress(state, data + i * 64);
    uint8_t tail[128];
    size_t rest = (size_t)(size % 64);
    memset(tail, 0, sizeof tail);
    if (rest)
        memcpy(tail, data + full * 64, rest);
    tail[rest] = 0x80;
    size_t total = rest < 56 ? 64 : 128;
    uint64_t bits = size * 8;
    for (int i = 0; i < 8; i++) {
        uint8_t byte = (uint8_t)(bits >> (8 * i));
        if (big_endian_length)
            tail[total - 1 - (size_t)i] = byte;
        else
            tail[total - 8 + (size_t)i] = byte;
    }
    compress(state, tail);
    if (total == 128)
        compress(state, tail + 64);
}

static void to_hex(const uint32_t *state, size_t words, bool big_endian, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t w = 0; w < words; w++) {
        for (int b = 0; b < 4; b++) {
            unsigned shift = big_endian ? 24 - 8 * (unsigned)b : 8 * (unsigned)b;
            uint8_t byte = (uint8_t)(state[w] >> shift);
            *out++ = digits[byte >> 4];
            *out++ = digits[byte & 15];
        }
    }
    *out = '\0';
}

/* --- MD5 --------------------------------------------------------------------- */

static const uint32_t MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391,
};

static const uint8_t MD5_SHIFT[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void md5_block(uint32_t *state, const uint8_t block[64]) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = load_le32(block + 4 * i);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t f;
        unsigned g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        uint32_t next = b + rotl(a + f + MD5_K[i] + m[g], MD5_SHIFT[i]);
        a = d;
        d = c;
        c = b;
        b = next;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md5_hex(const uint8_t *data, uint64_t size, char out[33]) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    run_hash(data, size, state, md5_block, false);
    to_hex(state, 4, false, out);
}

/* --- SHA-1 ------------------------------------------------------------------- */

static void sha1_block(uint32_t *state, const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = load_be32(block + 4 * i);
    for (int i = 16; i < 80; i++)
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        uint32_t next = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = next;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_hex(const uint8_t *data, uint64_t size, char out[41]) {
    uint32_t state[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    run_hash(data, size, state, sha1_block, true);
    to_hex(state, 5, true, out);
}

/* --- SHA-256 ----------------------------------------------------------------- */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
};

static void sha256_block(uint32_t *state, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = load_be32(block + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t v[8];
    memcpy(v, state, sizeof v);
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25);
        uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint32_t t1 = v[7] + s1 + ch + SHA256_K[i] + w[i];
        uint32_t s0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22);
        uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint32_t t2 = s0 + maj;
        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = v[3] + t1;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++)
        state[i] += v[i];
}

void sha256_hex(const uint8_t *data, uint64_t size, char out[65]) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    run_hash(data, size, state, sha256_block, true);
    to_hex(state, 8, true, out);
}
