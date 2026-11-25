/* AES block cipher (see aes.h). The S-box is computed, as crypto.py computes
 * it, rather than typed in: the inverse in GF(2**8) followed by the affine
 * map of FIPS-197, section 5.1.1. */
#include "aes.h"

static uint8_t SBOX[256], INV_SBOX[256];
/* Products in GF(2**8) by the constants of MixColumns and its inverse. */
static uint8_t MUL2[256], MUL3[256], MUL9[256], MUL11[256], MUL13[256], MUL14[256];
static bool tables_ready;

/* Multiplication in GF(2**8) modulo x**8 + x**4 + x**3 + x + 1. */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t product = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            product ^= a;
        bool high = (a & 0x80) != 0;
        a = (uint8_t)(a << 1);
        if (high)
            a ^= 0x1B;
        b >>= 1;
    }
    return product;
}

static uint8_t rotl8(uint8_t x, unsigned n) {
    return (uint8_t)(x << n | x >> (8 - n));
}

static void build_tables(void) {
    uint8_t power[256], logarithm[256];
    uint8_t x = 1;
    memset(logarithm, 0, sizeof logarithm);
    for (unsigned i = 0; i < 255; i++) {    /* powers of the generator 3 */
        power[i] = x;
        logarithm[x] = (uint8_t)i;
        x = gmul(x, 3);
    }
    for (unsigned a = 0; a < 256; a++) {
        uint8_t inverse = a == 0 ? 0 : power[(255 - logarithm[a]) % 255];
        uint8_t s = (uint8_t)(inverse ^ rotl8(inverse, 1) ^ rotl8(inverse, 2) ^
                              rotl8(inverse, 3) ^ rotl8(inverse, 4) ^ 0x63);
        SBOX[a] = s;
        INV_SBOX[s] = (uint8_t)a;
        MUL2[a] = gmul((uint8_t)a, 2);
        MUL3[a] = gmul((uint8_t)a, 3);
        MUL9[a] = gmul((uint8_t)a, 9);
        MUL11[a] = gmul((uint8_t)a, 11);
        MUL13[a] = gmul((uint8_t)a, 13);
        MUL14[a] = gmul((uint8_t)a, 14);
    }
    tables_ready = true;
}

bool aes_set_key(AesKey *k, const uint8_t *key, size_t length) {
    if (length != 16 && length != 24 && length != 32)
        return false;
    if (!tables_ready)
        build_tables();
    unsigned nk = (unsigned)length / 4;
    k->rounds = nk + 6;
    /* The key schedule, a word (four bytes) at a time. */
    uint8_t w[60][4];
    unsigned total = 4 * (k->rounds + 1);
    memcpy(w, key, length);
    uint8_t rcon = 1;
    for (unsigned i = nk; i < total; i++) {
        uint8_t t[4];
        memcpy(t, w[i - 1], 4);
        if (i % nk == 0) {
            uint8_t first = t[0];           /* RotWord, SubWord, Rcon */
            t[0] = SBOX[t[1]] ^ rcon;
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[first];
            rcon = gmul(rcon, 2);
        } else if (nk > 6 && i % nk == 4) {
            for (int b = 0; b < 4; b++)
                t[b] = SBOX[t[b]];
        }
        for (int b = 0; b < 4; b++)
            w[i][b] = w[i - nk][b] ^ t[b];
    }
    for (unsigned round = 0; round <= k->rounds; round++)
        memcpy(k->round_key[round], w[4 * round], 16);
    return true;
}

static void add_round_key(uint8_t s[16], const uint8_t key[16]) {
    for (int i = 0; i < 16; i++)
        s[i] ^= key[i];
}

/* The state is kept in the order of the input: byte r + 4c is row r of
 * column c. */
void aes_encrypt_block(const AesKey *k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    memcpy(s, in, 16);
    add_round_key(s, k->round_key[0]);
    for (unsigned round = 1; round <= k->rounds; round++) {
        /* SubBytes and ShiftRows: row r moves r places to the left */
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                t[r + 4 * c] = SBOX[s[r + 4 * ((c + r) & 3)]];
        if (round < k->rounds) {            /* MixColumns */
            for (int c = 0; c < 4; c++) {
                const uint8_t *a = t + 4 * c;
                s[4 * c] = MUL2[a[0]] ^ MUL3[a[1]] ^ a[2] ^ a[3];
                s[4 * c + 1] = a[0] ^ MUL2[a[1]] ^ MUL3[a[2]] ^ a[3];
                s[4 * c + 2] = a[0] ^ a[1] ^ MUL2[a[2]] ^ MUL3[a[3]];
                s[4 * c + 3] = MUL3[a[0]] ^ a[1] ^ a[2] ^ MUL2[a[3]];
            }
        } else {
            memcpy(s, t, 16);
        }
        add_round_key(s, k->round_key[round]);
    }
    memcpy(out, s, 16);
}

void aes_decrypt_block(const AesKey *k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    memcpy(s, in, 16);
    add_round_key(s, k->round_key[k->rounds]);
    for (unsigned round = k->rounds; round-- > 0;) {
        /* InvShiftRows and InvSubBytes: row r moves r places to the right */
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                t[r + 4 * ((c + r) & 3)] = INV_SBOX[s[r + 4 * c]];
        add_round_key(t, k->round_key[round]);
        if (round > 0) {                    /* InvMixColumns */
            for (int c = 0; c < 4; c++) {
                const uint8_t *a = t + 4 * c;
                s[4 * c] = MUL14[a[0]] ^ MUL11[a[1]] ^ MUL13[a[2]] ^ MUL9[a[3]];
                s[4 * c + 1] = MUL9[a[0]] ^ MUL14[a[1]] ^ MUL11[a[2]] ^ MUL13[a[3]];
                s[4 * c + 2] = MUL13[a[0]] ^ MUL9[a[1]] ^ MUL14[a[2]] ^ MUL11[a[3]];
                s[4 * c + 3] = MUL11[a[0]] ^ MUL13[a[1]] ^ MUL9[a[2]] ^ MUL14[a[3]];
            }
        } else {
            memcpy(s, t, 16);
        }
    }
    memcpy(out, s, 16);
}
