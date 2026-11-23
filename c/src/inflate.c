/* Raw DEFLATE decoder and CRC-32 (see inflate.h). The decoding steps, their
 * order and the error conditions follow RFC 1951 and the behaviour of zlib's
 * inflate(), which the Python edition uses. */
#include "inflate.h"

enum { HUFF_COMPLETE, HUFF_SINGLE, HUFF_EMPTY };
enum {
    M_TYPE, M_STORED, M_COPY, M_TABLE, M_LENLENS, M_CODELENS, M_LEN, M_LENEXT, M_DIST,
    M_DISTEXT, M_MATCH, M_LIT, M_DONE, M_BAD
};

#define NEED_MORE (-1)          /* the bits at hand do not finish a code */
#define NO_SUCH_CODE (-2)       /* the bits spell a code nothing is assigned to */
#define MAX_CODE_BITS 15
#define FAST_BITS 9

static const uint16_t LENGTH_BASE[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258};
static const uint8_t LENGTH_EXTRA[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t DISTANCE_BASE[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t DISTANCE_EXTRA[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
    13, 13};
/* Order in which the code-length code lengths are stored. */
static const uint8_t LENGTH_ORDER[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

/* Builds the decoding tables for `n` code lengths (each 0..15). Returns
 * false for a set of lengths that is not a prefix code: over-subscribed, or
 * incomplete. As in zlib, an incomplete code is accepted in one case only:
 * a literal/length or distance code with a single one-bit code. */
static bool huffman_build(BsHuffman *h, const uint16_t *lens, unsigned n, bool code_lengths) {
    unsigned next[MAX_CODE_BITS + 2];
    memset(h, 0, sizeof *h);
    for (unsigned i = 0; i < n; i++)
        h->count[lens[i]]++;
    h->count[0] = 0;
    unsigned longest = MAX_CODE_BITS;
    while (longest > 0 && h->count[longest] == 0)
        longest--;
    if (longest == 0) {
        h->kind = HUFF_EMPTY;       /* no codes at all: nothing can be decoded */
        return true;
    }
    int unused = 1;                 /* code space left at the current length */
    for (unsigned len = 1; len <= MAX_CODE_BITS; len++) {
        unused = unused * 2 - (int)h->count[len];
        if (unused < 0)
            return false;
    }
    if (unused > 0 && (code_lengths || longest != 1))
        return false;
    h->kind = unused > 0 ? HUFF_SINGLE : HUFF_COMPLETE;

    next[1] = 0;
    for (unsigned len = 1; len <= MAX_CODE_BITS; len++)
        next[len + 1] = next[len] + h->count[len];
    for (unsigned sym = 0; sym < n; sym++)
        if (lens[sym] != 0)
            h->symbol[next[lens[sym]]++] = (uint16_t)sym;
    if (h->kind != HUFF_COMPLETE)
        return true;

    /* Codes of up to FAST_BITS bits are found with one table lookup. The
     * stream holds a code most significant bit first, so the index is the
     * code reversed. */
    unsigned code = 0, index = 0;
    for (unsigned len = 1; len <= FAST_BITS; len++) {
        for (unsigned i = 0; i < h->count[len]; i++, code++, index++) {
            unsigned reversed = 0;
            for (unsigned bit = 0; bit < len; bit++)
                reversed |= ((code >> bit) & 1u) << (len - 1 - bit);
            for (unsigned k = reversed; k < (1u << FAST_BITS); k += 1u << len)
                h->fast[k] = (uint16_t)(len << FAST_BITS | h->symbol[index]);
        }
        code <<= 1;
    }
    return true;
}

/* The symbol whose code starts the `bits` available bits of `hold` (which is
 * zero above them), with its length in *len; NEED_MORE when those bits are
 * only the beginning of a code. */
static int huffman_lookup(const BsHuffman *h, uint64_t hold, unsigned bits, unsigned *len) {
    if (h->kind != HUFF_COMPLETE) {
        if (bits < 1)
            return NEED_MORE;
        *len = 1;
        if (h->kind == HUFF_SINGLE && (hold & 1u) == 0)
            return h->symbol[0];
        return NO_SUCH_CODE;
    }
    unsigned entry = h->fast[hold & ((1u << FAST_BITS) - 1)];
    if (entry != 0) {
        unsigned length = entry >> FAST_BITS;
        if (length > bits)
            return NEED_MORE;
        *len = length;
        return (int)(entry & ((1u << FAST_BITS) - 1));
    }
    int code = 0, first = 0, index = 0;
    for (unsigned length = 1; length <= MAX_CODE_BITS; length++) {
        if (length > bits)
            return NEED_MORE;
        code |= (int)((hold >> (length - 1)) & 1u);
        int count = h->count[length];
        if (code - count < first) {
            *len = length;
            return h->symbol[index + (code - first)];
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    *len = MAX_CODE_BITS;
    return NO_SUCH_CODE;            /* not reached: the code is complete */
}

static void fixed_tables(BsInflate *z) {
    uint16_t lens[288];
    unsigned sym = 0;
    while (sym < 144) lens[sym++] = 8;
    while (sym < 256) lens[sym++] = 9;
    while (sym < 280) lens[sym++] = 7;
    while (sym < 288) lens[sym++] = 8;
    huffman_build(&z->lencode, lens, 288, false);
    for (sym = 0; sym < 32; sym++)
        lens[sym] = 5;
    huffman_build(&z->distcode, lens, 32, false);
}

void bs_inflate_init(BsInflate *z) {
    memset(z, 0, sizeof *z);
    z->mode = M_TYPE;
}

BsInflateStatus bs_inflate(BsInflate *z) {
    const uint8_t *in = z->next_in;
    size_t have = z->avail_in;
    uint8_t *out = z->next_out;
    size_t left = z->avail_out;
    uint64_t hold = z->hold;
    unsigned bits = z->bits;
    unsigned wnext = z->wnext;
    uint64_t total = z->total_out;
    BsInflateStatus status = BS_INFLATE_OK;
    unsigned len = 0;
    int sym;

/* One more input byte into the bit buffer, or stop until there is one. */
#define PULLBYTE() \
    do { \
        if (have == 0) \
            goto leave; \
        have--; \
        hold += (uint64_t)*in++ << bits; \
        bits += 8; \
    } while (0)
#define NEEDBITS(n) \
    do { \
        while (bits < (unsigned)(n)) \
            PULLBYTE(); \
    } while (0)
#define BITS(n) ((unsigned)(hold & ((1u << (n)) - 1)))
#define DROPBITS(n) \
    do { \
        hold >>= (n); \
        bits -= (unsigned)(n); \
    } while (0)
#define FAIL(text) \
    do { \
        z->msg = (text); \
        z->mode = M_BAD; \
    } while (0)
#define EMIT(byte) \
    do { \
        uint8_t emitted = (uint8_t)(byte); \
        *out++ = emitted; \
        left--; \
        z->window[wnext] = emitted; \
        wnext = (wnext + 1) & (BS_INFLATE_WINDOW - 1); \
        total++; \
    } while (0)

    for (;;) {
        switch (z->mode) {
        case M_TYPE:
            if (z->last) {
                DROPBITS(bits & 7);
                z->mode = M_DONE;
                break;
            }
            NEEDBITS(3);
            z->last = BITS(1) != 0;
            DROPBITS(1);
            switch (BITS(2)) {
            case 0:
                z->mode = M_STORED;
                break;
            case 1:
                fixed_tables(z);
                z->mode = M_LEN;
                break;
            case 2:
                z->mode = M_TABLE;
                break;
            default:
                FAIL("invalid block type");
            }
            DROPBITS(2);
            break;

        case M_STORED:
            DROPBITS(bits & 7);         /* to a byte boundary */
            NEEDBITS(32);
            if ((hold & 0xffff) != (((hold >> 16) & 0xffff) ^ 0xffff)) {
                FAIL("invalid stored block lengths");
                break;
            }
            z->length = (unsigned)(hold & 0xffff);
            hold = 0;
            bits = 0;
            z->mode = M_COPY;
            /* fall through */
        case M_COPY:
            if (z->length != 0) {
                size_t copy = z->length;
                if (copy > have)
                    copy = have;
                if (copy > left)
                    copy = left;
                if (copy == 0)
                    goto leave;
                for (size_t i = 0; i < copy; i++)
                    EMIT(in[i]);
                in += copy;
                have -= copy;
                z->length -= (unsigned)copy;
                break;
            }
            z->mode = M_TYPE;
            break;

        case M_TABLE:
            NEEDBITS(14);
            z->nlen = BITS(5) + 257;
            DROPBITS(5);
            z->ndist = BITS(5) + 1;
            DROPBITS(5);
            z->ncode = BITS(4) + 4;
            DROPBITS(4);
            if (z->nlen > 286 || z->ndist > 30) {
                FAIL("too many length or distance symbols");
                break;
            }
            z->have = 0;
            z->mode = M_LENLENS;
            /* fall through */
        case M_LENLENS:
            while (z->have < z->ncode) {
                NEEDBITS(3);
                z->lens[LENGTH_ORDER[z->have++]] = (uint16_t)BITS(3);
                DROPBITS(3);
            }
            while (z->have < 19)
                z->lens[LENGTH_ORDER[z->have++]] = 0;
            if (!huffman_build(&z->codes, z->lens, 19, true)) {
                FAIL("invalid code lengths set");
                break;
            }
            z->have = 0;
            z->mode = M_CODELENS;
            /* fall through */
        case M_CODELENS:
            while (z->have < z->nlen + z->ndist) {
                for (;;) {
                    if (z->codes.kind == HUFF_EMPTY) {
                        /* zlib reads one bit per symbol from such a table
                         * and takes it for a length of zero. */
                        sym = bits >= 1 ? 0 : NEED_MORE;
                        len = 1;
                    } else {
                        sym = huffman_lookup(&z->codes, hold, bits, &len);
                    }
                    if (sym != NEED_MORE)
                        break;
                    PULLBYTE();
                }
                if (sym == NO_SUCH_CODE) {
                    FAIL("invalid code lengths set");
                    break;
                }
                if (sym < 16) {
                    DROPBITS(len);
                    z->lens[z->have++] = (uint16_t)sym;
                    continue;
                }
                unsigned repeat, value = 0;
                if (sym == 16) {
                    NEEDBITS(len + 2);
                    DROPBITS(len);
                    if (z->have == 0) {
                        FAIL("invalid bit length repeat");
                        break;
                    }
                    value = z->lens[z->have - 1];
                    repeat = 3 + BITS(2);
                    DROPBITS(2);
                } else if (sym == 17) {
                    NEEDBITS(len + 3);
                    DROPBITS(len);
                    repeat = 3 + BITS(3);
                    DROPBITS(3);
                } else {
                    NEEDBITS(len + 7);
                    DROPBITS(len);
                    repeat = 11 + BITS(7);
                    DROPBITS(7);
                }
                if (z->have + repeat > z->nlen + z->ndist) {
                    FAIL("invalid bit length repeat");
                    break;
                }
                while (repeat--)
                    z->lens[z->have++] = (uint16_t)value;
            }
            if (z->mode == M_BAD)
                break;
            if (z->lens[256] == 0) {
                FAIL("invalid code -- missing end-of-block");
                break;
            }
            if (!huffman_build(&z->lencode, z->lens, z->nlen, false)) {
                FAIL("invalid literal/lengths set");
                break;
            }
            if (!huffman_build(&z->distcode, z->lens + z->nlen, z->ndist, false)) {
                FAIL("invalid distances set");
                break;
            }
            z->mode = M_LEN;
            /* fall through */
        case M_LEN:
            for (;;) {
                sym = huffman_lookup(&z->lencode, hold, bits, &len);
                if (sym != NEED_MORE)
                    break;
                PULLBYTE();
            }
            if (sym == NO_SUCH_CODE) {
                FAIL("invalid literal/length code");
                break;
            }
            DROPBITS(len);
            if (sym < 256) {
                z->length = (unsigned)sym;
                z->mode = M_LIT;
                if (left == 0)
                    goto leave;
                EMIT(sym);
                z->mode = M_LEN;
                break;
            }
            if (sym == 256) {
                z->mode = M_TYPE;
                break;
            }
            if (sym > 285) {
                FAIL("invalid literal/length code");
                break;
            }
            z->length = LENGTH_BASE[sym - 257];
            z->extra = LENGTH_EXTRA[sym - 257];
            z->mode = M_LENEXT;
            /* fall through */
        case M_LENEXT:
            if (z->extra != 0) {
                NEEDBITS(z->extra);
                z->length += BITS(z->extra);
                DROPBITS(z->extra);
            }
            z->mode = M_DIST;
            /* fall through */
        case M_DIST:
            for (;;) {
                sym = huffman_lookup(&z->distcode, hold, bits, &len);
                if (sym != NEED_MORE)
                    break;
                PULLBYTE();
            }
            if (sym == NO_SUCH_CODE || sym >= 30) {
                FAIL("invalid distance code");
                break;
            }
            DROPBITS(len);
            z->offset = DISTANCE_BASE[sym];
            z->extra = DISTANCE_EXTRA[sym];
            z->mode = M_DISTEXT;
            /* fall through */
        case M_DISTEXT:
            if (z->extra != 0) {
                NEEDBITS(z->extra);
                z->offset += BITS(z->extra);
                DROPBITS(z->extra);
            }
            z->mode = M_MATCH;
            /* fall through */
        case M_MATCH: {
            if (left == 0)
                goto leave;
            if (z->offset > total) {
                FAIL("invalid distance too far back");
                break;
            }
            unsigned copy = z->length;
            if (copy > left)
                copy = (unsigned)left;
            unsigned from = (wnext - z->offset) & (BS_INFLATE_WINDOW - 1);
            z->length -= copy;
            while (copy--) {
                EMIT(z->window[from]);
                from = (from + 1) & (BS_INFLATE_WINDOW - 1);
            }
            if (z->length == 0)
                z->mode = M_LEN;
            break;
        }

        case M_LIT:
            if (left == 0)
                goto leave;
            EMIT(z->length);
            z->mode = M_LEN;
            break;

        case M_DONE:
            status = BS_INFLATE_END;
            goto leave;

        default:
            status = BS_INFLATE_ERROR;
            goto leave;
        }
    }

leave:
    z->next_in = in;
    z->avail_in = have;
    z->next_out = out;
    z->avail_out = left;
    z->hold = hold;
    z->bits = bits;
    z->wnext = wnext;
    z->total_out = total;
    return status;

#undef PULLBYTE
#undef NEEDBITS
#undef BITS
#undef DROPBITS
#undef FAIL
#undef EMIT
}

/* --- CRC-32 (IEEE 802.3, as used by ZIP) ---------------------------------------- */

static const uint32_t CRC_TABLE[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

uint32_t bs_crc32(uint32_t crc, const uint8_t *data, size_t size) {
    crc = ~crc;
    for (size_t i = 0; i < size; i++)
        crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}
