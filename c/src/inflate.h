/* Raw DEFLATE (RFC 1951) decompression and CRC-32, written for binspect: no
 * zlib dependency.
 *
 * The decoder is a streaming one with the calling convention of zlib's
 * inflate(): the caller points next_in/avail_in at compressed bytes and
 * next_out/avail_out at room for output, and bs_inflate() runs until it
 * needs input it does not have, needs room it does not have, reaches the end
 * of the stream or finds an error. It also stops at exactly the places where
 * zlib stops (it takes input a byte at a time, only when a decision needs
 * it, and after filling the output it still parses up to the next thing that
 * would produce output). The ZIP reader depends on that: the Python edition
 * reads entries through zipfile and zlib, and whether a damaged entry is
 * still readable there follows from those stopping points.
 *
 * Safety: the decoder never reads beyond next_in + avail_in and never
 * writes beyond next_out + avail_out; back-references are served from its
 * own 32 KiB window and are refused when they point before the start of
 * the output. */
#ifndef BINSPECT_INFLATE_H
#define BINSPECT_INFLATE_H

#include "common.h"

#define BS_INFLATE_WINDOW 32768u

typedef enum {
    BS_INFLATE_OK = 0,          /* call again with more input and/or room */
    BS_INFLATE_END = 1,         /* the final block has been decoded */
    BS_INFLATE_ERROR = -1       /* invalid stream; msg says why */
} BsInflateStatus;

typedef struct {
    uint16_t count[16];         /* number of codes of each bit length */
    uint16_t symbol[288];       /* symbols in canonical code order */
    uint16_t fast[512];         /* 9-bit prefix -> length << 9 | symbol, or 0 */
    uint8_t kind;               /* complete, single one-bit code, or empty */
} BsHuffman;

typedef struct {
    const uint8_t *next_in;
    size_t avail_in;
    uint8_t *next_out;
    size_t avail_out;
    const char *msg;            /* set with BS_INFLATE_ERROR */

    /* private */
    int mode;
    bool last;                  /* current block is the final one */
    uint64_t hold;              /* bits taken from the input, not yet used */
    unsigned bits;              /* number of bits in hold */
    unsigned length;            /* stored bytes or match bytes still to copy */
    unsigned offset;            /* match distance */
    unsigned extra;             /* extra bits still to read */
    unsigned nlen, ndist, ncode, have;
    uint16_t lens[320];
    BsHuffman codes, lencode, distcode;
    uint64_t total_out;
    unsigned wnext;             /* where the next output byte goes in window */
    uint8_t window[BS_INFLATE_WINDOW];
} BsInflate;

void bs_inflate_init(BsInflate *z);
BsInflateStatus bs_inflate(BsInflate *z);

/* zlib.crc32(data, crc): start with crc = 0. */
uint32_t bs_crc32(uint32_t crc, const uint8_t *data, size_t size);

#endif
