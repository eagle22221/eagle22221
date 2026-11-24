/* Printable-string extraction (ASCII and UTF-16LE) with light tagging of
 * strings that usually matter in reverse engineering (port of strings.py). */
#ifndef VEX_STRINGS_H
#define VEX_STRINGS_H

#include "model.h"

enum {
    TAG_URL = 1,
    TAG_IPV4 = 2,
    TAG_EMAIL = 4,
    TAG_REGISTRY = 8,
    TAG_PATH = 16
};

typedef struct {
    uint64_t offset;
    OptAddr vaddr;
    Str section;                /* STR_NONE outside every section */
    bool utf16;
    Str text;
    unsigned tags;              /* TAG_* bits */
} FoundString;

/* Tags for a string; 0 when it looks like nothing special. */
unsigned strings_classify(Str text);

/* Walks the file once and yields the strings in file-offset order. */
typedef struct {
    const Binary *binary;
    uint64_t min_length;
    bool want_ascii, want_utf16;
    uint64_t ascii_pos, utf16_pos;          /* where each search resumes */
    bool ascii_ready, utf16_ready;          /* a match is waiting */
    uint64_t ascii_start, ascii_end, utf16_start, utf16_end;
    struct SectionSpan *spans;              /* sections with file bytes, sorted */
    size_t nspans;
} StringScan;

/* encoding: "all", "ascii" or "utf16". */
void strings_begin(StringScan *scan, const Binary *b, Arena *a, big min_length,
                   const char *encoding);
/* Next string, or false at the end. `text` is allocated from `a` when it
 * cannot point into the file directly. */
bool strings_next(StringScan *scan, Arena *a, FoundString *out);

#endif
