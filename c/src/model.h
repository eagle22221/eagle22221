/* Format-independent description of a loaded binary (port of model.py and
 * reader.py). The ELF and PE parsers both fill in a Binary, so everything
 * downstream is written once. Addresses are absolute virtual addresses; for
 * PE that means image base + RVA.
 *
 * Addresses are `big`, not uint64_t: a hostile header can put a section at
 * image base 0xffffffffffffffff + RVA, and the Python reference then works
 * with (and prints) the unwrapped 65-bit sum. Keeping the same arithmetic is
 * what lets the two implementations agree on every input. */
#ifndef VEX_MODEL_H
#define VEX_MODEL_H

#include "common.h"

typedef struct {
    bool has;
    uint64_t v;
} OptU64;

typedef struct {
    bool has;
    big v;
} OptAddr;

typedef struct {
    Str name;
    big vaddr;              /* 0 when the section is not loaded into memory */
    uint64_t vsize;         /* size in memory */
    uint64_t offset;        /* file offset */
    uint64_t size;          /* bytes present in the file */
    char perms[4];          /* "r-x" style; "---" when not loaded */
    Str type;
} Section;

typedef struct {            /* ELF program header (PE files have none) */
    Str type;
    uint64_t vaddr, vsize, offset, size;
    char perms[4];
} Segment;

typedef struct {
    Str name;
    big address;
    uint64_t size;
    Str type;               /* func, object, notype, ... */
    Str binding;            /* local, global, weak */
    Str section;            /* may be STR_NONE */
} Symbol;

typedef struct {
    Str name;
    Str library;            /* may be STR_NONE */
    OptAddr address;        /* GOT slot (ELF) or IAT slot (PE) */
    OptU64 ordinal;         /* PE import by ordinal */
    Str version;            /* ELF symbol version, e.g. GLIBC_2.2.5 */
    bool delayed;           /* PE delay-load import */
} Import;

typedef struct {
    Str name;
    OptAddr address;        /* absent for forwarded exports */
    OptU64 ordinal;
    Str forwarder;          /* "OTHERDLL.Function" when forwarded */
} Export;

typedef struct {            /* file-backed address range */
    big vaddr;
    uint64_t offset, size;
} Map;

typedef struct {            /* part of the file that is not a section */
    const char *name;
    uint64_t offset, size;
    const char *kind;
} Region;

typedef struct {
    big start, end;
} Range;

/* One entry of the `security` or `metadata` dictionaries. */
typedef enum { META_NONE, META_BOOL, META_INT, META_STR, META_LIST, META_OVERLAY } MetaKind;

typedef struct {
    const char *key;
    MetaKind kind;
    bool flag;
    uint64_t number;        /* META_INT; overlay offset for META_OVERLAY */
    uint64_t number2;       /* overlay size */
    Str text;
    Str *items;             /* META_LIST */
    size_t count;
} Meta;

typedef VEC(Meta) MetaDict;

typedef struct Binary {
    Arena *arena;
    Err *err;
    const uint8_t *data;
    uint64_t size;
    const char *path;       /* as given by the user; may be NULL */
    const char *format;     /* "ELF" or "PE" */
    Str arch;
    int bits;
    const char *endian;
    const char *kind;
    OptAddr entry;
    uint64_t image_base;
    VEC(Section) sections;
    VEC(Segment) segments;
    VEC(Symbol) symbols;
    VEC(Import) imports;
    VEC(Export) exports;
    VEC(Str) libraries;
    MetaDict security;
    MetaDict metadata;
    VEC(Str) warnings;
    VEC(Range) function_ranges;     /* exact bounds from the PE exception table */
    VEC(Region) regions;
    VEC(Map) maps;
} Binary;

/* Parse an in-memory ELF or PE image. Throws ERR_UNKNOWN_FORMAT or ERR_PARSE
 * through `err`; never executes anything. `data` must outlive the Binary. */
Binary *binary_load(Arena *arena, Err *err, const uint8_t *data, uint64_t size,
                    const char *path);
void elf_parse(Binary *b);
void pe_parse(Binary *b);

void binary_warn(Binary *b, const char *fmt, ...) PRINTF_LIKE(2, 3);
void binary_add_map(Binary *b, big vaddr, big offset, big size);
void binary_note_overlay(Binary *b, big end_of_image);
const Map *binary_map_for(const Binary *b, big vaddr);
bool binary_vaddr_to_offset(const Binary *b, big vaddr, uint64_t *offset);
bool binary_offset_to_vaddr(const Binary *b, uint64_t offset, big *vaddr);
/* Up to `size` bytes at a virtual address; *got is shorter (or 0) when the
 * range is not backed by the file. */
const uint8_t *binary_read(const Binary *b, big vaddr, big size, uint64_t *got);
const Section *binary_section_at(const Binary *b, big vaddr);
bool binary_is_address(const Binary *b, big vaddr);
/* Every file-backed range holding code, sorted by address. */
typedef struct {
    big start;
    uint64_t size;
} CodeRange;
typedef VEC(CodeRange) CodeRanges;
void binary_executable_ranges(const Binary *b, Arena *a, CodeRanges *out);

Meta *meta_slot(Arena *a, MetaDict *dict, const char *key);  /* dict[key], created or reused */
const Meta *meta_get(const MetaDict *dict, const char *key);
void meta_set_str(Arena *a, MetaDict *dict, const char *key, Str value);
void meta_set_bool(Arena *a, MetaDict *dict, const char *key, bool value);

/* Shannon entropy in bits per byte, computed exactly like model.entropy. */
double entropy(const uint8_t *data, uint64_t size);

/* --- bounds-checked reads ------------------------------------------------------
 * Offsets and counts in these files are attacker-controlled. Every access to
 * the file goes through a Reader, which turns a bad offset into ERR_PARSE. */

typedef struct {
    const uint8_t *data;
    uint64_t size;
    bool little_endian;
    Err *err;
} Reader;

/* `size` bytes at `offset`. The try variant returns NULL after err_set(). */
const uint8_t *rd_try(const Reader *r, big offset, big size);
const uint8_t *rd_bytes(const Reader *r, big offset, big size);
uint8_t rd_u8(const Reader *r, big offset);
uint16_t rd_u16(const Reader *r, big offset);
uint32_t rd_u32(const Reader *r, big offset);
uint64_t rd_u64(const Reader *r, big offset);
/* Decode a field of a structure already fetched with rd_bytes(). */
uint16_t rd_get16(const Reader *r, const uint8_t *p);
uint32_t rd_get32(const Reader *r, const uint8_t *p);
uint64_t rd_get64(const Reader *r, const uint8_t *p);
/* NUL-terminated string at offset, at most `limit` bytes, decoded as UTF-8. */
bool rd_cstring_try(const Reader *r, Arena *a, big offset, big limit, Str *out);
Str rd_cstring(const Reader *r, Arena *a, big offset, big limit);

/* Set of strings (membership only). */
typedef struct {
    Str *slots;
    size_t cap, count;
} StrSet;

bool strset_has(const StrSet *set, Str s);
/* True when the string was not in the set before. */
bool strset_add(Arena *a, StrSet *set, Str s);

#endif
