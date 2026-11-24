/* Game asset packs: ZIP family, Quake PAK, Doom WAD and Godot PCK (the C
 * counterpart of binspect/archives/). Electron ASAR and Ren'Py RPA are
 * detected but only opened in the Python edition.
 *
 * A container's index is attacker-controlled, so the rules of archives.py
 * are followed here too: nothing is read with a size taken from the file
 * before that size has been checked against the real file size; entry data
 * is only read as ranges of the file, in chunks; names from the file are
 * never used as filesystem paths without going through safe_parts(). */
#include "archives.h"

#include <errno.h>

#include "fswalk.h"
#include "hash.h"
#include "inflate.h"
#include "platform.h"

/* Zip-bomb guards (archives.DEFAULT_MAX_ENTRY_SIZE and friends). */
#define DEFAULT_MAX_ENTRY_SIZE ((uint64_t)1 << 30)      /* one entry: 1 GiB */
#define DEFAULT_MAX_TOTAL_SIZE ((uint64_t)8 << 30)      /* one extract: 8 GiB */
#define MAX_ENTRIES ((uint64_t)1000000)
#define MAX_INDEX_SIZE ((uint64_t)256 << 20)
#define CHUNK ((size_t)1 << 20)

typedef enum { F_ZIP, F_PAK, F_WAD, F_PCK, F_ASAR, F_RPA } Format;

/* One record of a container. For ZIP this includes directory entries, which
 * are not listed but are preserved on repack; the public entry list holds
 * only the files. */
typedef struct {
    Str name;               /* display name (NUL-terminated), after suffixing */
    uint64_t size;          /* uncompressed size */
    bool compressed;
    bool encrypted;
    bool has_offset;
    uint64_t offset;        /* data offset in the file (stored formats) */
    const char *broken;     /* reason the data is not in the file, or NULL */
    Str raw_name;           /* name bytes exactly as stored (repack) */
    bool is_dir;            /* ZIP directory entry */
    /* ZIP */
    uint32_t method;
    uint64_t comp_size;
    uint64_t local_abs;     /* absolute file offset of the local header */
    uint16_t flags;
    uint16_t mtime, mdate;
    uint32_t crc;
    uint32_t external_attr;
    uint16_t internal_attr, version_made;
    /* PCK */
    const uint8_t *md5;     /* 16 bytes */
    uint32_t pck_flags;
} Rec;

struct BsArchive {
    Arena *arena;           /* owned; freed by bs_archive_close */
    const char *path;
    Format fmt;
    const char *format;     /* "zip", "quake-pak", ... */
    uint64_t file_size;
    bool writable;
    const char *readonly_reason;

    Rec *rec;
    size_t nrec, cap_rec;
    size_t *pub;            /* indices into rec[] that are listed files */
    size_t npub;
    BsArchiveEntry *entries;        /* parallel to pub */
    const char **notes;
    size_t nnotes, cap_notes;
    uint64_t max_entry_size, max_total_size;

    /* ZIP layout */
    uint64_t zip_prefix;
    bool zip_relative;
    uint8_t head[64];
    size_t headn;

    /* PCK layout */
    int pck_format;
    uint64_t pck_start;
    uint32_t pck_pack_flags;
    const uint8_t *pck_header;      /* first 20 bytes of the pack */
    const uint8_t *pck_reserved;    /* 64 bytes (formats 1/2) */
    bool pck_embedded;

    /* WAD layout */
    char wad_magic[4];
};

/* Context threaded through the parsers and workers. */
typedef struct {
    BsArchive *a;
    Arena *a_arena;         /* arena to allocate scratch into */
    Err *err;
} Ctx;

/* --- little-endian reads/writes ----------------------------------------------- */

static uint16_t ld16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t ld64(const uint8_t *p) {
    return (uint64_t)ld32(p) | (uint64_t)ld32(p + 4) << 32;
}
static void st16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void st64(uint8_t *p, uint64_t v) { st32(p, (uint32_t)v); st32(p + 4, (uint32_t)(v >> 32)); }

/* --- bounded file reads ------------------------------------------------------- */

static const uint8_t *fetch(Ctx *c, FILE *f, uint64_t total, big offset, big size,
                            const char *what) {
    char ob[40], sb[44];
    if (offset < 0 || size < 0 || (ubig)offset + (ubig)size > (ubig)total)
        err_throw(c->err, ERR_PARSE, "%s at offset %s (+%s bytes) is outside the file "
                  "(%" PRIu64 " bytes)", what, hex_big(ob, offset), dec_big(sb, size), total);
    uint8_t *buf = arena_alloc(c->a_arena, (size_t)size ? (size_t)size : 1);
    if (!fs_seek(f, (uint64_t)offset) || fread(buf, 1, (size_t)size, f) != (size_t)size)
        err_throw(c->err, ERR_PARSE, "%s at offset %s: the file ends early", what,
                  hex_big(ob, offset));
    return buf;
}

/* --- names -------------------------------------------------------------------- */

static const char *unsafe_reason(Str name) {
    if (name.n == 0)
        return "empty name";
    for (size_t i = 0; i < name.n; i++)
        if (name.p[i] == '\0')
            return "NUL byte";
    for (size_t i = 0; i < name.n; i++)
        if (name.p[i] == '\\')
            return "backslash";
    if (name.p[0] == '/')
        return "absolute path";
    size_t start = 0;
    for (size_t i = 0; i <= name.n; i++) {
        if (i == name.n || name.p[i] == '/') {
            size_t len = i - start;
            if (len == 0)
                return "empty path component";
            if (len == 1 && name.p[start] == '.')
                return "'.' path component";
            if (len == 2 && name.p[start] == '.' && name.p[start + 1] == '.')
                return "'..' path component";
            if (len >= 2 && name.p[start + 1] == ':' &&
                ((name.p[start] >= 'A' && name.p[start] <= 'Z') ||
                 (name.p[start] >= 'a' && name.p[start] <= 'z')))
                return "drive letter";
            start = i + 1;
        }
    }
    return NULL;
}

static const uint16_t CP437[128] = {
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB,
    0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4,
    0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5,
    0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, 0x2591, 0x2592,
    0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C,
    0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518,
    0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, 0x03B1, 0x00DF, 0x0393, 0x03C0,
    0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6,
    0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};

static void append_cp(Buf *b, uint32_t cp) {
    if (cp < 0x80) {
        buf_addch(b, (char)cp);
    } else if (cp < 0x800) {
        buf_addch(b, (char)(0xC0 | cp >> 6));
        buf_addch(b, (char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        buf_addch(b, (char)(0xE0 | cp >> 12));
        buf_addch(b, (char)(0x80 | (cp >> 6 & 0x3F)));
        buf_addch(b, (char)(0x80 | (cp & 0x3F)));
    } else {
        buf_addch(b, (char)(0xF0 | cp >> 18));
        buf_addch(b, (char)(0x80 | (cp >> 12 & 0x3F)));
        buf_addch(b, (char)(0x80 | (cp >> 6 & 0x3F)));
        buf_addch(b, (char)(0x80 | (cp & 0x3F)));
    }
}

static Str latin1_decode(Arena *a, const uint8_t *p, size_t n) {
    Buf b;
    buf_init(&b, a);
    for (size_t i = 0; i < n; i++)
        append_cp(&b, p[i]);
    return buf_str(&b);
}

static bool is_valid_utf8(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = p[i];
        size_t need;
        if (c < 0x80) { i++; continue; }
        else if (c >= 0xC2 && c < 0xE0) need = 2;
        else if (c >= 0xE0 && c < 0xF0) need = 3;
        else if (c >= 0xF0 && c < 0xF5) need = 4;
        else return false;
        if (i + need > n) return false;
        if (need == 3 && c == 0xE0 && p[i + 1] < 0xA0) return false;
        if (need == 3 && c == 0xED && p[i + 1] >= 0xA0) return false;
        if (need == 4 && c == 0xF0 && p[i + 1] < 0x90) return false;
        if (need == 4 && c == 0xF4 && p[i + 1] >= 0x90) return false;
        for (size_t k = 1; k < need; k++)
            if ((p[i + k] & 0xC0) != 0x80) return false;
        i += need;
    }
    return true;
}

static Str decode_name(Arena *a, const uint8_t *p, size_t n) {
    if (is_valid_utf8(p, n))
        return str_copy(a, (const char *)p, n);
    return latin1_decode(a, p, n);
}

static Str zip_name(Arena *a, const uint8_t *p, size_t n, bool utf8_flag) {
    if (utf8_flag)
        return utf8_decode(a, p, n);
    Buf b;
    buf_init(&b, a);
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = p[i];
        append_cp(&b, ch < 0x80 ? ch : CP437[ch - 0x80]);
    }
    return buf_str(&b);
}

static const char *reprn(Arena *a, Str name) {
    return py_repr(a, name.p ? name.p : "").p;
}

static Str human(Arena *a, uint64_t size) {
    static const char *units[4] = {"bytes", "KiB", "MiB", "GiB"};
    double val = (double)size;
    for (int i = 0; i < 4; i++) {
        if (val < 1024.0 || i == 3) {
            if (i == 0)
                return str_printf(a, "%" PRIu64 " bytes", size);
            return str_printf(a, "%.1f %s", val, units[i]);
        }
        val /= 1024.0;
    }
    return str_printf(a, "%" PRIu64 " bytes", size);
}

/* --- record and note lists ---------------------------------------------------- */

static Rec *add_rec(BsArchive *a) {
    if (a->nrec == a->cap_rec) {
        size_t cap = a->cap_rec ? a->cap_rec * 2 : 16;
        Rec *grown = arena_array(a->arena, cap, sizeof *grown);
        if (a->nrec)
            memcpy(grown, a->rec, a->nrec * sizeof *grown);
        a->rec = grown;
        a->cap_rec = cap;
    }
    Rec *r = &a->rec[a->nrec++];
    memset(r, 0, sizeof *r);
    return r;
}

static void note(BsArchive *a, Str text) {
    for (size_t i = 0; i < a->nnotes; i++)
        if (str_eq_c(text, a->notes[i]))
            return;
    if (a->nnotes == a->cap_notes) {
        size_t cap = a->cap_notes ? a->cap_notes * 2 : 8;
        const char **grown = arena_array(a->arena, cap, sizeof *grown);
        if (a->nnotes)
            memcpy(grown, a->notes, a->nnotes * sizeof *grown);
        a->notes = grown;
        a->cap_notes = cap;
    }
    a->notes[a->nnotes++] = text.p;
}

static void read_only(BsArchive *a, Str reason) {
    a->writable = false;
    if (a->readonly_reason == NULL)
        a->readonly_reason = reason.p;
    note(a, reason);
}

static void check_count(Ctx *c, uint64_t count, const char *what) {
    if (count > MAX_ENTRIES)
        err_throw(c->err, ERR_UNSUPPORTED, "%s archive declares %" PRIu64 " %s, more than "
                  "binspect.archives.MAX_ENTRIES (%" PRIu64 ")", c->a->format, count, what,
                  MAX_ENTRIES);
}

static void finish(Ctx *c) {
    BsArchive *a = c->a;
    Arena *ar = a->arena;
    a->pub = arena_array(ar, a->nrec ? a->nrec : 1, sizeof *a->pub);
    a->npub = 0;
    for (size_t i = 0; i < a->nrec; i++)
        if (!a->rec[i].is_dir)
            a->pub[a->npub++] = i;

    Str *base = arena_array(ar, a->npub ? a->npub : 1, sizeof *base);
    for (size_t i = 0; i < a->npub; i++)
        base[i] = a->rec[a->pub[i]].name;

    size_t renamed = 0;
    for (size_t i = 0; i < a->npub; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++)
            if (str_eq(a->rec[a->pub[j]].name, base[i])) { seen = true; break; }
        if (!seen) {
            a->rec[a->pub[i]].name = base[i];
            continue;
        }
        unsigned n = 1;
        Str candidate = STR_NONE;
        for (;;) {
            n++;
            candidate = str_printf(ar, "%.*s#%u", (int)base[i].n, base[i].p, n);
            bool clash = false;
            for (size_t j = 0; j < i && !clash; j++)
                if (str_eq(a->rec[a->pub[j]].name, candidate)) clash = true;
            for (size_t j = 0; j < a->npub && !clash; j++)
                if (str_eq(base[j], candidate)) clash = true;
            if (!clash)
                break;
        }
        a->rec[a->pub[i]].name = candidate;
        renamed++;
    }

    size_t broken = 0, encrypted = 0;
    for (size_t i = 0; i < a->npub; i++) {
        if (a->rec[a->pub[i]].broken) broken++;
        if (a->rec[a->pub[i]].encrypted) encrypted++;
    }
    if (renamed)
        note(a, str_printf(ar, "%zu entries share a name with an earlier entry and are listed "
                           "with a #N suffix", renamed));
    if (broken)
        note(a, str_printf(ar, "%zu entries point outside the file (truncated or corrupt "
                           "archive) and cannot be read", broken));
    if (encrypted)
        read_only(a, str_printf(ar, "%zu entries are encrypted; binspect does not decrypt them "
                                "and cannot repack this archive", encrypted));

    a->entries = arena_array(ar, a->npub ? a->npub : 1, sizeof *a->entries);
    for (size_t i = 0; i < a->npub; i++) {
        Rec *r = &a->rec[a->pub[i]];
        a->entries[i].name = r->name.p;
        a->entries[i].size = r->size;
        a->entries[i].compressed = r->compressed;
        a->entries[i].encrypted = r->encrypted;
    }
}

/* =============================================================================
 * Detection
 * ========================================================================== */

static const uint8_t *EXE_MAGICS[] = {
    (const uint8_t *)"MZ", (const uint8_t *)"\x7f" "ELF", (const uint8_t *)"\xcf\xfa\xed\xfe",
    (const uint8_t *)"\xce\xfa\xed\xfe", (const uint8_t *)"\xca\xfe\xba\xbe"};
static const size_t EXE_MAGIC_LEN[] = {2, 4, 4, 4, 4};

static bool head_is_exe(const uint8_t *head, size_t n) {
    for (size_t i = 0; i < 5; i++)
        if (n >= EXE_MAGIC_LEN[i] && memcmp(head, EXE_MAGICS[i], EXE_MAGIC_LEN[i]) == 0)
            return true;
    return false;
}

typedef struct { uint64_t eocd, cd_start, cd_size, cd_offset, count; } ZipTail;

static bool zip_tail(FILE *f, uint64_t size, ZipTail *out) {
    if (size < 22)
        return false;
    uint64_t span = size < 22 + 0xFFFF ? size : 22 + 0xFFFF;
    uint8_t *tail = malloc((size_t)span);
    if (tail == NULL)
        die_out_of_memory();
    if (!fs_seek(f, size - span) || fread(tail, 1, (size_t)span, f) != span) {
        free(tail);
        return false;
    }
    long at = -1;
    for (long i = (long)span - 22; i >= 0; i--)
        if (memcmp(tail + i, "PK\x05\x06", 4) == 0) { at = i; break; }
    if (at < 0 || (uint64_t)at + 22 > span) { free(tail); return false; }
    uint64_t eocd = size - span + (uint64_t)at;
    uint64_t count = ld16(tail + at + 10);
    uint64_t cd_size = ld32(tail + at + 12);
    uint64_t cd_offset = ld32(tail + at + 16);
    uint64_t cd_end = eocd;
    if (eocd >= 20 + 56) {
        uint8_t z64[56 + 20];
        if (fs_seek(f, eocd - 20 - 56) && fread(z64, 1, sizeof z64, f) == sizeof z64 &&
            memcmp(z64, "PK\x06\x06", 4) == 0 && memcmp(z64 + 56, "PK\x06\x07", 4) == 0) {
            count = ld64(z64 + 24);
            cd_size = ld64(z64 + 40);
            cd_offset = ld64(z64 + 48);
            cd_end = eocd - 20 - 56;
        }
    }
    free(tail);
    if (cd_size > cd_end)
        return false;
    uint64_t cd_start = cd_end - cd_size;
    if (cd_size) {
        uint8_t sig[4];
        if (!fs_seek(f, cd_start) || fread(sig, 1, 4, f) != 4 || memcmp(sig, "PK\x01\x02", 4) != 0)
            return false;
    } else if (count) {
        return false;
    }
    out->eocd = eocd;
    out->cd_start = cd_start;
    out->cd_size = cd_size;
    out->cd_offset = cd_offset;
    out->count = count;
    return true;
}

static int64_t pck_find(const uint8_t *head, size_t headn, FILE *f, uint64_t size) {
    if (headn >= 4 && memcmp(head, "GDPC", 4) == 0)
        return 0;
    if (size < 12 + 20)
        return -1;
    uint8_t tail[12];
    if (!fs_seek(f, size - 12) || fread(tail, 1, 12, f) != 12 || memcmp(tail + 8, "GDPC", 4) != 0)
        return -1;
    uint64_t packsize = ld64(tail);
    if ((ubig)packsize + 12 > size)
        return -1;
    uint64_t start = size - 12 - packsize;
    if (start == 0 || (ubig)start + 20 > (ubig)size - 12)
        return -1;
    uint8_t sig[4];
    if (!fs_seek(f, start) || fread(sig, 1, 4, f) != 4 || memcmp(sig, "GDPC", 4) != 0)
        return -1;
    return (int64_t)start;
}

static bool asar_matches(const uint8_t *head, size_t n) {
    if (n < 17)
        return false;
    uint32_t four = ld32(head), header_size = ld32(head + 4);
    uint32_t payload = ld32(head + 8), json_len = ld32(head + 12);
    if (four != 4 || header_size != payload + 4 || (uint64_t)json_len + 4 > payload || json_len < 2)
        return false;
    return head[16] == '{';
}

static bool rpa_matches(const uint8_t *head, size_t n) {
    if (n < 5 || memcmp(head, "RPA-", 4) != 0)
        return false;
    size_t i = 4, d = i;
    while (i < n && head[i] >= '0' && head[i] <= '9') i++;
    if (i == d || i >= n || head[i] != '.') return false;
    i++;
    d = i;
    while (i < n && head[i] >= '0' && head[i] <= '9') i++;
    if (i == d || i >= n || head[i] != ' ') return false;
    return true;
}

static bool detect(const uint8_t *head, size_t headn, FILE *f, uint64_t size, Format *out) {
    if (headn >= 4 && memcmp(head, "PACK", 4) == 0) { *out = F_PAK; return true; }
    if (headn >= 4 && (memcmp(head, "IWAD", 4) == 0 || memcmp(head, "PWAD", 4) == 0)) {
        *out = F_WAD; return true;
    }
    if (rpa_matches(head, headn)) { *out = F_RPA; return true; }
    if (pck_find(head, headn, f, size) >= 0) { *out = F_PCK; return true; }
    if (asar_matches(head, headn)) { *out = F_ASAR; return true; }
    if (headn >= 4 && (memcmp(head, "PK\x03\x04", 4) == 0 || memcmp(head, "PK\x05\x06", 4) == 0)) {
        *out = F_ZIP; return true;
    }
    ZipTail t;
    if (zip_tail(f, size, &t)) { *out = F_ZIP; return true; }
    return false;
}

bool bs_is_archive(const char *path) {
    if (path == NULL)
        return false;
    uint64_t size = 0;
    bool not_regular = false;
    FILE *f = fs_open_regular(path, &size, &not_regular);
    if (f == NULL)
        return false;
    uint8_t head[64];
    size_t headn = fread(head, 1, sizeof head, f);
    Format fmt;
    bool ok = detect(head, headn, f, size, &fmt);
    fclose(f);
    return ok;
}

/* =============================================================================
 * Format parsers
 * ========================================================================== */

static void load_pak(Ctx *c, FILE *f, uint64_t size, const uint8_t *head, size_t headn) {
    BsArchive *a = c->a;
    a->format = "quake-pak";
    if (headn < 12)
        err_throw(c->err, ERR_PARSE, "truncated PAK header");
    uint32_t dir_offset = ld32(head + 4), dir_len = ld32(head + 8);
    char ob[40];
    if (dir_len % 64)
        err_throw(c->err, ERR_PARSE, "PAK directory length %" PRIu32 " is not a multiple of 64 "
                  "(not a Quake PAK, or corrupt)", dir_len);
    if (dir_offset < 12 || (ubig)dir_offset + dir_len > size)
        err_throw(c->err, ERR_PARSE, "PAK directory at offset %s (+%" PRIu32 " bytes) is outside "
                  "the file (%" PRIu64 " bytes)", hex_big(ob, dir_offset), dir_len, size);
    uint64_t count = dir_len / 64;
    check_count(c, count, "entries");
    const uint8_t *table = fetch(c, f, size, dir_offset, dir_len, "PAK directory");
    for (uint64_t i = 0; i < count; i++) {
        const uint8_t *e = table + i * 64;
        size_t namelen = 0;
        while (namelen < 56 && e[namelen] != '\0') namelen++;
        uint32_t offset = ld32(e + 56), length = ld32(e + 60);
        Rec *r = add_rec(a);
        r->raw_name = str_copy(a->arena, (const char *)e, namelen);
        r->name = decode_name(a->arena, e, namelen);
        r->size = length;
        r->offset = offset;
        r->has_offset = true;
        if ((ubig)offset + length > size)
            r->broken = str_printf(a->arena, "data at offset %s (+%" PRIu32 " bytes) is outside "
                                   "the file (%" PRIu64 " bytes)", hex_big(ob, offset),
                                   length, size).p;
    }
    finish(c);
}

static void load_wad(Ctx *c, FILE *f, uint64_t size, const uint8_t *head, size_t headn) {
    BsArchive *a = c->a;
    a->format = "doom-wad";
    if (headn < 12)
        err_throw(c->err, ERR_PARSE, "truncated WAD header");
    uint32_t count = ld32(head + 4), dir_offset = ld32(head + 8);
    memcpy(a->wad_magic, head, 4);
    char ob[40];
    if (count > 0x7FFFFFFF)
        err_throw(c->err, ERR_PARSE, "WAD lump count %lld is negative",
                  (long long)count - ((long long)1 << 32));
    if (dir_offset < 12 || (ubig)dir_offset + (ubig)count * 16 > size)
        err_throw(c->err, ERR_PARSE, "WAD directory at offset %s (%" PRIu32 " lumps) is outside "
                  "the file (%" PRIu64 " bytes)", hex_big(ob, dir_offset), count, size);
    check_count(c, count, "lumps");
    const uint8_t *table = fetch(c, f, size, dir_offset, (big)count * 16, "WAD directory");
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = table + i * 16;
        uint32_t offset = ld32(e), length = ld32(e + 4);
        size_t namelen = 0;
        while (namelen < 8 && e[8 + namelen] != '\0') namelen++;
        Rec *r = add_rec(a);
        r->raw_name = str_copy(a->arena, (const char *)(e + 8), namelen);
        r->name = latin1_decode(a->arena, e + 8, namelen);
        r->size = length;
        r->offset = offset;
        r->has_offset = length != 0;
        if (length && (ubig)offset + length > size)
            r->broken = str_printf(a->arena, "data at offset %s (+%" PRIu32 " bytes) is outside "
                                   "the file (%" PRIu64 " bytes)", hex_big(ob, offset),
                                   length, size).p;
    }
    note(a, str_printf(a->arena, "%.4s: lump order is significant (markers, maps) and is "
                       "preserved; additions are appended at the end", (const char *)head));
    finish(c);
}

#define PACK_DIR_ENCRYPTED 1u
#define PACK_REL_FILEBASE 2u
#define PACK_SPARSE_BUNDLE 4u
#define FILE_ENCRYPTED 1u
#define FILE_REMOVAL 2u

static void load_pck(Ctx *c, FILE *f, uint64_t size, const uint8_t *head, size_t headn) {
    BsArchive *a = c->a;
    a->format = "godot-pck";
    int64_t start = pck_find(head, headn, f, size);
    if (start < 0)
        err_throw(c->err, ERR_PARSE, "Godot pack signature not found");
    a->pck_start = (uint64_t)start;
    const uint8_t *ph = fetch(c, f, size, start, 20, "PCK header");
    a->pck_header = ph;
    uint32_t fmt = ld32(ph + 4), major = ld32(ph + 8), minor = ld32(ph + 12), patch = ld32(ph + 16);
    a->pck_format = (int)fmt;
    if (fmt != 1 && fmt != 2 && fmt != 3)
        err_throw(c->err, ERR_UNSUPPORTED, "Godot pack format version %" PRIu32 " is not supported "
                  "(binspect reads formats 1 to 3, Godot 3.x and 4.x)", fmt);
    uint64_t pos = (uint64_t)start + 20;
    uint32_t flags = 0;
    uint64_t file_base = 0;
    if (fmt >= 2) {
        const uint8_t *fb = fetch(c, f, size, (big)pos, 12, "PCK header");
        flags = ld32(fb);
        file_base = ld64(fb + 4);
        pos += 12;
        if (fmt == 3 || (flags & PACK_REL_FILEBASE))
            file_base += (uint64_t)start;
    }
    a->pck_pack_flags = flags;
    if (fmt == 3) {
        const uint8_t *dof = fetch(c, f, size, (big)pos, 8, "PCK header");
        pos = (uint64_t)start + ld64(dof);
        a->pck_reserved = NULL;
    } else {
        a->pck_reserved = fetch(c, f, size, (big)pos, 64, "PCK header");
        pos += 64;
    }
    if (flags & PACK_DIR_ENCRYPTED)
        err_throw(c->err, ERR_UNSUPPORTED, "the index (directory) of this Godot pack is encrypted "
                  "with a key compiled into the game; binspect does not decrypt packs or recover "
                  "keys");
    if (flags & PACK_SPARSE_BUNDLE)
        err_throw(c->err, ERR_UNSUPPORTED, "this Godot pack is a sparse bundle (file data is "
                  "stored outside the pack), which binspect does not support");
    const uint8_t *cb = fetch(c, f, size, (big)pos, 4, "PCK file count");
    uint32_t count = ld32(cb);
    pos += 4;
    uint32_t fixed = fmt == 1 ? 32 : 36;
    if ((ubig)count * (4 + fixed) > (ubig)size - pos)
        err_throw(c->err, ERR_PARSE, "Godot pack declares %" PRIu32 " files but only %" PRIu64
                  " bytes follow its header", count, size - pos);
    check_count(c, count, "files");
    uint64_t directory_start = pos, removals = 0;
    char ob[40];
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *lb = fetch(c, f, size, (big)pos, 4, "PCK directory");
        uint32_t length = ld32(lb);
        if (length > 4096)
            err_throw(c->err, ERR_PARSE, "Godot pack path length %" PRIu32 " is implausible", length);
        const uint8_t *row = fetch(c, f, size, (big)pos + 4, (big)length + fixed, "PCK directory");
        pos += 4 + length + fixed;
        if (pos - directory_start > MAX_INDEX_SIZE)
            err_throw(c->err, ERR_UNSUPPORTED,
                      "Godot pack directory exceeds binspect.archives.MAX_INDEX_SIZE");
        size_t rawlen = 0;
        while (rawlen < length && row[rawlen] != '\0') rawlen++;
        uint64_t offset = ld64(row + length), length_ = ld64(row + length + 8);
        const uint8_t *md5 = row + length + 16;
        uint32_t fflags = fmt >= 2 ? ld32(row + length + 32) : 0;
        if (fmt >= 2)
            offset += file_base;
        Str name = utf8_decode(a->arena, row, rawlen);
        if (name.n >= 6 && memcmp(name.p, "res://", 6) == 0)
            name = str_copy(a->arena, name.p + 6, name.n - 6);
        Rec *r = add_rec(a);
        r->raw_name = str_copy(a->arena, (const char *)row, rawlen);
        r->name = name;
        r->size = length_;
        r->offset = offset;
        r->has_offset = true;
        r->encrypted = (fflags & FILE_ENCRYPTED) != 0;
        r->pck_flags = fflags;
        uint8_t *md5copy = arena_alloc(a->arena, 16);
        memcpy(md5copy, md5, 16);
        r->md5 = md5copy;
        if ((ubig)offset + length_ > size)
            r->broken = str_printf(a->arena, "data at offset %s (+%" PRIu64 " bytes) is outside "
                                   "the file (%" PRIu64 " bytes)", hex_big(ob, (big)offset),
                                   length_, size).p;
        if (fflags & FILE_REMOVAL)
            removals++;
    }
    if (fmt == 2 && a->nrec && pos > file_base)
        err_throw(c->err, ERR_PARSE, "Godot pack directory runs past the start of the file data "
                  "(file count or file base is corrupt)");
    a->pck_embedded = start > 0;
    note(a, str_printf(a->arena, "Godot %" PRIu32 ".%" PRIu32 ".%" PRIu32 ", pack format %" PRIu32,
                       major, minor, patch, fmt));
    if (a->pck_embedded) {
        const char *kind = head_is_exe(head, headn) ? "executable" : "file";
        note(a, str_printf(a->arena, "embedded in %s at offset %s", kind,
                           hex_big(ob, (big)start)));
        note(a, str_c("repacking writes a copy of the whole file with the new pack and a corrected "
                      "footer in place of the old one (a code signature on the executable, if any, "
                      "will no longer match)"));
    }
    if (removals)
        note(a, str_printf(a->arena, "%" PRIu64 " entries are removal markers of a patch pack",
                           removals));
    if (fmt == 3)
        read_only(a, str_c("pack format 3 (Godot 4.5+) is read-only in binspect: listing and "
                           "extraction work, repacking is not implemented"));
    finish(c);
}

static void zip64_extra(const uint8_t *extra, size_t extralen, uint64_t *uncomp, uint64_t *comp,
                        uint64_t *header_offset) {
    size_t pos = 0;
    while (pos + 4 <= extralen) {
        uint16_t id = ld16(extra + pos), len = ld16(extra + pos + 2);
        if (pos + 4 + len > extralen)
            break;
        if (id == 1) {
            const uint8_t *p = extra + pos + 4;
            size_t left = len;
            if (*uncomp == 0xFFFFFFFF && left >= 8) { *uncomp = ld64(p); p += 8; left -= 8; }
            if (*comp == 0xFFFFFFFF && left >= 8) { *comp = ld64(p); p += 8; left -= 8; }
            if (*header_offset == 0xFFFFFFFF && left >= 8) { *header_offset = ld64(p); }
            return;
        }
        pos += 4 + len;
    }
}

static bool path_has_suffix_ci(const char *path, const char *suffix) {
    size_t pl = strlen(path), sl = strlen(suffix);
    if (pl < sl)
        return false;
    for (size_t i = 0; i < sl; i++) {
        char ch = path[pl - sl + i];
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        if (ch != suffix[i])
            return false;
    }
    return true;
}

static void load_zip(Ctx *c, FILE *f, uint64_t size, const uint8_t *head, size_t headn) {
    BsArchive *a = c->a;
    a->format = "zip";
    ZipTail t;
    if (!zip_tail(f, size, &t))
        err_throw(c->err, ERR_PARSE, "ZIP end-of-central-directory record is missing or "
                  "inconsistent (truncated or corrupt archive)");
    if (t.count > MAX_ENTRIES || t.cd_size / 46 > MAX_ENTRIES)
        err_throw(c->err, ERR_UNSUPPORTED, "ZIP central directory describes more than "
                  "binspect.archives.MAX_ENTRIES (%" PRIu64 ") entries", MAX_ENTRIES);
    a->zip_relative = t.cd_start != t.cd_offset;
    big concat = (big)t.cd_start - (big)t.cd_offset;
    const uint8_t *cd = fetch(c, f, size, (big)t.cd_start, (big)t.cd_size, "ZIP central directory");

    uint64_t pos = 0, nfiles = 0;
    big min_abs = (big)t.cd_start;
    bool any = false;
    for (uint64_t n = 0; ; n++) {
        if (t.count != 0 && n >= t.count)
            break;
        if (pos + 46 > t.cd_size || memcmp(cd + pos, "PK\x01\x02", 4) != 0)
            break;
        const uint8_t *e = cd + pos;
        uint16_t version_made = ld16(e + 4), flags = ld16(e + 8), method = ld16(e + 10);
        uint16_t mtime = ld16(e + 12), mdate = ld16(e + 14);
        uint32_t crc = ld32(e + 16);
        uint64_t comp = ld32(e + 20), uncomp = ld32(e + 24);
        uint16_t name_len = ld16(e + 28), extra_len = ld16(e + 30), comment_len = ld16(e + 32);
        uint16_t internal_attr = ld16(e + 36);
        uint32_t external_attr = ld32(e + 38);
        uint64_t header_offset = ld32(e + 42);
        if (pos + 46 + (uint64_t)name_len + extra_len + comment_len > t.cd_size)
            break;
        const uint8_t *namep = e + 46;
        zip64_extra(namep + name_len, extra_len, &uncomp, &comp, &header_offset);
        nfiles++;
        check_count(c, nfiles, "entries");
        bool utf8 = (flags & 0x800) != 0;
        bool is_dir = name_len > 0 && namep[name_len - 1] == '/';
        big abs = concat + (big)header_offset;
        if (!any || abs < min_abs) { min_abs = abs; any = true; }

        Rec *r = add_rec(a);
        r->raw_name = str_copy(a->arena, (const char *)namep, name_len);
        r->name = zip_name(a->arena, namep, name_len, utf8);
        r->is_dir = is_dir;
        r->size = uncomp;
        r->comp_size = comp;
        r->method = method;
        r->flags = flags;
        r->mtime = mtime;
        r->mdate = mdate;
        r->crc = crc;
        r->external_attr = external_attr;
        r->internal_attr = internal_attr;
        r->version_made = version_made;
        r->compressed = method != 0;
        r->encrypted = (flags & 0x1) != 0;
        r->local_abs = abs < 0 ? 0 : (uint64_t)abs;
        if (!(flags & 0x1)) {
            if (comp > size)
                r->broken = str_printf(a->arena, "claims %" PRIu64 " bytes of stored data in a "
                                       "%" PRIu64 "-byte file", comp, size).p;
            else if (method == 0 && uncomp != comp)
                r->broken = str_printf(a->arena, "stored (uncompressed) entry claims %" PRIu64
                                       " bytes but holds %" PRIu64, uncomp, comp).p;
            else if (method == 8 && uncomp > comp * 1032 + 1024)
                r->broken = str_printf(a->arena, "claims %" PRIu64 " bytes from %" PRIu64 " bytes "
                                       "of deflate data, more than deflate can produce", uncomp,
                                       comp).p;
        }
        pos += 46 + name_len + extra_len + comment_len;
    }

    uint64_t prefix = any ? (min_abs < 0 ? 0 : (uint64_t)min_abs) : t.cd_start;
    if (prefix > size)
        prefix = size;
    a->zip_prefix = prefix;
    a->headn = headn < 64 ? headn : 64;
    memcpy(a->head, head, a->headn);
    char ob[40];
    if (prefix) {
        if (head_is_exe(head, headn))
            note(a, str_printf(a->arena, "embedded in executable at offset %s",
                               hex_big(ob, (big)prefix)));
        else
            note(a, str_printf(a->arena, "ZIP data starts at offset %s, after %" PRIu64 " bytes of "
                               "other data (kept on repack)", hex_big(ob, (big)prefix), prefix));
    }
    if (path_has_suffix_ci(a->path, ".apk") || path_has_suffix_ci(a->path, ".aab") ||
        path_has_suffix_ci(a->path, ".xapk")) {
        note(a, str_c("Android package: a repacked APK is unsigned and unaligned; run zipalign "
                      "and apksigner on it before installing"));
    } else {
        bool sig = false;
        const char *sfx[] = {".SF", ".RSA", ".DSA", ".EC"};
        for (size_t i = 0; i < a->nrec && !sig; i++) {
            Str nm = a->rec[i].name;
            if (nm.n < 9)
                continue;
            char up[9];
            for (int k = 0; k < 9; k++) {
                char ch = nm.p[k];
                up[k] = (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : ch;
            }
            if (memcmp(up, "META-INF/", 9) != 0)
                continue;
            for (size_t s = 0; s < 4; s++) {
                size_t sl = strlen(sfx[s]);
                if (nm.n < sl)
                    continue;
                bool ok = true;
                for (size_t k = 0; k < sl; k++) {
                    char ch = nm.p[nm.n - sl + k];
                    if (ch >= 'a' && ch <= 'z') ch -= 32;
                    if (ch != sfx[s][k]) { ok = false; break; }
                }
                if (ok) sig = true;
            }
        }
        if (sig)
            note(a, str_c("signed JAR: signature files in META-INF/ no longer match after a "
                          "repack; remove them or re-sign"));
    }
    finish(c);
}

/* =============================================================================
 * Opening
 * ========================================================================== */

typedef struct {
    BsArchive *a;
    Err *err;
    FILE *f;
    uint64_t size;
    const uint8_t *head;
    size_t headn;
} ParseJob;

static void parse_worker(void *arg) {
    ParseJob *j = arg;
    Ctx c = {j->a, j->a->arena, j->err};
    switch (j->a->fmt) {
    case F_PAK: load_pak(&c, j->f, j->size, j->head, j->headn); break;
    case F_WAD: load_wad(&c, j->f, j->size, j->head, j->headn); break;
    case F_PCK: load_pck(&c, j->f, j->size, j->head, j->headn); break;
    case F_ZIP: load_zip(&c, j->f, j->size, j->head, j->headn); break;
    case F_ASAR:
    case F_RPA:
        err_throw(j->err, ERR_UNSUPPORTED,
                  "this pack format is available in the Python edition of binspect");
    }
}

BsArchive *bs_archive_open(const char *path, char *err, size_t errlen) {
    if (path == NULL) {
        if (err && errlen) snprintf(err, errlen, "no path given");
        return NULL;
    }
    uint64_t size = 0;
    bool not_regular = false;
    FILE *f = fs_open_regular(path, &size, &not_regular);
    if (f == NULL) {
        if (err && errlen) {
            if (not_regular)
                snprintf(err, errlen, "not a regular file");
            else
                snprintf(err, errlen, "cannot read %s: %s", path, strerror(errno));
        }
        return NULL;
    }
    uint8_t head[64];
    size_t headn = fread(head, 1, sizeof head, f);
    Format fmt;
    if (!detect(head, headn, f, size, &fmt)) {
        if (err && errlen)
            snprintf(err, errlen, "%s", size == 0 ? "file is empty" :
                     "not a supported asset container (ZIP, Quake PAK, Doom WAD, Godot PCK, "
                     "Electron ASAR, Ren'Py RPA)");
        fclose(f);
        return NULL;
    }

    Arena *arena = calloc(1, sizeof *arena);
    if (arena == NULL)
        die_out_of_memory();
    BsArchive *a = arena_alloc(arena, sizeof *a);
    a->arena = arena;
    a->path = str_copy(arena, path, strlen(path)).p;
    a->fmt = fmt;
    a->file_size = size;
    a->writable = true;
    a->max_entry_size = DEFAULT_MAX_ENTRY_SIZE;
    a->max_total_size = DEFAULT_MAX_TOTAL_SIZE;

    Err e = {0};
    ParseJob job = {a, &e, f, size, head, headn};
    bool ok = err_protect(&e, parse_worker, &job);
    fclose(f);
    if (!ok) {
        if (err && errlen)
            snprintf(err, errlen, "%s", e.msg ? e.msg : "corrupt archive");
        err_release(&e);
        arena_release(arena);
        free(arena);
        return NULL;
    }
    err_release(&e);
    return a;
}

void bs_archive_close(BsArchive *a) {
    if (a == NULL)
        return;
    Arena *arena = a->arena;
    arena_release(arena);
    free(arena);
}

const char *bs_archive_format(const BsArchive *a) { return a ? a->format : ""; }
bool bs_archive_writable(const BsArchive *a) { return a ? a->writable : false; }
size_t bs_archive_count(const BsArchive *a) { return a ? a->npub : 0; }

const BsArchiveEntry *bs_archive_entry(const BsArchive *a, size_t index) {
    if (a == NULL || index >= a->npub)
        return NULL;
    return &a->entries[index];
}

size_t bs_archive_note_count(const BsArchive *a) { return a ? a->nnotes : 0; }

const char *bs_archive_note(const BsArchive *a, size_t index) {
    if (a == NULL || index >= a->nnotes)
        return NULL;
    return a->notes[index];
}

/* =============================================================================
 * Entry streaming, lookups, checks
 * ========================================================================== */

typedef bool (*Sink)(void *ctx, const uint8_t *data, size_t n);

static void stream_entry(Ctx *c, FILE *f, uint64_t fsize, size_t rec_index, Sink sink, void *sctx) {
    BsArchive *a = c->a;
    Rec *r = &a->rec[rec_index];
    char ob[40];
    if (a->fmt != F_ZIP) {
        if (r->size == 0)
            return;
        uint64_t off = r->offset, left = r->size;
        if ((ubig)off + left > fsize)
            err_throw(c->err, ERR_PARSE, "%s: data at offset %s (+%" PRIu64 " bytes) is outside "
                      "the file (%" PRIu64 " bytes)", reprn(c->a_arena, r->name),
                      hex_big(ob, (big)off), left, fsize);
        if (!fs_seek(f, off))
            err_throw(c->err, ERR_PARSE, "%s: the file ends early", reprn(c->a_arena, r->name));
        uint8_t *buf = arena_alloc(c->a_arena, CHUNK);
        while (left) {
            size_t want = left < CHUNK ? (size_t)left : CHUNK;
            if (fread(buf, 1, want, f) != want)
                err_throw(c->err, ERR_PARSE, "%s: the file ends early", reprn(c->a_arena, r->name));
            if (!sink(sctx, buf, want))
                err_throw(c->err, ERR_OS, "%s: write failed", reprn(c->a_arena, r->name));
            left -= want;
        }
        return;
    }
    uint8_t lh[30];
    if (!fs_seek(f, r->local_abs) || fread(lh, 1, 30, f) != 30 || memcmp(lh, "PK\x03\x04", 4) != 0)
        err_throw(c->err, ERR_PARSE, "%s: corrupt ZIP entry: bad local header",
                  reprn(c->a_arena, r->name));
    uint16_t lname = ld16(lh + 26), lextra = ld16(lh + 28);
    uint64_t data_start = r->local_abs + 30 + lname + lextra;
    if ((ubig)data_start + r->comp_size > fsize)
        err_throw(c->err, ERR_PARSE, "%s: corrupt ZIP entry: data runs past the end of the file",
                  reprn(c->a_arena, r->name));
    if (!fs_seek(f, data_start))
        err_throw(c->err, ERR_PARSE, "%s: the file ends early", reprn(c->a_arena, r->name));
    if (r->method == 0) {
        uint64_t left = r->comp_size, produced = 0;
        uint8_t *buf = arena_alloc(c->a_arena, CHUNK);
        while (left) {
            size_t want = left < CHUNK ? (size_t)left : CHUNK;
            if (fread(buf, 1, want, f) != want)
                err_throw(c->err, ERR_PARSE, "%s: the file ends early", reprn(c->a_arena, r->name));
            size_t emit = want;
            if (produced + emit > r->size)
                emit = (size_t)(r->size - produced);
            if (emit && !sink(sctx, buf, emit))
                err_throw(c->err, ERR_OS, "%s: write failed", reprn(c->a_arena, r->name));
            produced += want;
            left -= want;
        }
        if (produced != r->size)
            err_throw(c->err, ERR_PARSE, "%s: the archive holds %" PRIu64 " bytes, its index says "
                      "%" PRIu64, reprn(c->a_arena, r->name), produced, r->size);
        return;
    }
    if (r->method != 8)
        err_throw(c->err, ERR_UNSUPPORTED, "%s: unsupported ZIP compression method %" PRIu16,
                  reprn(c->a_arena, r->name), r->method);
    BsInflate *z = arena_alloc(c->a_arena, sizeof *z);
    bs_inflate_init(z);
    uint8_t *inbuf = arena_alloc(c->a_arena, CHUNK);
    uint8_t *outbuf = arena_alloc(c->a_arena, CHUNK);
    uint64_t remaining = r->comp_size, produced = 0;
    z->avail_in = 0;
    for (;;) {
        if (z->avail_in == 0 && remaining) {
            size_t want = remaining < CHUNK ? (size_t)remaining : CHUNK;
            if (fread(inbuf, 1, want, f) != want)
                err_throw(c->err, ERR_PARSE, "%s: the file ends early", reprn(c->a_arena, r->name));
            z->next_in = inbuf;
            z->avail_in = want;
            remaining -= want;
        }
        z->next_out = outbuf;
        z->avail_out = CHUNK;
        BsInflateStatus st = bs_inflate(z);
        size_t got = CHUNK - z->avail_out;
        if (got) {
            size_t emit = got;
            if (produced + emit > r->size)
                emit = (size_t)(r->size - produced);
            if (emit && !sink(sctx, outbuf, emit))
                err_throw(c->err, ERR_OS, "%s: write failed", reprn(c->a_arena, r->name));
            produced += got;
        }
        if (st == BS_INFLATE_ERROR)
            err_throw(c->err, ERR_PARSE, "%s: corrupt ZIP entry: %s", reprn(c->a_arena, r->name),
                      z->msg ? z->msg : "invalid deflate stream");
        if (st == BS_INFLATE_END)
            break;
        if (z->avail_in == 0 && remaining == 0)
            break;
    }
    if (produced != r->size)
        err_throw(c->err, ERR_PARSE, "%s: the archive holds %" PRIu64 " bytes, its index says "
                  "%" PRIu64, reprn(c->a_arena, r->name), produced, r->size);
}

static size_t lookup(Ctx *c, const char *name, const char *action) {
    BsArchive *a = c->a;
    for (size_t i = 0; i < a->npub; i++)
        if (strcmp(a->rec[a->pub[i]].name.p, name) == 0)
            return i;
    err_throw(c->err, ERR_LOCATION, "cannot %s %s: no such entry in %s", action,
              py_repr(c->a_arena, name).p, a->path);
}

static void check_entry(Ctx *c, size_t pub_index, bool have_max, uint64_t maximum) {
    Rec *r = &c->a->rec[c->a->pub[pub_index]];
    if (r->encrypted)
        err_throw(c->err, ERR_UNSUPPORTED, "%s is encrypted; binspect does not decrypt archive "
                  "contents (no key recovery, no DRM removal)", reprn(c->a_arena, r->name));
    if (r->broken)
        err_throw(c->err, ERR_PARSE, "%s: %s", reprn(c->a_arena, r->name), r->broken);
    if (have_max && r->size > maximum)
        err_throw(c->err, ERR_UNSUPPORTED, "%s is %s, over the per-entry limit of %s; pass a "
                  "larger max_entry_size / max_size (or set Archive.max_entry_size) if this is "
                  "expected", reprn(c->a_arena, r->name), human(c->a_arena, r->size).p,
                  human(c->a_arena, maximum).p);
}

static void close_file(void *p) {
    if (p)
        fclose((FILE *)p);
}

/* =============================================================================
 * Public: read
 * ========================================================================== */

static bool buf_sink(void *ctx, const uint8_t *data, size_t n) {
    buf_add((Buf *)ctx, (const char *)data, n);
    return true;
}

typedef struct {
    BsArchive *a;
    Arena *scratch;
    Err *err;
    const char *name;
    uint8_t *out;
    size_t outn;
} ReadJob;

static void read_worker(void *arg) {
    ReadJob *j = arg;
    Ctx c = {j->a, j->scratch, j->err};
    size_t idx = lookup(&c, j->name, "read");
    check_entry(&c, idx, true, j->a->max_entry_size);
    uint64_t fsize = 0;
    bool nr = false;
    FILE *f = fs_open_regular(j->a->path, &fsize, &nr);
    if (f == NULL)
        err_throw(j->err, ERR_OS, "cannot read %s: %s", j->a->path, strerror(errno));
    arena_on_release(j->scratch, close_file, f);
    Buf b;
    buf_init(&b, j->scratch);
    stream_entry(&c, f, fsize, j->a->pub[idx], buf_sink, &b);
    Str s = buf_str(&b);
    j->out = malloc(s.n ? s.n : 1);
    if (j->out == NULL)
        die_out_of_memory();
    if (s.n)
        memcpy(j->out, s.p, s.n);
    j->outn = s.n;
}

bool bs_archive_read(BsArchive *a, const char *name, uint8_t **data, size_t *size, char *err,
                     size_t errlen) {
    if (data) *data = NULL;
    if (size) *size = 0;
    if (a == NULL)
        return false;
    Arena scratch = {0};
    Err e = {0};
    ReadJob job = {a, &scratch, &e, name, NULL, 0};
    bool ok = err_protect(&e, read_worker, &job);
    if (ok) {
        if (data) *data = job.out; else free(job.out);
        if (size) *size = job.outn;
    } else if (err && errlen) {
        snprintf(err, errlen, "%s", e.msg ? e.msg : "error");
    }
    arena_release(&scratch);
    err_release(&e);
    return ok;
}

/* =============================================================================
 * Public: extract
 * ========================================================================== */

static bool mkdirs(const char *path) {
    size_t n = strlen(path);
    char *tmp = malloc(n + 1);
    if (tmp == NULL)
        die_out_of_memory();
    memcpy(tmp, path, n + 1);
    for (size_t i = 1; i <= n; i++) {
        if (i == n || fs_is_separator(tmp[i])) {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (tmp[0] && !(i == 2 && tmp[1] == ':')) {
                if (!fs_mkdir(tmp) && errno != EEXIST && fs_kind(tmp, true) != FS_DIR) {
                    free(tmp);
                    return false;
                }
            }
            tmp[i] = saved;
        }
    }
    free(tmp);
    return true;
}

typedef struct { FILE *f; } FileSink;
static bool file_sink(void *ctx, const uint8_t *data, size_t n) {
    return fwrite(data, 1, n, ((FileSink *)ctx)->f) == n;
}

static size_t safe_parts(Ctx *c, Str name, Str **parts) {
    const char *reason = unsafe_reason(name);
    if (reason)
        err_throw(c->err, ERR_PARSE, "unsafe entry name %s (%s): refusing to extract it",
                  reprn(c->a_arena, name), reason);
    size_t count = 1;
    for (size_t i = 0; i < name.n; i++)
        if (name.p[i] == '/')
            count++;
    Str *out = arena_array(c->a_arena, count, sizeof *out);
    size_t k = 0, start = 0;
    for (size_t i = 0; i <= name.n; i++) {
        if (i == name.n || name.p[i] == '/') {
            out[k++] = str_copy(c->a_arena, name.p + start, i - start);
            start = i + 1;
        }
    }
    *parts = out;
    return count;
}

static Str extract_name(Ctx *c, size_t rec_index) {
    BsArchive *a = c->a;
    Rec *r = &a->rec[rec_index];
    if (a->fmt != F_WAD)
        return r->name;
    static const char *PLAIN =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+.#[]";
    Buf b;
    buf_init(&b, c->a_arena);
    for (size_t i = 0; i < r->name.n;) {
        size_t adv = i;
        uint32_t cp = utf8_next(r->name.p, r->name.n, &adv);
        if (cp < 128 && strchr(PLAIN, (int)cp) != NULL)
            buf_addch(&b, (char)cp);
        else
            buf_printf(&b, "%%%02X", (unsigned)cp);
        i = adv;
    }
    Str out = buf_str(&b);
    if (out.n == 0 || str_eq_c(out, ".") || str_eq_c(out, "..")) {
        Buf b2;
        buf_init(&b2, c->a_arena);
        for (size_t i = 0; i < r->name.n;) {
            size_t adv = i;
            uint32_t cp = utf8_next(r->name.p, r->name.n, &adv);
            buf_printf(&b2, "%%%02X", (unsigned)cp);
            i = adv;
        }
        out = buf_str(&b2);
        if (out.n == 0)
            out = str_c("%00");
    }
    return out;
}

typedef struct {
    Ctx *c;
    FILE *f;
    uint64_t fsize;
    size_t rec;
    Sink sink;
    void *sctx;
} StreamJob;

static void stream_job(void *arg) {
    StreamJob *j = arg;
    stream_entry(j->c, j->f, j->fsize, j->rec, j->sink, j->sctx);
}

static NORETURN void reraise(Ctx *outer, Err *nested) {
    const char *msg = nested->msg ? nested->msg : "error";
    const char *copy = str_copy(outer->a_arena, msg, strlen(msg)).p;
    ErrKind kind = nested->kind;
    err_release(nested);
    err_throw(outer->err, kind, "%s", copy);
}

static void extract_one(Ctx *c, FILE *f, uint64_t fsize, size_t rec_index, const char *root,
                        Str *parts, size_t nparts) {
    Rec *r = &c->a->rec[rec_index];
    Buf cur;
    buf_init(&cur, c->a_arena);
    buf_addc(&cur, root);
    for (size_t i = 0; i + 1 < nparts; i++) {
        buf_addch(&cur, '/');
        buf_adds(&cur, parts[i]);
        const char *path = buf_str(&cur).p;
        FsKind k = fs_kind(path, false);
        if (k == FS_LINK)
            err_throw(c->err, ERR_PARSE, "%s: %s is a symbolic link; refusing to write through it",
                      reprn(c->a_arena, r->name), path);
        if (k == FS_MISSING) {
            if (!fs_mkdir(path) && errno != EEXIST)
                err_throw(c->err, ERR_OS, "cannot create %s: %s", path, strerror(errno));
        } else if (k != FS_DIR) {
            err_throw(c->err, ERR_PARSE, "%s: %s exists and is not a directory",
                      reprn(c->a_arena, r->name), path);
        }
    }
    buf_addch(&cur, '/');
    buf_adds(&cur, parts[nparts - 1]);
    const char *target = buf_str(&cur).p;
    FsKind tk = fs_kind(target, false);
    if (tk == FS_LINK)
        err_throw(c->err, ERR_PARSE, "%s: %s is a symbolic link; refusing to write through it",
                  reprn(c->a_arena, r->name), target);
    if (tk == FS_DIR)
        err_throw(c->err, ERR_PARSE, "%s: %s is a directory", reprn(c->a_arena, r->name), target);
    FILE *out = fs_create(target);
    if (out == NULL)
        err_throw(c->err, ERR_OS, "cannot write %s: %s", target, strerror(errno));
    FileSink fsink = {out};
    Err se = {0};
    Ctx sc = {c->a, c->a_arena, &se};
    StreamJob sj = {&sc, f, fsize, rec_index, file_sink, &fsink};
    bool ok = err_protect(&se, stream_job, &sj);
    fclose(out);
    if (!ok) {
        platform_remove(target);
        reraise(c, &se);
    }
    err_release(&se);
}

typedef struct {
    BsArchive *a;
    Arena *scratch;
    Err *err;
    const char *dest;
    const char *const *names;
    size_t n_names;
    size_t written;
} ExtractJob;

static void extract_worker(void *arg) {
    ExtractJob *j = arg;
    BsArchive *a = j->a;
    Ctx c = {a, j->scratch, j->err};

    size_t *indices, nindices;
    if (j->n_names == 0) {
        nindices = a->npub;
        indices = arena_array(j->scratch, nindices ? nindices : 1, sizeof *indices);
        for (size_t i = 0; i < nindices; i++)
            indices[i] = i;
    } else {
        indices = arena_array(j->scratch, j->n_names, sizeof *indices);
        nindices = 0;
        for (size_t i = 0; i < j->n_names; i++) {
            size_t idx = lookup(&c, j->names[i], "extract");
            bool dup = false;
            for (size_t k = 0; k < nindices; k++)
                if (indices[k] == idx) { dup = true; break; }
            if (!dup)
                indices[nindices++] = idx;
        }
    }

    Str **parts = arena_array(j->scratch, nindices ? nindices : 1, sizeof *parts);
    size_t *nparts = arena_array(j->scratch, nindices ? nindices : 1, sizeof *nparts);
    uint64_t total = 0;
    for (size_t i = 0; i < nindices; i++) {
        check_entry(&c, indices[i], true, a->max_entry_size);
        Str nm = extract_name(&c, a->pub[indices[i]]);
        nparts[i] = safe_parts(&c, nm, &parts[i]);
        total += a->rec[a->pub[indices[i]]].size;
        if (total > a->max_total_size)
            err_throw(j->err, ERR_UNSUPPORTED, "extracting would write more than %s in total; pass "
                      "a larger max_total_size (or set Archive.max_total_size) if this is "
                      "expected", human(j->scratch, a->max_total_size).p);
    }

    if (!mkdirs(j->dest))
        err_throw(j->err, ERR_OS, "cannot create %s: %s", j->dest, strerror(errno));
    const char *root = platform_realpath(j->scratch, j->dest);

    uint64_t fsize = 0;
    bool nr = false;
    FILE *f = fs_open_regular(a->path, &fsize, &nr);
    if (f == NULL)
        err_throw(j->err, ERR_OS, "cannot read %s: %s", a->path, strerror(errno));
    arena_on_release(j->scratch, close_file, f);
    for (size_t i = 0; i < nindices; i++) {
        extract_one(&c, f, fsize, a->pub[indices[i]], root, parts[i], nparts[i]);
        j->written++;
    }
}

bool bs_archive_extract(BsArchive *a, const char *dest_dir, const char *const *names,
                        size_t n_names, size_t *written, char *err, size_t errlen) {
    if (written) *written = 0;
    if (a == NULL)
        return false;
    Arena scratch = {0};
    Err e = {0};
    ExtractJob job = {a, &scratch, &e, dest_dir, names, n_names, 0};
    bool ok = err_protect(&e, extract_worker, &job);
    if (ok) {
        if (written) *written = job.written;
    } else if (err && errlen) {
        snprintf(err, errlen, "%s", e.msg ? e.msg : "error");
    }
    arena_release(&scratch);
    err_release(&e);
    return ok;
}

/* =============================================================================
 * Public: repack (single replace or add, as the CLI needs)
 * ========================================================================== */

/* A plan item: copy a source record, or write new bytes. */
typedef struct {
    int64_t rec;            /* source record index, or -1 for an addition */
    const uint8_t *data;    /* replacement/added content, or NULL to copy */
    size_t size;
    Str raw_name;           /* name bytes to store (additions / format needs) */
} Plan;

typedef struct {
    FILE *f;
    uint64_t pos;
    Ctx *c;
} Out;

static void o_write(Out *o, const void *p, size_t n) {
    if (n && fwrite(p, 1, n, o->f) != n)
        err_throw(o->c->err, ERR_OS, "cannot write output: %s", strerror(errno));
    o->pos += n;
}
static void o_zeros(Out *o, uint64_t n) {
    static const uint8_t z[256] = {0};
    while (n) {
        size_t w = n < sizeof z ? (size_t)n : sizeof z;
        o_write(o, z, w);
        n -= w;
    }
}
static void o_seek(Out *o, uint64_t pos) {
    if (fflush(o->f) != 0 || !fs_seek(o->f, pos))
        err_throw(o->c->err, ERR_OS, "cannot seek output");
    o->pos = pos;
}

static bool out_count_sink(void *ctx, const uint8_t *data, size_t n) {
    Out *o = ctx;
    if (n && fwrite(data, 1, n, o->f) != n)
        return false;
    o->pos += n;
    return true;
}

/* Stream an unchanged record into the output, returning the byte count. */
static uint64_t copy_rec(Ctx *c, FILE *src, uint64_t fsize, Out *out, size_t rec_index) {
    uint64_t before = out->pos;
    stream_entry(c, src, fsize, rec_index, out_count_sink, out);
    return out->pos - before;
}

static void copy_prefix(Ctx *c, FILE *src, uint64_t fsize, Out *out, uint64_t length) {
    if (length == 0)
        return;
    if (length > fsize || !fs_seek(src, 0))
        err_throw(c->err, ERR_PARSE, "data before the pack is outside the file");
    uint8_t *buf = arena_alloc(c->a_arena, CHUNK);
    uint64_t left = length;
    while (left) {
        size_t want = left < CHUNK ? (size_t)left : CHUNK;
        if (fread(buf, 1, want, src) != want)
            err_throw(c->err, ERR_PARSE, "data before the pack: the file ends early");
        o_write(out, buf, want);
        left -= want;
    }
}

static void check_new_name(Ctx *c, Str name) {
    const char *reason = unsafe_reason(name);
    if (reason)
        err_throw(c->err, ERR_UNSUPPORTED, "cannot add an entry named %s (%s)",
                  reprn(c->a_arena, name), reason);
    if (c->a->fmt == F_PAK) {
        if (name.n > 55)
            err_throw(c->err, ERR_UNSUPPORTED, "PAK entry names are limited to 55 bytes: %s",
                      reprn(c->a_arena, name));
    } else if (c->a->fmt == F_WAD) {
        /* 1..8 upper-case Latin-1 characters, no NUL */
        bool ok = true;
        size_t nbytes = 0;
        for (size_t i = 0; i < name.n && ok;) {
            size_t adv = i;
            uint32_t cp = utf8_next(name.p, name.n, &adv);
            if (cp > 0xFF || cp == 0)
                ok = false;
            else if ((cp >= 'a' && cp <= 'z') || (cp >= 0xE0 && cp <= 0xFE && cp != 0xF7) ||
                     cp == 0xDF || cp == 0xFF || cp == 0xB5)
                ok = false;         /* name != name.upper() */
            nbytes++;
            i = adv;
        }
        if (!ok || nbytes < 1 || nbytes > 8)
            err_throw(c->err, ERR_UNSUPPORTED, "WAD lump names are 1 to 8 upper-case Latin-1 "
                      "characters: %s", reprn(c->a_arena, name));
    } else if (c->a->fmt == F_PCK) {
        if (name.n + 6 > 4096)
            err_throw(c->err, ERR_UNSUPPORTED, "path too long for a Godot pack: %s",
                      reprn(c->a_arena, name));
    }
}

/* --- per-format writers ------------------------------------------------------- */

static void write_pak(Ctx *c, FILE *src, uint64_t fsize, Out *out, Plan *plan, size_t nplan) {
    o_zeros(out, 12);
    uint64_t position = 12;
    uint8_t *dir = arena_array(c->a_arena, nplan ? nplan : 1, 64);
    for (size_t i = 0; i < nplan; i++) {
        Str raw = plan[i].raw_name;
        uint64_t length;
        if (plan[i].data != NULL) {
            o_write(out, plan[i].data, plan[i].size);
            length = plan[i].size;
        } else {
            length = copy_rec(c, src, fsize, out, (size_t)plan[i].rec);
        }
        uint8_t *d = dir + i * 64;
        memset(d, 0, 64);
        memcpy(d, raw.p, raw.n < 56 ? raw.n : 56);
        st32(d + 56, (uint32_t)position);
        st32(d + 60, (uint32_t)length);
        position += length;
        if (position > 0x7FFFFFFF)
            err_throw(c->err, ERR_UNSUPPORTED, "PAK archives cannot exceed 2 GiB (32-bit offsets)");
    }
    o_write(out, dir, nplan * 64);
    o_seek(out, 0);
    uint8_t h[12];
    memcpy(h, "PACK", 4);
    st32(h + 4, (uint32_t)position);
    st32(h + 8, (uint32_t)(nplan * 64));
    o_write(out, h, 12);
}

static void write_wad(Ctx *c, FILE *src, uint64_t fsize, Out *out, Plan *plan, size_t nplan) {
    o_zeros(out, 12);
    uint64_t position = 12;
    uint8_t *dir = arena_array(c->a_arena, nplan ? nplan : 1, 16);
    for (size_t i = 0; i < nplan; i++) {
        Str raw = plan[i].raw_name;
        uint64_t length;
        if (plan[i].data != NULL) {
            o_write(out, plan[i].data, plan[i].size);
            length = plan[i].size;
        } else {
            length = copy_rec(c, src, fsize, out, (size_t)plan[i].rec);
        }
        uint8_t *d = dir + i * 16;
        memset(d, 0, 16);
        st32(d, length ? (uint32_t)position : 0);
        st32(d + 4, (uint32_t)length);
        memcpy(d + 8, raw.p, raw.n < 8 ? raw.n : 8);
        position += length;
        if (position > 0x7FFFFFFF)
            err_throw(c->err, ERR_UNSUPPORTED, "WAD files cannot exceed 2 GiB (32-bit offsets)");
    }
    o_write(out, dir, nplan * 16);
    o_seek(out, 0);
    uint8_t h[12];
    memcpy(h, c->a->wad_magic, 4);
    st32(h + 4, (uint32_t)nplan);
    st32(h + 8, (uint32_t)position);
    o_write(out, h, 12);
}

static void hex_to_md5(const char *hex, uint8_t out[16]) {
    for (int i = 0; i < 16; i++) {
        int hi = hex[i * 2], lo = hex[i * 2 + 1];
        hi = hi <= '9' ? hi - '0' : (hi | 0x20) - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : (lo | 0x20) - 'a' + 10;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
}

static void write_pck(Ctx *c, FILE *src, uint64_t fsize, Out *out, Plan *plan, size_t nplan) {
    BsArchive *a = c->a;
    uint64_t start = a->pck_start;
    int fmt = a->pck_format;
    if (start)
        copy_prefix(c, src, fsize, out, start);
    uint32_t fixed = fmt == 1 ? 32 : 36;
    uint32_t header_size = fmt == 1 ? 88 : 100;
    uint64_t directory_size = 0;
    for (size_t i = 0; i < nplan; i++) {
        size_t len = plan[i].raw_name.n;
        directory_size += 4 + len + ((4 - len % 4) % 4) + fixed;
    }
    uint64_t data_base = start + header_size + directory_size;
    data_base += (16 - data_base % 16) % 16;

    o_seek(out, data_base);
    uint64_t position = data_base;
    /* rows: raw_name, offset, length, md5(16), flags */
    typedef struct { Str raw; uint64_t offset, length; uint8_t md5[16]; uint32_t flags; } Row;
    Row *rows = arena_array(c->a_arena, nplan ? nplan : 1, sizeof *rows);
    for (size_t i = 0; i < nplan; i++) {
        uint64_t length;
        uint8_t md5[16];
        uint32_t flags = 0;
        if (plan[i].data != NULL) {
            o_write(out, plan[i].data, plan[i].size);
            length = plan[i].size;
            char hex[33];
            md5_hex(plan[i].data, plan[i].size, hex);
            hex_to_md5(hex, md5);
            if (plan[i].rec >= 0)
                flags = a->rec[plan[i].rec].pck_flags;
        } else {
            length = copy_rec(c, src, fsize, out, (size_t)plan[i].rec);
            memcpy(md5, a->rec[plan[i].rec].md5, 16);
            flags = a->rec[plan[i].rec].pck_flags;
        }
        rows[i].raw = plan[i].raw_name;
        rows[i].offset = position;
        rows[i].length = length;
        memcpy(rows[i].md5, md5, 16);
        rows[i].flags = flags;
        position += length;
        uint64_t pad = (16 - position % 16) % 16;
        o_zeros(out, pad);
        position += pad;
    }
    if (a->pck_embedded) {
        uint64_t pad = (8 - (position - start) % 8) % 8;
        uint64_t minpad = (a->file_size >= 12 + position) ? a->file_size - 12 - position : 0;
        if (minpad > pad)
            pad = minpad;
        pad += (8 - (position + pad - start) % 8) % 8;
        o_zeros(out, pad);
        position += pad;
        uint8_t foot[12];
        st64(foot, position - start);
        memcpy(foot + 8, "GDPC", 4);
        o_write(out, foot, 12);
    }
    o_seek(out, start);
    o_write(out, a->pck_header, 20);
    if (fmt == 2) {
        uint8_t fb[12];
        uint64_t stored = (a->pck_pack_flags & PACK_REL_FILEBASE) ? data_base - start : data_base;
        st32(fb, a->pck_pack_flags);
        st64(fb + 4, stored);
        o_write(out, fb, 12);
    }
    o_write(out, a->pck_reserved, 64);
    uint8_t cnt[4];
    st32(cnt, (uint32_t)nplan);
    o_write(out, cnt, 4);
    for (size_t i = 0; i < nplan; i++) {
        size_t len = rows[i].raw.n;
        uint64_t pad = (4 - len % 4) % 4;
        uint8_t lb[4];
        st32(lb, (uint32_t)(len + pad));
        o_write(out, lb, 4);
        o_write(out, rows[i].raw.p, len);
        o_zeros(out, pad);
        uint8_t ob2[16];
        st64(ob2, fmt == 1 ? rows[i].offset : rows[i].offset - data_base);
        st64(ob2 + 8, rows[i].length);
        o_write(out, ob2, 16);
        o_write(out, rows[i].md5, 16);
        if (fmt >= 2) {
            uint8_t fl[4];
            st32(fl, rows[i].flags);
            o_write(out, fl, 4);
        }
    }
}

/* --- ZIP writer --------------------------------------------------------------- */

typedef struct {
    Str raw_name;
    uint16_t flags, method, mtime, mdate, version_made, internal_attr;
    uint32_t crc, external_attr;
    uint64_t comp_size, uncomp_size, offset_rel;
} ZipCD;

static void zip_write_entry(Ctx *c, FILE *src, uint64_t fsize, Out *out, uint64_t base,
                            Rec *r, const uint8_t *newdata, size_t newsize, Str raw_name,
                            ZipCD *cd) {
    uint64_t offset_rel = out->pos - base;
    uint16_t flags, method, mtime, mdate, version_made, internal_attr;
    uint32_t crc, external_attr;
    uint64_t comp, uncomp;
    if (newdata != NULL || r == NULL) {
        /* stored */
        method = 0;
        flags = r ? (uint16_t)(r->flags & ~0x8u) : 0;
        if (raw_name.n && !is_valid_utf8((const uint8_t *)raw_name.p, raw_name.n))
            flags = (uint16_t)(flags & ~0x800u);
        else if (r == NULL) {
            /* new entry: set the UTF-8 flag when the name needs it */
            flags = 0;
            for (size_t i = 0; i < raw_name.n; i++)
                if ((uint8_t)raw_name.p[i] >= 0x80) { flags = 0x800; break; }
        }
        mtime = r ? r->mtime : 0;
        mdate = r ? r->mdate : 0x21;        /* 1980-01-01 */
        version_made = r ? r->version_made : 20;
        internal_attr = r ? r->internal_attr : 0;
        external_attr = r ? r->external_attr : (uint32_t)(0644u << 16);
        crc = bs_crc32(0, newdata, newsize);
        comp = uncomp = newsize;
    } else {
        method = r->method;
        flags = (uint16_t)(r->flags & ~0x8u);
        mtime = r->mtime;
        mdate = r->mdate;
        version_made = r->version_made;
        internal_attr = r->internal_attr;
        external_attr = r->external_attr;
        crc = r->crc;
        comp = r->comp_size;
        uncomp = r->size;
    }
    if (comp > 0xFFFFFFFFu || uncomp > 0xFFFFFFFFu || offset_rel > 0xFFFFFFFFu)
        err_throw(c->err, ERR_UNSUPPORTED, "ZIP64 output (entries or offsets above 4 GiB) is not "
                  "supported by the native edition");

    uint8_t lh[30];
    memcpy(lh, "PK\x03\x04", 4);
    st16(lh + 4, 20);
    st16(lh + 6, flags);
    st16(lh + 8, method);
    st16(lh + 10, mtime);
    st16(lh + 12, mdate);
    st32(lh + 14, crc);
    st32(lh + 18, (uint32_t)comp);
    st32(lh + 22, (uint32_t)uncomp);
    st16(lh + 26, (uint16_t)raw_name.n);
    st16(lh + 28, 0);
    o_write(out, lh, 30);
    o_write(out, raw_name.p, raw_name.n);

    if (newdata != NULL || r == NULL) {
        o_write(out, newdata, newsize);
    } else {
        /* copy the stored bytes verbatim from the source local data region */
        uint8_t slh[30];
        if (!fs_seek(src, r->local_abs) || fread(slh, 1, 30, src) != 30 ||
            memcmp(slh, "PK\x03\x04", 4) != 0)
            err_throw(c->err, ERR_PARSE, "%s: corrupt ZIP entry: bad local header",
                      reprn(c->a_arena, r->name));
        uint64_t ds = r->local_abs + 30 + ld16(slh + 26) + ld16(slh + 28);
        if ((ubig)ds + comp > fsize || !fs_seek(src, ds))
            err_throw(c->err, ERR_PARSE, "%s: corrupt ZIP entry: data runs past the end of the "
                      "file", reprn(c->a_arena, r->name));
        uint8_t *buf = arena_alloc(c->a_arena, CHUNK);
        uint64_t left = comp;
        while (left) {
            size_t want = left < CHUNK ? (size_t)left : CHUNK;
            if (fread(buf, 1, want, src) != want)
                err_throw(c->err, ERR_PARSE, "%s: the file ends early", reprn(c->a_arena, r->name));
            o_write(out, buf, want);
            left -= want;
        }
    }
    cd->raw_name = raw_name;
    cd->flags = flags;
    cd->method = method;
    cd->mtime = mtime;
    cd->mdate = mdate;
    cd->version_made = version_made;
    cd->internal_attr = internal_attr;
    cd->crc = crc;
    cd->external_attr = external_attr;
    cd->comp_size = comp;
    cd->uncomp_size = uncomp;
    cd->offset_rel = offset_rel;
}

static void write_zip(Ctx *c, FILE *src, uint64_t fsize, Out *out, const char *replace_name,
                      int64_t replace_rec, const uint8_t *newdata, size_t newsize,
                      bool add, Str add_name) {
    BsArchive *a = c->a;
    (void)replace_name;
    if (a->zip_prefix)
        copy_prefix(c, src, fsize, out, a->zip_prefix);
    uint64_t base = (a->zip_relative && a->zip_prefix) ? a->zip_prefix : 0;

    size_t total = a->nrec + (add ? 1 : 0);
    ZipCD *cds = arena_array(c->a_arena, total ? total : 1, sizeof *cds);
    size_t ncd = 0;
    for (size_t i = 0; i < a->nrec; i++) {
        Rec *r = &a->rec[i];
        if ((int64_t)i == replace_rec)
            zip_write_entry(c, src, fsize, out, base, r, newdata, newsize, r->raw_name, &cds[ncd++]);
        else
            zip_write_entry(c, src, fsize, out, base, r, NULL, 0, r->raw_name, &cds[ncd++]);
    }
    if (add)
        zip_write_entry(c, src, fsize, out, base, NULL, newdata, newsize, add_name, &cds[ncd++]);

    uint64_t cd_start = out->pos;
    for (size_t i = 0; i < ncd; i++) {
        ZipCD *e = &cds[i];
        uint8_t h[46];
        memcpy(h, "PK\x01\x02", 4);
        st16(h + 4, e->version_made);
        st16(h + 6, 20);
        st16(h + 8, e->flags);
        st16(h + 10, e->method);
        st16(h + 12, e->mtime);
        st16(h + 14, e->mdate);
        st32(h + 16, e->crc);
        st32(h + 20, (uint32_t)e->comp_size);
        st32(h + 24, (uint32_t)e->uncomp_size);
        st16(h + 28, (uint16_t)e->raw_name.n);
        st16(h + 30, 0);
        st16(h + 32, 0);
        st16(h + 34, 0);
        st16(h + 36, e->internal_attr);
        st32(h + 38, e->external_attr);
        st32(h + 42, (uint32_t)e->offset_rel);
        o_write(out, h, 46);
        o_write(out, e->raw_name.p, e->raw_name.n);
    }
    uint64_t cd_size = out->pos - cd_start;
    uint64_t cd_offset = cd_start - base;
    if (cd_offset > 0xFFFFFFFFu || cd_size > 0xFFFFFFFFu || ncd > 0xFFFF)
        err_throw(c->err, ERR_UNSUPPORTED, "ZIP64 output is not supported by the native edition");
    uint8_t eocd[22];
    memcpy(eocd, "PK\x05\x06", 4);
    st16(eocd + 4, 0);
    st16(eocd + 6, 0);
    st16(eocd + 8, (uint16_t)ncd);
    st16(eocd + 10, (uint16_t)ncd);
    st32(eocd + 12, (uint32_t)cd_size);
    st32(eocd + 16, (uint32_t)cd_offset);
    st16(eocd + 20, 0);
    o_write(out, eocd, 22);
}

/* --- repack driver ------------------------------------------------------------ */

typedef struct { FILE *out; const char *path; bool done; } TempCleanup;
static void cleanup_temp(void *p) {
    TempCleanup *t = p;
    if (t->out) { fclose(t->out); t->out = NULL; }
    if (!t->done)
        platform_remove(t->path);
}

typedef struct {
    BsArchive *a;
    Arena *scratch;
    Err *err;
    const char *out_path;
    const char *name;
    const uint8_t *data;
    size_t size;
    bool add;
} RepackJob;

static bool same_source(const char *out_path, const char *src_path, Arena *scratch) {
    if (platform_same_file(out_path, src_path))
        return true;
    const char *ra = platform_realpath(scratch, out_path);
    const char *rb = platform_realpath(scratch, src_path);
    return strcmp(ra, rb) == 0;
}

static void repack_worker(void *arg) {
    RepackJob *j = arg;
    BsArchive *a = j->a;
    Ctx c = {a, j->scratch, j->err};

    if (!a->writable)
        err_throw(j->err, ERR_UNSUPPORTED, "%s", a->readonly_reason ? a->readonly_reason :
                  str_printf(j->scratch, "this %s archive cannot be repacked", a->format).p);
    if (same_source(j->out_path, a->path, j->scratch))
        err_throw(j->err, ERR_UNSUPPORTED, "refusing to repack onto the source archive itself; "
                  "write to a different path and replace the original afterwards");

    Str change_name = str_c(j->name);
    int64_t replace_rec = -1;
    if (j->add) {
        for (size_t i = 0; i < a->npub; i++)
            if (strcmp(a->rec[a->pub[i]].name.p, j->name) == 0)
                err_throw(j->err, ERR_LOCATION, "cannot add %s: the archive already has an entry "
                          "of that name (use replacements)", reprn(j->scratch, change_name));
        check_new_name(&c, change_name);
    } else {
        size_t idx = lookup(&c, j->name, "replace");
        replace_rec = (int64_t)a->pub[idx];
    }
    /* unchanged entries must still be readable (broken ones fail here) */
    for (size_t i = 0; i < a->npub; i++)
        if ((int64_t)a->pub[i] != replace_rec)
            check_entry(&c, i, false, 0);

    uint64_t fsize = 0;
    bool nr = false;
    FILE *src = fs_open_regular(a->path, &fsize, &nr);
    if (src == NULL)
        err_throw(j->err, ERR_OS, "cannot read %s: %s", a->path, strerror(errno));
    arena_on_release(j->scratch, close_file, src);

    const char *tmp = NULL;
    FILE *outf = fs_create_temp(j->scratch, j->out_path, &tmp);
    if (outf == NULL)
        err_throw(j->err, ERR_OS, "cannot create a temporary file next to %s: %s", j->out_path,
                  strerror(errno));
    TempCleanup *tc = arena_alloc(j->scratch, sizeof *tc);
    tc->out = outf;
    tc->path = tmp;
    tc->done = false;
    arena_on_release(j->scratch, cleanup_temp, tc);

    Out out = {outf, 0, &c};

    if (a->fmt == F_ZIP) {
        Str add_name = str_c(j->name);
        write_zip(&c, src, fsize, &out, j->name, replace_rec, j->data, j->size, j->add, add_name);
    } else {
        /* build the plan over the public entries, plus the optional addition */
        size_t nplan = a->npub + (j->add ? 1 : 0);
        Plan *plan = arena_array(j->scratch, nplan ? nplan : 1, sizeof *plan);
        for (size_t i = 0; i < a->npub; i++) {
            size_t rec = a->pub[i];
            plan[i].rec = (int64_t)rec;
            plan[i].raw_name = a->rec[rec].raw_name;
            if ((int64_t)rec == replace_rec) {
                plan[i].data = j->data;
                plan[i].size = j->size;
            } else {
                plan[i].data = NULL;
                plan[i].size = 0;
            }
        }
        if (j->add) {
            Plan *p = &plan[a->npub];
            p->rec = -1;
            p->data = j->data;
            p->size = j->size;
            if (a->fmt == F_PCK) {
                bool prefixed = a->nrec == 0;
                for (size_t i = 0; i < a->nrec; i++)
                    if (a->rec[i].raw_name.n >= 6 && memcmp(a->rec[i].raw_name.p, "res://", 6) == 0)
                        prefixed = true;
                if (prefixed)
                    p->raw_name = str_printf(j->scratch, "res://%s", j->name);
                else
                    p->raw_name = str_c(j->name);
            } else if (a->fmt == F_WAD) {
                /* latin-1 bytes of the name (every code point is < 256) */
                Buf b;
                buf_init(&b, j->scratch);
                for (size_t i = 0; i < change_name.n;) {
                    size_t adv = i;
                    uint32_t cp = utf8_next(change_name.p, change_name.n, &adv);
                    buf_addch(&b, (char)cp);
                    i = adv;
                }
                p->raw_name = buf_str(&b);
            } else {
                p->raw_name = str_c(j->name);   /* PAK: UTF-8 bytes */
            }
        }
        if (a->fmt == F_PAK)
            write_pak(&c, src, fsize, &out, plan, nplan);
        else if (a->fmt == F_WAD)
            write_wad(&c, src, fsize, &out, plan, nplan);
        else if (a->fmt == F_PCK)
            write_pck(&c, src, fsize, &out, plan, nplan);
        else
            err_throw(j->err, ERR_UNSUPPORTED,
                      "this pack format is available in the Python edition of binspect");
    }

    if (fflush(outf) != 0)
        err_throw(j->err, ERR_OS, "cannot write %s: %s", j->out_path, strerror(errno));
    if (fclose(outf) != 0) {
        tc->out = NULL;
        err_throw(j->err, ERR_OS, "cannot write %s: %s", j->out_path, strerror(errno));
    }
    tc->out = NULL;
    fs_copy_mode(a->path, tmp);
    if (!platform_replace(tmp, j->out_path))
        err_throw(j->err, ERR_OS, "cannot save %s: %s", j->out_path, strerror(errno));
    tc->done = true;
}

bool bs_archive_repack(BsArchive *a, const char *out_path, const char *name, const uint8_t *data,
                       size_t size, bool add, char *err, size_t errlen) {
    if (a == NULL)
        return false;
    Arena scratch = {0};
    Err e = {0};
    RepackJob job = {a, &scratch, &e, out_path, name, data, size, add};
    bool ok = err_protect(&e, repack_worker, &job);
    if (!ok && err && errlen)
        snprintf(err, errlen, "%s", e.msg ? e.msg : "error");
    arena_release(&scratch);
    err_release(&e);
    return ok;
}
