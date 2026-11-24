/* Saving the parts of a program as separate files (see split.h).
 *
 * Everything here reads an untrusted file. Offsets and lengths are checked
 * against what is left of the file before any byte is read, sums that could
 * exceed 64 bits are made in `big`, and every loop advances by at least one
 * byte per step. */
#include "split.h"

#include <errno.h>

#include "fswalk.h"
#include "hash.h"
#include "platform.h"
#include "views.h"

/* --- reading -------------------------------------------------------------------- */

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | p[1] << 8);
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

/* A field of an ELF structure, in the byte order the file declares. */
static uint64_t elf_field(const uint8_t *p, unsigned width, bool little) {
    uint64_t value = 0;
    for (unsigned i = 0; i < width; i++)
        value |= (uint64_t)p[i] << (little ? 8 * i : 8 * (width - 1 - i));
    return value;
}

/* zlib.crc32() of a short run of bytes (PNG chunk headers). */
static uint32_t crc32_of(const uint8_t *p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = crc & 1 ? crc >> 1 ^ 0xEDB88320u : crc >> 1;
    }
    return ~crc;
}

/* --- embedded files ---------------------------------------------------------------
 * Each recogniser is given a file offset and returns the exact length of the
 * complete file that starts there, or 0. A length is only ever returned when
 * it fits inside what is left of the file. */

/* An end-of-central-directory record that can close a ZIP: it does so for
 * exactly one start offset (`start + cd_offset + cd_size == eocd`). */
typedef struct {
    uint64_t start, eocd, end;
} ZipEnd;

typedef struct {
    const uint8_t *data;
    uint64_t size;
    Arena *arena;
    bool zip_ready;
    ZipEnd *zip_ends;               /* sorted by start, then by eocd */
    size_t nzip_ends;
} Carver;

static uint64_t png_length(const Carver *c, uint64_t o) {
    static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    const uint8_t *d = c->data;
    uint64_t n = c->size;
    if (n - o < 8 || memcmp(d + o, signature, 8) != 0)
        return 0;
    uint64_t p = o + 8;
    bool first = true;
    for (;;) {
        /* length (4), type (4), data, crc (4) */
        if (n - p < 12)
            return 0;
        uint64_t length = be32(d + p);
        if (length > n - p - 12)
            return 0;
        const uint8_t *type = d + p + 4;
        if (first) {
            if (length != 13 || memcmp(type, "IHDR", 4) != 0)
                return 0;
            if (crc32_of(type, 4 + 13) != be32(type + 4 + 13))
                return 0;
            first = false;
        }
        p += 12 + length;
        if (memcmp(type, "IEND", 4) == 0)
            return p - o;
    }
}

/* Skips GIF data sub-blocks (a size byte and that many bytes, ended by a
 * zero size). False when the file ends first. */
static bool gif_sub_blocks(const Carver *c, uint64_t *at) {
    uint64_t p = *at, n = c->size;
    for (;;) {
        if (p >= n)
            return false;
        uint64_t size = c->data[p];
        p++;
        if (size == 0)
            break;
        if (size > n - p)
            return false;
        p += size;
    }
    *at = p;
    return true;
}

static uint64_t gif_length(const Carver *c, uint64_t o) {
    const uint8_t *d = c->data;
    uint64_t n = c->size;
    if (n - o < 13 || (memcmp(d + o, "GIF87a", 6) != 0 && memcmp(d + o, "GIF89a", 6) != 0))
        return 0;
    uint64_t p = o + 13;
    uint8_t packed = d[o + 10];
    if (packed & 0x80) {
        uint64_t table = (uint64_t)3 << ((packed & 7) + 1);
        if (table > n - p)
            return 0;
        p += table;
    }
    bool image = false;
    for (;;) {
        if (p >= n)
            return 0;
        uint8_t block = d[p];
        if (block == 0x3B)
            return image ? p + 1 - o : 0;
        if (block == 0x2C) {
            /* image descriptor: 0x2C, position and size (8), packed (1) */
            if (n - p < 10)
                return 0;
            packed = d[p + 9];
            p += 10;
            if (packed & 0x80) {
                uint64_t table = (uint64_t)3 << ((packed & 7) + 1);
                if (table > n - p)
                    return 0;
                p += table;
            }
            if (p >= n)
                return 0;
            p++;                        /* LZW minimum code size */
            if (!gif_sub_blocks(c, &p))
                return 0;
            image = true;
        } else if (block == 0x21) {
            if (n - p < 2)
                return 0;
            p += 2;                     /* 0x21 and the extension label */
            if (!gif_sub_blocks(c, &p))
                return 0;
        } else {
            return 0;
        }
    }
}

/* RIFF containers: the extension for a form type, or NULL. */
static const char *riff_ext(const uint8_t *form) {
    if (memcmp(form, "WAVE", 4) == 0)
        return "wav";
    if (memcmp(form, "AVI ", 4) == 0)
        return "avi";
    if (memcmp(form, "WEBP", 4) == 0)
        return "webp";
    return NULL;
}

static uint64_t riff_length(const Carver *c, uint64_t o, const char **ext) {
    const uint8_t *d = c->data;
    uint64_t n = c->size;
    if (n - o < 12 || memcmp(d + o, "RIFF", 4) != 0)
        return 0;
    *ext = riff_ext(d + o + 8);
    if (*ext == NULL)
        return 0;
    uint64_t size = le32(d + o + 4);
    if (size < 4 || size + 8 > n - o)
        return 0;
    return size + 8;
}

static int compare_zip_ends(const void *pa, const void *pb) {
    const ZipEnd *x = pa, *y = pb;
    if (x->start != y->start)
        return x->start < y->start ? -1 : 1;
    return (x->eocd > y->eocd) - (x->eocd < y->eocd);
}

/* One pass over the file for end-of-central-directory records. A record at
 * `eocd` closes the archive that starts at eocd - cd_offset - cd_size and no
 * other, so each local header is later matched with a binary search instead
 * of another scan of the file: a file made of nothing but signatures still
 * costs O(n log n). */
static void zip_prepare(Carver *c) {
    const uint8_t *d = c->data;
    uint64_t n = c->size;
    VEC(ZipEnd) ends = {0};
    c->zip_ready = true;
    if (n < 22)
        return;
    for (uint64_t e = 0; e <= n - 22; e++) {
        if (d[e] != 'P' || d[e + 1] != 'K' || d[e + 2] != 5 || d[e + 3] != 6)
            continue;
        uint64_t cd_size = le32(d + e + 12), cd_offset = le32(d + e + 16);
        uint64_t comment = le16(d + e + 20);
        if (cd_size > e || cd_offset > e - cd_size)
            continue;
        uint64_t start = e - cd_size - cd_offset;
        uint64_t directory = e - cd_size;           /* start + cd_offset */
        if (start == 0 || memcmp(d + start, "PK\x03\x04", 4) != 0)
            continue;
        if (memcmp(d + directory, "PK\x01\x02", 4) != 0)
            continue;
        if (comment > n - e - 22)
            continue;
        ZipEnd end = {start, e, e + 22 + comment};
        *VEC_PUSH(c->arena, ends) = end;
    }
    if (ends.n > 1)
        qsort(ends.v, ends.n, sizeof *ends.v, compare_zip_ends);
    c->zip_ends = ends.v;
    c->nzip_ends = ends.n;
}

static uint64_t zip_length(Carver *c, uint64_t o) {
    if (c->size - o < 4 || memcmp(c->data + o, "PK\x03\x04", 4) != 0)
        return 0;
    if (!c->zip_ready)
        zip_prepare(c);
    size_t low = 0, high = c->nzip_ends;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (c->zip_ends[middle].start < o)
            low = middle + 1;
        else
            high = middle;
    }
    if (low == c->nzip_ends || c->zip_ends[low].start != o)
        return 0;
    return c->zip_ends[low].end - o;
}

static uint64_t pe_length(const Carver *c, uint64_t o, const char **ext) {
    const uint8_t *d = c->data;
    uint64_t left = c->size - o;
    if (left < 0x40 || d[o] != 'M' || d[o + 1] != 'Z')
        return 0;
    uint64_t pe = le32(d + o + 0x3C);
    /* signature (4) and COFF header (20) */
    if (pe > left || left - pe < 24)
        return 0;
    const uint8_t *h = d + o + pe;
    if (memcmp(h, "PE\0\0", 4) != 0)
        return 0;
    unsigned sections = le16(h + 6);
    if (sections < 1 || sections > 96)
        return 0;
    uint64_t optional_size = le16(h + 20);
    unsigned characteristics = le16(h + 22);
    uint64_t optional = pe + 24;
    /* SizeOfHeaders is at offset 60 of the optional header (PE32 and PE32+). */
    if (optional_size < 64 || left - optional < optional_size)
        return 0;
    uint64_t length = le32(d + o + optional + 60);
    uint64_t table = optional + optional_size;
    if (left - table < (uint64_t)sections * 40)
        return 0;
    for (unsigned i = 0; i < sections; i++) {
        const uint8_t *s = d + o + table + (uint64_t)i * 40;
        uint64_t raw_size = le32(s + 16), raw_pointer = le32(s + 20);
        if (raw_pointer + raw_size > length)
            length = raw_pointer + raw_size;
    }
    if (length < 512 || length > left)
        return 0;
    *ext = characteristics & 0x2000 ? "dll" : "exe";
    return length;
}

static uint64_t elf_length(const Carver *c, uint64_t o) {
    const uint8_t *d = c->data;
    uint64_t left = c->size - o;
    if (left < 52 || memcmp(d + o, "\x7f" "ELF", 4) != 0)
        return 0;
    unsigned class = d[o + 4], order = d[o + 5], version = d[o + 6];
    if ((class != 1 && class != 2) || (order != 1 && order != 2) || version != 1)
        return 0;
    bool wide = class == 2, little = order == 1;
    if (wide && left < 64)
        return 0;
    const uint8_t *h = d + o;
    uint64_t phoff = wide ? elf_field(h + 32, 8, little) : elf_field(h + 28, 4, little);
    uint64_t shoff = wide ? elf_field(h + 40, 8, little) : elf_field(h + 32, 4, little);
    const uint8_t *counts = h + (wide ? 54 : 42);
    uint64_t phentsize = elf_field(counts, 2, little), phnum = elf_field(counts + 2, 2, little);
    uint64_t shentsize = elf_field(counts + 4, 2, little), shnum = elf_field(counts + 6, 2, little);
    uint64_t ph_need = wide ? 56 : 32, sh_need = wide ? 64 : 40;
    big length = wide ? 64 : 52;

    if (phnum) {
        big table_end = (big)phoff + (big)phnum * phentsize;
        if (phentsize < ph_need || table_end > (big)left)
            return 0;
        if (table_end > length)
            length = table_end;
        for (uint64_t i = 0; i < phnum; i++) {
            const uint8_t *p = h + phoff + i * phentsize;
            big end = wide ? (big)elf_field(p + 8, 8, little) + elf_field(p + 32, 8, little)
                           : (big)elf_field(p + 4, 4, little) + elf_field(p + 16, 4, little);
            if (end > (big)left)
                return 0;
            if (end > length)
                length = end;
        }
    }
    if (shnum) {
        big table_end = (big)shoff + (big)shnum * shentsize;
        if (shentsize < sh_need || table_end > (big)left)
            return 0;
        if (table_end > length)
            length = table_end;
        for (uint64_t i = 0; i < shnum; i++) {
            const uint8_t *s = h + shoff + i * shentsize;
            if (elf_field(s + 4, 4, little) == 8)       /* SHT_NOBITS: no bytes in the file */
                continue;
            big end = wide ? (big)elf_field(s + 24, 8, little) + elf_field(s + 32, 8, little)
                           : (big)elf_field(s + 16, 4, little) + elf_field(s + 20, 4, little);
            if (end > (big)left)
                return 0;
            if (end > length)
                length = end;
        }
    }
    if (length < 84 || length > (big)left)
        return 0;
    return (uint64_t)length;
}

/* The complete file starting at offset o, if any: its length and extension. */
static uint64_t embedded_at(Carver *c, uint64_t o, const char **ext) {
    uint64_t length = 0;
    switch (c->data[o]) {
    case 0x89:
        *ext = "png";
        length = png_length(c, o);
        break;
    case 'G':
        *ext = "gif";
        length = gif_length(c, o);
        break;
    case 'R':
        length = riff_length(c, o, ext);
        break;
    case 'P':
        *ext = "zip";
        length = zip_length(c, o);
        break;
    case 'M':
        length = pe_length(c, o, ext);
        break;
    case 0x7F:
        *ext = "elf";
        length = elf_length(c, o);
        break;
    default:
        break;
    }
    return length;
}

/* --- pieces --------------------------------------------------------------------- */

/* Every character outside [A-Za-z0-9._-] becomes "_" (one per character,
 * not per byte, as re.sub does on a Python str). */
static Str safe_name(Arena *a, Str name) {
    Buf out;
    buf_init(&out, a);
    size_t at = 0;
    while (at < name.n) {
        uint32_t c = utf8_next(name.p, name.n, &at);
        bool keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-';
        buf_addch(&out, keep ? (char)c : '_');
    }
    if (out.n == 0)
        buf_addc(&out, "unnamed");
    return buf_str(&out);
}

static bool all_zero(const uint8_t *data, uint64_t size) {
    for (uint64_t i = 0; i < size; i++)
        if (data[i])
            return false;
    return true;
}

typedef VEC(SplitPiece) Pieces;

static void add_parts(Arena *a, const Binary *b, Pieces *pieces) {
    const JVal *regions = j_get(view_layout(a, b), "regions");
    for (size_t i = 0; i < j_len(regions); i++) {
        const JVal *r = j_at(regions, i);
        SplitPiece piece;
        memset(&piece, 0, sizeof piece);
        piece.kind = j_text(j_get(r, "kind")).p;
        piece.name = j_text(j_get(r, "name"));
        piece.offset = j_number(j_get(r, "offset"));
        piece.size = j_number(j_get(r, "size"));
        piece.note = str_c("");
        /* A hostile header can describe a region that starts or ends past
         * the end of the file; what is saved is the part that exists. */
        big start = piece.offset < 0 ? 0 : piece.offset;
        big end = piece.offset + piece.size;
        if (start > (big)b->size)
            start = b->size;
        if (end > (big)b->size)
            end = b->size;
        if (end < start)
            end = start;
        piece.data = b->data + (uint64_t)start;
        piece.length = (uint64_t)(end - start);
        if (strcmp(piece.kind, "padding") == 0 && all_zero(piece.data, piece.length)) {
            piece.path = STR_NONE;
            piece.note = str_c("zero padding, not saved");
        } else {
            piece.path = str_printf(a, "parts/%02zu_%s.bin", i, safe_name(a, piece.name).p);
        }
        *VEC_PUSH(a, *pieces) = piece;
    }
}

static void add_embedded(Arena *a, const Binary *b, Pieces *pieces) {
    Carver carver = {b->data, b->size, a, false, NULL, 0};
    size_t nparts = pieces->n, part = 0, counter = 0;
    uint64_t o = 1;
    while (o < b->size) {
        const char *ext = NULL;
        uint64_t length = embedded_at(&carver, o, &ext);
        if (length == 0) {
            o++;
            continue;
        }
        /* The part that holds this offset. Parts are in file order, and so
         * are the hits, so the search never goes back. */
        while (part < nparts) {
            const SplitPiece *p = &pieces->v[part];
            if ((big)o < p->offset + p->size)
                break;
            part++;
        }
        Str where = part < nparts && pieces->v[part].offset <= (big)o ? pieces->v[part].name
                                                                    : str_c("the file");
        SplitPiece piece;
        memset(&piece, 0, sizeof piece);
        piece.kind = "embedded";
        piece.name = str_printf(a, "%s file", ext);
        piece.offset = o;
        piece.size = length;
        piece.data = b->data + o;
        piece.length = length;
        piece.path = str_printf(a, "embedded/%03zu_0x%08" PRIx64 ".%s", counter++, o, ext);
        piece.note = str_printf(a, "found inside %s", where.p);
        *VEC_PUSH(a, *pieces) = piece;
        o += length;
    }
}

Split *split_plan(Arena *a, const Binary *b) {
    Pieces pieces = {0};
    add_parts(a, b, &pieces);
    add_embedded(a, b, &pieces);
    Split *split = arena_alloc(a, sizeof *split);
    split->binary = b;
    split->pieces = pieces.v;
    split->npieces = pieces.n;
    for (size_t i = 0; i < pieces.n; i++) {
        if (pieces.v[i].path.p == NULL)
            continue;
        split->count++;
        split->bytes += pieces.v[i].length;
    }
    return split;
}

JVal *split_view(Arena *a, const Split *split, const char *dest) {
    JVal *pieces = j_list(a);
    for (size_t i = 0; i < split->npieces; i++) {
        const SplitPiece *p = &split->pieces[i];
        big address = 0;
        bool mapped = p->offset >= 0 && p->offset <= (big)UINT64_MAX &&
                      binary_offset_to_vaddr(split->binary, (uint64_t)p->offset, &address);
        JVal *row = j_dict(a);
        j_set(a, row, "path", j_str(a, p->path));
        j_set(a, row, "kind", j_cstr(a, p->kind));
        j_set(a, row, "name", j_str(a, p->name));
        j_set(a, row, "offset", j_int(a, p->offset));
        j_set(a, row, "size", j_int(a, p->size));
        j_set(a, row, "address", j_opt_hex(a, mapped, address));
        j_set(a, row, "note", j_str(a, p->note));
        j_push(a, pieces, row);
    }
    JVal *d = j_dict(a);
    j_set(a, d, "dest", j_cstr(a, dest));
    j_set(a, d, "count", j_int(a, split->count));
    j_set(a, d, "bytes", j_int(a, split->bytes));
    j_set(a, d, "index", j_cstr(a, "index.txt"));
    j_set(a, d, "pieces", pieces);
    return d;
}

/* --- index.txt ------------------------------------------------------------------ */

Str split_index(Arena *a, const Split *split) {
    const Binary *b = split->binary;
    char digest[65], number[44];
    sha256_hex(b->data, b->size, digest);
    Buf out;
    buf_init(&out, a);
    buf_printf(&out, "%s  %s bytes  sha256 %s\n", b->path ? platform_basename(b->path) : "",
               dec_big(number, b->size), digest);
    for (size_t i = 0; i < split->npieces; i++) {
        const SplitPiece *p = &split->pieces[i];
        char offset[40];
        buf_printf(&out, "%s  %s  %s  %s  %s  %s\n", hex_big(offset, p->offset),
                   dec_big(number, p->size), p->kind, p->path.p ? p->path.p : "-", p->name.p,
                   p->note.p);
    }
    return buf_str(&out);
}

/* --- writing -------------------------------------------------------------------- */

/* os.makedirs(path, exist_ok=True) */
static bool make_folders(Arena *a, const char *path) {
    size_t n = strlen(path);
    char *partial = arena_alloc(a, n + 1);
    memcpy(partial, path, n + 1);
    for (size_t i = 1; i <= n; i++) {
        if (i < n && !fs_is_separator(partial[i]))
            continue;
        char saved = partial[i];
        partial[i] = '\0';
        bool drive = i == 2 && partial[1] == ':';       /* "C:" is not a folder to make */
        if (!drive && !fs_is_separator(partial[i - 1]) && !fs_mkdir(partial) &&
            fs_kind(partial, true) != FS_DIR) {
            return false;
        }
        partial[i] = saved;
    }
    return true;
}

static void write_file(Err *err, const char *path, const uint8_t *data, uint64_t size) {
    FILE *f = fs_create(path);
    if (f == NULL)
        err_throw(err, ERR_OS, "cannot write %s: %s", path, strerror(errno));
    bool ok = true;
    int code = 0;
    /* In pieces: fwrite() of several gigabytes at once is not reliable everywhere. */
    for (uint64_t done = 0; ok && done < size;) {
        size_t chunk = size - done > (1u << 26) ? (1u << 26) : (size_t)(size - done);
        if (fwrite(data + done, 1, chunk, f) != chunk) {
            ok = false;
            code = errno;
        }
        done += chunk;
    }
    if (fclose(f) != 0 && ok) {
        ok = false;
        code = errno;
    }
    if (!ok)
        err_throw(err, ERR_OS, "cannot write %s: %s", path, strerror(code));
}

void split_write(Arena *a, Err *err, const Split *split, const char *folder,
                 const char *shown) {
    FsKind kind = fs_kind(folder, true);
    if (kind == FS_MISSING) {
        if (!make_folders(a, folder))
            err_throw(err, ERR_OS, "cannot create %s: %s", shown, strerror(errno));
    } else {
        FsEntry *entries = NULL;
        size_t count = 0;
        if (kind != FS_DIR || !fs_list(a, folder, 1, &entries, &count) || count > 0)
            err_throw(err, ERR_OTHER, "%s is not empty; choose a new or empty folder", shown);
    }
    bool made_parts = false, made_embedded = false;
    for (size_t i = 0; i < split->npieces; i++) {
        const SplitPiece *p = &split->pieces[i];
        if (p->path.p == NULL)
            continue;
        bool *made = strncmp(p->path.p, "parts/", 6) == 0 ? &made_parts : &made_embedded;
        if (!*made) {
            const char *sub = str_printf(a, "%s/%s", folder,
                                         made == &made_parts ? "parts" : "embedded").p;
            if (!fs_mkdir(sub) && fs_kind(sub, false) != FS_DIR)
                err_throw(err, ERR_OS, "cannot create %s: %s", sub, strerror(errno));
            *made = true;
        }
        write_file(err, str_printf(a, "%s/%s", folder, p->path.p).p, p->data, p->length);
    }
    Str index = split_index(a, split);
    write_file(err, str_printf(a, "%s/index.txt", folder).p, (const uint8_t *)index.p, index.n);
}
