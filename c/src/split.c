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

/* Results of walks that were already made, by where the walk stood.
 *
 * A PNG is a chain of chunks and a GIF a chain of blocks, and where a chain
 * leads depends only on where it stands, not on where it began. A hostile
 * file can start very many images that all run into one long chain; walking
 * it again for each would take time quadratic in the file size. So a long
 * walk leaves a mark every WALK_STRIDE steps, with its outcome, and a later
 * walk that reaches a mark stops there. That changes no result. */
typedef struct {
    uint64_t *keys, *values;        /* keys are stored + 1; 0 is an empty slot */
    size_t cap, count;
} Memo;

enum { WALK_STRIDE = 32 };

typedef struct {
    const uint8_t *data;
    uint64_t size;
    Arena *arena;
    bool zip_ready;
    ZipEnd *zip_ends;               /* sorted by start, then by eocd */
    size_t nzip_ends;
    Memo png, gif, elf;
    VEC(uint64_t) marks;            /* of the walk in progress */
    VEC(uint64_t) mark_images;      /* GIF: images seen before each mark */
} Carver;

static size_t memo_slot(const Memo *m, uint64_t key) {
    size_t i = (size_t)((key * UINT64_C(0x9E3779B97F4A7C15)) >> 32) & (m->cap - 1);
    while (m->keys[i] != 0 && m->keys[i] != key + 1)
        i = (i + 1) & (m->cap - 1);
    return i;
}

static bool memo_get(const Memo *m, uint64_t key, uint64_t *value) {
    if (m->cap == 0)
        return false;
    size_t i = memo_slot(m, key);
    if (m->keys[i] == 0)
        return false;
    *value = m->values[i];
    return true;
}

static void memo_put(Arena *a, Memo *m, uint64_t key, uint64_t value) {
    if ((m->count + 1) * 2 > m->cap) {
        Memo grown = {0};
        grown.cap = m->cap ? m->cap * 2 : 256;
        grown.keys = arena_array(a, grown.cap, sizeof *grown.keys);
        grown.values = arena_array(a, grown.cap, sizeof *grown.values);
        for (size_t i = 0; i < m->cap; i++) {
            if (m->keys[i] == 0)
                continue;
            size_t slot = memo_slot(&grown, m->keys[i] - 1);
            grown.keys[slot] = m->keys[i];
            grown.values[slot] = m->values[i];
        }
        grown.count = m->count;
        *m = grown;
    }
    size_t i = memo_slot(m, key);
    if (m->keys[i] == 0) {
        m->keys[i] = key + 1;
        m->count++;
    }
    m->values[i] = value;
}

static uint64_t png_length(Carver *c, uint64_t o) {
    static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    const uint8_t *d = c->data;
    uint64_t n = c->size;
    /* signature, then IHDR: length (4), type (4), data (13), crc (4) */
    if (n - o < 8 + 25 || memcmp(d + o, signature, 8) != 0)
        return 0;
    const uint8_t *header = d + o + 8;
    if (be32(header) != 13 || memcmp(header + 4, "IHDR", 4) != 0 ||
        crc32_of(header + 4, 4 + 13) != be32(header + 21))
        return 0;
    uint64_t p = o + 8 + 25, end = 0;       /* end: one past IEND, 0 when there is none */
    c->marks.n = 0;
    for (size_t steps = 0;; steps++) {
        if (steps >= WALK_STRIDE) {
            if (memo_get(&c->png, p, &end))
                break;
            if (steps % WALK_STRIDE == 0)
                *VEC_PUSH(c->arena, c->marks) = p;
        }
        if (n - p < 12)
            break;
        uint64_t length = be32(d + p);
        if (length > n - p - 12)
            break;
        const uint8_t *type = d + p + 4;
        p += 12 + length;
        if (memcmp(type, "IEND", 4) == 0) {
            end = p;
            break;
        }
    }
    for (size_t i = 0; i < c->marks.n; i++)
        memo_put(c->arena, &c->png, c->marks.v[i], end);
    return end ? end - o : 0;
}

/* The size of a GIF colour table, given the packed byte that announces it. */
static uint64_t gif_table(uint8_t packed) {
    return packed & 0x80 ? (uint64_t)3 << ((packed & 7) + 1) : 0;
}

static uint64_t gif_length(Carver *c, uint64_t o) {
    const uint8_t *d = c->data;
    uint64_t n = c->size;
    /* signature (6), logical screen descriptor (7) */
    if (n - o < 13 || (memcmp(d + o, "GIF87a", 6) != 0 && memcmp(d + o, "GIF89a", 6) != 0))
        return 0;
    uint64_t table = gif_table(d[o + 10]);
    if (table > n - o - 13)
        return 0;
    /* The walk stands either before a block or before a data sub-block (a
     * size byte and that many bytes; a zero size ends the run). */
    uint64_t p = o + 13 + table, end = 0, images = 0;
    bool in_data = false, later_image = false;
    c->marks.n = 0;
    c->mark_images.n = 0;
    for (size_t steps = 0;; steps++) {
        if (steps >= WALK_STRIDE) {
            uint64_t known;
            if (memo_get(&c->gif, p << 1 | in_data, &known)) {
                end = known >> 1;
                later_image = known & 1;
                break;
            }
            if (steps % WALK_STRIDE == 0) {
                *VEC_PUSH(c->arena, c->marks) = p << 1 | in_data;
                *VEC_PUSH(c->arena, c->mark_images) = images;
            }
        }
        if (p >= n)
            break;
        if (in_data) {
            uint64_t size = d[p];
            p++;
            if (size == 0)
                in_data = false;
            else if (size > n - p)
                break;
            else
                p += size;
        } else if (d[p] == 0x3B) {
            end = p + 1;
            break;
        } else if (d[p] == 0x2C) {
            /* image descriptor: 0x2C, position and size (8), packed (1); an
             * optional colour table; the LZW minimum code size (1) */
            if (n - p < 10)
                break;
            table = gif_table(d[p + 9]);
            p += 10;
            if (table > n - p || n - p - table < 1)
                break;
            p += table + 1;
            images++;
            in_data = true;
        } else if (d[p] == 0x21) {
            /* extension: 0x21, label (1) */
            if (n - p < 2)
                break;
            p += 2;
            in_data = true;
        } else {
            break;
        }
    }
    for (size_t i = 0; i < c->marks.n; i++) {
        bool image = later_image || images > c->mark_images.v[i];
        memo_put(c->arena, &c->gif, c->marks.v[i], end ? end << 1 | image : 0);
    }
    return end && (images > 0 || later_image) ? end - o : 0;
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
    /* signature (4), COFF header (20) and the optional header up to and
     * including SizeOfHeaders, which is at offset 60 for PE32 and PE32+ */
    if (pe > left || left - pe < 88)
        return 0;
    const uint8_t *h = d + o + pe;
    if (memcmp(h, "PE\0\0", 4) != 0)
        return 0;
    uint64_t sections = le16(h + 6);
    uint64_t table = pe + 24 + le16(h + 20);
    if (sections < 1 || sections > 96 || table > left || left - table < sections * 40)
        return 0;
    uint64_t length = le32(h + 24 + 60);
    for (uint64_t i = 0; i < sections; i++) {
        const uint8_t *s = d + o + table + i * 40;
        uint64_t end = (uint64_t)le32(s + 16) + le32(s + 20);   /* raw size + raw pointer */
        if (end > length)
            length = end;
    }
    if (length < 512 || length > left)
        return 0;
    *ext = le16(h + 22) & 0x2000 ? "dll" : "exe";
    return length;
}

/* --- ELF tables -------------------------------------------------------------------
 * An ELF's length needs the largest offset + size over its program and
 * section headers, up to 65535 of each. Many ELF headers can point into one
 * shared table, so the largest value of every aligned run of ELF_RUN entries
 * is kept once it has been worked out; a header then costs a few hundred
 * steps however long its tables are. */

enum { ELF_RUN = 256 };

typedef struct {
    bool sections;                  /* section headers, else program headers */
    bool wide, little;
    uint64_t entry;                 /* bytes per table entry */
} ElfTable;

/* Where the bytes of one table entry end in the file: offset + size, or 0
 * for a section that has none (SHT_NOBITS). Sums that do not fit in 64 bits
 * come back as the largest value: either way, past the end of any file. */
static uint64_t elf_entry_end(const uint8_t *p, const ElfTable *t) {
    uint64_t offset, size;
    if (t->sections) {
        if (elf_field(p + 4, 4, t->little) == 8)
            return 0;
        offset = t->wide ? elf_field(p + 24, 8, t->little) : elf_field(p + 16, 4, t->little);
        size = t->wide ? elf_field(p + 32, 8, t->little) : elf_field(p + 20, 4, t->little);
    } else {
        offset = t->wide ? elf_field(p + 8, 8, t->little) : elf_field(p + 4, 4, t->little);
        size = t->wide ? elf_field(p + 32, 8, t->little) : elf_field(p + 16, 4, t->little);
    }
    return offset > UINT64_MAX - size ? UINT64_MAX : offset + size;
}

/* The largest entry end of the `count` entries that start at file offset
 * `start` (all inside the file), or any value above `limit` as soon as one
 * entry is found to exceed it. */
static uint64_t elf_table_max(Carver *c, uint64_t start, uint64_t count, const ElfTable *t,
                              uint64_t limit) {
    /* Entries are numbered along the file: number g is at shift + g * entry. */
    uint64_t shift = start % t->entry, first = start / t->entry;
    uint64_t group = (uint64_t)t->sections | (uint64_t)t->wide << 1 | (uint64_t)t->little << 2 |
                     shift << 3;                    /* shift < 64: nine bits in all */
    uint64_t most = 0;
    for (uint64_t g = first; g < first + count && most <= limit;) {
        uint64_t value;
        if (g % ELF_RUN == 0 && first + count - g >= ELF_RUN) {
            uint64_t key = (g / ELF_RUN) << 9 | group;
            if (!memo_get(&c->elf, key, &value)) {
                value = 0;
                for (uint64_t i = 0; i < ELF_RUN; i++) {
                    uint64_t end = elf_entry_end(c->data + shift + (g + i) * t->entry, t);
                    if (end > value)
                        value = end;
                }
                memo_put(c->arena, &c->elf, key, value);
            }
            g += ELF_RUN;
        } else {
            value = elf_entry_end(c->data + shift + g * t->entry, t);
            g++;
        }
        if (value > most)
            most = value;
    }
    return most;
}

static uint64_t elf_length(Carver *c, uint64_t o) {
    const uint8_t *h = c->data + o;
    uint64_t left = c->size - o;
    if (left < 7 || memcmp(h, "\x7f" "ELF", 4) != 0)
        return 0;
    if ((h[4] != 1 && h[4] != 2) || (h[5] != 1 && h[5] != 2) || h[6] != 1)
        return 0;
    bool wide = h[4] == 2, little = h[5] == 1;
    if (left < (wide ? 64u : 52u))
        return 0;
    uint64_t phoff = wide ? elf_field(h + 32, 8, little) : elf_field(h + 28, 4, little);
    uint64_t shoff = wide ? elf_field(h + 40, 8, little) : elf_field(h + 32, 4, little);
    const uint8_t *counts = h + (wide ? 54 : 42);
    uint64_t phentsize = elf_field(counts, 2, little), phnum = elf_field(counts + 2, 2, little);
    uint64_t shentsize = elf_field(counts + 4, 2, little), shnum = elf_field(counts + 6, 2, little);
    ElfTable segments = {false, wide, little, wide ? 56 : 32};
    ElfTable sections = {true, wide, little, wide ? 64 : 40};
    if ((phnum && phentsize != segments.entry) || (shnum && shentsize != sections.entry))
        return 0;
    /* Where the two tables end (a table with no entries still "ends" at its
     * offset). Both must be inside the file before an entry is read. */
    big ph_end = (big)phoff + (big)phnum * phentsize, sh_end = (big)shoff + (big)shnum * shentsize;
    big tables = ph_end > sh_end ? ph_end : sh_end;
    if (tables > (big)left)
        return 0;
    uint64_t length = (uint64_t)tables, most;
    most = elf_table_max(c, o + phoff, phnum, &segments, left);
    if (most > length)
        length = most;
    if (length <= left) {
        most = elf_table_max(c, o + shoff, shnum, &sections, left);
        if (most > length)
            length = most;
    }
    if (length < 84 || length > left)
        return 0;
    return length;
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
    Carver carver;
    memset(&carver, 0, sizeof carver);
    carver.data = b->data;
    carver.size = b->size;
    carver.arena = a;
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

/* os.makedirs(path, exist_ok=True): the folder, after any missing parents. */
static bool make_folders(Arena *a, const char *path) {
    if (fs_mkdir(path) || fs_kind(path, true) == FS_DIR)
        return true;
    int code = errno;
    size_t n = strlen(path);
    while (n > 0 && fs_is_separator(path[n - 1]))
        n--;
    while (n > 0 && !fs_is_separator(path[n - 1]))
        n--;
    while (n > 0 && fs_is_separator(path[n - 1]))
        n--;
    if (n == 0) {                       /* no parent left to make */
        errno = code;
        return false;
    }
    if (!make_folders(a, str_copy(a, path, n).p))
        return false;
    return fs_mkdir(path) || fs_kind(path, true) == FS_DIR;
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
