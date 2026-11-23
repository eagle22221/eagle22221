/* Binary model helpers and the bounds-checked Reader. */
#include "model.h"

#include <math.h>

/* --- loading ------------------------------------------------------------------ */

Binary *binary_load(Arena *arena, Err *err, const uint8_t *data, uint64_t size,
                    const char *path) {
    Binary *b = arena_alloc(arena, sizeof *b);
    b->arena = arena;
    b->err = err;
    b->data = data;
    b->size = size;
    b->path = path;
    b->format = "";
    b->arch = str_c("unknown");
    b->endian = "little";
    b->kind = "unknown";
    if (size >= 4 && memcmp(data, "\x7f" "ELF", 4) == 0) {
        elf_parse(b);
    } else if (size >= 2 && memcmp(data, "MZ", 2) == 0) {
        pe_parse(b);
    } else {
        err_throw(err, ERR_UNKNOWN_FORMAT, "%s",
                  size ? "not an ELF or PE file (no \\x7fELF or MZ signature)"
                       : "file is empty");
    }
    return b;
}

void binary_warn(Binary *b, const char *fmt, ...) {
    va_list args, again;
    va_start(args, fmt);
    va_copy(again, args);
    int n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (n < 0)
        n = 0;
    char *text = arena_alloc(b->arena, (size_t)n + 1);
    vsnprintf(text, (size_t)n + 1, fmt, again);
    va_end(again);
    Str warning = {text, (size_t)n};
    *VEC_PUSH(b->arena, b->warnings) = warning;
}

/* --- address mapping ---------------------------------------------------------- */

void binary_add_map(Binary *b, big vaddr, big offset, big size) {
    if (offset < 0 || offset >= (big)b->size)
        return;
    if (size > (big)b->size - offset)
        size = (big)b->size - offset;       /* clip to what the file holds */
    if (size > 0) {
        Map m = {vaddr, (uint64_t)offset, (uint64_t)size};
        *VEC_PUSH(b->arena, b->maps) = m;
    }
}

void binary_note_overlay(Binary *b, big end_of_image) {
    if (end_of_image > 0 && end_of_image < (big)b->size) {
        Meta *m = meta_slot(b->arena, &b->metadata, "overlay");
        m->kind = META_OVERLAY;
        m->number = (uint64_t)end_of_image;
        m->number2 = b->size - (uint64_t)end_of_image;
    }
}

const Map *binary_map_for(const Binary *b, big vaddr) {
    for (size_t i = 0; i < b->maps.n; i++) {
        const Map *m = &b->maps.v[i];
        if (vaddr >= m->vaddr && vaddr - m->vaddr < (big)m->size)
            return m;
    }
    return NULL;
}

bool binary_vaddr_to_offset(const Binary *b, big vaddr, uint64_t *offset) {
    const Map *m = binary_map_for(b, vaddr);
    if (m == NULL)
        return false;
    *offset = m->offset + (uint64_t)(vaddr - m->vaddr);
    return true;
}

bool binary_offset_to_vaddr(const Binary *b, uint64_t offset, big *vaddr) {
    for (size_t i = 0; i < b->maps.n; i++) {
        const Map *m = &b->maps.v[i];
        if (offset >= m->offset && offset - m->offset < m->size) {
            *vaddr = m->vaddr + (offset - m->offset);
            return true;
        }
    }
    return false;
}

const uint8_t *binary_read(const Binary *b, big vaddr, big size, uint64_t *got) {
    const Map *m = binary_map_for(b, vaddr);
    *got = 0;
    if (m == NULL || size <= 0)
        return b->data;
    uint64_t skip = (uint64_t)(vaddr - m->vaddr);
    uint64_t available = m->size - skip;
    *got = size < (big)available ? (uint64_t)size : available;
    return b->data + m->offset + skip;
}

const Section *binary_section_at(const Binary *b, big vaddr) {
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        big extent = s->vsize ? s->vsize : 1;
        if (s->vaddr && vaddr >= s->vaddr && vaddr - s->vaddr < extent)
            return s;
    }
    return NULL;
}

bool binary_is_address(const Binary *b, big vaddr) {
    if (binary_map_for(b, vaddr) != NULL || binary_section_at(b, vaddr) != NULL)
        return true;
    for (size_t i = 0; i < b->segments.n; i++) {
        const Segment *s = &b->segments.v[i];
        if (str_eq_c(s->type, "LOAD") && vaddr >= (big)s->vaddr &&
            vaddr - s->vaddr < (big)s->vsize)
            return true;
    }
    return false;
}

static int compare_code_ranges(const void *pa, const void *pb) {
    const CodeRange *a = pa, *b = pb;
    if (a->start != b->start)
        return a->start < b->start ? -1 : 1;
    return (a->size > b->size) - (a->size < b->size);
}

void binary_executable_ranges(const Binary *b, Arena *a, CodeRanges *out) {
    out->n = 0;
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        if (strchr(s->perms, 'x') && s->size && s->vaddr) {
            CodeRange r = {s->vaddr, s->size};
            *VEC_PUSH(a, *out) = r;
        }
    }
    if (out->n == 0) {      /* no section headers: fall back to executable segments */
        for (size_t i = 0; i < b->segments.n; i++) {
            const Segment *s = &b->segments.v[i];
            if (str_eq_c(s->type, "LOAD") && strchr(s->perms, 'x') && s->size) {
                CodeRange r = {s->vaddr, s->size};
                *VEC_PUSH(a, *out) = r;
            }
        }
    }
    if (out->n > 1)
        qsort(out->v, out->n, sizeof *out->v, compare_code_ranges);
}

/* --- dictionaries -------------------------------------------------------------- */

Meta *meta_slot(Arena *a, MetaDict *dict, const char *key) {
    for (size_t i = 0; i < dict->n; i++)
        if (strcmp(dict->v[i].key, key) == 0)
            return &dict->v[i];
    Meta *m = VEC_PUSH(a, *dict);
    memset(m, 0, sizeof *m);
    m->key = key;
    return m;
}

const Meta *meta_get(const MetaDict *dict, const char *key) {
    for (size_t i = 0; i < dict->n; i++)
        if (strcmp(dict->v[i].key, key) == 0)
            return &dict->v[i];
    return NULL;
}

void meta_set_str(Arena *a, MetaDict *dict, const char *key, Str value) {
    Meta *m = meta_slot(a, dict, key);
    m->kind = value.p ? META_STR : META_NONE;
    m->text = value;
}

void meta_set_bool(Arena *a, MetaDict *dict, const char *key, bool value) {
    Meta *m = meta_slot(a, dict, key);
    m->kind = META_BOOL;
    m->flag = value;
}

/* --- entropy -------------------------------------------------------------------
 * Python: -sum(n / total * math.log2(n / total) for n in Counter(data).values())
 * The terms are added in order of first appearance of each byte value and
 * with the compensated summation CPython's sum() uses for floats, so the
 * result is the same double. */

double entropy(const uint8_t *data, uint64_t size) {
    if (size == 0)
        return 0.0;
    uint64_t counts[256] = {0};
    uint8_t order[256];
    size_t distinct = 0;
    for (uint64_t i = 0; i < size; i++) {
        if (counts[data[i]]++ == 0)
            order[distinct++] = data[i];
    }
    double total = (double)size;
    double sum = 0.0, compensation = 0.0;
    for (size_t i = 0; i < distinct; i++) {
        double p = (double)counts[order[i]] / total;
        double x = p * log2(p);
        if (i == 0) {
            sum = 0.0 + x;
            continue;
        }
        double t = sum + x;
        if (fabs(sum) >= fabs(x))
            compensation += (sum - t) + x;
        else
            compensation += (x - t) + sum;
        sum = t;
    }
    if (compensation != 0.0 && isfinite(compensation))
        sum += compensation;
    return -sum;
}

/* --- reader -------------------------------------------------------------------- */

static bool rd_fail(const Reader *r, big offset, big size) {
    char off[40], total[40], count[44];
    err_set(r->err, ERR_PARSE, "read of %s bytes at offset %s is outside the file (%s bytes)",
            dec_big(count, size), hex_big(off, offset), hex_big(total, (big)r->size));
    return false;
}

const uint8_t *rd_try(const Reader *r, big offset, big size) {
    if (offset < 0 || size < 0 || offset + size > (big)r->size) {
        rd_fail(r, offset, size);
        return NULL;
    }
    return r->data + (uint64_t)offset;
}

const uint8_t *rd_bytes(const Reader *r, big offset, big size) {
    const uint8_t *p = rd_try(r, offset, size);
    if (p == NULL)
        err_raise(r->err);
    return p;
}

uint16_t rd_get16(const Reader *r, const uint8_t *p) {
    return r->little_endian ? (uint16_t)(p[0] | p[1] << 8) : (uint16_t)(p[1] | p[0] << 8);
}

uint32_t rd_get32(const Reader *r, const uint8_t *p) {
    if (r->little_endian)
        return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
               (uint32_t)p[3] << 24;
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

uint64_t rd_get64(const Reader *r, const uint8_t *p) {
    if (r->little_endian)
        return (uint64_t)rd_get32(r, p) | (uint64_t)rd_get32(r, p + 4) << 32;
    return (uint64_t)rd_get32(r, p + 4) | (uint64_t)rd_get32(r, p) << 32;
}

uint8_t rd_u8(const Reader *r, big offset) {
    return rd_bytes(r, offset, 1)[0];
}

uint16_t rd_u16(const Reader *r, big offset) {
    return rd_get16(r, rd_bytes(r, offset, 2));
}

uint32_t rd_u32(const Reader *r, big offset) {
    return rd_get32(r, rd_bytes(r, offset, 4));
}

uint64_t rd_u64(const Reader *r, big offset) {
    return rd_get64(r, rd_bytes(r, offset, 8));
}

bool rd_cstring_try(const Reader *r, Arena *a, big offset, big limit, Str *out) {
    if (offset < 0 || offset >= (big)r->size) {
        char off[40];
        err_set(r->err, ERR_PARSE, "string offset %s is outside the file",
                hex_big(off, offset));
        return false;
    }
    uint64_t start = (uint64_t)offset;
    uint64_t room = r->size - start;
    if (limit < 0)
        limit = 0;
    if (limit < (big)room)
        room = (uint64_t)limit;
    const uint8_t *nul = room ? memchr(r->data + start, 0, (size_t)room) : NULL;
    size_t length = nul ? (size_t)(nul - (r->data + start)) : (size_t)room;
    *out = utf8_decode(a, r->data + start, length);
    return true;
}

Str rd_cstring(const Reader *r, Arena *a, big offset, big limit) {
    Str s;
    if (!rd_cstring_try(r, a, offset, limit, &s))
        err_raise(r->err);
    return s;
}

/* --- string set ---------------------------------------------------------------- */

bool strset_has(const StrSet *set, Str s) {
    if (set->cap == 0)
        return false;
    size_t mask = set->cap - 1;
    for (size_t i = (size_t)str_hash(s) & mask;; i = (i + 1) & mask) {
        if (set->slots[i].p == NULL)
            return false;
        if (str_eq(set->slots[i], s))
            return true;
    }
}

static void strset_insert(StrSet *set, Str s) {
    size_t mask = set->cap - 1;
    size_t i = (size_t)str_hash(s) & mask;
    while (set->slots[i].p != NULL)
        i = (i + 1) & mask;
    set->slots[i] = s;
    set->count++;
}

bool strset_add(Arena *a, StrSet *set, Str s) {
    if (strset_has(set, s))
        return false;
    if ((set->count + 1) * 2 > set->cap) {
        StrSet grown = {NULL, set->cap ? set->cap * 2 : 64, 0};
        grown.slots = arena_array(a, grown.cap, sizeof *grown.slots);
        for (size_t i = 0; i < set->cap; i++)
            if (set->slots[i].p != NULL)
                strset_insert(&grown, set->slots[i]);
        *set = grown;
    }
    if (s.p == NULL)
        s.p = "";
    strset_insert(set, s);
    return true;
}
