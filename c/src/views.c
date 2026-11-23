/* JSON-ready views of a binary (port of views.py). */
#include "views.h"

#include "hash.h"
#include "platform.h"

typedef struct {
    const char *key, *label, *meaning;
} SecurityLabel;

/* "protect": yes is good. "risk": a value is a warning sign. "info": neither. */
static const SecurityLabel SECURITY_LABELS[] = {
    {"nx", "Non-executable stack/data (NX, DEP)", "protect"},
    {"pie", "Position-independent executable (PIE)", "protect"},
    {"relro", "Read-only relocations (RELRO)", "protect"},
    {"canary", "Stack canary", "protect"},
    {"fortify", "Fortified libc calls (FORTIFY_SOURCE)", "protect"},
    {"stripped", "Symbols stripped", "info"},
    {"rpath", "RPATH", "risk"},
    {"runpath", "RUNPATH", "risk"},
    {"aslr", "Address randomisation (ASLR)", "protect"},
    {"high_entropy_va", "High-entropy 64-bit ASLR", "protect"},
    {"cfg", "Control Flow Guard", "protect"},
    {"seh", "Structured exception handling used", "info"},
    {"force_integrity", "Forced code-integrity checks", "info"},
    {"signed", "Authenticode signature present", "info"},
    {"dotnet", ".NET (managed) assembly", "info"},
};

static JVal *meta_value(Arena *a, const Meta *m) {
    switch (m->kind) {
    case META_NONE:
        return j_null(a);
    case META_BOOL:
        return j_bool(a, m->flag);
    case META_INT:
        return j_int(a, m->number);
    case META_STR:
        return j_str(a, m->text);
    case META_LIST: {
        JVal *list = j_list(a);
        for (size_t i = 0; i < m->count; i++)
            j_push(a, list, j_str(a, m->items[i]));
        return list;
    }
    case META_OVERLAY: {
        JVal *overlay = j_dict(a);
        j_set(a, overlay, "offset", j_int(a, m->number));
        j_set(a, overlay, "size", j_int(a, m->number2));
        return overlay;
    }
    }
    return j_null(a);
}

static JVal *meta_dict(Arena *a, const MetaDict *dict) {
    JVal *out = j_dict(a);
    for (size_t i = 0; i < dict->n; i++)
        j_set(a, out, dict->v[i].key, meta_value(a, &dict->v[i]));
    return out;
}

static JVal *security_details(Arena *a, const Binary *b) {
    JVal *rows = j_list(a);
    for (size_t i = 0; i < b->security.n; i++) {
        const Meta *m = &b->security.v[i];
        const char *label = m->key, *meaning = "info";
        for (size_t k = 0; k < ARRAY_LEN(SECURITY_LABELS); k++) {
            if (strcmp(SECURITY_LABELS[k].key, m->key) == 0) {
                label = SECURITY_LABELS[k].label;
                meaning = SECURITY_LABELS[k].meaning;
            }
        }
        bool none = m->kind == META_NONE;
        bool yes = m->kind == META_BOOL && m->flag;
        if (none && strcmp(meaning, "risk") == 0)
            continue;
        const char *state = "neutral";
        if (strcmp(meaning, "protect") == 0) {
            if (none)
                state = "neutral";
            else if (yes || (m->kind == META_STR && str_eq_c(m->text, "full")))
                state = "good";
            else if (m->kind == META_STR && str_eq_c(m->text, "partial"))
                state = "warn";
            else
                state = "bad";
        } else if (strcmp(meaning, "risk") == 0) {
            state = "warn";
        }
        JVal *row = j_dict(a);
        j_set(a, row, "key", j_cstr(a, m->key));
        j_set(a, row, "label", j_cstr(a, label));
        if (none)
            j_set(a, row, "value", j_cstr(a, "n/a"));
        else if (m->kind == META_BOOL)
            j_set(a, row, "value", j_cstr(a, m->flag ? "yes" : "no"));
        else
            j_set(a, row, "value", j_str(a, m->text));
        j_set(a, row, "state", j_cstr(a, state));
        j_push(a, rows, row);
    }
    return rows;
}

JVal *view_info(Arena *a, const Binary *b) {
    JVal *d = j_dict(a);
    j_set(a, d, "path", j_cstr(a, b->path));
    j_set(a, d, "name", j_cstr(a, b->path ? platform_basename(b->path) : NULL));
    j_set(a, d, "format", j_cstr(a, b->format));
    j_set(a, d, "arch", j_str(a, b->arch));
    j_set(a, d, "bits", j_int(a, b->bits));
    j_set(a, d, "endian", j_cstr(a, b->endian));
    j_set(a, d, "kind", j_cstr(a, b->kind));
    j_set(a, d, "entry", j_opt_hex(a, b->entry.has, b->entry.v));
    j_set(a, d, "image_base", j_hex(a, b->image_base));
    j_set(a, d, "size", j_int(a, b->size));
    j_set(a, d, "entropy", j_float(a, entropy(b->data, b->size)));

    char *md5 = arena_alloc(a, 33), *sha1 = arena_alloc(a, 41), *sha256 = arena_alloc(a, 65);
    md5_hex(b->data, b->size, md5);
    sha1_hex(b->data, b->size, sha1);
    sha256_hex(b->data, b->size, sha256);
    JVal *hashes = j_dict(a);
    j_set(a, hashes, "md5", j_cstr(a, md5));
    j_set(a, hashes, "sha1", j_cstr(a, sha1));
    j_set(a, hashes, "sha256", j_cstr(a, sha256));
    j_set(a, d, "hashes", hashes);

    JVal *libraries = j_list(a);
    for (size_t i = 0; i < b->libraries.n; i++)
        j_push(a, libraries, j_str(a, b->libraries.v[i]));
    j_set(a, d, "libraries", libraries);
    j_set(a, d, "security", meta_dict(a, &b->security));
    j_set(a, d, "security_details", security_details(a, b));
    j_set(a, d, "metadata", meta_dict(a, &b->metadata));

    JVal *counts = j_dict(a);
    j_set(a, counts, "sections", j_int(a, b->sections.n));
    j_set(a, counts, "symbols", j_int(a, b->symbols.n));
    j_set(a, counts, "imports", j_int(a, b->imports.n));
    j_set(a, counts, "exports", j_int(a, b->exports.n));
    j_set(a, d, "counts", counts);

    JVal *warnings = j_list(a);
    for (size_t i = 0; i < b->warnings.n; i++)
        j_push(a, warnings, j_str(a, b->warnings.v[i]));
    j_set(a, d, "warnings", warnings);
    return d;
}

JVal *view_sections(Arena *a, const Binary *b) {
    JVal *rows = j_list(a);
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        /* Python slices data[offset:offset + size], which clips to the file. */
        uint64_t start = s->offset < b->size ? s->offset : b->size;
        uint64_t length = s->size < b->size - start ? s->size : b->size - start;
        JVal *row = j_dict(a);
        j_set(a, row, "name", j_str(a, s->name));
        j_set(a, row, "address", j_opt_hex(a, s->vaddr != 0, s->vaddr));
        j_set(a, row, "vsize", j_int(a, s->vsize));
        j_set(a, row, "offset", j_int(a, s->offset));
        j_set(a, row, "size", j_int(a, s->size));
        j_set(a, row, "perms", j_cstr(a, s->perms));
        j_set(a, row, "type", j_str(a, s->type));
        j_set(a, row, "entropy", j_float(a, entropy(b->data + start, length)));
        j_push(a, rows, row);
    }
    return rows;
}

JVal *view_segments(Arena *a, const Binary *b) {
    JVal *rows = j_list(a);
    for (size_t i = 0; i < b->segments.n; i++) {
        const Segment *s = &b->segments.v[i];
        JVal *row = j_dict(a);
        j_set(a, row, "type", j_str(a, s->type));
        j_set(a, row, "address", j_hex(a, s->vaddr));
        j_set(a, row, "vsize", j_int(a, s->vsize));
        j_set(a, row, "offset", j_int(a, s->offset));
        j_set(a, row, "size", j_int(a, s->size));
        j_set(a, row, "perms", j_cstr(a, s->perms));
        j_push(a, rows, row);
    }
    return rows;
}

JVal *view_imports(Arena *a, const Binary *b) {
    JVal *rows = j_list(a);
    for (size_t i = 0; i < b->imports.n; i++) {
        const Import *imp = &b->imports.v[i];
        JVal *row = j_dict(a);
        j_set(a, row, "library", j_str(a, imp->library));
        j_set(a, row, "name", j_str(a, imp->name));
        j_set(a, row, "address", j_opt_hex(a, imp->address.has, imp->address.v));
        j_set(a, row, "ordinal", imp->ordinal.has ? j_int(a, imp->ordinal.v) : j_null(a));
        j_set(a, row, "version", j_str(a, imp->version));
        j_set(a, row, "delayed", j_bool(a, imp->delayed));
        j_push(a, rows, row);
    }
    return rows;
}

JVal *view_exports(Arena *a, const Binary *b) {
    JVal *rows = j_list(a);
    for (size_t i = 0; i < b->exports.n; i++) {
        const Export *e = &b->exports.v[i];
        JVal *row = j_dict(a);
        j_set(a, row, "name", j_str(a, e->name));
        j_set(a, row, "address", j_opt_hex(a, e->address.has, e->address.v));
        j_set(a, row, "ordinal", e->ordinal.has ? j_int(a, e->ordinal.v) : j_null(a));
        j_set(a, row, "forwarder", j_str(a, e->forwarder));
        j_push(a, rows, row);
    }
    return rows;
}

/* Stable merge sort of symbol pointers by address. */
static void sort_by_address(const Symbol **items, const Symbol **scratch, size_t n) {
    if (n < 2)
        return;
    size_t half = n / 2;
    sort_by_address(items, scratch, half);
    sort_by_address(items + half, scratch, n - half);
    size_t i = 0, j = half, k = 0;
    while (i < half && j < n)
        scratch[k++] = items[j]->address < items[i]->address ? items[j++] : items[i++];
    while (i < half)
        scratch[k++] = items[i++];
    while (j < n)
        scratch[k++] = items[j++];
    memcpy(items, scratch, n * sizeof *items);
}

JVal *view_symbols(Arena *a, const Binary *b, const char *grep) {
    size_t n = b->symbols.n;
    const Symbol **order = arena_array(a, n, sizeof *order);
    const Symbol **scratch = arena_array(a, n, sizeof *scratch);
    for (size_t i = 0; i < n; i++)
        order[i] = &b->symbols.v[i];
    sort_by_address(order, scratch, n);
    Str needle = str_c(grep ? grep : "");
    JVal *rows = j_list(a);
    for (size_t i = 0; i < n; i++) {
        const Symbol *s = order[i];
        if (!str_contains(s->name, needle))
            continue;
        JVal *row = j_dict(a);
        j_set(a, row, "name", j_str(a, s->name));
        j_set(a, row, "address", j_hex(a, s->address));
        j_set(a, row, "size", j_int(a, s->size));
        j_set(a, row, "type", j_str(a, s->type));
        j_set(a, row, "binding", j_str(a, s->binding));
        j_set(a, row, "section", j_str(a, s->section));
        j_push(a, rows, row);
    }
    return rows;
}

JVal *view_string(Arena *a, const FoundString *s) {
    static const struct {
        unsigned bit;
        const char *name;
    } tag_names[] = {{TAG_URL, "url"}, {TAG_IPV4, "ipv4"}, {TAG_EMAIL, "email"},
                     {TAG_REGISTRY, "registry"}, {TAG_PATH, "path"}};
    JVal *row = j_dict(a);
    j_set(a, row, "offset", j_int(a, s->offset));
    j_set(a, row, "address", j_opt_hex(a, s->vaddr.has, s->vaddr.v));
    j_set(a, row, "section", j_str(a, s->section));
    j_set(a, row, "encoding", j_cstr(a, s->utf16 ? "utf16" : "ascii"));
    j_set(a, row, "text", j_str(a, s->text));
    JVal *tags = j_list(a);
    for (size_t i = 0; i < ARRAY_LEN(tag_names); i++)
        if (s->tags & tag_names[i].bit)
            j_push(a, tags, j_cstr(a, tag_names[i].name));
    j_set(a, row, "tags", tags);
    return row;
}

JVal *view_strings(Arena *a, const Binary *b, big min_length, const char *encoding,
                   const char *grep, bool tagged) {
    StringScan scan;
    FoundString found;
    Str needle = str_c(grep ? grep : "");
    JVal *rows = j_list(a);
    strings_begin(&scan, b, a, min_length, encoding);
    while (strings_next(&scan, a, &found)) {
        if (str_contains(found.text, needle) && (found.tags || !tagged))
            j_push(a, rows, view_string(a, &found));
    }
    return rows;
}

JVal *view_hexdump(Arena *a, const Binary *b, const big *address, const big *offset,
                   big length) {
    char text[40], total[40];
    big start;
    if (offset != NULL) {
        start = *offset;
    } else {
        bool has_address = address != NULL || b->entry.has;
        big where = address != NULL ? *address : b->entry.v;
        start = 0;
        if (has_address) {
            uint64_t mapped;
            if (!binary_vaddr_to_offset(b, where, &mapped))
                err_throw(b->err, ERR_LOCATION, "address %s is not backed by the file",
                          hex_big(text, where));
            start = mapped;
        }
    }
    if (start < 0 || start >= (big)(b->size ? b->size : 1))
        err_throw(b->err, ERR_LOCATION, "offset %s is outside the file (%s bytes)",
                  hex_big(text, start), hex_big(total, (big)b->size));
    uint64_t first = (uint64_t)start;
    uint64_t count = b->size - first;
    if (length < 0)
        length = 0;
    if (length < (big)count)
        count = (uint64_t)length;

    static const char digits[] = "0123456789abcdef";
    JVal *rows = j_list(a);
    for (uint64_t i = 0; i < count; i += 16) {
        uint64_t chunk = count - i < 16 ? count - i : 16;
        char hex[48], ascii[17];
        size_t h = 0;
        for (uint64_t k = 0; k < chunk; k++) {
            uint8_t c = b->data[first + i + k];
            if (k)
                hex[h++] = ' ';
            hex[h++] = digits[c >> 4];
            hex[h++] = digits[c & 15];
            ascii[k] = (c >= 0x20 && c <= 0x7E) ? (char)c : '.';
        }
        big vaddr;
        bool mapped = binary_offset_to_vaddr(b, first + i, &vaddr);
        JVal *row = j_dict(a);
        j_set(a, row, "offset", j_int(a, first + i));
        j_set(a, row, "address", j_opt_hex(a, mapped, vaddr));
        j_set(a, row, "hex", j_str(a, str_copy(a, hex, h)));
        j_set(a, row, "ascii", j_str(a, str_copy(a, ascii, (size_t)chunk)));
        j_push(a, rows, row);
    }
    JVal *d = j_dict(a);
    j_set(a, d, "offset", j_int(a, first));
    j_set(a, d, "length", j_int(a, count));
    j_set(a, d, "rows", rows);
    return d;
}

typedef struct {
    uint64_t offset, size;
    Str name;
    const char *kind;
    size_t order;
} LayoutItem;

static int compare_layout(const void *pa, const void *pb) {
    const LayoutItem *x = pa, *y = pb;
    if (x->offset != y->offset)
        return x->offset < y->offset ? -1 : 1;
    if (x->size != y->size)
        return x->size > y->size ? -1 : 1;      /* larger first */
    return (x->order > y->order) - (x->order < y->order);
}

static JVal *layout_region(Arena *a, Str name, big offset, big size, const char *kind) {
    JVal *r = j_dict(a);
    j_set(a, r, "name", j_str(a, name));
    j_set(a, r, "offset", j_int(a, offset));
    j_set(a, r, "size", j_int(a, size));
    j_set(a, r, "kind", j_cstr(a, kind));
    return r;
}

JVal *view_layout(Arena *a, const Binary *b) {
    VEC(LayoutItem) items = {0};
    for (size_t i = 0; i < b->regions.n; i++) {
        const Region *r = &b->regions.v[i];
        LayoutItem item = {r->offset, r->size, str_c(r->name), r->kind, items.n};
        *VEC_PUSH(a, items) = item;
    }
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        if (!s->size)
            continue;
        const char *kind = strchr(s->perms, 'x') ? "code" :
                           strcmp(s->perms, "---") != 0 ? "data" : "meta";
        LayoutItem item = {s->offset, s->size, s->name.n ? s->name : str_c("(unnamed)"), kind,
                           items.n};
        *VEC_PUSH(a, items) = item;
    }
    const Meta *overlay = meta_get(&b->metadata, "overlay");
    if (overlay != NULL) {
        LayoutItem item = {overlay->number, overlay->number2, str_c("overlay"), "overlay",
                           items.n};
        *VEC_PUSH(a, items) = item;
    }
    if (items.n > 1)
        qsort(items.v, items.n, sizeof *items.v, compare_layout);
    JVal *regions = j_list(a);
    big cursor = 0;
    for (size_t i = 0; i < items.n; i++) {
        const LayoutItem *item = &items.v[i];
        big off = item->offset;
        big end = off + (big)item->size;
        if (end > (big)b->size)
            end = b->size;
        if (end <= cursor)
            continue;                   /* fully inside something already drawn */
        if (off > cursor)
            j_push(a, regions, layout_region(a, str_c("padding"), cursor, off - cursor,
                                             "padding"));
        big start = off > cursor ? off : cursor;
        j_push(a, regions, layout_region(a, item->name, start, end - start, item->kind));
        cursor = end;
    }
    if (cursor < (big)b->size)
        j_push(a, regions, layout_region(a, str_c("padding"), cursor, (big)b->size - cursor,
                                         "padding"));
    JVal *d = j_dict(a);
    j_set(a, d, "size", j_int(a, b->size));
    j_set(a, d, "regions", regions);
    return d;
}
