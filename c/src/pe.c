/* PE parser (port of vex/pe.py): Windows executables, DLLs and drivers,
 * PE32 and PE32+.
 *
 * Only the DOS/COFF/optional headers are mandatory; every data directory
 * (imports, exports, debug, ...) is parsed independently under err_protect(),
 * so one corrupt table costs a warning, not the whole analysis. */
#include "hash.h"
#include "model.h"

enum {
    DIR_EXPORT = 0, DIR_IMPORT = 1, DIR_EXCEPTION = 3, DIR_SECURITY = 4,
    DIR_DEBUG = 6, DIR_DELAY_IMPORT = 13, DIR_CLR = 14,
    FILE_RELOCS_STRIPPED = 0x0001, FILE_DLL = 0x2000,
    DLLCHAR_HIGH_ENTROPY_VA = 0x20, DLLCHAR_DYNAMIC_BASE = 0x40,
    DLLCHAR_FORCE_INTEGRITY = 0x80, DLLCHAR_NX_COMPAT = 0x100, DLLCHAR_NO_SEH = 0x400,
    DLLCHAR_GUARD_CF = 0x4000,
    SCN_CODE = 0x20, SCN_DATA = 0x40, SCN_BSS = 0x80,
    MAX_ENTRIES = 65536         /* upper bound for any table in a hostile file */
};
#define SCN_EXECUTE UINT32_C(0x20000000)
#define SCN_READ UINT32_C(0x40000000)
#define SCN_WRITE UINT32_C(0x80000000)

typedef struct {
    uint32_t rva, size;
} DataDir;

typedef struct {
    Str name;
    uint32_t rva;
} RawSection;

typedef struct {
    Binary *b;
    Arena *a;
    Err *err;
    Reader r;
    bool is64;
    unsigned nsections, characteristics, dll_chars;
    uint32_t symtab_off, nsymbols, section_align, file_align, headers_size;
    big section_table;
    DataDir dirs[16];
    size_t ndirs;
    VEC(RawSection) raw_sections;
} PeParser;

static const char *machine_name(unsigned machine) {
    switch (machine) {
    case 0x14C: return "x86";
    case 0x8664: return "x86_64";
    case 0x1C0: case 0x1C2: case 0x1C4: return "arm";
    case 0xAA64: return "aarch64";
    case 0x200: return "ia64";
    case 0x5032: case 0x5064: return "riscv";
    default: return NULL;
    }
}

static const char *subsystem_name(unsigned subsystem) {
    switch (subsystem) {
    case 1: return "native";
    case 2: return "gui";
    case 3: return "console";
    case 5: return "os2";
    case 7: return "posix";
    case 9: return "windows-ce";
    case 10: return "efi-application";
    case 11: return "efi-boot-driver";
    case 12: return "efi-runtime-driver";
    case 13: return "efi-rom";
    case 14: return "xbox";
    case 16: return "boot-application";
    default: return NULL;
    }
}

static DataDir directory(const PeParser *p, size_t index) {
    DataDir none = {0, 0};
    return index < p->ndirs ? p->dirs[index] : none;
}

/* File offset of an RVA, or ERR_PARSE naming the structure involved. The RVA
 * may be negative for old-style delay imports, which store absolute
 * addresses that are rebased here. */
static uint64_t rva_offset(const PeParser *p, big rva, const char *what) {
    uint64_t off;
    if (!binary_vaddr_to_offset(p->b, (big)p->b->image_base + rva, &off)) {
        char text[40];
        err_throw(p->err, ERR_PARSE, "%s at RVA %s is not inside the image", what,
                  hex_big(text, rva));
    }
    return off;
}

/* --- headers ------------------------------------------------------------------ */

/* strftime("%Y-%m-%dT%H:%M:%SZ") of a Unix timestamp in UTC. */
static Str format_timestamp(Arena *a, uint32_t timestamp) {
    uint32_t days = timestamp / 86400, rest = timestamp % 86400;
    /* Civil-from-days (proleptic Gregorian), days counted from 1970-01-01. */
    int64_t z = (int64_t)days + 719468;
    int64_t era = z / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    int64_t day = doy - (153 * mp + 2) / 5 + 1;
    int64_t month = mp < 10 ? mp + 3 : mp - 9;
    int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    return str_printf(a, "%04d-%02d-%02dT%02d:%02d:%02dZ", (int)year, (int)month, (int)day,
                      (int)(rest / 3600), (int)(rest / 60 % 60), (int)(rest % 60));
}

static void parse_headers(PeParser *p) {
    Binary *b = p->b;
    const Reader *r = &p->r;
    static const char not_pe[] = "MZ file without a PE header (DOS executable?)";
    if (r->size < 0x40)
        err_throw(p->err, ERR_UNKNOWN_FORMAT, "%s", not_pe);
    big pe = rd_u32(r, 0x3C);
    if (pe + 4 > (big)r->size || memcmp(rd_bytes(r, pe, 4), "PE\0\0", 4) != 0)
        err_throw(p->err, ERR_UNKNOWN_FORMAT, "%s", not_pe);

    /* Any read past the end of the file below means "truncated PE header". */
    big opt = pe + 24;
    const uint8_t *coff = rd_try(r, pe + 4, 20);
    const uint8_t *magic_at = coff ? rd_try(r, opt, 2) : NULL;
    if (magic_at == NULL)
        err_throw(p->err, ERR_PARSE, "truncated PE header");
    unsigned machine = rd_get16(r, coff);
    p->nsections = rd_get16(r, coff + 2);
    uint32_t timestamp = rd_get32(r, coff + 4);
    p->symtab_off = rd_get32(r, coff + 8);
    p->nsymbols = rd_get32(r, coff + 12);
    unsigned opt_size = rd_get16(r, coff + 16);
    p->characteristics = rd_get16(r, coff + 18);
    unsigned magic = rd_get16(r, magic_at);
    if (magic != 0x10B && magic != 0x20B)
        err_throw(p->err, ERR_PARSE, "unsupported optional header magic 0x%x", magic);
    p->is64 = magic == 0x20B;
    big ndirs_off = opt + (p->is64 ? 108 : 92);
    /* The fields are read in this order by the Python parser; the first one
     * that does not fit decides, and they all lead to the same error. */
    const uint8_t *linker = rd_try(r, opt + 2, 2);
    const uint8_t *entry_at = linker ? rd_try(r, opt + 16, 4) : NULL;
    const uint8_t *base_at = entry_at ? (p->is64 ? rd_try(r, opt + 24, 8)
                                                 : rd_try(r, opt + 28, 4)) : NULL;
    const uint8_t *aligns = base_at ? rd_try(r, opt + 32, 8) : NULL;
    const uint8_t *sizes = aligns ? rd_try(r, opt + 56, 16) : NULL;
    const uint8_t *ndirs_at = sizes ? rd_try(r, ndirs_off, 4) : NULL;
    if (ndirs_at == NULL)
        err_throw(p->err, ERR_PARSE, "truncated PE header");
    unsigned linker_major = linker[0], linker_minor = linker[1];
    uint32_t entry_rva = rd_get32(r, entry_at);
    uint64_t image_base = p->is64 ? rd_get64(r, base_at) : rd_get32(r, base_at);
    p->section_align = rd_get32(r, aligns);
    p->file_align = rd_get32(r, aligns + 4);
    p->headers_size = rd_get32(r, sizes + 4);
    uint32_t checksum = rd_get32(r, sizes + 8);
    unsigned subsystem = rd_get16(r, sizes + 12);
    p->dll_chars = rd_get16(r, sizes + 14);
    uint32_t ndirs = rd_get32(r, ndirs_at);
    if (ndirs > 16)
        ndirs = 16;
    for (uint32_t i = 0; i < ndirs; i++) {
        big off = ndirs_off + 4 + (big)i * 8;
        if (off + 8 > opt + opt_size || off + 8 > (big)r->size)
            break;
        const uint8_t *d = rd_bytes(r, off, 8);
        p->dirs[p->ndirs].rva = rd_get32(r, d);
        p->dirs[p->ndirs].size = rd_get32(r, d + 4);
        p->ndirs++;
    }
    p->section_table = opt + opt_size;

    b->bits = p->is64 ? 64 : 32;
    const char *arch = machine_name(machine);
    b->arch = arch ? str_c(arch) : str_printf(p->a, "unknown(0x%x)", machine);
    b->image_base = image_base;
    b->entry.has = entry_rva != 0;
    b->entry.v = (big)image_base + entry_rva;
    if (p->characteristics & FILE_DLL)
        b->kind = "dll";
    else if (subsystem == 1)
        b->kind = "driver";
    else
        b->kind = "executable";
    meta_set_str(b->arena, &b->metadata, "timestamp", format_timestamp(p->a, timestamp));
    const char *sub = subsystem_name(subsystem);
    meta_set_str(b->arena, &b->metadata, "subsystem",
                 sub ? str_c(sub) : str_printf(p->a, "unknown(%u)", subsystem));
    meta_set_str(b->arena, &b->metadata, "linker_version",
                 str_printf(p->a, "%u.%u", linker_major, linker_minor));
    Meta *m = meta_slot(b->arena, &b->metadata, "checksum");
    m->kind = META_INT;
    m->number = checksum;
    binary_add_map(b, image_base, 0, p->headers_size);
}

/* --- sections ----------------------------------------------------------------- */

static void parse_sections(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    uint64_t align = p->section_align ? p->section_align : 0x1000;
    for (unsigned i = 0; i < p->nsections; i++) {
        big off = p->section_table + (big)i * 40;
        const uint8_t *raw_name = rd_bytes(r, off, 8);
        const uint8_t *fields = rd_bytes(r, off + 8, 16);
        uint32_t vsize = rd_get32(r, fields), rva = rd_get32(r, fields + 4);
        uint32_t raw_size = rd_get32(r, fields + 8), raw_ptr = rd_get32(r, fields + 12);
        uint32_t flags = rd_u32(r, off + 36);
        size_t name_len = 0;
        while (name_len < 8 && raw_name[name_len] != 0)
            name_len++;
        Str name = utf8_decode(p->a, raw_name, name_len);
        if (p->file_align >= 0x200)
            raw_ptr &= ~UINT32_C(0x1FF);        /* the loader ignores the low 9 bits */
        big in_file = raw_size;
        if (in_file > (big)r->size - raw_ptr)
            in_file = (big)r->size - raw_ptr;
        if (in_file < 0)
            in_file = 0;
        big mapped = in_file;
        if (vsize) {
            big rounded = (big)(((uint64_t)vsize + align - 1) & ~(align - 1));
            if (rounded < mapped)
                mapped = rounded;
        }
        Section s;
        s.name = name;
        s.vaddr = (big)b->image_base + rva;
        s.vsize = vsize ? vsize : raw_size;
        s.offset = raw_ptr;
        s.size = (uint64_t)in_file;
        s.perms[0] = flags & SCN_READ ? 'r' : '-';
        s.perms[1] = flags & SCN_WRITE ? 'w' : '-';
        s.perms[2] = flags & SCN_EXECUTE ? 'x' : '-';
        s.perms[3] = '\0';
        s.type = str_c(flags & SCN_CODE ? "code" : flags & SCN_DATA ? "data" :
                       flags & SCN_BSS ? "bss" : "");
        RawSection raw = {name, rva};
        *VEC_PUSH(p->a, p->raw_sections) = raw;
        *VEC_PUSH(b->arena, b->sections) = s;
        binary_add_map(b, (big)b->image_base + rva, raw_ptr, mapped);
    }
}

/* --- imports ------------------------------------------------------------------ */

typedef struct {
    PeParser *p;
    big lookup_rva, iat_rva;
    Str library;
    bool delayed;
} ThunkArgs;

static void parse_thunks(void *arg) {
    const ThunkArgs *t = arg;
    PeParser *p = t->p;
    Binary *b = p->b;
    const Reader *r = &p->r;
    unsigned size = p->is64 ? 8 : 4;
    uint64_t ordinal_flag = p->is64 ? UINT64_C(1) << 63 : UINT64_C(1) << 31;
    Str names = str_printf(p->a, "import names of %s", t->library.p);
    Str name_in = str_printf(p->a, "import name in %s", t->library.p);
    uint64_t off = rva_offset(p, t->lookup_rva, names.p);
    for (unsigned i = 0; i < MAX_ENTRIES; i++) {
        big at = (big)off + (big)i * size;
        uint64_t value = p->is64 ? rd_u64(r, at) : rd_u32(r, at);
        if (value == 0)
            break;
        Import imp;
        memset(&imp, 0, sizeof imp);
        if (value & ordinal_flag) {
            imp.ordinal.has = true;
            imp.ordinal.v = value & 0xFFFF;
            imp.name = str_printf(p->a, "#%u", (unsigned)(value & 0xFFFF));
        } else {
            uint64_t name_off = rva_offset(p, (big)(value & 0x7FFFFFFF), name_in.p);
            imp.name = rd_cstring(r, p->a, (big)name_off + 2, 512);
        }
        imp.library = t->library;
        imp.address.has = true;
        imp.address.v = (big)b->image_base + t->iat_rva + (big)i * size;
        imp.delayed = t->delayed;
        *VEC_PUSH(b->arena, b->imports) = imp;
    }
}

static void add_library(Binary *b, Str name) {
    for (size_t i = 0; i < b->libraries.n; i++)
        if (str_eq(b->libraries.v[i], name))
            return;
    *VEC_PUSH(b->arena, b->libraries) = name;
}

static void parse_imports(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    uint32_t rva = directory(p, DIR_IMPORT).rva;
    if (!rva)
        return;
    uint64_t off = rva_offset(p, rva, "import directory");
    for (unsigned i = 0; i < MAX_ENTRIES; i++) {
        const uint8_t *d = rd_bytes(r, (big)off + (big)i * 20, 20);
        uint32_t lookup = rd_get32(r, d), name_rva = rd_get32(r, d + 12);
        uint32_t iat = rd_get32(r, d + 16);
        if (!name_rva && !iat)
            break;
        Str library = rd_cstring(r, p->a, rva_offset(p, name_rva, "import library name"), 512);
        add_library(b, library);
        ThunkArgs args = {p, lookup ? lookup : iat, iat, library, false};
        if (!err_protect(p->err, parse_thunks, &args))
            binary_warn(b, "imports of %s: %s", library.p, p->err->msg);
    }
}

static void parse_delay_imports(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    uint32_t rva = directory(p, DIR_DELAY_IMPORT).rva;
    if (!rva)
        return;
    uint64_t off = rva_offset(p, rva, "delay-import directory");
    for (unsigned i = 0; i < MAX_ENTRIES; i++) {
        const uint8_t *d = rd_bytes(r, (big)off + (big)i * 32, 32);
        uint32_t attrs = rd_get32(r, d);
        big name = rd_get32(r, d + 4), iat = rd_get32(r, d + 12), names = rd_get32(r, d + 16);
        if (!name)
            break;
        if (!(attrs & 1)) {             /* old format stores absolute addresses */
            big base = b->image_base;
            name -= base;
            iat -= base;
            names -= base;
        }
        Str library = rd_cstring(r, p->a, rva_offset(p, name, "delay-import library name"),
                                 512);
        add_library(b, library);
        ThunkArgs args = {p, names, iat, library, true};
        if (!err_protect(p->err, parse_thunks, &args))
            binary_warn(b, "delay imports of %s: %s", library.p, p->err->msg);
    }
}

/* --- exports ------------------------------------------------------------------ */

typedef struct {
    PeParser *p;
    big rva;
    const char *what;
    Str result;
} NameArgs;

static void read_name_at_rva(void *arg) {
    NameArgs *n = arg;
    n->result = rd_cstring(&n->p->r, n->p->a, rva_offset(n->p, n->rva, n->what), 512);
}

static void parse_exports(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    DataDir dir = directory(p, DIR_EXPORT);
    if (!dir.rva)
        return;
    uint64_t off = rva_offset(p, dir.rva, "export directory");
    const uint8_t *d = rd_bytes(r, off, 40);
    uint32_t name_rva = rd_get32(r, d + 12), base = rd_get32(r, d + 16);
    uint32_t nfuncs = rd_get32(r, d + 20), nnames = rd_get32(r, d + 24);
    uint32_t funcs_rva = rd_get32(r, d + 28), names_rva = rd_get32(r, d + 32);
    uint32_t ords_rva = rd_get32(r, d + 36);
    if (name_rva) {
        NameArgs args = {p, name_rva, "export DLL name", STR_NONE};
        if (err_protect(p->err, read_name_at_rva, &args))
            meta_set_str(b->arena, &b->metadata, "dll_name", args.result);
    }
    if (nfuncs > MAX_ENTRIES)
        nfuncs = MAX_ENTRIES;
    if (nnames > MAX_ENTRIES)
        nnames = MAX_ENTRIES;
    Str *names = NULL;                  /* function index -> name */
    if (nnames) {
        names = arena_array(p->a, 65536, sizeof *names);
        uint64_t names_off = rva_offset(p, names_rva, "export name table");
        uint64_t ords_off = rva_offset(p, ords_rva, "export ordinal table");
        for (uint32_t i = 0; i < nnames; i++) {
            unsigned index = rd_u16(r, (big)ords_off + 2 * (big)i);
            const uint8_t *entry = rd_try(r, (big)names_off + 4 * (big)i, 4);
            if (entry == NULL)
                continue;
            NameArgs args = {p, rd_get32(r, entry), "export name", STR_NONE};
            if (err_protect(p->err, read_name_at_rva, &args))
                names[index] = args.result;
        }
    }
    if (!nfuncs)
        return;
    uint64_t funcs_off = rva_offset(p, funcs_rva, "export address table");
    for (uint32_t i = 0; i < nfuncs; i++) {
        uint32_t func_rva = rd_u32(r, (big)funcs_off + 4 * (big)i);
        if (!func_rva)
            continue;
        Export e;
        memset(&e, 0, sizeof e);
        e.ordinal.has = true;
        e.ordinal.v = (uint64_t)base + i;
        if (names != NULL && names[i].p != NULL)
            e.name = names[i];
        else
            e.name = str_printf(p->a, "#%" PRIu64, e.ordinal.v);
        if (dir.rva <= func_rva && (uint64_t)func_rva < (uint64_t)dir.rva + dir.size) {
            /* An address inside the export directory is a forwarder string. */
            e.forwarder = rd_cstring(r, p->a, rva_offset(p, func_rva, "export forwarder"), 512);
        } else {
            e.address.has = true;
            e.address.v = (big)b->image_base + func_rva;
        }
        *VEC_PUSH(b->arena, b->exports) = e;
    }
}

/* --- COFF symbols (MinGW and some LLVM builds keep them) ---------------------- */

static void parse_coff_symbols(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    if (!p->symtab_off || !p->nsymbols)
        return;
    uint64_t count = p->nsymbols;
    uint64_t room = r->size > p->symtab_off ? (r->size - p->symtab_off) / 18 : 0;
    if (count > room)
        count = room;
    big strings = (big)p->symtab_off + (big)p->nsymbols * 18;
    StrSet section_names = {0};
    for (size_t i = 0; i < p->raw_sections.n; i++)
        strset_add(p->a, &section_names, p->raw_sections.v[i].name);
    uint64_t i = 0;
    while (i < count) {
        big off = (big)p->symtab_off + (big)i * 18;
        const uint8_t *raw_name = rd_bytes(r, off, 8);
        const uint8_t *fields = rd_bytes(r, off + 8, 10);
        uint32_t value = rd_get32(r, fields);
        int section = (int16_t)rd_get16(r, fields + 4);
        unsigned sym_type = rd_get16(r, fields + 6);
        unsigned storage = fields[8], naux = fields[9];
        i += 1 + naux;
        if ((storage != 2 && storage != 3) || section <= 0 ||
            (size_t)section > p->raw_sections.n)
            continue;
        Str name;
        if (memcmp(raw_name, "\0\0\0\0", 4) == 0) {
            if (!rd_cstring_try(r, p->a, strings + rd_get32(r, raw_name + 4), 4096, &name))
                continue;
        } else {
            size_t len = 8;
            while (len && raw_name[len - 1] == 0)
                len--;
            name = utf8_decode(p->a, raw_name, len);
        }
        if (name.n == 0 || (storage == 3 && strset_has(&section_names, name)))
            continue;
        const RawSection *target = &p->raw_sections.v[section - 1];
        Symbol s;
        s.name = name;
        s.address = (big)b->image_base + target->rva + value;
        s.size = 0;
        s.type = str_c((sym_type & 0x30) == 0x20 ? "func" : "notype");
        s.binding = str_c(storage == 2 ? "global" : "local");
        s.section = target->name;
        *VEC_PUSH(b->arena, b->symbols) = s;
    }
}

/* --- function ranges, debug info ---------------------------------------------- */

static int compare_ranges(const void *pa, const void *pb) {
    const Range *a = pa, *b = pb;
    if (a->start != b->start)
        return a->start < b->start ? -1 : 1;
    return (a->end > b->end) - (a->end < b->end);
}

static void parse_exception_table(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    DataDir dir = directory(p, DIR_EXCEPTION);
    if (!dir.rva || !str_eq_c(b->arch, "x86_64"))
        return;
    uint64_t off = rva_offset(p, dir.rva, "exception directory");
    uint64_t count = dir.size / 12;
    if (count > (r->size - off) / 12)
        count = (r->size - off) / 12;
    VEC(Range) ranges = {0};
    for (uint64_t i = 0; i < count; i++) {
        const uint8_t *e = rd_bytes(r, (big)off + (big)i * 12, 12);
        uint32_t begin = rd_get32(r, e), end = rd_get32(r, e + 4);
        if (begin && begin < end) {
            Range range = {(big)b->image_base + begin, (big)b->image_base + end};
            *VEC_PUSH(b->arena, ranges) = range;
        }
    }
    if (ranges.n > 1)
        qsort(ranges.v, ranges.n, sizeof *ranges.v, compare_ranges);
    size_t kept = 0;                    /* sorted(set(ranges)) */
    for (size_t i = 0; i < ranges.n; i++) {
        if (kept && ranges.v[kept - 1].start == ranges.v[i].start &&
            ranges.v[kept - 1].end == ranges.v[i].end)
            continue;
        ranges.v[kept++] = ranges.v[i];
    }
    b->function_ranges.v = ranges.v;
    b->function_ranges.n = kept;
    b->function_ranges.cap = ranges.cap;
}

static void parse_debug(void *arg) {
    PeParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    DataDir dir = directory(p, DIR_DEBUG);
    if (!dir.rva)
        return;
    uint64_t off = rva_offset(p, dir.rva, "debug directory");
    uint32_t count = dir.size / 28;
    if (count > MAX_ENTRIES)
        count = MAX_ENTRIES;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *d = rd_bytes(r, (big)off + (big)i * 28, 28);
        uint32_t kind = rd_get32(r, d + 12), data_size = rd_get32(r, d + 16);
        uint32_t ptr = rd_get32(r, d + 24);
        if (kind != 2 || data_size < 24)        /* 2 = CodeView */
            continue;
        const uint8_t *signature = rd_bytes(r, ptr, 4);
        unsigned path_off = memcmp(signature, "RSDS", 4) == 0 ? 24 :
                            memcmp(signature, "NB10", 4) == 0 ? 16 : 0;
        if (path_off) {
            meta_set_str(b->arena, &b->metadata, "pdb_path",
                         rd_cstring(r, p->a, (big)ptr + path_off, 1024));
            return;
        }
    }
}

/* --- security, import hash, overlay ------------------------------------------- */

static void security(PeParser *p) {
    Binary *b = p->b;
    Arena *a = b->arena;
    unsigned chars = p->dll_chars;
    bool relocatable = !(p->characteristics & FILE_RELOCS_STRIPPED);
    bool aslr = (chars & DLLCHAR_DYNAMIC_BASE) && relocatable;
    DataDir cert = directory(p, DIR_SECURITY);
    meta_set_bool(a, &b->security, "aslr", aslr);
    meta_set_bool(a, &b->security, "high_entropy_va", aslr && (chars & DLLCHAR_HIGH_ENTROPY_VA));
    meta_set_bool(a, &b->security, "nx", (chars & DLLCHAR_NX_COMPAT) != 0);
    meta_set_bool(a, &b->security, "cfg", (chars & DLLCHAR_GUARD_CF) != 0);
    meta_set_bool(a, &b->security, "seh", !(chars & DLLCHAR_NO_SEH));
    meta_set_bool(a, &b->security, "force_integrity", (chars & DLLCHAR_FORCE_INTEGRITY) != 0);
    meta_set_bool(a, &b->security, "signed", cert.rva && cert.size);
    meta_set_bool(a, &b->security, "dotnet", directory(p, DIR_CLR).rva != 0);
}

/* pefile-compatible import hash, used to cluster related malware. */
static void imphash(PeParser *p) {
    Binary *b = p->b;
    Buf parts;
    buf_init(&parts, p->a);
    bool any = false;
    for (size_t i = 0; i < b->imports.n; i++) {
        const Import *imp = &b->imports.v[i];
        if (imp->delayed)
            continue;
        Str library = str_lower_ascii(p->a, imp->library.p ? imp->library : str_c(""));
        size_t dot = library.n;
        while (dot > 0 && library.p[dot - 1] != '.')
            dot--;
        if (dot > 1) {                  /* a non-empty stem before the last dot */
            Str ext = {library.p + dot, library.n - dot};
            if (str_eq_c(ext, "dll") || str_eq_c(ext, "ocx") || str_eq_c(ext, "sys"))
                library.n = dot - 1;
        }
        if (any)
            buf_addch(&parts, ',');
        if (imp->ordinal.has) {
            if (str_eq_c(library, "ws2_32") || str_eq_c(library, "wsock32") ||
                str_eq_c(library, "oleaut32"))
                return;         /* pefile names these ordinals from a table we lack */
            buf_adds(&parts, library);
            buf_printf(&parts, ".ord%" PRIu64, imp->ordinal.v);
        } else {
            buf_adds(&parts, library);
            buf_addch(&parts, '.');
            buf_adds(&parts, str_lower_ascii(p->a, imp->name));
        }
        any = true;
    }
    if (any) {
        char *hex = arena_alloc(p->a, 33);
        md5_hex((const uint8_t *)buf_str(&parts).p, parts.n, hex);
        meta_set_str(b->arena, &b->metadata, "imphash", str_c(hex));
    }
}

static void overlay(PeParser *p) {
    Binary *b = p->b;
    const Reader *r = &p->r;
    big end = p->headers_size;
    Region headers = {"headers", 0, p->headers_size < r->size ? p->headers_size : r->size,
                      "headers"};
    *VEC_PUSH(b->arena, b->regions) = headers;
    for (size_t i = 0; i < b->sections.n; i++) {
        big stop = (big)b->sections.v[i].offset + b->sections.v[i].size;
        if (stop > end)
            end = stop;
    }
    if (p->symtab_off && p->nsymbols) {
        big strings = (big)p->symtab_off + (big)p->nsymbols * 18;
        big table_end = strings;
        const uint8_t *length = rd_try(r, strings, 4);
        if (length != NULL) {
            uint32_t size = rd_get32(r, length);
            table_end = strings + (size > 4 ? size : 4);
        }
        Region region = {"symbol table", p->symtab_off, (uint64_t)(table_end - p->symtab_off),
                         "meta"};
        *VEC_PUSH(b->arena, b->regions) = region;
        if (table_end > end)
            end = table_end;
    }
    DataDir cert = directory(p, DIR_SECURITY);      /* a file offset, not an RVA */
    if (cert.rva && cert.size) {
        Region region = {"certificates", cert.rva, cert.size, "meta"};
        *VEC_PUSH(b->arena, b->regions) = region;
        if ((big)cert.rva + cert.size > end)
            end = (big)cert.rva + cert.size;
    }
    /* Linkers pad the file to the file alignment; zero padding is not data. */
    big align = p->file_align >= 0x200 ? p->file_align : 1;
    big padded = (end + align - 1) / align * align;
    if (padded > (big)r->size)
        padded = r->size;
    bool all_zero = true;
    for (big i = end; i < padded && all_zero; i++)
        all_zero = r->data[(uint64_t)i] == 0;
    if (all_zero)
        end = padded;
    binary_note_overlay(b, end);
}

/* --- driver ------------------------------------------------------------------- */

static void run_step(PeParser *p, const char *label, void (*step)(void *)) {
    if (!err_protect(p->err, step, p))
        binary_warn(p->b, "%s: %s", label, p->err->msg);
}

void pe_parse(Binary *b) {
    PeParser parser;
    memset(&parser, 0, sizeof parser);
    PeParser *p = &parser;
    p->b = b;
    p->a = b->arena;
    p->err = b->err;
    p->r.data = b->data;
    p->r.size = b->size;
    p->r.little_endian = true;
    p->r.err = b->err;
    b->format = "PE";

    parse_headers(p);                   /* the only part allowed to fail hard */
    run_step(p, "section table", parse_sections);
    run_step(p, "import directory", parse_imports);
    run_step(p, "delay-import directory", parse_delay_imports);
    run_step(p, "export directory", parse_exports);
    run_step(p, "COFF symbol table", parse_coff_symbols);
    run_step(p, "exception directory", parse_exception_table);
    run_step(p, "debug directory", parse_debug);
    security(p);
    imphash(p);
    overlay(p);
}
