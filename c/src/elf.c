/* ELF parser (port of binspect/elf.py).
 *
 * Works from the program headers first, because the section header table is
 * optional at run time and is often removed from stripped or tampered
 * binaries; sections only add detail (names, static symbols). Only the ELF
 * header is mandatory: every later step runs under err_protect(), so one
 * corrupt table costs a warning and not the whole analysis. */
#include "model.h"

enum {
    ET_REL = 1, ET_EXEC = 2, ET_DYN = 3, ET_CORE = 4,
    PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4,
    PT_GNU_STACK = 0x6474E551, PT_GNU_RELRO = 0x6474E552,
    SHT_SYMTAB = 2, SHT_DYNAMIC = 6, SHT_NOTE = 7, SHT_NOBITS = 8, SHT_DYNSYM = 11,
    SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXEC = 4,
    SHN_UNDEF = 0, SHN_ABS = 0xFFF1, SHN_COMMON = 0xFFF2,
    DT_NEEDED = 1, DT_PLTRELSZ = 2, DT_HASH = 4, DT_STRTAB = 5, DT_SYMTAB = 6,
    DT_RELA = 7, DT_RELASZ = 8, DT_SYMENT = 11, DT_SONAME = 14, DT_RPATH = 15,
    DT_REL = 17, DT_RELSZ = 18, DT_PLTREL = 20, DT_JMPREL = 23, DT_BIND_NOW = 24,
    DT_RUNPATH = 29, DT_FLAGS = 30, DT_FLAGS_1 = 0x6FFFFFFB,
    DT_VERSYM = 0x6FFFFFF0, DT_VERNEED = 0x6FFFFFFE, DT_VERNEEDNUM = 0x6FFFFFFF,
    DF_BIND_NOW = 0x8, DF_1_NOW = 0x1, DF_1_PIE = 0x08000000,
    STT_SECTION = 3, STT_FILE = 4,
    MAX_CHAIN = 4096            /* upper bound for linked structures in hostile files */
};

typedef struct {
    uint32_t value;
    const char *name;
} Named;

static const Named MACHINES[] = {
    {2, "sparc"}, {3, "x86"}, {8, "mips"}, {20, "ppc"}, {21, "ppc64"}, {22, "s390x"},
    {40, "arm"}, {43, "sparc64"}, {62, "x86_64"}, {183, "aarch64"}, {243, "riscv"},
    {258, "loongarch"},
};

static const Named SEGMENT_TYPES[] = {
    {0, "NULL"}, {1, "LOAD"}, {2, "DYNAMIC"}, {3, "INTERP"}, {4, "NOTE"}, {5, "SHLIB"},
    {6, "PHDR"}, {7, "TLS"}, {0x6474E550, "GNU_EH_FRAME"}, {0x6474E551, "GNU_STACK"},
    {0x6474E552, "GNU_RELRO"}, {0x6474E553, "GNU_PROPERTY"},
};

static const Named SECTION_TYPES[] = {
    {0, "NULL"}, {1, "PROGBITS"}, {2, "SYMTAB"}, {3, "STRTAB"}, {4, "RELA"}, {5, "HASH"},
    {6, "DYNAMIC"}, {7, "NOTE"}, {8, "NOBITS"}, {9, "REL"}, {10, "SHLIB"}, {11, "DYNSYM"},
    {14, "INIT_ARRAY"}, {15, "FINI_ARRAY"}, {16, "PREINIT_ARRAY"}, {17, "GROUP"},
    {18, "SYMTAB_SHNDX"}, {0x6FFFFFF6, "GNU_HASH"}, {0x6FFFFFFD, "VERDEF"},
    {0x6FFFFFFE, "VERNEED"}, {0x6FFFFFFF, "VERSYM"},
};

static const Named SYMBOL_TYPES[] = {
    {0, "notype"}, {1, "object"}, {2, "func"}, {3, "section"}, {4, "file"},
    {5, "common"}, {6, "tls"}, {10, "ifunc"},
};

static const Named SYMBOL_BINDINGS[] = {
    {0, "local"}, {1, "global"}, {2, "weak"}, {10, "unique"},
};

static const char *lookup(const Named *table, size_t count, uint32_t value) {
    for (size_t i = 0; i < count; i++)
        if (table[i].value == value)
            return table[i].name;
    return NULL;
}

#define LOOKUP(table, value) lookup(table, ARRAY_LEN(table), value)

typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, filesz, memsz, align;
} Phdr;

typedef struct {
    uint32_t name_off, type;
    uint64_t flags, addr, offset, size;
    uint32_t link, info;
    uint64_t entsize;
    Str name;
} Shdr;

typedef struct {
    Str name;
    uint64_t value, size;
    uint8_t type, bind, vis;
    uint16_t shndx;
} Sym;

typedef struct {
    int64_t tag;
    uint64_t val;
} Dyn;

typedef struct ElfParser ElfParser;
/* Looks up a symbol name; false after err_set() when it cannot be read. */
typedef bool (*NameFn)(ElfParser *p, uint64_t index, Str *out);

struct ElfParser {
    Binary *b;
    Arena *a;
    Err *err;
    Reader r;
    bool is64;
    unsigned e_type, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
    uint64_t e_phoff, e_shoff;
    VEC(Phdr) phdrs;
    Shdr *shdrs;                    /* NULL until the whole table was read */
    size_t nshdrs;
    VEC(Dyn) dyn;                   /* entries of the dynamic section, in order */
    bool has_dynstr;
    big dynstr_off;                 /* file offset of the dynamic string table */
    const Shdr *symtab_strings;     /* string table of .symtab */
    bool has_symtab;
    size_t *seen;                   /* hash set over b->symbols: index + 1, 0 = empty */
    size_t seen_cap;
    const uint8_t *build_id;        /* latest GNU build-id note */
    uint64_t build_id_size;
};

static const Phdr *segment_of_type(const ElfParser *p, uint32_t type) {
    for (size_t i = 0; i < p->phdrs.n; i++)
        if (p->phdrs.v[i].type == type)
            return &p->phdrs.v[i];
    return NULL;
}

static const Shdr *section_of_type(const ElfParser *p, uint32_t type) {
    for (size_t i = 0; i < p->nshdrs; i++)
        if (p->shdrs[i].type == type)
            return &p->shdrs[i];
    return NULL;
}

/* First value recorded for a dynamic tag (Python: info.get(tag)). */
static bool dyn_get(const ElfParser *p, int64_t tag, uint64_t *value) {
    for (size_t i = 0; i < p->dyn.n; i++) {
        if (p->dyn.v[i].tag == tag) {
            *value = p->dyn.v[i].val;
            return true;
        }
    }
    return false;
}

static uint64_t dyn_value(const ElfParser *p, int64_t tag) {
    uint64_t value = 0;
    dyn_get(p, tag, &value);
    return value;
}

/* File offset of the address stored under a dynamic tag, if it is mapped. */
static bool dyn_offset(const ElfParser *p, int64_t tag, uint64_t *offset) {
    uint64_t vaddr;
    return dyn_get(p, tag, &vaddr) && binary_vaddr_to_offset(p->b, vaddr, offset);
}

/* --- header ------------------------------------------------------------------- */

static void parse_header(ElfParser *p) {
    Binary *b = p->b;
    const uint8_t *d = b->data;
    if (b->size < 16)
        err_throw(p->err, ERR_PARSE, "truncated ELF header");
    unsigned ei_class = d[4], ei_data = d[5];
    if (ei_class != 1 && ei_class != 2)
        err_throw(p->err, ERR_PARSE, "invalid ELF class %u", ei_class);
    if (ei_data != 1 && ei_data != 2)
        err_throw(p->err, ERR_PARSE, "invalid ELF data encoding %u", ei_data);
    p->is64 = ei_class == 2;
    p->r.little_endian = ei_data == 1;
    b->bits = p->is64 ? 64 : 32;
    b->endian = ei_data == 1 ? "little" : "big";

    const Reader *r = &p->r;
    const uint8_t *h = rd_try(r, 16, p->is64 ? 48 : 36);
    if (h == NULL)
        err_throw(p->err, ERR_PARSE, "truncated ELF header");
    p->e_type = rd_get16(r, h);
    unsigned machine = rd_get16(r, h + 2);
    uint64_t entry;
    if (p->is64) {
        entry = rd_get64(r, h + 8);
        p->e_phoff = rd_get64(r, h + 16);
        p->e_shoff = rd_get64(r, h + 24);
        h += 32;
    } else {
        entry = rd_get32(r, h + 8);
        p->e_phoff = rd_get32(r, h + 12);
        p->e_shoff = rd_get32(r, h + 16);
        h += 20;
    }
    /* h -> e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx */
    p->e_phentsize = rd_get16(r, h + 6);
    p->e_phnum = rd_get16(r, h + 8);
    p->e_shentsize = rd_get16(r, h + 10);
    p->e_shnum = rd_get16(r, h + 12);
    p->e_shstrndx = rd_get16(r, h + 14);

    const char *arch = LOOKUP(MACHINES, machine);
    b->arch = arch ? str_c(arch) : str_printf(p->a, "unknown(%u)", machine);
    b->entry.has = entry != 0;
    b->entry.v = entry;
}

/* --- program headers ---------------------------------------------------------- */

static void parse_segments(void *arg) {
    ElfParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    if (!p->e_phoff || !p->e_phnum)
        return;
    unsigned min_size = p->is64 ? 56 : 32;
    if (p->e_phentsize < min_size)
        err_throw(p->err, ERR_PARSE, "program header entry size %u is too small",
                  p->e_phentsize);
    for (unsigned i = 0; i < p->e_phnum; i++) {
        big off = (big)p->e_phoff + (big)i * p->e_phentsize;
        const uint8_t *h = rd_bytes(r, off, min_size);
        Phdr ph;
        ph.type = rd_get32(r, h);
        if (p->is64) {
            ph.flags = rd_get32(r, h + 4);
            ph.offset = rd_get64(r, h + 8);
            ph.vaddr = rd_get64(r, h + 16);
            ph.filesz = rd_get64(r, h + 32);
            ph.memsz = rd_get64(r, h + 40);
            ph.align = rd_get64(r, h + 48);
        } else {
            ph.offset = rd_get32(r, h + 4);
            ph.vaddr = rd_get32(r, h + 8);
            ph.filesz = rd_get32(r, h + 16);
            ph.memsz = rd_get32(r, h + 20);
            ph.flags = rd_get32(r, h + 24);
            ph.align = rd_get32(r, h + 28);
        }
        *VEC_PUSH(p->a, p->phdrs) = ph;

        Segment seg;
        const char *type = LOOKUP(SEGMENT_TYPES, ph.type);
        seg.type = type ? str_c(type) : str_printf(p->a, "0x%" PRIx32, ph.type);
        seg.vaddr = ph.vaddr;
        seg.vsize = ph.memsz;
        seg.offset = ph.offset;
        seg.size = ph.filesz;
        seg.perms[0] = ph.flags & 4 ? 'r' : '-';
        seg.perms[1] = ph.flags & 2 ? 'w' : '-';
        seg.perms[2] = ph.flags & 1 ? 'x' : '-';
        seg.perms[3] = '\0';
        *VEC_PUSH(b->arena, b->segments) = seg;
        if (ph.type == PT_LOAD)
            binary_add_map(b, ph.vaddr, ph.offset, ph.filesz);
    }
    bool any = false;
    uint64_t lowest = 0;
    for (size_t i = 0; i < p->phdrs.n; i++) {
        const Phdr *ph = &p->phdrs.v[i];
        if (ph->type == PT_LOAD && (!any || ph->vaddr < lowest)) {
            lowest = ph->vaddr;
            any = true;
        }
    }
    b->image_base = lowest;
}

/* --- section headers ---------------------------------------------------------- */

static void parse_sections(void *arg) {
    ElfParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    if (!p->e_shoff || !p->e_shnum)
        return;
    unsigned min_size = p->is64 ? 64 : 40;
    if (p->e_shentsize < min_size)
        err_throw(p->err, ERR_PARSE, "section header entry size %u is too small",
                  p->e_shentsize);
    if ((big)p->e_shoff + (big)p->e_shnum * p->e_shentsize > (big)r->size)
        err_throw(p->err, ERR_PARSE, "section header table extends past the end of the "
                                     "file; sections ignored");
    size_t count = p->e_shnum;
    Shdr *raw = arena_array(p->a, count, sizeof *raw);
    for (size_t i = 0; i < count; i++) {
        const uint8_t *h = rd_bytes(r, (big)p->e_shoff + (big)i * p->e_shentsize, min_size);
        Shdr *sh = &raw[i];
        sh->name_off = rd_get32(r, h);
        sh->type = rd_get32(r, h + 4);
        if (p->is64) {
            sh->flags = rd_get64(r, h + 8);
            sh->addr = rd_get64(r, h + 16);
            sh->offset = rd_get64(r, h + 24);
            sh->size = rd_get64(r, h + 32);
            sh->link = rd_get32(r, h + 40);
            sh->info = rd_get32(r, h + 44);
            sh->entsize = rd_get64(r, h + 56);
        } else {
            sh->flags = rd_get32(r, h + 8);
            sh->addr = rd_get32(r, h + 12);
            sh->offset = rd_get32(r, h + 16);
            sh->size = rd_get32(r, h + 20);
            sh->link = rd_get32(r, h + 24);
            sh->info = rd_get32(r, h + 28);
            sh->entsize = rd_get32(r, h + 36);
        }
        sh->name = str_c("");
    }
    if (p->e_shstrndx < count) {
        const Shdr *strtab = &raw[p->e_shstrndx];
        for (size_t i = 0; i < count; i++) {
            Str name;
            if (raw[i].name_off < strtab->size &&
                rd_cstring_try(r, p->a, (big)strtab->offset + raw[i].name_off, 256, &name))
                raw[i].name = name;
        }
    }
    p->shdrs = raw;
    p->nshdrs = count;
    for (size_t i = 1; i < count; i++) {
        const Shdr *sh = &raw[i];
        bool alloc = (sh->flags & SHF_ALLOC) != 0;
        Section s;
        s.name = sh->name;
        s.vaddr = alloc ? sh->addr : 0;
        s.vsize = alloc ? sh->size : 0;
        s.offset = sh->offset;
        big in_file = sh->type == SHT_NOBITS ? 0 : (big)sh->size;
        if (in_file > (big)r->size - (big)sh->offset)
            in_file = (big)r->size - (big)sh->offset;
        s.size = in_file > 0 ? (uint64_t)in_file : 0;
        if (alloc) {
            s.perms[0] = 'r';
            s.perms[1] = sh->flags & SHF_WRITE ? 'w' : '-';
            s.perms[2] = sh->flags & SHF_EXEC ? 'x' : '-';
        } else {
            memcpy(s.perms, "---", 3);
        }
        s.perms[3] = '\0';
        const char *type = LOOKUP(SECTION_TYPES, sh->type);
        s.type = type ? str_c(type) : str_printf(p->a, "0x%" PRIx32, sh->type);
        *VEC_PUSH(b->arena, b->sections) = s;
    }
    if (p->phdrs.n == 0) {
        /* Object files have no program headers; map loadable sections that
         * were given an address so reads by address still work. */
        for (size_t i = 1; i < count; i++) {
            const Shdr *sh = &raw[i];
            if ((sh->flags & SHF_ALLOC) && sh->type != SHT_NOBITS && sh->addr)
                binary_add_map(b, sh->addr, sh->offset, sh->size);
        }
    }
}

static Str section_name(const ElfParser *p, unsigned index) {
    if (index == SHN_ABS)
        return str_c("ABS");
    if (index == SHN_COMMON)
        return str_c("COMMON");
    if (index > 0 && index < p->nshdrs && p->shdrs[index].name.n)
        return p->shdrs[index].name;
    return STR_NONE;
}

/* --- symbols ------------------------------------------------------------------ */

static bool dynstr(ElfParser *p, uint64_t index, Str *out) {
    if (!p->has_dynstr) {
        err_set(p->err, ERR_PARSE, "dynamic string table not found");
        return false;
    }
    return rd_cstring_try(&p->r, p->a, p->dynstr_off + index, 4096, out);
}

static bool symtab_name(ElfParser *p, uint64_t index, Str *out) {
    const Shdr *strtab = p->symtab_strings;
    if (index >= strtab->size) {
        err_set(p->err, ERR_PARSE, "symbol name outside string table");
        return false;
    }
    return rd_cstring_try(&p->r, p->a, (big)strtab->offset + index, 4096, out);
}

static Sym read_symbol(ElfParser *p, big off, NameFn name_of) {
    const Reader *r = &p->r;
    Sym sym;
    uint32_t name;
    unsigned info, other;
    if (p->is64) {
        const uint8_t *s = rd_bytes(r, off, 24);
        name = rd_get32(r, s);
        info = s[4];
        other = s[5];
        sym.shndx = rd_get16(r, s + 6);
        sym.value = rd_get64(r, s + 8);
        sym.size = rd_get64(r, s + 16);
    } else {
        const uint8_t *s = rd_bytes(r, off, 16);
        name = rd_get32(r, s);
        sym.value = rd_get32(r, s + 4);
        sym.size = rd_get32(r, s + 8);
        info = s[12];
        other = s[13];
        sym.shndx = rd_get16(r, s + 14);
    }
    sym.name = str_c("");
    if (name) {
        Str text;
        if (name_of(p, name, &text))
            sym.name = text;
    }
    sym.type = info & 0xF;
    sym.bind = (uint8_t)(info >> 4);
    sym.vis = other & 3;
    return sym;
}

/* ARM/AArch64 "mapping symbols" ($a, $d, $t, $x, optionally ".suffix") mark
 * code/data boundaries; they are not names. Python: ^\$[adtx](\..*)?$ */
static bool is_mapping_symbol(Str name) {
    if (name.n < 2 || name.p[0] != '$')
        return false;
    char kind = name.p[1];
    if (kind != 'a' && kind != 'd' && kind != 't' && kind != 'x')
        return false;
    const char *rest = name.p + 2;
    size_t n = name.n - 2;
    if (n && rest[n - 1] == '\n')
        n--;                                /* "$" also matches before a final newline */
    if (n == 0)
        return true;
    return rest[0] == '.' && memchr(rest, '\n', n) == NULL;
}

static uint64_t symbol_key_hash(Str name, big value) {
    return str_hash(name) ^ ((uint64_t)value * UINT64_C(0x9E3779B97F4A7C15));
}

/* True when (name, address) was already recorded; otherwise remembers that
 * the symbol about to be appended at index b->symbols.n carries the pair. */
static bool symbol_seen(ElfParser *p, Str name, uint64_t value) {
    Binary *b = p->b;
    if ((b->symbols.n + 1) * 2 > p->seen_cap) {
        size_t cap = p->seen_cap ? p->seen_cap * 2 : 256;
        size_t *slots = arena_array(p->a, cap, sizeof *slots);
        for (size_t i = 0; i < b->symbols.n; i++) {
            const Symbol *s = &b->symbols.v[i];
            size_t at = (size_t)symbol_key_hash(s->name, s->address) & (cap - 1);
            while (slots[at])
                at = (at + 1) & (cap - 1);
            slots[at] = i + 1;
        }
        p->seen = slots;
        p->seen_cap = cap;
    }
    size_t mask = p->seen_cap - 1;
    size_t at = (size_t)symbol_key_hash(name, value) & mask;
    while (p->seen[at]) {
        const Symbol *s = &b->symbols.v[p->seen[at] - 1];
        if (s->address == value && str_eq(s->name, name))
            return true;
        at = (at + 1) & mask;
    }
    p->seen[at] = b->symbols.n + 1;
    return false;
}

/* Record a defined, named symbol once (.dynsym and .symtab overlap). */
static void add_symbol(ElfParser *p, const Sym *sym) {
    if (sym->name.n == 0 || sym->shndx == SHN_UNDEF)
        return;
    if (sym->type == STT_SECTION || sym->type == STT_FILE || is_mapping_symbol(sym->name))
        return;
    if (symbol_seen(p, sym->name, sym->value))
        return;
    Symbol s;
    s.name = sym->name;
    s.address = sym->value;
    s.size = sym->size;
    const char *type = LOOKUP(SYMBOL_TYPES, sym->type);
    s.type = type ? str_c(type) : str_printf(p->a, "%u", (unsigned)sym->type);
    const char *binding = LOOKUP(SYMBOL_BINDINGS, sym->bind);
    s.binding = binding ? str_c(binding) : str_printf(p->a, "%u", (unsigned)sym->bind);
    s.section = section_name(p, sym->shndx);
    *VEC_PUSH(p->b->arena, p->b->symbols) = s;
}

/* --- dynamic linking information ---------------------------------------------- */

static Sym *dynamic_symbols(ElfParser *p, const Shdr *dynsym_sec, size_t *count_out) {
    const Reader *r = &p->r;
    uint64_t smallest = p->is64 ? 24 : 16;
    uint64_t entsize = dyn_value(p, DT_SYMENT);
    if (entsize == 0)
        entsize = smallest;
    if (entsize < smallest)
        err_throw(p->err, ERR_PARSE, "dynamic symbol entry size %" PRIu64 " is too small",
                  entsize);
    uint64_t mapped;
    bool has_table = dyn_offset(p, DT_SYMTAB, &mapped);
    big table = has_table ? (big)mapped : 0;
    big count = 0;
    if (dynsym_sec != NULL) {
        if (!has_table) {
            table = dynsym_sec->offset;
            has_table = true;
        }
        count = dynsym_sec->size / entsize;
    } else if (has_table) {
        uint64_t hash_off;
        if (dyn_offset(p, DT_HASH, &hash_off)) {
            count = rd_u32(r, (big)hash_off + 4);       /* nchain == symbol count */
        } else if (p->has_dynstr && p->dynstr_off > table) {
            /* No count is stored without section headers or DT_HASH; the
             * string table conventionally follows the symbol table. */
            count = (p->dynstr_off - table) / entsize;
        }
    }
    *count_out = 0;
    if (!has_table)
        return NULL;
    big room = (big)r->size > table ? ((big)r->size - table) / entsize : 0;
    if (count > room)
        count = room;
    size_t n = (size_t)count;
    Sym *symbols = arena_array(p->a, n, sizeof *symbols);
    for (size_t i = 0; i < n; i++)
        symbols[i] = read_symbol(p, table + (big)i * entsize, dynstr);
    *count_out = n;
    return symbols;
}

typedef struct {
    Str library, version;       /* library.p == NULL: no version recorded */
} Version;

/* Dynamic symbol index -> (library, version) via .gnu.version(_r). */
static Version *symbol_versions(ElfParser *p, size_t nsyms) {
    const Reader *r = &p->r;
    Version *result = arena_array(p->a, nsyms, sizeof *result);
    uint64_t versym, verneed;
    if (!dyn_offset(p, DT_VERSYM, &versym) || !dyn_offset(p, DT_VERNEED, &verneed))
        return result;
    Version *by_index = arena_array(p->a, 0x8000, sizeof *by_index);
    uint64_t entries = dyn_value(p, DT_VERNEEDNUM);
    if (entries > MAX_CHAIN)
        entries = MAX_CHAIN;
    bool ok = true;
    big off = verneed;
    for (uint64_t n = 0; ok && n < entries; n++) {
        const uint8_t *need = rd_try(r, off, 16);
        Str library;
        if (need == NULL || !dynstr(p, rd_get32(r, need + 4), &library)) {
            ok = false;
            break;
        }
        unsigned aux_count = rd_get16(r, need + 2);
        uint32_t next = rd_get32(r, need + 12);
        big aux_off = off + rd_get32(r, need + 8);
        if (aux_count > MAX_CHAIN)
            aux_count = MAX_CHAIN;
        for (unsigned k = 0; k < aux_count; k++) {
            const uint8_t *aux = rd_try(r, aux_off, 16);
            Str version;
            if (aux == NULL || !dynstr(p, rd_get32(r, aux + 8), &version)) {
                ok = false;
                break;
            }
            Version *slot = &by_index[rd_get16(r, aux + 6) & 0x7FFF];
            slot->library = library;
            slot->version = version;
            uint32_t aux_next = rd_get32(r, aux + 12);
            if (!aux_next)
                break;
            aux_off += aux_next;
        }
        if (!ok || !next)
            break;
        off += next;
    }
    if (!ok)
        binary_warn(p->b, "symbol versions: %s", p->err->msg);
    for (size_t i = 0; i < nsyms; i++) {
        const uint8_t *entry = rd_try(r, (big)versym + 2 * (big)i, 2);
        if (entry == NULL)
            break;
        const Version *found = &by_index[rd_get16(r, entry) & 0x7FFF];
        if (found->library.p != NULL)
            result[i] = *found;
    }
    return result;
}

/* Is r_type a relocation that fills an import's GOT slot (GLOB_DAT, JUMP_SLOT)?
 * Architectures without an entry accept every type. */
static bool is_slot_reloc(Str arch, uint64_t r_type) {
    if (str_eq_c(arch, "x86") || str_eq_c(arch, "x86_64"))
        return r_type == 6 || r_type == 7;
    if (str_eq_c(arch, "arm"))
        return r_type == 21 || r_type == 22;
    if (str_eq_c(arch, "aarch64"))
        return r_type == 1025 || r_type == 1026;
    if (str_eq_c(arch, "riscv"))
        return r_type == 5;
    if (str_eq_c(arch, "ppc64"))
        return r_type == 21;
    if (str_eq_c(arch, "ppc"))
        return r_type == 20 || r_type == 21;
    return true;
}

/* Dynamic symbol index -> address of the GOT slot the loader fills. */
static OptAddr *import_slots(ElfParser *p, size_t nsyms) {
    const Reader *r = &p->r;
    OptAddr *slots = arena_array(p->a, nsyms, sizeof *slots);
    struct {
        bool present;
        uint64_t vaddr, size;
        bool has_addend;
    } tables[3];
    /* PLT relocations first: they are the call slots. */
    tables[0].present = dyn_get(p, DT_JMPREL, &tables[0].vaddr);
    tables[0].size = dyn_value(p, DT_PLTRELSZ);
    uint64_t pltrel;
    tables[0].has_addend = dyn_get(p, DT_PLTREL, &pltrel) && pltrel == DT_RELA;
    tables[1].present = dyn_get(p, DT_RELA, &tables[1].vaddr);
    tables[1].size = dyn_value(p, DT_RELASZ);
    tables[1].has_addend = true;
    tables[2].present = dyn_get(p, DT_REL, &tables[2].vaddr);
    tables[2].size = dyn_value(p, DT_RELSZ);
    tables[2].has_addend = false;
    for (size_t t = 0; t < 3; t++) {
        uint64_t off;
        if (!tables[t].present || !binary_vaddr_to_offset(p->b, tables[t].vaddr, &off))
            continue;
        unsigned entsize = p->is64 ? (tables[t].has_addend ? 24 : 16)
                                   : (tables[t].has_addend ? 12 : 8);
        big end = (big)off + tables[t].size - entsize + 1;
        for (big pos = off; pos < end; pos += entsize) {
            const uint8_t *rel = rd_try(r, pos, entsize);
            if (rel == NULL) {
                binary_warn(p->b, "relocations truncated: %s", p->err->msg);
                break;
            }
            uint64_t r_offset, sym, r_type;
            if (p->is64) {
                r_offset = rd_get64(r, rel);
                uint64_t info = rd_get64(r, rel + 8);
                sym = info >> 32;
                r_type = info & 0xFFFFFFFF;
            } else {
                r_offset = rd_get32(r, rel);
                uint32_t info = rd_get32(r, rel + 4);
                sym = info >> 8;
                r_type = info & 0xFF;
            }
            if (sym && sym < nsyms && !slots[sym].has && is_slot_reloc(p->b->arch, r_type)) {
                slots[sym].has = true;
                slots[sym].v = r_offset;
            }
        }
    }
    return slots;
}

static void parse_dynamic(void *arg) {
    ElfParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    uint64_t start, size;
    const Phdr *seg = segment_of_type(p, PT_DYNAMIC);
    if (seg != NULL) {
        start = seg->offset;
        size = seg->filesz;
    } else {
        const Shdr *sec = section_of_type(p, SHT_DYNAMIC);
        if (sec == NULL)
            return;
        start = sec->offset;
        size = sec->size;
    }
    unsigned entsize = p->is64 ? 16 : 8;
    big end = (big)start + size - entsize + 1;
    for (big off = start; off < end; off += entsize) {
        const uint8_t *entry = rd_try(r, off, entsize);
        if (entry == NULL) {
            binary_warn(b, "dynamic section truncated: %s", p->err->msg);
            break;
        }
        Dyn d;
        if (p->is64) {
            d.tag = (int64_t)rd_get64(r, entry);
            d.val = rd_get64(r, entry + 8);
        } else {
            d.tag = (int32_t)rd_get32(r, entry);
            d.val = rd_get32(r, entry + 4);
        }
        if (d.tag == 0)
            break;
        *VEC_PUSH(p->a, p->dyn) = d;
    }

    const Shdr *dynsym_sec = section_of_type(p, SHT_DYNSYM);
    uint64_t mapped;
    if (dyn_offset(p, DT_STRTAB, &mapped)) {
        p->has_dynstr = true;
        p->dynstr_off = mapped;
    } else if (dynsym_sec != NULL && dynsym_sec->link < p->nshdrs) {
        p->has_dynstr = true;
        p->dynstr_off = p->shdrs[dynsym_sec->link].offset;
    }

    for (size_t i = 0; i < p->dyn.n; i++) {
        int64_t tag = p->dyn.v[i].tag;
        const char *key = tag == DT_SONAME ? "soname" : tag == DT_RPATH ? "rpath" :
                          tag == DT_RUNPATH ? "runpath" : NULL;
        if (tag != DT_NEEDED && key == NULL)
            continue;
        Str text;
        if (!dynstr(p, p->dyn.v[i].val, &text)) {
            binary_warn(b, "dynamic string: %s", p->err->msg);
            continue;
        }
        if (tag == DT_NEEDED)
            *VEC_PUSH(b->arena, b->libraries) = text;
        else
            meta_set_str(b->arena, &b->metadata, key, text);
    }

    size_t nsyms;
    const Sym *symbols = dynamic_symbols(p, dynsym_sec, &nsyms);
    const Version *versions = symbol_versions(p, nsyms);
    const OptAddr *slots = import_slots(p, nsyms);

    for (size_t index = 1; index < nsyms; index++) {
        const Sym *sym = &symbols[index];
        if (sym->name.n == 0)
            continue;
        if (sym->shndx == SHN_UNDEF) {
            Import imp;
            memset(&imp, 0, sizeof imp);
            imp.name = sym->name;
            imp.library = versions[index].library;
            imp.version = versions[index].version;
            imp.address = slots[index];
            *VEC_PUSH(b->arena, b->imports) = imp;
        } else {
            bool exported = (sym->bind == 1 || sym->bind == 2 || sym->bind == 10) &&
                            (sym->vis == 0 || sym->vis == 3) &&
                            (sym->type == 0 || sym->type == 1 || sym->type == 2 ||
                             sym->type == 6 || sym->type == 10);
            if (exported) {
                Export e;
                memset(&e, 0, sizeof e);
                e.name = sym->name;
                e.address.has = true;
                e.address.v = sym->value;
                *VEC_PUSH(b->arena, b->exports) = e;
            }
            add_symbol(p, sym);
        }
    }
}

/* --- static symbols ----------------------------------------------------------- */

static void parse_static_symbols(void *arg) {
    ElfParser *p = arg;
    Binary *b = p->b;
    const Shdr *symtab = section_of_type(p, SHT_SYMTAB);
    if (symtab == NULL)
        return;
    p->has_symtab = true;
    if (symtab->link >= p->nshdrs)
        err_throw(p->err, ERR_PARSE, "symbol table has no string table");
    p->symtab_strings = &p->shdrs[symtab->link];
    uint64_t smallest = p->is64 ? 24 : 16;
    uint64_t entsize = symtab->entsize ? symtab->entsize : smallest;
    if (entsize < smallest)
        err_throw(p->err, ERR_PARSE, "symbol entry size %" PRIu64 " is too small", entsize);
    VEC(Str) files = {0};
    StrSet known = {0};
    uint64_t count = symtab->size / entsize;
    for (uint64_t i = 1; i < count; i++) {
        Sym sym = read_symbol(p, (big)symtab->offset + (big)i * entsize, symtab_name);
        if (sym.type == STT_FILE && sym.name.n && strset_add(p->a, &known, sym.name))
            *VEC_PUSH(p->a, files) = sym.name;
        add_symbol(p, &sym);
    }
    if (files.n) {
        Meta *m = meta_slot(b->arena, &b->metadata, "source_files");
        m->kind = META_LIST;
        m->items = files.v;
        m->count = files.n;
    }
}

/* --- metadata ----------------------------------------------------------------- */

static bool parse_notes(ElfParser *p, uint64_t offset, uint64_t size, unsigned align) {
    const Reader *r = &p->r;
    big pos = offset, end = (big)offset + size;
    big mask = ~(big)(align - 1);
    while (pos + 12 <= end) {
        const uint8_t *h = rd_try(r, pos, 12);
        if (h == NULL)
            return false;
        uint32_t namesz = rd_get32(r, h), descsz = rd_get32(r, h + 4);
        uint32_t type = rd_get32(r, h + 8);
        const uint8_t *name = rd_try(r, pos + 12, namesz);
        if (name == NULL)
            return false;
        size_t name_len = namesz;
        while (name_len && name[name_len - 1] == 0)
            name_len--;
        big desc_off = pos + 12 + (((big)namesz + align - 1) & mask);
        const uint8_t *desc = rd_try(r, desc_off, descsz);
        if (desc == NULL)
            return false;
        if (name_len == 3 && memcmp(name, "GNU", 3) == 0 && type == 3) {
            p->build_id = desc;
            p->build_id_size = descsz;
        }
        pos = desc_off + (((big)descsz + align - 1) & mask);
    }
    return true;
}

static void note_range(ElfParser *p, uint64_t offset, uint64_t size, uint64_t align) {
    if (!parse_notes(p, offset, size, align == 8 ? 8 : 4))
        binary_warn(p->b, "notes: %s", p->err->msg);
}

static void parse_metadata(void *arg) {
    ElfParser *p = arg;
    Binary *b = p->b;
    const Reader *r = &p->r;
    const Phdr *interp = segment_of_type(p, PT_INTERP);
    if (interp != NULL) {
        Str text;
        if (rd_cstring_try(r, p->a, interp->offset, interp->filesz ? interp->filesz : 1, &text))
            meta_set_str(b->arena, &b->metadata, "interpreter", text);
        else
            binary_warn(b, "interpreter: %s", p->err->msg);
    }
    if (segment_of_type(p, PT_NOTE) != NULL) {
        for (size_t i = 0; i < p->phdrs.n; i++) {
            const Phdr *ph = &p->phdrs.v[i];
            if (ph->type == PT_NOTE)
                note_range(p, ph->offset, ph->filesz, ph->align);
        }
    } else {
        for (size_t i = 0; i < p->nshdrs; i++)
            if (p->shdrs[i].type == SHT_NOTE)
                note_range(p, p->shdrs[i].offset, p->shdrs[i].size, 4);
    }
    if (p->build_id != NULL) {
        static const char digits[] = "0123456789abcdef";
        if (p->build_id_size > SIZE_MAX / 4)
            die_out_of_memory();
        size_t n = (size_t)p->build_id_size;
        char *hex = arena_alloc(p->a, 2 * n + 1);
        for (size_t i = 0; i < n; i++) {
            hex[2 * i] = digits[p->build_id[i] >> 4];
            hex[2 * i + 1] = digits[p->build_id[i] & 15];
        }
        Str text = {hex, 2 * n};
        meta_set_str(b->arena, &b->metadata, "build_id", text);
    }

    const Shdr *comment = NULL;
    for (size_t i = 0; i < p->nshdrs && comment == NULL; i++)
        if (str_eq_c(p->shdrs[i].name, ".comment"))
            comment = &p->shdrs[i];
    if (comment != NULL && comment->type != SHT_NOBITS) {
        size_t length = comment->size < 65536 ? (size_t)comment->size : 65536;
        const uint8_t *raw = rd_bytes(r, comment->offset, length);
        VEC(Str) found = {0};
        size_t start = 0;
        for (size_t i = 0; i <= length; i++) {
            if (i < length && raw[i] != 0)
                continue;
            Str text = str_strip(utf8_decode(p->a, raw + start, i - start));
            start = i + 1;
            if (text.n == 0)
                continue;
            bool known = false;
            for (size_t k = 0; k < found.n && !known; k++)
                known = str_eq(found.v[k], text);
            if (!known)
                *VEC_PUSH(p->a, found) = str_copy(p->a, text.p, text.n);
        }
        if (found.n) {
            Meta *m = meta_slot(b->arena, &b->metadata, "compiler");
            m->kind = META_LIST;
            m->items = found.v;
            m->count = found.n;
        }
    }
}

/* --- classification, security, overlay ---------------------------------------- */

static void classify(ElfParser *p) {
    uint64_t flags1 = dyn_value(p, DT_FLAGS_1);
    bool has_interp = segment_of_type(p, PT_INTERP) != NULL;
    switch (p->e_type) {
    case ET_EXEC:
        p->b->kind = "executable";
        break;
    case ET_DYN:
        p->b->kind = (has_interp || (flags1 & DF_1_PIE)) ? "executable" : "shared library";
        break;
    case ET_REL:
        p->b->kind = "relocatable";
        break;
    case ET_CORE:
        p->b->kind = "core";
        break;
    default:
        break;
    }
}

static void name_flags(Str name, bool *canary, bool *fortify) {
    if (str_eq_c(name, "__stack_chk_fail") || str_eq_c(name, "__stack_chk_guard") ||
        str_eq_c(name, "__stack_chk_fail_local"))
        *canary = true;
    if (str_ends_with(name, "_chk"))
        *fortify = true;
}

static void security(ElfParser *p) {
    Binary *b = p->b;
    Arena *a = b->arena;
    const Phdr *stack = segment_of_type(p, PT_GNU_STACK);
    bool relro = segment_of_type(p, PT_GNU_RELRO) != NULL;
    uint64_t ignored;
    bool bind_now = dyn_get(p, DT_BIND_NOW, &ignored) ||
                    (dyn_value(p, DT_FLAGS) & DF_BIND_NOW) ||
                    (dyn_value(p, DT_FLAGS_1) & DF_1_NOW);
    bool canary = false, fortify = false;
    for (size_t i = 0; i < b->imports.n; i++)
        name_flags(b->imports.v[i].name, &canary, &fortify);
    for (size_t i = 0; i < b->symbols.n; i++)
        name_flags(b->symbols.v[i].name, &canary, &fortify);

    meta_set_bool(a, &b->security, "nx", stack != NULL && !(stack->flags & 1));
    if (p->e_type == ET_DYN) {
        if (strcmp(b->kind, "executable") == 0)
            meta_set_bool(a, &b->security, "pie", true);
        else
            meta_slot(a, &b->security, "pie")->kind = META_NONE;
    } else {
        meta_set_bool(a, &b->security, "pie", false);
    }
    meta_set_str(a, &b->security, "relro",
                 str_c(relro ? (bind_now ? "full" : "partial") : "none"));
    meta_set_bool(a, &b->security, "canary", canary);
    meta_set_bool(a, &b->security, "fortify", fortify);
    meta_set_bool(a, &b->security, "stripped", !p->has_symtab);
    const Meta *rpath = meta_get(&b->metadata, "rpath");
    meta_set_str(a, &b->security, "rpath", rpath ? rpath->text : STR_NONE);
    const Meta *runpath = meta_get(&b->metadata, "runpath");
    meta_set_str(a, &b->security, "runpath", runpath ? runpath->text : STR_NONE);
}

static uint64_t saturate(big value) {
    if (value < 0)
        return 0;
    return value > (big)UINT64_MAX ? UINT64_MAX : (uint64_t)value;
}

static void overlay(ElfParser *p) {
    Binary *b = p->b;
    big end = p->phdrs.n ? (big)p->e_phoff + (big)p->e_phnum * p->e_phentsize : 0;
    big header = p->is64 ? 64 : 52;
    Region headers = {"headers", 0, saturate(end > header ? end : header), "headers"};
    *VEC_PUSH(b->arena, b->regions) = headers;
    if (p->nshdrs) {
        big table = (big)p->e_shnum * p->e_shentsize;
        Region region = {"section headers", p->e_shoff, saturate(table), "meta"};
        *VEC_PUSH(b->arena, b->regions) = region;
        if ((big)p->e_shoff + table > end)
            end = (big)p->e_shoff + table;
    }
    for (size_t i = 0; i < p->phdrs.n; i++) {
        big stop = (big)p->phdrs.v[i].offset + p->phdrs.v[i].filesz;
        if (stop > end)
            end = stop;
    }
    for (size_t i = 0; i < p->nshdrs; i++) {
        if (p->shdrs[i].type == SHT_NOBITS)
            continue;
        big stop = (big)p->shdrs[i].offset + p->shdrs[i].size;
        if (stop > end)
            end = stop;
    }
    binary_note_overlay(b, end);
}

/* --- driver ------------------------------------------------------------------- */

static void run_step(ElfParser *p, const char *label, void (*step)(void *)) {
    if (!err_protect(p->err, step, p))
        binary_warn(p->b, "%s: %s", label, p->err->msg);
}

void elf_parse(Binary *b) {
    ElfParser parser;
    memset(&parser, 0, sizeof parser);
    ElfParser *p = &parser;
    p->b = b;
    p->a = b->arena;
    p->err = b->err;
    p->r.data = b->data;
    p->r.size = b->size;
    p->r.little_endian = true;
    p->r.err = b->err;
    b->format = "ELF";

    parse_header(p);                    /* the only part allowed to fail hard */
    run_step(p, "program headers", parse_segments);
    run_step(p, "section headers", parse_sections);
    run_step(p, "dynamic section", parse_dynamic);
    run_step(p, "symbol table", parse_static_symbols);
    run_step(p, "notes", parse_metadata);
    classify(p);
    security(p);
    overlay(p);
}
