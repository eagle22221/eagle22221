/* Whole-program analysis built on one linear sweep of the code: function
 * discovery, name resolution and cross-references (port of analysis.py),
 * plus the views of it (functions, disassembly, xrefs from views.py). */
#include "analysis.h"

#include "disasm.h"
#include "strings.h"

typedef struct {
    big address;
    InsnKind kind;
    big refs[2];
    unsigned nrefs;
    Str text;                   /* the referencing instruction */
} IndexEntry;

typedef struct {
    big start;
    const Import *import;
} Thunk;

struct Analysis {
    Arena *a;
    const Binary *b;
    Disassembler *dis;
    bool swept;
    bool keep_index;            /* xrefs wanted: remember who mentions what */
    Function *functions;        /* sorted by address */
    size_t nfunctions;
    AddrMap by_address;         /* function start -> index */
    VEC(IndexEntry) index;      /* every instruction that mentions an address */
    VEC(Thunk) thunks;          /* jump stubs found by the sweep, in address order */
    AddrMap thunk_at;           /* stub start -> index into thunks */
};

Analysis *analysis_new(Arena *a, const Binary *b) {
    Analysis *an = arena_alloc(a, sizeof *an);
    an->a = a;
    an->b = b;
    an->dis = dis_new(a, b);
    return an;
}

/* --- sweep -------------------------------------------------------------------- */

static bool one_of(const char *text, const char *const *names, size_t count) {
    for (size_t i = 0; i < count; i++)
        if (strcmp(text, names[i]) == 0)
            return true;
    return false;
}

typedef struct {
    AddrMap calls;              /* targets of direct calls (a set) */
    VEC(big) call_list;
    bool has_main;
    big main;
} SweepResult;

/* One pass over every instruction in every executable range, in address
 * order. Linear sweep: fast and complete for compiler output; data embedded
 * in code may decode as junk instructions. */
static void sweep(Analysis *an, SweepResult *out) {
    static const char *const fillers[] = {"int3", "nop", ".byte", "endbr64", "endbr32", "hlt"};
    const Binary *b = an->b;
    Disassembler *dis = an->dis;
    Arena *a = an->a;
    CodeRanges code = {0};
    binary_executable_ranges(b, a, &code);

    AddrMap start_slots = {0};          /* slots of __libc_start_main */
    for (size_t i = 0; i < b->imports.n; i++) {
        const Import *imp = &b->imports.v[i];
        if (imp->address.has && str_eq_c(imp->name, "__libc_start_main"))
            addrmap_put(a, &start_slots, imp->address.v, 1, true);
    }
    bool find_main = start_slots.count != 0 && str_eq_c(b->arch, "x86_64");
    bool has_last_arg = false;          /* most recent "lea rdi, [rip+x]" (1st C argument) */
    big last_arg = 0;
    bool has_prev = false;
    InsnKind prev_kind = KIND_NONE;
    char prev_mnemonic[sizeof ((Insn *)0)->mnemonic] = "";
    big prev_address = 0;
    uint64_t ignored;

    for (size_t r = 0; r < code.n; r++) {
        uint64_t size;
        const uint8_t *bytes = binary_read(b, code.v[r].start, code.v[r].size, &size);
        Decoder dec;
        Insn insn;
        dis_decode(dis, &dec, bytes, size, code.v[r].start);
        while (dis_next(&dec, &insn)) {
            if (insn.nrefs) {
                if (an->keep_index) {
                    IndexEntry entry;
                    entry.address = insn.address;
                    entry.kind = insn.kind;
                    entry.nrefs = insn.nrefs;
                    memcpy(entry.refs, insn.refs, sizeof entry.refs);
                    entry.text = insn_text(a, &insn);
                    *VEC_PUSH(a, an->index) = entry;
                }

                if (insn.kind == KIND_CALL && insn.has_target && dis_in_code(dis, insn.target) &&
                    addrmap_put(a, &out->calls, insn.target, 1, false))
                    *VEC_PUSH(a, out->call_list) = insn.target;

                const Import *slot = insn.kind == KIND_JUMP && !insn.has_target
                                         ? dis_slot(dis, insn.refs[0]) : NULL;
                if (slot != NULL) {
                    /* "jmp [import slot]" at a function boundary is a PLT entry
                     * or import thunk; inside a function it is a tail call. */
                    big start = insn.address;
                    bool boundary = !has_prev || prev_kind == KIND_RET ||
                                    prev_kind == KIND_JUMP ||
                                    one_of(prev_mnemonic, fillers, ARRAY_LEN(fillers));
                    if (has_prev && (strcmp(prev_mnemonic, "endbr64") == 0 ||
                                     strcmp(prev_mnemonic, "endbr32") == 0))
                        start = prev_address;
                    if (boundary) {
                        uint64_t at;
                        if (addrmap_get(&an->thunk_at, start, &at)) {
                            an->thunks.v[at].import = slot;
                        } else {
                            addrmap_put(a, &an->thunk_at, start, an->thunks.n, true);
                            Thunk thunk = {start, slot};
                            *VEC_PUSH(a, an->thunks) = thunk;
                        }
                    }
                }

                if (find_main && !out->has_main) {
                    bool sets_first_argument =
                        (strcmp(insn.mnemonic, "lea") == 0 || strcmp(insn.mnemonic, "mov") == 0) &&
                        (strncmp(insn.operands, "rdi, ", 5) == 0 ||
                         strncmp(insn.operands, "edi, ", 5) == 0);
                    if (sets_first_argument) {
                        last_arg = insn.refs[0];
                        has_last_arg = true;
                    } else if (insn.kind == KIND_CALL && has_last_arg) {
                        bool starts_libc = addrmap_get(&start_slots, insn.refs[0], &ignored);
                        if (!starts_libc && insn.has_target) {
                            const Import *imp = dis_thunk_import(dis, insn.target);
                            starts_libc = imp != NULL && str_eq_c(imp->name, "__libc_start_main");
                        }
                        if (starts_libc) {
                            out->main = last_arg;
                            out->has_main = true;
                        }
                    }
                }
            }
            has_prev = true;
            prev_kind = insn.kind;
            prev_address = insn.address;
            memcpy(prev_mnemonic, insn.mnemonic, sizeof prev_mnemonic);
        }
    }
}

/* --- functions ---------------------------------------------------------------- */

typedef struct {
    big address;
    bool has_name;
    Str name;
    big size;
    const char *source;
} Found;

typedef struct {
    Analysis *an;
    AddrMap index;              /* address -> position in items */
    VEC(Found) items;
} FoundSet;

/* found.setdefault(address, [name, size, source]) for addresses in code. */
static void found_add(FoundSet *set, big address, bool has_name, Str name, big size,
                      const char *source) {
    Analysis *an = set->an;
    if (!dis_in_code(an->dis, address))
        return;
    if (!addrmap_put(an->a, &set->index, address, set->items.n, false))
        return;
    Found f = {address, has_name, name, size, source};
    *VEC_PUSH(an->a, set->items) = f;
}

static int compare_found(const void *pa, const void *pb) {
    const Found *x = pa, *y = pb;
    return (x->address > y->address) - (x->address < y->address);
}

static int compare_addresses(const void *pa, const void *pb) {
    big x = *(const big *)pa, y = *(const big *)pb;
    return (x > y) - (x < y);
}

static void find_functions(Analysis *an) {
    const Binary *b = an->b;
    Disassembler *dis = an->dis;
    Arena *a = an->a;
    SweepResult swept;
    memset(&swept, 0, sizeof swept);
    sweep(an, &swept);

    FoundSet set;
    memset(&set, 0, sizeof set);
    set.an = an;
    for (size_t i = 0; i < b->symbols.n; i++) {
        const Symbol *s = &b->symbols.v[i];
        if (str_eq_c(s->type, "func"))
            found_add(&set, s->address, s->name.n != 0, s->name, s->size, "symbol");
    }
    for (size_t i = 0; i < b->exports.n; i++) {
        const Export *e = &b->exports.v[i];
        if (e->address.has)
            found_add(&set, e->address.v, e->name.n != 0, e->name, 0, "export");
    }
    for (size_t i = 0; i < b->function_ranges.n; i++) {
        const Range *range = &b->function_ranges.v[i];
        found_add(&set, range->start, false, STR_NONE, range->end - range->start, "pdata");
        uint64_t at;
        if (addrmap_get(&set.index, range->start, &at) && !set.items.v[at].size)
            set.items.v[at].size = range->end - range->start;   /* exact size for a named function */
    }
    if (swept.has_main)
        found_add(&set, swept.main, true, str_c("main"), 0, "libc_start_main");
    if (b->entry.has)
        found_add(&set, b->entry.v, true, str_c("entry"), 0, "entry");
    if (swept.call_list.n > 1)
        qsort(swept.call_list.v, swept.call_list.n, sizeof *swept.call_list.v, compare_addresses);
    for (size_t i = 0; i < swept.call_list.n; i++)
        found_add(&set, swept.call_list.v[i], false, STR_NONE, 0, "call");

    size_t n = set.items.n;
    if (n > 1)
        qsort(set.items.v, n, sizeof *set.items.v, compare_found);
    CodeRanges ranges = {0};
    binary_executable_ranges(b, a, &ranges);
    Function *functions = arena_array(a, n, sizeof *functions);
    for (size_t i = 0; i < n; i++) {
        const Found *f = &set.items.v[i];
        Function *fn = &functions[i];
        fn->address = f->address;
        fn->source = f->source;
        fn->name = f->name;
        if (!f->has_name) {
            Str thunk = dis_thunk_at(dis, f->address);
            if (thunk.n) {
                fn->name = thunk;
            } else {
                char text[40];
                fn->name = str_printf(a, "sub_%s", hex_big(text, f->address) + 2);
            }
        }
        fn->size = f->size;
        if (!fn->size) {
            big limit = 0;
            for (size_t r = 0; r < ranges.n; r++) {
                if (f->address >= ranges.v[r].start &&
                    f->address - ranges.v[r].start < (big)ranges.v[r].size) {
                    limit = ranges.v[r].start + ranges.v[r].size;
                    break;
                }
            }
            if (i + 1 < n && set.items.v[i + 1].address < limit)
                limit = set.items.v[i + 1].address;
            fn->size = limit - f->address;
        }
        addrmap_put(a, &an->by_address, fn->address, i, true);
    }
    an->functions = functions;
    an->nfunctions = n;
    dis_add_names(dis, functions, n);
}

static void ensure_functions(Analysis *an) {
    if (!an->swept) {
        an->swept = true;
        find_functions(an);
    }
}

/* The function whose body contains address. */
static const Function *function_at(Analysis *an, big address) {
    ensure_functions(an);
    size_t lo = 0, hi = an->nfunctions;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (an->functions[mid].address <= address)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo > 0 && address < an->functions[lo - 1].address + an->functions[lo - 1].size)
        return &an->functions[lo - 1];
    return NULL;
}

/* "function+0x12" for code, else whatever name the address has. */
static Str label(Analysis *an, big address) {
    const Function *f = function_at(an, address);
    if (f == NULL)
        return dis_name_at(an->dis, address);
    if (address == f->address)
        return f->name;
    char offset[40];
    Buf out;
    buf_init(&out, an->a);
    buf_adds(&out, f->name);
    buf_addch(&out, '+');
    buf_addc(&out, hex_big(offset, address - f->address));
    return buf_str(&out);
}

/* --- name resolution ---------------------------------------------------------- */

typedef VEC(big) BigList;

static void add_unique(Arena *a, AddrMap *seen, BigList *list, big address) {
    if (addrmap_put(a, seen, address, 1, false))
        *VEC_PUSH(a, *list) = address;
}

static bool equal_ignoring_ascii_case(Str x, Str y) {
    if (x.n != y.n)
        return false;
    for (size_t i = 0; i < x.n; i++) {
        char p = x.p[i], q = y.p[i];
        if (p >= 'A' && p <= 'Z')
            p = (char)(p + 32);
        if (q >= 'A' && q <= 'Z')
            q = (char)(q + 32);
        if (p != q)
            return false;
    }
    return true;
}

static void resolve(Analysis *an, const char *given, BigList *out) {
    const Binary *b = an->b;
    Arena *a = an->a;
    Str text = str_strip(str_c(given));
    text = str_copy(a, text.p, text.n);
    out->n = 0;
    big number;
    if (parse_int(text.p, true, &number)) {
        *VEC_PUSH(a, *out) = number;
        return;
    }
    AddrMap seen = {0};
    for (size_t i = 0; i < b->symbols.n; i++)
        if (str_eq(b->symbols.v[i].name, text))
            add_unique(a, &seen, out, b->symbols.v[i].address);
    for (size_t i = 0; i < b->exports.n; i++)
        if (b->exports.v[i].address.has && str_eq(b->exports.v[i].name, text))
            add_unique(a, &seen, out, b->exports.v[i].address.v);
    ensure_functions(an);
    for (size_t i = 0; i < an->nfunctions; i++)
        if (str_eq(an->functions[i].name, text))
            add_unique(a, &seen, out, an->functions[i].address);
    if (out->n == 0 && str_eq_c(text, "entry") && b->entry.has)
        add_unique(a, &seen, out, b->entry.v);
    /* An import, optionally "library!name": its slot and its stubs. */
    size_t bang = text.n;
    while (bang > 0 && text.p[bang - 1] != '!')
        bang--;
    Str library = {text.p, bang ? bang - 1 : 0};
    Str name = {text.p + bang, text.n - bang};
    for (size_t i = 0; i < b->imports.n; i++) {
        const Import *imp = &b->imports.v[i];
        if (!str_eq(imp->name, name))
            continue;
        if (library.n && !equal_ignoring_ascii_case(imp->library.p ? imp->library : str_c(""),
                                                    library))
            continue;
        if (imp->address.has)
            add_unique(a, &seen, out, imp->address.v);
        for (size_t t = 0; t < an->thunks.n; t++)
            if (an->thunks.v[t].import == imp)
                add_unique(a, &seen, out, an->thunks.v[t].start);
    }
    if (out->n == 0)
        err_throw(b->err, ERR_LOCATION,
                  "cannot resolve %s: not an address, symbol, function or import name",
                  py_repr(a, text.p).p);
    if (out->n > 1)
        qsort(out->v, out->n, sizeof *out->v, compare_addresses);
}

void analysis_resolve(Analysis *an, const char *text, AddressList *out) {
    BigList found = {0};
    resolve(an, text, &found);
    out->v = found.v;
    out->n = found.n;
    out->cap = found.cap;
}

/* --- views -------------------------------------------------------------------- */

JVal *view_functions(Arena *a, Analysis *an, const char *grep) {
    ensure_functions(an);
    Str needle = str_c(grep ? grep : "");
    JVal *rows = j_list(a);
    for (size_t i = 0; i < an->nfunctions; i++) {
        const Function *f = &an->functions[i];
        if (!str_contains(f->name, needle))
            continue;
        JVal *row = j_dict(a);
        j_set(a, row, "address", j_hex(a, f->address));
        j_set(a, row, "size", j_int(a, f->size));
        j_set(a, row, "name", j_str(a, f->name));
        j_set(a, row, "source", j_cstr(a, f->source));
        j_push(a, rows, row);
    }
    return rows;
}

static Str hex_string(Arena *a, const uint8_t *bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    char *text = arena_array(a, size + 1, 2);
    for (size_t i = 0; i < size; i++) {
        text[2 * i] = digits[bytes[i] >> 4];
        text[2 * i + 1] = digits[bytes[i] & 15];
    }
    Str s = {text, 2 * size};
    return s;
}

JVal *view_disassembly(Arena *a, Analysis *an, const char *location, const big *count) {
    const Binary *b = an->b;
    Disassembler *dis = an->dis;
    char text[40];
    ensure_functions(an);                   /* also registers names */
    big address;
    if (location == NULL) {
        CodeRanges ranges = {0};
        binary_executable_ranges(b, a, &ranges);
        if (b->entry.has)
            address = b->entry.v;
        else if (ranges.n)
            address = ranges.v[0].start;
        else
            err_throw(b->err, ERR_LOCATION, "this file has no entry point or code section; "
                                            "give a location");
    } else {
        BigList found = {0};
        resolve(an, location, &found);
        address = found.v[0];
        for (size_t i = 0; i < found.n; i++) {
            if (dis_in_code(dis, found.v[i])) {
                address = found.v[i];
                break;
            }
        }
    }
    uint64_t at;
    const Function *function = addrmap_get(&an->by_address, address, &at) ? &an->functions[at]
                                                                          : NULL;
    /* A whole function when the location is a function start and no count
     * is given; otherwise `count` instructions (default 32). */
    bool whole = count == NULL && function != NULL;
    big limit = whole ? 0 : (count != NULL && *count != 0 ? *count : 32);
    big length = whole ? function->size : limit * 16;
    uint64_t ignored;
    if (!binary_vaddr_to_offset(b, address, &ignored))
        err_throw(b->err, ERR_LOCATION, "address %s is not inside the file",
                  hex_big(text, address));
    uint64_t size;
    const uint8_t *code = binary_read(b, address, length > 0 ? length : 0, &size);

    JVal *instructions = j_list(a);
    Decoder dec;
    Insn insn;
    dis_decode(dis, &dec, code, size, address);
    for (big done = 0; (whole || done < limit) && dis_next(&dec, &insn); done++) {
        dis_annotate(dis, &insn);
        JVal *refs = j_list(a);
        for (unsigned i = 0; i < insn.nrefs; i++)
            j_push(a, refs, j_hex(a, insn.refs[i]));
        JVal *row = j_dict(a);
        j_set(a, row, "address", j_hex(a, insn.address));
        j_set(a, row, "bytes", j_str(a, hex_string(a, insn.raw, insn.raw_size)));
        j_set(a, row, "mnemonic", j_str(a, str_copy(a, insn.mnemonic, strlen(insn.mnemonic))));
        j_set(a, row, "operands", j_str(a, str_copy(a, insn.operands, strlen(insn.operands))));
        j_set(a, row, "kind", j_cstr(a, insn_kind_name(insn.kind)));
        j_set(a, row, "target", j_opt_hex(a, insn.has_target, insn.target));
        j_set(a, row, "refs", refs);
        j_set(a, row, "comment", j_str(a, insn.comment));
        j_set(a, row, "label", addrmap_get(&an->by_address, insn.address, &at)
                                   ? j_str(a, an->functions[at].name) : j_null(a));
        j_push(a, instructions, row);
    }

    JVal *d = j_dict(a);
    j_set(a, d, "address", j_hex(a, address));
    j_set(a, d, "name", j_str(a, label(an, address)));
    if (function == NULL) {
        j_set(a, d, "function", j_null(a));
    } else {
        JVal *f = j_dict(a);
        j_set(a, f, "address", j_hex(a, function->address));
        j_set(a, f, "size", j_int(a, function->size));
        j_set(a, f, "name", j_str(a, function->name));
        j_set(a, d, "function", f);
    }
    j_set(a, d, "instructions", instructions);
    return d;
}

JVal *view_xrefs(Arena *a, Analysis *an, const char *target, const char *string) {
    const Binary *b = an->b;
    BigList addresses = {0};
    an->keep_index = true;                  /* before anything triggers the sweep */
    if (string != NULL && string[0] != '\0') {
        /* Addresses of strings containing the text. */
        StringScan scan;
        FoundString found;
        Str needle = str_c(string);
        strings_begin(&scan, b, a, 4, "all");
        while (strings_next(&scan, a, &found))
            if (found.vaddr.has && str_contains(found.text, needle))
                *VEC_PUSH(a, addresses) = found.vaddr.v;
        if (addresses.n == 0)
            err_throw(b->err, ERR_LOCATION, "no string containing %s with an address",
                      py_repr(a, string).p);
    } else if (target != NULL && target[0] != '\0') {
        resolve(an, target, &addresses);
    } else {
        err_throw(b->err, ERR_LOCATION,
                  "xrefs needs a target: an address, a name, or --string TEXT");
    }
    AddrMap targets = {0};
    for (size_t i = 0; i < addresses.n; i++)
        addrmap_put(a, &targets, addresses.v[i], 1, true);
    ensure_functions(an);                   /* make sure the sweep has run */
    JVal *rows = j_list(a);
    for (size_t i = 0; i < an->index.n; i++) {
        const IndexEntry *e = &an->index.v[i];
        uint64_t ignored;
        bool hit = false;
        for (unsigned r = 0; r < e->nrefs && !hit; r++)
            hit = addrmap_get(&targets, e->refs[r], &ignored);
        if (!hit)
            continue;
        JVal *row = j_dict(a);
        j_set(a, row, "address", j_hex(a, e->address));
        j_set(a, row, "kind", j_cstr(a, e->kind == KIND_CALL ? "call" :
                                        e->kind == KIND_JUMP ? "jump" : "data"));
        j_set(a, row, "function", j_str(a, label(an, e->address)));
        j_set(a, row, "text", j_str(a, e->text));
        j_push(a, rows, row);
    }
    return rows;
}
