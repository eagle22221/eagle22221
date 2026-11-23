/* Disassembler: Capstone plus name and operand analysis (port of disasm.py). */
#include "disasm.h"

#include <capstone/capstone.h>
/* Capstone's own header for its handle: needed for one thing, see dis_decode(). */
#include "cs_priv.h"

#define STRING_PREVIEW 60

typedef enum { CPU_OTHER, CPU_X86, CPU_AARCH64, CPU_ARM } Cpu;

typedef struct {
    big start, end;
    Str name;
} Extent;

struct Disassembler {
    Arena *a;
    const Binary *b;
    csh handle;
    cs_insn *scratch;
    Cpu cpu;
    bool is_arm;                /* Capstone's ARM decoder (keeps IT-block state) */
    bool is_pe;
    big mask;
    CodeRanges code;
    AddrMap slots;              /* address -> index into b->imports */
    size_t nslots;
    AddrMap thunks;             /* cache: address -> import index + 1, 0 = none */
    AddrMap exact;              /* address -> index into names */
    VEC(Extent) names;          /* exact names, in the order they were added */
    Extent *extents;            /* named ranges, sorted by start */
    size_t nextents;
};

const char *insn_kind_name(InsnKind kind) {
    switch (kind) {
    case KIND_CALL: return "call";
    case KIND_JUMP: return "jump";
    case KIND_RET: return "ret";
    default: return "";
    }
}

Str insn_text(Arena *a, const Insn *insn) {
    return str_strip(str_printf(a, "%s %s", insn->mnemonic, insn->operands));
}

/* --- address map -------------------------------------------------------------- */

static size_t addr_hash(big key) {
    uint64_t low = (uint64_t)key, high = (uint64_t)((ubig)key >> 64);
    uint64_t h = (low ^ (high * UINT64_C(0xD6E8FEB86659FD93))) * UINT64_C(0x9E3779B97F4A7C15);
    return (size_t)(h ^ (h >> 29));
}

bool addrmap_get(const AddrMap *map, big key, uint64_t *value) {
    if (map->cap == 0)
        return false;
    size_t mask = map->cap - 1;
    for (size_t i = addr_hash(key) & mask; map->used[i]; i = (i + 1) & mask) {
        if (map->keys[i] == key) {
            *value = map->values[i];
            return true;
        }
    }
    return false;
}

bool addrmap_put(Arena *a, AddrMap *map, big key, uint64_t value, bool overwrite) {
    if ((map->count + 1) * 2 > map->cap) {
        AddrMap grown = {NULL, NULL, NULL, map->cap ? map->cap * 2 : 64, 0};
        grown.keys = arena_array(a, grown.cap, sizeof *grown.keys);
        grown.values = arena_array(a, grown.cap, sizeof *grown.values);
        grown.used = arena_array(a, grown.cap, sizeof *grown.used);
        for (size_t i = 0; i < map->cap; i++)
            if (map->used[i])
                addrmap_put(a, &grown, map->keys[i], map->values[i], true);
        *map = grown;
    }
    size_t mask = map->cap - 1;
    size_t i = addr_hash(key) & mask;
    for (; map->used[i]; i = (i + 1) & mask) {
        if (map->keys[i] == key) {
            if (overwrite)
                map->values[i] = value;
            return overwrite;
        }
    }
    map->used[i] = true;
    map->keys[i] = key;
    map->values[i] = value;
    map->count++;
    return true;
}

/* --- names -------------------------------------------------------------------- */

bool dis_in_code(const Disassembler *d, big address) {
    for (size_t i = 0; i < d->code.n; i++)
        if (address >= d->code.v[i].start && address - d->code.v[i].start < (big)d->code.v[i].size)
            return true;
    return false;
}

const Import *dis_slot(const Disassembler *d, big address) {
    uint64_t index;
    return addrmap_get(&d->slots, address, &index) ? &d->b->imports.v[index] : NULL;
}

bool dis_has_slots(const Disassembler *d) {
    return d->nslots != 0;
}

/* self._exact.setdefault(address, name) */
static void add_exact(Disassembler *d, big address, Str name) {
    if (addrmap_put(d->a, &d->exact, address, d->names.n, false)) {
        Extent e = {address, address, name};
        *VEC_PUSH(d->a, d->names) = e;
    }
}

static bool exact_name(const Disassembler *d, big address, Str *name) {
    uint64_t index;
    if (!addrmap_get(&d->exact, address, &index))
        return false;
    *name = d->names.v[index].name;
    return true;
}

static int compare_big(const void *pa, const void *pb) {
    big a = *(const big *)pa, b = *(const big *)pb;
    return (a > b) - (a < b);
}

static int compare_extents(const void *pa, const void *pb) {
    const Extent *a = pa, *b = pb;
    return (a->start > b->start) - (a->start < b->start);
}

/* Number of items <= key in a sorted array (bisect.bisect_right). */
static size_t bisect_right(const big *items, size_t n, big key) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (items[mid] <= key)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* Give every named address an extent, so inner addresses can be shown as
 * name+offset. Unsized code labels run to the next label. */
static void set_extents(Disassembler *d, const AddrMap *sizes) {
    size_t n = d->names.n;
    big *code_starts = arena_array(d->a, n, sizeof *code_starts);
    size_t ncode = 0;
    for (size_t i = 0; i < n; i++)
        if (dis_in_code(d, d->names.v[i].start))
            code_starts[ncode++] = d->names.v[i].start;
    if (ncode > 1)
        qsort(code_starts, ncode, sizeof *code_starts, compare_big);
    Extent *extents = arena_array(d->a, n, sizeof *extents);
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        big address = d->names.v[i].start;
        uint64_t recorded = 0;
        addrmap_get(sizes, address, &recorded);
        big size = recorded;
        if (!size && dis_in_code(d, address)) {
            big limit = 0;
            for (size_t r = 0; r < d->code.n; r++) {
                const CodeRange *range = &d->code.v[r];
                if (address >= range->start && address - range->start < (big)range->size) {
                    limit = range->start + range->size;
                    break;
                }
            }
            size_t next = bisect_right(code_starts, ncode, address);
            if (next < ncode && code_starts[next] < limit)
                limit = code_starts[next];
            size = limit - address;
        }
        if (size) {
            Extent e = {address, address + size, d->names.v[i].name};
            extents[count++] = e;
        }
    }
    if (count > 1)
        qsort(extents, count, sizeof *extents, compare_extents);
    d->extents = extents;
    d->nextents = count;
}

/* {s.address: s.size for s in symbols if s.size} */
static void symbol_sizes(Disassembler *d, AddrMap *sizes) {
    const Binary *b = d->b;
    for (size_t i = 0; i < b->symbols.n; i++)
        if (b->symbols.v[i].size)
            addrmap_put(d->a, sizes, b->symbols.v[i].address, b->symbols.v[i].size, true);
}

/* Order for choosing a name when several symbols share an address:
 * functions first, then global before local, then alphabetically. */
static bool ranks_before(const Symbol *x, const Symbol *y) {
    bool x_other = !str_eq_c(x->type, "func"), y_other = !str_eq_c(y->type, "func");
    if (x_other != y_other)
        return y_other;
    bool x_local = str_eq_c(x->binding, "local"), y_local = str_eq_c(y->binding, "local");
    if (x_local != y_local)
        return y_local;
    return str_cmp(x->name, y->name) < 0;
}

static void sort_ranked(const Symbol **items, const Symbol **scratch, size_t n) {
    if (n < 2)
        return;
    size_t half = n / 2;
    sort_ranked(items, scratch, half);
    sort_ranked(items + half, scratch, n - half);
    size_t i = 0, j = half, k = 0;
    while (i < half && j < n)
        scratch[k++] = ranks_before(items[j], items[i]) ? items[j++] : items[i++];
    while (i < half)
        scratch[k++] = items[i++];
    while (j < n)
        scratch[k++] = items[j++];
    memcpy(items, scratch, n * sizeof *items);
}

static void build_names(Disassembler *d) {
    const Binary *b = d->b;
    size_t n = b->symbols.n;
    const Symbol **ranked = arena_array(d->a, n, sizeof *ranked);
    const Symbol **scratch = arena_array(d->a, n, sizeof *scratch);
    for (size_t i = 0; i < n; i++)
        ranked[i] = &b->symbols.v[i];
    sort_ranked(ranked, scratch, n);
    for (size_t i = 0; i < n; i++)
        add_exact(d, ranked[i]->address, ranked[i]->name);
    for (size_t i = 0; i < b->exports.n; i++)
        if (b->exports.v[i].address.has)
            add_exact(d, b->exports.v[i].address.v, b->exports.v[i].name);
    if (b->entry.has)
        add_exact(d, b->entry.v, str_c("entry"));
    AddrMap sizes = {0};
    symbol_sizes(d, &sizes);
    set_extents(d, &sizes);
}

void dis_add_names(Disassembler *d, const Function *functions, size_t count) {
    AddrMap sizes = {0};
    symbol_sizes(d, &sizes);
    for (size_t i = 0; i < count; i++) {
        add_exact(d, functions[i].address, functions[i].name);
        if (functions[i].size)
            addrmap_put(d->a, &sizes, functions[i].address, (uint64_t)functions[i].size, false);
    }
    set_extents(d, &sizes);
}

Str dis_name_at(Disassembler *d, big address) {
    Str name;
    if (exact_name(d, address, &name) && name.n)
        return name;
    Str thunk = dis_thunk_at(d, address);
    if (thunk.p != NULL)
        return thunk;
    size_t lo = 0, hi = d->nextents;
    while (lo < hi) {                       /* bisect_right on the extent starts */
        size_t mid = lo + (hi - lo) / 2;
        if (d->extents[mid].start <= address)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo > 0 && address < d->extents[lo - 1].end) {
        char offset[40];
        const Extent *e = &d->extents[lo - 1];
        Buf out;
        buf_init(&out, d->a);
        buf_adds(&out, e->name);
        buf_addch(&out, '+');
        buf_addc(&out, hex_big(offset, address - e->start));
        return buf_str(&out);
    }
    return STR_NONE;
}

/* --- operand analysis --------------------------------------------------------- */

static bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static bool is_dec(char c) {
    return c >= '0' && c <= '9';
}

/* Parses "0x" followed by hex digits at s; returns the length consumed
 * (0 when there is no such number). */
static size_t parse_hex(const char *s, big *value) {
    if (s[0] != '0' || s[1] != 'x' || !is_hex(s[2]))
        return 0;
    size_t n = 2;
    ubig v = 0;
    for (; is_hex(s[n]); n++)
        v = (v << 4) | (ubig)(s[n] <= '9' ? s[n] - '0' : s[n] - 'a' + 10);
    *value = (big)v;
    return n;
}

/* "0x1f" or "31" at s (the group (0x[0-9a-f]+|\d+)); length consumed or 0. */
static size_t parse_number(const char *s, big *value) {
    size_t n = parse_hex(s, value);
    if (n)
        return n;
    if (!is_dec(s[0]))
        return 0;
    ubig v = 0;
    for (n = 0; is_dec(s[n]); n++)
        v = v * 10 + (ubig)(s[n] - '0');
    *value = (big)v;
    return n;
}

static void add_ref(Insn *insn, big value) {
    if (insn->nrefs < ARRAY_LEN(insn->refs))
        insn->refs[insn->nrefs++] = value;
}

/* Is an immediate likely an address? Position-independent images are based
 * at 0, where small constants would all look like addresses. */
static bool plausible(const Disassembler *d, big value) {
    return d->b->image_base > 0 && value >= (big)d->b->image_base &&
           binary_is_address(d->b, value);
}

/* re.search(r"\[rip(?: ([+-]) (0x[0-9a-f]+))?\]", ops) */
static bool find_rip(const char *ops, big *disp) {
    for (const char *p = strstr(ops, "[rip"); p != NULL; p = strstr(p + 1, "[rip")) {
        const char *q = p + 4;
        if (*q == ']') {
            *disp = 0;
            return true;
        }
        if (q[0] == ' ' && (q[1] == '+' || q[1] == '-') && q[2] == ' ') {
            big value;
            size_t n = parse_hex(q + 3, &value);
            if (n && q[3 + n] == ']') {
                *disp = q[1] == '-' ? -value : value;
                return true;
            }
        }
    }
    return false;
}

/* re.search(r"\[(?:[a-z0-9]+\*[1248] \+ )?(0x[0-9a-f]+)\]", ops) */
static bool find_absolute(const char *ops, big *value) {
    for (const char *p = strchr(ops, '['); p != NULL; p = strchr(p + 1, '[')) {
        const char *q = p + 1;
        while ((*q >= 'a' && *q <= 'z') || is_dec(*q))
            q++;
        if (q > p + 1 && q[0] == '*' && strchr("1248", q[1]) != NULL && q[1] != '\0' &&
            q[2] == ' ' && q[3] == '+' && q[4] == ' ') {
            size_t n = parse_hex(q + 5, value);
            if (n && q[5 + n] == ']')
                return true;
        }
        size_t n = parse_hex(p + 1, value);
        if (n && p[1 + n] == ']')
            return true;
    }
    return false;
}

/* re.search(r"(?:^|, )(0x[0-9a-f]+)$", ops) */
static bool find_trailing_immediate(const char *ops, big *value) {
    size_t length = strlen(ops);
    if (length && ops[length - 1] == '\n')
        length--;                           /* "$" also matches before a final newline */
    size_t start = length;
    while (start > 0 && is_hex(ops[start - 1]))
        start--;
    if (start == length || start < 2 || ops[start - 1] != 'x' || ops[start - 2] != '0')
        return false;
    start -= 2;
    if (start != 0 && !(start >= 2 && ops[start - 2] == ',' && ops[start - 1] == ' '))
        return false;
    return parse_hex(ops + start, value) == length - start;
}

/* int(_HASH_IMM.findall(ops)[-1], 0): the last "#number" in the operands. */
static bool last_hash_immediate(const char *ops, big *value) {
    bool found = false;
    for (const char *p = strchr(ops, '#'); p != NULL; p = strchr(p, '#')) {
        big number;
        size_t n = parse_number(p + 1, &number);
        p += 1 + n;
        if (n) {
            *value = number;
            found = true;
        }
    }
    return found;
}

static bool mnemonic_in(const char *op, const char *const *names, size_t count) {
    for (size_t i = 0; i < count; i++)
        if (strcmp(op, names[i]) == 0)
            return true;
    return false;
}

#define ONE_OF(op, ...) \
    mnemonic_in(op, (const char *const[]){__VA_ARGS__}, \
                sizeof((const char *const[]){__VA_ARGS__}) / sizeof(const char *))

static void analyse_x86(const Disassembler *d, Insn *insn) {
    /* The operation is the last word that is not a prefix ("rep movsb"). */
    char op[sizeof insn->mnemonic] = "";
    for (const char *p = insn->mnemonic; *p;) {
        while (*p == ' ' || (*p >= '\t' && *p <= '\r'))
            p++;
        size_t n = 0;
        char word[sizeof insn->mnemonic];
        while (*p && !(*p == ' ' || (*p >= '\t' && *p <= '\r')))
            word[n++] = *p++;
        word[n] = '\0';
        if (n && !ONE_OF(word, "bnd", "notrack", "rep", "repe", "repne", "lock", "data16",
                         "addr32"))
            memcpy(op, word, n + 1);
    }
    const char *ops = insn->operands;
    if (strcmp(op, "call") == 0) {
        insn->kind = KIND_CALL;
    } else if (op[0] == 'j' || strncmp(op, "loop", 4) == 0) {
        insn->kind = KIND_JUMP;
    } else if (ONE_OF(op, "ret", "retf", "retfq", "iret", "iretd", "iretq")) {
        insn->kind = KIND_RET;
        return;
    }
    if (strstr(ops, "0x") == NULL && strstr(ops, "[rip]") == NULL)
        return;
    big value;
    if (insn->kind != KIND_NONE) {
        size_t n = parse_hex(ops, &value);
        if (n && ops[n] == '\0') {              /* the whole operand is one address */
            insn->has_target = true;
            insn->target = value;
            add_ref(insn, value);
            return;
        }
    }
    if (find_rip(ops, &value))
        add_ref(insn, (insn->address + insn->size + value) & d->mask);
    else if (find_absolute(ops, &value) && plausible(d, value))
        add_ref(insn, value);
    if (insn->kind == KIND_NONE && find_trailing_immediate(ops, &value)) {
        bool known = false;
        for (unsigned i = 0; i < insn->nrefs; i++)
            known = known || insn->refs[i] == value;
        if (!known && plausible(d, value))
            add_ref(insn, value);
    }
}

/* Length of "x<digits>" at s, else 0. */
static size_t x_register(const char *s) {
    if (s[0] != 'x' || !is_dec(s[1]))
        return 0;
    size_t n = 1;
    while (is_dec(s[n]))
        n++;
    return n;
}

/* re.search(r"\[(x\d+), #(0x[0-9a-f]+|\d+)\]", ops) */
static bool find_a64_memory(const char *ops, const char **reg, size_t *reg_len, big *value) {
    for (const char *p = strchr(ops, '['); p != NULL; p = strchr(p + 1, '[')) {
        size_t r = x_register(p + 1);
        if (!r || strncmp(p + 1 + r, ", #", 3) != 0)
            continue;
        size_t n = parse_number(p + 4 + r, value);
        if (n && p[4 + r + n] == ']') {
            *reg = p + 1;
            *reg_len = r;
            return true;
        }
    }
    return false;
}

/* re.match(r"^x\d+, (x\d+), #(0x[0-9a-f]+|\d+)$", ops) */
static bool match_a64_add(const char *ops, const char **reg, size_t *reg_len, big *value) {
    size_t first = x_register(ops);
    if (!first || strncmp(ops + first, ", ", 2) != 0)
        return false;
    const char *second = ops + first + 2;
    size_t r = x_register(second);
    if (!r || strncmp(second + r, ", #", 3) != 0)
        return false;
    size_t n = parse_number(second + r + 3, value);
    const char *end = second + r + 3 + n;
    if (!n || !(end[0] == '\0' || (end[0] == '\n' && end[1] == '\0')))
        return false;
    *reg = second;
    *reg_len = r;
    return true;
}

static void analyse_a64(Decoder *dec, Insn *insn) {
    const char *op = insn->mnemonic, *ops = insn->operands;
    uint64_t index = ++dec->index;
    if (ONE_OF(op, "bl", "blr")) {
        insn->kind = KIND_CALL;
    } else if (ONE_OF(op, "b", "br", "cbz", "cbnz", "tbz", "tbnz") || strncmp(op, "b.", 2) == 0) {
        insn->kind = KIND_JUMP;
    } else if (ONE_OF(op, "ret", "eret")) {
        insn->kind = KIND_RET;
        return;
    }
    big value;
    if (insn->kind != KIND_NONE) {
        if (!ONE_OF(op, "blr", "br") && last_hash_immediate(ops, &value)) {
            insn->has_target = true;
            insn->target = value;
            add_ref(insn, value);
        }
        return;
    }
    if (strcmp(op, "adr") == 0) {
        if (last_hash_immediate(ops, &value))
            add_ref(insn, value);
    } else if (strcmp(op, "adrp") == 0) {
        if (!last_hash_immediate(ops, &value))
            return;
        const char *comma = strchr(ops, ',');
        size_t n = comma ? (size_t)(comma - ops) : strlen(ops);
        if (n >= sizeof dec->pages[0].reg)
            return;
        size_t slot = 0;
        while (slot < dec->npages &&
               !(strlen(dec->pages[slot].reg) == n && memcmp(dec->pages[slot].reg, ops, n) == 0))
            slot++;
        if (slot == ARRAY_LEN(dec->pages))
            return;
        if (slot == dec->npages)
            dec->npages++;
        memcpy(dec->pages[slot].reg, ops, n);
        dec->pages[slot].reg[n] = '\0';
        dec->pages[slot].page = value;
        dec->pages[slot].seen = index;
    } else if (dec->npages) {
        /* adrp loads a page address; the low 12 bits come from a following
         * add or from the displacement of a load/store. */
        const char *reg;
        size_t reg_len;
        bool matched = strcmp(op, "add") == 0 ? match_a64_add(ops, &reg, &reg_len, &value)
                                              : find_a64_memory(ops, &reg, &reg_len, &value);
        if (!matched)
            return;
        for (size_t slot = 0; slot < dec->npages; slot++) {
            if (strlen(dec->pages[slot].reg) == reg_len &&
                memcmp(dec->pages[slot].reg, reg, reg_len) == 0) {
                if (index - dec->pages[slot].seen <= 4)
                    add_ref(insn, dec->pages[slot].page + value);
                return;
            }
        }
    }
}

static void analyse_arm(Insn *insn) {
    char op[sizeof insn->mnemonic];
    size_t n = strcspn(insn->mnemonic, ".");
    memcpy(op, insn->mnemonic, n);
    op[n] = '\0';
    if (ONE_OF(op, "bl", "blx"))
        insn->kind = KIND_CALL;
    else if (strcmp(op, "bx") == 0 && strcmp(insn->operands, "lr") == 0)
        insn->kind = KIND_RET;
    else if (op[0] == 'b' && !ONE_OF(op, "bic", "bics", "bkpt", "bfc", "bfi"))
        insn->kind = KIND_JUMP;
    big value;
    if ((insn->kind == KIND_CALL || insn->kind == KIND_JUMP) &&
        last_hash_immediate(insn->operands, &value)) {
        insn->has_target = true;
        insn->target = value;
        add_ref(insn, value);
    }
}

static void analyse(Decoder *dec, Insn *insn) {
    switch (dec->dis->cpu) {
    case CPU_X86:
        analyse_x86(dec->dis, insn);
        break;
    case CPU_AARCH64:
        analyse_a64(dec, insn);
        break;
    case CPU_ARM:
        analyse_arm(insn);
        break;
    default:
        break;
    }
}

/* --- decoding ----------------------------------------------------------------- */

void dis_decode(Disassembler *d, Decoder *dec, const uint8_t *code, uint64_t size, big address) {
    memset(dec, 0, sizeof *dec);
    dec->dis = d;
    dec->code = code;
    dec->code_size = size;
    dec->base = address;
    dec->cursor = code;
    dec->left = (size_t)size;
    dec->address = (uint64_t)address;
    /* The Python version decodes each buffer with one cs_disasm() call, which
     * starts outside any Thumb IT block. cs_disasm_iter(), used here to keep
     * memory flat, does not reset that state, so do it by hand. */
    if (d->is_arm)
        ((struct cs_struct *)(uintptr_t)d->handle)->ITBlock.size = 0;
}

/* The next instruction, not yet analysed. */
static bool decode_one(Decoder *dec, Insn *insn) {
    Disassembler *d = dec->dis;
    cs_insn *raw = d->scratch;
    if (dec->left == 0 || !cs_disasm_iter(d->handle, &dec->cursor, &dec->left, &dec->address, raw))
        return false;
    memset(insn, 0, sizeof *insn);
    insn->address = raw->address;
    insn->size = raw->size;
    memcpy(insn->mnemonic, raw->mnemonic, sizeof insn->mnemonic);
    insn->mnemonic[sizeof insn->mnemonic - 1] = '\0';
    memcpy(insn->operands, raw->op_str, sizeof insn->operands);
    insn->operands[sizeof insn->operands - 1] = '\0';
    /* Python: code[addr - base:addr - base + size], with its slice rules. */
    big length = dec->code_size;
    big from = insn->address - dec->base, to = from + insn->size;
    if (from < 0)
        from = from + length < 0 ? 0 : from + length;
    if (to < 0)
        to = to + length < 0 ? 0 : to + length;
    if (from > length)
        from = length;
    if (to > length)
        to = length;
    insn->raw = dec->code + (uint64_t)from;
    insn->raw_size = to > from ? (size_t)(to - from) : 0;
    return true;
}

bool dis_next(Decoder *dec, Insn *insn) {
    if (!decode_one(dec, insn))
        return false;
    if (strcmp(insn->mnemonic, ".byte") != 0)
        analyse(dec, insn);
    return true;
}

const Import *dis_thunk_import(Disassembler *d, big address) {
    uint64_t cached;
    if (addrmap_get(&d->thunks, address, &cached))
        return cached ? &d->b->imports.v[cached - 1] : NULL;
    const Import *result = NULL;
    if (d->nslots && dis_in_code(d, address)) {
        uint64_t got;
        const uint8_t *code = binary_read(d->b, address, 24, &got);
        Decoder dec;
        Insn insn;
        dis_decode(d, &dec, code, got, address);
        for (unsigned count = 0; decode_one(&dec, &insn); count++) {
            if (count == 0 && (strcmp(insn.mnemonic, "endbr64") == 0 ||
                               strcmp(insn.mnemonic, "endbr32") == 0))
                continue;
            Decoder fresh;                      /* analysed on its own: no adrp history */
            memset(&fresh, 0, sizeof fresh);
            fresh.dis = d;
            analyse(&fresh, &insn);
            if (insn.kind == KIND_JUMP && !insn.has_target && insn.nrefs)
                result = dis_slot(d, insn.refs[0]);
            break;
        }
    }
    addrmap_put(d->a, &d->thunks, address,
                result ? (uint64_t)(result - d->b->imports.v) + 1 : 0, true);
    return result;
}

Str dis_thunk_at(Disassembler *d, big address) {
    const Import *imp = dis_thunk_import(d, address);
    if (imp == NULL)
        return STR_NONE;
    Buf out;
    buf_init(&out, d->a);
    buf_adds(&out, imp->name);
    buf_addc(&out, d->is_pe ? "@thunk" : "@plt");
    return buf_str(&out);
}

/* --- annotation --------------------------------------------------------------- */

/* Quoted preview of a NUL-terminated ASCII or UTF-16 string at address (data
 * only: code bytes that happen to be printable are ignored). */
static Str string_at(Disassembler *d, big address) {
    if (dis_in_code(d, address))
        return STR_NONE;
    uint64_t length;
    const uint8_t *data = binary_read(d->b, address, 4 * STRING_PREVIEW, &length);
    for (uint64_t step = 1; step <= 2; step++) {
        char chars[4 * STRING_PREVIEW + 1];
        size_t n = 0;
        bool visible = false;
        for (uint64_t i = 0; i + step <= length; i += step) {
            uint8_t c = data[i];
            if (step == 2 && data[i + 1] != 0)
                break;
            if (!((c >= 0x20 && c <= 0x7E) || c == 9 || c == 10 || c == 13))
                break;
            chars[n++] = (char)c;
            visible = visible || c > ' ';
        }
        uint64_t end = n * step;
        bool terminated = end + step > length;      /* end >= len(data) - step */
        if (!terminated) {
            terminated = true;
            for (uint64_t k = 0; k < step; k++)
                terminated = terminated && data[end + k] == 0;
        }
        if (end + step == length && !terminated)
            terminated = true;
        if (n >= 4 && terminated && visible) {
            Buf out;
            buf_init(&out, d->a);
            buf_addch(&out, '"');
            for (size_t i = 0; i < n && i < STRING_PREVIEW; i++) {
                switch (chars[i]) {
                case '\n': buf_addc(&out, "\\n"); break;
                case '\r': buf_addc(&out, "\\r"); break;
                case '\t': buf_addc(&out, "\\t"); break;
                case '"': buf_addc(&out, "\\\""); break;
                case '\\': buf_addc(&out, "\\\\"); break;
                default: buf_addch(&out, chars[i]);
                }
            }
            buf_addc(&out, n > STRING_PREVIEW ? "...\"" : "\"");
            return buf_str(&out);
        }
    }
    return STR_NONE;
}

/* Annotation for a data address: import, name and/or string. */
static Str describe(Disassembler *d, big address) {
    const Import *imp = dis_slot(d, address);
    Buf out;
    buf_init(&out, d->a);
    if (imp != NULL) {
        if (d->is_pe && imp->library.n) {
            buf_adds(&out, imp->library);
            buf_addch(&out, '!');
        }
        buf_adds(&out, imp->name);
        return buf_str(&out);
    }
    Str name;
    if (exact_name(d, address, &name) && name.n)
        buf_adds(&out, name);
    Str text = string_at(d, address);
    if (text.p != NULL) {
        if (out.n)
            buf_addch(&out, ' ');
        buf_adds(&out, text);
    }
    if (out.n == 0) {
        name = dis_name_at(d, address);
        if (name.n)
            buf_adds(&out, name);
    }
    return buf_str(&out);
}

void dis_annotate(Disassembler *d, Insn *insn) {
    insn->comment = str_c("");
    if (insn->has_target) {
        Str name = dis_name_at(d, insn->target);
        if (name.p != NULL)
            insn->comment = name;
    } else if (insn->nrefs) {
        insn->comment = describe(d, insn->refs[0]);
    }
}

/* --- set-up ------------------------------------------------------------------- */

static void dis_close(void *arg) {
    Disassembler *d = arg;
    if (d->scratch != NULL)
        cs_free(d->scratch, 1);
    cs_close(&d->handle);
}

Disassembler *dis_new(Arena *a, const Binary *b) {
    Disassembler *d = arena_alloc(a, sizeof *d);
    d->a = a;
    d->b = b;
    bool big_endian = strcmp(b->endian, "big") == 0;
    int order = big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    cs_arch arch;
    int mode;
    d->is_pe = strcmp(b->format, "PE") == 0;
    if (str_eq_c(b->arch, "x86")) {
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
        d->cpu = CPU_X86;
    } else if (str_eq_c(b->arch, "x86_64")) {
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
        d->cpu = CPU_X86;
    } else if (str_eq_c(b->arch, "aarch64")) {
        arch = CS_ARCH_ARM64;
        mode = CS_MODE_ARM;
        d->cpu = CPU_AARCH64;
    } else if (str_eq_c(b->arch, "arm")) {
        arch = CS_ARCH_ARM;
        mode = (d->is_pe ? CS_MODE_THUMB : CS_MODE_ARM) | order;
        d->cpu = CPU_ARM;
        d->is_arm = true;
    } else if (str_eq_c(b->arch, "mips")) {
        arch = CS_ARCH_MIPS;
        mode = (b->bits == 64 ? CS_MODE_MIPS64 : CS_MODE_MIPS32) | order;
    } else if (str_eq_c(b->arch, "ppc")) {
        arch = CS_ARCH_PPC;
        mode = CS_MODE_32 | order;
    } else if (str_eq_c(b->arch, "ppc64")) {
        arch = CS_ARCH_PPC;
        mode = CS_MODE_64 | order;
    } else {
        err_throw(b->err, ERR_UNSUPPORTED, "no disassembler for CPU architecture '%s'",
                  b->arch.p);
    }
    cs_err status = cs_open(arch, (cs_mode)mode, &d->handle);
    if (status != CS_ERR_OK)
        err_throw(b->err, ERR_UNSUPPORTED, "the disassembler cannot be started: %s",
                  cs_strerror(status));
    arena_on_release(a, dis_close, d);
    cs_option(d->handle, CS_OPT_SKIPDATA, CS_OPT_ON);   /* undecodable bytes: ".byte" */
    d->scratch = cs_malloc(d->handle);
    if (d->scratch == NULL)
        die_out_of_memory();
    d->mask = b->bits ? ((big)1 << b->bits) - 1 : ((big)1 << 64) - 1;
    binary_executable_ranges(b, a, &d->code);
    for (size_t i = 0; i < b->imports.n; i++) {
        if (b->imports.v[i].address.has) {
            addrmap_put(a, &d->slots, b->imports.v[i].address.v, i, true);
            d->nslots++;
        }
    }
    build_names(d);
    return d;
}
