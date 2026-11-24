/* Text renderers (port of the _render_* functions in cli.py). */
#include "render.h"
#include "techniques.h"

/* --- styling ------------------------------------------------------------------ */

#define BOLD "1"
#define DIM "2"
#define RED "31"
#define GREEN "32"
#define YELLOW "33"
#define BLUE "34"
#define MAGENTA "35"
#define CYAN "36"

static Str styled(Arena *a, const Style *st, Str text, const char *codes) {
    if (!st->colour || codes == NULL)
        return text;
    Buf b;
    buf_init(&b, a);
    buf_printf(&b, "\x1b[%sm", codes);
    buf_adds(&b, text);
    buf_addc(&b, "\x1b[0m");
    return buf_str(&b);
}

static void add(Arena *a, Lines *out, Str line) {
    *VEC_PUSH(a, *out) = line;
}

static void heading(Arena *a, const Style *st, Lines *out, const char *title) {
    add(a, out, str_c(""));
    add(a, out, styled(a, st, str_printf(a, "== %s ==", title), BOLD ";" CYAN));
}

static void pad_to(Buf *b, Str text, size_t width, bool right) {
    size_t len = utf8_length(text);
    if (right)
        for (size_t i = len; i < width; i++)
            buf_addch(b, ' ');
    buf_adds(b, text);
    if (!right)
        for (size_t i = len; i < width; i++)
            buf_addch(b, ' ');
}

static Str hex_number(Arena *a, big value) {
    char text[40];
    return str_copy(a, hex_big(text, value), strlen(hex_big(text, value)));
}

static Str dec_number(Arena *a, big value) {
    char text[44];
    return str_copy(a, dec_big(text, value), strlen(dec_big(text, value)));
}

/* --- tables ------------------------------------------------------------------- */

typedef struct {
    Arena *arena;
    size_t columns;
    const char *const *headers;
    unsigned right;             /* bit i set: column i is right-aligned */
    VEC(Str) cells;             /* row-major */
} Table;

static void table_init(Table *t, Arena *a, const char *const *headers, size_t columns,
                       unsigned right) {
    memset(t, 0, sizeof *t);
    t->arena = a;
    t->headers = headers;
    t->columns = columns;
    t->right = right;
}

static void table_cell(Table *t, Str text) {
    *VEC_PUSH(t->arena, t->cells) = text.p ? text : str_c("");
}

static Str table_line(const Table *t, const size_t *widths, const Str *row) {
    Buf line;
    buf_init(&line, t->arena);
    for (size_t c = 0; c < t->columns; c++) {
        if (c)
            buf_addc(&line, "  ");
        pad_to(&line, row[c], widths[c], (t->right >> c) & 1);
    }
    Str s = buf_str(&line);
    while (s.n > 0 && (s.p[s.n - 1] == ' ' || s.p[s.n - 1] == '\t' || s.p[s.n - 1] == '\n' ||
                       s.p[s.n - 1] == '\r'))
        s.n--;
    return str_copy(t->arena, s.p, s.n);
}

/* Aligned text table: header, dashes, rows. */
static void table_render(const Table *t, const Style *st, Lines *out) {
    Arena *a = t->arena;
    size_t *widths = arena_array(a, t->columns, sizeof *widths);
    Str *head = arena_array(a, t->columns, sizeof *head);
    for (size_t c = 0; c < t->columns; c++) {
        head[c] = str_c(t->headers[c]);
        widths[c] = head[c].n;
    }
    size_t rows = t->cells.n / t->columns;
    for (size_t r = 0; r < rows; r++) {
        for (size_t c = 0; c < t->columns; c++) {
            size_t len = utf8_length(t->cells.v[r * t->columns + c]);
            if (len > widths[c])
                widths[c] = len;
        }
    }
    add(a, out, styled(a, st, table_line(t, widths, head), BOLD));
    Buf dashes;
    buf_init(&dashes, a);
    for (size_t c = 0; c < t->columns; c++) {
        if (c)
            buf_addc(&dashes, "  ");
        for (size_t i = 0; i < widths[c]; i++)
            buf_addch(&dashes, '-');
    }
    add(a, out, styled(a, st, buf_str(&dashes), DIM));
    for (size_t r = 0; r < rows; r++)
        add(a, out, table_line(t, widths, &t->cells.v[r * t->columns]));
}

/* --- info --------------------------------------------------------------------- */

typedef struct {
    const char *label;
    Str value;
} InfoRow;

static Str join_list(Arena *a, const JVal *list, const char *separator) {
    Buf b;
    buf_init(&b, a);
    for (size_t i = 0; i < j_len(list); i++) {
        if (i)
            buf_addc(&b, separator);
        buf_adds(&b, j_text(j_at(list, i)));
    }
    return buf_str(&b);
}

void render_info(Arena *a, const Style *st, const JVal *d, Lines *out) {
    static const struct {
        const char *key, *label;
    } labels[] = {
        {"interpreter", "Interpreter"}, {"build_id", "Build ID"}, {"soname", "SONAME"},
        {"compiler", "Compiler"}, {"source_files", "Source files"},
        {"timestamp", "Timestamp"}, {"subsystem", "Subsystem"},
        {"linker_version", "Linker version"}, {"dll_name", "Internal name"},
        {"pdb_path", "PDB path"}, {"imphash", "Import hash"},
    };
    const JVal *md = j_get(d, "metadata");
    const JVal *hashes = j_get(d, "hashes");
    double entropy = j_get(d, "entropy")->u.real;
    VEC(InfoRow) rows = {0};
#define ROW(label_text, value_text) \
    do { \
        InfoRow row_ = {label_text, value_text}; \
        *VEC_PUSH(a, rows) = row_; \
    } while (0)

    Str name = j_text(j_get(d, "name"));
    ROW("File", name.n ? name : str_c("<memory>"));
    ROW("Format", str_printf(a, "%s %d-bit %s, %s-endian, %s", j_text(j_get(d, "format")).p,
                             (int)j_number(j_get(d, "bits")), j_text(j_get(d, "arch")).p,
                             j_text(j_get(d, "endian")).p, j_text(j_get(d, "kind")).p));
    Str entry = j_text(j_get(d, "entry"));
    ROW("Entry point", entry.n ? entry : str_c("none"));
    ROW("Image base", j_text(j_get(d, "image_base")));
    ROW("Size", str_printf(a, "%s bytes", dec_number(a, j_number(j_get(d, "size"))).p));
    ROW("Entropy", str_printf(a, "%.2f bits/byte%s", entropy,
                              entropy > 7.2 ? "  (high: packed or encrypted?)" : ""));
    ROW("MD5", j_text(j_get(hashes, "md5")));
    ROW("SHA-1", j_text(j_get(hashes, "sha1")));
    ROW("SHA-256", j_text(j_get(hashes, "sha256")));
    Str libraries = join_list(a, j_get(d, "libraries"), ", ");
    ROW("Libraries", libraries.n ? libraries : str_c("none"));
    for (size_t i = 0; i < ARRAY_LEN(labels); i++) {
        const JVal *value = j_get(md, labels[i].key);
        if (value == NULL)
            continue;
        if (value->kind == J_LIST)
            ROW(labels[i].label, join_list(a, value, ", "));
        else if (value->kind == J_INT)
            ROW(labels[i].label, dec_number(a, value->u.number));
        else
            ROW(labels[i].label, j_text(value));
    }
    const JVal *overlay = j_get(md, "overlay");
    if (overlay != NULL)
        ROW("Overlay", str_printf(a, "%s bytes appended at offset %s",
                                  dec_number(a, j_number(j_get(overlay, "size"))).p,
                                  hex_number(a, j_number(j_get(overlay, "offset"))).p));
#undef ROW

    size_t width = 0;
    for (size_t i = 0; i < rows.n; i++)
        if (strlen(rows.v[i].label) > width)
            width = strlen(rows.v[i].label);
    heading(a, st, out, "Overview");
    for (size_t i = 0; i < rows.n; i++) {
        Buf line, label;
        buf_init(&line, a);
        buf_init(&label, a);
        pad_to(&label, str_c(rows.v[i].label), width, false);
        buf_adds(&line, styled(a, st, buf_str(&label), BOLD));
        buf_addc(&line, "  ");
        buf_adds(&line, rows.v[i].value);
        add(a, out, buf_str(&line));
    }

    heading(a, st, out, "Security");
    const JVal *sec = j_get(d, "security_details");
    width = 0;
    for (size_t i = 0; i < j_len(sec); i++) {
        size_t len = utf8_length(j_text(j_get(j_at(sec, i), "label")));
        if (len > width)
            width = len;
    }
    for (size_t i = 0; i < j_len(sec); i++) {
        const JVal *r = j_at(sec, i);
        Str state = j_text(j_get(r, "state"));
        const char *colour = str_eq_c(state, "good") ? GREEN ";" BOLD :
                             str_eq_c(state, "bad") ? RED ";" BOLD :
                             str_eq_c(state, "warn") ? YELLOW ";" BOLD : NULL;
        Buf line;
        buf_init(&line, a);
        pad_to(&line, j_text(j_get(r, "label")), width, false);
        buf_addc(&line, "  ");
        buf_adds(&line, styled(a, st, j_text(j_get(r, "value")), colour));
        add(a, out, buf_str(&line));
    }

    const JVal *warnings = j_get(d, "warnings");
    if (j_len(warnings)) {
        heading(a, st, out, "Warnings");
        for (size_t i = 0; i < j_len(warnings); i++) {
            Str w = j_text(j_at(warnings, i));
            add(a, out, styled(a, st, str_printf(a, "! %s", w.p), YELLOW));
        }
    }
}

/* --- tables of the binary ----------------------------------------------------- */

void render_sections(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    static const char *const headers[] = {"Name", "Address", "VSize", "Offset", "Size",
                                          "Perm", "Entropy", "Type"};
    Table t;
    table_init(&t, a, headers, 8, 1u << 2 | 1u << 3 | 1u << 4 | 1u << 6);
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        double entropy = j_get(r, "entropy")->u.real;
        Str address = j_text(j_get(r, "address"));
        table_cell(&t, j_text(j_get(r, "name")));
        table_cell(&t, address.n ? address : str_c("-"));
        table_cell(&t, hex_number(a, j_number(j_get(r, "vsize"))));
        table_cell(&t, hex_number(a, j_number(j_get(r, "offset"))));
        table_cell(&t, hex_number(a, j_number(j_get(r, "size"))));
        table_cell(&t, j_text(j_get(r, "perms")));
        table_cell(&t, str_printf(a, "%.2f%s", entropy, entropy > 7.2 ? " !" : ""));
        table_cell(&t, j_text(j_get(r, "type")));
    }
    table_render(&t, st, out);
}

void render_segments(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    static const char *const headers[] = {"Type", "Address", "VSize", "Offset", "Size", "Perm"};
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no segments)"));
        return;
    }
    Table t;
    table_init(&t, a, headers, 6, 1u << 2 | 1u << 3 | 1u << 4);
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        table_cell(&t, j_text(j_get(r, "type")));
        table_cell(&t, j_text(j_get(r, "address")));
        table_cell(&t, hex_number(a, j_number(j_get(r, "vsize"))));
        table_cell(&t, hex_number(a, j_number(j_get(r, "offset"))));
        table_cell(&t, hex_number(a, j_number(j_get(r, "size"))));
        table_cell(&t, j_text(j_get(r, "perms")));
    }
    table_render(&t, st, out);
}

void render_imports(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no imports)"));
        return;
    }
    const JVal *current = NULL;
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        const JVal *library = j_get(r, "library");
        bool same = current != NULL && current->kind == library->kind &&
                    (library->kind == J_NULL || str_eq(current->u.text, library->u.text));
        if (!same) {
            current = library;
            Str title = j_text(library);
            if (i)
                add(a, out, str_c(""));
            add(a, out, styled(a, st, title.n ? title : str_c("(library not recorded)"),
                               BOLD ";" CYAN));
        }
        Buf line;
        buf_init(&line, a);
        Str address = j_text(j_get(r, "address"));
        buf_addc(&line, "  ");
        pad_to(&line, address.n ? address : str_c("-"), 14, false);
        buf_addc(&line, "  ");
        buf_adds(&line, j_text(j_get(r, "name")));
        Str version = j_text(j_get(r, "version"));
        bool delayed = j_truthy(j_get(r, "delayed"));
        if (version.n || delayed) {
            Str extra = str_printf(a, "  [%s%s%s]", version.p,
                                   version.n && delayed ? ", " : "",
                                   delayed ? "delay-loaded" : "");
            buf_adds(&line, styled(a, st, extra, DIM));
        }
        add(a, out, buf_str(&line));
    }
}

void render_exports(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    static const char *const headers[] = {"Ordinal", "Address", "Name", "Forwarded to"};
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no exports)"));
        return;
    }
    Table t;
    table_init(&t, a, headers, 4, 1u << 0);
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        const JVal *ordinal = j_get(r, "ordinal");
        Str address = j_text(j_get(r, "address"));
        table_cell(&t, ordinal->kind == J_INT ? dec_number(a, ordinal->u.number) : str_c(""));
        table_cell(&t, address.n ? address : str_c("-"));
        table_cell(&t, j_text(j_get(r, "name")));
        table_cell(&t, j_text(j_get(r, "forwarder")));
    }
    table_render(&t, st, out);
}

void render_symbols(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    static const char *const headers[] = {"Address", "Size", "Type", "Bind", "Section", "Name"};
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no symbols)"));
        return;
    }
    Table t;
    table_init(&t, a, headers, 6, 1u << 1);
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        table_cell(&t, j_text(j_get(r, "address")));
        table_cell(&t, dec_number(a, j_number(j_get(r, "size"))));
        table_cell(&t, j_text(j_get(r, "type")));
        table_cell(&t, j_text(j_get(r, "binding")));
        table_cell(&t, j_text(j_get(r, "section")));
        table_cell(&t, j_text(j_get(r, "name")));
    }
    table_render(&t, st, out);
}

Str render_string_row(Arena *a, const Style *st, const JVal *r) {
    Buf line;
    buf_init(&line, a);
    Str address = j_text(j_get(r, "address"));
    if (address.n == 0)
        address = str_printf(a, "@%s", hex_number(a, j_number(j_get(r, "offset"))).p);
    pad_to(&line, address, 14, false);
    buf_addc(&line, "  ");
    pad_to(&line, j_text(j_get(r, "section")), 10, false);
    buf_addc(&line, "  ");
    buf_adds(&line, j_text(j_get(r, "text")));
    const JVal *tags = j_get(r, "tags");
    if (j_len(tags)) {
        Str joined = join_list(a, tags, ",");
        buf_adds(&line, styled(a, st, str_printf(a, " [%s]", joined.p), YELLOW));
    }
    if (str_eq_c(j_text(j_get(r, "encoding")), "utf16"))
        buf_adds(&line, styled(a, st, str_c(" (utf16)"), DIM));
    return buf_str(&line);
}

void render_strings(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no strings)"));
        return;
    }
    for (size_t i = 0; i < j_len(rows); i++)
        add(a, out, render_string_row(a, st, j_at(rows, i)));
}

/* --- code --------------------------------------------------------------------- */

static void functions_table(Arena *a, const Style *st, const JVal *rows, size_t limit,
                            Lines *out) {
    static const char *const headers[] = {"Address", "Size", "Found by", "Name"};
    Table t;
    table_init(&t, a, headers, 4, 1u << 1);
    for (size_t i = 0; i < j_len(rows) && i < limit; i++) {
        const JVal *r = j_at(rows, i);
        table_cell(&t, j_text(j_get(r, "address")));
        table_cell(&t, dec_number(a, j_number(j_get(r, "size"))));
        table_cell(&t, j_text(j_get(r, "source")));
        table_cell(&t, j_text(j_get(r, "name")));
    }
    table_render(&t, st, out);
}

void render_functions(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no functions)"));
        return;
    }
    functions_table(a, st, rows, SIZE_MAX, out);
}

static Str instruction_text(Arena *a, const JVal *insn) {
    Str mnemonic = j_text(j_get(insn, "mnemonic")), operands = j_text(j_get(insn, "operands"));
    Str text = str_printf(a, "%s %s", mnemonic.p, operands.p);
    return str_strip(text);
}

void render_disassembly(Arena *a, const Style *st, const JVal *d, Lines *out) {
    const JVal *insns = j_get(d, "instructions");
    size_t width = 0, text_width = 0;
    for (size_t i = 0; i < j_len(insns); i++) {
        const JVal *insn = j_at(insns, i);
        size_t bytes = j_text(j_get(insn, "bytes")).n;
        size_t text = instruction_text(a, insn).n;
        if (bytes > width)
            width = bytes;
        if (text > text_width)
            text_width = text;
    }
    width += width / 2;                 /* room for a space after every byte */
    if (text_width > 44)
        text_width = 44;
    for (size_t i = 0; i < j_len(insns); i++) {
        const JVal *insn = j_at(insns, i);
        Str label = j_text(j_get(insn, "label"));
        if (label.n) {
            add(a, out, str_c(""));
            add(a, out, styled(a, st, str_printf(a, "%s:", label.p), BOLD ";" CYAN));
        }
        Str bytes = j_text(j_get(insn, "bytes"));
        Buf raw;
        buf_init(&raw, a);
        for (size_t n = 0; n < bytes.n; n += 2) {
            if (n)
                buf_addch(&raw, ' ');
            buf_add(&raw, bytes.p + n, bytes.n - n < 2 ? bytes.n - n : 2);
        }
        while (raw.n < width)
            buf_addch(&raw, ' ');
        Str kind = j_text(j_get(insn, "kind"));
        const char *colour = str_eq_c(kind, "call") ? GREEN : str_eq_c(kind, "jump") ? YELLOW :
                             str_eq_c(kind, "ret") ? MAGENTA : BLUE;
        Str operands = j_text(j_get(insn, "operands"));
        Str comment = j_text(j_get(insn, "comment"));
        Buf line;
        buf_init(&line, a);
        buf_addc(&line, "  ");
        buf_adds(&line, styled(a, st, str_printf(a, "%s:", j_text(j_get(insn, "address")).p),
                               DIM));
        buf_addc(&line, "  ");
        buf_adds(&line, styled(a, st, buf_str(&raw), DIM));
        buf_addc(&line, "  ");
        buf_adds(&line, styled(a, st, j_text(j_get(insn, "mnemonic")), colour));
        if (operands.n) {
            buf_addch(&line, ' ');
            buf_adds(&line, operands);
        }
        if (comment.n) {
            for (size_t n = instruction_text(a, insn).n; n < text_width; n++)
                buf_addch(&line, ' ');
            buf_addc(&line, "  ");
            buf_adds(&line, styled(a, st, str_printf(a, "; %s", comment.p), GREEN));
        }
        add(a, out, buf_str(&line));
    }
}

void render_xrefs(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    static const char *const headers[] = {"Address", "Kind", "In", "Instruction"};
    if (j_len(rows) == 0) {
        add(a, out, str_c("(no references found)"));
        return;
    }
    Table t;
    table_init(&t, a, headers, 4, 0);
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        table_cell(&t, j_text(j_get(r, "address")));
        table_cell(&t, j_text(j_get(r, "kind")));
        table_cell(&t, j_text(j_get(r, "function")));
        table_cell(&t, j_text(j_get(r, "text")));
    }
    table_render(&t, st, out);
}

/* --- raw views ---------------------------------------------------------------- */

void render_hexdump(Arena *a, const Style *st, const JVal *d, Lines *out) {
    const JVal *rows = j_get(d, "rows");
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        Buf line;
        buf_init(&line, a);
        buf_adds(&line, styled(a, st, str_printf(a, "%08" PRIx64,
                                                 (uint64_t)j_number(j_get(r, "offset"))), DIM));
        buf_addc(&line, "  ");
        pad_to(&line, j_text(j_get(r, "address")), 12, false);
        buf_addc(&line, "  ");
        pad_to(&line, j_text(j_get(r, "hex")), 47, false);
        buf_addc(&line, "  |");
        buf_adds(&line, j_text(j_get(r, "ascii")));
        buf_addch(&line, '|');
        add(a, out, buf_str(&line));
    }
}

void render_layout(Arena *a, const Style *st, const JVal *d, Lines *out) {
    static const char *const headers[] = {"Offset", "Size", "Kind", "Name"};
    Table t;
    table_init(&t, a, headers, 4, 1u << 0 | 1u << 1);
    const JVal *regions = j_get(d, "regions");
    for (size_t i = 0; i < j_len(regions); i++) {
        const JVal *r = j_at(regions, i);
        table_cell(&t, hex_number(a, j_number(j_get(r, "offset"))));
        table_cell(&t, hex_number(a, j_number(j_get(r, "size"))));
        table_cell(&t, j_text(j_get(r, "kind")));
        table_cell(&t, j_text(j_get(r, "name")));
    }
    table_render(&t, st, out);
}

void render_report(Arena *a, const Style *st, const JVal *d, Lines *out) {
    render_info(a, st, j_get(d, "info"), out);
    const JVal *techniques = j_get(d, "techniques");
    if (j_len(techniques) > 0) {
        heading(a, st, out, "Techniques");
        render_techniques(a, st, techniques, out);
    }
    heading(a, st, out, "Sections");
    render_sections(a, st, j_get(d, "sections"), out);
    heading(a, st, out, "Imports");
    render_imports(a, st, j_get(d, "imports"), out);
    if (j_len(j_get(d, "exports"))) {
        heading(a, st, out, "Exports");
        render_exports(a, st, j_get(d, "exports"), out);
    }
    heading(a, st, out, "Interesting strings");
    const JVal *strings = j_get(d, "strings");
    if (j_len(strings) == 0)
        add(a, out, str_c("(none tagged)"));
    for (size_t i = 0; i < j_len(strings) && i < 60; i++)
        add(a, out, render_string_row(a, st, j_at(strings, i)));
    if (j_len(strings) > 60)
        add(a, out, styled(a, st, str_printf(a, "... %zu more (vex strings --tagged)",
                                             j_len(strings) - 60), DIM));
    heading(a, st, out, "Functions");
    const JVal *functions = j_get(d, "functions");
    if (functions == NULL || functions->kind != J_LIST) {
        const JVal *why = j_get(d, "functions_error");
        add(a, out, str_printf(a, "(unavailable: %s)",
                               why ? j_text(why).p : "no disassembler"));
    } else {
        functions_table(a, st, functions, 60, out);
        if (j_len(functions) > 60)
            add(a, out, styled(a, st, str_printf(a, "... %zu more (vex functions)",
                                                 j_len(functions) - 60), DIM));
    }
}

/* The piece table of `vex split`, then the "Saved N files" line. */
void render_split(Arena *a, const Style *st, const JVal *d, Lines *out) {
    static const char *const headers[] = {"Offset", "Size", "Kind", "File", "Name", "Note"};
    Table t;
    table_init(&t, a, headers, 6, 1u << 0 | 1u << 1);
    const JVal *pieces = j_get(d, "pieces");
    for (size_t i = 0; i < j_len(pieces); i++) {
        const JVal *p = j_at(pieces, i);
        Str path = j_text(j_get(p, "path"));
        table_cell(&t, hex_number(a, j_number(j_get(p, "offset"))));
        table_cell(&t, dec_number(a, j_number(j_get(p, "size"))));
        table_cell(&t, j_text(j_get(p, "kind")));
        table_cell(&t, path.n ? path : str_c("-"));
        table_cell(&t, j_text(j_get(p, "name")));
        table_cell(&t, j_text(j_get(p, "note")));
    }
    table_render(&t, st, out);
    add(a, out, styled(a, st, j_text(j_get(d, "message")), GREEN ";" BOLD));
}

void render_done(Arena *a, const Style *st, const JVal *d, Lines *out) {
    const JVal *patches = j_get(d, "patches");
    for (size_t i = 0; i < j_len(patches); i++) {
        const JVal *p = j_at(patches, i);
        Str where = j_text(j_get(p, "address"));
        if (where.n == 0)
            where = str_printf(a, "file offset %s",
                               hex_number(a, j_number(j_get(p, "offset"))).p);
        add(a, out, str_printf(a, "%s: %s -> %s", where.p, j_text(j_get(p, "old")).p,
                               j_text(j_get(p, "new")).p));
    }
    add(a, out, styled(a, st, j_text(j_get(d, "message")), GREEN ";" BOLD));
}

void lines_print(FILE *out, const Lines *lines) {
    size_t first = 0;
    while (first < lines->n && lines->v[first].n == 0)
        first++;                        /* lstrip("\n") of the joined text */
    for (size_t i = first; i < lines->n; i++) {
        if (i > first)
            fputc('\n', out);
        fwrite(lines->v[i].p, 1, lines->v[i].n, out);
    }
    fputc('\n', out);
}
