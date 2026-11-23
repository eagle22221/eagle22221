/* Command-line interface: `binspect <command> FILE ...` (port of cli.py). */
#include "cli.h"

#include <errno.h>

#include "platform.h"

/* --- usage errors ------------------------------------------------------------- */

static const char USAGE[] =
    "usage: binspect [--json] [--color auto|always|never] COMMAND FILE [options]\n";

static const char HELP[] =
    "\n"
    "Reverse-engineering toolkit for Linux (ELF) and Windows (PE) programs.\n"
    "Files are never run; originals are never changed unless you ask.\n"
    "\n"
    "commands:\n"
    "  info FILE                 identity, hashes, metadata and security mitigations\n"
    "  sections FILE             section table with permissions and entropy\n"
    "  segments FILE             ELF program headers\n"
    "  imports FILE              functions imported from other libraries\n"
    "  exports FILE              functions this file offers to others\n"
    "  symbols FILE [--grep TEXT]\n"
    "                            named addresses kept in the file\n"
    "  strings FILE [-n N] [-e all|ascii|utf16] [--grep TEXT] [--tagged]\n"
    "                            printable text found in the file; --tagged keeps\n"
    "                            only URLs, IP addresses, e-mails, paths and\n"
    "                            registry keys\n"
    "  functions FILE [--grep TEXT]\n"
    "                            functions found in the code\n"
    "  disasm FILE [LOCATION] [-n COUNT]\n"
    "                            disassemble a function or address range\n"
    "  xrefs FILE TARGET | --string TEXT\n"
    "                            find the code that uses an address, function or\n"
    "                            string\n"
    "  hexdump FILE [LOCATION] [--offset N] [-n BYTES]\n"
    "                            raw bytes at an address or file offset\n"
    "  layout FILE               the file as consecutive regions\n"
    "  report FILE               everything at a glance\n"
    "  patch bytes FILE LOCATION HEX [--offset] (-o OUT | --in-place)\n"
    "  patch nop FILE LOCATION BYTES [--offset] (-o OUT | --in-place)\n"
    "  patch string FILE OLD NEW [-e ascii|utf16] (-o OUT | --in-place)\n"
    "                            overwrite bytes, instructions or text; --in-place\n"
    "                            keeps the original as FILE.bak\n"
    "\n"
    "LOCATION and TARGET are a 0x address, a function, symbol or import name\n"
    "(optionally library!name), or 'entry'.\n"
    "\n"
    "options:\n"
    "  --json                    machine-readable JSON output\n"
    "  --color auto|always|never colour the output (default: only on a terminal)\n"
    "  --version                 show the version and exit\n"
    "  -h, --help                show this help and exit\n"
    "\n"
    "--grep TEXT keeps the entries that contain TEXT exactly as written\n"
    "(case-sensitive); it is not a regular expression.\n"
    "\n"
    "Giving just a file (or dropping one on the program) is the same as\n"
    "`binspect report FILE`.\n";

NORETURN void cli_usage_error(Session *s, const char *fmt, ...) {
    va_list args;
    char text[1024];
    va_start(args, fmt);
    vsnprintf(text, sizeof text, fmt, args);
    va_end(args);
    err_throw(s->err, ERR_USAGE, "%s", text);
}

/* --- reading files ------------------------------------------------------------ */

const uint8_t *cli_read_file(Session *s, const char *path, uint64_t *size) {
    FILE *f = platform_fopen(path, "rb");
    if (f == NULL)
        err_throw(s->err, ERR_OS, "cannot read %s: %s", path, strerror(errno));
    size_t cap = 1 << 16, used = 0;
    uint8_t *data = malloc(cap);
    if (data == NULL)
        die_out_of_memory();
    for (;;) {
        size_t got = fread(data + used, 1, cap - used, f);
        used += got;
        if (used < cap)
            break;
        if (cap > SIZE_MAX / 2)
            die_out_of_memory();
        cap *= 2;
        uint8_t *grown = realloc(data, cap);
        if (grown == NULL)
            die_out_of_memory();
        data = grown;
    }
    if (ferror(f)) {
        int code = errno;
        fclose(f);
        free(data);
        err_throw(s->err, ERR_OS, "cannot read %s: %s", path, strerror(code));
    }
    fclose(f);
    arena_adopt(s->a, data);
    *size = used;
    return data;
}

Binary *cli_load(Session *s, const char *path) {
    uint64_t size;
    const uint8_t *data = cli_read_file(s, path, &size);
    return binary_load(s->a, s->err, data, size, path);
}

/* --- output ------------------------------------------------------------------- */

void cli_emit(Session *s, const JVal *data, Renderer render) {
    if (s->json) {
        j_dump(stdout, data, 0);
        fputc('\n', stdout);
    } else {
        Lines lines = {0};
        render(s->a, &s->style, data, &lines);
        lines_print(stdout, &lines);
    }
}

/* --- option access ------------------------------------------------------------ */

const char *cli_option(const Session *s, const char *name) {
    for (size_t i = 0; i < s->command->noptions; i++)
        if (strcmp(s->command->options[i].name, name) == 0)
            return s->option_seen[i] ? s->option_value[i] : NULL;
    return NULL;
}

bool cli_flag(const Session *s, const char *name) {
    for (size_t i = 0; i < s->command->noptions; i++)
        if (strcmp(s->command->options[i].name, name) == 0)
            return s->option_seen[i];
    return false;
}

/* An integer option; `any_base` accepts 0x.. like Python's int(text, 0). */
bool cli_int_option(Session *s, const char *name, const char *display, bool any_base,
                    big *out) {
    const char *text = cli_option(s, name);
    if (text == NULL)
        return false;
    if (!parse_int(text, any_base, out))
        cli_usage_error(s, "argument %s: invalid int value: '%s'", display, text);
    return true;
}

const char *cli_choice(Session *s, const char *name, const char *display, const char *fallback,
                       const char *const *choices, size_t count) {
    const char *text = cli_option(s, name);
    if (text == NULL)
        return fallback;
    for (size_t i = 0; i < count; i++)
        if (strcmp(text, choices[i]) == 0)
            return text;
    Buf list;
    buf_init(&list, s->a);
    for (size_t i = 0; i < count; i++)
        buf_printf(&list, "%s'%s'", i ? ", " : "", choices[i]);
    cli_usage_error(s, "argument %s: invalid choice: '%s' (choose from %s)", display, text,
                    buf_str(&list).p);
}

/* --- read-only commands ------------------------------------------------------- */

static void cmd_info(Session *s) {
    cli_emit(s, view_info(s->a, cli_load(s, s->positional[0])), render_info);
}

static void cmd_sections(Session *s) {
    cli_emit(s, view_sections(s->a, cli_load(s, s->positional[0])), render_sections);
}

static void cmd_segments(Session *s) {
    cli_emit(s, view_segments(s->a, cli_load(s, s->positional[0])), render_segments);
}

static void cmd_imports(Session *s) {
    cli_emit(s, view_imports(s->a, cli_load(s, s->positional[0])), render_imports);
}

static void cmd_exports(Session *s) {
    cli_emit(s, view_exports(s->a, cli_load(s, s->positional[0])), render_exports);
}

static void cmd_layout(Session *s) {
    cli_emit(s, view_layout(s->a, cli_load(s, s->positional[0])), render_layout);
}

static void cmd_symbols(Session *s) {
    const Binary *b = cli_load(s, s->positional[0]);
    cli_emit(s, view_symbols(s->a, b, cli_option(s, "grep")), render_symbols);
}

/* Strings are written one at a time: a large file holds millions of them. */
static void cmd_strings(Session *s) {
    static const char *const encodings[] = {"all", "ascii", "utf16"};
    big min_length = 4;
    cli_int_option(s, "min", "-n/--min", false, &min_length);
    const char *encoding = cli_choice(s, "encoding", "-e/--encoding", "all", encodings, 3);
    Str needle = str_c(cli_option(s, "grep") ? cli_option(s, "grep") : "");
    bool tagged = cli_flag(s, "tagged");
    const Binary *b = cli_load(s, s->positional[0]);

    StringScan scan;
    FoundString found;
    size_t printed = 0;
    strings_begin(&scan, b, s->a, min_length, encoding);
    for (;;) {
        arena_release(&s->scratch);
        if (!strings_next(&scan, &s->scratch, &found))
            break;
        if (!str_contains(found.text, needle) || (tagged && !found.tags))
            continue;
        const JVal *row = view_string(&s->scratch, &found);
        if (s->json) {
            fputs(printed ? ",\n  " : "[\n  ", stdout);
            j_dump(stdout, row, 1);
        } else {
            Str line = render_string_row(&s->scratch, &s->style, row);
            fwrite(line.p, 1, line.n, stdout);
            fputc('\n', stdout);
        }
        printed++;
    }
    if (s->json)
        fputs(printed ? "\n]\n" : "[]\n", stdout);
    else if (!printed)
        fputs("(no strings)\n", stdout);
}

static void cmd_functions(Session *s) {
    const Binary *b = cli_load(s, s->positional[0]);
    Analysis *an = analysis_new(s->a, b);
    cli_emit(s, view_functions(s->a, an, cli_option(s, "grep")), render_functions);
}

static void cmd_disasm(Session *s) {
    big count;
    bool has_count = cli_int_option(s, "count", "-n/--count", false, &count);
    const Binary *b = cli_load(s, s->positional[0]);
    Analysis *an = analysis_new(s->a, b);
    const char *location = s->npositional > 1 ? s->positional[1] : NULL;
    cli_emit(s, view_disassembly(s->a, an, location, has_count ? &count : NULL),
             render_disassembly);
}

static void cmd_xrefs(Session *s) {
    const Binary *b = cli_load(s, s->positional[0]);
    Analysis *an = analysis_new(s->a, b);
    const char *target = s->npositional > 1 ? s->positional[1] : NULL;
    cli_emit(s, view_xrefs(s->a, an, target, cli_option(s, "string")), render_xrefs);
}

static void cmd_hexdump(Session *s) {
    big offset, length = 256, address;
    bool has_offset = cli_int_option(s, "offset", "--offset", true, &offset);
    cli_int_option(s, "length", "-n/--length", true, &length);
    const Binary *b = cli_load(s, s->positional[0]);
    bool has_address = false;
    if (s->npositional > 1 && !has_offset) {
        has_address = true;
        if (!parse_int(s->positional[1], true, &address)) {
            AddressList found = {0};
            analysis_resolve(analysis_new(s->a, b), s->positional[1], &found);
            address = found.v[0];
        }
    }
    cli_emit(s, view_hexdump(s->a, b, has_address ? &address : NULL,
                             has_offset ? &offset : NULL, length), render_hexdump);
}

typedef struct {
    Session *s;
    const Binary *b;
    JVal *functions;
} FunctionsJob;

static void find_functions(void *arg) {
    FunctionsJob *job = arg;
    job->functions = view_functions(job->s->a, analysis_new(job->s->a, job->b), NULL);
}

static void cmd_report(Session *s) {
    Arena *a = s->a;
    const Binary *b = cli_load(s, s->positional[0]);
    JVal *d = j_dict(a);
    j_set(a, d, "info", view_info(a, b));
    j_set(a, d, "sections", view_sections(a, b));
    j_set(a, d, "imports", view_imports(a, b));
    j_set(a, d, "exports", view_exports(a, b));
    j_set(a, d, "strings", view_strings(a, b, 4, "all", NULL, true));
    FunctionsJob job = {s, b, NULL};
    if (err_protect(s->err, find_functions, &job)) {
        j_set(a, d, "functions", job.functions);
    } else if (s->err->kind == ERR_NO_DISASSEMBLER || s->err->kind == ERR_UNSUPPORTED) {
        j_set(a, d, "functions", j_null(a));
        j_set(a, d, "functions_error", j_str(a, str_copy(a, s->err->msg, strlen(s->err->msg))));
    } else {
        err_raise(s->err);
    }
    cli_emit(s, d, render_report);
}

/* --- command table ------------------------------------------------------------ */

static const OptSpec GREP_OPTION[] = {{"grep", 0, true}};
static const OptSpec STRINGS_OPTIONS[] = {
    {"min", 'n', true}, {"encoding", 'e', true}, {"grep", 0, true}, {"tagged", 0, false}};
static const OptSpec DISASM_OPTIONS[] = {{"count", 'n', true}};
static const OptSpec XREFS_OPTIONS[] = {{"string", 0, true}};
static const OptSpec HEXDUMP_OPTIONS[] = {{"offset", 0, true}, {"length", 'n', true}};
static const OptSpec PATCH_OPTIONS[] = {
    {"offset", 0, false}, {"output", 'o', true}, {"in-place", 0, false}};
static const OptSpec PATCH_STRING_OPTIONS[] = {
    {"encoding", 'e', true}, {"output", 'o', true}, {"in-place", 0, false}};

static const Command COMMANDS[] = {
    {"info", NULL, 1, 1, "FILE", NULL, 0, cmd_info},
    {"sections", NULL, 1, 1, "FILE", NULL, 0, cmd_sections},
    {"segments", NULL, 1, 1, "FILE", NULL, 0, cmd_segments},
    {"imports", NULL, 1, 1, "FILE", NULL, 0, cmd_imports},
    {"exports", NULL, 1, 1, "FILE", NULL, 0, cmd_exports},
    {"symbols", NULL, 1, 1, "FILE", GREP_OPTION, 1, cmd_symbols},
    {"strings", NULL, 1, 1, "FILE", STRINGS_OPTIONS, 4, cmd_strings},
    {"functions", NULL, 1, 1, "FILE", GREP_OPTION, 1, cmd_functions},
    {"disasm", NULL, 1, 2, "FILE", DISASM_OPTIONS, 1, cmd_disasm},
    {"xrefs", NULL, 1, 2, "FILE", XREFS_OPTIONS, 1, cmd_xrefs},
    {"hexdump", NULL, 1, 2, "FILE", HEXDUMP_OPTIONS, 2, cmd_hexdump},
    {"layout", NULL, 1, 1, "FILE", NULL, 0, cmd_layout},
    {"report", NULL, 1, 1, "FILE", NULL, 0, cmd_report},
    {"patch", "bytes", 3, 3, "FILE, LOCATION, HEX", PATCH_OPTIONS, 3, cmd_patch},
    {"patch", "nop", 3, 3, "FILE, LOCATION, BYTES", PATCH_OPTIONS, 3, cmd_patch},
    {"patch", "string", 3, 3, "FILE, OLD, NEW", PATCH_STRING_OPTIONS, 3, cmd_patch},
};

/* Commands of the Python version that the native program does not have. */
static const char *const PYTHON_ONLY[] = {"engine", "assets", "resources", "gui"};

static const Command *find_command(const char *name, const char *action) {
    for (size_t i = 0; i < ARRAY_LEN(COMMANDS); i++) {
        const Command *c = &COMMANDS[i];
        if (strcmp(c->name, name) != 0)
            continue;
        if (c->action == NULL || (action != NULL && strcmp(c->action, action) == 0))
            return c;
    }
    return NULL;
}

/* --- argument parsing --------------------------------------------------------- */

static bool looks_like_option(const char *arg) {
    if (arg[0] != '-' || arg[1] == '\0')
        return false;
    big ignored;
    return !parse_int(arg, false, &ignored);    /* "-5" is a value, not an option */
}

typedef struct {
    Session *s;
    int argc;
    char **argv;
    int at;
} ArgCursor;

/* The value of an option: after "=", glued to a short option, or the next
 * argument. */
static const char *option_value(ArgCursor *cur, const char *display, const char *attached) {
    if (attached != NULL)
        return attached;
    if (cur->at + 1 >= cur->argc || looks_like_option(cur->argv[cur->at + 1]))
        cli_usage_error(cur->s, "argument %s: expected one argument", display);
    return cur->argv[++cur->at];
}

/* Handles one "-x"/"--name" argument: a global option, or one of the
 * command's own. Long names may be shortened to any unambiguous prefix. */
static void parse_option(ArgCursor *cur, bool *want_help) {
    Session *s = cur->s;
    const char *arg = cur->argv[cur->at];
    static const OptSpec GLOBALS[] = {
        {"json", 0, false}, {"color", 0, true}, {"version", 0, false}, {"help", 'h', false}};
    const OptSpec *own = s->command ? s->command->options : NULL;
    size_t nown = s->command ? s->command->noptions : 0;
    const OptSpec *match = NULL;
    bool is_global = false;
    const char *attached = NULL;

    if (arg[1] == '-') {
        const char *name = arg + 2;
        const char *eq = strchr(name, '=');
        size_t len = eq ? (size_t)(eq - name) : strlen(name);
        attached = eq ? eq + 1 : NULL;
        size_t candidates = 0;
        for (size_t pass = 0; pass < 2; pass++) {
            const OptSpec *table = pass ? GLOBALS : own;
            size_t count = pass ? ARRAY_LEN(GLOBALS) : nown;
            for (size_t i = 0; i < count; i++) {
                if (len == 0 || strncmp(table[i].name, name, len) != 0)
                    continue;
                bool exact = table[i].name[len] == '\0';
                if (exact) {
                    match = &table[i];
                    is_global = pass == 1;
                    candidates = 1;
                    goto found;
                }
                match = &table[i];
                is_global = pass == 1;
                candidates++;
            }
        }
        if (candidates > 1)
            cli_usage_error(s, "ambiguous option: %.*s", (int)(len + 2), arg);
        if (candidates == 0)
            match = NULL;
    } else {
        for (size_t i = 0; i < nown && match == NULL; i++)
            if (own[i].letter == arg[1])
                match = &own[i];
        if (match == NULL && arg[1] == 'h') {
            match = &GLOBALS[3];
            is_global = true;
        }
        if (match != NULL && arg[2] != '\0') {
            if (!match->takes_value)
                cli_usage_error(s, "unrecognized arguments: %s", arg);
            attached = arg[2] == '=' ? arg + 3 : arg + 2;
        }
    }
found:
    if (match == NULL)
        cli_usage_error(s, "unrecognized arguments: %s", arg);
    char display[40];
    snprintf(display, sizeof display, "--%s", match->name);
    if (!match->takes_value && attached != NULL)
        cli_usage_error(s, "argument %s: ignored explicit argument '%s'", display, attached);
    const char *value = match->takes_value ? option_value(cur, display, attached) : NULL;
    if (is_global) {
        if (strcmp(match->name, "json") == 0) {
            s->json = true;
        } else if (strcmp(match->name, "color") == 0) {
            if (strcmp(value, "auto") != 0 && strcmp(value, "always") != 0 &&
                strcmp(value, "never") != 0)
                cli_usage_error(s, "argument --color: invalid choice: '%s' (choose from "
                                   "'auto', 'always', 'never')", value);
            s->color = value;
        } else if (strcmp(match->name, "version") == 0) {
            s->want_version = true;
        } else {
            *want_help = true;
        }
        return;
    }
    size_t index = (size_t)(match - own);
    s->option_seen[index] = true;
    s->option_value[index] = value;
}

static void parse_arguments(Session *s, int argc, char **argv, bool *want_help) {
    ArgCursor cur = {s, argc, argv, 1};
    bool options_ended = false;
    const char *pending_patch = NULL;       /* "patch" seen, action still to come */
    for (; cur.at < argc; cur.at++) {
        const char *arg = argv[cur.at];
        if (!options_ended && strcmp(arg, "--") == 0) {
            options_ended = true;
            continue;
        }
        if (!options_ended && looks_like_option(arg)) {
            parse_option(&cur, want_help);
            if (*want_help || s->want_version)
                return;
            continue;
        }
        if (s->command == NULL && pending_patch == NULL) {
            if (strcmp(arg, "patch") == 0) {
                pending_patch = arg;
                continue;
            }
            s->command = find_command(arg, NULL);
            if (s->command != NULL)
                continue;
            for (size_t i = 0; i < ARRAY_LEN(PYTHON_ONLY); i++)
                if (strcmp(PYTHON_ONLY[i], arg) == 0)
                    cli_usage_error(s, "the '%s' command is only available in the Python "
                                       "version of binspect", arg);
            if (!platform_is_file(arg))
                cli_usage_error(s, "argument COMMAND: invalid choice: '%s' (see binspect "
                                   "--help)", arg);
            /* Just a file, e.g. dropped onto the program: show the report. */
            s->command = find_command("report", NULL);
        } else if (s->command == NULL) {
            s->command = find_command("patch", arg);
            if (s->command == NULL)
                cli_usage_error(s, "argument ACTION: invalid choice: '%s' (choose from "
                                   "'bytes', 'nop', 'string')", arg);
            continue;
        }
        if (s->npositional >= (size_t)s->command->max_positional)
            cli_usage_error(s, "unrecognized arguments: %s", arg);
        s->positional[s->npositional++] = arg;
    }
    if (pending_patch != NULL && s->command == NULL)
        cli_usage_error(s, "the following arguments are required: ACTION");
    if (s->command == NULL)
        cli_usage_error(s, "the following arguments are required: COMMAND");
    if (s->npositional < (size_t)s->command->min_positional)
        cli_usage_error(s, "the following arguments are required: %s",
                        s->command->positional_names);
}

static bool use_colour(const Session *s) {
    if (strcmp(s->color, "always") == 0)
        return true;
    const char *term = getenv("TERM");
    if (strcmp(s->color, "never") == 0 || getenv("NO_COLOR") != NULL ||
        (term != NULL && strcmp(term, "dumb") == 0))
        return false;
    return platform_stdout_is_terminal();
}

typedef struct {
    Session *s;
    int argc;
    char **argv;
    bool help;
} Invocation;

static void run(void *arg) {
    Invocation *inv = arg;
    Session *s = inv->s;
    parse_arguments(s, inv->argc, inv->argv, &inv->help);
    if (inv->help || s->want_version)
        return;
    s->style.colour = use_colour(s) && !s->json && platform_enable_ansi();
    s->command->run(s);
}

int cli_main(int argc, char **argv) {
    Arena arena = {0};
    Err err = {0};
    Session session;
    memset(&session, 0, sizeof session);
    session.a = &arena;
    session.err = &err;
    session.color = "auto";
    Invocation inv = {&session, argc, argv, false};
    int status = 0;

    /* Large outputs are written in big pieces, not line by line. */
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    if (argc < 2) {
        fputs(USAGE, stderr);
        fputs(HELP, stderr);
        fputs("\nbinspect: error: the following arguments are required: COMMAND\n", stderr);
        status = 2;
    } else if (!err_protect(&err, run, &inv)) {
        fflush(stdout);
        if (err.kind == ERR_USAGE) {
            fputs(USAGE, stderr);
            fprintf(stderr, "binspect: error: %s\n", err.msg);
            status = 2;
        } else {
            fprintf(stderr, "binspect: error: %s\n", err.msg);
            status = 1;
        }
    } else if (inv.help) {
        fputs(USAGE, stdout);
        fputs(HELP, stdout);
    } else if (session.want_version) {
        fputs("binspect " BINSPECT_VERSION "\n", stdout);
    }
    if (fflush(stdout) != 0 && status == 0)
        status = 1;
    arena_release(&session.scratch);
    arena_release(&arena);
    err_release(&err);
    return status;
}
