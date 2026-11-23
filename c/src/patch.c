/* Modify bytes in an executable without breaking it (port of patch.py and of
 * the `patch` command in cli.py).
 *
 * Everything here overwrites bytes in place: nothing is inserted, so no
 * offset or address in the file moves and its size never changes. A patch is
 * located by file offset or by virtual address (translated with the binary's
 * own section/segment mapping), validated completely, and only then written.
 *
 * Output files are written atomically (temp file next to the destination,
 * then a rename). When a file is modified in place, the original is first
 * saved as `<file>.bak`; an existing backup is never overwritten, because it
 * is the only pristine copy. */
#include <errno.h>

#include "cli.h"
#include "platform.h"

typedef struct {
    uint64_t offset;            /* file offset that was written */
    OptAddr vaddr;              /* virtual address of that offset, if it has one */
    const uint8_t *old_bytes, *new_bytes;
    size_t size;
} PatchResult;

/* Python reports every OSError of a command as "cannot read FILE: reason",
 * also when writing the output failed; the C version says the same. */
static NORETURN void fail_os(Session *s, int code) {
    err_throw(s->err, ERR_OS, "cannot read %s: %s", s->positional[0], strerror(code));
}

/* --- writing files ------------------------------------------------------------ */

/* Save `src` as `<src>.bak` unless a backup already exists. Returns 0 or an
 * errno value. */
static int back_up(Session *s, const char *src, const uint8_t *original, size_t size) {
    Str backup = str_printf(s->a, "%s.bak", src);
    if (platform_exists(backup.p))
        return 0;
    char *tmp = platform_write_temp(s->a, backup.p, original, size, src);
    if (tmp == NULL)
        return errno;
    bool ok = platform_move_new(tmp, backup.p);     /* fails instead of overwriting */
    int code = errno;
    platform_remove(tmp);
    /* Somebody else just made a backup: keep theirs. */
    return ok || platform_exists(backup.p) ? 0 : code;
}

/* Write `data`, a modified image of the file `src` (whose current contents
 * are `original`), to `dst`. The bytes go to a temp file in the destination
 * directory, which then replaces `dst` in one step, so a crash leaves either
 * the old file or the new one, never half of each. */
static void save_copy(Session *s, const char *src, const char *dst, const uint8_t *data,
                      const uint8_t *original, size_t size) {
    bool in_place = platform_same_file(src, dst);
    if (in_place)
        dst = platform_realpath(s->a, dst);         /* replace the file, not a link to it */
    char *tmp = platform_write_temp(s->a, dst, data, size, src);
    if (tmp == NULL)
        fail_os(s, errno);
    int code = in_place ? back_up(s, src, original, size) : 0;
    if (code == 0 && !platform_replace(tmp, dst))
        code = errno;
    if (code != 0) {
        platform_remove(tmp);
        fail_os(s, code);
    }
}

/* --- locating ----------------------------------------------------------------- */

typedef struct {
    Session *s;
    const uint8_t *data;
    uint64_t size;
    const char *path;
    Binary *binary;
} LoadJob;

static void load_job(void *arg) {
    LoadJob *job = arg;
    job->binary = binary_load(job->s->a, job->s->err, job->data, job->size, job->path);
}

/* The parsed binary, or NULL when the file is not a (readable) ELF or PE:
 * such a file has no virtual addresses but can still be patched by offset. */
static Binary *try_load(Session *s, const uint8_t *data, uint64_t size, const char *path) {
    LoadJob job = {s, data, size, path, NULL};
    return err_protect(s->err, load_job, &job) ? job.binary : NULL;
}

/* Validate a patch location; returns it with the old bytes filled in. */
static PatchResult locate(Session *s, const Binary *binary, const uint8_t *data,
                          uint64_t file_size, big size, const big *offset, const big *vaddr) {
    char a[40], b[40], c[44], d[44];
    PatchResult result;
    memset(&result, 0, sizeof result);
    if (size <= 0)
        err_throw(s->err, ERR_LOCATION, "patch data is empty: there is nothing to write");
    if (vaddr != NULL) {
        uint64_t mapped, available;
        if (!binary_vaddr_to_offset(binary, *vaddr, &mapped))
            err_throw(s->err, ERR_LOCATION,
                      "address %s is not backed by bytes in the file (unmapped, or "
                      "zero-initialised memory such as .bss)", hex_big(a, *vaddr));
        binary_read(binary, *vaddr, size, &available);
        if ((big)available < size)
            err_throw(s->err, ERR_LOCATION,
                      "only %s of the %s bytes at %s are backed by the file; the patch would "
                      "run past the end of its section or segment",
                      dec_big(c, available), dec_big(d, size), hex_big(a, *vaddr));
        result.offset = mapped;
        result.vaddr.has = true;
        result.vaddr.v = *vaddr;
    } else {
        if (*offset < 0 || *offset + size > (big)file_size)
            err_throw(s->err, ERR_LOCATION,
                      "%s bytes at file offset %s do not lie inside the file (%s bytes); a "
                      "patch never changes the file size",
                      dec_big(c, size), hex_big(a, *offset), hex_big(b, (big)file_size));
        result.offset = (uint64_t)*offset;
        if (binary != NULL)
            result.vaddr.has = binary_offset_to_vaddr(binary, result.offset, &result.vaddr.v);
    }
    result.old_bytes = data + result.offset;
    result.size = (size_t)size;
    return result;
}

/* --- no-ops -------------------------------------------------------------------- */

static bool arm_code_is_little_endian(const Binary *b) {
    if (strcmp(b->endian, "big") != 0)
        return true;
    /* ARMv6+ "BE8" executables are big-endian files whose code is little-endian. */
    if (strcmp(b->format, "ELF") == 0 && b->size >= 40 && b->data[4] == 1)
        return (b->data[37] & 0x80) != 0;       /* EF_ARM_BE8 = 0x00800000 in e_flags */
    return false;
}

/* The no-op instruction for the binary's CPU, as the bytes of the image;
 * returns its length. x86 uses the one-byte 0x90; AArch64 and 32-bit ARM
 * (A32 encoding) have four-byte instructions. */
static size_t nop_unit(Session *s, const Binary *b, big length, uint8_t unit[4]) {
    char text[44];
    if (length < 0)
        err_throw(s->err, ERR_LOCATION, "cannot produce %s bytes of no-ops",
                  dec_big(text, length));
    size_t n;
    if (str_eq_c(b->arch, "x86") || str_eq_c(b->arch, "x86_64")) {
        unit[0] = 0x90;
        n = 1;
    } else if (str_eq_c(b->arch, "aarch64")) {
        memcpy(unit, "\x1f\x20\x03\xd5", 4);            /* nop (hint #0), 0xD503201F */
        n = 4;
    } else if (str_eq_c(b->arch, "arm")) {
        if (arm_code_is_little_endian(b))
            memcpy(unit, "\x00\xf0\x20\xe3", 4);        /* nop, 0xE320F000 */
        else
            memcpy(unit, "\xe3\x20\xf0\x00", 4);
        n = 4;
    } else {
        err_throw(s->err, ERR_UNSUPPORTED, "no no-op encoding known for architecture '%s'",
                  b->arch.n ? b->arch.p : "unknown");
    }
    if (length % (big)n != 0)
        err_throw(s->err, ERR_LOCATION,
                  "%s instructions are %zu bytes long; %s bytes would leave a partial "
                  "instruction", b->arch.p, n, dec_big(text, length));
    return n;
}

/* --- hex input ----------------------------------------------------------------- */

static int hex_digit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* bytes.fromhex(text.replace("0x", "").replace(",", " ")) */
static uint8_t *parse_hex(Session *s, const char *text, size_t *size) {
    size_t length = strlen(text);
    char *clean = arena_alloc(s->a, length + 1);
    size_t n = 0;
    for (size_t i = 0; i < length; i++) {
        if (text[i] == '0' && text[i + 1] == 'x') {
            i++;
            continue;
        }
        clean[n++] = text[i] == ',' ? ' ' : text[i];
    }
    uint8_t *out = arena_alloc(s->a, n / 2 + 1);
    size_t count = 0;
    for (size_t i = 0; i < n;) {
        char c = clean[i];
        if (c == ' ' || (c >= '\t' && c <= '\r')) {
            i++;
            continue;
        }
        int high = hex_digit(c), low = i + 1 < n ? hex_digit(clean[i + 1]) : -1;
        if (high < 0 || low < 0)
            err_throw(s->err, ERR_OTHER, "bytes must be hex, for example: \"90 90 eb 05\"");
        out[count++] = (uint8_t)(high << 4 | low);
        i += 2;
    }
    *size = count;
    return out;
}

/* --- text ---------------------------------------------------------------------- */

/* Next code point of a command-line argument. Bytes that are not valid UTF-8
 * come back as 0xDC80..0xDCFF, the way Python's surrogateescape reads them. */
static uint32_t next_code_point(const char *text, size_t length, size_t *at) {
    const uint8_t *p = (const uint8_t *)text + *at;
    size_t left = length - *at;
    uint8_t c = p[0];
    size_t need = c < 0x80 ? 1 : c < 0xC2 ? 0 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : c < 0xF5 ? 4 : 0;
    bool valid = need != 0 && need <= left;
    for (size_t k = 1; valid && k < need; k++)
        valid = (p[k] & 0xC0) == 0x80;
    if (valid && need == 3)
        valid = !(c == 0xE0 && p[1] < 0xA0) && !(c == 0xED && p[1] >= 0xA0);
    if (valid && need == 4)
        valid = !(c == 0xF0 && p[1] < 0x90) && !(c == 0xF4 && p[1] >= 0x90);
    if (!valid) {
        *at += 1;
        return 0xDC00 + c;
    }
    uint32_t cp = need == 1 ? c : c & (0xFFu >> (need + 1));
    for (size_t k = 1; k < need; k++)
        cp = (cp << 6) | (p[k] & 0x3F);
    *at += need;
    return cp;
}

static void add_escaped(Buf *b, uint32_t cp) {
    if (cp < 0x100)
        buf_printf(b, "\\x%02x", (unsigned)cp);
    else if (cp < 0x10000)
        buf_printf(b, "\\u%04x", (unsigned)cp);
    else
        buf_printf(b, "\\U%08x", (unsigned)cp);
}

/* Encode an argument as ASCII or UTF-16LE. On failure throws the message of
 * Python's UnicodeEncodeError. */
static uint8_t *encode_text(Session *s, const char *text, bool utf16, size_t *size) {
    size_t length = strlen(text);
    uint8_t *out = arena_alloc(s->a, length * 2 + 2);
    size_t n = 0, index = 0;
    for (size_t at = 0; at < length; index++) {
        uint32_t cp = next_code_point(text, length, &at);
        bool surrogate = cp >= 0xD800 && cp <= 0xDFFF;
        if (utf16 ? surrogate : cp >= 0x80) {
            /* The error names the whole run of characters that do not fit. */
            size_t last = index;
            uint32_t bad = cp;
            while (at < length) {
                size_t peek = at;
                uint32_t next = next_code_point(text, length, &peek);
                if (utf16 ? !(next >= 0xD800 && next <= 0xDFFF) : next < 0x80)
                    break;
                at = peek;
                last++;
            }
            Buf why;
            buf_init(&why, s->a);
            buf_printf(&why, "'%s' codec can't encode ", utf16 ? "utf-16-le" : "ascii");
            if (last == index) {
                buf_addc(&why, "character '");
                add_escaped(&why, bad);
                buf_printf(&why, "' in position %zu", index);
            } else {
                buf_printf(&why, "characters in position %zu-%zu", index, last);
            }
            buf_addc(&why, utf16 ? ": surrogates not allowed" : ": ordinal not in range(128)");
            err_throw(s->err, ERR_LOCATION, "text cannot be written as %s: %s",
                      utf16 ? "utf16" : "ascii", buf_str(&why).p);
        }
        if (!utf16) {
            out[n++] = (uint8_t)cp;
        } else if (cp < 0x10000) {
            out[n++] = (uint8_t)cp;
            out[n++] = (uint8_t)(cp >> 8);
        } else {
            uint32_t v = cp - 0x10000, high = 0xD800 + (v >> 10), low = 0xDC00 + (v & 0x3FF);
            out[n++] = (uint8_t)high;
            out[n++] = (uint8_t)(high >> 8);
            out[n++] = (uint8_t)low;
            out[n++] = (uint8_t)(low >> 8);
        }
    }
    *size = n;
    return out;
}

/* repr() of a command-line argument, for error messages. */
static Str python_repr(Arena *a, const char *text) {
    size_t length = strlen(text);
    char quote = strchr(text, '\'') != NULL && strchr(text, '"') == NULL ? '"' : '\'';
    Buf b;
    buf_init(&b, a);
    buf_addch(&b, quote);
    for (size_t at = 0; at < length;) {
        size_t start = at;
        uint32_t cp = next_code_point(text, length, &at);
        if (cp == (uint32_t)quote || cp == '\\') {
            buf_addch(&b, '\\');
            buf_addch(&b, (char)cp);
        } else if (cp == '\n') {
            buf_addc(&b, "\\n");
        } else if (cp == '\r') {
            buf_addc(&b, "\\r");
        } else if (cp == '\t') {
            buf_addc(&b, "\\t");
        } else if (cp < 0x20 || cp == 0x7F || (cp >= 0x80 && cp <= 0xA0) || cp == 0xAD ||
                   (cp >= 0xD800 && cp <= 0xDFFF) || cp == 0x2028 || cp == 0x2029) {
            add_escaped(&b, cp);
        } else {
            buf_add(&b, text + start, at - start);
        }
    }
    buf_addch(&b, quote);
    return buf_str(&b);
}

/* --- the command --------------------------------------------------------------- */

static Str hex_bytes(Arena *a, const uint8_t *bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    char *text = arena_array(a, size + 1, 3);
    size_t n = 0;
    for (size_t i = 0; i < size; i++) {
        if (i)
            text[n++] = ' ';
        text[n++] = digits[bytes[i] >> 4];
        text[n++] = digits[bytes[i] & 15];
    }
    Str s = {text, n};
    return s;
}

static JVal *patch_view(Arena *a, const char *out, const PatchResult *r) {
    JVal *d = j_dict(a);
    j_set(a, d, "out", j_cstr(a, out));
    j_set(a, d, "offset", j_int(a, r->offset));
    j_set(a, d, "address", j_opt_hex(a, r->vaddr.has, r->vaddr.v));
    j_set(a, d, "old", j_str(a, hex_bytes(a, r->old_bytes, r->size)));
    j_set(a, d, "new", j_str(a, hex_bytes(a, r->new_bytes, r->size)));
    return d;
}

/* Replace every occurrence of the text `old_text` by `new_text`, in place.
 * Shorter text is padded with NUL characters to the old length. */
static void replace_string(Session *s, const char *src, const char *out, const char *old_text,
                           const char *new_text, bool utf16, JVal *patches) {
    Arena *a = s->a;
    size_t old_size, new_size;
    const uint8_t *old_bytes = encode_text(s, old_text, utf16, &old_size);
    const uint8_t *new_encoded = encode_text(s, new_text, utf16, &new_size);
    if (old_size == 0)
        err_throw(s->err, ERR_LOCATION, "the text to replace is empty");
    if (new_size > old_size)
        err_throw(s->err, ERR_LOCATION,
                  "the new text is longer than the old one (%zu > %zu bytes): strings can "
                  "only be replaced in place by equal or shorter text, because nothing after "
                  "them may move", new_size, old_size);
    uint8_t *new_bytes = arena_alloc(a, old_size);      /* zero-filled: the padding */
    memcpy(new_bytes, new_encoded, new_size);

    uint64_t size;
    const uint8_t *original = cli_read_file(s, src, &size);
    uint8_t *image = malloc(size ? (size_t)size : 1);
    if (image == NULL)
        die_out_of_memory();
    arena_adopt(a, image);
    memcpy(image, original, (size_t)size);
    VEC(uint64_t) offsets = {0};
    for (uint64_t at = 0; at + old_size <= size;) {
        const uint8_t *hit = memchr(original + at, old_bytes[0], (size_t)(size - at - old_size) + 1);
        if (hit == NULL)
            break;
        at = (uint64_t)(hit - original);
        if (memcmp(hit, old_bytes, old_size) != 0) {
            at++;
            continue;
        }
        *VEC_PUSH(a, offsets) = at;
        memcpy(image + at, new_bytes, old_size);
        at += old_size;
    }
    if (offsets.n == 0)
        err_throw(s->err, ERR_LOCATION, "the %s text %s does not occur in the file",
                  utf16 ? "utf16" : "ascii", python_repr(a, old_text).p);
    const Binary *binary = try_load(s, original, size, src);
    for (size_t i = 0; i < offsets.n; i++) {
        PatchResult r;
        memset(&r, 0, sizeof r);
        r.offset = offsets.v[i];
        if (binary != NULL)
            r.vaddr.has = binary_offset_to_vaddr(binary, r.offset, &r.vaddr.v);
        r.old_bytes = old_bytes;
        r.new_bytes = new_bytes;
        r.size = old_size;
        j_push(a, patches, patch_view(a, out, &r));
    }
    save_copy(s, src, out, image, original, (size_t)size);
}

void cmd_patch(Session *s) {
    static const char *const encodings[] = {"ascii", "utf16"};
    Arena *a = s->a;
    const char *action = s->command->action;
    const char *file = s->positional[0];
    const char *output = cli_option(s, "output");
    bool in_place = cli_flag(s, "in-place");
    bool is_string = strcmp(action, "string") == 0, is_nop = strcmp(action, "nop") == 0;
    big length = 0;
    const char *encoding = "ascii";
    if (is_nop && !parse_int(s->positional[2], true, &length))
        cli_usage_error(s, "argument BYTES: invalid int value: '%s'", s->positional[2]);
    if (is_string)
        encoding = cli_choice(s, "encoding", "-e/--encoding", "ascii", encodings, 2);
    if ((output != NULL && output[0] != '\0') == in_place)
        err_throw(s->err, ERR_OTHER, "say where to save: -o OUT for a modified copy, or "
                                     "--in-place to change the file (a .bak backup is kept)");
    const char *out = in_place ? file : output;
    JVal *patches = j_list(a);

    if (is_string) {
        replace_string(s, file, out, s->positional[1], s->positional[2],
                       strcmp(encoding, "utf16") == 0, patches);
    } else {
        const Binary *binary = cli_load(s, file);
        const char *location = s->positional[1];
        big where;
        bool by_offset = cli_flag(s, "offset");
        if (!parse_int(location, true, &where)) {
            if (by_offset)
                err_throw(s->err, ERR_LOCATION, "%s is not a file offset",
                          python_repr(a, location).p);
            AddressList found = {0};
            analysis_resolve(analysis_new(a, binary), location, &found);
            where = found.v[0];
        }
        const uint8_t *data;
        uint8_t unit[4];
        size_t unit_size = 0, size;
        if (is_nop) {
            unit_size = nop_unit(s, binary, length, unit);
            data = NULL;
        } else {
            data = parse_hex(s, s->positional[2], &size);
            length = (big)size;
        }
        PatchResult r = locate(s, binary, binary->data, binary->size, length,
                               by_offset ? &where : NULL, by_offset ? NULL : &where);
        if (is_nop) {
            uint8_t *fill = arena_alloc(a, r.size);
            for (size_t i = 0; i < r.size; i++)
                fill[i] = unit[i % unit_size];
            data = fill;
        }
        r.new_bytes = data;
        uint8_t *image = malloc((size_t)binary->size);
        if (image == NULL)
            die_out_of_memory();
        arena_adopt(a, image);
        memcpy(image, binary->data, (size_t)binary->size);
        memcpy(image + r.offset, data, r.size);
        j_push(a, patches, patch_view(a, out, &r));
        save_copy(s, file, out, image, binary->data, (size_t)binary->size);
    }

    JVal *d = j_dict(a);
    j_set(a, d, "out", j_cstr(a, platform_abspath(a, out)));
    j_set(a, d, "patches", patches);
    j_set(a, d, "message", j_str(a, str_printf(a, "Saved %s", out)));
    cli_emit(s, d, render_done);
}
