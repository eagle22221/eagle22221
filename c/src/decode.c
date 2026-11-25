/* The decode & cipher workbench (see decode.h). Each operation follows the
 * Python function of the same name in decode.py, down to the wording of its
 * error messages; where Python leans on a library (base64, binascii, zlib,
 * urllib, the codecs) the library's behaviour is reproduced here. */
#include "decode.h"

#include "hash.h"
#include "inflate.h"
#include "pystr.h"

#define CAP DECODE_CAP
/* Decompressors produce at most this much between two looks at the cap. */
#define CHUNK ((size_t)1 << 20)
/* Solvers look at (and return) at most this much of the input. */
#define SOLVE_CAP ((size_t)1 << 16)

static const char TOO_LARGE[] = "output too large";

/* --- byte buffers --------------------------------------------------------------- */

typedef struct {
    uint8_t *p;                 /* malloc'ed */
    size_t n, cap;
} Bytes;

static void bytes_reserve(Bytes *b, size_t total) {
    if (total <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < total) {
        if (cap > SIZE_MAX / 2)
            die_out_of_memory();
        cap *= 2;
    }
    uint8_t *grown = realloc(b->p, cap);
    if (grown == NULL)
        die_out_of_memory();
    b->p = grown;
    b->cap = cap;
}

static void bytes_free(Bytes *b) {
    free(b->p);
    b->p = NULL;
    b->n = b->cap = 0;
}

static void bytes_set(Bytes *b, const uint8_t *data, size_t n) {
    bytes_reserve(b, n ? n : 1);
    if (n)
        memcpy(b->p, data, n);
    b->n = n;
}

/* --- an operation's view of its call ---------------------------------------------- */

typedef struct {
    Arena *a;
    const JVal *params;         /* J_DICT, or NULL for none */
    Str error;                  /* why the operation failed */
} Op;

static bool fail(Op *c, const char *fmt, ...) PRINTF_LIKE(2, 3);
static bool fail(Op *c, const char *fmt, ...) {
    va_list args, again;
    va_start(args, fmt);
    va_copy(again, args);
    int n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (n < 0)
        n = 0;
    char *text = arena_alloc(c->a, (size_t)n + 1);
    vsnprintf(text, (size_t)n + 1, fmt, again);
    va_end(again);
    c->error.p = text;
    c->error.n = (size_t)n;
    return false;
}

static bool fail_str(Op *c, Str message) {
    c->error = message;
    return false;
}

/* --- Python's view of a JSON value ------------------------------------------------ */

static void repr_into(Arena *a, Buf *b, const JVal *v) {
    char number[44];
    if (v == NULL) {
        buf_addc(b, "None");
        return;
    }
    switch (v->kind) {
    case J_NULL:
        buf_addc(b, "None");
        break;
    case J_BOOL:
        buf_addc(b, v->u.flag ? "True" : "False");
        break;
    case J_INT:
        buf_addc(b, dec_big(number, v->u.number));
        break;
    case J_FLOAT:
        buf_adds(b, py_repr_float(a, v->u.real));
        break;
    case J_RAW:
        if (j_raw_is_float(v))
            buf_adds(b, py_repr_float(a, j_raw_double(v)));
        else if (str_eq_c(v->u.text, "-0"))
            buf_addch(b, '0');
        else
            buf_adds(b, v->u.text);
        break;
    case J_STR:
        buf_adds(b, py_repr_str(a, v->u.text));
        break;
    case J_LIST:
        buf_addch(b, '[');
        for (size_t i = 0; i < v->u.list.n; i++) {
            if (i)
                buf_addc(b, ", ");
            repr_into(a, b, v->u.list.v[i]);
        }
        buf_addch(b, ']');
        break;
    case J_DICT:
        buf_addch(b, '{');
        for (size_t i = 0; i < v->u.dict.n; i++) {
            if (i)
                buf_addc(b, ", ");
            Str key = {v->u.dict.v[i].key, v->u.dict.v[i].key_len};
            buf_adds(b, py_repr_str(a, key));
            buf_addc(b, ": ");
            repr_into(a, b, v->u.dict.v[i].value);
        }
        buf_addch(b, '}');
        break;
    }
}

Str decode_pyrepr(Arena *a, const JVal *value) {
    Buf b;
    buf_init(&b, a);
    repr_into(a, &b, value);
    return buf_str(&b);
}

Str decode_pystr(Arena *a, const JVal *value) {
    if (value != NULL && value->kind == J_STR)
        return value->u.text;
    return decode_pyrepr(a, value);
}

/* value in (None, "") */
static bool blank(const JVal *value) {
    return value == NULL || value->kind == J_NULL ||
           (value->kind == J_STR && value->u.text.n == 0);
}

static const JVal *param(const Op *c, const char *name) {
    return j_get(c->params, name);
}

static bool has_param(const Op *c, const char *name) {
    return param(c, name) != NULL;
}

/* Is the parameter the string `text`? */
static bool param_is(const Op *c, const char *name, const char *text) {
    const JVal *v = param(c, name);
    return v != NULL && v->kind == J_STR && str_eq_c(v->u.text, text);
}

/* _as_int(value, name) */
static bool as_int(Arena *a, const JVal *value, const char *name, PyInt *out, Str *error) {
    if (value != NULL && value->kind == J_BOOL) {
        *error = str_printf(a, "%s must be a number", name);
        return false;
    }
    if (value != NULL && value->kind == J_RAW && !j_raw_is_float(value) &&
        py_int_parse(value->u.text, out))
        return true;
    if (value != NULL && value->kind == J_INT) {
        big v = value->u.number;
        out->negative = v < 0;
        ubig magnitude = v < 0 ? (ubig)0 - (ubig)v : (ubig)v;
        out->huge = magnitude >= ((ubig)1 << 62);
        out->magnitude = out->huge ? 0 : (uint64_t)magnitude;
        out->low32 = (uint32_t)(ubig)v;
        return true;
    }
    if (py_int_parse(py_strip(decode_pystr(a, value)), out))
        return true;
    *error = str_printf(a, "%s must be a number, not %s", name, decode_pyrepr(a, value).p);
    return false;
}

/* --- hex ------------------------------------------------------------------------ */

static int hex_value(uint32_t c) {
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A' + 10);
    return -1;
}

/* The next character of the text: of WTF-8 when `wide`, else one byte (the
 * bytes read as Latin-1). */
static uint32_t next_char(const char *p, size_t n, size_t *at, bool wide) {
    if (wide)
        return wtf8_next(p, n, at);
    return (uint8_t)p[(*at)++];
}

/* The next character that _parse_hex keeps: "0x" is taken out first, then
 * white space, commas and colons. False at the end. */
static bool next_hex_char(const char *p, size_t n, size_t *at, bool wide, uint32_t *out) {
    while (*at < n) {
        uint32_t c = next_char(p, n, at, wide);
        if (c == '0' && *at < n && (p[*at] == 'x' || p[*at] == 'X')) {
            *at += 1;
            continue;
        }
        if (c == ',' || c == ':' || py_isspace(c))
            continue;
        *out = c;
        return true;
    }
    return false;
}

/* _parse_hex(): lenient hex. */
static bool parse_hex(const char *p, size_t n, bool wide, Bytes *out, const char **error) {
    size_t at = 0, kept = 0;
    uint32_t c;
    while (next_hex_char(p, n, &at, wide, &c))
        kept++;
    if (kept % 2 != 0) {
        *error = "hex needs an even number of digits";
        return false;
    }
    bytes_reserve(out, kept / 2 + 1);
    out->n = 0;
    at = 0;
    while (next_hex_char(p, n, &at, wide, &c)) {
        uint32_t d = 0;
        next_hex_char(p, n, &at, wide, &d);
        int hi = hex_value(c), lo = hex_value(d);
        if (hi < 0 || lo < 0) {
            *error = "not valid hex";
            return false;
        }
        out->p[out->n++] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

/* A hex parameter as bytes. */
static bool hex_param(Op *c, const JVal *value, Bytes *out) {
    Str text = decode_pystr(c->a, value);
    const char *error = NULL;
    if (!parse_hex(text.p, text.n, true, out, &error))
        return fail(c, "%s", error);
    return true;
}

/* _key_bytes(): the `key` (hex) or `key_text` parameter. *unencodable is set
 * when key_text holds a lone surrogate (Python: UnicodeEncodeError). */
static bool key_bytes(Op *c, const char *op_name, Bytes *out, bool *unencodable) {
    *unencodable = false;
    const JVal *key = param(c, "key");
    if (!blank(key))
        return hex_param(c, key, out);
    const JVal *text = param(c, "key_text");
    if (!blank(text)) {
        Str s = decode_pystr(c->a, text);
        Str why;
        if (!py_encode_utf8(c->a, s, &why)) {
            *unencodable = true;
            return fail_str(c, why);
        }
        bytes_set(out, (const uint8_t *)s.p, s.n);
        return true;
    }
    return fail(c, "%s needs a key (key=HEX or key_text=TEXT)", op_name);
}

static const char HEX_DIGITS[] = "0123456789abcdef";

/* --- base64 --------------------------------------------------------------------- */

static bool is_b64_space(uint8_t c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

static int b64_value(uint8_t c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* _from_base64(): white space is dropped, missing padding is added, then
 * binascii.a2b_base64(strict_mode=True). */
static bool base64_decode(Op *c, const uint8_t *in, size_t n, bool url, Bytes *out) {
    size_t total = 0;
    for (size_t i = 0; i < n; i++)
        if (!is_b64_space(in[i]))
            total++;
    size_t length = total + (4 - total % 4) % 4;        /* with the padding added */
    bytes_reserve(out, length / 4 * 3 + 1);
    out->n = 0;

    size_t at = 0;                  /* next unread byte of `in` */
    unsigned quad = 0, pads = 0;
    uint8_t left = 0;
    bool padding_started = false;
    for (size_t i = 0; i < length; i++) {
        uint8_t ch = '=';
        if (i < total) {
            while (is_b64_space(in[at]))
                at++;
            ch = in[at++];
        }
        if (i == 0 && ch == '=')
            return fail(c, "invalid base64: Leading padding not allowed");
        if (ch == '=') {
            padding_started = true;
            if (quad >= 2 && quad + ++pads >= 4) {
                if (i + 1 < length)
                    return fail(c, "invalid base64: Excess data after padding");
                return true;
            }
            continue;
        }
        if (url && ch == '-')
            ch = '+';
        else if (url && ch == '_')
            ch = '/';
        int v = b64_value(ch);
        if (v < 0)
            return fail(c, "invalid base64: Only base64 data is allowed");
        if (padding_started)
            return fail(c, "invalid base64: Discontinuous padding not allowed");
        pads = 0;
        switch (quad) {
        case 0:
            quad = 1;
            left = (uint8_t)v;
            break;
        case 1:
            quad = 2;
            out->p[out->n++] = (uint8_t)(left << 2 | v >> 4);
            left = (uint8_t)(v & 0x0f);
            break;
        case 2:
            quad = 3;
            out->p[out->n++] = (uint8_t)(left << 4 | v >> 2);
            left = (uint8_t)(v & 0x03);
            break;
        default:
            quad = 0;
            out->p[out->n++] = (uint8_t)(left << 6 | v);
            left = 0;
        }
    }
    if (quad == 1)
        return fail(c, "invalid base64: Invalid base64-encoded string: number of data "
                       "characters (%zu) cannot be 1 more than a multiple of 4",
                    out->n / 3 * 4 + 1);
    if (quad != 0)
        return fail(c, "invalid base64: Incorrect padding");
    return true;
}

/* The `alphabet` parameter: 0 std, 1 url. */
static bool alphabet_param(Op *c, bool *url) {
    *url = false;
    if (!has_param(c, "alphabet") || param_is(c, "alphabet", "std"))
        return true;
    if (param_is(c, "alphabet", "url")) {
        *url = true;
        return true;
    }
    return fail(c, "alphabet must be std or url");
}

static bool op_from_base64(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    bool url;
    if (!alphabet_param(c, &url))
        return false;
    return base64_decode(c, in, n, url, out);
}

static bool op_to_base64(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    bool url;
    if (!alphabet_param(c, &url))
        return false;
    const char *digits = url
        ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups = n / 3 + (n % 3 != 0);
    if (groups > CAP / 4)
        return fail(c, "%s", TOO_LARGE);
    bytes_reserve(out, groups * 4 + 1);
    uint8_t *w = out->p;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        *w++ = (uint8_t)digits[v >> 18];
        *w++ = (uint8_t)digits[(v >> 12) & 63];
        *w++ = (uint8_t)digits[(v >> 6) & 63];
        *w++ = (uint8_t)digits[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        *w++ = (uint8_t)digits[v >> 18];
        *w++ = (uint8_t)digits[(v >> 12) & 63];
        *w++ = '=';
        *w++ = '=';
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        *w++ = (uint8_t)digits[v >> 18];
        *w++ = (uint8_t)digits[(v >> 12) & 63];
        *w++ = (uint8_t)digits[(v >> 6) & 63];
        *w++ = '=';
    }
    out->n = (size_t)(w - out->p);
    return true;
}

/* --- base32 --------------------------------------------------------------------- */

static int b32_value(uint8_t c) {
    if (c >= 'a' && c <= 'z')
        c = (uint8_t)(c - 32);          /* casefold=True */
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= '2' && c <= '7')
        return c - '2' + 26;
    return -1;
}

/* base64.b32decode(casefold=True) of the input without white space and
 * padded with "=" to a multiple of eight. */
static bool op_from_base32(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    size_t total = 0, last = 0;         /* `last`: characters up to the final non-"=" */
    for (size_t i = 0; i < n; i++) {
        if (is_b64_space(in[i]))
            continue;
        total++;
        if (in[i] != '=')
            last = total;
    }
    size_t length = total + (8 - total % 8) % 8;
    size_t padchars = length - last;
    bytes_reserve(out, last / 8 * 5 + 6);
    out->n = 0;
    size_t at = 0;
    uint64_t acc = 0;
    unsigned filled = 0;
    for (size_t i = 0; i < last; i++) {
        while (is_b64_space(in[at]))
            at++;
        int v = b32_value(in[at++]);
        if (v < 0)
            return fail(c, "invalid base32: Non-base32 digit found");
        acc = acc << 5 | (unsigned)v;
        if (++filled == 8) {
            for (int shift = 32; shift >= 0; shift -= 8)
                out->p[out->n++] = (uint8_t)(acc >> shift);
            acc = 0;
            filled = 0;
        }
    }
    if (padchars != 0 && padchars != 1 && padchars != 3 && padchars != 4 && padchars != 6)
        return fail(c, "invalid base32: Incorrect padding");
    if (padchars != 0 && filled != 0) {
        /* The last, partial group: 1 pad leaves 4 bytes, 3: 3, 4: 2, 6: 1. */
        acc <<= 5 * padchars;
        size_t keep = (43 - 5 * padchars) / 8;
        for (size_t k = 0; k < keep; k++)
            out->p[out->n++] = (uint8_t)(acc >> (32 - 8 * k));
    }
    return true;
}

static bool op_to_base32(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static const uint8_t used[5] = {0, 2, 4, 5, 7};     /* characters for 1..4 bytes */
    size_t groups = n / 5 + (n % 5 != 0);
    if (groups > CAP / 8)
        return fail(c, "%s", TOO_LARGE);
    bytes_reserve(out, groups * 8 + 1);
    uint8_t *w = out->p;
    for (size_t i = 0; i < n; i += 5) {
        size_t have = n - i < 5 ? n - i : 5;
        uint64_t v = 0;
        for (size_t k = 0; k < 5; k++)
            v = v << 8 | (k < have ? in[i + k] : 0);
        size_t chars = have == 5 ? 8 : used[have];
        for (size_t k = 0; k < 8; k++)
            *w++ = k < chars ? (uint8_t)digits[(v >> (35 - 5 * k)) & 31] : '=';
    }
    out->n = (size_t)(w - out->p);
    return true;
}

/* --- hex operations ------------------------------------------------------------- */

static bool op_from_hex(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    const char *error = NULL;
    if (!parse_hex((const char *)in, n, false, out, &error))
        return fail(c, "%s", error);
    return true;
}

static bool op_to_hex(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    if (n > CAP / 2)
        return fail(c, "%s", TOO_LARGE);
    bytes_reserve(out, n * 2 + 1);
    for (size_t i = 0; i < n; i++) {
        out->p[2 * i] = (uint8_t)HEX_DIGITS[in[i] >> 4];
        out->p[2 * i + 1] = (uint8_t)HEX_DIGITS[in[i] & 15];
    }
    out->n = n * 2;
    return true;
}

/* --- base85 --------------------------------------------------------------------- */

static const char Z85_DIGITS[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

static bool variant_param(Op *c, bool *z85) {
    *z85 = false;
    if (!has_param(c, "variant") || param_is(c, "variant", "ascii85"))
        return true;
    if (param_is(c, "variant", "z85")) {
        *z85 = true;
        return true;
    }
    return fail(c, "variant must be ascii85 or z85");
}

/* base64.a85decode(). With out == NULL only the length is worked out (and
 * every error found), so that an oversized result is never built. */
static bool a85_decode(Op *c, const uint8_t *in, size_t n, uint8_t *out, size_t *out_len) {
    size_t produced = 0;
    unsigned filled = 0;
    uint64_t acc = 0;
    for (size_t i = 0; i < n + 4; i++) {
        uint8_t x = i < n ? in[i] : 'u';        /* four "u" finish the last group */
        if (x >= '!' && x <= 'u') {
            acc = acc * 85 + (uint64_t)(x - 33);
            if (++filled == 5) {
                if (acc > 0xFFFFFFFFu)
                    return fail(c, "invalid base85: Ascii85 overflow");
                if (out != NULL)
                    for (int shift = 24; shift >= 0; shift -= 8)
                        out[produced + (size_t)(3 - shift / 8)] = (uint8_t)(acc >> shift);
                produced += 4;
                acc = 0;
                filled = 0;
            }
        } else if (x == 'z') {
            if (filled != 0)
                return fail(c, "invalid base85: z inside Ascii85 5-tuple");
            if (out != NULL)
                memset(out + produced, 0, 4);
            produced += 4;
        } else if (x == ' ' || x == '\t' || x == '\n' || x == '\r' || x == '\v') {
            continue;
        } else {
            /* "%c" of the byte: the character with that code point. */
            Buf message;
            buf_init(&message, c->a);
            buf_addc(&message, "invalid base85: Non-Ascii85 digit found: ");
            wtf8_put(&message, x);
            return fail_str(c, buf_str(&message));
        }
    }
    *out_len = produced - (4 - filled);         /* the padding is thrown away */
    return true;
}

static int z85_value(uint8_t ch) {
    const char *found = ch != '\0' ? strchr(Z85_DIGITS, ch) : NULL;
    return found != NULL ? (int)(found - Z85_DIGITS) : -1;
}

/* base64.z85decode() of the input without white space. */
static bool z85_decode(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    size_t total = 0;
    for (size_t i = 0; i < n; i++)
        if (!is_b64_space(in[i]))
            total++;
    size_t padding = (5 - total % 5) % 5;
    size_t groups = (total + padding) / 5;
    bytes_reserve(out, groups * 4 + 1);
    out->n = 0;
    size_t at = 0;
    for (size_t g = 0; g < groups; g++) {
        uint64_t acc = 0;
        for (size_t j = 0; j < 5; j++) {
            size_t position = g * 5 + j;
            int v = 84;                         /* padded with the highest digit */
            if (position < total) {
                while (is_b64_space(in[at]))
                    at++;
                v = z85_value(in[at++]);
                if (v < 0)
                    return fail(c, "invalid base85: bad z85 character at position %zu",
                                position);
            }
            acc = acc * 85 + (unsigned)v;
        }
        if (acc > 0xFFFFFFFFu)
            return fail(c, "invalid base85: z85 overflow in hunk starting at byte %zu", g * 5);
        for (int shift = 24; shift >= 0; shift -= 8)
            out->p[out->n++] = (uint8_t)(acc >> shift);
    }
    out->n -= padding;
    return true;
}

static bool op_from_base85(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    /* Python looks at the data before it looks at an unknown variant. */
    if (!has_param(c, "variant") || param_is(c, "variant", "ascii85")) {
        size_t length = 0;
        if (!a85_decode(c, in, n, NULL, &length))
            return false;
        if (length > CAP)
            return fail(c, "%s", TOO_LARGE);
        /* The decoder writes whole groups; the padding is cut afterwards. */
        bytes_reserve(out, length + 8);
        a85_decode(c, in, n, out->p, &length);
        out->n = length;
        return true;
    }
    if (param_is(c, "variant", "z85"))
        return z85_decode(c, in, n, out);
    return fail(c, "variant must be ascii85 or z85");
}

static bool op_to_base85(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    bool z85;
    if (!variant_param(c, &z85))
        return false;
    if (z85 && n % 4 != 0)
        return fail(c, "z85 needs a length that is a multiple of 4 bytes");
    size_t padding = (4 - n % 4) % 4;
    size_t words = (n + padding) / 4;
    /* First the length: a zero word is one "z" in Ascii85 (not the last,
     * padded one), every other word five characters. */
    size_t length = 0;
    for (size_t w = 0; w < words; w++) {
        bool zero = !z85 && w * 4 + 4 <= n && in[w * 4] == 0 && in[w * 4 + 1] == 0 &&
                    in[w * 4 + 2] == 0 && in[w * 4 + 3] == 0;
        length += zero ? 1 : 5;
    }
    length -= padding;
    if (length > CAP)
        return fail(c, "%s", TOO_LARGE);
    bytes_reserve(out, length + 8);
    uint8_t *w = out->p;
    for (size_t k = 0; k < words; k++) {
        uint32_t word = 0;
        for (size_t j = 0; j < 4; j++)
            word = word << 8 | (k * 4 + j < n ? in[k * 4 + j] : 0);
        if (!z85 && word == 0 && k * 4 + 4 <= n) {
            *w++ = 'z';
            continue;
        }
        for (int j = 4; j >= 0; j--) {
            uint32_t digit = word % 85;
            word /= 85;
            w[j] = z85 ? (uint8_t)Z85_DIGITS[digit] : (uint8_t)(33 + digit);
        }
        w += 5;
    }
    out->n = length;
    return true;
}

/* --- percent-encoding and quoted-printable ---------------------------------------- */

/* urllib.parse.unquote_to_bytes() */
static bool op_url_decode(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    (void)c;
    bytes_reserve(out, n + 1);
    size_t w = 0;
    for (size_t i = 0; i < n;) {
        if (in[i] == '%' && n - i >= 3 && hex_value(in[i + 1]) >= 0 && hex_value(in[i + 2]) >= 0) {
            out->p[w++] = (uint8_t)(hex_value(in[i + 1]) << 4 | hex_value(in[i + 2]));
            i += 3;
        } else {
            out->p[w++] = in[i++];
        }
    }
    out->n = w;
    return true;
}

static bool url_safe(uint8_t ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
           ch == '_' || ch == '.' || ch == '-' || ch == '~';
}

/* urllib.parse.quote_from_bytes(safe=b"") */
static bool op_url_encode(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    static const char upper[] = "0123456789ABCDEF";
    size_t length = 0;
    for (size_t i = 0; i < n; i++)
        length += url_safe(in[i]) ? 1 : 3;
    if (length > CAP)
        return fail(c, "%s", TOO_LARGE);
    bytes_reserve(out, length + 1);
    uint8_t *w = out->p;
    for (size_t i = 0; i < n; i++) {
        if (url_safe(in[i])) {
            *w++ = in[i];
        } else {
            *w++ = '%';
            *w++ = (uint8_t)upper[in[i] >> 4];
            *w++ = (uint8_t)upper[in[i] & 15];
        }
    }
    out->n = length;
    return true;
}

/* binascii.a2b_qp(), which quopri.decodestring() uses */
static bool op_qp_decode(Op *c, const uint8_t *data, size_t n, Bytes *out) {
    (void)c;
    bytes_reserve(out, n + 1);
    size_t in = 0, w = 0;
    while (in < n) {
        if (data[in] != '=') {
            out->p[w++] = data[in++];
            continue;
        }
        in++;
        if (in >= n)
            break;
        if (data[in] == '\n' || data[in] == '\r') {     /* a soft line break */
            if (data[in] != '\n')
                while (in < n && data[in] != '\n')
                    in++;
            if (in < n)
                in++;
        } else if (data[in] == '=') {
            out->p[w++] = '=';
            in++;
        } else if (in + 1 < n && hex_value(data[in]) >= 0 && hex_value(data[in + 1]) >= 0) {
            out->p[w++] = (uint8_t)(hex_value(data[in]) << 4 | hex_value(data[in + 1]));
            in += 2;
        } else {
            out->p[w++] = '=';
        }
    }
    out->n = w;
    return true;
}

/* --- letters -------------------------------------------------------------------- */

static bool is_upper(uint8_t ch) {
    return ch >= 'A' && ch <= 'Z';
}

static bool is_lower(uint8_t ch) {
    return ch >= 'a' && ch <= 'z';
}

static void rotate(const uint8_t *in, size_t n, unsigned shift, uint8_t *out) {
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = in[i];
        if (is_upper(ch))
            ch = (uint8_t)((ch - 'A' + shift) % 26 + 'A');
        else if (is_lower(ch))
            ch = (uint8_t)((ch - 'a' + shift) % 26 + 'a');
        out[i] = ch;
    }
}

static bool op_rot13(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    (void)c;
    bytes_reserve(out, n + 1);
    rotate(in, n, 13, out->p);
    out->n = n;
    return true;
}

static bool op_reverse(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    (void)c;
    bytes_reserve(out, n + 1);
    for (size_t i = 0; i < n; i++)
        out->p[i] = in[n - 1 - i];
    out->n = n;
    return true;
}

static bool op_rot_n(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    PyInt shift = {false, false, 13, 13};
    if (has_param(c, "n") && !as_int(c->a, param(c, "n"), "n", &shift, &c->error))
        return false;
    if (!py_int_between(&shift, 0, 25))
        return fail(c, "n must be between 0 and 25");
    bytes_reserve(out, n + 1);
    rotate(in, n, (unsigned)shift.magnitude, out->p);
    out->n = n;
    return true;
}

static bool op_atbash(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    (void)c;
    bytes_reserve(out, n + 1);
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = in[i];
        if (is_upper(ch))
            ch = (uint8_t)('Z' - (ch - 'A'));
        else if (is_lower(ch))
            ch = (uint8_t)('z' - (ch - 'a'));
        out->p[i] = ch;
    }
    out->n = n;
    return true;
}

/* The `mode` parameter: decrypt (the default) or encrypt. */
static bool mode_param(Op *c, bool *encrypt) {
    *encrypt = false;
    if (!has_param(c, "mode") || param_is(c, "mode", "decrypt"))
        return true;
    if (param_is(c, "mode", "encrypt")) {
        *encrypt = true;
        return true;
    }
    return fail(c, "mode must be decrypt or encrypt");
}

static bool op_vigenere(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    bool encrypt;
    if (!mode_param(c, &encrypt))
        return false;
    /* One shift per letter of the key: ord(letter.upper()) - 65. Python
     * takes every Unicode letter, so does this. */
    Str key = decode_pystr(c->a, param(c, "key"));
    uint8_t *shifts = arena_alloc(c->a, key.n + 1);
    size_t count = 0;
    for (size_t i = 0; i < key.n;) {
        uint32_t cp = wtf8_next(key.p, key.n, &i);
        if (!py_isalpha(cp))
            continue;
        uint32_t upper[3];
        if (py_upper(cp, upper) != 1)
            /* "ß".upper() is "SS": Python stops with a TypeError here. */
            return fail(c, "vigenere needs a key of letters");
        shifts[count++] = (uint8_t)((upper[0] + 26 * 3 - 65) % 26);
    }
    if (count == 0)
        return fail(c, "vigenere needs a key of letters");
    bytes_reserve(out, n + 1);
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = in[i];
        if (is_upper(ch) || is_lower(ch)) {
            unsigned base = is_upper(ch) ? 'A' : 'a';
            unsigned shift = shifts[j++ % count];
            ch = (uint8_t)((ch - base + (encrypt ? shift : 26 - shift)) % 26 + base);
        }
        out->p[i] = ch;
    }
    out->n = n;
    return true;
}

static void xor_with(const uint8_t *in, size_t n, const uint8_t *key, size_t key_len,
                     uint8_t *out) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        out[i] = in[i] ^ key[k];
        if (++k == key_len)
            k = 0;
    }
}

static bool op_xor(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    Bytes key = {0};
    bool unencodable;
    if (!key_bytes(c, "xor", &key, &unencodable)) {
        bytes_free(&key);
        return false;
    }
    if (key.n == 0) {
        bytes_free(&key);
        return fail(c, "xor needs a non-empty key");
    }
    bytes_reserve(out, n + 1);
    xor_with(in, n, key.p, key.n, out->p);
    out->n = n;
    bytes_free(&key);
    return true;
}

static bool op_railfence(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    PyInt rails;
    if (!as_int(c->a, param(c, "rails"), "rails", &rails, &c->error))
        return false;
    if (rails.negative || (!rails.huge && rails.magnitude < 2))
        return fail(c, "rails must be at least 2");
    bool encrypt;
    if (!mode_param(c, &encrypt))
        return false;
    bytes_reserve(out, n + 1);
    out->n = n;
    if (rails.huge || rails.magnitude >= n) {
        /* Every byte has a rail to itself: the zig-zag never turns. */
        if (n)
            memcpy(out->p, in, n);
        return true;
    }
    /* The bytes of rail r are those at r, period - r, period + r, ... The
     * cipher text is rail 0, then rail 1, and so on. */
    size_t count = (size_t)rails.magnitude, period = 2 * (count - 1), j = 0;
    for (size_t r = 0; r < count; r++) {
        bool edge = r == 0 || r == count - 1;
        for (size_t base = 0; base < n; base += period) {
            size_t down = base + r, up = base + period - r;
            if (down < n) {
                if (encrypt)
                    out->p[j] = in[down];
                else
                    out->p[down] = in[j];
                j++;
            }
            if (!edge && up < n) {
                if (encrypt)
                    out->p[j] = in[up];
                else
                    out->p[up] = in[j];
                j++;
            }
        }
    }
    return true;
}

typedef struct {
    size_t n;
    uint32_t cp[3];
} UpperForm;

static const char BAD_MAP[] = "map must be a 26-letter permutation of the alphabet";

static bool op_substitution(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    /* The letters of the map, upper-cased, in order: plain letter i is
     * written as the i-th. Python accepts any 26 different letters. */
    Str map = decode_pystr(c->a, param(c, "map"));
    UpperForm cipher[26];
    size_t count = 0;
    for (size_t i = 0; i < map.n;) {
        uint32_t cp = wtf8_next(map.p, map.n, &i);
        if (!py_isalpha(cp))
            continue;
        if (count == 26)
            return fail(c, "%s", BAD_MAP);
        memset(&cipher[count], 0, sizeof cipher[count]);
        cipher[count].n = py_upper(cp, cipher[count].cp);
        count++;
    }
    if (count != 26)
        return fail(c, "%s", BAD_MAP);
    int plain[26];
    for (int i = 0; i < 26; i++)
        plain[i] = -1;
    for (size_t i = 0; i < 26; i++) {
        for (size_t k = 0; k < i; k++)
            if (cipher[i].n == cipher[k].n &&
                memcmp(cipher[i].cp, cipher[k].cp, sizeof cipher[i].cp) == 0)
                return fail(c, "%s", BAD_MAP);
        if (cipher[i].n == 1 && cipher[i].cp[0] >= 'A' && cipher[i].cp[0] <= 'Z')
            plain[cipher[i].cp[0] - 'A'] = (int)i;
    }
    bytes_reserve(out, n + 1);
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = in[i];
        if (is_upper(ch) || is_lower(ch)) {
            uint8_t base = is_upper(ch) ? 'A' : 'a';
            int index = plain[ch - base];
            if (index < 0)
                /* A map of 26 letters that are not A to Z: Python stops
                 * with a KeyError at the first letter it cannot look up. */
                return fail(c, "%s", BAD_MAP);
            ch = (uint8_t)(base + index);
        }
        out->p[i] = ch;
    }
    out->n = n;
    return true;
}

/* --- charset-decode --------------------------------------------------------------- */

typedef struct {
    size_t start, end;          /* the bytes that cannot be decoded */
    const char *reason;
} CodecError;

static bool is_continuation(uint8_t ch) {
    return (ch & 0xC0) == 0x80;
}

/* The first place where bytes.decode("utf-8") fails, as CPython reports it. */
static bool utf8_check(const uint8_t *p, size_t n, CodecError *e) {
    static const char continuation[] = "invalid continuation byte";
    size_t i = 0;
    while (i < n) {
        uint8_t ch = p[i];
        size_t left = n - i, bad = 0;
        if (ch < 0x80) {
            i++;
            continue;
        }
        e->start = i;
        e->reason = continuation;
        if (ch < 0xC2 || ch > 0xF4) {
            e->end = i + 1;
            e->reason = "invalid start byte";
            return false;
        }
        if (ch < 0xE0) {
            if (left < 2)
                goto truncated;
            if (!is_continuation(p[i + 1]))
                bad = 1;
            else
                i += 2;
        } else if (ch < 0xF0) {
            if (left < 2)
                goto truncated;
            uint8_t c2 = p[i + 1];
            if (!is_continuation(c2) || (c2 < 0xA0 ? ch == 0xE0 : ch == 0xED))
                bad = 1;
            else if (left < 3)
                goto truncated;
            else if (!is_continuation(p[i + 2]))
                bad = 2;
            else
                i += 3;
        } else {
            if (left < 2)
                goto truncated;
            uint8_t c2 = p[i + 1];
            if (!is_continuation(c2) || (c2 < 0x90 ? ch == 0xF0 : ch == 0xF4))
                bad = 1;
            else if (left < 3)
                goto truncated;
            else if (!is_continuation(p[i + 2]))
                bad = 2;
            else if (left < 4)
                goto truncated;
            else if (!is_continuation(p[i + 3]))
                bad = 3;
            else
                i += 4;
        }
        if (bad) {
            e->end = e->start + bad;
            return false;
        }
    }
    return true;
truncated:
    e->end = n;
    e->reason = "unexpected end of data";
    return false;
}

static unsigned utf16_unit(const uint8_t *p, bool big_endian) {
    return big_endian ? (unsigned)p[0] << 8 | p[1] : (unsigned)p[1] << 8 | p[0];
}

static size_t utf8_size(uint32_t cp) {
    return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
}

static uint8_t *utf8_write(uint8_t *w, uint32_t cp) {
    if (cp < 0x80) {
        *w++ = (uint8_t)cp;
    } else if (cp < 0x800) {
        *w++ = (uint8_t)(0xC0 | cp >> 6);
        *w++ = (uint8_t)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        *w++ = (uint8_t)(0xE0 | cp >> 12);
        *w++ = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        *w++ = (uint8_t)(0x80 | (cp & 0x3F));
    } else {
        *w++ = (uint8_t)(0xF0 | cp >> 18);
        *w++ = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
        *w++ = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        *w++ = (uint8_t)(0x80 | (cp & 0x3F));
    }
    return w;
}

/* bytes.decode("utf-16-le" / "utf-16-be").encode("utf-8"). With out == NULL
 * only the length of the result is worked out, and the first error found. */
static bool utf16_to_utf8(const uint8_t *p, size_t n, bool big_endian, uint8_t *out,
                          size_t *out_len, CodecError *e) {
    size_t length = 0, i = 0;
    uint8_t *w = out;
    while (n - i >= 2) {
        uint32_t cp = utf16_unit(p + i, big_endian);
        if (cp >= 0xD800 && cp <= 0xDFFF) {
            e->start = i;
            e->end = i + 2;
            if (cp >= 0xDC00) {
                e->reason = "illegal encoding";
                return false;
            }
            if (n - i < 4) {
                e->end = n;
                e->reason = "unexpected end of data";
                return false;
            }
            unsigned low = utf16_unit(p + i + 2, big_endian);
            if (low < 0xDC00 || low > 0xDFFF) {
                e->reason = "illegal UTF-16 surrogate";
                return false;
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            i += 2;
        }
        i += 2;
        length += utf8_size(cp);
        if (w != NULL)
            w = utf8_write(w, cp);
    }
    if (i < n) {
        e->start = i;
        e->end = n;
        e->reason = "truncated data";
        return false;
    }
    *out_len = length;
    return true;
}

static bool codec_fail(Op *c, const char *name, const char *codec, const uint8_t *in,
                       const CodecError *e) {
    if (e->end == e->start + 1)
        return fail(c, "cannot read bytes as %s: '%s' codec can't decode byte 0x%02x in "
                       "position %zu: %s", name, codec, in[e->start], e->start, e->reason);
    return fail(c, "cannot read bytes as %s: '%s' codec can't decode bytes in position "
                   "%zu-%zu: %s", name, codec, e->start, e->end - 1, e->reason);
}

static bool op_charset_decode(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    CodecError e = {0, 0, ""};
    if (!has_param(c, "from") || param_is(c, "from", "utf-8")) {
        if (!utf8_check(in, n, &e))
            return codec_fail(c, "utf-8", "utf-8", in, &e);
        bytes_set(out, in, n);
        return true;
    }
    if (param_is(c, "from", "utf-16le") || param_is(c, "from", "utf-16be")) {
        bool big_endian = param_is(c, "from", "utf-16be");
        size_t length = 0;
        if (!utf16_to_utf8(in, n, big_endian, NULL, &length, &e))
            return codec_fail(c, big_endian ? "utf-16be" : "utf-16le",
                              big_endian ? "utf-16-be" : "utf-16-le", in, &e);
        if (length > CAP)
            return fail(c, "%s", TOO_LARGE);
        bytes_reserve(out, length + 1);
        utf16_to_utf8(in, n, big_endian, out->p, &length, &e);
        out->n = length;
        return true;
    }
    if (param_is(c, "from", "latin-1")) {
        size_t length = n;
        for (size_t i = 0; i < n; i++)
            length += in[i] >= 0x80;
        if (length > CAP)
            return fail(c, "%s", TOO_LARGE);
        bytes_reserve(out, length + 1);
        uint8_t *w = out->p;
        for (size_t i = 0; i < n; i++)
            w = utf8_write(w, in[i]);
        out->n = length;
        return true;
    }
    return fail(c, "from must be utf-8, utf-16le, utf-16be or latin-1");
}

/* --- decompress ------------------------------------------------------------------- */

static uint32_t adler32(uint32_t adler, const uint8_t *data, size_t n) {
    uint32_t a = adler & 0xffff, b = adler >> 16;
    while (n > 0) {
        size_t run = n < 5552 ? n : 5552;       /* the sums cannot overflow before this */
        for (size_t i = 0; i < run; i++) {
            a += data[i];
            b += a;
        }
        a %= 65521;
        b %= 65521;
        data += run;
        n -= run;
    }
    return b << 16 | a;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

typedef enum { RAW_DEFLATE, ZLIB_STREAM, GZIP_STREAM } Wrapper;

static bool zlib_fail(Op *c, const char *message) {
    return fail(c, "not valid compressed data: Error -3 while decompressing data: %s", message);
}

/* The header in front of the DEFLATE data, read the way zlib's inflate()
 * reads it. *at receives its length. *waiting is set when the input ends
 * inside the header: zlib then waits for more, which is not an error. */
static bool read_header(Op *c, Wrapper wrapper, const uint8_t *in, size_t n, size_t *at,
                        bool *waiting) {
    *at = 0;
    *waiting = true;
    if (wrapper == RAW_DEFLATE) {
        *waiting = false;
        return true;
    }
    if (n < 2)
        return true;
    if (wrapper == ZLIB_STREAM) {
        unsigned cmf = in[0], flags = in[1];
        if (((cmf << 8) + flags) % 31 != 0)
            return zlib_fail(c, "incorrect header check");
        if ((cmf & 15) != 8)
            return zlib_fail(c, "unknown compression method");
        if ((cmf >> 4) + 8 > 15)
            return zlib_fail(c, "invalid window size");
        if (flags & 0x20) {
            /* A preset dictionary is asked for once its id has been read. */
            if (n < 6)
                return true;
            return fail(c, "not valid compressed data: Error 2 while decompressing data");
        }
        *at = 2;
        *waiting = false;
        return true;
    }
    if (in[0] != 0x1f || in[1] != 0x8b)
        return zlib_fail(c, "incorrect header check");
    if (n < 4)
        return true;
    unsigned flags = in[3];
    if (in[2] != 8)
        return zlib_fail(c, "unknown compression method");
    if (flags & 0xe0)
        return zlib_fail(c, "unknown header flags set");
    size_t i = 10;                      /* magic, method, flags, time, xfl, os */
    if (n < i)
        return true;
    if (flags & 0x04) {                 /* extra field */
        if (n - i < 2)
            return true;
        size_t extra = (size_t)in[i] | (size_t)in[i + 1] << 8;
        i += 2;
        if (n - i < extra)
            return true;
        i += extra;
    }
    for (unsigned flag = 0x08; flag <= 0x10; flag <<= 1) {      /* name, comment */
        if (!(flags & flag))
            continue;
        const uint8_t *zero = memchr(in + i, 0, n - i);
        if (zero == NULL)
            return true;
        i = (size_t)(zero - in) + 1;
    }
    if (flags & 0x02) {                 /* header CRC */
        if (n - i < 2)
            return true;
        unsigned stored = (unsigned)in[i] | (unsigned)in[i + 1] << 8;
        if (stored != (bs_crc32(0, in, i) & 0xffff))
            return zlib_fail(c, "header crc mismatch");
        i += 2;
    }
    *at = i;
    *waiting = false;
    return true;
}

/* decode.py's _inflate(): zlib.decompressobj(wbits).decompress(data, 1 MiB)
 * again and again until nothing more comes out, with the cap looked at after
 * every piece. A stream that stops short is not an error (the object waits
 * for more input that never comes); a damaged one is, with zlib's message.
 * Whatever follows the end of the stream is ignored. */
static bool inflate_stream(Op *c, Wrapper wrapper, const uint8_t *in, size_t n, Bytes *out) {
    size_t at;
    bool waiting;
    bytes_reserve(out, 1);
    out->n = 0;
    if (!read_header(c, wrapper, in, n, &at, &waiting))
        return false;
    if (waiting)
        return true;

    BsInflate *z = malloc(sizeof *z);
    if (z == NULL)
        die_out_of_memory();
    bs_inflate_init(z);
    z->next_in = in + at;
    z->avail_in = n - at;
    uint32_t check = wrapper == GZIP_STREAM ? 0 : 1;
    enum { BODY, TRAILER, FINISHED } stage = BODY;
    bool ok = true;
    for (;;) {
        size_t produced = 0;
        if (stage == BODY) {
            bytes_reserve(out, out->n + CHUNK);
            z->next_out = out->p + out->n;
            z->avail_out = CHUNK;
            BsInflateStatus status = bs_inflate(z);
            produced = CHUNK - z->avail_out;
            if (wrapper == GZIP_STREAM)
                check = bs_crc32(check, out->p + out->n, produced);
            else if (wrapper == ZLIB_STREAM)
                check = adler32(check, out->p + out->n, produced);
            out->n += produced;
            if (status == BS_INFLATE_ERROR) {
                ok = zlib_fail(c, z->msg != NULL ? z->msg : "invalid input data");
                break;
            }
            if (status == BS_INFLATE_END) {
                /* Whole bytes read ahead (none, in practice) are not used up. */
                size_t spare = z->bits / 8;
                z->next_in -= spare;
                z->avail_in += spare;
                stage = TRAILER;
            }
        }
        if (stage == TRAILER) {
            /* The check value, and for gzip the length, as far as they are there. */
            stage = FINISHED;
            if (wrapper != RAW_DEFLATE && z->avail_in >= 4) {
                const uint8_t *t = z->next_in;
                uint32_t stored = wrapper == GZIP_STREAM
                    ? le32(t)
                    : (uint32_t)t[0] << 24 | (uint32_t)t[1] << 16 | (uint32_t)t[2] << 8 | t[3];
                if (stored != check) {
                    ok = zlib_fail(c, "incorrect data check");
                    break;
                }
                if (wrapper == GZIP_STREAM && z->avail_in >= 8 &&
                    le32(t + 4) != (uint32_t)(z->total_out & 0xffffffffu)) {
                    ok = zlib_fail(c, "incorrect length check");
                    break;
                }
            }
        }
        if (produced == 0)
            break;
        if (out->n > CAP) {
            ok = fail(c, "%s", TOO_LARGE);
            break;
        }
    }
    free(z);
    return ok;
}

static bool op_zlib_inflate(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    return inflate_stream(c, ZLIB_STREAM, in, n, out);
}

static bool op_raw_inflate(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    return inflate_stream(c, RAW_DEFLATE, in, n, out);
}

static bool op_gunzip(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    return inflate_stream(c, GZIP_STREAM, in, n, out);
}

/* --- hash ------------------------------------------------------------------------- */

static bool op_hash(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    char digest[65];
    if (param_is(c, "algo", "crc32"))
        snprintf(digest, sizeof digest, "%08x", (unsigned)bs_crc32(0, in, n));
    else if (param_is(c, "algo", "md5"))
        md5_hex(in, n, digest);
    else if (param_is(c, "algo", "sha1"))
        sha1_hex(in, n, digest);
    else if (!has_param(c, "algo") || param_is(c, "algo", "sha256"))
        sha256_hex(in, n, digest);
    else
        return fail(c, "algo must be md5, sha1, sha256 or crc32");
    bytes_set(out, (const uint8_t *)digest, strlen(digest));
    return true;
}

/* --- symmetric ciphers (crypto.py) ------------------------------------------------- */

static uint32_t rotl32(uint32_t x, unsigned n) {
    return x << n | x >> (32 - n);
}

#define QUARTER(a, b, c, d) \
    do { \
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7); \
    } while (0)

static void chacha_block(const uint32_t state[16], uint8_t stream[64]) {
    uint32_t x[16];
    memcpy(x, state, sizeof x);
    for (int round = 0; round < 10; round++) {
        QUARTER(0, 4, 8, 12);
        QUARTER(1, 5, 9, 13);
        QUARTER(2, 6, 10, 14);
        QUARTER(3, 7, 11, 15);
        QUARTER(0, 5, 10, 15);
        QUARTER(1, 6, 11, 12);
        QUARTER(2, 7, 8, 13);
        QUARTER(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t word = x[i] + state[i];
        stream[4 * i] = (uint8_t)word;
        stream[4 * i + 1] = (uint8_t)(word >> 8);
        stream[4 * i + 2] = (uint8_t)(word >> 16);
        stream[4 * i + 3] = (uint8_t)(word >> 24);
    }
}

#undef QUARTER

/* ChaCha20 of RFC 8439 */
static bool op_chacha20(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    Bytes key = {0}, nonce = {0};
    PyInt counter = {false, false, 1, 1};
    bool ok = hex_param(c, param(c, "key"), &key) && hex_param(c, param(c, "nonce"), &nonce) &&
              (!has_param(c, "counter") ||
               as_int(c->a, param(c, "counter"), "counter", &counter, &c->error));
    if (ok && key.n != 32)
        ok = fail(c, "chacha20 failed: ChaCha20 key must be 32 bytes, got %zu", key.n);
    if (ok && nonce.n != 12)
        ok = fail(c, "chacha20 failed: ChaCha20 nonce must be 12 bytes, got %zu", nonce.n);
    if (ok) {
        uint32_t state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        for (int i = 0; i < 8; i++)
            state[4 + i] = le32(key.p + 4 * i);
        state[12] = counter.low32;
        for (int i = 0; i < 3; i++)
            state[13 + i] = le32(nonce.p + 4 * i);
        bytes_reserve(out, n + 1);
        uint8_t stream[64];
        for (size_t i = 0; i < n; i += 64) {
            chacha_block(state, stream);
            size_t run = n - i < 64 ? n - i : 64;
            for (size_t k = 0; k < run; k++)
                out->p[i + k] = in[i + k] ^ stream[k];
            state[12]++;                /* wraps at 2**32, as in crypto.py */
        }
        out->n = n;
    }
    bytes_free(&key);
    bytes_free(&nonce);
    return ok;
}

static bool op_rc4(Op *c, const uint8_t *in, size_t n, Bytes *out) {
    Bytes key = {0};
    bool unencodable;
    if (!key_bytes(c, "rc4", &key, &unencodable)) {
        bytes_free(&key);
        if (unencodable)                /* Python: wrapped like any other exception */
            return fail(c, "rc4 failed: %s", c->error.p);
        return false;
    }
    if (key.n < 1 || key.n > 256) {
        size_t length = key.n;
        bytes_free(&key);
        return fail(c, "rc4 failed: RC4 key must be 1..256 bytes, got %zu", length);
    }
    uint8_t s[256];
    for (int i = 0; i < 256; i++)
        s[i] = (uint8_t)i;
    unsigned j = 0;
    for (unsigned i = 0; i < 256; i++) {
        j = (j + s[i] + key.p[i % key.n]) & 0xff;
        uint8_t t = s[i];
        s[i] = s[j];
        s[j] = t;
    }
    bytes_free(&key);
    bytes_reserve(out, n + 1);
    unsigned i = 0;
    j = 0;
    for (size_t k = 0; k < n; k++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        uint8_t t = s[i];
        s[i] = s[j];
        s[j] = t;
        out->p[k] = in[k] ^ s[(s[i] + s[j]) & 0xff];
    }
    out->n = n;
    return true;
}

/* --- the operation registry -------------------------------------------------------- */

typedef bool (*OpFn)(Op *c, const uint8_t *in, size_t n, Bytes *out);

typedef struct {
    const char *name;
    const char *type;           /* string, int, hex or choice */
    bool required;
    const char *choices;        /* "a|b|c", or NULL */
    const char *fallback;       /* default of a choice, or NULL */
    int number;                 /* default of an int when has_number */
    bool has_number;
} ParamSpec;

typedef struct {
    const char *name, *group, *summary;
    const ParamSpec *params;
    size_t nparams;
    OpFn fn;                    /* NULL: not in this build */
} OpSpec;

#define MODE {"mode", "choice", false, "decrypt|encrypt", "decrypt", 0, false}
#define OPERATION {"op", "choice", false, "decrypt|encrypt", "decrypt", 0, false}

static const ParamSpec P_ALPHABET[] = {{"alphabet", "choice", false, "std|url", "std", 0, false}};
static const ParamSpec P_VARIANT[] = {
    {"variant", "choice", false, "ascii85|z85", "ascii85", 0, false}};
static const ParamSpec P_CHARSET[] = {
    {"from", "choice", false, "utf-8|utf-16le|utf-16be|latin-1", "utf-8", 0, false}};
static const ParamSpec P_ROT_N[] = {{"n", "int", false, NULL, NULL, 13, true}};
static const ParamSpec P_VIGENERE[] = {{"key", "string", true, NULL, NULL, 0, false}, MODE};
static const ParamSpec P_KEY[] = {
    {"key", "hex", false, NULL, NULL, 0, false}, {"key_text", "string", false, NULL, NULL, 0, false}};
static const ParamSpec P_RAILFENCE[] = {{"rails", "int", true, NULL, NULL, 0, false}, MODE};
static const ParamSpec P_SUBSTITUTION[] = {{"map", "string", true, NULL, NULL, 0, false}};
static const ParamSpec P_AES[] = {
    {"key", "hex", true, NULL, NULL, 0, false},
    {"mode", "choice", true, "ecb|cbc|ctr|gcm", NULL, 0, false},
    {"iv", "hex", false, NULL, NULL, 0, false},
    {"nonce", "hex", false, NULL, NULL, 0, false},
    {"tag", "hex", false, NULL, NULL, 0, false},
    OPERATION,
    {"unpad", "choice", false, "pkcs7|none", "pkcs7", 0, false}};
static const ParamSpec P_CHACHA20[] = {
    {"key", "hex", true, NULL, NULL, 0, false},
    {"nonce", "hex", true, NULL, NULL, 0, false},
    {"counter", "int", false, NULL, NULL, 1, true}};
static const ParamSpec P_DES[] = {
    {"key", "hex", true, NULL, NULL, 0, false},
    {"mode", "choice", false, "ecb|cbc", "ecb", 0, false},
    {"iv", "hex", false, NULL, NULL, 0, false},
    OPERATION};
static const ParamSpec P_HASH[] = {
    {"algo", "choice", false, "md5|sha1|sha256|crc32", "sha256", 0, false}};

#define WITH(params) params, ARRAY_LEN(params)
#define NONE NULL, 0

/* The same operations, in the same order, as _OP_LIST in decode.py. */
static const OpSpec OPS[] = {
    {"from-base64", "Encoding", "decode base64", WITH(P_ALPHABET), op_from_base64},
    {"to-base64", "Encoding", "encode base64", WITH(P_ALPHABET), op_to_base64},
    {"from-base32", "Encoding", "decode base32", NONE, op_from_base32},
    {"to-base32", "Encoding", "encode base32", NONE, op_to_base32},
    {"from-hex", "Encoding", "decode hex (lenient whitespace)", NONE, op_from_hex},
    {"to-hex", "Encoding", "encode hex", NONE, op_to_hex},
    {"from-base85", "Encoding", "decode ascii85 or z85", WITH(P_VARIANT), op_from_base85},
    {"to-base85", "Encoding", "encode ascii85 or z85", WITH(P_VARIANT), op_to_base85},
    {"url-decode", "Encoding", "decode percent-encoding", NONE, op_url_decode},
    {"url-encode", "Encoding", "encode percent-encoding", NONE, op_url_encode},
    {"qp-decode", "Encoding", "decode quoted-printable", NONE, op_qp_decode},
    {"rot13", "Encoding", "ROT13 on letters (self-inverse)", NONE, op_rot13},
    {"reverse", "Encoding", "reverse the bytes", NONE, op_reverse},
    {"charset-decode", "Encoding", "reinterpret text and re-emit UTF-8", WITH(P_CHARSET),
     op_charset_decode},
    {"zlib-inflate", "Decompress", "inflate a zlib stream", NONE, op_zlib_inflate},
    {"raw-inflate", "Decompress", "inflate a headerless DEFLATE stream", NONE, op_raw_inflate},
    {"gunzip", "Decompress", "decompress a gzip stream", NONE, op_gunzip},
    {"bunzip2", "Decompress", "decompress a bzip2 stream", NONE, NULL},
    {"unxz", "Decompress", "decompress an xz stream", NONE, NULL},
    {"rot-n", "Classic cipher", "Caesar shift on letters", WITH(P_ROT_N), op_rot_n},
    {"atbash", "Classic cipher", "Atbash (self-inverse)", NONE, op_atbash},
    {"vigenere", "Classic cipher", "Vigenere cipher", WITH(P_VIGENERE), op_vigenere},
    {"xor", "Classic cipher", "repeating-key XOR (self-inverse)", WITH(P_KEY), op_xor},
    {"railfence", "Classic cipher", "rail-fence transposition", WITH(P_RAILFENCE), op_railfence},
    {"substitution", "Classic cipher", "monoalphabetic substitution", WITH(P_SUBSTITUTION),
     op_substitution},
    {"aes", "Symmetric", "AES (needs a supplied key)", WITH(P_AES), NULL},
    {"chacha20", "Symmetric", "ChaCha20 (RFC 8439, self-inverse)", WITH(P_CHACHA20), op_chacha20},
    {"rc4", "Symmetric", "RC4 (self-inverse)", WITH(P_KEY), op_rc4},
    {"des", "Symmetric", "DES (needs a supplied key)", WITH(P_DES), NULL},
    {"3des", "Symmetric", "Triple DES (needs a supplied key)", WITH(P_DES), NULL},
    {"hash", "Hash", "replace data with its digest as hex", WITH(P_HASH), op_hash},
};

static const char *const GROUPS[] = {"Encoding", "Decompress", "Classic cipher", "Symmetric",
                                     "Hash"};

static const struct {
    const char *name, *summary;
} SOLVERS[] = {
    {"caesar", "try all 26 Caesar shifts"},
    {"xor-single", "try all 256 single-byte XOR keys"},
    {"xor-keylen", "guess a repeating-XOR key of length 1..40"},
    {"substitution", "frequency-match a monoalphabetic substitution"},
};

static const OpSpec *find_op(Str name) {
    for (size_t i = 0; i < ARRAY_LEN(OPS); i++)
        if (str_eq_c(name, OPS[i].name))
            return &OPS[i];
    return NULL;
}

static const ParamSpec *find_param(const OpSpec *op, Str name) {
    for (size_t i = 0; i < op->nparams; i++)
        if (str_eq_c(name, op->params[i].name))
            return &op->params[i];
    return NULL;
}

/* apply_op(): one operation, with its name, its parameters and the size of
 * its result checked. */
static bool apply_op(Arena *a, const DecodeStep *step, const uint8_t *in, size_t n, Bytes *out,
                     Str *error) {
    Op c = {a, step->params, STR_NONE};
    const OpSpec *op = find_op(step->op);
    bool ok;
    if (op == NULL) {
        ok = fail(&c, "unknown operation: %s", py_repr_str(a, step->op).p);
    } else if (op->fn == NULL) {
        ok = fail(&c, "%s is not available in this build", op->name);
    } else {
        ok = true;
        const JVal *params = step->params;
        for (size_t i = 0; ok && params != NULL && i < params->u.dict.n; i++) {
            Str key = {params->u.dict.v[i].key, params->u.dict.v[i].key_len};
            if (find_param(op, key) == NULL)
                ok = fail(&c, "unknown parameter %s for %s", py_repr_str(a, key).p, op->name);
        }
        for (size_t i = 0; ok && i < op->nparams; i++)
            if (op->params[i].required && blank(param(&c, op->params[i].name)))
                ok = fail(&c, "%s needs parameter %s", op->name, op->params[i].name);
        if (ok)
            ok = op->fn(&c, in, n, out);
        if (ok && out->n > CAP)
            ok = fail(&c, "%s", TOO_LARGE);
    }
    *error = c.error;
    return ok;
}

/* --- sources ---------------------------------------------------------------------- */

/* source_bytes(): the bytes are either a slice of the file or in `owned`. */
static bool source_bytes(Arena *a, const DecodeSource *source, Bytes *owned,
                         const uint8_t **data, size_t *size, Str *error) {
    Op c = {a, NULL, STR_NONE};
    bool ok = true;
    if (source->kind == DECODE_FILE) {
        PyInt offset = {false, false, 0, 0}, length = {false, false, 0, 0};
        bool to_end = blank(source->length);
        if (!blank(source->offset))
            ok = as_int(a, source->offset, "offset", &offset, &c.error);
        if (ok && offset.negative)
            ok = fail(&c, "offset must not be negative");
        if (ok && !to_end)
            ok = as_int(a, source->length, "length", &length, &c.error);
        if (ok && !to_end && length.negative)
            ok = fail(&c, "length must not be negative");
        if (ok) {
            /* bytes(data)[offset:offset + length], as a slice clamps it */
            size_t total = source->file_size;
            size_t start = offset.huge || offset.magnitude > total ? total
                                                                    : (size_t)offset.magnitude;
            size_t count = total - start;
            if (!to_end && !length.huge && length.magnitude < count)
                count = (size_t)length.magnitude;
            *data = source->file + start;
            *size = count;
        }
    } else {
        Str text = blank(source->value) ? str_c("") : decode_pystr(a, source->value);
        const char *why = NULL;
        Str encoded;
        if (source->kind == DECODE_TEXT) {
            /* str.encode("utf-8"); a lone surrogate cannot be encoded */
            if (!py_encode_utf8(a, text, &c.error))
                ok = false;
            else
                bytes_set(owned, (const uint8_t *)text.p, text.n);
        } else if (source->kind == DECODE_HEX) {
            if (!parse_hex(text.p, text.n, true, owned, &why))
                ok = fail(&c, "%s", why);
        } else {
            /* str.encode("latin-1"), then base64 with the standard alphabet */
            if (!py_encode_latin1(a, text, &encoded, &c.error))
                ok = false;
            else
                ok = base64_decode(&c, (const uint8_t *)encoded.p, encoded.n, false, owned);
        }
        if (ok) {
            if (owned->p == NULL)
                bytes_reserve(owned, 1);
            *data = owned->p;
            *size = owned->n;
        }
    }
    *error = c.error;
    return ok;
}

/* --- the pipeline ------------------------------------------------------------------ */

static void keep_bytes(Arena *a, Bytes *b) {
    if (b->p != NULL)
        arena_adopt(a, b->p);
    b->p = NULL;
}

void decode_execute(Arena *a, const DecodeSource *source, const DecodeStep *steps, size_t nsteps,
                    DecodeResult *result) {
    memset(result, 0, sizeof *result);
    result->data = (const uint8_t *)"";
    result->error = STR_NONE;
    Bytes current = {0};
    const uint8_t *data = NULL;
    size_t size = 0;
    if (!source_bytes(a, source, &current, &data, &size, &result->error)) {
        bytes_free(&current);
        return;
    }
    if (size > CAP) {
        bytes_free(&current);
        result->error = str_c(TOO_LARGE);
        return;
    }
    result->steps = arena_array(a, nsteps ? nsteps : 1, sizeof *result->steps);
    result->ok = true;
    for (size_t i = 0; i < nsteps; i++) {
        Bytes next = {0};
        if (!apply_op(a, &steps[i], data, size, &next, &result->error)) {
            bytes_free(&next);
            result->ok = false;
            break;
        }
        if (next.p == NULL)
            bytes_reserve(&next, 1);
        bytes_free(&current);           /* the previous step's bytes, if they were ours */
        current = next;
        data = current.p;
        size = current.n;
        result->steps[result->nsteps].op = steps[i].op;
        result->steps[result->nsteps].size = size;
        result->nsteps++;
    }
    keep_bytes(a, &current);
    result->data = size ? data : (const uint8_t *)"";
    result->size = size;
}

static Str hex_text(Arena *a, const uint8_t *data, size_t n) {
    if (n > SIZE_MAX / 4)
        die_out_of_memory();
    char *text = arena_alloc(a, n * 2 + 1);
    for (size_t i = 0; i < n; i++) {
        text[2 * i] = HEX_DIGITS[data[i] >> 4];
        text[2 * i + 1] = HEX_DIGITS[data[i] & 15];
    }
    Str s = {text, n * 2};
    return s;
}

JVal *decode_result_view(Arena *a, const DecodeResult *r) {
    JVal *d = j_dict(a);
    j_set(a, d, "ok", j_bool(a, r->ok));
    j_set(a, d, "size", j_int(a, (big)r->size));
    j_set(a, d, "hex", j_str(a, hex_text(a, r->data, r->size)));
    j_set(a, d, "text", j_str(a, utf8_decode(a, r->data, r->size)));
    j_set(a, d, "looks_like", j_cstr(a, decode_looks_like(r->data, r->size)));
    JVal *steps = j_list(a);
    for (size_t i = 0; i < r->nsteps; i++) {
        JVal *step = j_dict(a);
        j_set(a, step, "op", j_str(a, r->steps[i].op));
        j_set(a, step, "size", j_int(a, (big)r->steps[i].size));
        j_push(a, steps, step);
    }
    j_set(a, d, "steps", steps);
    j_set(a, d, "error", j_str(a, r->error));
    return d;
}

/* --- the recipe grammar ------------------------------------------------------------ */

static bool recipe_fail(Arena *a, Str *error, const char *fmt, ...) PRINTF_LIKE(3, 4);
static bool recipe_fail(Arena *a, Str *error, const char *fmt, ...) {
    va_list args, again;
    va_start(args, fmt);
    va_copy(again, args);
    int n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (n < 0)
        n = 0;
    char *text = arena_alloc(a, (size_t)n + 1);
    vsnprintf(text, (size_t)n + 1, fmt, again);
    va_end(again);
    error->p = text;
    error->n = (size_t)n;
    return false;
}

/* s.partition(separator): the part before the first separator; *rest is
 * what follows it, or STR_NONE when there is none. */
static Str partition(Str s, char separator, Str *rest) {
    const char *found = s.n ? memchr(s.p, separator, s.n) : NULL;
    if (found == NULL) {
        *rest = STR_NONE;
        return s;
    }
    Str head = {s.p, (size_t)(found - s.p)};
    rest->p = found + 1;
    rest->n = s.n - head.n - 1;
    return head;
}

bool decode_parse_recipe(Arena *a, Str text, DecodeStep **steps, size_t *nsteps, Str *error) {
    VEC(DecodeStep) found = {0};
    *steps = NULL;
    *nsteps = 0;
    if (py_strip(text).n == 0)
        return true;
    Str rest = text;
    while (rest.p != NULL) {
        Str piece = partition(rest, '|', &rest);
        Str arguments;
        Str name = py_strip(partition(piece, ':', &arguments));
        if (name.n == 0)
            return recipe_fail(a, error, "empty operation in recipe");
        const OpSpec *op = find_op(name);
        if (op == NULL)
            return recipe_fail(a, error, "unknown operation: %s", py_repr_str(a, name).p);
        JVal *params = j_dict(a);
        while (arguments.p != NULL) {
            Str pair = partition(arguments, ',', &arguments);
            if (py_strip(pair).n == 0)
                continue;
            Str value;
            Str key = py_strip(partition(pair, '=', &value));
            if (value.p == NULL)
                return recipe_fail(a, error, "expected key=value, got %s for %s",
                                   py_repr_str(a, py_strip(pair)).p, op->name);
            const ParamSpec *spec = find_param(op, key);
            if (spec == NULL)
                return recipe_fail(a, error, "unknown parameter %s for %s",
                                   py_repr_str(a, key).p, op->name);
            value = py_strip(value);
            j_set(a, params, spec->name, j_str(a, str_copy(a, value.p, value.n)));
        }
        DecodeStep step = {str_c(op->name), params};
        *VEC_PUSH(a, found) = step;
    }
    *steps = found.v;
    *nsteps = found.n;
    return true;
}

/* --- the catalogue ------------------------------------------------------------------ */

JVal *decode_catalogue(Arena *a) {
    JVal *groups = j_list(a);
    for (size_t g = 0; g < ARRAY_LEN(GROUPS); g++) {
        JVal *entries = j_list(a);
        for (size_t i = 0; i < ARRAY_LEN(OPS); i++) {
            const OpSpec *op = &OPS[i];
            if (strcmp(op->group, GROUPS[g]) != 0)
                continue;
            JVal *params = j_list(a);
            for (size_t k = 0; k < op->nparams; k++) {
                const ParamSpec *spec = &op->params[k];
                JVal *p = j_dict(a);
                j_set(a, p, "name", j_cstr(a, spec->name));
                j_set(a, p, "required", j_bool(a, spec->required));
                j_set(a, p, "type", j_cstr(a, spec->type));
                if (spec->choices != NULL) {
                    JVal *choices = j_list(a);
                    Str left = str_c(spec->choices);
                    while (left.p != NULL) {
                        Str choice = partition(left, '|', &left);
                        j_push(a, choices, j_str(a, str_copy(a, choice.p, choice.n)));
                    }
                    j_set(a, p, "choices", choices);
                }
                if (spec->fallback != NULL)
                    j_set(a, p, "default", j_cstr(a, spec->fallback));
                else if (spec->has_number)
                    j_set(a, p, "default", j_int(a, spec->number));
                j_push(a, params, p);
            }
            JVal *entry = j_dict(a);
            j_set(a, entry, "name", j_cstr(a, op->name));
            j_set(a, entry, "summary", j_cstr(a, op->summary));
            j_set(a, entry, "available", j_bool(a, op->fn != NULL));
            j_set(a, entry, "params", params);
            j_push(a, entries, entry);
        }
        JVal *group = j_dict(a);
        j_set(a, group, "name", j_cstr(a, GROUPS[g]));
        j_set(a, group, "ops", entries);
        j_push(a, groups, group);
    }
    JVal *solvers = j_list(a);
    for (size_t i = 0; i < ARRAY_LEN(SOLVERS); i++) {
        JVal *solver = j_dict(a);
        j_set(a, solver, "name", j_cstr(a, SOLVERS[i].name));
        j_set(a, solver, "summary", j_cstr(a, SOLVERS[i].summary));
        j_push(a, solvers, solver);
    }
    JVal *d = j_dict(a);
    j_set(a, d, "groups", groups);
    j_set(a, d, "solvers", solvers);
    return d;
}

/* --- looks_like --------------------------------------------------------------------- */

static bool printable(uint8_t ch) {
    return (ch >= 0x20 && ch <= 0x7E) || ch == 0x09 || ch == 0x0A || ch == 0x0D;
}

static size_t printable_count(const uint8_t *data, size_t n) {
    size_t count = 0;
    for (size_t i = 0; i < n; i++)
        count += printable(data[i]);
    return count;
}

const char *decode_looks_like(const uint8_t *data, size_t n) {
    static const struct {
        const char *magic;
        size_t length;
        const char *name;
    } signatures[] = {
        {"\x89PNG\r\n\x1a\n", 8, "PNG image"}, {"\x1f\x8b", 2, "gzip"}, {"BZh", 3, "bzip2"},
        {"\xfd" "7zXZ\x00", 6, "xz"}, {"PK\x03\x04", 4, "zip archive"},
        {"PK\x05\x06", 4, "zip archive"}, {"\x7f" "ELF", 4, "ELF program"},
        {"%PDF-", 5, "PDF document"}, {"\xff\xd8\xff", 3, "JPEG image"},
        {"GIF87a", 6, "GIF image"}, {"GIF89a", 6, "GIF image"}, {"%!", 2, "PostScript"},
    };
    if (n == 0)
        return "empty";
    for (size_t i = 0; i < ARRAY_LEN(signatures); i++)
        if (n >= signatures[i].length &&
            memcmp(data, signatures[i].magic, signatures[i].length) == 0)
            return signatures[i].name;
    if (n >= 2 && data[0] == 'M' && data[1] == 'Z') {
        if (n >= 0x40) {
            size_t at = le32(data + 0x3C);
            if (at <= n - 4 && memcmp(data + at, "PE\0\0", 4) == 0)
                return "PE program";
        }
        return "DOS executable";
    }
    if ((double)printable_count(data, n) / (double)n >= 0.95)
        return "printable text";
    return "binary";
}

/* --- scoring ------------------------------------------------------------------------ */

static const double ENGLISH_FREQ[26] = {
    .08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094, .06966, .00153, .00772,
    .04025, .02406, .06749, .07507, .01929, .00095, .05987, .06327, .09056, .02758, .00978,
    .02360, .00150, .01974, .00074,
};
/* The commonest English letter pairs, per 10,000 pairs (_PAIRS in decode.py). */
static const struct {
    char pair[3];
    int count;
} PAIRS[] = {
    {"th", 356}, {"he", 307}, {"in", 243}, {"er", 205}, {"an", 199}, {"re", 185}, {"on", 176},
    {"at", 149}, {"en", 145}, {"nd", 135}, {"ti", 134}, {"es", 134}, {"or", 128}, {"te", 120},
    {"of", 117}, {"ed", 117}, {"is", 113}, {"it", 112}, {"al", 109}, {"ar", 107}, {"st", 105},
    {"to", 104}, {"nt", 104}, {"ng", 95}, {"se", 93}, {"ha", 93}, {"as", 87}, {"ou", 87},
    {"io", 83}, {"le", 83}, {"ve", 83}, {"co", 79}, {"me", 79}, {"de", 76}, {"hi", 76},
    {"ri", 73}, {"ro", 73}, {"ic", 70}, {"ne", 69}, {"ea", 69}, {"ra", 69}, {"ce", 65},
    {"li", 62}, {"ch", 60}, {"ll", 58}, {"be", 58}, {"ma", 57}, {"si", 55}, {"om", 55},
    {"ur", 54},
};
#define SPACE_WEIGHT 0.19           /* a space is the commonest character in English */
#define WEIGHT_FULL 0.085           /* mean character weight of ordinary English */
#define PAIR_FULL 0.0075            /* mean pair weight of ordinary English */

static double pair_freq[26][26];
static bool pair_freq_ready;

static int letter_index(uint8_t ch) {
    if (is_upper(ch))
        return ch - 'A';
    if (is_lower(ch))
        return ch - 'a';
    return -1;
}

/* _english_fitness(): the sums run in the order of the Python code, so the
 * doubles are the same ones. */
static double english_fitness(const uint8_t *data, size_t n) {
    if (n == 0)
        return 0.0;
    if (!pair_freq_ready) {
        for (size_t i = 0; i < ARRAY_LEN(PAIRS); i++)
            pair_freq[PAIRS[i].pair[0] - 'a'][PAIRS[i].pair[1] - 'a'] =
                (double)PAIRS[i].count / 10000.0;
        pair_freq_ready = true;
    }
    double total = 0.0;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = data[i];
        int letter = letter_index(ch);
        if (ch == 0x20)
            total += SPACE_WEIGHT;
        else if (letter >= 0)
            total += ENGLISH_FREQ[letter];
        else if (!printable(ch))
            total -= 0.5;
    }
    double chars = total / (double)n / WEIGHT_FULL;
    if (!(chars > 0.0))
        chars = 0.0;                    /* max(0.0, x) */
    if (!(chars < 1.0))
        chars = 1.0;                    /* min(1.0, x) */
    double pairs = 0.0;
    if (n > 1) {
        double hits = 0.0;
        for (size_t i = 0; i + 1 < n; i++) {
            int first = letter_index(data[i]), second = letter_index(data[i + 1]);
            hits += first >= 0 && second >= 0 ? pair_freq[first][second] : 0.0;
        }
        pairs = hits / (double)(n - 1) / PAIR_FULL;
        if (!(pairs < 1.0))
            pairs = 1.0;
    }
    return 0.7 * chars + 0.3 * pairs;
}

/* round(_score(data), 6), in millionths. */
static uint32_t score_micro(const uint8_t *data, size_t n) {
    double ratio = n ? (double)printable_count(data, n) / (double)n : 0.0;
    double score = 0.6 * ratio + 0.4 * english_fitness(data, n);
    /* The decimal rounding Python's round() does: "%.6f" rounds the exact
     * value of the double correctly, ties to even. */
    char text[32];
    snprintf(text, sizeof text, "%.6f", score);
    uint32_t micro = 0;
    for (const char *p = text; *p; p++)
        if (*p >= '0' && *p <= '9')
            micro = micro * 10 + (uint32_t)(*p - '0');
    return micro;
}

/* repr() of the float that round(score, 6) is: its shortest form. */
static Str score_token(Arena *a, uint32_t micro) {
    char text[32];
    if (micro >= 100) {
        snprintf(text, sizeof text, "%u.%06u", (unsigned)(micro / 1000000),
                 (unsigned)(micro % 1000000));
        size_t n = strlen(text);
        while (text[n - 1] == '0' && text[n - 2] != '.')
            text[--n] = '\0';
    } else if (micro == 0) {
        snprintf(text, sizeof text, "0.0");
    } else {
        /* Below 0.0001 repr() switches to the exponent form: 1.2e-05. */
        int exponent = -6;
        unsigned digits = micro;
        while (digits % 10 == 0) {
            digits /= 10;
            exponent++;
        }
        if (digits >= 10)
            snprintf(text, sizeof text, "%u.%ue-%02d", digits / 10, digits % 10, -(exponent + 1));
        else
            snprintf(text, sizeof text, "%ue-%02d", digits, -exponent);
    }
    return str_copy(a, text, strlen(text));
}

/* --- solvers ------------------------------------------------------------------------ */

/* _candidate() */
static JVal *candidate(Arena *a, JVal *params, const uint8_t *data, size_t n, uint32_t micro) {
    JVal *d = j_dict(a);
    j_set(a, d, "params", params);
    j_set(a, d, "size", j_int(a, (big)n));
    j_set(a, d, "hex", j_str(a, hex_text(a, data, n)));
    j_set(a, d, "text", j_str(a, utf8_decode(a, data, n)));
    j_set(a, d, "score", j_raw(a, score_token(a, micro)));
    return d;
}

typedef struct {
    uint32_t micro;
    unsigned tie;               /* smaller first among equal scores (0 for "as found") */
    unsigned which;             /* what the candidate is */
} Ranked;

/* list.sort(key=score, reverse=True): the best first; candidates with the
 * same score stay in the order they were in. Small lists only. */
static void rank(Ranked *items, size_t count) {
    for (size_t i = 1; i < count; i++) {
        Ranked item = items[i];
        size_t k = i;
        while (k > 0 && (items[k - 1].micro < item.micro ||
                         (items[k - 1].micro == item.micro && items[k - 1].tie > item.tie))) {
            items[k] = items[k - 1];
            k--;
        }
        items[k] = item;
    }
}

static void solve_caesar(Arena *a, const uint8_t *data, size_t n, JVal *out) {
    uint8_t *work = arena_alloc(a, n + 1);
    Ranked ranked[26];
    for (unsigned shift = 0; shift < 26; shift++) {
        rotate(data, n, shift, work);
        ranked[shift].micro = score_micro(work, n);
        ranked[shift].tie = 0;
        ranked[shift].which = shift;
    }
    rank(ranked, 26);
    for (size_t i = 0; i < 20; i++) {
        uint8_t *text = arena_alloc(a, n + 1);
        rotate(data, n, ranked[i].which, text);
        JVal *params = j_dict(a);
        j_set(a, params, "n", j_int(a, ranked[i].which));
        j_push(a, out, candidate(a, params, text, n, ranked[i].micro));
    }
}

static void solve_xor_single(Arena *a, const uint8_t *data, size_t n, JVal *out) {
    uint8_t *work = arena_alloc(a, n + 1);
    Ranked ranked[256];
    for (unsigned key = 0; key < 256; key++) {
        for (size_t i = 0; i < n; i++)
            work[i] = data[i] ^ (uint8_t)key;
        ranked[key].micro = score_micro(work, n);
        ranked[key].tie = 0;
        ranked[key].which = key;
    }
    rank(ranked, 256);
    for (size_t i = 0; i < 20; i++) {
        uint8_t *text = arena_alloc(a, n + 1);
        for (size_t k = 0; k < n; k++)
            text[k] = data[k] ^ (uint8_t)ranked[i].which;
        JVal *params = j_dict(a);
        j_set(a, params, "key", j_str(a, str_printf(a, "%02x", ranked[i].which)));
        j_push(a, out, candidate(a, params, text, n, ranked[i].micro));
    }
}

static unsigned bit_count(uint8_t x) {
    unsigned count = 0;
    for (; x; x &= (uint8_t)(x - 1))
        count++;
    return count;
}

/* _best_single_byte(): the byte that makes every `step`-th byte from `first`
 * on look most like English text (spaces count here: _recovery_score). */
static uint8_t best_single_byte(const uint8_t *data, size_t n, size_t first, size_t step) {
    unsigned best = 0;
    bool have = false;
    double best_score = 0.0;
    for (unsigned key = 0; key < 256; key++) {
        double total = 0.0;
        for (size_t i = first; i < n; i += step) {
            uint8_t ch = data[i] ^ (uint8_t)key;
            int letter = letter_index(ch);
            if (ch == 0x20)
                total += 0.19;
            else if (letter >= 0)
                total += ENGLISH_FREQ[letter];
            else if (ch == 0x09 || ch == 0x0A || ch == 0x0D || (ch >= 0x21 && ch <= 0x7E))
                total += 0.0;
            else
                total -= 0.5;
        }
        if (!have || total > best_score) {
            have = true;
            best_score = total;
            best = key;
        }
    }
    return (uint8_t)best;
}

/* _minimal_period(): the length of the shortest key this one repeats. */
static size_t minimal_period(const uint8_t *key, size_t n) {
    for (size_t p = 1; p < n; p++) {
        if (n % p != 0)
            continue;
        bool repeats = true;
        for (size_t i = p; i < n && repeats; i++)
            repeats = key[i] == key[i - p];
        if (repeats)
            return p;
    }
    return n;
}

typedef struct {
    double distance;
    size_t length;
} KeyLength;

static void solve_xor_keylen(Arena *a, const uint8_t *data, size_t n, JVal *out) {
    if (n < 2) {
        solve_xor_single(a, data, n, out);
        return;
    }
    /* The key lengths whose neighbouring blocks differ in the fewest bits. */
    size_t max_length = n / 2 < 40 ? n / 2 : 40;
    KeyLength scored[40];
    size_t nscored = 0;
    for (size_t length = 1; length <= max_length; length++) {
        size_t blocks = n / length;
        size_t pairs = blocks - 1 < 12 ? blocks - 1 : 12;
        if (pairs < 1)
            continue;
        uint64_t bits = 0;
        for (size_t i = 0; i < pairs * length; i++)
            bits += bit_count(data[i] ^ data[i + length]);
        KeyLength item = {(double)bits / (double)(pairs * length), length};
        /* sorted by distance; equal distances keep the shorter length first */
        size_t k = nscored++;
        while (k > 0 && scored[k - 1].distance > item.distance) {
            scored[k] = scored[k - 1];
            k--;
        }
        scored[k] = item;
    }
    size_t tries = nscored < 4 ? nscored : 4;
    uint8_t keys[4][40];
    size_t key_sizes[4];
    Ranked ranked[4];
    size_t found = 0;
    uint8_t *work = arena_alloc(a, n + 1);
    for (size_t t = 0; t < tries; t++) {
        size_t length = scored[t].length;
        uint8_t key[40];
        for (size_t column = 0; column < length; column++)
            key[column] = best_single_byte(data, n, column, length);
        size_t size = minimal_period(key, length);
        bool seen = false;
        for (size_t k = 0; k < found && !seen; k++)
            seen = key_sizes[k] == size && memcmp(keys[k], key, size) == 0;
        if (seen)
            continue;
        memcpy(keys[found], key, size);
        key_sizes[found] = size;
        xor_with(data, n, key, size, work);
        ranked[found].micro = score_micro(work, n);
        ranked[found].tie = (unsigned)size;     /* on a tie the shorter key wins */
        ranked[found].which = (unsigned)found;
        found++;
    }
    rank(ranked, found);
    for (size_t i = 0; i < found; i++) {
        const uint8_t *key = keys[ranked[i].which];
        size_t size = key_sizes[ranked[i].which];
        uint8_t *text = arena_alloc(a, n + 1);
        xor_with(data, n, key, size, text);
        JVal *params = j_dict(a);
        j_set(a, params, "key", j_str(a, hex_text(a, key, size)));
        j_set(a, params, "keylen", j_int(a, (big)size));
        j_push(a, out, candidate(a, params, text, n, ranked[i].micro));
    }
}

static void solve_substitution(Arena *a, const uint8_t *data, size_t n, JVal *out) {
    static const char english_order[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    size_t counts[26] = {0};
    for (size_t i = 0; i < n; i++) {
        int letter = letter_index(data[i]);
        if (letter >= 0)
            counts[letter]++;
    }
    /* The cipher letters, most frequent first (equal counts: A before B). */
    int order[26];
    for (int i = 0; i < 26; i++) {
        int k = i;
        while (k > 0 && counts[order[k - 1]] < counts[i]) {
            order[k] = order[k - 1];
            k--;
        }
        order[k] = i;
    }
    /* The i-th most common cipher letter stands for the i-th most common
     * English letter. */
    char map[27];
    int plain[26];
    for (int i = 0; i < 26; i++) {
        map[english_order[i] - 'A'] = (char)('A' + order[i]);
        plain[order[i]] = english_order[i] - 'A';
    }
    map[26] = '\0';
    uint8_t *text = arena_alloc(a, n + 1);
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = data[i];
        if (is_upper(ch))
            ch = (uint8_t)('A' + plain[ch - 'A']);
        else if (is_lower(ch))
            ch = (uint8_t)('a' + plain[ch - 'a']);
        text[i] = ch;
    }
    JVal *params = j_dict(a);
    j_set(a, params, "map", j_str(a, str_copy(a, map, 26)));
    j_push(a, out, candidate(a, params, text, n, score_micro(text, n)));
}

JVal *decode_solve(Arena *a, Str name, const DecodeSource *source) {
    JVal *d = j_dict(a);
    JVal *candidates = j_list(a);
    Str error = STR_NONE;
    bool ok = false;
    int solver = -1;
    for (size_t i = 0; i < ARRAY_LEN(SOLVERS); i++)
        if (str_eq_c(name, SOLVERS[i].name))
            solver = (int)i;
    if (solver < 0) {
        error = str_printf(a, "unknown solver: %s", py_repr_str(a, name).p);
    } else {
        Bytes owned = {0};
        const uint8_t *data = NULL;
        size_t size = 0;
        if (source_bytes(a, source, &owned, &data, &size, &error)) {
            ok = true;
            if (size > SOLVE_CAP)
                size = SOLVE_CAP;
            switch (solver) {
            case 0: solve_caesar(a, data, size, candidates); break;
            case 1: solve_xor_single(a, data, size, candidates); break;
            case 2: solve_xor_keylen(a, data, size, candidates); break;
            default: solve_substitution(a, data, size, candidates);
            }
        }
        bytes_free(&owned);
    }
    j_set(a, d, "ok", j_bool(a, ok));
    j_set(a, d, "candidates", candidates);
    j_set(a, d, "error", j_str(a, error));
    return d;
}
