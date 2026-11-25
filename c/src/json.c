/* JSON document tree, writer and reader. */
#include "json.h"

#include <math.h>

static JVal *j_new(Arena *a, JKind kind) {
    JVal *v = arena_alloc(a, sizeof *v);
    v->kind = kind;
    return v;
}

JVal *j_null(Arena *a) {
    return j_new(a, J_NULL);
}

JVal *j_bool(Arena *a, bool value) {
    JVal *v = j_new(a, J_BOOL);
    v->u.flag = value;
    return v;
}

JVal *j_int(Arena *a, big value) {
    JVal *v = j_new(a, J_INT);
    v->u.number = value;
    return v;
}

JVal *j_float(Arena *a, double value) {
    JVal *v = j_new(a, J_FLOAT);
    char text[40];
    v->u.real = strtod(format_rounded(text, value), NULL);
    return v;
}

JVal *j_str(Arena *a, Str value) {
    if (value.p == NULL)
        return j_null(a);
    JVal *v = j_new(a, J_STR);
    v->u.text = value;
    return v;
}

JVal *j_cstr(Arena *a, const char *value) {
    return j_str(a, str_c(value));
}

JVal *j_raw(Arena *a, Str token) {
    JVal *v = j_new(a, J_RAW);
    v->u.text = token;
    return v;
}

JVal *j_hex(Arena *a, big value) {
    char text[40];
    hex_big(text, value);
    return j_str(a, str_copy(a, text, strlen(text)));
}

JVal *j_opt_hex(Arena *a, bool has, big value) {
    return has ? j_hex(a, value) : j_null(a);
}

JVal *j_list(Arena *a) {
    return j_new(a, J_LIST);
}

JVal *j_dict(Arena *a) {
    return j_new(a, J_DICT);
}

void j_push(Arena *a, JVal *list, JVal *item) {
    *VEC_PUSH(a, list->u.list) = item;
}

static JMember *find_member(const JVal *dict, const char *key, size_t key_len) {
    for (size_t i = 0; i < dict->u.dict.n; i++) {
        JMember *m = &dict->u.dict.v[i];
        if (m->key_len == key_len && (key_len == 0 || memcmp(m->key, key, key_len) == 0))
            return m;
    }
    return NULL;
}

static void set_member(Arena *a, JVal *dict, const char *key, size_t key_len, JVal *value) {
    JMember *found = find_member(dict, key, key_len);
    if (found != NULL) {
        found->value = value;
        return;
    }
    JMember m = {key, value, key_len};
    *VEC_PUSH(a, dict->u.dict) = m;
}

void j_set(Arena *a, JVal *dict, const char *key, JVal *value) {
    set_member(a, dict, key, strlen(key), value);
}

const JVal *j_get(const JVal *dict, const char *key) {
    return j_member(dict, str_c(key));
}

const JVal *j_member(const JVal *dict, Str key) {
    if (dict == NULL || dict->kind != J_DICT)
        return NULL;
    const JMember *found = find_member(dict, key.p, key.n);
    return found != NULL ? found->value : NULL;
}

Str j_text(const JVal *value) {
    if (value != NULL && value->kind == J_STR)
        return value->u.text;
    return str_c("");
}

big j_number(const JVal *value) {
    return value != NULL && value->kind == J_INT ? value->u.number : 0;
}

size_t j_len(const JVal *list) {
    return list != NULL && list->kind == J_LIST ? list->u.list.n : 0;
}

const JVal *j_at(const JVal *list, size_t index) {
    return index < j_len(list) ? list->u.list.v[index] : NULL;
}

bool j_truthy(const JVal *value) {
    if (value == NULL)
        return false;
    switch (value->kind) {
    case J_NULL: return false;
    case J_BOOL: return value->u.flag;
    case J_INT: return value->u.number != 0;
    case J_FLOAT: return value->u.real != 0.0;
    case J_STR: return value->u.text.n != 0;
    case J_LIST: return value->u.list.n != 0;
    case J_DICT: return value->u.dict.n != 0;
    case J_RAW: {
        /* bool() of an int or a float: only zero is false (NaN is true). */
        if (!j_raw_is_float(value)) {
            for (size_t i = 0; i < value->u.text.n; i++)
                if (value->u.text.p[i] >= '1' && value->u.text.p[i] <= '9')
                    return true;
            return false;
        }
        return j_raw_double(value) != 0.0;  /* true for NaN, as in Python */
    }
    }
    return false;
}

bool j_raw_is_float(const JVal *value) {
    if (value == NULL || value->kind != J_RAW)
        return false;
    for (size_t i = 0; i < value->u.text.n; i++) {
        char c = value->u.text.p[i];
        if (c != '-' && (c < '0' || c > '9'))
            return true;
    }
    return false;
}

const char *format_rounded(char buf[40], double value) {
    snprintf(buf, 40, "%.3f", value);
    size_t n = strlen(buf);
    while (n > 0 && buf[n - 1] == '0' && buf[n - 2] != '.')
        buf[--n] = '\0';
    return buf;
}

static void dump_string(FILE *out, Str s) {
    static const char hex[] = "0123456789abcdef";
    fputc('"', out);
    size_t i = 0;
    while (i < s.n) {
        uint8_t c = (uint8_t)s.p[i];
        if (c >= 0x80) {
            /* Strings are valid UTF-8 here (see utf8_decode). */
            size_t len = c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
            if (len > s.n - i)
                len = s.n - i;
            uint32_t cp = c & (0xFFu >> (len + 1));
            for (size_t k = 1; k < len; k++)
                cp = (cp << 6) | ((uint8_t)s.p[i + k] & 0x3F);
            i += len;
            if (cp >= 0x10000) {            /* surrogate pair, as json.dumps writes */
                cp -= 0x10000;
                fprintf(out, "\\u%04x\\u%04x", (unsigned)(0xD800 + (cp >> 10)),
                        (unsigned)(0xDC00 + (cp & 0x3FF)));
            } else {
                fprintf(out, "\\u%04x", (unsigned)cp);
            }
            continue;
        }
        i++;
        switch (c) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        case '\b': fputs("\\b", out); break;
        case '\f': fputs("\\f", out); break;
        default:
            if (c < 0x20) {
                fputs("\\u00", out);
                fputc(hex[c >> 4], out);
                fputc(hex[c & 15], out);
            } else {
                fputc(c, out);
            }
        }
    }
    fputc('"', out);
}

static void indent(FILE *out, int depth) {
    for (int i = 0; i < depth; i++)
        fputs("  ", out);
}

void j_dump(FILE *out, const JVal *value, int depth) {
    char number[44];
    switch (value->kind) {
    case J_NULL:
        fputs("null", out);
        break;
    case J_BOOL:
        fputs(value->u.flag ? "true" : "false", out);
        break;
    case J_INT:
        fputs(dec_big(number, value->u.number), out);
        break;
    case J_FLOAT:
        fputs(format_rounded(number, value->u.real), out);
        break;
    case J_STR:
        dump_string(out, value->u.text);
        break;
    case J_RAW:
        fwrite(value->u.text.p, 1, value->u.text.n, out);
        break;
    case J_LIST:
        if (value->u.list.n == 0) {
            fputs("[]", out);
            break;
        }
        fputs("[\n", out);
        for (size_t i = 0; i < value->u.list.n; i++) {
            indent(out, depth + 1);
            j_dump(out, value->u.list.v[i], depth + 1);
            fputs(i + 1 < value->u.list.n ? ",\n" : "\n", out);
        }
        indent(out, depth);
        fputc(']', out);
        break;
    case J_DICT:
        if (value->u.dict.n == 0) {
            fputs("{}", out);
            break;
        }
        fputs("{\n", out);
        for (size_t i = 0; i < value->u.dict.n; i++) {
            indent(out, depth + 1);
            dump_string(out, (Str){value->u.dict.v[i].key, value->u.dict.v[i].key_len});
            fputs(": ", out);
            j_dump(out, value->u.dict.v[i].value, depth + 1);
            fputs(i + 1 < value->u.dict.n ? ",\n" : "\n", out);
        }
        indent(out, depth);
        fputc('}', out);
        break;
    }
}

/* --- reader -------------------------------------------------------------------- */

double j_raw_double(const JVal *value) {
    if (value == NULL || value->kind != J_RAW || value->u.text.n == 0)
        return 0.0;
    const char *text = value->u.text.p;
    if (text[0] == 'N')
        return (double)NAN;
    if (text[0] == 'I')
        return (double)INFINITY;
    if (text[0] == '-' && value->u.text.n > 1 && text[1] == 'I')
        return -(double)INFINITY;
    return strtod(text, NULL);              /* the token is NUL-terminated */
}

typedef struct {
    Arena *a;
    const char *p;              /* the document, as WTF-8 */
    size_t n, at;
    int depth;
} JReader;

static void put_code_point(Buf *b, uint32_t cp) {
    char out[4];
    size_t n;
    if (cp < 0x80) {
        out[0] = (char)cp;
        n = 1;
    } else if (cp < 0x800) {
        out[0] = (char)(0xC0 | cp >> 6);
        out[1] = (char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {      /* a surrogate included: WTF-8 */
        out[0] = (char)(0xE0 | cp >> 12);
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        out[0] = (char)(0xF0 | cp >> 18);
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    buf_add(b, out, n);
}

static bool continuation(uint8_t c) {
    return (c & 0xC0) == 0x80;
}

/* bytes.decode("utf-8", "surrogatepass"): is this valid UTF-8 in which a
 * surrogate may be written as three bytes? */
static bool valid_wtf8(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = p[i];
        size_t left = n - i;
        if (c < 0x80) {
            i++;
        } else if (c >= 0xC2 && c <= 0xDF) {
            if (left < 2 || !continuation(p[i + 1]))
                return false;
            i += 2;
        } else if (c >= 0xE0 && c <= 0xEF) {
            if (left < 3 || !continuation(p[i + 1]) || !continuation(p[i + 2]))
                return false;
            if (c == 0xE0 && p[i + 1] < 0xA0)
                return false;               /* overlong */
            i += 3;                         /* ED A0..BF xx is a surrogate: let through */
        } else if (c >= 0xF0 && c <= 0xF4) {
            if (left < 4 || !continuation(p[i + 1]) || !continuation(p[i + 2]) ||
                !continuation(p[i + 3]))
                return false;
            if ((c == 0xF0 && p[i + 1] < 0x90) || (c == 0xF4 && p[i + 1] >= 0x90))
                return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

/* UTF-16 or UTF-32 to WTF-8, as the codec does with "surrogatepass": false
 * for a truncated unit or a code point above U+10FFFF. */
static bool transcode(Buf *out, const uint8_t *p, size_t n, unsigned unit, bool big_endian) {
    if (n % unit != 0)
        return false;
    for (size_t i = 0; i < n; i += unit) {
        uint32_t cp = 0;
        for (unsigned k = 0; k < unit; k++)
            cp |= (uint32_t)p[i + k] << (8 * (big_endian ? unit - 1 - k : k));
        if (unit == 2 && cp >= 0xD800 && cp <= 0xDBFF && n - i >= 4) {
            uint32_t low = 0;
            for (unsigned k = 0; k < 2; k++)
                low |= (uint32_t)p[i + 2 + k] << (8 * (big_endian ? 1 - k : k));
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                i += 2;
            }
        }
        if (cp > 0x10FFFF)
            return false;
        put_code_point(out, cp);
    }
    return true;
}

/* The document as text: json.detect_encoding(), then decode. */
static bool decode_document(JReader *r, const uint8_t *p, size_t n) {
    unsigned unit = 0;          /* 0: UTF-8 */
    bool big_endian = false;
    size_t skip = 0;
    if (n >= 4 && ((p[0] == 0 && p[1] == 0 && p[2] == 0xFE && p[3] == 0xFF) ||
                   (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0 && p[3] == 0))) {
        unit = 4;
        big_endian = p[0] == 0;
        skip = 4;
    } else if (n >= 2 && ((p[0] == 0xFE && p[1] == 0xFF) || (p[0] == 0xFF && p[1] == 0xFE))) {
        unit = 2;
        big_endian = p[0] == 0xFE;
        skip = 2;
    } else if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
        skip = 3;
    } else if (n >= 4) {
        if (p[0] == 0) {
            unit = p[1] != 0 ? 2 : 4;
            big_endian = true;
        } else if (p[1] == 0) {
            unit = (p[2] != 0 || p[3] != 0) ? 2 : 4;
        }
    } else if (n == 2) {
        if (p[0] == 0) {
            unit = 2;
            big_endian = true;
        } else if (p[1] == 0) {
            unit = 2;
        }
    }
    if (unit == 0) {
        if (!valid_wtf8(p + skip, n - skip))
            return false;
        r->p = (const char *)p + skip;
        r->n = n - skip;
        return true;
    }
    Buf text;
    buf_init(&text, r->a);
    if (!transcode(&text, p + skip, n - skip, unit, big_endian))
        return false;
    Str s = buf_str(&text);
    r->p = s.p;
    r->n = s.n;
    return true;
}

static void skip_space(JReader *r) {
    while (r->at < r->n) {
        char c = r->p[r->at];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            break;
        r->at++;
    }
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Four hex digits at `at`, or -1. */
static long hex4(const JReader *r, size_t at) {
    if (r->n - at < 4)
        return -1;
    long value = 0;
    for (size_t k = 0; k < 4; k++) {
        int d = hex_digit(r->p[at + k]);
        if (d < 0)
            return -1;
        value = value << 4 | d;
    }
    return value;
}

/* The string whose opening quote was just passed. */
static bool read_string(JReader *r, Str *out) {
    size_t start = r->at;
    /* Without an escape the string is a slice of the document. */
    size_t i = start;
    while (i < r->n && r->p[i] != '"' && r->p[i] != '\\') {
        if ((uint8_t)r->p[i] < 0x20)
            return false;
        i++;
    }
    if (i == r->n)
        return false;                       /* unterminated */
    if (r->p[i] == '"') {
        *out = str_copy(r->a, r->p + start, i - start);
        r->at = i + 1;
        return true;
    }
    Buf b;
    buf_init(&b, r->a);
    buf_add(&b, r->p + start, i - start);
    for (;;) {
        if (i == r->n)
            return false;
        char c = r->p[i];
        if (c == '"') {
            i++;
            break;
        }
        if ((uint8_t)c < 0x20)
            return false;
        if (c != '\\') {
            size_t run = i;
            while (run < r->n && r->p[run] != '"' && r->p[run] != '\\' &&
                   (uint8_t)r->p[run] >= 0x20)
                run++;
            buf_add(&b, r->p + i, run - i);
            i = run;
            continue;
        }
        if (++i == r->n)
            return false;
        c = r->p[i++];
        switch (c) {
        case '"': buf_addch(&b, '"'); break;
        case '\\': buf_addch(&b, '\\'); break;
        case '/': buf_addch(&b, '/'); break;
        case 'b': buf_addch(&b, '\b'); break;
        case 'f': buf_addch(&b, '\f'); break;
        case 'n': buf_addch(&b, '\n'); break;
        case 'r': buf_addch(&b, '\r'); break;
        case 't': buf_addch(&b, '\t'); break;
        case 'u': {
            long cp = hex4(r, i);
            if (cp < 0)
                return false;
            i += 4;
            /* A high surrogate and a low one written as two escapes make
             * one character; a surrogate on its own stays what it is. */
            if (cp >= 0xD800 && cp <= 0xDBFF && r->n - i >= 6 && r->p[i] == '\\' &&
                r->p[i + 1] == 'u') {
                long low = hex4(r, i + 2);
                if (low < 0)
                    return false;
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    i += 6;
                }
            }
            put_code_point(&b, (uint32_t)cp);
            break;
        }
        default:
            return false;
        }
    }
    *out = buf_str(&b);
    r->at = i;
    return true;
}

static bool is_digit(const JReader *r, size_t at) {
    return at < r->n && r->p[at] >= '0' && r->p[at] <= '9';
}

static bool literal(JReader *r, const char *word) {
    size_t length = strlen(word);
    if (r->n - r->at < length || memcmp(r->p + r->at, word, length) != 0)
        return false;
    r->at += length;
    return true;
}

/* sys.get_int_max_str_digits(): int() refuses longer decimal numbers. */
#define J_MAX_INT_DIGITS 4300

static JVal *read_number(JReader *r) {
    size_t start = r->at, i = r->at;
    if (i < r->n && r->p[i] == '-')
        i++;
    if (is_digit(r, i) && r->p[i] != '0') {
        while (is_digit(r, i))
            i++;
    } else if (is_digit(r, i)) {
        i++;                                /* a zero stands alone */
    } else {
        return NULL;
    }
    size_t int_end = i;
    bool is_float = false;
    if (i < r->n && r->p[i] == '.' && is_digit(r, i + 1)) {
        is_float = true;
        i += 2;
        while (is_digit(r, i))
            i++;
    }
    if (i < r->n && (r->p[i] == 'e' || r->p[i] == 'E')) {
        size_t e = i + 1;
        if (e < r->n && (r->p[e] == '-' || r->p[e] == '+'))
            e++;
        if (is_digit(r, e)) {
            is_float = true;
            while (is_digit(r, e))
                e++;
            i = e;
        }
    }
    if (!is_float) {
        size_t digits = int_end - start - (r->p[start] == '-' ? 1 : 0);
        if (digits > J_MAX_INT_DIGITS)
            return NULL;
    }
    r->at = i;
    return j_raw(r->a, str_copy(r->a, r->p + start, i - start));
}

static JVal *read_value(JReader *r);

static JVal *read_list(JReader *r) {
    JVal *list = j_list(r->a);
    skip_space(r);
    if (r->at < r->n && r->p[r->at] == ']') {
        r->at++;
        return list;
    }
    for (;;) {
        JVal *item = read_value(r);
        if (item == NULL)
            return NULL;
        j_push(r->a, list, item);
        skip_space(r);
        if (r->at < r->n && r->p[r->at] == ']') {
            r->at++;
            return list;
        }
        if (r->at >= r->n || r->p[r->at] != ',')
            return NULL;
        r->at++;
        skip_space(r);
    }
}

static JVal *read_dict(JReader *r) {
    JVal *dict = j_dict(r->a);
    skip_space(r);
    if (r->at < r->n && r->p[r->at] == '}') {
        r->at++;
        return dict;
    }
    for (;;) {
        if (r->at >= r->n || r->p[r->at] != '"')
            return NULL;
        r->at++;
        Str key;
        if (!read_string(r, &key))
            return NULL;
        skip_space(r);
        if (r->at >= r->n || r->p[r->at] != ':')
            return NULL;
        r->at++;
        skip_space(r);
        JVal *value = read_value(r);
        if (value == NULL)
            return NULL;
        set_member(r->a, dict, key.p, key.n, value);
        skip_space(r);
        if (r->at < r->n && r->p[r->at] == '}') {
            r->at++;
            return dict;
        }
        if (r->at >= r->n || r->p[r->at] != ',')
            return NULL;
        r->at++;
        skip_space(r);
    }
}

static JVal *read_value(JReader *r) {
    if (r->at >= r->n)
        return NULL;
    JVal *value = NULL;
    switch (r->p[r->at]) {
    case '"': {
        Str text;
        r->at++;
        if (read_string(r, &text))
            value = j_str(r->a, text);
        break;
    }
    case '{':
    case '[': {
        if (r->depth >= J_MAX_DEPTH)
            return NULL;
        bool is_dict = r->p[r->at] == '{';
        r->depth++;
        r->at++;
        value = is_dict ? read_dict(r) : read_list(r);
        r->depth--;
        break;
    }
    case 'n':
        if (literal(r, "null"))
            value = j_null(r->a);
        break;
    case 't':
        if (literal(r, "true"))
            value = j_bool(r->a, true);
        break;
    case 'f':
        if (literal(r, "false"))
            value = j_bool(r->a, false);
        break;
    case 'N':
        if (literal(r, "NaN"))
            value = j_raw(r->a, str_c("NaN"));
        break;
    case 'I':
        if (literal(r, "Infinity"))
            value = j_raw(r->a, str_c("Infinity"));
        break;
    case '-':
        if (literal(r, "-Infinity"))
            value = j_raw(r->a, str_c("-Infinity"));
        else
            value = read_number(r);
        break;
    default:
        value = read_number(r);
    }
    return value;
}

JVal *j_parse(Arena *a, const uint8_t *data, size_t size) {
    JReader r = {a, NULL, 0, 0, 0};
    if (!decode_document(&r, data, size))
        return NULL;
    skip_space(&r);
    JVal *value = read_value(&r);
    if (value == NULL)
        return NULL;
    skip_space(&r);
    return r.at == r.n ? value : NULL;
}
