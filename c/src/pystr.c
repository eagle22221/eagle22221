/* Python's text semantics (see pystr.h). */
#include "pystr.h"

#include <float.h>

#include "unicode_data.h"

/* --- WTF-8 --------------------------------------------------------------------- */

uint32_t wtf8_next(const char *text, size_t n, size_t *at) {
    const uint8_t *p = (const uint8_t *)text + *at;
    size_t left = n - *at;
    uint8_t c = p[0];
    if (c < 0x80) {
        *at += 1;
        return c;
    }
    size_t need = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 0;
    if (need == 0 || need > left) {
        *at += 1;
        return 0xDC00u + c;
    }
    uint32_t cp = c & (0xFFu >> (need + 1));
    for (size_t k = 1; k < need; k++) {
        if ((p[k] & 0xC0) != 0x80) {
            *at += 1;
            return 0xDC00u + c;
        }
        cp = cp << 6 | (p[k] & 0x3Fu);
    }
    *at += need;
    return cp;
}

void wtf8_put(Buf *b, uint32_t cp) {
    char out[4];
    size_t n;
    if (cp < 0x80) {
        out[0] = (char)cp;
        n = 1;
    } else if (cp < 0x800) {
        out[0] = (char)(0xC0 | cp >> 6);
        out[1] = (char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        out[0] = (char)(0xE0 | cp >> 12);
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        out[0] = (char)(0xF0 | ((cp >> 18) & 0x07));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    buf_add(b, out, n);
}

Str wtf8_from_argument(Arena *a, const char *text) {
    size_t length = strlen(text);
    size_t i = 0;
    while (i < length && (uint8_t)text[i] < 0x80)
        i++;
    if (i == length)
        return str_copy(a, text, length);           /* plain ASCII */
    Buf b;
    buf_init(&b, a);
    buf_add(&b, text, i);
    while (i < length)
        wtf8_put(&b, utf8_next(text, length, &i));  /* strict UTF-8, else U+DCxx */
    return buf_str(&b);
}

/* --- character properties ------------------------------------------------------ */

static bool in_ranges(const UniRange *table, size_t count, uint32_t cp, uint32_t *start) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < table[mid].lo) {
            hi = mid;
        } else if (cp > table[mid].hi) {
            lo = mid + 1;
        } else {
            if (start != NULL)
                *start = table[mid].lo;
            return true;
        }
    }
    return false;
}

bool py_isspace(uint32_t cp) {
    if (cp < 0x80)      /* the same answers as the table, without the search */
        return cp == ' ' || (cp >= 0x09 && cp <= 0x0D) || (cp >= 0x1C && cp <= 0x1F);
    for (size_t i = 0; i < ARRAY_LEN(UNI_SPACE); i++)
        if (UNI_SPACE[i] == cp)
            return true;
    return false;
}

bool py_isalpha(uint32_t cp) {
    if (cp < 0x80)
        return (cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z');
    return in_ranges(UNI_ALPHA, ARRAY_LEN(UNI_ALPHA), cp, NULL);
}

bool py_isprintable(uint32_t cp) {
    if (cp < 0x80)
        return cp >= 0x20 && cp != 0x7F;
    return !in_ranges(UNI_NOT_PRINTABLE, ARRAY_LEN(UNI_NOT_PRINTABLE), cp, NULL);
}

int py_decimal(uint32_t cp) {
    if (cp < 0x80)
        return cp >= '0' && cp <= '9' ? (int)(cp - '0') : -1;
    uint32_t start;
    if (!in_ranges(UNI_DECIMAL, ARRAY_LEN(UNI_DECIMAL), cp, &start))
        return -1;
    return (int)((cp - start) % 10);
}

size_t py_upper(uint32_t cp, uint32_t out[3]) {
    out[0] = cp;
    if (cp < 0x80) {
        if (cp >= 'a' && cp <= 'z')
            out[0] = cp - 32;
        return 1;
    }
    for (size_t i = 0; i < ARRAY_LEN(UNI_UPPER_SPECIAL); i++) {
        if (UNI_UPPER_SPECIAL[i].cp == cp) {
            for (size_t k = 0; k < UNI_UPPER_SPECIAL[i].n; k++)
                out[k] = UNI_UPPER_SPECIAL[i].to[k];
            return UNI_UPPER_SPECIAL[i].n;
        }
    }
    size_t lo = 0, hi = ARRAY_LEN(UNI_UPPER);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < UNI_UPPER[mid].lo) {
            hi = mid;
        } else if (cp > UNI_UPPER[mid].hi) {
            lo = mid + 1;
        } else {
            out[0] = (uint32_t)((int64_t)cp + UNI_UPPER[mid].delta);
            break;
        }
    }
    return 1;
}

/* --- str methods --------------------------------------------------------------- */

Str py_strip(Str s) {
    size_t start = s.n, end = 0;
    for (size_t i = 0; i < s.n;) {
        size_t at = i;
        uint32_t cp = wtf8_next(s.p, s.n, &i);
        if (py_isspace(cp))
            continue;
        if (start == s.n)
            start = at;
        end = i;
    }
    if (start == s.n) {
        Str empty = {s.p, 0};
        return empty;
    }
    Str out = {s.p + start, end - start};
    return out;
}

Str py_repr_str(Arena *a, Str s) {
    bool single = false, dbl = false;
    for (size_t i = 0; i < s.n; i++) {
        if (s.p[i] == '\'')
            single = true;
        else if (s.p[i] == '"')
            dbl = true;
    }
    char quote = single && !dbl ? '"' : '\'';
    Buf b;
    buf_init(&b, a);
    buf_addch(&b, quote);
    for (size_t i = 0; i < s.n;) {
        size_t at = i;
        uint32_t cp = wtf8_next(s.p, s.n, &i);
        if (cp == (uint32_t)quote || cp == '\\') {
            buf_addch(&b, '\\');
            buf_addch(&b, (char)cp);
        } else if (cp == '\t') {
            buf_addc(&b, "\\t");
        } else if (cp == '\n') {
            buf_addc(&b, "\\n");
        } else if (cp == '\r') {
            buf_addc(&b, "\\r");
        } else if (!py_isprintable(cp)) {
            buf_add_escaped(&b, cp);
        } else {
            buf_add(&b, s.p + at, i - at);
        }
    }
    buf_addch(&b, quote);
    return buf_str(&b);
}

/* The text of a UnicodeEncodeError: the characters [start, end) of the str
 * cannot be encoded; `bad` is the first of them. */
static Str encode_error(Arena *a, const char *codec, uint32_t bad, size_t start, size_t end,
                        const char *reason) {
    Buf b;
    buf_init(&b, a);
    buf_printf(&b, "'%s' codec can't encode ", codec);
    if (end == start + 1) {
        buf_addc(&b, "character '");
        buf_add_escaped(&b, bad);
        buf_printf(&b, "' in position %zu", start);
    } else {
        buf_printf(&b, "characters in position %zu-%zu", start, end - 1);
    }
    buf_printf(&b, ": %s", reason);
    return buf_str(&b);
}

static bool is_surrogate(uint32_t cp) {
    return cp >= 0xD800 && cp <= 0xDFFF;
}

bool py_encode_utf8(Arena *a, Str s, Str *error) {
    size_t index = 0;
    for (size_t i = 0; i < s.n; index++) {
        uint32_t cp = wtf8_next(s.p, s.n, &i);
        if (!is_surrogate(cp))
            continue;
        size_t end = index + 1;
        while (i < s.n) {
            size_t peek = i;
            if (!is_surrogate(wtf8_next(s.p, s.n, &peek)))
                break;
            i = peek;
            end++;
        }
        *error = encode_error(a, "utf-8", cp, index, end, "surrogates not allowed");
        return false;
    }
    return true;
}

bool py_encode_latin1(Arena *a, Str s, Str *out, Str *error) {
    char *bytes = arena_alloc(a, s.n + 1);
    size_t count = 0, index = 0;
    for (size_t i = 0; i < s.n; index++) {
        uint32_t cp = wtf8_next(s.p, s.n, &i);
        if (cp <= 0xFF) {
            bytes[count++] = (char)cp;
            continue;
        }
        size_t end = index + 1;
        while (i < s.n) {
            size_t peek = i;
            if (wtf8_next(s.p, s.n, &peek) <= 0xFF)
                break;
            i = peek;
            end++;
        }
        *error = encode_error(a, "latin-1", cp, index, end, "ordinal not in range(256)");
        return false;
    }
    out->p = bytes;
    out->n = count;
    return true;
}

/* --- repr(float) --------------------------------------------------------------- */

/* `text` is a number as "%.Ne" writes it: [-]d[.ddd]e(+|-)XX. Writes to
 * `out` the number whose last digit is one more (step > 0) or one less. False
 * when that number has fewer digits. */
static bool neighbour(const char *text, int step, char out[48]) {
    bool negative = text[0] == '-';
    const char *p = text + negative;
    unsigned long long digits = 0;
    int count = 0;
    for (; *p != '\0' && *p != 'e'; p++) {
        if (*p == '.')
            continue;
        digits = digits * 10 + (unsigned)(*p - '0');
        count++;
    }
    long exponent = *p == 'e' ? strtol(p + 1, NULL, 10) : 0;
    unsigned long long limit = 1;       /* 10 ** count */
    for (int i = 0; i < count; i++)
        limit *= 10;
    if (step > 0) {
        if (++digits == limit) {        /* 9.99 -> 1.00, one power of ten up */
            digits = limit / 10;
            exponent++;
        }
    } else {
        if (digits <= limit / 10)
            return false;               /* 1.00 -> 0.99: a shorter number */
        digits--;
    }
    char plain[24];
    snprintf(plain, sizeof plain, "%llu", digits);
    snprintf(out, 48, "%s%c%s%se%ld", negative ? "-" : "", plain[0], count > 1 ? "." : "",
             plain + 1, exponent);
    return true;
}

Str py_repr_float(Arena *a, double value) {
    if (value != value)
        return str_c("nan");
    if (value > DBL_MAX)
        return str_c("inf");
    if (value < -DBL_MAX)
        return str_c("-inf");
    /* The shortest decimal that reads back as the same double and, of those,
     * the one nearest to it. That is the correctly rounded one ("%.Ne") or,
     * next to a power of two, where doubles are twice as dense on one side,
     * its neighbour. */
    char text[48], other[48];
    for (int precision = 0; precision <= 16; precision++) {
        snprintf(text, sizeof text, "%.*e", precision, value);
        if (strtod(text, NULL) == value)
            break;
        bool found = false;
        for (int step = 1; step >= -1 && !found; step -= 2)
            found = neighbour(text, step, other) && strtod(other, NULL) == value;
        if (found) {
            memcpy(text, other, sizeof text);
            break;
        }
    }
    /* text is [-]d[.ddd]e(+|-)XX */
    const char *p = text;
    bool negative = *p == '-';
    if (negative)
        p++;
    char digits[24];
    size_t count = 0;
    for (; *p != '\0' && *p != 'e'; p++)
        if (*p != '.' && count < sizeof digits - 1)
            digits[count++] = *p;
    while (count > 1 && digits[count - 1] == '0')
        count--;
    long exponent = *p == 'e' ? strtol(p + 1, NULL, 10) : 0;
    long point = exponent + 1;          /* the value is 0.DIGITS * 10**point */

    Buf b;
    buf_init(&b, a);
    if (negative)
        buf_addch(&b, '-');
    if (point <= -4 || point > 16) {
        buf_addch(&b, digits[0]);
        if (count > 1) {
            buf_addch(&b, '.');
            buf_add(&b, digits + 1, count - 1);
        }
        buf_printf(&b, "e%c%02ld", exponent < 0 ? '-' : '+', exponent < 0 ? -exponent : exponent);
    } else if (point <= 0) {
        buf_addc(&b, "0.");
        for (long i = point; i < 0; i++)
            buf_addch(&b, '0');
        buf_add(&b, digits, count);
    } else if ((size_t)point >= count) {
        buf_add(&b, digits, count);
        for (size_t i = count; i < (size_t)point; i++)
            buf_addch(&b, '0');
        buf_addc(&b, ".0");
    } else {
        buf_add(&b, digits, (size_t)point);
        buf_addch(&b, '.');
        buf_add(&b, digits + point, count - (size_t)point);
    }
    return buf_str(&b);
}

/* --- int(text, 0) -------------------------------------------------------------- */

#define PYINT_LIMIT ((UINT64_C(1) << 62) - 1)
/* sys.get_int_max_str_digits(): longer decimal numbers are refused. */
#define PYINT_MAX_STR_DIGITS 4300

static bool is_c_space(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

static int digit_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 10;
    return 99;
}

bool py_int_parse(Str text, PyInt *out) {
    /* Digits of any script become ASCII digits and every kind of space a
     * plain space; any other character outside ASCII ends the number. */
    char stack[128];
    char *ascii = stack;
    if (text.n >= sizeof stack) {
        ascii = malloc(text.n + 1);
        if (ascii == NULL)
            die_out_of_memory();
    }
    size_t length = 0;
    bool valid = true;
    for (size_t i = 0; i < text.n && valid;) {
        uint32_t cp = wtf8_next(text.p, text.n, &i);
        int digit;
        if (cp < 0x80)
            ascii[length++] = (char)cp;
        else if (py_isspace(cp))
            ascii[length++] = ' ';
        else if ((digit = py_decimal(cp)) >= 0)
            ascii[length++] = (char)('0' + digit);
        else
            valid = false;
    }
    const char *p = ascii, *end = ascii + length;
    PyInt value = {false, false, 0, 0};
    while (valid && p < end && is_c_space(*p))
        p++;
    if (valid && p < end && (*p == '+' || *p == '-')) {
        value.negative = *p == '-';
        p++;
    }
    unsigned base = 10;
    bool must_be_zero = false;
    if (valid && end - p >= 1 && p[0] == '0') {
        char kind = end - p >= 2 ? p[1] : '\0';
        if (kind == 'x' || kind == 'X')
            base = 16;
        else if (kind == 'o' || kind == 'O')
            base = 8;
        else if (kind == 'b' || kind == 'B')
            base = 2;
        else
            must_be_zero = true;        /* "010": only zeros may follow a zero */
        if (base != 10) {
            p += 2;
            if (p < end && *p == '_')
                p++;                    /* one underscore may follow the prefix */
        }
    }
    size_t ndigits = 0;
    char previous = '\0';
    bool nonzero = false;
    if (valid && p < end && *p == '_')
        valid = false;
    for (; valid && p < end; p++) {
        if (*p == '_') {
            if (previous == '_')
                valid = false;
            previous = '_';
            continue;
        }
        unsigned d = (unsigned)digit_value(*p);
        if (d >= base)
            break;
        previous = *p;
        ndigits++;
        if (d != 0)
            nonzero = true;
        value.low32 = value.low32 * base + d;
        if (!value.huge) {
            if (value.magnitude > (PYINT_LIMIT - d) / base)
                value.huge = true;
            else
                value.magnitude = value.magnitude * base + d;
        }
    }
    if (ndigits == 0 || previous == '_' || (must_be_zero && nonzero))
        valid = false;
    if (base == 10 && ndigits > PYINT_MAX_STR_DIGITS)
        valid = false;
    while (valid && p < end && is_c_space(*p))
        p++;
    if (p != end)
        valid = false;
    if (ascii != stack)
        free(ascii);
    if (!valid)
        return false;
    if (!nonzero)
        value.negative = false;
    if (value.negative)
        value.low32 = (uint32_t)0 - value.low32;
    *out = value;
    return true;
}

bool py_int_between(const PyInt *value, uint64_t lo, uint64_t hi) {
    if (value->huge)
        return false;
    if (value->negative)
        return false;           /* -0 is never stored */
    return value->magnitude >= lo && value->magnitude <= hi;
}
