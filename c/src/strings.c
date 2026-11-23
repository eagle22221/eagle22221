/* String extraction and tagging. The Python version uses regular expressions;
 * the matchers here are written by hand to accept exactly the same strings
 * (the extractor only ever passes printable ASCII and tabs to them). */
#include "strings.h"

/* --- character classes -------------------------------------------------------- */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static bool is_word(char c) { return is_alpha(c) || is_digit(c) || c == '_'; }
static bool is_space(char c) { return c == ' ' || (c >= '\t' && c <= '\r') ||
                                      (c >= 0x1C && c <= 0x1F); }
static bool is_printable(uint8_t c) { return (c >= 0x20 && c <= 0x7E) || c == '\t'; }

/* True when a \b word boundary lies just before s[i]. */
static bool boundary_before(const char *s, size_t n, size_t i) {
    bool left = i > 0 && is_word(s[i - 1]);
    bool right = i < n && is_word(s[i]);
    return left != right;
}

static bool starts_with(const char *s, size_t n, size_t at, const char *prefix, bool any_case) {
    for (size_t k = 0; prefix[k]; k++) {
        if (at + k >= n)
            return false;
        char c = s[at + k];
        if (any_case && c >= 'a' && c <= 'z')
            c = (char)(c - 32);
        if (c != prefix[k])
            return false;
    }
    return true;
}

/* --- \b[a-zA-Z][a-zA-Z0-9+.-]{1,9}://[^\s"'<>]{3,} ---------------------------- */

static bool is_scheme_char(char c) {
    return is_alpha(c) || is_digit(c) || c == '+' || c == '.' || c == '-';
}

static bool is_url_char(char c) {
    return !is_space(c) && c != '"' && c != '\'' && c != '<' && c != '>';
}

static bool has_url(const char *s, size_t n) {
    for (size_t k = 2; k + 6 <= n; k++) {
        if (s[k] != ':' || s[k + 1] != '/' || s[k + 2] != '/')
            continue;
        if (!is_url_char(s[k + 3]) || !is_url_char(s[k + 4]) || !is_url_char(s[k + 5]))
            continue;
        /* Walk back over the scheme: a letter at a word boundary followed by
         * one to nine scheme characters ending right before the colon. */
        for (size_t len = 1; len <= 10 && len <= k; len++) {
            size_t j = k - len;
            if (len >= 2 && is_alpha(s[j]) && boundary_before(s, n, j))
                return true;
            if (!is_scheme_char(s[j]))
                break;
        }
    }
    return false;
}

/* --- (?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.]) ------------ */

/* The look-arounds force a match to be a whole maximal run of digits and
 * dots, so each run is either a dotted quad or not a match at all. */
static bool has_ipv4(const char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (!is_digit(s[i]) && s[i] != '.') {
            i++;
            continue;
        }
        size_t parts = 0;
        bool shaped = true, in_range = true;
        while (i < n && (is_digit(s[i]) || s[i] == '.')) {
            size_t digits = 0;
            unsigned value = 0;
            while (i < n && is_digit(s[i])) {
                if (digits < 4)
                    value = value * 10 + (unsigned)(s[i] - '0');
                digits++;
                i++;
            }
            if (digits < 1 || digits > 3)
                shaped = false;
            if (value > 255)
                in_range = false;
            parts++;
            if (i < n && s[i] == '.') {
                i++;
                if (i >= n || !is_digit(s[i]))
                    shaped = false;         /* trailing or doubled dot */
            }
        }
        if (shaped && parts == 4 && in_range)
            return true;
    }
    return false;
}

/* --- \b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b ------------- */

static bool is_local_char(char c) { return is_word(c) || c == '.' || c == '+' || c == '-'; }
static bool is_domain_char(char c) { return is_alpha(c) || is_digit(c) || c == '-'; }

static bool has_email(const char *s, size_t n) {
    for (size_t at = 1; at < n; at++) {
        if (s[at] != '@')
            continue;
        /* The local part can start at a word boundary somewhere in the run of
         * local characters before the "@" exactly when the run holds a word
         * character. */
        bool word = false;
        for (size_t j = at; j > 0 && is_local_char(s[j - 1]); j--)
            if (is_word(s[j - 1]))
                word = true;
        if (!word)
            continue;
        size_t pos = at + 1;
        for (;;) {
            size_t label = pos;
            while (pos < n && is_domain_char(s[pos]))
                pos++;
            if (pos == label || pos >= n || s[pos] != '.')
                break;
            size_t tld = pos + 1, end = tld;
            while (end < n && is_alpha(s[end]))
                end++;
            if (end - tld >= 2 && (end == n || !is_word(s[end])))
                return true;
            pos = tld;
        }
    }
    return false;
}

/* --- \b(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\ (ignoring case) -------------------- */

static bool has_registry_key(const char *s, size_t n) {
    static const char *const hives[] = {"HKLM", "HKCU", "HKCR", "HKU"};
    for (size_t j = 0; j + 3 < n; j++) {
        if ((s[j] != 'H' && s[j] != 'h') || (j > 0 && is_word(s[j - 1])))
            continue;
        if (starts_with(s, n, j, "HKEY_", true)) {
            size_t end = j + 5;
            while (end < n && (is_alpha(s[end]) || s[end] == '_'))
                end++;
            if (end > j + 5 && end < n && s[end] == '\\')
                return true;
        }
        for (size_t h = 0; h < ARRAY_LEN(hives); h++) {
            size_t len = strlen(hives[h]);
            if (starts_with(s, n, j, hives[h], true) && j + len < n && s[j + len] == '\\')
                return true;
        }
    }
    return false;
}

/* --- (?<![A-Za-z])[A-Za-z]:\\[^\s:*?"<>|]+|\\\\[\w.$-]+\\[\w.$-]+ ------------- */

static bool is_unc_char(char c) { return is_word(c) || c == '.' || c == '$' || c == '-'; }

static bool has_windows_path(const char *s, size_t n) {
    for (size_t j = 0; j + 3 < n; j++) {
        if (is_alpha(s[j]) && s[j + 1] == ':' && s[j + 2] == '\\' &&
            (j == 0 || !is_alpha(s[j - 1]))) {
            char c = s[j + 3];
            if (!is_space(c) && strchr(":*?\"<>|", c) == NULL)
                return true;
        }
        if (s[j] == '\\' && s[j + 1] == '\\') {
            size_t end = j + 2;
            while (end < n && is_unc_char(s[end]))
                end++;
            if (end > j + 2 && end + 1 < n && s[end] == '\\' && is_unc_char(s[end + 1]))
                return true;
        }
    }
    return false;
}

/* --- (?<![\w/.:])/(?:[\w.+-]+/)+[\w.+-]*
 *     |(?<![\w/.:])/(?:etc|bin|tmp|usr|var|dev|proc|home|lib|opt|root|sys)/?[\w.+-]* */

static bool has_unix_path(const char *s, size_t n) {
    static const char *const roots[] = {"etc", "bin", "tmp", "usr", "var", "dev", "proc",
                                        "home", "lib", "opt", "root", "sys"};
    for (size_t j = 0; j + 1 < n; j++) {
        if (s[j] != '/')
            continue;
        if (j > 0 && (is_word(s[j - 1]) || s[j - 1] == '/' || s[j - 1] == '.' ||
                      s[j - 1] == ':'))
            continue;
        size_t end = j + 1;
        while (end < n && is_local_char(s[end]))
            end++;
        if (end > j + 1 && end < n && s[end] == '/')
            return true;
        for (size_t r = 0; r < ARRAY_LEN(roots); r++)
            if (starts_with(s, n, j + 1, roots[r], false))
                return true;
    }
    return false;
}

unsigned strings_classify(Str text) {
    const char *s = text.p;
    size_t n = text.n;
    unsigned tags = 0;
    if (has_url(s, n))
        tags |= TAG_URL;
    if (has_ipv4(s, n))
        tags |= TAG_IPV4;
    if (has_email(s, n))
        tags |= TAG_EMAIL;
    if (has_registry_key(s, n))
        tags |= TAG_REGISTRY;
    else if (!(tags & TAG_URL) && (has_windows_path(s, n) || has_unix_path(s, n)))
        tags |= TAG_PATH;
    return tags;
}

/* --- extraction --------------------------------------------------------------- */

struct SectionSpan {
    uint64_t start, end;
    Str name;
};

static int compare_spans(const void *pa, const void *pb) {
    const struct SectionSpan *a = pa, *b = pb;
    if (a->start != b->start)
        return a->start < b->start ? -1 : 1;
    if (a->end != b->end)
        return a->end < b->end ? -1 : 1;
    return str_cmp(a->name, b->name);
}

/* Name of the section whose file bytes contain offset. Sections may nest or
 * overlap; like the Python version, the last one in sorted order wins. */
static Str section_of(const StringScan *scan, uint64_t offset) {
    size_t lo = 0, hi = scan->nspans;
    while (lo < hi) {                       /* bisect_right on the start offsets */
        size_t mid = lo + (hi - lo) / 2;
        if (scan->spans[mid].start <= offset)
            lo = mid + 1;
        else
            hi = mid;
    }
    while (lo > 0) {
        const struct SectionSpan *span = &scan->spans[--lo];
        if (offset < span->end)
            return span->name;
    }
    return STR_NONE;
}

void strings_begin(StringScan *scan, const Binary *b, Arena *a, big min_length,
                   const char *encoding) {
    memset(scan, 0, sizeof *scan);
    scan->binary = b;
    if (min_length < 1)
        min_length = 1;
    scan->min_length = min_length > (big)UINT64_MAX / 4 ? UINT64_MAX / 4 : (uint64_t)min_length;
    scan->want_ascii = strcmp(encoding, "utf16") != 0;
    scan->want_utf16 = strcmp(encoding, "ascii") != 0;
    scan->spans = arena_array(a, b->sections.n, sizeof *scan->spans);
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        if (s->size) {
            struct SectionSpan span = {s->offset, s->offset + s->size, s->name};
            scan->spans[scan->nspans++] = span;
        }
    }
    if (scan->nspans > 1)
        qsort(scan->spans, scan->nspans, sizeof *scan->spans, compare_spans);
}

/* Next run of at least min_length printable bytes at or after ascii_pos. */
static void find_ascii(StringScan *scan) {
    const uint8_t *d = scan->binary->data;
    uint64_t size = scan->binary->size, i = scan->ascii_pos;
    while (i < size) {
        if (!is_printable(d[i])) {
            i++;
            continue;
        }
        uint64_t start = i;
        while (i < size && is_printable(d[i]))
            i++;
        if (i - start >= scan->min_length) {
            scan->ascii_start = start;
            scan->ascii_end = i;
            scan->ascii_pos = i;
            scan->ascii_ready = true;
            return;
        }
    }
    scan->ascii_pos = size;
}

/* Next run of at least min_length (printable byte, zero byte) pairs. A run
 * that is too short cannot contain a shorter match, so the search resumes
 * right after it. */
static void find_utf16(StringScan *scan) {
    const uint8_t *d = scan->binary->data;
    uint64_t size = scan->binary->size, i = scan->utf16_pos;
    while (i + 1 < size) {
        uint64_t pairs = 0;
        while (i + 2 * pairs + 1 < size && is_printable(d[i + 2 * pairs]) &&
               d[i + 2 * pairs + 1] == 0)
            pairs++;
        if (pairs >= scan->min_length) {
            scan->utf16_start = i;
            scan->utf16_end = i + 2 * pairs;
            scan->utf16_pos = scan->utf16_end;
            scan->utf16_ready = true;
            return;
        }
        i += 2 * pairs + 1;
    }
    scan->utf16_pos = size;
}

bool strings_next(StringScan *scan, Arena *a, FoundString *out) {
    const Binary *b = scan->binary;
    if (scan->want_ascii && !scan->ascii_ready)
        find_ascii(scan);
    if (scan->want_utf16 && !scan->utf16_ready)
        find_utf16(scan);
    bool ascii;
    if (scan->ascii_ready && scan->utf16_ready)
        ascii = scan->ascii_start <= scan->utf16_start;     /* stable: ASCII first */
    else if (scan->ascii_ready || scan->utf16_ready)
        ascii = scan->ascii_ready;
    else
        return false;
    memset(out, 0, sizeof *out);
    if (ascii) {
        out->offset = scan->ascii_start;
        out->text.p = (const char *)b->data + scan->ascii_start;
        out->text.n = (size_t)(scan->ascii_end - scan->ascii_start);
        scan->ascii_ready = false;
    } else {
        size_t n = (size_t)((scan->utf16_end - scan->utf16_start) / 2);
        char *text = arena_alloc(a, n + 1);
        for (size_t i = 0; i < n; i++)
            text[i] = (char)b->data[scan->utf16_start + 2 * i];
        out->offset = scan->utf16_start;
        out->text.p = text;
        out->text.n = n;
        out->utf16 = true;
        scan->utf16_ready = false;
    }
    out->vaddr.has = binary_offset_to_vaddr(b, out->offset, &out->vaddr.v);
    out->section = section_of(scan, out->offset);
    out->tags = strings_classify(out->text);
    return true;
}
