/* Arena memory, strings, number formatting and the error mechanism. */
#include "common.h"

NORETURN void die_out_of_memory(void) {
    fputs("binspect: error: out of memory\n", stderr);
    exit(1);
}

/* --- arena ------------------------------------------------------------------- */

#define ARENA_BLOCK_SIZE ((size_t)64 * 1024)
#define ARENA_ALIGN ((size_t)16)

struct ArenaBlock {
    ArenaBlock *next;
    size_t used, cap;
    /* payload follows the header, rounded up to ARENA_ALIGN */
};

static size_t block_header_size(void) {
    return (sizeof(ArenaBlock) + ARENA_ALIGN - 1) & ~(ARENA_ALIGN - 1);
}

void *arena_alloc(Arena *a, size_t size) {
    if (size > SIZE_MAX / 2)
        die_out_of_memory();
    size = (size + ARENA_ALIGN - 1) & ~(ARENA_ALIGN - 1);
    if (size == 0)
        size = ARENA_ALIGN;
    ArenaBlock *block = a->head;
    if (block == NULL || block->cap - block->used < size) {
        size_t cap = size > ARENA_BLOCK_SIZE ? size : ARENA_BLOCK_SIZE;
        ArenaBlock *fresh = malloc(block_header_size() + cap);
        if (fresh == NULL)
            die_out_of_memory();
        fresh->used = 0;
        fresh->cap = cap;
        if (block != NULL && cap == size && size > ARENA_BLOCK_SIZE) {
            /* A dedicated block for one large request: keep filling the
             * current block afterwards instead of abandoning its free space. */
            fresh->next = block->next;
            block->next = fresh;
        } else {
            fresh->next = block;
            a->head = fresh;
        }
        block = fresh;
    }
    void *p = (char *)block + block_header_size() + block->used;
    block->used += size;
    memset(p, 0, size);
    return p;
}

void *arena_array(Arena *a, size_t count, size_t item_size) {
    if (item_size != 0 && count > SIZE_MAX / 2 / item_size)
        die_out_of_memory();
    return arena_alloc(a, count * item_size);
}

struct ArenaAdopted {
    struct ArenaAdopted *next;
    void *buffer;
};

void arena_adopt(Arena *a, void *buffer) {
    struct ArenaAdopted *node = arena_alloc(a, sizeof *node);
    node->buffer = buffer;
    node->next = a->adopted;
    a->adopted = node;
}

void arena_release(Arena *a) {
    for (struct ArenaAdopted *node = a->adopted; node != NULL; node = node->next)
        free(node->buffer);
    a->adopted = NULL;
    ArenaBlock *block = a->head;
    while (block != NULL) {
        ArenaBlock *next = block->next;
        free(block);
        block = next;
    }
    a->head = NULL;
}

void *vec_grow(Arena *a, void *items, size_t *cap, size_t item_size) {
    size_t old = *cap;
    size_t wanted = old ? old * 2 : 8;
    void *fresh = arena_array(a, wanted, item_size);
    if (old)
        memcpy(fresh, items, old * item_size);
    *cap = wanted;
    return fresh;
}

/* --- strings ----------------------------------------------------------------- */

Str str_c(const char *text) {
    Str s = {text, text ? strlen(text) : 0};
    return s;
}

Str str_copy(Arena *a, const char *p, size_t n) {
    char *copy = arena_alloc(a, n + 1);
    if (n)
        memcpy(copy, p, n);
    copy[n] = '\0';
    Str s = {copy, n};
    return s;
}

Str str_printf(Arena *a, const char *fmt, ...) {
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
    Str s = {text, (size_t)n};
    return s;
}

bool str_eq(Str a, Str b) {
    if ((a.p == NULL) != (b.p == NULL) || a.n != b.n)
        return false;
    return a.n == 0 || memcmp(a.p, b.p, a.n) == 0;
}

bool str_eq_c(Str a, const char *text) {
    return str_eq(a, str_c(text));
}

int str_cmp(Str a, Str b) {
    size_t common = a.n < b.n ? a.n : b.n;
    int order = common ? memcmp(a.p, b.p, common) : 0;
    if (order != 0)
        return order;
    return (a.n > b.n) - (a.n < b.n);
}

bool str_contains(Str haystack, Str needle) {
    if (needle.n == 0)
        return true;
    if (needle.n > haystack.n)
        return false;
    const char first = needle.p[0];
    size_t last = haystack.n - needle.n;
    for (size_t i = 0; i <= last; i++) {
        const char *hit = memchr(haystack.p + i, first, last - i + 1);
        if (hit == NULL)
            return false;
        i = (size_t)(hit - haystack.p);
        if (memcmp(hit, needle.p, needle.n) == 0)
            return true;
    }
    return false;
}

bool str_ends_with(Str s, const char *suffix) {
    size_t n = strlen(suffix);
    return s.n >= n && memcmp(s.p + s.n - n, suffix, n) == 0;
}

uint64_t str_hash(Str s) {
    uint64_t h = UINT64_C(0xcbf29ce484222325);      /* FNV-1a */
    for (size_t i = 0; i < s.n; i++) {
        h ^= (uint8_t)s.p[i];
        h *= UINT64_C(0x100000001b3);
    }
    return h;
}

size_t utf8_length(Str s) {
    size_t count = 0;
    for (size_t i = 0; i < s.n; i++)
        if (((uint8_t)s.p[i] & 0xC0) != 0x80)
            count++;
    return count;
}

static bool is_continuation(uint8_t c) {
    return (c & 0xC0) == 0x80;
}

/* Length of the valid UTF-8 sequence at p (1..4), or 0 with *bad set to the
 * number of bytes CPython's decoder replaces by one U+FFFD. */
static size_t utf8_sequence(const uint8_t *p, size_t left, size_t *bad) {
    uint8_t c = p[0];
    if (c < 0x80)
        return 1;
    if (c < 0xC2 || c > 0xF4) {
        *bad = 1;
        return 0;
    }
    if (c < 0xE0) {
        if (left < 2 || !is_continuation(p[1])) {
            *bad = 1;
            return 0;
        }
        return 2;
    }
    if (c < 0xF0) {
        if (left < 2) {
            *bad = 1;                       /* cut off: the rest of the input */
            return 0;
        }
        uint8_t c2 = p[1];
        if (!is_continuation(c2) || (c == 0xE0 && c2 < 0xA0) || (c == 0xED && c2 >= 0xA0)) {
            *bad = 1;
            return 0;
        }
        if (left < 3) {
            *bad = 2;
            return 0;
        }
        if (!is_continuation(p[2])) {
            *bad = 2;
            return 0;
        }
        return 3;
    }
    if (left < 2) {
        *bad = 1;
        return 0;
    }
    uint8_t c2 = p[1];
    if (!is_continuation(c2) || (c == 0xF0 && c2 < 0x90) || (c == 0xF4 && c2 >= 0x90)) {
        *bad = 1;
        return 0;
    }
    if (left < 3 || !is_continuation(p[2])) {
        *bad = 2;
        return 0;
    }
    if (left < 4 || !is_continuation(p[3])) {
        *bad = 3;
        return 0;
    }
    return 4;
}

Str utf8_decode(Arena *a, const uint8_t *bytes, size_t n) {
    size_t i = 0;
    while (i < n && bytes[i] < 0x80)
        i++;
    if (i == n)
        return str_copy(a, (const char *)bytes, n);    /* plain ASCII */
    if (n > SIZE_MAX / 4)
        die_out_of_memory();
    char *out = arena_alloc(a, n * 3 + 1);
    size_t used = i;
    memcpy(out, bytes, i);
    while (i < n) {
        size_t bad = 0;
        size_t len = utf8_sequence(bytes + i, n - i, &bad);
        if (len) {
            memcpy(out + used, bytes + i, len);
            used += len;
            i += len;
        } else {
            memcpy(out + used, "\xEF\xBF\xBD", 3);
            used += 3;
            i += bad;
        }
    }
    out[used] = '\0';
    Str s = {out, used};
    return s;
}

/* Code point starting at s.p[i] of valid UTF-8; *len receives its size. */
static uint32_t utf8_at(Str s, size_t i, size_t *len) {
    uint8_t c = (uint8_t)s.p[i];
    size_t need = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
    if (need > s.n - i)
        need = 1;
    *len = need;
    if (need == 1)
        return c;
    uint32_t cp = c & (0xFF >> (need + 1));
    for (size_t k = 1; k < need; k++)
        cp = (cp << 6) | ((uint8_t)s.p[i + k] & 0x3F);
    return cp;
}

/* str.isspace() for one character. */
static bool is_py_space(uint32_t cp) {
    return (cp >= 0x09 && cp <= 0x0D) || (cp >= 0x1C && cp <= 0x20) || cp == 0x85 ||
           cp == 0xA0 || cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200A) || cp == 0x2028 ||
           cp == 0x2029 || cp == 0x202F || cp == 0x205F || cp == 0x3000;
}

Str str_strip(Str s) {
    size_t start = 0, end = s.n;
    while (start < end) {
        size_t len;
        if (!is_py_space(utf8_at(s, start, &len)))
            break;
        start += len;
    }
    while (end > start) {
        size_t back = end - 1;
        while (back > start && ((uint8_t)s.p[back] & 0xC0) == 0x80)
            back--;
        size_t len;
        if (!is_py_space(utf8_at(s, back, &len)))
            break;
        end = back;
    }
    Str out = {s.p + start, end - start};
    return out;
}

Str str_lower_ascii(Arena *a, Str s) {
    char *out = arena_alloc(a, s.n + 1);
    for (size_t i = 0; i < s.n; i++) {
        char c = s.p[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    Str lowered = {out, s.n};
    return lowered;
}

/* --- text buffer ------------------------------------------------------------- */

void buf_init(Buf *b, Arena *a) {
    b->arena = a;
    b->p = NULL;
    b->n = 0;
    b->cap = 0;
}

static void buf_reserve(Buf *b, size_t extra) {
    if (extra > SIZE_MAX / 4 - b->n)
        die_out_of_memory();
    size_t need = b->n + extra + 1;
    if (need <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < need)
        cap *= 2;
    char *fresh = arena_alloc(b->arena, cap);
    if (b->n)
        memcpy(fresh, b->p, b->n);
    b->p = fresh;
    b->cap = cap;
}

void buf_add(Buf *b, const char *p, size_t n) {
    buf_reserve(b, n);
    if (n)
        memcpy(b->p + b->n, p, n);
    b->n += n;
    b->p[b->n] = '\0';
}

void buf_adds(Buf *b, Str s) {
    buf_add(b, s.p, s.n);
}

void buf_addc(Buf *b, const char *text) {
    buf_add(b, text, strlen(text));
}

void buf_addch(Buf *b, char c) {
    buf_add(b, &c, 1);
}

void buf_printf(Buf *b, const char *fmt, ...) {
    va_list args, again;
    va_start(args, fmt);
    va_copy(again, args);
    int n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (n > 0) {
        buf_reserve(b, (size_t)n);
        vsnprintf(b->p + b->n, (size_t)n + 1, fmt, again);
        b->n += (size_t)n;
    }
    va_end(again);
}

Str buf_str(const Buf *b) {
    Str s = {b->p ? b->p : "", b->n};
    return s;
}

/* --- numbers ----------------------------------------------------------------- */

static const char *format_big(char *buf, size_t size, big value, unsigned base,
                              const char *prefix) {
    ubig magnitude = value < 0 ? (ubig)0 - (ubig)value : (ubig)value;
    char digits[48];
    size_t count = 0;
    do {
        digits[count++] = "0123456789abcdef"[(unsigned)(magnitude % base)];
        magnitude /= base;
    } while (magnitude != 0);
    size_t pos = 0;
    if (value < 0)
        buf[pos++] = '-';
    for (const char *p = prefix; *p; p++)
        buf[pos++] = *p;
    while (count > 0 && pos + 1 < size)
        buf[pos++] = digits[--count];
    buf[pos] = '\0';
    return buf;
}

const char *hex_big(char buf[40], big value) {
    return format_big(buf, 40, value, 16, "0x");
}

const char *dec_big(char buf[44], big value) {
    return format_big(buf, 44, value, 10, "");
}

static bool is_ascii_space(char c) {
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

bool parse_int(const char *text, bool any_base, big *out) {
    const char *p = text;
    const char *end = text + strlen(text);
    while (p < end && is_ascii_space(*p))
        p++;
    while (end > p && is_ascii_space(end[-1]))
        end--;
    bool negative = false;
    if (p < end && (*p == '+' || *p == '-')) {
        negative = *p == '-';
        p++;
    }
    int base = 10;
    bool prefixed = false;
    if (any_base && end - p >= 2 && p[0] == '0') {
        char kind = p[1];
        if (kind == 'x' || kind == 'X')
            base = 16;
        else if (kind == 'o' || kind == 'O')
            base = 8;
        else if (kind == 'b' || kind == 'B')
            base = 2;
        if (base != 10) {
            p += 2;
            prefixed = true;
        }
    }
    if (p == end)
        return false;
    /* One underscore may separate digits (and follow a base prefix). */
    bool leading_zero = any_base && !prefixed && *p == '0';
    bool nonzero = false;
    bool want_digit = true;
    big value = 0;
    const big limit = (big)1 << 126;
    if (prefixed && *p == '_')
        p++;
    for (; p < end; p++) {
        if (*p == '_') {
            if (want_digit)
                return false;
            want_digit = true;
            continue;
        }
        int d = digit_value(*p);
        if (d >= base)
            return false;
        if (d != 0)
            nonzero = true;
        value = value * base + d;
        if (value >= limit)
            return false;
        want_digit = false;
    }
    if (want_digit)
        return false;
    if (leading_zero && nonzero)
        return false;                       /* int("010", 0) is an error */
    *out = negative ? -value : value;
    return true;
}

/* --- errors ------------------------------------------------------------------ */

static void err_format(Err *e, ErrKind kind, const char *fmt, va_list args) {
    va_list again;
    va_copy(again, args);
    int n = vsnprintf(NULL, 0, fmt, args);
    if (n < 0)
        n = 0;
    char *msg = malloc((size_t)n + 1);
    if (msg == NULL)
        die_out_of_memory();
    vsnprintf(msg, (size_t)n + 1, fmt, again);      /* may read the old e->msg */
    va_end(again);
    free(e->msg);
    e->msg = msg;
    e->cap = (size_t)n + 1;
    e->kind = kind;
}

void err_set(Err *e, ErrKind kind, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    err_format(e, kind, fmt, args);
    va_end(args);
}

NORETURN void err_raise(Err *e) {
    ErrFrame *frame = e->top;
    if (frame == NULL) {
        fprintf(stderr, "binspect: error: %s\n", e->msg ? e->msg : "internal error");
        exit(1);
    }
    e->top = frame->prev;
    longjmp(frame->env, 1);
}

NORETURN void err_throw(Err *e, ErrKind kind, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    err_format(e, kind, fmt, args);
    va_end(args);
    err_raise(e);
}

bool err_protect(Err *e, void (*fn)(void *), void *arg) {
    ErrFrame frame;
    frame.prev = e->top;
    e->top = &frame;
    if (setjmp(frame.env) == 0) {
        fn(arg);
        e->top = frame.prev;
        return true;
    }
    return false;                           /* err_raise() popped the frame */
}

void err_release(Err *e) {
    free(e->msg);
    e->msg = NULL;
    e->cap = 0;
}
