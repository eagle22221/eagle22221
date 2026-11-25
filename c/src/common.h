/* Shared basics for every vex source file: integer types, memory,
 * strings and the error mechanism. Must be the first include everywhere. */
#ifndef VEX_COMMON_H
#define VEX_COMMON_H

/* MinGW: use the C99 printf family (%zu, %llu) instead of msvcrt's. */
#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VEX_VERSION "0.1.0"

/* The Python reference computes file offsets with unbounded integers, so a
 * hostile header can produce sums above 2**64 or below zero and they must
 * still compare (and print) correctly instead of wrapping around to a valid
 * offset. `big` holds every such intermediate value exactly. It is the one
 * compiler extension vex relies on; gcc, clang and MinGW-w64 provide it
 * on all 64-bit targets. */
#if defined(__SIZEOF_INT128__)
__extension__ typedef __int128 big;
__extension__ typedef unsigned __int128 ubig;
#else
#error "vex needs a 128-bit integer type (gcc, clang or MinGW-w64, 64-bit target)"
#endif

#if defined(__MINGW32__)
#define PRINTF_LIKE(f, a) __attribute__((format(gnu_printf, f, a)))
#elif defined(__GNUC__)
#define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#else
#define PRINTF_LIKE(f, a)
#endif
#if defined(__GNUC__)
#define NORETURN __attribute__((noreturn))
#else
#define NORETURN
#endif

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

/* --- memory ------------------------------------------------------------------
 * Everything a command allocates lives in one arena that is released in a
 * single call when the command is done. That keeps error paths (which unwind
 * with longjmp, see Err below) free of leaks by construction. */

typedef struct ArenaBlock ArenaBlock;
typedef struct {
    ArenaBlock *head;
    struct ArenaCleanup *cleanups;
} Arena;

void *arena_alloc(Arena *a, size_t size);            /* zero-filled */
void *arena_array(Arena *a, size_t count, size_t item_size);
/* Hand a malloc'ed buffer to the arena, to be freed with it. */
void arena_adopt(Arena *a, void *buffer);
/* Call fn(arg) when the arena is released (most recent first). */
void arena_on_release(Arena *a, void (*fn)(void *), void *arg);
void arena_release(Arena *a);

/* Growable array whose storage lives in an arena. */
#define VEC(T) struct { T *v; size_t n, cap; }
void *vec_grow(Arena *a, void *items, size_t *cap, size_t item_size);
#define VEC_PUSH(a, vec) \
    (((vec).n == (vec).cap \
          ? ((vec).v = vec_grow((a), (vec).v, &(vec).cap, sizeof *(vec).v)) \
          : (vec).v), \
     &(vec).v[(vec).n++])

/* --- strings -----------------------------------------------------------------
 * Text decoded from a binary may contain any character, including NUL, so a
 * string is a pointer plus a length. p == NULL means "no value" (Python's
 * None), which is different from the empty string. Strings made by the
 * functions below are also NUL-terminated for use with printf. */

typedef struct {
    const char *p;
    size_t n;
} Str;

struct Buf;

#define STR_NONE ((Str){NULL, 0})

Str str_c(const char *text);                         /* wraps, does not copy */
Str str_copy(Arena *a, const char *p, size_t n);
Str str_printf(Arena *a, const char *fmt, ...) PRINTF_LIKE(2, 3);
bool str_eq(Str a, Str b);
bool str_eq_c(Str a, const char *text);
int str_cmp(Str a, Str b);                           /* by byte, then length */
bool str_contains(Str haystack, Str needle);
bool str_ends_with(Str s, const char *suffix);
uint64_t str_hash(Str s);
size_t utf8_length(Str s);                           /* code points */

/* bytes.decode("utf-8", errors="replace"): invalid input becomes U+FFFD
 * exactly where CPython puts it. The result is always valid UTF-8. */
Str utf8_decode(Arena *a, const uint8_t *bytes, size_t n);
/* str.strip() */
Str str_strip(Str s);
/* Next code point of text that should be UTF-8, advancing *at. Bytes that
 * are not valid UTF-8 come back as 0xDC80..0xDCFF, the way Python reads
 * such command-line arguments (surrogateescape). */
uint32_t utf8_next(const char *text, size_t length, size_t *at);
/* repr() of a Python str holding the given command-line argument. */
Str py_repr(Arena *a, const char *text);
/* "\xe9", "\u20ac" or "\U0001f600": how repr() escapes a character. */
void buf_add_escaped(struct Buf *b, uint32_t code_point);
/* ASCII-only str.lower() */
Str str_lower_ascii(Arena *a, Str s);

/* Growable text buffer (arena-backed). */
typedef struct Buf {
    Arena *arena;
    char *p;
    size_t n, cap;
} Buf;

void buf_init(Buf *b, Arena *a);
void buf_add(Buf *b, const char *p, size_t n);
void buf_adds(Buf *b, Str s);
void buf_addc(Buf *b, const char *text);
void buf_addch(Buf *b, char c);
void buf_printf(Buf *b, const char *fmt, ...) PRINTF_LIKE(2, 3);
Str buf_str(const Buf *b);

/* --- numbers ----------------------------------------------------------------- */

/* f"{value:#x}" for any integer: "0x1f", "-0x1f". buf needs 40 bytes. */
const char *hex_big(char buf[40], big value);
/* str(value) for any integer. buf needs 44 bytes. */
const char *dec_big(char buf[44], big value);
/* int(text, 0) when any_base, else int(text): false when Python would raise
 * ValueError (or the value needs more than 126 bits). */
bool parse_int(const char *text, bool any_base, big *out);

/* --- errors ------------------------------------------------------------------
 * The Python code signals problems with exceptions and catches them at
 * well-defined places (one corrupt table costs a warning, not the analysis).
 * The C port keeps that structure: err_throw() unwinds to the innermost
 * err_protect() call, which reports failure to its caller. */

typedef enum {
    ERR_NONE = 0,
    ERR_PARSE,              /* ParseError: truncated or corrupt input */
    ERR_UNKNOWN_FORMAT,     /* UnknownFormatError: neither ELF nor PE */
    ERR_LOCATION,           /* LocationError: unresolvable name/address */
    ERR_UNSUPPORTED,        /* UnsupportedError */
    ERR_NO_DISASSEMBLER,    /* MissingDependencyError */
    ERR_OTHER,              /* plain VexError */
    ERR_OS,                 /* file could not be read or written */
    ERR_USAGE,              /* bad command line (exit status 2) */
    ERR_RECIPE              /* bad decode recipe: exit status 2, no usage line */
} ErrKind;

typedef struct ErrFrame {
    jmp_buf env;
    struct ErrFrame *prev;
} ErrFrame;

typedef struct {
    ErrFrame *top;
    ErrKind kind;
    char *msg;              /* malloc'ed; valid after a failure */
    size_t cap;
} Err;

/* Record an error without unwinding (for "try this, else carry on" code). */
void err_set(Err *e, ErrKind kind, const char *fmt, ...) PRINTF_LIKE(3, 4);
/* Unwind with the error recorded by err_set(). */
NORETURN void err_raise(Err *e);
/* err_set() + err_raise(). */
NORETURN void err_throw(Err *e, ErrKind kind, const char *fmt, ...) PRINTF_LIKE(3, 4);
/* Run fn(arg). True when it returned normally; false when it threw, with
 * e->kind and e->msg describing why. */
bool err_protect(Err *e, void (*fn)(void *), void *arg);
void err_release(Err *e);

NORETURN void die_out_of_memory(void);

#endif
