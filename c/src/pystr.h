/* Python's text semantics, for the places where the output of vex must
 * match what the Python edition computes from a str: repr() in error
 * messages, str.strip(), str.isalpha() and str.upper(), int(text, 0),
 * repr(float) and the UnicodeEncodeError messages.
 *
 * A Python str can hold any code point, lone surrogates included (a
 * command-line argument that is not UTF-8 arrives as U+DC80..U+DCFF, and
 * JSON can spell a surrogate as \udXXX). Such text is kept here as "WTF-8":
 * UTF-8 in which a surrogate is written as the three bytes its code point
 * would take. Text without surrogates is plain UTF-8. */
#ifndef VEX_PYSTR_H
#define VEX_PYSTR_H

#include "common.h"

/* The next code point of WTF-8 text; *at < n on entry and it is advanced.
 * Never reads past n: a byte that does not start a complete sequence comes
 * back as U+DC00 + byte. */
uint32_t wtf8_next(const char *text, size_t n, size_t *at);
void wtf8_put(Buf *b, uint32_t code_point);
/* A command-line argument as Python reads it: bytes that are not UTF-8
 * become U+DC80..U+DCFF (the surrogateescape error handler). */
Str wtf8_from_argument(Arena *a, const char *text);

bool py_isspace(uint32_t code_point);
bool py_isalpha(uint32_t code_point);
bool py_isprintable(uint32_t code_point);
/* The value of a decimal digit of any script, or -1. */
int py_decimal(uint32_t code_point);
/* str.upper() of one character: one to three code points. */
size_t py_upper(uint32_t code_point, uint32_t out[3]);

/* str.strip(): a slice of `s`. */
Str py_strip(Str s);
/* repr() of a str. The result has no surrogates: it is valid UTF-8. */
Str py_repr_str(Arena *a, Str s);
/* str.encode("utf-8"): fails on a lone surrogate, with the text of Python's
 * UnicodeEncodeError in *error. On success the bytes are `s` itself. */
bool py_encode_utf8(Arena *a, Str s, Str *error);
/* str.encode("latin-1"), the same way. */
bool py_encode_latin1(Arena *a, Str s, Str *out, Str *error);
/* repr() of a float. */
Str py_repr_float(Arena *a, double value);

/* An integer of any size, as far as vex needs to know it. */
typedef struct {
    bool negative;
    bool huge;              /* the magnitude does not fit `magnitude` */
    uint64_t magnitude;     /* valid unless huge; below 2**62 */
    uint32_t low32;         /* the value & 0xFFFFFFFF, as Python computes it */
} PyInt;

/* int(text, 0): false where Python raises ValueError. */
bool py_int_parse(Str text, PyInt *out);
/* Is lo <= value <= hi? (0 <= lo, hi < 2**62) */
bool py_int_between(const PyInt *value, uint64_t lo, uint64_t hi);

#endif
