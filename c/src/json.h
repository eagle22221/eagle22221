/* A small JSON document tree. The views build one per command; the CLI then
 * either prints it as JSON or renders text from it, so the two outputs cannot
 * disagree (the same arrangement as views.py and cli.py). */
#ifndef VEX_JSON_H
#define VEX_JSON_H

#include "common.h"

typedef enum { J_NULL, J_BOOL, J_INT, J_FLOAT, J_STR, J_LIST, J_DICT, J_RAW } JKind;

typedef struct JVal JVal;

typedef struct {
    const char *key;            /* NUL-terminated; key_len bytes (a key that was */
    JVal *value;                /* read by j_parse may hold NUL bytes itself)    */
    size_t key_len;
} JMember;

struct JVal {
    JKind kind;
    union {
        bool flag;
        big number;
        double real;                /* already rounded to three decimals */
        Str text;                   /* J_STR; J_RAW: a number, as it is written */
        VEC(JVal *) list;
        VEC(JMember) dict;
    } u;
};

JVal *j_null(Arena *a);
JVal *j_bool(Arena *a, bool value);
JVal *j_int(Arena *a, big value);
JVal *j_float(Arena *a, double value);      /* Python: round(value, 3) */
JVal *j_str(Arena *a, Str value);           /* STR_NONE becomes null */
JVal *j_cstr(Arena *a, const char *value);  /* NULL becomes null */
/* A number written exactly as `token` (a float as repr() shows it, or a
 * number of a document read by j_parse). */
JVal *j_raw(Arena *a, Str token);
JVal *j_hex(Arena *a, big value);           /* "0x1f" */
JVal *j_opt_hex(Arena *a, bool has, big value);
JVal *j_list(Arena *a);
JVal *j_dict(Arena *a);
void j_push(Arena *a, JVal *list, JVal *item);
void j_set(Arena *a, JVal *dict, const char *key, JVal *value);

/* Accessors for the text renderers. */
const JVal *j_get(const JVal *dict, const char *key);
Str j_text(const JVal *value);              /* "" unless a string */
big j_number(const JVal *value);
size_t j_len(const JVal *list);
const JVal *j_at(const JVal *list, size_t index);
bool j_truthy(const JVal *value);

/* Prints like Python's json.dumps(value, indent=2); `depth` is the nesting
 * level the value starts at. Non-ASCII characters are written as \uXXXX. */
void j_dump(FILE *out, const JVal *value, int depth);
/* "%.3f" with trailing zeros removed, as repr() shows a rounded float. */
const char *format_rounded(char buf[40], double value);

/* --- reading -------------------------------------------------------------------
 * json.loads(bytes) of CPython: the same documents are accepted (NaN,
 * Infinity and -Infinity included, UTF-8 with or without a byte order mark,
 * UTF-16 and UTF-32 as json.detect_encoding recognises them, a lone surrogate
 * written as \udXXX) and the same ones are refused. Returns NULL where
 * Python raises ValueError, and also for a document nested deeper than
 * J_MAX_DEPTH levels (Python gives up later, with a RecursionError).
 *
 * In the result a string is WTF-8 (see pystr.h), a number is a J_RAW holding
 * its text, and of two equal keys of an object the last value wins, at the
 * place of the first. */
#define J_MAX_DEPTH 512
JVal *j_parse(Arena *a, const uint8_t *data, size_t size);
/* Is this J_RAW number a float (it has a fraction or an exponent, or is
 * NaN or an infinity) rather than an integer? */
bool j_raw_is_float(const JVal *value);
/* float() of a J_RAW number. */
double j_raw_double(const JVal *value);
/* The member of a dict read by j_parse, or NULL. */
const JVal *j_member(const JVal *dict, Str key);

#endif
