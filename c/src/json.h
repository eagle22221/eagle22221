/* A small JSON document tree. The views build one per command; the CLI then
 * either prints it as JSON or renders text from it, so the two outputs cannot
 * disagree (the same arrangement as views.py and cli.py). */
#ifndef BINSPECT_JSON_H
#define BINSPECT_JSON_H

#include "common.h"

typedef enum { J_NULL, J_BOOL, J_INT, J_FLOAT, J_STR, J_LIST, J_DICT } JKind;

typedef struct JVal JVal;

typedef struct {
    const char *key;
    JVal *value;
} JMember;

struct JVal {
    JKind kind;
    union {
        bool flag;
        big number;
        double real;                /* already rounded to three decimals */
        Str text;
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

#endif
