/* `vex decode`: the decode & cipher workbench (port of decode.py and of the
 * parts of crypto.py the native edition has; the specification is
 * docs/dev/decode-spec.md).
 *
 * An operation maps bytes to bytes; a recipe applies operations left to
 * right to the bytes of a source. Everything works on data the user gives:
 * nothing here looks for an unknown key, and nothing is ever run. No
 * operation and no recipe produces more than 64 MiB; decompression checks
 * that limit as it goes, so a decompression bomb is refused, not expanded.
 *
 * Nothing in this module unwinds with longjmp: a problem with the input is
 * reported in the result. */
#ifndef VEX_DECODE_H
#define VEX_DECODE_H

#include "json.h"

#define DECODE_CAP ((size_t)64 << 20)

/* Where the bytes come from. Values are JSON values because that is what
 * the HTTP API receives; the command line passes strings. A NULL value is
 * Python's None. */
typedef enum { DECODE_TEXT, DECODE_HEX, DECODE_BASE64, DECODE_FILE } DecodeKind;

typedef struct {
    DecodeKind kind;
    const JVal *value;          /* text, hex, base64 */
    const uint8_t *file;        /* file: the whole file */
    size_t file_size;
    const JVal *offset;         /* file: NULL means 0 */
    const JVal *length;         /* file: NULL means "to the end" */
} DecodeSource;

/* One step of a recipe: the operation's name as it was given (it may name
 * nothing) and its parameters, a J_DICT of name -> value. */
typedef struct {
    Str op;
    const JVal *params;
} DecodeStep;

typedef struct {
    Str op;
    size_t size;
} DecodeDone;

typedef struct {
    bool ok;
    const uint8_t *data;        /* the final bytes, or the last good ones */
    size_t size;
    DecodeDone *steps;          /* the steps that completed */
    size_t nsteps;
    Str error;                  /* STR_NONE when ok */
} DecodeResult;

/* The recipe of the command line, "op[:k=v,...][|op...]". False for an
 * unknown operation or parameter or a malformed k=v, with the message. */
bool decode_parse_recipe(Arena *a, Str text, DecodeStep **steps, size_t *nsteps, Str *error);
/* Resolves the source and applies the steps. The result's bytes live as
 * long as the arena. */
void decode_execute(Arena *a, const DecodeSource *source, const DecodeStep *steps, size_t nsteps,
                    DecodeResult *result);
/* {ok, size, hex, text, looks_like, steps, error} */
JVal *decode_result_view(Arena *a, const DecodeResult *result);
/* {ok, candidates, error}: the solver `name` over the source bytes. */
JVal *decode_solve(Arena *a, Str name, const DecodeSource *source);
/* {groups, solvers}: every operation with its parameters, and whether this
 * build has it. */
JVal *decode_catalogue(Arena *a);
/* "PNG image", "printable text", "binary", "empty", ... */
const char *decode_looks_like(const uint8_t *data, size_t size);

/* Python's str(value) and repr(value) of a JSON value (NULL is None). */
Str decode_pystr(Arena *a, const JVal *value);
Str decode_pyrepr(Arena *a, const JVal *value);

#endif
