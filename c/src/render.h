/* Text renderers: the human-readable form of each view (port of the
 * _render_* functions in cli.py). */
#ifndef VEX_RENDER_H
#define VEX_RENDER_H

#include "json.h"

typedef struct {
    bool colour;                /* wrap text in ANSI escapes */
} Style;

typedef VEC(Str) Lines;

typedef void (*Renderer)(Arena *a, const Style *st, const JVal *data, Lines *out);

void render_info(Arena *a, const Style *st, const JVal *d, Lines *out);
void render_sections(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_segments(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_imports(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_exports(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_symbols(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_strings(Arena *a, const Style *st, const JVal *rows, Lines *out);
Str render_string_row(Arena *a, const Style *st, const JVal *row);
void render_functions(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_disassembly(Arena *a, const Style *st, const JVal *d, Lines *out);
void render_xrefs(Arena *a, const Style *st, const JVal *rows, Lines *out);
void render_hexdump(Arena *a, const Style *st, const JVal *d, Lines *out);
void render_layout(Arena *a, const Style *st, const JVal *d, Lines *out);
void render_report(Arena *a, const Style *st, const JVal *d, Lines *out);
void render_split(Arena *a, const Style *st, const JVal *d, Lines *out);
void render_done(Arena *a, const Style *st, const JVal *d, Lines *out);

/* print("\n".join(lines).lstrip("\n")) */
void lines_print(FILE *out, const Lines *lines);

#endif
