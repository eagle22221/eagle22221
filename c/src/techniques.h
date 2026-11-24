/* Static detection of protection and evasion techniques (port of
 * techniques.py). Everything is read from the already-parsed Binary: imports,
 * section names and entropy, subsystem, strings and overlay. */
#ifndef VEX_TECHNIQUES_H
#define VEX_TECHNIQUES_H

#include "json.h"
#include "model.h"
#include "render.h"

/* The list of {category, title, confidence, evidence, explanation} dicts,
 * ordered by category, exactly as views.techniques() produces. */
JVal *tech_view(Arena *a, const Binary *b);

/* Text form of tech_view's output (port of _render_techniques in cli.py). */
void render_techniques(Arena *a, const Style *st, const JVal *rows, Lines *out);

#endif
