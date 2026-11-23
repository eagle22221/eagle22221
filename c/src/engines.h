/* Game-engine detection and nearby asset packs (the C counterpart of
 * engines.py and views.engine()). */
#ifndef BINSPECT_ENGINES_H
#define BINSPECT_ENGINES_H

#include "json.h"

JVal *bs_engine_view(Arena *arena, const char *path, char *err, size_t errlen);  /* same JSON as Python views.engine(); NULL + message on failure */

#endif
