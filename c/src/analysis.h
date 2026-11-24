/* Disassembly and whole-program analysis: function discovery, name
 * resolution and cross-references (port of disasm.py and analysis.py).
 *
 * The implementation needs the Capstone engine. A build without it
 * (-DVEX_NO_CAPSTONE) still provides these functions; analysis_new()
 * then throws ERR_NO_DISASSEMBLER. */
#ifndef VEX_ANALYSIS_H
#define VEX_ANALYSIS_H

#include "json.h"
#include "model.h"

typedef struct Analysis Analysis;

typedef VEC(big) AddressList;

/* Throws ERR_NO_DISASSEMBLER (no Capstone in this build) or ERR_UNSUPPORTED
 * (no disassembler for the file's CPU). */
Analysis *analysis_new(Arena *a, const Binary *b);
/* Addresses for a user-supplied location: an address, a symbol, function or
 * export name, "entry", or an import name (optionally "library!name").
 * Sorted; throws ERR_LOCATION when nothing matches. */
void analysis_resolve(Analysis *an, const char *text, AddressList *out);

JVal *view_functions(Arena *a, Analysis *an, const char *grep);
/* Listing at a location (default: the entry point); a whole function when
 * the location is a function start and no count is given. */
JVal *view_disassembly(Arena *a, Analysis *an, const char *location, const big *count);
JVal *view_xrefs(Arena *a, Analysis *an, const char *target, const char *string);

#endif
