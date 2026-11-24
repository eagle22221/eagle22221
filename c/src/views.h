/* Plain, JSON-ready views of a binary (port of views.py). The command line
 * (--json and text) is rendered from these, so the two cannot disagree.
 * Addresses are hex strings ("0x140001000"): JSON numbers lose precision
 * above 2**53, which 64-bit addresses can exceed. */
#ifndef VEX_VIEWS_H
#define VEX_VIEWS_H

#include "json.h"
#include "model.h"
#include "strings.h"

JVal *view_info(Arena *a, const Binary *b);
JVal *view_sections(Arena *a, const Binary *b);
JVal *view_segments(Arena *a, const Binary *b);
JVal *view_imports(Arena *a, const Binary *b);
JVal *view_exports(Arena *a, const Binary *b);
/* `grep` (may be NULL) keeps the names that contain it. */
JVal *view_symbols(Arena *a, const Binary *b, const char *grep);
JVal *view_string(Arena *a, const FoundString *s);
JVal *view_strings(Arena *a, const Binary *b, big min_length, const char *encoding,
                   const char *grep, bool tagged);
/* Rows of 16 bytes starting at a file offset or a virtual address (default:
 * the entry point). Throws ERR_LOCATION. */
JVal *view_hexdump(Arena *a, const Binary *b, const big *address, const big *offset,
                   big length);
/* The file as consecutive, non-overlapping regions. */
JVal *view_layout(Arena *a, const Binary *b);

#endif
