/* Stand-in for disasm.c/analysis.c in builds without the Capstone engine:
 * the disassembly commands exist and fail cleanly. */
#include "analysis.h"

Analysis *analysis_new(Arena *a, const Binary *b) {
    (void)a;
    err_throw(b->err, ERR_NO_DISASSEMBLER, "this build has no disassembler");
}

void analysis_resolve(Analysis *an, const char *text, AddressList *out) {
    (void)an;
    (void)text;
    (void)out;
}

JVal *view_functions(Arena *a, Analysis *an, const char *grep) {
    (void)an;
    (void)grep;
    return j_list(a);
}

JVal *view_disassembly(Arena *a, Analysis *an, const char *location, const big *count) {
    (void)an;
    (void)location;
    (void)count;
    return j_dict(a);
}

JVal *view_xrefs(Arena *a, Analysis *an, const char *target, const char *string) {
    (void)an;
    (void)target;
    (void)string;
    return j_list(a);
}
