/* Disassembly (via Capstone) with the annotations a reverse engineer wants:
 * who is being called, which import a slot belongs to, which string a
 * pointer refers to (port of disasm.py).
 *
 * Operands are analysed from Capstone's text output rather than its detail
 * structures, exactly like the Python version, so both produce the same
 * references for every architecture. */
#ifndef BINSPECT_DISASM_H
#define BINSPECT_DISASM_H

#include "model.h"

typedef enum { KIND_NONE, KIND_CALL, KIND_JUMP, KIND_RET } InsnKind;

typedef struct {
    big address;
    unsigned size;
    const uint8_t *raw;         /* the instruction's bytes */
    size_t raw_size;
    char mnemonic[32];
    char operands[160];
    InsnKind kind;
    bool has_target;
    big target;                 /* destination of a direct call/jump */
    big refs[2];                /* every address the instruction mentions */
    unsigned nrefs;
    Str comment;
} Insn;

const char *insn_kind_name(InsnKind kind);      /* "call", "jump", "ret" or "" */
/* f"{mnemonic} {operands}".strip() */
Str insn_text(Arena *a, const Insn *insn);

typedef struct {
    big address;
    big size;
    Str name;
    const char *source;         /* symbol, export, pdata, libc_start_main, entry, call */
} Function;

/* Hash map keyed by address. Values are small integers or pointers. */
typedef struct {
    big *keys;
    uint64_t *values;
    bool *used;
    size_t cap, count;
} AddrMap;

bool addrmap_get(const AddrMap *map, big key, uint64_t *value);
/* Returns false (and changes nothing) when the key exists and !overwrite. */
bool addrmap_put(Arena *a, AddrMap *map, big key, uint64_t value, bool overwrite);

typedef struct Disassembler Disassembler;

/* Throws ERR_UNSUPPORTED when there is no disassembler for the binary's CPU. */
Disassembler *dis_new(Arena *a, const Binary *b);
bool dis_in_code(const Disassembler *d, big address);
/* The import whose slot (GOT/IAT entry) is at address, or NULL. */
const Import *dis_slot(const Disassembler *d, big address);
bool dis_has_slots(const Disassembler *d);
/* Symbolic name for an address: "main", "main+0x1c", "puts@plt"; STR_NONE. */
Str dis_name_at(Disassembler *d, big address);
/* The import a jump stub (PLT entry / import thunk) at address leads to. */
const Import *dis_thunk_import(Disassembler *d, big address);
/* "puts@plt" / "WriteFile@thunk" for a jump stub, else STR_NONE. */
Str dis_thunk_at(Disassembler *d, big address);
/* Adopt names and sizes found by function discovery. */
void dis_add_names(Disassembler *d, const Function *functions, size_t count);
/* Fill in insn->comment. */
void dis_annotate(Disassembler *d, Insn *insn);

/* Decoding: every instruction in `code`, which sits at `address`. Bytes that
 * do not decode become ".byte" lines. */
typedef struct {
    Disassembler *dis;
    const uint8_t *code;
    uint64_t code_size;
    big base;
    const uint8_t *cursor;
    size_t left;
    uint64_t address;           /* Capstone works modulo 2**64 */
    struct {
        char reg[12];
        big page;
        uint64_t seen;
    } pages[40];                /* AArch64: registers loaded by adrp */
    size_t npages;
    uint64_t index;
} Decoder;

void dis_decode(Disassembler *d, Decoder *dec, const uint8_t *code, uint64_t size, big address);
bool dis_next(Decoder *dec, Insn *insn);

#endif
