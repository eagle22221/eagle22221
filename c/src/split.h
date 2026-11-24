/* `vex split FILE FOLDER`: save the parts of a program as separate files
 * (port of split.py; the specification is docs/dev/split-spec.md).
 *
 * Only bytes that are already in the file are copied: nothing is decrypted,
 * unpacked, decompressed or run, and the original is never modified. */
#ifndef VEX_SPLIT_H
#define VEX_SPLIT_H

#include "json.h"
#include "model.h"

typedef struct {
    Str path;               /* relative, forward slashes; STR_NONE when not saved */
    const char *kind;       /* the region's kind, or "embedded" */
    Str name;
    big offset, size;       /* as reported (the layout's own numbers) */
    const uint8_t *data;    /* the bytes to save: always inside the file */
    uint64_t length;
    Str note;
} SplitPiece;

typedef struct {
    const Binary *binary;
    SplitPiece *pieces;
    size_t npieces;
    uint64_t count;         /* files that are (or would be) written, without index.txt */
    uint64_t bytes;         /* their total size */
} Split;

/* Works out every piece of the binary. Touches no file. */
Split *split_plan(Arena *a, const Binary *b);
/* The result as JSON; `dest` is the absolute folder, or NULL for a preview. */
JVal *split_view(Arena *a, const Split *split, const char *dest);
/* The text of index.txt. */
Str split_index(Arena *a, const Split *split);
/* Refuses (ERR_OTHER) a destination that exists and is anything but an
 * empty folder. */
void split_check_folder(Arena *a, Err *err, const char *folder);
/* Writes the pieces and index.txt into `folder` (as the user named it),
 * which is created when it does not exist and must be empty when it does;
 * otherwise nothing is written. Throws ERR_OTHER. */
void split_write(Arena *a, Err *err, const Split *split, const char *folder);

#endif
