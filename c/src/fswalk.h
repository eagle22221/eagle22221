/* File-system access for the asset-pack and engine code: the calls that the
 * C standard library does not have (directories, symbolic links, files
 * larger than 2 GiB). Everything that differs between Windows and POSIX is
 * inside fswalk.c; callers see UTF-8 paths and errno. */
#ifndef BINSPECT_FSWALK_H
#define BINSPECT_FSWALK_H

#include "common.h"

typedef enum { FS_MISSING, FS_FILE, FS_DIR, FS_LINK, FS_OTHER } FsKind;

/* '/' or '\\': what os.sep is in the Python edition. */
char fs_separator(void);
bool fs_is_separator(char c);

/* What `path` names. With `follow` a symbolic link is looked through (the
 * answer is never FS_LINK), as stat() does; without, as lstat() does. */
FsKind fs_kind(const char *path, bool follow);
/* os.path.getsize() */
bool fs_size(const char *path, uint64_t *size);

/* Opens a regular file for reading and reports its size. A named pipe, a
 * device or a directory is never opened (it could block or never end):
 * NULL with *not_regular set. Otherwise NULL means errno says why. */
FILE *fs_open_regular(const char *path, uint64_t *size, bool *not_regular);
/* fseek() to an absolute position, for files of any size. */
bool fs_seek(FILE *f, uint64_t offset);

/* mkdir() of one directory; false with errno (EEXIST when it is there). */
bool fs_mkdir(const char *path);
/* Creates or truncates a file for writing without following a symbolic
 * link in the last component. */
FILE *fs_create(const char *path);
/* A new, uniquely named file next to `dest`, open for reading and writing;
 * *name receives its path (arena memory). */
FILE *fs_create_temp(Arena *a, const char *dest, const char **name);
/* shutil.copymode(): permission bits of `from` onto `to`; errors ignored. */
void fs_copy_mode(const char *from, const char *to);

typedef struct {
    const char *name;
    FsKind kind;                /* of the entry itself (lstat) */
    FsKind target;              /* of what it leads to (stat) */
} FsEntry;

/* The entries of a directory in the order the system returns them, without
 * "." and "..", at most `limit` of them. False when it cannot be listed. */
bool fs_list(Arena *a, const char *dir, size_t limit, FsEntry **entries, size_t *count);

#endif
