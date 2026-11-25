/* Everything that differs between Windows and POSIX systems lives behind
 * this interface (platform.c); the rest of vex is portable C11. */
#ifndef VEX_PLATFORM_H
#define VEX_PLATFORM_H

#include "common.h"

/* Process start-up: binary-mode standard streams and a UTF-8 console on
 * Windows; nothing elsewhere. */
void platform_init(void);
/* The command line as UTF-8 strings (Windows hands main() a lossy copy). */
char **platform_argv(Arena *a, int argc, char **argv, int *argc_out);
/* fopen() that accepts UTF-8 paths on Windows. */
FILE *platform_fopen(const char *path, const char *mode);
/* Is `path` an existing regular file? */
bool platform_is_file(const char *path);
bool platform_stdout_is_terminal(void);
/* Make ANSI colour escapes work on stdout; false when they would not. */
bool platform_enable_ansi(void);
/* On Windows, when this process owns its console window (started by a
 * double-click or by dropping a file on the .exe), wait for Enter so the
 * window does not vanish before the output can be read. */
void platform_pause_if_own_console(void);
/* os.path.basename(): the part after the last directory separator. */
const char *platform_basename(const char *path);
/* os.path.abspath() */
const char *platform_abspath(Arena *a, const char *path);

/* --- writing files (for the patch commands) -------------------------------------
 * The functions that can fail return false/NULL and leave the reason in errno. */

/* Does anything exist at `path` (even a dangling symbolic link)? */
bool platform_exists(const char *path);
/* os.path.exists(): does `path`, with symbolic links followed, exist? */
bool platform_path_exists(const char *path);
/* Do both paths name the same existing file? */
bool platform_same_file(const char *a, const char *b);
/* The path with symbolic links resolved (or the path itself). */
const char *platform_realpath(Arena *a, const char *path);
/* Write `size` bytes to a new, uniquely named file in the directory of
 * `path`, flushed to disk and with the permission bits of the file `like`.
 * Returns the temp file's name; the caller renames or removes it. */
char *platform_write_temp(Arena *a, const char *path, const uint8_t *data, size_t size,
                          const char *like);
/* Rename `from` to `to`, replacing an existing file in one step. */
bool platform_replace(const char *from, const char *to);
/* Give the file `from` the name `to` unless that name is taken; `from` may
 * or may not exist afterwards. */
bool platform_move_new(const char *from, const char *to);
void platform_remove(const char *path);

#endif
