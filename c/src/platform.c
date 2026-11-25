/* The operating-system specific corner of vex. */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#else
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700       /* POSIX.1-2008 with realpath() and mkstemp() */
#endif
#endif

#include "platform.h"

#ifdef _WIN32

#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
#include <shellapi.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

static UINT original_output_codepage;

static void restore_console(void) {
    if (original_output_codepage)
        SetConsoleOutputCP(original_output_codepage);
}

void platform_init(void) {
    /* Bytes go out exactly as written: no "\n" -> "\r\n" translation. */
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
    /* Text is UTF-8; tell the console, and put its setting back on exit. */
    if (platform_stdout_is_terminal()) {
        original_output_codepage = GetConsoleOutputCP();
        if (original_output_codepage != CP_UTF8 && SetConsoleOutputCP(CP_UTF8))
            atexit(restore_console);
        else
            original_output_codepage = 0;
    }
}

static wchar_t *to_wide(const char *text) {
    int n = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    wchar_t *wide = malloc((size_t)n * sizeof *wide);
    if (wide == NULL)
        die_out_of_memory();
    if (MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, n) <= 0) {
        free(wide);
        return NULL;
    }
    return wide;
}

char **platform_argv(Arena *a, int argc, char **argv, int *argc_out) {
    int count = 0;
    LPWSTR *wide = CommandLineToArgvW(GetCommandLineW(), &count);
    if (wide == NULL || count <= 0) {
        *argc_out = argc;
        return argv;
    }
    char **out = arena_array(a, (size_t)count + 1, sizeof *out);
    for (int i = 0; i < count; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, NULL, 0, NULL, NULL);
        if (n <= 0)
            n = 1;
        char *text = arena_alloc(a, (size_t)n);
        WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, text, n, NULL, NULL);
        out[i] = text;
    }
    LocalFree(wide);
    *argc_out = count;
    return out;
}

FILE *platform_fopen(const char *path, const char *mode) {
    wchar_t *wide_path = to_wide(path);
    wchar_t *wide_mode = to_wide(mode);
    FILE *f = NULL;
    if (wide_path != NULL && wide_mode != NULL)
        f = _wfopen(wide_path, wide_mode);
    else
        errno = EINVAL;
    free(wide_path);
    free(wide_mode);
    return f;
}

bool platform_is_file(const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL)
        return false;
    DWORD attributes = GetFileAttributesW(wide);
    free(wide);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool platform_stdout_is_terminal(void) {
    DWORD mode;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    return out != NULL && out != INVALID_HANDLE_VALUE && GetConsoleMode(out, &mode);
}

bool platform_enable_ansi(void) {
    DWORD mode;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == NULL || out == INVALID_HANDLE_VALUE || !GetConsoleMode(out, &mode))
        return true;            /* a file or pipe: nothing to switch on */
    if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        return true;
    return SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

void platform_pause_if_own_console(void) {
    DWORD processes[2];
    /* 1: this process is the only one attached to the console, so the
     * window was created for it and closes when it exits. A program run
     * from cmd.exe or PowerShell shares the console with that shell. */
    if (GetConsoleProcessList(processes, 2) != 1)
        return;
    /* Only when a person is looking at that window: not when another
     * program started us with redirected input or output. */
    DWORD mode;
    if (!platform_stdout_is_terminal() || !GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode))
        return;
    fflush(stdout);
    fputs("\nPress Enter to close this window...", stderr);
    fflush(stderr);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
}

const char *platform_basename(const char *path) {
    const char *base = path;
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':')
        base = path + 2;        /* "C:name" is relative to drive C: */
    for (const char *p = base; *p; p++)
        if (*p == '\\' || *p == '/')
            base = p + 1;
    return base;
}

static char *to_utf8(Arena *a, const wchar_t *wide) {
    int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (n <= 0)
        n = 1;
    char *text = arena_alloc(a, (size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, text, n, NULL, NULL);
    return text;
}

/* errno for the last failed Win32 call. */
static void set_errno_from_windows(void) {
    switch (GetLastError()) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
        errno = ENOENT;
        break;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        errno = ENOSPC;
        break;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_WRITE_PROTECT:
        errno = EACCES;
        break;
    default:
        errno = EIO;
    }
}

const char *platform_abspath(Arena *a, const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL)
        return path;
    const char *result = path;
    DWORD need = GetFullPathNameW(wide, 0, NULL, NULL);
    if (need > 0) {
        wchar_t *full = malloc(((size_t)need + 1) * sizeof *full);
        if (full == NULL)
            die_out_of_memory();
        DWORD got = GetFullPathNameW(wide, need + 1, full, NULL);
        if (got > 0 && got <= need)
            result = to_utf8(a, full);
        free(full);
    }
    free(wide);
    return result;
}

bool platform_exists(const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL)
        return false;
    DWORD attributes = GetFileAttributesW(wide);
    free(wide);
    return attributes != INVALID_FILE_ATTRIBUTES;
}

bool platform_path_exists(const char *path) {
    return platform_exists(path);
}

static bool file_identity(const char *path, BY_HANDLE_FILE_INFORMATION *info) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL)
        return false;
    HANDLE h = CreateFileW(wide, FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    bool ok = GetFileInformationByHandle(h, info) != 0;
    CloseHandle(h);
    return ok;
}

bool platform_same_file(const char *a, const char *b) {
    BY_HANDLE_FILE_INFORMATION x, y;
    return file_identity(a, &x) && file_identity(b, &y) &&
           x.dwVolumeSerialNumber == y.dwVolumeSerialNumber &&
           x.nFileIndexHigh == y.nFileIndexHigh && x.nFileIndexLow == y.nFileIndexLow;
}

const char *platform_realpath(Arena *a, const char *path) {
    return platform_abspath(a, path);
}

char *platform_write_temp(Arena *a, const char *path, const uint8_t *data, size_t size,
                          const char *like) {
    (void)like;                 /* Windows files carry no permission bits to copy */
    const char *base = platform_basename(path);
    static unsigned counter;
    for (int attempt = 0; attempt < 100; attempt++) {
        unsigned tag = (unsigned)GetTickCount() ^ (unsigned)GetCurrentProcessId() * 2654435761u ^
                       ++counter * 40503u;
        Str name = str_printf(a, "%.*s.%s.%08x.tmp", (int)(base - path), path, base, tag);
        wchar_t *wide = to_wide(name.p);
        if (wide == NULL) {
            errno = EINVAL;
            return NULL;
        }
        int fd = _wopen(wide, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _S_IREAD | _S_IWRITE);
        free(wide);
        if (fd < 0) {
            if (errno == EEXIST)
                continue;
            return NULL;
        }
        FILE *f = _fdopen(fd, "wb");
        if (f == NULL) {
            int code = errno;
            _close(fd);
            platform_remove(name.p);
            errno = code;
            return NULL;
        }
        bool ok = fwrite(data, 1, size, f) == size && fflush(f) == 0 && _commit(fd) == 0;
        int code = errno;
        if (fclose(f) != 0 && ok) {
            ok = false;
            code = errno;
        }
        if (!ok) {
            platform_remove(name.p);
            errno = code;
            return NULL;
        }
        return (char *)name.p;
    }
    errno = EEXIST;
    return NULL;
}

static bool move_file(const char *from, const char *to, DWORD flags) {
    wchar_t *wide_from = to_wide(from), *wide_to = to_wide(to);
    bool ok = wide_from != NULL && wide_to != NULL && MoveFileExW(wide_from, wide_to, flags);
    if (!ok)
        set_errno_from_windows();
    free(wide_from);
    free(wide_to);
    return ok;
}

bool platform_replace(const char *from, const char *to) {
    return move_file(from, to, MOVEFILE_REPLACE_EXISTING);
}

bool platform_move_new(const char *from, const char *to) {
    return move_file(from, to, 0);      /* fails when `to` exists */
}

void platform_remove(const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide != NULL)
        DeleteFileW(wide);
    free(wide);
}

#else /* POSIX */

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

void platform_init(void) {
}

char **platform_argv(Arena *a, int argc, char **argv, int *argc_out) {
    (void)a;
    *argc_out = argc;
    return argv;
}

FILE *platform_fopen(const char *path, const char *mode) {
    return fopen(path, mode);
}

bool platform_is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool platform_stdout_is_terminal(void) {
    return isatty(STDOUT_FILENO) != 0;
}

bool platform_enable_ansi(void) {
    return true;
}

void platform_pause_if_own_console(void) {
}

const char *platform_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* posixpath.normpath(): collapse "//", "." and "..". */
static const char *normalize(Arena *a, const char *path) {
    size_t length = strlen(path);
    if (length == 0)
        return ".";
    size_t slashes = path[0] != '/' ? 0 : (path[1] == '/' && path[2] != '/') ? 2 : 1;
    const char **parts = arena_array(a, length + 1, sizeof *parts);
    size_t *sizes = arena_array(a, length + 1, sizeof *sizes);
    size_t count = 0;
    for (size_t i = 0; i < length;) {
        size_t start = i;
        while (i < length && path[i] != '/')
            i++;
        size_t n = i - start;
        i++;
        if (n == 0 || (n == 1 && path[start] == '.'))
            continue;
        bool up = n == 2 && path[start] == '.' && path[start + 1] == '.';
        bool last_is_up = count > 0 && sizes[count - 1] == 2 &&
                          memcmp(parts[count - 1], "..", 2) == 0;
        if (up && count > 0 && !last_is_up) {
            count--;
        } else if (!up || !slashes) {
            parts[count] = path + start;
            sizes[count] = n;
            count++;
        }
    }
    Buf out;
    buf_init(&out, a);
    for (size_t i = 0; i < slashes; i++)
        buf_addch(&out, '/');
    for (size_t i = 0; i < count; i++) {
        if (i)
            buf_addch(&out, '/');
        buf_add(&out, parts[i], sizes[i]);
    }
    return out.n ? buf_str(&out).p : ".";
}

const char *platform_abspath(Arena *a, const char *path) {
    if (path[0] == '/')
        return normalize(a, path);
    size_t cap = 256;
    for (;;) {
        char *cwd = arena_alloc(a, cap);
        if (getcwd(cwd, cap) != NULL)
            return normalize(a, str_printf(a, "%s/%s", cwd, path).p);
        if (errno != ERANGE)
            return path;
        cap *= 2;
    }
}

bool platform_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

bool platform_path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

bool platform_same_file(const char *a, const char *b) {
    struct stat x, y;
    return stat(a, &x) == 0 && stat(b, &y) == 0 && x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}

const char *platform_realpath(Arena *a, const char *path) {
    char *resolved = realpath(path, NULL);
    if (resolved == NULL)
        return path;
    const char *copy = str_copy(a, resolved, strlen(resolved)).p;
    free(resolved);
    return copy;
}

char *platform_write_temp(Arena *a, const char *path, const uint8_t *data, size_t size,
                          const char *like) {
    const char *base = platform_basename(path);
    Str made = str_printf(a, "%.*s.%s.XXXXXX", (int)(base - path), path, base);
    char *name = arena_alloc(a, made.n + 1);
    memcpy(name, made.p, made.n + 1);
    int fd = mkstemp(name);
    if (fd < 0)
        return NULL;
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        int code = errno;
        close(fd);
        unlink(name);
        errno = code;
        return NULL;
    }
    bool ok = fwrite(data, 1, size, f) == size && fflush(f) == 0 && fsync(fd) == 0;
    int code = errno;
    if (fclose(f) != 0 && ok) {
        ok = false;
        code = errno;
    }
    if (!ok) {
        unlink(name);
        errno = code;
        return NULL;
    }
    struct stat st;
    if (stat(like, &st) == 0)
        chmod(name, st.st_mode & 07777);
    return name;
}

bool platform_replace(const char *from, const char *to) {
    return rename(from, to) == 0;
}

bool platform_move_new(const char *from, const char *to) {
    if (link(from, to) == 0)            /* fails instead of overwriting */
        return true;
    if (errno == EEXIST)
        return false;
    /* No hard links here (FAT, some network shares): fall back to rename. */
    struct stat st;
    if (lstat(to, &st) == 0) {
        errno = EEXIST;
        return false;
    }
    return rename(from, to) == 0;
}

void platform_remove(const char *path) {
    unlink(path);
}

#endif
