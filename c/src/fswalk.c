/* File-system layer (see fswalk.h): one Windows half, one POSIX half. */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#else
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif

#include "fswalk.h"

#include <errno.h>

#include "platform.h"

#ifdef _WIN32

#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

char fs_separator(void) {
    return '\\';
}

bool fs_is_separator(char c) {
    return c == '\\' || c == '/';
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

static FsKind kind_of_attributes(DWORD attributes) {
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return FS_MISSING;
    return attributes & FILE_ATTRIBUTE_DIRECTORY ? FS_DIR : FS_FILE;
}

/* Attributes of what a path leads to, links and junctions resolved. */
static DWORD target_attributes(const wchar_t *wide) {
    HANDLE h = CreateFileW(wide, FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return INVALID_FILE_ATTRIBUTES;
    BY_HANDLE_FILE_INFORMATION info;
    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    if (GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandle(h, &info))
        attributes = info.dwFileAttributes;
    CloseHandle(h);
    return attributes;
}

static FsKind kind_wide(const wchar_t *wide, bool follow) {
    DWORD attributes = GetFileAttributesW(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return FS_MISSING;
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        if (!follow)
            return FS_LINK;
        attributes = target_attributes(wide);
    }
    return kind_of_attributes(attributes);
}

FsKind fs_kind(const char *path, bool follow) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL)
        return FS_MISSING;
    FsKind kind = kind_wide(wide, follow);
    free(wide);
    return kind;
}

bool fs_size(const char *path, uint64_t *size) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL)
        return false;
    HANDLE h = CreateFileW(wide, FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER value;
    bool ok = GetFileSizeEx(h, &value) != 0;
    CloseHandle(h);
    if (ok)
        *size = (uint64_t)value.QuadPart;
    return ok;
}

FILE *fs_open_regular(const char *path, uint64_t *size, bool *not_regular) {
    *not_regular = false;
    wchar_t *wide = to_wide(path);
    if (wide == NULL) {
        errno = ENOENT;
        return NULL;
    }
    FsKind kind = kind_wide(wide, true);
    if (kind == FS_DIR) {
        free(wide);
        *not_regular = true;
        return NULL;
    }
    FILE *f = _wfopen(wide, L"rb");
    free(wide);
    if (f == NULL)
        return NULL;
    /* A console, a pipe or a device ("CON", "NUL") is not a file on disk. */
    HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));
    __int64 length = _filelengthi64(_fileno(f));
    if (h == INVALID_HANDLE_VALUE || GetFileType(h) != FILE_TYPE_DISK || length < 0) {
        fclose(f);
        *not_regular = true;
        return NULL;
    }
    *size = (uint64_t)length;
    return f;
}

bool fs_seek(FILE *f, uint64_t offset) {
    return offset <= (uint64_t)INT64_MAX && _fseeki64(f, (__int64)offset, SEEK_SET) == 0;
}

bool fs_mkdir(const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL) {
        errno = ENOENT;
        return false;
    }
    bool ok = _wmkdir(wide) == 0;
    free(wide);
    return ok;
}

FILE *fs_create(const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL) {
        errno = ENOENT;
        return NULL;
    }
    FILE *f = NULL;
    if (kind_wide(wide, false) == FS_LINK)
        errno = EACCES;                 /* never through a link or junction */
    else
        f = _wfopen(wide, L"wb");
    free(wide);
    return f;
}

FILE *fs_create_new(const char *path) {
    wchar_t *wide = to_wide(path);
    if (wide == NULL) {
        errno = ENOENT;
        return NULL;
    }
    int fd = _wopen(wide, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _S_IREAD | _S_IWRITE);
    free(wide);
    if (fd < 0)
        return NULL;
    FILE *f = _fdopen(fd, "wb");
    if (f == NULL) {
        int code = errno;
        _close(fd);
        errno = code;
    }
    return f;
}

FILE *fs_create_temp(Arena *a, const char *dest, const char **name) {
    static unsigned counter;
    for (int attempt = 0; attempt < 100; attempt++) {
        unsigned tag = (unsigned)GetTickCount() ^ (unsigned)GetCurrentProcessId() * 2654435761u ^
                       ++counter * 40503u;
        Str made = str_printf(a, "%s.%08x.tmp", dest, tag);
        wchar_t *wide = to_wide(made.p);
        if (wide == NULL) {
            errno = ENOENT;
            return NULL;
        }
        int fd = _wopen(wide, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
        free(wide);
        if (fd < 0) {
            if (errno == EEXIST)
                continue;
            return NULL;
        }
        FILE *f = _fdopen(fd, "w+b");
        if (f == NULL) {
            int code = errno;
            _close(fd);
            platform_remove(made.p);
            errno = code;
            return NULL;
        }
        *name = made.p;
        return f;
    }
    errno = EEXIST;
    return NULL;
}

void fs_copy_mode(const char *from, const char *to) {
    (void)from;                         /* no permission bits to carry over */
    (void)to;
}

bool fs_list(Arena *a, const char *dir, size_t limit, FsEntry **entries, size_t *count) {
    VEC(FsEntry) found = {0};
    Str pattern = str_printf(a, "%s\\*", dir);
    wchar_t *wide = to_wide(pattern.p);
    if (wide == NULL)
        return false;
    WIN32_FIND_DATAW data;
    HANDLE h = FindFirstFileW(wide, &data);
    free(wide);
    if (h == INVALID_HANDLE_VALUE) {
        /* The root of an empty drive has no entries at all, not even ".". */
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            return false;
        *entries = NULL;
        *count = 0;
        return true;
    }
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;
        if (found.n >= limit)
            break;
        int n = WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1, NULL, 0, NULL, NULL);
        if (n <= 0)
            continue;
        char *text = arena_alloc(a, (size_t)n);
        WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1, text, n, NULL, NULL);
        FsEntry *e = VEC_PUSH(a, found);
        e->name = text;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            e->kind = FS_LINK;
            e->target = fs_kind(str_printf(a, "%s\\%s", dir, text).p, true);
        } else {
            e->kind = e->target = kind_of_attributes(data.dwFileAttributes);
        }
    } while (FindNextFileW(h, &data));
    FindClose(h);
    *entries = found.v;
    *count = found.n;
    return true;
}

#else /* POSIX */

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

char fs_separator(void) {
    return '/';
}

bool fs_is_separator(char c) {
    return c == '/';
}

static FsKind kind_of_mode(mode_t mode) {
    return S_ISREG(mode) ? FS_FILE : S_ISDIR(mode) ? FS_DIR : S_ISLNK(mode) ? FS_LINK : FS_OTHER;
}

FsKind fs_kind(const char *path, bool follow) {
    struct stat st;
    if ((follow ? stat(path, &st) : lstat(path, &st)) != 0)
        return FS_MISSING;
    return kind_of_mode(st.st_mode);
}

bool fs_size(const char *path, uint64_t *size) {
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    *size = (uint64_t)st.st_size;
    return true;
}

FILE *fs_open_regular(const char *path, uint64_t *size, bool *not_regular) {
    *not_regular = false;
    /* O_NONBLOCK: opening a named pipe must not wait for a writer. */
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int code = errno;
        close(fd);
        errno = code;
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        *not_regular = true;
        return NULL;
    }
    FILE *f = fdopen(fd, "rb");
    if (f == NULL) {
        int code = errno;
        close(fd);
        errno = code;
        return NULL;
    }
    *size = (uint64_t)st.st_size;
    return f;
}

bool fs_seek(FILE *f, uint64_t offset) {
    return offset <= (uint64_t)INT64_MAX && fseeko(f, (off_t)offset, SEEK_SET) == 0;
}

bool fs_mkdir(const char *path) {
    return mkdir(path, 0777) == 0;
}

FILE *fs_create(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0666);
    if (fd < 0)
        return NULL;
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        int code = errno;
        close(fd);
        errno = code;
    }
    return f;
}

FILE *fs_create_new(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0)
        return NULL;
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        int code = errno;
        close(fd);
        errno = code;
    }
    return f;
}

FILE *fs_create_temp(Arena *a, const char *dest, const char **name) {
    Str made = str_printf(a, "%s.XXXXXX", dest);
    char *path = arena_alloc(a, made.n + 1);
    memcpy(path, made.p, made.n + 1);
    int fd = mkstemp(path);
    if (fd < 0)
        return NULL;
    FILE *f = fdopen(fd, "w+b");
    if (f == NULL) {
        int code = errno;
        close(fd);
        unlink(path);
        errno = code;
        return NULL;
    }
    *name = path;
    return f;
}

void fs_copy_mode(const char *from, const char *to) {
    struct stat st;
    if (stat(from, &st) == 0)
        chmod(to, st.st_mode & 07777);
}

bool fs_list(Arena *a, const char *dir, size_t limit, FsEntry **entries, size_t *count) {
    VEC(FsEntry) found = {0};
    DIR *d = opendir(dir);
    if (d == NULL)
        return false;
    struct dirent *item;
    while (found.n < limit && (item = readdir(d)) != NULL) {
        const char *text = item->d_name;
        if (strcmp(text, ".") == 0 || strcmp(text, "..") == 0)
            continue;
        FsEntry *e = VEC_PUSH(a, found);
        e->name = str_copy(a, text, strlen(text)).p;
        const char *path = str_printf(a, "%s/%s", dir, text).p;
        e->kind = fs_kind(path, false);
        e->target = e->kind == FS_LINK ? fs_kind(path, true) : e->kind;
    }
    closedir(d);
    *entries = found.v;
    *count = found.n;
    return true;
}

#endif
