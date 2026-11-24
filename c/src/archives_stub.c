/* Stand-in for archives.c/engines.c in builds without asset-pack support:
 * the functions exist and report that the feature is not available, so the
 * web interface (server.c) works the same with and without it. */
#include "archives.h"
#include "engines.h"
#include "platform.h"

static const char UNAVAILABLE[] = "asset packs are not available in this build of vex";

static void unavailable(char *err, size_t errlen) {
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "%s", UNAVAILABLE);
}

bool bs_is_archive(const char *path) {
    (void)path;
    return false;
}

BsArchive *bs_archive_open(const char *path, char *err, size_t errlen) {
    (void)path;
    unavailable(err, errlen);
    return NULL;
}

void bs_archive_close(BsArchive *a) {
    (void)a;
}

const char *bs_archive_format(const BsArchive *a) {
    (void)a;
    return "";
}

bool bs_archive_writable(const BsArchive *a) {
    (void)a;
    return false;
}

size_t bs_archive_count(const BsArchive *a) {
    (void)a;
    return 0;
}

const BsArchiveEntry *bs_archive_entry(const BsArchive *a, size_t index) {
    (void)a;
    (void)index;
    return NULL;
}

size_t bs_archive_note_count(const BsArchive *a) {
    (void)a;
    return 0;
}

const char *bs_archive_note(const BsArchive *a, size_t index) {
    (void)a;
    (void)index;
    return NULL;
}

bool bs_archive_read(BsArchive *a, const char *name, uint8_t **data, size_t *size, char *err,
                     size_t errlen) {
    (void)a;
    (void)name;
    if (data != NULL)
        *data = NULL;
    if (size != NULL)
        *size = 0;
    unavailable(err, errlen);
    return false;
}

bool bs_archive_extract(BsArchive *a, const char *dest_dir, const char *const *names,
                        size_t n_names, size_t *written, char *err, size_t errlen) {
    (void)a;
    (void)dest_dir;
    (void)names;
    (void)n_names;
    if (written != NULL)
        *written = 0;
    unavailable(err, errlen);
    return false;
}

bool bs_archive_repack(BsArchive *a, const char *out_path, const char *name, const uint8_t *data,
                       size_t size, bool add, char *err, size_t errlen) {
    (void)a;
    (void)out_path;
    (void)name;
    (void)data;
    (void)size;
    (void)add;
    unavailable(err, errlen);
    return false;
}

static bool is_separator(char c) {
#ifdef _WIN32
    return c == '\\' || c == '/';
#else
    return c == '/';
#endif
}

/* The folder a path is in (os.path.dirname of an absolute path). */
static Str parent_folder(Arena *a, const char *path) {
    size_t root = 0, end = strlen(path);
#ifdef _WIN32
    if (end >= 2 && path[1] == ':')
        root = 2;                           /* "C:" stays in front */
#endif
    while (end > root && !is_separator(path[end - 1]))
        end--;                              /* drop the last name */
    size_t kept = end;
    while (kept > root && is_separator(path[kept - 1]))
        kept--;                             /* and the separators before it */
    if (kept == root)
        kept = end;                         /* nothing else left: that is the root folder */
    return str_copy(a, path, kept);
}

/* No engine is recognised and no pack is listed; `root` is still the folder
 * that was looked at, as in the full implementation. */
JVal *bs_engine_view(Arena *arena, const char *path, char *err, size_t errlen) {
    (void)err;
    (void)errlen;
    const char *full = platform_abspath(arena, path);
    bool is_folder = platform_exists(full) && !platform_is_file(full);
    JVal *d = j_dict(arena);
    j_set(arena, d, "root", is_folder ? j_cstr(arena, full) : j_str(arena, parent_folder(arena, full)));
    j_set(arena, d, "matches", j_list(arena));
    j_set(arena, d, "packs", j_list(arena));
    return d;
}
