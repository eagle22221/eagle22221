/* Game asset packs (ZIP, PAK, WAD, ...): listing, reading, extracting and
 * rebuilding (the C counterpart of archives.py). */
#ifndef BINSPECT_ARCHIVES_H
#define BINSPECT_ARCHIVES_H

#include "common.h"

typedef struct { const char *name; uint64_t size; bool compressed; bool encrypted; } BsArchiveEntry;
typedef struct BsArchive BsArchive;
bool bs_is_archive(const char *path);
BsArchive *bs_archive_open(const char *path, char *err, size_t errlen);   /* NULL + message on failure */
void bs_archive_close(BsArchive *a);
const char *bs_archive_format(const BsArchive *a);
bool bs_archive_writable(const BsArchive *a);
size_t bs_archive_count(const BsArchive *a);
const BsArchiveEntry *bs_archive_entry(const BsArchive *a, size_t index);
size_t bs_archive_note_count(const BsArchive *a);
const char *bs_archive_note(const BsArchive *a, size_t index);
/* all return true on success; on failure write a message to err */
bool bs_archive_read(BsArchive *a, const char *name, uint8_t **data, size_t *size, char *err, size_t errlen);  /* caller frees *data */
bool bs_archive_extract(BsArchive *a, const char *dest_dir, const char *const *names, size_t n_names, size_t *written, char *err, size_t errlen); /* n_names == 0: everything */
bool bs_archive_repack(BsArchive *a, const char *out_path, const char *name, const uint8_t *data, size_t size, bool add, char *err, size_t errlen);

#endif
