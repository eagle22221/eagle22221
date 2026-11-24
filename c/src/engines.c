/* Which engine or runtime a game was built with, and nearby asset packs (the
 * C counterpart of vex/engines.py and views.engine()/find_packs()).
 *
 * Detection uses cheap evidence only: the names of neighbouring files and
 * folders, the signature of asset containers found there, and a capped scan
 * of the executable for marker strings. Nothing is executed and no file is
 * read in full. */
#include "engines.h"

#include "archives.h"
#include "fswalk.h"
#include "platform.h"

#define MAX_DEPTH 3
#define MAX_SCAN_ENTRIES 5000
#define MAX_EXE_SCAN ((uint64_t)64 << 20)
#define MAX_ASSET_FILES 200

#define HIGH 5
#define MEDIUM 3
#define STRONG 5
#define GOOD 3
#define WEAK 1

/* --- small helpers ------------------------------------------------------------ */

static void *mem_find(const void *hay, size_t haylen, const void *needle, size_t nlen) {
    if (nlen == 0)
        return (void *)hay;
    if (nlen > haylen)
        return NULL;
    const uint8_t *h = hay;
    for (size_t i = 0; i + nlen <= haylen; i++)
        if (h[i] == *(const uint8_t *)needle && memcmp(h + i, needle, nlen) == 0)
            return (void *)(h + i);
    return NULL;
}

static char lower1(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

static const char *lower_str(Arena *a, const char *s) {
    size_t n = strlen(s);
    char *out = arena_alloc(a, n + 1);
    for (size_t i = 0; i < n; i++)
        out[i] = lower1(s[i]);
    out[n] = '\0';
    return out;
}

/* Shell-style match: '*' matches a run with no '/', '?' one non-'/' char. Both
 * strings are lower case. */
static bool glob_match(const char *p, const char *s) {
    while (*p) {
        if (*p == '*') {
            p++;
            for (;;) {
                if (glob_match(p, s))
                    return true;
                if (*s == '\0' || *s == '/')
                    return false;
                s++;
            }
        } else if (*p == '?') {
            if (*s == '\0' || *s == '/')
                return false;
            p++;
            s++;
        } else {
            if (*p != *s)
                return false;
            p++;
            s++;
        }
    }
    return *s == '\0';
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* --- path arithmetic ---------------------------------------------------------- */

/* os.path.relpath(target, base) for absolute POSIX-style paths. */
static const char *rel_path(Arena *a, const char *target, const char *base) {
    size_t common = 0;
    Buf out;
    buf_init(&out, a);
    const char *tc[512], *bc[512];
    size_t tn = 0, bn = 0;
    char *tcopy = arena_alloc(a, strlen(target) + 1);
    strcpy(tcopy, target);
    char *bcopy = arena_alloc(a, strlen(base) + 1);
    strcpy(bcopy, base);
    for (char *p = tcopy; *p && tn < 512;) {
        while (*p == '/') p++;
        if (!*p) break;
        tc[tn++] = p;
        while (*p && *p != '/') p++;
        if (*p) *p++ = '\0';
    }
    for (char *p = bcopy; *p && bn < 512;) {
        while (*p == '/') p++;
        if (!*p) break;
        bc[bn++] = p;
        while (*p && *p != '/') p++;
        if (*p) *p++ = '\0';
    }
    while (common < tn && common < bn && strcmp(tc[common], bc[common]) == 0)
        common++;
    bool wrote = false;
    for (size_t i = common; i < bn; i++) {
        buf_addc(&out, wrote ? "/.." : "..");
        wrote = true;
    }
    for (size_t i = common; i < tn; i++) {
        if (wrote)
            buf_addch(&out, '/');
        buf_addc(&out, tc[i]);
        wrote = true;
    }
    if (!wrote)
        return ".";
    return buf_str(&out).p;
}

/* --- reading file heads/tails ------------------------------------------------- */

/* Up to `size` bytes of a regular file; from the end when `from_end`. "" on
 * anything unreadable. */
static Str read_part(Arena *a, const char *path, size_t size, bool from_end) {
    uint64_t fsize = 0;
    bool nr = false;
    FILE *f = fs_open_regular(path, &fsize, &nr);
    if (f == NULL)
        return str_c("");
    uint64_t off = 0;
    if (from_end)
        off = fsize > size ? fsize - size : 0;
    if (off && !fs_seek(f, off)) {
        fclose(f);
        return str_c("");
    }
    uint8_t *buf = arena_alloc(a, size ? size : 1);
    size_t got = fread(buf, 1, size, f);
    fclose(f);
    return str_copy(a, (const char *)buf, got);
}

/* =============================================================================
 * The bounded directory listing (_Tree)
 * ========================================================================== */

typedef struct { const char *lower; const char *actual; } Ent;

typedef struct {
    Arena *arena;
    const char *root;       /* directory that is listed */
    const char *base;       /* directory asset paths are reported relative to */
    const char *given;      /* file the caller pointed at, if any */
    const char *given_rel;  /* given relative to root, or NULL */
    VEC(Ent) files;
    VEC(Ent) dirs;
    /* markers */
    bool markers_done;
    VEC(const char *) marker_engine;    /* parallel: engine name of each hit */
    VEC(const char *) marker_text;
} Tree;

static void tree_walk(Tree *t) {
    typedef struct { const char *rel; int depth; } QItem;
    VEC(QItem) queue = {0};
    QItem *first = VEC_PUSH(t->arena, queue);
    first->rel = "";
    first->depth = 0;
    size_t head = 0;
    int budget = MAX_SCAN_ENTRIES;
    while (head < queue.n && budget > 0) {
        QItem item = queue.v[head++];
        const char *folder = item.rel[0] ? str_printf(t->arena, "%s/%s", t->root, item.rel).p
                                         : t->root;
        FsEntry *entries;
        size_t n;
        if (!fs_list(t->arena, folder, (size_t)budget, &entries, &n))
            continue;
        budget -= (int)n;
        /* sort by name */
        const char **order = arena_array(t->arena, n ? n : 1, sizeof *order);
        size_t *idx = arena_array(t->arena, n ? n : 1, sizeof *idx);
        for (size_t i = 0; i < n; i++) { order[i] = entries[i].name; idx[i] = i; }
        /* simple insertion sort on names, carrying idx */
        for (size_t i = 1; i < n; i++) {
            const char *ov = order[i];
            size_t oi = idx[i];
            size_t k = i;
            while (k > 0 && strcmp(order[k - 1], ov) > 0) {
                order[k] = order[k - 1];
                idx[k] = idx[k - 1];
                k--;
            }
            order[k] = ov;
            idx[k] = oi;
        }
        for (size_t i = 0; i < n; i++) {
            FsEntry *e = &entries[idx[i]];
            bool is_dir = e->kind == FS_DIR;
            bool is_file = !is_dir && e->target == FS_FILE;
            const char *child = item.rel[0] ? str_printf(t->arena, "%s/%s", item.rel, e->name).p
                                            : e->name;
            if (is_dir) {
                Ent *d = VEC_PUSH(t->arena, t->dirs);
                d->lower = lower_str(t->arena, child);
                d->actual = child;
                if (item.depth < MAX_DEPTH) {
                    QItem *q = VEC_PUSH(t->arena, queue);
                    q->rel = child;
                    q->depth = item.depth + 1;
                }
            } else if (is_file) {
                Ent *ff = VEC_PUSH(t->arena, t->files);
                ff->lower = lower_str(t->arena, child);
                ff->actual = child;
            }
        }
    }
}

static Tree *tree_new(Arena *a, const char *root, const char *base, const char *given) {
    Tree *t = arena_alloc(a, sizeof *t);
    memset(t, 0, sizeof *t);
    t->arena = a;
    t->root = root;
    t->base = base;
    t->given = given;
    tree_walk(t);
    if (given) {
        const char *gr = rel_path(a, platform_abspath(a, given), root);
        if (gr && strncmp(gr, "..", 2) != 0 && strcmp(gr, ".") != 0) {
            t->given_rel = gr;
            /* setdefault into files */
            const char *lo = lower_str(a, gr);
            bool have = false;
            for (size_t i = 0; i < t->files.n; i++)
                if (strcmp(t->files.v[i].lower, lo) == 0) { have = true; break; }
            if (!have) {
                Ent *ff = VEC_PUSH(a, t->files);
                ff->lower = lo;
                ff->actual = gr;
            }
        }
    }
    return t;
}

/* lookups ------------------------------------------------------------------------ */

static const char *tree_file(Tree *t, const char *const *cands, size_t n) {
    for (size_t c = 0; c < n; c++) {
        const char *lo = lower_str(t->arena, cands[c]);
        for (size_t i = 0; i < t->files.n; i++)
            if (strcmp(t->files.v[i].lower, lo) == 0)
                return t->files.v[i].actual;
    }
    return NULL;
}
#define TFILE(t, ...) tree_file((t), (const char *[]){__VA_ARGS__}, \
                                sizeof((const char *[]){__VA_ARGS__}) / sizeof(char *))

static const char *tree_dir(Tree *t, const char *const *cands, size_t n) {
    for (size_t c = 0; c < n; c++) {
        const char *lo = lower_str(t->arena, cands[c]);
        for (size_t i = 0; i < t->dirs.n; i++)
            if (strcmp(t->dirs.v[i].lower, lo) == 0)
                return t->dirs.v[i].actual;
    }
    return NULL;
}
#define TDIR(t, ...) tree_dir((t), (const char *[]){__VA_ARGS__}, \
                              sizeof((const char *[]){__VA_ARGS__}) / sizeof(char *))

typedef VEC(const char *) StrList;

static void sort_list(StrList *l) {
    if (l->n > 1)
        qsort(l->v, l->n, sizeof *l->v, cmp_str);
}

static StrList tree_glob(Tree *t, const char *const *pats, size_t npat, bool dirs) {
    StrList out = {0};
    Ent *table = dirs ? t->dirs.v : t->files.v;
    size_t n = dirs ? t->dirs.n : t->files.n;
    const char **lpats = arena_array(t->arena, npat, sizeof *lpats);
    for (size_t i = 0; i < npat; i++)
        lpats[i] = lower_str(t->arena, pats[i]);
    for (size_t i = 0; i < n; i++) {
        for (size_t p = 0; p < npat; p++)
            if (glob_match(lpats[p], table[i].lower)) {
                *VEC_PUSH(t->arena, out) = table[i].actual;
                break;
            }
    }
    sort_list(&out);
    return out;
}
#define TGLOB(t, ...) tree_glob((t), (const char *[]){__VA_ARGS__}, \
                               sizeof((const char *[]){__VA_ARGS__}) / sizeof(char *), false)
#define TGLOBD(t, ...) tree_glob((t), (const char *[]){__VA_ARGS__}, \
                                sizeof((const char *[]){__VA_ARGS__}) / sizeof(char *), true)

static StrList tree_named(Tree *t, const char *const *names, size_t n) {
    StrList out = {0};
    const char **lo = arena_array(t->arena, n, sizeof *lo);
    for (size_t i = 0; i < n; i++)
        lo[i] = lower_str(t->arena, names[i]);
    for (size_t i = 0; i < t->files.n; i++) {
        const char *base = strrchr(t->files.v[i].lower, '/');
        base = base ? base + 1 : t->files.v[i].lower;
        for (size_t k = 0; k < n; k++)
            if (strcmp(base, lo[k]) == 0) {
                *VEC_PUSH(t->arena, out) = t->files.v[i].actual;
                break;
            }
    }
    sort_list(&out);
    return out;
}
#define TNAMED(t, ...) tree_named((t), (const char *[]){__VA_ARGS__}, \
                                 sizeof((const char *[]){__VA_ARGS__}) / sizeof(char *))

static StrList tree_suffix(Tree *t, const char *const *sfx, size_t n) {
    StrList out = {0};
    const char **lo = arena_array(t->arena, n, sizeof *lo);
    for (size_t i = 0; i < n; i++)
        lo[i] = lower_str(t->arena, sfx[i]);
    for (size_t i = 0; i < t->files.n; i++) {
        size_t ll = strlen(t->files.v[i].lower);
        for (size_t k = 0; k < n; k++) {
            size_t sl = strlen(lo[k]);
            if (ll >= sl && memcmp(t->files.v[i].lower + ll - sl, lo[k], sl) == 0) {
                *VEC_PUSH(t->arena, out) = t->files.v[i].actual;
                break;
            }
        }
    }
    sort_list(&out);
    return out;
}
#define TSUFFIX(t, ...) tree_suffix((t), (const char *[]){__VA_ARGS__}, \
                                   sizeof((const char *[]){__VA_ARGS__}) / sizeof(char *))

static const char *tree_abspath(Tree *t, const char *relative) {
    return platform_abspath(t->arena, str_printf(t->arena, "%s/%s", t->root, relative).p);
}

static const char *tree_report(Tree *t, const char *relative) {
    return rel_path(t->arena, tree_abspath(t, relative), t->base);
}

static StrList tree_reports(Tree *t, StrList assets) {
    StrList out = {0};
    for (size_t i = 0; i < assets.n; i++) {
        const char *rep = tree_report(t, assets.v[i]);
        bool dup = false;
        for (size_t k = 0; k < out.n; k++)
            if (strcmp(out.v[k], rep) == 0) { dup = true; break; }
        if (!dup)
            *VEC_PUSH(t->arena, out) = rep;
    }
    sort_list(&out);
    if (out.n > MAX_ASSET_FILES)
        out.n = MAX_ASSET_FILES;
    return out;
}

static Str tree_head(Tree *t, const char *relative, size_t size) {
    return read_part(t->arena, tree_abspath(t, relative), size, false);
}
static Str tree_tail(Tree *t, const char *relative, size_t size) {
    return read_part(t->arena, tree_abspath(t, relative), size, true);
}

/* Open an archive at a relative path; NULL + reason on failure. */
static BsArchive *tree_archive(Tree *t, const char *relative, char *err, size_t errlen) {
    return bs_archive_open(tree_abspath(t, relative), err, errlen);
}

static bool tree_has_member(Tree *t, const char *relative, const char *member) {
    char err[256];
    BsArchive *a = tree_archive(t, relative, err, sizeof err);
    if (a == NULL)
        return false;
    bool found = false;
    for (size_t i = 0; i < bs_archive_count(a); i++)
        if (strcmp(bs_archive_entry(a, i)->name, member) == 0) { found = true; break; }
    bs_archive_close(a);
    return found;
}

static Str tree_member(Tree *t, const char *relative, const char *member, size_t limit) {
    char err[256];
    BsArchive *a = tree_archive(t, relative, err, sizeof err);
    if (a == NULL)
        return str_c("");
    /* bs_archive_read uses the archive's default max; the member helper only
     * needs small members, which are well under that limit. */
    (void)limit;
    uint8_t *data = NULL;
    size_t size = 0;
    Str out = str_c("");
    if (bs_archive_read(a, member, &data, &size, err, sizeof err)) {
        out = str_copy(t->arena, (const char *)data, size);
        free(data);
    }
    bs_archive_close(a);
    return out;
}

/* executables ------------------------------------------------------------------- */

static StrList tree_executables(Tree *t) {
    StrList out = {0};
    if (t->given_rel) {
        *VEC_PUSH(t->arena, out) = t->given_rel;
        return out;
    }
    /* top-level files, sorted; at most three exe-like ones */
    StrList top = {0};
    for (size_t i = 0; i < t->files.n; i++)
        if (strchr(t->files.v[i].lower, '/') == NULL)
            *VEC_PUSH(t->arena, top) = t->files.v[i].actual;
    sort_list(&top);
    for (size_t i = 0; i < top.n && out.n < 3; i++) {
        const char *lo = lower_str(t->arena, top.v[i]);
        size_t ll = strlen(lo);
        bool exe = (ll >= 4 && strcmp(lo + ll - 4, ".exe") == 0) ||
                   (ll >= 7 && strcmp(lo + ll - 7, ".x86_64") == 0) ||
                   (ll >= 4 && strcmp(lo + ll - 4, ".x86") == 0);
        if (exe) {
            *VEC_PUSH(t->arena, out) = top.v[i];
        } else if (strchr(lo, '.') == NULL) {
            Str h = tree_head(t, top.v[i], 4);
            if (h.n == 4 && memcmp(h.p, "\x7f" "ELF", 4) == 0)
                *VEC_PUSH(t->arena, out) = top.v[i];
        }
    }
    return out;
}

/* marker strings ----------------------------------------------------------------- */

static const struct { const char *engine; const char *text; } MARKERS[] = {
    {"Unity", "UnityPlayer.dll"}, {"Unity", "UnityMain"},
    {"Unreal Engine", "/Script/Engine"}, {"Unreal Engine", "/Script/CoreUObject"},
    {"Unreal Engine", "UnrealEngine"},
    {"Godot", "Godot Engine"},
    {"GameMaker", "YoYo Games"}, {"GameMaker", "GameMaker"},
    {"Electron", "ELECTRON_RUN_AS_NODE"},
    {"Java", "launch4j"}, {"Java", "JNI_CreateJavaVM"},
    {"MonoGame/XNA", "Microsoft.Xna.Framework"}, {"MonoGame/XNA", "MonoGame.Framework"},
    {"RPG Maker", "RGSSGameMain"},
    {"L\xC3\x96VE", "love.boot"},
};
#define NMARKERS (sizeof MARKERS / sizeof MARKERS[0])

static void tree_markers(Tree *t) {
    if (t->markers_done)
        return;
    t->markers_done = true;
    bool found[NMARKERS] = {false};
    /* utf-16-le patterns */
    uint8_t *u16[NMARKERS];
    size_t u16len[NMARKERS];
    size_t alen[NMARKERS];
    for (size_t i = 0; i < NMARKERS; i++) {
        alen[i] = strlen(MARKERS[i].text);
        u16len[i] = alen[i] * 2;
        u16[i] = arena_alloc(t->arena, u16len[i] ? u16len[i] : 1);
        for (size_t k = 0; k < alen[i]; k++) {
            u16[i][k * 2] = (uint8_t)MARKERS[i].text[k];
            u16[i][k * 2 + 1] = 0;
        }
    }
    size_t overlap = 0;
    for (size_t i = 0; i < NMARKERS; i++)
        if (u16len[i] > overlap)
            overlap = u16len[i];

    uint64_t budget = MAX_EXE_SCAN;
    StrList exes = tree_executables(t);
    for (size_t ei = 0; ei < exes.n && budget > 0; ei++) {
        const char *path = tree_abspath(t, exes.v[ei]);
        uint64_t fsize = 0;
        bool nr = false;
        FILE *f = fs_open_regular(path, &fsize, &nr);
        if (f == NULL)
            continue;
        uint8_t *carry = arena_alloc(t->arena, overlap ? overlap : 1);
        size_t carryn = 0;
        uint8_t *chunk = arena_alloc(t->arena, 1 << 20);
        uint8_t *window = arena_alloc(t->arena, (1 << 20) + overlap);
        while (budget > 0) {
            size_t want = budget < (1 << 20) ? (size_t)budget : (1 << 20);
            size_t got = fread(chunk, 1, want, f);
            if (got == 0)
                break;
            budget -= got;
            memcpy(window, carry, carryn);
            memcpy(window + carryn, chunk, got);
            size_t wlen = carryn + got;
            for (size_t i = 0; i < NMARKERS; i++) {
                if (found[i])
                    continue;
                if (mem_find(window, wlen, MARKERS[i].text, alen[i]) ||
                    mem_find(window, wlen, u16[i], u16len[i])) {
                    found[i] = true;
                    *VEC_PUSH(t->arena, t->marker_engine) = MARKERS[i].engine;
                    *VEC_PUSH(t->arena, t->marker_text) = MARKERS[i].text;
                }
            }
            carryn = wlen < overlap ? wlen : overlap;
            memcpy(carry, window + wlen - carryn, carryn);
        }
        fclose(f);
    }
}

/* Marker hits for an engine, as a ", "-joined, quoted list, or NULL. */
static const char *markers_for(Tree *t, const char *engine) {
    tree_markers(t);
    Buf b;
    buf_init(&b, t->arena);
    bool any = false;
    for (size_t i = 0; i < t->marker_engine.n; i++) {
        if (strcmp(t->marker_engine.v[i], engine) != 0)
            continue;
        buf_printf(&b, "%s'%s'", any ? ", " : "", t->marker_text.v[i]);
        any = true;
    }
    return any ? buf_str(&b).p : NULL;
}

/* =============================================================================
 * Evidence cases
 * ========================================================================== */

typedef struct { const char *k, *v; } KV;
typedef struct {
    Tree *t;
    const char *engine;
    int score;
    VEC(const char *) evidence;
    VEC(KV) details;
    StrList assets;
    VEC(const char *) advice;
} Case;

static void case_init(Case *c, Tree *t, const char *engine) {
    memset(c, 0, sizeof *c);
    c->t = t;
    c->engine = engine;
}
static void c_add(Case *c, int weight, const char *text) {
    c->score += weight;
    *VEC_PUSH(c->t->arena, c->evidence) = text;
}
static void c_add_markers(Case *c) {
    const char *hits = markers_for(c->t, c->engine);
    if (hits)
        c_add(c, GOOD, str_printf(c->t->arena, "marker string %s in the executable", hits).p);
}
static void c_detail_set(Case *c, const char *k, const char *v) {
    for (size_t i = 0; i < c->details.n; i++)
        if (strcmp(c->details.v[i].k, k) == 0) { c->details.v[i].v = v; return; }
    KV *kv = VEC_PUSH(c->t->arena, c->details);
    kv->k = k;
    kv->v = v;
}
static void c_detail_default(Case *c, const char *k, const char *v) {
    for (size_t i = 0; i < c->details.n; i++)
        if (strcmp(c->details.v[i].k, k) == 0)
            return;
    KV *kv = VEC_PUSH(c->t->arena, c->details);
    kv->k = k;
    kv->v = v;
}
static const char *c_detail_get(Case *c, const char *k) {
    for (size_t i = 0; i < c->details.n; i++)
        if (strcmp(c->details.v[i].k, k) == 0)
            return c->details.v[i].v;
    return NULL;
}
static void c_advice(Case *c, const char *text) {
    *VEC_PUSH(c->t->arena, c->advice) = text;
}
static void c_asset(Case *c, const char *rel) {
    *VEC_PUSH(c->t->arena, c->assets) = rel;
}
static void c_assets_list(Case *c, StrList list) {
    for (size_t i = 0; i < list.n; i++)
        c_asset(c, list.v[i]);
}

/* rstrip a trailing '.' */
static const char *strip_dot(Arena *a, const char *s) {
    size_t n = strlen(s);
    while (n > 0 && s[n - 1] == '.')
        n--;
    return str_copy(a, s, n).p;
}

/* (can vex open it, advice sentence). */
static bool archive_advice(Tree *t, const char *relative, const char *what, const char **sentence) {
    Arena *a = t->arena;
    const char *shown = tree_report(t, relative);
    char err[512];
    BsArchive *ar = tree_archive(t, relative, err, sizeof err);
    if (ar == NULL) {
        *sentence = str_printf(a, "vex cannot open %s: %s.", shown, strip_dot(a, err)).p;
        return false;
    }
    bool writable = bs_archive_writable(ar);
    if (writable) {
        *sentence = str_printf(a,
            "vex can browse, extract and repack %s (%s): open it in the Assets view, or run "
            "`vex assets list PACK`, `vex assets extract PACK FOLDER`, `vex assets "
            "replace PACK NAME NEWFILE -o NEWPACK`. Repacking always writes a new file, so keep "
            "the original as a backup.", what, shown).p;
        bs_archive_close(ar);
        return true;
    }
    Buf why;
    buf_init(&why, a);
    bool first = true;
    for (size_t i = 0; i < bs_archive_note_count(ar); i++) {
        const char *note = bs_archive_note(ar, i);
        if (strstr(note, "repack") || strstr(note, "encrypted")) {
            buf_printf(&why, "%s%s", first ? "" : "; ", note);
            first = false;
        }
    }
    const char *whytext = why.n ? strip_dot(a, buf_str(&why).p) : "not supported for this pack";
    *sentence = str_printf(a,
        "vex can browse and extract %s (%s) in the Assets view or with `vex assets list "
        "PACK` and `vex assets extract PACK FOLDER`, but cannot repack it: %s.", what, shown,
        whytext).p;
    bs_archive_close(ar);
    return true;
}

/* small helpers over Str for substring/regex-lite ------------------------------- */

static bool bytes_contains(Str s, const char *needle) {
    return mem_find(s.p, s.n, needle, strlen(needle)) != NULL;
}

/* search for a semantic version like 2021.3.16f1 in a head buffer */
static const char *find_unity_version(Arena *a, Str head) {
    /* (?<![\d.]) d{1,4}.d{1,2}.d{1,3}[abcfpx]d{1,3} */
    for (size_t i = 0; i < head.n; i++) {
        if (i > 0) {
            char pc = head.p[i - 1];
            if ((pc >= '0' && pc <= '9') || pc == '.')
                continue;
        }
        size_t j = i, d;
        d = j; while (j < head.n && head.p[j] >= '0' && head.p[j] <= '9' && j - d < 4) j++;
        if (j == d || j >= head.n || head.p[j] != '.') continue;
        size_t a1 = j - d; (void)a1;
        j++;
        d = j; while (j < head.n && head.p[j] >= '0' && head.p[j] <= '9' && j - d < 2) j++;
        if (j == d || j >= head.n || head.p[j] != '.') continue;
        j++;
        d = j; while (j < head.n && head.p[j] >= '0' && head.p[j] <= '9' && j - d < 3) j++;
        if (j == d || j >= head.n) continue;
        char rel = head.p[j];
        if (rel != 'a' && rel != 'b' && rel != 'c' && rel != 'f' && rel != 'p' && rel != 'x')
            continue;
        j++;
        d = j; while (j < head.n && head.p[j] >= '0' && head.p[j] <= '9' && j - d < 3) j++;
        if (j == d) continue;
        return str_copy(a, head.p + i, j - i).p;
    }
    return NULL;
}

/* =============================================================================
 * Detectors
 * ========================================================================== */

static void d_unity(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Unity");
    const char *player = TFILE(t, "UnityPlayer.dll", "UnityPlayer.so", "UnityPlayer.dylib");
    if (player)
        c_add(c, STRONG, str_printf(a, "%s next to the executable", player).p);
    const char *data_dir = NULL;
    StrList datas = TGLOBD(t, "*_data");
    for (size_t i = 0; i < datas.n && !data_dir; i++) {
        const char *folder = datas.v[i];
        Buf contents;
        buf_init(&contents, a);
        bool any = false;
        const char *fnames[] = {"globalgamemanagers", "mainData", "data.unity3d",
                                "resources.assets"};
        for (size_t k = 0; k < 4; k++) {
            const char *p = str_printf(a, "%s/%s", folder, fnames[k]).p;
            if (TFILE(t, p)) {
                buf_printf(&contents, "%s%s", any ? ", " : "", fnames[k]);
                any = true;
            }
        }
        const char *dnames[] = {"Managed", "il2cpp_data"};
        for (size_t k = 0; k < 2; k++) {
            const char *p = str_printf(a, "%s/%s", folder, dnames[k]).p;
            if (TDIR(t, p)) {
                buf_printf(&contents, "%s%s/", any ? ", " : "", dnames[k]);
                any = true;
            }
        }
        if (any) {
            data_dir = folder;
            c_add(c, STRONG, str_printf(a, "%s/ folder with Unity player data (%s)", folder,
                                        buf_str(&contents).p).p);
        }
    }
    const char *il2cpp = TFILE(t, "GameAssembly.dll", "GameAssembly.so", "GameAssembly.dylib");
    StrList managed = TGLOB(t, "*_data/managed/assembly-csharp.dll");
    if (il2cpp) {
        c_add(c, GOOD, str_printf(a, "%s (IL2CPP-compiled game code)", il2cpp).p);
        c_detail_set(c, "scripting", "IL2CPP");
    } else if (managed.n) {
        c_add(c, GOOD, str_printf(a, "%s (Mono game code)", managed.v[0]).p);
        c_detail_set(c, "scripting", "Mono");
    }
    const char *crash = TFILE(t, "UnityCrashHandler64.exe", "UnityCrashHandler32.exe");
    if (crash)
        c_add(c, GOOD, crash);
    if (TDIR(t, "MonoBleedingEdge"))
        c_add(c, WEAK, "MonoBleedingEdge/ folder");
    c_add_markers(c);
    if (!c->score)
        return;

    if (data_dir) {
        const char *names[] = {"globalgamemanagers", "data.unity3d", "mainData", "level0"};
        for (size_t k = 0; k < 4; k++) {
            const char *p = str_printf(a, "%s/%s", data_dir, names[k]).p;
            const char *found = TFILE(t, p);
            if (!found)
                continue;
            const char *v = find_unity_version(a, tree_head(t, found, 256));
            if (v) {
                c_detail_set(c, "version", v);
                break;
            }
        }
    }
    c_assets_list(c, TGLOB(t,
        "*_data/*.assets", "*_data/data.unity3d", "*_data/globalgamemanagers", "*_data/maindata",
        "*_data/level*", "*_data/*.bundle", "*_data/*.unity3d", "*_data/streamingassets/*.bundle",
        "*_data/streamingassets/*/*.bundle", "*_data/streamingassets/*.unity3d"));
    c_advice(c, "vex cannot open Unity's serialized files (.assets, level*, "
             "globalgamemanagers) or asset bundles / UnityFS (data.unity3d, *.bundle). Use "
             "AssetStudio or AssetRipper to browse and export assets, and UABEA to edit or "
             "replace them.");
    const char *scr = c_detail_get(c, "scripting");
    if (scr && strcmp(scr, "IL2CPP") == 0) {
        c_advice(c, "Game code is compiled to native code (IL2CPP) in GameAssembly: vex can "
                 "disassemble it like any native binary, but recovering class and method names "
                 "needs Il2CppDumper or Cpp2IL together with il2cpp_data/Metadata/"
                 "global-metadata.dat.");
        StrList md = TGLOB(t, "*_data/il2cpp_data/metadata/global-metadata.dat");
        if (md.n) {
            Str h = tree_head(t, md.v[0], 4);
            if (h.n != 0 && !(h.n == 4 && memcmp(h.p, "\xaf\x1b\xb1\xfa", 4) == 0))
                c_advice(c, str_printf(a, "%s does not start with the IL2CPP metadata signature: "
                         "it is probably encrypted or obfuscated. vex does not decrypt it.",
                         tree_report(t, md.v[0])).p);
        }
    } else if (scr && strcmp(scr, "Mono") == 0) {
        c_advice(c, str_printf(a, "Game code is .NET IL in %s: decompile and edit it with ILSpy or "
                 "dnSpy (dnSpyEx). vex only reads the PE headers of .NET assemblies; it does "
                 "not decompile IL.", tree_report(t, managed.v[0])).p);
    }
}

static void d_unreal(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Unreal Engine");
    if (TDIR(t, "Engine/Binaries"))
        c_add(c, STRONG, "Engine/Binaries folder");
    else if (TDIR(t, "Engine/Content"))
        c_add(c, GOOD, "Engine/Content folder");
    StrList paks = TGLOB(t, "*/content/paks/*.pak", "content/paks/*.pak", "*/content/paks/*/*.pak");
    if (paks.n)
        c_add(c, STRONG, str_printf(a, "%s (Content/Paks/*.pak)", tree_report(t, paks.v[0])).p);
    StrList iostore = TGLOB(t, "*/content/paks/*.utoc", "*/content/paks/*.ucas",
                            "content/paks/*.utoc", "content/paks/*.ucas");
    StrList packages = TGLOB(t, "*/cookedpc/*.upk", "*/cookedpcconsole/*.upk", "*/content/*.upk");
    if (packages.n)
        c_add(c, GOOD, str_printf(a, "%s (Unreal Engine 3 package)", tree_report(t, packages.v[0])).p);
    StrList exes = tree_executables(t);
    const char *shipping = NULL;
    for (size_t i = 0; i < exes.n && !shipping; i++) {
        const char *lo = lower_str(a, exes.v[i]);
        const char *pats[] = {"-win64-shipping", "-win32-shipping", "-linux-shipping",
                              "-wingdk-shipping"};
        for (size_t k = 0; k < 4; k++)
            if (strstr(lo, pats[k])) { shipping = exes.v[i]; break; }
    }
    if (shipping)
        c_add(c, GOOD, str_printf(a, "%s (Unreal shipping executable name)", shipping).p);
    if (TGLOB(t, "manifest_nonufsfiles_*.txt", "manifest_ufsfiles_*.txt").n)
        c_add(c, GOOD, "Manifest_NonUFSFiles_*.txt (Unreal packaging manifest)");
    c_add_markers(c);
    if (!c->score)
        return;

    for (size_t i = 0; i < paks.n; i++) c_asset(c, paks.v[i]);
    for (size_t i = 0; i < iostore.n; i++) c_asset(c, iostore.v[i]);
    for (size_t i = 0; i < packages.n; i++) c_asset(c, packages.v[i]);
    if (iostore.n)
        c_detail_set(c, "packaging", "IoStore (.utoc/.ucas) with .pak");
    else if (paks.n)
        c_detail_set(c, "packaging", ".pak");
    bool encrypted = false;
    for (size_t i = 0; i < paks.n && i < 4; i++) {
        Str tail = tree_tail(t, paks.v[i], 512);
        void *at = NULL;
        for (long k = (long)tail.n - 4; k >= 0; k--)
            if (memcmp(tail.p + k, "\xe1\x12\x6f\x5a", 4) == 0) { at = (void *)(tail.p + k); break; }
        if (at == NULL)
            continue;
        size_t off = (size_t)((const char *)at - tail.p);
        if (off < 1 || off + 8 > tail.n)
            continue;
        uint32_t version = (uint8_t)tail.p[off + 4] | (uint8_t)tail.p[off + 5] << 8 |
                           (uint8_t)tail.p[off + 6] << 16 | (uint32_t)(uint8_t)tail.p[off + 7] << 24;
        if (version < 1 || version > 32)
            continue;
        c_detail_set(c, "pak_version", str_printf(a, "%u", version).p);
        if (version >= 4 && (uint8_t)tail.p[off - 1] == 1) {
            encrypted = true;
            c_detail_set(c, "pak_index_encrypted", "yes");
        }
        break;
    }
    c_advice(c, "vex cannot open Unreal .pak or IoStore (.utoc/.ucas) containers, nor the "
             ".uasset/.umap packages inside. Use FModel or UE Viewer (umodel) to browse and "
             "export assets, and UnrealPak or repak to build paks.");
    c_advice(c, "Mods are normally shipped as an additional patch pak (a name ending in _P) in "
             "Content/Paks, often in a ~mods subfolder, rather than by rewriting the game's own "
             "pak.");
    if (encrypted)
        c_advice(c, "The pak index is encrypted (AES): those tools need the game's key. vex "
                 "does not decrypt paks and does not recover keys.");
}

static const char *godot_header(Arena *a, Str data, int *fmt, uint32_t *flags) {
    if (data.n < 20 || memcmp(data.p, "GDPC", 4) != 0)
        return NULL;
    const uint8_t *p = (const uint8_t *)data.p;
    uint32_t f = (uint32_t)p[4] | p[5] << 8 | p[6] << 16 | (uint32_t)p[7] << 24;
    uint32_t major = (uint32_t)p[8] | p[9] << 8 | p[10] << 16 | (uint32_t)p[11] << 24;
    uint32_t minor = (uint32_t)p[12] | p[13] << 8 | p[14] << 16 | (uint32_t)p[15] << 24;
    uint32_t patch = (uint32_t)p[16] | p[17] << 8 | p[18] << 16 | (uint32_t)p[19] << 24;
    *fmt = (int)f;
    *flags = (f >= 2 && data.n >= 24) ? ((uint32_t)p[20] | p[21] << 8 | p[22] << 16 |
                                         (uint32_t)p[23] << 24) : 0;
    return str_printf(a, "%u.%u.%u", major, minor, patch).p;
}

static void d_godot(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Godot");
    StrList packs = {0};
    int hfmt = 0;
    uint32_t hflags = 0;
    const char *hver = NULL;
    StrList pcks = TSUFFIX(t, ".pck");
    for (size_t i = 0; i < pcks.n && i < 8; i++) {
        Str head = tree_head(t, pcks.v[i], 32);
        int fmt = 0;
        uint32_t flags = 0;
        const char *ver = godot_header(a, head, &fmt, &flags);
        if (ver) {
            *VEC_PUSH(a, packs) = pcks.v[i];
            if (!hver) { hver = ver; hfmt = fmt; hflags = flags; }
            c_add(c, STRONG, str_printf(a, "%s is a Godot pack ('GDPC' signature, pack format %d, "
                  "engine %s)", tree_report(t, pcks.v[i]), fmt, ver).p);
        } else if (head.n == 0) {
            c_add(c, WEAK, str_printf(a, "%s (.pck file; its signature could not be read)",
                  tree_report(t, pcks.v[i])).p);
        }
    }
    StrList exes = tree_executables(t);
    for (size_t i = 0; i < exes.n; i++) {
        Str tail = tree_tail(t, exes.v[i], 12);
        if (tail.n == 12 && memcmp(tail.p + 8, "GDPC", 4) == 0) {
            uint64_t sz = 0;
            for (int k = 7; k >= 0; k--)
                sz = sz << 8 | (uint8_t)tail.p[k];
            uint64_t fsize = 0;
            if (!fs_size(tree_abspath(t, exes.v[i]), &fsize))
                continue;
            if (fsize < 12 + sz)
                continue;
            uint64_t start = fsize - 12 - sz;
            if (start == 0)
                continue;
            Str emb = str_c("");
            {
                uint64_t fs2 = 0; bool nr = false;
                FILE *f = fs_open_regular(tree_abspath(t, exes.v[i]), &fs2, &nr);
                if (f && fs_seek(f, start)) {
                    uint8_t *buf = arena_alloc(a, 32);
                    size_t got = fread(buf, 1, 32, f);
                    emb = str_copy(a, (const char *)buf, got);
                }
                if (f) fclose(f);
            }
            int fmt = 0;
            uint32_t flags = 0;
            const char *ver = godot_header(a, emb, &fmt, &flags);
            if (ver) {
                *VEC_PUSH(a, packs) = exes.v[i];
                if (!hver) { hver = ver; hfmt = fmt; hflags = flags; }
                char ob[40];
                c_add(c, STRONG, str_printf(a, "Godot pack embedded in %s at offset %s (pack "
                      "format %d, engine %s)", tree_report(t, exes.v[i]), hex_big(ob, (big)start),
                      fmt, ver).p);
            }
        }
    }
    c_add_markers(c);
    if (!c->score)
        return;

    c_assets_list(c, packs);
    bool encrypted = false;
    if (hver) {
        c_detail_set(c, "version", hver);
        c_detail_set(c, "pack_format", str_printf(a, "%d", hfmt).p);
        if (hfmt >= 2 && (hflags & 1)) {
            encrypted = true;
            c_detail_set(c, "encrypted", "yes");
        }
    }
    if (TGLOB(t, "data_*/godotsharp.dll", "data_*/*/godotsharp.dll").n)
        c_detail_set(c, "scripting", "C# (.NET) and GDScript");
    for (size_t i = 0; i < packs.n && i < 2; i++) {
        const char *s = NULL;
        archive_advice(t, packs.v[i], "this Godot pack", &s);
        c_advice(c, s);
    }
    if (encrypted)
        c_advice(c, "The pack's index is encrypted with a key compiled into the game. vex "
                 "reports this but does not decrypt the pack or recover the key.");
    if (packs.n)
        c_advice(c, "Files inside a pack are in Godot's imported formats (.ctex/.stex textures, "
                 ".sample/.oggvorbisstr audio, binary .scn/.res, compiled .gdc scripts): use "
                 "gdsdecomp (GDRE Tools) to convert them back or to decompile scripts.");
    if (c_detail_get(c, "scripting"))
        c_advice(c, "C# game code is in .NET assemblies under the data_* folder: decompile them "
                 "with ILSpy or dnSpy.");
}

static void d_gamemaker(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "GameMaker");
    StrList data_files = TNAMED(t, "data.win", "game.unx", "game.ios", "game.droid");
    const char *confirmed = NULL;
    for (size_t i = 0; i < data_files.n; i++) {
        Str head = tree_head(t, data_files.v[i], 32);
        if (head.n >= 4 && memcmp(head.p, "FORM", 4) == 0) {
            if (!confirmed) confirmed = data_files.v[i];
            c_add(c, STRONG, str_printf(a, "%s starts with GameMaker's 'FORM' signature",
                  tree_report(t, data_files.v[i])).p);
            if (head.n >= 18 && memcmp(head.p + 8, "GEN8", 4) == 0)
                c_detail_default(c, "bytecode_version", str_printf(a, "%u", (uint8_t)head.p[17]).p);
        } else {
            c_add(c, WEAK, str_printf(a, "a file named %s (GameMaker's data file name, signature "
                  "not confirmed)", tree_report(t, data_files.v[i])).p);
        }
    }
    if (confirmed && TFILE(t, "options.ini"))
        c_add(c, WEAK, "options.ini next to the data file");
    c_add_markers(c);
    if (!c->score)
        return;
    c_assets_list(c, data_files);
    c_assets_list(c, TGLOB(t, "audiogroup*.dat", "*/audiogroup*.dat"));
    c_advice(c, "vex cannot open data.win / game.unx (GameMaker's IFF-style 'FORM' data file "
             "holding sprites, sounds, rooms and code). Use UndertaleModTool to browse and edit "
             "it.");
    c_advice(c, "Games built with the YYC compiler have their code compiled into the executable "
             "instead of bytecode in the data file; vex can disassemble that as native code "
             "but cannot recover GML.");
}

/* version = u?['"]([0-9][0-9.]*)['"] after `version =` (multiline) */
static const char *find_renpy_version(Arena *a, Str head) {
    const char *key = "version";
    for (size_t i = 0; i + 7 <= head.n; i++) {
        /* at start of line */
        if (i != 0 && head.p[i - 1] != '\n')
            continue;
        if (memcmp(head.p + i, key, 7) != 0)
            continue;
        size_t j = i + 7;
        while (j < head.n && (head.p[j] == ' ' || head.p[j] == '\t')) j++;
        if (j >= head.n || head.p[j] != '=') continue;
        j++;
        while (j < head.n && (head.p[j] == ' ' || head.p[j] == '\t')) j++;
        if (j < head.n && (head.p[j] == 'u')) j++;
        if (j >= head.n || (head.p[j] != '\'' && head.p[j] != '"')) continue;
        char q = head.p[j++];
        size_t s = j;
        if (s >= head.n || !(head.p[s] >= '0' && head.p[s] <= '9')) continue;
        while (j < head.n && ((head.p[j] >= '0' && head.p[j] <= '9') || head.p[j] == '.')) j++;
        if (j >= head.n || head.p[j] != q) continue;
        return str_copy(a, head.p + s, j - s).p;
    }
    return NULL;
}

static void d_renpy(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Ren'Py");
    if (TDIR(t, "renpy")) {
        c_add(c, GOOD, "renpy/ folder (the engine's Python package)");
        if (TFILE(t, "renpy/__init__.py", "renpy/__init__.pyo", "renpy/__init__.pyc") ||
            TDIR(t, "renpy/common"))
            c_add(c, GOOD, "renpy/ contains the engine modules");
    }
    StrList archives_found = TSUFFIX(t, ".rpa");
    StrList game_rpa = TGLOB(t, "game/*.rpa");
    if (game_rpa.n)
        c_add(c, GOOD, str_printf(a, "%s (Ren'Py archive in game/)", game_rpa.v[0]).p);
    StrList scripts = TGLOB(t, "game/*.rpyc", "game/*.rpy", "game/*/*.rpyc", "game/*/*.rpy");
    if (scripts.n)
        c_add(c, GOOD, str_printf(a, "%s (Ren'Py script)", scripts.v[0]).p);
    if (TGLOBD(t, "lib/py*", "lib/windows-*", "lib/linux-*").n)
        c_add(c, WEAK, "lib/ folder with a bundled Python runtime");
    if (!c->score)
        return;

    if (TFILE(t, "renpy/vc_version.py")) {
        const char *v = find_renpy_version(a, tree_head(t, "renpy/vc_version.py", 4096));
        if (v)
            c_detail_set(c, "version", v);
    }
    c_assets_list(c, archives_found);
    if (archives_found.n) {
        const char *s = NULL;
        bool ok = archive_advice(t, archives_found.v[0], "Ren'Py RPA archives", &s);
        c_advice(c, s);
        if (!ok)
            c_advice(c, "Only the standard RPA-2.0 and RPA-3.0 archive layouts are supported; a "
                     "different header means the developer changed the format, which is not "
                     "supported.");
    }
    c_advice(c, "Ren'Py looks for a file in the game/ folder before it looks in the archives, so a "
             "changed image, sound or script can simply be placed in game/ under the same path; "
             "repacking is rarely necessary.");
    c_advice(c, ".rpyc files are compiled scripts: vex does not decompile them; use unrpyc to "
             "get .rpy sources back.");
}

static void d_rpg_maker(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "RPG Maker");
    const char *mv = TFILE(t, "www/js/rpg_core.js", "js/rpg_core.js");
    const char *mz = TFILE(t, "js/rmmz_core.js", "www/js/rmmz_core.js");
    StrList rgss = TGLOB(t, "*.rgss3a", "*.rgss2a", "*.rgssad");
    if (mz) {
        c_add(c, STRONG, str_printf(a, "%s (RPG Maker MZ core script)", mz).p);
        c_detail_set(c, "version", "MZ");
    } else if (mv) {
        c_add(c, STRONG, str_printf(a, "%s (RPG Maker MV core script)", mv).p);
        c_detail_set(c, "version", "MV");
    }
    if (rgss.n) {
        const char *lo = lower_str(a, rgss.v[0]);
        const char *suffix = strrchr(lo, '.');
        suffix = suffix ? suffix + 1 : lo;
        const char *ver = strcmp(suffix, "rgss3a") == 0 ? "VX Ace" :
                          strcmp(suffix, "rgss2a") == 0 ? "VX" : "XP";
        c_detail_default(c, "version", ver);
        c_add(c, STRONG, str_printf(a, "%s (RGSS encrypted archive)", rgss.v[0]).p);
    }
    StrList libs = TGLOB(t, "rgss*.dll", "system/rgss*.dll");
    if (libs.n)
        c_add(c, GOOD, str_printf(a, "%s (RGSS runtime library)", libs.v[0]).p);
    if (TFILE(t, "RPG_RT.exe") && TFILE(t, "RPG_RT.ldb", "RPG_RT.lmt")) {
        c_add(c, STRONG, "RPG_RT.exe with RPG_RT.ldb (RPG Maker 2000/2003)");
        c_detail_default(c, "version", "2000/2003");
    }
    c_add_markers(c);
    if (!c->score)
        return;

    c_assets_list(c, rgss);
    if (mv || mz) {
        const char *system = TFILE(t, "www/data/System.json", "data/System.json");
        bool flagged = false;
        if (system) {
            Str h = tree_head(t, system, 1 << 20);
            flagged = bytes_contains(h, "\"hasEncryptedImages\"") &&
                      (mem_find(h.p, h.n, "true", 4) != NULL);
            /* a close-enough port: flagged when the head says hasEncrypted(Images|Audio): true */
            bool imgs = false, aud = false;
            const char *ki = "\"hasEncryptedImages\"", *ka = "\"hasEncryptedAudio\"";
            void *pi = mem_find(h.p, h.n, ki, strlen(ki));
            void *pa = mem_find(h.p, h.n, ka, strlen(ka));
            if (pi) {
                const char *q = (const char *)pi + strlen(ki);
                while (q < h.p + h.n && (*q == ' ' || *q == ':')) q++;
                imgs = (size_t)(h.p + h.n - q) >= 4 && memcmp(q, "true", 4) == 0;
            }
            if (pa) {
                const char *q = (const char *)pa + strlen(ka);
                while (q < h.p + h.n && (*q == ' ' || *q == ':')) q++;
                aud = (size_t)(h.p + h.n - q) >= 4 && memcmp(q, "true", 4) == 0;
            }
            flagged = imgs || aud;
        }
        StrList scrambled = TSUFFIX(t, ".rpgmvp", ".rpgmvo", ".rpgmvm", ".png_", ".ogg_", ".m4a_");
        if (flagged || scrambled.n) {
            c_detail_set(c, "encrypted_assets", "yes");
            c_assets_list(c, scrambled);
            c_advice(c, "Images and/or audio were deployed with RPG Maker's built-in asset "
                     "encryption (.rpgmvp/.rpgmvo/.rpgmvm, or .png_/.ogg_/.m4a_ in MZ). vex "
                     "reports this but does not decrypt them.");
        } else {
            c_advice(c, "Images (img/) and audio (audio/) are plain .png/.ogg/.m4a files: replace "
                     "them directly, no container is involved.");
        }
        c_advice(c, "Game data (data/*.json), scripts (js/) and plugins are plain text files that "
                 "can be edited directly.");
    }
    if (rgss.n)
        c_advice(c, str_printf(a, "%s is an RGSS archive, which is always encrypted: vex "
                 "cannot open it and does not decrypt it.", rgss.v[0]).p);
    const char *ver = c_detail_get(c, "version");
    if (ver && strcmp(ver, "2000/2003") == 0)
        c_advice(c, "RPG Maker 2000/2003 keeps assets as loose files in folders next to RPG_RT.exe "
                 "(some in the proprietary XYZ image format); vex has no special support for "
                 "its .ldb/.lmu databases. EasyRPG's tools can read them.");
}

static void d_electron(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Electron");
    const char *app = TFILE(t, "resources/app.asar");
    if (app)
        c_add(c, STRONG, str_printf(a, "%s (Electron application archive)", app).p);
    else if (TFILE(t, "resources/app/package.json"))
        c_add(c, GOOD, "resources/app/package.json (unpacked Electron application)");
    const char *other = TFILE(t, "resources/electron.asar", "resources/default_app.asar");
    if (other)
        c_add(c, GOOD, other);
    bool is_nw = TFILE(t, "nw.pak", "nw.dll", "package.nw", "nw_100_percent.pak") != NULL;
    const char *rnames[] = {"icudtl.dat", "v8_context_snapshot.bin", "snapshot_blob.bin",
                            "chrome_100_percent.pak", "resources.pak"};
    Buf runtime;
    buf_init(&runtime, a);
    int nruntime = 0;
    for (size_t k = 0; k < 5; k++)
        if (TFILE(t, rnames[k])) {
            buf_printf(&runtime, "%s%s", nruntime ? ", " : "", rnames[k]);
            nruntime++;
        }
    if (c->score && nruntime >= 2 && !is_nw)
        c_add(c, WEAK, str_printf(a, "Chromium runtime files (%s)", buf_str(&runtime).p).p);
    c_add_markers(c);
    if (!c->score)
        return;

    if (TFILE(t, "version")) {
        Str h = tree_head(t, "version", 64);
        /* v?(\d+\.\d+\.\d+)\s*\Z */
        size_t i = 0;
        if (i < h.n && h.p[i] == 'v') i++;
        size_t s = i, d;
        d = i; while (i < h.n && h.p[i] >= '0' && h.p[i] <= '9') i++;
        bool ok = i > d;
        if (ok && i < h.n && h.p[i] == '.') { i++; d = i; while (i < h.n && h.p[i] >= '0' && h.p[i] <= '9') i++; ok = i > d; }
        else ok = false;
        if (ok && i < h.n && h.p[i] == '.') { i++; d = i; while (i < h.n && h.p[i] >= '0' && h.p[i] <= '9') i++; ok = i > d; }
        else ok = false;
        size_t e = i;
        while (i < h.n && (h.p[i] == ' ' || h.p[i] == '\t' || h.p[i] == '\r' || h.p[i] == '\n')) i++;
        if (ok && i == h.n)
            c_detail_set(c, "version", str_copy(a, h.p + s, e - s).p);
    }
    c_assets_list(c, TGLOB(t, "resources/*.asar"));
    if (app) {
        const char *s = NULL;
        archive_advice(t, app, "the application archive", &s);
        c_advice(c, s);
        c_advice(c, "The archive holds the app's JavaScript, HTML and CSS as plain files. Files its "
                 "header marks as unpacked live in resources/app.asar.unpacked/ instead.");
        c_advice(c, "If the app enables Electron's ASAR integrity validation, a modified app.asar "
                 "is rejected unless the hash stored in the executable is updated as well; "
                 "vex does not do that.");
    } else if (TFILE(t, "resources/app/package.json")) {
        c_advice(c, "The application is not packed: its JavaScript, HTML and CSS are plain files "
                 "under resources/app/ and can be edited directly.");
    } else {
        c_advice(c, "No resources/app.asar was found next to this executable; if the app keeps one "
                 "elsewhere, vex can browse, extract and repack it (Assets view, or `vex "
                 "assets list PACK`).");
    }
}

static void d_love(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "L\xC3\x96VE");
    StrList containers = {0};
    StrList exes = tree_executables(t);
    for (size_t i = 0; i < exes.n; i++) {
        const char *lo = lower_str(a, exes.v[i]);
        size_t ll = strlen(lo);
        if (ll >= 5 && strcmp(lo + ll - 5, ".love") == 0)
            continue;
        if (bs_is_archive(tree_abspath(t, exes.v[i])) && tree_has_member(t, exes.v[i], "main.lua")) {
            *VEC_PUSH(a, containers) = exes.v[i];
            c_add(c, STRONG, str_printf(a, "%s has a ZIP appended that contains main.lua (a L\xC3\x96VE "
                  "game fused to its executable)", tree_report(t, exes.v[i])).p);
        }
    }
    StrList loves = TGLOB(t, "*.love");
    for (size_t i = 0; i < loves.n; i++) {
        if (tree_has_member(t, loves.v[i], "main.lua")) {
            *VEC_PUSH(a, containers) = loves.v[i];
            c_add(c, STRONG, str_printf(a, "%s is a ZIP containing main.lua",
                  tree_report(t, loves.v[i])).p);
        } else {
            c_add(c, GOOD, str_printf(a, "%s (.love file)", tree_report(t, loves.v[i])).p);
            *VEC_PUSH(a, containers) = loves.v[i];
        }
    }
    const char *runtime = TFILE(t, "love.dll", "love.exe", "liblove.so");
    if (!runtime) {
        StrList r = TGLOB(t, "liblove*.so*", "lib/liblove*.so*");
        if (r.n)
            runtime = r.v[0];
    }
    if (runtime)
        c_add(c, GOOD, str_printf(a, "%s (L\xC3\x96VE runtime)", runtime).p);
    if (TFILE(t, "main.lua")) {
        Str h = tree_head(t, "main.lua", 65536);
        Str conf = TFILE(t, "conf.lua") ? tree_head(t, "conf.lua", 65536) : str_c("");
        bool uses = bytes_contains(h, "love.") || bytes_contains(conf, "love.");
        if (uses)
            c_add(c, GOOD, "main.lua using the love.* API (unpacked L\xC3\x96VE game)");
    }
    if (c->score)
        c_add_markers(c);
    if (!c->score)
        return;

    Str conf = str_c("");
    for (size_t i = 0; i < containers.n && conf.n == 0; i++)
        conf = tree_member(t, containers.v[i], "conf.lua", 65536);
    if (conf.n == 0 && TFILE(t, "conf.lua"))
        conf = tree_head(t, "conf.lua", 65536);
    /* .version = ["']([0-9][0-9.]*)["'] */
    for (size_t i = 0; i + 8 <= conf.n; i++) {
        if (memcmp(conf.p + i, ".version", 8) != 0)
            continue;
        size_t j = i + 8;
        while (j < conf.n && (conf.p[j] == ' ' || conf.p[j] == '\t')) j++;
        if (j >= conf.n || conf.p[j] != '=') continue;
        j++;
        while (j < conf.n && (conf.p[j] == ' ' || conf.p[j] == '\t')) j++;
        if (j >= conf.n || (conf.p[j] != '"' && conf.p[j] != '\'')) continue;
        char q = conf.p[j++];
        size_t s = j;
        if (s >= conf.n || !(conf.p[s] >= '0' && conf.p[s] <= '9')) continue;
        while (j < conf.n && ((conf.p[j] >= '0' && conf.p[j] <= '9') || conf.p[j] == '.')) j++;
        if (j >= conf.n || conf.p[j] != q) continue;
        c_detail_set(c, "version", str_copy(a, conf.p + s, j - s).p);
        break;
    }
    c_assets_list(c, containers);
    if (containers.n) {
        const char *s = NULL;
        archive_advice(t, containers.v[0], "the game archive (a plain ZIP)", &s);
        c_advice(c, s);
    }
    c_advice(c, "A L\xC3\x96VE game is Lua source plus loose images and sounds. Scripts are normally "
             "plain text; if they were precompiled to LuaJIT bytecode, vex does not decompile "
             "them.");
}

static void d_source(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Source");
    StrList gameinfo = TGLOB(t, "*/gameinfo.txt");
    if (gameinfo.n)
        c_add(c, STRONG, str_printf(a, "%s (Source game definition)", gameinfo.v[0]).p);
    StrList source2 = TGLOB(t, "game/*/gameinfo.gi");
    if (!source2.n)
        source2 = TGLOB(t, "game/bin/*/engine2.dll");
    if (source2.n) {
        c_add(c, STRONG, str_printf(a, "%s (Source 2)", source2.v[0]).p);
        c_detail_set(c, "generation", "Source 2");
    }
    StrList vpks = TSUFFIX(t, ".vpk");
    /* _dir.vpk first, then the rest */
    StrList ordered = {0};
    for (size_t i = 0; i < vpks.n; i++) {
        const char *lo = lower_str(a, vpks.v[i]);
        size_t ll = strlen(lo);
        if (ll >= 8 && strcmp(lo + ll - 8, "_dir.vpk") == 0)
            *VEC_PUSH(a, ordered) = vpks.v[i];
    }
    for (size_t i = 0; i < vpks.n; i++)
        *VEC_PUSH(a, ordered) = vpks.v[i];
    long version = -1;
    for (size_t i = 0; i < ordered.n; i++) {
        Str head = tree_head(t, ordered.v[i], 12);
        if (head.n >= 8 && memcmp(head.p, "\x34\x12\xaa\x55", 4) == 0) {
            version = (uint8_t)head.p[4] | (uint8_t)head.p[5] << 8 | (uint8_t)head.p[6] << 16 |
                      (uint32_t)(uint8_t)head.p[7] << 24;
            c_add(c, STRONG, str_printf(a, "%s is a Valve pack file (VPK signature, version %ld)",
                  ordered.v[i], version).p);
            if (version == 1 || version == 2)
                c_detail_set(c, "vpk_version", str_printf(a, "%ld", version).p);
            break;
        }
    }
    if (vpks.n && version < 0)
        c_add(c, WEAK, str_printf(a, "%s (.vpk file)", vpks.v[0]).p);
    const char *launcher = TFILE(t, "hl2.exe", "hl2_linux", "hl2.sh", "hl2_osx");
    if (launcher)
        c_add(c, GOOD, str_printf(a, "%s (Source launcher)", launcher).p);
    const char *engine = TFILE(t, "bin/engine.dll", "bin/engine.so", "bin/engine_srv.so",
                               "bin/win64/engine.dll", "bin/x64/engine.dll");
    if (engine)
        c_add(c, GOOD, engine);
    if (!c->score)
        return;
    c_assets_list(c, vpks);
    c_advice(c, "vex cannot open Valve VPK pack files. Use VPKEdit or GCFScape to browse and "
             "extract them, and Valve's vpk tool (shipped in the game's bin folder) to build new "
             "ones.");
    c_advice(c, "Many Source games load loose files or extra VPKs from a custom/ or addons/ folder "
             "inside the game folder, which avoids rewriting the original packs.");
}

static void d_goldsrc(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "GoldSrc");
    StrList liblist = TGLOB(t, "*/liblist.gam");
    if (liblist.n)
        c_add(c, STRONG, str_printf(a, "%s (GoldSrc game definition)", liblist.v[0]).p);
    const char *launcher = TFILE(t, "hl.exe", "hl_linux", "hl.sh");
    if (launcher && (liblist.n || TDIR(t, "valve")))
        c_add(c, GOOD, str_printf(a, "%s (Half-Life launcher)", launcher).p);
    if (!liblist.n) {
        c->score = 0;
        return;
    }
    StrList paks = {0};
    StrList allpaks = TGLOB(t, "*/*.pak");
    for (size_t i = 0; i < allpaks.n; i++) {
        Str h = tree_head(t, allpaks.v[i], 4);
        if (h.n == 4 && memcmp(h.p, "PACK", 4) == 0)
            *VEC_PUSH(a, paks) = allpaks.v[i];
    }
    StrList wads = TGLOB(t, "*/*.wad");
    c_assets_list(c, paks);
    c_assets_list(c, wads);
    if (paks.n) {
        const char *s = NULL;
        archive_advice(t, paks.v[0], "the Quake-format PAK files", &s);
        c_advice(c, s);
    }
    StrList texwads = {0};
    for (size_t i = 0; i < wads.n; i++) {
        Str h = tree_head(t, wads.v[i], 4);
        if (h.n == 4 && (memcmp(h.p, "WAD3", 4) == 0 || memcmp(h.p, "WAD2", 4) == 0))
            *VEC_PUSH(a, texwads) = wads.v[i];
    }
    if (texwads.n)
        c_advice(c, str_printf(a, "%s and the other .wad files are Half-Life texture WADs (WAD3), a "
                 "different format from Doom's IWAD/PWAD: vex cannot open them. Use a WAD3 "
                 "editor such as Wally.", tree_report(t, texwads.v[0])).p);
    c_advice(c, "GoldSrc loads loose files from the game folder (and its _addon/_hd variants) "
             "before pak files, so replacement assets can usually be placed there directly.");
}

static const char *QUAKE_DIRS[] = {"id1", "hipnotic", "rogue", "baseq2", "baseq3", "base",
                                   "missionpack", "xatrix", "main", "data"};

static void d_id_tech(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "id Tech");
    if (TGLOB(t, "*/liblist.gam").n)
        return;
    StrList paks = {0};
    StrList allpaks = TSUFFIX(t, ".pak");
    for (size_t i = 0; i < allpaks.n && i < 40; i++) {
        Str h = tree_head(t, allpaks.v[i], 4);
        if (h.n == 4 && memcmp(h.p, "PACK", 4) == 0)
            *VEC_PUSH(a, paks) = allpaks.v[i];
    }
    if (paks.n) {
        const char *lo = lower_str(a, paks.v[0]);
        const char *slash = strchr(lo, '/');
        bool quake_dir = false;
        if (slash) {
            size_t flen = (size_t)(slash - lo);
            for (size_t k = 0; k < sizeof QUAKE_DIRS / sizeof QUAKE_DIRS[0]; k++)
                if (strlen(QUAKE_DIRS[k]) == flen && memcmp(lo, QUAKE_DIRS[k], flen) == 0)
                    quake_dir = true;
        }
        c_add(c, quake_dir ? STRONG : GOOD, str_printf(a, "%s is a Quake PAK ('PACK' signature)",
              paks.v[0]).p);
    }
    StrList iwads = {0}, pwads = {0};
    StrList allwads = TSUFFIX(t, ".wad");
    for (size_t i = 0; i < allwads.n && i < 40; i++) {
        Str h = tree_head(t, allwads.v[i], 4);
        if (h.n == 4 && memcmp(h.p, "IWAD", 4) == 0)
            *VEC_PUSH(a, iwads) = allwads.v[i];
        else if (h.n == 4 && memcmp(h.p, "PWAD", 4) == 0)
            *VEC_PUSH(a, pwads) = allwads.v[i];
    }
    if (iwads.n)
        c_add(c, STRONG, str_printf(a, "%s is a Doom IWAD (the game's main data file)",
              iwads.v[0]).p);
    else if (pwads.n)
        c_add(c, GOOD, str_printf(a, "%s is a Doom PWAD", pwads.v[0]).p);
    StrList zips = {0};
    StrList allzips = TSUFFIX(t, ".pk3", ".pk4", ".kpf");
    for (size_t i = 0; i < allzips.n && i < 40; i++) {
        Str h = tree_head(t, allzips.v[i], 4);
        if (h.n == 4 && memcmp(h.p, "PK\x03\x04", 4) == 0)
            *VEC_PUSH(a, zips) = allzips.v[i];
    }
    if (zips.n)
        c_add(c, GOOD, str_printf(a, "%s (id Tech 3/4 style ZIP pack)", zips.v[0]).p);
    if (!c->score)
        return;
    c_assets_list(c, paks);
    c_assets_list(c, iwads);
    c_assets_list(c, pwads);
    c_assets_list(c, zips);
    /* advice: one per distinct container kind present, in order PAK, WAD, zip */
    bool did_pak = false, did_wad = false, did_zip = false;
    if (paks.n && !did_pak) {
        did_pak = true;
        const char *s = NULL;
        archive_advice(t, paks.v[0], "Quake PAK files", &s);
        c_advice(c, s);
    }
    if ((iwads.n || pwads.n) && !did_wad) {
        did_wad = true;
        const char *w = iwads.n ? iwads.v[0] : pwads.v[0];
        const char *s = NULL;
        archive_advice(t, w, "Doom WAD files", &s);
        c_advice(c, s);
    }
    if (zips.n && !did_zip) {
        did_zip = true;
        const char *s = NULL;
        archive_advice(t, zips.v[0], "pk3/pk4/kpf packs (plain ZIP)", &s);
        c_advice(c, s);
    }
    c_advice(c, "These engines let later packs override earlier ones (pak1 over pak0, a PWAD loaded "
             "with -file over the IWAD): ship changes as an additional pack instead of rewriting "
             "the original.");
    if (iwads.n || pwads.n)
        c_advice(c, "WAD lumps are in Doom's own formats (patches, flats, maps, DMX sounds): "
                 "vex extracts and replaces the raw lumps; use SLADE to view, convert and "
                 "edit them.");
}

static void d_java(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "Java");
    const char *main_jar = NULL;
    StrList exes = tree_executables(t);
    for (size_t i = 0; i < exes.n; i++) {
        if (bs_is_archive(tree_abspath(t, exes.v[i])) &&
            tree_has_member(t, exes.v[i], "META-INF/MANIFEST.MF")) {
            if (!main_jar) main_jar = exes.v[i];
            const char *lo = lower_str(a, exes.v[i]);
            size_t ll = strlen(lo);
            const char *kind = (ll >= 4 && strcmp(lo + ll - 4, ".jar") == 0) ? "is a JAR"
                : "has a JAR appended (wrapped Java application)";
            c_add(c, STRONG, str_printf(a, "%s %s: ZIP with META-INF/MANIFEST.MF",
                  tree_report(t, exes.v[i]), kind).p);
        }
    }
    StrList top_all = TGLOB(t, "*.jar");
    StrList top = {0};
    for (size_t i = 0; i < top_all.n; i++)
        if (!main_jar || strcmp(top_all.v[i], main_jar) != 0)
            *VEC_PUSH(a, top) = top_all.v[i];
    StrList nested = TGLOB(t, "*/*.jar", "*/*/*.jar");
    if (top.n)
        c_add(c, GOOD, str_printf(a, "%s next to the executable", top.v[0]).p);
    else if (nested.n && !main_jar)
        c_add(c, WEAK, str_printf(a, "%s (.jar file in a subfolder)", nested.v[0]).p);
    const char *rt_dirs[] = {"jre", "runtime", "jdk", "java"};
    const char *rt_bins[] = {"java.exe", "javaw.exe", "java"};
    const char *runtime = NULL;
    for (size_t d = 0; d < 4 && !runtime; d++)
        for (size_t b = 0; b < 3 && !runtime; b++)
            runtime = TFILE(t, str_printf(a, "%s/bin/%s", rt_dirs[d], rt_bins[b]).p);
    if (runtime && c->score)
        c_add(c, GOOD, str_printf(a, "bundled Java runtime (%s)", runtime).p);
    c_add_markers(c);
    if (!c->score)
        return;

    StrList jars = {0};
    if (main_jar) *VEC_PUSH(a, jars) = main_jar;
    for (size_t i = 0; i < top.n; i++) *VEC_PUSH(a, jars) = top.v[i];
    for (size_t i = 0; i < nested.n; i++) *VEC_PUSH(a, jars) = nested.v[i];
    c_assets_list(c, jars);
    const char *preferred = main_jar;
    if (!preferred && t->given) {
        /* stem of the given file */
        const char *base = platform_basename(t->given);
        char *stem = arena_alloc(a, strlen(base) + 1);
        strcpy(stem, base);
        char *dot = strrchr(stem, '.');
        if (dot) *dot = '\0';
        const char *lstem = lower_str(a, stem);
        for (size_t i = 0; i < top.n; i++) {
            const char *lo = lower_str(a, top.v[i]);
            char *tdot = strrchr(lo, '.');
            if (tdot) *tdot = '\0';
            if (strcmp(lo, lstem) == 0) { preferred = top.v[i]; break; }
        }
    }
    if (!preferred && top.n)
        preferred = top.v[0];
    if (preferred) {
        Str mf = tree_member(t, preferred, "META-INF/MANIFEST.MF", 65536);
        /* (?mi)^Main-Class:[ \t]*([\w.$]+) */
        for (size_t i = 0; i + 11 <= mf.n; i++) {
            if (i != 0 && mf.p[i - 1] != '\n')
                continue;
            bool mc = true;
            const char *key = "main-class:";
            for (size_t k = 0; k < 11; k++)
                if (lower1(mf.p[i + k]) != key[k]) { mc = false; break; }
            if (!mc)
                continue;
            size_t j = i + 11;
            while (j < mf.n && (mf.p[j] == ' ' || mf.p[j] == '\t')) j++;
            size_t s = j;
            while (j < mf.n) {
                char ch = mf.p[j];
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '$')
                    j++;
                else break;
            }
            if (j > s)
                c_detail_set(c, "main_class", str_copy(a, mf.p + s, j - s).p);
            break;
        }
    }
    if (jars.n) {
        const char *s = NULL;
        archive_advice(t, preferred ? preferred : jars.v[0], "JAR files (they are ZIP archives)", &s);
        c_advice(c, s);
        c_advice(c, "Images, sounds and data inside a JAR are ordinary files. .class files are JVM "
                 "bytecode, which vex does not decompile: use a Java decompiler such as CFR, "
                 "Vineflower or JD-GUI, or Recaf to edit classes.");
        c_advice(c, "A signed JAR (META-INF/*.SF) fails verification once changed: remove the "
                 "signature files or re-sign it.");
    } else {
        c_advice(c, "The executable looks like a Java launcher but no JAR was found next to it; JAR "
                 "files are ZIP archives that vex can browse, extract and repack.");
    }
}

static void d_monogame(Case *c) {
    Tree *t = c->t;
    Arena *a = t->arena;
    case_init(c, t, "MonoGame/XNA");
    const char *monogame = TFILE(t, "MonoGame.Framework.dll");
    if (!monogame) {
        StrList g = TGLOB(t, "*/monogame.framework.dll");
        if (g.n) monogame = g.v[0];
    }
    const char *fna = TFILE(t, "FNA.dll");
    StrList xg = TGLOB(t, "microsoft.xna.framework*.dll");
    const char *xna = xg.n ? xg.v[0] : NULL;
    const char *libs[] = {monogame, fna, xna};
    const char *lnames[] = {"MonoGame", "FNA", "XNA"};
    for (int i = 0; i < 3; i++)
        if (libs[i]) {
            c_add(c, STRONG, str_printf(a, "%s (%s framework assembly)", libs[i], lnames[i]).p);
            c_detail_default(c, "framework", lnames[i]);
        }
    StrList content = TGLOB(t, "content/*.xnb", "content/*/*.xnb", "content/*/*/*.xnb");
    if (content.n) {
        Str h = tree_head(t, content.v[0], 3);
        if (h.n == 3 && memcmp(h.p, "XNB", 3) == 0)
            c_add(c, c->score ? GOOD : STRONG, str_printf(a, "%s (compiled XNA content, 'XNB' "
                  "signature)", content.v[0]).p);
        else
            c_add(c, WEAK, str_printf(a, "%s (.xnb file)", content.v[0]).p);
    }
    c_add_markers(c);
    if (!c->score)
        return;
    c_assets_list(c, content);
    c_advice(c, "vex cannot open .xnb files (XNA's compiled content, usually LZX or LZ4 "
             "compressed). Use an XNB tool such as xnbcli to unpack and repack them.");
    c_advice(c, "The game code is .NET: decompile and edit the game's .exe and .dll assemblies with "
             "ILSpy or dnSpy. vex only reads their PE headers.");
}

typedef void (*Detector)(Case *);
static const Detector DETECTORS[] = {
    d_unity, d_unreal, d_godot, d_gamemaker, d_renpy, d_rpg_maker, d_electron, d_love,
    d_source, d_goldsrc, d_id_tech, d_java, d_monogame,
};
#define NDETECTORS (sizeof DETECTORS / sizeof DETECTORS[0])

/* =============================================================================
 * JSON view
 * ========================================================================== */

static JVal *case_to_json(Arena *a, Case *c) {
    const char *confidence = c->score >= HIGH ? "high" : c->score >= MEDIUM ? "medium" : "low";
    JVal *d = j_dict(a);
    j_set(a, d, "engine", j_cstr(a, c->engine));
    j_set(a, d, "confidence", j_cstr(a, confidence));
    JVal *ev = j_list(a);
    for (size_t i = 0; i < c->evidence.n; i++)
        j_push(a, ev, j_cstr(a, c->evidence.v[i]));
    j_set(a, d, "evidence", ev);
    JVal *det = j_dict(a);
    for (size_t i = 0; i < c->details.n; i++)
        j_set(a, det, c->details.v[i].k, j_cstr(a, c->details.v[i].v));
    j_set(a, d, "details", det);
    JVal *af = j_list(a);
    StrList reps = tree_reports(c->t, c->assets);
    for (size_t i = 0; i < reps.n; i++)
        j_push(a, af, j_cstr(a, reps.v[i]));
    j_set(a, d, "asset_files", af);
    JVal *adv = j_list(a);
    for (size_t i = 0; i < c->advice.n; i++)
        j_push(a, adv, j_cstr(a, c->advice.v[i]));
    j_set(a, d, "advice", adv);
    return d;
}

/* find_packs: asset packs vex can open under root (at most 3 deep). */
typedef struct { const char *abspath; } Cand;
typedef struct { Cand *v; size_t n, cap; } CandVec;

static void fp_walk(Arena *a, const char *root, const char *rel, int depth, CandVec *cands,
                    size_t *seen, bool *stop) {
    if (*stop)
        return;
    const char *folder = rel[0] ? str_printf(a, "%s/%s", root, rel).p : root;
    FsEntry *entries;
    size_t n;
    if (!fs_list(a, folder, 100000, &entries, &n))
        return;
    /* sort by name */
    const char **names = arena_array(a, n ? n : 1, sizeof *names);
    size_t *idx = arena_array(a, n ? n : 1, sizeof *idx);
    for (size_t i = 0; i < n; i++) { names[i] = entries[i].name; idx[i] = i; }
    for (size_t i = 1; i < n; i++) {
        const char *nv = names[i]; size_t oi = idx[i]; size_t k = i;
        while (k > 0 && strcmp(names[k - 1], nv) > 0) { names[k] = names[k-1]; idx[k] = idx[k-1]; k--; }
        names[k] = nv; idx[k] = oi;
    }
    /* files of this folder first */
    for (size_t i = 0; i < n; i++) {
        FsEntry *e = &entries[idx[i]];
        bool is_dir = e->target == FS_DIR;
        if (is_dir)
            continue;
        (*seen)++;
        const char *childrel = rel[0] ? str_printf(a, "%s/%s", rel, e->name).p : e->name;
        Cand *cand = VEC_PUSH(a, *cands);
        cand->abspath = platform_abspath(a, str_printf(a, "%s/%s", root, childrel).p);
    }
    if (*seen > 4000)
        *stop = true;
    if (*stop)
        return;
    /* recurse into real subdirs if depth < 3 */
    if (depth < 3) {
        for (size_t i = 0; i < n && !*stop; i++) {
            FsEntry *e = &entries[idx[i]];
            if (e->kind != FS_DIR)
                continue;
            const char *childrel = rel[0] ? str_printf(a, "%s/%s", rel, e->name).p : e->name;
            fp_walk(a, root, childrel, depth + 1, cands, seen, stop);
        }
    }
}

static JVal *find_packs(Arena *a, const char *root, const char *also) {
    CandVec cands = {0};
    if (also && platform_is_file(also)) {
        Cand *c0 = VEC_PUSH(a, cands);
        c0->abspath = also;
    }
    size_t seen = 0;
    bool stop = false;
    fp_walk(a, root, "", 0, &cands, &seen, &stop);

    JVal *packs = j_list(a);
    size_t found = 0;
    for (size_t i = 0; i < cands.n && found < 200; i++) {
        /* dedup: skip if an earlier candidate had the same abspath */
        bool dup = false;
        for (size_t k = 0; k < i; k++)
            if (strcmp(cands.v[k].abspath, cands.v[i].abspath) == 0) { dup = true; break; }
        if (dup)
            continue;
        if (!bs_is_archive(cands.v[i].abspath))
            continue;
        uint64_t size = 0;
        if (!fs_size(cands.v[i].abspath, &size))
            continue;
        JVal *p = j_dict(a);
        j_set(a, p, "path", j_cstr(a, cands.v[i].abspath));
        j_set(a, p, "relative", j_cstr(a, rel_path(a, cands.v[i].abspath, root)));
        j_set(a, p, "size", j_int(a, (big)size));
        j_push(a, packs, p);
        found++;
    }
    return packs;
}

JVal *bs_engine_view(Arena *arena, const char *path, char *err, size_t errlen) {
    const char *full = platform_abspath(arena, path);
    if (fs_kind(full, true) == FS_MISSING) {    /* os.path.exists: follows symlinks */
        snprintf(err, errlen, "No such file or directory: %s", path);
        return NULL;
    }
    bool is_dir = fs_kind(full, true) == FS_DIR;
    const char *root = is_dir ? full : NULL;
    const char *base;
    const char *given = is_dir ? NULL : full;
    if (is_dir) {
        base = full;
    } else {
        /* dirname(full) */
        char *d = arena_alloc(arena, strlen(full) + 1);
        strcpy(d, full);
        char *slash = strrchr(d, '/');
        if (slash) *slash = '\0';
        base = d;
        root = base;
        /* <root>/<Project>/Binaries/<Platform>/exe: game dir is three up */
        char *parent = arena_alloc(arena, strlen(base) + 1);
        strcpy(parent, base);
        char *s1 = strrchr(parent, '/');
        if (s1) {
            *s1 = '\0';
            const char *grandparent_base = strrchr(parent, '/');
            grandparent_base = grandparent_base ? grandparent_base + 1 : parent;
            const char *lo = lower_str(arena, grandparent_base);
            if (strcmp(lo, "binaries") == 0) {
                /* dirname(dirname(dirname(base))) */
                char *cand = arena_alloc(arena, strlen(base) + 1);
                strcpy(cand, base);
                for (int k = 0; k < 3; k++) {
                    char *sl = strrchr(cand, '/');
                    if (sl) *sl = '\0';
                }
                if (fs_kind(cand, true) == FS_DIR)
                    root = cand;
            }
        }
    }

    /* views.engine() reports the directory the file is in (or the directory
     * itself), and finds packs there; the detectors' tree may reach higher
     * (the Unreal Binaries case), but that never changes the reported root. */
    JVal *d = j_dict(arena);
    j_set(arena, d, "root", j_cstr(arena, base));

    JVal *matches = j_list(arena);
    /* run detectors, collect (score, json) and sort by score desc (stable) */
    typedef struct { int score; JVal *json; } Scored;
    VEC(Scored) scored = {0};
    Tree *t = tree_new(arena, root, base, given);
    for (size_t i = 0; i < NDETECTORS; i++) {
        Case c;
        memset(&c, 0, sizeof c);
        c.t = t;        /* detectors read c->t before case_init resets it */
        DETECTORS[i](&c);
        if (c.score > 0) {
            Scored *s = VEC_PUSH(arena, scored);
            s->score = c.score;
            s->json = case_to_json(arena, &c);
        }
    }
    /* stable sort by -score */
    for (size_t i = 1; i < scored.n; i++) {
        Scored key = scored.v[i];
        size_t k = i;
        while (k > 0 && scored.v[k - 1].score < key.score) {
            scored.v[k] = scored.v[k - 1];
            k--;
        }
        scored.v[k] = key;
    }
    for (size_t i = 0; i < scored.n; i++)
        j_push(arena, matches, scored.v[i].json);
    j_set(arena, d, "matches", matches);

    j_set(arena, d, "packs", find_packs(arena, base, given));
    (void)err;
    return d;
}
