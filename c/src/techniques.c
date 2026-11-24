/* Static detection of protection and evasion techniques (port of
 * techniques.py). The file is never run; everything is read from the parsed
 * Binary. */
#include "techniques.h"

#include "strings.h"

#define HIGH_ENTROPY 7.2

/* category -> (title, plain-language explanation). */
static const struct {
    const char *category, *title, *explanation;
} CATEGORIES[] = {
    {"packing", "Packing or protection",
     "The program's code is compressed or protected, so most of it cannot "
     "be read until the program unpacks itself in memory at run time. "
     "Packers and protectors are used by anti-cheat, DRM and malware alike; "
     "to read the real code you would run it under a debugger and dump it."},
    {"anti-debug", "Anti-debugging",
     "The program checks whether it is being debugged and can hide, change "
     "its behaviour or refuse to run. Common in anti-cheat, DRM and malware."},
    {"anti-vm", "Virtual-machine or sandbox checks",
     "The program looks for signs that it is running in a virtual machine "
     "or an analysis sandbox, which it may use to behave differently when "
     "watched."},
    {"injection", "Process injection",
     "The program can write code or data into another running process and "
     "execute it. Game cheats use this to get inside a game; some anti-cheat "
     "and much malware use it too."},
    {"hooking", "API or input hooking",
     "The program can intercept calls, messages or input that belong to "
     "other software. Used by overlays, cheats, key loggers and anti-cheat."},
    {"driver", "Kernel driver",
     "The program talks to, or is, a kernel-mode driver, giving it deep "
     "access to the whole system. Modern anti-cheat and some cheats ship a "
     "driver for this reach."},
    {"overlay", "Appended data",
     "Extra data is stored after the end of the program itself. Installers "
     "and self-extracting or self-modifying programs keep payloads here; it "
     "is worth extracting and inspecting."},
};

/* --- import-name tables (all matched case-insensitively, lowercase here) ------ */

static const char *const ANTI_DEBUG[] = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "ntsetinformationthread", "debugactiveprocess", "ntqueryobject", "ntclose",
    "outputdebugstringa", "outputdebugstringw", "rtladjustprivilege",
    "dbgbreakpoint", "dbguiremotebreakin", "blockinput", "ptrace",
};
/* imports that only hint at anti-debugging (timing side-channels, logging) */
static const char *const ANTI_DEBUG_WEAK[] = {
    "gettickcount", "gettickcount64", "queryperformancecounter", "timegettime",
    "ntclose", "outputdebugstringa", "outputdebugstringw",
};
static const char *const INJECTION[] = {
    "virtualallocex", "virtualprotectex", "writeprocessmemory", "createremotethread",
    "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread",
    "ntmapviewofsection", "setthreadcontext", "ntsetcontextthread",
    "ntwritevirtualmemory", "zwwritevirtualmemory", "process_vm_writev",
    "createremotethreadex",
};
static const char *const HOOKING[] = {
    "setwindowshookexa", "setwindowshookexw", "setwineventhook",
    "unhookwindowshookex", "callnexthookex",
};
/* libraries that only a kernel-mode driver imports from */
static const char *const DRIVER_LIBS[] = {
    "ntoskrnl.exe", "hal.dll", "wdfldr.sys", "ndis.sys", "fltmgr.sys",
    "ksecdd.sys", "wdf01000.sys", "storport.sys",
};

/* packer / protector section-name signatures: {signature, signature stripped
 * of dots, product}. The signature matches when a section name starts with it,
 * or equals the stripped form. First match in this order wins. */
static const struct {
    const char *sig, *stripped, *product;
} PACKER_SECTIONS[] = {
    {"upx", "upx", "UPX"}, {".vmp", "vmp", "VMProtect"}, {"vmp0", "vmp0", "VMProtect"},
    {"vmp1", "vmp1", "VMProtect"}, {".themida", "themida", "Themida"},
    {".winlice", "winlice", "Themida/WinLicense"}, {"winlicen", "winlicen", "Themida/WinLicense"},
    {".enigma", "enigma", "Enigma Protector"}, {"enigma", "enigma", "Enigma Protector"},
    {".aspack", "aspack", "ASPack"}, {"aspack", "aspack", "ASPack"}, {".adata", "adata", "ASPack"},
    {".petite", "petite", "Petite"}, {"petite", "petite", "Petite"},
    {".mpress", "mpress", "MPRESS"}, {"mpress", "mpress", "MPRESS"},
    {".fsg", "fsg", "FSG"}, {"fsg!", "fsg!", "FSG"}, {".nsp", "nsp", "NsPack"},
    {"nsp0", "nsp0", "NsPack"}, {"molebox", "molebox", "MoleBox"}, {".boom", "boom", "The Boomerang"},
    {".perplex", "perplex", "Perplex"}, {".y0da", "y0da", "yoda's crypter"},
    {".pelock", "pelock", "PELock"}, {".pack", "pack", "generic packer"},
    {".rmnet", "rmnet", "packer"}, {".taz", "taz", "PESpin"},
};

/* virtual-machine / sandbox ARTIFACT marker -> vendor family. {marker as shown,
 * marker lowercased for matching, family}. Driver, service and device names,
 * not plain vendor words that show up in ordinary software. */
static const struct {
    const char *marker, *lower, *family;
} VM_MARKERS[] = {
    {"VBoxGuest", "vboxguest", "vbox"}, {"vboxservice", "vboxservice", "vbox"},
    {"vboxtray", "vboxtray", "vbox"}, {"VBoxSF", "vboxsf", "vbox"},
    {"VBoxMouse", "vboxmouse", "vbox"}, {"VBoxVideo", "vboxvideo", "vbox"},
    {"VBoxMiniRdr", "vboxminirdr", "vbox"}, {"vboxdisp", "vboxdisp", "vbox"},
    {"vmci.sys", "vmci.sys", "vmware"}, {"vmtoolsd", "vmtoolsd", "vmware"},
    {"vmwaretray", "vmwaretray", "vmware"}, {"vmwareuser", "vmwareuser", "vmware"},
    {"vmmouse.sys", "vmmouse.sys", "vmware"}, {"vmhgfs", "vmhgfs", "vmware"},
    {"vmware-vmx", "vmware-vmx", "vmware"},
    {"qemu-ga", "qemu-ga", "qemu"}, {"qemuwmi", "qemuwmi", "qemu"},
    {"xenservice", "xenservice", "xen"}, {"xenvbd", "xenvbd", "xen"},
    {"xennet", "xennet", "xen"},
    {"SbieDll.dll", "sbiedll.dll", "sandbox"}, {"sbiedll", "sbiedll", "sandbox"},
    {"cuckoomon", "cuckoomon", "sandbox"}, {"sandboxiedcomlaunch", "sandboxiedcomlaunch", "sandbox"},
    {"prl_cc", "prl_cc", "parallels"}, {"prltools", "prltools", "parallels"},
};

/* --- small helpers ------------------------------------------------------------ */

typedef VEC(Str) StrVec;

typedef struct {
    const char *category, *title, *confidence, *explanation;
    StrVec evidence;
} Tech;

typedef VEC(Tech) TechVec;

/* An import flagged-lookup entry: lowercase name -> first original spelling. */
typedef struct {
    Str lower, original;
} Imp;

typedef VEC(Imp) ImpVec;

static int cmp_str(const void *pa, const void *pb) {
    return str_cmp(*(const Str *)pa, *(const Str *)pb);
}

static int cmp_tech(const void *pa, const void *pb) {
    return strcmp(((const Tech *)pa)->category, ((const Tech *)pb)->category);
}

static bool in_set(Str lower, const char *const *set, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (str_eq_c(lower, set[i]))
            return true;
    return false;
}

/* ASCII-case-insensitive substring search; `needle` is already lowercase. */
static bool contains_ci(Str hay, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0)
        return true;
    if (m > hay.n)
        return false;
    for (size_t i = 0; i + m <= hay.n; i++) {
        size_t k = 0;
        for (; k < m; k++) {
            char c = hay.p[i + k];
            if (c >= 'A' && c <= 'Z')
                c = (char)(c + 32);
            if (c != needle[k])
                break;
        }
        if (k == m)
            return true;
    }
    return false;
}

static Str section_name(const Section *s) {
    return s->name.p ? s->name : str_c("");
}

/* entropy of the section's file bytes, clipped to the file exactly as the
 * `sections` view does (Section.section_entropy / section_data in Python). */
static double section_entropy(const Binary *b, const Section *s) {
    uint64_t start = s->offset < b->size ? s->offset : b->size;
    uint64_t length = s->size < b->size - start ? s->size : b->size - start;
    return entropy(b->data + start, length);
}

/* Flagged-lookup helper: lowercase import name -> first original spelling. */
static ImpVec build_imports(Arena *a, const Binary *b) {
    ImpVec imps = {0};
    StrSet seen = {0};
    for (size_t i = 0; i < b->imports.n; i++) {
        Str name = b->imports.v[i].name;
        if (name.p == NULL || name.n == 0 || name.p[0] == '#')
            continue;
        Str lower = str_lower_ascii(a, name);
        if (strset_add(a, &seen, lower)) {
            Imp *e = VEC_PUSH(a, imps);
            e->lower = lower;
            e->original = name;
        }
    }
    return imps;
}

/* sorted original spellings of imports whose lowercase name is in set1 or set2
 * (set2 may be NULL); the union, each spelling once (Python's _from_imports). */
static StrVec from_imports(Arena *a, const ImpVec *imps, const char *const *set1, size_t n1,
                           const char *const *set2, size_t n2) {
    StrVec out = {0};
    for (size_t i = 0; i < imps->n; i++) {
        Str lower = imps->v[i].lower;
        if (in_set(lower, set1, n1) || (set2 != NULL && in_set(lower, set2, n2)))
            *VEC_PUSH(a, out) = imps->v[i].original;
    }
    if (out.n > 1)
        qsort(out.v, out.n, sizeof *out.v, cmp_str);
    return out;
}

/* The import's original spelling for a lowercase name, or STR_NONE. */
static Str import_named(const ImpVec *imps, const char *lower) {
    for (size_t i = 0; i < imps->n; i++)
        if (str_eq_c(imps->v[i].lower, lower))
            return imps->v[i].original;
    return STR_NONE;
}

static StrVec evidence_imports(Arena *a, const StrVec *names) {
    StrVec ev = {0};
    for (size_t i = 0; i < names->n; i++)
        *VEC_PUSH(a, ev) = str_printf(a, "imports %.*s", (int)names->v[i].n, names->v[i].p);
    return ev;
}

static void add_tech(Arena *a, TechVec *techs, const char *category, const char *confidence,
                     StrVec evidence) {
    const char *title = category, *explanation = "";
    for (size_t i = 0; i < ARRAY_LEN(CATEGORIES); i++)
        if (strcmp(CATEGORIES[i].category, category) == 0) {
            title = CATEGORIES[i].title;
            explanation = CATEGORIES[i].explanation;
        }
    Tech *t = VEC_PUSH(a, *techs);
    t->category = category;
    t->title = title;
    t->confidence = confidence;
    t->explanation = explanation;
    t->evidence = evidence;
}

/* (marker, family) pairs whose marker appears in a readable string, as sorted
 * `string "<marker>"` evidence. Strings inside high-entropy sections are
 * skipped. *families is the count of distinct vendor families found. */
static StrVec vm_markers(Arena *a, const Binary *b, int *families) {
    /* section names of readable strings to ignore (packed / high entropy) */
    StrVec noisy = {0};
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        if (s->size >= 64 && section_entropy(b, s) > 7.0)
            *VEC_PUSH(a, noisy) = section_name(s);
    }
    bool matched[ARRAY_LEN(VM_MARKERS)] = {false};
    StringScan scan;
    FoundString found;
    Arena scratch = {0};
    strings_begin(&scan, b, a, 4, "all");
    for (;;) {
        arena_release(&scratch);
        if (!strings_next(&scan, &scratch, &found))
            break;
        if (found.section.p != NULL) {
            bool skip = false;
            for (size_t i = 0; i < noisy.n && !skip; i++)
                skip = str_eq(found.section, noisy.v[i]);
            if (skip)
                continue;
        }
        for (size_t i = 0; i < ARRAY_LEN(VM_MARKERS); i++)
            if (!matched[i] && contains_ci(found.text, VM_MARKERS[i].lower))
                matched[i] = true;
    }
    arena_release(&scratch);

    StrVec ev = {0};
    const char *fams[8];
    int nf = 0;
    for (size_t i = 0; i < ARRAY_LEN(VM_MARKERS); i++) {
        if (!matched[i])
            continue;
        *VEC_PUSH(a, ev) = str_printf(a, "string \"%s\"", VM_MARKERS[i].marker);
        bool seen_family = false;
        for (int j = 0; j < nf; j++)
            seen_family = seen_family || strcmp(fams[j], VM_MARKERS[i].family) == 0;
        if (!seen_family && nf < (int)ARRAY_LEN(fams))
            fams[nf++] = VM_MARKERS[i].family;
    }
    if (ev.n > 1)
        qsort(ev.v, ev.n, sizeof *ev.v, cmp_str);
    *families = nf;
    return ev;
}

JVal *tech_view(Arena *a, const Binary *b) {
    TechVec techs = {0};
    ImpVec imps = build_imports(a, b);

    /* -- packing / protectors -------------------------------------------- */
    StrVec packer = {0};
    for (size_t i = 0; i < b->sections.n; i++) {
        const Section *s = &b->sections.v[i];
        if (s->size < 64)
            continue;
        Str name = section_name(s);
        Str low = str_lower_ascii(a, name);
        const char *product = NULL;
        for (size_t k = 0; k < ARRAY_LEN(PACKER_SECTIONS); k++) {
            size_t sl = strlen(PACKER_SECTIONS[k].sig);
            bool starts = low.n >= sl && memcmp(low.p, PACKER_SECTIONS[k].sig, sl) == 0;
            if (starts || str_eq_c(low, PACKER_SECTIONS[k].stripped)) {
                product = PACKER_SECTIONS[k].product;
                break;
            }
        }
        double e = section_entropy(b, s);
        if (product != NULL) {
            *VEC_PUSH(a, packer) =
                str_printf(a, "section \"%.*s\" (%s)", (int)name.n, name.p, product);
            if (e > HIGH_ENTROPY)
                *VEC_PUSH(a, packer) =
                    str_printf(a, "section \"%.*s\" entropy %.2f of 8", (int)name.n, name.p, e);
        } else if (e > HIGH_ENTROPY && strchr(s->perms, 'x') != NULL) {
            *VEC_PUSH(a, packer) = str_printf(a, "executable section \"%.*s\" entropy %.2f of 8",
                                              (int)name.n, name.p, e);
        }
    }
    if (packer.n == 0 && b->entry.has) {
        const Section *entry_sec = binary_section_at(b, b->entry.v);
        if (entry_sec != NULL) {
            double e = section_entropy(b, entry_sec);
            if (e > HIGH_ENTROPY) {
                Str name = section_name(entry_sec);
                *VEC_PUSH(a, packer) =
                    str_printf(a, "entry point is in high-entropy section \"%.*s\" (%.2f of 8)",
                               (int)name.n, name.p, e);
            }
        }
    }
    if (packer.n > 0)
        add_tech(a, &techs, "packing", "high", packer);

    /* -- anti-debugging -------------------------------------------------- */
    StrVec debug = from_imports(a, &imps, ANTI_DEBUG, ARRAY_LEN(ANTI_DEBUG),
                                ANTI_DEBUG_WEAK, ARRAY_LEN(ANTI_DEBUG_WEAK));
    if (debug.n > 0) {
        bool strong = false;
        for (size_t i = 0; i < debug.n && !strong; i++) {
            Str lower = str_lower_ascii(a, debug.v[i]);
            strong = in_set(lower, ANTI_DEBUG, ARRAY_LEN(ANTI_DEBUG)) &&
                     !in_set(lower, ANTI_DEBUG_WEAK, ARRAY_LEN(ANTI_DEBUG_WEAK));
        }
        add_tech(a, &techs, "anti-debug", strong ? "high" : "medium",
                 evidence_imports(a, &debug));
    }

    /* -- anti-vm / sandbox ----------------------------------------------- */
    int families = 0;
    StrVec vm = vm_markers(a, b, &families);
    if (vm.n > 0)
        add_tech(a, &techs, "anti-vm", families >= 3 ? "high" : "medium", vm);

    /* -- process injection ----------------------------------------------- */
    StrVec inject = from_imports(a, &imps, INJECTION, ARRAY_LEN(INJECTION), NULL, 0);
    if (inject.n > 0)
        add_tech(a, &techs, "injection", inject.n >= 2 ? "high" : "medium",
                 evidence_imports(a, &inject));

    /* -- hooking --------------------------------------------------------- */
    StrVec hook = from_imports(a, &imps, HOOKING, ARRAY_LEN(HOOKING), NULL, 0);
    if (hook.n > 0)
        add_tech(a, &techs, "hooking", "high", evidence_imports(a, &hook));

    /* -- kernel driver --------------------------------------------------- */
    StrVec driver = {0};
    const Meta *subsystem = meta_get(&b->metadata, "subsystem");
    bool native = subsystem != NULL && subsystem->kind == META_STR &&
                  str_eq_c(subsystem->text, "native");
    if ((b->kind != NULL && strcmp(b->kind, "driver") == 0) || native)
        *VEC_PUSH(a, driver) = str_c("native subsystem (kernel-mode driver)");
    for (size_t i = 0; i < b->libraries.n; i++) {
        Str lib = b->libraries.v[i];
        Str lower = str_lower_ascii(a, lib);
        if (in_set(lower, DRIVER_LIBS, ARRAY_LEN(DRIVER_LIBS)))
            *VEC_PUSH(a, driver) = str_printf(a, "imports from %.*s", (int)lib.n, lib.p);
    }
    if (driver.n > 0) {
        add_tech(a, &techs, "driver", "high", driver);
    } else {
        Str dic = import_named(&imps, "deviceiocontrol");
        if (dic.p != NULL) {
            StrVec ev = {0};
            *VEC_PUSH(a, ev) = str_printf(a, "imports %.*s", (int)dic.n, dic.p);
            add_tech(a, &techs, "driver", "medium", ev);
        }
    }

    /* -- overlay --------------------------------------------------------- */
    const Meta *overlay = meta_get(&b->metadata, "overlay");
    if (overlay != NULL && overlay->kind == META_OVERLAY && overlay->number2 > 256) {
        StrVec ev = {0};
        *VEC_PUSH(a, ev) = str_printf(a, "appended data: %" PRIu64 " bytes at offset %#" PRIx64,
                                      overlay->number2, overlay->number);
        add_tech(a, &techs, "overlay", "medium", ev);
    }

    if (techs.n > 1)
        qsort(techs.v, techs.n, sizeof *techs.v, cmp_tech);

    JVal *list = j_list(a);
    for (size_t i = 0; i < techs.n; i++) {
        const Tech *t = &techs.v[i];
        JVal *d = j_dict(a);
        j_set(a, d, "category", j_cstr(a, t->category));
        j_set(a, d, "title", j_cstr(a, t->title));
        j_set(a, d, "confidence", j_cstr(a, t->confidence));
        JVal *ev = j_list(a);
        for (size_t k = 0; k < t->evidence.n; k++)
            j_push(a, ev, j_str(a, t->evidence.v[k]));
        j_set(a, d, "evidence", ev);
        j_set(a, d, "explanation", j_cstr(a, t->explanation));
        j_push(a, list, d);
    }
    return list;
}

/* --- text rendering (port of _render_techniques in cli.py) -------------------- */

#define T_BOLD "1"
#define T_DIM "2"
#define T_RED "31"
#define T_GREEN "32"
#define T_YELLOW "33"
#define T_CYAN "36"

static Str tstyled(Arena *a, const Style *st, Str text, const char *codes) {
    if (!st->colour || codes == NULL)
        return text;
    Buf b;
    buf_init(&b, a);
    buf_printf(&b, "\x1b[%sm", codes);
    buf_adds(&b, text);
    buf_addc(&b, "\x1b[0m");
    return buf_str(&b);
}

static void add_line(Arena *a, Lines *out, Str line) {
    *VEC_PUSH(a, *out) = line;
}

void render_techniques(Arena *a, const Style *st, const JVal *rows, Lines *out) {
    if (j_len(rows) == 0) {
        add_line(a, out, tstyled(a, st, str_c("No notable protection or evasion techniques found."),
                                 T_GREEN));
        return;
    }
    add_line(a, out, tstyled(a, st,
                             str_c("binspect identifies these techniques; it does not defeat them."),
                             T_DIM));
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *r = j_at(rows, i);
        Str confidence = j_text(j_get(r, "confidence"));
        const char *codes = T_BOLD ";" T_CYAN;
        if (str_eq_c(confidence, "high"))
            codes = T_BOLD ";" T_RED;
        else if (str_eq_c(confidence, "medium"))
            codes = T_BOLD ";" T_YELLOW;
        add_line(a, out, str_c(""));
        add_line(a, out, tstyled(a, st, str_printf(a, "%.*s  [%.*s]",
                                                   (int)j_text(j_get(r, "title")).n,
                                                   j_text(j_get(r, "title")).p,
                                                   (int)confidence.n, confidence.p),
                                 codes));
        const JVal *evidence = j_get(r, "evidence");
        for (size_t k = 0; k < j_len(evidence); k++) {
            Str e = j_text(j_at(evidence, k));
            add_line(a, out, str_printf(a, "  - %.*s", (int)e.n, e.p));
        }
        Str expl = j_text(j_get(r, "explanation"));
        add_line(a, out, tstyled(a, st, str_printf(a, "  %.*s", (int)expl.n, expl.p), T_DIM));
    }
}
