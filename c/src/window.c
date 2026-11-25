/* The app window, and the small pieces the front ends share. See window.h.
 *
 * The app window is a Chromium-family browser run as
 *
 *     BROWSER --app=URL --user-data-dir=PROFILE ...
 *
 * With a profile of its own the process we start is the browser itself, not a
 * messenger to one that is already running, so it lives exactly as long as the
 * window does and vex can stop when it ends. The profile is created for the
 * session and deleted afterwards. vex/window.py is the same thing in Python.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#else
#define _XOPEN_SOURCE 700       /* mkdtemp, lstat, clock_gettime, kill */
#define _DEFAULT_SOURCE
#endif

#include "window.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A window that "closes" sooner than this was never ours to follow: either the
 * browser could not start, or a browser that is already running took it over.
 * Matches QUICK_EXIT_SECS in vex/window.py. */
#define QUICK_EXIT_MS 3000
#define PROFILE_MARK "vex-window-"

#ifdef _WIN32
/* ============================== Windows ====================================== */

#include <windows.h>

#define PATH_CAP 1024
#define BROWSER_FLAGS L" --no-first-run --no-default-browser-check" \
                      L" --disable-background-mode --window-size=1360,900"

static HANDLE g_process;            /* NULL when no window is being followed */
static DWORD g_pid;
static ULONGLONG g_started;         /* GetTickCount64() at launch */
static ULONGLONG g_last_look;       /* when its windows were last counted */
static bool g_had_window;
static int g_looks_without_window;
static wchar_t g_profile[MAX_PATH];

/* The console program (vex.exe) always counts as having one, even when it was
 * started with its console hidden: a message box there could wait for a click
 * that nobody can see coming. Only the windowed program (vex-app.exe) has
 * none, unless it was given one. */
bool window_has_console(void) {
    const BYTE *image = (const BYTE *)GetModuleHandleW(NULL);
    if (image != NULL) {
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)image;
        const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(image + dos->e_lfanew);
        if (nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
            return true;
    }
    return GetConsoleWindow() != NULL;
}

void window_trace(const char *format, ...) {
    wchar_t path[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"VEX_WINDOW_LOG", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return;
    FILE *log = _wfopen(path, L"a");
    if (log == NULL)
        return;
    static ULONGLONG first;
    ULONGLONG now = GetTickCount64();
    if (first == 0)
        first = now;
    fprintf(log, "[%6lu ms] ", (unsigned long)(now - first));
    va_list args;
    va_start(args, format);
    vfprintf(log, format, args);
    va_end(args);
    fputc('\n', log);
    fclose(log);
}

/* A wide string for the log, as UTF-8 (in a static buffer: one at a time). */
static const char *narrow(const wchar_t *text) {
    static char out[PATH_CAP * 3];
    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, out, (int)sizeof out, NULL, NULL) <= 0)
        strcpy(out, "?");
    return out;
}

static wchar_t *to_wide(const char *text) {
    int n = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    wchar_t *wide = malloc((size_t)n * sizeof *wide);
    if (wide != NULL && MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, n) <= 0) {
        free(wide);
        wide = NULL;
    }
    return wide;
}

void window_message(const char *text) {
    if (window_has_console())
        return;
    wchar_t *wide = to_wide(text);
    if (wide != NULL)
        MessageBoxW(NULL, wide, L"vex", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    free(wide);
}

typedef struct {
    wchar_t *text;
    void (*on_dismiss)(void);
} StopBox;

static DWORD WINAPI stop_box_thread(LPVOID arg) {
    StopBox *box = arg;
    MessageBoxW(NULL, box->text, L"vex", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    void (*on_dismiss)(void) = box->on_dismiss;
    free(box->text);
    free(box);
    if (on_dismiss != NULL)
        on_dismiss();
    return 0;
}

void window_stop_box(const char *text, void (*on_dismiss)(void)) {
    if (window_has_console())
        return;
    StopBox *box = malloc(sizeof *box);
    if (box == NULL)
        return;
    box->text = to_wide(text);
    box->on_dismiss = on_dismiss;
    HANDLE thread = box->text != NULL ? CreateThread(NULL, 0, stop_box_thread, box, 0, NULL) : NULL;
    if (thread == NULL) {
        free(box->text);
        free(box);
        return;
    }
    CloseHandle(thread);
}

/* --- finding a browser ------------------------------------------------------- */

static bool is_file(const wchar_t *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

/* `out` = a + b, false when it does not fit in PATH_CAP characters. */
static bool join(wchar_t *out, const wchar_t *a, const wchar_t *b) {
    size_t na = wcslen(a), nb = wcslen(b);
    if (na + nb + 1 > PATH_CAP)
        return false;
    memmove(out, a, na * sizeof *a);
    memcpy(out + na, b, (nb + 1) * sizeof *b);
    return true;
}

/* An environment variable. False when it is unset, empty or too long; `set`
 * (when not NULL) says whether the variable exists at all. */
static bool env_var(const wchar_t *name, wchar_t *out, bool *set) {
    SetLastError(ERROR_SUCCESS);
    DWORD n = GetEnvironmentVariableW(name, out, PATH_CAP);
    if (set != NULL)
        *set = !(n == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND);
    if (n == 0 || n >= PATH_CAP) {
        out[0] = L'\0';
        return false;
    }
    return true;
}

/* The browser to open the window with: %VEX_BROWSER% when set (and nothing else
 * then), else Edge, else Chrome, by their registered and usual locations. */
static bool find_browser(wchar_t *out) {
    bool chosen = false;
    if (env_var(L"VEX_BROWSER", out, &chosen)) {
        if (is_file(out))
            return true;
        window_trace("app window: no browser: %%VEX_BROWSER%% names %s, which is not a file",
                     narrow(out));
        return false;
    }
    if (chosen) {
        window_trace("app window: no browser: %%VEX_BROWSER%% is set but empty or too long");
        return false;
    }

    static const wchar_t *const EXES[] = {L"msedge.exe", L"chrome.exe"};
    const HKEY roots[] = {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    for (size_t e = 0; e < sizeof EXES / sizeof EXES[0]; e++) {
        wchar_t key[PATH_CAP];
        if (!join(key, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\", EXES[e]))
            continue;
        for (size_t r = 0; r < sizeof roots / sizeof roots[0]; r++) {
            wchar_t value[PATH_CAP + 1];
            DWORD bytes = (DWORD)(PATH_CAP * sizeof(wchar_t));
            if (RegGetValueW(roots[r], key, NULL, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, NULL,
                             value, &bytes) != ERROR_SUCCESS)
                continue;
            value[PATH_CAP] = L'\0';
            wchar_t *path = value;
            size_t n = wcslen(path);
            if (n >= 2 && path[0] == L'"' && path[n - 1] == L'"') {
                path[n - 1] = L'\0';
                path++;
            }
            if (is_file(path) && join(out, path, L""))
                return true;
        }
    }

    static const wchar_t *const PLACES[] = {L"\\Microsoft\\Edge\\Application\\msedge.exe",
                                            L"\\Google\\Chrome\\Application\\chrome.exe"};
    static const wchar_t *const BASES[] = {L"ProgramFiles(x86)", L"ProgramFiles", L"LOCALAPPDATA"};
    for (size_t p = 0; p < sizeof PLACES / sizeof PLACES[0]; p++)
        for (size_t b = 0; b < sizeof BASES / sizeof BASES[0]; b++) {
            wchar_t base[PATH_CAP];
            if (env_var(BASES[b], base, NULL) && join(out, base, PLACES[p]) && is_file(out))
                return true;
        }
    out[0] = L'\0';
    window_trace("app window: no browser: neither Edge nor Chrome was found");
    return false;
}

/* --- the throw-away profile -------------------------------------------------- */

static bool make_profile(void) {
    wchar_t base[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, base);         /* ends with a backslash */
    if (n == 0 || n >= MAX_PATH)
        return false;
    for (unsigned attempt = 0; attempt < 50; attempt++) {
        unsigned long tag = (unsigned long)GetCurrentProcessId() * 2654435761UL;
        tag ^= (unsigned long)GetTickCount64() + attempt * 7919UL;
        wchar_t name[] = L"" PROFILE_MARK "00000000";
        static const wchar_t HEX[] = L"0123456789abcdef";
        size_t end = wcslen(name);
        for (int i = 0; i < 8; i++)
            name[end - 1 - (size_t)i] = HEX[(tag >> (4 * i)) & 15];
        if (wcslen(base) + wcslen(name) + 1 > MAX_PATH)
            return false;
        wcscpy(g_profile, base);
        wcscat(g_profile, name);
        if (CreateDirectoryW(g_profile, NULL))
            return true;
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            break;
    }
    g_profile[0] = L'\0';
    return false;
}

/* Delete a folder and everything in it. Links are removed, never followed. */
static void remove_tree(const wchar_t *dir, int depth) {
    size_t n = wcslen(dir);
    if (depth > 64 || n == 0 || n > 30000)
        return;
    wchar_t *pattern = malloc((n + 3) * sizeof *pattern);
    if (pattern == NULL)
        return;
    memcpy(pattern, dir, n * sizeof *dir);
    memcpy(pattern + n, L"\\*", 3 * sizeof *pattern);
    WIN32_FIND_DATAW found;
    HANDLE find = FindFirstFileW(pattern, &found);
    free(pattern);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            const wchar_t *name = found.cFileName;
            if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0)
                continue;
            size_t m = wcslen(name);
            wchar_t *child = malloc((n + m + 2) * sizeof *child);
            if (child == NULL)
                continue;
            memcpy(child, dir, n * sizeof *dir);
            child[n] = L'\\';
            memcpy(child + n + 1, name, (m + 1) * sizeof *name);
            DWORD attrs = found.dwFileAttributes;
            if (attrs & FILE_ATTRIBUTE_READONLY)
                SetFileAttributesW(child, attrs & ~(DWORD)FILE_ATTRIBUTE_READONLY);
            if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
                DeleteFileW(child);
            else if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
                RemoveDirectoryW(child);            /* a link: remove the link only */
            else
                remove_tree(child, depth + 1);
            free(child);
        } while (FindNextFileW(find, &found));
        FindClose(find);
    }
    RemoveDirectoryW(dir);
}

static void remove_profile(void) {
    if (g_profile[0] == L'\0' || wcsstr(g_profile, L"" PROFILE_MARK) == NULL)
        return;
    /* The browser's helper processes can hold files for a moment after it ends. */
    bool gone = false;
    for (int attempt = 0; attempt < 15 && !gone; attempt++) {
        remove_tree(g_profile, 0);
        gone = GetFileAttributesW(g_profile) == INVALID_FILE_ATTRIBUTES;
        if (!gone)
            Sleep(200);
    }
    if (gone)
        window_trace("app window: profile deleted");
    else
        window_trace("app window: could not delete the profile %s", narrow(g_profile));
    g_profile[0] = L'\0';
}

/* --- opening, following and closing the window ------------------------------- */

bool window_open(const char *url) {
    if (g_process != NULL || url == NULL || strchr(url, '"') != NULL)
        return false;
    wchar_t browser[PATH_CAP];
    if (!find_browser(browser))
        return false;
    if (!make_profile()) {
        window_trace("app window: could not create a profile folder (error %lu)",
                     (unsigned long)GetLastError());
        return false;
    }
    wchar_t *wide_url = to_wide(url);
    if (wide_url == NULL) {
        remove_profile();
        return false;
    }
    /* "BROWSER" "--app=URL" "--user-data-dir=PROFILE" flags */
    size_t cap = wcslen(browser) + wcslen(wide_url) + wcslen(g_profile) + wcslen(BROWSER_FLAGS) + 64;
    wchar_t *command = malloc(cap * sizeof *command);
    if (command == NULL) {
        free(wide_url);
        remove_profile();
        return false;
    }
    wcscpy(command, L"\"");
    wcscat(command, browser);
    wcscat(command, L"\" \"--app=");
    wcscat(command, wide_url);
    wcscat(command, L"\" \"--user-data-dir=");
    wcscat(command, g_profile);
    wcscat(command, L"\"" BROWSER_FLAGS);
    free(wide_url);

    STARTUPINFOW startup;
    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    PROCESS_INFORMATION started;
    BOOL ok = CreateProcessW(browser, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &started);
    free(command);
    if (!ok) {
        window_trace("app window: could not start %s (error %lu)", narrow(browser),
                     (unsigned long)GetLastError());
        remove_profile();
        return false;
    }
    CloseHandle(started.hThread);
    g_process = started.hProcess;
    g_pid = started.dwProcessId;
    window_trace("app window: started %s (process %lu)", narrow(browser), (unsigned long)g_pid);
    window_trace("app window: profile %s", narrow(g_profile));
    g_started = g_last_look = GetTickCount64();
    g_had_window = false;
    g_looks_without_window = 0;
    return true;
}

typedef struct {
    DWORD pid;
    int visible;
    bool close;         /* ask each of them to close */
} WindowWalk;

static BOOL CALLBACK walk_window(HWND hwnd, LPARAM arg) {
    WindowWalk *walk = (WindowWalk *)arg;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == walk->pid && IsWindowVisible(hwnd)) {
        walk->visible++;
        if (walk->close)
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

static void forget_process(void) {
    CloseHandle(g_process);
    g_process = NULL;
    remove_profile();
}

WindowState window_poll(void) {
    if (g_process == NULL)
        return WINDOW_NONE;
    if (WaitForSingleObject(g_process, 0) != WAIT_TIMEOUT) {
        DWORD code = 1;
        GetExitCodeProcess(g_process, &code);
        ULONGLONG lived = GetTickCount64() - g_started;
        WindowState state = lived >= QUICK_EXIT_MS ? WINDOW_CLOSED
                          : code == 0              ? WINDOW_LOST
                                                   : WINDOW_FAILED;
        window_trace("app window: %s: the browser ended after %lu ms with exit status %lu%s",
                     state == WINDOW_CLOSED ? "closed" : state == WINDOW_LOST ? "lost" : "failed",
                     (unsigned long)lived, (unsigned long)code,
                     state == WINDOW_LOST ? " (a browser that was already running may have"
                                            " taken the window over)" : "");
        forget_process();
        return state;
    }
    /* A browser can stay in the background after its last window closes. Once
     * its window has been seen and is then gone for two looks, it is closed. */
    ULONGLONG now = GetTickCount64();
    if (now - g_last_look >= 2000) {
        g_last_look = now;
        WindowWalk walk = {g_pid, 0, false};
        EnumWindows(walk_window, (LPARAM)&walk);
        if (walk.visible > 0) {
            if (!g_had_window)
                window_trace("app window: its window is on screen after %lu ms",
                             (unsigned long)(now - g_started));
            g_had_window = true;
            g_looks_without_window = 0;
        } else if (g_had_window && ++g_looks_without_window >= 2) {
            window_trace("app window: closed: its window is gone but the browser is still "
                         "running, so it is ended");
            TerminateProcess(g_process, 0);
            WaitForSingleObject(g_process, 3000);
            forget_process();
            return WINDOW_CLOSED;
        }
    }
    return WINDOW_OPEN;
}

void window_close(void) {
    if (g_process != NULL) {
        if (WaitForSingleObject(g_process, 0) == WAIT_TIMEOUT) {
            window_trace("app window: closing it");
            WindowWalk walk = {g_pid, 0, true};
            EnumWindows(walk_window, (LPARAM)&walk);
            if (WaitForSingleObject(g_process, 3000) == WAIT_TIMEOUT) {
                TerminateProcess(g_process, 0);
                WaitForSingleObject(g_process, 3000);
            }
        }
        CloseHandle(g_process);
        g_process = NULL;
    }
    remove_profile();
}

#else
/* =============================== POSIX ======================================= */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PATH_CAP 4096

static pid_t g_pid = -1;            /* -1 when no window is being followed */
static struct timespec g_started;
static char g_profile[PATH_CAP];

bool window_has_console(void) {
    return true;
}

static long ms_since(const struct timespec *then) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(now.tv_sec - then->tv_sec) * 1000 + (now.tv_nsec - then->tv_nsec) / 1000000;
}

void window_trace(const char *format, ...) {
    const char *path = getenv("VEX_WINDOW_LOG");
    if (path == NULL || path[0] == '\0')
        return;
    FILE *log = fopen(path, "a");
    if (log == NULL)
        return;
    static struct timespec first;
    static bool started;
    if (!started) {
        clock_gettime(CLOCK_MONOTONIC, &first);
        started = true;
    }
    fprintf(log, "[%6ld ms] ", ms_since(&first));
    va_list args;
    va_start(args, format);
    vfprintf(log, format, args);
    va_end(args);
    fputc('\n', log);
    fclose(log);
}

void window_message(const char *text) {
    (void)text;
}

void window_stop_box(const char *text, void (*on_dismiss)(void)) {
    (void)text;
    (void)on_dismiss;
}

NativeResult native_window_run(const char *url, void (*on_shown)(void)) {
    (void)url;
    (void)on_shown;
    return NATIVE_UNAVAILABLE;
}

void native_window_request_close(void) {
}

/* --- finding a browser ------------------------------------------------------- */

static bool is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* The browser to open the window with: $VEX_BROWSER when set (and nothing else
 * then), else the first known Chromium-family browser on the PATH. */
static bool find_browser(char *out) {
    const char *chosen = getenv("VEX_BROWSER");
    if (chosen != NULL) {
        if (strlen(chosen) >= PATH_CAP || !is_file(chosen)) {
            window_trace("app window: no browser: $VEX_BROWSER names %s, which is not a file",
                         chosen);
            return false;
        }
        strcpy(out, chosen);
        return true;
    }
#ifdef __APPLE__
    static const char *const APPS[] = {
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium"};
    for (size_t i = 0; i < sizeof APPS / sizeof APPS[0]; i++)
        if (is_file(APPS[i])) {
            strcpy(out, APPS[i]);
            return true;
        }
#endif
    static const char *const NAMES[] = {"google-chrome", "google-chrome-stable", "chromium",
                                        "chromium-browser", "microsoft-edge",
                                        "microsoft-edge-stable", "brave-browser"};
    const char *path = getenv("PATH");
    if (path == NULL || path[0] == '\0') {
        window_trace("app window: no browser: $PATH is empty");
        return false;
    }
    for (size_t i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++)
        for (const char *dir = path; dir != NULL;) {
            const char *end = strchr(dir, ':');
            size_t n = end != NULL ? (size_t)(end - dir) : strlen(dir);
            if (n + strlen(NAMES[i]) + 2 <= PATH_CAP) {
                memcpy(out, dir, n);
                snprintf(out + n, PATH_CAP - n, "%s%s", n > 0 ? "/" : "", NAMES[i]);
                if (is_file(out) && access(out, X_OK) == 0)
                    return true;
            }
            dir = end != NULL ? end + 1 : NULL;
        }
    window_trace("app window: no browser: no Chrome, Chromium, Edge or Brave on the PATH");
    return false;
}

/* --- the throw-away profile -------------------------------------------------- */

static bool make_profile(void) {
    const char *base = getenv("TMPDIR");
    if (base == NULL || base[0] == '\0')
        base = "/tmp";
    size_t n = strlen(base);
    int wrote = snprintf(g_profile, sizeof g_profile, "%s%s" PROFILE_MARK "XXXXXX", base,
                         base[n - 1] == '/' ? "" : "/");
    if (wrote < 0 || (size_t)wrote >= sizeof g_profile || mkdtemp(g_profile) == NULL) {
        g_profile[0] = '\0';
        return false;
    }
    return true;
}

/* Delete a folder and everything in it. Links are removed, never followed. */
static void remove_tree(const char *dir, int depth) {
    if (depth > 64)
        return;
    DIR *d = opendir(dir);
    if (d != NULL) {
        struct dirent *entry;
        while ((entry = readdir(d)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            size_t n = strlen(dir) + strlen(entry->d_name) + 2;
            char *child = malloc(n);
            if (child == NULL)
                continue;
            snprintf(child, n, "%s/%s", dir, entry->d_name);
            struct stat st;
            if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
                remove_tree(child, depth + 1);
            else
                unlink(child);
            free(child);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void nap(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void remove_profile(void) {
    if (g_profile[0] == '\0' || strstr(g_profile, PROFILE_MARK) == NULL)
        return;
    /* The browser's helper processes can write for a moment after it ends. */
    bool gone = false;
    for (int attempt = 0; attempt < 10 && !gone; attempt++) {
        remove_tree(g_profile, 0);
        struct stat st;
        gone = lstat(g_profile, &st) != 0;
        if (!gone)
            nap(100);
    }
    if (gone)
        window_trace("app window: profile deleted");
    else
        window_trace("app window: could not delete the profile %s", g_profile);
    g_profile[0] = '\0';
}

/* --- opening, following and closing the window ------------------------------- */

bool window_open(const char *url) {
    if (g_pid > 0 || url == NULL)
        return false;
    char browser[PATH_CAP];
    if (!find_browser(browser))
        return false;
    if (!make_profile()) {
        window_trace("app window: could not create a profile folder: %s", strerror(errno));
        return false;
    }
    size_t app_cap = strlen(url) + 16, dir_cap = strlen(g_profile) + 32;
    char *app = malloc(app_cap), *dir = malloc(dir_cap);
    if (app == NULL || dir == NULL) {
        free(app);
        free(dir);
        remove_profile();
        return false;
    }
    snprintf(app, app_cap, "--app=%s", url);
    snprintf(dir, dir_cap, "--user-data-dir=%s", g_profile);
    char *const argv[] = {browser, app, dir, (char *)"--no-first-run",
                          (char *)"--no-default-browser-check",
                          (char *)"--disable-background-mode",
                          (char *)"--window-size=1360,900", NULL};
    clock_gettime(CLOCK_MONOTONIC, &g_started);
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGPIPE, SIG_DFL);       /* vex ignores it; the browser must not inherit that */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
        long limit = sysconf(_SC_OPEN_MAX);
        if (limit < 0 || limit > 65536)
            limit = 65536;
        for (int fd = 3; fd < limit; fd++)     /* the browser must not hold our sockets */
            close(fd);
        execv(browser, argv);
        _exit(127);
    }
    free(app);
    free(dir);
    if (pid < 0) {
        window_trace("app window: could not start %s: %s", browser, strerror(errno));
        remove_profile();
        return false;
    }
    g_pid = pid;
    window_trace("app window: started %s (process %ld)", browser, (long)pid);
    window_trace("app window: profile %s", g_profile);
    return true;
}

WindowState window_poll(void) {
    if (g_pid <= 0)
        return WINDOW_NONE;
    int status = 0;
    pid_t ended = waitpid(g_pid, &status, WNOHANG);
    if (ended == 0 || (ended < 0 && errno == EINTR))
        return WINDOW_OPEN;
    long lived = ms_since(&g_started);
    g_pid = -1;
    bool clean = ended > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    WindowState state = lived >= QUICK_EXIT_MS ? WINDOW_CLOSED
                      : clean                  ? WINDOW_LOST
                                               : WINDOW_FAILED;
    char how[48];
    if (ended > 0 && WIFEXITED(status))
        snprintf(how, sizeof how, "exit status %d", WEXITSTATUS(status));
    else if (ended > 0 && WIFSIGNALED(status))
        snprintf(how, sizeof how, "signal %d", WTERMSIG(status));
    else
        snprintf(how, sizeof how, "an unknown status");
    window_trace("app window: %s: the browser ended after %ld ms with %s%s",
                 state == WINDOW_CLOSED ? "closed" : state == WINDOW_LOST ? "lost" : "failed",
                 lived, how,
                 state == WINDOW_LOST ? " (a browser that was already running may have"
                                        " taken the window over)" : "");
    remove_profile();
    return state;
}

void window_close(void) {
    if (g_pid > 0) {
        window_trace("app window: closing it");
        kill(g_pid, SIGTERM);
        for (int i = 0; i < 100 && g_pid > 0; i++) {
            if (waitpid(g_pid, NULL, WNOHANG) != 0)
                g_pid = -1;
            else
                nap(50);
        }
        if (g_pid > 0) {
            kill(g_pid, SIGKILL);
            waitpid(g_pid, NULL, 0);
            g_pid = -1;
        }
    }
    remove_profile();
}

#endif
