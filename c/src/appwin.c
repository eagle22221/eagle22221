/* The native window (Windows): vex's own top-level window, with the interface
 * shown inside it by the system web view, Microsoft Edge WebView2.
 *
 * The window belongs to the vex process: it has vex's icon and title, its own
 * taskbar button, and closing it ends the program. WebView2 is the web engine
 * Windows itself ships (on every Windows 11, and on Windows 10 with Edge); it
 * is reached through WebView2Loader.dll, Microsoft's small redistributable
 * loader, which has to sit next to the program. When the loader or the engine
 * is missing, or anything fails before the page is on screen,
 * native_window_run() returns NATIVE_UNAVAILABLE and the caller falls back to
 * another front end (see window.h).
 *
 * Everything here runs on the program's main thread; WebView2 calls the
 * handlers below from the message loop of that same thread.
 */
#if defined(_WIN32) && !defined(VEX_NO_WEBVIEW2)

#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define COBJMACROS

#include "window.h"

#include <windows.h>
#include <ole2.h>               /* everything the SDK header itself includes... */
#include <eventtoken.h>         /* ...so that only its own declarations follow */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The SDK header is written for MSVC: it uses MSVC pragmas, and defines its
 * interface IDs with `extern` plus an initialiser, which GCC warns about. This
 * is the only file that includes it, so the IDs can simply be defined here. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#undef EXTERN_C
#define EXTERN_C
#include "WebView2.h"
#undef EXTERN_C
#define EXTERN_C extern
#pragma GCC diagnostic pop

#define WINDOW_CLASS L"VexMainWindow"
#define LOADER_NAME L"WebView2Loader.dll"
#define ICON_ID 1                       /* res/vex.rc */
#define STARTUP_TIMER 1
#define STARTUP_TIMEOUT_MS 20000        /* the first start creates a profile: allow for a slow disk */
#define WIDTH_AT_96_DPI 1360
#define HEIGHT_AT_96_DPI 900
#define BACKGROUND RGB(0x0B, 0x0C, 0x0F)    /* the page's own dark background */

typedef HRESULT(STDAPICALLTYPE *CreateEnvironmentFn)(
    PCWSTR browser_folder, PCWSTR user_data_folder, ICoreWebView2EnvironmentOptions *options,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *handler);

static struct {
    HWND hwnd;
    wchar_t *url;
    void (*on_shown)(void);
    ICoreWebView2Environment *environment;
    ICoreWebView2Controller *controller;
    ICoreWebView2 *webview;
    bool shown;         /* the page is on screen: from here on the window is the program */
    bool failed;        /* gave up before that */
} g;

/* A step-by-step record of how the window came up, appended to the file named
 * by %VEX_WINDOW_LOG% when that is set. A windowed program has nowhere to
 * print, so this is how a start-up problem gets diagnosed. */
static void trace(const char *format, ...) {
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

/* A number from the environment, for diagnosing start-up on a machine where it
 * goes wrong: %VEX_WINDOW_TIMEOUT_MS% (how long to wait for the engine) and
 * %VEX_WINDOW_SHOW_EARLY% (show the empty window while the engine starts). */
static unsigned long env_number(const wchar_t *name, unsigned long fallback) {
    wchar_t text[32];
    DWORD n = GetEnvironmentVariableW(name, text, 32);
    if (n == 0 || n >= 32)
        return fallback;
    wchar_t *end = NULL;
    unsigned long value = wcstoul(text, &end, 10);
    return end != text && *end == L'\0' ? value : fallback;
}

/* Give up on the native window (only ever before it is shown). */
static void fail(void) {
    if (g.shown || g.failed)
        return;
    trace("giving up on the native window");
    g.failed = true;
    if (g.hwnd != NULL)
        DestroyWindow(g.hwnd);
}

/* --- COM handlers ------------------------------------------------------------
 * Each is a static object that lives for the whole program, so reference
 * counting has nothing to do. */

#define STATIC_OBJECT(prefix, Interface)                                 \
    static ULONG STDMETHODCALLTYPE prefix##_add_ref(Interface *self) {  \
        (void)self;                                                     \
        return 2;                                                       \
    }                                                                   \
    static ULONG STDMETHODCALLTYPE prefix##_release(Interface *self) {  \
        (void)self;                                                     \
        return 1;                                                       \
    }

STATIC_OBJECT(title, ICoreWebView2DocumentTitleChangedEventHandler)
STATIC_OBJECT(controller, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler)
STATIC_OBJECT(environment, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler)

static HRESULT query(void *self, REFIID wanted, REFIID mine, void **out) {
    if (out == NULL)
        return E_POINTER;
    if (IsEqualIID(wanted, &IID_IUnknown) || IsEqualIID(wanted, mine)) {
        *out = self;
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

/* The page's title becomes the window's title. */
static HRESULT STDMETHODCALLTYPE title_query(ICoreWebView2DocumentTitleChangedEventHandler *self,
                                             REFIID iid, void **out) {
    return query(self, iid, &IID_ICoreWebView2DocumentTitleChangedEventHandler, out);
}

static HRESULT STDMETHODCALLTYPE title_invoke(ICoreWebView2DocumentTitleChangedEventHandler *self,
                                              ICoreWebView2 *sender, IUnknown *args) {
    (void)self;
    (void)args;
    LPWSTR title = NULL;
    if (sender != NULL && g.hwnd != NULL &&
        SUCCEEDED(ICoreWebView2_get_DocumentTitle(sender, &title)) && title != NULL) {
        SetWindowTextW(g.hwnd, title[0] != L'\0' ? title : L"vex");
    }
    CoTaskMemFree(title);
    return S_OK;
}

static ICoreWebView2DocumentTitleChangedEventHandlerVtbl g_title_vtbl = {
    title_query, title_add_ref, title_release, title_invoke};
static ICoreWebView2DocumentTitleChangedEventHandler g_title_handler = {&g_title_vtbl};

/* Step 2: the controller (the web view itself) exists. Size it, show the
 * window and load the page. */
static HRESULT STDMETHODCALLTYPE controller_query(
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *self, REFIID iid, void **out) {
    return query(self, iid, &IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler, out);
}

static HRESULT STDMETHODCALLTYPE controller_invoke(
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *self, HRESULT result,
    ICoreWebView2Controller *controller) {
    (void)self;
    trace("controller: result 0x%08lx", (unsigned long)result);
    if (g.failed || g.hwnd == NULL) {           /* too late: the window has gone */
        if (SUCCEEDED(result) && controller != NULL)
            ICoreWebView2Controller_Close(controller);
        return S_OK;
    }
    if (FAILED(result) || controller == NULL) {
        fail();
        return S_OK;
    }
    ICoreWebView2Controller_AddRef(controller);
    g.controller = controller;
    if (FAILED(ICoreWebView2Controller_get_CoreWebView2(controller, &g.webview)) ||
        g.webview == NULL) {
        fail();
        return S_OK;
    }

    /* No white flash before the page paints (needs a newer runtime; optional). */
    ICoreWebView2Controller2 *controller2 = NULL;
    if (SUCCEEDED(ICoreWebView2Controller_QueryInterface(controller, &IID_ICoreWebView2Controller2,
                                                         (void **)&controller2)) &&
        controller2 != NULL) {
        COREWEBVIEW2_COLOR colour = {255, GetRValue(BACKGROUND), GetGValue(BACKGROUND),
                                     GetBValue(BACKGROUND)};
        ICoreWebView2Controller2_put_DefaultBackgroundColor(controller2, colour);
        ICoreWebView2Controller2_Release(controller2);
    }

    RECT bounds;
    GetClientRect(g.hwnd, &bounds);
    ICoreWebView2Controller_put_Bounds(controller, bounds);
    ICoreWebView2Controller_put_IsVisible(controller, TRUE);

    EventRegistrationToken token;
    ICoreWebView2_add_DocumentTitleChanged(g.webview, &g_title_handler, &token);

    HRESULT navigated = ICoreWebView2_Navigate(g.webview, g.url);
    trace("navigate: result 0x%08lx", (unsigned long)navigated);
    if (FAILED(navigated)) {
        fail();
        return S_OK;
    }
    g.shown = true;
    if (g.on_shown != NULL)
        g.on_shown();
    KillTimer(g.hwnd, STARTUP_TIMER);
    ShowWindow(g.hwnd, SW_SHOWNORMAL);
    SetForegroundWindow(g.hwnd);
    ICoreWebView2Controller_MoveFocus(controller, COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
    return S_OK;
}

static ICoreWebView2CreateCoreWebView2ControllerCompletedHandlerVtbl g_controller_vtbl = {
    controller_query, controller_add_ref, controller_release, controller_invoke};
static ICoreWebView2CreateCoreWebView2ControllerCompletedHandler g_controller_handler = {
    &g_controller_vtbl};

/* Step 1: the environment (the engine, with our data folder) exists. Ask it for
 * a web view inside our window. */
static HRESULT STDMETHODCALLTYPE environment_query(
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *self, REFIID iid, void **out) {
    return query(self, iid, &IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, out);
}

static HRESULT STDMETHODCALLTYPE environment_invoke(
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *self, HRESULT result,
    ICoreWebView2Environment *environment) {
    (void)self;
    trace("environment: result 0x%08lx", (unsigned long)result);
    if (g.failed || g.hwnd == NULL)
        return S_OK;
    if (FAILED(result) || environment == NULL) {
        fail();
        return S_OK;
    }
    ICoreWebView2Environment_AddRef(environment);
    g.environment = environment;
    HRESULT asked = ICoreWebView2Environment_CreateCoreWebView2Controller(environment, g.hwnd,
                                                                          &g_controller_handler);
    trace("create controller: result 0x%08lx", (unsigned long)asked);
    if (FAILED(asked))
        fail();
    return S_OK;
}

static ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandlerVtbl g_environment_vtbl = {
    environment_query, environment_add_ref, environment_release, environment_invoke};
static ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler g_environment_handler = {
    &g_environment_vtbl};

/* --- the window -------------------------------------------------------------- */

static void release_webview(void) {
    if (g.controller != NULL)
        ICoreWebView2Controller_Close(g.controller);
    if (g.webview != NULL) {
        ICoreWebView2_Release(g.webview);
        g.webview = NULL;
    }
    if (g.controller != NULL) {
        ICoreWebView2Controller_Release(g.controller);
        g.controller = NULL;
    }
    if (g.environment != NULL) {
        ICoreWebView2Environment_Release(g.environment);
        g.environment = NULL;
    }
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_SIZE:
        if (g.controller != NULL) {
            RECT bounds;
            GetClientRect(hwnd, &bounds);
            ICoreWebView2Controller_put_Bounds(g.controller, bounds);
        }
        return 0;
    case WM_MOVE:
    case WM_MOVING:
        if (g.controller != NULL)
            ICoreWebView2Controller_NotifyParentWindowPositionChanged(g.controller);
        break;
    case WM_SETFOCUS:
        if (g.controller != NULL)
            ICoreWebView2Controller_MoveFocus(g.controller,
                                              COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
        return 0;
    case WM_DPICHANGED: {                       /* moved to a screen with another scale */
        const RECT *suggested = (const RECT *)lparam;
        SetWindowPos(hwnd, NULL, suggested->left, suggested->top,
                     suggested->right - suggested->left, suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_TIMER:
        if (wparam == STARTUP_TIMER) {
            KillTimer(hwnd, STARTUP_TIMER);
            trace("the engine did not answer in time");
            fail();                             /* the engine never answered */
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        release_webview();
        g.hwnd = NULL;
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

/* A function from a system DLL that older Windows versions may not have. */
static FARPROC optional_function(const wchar_t *dll, const char *name) {
    HMODULE module = LoadLibraryExW(dll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    return module != NULL ? GetProcAddress(module, name) : NULL;
}

/* Sharp text on high-resolution screens: without this Windows stretches the
 * window like a picture. */
static void be_dpi_aware(void) {
    typedef BOOL(WINAPI *SetContextFn)(HANDLE);
    SetContextFn set_context =
        (SetContextFn)(void (*)(void))optional_function(L"user32.dll", "SetProcessDpiAwarenessContext");
    /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 is ((HANDLE)-4), -3 is version 1. */
    if (set_context != NULL &&
        (set_context((HANDLE)(INT_PTR)-4) || set_context((HANDLE)(INT_PTR)-3)))
        return;
    SetProcessDPIAware();
}

static UINT dpi_of(HWND hwnd) {
    typedef UINT(WINAPI *GetDpiFn)(HWND);
    GetDpiFn get_dpi = (GetDpiFn)(void (*)(void))optional_function(L"user32.dll", "GetDpiForWindow");
    UINT dpi = get_dpi != NULL ? get_dpi(hwnd) : 0;
    return dpi != 0 ? dpi : 96;
}

/* A dark title bar when Windows is set to dark apps, to match the page. */
static void match_system_theme(HWND hwnd) {
    DWORD light = 1, size = sizeof light;
    RegGetValueW(HKEY_CURRENT_USER,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                 L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &light, &size);
    typedef HRESULT(WINAPI *SetAttributeFn)(HWND, DWORD, LPCVOID, DWORD);
    SetAttributeFn set_attribute =
        (SetAttributeFn)(void (*)(void))optional_function(L"dwmapi.dll", "DwmSetWindowAttribute");
    if (set_attribute != NULL) {
        BOOL dark = light == 0;
        set_attribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    }
}

/* Size the window for its screen's scale and centre it in the work area. */
static void place_window(HWND hwnd) {
    UINT dpi = dpi_of(hwnd);
    int width = MulDiv(WIDTH_AT_96_DPI, (int)dpi, 96);
    int height = MulDiv(HEIGHT_AT_96_DPI, (int)dpi, 96);
    MONITORINFO monitor;
    memset(&monitor, 0, sizeof monitor);
    monitor.cbSize = sizeof monitor;
    if (!GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY), &monitor))
        return;
    int area_width = monitor.rcWork.right - monitor.rcWork.left;
    int area_height = monitor.rcWork.bottom - monitor.rcWork.top;
    if (width > area_width)
        width = area_width;
    if (height > area_height)
        height = area_height;
    SetWindowPos(hwnd, NULL, monitor.rcWork.left + (area_width - width) / 2,
                 monitor.rcWork.top + (area_height - height) / 2, width, height,
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

/* --- finding the loader and a place for the engine's data -------------------- */

/* WebView2Loader.dll from the folder the program is in, and nowhere else. */
static CreateEnvironmentFn load_loader(void) {
    wchar_t path[MAX_PATH + 32];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return NULL;
    wchar_t *slash = wcsrchr(path, L'\\');
    if (slash == NULL)
        return NULL;
    wcscpy(slash + 1, LOADER_NAME);
    HMODULE loader = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (loader == NULL)
        return NULL;
    return (CreateEnvironmentFn)(void (*)(void))GetProcAddress(
        loader, "CreateCoreWebView2EnvironmentWithOptions");
}

/* %LOCALAPPDATA%\vex\WebView2: the engine keeps its cache and settings there.
 * (Its default, a folder next to the program, fails where that is read-only.) */
static bool data_folder(wchar_t *out, size_t cap) {
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", out, (DWORD)cap);
    if (n == 0 || n + 32 >= cap)
        return false;
    wcscat(out, L"\\vex");
    if (!CreateDirectoryW(out, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return false;
    wcscat(out, L"\\WebView2");
    return true;
}

/* --- the entry point --------------------------------------------------------- */

void native_window_request_close(void) {
    HWND hwnd = g.hwnd;                 /* read once: the main thread clears it */
    if (hwnd != NULL)
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
}

NativeResult native_window_run(const char *url, void (*on_shown)(void)) {
    memset(&g, 0, sizeof g);
    g.on_shown = on_shown;
    CreateEnvironmentFn create_environment = load_loader();
    wchar_t data[MAX_PATH + 64];
    trace("native window: loader %s", create_environment != NULL ? "found" : "not found");
    if (create_environment == NULL || url == NULL || !data_folder(data, MAX_PATH + 64))
        return NATIVE_UNAVAILABLE;

    int url_chars = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    if (url_chars <= 0)
        return NATIVE_UNAVAILABLE;
    g.url = malloc((size_t)url_chars * sizeof *g.url);
    if (g.url == NULL || MultiByteToWideChar(CP_UTF8, 0, url, -1, g.url, url_chars) <= 0) {
        free(g.url);
        return NATIVE_UNAVAILABLE;
    }

    be_dpi_aware();
    HRESULT com = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) {
        free(g.url);
        return NATIVE_UNAVAILABLE;
    }

    HINSTANCE instance = GetModuleHandleW(NULL);
    WNDCLASSEXW cls;
    memset(&cls, 0, sizeof cls);
    cls.cbSize = sizeof cls;
    cls.lpfnWndProc = window_proc;
    cls.hInstance = instance;
    cls.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    cls.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(ICON_ID));
    cls.hIconSm = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(ICON_ID), IMAGE_ICON,
                                    GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                    LR_DEFAULTCOLOR);
    cls.hbrBackground = CreateSolidBrush(BACKGROUND);
    cls.lpszClassName = WINDOW_CLASS;
    if (RegisterClassExW(&cls) != 0) {
        /* Created hidden; it is shown once the page is ready to appear in it. */
        g.hwnd = CreateWindowExW(0, WINDOW_CLASS, L"vex", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                 CW_USEDEFAULT, WIDTH_AT_96_DPI, HEIGHT_AT_96_DPI, NULL, NULL,
                                 instance, NULL);
    }
    if (g.hwnd != NULL) {
        place_window(g.hwnd);
        match_system_theme(g.hwnd);
        SetTimer(g.hwnd, STARTUP_TIMER,
                 (UINT)env_number(L"VEX_WINDOW_TIMEOUT_MS", STARTUP_TIMEOUT_MS), NULL);
        if (env_number(L"VEX_WINDOW_SHOW_EARLY", 0) != 0)
            ShowWindow(g.hwnd, SW_SHOWNORMAL);
        HRESULT asked = create_environment(NULL, data, NULL, &g_environment_handler);
        trace("create environment: result 0x%08lx", (unsigned long)asked);
        if (FAILED(asked))
            fail();                             /* e.g. the engine is not installed */

        /* Runs until the window is destroyed - closed by the user, or by
         * fail() - and its WM_QUIT arrives. That message has to be taken off
         * the queue here: left behind, it would close the next message box. */
        MSG message;
        while (GetMessageW(&message, NULL, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    release_webview();
    free(g.url);
    g.url = NULL;
    CoUninitialize();
    trace("native window: %s", g.shown ? "closed by the user" : "unavailable");
    return g.shown ? NATIVE_CLOSED : NATIVE_UNAVAILABLE;
}

#elif defined(_WIN32)
/* Built without the WebView2 SDK (see fetch_webview2.sh): no native window. */

#include "window.h"

NativeResult native_window_run(const char *url, void (*on_shown)(void)) {
    (void)url;
    (void)on_shown;
    return NATIVE_UNAVAILABLE;
}

void native_window_request_close(void) {
}

#else
typedef int vex_appwin_is_windows_only;         /* keeps this file a valid translation unit */
#endif
