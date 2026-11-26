/* Front ends for the graphical interface: where the page is shown.
 *
 *   - a native window (Windows): vex's own window, hosting the system web view
 *     (Microsoft Edge WebView2) inside the vex process;
 *   - an app window: a Chromium-family browser (Edge, Chrome, Chromium) started
 *     in app mode with a throw-away profile - one window, no tabs, no address
 *     bar - used where there is no native window;
 *   - failing both, an ordinary browser tab (server.c).
 */
#ifndef VEX_WINDOW_H
#define VEX_WINDOW_H

#include <stdbool.h>

/* --- the app window ---------------------------------------------------------- */

typedef enum {
    WINDOW_NONE,        /* no window is being followed */
    WINDOW_OPEN,        /* the window is up */
    WINDOW_CLOSED,      /* it was up and has been closed: time to stop */
    WINDOW_FAILED,      /* it ended at once with an error: it never opened */
    WINDOW_LOST         /* it ended at once without error: vex cannot follow it */
} WindowState;

/* Start the app window on `url`. False when no suitable browser is installed
 * or it could not be started. */
bool window_open(const char *url);

/* Call a few times a second while serving. WINDOW_OPEN while the window is up;
 * CLOSED, FAILED or LOST once when it ends, and WINDOW_NONE after that. */
WindowState window_poll(void);

/* Close the window if it is still open and delete its throw-away profile. */
void window_close(void);

/* --- the native window (Windows only) ---------------------------------------- */

typedef enum {
    NATIVE_UNAVAILABLE, /* it could not be shown: use another front end */
    NATIVE_CLOSED       /* it was shown, and the user has closed it */
} NativeResult;

/* Show vex's own window on `url` and run it until it is closed. Must be called
 * on the program's main thread; the server has to run on another thread
 * meanwhile. `on_shown` (may be NULL) is called once, when the page appears.
 * Always NATIVE_UNAVAILABLE on systems other than Windows, and in a build made
 * without the WebView2 SDK. */
NativeResult native_window_run(const char *url, void (*on_shown)(void));

/* Ask the native window to close, from any thread. Does nothing without one. */
void native_window_request_close(void);

/* True when the program has a console to print to (always, except for the
 * windowed Windows build started from the desktop). */
bool window_has_console(void);

/* Tell the user something when there is no console to print it to: a message
 * box that the call waits on (Windows). Does nothing where there is a console. */
void window_message(const char *text);

/* The same box as the program's only control: it is shown without blocking,
 * and `on_dismiss` is called (on another thread) when the user closes it.
 * Does nothing where there is a console. */
void window_stop_box(const char *text, void (*on_dismiss)(void));

/* --- diagnosis: the log ------------------------------------------------------- */

/* Each run that shows the interface (vex-app.exe, `vex gui`, a double-clicked
 * vex.exe) keeps a log, so that a user who sees a problem can send one file.
 * Where it goes:
 *
 *   %VEX_WINDOW_LOG% (POSIX: $VEX_WINDOW_LOG) set to a file name: that file;
 *                    set to "off" or "0": no log at all;
 *   otherwise, on Windows: vex-log.txt in the program's own folder, or, where
 *                    that folder cannot be written to (Program Files),
 *                    %LOCALAPPDATA%\vex\vex-log.txt;
 *   otherwise, elsewhere: no log (nothing is written next to the program).
 *
 * The first line of a run moves the log of the run before to NAME.previous.EXT
 * (vex-log.previous.txt) and starts a fresh file, which ends after about 2 MB
 * with a last "log full" line. Each line is written out as soon as it is
 * traced, from any thread. File contents, request bodies and the session
 * token are never written (see window_log_secret). */

/* Start this run's log: open (and rotate) it and write the first lines (date,
 * vex version, the program, the system). Called by every program that shows
 * the interface, before anything else is traced; later calls do nothing.
 * Nothing is ever written in a run that has not called it, so plain commands
 * (`vex info FILE`) never create or touch a log. */
void window_log_start(void);

/* Never write `secret` (the session token) to the log: every occurrence of it
 * in a line is replaced by "[hidden]". At most one secret; NULL forgets it. */
void window_log_secret(const char *secret);

/* One line, "[  1234 ms] text", in the log when it has been started, and
 * nothing otherwise. The front ends, the server and `vex gui` record each step
 * there, so a problem in a program with nowhere to print can be diagnosed
 * from the file alone. Times count from the first line of the run. Control
 * characters become spaces (one call, one line). Only plain printf
 * conversions (%s, %d, %u, %lu, %x, %lx) are used with it. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 1, 2)))
#endif
void window_trace(const char *format, ...);

/* Windows: one line naming the installed WebView2 runtime (asked of
 * WebView2Loader.dll next to the program), or saying why there is none.
 * Part of window_log_start(); defined in appwin.c. */
void native_window_trace_runtime(void);

#endif
