/* vex-app.exe: the windowed Windows program (built with -mwindows, so it never
 * opens a console window). It is `vex gui [FILE]` and nothing else:
 *
 *   vex-app.exe [FILE]      (or a file dropped on its icon)
 *
 * shows the interface in vex's own window (window.h) and ends when that is
 * closed. With no console to print to, errors are shown in a message box
 * (cli.c), and when the page can only be shown in a browser tab a box with an
 * OK button is the way to stop it (server.c). %VEX_WINDOW_LOG% names a file
 * that receives a record of each step, for diagnosing a start-up problem.
 * main.c is the entry point of vex.exe, the command-line program. */
#include "cli.h"
#include "platform.h"
#include "window.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>

/* A windowed program is started without standard output and error, and the
 * C library then fails every write to them (which would make the exit status
 * 1) or even rejects them outright. Point them at NUL unless the starter gave
 * real ones (a redirection), which are kept. */
static void quiet_stream(DWORD which, FILE *stream) {
    HANDLE handle = GetStdHandle(which);
    bool real = handle != NULL && handle != INVALID_HANDLE_VALUE &&
                GetFileType(handle) != FILE_TYPE_UNKNOWN && _fileno(stream) >= 0;
    if (!real && freopen("NUL", "wb", stream) == NULL)
        window_trace("vex-app: could not point a standard stream at NUL");
}
#endif

int main(int argc, char **argv) {
#ifdef _WIN32
    quiet_stream(STD_OUTPUT_HANDLE, stdout);
    quiet_stream(STD_ERROR_HANDLE, stderr);
#endif
    Arena arguments = {0};
    platform_init();
    argv = platform_argv(&arguments, argc, argv, &argc);
    window_trace("vex-app: started with %d argument%s", argc - 1, argc == 2 ? "" : "s");
    /* Whatever it is given is a file to open: "--" keeps a name that starts
     * with "-" from being read as an option. Only the first one is opened. */
    char *gui[] = {argv[0], (char *)"gui", (char *)"--", argc > 1 ? argv[1] : NULL, NULL};
    if (argc > 2)
        window_trace("vex-app: opening only the first of the files it was given");
    int status = cli_main(argc > 1 ? 4 : 2, gui);
    window_trace("vex-app: exit status %d", status);
    arena_release(&arguments);
    return status;
}
