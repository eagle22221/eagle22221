/* A probe for the native window on its own (Windows): shows a fixed page in
 * vex's window, with no server behind it, to tell a problem with the window
 * from a problem with anything else (see c/tests/windows_smoke.ps1).
 *
 *   appwin-probe.exe [URL]
 *
 * Exit status: 0 the window was shown and then closed, 3 it could not be shown.
 * It keeps a step-by-step log like vex-app.exe (vex-log.txt next to it, or the
 * file named by %VEX_WINDOW_LOG%). */
#include "../src/window.h"

#include <stddef.h>

int main(int argc, char **argv) {
    window_log_start();
    const char *url = argc > 1 ? argv[1]
        : "data:text/html,<title>vex probe</title><body style='background:%230B0C0F;color:white;"
          "font:28px sans-serif;padding:40px'>vex probe: the native window works";
    return native_window_run(url, NULL) == NATIVE_CLOSED ? 0 : 3;
}
