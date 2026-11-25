/* vex: static reverse-engineering toolkit for ELF and PE binaries.
 * (vex-app.exe, the windowed Windows program, starts in app_main.c.) */
#include "cli.h"
#include "platform.h"
#include "server.h"

int main(int argc, char **argv) {
    Arena arguments = {0};
    platform_init();
    argv = platform_argv(&arguments, argc, argv, &argc);
    int status = cli_main(argc, argv);
    arena_release(&arguments);
    /* A console window of its own stays until Enter is pressed, so the output
     * can be read - except after the graphical interface, which the user has
     * just closed: then the program is simply done. */
    if (!gui_ended_as_asked())
        platform_pause_if_own_console();
    return status;
}
