/* binspect: static reverse-engineering toolkit for ELF and PE binaries. */
#include "cli.h"
#include "platform.h"

int main(int argc, char **argv) {
    Arena arguments = {0};
    platform_init();
    argv = platform_argv(&arguments, argc, argv, &argc);
    int status = cli_main(argc, argv);
    arena_release(&arguments);
    platform_pause_if_own_console();
    return status;
}
