/* Command-line session shared by the command implementations. */
#ifndef VEX_CLI_H
#define VEX_CLI_H

#include "analysis.h"
#include "render.h"
#include "views.h"

typedef struct {
    const char *name;           /* long name without the dashes */
    char letter;                /* short form, or 0 */
    bool takes_value;
} OptSpec;

typedef struct Session Session;

typedef struct {
    const char *name;
    const char *action;         /* second word ("patch bytes"), or NULL */
    int min_positional, max_positional;
    const char *positional_names;
    const OptSpec *options;
    size_t noptions;
    void (*run)(Session *s);
} Command;

struct Session {
    Arena *a;                   /* lives until the command is done */
    Arena scratch;              /* reset between rows of streamed output */
    Err *err;
    bool json;
    const char *color;          /* auto, always or never */
    bool want_version;
    Style style;
    const Command *command;
    const char *positional[64];     /* PACK, FOLDER then entry names for `assets extract` */
    size_t npositional;
    const char *option_value[12];   /* parallel to command->options */
    bool option_seen[12];
    unsigned option_order[12];      /* 1 for the option given first, 2 for the next... */
    unsigned options_given;
    int exit_status;                /* of a command that ran to its end (decode: 1 */
};                                  /* when the result says ok: false)             */

/* Runs the program; returns the process exit status (0, 1, or 2 for a bad
 * command line). */
int cli_main(int argc, char **argv);

NORETURN void cli_usage_error(Session *s, const char *fmt, ...) PRINTF_LIKE(2, 3);
/* Whole file in memory (owned by the session). Throws ERR_OS. */
const uint8_t *cli_read_file(Session *s, const char *path, uint64_t *size);
Binary *cli_load(Session *s, const char *path);
/* Print a view as JSON or as text, depending on --json. */
void cli_emit(Session *s, const JVal *data, Renderer render);
const char *cli_option(const Session *s, const char *name);
bool cli_flag(const Session *s, const char *name);
bool cli_int_option(Session *s, const char *name, const char *display, bool any_base,
                    big *out);
const char *cli_choice(Session *s, const char *name, const char *display, const char *fallback,
                       const char *const *choices, size_t count);

/* patch.c */
void cmd_patch(Session *s);

#endif
