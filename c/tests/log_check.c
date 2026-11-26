/* Unit checks of the log (window.c), run by tests/test_c_log.py on POSIX.
 *
 * window.c is included whole, so its private helpers can be called: the path
 * helpers the Windows log is built with (sibling_path, join_path,
 * previous_path, with Windows separators too), hiding the session token,
 * cutting long lines, and the POSIX log itself (rotation, the size cap and
 * many threads writing at once).
 *
 *   log-check paths          the helpers; no files
 *   log-check run DIR        the log, in DIR/vex-log.txt ($VEX_WINDOW_LOG)
 *   log-check quiet          trace without starting the log: nothing written
 *
 * Exit status 0 when every check passed; each failure is printed. */
#define VEX_LOG_CAP_BYTES (64ul << 10)      /* small, so the cap is reached quickly */
#include "../src/window.c"

#include <pthread.h>

static int failures;

#define CHECK(cond)                                                                     \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond);   \
            failures++;                                                                 \
        }                                                                               \
    } while (0)

#define WIN "\\/"

static bool previous_is(const char *path, const char *seps, const char *want) {
    char out[256];
    bool ok = previous_path(out, sizeof out, path, seps);
    if (want == NULL)
        return !ok;
    if (!ok || strcmp(out, want) != 0) {
        fprintf(stderr, "previous_path(%s) = %s, want %s\n", path, ok ? out : "(false)", want);
        return false;
    }
    return true;
}

static void check_paths(void) {
    char out[64];
    /* the Windows log's place, from the program's path */
    CHECK(sibling_path(out, sizeof out, "C:\\vex\\vex-app.exe", LOG_NAME, WIN) &&
          strcmp(out, "C:\\vex\\vex-log.txt") == 0);
    CHECK(sibling_path(out, sizeof out, "C:/vex/vex.exe", LOG_NAME, WIN) &&
          strcmp(out, "C:/vex/vex-log.txt") == 0);
    CHECK(sibling_path(out, sizeof out, "\\\\server\\share\\vex.exe", LOG_NAME, WIN) &&
          strcmp(out, "\\\\server\\share\\vex-log.txt") == 0);
    CHECK(!sibling_path(out, sizeof out, "vex.exe", LOG_NAME, WIN));     /* no folder part */
    CHECK(!sibling_path(out, 12, "C:\\vex\\vex.exe", LOG_NAME, WIN));    /* does not fit */
    CHECK(sibling_path(out, 19, "C:\\vex\\vex.exe", LOG_NAME, WIN));     /* just fits */
    /* UTF-8 is passed through byte for byte ("Документы", "テスト") */
    const char *cyrillic = "C:\\Users\\\xd0\x94\xd0\xbe\xd0\xba\\\xe3\x83\x86\\vex.exe";
    char wide_out[128];
    CHECK(sibling_path(wide_out, sizeof wide_out, cyrillic, LOG_NAME, WIN) &&
          strcmp(wide_out, "C:\\Users\\\xd0\x94\xd0\xbe\xd0\xba\\\xe3\x83\x86\\vex-log.txt") == 0);
    /* the %LOCALAPPDATA% fallback */
    CHECK(join_path(out, sizeof out, "C:\\Users\\a\\AppData\\Local", "vex", WIN) &&
          strcmp(out, "C:\\Users\\a\\AppData\\Local\\vex") == 0);
    CHECK(join_path(out, sizeof out, "C:\\Local\\", "vex", WIN) && strcmp(out, "C:\\Local\\vex") == 0);
    CHECK(!join_path(out, sizeof out, "", "vex", WIN));
    CHECK(!join_path(out, 8, "C:\\Local", "vex", WIN));
    /* the log of the run before */
    CHECK(previous_is("C:\\vex\\vex-log.txt", WIN, "C:\\vex\\vex-log.previous.txt"));
    CHECK(previous_is("C:\\v.1\\log", WIN, "C:\\v.1\\log.previous"));       /* a dot in a folder */
    CHECK(previous_is("/tmp/v.1/log", "/", "/tmp/v.1/log.previous"));
    CHECK(previous_is("/tmp/a.b.log", "/", "/tmp/a.b.previous.log"));
    CHECK(previous_is("/tmp/.log", "/", "/tmp/.log.previous"));             /* a dot file */
    CHECK(previous_is("window.log", "/", "window.previous.log"));
    CHECK(previous_is("/tmp/", "/", NULL));                                 /* no name */
    /* off */
    CHECK(log_setting_off("off") && log_setting_off("OFF") && log_setting_off("Off") &&
          log_setting_off("0"));
    CHECK(!log_setting_off("of") && !log_setting_off("offf") && !log_setting_off("00") &&
          !log_setting_off("C:\\off"));
    /* the secret, hidden everywhere, also across where a line is cut */
    char shown[64];
    hide_secret(shown, sizeof shown, "a TOKEN b TOKENTOKEN", "TOKEN");
    CHECK(strcmp(shown, "a [hidden] b [hidden][hidden]") == 0);
    hide_secret(shown, sizeof shown, "no secret set", "");
    CHECK(strcmp(shown, "no secret set") == 0);
    char longer[200];
    memset(longer, 'x', sizeof longer);
    memcpy(longer + 50, "TOKEN", 5);                /* across the cut at 64 */
    longer[sizeof longer - 1] = '\0';
    hide_secret(shown, sizeof shown, longer, "TOKEN");
    CHECK(strlen(shown) < sizeof shown && strstr(shown, "TOK") == NULL);
    CHECK(strstr(shown, LOG_CUT) != NULL);
    memcpy(longer + 50, "TOKEN", 5);
    longer[60] = '\0';                              /* fits: not cut */
    hide_secret(shown, sizeof shown, longer, "TOKEN");
    CHECK(strstr(shown, LOG_CUT) == NULL && strstr(shown, LOG_HIDDEN) != NULL);
    char flat[] = "one\ntwo\r\tthree\x7f";
    flatten(flat);
    CHECK(strcmp(flat, "one two  three ") == 0);
}

static char *slurp(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;
    char *data = malloc(1 << 20);
    size_t n = data != NULL ? fread(data, 1, (1 << 20) - 1, f) : 0;
    fclose(f);
    if (data != NULL)
        data[n] = '\0';
    if (size != NULL)
        *size = n;
    return data;
}

#define THREADS 8
#define LINES_PER_THREAD 300

static void *writer(void *arg) {
    int id = (int)(intptr_t)arg;
    for (int i = 0; i < LINES_PER_THREAD; i++)
        window_trace("thread %d line %d SECRET", id, i);
    return NULL;
}

/* Every line "[ NNN ms] text\n", none cut into by another. */
static bool well_formed(const char *text, int *lines, int *thread_lines) {
    *lines = *thread_lines = 0;
    for (const char *p = text; *p != '\0';) {
        const char *end = strchr(p, '\n');
        if (end == NULL)
            return false;
        unsigned long ms;
        int used = 0;
        if (sscanf(p, "[%lu ms] %n", &ms, &used) != 1 || used == 0) {
            fprintf(stderr, "bad line: %.*s\n", (int)(end - p), p);
            return false;
        }
        int id, i, tail = 0;
        if (strncmp(p + used, "thread ", 7) == 0) {
            if (sscanf(p + used, "thread %d line %d [hidden]%n", &id, &i, &tail) != 2 ||
                p + used + tail != end || id < 0 || id >= THREADS || i < 0 ||
                i >= LINES_PER_THREAD) {
                fprintf(stderr, "mixed line: %.*s\n", (int)(end - p), p);
                return false;
            }
            ++*thread_lines;
        }
        ++*lines;
        p = end + 1;
    }
    return true;
}

static void check_run(const char *dir) {
    char path[1024], previous[1024];
    snprintf(path, sizeof path, "%s/vex-log.txt", dir);
    snprintf(previous, sizeof previous, "%s/vex-log.previous.txt", dir);
    setenv("VEX_WINDOW_LOG", path, 1);

    window_trace("before the start: never written");
    char *old = slurp(path, NULL);
    CHECK(old != NULL && strcmp(old, "the run before\n") == 0);   /* untouched so far */
    free(old);

    window_log_start();
    window_log_start();                                 /* a second call does nothing */
    old = slurp(previous, NULL);
    CHECK(old != NULL && strcmp(old, "the run before\n") == 0);   /* kept */
    free(old);

    window_log_secret("SECRET");
    window_trace("a line with SECRET in it, twice: SECRETSECRET");
    window_trace("a line\nwith a newline");
    char big[LOG_LINE_CAP * 2];
    memset(big, 'y', sizeof big);
    big[sizeof big - 1] = '\0';
    window_trace("%s", big);

    pthread_t threads[THREADS];
    for (int t = 0; t < THREADS; t++)
        CHECK(pthread_create(&threads[t], NULL, writer, (void *)(intptr_t)t) == 0);
    for (int t = 0; t < THREADS; t++)
        pthread_join(threads[t], NULL);

    size_t size = 0;
    char *text = slurp(path, &size);
    CHECK(text != NULL);
    if (text == NULL)
        return;
    CHECK(strstr(text, "before the start") == NULL);
    CHECK(strstr(text, "vex " VEX_VERSION ": the log of this run, started ") != NULL);
    CHECK(strstr(text, "the run before is in vex-log.previous.txt") != NULL);
    CHECK(strstr(text, "] program: ") != NULL && strstr(text, "] system: ") != NULL);
    CHECK(strstr(text, "SECRET") == NULL);
    CHECK(strstr(text, "a line with [hidden] in it, twice: [hidden][hidden]\n") != NULL);
    CHECK(strstr(text, "a line with a newline\n") != NULL);
    CHECK(strstr(text, LOG_CUT "\n") != NULL);          /* the long line, cut */
    int lines, thread_lines;
    CHECK(well_formed(text, &lines, &thread_lines));
    /* All of them, or as many as fit before the cap, then the "log full" line. */
    bool full = strstr(text, "] log full (") != NULL;
    CHECK(full ? size <= VEX_LOG_CAP_BYTES + 200 : thread_lines == THREADS * LINES_PER_THREAD);
    CHECK(full);                                        /* 2400 lines pass 64 KB */
    free(text);

    window_trace("after the cap: never written");
    text = slurp(path, NULL);
    CHECK(text != NULL && strstr(text, "after the cap") == NULL);
    const char *last = text != NULL ? strrchr(text, '[') : NULL;
    CHECK(last != NULL && strstr(last, "log full") != NULL);
    free(text);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "paths") == 0)
        check_paths();
    else if (argc == 3 && strcmp(argv[1], "run") == 0)
        check_run(argv[2]);
    else if (argc == 2 && strcmp(argv[1], "quiet") == 0) {
        window_log_start();                 /* $VEX_WINDOW_LOG is off, unset or empty */
        window_trace("nothing");
    } else {
        fprintf(stderr, "usage: log-check paths | run DIR | quiet\n");
        return 2;
    }
    if (failures == 0)
        printf("ok\n");
    return failures == 0 ? 0 : 1;
}
