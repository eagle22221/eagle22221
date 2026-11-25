/* The graphical interface: `vex gui [PATH] [--port N] [--no-browser]`
 * (port of server.py).
 *
 * A single-threaded HTTP server bound to the loopback interface. It serves
 * the embedded single-page web interface (see tools/embed_web.py) and a JSON
 * API built from the same views the command line prints, so the two outputs
 * cannot disagree.
 *
 * Three things keep other web pages in the same browser from driving it, as
 * in server.py: every /api/ call needs a random per-session token sent in a
 * header (which a cross-site page cannot set), the Host header must be this
 * server's own address (which defeats DNS rebinding), and no CORS headers are
 * ever sent. */
#ifdef _WIN32
#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN
#else
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700       /* POSIX.1-2008: mkdtemp, sigaction, getpwuid, ... */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include "server.h"

#include <errno.h>
#include <signal.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
typedef SOCKET socket_t;
#define BAD_SOCKET INVALID_SOCKET
#define closesock closesocket
#include <direct.h>
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int socket_t;
#define BAD_SOCKET (-1)
#define closesock close
#endif

#include "analysis.h"
#include "techniques.h"
#include "archives.h"
#include "decode.h"
#include "engines.h"
#include "model.h"
#include "platform.h"
#include "split.h"
#include "strings.h"
#include "views.h"

/* server.py: CSP, MAX_UPLOAD. */
static const char CSP[] =
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'";
static const char RAW_CSP[] = "sandbox; default-src 'none'";
#define MAX_UPLOAD ((big)4 << 30)
#define MAX_PREVIEW ((big)64 << 20)
#define MAX_HEADER_BYTES 65536
#define RECV_TIMEOUT_SECS 20

/* --- server and request state ------------------------------------------------ */

typedef struct {
    socket_t listen_fd;
    unsigned port;
    char token[64];                 /* base64url of >=24 random bytes */
    const char *tempdir;            /* per-session scratch (uploads) */
    unsigned uploads;
    Err err;
} Server;

typedef struct {
    const char *key, *value;
} QParam;

typedef struct Req Req;
typedef void (*ApiHandler)(Req *req);

struct Req {
    Arena *a;
    Err *err;
    Server *srv;
    socket_t fd;

    const char *method;             /* "GET" / "POST" */
    const char *host;               /* Host header value, or NULL */
    const char *token_hdr;          /* X-Vex-Token, or NULL */
    big content_length;

    QParam *params;
    size_t nparams;

    const uint8_t *leftover;        /* body bytes already read with the headers */
    size_t leftover_len;
    const uint8_t *body;            /* the whole request body, once read */
    size_t body_len;
    bool body_read;

    ApiHandler handler;
    int status;                     /* set by api_error before throwing */
    bool have_status;

    JVal *result;                   /* JSON result on success */
    bool is_raw;                    /* result is raw bytes instead */
    const uint8_t *raw_data;
    size_t raw_len;
    const char *raw_ctype;
    const char *raw_filename;       /* for Content-Disposition, or NULL */
};

/* Throw an API error carrying an explicit HTTP status (mirrors ApiError). */
static NORETURN void api_error(Req *req, int status, const char *fmt, ...) PRINTF_LIKE(3, 4);
static NORETURN void api_error(Req *req, int status, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char text[1024];
    vsnprintf(text, sizeof text, fmt, args);
    va_end(args);
    req->status = status;
    req->have_status = true;
    err_throw(req->err, ERR_OTHER, "%s", text);
}

/* --- random session token ---------------------------------------------------- */

static bool os_random(uint8_t *buf, size_t n) {
#ifdef _WIN32
    for (size_t i = 0; i < n;) {
        unsigned v;
        if (rand_s(&v) != 0)
            return false;
        for (int k = 0; k < 4 && i < n; k++)
            buf[i++] = (uint8_t)(v >> (8 * k));
    }
    return true;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL)
        return false;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n;
#endif
}

/* secrets.token_urlsafe(n): url-safe base64 of n random bytes, no padding. */
static bool make_token(char *out, size_t out_cap) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint8_t raw[24];
    if (!os_random(raw, sizeof raw))
        return false;
    size_t n = 0;
    for (size_t i = 0; i < sizeof raw; i += 3) {
        unsigned v = (unsigned)raw[i] << 16 | (unsigned)raw[i + 1] << 8 | raw[i + 2];
        if (n + 4 >= out_cap)
            return false;
        out[n++] = b64[(v >> 18) & 63];
        out[n++] = b64[(v >> 12) & 63];
        out[n++] = b64[(v >> 6) & 63];
        out[n++] = b64[v & 63];
    }
    out[n] = '\0';
    return true;
}

/* Constant-time string compare (hmac.compare_digest). */
static bool const_time_eq(const char *a, const char *b) {
    size_t na = a ? strlen(a) : 0, nb = strlen(b);
    unsigned diff = (unsigned)(na ^ nb);
    for (size_t i = 0; i < nb; i++)
        diff |= (unsigned)((unsigned char)(i < na ? a[i] : 0) ^ (unsigned char)b[i]);
    return diff == 0;
}

/* --- percent-decoding and query parsing -------------------------------------- */

static int hex_value(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* unquote() / unquote_plus(): decode %XX; a stray % is kept literally, never
 * reading past the end. */
static char *percent_decode(Arena *a, const char *s, size_t n, bool plus_to_space) {
    char *out = arena_alloc(a, n + 1);
    size_t w = 0;
    for (size_t i = 0; i < n;) {
        char c = s[i];
        if (c == '%' && i + 2 < n) {
            int hi = hex_value((unsigned char)s[i + 1]);
            int lo = hex_value((unsigned char)s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out[w++] = (char)(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        if (plus_to_space && c == '+')
            c = ' ';
        out[w++] = c;
        i++;
    }
    out[w] = '\0';
    return out;
}

/* parse_qs(keep_blank_values=True): split on '&', then first '='. */
static void parse_query(Req *req, const char *query, size_t n) {
    VEC(QParam) params = {0};
    size_t i = 0;
    while (i < n) {
        size_t start = i;
        while (i < n && query[i] != '&')
            i++;
        size_t end = i;
        i++;                        /* skip '&' */
        if (end == start)
            continue;
        const char *eq = memchr(query + start, '=', end - start);
        QParam p;
        if (eq != NULL) {
            p.key = percent_decode(req->a, query + start, (size_t)(eq - (query + start)), true);
            p.value = percent_decode(req->a, eq + 1, (size_t)(query + end - (eq + 1)), true);
        } else {
            p.key = percent_decode(req->a, query + start, end - start, true);
            p.value = "";
        }
        *VEC_PUSH(req->a, params) = p;
    }
    req->params = params.v;
    req->nparams = params.n;
}

/* --- parameter access (mirrors server.py Params) ----------------------------- */

static const char *q_get(Req *req, const char *name) {
    for (size_t i = 0; i < req->nparams; i++)
        if (strcmp(req->params[i].key, name) == 0)
            return req->params[i].value;
    return NULL;
}

static const char *q_need(Req *req, const char *name) {
    const char *v = q_get(req, name);
    if (v == NULL || v[0] == '\0')
        api_error(req, 400, "missing parameter: %s", name);
    return v;
}

/* number(name, default): int(value, 0) or the default when blank. */
static big q_number(Req *req, const char *name, big fallback) {
    const char *v = q_get(req, name);
    if (v == NULL || v[0] == '\0')
        return fallback;
    big out;
    if (!parse_int(v, true, &out))
        api_error(req, 400, "parameter %s must be a number", name);
    return out;
}

/* number(name) with no default: true when a value was given. */
static bool q_number_opt(Req *req, const char *name, big *out) {
    const char *v = q_get(req, name);
    if (v == NULL || v[0] == '\0')
        return false;
    if (!parse_int(v, true, out))
        api_error(req, 400, "parameter %s must be a number", name);
    return true;
}

/* --- sending responses ------------------------------------------------------- */

static void send_all(socket_t fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        int n = send(fd, (const char *)data + sent, (int)(len - sent > 1 << 20 ? 1 << 20 : len - sent), 0);
#else
        ssize_t n = send(fd, data + sent, len - sent, 0);
#endif
        if (n <= 0)
            return;                 /* client went away: nothing more we can do */
        sent += (size_t)n;
    }
}

static const char *reason_phrase(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 413: return "Request Entity Too Large";
    default: return "Internal Server Error";
    }
}

static void send_head(Req *req, int status, const char *ctype, size_t len, const char *csp,
                      const char *disposition) {
    Buf h;
    buf_init(&h, req->a);
    buf_printf(&h, "HTTP/1.1 %d %s\r\n", status, reason_phrase(status));
    buf_addc(&h, "Server: vex\r\n");
    buf_printf(&h, "Content-Type: %s\r\n", ctype);
    buf_printf(&h, "Content-Length: %zu\r\n", len);
    buf_addc(&h, "X-Content-Type-Options: nosniff\r\n");
    buf_addc(&h, "Referrer-Policy: no-referrer\r\n");
    buf_addc(&h, "Cache-Control: no-store\r\n");
    buf_printf(&h, "Content-Security-Policy: %s\r\n", csp);
    if (disposition != NULL)
        buf_printf(&h, "Content-Disposition: %s\r\n", disposition);
    buf_addc(&h, "Connection: close\r\n\r\n");
    Str hs = buf_str(&h);
    send_all(req->fd, (const uint8_t *)hs.p, hs.n);
}

static void send_response(Req *req, int status, const char *ctype, const uint8_t *body,
                          size_t len, const char *csp, const char *disposition) {
    send_head(req, status, ctype, len, csp, disposition);
    if (len && body != NULL)
        send_all(req->fd, body, len);
}

/* --- JSON serialisation (compact; decodes identically to json.dumps) ---------
 * A result can be large (the hex and the text of 64 MiB of decoded bytes),
 * so it is not built in memory: it is measured for the Content-Length, then
 * written to the socket piece by piece. */

typedef struct {
    socket_t fd;
    bool measuring;                 /* count the bytes, send nothing */
    size_t total;
    size_t used;
    uint8_t piece[1 << 15];
} JsonOut;

static void out_add(JsonOut *o, const char *p, size_t n) {
    o->total += n;
    if (o->measuring)
        return;
    while (n > 0) {
        size_t room = sizeof o->piece - o->used;
        size_t take = n < room ? n : room;
        memcpy(o->piece + o->used, p, take);
        o->used += take;
        p += take;
        n -= take;
        if (o->used == sizeof o->piece) {
            send_all(o->fd, o->piece, o->used);
            o->used = 0;
        }
    }
}

static void out_text(JsonOut *o, const char *text) {
    out_add(o, text, strlen(text));
}

static void json_write_string(JsonOut *o, Str s) {
    static const char hexd[] = "0123456789abcdef";
    out_add(o, "\"", 1);
    size_t i = 0;
    while (i < s.n) {
        /* what needs no escape goes out in one piece */
        size_t run = i;
        while (run < s.n && (uint8_t)s.p[run] >= 0x20 && (uint8_t)s.p[run] < 0x7F &&
               s.p[run] != '"' && s.p[run] != '\\')
            run++;
        if (run > i) {
            out_add(o, s.p + i, run - i);
            i = run;
            continue;
        }
        uint8_t c = (uint8_t)s.p[i];
        if (c >= 0x80) {
            size_t len = c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
            if (len > s.n - i)
                len = s.n - i;
            uint32_t cp = c & (0xFFu >> (len + 1));
            for (size_t k = 1; k < len; k++)
                cp = (cp << 6) | ((uint8_t)s.p[i + k] & 0x3F);
            i += len;
            char esc[16];
            if (cp >= 0x10000) {
                cp -= 0x10000;
                snprintf(esc, sizeof esc, "\\u%04x\\u%04x", (unsigned)(0xD800 + (cp >> 10)),
                         (unsigned)(0xDC00 + (cp & 0x3FF)));
            } else {
                snprintf(esc, sizeof esc, "\\u%04x", (unsigned)cp);
            }
            out_text(o, esc);
            continue;
        }
        i++;
        switch (c) {
        case '"': out_text(o, "\\\""); break;
        case '\\': out_text(o, "\\\\"); break;
        case '\n': out_text(o, "\\n"); break;
        case '\r': out_text(o, "\\r"); break;
        case '\t': out_text(o, "\\t"); break;
        case '\b': out_text(o, "\\b"); break;
        case '\f': out_text(o, "\\f"); break;
        default: {
            char esc[8] = {'\\', 'u', '0', '0', hexd[c >> 4], hexd[c & 15], 0};
            out_text(o, esc);
        }
        }
    }
    out_add(o, "\"", 1);
}

static void json_write(JsonOut *o, const JVal *v) {
    char number[44];
    switch (v->kind) {
    case J_NULL: out_text(o, "null"); break;
    case J_BOOL: out_text(o, v->u.flag ? "true" : "false"); break;
    case J_INT: out_text(o, dec_big(number, v->u.number)); break;
    case J_FLOAT: out_text(o, format_rounded(number, v->u.real)); break;
    case J_STR: json_write_string(o, v->u.text); break;
    case J_RAW: out_add(o, v->u.text.p, v->u.text.n); break;
    case J_LIST:
        out_add(o, "[", 1);
        for (size_t i = 0; i < v->u.list.n; i++) {
            if (i)
                out_add(o, ",", 1);
            json_write(o, v->u.list.v[i]);
        }
        out_add(o, "]", 1);
        break;
    case J_DICT:
        out_add(o, "{", 1);
        for (size_t i = 0; i < v->u.dict.n; i++) {
            if (i)
                out_add(o, ",", 1);
            json_write_string(o, (Str){v->u.dict.v[i].key, v->u.dict.v[i].key_len});
            out_add(o, ":", 1);
            json_write(o, v->u.dict.v[i].value);
        }
        out_add(o, "}", 1);
        break;
    }
}

static void send_json(Req *req, int status, const JVal *value) {
    JsonOut *out = arena_alloc(req->a, sizeof *out);
    out->fd = req->fd;
    out->measuring = true;
    json_write(out, value);
    send_head(req, status, "application/json", out->total, CSP, NULL);
    out->measuring = false;
    out->total = 0;
    json_write(out, value);
    if (out->used)
        send_all(req->fd, out->piece, out->used);
}

static void send_json_error(Req *req, int status, const char *message) {
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "error", j_cstr(req->a, message));
    send_json(req, status, d);
}

/* --- reading the request ----------------------------------------------------- */

static ssize_t sock_recv(socket_t fd, void *buf, size_t n) {
#ifdef _WIN32
    return recv(fd, (char *)buf, (int)(n > (1 << 20) ? (1 << 20) : n), 0);
#else
    return recv(fd, buf, n, 0);
#endif
}

/* Read up to the end of the request headers ("\r\n\r\n"). Returns the header
 * text (NUL-terminated) and keeps any body bytes that arrived with it. NULL on
 * a malformed or oversized request head. */
static char *read_head(Req *req, size_t *head_len) {
    size_t cap = 4096, used = 0;
    uint8_t *buf = arena_alloc(req->a, cap);
    for (;;) {
        if (used == cap) {
            if (cap >= MAX_HEADER_BYTES)
                return NULL;        /* request head too large */
            size_t ncap = cap * 2;
            uint8_t *grown = arena_alloc(req->a, ncap);
            memcpy(grown, buf, used);
            buf = grown;
            cap = ncap;
        }
        ssize_t n = sock_recv(req->fd, buf + used, cap - used);
        if (n <= 0)
            return NULL;            /* EOF or timeout before the head completed */
        used += (size_t)n;
        /* find CRLFCRLF */
        for (size_t i = 3; i < used; i++) {
            if (buf[i] == '\n' && buf[i - 1] == '\r' && buf[i - 2] == '\n' && buf[i - 3] == '\r') {
                *head_len = i + 1;
                req->leftover = buf + i + 1;
                req->leftover_len = used - (i + 1);
                buf[i - 3] = '\0';  /* terminate the header block at the blank line */
                return (char *)buf;
            }
        }
        if (used > MAX_HEADER_BYTES)
            return NULL;
    }
}

/* Read the whole request body (lazily, once). Grows with the bytes actually
 * received, so a lying Content-Length never forces a huge allocation. */
static void req_body(Req *req, const uint8_t **out, size_t *out_len) {
    if (!req->body_read) {
        req->body_read = true;
        big want = req->content_length;
        if (want < 0)
            want = 0;
        size_t cap = req->leftover_len + 4096;
        uint8_t *buf = malloc(cap ? cap : 1);
        if (buf == NULL) {
            req->body = NULL;
            req->body_len = 0;
            return;
        }
        size_t have = 0;
        if (req->leftover_len) {
            size_t c = (big)req->leftover_len < want ? req->leftover_len : (size_t)want;
            memcpy(buf, req->leftover, c);
            have = c;
        }
        while ((big)have < want) {
            if (have == cap) {
                size_t ncap = cap < (1u << 20) ? cap * 2 : cap + (1u << 20);
                uint8_t *grown = realloc(buf, ncap);
                if (grown == NULL)
                    break;
                buf = grown;
                cap = ncap;
            }
            size_t room = cap - have;
            big left = want - (big)have;
            if ((big)room > left)
                room = (size_t)left;
            ssize_t n = sock_recv(req->fd, buf + have, room);
            if (n <= 0)
                break;              /* EOF or timeout: truncated body */
            have += (size_t)n;
        }
        arena_adopt(req->a, buf);
        req->body = buf;
        req->body_len = have;
    }
    *out = req->body;
    *out_len = req->body_len;
}

/* --- loading binaries for the API -------------------------------------------- */

static const char *abspath_param(Req *req, const char *name) {
    return platform_abspath(req->a, q_need(req, name));
}

static const uint8_t *read_whole_file(Req *req, const char *path, uint64_t *size) {
    FILE *f = platform_fopen(path, "rb");
    if (f == NULL)
        err_throw(req->err, ERR_OS, "cannot read %s: %s", path, strerror(errno));
    size_t cap = 1 << 16, used = 0;
    uint8_t *data = malloc(cap);
    if (data == NULL)
        die_out_of_memory();
    for (;;) {
        size_t got = fread(data + used, 1, cap - used, f);
        used += got;
        if (used < cap)
            break;
        if (cap > SIZE_MAX / 2)
            die_out_of_memory();
        cap *= 2;
        uint8_t *grown = realloc(data, cap);
        if (grown == NULL)
            die_out_of_memory();
        data = grown;
    }
    bool bad = ferror(f) != 0;
    int code = errno;
    fclose(f);
    if (bad) {
        free(data);
        err_throw(req->err, ERR_OS, "cannot read %s: %s", path, strerror(code));
    }
    arena_adopt(req->a, data);
    *size = used;
    return data;
}

/* The binary at an absolute path, with a 404 for a missing file (as os.stat
 * would raise) and whatever binary_load() throws for an unreadable or
 * non-binary one. */
static Binary *load_binary_at(Req *req, const char *ap) {
    if (!platform_exists(ap))
        api_error(req, 404, "no such file or folder: %s", ap);
    uint64_t size;
    const uint8_t *data = read_whole_file(req, ap, &size);
    return binary_load(req->a, req->err, data, size, ap);
}

/* The binary named by the query parameter `name`. */
static Binary *load_binary(Req *req, const char *name, const char **abspath_out) {
    const char *ap = abspath_param(req, name);
    if (abspath_out != NULL)
        *abspath_out = ap;
    return load_binary_at(req, ap);
}

/* --- pagination and filtering (mirrors _page / _contains) -------------------- */

static JVal *page(Req *req, JVal *rows, int default_limit) {
    big offset = q_number(req, "offset", 0);
    if (offset < 0)
        offset = 0;
    big limit = q_number(req, "limit", default_limit);
    if (limit > 20000)
        limit = 20000;
    if (limit < 1)
        limit = 1;
    size_t total = j_len(rows);
    size_t start = (big)total < offset ? total : (size_t)offset;
    size_t count = total - start;
    if ((big)count > limit)
        count = (size_t)limit;
    JVal *items = j_list(req->a);
    for (size_t i = 0; i < count; i++)
        j_push(req->a, items, (JVal *)j_at(rows, start + i));
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "total", j_int(req->a, (big)total));
    j_set(req->a, d, "items", items);
    return d;
}

/* Filter a list of row dicts by a case-insensitive substring of one field and,
 * optionally, keep only rows whose "tags" list is non-empty. Then paginate. */
static JVal *filter_and_page(Req *req, JVal *rows, const char *field, bool tagged_filter,
                             int default_limit) {
    const char *q = q_get(req, "q");
    Str needle = str_lower_ascii(req->a, str_c(q ? q : ""));
    bool tagged = false;
    if (tagged_filter) {
        const char *t = q_get(req, "tagged");
        tagged = t != NULL && (strcmp(t, "1") == 0 || strcmp(t, "true") == 0);
    }
    JVal *kept = j_list(req->a);
    for (size_t i = 0; i < j_len(rows); i++) {
        const JVal *row = j_at(rows, i);
        if (needle.n) {
            Str text = str_lower_ascii(req->a, j_text(j_get(row, field)));
            if (!str_contains(text, needle))
                continue;
        }
        if (tagged && j_len(j_get(row, "tags")) == 0)
            continue;
        j_push(req->a, kept, (JVal *)row);
    }
    return page(req, kept, default_limit);
}

/* --- percent-encoding for the start-up URL (urllib.parse.quote, safe="") ----- */

static Str url_quote(Arena *a, const char *s) {
    static const char hexd[] = "0123456789ABCDEF";
    Buf b;
    buf_init(&b, a);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == '~';
        if (unreserved) {
            buf_addch(&b, (char)c);
        } else {
            char esc[4] = {'%', hexd[c >> 4], hexd[c & 15], 0};
            buf_addc(&b, esc);
        }
    }
    return buf_str(&b);
}

/* --- file classification (server.py _file_kind) ------------------------------ */

static const char *file_kind(const char *path) {
    FILE *f = platform_fopen(path, "rb");
    if (f == NULL)
        return "unknown";
    unsigned char magic[4] = {0};
    size_t got = fread(magic, 1, 4, f);
    fclose(f);
    if (got >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return "binary";
    if (got >= 2 && magic[0] == 'M' && magic[1] == 'Z')
        return "binary";
    if (bs_is_archive(path))
        return "archive";
    return "unknown";
}

/* --- GET: analysis endpoints ------------------------------------------------- */

static void h_info(Req *req) {
    req->result = view_info(req->a, load_binary(req, "path", NULL));
}

static void h_layout(Req *req) {
    req->result = view_layout(req->a, load_binary(req, "path", NULL));
}

static void h_sections(Req *req) {
    req->result = view_sections(req->a, load_binary(req, "path", NULL));
}

static void h_segments(Req *req) {
    req->result = view_segments(req->a, load_binary(req, "path", NULL));
}

static void h_imports(Req *req) {
    req->result = view_imports(req->a, load_binary(req, "path", NULL));
}

static void h_exports(Req *req) {
    req->result = view_exports(req->a, load_binary(req, "path", NULL));
}

static void h_symbols(Req *req) {
    JVal *rows = view_symbols(req->a, load_binary(req, "path", NULL), NULL);
    req->result = filter_and_page(req, rows, "name", false, 2000);
}

static void h_strings(Req *req) {
    big minimum = q_number(req, "min", 4);
    if (minimum < 1)
        minimum = 1;
    const char *encoding = q_get(req, "encoding");
    if (encoding == NULL || encoding[0] == '\0')
        encoding = "all";
    if (strcmp(encoding, "all") != 0 && strcmp(encoding, "ascii") != 0 &&
        strcmp(encoding, "utf16") != 0)
        api_error(req, 400, "encoding must be all, ascii or utf16");
    Binary *b = load_binary(req, "path", NULL);
    JVal *rows = view_strings(req->a, b, minimum, encoding, NULL, false);
    req->result = filter_and_page(req, rows, "text", true, 500);
}

static void h_functions(Req *req) {
    Binary *b = load_binary(req, "path", NULL);
    Analysis *an = analysis_new(req->a, b);
    JVal *rows = view_functions(req->a, an, NULL);
    req->result = filter_and_page(req, rows, "name", false, 5000);
}

static void h_disasm(Req *req) {
    big count;
    bool has_count = q_number_opt(req, "count", &count);
    if (has_count) {
        if (count < 1)
            count = 1;
        if (count > 5000)
            count = 5000;
    }
    Binary *b = load_binary(req, "path", NULL);
    Analysis *an = analysis_new(req->a, b);
    const char *at = q_get(req, "at");
    if (at != NULL && at[0] == '\0')
        at = NULL;
    req->result = view_disassembly(req->a, an, at, has_count ? &count : NULL);
}

static void h_xrefs(Req *req) {
    Binary *b = load_binary(req, "path", NULL);
    Analysis *an = analysis_new(req->a, b);
    req->result = view_xrefs(req->a, an, q_get(req, "target"), q_get(req, "string"));
}

static void h_hexdump(Req *req) {
    big address, offset;
    bool has_address = q_number_opt(req, "address", &address);
    bool has_offset = q_number_opt(req, "offset", &offset);
    big length = q_number(req, "length", 512);
    if (length > 65536)
        length = 65536;
    if (length < 1)
        length = 1;
    Binary *b = load_binary(req, "path", NULL);
    req->result = view_hexdump(req->a, b, has_address ? &address : NULL,
                               has_offset ? &offset : NULL, length);
}

static void h_techniques(Req *req) {
    Binary *b = load_binary(req, "path", NULL);
    req->result = tech_view(req->a, b);
}

/* --- GET: opening files ------------------------------------------------------ */

static void h_open(Req *req) {
    const char *ap = abspath_param(req, "path");
    JVal *d = j_dict(req->a);
    if (platform_exists(ap) && !platform_is_file(ap)) {
        j_set(req->a, d, "kind", j_cstr(req->a, "folder"));
        j_set(req->a, d, "path", j_cstr(req->a, ap));
        req->result = d;
        return;
    }
    if (!platform_is_file(ap))
        api_error(req, 404, "no such file or folder: %s", ap);
    j_set(req->a, d, "kind", j_cstr(req->a, file_kind(ap)));
    j_set(req->a, d, "path", j_cstr(req->a, ap));
    j_set(req->a, d, "name", j_cstr(req->a, platform_basename(ap)));
    req->result = d;
}

static const char *home_dir(Req *req) {
    (void)req;
#ifdef _WIN32
    const char *h = getenv("USERPROFILE");
    if (h != NULL && h[0])
        return h;
    const char *drive = getenv("HOMEDRIVE"), *path = getenv("HOMEPATH");
    if (drive != NULL && path != NULL)
        return str_printf(req->a, "%s%s", drive, path).p;
    return "C:\\";
#else
    const char *h = getenv("HOME");
    if (h != NULL && h[0])
        return h;
    struct passwd *pw = getpwuid(getuid());
    return pw != NULL ? pw->pw_dir : "/";
#endif
}

/* os.path.dirname of an absolute path. */
static const char *path_dirname(Arena *a, const char *path) {
    size_t n = strlen(path);
    size_t root = 0;
#ifdef _WIN32
    if (n >= 2 && path[1] == ':')
        root = 2;
#endif
    size_t end = n;
    while (end > root && path[end - 1] != '/' && path[end - 1] != '\\')
        end--;
    /* strip trailing separators (but keep a leading root slash) */
    while (end > root + 1 && (path[end - 1] == '/' || path[end - 1] == '\\'))
        end--;
    if (end == 0 && root == 0) {
        if (n > 0 && (path[0] == '/' || path[0] == '\\'))
            return str_copy(a, path, 1).p;
        return "";
    }
    return str_copy(a, path, end).p;
}

static bool is_dir(const char *path) {
    return platform_exists(path) && !platform_is_file(path);
}

typedef struct {
    Str name;
    bool is_dir;
    bool has_size;
    uint64_t size;
    const char *kind;
} BrowseEntry;

static int compare_browse(const void *pa, const void *pb) {
    const BrowseEntry *x = pa, *y = pb;
    if (x->is_dir != y->is_dir)
        return x->is_dir ? -1 : 1;      /* folders first (not is_dir) */
    size_t n = x->name.n < y->name.n ? x->name.n : y->name.n;
    for (size_t i = 0; i < n; i++) {
        int cx = (unsigned char)x->name.p[i], cy = (unsigned char)y->name.p[i];
        if (cx >= 'A' && cx <= 'Z') cx += 32;
        if (cy >= 'A' && cy <= 'Z') cy += 32;
        if (cx != cy)
            return cx < cy ? -1 : 1;
    }
    return x->name.n < y->name.n ? -1 : x->name.n > y->name.n ? 1 : 0;
}

static void h_browse(Req *req) {
    const char *dir = q_get(req, "dir");
    if (dir == NULL || dir[0] == '\0')
        dir = home_dir(req);
    const char *ap = platform_abspath(req->a, dir);

    VEC(BrowseEntry) entries = {0};
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    const char *pattern = str_printf(req->a, "%s\\*", ap).p;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        api_error(req, 404, "no such file or folder: %s", ap);
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        BrowseEntry e;
        e.name = str_copy(req->a, fd.cFileName, strlen(fd.cFileName));
        e.is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        e.has_size = !e.is_dir;
        e.size = (uint64_t)fd.nFileSizeHigh << 32 | fd.nFileSizeLow;
        const char *full = str_printf(req->a, "%s\\%s", ap, fd.cFileName).p;
        e.kind = e.is_dir ? "folder" : file_kind(full);
        *VEC_PUSH(req->a, entries) = e;
        if (entries.n >= 5000)
            break;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(ap);
    if (d == NULL) {
        if (errno == ENOENT)
            api_error(req, 404, "no such file or folder: %s", ap);
        api_error(req, 400, "%s: %s", strerror(errno), ap);
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        const char *full = str_printf(req->a, "%s/%s", ap, de->d_name).p;
        struct stat st;
        if (stat(full, &st) != 0)
            continue;
        BrowseEntry e;
        e.name = str_copy(req->a, de->d_name, strlen(de->d_name));
        e.is_dir = S_ISDIR(st.st_mode);
        e.has_size = !e.is_dir;
        e.size = (uint64_t)st.st_size;
        e.kind = e.is_dir ? "folder" : file_kind(full);
        *VEC_PUSH(req->a, entries) = e;
        if (entries.n >= 5000)
            break;
    }
    closedir(d);
#endif
    if (entries.n > 1)
        qsort(entries.v, entries.n, sizeof *entries.v, compare_browse);

    JVal *list = j_list(req->a);
    for (size_t i = 0; i < entries.n; i++) {
        const BrowseEntry *e = &entries.v[i];
        JVal *row = j_dict(req->a);
        j_set(req->a, row, "name", j_str(req->a, e->name));
        j_set(req->a, row, "is_dir", j_bool(req->a, e->is_dir));
        j_set(req->a, row, "size", e->has_size ? j_int(req->a, (big)e->size) : j_null(req->a));
        j_set(req->a, row, "kind", j_cstr(req->a, e->kind));
        j_push(req->a, list, row);
    }
    const char *parent = path_dirname(req->a, ap);
    JVal *roots = j_list(req->a);
#ifdef _WIN32
    for (char c = 'A'; c <= 'Z'; c++) {
        char r[4] = {c, ':', '\\', 0};
        if (platform_exists(r))
            j_push(req->a, roots, j_cstr(req->a, r));
    }
#else
    j_push(req->a, roots, j_cstr(req->a, "/"));
#endif
    JVal *res = j_dict(req->a);
    j_set(req->a, res, "path", j_cstr(req->a, ap));
    j_set(req->a, res, "parent",
          strcmp(parent, ap) != 0 ? j_cstr(req->a, parent) : j_null(req->a));
    j_set(req->a, res, "home", j_cstr(req->a, home_dir(req)));
    j_set(req->a, res, "roots", roots);
    j_set(req->a, res, "entries", list);
    req->result = res;
}

/* --- GET: engine and archives ------------------------------------------------ */

static void h_engine(Req *req) {
    const char *ap = abspath_param(req, "path");
    if (!platform_exists(ap))
        api_error(req, 404, "no such file or folder: %s", ap);
    char err[256] = {0};
    JVal *d = bs_engine_view(req->a, ap, err, sizeof err);
    if (d == NULL)
        api_error(req, 400, "%s", err[0] ? err : "could not inspect this path");
    req->result = d;
}

/* The archive named by "path", with a 404 for a missing file (as server.py's
 * _archive does). The caller frees nothing; the arena owns the handle. */
static void archive_cleanup(void *p) {
    bs_archive_close(p);
}

static BsArchive *open_archive_param(Req *req, const char **abspath_out) {
    const char *ap = abspath_param(req, "path");
    if (abspath_out != NULL)
        *abspath_out = ap;
    if (!platform_is_file(ap))
        api_error(req, 404, "no such file or folder: %s", ap);
    char err[256] = {0};
    BsArchive *arch = bs_archive_open(ap, err, sizeof err);
    if (arch == NULL)
        api_error(req, 400, "%s", err[0] ? err : "this file is not a recognised asset pack");
    arena_on_release(req->a, archive_cleanup, arch);
    return arch;
}

static void h_archive_list(Req *req) {
    BsArchive *arch = open_archive_param(req, NULL);
    const char *q = q_get(req, "q");
    Str needle = str_lower_ascii(req->a, str_c(q ? q : ""));
    JVal *items = j_list(req->a);
    size_t count = bs_archive_count(arch);
    for (size_t i = 0; i < count; i++) {
        const BsArchiveEntry *e = bs_archive_entry(arch, i);
        if (needle.n) {
            Str low = str_lower_ascii(req->a, str_c(e->name));
            if (!str_contains(low, needle))
                continue;
        }
        JVal *row = j_dict(req->a);
        j_set(req->a, row, "name", j_cstr(req->a, e->name));
        j_set(req->a, row, "size", j_int(req->a, (big)e->size));
        j_set(req->a, row, "compressed", j_bool(req->a, e->compressed));
        j_set(req->a, row, "encrypted", j_bool(req->a, e->encrypted));
        j_push(req->a, items, row);
    }
    JVal *d = page(req, items, 400);
    j_set(req->a, d, "format", j_cstr(req->a, bs_archive_format(arch)));
    j_set(req->a, d, "writable", j_bool(req->a, bs_archive_writable(arch)));
    JVal *notes = j_list(req->a);
    size_t nn = bs_archive_note_count(arch);
    for (size_t i = 0; i < nn; i++)
        j_push(req->a, notes, j_cstr(req->a, bs_archive_note(arch, i)));
    j_set(req->a, d, "notes", notes);
    j_set(req->a, d, "count", j_int(req->a, (big)count));
    req->result = d;
}

static void h_archive_file(Req *req) {
    BsArchive *arch = open_archive_param(req, NULL);
    const char *name = q_need(req, "name");
    const BsArchiveEntry *entry = NULL;
    size_t count = bs_archive_count(arch);
    for (size_t i = 0; i < count; i++) {
        const BsArchiveEntry *e = bs_archive_entry(arch, i);
        if (strcmp(e->name, name) == 0) {
            entry = e;
            break;
        }
    }
    if (entry == NULL)
        api_error(req, 404, "no file named '%s' in this pack", name);
    if ((big)entry->size > MAX_PREVIEW)
        api_error(req, 413, "this file is too large to preview; extract the pack instead");
    uint8_t *data = NULL;
    size_t size = 0;
    char err[256] = {0};
    if (!bs_archive_read(arch, name, &data, &size, err, sizeof err))
        api_error(req, 400, "%s", err[0] ? err : "could not read this file");
    uint8_t *copy = arena_alloc(req->a, size ? size : 1);
    memcpy(copy, data, size);
    free(data);
    req->is_raw = true;
    req->raw_data = copy;
    req->raw_len = size;
    req->raw_ctype = "application/octet-stream";
    req->raw_filename = platform_basename(name);
}

/* --- GET: resources (not ported to C) ---------------------------------------- */

static void h_resources(Req *req) {
    (void)load_binary(req, "path", NULL);   /* validate the file like server.py */
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "items", j_list(req->a));
    j_set(req->a, d, "version", j_dict(req->a));
    req->result = d;
}

static void h_resource_unavailable(Req *req) {
    api_error(req, 400, "resources are available in the Python edition");
}

/* --- POST: upload ------------------------------------------------------------ */

/* new_upload_path: a sanitised name in a fresh per-upload folder. */
static const char *new_upload_path(Req *req, const char *name) {
    const char *base = name;
    for (const char *p = name; *p; p++)
        if (*p == '/' || *p == '\\')
            base = p + 1;
    size_t n = strlen(base);
    char *safe = arena_alloc(req->a, n + 1);
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        char c = base[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        safe[w++] = ok ? c : '_';
    }
    safe[w] = '\0';
    size_t lead = 0;
    while (safe[lead] == '.')
        lead++;
    const char *stripped = safe[lead] != '\0' ? safe + lead : "upload.bin";
    req->srv->uploads++;
#ifdef _WIN32
    const char *sep = "\\";
#else
    const char *sep = "/";
#endif
    const char *folder = str_printf(req->a, "%s%supload%u", req->srv->tempdir, sep,
                                    req->srv->uploads).p;
#ifdef _WIN32
    _mkdir(folder);
#else
    mkdir(folder, 0700);
#endif
    return str_printf(req->a, "%s%s%s", folder, sep, stripped).p;
}

static void h_upload(Req *req) {
    const char *path = new_upload_path(req, q_need(req, "name"));
    const uint8_t *body;
    size_t body_len;
    req_body(req, &body, &body_len);
    FILE *f = platform_fopen(path, "wb");
    if (f == NULL)
        err_throw(req->err, ERR_OS, "cannot write %s: %s", path, strerror(errno));
    bool ok = body_len == 0 || fwrite(body, 1, body_len, f) == body_len;
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
        err_throw(req->err, ERR_OS, "cannot write %s", path);
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "path", j_cstr(req->a, path));
    j_set(req->a, d, "name", j_cstr(req->a, platform_basename(path)));
    req->result = d;
}

/* --- POST: archive extract/replace ------------------------------------------- */

/* _output_path: an absolute path that is not a folder and whose parent exists. */
static const char *output_path(Req *req) {
    const char *out = abspath_param(req, "out");
    if (is_dir(out))
        api_error(req, 400, "%s is a folder; give a file name to save to", out);
    const char *parent = path_dirname(req->a, out);
    if (!is_dir(parent))
        api_error(req, 400, "the folder %s does not exist", parent);
    return out;
}

static void h_archive_extract(Req *req) {
    const char *src;
    BsArchive *arch = open_archive_param(req, &src);
    const char *dest = platform_abspath(req->a, q_need(req, "dest"));
    const char *name = q_get(req, "name");
    const char *names[1];
    size_t n_names = 0;
    if (name != NULL && name[0]) {
        names[0] = name;
        n_names = 1;
    }
    size_t written = 0;
    char err[256] = {0};
    if (!bs_archive_extract(arch, dest, n_names ? names : NULL, n_names, &written, err,
                            sizeof err))
        api_error(req, 400, "%s", err[0] ? err : "could not extract this pack");
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "dest", j_cstr(req->a, dest));
    j_set(req->a, d, "count", j_int(req->a, (big)written));
    req->result = d;
}

static void h_archive_replace(Req *req) {
    const char *src;
    BsArchive *arch = open_archive_param(req, &src);
    const char *name = q_need(req, "name");
    const char *out = output_path(req);
    if (strcmp(out, src) == 0)
        api_error(req, 400,
                  "save the modified pack under a new name; the original is left untouched");
    const uint8_t *body;
    size_t body_len;
    req_body(req, &body, &body_len);
    bool add = true;
    size_t count = bs_archive_count(arch);
    for (size_t i = 0; i < count; i++)
        if (strcmp(bs_archive_entry(arch, i)->name, name) == 0) {
            add = false;
            break;
        }
    char err[256] = {0};
    if (!bs_archive_repack(arch, out, name, body, body_len, add, err, sizeof err))
        api_error(req, 400, "%s", err[0] ? err : "could not rebuild this pack");
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "out", j_cstr(req->a, out));
    j_set(req->a, d, "name", j_cstr(req->a, name));
    j_set(req->a, d, "size", j_int(req->a, (big)body_len));
    req->result = d;
}

/* --- split: preview (GET) and perform (POST) ---------------------------------- */

static void h_split_preview(Req *req) {
    const Binary *b = load_binary(req, "path", NULL);
    req->result = split_view(req->a, split_plan(req->a, b), NULL);
}

static void h_split(Req *req) {
    /* The folder as it was given: server.py hands it on unchanged. */
    const char *dest = q_need(req, "dest");
    const Binary *b = load_binary(req, "path", NULL);
    split_check_folder(req->a, req->err, dest);
    const Split *split = split_plan(req->a, b);
    split_write(req->a, req->err, split, dest);
    req->result = split_view(req->a, split, platform_abspath(req->a, dest));
}

/* --- decode & cipher workbench ------------------------------------------------ */

/* _json_body(): the request body as a JSON object; anything else is a 400. */
static const JVal *json_body(Req *req) {
    static const uint8_t empty[] = "{}";
    const uint8_t *body;
    size_t length;
    req_body(req, &body, &length);
    if (length == 0) {
        body = empty;
        length = 2;
    }
    const JVal *parsed = j_parse(req->a, body, length);
    if (parsed == NULL)
        api_error(req, 400, "request body must be JSON");
    if (parsed->kind != J_DICT)
        api_error(req, 400, "request body must be a JSON object");
    return parsed;
}

/* x or None: the value unless Python calls it false. */
static const JVal *if_true(const JVal *value) {
    return j_truthy(value) ? value : NULL;
}

/* _decode_source(): where the bytes come from. A `file` source is the open
 * program, read the way the other routes read it. */
static void decode_source(Req *req, const JVal *source, DecodeSource *out) {
    memset(out, 0, sizeof *out);
    if (source == NULL || source->kind != J_DICT)
        api_error(req, 400, "source must be an object");
    Str kind = j_text(j_get(source, "kind"));
    if (str_eq_c(kind, "text") || str_eq_c(kind, "hex") || str_eq_c(kind, "base64")) {
        out->kind = str_eq_c(kind, "text") ? DECODE_TEXT
                  : str_eq_c(kind, "hex") ? DECODE_HEX : DECODE_BASE64;
        out->value = if_true(j_get(source, "value"));
        return;
    }
    if (!str_eq_c(kind, "file"))
        api_error(req, 400, "source kind must be text, hex, base64 or file");
    const JVal *path = if_true(j_get(source, "path"));
    /* A path that is not text (or holds a NUL) names no file. */
    if (path == NULL || path->kind != J_STR || strlen(path->u.text.p) != path->u.text.n)
        api_error(req, 400, "a file source needs a path");
    const Binary *b = load_binary_at(req, platform_abspath(req->a, path->u.text.p));
    out->kind = DECODE_FILE;
    out->file = b->data;
    out->file_size = (size_t)b->size;
    out->offset = if_true(j_get(source, "offset"));
    out->length = j_get(source, "length");
}

static void h_decode_ops(Req *req) {
    req->result = decode_catalogue(req->a);
}

static void h_decode(Req *req) {
    const JVal *body = json_body(req);
    DecodeSource source;
    decode_source(req, j_get(body, "source"), &source);
    /* The steps: every object in the list, with str(op) and its params. */
    VEC(DecodeStep) steps = {0};
    const JVal *recipe = if_true(j_get(body, "recipe"));
    if (recipe != NULL && recipe->kind != J_LIST && recipe->kind != J_DICT &&
        recipe->kind != J_STR)
        api_error(req, 400, "recipe must be a list of steps");
    for (size_t i = 0; i < j_len(recipe); i++) {
        const JVal *item = j_at(recipe, i);
        if (item->kind != J_DICT)
            continue;
        DecodeStep step = {decode_pystr(req->a, j_get(item, "op")),
                           if_true(j_get(item, "params"))};
        *VEC_PUSH(req->a, steps) = step;
    }
    DecodeResult result;
    decode_execute(req->a, &source, steps.v, steps.n, &result);
    req->result = decode_result_view(req->a, &result);
}

static void h_decode_solve(Req *req) {
    const JVal *body = json_body(req);
    DecodeSource source;
    decode_source(req, j_get(body, "source"), &source);
    req->result = decode_solve(req->a, decode_pystr(req->a, j_get(body, "name")), &source);
}

/* --- POST: patching ---------------------------------------------------------- */
/* A faithful re-implementation of the subset of patch.py the web API uses, so
 * the bytes written and the JSON returned match the Python server exactly. */

typedef struct {
    uint64_t offset;
    OptAddr vaddr;
    const uint8_t *old_bytes, *new_bytes;
    size_t size;
} ServerPatch;

static Str hex_spaced(Arena *a, const uint8_t *bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    char *text = arena_array(a, size ? size : 1, 3);
    size_t n = 0;
    for (size_t i = 0; i < size; i++) {
        if (i)
            text[n++] = ' ';
        text[n++] = digits[bytes[i] >> 4];
        text[n++] = digits[bytes[i] & 15];
    }
    Str s = {text, n};
    return s;
}

static JVal *patch_view(Req *req, const char *out, const ServerPatch *p) {
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "out", j_cstr(req->a, out));
    j_set(req->a, d, "offset", j_int(req->a, (big)p->offset));
    j_set(req->a, d, "address", j_opt_hex(req->a, p->vaddr.has, p->vaddr.v));
    j_set(req->a, d, "old", j_str(req->a, hex_spaced(req->a, p->old_bytes, p->size)));
    j_set(req->a, d, "new", j_str(req->a, hex_spaced(req->a, p->new_bytes, p->size)));
    return d;
}

typedef struct {
    Req *req;
    const uint8_t *data;
    uint64_t size;
    const char *path;
    Binary *binary;
} LoadAttempt;

static void try_load_job(void *arg) {
    LoadAttempt *j = arg;
    j->binary = binary_load(j->req->a, j->req->err, j->data, j->size, j->path);
}

/* load_bytes() that returns NULL for a non-binary file instead of throwing. */
static Binary *try_load(Req *req, const uint8_t *data, uint64_t size, const char *path) {
    LoadAttempt job = {req, data, size, path, NULL};
    return err_protect(req->err, try_load_job, &job) ? job.binary : NULL;
}

/* _locate for a virtual address: load the binary, mapping UnknownFormat to the
 * "patch by offset instead" message exactly as patch.py does. */
static Binary *load_for_vaddr(Req *req, const uint8_t *data, uint64_t size, const char *path) {
    LoadAttempt job = {req, data, size, path, NULL};
    if (err_protect(req->err, try_load_job, &job))
        return job.binary;
    if (req->err->kind == ERR_UNKNOWN_FORMAT)
        err_throw(req->err, ERR_LOCATION,
                  "virtual addresses need an ELF or PE file; patch this file by file offset "
                  "instead");
    err_raise(req->err);            /* a genuine parse error: propagate it */
}

/* atomic save (patch.py save_copy + _back_up). */
static int server_back_up(Req *req, const char *src, const uint8_t *original, size_t size) {
    Str backup = str_printf(req->a, "%s.bak", src);
    if (platform_exists(backup.p))
        return 0;
    char *tmp = platform_write_temp(req->a, backup.p, original, size, src);
    if (tmp == NULL)
        return errno;
    bool ok = platform_move_new(tmp, backup.p);
    int code = errno;
    platform_remove(tmp);
    return ok || platform_exists(backup.p) ? 0 : code;
}

static void server_save_copy(Req *req, const char *src, const char *dst, const uint8_t *data,
                             const uint8_t *original, size_t size) {
    bool in_place = platform_same_file(src, dst);
    if (in_place)
        dst = platform_realpath(req->a, dst);
    char *tmp = platform_write_temp(req->a, dst, data, size, src);
    if (tmp == NULL)
        err_throw(req->err, ERR_OS, "cannot write %s: %s", dst, strerror(errno));
    int code = in_place ? server_back_up(req, src, original, size) : 0;
    if (code == 0 && !platform_replace(tmp, dst))
        code = errno;
    if (code != 0) {
        platform_remove(tmp);
        err_throw(req->err, ERR_OS, "cannot write %s: %s", dst, strerror(code));
    }
}

/* apply_patch(): validate the location, write the modified image, return the
 * result. `is_offset` picks offset vs virtual address. */
static ServerPatch apply_patch(Req *req, const char *src, const char *out, const uint8_t *orig,
                               uint64_t osize, const uint8_t *data, size_t dsize, bool is_offset,
                               big where) {
    char a[40], b[40], c[44], d[44];
    ServerPatch r;
    memset(&r, 0, sizeof r);
    if (dsize == 0)
        err_throw(req->err, ERR_LOCATION, "patch data is empty: there is nothing to write");
    if (!is_offset) {
        Binary *bin = load_for_vaddr(req, orig, osize, src);
        uint64_t mapped, available;
        if (!binary_vaddr_to_offset(bin, where, &mapped))
            err_throw(req->err, ERR_LOCATION,
                      "address %s is not backed by bytes in the file (unmapped, or "
                      "zero-initialised memory such as .bss)", hex_big(a, where));
        binary_read(bin, where, (big)dsize, &available);
        if ((big)available < (big)dsize)
            err_throw(req->err, ERR_LOCATION,
                      "only %s of the %s bytes at %s are backed by the file; the patch would "
                      "run past the end of its section or segment",
                      dec_big(c, (big)available), dec_big(d, (big)dsize), hex_big(a, where));
        r.offset = mapped;
        r.vaddr.has = true;
        r.vaddr.v = where;
    } else {
        if (where < 0 || where + (big)dsize > (big)osize)
            err_throw(req->err, ERR_LOCATION,
                      "%s bytes at file offset %s do not lie inside the file (%s bytes); a "
                      "patch never changes the file size",
                      dec_big(c, (big)dsize), hex_big(a, where), hex_big(b, (big)osize));
        r.offset = (uint64_t)where;
        Binary *bin = try_load(req, orig, osize, src);
        if (bin != NULL)
            r.vaddr.has = binary_offset_to_vaddr(bin, r.offset, &r.vaddr.v);
    }
    r.old_bytes = orig + r.offset;
    r.new_bytes = data;
    r.size = dsize;
    uint8_t *image = malloc(osize ? (size_t)osize : 1);
    if (image == NULL)
        die_out_of_memory();
    arena_adopt(req->a, image);
    memcpy(image, orig, (size_t)osize);
    memcpy(image + r.offset, data, dsize);
    server_save_copy(req, src, out, image, orig, (size_t)osize);
    return r;
}

/* _patch_target(): offset, or an address (number or resolved name). */
static void patch_target(Req *req, const char *src, const uint8_t *orig, uint64_t osize,
                         bool *is_offset, big *where) {
    big offset;
    if (q_number_opt(req, "offset", &offset)) {
        *is_offset = true;
        *where = offset;
        return;
    }
    const char *text = q_need(req, "address");
    if (parse_int(text, true, where)) {
        *is_offset = false;
        return;
    }
    Binary *bin = binary_load(req->a, req->err, orig, osize, src);   /* may throw 400 */
    Analysis *an = analysis_new(req->a, bin);
    AddressList found = {0};
    analysis_resolve(an, text, &found);
    *is_offset = false;
    *where = found.v[0];
}

/* bytes.fromhex after removing whitespace, commas and "0x" (server.py). */
static uint8_t *parse_patch_hex(Req *req, const char *text, size_t *size) {
    size_t length = strlen(text);
    char *clean = arena_alloc(req->a, length + 1);
    size_t n = 0;
    for (size_t i = 0; i < length; i++) {
        if (text[i] == '0' && text[i + 1] == 'x') {
            i++;
            continue;
        }
        char c = text[i];
        if (c == ',' || c == ' ' || (c >= '\t' && c <= '\r'))
            continue;
        clean[n++] = c;
    }
    if (n % 2 != 0)
        api_error(req, 400, "bytes must be written in hex, for example: 90 90 eb 05");
    uint8_t *out = arena_alloc(req->a, n / 2 + 1);
    size_t count = 0;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_value((unsigned char)clean[i]);
        int lo = hex_value((unsigned char)clean[i + 1]);
        if (hi < 0 || lo < 0)
            api_error(req, 400, "bytes must be written in hex, for example: 90 90 eb 05");
        out[count++] = (uint8_t)(hi << 4 | lo);
    }
    *size = count;
    return out;
}

static void h_patch_bytes(Req *req) {
    const char *path = abspath_param(req, "path");
    size_t dsize;
    uint8_t *data = parse_patch_hex(req, q_need(req, "hex"), &dsize);
    if (dsize == 0)
        api_error(req, 400, "no bytes given");
    const char *out = output_path(req);
    if (!platform_exists(path))
        api_error(req, 404, "no such file or folder: %s", path);
    uint64_t osize;
    const uint8_t *orig = read_whole_file(req, path, &osize);
    bool is_offset;
    big where;
    patch_target(req, path, orig, osize, &is_offset, &where);
    ServerPatch r = apply_patch(req, path, out, orig, osize, data, dsize, is_offset, where);
    req->result = patch_view(req, out, &r);
}

static bool arm_code_is_little_endian(const Binary *b) {
    if (strcmp(b->endian, "big") != 0)
        return true;
    if (strcmp(b->format, "ELF") == 0 && b->size >= 40 && b->data[4] == 1)
        return (b->data[37] & 0x80) != 0;
    return false;
}

/* nop_bytes(): fill of `length` no-op bytes for the binary's CPU. */
static uint8_t *nop_fill(Req *req, const Binary *b, big length, size_t *out_size) {
    char text[44];
    uint8_t unit[4];
    size_t n;
    if (length < 0)
        err_throw(req->err, ERR_LOCATION, "cannot produce %s bytes of no-ops",
                  dec_big(text, length));
    if (str_eq_c(b->arch, "x86") || str_eq_c(b->arch, "x86_64")) {
        unit[0] = 0x90;
        n = 1;
    } else if (str_eq_c(b->arch, "aarch64")) {
        memcpy(unit, "\x1f\x20\x03\xd5", 4);
        n = 4;
    } else if (str_eq_c(b->arch, "arm")) {
        if (arm_code_is_little_endian(b))
            memcpy(unit, "\x00\xf0\x20\xe3", 4);
        else
            memcpy(unit, "\xe3\x20\xf0\x00", 4);
        n = 4;
    } else {
        err_throw(req->err, ERR_UNSUPPORTED, "no no-op encoding known for architecture '%s'",
                  b->arch.n ? b->arch.p : "unknown");
    }
    if (length % (big)n != 0)
        err_throw(req->err, ERR_LOCATION,
                  "%s instructions are %zu bytes long; %s bytes would leave a partial "
                  "instruction", b->arch.p, n, dec_big(text, length));
    uint8_t *fill = arena_alloc(req->a, (size_t)length ? (size_t)length : 1);
    for (size_t i = 0; i < (size_t)length; i++)
        fill[i] = unit[i % n];
    *out_size = (size_t)length;
    return fill;
}

static void h_patch_nop(Req *req) {
    const char *path = abspath_param(req, "path");
    big length = q_number(req, "length", 0);
    if (length < 1 || length > (1 << 20))
        api_error(req, 400, "the number of bytes must be at least 1");
    const char *out = output_path(req);
    Binary *bin = load_binary(req, "path", NULL);
    size_t dsize;
    uint8_t *data = nop_fill(req, bin, length, &dsize);
    bool is_offset;
    big where;
    patch_target(req, path, bin->data, bin->size, &is_offset, &where);
    ServerPatch r = apply_patch(req, path, out, bin->data, bin->size, data, dsize, is_offset,
                                where);
    req->result = patch_view(req, out, &r);
}

/* encode_text(): ASCII or UTF-16LE, with Python's UnicodeEncodeError message. */
static uint8_t *encode_text(Req *req, const char *text, bool utf16, size_t *size) {
    size_t length = strlen(text);
    uint8_t *out = arena_alloc(req->a, length * 2 + 2);
    size_t n = 0, index = 0;
    for (size_t at = 0; at < length; index++) {
        uint32_t cp = utf8_next(text, length, &at);
        bool surrogate = cp >= 0xD800 && cp <= 0xDFFF;
        if (utf16 ? surrogate : cp >= 0x80) {
            size_t last = index;
            uint32_t bad = cp;
            while (at < length) {
                size_t peek = at;
                uint32_t next = utf8_next(text, length, &peek);
                if (utf16 ? !(next >= 0xD800 && next <= 0xDFFF) : next < 0x80)
                    break;
                at = peek;
                last++;
            }
            Buf why;
            buf_init(&why, req->a);
            buf_printf(&why, "'%s' codec can't encode ", utf16 ? "utf-16-le" : "ascii");
            if (last == index) {
                buf_addc(&why, "character '");
                buf_add_escaped(&why, bad);
                buf_printf(&why, "' in position %zu", index);
            } else {
                buf_printf(&why, "characters in position %zu-%zu", index, last);
            }
            buf_addc(&why, utf16 ? ": surrogates not allowed" : ": ordinal not in range(128)");
            err_throw(req->err, ERR_LOCATION, "text cannot be written as %s: %s",
                      utf16 ? "utf16" : "ascii", buf_str(&why).p);
        }
        if (!utf16) {
            out[n++] = (uint8_t)cp;
        } else if (cp < 0x10000) {
            out[n++] = (uint8_t)cp;
            out[n++] = (uint8_t)(cp >> 8);
        } else {
            uint32_t v = cp - 0x10000, high = 0xD800 + (v >> 10), low = 0xDC00 + (v & 0x3FF);
            out[n++] = (uint8_t)high;
            out[n++] = (uint8_t)(high >> 8);
            out[n++] = (uint8_t)low;
            out[n++] = (uint8_t)(low >> 8);
        }
    }
    *size = n;
    return out;
}

static void h_patch_string(Req *req) {
    const char *path = abspath_param(req, "path");
    const char *out = output_path(req);
    const char *old_text = q_need(req, "old");
    const char *new_text = q_get(req, "new");
    if (new_text == NULL)
        new_text = "";
    const char *encoding = q_get(req, "encoding");
    if (encoding == NULL || encoding[0] == '\0')
        encoding = "ascii";
    if (strcmp(encoding, "ascii") != 0 && strcmp(encoding, "utf16") != 0)
        err_throw(req->err, ERR_UNSUPPORTED,
                  "unknown string encoding '%s' (use 'ascii' or 'utf16')", encoding);
    bool utf16 = strcmp(encoding, "utf16") == 0;
    size_t old_size, new_size;
    const uint8_t *old_bytes = encode_text(req, old_text, utf16, &old_size);
    const uint8_t *new_encoded = encode_text(req, new_text, utf16, &new_size);
    if (old_size == 0)
        err_throw(req->err, ERR_LOCATION, "the text to replace is empty");
    if (new_size > old_size)
        err_throw(req->err, ERR_LOCATION,
                  "the new text is longer than the old one (%zu > %zu bytes): strings can only "
                  "be replaced in place by equal or shorter text, because nothing after them "
                  "may move", new_size, old_size);
    uint8_t *new_bytes = arena_alloc(req->a, old_size);     /* zero-padded */
    memcpy(new_bytes, new_encoded, new_size);

    if (!platform_exists(path))
        api_error(req, 404, "no such file or folder: %s", path);
    uint64_t size;
    const uint8_t *original = read_whole_file(req, path, &size);
    uint8_t *image = malloc(size ? (size_t)size : 1);
    if (image == NULL)
        die_out_of_memory();
    arena_adopt(req->a, image);
    memcpy(image, original, (size_t)size);

    VEC(uint64_t) offsets = {0};
    for (uint64_t at = 0; old_size <= size && at + old_size <= size;) {
        const uint8_t *hit = memchr(original + at, old_bytes[0],
                                    (size_t)(size - at - old_size) + 1);
        if (hit == NULL)
            break;
        at = (uint64_t)(hit - original);
        if (memcmp(hit, old_bytes, old_size) != 0) {
            at++;
            continue;
        }
        *VEC_PUSH(req->a, offsets) = at;
        memcpy(image + at, new_bytes, old_size);
        at += old_size;
    }
    if (offsets.n == 0) {
        Str repr = py_repr(req->a, old_text);
        err_throw(req->err, ERR_LOCATION, "the %s text %s does not occur in the file",
                  utf16 ? "utf16" : "ascii", repr.p);
    }
    Binary *binary = try_load(req, original, size, path);
    JVal *patches = j_list(req->a);
    for (size_t i = 0; i < offsets.n; i++) {
        ServerPatch r;
        memset(&r, 0, sizeof r);
        r.offset = offsets.v[i];
        if (binary != NULL)
            r.vaddr.has = binary_offset_to_vaddr(binary, r.offset, &r.vaddr.v);
        r.old_bytes = old_bytes;
        r.new_bytes = new_bytes;
        r.size = old_size;
        j_push(req->a, patches, patch_view(req, out, &r));
    }
    server_save_copy(req, path, out, image, original, (size_t)size);
    JVal *d = j_dict(req->a);
    j_set(req->a, d, "out", j_cstr(req->a, out));
    j_set(req->a, d, "patches", patches);
    req->result = d;
}

/* --- route table and dispatch ------------------------------------------------ */

typedef struct {
    const char *method;
    const char *name;
    ApiHandler fn;
} Route;

static const Route ROUTES[] = {
    {"GET", "info", h_info}, {"GET", "layout", h_layout}, {"GET", "sections", h_sections},
    {"GET", "segments", h_segments}, {"GET", "imports", h_imports}, {"GET", "exports", h_exports},
    {"GET", "symbols", h_symbols}, {"GET", "strings", h_strings}, {"GET", "functions", h_functions},
    {"GET", "disasm", h_disasm}, {"GET", "xrefs", h_xrefs}, {"GET", "hexdump", h_hexdump}, {"GET", "techniques", h_techniques},
    {"GET", "open", h_open}, {"GET", "browse", h_browse}, {"GET", "engine", h_engine},
    {"GET", "archive/list", h_archive_list}, {"GET", "archive/file", h_archive_file},
    {"GET", "resources", h_resources}, {"GET", "resource/data", h_resource_unavailable},
    {"GET", "resource/icon", h_resource_unavailable},
    {"GET", "split", h_split_preview}, {"POST", "split", h_split},
    {"GET", "decode/ops", h_decode_ops}, {"POST", "decode", h_decode},
    {"POST", "decode/solve", h_decode_solve},
    {"POST", "upload", h_upload}, {"POST", "archive/extract", h_archive_extract},
    {"POST", "archive/replace", h_archive_replace},
    {"POST", "resource/replace", h_resource_unavailable},
    {"POST", "patch/bytes", h_patch_bytes}, {"POST", "patch/nop", h_patch_nop},
    {"POST", "patch/string", h_patch_string},
};

static void run_handler(void *arg) {
    Req *req = arg;
    req->handler(req);
}

static void api_dispatch(Req *req, const char *name) {
    if (!const_time_eq(req->token_hdr, req->srv->token)) {
        send_json_error(req, 403, "missing or wrong session token");
        return;
    }
    ApiHandler handler = NULL;
    for (size_t i = 0; i < ARRAY_LEN(ROUTES); i++)
        if (strcmp(ROUTES[i].method, req->method) == 0 && strcmp(ROUTES[i].name, name) == 0) {
            handler = ROUTES[i].fn;
            break;
        }
    if (handler == NULL) {
        char msg[256];
        snprintf(msg, sizeof msg, "unknown API endpoint: %s", name);
        send_json_error(req, 404, msg);
        return;
    }
    if (req->content_length > MAX_UPLOAD) {
        send_json_error(req, 413, "upload too large");
        return;
    }
    req->handler = handler;
    req->have_status = false;
    req->is_raw = false;
    req->result = NULL;
    if (err_protect(req->err, run_handler, req)) {
        if (req->is_raw) {
            const char *disposition = NULL;
            if (req->raw_filename != NULL) {
                char safe[256];
                size_t w = 0;
                for (const char *p = req->raw_filename; *p && w + 1 < sizeof safe; p++) {
                    char c = *p;
                    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                    safe[w++] = ok ? c : '_';
                }
                safe[w] = '\0';
                disposition = str_printf(req->a, "attachment; filename=\"%s\"", safe).p;
            }
            send_response(req, 200, req->raw_ctype, req->raw_data, req->raw_len, RAW_CSP,
                          disposition);
        } else {
            send_json(req, 200, req->result);
        }
    } else {
        int status = req->have_status ? req->status : 400;
        send_json_error(req, status, req->err->msg ? req->err->msg : "internal error");
    }
}

/* --- static files ------------------------------------------------------------ */

static const WebAsset *find_asset(const char *rel) {
    for (size_t i = 0; i < WEB_ASSET_COUNT; i++)
        if (strcmp(WEB_ASSETS[i].path, rel) == 0)
            return &WEB_ASSETS[i];
    return NULL;
}

static void static_serve(Req *req, const char *route) {
    const char *rel;
    if (strcmp(route, "/") == 0 || strcmp(route, "/index.html") == 0)
        rel = "index.html";
    else if (strncmp(route, "/static/", 8) == 0)
        rel = route + 8;
    else {
        send_json_error(req, 404, "not found");
        return;
    }
    const WebAsset *asset = find_asset(rel);
    if (asset == NULL) {
        send_json_error(req, 404, "not found");
        return;
    }
    send_response(req, 200, asset->content_type, asset->data, asset->size, CSP, NULL);
}

/* --- request parsing and the connection ------------------------------------- */

/* ASCII case-insensitive equality (for header names). */
static bool ci_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        int ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb)
            return false;
    }
    return *a == *b;
}

static char *trim_value(char *s) {
    while (*s == ' ' || *s == '\t')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        s[--n] = '\0';
    return s;
}

static void handle_request(Req *req, char *head) {
    /* Request line: METHOD SP TARGET SP VERSION */
    char *line_end = strstr(head, "\r\n");
    char *first_line = head;
    char *headers = NULL;
    if (line_end != NULL) {
        *line_end = '\0';
        headers = line_end + 2;
    }
    char *sp1 = strchr(first_line, ' ');
    if (sp1 == NULL) {
        send_json_error(req, 400, "bad request");
        return;
    }
    *sp1 = '\0';
    char *method = first_line;
    char *target = sp1 + 1;
    char *sp2 = strchr(target, ' ');
    if (sp2 != NULL)
        *sp2 = '\0';
    req->method = method;

    /* Parse headers we care about. */
    req->host = NULL;
    req->token_hdr = NULL;
    req->content_length = 0;
    for (char *p = headers; p != NULL && *p;) {
        char *eol = strstr(p, "\r\n");
        if (eol != NULL)
            *eol = '\0';
        char *colon = strchr(p, ':');
        if (colon != NULL) {
            *colon = '\0';
            char *value = trim_value(colon + 1);
            if (ci_eq(p, "Host"))
                req->host = value;
            else if (ci_eq(p, "X-Vex-Token"))
                req->token_hdr = value;
            else if (ci_eq(p, "Content-Length")) {
                big cl;
                if (parse_int(value, false, &cl) && cl >= 0)
                    req->content_length = cl;
                else {
                    send_json_error(req, 400, "bad request");
                    return;
                }
            }
        }
        p = eol != NULL ? eol + 2 : NULL;
    }

    /* Host check (DNS-rebinding defence). */
    char host_ip[64], host_local[64];
    snprintf(host_ip, sizeof host_ip, "127.0.0.1:%u", req->srv->port);
    snprintf(host_local, sizeof host_local, "localhost:%u", req->srv->port);
    if (req->host == NULL ||
        (strcmp(req->host, host_ip) != 0 && strcmp(req->host, host_local) != 0)) {
        send_json_error(req, 403, "request refused: unexpected Host header");
        return;
    }

    /* Split target into path and query, then percent-decode the path. */
    char *qmark = strchr(target, '?');
    const char *query = "";
    size_t query_len = 0;
    if (qmark != NULL) {
        *qmark = '\0';
        query = qmark + 1;
        query_len = strlen(query);
    }
    const char *route = percent_decode(req->a, target, strlen(target), false);
    parse_query(req, query, query_len);

    if (strncmp(route, "/api/", 5) == 0)
        api_dispatch(req, route + 5);
    else if (strcmp(req->method, "GET") == 0)
        static_serve(req, route);
    else
        send_json_error(req, 404, "not found");
}

static void handle_connection(Server *srv, socket_t fd) {
    Arena ra = {0};
    Req req;
    memset(&req, 0, sizeof req);
    req.a = &ra;
    req.err = &srv->err;
    req.srv = srv;
    req.fd = fd;
    size_t head_len;
    char *head = read_head(&req, &head_len);
    if (head != NULL)
        handle_request(&req, head);
    arena_release(&ra);
}

/* --- opening a browser ------------------------------------------------------- */

static void open_browser(const char *url) {
#ifdef _WIN32
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
#else
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        pid_t grandchild = fork();
        if (grandchild == 0) {
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, 0);
                dup2(devnull, 1);
                dup2(devnull, 2);
                if (devnull > 2)
                    close(devnull);
            }
            execlp("xdg-open", "xdg-open", url, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);       /* reap the intermediate child at once */
    }
#endif
}

/* --- temp directory for the session ----------------------------------------- */

static const char *make_tempdir(Arena *a) {
#ifdef _WIN32
    char base[MAX_PATH];
    DWORD n = GetTempPathA(sizeof base, base);
    if (n == 0 || n >= sizeof base)
        strcpy(base, ".\\");
    for (int attempt = 0; attempt < 100; attempt++) {
        uint8_t raw[8];
        if (!os_random(raw, sizeof raw))
            return NULL;
        char suffix[17];
        static const char hexd[] = "0123456789abcdef";
        for (int i = 0; i < 8; i++) {
            suffix[i * 2] = hexd[raw[i] >> 4];
            suffix[i * 2 + 1] = hexd[raw[i] & 15];
        }
        suffix[16] = '\0';
        const char *dir = str_printf(a, "%svex-%s", base, suffix).p;
        if (_mkdir(dir) == 0)
            return dir;
    }
    return NULL;
#else
    const char *base = getenv("TMPDIR");
    if (base == NULL || base[0] == '\0')
        base = "/tmp";
    size_t n = strlen(base);
    const char *sep = n > 0 && base[n - 1] == '/' ? "" : "/";
    char *tmpl = (char *)str_printf(a, "%s%svex-XXXXXX", base, sep).p;
    return mkdtemp(tmpl);
#endif
}

/* --- graceful shutdown ------------------------------------------------------- */

static volatile sig_atomic_t g_stop;
static socket_t g_listen = BAD_SOCKET;

static void on_interrupt(int sig) {
    (void)sig;
    g_stop = 1;
#ifdef _WIN32
    /* The handler runs on another thread, so close the socket to wake accept(). */
    if (g_listen != BAD_SOCKET) {
        closesocket(g_listen);
        g_listen = BAD_SOCKET;
    }
#endif
}

static void install_interrupt_handler(void) {
#ifdef _WIN32
    signal(SIGINT, on_interrupt);
#else
    /* No SA_RESTART: a signal makes the blocked accept() return with EINTR. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_interrupt;
    sigaction(SIGINT, &sa, NULL);
#endif
}

/* --- the gui command --------------------------------------------------------- */

void cmd_gui(Session *s) {
    big port = 0;
    cli_int_option(s, "port", "--port", false, &port);
    if (port < 0 || port > 65535)
        cli_usage_error(s, "argument --port: must be between 0 and 65535");
    bool no_browser = cli_flag(s, "no-browser");
    const char *path = s->npositional > 0 ? s->positional[0] : NULL;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        err_throw(s->err, ERR_OTHER, "could not start Windows networking");
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == BAD_SOCKET)
        err_throw(s->err, ERR_OTHER, "could not create a socket");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      /* 127.0.0.1 only */
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        closesock(fd);
        err_throw(s->err, ERR_OS, "could not bind to the port: %s", strerror(errno));
    }
    if (listen(fd, 16) != 0) {
        closesock(fd);
        err_throw(s->err, ERR_OS, "could not listen on the socket: %s", strerror(errno));
    }
    struct sockaddr_in bound;
    socklen_t blen = sizeof bound;
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) != 0) {
        closesock(fd);
        err_throw(s->err, ERR_OS, "could not read the server address: %s", strerror(errno));
    }

    Server srv;
    memset(&srv, 0, sizeof srv);
    srv.listen_fd = fd;
    srv.port = ntohs(bound.sin_port);
    if (!make_token(srv.token, sizeof srv.token)) {
        closesock(fd);
        err_throw(s->err, ERR_OTHER, "could not generate a session token from the system RNG");
    }
    srv.tempdir = make_tempdir(s->a);
    if (srv.tempdir == NULL) {
        closesock(fd);
        err_throw(s->err, ERR_OS, "could not create a temporary folder: %s", strerror(errno));
    }

    /* The token travels in the URL fragment, which browsers never send. */
    Buf url;
    buf_init(&url, s->a);
    buf_printf(&url, "http://127.0.0.1:%u/#token=%s", srv.port, srv.token);
    if (path != NULL) {
        Str enc = url_quote(s->a, platform_abspath(s->a, path));
        buf_printf(&url, "&open=%.*s", (int)enc.n, enc.p);
    }
    printf("vex is running at:\n\n  %s\n\nPress Ctrl+C to stop.\n", buf_str(&url).p);
    fflush(stdout);

    if (!no_browser)
        open_browser(buf_str(&url).p);

    g_stop = 0;
    g_listen = fd;
    install_interrupt_handler();

    while (!g_stop) {
        socket_t conn = accept(fd, NULL, NULL);
        if (conn == BAD_SOCKET) {
            if (g_stop)
                break;
            continue;               /* interrupted or transient: keep serving */
        }
#ifdef _WIN32
        DWORD tv = RECV_TIMEOUT_SECS * 1000;
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
#else
        struct timeval tv = {RECV_TIMEOUT_SECS, 0};
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#endif
        handle_connection(&srv, conn);
        closesock(conn);
    }

    if (g_listen != BAD_SOCKET) {
        closesock(fd);
        g_listen = BAD_SOCKET;
    }
    err_release(&srv.err);
    printf("\nstopped.\n");
    fflush(stdout);
#ifdef _WIN32
    WSACleanup();
#endif
}

/* --- desktop-launch helpers (used by cli.c) ---------------------------------- */

bool gui_can_open(const char *path) {
    return platform_exists(path);
}

bool gui_started_from_desktop(void) {
#ifdef _WIN32
    DWORD processes[2];
    if (GetConsoleProcessList(processes, 2) != 1)
        return false;              /* sharing a console with a shell */
    DWORD mode;
    return platform_stdout_is_terminal() &&
           GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
#else
    return false;
#endif
}
