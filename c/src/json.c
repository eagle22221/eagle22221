/* JSON document tree and writer. */
#include "json.h"

static JVal *j_new(Arena *a, JKind kind) {
    JVal *v = arena_alloc(a, sizeof *v);
    v->kind = kind;
    return v;
}

JVal *j_null(Arena *a) {
    return j_new(a, J_NULL);
}

JVal *j_bool(Arena *a, bool value) {
    JVal *v = j_new(a, J_BOOL);
    v->u.flag = value;
    return v;
}

JVal *j_int(Arena *a, big value) {
    JVal *v = j_new(a, J_INT);
    v->u.number = value;
    return v;
}

JVal *j_float(Arena *a, double value) {
    JVal *v = j_new(a, J_FLOAT);
    char text[40];
    v->u.real = strtod(format_rounded(text, value), NULL);
    return v;
}

JVal *j_str(Arena *a, Str value) {
    if (value.p == NULL)
        return j_null(a);
    JVal *v = j_new(a, J_STR);
    v->u.text = value;
    return v;
}

JVal *j_cstr(Arena *a, const char *value) {
    return j_str(a, str_c(value));
}

JVal *j_hex(Arena *a, big value) {
    char text[40];
    hex_big(text, value);
    return j_str(a, str_copy(a, text, strlen(text)));
}

JVal *j_opt_hex(Arena *a, bool has, big value) {
    return has ? j_hex(a, value) : j_null(a);
}

JVal *j_list(Arena *a) {
    return j_new(a, J_LIST);
}

JVal *j_dict(Arena *a) {
    return j_new(a, J_DICT);
}

void j_push(Arena *a, JVal *list, JVal *item) {
    *VEC_PUSH(a, list->u.list) = item;
}

void j_set(Arena *a, JVal *dict, const char *key, JVal *value) {
    for (size_t i = 0; i < dict->u.dict.n; i++) {
        if (strcmp(dict->u.dict.v[i].key, key) == 0) {
            dict->u.dict.v[i].value = value;
            return;
        }
    }
    JMember m = {key, value};
    *VEC_PUSH(a, dict->u.dict) = m;
}

const JVal *j_get(const JVal *dict, const char *key) {
    if (dict == NULL || dict->kind != J_DICT)
        return NULL;
    for (size_t i = 0; i < dict->u.dict.n; i++)
        if (strcmp(dict->u.dict.v[i].key, key) == 0)
            return dict->u.dict.v[i].value;
    return NULL;
}

Str j_text(const JVal *value) {
    if (value != NULL && value->kind == J_STR)
        return value->u.text;
    return str_c("");
}

big j_number(const JVal *value) {
    return value != NULL && value->kind == J_INT ? value->u.number : 0;
}

size_t j_len(const JVal *list) {
    return list != NULL && list->kind == J_LIST ? list->u.list.n : 0;
}

const JVal *j_at(const JVal *list, size_t index) {
    return index < j_len(list) ? list->u.list.v[index] : NULL;
}

bool j_truthy(const JVal *value) {
    if (value == NULL)
        return false;
    switch (value->kind) {
    case J_NULL: return false;
    case J_BOOL: return value->u.flag;
    case J_INT: return value->u.number != 0;
    case J_FLOAT: return value->u.real != 0.0;
    case J_STR: return value->u.text.n != 0;
    case J_LIST: return value->u.list.n != 0;
    case J_DICT: return value->u.dict.n != 0;
    }
    return false;
}

const char *format_rounded(char buf[40], double value) {
    snprintf(buf, 40, "%.3f", value);
    size_t n = strlen(buf);
    while (n > 0 && buf[n - 1] == '0' && buf[n - 2] != '.')
        buf[--n] = '\0';
    return buf;
}

static void dump_string(FILE *out, Str s) {
    static const char hex[] = "0123456789abcdef";
    fputc('"', out);
    size_t i = 0;
    while (i < s.n) {
        uint8_t c = (uint8_t)s.p[i];
        if (c >= 0x80) {
            /* Strings are valid UTF-8 here (see utf8_decode). */
            size_t len = c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
            if (len > s.n - i)
                len = s.n - i;
            uint32_t cp = c & (0xFFu >> (len + 1));
            for (size_t k = 1; k < len; k++)
                cp = (cp << 6) | ((uint8_t)s.p[i + k] & 0x3F);
            i += len;
            if (cp >= 0x10000) {            /* surrogate pair, as json.dumps writes */
                cp -= 0x10000;
                fprintf(out, "\\u%04x\\u%04x", (unsigned)(0xD800 + (cp >> 10)),
                        (unsigned)(0xDC00 + (cp & 0x3FF)));
            } else {
                fprintf(out, "\\u%04x", (unsigned)cp);
            }
            continue;
        }
        i++;
        switch (c) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        case '\b': fputs("\\b", out); break;
        case '\f': fputs("\\f", out); break;
        default:
            if (c < 0x20) {
                fputs("\\u00", out);
                fputc(hex[c >> 4], out);
                fputc(hex[c & 15], out);
            } else {
                fputc(c, out);
            }
        }
    }
    fputc('"', out);
}

static void indent(FILE *out, int depth) {
    for (int i = 0; i < depth; i++)
        fputs("  ", out);
}

void j_dump(FILE *out, const JVal *value, int depth) {
    char number[44];
    switch (value->kind) {
    case J_NULL:
        fputs("null", out);
        break;
    case J_BOOL:
        fputs(value->u.flag ? "true" : "false", out);
        break;
    case J_INT:
        fputs(dec_big(number, value->u.number), out);
        break;
    case J_FLOAT:
        fputs(format_rounded(number, value->u.real), out);
        break;
    case J_STR:
        dump_string(out, value->u.text);
        break;
    case J_LIST:
        if (value->u.list.n == 0) {
            fputs("[]", out);
            break;
        }
        fputs("[\n", out);
        for (size_t i = 0; i < value->u.list.n; i++) {
            indent(out, depth + 1);
            j_dump(out, value->u.list.v[i], depth + 1);
            fputs(i + 1 < value->u.list.n ? ",\n" : "\n", out);
        }
        indent(out, depth);
        fputc(']', out);
        break;
    case J_DICT:
        if (value->u.dict.n == 0) {
            fputs("{}", out);
            break;
        }
        fputs("{\n", out);
        for (size_t i = 0; i < value->u.dict.n; i++) {
            indent(out, depth + 1);
            dump_string(out, str_c(value->u.dict.v[i].key));
            fputs(": ", out);
            j_dump(out, value->u.dict.v[i].value, depth + 1);
            fputs(i + 1 < value->u.dict.n ? ",\n" : "\n", out);
        }
        indent(out, depth);
        fputc('}', out);
        break;
    }
}
