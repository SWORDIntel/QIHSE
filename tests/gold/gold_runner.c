/*
 * gold_runner.c — QIHSE gold validation suite runner (roadmap W5.3).
 *
 * One entry point that executes a versioned workload pack and prints a
 * per-area pass/fail summary plus a final verdict.  The pack is data: adding a
 * workload is a pack edit, never a runner edit.
 *
 * Usage:  LD_LIBRARY_PATH=. ./tests/gold/gold_runner [--strict] [--list] <pack>
 *
 * Environment: GOLD_STRICT=1 is equivalent to --strict.
 *
 * Pack grammar (docs/development/gold_validation_suite.md documents it in
 * full; the pack header repeats the essentials):
 *
 *   pack-version 1
 *   pack-id <string>
 *   area <id> <description>
 *   workload <id> area=<area> expect=<pass|known-bug|known-fail> [timeout=<sec>]
 *                output="<required substring>" match="<required substring>"
 *                ref="<relative path>" bin=<relative path> run="<argv...>"
 *   gap <id> [area=<area>] reason="<why this cannot be tested today>"
 *
 * Statuses:
 *   PASS        ran, exit 0, and printed the required evidence line
 *   FAIL        ran and failed, or did not print the required evidence
 *   ERROR       could not be run at all (exec/build failure, unreadable pack)
 *   TIMEOUT     exceeded its timeout and was killed
 *   KNOWN-BUG   a known-defect probe reported the defect is still present
 *   KNOWN-FAIL  a workload whose failure is recorded, with the documented reason
 *   FIXED       a known-defect probe reports the defect is gone (update the pack)
 *   XPASS       a known-fail workload now passes (update the pack)
 *   UNCOVERED   an area with no runnable workload, with the reason recorded
 *   PARTIAL     an area with runnable workloads and recorded coverage gaps
 *
 * Exit status:
 *   0  no workload failed, could not run, or timed out
 *   1  a workload failed, could not run, or timed out
 *   2  --strict/GOLD_STRICT=1 and the verdict is not fully green (known
 *      defects, stale expectations, or coverage gaps)
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define GOLD_MAX_OUTPUT (2u * 1024u * 1024u)   /* capture cap, heap allocated */
#define GOLD_TAIL_LINES 12                     /* failure output tail */

typedef enum {
    GOLD_EXPECT_PASS = 0,
    GOLD_EXPECT_KNOWN_BUG,
    GOLD_EXPECT_KNOWN_FAIL
} gold_expect_t;

typedef enum {
    GOLD_STATUS_PENDING = 0,
    GOLD_STATUS_PASS,
    GOLD_STATUS_FAIL,
    GOLD_STATUS_ERROR,
    GOLD_STATUS_TIMEOUT,
    GOLD_STATUS_KNOWN_BUG,
    GOLD_STATUS_KNOWN_FAIL,
    GOLD_STATUS_FIXED,
    GOLD_STATUS_XPASS
} gold_status_t;

typedef struct {
    char* id;
    char* desc;
    size_t workloads;
    size_t gaps;
} gold_area_t;

typedef struct {
    char* id;
    char* area;
    gold_expect_t expect;
    long timeout;
    char* output;      /* required evidence substring (expect=pass) */
    char* match;       /* required failure substring (expect=known-fail) */
    char* ref;         /* relative reference path (known states) */
    char* bin;         /* relative binary path, used by the Makefile */
    char** argv;
    size_t argc;
    char* command;     /* run= as written, for reporting */

    gold_status_t status;
    double seconds;
    int exit_code;
    char* detail;      /* probe lines / failure tail, heap allocated */
} gold_workload_t;

typedef struct {
    char* id;
    char* area;        /* NULL for a suite-wide gap */
    char* reason;
} gold_gap_t;

typedef struct {
    char* pack_id;
    int pack_version;
    gold_area_t* areas;
    size_t n_areas;
    gold_workload_t* workloads;
    size_t n_workloads;
    gold_gap_t* gaps;
    size_t n_gaps;
} gold_pack_t;

/* ── Small helpers ──────────────────────────────────────────────────────── */

static const char* status_name(gold_status_t s) {
    switch (s) {
        case GOLD_STATUS_PASS:       return "PASS";
        case GOLD_STATUS_FAIL:       return "FAIL";
        case GOLD_STATUS_ERROR:      return "ERROR";
        case GOLD_STATUS_TIMEOUT:    return "TIMEOUT";
        case GOLD_STATUS_KNOWN_BUG:  return "KNOWN-BUG";
        case GOLD_STATUS_KNOWN_FAIL: return "KNOWN-FAIL";
        case GOLD_STATUS_FIXED:      return "FIXED";
        case GOLD_STATUS_XPASS:      return "XPASS";
        default:                     return "PENDING";
    }
}

static void* xmalloc(size_t n) {
    void* p = malloc(n ? n : 1u);
    if (!p) {
        fprintf(stderr, "gold_runner: out of memory\n");
        exit(1);
    }
    return p;
}

static char* xstrdup(const char* s) {
    size_t n = strlen(s) + 1u;
    char* p = (char*)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static char* read_file(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0 || size > (long)GOLD_MAX_OUTPUT) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char* buf = (char*)xmalloc((size_t)size + 1u);
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[got] = '\0';
    if (out_len) *out_len = got;
    return buf;
}

/* Append a runner-synthesised line to a captured output buffer.  Used for
 * events the workload itself cannot report (a signal death, an exec failure),
 * so the pack can match them. */
static void append_output_line(char** text, const char* line) {
    size_t old = strlen(*text);
    size_t add = strlen(line);
    char* grown = (char*)realloc(*text, old + add + 2u);
    if (!grown) {
        fprintf(stderr, "gold_runner: out of memory\n");
        exit(1);
    }
    memcpy(grown + old, line, add);
    grown[old + add] = '\n';
    grown[old + add + 1u] = '\0';
    *text = grown;
}

static bool is_absolute_path(const char* p) {
    return p && p[0] == '/';
}

/* ── Pack parsing ───────────────────────────────────────────────────────── */

static void pack_error(const char* path, size_t line, const char* fmt, ...) {
    va_list ap;
    fprintf(stderr, "gold_runner: %s:%zu: ", path, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/* Split a workload/gap body into key=value tokens.  Values are either bare
 * (no whitespace) or double quoted.  Returns the number of tokens. */
#define GOLD_MAX_TOKENS 24
typedef struct {
    char* key;
    char* value;
} gold_token_t;

static int tokenize(const char* body, gold_token_t* tokens, int max_tokens,
                    size_t line_no, const char* path) {
    int n = 0;
    const char* p = body;
    while (*p && n < max_tokens) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char* key = p;
        while (*p && *p != '=' && *p != ' ' && *p != '\t') p++;
        if (*p != '=') {
            pack_error(path, line_no, "token '%.*s' is not key=value",
                       (int)(p - key), key);
            return -1;
        }
        size_t key_len = (size_t)(p - key);
        p++;   /* skip '=' */
        char* value = NULL;
        if (*p == '"') {
            p++;
            /* Quoted value; \" and \\ are the only escapes. */
            size_t cap = strlen(p) + 1u, vlen = 0;
            value = (char*)xmalloc(cap);
            while (*p && *p != '"') {
                if (*p == '\\' && (p[1] == '"' || p[1] == '\\')) {
                    value[vlen++] = p[1];
                    p += 2;
                    continue;
                }
                value[vlen++] = *p++;
            }
            if (*p != '"') {
                pack_error(path, line_no, "unterminated quoted value for '%.*s'",
                           (int)key_len, key);
                free(value);
                return -1;
            }
            value[vlen] = '\0';
            p++;
        } else {
            const char* start = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            value = (char*)xmalloc((size_t)(p - start) + 1u);
            memcpy(value, start, (size_t)(p - start));
            value[p - start] = '\0';
        }
        tokens[n].key = (char*)xmalloc(key_len + 1u);
        memcpy(tokens[n].key, key, key_len);
        tokens[n].key[key_len] = '\0';
        tokens[n].value = value;
        n++;
    }
    if (*p && n == max_tokens) {
        pack_error(path, line_no, "too many key=value tokens (max %d)", max_tokens);
        return -1;
    }
    return n;
}

static void tokens_free(gold_token_t* tokens, int n) {
    for (int i = 0; i < n; i++) {
        free(tokens[i].key);
        free(tokens[i].value);
    }
}

static char* token_get(gold_token_t* tokens, int n, const char* key) {
    for (int i = 0; i < n; i++)
        if (strcmp(tokens[i].key, key) == 0) return tokens[i].value;
    return NULL;
}

static int split_argv(const char* command, char*** out_argv, size_t* out_argc) {
    size_t cap = 8, argc = 0;
    char** argv = (char**)xmalloc(cap * sizeof(char*));
    const char* p = command;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char* start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (argc + 2u > cap) {
            cap *= 2u;
            argv = (char**)realloc(argv, cap * sizeof(char*));
            if (!argv) {
                fprintf(stderr, "gold_runner: out of memory\n");
                exit(1);
            }
        }
        size_t len = (size_t)(p - start);
        argv[argc] = (char*)xmalloc(len + 1u);
        memcpy(argv[argc], start, len);
        argv[argc][len] = '\0';
        argc++;
    }
    argv[argc] = NULL;
    *out_argv = argv;
    *out_argc = argc;
    return argc > 0 ? 0 : -1;
}

static gold_area_t* find_area(gold_pack_t* pack, const char* id) {
    for (size_t i = 0; i < pack->n_areas; i++)
        if (strcmp(pack->areas[i].id, id) == 0) return &pack->areas[i];
    return NULL;
}

static int parse_pack(const char* path, gold_pack_t* pack) {
    size_t len = 0;
    char* text = read_file(path, &len);
    if (!text) {
        fprintf(stderr, "gold_runner: cannot read pack '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    pack->pack_version = -1;
    pack->pack_id = NULL;

    /* Logical lines: a trailing backslash continues the entry on the next
     * physical line, which keeps long workload entries readable.  `logical`
     * accumulates the line being read; `current` holds the completed line while
     * it is parsed (both live in one allocation, so a single free releases
     * them). */
    char* logical = (char*)xmalloc(2u * (len + 2u));
    char* current = logical + len + 2u;
    size_t logical_len = 0;
    logical[0] = '\0';

    size_t line_no = 0;
    size_t logical_start = 0;
    char* cursor = text;
    while (cursor && *cursor) {
        char* nl = strchr(cursor, '\n');
        if (nl) *nl = '\0';
        line_no++;
        if (logical_len == 0u) logical_start = line_no;

        char* piece = cursor;
        size_t l = strlen(piece);
        while (l > 0 && (piece[l - 1] == '\r' || piece[l - 1] == ' ' ||
                         piece[l - 1] == '\t')) {
            piece[--l] = '\0';
        }
        bool continued = false;
        if (l > 0 && piece[l - 1] == '\\') {
            piece[--l] = '\0';
            while (l > 0 && (piece[l - 1] == ' ' || piece[l - 1] == '\t'))
                piece[--l] = '\0';
            continued = true;
        }
        if (logical_len + l + 2u > len + 1u) {
            pack_error(path, logical_start, "logical line is too long");
            free(text); free(logical);
            return -1;
        }
        if (logical_len && l) logical[logical_len++] = ' ';
        memcpy(logical + logical_len, piece, l);
        logical_len += l;
        logical[logical_len] = '\0';

        if (continued) {
            if (!nl) break;              /* trailing backslash at EOF */
            cursor = nl + 1;
            continue;
        }

        char* line = current;
        size_t line_number = logical_start;
        memcpy(current, logical, logical_len + 1u);
        logical_len = 0;
        logical[0] = '\0';
        if (nl) cursor = nl + 1; else cursor = NULL;

        while (*line == ' ' || *line == '\t') line++;
        if (!*line || *line == '#') continue;

        /* directive */
        char* sp = line;
        while (*sp && *sp != ' ' && *sp != '\t') sp++;
        char saved = *sp;
        *sp = '\0';
        const char* directive = line;
        char* body = saved ? sp + 1 : sp;
        while (*body == ' ' || *body == '\t') body++;

        if (strcmp(directive, "pack-version") == 0) {
            char* end = NULL;
            long v = strtol(body, &end, 10);
            if (end == body || v <= 0 || v > 1000) {
                pack_error(path, line_number, "pack-version must be a positive integer");
                free(text); free(logical);
                return -1;
            }
            pack->pack_version = (int)v;
        } else if (strcmp(directive, "pack-id") == 0) {
            free(pack->pack_id);
            pack->pack_id = xstrdup(body);
        } else if (strcmp(directive, "area") == 0) {
            char* id = body;
            char* desc = body;
            while (*desc && *desc != ' ' && *desc != '\t') desc++;
            if (*desc) { *desc = '\0'; desc++; }
            while (*desc == ' ' || *desc == '\t') desc++;
            size_t dlen = strlen(desc);
            if (dlen >= 2u && desc[0] == '"' && desc[dlen - 1u] == '"') {
                desc[dlen - 1u] = '\0';
                desc++;
            }
            if (!*id || !*desc) {
                pack_error(path, line_number, "area needs <id> <description>");
                free(text); free(logical);
                return -1;
            }
            if (find_area(pack, id)) {
                pack_error(path, line_number, "duplicate area '%s'", id);
                free(text); free(logical);
                return -1;
            }
            pack->areas = (gold_area_t*)realloc(pack->areas,
                                                (pack->n_areas + 1u) * sizeof(gold_area_t));
            if (!pack->areas) { fprintf(stderr, "gold_runner: out of memory\n"); exit(1); }
            gold_area_t* a = &pack->areas[pack->n_areas++];
            memset(a, 0, sizeof(*a));
            a->id = xstrdup(id);
            a->desc = xstrdup(desc);
        } else if (strcmp(directive, "workload") == 0) {
            char* id = body;
            while (*body && *body != ' ' && *body != '\t') body++;
            if (*body) { *body = '\0'; body++; }
            if (!*id) {
                pack_error(path, line_number, "workload needs an <id>");
                free(text); free(logical);
                return -1;
            }
            gold_token_t tokens[GOLD_MAX_TOKENS];
            memset(tokens, 0, sizeof(tokens));
            int ntok = tokenize(body, tokens, GOLD_MAX_TOKENS, line_no, path);
            if (ntok < 0) { free(text); return -1; }

            gold_workload_t w;
            memset(&w, 0, sizeof(w));
            w.id = xstrdup(id);
            w.timeout = 300;
            w.status = GOLD_STATUS_PENDING;

            char* area_id = token_get(tokens, ntok, "area");
            char* expect = token_get(tokens, ntok, "expect");
            char* timeout = token_get(tokens, ntok, "timeout");
            char* output = token_get(tokens, ntok, "output");
            char* match = token_get(tokens, ntok, "match");
            char* ref = token_get(tokens, ntok, "ref");
            char* bin = token_get(tokens, ntok, "bin");
            char* run = token_get(tokens, ntok, "run");

            if (!area_id || !expect || !run) {
                pack_error(path, line_number,
                           "workload '%s' needs area=, expect= and run=", id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            if (strcmp(expect, "pass") == 0) {
                w.expect = GOLD_EXPECT_PASS;
                if (!output) {
                    pack_error(path, line_number,
                               "workload '%s': expect=pass needs output= (the "
                               "evidence line it must print)", id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
            } else if (strcmp(expect, "known-bug") == 0) {
                w.expect = GOLD_EXPECT_KNOWN_BUG;
                if (!ref) {
                    pack_error(path, line_number,
                               "workload '%s': expect=known-bug needs ref=", id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
            } else if (strcmp(expect, "known-fail") == 0) {
                w.expect = GOLD_EXPECT_KNOWN_FAIL;
                if (!ref || !match) {
                    pack_error(path, line_number,
                               "workload '%s': expect=known-fail needs ref= and "
                               "match= (the documented failure text)", id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
            } else {
                pack_error(path, line_number,
                           "workload '%s': expect must be pass|known-bug|known-fail",
                           id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            if (!find_area(pack, area_id)) {
                pack_error(path, line_number,
                           "workload '%s' names undeclared area '%s'", id, area_id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            if (timeout) {
                char* end = NULL;
                long t = strtol(timeout, &end, 10);
                if (end == timeout || t <= 0 || t > 86400) {
                    pack_error(path, line_number, "workload '%s': bad timeout", id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
                w.timeout = t;
            }
            if (bin) {
                if (is_absolute_path(bin)) {
                    pack_error(path, line_number,
                               "workload '%s': bin= must be relative (path policy)",
                               id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
                w.bin = xstrdup(bin);
            }
            w.area = xstrdup(area_id);
            if (output) w.output = xstrdup(output);
            if (match) w.match = xstrdup(match);
            if (ref) {
                if (is_absolute_path(ref)) {
                    pack_error(path, line_number,
                               "workload '%s': ref= must be relative (path policy)",
                               id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
                struct stat st;
                if (stat(ref, &st) != 0) {
                    pack_error(path, line_number,
                               "workload '%s': ref='%s' does not exist", id, ref);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
                w.ref = xstrdup(ref);
            }
            w.command = xstrdup(run);
            if (split_argv(run, &w.argv, &w.argc) != 0) {
                pack_error(path, line_number, "workload '%s': empty run=", id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            if (is_absolute_path(w.argv[0])) {
                pack_error(path, line_number,
                           "workload '%s': run= must not use an absolute path "
                           "(path policy)", id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            for (size_t i = 0; i < pack->n_workloads; i++) {
                if (strcmp(pack->workloads[i].id, w.id) == 0) {
                    pack_error(path, line_number, "duplicate workload '%s'", id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
            }
            pack->workloads = (gold_workload_t*)realloc(
                pack->workloads, (pack->n_workloads + 1u) * sizeof(gold_workload_t));
            if (!pack->workloads) { fprintf(stderr, "gold_runner: out of memory\n"); exit(1); }
            pack->workloads[pack->n_workloads++] = w;
            tokens_free(tokens, ntok);
        } else if (strcmp(directive, "gap") == 0) {
            char* id = body;
            while (*body && *body != ' ' && *body != '\t') body++;
            if (*body) { *body = '\0'; body++; }
            if (!*id) {
                pack_error(path, line_number, "gap needs an <id>");
                free(text); free(logical);
                return -1;
            }
            gold_token_t tokens[GOLD_MAX_TOKENS];
            memset(tokens, 0, sizeof(tokens));
            int ntok = tokenize(body, tokens, GOLD_MAX_TOKENS, line_no, path);
            if (ntok < 0) { free(text); return -1; }
            char* area_id = token_get(tokens, ntok, "area");
            char* reason = token_get(tokens, ntok, "reason");
            if (!reason) {
                pack_error(path, line_number, "gap '%s' needs reason=", id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            if (area_id && !find_area(pack, area_id)) {
                pack_error(path, line_number,
                           "gap '%s' names undeclared area '%s'", id, area_id);
                tokens_free(tokens, ntok);
                free(text); free(logical);
                return -1;
            }
            for (size_t i = 0; i < pack->n_gaps; i++) {
                if (strcmp(pack->gaps[i].id, id) == 0) {
                    pack_error(path, line_number, "duplicate gap '%s'", id);
                    tokens_free(tokens, ntok);
                    free(text); free(logical);
                    return -1;
                }
            }
            pack->gaps = (gold_gap_t*)realloc(pack->gaps,
                                              (pack->n_gaps + 1u) * sizeof(gold_gap_t));
            if (!pack->gaps) { fprintf(stderr, "gold_runner: out of memory\n"); exit(1); }
            gold_gap_t* g = &pack->gaps[pack->n_gaps++];
            memset(g, 0, sizeof(*g));
            g->id = xstrdup(id);
            g->area = area_id ? xstrdup(area_id) : NULL;
            g->reason = xstrdup(reason);
            tokens_free(tokens, ntok);
        } else {
            pack_error(path, line_number, "unknown directive '%s'", directive);
            free(text); free(logical);
            return -1;
        }
    }
    free(text); free(logical);

    if (pack->pack_version < 0) {
        fprintf(stderr, "gold_runner: %s: missing pack-version directive\n", path);
        return -1;
    }
    if (!pack->pack_id) {
        fprintf(stderr, "gold_runner: %s: missing pack-id directive\n", path);
        return -1;
    }
    if (pack->pack_version != 1) {
        fprintf(stderr,
                "gold_runner: pack '%s' declares version %d, which this runner "
                "does not implement (supported: 1); refusing to run\n",
                path, pack->pack_version);
        return -1;
    }
    /* The filename carries the version: pack.v<N>.gold.  If it disagrees with
     * the directive, the suite's identity is ambiguous. */
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    const char* vmark = strstr(base, ".v");
    if (vmark) {
        long file_version = strtol(vmark + 2, NULL, 10);
        if (file_version != (long)pack->pack_version) {
            fprintf(stderr,
                    "gold_runner: pack file name says version %ld but the file "
                    "declares pack-version %d; refusing to run\n",
                    file_version, pack->pack_version);
            return -1;
        }
    }

    /* Every declared area must be honest: either it has runnable workloads, or
     * it has a recorded gap explaining why it cannot be tested.  An area that
     * silently has neither is exactly the failure mode this suite exists to
     * prevent. */
    for (size_t i = 0; i < pack->n_areas; i++) {
        gold_area_t* a = &pack->areas[i];
        for (size_t j = 0; j < pack->n_workloads; j++)
            if (strcmp(pack->workloads[j].area, a->id) == 0) a->workloads++;
        for (size_t j = 0; j < pack->n_gaps; j++)
            if (pack->gaps[j].area && strcmp(pack->gaps[j].area, a->id) == 0) a->gaps++;
        if (a->workloads == 0 && a->gaps == 0) {
            fprintf(stderr,
                    "gold_runner: area '%s' has no workloads and no gap "
                    "declaration; add a workload or record why it cannot be "
                    "tested (refusing to report it as covered)\n", a->id);
            return -1;
        }
    }
    return 0;
}

/* ── Workload execution ─────────────────────────────────────────────────── */

static double monotonic_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Run one workload.  Returns 0 when the process ran (status/exit_code set),
 * -1 when it could not be run at all. */
static int run_workload(gold_workload_t* w, const char* capture_path,
                        char** out_output) {
    int cap_fd = open(capture_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (cap_fd < 0) {
        w->status = GOLD_STATUS_ERROR;
        w->detail = xstrdup("cannot open the output capture file");
        return -1;
    }

    int exec_pipe[2];
    if (pipe(exec_pipe) != 0) {
        close(cap_fd);
        w->status = GOLD_STATUS_ERROR;
        w->detail = xstrdup("pipe() failed");
        return -1;
    }
    fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);

    double start = monotonic_seconds();
    pid_t pid = fork();
    if (pid < 0) {
        close(cap_fd);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        w->status = GOLD_STATUS_ERROR;
        w->detail = xstrdup("fork() failed");
        return -1;
    }
    if (pid == 0) {
        setpgid(0, 0);
        if (dup2(cap_fd, STDOUT_FILENO) < 0 || dup2(cap_fd, STDERR_FILENO) < 0)
            _exit(120);
        close(cap_fd);
        close(exec_pipe[0]);
        /* A nested make must not inherit this make's jobserver descriptors. */
        unsetenv("MAKEFLAGS");
        unsetenv("MFLAGS");
        execvp(w->argv[0], w->argv);
        int err = errno;
        ssize_t ignored = write(exec_pipe[1], &err, sizeof(err));
        (void)ignored;
        _exit(127);
    }

    close(cap_fd);
    close(exec_pipe[1]);

    int exit_status = 0;
    bool timed_out = false;
    for (;;) {
        pid_t r = waitpid(pid, &exit_status, WNOHANG);
        if (r == pid) break;
        if (r < 0 && errno != EINTR) {
            w->status = GOLD_STATUS_ERROR;
            w->detail = xstrdup("waitpid() failed");
            close(exec_pipe[0]);
            return -1;
        }
        if (monotonic_seconds() - start > (double)w->timeout) {
            timed_out = true;
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &exit_status, 0);
            break;
        }
        struct timespec nap = {0, 10 * 1000 * 1000};   /* 10 ms */
        nanosleep(&nap, NULL);
    }
    w->seconds = monotonic_seconds() - start;

    int exec_errno = 0;
    ssize_t got = read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
    close(exec_pipe[0]);

    if (out_output) {
        size_t len = 0;
        char* text = read_file(capture_path, &len);
        *out_output = text ? text : xstrdup("");
    }

    if (timed_out) {
        w->status = GOLD_STATUS_TIMEOUT;
        char buf[128];
        snprintf(buf, sizeof(buf), "killed after %lds", w->timeout);
        w->detail = xstrdup(buf);
        return 0;
    }
    if (got == (ssize_t)sizeof(exec_errno)) {
        w->status = GOLD_STATUS_ERROR;
        char buf[256];
        snprintf(buf, sizeof(buf), "cannot run '%s': %s",
                 w->argv[0], strerror(exec_errno));
        w->detail = xstrdup(buf);
        return -1;
    }
    if (WIFSIGNALED(exit_status)) {
        w->exit_code = 128 + WTERMSIG(exit_status);
        if (out_output) {
            char buf[128];
            snprintf(buf, sizeof(buf), "GOLD-RUNNER: terminated by signal %d (%s)",
                     WTERMSIG(exit_status), strsignal(WTERMSIG(exit_status)));
            append_output_line(out_output, buf);
        }
    } else if (WIFEXITED(exit_status)) {
        w->exit_code = WEXITSTATUS(exit_status);
    } else {
        w->exit_code = -1;
    }
    return 0;
}

/* The first line of output containing `needle`, heap allocated. */
static char* matched_line(const char* output, const char* needle) {
    const char* p = strstr(output, needle);
    if (!p) return xstrdup("");
    const char* start = p;
    while (start > output && start[-1] != '\n') start--;
    const char* end = p;
    while (*end && *end != '\n') end++;
    size_t len = (size_t)(end - start);
    char* line = (char*)xmalloc(len + 1u);
    memcpy(line, start, len);
    line[len] = '\0';
    return line;
}

/* Print a multi-line detail with an indent, without modifying the buffer (a
 * destructive strtok would leave later sections with only the first line). */
static void print_indented_lines(const char* text, const char* indent) {
    const char* p = text;
    while (p && *p) {
        const char* eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len) printf("%s%.*s\n", indent, (int)len, p);
        if (!eol) break;
        p = eol + 1;
    }
}

/* A probe marker must name this workload: either the pack's workload id or the
 * basename of the binary the pack runs.  Anything else is a hard failure, so
 * output from another process can never be attributed to this workload. */
static bool marker_id_matches(const char* marker_id, const gold_workload_t* w) {
    size_t n = strlen(marker_id);
    const char* candidates[2];
    candidates[0] = w->id;
    candidates[1] = NULL;
    if (w->bin) {
        const char* base = strrchr(w->bin, '/');
        candidates[1] = base ? base + 1 : w->bin;
    }
    for (size_t i = 0; i < 2; i++) {
        if (!candidates[i]) continue;
        size_t len = strlen(candidates[i]);
        if (n >= len && strncmp(marker_id, candidates[i], len) == 0 &&
            (marker_id[len] == ' ' || marker_id[len] == '\0')) {
            return true;
        }
    }
    return false;
}

/* Collect "GOLD: <KIND> <id> ..." lines into detail text.  Returns the number
 * of KNOWN-BUG lines; sets *ok_lines to the number of GOLD: OK lines.  A line
 * whose id does not match the workload is a hard failure. */
static int collect_markers(const char* output, const gold_workload_t* w,
                           char** detail, int* ok_lines, bool* id_mismatch) {
    int bugs = 0;
    *ok_lines = 0;
    *id_mismatch = false;
    size_t cap = 4096, len = 0;
    char* buf = (char*)xmalloc(cap);
    buf[0] = '\0';

    const char* p = output;
    while ((p = strstr(p, "GOLD: ")) != NULL) {
        const char* eol = strchr(p, '\n');
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
        char* line = (char*)xmalloc(line_len + 1u);
        memcpy(line, p, line_len);
        line[line_len] = '\0';

        const char* kind = p + 6;
        if (strncmp(kind, "KNOWN-BUG ", 10) == 0) {
            if (!marker_id_matches(kind + 10, w)) {
                *id_mismatch = true;
            } else {
                bugs++;
                if (len + line_len + 2u > cap) {
                    cap = (len + line_len + 2u) * 2u;
                    buf = (char*)realloc(buf, cap);
                    if (!buf) { fprintf(stderr, "gold_runner: out of memory\n"); exit(1); }
                }
                memcpy(buf + len, line, line_len);
                len += line_len;
                buf[len++] = '\n';
                buf[len] = '\0';
            }
        } else if (strncmp(kind, "OK ", 3) == 0) {
            if (!marker_id_matches(kind + 3, w)) {
                *id_mismatch = true;
            } else {
                (*ok_lines)++;
            }
        }
        free(line);
        p += 6;
    }
    *detail = buf;
    return bugs;
}

/* Last N non-empty lines of output, for failure reporting. */
static char* output_tail(const char* output) {
    size_t n_lines = 0;
    const char* lines[GOLD_TAIL_LINES];
    size_t lens[GOLD_TAIL_LINES];
    const char* p = output;
    while (*p) {
        const char* eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        bool blank = true;
        for (size_t i = 0; i < len; i++)
            if (p[i] != ' ' && p[i] != '\t' && p[i] != '\r') { blank = false; break; }
        if (!blank && len > 0) {
            if (n_lines == GOLD_TAIL_LINES) {
                memmove(lines, lines + 1, (GOLD_TAIL_LINES - 1) * sizeof(lines[0]));
                memmove(lens, lens + 1, (GOLD_TAIL_LINES - 1) * sizeof(lens[0]));
                n_lines--;
            }
            lines[n_lines] = p;
            lens[n_lines] = len;
            n_lines++;
        }
        if (!eol) break;
        p = eol + 1;
    }
    size_t total = 1;
    for (size_t i = 0; i < n_lines; i++) total += lens[i] + 1u;
    char* buf = (char*)xmalloc(total);
    size_t off = 0;
    for (size_t i = 0; i < n_lines; i++) {
        memcpy(buf + off, lines[i], lens[i]);
        off += lens[i];
        buf[off++] = '\n';
    }
    buf[off] = '\0';
    return buf;
}

static void classify_workload(gold_workload_t* w, const char* output) {
    int ok_lines = 0;
    bool id_mismatch = false;
    char* markers = NULL;
    int bugs = collect_markers(output, w, &markers, &ok_lines, &id_mismatch);

    if (id_mismatch) {
        w->status = GOLD_STATUS_FAIL;
        w->detail = xstrdup("a GOLD: marker names a different workload id");
        free(markers);
        return;
    }
    if (w->status == GOLD_STATUS_ERROR || w->status == GOLD_STATUS_TIMEOUT) return;

    if (w->exit_code != 0) {
        if (w->expect == GOLD_EXPECT_KNOWN_FAIL) {
            if (w->match && strstr(output, w->match)) {
                w->status = GOLD_STATUS_KNOWN_FAIL;
                char* line = matched_line(output, w->match);
                size_t n = strlen(line) + strlen(w->match) + 96u;
                w->detail = (char*)xmalloc(n);
                snprintf(w->detail, n,
                         "documented failure reproduced (match=\"%s\"):\n%s",
                         w->match, line);
                free(line);
            } else {
                w->status = GOLD_STATUS_FAIL;
                w->detail = xstrdup("failed for a reason that is NOT the "
                                    "documented one (match= not found)");
            }
        } else {
            w->status = GOLD_STATUS_FAIL;
            char* tail = output_tail(output);
            size_t n = strlen(tail) + 64u;
            w->detail = (char*)xmalloc(n);
            snprintf(w->detail, n, "exit=%d; last output:\n%s", w->exit_code, tail);
            free(tail);
        }
        free(markers);
        return;
    }

    /* exit 0 */
    if (w->expect == GOLD_EXPECT_KNOWN_BUG) {
        if (bugs > 0) {
            w->status = GOLD_STATUS_KNOWN_BUG;
            w->detail = markers;
            return;
        }
        free(markers);
        if (ok_lines > 0) {
            w->status = GOLD_STATUS_FIXED;
            w->detail = xstrdup("every check in this probe now reports OK; the "
                                "pack's known-bug expectation is stale");
        } else {
            w->status = GOLD_STATUS_FAIL;
            w->detail = xstrdup("probe printed no GOLD: marker");
        }
        return;
    }
    if (w->expect == GOLD_EXPECT_KNOWN_FAIL) {
        free(markers);
        w->status = GOLD_STATUS_XPASS;
        w->detail = xstrdup("this workload is recorded as known-failing but it "
                            "now passes; update the pack");
        return;
    }
    /* expect == pass */
    if (bugs > 0) {
        w->status = GOLD_STATUS_FAIL;
        w->detail = markers;
        return;
    }
    free(markers);
    if (w->output && !strstr(output, w->output)) {
        w->status = GOLD_STATUS_FAIL;
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "exit=0 but the required evidence line was not printed: \"%s\"",
                 w->output);
        w->detail = xstrdup(buf);
        return;
    }
    w->status = GOLD_STATUS_PASS;
    w->detail = NULL;
}

/* ── Reporting ──────────────────────────────────────────────────────────── */

static void print_rule(void) {
    printf("===============================================================================\n");
}

int main(int argc, char** argv) {
    bool strict = false;
    bool list_only = false;
    const char* pack_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--strict") == 0) strict = true;
        else if (strcmp(argv[i], "--list") == 0) list_only = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: gold_runner [--strict] [--list] <pack file>\n"
                   "  --strict  exit 2 when the verdict is not fully green\n"
                   "  --list    print the pack contents and exit\n");
            return 0;
        } else if (!pack_path) pack_path = argv[i];
        else {
            fprintf(stderr, "gold_runner: unexpected argument '%s'\n", argv[i]);
            return 1;
        }
    }
    if (!pack_path) {
        fprintf(stderr, "gold_runner: no pack file given (usage: gold_runner "
                        "[--strict] [--list] <pack file>)\n");
        return 1;
    }
    const char* env_strict = getenv("GOLD_STRICT");
    if (env_strict && *env_strict && strcmp(env_strict, "0") != 0) strict = true;

    gold_pack_t pack;
    memset(&pack, 0, sizeof(pack));
    if (parse_pack(pack_path, &pack) != 0) return 1;

    print_rule();
    printf("QIHSE gold validation suite — pack %s (pack-version %d)\n",
           pack.pack_id, pack.pack_version);
    printf("pack file: %s\n", pack_path);
    printf("%zu areas, %zu workloads, %zu declared coverage gaps\n",
           pack.n_areas, pack.n_workloads, pack.n_gaps);
    print_rule();

    if (list_only) {
        for (size_t i = 0; i < pack.n_areas; i++) {
            printf("area %-24s %s\n", pack.areas[i].id, pack.areas[i].desc);
            for (size_t j = 0; j < pack.n_workloads; j++) {
                if (strcmp(pack.workloads[j].area, pack.areas[i].id) != 0) continue;
                printf("  workload %-28s expect=%-9s run=%s\n",
                       pack.workloads[j].id,
                       pack.workloads[j].expect == GOLD_EXPECT_PASS ? "pass" :
                       pack.workloads[j].expect == GOLD_EXPECT_KNOWN_BUG ?
                       "known-bug" : "known-fail",
                       pack.workloads[j].command);
            }
        }
        return 0;
    }

    if (mkdir("tests/gold/.tmp", 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "gold_runner: cannot create tests/gold/.tmp: %s\n",
                strerror(errno));
        return 1;
    }
    char capture_path[128];
    snprintf(capture_path, sizeof(capture_path),
             "tests/gold/.tmp/gold-runner-%ld.out", (long)getpid());

    /* Run every workload, grouped by area. */
    for (size_t a = 0; a < pack.n_areas; a++) {
        gold_area_t* area = &pack.areas[a];
        printf("\n%s  %s\n", area->id, area->desc);
        for (size_t i = 0; i < pack.n_workloads; i++) {
            gold_workload_t* w = &pack.workloads[i];
            if (strcmp(w->area, area->id) != 0) continue;

            char* output = NULL;
            if (run_workload(w, capture_path, &output) == 0)
                classify_workload(w, output);
            else if (w->status == GOLD_STATUS_PENDING)
                w->status = GOLD_STATUS_ERROR;

            printf("  [%-10s] %-30s %6.2fs  %s\n", status_name(w->status),
                   w->id, w->seconds, w->command);
            if (w->detail && *w->detail)
                print_indented_lines(w->detail, "      ");
            if (w->ref) printf("      ref: %s\n", w->ref);
            free(output);
        }
        /* Area verdict. */
        size_t pass = 0, bugs = 0, kfail = 0, hard = 0, stale = 0;
        for (size_t i = 0; i < pack.n_workloads; i++) {
            gold_workload_t* w = &pack.workloads[i];
            if (strcmp(w->area, area->id) != 0) continue;
            switch (w->status) {
                case GOLD_STATUS_PASS: pass++; break;
                case GOLD_STATUS_KNOWN_BUG: bugs++; break;
                case GOLD_STATUS_KNOWN_FAIL: kfail++; break;
                case GOLD_STATUS_FIXED:
                case GOLD_STATUS_XPASS: stale++; break;
                default: hard++; break;
            }
        }
        printf("  -> ");
        if (area->workloads == 0) {
            printf("UNCOVERED (no runnable workload)\n");
        } else if (hard > 0) {
            printf("FAILED (%zu of %zu workloads failed, could not run, or timed out)\n",
                   hard, area->workloads);
        } else {
            printf("%s (%zu pass", area->gaps ? "PARTIAL" : "FULL", pass);
            if (bugs) printf(", %zu known-bug", bugs);
            if (kfail) printf(", %zu known-fail", kfail);
            if (stale) printf(", %zu stale expectation", stale);
            printf(")\n");
        }
    }

    /* Coverage gaps. */
    if (pack.n_gaps) {
        printf("\nCOVERAGE GAPS (declared, not silently skipped)\n");
        for (size_t i = 0; i < pack.n_gaps; i++) {
            printf("  %s%s: %s\n",
                   pack.gaps[i].id,
                   pack.gaps[i].area ? "" : " (suite-wide)",
                   pack.gaps[i].reason);
        }
    }

    /* Summary table. */
    size_t total_pass = 0, total_bug = 0, total_kfail = 0, total_hard = 0,
           total_stale = 0, uncovered_areas = 0, partial_areas = 0, full_areas = 0;
    print_rule();
    printf("AREA SUMMARY\n");
    for (size_t a = 0; a < pack.n_areas; a++) {
        gold_area_t* area = &pack.areas[a];
        size_t pass = 0, bugs = 0, kfail = 0, hard = 0, stale = 0;
        for (size_t i = 0; i < pack.n_workloads; i++) {
            gold_workload_t* w = &pack.workloads[i];
            if (strcmp(w->area, area->id) != 0) continue;
            switch (w->status) {
                case GOLD_STATUS_PASS: pass++; break;
                case GOLD_STATUS_KNOWN_BUG: bugs++; break;
                case GOLD_STATUS_KNOWN_FAIL: kfail++; break;
                case GOLD_STATUS_FIXED:
                case GOLD_STATUS_XPASS: stale++; break;
                default: hard++; break;
            }
        }
        const char* coverage = (area->workloads == 0) ? "UNCOVERED" :
                               (area->gaps ? "PARTIAL" : "FULL");
        if (area->workloads == 0) uncovered_areas++;
        else if (area->gaps) partial_areas++;
        else full_areas++;
        printf("  %-24s %-9s %zu workload(s): %zu pass", area->id, coverage,
               area->workloads, pass);
        if (bugs) printf(", %zu known-bug", bugs);
        if (kfail) printf(", %zu known-fail", kfail);
        if (hard) printf(", %zu FAILED", hard);
        if (stale) printf(", %zu stale expectation", stale);
        if (area->gaps) printf(", %zu gap(s)", area->gaps);
        printf("\n");
        total_pass += pass; total_bug += bugs; total_kfail += kfail;
        total_hard += hard; total_stale += stale;
    }
    printf("\nWORKLOADS: %zu total — %zu pass, %zu known-bug, %zu known-fail, "
           "%zu failed, %zu stale\n",
           pack.n_workloads, total_pass, total_bug, total_kfail, total_hard,
           total_stale);
    printf("AREAS: %zu — %zu fully covered, %zu partial, %zu uncovered\n",
           pack.n_areas, full_areas, partial_areas, uncovered_areas);

    /* Known defects, restated as the headline state of the system. */
    size_t known = total_bug + total_kfail;
    if (known) {
        printf("\nKNOWN DEFECTS / KNOWN FAILURES RECORDED (%zu) — these are NOT passes:\n", known);
        for (size_t i = 0; i < pack.n_workloads; i++) {
            gold_workload_t* w = &pack.workloads[i];
            if (w->status != GOLD_STATUS_KNOWN_BUG &&
                w->status != GOLD_STATUS_KNOWN_FAIL) continue;
            printf("  %-10s %s/%s\n", status_name(w->status), w->area, w->id);
            if (w->ref) printf("      ref: %s\n", w->ref);
            if (w->detail) print_indented_lines(w->detail, "      ");
        }
    }
    if (total_stale) {
        printf("\nSTALE EXPECTATIONS (%zu) — update the pack:\n", total_stale);
        for (size_t i = 0; i < pack.n_workloads; i++) {
            gold_workload_t* w = &pack.workloads[i];
            if (w->status != GOLD_STATUS_FIXED && w->status != GOLD_STATUS_XPASS)
                continue;
            printf("  %-6s %s/%s: %s\n", status_name(w->status), w->area, w->id,
                   w->detail ? w->detail : "");
        }
    }

    /* Verdict.  Hard failures are also written to stderr so a failing run is
     * loud even when only stderr is read. */
    for (size_t i = 0; i < pack.n_workloads; i++) {
        gold_workload_t* w = &pack.workloads[i];
        if (w->status == GOLD_STATUS_FAIL || w->status == GOLD_STATUS_ERROR ||
            w->status == GOLD_STATUS_TIMEOUT) {
            fprintf(stderr, "gold_runner: %s %s/%s: %s\n", status_name(w->status),
                    w->area, w->id, w->detail ? w->detail : "");
        }
    }
    int rc = 0;
    bool not_green = (total_hard > 0) || (known > 0) || (total_stale > 0) ||
                     uncovered_areas > 0 || partial_areas > 0;
    if (total_hard > 0) {
        printf("\nVERDICT: FAIL — %zu workload(s) failed, could not run, or timed out\n",
               total_hard);
        rc = 1;
    } else if (not_green) {
        printf("\nVERDICT: PASS WITH CAVEATS — no workload failed, but %zu known "
               "defect(s), %zu stale expectation(s) and %zu area(s) with "
               "recorded coverage gaps remain\n",
               known, total_stale, partial_areas + uncovered_areas);
        rc = strict ? 2 : 0;
    } else {
        printf("\nVERDICT: PASS — every area is fully covered and every workload "
               "passed\n");
        rc = 0;
    }
    printf("exit status %d%s\n", rc,
           strict ? " (strict mode: known defects and gaps are fatal)" : "");
    print_rule();

    unlink(capture_path);
    rmdir("tests/gold/.tmp");
    return rc;
}
