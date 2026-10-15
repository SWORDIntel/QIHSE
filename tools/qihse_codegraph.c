/* SPDX-License-Identifier: LicenseRef-SRSL-1.0 */
/*
 * QIHSE CodeGraph v1: offline, durable, structural-code graph CLI.
 * CRG supplies canonical, evidence-tagged JSONL. QIHSE KV owns snapshot
 * persistence, and the native QIHSE graph engine owns indexed traversal.
 *
 * No network listener, no embedded Python, and no SQL/Neo4j dependency.
 * One process reads one published immutable generation; imports publish only
 * after validation, QIHSE KV serialization and fsync.
 */
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_kv_store.h"
#include "qihse_graph_store.h"

#define CG_MAX_LINE 262144u
#define CG_MAX_NODES 2000000u
#define CG_MAX_EDGES 8000000u
#define CG_MAX_OUT 100000u
#define CG_MAX_FILES 64u

typedef struct {
    char id[65];
    char *file, *name, *kind;
    int line, end_line, is_test;
    uint64_t vertex;
} cg_node;

typedef struct {
    qihse_kv_store_t *kv;
    qihse_graph_t *graph;
    cg_node *nodes;
    cg_node **by_vertex;
    size_t nn, capacity, edges, unresolved;
    struct json_object *meta, *manifest;
    char directory[PATH_MAX], repository[PATH_MAX];
    char scratch[PATH_MAX];
} cg_state;

static char *json_string(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field) ||
        !json_object_is_type(field, json_type_string)) return NULL;
    return (char *)json_object_get_string(field);
}
static int64_t json_num(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field)) return 0;
    return json_object_get_int64(field);
}
static double json_double(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field)) return 0;
    return json_object_get_double(field);
}
static bool json_flag(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    return json_object_object_get_ex(obj, key, &field) &&
           json_object_get_boolean(field);
}
static void json_text(struct json_object *obj, const char *key, const char *value) {
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}
static void json_int(struct json_object *obj, const char *key, int64_t value) {
    json_object_object_add(obj, key, json_object_new_int64(value));
}
static void json_bool(struct json_object *obj, const char *key, bool value) {
    json_object_object_add(obj, key, json_object_new_boolean(value));
}
static void print_json(struct json_object *obj) {
    puts(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
}
static int error_json(const char *reason) {
    struct json_object *o = json_object_new_object();
    json_text(o, "error", reason);
    print_json(o); json_object_put(o);
    return 1;
}
static bool hex64(const char *v) {
    if (!v || strlen(v) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((v[i] >= '0' && v[i] <= '9') ||
              (v[i] >= 'a' && v[i] <= 'f'))) return false;
    return true;
}
static bool safe_relative(const char *path) {
    if (!path || *path == '/' || *path == '~' || strchr(path, '\\')) return false;
    for (const char *p = path; *p;) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 2 && p[0] == '.' && p[1] == '.') ||
            (n == 4 && !memcmp(p, ".git", 4))) return false;
        p = end ? end + 1 : p + n;
    }
    return true;
}
static bool make_directory(const char *path) {
    if (!path || *path != '/' || strlen(path) >= PATH_MAX) return false;
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1;; p++) {
        if (*p != '/' && *p != '\0') continue;
        char old = *p;
        *p = '\0';
        struct stat st;
        if (lstat(buf, &st) != 0) {
            if (errno != ENOENT || mkdir(buf, 0700) != 0) return false;
        } else if (!S_ISDIR(st.st_mode)) return false;
        *p = old;
        if (!old) break;
    }
    return true;
}
static void digest_hex(const unsigned char *data, size_t n, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 15];
    }
    out[n * 2] = '\0';
}
static bool sha256_buffer(const char *data, size_t count, char out[65]) {
    unsigned char sum[EVP_MAX_MD_SIZE]; unsigned int n = 0;
    if (!EVP_Digest(data, count, sum, &n, EVP_sha256(), NULL) || n != 32) return false;
    digest_hex(sum, n, out);
    return true;
}
static bool sha256_file(const char *path, char out[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    unsigned char bytes[65536], sum[EVP_MAX_MD_SIZE]; unsigned int n = 0;
    while (ok) {
        ssize_t received = read(fd, bytes, sizeof(bytes));
        if (received == 0) break;
        if (received < 0) { if (errno == EINTR) continue; ok = false; break; }
        ok = EVP_DigestUpdate(ctx, bytes, (size_t)received) == 1;
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
    if (ok) digest_hex(sum, n, out);
    EVP_MD_CTX_free(ctx); close(fd);
    return ok;
}
static int delete_scratch_entry(const char *path, const struct stat *st,
                                int flags, struct FTW *ftw) {
    (void)st; (void)flags; (void)ftw;
    return remove(path);
}
static void graph_close(cg_state *st) {
    if (st->graph) qihse_graph_destroy(st->graph);
    if (st->kv) qihse_kv_store_destroy(st->kv);
    for (size_t i = 0; i < st->nn; i++) {
        free(st->nodes[i].file); free(st->nodes[i].name); free(st->nodes[i].kind);
    }
    free(st->nodes); free(st->by_vertex);
    if (st->meta) json_object_put(st->meta);
    if (st->manifest) json_object_put(st->manifest);
    if (st->scratch[0]) nftw(st->scratch, delete_scratch_entry, 16, FTW_DEPTH | FTW_PHYS);
}
static bool graph_open(cg_state *st, const char *repo) {
    memset(st, 0, sizeof(*st));
    if (!realpath(repo, st->repository)) return false;
    char work_marker[PATH_MAX];
    if (snprintf(work_marker, sizeof(work_marker), "%s/.git", st->repository) >=
        (int)sizeof(work_marker) || access(work_marker, F_OK) != 0) return false;
    const char *state = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
    char base[PATH_MAX];
    if (state && *state) snprintf(base, sizeof(base), "%s", state);
    else if (home && *home) snprintf(base, sizeof(base), "%s/.local/state", home);
    else return false;
    char repo_hash[65];
    if (!sha256_buffer(st->repository, strlen(st->repository), repo_hash)) return false;
    if (snprintf(st->directory, sizeof(st->directory), "%s/qihse/codegraph/%s",
                 base, repo_hash) >= (int)sizeof(st->directory)) return false;
    if (!make_directory(st->directory)) return false;
    if (snprintf(st->scratch, sizeof(st->scratch), "%s/.runtime-XXXXXX",
                 st->directory) >= (int)sizeof(st->scratch) ||
        !mkdtemp(st->scratch)) {
        st->scratch[0] = '\0';
        return false;
    }
    /* Force QIHSE's KV runtime into our private disposable directory,
     * never the host's production /opt/qihse-data. This process is single
     * purpose; QIHSE caches its data dir for the process lifetime. */
    if (setenv("QIHSE_DATA_DIR", st->scratch, 1) != 0) return false;
    st->kv = qihse_kv_store_create();
    if (!st->kv) return false;
    return true;
}
static bool atomic_write(const char *path, const char *text) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp-XXXXXX", path) >= (int)sizeof(tmp)) return false;
    int fd = mkstemp(tmp);
    if (fd < 0) return false;
    (void)fchmod(fd, 0600);
    size_t offset = 0, count = strlen(text);
    bool ok = true;
    while (offset < count) {
        ssize_t n = write(fd, text + offset, count - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        offset += (size_t)n;
    }
    if (ok) ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (ok) ok = rename(tmp, path) == 0;
    if (!ok) unlink(tmp);
    if (ok) {
        char directory[PATH_MAX]; snprintf(directory, sizeof(directory), "%s", path);
        char *slash = strrchr(directory, '/');
        if (slash) { *slash = '\0'; int dfd = open(directory, O_RDONLY | O_DIRECTORY);
            if (dfd >= 0) { ok = fsync(dfd) == 0; close(dfd); } }
    }
    return ok;
}
static bool validate_node(struct json_object *item) {
    char *id = json_string(item, "id"), *file = json_string(item, "file");
    char *name = json_string(item, "name"), *kind = json_string(item, "kind");
    return hex64(id) && file && safe_relative(file) && strlen(file) <= 4096 &&
           name && strlen(name) <= 512 && kind && strlen(kind) <= 64 &&
           json_num(item, "line_start") >= 0 &&
           json_num(item, "line_end") >= 0;
}
static bool validate_edge(struct json_object *item) {
    char *id = json_string(item, "id"), *file = json_string(item, "file");
    char *src = json_string(item, "source"), *dst = json_string(item, "target");
    char *type = json_string(item, "relation");
    char *resolution = json_string(item, "resolution");
    bool traversable = json_flag(item, "traversable");
    return hex64(id) && file && safe_relative(file) &&
           src && (!*src || hex64(src)) && dst && (!*dst || hex64(dst)) &&
           type && strlen(type) < 32 && resolution &&
           json_num(item, "line") >= 0 && json_double(item, "confidence") >= 0.0 &&
           json_double(item, "confidence") <= 1.0 &&
           (!traversable || (hex64(src) && hex64(dst) &&
                             strcmp(resolution, "direct") == 0 &&
                             json_double(item, "confidence") >= 0.8));
}

/* A publication is all-or-nothing: validate the entire JSONL file and QIHSE
 * KV serialization before replacing the manifest naming the active snapshot. */
static int import_snapshot(cg_state *st, const char *input) {
    char lock_path[PATH_MAX], manifest_path[PATH_MAX];
    snprintf(lock_path, sizeof(lock_path), "%s/.import.lock", st->directory);
    snprintf(manifest_path, sizeof(manifest_path), "%s/current.json", st->directory);
    int lfd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lfd < 0 || flock(lfd, LOCK_EX) != 0) {
        if (lfd >= 0) close(lfd);
        return error_json("cannot obtain CodeGraph import lock");
    }
    int input_fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat source_stat;
    if (input_fd < 0 || fstat(input_fd, &source_stat) ||
        !S_ISREG(source_stat.st_mode)) {
        if (input_fd >= 0) close(input_fd);
        close(lfd);
        return error_json("snapshot source must be a regular non-symlink file");
    }
    FILE *stream = fdopen(input_fd, "r");
    if (!stream) { close(input_fd); close(lfd); return error_json("snapshot open failed"); }
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    bool ok = digest && EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1;
    char *line = NULL; size_t capacity = 0, nodes = 0, edges = 0, unresolved = 0;
    bool header = false, trailer = false;
    char input_hash[65] = {0};
    struct json_object *meta = NULL;
    const char *problem = "invalid CodeGraph snapshot";
    ssize_t length;
    while (ok && (length = getline(&line, &capacity, stream)) > 0) {
        if ((size_t)length > CG_MAX_LINE || line[length - 1] != '\n') {
            problem = "oversized/unterminated CodeGraph record"; ok = false; break;
        }
        struct json_object *row = json_tokener_parse(line);
        if (!row || !json_object_is_type(row, json_type_object)) {
            if (row) json_object_put(row);
            problem = "malformed JSONL record"; ok = false; break;
        }
        char *type = json_string(row, "t");
        if (!type || trailer) { problem = "bad record ordering"; ok = false; }
        else if (!header) {
            char *format = json_string(row, "format");
            char *head = json_string(row, "head");
            char *worktree = json_string(row, "worktree");
            if (strcmp(type, "h") || !format ||
                strcmp(format, "qihse-codegraph-v1") ||
                json_num(row, "version") != 1 || !hex64(head) || !hex64(worktree)) {
                problem = "invalid header/version"; ok = false;
            } else {
                meta = json_object_get(row); header = true;
            }
        } else if (strcmp(type, "n") == 0 || strcmp(type, "e") == 0) {
            bool is_node = strcmp(type, "n") == 0;
            if ((is_node ? !validate_node(row) : !validate_edge(row))) {
                problem = "invalid node/edge evidence"; ok = false;
            } else {
                char key[72];
                snprintf(key, sizeof(key), "%c:%s", is_node ? 'n' : 'e',
                         json_string(row, "id"));
                if (qihse_kv_exists(st->kv, key) ||
                    !qihse_kv_set(st->kv, key, line, 0, 0)) {
                    problem = "duplicate record or QIHSE KV write failed"; ok = false;
                } else {
                    if (is_node) nodes++; else {
                        edges++;
                        if (!json_flag(row, "traversable")) unresolved++;
                    }
                    if (nodes > CG_MAX_NODES || edges > CG_MAX_EDGES) {
                        problem = "CodeGraph capacity exceeded"; ok = false;
                    }
                }
            }
        } else if (strcmp(type, "end") == 0) {
            unsigned char sum[32]; unsigned int sum_len = 0;
            if (!EVP_DigestFinal_ex(digest, sum, &sum_len) || sum_len != 32) {
                problem = "digest verification unavailable"; ok = false;
            } else {
                digest_hex(sum, 32, input_hash);
                char *claimed = json_string(row, "sha256");
                if (!claimed || strcmp(claimed, input_hash) ||
                    json_num(row, "nodes") != (int64_t)nodes ||
                    json_num(row, "edges") != (int64_t)edges ||
                    json_num(row, "unresolved_edges") != (int64_t)unresolved) {
                    problem = "snapshot checksum/count mismatch"; ok = false;
                } else trailer = true;
            }
        } else { problem = "unknown CodeGraph record type"; ok = false; }
        if (ok && !trailer) ok = EVP_DigestUpdate(digest, line, (size_t)length) == 1;
        json_object_put(row);
    }
    if (ferror(stream)) { ok = false; problem = "snapshot read failed"; }
    fclose(stream);
    free(line);
    EVP_MD_CTX_free(digest);
    if (!header || !trailer) { ok = false; problem = "snapshot header/trailer missing"; }
    if (!ok) {
        if (meta) json_object_put(meta);
        close(lfd);
        return error_json(problem);
    }
    /* Save verified header and trailer within the QIHSE KV generation. */
    const char *meta_json = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    ok = qihse_kv_set(st->kv, "_meta", meta_json, 0, 0);
    struct json_object *end = json_object_new_object();
    json_int(end, "nodes", (int64_t)nodes);
    json_int(end, "edges", (int64_t)edges);
    json_int(end, "unresolved_edges", (int64_t)unresolved);
    json_text(end, "sha256", input_hash);
    ok = ok && qihse_kv_set(st->kv, "_end",
        json_object_to_json_string_ext(end, JSON_C_TO_STRING_PLAIN), 0, 0);
    json_object_put(end);
    if (!ok) { json_object_put(meta); close(lfd);
        return error_json("failed to publish verified metadata in QIHSE KV"); }

    char name[128], published[PATH_MAX], temporary[PATH_MAX];
    snprintf(name, sizeof(name), "graph-%s-%ld.kv", input_hash, (long)getpid());
    snprintf(published, sizeof(published), "%s/%s", st->directory, name);
    snprintf(temporary, sizeof(temporary), "%s/.snapshot-%ld.tmp",
             st->directory, (long)getpid());
    if (qihse_kv_save(st->kv, temporary) != 0) {
        json_object_put(meta); close(lfd);
        return error_json("QIHSE KV snapshot serialization failed");
    }
    char binary_hash[65];
    if (!sha256_file(temporary, binary_hash) || rename(temporary, published) != 0) {
        unlink(temporary); json_object_put(meta); close(lfd);
        return error_json("QIHSE snapshot hashing/publication failed");
    }
    struct json_object *manifest = json_object_new_object();
    json_text(manifest, "snapshot", name);
    json_text(manifest, "sha256", binary_hash);
    json_text(manifest, "head", json_string(meta, "head"));
    json_text(manifest, "worktree", json_string(meta, "worktree"));
    json_int(manifest, "nodes", (int64_t)nodes);
    json_int(manifest, "edges", (int64_t)edges);
    json_int(manifest, "unresolved_edges", (int64_t)unresolved);
    json_text(manifest, "input_sha256", input_hash);
    bool persisted = atomic_write(manifest_path,
        json_object_to_json_string_ext(manifest, JSON_C_TO_STRING_PLAIN));
    if (persisted) {
        struct json_object *result = json_object_new_object();
        json_text(result, "status", "published");
        json_text(result, "snapshot", name);
        json_int(result, "nodes", (int64_t)nodes);
        json_int(result, "edges", (int64_t)edges);
        json_int(result, "unresolved_edges", (int64_t)unresolved);
        json_text(result, "source_sha256", input_hash);
        print_json(result); json_object_put(result);
    }
    json_object_put(meta);
    json_object_put(manifest);
    close(lfd);
    return persisted ? 0 : error_json("manifest publication failed; previous generation retained");
}
