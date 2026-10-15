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
    char *tier = json_string(item, "tier");
    return hex64(id) && file && safe_relative(file) &&
           src && (!*src || hex64(src)) && dst && (!*dst || hex64(dst)) &&
           type && strlen(type) < 32 && resolution &&
           json_num(item, "line") >= 0 && json_double(item, "confidence") >= 0.0 &&
           json_double(item, "confidence") <= 1.0 &&
           (!traversable || (hex64(src) && hex64(dst) && tier &&
                             strcmp(resolution, "direct") == 0 &&
                             strcmp(tier, "EXTRACTED") == 0 &&
                             json_double(item, "confidence") >= 0.8));
}

/* A publication is all-or-nothing: validate the entire JSONL file and QIHSE
 * KV serialization before replacing the manifest naming the active snapshot. */
static bool build_native_graph(cg_state *st, size_t expected_nodes,
                               size_t expected_edges, size_t expected_unresolved);

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
    /* Reject dangling authoritative endpoints before publishing a generation.
     * The QIHSE graph itself is constructed using the same native validator
     * as a subsequent review query. */
    if (!build_native_graph(st, nodes, edges, unresolved)) {
        json_object_put(meta); close(lfd);
        return error_json("invalid CodeGraph structural endpoints or adjacency");
    }

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


/* Rebuild a memory-resident structural graph from one immutable QIHSE KV
 * generation. The QIHSE graph engine provides indexed incident adjacency;
 * raw CRG qualified names are never guessed or re-resolved here. */
static int compare_node_id(const void *a, const void *b) {
    return strcmp(((const cg_node *)a)->id, ((const cg_node *)b)->id);
}
static cg_node *find_node(cg_state *st, const char *id) {
    cg_node probe = {0};
    if (!id || !hex64(id)) return NULL;
    memcpy(probe.id, id, 65);
    return bsearch(&probe, st->nodes, st->nn, sizeof(*st->nodes), compare_node_id);
}
static bool nodes_from_kv(const char *key, const char *value, void *user) {
    cg_state *st = user;
    if (strncmp(key, "n:", 2) != 0) return true;
    struct json_object *row = json_tokener_parse(value);
    if (!row || !validate_node(row) || st->nn >= CG_MAX_NODES) {
        if (row) json_object_put(row);
        st->capacity = SIZE_MAX; /* record parse failure */
        return false;
    }
    if (st->nn == st->capacity) {
        size_t cap = st->capacity ? st->capacity * 2 : 256;
        cg_node *grown = realloc(st->nodes, cap * sizeof(*st->nodes));
        if (!grown) {
            st->capacity = SIZE_MAX;
            json_object_put(row);
            return false;
        }
        st->nodes = grown; st->capacity = cap;
    }
    cg_node *node = &st->nodes[st->nn++];
    memset(node, 0, sizeof(*node));
    snprintf(node->id, sizeof(node->id), "%s", json_string(row, "id"));
    node->file = strdup(json_string(row, "file"));
    node->name = strdup(json_string(row, "name"));
    node->kind = strdup(json_string(row, "kind"));
    node->line = (int)json_num(row, "line_start");
    node->end_line = (int)json_num(row, "line_end");
    node->is_test = json_flag(row, "is_test");
    const char *labels[] = {node->kind};
    const char *keys[] = {"file", "name"};
    graph_prop_t props[2] = {
        graph_prop_make_string(node->file), graph_prop_make_string(node->name),
    };
    node->vertex = qihse_graph_vertex_create(st->graph, labels, 1, keys, props, 2);
    graph_prop_free(&props[0]); graph_prop_free(&props[1]);
    json_object_put(row);
    if (!node->file || !node->name || !node->kind || !node->vertex) {
        st->capacity = SIZE_MAX;
        return false;
    }
    return true;
}
static bool edges_from_kv(const char *key, const char *value, void *user) {
    cg_state *st = user;
    if (strncmp(key, "e:", 2) != 0) return true;
    struct json_object *row = json_tokener_parse(value);
    if (!row || !validate_edge(row)) {
        if (row) json_object_put(row);
        st->edges = SIZE_MAX;
        return false;
    }
    st->edges++;
    if (json_flag(row, "traversable")) {
        cg_node *src = find_node(st, json_string(row, "source"));
        cg_node *dst = find_node(st, json_string(row, "target"));
        if (!src || !dst) {
            st->edges = SIZE_MAX; /* forged authoritative endpoint */
        } else {
            const char *keys[] = {"file", "line", "confidence"};
            graph_prop_t props[3] = {
                graph_prop_make_string(json_string(row, "file")),
                graph_prop_make_int64(json_num(row, "line")),
                graph_prop_make_double(json_double(row, "confidence")),
            };
            uint64_t id = qihse_graph_edge_create(
                st->graph, json_string(row, "relation"), src->vertex, dst->vertex,
                keys, props, 3);
            graph_prop_free(&props[0]);
            if (!id) st->edges = SIZE_MAX;
        }
    } else st->unresolved++;
    json_object_put(row);
    return st->edges != SIZE_MAX;
}

static bool build_native_graph(cg_state *st, size_t expected_nodes,
                               size_t expected_edges, size_t expected_unresolved) {
    if (st->graph) return false;
    st->graph = qihse_graph_create();
    if (!st->graph ||
        !qihse_kv_foreach_user(st->kv, NULL, nodes_from_kv, st) ||
        st->capacity == SIZE_MAX || st->nn != expected_nodes)
        return false;
    qsort(st->nodes, st->nn, sizeof(*st->nodes), compare_node_id);
    st->by_vertex = calloc(st->nn + 2, sizeof(*st->by_vertex));
    if (!st->by_vertex) return false;
    for (size_t i = 0; i < st->nn; ++i) {
        if (st->nodes[i].vertex > st->nn) return false;
        if (i > 0 && strcmp(st->nodes[i - 1].id, st->nodes[i].id) == 0)
            return false;
        st->by_vertex[st->nodes[i].vertex] = &st->nodes[i];
    }
    return qihse_kv_foreach_user(st->kv, NULL, edges_from_kv, st) &&
           st->edges != SIZE_MAX && st->edges == expected_edges &&
           st->unresolved == expected_unresolved;
}

static struct json_object *read_json_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size <= 0 || info.st_size > 32768) { close(fd); return NULL; }
    char *buf = malloc((size_t)info.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    size_t have = 0; bool ok = true;
    while (have < (size_t)info.st_size) {
        ssize_t n = read(fd, buf + have, (size_t)info.st_size - have);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        have += (size_t)n;
    }
    close(fd);
    buf[have] = '\0';
    struct json_object *row = ok ? json_tokener_parse(buf) : NULL;
    free(buf);
    if (row && !json_object_is_type(row, json_type_object)) {
        json_object_put(row);
        return NULL;
    }
    return row;
}
static bool load_snapshot(cg_state *st) {
    char manifest_path[PATH_MAX];
    snprintf(manifest_path, sizeof(manifest_path), "%s/current.json", st->directory);
    st->manifest = read_json_file(manifest_path);
    if (!st->manifest) return false;
    char *snapshot = json_string(st->manifest, "snapshot");
    char *sha = json_string(st->manifest, "sha256");
    if (!snapshot || strncmp(snapshot, "graph-", 6) != 0 ||
        strlen(snapshot) > 120 || strchr(snapshot, '/') ||
        !strstr(snapshot, ".kv") || !hex64(sha)) return false;
    char snapshot_path[PATH_MAX], actual[65];
    if (snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s",
                 st->directory, snapshot) >= (int)sizeof(snapshot_path) ||
        !sha256_file(snapshot_path, actual) || strcmp(actual, sha)) return false;
    if (qihse_kv_load(st->kv, snapshot_path) != 0) return false;
    char *header = qihse_kv_get(st->kv, "_meta");
    char *end = qihse_kv_get(st->kv, "_end");
    if (!header || !end) { free(header); free(end); return false; }
    st->meta = json_tokener_parse(header);
    struct json_object *trailer = json_tokener_parse(end);
    free(header); free(end);
    bool ok = st->meta && trailer &&
              strcmp(json_string(st->meta, "format") ?
                     json_string(st->meta, "format") : "", "qihse-codegraph-v1") == 0 &&
              json_num(st->manifest, "nodes") == json_num(trailer, "nodes") &&
              json_num(st->manifest, "edges") == json_num(trailer, "edges") &&
              json_num(st->manifest, "unresolved_edges") ==
              json_num(trailer, "unresolved_edges");
    if (trailer) json_object_put(trailer);
    if (!ok) return false;
    return build_native_graph(st,
        (size_t)json_num(st->manifest, "nodes"),
        (size_t)json_num(st->manifest, "edges"),
        (size_t)json_num(st->manifest, "unresolved_edges"));
}

/* Git metadata is compared at request time. A changed HEAD, staged work or
 * edited tracked files makes the old snapshot stale and review fails closed. */
static bool git_capture(const char *repo, const char *const args[],
                        unsigned char **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    int fds[2];
    if (pipe(fds) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return false; }
    if (pid == 0) {
        close(fds[0]); dup2(fds[1], STDOUT_FILENO); close(fds[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) { dup2(null, STDERR_FILENO); close(null); }
        if (chdir(repo) != 0) _exit(127);
        execvp("git", (char *const *)args);
        _exit(127);
    }
    close(fds[1]);
    size_t cap = 4096, used = 0;
    unsigned char *buf = malloc(cap);
    bool ok = buf != NULL;
    while (ok) {
        if (used == cap) {
            if (cap >= 4 * 1024 * 1024) { ok = false; break; }
            unsigned char *next = realloc(buf, cap * 2);
            if (!next) { ok = false; break; }
            buf = next; cap *= 2;
        }
        ssize_t n = read(fds[0], buf + used, cap - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) ok = false;
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fds[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!ok || !WIFEXITED(status) || WEXITSTATUS(status)) { free(buf); return false; }
    *out = buf; *out_len = used;
    return true;
}
static bool freshness(cg_state *st, const char **reason) {
    const char *const head_args[] = {"git", "--no-optional-locks",
                                    "rev-parse", "--verify", "HEAD", NULL};
    const char *const status_args[] = {"git", "--no-optional-locks",
                                      "status", "--porcelain=v1", "-z",
                                      "--untracked-files=normal", "--", ".",
                                      ":(exclude).code-review-graph", NULL};
    const char *const diff_args[] = {"git", "--no-optional-locks",
                                    "diff", "--no-ext-diff", "--no-textconv",
                                    "--binary", "HEAD", "--", ".",
                                    ":(exclude).code-review-graph", NULL};
    unsigned char *head = NULL, *worktree = NULL, *diff = NULL;
    size_t nhead = 0, nstatus = 0, ndiff = 0;
    if (!git_capture(st->repository, head_args, &head, &nhead) ||
        !git_capture(st->repository, status_args, &worktree, &nstatus) ||
        !git_capture(st->repository, diff_args, &diff, &ndiff)) {
        free(head); free(worktree); free(diff);
        *reason = "git status/diff verification unavailable or too large";
        return false;
    }
    while (nhead && (head[nhead - 1] == '\n' || head[nhead - 1] == '\r')) nhead--;
    /* Match CRG's exact digest: SHA256(status + NUL + tracked diff).
     * Comparing porcelain status alone misses edits to already-dirty files. */
    char status_hash[65] = {0};
    unsigned char sum[32]; unsigned int n = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    if (ok) ok = EVP_DigestUpdate(ctx, worktree, nstatus) == 1 &&
                 EVP_DigestUpdate(ctx, "\0", 1) == 1 &&
                 EVP_DigestUpdate(ctx, diff, ndiff) == 1 &&
                 EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    if (ok) digest_hex(sum, n, status_hash);
    char *baseline = json_string(st->manifest, "head");
    char *stored_worktree = json_string(st->manifest, "worktree");
    if (!ok || !baseline || !stored_worktree ||
        strlen(baseline) != nhead || memcmp(baseline, head, nhead) != 0 ||
        strcmp(status_hash, stored_worktree) != 0) {
        *reason = "repository changed since index publication";
        ok = false;
    }
    free(head); free(worktree); free(diff);
    return ok;
}
static struct json_object *summary(cg_state *st) {
    struct json_object *obj = json_object_new_object();
    json_text(obj, "backend", "QIHSE native CodeGraph");
    json_text(obj, "format", "qihse-codegraph-v1");
    json_int(obj, "nodes", (int64_t)st->nn);
    json_int(obj, "edges", (int64_t)st->edges);
    json_int(obj, "unresolved_edges", (int64_t)st->unresolved);
    json_text(obj, "head", json_string(st->manifest, "head"));
    const char *reason = NULL;
    bool fresh = freshness(st, &reason);
    json_bool(obj, "fresh", fresh);
    if (!fresh) json_text(obj, "stale_reason", reason);
    return obj;
}
static bool impact_edge(const char *type, bool incoming) {
    if (!strcmp(type, "TESTED_BY")) return !incoming;
    if (!incoming) return false;
    return !strcmp(type, "CALLS") || !strcmp(type, "IMPORTS_FROM") ||
           !strcmp(type, "DEPENDS_ON") || !strcmp(type, "REFERENCES") ||
           !strcmp(type, "INHERITS") || !strcmp(type, "IMPLEMENTS") ||
           !strcmp(type, "HANDLES") || !strcmp(type, "TRIGGERS");
}
static struct json_object *record_node(cg_node *n, int hop, double risk,
                                       bool compact) {
    struct json_object *record = json_object_new_object();
    if (!compact) json_text(record, "id", n->id);
    json_text(record, "file", n->file);
    json_text(record, "symbol", n->name);
    json_text(record, "kind", n->kind);
    json_int(record, "line_start", n->line);
    if (!compact) json_int(record, "line_end", n->end_line);
    json_int(record, "hop", hop);
    json_bool(record, "is_test", n->is_test);
    if (!compact)
        json_object_object_add(record, "risk_hint",
                               json_object_new_double(risk));
    return record;
}
static bool matches_symbol(const cg_node *node, const char *query) {
    return query && *query && (strcasestr(node->name, query) != NULL);
}
static bool matches_file(const cg_node *node, const char *files[], size_t nfiles) {
    for (size_t i = 0; i < nfiles; ++i)
        if (strcmp(node->file, files[i]) == 0) return true;
    return false;
}
static bool safe_git_ref(const char *ref) {
    if (!ref || !*ref || strlen(ref) > 120 || ref[0] == '-') return false;
    for (const char *p = ref; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || strchr("._/~^+-", *p)))
            return false;
    return true;
}
static size_t git_changed_files(cg_state *st, const char *base, char ***names) {
    *names = NULL;
    if (!safe_git_ref(base)) return SIZE_MAX;
    const char *args[] = {"git", "--no-optional-locks", "diff", "--name-only",
                          "-z", "--diff-filter=ACMRT", base, "--", NULL};
    unsigned char *raw = NULL;
    size_t bytes = 0;
    if (!git_capture(st->repository, args, &raw, &bytes)) return SIZE_MAX;
    char **result = calloc(CG_MAX_FILES, sizeof(*result));
    if (!result) { free(raw); return SIZE_MAX; }
    size_t count = 0;
    for (size_t i = 0; i < bytes;) {
        size_t end = i;
        while (end < bytes && raw[end]) end++;
        if (end == bytes || count == CG_MAX_FILES) { count = SIZE_MAX; break; }
        if (end > i) {
            char *path = strndup((const char *)raw + i, end - i);
            if (!safe_relative(path)) { free(path); count = SIZE_MAX; break; }
            result[count++] = path;
        }
        i = end + 1;
    }
    free(raw);
    if (count == SIZE_MAX) {
        for (size_t i = 0; i < CG_MAX_FILES; ++i) free(result[i]);
        free(result); return SIZE_MAX;
    }
    *names = result;
    return count;
}

/* A bounded BFS. Stop at the first hit of each vertex; never claim that a
 * truncated traversal covers all callers/tests. Neighbor retrieval operates
 * against native QIHSE indexed adjacency, never a global edge-table scan. */
static int query_graph(cg_state *st, const char *action, const char *symbol,
                       const char *files[], size_t nfiles, const char *base,
                       int depth, size_t max_nodes, int token_budget) {
    struct json_object *report = summary(st);
    if (!json_flag(report, "fresh")) {
        json_text(report, "error", "stale CodeGraph: run graph_index update");
        print_json(report); json_object_put(report);
        return 2;
    }
    char **changed = NULL;
    if (base) {
        size_t extra = git_changed_files(st, base, &changed);
        if (extra == SIZE_MAX || extra + nfiles > CG_MAX_FILES) {
            json_object_put(report);
            if (changed) {
                for (size_t i = 0; i < extra && i < CG_MAX_FILES; ++i) free(changed[i]);
                free(changed);
            }
            return error_json("git diff failed or changed-file set exceeds limit");
        }
        nfiles = extra;
        files = (const char **)changed;
    }
    if ((!symbol || !*symbol) && nfiles == 0 && strcmp(action, "query") == 0) {
        json_object_put(report);
        return error_json("query requires --symbol or --file");
    }
    depth = depth < 1 ? 1 : depth > 5 ? 5 : depth;
    max_nodes = max_nodes < 1 ? 1 : max_nodes > 256 ? 256 : max_nodes;
    if (token_budget > 0 && max_nodes > (size_t)(token_budget / 45))
        max_nodes = (size_t)(token_budget / 45);
    if (!max_nodes) max_nodes = 1;
    uint8_t *visited = calloc(st->nn + 2, sizeof(*visited));
    uint8_t *distance = calloc(st->nn + 2, sizeof(*distance));
    uint64_t *queue = calloc(max_nodes + 1, sizeof(*queue));
    graph_adj_t *edges = calloc(2048, sizeof(*edges));
    struct json_object *found = json_object_new_array();
    struct json_object *tests = json_object_new_array();
    struct json_object *affected = json_object_new_array();
    struct json_object *evidence = json_object_new_array();
    struct json_object *gaps = json_object_new_array();
    bool truncated = false;
    size_t start = 0, used = 0, seeds = 0;
    if (!visited || !distance || !queue || !edges) {
        json_object_put(report);
        if (changed) { for (size_t i = 0; i < nfiles; ++i) free(changed[i]); free(changed); }
        free(visited); free(distance); free(queue); free(edges);
        json_object_put(found); json_object_put(tests); json_object_put(affected);
        json_object_put(evidence); json_object_put(gaps);
        return error_json("CodeGraph query allocation failed");
    }
    for (size_t i = 0; i < st->nn; ++i) {
        cg_node *n = &st->nodes[i];
        if (!matches_symbol(n, symbol) && !matches_file(n, files, nfiles)) continue;
        seeds++;
        if (used < max_nodes) { visited[n->vertex] = 1; queue[used++] = n->vertex; }
        else truncated = true;
    }
    size_t shown = 0;
    while (start < used) {
        uint64_t id = queue[start++];
        cg_node *node = st->by_vertex[id];
        int hop = distance[id];
        double risk = 0.10 + (node->is_test ? 0.0 : 0.25) +
                      (hop == 0 ? 0.2 : 0.1 / (hop + 1));
        if (strcasestr(node->name, "auth") || strcasestr(node->name, "crypto") ||
            strcasestr(node->name, "alloc")) risk += 0.2;
        if (risk > 1.0) risk = 1.0;
        json_object_array_add(found, record_node(node, hop, risk,
                                                 strcmp(action, "context") == 0));
        shown++;
        if (node->is_test) {
            json_object_array_add(tests, json_object_new_string(node->file));
        }
        bool known = false;
        for (size_t k = 0; k < json_object_array_length(affected); ++k) {
            if (!strcmp(json_object_get_string(json_object_array_get_idx(affected, k)),
                        node->file)) { known = true; break; }
        }
        if (!known && *node->file)
            json_object_array_add(affected, json_object_new_string(node->file));
        if (hop >= depth) continue;
        for (int direction = 0; direction < 2; ++direction) {
            graph_dir_t dir = direction == 0 ?
                              GRAPH_DIR_INCOMING : GRAPH_DIR_OUTGOING;
            size_t count = qihse_graph_get_neighbors(st->graph, id, dir, NULL, edges, 2048);
            if (count == 2048) truncated = true;
            for (size_t e = 0; e < count; ++e) {
                graph_adj_t *adj = &edges[e];
                if (strcmp(action, "query") != 0 &&
                    !impact_edge(adj->edge_type, dir == GRAPH_DIR_INCOMING))
                    continue;
                uint64_t neighbor = adj->neighbor_id;
                if (neighbor > st->nn || visited[neighbor]) continue;
                if (used >= max_nodes) { truncated = true; continue; }
                visited[neighbor] = 1;
                distance[neighbor] = (uint8_t)(hop + 1);
                queue[used++] = neighbor;
                /* Explain each included relationship with its original
                 * source line and confidence. No guessed targets are here. */
                if (json_object_array_length(evidence) < 40 &&
                    strcmp(action, "context") != 0) {
                    graph_edge_t *edge = qihse_graph_edge_get(st->graph, adj->edge_id);
                    if (edge) {
                        cg_node *related = st->by_vertex[neighbor];
                        struct json_object *ev = json_object_new_object();
                        json_text(ev, "relation", adj->edge_type);
                        json_text(ev, "from", dir == GRAPH_DIR_INCOMING ?
                                         related->name : node->name);
                        json_text(ev, "to", dir == GRAPH_DIR_INCOMING ?
                                         node->name : related->name);
                        const graph_prop_t *file = graph_edge_get_property(edge, "file");
                        const graph_prop_t *line = graph_edge_get_property(edge, "line");
                        const graph_prop_t *confidence =
                            graph_edge_get_property(edge, "confidence");
                        if (file && file->type == GRAPH_PROP_STRING)
                            json_text(ev, "file", file->val.s);
                        if (line && line->type == GRAPH_PROP_INT64)
                            json_int(ev, "line", line->val.i);
                        if (confidence && confidence->type == GRAPH_PROP_DOUBLE)
                            json_object_object_add(ev, "confidence",
                                json_object_new_double(confidence->val.d));
                        json_object_array_add(evidence, ev);
                        graph_edge_free(edge);
                    }
                }
            }
        }
    }
    /* A missing direct test edge is a test-coverage hint, never a claim that
     * the function is untested. Caller-level and dynamic coverage differ. */
    if (!strcmp(action, "review")) {
        for (size_t i = 0; i < st->nn && json_object_array_length(gaps) < 40; ++i) {
            cg_node *node = &st->nodes[i];
            if (!visited[node->vertex] || node->is_test || !node->file[0])
                continue;
            bool has_test = false;
            size_t n = qihse_graph_get_neighbors(st->graph, node->vertex,
                          GRAPH_DIR_OUTGOING, "TESTED_BY", edges, 2048);
            if (n) has_test = true;
            n = qihse_graph_get_neighbors(st->graph, node->vertex,
                    GRAPH_DIR_INCOMING, "CALLS", edges, 2048);
            for (size_t j = 0; j < n; ++j)
                if (st->by_vertex[edges[j].neighbor_id]->is_test)
                    has_test = true;
            if (!has_test) {
                struct json_object *gap = json_object_new_object();
                json_text(gap, "symbol", node->name);
                json_text(gap, "file", node->file);
                json_text(gap, "kind", "no direct test relation in indexed graph");
                json_object_array_add(gaps, gap);
            }
        }
    }
    if (!symbol && nfiles == 0 && base)
        json_text(report, "scope", "no changed files at selected Git base");
    json_int(report, "seed_nodes", (int64_t)seeds);
    json_int(report, "shown_nodes", (int64_t)shown);
    json_int(report, "depth", depth);
    json_bool(report, "truncated", truncated);
    json_text(report, "risk_kind", "heuristic review priority; not vulnerability probability");
    json_object_object_add(report, "nodes", found);
    json_object_object_add(report, "affected_files", affected);
    json_object_object_add(report, "candidate_tests", tests);
    if (strcmp(action, "context") == 0) {
        json_object_put(evidence);
        json_object_put(gaps);
    } else {
        json_object_object_add(report, "evidence", evidence);
        json_object_object_add(report, "test_gap_candidates", gaps);
    }
    if (!seeds && (symbol || nfiles)) {
        json_text(report, "error", "no indexed seed nodes; refresh or narrow query");
    } else if (st->unresolved) {
        json_text(report, "uncertainty",
                  "unresolved/low-confidence relations excluded; review not exhaustive");
    }
    print_json(report);
    json_object_put(report);
    if (changed) { for (size_t i = 0; i < nfiles; ++i) free(changed[i]); free(changed); }
    free(visited); free(distance); free(queue); free(edges);
    return seeds || (!symbol && nfiles == 0) ? 0 : 2;
}

static int usage(void) {
    fputs("usage: qihse-codegraph <import|status|query|impact|review|context> "
          "[--repo DIR] [--input JSONL] [--symbol NAME] [--file PATH] "
          "[--base GITREF] [--depth 1..5] [--limit 1..256] "
          "[--max-tokens 128..16000]\n", stderr);
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *action = argv[1], *repo = ".", *input = NULL;
    const char *symbol = NULL, *base = NULL, *files[CG_MAX_FILES] = {0};
    size_t nfiles = 0, limit = 80;
    int depth = 2, tokens = 4000;
    for (int i = 2; i < argc; i++) {
        const char *flag = argv[i];
        if (i + 1 >= argc) return usage();
        const char *value = argv[++i];
        if (!strcmp(flag, "--repo")) repo = value;
        else if (!strcmp(flag, "--input")) input = value;
        else if (!strcmp(flag, "--symbol")) symbol = value;
        else if (!strcmp(flag, "--base")) base = value;
        else if (!strcmp(flag, "--file")) {
            if (nfiles == CG_MAX_FILES || !safe_relative(value)) return usage();
            files[nfiles++] = value;
        } else if (!strcmp(flag, "--depth")) depth = atoi(value);
        else if (!strcmp(flag, "--limit")) limit = (size_t)atoi(value);
        else if (!strcmp(flag, "--max-tokens")) tokens = atoi(value);
        else return usage();
    }
    if (strcmp(action, "import") && strcmp(action, "status") &&
        strcmp(action, "query") && strcmp(action, "impact") &&
        strcmp(action, "review") && strcmp(action, "context")) return usage();
    /* Bare impact/review means "changed since HEAD", never whole-repo
     * pseudo-review with no seeds. Graph context requires an explicit seed. */
    if (!symbol && !base && !nfiles &&
        (!strcmp(action, "impact") || !strcmp(action, "review")))
        base = "HEAD";
    if (tokens < 128 || tokens > 16000 || limit == 0 || limit > 256 ||
        depth < 1 || depth > 5) return usage();
    cg_state st;
    if (!graph_open(&st, repo)) {
        graph_close(&st);
        return error_json("CodeGraph repo/runtime not available");
    }
    int rc;
    if (!strcmp(action, "import")) {
        rc = input ? import_snapshot(&st, input) : usage();
    } else if (!load_snapshot(&st)) {
        rc = error_json("no valid QIHSE CodeGraph generation; import a fresh CRG snapshot");
    } else if (!strcmp(action, "status")) {
        struct json_object *report = summary(&st);
        print_json(report);
        json_object_put(report);
        rc = 0;
    } else {
        rc = query_graph(&st, action, symbol, files, nfiles, base,
                         depth, limit, tokens);
    }
    graph_close(&st);
    return rc;
}
