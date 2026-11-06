/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
/*
 * QIHSE CodeGraph v1: offline, durable, structural-code graph CLI.
 * CRG supplies canonical, evidence-tagged JSONL. QIHSE KV owns snapshot
 * persistence, and the native QIHSE graph engine owns indexed traversal.
 *
 * Optional owner-only Unix reader socket; no remote listener, embedded Python,
 * or SQL/Neo4j dependency.
 * One process reads one published immutable generation; imports publish only
 * after validation, QIHSE KV serialization and fsync.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _XOPEN_SOURCE 700
#include "qihse_audit.h"
#include "qihse_graph_store.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_storage.h"
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define CG_MAX_LINE 262144u
#define CG_MAX_NODES 2000000u
#define CG_MAX_EDGES 8000000u
#define CG_MAX_OUT 100000u
#define CG_MAX_FILES 64u
#define CG_REQUEST_MAX 65536u

typedef struct {
    char id[65];
    char *file, *name, *kind;
    int line, end_line, is_test;
    uint64_t vertex;
} cg_node;

typedef struct {
    qihse_kv_store_t *kv;
    qihse_user_t *principal;
    qihse_graph_t *graph;
    cg_node *nodes;
    cg_node **by_vertex, **by_name, **by_file;
    size_t nn, capacity, edges, unresolved;
    struct json_object *meta, *manifest;
    bool audit_ready;
    int lifecycle_fd, lease_fd;
    char directory[PATH_MAX], repository[PATH_MAX];
    char scratch[PATH_MAX];
} cg_state;

static char *json_string(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field) ||
        !json_object_is_type(field, json_type_string))
        return NULL;
    return (char *)json_object_get_string(field);
}
static int64_t json_num(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field))
        return 0;
    return json_object_get_int64(field);
}
static double json_double(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field))
        return 0;
    return json_object_get_double(field);
}
static bool json_flag(struct json_object *obj, const char *key) {
    struct json_object *field = NULL;
    return json_object_object_get_ex(obj, key, &field) && json_object_get_boolean(field);
}
static void json_text(struct json_object *obj, const char *key, const char *value) {
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}
static void json_int(struct json_object *obj, const char *key, int64_t value) {
    json_object_object_add(obj, key, json_object_new_int64(value));
}
static void json_boolean(struct json_object *obj, const char *key, bool value) {
    json_object_object_add(obj, key, json_object_new_boolean(value));
}
static double monotonic_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0;
}
static _Thread_local double generation_ms, seed_ms, traversal_ms;
static _Thread_local double auth_ms, capability_authorization_ms, snapshot_verify_ms, kv_load_ms,
    graph_build_ms;
static _Thread_local bool output_compact, batch_query;
static _Thread_local const char *requested_match;
static _Thread_local FILE *response_stream;
static pthread_mutex_t graph_api_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t capability_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t generation_lock = PTHREAD_RWLOCK_INITIALIZER;

static bool principal_active(cg_state *st) {
    pthread_mutex_lock(&graph_api_lock);
    bool active =
        qihse_auth_user_is_active(st->principal) && qihse_auth_can_access(st->principal, 0, 0);
    pthread_mutex_unlock(&graph_api_lock);
    return active;
}
static void print_json(struct json_object *obj) {
    FILE *out = response_stream ? response_stream : stdout;
    fputs(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN), out);
    fputc('\n', out);
}
static int error_json(const char *reason) {
    struct json_object *o = json_object_new_object();
    json_text(o, "error", reason);
    print_json(o);
    json_object_put(o);
    return 1;
}
static bool hex_n(const char *v, size_t length) {
    if (!v || strlen(v) != length)
        return false;
    for (size_t i = 0; i < length; ++i)
        if (!((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f')))
            return false;
    return true;
}
static bool hex64(const char *v) { return hex_n(v, 64); }
static bool safe_relative(const char *path) {
    if (!path || *path == '/' || *path == '~' || strchr(path, '\\'))
        return false;
    for (const char *p = path; *p;) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 2 && p[0] == '.' && p[1] == '.') || (n == 4 && !memcmp(p, ".git", 4)))
            return false;
        p = end ? end + 1 : p + n;
    }
    return true;
}
static bool make_directory(const char *path) {
    if (!path || *path != '/' || strlen(path) >= PATH_MAX)
        return false;
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1;; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char old = *p;
        *p = '\0';
        struct stat st;
        if (lstat(buf, &st) != 0) {
            if (errno != ENOENT || mkdir(buf, 0700) != 0)
                return false;
        } else if (!S_ISDIR(st.st_mode))
            return false;
        *p = old;
        if (!old)
            break;
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
    unsigned char sum[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if (!EVP_Digest(data, count, sum, &n, EVP_sha256(), NULL) || n != 32)
        return false;
    digest_hex(sum, n, out);
    return true;
}
static bool sha256_file(const char *path, char out[65], double deadline) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return false;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode)) {
        close(fd);
        return false;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    unsigned char bytes[65536], sum[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    while (ok) {
        if (deadline > 0 && monotonic_ms() >= deadline) {
            ok = false;
            break;
        }
        ssize_t received = read(fd, bytes, sizeof(bytes));
        if (received == 0)
            break;
        if (received < 0) {
            if (errno == EINTR)
                continue;
            ok = false;
            break;
        }
        ok = EVP_DigestUpdate(ctx, bytes, (size_t)received) == 1;
    }
    if (ok)
        ok = EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
    if (ok)
        digest_hex(sum, n, out);
    EVP_MD_CTX_free(ctx);
    close(fd);
    return ok;
}
/* Locks are stable files, never removed during collection. */
static int private_lock(const char *path, int operation, bool create) {
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                        (create ? O_CREAT : 0), 0600);
    struct stat info;
    if (fd < 0) return -1;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 077) || info.st_nlink != 1 || flock(fd, operation)) {
        close(fd);
        return -1;
    }
    return fd;
}
static bool storage_lock(cg_state *st, int operation) {
    return st->lifecycle_fd >= 0 && flock(st->lifecycle_fd, operation) == 0;
}
static struct json_object *read_json_file(const char *path);
static bool load_snapshot_unlocked(cg_state *st, bool build_graph);
static bool snapshot_name(const char *name) {
    if (!name) return false;
    size_t length = strlen(name);
    if (length < 75 || length > 84 || strncmp(name, "graph-", 6) ||
        name[70] != '-' || strcmp(name + length - 3, ".kv")) return false;
    for (size_t i = 6; i < 70; i++)
        if (!((name[i] >= '0' && name[i] <= '9') ||
              (name[i] >= 'a' && name[i] <= 'f'))) return false;
    size_t suffix_length = length - 74;
    bool random_suffix = suffix_length == 6;
    unsigned long pid = 0;
    bool pid_suffix = name[71] != '0';
    for (size_t i = 71; i < length - 3; i++) {
        bool digit = name[i] >= '0' && name[i] <= '9';
        if (!(digit || (name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= 'A' && name[i] <= 'Z'))) random_suffix = false;
        if (pid_suffix) {
            if (!digit) pid_suffix = false;
            else {
                unsigned value = (unsigned)(name[i] - '0');
                if (pid > ((unsigned long)INT_MAX - value) / 10) pid_suffix = false;
                else pid = pid * 10 + value;
            }
        }
    }
    /* Original publishers used getpid(); newer ones use mkstemps(). */
    return random_suffix || pid_suffix;
}
/* Keep the ownership lease until every data entry has been removed. A crash
 * during a large cleanup must leave a runtime that later GC can still identify. */
static int delete_scratch_entry(const char *path, const struct stat *st, int flags,
                                struct FTW *ftw) {
    (void)st;
    (void)flags;
    if (ftw->level == 0 || (ftw->level == 1 && !strcmp(path + ftw->base, ".lease")))
        return 0;
    return remove(path);
}
static int remove_scratch(const char *path) {
    if (nftw(path, delete_scratch_entry, 16, FTW_DEPTH | FTW_PHYS)) return -1;
    char lease[PATH_MAX];
    if (snprintf(lease, sizeof(lease), "%s/.lease", path) >= (int)sizeof(lease)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (unlink(lease) && errno != ENOENT) return -1;
    return rmdir(path);
}
static void graph_close(cg_state *st) {
    if (st->graph)
        qihse_graph_destroy(st->graph);
    if (st->kv)
        qihse_kv_store_destroy(st->kv);
    for (size_t i = 0; i < st->nn; i++) {
        free(st->nodes[i].file);
        free(st->nodes[i].name);
        free(st->nodes[i].kind);
    }
    free(st->nodes);
    free(st->by_name);
    st->by_name = NULL;
    free(st->by_file);
    st->by_file = NULL;
    free(st->by_vertex);
    if (st->meta)
        json_object_put(st->meta);
    if (st->manifest)
        json_object_put(st->manifest);
    if (st->audit_ready) {
        qihse_audit_flush();
        qihse_audit_shutdown();
    }
    if (st->scratch[0] &&
        remove_scratch(st->scratch))
        fprintf(stderr, "CodeGraph scratch cleanup failed: %s\n", strerror(errno));
    if (st->lease_fd >= 0) close(st->lease_fd);
    if (st->lifecycle_fd >= 0) close(st->lifecycle_fd);
}
static bool graph_open(cg_state *st, const char *repo, bool importing) {
    memset(st, 0, sizeof(*st));
    st->lifecycle_fd = st->lease_fd = -1;
    if (!realpath(repo, st->repository))
        return false;
    char work_marker[PATH_MAX];
    if (snprintf(work_marker, sizeof(work_marker), "%s/.git", st->repository) >=
            (int)sizeof(work_marker) ||
        access(work_marker, F_OK) != 0)
        return false;
    const char *state = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
    char base[PATH_MAX];
    if (state && *state)
        snprintf(base, sizeof(base), "%s", state);
    else if (home && *home)
        snprintf(base, sizeof(base), "%s/.local/state", home);
    else
        return false;
    char repo_hash[65];
    if (!sha256_buffer(st->repository, strlen(st->repository), repo_hash))
        return false;
    if (snprintf(st->directory, sizeof(st->directory), "%s/qihse/codegraph/%s", base, repo_hash) >=
        (int)sizeof(st->directory))
        return false;
    if (importing) {
        if (!make_directory(st->directory))
            return false;
    } else {
        struct stat state_stat;
        if (stat(st->directory, &state_stat) != 0 || !S_ISDIR(state_stat.st_mode))
            return false;
    }
    char lock_path[PATH_MAX];
    if (snprintf(lock_path, sizeof(lock_path), "%s/.storage.lock", st->directory) >=
        (int)sizeof(lock_path)) return false;
    st->lifecycle_fd = private_lock(lock_path, LOCK_SH, true);
    if (st->lifecycle_fd < 0) return false;
    if (snprintf(st->scratch, sizeof(st->scratch), "%s/.runtime-XXXXXX", st->directory) >=
            (int)sizeof(st->scratch) ||
        !mkdtemp(st->scratch)) {
        st->scratch[0] = '\0';
        return false;
    }
    if (snprintf(lock_path, sizeof(lock_path), "%s/.lease", st->scratch) >=
        (int)sizeof(lock_path)) return false;
    st->lease_fd = private_lock(lock_path, LOCK_EX | LOCK_NB, true);
    if (st->lease_fd < 0 || !storage_lock(st, LOCK_UN)) return false;
    /* Force QIHSE's KV runtime into our private disposable directory,
     * never the host's production /opt/qihse-data. This process is single
     * purpose; QIHSE caches its data dir for the process lifetime. */
    if (setenv("QIHSE_DATA_DIR", st->scratch, 1) != 0)
        return false;
    /* This offline process has its own authenticated realm. Never inherit
     * credentials or storage from a running QIHSE service. */
    if (unsetenv("QIHSE_OPERATOR_PASSWORD") != 0)
        return false;
    unsigned char secret[32];
    char password[65];
    if (RAND_bytes(secret, sizeof(secret)) != 1)
        return false;
    digest_hex(secret, sizeof(secret), password);
    OPENSSL_cleanse(secret, sizeof(secret));
    st->audit_ready = true;
    double auth_start = monotonic_ms();
    bool initialized = qihse_auth_init();
    bool authenticated = initialized && qihse_auth_bootstrap_operator(password);
    qihse_user_t *operator_user = authenticated ? qihse_auth_authenticate_id(0, password) : NULL;
    if (operator_user && !importing) {
        /* A reader needs only public CodeGraph records. The isolated realm's
         * Operator creates a low-clearance identity; graph snapshot load,
         * iteration and KV reads all carry that identity. */
        qihse_user_t *created =
            qihse_auth_create_user(operator_user, 77u, QIHSE_ROLE_GUEST, 0, 0, password, false);
        if (created)
            st->principal = qihse_auth_authenticate_id(77u, password);
    } else
        st->principal = operator_user;
    OPENSSL_cleanse(password, sizeof(password));
    auth_ms = monotonic_ms() - auth_start;
    if (!st->principal)
        return false;
    st->kv = qihse_kv_store_create();
    if (!st->kv)
        return false;
    return true;
}
static bool atomic_write(const char *path, const char *text, bool *committed) {
    if (committed)
        *committed = false;
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp-XXXXXX", path) >= (int)sizeof(tmp))
        return false;
    int fd = mkstemp(tmp);
    if (fd < 0)
        return false;
    (void)fchmod(fd, 0600);
    size_t offset = 0, count = strlen(text);
    bool ok = true;
    while (offset < count) {
        ssize_t n = write(fd, text + offset, count - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        offset += (size_t)n;
    }
    if (ok)
        ok = fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (ok)
        ok = rename(tmp, path) == 0;
    if (committed)
        *committed = ok;
    if (!ok)
        unlink(tmp);
    if (ok) {
        char directory[PATH_MAX];
        snprintf(directory, sizeof(directory), "%s", path);
        char *slash = strrchr(directory, '/');
        if (slash) {
            *slash = '\0';
            int dfd = open(directory, O_RDONLY | O_DIRECTORY);
            if (dfd >= 0) {
                ok = fsync(dfd) == 0;
                close(dfd);
            } else {
                ok = false;
            }
        }
    }
    return ok;
}
static bool validate_node(struct json_object *item) {
    char *id = json_string(item, "id"), *file = json_string(item, "file");
    char *name = json_string(item, "name"), *kind = json_string(item, "kind");
    struct json_object *classification = NULL, *sci = NULL;
    if ((json_object_object_get_ex(item, "classification", &classification) &&
         (!json_object_is_type(classification, json_type_int) ||
          json_object_get_int64(classification) != 0)) ||
        (json_object_object_get_ex(item, "sci", &sci) &&
         (!json_object_is_type(sci, json_type_int) || json_object_get_int64(sci) != 0)))
        return false;
    return hex64(id) && file && safe_relative(file) && strlen(file) <= 4096 && name &&
           strlen(name) <= 512 && kind && strlen(kind) <= 64 && json_num(item, "line_start") >= 0 &&
           json_num(item, "line_end") >= 0;
}
static bool validate_edge(struct json_object *item) {
    char *id = json_string(item, "id"), *file = json_string(item, "file");
    char *src = json_string(item, "source"), *dst = json_string(item, "target");
    char *type = json_string(item, "relation");
    char *resolution = json_string(item, "resolution");
    bool traversable = json_flag(item, "traversable");
    char *tier = json_string(item, "tier");
    struct json_object *classification = NULL, *sci = NULL;
    if ((json_object_object_get_ex(item, "classification", &classification) &&
         (!json_object_is_type(classification, json_type_int) ||
          json_object_get_int64(classification) != 0)) ||
        (json_object_object_get_ex(item, "sci", &sci) &&
         (!json_object_is_type(sci, json_type_int) || json_object_get_int64(sci) != 0)))
        return false;
    return hex64(id) && file && safe_relative(file) && src && (!*src || hex64(src)) && dst &&
           (!*dst || hex64(dst)) && type && strlen(type) < 32 && resolution &&
           json_num(item, "line") >= 0 && json_double(item, "confidence") >= 0.0 &&
           json_double(item, "confidence") <= 1.0 &&
           (!traversable ||
            (hex64(src) && hex64(dst) && tier && strcmp(resolution, "direct") == 0 &&
             strcmp(tier, "EXTRACTED") == 0 && json_double(item, "confidence") >= 0.8));
}

/* A publication is all-or-nothing: validate the entire JSONL file and QIHSE
 * KV serialization before replacing the manifest naming the active snapshot. */
static bool build_native_graph(cg_state *st, size_t expected_nodes, size_t expected_edges,
                               size_t expected_unresolved);
static bool freshness(cg_state *st, const char **reason);

/* Canonical multiset digest: authenticated enumeration, length-delimited records.
 * Reload the SAME store: separate handles share the process QIHSE_DATA_DIR. */
typedef struct { unsigned char (*hashes)[32]; size_t n, cap; bool ok; } cg_fingerprint;
static bool fingerprint_record(const char *key, const char *value, void *arg) {
    cg_fingerprint *f = arg;
    if (f->n >= CG_MAX_NODES + CG_MAX_EDGES + 2u) return f->ok = false;
    if (f->n == f->cap) {
        size_t cap = f->cap ? f->cap * 2 : 256;
        void *next = realloc(f->hashes, cap * 32);
        if (!next) return f->ok = false;
        f->hashes = next; f->cap = cap;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t kn = strlen(key), vn = strlen(value);
    unsigned char lengths[16];
    for (size_t i = 0; i < 8; ++i) {
        lengths[i] = (uint64_t)kn >> (56 - 8*i);
        lengths[8+i] = (uint64_t)vn >> (56 - 8*i);
    }
    unsigned int n = 0;
    f->ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, lengths, sizeof(lengths)) == 1 &&
        EVP_DigestUpdate(ctx, key, kn) == 1 && EVP_DigestUpdate(ctx, value, vn) == 1 &&
        EVP_DigestFinal_ex(ctx, f->hashes[f->n], &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    if (f->ok) f->n++;
    return f->ok;
}
static int compare_hashes(const void *a, const void *b) { return memcmp(a, b, 32); }
static bool record_fingerprint(cg_state *st, char result[65], size_t *count) {
    cg_fingerprint f = {NULL, 0, 0, true};
    bool ok = qihse_kv_foreach_user(st->kv, st->principal, fingerprint_record, &f) && f.ok;
    if (ok) {
        if (f.n) qsort(f.hashes, f.n, 32, compare_hashes);
        ok = sha256_buffer((const char *)f.hashes, f.n * 32, result);
    }
    *count = f.n;
    free(f.hashes);
    return ok;
}
/* Retain bounded snapshots in memory without installing a runtime SST copy.
 * Large snapshots keep the durable path; auth/corruption never triggers fallback. */
static bool replace_snapshot_store(cg_state *st, const char *path) {
    qihse_kv_store_t *loaded = cg_storage_open(path, st->principal,
                                             UINT64_C(64) << 20, 100000);
    if (loaded) {
        if (st->kv) qihse_kv_store_destroy(st->kv);
        st->kv = loaded;
        return true;
    }
    if (errno != EFBIG && errno != E2BIG) return false;
    if (st->kv) qihse_kv_store_destroy(st->kv);
    st->kv = qihse_kv_store_create();
    return st->kv && cg_storage_load(st->kv, path, st->principal);
}
static bool verify_saved(cg_state *st, const char *path) {
    char before[65], after[65]; size_t n_before, n_after;
    return record_fingerprint(st, before, &n_before) &&
           replace_snapshot_store(st, path) &&
           record_fingerprint(st, after, &n_after) &&
           n_before == n_after && !strcmp(before, after);
}
static int import_snapshot_unlocked(cg_state *st, const char *input) {
    char lock_path[PATH_MAX], manifest_path[PATH_MAX];
    if (snprintf(lock_path, sizeof(lock_path), "%s/.import.lock", st->directory) >=
            (int)sizeof(lock_path) ||
        snprintf(manifest_path, sizeof(manifest_path), "%s/current.json", st->directory) >=
            (int)sizeof(manifest_path))
        return error_json("CodeGraph import path too long");
    int lfd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lfd < 0 || flock(lfd, LOCK_EX) != 0) {
        if (lfd >= 0)
            close(lfd);
        return error_json("cannot obtain CodeGraph import lock");
    }
    int input_fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat source_stat;
    if (input_fd < 0 || fstat(input_fd, &source_stat) || !S_ISREG(source_stat.st_mode)) {
        if (input_fd >= 0)
            close(input_fd);
        close(lfd);
        return error_json("snapshot source must be a regular non-symlink file");
    }
    FILE *stream = fdopen(input_fd, "r");
    if (!stream) {
        close(input_fd);
        close(lfd);
        return error_json("snapshot open failed");
    }
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    bool ok = digest && EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1;
    char *line = NULL;
    size_t capacity = 0, nodes = 0, edges = 0, unresolved = 0;
    bool header = false, trailer = false;
    char input_hash[65] = {0};
    struct json_object *meta = NULL;
    const char *problem = "invalid CodeGraph snapshot";
    ssize_t length;
    while (ok && (length = getline(&line, &capacity, stream)) > 0) {
        if ((size_t)length > CG_MAX_LINE || line[length - 1] != '\n') {
            problem = "oversized/unterminated CodeGraph record";
            ok = false;
            break;
        }
        struct json_object *row = json_tokener_parse(line);
        if (!row || !json_object_is_type(row, json_type_object)) {
            if (row)
                json_object_put(row);
            problem = "malformed JSONL record";
            ok = false;
            break;
        }
        char *type = json_string(row, "t");
        if (!type || trailer) {
            problem = "bad record ordering";
            ok = false;
        } else if (!header) {
            char *format = json_string(row, "format");
            char *head = json_string(row, "head");
            char *worktree = json_string(row, "worktree");
            const char *policy = json_string(row, "freshness");
            const char *worktree_v2 = json_string(row, "worktree_v2");
            if (strcmp(type, "h") || !format || strcmp(format, "qihse-codegraph-v1") ||
                json_num(row, "version") != 1 || !(hex_n(head, 40) || hex_n(head, 64)) ||
                !hex64(worktree) || !policy ||
                strcmp(policy, "git-status-diff-index-untracked-v2") || !hex64(worktree_v2)) {
                problem = "invalid header/version";
                ok = false;
            } else {
                meta = json_object_get(row);
                header = true;
            }
        } else if (strcmp(type, "n") == 0 || strcmp(type, "e") == 0) {
            bool is_node = strcmp(type, "n") == 0;
            if ((is_node ? !validate_node(row) : !validate_edge(row))) {
                problem = "invalid node/edge evidence";
                ok = false;
            } else {
                char key[72];
                snprintf(key, sizeof(key), "%c:%s", is_node ? 'n' : 'e', json_string(row, "id"));
                if (qihse_kv_exists_user(st->kv, key, st->principal) ||
                    !qihse_kv_set_user(st->kv, key, line, 0, 0, st->principal)) {
                    problem = "duplicate record or QIHSE KV write failed";
                    ok = false;
                } else {
                    if (is_node)
                        nodes++;
                    else {
                        edges++;
                        if (!json_flag(row, "traversable"))
                            unresolved++;
                    }
                    if (nodes > CG_MAX_NODES || edges > CG_MAX_EDGES) {
                        problem = "CodeGraph capacity exceeded";
                        ok = false;
                    }
                }
            }
        } else if (strcmp(type, "end") == 0) {
            unsigned char sum[32];
            unsigned int sum_len = 0;
            if (!EVP_DigestFinal_ex(digest, sum, &sum_len) || sum_len != 32) {
                problem = "digest verification unavailable";
                ok = false;
            } else {
                digest_hex(sum, 32, input_hash);
                char *claimed = json_string(row, "sha256");
                if (!claimed || strcmp(claimed, input_hash) ||
                    json_num(row, "nodes") != (int64_t)nodes ||
                    json_num(row, "edges") != (int64_t)edges ||
                    json_num(row, "unresolved_edges") != (int64_t)unresolved) {
                    problem = "snapshot checksum/count mismatch";
                    ok = false;
                } else
                    trailer = true;
            }
        } else {
            problem = "unknown CodeGraph record type";
            ok = false;
        }
        if (ok && !trailer)
            ok = EVP_DigestUpdate(digest, line, (size_t)length) == 1;
        json_object_put(row);
    }
    if (ferror(stream)) {
        ok = false;
        problem = "snapshot read failed";
    }
    fclose(stream);
    free(line);
    EVP_MD_CTX_free(digest);
    if (ok && (!header || !trailer)) {
        ok = false;
        problem = "snapshot header/trailer missing";
    }
    if (!ok) {
        if (meta)
            json_object_put(meta);
        close(lfd);
        return error_json(problem);
    }
    /* Save verified header and trailer within the QIHSE KV generation. */
    const char *meta_json = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    ok = qihse_kv_set_user(st->kv, "_meta", meta_json, 0, 0, st->principal);
    struct json_object *end = json_object_new_object();
    json_int(end, "nodes", (int64_t)nodes);
    json_int(end, "edges", (int64_t)edges);
    json_int(end, "unresolved_edges", (int64_t)unresolved);
    json_text(end, "sha256", input_hash);
    ok = ok && qihse_kv_set_user(st->kv, "_end",
                                 json_object_to_json_string_ext(end, JSON_C_TO_STRING_PLAIN), 0, 0,
                                 st->principal);
    json_object_put(end);
    if (!ok) {
        json_object_put(meta);
        close(lfd);
        return error_json("failed to publish verified metadata in QIHSE KV");
    }
    /* Reject dangling authoritative endpoints before publishing a generation.
     * The QIHSE graph itself is constructed using the same native validator
     * as a subsequent review query. */
    if (!build_native_graph(st, nodes, edges, unresolved)) {
        json_object_put(meta);
        close(lfd);
        return error_json("invalid CodeGraph structural endpoints or adjacency");
    }
    /* The source may change between CRG export and QIHSE import. Verify the
     * very same HEAD + porcelain + content-diff identity before publishing. */
    st->manifest = json_object_new_object();
    json_text(st->manifest, "freshness", "git-status-diff-index-untracked-v2");
    json_text(st->manifest, "head", json_string(meta, "head"));
    json_text(st->manifest, "worktree", json_string(meta, "worktree_v2"));
    const char *stale_reason = NULL;
    bool current = freshness(st, &stale_reason);
    json_object_put(st->manifest);
    st->manifest = NULL;
    if (!current) {
        json_object_put(meta);
        close(lfd);
        return error_json("source changed since CRG export; rebuild before import");
    }

    struct json_object *previous = read_json_file(manifest_path);
    const char *old_name = previous ? json_string(previous, "snapshot") : NULL;
    const char *old_hash = previous ? json_string(previous, "input_sha256") : NULL;
    const char *old_sha = previous ? json_string(previous, "sha256") : NULL;
    char old_path[PATH_MAX], old_actual[65], rollback[128] = {0};
    struct json_object *old_format_field = NULL;
    bool old_format_valid = !previous ||
        !json_object_object_get_ex(previous, "storage_format", &old_format_field) ||
        (json_object_is_type(old_format_field, json_type_string) &&
         !strcmp(json_object_get_string(old_format_field), "qihse-codegraph-zstd-v1"));
    if (snapshot_name(old_name)) {
        snprintf(rollback, sizeof(rollback), "%s", old_name);
        if (old_format_valid && old_hash && !strcmp(old_hash, input_hash) && hex64(old_sha) &&
            snprintf(old_path, sizeof(old_path), "%s/%s", st->directory, old_name) <
                (int)sizeof(old_path) && sha256_file(old_path, old_actual, 0) &&
            !strcmp(old_actual, old_sha) &&
            json_string(previous, "head") &&
            !strcmp(json_string(previous, "head"), json_string(meta, "head")) &&
            json_string(previous, "worktree") &&
            !strcmp(json_string(previous, "worktree"), json_string(meta, "worktree_v2")) &&
            json_string(previous, "freshness") &&
            !strcmp(json_string(previous, "freshness"), "git-status-diff-index-untracked-v2") &&
            json_num(previous, "nodes") == (int64_t)nodes &&
            json_num(previous, "edges") == (int64_t)edges &&
            json_num(previous, "unresolved_edges") == (int64_t)unresolved) {
            if (!verify_saved(st, old_path)) {
                json_object_put(previous); json_object_put(meta); close(lfd);
                return error_json("existing snapshot does not match verified import records");
            }
            st->manifest = previous;
            bool still_current = freshness(st, &stale_reason);
            st->manifest = NULL;
            if (!still_current) {
                json_object_put(previous);
                json_object_put(meta);
                close(lfd);
                return error_json("source changed during unchanged snapshot verification");
            }
            json_text(previous, "status", "unchanged");
            print_json(previous);
            json_object_put(previous);
            json_object_put(meta);
            close(lfd);
            return 0;
        }
    }
    if (previous) json_object_put(previous);
    char name[128], published[PATH_MAX], temporary[PATH_MAX];
    snprintf(name, sizeof(name), "graph-%s-XXXXXX.kv", input_hash);
    if (snprintf(published, sizeof(published), "%s/%s", st->directory, name) >=
            (int)sizeof(published) ||
        snprintf(temporary, sizeof(temporary), "%s/.snapshot-%ld.tmp", st->directory,
                 (long)getpid()) >= (int)sizeof(temporary)) {
        json_object_put(meta);
        close(lfd);
        return error_json("CodeGraph snapshot path too long");
    }
    int reserved = mkstemps(published, 3);
    if (reserved < 0) {
        json_object_put(meta);
        close(lfd);
        return error_json("CodeGraph generation reservation failed");
    }
    close(reserved);
    snprintf(name, sizeof(name), "%s", strrchr(published, '/') + 1);
    if (!cg_storage_save(st->kv, temporary, st->principal)) {
        unlink(published);
        unlink(temporary);
        json_object_put(meta);
        close(lfd);
        return error_json("QIHSE KV snapshot serialization failed");
    }
    char binary_hash[65];
    if (!sha256_file(temporary, binary_hash, 0) || rename(temporary, published) != 0) {
        unlink(published);
        unlink(temporary);
        json_object_put(meta);
        close(lfd);
        return error_json("QIHSE snapshot hashing/publication failed");
    }
    struct json_object *manifest = json_object_new_object();
    json_text(manifest, "snapshot", name);
    json_text(manifest, "storage_format", "qihse-codegraph-zstd-v1");
    if (rollback[0]) json_text(manifest, "previous_snapshot", rollback);
    json_text(manifest, "sha256", binary_hash);
    json_text(manifest, "head", json_string(meta, "head"));
    json_text(manifest, "worktree", json_string(meta, "worktree_v2"));
    json_text(manifest, "freshness", "git-status-diff-index-untracked-v2");
    json_int(manifest, "nodes", (int64_t)nodes);
    json_int(manifest, "edges", (int64_t)edges);
    json_int(manifest, "unresolved_edges", (int64_t)unresolved);
    json_text(manifest, "input_sha256", input_hash);
    st->manifest = manifest;
    current = freshness(st, &stale_reason);
    st->manifest = NULL;
    if (!current) {
        unlink(published);
        json_object_put(meta);
        json_object_put(manifest);
        close(lfd);
        return error_json("source changed during import; previous generation retained");
    }
    bool persisted = atomic_write(
        manifest_path, json_object_to_json_string_ext(manifest, JSON_C_TO_STRING_PLAIN), NULL);
    if (persisted) {
        struct json_object *result = json_object_new_object();
        json_text(result, "status", "published");
        json_text(result, "snapshot", name);
        json_int(result, "nodes", (int64_t)nodes);
        json_int(result, "edges", (int64_t)edges);
        json_int(result, "unresolved_edges", (int64_t)unresolved);
        json_text(result, "source_sha256", input_hash);
        print_json(result);
        json_object_put(result);
    }
    json_object_put(meta);
    json_object_put(manifest);
    close(lfd);
    return persisted ? 0
                     : error_json(
                           "manifest publication or durability failed; inspect current generation");
}

/* Rebuild a memory-resident structural graph from one immutable QIHSE KV
 * generation. The QIHSE graph engine provides indexed incident adjacency;
 * raw CRG qualified names are never guessed or re-resolved here. */
static int compare_node_id(const void *a, const void *b) {
    return strcmp(((const cg_node *)a)->id, ((const cg_node *)b)->id);
}
static int compare_node_pointer_id(const void *a, const void *b) {
    return strcmp((*(cg_node *const *)a)->id, (*(cg_node *const *)b)->id);
}
static int compare_node_name(const void *a, const void *b) {
    const cg_node *x = *(cg_node *const *)a, *y = *(cg_node *const *)b;
    int order = strcasecmp(x->name, y->name);
    return order ? order : strcmp(x->id, y->id);
}
static int compare_node_file(const void *a, const void *b) {
    const cg_node *x = *(cg_node *const *)a, *y = *(cg_node *const *)b;
    int order = strcmp(x->file, y->file);
    return order ? order : compare_node_name(a, b);
}
static size_t node_lower_bound(cg_node **index, size_t count, const char *key, bool file) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *value = file ? index[mid]->file : index[mid]->name;
        if ((file ? strcmp(value, key) : strcasecmp(value, key)) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}
static cg_node *find_node(cg_state *st, const char *id) {
    cg_node probe = {0};
    if (!id || !hex64(id))
        return NULL;
    memcpy(probe.id, id, 65);
    return bsearch(&probe, st->nodes, st->nn, sizeof(*st->nodes), compare_node_id);
}
static bool nodes_from_kv(const char *key, const char *value, void *user) {
    cg_state *st = user;
    if (strncmp(key, "n:", 2) != 0)
        return true;
    struct json_object *row = json_tokener_parse(value);
    if (!row || !validate_node(row) || st->nn >= CG_MAX_NODES) {
        if (row)
            json_object_put(row);
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
        st->nodes = grown;
        st->capacity = cap;
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
        graph_prop_make_string(node->file),
        graph_prop_make_string(node->name),
    };
    node->vertex = qihse_graph_vertex_create(st->graph, labels, 1, keys, props, 2);
    graph_prop_free(&props[0]);
    graph_prop_free(&props[1]);
    json_object_put(row);
    if (!node->file || !node->name || !node->kind || !node->vertex) {
        st->capacity = SIZE_MAX;
        return false;
    }
    return true;
}
static bool edges_from_kv(const char *key, const char *value, void *user) {
    cg_state *st = user;
    if (strncmp(key, "e:", 2) != 0)
        return true;
    struct json_object *row = json_tokener_parse(value);
    if (!row || !validate_edge(row)) {
        if (row)
            json_object_put(row);
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
            uint64_t id = qihse_graph_edge_create(st->graph, json_string(row, "relation"),
                                                  src->vertex, dst->vertex, keys, props, 3);
            graph_prop_free(&props[0]);
            if (!id)
                st->edges = SIZE_MAX;
        }
    } else
        st->unresolved++;
    json_object_put(row);
    return st->edges != SIZE_MAX;
}

static bool build_native_graph(cg_state *st, size_t expected_nodes, size_t expected_edges,
                               size_t expected_unresolved) {
    if (st->graph)
        return false;
    st->graph = qihse_graph_create();
    if (!st->graph ||
        !qihse_kv_foreach_prefix_user(st->kv, "n:", st->principal, nodes_from_kv, st) ||
        st->capacity == SIZE_MAX || st->nn != expected_nodes)
        return false;
    qsort(st->nodes, st->nn, sizeof(*st->nodes), compare_node_id);
    st->by_vertex = calloc(st->nn + 2, sizeof(*st->by_vertex));
    st->by_name = calloc(st->nn + 1, sizeof(*st->by_name));
    st->by_file = calloc(st->nn + 1, sizeof(*st->by_file));
    if (!st->by_vertex || !st->by_name || !st->by_file)
        return false;
    for (size_t i = 0; i < st->nn; ++i) {
        st->by_name[i] = st->by_file[i] = &st->nodes[i];
        if (st->nodes[i].vertex > st->nn)
            return false;
        if (i > 0 && strcmp(st->nodes[i - 1].id, st->nodes[i].id) == 0)
            return false;
        st->by_vertex[st->nodes[i].vertex] = &st->nodes[i];
    }
    qsort(st->by_name, st->nn, sizeof(*st->by_name), compare_node_name);
    qsort(st->by_file, st->nn, sizeof(*st->by_file), compare_node_file);
    return qihse_kv_foreach_prefix_user(st->kv, "e:", st->principal, edges_from_kv, st) &&
           st->edges != SIZE_MAX && st->edges == expected_edges &&
           st->unresolved == expected_unresolved;
}

static struct json_object *read_json_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
        info.st_size > 32768) {
        close(fd);
        return NULL;
    }
    char *buf = malloc((size_t)info.st_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    size_t have = 0;
    bool ok = true;
    while (have < (size_t)info.st_size) {
        ssize_t n = read(fd, buf + have, (size_t)info.st_size - have);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
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
static bool load_snapshot_unlocked(cg_state *st, bool build_graph) {
    double phase_start = monotonic_ms();
    char manifest_path[PATH_MAX];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/current.json", st->directory) >=
        (int)sizeof(manifest_path))
        return false;
    st->manifest = read_json_file(manifest_path);
    if (!st->manifest)
        return false;
    const char *format = json_string(st->manifest, "storage_format");
    struct json_object *format_field;
    if (json_object_object_get_ex(st->manifest, "storage_format", &format_field) &&
        (!format || strcmp(format, "qihse-codegraph-zstd-v1"))) return false;
    char *snapshot = json_string(st->manifest, "snapshot");
    char *sha = json_string(st->manifest, "sha256");
    if (!snapshot || strncmp(snapshot, "graph-", 6) != 0 || strlen(snapshot) > 120 ||
        strchr(snapshot, '/') || !strstr(snapshot, ".kv") || !hex64(sha))
        return false;
    char snapshot_path[PATH_MAX], actual[65];
    if (snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s", st->directory, snapshot) >=
            (int)sizeof(snapshot_path) ||
        !sha256_file(snapshot_path, actual, 0) || strcmp(actual, sha))
        return false;
    snapshot_verify_ms = monotonic_ms() - phase_start;
    phase_start = monotonic_ms();
    bool loaded = replace_snapshot_store(st, snapshot_path);
    kv_load_ms = monotonic_ms() - phase_start;
    if (!loaded)
        return false;
    char *header = qihse_kv_get_user(st->kv, "_meta", st->principal);
    char *end = qihse_kv_get_user(st->kv, "_end", st->principal);
    if (!header || !end) {
        free(header);
        free(end);
        return false;
    }
    st->meta = json_tokener_parse(header);
    struct json_object *trailer = json_tokener_parse(end);
    free(header);
    free(end);
    bool ok = st->meta && trailer &&
              strcmp(json_string(st->meta, "format") ? json_string(st->meta, "format") : "",
                     "qihse-codegraph-v1") == 0 &&
              json_num(st->manifest, "nodes") == json_num(trailer, "nodes") &&
              json_num(st->manifest, "edges") == json_num(trailer, "edges") &&
              json_num(st->manifest, "unresolved_edges") == json_num(trailer, "unresolved_edges");
    if (trailer)
        json_object_put(trailer);
    if (!ok)
        return false;
    if (!build_graph)
        return true;
    phase_start = monotonic_ms();
    bool built = build_native_graph(st, (size_t)json_num(st->manifest, "nodes"),
                                    (size_t)json_num(st->manifest, "edges"),
                                    (size_t)json_num(st->manifest, "unresolved_edges"));
    graph_build_ms = monotonic_ms() - phase_start;
    return built;
}

static bool load_snapshot(cg_state *st, bool build_graph) {
    if (!storage_lock(st, LOCK_SH)) return false;
    bool ok = load_snapshot_unlocked(st, build_graph);
    storage_lock(st, LOCK_UN);
    return ok;
}
static int import_snapshot(cg_state *st, const char *input) {
    if (!storage_lock(st, LOCK_EX)) return error_json("storage lock failed");
    int rc = import_snapshot_unlocked(st, input);
    storage_lock(st, LOCK_UN);
    return rc;
}

/* Conversion preserves source freshness and every KV record; no reindexing. */
static int migrate_snapshot(cg_state *st) {
    if (!storage_lock(st, LOCK_EX)) return error_json("storage lock failed");
    int rc = 1;
    char output[PATH_MAX] = {0}, manifest_path[PATH_MAX];
    bool committed = false;
    const char *failure = "CodeGraph migration failed while loading the current graph";
    if (!load_snapshot_unlocked(st, true)) goto done;
    if (json_string(st->manifest, "storage_format") &&
        !strcmp(json_string(st->manifest, "storage_format"), "qihse-codegraph-zstd-v1")) {
        json_text(st->manifest, "status", "unchanged");
        print_json(st->manifest);
        rc = 0;
        goto done;
    }
    const char *input_hash = json_string(st->manifest, "input_sha256");
    const char *old_name = json_string(st->manifest, "snapshot");
    char previous[128];
    failure = "CodeGraph migration failed: invalid input digest in current manifest";
    if (!hex64(input_hash)) goto done;
    failure = "CodeGraph migration failed: unsupported snapshot filename in current manifest";
    if (!snapshot_name(old_name)) goto done;
    snprintf(previous, sizeof(previous), "%s", old_name);
    failure = "CodeGraph migration failed while creating the compact snapshot";
    if (snprintf(output, sizeof(output), "%s/graph-%s-XXXXXX.kv", st->directory,
                 input_hash) >= (int)sizeof(output)) { output[0] = 0; goto done; }
    int fd = mkstemps(output, 3);
    if (fd < 0) { output[0] = 0; goto done; }
    close(fd);
    char sha[65];
    failure = "CodeGraph migration failed while writing the compact snapshot";
    if (!cg_storage_save(st->kv, output, st->principal)) goto done;
    failure = "CodeGraph migration failed while verifying the compact snapshot";
    if (!verify_saved(st, output) || !sha256_file(output, sha, 0)) goto done;
    json_text(st->manifest, "snapshot", strrchr(output, '/') + 1);
    json_text(st->manifest, "sha256", sha);
    json_text(st->manifest, "storage_format", "qihse-codegraph-zstd-v1");
    json_text(st->manifest, "previous_snapshot", previous);
    failure = "CodeGraph migration failed while publishing the manifest; inspect current status before retry";
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/current.json", st->directory) >=
        (int)sizeof(manifest_path)) goto done;
    if (!atomic_write(manifest_path,
                      json_object_to_json_string_ext(st->manifest, JSON_C_TO_STRING_PLAIN),
                      &committed)) goto done;
    json_text(st->manifest, "status", "migrated");
    print_json(st->manifest);
    rc = 0;
done:
    if (rc && output[0] && !committed) unlink(output);
    storage_lock(st, LOCK_UN);
    return rc ? error_json(failure) : 0;
}
static int collect_snapshots(cg_state *st) {
    if (!storage_lock(st, LOCK_EX)) return error_json("storage lock failed");
    int rc = 1;
    size_t removed = 0, runtimes = 0;
    DIR *dir = NULL;
    /* Authenticate and validate the retained current graph before removing anything. */
    if (!load_snapshot_unlocked(st, true)) goto done;
    const char *current = json_string(st->manifest, "snapshot");
    const char *previous = json_string(st->manifest, "previous_snapshot");
    struct json_object *previous_field = NULL;
    if (!snapshot_name(current) ||
        (json_object_object_get_ex(st->manifest, "previous_snapshot", &previous_field) &&
         !snapshot_name(previous))) goto done;
    dir = opendir(st->directory);
    if (!dir) goto done;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        const char *name = entry->d_name;
        char path[PATH_MAX];
        struct stat info;
        if (snprintf(path, sizeof(path), "%s/%s", st->directory, name) >=
                (int)sizeof(path)) goto done;
        if (lstat(path, &info)) {
            if (errno == ENOENT) continue;
            goto done;
        }
        if (snapshot_name(name) && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
            strcmp(name, current) && (!previous || strcmp(name, previous))) {
            if (unlink(path)) goto done;
            removed++;
        } else if (!strncmp(name, ".runtime-", 9) && S_ISDIR(info.st_mode) &&
                   info.st_uid == geteuid() && !(info.st_mode & 077)) {
            char lease[PATH_MAX];
            if (snprintf(lease, sizeof(lease), "%s/.lease", path) >= (int)sizeof(lease))
                goto done;
            int fd = private_lock(lease, LOCK_EX | LOCK_NB, false);
            if (fd < 0) continue; /* Active or legacy/unmanaged scratch: preserve. */
            int failure = remove_scratch(path);
            close(fd);
            if (failure) goto done;
            runtimes++;
        }
    }
    if (fsync(dirfd(dir))) goto done;
    rc = 0;
done:
    if (dir) closedir(dir);
    storage_lock(st, LOCK_UN);
    struct json_object *report = json_object_new_object();
    json_text(report, "status", rc ? "collection_failed" : "collected");
    json_int(report, "removed_snapshots", (int64_t)removed);
    json_int(report, "removed_runtimes", (int64_t)runtimes);
    print_json(report);
    json_object_put(report);
    return rc;
}

/* Git metadata is compared at request time. A changed HEAD, staged work or
 * edited tracked files makes the old snapshot stale and review fails closed. */
static bool git_capture(const char *repo, const char *const args[], unsigned char **out,
                        size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return false;
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    bool initialized = result == 0;
    if (!result)
        result = posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    if (!result && fds[0] != STDOUT_FILENO)
        result = posix_spawn_file_actions_addclose(&actions, fds[0]);
    if (!result && fds[1] != STDOUT_FILENO)
        result = posix_spawn_file_actions_addclose(&actions, fds[1]);
    if (!result)
        result =
            posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    if (!result)
        result = posix_spawn_file_actions_addchdir_np(&actions, repo);
    posix_spawnattr_t attributes;
    bool attributes_ready = false;
    if (!result) {
        result = posix_spawnattr_init(&attributes);
        attributes_ready = result == 0;
    }
    if (!result)
        result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    if (!result)
        result = posix_spawnattr_setpgroup(&attributes, 0);
    pid_t pid = -1;
    if (!result)
        result = posix_spawnp(&pid, "git", &actions, &attributes, (char *const *)args, environ);
    if (attributes_ready)
        posix_spawnattr_destroy(&attributes);
    if (initialized)
        posix_spawn_file_actions_destroy(&actions);
    if (result) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    close(fds[1]);
    size_t cap = 4096, used = 0;
    unsigned char *buf = malloc(cap);
    bool ok = buf != NULL;
    double deadline = monotonic_ms() + 5000.0;
    while (ok) {
        double remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            ok = false;
            break;
        }
        struct pollfd ready = {.fd = fds[0], .events = POLLIN};
        int polled = poll(&ready, 1, (int)remaining + 1);
        if (polled < 0 && errno == EINTR)
            continue;
        if (polled <= 0) {
            ok = false;
            break;
        }
        if (used == cap) {
            if (cap >= 4 * 1024 * 1024) {
                ok = false;
                break;
            }
            unsigned char *next = realloc(buf, cap * 2);
            if (!next) {
                ok = false;
                break;
            }
            buf = next;
            cap *= 2;
        }
        ssize_t n = read(fds[0], buf + used, cap - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            ok = false;
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(fds[0]);
    int status = 0;
    pid_t waited = -1;
    while (ok) {
        waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid)
            break;
        if ((waited < 0 && errno != EINTR) || monotonic_ms() >= deadline) {
            ok = false;
            break;
        }
        poll(NULL, 0, 1);
    }
    if (!ok) {
        kill(-pid, SIGKILL);
        do {
            waited = waitpid(pid, &status, 0);
        } while (waited < 0 && errno == EINTR);
    }
    if (!ok || waited != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
        free(buf);
        return false;
    }
    *out = buf;
    *out_len = used;
    return true;
}
static bool hash_untracked(cg_state *st, EVP_MD_CTX *ctx) {
    double deadline = monotonic_ms() + 5000.0;
    const char *const args[] = {"git",
                                "--no-optional-locks",
                                "ls-files",
                                "--others",
                                "--exclude-standard",
                                "-z",
                                "--",
                                ".",
                                ":(exclude).code-review-graph",
                                NULL};
    unsigned char *listing = NULL;
    size_t length = 0;
    if (!git_capture(st->repository, args, &listing, &length))
        return false;
    bool ok = true;
    for (size_t offset = 0; ok && offset < length;) {
        if (monotonic_ms() >= deadline) {
            ok = false;
            break;
        }
        char *name = (char *)listing + offset;
        char *end = memchr(name, 0, length - offset);
        if (!end || !*name || !safe_relative(name)) {
            ok = false;
            break;
        }
        offset += (size_t)(end - name) + 1;
        char path[PATH_MAX], digest[65], parent[PATH_MAX], resolved[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", st->repository, name) >= (int)sizeof(path)) {
            ok = false;
            break;
        }
        snprintf(parent, sizeof(parent), "%s", path);
        *strrchr(parent, '/') = 0;
        if (!realpath(parent, resolved)) {
            ok = false;
            break;
        }
        size_t root_len = strlen(st->repository);
        if (strncmp(resolved, st->repository, root_len) ||
            (resolved[root_len] && resolved[root_len] != '/')) {
            ok = false;
            break;
        }
        struct stat info;
        if (lstat(path, &info)) {
            ok = false;
            break;
        }
        const char *kind = "f";
        if (S_ISLNK(info.st_mode)) {
            char target[PATH_MAX];
            ssize_t n = readlink(path, target, sizeof(target));
            kind = "l";
            ok = n >= 0 && n < (ssize_t)sizeof(target) && sha256_buffer(target, (size_t)n, digest);
        } else
            ok = S_ISREG(info.st_mode) && sha256_file(path, digest, deadline);
        if (ok)
            ok = EVP_DigestUpdate(ctx, name, strlen(name) + 1) == 1 &&
                 EVP_DigestUpdate(ctx, kind, 2) == 1 && EVP_DigestUpdate(ctx, digest, 65) == 1;
    }
    free(listing);
    return ok;
}
static bool freshness(cg_state *st, const char **reason) {
    const char *const flags_args[] = {
        "git", "--no-optional-locks",          "ls-files", "--stage", "-v", "-f", "-z", "--",
        ".",   ":(exclude).code-review-graph", NULL};
    unsigned char *flags = NULL;
    size_t nflags = 0, nindex = 0;
    if (!git_capture(st->repository, flags_args, &flags, &nflags)) {
        *reason = "Git index trust flags unavailable";
        return false;
    }
    bool trusted = true;
    for (size_t offset = 0; offset < nflags;) {
        unsigned char *end = memchr(flags + offset, 0, nflags - offset);
        unsigned char flag = flags[offset];
        if (!end || end - (flags + offset) < 3 || flags[offset + 1] != ' ' || flag == 'S' ||
            (flag >= 'a' && flag <= 'z')) {
            trusted = false;
            break;
        }
        size_t next = (size_t)(end - flags) + 1;
        size_t bytes = (size_t)(end - flags - offset) - 1;
        /* Strip the flag and space, preserving the exact --stage -z digest bytes. */
        memmove(flags + nindex, flags + offset + 2, bytes);
        nindex += bytes;
        offset = next;
    }
    if (!trusted) {
        free(flags);
        *reason = "Git index flags (assume-unchanged, skip-worktree or fsmonitor-valid) cannot be "
                  "verified";
        return false;
    }
    const char *const head_args[] = {"git", "--no-optional-locks", "rev-parse", "--verify", "HEAD",
                                     NULL};
    const char *const status_args[] = {"git",
                                       "--no-optional-locks",
                                       "status",
                                       "--porcelain=v1",
                                       "-z",
                                       "--untracked-files=normal",
                                       "--",
                                       ".",
                                       ":(exclude).code-review-graph",
                                       NULL};
    const char *const diff_args[] = {"git",
                                     "--no-optional-locks",
                                     "diff",
                                     "--no-ext-diff",
                                     "--no-textconv",
                                     "--binary",
                                     "HEAD",
                                     "--",
                                     ".",
                                     ":(exclude).code-review-graph",
                                     NULL};
    unsigned char *head = NULL, *worktree = NULL, *diff = NULL, *index = flags;
    size_t nhead = 0, nstatus = 0, ndiff = 0;
    if (!git_capture(st->repository, head_args, &head, &nhead) ||
        !git_capture(st->repository, status_args, &worktree, &nstatus) ||
        !git_capture(st->repository, diff_args, &diff, &ndiff)) {
        free(head);
        free(worktree);
        free(diff);
        free(index);
        *reason = "git status/diff verification unavailable or too large";
        return false;
    }
    while (nhead && (head[nhead - 1] == '\n' || head[nhead - 1] == '\r'))
        nhead--;
    /* v2 also binds staged identity and untracked bytes: porcelain and
     * HEAD diff alone miss index-only changes and already-untracked edits. */
    char status_hash[65] = {0};
    unsigned char sum[32];
    unsigned int n = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    if (ok)
        ok = EVP_DigestUpdate(ctx, worktree, nstatus) == 1 && EVP_DigestUpdate(ctx, "\0", 1) == 1 &&
             EVP_DigestUpdate(ctx, diff, ndiff) == 1 && EVP_DigestUpdate(ctx, "\0", 1) == 1 &&
             EVP_DigestUpdate(ctx, index, nindex) == 1 && EVP_DigestUpdate(ctx, "\0", 1) == 1 &&
             hash_untracked(st, ctx) && EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    if (ok)
        digest_hex(sum, n, status_hash);
    char *baseline = json_string(st->manifest, "head");
    char *stored_worktree = json_string(st->manifest, "worktree");
    if (!ok || !baseline || !stored_worktree || strlen(baseline) != nhead ||
        memcmp(baseline, head, nhead) != 0 || strcmp(status_hash, stored_worktree) != 0) {
        *reason = "repository changed since index publication";
        ok = false;
    }
    free(head);
    free(worktree);
    free(diff);
    free(index);
    return ok;
}
static struct json_object *summary(cg_state *st, bool freshness_verified) {
    struct json_object *obj = json_object_new_object();
    json_text(obj, "backend", "QIHSE native CodeGraph");
    json_text(obj, "format", "qihse-codegraph-v1");
    json_int(obj, "nodes", json_num(st->manifest, "nodes"));
    json_int(obj, "edges", json_num(st->manifest, "edges"));
    json_int(obj, "unresolved_edges", json_num(st->manifest, "unresolved_edges"));
    json_text(obj, "head", json_string(st->manifest, "head"));
    json_text(obj, "generation", json_string(st->manifest, "snapshot"));
    const char *reason = NULL;
    bool fresh = freshness_verified || freshness(st, &reason);
    json_boolean(obj, "fresh", fresh);
    if (!fresh)
        json_text(obj, "stale_reason", reason);
    return obj;
}

/* Account only for the generation the principal has just loaded and authorized.
 * Historical files may have different labels and cannot be enumerated as data
 * merely because their names appear in the same directory. */
static int storage_stats(cg_state *st) {
    if (!storage_lock(st, LOCK_SH)) return error_json("storage lock failed");
    int rc = 1;
    int fd = -1;
    struct stat info;
    unsigned char header[16];
    uint64_t decoded = 0;
    bool compact = false;
    if (!load_snapshot_unlocked(st, false) || !principal_active(st)) goto done;
    const char *name = json_string(st->manifest, "snapshot");
    char path[PATH_MAX];
    if (!snapshot_name(name) ||
        snprintf(path, sizeof(path), "%s/%s", st->directory, name) >= (int)sizeof(path))
        goto done;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || info.st_nlink != 1 || info.st_size < 0 ||
        info.st_blocks < 0 || info.st_blocks > INT64_MAX / 512) goto done;
    ssize_t n = pread(fd, header, sizeof(header), 0);
    if (n < 0) goto done;
    compact = n >= 4 && !memcmp(header, "QCGZ", 4);
    if (compact) {
        if (n != (ssize_t)sizeof(header) || memcmp(header, "QCGZ0001", 8)) goto done;
        for (size_t i = 8; i < sizeof(header); ++i)
            decoded = (decoded << 8) | header[i];
        if (decoded > (UINT64_C(64) << 30)) goto done;
    } else {
        decoded = (uint64_t)info.st_size;
    }
    if (!principal_active(st)) goto done;
    struct json_object *report = summary(st, false);
    json_text(report, "storage_format", compact ? "qihse-codegraph-zstd-v1" : "qihse-kv-legacy");
    json_text(report, "coverage", "authorized_current_generation");
    json_int(report, "encoded_bytes", (int64_t)info.st_size);
    json_int(report, "allocated_bytes", (int64_t)info.st_blocks * 512);
    json_int(report, "decoded_bytes", (int64_t)decoded);
    print_json(report);
    json_object_put(report);
    rc = 0;
done:
    if (fd >= 0) close(fd);
    storage_lock(st, LOCK_UN);
    return rc ? error_json("current CodeGraph storage accounting unavailable") : 0;
}
static bool impact_edge(const char *type, bool incoming) {
    if (!strcmp(type, "TESTED_BY"))
        return !incoming;
    if (!incoming)
        return false;
    return !strcmp(type, "CALLS") || !strcmp(type, "IMPORTS_FROM") || !strcmp(type, "DEPENDS_ON") ||
           !strcmp(type, "REFERENCES") || !strcmp(type, "INHERITS") ||
           !strcmp(type, "IMPLEMENTS") || !strcmp(type, "HANDLES") || !strcmp(type, "TRIGGERS");
}
static bool context_edge(const char *type, bool incoming) {
    if (!strcmp(type, "TESTED_BY"))
        return !incoming;
    return !strcmp(type, "CALLS") || !strcmp(type, "IMPORTS_FROM") || !strcmp(type, "DEPENDS_ON") ||
           !strcmp(type, "REFERENCES") || !strcmp(type, "INHERITS") ||
           !strcmp(type, "IMPLEMENTS") || !strcmp(type, "HANDLES") || !strcmp(type, "TRIGGERS");
}
static struct json_object *record_node(cg_node *n, int hop, double risk, bool compact) {
    struct json_object *record = json_object_new_object();
    if (!compact || output_compact || batch_query)
        json_text(record, "id", n->id);
    json_text(record, "file", n->file);
    json_text(record, "symbol", n->name);
    json_text(record, "kind", n->kind);
    json_int(record, "line_start", n->line);
    json_int(record, "line_end", n->end_line);
    json_int(record, "hop", hop);
    json_boolean(record, "is_test", n->is_test);
    if (!compact)
        json_object_object_add(record, "risk_hint", json_object_new_double(risk));
    return record;
}
static bool safe_git_ref(const char *ref) {
    if (!ref || !*ref || strlen(ref) > 120 || ref[0] == '-')
        return false;
    for (const char *p = ref; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              strchr("._/~^+-", *p)))
            return false;
    return true;
}
static size_t git_changed_files(cg_state *st, const char *base, char ***names) {
    *names = NULL;
    if (!safe_git_ref(base))
        return SIZE_MAX;
    const char *args[] = {"git", "--no-optional-locks", "diff", "--name-only",
                          "-z",  "--diff-filter=ACMRT", base,   "--",
                          NULL};
    unsigned char *raw = NULL;
    size_t bytes = 0;
    if (!git_capture(st->repository, args, &raw, &bytes))
        return SIZE_MAX;
    char **result = calloc(CG_MAX_FILES, sizeof(*result));
    if (!result) {
        free(raw);
        return SIZE_MAX;
    }
    size_t count = 0;
    for (size_t i = 0; i < bytes;) {
        size_t end = i;
        while (end < bytes && raw[end])
            end++;
        if (end == bytes || count == CG_MAX_FILES) {
            count = SIZE_MAX;
            break;
        }
        if (end > i) {
            char *path = strndup((const char *)raw + i, end - i);
            if (!safe_relative(path)) {
                free(path);
                count = SIZE_MAX;
                break;
            }
            result[count++] = path;
        }
        i = end + 1;
    }
    free(raw);
    if (count == SIZE_MAX) {
        for (size_t i = 0; i < CG_MAX_FILES; ++i)
            free(result[i]);
        free(result);
        return SIZE_MAX;
    }
    *names = result;
    return count;
}

/* A bounded BFS. Stop at the first hit of each vertex; never claim that a
 * truncated traversal covers all callers/tests. Neighbor retrieval operates
 * against native QIHSE indexed adjacency, never a global edge-table scan. */
static void select_seed(cg_state *st, cg_node *node, uint8_t *selected, uint64_t *queue,
                        size_t limit, size_t *used, size_t *seeds, bool *truncated) {
    if (selected[node->vertex])
        return;
    selected[node->vertex] = 1;
    (*seeds)++;
    size_t at = *used;
    if (at == limit) {
        *truncated = true;
        if (strcmp(node->id, st->by_vertex[queue[at - 1]]->id) >= 0)
            return;
        at--;
    } else
        (*used)++;
    while (at && strcmp(node->id, st->by_vertex[queue[at - 1]]->id) < 0) {
        queue[at] = queue[at - 1];
        at--;
    }
    queue[at] = node->vertex;
}
static struct json_object *request_error(const char *reason) {
    struct json_object *obj = json_object_new_object();
    json_text(obj, "error", reason);
    return obj;
}
static struct json_object *query_graph(cg_state *st, const char *action, const char *symbol,
                                       const char *files[], size_t nfiles, const char *base,
                                       int depth, size_t max_nodes, int token_budget,
                                       bool freshness_verified, int *rc) {
    *rc = 1;
    struct json_object *report = summary(st, freshness_verified);
    if (!json_flag(report, "fresh")) {
        json_text(report, "error", "stale CodeGraph: run graph_index update");
        *rc = 2;
        return report;
    }
    char **changed = NULL;
    if (base) {
        size_t extra = git_changed_files(st, base, &changed);
        if (extra == SIZE_MAX || extra + nfiles > CG_MAX_FILES) {
            json_object_put(report);
            if (changed) {
                for (size_t i = 0; i < extra && i < CG_MAX_FILES; ++i)
                    free(changed[i]);
                free(changed);
            }
            return request_error("git diff failed or changed-file set exceeds limit");
        }
        nfiles = extra;
        files = (const char **)changed;
    }
    if ((!symbol || !*symbol) && nfiles == 0 && strcmp(action, "query") == 0) {
        json_object_put(report);
        return request_error("query requires --symbol or --file");
    }
    depth = depth < 1 ? 1 : depth > 5 ? 5 : depth;
    max_nodes = max_nodes < 1 ? 1 : max_nodes > 256 ? 256 : max_nodes;
    bool compact = strcmp(action, "context") == 0;
    if (token_budget > 0 && max_nodes > (size_t)(token_budget / (compact ? 80 : 45)))
        max_nodes = (size_t)(token_budget / (compact ? 80 : 45));
    if (!max_nodes)
        max_nodes = 1;
    size_t evidence_limit = compact ? (size_t)(token_budget / 180) : 40;
    if (!evidence_limit)
        evidence_limit = 1;
    if (compact && evidence_limit > 16)
        evidence_limit = 16;
    /* 0 = unseen, 1 = matched seed, 2 + hop = admitted to the bounded walk.
     * Seed candidates outside the output limit remain eligible as neighbours. */
    uint8_t *visited = calloc(st->nn + 2, sizeof(*visited));
    uint64_t *queue = calloc(max_nodes + 1, sizeof(*queue));
    graph_adj_t *edges = calloc(2048, sizeof(*edges));
    struct json_object *found = json_object_new_array();
    struct json_object *tests = json_object_new_array();
    struct json_object *affected = json_object_new_array();
    struct json_object *evidence = json_object_new_array();
    struct json_object *gaps = json_object_new_array();
    bool truncated = false;
    size_t start = 0, used = 0, seeds = 0;
    if (!visited || !queue || !edges) {
        json_object_put(report);
        if (changed) {
            for (size_t i = 0; i < nfiles; ++i)
                free(changed[i]);
            free(changed);
        }
        free(visited);
        free(queue);
        free(edges);
        json_object_put(found);
        json_object_put(tests);
        json_object_put(affected);
        json_object_put(evidence);
        json_object_put(gaps);
        return request_error("CodeGraph query allocation failed");
    }
    double plan_start = monotonic_ms();
    if (symbol && *symbol) {
        char qualified[1025];
        snprintf(qualified, sizeof(qualified), "%s", symbol);
        char *separator = strstr(qualified, "::");
        size_t full = node_lower_bound(st->by_name, st->nn, symbol, false);
        if (separator && (!requested_match || strcmp(requested_match, "qualified"))) {
            *separator = 0;
            size_t file = node_lower_bound(st->by_file, st->nn, qualified, true);
            bool indexed_file = file < st->nn && !strcmp(st->by_file[file]->file, qualified);
            *separator = ':';
            if (!indexed_file || (full < st->nn && !strcasecmp(st->by_name[full]->name, symbol)))
                separator = NULL;
        }
        const char *name = separator ? separator + 2 : symbol;
        if (separator)
            *separator = 0;
        const char *mode = requested_match ? requested_match : "auto";
        size_t first = node_lower_bound(st->by_name, st->nn, name, false);
        bool exact = first < st->nn && !strcasecmp(st->by_name[first]->name, name);
        bool prefix = !strcmp(mode, "prefix");
        bool substring =
            !strcmp(mode, "substring") || (!strcmp(mode, "auto") && !exact && !separator);
        size_t matches = 0, name_length = strlen(name);
        for (size_t i = substring ? 0 : first; i < st->nn; ++i) {
            cg_node *node = st->by_name[i];
            bool match = substring ? strcasestr(node->name, name) != NULL
                         : prefix  ? !strncasecmp(node->name, name, name_length)
                                   : !strcasecmp(node->name, name);
            if (!match && !substring)
                break;
            if (!match || (separator && strcmp(node->file, qualified)))
                continue;
            select_seed(st, node, visited, queue, max_nodes, &used, &seeds, &truncated);
            matches++;
        }
        json_text(report, "seed_match",
                  separator   ? "qualified"
                  : substring ? "substring"
                  : prefix    ? "prefix"
                              : "exact");
        json_boolean(report, "ambiguous", matches > 1);
        json_int(report, "matched_symbols", (int64_t)matches);
    }
    for (size_t f = 0; f < nfiles; ++f) {
        size_t first = node_lower_bound(st->by_file, st->nn, files[f], true);
        for (size_t i = first; i < st->nn && !strcmp(st->by_file[i]->file, files[f]); ++i)
            select_seed(st, st->by_file[i], visited, queue, max_nodes, &used, &seeds, &truncated);
    }
    for (size_t i = 0; i < used; ++i)
        visited[queue[i]] = 2;
    seed_ms += monotonic_ms() - plan_start;
    double walk_start = monotonic_ms();
    size_t shown = 0;
    while (start < used) {
        uint64_t id = queue[start++];
        cg_node *node = st->by_vertex[id];
        int hop = visited[id] - 2;
        double risk = 0.10 + (node->is_test ? 0.0 : 0.25) + (hop == 0 ? 0.2 : 0.1 / (hop + 1));
        if (strcasestr(node->name, "auth") || strcasestr(node->name, "crypto") ||
            strcasestr(node->name, "alloc"))
            risk += 0.2;
        if (risk > 1.0)
            risk = 1.0;
        json_object_array_add(found, record_node(node, hop, risk, compact || output_compact));
        shown++;
        if (node->is_test) {
            json_object_array_add(tests, json_object_new_string(node->file));
        }
        bool known = false;
        for (size_t k = 0; k < json_object_array_length(affected); ++k) {
            if (!strcmp(json_object_get_string(json_object_array_get_idx(affected, k)),
                        node->file)) {
                known = true;
                break;
            }
        }
        if (!known && *node->file)
            json_object_array_add(affected, json_object_new_string(node->file));
        if (hop >= depth)
            continue;
        for (int direction = 0; direction < 2; ++direction) {
            graph_dir_t dir = direction == 0 ? GRAPH_DIR_INCOMING : GRAPH_DIR_OUTGOING;
            size_t count = qihse_graph_get_neighbors(st->graph, id, dir, NULL, edges, 2048);
            if (count == 2048)
                truncated = true;
            for (size_t e = 0; e < count; ++e) {
                graph_adj_t *adj = &edges[e];
                bool incoming = dir == GRAPH_DIR_INCOMING;
                if (strcmp(action, "query") != 0 &&
                    !(compact ? context_edge(adj->edge_type, incoming)
                              : impact_edge(adj->edge_type, incoming)))
                    continue;
                uint64_t neighbor = adj->neighbor_id;
                if (neighbor > st->nn || visited[neighbor] >= 2)
                    continue;
                if (used >= max_nodes) {
                    truncated = true;
                    continue;
                }
                visited[neighbor] = (uint8_t)(hop + 3);
                queue[used++] = neighbor;
                /* Explain each included relationship with its original
                 * source line and confidence. No guessed targets are here. */
                if (json_object_array_length(evidence) < evidence_limit) {
                    graph_edge_t *edge = qihse_graph_edge_get(st->graph, adj->edge_id);
                    if (edge) {
                        cg_node *related = st->by_vertex[neighbor];
                        struct json_object *ev = json_object_new_object();
                        json_text(ev, "relation", adj->edge_type);
                        json_text(ev, "from",
                                  dir == GRAPH_DIR_INCOMING ? related->name : node->name);
                        json_text(ev, "to", dir == GRAPH_DIR_INCOMING ? node->name : related->name);
                        if (batch_query || output_compact) {
                            json_text(ev, "from_id",
                                      dir == GRAPH_DIR_INCOMING ? related->id : node->id);
                            json_text(ev, "to_id",
                                      dir == GRAPH_DIR_INCOMING ? node->id : related->id);
                        }
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
                } else
                    truncated = true;
            }
        }
    }
    /* A missing direct test edge is a test-coverage hint, never a claim that
     * the function is untested. Caller-level and dynamic coverage differ. */
    if (!strcmp(action, "review")) {
        /* Preserve the original ID order while examining only visited nodes. */
        cg_node *review_nodes[256];
        for (size_t i = 0; i < used; ++i)
            review_nodes[i] = st->by_vertex[queue[i]];
        qsort(review_nodes, used, sizeof(*review_nodes), compare_node_pointer_id);
        for (size_t i = 0; i < used && json_object_array_length(gaps) < 40; ++i) {
            cg_node *node = review_nodes[i];
            if (node->is_test || !node->file[0])
                continue;
            bool has_test = false;
            size_t n = qihse_graph_get_neighbors(st->graph, node->vertex, GRAPH_DIR_OUTGOING,
                                                 "TESTED_BY", edges, 2048);
            if (n)
                has_test = true;
            n = qihse_graph_get_neighbors(st->graph, node->vertex, GRAPH_DIR_INCOMING, "CALLS",
                                          edges, 2048);
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
    json_boolean(report, "truncated", truncated);
    json_text(report, "risk_kind", "heuristic review priority; not vulnerability probability");
    json_object_object_add(report, "nodes", found);
    json_object_object_add(report, "affected_files", affected);
    json_object_object_add(report, "candidate_tests", tests);
    if (compact) {
        json_object_object_add(report, "evidence", evidence);
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
    traversal_ms += monotonic_ms() - walk_start;
    if (output_compact) {
        json_object_object_del(report, "risk_kind");
        json_object_object_del(report, "test_gap_candidates");
    }
    if (changed) {
        for (size_t i = 0; i < nfiles; ++i)
            free(changed[i]);
        free(changed);
    }
    free(visited);
    free(queue);
    free(edges);
    *rc = seeds || (!symbol && nfiles == 0) ? 0 : 2;
    return report;
}

/* A generation read lease pins these structures until a request finishes. Replacement
 * takes the write lease; graph/KV APIs remain serialized by graph_api_lock, while
 * filesystem freshness checks and response construction can run independently. */
static void clear_generation(cg_state *st) {
    if (st->graph)
        qihse_graph_destroy(st->graph);
    st->graph = NULL;
    if (st->kv)
        qihse_kv_store_destroy(st->kv);
    st->kv = NULL;
    for (size_t i = 0; i < st->nn; ++i) {
        free(st->nodes[i].file);
        free(st->nodes[i].name);
        free(st->nodes[i].kind);
    }
    free(st->nodes);
    st->nodes = NULL;
    free(st->by_name);
    st->by_name = NULL;
    free(st->by_file);
    st->by_file = NULL;
    free(st->by_vertex);
    st->by_vertex = NULL;
    st->nn = st->capacity = st->edges = st->unresolved = 0;
    if (st->meta)
        json_object_put(st->meta);
    if (st->manifest)
        json_object_put(st->manifest);
    st->meta = st->manifest = NULL;
}

static bool same_manifest(struct json_object *a, struct json_object *b) {
    if (!a || !b)
        return false;
    return json_object_equal(a, b);
}

static bool current_manifest(cg_state *st, struct json_object **out) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/current.json", st->directory) >= (int)sizeof(path))
        return false;
    *out = read_json_file(path);
    return *out != NULL;
}

static bool refresh_generation(cg_state *st) {
    struct json_object *published = NULL;
    bool available = current_manifest(st, &published);
    bool same = available && same_manifest(st->manifest, published);
    if (published)
        json_object_put(published);
    if (!available) {
        clear_generation(st);
        return false;
    }
    if (same && st->graph)
        return true;
    /* Drop the old graph before trying the new publication. An invalid
     * replacement must never leave an older generation serviceable. */
    clear_generation(st);
    st->kv = qihse_kv_store_create();
    if (!st->kv || !load_snapshot(st, true)) {
        clear_generation(st);
        return false;
    }
    return true;
}

static bool paired_socket_paths(const char *socket_path, const char *token_path) {
    if (!socket_path || !token_path || socket_path[0] != '/' || token_path[0] != '/' ||
        strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return false;
    char first[PATH_MAX], second[PATH_MAX];
    snprintf(first, sizeof(first), "%s", socket_path);
    snprintf(second, sizeof(second), "%s", token_path);
    char *a = strrchr(first, '/'), *b = strrchr(second, '/');
    if (!a || !b || !a[1] || !b[1] || strcmp(a + 1, b + 1) == 0)
        return false;
    *a = *b = '\0';
    if (strcmp(first, second) != 0)
        return false;
    struct stat info;
    /* The socket and token must share one real directory (lstat rejects
     * symlinks); no group/other restrictions apply to the directory itself,
     * since the socket and token files carry their own owner-only checks. */
    return lstat(first, &info) == 0 && S_ISDIR(info.st_mode);
}

static bool new_capability(const char *path, char token[65]) {
    unsigned char random[32];
    if (RAND_bytes(random, sizeof(random)) != 1)
        return false;
    char replacement[65], line[66];
    digest_hex(random, sizeof(random), replacement);
    OPENSSL_cleanse(random, sizeof(random));
    snprintf(line, sizeof(line), "%s\n", replacement);
    bool committed = false;
    bool durable = atomic_write(path, line, &committed);
    if (committed)
        memcpy(token, replacement, sizeof(replacement));
    OPENSSL_cleanse(replacement, sizeof(replacement));
    OPENSSL_cleanse(line, sizeof(line));
    return durable;
}

static bool authorized_request(cg_state *st, struct json_object *request, const char token[65]) {
    const char *presented = json_string(request, "token");
    return presented && hex64(presented) && CRYPTO_memcmp(presented, token, 64) == 0 &&
           principal_active(st);
}

static int socket_reply(FILE *out, const char *reason) {
    struct json_object *obj = json_object_new_object();
    json_text(obj, "error", reason);
    fputs(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN), out);
    fputc('\n', out);
    json_object_put(obj);
    return 1;
}

static bool read_action(const char *action) {
    return action &&
           (!strcmp(action, "status") || !strcmp(action, "query") || !strcmp(action, "impact") ||
            !strcmp(action, "review") || !strcmp(action, "context"));
}
static bool valid_match(const char *mode) {
    return !mode || !strcmp(mode, "auto") || !strcmp(mode, "exact") || !strcmp(mode, "qualified") ||
           !strcmp(mode, "prefix") || !strcmp(mode, "substring");
}
static void timing_field(struct json_object *obj, const char *key, double value) {
    json_object_object_add(obj, key, json_object_new_double(value));
}
static int compare_context_nodes(const void *first, const void *second) {
    struct json_object *a = *(struct json_object *const *)first;
    struct json_object *b = *(struct json_object *const *)second;
    int64_t left = json_num(a, "hop"), right = json_num(b, "hop");
    if (left != right)
        return left < right ? -1 : 1;
    const char *a_id = json_string(a, "id"), *b_id = json_string(b, "id");
    assert(a_id && b_id);
    return strcmp(a_id, b_id);
}
static void remove_batch_node(struct json_object *nodes, size_t index, struct json_object *mapping,
                              struct json_object *evidence, struct json_object *seen,
                              struct json_object *edge_seen) {
    const char *id = json_string(json_object_array_get_idx(nodes, index), "id");
    assert(id);
    json_object_object_foreach(mapping, key, entry) {
        (void)key;
        struct json_object *ids = NULL;
        if (!json_object_object_get_ex(entry, "node_ids", &ids))
            continue;
        for (size_t j = json_object_array_length(ids); j > 0; --j)
            if (!strcmp(json_object_get_string(json_object_array_get_idx(ids, j - 1)), id))
                json_object_array_del_idx(ids, j - 1, 1);
    }
    for (size_t j = json_object_array_length(evidence); j > 0; --j) {
        struct json_object *edge = json_object_array_get_idx(evidence, j - 1);
        const char *from = json_string(edge, "from_id"), *to = json_string(edge, "to_id");
        if ((from && !strcmp(from, id)) || (to && !strcmp(to, id))) {
            if (edge_seen)
                json_object_object_del(
                    edge_seen, json_object_to_json_string_ext(edge, JSON_C_TO_STRING_PLAIN));
            json_object_array_del_idx(evidence, j - 1, 1);
        }
    }
    if (seen)
        json_object_object_del(seen, id);
    json_object_array_del_idx(nodes, index, 1);
}
static struct json_object *execute_read(cg_state *st, struct json_object *request, int *rc) {
    double started = monotonic_ms();
    seed_ms = traversal_ms = 0;
    batch_query = false;
    const char *command = json_string(request, "command"), *symbol = json_string(request, "symbol");
    const char *base = json_string(request, "base"), *repo = json_string(request, "repo");
    const char *mode = json_string(request, "match");
    struct json_object *field = NULL, *symbols = NULL;
    int64_t depth =
        json_object_object_get_ex(request, "depth", &field) ? json_num(request, "depth") : 2;
    int64_t limit =
        json_object_object_get_ex(request, "limit", &field) ? json_num(request, "limit") : 80;
    int64_t tokens = json_object_object_get_ex(request, "max_tokens", &field)
                         ? json_num(request, "max_tokens")
                         : 4000;
    const char *files[CG_MAX_FILES];
    size_t nfiles = 0;
    *rc = 1;
    if (!read_action(command) || !valid_match(mode) || depth < 1 || depth > 5 || limit < 1 ||
        limit > 256 || tokens < 128 || tokens > 16000 ||
        (symbol && (!*symbol || strlen(symbol) > 1024)) || (base && !safe_git_ref(base)))
        return request_error("invalid bounded CodeGraph request");
    if (repo) {
        char canonical[PATH_MAX];
        if (!realpath(repo, canonical) || strcmp(canonical, st->repository))
            return request_error("CodeGraph reader repository mismatch");
    }
    if (json_object_object_get_ex(request, "files", &field)) {
        if (!json_object_is_type(field, json_type_array) ||
            json_object_array_length(field) > CG_MAX_FILES)
            return request_error("invalid bounded CodeGraph files");
        for (size_t i = 0; i < json_object_array_length(field); ++i) {
            struct json_object *value = json_object_array_get_idx(field, i);
            const char *file =
                json_object_is_type(value, json_type_string) ? json_object_get_string(value) : NULL;
            if (!file || !*file || !safe_relative(file))
                return request_error("invalid CodeGraph file");
            files[nfiles++] = file;
        }
    }
    const char *file = json_string(request, "file");
    if (file) {
        if (nfiles == CG_MAX_FILES || !*file || !safe_relative(file))
            return request_error("invalid CodeGraph file");
        files[nfiles++] = file;
    }
    bool batch = json_object_object_get_ex(request, "symbols", &symbols);
    if (batch && (!json_object_is_type(symbols, json_type_array) ||
                  !json_object_array_length(symbols) || json_object_array_length(symbols) > 32 ||
                  symbol || base || nfiles || !strcmp(command, "status")))
        return request_error("invalid bounded CodeGraph symbols");
    if (batch)
        for (size_t i = 0; i < json_object_array_length(symbols); ++i) {
            struct json_object *value = json_object_array_get_idx(symbols, i);
            if (!json_object_is_type(value, json_type_string) || !*json_object_get_string(value) ||
                strlen(json_object_get_string(value)) > 1024)
                return request_error("invalid CodeGraph batch symbol");
        }
    if (!symbol && !base && !nfiles && !batch &&
        (!strcmp(command, "impact") || !strcmp(command, "review")))
        base = "HEAD";
    requested_match = mode;
    output_compact = json_flag(request, "compact");
    seed_ms = traversal_ms = 0;
    const char *reason = NULL;
    double begin = monotonic_ms();
    bool fresh = freshness(st, &reason);
    double pre_ms = monotonic_ms() - begin;
    if (!fresh) {
        struct json_object *report = summary(st, true);
        json_boolean(report, "fresh", false);
        json_text(report, "stale_reason", reason);
        if (strcmp(command, "status"))
            json_text(report, "error", "stale CodeGraph: run graph_index update");
        *rc = !strcmp(command, "status") ? 0 : 2;
        return report;
    }
    begin = monotonic_ms();
    struct json_object *report = NULL;
    if (!strcmp(command, "status")) {
        report = summary(st, true);
        *rc = 0;
    } else if (!batch) {
        pthread_mutex_lock(&graph_api_lock);
        report = query_graph(st, command, symbol, files, nfiles, base, (int)depth, (size_t)limit,
                             (int)tokens, true, rc);
        pthread_mutex_unlock(&graph_api_lock);
    } else {
        report = summary(st, true);
        struct json_object *mapping = json_object_new_object();
        struct json_object *all_evidence = json_object_new_array();
        struct json_object *evidence_seen = json_object_new_object();
        struct json_object *unique = json_object_new_array(), *seen = json_object_new_object();
        size_t budget = (size_t)limit;
        if (budget > (size_t)tokens / 180)
            budget = (size_t)tokens / 180;
        if (!budget)
            budget = 1;
        bool truncated = false;
        *rc = 0;
        for (size_t i = 0; i < json_object_array_length(symbols); ++i) {
            const char *name = json_object_get_string(json_object_array_get_idx(symbols, i));
            struct json_object *prior = NULL;
            if (json_object_object_get_ex(mapping, name, &prior))
                continue;
            int query_rc = 0;
            batch_query = true;
            pthread_mutex_lock(&graph_api_lock);
            struct json_object *item = query_graph(st, command, name, NULL, 0, NULL, (int)depth,
                                                   budget, (int)tokens, true, &query_rc);
            pthread_mutex_unlock(&graph_api_lock);
            batch_query = false;
            if (!item) {
                *rc = 1;
                break;
            }
            struct json_object *nodes = NULL, *ids = json_object_new_array();
            struct json_object *entry = json_object_new_object();
            json_object_object_add(entry, "node_ids", ids);
            json_object_object_add(mapping, name, entry);
            if (json_object_object_get_ex(item, "nodes", &nodes) &&
                json_object_is_type(nodes, json_type_array)) {
                for (size_t j = 0; j < json_object_array_length(nodes); ++j) {
                    struct json_object *node = json_object_array_get_idx(nodes, j), *known = NULL;
                    const char *id = json_string(node, "id");
                    if (!id)
                        continue;
                    if (json_object_object_get_ex(seen, id, &known)) {
                        for (size_t k = 0; k < json_object_array_length(unique); ++k) {
                            struct json_object *prior_node = json_object_array_get_idx(unique, k);
                            if (!strcmp(json_string(prior_node, "id"), id) &&
                                json_num(node, "hop") < json_num(prior_node, "hop")) {
                                json_object_array_put_idx(unique, k, json_object_get(node));
                                break;
                            }
                        }
                        json_object_array_add(ids, json_object_new_string(id));
                        continue;
                    }
                    if (json_object_array_length(unique) >= budget) {
                        truncated = true;
                        size_t victim = 0;
                        struct json_object *worst = json_object_array_get_idx(unique, 0);
                        for (size_t k = 1; k < json_object_array_length(unique); ++k) {
                            struct json_object *candidate = json_object_array_get_idx(unique, k);
                            if (compare_context_nodes(&candidate, &worst) > 0) {
                                victim = k;
                                worst = candidate;
                            }
                        }
                        /* Later seeds must not lose their slots to earlier neighbourhoods. */
                        if (compare_context_nodes(&node, &worst) >= 0)
                            continue;
                        remove_batch_node(unique, victim, mapping, all_evidence, seen,
                                          evidence_seen);
                    }
                    json_object_object_add(seen, id, json_object_new_boolean(true));
                    json_object_array_add(unique, json_object_get(node));
                    json_object_array_add(ids, json_object_new_string(id));
                }
            }
            struct json_object *relationships = NULL;
            if (json_object_object_get_ex(item, "evidence", &relationships)) {
                for (size_t j = 0; j < json_object_array_length(relationships); ++j) {
                    struct json_object *edge = json_object_array_get_idx(relationships, j),
                                       *known = NULL;
                    const char *from = json_string(edge, "from_id"),
                               *to = json_string(edge, "to_id");
                    if (!from || !to || !json_object_object_get_ex(seen, from, &known) ||
                        !json_object_object_get_ex(seen, to, &known)) {
                        truncated = true;
                        continue;
                    }
                    const char *key = json_object_to_json_string_ext(edge, JSON_C_TO_STRING_PLAIN);
                    if (json_object_object_get_ex(evidence_seen, key, &known))
                        continue;
                    if (json_object_array_length(all_evidence) >= budget) {
                        truncated = true;
                        continue;
                    }
                    json_object_object_add(evidence_seen, key, json_object_new_boolean(true));
                    json_object_array_add(all_evidence, json_object_get(edge));
                }
            }
            truncated = truncated || json_flag(item, "truncated");
            json_object_object_foreach(item, key, value) {
                if (!strcmp(key, "seed_nodes") || !strcmp(key, "seed_match") ||
                    !strcmp(key, "ambiguous") || !strcmp(key, "error"))
                    json_object_object_add(entry, key, json_object_get(value));
            }
            json_object_put(item);
            if (query_rc == 1)
                *rc = 1;
        }
        json_object_array_sort(unique, compare_context_nodes);
        json_object_object_add(report, "nodes", unique);
        json_object_object_add(report, "evidence", all_evidence);
        json_object_object_add(report, "symbol_results", mapping);
        json_int(report, "shown_nodes", (int64_t)json_object_array_length(unique));
        json_boolean(report, "truncated", truncated);
        json_object_put(seen);
        json_object_put(evidence_seen);
    }
    double query_ms = monotonic_ms() - begin;
    begin = monotonic_ms();
    struct json_object *published = NULL;
    bool current = current_manifest(st, &published) && same_manifest(st->manifest, published) &&
                   freshness(st, &reason) && principal_active(st);
    if (published)
        json_object_put(published);
    double post_ms = monotonic_ms() - begin;
    if (!current || !report) {
        if (report)
            json_object_put(report);
        *rc = 1;
        return request_error(current ? "CodeGraph response allocation failed"
                                     : "CodeGraph changed during query");
    }
    if (json_flag(request, "timings")) {
        struct json_object *timings = json_object_new_object();
        timing_field(timings, "generation_load_ms", generation_ms);
        timing_field(timings, "auth_ms", auth_ms);
        timing_field(timings, "capability_authorization_ms", capability_authorization_ms);
        timing_field(timings, "snapshot_verify_ms", snapshot_verify_ms);
        timing_field(timings, "kv_load_ms", kv_load_ms);
        timing_field(timings, "graph_build_ms", graph_build_ms);
        timing_field(timings, "freshness_pre_ms", pre_ms);
        timing_field(timings, "seed_plan_ms", seed_ms);
        timing_field(timings, "traversal_ms", traversal_ms);
        timing_field(timings, "query_ms", query_ms);
        timing_field(timings, "freshness_post_ms", post_ms);
        timing_field(timings, "total_ms", monotonic_ms() - started + generation_ms);
        json_object_object_add(report, "timings", timings);
    }
    if (batch) {
        struct json_object *nodes = NULL, *evidence = NULL, *mapping = NULL;
        json_object_object_get_ex(report, "nodes", &nodes);
        json_object_object_get_ex(report, "evidence", &evidence);
        json_object_object_get_ex(report, "symbol_results", &mapping);
        while (strlen(json_object_to_json_string_ext(report, JSON_C_TO_STRING_PLAIN)) >
               (size_t)tokens * 4) {
            json_boolean(report, "truncated", true);
            size_t edges = json_object_array_length(evidence),
                   count = json_object_array_length(nodes);
            if (edges) {
                json_object_array_del_idx(evidence, edges - 1, 1);
                continue;
            }
            if (!count) {
                json_object_put(report);
                *rc = 1;
                return request_error("CodeGraph batch metadata exceeds shared token budget");
            }
            remove_batch_node(nodes, count - 1, mapping, evidence, NULL, NULL);
            json_int(report, "shown_nodes", (int64_t)count - 1);
        }
    }
    return report;
}
static struct json_object *format_response(cg_state *st, struct json_object *request,
                                           struct json_object *report) {
    bool compact = json_flag(request, "compact");
    bool timed = compact || json_flag(request, "timings");
    struct json_object *nodes = NULL, *relations = NULL, *mapping = NULL;
    json_object_object_get_ex(report, "nodes", &nodes);
    json_object_object_get_ex(report, "evidence", &relations);
    json_object_object_get_ex(report, "symbol_results", &mapping);
    if (compact) {
        struct json_object *out = json_object_new_object();
        struct json_object *fresh_field = NULL;
        bool stale = json_object_object_get_ex(report, "fresh", &fresh_field) &&
                     !json_object_get_boolean(fresh_field);
        const char *error = json_string(report, "error");
        const char *strategy = json_string(report, "seed_match");
        if (!strategy)
            strategy = mapping ? "batch" : "file-or-status";
        const char *why =
            !strcmp(strategy, "substring")
                ? "explicit substring or no exact name; bounded scan retains ambiguity"
            : !strcmp(strategy, "prefix")
                ? "indexed case-insensitive prefix; bounded output retains ambiguity"
            : !strcmp(strategy, "qualified")
                ? "indexed name constrained to exact repository-relative file"
            : !strcmp(strategy, "batch")
                ? "shared freshness and output budget; symbols and node IDs deduplicated"
            : !strcmp(strategy, "exact")
                ? "indexed case-insensitive exact name; bounded output retains ambiguity"
                : "repository-relative file index or generation status";
        json_text(out, "schema", "qihse.codegraph.search.v1");
        json_text(out, "status", stale ? "stale" : error ? "error" : "ok");
        json_boolean(out, "fresh", fresh_field && json_object_get_boolean(fresh_field) && !error);
        const char *generation = json_string(report, "generation");
        if (!generation)
            generation = json_string(st->manifest, "generation");
        json_object_object_add(out, "generation",
                               generation ? json_object_new_string(generation)
                                          : json_object_new_null());
        json_text(out, "strategy", strategy);
        json_text(out, "strategy_reason", why);
        json_boolean(out, "truncated", json_flag(report, "truncated"));
        if (error)
            json_text(out, "error", error);
        const char *reason = json_string(report, "stale_reason");
        if (reason)
            json_text(out, "stale_reason", reason);
        struct json_object *matches = nodes && json_object_is_type(nodes, json_type_array)
                                          ? json_object_get(nodes)
                                          : json_object_new_array();
        struct json_object *edges = relations && json_object_is_type(relations, json_type_array)
                                        ? json_object_get(relations)
                                        : json_object_new_array();
        json_object_object_add(out, "matches", matches);
        json_object_object_add(out, "relations", edges);
        struct json_object *unresolved = json_object_new_array();
        if (!stale && !error && st->unresolved) {
            struct json_object *gap = json_object_new_object();
            json_int(gap, "count", (int64_t)st->unresolved);
            json_text(gap, "reason",
                      "unresolved/low-confidence relations excluded; details not materialized");
            json_object_array_add(unresolved, gap);
        }
        json_object_object_add(out, "unresolved", unresolved);
        if (mapping)
            json_object_object_add(out, "symbol_results", json_object_get(mapping));
        struct json_object *value = NULL;
        const char *keys[] = {"seed_nodes", "ambiguous", "matched_symbols"};
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
            if (json_object_object_get_ex(report, keys[i], &value))
                json_object_object_add(out, keys[i], json_object_get(value));
        struct json_object *budget = json_object_new_object(), *counts = json_object_new_object();
        json_int(budget, "max_tokens",
                 json_num(request, "max_tokens") ? json_num(request, "max_tokens") : 4000);
        json_int(budget, "node_limit",
                 json_num(request, "limit") ? json_num(request, "limit") : 80);
        json_text(budget, "token_estimate", "serialized UTF-8 bytes / 4");
        json_object_object_add(out, "budget", budget);
        json_int(counts, "matches", (int64_t)json_object_array_length(matches));
        json_int(counts, "relations", (int64_t)json_object_array_length(edges));
        json_int(counts, "excluded_relations", (!stale && !error) ? (int64_t)st->unresolved : 0);
        json_object_object_add(out, "counts", counts);
        json_object_put(report);
        report = out;
    }
    if (timed) {
        /* Measure payload encoding before adding its own timing fields. */
        double begin = monotonic_ms();
        (void)json_object_to_json_string_ext(report, JSON_C_TO_STRING_PLAIN);
        double serialization_ms = monotonic_ms() - begin;
        if (compact) {
            struct json_object *timings = json_object_new_object();
            timing_field(timings, "auth", auth_ms * 1000.0);
            timing_field(timings, "capability_authorization", capability_authorization_ms * 1000.0);
            timing_field(timings, "snapshot_verify", snapshot_verify_ms * 1000.0);
            timing_field(timings, "kv_load", kv_load_ms * 1000.0);
            timing_field(timings, "graph_build", graph_build_ms * 1000.0);
            timing_field(timings, "lookup", seed_ms * 1000.0);
            timing_field(timings, "traversal", traversal_ms * 1000.0);
            timing_field(timings, "serialization", serialization_ms * 1000.0);
            json_object_object_add(report, "timing_us", timings);
        } else {
            struct json_object *timings = NULL;
            if (!json_object_object_get_ex(report, "timings", &timings)) {
                timings = json_object_new_object();
                json_object_object_add(report, "timings", timings);
            }
            timing_field(timings, "serialization_ms", serialization_ms);
        }
    }
    if (compact) {
        int64_t tokens = json_num(request, "max_tokens");
        if (tokens < 128 || tokens > 16000)
            tokens = 4000;
        struct json_object *matches = NULL, *edges = NULL, *counts = NULL;
        json_object_object_get_ex(report, "matches", &matches);
        json_object_object_get_ex(report, "relations", &edges);
        json_object_object_get_ex(report, "counts", &counts);
        json_object_object_get_ex(report, "symbol_results", &mapping);
        while (strlen(json_object_to_json_string_ext(report, JSON_C_TO_STRING_PLAIN)) >
               (size_t)tokens * 4) {
            json_boolean(report, "truncated", true);
            size_t ne = json_object_array_length(edges), nn = json_object_array_length(matches);
            if (ne) {
                json_object_array_del_idx(edges, ne - 1, 1);
                json_int(counts, "relations", (int64_t)ne - 1);
                continue;
            }
            if (!nn) {
                json_object_put(report);
                report = request_error("CodeGraph compact metadata exceeds token budget");
                json_text(report, "schema", "qihse.codegraph.search.v1");
                json_text(report, "status", "error");
                json_boolean(report, "fresh", false);
                json_object_object_add(report, "generation", json_object_new_null());
                json_object_object_add(report, "timing_us", json_object_new_object());
                json_text(report, "strategy", "budget");
                json_text(report, "strategy_reason", "metadata cannot fit");
                json_object_object_add(report, "matches", json_object_new_array());
                json_object_object_add(report, "relations", json_object_new_array());
                json_object_object_add(report, "unresolved", json_object_new_array());
                json_boolean(report, "truncated", true);
                break;
            }
            const char *id = json_string(json_object_array_get_idx(matches, nn - 1), "id");
            if (mapping && id) {
                json_object_object_foreach(mapping, key, entry) {
                    (void)key;
                    struct json_object *ids = NULL;
                    if (!json_object_object_get_ex(entry, "node_ids", &ids))
                        continue;
                    for (size_t j = json_object_array_length(ids); j > 0; --j)
                        if (!strcmp(json_object_get_string(json_object_array_get_idx(ids, j - 1)),
                                    id))
                            json_object_array_del_idx(ids, j - 1, 1);
                }
            }
            json_object_array_del_idx(matches, nn - 1, 1);
            json_int(counts, "matches", (int64_t)nn - 1);
        }
    }
    return report;
}

static void serve_request(cg_state *st, FILE *stream, const char *token_path, char token[65],
                          double deadline) {
    char *line = malloc(CG_REQUEST_MAX + 2);
    if (!line) {
        socket_reply(stream, "request allocation failed");
        return;
    }
    size_t used = 0;
    bool complete = false;
    while (used <= CG_REQUEST_MAX) {
        double remaining = deadline - monotonic_ms();
        if (remaining <= 0)
            break;
        struct pollfd ready = {.fd = fileno(stream), .events = POLLIN};
        int polled = poll(&ready, 1, (int)remaining + 1);
        if (polled < 0 && errno == EINTR)
            continue;
        if (polled <= 0)
            break;
        ssize_t n = recv(fileno(stream), line + used, CG_REQUEST_MAX + 1 - used, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        used += (size_t)n;
        if (memchr(line, '\n', used)) {
            complete = true;
            break;
        }
    }
    bool framed = complete && used <= CG_REQUEST_MAX && !memchr(line, '\0', used) &&
                  line[used - 1] == '\n' && !memchr(line, '\n', used - 1);
    line[used] = '\0';
    if (!framed) {
        free(line);
        socket_reply(stream, "invalid or oversized CodeGraph request");
        return;
    }
    struct json_tokener *parser = json_tokener_new();
    struct json_object *request = parser ? json_tokener_parse_ex(parser, line, (int)used) : NULL;
    bool parsed = parser && json_tokener_get_error(parser) == json_tokener_success &&
                  json_tokener_get_parse_end(parser) == used;
    json_tokener_free(parser);
    free(line);
    if (!parsed || !request || !json_object_is_type(request, json_type_object)) {
        if (request)
            json_object_put(request);
        socket_reply(stream, "invalid CodeGraph request JSON");
        return;
    }
    double auth_start = monotonic_ms();
    pthread_mutex_lock(&capability_lock);
    bool authorized = authorized_request(st, request, token);
    pthread_mutex_unlock(&capability_lock);
    capability_authorization_ms = monotonic_ms() - auth_start;
    auth_ms = 0;
    if (!authorized) {
        socket_reply(stream, "CodeGraph authentication or authorization denied");
        json_object_put(request);
        return;
    }
    const char *command = json_string(request, "command");
    if (command && !strcmp(command, "ping"))
        fputs("{\"status\":\"ready\"}\n", stream);
    else if (command && !strcmp(command, "revoke")) {
        pthread_mutex_lock(&capability_lock);
        bool rotated = authorized_request(st, request, token) && new_capability(token_path, token);
        pthread_mutex_unlock(&capability_lock);
        if (rotated)
            fputs("{\"status\":\"revoked\"}\n", stream);
        else
            socket_reply(stream, "CodeGraph capability rotation failed or authorization revoked");
    } else if (read_action(command)) {
        double begin = monotonic_ms();
        snapshot_verify_ms = kv_load_ms = graph_build_ms = 0;
        pthread_rwlock_rdlock(&generation_lock);
        struct json_object *visible = NULL;
        bool loaded =
            st->graph && current_manifest(st, &visible) && same_manifest(st->manifest, visible);
        if (visible)
            json_object_put(visible);
        if (!loaded) {
            pthread_rwlock_unlock(&generation_lock);
            pthread_rwlock_wrlock(&generation_lock);
            pthread_mutex_lock(&graph_api_lock);
            loaded = refresh_generation(st);
            pthread_mutex_unlock(&graph_api_lock);
            pthread_rwlock_unlock(&generation_lock);
            pthread_rwlock_rdlock(&generation_lock);
        }
        generation_ms = monotonic_ms() - begin;
        int rc = 1;
        struct json_object *report = loaded ? execute_read(st, request, &rc)
                                            : request_error("no valid QIHSE CodeGraph generation");
        pthread_mutex_lock(&capability_lock);
        authorized = authorized_request(st, request, token);
        pthread_mutex_unlock(&capability_lock);
        if (!authorized) {
            json_object_put(report);
            report = request_error("CodeGraph authorization revoked during query");
            rc = 1;
        }
        report = format_response(st, request, report);
        if (!rc && json_string(report, "error"))
            rc = 1;
        if (json_flag(request, "cli"))
            json_int(report, "_exit_code", rc);
        print_json(report);
        json_object_put(report);
        pthread_rwlock_unlock(&generation_lock);
    } else
        socket_reply(stream, "unsupported CodeGraph reader command");
    json_object_put(request);
}

#define CG_WORKERS 4u
#define CG_PENDING 16u
struct reader_job {
    int fd;
    double accepted;
};
struct reader_pool {
    cg_state *state;
    const char *token_path;
    char *token;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_t workers[CG_WORKERS];
    size_t started, head, count;
    bool stopping;
    struct reader_job jobs[CG_PENDING];
};
static void *reader_worker(void *argument) {
    struct reader_pool *pool = argument;
    for (;;) {
        pthread_mutex_lock(&pool->lock);
        while (!pool->count && !pool->stopping)
            pthread_cond_wait(&pool->ready, &pool->lock);
        if (!pool->count) {
            pthread_mutex_unlock(&pool->lock);
            return NULL;
        }
        struct reader_job job = pool->jobs[pool->head];
        pool->head = (pool->head + 1) % CG_PENDING;
        pool->count--;
        pthread_mutex_unlock(&pool->lock);
        generation_ms = seed_ms = traversal_ms = 0;
        auth_ms = capability_authorization_ms = snapshot_verify_ms = kv_load_ms = graph_build_ms =
            0;
        output_compact = batch_query = false;
        requested_match = NULL;
        FILE *stream = fdopen(job.fd, "w");
        if (!stream) {
            close(job.fd);
            continue;
        }
        response_stream = stream;
        serve_request(pool->state, stream, pool->token_path, pool->token, job.accepted + 5000.0);
        fflush(stream);
        fclose(stream);
        response_stream = NULL;
    }
}
static void reader_pool_stop(struct reader_pool *pool) {
    pthread_mutex_lock(&pool->lock);
    pool->stopping = true;
    pthread_cond_broadcast(&pool->ready);
    pthread_mutex_unlock(&pool->lock);
    for (size_t i = 0; i < pool->started; ++i)
        pthread_join(pool->workers[i], NULL);
    pthread_cond_destroy(&pool->ready);
    pthread_mutex_destroy(&pool->lock);
}
static bool reader_pool_start(struct reader_pool *pool, cg_state *state, const char *token_path,
                              char token[65], size_t workers) {
    *pool = (struct reader_pool){.state = state, .token_path = token_path, .token = token};
    if (pthread_mutex_init(&pool->lock, NULL))
        return false;
    if (pthread_cond_init(&pool->ready, NULL)) {
        pthread_mutex_destroy(&pool->lock);
        return false;
    }
    for (size_t i = 0; i < workers; ++i) {
        if (pthread_create(&pool->workers[i], NULL, reader_worker, pool)) {
            reader_pool_stop(pool);
            return false;
        }
        pool->started++;
    }
    return true;
}
static bool reader_pool_push(struct reader_pool *pool, int fd) {
    pthread_mutex_lock(&pool->lock);
    bool room = pool->count < CG_PENDING;
    if (room) {
        size_t tail = (pool->head + pool->count) % CG_PENDING;
        pool->jobs[tail] = (struct reader_job){.fd = fd, .accepted = monotonic_ms()};
        pool->count++;
        pthread_cond_signal(&pool->ready);
    }
    pthread_mutex_unlock(&pool->lock);
    return room;
}
static int serve_graph(cg_state *st, const char *socket_path, const char *token_path,
                       int idle_seconds, size_t workers) {
    struct sigaction ignore_pipe = {.sa_handler = SIG_IGN};
    sigemptyset(&ignore_pipe.sa_mask);
    if (sigaction(SIGPIPE, &ignore_pipe, NULL))
        return error_json("CodeGraph reader signal setup failed");
    if (!paired_socket_paths(socket_path, token_path))
        return error_json("CodeGraph socket/token paths must share one directory");
    char token[65] = {0};
    char lock_path[PATH_MAX];
    if (snprintf(lock_path, sizeof(lock_path), "%s.lock", socket_path) >= (int)sizeof(lock_path))
        return error_json("CodeGraph socket lock path too long");
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (lock_fd >= 0)
            close(lock_fd);
        return error_json("CodeGraph reader already active");
    }
    bool token_owned = false, socket_owned = false;
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        goto failed;
    struct stat existing;
    if (lstat(socket_path, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid())
            goto failed;
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
        int active =
            probe >= 0 && connect(probe, (struct sockaddr *)&address, sizeof(address)) == 0;
        if (probe >= 0)
            close(probe);
        if (active || unlink(socket_path) != 0)
            goto failed;
    } else if (errno != ENOENT)
        goto failed;
    if (!new_capability(token_path, token))
        goto failed;
    token_owned = true;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    mode_t old_umask = umask(0077);
    int bound = bind(listener, (struct sockaddr *)&address, sizeof(address));
    umask(old_umask);
    socket_owned = bound == 0;
    if (bound != 0 || chmod(socket_path, 0600) != 0 || listen(listener, 16) != 0)
        goto failed_socket;
    struct reader_pool pool;
    if (!reader_pool_start(&pool, st, token_path, token, workers))
        goto failed_socket;
    for (;;) {
        struct pollfd ready = {.fd = listener, .events = POLLIN};
        int polled = poll(&ready, 1, idle_seconds * 1000);
        if (polled == 0)
            break;
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        struct ucred peer;
        socklen_t peer_size = sizeof(peer);
        bool same_uid = getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) == 0 &&
                        peer_size == sizeof(peer) && peer.uid == geteuid();
        struct timeval timeout = {.tv_sec = 5};
        if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
            close(client);
            continue;
        }
        if (same_uid && reader_pool_push(&pool, client))
            continue;
        FILE *stream = fdopen(client, "w");
        if (!stream) {
            close(client);
            continue;
        }
        socket_reply(stream, same_uid ? "CodeGraph reader busy" : "CodeGraph peer denied");
        fflush(stream);
        fclose(stream);
    }
    reader_pool_stop(&pool);
    close(listener);
    unlink(socket_path);
    unlink(token_path);
    close(lock_fd);
    OPENSSL_cleanse(token, sizeof(token));
    return 0;
failed_socket:
    if (socket_owned)
        unlink(socket_path);
failed:
    if (listener >= 0)
        close(listener);
    if (token_owned)
        unlink(token_path);
    close(lock_fd);
    OPENSSL_cleanse(token, sizeof(token));
    return error_json("CodeGraph reader socket unavailable");
}

static int socket_query(const char *socket_path, const char *token_path,
                        struct json_object *request) {
    if (!paired_socket_paths(socket_path, token_path))
        return error_json("CodeGraph socket/token paths must share one directory");
    struct stat info;
    if (lstat(socket_path, &info))
        return errno == ENOENT ? -1 : error_json("CodeGraph socket metadata unavailable");
    if (!S_ISSOCK(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0077))
        return error_json("CodeGraph socket ownership or permissions denied");
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return error_json("CodeGraph client socket unavailable");
    struct timeval timeout = {.tv_sec = 120};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        int saved = errno;
        close(fd);
        return saved == ENOENT || saved == ECONNREFUSED
                   ? -1
                   : error_json("CodeGraph reader connection failed");
    }
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) || size != sizeof(peer) ||
        peer.uid != geteuid()) {
        close(fd);
        return error_json("CodeGraph reader peer denied");
    }
    int cap = open(token_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char token[67] = {0};
    bool safe = cap >= 0 && fstat(cap, &info) == 0 && S_ISREG(info.st_mode) &&
                info.st_uid == geteuid() && !(info.st_mode & 0077) && info.st_size == 65;
    ssize_t got = safe ? read(cap, token, sizeof(token) - 1) : -1;
    if (cap >= 0)
        close(cap);
    safe = safe && got == 65 && token[64] == '\n';
    token[64] = 0;
    if (!safe || !hex64(token)) {
        OPENSSL_cleanse(token, sizeof(token));
        close(fd);
        return error_json("CodeGraph capability file denied");
    }
    json_text(request, "token", token);
    json_boolean(request, "cli", true);
    OPENSSL_cleanse(token, sizeof(token));
    const char *wire = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);
    size_t length = strlen(wire), sent = 0;
    bool ok = length + 1 <= CG_REQUEST_MAX;
    while (ok && sent < length) {
        ssize_t n = send(fd, wire + sent, length - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        sent += (size_t)n;
    }
    if (ok)
        ok = send(fd, "\n", 1, MSG_NOSIGNAL) == 1;
    json_object_object_del(request, "token");
    size_t used = 0, capacity = 4096;
    char *reply = malloc(capacity + 1);
    ok = ok && reply;
    bool complete = false;
    while (ok && !complete) {
        if (used == capacity) {
            if (capacity == 4 * 1024 * 1024) {
                ok = false;
                break;
            }
            capacity *= 2;
            char *grown = realloc(reply, capacity + 1);
            if (!grown) {
                ok = false;
                break;
            }
            reply = grown;
        }
        ssize_t n = recv(fd, reply + used, capacity - used, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        used += (size_t)n;
        complete = memchr(reply, '\n', used) != NULL;
    }
    close(fd);
    struct json_object *report = NULL;
    if (ok && complete && !memchr(reply, 0, used) && reply[used - 1] == '\n') {
        reply[used] = 0;
        report = json_tokener_parse(reply);
    }
    free(reply);
    if (!report || !json_object_is_type(report, json_type_object)) {
        if (report)
            json_object_put(report);
        return error_json("invalid or incomplete CodeGraph reader response");
    }
    struct json_object *field = NULL;
    int rc = json_object_object_get_ex(report, "_exit_code", &field)
                 ? (int)json_object_get_int(field)
             : json_object_object_get_ex(report, "error", &field) ? 1
                                                                  : 0;
    json_object_object_del(report, "_exit_code");
    print_json(report);
    json_object_put(report);
    return rc >= 0 && rc <= 2 ? rc : 1;
}

/* One locked byte reserves one MiB. Kernel locks survive the startup window and
 * release on exit/crash, so a caller dying between spawn and bookkeeping cannot
 * lose a reservation. Keep this fd open for the reader's entire lifetime. */
static int reserve_reader_memory(const char *path, int memory_mib, int budget_mib) {
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0)
        return -1;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 077) || info.st_nlink != 1 || flock(fd, LOCK_EX | LOCK_NB))
        goto fail;
    off_t cursor = 0, available = -1, total = 0;
    for (unsigned int n = 0; n < 4096; n++) {
        struct flock held = {
            .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = cursor, .l_len = 0};
        if (fcntl(fd, F_GETLK, &held))
            goto fail;
        if (held.l_type == F_UNLCK) {
            if (available < 0)
                available = cursor;
            if (total + memory_mib > budget_mib || available > 262144 - memory_mib)
                goto fail;
            struct flock claim = {
                .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = available, .l_len = memory_mib};
            if (fcntl(fd, F_SETLK, &claim) || flock(fd, LOCK_UN))
                goto fail;
            return fd;
        }
        if (held.l_start < cursor || held.l_len <= 0 || held.l_start > 262144 ||
            held.l_len > 262144 - held.l_start)
            goto fail;
        if (available < 0 && held.l_start - cursor >= memory_mib)
            available = cursor;
        total += held.l_len;
        if (total > budget_mib)
            goto fail;
        cursor = held.l_start + held.l_len;
    }
fail:
    close(fd);
    return -1;
}

static int memory_option(const char *text, int maximum) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    return errno || !*text || !end || *end || value < 128 || value > maximum ? -1 : (int)value;
}

static const char *usage_text =
    "usage: qihse-codegraph <import|migrate|gc|status|stats|query|impact|review|context|serve> "
    "[--repo DIR] [--input JSONL] [--symbol NAME] [--file PATH] "
    "[--base GITREF] [--depth 1..5] [--limit 1..256] "
    "[--max-tokens 128..16000] [--socket PATH] [--token-file PATH] "
    "[--idle-seconds 1..3600] [--workers 1..4] [--fallback error|oneshot] "
    "[--memory-limit-mib 128..65536] [--pool-file PATH --pool-budget-mib 128..262144] "
    "[--match auto|exact|qualified|prefix|substring] [--timings] [--compact]\n";
static int usage(void) {
    fputs(usage_text, stderr);
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return usage();
    if (!strcmp(argv[1], "--help")) {
        fputs(usage_text, stdout);
        return 0;
    }
    const char *action = argv[1], *repo = ".", *input = NULL;
    const char *socket_path = NULL, *token_path = NULL;
    const char *symbol = NULL, *base = NULL, *files[CG_MAX_FILES] = {0};
    size_t nfiles = 0, limit = 80;
    int depth = 2, tokens = 4000;
    int idle_seconds = 60;
    int memory_mib = 0, pool_budget_mib = 0, pool_fd = -1;
    const char *pool_path = NULL;
    size_t workers = CG_WORKERS;
    const char *fallback = "error", *match = NULL;
    bool timings = false, compact_output = false;
    for (int i = 2; i < argc; i++) {
        const char *flag = argv[i];
        if (!strcmp(flag, "--help")) {
            if (!read_action(action) && strcmp(action, "stats") && strcmp(action, "serve") && strcmp(action, "import") &&
                strcmp(action, "migrate") && strcmp(action, "gc"))
                return usage();
            fputs(usage_text, stdout);
            return 0;
        }
        if (!strcmp(flag, "--timings")) {
            timings = true;
            continue;
        }
        if (!strcmp(flag, "--compact")) {
            compact_output = true;
            continue;
        }
        if (i + 1 >= argc)
            return usage();
        const char *value = argv[++i];
        if (!strcmp(flag, "--repo"))
            repo = value;
        else if (!strcmp(flag, "--input"))
            input = value;
        else if (!strcmp(flag, "--symbol"))
            symbol = value;
        else if (!strcmp(flag, "--base"))
            base = value;
        else if (!strcmp(flag, "--file")) {
            if (nfiles == CG_MAX_FILES || !safe_relative(value))
                return usage();
            files[nfiles++] = value;
        } else if (!strcmp(flag, "--depth"))
            depth = atoi(value);
        else if (!strcmp(flag, "--limit"))
            limit = (size_t)atoi(value);
        else if (!strcmp(flag, "--max-tokens"))
            tokens = atoi(value);
        else if (!strcmp(flag, "--socket"))
            socket_path = value;
        else if (!strcmp(flag, "--token-file"))
            token_path = value;
        else if (!strcmp(flag, "--idle-seconds"))
            idle_seconds = atoi(value);
        else if (!strcmp(flag, "--workers"))
            workers = (size_t)atoi(value);
        else if (!strcmp(flag, "--memory-limit-mib"))
            memory_mib = memory_option(value, 65536);
        else if (!strcmp(flag, "--pool-budget-mib"))
            pool_budget_mib = memory_option(value, 262144);
        else if (!strcmp(flag, "--pool-file"))
            pool_path = value;
        else if (!strcmp(flag, "--fallback"))
            fallback = value;
        else if (!strcmp(flag, "--match"))
            match = value;
        else
            return usage();
    }
    if (strcmp(action, "import") && strcmp(action, "status") && strcmp(action, "stats") && strcmp(action, "query") &&
        strcmp(action, "impact") && strcmp(action, "review") && strcmp(action, "context") &&
        strcmp(action, "serve") && strcmp(action, "migrate") && strcmp(action, "gc"))
        return usage();
    /* Bare impact/review means "changed since HEAD", never whole-repo
     * pseudo-review with no seeds. Graph context requires an explicit seed. */
    if (!symbol && !base && !nfiles && (!strcmp(action, "impact") || !strcmp(action, "review")))
        base = "HEAD";
    if (tokens < 128 || tokens > 16000 || limit == 0 || limit > 256 || depth < 1 || depth > 5 ||
        idle_seconds < 1 || idle_seconds > 3600 || workers < 1 || workers > CG_WORKERS ||
        (!strcmp(action, "serve") && (!socket_path || !token_path)) ||
        (!strcmp(action, "stats") && (socket_path || token_path || input)) ||
        (!!socket_path != !!token_path) || !valid_match(match) ||
        (strcmp(fallback, "error") && strcmp(fallback, "oneshot")))
        return usage();
    if (memory_mib < 0 || pool_budget_mib < 0 || (!!pool_path != !!pool_budget_mib) ||
        (pool_path && (!memory_mib || memory_mib > pool_budget_mib)) ||
        ((memory_mib || pool_path) && strcmp(action, "serve")))
        return usage();
    if (memory_mib) {
        struct rlimit limit = {.rlim_cur = (rlim_t)memory_mib * 1024 * 1024,
                               .rlim_max = (rlim_t)memory_mib * 1024 * 1024};
        struct rlimit inherited;
        if (getrlimit(RLIMIT_AS, &inherited))
            return error_json("cannot inspect CodeGraph reader memory limit");
        if (inherited.rlim_max != RLIM_INFINITY && inherited.rlim_max < limit.rlim_max)
            limit.rlim_cur = limit.rlim_max = inherited.rlim_max;
        if (setrlimit(RLIMIT_AS, &limit))
            return error_json("cannot enforce CodeGraph reader memory limit");
    }
    if (pool_path) {
        pool_fd = reserve_reader_memory(pool_path, memory_mib, pool_budget_mib);
        if (pool_fd < 0)
            return error_json("CodeGraph resident memory budget unavailable");
    }
    char request_repo[PATH_MAX];
    if (!realpath(repo, request_repo))
        return error_json("CodeGraph repo/runtime not available");
    struct json_object *request = json_object_new_object();
    json_text(request, "command", action);
    json_text(request, "repo", request_repo);
    if (symbol)
        json_text(request, "symbol", symbol);
    if (base)
        json_text(request, "base", base);
    if (match)
        json_text(request, "match", match);
    json_int(request, "depth", depth);
    json_int(request, "limit", (int64_t)limit);
    json_int(request, "max_tokens", tokens);
    json_boolean(request, "timings", timings);
    json_boolean(request, "compact", compact_output);
    struct json_object *file_array = json_object_new_array();
    for (size_t i = 0; i < nfiles; ++i)
        json_object_array_add(file_array, json_object_new_string(files[i]));
    json_object_object_add(request, "files", file_array);
    if (socket_path && read_action(action)) {
        int result = socket_query(socket_path, token_path, request);
        if (result >= 0 || strcmp(fallback, "oneshot")) {
            json_object_put(request);
            return result >= 0 ? result
                               : error_json("CodeGraph reader unavailable; use "
                                            "--fallback oneshot explicitly");
        }
        json_object_object_del(request, "cli");
    }
    double load_start = monotonic_ms();
    cg_state st;
    if (!graph_open(&st, repo, !strcmp(action, "import"))) {
        graph_close(&st);
        json_object_put(request);
        return error_json("CodeGraph repo/runtime not available");
    }
    int rc;
    if (!strcmp(action, "import")) {
        rc = input ? import_snapshot(&st, input) : usage();
    } else if (!strcmp(action, "migrate")) {
        rc = migrate_snapshot(&st);
    } else if (!strcmp(action, "gc")) {
        rc = collect_snapshots(&st);
    } else if (!strcmp(action, "stats")) {
        rc = storage_stats(&st);
    } else if (!load_snapshot(&st, strcmp(action, "status") != 0)) {
        rc = error_json("no valid QIHSE CodeGraph generation; import a fresh CRG snapshot");
    } else if (!strcmp(action, "serve")) {
        rc = serve_graph(&st, socket_path, token_path, idle_seconds, workers);
    } else {
        generation_ms = monotonic_ms() - load_start;
        struct json_object *report = execute_read(&st, request, &rc);
        report = format_response(&st, request, report);
        if (!rc && json_string(report, "error"))
            rc = 1;
        print_json(report);
        json_object_put(report);
    }
    json_object_put(request);
    graph_close(&st);
    if (pool_fd >= 0)
        close(pool_fd);
    return rc;
}
