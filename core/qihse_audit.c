#include "qihse_audit.h"
#include "qihse_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <openssl/sha.h>
#endif
#ifndef _WIN32
#include <openssl/evp.h>
#endif
#ifndef _WIN32
#include <openssl/err.h>
#include <openssl/provider.h>
#endif

static EVP_PKEY *audit_pkey = NULL;
static OSSL_PROVIDER *oqs_provider = NULL;

static pthread_mutex_t audit_mutex = PTHREAD_MUTEX_INITIALIZER;
static char last_hash[129] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // 96 chars for SHA-384
static char webhook_target[256] = ""; // Optional audit notification endpoint
/* Latest-pending webhook notification — set under audit_mutex, drained by
 * the signer thread.  Coalesces classified-access bursts to the most recent
 * event instead of opening a socket per row. */
static int g_ping_pending = 0;
static uint32_t g_ping_uid = 0;
static uint16_t g_ping_classif = 0, g_ping_sci = 0;

#define AUDIT_FILE "qihse_audit.log"
#define INTEGRITY_CHAIN_FILE "qihse_integrity.chain"
#define AUDIT_WRITER_LOCK_FILE "qihse_audit.writer.lock"
#define XOR_KEY 0x5A
#define MLDSA87_SIG_BYTES 4627 // ML-DSA-87 signature size

/* Build a state-file path from QIHSE_DATA_DIR env or fall back to CWD */
static void build_state_path(char *buf, size_t buflen, const char *leaf) {
    const char *dir = getenv("QIHSE_DATA_DIR");
    if (dir && *dir) {
        snprintf(buf, buflen, "%s/%s", dir, leaf);
    } else {
        snprintf(buf, buflen, "%s", leaf);
    }
}

/* Build integrity chain path from QIHSE_DATA_DIR env or fall back to CWD */
static void build_chain_path(char *buf, size_t buflen) {
    build_state_path(buf, buflen, INTEGRITY_CHAIN_FILE);
}

/* Audit log: same data-dir routing as the chain, so parallel test
 * aggregates never share one root-level log file. */
static void build_audit_path(char *buf, size_t buflen) {
    build_state_path(buf, buflen, AUDIT_FILE);
}

#ifndef _WIN32
/* Distinguish a new directory entry from an append.  The writer lock
 * serializes QIHSE writers; if the path disappears between the two opens,
 * fail closed instead of silently creating an unsynced replacement. */
static int audit_open_live(const char *path, int *created) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        *created = 1;
        return fd;
    }
    if (errno != EEXIST) return -1;
    *created = 0;
    return open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);
}

static int audit_sync_live_directory(const char *path) {
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s", path);
    char *slash = strrchr(dir_path, '/');
    if (slash == dir_path) slash[1] = '\0';
    else if (slash) *slash = '\0';
    else snprintf(dir_path, sizeof(dir_path), ".");
    int fd = open(dir_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return -1;
    int synced = fsync(fd);
    int closed = close(fd);
    return synced == 0 && closed == 0 ? 0 : -1;
}
#endif

/* ── Audit log rotation ────────────────────────────────────────────────────
 * Size-threshold rename. The hash chain is logical (last_hash → new_hash,
 * anchored in the integrity-chain file) and NOT file-bound, so rotating the
 * container between records preserves tamper-evidence across the boundary.
 * Only the signer thread (or a fallback caller while the signer is down)
 * writes records in one process, and every record opens the path fresh with
 * O_APPEND|O_CREAT|O_NOFOLLOW, so a rename between records IS the rotation:
 * the next record re-creates the live file. The owner-checked writer lock
 * serializes this path across processes sharing the audit directory.
 * Rotated names carry a decimal-seconds suffix so they sort chronologically
 * by name. POSIX only; on Windows the log grows unbounded. */
static uint64_t audit_rotate_threshold(void) {
    const char* env = getenv("QIHSE_AUDIT_ROTATE_BYTES");
    if (env && *env) {
        char* end = NULL;
        unsigned long long v = strtoull(env, &end, 10);
        /* A threshold below one record (~4.8 KB with its ML-DSA-87
         * signature) would rotate on every write; floor it. */
        if (end && *end == '\0' && v >= 8192ull) return (uint64_t)v;
    }
    return 64ull * 1024ull * 1024ull;
}

/* Both recovery and pruning use this bound and the same filename grammar.
 * Exceeding it fails closed rather than silently omitting an older record. */
#define AUDIT_MAX_ROTATED_LOGS 256u

typedef struct {
    char *names[AUDIT_MAX_ROTATED_LOGS];
    size_t count;
} audit_rotated_list_t;

/* Recovery and rotation enumerate the same owner-controlled audit directory.
 * This is a typed, process-bound service principal, not an ordinary QIHSE
 * account or a bypass for classified database reads. */
typedef struct {
    uid_t effective_uid;
    pid_t process_id;
    dev_t directory_device;
    ino_t directory_inode;
} audit_recovery_context_t;

static void audit_integrity_error(const char *reason);
static void audit_context_create(audit_recovery_context_t *ctx);
static void audit_context_authorize_directory(const audit_recovery_context_t *ctx,
                                              int directory_fd);

static int audit_decimal(const char **cursor, uint64_t *value) {
    const unsigned char *p = (const unsigned char *)*cursor;
    if (!isdigit(*p)) return 0;
    uint64_t n = 0;
    do {
        unsigned int digit = *p - '0';
        if (n > (UINT64_MAX - digit) / 10) return 0;
        n = n * 10 + digit;
        p++;
    } while (isdigit(*p));
    *cursor = (const char *)p;
    *value = n;
    return 1;
}

/* 0: unrelated name; 1: exact rotated name; -1: malformed candidate.
 * A digit-prefixed malformed suffix could hide a retained audit record. */
static int audit_rotated_name(const char *name, const char *base,
                              uint64_t *stamp, uint64_t *retry) {
    size_t n = strlen(base);
    if (strncmp(name, base, n) != 0 || name[n] != '.' ||
        !isdigit((unsigned char)name[n + 1])) return 0;
    const char *p = name + n + 1;
    if (*p == '0' && isdigit((unsigned char)p[1])) return -1;
    if (!audit_decimal(&p, stamp)) return -1;
    *retry = 0;
    if (*p == '.') {
        p++;
        if (*p == '0' || !audit_decimal(&p, retry)) return -1;
    }
    return *p == '\0' ? 1 : -1;
}

static int audit_rotated_order(const char *an, const char *bn) {
    uint64_t at, bt, ai, bi;
    if (audit_rotated_name(an, AUDIT_FILE, &at, &ai) != 1 ||
        audit_rotated_name(bn, AUDIT_FILE, &bt, &bi) != 1)
        audit_integrity_error("invalid rotated audit filename in ordering");
    if (at != bt) return at < bt ? -1 : 1;
    if (ai != bi) return ai < bi ? -1 : 1;
    /* Preserve a total order even for numerically equivalent inputs. */
    return strcmp(an, bn);
}

static int audit_name_cmp(const void *a, const void *b) {
    return audit_rotated_order(*(const char *const *)a,
                               *(const char *const *)b);
}

static void audit_free_rotated(audit_rotated_list_t *list) {
    for (size_t i = 0; i < list->count; i++) free(list->names[i]);
    list->count = 0;
}

static int audit_collect_rotated(const audit_recovery_context_t *ctx,
                                 DIR *dir, const char *base,
                                 audit_rotated_list_t *list) {
    audit_context_authorize_directory(ctx, dirfd(dir));
    list->count = 0;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) return errno == 0;
        uint64_t stamp, retry;
        int match = audit_rotated_name(de->d_name, base, &stamp, &retry);
        if (match < 0 || (match > 0 && list->count == AUDIT_MAX_ROTATED_LOGS))
            return 0;
        if (!match) continue;
        list->names[list->count] = strdup(de->d_name);
        if (!list->names[list->count]) return 0;
        list->count++;
    }
}

static size_t audit_rotate_keep(void) {
    const char* env = getenv("QIHSE_AUDIT_ROTATE_KEEP");
    if (env && *env) {
        char* end = NULL;
        unsigned long long v = strtoull(env, &end, 10);
        if (end && *end == '\0' && v <= AUDIT_MAX_ROTATED_LOGS)
            return (size_t)v; /* 0 = keep everything up to the scan bound */
        audit_integrity_error("invalid rotated audit retention limit");
    }
    return 8;
}

static void audit_prune_rotated(const char* apath, size_t target) {
    char dirbuf[512];
    const char* base = strrchr(apath, '/');
    if (base) {
        size_t dlen = (size_t)(base - apath);
        if (dlen == 0 || dlen >= sizeof(dirbuf))
            audit_integrity_error("audit directory path too long");
        memcpy(dirbuf, apath, dlen);
        dirbuf[dlen] = '\0';
        base++;
    } else {
        snprintf(dirbuf, sizeof(dirbuf), "%s", ".");
        base = apath;
    }
    DIR* d = opendir(dirbuf);
    if (!d) audit_integrity_error("cannot list rotated audit logs");
    audit_recovery_context_t ctx;
    audit_context_create(&ctx);
    audit_rotated_list_t list = {0};
    if (!audit_collect_rotated(&ctx, d, base, &list))
        audit_integrity_error("invalid or excess rotated audit logs");
    if (target == SIZE_MAX && list.count == AUDIT_MAX_ROTATED_LOGS)
        audit_integrity_error("rotated audit scan limit reached");
    qsort(list.names, list.count, sizeof(list.names[0]), audit_name_cmp);
    size_t remove = list.count > target ? list.count - target : 0;
    for (size_t i = 0; i < remove; i++) {
        struct stat st;
        if (fstatat(dirfd(d), list.names[i], &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
            (st.st_mode & 0077) != 0 ||
            unlinkat(dirfd(d), list.names[i], 0) != 0)
            audit_integrity_error("cannot safely prune rotated audit log");
    }
    if (remove && fsync(dirfd(d)) != 0)
        audit_integrity_error("cannot persist rotated audit pruning");
    audit_free_rotated(&list);
    if (closedir(d) != 0)
        audit_integrity_error("cannot close audit directory after pruning");
}

static void audit_maybe_rotate(void) {
    char apath[512];
    const char *data_dir = getenv("QIHSE_DATA_DIR");
    if (data_dir && *data_dir &&
        strlen(data_dir) + 1 + strlen(AUDIT_FILE) >= sizeof(apath))
        audit_integrity_error("audit path too long for rotation");
    build_audit_path(apath, sizeof(apath));
    struct stat st;
    if (lstat(apath, &st) != 0) {
        if (errno == ENOENT) return;
        audit_integrity_error("cannot inspect audit log for rotation");
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077) != 0)
        audit_integrity_error("unsafe audit log for rotation");
    if ((uint64_t)st.st_size < audit_rotate_threshold()) return;

    char rotated[640];
    long t = (long)time(NULL);
    int attempt;
    for (attempt = 0; attempt < 1000; attempt++) {
        int n = attempt == 0
            ? snprintf(rotated, sizeof(rotated), "%s.%ld", apath, t)
            : snprintf(rotated, sizeof(rotated), "%s.%ld.%d", apath, t, attempt);
        if (n < 0 || (size_t)n >= sizeof(rotated))
            audit_integrity_error("rotated audit path too long");
        if (lstat(rotated, &st) != 0) {
            if (errno == ENOENT) break;
            audit_integrity_error("cannot inspect rotated audit path");
        }
    }
    if (attempt >= 1000) audit_integrity_error("rotated audit suffix exhausted");

    size_t keep = audit_rotate_keep();
    /* Reserve one filename before rename. Even a crash between rename and
     * post-rotation work must leave no more files than recovery can scan. */
    audit_prune_rotated(apath, keep ? keep - 1 : SIZE_MAX);

    if (rename(apath, rotated) != 0)
        audit_integrity_error("cannot rotate audit log");
    char dirbuf[sizeof(apath)];
    snprintf(dirbuf, sizeof(dirbuf), "%s", apath);
    char *slash = strrchr(dirbuf, '/');
    if (slash == dirbuf) slash[1] = '\0';
    else if (slash) *slash = '\0';
    else snprintf(dirbuf, sizeof(dirbuf), ".");
    int dfd = open(dirbuf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dfd < 0 || fsync(dfd) != 0)
        audit_integrity_error("cannot persist audit rotation");
    /* Re-create the live file immediately so the next record — and any
     * external tail — finds it in place with the right mode. */
    int fd = open(apath, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0 || fchmod(fd, 0600) != 0 || close(fd) != 0 ||
        fsync(dfd) != 0 || close(dfd) != 0)
        audit_integrity_error("cannot persist live audit log after rotation");
}
/*
 * Asynchronous audit signing.
 *
 * The SHA-384 hash chain is computed synchronously (cheap, and it preserves
 * ordering + tamper-evidence), but the expensive ML-DSA-87 signature and the
 * audit-file / integrity-chain writes are performed by a background signer
 * thread.  Normally qihse_audit_log() does not pay the signing cost on the
 * calling thread; when the bounded queue fills it waits for signer capacity.
 * Records remain byte-identical and ordered as in the synchronous path.
 */
typedef struct audit_pending {
    char buffer[1024];
    char new_hash[129];
    struct audit_pending* next;
} audit_pending_t;

static audit_pending_t* g_q_head = NULL;
static audit_pending_t* g_q_tail = NULL;
/* Bound queued shutdown work and memory while retaining every chain entry.
 * Producers wait before advancing last_hash when the signer falls behind. */
#define AUDIT_PENDING_LIMIT 128u
static size_t g_q_count = 0u;
static pthread_cond_t g_q_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_q_empty_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_q_space_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_signer_tid;
static int g_signer_started = 0;
static int g_signer_ok = 0;
static int g_signer_stop = 0;
static int g_signer_inflight = 0;
static int g_sync_fallback = 0;

/* ── Granted-access aggregation ────────────────────────────────────────────
 * qihse_check_access() used to append one signed audit record per granted
 * classified access. That made every classified KV row an ML-DSA-87
 * signature plus an fsync — megabytes of audit I/O per minute of ordinary
 * marketplace traffic — without adding evidence value over a counted
 * summary. Grants are now counted per (uid, classification, SCI) window and
 * the signer emits one chained, signed ACCESS_COUNT record per expired
 * bucket. Denials stay per-record: they are rare and forensically load-
 * bearing. QIHSE_AUDIT_ACCESS_WINDOW_MS overrides the window (1000..3600000;
 * floor 1000 because a shorter window would rotate on every burst). */
#define AUDIT_ACCESS_SLOTS 1024u
typedef struct access_bucket {
    uint32_t uid;
    uint16_t classif;
    uint16_t sci;
    uint64_t window_id;   /* wall-clock seconds / window */
    uint64_t count;
    uint64_t last_seen;   /* window id of the last increment */
    int used;
} access_bucket_t;
static access_bucket_t g_access_buckets[AUDIT_ACCESS_SLOTS];
static size_t g_access_used = 0u;
static uint64_t g_access_window_secs = 5u; /* read from env at first use */

static uint64_t audit_access_window_secs(void) {
    if (g_access_window_secs) return g_access_window_secs;
    uint64_t w = 5u;
    const char* env = getenv("QIHSE_AUDIT_ACCESS_WINDOW_MS");
    if (env && *env) {
        char* end = NULL;
        unsigned long long ms = strtoull(env, &end, 10);
        if (end && *end == '\0' && ms >= 1000u && ms <= 3600000000ull)
            w = ms / 1000u;
        if (w == 0u) w = 1u;
    }
    g_access_window_secs = w;
    return w;
}

static size_t access_bucket_index(uint32_t uid, uint16_t classif,
                                  uint16_t sci, uint64_t window_id) {
    uint32_t h = uid * 0x9E3779B9u;
    h ^= (uint32_t)classif * 0x85EBCA6Bu;
    h ^= (uint32_t)sci * 0xC2B2AE35u;
    h ^= (uint32_t)(window_id ^ (window_id >> 32));
    h ^= h >> 15;
    return (size_t)(h % AUDIT_ACCESS_SLOTS);
}

/* Snapshot expired buckets into out[]. Caller holds audit_mutex. */
static size_t access_collect_expired_locked(access_bucket_t* out,
                                            size_t cap, uint64_t now_window,
                                            int flush_all) {
    size_t n = 0u;
    for (size_t i = 0; i < AUDIT_ACCESS_SLOTS && n < cap; ++i) {
        access_bucket_t* b = &g_access_buckets[i];
        if (!b->used) continue;
        if (!flush_all && b->window_id + g_access_window_secs > now_window)
            continue;
        out[n++] = *b;
        b->used = 0;
        b->count = 0;
        g_access_used--;
    }
    return n;
}

#ifndef _WIN32
/* One kernel-held lock covers log rotation, append and chain-tip publication.
 * A forked child closes its inherited descriptor and must initialize afresh. */
static int audit_writer_lock_fd = -1;
static char audit_writer_lock_path[4096];
static int audit_recovery_context_ready = 0;
#endif

/* Start the background signer if it isn't running yet.  Must be called
 * with audit_mutex held.  Also registers the atexit teardown handler on
 * first use.  If the thread cannot start, callers fall back to sync. */
static void* audit_signer_main(void* arg);

static void audit_register_atfork(void);

/* Granted-access aggregation forward declarations. */
static void access_emit_sync(const access_bucket_t* b);
void qihse_audit_access_granted(uint32_t user_id, uint16_t classif, uint16_t sci);
static size_t access_emit_via_queue(int flush_all);

static void audit_ensure_signer_locked(void) {
    if (!g_signer_started) {
        g_signer_stop = 0;
        if (pthread_create(&g_signer_tid, NULL, audit_signer_main, NULL) == 0) {
            g_signer_ok = 1;
            g_signer_started = 1;
        }
    }
    audit_register_atfork();
    {
        static int atexit_registered = 0;
        if (!atexit_registered) { atexit_registered = 1; atexit(qihse_audit_shutdown); }
    }
}

/* ── fork safety ───────────────────────────────────────────────────────────
 * The signer thread does not survive fork(). The prepare handler drains it
 * before the address space splits, so queued entries are written by the
 * parent once. The child discards the inherited signer state and writer-lock
 * descriptor. It cannot append or verify until it calls qihse_audit_init()
 * and obtains its own exclusive lock; while the parent remains the writer,
 * that initialization fails closed. Fork-and-exec children need no lock. */
static void audit_atfork_prepare(void) {
    pthread_mutex_lock(&audit_mutex);
    /* Wait for the signer to drain the queue so pre-fork entries are on
     * disk before the address space splits. */
    while (g_sync_fallback ||
           ((g_q_head || g_signer_inflight || g_ping_pending) &&
            g_signer_ok)) {
        pthread_mutex_unlock(&audit_mutex);
        usleep(1000);
        pthread_mutex_lock(&audit_mutex);
    }
}

static void audit_atfork_parent(void) {
    pthread_mutex_unlock(&audit_mutex);
}

static void audit_atfork_child(void) {
    /* The signer is gone; keep the child inert until exclusive reinit. */
    g_q_head = NULL;
    g_q_tail = NULL;
    g_q_count = 0u;
    g_signer_inflight = 0;
    g_sync_fallback = 0;
    g_ping_pending = 0;
    g_signer_tid = pthread_self(); /* mark invalid-ish; started flag drives */
    g_signer_ok = 0;
    g_signer_started = 0;
#ifndef _WIN32
    if (audit_writer_lock_fd >= 0) close(audit_writer_lock_fd);
    audit_writer_lock_fd = -1;
    audit_writer_lock_path[0] = '\0';
    audit_recovery_context_ready = 0;
#endif
    pthread_mutex_unlock(&audit_mutex);
}

static void audit_register_atfork(void) {
    static int registered = 0;
    if (!registered) {
        registered = 1;
        pthread_atfork(audit_atfork_prepare, audit_atfork_parent,
                       audit_atfork_child);
    }
}

static void send_webhook_ping(uint32_t user_id, uint16_t classif, uint16_t sci);

// CNSA 2.0: REAL SHA-384
static void compute_sha384(const char *input, char *output) {
    static const char hex[] = "0123456789abcdef";
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
        output[i * 2]     = hex[(hash[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex[hash[i] & 0x0F];
    }
    output[96] = '\0';
}

static bool write_obfuscated(FILE *f, const char* buffer) {
    size_t len = strlen(buffer);
    if (len + 1u > 4096u) {
        for (size_t i = 0; i < len; i++) {
            if (fputc(buffer[i] ^ XOR_KEY, f) == EOF) return false;
        }
        return fputc('\n' ^ XOR_KEY, f) != EOF;
    }
    char tmp[4096];
    for (size_t i = 0; i < len; i++) tmp[i] = (char)(buffer[i] ^ XOR_KEY);
    tmp[len] = (char)('\n' ^ XOR_KEY);
    return fwrite(tmp, 1u, len + 1u, f) == len + 1u;
}

static bool update_integrity_chain(const char* new_hash);

static void audit_integrity_error(const char *reason) {
    fprintf(stderr, "[QIHSE AUDIT] Integrity continuity failure: %s\n", reason);
    /* The void initialization API has no safe degraded mode: writing after
     * a broken anchor would make the evidence harder to recover. */
    abort();
}

#ifndef _WIN32
static int audit_hex_hash(const char *hash) {
    for (size_t i = 0; i < 96; i++) {
        if (!((hash[i] >= '0' && hash[i] <= '9') ||
              (hash[i] >= 'a' && hash[i] <= 'f'))) return 0;
    }
    return 1;
}

static audit_recovery_context_t audit_recovery_context;

static int audit_context_matches_process(const audit_recovery_context_t *ctx) {
    return ctx && ctx->process_id == getpid() &&
           ctx->effective_uid == geteuid();
}

static int audit_context_allows_file(const audit_recovery_context_t *ctx,
                                     const struct stat *st) {
    return audit_context_matches_process(ctx) && st && S_ISREG(st->st_mode) &&
           st->st_uid == ctx->effective_uid && (st->st_mode & 0077) == 0;
}

static void audit_context_authorize_directory(const audit_recovery_context_t *ctx,
                                              int directory_fd) {
    struct stat st;
    if (!audit_context_matches_process(ctx) || directory_fd < 0 ||
        fstat(directory_fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != ctx->effective_uid || (st.st_mode & 0022) != 0 ||
        (ctx->directory_inode &&
         (ctx->directory_device != st.st_dev || ctx->directory_inode != st.st_ino))) {
        audit_integrity_error("audit recovery context cannot access directory");
    }
}

static void audit_context_create(audit_recovery_context_t *ctx) {
    char apath[4096], dirbuf[4096];
    build_audit_path(apath, sizeof(apath));
    const char *slash = strrchr(apath, '/');
    if (slash) {
        size_t n = (size_t)(slash - apath);
        if (n >= sizeof(dirbuf)) audit_integrity_error("audit directory path too long");
        if (n == 0) audit_integrity_error("root audit directory unsupported");
        memcpy(dirbuf, apath, n);
        dirbuf[n] = '\0';
    } else {
        snprintf(dirbuf, sizeof(dirbuf), ".");
    }
    int fd = open(dirbuf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) audit_integrity_error("cannot open audit directory");
    audit_recovery_context_t candidate = {
        .effective_uid = geteuid(), .process_id = getpid()
    };
    audit_context_authorize_directory(&candidate, fd);
    struct stat st;
    if (fstat(fd, &st) != 0) audit_integrity_error("cannot identify audit directory");
    candidate.directory_device = st.st_dev;
    candidate.directory_inode = st.st_ino;
    close(fd);
    *ctx = candidate;
}

static void audit_writer_lock_acquire(const audit_recovery_context_t *ctx) {
    if (!audit_context_matches_process(ctx))
        audit_integrity_error("invalid audit writer identity");
    const char *data_dir = getenv("QIHSE_DATA_DIR");
    char path[4096];
    if (data_dir && *data_dir &&
        strlen(data_dir) + 1 + strlen(AUDIT_WRITER_LOCK_FILE) >= sizeof(path))
        audit_integrity_error("audit writer lock path too long");
    build_state_path(path, sizeof(path), AUDIT_WRITER_LOCK_FILE);
    if (audit_writer_lock_fd >= 0) {
        struct stat held, named;
        if (strcmp(path, audit_writer_lock_path) != 0 ||
            fstat(audit_writer_lock_fd, &held) != 0 ||
            lstat(path, &named) != 0 ||
            !audit_context_allows_file(ctx, &held) ||
            !audit_context_allows_file(ctx, &named) ||
            held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
            flock(audit_writer_lock_fd, LOCK_EX | LOCK_NB) != 0)
            audit_integrity_error("audit writer lock was replaced or released");
        return;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) audit_integrity_error("cannot open audit writer lock");
    struct stat held, named;
    if (fstat(fd, &held) != 0 || lstat(path, &named) != 0 ||
        !audit_context_allows_file(ctx, &held) ||
        !audit_context_allows_file(ctx, &named) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        audit_integrity_error("audit writer lock is unavailable or unsafe");
    }
    audit_writer_lock_fd = fd;
    memcpy(audit_writer_lock_path, path, strlen(path) + 1);
}

/* The legacy log is an XOR-encoded line followed by a fixed-size signature.
 * Validate each retained record, including links across rotated files. The
 * first retained record can have a pruned predecessor; the chain file is the
 * independent anchor for the latest retained suffix. */
static int audit_scan_file(const audit_recovery_context_t *ctx,
                           int directory_fd, const char *name,
                           char tip[129], int *have_record,
                           const char stored[129], int *anchor_seen,
                           int *banner_since_record) {
    if (!audit_context_matches_process(ctx) || directory_fd < 0 || !name ||
        strchr(name, '/')) return 0;
    int fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0 || !audit_context_allows_file(ctx, &st)) {
        close(fd); return 0;
    }
    FILE *f = fdopen(fd, "rb");
    if (!f) { close(fd); return 0; }
    int ok = 1;
    for (;;) {
        char line[2048];
        size_t len = 0;
        int c;
        while ((c = fgetc(f)) != EOF && ((unsigned char)c ^ XOR_KEY) != '\n') {
            if (len + 1 >= sizeof(line)) { ok = 0; break; }
            line[len++] = (char)((unsigned char)c ^ XOR_KEY);
        }
        if (!ok) break;
        if (c == EOF) { if (len) ok = 0; break; }
        line[len] = '\0';
        if (memchr(line, '\0', len) != NULL) { ok = 0; break; }
        static const char marker[] = "|SIG_MLDSA87_ATTACHED";
        size_t marker_len = sizeof(marker) - 1;
        if (len < marker_len || strcmp(line + len - marker_len, marker) != 0) {
            /* Historical initialization banners have no signature. Accept
             * only the two exact forms emitted by the legacy writer. */
            static const char signed_banner[] =
                "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 ML-DSA-87 ENABLED] ---";
            static const char hash_banner[] =
                "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 SHA-384 HASH CHAIN (PQC UNAVAILABLE)] ---";
            if (!((len == sizeof(signed_banner) - 1 &&
                   memcmp(line, signed_banner, len) == 0) ||
                  (len == sizeof(hash_banner) - 1 &&
                   memcmp(line, hash_banner, len) == 0))) ok = 0;
            if (!ok) break;
            *banner_since_record = 1;
            continue;
        }
        if (len < 96 + 1 + 1 + 96 + marker_len) { ok = 0; break; }
        size_t hash_start = len - marker_len - 96;
        if (line[hash_start - 1] != '|' || !audit_hex_hash(line) ||
            line[96] != '|' || !audit_hex_hash(line + hash_start)) {
            ok = 0; break;
        }
        char expected[129];
        line[hash_start - 1] = '\0';
        compute_sha384(line, expected);
        if (memcmp(expected, line + hash_start, 96) != 0) { ok = 0; break; }
        if (*have_record && memcmp(line, tip, 96) != 0) {
            /* Older versions started every process from the all-zero hash.
             * Accept that legacy boundary only after an initialization
             * banner; never treat an arbitrary broken link as a restart. */
            static const char zero[97] =
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            if (!*banner_since_record || memcmp(line, zero, 96) != 0) {
                ok = 0; break;
            }
            *anchor_seen = 0;
        }
        if (stored && (memcmp(line, stored, 96) == 0 ||
                       memcmp(expected, stored, 96) == 0)) *anchor_seen = 1;
        memcpy(tip, expected, 97);
        *have_record = 1;
        *banner_since_record = 0;
        unsigned char signature[MLDSA87_SIG_BYTES];
        if (fread(signature, 1, sizeof(signature), f) != sizeof(signature)) {
            ok = 0; break;
        }
    }
    if (ferror(f)) ok = 0;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

static void audit_load_continuity_locked(const audit_recovery_context_t *ctx) {
    if (!audit_context_matches_process(ctx))
        audit_integrity_error("missing audit recovery context");
    char chain_path[4096], apath[4096], stored[129] = {0};
    build_chain_path(chain_path, sizeof(chain_path));
    build_audit_path(apath, sizeof(apath));
    char dirbuf[4096];
    const char *base = strrchr(apath, '/');
    if (base) {
        size_t n = (size_t)(base - apath);
        if (n >= sizeof(dirbuf)) audit_integrity_error("audit path too long");
        if (n == 0) audit_integrity_error("root audit directory unsupported");
        memcpy(dirbuf, apath, n);
        dirbuf[n] = '\0';
        base++;
    } else { snprintf(dirbuf, sizeof(dirbuf), "."); base = apath; }
    DIR *dir = opendir(dirbuf);
    if (!dir) audit_integrity_error("cannot list audit logs");
    audit_context_authorize_directory(ctx, dirfd(dir));
    int chain_present = 0;
    const char *chain_name = strrchr(chain_path, '/');
    chain_name = chain_name ? chain_name + 1 : chain_path;
    int fd = openat(dirfd(dir), chain_name, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        char raw[98];
        int valid = fstat(fd, &st) == 0 && audit_context_allows_file(ctx, &st) &&
                    (st.st_size == 96 || st.st_size == 97);
        ssize_t got = valid ? read(fd, raw, sizeof(raw)) : -1;
        valid = valid && got == st.st_size &&
                (st.st_size == 96 || raw[96] == '\n');
        close(fd);
        if (!valid || !audit_hex_hash(raw)) {
            audit_integrity_error("invalid chain tip file");
            return;
        }
        memcpy(stored, raw, 96);
        stored[96] = '\0';
        chain_present = 1;
    } else if (errno != ENOENT) {
        audit_integrity_error("cannot read chain tip file");
        return;
    }

    audit_rotated_list_t list = {0};
    if (!audit_collect_rotated(ctx, dir, base, &list))
        audit_integrity_error("invalid or excess rotated audit logs");
    qsort(list.names, list.count, sizeof(list.names[0]), audit_name_cmp);
    char tip[129] = {0};
    int have_record = 0, anchor_seen = 0, banner_since_record = 0;
    int valid = 1;
    for (size_t i = 0; i < list.count; i++) {
        if (!audit_scan_file(ctx, dirfd(dir), list.names[i], tip, &have_record,
                             chain_present ? stored : NULL, &anchor_seen,
                             &banner_since_record)) valid = 0;
        if (!valid) break;
    }
    audit_free_rotated(&list);
    struct stat st;
    if (valid && fstatat(dirfd(dir), base, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        valid = audit_scan_file(ctx, dirfd(dir), base, tip, &have_record,
                                chain_present ? stored : NULL, &anchor_seen,
                                &banner_since_record);
    } else if (errno != ENOENT) valid = 0;
    closedir(dir);
    if (!valid) { audit_integrity_error("invalid or unreadable audit log"); return; }
    if (!have_record && chain_present) {
        audit_integrity_error("chain tip exists without retained audit records");
        memcpy(last_hash, stored, 97);
        return;
    }
    if (!have_record) return;
    if (!chain_present) {
        audit_integrity_error("audit records exist without a chain tip");
        memcpy(last_hash, tip, 97);
        return;
    }
    if (memcmp(stored, tip, 96) != 0) {
        if (anchor_seen) {
            /* The durable log contains a valid suffix beyond the old tip. */
            if (!update_integrity_chain(tip)) {
                audit_integrity_error("cannot advance lagging chain tip");
                return;
            }
        } else {
            audit_integrity_error("chain tip is not anchored in retained log");
            return;
        }
    }
    memcpy(last_hash, tip, 97);
}
#endif

void qihse_audit_verify_integrity(void) {
#ifndef _WIN32
    pthread_mutex_lock(&audit_mutex);
    while (g_sync_fallback ||
           ((g_q_head || g_signer_inflight) && g_signer_ok))
        pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
    if (!audit_recovery_context_ready || audit_writer_lock_fd < 0)
        audit_integrity_error("audit recovery has no authenticated context");
    audit_writer_lock_acquire(&audit_recovery_context);
    audit_load_continuity_locked(&audit_recovery_context);
    pthread_mutex_unlock(&audit_mutex);
#else
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    FILE *sf = fopen(chain_path, "r");
    if (sf) {
        char stored_hash[129];
        if (fgets(stored_hash, sizeof(stored_hash), sf) != NULL) {
            if (strncmp(stored_hash, last_hash, 96) != 0) {
                fprintf(stderr, "[QIHSE AUDIT] Integrity chain mismatch detected!\n");
                const char* strict = getenv("QIHSE_STRICT_AUDIT");
                if (strict && strcmp(strict, "1") == 0) {
                    fprintf(stderr, "[QIHSE AUDIT] Strict audit enforcement: aborting on integrity mismatch.\n");
                    abort();
                }
            }
        }
        fclose(sf);
    }
#endif
}

static bool update_integrity_chain(const char* new_hash) {
#ifndef _WIN32
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    char temp_path[sizeof(chain_path) + 16];
    int n = snprintf(temp_path, sizeof(temp_path), "%s.tmp.XXXXXX", chain_path);
    if (n < 0 || (size_t)n >= sizeof(temp_path)) goto error;
    int fd = mkstemp(temp_path);
    if (fd < 0) goto error;
    if (fchmod(fd, 0600) != 0) goto failed;
    size_t offset = 0;
    while (offset < 96u) {
        ssize_t written = write(fd, new_hash + offset, 96u - offset);
        if (written <= 0) goto failed;
        offset += (size_t)written;
    }
    if (fsync(fd) != 0) goto failed;
    if (close(fd) != 0) {
        fd = -1;
        goto failed;
    }
    fd = -1;
    if (rename(temp_path, chain_path) != 0) goto failed;
    /* Persist the directory entry as well as the content. */
    char dir_path[sizeof(chain_path)];
    snprintf(dir_path, sizeof(dir_path), "%s", chain_path);
    char *slash = strrchr(dir_path, '/');
    if (slash == dir_path) slash[1] = '\0';
    else if (slash) *slash = '\0';
    else snprintf(dir_path, sizeof(dir_path), ".");
    int dirfd = open(dir_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) goto error;
    int synced = fsync(dirfd);
    int closed = close(dirfd);
    if (synced != 0 || closed != 0) goto error;
    return true;
failed:
    if (fd >= 0) close(fd);
    unlink(temp_path);
error:
    fprintf(stderr, "[QIHSE AUDIT] Could not persist integrity chain tip.\n");
    return false;
#else
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    FILE *sf = fopen(chain_path, "w");
    if (sf) {
        fprintf(sf, "%s", new_hash);
        fclose(sf);
        return true;
    }
    return false;
#endif
}

void qihse_audit_set_webhook(const char* url) {
    pthread_mutex_lock(&audit_mutex);
    if (url) {
        strncpy(webhook_target, url, sizeof(webhook_target) - 1);
    } else {
        webhook_target[0] = '\0';
    }
    pthread_mutex_unlock(&audit_mutex);
}

void qihse_audit_init(void) {
    pthread_mutex_lock(&audit_mutex);
#ifndef _WIN32
    while (g_sync_fallback ||
           ((g_q_head || g_signer_inflight) && g_signer_ok))
        pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
    /* Validate and restore the last durable tip before rotating, pruning or
     * appending the startup banner. A strict mismatch aborts before mutation. */
    audit_recovery_context_t candidate;
    audit_context_create(&candidate);
    if (audit_recovery_context_ready &&
        (audit_recovery_context.directory_device != candidate.directory_device ||
         audit_recovery_context.directory_inode != candidate.directory_inode))
        audit_integrity_error("audit directory changed during process lifetime");
    audit_writer_lock_acquire(&candidate);
    audit_recovery_context = candidate;
    audit_recovery_context_ready = 1;
    audit_load_continuity_locked(&audit_recovery_context);
#endif
    
    static OSSL_PROVIDER *default_provider = NULL;
    if (!default_provider) {
        default_provider = OSSL_PROVIDER_load(NULL, "default");
    }

    /* Load the OQS provider for PQC algorithms (ML-DSA-87, ML-KEM-1024) by default. */
    if (!oqs_provider && !getenv("QIHSE_DISABLE_PQC")) {
        oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
        if (!oqs_provider) {
            const char *paths[] = {
                "vendor/oqs-provider/build/lib/oqsprovider.so",
                "./vendor/oqs-provider/build/lib/oqsprovider.so",
                "/usr/local/lib/ossl-modules/oqsprovider.so",
                "/usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so",
                NULL
            };
            for (int i = 0; paths[i]; i++) {
                oqs_provider = OSSL_PROVIDER_load(NULL, paths[i]);
                if (oqs_provider) break;
            }
        }
    }

    /* Generate ML-DSA-87 keys for signing the audit logs */
    if (!audit_pkey) {
        audit_pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
        if (!audit_pkey) {
            fprintf(stderr, "[WARN] ML-DSA-87 PQC unavailable, audit log will use SHA-384 hash chain only.\n");
        }
    }

    char apath[512];
    build_audit_path(apath, sizeof(apath));
#ifndef _WIN32
    /* A file that already exceeds the threshold (e.g. after months of
     * un-rotated runtime) is archived here at startup, before any new
     * record lands. */
    audit_maybe_rotate();
#endif
#ifndef _WIN32
    int banner_created = 0;
    int banner_fd = audit_open_live(apath, &banner_created);
    if (banner_fd >= 0 && fchmod(banner_fd, 0600) != 0) {
        close(banner_fd);
        banner_fd = -1;
    }
    FILE *f = banner_fd >= 0 ? fdopen(banner_fd, "ab") : NULL;
    if (banner_fd >= 0 && !f) close(banner_fd);
#else
    FILE *f = fopen(apath, "ab");
#endif
    if (f) {
        bool banner_written;
        if (audit_pkey) {
            banner_written = write_obfuscated(f, "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 ML-DSA-87 ENABLED] ---");
        } else {
            banner_written = write_obfuscated(f, "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 SHA-384 HASH CHAIN (PQC UNAVAILABLE)] ---");
        }
        int flushed = fflush(f);
#ifndef _WIN32
        int synced = flushed == 0 ? fsync(fileno(f)) : -1;
#else
        int synced = flushed;
#endif
        int closed = fclose(f);
        int directory_synced = 1;
#ifndef _WIN32
        if (banner_created && flushed == 0 && synced == 0 && closed == 0)
            directory_synced = audit_sync_live_directory(apath) == 0;
#endif
        if (!banner_written || flushed != 0 || synced != 0 || closed != 0 ||
            !directory_synced) {
            fprintf(stderr, "[QIHSE AUDIT] Startup banner could not be persisted.\n");
            abort();
        }
    } else {
        fprintf(stderr, "[QIHSE AUDIT] Audit log could not be opened.\n");
        abort();
    }
    /* Start the background signer to remove ML-DSA-87 signing from the normal
     * caller path. A full queue applies backpressure; signer startup failure
     * falls back to synchronous signing. */
    audit_ensure_signer_locked();
    pthread_mutex_unlock(&audit_mutex);
}

/* The expensive part: ML-DSA-87 signature + audit file + integrity chain.
 * Runs on the signer thread (or inline as a fallback). */
static void audit_sign_and_write(const char* buffer, const char* new_hash) {
#ifndef _WIN32
    if (!audit_recovery_context_ready || audit_writer_lock_fd < 0)
        audit_integrity_error("audit writer is not initialized in this process");
    audit_writer_lock_acquire(&audit_recovery_context);
#endif
    unsigned char mldsa87_sig[MLDSA87_SIG_BYTES];
    size_t siglen = sizeof(mldsa87_sig);
    memset(mldsa87_sig, 0, sizeof(mldsa87_sig));

    if (audit_pkey) {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (mctx) {
            if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, audit_pkey) > 0) {
                EVP_DigestSign(mctx, mldsa87_sig, &siglen, (const unsigned char*)new_hash, strlen(new_hash));
            }
            EVP_MD_CTX_free(mctx);
        }
    }

#ifndef _WIN32
    /* Rotate before this record is written so the oversized container is
     * archived between records, never mid-record. */
    audit_maybe_rotate();
    char apath2[512];
    build_audit_path(apath2, sizeof(apath2));
    int audit_created = 0;
    int afd = audit_open_live(apath2, &audit_created);
    if (afd >= 0 && fchmod(afd, 0600) != 0) {
        close(afd);
        afd = -1;
    }
    FILE *f = NULL;
    if (afd >= 0) f = fdopen(afd, "ab");
#else
    char wpath[512];
    build_audit_path(wpath, sizeof(wpath));
    FILE *f = fopen(wpath, "ab");
#endif
    int log_durable = 0;
    if (f) {
        char out_buf[2048];
        snprintf(out_buf, sizeof(out_buf), "%s|%s|SIG_MLDSA87_ATTACHED", buffer, new_hash);
        bool record_written = write_obfuscated(f, out_buf);
        char sigbuf[MLDSA87_SIG_BYTES];
        for (int i = 0; i < MLDSA87_SIG_BYTES; i++) sigbuf[i] = (char)(mldsa87_sig[i] ^ XOR_KEY);
        size_t sig_written = fwrite(sigbuf, 1u, sizeof(sigbuf), f);
        int flushed = fflush(f);
#ifndef _WIN32
        int synced = flushed == 0 ? fsync(fileno(f)) : -1;
#else
        int synced = flushed;
#endif
        int closed = fclose(f);
        log_durable = record_written && sig_written == sizeof(sigbuf) && flushed == 0 &&
                      synced == 0 && closed == 0;
    }
#ifndef _WIN32
    if (afd >= 0 && !f) close(afd);
    /* An append changes file contents, not its directory entry.  Rotation
     * syncs both rename and re-creation above; only an unexpected new live
     * file needs a directory sync before publishing the chain tip. */
    if (log_durable && audit_created &&
        audit_sync_live_directory(apath2) != 0) log_durable = 0;
#endif

    /* Never publish a chain tip for a record that was not durably appended.
     * Continuing would silently fork the chain after an I/O failure. */
    if (!log_durable) {
        fprintf(stderr, "[QIHSE AUDIT] Audit record could not be persisted.\n");
        abort();
    }

    if (!update_integrity_chain(new_hash)) abort();
}

static void* audit_signer_main(void* arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&audit_mutex);
        while (!g_q_head && !g_ping_pending && !g_signer_stop) {
            /* One-second tick: an idle signer still expires access buckets
             * so counted evidence lands promptly after each window. */
            struct timespec tick;
            clock_gettime(CLOCK_REALTIME, &tick);
            tick.tv_sec += 1;
            pthread_cond_timedwait(&g_q_cond, &audit_mutex, &tick);
        }
        if (!g_q_head && !g_ping_pending && g_signer_stop) {
            pthread_mutex_unlock(&audit_mutex);
            return NULL;
        }
        if (!g_q_head && !g_ping_pending) {
            /* Timed tick with an idle queue: flush expired access buckets
             * synchronously. The signer owns this path — emitting through
             * the producer queue here could wait on space only it frees. */
            access_bucket_t snapshot[AUDIT_ACCESS_SLOTS];
            uint64_t now_window = (uint64_t)time(NULL);
            size_t n = access_collect_expired_locked(
                snapshot, AUDIT_ACCESS_SLOTS, now_window, 0);
            pthread_mutex_unlock(&audit_mutex);
            for (size_t k = 0; k < n; ++k) access_emit_sync(&snapshot[k]);
            continue;
        }
        audit_pending_t* e = g_q_head;
        if (e) {
            g_q_head = e->next;
            g_q_count--;
            pthread_cond_signal(&g_q_space_cond);
            g_signer_inflight = 1;
            if (!g_q_head) g_q_tail = NULL;
        }
        int ping = g_ping_pending;
        uint32_t pu = g_ping_uid; uint16_t pc = g_ping_classif, ps = g_ping_sci;
        g_ping_pending = 0;
        pthread_mutex_unlock(&audit_mutex);

        if (e) {
            audit_sign_and_write(e->buffer, e->new_hash);
            free(e);
            pthread_mutex_lock(&audit_mutex);
            g_signer_inflight = 0;
            if (!g_q_head) pthread_cond_broadcast(&g_q_empty_cond);
            pthread_mutex_unlock(&audit_mutex);
        }
        if (ping) send_webhook_ping(pu, pc, ps);
    }
}

/* Block until every queued audit entry has been signed and written.
 * Pending granted-access buckets are flushed through the queue first, so
 * after this returns the on-disk trail includes every counted access. */
void qihse_audit_flush(void) {
    if (g_signer_ok) access_emit_via_queue(1);
    pthread_mutex_lock(&audit_mutex);
    while (g_sync_fallback ||
           ((g_q_head || g_signer_inflight) && g_signer_ok)) {
        pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
    }
    pthread_mutex_unlock(&audit_mutex);
}

/* Drain the queue and stop the signer thread. */
void qihse_audit_shutdown(void) {
    pthread_mutex_lock(&audit_mutex);
    if (!g_signer_ok) {
        pthread_mutex_unlock(&audit_mutex);
        return;
    }
    pthread_mutex_unlock(&audit_mutex);
    /* Emit every live access bucket through the queue before the signer
     * stops, so a clean exit loses no counted access. */
    access_emit_via_queue(1);
    pthread_mutex_lock(&audit_mutex);
    /* Stop accepting asynchronous entries; the signer drains its existing
     * queue before exit. Wake blocked producers to use the ordered fallback. */
    g_signer_stop = 1;
    pthread_cond_broadcast(&g_q_cond);
    pthread_cond_broadcast(&g_q_space_cond);
    pthread_mutex_unlock(&audit_mutex);
    pthread_join(g_signer_tid, NULL);
    pthread_mutex_lock(&audit_mutex);
    while (g_sync_fallback)
        pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
    g_signer_ok = 0;
    g_signer_started = 0;
    pthread_mutex_unlock(&audit_mutex);
}

void qihse_audit_log(const char* action, uint32_t user_id, uint32_t target_id, uint16_t classif, uint16_t sci) {
    char buffer[1024];
    char new_hash[129];

    /* Hash-chain step stays synchronous: it is cheap and preserves the exact
     * ordering and tamper-evidence of the chain. */
    pthread_mutex_lock(&audit_mutex);
#ifndef _WIN32
    if (!audit_recovery_context_ready || audit_writer_lock_fd < 0 ||
        !audit_context_matches_process(&audit_recovery_context))
        audit_integrity_error("audit writer is not initialized in this process");
    audit_writer_lock_acquire(&audit_recovery_context);
#endif
    for (;;) {
        if (g_sync_fallback) {
            pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
        } else if (g_q_count >= AUDIT_PENDING_LIMIT &&
                   g_signer_ok && !g_signer_stop) {
            pthread_cond_wait(&g_q_space_cond, &audit_mutex);
        } else {
            break;
        }
    }
    time_t now = time(NULL);
    snprintf(buffer, sizeof(buffer), "%s|%ld|%s|%u|%u|%u|%u",
             last_hash, (long)now, action, user_id, target_id, classif, sci);
    compute_sha384(buffer, new_hash);
    memcpy(last_hash, new_hash, 129);

    /* Offload the ML-DSA-87 signature + file writes to the signer thread. */
    if (g_signer_ok && !g_signer_stop) {
        audit_pending_t* e = (audit_pending_t*)malloc(sizeof(*e));
        if (e) {
            memcpy(e->buffer, buffer, sizeof(e->buffer));
            memcpy(e->new_hash, new_hash, sizeof(e->new_hash));
            e->next = NULL;
            if (g_q_tail) g_q_tail->next = e; else g_q_head = e;
            g_q_tail = e;
            g_q_count++;
            pthread_cond_signal(&g_q_cond);
            pthread_mutex_unlock(&audit_mutex);
            return;
        }
    }
    /* Block subsequent chain steps while an allocation fallback waits for
     * earlier queued records and writes its already-hashed record. */
    g_sync_fallback = 1;
    while ((g_q_head || g_signer_inflight) && g_signer_ok)
        pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
    pthread_mutex_unlock(&audit_mutex);
    audit_sign_and_write(buffer, new_hash);
    pthread_mutex_lock(&audit_mutex);
    g_sync_fallback = 0;
    pthread_cond_broadcast(&g_q_empty_cond);
    pthread_mutex_unlock(&audit_mutex);
}

/* ── Granted-access aggregation ────────────────────────────────────────────
 * One chained, signed ACCESS_COUNT record per (uid, classif, SCI) window
 * replaces one record per granted access. The summary record carries the
 * hit count in the target_id field; the window covered is
 * (record_time - window, record_time]. Denials and every other event keep
 * the original per-record path unchanged. */

/* Signer-thread-only emit: hash step + durable write without touching the
 * producer queue (the signer is the queue's only consumer; going through
 * qihse_audit_log here could wait on space it alone would free). */
static void access_emit_sync(const access_bucket_t* b) {
    char buffer[1024];
    char new_hash[129];
    uint64_t count = b->count > 0xFFFFFFFFull ? 0xFFFFFFFFull : b->count;
    pthread_mutex_lock(&audit_mutex);
    snprintf(buffer, sizeof(buffer), "%s|%ld|ACCESS_COUNT|%u|%u|%u|%u",
             last_hash, (long)time(NULL), b->uid, (uint32_t)count,
             b->classif, b->sci);
    compute_sha384(buffer, new_hash);
    memcpy(last_hash, new_hash, 129);
    pthread_mutex_unlock(&audit_mutex);
    audit_sign_and_write(buffer, new_hash);
}

void qihse_audit_access_granted(uint32_t user_id, uint16_t classif, uint16_t sci) {
    pthread_mutex_lock(&audit_mutex);
#ifndef _WIN32
    if (!audit_recovery_context_ready || audit_writer_lock_fd < 0 ||
        !audit_context_matches_process(&audit_recovery_context))
        audit_integrity_error("audit writer is not initialized in this process");
#endif
    uint64_t window = (uint64_t)time(NULL) / audit_access_window_secs();
    size_t i = access_bucket_index(user_id, classif, sci, window);
    for (size_t probe = 0; probe < AUDIT_ACCESS_SLOTS; ++probe) {
        access_bucket_t* b = &g_access_buckets[(i + probe) % AUDIT_ACCESS_SLOTS];
        if (b->used && b->uid == user_id && b->classif == classif &&
            b->sci == sci && b->window_id == window) {
            if (b->count < UINT64_MAX) b->count++;
            pthread_mutex_unlock(&audit_mutex);
            return;
        }
        if (!b->used) {
            /* Free slot. Occupied slots holding expired windows are left in
             * place for the expiry sweep, so no counted access is lost. */
            b->used = 1;
            b->uid = user_id;
            b->classif = classif;
            b->sci = sci;
            b->window_id = window;
            b->count = 1;
            b->last_seen = window;
            g_access_used++;
            pthread_mutex_unlock(&audit_mutex);
            return;
        }
    }
    /* Table full: snapshot every live bucket and emit each through the
     * normal queue, then retry once into the emptied table. */
    access_bucket_t snapshot[AUDIT_ACCESS_SLOTS];
    size_t n = access_collect_expired_locked(snapshot, AUDIT_ACCESS_SLOTS,
                                             (uint64_t)time(NULL), 1);
    pthread_mutex_unlock(&audit_mutex);
    for (size_t k = 0; k < n; ++k)
        qihse_audit_log("ACCESS_COUNT", snapshot[k].uid,
                        (uint32_t)(snapshot[k].count > 0xFFFFFFFFull
                                       ? 0xFFFFFFFFull
                                       : snapshot[k].count),
                        snapshot[k].classif, snapshot[k].sci);
    qihse_audit_access_granted(user_id, classif, sci);
}

/* Emit buckets through the producer queue. Called from threads other than
 * the signer (flush, shutdown). flush_all also emits live windows, so a
 * clean exit or completeness barrier loses no counted access. Returns the
 * number of summaries emitted. */
static size_t access_emit_via_queue(int flush_all) {
    access_bucket_t snapshot[AUDIT_ACCESS_SLOTS];
    pthread_mutex_lock(&audit_mutex);
    if (!g_signer_ok || g_signer_stop) {
        pthread_mutex_unlock(&audit_mutex);
        return 0;
    }
    uint64_t now_window = (uint64_t)time(NULL);
    size_t n = access_collect_expired_locked(snapshot, AUDIT_ACCESS_SLOTS,
                                             now_window, flush_all);
    pthread_mutex_unlock(&audit_mutex);
    for (size_t k = 0; k < n; ++k)
        qihse_audit_log("ACCESS_COUNT", snapshot[k].uid,
                        (uint32_t)(snapshot[k].count > 0xFFFFFFFFull
                                       ? 0xFFFFFFFFull
                                       : snapshot[k].count),
                        snapshot[k].classif, snapshot[k].sci);
    return n;
}

#include <fcntl.h>

/*
 * qihse_audit_webhook_ping - Fire-and-forget audit notification.
 *
 * When a non-UNCLASSIFIED access event occurs and an audit webhook endpoint
 * has been configured via qihse_audit_set_webhook(), this function posts a
 * JSON event payload to that endpoint using a non-blocking native TCP socket.
 *
 * The webhook is entirely opt-in: if no endpoint is configured (default),
 * this function returns immediately without touching the network.
 *
 * Configure at build time via Makefile:
 *   make QIHSE_AUDIT_WEBHOOK_URL="http://your.siem.host:8080"
 * Or at runtime:
 *   qihse_audit_set_webhook("192.0.2.10:9000");
 *
 * Payload format:
 *   {"event":"classified_access", "user_id":<UID>, "classif":<LEVEL>, "sci":<COMPARTMENTS>}
 */
static void send_webhook_ping(uint32_t user_id, uint16_t classif, uint16_t sci) {
    if (webhook_target[0] == '\0') return;

    // Non-blocking socket so we never stall the calling thread.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Expected format: "IP:PORT"
    char ip[64] = "127.0.0.1";
    int port = 8080;
    if (sscanf(webhook_target, "%63[^:]:%d", ip, &port) != 2) {
        snprintf(ip, sizeof(ip), "127.0.0.1");
        port = 8080;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv_addr.sin_addr);

    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    char payload[256];
    int payload_len = snprintf(payload, sizeof(payload),
        "{\"event\":\"classified_access\", \"user_id\":%u, \"classif\":%u, \"sci\":%u}",
        user_id, classif, sci);

    char request[512];
    int req_len = snprintf(request, sizeof(request),
        "POST /callout HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
        "%s", ip, port, payload_len, payload);

    // Fire-and-forget: connect() is still in progress (non-blocking),
    // send() will either succeed or fail — both outcomes are acceptable
    // for a best-effort audit notification.
    send(sock, request, req_len, MSG_NOSIGNAL);
    close(sock);
}

void qihse_audit_webhook_ping(uint32_t user_id, uint16_t classif, uint16_t sci) {
    pthread_mutex_lock(&audit_mutex);
    if (webhook_target[0] == '\0') {
        pthread_mutex_unlock(&audit_mutex);
        return; // No endpoint configured — skip entirely.
    }
    audit_ensure_signer_locked();
    if (g_signer_ok) {
        g_ping_uid = user_id;
        g_ping_classif = classif;
        g_ping_sci = sci;
        g_ping_pending = 1;
        pthread_cond_signal(&g_q_cond);
        pthread_mutex_unlock(&audit_mutex);
        return;
    }
    pthread_mutex_unlock(&audit_mutex);
    /* Signer thread unavailable — preserve the original direct-send behavior. */
    send_webhook_ping(user_id, classif, sci);
}
