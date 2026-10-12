#include "qihse_audit.h"
#include "qihse_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <fcntl.h>
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

/* ── Audit log rotation ────────────────────────────────────────────────────
 * Size-threshold rename. The hash chain is logical (last_hash → new_hash,
 * anchored in the integrity-chain file) and NOT file-bound, so rotating the
 * container between records preserves tamper-evidence across the boundary.
 * Only the signer thread (or a fallback caller while the signer is down)
 * writes records, and every record opens the path fresh with
 * O_APPEND|O_CREAT|O_NOFOLLOW, so a rename between records IS the rotation:
 * the next record re-creates the live file. Concurrent fallback writers race
 * harmlessly — an fd already open keeps writing into the renamed inode.
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

static size_t audit_rotate_keep(void) {
    const char* env = getenv("QIHSE_AUDIT_ROTATE_KEEP");
    if (env && *env) {
        char* end = NULL;
        unsigned long long v = strtoull(env, &end, 10);
        if (end && *end == '\0') return (size_t)v; /* 0 = keep everything */
    }
    return 8;
}

static void audit_prune_rotated(const char* apath) {
    size_t keep = audit_rotate_keep();
    if (keep == 0) return;

    char dirbuf[512];
    const char* base = strrchr(apath, '/');
    if (base) {
        size_t dlen = (size_t)(base - apath);
        if (dlen >= sizeof(dirbuf)) return;
        memcpy(dirbuf, apath, dlen);
        dirbuf[dlen] = '\0';
        base++;
    } else {
        snprintf(dirbuf, sizeof(dirbuf), "%s", ".");
        base = apath;
    }
    size_t base_len = strlen(base);

    char names[64][320];
    size_t count = 0;
    DIR* d = opendir(dirbuf);
    if (!d) return;
    struct dirent* de;
    while ((de = readdir(d)) != NULL && count < 64) {
        if (strncmp(de->d_name, base, base_len) != 0) continue;
        const char* suffix = de->d_name + base_len;
        if (suffix[0] != '.' || !isdigit((unsigned char)suffix[1])) continue;
        snprintf(names[count], sizeof(names[0]), "%s", de->d_name);
        count++;
    }
    closedir(d);

    /* Ascending strcmp == ascending timestamp for the numeric suffix. */
    for (size_t i = 1; i < count; i++) {
        char tmp[sizeof(names[0])];
        memcpy(tmp, names[i], sizeof(tmp));
        size_t j = i;
        while (j > 0 && strcmp(names[j - 1], tmp) > 0) {
            memcpy(names[j], names[j - 1], sizeof(names[0]));
            j--;
        }
        memcpy(names[j], tmp, sizeof(tmp));
    }
    for (size_t i = 0; i + keep < count; i++) {
        char full[640];
        if (dirbuf[strlen(dirbuf) - 1] == '/') snprintf(full, sizeof(full), "%s%s", dirbuf, names[i]);
        else snprintf(full, sizeof(full), "%s/%s", dirbuf, names[i]);
        unlink(full);
    }
}

static void audit_maybe_rotate(void) {
    char apath[512];
    build_audit_path(apath, sizeof(apath));
    struct stat st;
    if (stat(apath, &st) != 0) return;
    if ((uint64_t)st.st_size < audit_rotate_threshold()) return;

    char rotated[640];
    long t = (long)time(NULL);
    int attempt;
    for (attempt = 0; attempt < 1000; attempt++) {
        if (attempt == 0) snprintf(rotated, sizeof(rotated), "%s.%ld", apath, t);
        else snprintf(rotated, sizeof(rotated), "%s.%ld.%d", apath, t, attempt);
        if (access(rotated, F_OK) != 0) break;
    }
    if (attempt >= 1000) return; /* pathological; keep appending rather than lose records */

    if (rename(apath, rotated) != 0) return;
    audit_prune_rotated(apath);
    /* Re-create the live file immediately so the next record — and any
     * external tail — finds it in place with the right mode. */
    int fd = open(apath, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd >= 0) close(fd);
    chmod(apath, 0600);
}
/*
 * Asynchronous audit signing.
 *
 * The SHA-384 hash chain is computed synchronously (cheap, and it preserves
 * ordering + tamper-evidence), but the expensive ML-DSA-87 signature and the
 * audit-file / integrity-chain writes are performed by a background signer
 * thread.  qihse_audit_log() therefore no longer pays the ~6.5 ms/entry
 * signing cost on the calling thread, while the emitted records are
 * byte-identical and in the same order as the synchronous implementation.
 */
typedef struct audit_pending {
    char buffer[1024];
    char new_hash[129];
    struct audit_pending* next;
} audit_pending_t;

static audit_pending_t* g_q_head = NULL;
static audit_pending_t* g_q_tail = NULL;
static pthread_cond_t g_q_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_q_empty_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_signer_tid;
static int g_signer_started = 0;
static int g_signer_ok = 0;
static int g_signer_stop = 0;
static int g_signer_busy = 0;

/* Start the background signer if it isn't running yet.  Must be called
 * with audit_mutex held.  Also registers the atexit teardown handler on
 * first use.  If the thread cannot start, callers fall back to sync. */
static void* audit_signer_main(void* arg);

static void audit_register_atfork(void);

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
 * The signer thread does not survive fork(): the child inherits a copy of
 * the process with the signer thread GONE but every audit mutex frozen in
 * whatever state the parent's threads left it — the first child action that
 * logs (or drains the queue) then deadlocks on a mutex no surviving thread
 * will ever release.  pthread_atfork handlers fence the signer around the
 * fork and restart it fresh in the child, so a forked server (test harnesses
 * fork per session; the cluster daemon forks workers) keeps a working audit
 * path.  The child's queue is drained-to-nothing by design: entries queued
 * pre-fork were signed and written by the PARENT's signer before the fence
 * (prepare waits for the queue to empty), so nothing is lost and nothing is
 * duplicated. */
static void audit_atfork_prepare(void) {
    pthread_mutex_lock(&audit_mutex);
    /* Wait for the signer to drain the queue so pre-fork entries are on
     * disk before the address space splits. */
    while ((g_q_head || g_ping_pending || g_signer_busy) &&
           g_signer_ok && !g_signer_stop) {
        pthread_mutex_unlock(&audit_mutex);
        usleep(1000);
        pthread_mutex_lock(&audit_mutex);
    }
}

static void audit_atfork_parent(void) {
    pthread_mutex_unlock(&audit_mutex);
}

static void audit_atfork_child(void) {
    /* The signer thread does not exist in the child: reset its bookkeeping
     * so the next audit entry restarts it.  Mutexes are frozen-unlocked by
     * the prepare fence above; the queue is empty (prepare drained it). */
    g_q_head = NULL;
    g_q_tail = NULL;
    g_ping_pending = 0;
    g_signer_busy = 0;
    g_signer_tid = pthread_self(); /* mark invalid-ish; started flag drives */
    g_signer_ok = 0;
    g_signer_started = 0;
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

static void write_obfuscated(FILE *f, const char* buffer) {
    size_t len = strlen(buffer);
    if (len + 1u > 4096u) {
        for (size_t i = 0; i < len; i++) fputc(buffer[i] ^ XOR_KEY, f);
        fputc('\n' ^ XOR_KEY, f);
        return;
    }
    char tmp[4096];
    for (size_t i = 0; i < len; i++) tmp[i] = (char)(buffer[i] ^ XOR_KEY);
    tmp[len] = (char)('\n' ^ XOR_KEY);
    fwrite(tmp, 1u, len + 1u, f);
}

static int update_integrity_chain(const char* new_hash);

#ifndef _WIN32
static int audit_hex_hash(const char *value) {
    for (size_t i = 0; i < 96u; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    }
    return 1;
}

/* Recover the previous process's chain head only when its final on-disk
 * record agrees with the separate chain file. This verifies the final link,
 * not an independently anchored history of every rotated record. */
static int audit_recover_last_hash(void) {
    char chain_path[4096], audit_path[4096], stored[97];
    build_chain_path(chain_path, sizeof(chain_path));
    int chain_fd = open(chain_path, O_RDONLY | O_NOFOLLOW);
    if (chain_fd < 0) return 0; /* No chain file: new audit history. */
    struct stat chain_stat;
    int valid = fstat(chain_fd, &chain_stat) == 0 &&
                S_ISREG(chain_stat.st_mode) && chain_stat.st_size == 96 &&
                read(chain_fd, stored, 96u) == 96 && audit_hex_hash(stored);
    close(chain_fd);
    if (!valid) return -1;
    stored[96] = '\0';

    build_audit_path(audit_path, sizeof(audit_path));
    int audit_fd = open(audit_path, O_RDONLY | O_NOFOLLOW);
    if (audit_fd < 0) return -1;
    struct stat audit_stat;
    if (fstat(audit_fd, &audit_stat) != 0 ||
        !S_ISREG(audit_stat.st_mode) || audit_stat.st_size <
        (off_t)MLDSA87_SIG_BYTES + 100) {
        close(audit_fd);
        return -1;
    }
    /* Startup markers are not chained records. Earlier versions appended
     * one on every restart, including restarts with no later audit event. */
    size_t window = audit_stat.st_size < 65536 ?
                    (size_t)audit_stat.st_size : 65536u;
    char *scan = malloc(window);
    if (!scan) { close(audit_fd); return -1; }
    ssize_t scanned = pread(audit_fd, scan, window,
                            audit_stat.st_size - (off_t)window);
    if (scanned != (ssize_t)window) {
        free(scan);
        close(audit_fd);
        return -1;
    }
    for (size_t i = 0; i < window; i++) scan[i] ^= XOR_KEY;
    static const char suffix[] = "|SIG_MLDSA87_ATTACHED\n";
    const size_t suffix_len = sizeof(suffix) - 1u;
    static const char marker[] = "--- SYSTEM AUTH CACHE INITIALIZED [";
    off_t record_end = -1;
    for (size_t i = window; i-- > 0;) {
        if (i + suffix_len + MLDSA87_SIG_BYTES > window ||
            memcmp(scan + i, suffix, suffix_len) != 0) continue;
        size_t trailing = i + suffix_len + MLDSA87_SIG_BYTES;
        int valid_trailer = 1;
        while (trailing < window) {
            if (window - trailing < sizeof(marker) - 1u ||
                memcmp(scan + trailing, marker, sizeof(marker) - 1u) != 0) {
                valid_trailer = 0;
                break;
            }
            char *newline = memchr(scan + trailing, '\n', window - trailing);
            if (!newline || (size_t)(newline - (scan + trailing)) > 256u) {
                valid_trailer = 0;
                break;
            }
            trailing = (size_t)(newline - scan) + 1u;
        }
        if (valid_trailer) {
            record_end = audit_stat.st_size - (off_t)window +
                         (off_t)i + (off_t)suffix_len;
            break;
        }
    }
    free(scan);
    if (record_end < 0) { close(audit_fd); return -1; }
    size_t length = record_end < 4096 ? (size_t)record_end : 4096u;
    char tail[4097];
    ssize_t got = pread(audit_fd, tail, length, record_end - (off_t)length);
    close(audit_fd);
    if (got != (ssize_t)length) return -1;
    for (size_t i = 0; i < length; i++) tail[i] ^= XOR_KEY;
    tail[length] = '\0';
    if (length < suffix_len + 97u ||
        memcmp(tail + length - suffix_len, suffix, suffix_len) != 0) return -1;
    size_t hash_at = length - suffix_len - 96u;
    if (hash_at == 0 || tail[hash_at - 1u] != '|' ||
        !audit_hex_hash(tail + hash_at) ||
        memcmp(tail + hash_at, stored, 96u) != 0) return -1;
    char saved = tail[hash_at - 1u];
    tail[hash_at - 1u] = '\0';
    int matched = 0;
    for (size_t start = 0; start + 97u <= hash_at - 1u; start++) {
        if (tail[start + 96u] != '|' || !audit_hex_hash(tail + start) ||
            hash_at - 1u - start >= 1024u) continue;
        char calculated[129];
        compute_sha384(tail + start, calculated);
        if (memcmp(calculated, stored, 96u) == 0) {
            matched = 1;
            break;
        }
    }
    tail[hash_at - 1u] = saved;
    if (!matched) return -1;
    memcpy(last_hash, stored, sizeof(stored));
    return 1;
}
#endif

void qihse_audit_verify_integrity(void) {
#ifndef _WIN32
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    int sfd = open(chain_path, O_RDONLY | O_NOFOLLOW);
    if (sfd >= 0) {
    FILE *sf = fdopen(sfd, "r");
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
    } else {
        close(sfd);
    }
    }
    // No integrity chain file = fresh start, no lockdown
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

static int update_integrity_chain(const char* new_hash) {
#ifndef _WIN32
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    char temporary[sizeof(chain_path) + 16u];
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX",
                     chain_path);
    if (n < 0 || (size_t)n >= sizeof(temporary)) return 0;
    int fd = mkstemp(temporary);
    if (fd < 0) return 0;
    int ok = fchmod(fd, 0600) == 0;
    size_t written = 0;
    while (ok && written < 96u) {
        ssize_t count = write(fd, new_hash + written, 96u - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = 0; break; }
        written += (size_t)count;
    }
    if (ok && fsync(fd) != 0) ok = 0;
    if (close(fd) != 0) ok = 0;
    if (ok && rename(temporary, chain_path) != 0) ok = 0;
    if (!ok) { unlink(temporary); return 0; }
    char directory[sizeof(chain_path)];
    const char *slash = strrchr(chain_path, '/');
    if (slash) {
        size_t length = (size_t)(slash - chain_path);
        if (length == 0 || length >= sizeof(directory)) return 0;
        memcpy(directory, chain_path, length);
        directory[length] = '\0';
    } else {
        memcpy(directory, ".", 2u);
    }
    int dir_fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0) return 0;
    ok = fsync(dir_fd) == 0;
    close(dir_fd);
    return ok;
#else
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    FILE *sf = fopen(chain_path, "w");
    if (!sf) return 0;
    int ok = fprintf(sf, "%s", new_hash) == 96;
    if (fclose(sf) != 0) ok = 0;
    return ok;
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

#ifndef _WIN32
    if (audit_recover_last_hash() < 0) {
        fprintf(stderr, "[QIHSE AUDIT] Integrity chain mismatch detected!\n");
        const char *strict = getenv("QIHSE_STRICT_AUDIT");
        if (strict && strcmp(strict, "1") == 0) {
            fprintf(stderr, "[QIHSE AUDIT] Strict audit enforcement: aborting on integrity mismatch.\n");
            abort();
        }
    }
#endif

    char apath[512];
    build_audit_path(apath, sizeof(apath));
#ifndef _WIN32
    /* A file that already exceeds the threshold (e.g. after months of
     * un-rotated runtime) is archived here at startup, before any new
     * record lands. */
    audit_maybe_rotate();
#endif
    FILE *f = fopen(apath, "ab");
    if (f) {
        if (audit_pkey) {
            write_obfuscated(f, "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 ML-DSA-87 ENABLED] ---");
        } else {
            write_obfuscated(f, "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 SHA-384 HASH CHAIN (PQC UNAVAILABLE)] ---");
        }
        fclose(f);
#ifndef _WIN32
        chmod(apath, 0600);
#endif
    }
    /* Start the background signer so qihse_audit_log() never blocks on the
     * ~6.5 ms/entry ML-DSA-87 signing path.  If the thread cannot start, the
     * log path transparently falls back to synchronous signing. */
    audit_ensure_signer_locked();
    pthread_mutex_unlock(&audit_mutex);
#ifdef _WIN32
    qihse_audit_verify_integrity();
#endif
}

/* The expensive part: ML-DSA-87 signature + audit file + integrity chain.
 * Runs on the signer thread (or inline as a fallback). */
static void audit_sign_and_write(const char* buffer, const char* new_hash) {
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
    int afd = open(apath2, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    FILE *f = NULL;
    if (afd >= 0) f = fdopen(afd, "ab");
#else
    char wpath[512];
    build_audit_path(wpath, sizeof(wpath));
    FILE *f = fopen(wpath, "ab");
#endif
    int recorded = 0;
    if (f) {
        char out_buf[2048];
        snprintf(out_buf, sizeof(out_buf), "%s|%s|SIG_MLDSA87_ATTACHED", buffer, new_hash);
        write_obfuscated(f, out_buf);
        char sigbuf[MLDSA87_SIG_BYTES];
        for (int i = 0; i < MLDSA87_SIG_BYTES; i++) sigbuf[i] = (char)(mldsa87_sig[i] ^ XOR_KEY);
        size_t sig_written = fwrite(sigbuf, 1u, sizeof(sigbuf), f);
        int write_error = ferror(f) || fflush(f) != 0;
#ifndef _WIN32
        if (!write_error && fsync(fileno(f)) != 0) write_error = 1;
#endif
        int close_error = fclose(f);
        recorded = sig_written == sizeof(sigbuf) && !write_error &&
                   close_error == 0;
    }
#ifndef _WIN32
    if (afd >= 0 && !f) close(afd);
#endif

    if (!recorded) {
        fprintf(stderr, "[QIHSE AUDIT] Failed to persist audit record.\n");
        const char *strict = getenv("QIHSE_STRICT_AUDIT");
        if (strict && strcmp(strict, "1") == 0) abort();
        return;
    }
    if (!update_integrity_chain(new_hash)) {
        fprintf(stderr, "[QIHSE AUDIT] Failed to persist integrity chain.\n");
        const char *strict = getenv("QIHSE_STRICT_AUDIT");
        if (strict && strcmp(strict, "1") == 0) abort();
    }
}

static void* audit_signer_main(void* arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&audit_mutex);
        while (!g_q_head && !g_ping_pending && !g_signer_stop) {
            pthread_cond_wait(&g_q_cond, &audit_mutex);
        }
        if (!g_q_head && !g_ping_pending && g_signer_stop) {
            pthread_mutex_unlock(&audit_mutex);
            return NULL;
        }
        audit_pending_t* e = g_q_head;
        if (e) {
            g_q_head = e->next;
            if (!g_q_head) g_q_tail = NULL;
        }
        int ping = g_ping_pending;
        uint32_t pu = g_ping_uid; uint16_t pc = g_ping_classif, ps = g_ping_sci;
        g_ping_pending = 0;
        g_signer_busy = 1;
        pthread_mutex_unlock(&audit_mutex);

        if (e) { audit_sign_and_write(e->buffer, e->new_hash); free(e); }
        if (ping) send_webhook_ping(pu, pc, ps);
        pthread_mutex_lock(&audit_mutex);
        g_signer_busy = 0;
        if (!g_q_head && !g_ping_pending)
            pthread_cond_broadcast(&g_q_empty_cond);
        pthread_mutex_unlock(&audit_mutex);
    }
}

/* Block until every queued audit entry has been signed and written. */
void qihse_audit_flush(void) {
    if (!g_signer_ok) return;
    pthread_mutex_lock(&audit_mutex);
    while ((g_q_head || g_ping_pending || g_signer_busy) &&
           !g_signer_stop) {
        pthread_cond_wait(&g_q_empty_cond, &audit_mutex);
    }
    pthread_mutex_unlock(&audit_mutex);
}

/* Drain the queue and stop the signer thread. */
void qihse_audit_shutdown(void) {
    if (!g_signer_ok) return;
    qihse_audit_flush();
    pthread_mutex_lock(&audit_mutex);
    g_signer_stop = 1;
    pthread_cond_broadcast(&g_q_cond);
    pthread_mutex_unlock(&audit_mutex);
    pthread_join(g_signer_tid, NULL);
    g_signer_ok = 0;
    g_signer_started = 0;
}

void qihse_audit_log(const char* action, uint32_t user_id, uint32_t target_id, uint16_t classif, uint16_t sci) {
    char buffer[1024];
    char new_hash[129];

    /* Hash-chain step stays synchronous: it is cheap and preserves the exact
     * ordering and tamper-evidence of the chain. */
    pthread_mutex_lock(&audit_mutex);
    time_t now = time(NULL);
    snprintf(buffer, sizeof(buffer), "%s|%ld|%s|%u|%u|%u|%u",
             last_hash, (long)now, action, user_id, target_id, classif, sci);
    compute_sha384(buffer, new_hash);
    memcpy(last_hash, new_hash, 129);

    /* Offload the ML-DSA-87 signature + file writes to the signer thread. */
    if (g_signer_ok) {
        audit_pending_t* e = (audit_pending_t*)malloc(sizeof(*e));
        if (e) {
            memcpy(e->buffer, buffer, sizeof(e->buffer));
            memcpy(e->new_hash, new_hash, sizeof(e->new_hash));
            e->next = NULL;
            if (g_q_tail) g_q_tail->next = e; else g_q_head = e;
            g_q_tail = e;
            pthread_cond_signal(&g_q_cond);
            pthread_mutex_unlock(&audit_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&audit_mutex);

    /* Fallback (signer unavailable or allocation failure): sign inline so an
     * entry is never silently dropped. */
    audit_sign_and_write(buffer, new_hash);
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
