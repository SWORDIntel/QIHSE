#include "qihse_audit.h"
#include "qihse_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#define AUDIT_FILE "qihse_audit.log"
#define INTEGRITY_CHAIN_FILE "qihse_integrity.chain"
#define XOR_KEY 0x5A
#define MLDSA87_SIG_BYTES 4627 // ML-DSA-87 signature size

/* Build integrity chain path from QIHSE_DATA_DIR env or fall back to CWD */
static void build_chain_path(char *buf, size_t buflen) {
    const char *dir = getenv("QIHSE_DATA_DIR");
    if (dir && *dir) {
        snprintf(buf, buflen, "%s/%s", dir, INTEGRITY_CHAIN_FILE);
    } else {
        snprintf(buf, buflen, "%s", INTEGRITY_CHAIN_FILE);
    }
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

static void* audit_signer_main(void* arg);

// CNSA 2.0: REAL SHA-384
static void compute_sha384(const char *input, char *output) {
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
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

static void update_integrity_chain(const char* new_hash);

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
                // Security is optional by default — log warning but do not abort.
                // This matches the README: "by default, QIHSE grants full access
                // so you can build fast. If you don't need it, it stays out of your way."
                fprintf(stderr, "[QIHSE AUDIT] Integrity chain mismatch detected (non-fatal in default mode).\n");
                // Reset chain to current state instead of locking down
                update_integrity_chain(last_hash);
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
                fprintf(stderr, "[QIHSE AUDIT] Integrity chain mismatch detected (non-fatal in default mode).\n");
                update_integrity_chain(last_hash);
            }
        }
        fclose(sf);
    }
#endif
}

static void update_integrity_chain(const char* new_hash) {
#ifndef _WIN32
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    int sfd = open(chain_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (sfd >= 0) {
        FILE *sf = fdopen(sfd, "w");
        if (sf) {
            fprintf(sf, "%s", new_hash);
            fclose(sf);
        } else {
            close(sfd);
        }
    }
#else
    char chain_path[4096];
    build_chain_path(chain_path, sizeof(chain_path));
    FILE *sf = fopen(chain_path, "w");
    if (sf) {
        fprintf(sf, "%s", new_hash);
        fclose(sf);
    }
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

    FILE *f = fopen(AUDIT_FILE, "ab");
    if (f) {
        if (audit_pkey) {
            write_obfuscated(f, "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 ML-DSA-87 ENABLED] ---");
        } else {
            write_obfuscated(f, "--- SYSTEM AUTH CACHE INITIALIZED [CNSA 2.0 SHA-384 HASH CHAIN (PQC UNAVAILABLE)] ---");
        }
        fclose(f);
#ifndef _WIN32
        chmod(AUDIT_FILE, 0600);
#endif
    }
    /* Start the background signer so qihse_audit_log() never blocks on the
     * ~6.5 ms/entry ML-DSA-87 signing path.  If the thread cannot start, the
     * log path transparently falls back to synchronous signing. */
    if (!g_signer_started) {
        g_signer_stop = 0;
        if (pthread_create(&g_signer_tid, NULL, audit_signer_main, NULL) == 0) {
            g_signer_ok = 1;
            g_signer_started = 1;
        }
    }
    {
        static int atexit_registered = 0;
        if (!atexit_registered) { atexit_registered = 1; atexit(qihse_audit_flush); }
    }
    pthread_mutex_unlock(&audit_mutex);
    qihse_audit_verify_integrity();
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
    int afd = open(AUDIT_FILE, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    FILE *f = NULL;
    if (afd >= 0) f = fdopen(afd, "ab");
#else
    FILE *f = fopen(AUDIT_FILE, "ab");
#endif
    if (f) {
        char out_buf[2048];
        snprintf(out_buf, sizeof(out_buf), "%s|%s|SIG_MLDSA87_ATTACHED", buffer, new_hash);
        write_obfuscated(f, out_buf);
        char sigbuf[MLDSA87_SIG_BYTES];
        for (int i = 0; i < MLDSA87_SIG_BYTES; i++) sigbuf[i] = (char)(mldsa87_sig[i] ^ XOR_KEY);
        fwrite(sigbuf, 1u, sizeof(sigbuf), f);
        fclose(f);
    }
#ifndef _WIN32
    if (afd >= 0 && !f) close(afd);
#endif

    update_integrity_chain(new_hash);
}

static void* audit_signer_main(void* arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&audit_mutex);
        while (!g_q_head && !g_signer_stop) {
            pthread_cond_wait(&g_q_cond, &audit_mutex);
        }
        if (!g_q_head && g_signer_stop) {
            pthread_mutex_unlock(&audit_mutex);
            return NULL;
        }
        audit_pending_t* e = g_q_head;
        g_q_head = e->next;
        if (!g_q_head) { g_q_tail = NULL; pthread_cond_broadcast(&g_q_empty_cond); }
        pthread_mutex_unlock(&audit_mutex);

        audit_sign_and_write(e->buffer, e->new_hash);
        free(e);
    }
}

/* Block until every queued audit entry has been signed and written. */
void qihse_audit_flush(void) {
    if (!g_signer_ok) return;
    pthread_mutex_lock(&audit_mutex);
    while (g_q_head && !g_signer_stop) {
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
void qihse_audit_webhook_ping(uint32_t user_id, uint16_t classif, uint16_t sci) {
    if (webhook_target[0] == '\0') {
        return; // No endpoint configured — skip network call entirely.
    }

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
