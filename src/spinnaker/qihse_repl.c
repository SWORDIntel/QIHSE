#include "qihse_repl.h"
#include "qihse_wal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

/* Replay staging helpers, defined with the applier below. */
static int  repl_stage_open(qihse_repl_context_t* ctx);
static void repl_stage_close(qihse_repl_context_t* ctx);

qihse_repl_context_t* qihse_repl_create(repl_role_t role) {
    qihse_repl_context_t* ctx = (qihse_repl_context_t*)calloc(1, sizeof(qihse_repl_context_t));
    if (!ctx) return NULL;
    ctx->role = role;
    ctx->state = REPL_STATE_DISCONNECTED;
    ctx->stream_fd = -1;
    ctx->sync_mode = 0;
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->slots = NULL;
    ctx->num_slots = 0;
    ctx->slots_cap = 0;
    ctx->store = NULL;        /* bound later with qihse_repl_set_store() */
    ctx->stage_dir = NULL;    /* replay staging, created on first apply */
    ctx->stage_seg = NULL;
    return ctx;
}

int qihse_repl_connect_primary(qihse_repl_context_t* ctx, const char* host, uint16_t port) {
    if (!ctx || !host) return -1;
    pthread_mutex_lock(&ctx->lock);
    free(ctx->primary_host);
    ctx->primary_host = strdup(host);
    ctx->primary_port = port;
    ctx->state = REPL_STATE_CONNECTING;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { ctx->state = REPL_STATE_ERROR; pthread_mutex_unlock(&ctx->lock); return -1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        ctx->state = REPL_STATE_ERROR;
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        ctx->state = REPL_STATE_ERROR;
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    
    ctx->stream_fd = fd;
    ctx->state = REPL_STATE_CONNECTING;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_start_streaming(qihse_repl_context_t* ctx) {
    if (!ctx || ctx->stream_fd < 0) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->state = REPL_STATE_STREAMING;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_stop(qihse_repl_context_t* ctx) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (ctx->stream_fd >= 0) { close(ctx->stream_fd); ctx->stream_fd = -1; }
    ctx->state = REPL_STATE_DISCONNECTED;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

void qihse_repl_destroy(qihse_repl_context_t* ctx) {
    if (!ctx) return;
    qihse_repl_stop(ctx);
    pthread_mutex_lock(&ctx->lock);
    free(ctx->primary_host);
    free(ctx->replica_name);
    for (size_t i = 0; i < ctx->num_slots; i++) free(ctx->slots[i].name);
    free(ctx->slots);
    repl_stage_close(ctx);
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

int qihse_repl_ship_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn) {
    if (!ctx || !wal_data || len == 0) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (ctx->stream_fd < 0 || ctx->state != REPL_STATE_STREAMING) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    /* Send: [8-byte LSN][8-byte length][data] */
    uint64_t hdr[2];
    hdr[0] = lsn;
    hdr[1] = (uint64_t)len;
    ssize_t w = write(ctx->stream_fd, hdr, sizeof(hdr));
    if (w != (ssize_t)sizeof(hdr)) { ctx->state = REPL_STATE_ERROR; pthread_mutex_unlock(&ctx->lock); return -1; }
    w = write(ctx->stream_fd, wal_data, len);
    if (w != (ssize_t)len) { ctx->state = REPL_STATE_ERROR; pthread_mutex_unlock(&ctx->lock); return -1; }
    ctx->last_lsn = lsn;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

/* ── Replica-side apply ─────────────────────────────────────────────────── */

/* The applier does not hand-parse a record into a store mutation: it stages
 * the received bytes as the only record of a private WAL segment and drives
 * qihse_wal_replay() over it.  The WAL layer therefore owns every decision
 * about whether the bytes are a record (header, declared lengths, CRC32), and
 * the store mutation runs in the replay callback, which the WAL layer calls
 * only after it has accepted the record — a refused record never reaches the
 * store, so there is nothing to roll back. */

#define REPL_APPLY_SEGMENT_SIZE (1u << 20)

/* Staging paths are heap-held by the context: a decoder that keeps PATH_MAX
 * buffers on the stack is exactly what AGENTS.md forbids, and TMPDIR has no
 * fixed bound.  Called with ctx->lock held. */
static int repl_stage_open(qihse_repl_context_t* ctx) {
    if (ctx->stage_dir) return 0;
    const char* tmp = getenv("TMPDIR");
    if (!tmp || tmp[0] == '\0') tmp = ".";   /* relative fallback, per AGENTS.md */
    size_t dirlen = strlen(tmp);
    bool needs_slash = (tmp[dirlen - 1u] != '/');
    size_t cap = dirlen + (needs_slash ? 1u : 0u) + sizeof("qihse-repl-stage-XXXXXX");
    char* dir = (char*)malloc(cap);
    if (!dir) return -1;
    snprintf(dir, cap, "%s%sqihse-repl-stage-XXXXXX", tmp, needs_slash ? "/" : "");
    if (!mkdtemp(dir)) { free(dir); return -1; }

    size_t segcap = strlen(dir) + sizeof("/wal_00000000000000000000.log");
    char* seg = (char*)malloc(segcap);
    if (!seg) { rmdir(dir); free(dir); return -1; }
    snprintf(seg, segcap, "%s/wal_%020lu.log", dir, 0ul);

    ctx->stage_dir = dir;
    ctx->stage_seg = seg;
    return 0;
}

/* Remove the staging area.  Called with ctx->lock held (destroy, or the retry
 * in apply after an external cleaner removed the directory). */
static void repl_stage_close(qihse_repl_context_t* ctx) {
    if (ctx->stage_seg) {
        unlink(ctx->stage_seg);
        free(ctx->stage_seg);
        ctx->stage_seg = NULL;
    }
    if (ctx->stage_dir) {
        rmdir(ctx->stage_dir);
        free(ctx->stage_dir);
        ctx->stage_dir = NULL;
    }
}

/* A length-delimited WAL field as a NUL-terminated C string, because the KV
 * layer's key/value API is string based.  A field with an embedded NUL cannot
 * be represented there, and returning NULL refuses the record instead of
 * silently truncating it. */
static char* repl_field_str(const void* field, uint32_t len) {
    if (len > 0 && !field) return NULL;
    char* s = (char*)malloc((size_t)len + 1u);
    if (!s) return NULL;
    if (len > 0) memcpy(s, field, len);
    s[len] = '\0';
    if (strlen(s) != (size_t)len) { free(s); return NULL; }
    return s;
}

typedef struct repl_apply_seen_s {
    qihse_kv_store_t* store;
    uint64_t          lsn;      /* the LSN the caller declared for this record */
    bool              refused;  /* the record or the store refused the mutation */
} repl_apply_seen_t;

static bool repl_apply_cb(const qihse_wal_record_t* record, const void* key,
                          uint32_t key_len, const void* value, uint32_t value_len,
                          void* user_data) {
    repl_apply_seen_t* seen = (repl_apply_seen_t*)user_data;
    if (!record || record->lsn != seen->lsn) { seen->refused = true; return false; }

    switch (record->op_type) {
    case QIHSE_WAL_OP_INSERT:
    case QIHSE_WAL_OP_UPDATE: {
        char* k = repl_field_str(key, key_len);
        char* v = repl_field_str(value, value_len);
        bool ok = (k && v && qihse_kv_set(seen->store, k, v, 0u, 0u));
        free(k);
        free(v);
        if (!ok) { seen->refused = true; return false; }
        return true;
    }
    case QIHSE_WAL_OP_DELETE: {
        char* k = repl_field_str(key, key_len);
        bool ok = (k && qihse_kv_del(seen->store, k));
        free(k);
        /* A false from the store is a refusal, not a no-op: a context-free
         * principal cannot distinguish "the key is absent" from "the key is
         * present but above its clearance", so neither is reported as
         * applied. */
        if (!ok) { seen->refused = true; return false; }
        return true;
    }
    case QIHSE_WAL_OP_BEGIN:
    case QIHSE_WAL_OP_COMMIT:
    case QIHSE_WAL_OP_ABORT:
    case QIHSE_WAL_OP_CHECKPOINT:
        return true;   /* no store mutation; the position still advances */
    default:
        seen->refused = true;
        return false;
    }
}

int qihse_repl_set_store(qihse_repl_context_t* ctx, qihse_kv_store_t* store) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->store = store;   /* borrowed, never owned */
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

qihse_kv_store_t* qihse_repl_get_store(qihse_repl_context_t* ctx) {
    if (!ctx) return NULL;
    pthread_mutex_lock(&ctx->lock);
    qihse_kv_store_t* store = ctx->store;
    pthread_mutex_unlock(&ctx->lock);
    return store;
}

int qihse_repl_apply_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn) {
    if (!ctx || !wal_data || len == 0) return -1;

    pthread_mutex_lock(&ctx->lock);

    /* An applier with no target store accepts nothing: advancing flush_lsn for
     * a record that reached no store is the false acknowledgement this path
     * exists to prevent. */
    if (!ctx->store || lsn == QIHSE_WAL_INVALID_LSN ||
        len < (size_t)QIHSE_WAL_RECORD_HEADER_SIZE) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    /* Ordering/idempotency watermark: at or below replay_lsn the record has
     * already reached the store.  It is not applied twice, and success is
     * still reported so a retransmission is a no-op rather than an error. */
    if (ctx->replay_lsn != QIHSE_WAL_INVALID_LSN && lsn <= ctx->replay_lsn) {
        pthread_mutex_unlock(&ctx->lock);
        return 0;
    }

    /* The declared field lengths must agree with the encoded length.  The
     * checksum is deliberately not recomputed here — the record is replayed
     * and qihse_wal_replay() is what verifies it. */
    uint32_t key_len = 0, value_len = 0;
    memcpy(&key_len, wal_data + 18, 4);
    memcpy(&value_len, wal_data + 22, 4);
    if (key_len > QIHSE_WAL_MAX_KEY || value_len > QIHSE_WAL_MAX_VALUE ||
        (size_t)QIHSE_WAL_RECORD_HEADER_SIZE + (size_t)key_len + (size_t)value_len != len) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    if (repl_stage_open(ctx) != 0) { pthread_mutex_unlock(&ctx->lock); return -1; }

    int fd = open(ctx->stage_seg, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 && errno == ENOENT) {
        /* The staging directory was removed under us (a tmp cleaner): rebuild
         * it once rather than refusing every record from now on. */
        repl_stage_close(ctx);
        if (repl_stage_open(ctx) != 0) { pthread_mutex_unlock(&ctx->lock); return -1; }
        fd = open(ctx->stage_seg, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    }
    if (fd < 0) { pthread_mutex_unlock(&ctx->lock); return -1; }

    bool wrote = true;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, wal_data + off, len - off);
        if (w <= 0) { wrote = false; break; }
        off += (size_t)w;
    }
    if (close(fd) != 0) wrote = false;

    repl_apply_seen_t seen;
    memset(&seen, 0, sizeof(seen));
    seen.store = ctx->store;
    seen.lsn = lsn;

    int replayed = -1;
    if (wrote) {
        qihse_wal_t* staged = qihse_wal_create(ctx->stage_dir, REPL_APPLY_SEGMENT_SIZE,
                                               QIHSE_WAL_DURABILITY_NONE);
        if (staged) {
            replayed = qihse_wal_replay(staged, QIHSE_WAL_INVALID_LSN, repl_apply_cb, &seen);
            qihse_wal_destroy(staged);
        }
    }
    unlink(ctx->stage_seg);   /* the staging area holds one record at a time */

    if (replayed != 1 || seen.refused) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    ctx->replay_lsn = lsn;
    ctx->flush_lsn = lsn;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_get_status(qihse_repl_context_t* ctx, uint64_t* last_lsn, uint64_t* flush_lsn, repl_state_t* state) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (last_lsn) *last_lsn = ctx->last_lsn;
    if (flush_lsn) *flush_lsn = ctx->flush_lsn;
    if (state) *state = ctx->state;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_create_slot(qihse_repl_context_t* ctx, const char* name) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    /* Check if slot already exists */
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, name) == 0) { pthread_mutex_unlock(&ctx->lock); return -1; }
    }
    if (ctx->num_slots >= ctx->slots_cap) {
        ctx->slots_cap = ctx->slots_cap ? ctx->slots_cap * 2 : 4;
        ctx->slots = (qihse_repl_slot_t*)realloc(ctx->slots, ctx->slots_cap * sizeof(qihse_repl_slot_t));
    }
    ctx->slots[ctx->num_slots].name = strdup(name);
    ctx->slots[ctx->num_slots].restart_lsn = 0;
    ctx->slots[ctx->num_slots].confirmed_flush_lsn = 0;
    ctx->slots[ctx->num_slots].active = 0;
    ctx->num_slots++;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_drop_slot(qihse_repl_context_t* ctx, const char* name) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, name) == 0) {
            free(ctx->slots[i].name);
            memmove(&ctx->slots[i], &ctx->slots[i+1], (ctx->num_slots - i - 1) * sizeof(qihse_repl_slot_t));
            ctx->num_slots--;
            pthread_mutex_unlock(&ctx->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return -1;
}

int qihse_repl_advance_slot(qihse_repl_context_t* ctx, const char* name, uint64_t new_lsn) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, name) == 0) {
            if (new_lsn > ctx->slots[i].restart_lsn) ctx->slots[i].restart_lsn = new_lsn;
            ctx->slots[i].confirmed_flush_lsn = new_lsn;
            pthread_mutex_unlock(&ctx->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return -1;
}

size_t qihse_repl_slot_count(qihse_repl_context_t* ctx) {
    if (!ctx) return 0;
    pthread_mutex_lock(&ctx->lock);
    size_t n = ctx->num_slots;
    pthread_mutex_unlock(&ctx->lock);
    return n;
}
