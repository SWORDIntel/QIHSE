/* QIHSE federation — stage F0 primitives.
 *
 * Identity, hybrid logical time, object generations, and fencing epochs.
 * No behaviour changes to the existing cluster: these are the vocabulary the
 * federation stages (F1+) are built from.
 * See docs/plans/qihse_federation_upgrade_plan.md §7. */
#include "qihse_federation.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_event_stream.h"
#include "qihse_kv_store.h"

/* ── UUID ───────────────────────────────────────────────────────────────── */

bool qihse_uuid_generate(qihse_uuid_t* out) {
    if (!out) return false;
    if (RAND_bytes(out->bytes, (int)QIHSE_UUID_BYTES) != 1) return false;
    out->bytes[6] = (uint8_t)((out->bytes[6] & 0x0Fu) | 0x40u); /* version 4 */
    out->bytes[8] = (uint8_t)((out->bytes[8] & 0x3Fu) | 0x80u); /* RFC 4122 variant */
    return true;
}

bool qihse_uuid_from_seed(const void* seed, size_t seed_len, qihse_uuid_t* out) {
    if (!out || (!seed && seed_len > 0)) return false;
    uint8_t digest[48]; /* SHA-384 */
    unsigned int digest_len = 0;
    if (EVP_Digest(seed, seed_len, digest, &digest_len, EVP_sha384(), NULL) != 1 ||
        digest_len < QIHSE_UUID_BYTES) {
        return false;
    }
    memcpy(out->bytes, digest, QIHSE_UUID_BYTES);
    out->bytes[6] = (uint8_t)((out->bytes[6] & 0x0Fu) | 0x50u); /* version 5 (name-based) */
    out->bytes[8] = (uint8_t)((out->bytes[8] & 0x3Fu) | 0x80u);
    return true;
}

static int uuid_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool qihse_uuid_parse(const char* text, qihse_uuid_t* out) {
    if (!text || !out) return false;
    size_t o = 0;
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++) {
        if (text[o] == '-') o++;
        int hi = uuid_hex_val(text[o]);
        int lo = uuid_hex_val(text[o + 1u]);
        if (hi < 0 || lo < 0) return false;
        out->bytes[i] = (uint8_t)((hi << 4) | lo);
        o += 2u;
    }
    return text[o] == '\0';
}

bool qihse_uuid_format(const qihse_uuid_t* id, char out[QIHSE_UUID_STR_LEN + 1u]) {
    if (!id || !out) return false;
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++) {
        if (i == 4u || i == 6u || i == 8u || i == 10u) out[o++] = '-';
        out[o++] = hex[(id->bytes[i] >> 4) & 0x0Fu];
        out[o++] = hex[id->bytes[i] & 0x0Fu];
    }
    out[o] = '\0';
    return o == QIHSE_UUID_STR_LEN;
}

bool qihse_uuid_is_nil(const qihse_uuid_t* id) {
    if (!id) return true;
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++)
        if (id->bytes[i] != 0) return false;
    return true;
}

bool qihse_uuid_equal(const qihse_uuid_t* a, const qihse_uuid_t* b) {
    if (!a || !b) return false;
    return memcmp(a->bytes, b->bytes, QIHSE_UUID_BYTES) == 0;
}

/* ── Hybrid logical clock ───────────────────────────────────────────────── */

static uint64_t fed_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void qihse_hlc_init(qihse_hlc_t* clock) {
    if (!clock) return;
    clock->physical_ms = 0;
    clock->logical = 0;
}

void qihse_hlc_tick(qihse_hlc_t* clock, qihse_hlc_t* out) {
    if (!clock || !out) return;
    uint64_t now = fed_now_ms();
    if (now > clock->physical_ms) {
        clock->physical_ms = now;
        clock->logical = 0;
    } else {
        /* Clock did not advance (or went backwards): keep ordering with the
         * logical counter. */
        clock->logical++;
    }
    *out = *clock;
}

void qihse_hlc_observe(qihse_hlc_t* clock, const qihse_hlc_t* remote) {
    if (!clock || !remote) return;
    uint64_t now = fed_now_ms();
    uint64_t physical = clock->physical_ms;
    if (now > physical) physical = now;
    if (remote->physical_ms > physical) physical = remote->physical_ms;

    uint32_t logical = 0;
    if (physical == clock->physical_ms && physical == remote->physical_ms) {
        logical = (clock->logical > remote->logical ? clock->logical : remote->logical) + 1u;
    } else if (physical == clock->physical_ms) {
        logical = clock->logical + 1u;
    } else if (physical == remote->physical_ms) {
        logical = remote->logical + 1u;
    }
    clock->physical_ms = physical;
    clock->logical = logical;
}

int qihse_hlc_compare(const qihse_hlc_t* a, const qihse_hlc_t* b) {
    if (!a || !b) return 0;
    if (a->physical_ms < b->physical_ms) return -1;
    if (a->physical_ms > b->physical_ms) return 1;
    if (a->logical < b->logical) return -1;
    if (a->logical > b->logical) return 1;
    return 0;
}

uint64_t qihse_hlc_pack(const qihse_hlc_t* clock) {
    if (!clock) return 0;
    return (clock->physical_ms << 16) | (uint64_t)(clock->logical & 0xFFFFu);
}

void qihse_hlc_unpack(uint64_t packed, qihse_hlc_t* out) {
    if (!out) return;
    out->physical_ms = packed >> 16;
    out->logical = (uint32_t)(packed & 0xFFFFu);
}

/* ── Object generation ──────────────────────────────────────────────────── */

void qihse_object_version_init(qihse_object_version_t* version, const qihse_uuid_t* object) {
    if (!version) return;
    memset(version, 0, sizeof(*version));
    if (object) version->object = *object;
    version->generation = 1u;
}

void qihse_object_version_bump(qihse_object_version_t* version, qihse_hlc_t* clock) {
    if (!version || !clock) return;
    version->generation++;
    qihse_hlc_t stamp;
    qihse_hlc_tick(clock, &stamp);
    version->stamp = stamp;
}

int qihse_object_version_compare(const qihse_object_version_t* a,
                                 const qihse_object_version_t* b) {
    if (!a || !b) return 0;
    if (a->generation < b->generation) return -1;
    if (a->generation > b->generation) return 1;
    return qihse_hlc_compare(&a->stamp, &b->stamp);
}

/* ── Fencing epoch ──────────────────────────────────────────────────────── */

void qihse_fencing_token_init(qihse_fencing_token_t* token) {
    if (!token) return;
    memset(token, 0, sizeof(*token));
}

bool qihse_fencing_acquire(qihse_fencing_token_t* token, uint64_t observed_epoch,
                           const qihse_uuid_t* holder) {
    if (!token || !holder) return false;
    /* Fail closed: the caller must have observed the epoch it is replacing,
     * and the new epoch is always strictly higher. */
    if (observed_epoch != token->epoch) return false;
    token->epoch = observed_epoch + 1u;
    token->holder = *holder;
    return true;
}

bool qihse_fencing_valid(const qihse_fencing_token_t* token, uint64_t observed_epoch) {
    if (!token) return false;
    return token->epoch > observed_epoch;
}

/* ── F1: Consistency classes ────────────────────────────────────────────── */

const char* qihse_consistency_class_name(qihse_consistency_class_t c) {
    switch (c) {
        case QIHSE_CONSISTENCY_LOCAL:        return "LOCAL";
        case QIHSE_CONSISTENCY_EVENTUAL:     return "EVENTUAL";
        case QIHSE_CONSISTENCY_CAUSAL:       return "CAUSAL";
        case QIHSE_CONSISTENCY_QUORUM:       return "QUORUM";
        case QIHSE_CONSISTENCY_LINEARIZABLE: return "LINEARIZABLE";
    }
    return NULL;
}

bool qihse_consistency_class_parse(const char* name, qihse_consistency_class_t* out) {
    if (!name || !out) return false;
    if (strcmp(name, "LOCAL") == 0)        { *out = QIHSE_CONSISTENCY_LOCAL;        return true; }
    if (strcmp(name, "EVENTUAL") == 0)     { *out = QIHSE_CONSISTENCY_EVENTUAL;     return true; }
    if (strcmp(name, "CAUSAL") == 0)       { *out = QIHSE_CONSISTENCY_CAUSAL;       return true; }
    if (strcmp(name, "QUORUM") == 0)       { *out = QIHSE_CONSISTENCY_QUORUM;       return true; }
    if (strcmp(name, "LINEARIZABLE") == 0) { *out = QIHSE_CONSISTENCY_LINEARIZABLE; return true; }
    return false;
}

bool qihse_consistency_class_is_local_safe(qihse_consistency_class_t c) {
    /* LOCAL is always local-safe; EVENTUAL and CAUSAL tolerate disconnected
     * writes and reconcile later (plan §4.1–§4.3). */
    return c == QIHSE_CONSISTENCY_LOCAL ||
           c == QIHSE_CONSISTENCY_EVENTUAL ||
           c == QIHSE_CONSISTENCY_CAUSAL;
}

bool qihse_consistency_class_is_strong(qihse_consistency_class_t c) {
    return c == QIHSE_CONSISTENCY_QUORUM ||
           c == QIHSE_CONSISTENCY_LINEARIZABLE;
}

/* ── F1: Federation state ───────────────────────────────────────────────── */

const char* qihse_federation_state_name(qihse_federation_state_t s) {
    switch (s) {
        case QIHSE_FEDERATION_STATE_CONNECTED:  return "connected";
        case QIHSE_FEDERATION_STATE_DEGRADED:   return "degraded";
        case QIHSE_FEDERATION_STATE_ISOLATED:   return "isolated";
        case QIHSE_FEDERATION_STATE_RECOVERING: return "recovering";
        case QIHSE_FEDERATION_STATE_FENCED:     return "fenced";
        case QIHSE_FEDERATION_STATE_MAINTENANCE:return "maintenance";
    }
    return NULL;
}

bool qihse_federation_state_parse(const char* name, qihse_federation_state_t* out) {
    if (!name || !out) return false;
    if (strcmp(name, "connected") == 0)   { *out = QIHSE_FEDERATION_STATE_CONNECTED;   return true; }
    if (strcmp(name, "degraded") == 0)    { *out = QIHSE_FEDERATION_STATE_DEGRADED;    return true; }
    if (strcmp(name, "isolated") == 0)    { *out = QIHSE_FEDERATION_STATE_ISOLATED;    return true; }
    if (strcmp(name, "recovering") == 0)  { *out = QIHSE_FEDERATION_STATE_RECOVERING; return true; }
    if (strcmp(name, "fenced") == 0)      { *out = QIHSE_FEDERATION_STATE_FENCED;     return true; }
    if (strcmp(name, "maintenance") == 0)  { *out = QIHSE_FEDERATION_STATE_MAINTENANCE;return true; }
    return false;
}

const char* qihse_local_db_state_name(qihse_local_db_state_t s) {
    return s == QIHSE_LOCAL_DB_READ_WRITE ? "read-write" : "read-only";
}

/* ── F1: Namespace writability ──────────────────────────────────────────── */

bool qihse_federation_namespace_writable(const qihse_federation_namespace_t* ns,
                                         qihse_federation_state_t state,
                                         const qihse_uuid_t* local_node) {
    if (!ns) return false;
    (void)local_node; /* reserved for finer authority checks in F4 */
    /* Local-safe classes remain writable regardless of federation state
     * (acceptance criteria 1–2). */
    if (qihse_consistency_class_is_local_safe(ns->consistency)) return true;
    /* Strong namespaces require peer agreement. They fail closed unless the
     * node is connected (or degraded, which still has a quorum path). */
    if (qihse_consistency_class_is_strong(ns->consistency)) {
        return state == QIHSE_FEDERATION_STATE_CONNECTED ||
               state == QIHSE_FEDERATION_STATE_DEGRADED;
    }
    return false;
}

/* ── F1: Federation status ──────────────────────────────────────────────── */

void qihse_federation_status_init(qihse_federation_status_t* status,
                                 const qihse_uuid_t* node_id) {
    if (!status) return;
    memset(status, 0, sizeof(*status));
    if (node_id) status->node_id = *node_id;
    status->federation_state = QIHSE_FEDERATION_STATE_CONNECTED;
    status->local_database = QIHSE_LOCAL_DB_READ_WRITE;
    status->strong_namespaces_available = true;
    status->eventual_namespaces_available = true;
    qihse_hlc_init(&status->last_peer_contact_hlc);
}

void qihse_federation_status_recompute(qihse_federation_status_t* status) {
    if (!status) return;
    /* Local-safe namespaces keep the local database read-write even when the
     * node is isolated (acceptance criterion 2: quorum loss does not force
     * the whole node read-only). */
    status->local_database = QIHSE_LOCAL_DB_READ_WRITE;
    status->eventual_namespaces_available = true;
    /* Strong namespaces are only available when consensus is reachable. */
    bool consensus_reachable = (status->federation_state == QIHSE_FEDERATION_STATE_CONNECTED) ||
                              (status->federation_state == QIHSE_FEDERATION_STATE_DEGRADED);
    status->strong_namespaces_available = consensus_reachable;
    /* Maintenance deliberately takes the local DB read-only for planned
     * work; F1 does not automate this but the status reflects it. */
    if (status->federation_state == QIHSE_FEDERATION_STATE_MAINTENANCE) {
        status->local_database = QIHSE_LOCAL_DB_READ_ONLY;
        status->strong_namespaces_available = false;
    }
    /* Reconciliation is required after isolation or recovery. */
    status->reconciliation_required =
        status->federation_state == QIHSE_FEDERATION_STATE_ISOLATED ||
        status->federation_state == QIHSE_FEDERATION_STATE_RECOVERING ||
        status->federation_state == QIHSE_FEDERATION_STATE_FENCED;
}

void qihse_federation_status_format(const qihse_federation_status_t* status,
                                    char* out, size_t out_cap) {
    if (!status || !out || out_cap == 0) return;
    char node_str[QIHSE_UUID_STR_LEN + 1u];
    char hlc_str[64];
    qihse_uuid_format(&status->node_id, node_str);
    uint64_t packed = qihse_hlc_pack(&status->last_peer_contact_hlc);
    snprintf(hlc_str, sizeof(hlc_str), "%llu:%u",
             (unsigned long long)status->last_peer_contact_hlc.physical_ms,
             (unsigned)status->last_peer_contact_hlc.logical);
    snprintf(out, out_cap,
             "{\"node_id\":\"%s\",\"federation_state\":\"%s\","
             "\"local_database\":\"%s\",\"strong_namespaces_available\":%s,"
             "\"eventual_namespaces_available\":%s,"
             "\"pending_replication_events\":%llu,"
             "\"last_peer_contact_hlc\":\"%s\","
             "\"reconciliation_required\":%s}",
             node_str,
             qihse_federation_state_name(status->federation_state),
             qihse_local_db_state_name(status->local_database),
             status->strong_namespaces_available ? "true" : "false",
             status->eventual_namespaces_available ? "true" : "false",
             (unsigned long long)status->pending_replication_events,
             packed ? hlc_str : "none",
             status->reconciliation_required ? "true" : "false");
    (void)packed;
}

/* ── F1: Namespace registry (KV-backed under "fedns:") ──────────────────── */

static void ns_kv_key(const char* name, char* out, size_t cap) {
    snprintf(out, cap, QIHSE_FEDERATION_NS_PREFIX "%s", name);
}

/* Wire format: <consistency_int>\t<authority_uuid_str>\t<local_authority_0or1> */
static void ns_encode(const qihse_federation_namespace_t* ns, char* out, size_t cap) {
    char auth_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&ns->authority_node, auth_str);
    snprintf(out, cap, "%d\t%s\t%d", (int)ns->consistency, auth_str,
             ns->local_authority ? 1 : 0);
}

static bool ns_decode(const char* blob, qihse_federation_namespace_t* out) {
    if (!blob || !out) return false;
    int c = 0;
    char auth_str[QIHSE_UUID_STR_LEN + 1u];
    int la = 0;
    if (sscanf(blob, "%d\t%36[^\t]\t%d", &c, auth_str, &la) != 3) return false;
    if (c < 0 || c > (int)QIHSE_CONSISTENCY_LINEARIZABLE) return false;
    if (!qihse_uuid_parse(auth_str, &out->authority_node)) return false;
    out->consistency = (qihse_consistency_class_t)c;
    out->local_authority = la != 0;
    return true;
}

bool qihse_federation_namespace_register(void* store_void, void* user_void,
                                         const char* name,
                                         qihse_consistency_class_t consistency,
                                         const qihse_uuid_t* authority_node,
                                         const qihse_uuid_t* local_node) {
    if (!store_void || !user_void || !name || !authority_node || !local_node) return false;
    size_t nl = strlen(name);
    if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return false;
    if (qihse_consistency_class_name(consistency) == NULL) return false;
    qihse_federation_namespace_t ns;
    memset(&ns, 0, sizeof(ns));
    snprintf(ns.name, sizeof(ns.name), "%s", name);
    ns.consistency = consistency;
    ns.authority_node = *authority_node;
    ns.local_authority = (consistency == QIHSE_CONSISTENCY_LOCAL) ||
                        qihse_uuid_equal(authority_node, local_node);
    char key[128];
    ns_kv_key(name, key, sizeof(key));
    char blob[128];
    ns_encode(&ns, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_namespace_lookup(void* store_void, void* user_void,
                                        const char* name,
                                        qihse_federation_namespace_t* out) {
    if (!store_void || !user_void || !name || !out) return false;
    char key[128];
    ns_kv_key(name, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                  (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = ns_decode(blob, out);
    snprintf(out->name, sizeof(out->name), "%s", name);
    free(blob);
    return ok;
}

bool qihse_federation_namespace_unregister(void* store_void, void* user_void,
                                            const char* name) {
    if (!store_void || !user_void || !name) return false;
    char key[128];
    ns_kv_key(name, key, sizeof(key));
    return qihse_kv_del_user((qihse_kv_store_t*)store_void, key,
                             (qihse_user_t*)user_void);
}

typedef struct {
    qihse_federation_ns_iter_cb cb;
    void* user_data;
} ns_iter_ctx_t;

static bool ns_iter_cb(const char* key, const char* value, void* user_data) {
    ns_iter_ctx_t* ctx = (ns_iter_ctx_t*)user_data;
    size_t plen = strlen(QIHSE_FEDERATION_NS_PREFIX);
    if (strncmp(key, QIHSE_FEDERATION_NS_PREFIX, plen) != 0) return true;
    const char* name = key + plen;
    qihse_federation_namespace_t ns;
    if (!ns_decode(value, &ns)) return true;
    snprintf(ns.name, sizeof(ns.name), "%s", name);
    return ctx->cb(&ns, ctx->user_data);
}

void qihse_federation_namespace_foreach(void* store_void, void* user_void,
                                        qihse_federation_ns_iter_cb cb,
                                        void* user_data) {
    if (!store_void || !cb) return;
    ns_iter_ctx_t ctx = { cb, user_data };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          ns_iter_cb, &ctx);
}

/* ── F2: Idempotency ledger ──────────────────────────────────────────────── */

static void req_kv_key(const qihse_uuid_t* request_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(request_id, id_str);
    snprintf(out, cap, QIHSE_FEDERATION_REQ_PREFIX "%s", id_str);
}

/* Wire format: <result_code>\t<completed_generation>\t<result_digest> */
static void req_encode(const qihse_federation_request_result_t* r, char* out, size_t cap) {
    snprintf(out, cap, "%u\t%llu\t%s", (unsigned)r->result_code,
             (unsigned long long)r->completed_generation, r->result_digest);
}

static bool req_decode(const char* blob, qihse_federation_request_result_t* out) {
    if (!blob || !out) return false;
    unsigned rc = 0;
    unsigned long long gen = 0;
    char digest[64];
    digest[0] = '\0';
    if (sscanf(blob, "%u\t%llu\t%63[^\n]", &rc, &gen, digest) < 2) return false;
    out->result_code = rc;
    out->completed_generation = (uint64_t)gen;
    snprintf(out->result_digest, sizeof(out->result_digest), "%s", digest);
    return true;
}

bool qihse_federation_request_record(void* store_void, void* user_void,
                                     const qihse_federation_request_result_t* result) {
    if (!store_void || !user_void || !result) return false;
    char key[128];
    req_kv_key(&result->request_id, key, sizeof(key));
    /* Check for existing — idempotency: a replay must not overwrite. */
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) { free(existing); return false; }
    char blob[256];
    req_encode(result, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_request_lookup(void* store_void, void* user_void,
                                     const qihse_uuid_t* request_id,
                                     qihse_federation_request_result_t* out) {
    if (!store_void || !user_void || !request_id || !out) return false;
    char key[128];
    req_kv_key(request_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                  (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = req_decode(blob, out);
    out->request_id = *request_id;
    free(blob);
    return ok;
}

bool qihse_federation_request_seen(void* store_void, void* user_void,
                                   const qihse_uuid_t* request_id) {
    if (!store_void || !user_void || !request_id) return false;
    char key[128];
    req_kv_key(request_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                  (qihse_user_t*)user_void);
    if (!blob) return false;
    free(blob);
    return true;
}

/* ── F2: Event journal ──────────────────────────────────────────────────── */

struct qihse_federation_journal {
    qihse_event_stream_t* stream;
    qihse_hlc_t clock;
    uint8_t previous_hash[48];
    bool has_previous;
};

qihse_federation_journal_t* qihse_federation_journal_open(const char* log_directory,
                                                         qihse_es_durability_t durability) {
    if (!log_directory) return NULL;
    qihse_federation_journal_t* j = (qihse_federation_journal_t*)calloc(1, sizeof(*j));
    if (!j) return NULL;
    j->stream = qihse_event_stream_open(log_directory, durability, false);
    if (!j->stream) {
        free(j);
        return NULL;
    }
    qihse_hlc_init(&j->clock);
    memset(j->previous_hash, 0, sizeof(j->previous_hash));
    j->has_previous = false;
    /* Replay to recover the last hash so the chain continues across restarts. */
    qihse_es_record_header_t hdr;
    uint8_t* payload = NULL;
    size_t plen = 0;
    uint64_t cursor = 0;
    while (qihse_event_stream_iterate(j->stream, QIHSE_FEDERATION_JOURNAL_TOPIC,
                                      &cursor, &hdr, &payload, &plen)) {
        /* The event_id field in the record header is the hash of the record.
         * We use it as the chain tip. */
        memcpy(j->previous_hash, hdr.event_id, 48);
        j->has_previous = true;
        free(payload);
        payload = NULL;
    }
    return j;
}

void qihse_federation_journal_destroy(qihse_federation_journal_t* journal) {
    if (!journal) return;
    if (journal->stream) qihse_event_stream_destroy(journal->stream);
    free(journal);
}

/* Serialize a mutation envelope + event metadata into a payload for the
 * event stream. Format (all little-endian, fixed-width):
 *   [event_type 64B][resource_id 64B]
 *   [mutation: request_id 16 + origin 16 + principal 16 + hlc 12 +
 *              expected_gen 8 + fencing_epoch 8 + consistency 4 + flags 4]
 *   [previous_hash 48B]
 *   [user_payload...]                                            */
static void journal_serialize(const qihse_federation_event_t* ev,
                              const uint8_t* user_payload, size_t user_len,
                              uint8_t* out, size_t out_cap) {
    size_t off = 0;
    memset(out, 0, out_cap);
    memcpy(out + off, ev->event_type, 64); off += 64;
    memcpy(out + off, ev->resource_id, 64); off += 64;
    /* mutation */
    memcpy(out + off, &ev->mutation.request_id, 16); off += 16;
    memcpy(out + off, &ev->mutation.origin_node, 16); off += 16;
    memcpy(out + off, &ev->mutation.principal_id, 16); off += 16;
    memcpy(out + off, &ev->mutation.hlc, sizeof(qihse_hlc_t)); off += sizeof(qihse_hlc_t);
    memcpy(out + off, &ev->mutation.expected_generation, 8); off += 8;
    memcpy(out + off, &ev->mutation.fencing_epoch, 8); off += 8;
    uint32_t cc = (uint32_t)ev->mutation.consistency;
    memcpy(out + off, &cc, 4); off += 4;
    memcpy(out + off, &ev->mutation.flags, 4); off += 4;
    /* hash chain */
    memcpy(out + off, ev->previous_hash, 48); off += 48;
    if (user_payload && user_len) {
        memcpy(out + off, user_payload, user_len); off += user_len;
    }
}

static void journal_deserialize(const uint8_t* blob, size_t blen,
                                qihse_federation_event_t* ev,
                                const uint8_t** out_user_payload,
                                size_t* out_user_len) {
    size_t off = 0;
    memset(ev, 0, sizeof(*ev));
    memcpy(ev->event_type, blob + off, 64); ev->event_type[64] = '\0'; off += 64;
    memcpy(ev->resource_id, blob + off, 64); ev->resource_id[64] = '\0'; off += 64;
    memcpy(&ev->mutation.request_id, blob + off, 16); off += 16;
    memcpy(&ev->mutation.origin_node, blob + off, 16); off += 16;
    memcpy(&ev->mutation.principal_id, blob + off, 16); off += 16;
    memcpy(&ev->mutation.hlc, blob + off, sizeof(qihse_hlc_t)); off += sizeof(qihse_hlc_t);
    memcpy(&ev->mutation.expected_generation, blob + off, 8); off += 8;
    memcpy(&ev->mutation.fencing_epoch, blob + off, 8); off += 8;
    uint32_t cc = 0;
    memcpy(&cc, blob + off, 4); off += 4;
    ev->mutation.consistency = (qihse_consistency_class_t)cc;
    memcpy(&ev->mutation.flags, blob + off, 4); off += 4;
    memcpy(ev->previous_hash, blob + off, 48); off += 48;
    if (out_user_payload && out_user_len) {
        *out_user_len = blen > off ? blen - off : 0;
        *out_user_payload = *out_user_len > 0 ? blob + off : NULL;
    }
}

/* Compute SHA-384 of (previous_hash || serialized_envelope || user_payload).
 * The event stream already computes its own event_id as SHA-384(topic||payload),
 * but we also embed an explicit hash chain in the payload for tamper-evidence
 * that survives topic changes. */
static void journal_hash(const uint8_t* previous_hash, const uint8_t* serialized,
                         size_t slen, const uint8_t* user_payload, size_t user_len,
                         uint8_t out[48]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out, 0, 48); return; }
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    EVP_DigestUpdate(ctx, previous_hash, 48);
    EVP_DigestUpdate(ctx, serialized, slen);
    if (user_payload && user_len) EVP_DigestUpdate(ctx, user_payload, user_len);
    unsigned int hlen = 48;
    EVP_DigestFinal_ex(ctx, out, &hlen);
    EVP_MD_CTX_free(ctx);
}

uint64_t qihse_federation_journal_append(qihse_federation_journal_t* journal,
                                        const qihse_federation_mutation_t* mutation,
                                        const char* event_type,
                                        const char* resource_id,
                                        const uint8_t* payload, size_t payload_len,
                                        qihse_federation_event_t* out_event) {
    if (!journal || !mutation || !event_type) return 0;
    qihse_federation_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.mutation = *mutation;
    snprintf(ev.event_type, sizeof(ev.event_type), "%s", event_type);
    if (resource_id) snprintf(ev.resource_id, sizeof(ev.resource_id), "%s", resource_id);
    /* Tick the HLC if the caller didn't supply one. */
    if (ev.mutation.hlc.physical_ms == 0 && ev.mutation.hlc.logical == 0) {
        qihse_hlc_tick(&journal->clock, &ev.mutation.hlc);
    } else {
        qihse_hlc_observe(&journal->clock, &ev.mutation.hlc);
    }
    /* Generate an event_id if nil. */
    if (qihse_uuid_is_nil(&ev.mutation.request_id)) {
        qihse_uuid_generate(&ev.mutation.request_id);
    }
    ev.event_id = ev.mutation.request_id; /* event_id == request_id for dedupe */
    /* Hash chain. */
    if (journal->has_previous) {
        memcpy(ev.previous_hash, journal->previous_hash, 48);
    } else {
        memset(ev.previous_hash, 0, 48);
    }
    /* Serialize. */
    size_t header_len = 64 + 64 + 16 + 16 + 16 + sizeof(qihse_hlc_t) + 8 + 8 + 4 + 4 + 48;
    size_t total = header_len + payload_len;
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) return 0;
    journal_serialize(&ev, payload, payload_len, buf, total);
    /* Compute the embedded hash. */
    journal_hash(ev.previous_hash, buf, header_len, payload, payload_len, ev.hash);
    /* Re-serialize with the hash filled in (hash goes after previous_hash). */
    /* Actually the hash is not stored in the payload — it's recomputed on
     * replay. We store previous_hash in the payload; the record header's
     * event_id (SHA-384 of topic||payload) serves as the chain link. */
    /* Append to the event stream. */
    uint64_t offset = qihse_event_stream_append_record(journal->stream,
                                                       QIHSE_FEDERATION_JOURNAL_TOPIC,
                                                       1u, /* schema version */
                                                       ev.hash, /* use our hash as event_id */
                                                       buf, total);
    free(buf);
    if (offset == 0) return 0;
    ev.journal_offset = offset;
    /* Update the chain tip. */
    memcpy(journal->previous_hash, ev.hash, 48);
    journal->has_previous = true;
    if (out_event) *out_event = ev;
    return offset;
}

uint64_t qihse_federation_journal_replay(qihse_federation_journal_t* journal,
                                        uint64_t from_cursor,
                                        qihse_federation_journal_cb cb,
                                        void* user_data) {
    if (!journal || !cb) return 0;
    qihse_es_record_header_t hdr;
    uint8_t* payload = NULL;
    size_t plen = 0;
    uint64_t cursor = from_cursor;
    uint64_t count = 0;
    while (qihse_event_stream_iterate(journal->stream, QIHSE_FEDERATION_JOURNAL_TOPIC,
                                      &cursor, &hdr, &payload, &plen)) {
        qihse_federation_event_t ev;
        const uint8_t* user_payload = NULL;
        size_t user_len = 0;
        journal_deserialize(payload, plen, &ev, &user_payload, &user_len);
        ev.journal_offset = hdr.stream_offset;
        memcpy(ev.hash, hdr.event_id, 48);
        bool cont = cb(&ev, user_payload, user_len, user_data);
        free(payload);
        payload = NULL;
        count++;
        if (!cont) break;
    }
    return count;
}

uint64_t qihse_federation_journal_replay_window(qihse_federation_journal_t* journal,
                                               uint64_t from_cursor,
                                               uint64_t max_events,
                                               qihse_federation_journal_cb cb,
                                               void* user_data,
                                               uint64_t* out_cursor) {
    if (!journal || !cb) return 0;
    if (out_cursor) *out_cursor = from_cursor;

    qihse_es_record_header_t hdr;
    uint8_t* payload = NULL;
    size_t plen = 0;
    uint64_t cursor = from_cursor;
    uint64_t count = 0;
    /* Remember the offset of the last record DELIVERED, so the resume point
     * never runs past a record the callback refused. */
    uint64_t last_delivered_end = from_cursor;
    uint64_t last_delivered_start = from_cursor;
    bool delivered_any = false;

    while (count < max_events &&
           qihse_event_stream_iterate(journal->stream, QIHSE_FEDERATION_JOURNAL_TOPIC,
                                      &cursor, &hdr, &payload, &plen)) {
        qihse_federation_event_t ev;
        const uint8_t* user_payload = NULL;
        size_t user_len = 0;
        journal_deserialize(payload, plen, &ev, &user_payload, &user_len);
        ev.journal_offset = hdr.stream_offset;
        memcpy(ev.hash, hdr.event_id, 48);
        last_delivered_start = hdr.stream_offset;
        last_delivered_end = cursor;
        bool cont = cb(&ev, user_payload, user_len, user_data);
        free(payload);
        payload = NULL;
        count++;
        delivered_any = true;
        if (!cont) break;
    }

    if (out_cursor) {
        /* The resume point is the offset after the last record the callback
         * ACCEPTED, not the iterator's position: a callback that stopped early
         * must not have its remaining records skipped. */
        *out_cursor = delivered_any ? last_delivered_end : from_cursor;
        (void)last_delivered_start;
    }
    return count;
}

uint64_t qihse_federation_journal_length(qihse_federation_journal_t* journal) {
    if (!journal || !journal->stream) return 0;
    return qihse_event_stream_length(journal->stream, QIHSE_FEDERATION_JOURNAL_TOPIC);
}

/* ── F2: Resumable watches ──────────────────────────────────────────────── */

struct qihse_federation_watch {
    qihse_federation_journal_t* journal;
    char prefix[64];
    uint64_t cursor;
    uint64_t last_ack;
    size_t backlog_limit;
};

qihse_federation_watch_t* qihse_federation_watch_open(qihse_federation_journal_t* journal,
                                                     const qihse_federation_watch_config_t* config) {
    if (!journal) return NULL;
    qihse_federation_watch_t* w = (qihse_federation_watch_t*)calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->journal = journal;
    if (config) {
        snprintf(w->prefix, sizeof(w->prefix), "%s", config->prefix);
        w->cursor = config->cursor;
        w->last_ack = config->last_ack;
        w->backlog_limit = config->backlog_limit ? config->backlog_limit : 1024;
    } else {
        w->backlog_limit = 1024;
    }
    return w;
}

void qihse_federation_watch_destroy(qihse_federation_watch_t* watch) {
    free(watch);
}

bool qihse_federation_watch_next(qihse_federation_watch_t* watch,
                                qihse_federation_event_t* out_event,
                                uint8_t** out_payload, size_t* out_payload_len) {
    if (!watch || !out_event) return false;
    qihse_es_record_header_t hdr;
    uint8_t* payload = NULL;
    size_t plen = 0;
    while (qihse_event_stream_iterate(watch->journal->stream,
                                      QIHSE_FEDERATION_JOURNAL_TOPIC,
                                      &watch->cursor, &hdr, &payload, &plen)) {
        qihse_federation_event_t ev;
        const uint8_t* user_payload = NULL;
        size_t user_len = 0;
        journal_deserialize(payload, plen, &ev, &user_payload, &user_len);
        ev.journal_offset = hdr.stream_offset;
        memcpy(ev.hash, hdr.event_id, 48);
        /* Prefix filter on resource_id. */
        if (watch->prefix[0] != '\0' &&
            strncmp(ev.resource_id, watch->prefix, strlen(watch->prefix)) != 0) {
            free(payload);
            payload = NULL;
            continue;
        }
        *out_event = ev;
        if (out_payload && out_payload_len) {
            if (user_payload && user_len > 0) {
                *out_payload = (uint8_t*)malloc(user_len);
                if (*out_payload) {
                    memcpy(*out_payload, user_payload, user_len);
                    *out_payload_len = user_len;
                } else {
                    *out_payload_len = 0;
                }
            } else {
                *out_payload = NULL;
                *out_payload_len = 0;
            }
        }
        free(payload);
        return true;
    }
    return false;
}

bool qihse_federation_watch_ack(qihse_federation_watch_t* watch, uint64_t offset) {
    if (!watch) return false;
    if (offset > watch->last_ack) watch->last_ack = offset;
    return true;
}

bool qihse_federation_watch_resume(qihse_federation_watch_t* watch, uint64_t cursor) {
    if (!watch) return false;
    watch->cursor = cursor;
    return true;
}

uint64_t qihse_federation_watch_cursor(const qihse_federation_watch_t* watch) {
    return watch ? watch->cursor : 0;
}

uint64_t qihse_federation_watch_last_ack(const qihse_federation_watch_t* watch) {
    return watch ? watch->last_ack : 0;
}

size_t qihse_federation_watch_backlog(const qihse_federation_watch_t* watch) {
    if (!watch) return 0;
    /* Backlog = events delivered but not yet acked. */
    if (watch->cursor <= watch->last_ack) return 0;
    /* This is approximate since cursor is a byte offset, not an event count. */
    return 0; /* precise backlog tracking requires per-event ack bookkeeping */
}

/* ── F3: Conflict policies ─────────────────────────────────────────────── */

const char* qihse_conflict_policy_name(qihse_conflict_policy_t policy) {
    switch (policy) {
        case QIHSE_CONFLICT_LWW_HLC:    return "lww_hlc";
        case QIHSE_CONFLICT_MERGE_SET:  return "merge_set";
        case QIHSE_CONFLICT_COUNTER:    return "counter";
        case QIHSE_CONFLICT_APPEND_ONLY: return "append_only";
        case QIHSE_CONFLICT_MANUAL:     return "manual";
        case QIHSE_CONFLICT_REJECT:     return "reject";
        case QIHSE_CONFLICT_CUSTOM:     return "custom";
    }
    return "unknown";
}

bool qihse_conflict_policy_parse(const char* name, qihse_conflict_policy_t* out) {
    if (!name || !out) return false;
    if (strcmp(name, "lww_hlc") == 0)     { *out = QIHSE_CONFLICT_LWW_HLC; return true; }
    if (strcmp(name, "merge_set") == 0)   { *out = QIHSE_CONFLICT_MERGE_SET; return true; }
    if (strcmp(name, "counter") == 0)    { *out = QIHSE_CONFLICT_COUNTER; return true; }
    if (strcmp(name, "append_only") == 0){ *out = QIHSE_CONFLICT_APPEND_ONLY; return true; }
    if (strcmp(name, "manual") == 0)     { *out = QIHSE_CONFLICT_MANUAL; return true; }
    if (strcmp(name, "reject") == 0)     { *out = QIHSE_CONFLICT_REJECT; return true; }
    if (strcmp(name, "custom") == 0)     { *out = QIHSE_CONFLICT_CUSTOM; return true; }
    return false;
}

/* ── F3: Conflict store ────────────────────────────────────────────────── */

static void conflict_kv_key(const qihse_uuid_t* conflict_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(conflict_id, id_str);
    snprintf(out, cap, QIHSE_FEDERATION_CONFLICT_PREFIX "%s", id_str);
}

/* Wire format (tab-separated, fixed sections):
 *   policy_int \t namespace \t resource_id \t resolved_0or1 \t
 *   local_mutation(request_id 16B hex \t origin 16B hex \t principal 16B hex \t
 *                   hlc_phys \t hlc_logical \t expected_gen \t fencing_epoch \t
 *                   consistency \t flags) \t
 *   remote_mutation(...) \t
 *   local_value_len \t local_value_hex \t
 *   remote_value_len \t remote_value_hex \t
 *   reason \t resolved_by_16B_hex \t resolved_at_hlc_physical
 * We use a binary-safe encoding: values are hex-encoded. */
/* Split a tab-separated record, preserving empty fields.  sscanf's "%[^\t]"
 * cannot match an empty field, and supply-chain and identity records have
 * optional columns. */
static const char* fed_next_field(const char* p, char* out, size_t cap) {
    if (!p) { if (cap) out[0] = '\0'; return NULL; }
    const char* start = p;
    while (*p && *p != '\t') p++;
    size_t len = (size_t)(p - start);
    if (len >= cap) len = cap - 1u;
    if (cap) { memcpy(out, start, len); out[len] = '\0'; }
    return (*p == '\t') ? p + 1 : NULL;
}

static void uuid_hex(const qihse_uuid_t* u, char* out) {
    const uint8_t* b = (const uint8_t*)u;
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", b[i]);
    out[32] = '\0';
}

static bool uuid_from_hex(const char* hex, qihse_uuid_t* out) {
    if (!hex || strlen(hex) != 32) return false;
    uint8_t* b = (uint8_t*)out;
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        b[i] = (uint8_t)byte;
    }
    return true;
}

static void value_hex(const uint8_t* val, size_t len, char* out, size_t cap) {
    if (!val || len == 0) { out[0] = '\0'; return; }
    size_t i;
    for (i = 0; i < len && i * 2 + 1 < cap - 1; i++)
        snprintf(out + i * 2, 3, "%02x", val[i]);
    out[i * 2] = '\0';
}

static bool value_from_hex(const char* hex, uint8_t* out, size_t cap, size_t* out_len) {
    size_t hlen = hex ? strlen(hex) : 0;
    if (hlen % 2 != 0) return false;
    size_t n = hlen / 2;
    if (n > cap) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        out[i] = (uint8_t)byte;
    }
    *out_len = n;
    return true;
}

static void mutation_to_str(const qihse_federation_mutation_t* m, char* out, size_t cap) {
    char rid[33], oid[33], pid[33];
    uuid_hex(&m->request_id, rid);
    uuid_hex(&m->origin_node, oid);
    uuid_hex(&m->principal_id, pid);
    /* Use pipe-separated fields inside the mutation so the outer tab-separated
     * conflict encoding can parse the mutation as a single token. */
    snprintf(out, cap, "%s|%s|%s|%llu|%u|%llu|%llu|%u|%u",
             rid, oid, pid,
             (unsigned long long)m->hlc.physical_ms, (unsigned)m->hlc.logical,
             (unsigned long long)m->expected_generation,
             (unsigned long long)m->fencing_epoch,
             (unsigned)m->consistency, (unsigned)m->flags);
}

static bool mutation_from_str(const char* str, qihse_federation_mutation_t* m) {
    char rid[33], oid[33], pid[33];
    unsigned long long hlc_phys = 0, exp_gen = 0, fence_epoch = 0;
    unsigned hlc_log = 0, cons = 0, flags = 0;
    int n = sscanf(str, "%32[^|]|%32[^|]|%32[^|]|%llu|%u|%llu|%llu|%u|%u",
                   rid, oid, pid, &hlc_phys, &hlc_log, &exp_gen, &fence_epoch, &cons, &flags);
    if (n < 9) return false;
    memset(m, 0, sizeof(*m));
    uuid_from_hex(rid, &m->request_id);
    uuid_from_hex(oid, &m->origin_node);
    uuid_from_hex(pid, &m->principal_id);
    m->hlc.physical_ms = (uint64_t)hlc_phys;
    m->hlc.logical = (uint16_t)hlc_log;
    m->expected_generation = (uint64_t)exp_gen;
    m->fencing_epoch = (uint64_t)fence_epoch;
    m->consistency = (qihse_consistency_class_t)cons;
    m->flags = (uint32_t)flags;
    return true;
}

static void conflict_encode(const qihse_federation_conflict_t* c, char* out, size_t cap) {
    char local_m[512], remote_m[512];
    mutation_to_str(&c->local_mutation, local_m, sizeof(local_m));
    mutation_to_str(&c->remote_mutation, remote_m, sizeof(remote_m));
    char local_val[512], remote_val[512];
    value_hex(c->local_value, c->local_value_len, local_val, sizeof(local_val));
    value_hex(c->remote_value, c->remote_value_len, remote_val, sizeof(remote_val));
    char resolved_by[33];
    uuid_hex(&c->resolved_by, resolved_by);
    snprintf(out, cap, "%u\t%s\t%s\t%d\t%s\t%s\t%llu\t%s\t%llu\t%s\t%s\t%s\t%llu",
             (unsigned)c->policy, c->namespace_name, c->resource_id,
             c->resolved ? 1 : 0,
             local_m, remote_m,
             (unsigned long long)c->local_value_len, local_val,
             (unsigned long long)c->remote_value_len, remote_val,
             c->reason, resolved_by,
             (unsigned long long)c->resolved_at_hlc_physical);
}

static bool conflict_decode(const char* blob, qihse_federation_conflict_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    unsigned policy_u = 0, resolved_u = 0;
    unsigned long long local_len = 0, remote_len = 0, resolved_at = 0;
    char ns[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    char resource[64];
    char local_m[512], remote_m[512];
    char local_val_hex[512], remote_val_hex[512];
    char reason[128];
    char resolved_by_hex[33];
    /* Use %63[^\t] which requires at least one char; for empty fields we
     * need to handle them specially. We parse field by field manually. */
    const char* p = blob;
    /* policy */
    policy_u = (unsigned)strtoul(p, (char**)&p, 10);
    if (*p != '\t') return false;
    p++;
    /* namespace */
    const char* start = p;
    while (*p && *p != '\t') p++;
    size_t nlen = (size_t)(p - start);
    if (nlen >= sizeof(ns)) return false;
    memcpy(ns, start, nlen); ns[nlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* resource_id */
    start = p;
    while (*p && *p != '\t') p++;
    size_t rlen = (size_t)(p - start);
    if (rlen >= sizeof(resource)) return false;
    memcpy(resource, start, rlen); resource[rlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* resolved */
    resolved_u = (unsigned)strtoul(p, (char**)&p, 10);
    if (*p != '\t') return false;
    p++;
    /* local_mutation */
    start = p;
    while (*p && *p != '\t') p++;
    size_t lmlen = (size_t)(p - start);
    if (lmlen >= sizeof(local_m)) return false;
    memcpy(local_m, start, lmlen); local_m[lmlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* remote_mutation */
    start = p;
    while (*p && *p != '\t') p++;
    size_t rmlen = (size_t)(p - start);
    if (rmlen >= sizeof(remote_m)) return false;
    memcpy(remote_m, start, rmlen); remote_m[rmlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* local_value_len */
    local_len = strtoull(p, (char**)&p, 10);
    if (*p != '\t') return false;
    p++;
    /* local_value_hex */
    start = p;
    while (*p && *p != '\t') p++;
    size_t lvlen = (size_t)(p - start);
    if (lvlen >= sizeof(local_val_hex)) return false;
    memcpy(local_val_hex, start, lvlen); local_val_hex[lvlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* remote_value_len */
    remote_len = strtoull(p, (char**)&p, 10);
    if (*p != '\t') return false;
    p++;
    /* remote_value_hex */
    start = p;
    while (*p && *p != '\t') p++;
    size_t rvlen = (size_t)(p - start);
    if (rvlen >= sizeof(remote_val_hex)) return false;
    memcpy(remote_val_hex, start, rvlen); remote_val_hex[rvlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* reason */
    start = p;
    while (*p && *p != '\t') p++;
    size_t rsnlen = (size_t)(p - start);
    if (rsnlen >= sizeof(reason)) return false;
    memcpy(reason, start, rsnlen); reason[rsnlen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* resolved_by_hex */
    start = p;
    while (*p && *p != '\t') p++;
    size_t rblen = (size_t)(p - start);
    if (rblen >= sizeof(resolved_by_hex)) return false;
    memcpy(resolved_by_hex, start, rblen); resolved_by_hex[rblen] = '\0';
    if (*p != '\t') return false;
    p++;
    /* resolved_at_hlc_physical */
    resolved_at = strtoull(p, (char**)&p, 10);

    if (policy_u > (unsigned)QIHSE_CONFLICT_CUSTOM) return false;
    out->policy = (qihse_conflict_policy_t)policy_u;
    snprintf(out->namespace_name, sizeof(out->namespace_name), "%s", ns);
    snprintf(out->resource_id, sizeof(out->resource_id), "%s", resource);
    out->resolved = resolved_u != 0;
    mutation_from_str(local_m, &out->local_mutation);
    mutation_from_str(remote_m, &out->remote_mutation);
    out->local_value_len = (size_t)local_len;
    out->remote_value_len = (size_t)remote_len;
    if (out->local_value_len <= sizeof(out->local_value))
        value_from_hex(local_val_hex, out->local_value, sizeof(out->local_value), &out->local_value_len);
    if (out->remote_value_len <= sizeof(out->remote_value))
        value_from_hex(remote_val_hex, out->remote_value, sizeof(out->remote_value), &out->remote_value_len);
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
    uuid_from_hex(resolved_by_hex, &out->resolved_by);
    out->resolved_at_hlc_physical = (uint64_t)resolved_at;
    return true;
}

bool qihse_federation_conflict_record(void* store_void, void* user_void,
                                     const qihse_federation_conflict_t* conflict) {
    if (!store_void || !user_void || !conflict) return false;
    char key[128];
    conflict_kv_key(&conflict->conflict_id, key, sizeof(key));
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) { free(existing); return false; }
    char blob[4096];
    conflict_encode(conflict, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_conflict_lookup(void* store_void, void* user_void,
                                      const qihse_uuid_t* conflict_id,
                                      qihse_federation_conflict_t* out) {
    if (!store_void || !user_void || !conflict_id || !out) return false;
    char key[128];
    conflict_kv_key(conflict_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                  (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = conflict_decode(blob, out);
    out->conflict_id = *conflict_id;
    free(blob);
    return ok;
}

bool qihse_federation_conflict_resolve(void* store_void, void* user_void,
                                       const qihse_uuid_t* conflict_id,
                                       const qihse_uuid_t* resolver) {
    if (!store_void || !user_void || !conflict_id || !resolver) return false;
    qihse_federation_conflict_t c;
    if (!qihse_federation_conflict_lookup(store_void, user_void, conflict_id, &c)) return false;
    if (c.resolved) return false;
    c.resolved = true;
    c.resolved_by = *resolver;
    c.resolved_at_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
    char key[128];
    conflict_kv_key(conflict_id, key, sizeof(key));
    char blob[4096];
    conflict_encode(&c, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

typedef struct {
    qihse_federation_conflict_cb cb;
    void* user_data;
} conflict_iter_ctx_t;

static bool conflict_iter_cb(const char* key, const char* value, void* user_data) {
    conflict_iter_ctx_t* ctx = (conflict_iter_ctx_t*)user_data;
    if (strncmp(key, QIHSE_FEDERATION_CONFLICT_PREFIX,
                strlen(QIHSE_FEDERATION_CONFLICT_PREFIX)) != 0) return true;
    qihse_federation_conflict_t c;
    if (!conflict_decode(value, &c)) return true;
    /* Parse the conflict_id from the key. */
    const char* uuid_str = key + strlen(QIHSE_FEDERATION_CONFLICT_PREFIX);
    qihse_uuid_t cid;
    if (qihse_uuid_parse(uuid_str, &cid)) c.conflict_id = cid;
    if (c.resolved) return true; /* skip resolved */
    return ctx->cb(&c, ctx->user_data);
}

void qihse_federation_conflict_foreach(void* store_void, void* user_void,
                                       qihse_federation_conflict_cb cb,
                                       void* user_data) {
    if (!store_void || !cb) return;
    conflict_iter_ctx_t ctx = { cb, user_data };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          conflict_iter_cb, &ctx);
}

/* ── F3: Namespace manifest ─────────────────────────────────────────────── */

typedef struct {
    qihse_federation_manifest_t* manifest;
    char ns_prefix[128];
    size_t ns_prefix_len;
    qihse_federation_manifest_entry_t* current_entry;
    char current_range_start[64];
    uint64_t current_count;
    EVP_MD_CTX* digest_ctx;
} manifest_build_ctx_t;

static bool manifest_flush_range(manifest_build_ctx_t* ctx) {
    if (ctx->current_count == 0) return true;
    if (ctx->manifest->entry_count >= QIHSE_FEDERATION_MANIFEST_MAX_RANGES) return false;
    qihse_federation_manifest_entry_t* e = &ctx->manifest->entries[ctx->manifest->entry_count++];
    snprintf(e->range_start, sizeof(e->range_start), "%s", ctx->current_range_start);
    e->range_end[0] = '\0'; /* we use a single range for simplicity in F3 */
    e->object_count = ctx->current_count;
    unsigned int hlen = 48;
    EVP_DigestFinal_ex(ctx->digest_ctx, e->digest, &hlen);
    EVP_MD_CTX_free(ctx->digest_ctx);
    ctx->digest_ctx = NULL;
    ctx->current_count = 0;
    return true;
}

static bool manifest_kv_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    manifest_build_ctx_t* ctx = (manifest_build_ctx_t*)user_data;
    /* Only keys that start with the namespace prefix. */
    if (strncmp(key, ctx->ns_prefix, ctx->ns_prefix_len) != 0) return true;
    const char* obj_id = key + ctx->ns_prefix_len;
    if (ctx->current_count == 0) {
        /* Start a new range. */
        snprintf(ctx->current_range_start, sizeof(ctx->current_range_start), "%s", obj_id);
        ctx->digest_ctx = EVP_MD_CTX_new();
        if (!ctx->digest_ctx) return false;
        EVP_DigestInit_ex(ctx->digest_ctx, EVP_sha384(), NULL);
    }
    /* Hash the object id into the digest. We don't have generation/HLC
     * metadata in the KV value for F3's simple model, so we hash the
     * id and value together. */
    EVP_DigestUpdate(ctx->digest_ctx, key, strlen(key));
    if (value) EVP_DigestUpdate(ctx->digest_ctx, value, strlen(value));
    ctx->current_count++;
    ctx->manifest->total_objects++;
    return true;
}

bool qihse_federation_manifest_build(void* store_void, void* user_void,
                                     const char* namespace_name,
                                     qihse_federation_manifest_t* out) {
    if (!store_void || !user_void || !namespace_name || !out) return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->namespace_name, sizeof(out->namespace_name), "%s", namespace_name);
    manifest_build_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.manifest = out;
    snprintf(ctx.ns_prefix, sizeof(ctx.ns_prefix), "ns:%s:", namespace_name);
    ctx.ns_prefix_len = strlen(ctx.ns_prefix);
    ctx.current_count = 0;
    ctx.digest_ctx = NULL;
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          manifest_kv_cb, &ctx);
    if (ctx.digest_ctx) {
        manifest_flush_range(&ctx);
    }
    return true;
}

size_t qihse_federation_manifest_compare(const qihse_federation_manifest_t* local,
                                        const qihse_federation_manifest_t* remote,
                                        qihse_federation_manifest_entry_t* out_divergent,
                                        size_t out_cap) {
    if (!local || !remote) return 0;
    size_t divergent = 0;
    /* Simple comparison: compare each local entry against the remote.
     * For F3 we use a single-range manifest, so we compare the two
     * single entries directly. */
    for (size_t i = 0; i < local->entry_count && divergent < out_cap; i++) {
        bool found = false;
        for (size_t j = 0; j < remote->entry_count; j++) {
            if (strcmp(local->entries[i].range_start, remote->entries[j].range_start) == 0) {
                found = true;
                if (local->entries[i].object_count != remote->entries[j].object_count ||
                    memcmp(local->entries[i].digest, remote->entries[j].digest, 48) != 0) {
                    out_divergent[divergent++] = local->entries[i];
                }
                break;
            }
        }
        if (!found && divergent < out_cap) {
            out_divergent[divergent++] = local->entries[i];
        }
    }
    /* Check for ranges remote has that local doesn't. */
    for (size_t j = 0; j < remote->entry_count && divergent < out_cap; j++) {
        bool found = false;
        for (size_t i = 0; i < local->entry_count; i++) {
            if (strcmp(local->entries[i].range_start, remote->entries[j].range_start) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            out_divergent[divergent++] = remote->entries[j];
        }
    }
    return divergent;
}

/* ── F3: Anti-entropy sync plan ─────────────────────────────────────────── */

size_t qihse_federation_sync_plan(const qihse_federation_manifest_t* local,
                                 const qihse_federation_manifest_t* remote,
                                 qihse_federation_sync_range_t* out_ranges,
                                 size_t out_cap) {
    if (!local || !remote || !out_ranges || out_cap == 0) return 0;
    size_t count = 0;
    /* For each local entry, determine the action. */
    for (size_t i = 0; i < local->entry_count && count < out_cap; i++) {
        bool found = false;
        for (size_t j = 0; j < remote->entry_count; j++) {
            if (strcmp(local->entries[i].range_start, remote->entries[j].range_start) == 0) {
                found = true;
                if (local->entries[i].object_count == remote->entries[j].object_count &&
                    memcmp(local->entries[i].digest, remote->entries[j].digest, 48) == 0) {
                    /* in sync — no action */
                } else {
                    /* divergent — potential conflict */
                    out_ranges[count].action = QIHSE_SYNC_CONFLICT;
                    snprintf(out_ranges[count].range_start, sizeof(out_ranges[count].range_start),
                             "%s", local->entries[i].range_start);
                    snprintf(out_ranges[count].range_end, sizeof(out_ranges[count].range_end),
                             "%s", local->entries[i].range_end);
                    count++;
                }
                break;
            }
        }
        if (!found) {
            /* local has objects remote doesn't — send */
            out_ranges[count].action = QIHSE_SYNC_SEND;
            snprintf(out_ranges[count].range_start, sizeof(out_ranges[count].range_start),
                     "%s", local->entries[i].range_start);
            snprintf(out_ranges[count].range_end, sizeof(out_ranges[count].range_end),
                     "%s", local->entries[i].range_end);
            count++;
        }
    }
    /* Remote has objects local doesn't — fetch. */
    for (size_t j = 0; j < remote->entry_count && count < out_cap; j++) {
        bool found = false;
        for (size_t i = 0; i < local->entry_count; i++) {
            if (strcmp(local->entries[i].range_start, remote->entries[j].range_start) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            out_ranges[count].action = QIHSE_SYNC_FETCH;
            snprintf(out_ranges[count].range_start, sizeof(out_ranges[count].range_start),
                     "%s", remote->entries[j].range_start);
            snprintf(out_ranges[count].range_end, sizeof(out_ranges[count].range_end),
                     "%s", remote->entries[j].range_end);
            count++;
        }
    }
    return count;
}

/* ── F4: Native CAS (plan §7.2) ────────────────────────────────────────── */

#include <pthread.h>

static pthread_mutex_t g_federation_cas_lock = PTHREAD_MUTEX_INITIALIZER;

static void fedobj_key(const char* ns, const char* resource, char* out, size_t cap) {
    snprintf(out, cap, "fedobj:%s:%s", ns, resource);
}

bool qihse_federation_object_get(void* store_void, void* user_void,
                                 const char* namespace_name,
                                 const char* resource_id,
                                 uint64_t* out_generation,
                                 char* out_value, size_t out_value_cap) {
    if (!store_void || !user_void || !namespace_name || !resource_id || !out_value) return false;
    char key[256];
    fedobj_key(namespace_name, resource_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!blob) return false;
    /* Format: "<generation>\t<value>" */
    char* tab = strchr(blob, '\t');
    if (!tab) { free(blob); return false; }
    if (out_generation) *out_generation = strtoull(blob, NULL, 10);
    size_t vlen = strlen(tab + 1);
    if (vlen >= out_value_cap) vlen = out_value_cap - 1u;
    memcpy(out_value, tab + 1, vlen);
    out_value[vlen] = '\0';
    free(blob);
    return true;
}

bool qihse_federation_object_cas(void* store_void, void* user_void,
                                 const char* namespace_name,
                                 const char* resource_id,
                                 uint64_t expected_generation,
                                 const char* new_value,
                                 qihse_federation_cas_result_t* result) {
    if (!store_void || !user_void || !namespace_name || !resource_id || !new_value) return false;
    if (result) memset(result, 0, sizeof(*result));

    pthread_mutex_lock(&g_federation_cas_lock);

    char key[256];
    fedobj_key(namespace_name, resource_id, key, sizeof(key));
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);

    uint64_t current_gen = 0;
    if (existing) {
        current_gen = strtoull(existing, NULL, 10);
        free(existing);
    }

    if (result) result->old_generation = current_gen;

    if (existing && current_gen != expected_generation) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        if (result) result->swapped = false;
        return true; /* CAS failed but the call itself succeeded */
    }

    /* If the key doesn't exist, expected_generation must be 0. */
    if (!existing && expected_generation != 0) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        if (result) result->swapped = false;
        return true;
    }

    uint64_t new_gen = current_gen + 1;
    char blob[4096];
    snprintf(blob, sizeof(blob), "%llu\t%s", (unsigned long long)new_gen, new_value);
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);

    pthread_mutex_unlock(&g_federation_cas_lock);

    if (!ok) return false;
    if (result) {
        result->swapped = true;
        result->new_generation = new_gen;
    }
    return true;
}

/* ── F4: Fencing epochs (plan §7.3) ────────────────────────────────────── */

static void fedepoch_key(const qihse_uuid_t* node_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(node_id, id_str);
    snprintf(out, cap, "fedepoch:%s", id_str);
}

uint64_t qihse_federation_epoch_current(void* store_void, void* user_void,
                                        const qihse_uuid_t* node_id) {
    if (!store_void || !user_void || !node_id) return 0;
    char key[128];
    fedepoch_key(node_id, key, sizeof(key));
    char* val = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!val) return 0;
    uint64_t epoch = strtoull(val, NULL, 10);
    free(val);
    return epoch;
}

uint64_t qihse_federation_epoch_next(void* store_void, void* user_void,
                                      const qihse_uuid_t* node_id) {
    if (!store_void || !user_void || !node_id) return 0;
    pthread_mutex_lock(&g_federation_cas_lock);
    char key[128];
    fedepoch_key(node_id, key, sizeof(key));
    char* val = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    uint64_t current = val ? strtoull(val, NULL, 10) : 0;
    free(val);
    uint64_t next = current + 1;
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)next);
    qihse_kv_set_user((qihse_kv_store_t*)store_void, key, buf, 0, 0, (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_federation_cas_lock);
    return next;
}

/* ── F4: Lease primitive (plan §14) ────────────────────────────────────── */

const char* qihse_lease_state_name(qihse_lease_state_t state) {
    switch (state) {
        case QIHSE_LEASE_FREE:     return "free";
        case QIHSE_LEASE_GRANTED:   return "granted";
        case QIHSE_LEASE_EXPIRED:  return "expired";
        case QIHSE_LEASE_RELEASED: return "released";
    }
    return "unknown";
}

static void lease_kv_key(const qihse_uuid_t* lease_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(lease_id, id_str);
    snprintf(out, cap, QIHSE_FEDERATION_LEASE_PREFIX "%s", id_str);
}

static void lease_encode(const qihse_federation_lease_t* l, char* out, size_t cap) {
    char lid[33], oid[33], rid[33], iss[33];
    uuid_hex(&l->lease_id, lid);
    uuid_hex(&l->owner_node, oid);
    uuid_hex(&l->request_id, rid);
    uuid_hex(&l->issuer, iss);
    snprintf(out, cap, "%s\t%s\t%s\t%llu\t%llu\t%u\t%llu\t%llu\t%s\t%s",
             lid, oid, l->resource_id,
             (unsigned long long)l->fencing_epoch,
             (unsigned long long)l->generation,
             (unsigned)l->state,
             (unsigned long long)l->issued_hlc_physical,
             (unsigned long long)l->expires_hlc_physical,
             rid, iss);
}

static bool lease_decode(const char* blob, qihse_federation_lease_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char lid[33], oid[33], rid[33], iss[33];
    char resource[64];
    unsigned state_u = 0;
    unsigned long long fence = 0, gen = 0, issued = 0, expires = 0;
    int n = sscanf(blob, "%32[^\t]\t%32[^\t]\t%63[^\t]\t%llu\t%llu\t%u\t%llu\t%llu\t%32[^\t]\t%32[^\t]",
                   lid, oid, resource, &fence, &gen, &state_u, &issued, &expires, rid, iss);
    if (n < 8) return false;
    uuid_from_hex(lid, &out->lease_id);
    uuid_from_hex(oid, &out->owner_node);
    snprintf(out->resource_id, sizeof(out->resource_id), "%s", resource);
    out->fencing_epoch = (uint64_t)fence;
    out->generation = (uint64_t)gen;
    /* A state outside the enum means the record is corrupt; refuse rather
     * than hand back a lease in a state that does not exist. */
    if (state_u > (unsigned)QIHSE_LEASE_RELEASED) return false;
    out->state = (qihse_lease_state_t)state_u;
    out->issued_hlc_physical = (uint64_t)issued;
    out->expires_hlc_physical = (uint64_t)expires;
    if (n >= 9) uuid_from_hex(rid, &out->request_id);
    if (n >= 10) uuid_from_hex(iss, &out->issuer);
    return true;
}

bool qihse_federation_lease_acquire(void* store_void, void* user_void,
                                   const qihse_federation_lease_t* request,
                                   qihse_federation_lease_t* out) {
    if (!store_void || !user_void || !request || !out) return false;
    memset(out, 0, sizeof(*out));

    pthread_mutex_lock(&g_federation_cas_lock);

    /* Idempotency: a repeated request_id returns the previously issued lease
     * rather than minting a new one. */
    char req_key[128];
    {
        char rid_str[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&request->request_id, rid_str);
        snprintf(req_key, sizeof(req_key), QIHSE_FEDERATION_LEASE_REQUEST_PREFIX "%s", rid_str);
    }
    char* prior_id = qihse_kv_get_user((qihse_kv_store_t*)store_void, req_key,
                                       (qihse_user_t*)user_void);
    if (prior_id) {
        qihse_uuid_t prior;
        bool have_prior = qihse_uuid_parse(prior_id, &prior);
        free(prior_id);
        if (have_prior) {
            char pkey[128];
            lease_kv_key(&prior, pkey, sizeof(pkey));
            char* pblob = qihse_kv_get_user((qihse_kv_store_t*)store_void, pkey,
                                            (qihse_user_t*)user_void);
            if (pblob) {
                bool decoded = lease_decode(pblob, out);
                free(pblob);
                if (decoded) {
                    pthread_mutex_unlock(&g_federation_cas_lock);
                    return true;
                }
            }
        }
    }

    /* Resource exclusivity with a monotonic fencing high-water mark.  The
     * resource record persists after release so a stale holder at a lower
     * epoch can never re-acquire the resource. */
    char res_key[192];
    snprintf(res_key, sizeof(res_key), QIHSE_FEDERATION_LEASE_RESOURCE_PREFIX "%s:%s",
             request->namespace_name, request->resource_id);
    char* res_val = qihse_kv_get_user((qihse_kv_store_t*)store_void, res_key,
                                      (qihse_user_t*)user_void);
    if (res_val) {
        unsigned long long high_epoch = 0;
        char holder_str[QIHSE_UUID_STR_LEN + 1u];
        holder_str[0] = '\0';
        if (sscanf(res_val, "%40[^\t]\t%llu", holder_str, &high_epoch) >= 1) {
            if ((uint64_t)high_epoch >= request->fencing_epoch) {
                free(res_val);
                pthread_mutex_unlock(&g_federation_cas_lock);
                return false; /* stale fencing epoch — refuse */
            }
        }
        free(res_val);
    }

    /* Issue the lease. */
    *out = *request;
    out->state = QIHSE_LEASE_GRANTED;
    out->generation = request->generation + 1u;
    char key[128];
    lease_kv_key(&out->lease_id, key, sizeof(key));
    char blob[1024];
    lease_encode(out, blob, sizeof(blob));
    if (!qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                           (qihse_user_t*)user_void)) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return false;
    }

    /* Publish the fencing high-water mark for the resource. */
    char lid_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&out->lease_id, lid_str);
    char res_val_new[128];
    snprintf(res_val_new, sizeof(res_val_new), "%s\t%llu", lid_str,
             (unsigned long long)out->fencing_epoch);
    qihse_kv_set_user((qihse_kv_store_t*)store_void, res_key, res_val_new, 0, 0,
                      (qihse_user_t*)user_void);

    /* Record the request index for idempotent retries. */
    qihse_kv_set_user((qihse_kv_store_t*)store_void, req_key, lid_str, 0, 0,
                      (qihse_user_t*)user_void);

    pthread_mutex_unlock(&g_federation_cas_lock);
    return true;
}

bool qihse_federation_lease_renew(void* store_void, void* user_void,
                                 const qihse_uuid_t* lease_id,
                                 uint64_t new_expires_hlc_physical,
                                 qihse_federation_lease_t* out) {
    if (!store_void || !user_void || !lease_id || !out) return false;
    pthread_mutex_lock(&g_federation_cas_lock);
    char key[128];
    lease_kv_key(lease_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!blob) { pthread_mutex_unlock(&g_federation_cas_lock); return false; }
    if (!lease_decode(blob, out)) { free(blob); pthread_mutex_unlock(&g_federation_cas_lock); return false; }
    free(blob);
    if (out->state != QIHSE_LEASE_GRANTED) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return false;
    }
    out->expires_hlc_physical = new_expires_hlc_physical;
    char new_blob[1024];
    lease_encode(out, new_blob, sizeof(new_blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_federation_cas_lock);
    return ok;
}

bool qihse_federation_lease_release(void* store_void, void* user_void,
                                   const qihse_uuid_t* lease_id) {
    if (!store_void || !user_void || !lease_id) return false;
    pthread_mutex_lock(&g_federation_cas_lock);
    char key[128];
    lease_kv_key(lease_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!blob) { pthread_mutex_unlock(&g_federation_cas_lock); return false; }
    qihse_federation_lease_t l;
    if (!lease_decode(blob, &l)) { free(blob); pthread_mutex_unlock(&g_federation_cas_lock); return false; }
    free(blob);
    if (l.state == QIHSE_LEASE_RELEASED) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return true; /* idempotent */
    }
    l.state = QIHSE_LEASE_RELEASED;
    char new_blob[1024];
    lease_encode(&l, new_blob, sizeof(new_blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_federation_cas_lock);
    return ok;
}

bool qihse_federation_lease_read(void* store_void, void* user_void,
                                 const qihse_uuid_t* lease_id,
                                 qihse_federation_lease_t* out) {
    if (!store_void || !user_void || !lease_id || !out) return false;
    char key[128];
    lease_kv_key(lease_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = lease_decode(blob, out);
    free(blob);
    /* The embedded id must agree with the key it was stored under.  A record
     * whose body names a different lease is corrupt, and returning it would
     * hand the caller a record belonging to something else. */
    if (ok && !qihse_uuid_equal(&out->lease_id, lease_id)) return false;
    return ok;
}

/* ── F4: Replication groups (plan §15) ─────────────────────────────────── */

static void group_kv_key(const char* group_id, char* out, size_t cap) {
    snprintf(out, cap, QIHSE_FEDERATION_GROUP_PREFIX "%s", group_id);
}

static void group_encode(const qihse_federation_group_t* g, char* out, size_t cap) {
    size_t off = 0;
    off += (size_t)snprintf(out + off, cap - off, "%s\t%llu\t%u\t%zu",
                           g->group_id, (unsigned long long)g->term,
                           (unsigned)g->consistency, g->member_count);
    for (size_t i = 0; i < g->member_count && off < cap; i++) {
        char mid[33];
        uuid_hex(&g->members[i].member_id, mid);
        off += (size_t)snprintf(out + off, cap - off, "\t%s\t%d\t%d",
                               mid, g->members[i].is_voter ? 1 : 0,
                               g->members[i].is_witness ? 1 : 0);
    }
}

static bool group_decode(const char* blob, qihse_federation_group_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char gid[64];
    unsigned long long term = 0;
    unsigned cons = 0;
    unsigned long long mcount = 0;
    int n = sscanf(blob, "%63[^\t]\t%llu\t%u\t%llu",
                   gid, &term, &cons, &mcount);
    if (n < 4) return false;
    if (cons > (unsigned)QIHSE_CONSISTENCY_LINEARIZABLE) return false;
    snprintf(out->group_id, sizeof(out->group_id), "%s", gid);
    out->term = (uint64_t)term;
    out->consistency = (qihse_consistency_class_t)cons;
    out->member_count = (size_t)mcount;
    if (out->member_count > QIHSE_FEDERATION_GROUP_MAX_MEMBERS) return false;
    /* Parse members from the remaining tabs. */
    const char* p = blob;
    /* Skip past the first 4 fields. */
    for (int i = 0; i < 4; i++) {
        p = strchr(p, '\t');
        if (!p) return n >= 4; /* no members is valid */
        p++;
    }
    for (size_t i = 0; i < out->member_count && i < QIHSE_FEDERATION_GROUP_MAX_MEMBERS; i++) {
        char mid[33];
        int voter = 0, witness = 0;
        int mn = sscanf(p, "%32[^\t]\t%d\t%d", mid, &voter, &witness);
        if (mn < 1) break;
        uuid_from_hex(mid, &out->members[i].member_id);
        out->members[i].is_voter = voter != 0;
        out->members[i].is_witness = witness != 0;
        /* Advance past member_id, voter, witness. */
        for (int j = 0; j < 3; j++) {
            p = strchr(p, '\t');
            if (!p) return true;
            p++;
        }
    }
    return true;
}

bool qihse_federation_group_create(void* store_void, void* user_void,
                                   const qihse_federation_group_t* group) {
    if (!store_void || !user_void || !group) return false;
    char key[128];
    group_kv_key(group->group_id, key, sizeof(key));
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (existing) { free(existing); return false; }
    char blob[4096];
    group_encode(group, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_group_lookup(void* store_void, void* user_void,
                                   const char* group_id,
                                   qihse_federation_group_t* out) {
    if (!store_void || !user_void || !group_id || !out) return false;
    char key[128];
    group_kv_key(group_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = group_decode(blob, out);
    free(blob);
    return ok;
}

bool qihse_federation_group_add_member(void* store_void, void* user_void,
                                       const char* group_id,
                                       const qihse_federation_group_member_t* member) {
    if (!store_void || !user_void || !group_id || !member) return false;
    pthread_mutex_lock(&g_federation_cas_lock);
    qihse_federation_group_t g;
    if (!qihse_federation_group_lookup(store_void, user_void, group_id, &g)) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return false;
    }
    /* Check if member already exists; if so, update. */
    bool found = false;
    for (size_t i = 0; i < g.member_count; i++) {
        if (qihse_uuid_equal(&g.members[i].member_id, &member->member_id)) {
            g.members[i] = *member;
            found = true;
            break;
        }
    }
    if (!found) {
        if (g.member_count >= QIHSE_FEDERATION_GROUP_MAX_MEMBERS) {
            pthread_mutex_unlock(&g_federation_cas_lock);
            return false;
        }
        g.members[g.member_count++] = *member;
    }
    char key[128];
    group_kv_key(group_id, key, sizeof(key));
    char blob[4096];
    group_encode(&g, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_federation_cas_lock);
    return ok;
}

bool qihse_federation_group_remove_member(void* store_void, void* user_void,
                                          const char* group_id,
                                          const qihse_uuid_t* member_id) {
    if (!store_void || !user_void || !group_id || !member_id) return false;
    pthread_mutex_lock(&g_federation_cas_lock);
    qihse_federation_group_t g;
    if (!qihse_federation_group_lookup(store_void, user_void, group_id, &g)) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return false;
    }
    bool found = false;
    for (size_t i = 0; i < g.member_count; i++) {
        if (qihse_uuid_equal(&g.members[i].member_id, member_id)) {
            /* Shift remaining members down. */
            for (size_t j = i; j + 1 < g.member_count; j++)
                g.members[j] = g.members[j + 1];
            g.member_count--;
            found = true;
            break;
        }
    }
    if (!found) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return false;
    }
    char key[128];
    group_kv_key(group_id, key, sizeof(key));
    char blob[4096];
    group_encode(&g, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_federation_cas_lock);
    return ok;
}

uint64_t qihse_federation_group_advance_term(void* store_void, void* user_void,
                                              const char* group_id) {
    if (!store_void || !user_void || !group_id) return 0;
    pthread_mutex_lock(&g_federation_cas_lock);
    qihse_federation_group_t g;
    if (!qihse_federation_group_lookup(store_void, user_void, group_id, &g)) {
        pthread_mutex_unlock(&g_federation_cas_lock);
        return 0;
    }
    g.term++;
    char key[128];
    group_kv_key(group_id, key, sizeof(key));
    char blob[4096];
    group_encode(&g, blob, sizeof(blob));
    qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                      (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_federation_cas_lock);
    return g.term;
}

typedef struct {
    qihse_federation_group_cb cb;
    void* user_data;
} group_iter_ctx_t;

static bool group_iter_cb(const char* key, const char* value, void* user_data) {
    group_iter_ctx_t* ctx = (group_iter_ctx_t*)user_data;
    if (strncmp(key, QIHSE_FEDERATION_GROUP_PREFIX,
                strlen(QIHSE_FEDERATION_GROUP_PREFIX)) != 0) return true;
    qihse_federation_group_t g;
    if (!group_decode(value, &g)) return true;
    return ctx->cb(&g, ctx->user_data);
}

void qihse_federation_group_foreach(void* store_void, void* user_void,
                                    qihse_federation_group_cb cb,
                                    void* user_data) {
    if (!store_void || !cb) return;
    group_iter_ctx_t ctx = { cb, user_data };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          group_iter_cb, &ctx);
}

/* ── F5: Infrastructure authorization scopes (plan §19) ────────────────── */

typedef struct {
    qihse_infra_scope_t bit;
    const char* name;
} infra_scope_entry_t;

static const infra_scope_entry_t g_infra_scopes[] = {
    { QIHSE_SCOPE_FEDERATION_READ,  "FEDERATION_READ"  },
    { QIHSE_SCOPE_FEDERATION_WRITE, "FEDERATION_WRITE" },
    { QIHSE_SCOPE_NODE_ENROLL,      "NODE_ENROLL"      },
    { QIHSE_SCOPE_NODE_REVOKE,      "NODE_REVOKE"      },
    { QIHSE_SCOPE_POLICY_READ,      "POLICY_READ"      },
    { QIHSE_SCOPE_POLICY_WRITE,     "POLICY_WRITE"     },
    { QIHSE_SCOPE_LEASE_READ,       "LEASE_READ"       },
    { QIHSE_SCOPE_LEASE_WRITE,      "LEASE_WRITE"      },
    { QIHSE_SCOPE_SECURITY_ADMIN,   "SECURITY_ADMIN"   },
    { QIHSE_SCOPE_AUDIT_READ,       "AUDIT_READ"       },
    { QIHSE_SCOPE_TELEMETRY_WRITE,  "TELEMETRY_WRITE"  },
};

const char* qihse_infra_scope_name(qihse_infra_scope_t scope) {
    for (size_t i = 0; i < sizeof(g_infra_scopes) / sizeof(g_infra_scopes[0]); i++) {
        if (g_infra_scopes[i].bit == scope) return g_infra_scopes[i].name;
    }
    return "UNKNOWN";
}

bool qihse_infra_scope_parse(const char* name, qihse_infra_scope_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_infra_scopes) / sizeof(g_infra_scopes[0]); i++) {
        if (strcasecmp(g_infra_scopes[i].name, name) == 0) {
            *out = g_infra_scopes[i].bit;
            return true;
        }
    }
    return false;
}

typedef struct {
    qihse_service_identity_t kind;
    const char* name;
    qihse_infra_scope_t scopes;
} service_identity_entry_t;

static const service_identity_entry_t g_service_identities[] = {
    { QIHSE_IDENTITY_OPERATOR,              "operator",              QIHSE_SCOPE_ALL },
    { QIHSE_IDENTITY_HYPERVISOR_CONTROLLER, "hypervisor-controller",
      QIHSE_SCOPE_FEDERATION_READ | QIHSE_SCOPE_FEDERATION_WRITE |
      QIHSE_SCOPE_POLICY_READ | QIHSE_SCOPE_POLICY_WRITE |
      QIHSE_SCOPE_LEASE_READ | QIHSE_SCOPE_LEASE_WRITE |
      QIHSE_SCOPE_TELEMETRY_WRITE },
    { QIHSE_IDENTITY_HOST_AGENT,            "host-agent",
      QIHSE_SCOPE_FEDERATION_READ | QIHSE_SCOPE_TELEMETRY_WRITE |
      QIHSE_SCOPE_LEASE_READ },
    { QIHSE_IDENTITY_UI_API,                "ui-api",
      QIHSE_SCOPE_FEDERATION_READ | QIHSE_SCOPE_POLICY_READ |
      QIHSE_SCOPE_LEASE_READ },
    /* KEYSTONE receives a read/index identity, never database-admin. */
    { QIHSE_IDENTITY_KEYSTONE_INDEXER,      "keystone-indexer",
      QIHSE_SCOPE_FEDERATION_READ },
    { QIHSE_IDENTITY_BACKUP_AGENT,          "backup-agent",
      QIHSE_SCOPE_FEDERATION_READ | QIHSE_SCOPE_POLICY_READ |
      QIHSE_SCOPE_AUDIT_READ },
};

const char* qihse_service_identity_name(qihse_service_identity_t kind) {
    for (size_t i = 0; i < sizeof(g_service_identities) / sizeof(g_service_identities[0]); i++) {
        if (g_service_identities[i].kind == kind) return g_service_identities[i].name;
    }
    return "unknown";
}

bool qihse_service_identity_parse(const char* name, qihse_service_identity_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_service_identities) / sizeof(g_service_identities[0]); i++) {
        if (strcmp(g_service_identities[i].name, name) == 0) {
            *out = g_service_identities[i].kind;
            return true;
        }
    }
    return false;
}

qihse_infra_scope_t qihse_service_identity_default_scopes(qihse_service_identity_t kind) {
    for (size_t i = 0; i < sizeof(g_service_identities) / sizeof(g_service_identities[0]); i++) {
        if (g_service_identities[i].kind == kind) return g_service_identities[i].scopes;
    }
    return QIHSE_SCOPE_NONE;
}

bool qihse_infra_scope_check(void* user_void, qihse_infra_scope_t required) {
    if (!user_void) return false; /* NULL is never an authorization bypass */
    qihse_user_t* user = (qihse_user_t*)user_void;
    uint16_t role = qihse_user_get_role(user);
    qihse_infra_scope_t held;
    switch (role) {
        case QIHSE_ROLE_OPERATOR: held = QIHSE_SCOPE_ALL; break;
        case QIHSE_ROLE_ANALYST:
            held = QIHSE_SCOPE_FEDERATION_READ | QIHSE_SCOPE_POLICY_READ |
                   QIHSE_SCOPE_LEASE_READ | QIHSE_SCOPE_TELEMETRY_WRITE;
            break;
        default: held = QIHSE_SCOPE_NONE; break;
    }
    if (required == QIHSE_SCOPE_NONE) return true;
    return (held & required) == required;
}

/* ── F5: Node identity and trust (plan §18, §20) ───────────────────────── */

const char* qihse_trust_state_name(qihse_trust_state_t state) {
    switch (state) {
        case QIHSE_TRUST_UNKNOWN:  return "unknown";
        case QIHSE_TRUST_PENDING:  return "pending";
        case QIHSE_TRUST_APPROVED: return "approved";
        case QIHSE_TRUST_REVOKED:  return "revoked";
    }
    return "unknown";
}

bool qihse_trust_state_parse(const char* name, qihse_trust_state_t* out) {
    if (!name || !out) return false;
    if (strcmp(name, "unknown") == 0)  { *out = QIHSE_TRUST_UNKNOWN; return true; }
    if (strcmp(name, "pending") == 0)  { *out = QIHSE_TRUST_PENDING; return true; }
    if (strcmp(name, "approved") == 0) { *out = QIHSE_TRUST_APPROVED; return true; }
    if (strcmp(name, "revoked") == 0)  { *out = QIHSE_TRUST_REVOKED; return true; }
    return false;
}

/* ── Signature algorithms ──────────────────────────────────────────────── */

typedef struct {
    qihse_sig_alg_t alg;
    const char* name;
    const char* ossl_name;   /* name OpenSSL knows this key type by */
    size_t pk_bytes;
    size_t sig_bytes;
    bool post_quantum;
} sig_alg_entry_t;

static const sig_alg_entry_t g_sig_algs[] = {
    { QIHSE_SIG_ED25519,   "ed25519",   "ED25519",   32u,    64u,   false },
    { QIHSE_SIG_ML_DSA_44, "ml-dsa-44", "ML-DSA-44", 1312u,  2420u, true  },
    { QIHSE_SIG_ML_DSA_65, "ml-dsa-65", "ML-DSA-65", 1952u,  3309u, true  },
    { QIHSE_SIG_ML_DSA_87, "ml-dsa-87", "ML-DSA-87", 2592u,  4627u, true  },
};

static const sig_alg_entry_t* sig_alg_lookup(qihse_sig_alg_t alg) {
    for (size_t i = 0; i < sizeof(g_sig_algs) / sizeof(g_sig_algs[0]); i++) {
        if (g_sig_algs[i].alg == alg) return &g_sig_algs[i];
    }
    return NULL;
}

const char* qihse_sig_alg_name(qihse_sig_alg_t alg) {
    const sig_alg_entry_t* e = sig_alg_lookup(alg);
    return e ? e->name : "unknown";
}

bool qihse_sig_alg_parse(const char* name, qihse_sig_alg_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_sig_algs) / sizeof(g_sig_algs[0]); i++) {
        if (strcasecmp(g_sig_algs[i].name, name) == 0) {
            *out = g_sig_algs[i].alg;
            return true;
        }
    }
    return false;
}

size_t qihse_sig_alg_public_key_bytes(qihse_sig_alg_t alg) {
    const sig_alg_entry_t* e = sig_alg_lookup(alg);
    return e ? e->pk_bytes : 0u;
}

size_t qihse_sig_alg_signature_bytes(qihse_sig_alg_t alg) {
    const sig_alg_entry_t* e = sig_alg_lookup(alg);
    return e ? e->sig_bytes : 0u;
}

bool qihse_sig_alg_is_post_quantum(qihse_sig_alg_t alg) {
    const sig_alg_entry_t* e = sig_alg_lookup(alg);
    return e ? e->post_quantum : false;
}

bool qihse_federation_node_fingerprint(const uint8_t* public_key,
                                       size_t public_key_len,
                                       uint8_t* out_fingerprint) {
    if (!public_key || public_key_len == 0 || !out_fingerprint) return false;
    unsigned int len = 0;
    if (!EVP_Digest(public_key, public_key_len,
                    out_fingerprint, &len, EVP_sha384(), NULL)) return false;
    return len == QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES;
}

/* Shared keypair generation for one algorithm.  Writes the private key
 * PEM-encoded at 0600 and returns the raw public key. */
static bool node_keygen_for_alg(const char* key_directory,
                                const qihse_uuid_t* node_id,
                                qihse_sig_alg_t alg,
                                uint8_t* out_public_key, size_t* out_public_key_len,
                                char* out_key_handle, size_t out_key_handle_cap) {
    const sig_alg_entry_t* entry = sig_alg_lookup(alg);
    if (!entry) return false;

    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, entry->ossl_name);
    if (!pkey) return false;

    size_t pub_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) != 1 ||
        pub_len != entry->pk_bytes) {
        EVP_PKEY_free(pkey);
        return false;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, out_public_key, &pub_len) != 1 ||
        pub_len != entry->pk_bytes) {
        EVP_PKEY_free(pkey);
        return false;
    }

    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(node_id, id_str);
    int n = snprintf(out_key_handle, out_key_handle_cap, "%s/%s.key", key_directory, id_str);
    if (n <= 0 || (size_t)n >= out_key_handle_cap) { EVP_PKEY_free(pkey); return false; }

    FILE* f = fopen(out_key_handle, "wb");
    if (!f) { EVP_PKEY_free(pkey); return false; }
    int ok = PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    if (ok != 1) {
        (void)remove(out_key_handle);
        EVP_PKEY_free(pkey);
        return false;
    }
#ifndef _WIN32
    (void)chmod(out_key_handle, 0600);
#endif
    EVP_PKEY_free(pkey);
    if (out_public_key_len) *out_public_key_len = entry->pk_bytes;
    return true;
}

/* Legacy entry point: Ed25519, for bootstrap and pre-quantum compatibility. */
bool qihse_federation_node_keygen(const char* key_directory,
                                  const qihse_uuid_t* node_id,
                                  uint8_t* out_public_key,
                                  char* out_key_handle, size_t out_key_handle_cap) {
    if (!key_directory || !node_id || !out_public_key || !out_key_handle) return false;
    return node_keygen_for_alg(key_directory, node_id, QIHSE_SIG_ED25519,
                               out_public_key, NULL, out_key_handle, out_key_handle_cap);
}

bool qihse_federation_node_keygen_alg(const char* key_directory,
                                      qihse_sig_alg_t alg,
                                      qihse_federation_node_identity_t* out) {
    if (!key_directory || !out) return false;
    if (!sig_alg_lookup(alg)) return false;

    size_t pk_len = 0;
    if (!node_keygen_for_alg(key_directory, &out->node_id, alg,
                             out->public_key, &pk_len,
                             out->key_handle, sizeof(out->key_handle))) {
        return false;
    }
    out->sig_alg = alg;
    out->public_key_len = (uint16_t)pk_len;
    return qihse_federation_node_fingerprint(out->public_key, pk_len, out->fingerprint);
}

void* qihse_federation_node_key_load(const char* key_handle) {
    if (!key_handle) return NULL;
    FILE* f = fopen(key_handle, "rb");
    if (!f) return NULL;
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

void qihse_federation_node_key_free(void* pkey) {
    if (pkey) EVP_PKEY_free((EVP_PKEY*)pkey);
}

/* Node record wire format (tab-separated, binary fields hex-encoded). */
/* Hex-encode a byte string into a caller buffer (2 chars per byte + NUL). */
static void bytes_to_hex(const uint8_t* in, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) snprintf(out + i * 2, 3, "%02x", in[i]);
    out[len * 2] = '\0';
}

static bool hex_to_bytes(const char* hex, uint8_t* out, size_t max_len, size_t* out_len) {
    size_t hlen = hex ? strlen(hex) : 0;
    if (hlen == 0 || (hlen % 2u) != 0) return false;
    size_t n = hlen / 2u;
    if (n > max_len) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        out[i] = (uint8_t)byte;
    }
    if (out_len) *out_len = n;
    return true;
}

/* Node record wire format.  The signature algorithm and the public key length
 * are recorded so a record written under one algorithm stays readable after
 * the fleet moves to another. */
static bool node_encode(const qihse_federation_node_identity_t* n, char* out, size_t cap) {
    char nid[33], fp_hex[97];
    uuid_hex(&n->node_id, nid);
    /* Public keys reach 2592 bytes, so hex needs 5185 characters; build it in
     * a heap buffer rather than a large stack frame. */
    size_t pk_hex_len = (size_t)n->public_key_len * 2u + 1u;
    char* pub_hex = (char*)malloc(pk_hex_len);
    /* Returning silently here would leave `out` uninitialised and the caller
     * would store garbage as a node record. */
    if (!pub_hex) return false;
    bytes_to_hex(n->public_key, n->public_key_len, pub_hex);
    bytes_to_hex(n->fingerprint, QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES, fp_hex);
    snprintf(out, cap, "%s\t%s\t%s\t%s\t%u\t%u\t%s\t%s\t%u\t%llu\t%u\t%u\t%u\t%llu",
             nid, n->hostname, n->boot_id, n->key_handle,
             (unsigned)n->sig_alg, (unsigned)n->public_key_len,
             pub_hex, fp_hex,
             (unsigned)n->trust, (unsigned long long)n->enrollment_epoch,
             (unsigned)n->identity_kind, (unsigned)n->scopes,
             (unsigned)n->capabilities,
             (unsigned long long)n->last_hlc_physical);
    free(pub_hex);
    return true;
}

static bool node_decode(const char* blob, qihse_federation_node_identity_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));

    /* Walk the record field by field: the public key is variable length and
     * the trailing fields are optional, so positional sscanf cannot be used.
     *
     * ONE reusable heap buffer rather than one array element per column.  A
     * `char f[14][5200]` frame is ~73 KB, which is a needless denial-of-service
     * surface for a malformed record and would blow a small thread stack — and
     * this decoder runs on the bus thread. */
    size_t buf_cap = QIHSE_FEDERATION_PUBKEY_MAX_BYTES * 2u + 2u;
    char* f = (char*)malloc(buf_cap);
    if (!f) return false;
    bool ok = false;
    const char* p = blob;
    size_t declared_pk_len = 0, actual_pk_len = 0, fp_len = 0;

    /* 0: node id */
    p = fed_next_field(p, f, buf_cap);
    if (!uuid_from_hex(f, &out->node_id)) goto done;
    /* 1-3: display attributes and the key handle */
    p = fed_next_field(p, out->hostname, sizeof(out->hostname));
    p = fed_next_field(p, out->boot_id, sizeof(out->boot_id));
    p = fed_next_field(p, out->key_handle, sizeof(out->key_handle));
    /* 4: signature algorithm */
    p = fed_next_field(p, f, buf_cap);
    {
        uint64_t alg_raw = strtoull(f, NULL, 10);
        if (alg_raw > (uint64_t)QIHSE_SIG_ML_DSA_87) goto done;
        out->sig_alg = (qihse_sig_alg_t)alg_raw;
    }
    /* 5: declared public key length */
    p = fed_next_field(p, f, buf_cap);
    declared_pk_len = (size_t)strtoull(f, NULL, 10);
    /* 6: public key, hex */
    p = fed_next_field(p, f, buf_cap);
    if (!hex_to_bytes(f, out->public_key, QIHSE_FEDERATION_PUBKEY_MAX_BYTES,
                      &actual_pk_len)) goto done;
    /* The declared length must match the encoded length AND the algorithm's
     * fixed size, or the record is inconsistent. */
    if (declared_pk_len != actual_pk_len) goto done;
    if (actual_pk_len != qihse_sig_alg_public_key_bytes(out->sig_alg)) goto done;
    out->public_key_len = (uint16_t)actual_pk_len;
    /* 7: fingerprint, which must actually describe the key it is attached to */
    p = fed_next_field(p, f, buf_cap);
    if (!hex_to_bytes(f, out->fingerprint, QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES,
                      &fp_len)) goto done;
    if (fp_len != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) goto done;
    {
        uint8_t recomputed[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
        if (!qihse_federation_node_fingerprint(out->public_key, actual_pk_len, recomputed)) {
            goto done;
        }
        if (memcmp(recomputed, out->fingerprint, sizeof(recomputed)) != 0) goto done;
    }
    /* 8: trust state */
    p = fed_next_field(p, f, buf_cap);
    {
        uint64_t trust_raw = strtoull(f, NULL, 10);
        if (trust_raw > (uint64_t)QIHSE_TRUST_REVOKED) goto done;
        out->trust = (qihse_trust_state_t)trust_raw;
    }
    /* 9: enrollment epoch */
    p = fed_next_field(p, f, buf_cap);
    out->enrollment_epoch = (uint64_t)strtoull(f, NULL, 10);
    /* 10: service identity kind */
    p = fed_next_field(p, f, buf_cap);
    {
        uint64_t kind_raw = strtoull(f, NULL, 10);
        if (kind_raw > (uint64_t)QIHSE_IDENTITY_BACKUP_AGENT) goto done;
        out->identity_kind = (qihse_service_identity_t)kind_raw;
    }
    /* 11-13: scopes, capabilities, last HLC */
    p = fed_next_field(p, f, buf_cap);
    out->scopes = (qihse_infra_scope_t)strtoul(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    out->capabilities = (uint32_t)strtoul(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    out->last_hlc_physical = (uint64_t)strtoull(f, NULL, 10);
    ok = true;

done:
    free(f);
    return ok;
}

static void node_kv_key(const qihse_uuid_t* node_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(node_id, id_str);
    snprintf(out, cap, QIHSE_FEDERATION_NODE_PREFIX "%s", id_str);
}

bool qihse_federation_node_enroll_request(void* store_void, void* user_void,
                                         const qihse_federation_node_identity_t* identity) {
    if (!store_void || !user_void || !identity) return false;
    char key[128];
    node_kv_key(&identity->node_id, key, sizeof(key));
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) { free(existing); return false; }

    qihse_federation_node_identity_t rec = *identity;
    rec.trust = QIHSE_TRUST_PENDING;
    rec.enrollment_epoch = 0;
    /* The identity's scopes come from its service identity kind, not from
     * the enrolling caller — a requester cannot self-grant privilege. */
    rec.scopes = qihse_service_identity_default_scopes(rec.identity_kind);
    if (rec.public_key_len == 0 ||
        rec.public_key_len != qihse_sig_alg_public_key_bytes(rec.sig_alg)) return false;
    if (!qihse_federation_node_fingerprint(rec.public_key, rec.public_key_len,
                                          rec.fingerprint)) return false;

    /* An ML-DSA-87 public key hex-encodes to 5184 characters. */
    char blob[8192];
    /* An encode failure means the record could not be built; storing an
     * uninitialised buffer as a node identity would be worse than failing. */
    if (!node_encode(&rec, blob, sizeof(blob))) return false;
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_node_enroll_approve(void* store_void, void* user_void,
                                         const qihse_uuid_t* node_id,
                                         uint64_t enrollment_epoch) {
    if (!store_void || !user_void || !node_id) return false;
    if (!qihse_infra_scope_check(user_void, QIHSE_SCOPE_NODE_ENROLL)) return false;
    char key[128];
    node_kv_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    qihse_federation_node_identity_t rec;
    bool ok = node_decode(blob, &rec);
    free(blob);
    if (!ok) return false;
    if (rec.trust == QIHSE_TRUST_REVOKED) return false; /* revocation is permanent */
    rec.trust = QIHSE_TRUST_APPROVED;
    rec.enrollment_epoch = enrollment_epoch;
    char new_blob[8192];
    if (!node_encode(&rec, new_blob, sizeof(new_blob))) return false;
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_node_revoke(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id) {
    if (!store_void || !user_void || !node_id) return false;
    if (!qihse_infra_scope_check(user_void, QIHSE_SCOPE_NODE_REVOKE)) return false;
    char key[128];
    node_kv_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    qihse_federation_node_identity_t rec;
    bool ok = node_decode(blob, &rec);
    free(blob);
    if (!ok) return false;
    rec.trust = QIHSE_TRUST_REVOKED;
    rec.scopes = QIHSE_SCOPE_NONE;
    char new_blob[8192];
    if (!node_encode(&rec, new_blob, sizeof(new_blob))) return false;
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_federation_node_lookup(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id,
                                  qihse_federation_node_identity_t* out) {
    if (!store_void || !user_void || !node_id || !out) return false;
    char key[128];
    node_kv_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = node_decode(blob, out);
    free(blob);
    if (ok && !qihse_uuid_equal(&out->node_id, node_id)) return false;
    return ok;
}

typedef struct {
    qihse_federation_node_cb cb;
    void* user_data;
} node_iter_ctx_t;

static bool node_iter_cb(const char* key, const char* value, void* user_data) {
    node_iter_ctx_t* ctx = (node_iter_ctx_t*)user_data;
    if (strncmp(key, QIHSE_FEDERATION_NODE_PREFIX,
                strlen(QIHSE_FEDERATION_NODE_PREFIX)) != 0) return true;
    qihse_federation_node_identity_t rec;
    if (!node_decode(value, &rec)) return true;
    return ctx->cb(&rec, ctx->user_data);
}

void qihse_federation_node_foreach(void* store_void, void* user_void,
                                   qihse_federation_node_cb cb, void* user_data) {
    if (!store_void || !cb) return;
    node_iter_ctx_t ctx = { cb, user_data };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          node_iter_cb, &ctx);
}

/* ── Node capability records (W2.4) ───────────────────────────────────────
 *
 * The durable form of a NODE_CAP payload, at "federation/node/<uuid>".
 * Separate from the identity record by design (see the header): a capability
 * update must never be a read-modify-write of a trust record. */

#define CAP_RECORD_VERSION 2u

const char* qihse_capability_source_name(qihse_capability_source_t source) {
    switch (source) {
        case QIHSE_CAP_SOURCE_NONE:             return "none";
        case QIHSE_CAP_SOURCE_LOCAL_PROBE:      return "local-probe";
        case QIHSE_CAP_SOURCE_SIGNED_STATEMENT: return "signed-statement";
        case QIHSE_CAP_SOURCE_OPERATOR:         return "operator";
    }
    return "unknown";
}

/* Strict unsigned parse: the whole field must be a number.  strtoull() alone
 * accepts "12abc" as 12, which would let a malformed record decode as a
 * different record. */
static bool cap_parse_u64(const char* f, uint64_t* out) {
    if (!f || !out || *f == '\0') return false;
    char* end = NULL;
    errno = 0;
    unsigned long long v = strtoull(f, &end, 10);
    if (errno != 0 || !end || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

static void cap_kv_key(const qihse_uuid_t* node_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(node_id, id_str);
    snprintf(out, cap, QIHSE_FEDERATION_NODE_CAP_PREFIX "%s", id_str);
}

/* A tuple is refused on write and on read unless every field is inside its
 * declared range.  The decoder must never be more permissive than the
 * producer. */
static bool cap_values_valid(const qihse_federation_capability_values_t* v) {
    if (!v) return false;
    if (v->isa_tier > QIHSE_FEDERATION_CAP_ISA_TIER_MAX) return false;
    if (v->npu > 1u || v->gpu > 1u) return false;
    return true;
}

/* The host/port contract for a signed endpoint: port 0 means "not
 * advertised" and requires an empty host; a nonzero port requires a
 * printable, whitespace-free host that NUL-terminates inside the field.
 * Whitespace is refused because the durable record columns are
 * tab-separated — a host containing one would silently rewrite the
 * record's field boundaries. */
static bool fed_endpoint_valid(const qihse_federation_endpoint_t* ep) {
    if (!ep) return false;
    if (ep->port == 0u) return ep->host[0] == '\0';
    if (ep->host[0] == '\0') return false;
    for (size_t i = 0; i < QIHSE_FEDERATION_ENDPOINT_HOST_LEN; i++) {
        unsigned char c = (unsigned char)ep->host[i];
        if (c == 0u) return true;
        if (c < 0x21u || c > 0x7eu) return false;
    }
    return false; /* no NUL inside the field */
}

/* Attribution invariants shared by the writer and the reader, so a record the
 * decoder would refuse can never be written. */
static bool cap_attribution_valid(const qihse_federation_node_capability_t* c) {
    switch (c->source) {
        case QIHSE_CAP_SOURCE_LOCAL_PROBE:
            /* A local probe may precede enrollment (trust UNKNOWN), but a
             * revoked node must not keep re-writing its own profile. */
            return c->trust == QIHSE_TRUST_UNKNOWN || c->trust == QIHSE_TRUST_PENDING ||
                   c->trust == QIHSE_TRUST_APPROVED;
        case QIHSE_CAP_SOURCE_SIGNED_STATEMENT:
            /* Attributable only with the boot and session that carried it. */
            return c->trust == QIHSE_TRUST_APPROVED &&
                   !qihse_uuid_is_nil(&c->boot_id) && !qihse_uuid_is_nil(&c->session_id);
        case QIHSE_CAP_SOURCE_OPERATOR:
            return true; /* reserved: operator-attested records */
        default:
            return false;
    }
}

static bool cap_encode(const qihse_federation_node_capability_t* c, char* out, size_t cap) {
    char nid[33], bid[33], sid[33];
    uuid_hex(&c->node_id, nid);
    uuid_hex(&c->boot_id, bid);
    uuid_hex(&c->session_id, sid);
    /* v2 appends the signed dispatch endpoint (host, port) as trailing
     * columns.  A v1 record decodes with an empty endpoint — which is the
     * truth: nothing unsigned ever populated it. */
    int n = snprintf(out, cap,
                     "%u\t%s\t%s\t%s\t%llu\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%llu\t%u\t%s\t%u",
                     (unsigned)CAP_RECORD_VERSION, nid, bid, sid,
                     (unsigned long long)c->sequence,
                     (unsigned)c->values.isa_tier, (unsigned)c->values.npu,
                     (unsigned)c->values.gpu, (unsigned)c->values.free_ram_mb,
                     (unsigned)c->values.load_pct,
                     (unsigned)c->trust, (unsigned)c->source, (unsigned)c->flags,
                     (unsigned long long)c->observed.physical_ms,
                     (unsigned)c->observed.logical,
                     c->dispatch_endpoint.host,
                     (unsigned)c->dispatch_endpoint.port);
    return n > 0 && (size_t)n < cap;
}

static bool cap_decode(const char* blob, qihse_federation_node_capability_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));

    /* Every column is small (a UUID is 32 hex chars, a counter under 21
     * digits), so ONE reusable field buffer keeps this frame tiny.  There is
     * no variable-length field here; the record cannot be inflated. */
    char f[64];
    const char* p = blob;
    uint64_t v = 0;

    uint64_t record_version = 0;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &record_version) ||
        record_version == 0u || record_version > CAP_RECORD_VERSION) return false;
    p = fed_next_field(p, f, sizeof(f));
    if (!uuid_from_hex(f, &out->node_id)) return false;
    p = fed_next_field(p, f, sizeof(f));
    if (!uuid_from_hex(f, &out->boot_id)) return false;
    p = fed_next_field(p, f, sizeof(f));
    if (!uuid_from_hex(f, &out->session_id)) return false;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &out->sequence)) return false;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > QIHSE_FEDERATION_CAP_ISA_TIER_MAX) return false;
    out->values.isa_tier = (uint8_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > 1u) return false;
    out->values.npu = (uint8_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > 1u) return false;
    out->values.gpu = (uint8_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > UINT32_MAX) return false;
    out->values.free_ram_mb = (uint32_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > UINT16_MAX) return false;
    out->values.load_pct = (uint16_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > (uint64_t)QIHSE_TRUST_REVOKED) return false;
    out->trust = (qihse_trust_state_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > (uint64_t)QIHSE_CAP_SOURCE_OPERATOR) return false;
    out->source = (qihse_capability_source_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > UINT32_MAX) return false;
    out->flags = (uint32_t)v;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &out->observed.physical_ms)) return false;
    p = fed_next_field(p, f, sizeof(f));
    if (!cap_parse_u64(f, &v) || v > UINT32_MAX) return false;
    out->observed.logical = (uint32_t)v;

    if (record_version >= 2u) {
        /* The signed dispatch endpoint columns. */
        p = fed_next_field(p, f, sizeof(f));
        if (!p || strlen(f) >= QIHSE_FEDERATION_ENDPOINT_HOST_LEN) return false;
        memcpy(out->dispatch_endpoint.host, f, strlen(f) + 1u);
        p = fed_next_field(p, f, sizeof(f));
        if (!cap_parse_u64(f, &v) || v > UINT16_MAX) return false;
        out->dispatch_endpoint.port = (uint16_t)v;
        if (!fed_endpoint_valid(&out->dispatch_endpoint)) return false;
    }

    /* Length agreement: a record with trailing columns is not the record this
     * library wrote, so it is refused rather than partially read. */
    if (p != NULL && *p != '\0') return false;

    return cap_values_valid(&out->values) && cap_attribution_valid(out) &&
           fed_endpoint_valid(&out->dispatch_endpoint);
}

static bool cap_put(void* store_void, void* user_void,
                    const qihse_federation_node_capability_t* c) {
    if (!store_void || !user_void || !c) return false;
    if (qihse_uuid_is_nil(&c->node_id)) return false;
    if (c->trust > QIHSE_TRUST_REVOKED) return false;
    if (!cap_values_valid(&c->values) || !cap_attribution_valid(c)) return false;
    if (!fed_endpoint_valid(&c->dispatch_endpoint)) return false;
    char key[128];
    cap_kv_key(&c->node_id, key, sizeof(key));
    char blob[512];
    /* A silent encode failure would store an uninitialised buffer as a
     * durable record (AGENTS.md). */
    if (!cap_encode(c, blob, sizeof(blob))) return false;
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

/* Producer for a peer's profile: only ever called with a statement that
 * already passed signature, trust-state and replay verification. */
static bool cap_record_from_statement(void* store_void, void* user_void,
                                      const qihse_federation_gossip_t* stmt,
                                      qihse_trust_state_t trust) {
    qihse_federation_node_capability_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.node_id = stmt->sender_node;
    rec.boot_id = stmt->boot_id;
    rec.session_id = stmt->session_id;
    rec.sequence = stmt->sequence;
    rec.values = stmt->caps;
    /* Only a v4 statement may populate the endpoint: it is inside the signed
     * region, so it carries the statement's attribution with it.  An older
     * statement leaves the field empty. */
    if (stmt->version >= QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT &&
        fed_endpoint_valid(&stmt->dispatch_endpoint)) {
        rec.dispatch_endpoint = stmt->dispatch_endpoint;
    }
    rec.trust = trust;
    rec.source = QIHSE_CAP_SOURCE_SIGNED_STATEMENT;
    rec.flags = 0u; /* a signature is not an attestation of the hardware */
    rec.observed = stmt->hlc;
    return cap_put(store_void, user_void, &rec);
}

bool qihse_federation_node_capability_record_local(
    void* store_void, void* user_void, const qihse_uuid_t* node_id,
    const qihse_federation_capability_values_t* values) {
    if (!store_void || !user_void || !node_id || !values) return false;
    if (qihse_uuid_is_nil(node_id)) return false;
    qihse_federation_node_capability_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.node_id = *node_id;
    rec.values = *values;
    rec.source = QIHSE_CAP_SOURCE_LOCAL_PROBE;
    rec.flags = 0u;
    rec.observed.physical_ms = fed_now_ms();
    rec.observed.logical = 0u;
    /* The trust snapshot is READ from the identity record, never supplied by
     * the caller.  An unenrolled node still gets a durable record — the data
     * must survive a restart — but admissibility requires APPROVED. */
    qihse_federation_node_identity_t identity;
    rec.trust = qihse_federation_node_lookup(store_void, user_void, node_id, &identity)
                    ? identity.trust
                    : QIHSE_TRUST_UNKNOWN;
    return cap_put(store_void, user_void, &rec);
}

bool qihse_federation_node_capability_lookup(void* store_void, void* user_void,
                                             const qihse_uuid_t* node_id,
                                             qihse_federation_node_capability_t* out) {
    if (!store_void || !user_void || !node_id || !out) return false;
    char key[128];
    cap_kv_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = cap_decode(blob, out);
    free(blob);
    /* The body's node id must agree with the key. */
    if (ok && !qihse_uuid_equal(&out->node_id, node_id)) return false;
    return ok;
}

bool qihse_federation_node_capability_lookup_admissible(
    void* store_void, void* user_void, const qihse_uuid_t* node_id,
    qihse_federation_node_capability_t* out) {
    if (!qihse_federation_node_capability_lookup(store_void, user_void, node_id, out)) {
        return false;
    }
    /* The trust snapshot inside the record is attribution, not authorization:
     * re-read the identity record so a revocation that happened after
     * admission takes effect immediately. */
    qihse_federation_node_identity_t identity;
    if (!qihse_federation_node_lookup(store_void, user_void, node_id, &identity)) return false;
    return identity.trust == QIHSE_TRUST_APPROVED;
}

/* ── F5: Signed gossip / membership plane (plan §17) ───────────────────── */

/* Little-endian buffer writer. */
typedef struct { uint8_t* buf; size_t cap; size_t len; bool overflow; } le_writer_t;

static void le_u8(le_writer_t* w, uint8_t v) {
    if (w->len + 1u > w->cap) { w->overflow = true; return; }
    w->buf[w->len++] = v;
}
static void le_u16(le_writer_t* w, uint16_t v) {
    if (w->len + 2u > w->cap) { w->overflow = true; return; }
    w->buf[w->len++] = (uint8_t)(v & 0xFFu);
    w->buf[w->len++] = (uint8_t)((v >> 8) & 0xFFu);
}
static void le_u32(le_writer_t* w, uint32_t v) {
    for (int i = 0; i < 4; i++) {
        if (w->len + 1u > w->cap) { w->overflow = true; return; }
        w->buf[w->len++] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}
static void le_u64(le_writer_t* w, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        if (w->len + 1u > w->cap) { w->overflow = true; return; }
        w->buf[w->len++] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}
static void le_bytes(le_writer_t* w, const uint8_t* b, size_t n) {
    if (w->len + n > w->cap) { w->overflow = true; return; }
    memcpy(w->buf + w->len, b, n);
    w->len += n;
}

/* The signed bytes: every field except the signature itself.  The algorithm
 * and the signature length are INSIDE the signed region, so an attacker
 * cannot downgrade the algorithm by editing those two fields.
 *
 * The layout is version-dependent, and the version field is itself signed:
 * v2 is the pre-W2.4 layout, v3 appends the capability profile.  A v2 frame
 * therefore verifies against the v2 bytes it was signed over, and an attacker
 * cannot reinterpret a v2 frame as a v3 frame (the version byte is covered). */
bool qihse_federation_gossip_serialize(const qihse_federation_gossip_t* gossip,
                                       uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!gossip || !out || !out_len) return false;
    if (gossip->version < QIHSE_FEDERATION_GOSSIP_VERSION_MIN ||
        gossip->version > QIHSE_FEDERATION_GOSSIP_VERSION_MAX) {
        return false;
    }
    le_writer_t w = { out, out_cap, 0, false };
    le_u32(&w, gossip->magic);
    le_u16(&w, gossip->version);
    le_u16(&w, gossip->feature_bitmap);
    le_bytes(&w, gossip->cluster_id.bytes, QIHSE_UUID_BYTES);
    le_bytes(&w, gossip->sender_node.bytes, QIHSE_UUID_BYTES);
    le_bytes(&w, gossip->boot_id.bytes, QIHSE_UUID_BYTES);
    le_bytes(&w, gossip->session_id.bytes, QIHSE_UUID_BYTES);
    le_u64(&w, gossip->sequence);
    le_u64(&w, gossip->hlc.physical_ms);
    le_u16(&w, gossip->hlc.logical);
    le_u16(&w, 0u); /* reserved, keeps the frame 4-byte aligned */
    le_u32(&w, gossip->capability_bitmap);
    le_u32(&w, gossip->health_summary);
    if (gossip->version >= QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY) {
        le_u8(&w, gossip->caps.isa_tier);
        le_u8(&w, gossip->caps.npu);
        le_u8(&w, gossip->caps.gpu);
        le_u8(&w, 0u); /* reserved */
        le_u32(&w, gossip->caps.free_ram_mb);
        le_u16(&w, gossip->caps.load_pct);
        le_u16(&w, 0u); /* reserved */
    }
    if (gossip->version >= QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT) {
        /* The endpoint is validated before it enters the signed region:
         * a producer must not sign a claim no receiver will accept. */
        if (!fed_endpoint_valid(&gossip->dispatch_endpoint)) return false;
        le_bytes(&w, (const uint8_t*)gossip->dispatch_endpoint.host,
                 QIHSE_FEDERATION_ENDPOINT_HOST_LEN);
        le_u16(&w, gossip->dispatch_endpoint.port);
        le_u16(&w, 0u); /* reserved, keeps the region 4-byte aligned */
    }
    le_u16(&w, (uint16_t)gossip->sig_alg);
    le_u16(&w, gossip->signature_len);
    if (w.overflow) return false;
    *out_len = w.len;
    return true;
}

/* Map an EVP_PKEY to the algorithm enum, so a signer cannot mislabel a key.
 *
 * EVP_PKEY_get_base_id() and EVP_PKEY_get_id() are NOT usable here: ML-DSA
 * keys are provider-native types with no legacy NID, so they report base id 0
 * and id -1.  EVP_PKEY_is_a() is the provider-aware check and is the only
 * reliable way to identify them. */
static bool pkey_sig_alg(EVP_PKEY* pkey, qihse_sig_alg_t* out) {
    if (!pkey || !out) return false;
    for (size_t i = 0; i < sizeof(g_sig_algs) / sizeof(g_sig_algs[0]); i++) {
        if (EVP_PKEY_is_a(pkey, g_sig_algs[i].ossl_name) == 1) {
            *out = g_sig_algs[i].alg;
            return true;
        }
    }
    return false;
}

bool qihse_federation_gossip_sign(void* pkey, qihse_federation_gossip_t* gossip) {
    if (!pkey || !gossip) return false;

    /* Record the algorithm from the key itself rather than trusting a caller
     * to set it consistently with the key they pass. */
    qihse_sig_alg_t alg;
    if (!pkey_sig_alg((EVP_PKEY*)pkey, &alg)) return false;
    gossip->sig_alg = alg;
    gossip->signature_len = (uint16_t)qihse_sig_alg_signature_bytes(alg);

    /* The serialized region is ~120 bytes; the signature is appended by the
     * caller's structure, not by this buffer. */
    uint8_t frame[256];
    size_t frame_len = 0;
    if (!qihse_federation_gossip_serialize(gossip, frame, sizeof(frame), &frame_len)) return false;

    size_t sig_len = sizeof(gossip->signature);
    if (!qihse_federation_sign(pkey, frame, frame_len, gossip->signature, &sig_len)) {
        gossip->signature_len = 0;
        return false;
    }
    gossip->signature_len = (uint16_t)sig_len;
    return true;
}

bool qihse_federation_gossip_verify(const uint8_t* public_key, size_t public_key_len,
                                    const qihse_federation_gossip_t* gossip) {
    if (!public_key || !gossip) return false;

    uint8_t frame[256];
    size_t frame_len = 0;
    if (!qihse_federation_gossip_serialize(gossip, frame, sizeof(frame), &frame_len)) return false;

    return qihse_federation_verify(gossip->sig_alg, public_key, public_key_len,
                                   frame, frame_len,
                                   gossip->signature, gossip->signature_len);
}

/* ── Algorithm-agile detached signatures ──────────────────────────────── */

bool qihse_federation_pkey_sig_alg(void* pkey, qihse_sig_alg_t* out) {
    if (!pkey || !out) return false;
    return pkey_sig_alg((EVP_PKEY*)pkey, out);
}

bool qihse_federation_sign(void* pkey, const uint8_t* data, size_t data_len,
                           uint8_t* out_sig, size_t* in_out_len) {
    if (!pkey || !out_sig || !in_out_len) return false;
    if (!data && data_len > 0) return false;

    qihse_sig_alg_t alg;
    if (!pkey_sig_alg((EVP_PKEY*)pkey, &alg)) return false;
    size_t want = qihse_sig_alg_signature_bytes(alg);
    if (want == 0 || *in_out_len < want) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    size_t sig_len = want;
    bool ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, (EVP_PKEY*)pkey) == 1 &&
              EVP_DigestSign(ctx, out_sig, &sig_len, data, data_len) == 1 &&
              sig_len == want;
    EVP_MD_CTX_free(ctx);
    if (!ok) return false;
    *in_out_len = sig_len;
    return true;
}

bool qihse_federation_verify(qihse_sig_alg_t alg,
                             const uint8_t* public_key, size_t public_key_len,
                             const uint8_t* data, size_t data_len,
                             const uint8_t* signature, size_t signature_len) {
    if (!public_key || !signature) return false;
    if (!data && data_len > 0) return false;

    const sig_alg_entry_t* entry = sig_alg_lookup(alg);
    if (!entry) return false;
    /* The declared key length and signature length must match the algorithm,
     * so a truncated or padded signature is rejected before any crypto runs. */
    if (public_key_len != entry->pk_bytes) return false;
    if (signature_len != entry->sig_bytes) return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(NULL, entry->ossl_name, NULL,
                                                   public_key, public_key_len);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }
    bool ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
              EVP_DigestVerify(ctx, signature, signature_len, data, data_len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* The wire layout is: [ signed region ][ raw signature ].
 *
 * The signed region's size is DERIVED from the serializer rather than
 * hard-coded, so adding a field cannot silently desynchronise the reader from
 * the writer.  It is derived PER VERSION, because the verifier must rebuild
 * the exact bytes a frame was signed over. */
static size_t gossip_signed_region_bytes(uint16_t version) {
    if (version < QIHSE_FEDERATION_GOSSIP_VERSION_MIN ||
        version > QIHSE_FEDERATION_GOSSIP_VERSION_MAX) {
        return 0;
    }
    /* One cache slot per supported version, indexed by the version itself so
     * adding a version cannot silently alias another's size. */
    enum { GOSSIP_VERSION_SLOTS =
               QIHSE_FEDERATION_GOSSIP_VERSION_MAX - QIHSE_FEDERATION_GOSSIP_VERSION_MIN + 1u };
    static size_t cached[GOSSIP_VERSION_SLOTS];
    size_t slot = (size_t)(version - QIHSE_FEDERATION_GOSSIP_VERSION_MIN);
    if (slot >= (size_t)GOSSIP_VERSION_SLOTS) return 0;
    if (cached[slot] != 0u) return cached[slot];
    qihse_federation_gossip_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.version = version;
    uint8_t buf[256];
    size_t len = 0;
    if (!qihse_federation_gossip_serialize(&probe, buf, sizeof(buf), &len)) return 0;
    cached[slot] = len;
    return cached[slot];
}

size_t qihse_federation_gossip_wire_size_v(uint16_t version, qihse_sig_alg_t alg) {
    size_t region = gossip_signed_region_bytes(version);
    size_t sig = qihse_sig_alg_signature_bytes(alg);
    return (region && sig) ? region + sig : 0u;
}

size_t qihse_federation_gossip_wire_size(qihse_sig_alg_t alg) {
    return qihse_federation_gossip_wire_size_v(QIHSE_FEDERATION_GOSSIP_VERSION, alg);
}

bool qihse_federation_gossip_deserialize(const uint8_t* in, size_t in_len,
                                         qihse_federation_gossip_t* out) {
    if (!in || !out) return false;
    /* The version is read FIRST, because it decides the layout; an unknown
     * version is refused before any length arithmetic. */
    if (in_len < 8u) return false;
    uint32_t magic = 0;
    uint16_t version = 0;
    memcpy(&magic, in, 4);
    memcpy(&version, in + 4, 2);
    if (magic != QIHSE_FEDERATION_GOSSIP_MAGIC) return false;
    if (version < QIHSE_FEDERATION_GOSSIP_VERSION_MIN ||
        version > QIHSE_FEDERATION_GOSSIP_VERSION_MAX) {
        return false;
    }
    size_t region = gossip_signed_region_bytes(version);
    if (region == 0 || in_len < region + 1u) return false;
    memset(out, 0, sizeof(*out));

    size_t o = 0;
    memcpy(&out->magic, in + o, 4); o += 4;
    memcpy(&out->version, in + o, 2); o += 2;
    memcpy(&out->feature_bitmap, in + o, 2); o += 2;
    memcpy(out->cluster_id.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(out->sender_node.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(out->boot_id.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(out->session_id.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(&out->sequence, in + o, 8); o += 8;
    memcpy(&out->hlc.physical_ms, in + o, 8); o += 8;
    memcpy(&out->hlc.logical, in + o, 2); o += 2;
    o += 2; /* reserved */
    memcpy(&out->capability_bitmap, in + o, 4); o += 4;
    memcpy(&out->health_summary, in + o, 4); o += 4;
    if (version >= QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY) {
        out->caps.isa_tier = in[o]; o += 1;
        out->caps.npu = in[o]; o += 1;
        out->caps.gpu = in[o]; o += 1;
        o += 1; /* reserved */
        memcpy(&out->caps.free_ram_mb, in + o, 4); o += 4;
        memcpy(&out->caps.load_pct, in + o, 2); o += 2;
        o += 2; /* reserved */
        /* Range-check the claim before any crypto: a statement naming an
         * impossible capability is malformed, not merely implausible. */
        if (out->caps.isa_tier > QIHSE_FEDERATION_CAP_ISA_TIER_MAX) return false;
        if (out->caps.npu > 1u || out->caps.gpu > 1u) return false;
    }
    if (version >= QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT) {
        memcpy(out->dispatch_endpoint.host, in + o,
               QIHSE_FEDERATION_ENDPOINT_HOST_LEN); o += QIHSE_FEDERATION_ENDPOINT_HOST_LEN;
        memcpy(&out->dispatch_endpoint.port, in + o, 2); o += 2;
        o += 2; /* reserved */
        /* A malformed endpoint is a malformed frame: refuse it before the
         * verifier, never carry it into a capability record. */
        if (!fed_endpoint_valid(&out->dispatch_endpoint)) return false;
    }
    uint16_t alg_raw = 0, sig_len = 0;
    memcpy(&alg_raw, in + o, 2); o += 2;
    memcpy(&sig_len, in + o, 2); o += 2;
    /* The reader and the writer must agree on the layout, not just on the
     * fields: a mismatch here means a frame built for another version. */
    if (o != region) return false;

    /* Validate before any crypto: a frame that names an unknown algorithm, or
     * whose length fields disagree with the algorithm, is malformed. */
    if (alg_raw > (uint16_t)QIHSE_SIG_ML_DSA_87) return false;
    out->sig_alg = (qihse_sig_alg_t)alg_raw;
    if (sig_len != qihse_sig_alg_signature_bytes(out->sig_alg)) return false;
    if (in_len != region + sig_len) return false;
    out->signature_len = sig_len;
    memcpy(out->signature, in + region, sig_len);
    return true;
}

/* ── Cheap heartbeat tier ──────────────────────────────────────────────── */

bool qihse_federation_heartbeat_serialize(const qihse_federation_heartbeat_t* hb,
                                          uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!hb || !out || !out_len) return false;
    le_writer_t w = { out, out_cap, 0, false };
    le_u32(&w, hb->magic);
    le_u16(&w, hb->version);
    le_u16(&w, hb->reserved);
    le_bytes(&w, hb->sender_node.bytes, QIHSE_UUID_BYTES);
    le_bytes(&w, hb->boot_id.bytes, QIHSE_UUID_BYTES);
    le_bytes(&w, hb->session_id.bytes, QIHSE_UUID_BYTES);
    le_u64(&w, hb->sequence);
    le_u64(&w, hb->hlc.physical_ms);
    le_u16(&w, hb->hlc.logical);
    le_u16(&w, 0u);
    le_u32(&w, hb->health_summary);
    if (w.overflow) return false;
    *out_len = w.len;
    return true;
}

bool qihse_federation_heartbeat_deserialize(const uint8_t* in, size_t in_len,
                                            qihse_federation_heartbeat_t* out) {
    if (!in || !out) return false;
    /* Fixed layout: 4+2+2+16+16+16+8+8+2+2+4 = 80 bytes. */
    if (in_len != 80u) return false;
    memset(out, 0, sizeof(*out));
    size_t o = 0;
    memcpy(&out->magic, in + o, 4); o += 4;
    memcpy(&out->version, in + o, 2); o += 2;
    memcpy(&out->reserved, in + o, 2); o += 2;
    memcpy(out->sender_node.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(out->boot_id.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(out->session_id.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(&out->sequence, in + o, 8); o += 8;
    memcpy(&out->hlc.physical_ms, in + o, 8); o += 8;
    memcpy(&out->hlc.logical, in + o, 2); o += 2;
    o += 2; /* reserved */
    memcpy(&out->health_summary, in + o, 4); o += 4;
    if (out->magic != QIHSE_FEDERATION_HEARTBEAT_MAGIC) return false;
    if (out->version != QIHSE_FEDERATION_HEARTBEAT_VERSION) return false;
    return true;
}

/* The statement record: the signed frame stored under its (sender, boot) key,
 * so heartbeats can be checked against the session it minted. */
static void statement_kv_key(const qihse_uuid_t* sender, const qihse_uuid_t* boot,
                             char* out, size_t cap) {
    char s_str[QIHSE_UUID_STR_LEN + 1u], b_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(sender, s_str);
    qihse_uuid_format(boot, b_str);
    snprintf(out, cap, "fedstmt:%s:%s", s_str, b_str);
}

static bool statement_encode(const qihse_federation_gossip_t* g, char* out, size_t cap) {
    char cid[33], snd[33], boot[33], sess[33], sig_hex[QIHSE_FEDERATION_SIG_MAX_BYTES * 2u + 1u];
    uuid_hex(&g->cluster_id, cid);
    uuid_hex(&g->sender_node, snd);
    uuid_hex(&g->boot_id, boot);
    uuid_hex(&g->session_id, sess);
    bytes_to_hex(g->signature, g->signature_len, sig_hex);
    /* The version and the capability profile are TRAILING columns: a record
     * written before they existed decodes as a v2 statement with no profile,
     * so old on-disk records still load and still verify against the v2 bytes
     * they were signed over.  The cap columns are written for v3 only, so the
     * stored record matches the wire layout for its version. */
    int n;
    if (g->version >= QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT) {
        n = snprintf(out, cap,
                     "%s\t%s\t%s\t%s\t%llu\t%llu\t%u\t%u\t%u\t%u\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%s\t%u",
                     cid, snd, boot, sess,
                     (unsigned long long)g->sequence,
                     (unsigned long long)g->hlc.physical_ms,
                     (unsigned)g->capability_bitmap,
                     (unsigned)g->health_summary,
                     (unsigned)g->sig_alg,
                     (unsigned)g->signature_len,
                     sig_hex,
                     (unsigned)g->version,
                     (unsigned)g->caps.isa_tier,
                     (unsigned)g->caps.npu,
                     (unsigned)g->caps.gpu,
                     (unsigned)g->caps.free_ram_mb,
                     (unsigned)g->caps.load_pct,
                     g->dispatch_endpoint.host,
                     (unsigned)g->dispatch_endpoint.port);
    } else if (g->version >= QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY) {
        n = snprintf(out, cap,
                     "%s\t%s\t%s\t%s\t%llu\t%llu\t%u\t%u\t%u\t%u\t%s\t%u\t%u\t%u\t%u\t%u\t%u",
                     cid, snd, boot, sess,
                     (unsigned long long)g->sequence,
                     (unsigned long long)g->hlc.physical_ms,
                     (unsigned)g->capability_bitmap,
                     (unsigned)g->health_summary,
                     (unsigned)g->sig_alg,
                     (unsigned)g->signature_len,
                     sig_hex,
                     (unsigned)g->version,
                     (unsigned)g->caps.isa_tier,
                     (unsigned)g->caps.npu,
                     (unsigned)g->caps.gpu,
                     (unsigned)g->caps.free_ram_mb,
                     (unsigned)g->caps.load_pct);
    } else {
        n = snprintf(out, cap, "%s\t%s\t%s\t%s\t%llu\t%llu\t%u\t%u\t%u\t%u\t%s\t%u",
                     cid, snd, boot, sess,
                     (unsigned long long)g->sequence,
                     (unsigned long long)g->hlc.physical_ms,
                     (unsigned)g->capability_bitmap,
                     (unsigned)g->health_summary,
                     (unsigned)g->sig_alg,
                     (unsigned)g->signature_len,
                     sig_hex,
                     (unsigned)g->version);
    }
    /* A truncating encode must not be stored as if it were the record. */
    return n > 0 && (size_t)n < cap;
}

static bool statement_decode(const char* blob, qihse_federation_gossip_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));

    /* One reusable heap buffer rather than `char f[11][9256]`, which is a
     * ~102 KB stack frame — a malformed record must not cost that much, and
     * this runs on the bus thread. */
    size_t buf_cap = QIHSE_FEDERATION_SIG_MAX_BYTES * 2u + 2u;
    char* f = (char*)malloc(buf_cap);
    if (!f) return false;
    bool ok = false;
    const char* p = blob;
    size_t declared = 0, actual = 0;

    p = fed_next_field(p, f, buf_cap);
    if (!uuid_from_hex(f, &out->cluster_id)) goto done;
    p = fed_next_field(p, f, buf_cap);
    if (!uuid_from_hex(f, &out->sender_node)) goto done;
    p = fed_next_field(p, f, buf_cap);
    if (!uuid_from_hex(f, &out->boot_id)) goto done;
    p = fed_next_field(p, f, buf_cap);
    if (!uuid_from_hex(f, &out->session_id)) goto done;
    p = fed_next_field(p, f, buf_cap);
    out->sequence = (uint64_t)strtoull(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    out->hlc.physical_ms = (uint64_t)strtoull(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    out->capability_bitmap = (uint32_t)strtoul(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    out->health_summary = (uint32_t)strtoul(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    {
        uint64_t alg_raw = strtoull(f, NULL, 10);
        if (alg_raw > (uint64_t)QIHSE_SIG_ML_DSA_87) goto done;
        out->sig_alg = (qihse_sig_alg_t)alg_raw;
    }
    p = fed_next_field(p, f, buf_cap);
    declared = (size_t)strtoull(f, NULL, 10);
    p = fed_next_field(p, f, buf_cap);
    if (!hex_to_bytes(f, out->signature, QIHSE_FEDERATION_SIG_MAX_BYTES, &actual)) goto done;
    if (declared != actual) goto done;
    if (actual != qihse_sig_alg_signature_bytes(out->sig_alg)) goto done;
    out->signature_len = (uint16_t)actual;
    out->magic = QIHSE_FEDERATION_GOSSIP_MAGIC;

    /* Trailing columns: version, then (for v3) the capability profile.  A
     * record that predates them is a v2 statement. */
    out->version = QIHSE_FEDERATION_GOSSIP_VERSION_MIN;
    if (p != NULL) {
        uint64_t ver = 0;
        p = fed_next_field(p, f, buf_cap);
        if (!cap_parse_u64(f, &ver) ||
            ver < QIHSE_FEDERATION_GOSSIP_VERSION_MIN ||
            ver > QIHSE_FEDERATION_GOSSIP_VERSION_MAX) {
            goto done; /* present but invalid: not a record this library wrote */
        }
        out->version = (uint16_t)ver;
        if (out->version >= QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY) {
            uint64_t v = 0;
            p = fed_next_field(p, f, buf_cap);
            if (!cap_parse_u64(f, &v) || v > QIHSE_FEDERATION_CAP_ISA_TIER_MAX) goto done;
            out->caps.isa_tier = (uint8_t)v;
            p = fed_next_field(p, f, buf_cap);
            if (!cap_parse_u64(f, &v) || v > 1u) goto done;
            out->caps.npu = (uint8_t)v;
            p = fed_next_field(p, f, buf_cap);
            if (!cap_parse_u64(f, &v) || v > 1u) goto done;
            out->caps.gpu = (uint8_t)v;
            p = fed_next_field(p, f, buf_cap);
            if (!cap_parse_u64(f, &v) || v > UINT32_MAX) goto done;
            out->caps.free_ram_mb = (uint32_t)v;
            p = fed_next_field(p, f, buf_cap);
            if (!cap_parse_u64(f, &v) || v > UINT16_MAX) goto done;
            out->caps.load_pct = (uint16_t)v;
        }
        if (out->version >= QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT) {
            /* The endpoint host is a text column; the field buffer is the
             * reusable one and is bounded, so an oversized host fails here. */
            p = fed_next_field(p, f, buf_cap);
            if (strlen(f) >= QIHSE_FEDERATION_ENDPOINT_HOST_LEN) goto done;
            memcpy(out->dispatch_endpoint.host, f, strlen(f) + 1u);
            uint64_t v = 0;
            p = fed_next_field(p, f, buf_cap);
            if (!cap_parse_u64(f, &v) || v > UINT16_MAX) goto done;
            out->dispatch_endpoint.port = (uint16_t)v;
            /* The stored record has to satisfy the same contract the wire
             * decoder enforces. */
            if (!fed_endpoint_valid(&out->dispatch_endpoint)) goto done;
        }
        if (p != NULL && *p != '\0') goto done; /* extra columns */
    }
    ok = true;

done:
    free(f);
    return ok;
}

bool qihse_federation_membership_from_statement(const qihse_federation_gossip_t* stmt,
                                               qihse_federation_membership_t* out) {
    if (!stmt || !out) return false;
    /* A membership record is only ever derived from a well-formed statement.
     * This is the single chokepoint, which is what makes the rule auditable:
     * grep for this function and you have found every path to an authority
     * input. */
    if (stmt->magic != QIHSE_FEDERATION_GOSSIP_MAGIC) return false;
    if (stmt->version < QIHSE_FEDERATION_GOSSIP_VERSION_MIN ||
        stmt->version > QIHSE_FEDERATION_GOSSIP_VERSION_MAX) return false;
    if (stmt->signature_len != qihse_sig_alg_signature_bytes(stmt->sig_alg)) return false;
    memset(out, 0, sizeof(*out));
    out->sender_node = stmt->sender_node;
    out->boot_id = stmt->boot_id;
    out->session_id = stmt->session_id;
    out->sequence = stmt->sequence;
    out->hlc = stmt->hlc;
    out->capability_bitmap = stmt->capability_bitmap;
    out->health_summary = stmt->health_summary;
    if (stmt->version >= QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY) out->caps = stmt->caps;
    if (stmt->version >= QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT) {
        out->dispatch_endpoint = stmt->dispatch_endpoint;
    }
    out->sig_alg = stmt->sig_alg;
    return true;
}

bool qihse_federation_gossip_statement_read(void* store_void, void* user_void,
                                            const qihse_uuid_t* sender_node,
                                            const qihse_uuid_t* boot_id,
                                            qihse_federation_gossip_t* out) {
    if (!store_void || !user_void || !sender_node || !boot_id || !out) return false;
    char key[160];
    statement_kv_key(sender_node, boot_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = statement_decode(blob, out);
    free(blob);
    return ok;
}

static bool statement_store(void* store_void, void* user_void,
                            const qihse_federation_gossip_t* g) {
    char key[160];
    statement_kv_key(&g->sender_node, &g->boot_id, key, sizeof(key));
    /* The signature reaches 4627 bytes -> 9255 hex characters, plus the
     * version and capability columns. */
    size_t blob_len = QIHSE_FEDERATION_SIG_MAX_BYTES * 2u + 640u;
    char* blob = (char*)malloc(blob_len);
    if (!blob) return false;
    if (!statement_encode(g, blob, blob_len)) { free(blob); return false; }
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    free(blob);
    return ok;
}

/* Heartbeat sequence state, keyed on (sender, boot) like the replay window. */
static void hb_kv_key(const qihse_uuid_t* sender, const qihse_uuid_t* boot,
                      char* out, size_t cap) {
    char s_str[QIHSE_UUID_STR_LEN + 1u], b_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(sender, s_str);
    qihse_uuid_format(boot, b_str);
    snprintf(out, cap, "fedhb:%s:%s", s_str, b_str);
}

qihse_gossip_result_t qihse_federation_heartbeat_accept(void* store_void, void* user_void,
                                                       const qihse_federation_heartbeat_t* hb) {
    if (!store_void || !user_void || !hb) return QIHSE_GOSSIP_REJECT_MALFORMED;
    if (hb->magic != QIHSE_FEDERATION_HEARTBEAT_MAGIC) return QIHSE_GOSSIP_REJECT_MALFORMED;
    if (hb->version != QIHSE_FEDERATION_HEARTBEAT_VERSION) return QIHSE_GOSSIP_REJECT_VERSION;

    /* The sender must be an enrolled, approved node. */
    qihse_federation_node_identity_t sender;
    if (!qihse_federation_node_lookup(store_void, user_void, &hb->sender_node, &sender)) {
        return QIHSE_GOSSIP_REJECT_UNKNOWN_SENDER;
    }
    if (sender.trust != QIHSE_TRUST_APPROVED) return QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER;

    /* A heartbeat has no authority of its own: it is accepted only while it
     * matches the session minted by a valid signed statement.  Without a
     * statement on record there is nothing to match, so it is refused. */
    qihse_federation_gossip_t stmt;
    if (!qihse_federation_gossip_statement_read(store_void, user_void,
                                                &hb->sender_node, &hb->boot_id, &stmt)) {
        return QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER;
    }
    if (!qihse_uuid_equal(&stmt.session_id, &hb->session_id)) {
        return QIHSE_GOSSIP_REJECT_REPLAY; /* retired session */
    }
    /* Re-verify the statement: it may have been written before a revocation
     * or a policy change, and the record is not itself proof of validity. */
    if (!qihse_federation_gossip_verify(sender.public_key, sender.public_key_len, &stmt)) {
        return QIHSE_GOSSIP_REJECT_BAD_SIGNATURE;
    }

    /* The sequence must advance, but the sequence space is per SESSION rather
     * than per boot: a new signed statement retires the previous session
     * entirely, so its first heartbeat legitimately starts again at 1.  Replay
     * protection within a session comes from the monotonic counter, and replay
     * across sessions comes from the session id check above. */
    char key[160];
    hb_kv_key(&hb->sender_node, &hb->boot_id, key, sizeof(key));
    char* val = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                  (qihse_user_t*)user_void);
    uint64_t highest = 0;
    bool same_session = false;
    if (val) {
        char f[2][64];
        const char* q = val;
        for (size_t i = 0; i < 2u; i++) q = fed_next_field(q, f[i], sizeof(f[i]));
        qihse_uuid_t seen_session;
        if (qihse_uuid_parse(f[0], &seen_session)) {
            same_session = qihse_uuid_equal(&seen_session, &hb->session_id);
        }
        if (same_session) highest = (uint64_t)strtoull(f[1], NULL, 10);
        free(val);
    }
    if (same_session && highest != 0 && hb->sequence <= highest) {
        return QIHSE_GOSSIP_REJECT_REPLAY;
    }

    char sess_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&hb->session_id, sess_str);
    char new_val[96];
    snprintf(new_val, sizeof(new_val), "%s\t%llu", sess_str,
             (unsigned long long)hb->sequence);
    if (!qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_val, 0, 0,
                           (qihse_user_t*)user_void)) {
        return QIHSE_GOSSIP_REJECT_MALFORMED;
    }
    return QIHSE_GOSSIP_ACCEPTED;
}

const char* qihse_gossip_result_name(qihse_gossip_result_t result) {
    switch (result) {
        case QIHSE_GOSSIP_ACCEPTED:               return "accepted";
        case QIHSE_GOSSIP_REJECT_MALFORMED:       return "malformed";
        case QIHSE_GOSSIP_REJECT_VERSION:         return "version";
        case QIHSE_GOSSIP_REJECT_UNKNOWN_SENDER:  return "unknown_sender";
        case QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER:return "untrusted_sender";
        case QIHSE_GOSSIP_REJECT_BAD_SIGNATURE:   return "bad_signature";
        case QIHSE_GOSSIP_REJECT_REPLAY:          return "replay";
    }
    return "unknown";
}

static void replay_kv_key(const qihse_uuid_t* sender, const qihse_uuid_t* boot,
                          char* out, size_t cap) {
    char s_str[QIHSE_UUID_STR_LEN + 1u], b_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(sender, s_str);
    qihse_uuid_format(boot, b_str);
    snprintf(out, cap, QIHSE_FEDERATION_REPLAY_PREFIX "%s:%s", s_str, b_str);
}

bool qihse_federation_replay_state_read(void* store_void, void* user_void,
                                        const qihse_uuid_t* sender_node,
                                        const qihse_uuid_t* boot_id,
                                        qihse_federation_replay_state_t* out) {
    if (!store_void || !user_void || !sender_node || !boot_id || !out) return false;
    char key[192];
    replay_kv_key(sender_node, boot_id, key, sizeof(key));
    char* val = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    if (!val) return false;
    memset(out, 0, sizeof(*out));
    out->sender_node = *sender_node;
    out->boot_id = *boot_id;
    unsigned long long seq = 0, first = 0;
    int n = sscanf(val, "%llu\t%llu", &seq, &first);
    free(val);
    if (n < 1) return false;
    out->highest_sequence = (uint64_t)seq;
    if (n >= 2) out->first_seen_hlc_physical = (uint64_t)first;
    return true;
}

qihse_gossip_result_t qihse_federation_gossip_accept(void* store_void, void* user_void,
                                                    const qihse_federation_gossip_t* gossip) {
    if (!store_void || !user_void || !gossip) return QIHSE_GOSSIP_REJECT_MALFORMED;
    if (gossip->magic != QIHSE_FEDERATION_GOSSIP_MAGIC) return QIHSE_GOSSIP_REJECT_MALFORMED;
    if (gossip->version < QIHSE_FEDERATION_GOSSIP_VERSION_MIN ||
        gossip->version > QIHSE_FEDERATION_GOSSIP_VERSION_MAX) {
        return QIHSE_GOSSIP_REJECT_VERSION;
    }

    /* Read the previously recorded session id first, so a genuine new session
     * is distinguishable from a replayed statement. */
    qihse_uuid_t prev_session;
    memset(&prev_session, 0, sizeof(prev_session));
    qihse_federation_gossip_t prior;
    if (qihse_federation_gossip_statement_read(store_void, user_void,
                                              &gossip->sender_node, &gossip->boot_id,
                                              &prior)) {
        prev_session = prior.session_id;
    }

    /* A datagram is never trusted because of its source IP — the sender must
     * be an enrolled, approved node and the frame must carry a valid
     * signature from that node's identity key (plan §17, §18). */
    qihse_federation_node_identity_t sender;
    if (!qihse_federation_node_lookup(store_void, user_void, &gossip->sender_node, &sender)) {
        return QIHSE_GOSSIP_REJECT_UNKNOWN_SENDER;
    }
    if (sender.trust != QIHSE_TRUST_APPROVED) return QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER;
    if (!qihse_federation_gossip_verify(sender.public_key, sender.public_key_len, gossip)) {
        return QIHSE_GOSSIP_REJECT_BAD_SIGNATURE;
    }

    /* Replay window BEFORE the statement store: a replayed OLD statement
     * carries a different session id, and recording it would retire the
     * current session's heartbeats — a replay would then be a live denial,
     * not just a refused frame.  Refuse first, record second. */
    char key[192];
    replay_kv_key(&gossip->sender_node, &gossip->boot_id, key, sizeof(key));
    char* val = qihse_kv_get_user((qihse_kv_store_t*)store_void, key, (qihse_user_t*)user_void);
    uint64_t highest = 0;
    if (val) {
        unsigned long long seq = 0;
        if (sscanf(val, "%llu", &seq) >= 1) highest = (uint64_t)seq;
        free(val);
    }
    if (highest != 0 && gossip->sequence <= highest) return QIHSE_GOSSIP_REJECT_REPLAY;

    /* A new session id retires every heartbeat issued under the old one, so
     * the statement must be recorded before its heartbeats are accepted. */
    if (!qihse_uuid_equal(&gossip->session_id, &prev_session)) {
        if (!statement_store(store_void, user_void, gossip)) {
            return QIHSE_GOSSIP_REJECT_MALFORMED;
        }
    }
    (void)prev_session;

    /* W2.4 producer: the capability profile is inside the signed region, so
     * by this point it is attributable to an enrolled, APPROVED node and its
     * signature and replay window have been checked.  Persist it as the
     * node's durable capability record.  A storage failure refuses the frame
     * (matching statement_store above) rather than leaving a node looking
     * capable with no record of the claim.  A v2 frame carries no profile and
     * leaves any existing record untouched. */
    if (gossip->version >= QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY) {
        if (!cap_record_from_statement(store_void, user_void, gossip, sender.trust)) {
            return QIHSE_GOSSIP_REJECT_MALFORMED;
        }
    }

    char new_val[64];
    snprintf(new_val, sizeof(new_val), "%llu\t%llu",
             (unsigned long long)gossip->sequence,
             (unsigned long long)gossip->hlc.physical_ms);
    if (!qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_val, 0, 0,
                           (qihse_user_t*)user_void)) {
        return QIHSE_GOSSIP_REJECT_MALFORMED;
    }
    return QIHSE_GOSSIP_ACCEPTED;
}

/* ── Statement production ─────────────────────────────────────────────── */

bool qihse_federation_statement_mint(void* store_void, void* user_void,
                                     const qihse_uuid_t* cluster_id,
                                     const qihse_uuid_t* sender_node,
                                     const qihse_uuid_t* boot_id,
                                     const qihse_federation_capability_values_t* caps,
                                     const qihse_federation_endpoint_t* endpoint,
                                     void* pkey,
                                     qihse_federation_gossip_t* out) {
    if (!sender_node || !boot_id || !pkey || !out) return false;
    memset(out, 0, sizeof(*out));
    out->magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    out->version = QIHSE_FEDERATION_GOSSIP_VERSION_ENDPOINT;
    out->feature_bitmap = 0u;
    if (cluster_id) out->cluster_id = *cluster_id;
    out->sender_node = *sender_node;
    out->boot_id = *boot_id;
    if (!qihse_uuid_generate(&out->session_id)) return false;

    /* Sequence continues from the highest the store knows about: the stored
     * statement (written by accept) and the replay record (also written by
     * accept) are both consulted, so a mint after a partial write still
     * produces a sequence a receiver's window accepts. */
    uint64_t seq = 0;
    if (store_void && user_void) {
        qihse_federation_gossip_t prior;
        if (qihse_federation_gossip_statement_read(store_void, user_void,
                                                  sender_node, boot_id, &prior) &&
            prior.sequence > seq) {
            seq = prior.sequence;
        }
        qihse_federation_replay_state_t replay;
        if (qihse_federation_replay_state_read(store_void, user_void,
                                               sender_node, boot_id, &replay) &&
            replay.highest_sequence > seq) {
            seq = replay.highest_sequence;
        }
    }
    out->sequence = seq + 1u;
    out->hlc.physical_ms = fed_now_ms();
    out->hlc.logical = 0u;
    out->capability_bitmap = 0u;
    out->health_summary = 0u;
    if (caps) {
        if (!cap_values_valid(caps)) return false;
        out->caps = *caps;
    }
    if (endpoint) {
        /* A node that advertises a listener signs for it; a node with none
         * signs the empty endpoint, which is also attributable. */
        if (!fed_endpoint_valid(endpoint)) return false;
        out->dispatch_endpoint = *endpoint;
    }
    /* Sign last: nothing is emitted unsigned, and a signing failure leaves
     * the output zeroed rather than a plausible-looking frame. */
    if (!qihse_federation_gossip_sign(pkey, out)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}
