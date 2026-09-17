/* QIHSE federation — stage F0 primitives.
 *
 * Identity, hybrid logical time, object generations, and fencing epochs.
 * No behaviour changes to the existing cluster: these are the vocabulary the
 * federation stages (F1+) are built from.
 * See docs/plans/qihse_federation_upgrade_plan.md §7. */
#include "qihse_federation.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
