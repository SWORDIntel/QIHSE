/*
 * QIHSE operational hardening — federation stage F8.
 * See docs/plans/qihse_federation_upgrade_plan.md §23, §24, §40, §41, §43.
 */
#include "qihse_operations.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "qihse_kv_store.h"

/* ── Record encoding helpers ───────────────────────────────────────────── */

/* Tab-separated records with legitimately empty fields, so decoders walk the
 * record rather than using sscanf("%[^\t]"). */
static const char* op_next_field(const char* p, char* out, size_t cap) {
    if (!p) { if (cap) out[0] = '\0'; return NULL; }
    const char* start = p;
    while (*p && *p != '\t') p++;
    size_t len = (size_t)(p - start);
    if (len >= cap) len = cap - 1u;
    if (cap) { memcpy(out, start, len); out[len] = '\0'; }
    return (*p == '\t') ? p + 1 : NULL;
}

static pthread_mutex_t g_ops_lock = PTHREAD_MUTEX_INITIALIZER;

/* Decoders must refuse a record they could not have produced.  An enum field
 * outside its range means the bytes are corrupt (or hostile), and returning a
 * "successfully decoded" record with a nonsense state would turn a damaged
 * record into a plausible-looking lie. */
static bool enum_in_range(uint64_t v, uint32_t count) {
    return v < (uint64_t)count;
}

/* ── Schema evolution (plan §24) ──────────────────────────────────────── */

const char* qihse_schema_result_name(qihse_schema_result_t r) {
    switch (r) {
        case QIHSE_SCHEMA_OK:                          return "ok";
        case QIHSE_SCHEMA_ERR_MALFORMED:               return "malformed";
        case QIHSE_SCHEMA_ERR_READER_TOO_OLD:          return "reader_too_old";
        case QIHSE_SCHEMA_ERR_UNKNOWN_REQUIRED_FEATURE: return "unknown_required_feature";
    }
    return "unknown";
}

void qihse_schema_header_init(qihse_schema_header_t* header, uint32_t schema_id,
                              uint32_t version) {
    if (!header) return;
    memset(header, 0, sizeof(*header));
    header->schema_id = schema_id;
    header->schema_version = version;
    /* Default to the same version: an object is readable by anyone who can
     * read its writer unless the writer says otherwise deliberately. */
    header->minimum_reader_version = version;
    header->required_features = 0;
    header->optional_features = 0;
}

qihse_schema_result_t qihse_schema_check(const qihse_schema_header_t* header,
                                         const qihse_schema_reader_t* reader) {
    if (!header || !reader) return QIHSE_SCHEMA_ERR_MALFORMED;
    if (header->schema_version == 0) return QIHSE_SCHEMA_ERR_MALFORMED;

    /* A reader older than the writer's stated floor must refuse rather than
     * guess at semantics it does not know. */
    if (reader->max_schema_version < header->minimum_reader_version) {
        return QIHSE_SCHEMA_ERR_READER_TOO_OLD;
    }
    /* An unknown REQUIRED feature is a hard rejection. */
    if ((header->required_features & ~reader->known_features) != 0) {
        return QIHSE_SCHEMA_ERR_UNKNOWN_REQUIRED_FEATURE;
    }
    /* Unknown OPTIONAL features are ignored by design. */
    return QIHSE_SCHEMA_OK;
}

/* ── Migrations ────────────────────────────────────────────────────────── */

static void migration_key(uint32_t schema_id, uint32_t from_version,
                          char* out, size_t cap) {
    snprintf(out, cap, QIHSE_SCHEMA_MIGRATION_PREFIX "%u:%u", schema_id, from_version);
}

static void progress_key(uint32_t schema_id, uint32_t version,
                         char* out, size_t cap) {
    snprintf(out, cap, QIHSE_SCHEMA_PROGRESS_PREFIX "%u:%u", schema_id, version);
}

bool qihse_schema_migration_register(void* store_void, void* user_void,
                                     const qihse_schema_migration_t* migration) {
    if (!store_void || !user_void || !migration) return false;
    /* A migration must actually move forward, otherwise it is a no-op that
     * would silently mark a version as handled. */
    if (migration->to_version <= migration->from_version) return false;
    char key[192];
    migration_key(migration->schema_id, migration->from_version, key, sizeof(key));
    char blob[512];
    snprintf(blob, sizeof(blob), "%u\t%u\t%d\t%s",
             migration->schema_id, migration->to_version,
             migration->resumable ? 1 : 0, migration->description);
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_schema_migration_lookup(void* store_void, void* user_void,
                                   uint32_t schema_id, uint32_t from_version,
                                   qihse_schema_migration_t* out) {
    if (!store_void || !user_void || !out) return false;
    char key[192];
    migration_key(schema_id, from_version, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    memset(out, 0, sizeof(*out));
    char f[4][160];
    const char* p = blob;
    for (size_t i = 0; i < 4u; i++) p = op_next_field(p, f[i], sizeof(f[i]));
    free(blob);
    out->schema_id = (uint32_t)strtoul(f[0], NULL, 10);
    out->from_version = from_version;
    out->to_version = (uint32_t)strtoul(f[1], NULL, 10);
    out->resumable = strtoul(f[2], NULL, 10) != 0;
    /* description is a fixed-width field of the migration record; the record
     * width is part of its contract, so the copy is bounded explicitly rather
     * than widening the field.  Truncation at 127 chars is unchanged. */
    snprintf(out->description, sizeof(out->description), "%.*s",
             (int)(sizeof(out->description) - 1u), f[3]);
    return true;
}

bool qihse_schema_progress_set(void* store_void, void* user_void,
                               uint32_t schema_id, uint32_t version,
                               uint64_t completed_units, uint64_t total_units) {
    if (!store_void || !user_void) return false;
    if (completed_units > total_units) return false; /* never over-report */
    char key[192];
    progress_key(schema_id, version, key, sizeof(key));
    char blob[64];
    snprintf(blob, sizeof(blob), "%llu\t%llu",
             (unsigned long long)completed_units, (unsigned long long)total_units);
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_schema_progress_get(void* store_void, void* user_void,
                               uint32_t schema_id, uint32_t version,
                               uint64_t* out_completed, uint64_t* out_total) {
    if (!store_void || !user_void) return false;
    char key[192];
    progress_key(schema_id, version, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    char f[2][32];
    const char* p = blob;
    for (size_t i = 0; i < 2u; i++) p = op_next_field(p, f[i], sizeof(f[i]));
    free(blob);
    if (out_completed) *out_completed = (uint64_t)strtoull(f[0], NULL, 10);
    if (out_total) *out_total = (uint64_t)strtoull(f[1], NULL, 10);
    return true;
}

bool qihse_schema_progress_complete(void* store_void, void* user_void,
                                    uint32_t schema_id, uint32_t version) {
    uint64_t completed = 0, total = 0;
    if (!qihse_schema_progress_get(store_void, user_void, schema_id, version,
                                   &completed, &total)) return false;
    /* A zero-unit migration is not "complete": there was nothing to do, which
     * usually means the progress record was never written. */
    if (total == 0) return false;
    return completed == total;
}

/* ── Snapshots (plan §23) ─────────────────────────────────────────────── */

typedef struct { qihse_snapshot_kind_t v; const char* name; } snapshot_kind_entry_t;

static const snapshot_kind_entry_t g_snapshot_kinds[] = {
    { QIHSE_SNAPSHOT_LOCAL,       "local"       },
    { QIHSE_SNAPSHOT_COORDINATED, "coordinated" },
};

const char* qihse_snapshot_kind_name(qihse_snapshot_kind_t kind) {
    for (size_t i = 0; i < sizeof(g_snapshot_kinds) / sizeof(g_snapshot_kinds[0]); i++) {
        if (g_snapshot_kinds[i].v == kind) return g_snapshot_kinds[i].name;
    }
    return "unknown";
}

bool qihse_snapshot_kind_parse(const char* name, qihse_snapshot_kind_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_snapshot_kinds) / sizeof(g_snapshot_kinds[0]); i++) {
        if (strcasecmp(g_snapshot_kinds[i].name, name) == 0) {
            *out = g_snapshot_kinds[i].v;
            return true;
        }
    }
    return false;
}

static void snapshot_key(const qihse_uuid_t* id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(id, id_str);
    snprintf(out, cap, QIHSE_SNAPSHOT_PREFIX "%s", id_str);
}

static void uuid_hex32(const qihse_uuid_t* u, char* out) {
    const uint8_t* b = (const uint8_t*)u;
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", b[i]);
    out[32] = '\0';
}

/* The manifest body: everything the checksum covers.  Deliberately excludes
 * the checksum field itself and nothing else, so an edit to any recorded
 * value is detectable. */
static void snapshot_body(const qihse_snapshot_manifest_t* m, char* out, size_t cap) {
    char sid[33], cid[33], by[33];
    uuid_hex32(&m->snapshot_id, sid);
    uuid_hex32(&m->cluster_id, cid);
    uuid_hex32(&m->created_by, by);
    size_t off = 0;
    off += (size_t)snprintf(out + off, cap - off,
                            "%s\t%u\t%s\t%s\t%llu\t%u\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t%s\t%u",
                            sid, (unsigned)m->kind, cid, by,
                            (unsigned long long)m->created_hlc_physical,
                            m->schema.schema_id, m->schema.schema_version,
                            m->schema.minimum_reader_version,
                            (unsigned long long)m->schema.required_features,
                            (unsigned long long)m->schema.optional_features,
                            (unsigned long long)m->max_generation,
                            (unsigned long long)m->wal_continuation_offset,
                            m->encryption_key_id,
                            (unsigned)m->group_count);
    for (uint32_t i = 0; i < m->group_count && off < cap; i++) {
        off += (size_t)snprintf(out + off, cap - off, "\t%s", m->groups[i]);
    }
    if (off < cap) {
        snprintf(out + off, cap - off, "\t%llu", (unsigned long long)m->object_count);
    }
}

static bool snapshot_compute_checksum(qihse_snapshot_manifest_t* m) {
    char body[4096];
    snapshot_body(m, body, sizeof(body));
    unsigned int len = 0;
    if (!EVP_Digest(body, strlen(body), m->checksum, &len, EVP_sha384(), NULL)) return false;
    return len == 48u;
}

bool qihse_snapshot_record(void* store_void, void* user_void,
                           qihse_snapshot_manifest_t* manifest) {
    if (!store_void || !user_void || !manifest) return false;
    if (manifest->group_count > QIHSE_SNAPSHOT_MAX_GROUPS) return false;
    /* The manifest digest is computed here, so a caller cannot record a
     * manifest whose checksum disagrees with its contents. */
    if (!snapshot_compute_checksum(manifest)) return false;

    char body[4096];
    snapshot_body(manifest, body, sizeof(body));
    char ck[97];
    for (size_t i = 0; i < 48u; i++) snprintf(ck + i * 2, 3, "%02x", manifest->checksum[i]);
    ck[96] = '\0';

    char blob[8192];
    snprintf(blob, sizeof(blob), "%s\t%s", body, ck);

    char key[160];
    snapshot_key(&manifest->snapshot_id, key, sizeof(key));
    pthread_mutex_lock(&g_ops_lock);
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_ops_lock);
    return ok;
}

bool qihse_snapshot_lookup(void* store_void, void* user_void,
                           const qihse_uuid_t* snapshot_id,
                           qihse_snapshot_manifest_t* out) {
    if (!store_void || !user_void || !snapshot_id || !out) return false;
    char key[160];
    snapshot_key(snapshot_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;

    memset(out, 0, sizeof(*out));
    /* Fields: 14 body columns, then group_count group names, then the object
     * count, then the hex checksum.  The splitter preserves empty columns, so
     * the indices are stable even for a manifest with no groups. */
    char f[16 + QIHSE_SNAPSHOT_MAX_GROUPS][256];
    const char* p = blob;
    size_t nfields = 15u + QIHSE_SNAPSHOT_MAX_GROUPS + 1u;
    for (size_t i = 0; i < nfields; i++) p = op_next_field(p, f[i], sizeof(f[i]));

    if (!qihse_uuid_parse(f[0], &out->snapshot_id)) { free(blob); return false; }
    uint64_t kind_raw = strtoull(f[1], NULL, 10);
    if (!enum_in_range(kind_raw, 2u)) { free(blob); return false; }
    out->kind = (qihse_snapshot_kind_t)kind_raw;
    (void)qihse_uuid_parse(f[2], &out->cluster_id);
    (void)qihse_uuid_parse(f[3], &out->created_by);
    out->created_hlc_physical = (uint64_t)strtoull(f[4], NULL, 10);
    out->schema.schema_id = (uint32_t)strtoul(f[5], NULL, 10);
    out->schema.schema_version = (uint32_t)strtoul(f[6], NULL, 10);
    out->schema.minimum_reader_version = (uint32_t)strtoul(f[7], NULL, 10);
    out->schema.required_features = (uint64_t)strtoull(f[8], NULL, 10);
    out->schema.optional_features = (uint64_t)strtoull(f[9], NULL, 10);
    out->max_generation = (uint64_t)strtoull(f[10], NULL, 10);
    out->wal_continuation_offset = (uint64_t)strtoull(f[11], NULL, 10);
    /* Fixed-width record field; the record width is part of its contract, so
     * the copy is bounded explicitly rather than widening the field. */
    snprintf(out->encryption_key_id, sizeof(out->encryption_key_id), "%.*s",
             (int)(sizeof(out->encryption_key_id) - 1u), f[12]);
    uint32_t groups = (uint32_t)strtoul(f[13], NULL, 10);
    if (groups > QIHSE_SNAPSHOT_MAX_GROUPS) { free(blob); return false; }
    out->group_count = groups;
    for (uint32_t i = 0; i < groups; i++) {
        snprintf(out->groups[i], sizeof(out->groups[i]), "%s", f[14 + i]);
    }
    out->object_count = (uint64_t)strtoull(f[14 + groups], NULL, 10);

    /* Decode the hex checksum so a caller can compare it against a manifest
     * it holds independently. */
    const char* ck = f[15 + groups];
    for (size_t i = 0; i < 48u; i++) {
        unsigned int byte;
        if (sscanf(ck + i * 2, "%2x", &byte) != 1) break;
        out->checksum[i] = (uint8_t)byte;
    }
    free(blob);
    /* The body's snapshot id must agree with the key. */
    if (!qihse_uuid_equal(&out->snapshot_id, snapshot_id)) return false;
    return true;
}

bool qihse_snapshot_verify(void* store_void, void* user_void,
                           const qihse_uuid_t* snapshot_id) {
    if (!store_void || !user_void || !snapshot_id) return false;
    char key[160];
    snapshot_key(snapshot_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;

    /* The stored record is "<body>\t<checksum>"; recompute over the body and
     * compare, so a truncated or edited manifest is caught here. */
    char* last_tab = strrchr(blob, '\t');
    if (!last_tab) { free(blob); return false; }
    *last_tab = '\0';
    const char* stored_ck = last_tab + 1;

    unsigned char digest[48];
    unsigned int len = 0;
    bool ok = EVP_Digest(blob, strlen(blob), digest, &len, EVP_sha384(), NULL) == 1 &&
              len == 48u;
    if (ok) {
        char computed[97];
        for (size_t i = 0; i < 48u; i++) snprintf(computed + i * 2, 3, "%02x", digest[i]);
        computed[96] = '\0';
        ok = (strcmp(computed, stored_ck) == 0);
    }
    free(blob);
    return ok;
}

/* ── Reconciliation safety (plan §43) ─────────────────────────────────── */

typedef struct { qihse_rejoin_step_t v; const char* name; } rejoin_step_entry_t;

static const rejoin_step_entry_t g_rejoin_steps[] = {
    { QIHSE_REJOIN_IDLE,                    "IDLE"                    },
    { QIHSE_REJOIN_AUTHENTICATE_PEER,       "AUTHENTICATE_PEER"       },
    { QIHSE_REJOIN_COMPARE_FEDERATION_UUID, "COMPARE_FEDERATION_UUID" },
    { QIHSE_REJOIN_COMPARE_BOOT_UUID,       "COMPARE_BOOT_UUID"       },
    { QIHSE_REJOIN_EXCHANGE_HLC,            "EXCHANGE_HLC"            },
    { QIHSE_REJOIN_EXCHANGE_MANIFESTS,      "EXCHANGE_MANIFESTS"      },
    { QIHSE_REJOIN_IDENTIFY_DIVERGENCE,     "IDENTIFY_DIVERGENCE"     },
    { QIHSE_REJOIN_TRANSFER_EVENTS,         "TRANSFER_EVENTS"         },
    { QIHSE_REJOIN_APPLY_CONFLICT_POLICY,   "APPLY_CONFLICT_POLICY"   },
    { QIHSE_REJOIN_RECONSTRUCT_STATE,       "RECONSTRUCT_STATE"       },
    { QIHSE_REJOIN_VERIFY_CHECKSUMS,        "VERIFY_CHECKSUMS"        },
    { QIHSE_REJOIN_COMPLETE,                "COMPLETE"                },
    { QIHSE_REJOIN_ABORTED,                 "ABORTED"                 },
};

const char* qihse_rejoin_step_name(qihse_rejoin_step_t step) {
    for (size_t i = 0; i < sizeof(g_rejoin_steps) / sizeof(g_rejoin_steps[0]); i++) {
        if (g_rejoin_steps[i].v == step) return g_rejoin_steps[i].name;
    }
    return "UNKNOWN";
}

bool qihse_rejoin_step_parse(const char* name, qihse_rejoin_step_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_rejoin_steps) / sizeof(g_rejoin_steps[0]); i++) {
        if (strcasecmp(g_rejoin_steps[i].name, name) == 0) {
            *out = g_rejoin_steps[i].v;
            return true;
        }
    }
    return false;
}

qihse_rejoin_step_t qihse_rejoin_next_step(qihse_rejoin_step_t current) {
    switch (current) {
        case QIHSE_REJOIN_IDLE:
            return QIHSE_REJOIN_AUTHENTICATE_PEER;
        case QIHSE_REJOIN_AUTHENTICATE_PEER:
            return QIHSE_REJOIN_COMPARE_FEDERATION_UUID;
        case QIHSE_REJOIN_COMPARE_FEDERATION_UUID:
            return QIHSE_REJOIN_COMPARE_BOOT_UUID;
        case QIHSE_REJOIN_COMPARE_BOOT_UUID:
            return QIHSE_REJOIN_EXCHANGE_HLC;
        case QIHSE_REJOIN_EXCHANGE_HLC:
            return QIHSE_REJOIN_EXCHANGE_MANIFESTS;
        case QIHSE_REJOIN_EXCHANGE_MANIFESTS:
            return QIHSE_REJOIN_IDENTIFY_DIVERGENCE;
        case QIHSE_REJOIN_IDENTIFY_DIVERGENCE:
            return QIHSE_REJOIN_TRANSFER_EVENTS;
        case QIHSE_REJOIN_TRANSFER_EVENTS:
            return QIHSE_REJOIN_APPLY_CONFLICT_POLICY;
        case QIHSE_REJOIN_APPLY_CONFLICT_POLICY:
            return QIHSE_REJOIN_RECONSTRUCT_STATE;
        case QIHSE_REJOIN_RECONSTRUCT_STATE:
            return QIHSE_REJOIN_VERIFY_CHECKSUMS;
        case QIHSE_REJOIN_VERIFY_CHECKSUMS:
            return QIHSE_REJOIN_COMPLETE;
        case QIHSE_REJOIN_COMPLETE:
        case QIHSE_REJOIN_ABORTED:
        default:
            return QIHSE_REJOIN_ABORTED;
    }
}

bool qihse_rejoin_may_publish_ownership(qihse_rejoin_step_t current) {
    /* Only after the state has been reconstructed AND the range checksums
     * verified.  Publishing earlier is exactly how a rejoining node makes a
     * stale exclusive ownership claim authoritative. */
    return current == QIHSE_REJOIN_COMPLETE;
}

static void rejoin_key(const qihse_uuid_t* node_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(node_id, id_str);
    snprintf(out, cap, QIHSE_REJOIN_PREFIX "%s", id_str);
}

bool qihse_rejoin_state_put(void* store_void, void* user_void,
                            const qihse_rejoin_state_t* state) {
    if (!store_void || !user_void || !state) return false;
    char nid[33], pid[33];
    uuid_hex32(&state->node_id, nid);
    uuid_hex32(&state->peer_node, pid);
    char blob[512];
    snprintf(blob, sizeof(blob), "%s\t%s\t%u\t%llu\t%llu\t%llu\t%llu\t%s",
             nid, pid, (unsigned)state->step,
             (unsigned long long)state->started_hlc_physical,
             (unsigned long long)state->updated_hlc_physical,
             (unsigned long long)state->events_transferred,
             (unsigned long long)state->conflicts_applied,
             state->last_error);
    char key[160];
    rejoin_key(&state->node_id, key, sizeof(key));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_rejoin_state_get(void* store_void, void* user_void,
                            const qihse_uuid_t* node_id,
                            qihse_rejoin_state_t* out) {
    if (!store_void || !user_void || !node_id || !out) return false;
    char key[160];
    rejoin_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    memset(out, 0, sizeof(*out));
    char f[8][160];
    const char* p = blob;
    for (size_t i = 0; i < 8u; i++) p = op_next_field(p, f[i], sizeof(f[i]));
    free(blob);
    if (!qihse_uuid_parse(f[0], &out->node_id)) return false;
    if (!qihse_uuid_parse(f[1], &out->peer_node)) return false;
    uint64_t step_raw = strtoull(f[2], NULL, 10);
    if (!enum_in_range(step_raw, (uint32_t)QIHSE_REJOIN_ABORTED + 1u)) return false;
    out->step = (qihse_rejoin_step_t)step_raw;
    out->started_hlc_physical = (uint64_t)strtoull(f[3], NULL, 10);
    out->updated_hlc_physical = (uint64_t)strtoull(f[4], NULL, 10);
    out->events_transferred = (uint64_t)strtoull(f[5], NULL, 10);
    out->conflicts_applied = (uint64_t)strtoull(f[6], NULL, 10);
    /* Fixed-width record field; the record width is part of its contract, so
     * the copy is bounded explicitly rather than widening the field. */
    snprintf(out->last_error, sizeof(out->last_error), "%.*s",
             (int)(sizeof(out->last_error) - 1u), f[7]);
    if (!qihse_uuid_equal(&out->node_id, node_id)) return false;
    return true;
}

/* ── Observability (plan §41) ─────────────────────────────────────────── */

void qihse_federation_metrics_init(qihse_federation_metrics_t* m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
}

bool qihse_federation_metrics_render(const qihse_federation_metrics_t* m,
                                     const char* prefix,
                                     char* out, size_t out_cap) {
    if (!m || !out || out_cap == 0) return false;
    const char* p = (prefix && prefix[0]) ? prefix : "qihse";
    size_t off = 0;
    /* Label-bounded: one series per metric, no node/namespace labels. */
    struct { const char* name; uint64_t value; } rows[] = {
        { "federation_peer_state",               m->federation_peer_state_connected },
        { "replication_lag_ms",                  m->replication_lag_ms },
        { "unreplicated_bytes",                  m->unreplicated_bytes },
        { "anti_entropy_ranges_checked",         m->anti_entropy_ranges_checked },
        { "anti_entropy_bytes_repaired",         m->anti_entropy_bytes_repaired },
        { "conflict_count",                      m->conflict_count },
        { "watch_subscribers",                   m->watch_subscribers },
        { "watch_backlog",                       m->watch_backlog },
        { "lease_count",                         m->lease_count },
        { "lease_expiry_failures",               m->lease_expiry_failures },
        { "cas_failures",                        m->cas_failures },
        { "stale_epoch_rejections",              m->stale_epoch_rejections },
        { "auth_failures",                       m->auth_failures },
        { "audit_chain_status",                  m->audit_chain_status_ok },
        { "runtime_trust_state",                 m->runtime_trust_state },
        { "runtime_profile_drift",               m->runtime_profile_drift },
        { "unexpected_listener_count",           m->unexpected_listener_count },
        { "unexpected_capability_count",         m->unexpected_capability_count },
        { "provenance_verification_state",       m->provenance_verification_state },
        { "clock_sync_state",                    m->clock_sync_state },
        { "peer_clock_skew_ms",                  m->peer_clock_skew_ms },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        int n = snprintf(out + off, out_cap - off, "%s_%s %llu\n",
                         p, rows[i].name, (unsigned long long)rows[i].value);
        if (n < 0 || (size_t)n >= out_cap - off) return false;
        off += (size_t)n;
    }
    return true;
}

/* ── Performance budgets (plan §40) ───────────────────────────────────── */

void qihse_perf_budget_init(qihse_perf_budget_t* b) {
    if (!b) return;
    /* Engineering targets from the brief. */
    b->local_kv_overhead_p50_pct = 5.0;
    b->local_kv_overhead_p99_pct = 10.0;
    b->event_append_per_sec_min = 100000.0;
    b->watch_delivery_p50_ms = 10.0;
}

bool qihse_perf_evaluate(const qihse_perf_budget_t* budget,
                         const qihse_perf_measurement_t* measured,
                         qihse_perf_verdict_t* out) {
    if (!budget || !measured || !out) return false;
    memset(out, 0, sizeof(*out));

    /* A non-positive measurement means "not measured", so a partial harness
     * cannot produce a false failure. */
    if (measured->local_kv_overhead_p50_pct > 0.0 &&
        measured->local_kv_overhead_p50_pct > budget->local_kv_overhead_p50_pct) {
        snprintf(out->failures[out->failure_count++], 128,
                 "local KV p50 overhead %.2f%% exceeds budget %.2f%%",
                 measured->local_kv_overhead_p50_pct, budget->local_kv_overhead_p50_pct);
    }
    if (measured->local_kv_overhead_p99_pct > 0.0 &&
        measured->local_kv_overhead_p99_pct > budget->local_kv_overhead_p99_pct) {
        snprintf(out->failures[out->failure_count++], 128,
                 "local KV p99 overhead %.2f%% exceeds budget %.2f%%",
                 measured->local_kv_overhead_p99_pct, budget->local_kv_overhead_p99_pct);
    }
    if (measured->event_append_per_sec > 0.0 &&
        measured->event_append_per_sec < budget->event_append_per_sec_min) {
        snprintf(out->failures[out->failure_count++], 128,
                 "event append %.0f/s below budget %.0f/s",
                 measured->event_append_per_sec, budget->event_append_per_sec_min);
    }
    if (measured->watch_delivery_p50_ms > 0.0 &&
        measured->watch_delivery_p50_ms > budget->watch_delivery_p50_ms) {
        snprintf(out->failures[out->failure_count++], 128,
                 "watch delivery p50 %.2fms exceeds budget %.2fms",
                 measured->watch_delivery_p50_ms, budget->watch_delivery_p50_ms);
    }

    out->passed = (out->failure_count == 0);
    return true;
}
