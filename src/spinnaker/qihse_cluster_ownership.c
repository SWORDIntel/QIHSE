#include "qihse_cluster_ownership.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

/* Constructor and verifier live in the QKP/RESP transport. This opaque object
 * is only emitted after verification against the provisioned peer pin. */
extern bool qihse_resp_ct_peer_receipt_validate(
    const qihse_cluster_ct_peer_receipt_t* receipt,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t* out_target_lsn,
    unsigned char out_checksum[32]);
extern bool qihse_resp_ct_peer_receipt_query(
    qihse_resp_server_t* server, const char* transfer_id,
    const char* topology_source_id, const char* topology_target_id,
    const char* qkp_source_id, const char* qkp_target_id,
    const char* generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_lsn, uint64_t config_epoch,
    qihse_cluster_ct_peer_receipt_t** out_receipt);
extern bool qihse_resp_ct_peer_receipt_query_to(
    qihse_resp_server_t* server, uint16_t target_topology_index,
    const char* target_qkp_id, const char* transfer_id,
    const char* topology_source_id, const char* topology_target_id,
    const char* qkp_source_id, const char* qkp_target_id,
    const char* generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_lsn, uint64_t config_epoch,
    qihse_cluster_ct_peer_receipt_t** out_receipt);
extern void qihse_resp_ct_peer_receipt_free(qihse_cluster_ct_peer_receipt_t* receipt);
extern bool qihse_resp_ct_peer_prepared_receipt_query_to(
    qihse_resp_server_t* server, uint16_t source_topology_index,
    const char* source_qkp_id, const char* transfer_id,
    const char* topology_source_id, const char* topology_target_id,
    const char* qkp_source_id, const char* qkp_target_id,
    const char* generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_lsn, uint64_t config_epoch,
    const unsigned char checksum[32], qihse_cluster_ct_peer_receipt_t** out);
extern bool qihse_resp_ct_peer_aborted_receipt_query_to(
    qihse_resp_server_t* server, uint16_t source_topology_index,
    const char* source_qkp_id, const char* transfer_id,
    const char* topology_source_id, const char* topology_target_id,
    const char* qkp_source_id, const char* qkp_target_id,
    const char* generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_lsn, uint64_t config_epoch,
    const unsigned char checksum[32], qihse_cluster_ct_peer_receipt_t** out);
extern bool qihse_resp_ct_source_receipt_validate(
    const qihse_cluster_ct_peer_receipt_t* receipt, const char* phase,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, const unsigned char checksum[32]);
extern bool qihse_resp_ct_begin_request_fields(
    const qihse_resp_ct_begin_request_t*, const char**, const char**,
    const char**, const char**, const char**, const char**, uint16_t*, uint16_t*,
    uint64_t*, uint64_t*, unsigned char[32], unsigned char[32], uint64_t*);
extern bool qihse_resp_ct_abort_request_fields(
    const qihse_resp_ct_abort_request_t*, const char**, const char**,
    const char**, const char**, const char**, const char**, uint16_t*, uint16_t*,
    uint64_t*, uint64_t*, unsigned char[32]);
extern bool qihse_resp_ct_activation_receipt_validate(
    const qihse_cluster_ct_activation_receipt_t* receipt,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t* out_target_lsn,
    unsigned char out_checksum[32]);
extern void qihse_resp_ct_activation_receipt_free(
    qihse_cluster_ct_activation_receipt_t* receipt);
extern bool qihse_resp_ct_peer_activation_receipt_query_to(
    qihse_resp_server_t* server, uint16_t target_topology_index,
    const char* target_qkp_id, const char* transfer_id,
    const char* topology_source_id, const char* topology_target_id,
    const char* qkp_source_id, const char* qkp_target_id,
    const char* generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_lsn, uint64_t config_epoch, uint64_t target_lsn,
    const unsigned char checksum[32],
    qihse_cluster_ct_activation_receipt_t** out_receipt);
typedef struct { const void* data; size_t len; } qihse_resp_ct_arg_t;
typedef struct { unsigned char* data; size_t len; } qihse_resp_ct_reply_t;
extern bool qihse_resp_ct_peer_command_to(
    qihse_resp_server_t* server, uint16_t target_topology_index,
    const char* expected_qkp_node_id, const qihse_resp_ct_arg_t* args,
    size_t argc, qihse_resp_ct_reply_t* out);
extern void qihse_resp_ct_reply_free(qihse_resp_ct_reply_t* reply);
extern bool qihse_resp_ct_activation_request_fields(
    const qihse_resp_ct_activation_request_t* request,
    const char** transfer_id, const char** topology_source_id,
    const char** topology_target_id, const char** qkp_source_id,
    const char** qkp_target_id, const char** generation,
    uint16_t* first_slot, uint16_t* last_slot,
    uint64_t* source_lsn, uint64_t* config_epoch, uint64_t* target_lsn,
    unsigned char checksum[32]);
extern qihse_user_t* qihse_resp_ct_begin_request_principal(
    const qihse_resp_ct_begin_request_t* request);

static bool adopt_txn_ranges(qihse_cluster_topology_t* topology,
                             qihse_cluster_bus_t* bus,
                             const qihse_cluster_ownership_txn_t* txn,
                             uint16_t owner_index);
extern qihse_user_t* qihse_resp_ct_abort_request_principal(
    const qihse_resp_ct_abort_request_t* request);
extern qihse_user_t* qihse_resp_ct_activation_request_principal(
    const qihse_resp_ct_activation_request_t* request);

typedef struct {
    const qihse_cluster_ct_peer_receipt_t* receipt;
    const qihse_cluster_ownership_txn_t* txn;
} receipt_verify_context_t;

static bool verify_storage_receipt_claim(
    const qihse_kv_ct_target_receipt_claim_t* claim, void* opaque) {
    receipt_verify_context_t* v = opaque;
    if (!v || !v->receipt || !v->txn || !claim) return false;
    const qihse_cluster_ownership_txn_t* t = v->txn;
    uint64_t target_lsn = 0;
    uint8_t checksum[32] = {0};
    bool ok = !strcmp(claim->transfer_id, t->transfer_id) &&
        !strcmp(claim->source_id, t->source_qkp_id) &&
        !strcmp(claim->target_id, t->target_qkp_id) &&
        !strcmp(claim->generation, t->generation) &&
        claim->first_slot == t->start && claim->last_slot == t->end &&
        claim->source_cut == t->source_lsn &&
        qihse_resp_ct_peer_receipt_validate(v->receipt, t->transfer_id,
            t->source_id, t->target_id, t->source_qkp_id, t->target_qkp_id,
            t->generation, t->start, t->end, t->source_lsn,
            t->config_epoch,
            &target_lsn, checksum) && target_lsn == claim->target_durable_cursor &&
        CRYPTO_memcmp(checksum, claim->range_checksum, sizeof(checksum)) == 0;
    OPENSSL_cleanse(checksum, sizeof(checksum));
    return ok;
}

typedef struct {
    const qihse_resp_ct_activation_request_t* request;
    const qihse_cluster_ownership_txn_t* txn;
} activation_verify_context_t;

typedef struct {
    const qihse_cluster_ct_activation_receipt_t* receipt;
    const qihse_cluster_ownership_txn_t* txn;
} activation_receipt_verify_context_t;

static bool verify_activation_receipt_claim(
    const qihse_kv_ct_target_receipt_claim_t* claim, void* opaque) {
    activation_receipt_verify_context_t* v = opaque;
    if (!v || !v->receipt || !v->txn || !claim) return false;
    const qihse_cluster_ownership_txn_t* t = v->txn;
    uint64_t target_lsn = 0;
    uint8_t checksum[32] = {0};
    bool ok = !strcmp(claim->transfer_id, t->transfer_id) &&
        !strcmp(claim->source_id, t->source_qkp_id) &&
        !strcmp(claim->target_id, t->target_qkp_id) &&
        !strcmp(claim->generation, t->generation) &&
        claim->first_slot == t->start && claim->last_slot == t->end &&
        claim->source_cut == t->source_lsn &&
        qihse_resp_ct_activation_receipt_validate(v->receipt, t->transfer_id,
            t->source_id, t->target_id, t->source_qkp_id, t->target_qkp_id,
            t->generation, t->start, t->end, t->source_lsn,
            t->config_epoch,
            &target_lsn, checksum) && target_lsn == claim->target_durable_cursor &&
        CRYPTO_memcmp(checksum, claim->range_checksum, sizeof(checksum)) == 0;
    OPENSSL_cleanse(checksum, sizeof(checksum));
    return ok;
}

static bool verify_authenticated_source_commit(
    const qihse_kv_ct_target_receipt_claim_t* claim, void* opaque) {
    activation_verify_context_t* v = opaque;
    if (!v || !v->request || !v->txn || !claim) return false;
    const char *transfer = NULL, *topo_source = NULL, *topo_target = NULL;
    const char *qkp_source = NULL, *qkp_target = NULL, *generation = NULL;
    uint16_t first = 0, last = 0;
    uint64_t source_lsn = 0, config_epoch = 0, target_lsn = 0;
    uint8_t checksum[32] = {0};
    const qihse_cluster_ownership_txn_t* t = v->txn;
    bool ok = qihse_resp_ct_activation_request_fields(v->request,
        &transfer, &topo_source, &topo_target, &qkp_source, &qkp_target,
        &generation, &first, &last, &source_lsn, &config_epoch, &target_lsn, checksum) &&
        transfer && topo_source && topo_target && qkp_source && qkp_target && generation &&
        !strcmp(transfer, t->transfer_id) && !strcmp(topo_source, t->source_id) &&
        !strcmp(topo_target, t->target_id) && !strcmp(qkp_source, t->source_qkp_id) &&
        !strcmp(qkp_target, t->target_qkp_id) && !strcmp(generation, t->generation) &&
        first == t->start && last == t->end && source_lsn == t->source_lsn &&
        config_epoch == t->config_epoch &&
        target_lsn == t->target_lsn &&
        CRYPTO_memcmp(checksum, t->proof_digest, sizeof(checksum)) == 0 &&
        !strcmp(claim->transfer_id, t->transfer_id) &&
        !strcmp(claim->source_id, t->source_qkp_id) &&
        !strcmp(claim->target_id, t->target_qkp_id) &&
        !strcmp(claim->generation, t->generation) &&
        claim->first_slot == t->start && claim->last_slot == t->end &&
        claim->source_cut == t->source_lsn &&
        claim->target_durable_cursor == t->target_lsn &&
        CRYPTO_memcmp(claim->range_checksum, t->proof_digest, sizeof(t->proof_digest)) == 0;
    OPENSSL_cleanse(checksum, sizeof(checksum));
    return ok;
}

static void set_error(char* err, size_t cap, const char* message) {
    if (err && cap) snprintf(err, cap, "%s", message ? message : "ownership transfer failed");
}

static bool range_authority_hooks_valid(
    const qihse_cluster_ownership_context_t* c) {
    if (!c) return false;
    unsigned configured = (c->range_reserve != NULL) +
        (c->range_check_reserved != NULL) + (c->range_finalize != NULL) +
        (c->range_check_finalized != NULL) + (c->range_abort != NULL);
    return configured == 0 || configured == 5;
}

static bool range_check_reserved(qihse_cluster_ownership_context_t* c,
    const qihse_cluster_ownership_txn_t* txn, char* err, size_t err_cap) {
    if (!range_authority_hooks_valid(c)) {
        set_error(err, err_cap, "range authority hooks are incomplete");
        return false;
    }
    return !c->range_check_reserved || c->range_check_reserved(
        c->range_authority_context, c->principal, txn, err, err_cap);
}

static bool range_check_finalized(qihse_cluster_ownership_context_t* c,
    const qihse_cluster_ownership_txn_t* txn, char* err, size_t err_cap) {
    if (!range_authority_hooks_valid(c)) {
        set_error(err, err_cap, "range authority hooks are incomplete");
        return false;
    }
    return !c->range_check_finalized || c->range_check_finalized(
        c->range_authority_context, c->principal, txn, err, err_cap);
}

static bool ownership_system_operator_active(const qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
}

static bool resolve_qkp_id(const qihse_cluster_ownership_context_t* c,
                           const char* topology_id,
                           char out[QIHSE_KV_CT_ID_MAX + 1u]) {
    if (!c || !c->peer_id || !topology_id || !out) return false;
    memset(out, 0, QIHSE_KV_CT_ID_MAX + 1u);
    if (!c->peer_id(c->peer_id_context, topology_id, out)) return false;
    return strnlen(out, QIHSE_KV_CT_ID_MAX + 1u) > 0 &&
           strnlen(out, QIHSE_KV_CT_ID_MAX + 1u) <= QIHSE_KV_CT_ID_MAX;
}

static void ct_update_from_txn(const qihse_cluster_ownership_txn_t* txn,
                               qihse_cluster_bus_ct_slot_update_t* update) {
    memset(update, 0, sizeof(*update));
    update->magic = QIHSE_CLUSTER_BUS_CT_UPDATE_MAGIC;
    update->start = txn->start; update->end = txn->end;
    update->config_epoch = txn->config_epoch;
    update->source_lsn = txn->source_lsn; update->target_lsn = txn->target_lsn;
    snprintf(update->transfer_id, sizeof(update->transfer_id), "%s", txn->transfer_id);
    snprintf(update->source_id, sizeof(update->source_id), "%s", txn->source_id);
    snprintf(update->target_id, sizeof(update->target_id), "%s", txn->target_id);
    snprintf(update->source_qkp_id, sizeof(update->source_qkp_id), "%s", txn->source_qkp_id);
    snprintf(update->target_qkp_id, sizeof(update->target_qkp_id), "%s", txn->target_qkp_id);
    snprintf(update->generation, sizeof(update->generation), "%s", txn->generation);
    snprintf(update->owner_id, sizeof(update->owner_id), "%s", txn->target_id);
    memcpy(update->checksum, txn->proof_digest, sizeof(update->checksum));
}

static bool transfer_context(qihse_cluster_ownership_context_t* c,
                             const char* transfer_id, uint16_t source_index,
                             uint16_t target_index, uint16_t first,
                             uint16_t last, qihse_cluster_node_t* source,
                             qihse_cluster_node_t* target,
                             char source_qkp[QIHSE_KV_CT_ID_MAX + 1u],
                             char target_qkp[QIHSE_KV_CT_ID_MAX + 1u],
                             char* err, size_t err_cap) {
    if (!c || !c->topology || !c->store || !c->principal || !c->data_principal || !c->peer_id ||
        !transfer_id || !*transfer_id || strlen(transfer_id) > QIHSE_KV_CT_ID_MAX ||
        first > last || last >= QIHSE_CLUSTER_SLOT_COUNT) {
        set_error(err, err_cap, "invalid ownership transfer context or range");
        return false;
    }
    if (!qihse_cluster_topology_get_node(c->topology, source_index, source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, target) ||
        source_index == target_index || source->role != QIHSE_CLUSTER_NODE_PRIMARY ||
        target->role != QIHSE_CLUSTER_NODE_PRIMARY || !target->healthy) {
        set_error(err, err_cap, "source/target topology nodes are not a valid primary pair");
        return false;
    }
    if (qihse_cluster_topology_local_node(c->topology) != source_index) {
        set_error(err, err_cap, "only the local source may fence and transfer its range");
        return false;
    }
    if (!resolve_qkp_id(c, source->id, source_qkp) ||
        !resolve_qkp_id(c, target->id, target_qkp) ||
        !strcmp(source_qkp, target_qkp)) {
        set_error(err, err_cap, "explicit topology-to-QKP pin mapping is missing or ambiguous");
        return false;
    }
    for (uint32_t slot = first; slot <= last; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_slot_state_t state = QIHSE_CLUSTER_SLOT_STABLE;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot, &owner, &state, NULL) ||
            owner != source_index || state != QIHSE_CLUSTER_SLOT_STABLE) {
            set_error(err, err_cap, "every transferred slot must be stable and owned by the source");
            return false;
        }
    }
    return true;
}

bool qihse_cluster_ownership_transfer_prepare_ex(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    uint16_t source_index, uint16_t target_index, uint16_t first,
    uint16_t last, uint64_t* out_source_lsn, bool* out_recovery_may_be_needed,
    char* err, size_t err_cap) {
    if (out_source_lsn) *out_source_lsn = 0;
    if (out_recovery_may_be_needed) *out_recovery_may_be_needed = false;
    if (!out_source_lsn || !out_recovery_may_be_needed) {
        set_error(err, err_cap, "source cut and fence state outputs are required");
        return false;
    }
    if (!range_authority_hooks_valid(c)) {
        set_error(err, err_cap, "range authority hooks are incomplete");
        return false;
    }
    bool unresolved = false;
    if (!qihse_cluster_ownership_replay_control(c, &unresolved, err, err_cap)) {
        *out_recovery_may_be_needed = true;
        return false;
    }
    if (unresolved) {
        *out_recovery_may_be_needed = true;
        qihse_cluster_ownership_txn_t recovered;
        if (qihse_cluster_ownership_transfer_get_prepared(c, transfer_id,
                &recovered, NULL, 0)) {
            if (!range_check_reserved(c, &recovered, err, err_cap)) {
                OPENSSL_cleanse(&recovered, sizeof(recovered));
                return false;
            }
            *out_source_lsn = recovered.source_lsn;
            *out_recovery_may_be_needed = true;
            OPENSSL_cleanse(&recovered, sizeof(recovered));
            set_error(err, err_cap, "");
            return true;
        }
        if (!err || !err_cap || !err[0])
            set_error(err, err_cap, "an existing transfer intent/fence must recover before preparing another range");
        return false;
    }
    qihse_cluster_node_t source, target;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!transfer_context(c, transfer_id, source_index, target_index, first, last,
                          &source, &target, source_qkp, target_qkp, err, err_cap)) return false;
    qihse_kv_ct_source_status_t status;
    memset(&status, 0, sizeof(status));
    if (!qihse_kv_ct_source_status(c->store, c->principal, &status) ||
        strcmp(status.source_id, source_qkp) || !status.generation[0]) {
        set_error(err, err_cap, "persisted source identity/generation does not match the configured QKP pin");
        return false;
    }
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    if (!qihse_kv_ct_owner_token_get(c->store, c->principal, owner_token)) {
        set_error(err, err_cap, "principal cannot authorize the local CT owner capability");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    if (!data_dir) {
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        set_error(err, err_cap, "KV store has no durable journal directory"); return false;
    }
    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    txn.phase = QIHSE_OWNERSHIP_INTENT;
    txn.start = first; txn.end = last;
    snprintf(txn.transfer_id, sizeof(txn.transfer_id), "%s", transfer_id);
    snprintf(txn.source_id, sizeof(txn.source_id), "%s", source.id);
    snprintf(txn.target_id, sizeof(txn.target_id), "%s", target.id);
    snprintf(txn.source_qkp_id, sizeof(txn.source_qkp_id), "%s", source_qkp);
    snprintf(txn.target_qkp_id, sizeof(txn.target_qkp_id), "%s", target_qkp);
    snprintf(txn.generation, sizeof(txn.generation), "%s", status.generation);
    snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", source.id);
    txn.config_epoch = 0;
    if (c->range_reserve) {
        if (!c->range_reserve(c->range_authority_context, c->principal,
                &txn, err, err_cap)) {
            OPENSSL_cleanse(owner_token, sizeof(owner_token));
            return false;
        }
    } else {
        txn.config_epoch = qihse_cluster_topology_epoch(c->topology) + 1u;
    }
    if (txn.config_epoch == 0) {
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        set_error(err, err_cap, "topology config epoch exhausted"); return false;
    }
    bool intent_write_may_have_occurred = false;
    int intent_result = qihse_cluster_ownership_journal_append_txn_ex(
        data_dir, &txn, &intent_write_may_have_occurred);
    *out_recovery_may_be_needed = intent_write_may_have_occurred;
    if (intent_result != 0) {
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        set_error(err, err_cap, "could not persist CT2 ownership intent before fencing");
        return false;
    }
    /* The intent is now recorded. From here on, caller recovery must not
     * report a definite rejection until it verifies the source fence state. */
    *out_recovery_may_be_needed = true;
    uint64_t cut = 0;
    /* The KV operation can report failure after its durable fence transition
     * has reached storage. Preserve an unknown result from this point. */
    bool fenced = qihse_kv_ct_fence_range(c->store, c->principal, transfer_id,
        first, last, owner_token, &cut);
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    if (!fenced) {
        set_error(err, err_cap, "KV store did not persist a range fence and source cut; intent remains recoverable");
        return false;
    }
    txn.source_lsn = cut;
    txn.phase = QIHSE_OWNERSHIP_PREPARED;
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        set_error(err, err_cap, "range is fenced; replay will bind the durable fence to its intent");
        return false;
    }
    *out_source_lsn = cut;
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_transfer_prepare(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    uint16_t source_index, uint16_t target_index, uint16_t first,
    uint16_t last, uint64_t* out_source_lsn, char* err, size_t err_cap) {
    bool recovery_may_be_needed = false;
    return qihse_cluster_ownership_transfer_prepare_ex(c, transfer_id,
        source_index, target_index, first, last, out_source_lsn,
        &recovery_may_be_needed, err, err_cap);
}

typedef struct {
    bool pending;
    qihse_cluster_ownership_txn_t txn;
} pending_state_t;
static bool pending_state_cb(const qihse_cluster_ownership_txn_t* t, void* ctx) {
    pending_state_t* s = ctx;
    if (t->phase == QIHSE_OWNERSHIP_INTENT ||
        t->phase == QIHSE_OWNERSHIP_PREPARED ||
        t->phase == QIHSE_OWNERSHIP_COMMITTED) {
        s->pending = true; s->txn = *t;
    }
    else { s->pending = false; memset(&s->txn, 0, sizeof(s->txn)); }
    return true;
}
typedef struct {
    bool has_record;
    qihse_cluster_ownership_txn_t txn;
} last_txn_state_t;
static bool last_txn_state_cb(const qihse_cluster_ownership_txn_t* t, void* ctx) {
    last_txn_state_t* state = ctx;
    state->has_record = true;
    state->txn = *t;
    return true;
}

bool qihse_cluster_ownership_transfer_get_prepared(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out, char* err, size_t err_cap) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !c->store || !ownership_system_operator_active(c->principal) ||
        !transfer_id || !*transfer_id ||
        strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX || !out) {
        set_error(err, err_cap, "active system Operator and ownership outputs are required");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    pending_state_t pending = {0}; bool unresolved = false;
    int count = data_dir ? qihse_cluster_ownership_journal_replay_txn(
        data_dir, pending_state_cb, &pending, &unresolved) : -1;
    if (count < 0 || !unresolved || !pending.pending ||
        pending.txn.phase != QIHSE_OWNERSHIP_PREPARED ||
        strcmp(pending.txn.transfer_id, transfer_id)) {
        set_error(err, err_cap, "matching durable PREPARED source transaction is unavailable");
        return false;
    }
    *out = pending.txn;
    set_error(err, err_cap, "");
    return true;
}

typedef struct {
    const char* transfer_id;
    bool found;
    qihse_cluster_ownership_txn_t txn;
} find_txn_t;
static bool find_txn_cb(const qihse_cluster_ownership_txn_t* t, void* opaque) {
    find_txn_t* f = opaque;
    if (!strcmp(t->transfer_id, f->transfer_id)) {
        f->txn = *t;
        f->found = true;
    }
    return true;
}

bool qihse_cluster_ownership_transfer_get_committed(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out, char* err, size_t err_cap) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !c->store || !ownership_system_operator_active(c->principal) ||
        !transfer_id || !*transfer_id ||
        strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX || !out) {
        set_error(err, err_cap, "active system Operator and ownership outputs are required");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    find_txn_t f = {.transfer_id = transfer_id};
    bool unresolved = false;
    if (!data_dir || qihse_cluster_ownership_journal_replay_txn(
            data_dir, find_txn_cb, &f, &unresolved) < 0 || !f.found ||
        f.txn.phase != QIHSE_OWNERSHIP_COMMITTED || f.txn.next_generation[0]) {
        set_error(err, err_cap, "matching committed CT2 source transaction is unavailable");
        return false;
    }
    *out = f.txn;
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_transfer_get_finalized(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out, char* err, size_t err_cap) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !c->store || !ownership_system_operator_active(c->principal) ||
        !transfer_id || !*transfer_id ||
        strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX || !out) {
        set_error(err, err_cap, "active system Operator and valid transfer ID are required");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    find_txn_t found = {.transfer_id = transfer_id};
    bool unresolved = false;
    int count = data_dir ? qihse_cluster_ownership_journal_replay_txn(
        data_dir, find_txn_cb, &found, &unresolved) : -1;
    /* A different in-flight transfer does not invalidate this immutable
     * result. The callback keeps the latest phase for this ID, so a reused ID
     * currently PREPARED or COMMITTED is refused. */
    if (count < 0 || !found.found ||
        found.txn.phase != QIHSE_OWNERSHIP_FINALIZED ||
        found.txn.next_generation[0]) {
        set_error(err, err_cap, "matching finalized CT2 transfer is unavailable");
        return false;
    }
    *out = found.txn;
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_transfer_get_aborted(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out, char* err, size_t err_cap) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !c->store || !ownership_system_operator_active(c->principal) ||
        !transfer_id || !*transfer_id ||
        strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX || !out) {
        set_error(err, err_cap, "active system Operator and valid transfer ID are required");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    find_txn_t found = {.transfer_id = transfer_id};
    bool unresolved = false;
    int count = data_dir ? qihse_cluster_ownership_journal_replay_txn(
        data_dir, find_txn_cb, &found, &unresolved) : -1;
    if (count < 0 || !found.found || found.txn.phase != QIHSE_OWNERSHIP_ABORTED ||
        found.txn.next_generation[0] || found.txn.target_lsn != 0) {
        set_error(err, err_cap, "matching aborted CT2 transfer is unavailable");
        return false;
    }
    *out = found.txn;
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_transfer_finish_finalized(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    char* err, size_t err_cap) {
    if (!c || !c->topology || !c->store || !ownership_system_operator_active(c->principal) ||
        !transfer_id || !*transfer_id || strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX) {
        set_error(err, err_cap, "active system Operator and ownership context are required");
        errno = EACCES;
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    find_txn_t found = {.transfer_id = transfer_id};
    bool unresolved = false;
    if (!data_dir || qihse_cluster_ownership_journal_replay_txn(
            data_dir, find_txn_cb, &found, &unresolved) < 0 || !found.found ||
        found.txn.phase != QIHSE_OWNERSHIP_FINALIZED || found.txn.next_generation[0] ||
        strcmp(found.txn.owner_id, found.txn.target_id)) {
        set_error(err, err_cap, "matching durable finalized CT2 result is unavailable");
        return false;
    }

    qihse_cluster_ownership_txn_t txn = found.txn;
    if (!range_check_finalized(c, &txn, err, err_cap)) {
        OPENSSL_cleanse(&txn, sizeof(txn));
        return false;
    }
    uint16_t source_index, target_index;
    qihse_cluster_node_t source, target;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    if (!c->peer_id ||
        !qihse_cluster_topology_find_node(c->topology, txn.source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, txn.target_id, &target_index) ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        qihse_cluster_topology_local_node(c->topology) != source_index ||
        !resolve_qkp_id(c, source.id, source_qkp) ||
        !resolve_qkp_id(c, target.id, target_qkp) ||
        strcmp(source_qkp, txn.source_qkp_id) || strcmp(target_qkp, txn.target_qkp_id)) {
        set_error(err, err_cap, "finalized CT2 identities no longer match local topology/QKP pins");
        OPENSSL_cleanse(&txn, sizeof(txn));
        return false;
    }

    bool needs_apply = false;
    for (uint32_t slot = txn.start; slot <= txn.end; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot,
                &owner, NULL, NULL) ||
            !qihse_cluster_topology_get_slot_epoch(c->topology,
                (uint16_t)slot, &epoch)) {
            set_error(err, err_cap, "could not read local ownership before finalized replay");
            OPENSSL_cleanse(&txn, sizeof(txn));
            return false;
        }
        if (epoch > txn.config_epoch ||
            (epoch == txn.config_epoch && owner == target_index)) continue;
        if (epoch == txn.config_epoch ||
            (owner != source_index && owner != target_index)) {
            set_error(err, err_cap, "finalized CT2 proof conflicts with current slot ownership");
            OPENSSL_cleanse(&txn, sizeof(txn));
            return false;
        }
        needs_apply = true;
    }

    if (needs_apply && !adopt_txn_ranges(c->topology, NULL, &txn, target_index)) {
        set_error(err, err_cap, "finalized CT2 slot ownership could not be replayed");
        OPENSSL_cleanse(&txn, sizeof(txn));
        return false;
    }
    if (target.config_epoch < txn.config_epoch) {
        target.config_epoch = txn.config_epoch;
        if (!qihse_cluster_topology_upsert_node(c->topology, &target, NULL)) {
            set_error(err, err_cap, "finalized CT2 target node epoch could not be replayed");
            OPENSSL_cleanse(&txn, sizeof(txn));
            return false;
        }
    }
    if (c->bus) {
        qihse_cluster_bus_ct_slot_update_t update;
        ct_update_from_txn(&txn, &update);
        (void)qihse_cluster_bus_broadcast_ct_slot_update(c->bus, &update);
        OPENSSL_cleanse(&update, sizeof(update));
    }
    OPENSSL_cleanse(&txn, sizeof(txn));
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_source_phase_receipt(
    qihse_cluster_ownership_context_t* c, const char* phase,
    const qihse_cluster_ownership_txn_t* expected,
    unsigned char out_checksum[32], char* err, size_t err_cap) {
    if (out_checksum) memset(out_checksum, 0, 32u);
    if (!c || !c->topology || !c->store || !c->principal || !c->peer_id ||
        !phase || !expected || !out_checksum ||
        (strcmp(phase, "PREPARED") && strcmp(phase, "ABORTED")) ||
        expected->phase != (strcmp(phase, "PREPARED") == 0 ?
            QIHSE_OWNERSHIP_PREPARED : QIHSE_OWNERSHIP_ABORTED) ||
        expected->next_generation[0]) {
        set_error(err, err_cap, "valid CT2 source receipt request is required");
        return false;
    }
    uint16_t source_index = 0;
    qihse_cluster_node_t source;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!qihse_cluster_topology_find_node(c->topology, expected->source_id,
            &source_index) || qihse_cluster_topology_local_node(c->topology) != source_index ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !resolve_qkp_id(c, expected->source_id, source_qkp) ||
        !resolve_qkp_id(c, expected->target_id, target_qkp) ||
        strcmp(source_qkp, expected->source_qkp_id) ||
        strcmp(target_qkp, expected->target_qkp_id)) {
        set_error(err, err_cap, "source receipt tuple does not match local topology and configured pins");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    find_txn_t found = {.transfer_id = expected->transfer_id};
    bool unresolved = false;
    if (!data_dir || qihse_cluster_ownership_journal_replay_txn(
            data_dir, find_txn_cb, &found, &unresolved) < 0 || !found.found ||
        found.txn.phase != expected->phase || unresolved !=
            (expected->phase == QIHSE_OWNERSHIP_PREPARED) ||
        strcmp(found.txn.source_id, expected->source_id) ||
        strcmp(found.txn.target_id, expected->target_id) ||
        strcmp(found.txn.source_qkp_id, expected->source_qkp_id) ||
        strcmp(found.txn.target_qkp_id, expected->target_qkp_id) ||
        strcmp(found.txn.generation, expected->generation) ||
        found.txn.start != expected->start || found.txn.end != expected->end ||
        found.txn.source_lsn != expected->source_lsn ||
        found.txn.config_epoch != expected->config_epoch) {
        set_error(err, err_cap, "source receipt does not match a terminal local journal phase");
        return false;
    }
    if (expected->phase == QIHSE_OWNERSHIP_ABORTED) {
        qihse_kv_ct_transfer_status_t status;
        memset(&status, 0, sizeof(status));
        if (!qihse_kv_ct_transfer_status(c->store, c->principal, &status)) {
            set_error(err, err_cap, "source transfer fence status is unavailable");
            return false;
        }
        if (status.fence_state == 1u &&
            !strcmp(status.transfer_id, expected->transfer_id)) {
            unsigned char token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
            bool released = qihse_kv_ct_owner_token_get(c->store, c->principal, token) &&
                qihse_kv_ct_fence_finish(c->store, c->principal,
                    expected->transfer_id, false, token);
            OPENSSL_cleanse(token, sizeof(token));
            OPENSSL_cleanse(&status, sizeof(status));
            memset(&status, 0, sizeof(status));
            if (!released || !qihse_kv_ct_transfer_status(c->store, c->principal, &status)) {
                set_error(err, err_cap, "durable source abort fence release needs recovery");
                return false;
            }
        }
        bool released = status.fence_state == 0u && status.transfer_id[0] == '\0';
        OPENSSL_cleanse(&status, sizeof(status));
        if (!released) {
            set_error(err, err_cap, "source transfer fence is not durably released for ABORTED receipt");
            return false;
        }
        set_error(err, err_cap, "");
        return true;
    }
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_source_transfer_proof_create(
        c->store, c->principal, c->data_principal, expected->transfer_id, expected->source_qkp_id,
        expected->target_qkp_id, expected->generation, expected->start,
        expected->end, expected->source_lsn);
    if (!proof) {
        set_error(err, err_cap, "source PREPARED storage fence has no valid range proof");
        return false;
    }
    const char *transfer_id = NULL, *source_id = NULL, *target_id = NULL, *generation = NULL;
    uint16_t first = 0, last = 0;
    uint64_t source_lsn = 0, target_lsn = 0;
    bool ok = qihse_kv_ct_proof_validate(c->store, c->principal, c->data_principal, proof) &&
        qihse_kv_ct_proof_fields(c->store, c->principal, c->data_principal, proof,
            &transfer_id, &source_id, &target_id, &generation, &first, &last,
            &source_lsn, &target_lsn, out_checksum) &&
        transfer_id && source_id && target_id && generation &&
        !strcmp(transfer_id, expected->transfer_id) &&
        !strcmp(source_id, expected->source_qkp_id) &&
        !strcmp(target_id, expected->target_qkp_id) &&
        !strcmp(generation, expected->generation) && first == expected->start &&
        last == expected->end && source_lsn == expected->source_lsn && target_lsn == 0;
    qihse_kv_ct_proof_destroy(proof);
    if (!ok) {
        OPENSSL_cleanse(out_checksum, 32u);
        set_error(err, err_cap, "source PREPARED range proof does not match the journal tuple");
        return false;
    }
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_activate_target(
    qihse_cluster_ownership_context_t* c,
    const qihse_resp_ct_activation_request_t* request,
    char* err, size_t err_cap) {
    if (!c || !c->topology || !c->store || !c->principal || !c->data_principal || !request) {
        set_error(err, err_cap, "authenticated target context and source activation request are required");
        return false;
    }
    qihse_user_t* request_data_principal =
        qihse_resp_ct_activation_request_principal(request);
    if (!request_data_principal || !qihse_auth_user_is_active(request_data_principal) ||
        qihse_user_get_id(request_data_principal) != qihse_user_get_id(c->data_principal)) {
        set_error(err, err_cap, "ACTIVATE data principal does not match the configured replication identity");
        return false;
    }
    const char *transfer = NULL, *topo_source = NULL, *topo_target = NULL;
    const char *qkp_source = NULL, *qkp_target = NULL, *generation = NULL;
    uint16_t first = 0, last = 0;
    uint64_t source_lsn = 0, config_epoch = 0, target_lsn = 0;
    uint8_t checksum[32] = {0};
    if (!qihse_resp_ct_activation_request_fields(request, &transfer, &topo_source,
            &topo_target, &qkp_source, &qkp_target, &generation, &first, &last,
            &source_lsn, &config_epoch, &target_lsn, checksum) || !transfer || !topo_source ||
        !topo_target || !qkp_source || !qkp_target || !generation ||
        first > last || last >= QIHSE_CLUSTER_SLOT_COUNT) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "source ACTIVATE request is malformed or not authenticated");
        return false;
    }
    uint16_t source_index, target_index;
    qihse_cluster_node_t source, target;
    char source_pin[QIHSE_KV_CT_ID_MAX + 1u], target_pin[QIHSE_KV_CT_ID_MAX + 1u];
    if (!qihse_cluster_topology_find_node(c->topology, topo_source, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, topo_target, &target_index) ||
        qihse_cluster_topology_local_node(c->topology) != target_index ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        !resolve_qkp_id(c, source.id, source_pin) || !resolve_qkp_id(c, target.id, target_pin) ||
        strcmp(source_pin, qkp_source) || strcmp(target_pin, qkp_target)) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "ACTIVATE peer identities do not match the trusted pin map/local target");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    pending_state_t pending = {0}; bool unresolved = false;
    int replayed = data_dir ? qihse_cluster_ownership_journal_replay_txn(
        data_dir, pending_state_cb, &pending, &unresolved) : -1;
    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    if (replayed < 0) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "target ownership journal cannot be read safely");
        return false;
    }
    if (unresolved && pending.pending &&
        (pending.txn.phase == QIHSE_OWNERSHIP_PREPARED ||
         pending.txn.phase == QIHSE_OWNERSHIP_COMMITTED)) {
        txn = pending.txn;
    } else if (!unresolved) {
        find_txn_t found = {.transfer_id = transfer};
        if (qihse_cluster_ownership_journal_replay_txn(
                data_dir, find_txn_cb, &found, &unresolved) < 0 || unresolved ||
            !found.found || found.txn.phase != QIHSE_OWNERSHIP_FINALIZED) {
            OPENSSL_cleanse(checksum, sizeof(checksum));
            set_error(err, err_cap, "target activation has no matching pending or finalized journal record");
            return false;
        }
        txn = found.txn;
    } else {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "a different unresolved ownership transition blocks target activation");
        return false;
    }
    if (strcmp(txn.transfer_id, transfer) ||
        strcmp(txn.source_id, topo_source) || strcmp(txn.target_id, topo_target) ||
        strcmp(txn.source_qkp_id, qkp_source) || strcmp(txn.target_qkp_id, qkp_target) ||
        strcmp(txn.generation, generation) || txn.start != first || txn.end != last ||
        txn.source_lsn != source_lsn || txn.config_epoch != config_epoch ||
        txn.config_epoch == 0 || txn.next_generation[0] ||
        (txn.phase == QIHSE_OWNERSHIP_COMMITTED &&
         (txn.target_lsn != target_lsn ||
          CRYPTO_memcmp(txn.proof_digest, checksum, sizeof(checksum)) != 0)) ||
        (txn.phase == QIHSE_OWNERSHIP_FINALIZED &&
         (txn.target_lsn != target_lsn ||
          CRYPTO_memcmp(txn.proof_digest, checksum, sizeof(checksum)) != 0))) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "activation request differs from the durable target ownership phase");
        return false;
    }
    if (txn.phase == QIHSE_OWNERSHIP_FINALIZED) {
        if (!range_check_finalized(c, &txn, err, err_cap)) {
            OPENSSL_cleanse(checksum, sizeof(checksum));
            return false;
        }
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "");
        return true;
    }
    if (!range_check_reserved(c, &txn, err, err_cap)) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        return false;
    }
    qihse_kv_ct_proof_t* seal = qihse_kv_ct_target_seal_create(c->store,
        c->principal, request_data_principal, txn.transfer_id, txn.source_qkp_id, txn.target_qkp_id,
        txn.generation, txn.start, txn.end, txn.source_lsn);
    const char *proof_transfer = NULL, *proof_source = NULL, *proof_target = NULL, *proof_generation = NULL;
    uint16_t proof_first = 0, proof_last = 0;
    uint64_t proof_source_lsn = 0, proof_target_lsn = 0;
    uint8_t proof_checksum[32] = {0};
    bool seal_ok = txn.phase == QIHSE_OWNERSHIP_COMMITTED && !seal;
    seal_ok = seal_ok || (seal && qihse_kv_ct_proof_validate(c->store, c->principal, request_data_principal, seal) &&
        qihse_kv_ct_proof_fields(c->store, c->principal, request_data_principal, seal,
            &proof_transfer, &proof_source, &proof_target, &proof_generation,
            &proof_first, &proof_last, &proof_source_lsn, &proof_target_lsn,
            proof_checksum) && proof_transfer && proof_source && proof_target && proof_generation &&
        !strcmp(proof_transfer, txn.transfer_id) && !strcmp(proof_source, txn.source_qkp_id) &&
        !strcmp(proof_target, txn.target_qkp_id) && !strcmp(proof_generation, txn.generation) &&
        proof_first == txn.start && proof_last == txn.end && proof_source_lsn == txn.source_lsn &&
        proof_target_lsn == target_lsn &&
        CRYPTO_memcmp(proof_checksum, checksum, sizeof(checksum)) == 0);
    OPENSSL_cleanse(checksum, sizeof(checksum));
    if (!seal_ok) {
        OPENSSL_cleanse(proof_checksum, sizeof(proof_checksum));
        qihse_kv_ct_proof_destroy(seal);
        set_error(err, err_cap, "target's durable range seal does not match source ACTIVATE proof");
        return false;
    }
    if (txn.phase == QIHSE_OWNERSHIP_PREPARED) {
        txn.phase = QIHSE_OWNERSHIP_COMMITTED;
        txn.target_lsn = target_lsn;
        snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", txn.target_id);
        /* The request has already passed exact source-QKP session authentication
         * in the RESP engine. Persist that authenticated claim before KV release. */
        memcpy(txn.proof_digest, proof_checksum, sizeof(txn.proof_digest));
    }
    OPENSSL_cleanse(proof_checksum, sizeof(proof_checksum));
    if (pending.txn.phase == QIHSE_OWNERSHIP_PREPARED &&
        qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        qihse_kv_ct_proof_destroy(seal);
        set_error(err, err_cap, "target COMMITTED activation journal could not be persisted");
        return false;
    }
    uint8_t token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    qihse_kv_ct_target_receipt_claim_t claim;
    memset(&claim, 0, sizeof(claim));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "%s", txn.transfer_id);
    snprintf(claim.source_id, sizeof(claim.source_id), "%s", txn.source_qkp_id);
    snprintf(claim.target_id, sizeof(claim.target_id), "%s", txn.target_qkp_id);
    snprintf(claim.generation, sizeof(claim.generation), "%s", txn.generation);
    claim.first_slot = txn.start; claim.last_slot = txn.end;
    claim.source_cut = txn.source_lsn; claim.target_durable_cursor = txn.target_lsn;
    memcpy(claim.range_checksum, txn.proof_digest, sizeof(claim.range_checksum));
    activation_verify_context_t verify = {.request = request, .txn = &txn};
    bool activated = qihse_kv_ct_owner_token_get(c->store, c->principal, token) &&
        qihse_kv_ct_target_activate(c->store, c->principal, seal, &claim,
            verify_authenticated_source_commit, &verify, token);
    OPENSSL_cleanse(token, sizeof(token));
    OPENSSL_cleanse(&claim, sizeof(claim));
    qihse_kv_ct_proof_destroy(seal);
    if (!activated) {
        set_error(err, err_cap, "target COMMITTED record is durable but proof-consuming activation needs recovery");
        return false;
    }
    if (c->range_finalize) {
        /* ACTIVATE makes the target's data durable and query-ready for the
         * exact receipt. The source then commits quorum FINALIZE; routing
         * ownership is adopted only from that proof-bearing CT update. */
        set_error(err, err_cap, "");
        return true;
    }
    txn.phase = QIHSE_OWNERSHIP_FINALIZED;
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        set_error(err, err_cap, "target is active but FINALIZED replay evidence could not be persisted");
        return false;
    }
    if (target.config_epoch < txn.config_epoch) target.config_epoch = txn.config_epoch;
    if (!adopt_txn_ranges(c->topology, NULL, &txn, target_index) ||
        !qihse_cluster_topology_upsert_node(c->topology, &target, NULL)) {
        set_error(err, err_cap, "target is active and committed; local topology activation needs replay");
        return false;
    }
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_ct_activation_handler(
    void* opaque, const qihse_resp_ct_activation_request_t* request,
    char* err, size_t err_cap) {
    return qihse_cluster_ownership_activate_target(
        (qihse_cluster_ownership_context_t*)opaque, request, err, err_cap);
}

typedef struct {
    qihse_cluster_ct_peer_receipt_t* receipt;
    const char* phase;
    const char* topology_source_id;
    const char* topology_target_id;
    uint64_t config_epoch;
} target_phase_receipt_context_t;

static bool verify_target_phase_receipt(
    const qihse_kv_ct_target_receipt_claim_t* claim, void* opaque) {
    target_phase_receipt_context_t* context = opaque;
    return claim && context && context->receipt &&
        qihse_resp_ct_source_receipt_validate(context->receipt,
            context->phase, claim->transfer_id, context->topology_source_id,
            context->topology_target_id, claim->source_id, claim->target_id,
            claim->generation, claim->first_slot, claim->last_slot,
            claim->source_cut, context->config_epoch,
            strcmp(context->phase, "ABORTED") == 0 ? NULL : claim->range_checksum);
}

static bool target_request_topology(
    qihse_cluster_ownership_context_t* c,
    const char* topology_source_id, const char* topology_target_id,
    const char* source_qkp_id, const char* target_qkp_id,
    uint16_t first_slot, uint16_t last_slot,
    uint16_t* out_source_index, uint16_t* out_target_index,
    qihse_cluster_node_t* out_source, qihse_cluster_node_t* out_target,
    char* err, size_t err_cap) {
    uint16_t si = 0, ti = 0;
    qihse_cluster_node_t source, target;
    char expected_source[QIHSE_KV_CT_ID_MAX + 1u];
    char expected_target[QIHSE_KV_CT_ID_MAX + 1u];
    if (!c || !c->topology || !c->peer_id ||
        !qihse_cluster_topology_find_node(c->topology, topology_source_id, &si) ||
        !qihse_cluster_topology_find_node(c->topology, topology_target_id, &ti) ||
        !qihse_cluster_topology_get_node(c->topology, si, &source) ||
        !qihse_cluster_topology_get_node(c->topology, ti, &target) ||
        qihse_cluster_topology_local_node(c->topology) != ti ||
        source.role != QIHSE_CLUSTER_NODE_PRIMARY ||
        target.role != QIHSE_CLUSTER_NODE_PRIMARY || !source.healthy || !target.healthy ||
        !resolve_qkp_id(c, source.id, expected_source) ||
        !resolve_qkp_id(c, target.id, expected_target) ||
        strcmp(expected_source, source_qkp_id) || strcmp(expected_target, target_qkp_id)) {
        set_error(err, err_cap, "CT2 target tuple is not the configured local topology and QKP pin pair");
        return false;
    }
    for (uint32_t slot = first_slot; slot <= last_slot; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_slot_state_t state = QIHSE_CLUSTER_SLOT_STABLE;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot,
                &owner, &state, NULL) || owner != si || state != QIHSE_CLUSTER_SLOT_STABLE) {
            set_error(err, err_cap, "CT2 ownership tuple does not match stable source ownership");
            return false;
        }
    }
    *out_source_index = si; *out_target_index = ti;
    if (out_source) *out_source = source;
    if (out_target) *out_target = target;
    return true;
}

static void target_txn_from_tuple(qihse_cluster_ownership_txn_t* txn,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* source_qkp_id,
    const char* target_qkp_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch) {
    memset(txn, 0, sizeof(*txn));
    txn->phase = QIHSE_OWNERSHIP_PREPARED;
    txn->start = first_slot; txn->end = last_slot;
    snprintf(txn->transfer_id, sizeof(txn->transfer_id), "%s", transfer_id);
    snprintf(txn->source_id, sizeof(txn->source_id), "%s", topology_source_id);
    snprintf(txn->target_id, sizeof(txn->target_id), "%s", topology_target_id);
    snprintf(txn->source_qkp_id, sizeof(txn->source_qkp_id), "%s", source_qkp_id);
    snprintf(txn->target_qkp_id, sizeof(txn->target_qkp_id), "%s", target_qkp_id);
    snprintf(txn->generation, sizeof(txn->generation), "%s", generation);
    snprintf(txn->owner_id, sizeof(txn->owner_id), "%s", topology_source_id);
    txn->source_lsn = source_lsn;
    txn->config_epoch = config_epoch;
}

bool qihse_cluster_ownership_target_prepare(
    qihse_cluster_ownership_context_t* c,
    const qihse_cluster_ownership_txn_t* txn, uint64_t* out_target_cut,
    char* err, size_t err_cap) {
    (void)c; (void)txn;
    if (out_target_cut) *out_target_cut = 0;
    set_error(err, err_cap, "raw CT2 PREPARED descriptors are not proof of a durable source fence");
    errno = EACCES;
    return false;
}

bool qihse_cluster_ownership_prepare_target_handler(
    void* opaque, const qihse_resp_ct_begin_request_t* request,
    uint64_t* out_target_cut, char* err, size_t err_cap) {
    qihse_cluster_ownership_context_t* c = opaque;
    const char *transfer_id = NULL, *topology_source_id = NULL, *topology_target_id = NULL;
    const char *source_qkp_id = NULL, *target_qkp_id = NULL, *generation = NULL;
    uint16_t first_slot = 0, last_slot = 0, source_index = 0, target_index = 0;
    uint64_t source_lsn = 0, config_epoch = 0, total_bytes = 0;
    unsigned char range_checksum[32] = {0}, image_sha256[32] = {0};
    if (out_target_cut) *out_target_cut = 0;
    if (!c || !request || !out_target_cut || !c->resp_server || !c->store ||
        !c->principal || !qihse_resp_ct_begin_request_fields(request,
            &transfer_id, &topology_source_id, &topology_target_id,
            &source_qkp_id, &target_qkp_id, &generation, &first_slot,
            &last_slot, &source_lsn, &config_epoch, range_checksum,
            image_sha256, &total_bytes) || !transfer_id || !topology_source_id ||
        !topology_target_id || !source_qkp_id || !target_qkp_id || !generation ||
        !source_lsn || !config_epoch || !total_bytes || first_slot > last_slot ||
        last_slot >= QIHSE_CLUSTER_SLOT_COUNT || total_bytes > INT64_MAX) {
        set_error(err, err_cap, "authenticated CT2 BEGIN request is malformed");
        goto done;
    }
    qihse_user_t* request_data_principal = qihse_resp_ct_begin_request_principal(request);
    if (!c->data_principal || !request_data_principal ||
        !qihse_auth_user_is_active(request_data_principal) ||
        qihse_user_get_id(request_data_principal) != qihse_user_get_id(c->data_principal)) {
        set_error(err, err_cap, "BEGIN data principal does not match the configured replication identity");
        goto done;
    }
    unsigned char image_digest_or = 0;
    for (size_t i = 0; i < sizeof(image_sha256); ++i) image_digest_or |= image_sha256[i];
    if (!image_digest_or) {
        set_error(err, err_cap, "authenticated CT2 image checksum is empty");
        goto done;
    }
    if (!target_request_topology(c, topology_source_id, topology_target_id,
            source_qkp_id, target_qkp_id, first_slot, last_slot,
            &source_index, &target_index, NULL, NULL, err, err_cap)) goto done;

    qihse_cluster_ct_peer_receipt_t* receipt = NULL;
    if (!qihse_resp_ct_peer_prepared_receipt_query_to(c->resp_server,
            source_index, source_qkp_id, transfer_id, topology_source_id,
            topology_target_id, source_qkp_id, target_qkp_id, generation,
            first_slot, last_slot, source_lsn, config_epoch,
            range_checksum, &receipt) || !receipt) {
        set_error(err, err_cap, "source did not prove a matching durable PREPARED fence");
        qihse_resp_ct_peer_receipt_free(receipt);
        goto done;
    }
    qihse_kv_ct_target_receipt_claim_t claim;
    memset(&claim, 0, sizeof(claim));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "%s", transfer_id);
    snprintf(claim.source_id, sizeof(claim.source_id), "%s", source_qkp_id);
    snprintf(claim.target_id, sizeof(claim.target_id), "%s", target_qkp_id);
    snprintf(claim.generation, sizeof(claim.generation), "%s", generation);
    claim.first_slot = first_slot; claim.last_slot = last_slot;
    claim.source_cut = source_lsn;
    memcpy(claim.range_checksum, range_checksum, sizeof(range_checksum));
    target_phase_receipt_context_t verify = {
        .receipt = receipt, .phase = "PREPARED",
        .topology_source_id = topology_source_id,
        .topology_target_id = topology_target_id,
        .config_epoch = config_epoch
    };
    qihse_cluster_ownership_txn_t txn;
    target_txn_from_tuple(&txn, transfer_id, topology_source_id,
        topology_target_id, source_qkp_id, target_qkp_id, generation,
        first_slot, last_slot, source_lsn, config_epoch);
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    pending_state_t pending = {0}; bool unresolved = false;
    int replayed = data_dir ? qihse_cluster_ownership_journal_replay_txn(
        data_dir, pending_state_cb, &pending, &unresolved) : -1;
    bool tuple_matches = replayed >= 0 && unresolved && pending.pending &&
          (pending.txn.phase == QIHSE_OWNERSHIP_INTENT ||
           pending.txn.phase == QIHSE_OWNERSHIP_PREPARED) &&
          !strcmp(pending.txn.transfer_id, transfer_id) &&
          !strcmp(pending.txn.source_id, topology_source_id) &&
          !strcmp(pending.txn.target_id, topology_target_id) &&
          !strcmp(pending.txn.source_qkp_id, source_qkp_id) &&
          !strcmp(pending.txn.target_qkp_id, target_qkp_id) &&
          !strcmp(pending.txn.generation, generation) &&
          pending.txn.start == first_slot && pending.txn.end == last_slot &&
          pending.txn.source_lsn == source_lsn &&
          pending.txn.config_epoch == config_epoch;
    if (replayed < 0 || (unresolved && !tuple_matches)) {
        qihse_resp_ct_peer_receipt_free(receipt);
        OPENSSL_cleanse(&claim, sizeof(claim));
        set_error(err, err_cap, "a different target ownership transaction blocks this CT2 BEGIN");
        goto done;
    }
    if (!range_check_reserved(c, &txn, err, err_cap)) {
        qihse_resp_ct_peer_receipt_free(receipt);
        OPENSSL_cleanse(&claim, sizeof(claim));
        goto done;
    }
    bool intent_written = false;
    if (!unresolved) {
        txn.phase = QIHSE_OWNERSHIP_INTENT;
        if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
            qihse_resp_ct_peer_receipt_free(receipt);
            OPENSSL_cleanse(&claim, sizeof(claim));
            set_error(err, err_cap, "could not persist target CT2 intent before fencing");
            goto done;
        }
        intent_written = true;
    }

    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    uint64_t target_cut = 0;
    bool ok = qihse_kv_ct_owner_token_get(c->store, c->principal, owner_token) &&
        qihse_kv_ct_target_prepare(c->store, c->principal, &claim,
            verify_target_phase_receipt, &verify, owner_token, &target_cut);
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    qihse_resp_ct_peer_receipt_free(receipt);
    OPENSSL_cleanse(&claim, sizeof(claim));
    if (!ok) {
        set_error(err, err_cap, "target storage rejected the source PREPARED proof or durable fence; intent remains recoverable");
        goto done;
    }
    if (intent_written || (unresolved && pending.txn.phase == QIHSE_OWNERSHIP_INTENT)) {
        txn.phase = QIHSE_OWNERSHIP_PREPARED;
        if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
            set_error(err, err_cap, "target is fenced; replay will bind the durable fence to its intent");
            goto done;
        }
    }
    *out_target_cut = target_cut;
    set_error(err, err_cap, "");
    OPENSSL_cleanse(&txn, sizeof(txn));
    OPENSSL_cleanse(range_checksum, sizeof(range_checksum));
    OPENSSL_cleanse(image_sha256, sizeof(image_sha256));
    return true;
done:
    OPENSSL_cleanse(range_checksum, sizeof(range_checksum));
    OPENSSL_cleanse(image_sha256, sizeof(image_sha256));
    return false;
}

bool qihse_cluster_ownership_abort_target_handler(
    void* opaque, const qihse_resp_ct_abort_request_t* request,
    char* err, size_t err_cap) {
    qihse_cluster_ownership_context_t* c = opaque;
    const char *transfer_id = NULL, *topology_source_id = NULL, *topology_target_id = NULL;
    const char *source_qkp_id = NULL, *target_qkp_id = NULL, *generation = NULL;
    uint16_t first_slot = 0, last_slot = 0, source_index = 0, target_index = 0;
    uint64_t source_lsn = 0, config_epoch = 0;
    unsigned char checksum[32] = {0};
    if (!c || !request || !c->resp_server || !c->store || !c->principal ||
        !qihse_resp_ct_abort_request_fields(request, &transfer_id,
            &topology_source_id, &topology_target_id, &source_qkp_id,
            &target_qkp_id, &generation, &first_slot, &last_slot,
            &source_lsn, &config_epoch, checksum) || !transfer_id ||
        !topology_source_id || !topology_target_id || !source_qkp_id ||
        !target_qkp_id || !generation || !source_lsn || !config_epoch ||
        first_slot > last_slot || last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !target_request_topology(c, topology_source_id, topology_target_id,
            source_qkp_id, target_qkp_id, first_slot, last_slot,
            &source_index, &target_index, NULL, NULL, err, err_cap)) {
        if (!err || !err_cap || !err[0]) set_error(err, err_cap, "authenticated CT2 ABORT request is malformed");
        OPENSSL_cleanse(checksum, sizeof(checksum));
        return false;
    }
    qihse_user_t* request_data_principal = qihse_resp_ct_abort_request_principal(request);
    if (!c->data_principal || !request_data_principal ||
        !qihse_auth_user_is_active(request_data_principal) ||
        qihse_user_get_id(request_data_principal) != qihse_user_get_id(c->data_principal)) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "ABORT data principal does not match the configured replication identity");
        return false;
    }
    qihse_cluster_ct_peer_receipt_t* receipt = NULL;
    if (!qihse_resp_ct_peer_aborted_receipt_query_to(c->resp_server,
            source_index, source_qkp_id, transfer_id, topology_source_id,
            topology_target_id, source_qkp_id, target_qkp_id, generation,
            first_slot, last_slot, source_lsn, config_epoch, checksum, &receipt) || !receipt) {
        qihse_resp_ct_peer_receipt_free(receipt);
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "source did not prove a matching durable ABORTED phase");
        return false;
    }
    qihse_kv_ct_target_receipt_claim_t claim;
    memset(&claim, 0, sizeof(claim));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "%s", transfer_id);
    snprintf(claim.source_id, sizeof(claim.source_id), "%s", source_qkp_id);
    snprintf(claim.target_id, sizeof(claim.target_id), "%s", target_qkp_id);
    snprintf(claim.generation, sizeof(claim.generation), "%s", generation);
    claim.first_slot = first_slot; claim.last_slot = last_slot;
    claim.source_cut = source_lsn;
    memcpy(claim.range_checksum, checksum, sizeof(checksum));
    target_phase_receipt_context_t verify = {
        .receipt = receipt, .phase = "ABORTED",
        .topology_source_id = topology_source_id,
        .topology_target_id = topology_target_id,
        .config_epoch = config_epoch
    };
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    qihse_kv_ct_transfer_status_detail_t fence_detail;
    memset(&fence_detail, 0, sizeof(fence_detail));
    bool status_ok = qihse_kv_ct_transfer_status_detail(c->store, c->principal,
                                                        &fence_detail);
    bool no_fence = status_ok && fence_detail.base.fence_state == 0u;
    bool ok = no_fence ||
        (qihse_kv_ct_owner_token_get(c->store, c->principal, owner_token) &&
         qihse_kv_ct_target_abort(c->store, c->principal, &claim,
            verify_target_phase_receipt, &verify, owner_token));
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
    qihse_resp_ct_peer_receipt_free(receipt);
    if (ok) {
        qihse_cluster_ownership_txn_t aborted;
        target_txn_from_tuple(&aborted, transfer_id, topology_source_id,
            topology_target_id, source_qkp_id, target_qkp_id, generation,
            first_slot, last_slot, source_lsn, config_epoch);
        aborted.phase = QIHSE_OWNERSHIP_ABORTED;
        const char* data_dir = qihse_kv_store_data_directory(c->store);
        last_txn_state_t last = {0}; bool unresolved = false;
        int replayed = data_dir ? qihse_cluster_ownership_journal_replay_txn(
            data_dir, last_txn_state_cb, &last, &unresolved) : -1;
        bool already_aborted = replayed >= 0 && last.has_record &&
            last.txn.phase == QIHSE_OWNERSHIP_ABORTED &&
            !strcmp(last.txn.transfer_id, transfer_id) &&
            !strcmp(last.txn.source_id, topology_source_id) &&
            !strcmp(last.txn.target_id, topology_target_id) &&
            !strcmp(last.txn.source_qkp_id, source_qkp_id) &&
            !strcmp(last.txn.target_qkp_id, target_qkp_id) &&
            !strcmp(last.txn.generation, generation) &&
            last.txn.start == first_slot && last.txn.end == last_slot &&
            last.txn.source_lsn == source_lsn && last.txn.config_epoch == config_epoch;
        ok = already_aborted || (replayed >= 0 && unresolved &&
            qihse_cluster_ownership_journal_append_txn(data_dir, &aborted) == 0);
        OPENSSL_cleanse(&last, sizeof(last));
        OPENSSL_cleanse(&aborted, sizeof(aborted));
    }
    OPENSSL_cleanse(&claim, sizeof(claim));
    OPENSSL_cleanse(checksum, sizeof(checksum));
    set_error(err, err_cap, ok ? "" : "target ABORTED phase requires durable journal recovery");
    return ok;
}
bool qihse_cluster_ownership_transfer_abort(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    uint16_t source_index, uint16_t target_index,
    char* err, size_t err_cap) {
    if (!c || !c->topology || !c->store || !c->principal || !transfer_id) {
        set_error(err, err_cap, "authenticated context and transfer ID are required for abort");
        return false;
    }
    if (!range_authority_hooks_valid(c)) {
        set_error(err, err_cap, "range authority hooks are incomplete");
        return false;
    }
    if (qihse_cluster_topology_local_node(c->topology) != source_index) {
        set_error(err, err_cap, "only the local source may abort a prepared range transfer");
        return false;
    }
    qihse_cluster_node_t source, target;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        !resolve_qkp_id(c, source.id, source_qkp) || !resolve_qkp_id(c, target.id, target_qkp)) {
        set_error(err, err_cap, "source/target identity mapping is unavailable");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    pending_state_t pending = {0}; bool unresolved = false;
    int n = data_dir ? qihse_cluster_ownership_journal_replay_txn(
        data_dir, pending_state_cb, &pending, &unresolved) : -1;
    if (n >= 0 && !unresolved) {
        qihse_cluster_ownership_txn_t aborted;
        memset(&aborted, 0, sizeof(aborted));
        if (!qihse_cluster_ownership_transfer_get_aborted(c, transfer_id,
                &aborted, err, err_cap) ||
            strcmp(aborted.source_id, source.id) ||
            strcmp(aborted.target_id, target.id) ||
            strcmp(aborted.source_qkp_id, source_qkp) ||
            strcmp(aborted.target_qkp_id, target_qkp)) {
            OPENSSL_cleanse(&aborted, sizeof(aborted));
            set_error(err, err_cap, "matching durable CT2 ABORTED record is unavailable");
            return false;
        }
        if (c->range_abort && !c->range_abort(c->range_authority_context,
                c->principal, &aborted, err, err_cap)) {
            OPENSSL_cleanse(&aborted, sizeof(aborted));
            if (!err || !err_cap || !err[0])
                set_error(err, err_cap, "quorum ABORT is not durable; source fence remains active");
            return false;
        }
        qihse_kv_ct_transfer_status_t status;
        memset(&status, 0, sizeof(status));
        bool status_ok = qihse_kv_ct_transfer_status(c->store, c->principal, &status);
        bool same_fence = status_ok && status.fence_state == 1u &&
            !strcmp(status.transfer_id, aborted.transfer_id) &&
            status.first_slot == aborted.start && status.last_slot == aborted.end &&
            status.cut_position == aborted.source_lsn &&
            !strcmp(status.source_id, aborted.source_qkp_id) &&
            !strcmp(status.generation, aborted.generation);
        bool fence_same_id = status_ok && status.fence_state == 1u &&
            !strcmp(status.transfer_id, aborted.transfer_id);
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        bool released = !fence_same_id;
        if (fence_same_id && same_fence)
            released = qihse_kv_ct_owner_token_get(c->store, c->principal, token) &&
                qihse_kv_ct_fence_finish(c->store, c->principal,
                    transfer_id, false, token);
        OPENSSL_cleanse(token, sizeof(token));
        OPENSSL_cleanse(&status, sizeof(status));
        OPENSSL_cleanse(&aborted, sizeof(aborted));
        if (!status_ok || !released) {
            set_error(err, err_cap, "quorum abort is durable but source fence release needs recovery");
            return false;
        }
        set_error(err, err_cap, "");
        return true;
    }
    if (n < 0 || !unresolved || !pending.pending ||
        strcmp(pending.txn.transfer_id, transfer_id) ||
        strcmp(pending.txn.source_id, source.id) || strcmp(pending.txn.target_id, target.id) ||
        strcmp(pending.txn.source_qkp_id, source_qkp) ||
        strcmp(pending.txn.target_qkp_id, target_qkp) || pending.txn.next_generation[0]) {
        set_error(err, err_cap, "matching abortable CT2 PREPARED record is unavailable");
        return false;
    }
    qihse_cluster_ownership_txn_t aborted = pending.txn;
    aborted.phase = QIHSE_OWNERSHIP_ABORTED;
    aborted.target_lsn = 0;
    memset(aborted.proof_digest, 0, sizeof(aborted.proof_digest));
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    if (!qihse_kv_ct_owner_token_get(c->store, c->principal, owner_token)) {
        set_error(err, err_cap, "principal cannot authorize the source owner capability");
        return false;
    }
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &aborted) != 0) {
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        set_error(err, err_cap, "abort record could not be persisted; source fence remains active");
        return false;
    }
    if (c->range_abort && !c->range_abort(c->range_authority_context,
            c->principal, &aborted, err, err_cap)) {
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        OPENSSL_cleanse(&aborted, sizeof(aborted));
        if (!err || !err_cap || !err[0])
            set_error(err, err_cap, "quorum abort failed; source fence remains active");
        return false;
    }
    bool ok = qihse_kv_ct_fence_finish(c->store, c->principal,
        transfer_id, false, owner_token);
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    OPENSSL_cleanse(&aborted, sizeof(aborted));
    if (!ok) {
        set_error(err, err_cap, "abort is durable but source fence release requires recovery");
        return false;
    }
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_transfer_commit(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    uint16_t source_index, uint16_t target_index,
    const qihse_cluster_ct_peer_receipt_t* receipt,
    char* err, size_t err_cap) {
    if (!receipt || !transfer_id) { set_error(err, err_cap, "authenticated target receipt is required"); return false; }
    qihse_cluster_node_t source, target;
    /* Range comes from the PREPARED record; find it by replay and bind all
     * identities again against the current topology and QKP pin registry. */
    if (!c || !c->store || !c->principal || !c->data_principal || !c->topology) {
        set_error(err, err_cap, "invalid ownership transfer context"); return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    if (!data_dir || !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target)) {
        set_error(err, err_cap, "topology or durable store directory is unavailable"); return false;
    }
    pending_state_t pending = {0}; bool unresolved = false;
    int replayed = qihse_cluster_ownership_journal_replay_txn(
        data_dir, pending_state_cb, &pending, &unresolved);
    if (replayed < 0 || !unresolved || !pending.pending ||
        strcmp(pending.txn.transfer_id, transfer_id) ||
        strcmp(pending.txn.source_id, source.id) || strcmp(pending.txn.target_id, target.id)) {
        set_error(err, err_cap, "matching durable PREPARED transfer is unavailable or journal recovery is required");
        return false;
    }
    qihse_cluster_ownership_txn_t txn = pending.txn;
    if (txn.start > txn.end) {
        set_error(err, err_cap, "PREPARED record has an invalid source cut"); return false;
    }
    if (qihse_cluster_topology_local_node(c->topology) != source_index ||
        source.role != QIHSE_CLUSTER_NODE_PRIMARY || target.role != QIHSE_CLUSTER_NODE_PRIMARY ||
        !target.healthy) {
        set_error(err, err_cap, "source/target topology authority changed during transfer"); return false;
    }
    for (uint32_t slot = txn.start; slot <= txn.end; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_slot_state_t state = QIHSE_CLUSTER_SLOT_STABLE;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot, &owner, &state, NULL) ||
            owner != source_index || state != QIHSE_CLUSTER_SLOT_STABLE) {
            set_error(err, err_cap, "topology changed while the source fence was active"); return false;
        }
    }
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!resolve_qkp_id(c, source.id, source_qkp) || !resolve_qkp_id(c, target.id, target_qkp) ||
        strcmp(txn.source_qkp_id, source_qkp) || strcmp(txn.target_qkp_id, target_qkp)) {
        set_error(err, err_cap, "PREPARED identities no longer match the configured QKP pins"); return false;
    }
    qihse_kv_ct_source_status_t status;
    memset(&status, 0, sizeof(status));
    if (!qihse_kv_ct_source_status(c->store, c->principal, &status) ||
        strcmp(status.source_id, source_qkp) || strcmp(status.generation, txn.generation)) {
        set_error(err, err_cap, "source generation or configured QKP identity changed during transfer"); return false;
    }
    uint64_t target_lsn = 0;
    uint8_t target_checksum[32] = {0};
    if (!qihse_resp_ct_peer_receipt_validate(receipt, txn.transfer_id,
            txn.source_id, txn.target_id, txn.source_qkp_id, txn.target_qkp_id,
            txn.generation, txn.start, txn.end, txn.source_lsn,
            txn.config_epoch,
            &target_lsn, target_checksum)) {
        set_error(err, err_cap, "QKP-pinned durable target receipt does not match the fenced source cut");
        return false;
    }
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_source_transfer_proof_create(
        c->store, c->principal, c->data_principal, txn.transfer_id, txn.source_qkp_id,
        txn.target_qkp_id, txn.generation, txn.start, txn.end, txn.source_lsn);
    if (!proof) { set_error(err, err_cap, "source range seal could not be created"); return false; }
    bool proof_ok = qihse_kv_ct_proof_validate(c->store, c->principal, c->data_principal, proof);
    const char *proof_transfer = NULL, *proof_source = NULL, *proof_target = NULL, *proof_generation = NULL;
    uint16_t proof_first = 0, proof_last = 0;
    uint64_t proof_source_lsn = 0, proof_target_lsn = 0;
    uint8_t source_checksum[32] = {0};
    proof_ok = proof_ok && qihse_kv_ct_proof_fields(c->store, c->principal, c->data_principal, proof,
        &proof_transfer, &proof_source,
        &proof_target, &proof_generation, &proof_first, &proof_last,
        &proof_source_lsn, &proof_target_lsn, source_checksum) &&
        proof_transfer && proof_source && proof_target && proof_generation &&
        !strcmp(proof_transfer, txn.transfer_id) && !strcmp(proof_source, txn.source_qkp_id) &&
        !strcmp(proof_target, txn.target_qkp_id) && !strcmp(proof_generation, txn.generation) &&
        proof_first == txn.start && proof_last == txn.end && proof_source_lsn == txn.source_lsn &&
        CRYPTO_memcmp(source_checksum, target_checksum, sizeof(source_checksum)) == 0;
    OPENSSL_cleanse(source_checksum, sizeof(source_checksum));
    if (!proof_ok) {
        qihse_kv_ct_proof_destroy(proof);
        OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
        set_error(err, err_cap, "source and signed target range seals disagree");
        return false;
    }
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    if (!qihse_kv_ct_owner_token_get(c->store, c->principal, owner_token)) {
        qihse_kv_ct_proof_destroy(proof);
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
        set_error(err, err_cap, "principal cannot authorize the local CT owner capability");
        return false;
    }
    txn.phase = QIHSE_OWNERSHIP_COMMITTED;
    txn.owner_id[0] = '\0';
    snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", target.id);
    txn.target_lsn = target_lsn;
    memcpy(txn.proof_digest, target_checksum, sizeof(txn.proof_digest));
    OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        qihse_kv_ct_proof_destroy(proof);
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        set_error(err, err_cap, "committed journal transition failed; source remains fenced for recovery");
        return false;
    }
    qihse_kv_ct_target_receipt_claim_t claim;
    memset(&claim, 0, sizeof(claim));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "%s", txn.transfer_id);
    snprintf(claim.source_id, sizeof(claim.source_id), "%s", txn.source_qkp_id);
    snprintf(claim.target_id, sizeof(claim.target_id), "%s", txn.target_qkp_id);
    snprintf(claim.generation, sizeof(claim.generation), "%s", txn.generation);
    claim.first_slot = txn.start; claim.last_slot = txn.end;
    claim.source_cut = txn.source_lsn; claim.target_durable_cursor = txn.target_lsn;
    memcpy(claim.range_checksum, txn.proof_digest, sizeof(claim.range_checksum));
    receipt_verify_context_t verify = {.receipt = receipt, .txn = &txn};
    if (!qihse_kv_ct_source_fence_commit(c->store, c->principal, proof, &claim,
            verify_storage_receipt_claim, &verify, owner_token)) {
        qihse_kv_ct_proof_destroy(proof);
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        OPENSSL_cleanse(&claim, sizeof(claim));
        set_error(err, err_cap, "source COMMITTED is durable but proof-consuming fence transition needs recovery");
        return false;
    }
    qihse_kv_ct_proof_destroy(proof);
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    OPENSSL_cleanse(&claim, sizeof(claim));
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_transfer_publish(
    qihse_cluster_ownership_context_t* c, const char* transfer_id,
    const qihse_cluster_ct_activation_receipt_t* activation,
    char* err, size_t err_cap) {
    if (!c || !c->topology || !c->store || !c->principal || !transfer_id || !activation) {
        set_error(err, err_cap, "durable source context and target activation receipt are required");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    find_txn_t found = {.transfer_id = transfer_id};
    bool journal_unresolved = false;
    if (!data_dir || qihse_cluster_ownership_journal_replay_txn(
            data_dir, find_txn_cb, &found, &journal_unresolved) < 0 || !found.found ||
        (found.txn.phase != QIHSE_OWNERSHIP_COMMITTED &&
         found.txn.phase != QIHSE_OWNERSHIP_FINALIZED) ||
        (found.txn.phase == QIHSE_OWNERSHIP_COMMITTED && !journal_unresolved)) {
        set_error(err, err_cap, "matching committed/finalized CT2 source transaction is unavailable");
        return false;
    }
    qihse_cluster_ownership_txn_t txn = found.txn;
    uint16_t source_index, target_index;
    qihse_cluster_node_t source, target;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!qihse_cluster_topology_find_node(c->topology, txn.source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, txn.target_id, &target_index) ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        qihse_cluster_topology_local_node(c->topology) != source_index ||
        !resolve_qkp_id(c, source.id, source_qkp) || !resolve_qkp_id(c, target.id, target_qkp) ||
        strcmp(source_qkp, txn.source_qkp_id) || strcmp(target_qkp, txn.target_qkp_id)) {
        set_error(err, err_cap, "committed transfer identity no longer matches local topology/QKP pins");
        return false;
    }
    uint64_t target_lsn = 0;
    uint8_t checksum[32] = {0};
    bool receipt_ok = qihse_resp_ct_activation_receipt_validate(activation,
        txn.transfer_id, txn.source_id, txn.target_id, txn.source_qkp_id,
        txn.target_qkp_id, txn.generation, txn.start, txn.end, txn.source_lsn,
        txn.config_epoch,
        &target_lsn, checksum) && target_lsn == txn.target_lsn &&
        CRYPTO_memcmp(checksum, txn.proof_digest, sizeof(checksum)) == 0;
    OPENSSL_cleanse(checksum, sizeof(checksum));
    if (!receipt_ok) {
        set_error(err, err_cap, "target is not durably activated for this exact committed transfer");
        return false;
    }
    if (!range_authority_hooks_valid(c)) {
        set_error(err, err_cap, "range authority hooks are incomplete");
        return false;
    }
    bool needs_apply = false;
    for (uint32_t slot = txn.start; slot <= txn.end; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot,
                &owner, NULL, NULL) ||
            !qihse_cluster_topology_get_slot_epoch(c->topology,
                (uint16_t)slot, &epoch)) {
            set_error(err, err_cap, "could not read source topology before publish");
            return false;
        }
        if (epoch > txn.config_epoch || (epoch == txn.config_epoch && owner == target_index))
            continue;
        if (epoch == txn.config_epoch ||
            (owner != source_index && owner != target_index)) {
            set_error(err, err_cap, "slot map changed outside this committed transfer epoch");
            return false;
        }
        needs_apply = true;
    }
    if (txn.phase == QIHSE_OWNERSHIP_COMMITTED) {
        if (c->range_finalize && !c->range_finalize(
                c->range_authority_context, c->principal, &txn, activation,
                err, err_cap))
            return false;
        qihse_cluster_ownership_txn_t finalized = txn;
        finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
        if (qihse_cluster_ownership_journal_append_txn(data_dir, &finalized) != 0) {
            set_error(err, err_cap, "target activation is verified but FINALIZED publication evidence failed");
            return false;
        }
        txn = finalized;
    }
    if (!range_check_finalized(c, &txn, err, err_cap)) return false;
    if (needs_apply) {
        if (!adopt_txn_ranges(c->topology, NULL, &txn, target_index)) {
            set_error(err, err_cap, "target activation is durable; source topology publish needs replay");
            return false;
        }
    }
    if (needs_apply && target.config_epoch < txn.config_epoch)
        target.config_epoch = txn.config_epoch;
    if (needs_apply && !qihse_cluster_topology_upsert_node(c->topology, &target, NULL)) {
        set_error(err, err_cap, "target activation is durable; node epoch publish needs replay");
        return false;
    }
    if (c->bus) {
        qihse_cluster_bus_ct_slot_update_t update;
        ct_update_from_txn(&txn, &update);
        bool sent = qihse_cluster_bus_broadcast_ct_slot_update(c->bus, &update);
        OPENSSL_cleanse(&update, sizeof(update));
        if (!sent) {
            set_error(err, err_cap, "ownership is published locally; authenticated bus broadcast must retry");
            return false;
        }
    }
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_receive_ct_update(
    qihse_cluster_ownership_context_t* c,
    const qihse_cluster_bus_ct_slot_update_t* u,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* err, size_t err_cap) {
    if (!c || !c->topology || !c->store || !c->principal || !u || !receipt ||
        u->magic != QIHSE_CLUSTER_BUS_CT_UPDATE_MAGIC || u->reserved ||
        u->start > u->end || u->end >= QIHSE_CLUSTER_SLOT_COUNT ||
        !u->transfer_id[0] || !u->source_id[0] || !u->target_id[0] ||
        !u->generation[0] || strcmp(u->owner_id, u->target_id)) {
        set_error(err, err_cap, "authenticated context, valid CT update, and pinned receipt are required");
        return false;
    }
    uint16_t source_index, target_index;
    qihse_cluster_node_t source, target;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!qihse_cluster_topology_find_node(c->topology, u->source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, u->target_id, &target_index) ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        !resolve_qkp_id(c, source.id, source_qkp) || !resolve_qkp_id(c, target.id, target_qkp) ||
        strcmp(source_qkp, u->source_qkp_id) || strcmp(target_qkp, u->target_qkp_id)) {
        set_error(err, err_cap, "CT update does not match the provisioned topology-to-QKP identity map");
        return false;
    }
    uint64_t target_lsn = 0;
    uint8_t checksum[32] = {0};
    bool receipt_ok = qihse_resp_ct_activation_receipt_validate(receipt,
        u->transfer_id, u->source_id, u->target_id, u->source_qkp_id,
        u->target_qkp_id, u->generation, u->start, u->end, u->source_lsn,
        u->config_epoch,
        &target_lsn, checksum) && target_lsn == u->target_lsn &&
        CRYPTO_memcmp(checksum, u->checksum, sizeof(checksum)) == 0;
    OPENSSL_cleanse(checksum, sizeof(checksum));
    if (!receipt_ok) {
        set_error(err, err_cap, "target activation receipt does not match the proof-bearing bus update");
        return false;
    }
    qihse_cluster_ownership_txn_t authority_txn;
    target_txn_from_tuple(&authority_txn, u->transfer_id, u->source_id,
        u->target_id, u->source_qkp_id, u->target_qkp_id, u->generation,
        u->start, u->end, u->source_lsn, u->config_epoch);
    authority_txn.target_lsn = u->target_lsn;
    memcpy(authority_txn.proof_digest, u->checksum, sizeof(authority_txn.proof_digest));
    authority_txn.phase = QIHSE_OWNERSHIP_FINALIZED;
    snprintf(authority_txn.owner_id, sizeof(authority_txn.owner_id), "%s", u->target_id);
    if (!range_check_finalized(c, &authority_txn, err, err_cap)) {
        OPENSSL_cleanse(&authority_txn, sizeof(authority_txn));
        return false;
    }
    OPENSSL_cleanse(&authority_txn, sizeof(authority_txn));
    uint16_t local_index = qihse_cluster_topology_local_node(c->topology);
    bool already_target = true;
    bool can_advance = true;
    bool target_already_owns_eligible = true;
    for (uint32_t slot = u->start; slot <= u->end; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot,
                &owner, NULL, NULL) ||
            !qihse_cluster_topology_get_slot_epoch(c->topology,
                (uint16_t)slot, &epoch)) {
            set_error(err, err_cap, "could not read local slot ownership");
            return false;
        }
        if (epoch > u->config_epoch || (epoch == u->config_epoch && owner == target_index))
            continue;
        if (epoch == u->config_epoch ||
            (owner != source_index && owner != target_index)) {
            set_error(err, err_cap, "CT update conflicts with the local per-slot ownership epoch");
            return false;
        }
        already_target = false;
        can_advance = true;
        if (owner != target_index) target_already_owns_eligible = false;
    }
    if (already_target) {
        set_error(err, err_cap, "");
        return true; /* replayed/duplicate activation; receipt was rechecked */
    }
    if (local_index == target_index && c->range_finalize) {
        const char* data_dir = qihse_kv_store_data_directory(c->store);
        pending_state_t pending = {0}; bool unresolved = false;
        int replayed = data_dir ? qihse_cluster_ownership_journal_replay_txn(
            data_dir, pending_state_cb, &pending, &unresolved) : -1;
        if (replayed < 0 || !unresolved || !pending.pending ||
            pending.txn.phase != QIHSE_OWNERSHIP_COMMITTED ||
            strcmp(pending.txn.transfer_id, u->transfer_id) ||
            pending.txn.start != u->start || pending.txn.end != u->end ||
            strcmp(pending.txn.source_id, u->source_id) ||
            strcmp(pending.txn.target_id, u->target_id) ||
            strcmp(pending.txn.source_qkp_id, u->source_qkp_id) ||
            strcmp(pending.txn.target_qkp_id, u->target_qkp_id) ||
            strcmp(pending.txn.generation, u->generation) ||
            pending.txn.source_lsn != u->source_lsn ||
            pending.txn.config_epoch != u->config_epoch ||
            pending.txn.target_lsn != u->target_lsn ||
            CRYPTO_memcmp(pending.txn.proof_digest, u->checksum, 32u) != 0) {
            set_error(err, err_cap, "target activation journal does not match the finalized quorum update");
            return false;
        }
        qihse_cluster_ownership_txn_t finalized = pending.txn;
        finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
        if (!data_dir || qihse_cluster_ownership_journal_append_txn(
                data_dir, &finalized) != 0 ||
            !adopt_txn_ranges(c->topology, NULL, &finalized, target_index)) {
            OPENSSL_cleanse(&finalized, sizeof(finalized));
            set_error(err, err_cap, "quorum-finalized target ownership needs local recovery");
            return false;
        }
        if (target.config_epoch < u->config_epoch) target.config_epoch = u->config_epoch;
        bool node_ok = qihse_cluster_topology_upsert_node(c->topology, &target, NULL);
        OPENSSL_cleanse(&finalized, sizeof(finalized));
        if (!node_ok) {
            set_error(err, err_cap, "quorum-finalized target node epoch needs local recovery");
            return false;
        }
        set_error(err, err_cap, "");
        return true;
    }
    if (local_index == target_index && target_already_owns_eligible && can_advance) {
        if (!adopt_txn_ranges(c->topology, NULL, &(qihse_cluster_ownership_txn_t){
                .start = u->start, .end = u->end, .config_epoch = u->config_epoch
            }, target_index)) {
            set_error(err, err_cap, "target ownership is durable but its slot epochs need replay");
            return false;
        }
        if (target.config_epoch < u->config_epoch) target.config_epoch = u->config_epoch;
        if (!qihse_cluster_topology_upsert_node(c->topology, &target, NULL)) {
            set_error(err, err_cap, "target ownership is durable but its node epoch needs replay");
            return false;
        }
        set_error(err, err_cap, "");
        return true;
    }
    if (u->config_epoch == 0 || (local_index == target_index &&
        (source.role != QIHSE_CLUSTER_NODE_PRIMARY || target.role != QIHSE_CLUSTER_NODE_PRIMARY))) {
        set_error(err, err_cap, "target role or topology epoch is not valid for this ownership commit");
        return false;
    }
    if (!can_advance) {
        set_error(err, err_cap, "CT update cannot advance all slots at its proof epoch");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    if (!data_dir) { set_error(err, err_cap, "local store has no durable ownership journal"); return false; }
    pending_state_t pending = {0}; bool unresolved = false;
    int count = qihse_cluster_ownership_journal_replay_txn(
        data_dir, pending_state_cb, &pending, &unresolved);
    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    if (count < 0 || unresolved) {
        if (!pending.pending || strcmp(pending.txn.transfer_id, u->transfer_id)) {
            set_error(err, err_cap, "another unresolved local ownership transaction must recover first");
            return false;
        }
        txn = pending.txn;
    } else {
        txn.phase = QIHSE_OWNERSHIP_PREPARED;
        txn.start = u->start; txn.end = u->end;
        snprintf(txn.transfer_id, sizeof(txn.transfer_id), "%s", u->transfer_id);
        snprintf(txn.source_id, sizeof(txn.source_id), "%s", u->source_id);
        snprintf(txn.target_id, sizeof(txn.target_id), "%s", u->target_id);
        snprintf(txn.source_qkp_id, sizeof(txn.source_qkp_id), "%s", u->source_qkp_id);
        snprintf(txn.target_qkp_id, sizeof(txn.target_qkp_id), "%s", u->target_qkp_id);
        snprintf(txn.generation, sizeof(txn.generation), "%s", u->generation);
        snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", u->source_id);
        txn.config_epoch = u->config_epoch;
        txn.source_lsn = u->source_lsn;
        if (local_index == target_index) {
            set_error(err, err_cap, "target must have its fenced PREPARED record before activation");
            return false;
        }
        if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
            set_error(err, err_cap, "could not persist local PREPARED ownership receipt");
            return false;
        }
    }
    if (strcmp(txn.transfer_id, u->transfer_id) || txn.start != u->start || txn.end != u->end ||
        strcmp(txn.source_id, u->source_id) || strcmp(txn.target_id, u->target_id) ||
        strcmp(txn.source_qkp_id, u->source_qkp_id) || strcmp(txn.target_qkp_id, u->target_qkp_id) ||
        strcmp(txn.generation, u->generation) || txn.source_lsn != u->source_lsn ||
        txn.config_epoch != u->config_epoch || txn.next_generation[0]) {
        set_error(err, err_cap, "local PREPARED journal tuple differs from the authenticated activation");
        return false;
    }
    txn.phase = QIHSE_OWNERSHIP_COMMITTED;
    txn.target_lsn = u->target_lsn;
    snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", u->target_id);
    memcpy(txn.proof_digest, u->checksum, sizeof(txn.proof_digest));
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        set_error(err, err_cap, "local COMMITTED receipt could not be persisted");
        return false;
    }
    if (local_index == target_index) {
        uint8_t token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        if (!qihse_kv_ct_owner_token_get(c->store, c->principal, token) ||
            !qihse_kv_ct_fence_finish(c->store, c->principal,
                txn.transfer_id, false, token)) {
            OPENSSL_cleanse(token, sizeof(token));
            set_error(err, err_cap, "target commit is durable but the staging fence needs activation recovery");
            return false;
        }
        OPENSSL_cleanse(token, sizeof(token));
    }
    txn.phase = QIHSE_OWNERSHIP_FINALIZED;
    if (qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        set_error(err, err_cap, "target is activated but FINALIZED replay evidence could not be persisted");
        return false;
    }
    if (target.config_epoch < txn.config_epoch) target.config_epoch = txn.config_epoch;
    if (!qihse_cluster_topology_adopt_range(c->topology, txn.start, txn.end,
            target_index, txn.config_epoch) ||
        !qihse_cluster_topology_upsert_node(c->topology, &target, NULL)) {
        set_error(err, err_cap, "local COMMITTED receipt is durable; topology activation needs recovery");
        return false;
    }
    set_error(err, err_cap, "");
    return true;
}

void qihse_cluster_ownership_bus_update_callback(
    qihse_cluster_bus_t* bus,
    const qihse_cluster_bus_ct_slot_update_t* update, void* opaque) {
    (void)bus;
    qihse_cluster_ownership_context_t* c = opaque;
    if (!c || !c->resp_server || !c->topology || !update) return;
    uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    if (!qihse_cluster_topology_find_node(c->topology, update->target_id,
            &target_index) ||
        !resolve_qkp_id(c, update->target_id, target_qkp) ||
        strcmp(target_qkp, update->target_qkp_id)) return;
    qihse_cluster_ct_activation_receipt_t* receipt = NULL;
    if (!qihse_resp_ct_peer_activation_receipt_query_to(c->resp_server,
            target_index, target_qkp,
            update->transfer_id, update->source_id, update->target_id,
            update->source_qkp_id, update->target_qkp_id, update->generation,
            update->start, update->end, update->source_lsn,
            update->config_epoch, update->target_lsn, update->checksum,
            &receipt) || !receipt) {
        qihse_resp_ct_activation_receipt_free(receipt);
        return;
    }
    char err[160];
    (void)qihse_cluster_ownership_receive_ct_update(c, update, receipt, err, sizeof(err));
    qihse_resp_ct_activation_receipt_free(receipt);
}

typedef struct {
    qihse_cluster_ownership_context_t* context;
    char* err;
    size_t err_cap;
    bool failed;
    bool has_prepared;
    qihse_cluster_ownership_txn_t prepared;
} replay_context_t;

static bool ct1_recovery_digest(const qihse_cluster_ownership_txn_t* txn,
                               const char* successor_topology_id,
                               const char* successor_qkp_id,
                               uint8_t out[32]);
static bool topology_node_owns_slots(qihse_cluster_topology_t* topology,
                                    uint16_t node_index, bool* out_owns);

static bool promotion_roles_can_apply(qihse_cluster_topology_t* topology,
    uint64_t epoch, uint16_t source_index, uint16_t target_index,
    uint16_t successor_index, qihse_cluster_node_t* source,
    qihse_cluster_node_t* target, qihse_cluster_node_t* successor) {
    if (!topology || !source || !target || !successor ||
        source->config_epoch > epoch || target->config_epoch > epoch ||
        successor->config_epoch > epoch || !successor->healthy ||
        !((target->role == QIHSE_CLUSTER_NODE_PRIMARY) ||
          (target->role == QIHSE_CLUSTER_NODE_REPLICA &&
           target->primary_index == source_index)) ||
        !((source->role == QIHSE_CLUSTER_NODE_PRIMARY) ||
          (source->role == QIHSE_CLUSTER_NODE_REPLICA &&
           source->primary_index == target_index))) return false;
    bool successor_owns_slots = false;
    if (!topology_node_owns_slots(topology, successor_index, &successor_owns_slots) ||
        (successor_owns_slots &&
         !(successor->role == QIHSE_CLUSTER_NODE_REPLICA &&
           successor->primary_index == target_index))) return false;
    target->role = QIHSE_CLUSTER_NODE_PRIMARY;
    target->primary_index = QIHSE_CLUSTER_NODE_NONE;
    target->healthy = true;
    if (target->config_epoch < epoch) target->config_epoch = epoch;
    source->role = QIHSE_CLUSTER_NODE_REPLICA;
    source->primary_index = target_index;
    if (source->config_epoch < epoch) source->config_epoch = epoch;
    successor->role = QIHSE_CLUSTER_NODE_REPLICA;
    successor->primary_index = target_index;
    if (successor->config_epoch < epoch) successor->config_epoch = epoch;
    return true;
}

static bool adopt_txn_ranges(qihse_cluster_topology_t* topology,
                             qihse_cluster_bus_t* bus,
                             const qihse_cluster_ownership_txn_t* txn,
                             uint16_t target_index) {
    (void)bus; /* CT1/CT2 changes are announced with their proof-bearing event. */
    for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT;) {
        bool included = txn->next_generation[0]
            ? (txn->slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0
            : slot >= txn->start && slot <= txn->end;
        if (!included) { ++slot; continue; }
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        if (!qihse_cluster_topology_get_slot(topology, (uint16_t)slot, &owner, NULL, NULL) ||
            !qihse_cluster_topology_get_slot_epoch(topology, (uint16_t)slot, &epoch)) return false;
        if (epoch > txn->config_epoch || (epoch == txn->config_epoch && owner == target_index)) {
            ++slot; continue; /* a newer or already-applied proof wins */
        }
        if (epoch == txn->config_epoch) return false; /* same epoch, conflicting owner */
        uint32_t first = slot++;
        while (slot < QIHSE_CLUSTER_SLOT_COUNT) {
            bool next_included = txn->next_generation[0]
                ? (txn->slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0
                : slot >= txn->start && slot <= txn->end;
            if (!next_included) break;
            uint16_t next_owner = QIHSE_CLUSTER_NODE_NONE;
            uint64_t next_epoch = 0;
            if (!qihse_cluster_topology_get_slot(topology, (uint16_t)slot, &next_owner, NULL, NULL) ||
                !qihse_cluster_topology_get_slot_epoch(topology, (uint16_t)slot, &next_epoch)) return false;
            if (next_epoch >= txn->config_epoch || next_owner == target_index) break;
            ++slot;
        }
        uint32_t last = slot - 1u;
        if (!qihse_cluster_topology_adopt_range(topology, (uint16_t)first,
                (uint16_t)last, target_index, txn->config_epoch)) return false;
    }
    return true;
}

static bool ct1_update_from_txn(const qihse_cluster_ownership_txn_t* txn,
                                const char* successor_qkp,
                                qihse_cluster_bus_ct1_promotion_update_t* update) {
    if (!txn || !successor_qkp || !update || !txn->next_generation[0]) return false;
    memset(update, 0, sizeof(*update));
    update->magic = QIHSE_CLUSTER_BUS_CT1_PROMOTION_MAGIC;
    update->start = txn->start; update->end = txn->end;
    update->config_epoch = txn->config_epoch;
    update->durable_cursor = txn->source_lsn;
    snprintf(update->transfer_id, sizeof(update->transfer_id), "%s", txn->transfer_id);
    snprintf(update->source_id, sizeof(update->source_id), "%s", txn->source_id);
    snprintf(update->target_id, sizeof(update->target_id), "%s", txn->target_id);
    snprintf(update->source_qkp_id, sizeof(update->source_qkp_id), "%s", txn->source_qkp_id);
    snprintf(update->target_qkp_id, sizeof(update->target_qkp_id), "%s", txn->target_qkp_id);
    snprintf(update->successor_id, sizeof(update->successor_id), "%s", txn->owner_id);
    snprintf(update->successor_qkp_id, sizeof(update->successor_qkp_id), "%s", successor_qkp);
    snprintf(update->generation, sizeof(update->generation), "%s", txn->generation);
    snprintf(update->next_generation, sizeof(update->next_generation), "%s", txn->next_generation);
    memcpy(update->slot_bitmap, txn->slot_bitmap, sizeof(update->slot_bitmap));
    memcpy(update->promotion_digest, txn->proof_digest, sizeof(update->promotion_digest));
    return qihse_cluster_bus_ct1_promotion_seal(update);
}

static bool recover_txn(const qihse_cluster_ownership_txn_t* txn, void* opaque) {
    replay_context_t* r = opaque;
    qihse_cluster_ownership_context_t* c = r->context;
    if (txn->phase == QIHSE_OWNERSHIP_INTENT ||
        txn->phase == QIHSE_OWNERSHIP_PREPARED ||
        txn->phase == QIHSE_OWNERSHIP_COMMITTED) {
        r->has_prepared = true;
        r->prepared = *txn;
        return true; /* resolve only the final outstanding phase after full replay */
    }
    uint16_t source_index, target_index;
    qihse_cluster_node_t source, target;
    bool promotion_roles_applied = false;
    if (!qihse_cluster_topology_find_node(c->topology, txn->source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, txn->target_id, &target_index) ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target)) {
        set_error(r->err, r->err_cap, "journal owner node is not present in the trusted topology");
        r->failed = true; return false;
    }
    uint16_t local_index = qihse_cluster_topology_local_node(c->topology);
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!resolve_qkp_id(c, source.id, source_qkp) || !resolve_qkp_id(c, target.id, target_qkp) ||
        strcmp(source_qkp, txn->source_qkp_id) || strcmp(target_qkp, txn->target_qkp_id)) {
        set_error(r->err, r->err_cap, "journal QKP identities no longer match the configured peer pins");
        r->failed = true; return false;
    }
    if (txn->phase == QIHSE_OWNERSHIP_ABORTED) {
        if (local_index != source_index) {
            set_error(r->err, r->err_cap, "aborted transfer journal is not on its source");
            r->failed = true; return false;
        }
        qihse_kv_ct_transfer_status_t status;
        memset(&status, 0, sizeof(status));
        bool ok = qihse_kv_ct_transfer_status(c->store, c->principal, &status);
        bool same_fence = ok && status.fence_state == 1u &&
            !strcmp(status.transfer_id, txn->transfer_id) &&
            status.first_slot == txn->start && status.last_slot == txn->end &&
            status.cut_position == txn->source_lsn &&
            !strcmp(status.source_id, txn->source_qkp_id) &&
            !strcmp(status.generation, txn->generation);
        if (ok && c->range_abort &&
            !c->range_abort(c->range_authority_context, c->principal,
                txn, r->err, r->err_cap)) {
            OPENSSL_cleanse(&status, sizeof(status));
            set_error(r->err, r->err_cap, "quorum ABORT is not durable; source fence remains active");
            r->failed = true; return false;
        }
        if (same_fence) {
            unsigned char token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
            ok = qihse_kv_ct_owner_token_get(c->store, c->principal, token) &&
                qihse_kv_ct_fence_finish(c->store, c->principal,
                    txn->transfer_id, false, token);
            OPENSSL_cleanse(token, sizeof(token));
            memset(&status, 0, sizeof(status));
            ok = ok && qihse_kv_ct_transfer_status(c->store, c->principal, &status);
        }
        /* ABORTED is durable before its source fence is released. Finish that
         * crash window only when every durable fence field identifies this
         * exact transaction. Older ABORTED entries can precede a later active
         * transfer in the journal; leave that fence for final replay
         * validation rather than mistaking it for this transaction. */
        ok = ok && (status.fence_state != 1u ||
            (status.transfer_id[0] && strcmp(status.transfer_id, txn->transfer_id)));
        OPENSSL_cleanse(&status, sizeof(status));
        if (!ok) {
            set_error(r->err, r->err_cap, "durable source abort fence recovery failed");
            r->failed = true; return false;
        }
        return true;
    }
    if (txn->phase != QIHSE_OWNERSHIP_FINALIZED &&
        txn->phase != QIHSE_OWNERSHIP_ADOPTED) return false;
    if (txn->next_generation[0]) {
        if (txn->phase == QIHSE_OWNERSHIP_FINALIZED && local_index != target_index) {
            set_error(r->err, r->err_cap, "finalized CT1 promotion journal is not on its promoted target");
            r->failed = true; return false;
        }
        qihse_kv_ct_source_status_t promoted;
        memset(&promoted, 0, sizeof(promoted));
        char successor_qkp[QIHSE_KV_CT_ID_MAX + 1u];
        uint16_t successor_index = source_index;
        qihse_cluster_node_t successor_node = source;
        if (!strcmp(txn->owner_id, txn->source_id) ||
            !strcmp(txn->owner_id, txn->target_id)) {
            /* v2 journals predating explicit successor selection rebound to
             * the former primary. */
            snprintf(successor_qkp, sizeof(successor_qkp), "%s", source_qkp);
        } else if (!qihse_cluster_topology_find_node(c->topology, txn->owner_id,
                    &successor_index) ||
                   !qihse_cluster_topology_get_node(c->topology, successor_index,
                    &successor_node) ||
                   !resolve_qkp_id(c, txn->owner_id, successor_qkp)) {
            set_error(r->err, r->err_cap, "finalized CT1 successor is missing from the trusted topology/pin map");
            r->failed = true; return false;
        }
        if (strcmp(txn->owner_id, txn->source_id) &&
            strcmp(txn->owner_id, txn->target_id)) {
            uint8_t expected[32] = {0};
            bool digest_ok = ct1_recovery_digest(txn, txn->owner_id,
                successor_qkp, expected) &&
                CRYPTO_memcmp(expected, txn->proof_digest, sizeof(expected)) == 0;
            OPENSSL_cleanse(expected, sizeof(expected));
            if (!digest_ok) {
                OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
                set_error(r->err, r->err_cap, "finalized CT1 journal successor fingerprint is invalid");
                r->failed = true; return false;
            }
        }
        bool durable_target = txn->phase == QIHSE_OWNERSHIP_ADOPTED ||
            (qihse_kv_ct_source_status(c->store, c->principal, &promoted) &&
             !strcmp(promoted.source_id, target_qkp) &&
             !strcmp(promoted.successor_id, successor_qkp) &&
             !strcmp(promoted.generation, txn->next_generation));
        if (!durable_target) {
            OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
            set_error(r->err, r->err_cap, "finalized CT1 journal disagrees with the persisted promoted generation");
            r->failed = true; return false;
        }
        if (txn->phase == QIHSE_OWNERSHIP_FINALIZED && local_index == target_index && c->bus) {
            qihse_cluster_bus_ct1_promotion_update_t update;
            if (!ct1_update_from_txn(txn, successor_qkp, &update)) {
                OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
                set_error(r->err, r->err_cap, "could not rebuild signed CT1 promotion anti-entropy record");
                r->failed = true; return false;
            }
            (void)qihse_cluster_bus_broadcast_ct1_promotion(c->bus, &update);
            OPENSSL_cleanse(&update, sizeof(update));
        }
        OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
        bool apply_roles = promotion_roles_can_apply(c->topology,
            txn->config_epoch, source_index, target_index, successor_index,
            &source, &target, &successor_node);
        promotion_roles_applied = apply_roles;
        bool promotion_range_is_stale = !apply_roles &&
            (target.role != QIHSE_CLUSTER_NODE_PRIMARY ||
             target.config_epoch > txn->config_epoch);
        if (apply_roles &&
            (!qihse_cluster_topology_upsert_node(c->topology, &source, NULL) ||
             !qihse_cluster_topology_upsert_node(c->topology, &successor_node, NULL))) {
            set_error(r->err, r->err_cap, "finalized CT1 promoted source is durable; successor role replay failed");
            r->failed = true; return false;
        }
        if (promotion_range_is_stale) {
            /* A durable historical promotion proves its own transition only.
             * Once the target's node epoch has advanced, replay must not use
             * that old proof to fill slots still waiting for the newer chain. */
            r->has_prepared = false;
            memset(&r->prepared, 0, sizeof(r->prepared));
            return true;
        }
    }
    bool update_target_node = !txn->next_generation[0] || promotion_roles_applied;
    if (!txn->next_generation[0] && !range_check_finalized(c, txn,
            r->err, r->err_cap)) {
        if (!r->err || !r->err_cap || !r->err[0])
            set_error(r->err, r->err_cap, "finalized CT2 quorum decision is unavailable during replay");
        r->failed = true;
        return false;
    }
    if (update_target_node && target.config_epoch < txn->config_epoch)
        target.config_epoch = txn->config_epoch;
    if ((update_target_node && !qihse_cluster_topology_upsert_node(c->topology, &target, NULL)) ||
        !adopt_txn_ranges(c->topology, NULL, txn, target_index)) {
        set_error(r->err, r->err_cap, "finalized ownership could not be restored locally");
        r->failed = true; return false;
    }
    if (!txn->next_generation[0] && c->bus && local_index == source_index) {
        /* Seed bounded anti-entropy from the complete, checksummed journal.
         * Per-slot cache replacement keeps only the greatest ownership epoch;
         * each receiver still fetches this exact typed activation receipt from
         * the configured QKP target before it adopts the range. */
        qihse_cluster_bus_ct_slot_update_t update;
        ct_update_from_txn(txn, &update);
        (void)qihse_cluster_bus_broadcast_ct_slot_update(c->bus, &update);
        OPENSSL_cleanse(&update, sizeof(update));
    }
    r->has_prepared = false;
    memset(&r->prepared, 0, sizeof(r->prepared));
    return true;
}

static bool ct1_recovery_digest(const qihse_cluster_ownership_txn_t* txn,
                               const char* successor_topology_id,
                               const char* successor_qkp_id,
                               uint8_t out[32]) {
    char lsn[32];
    snprintf(lsn, sizeof(lsn), "%llu", (unsigned long long)txn->source_lsn);
    const char* fields[] = {txn->source_id, txn->target_id, txn->source_qkp_id,
        txn->target_qkp_id, successor_topology_id, successor_qkp_id,
        txn->generation, txn->next_generation, lsn};
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) return false;
    unsigned int n = 0;
    bool ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); ++i)
        ok = EVP_DigestUpdate(md, fields[i], strlen(fields[i])) == 1;
    if (ok) ok = EVP_DigestFinal_ex(md, out, &n) == 1 && n == 32;
    EVP_MD_CTX_free(md);
    return ok;
}

bool qihse_cluster_ownership_receive_ct1_promotion(
    qihse_cluster_ownership_context_t* c,
    const qihse_cluster_bus_ct1_promotion_update_t* u,
    char* err, size_t err_cap) {
    if (!c || !u || u->magic != QIHSE_CLUSTER_BUS_CT1_PROMOTION_MAGIC ||
        u->reserved || !u->config_epoch || u->start > u->end ||
        u->end >= QIHSE_CLUSTER_SLOT_COUNT || !u->transfer_id[0] ||
        !u->source_id[0] || !u->target_id[0] || !u->successor_id[0] ||
        !u->generation[0] || !u->next_generation[0]) {
        set_error(err, err_cap, "signed CT1 promotion tuple is malformed");
        return false;
    }
    qihse_cluster_bus_ct1_promotion_update_t sealed = *u;
    if (!qihse_cluster_bus_ct1_promotion_seal(&sealed) ||
        CRYPTO_memcmp(sealed.event_digest, u->event_digest, 32u) != 0) {
        OPENSSL_cleanse(&sealed, sizeof(sealed));
        set_error(err, err_cap, "CT1 event digest does not bind its full promotion bitmap");
        return false;
    }
    OPENSSL_cleanse(&sealed, sizeof(sealed));
    uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
    uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
    uint16_t successor_index = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_node_t source, target, successor;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char successor_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    if (!qihse_cluster_topology_find_node(c->topology, u->source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, u->target_id, &target_index) ||
        !qihse_cluster_topology_find_node(c->topology, u->successor_id, &successor_index) ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        !qihse_cluster_topology_get_node(c->topology, successor_index, &successor) ||
        !resolve_qkp_id(c, source.id, source_qkp) ||
        !resolve_qkp_id(c, target.id, target_qkp) ||
        !resolve_qkp_id(c, successor.id, successor_qkp) ||
        strcmp(source_qkp, u->source_qkp_id) || strcmp(target_qkp, u->target_qkp_id) ||
        strcmp(successor_qkp, u->successor_qkp_id) ||
        source_index == target_index || successor_index == target_index ||
        successor_index == source_index) {
        set_error(err, err_cap, "CT1 event identities do not match trusted topology/QKP pins");
        return false;
    }
    /* The successor may have acquired unrelated slots since this promotion.
     * The target signature and promotion digest bind the successor selected by
     * the authorized local promotion path; current slotlessness is not a
     * historical validity condition. */
    bool target_relationship_current = target.role == QIHSE_CLUSTER_NODE_PRIMARY ||
        (target.role == QIHSE_CLUSTER_NODE_REPLICA && target.primary_index == source_index);
    if (!target_relationship_current && target.config_epoch <= u->config_epoch) {
        set_error(err, err_cap, "signed CT1 target is not the configured replica of the previous owner");
        return false;
    }
    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    txn.phase = QIHSE_OWNERSHIP_ADOPTED;
    txn.start = QIHSE_CLUSTER_SLOT_COUNT;
    txn.end = 0;
    txn.config_epoch = u->config_epoch;
    txn.source_lsn = u->durable_cursor;
    txn.target_lsn = u->durable_cursor;
    snprintf(txn.transfer_id, sizeof(txn.transfer_id), "%s", u->transfer_id);
    snprintf(txn.source_id, sizeof(txn.source_id), "%s", u->source_id);
    snprintf(txn.target_id, sizeof(txn.target_id), "%s", u->target_id);
    snprintf(txn.source_qkp_id, sizeof(txn.source_qkp_id), "%s", u->source_qkp_id);
    snprintf(txn.target_qkp_id, sizeof(txn.target_qkp_id), "%s", u->target_qkp_id);
    snprintf(txn.generation, sizeof(txn.generation), "%s", u->generation);
    snprintf(txn.next_generation, sizeof(txn.next_generation), "%s", u->next_generation);
    snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", u->successor_id);
    memcpy(txn.slot_bitmap, u->slot_bitmap, sizeof(txn.slot_bitmap));
    for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; ++slot) {
        if (!(txn.slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u)))) continue;
        if (slot < txn.start) txn.start = (uint16_t)slot;
        txn.end = (uint16_t)slot;
    }
    bool run_is_bound = true;
    for (uint32_t slot = u->start; slot <= u->end; ++slot)
        if (!(txn.slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u)))) {
            run_is_bound = false;
            break;
        }
    if ((u->start > 0u && (txn.slot_bitmap[(u->start - 1u) / 8u] &
            (uint8_t)(1u << ((u->start - 1u) % 8u)))) ||
        (u->end + 1u < QIHSE_CLUSTER_SLOT_COUNT &&
            (txn.slot_bitmap[(u->end + 1u) / 8u] &
             (uint8_t)(1u << ((u->end + 1u) % 8u))))) run_is_bound = false;
    if (!run_is_bound || txn.start >= QIHSE_CLUSTER_SLOT_COUNT ||
        strcmp(txn.transfer_id, u->transfer_id) || txn.start > u->start || txn.end < u->end) {
        set_error(err, err_cap, "CT1 event range is not contained in its durable slot bitmap");
        return false;
    }
    uint8_t expected_digest[32] = {0};
    if (!ct1_recovery_digest(&txn, txn.owner_id, u->successor_qkp_id, expected_digest) ||
        CRYPTO_memcmp(expected_digest, u->promotion_digest, 32u) != 0) {
        OPENSSL_cleanse(expected_digest, sizeof(expected_digest));
        set_error(err, err_cap, "CT1 event does not match the target's durable promotion proof fingerprint");
        return false;
    }
    memcpy(txn.proof_digest, expected_digest, sizeof(txn.proof_digest));
    OPENSSL_cleanse(expected_digest, sizeof(expected_digest));

    bool needs_apply = false;
    for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; ++slot) {
        if (!(txn.slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u)))) continue;
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        uint64_t epoch = 0;
        if (!qihse_cluster_topology_get_slot(c->topology, (uint16_t)slot, &owner, NULL, NULL) ||
            !qihse_cluster_topology_get_slot_epoch(c->topology, (uint16_t)slot, &epoch)) {
            set_error(err, err_cap, "could not read local slot epoch for CT1 promotion");
            return false;
        }
        if (epoch > txn.config_epoch || (epoch == txn.config_epoch && owner == target_index)) continue;
        if (epoch == txn.config_epoch || (owner != source_index && owner != target_index)) {
            set_error(err, err_cap, "CT1 event conflicts with a newer or same-epoch owner");
            return false;
        }
        needs_apply = true;
    }
    if (!needs_apply) { set_error(err, err_cap, ""); return true; }
    bool apply_roles = promotion_roles_can_apply(c->topology,
        txn.config_epoch, source_index, target_index, successor_index,
        &source, &target, &successor);
    if (!apply_roles && (target.role != QIHSE_CLUSTER_NODE_PRIMARY ||
                         target.config_epoch > txn.config_epoch)) {
        /* A replica cannot serve these slots, and an advanced primary's old
         * relationship does not prove it still owns the unresolved bitmap.
         * Keep current owners until the newer promotion chain is known. */
        set_error(err, err_cap, "");
        return true;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    if (!data_dir || qihse_cluster_ownership_journal_append_txn(data_dir, &txn) != 0) {
        set_error(err, err_cap, "could not persist the signed CT1 adoption before routing slots");
        return false;
    }
    if ((apply_roles &&
         (!qihse_cluster_topology_upsert_node(c->topology, &target, NULL) ||
          !qihse_cluster_topology_upsert_node(c->topology, &source, NULL) ||
          !qihse_cluster_topology_upsert_node(c->topology, &successor, NULL))) ||
        !adopt_txn_ranges(c->topology, NULL, &txn, target_index)) {
        set_error(err, err_cap, "CT1 adoption is durable but local topology replay is required");
        return false;
    }
    OPENSSL_cleanse(&txn, sizeof(txn));
    set_error(err, err_cap, "");
    return true;
}

void qihse_cluster_ownership_ct1_promotion_bus_callback(
    qihse_cluster_bus_t* bus,
    const qihse_cluster_bus_ct1_promotion_update_t* update, void* opaque) {
    (void)bus;
    char err[192];
    (void)qihse_cluster_ownership_receive_ct1_promotion(opaque, update, err, sizeof(err));
}

static bool topology_node_owns_slots(qihse_cluster_topology_t* topology,
                                     uint16_t node_index, bool* out_owns) {
    if (out_owns) *out_owns = false;
    if (!topology || !out_owns) return false;
    qihse_cluster_slot_range_t* ranges = calloc(
        QIHSE_CLUSTER_SLOT_COUNT, sizeof(*ranges));
    if (!ranges) return false;
    size_t count = qihse_cluster_topology_ranges(topology, ranges,
                                                 QIHSE_CLUSTER_SLOT_COUNT);
    bool owns = false;
    for (size_t i = 0; i < count && i < QIHSE_CLUSTER_SLOT_COUNT; ++i)
        if (ranges[i].owner_index == node_index) { owns = true; break; }
    free(ranges);
    *out_owns = owns;
    return true;
}

static bool resume_prepared_ct1(qihse_cluster_ownership_context_t* c,
                                qihse_cluster_ownership_txn_t* txn,
                                char* err, size_t err_cap) {
    uint16_t source_index, target_index;
    qihse_cluster_node_t source, target;
    if (!txn->next_generation[0] ||
        !qihse_cluster_topology_find_node(c->topology, txn->source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, txn->target_id, &target_index) ||
        qihse_cluster_topology_local_node(c->topology) != target_index ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target)) {
        set_error(err, err_cap, "prepared CT1 promotion is not for this local candidate");
        return false;
    }
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u], target_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    if (!resolve_qkp_id(c, source.id, source_qkp) || !resolve_qkp_id(c, target.id, target_qkp) ||
        strcmp(source_qkp, txn->source_qkp_id) || strcmp(target_qkp, txn->target_qkp_id)) {
        set_error(err, err_cap, "prepared CT1 peer identity no longer matches trusted QKP pins");
        return false;
    }
    char successor_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char successor_qkp[QIHSE_KV_CT_ID_MAX + 1u];
    qihse_cluster_node_t successor_node = source;
    uint16_t successor_index = source_index;
    bool legacy_successor = !strcmp(txn->owner_id, txn->source_id) ||
                            !strcmp(txn->owner_id, txn->target_id);
    if (legacy_successor) {
        snprintf(successor_topology, sizeof(successor_topology), "%s", txn->source_id);
        snprintf(successor_qkp, sizeof(successor_qkp), "%s", source_qkp);
    } else {
        successor_index = QIHSE_CLUSTER_NODE_NONE;
        snprintf(successor_topology, sizeof(successor_topology), "%s", txn->owner_id);
        if (!qihse_cluster_topology_find_node(c->topology, successor_topology, &successor_index) ||
            successor_index == source_index || successor_index == target_index ||
            !qihse_cluster_topology_get_node(c->topology, successor_index, &successor_node) ||
            !successor_node.healthy ||
            !resolve_qkp_id(c, successor_node.id, successor_qkp) ||
            !strcmp(successor_qkp, source_qkp) || !strcmp(successor_qkp, target_qkp)) {
            set_error(err, err_cap, "prepared CT1 successor is not a healthy configured primary with a distinct pin");
            return false;
        }
        bool owns_slots = false;
        if (!topology_node_owns_slots(c->topology, successor_index, &owns_slots) || owns_slots) {
            set_error(err, err_cap, "prepared CT1 successor acquired slots; refusing a destructive full baseline");
            return false;
        }
    }
    qihse_kv_ct_receiver_status_t receiver;
    memset(&receiver, 0, sizeof(receiver));
    bool is_receiver = qihse_kv_ct_receiver_status(c->store, c->principal, &receiver) &&
        strcmp(receiver.source_id, source_qkp) == 0 &&
        strcmp(receiver.generation, txn->generation) == 0 &&
        receiver.durable_cursor == txn->source_lsn;
    if (is_receiver) {
        if (!c->promotion_authorized || !c->promotion_authorized(c->promotion_context,
                source.id, target.id, txn->generation, txn->source_lsn)) {
            set_error(err, err_cap, "current consensus lease/quorum does not authorize prepared CT1 recovery");
            return false;
        }
        qihse_kv_ct_proof_t* proof = qihse_kv_ct_promotion_proof_create(
            c->store, c->principal, source_qkp, target_qkp,
            txn->generation, txn->source_lsn);
        if (!proof) { set_error(err, err_cap, "persisted receiver proof is unavailable for CT1 recovery"); return false; }
        bool proof_ok = qihse_kv_ct_proof_validate(c->store, c->principal, NULL, proof);
        const char *transfer = NULL, *proof_source = NULL, *proof_target = NULL, *generation = NULL;
        uint16_t first = 0, last = 0; uint64_t source_lsn = 0, target_lsn = 0;
        uint8_t checksum[32] = {0};
        proof_ok = proof_ok && qihse_kv_ct_proof_fields(c->store, c->principal, NULL, proof,
            &transfer, &proof_source, &proof_target, &generation, &first, &last,
            &source_lsn, &target_lsn, checksum) && proof_source && proof_target && generation &&
            strcmp(proof_source, source_qkp) == 0 && strcmp(proof_target, target_qkp) == 0 &&
            strcmp(generation, txn->generation) == 0 && source_lsn == txn->source_lsn &&
            target_lsn == source_lsn;
        OPENSSL_cleanse(checksum, sizeof(checksum));
        if (!proof_ok) {
            qihse_kv_ct_proof_destroy(proof);
            set_error(err, err_cap, "receiver proof no longer validates the prepared CT1 cursor");
            return false;
        }
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        bool promoted = qihse_kv_ct_owner_token_get(c->store, c->principal, token) &&
            qihse_kv_ct_receiver_promote(c->store, c->principal, proof,
                txn->next_generation, successor_qkp, token);
        OPENSSL_cleanse(token, sizeof(token));
        qihse_kv_ct_proof_destroy(proof);
        if (!promoted) { set_error(err, err_cap, "durable CT1 generation recovery failed"); return false; }
    }
    /* The generation may already have switched if the process died between
     * receiver_promote() and the COMMITTED journal append. */
    qihse_kv_ct_source_status_t promoted_status;
    memset(&promoted_status, 0, sizeof(promoted_status));
    if (!qihse_kv_ct_source_status(c->store, c->principal, &promoted_status) ||
        strcmp(promoted_status.source_id, target_qkp) ||
        strcmp(promoted_status.successor_id, successor_qkp) ||
        strcmp(promoted_status.generation, txn->next_generation)) {
        set_error(err, err_cap, "persistent CT1 promoted generation does not match the journal");
        return false;
    }
    uint8_t audit_digest[32];
    if (!ct1_recovery_digest(txn, successor_topology, successor_qkp, audit_digest)) {
        set_error(err, err_cap, "could not recover CT1 proof fingerprint"); return false;
    }
    txn->phase = QIHSE_OWNERSHIP_COMMITTED;
    txn->target_lsn = txn->source_lsn;
    snprintf(txn->owner_id, sizeof(txn->owner_id), "%s", successor_topology);
    memcpy(txn->proof_digest, audit_digest, sizeof(txn->proof_digest));
    OPENSSL_cleanse(audit_digest, sizeof(audit_digest));
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    if (!data_dir || qihse_cluster_ownership_journal_append_txn(data_dir, txn) != 0) {
        set_error(err, err_cap, "CT1 generation is promoted but COMMITTED journal recovery failed");
        return false;
    }
    txn->phase = QIHSE_OWNERSHIP_FINALIZED;
    if (qihse_cluster_ownership_journal_append_txn(data_dir, txn) != 0) {
        set_error(err, err_cap, "CT1 promotion committed; FINALIZED recovery marker failed");
        return false;
    }
    OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
    OPENSSL_cleanse(successor_topology, sizeof(successor_topology));
    target.role = QIHSE_CLUSTER_NODE_PRIMARY;
    target.primary_index = QIHSE_CLUSTER_NODE_NONE;
    target.healthy = true;
    target.config_epoch = txn->config_epoch;
    successor_node.role = QIHSE_CLUSTER_NODE_REPLICA;
    successor_node.primary_index = target_index;
    successor_node.config_epoch = txn->config_epoch;
    if (!qihse_cluster_topology_upsert_node(c->topology, &target, NULL) ||
        !qihse_cluster_topology_upsert_node(c->topology, &successor_node, NULL) ||
        !adopt_txn_ranges(c->topology, c->bus, txn, target_index)) {
        set_error(err, err_cap, "CT1 commit recovered durably; topology activation must be retried");
        return false;
    }
    if (c->bus) qihse_cluster_bus_broadcast_node_update(c->bus, target_index);
    return true;
}

static void hex_checksum(const uint8_t digest[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32u; ++i) {
        out[2u * i] = hex[digest[i] >> 4];
        out[2u * i + 1u] = hex[digest[i] & 15u];
    }
    out[64] = '\0';
}

/* Resume the source half of CT2 after its COMMITTED journal frame. The
 * source's durable range fence is revalidated against either the target's
 * still-sealed receipt or its stronger activated receipt, then ACTIVATE is
 * retried over the configured QKP pin. Publication still requires the typed
 * ACTIVATED receipt and is journaled FINALIZED before local map changes. */
static bool resume_committed_ct2_source(qihse_cluster_ownership_context_t* c,
                                        const qihse_cluster_ownership_txn_t* txn,
                                        char* err, size_t err_cap) {
    if (!c->resp_server || !c->data_principal || !txn || txn->phase != QIHSE_OWNERSHIP_COMMITTED ||
        txn->next_generation[0]) {
        set_error(err, err_cap, "CT2 source recovery requires a committed transaction and pinned QKP client");
        return false;
    }
    uint16_t source_index = 0, target_index = 0;
    qihse_cluster_node_t source, target;
    char source_pin[QIHSE_KV_CT_ID_MAX + 1u], target_pin[QIHSE_KV_CT_ID_MAX + 1u];
    if (!qihse_cluster_topology_find_node(c->topology, txn->source_id, &source_index) ||
        !qihse_cluster_topology_find_node(c->topology, txn->target_id, &target_index) ||
        !qihse_cluster_topology_get_node(c->topology, source_index, &source) ||
        !qihse_cluster_topology_get_node(c->topology, target_index, &target) ||
        qihse_cluster_topology_local_node(c->topology) != source_index ||
        !resolve_qkp_id(c, source.id, source_pin) || !resolve_qkp_id(c, target.id, target_pin) ||
        strcmp(source_pin, txn->source_qkp_id) || strcmp(target_pin, txn->target_qkp_id)) {
        set_error(err, err_cap, "committed CT2 source identities no longer match local topology and configured pins");
        return false;
    }

    qihse_kv_ct_target_receipt_claim_t claim;
    memset(&claim, 0, sizeof(claim));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "%s", txn->transfer_id);
    snprintf(claim.source_id, sizeof(claim.source_id), "%s", txn->source_qkp_id);
    snprintf(claim.target_id, sizeof(claim.target_id), "%s", txn->target_qkp_id);
    snprintf(claim.generation, sizeof(claim.generation), "%s", txn->generation);
    claim.first_slot = txn->start; claim.last_slot = txn->end;
    claim.source_cut = txn->source_lsn; claim.target_durable_cursor = txn->target_lsn;
    memcpy(claim.range_checksum, txn->proof_digest, sizeof(claim.range_checksum));
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    if (!qihse_kv_ct_owner_token_get(c->store, c->principal, owner_token)) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        set_error(err, err_cap, "principal cannot authorize recovery of the persisted CT2 source fence");
        return false;
    }

    qihse_cluster_ct_peer_receipt_t* sealed = NULL;
    qihse_cluster_ct_activation_receipt_t* activated = NULL;
    bool fence_ok = false;
    if (qihse_resp_ct_peer_receipt_query_to(c->resp_server, target_index,
            txn->target_qkp_id, txn->transfer_id, txn->source_id, txn->target_id,
            txn->source_qkp_id, txn->target_qkp_id, txn->generation,
            txn->start, txn->end, txn->source_lsn, txn->config_epoch, &sealed)) {
        receipt_verify_context_t verify = {.receipt = sealed, .txn = txn};
        qihse_kv_ct_proof_t* source_proof = qihse_kv_ct_source_transfer_proof_create(
            c->store, c->principal, c->data_principal, txn->transfer_id, txn->source_qkp_id,
            txn->target_qkp_id, txn->generation, txn->start, txn->end,
            txn->source_lsn);
        fence_ok = qihse_kv_ct_source_fence_commit(c->store, c->principal,
            source_proof, &claim, verify_storage_receipt_claim, &verify, owner_token);
        qihse_kv_ct_proof_destroy(source_proof);
    }
    if (!fence_ok && qihse_resp_ct_peer_activation_receipt_query_to(c->resp_server,
            target_index, txn->target_qkp_id, txn->transfer_id,
            txn->source_id, txn->target_id, txn->source_qkp_id, txn->target_qkp_id,
            txn->generation, txn->start, txn->end, txn->source_lsn,
            txn->config_epoch,
            txn->target_lsn, txn->proof_digest, &activated)) {
        activation_receipt_verify_context_t verify = {.receipt = activated, .txn = txn};
        fence_ok = qihse_kv_ct_source_fence_commit(c->store, c->principal,
            NULL, &claim, verify_activation_receipt_claim, &verify, owner_token);
    }
    qihse_resp_ct_peer_receipt_free(sealed);
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    OPENSSL_cleanse(&claim, sizeof(claim));
    if (!fence_ok) {
        qihse_resp_ct_activation_receipt_free(activated);
        set_error(err, err_cap, "target durable seal/activation could not revalidate the committed source fence");
        return false;
    }
    qihse_resp_ct_activation_receipt_free(activated);

    char first[8], last[8], source_lsn[32], epoch[32], target_lsn[32], checksum[65];
    snprintf(first, sizeof(first), "%u", (unsigned)txn->start);
    snprintf(last, sizeof(last), "%u", (unsigned)txn->end);
    snprintf(source_lsn, sizeof(source_lsn), "%llu", (unsigned long long)txn->source_lsn);
    snprintf(epoch, sizeof(epoch), "%llu", (unsigned long long)txn->config_epoch);
    snprintf(target_lsn, sizeof(target_lsn), "%llu", (unsigned long long)txn->target_lsn);
    hex_checksum(txn->proof_digest, checksum);
    const char* argv[] = {"REPL.CT2", "ACTIVATE", txn->transfer_id,
        txn->source_id, txn->target_id, txn->source_qkp_id, txn->target_qkp_id,
        txn->generation, first, last, source_lsn, epoch, target_lsn, checksum};
    qihse_resp_ct_arg_t args[14];
    for (size_t i = 0; i < 14u; ++i)
        args[i] = (qihse_resp_ct_arg_t){argv[i], strlen(argv[i])};
    qihse_resp_ct_reply_t reply = {0};
    bool command_ok = qihse_resp_ct_peer_command_to(c->resp_server, target_index,
        txn->target_qkp_id, args, 14u, &reply) && reply.data && reply.len == 5u &&
        memcmp(reply.data, "+OK\r\n", 5u) == 0;
    qihse_resp_ct_reply_free(&reply);
    if (!command_ok) {
        set_error(err, err_cap, "source remains fenced: target ACTIVATE retry was not acknowledged");
        return false;
    }
    qihse_cluster_ct_activation_receipt_t* receipt = NULL;
    bool receipt_ok = qihse_resp_ct_peer_activation_receipt_query_to(c->resp_server,
        target_index, txn->target_qkp_id, txn->transfer_id,
        txn->source_id, txn->target_id, txn->source_qkp_id, txn->target_qkp_id,
        txn->generation, txn->start, txn->end, txn->source_lsn,
        txn->config_epoch,
        txn->target_lsn, txn->proof_digest, &receipt);
    uint64_t checked_target_lsn = 0;
    uint8_t checked_checksum[32] = {0};
    receipt_ok = receipt_ok && qihse_resp_ct_activation_receipt_validate(receipt,
        txn->transfer_id, txn->source_id, txn->target_id, txn->source_qkp_id,
        txn->target_qkp_id, txn->generation, txn->start, txn->end,
        txn->source_lsn, txn->config_epoch, &checked_target_lsn, checked_checksum) &&
        checked_target_lsn == txn->target_lsn &&
        CRYPTO_memcmp(checked_checksum, txn->proof_digest, sizeof(checked_checksum)) == 0;
    OPENSSL_cleanse(checked_checksum, sizeof(checked_checksum));
    if (!receipt_ok) {
        qihse_resp_ct_activation_receipt_free(receipt);
        set_error(err, err_cap, "target ACTIVATE was acknowledged but durable activation receipt is unavailable");
        return false;
    }
    bool published = qihse_cluster_ownership_transfer_publish(c,
        txn->transfer_id, receipt, err, err_cap);
    qihse_resp_ct_activation_receipt_free(receipt);
    return published;
}

static bool ownership_replay_impl(
    qihse_cluster_ownership_context_t* c, bool* out_unresolved,
    bool allow_pending, char* err, size_t err_cap) {
    if (out_unresolved) *out_unresolved = false;
    if (!c || !c->topology || !c->store || !c->principal || !out_unresolved) {
        set_error(err, err_cap, "authenticated topology/store context is required for ownership recovery");
        return false;
    }
    if (!range_authority_hooks_valid(c)) {
        set_error(err, err_cap, "range authority hooks are incomplete");
        return false;
    }
    const char* data_dir = qihse_kv_store_data_directory(c->store);
    if (!data_dir) { set_error(err, err_cap, "KV store has no durable data directory"); return false; }
    replay_context_t ctx = { .context = c, .err = err, .err_cap = err_cap, .failed = false };
    int count = qihse_cluster_ownership_journal_replay_txn(
        data_dir, recover_txn, &ctx, out_unresolved);
    if (count < 0 || ctx.failed) {
        if (!err || !err_cap || !err[0]) set_error(err, err_cap, "ownership journal is corrupt or recovery failed");
        return false;
    }
    /* The replay callback visits historical terminal records before it knows
     * which transaction is last. Validate any remaining live fence against
     * that final journal state so a deferred historical ABORTED record cannot
     * hide an unrelated transfer. */
    qihse_kv_ct_transfer_status_detail_t fence_detail;
    memset(&fence_detail, 0, sizeof(fence_detail));
    if (!qihse_kv_ct_transfer_status_detail(c->store, c->principal, &fence_detail)) {
        set_error(err, err_cap, "durable CT transfer status unavailable during journal recovery");
        return false;
    }
    qihse_kv_ct_transfer_status_t* fence_status = &fence_detail.base;
    uint16_t local_index = qihse_cluster_topology_local_node(c->topology);
    if (*out_unresolved && ctx.has_prepared &&
        ctx.prepared.phase == QIHSE_OWNERSHIP_INTENT) {
        qihse_cluster_ownership_txn_t intent = ctx.prepared;
        uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
        uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
        bool nodes_ok = qihse_cluster_topology_find_node(c->topology,
                intent.source_id, &source_index) &&
            qihse_cluster_topology_find_node(c->topology,
                intent.target_id, &target_index);
        if (!nodes_ok || (local_index != source_index && local_index != target_index)) {
            OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
            set_error(err, err_cap, "CT2 intent is not local to its configured source or target");
            return false;
        }
        if (fence_status->fence_state == 0u && local_index == source_index &&
            intent.source_lsn == 0u) {
            /* No source fence means this intent never returned a source cut,
             * so no target request could have been issued. Close the orphan
             * intent durably and permit a fresh attempt. */
            intent.phase = QIHSE_OWNERSHIP_ABORTED;
            if (qihse_cluster_ownership_journal_append_txn(data_dir, &intent) != 0) {
                OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
                set_error(err, err_cap, "unfenced CT2 source intent could not be closed as aborted");
                return false;
            }
            *out_unresolved = false;
            ctx.has_prepared = false;
            memset(&ctx.prepared, 0, sizeof(ctx.prepared));
        } else if (fence_status->fence_state == 1u) {
            bool common = fence_status->mode == 1u &&
                !strcmp(fence_status->transfer_id, intent.transfer_id) &&
                fence_status->first_slot == intent.start &&
                fence_status->last_slot == intent.end;
            bool source_match = local_index == source_index && common &&
                !strcmp(fence_status->source_id, intent.source_qkp_id) &&
                !strcmp(fence_status->generation, intent.generation) &&
                (!intent.source_lsn || intent.source_lsn == fence_status->cut_position);
            bool target_match = local_index == target_index && common &&
                !strcmp(fence_status->source_id, intent.target_qkp_id) &&
                !strcmp(fence_detail.transfer_source_id, intent.source_qkp_id) &&
                !strcmp(fence_detail.transfer_source_generation, intent.generation) &&
                fence_detail.transfer_source_cut == intent.source_lsn;
            if (!source_match && !target_match) {
                OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
                set_error(err, err_cap, "durable CT2 fence does not match its pre-fence intent");
                return false;
            }
            if (source_match) intent.source_lsn = fence_status->cut_position;
            intent.phase = QIHSE_OWNERSHIP_PREPARED;
            if (qihse_cluster_ownership_journal_append_txn(data_dir, &intent) != 0) {
                OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
                set_error(err, err_cap, "matching durable CT2 fence could not be bound to PREPARED intent");
                return false;
            }
            ctx.prepared = intent;
            ctx.has_prepared = true;
            *out_unresolved = true;
        } else if (local_index == target_index && fence_status->fence_state == 0u) {
            /* Source may retry BEGIN; the target intent is deliberately kept
             * unresolved until it either acquires the exact durable fence or
             * receives a proof-bearing ABORT. */
        } else {
            OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
            set_error(err, err_cap, "CT2 intent has an incompatible durable fence state");
            return false;
        }
    }
    if (fence_status->fence_state == 1u) {
        const qihse_cluster_ownership_txn_t* pending =
            (*out_unresolved && ctx.has_prepared) ? &ctx.prepared : NULL;
        uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
        uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
        bool nodes_ok = pending &&
            qihse_cluster_topology_find_node(c->topology, pending->source_id, &source_index) &&
            qihse_cluster_topology_find_node(c->topology, pending->target_id, &target_index);
        bool common = nodes_ok && fence_status->mode == 1u &&
            !strcmp(fence_status->transfer_id, pending->transfer_id) &&
            fence_status->first_slot == pending->start &&
            fence_status->last_slot == pending->end;
        bool source_match = common && local_index == source_index &&
            fence_status->cut_position == pending->source_lsn &&
            !strcmp(fence_status->source_id, pending->source_qkp_id) &&
            !strcmp(fence_status->generation, pending->generation);
        bool target_match = common && local_index == target_index &&
            !strcmp(fence_status->source_id, pending->target_qkp_id) &&
            !strcmp(fence_detail.transfer_source_id, pending->source_qkp_id) &&
            !strcmp(fence_detail.transfer_source_generation, pending->generation) &&
            fence_detail.transfer_source_cut == pending->source_lsn;
        bool matches_pending = source_match || target_match;
        if (!matches_pending) {
            OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
            set_error(err, err_cap, "active CT fence does not match the final unfinished ownership transaction");
            return false;
        }
    }
    OPENSSL_cleanse(&fence_detail, sizeof(fence_detail));
    if (*out_unresolved && ctx.has_prepared && ctx.prepared.next_generation[0]) {
        if (!resume_prepared_ct1(c, &ctx.prepared, err, err_cap)) return false;
        *out_unresolved = false;
    }
    if (*out_unresolved && ctx.has_prepared &&
        ctx.prepared.phase == QIHSE_OWNERSHIP_COMMITTED &&
        !ctx.prepared.next_generation[0]) {
        if (!resume_committed_ct2_source(c, &ctx.prepared, err, err_cap)) return false;
        *out_unresolved = false;
    }
    if (*out_unresolved) {
        if (allow_pending) {
            set_error(err, err_cap, "control-plane recovery remains pending; keep ordinary data listeners closed");
            return true;
        }
        set_error(err, err_cap, "unfinished transfer remains fenced; recovery/abort is required");
        return false;
    }
    set_error(err, err_cap, "");
    return true;
}

bool qihse_cluster_ownership_replay(
    qihse_cluster_ownership_context_t* c, bool* out_unresolved,
    char* err, size_t err_cap) {
    return ownership_replay_impl(c, out_unresolved, false, err, err_cap);
}

bool qihse_cluster_ownership_replay_control(
    qihse_cluster_ownership_context_t* c, bool* out_unresolved,
    char* err, size_t err_cap) {
    return ownership_replay_impl(c, out_unresolved, true, err, err_cap);
}
