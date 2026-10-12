#include "qihse_principal_store.h"
#include "qihse_consensus_rejoin_guard.h"
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define PRINCIPAL_SLOT_COUNT 65536u

typedef struct {
    qihse_user_t* user;
    uint64_t generation;
} principal_slot_t;

typedef struct request_node_s {
    uint8_t id[16];
    struct request_node_s* next;
} request_node_t;

struct qihse_principal_store_s {
    principal_slot_t* slots;
    request_node_t* requests;
    uint64_t applied_index;
    uint64_t generation;
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
    bool history_bound;
};

struct qihse_principal_snapshot_s {
    qihse_principal_snapshot_metadata_t metadata;
    qihse_principal_snapshot_entry_t* entries;
};

static bool snapshot_requester_authorized(const qihse_user_t* requester) {
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    if (!requester || qihse_user_get_role(requester) != QIHSE_ROLE_OPERATOR)
        return false;
    qihse_auth_user_active_and_tenant(requester, &active, &tenant);
    return active && tenant == QIHSE_TENANT_SYSTEM;
}

qihse_principal_store_t* qihse_principal_store_new(
    const qihse_user_t* bootstrap_operator) {
    if (!bootstrap_operator || bootstrap_operator->user_id != 0u ||
        bootstrap_operator->role != QIHSE_ROLE_OPERATOR ||
        bootstrap_operator->tenant_id != QIHSE_TENANT_SYSTEM ||
        bootstrap_operator->classification_level != UINT16_MAX ||
        bootstrap_operator->sci_compartments != UINT16_MAX ||
        !bootstrap_operator->password_set) return NULL;
    qihse_principal_store_t* store = calloc(1, sizeof(*store));
    if (!store) return NULL;
    store->slots = calloc(PRINCIPAL_SLOT_COUNT, sizeof(*store->slots));
    if (!store->slots) {
        free(store);
        return NULL;
    }
    store->slots[0].user = malloc(sizeof(*bootstrap_operator));
    if (!store->slots[0].user) {
        free(store->slots);
        free(store);
        return NULL;
    }
    memcpy(store->slots[0].user, bootstrap_operator, sizeof(*bootstrap_operator));
    store->slots[0].generation = 1u;
    return store;
}

qihse_principal_store_t* qihse_principal_store_new_bound(
    const qihse_user_t* bootstrap_operator, const char* group_id,
    const uint8_t history_id[32], uint64_t writer_epoch_floor) {
    if (!group_id || !history_id ||
        qihse_auth_is_operator_password_default() ||
        !snapshot_requester_authorized(bootstrap_operator) ||
        !qihse_consensus_history_identity_valid(group_id, history_id,
                                                writer_epoch_floor)) return NULL;
    qihse_principal_store_t* store =
        qihse_principal_store_new(bootstrap_operator);
    if (!store) return NULL;
    memcpy(store->group_id, group_id, strlen(group_id) + 1u);
    memcpy(store->history_id, history_id, sizeof(store->history_id));
    store->writer_epoch_floor = writer_epoch_floor;
    store->history_bound = true;
    return store;
}

void qihse_principal_store_free(qihse_principal_store_t* store) {
    if (!store) return;
    if (store->slots) {
        for (size_t i = 0; i < PRINCIPAL_SLOT_COUNT; i++) {
            if (store->slots[i].user) {
                OPENSSL_cleanse(store->slots[i].user,
                                sizeof(*store->slots[i].user));
                free(store->slots[i].user);
            }
        }
        free(store->slots);
    }
    request_node_t* node = store->requests;
    while (node) {
        request_node_t* next = node->next;
        OPENSSL_cleanse(node, sizeof(*node));
        free(node);
        node = next;
    }
    OPENSSL_cleanse(store, sizeof(*store));
    free(store);
}

uint64_t qihse_principal_store_applied_index(
    const qihse_principal_store_t* store) {
    return store ? store->applied_index : 0u;
}

uint64_t qihse_principal_store_generation(
    const qihse_principal_store_t* store) {
    return store ? store->generation : 0u;
}

bool qihse_principal_store_export_user(
    const qihse_principal_store_t* store, const qihse_user_t* requester,
    const char* expected_group_id, const uint8_t expected_history_id[32],
    qihse_principal_snapshot_t** out_snapshot) {
    if (out_snapshot) *out_snapshot = NULL;
    if (!store || !store->history_bound || !requester || !expected_group_id ||
        !expected_history_id || !out_snapshot ||
        strcmp(expected_group_id, store->group_id) != 0 ||
        CRYPTO_memcmp(expected_history_id, store->history_id,
                      sizeof(store->history_id)) != 0 ||
        !snapshot_requester_authorized(requester)) return false;

    size_t count = 0u;
    for (uint32_t id = 1u; id < PRINCIPAL_SLOT_COUNT; id++)
        if (store->slots[id].generation != 0u) count++;
    qihse_principal_snapshot_t* snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) return false;
    if (count) {
        snapshot->entries = calloc(count, sizeof(*snapshot->entries));
        if (!snapshot->entries) {
            free(snapshot);
            return false;
        }
    }
    memcpy(snapshot->metadata.group_id, store->group_id,
           sizeof(snapshot->metadata.group_id));
    memcpy(snapshot->metadata.history_id, store->history_id,
           sizeof(snapshot->metadata.history_id));
    snapshot->metadata.writer_epoch_floor = store->writer_epoch_floor;
    snapshot->metadata.applied_index = store->applied_index;
    snapshot->metadata.registry_generation = store->generation;
    snapshot->metadata.entry_count = count;
    size_t at = 0u;
    for (uint32_t id = 1u; id < PRINCIPAL_SLOT_COUNT; id++) {
        const principal_slot_t* slot = &store->slots[id];
        if (slot->generation == 0u) continue;
        qihse_principal_snapshot_entry_t* item = &snapshot->entries[at++];
        item->user_id = id;
        item->principal_generation = slot->generation;
        item->present = slot->user != NULL;
        if (slot->user) memcpy(&item->principal, slot->user,
                               sizeof(item->principal));
    }
    *out_snapshot = snapshot;
    return true;
}

bool qihse_principal_snapshot_metadata_user(
    const qihse_principal_snapshot_t* snapshot,
    const qihse_user_t* requester,
    qihse_principal_snapshot_metadata_t* out_metadata) {
    if (out_metadata) memset(out_metadata, 0, sizeof(*out_metadata));
    if (!snapshot || !out_metadata || !snapshot_requester_authorized(requester))
        return false;
    *out_metadata = snapshot->metadata;
    return true;
}

bool qihse_principal_snapshot_entry_user(
    const qihse_principal_snapshot_t* snapshot,
    const qihse_user_t* requester, size_t position,
    qihse_principal_snapshot_entry_t* out_entry) {
    if (out_entry) memset(out_entry, 0, sizeof(*out_entry));
    if (!snapshot || !out_entry || position >= snapshot->metadata.entry_count ||
        !snapshot_requester_authorized(requester)) return false;
    *out_entry = snapshot->entries[position];
    return true;
}

bool qihse_principal_snapshot_visit_user(
    const qihse_principal_snapshot_t* snapshot,
    const qihse_user_t* requester,
    qihse_principal_snapshot_visit_fn visit, void* opaque) {
    if (!snapshot || !visit || !snapshot_requester_authorized(requester))
        return false;
    for (size_t i = 0u; i < snapshot->metadata.entry_count; i++)
        if (!visit(opaque, &snapshot->entries[i])) return false;
    return snapshot_requester_authorized(requester);
}

void qihse_principal_snapshot_free(qihse_principal_snapshot_t* snapshot) {
    if (!snapshot) return;
    if (snapshot->entries) {
        OPENSSL_cleanse(snapshot->entries,
                        snapshot->metadata.entry_count * sizeof(*snapshot->entries));
        free(snapshot->entries);
    }
    OPENSSL_cleanse(snapshot, sizeof(*snapshot));
    free(snapshot);
}

static bool username_taken(const qihse_principal_store_t* store,
                           uint32_t except_id, const char* username) {
    for (uint32_t id = 0; id < PRINCIPAL_SLOT_COUNT; id++) {
        const qihse_user_t* user = store->slots[id].user;
        if (id != except_id && user &&
            strcmp(user->username, username) == 0) return true;
    }
    return false;
}

qihse_principal_apply_result_t qihse_principal_store_apply_committed(
    qihse_principal_store_t* store, uint64_t index,
    const uint8_t* payload, size_t payload_len) {
    if (!store || !payload || store->applied_index == UINT64_MAX ||
        index != store->applied_index + 1u ||
        store->generation == UINT64_MAX) return QIHSE_PRINCIPAL_APPLY_ERROR;

    qihse_principal_record_t record;
    bool decoded = qihse_principal_record_decode(payload, payload_len, &record);
    if (!decoded) {
        store->applied_index = index;
        return QIHSE_PRINCIPAL_APPLY_REJECTED;
    }
    for (request_node_t* node = store->requests; node; node = node->next) {
        if (memcmp(node->id, record.request_id, sizeof(node->id)) == 0) {
            store->applied_index = index;
            OPENSSL_cleanse(&record, sizeof(record));
            return QIHSE_PRINCIPAL_APPLY_REJECTED;
        }
    }

    request_node_t* request = malloc(sizeof(*request));
    if (!request) {
        OPENSSL_cleanse(&record, sizeof(record));
        return QIHSE_PRINCIPAL_APPLY_ERROR;
    }
    memcpy(request->id, record.request_id, sizeof(request->id));
    request->next = NULL;
    principal_slot_t* target = &store->slots[record.target_id];
    const principal_slot_t* actor = &store->slots[record.actor_id];
    bool authorized = actor->user &&
        qihse_principal_record_authorize_transition(
            &record, store->generation, actor->user, actor->generation,
            target->user, target->generation);
    if (authorized && record.kind == QIHSE_PRINCIPAL_PUT)
        authorized = !username_taken(store, record.target_id,
                                     record.principal.username);
    qihse_user_t* replacement = NULL;
    if (authorized && record.kind == QIHSE_PRINCIPAL_PUT) {
        replacement = malloc(sizeof(*replacement));
        if (!replacement) {
            OPENSSL_cleanse(request, sizeof(*request));
            free(request);
            OPENSSL_cleanse(&record, sizeof(record));
            return QIHSE_PRINCIPAL_APPLY_ERROR;
        }
        memcpy(replacement, &record.principal, sizeof(*replacement));
    }

    request->next = store->requests;
    store->requests = request;
    store->applied_index = index;
    if (!authorized) {
        OPENSSL_cleanse(&record, sizeof(record));
        return QIHSE_PRINCIPAL_APPLY_REJECTED;
    }
    if (target->user) {
        OPENSSL_cleanse(target->user, sizeof(*target->user));
        free(target->user);
    }
    target->user = replacement;
    target->generation = record.principal_generation;
    store->generation++;
    OPENSSL_cleanse(&record, sizeof(record));
    return QIHSE_PRINCIPAL_APPLY_APPLIED;
}
