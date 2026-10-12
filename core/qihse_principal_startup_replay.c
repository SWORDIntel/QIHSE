#include "qihse_principal_startup_replay.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

#define QPR_REF_HASH_OFF 64u
#define QPR_REF_SIZE_OFF 112u

struct qihse_principal_verified_startup_snapshot_s {
    qihse_principal_snapshot_t* snapshot;
};

static uint64_t read_be64(const uint8_t* bytes) {
    uint64_t value = 0u;
    for (size_t i = 0u; i < 8u; i++) value = (value << 8u) | bytes[i];
    return value;
}

static bool apply_data(qihse_principal_store_t* store, uint64_t index,
                       const qihse_consensus_entry_t* entry,
                       qihse_consensus_blob_context_t* blobs,
                       qihse_user_t* operator_user) {
    if (!qihse_consensus_blob_validate(blobs, entry)) return false;
    const uint8_t* reference = entry->payload;
    uint64_t blob_size = read_be64(reference + QPR_REF_SIZE_OFF);
    if (blob_size <= QIHSE_CONSENSUS_BLOB_HEADER_BYTES ||
        blob_size > QIHSE_BLOB_MAX_SIZE) return false;
    uint64_t tx_size = blob_size - QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
    size_t prefix_len = tx_size < QIHSE_PRINCIPAL_RECORD_MAX_BYTES
        ? (size_t)tx_size : QIHSE_PRINCIPAL_RECORD_MAX_BYTES;
    size_t wanted = QIHSE_CONSENSUS_BLOB_HEADER_BYTES + prefix_len;
    uint8_t* bytes = malloc(wanted);
    if (!bytes) return false;
    size_t offset = 0u;
    bool ok = true;
    while (ok && offset < wanted) {
        size_t got = 0u;
        ok = qihse_blob_get_user(blobs->blobs,
                                 reference + QPR_REF_HASH_OFF,
                                 (uint64_t)offset, bytes + offset,
                                 wanted - offset, &got, operator_user) &&
             got > 0u && got <= wanted - offset;
        if (ok) offset += got;
    }
    static const uint8_t nonprincipal[] = {0};
    const uint8_t* payload = nonprincipal;
    size_t payload_len = sizeof(nonprincipal);
    if (ok && prefix_len >= 3u &&
        memcmp(bytes + QIHSE_CONSENSUS_BLOB_HEADER_BYTES, "QPR", 3u) == 0) {
        if (tx_size > QIHSE_PRINCIPAL_RECORD_MAX_BYTES) ok = false;
        else {
            payload = bytes + QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
            payload_len = (size_t)tx_size;
            qihse_principal_record_t decoded;
            ok = qihse_principal_record_decode(payload, payload_len,
                                               &decoded);
            OPENSSL_cleanse(&decoded, sizeof(decoded));
        }
    }
    if (ok) ok = qihse_principal_store_apply_committed(
        store, index, payload, payload_len) != QIHSE_PRINCIPAL_APPLY_ERROR;
    OPENSSL_cleanse(bytes, wanted);
    free(bytes);
    return ok;
}

bool qihse_principal_startup_replay_user(
    qihse_consensus_mesh_t* mesh, qihse_consensus_blob_context_t* blobs,
    qihse_user_t* system_operator, const char* group_id,
    const uint8_t history_id[32], uint64_t writer_epoch_floor,
    qihse_principal_store_t** out_store) {
    if (out_store) *out_store = NULL;
    if (!mesh || !blobs || !blobs->blobs || !system_operator ||
        !group_id || !history_id || !out_store) return false;
    size_t group_len = 0u;
    while (group_len <= QIHSE_CONSENSUS_GROUP_ID_MAX && group_id[group_len])
        group_len++;
    if (group_len == 0u || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX)
        return false;
    qihse_consensus_mesh_identity_t identity;
    if (!qihse_consensus_mesh_history_identity(mesh, &identity) ||
        identity.group_id[group_len] != '\0' ||
        memcmp(group_id, identity.group_id, group_len) != 0 ||
        CRYPTO_memcmp(history_id, identity.history_id,
                      sizeof(identity.history_id)) != 0 ||
        writer_epoch_floor != identity.writer_epoch_floor) return false;
    /* Bind the supplied group to the QTX1 validator before touching data. */
    uint8_t group_hash[SHA384_DIGEST_LENGTH];
    if (!SHA384((const uint8_t*)group_id, group_len, group_hash) ||
        CRYPTO_memcmp(group_hash, blobs->group_hash, sizeof(group_hash)) != 0)
        return false;
    qihse_principal_store_t* store = qihse_principal_store_new_bound(
        system_operator, group_id, history_id, writer_epoch_floor);
    if (!store) return false;
    uint64_t committed = qihse_consensus_mesh_commit_index(mesh);
    bool ok = true;
    static const uint8_t nonprincipal[] = {0};
    for (uint64_t index = 1u; ok && index <= committed; index++) {
        qihse_consensus_entry_t entry;
        size_t count = 0u;
        uint64_t watermark = 0u;
        ok = qihse_consensus_mesh_read_committed_page(
            mesh, system_operator, index, &entry, 1u, &count, &watermark) &&
             watermark == committed && count == 1u && entry.index == index;
        if (!ok) break;
        if (entry.type == QIHSE_CONSENSUS_ENTRY_DATA) {
            ok = apply_data(store, index, &entry, blobs, system_operator);
        } else if (entry.type >= QIHSE_CONSENSUS_ENTRY_CONFIG_ADD &&
                   entry.type <= QIHSE_CONSENSUS_ENTRY_CONFIG_JOINT_END) {
            ok = qihse_principal_store_apply_committed(
                store, index, nonprincipal, sizeof(nonprincipal)) !=
                QIHSE_PRINCIPAL_APPLY_ERROR;
        } else {
            ok = false;
        }
        if (index == UINT64_MAX) break;
    }
    ok = ok && qihse_consensus_mesh_commit_index(mesh) == committed &&
         qihse_principal_store_applied_index(store) == committed;
    if (!ok) {
        qihse_principal_store_free(store);
        return false;
    }
    *out_store = store;
    return true;
}

bool qihse_principal_startup_replay_snapshot_user(
    qihse_consensus_mesh_t* mesh, qihse_consensus_blob_context_t* blobs,
    qihse_user_t* system_operator, const char* group_id,
    const uint8_t history_id[32], uint64_t writer_epoch_floor,
    qihse_principal_verified_startup_snapshot_t** out_snapshot) {
    if (out_snapshot) *out_snapshot = NULL;
    if (!out_snapshot) return false;
    qihse_principal_store_t* store = NULL;
    if (!qihse_principal_startup_replay_user(
            mesh, blobs, system_operator, group_id, history_id,
            writer_epoch_floor, &store)) return false;
    qihse_principal_verified_startup_snapshot_t* verified =
        calloc(1, sizeof(*verified));
    if (!verified) {
        qihse_principal_store_free(store);
        return false;
    }
    bool ok = qihse_principal_store_export_user(
        store, system_operator, group_id, history_id, &verified->snapshot);
    qihse_principal_store_free(store);
    if (!ok || !verified->snapshot) {
        free(verified);
        return false;
    }
    /* The mesh must still expose the same exact prefix and opened identity
     * after materialization. A concurrent mesh start violates the caller's
     * pre-start contract, but is also refused when observable here. */
    qihse_principal_snapshot_metadata_t metadata;
    qihse_consensus_mesh_identity_t identity;
    ok = qihse_principal_snapshot_metadata_user(
             verified->snapshot, system_operator, &metadata) &&
         qihse_consensus_mesh_history_identity(mesh, &identity) &&
         strcmp(metadata.group_id, identity.group_id) == 0 &&
         CRYPTO_memcmp(metadata.history_id, identity.history_id,
                       sizeof(metadata.history_id)) == 0 &&
         metadata.writer_epoch_floor == identity.writer_epoch_floor &&
         qihse_consensus_mesh_commit_index(mesh) == metadata.applied_index;
    if (!ok) {
        qihse_principal_verified_startup_snapshot_free(verified);
        return false;
    }
    *out_snapshot = verified;
    return true;
}

bool qihse_principal_verified_startup_metadata_user(
    const qihse_principal_verified_startup_snapshot_t* verified,
    const qihse_user_t* requester,
    qihse_principal_snapshot_metadata_t* out_metadata) {
    if (!verified && out_metadata) memset(out_metadata, 0, sizeof(*out_metadata));
    return verified && qihse_principal_snapshot_metadata_user(
        verified->snapshot, requester, out_metadata);
}

bool qihse_principal_verified_startup_visit_user(
    const qihse_principal_verified_startup_snapshot_t* verified,
    const qihse_user_t* requester,
    qihse_principal_snapshot_visit_fn visit, void* opaque) {
    return verified && qihse_principal_snapshot_visit_user(
        verified->snapshot, requester, visit, opaque);
}

void qihse_principal_verified_startup_snapshot_free(
    qihse_principal_verified_startup_snapshot_t* verified) {
    if (!verified) return;
    qihse_principal_snapshot_free(verified->snapshot);
    OPENSSL_cleanse(verified, sizeof(*verified));
    free(verified);
}
