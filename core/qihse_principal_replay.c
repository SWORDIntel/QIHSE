#include "qihse_principal_replay.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

/* This is deliberately a bounded startup path. Until transactions have a
 * typed envelope, a non-principal DATA transaction must be read in full to
 * distinguish it from a malformed principal record. Oversize means fail
 * closed, never skip a committed index. */
#define REPLAY_TRANSACTION_MAX (16u * 1024u * 1024u)

bool qihse_principal_replay_committed_prefix(
    qihse_principal_store_t* store, const qihse_consensus_t* consensus,
    qihse_consensus_blob_context_t* blobs, qihse_user_t* system_operator,
    uint64_t through_index) {
    if (!store || !consensus || !blobs || !system_operator ||
        qihse_auth_is_operator_password_default() ||
        through_index > qihse_consensus_commit_index(consensus) ||
        qihse_principal_store_applied_index(store) != 0u) return false;

    uint8_t* transaction = malloc(REPLAY_TRANSACTION_MAX);
    if (!transaction) return false;
    bool ok = true;
    static const uint8_t nonprincipal[] = {0};
    for (uint64_t index = 1u; ok && index <= through_index; index++) {
        qihse_consensus_entry_t entry;
        size_t count = 0u;
        if (!qihse_consensus_read_committed_exact(consensus, system_operator,
                                                   index, &entry, 1u, &count) ||
            count != 1u || entry.index != index) {
            ok = false;
            break;
        }
        const uint8_t* payload = nonprincipal;
        size_t payload_len = sizeof(nonprincipal);
        size_t transaction_len = 0u;
        if (entry.type == QIHSE_CONSENSUS_ENTRY_DATA) {
            if (!qihse_consensus_blob_read_committed_transaction_user(
                    blobs, consensus, system_operator, index, transaction,
                    REPLAY_TRANSACTION_MAX, &transaction_len)) {
                ok = false;
                break;
            }
            /* A future/garbled QPR version cannot become an unrelated
             * transaction no-op merely by changing its version byte. */
            if (transaction_len >= 3u &&
                memcmp(transaction, "QPR", 3u) == 0) {
                qihse_principal_record_t decoded;
                if (!qihse_principal_record_decode(transaction,
                                                   transaction_len, &decoded)) {
                    ok = false;
                    break;
                }
                OPENSSL_cleanse(&decoded, sizeof(decoded));
                payload = transaction;
                payload_len = transaction_len;
            }
        } else if (entry.type < QIHSE_CONSENSUS_ENTRY_CONFIG_ADD ||
                   entry.type > QIHSE_CONSENSUS_ENTRY_CONFIG_JOINT_END) {
            ok = false;
            break;
        }
        if (qihse_principal_store_apply_committed(store, index, payload,
                                                   payload_len) ==
            QIHSE_PRINCIPAL_APPLY_ERROR) ok = false;
        if (transaction_len) OPENSSL_cleanse(transaction, transaction_len);
        if (index == UINT64_MAX) break;
    }
    OPENSSL_cleanse(transaction, REPLAY_TRANSACTION_MAX);
    free(transaction);
    return ok && qihse_principal_store_applied_index(store) == through_index;
}
