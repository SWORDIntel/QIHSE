#ifndef QIHSE_CONSENSUS_BLOB_H
#define QIHSE_CONSENSUS_BLOB_H

/* Local transaction staging contract for qihse_consensus DATA entries.
 * A 120-byte QBR1 reference fits the consensus payload; the referenced
 * QTX1 blob starts with group, generation, class/SCI and length metadata.
 * This is an internal storage API, not a peer protocol or commit path. */

#include "qihse_blob.h"
#include "qihse_consensus.h"

#define QIHSE_CONSENSUS_BLOB_REF_BYTES 120u
#define QIHSE_CONSENSUS_BLOB_HEADER_BYTES 72u

#if QIHSE_CONSENSUS_BLOB_REF_BYTES > QIHSE_CONSENSUS_PAYLOAD_MAX
#error Consensus blob reference exceeds a consensus entry payload
#endif

typedef struct {
    qihse_blob_store_t* blobs;
    qihse_user_t* principal;
    uint8_t group_hash[QIHSE_BLOB_HASH_BYTES];
} qihse_consensus_blob_context_t;

/* The caller keeps blobs and principal alive for the consensus instance.
 * Only an active system-domain Operator may stage or validate transactions. */
bool qihse_consensus_blob_context_init(qihse_consensus_blob_context_t* context,
                                       qihse_blob_store_t* blobs,
                                       qihse_user_t* principal,
                                       const char* group_id);

/* Confirm the context is for config->group_id, then install a mandatory
 * validator. Call before qihse_consensus_open(). */
bool qihse_consensus_blob_bind_config(qihse_consensus_blob_context_t* context,
                                      qihse_consensus_config_t* config);

/* Persist an envelope plus transaction bytes and emit the reference to put
 * in qihse_consensus_propose(). A zero-length transaction is refused. */
bool qihse_consensus_blob_stage_user(
    qihse_consensus_blob_context_t* context, uint64_t journal_generation,
    uint16_t classification, uint16_t sci, const void* transaction,
    size_t transaction_len,
    uint8_t out_reference[QIHSE_CONSENSUS_BLOB_REF_BYTES]);

/* Import a complete QTX1 blob from a caller-supplied stream before a follower
 * receives the corresponding append. The caller authenticates its peer;
 * this internal function checks the declared reference, performs an
 * authorized durable write, then verifies hash, size, binding and envelope.
 * On failure it drops the reference it added. The reader is not consumed if
 * this node already has a verified copy. read_fn must be a framed source that
 * returns EOF after its declared blob bytes; a raw socket reader can block
 * while this function checks for an extra byte. */
bool qihse_consensus_blob_import_user(qihse_consensus_blob_context_t* context,
                                      const qihse_consensus_entry_t* entry,
                                      qihse_blob_read_fn read_fn,
                                      void* read_opaque);

/* Supply as qihse_consensus_config_t.validate_data on every member. Returns
 * false if the local blob, its full digest, binding, or envelope mismatches. */
bool qihse_consensus_blob_validate(void* context,
                                   const qihse_consensus_entry_t* entry);

#endif /* QIHSE_CONSENSUS_BLOB_H */
