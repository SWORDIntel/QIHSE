#include "qihse_consensus_blob.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

#define QCB_GROUP_OFF 4u
#define QCB_GEN_OFF 52u
#define QCB_CLASS_OFF 60u
#define QCB_SCI_OFF 62u
#define QCB_HASH_OFF 64u
#define QCB_SIZE_OFF 112u
#define QCB_TX_LEN_OFF 64u

typedef struct {
    const uint8_t* header;
    const uint8_t* transaction;
    size_t transaction_len;
    size_t cursor;
} qcb_stream_t;

typedef struct {
    qihse_blob_read_fn source;
    void* source_opaque;
    const qihse_consensus_entry_t* entry;
    const uint8_t* group_hash;
    uint64_t expected_size;
    uint64_t seen;
    uint8_t header[QIHSE_CONSENSUS_BLOB_HEADER_BYTES];
    size_t header_have;
} qcb_import_stream_t;

static void qcb_put_u16(uint8_t* out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void qcb_put_u64(uint8_t* out, uint64_t value) {
    for (unsigned i = 0; i < 8u; i++) out[7u - i] = (uint8_t)(value >> (8u * i));
}

static uint16_t qcb_get_u16(const uint8_t* in) {
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint64_t qcb_get_u64(const uint8_t* in) {
    uint64_t value = 0u;
    for (unsigned i = 0; i < 8u; i++) value = (value << 8) | in[i];
    return value;
}

static bool qcb_system_operator(qihse_user_t* user) {
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    if (!user || qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR) return false;
    qihse_auth_user_active_and_tenant(user, &active, &tenant);
    return active && tenant == QIHSE_TENANT_SYSTEM;
}

static int64_t qcb_stream_read(void* opaque, uint8_t* buffer, size_t capacity) {
    qcb_stream_t* stream = opaque;
    if (!stream || !buffer || capacity == 0u) return -1;
    size_t total = QIHSE_CONSENSUS_BLOB_HEADER_BYTES + stream->transaction_len;
    if (stream->cursor >= total) return 0;
    size_t copied = 0u;
    while (copied < capacity && stream->cursor < total) {
        size_t boundary = QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
        const uint8_t* source;
        size_t available;
        if (stream->cursor < boundary) {
            source = stream->header + stream->cursor;
            available = boundary - stream->cursor;
        } else {
            source = stream->transaction + stream->cursor - boundary;
            available = total - stream->cursor;
        }
        if (available > capacity - copied) available = capacity - copied;
        memcpy(buffer + copied, source, available);
        copied += available;
        stream->cursor += available;
    }
    return (int64_t)copied;
}

static bool qcb_import_header_valid(const qcb_import_stream_t* stream) {
    const uint8_t* header = stream->header;
    return memcmp(header, "QTX1", 4u) == 0 &&
           CRYPTO_memcmp(header + QCB_GROUP_OFF, stream->group_hash,
                         QIHSE_BLOB_HASH_BYTES) == 0 &&
           qcb_get_u64(header + QCB_GEN_OFF) ==
               stream->entry->journal_generation &&
           qcb_get_u16(header + QCB_CLASS_OFF) == stream->entry->classif &&
           qcb_get_u16(header + QCB_SCI_OFF) == stream->entry->sci &&
           qcb_get_u64(header + QCB_TX_LEN_OFF) ==
               stream->expected_size - QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
}

static int64_t qcb_import_read(void* opaque, uint8_t* buffer, size_t capacity) {
    qcb_import_stream_t* stream = opaque;
    if (!stream || !buffer || capacity == 0u) return -1;
    uint64_t remaining = stream->expected_size - stream->seen;
    size_t requested = capacity;
    if ((uint64_t)requested > remaining + 1u) requested = (size_t)(remaining + 1u);
    int64_t read_count = stream->source(stream->source_opaque, buffer, requested);
    if (read_count < 0 || (uint64_t)read_count > requested) return -1;
    if (remaining == 0u) return read_count == 0 ? 0 : -1;
    if (read_count == 0 || (uint64_t)read_count > remaining) return -1;
    if (stream->header_have < sizeof(stream->header)) {
        size_t part = sizeof(stream->header) - stream->header_have;
        if (part > (size_t)read_count) part = (size_t)read_count;
        memcpy(stream->header + stream->header_have, buffer, part);
        stream->header_have += part;
        if (stream->header_have == sizeof(stream->header) &&
            !qcb_import_header_valid(stream)) return -1;
    }
    stream->seen += (uint64_t)read_count;
    return read_count;
}

bool qihse_consensus_blob_context_init(qihse_consensus_blob_context_t* context,
                                       qihse_blob_store_t* blobs,
                                       qihse_user_t* principal,
                                       const char* group_id) {
    if (!context) return false;
    memset(context, 0, sizeof(*context));
    if (!blobs || !qcb_system_operator(principal) || !group_id) return false;
    size_t len = 0u;
    while (len <= QIHSE_CONSENSUS_GROUP_ID_MAX && group_id[len]) {
        unsigned char c = (unsigned char)group_id[len];
        if (c < 0x20u || c == 0x7fu) return false;
        len++;
    }
    if (len == 0u || len > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    if (!SHA384((const unsigned char*)group_id, len, hash)) return false;
    context->blobs = blobs;
    context->principal = principal;
    memcpy(context->group_hash, hash, sizeof(hash));
    return true;
}

bool qihse_consensus_blob_bind_config(qihse_consensus_blob_context_t* context,
                                      qihse_consensus_config_t* config) {
    if (!context || !context->blobs || !config ||
        !qcb_system_operator(context->principal)) return false;
    size_t len = 0u;
    while (len <= QIHSE_CONSENSUS_GROUP_ID_MAX && config->group_id[len]) len++;
    if (len == 0u || len > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    if (!SHA384((const unsigned char*)config->group_id, len, hash) ||
        CRYPTO_memcmp(hash, context->group_hash, sizeof(hash)) != 0) return false;
    config->validate_data = qihse_consensus_blob_validate;
    config->validate_data_context = context;
    config->require_data_validator = true;
    return true;
}

bool qihse_consensus_blob_stage_user(
    qihse_consensus_blob_context_t* context, uint64_t journal_generation,
    uint16_t classification, uint16_t sci, const void* transaction,
    size_t transaction_len,
    uint8_t out_reference[QIHSE_CONSENSUS_BLOB_REF_BYTES]) {
    if (!context || !context->blobs || !out_reference || !transaction ||
        transaction_len == 0u || journal_generation == 0u ||
        transaction_len > QIHSE_BLOB_MAX_SIZE - QIHSE_CONSENSUS_BLOB_HEADER_BYTES ||
        !qcb_system_operator(context->principal) ||
        !qihse_auth_can_access(context->principal, classification, sci)) return false;

    uint8_t header[QIHSE_CONSENSUS_BLOB_HEADER_BYTES] = {0};
    memcpy(header, "QTX1", 4u);
    memcpy(header + QCB_GROUP_OFF, context->group_hash, QIHSE_BLOB_HASH_BYTES);
    qcb_put_u64(header + QCB_GEN_OFF, journal_generation);
    qcb_put_u16(header + QCB_CLASS_OFF, classification);
    qcb_put_u16(header + QCB_SCI_OFF, sci);
    qcb_put_u64(header + QCB_TX_LEN_OFF, (uint64_t)transaction_len);

    qcb_stream_t stream = {header, transaction, transaction_len, 0u};
    uint8_t blob_hash[QIHSE_BLOB_HASH_BYTES];
    uint64_t blob_size = 0u;
    if (!qihse_blob_put_user(context->blobs, QIHSE_TENANT_SYSTEM,
            QIHSE_BLOB_TAG_REPL_TRANSACTION, classification, sci,
            context->principal, qcb_stream_read, &stream, blob_hash,
            &blob_size) ||
        blob_size != (uint64_t)transaction_len + sizeof(header)) return false;

    uint8_t reference[QIHSE_CONSENSUS_BLOB_REF_BYTES] = {0};
    memcpy(reference, "QBR1", 4u);
    memcpy(reference + QCB_GROUP_OFF, context->group_hash, QIHSE_BLOB_HASH_BYTES);
    qcb_put_u64(reference + QCB_GEN_OFF, journal_generation);
    qcb_put_u16(reference + QCB_CLASS_OFF, classification);
    qcb_put_u16(reference + QCB_SCI_OFF, sci);
    memcpy(reference + QCB_HASH_OFF, blob_hash, sizeof(blob_hash));
    qcb_put_u64(reference + QCB_SIZE_OFF, blob_size);
    memcpy(out_reference, reference, sizeof(reference));
    return true;
}

static bool qcb_reference_matches(qihse_consensus_blob_context_t* context,
                                  const qihse_consensus_entry_t* entry) {
    if (!context || !context->blobs || !entry ||
        entry->type != QIHSE_CONSENSUS_ENTRY_DATA ||
        entry->payload_len != QIHSE_CONSENSUS_BLOB_REF_BYTES ||
        !qcb_system_operator(context->principal) ||
        !qihse_auth_can_access(context->principal, entry->classif, entry->sci)) return false;

    const uint8_t* reference = entry->payload;
    if (memcmp(reference, "QBR1", 4u) != 0 ||
        CRYPTO_memcmp(reference + QCB_GROUP_OFF, context->group_hash,
                      QIHSE_BLOB_HASH_BYTES) != 0 ||
        qcb_get_u64(reference + QCB_GEN_OFF) != entry->journal_generation ||
        qcb_get_u16(reference + QCB_CLASS_OFF) != entry->classif ||
        qcb_get_u16(reference + QCB_SCI_OFF) != entry->sci) return false;

    uint64_t expected_size = qcb_get_u64(reference + QCB_SIZE_OFF);
    return expected_size > QIHSE_CONSENSUS_BLOB_HEADER_BYTES &&
           expected_size <= QIHSE_BLOB_MAX_SIZE;
}

bool qihse_consensus_blob_validate(void* opaque,
                                   const qihse_consensus_entry_t* entry) {
    qihse_consensus_blob_context_t* context = opaque;
    if (!qcb_reference_matches(context, entry)) return false;

    const uint8_t* reference = entry->payload;
    const uint8_t* blob_hash = reference + QCB_HASH_OFF;
    uint64_t expected_size = qcb_get_u64(reference + QCB_SIZE_OFF);
    qihse_blob_info_t info;
    uint8_t header[QIHSE_CONSENSUS_BLOB_HEADER_BYTES];
    if (!qihse_blob_verify_with_info_user(context->blobs, blob_hash,
            context->principal, &info, header, sizeof(header))) return false;
    return info.tenant_id == QIHSE_TENANT_SYSTEM &&
           info.tag == QIHSE_BLOB_TAG_REPL_TRANSACTION &&
           info.classification == entry->classif &&
           info.sci_compartment == entry->sci &&
           info.size == expected_size &&
           memcmp(header, "QTX1", 4u) == 0 &&
           CRYPTO_memcmp(header + QCB_GROUP_OFF, context->group_hash,
                         QIHSE_BLOB_HASH_BYTES) == 0 &&
           qcb_get_u64(header + QCB_GEN_OFF) == entry->journal_generation &&
           qcb_get_u16(header + QCB_CLASS_OFF) == entry->classif &&
           qcb_get_u16(header + QCB_SCI_OFF) == entry->sci &&
           qcb_get_u64(header + QCB_TX_LEN_OFF) ==
               expected_size - QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
}

bool qihse_consensus_blob_import_user(qihse_consensus_blob_context_t* context,
                                      const qihse_consensus_entry_t* entry,
                                      qihse_blob_read_fn read_fn,
                                      void* read_opaque) {
    if (!read_fn || !qcb_reference_matches(context, entry)) return false;
    if (qihse_consensus_blob_validate(context, entry)) return true;

    const uint8_t* reference = entry->payload;
    qcb_import_stream_t stream = {
        .source = read_fn,
        .source_opaque = read_opaque,
        .entry = entry,
        .group_hash = context->group_hash,
        .expected_size = qcb_get_u64(reference + QCB_SIZE_OFF)
    };
    if (!qihse_blob_put_expected_user(context->blobs, QIHSE_TENANT_SYSTEM,
            QIHSE_BLOB_TAG_REPL_TRANSACTION, entry->classif, entry->sci,
            context->principal, qcb_import_read, &stream,
            reference + QCB_HASH_OFF, stream.expected_size)) return false;

    bool valid = qihse_consensus_blob_validate(context, entry);
    if (!valid) (void)qihse_blob_delete_user(context->blobs,
                    reference + QCB_HASH_OFF, context->principal);
    return valid;
}

bool qihse_consensus_blob_read_committed_transaction_user(
    qihse_consensus_blob_context_t* context,
    const qihse_consensus_t* consensus, qihse_user_t* user,
    uint64_t index, uint8_t* out, size_t out_cap, size_t* out_len) {
    if (out_len) *out_len = 0u;
    if (!context || !context->blobs || !consensus || !out || !out_len ||
        index == 0u || !qcb_system_operator(user) ||
        !qcb_system_operator(context->principal)) return false;

    qihse_consensus_entry_t entry;
    size_t count = 0u;
    if (!qihse_consensus_read_committed_exact(consensus, user, index,
                                               &entry, 1u, &count) ||
        count != 1u || entry.index != index ||
        !qcb_reference_matches(context, &entry)) return false;

    const uint8_t* reference = entry.payload;
    const uint8_t* hash = reference + QCB_HASH_OFF;
    uint64_t expected_size = qcb_get_u64(reference + QCB_SIZE_OFF);
    uint64_t tx_size = expected_size - QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
    if (tx_size > out_cap || expected_size > SIZE_MAX) return false;

    qihse_blob_info_t info;
    uint8_t header[QIHSE_CONSENSUS_BLOB_HEADER_BYTES];
    if (!qihse_blob_verify_with_info_user(context->blobs, hash, user,
            &info, header, sizeof(header)) ||
        info.tenant_id != QIHSE_TENANT_SYSTEM ||
        info.tag != QIHSE_BLOB_TAG_REPL_TRANSACTION ||
        info.classification != entry.classif ||
        info.sci_compartment != entry.sci ||
        info.size != expected_size ||
        memcmp(header, "QTX1", 4u) != 0 ||
        CRYPTO_memcmp(header + QCB_GROUP_OFF, context->group_hash,
                      QIHSE_BLOB_HASH_BYTES) != 0 ||
        qcb_get_u64(header + QCB_GEN_OFF) != entry.journal_generation ||
        qcb_get_u16(header + QCB_CLASS_OFF) != entry.classif ||
        qcb_get_u16(header + QCB_SCI_OFF) != entry.sci ||
        qcb_get_u64(header + QCB_TX_LEN_OFF) != tx_size) return false;

    uint8_t* complete = malloc((size_t)expected_size);
    if (!complete) return false;
    bool ok = true;
    size_t offset = 0u;
    while (ok && offset < (size_t)expected_size) {
        size_t wanted = (size_t)expected_size - offset;
        if (wanted > 65536u) wanted = 65536u;
        size_t got = 0u;
        ok = qihse_blob_get_user(context->blobs, hash, (uint64_t)offset,
                                 complete + offset, wanted, &got, user) &&
             got > 0u && got <= wanted;
        if (ok) offset += got;
    }
    uint8_t actual[QIHSE_BLOB_HASH_BYTES];
    if (ok) ok = SHA384(complete, (size_t)expected_size, actual) != NULL &&
                 CRYPTO_memcmp(actual, hash, sizeof(actual)) == 0 &&
                 CRYPTO_memcmp(complete, header, sizeof(header)) == 0;
    if (ok) {
        memcpy(out, complete + sizeof(header), (size_t)tx_size);
        *out_len = (size_t)tx_size;
    }
    OPENSSL_cleanse(complete, (size_t)expected_size);
    free(complete);
    OPENSSL_cleanse(actual, sizeof(actual));
    return ok;
}
