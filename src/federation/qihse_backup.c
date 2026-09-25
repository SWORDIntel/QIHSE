/*
 * QIHSE federation backup writer and reader — the data a snapshot manifest
 * refers to, plus the bounded WAL run that follows it.  See
 * docs/plans/qihse_federation_upgrade_plan.md §20, §21, §23.
 *
 * A manifest is a claim; this makes the claim true and refuses to pretend
 * otherwise.  Rules worth restating where the code enforces them:
 *
 *   - The security context is mandatory and is propagated to the KV layer
 *     rather than re-implemented here (AGENTS.md invariant 1).  The KV layer
 *     is the only code that knows a record's classification, so it is the
 *     only code that can decide whether this principal may export or import
 *     it — and it decides all-or-nothing, which is what keeps a denied
 *     backup from being a partially disclosed one (invariant 2).
 *
 *   - Verification precedes application.  The manifest checksum is checked
 *     before the container is opened, the signature is checked before any
 *     payload byte is read, the container's SHA-384s are checked before the
 *     KV layer is handed anything, the WAL section is validated whole before
 *     the dataset is replaced, and the KV load is transactional, so a
 *     truncated, edited or unauthorized restore leaves the live dataset
 *     exactly as it was.
 *
 * This is the v3 container.  Version history (the version field sits inside
 * the signed region, so a version edit invalidates the signature):
 *
 *   v1  unsigned, integrity-only          — retired; no writer, no reader
 *   v2  signed, no WAL section            — retired; no writer, no reader
 *   v3  signed + bounded WAL section      — this file
 *
 * The v3 file layout is
 *
 *   [ header 464 ][ signature ][ data section ][ WAL section ]
 *
 * The signature covers exactly the 464 header bytes, which carry the
 * manifest checksum, the data section's SHA-384, the WAL section's SHA-384
 * and length, the WAL LSN range and the signer identity — so one detached
 * signature authenticates everything integrity-bearing at once, and every
 * payload byte sits AFTER the signature so a reader can refuse a forged
 * container before reading it.
 */
#include "qihse_backup.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_federation.h"
#include "qihse_wal.h"

/* ── Result vocabulary ─────────────────────────────────────────────────── */

typedef struct { qihse_backup_result_t v; const char* name; } backup_result_entry_t;

static const backup_result_entry_t g_backup_results[] = {
    { QIHSE_BACKUP_OK,                    "ok"                    },
    { QIHSE_BACKUP_ERR_ARGUMENT,          "argument"              },
    { QIHSE_BACKUP_ERR_DENIED,            "denied"                },
    { QIHSE_BACKUP_ERR_MANIFEST,          "manifest"              },
    { QIHSE_BACKUP_ERR_TRUNCATED,         "truncated"             },
    { QIHSE_BACKUP_ERR_CHECKSUM,          "checksum"              },
    { QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH, "snapshot_mismatch"     },
    { QIHSE_BACKUP_ERR_WAL_POINT,         "wal_point"             },
    { QIHSE_BACKUP_ERR_COVERAGE,          "coverage"              },
    { QIHSE_BACKUP_ERR_KEY_MATERIAL,      "key_material"          },
    { QIHSE_BACKUP_ERR_IO,                "io"                    },
    { QIHSE_BACKUP_ERR_SIGNER,            "signer"                },
    { QIHSE_BACKUP_ERR_SIGNATURE,         "signature"             },
    { QIHSE_BACKUP_ERR_VERSION,           "version"               },
};

const char* qihse_backup_result_name(qihse_backup_result_t r) {
    for (size_t i = 0; i < sizeof(g_backup_results) / sizeof(g_backup_results[0]); i++) {
        if (g_backup_results[i].v == r) return g_backup_results[i].name;
    }
    return "unknown";
}

/* One writer per process is enough: the container is assembled through temp
 * files in a caller-named directory, and two writers racing on the same path
 * would fight over the rename.  The KV layer keeps its own locking; this
 * covers only the container. */
static pthread_mutex_t g_backup_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Container layout ──────────────────────────────────────────────────── */

/* Fixed-size header, little-endian, so the data section's offset never
 * depends on a variable-length field and a truncated container is detectable
 * by comparing the declared length with the file's actual size:
 *
 *    0   magic "QIHSEBK1"                     8
 *    8   version (3)                          4
 *   12   reserved (0)                         4
 *   16   snapshot_id                         16
 *   32   wal_continuation_offset              8
 *   40   max_generation                       8
 *   48   object_count                         8
 *   56   data_bytes                           8
 *   64   manifest_checksum                   48
 *  112   data_checksum                       48
 *  160   encryption_key_id (NUL-terminated) 128
 *  288   schema_id                            4
 *  292   schema_version                       4
 *  296   minimum_reader_version               4
 *  300   reserved (0)                         4
 *  304   required_features                    8
 *  312   optional_features                    8
 *  320   signer_node_id                      16
 *  336   signer_fingerprint                  48   (SHA-384 of the enrolled public key)
 *  384   sig_alg                              4
 *  388   signature_len                        4   (the algorithm's fixed size)
 *  392   wal_bytes                            8   (length of the WAL section)
 *  400   wal_checksum                        48   (SHA-384 over the WAL section)
 *  448   wal_first_lsn                        8   (first record's LSN; 0 iff empty)
 *  456   wal_last_lsn                         8   (last record's LSN; 0 iff empty)
 *  464   end of the header
 *
 * Everything from byte 0 to 464 is the SIGNED region.  The v1 and v2 fields
 * keep their historical offsets, so no older field can be reinterpreted by
 * version — but those versions are retired outright: a container whose
 * version is not 3 is refused with QIHSE_BACKUP_ERR_VERSION, never decoded
 * with whichever checks an older layout could still run.
 */
#define BACKUP_OFF_MAGIC        0u
#define BACKUP_OFF_VERSION      8u
#define BACKUP_OFF_RESERVED     12u
#define BACKUP_OFF_SNAPSHOT_ID  16u
#define BACKUP_OFF_WAL          32u
#define BACKUP_OFF_MAX_GEN      40u
#define BACKUP_OFF_OBJECTS      48u
#define BACKUP_OFF_DATA_BYTES   56u
#define BACKUP_OFF_MANIFEST_CK  64u
#define BACKUP_OFF_DATA_CK      112u
#define BACKUP_OFF_KEY_ID       160u
#define BACKUP_OFF_SCHEMA_ID    288u
#define BACKUP_OFF_SCHEMA_VER   292u
#define BACKUP_OFF_SCHEMA_MIN   296u
#define BACKUP_OFF_RESERVED2    300u
#define BACKUP_OFF_SCHEMA_REQ   304u
#define BACKUP_OFF_SCHEMA_OPT   312u
#define BACKUP_OFF_SIGNER_NODE  320u
#define BACKUP_OFF_SIGNER_FP    336u
#define BACKUP_OFF_SIG_ALG      384u
#define BACKUP_OFF_SIG_LEN      388u
#define BACKUP_OFF_WAL_BYTES    392u
#define BACKUP_OFF_WAL_CK       400u
#define BACKUP_OFF_WAL_FIRST    448u
#define BACKUP_OFF_WAL_LAST     456u

#define BACKUP_CK_BYTES 48u
#define BACKUP_KEY_ID_BYTES (QIHSE_BACKUP_KEY_ID_MAX + 1u)
#define BACKUP_PATH_MAX 2048u

/* One reusable heap buffer for every copy, never one array element per
 * record (AGENTS.md: bounded stack frames). */
#define BACKUP_COPY_CHUNK (64u * 1024u)

static void backup_put_bytes(uint8_t* out, size_t off, const void* src, size_t n) {
    memcpy(out + off, src, n);
}

static void backup_get_bytes(const uint8_t* in, size_t off, void* dst, size_t n) {
    memcpy(dst, in + off, n);
}

/* The common snapshot fields, offsets 0..320 — the region every container
 * version has shared since v1, so no field can move between versions. */
static void backup_encode_common(const qihse_backup_descriptor_t* d,
                                 uint8_t* out) {
    uint32_t zero = 0u;
    uint32_t schema_id = d->schema.schema_id;
    uint32_t schema_version = d->schema.schema_version;
    uint32_t schema_min = d->schema.minimum_reader_version;

    backup_put_bytes(out, BACKUP_OFF_MAGIC, QIHSE_BACKUP_MAGIC, QIHSE_BACKUP_MAGIC_LEN);
    backup_put_bytes(out, BACKUP_OFF_RESERVED, &zero, 4u);
    backup_put_bytes(out, BACKUP_OFF_SNAPSHOT_ID, d->snapshot_id.bytes, QIHSE_UUID_BYTES);
    backup_put_bytes(out, BACKUP_OFF_WAL, &d->wal_continuation_offset, 8u);
    backup_put_bytes(out, BACKUP_OFF_MAX_GEN, &d->max_generation, 8u);
    backup_put_bytes(out, BACKUP_OFF_OBJECTS, &d->object_count, 8u);
    backup_put_bytes(out, BACKUP_OFF_DATA_BYTES, &d->data_bytes, 8u);
    backup_put_bytes(out, BACKUP_OFF_MANIFEST_CK, d->manifest_checksum, BACKUP_CK_BYTES);
    backup_put_bytes(out, BACKUP_OFF_DATA_CK, d->data_checksum, BACKUP_CK_BYTES);
    backup_put_bytes(out, BACKUP_OFF_KEY_ID, d->encryption_key_id,
                     strlen(d->encryption_key_id));
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_ID, &schema_id, 4u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_VER, &schema_version, 4u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_MIN, &schema_min, 4u);
    backup_put_bytes(out, BACKUP_OFF_RESERVED2, &zero, 4u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_REQ, &d->schema.required_features, 8u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_OPT, &d->schema.optional_features, 8u);
}

/* The v3 encoder.  The signature length written is DERIVED from the
 * algorithm — the algorithm's fixed size is the only length a container may
 * declare. */
static void backup_encode_header(const qihse_backup_descriptor_t* d,
                                 uint8_t out[QIHSE_BACKUP_HEADER_WAL_BYTES]) {
    uint32_t version = QIHSE_BACKUP_VERSION_WAL;
    uint32_t sig_alg = (uint32_t)d->sig_alg;
    uint32_t sig_len = (uint32_t)qihse_sig_alg_signature_bytes(d->sig_alg);

    /* The zeroed tail also NUL-terminates the key id field. */
    memset(out, 0, QIHSE_BACKUP_HEADER_WAL_BYTES);
    backup_encode_common(d, out);
    backup_put_bytes(out, BACKUP_OFF_VERSION, &version, 4u);
    backup_put_bytes(out, BACKUP_OFF_SIGNER_NODE, d->signer_node.bytes, QIHSE_UUID_BYTES);
    backup_put_bytes(out, BACKUP_OFF_SIGNER_FP, d->signer_fingerprint,
                     QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES);
    backup_put_bytes(out, BACKUP_OFF_SIG_ALG, &sig_alg, 4u);
    backup_put_bytes(out, BACKUP_OFF_SIG_LEN, &sig_len, 4u);
    backup_put_bytes(out, BACKUP_OFF_WAL_BYTES, &d->wal_bytes, 8u);
    backup_put_bytes(out, BACKUP_OFF_WAL_CK, d->wal_checksum, BACKUP_CK_BYTES);
    backup_put_bytes(out, BACKUP_OFF_WAL_FIRST, &d->wal_first_lsn, 8u);
    backup_put_bytes(out, BACKUP_OFF_WAL_LAST, &d->wal_last_lsn, 8u);
}

/* A decoder must refuse a container it could not have written.  Every field
 * is validated against the bytes actually present, so a malformed or hostile
 * container is rejected rather than half-interpreted.  A wrong VERSION is
 * reported by the caller as QIHSE_BACKUP_ERR_VERSION (it peeks the version
 * field when this returns false). */
static bool backup_decode_header(const uint8_t* in, size_t in_len,
                                 qihse_backup_descriptor_t* out) {
    if (!in || in_len < QIHSE_BACKUP_HEADER_WAL_BYTES) return false;
    uint32_t version = 0u, reserved = 0u, reserved2 = 0u;
    uint32_t sig_alg_raw = 0u, sig_len_raw = 0u;
    if (memcmp(in + BACKUP_OFF_MAGIC, QIHSE_BACKUP_MAGIC, QIHSE_BACKUP_MAGIC_LEN) != 0) {
        return false;
    }
    backup_get_bytes(in, BACKUP_OFF_VERSION, &version, 4u);
    if (version != QIHSE_BACKUP_VERSION_WAL) return false;
    backup_get_bytes(in, BACKUP_OFF_RESERVED, &reserved, 4u);
    backup_get_bytes(in, BACKUP_OFF_RESERVED2, &reserved2, 4u);
    if (reserved != 0u || reserved2 != 0u) return false;

    memset(out, 0, sizeof(*out));
    backup_get_bytes(in, BACKUP_OFF_SNAPSHOT_ID, out->snapshot_id.bytes, QIHSE_UUID_BYTES);
    backup_get_bytes(in, BACKUP_OFF_WAL, &out->wal_continuation_offset, 8u);
    backup_get_bytes(in, BACKUP_OFF_MAX_GEN, &out->max_generation, 8u);
    backup_get_bytes(in, BACKUP_OFF_OBJECTS, &out->object_count, 8u);
    backup_get_bytes(in, BACKUP_OFF_DATA_BYTES, &out->data_bytes, 8u);
    backup_get_bytes(in, BACKUP_OFF_MANIFEST_CK, out->manifest_checksum, BACKUP_CK_BYTES);
    backup_get_bytes(in, BACKUP_OFF_DATA_CK, out->data_checksum, BACKUP_CK_BYTES);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_ID, &out->schema.schema_id, 4u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_VER, &out->schema.schema_version, 4u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_MIN, &out->schema.minimum_reader_version, 4u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_REQ, &out->schema.required_features, 8u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_OPT, &out->schema.optional_features, 8u);

    backup_get_bytes(in, BACKUP_OFF_SIGNER_NODE, out->signer_node.bytes, QIHSE_UUID_BYTES);
    if (qihse_uuid_is_nil(&out->signer_node)) return false;
    backup_get_bytes(in, BACKUP_OFF_SIGNER_FP, out->signer_fingerprint,
                     QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES);
    backup_get_bytes(in, BACKUP_OFF_SIG_ALG, &sig_alg_raw, 4u);
    if (sig_alg_raw > (uint32_t)QIHSE_SIG_ML_DSA_87) return false;
    out->sig_alg = (qihse_sig_alg_t)sig_alg_raw;
    backup_get_bytes(in, BACKUP_OFF_SIG_LEN, &sig_len_raw, 4u);
    /* Declared length versus the algorithm's fixed size: a truncated or
     * padded signature is rejected before any crypto runs, the same contract
     * qihse_federation_verify() enforces on its own inputs. */
    if (sig_len_raw == 0u ||
        (size_t)sig_len_raw != qihse_sig_alg_signature_bytes(out->sig_alg)) {
        return false;
    }

    /* The WAL block.  The declared length is bounded by the format (a
     * decoder must refuse what no writer of this format could produce), and
     * an absent section claims no LSNs: declared, encoded and structural
     * views of the section must agree.  The bytes-actually-present half of
     * wal_bytes is checked against the file size by the caller. */
    backup_get_bytes(in, BACKUP_OFF_WAL_BYTES, &out->wal_bytes, 8u);
    backup_get_bytes(in, BACKUP_OFF_WAL_CK, out->wal_checksum, BACKUP_CK_BYTES);
    backup_get_bytes(in, BACKUP_OFF_WAL_FIRST, &out->wal_first_lsn, 8u);
    backup_get_bytes(in, BACKUP_OFF_WAL_LAST, &out->wal_last_lsn, 8u);
    if (out->wal_bytes > (uint64_t)QIHSE_BACKUP_WAL_SECTION_MAX) return false;
    if (out->wal_bytes == 0u) {
        if (out->wal_first_lsn != 0u || out->wal_last_lsn != 0u) return false;
    } else {
        if (out->wal_first_lsn == 0u || out->wal_last_lsn < out->wal_first_lsn) return false;
    }
    return true;
}

/* The manifest carries a key ID and nothing else (plan §20, §21).  A backup
 * is the one artefact where a key mistake is unrecoverable, so a value that
 * looks like key material is refused here rather than copied.  An empty key
 * id records a backup the snapshot itself declared unencrypted. */
static bool backup_key_id_is_identifier(const char* id) {
    if (!id) return false;
    size_t n = strlen(id);
    if (n > QIHSE_BACKUP_KEY_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (c < 0x20u || c == 0x7Fu) return false;
    }
    if (strstr(id, "-----BEGIN") != NULL) return false;
    if (strstr(id, "PRIVATE KEY") != NULL) return false;
    return true;
}

/* ── WAL section codec ─────────────────────────────────────────────────── */
/*
 * A record mirrors the tractable WAL's guarantees with the two fields the
 * KV layer needs to preserve classification through a replay:
 *
 *    0   lsn                    8   (nonzero, strictly increasing in-section)
 *    8   txn_id                 8
 *   16   engine_id              1
 *   17   op_type                1   (qihse_wal_op_t)
 *   18   classification         2
 *   20   sci_compartment       2
 *   22   key_length             4   (<= QIHSE_WAL_MAX_KEY)
 *   26   value_length           4   (<= QIHSE_WAL_MAX_VALUE)
 *   30   reserved (0)           2
 *   32   checksum               4   (CRC32, the qihse_wal composition)
 *   36   -> key[key_length] value[value_length]
 *
 * The checksum uses qihse_wal_crc32 over each field and over the key and
 * value, XOR-combined — exactly the composition src/tractable/qihse_wal.c
 * uses for its own records — extended over the classification fields, so a
 * tampered classification is caught per-record as well as by the section
 * digest and the signature.
 */
#define BWAL_OFF_LSN       0u
#define BWAL_OFF_TXN       8u
#define BWAL_OFF_ENGINE    16u
#define BWAL_OFF_OP        17u
#define BWAL_OFF_CLASSIF   18u
#define BWAL_OFF_SCI       20u
#define BWAL_OFF_KEY_LEN   22u
#define BWAL_OFF_VAL_LEN   26u
#define BWAL_OFF_RESERVED  30u
#define BWAL_OFF_CRC       32u

typedef struct {
    uint64_t lsn;
    uint64_t txn_id;
    uint8_t  engine_id;
    uint8_t  op_type;
    uint16_t classification;
    uint16_t sci;
    uint32_t key_length;
    uint32_t value_length;
    size_t   total_bytes;   /* header + key + value */
} backup_wal_record_t;

static uint32_t backup_wal_record_crc(const backup_wal_record_t* rec,
                                      const uint8_t* key, const uint8_t* value) {
    uint16_t reserved = 0u;
    uint32_t crc = 0u;
    crc ^= qihse_wal_crc32(&rec->lsn, 8u);
    crc ^= qihse_wal_crc32(&rec->txn_id, 8u);
    crc ^= qihse_wal_crc32(&rec->engine_id, 1u);
    crc ^= qihse_wal_crc32(&rec->op_type, 1u);
    crc ^= qihse_wal_crc32(&rec->classification, 2u);
    crc ^= qihse_wal_crc32(&rec->sci, 2u);
    crc ^= qihse_wal_crc32(&rec->key_length, 4u);
    crc ^= qihse_wal_crc32(&rec->value_length, 4u);
    crc ^= qihse_wal_crc32(&reserved, 2u);
    if (rec->key_length > 0u && key) {
        crc ^= qihse_wal_crc32(key, rec->key_length);
    }
    if (rec->value_length > 0u && value) {
        crc ^= qihse_wal_crc32(value, rec->value_length);
    }
    return crc;
}

static bool backup_wal_op_is_known(uint8_t op) {
    return op == (uint8_t)QIHSE_WAL_OP_INSERT ||
           op == (uint8_t)QIHSE_WAL_OP_UPDATE ||
           op == (uint8_t)QIHSE_WAL_OP_DELETE ||
           op == (uint8_t)QIHSE_WAL_OP_BEGIN ||
           op == (uint8_t)QIHSE_WAL_OP_COMMIT ||
           op == (uint8_t)QIHSE_WAL_OP_ABORT ||
           op == (uint8_t)QIHSE_WAL_OP_CHECKPOINT;
}

/* Keys and values are applied through the KV layer's C-string primitives,
 * so a record that could not survive that hop honestly (an embedded NUL, an
 * empty key, a DELETE carrying a value) is refused rather than truncated
 * into place. */
static bool backup_wal_bytes_are_string(const uint8_t* p, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        if (p[i] == 0u) return false;
    }
    return true;
}

/* Decode and fully validate the record at section offset `off`.  Returns
 * false for anything a correct encoder could not have written: a short
 * header, a nonzero reserved field, an unknown op, an out-of-bounds or
 * NUL-bearing key/value, a DELETE with a value, a fence record carrying a
 * payload shape the tractable WAL never produces, an LSN of zero, a
 * record that overruns the section, or a CRC mismatch. */
static bool backup_wal_record_decode(const uint8_t* section, size_t len, size_t off,
                                     backup_wal_record_t* rec) {
    if (!section || !rec || off > len || len - off < QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES) {
        return false;
    }
    const uint8_t* hdr = section + off;
    uint16_t reserved = 0u;
    uint32_t crc_stored = 0u;

    memset(rec, 0, sizeof(*rec));
    backup_get_bytes(hdr, BWAL_OFF_LSN, &rec->lsn, 8u);
    backup_get_bytes(hdr, BWAL_OFF_TXN, &rec->txn_id, 8u);
    rec->engine_id = hdr[BWAL_OFF_ENGINE];
    rec->op_type = hdr[BWAL_OFF_OP];
    backup_get_bytes(hdr, BWAL_OFF_CLASSIF, &rec->classification, 2u);
    backup_get_bytes(hdr, BWAL_OFF_SCI, &rec->sci, 2u);
    backup_get_bytes(hdr, BWAL_OFF_KEY_LEN, &rec->key_length, 4u);
    backup_get_bytes(hdr, BWAL_OFF_VAL_LEN, &rec->value_length, 4u);
    backup_get_bytes(hdr, BWAL_OFF_RESERVED, &reserved, 2u);
    backup_get_bytes(hdr, BWAL_OFF_CRC, &crc_stored, 4u);

    if (reserved != 0u) return false;
    if (!backup_wal_op_is_known(rec->op_type)) return false;
    if (rec->lsn == QIHSE_WAL_INVALID_LSN) return false;
    if (rec->key_length > (uint32_t)QIHSE_WAL_MAX_KEY) return false;
    if (rec->value_length > (uint32_t)QIHSE_WAL_MAX_VALUE) return false;

    /* Declared lengths versus the bytes actually present. */
    uint64_t total = (uint64_t)QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES +
                     (uint64_t)rec->key_length + (uint64_t)rec->value_length;
    if (total > (uint64_t)(len - off)) return false;
    rec->total_bytes = (size_t)total;

    const uint8_t* key = hdr + QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES;
    const uint8_t* value = key + rec->key_length;

    if (rec->op_type == (uint8_t)QIHSE_WAL_OP_INSERT ||
        rec->op_type == (uint8_t)QIHSE_WAL_OP_UPDATE) {
        if (rec->key_length == 0u) return false;
        if (!backup_wal_bytes_are_string(key, rec->key_length)) return false;
        if (!backup_wal_bytes_are_string(value, rec->value_length)) return false;
    } else if (rec->op_type == (uint8_t)QIHSE_WAL_OP_DELETE) {
        if (rec->key_length == 0u) return false;
        if (rec->value_length != 0u) return false;
        if (!backup_wal_bytes_are_string(key, rec->key_length)) return false;
    } else {
        /* Transaction fences: the tractable WAL's own append helpers write
         * BEGIN/COMMIT/ABORT with no payload and CHECKPOINT with the LSN
         * (8 bytes) as the key — anything else is not a shape it produces. */
        if (rec->key_length > (uint32_t)sizeof(uint64_t)) return false;
        if (rec->value_length != 0u) return false;
    }

    if (backup_wal_record_crc(rec, key, value) != crc_stored) return false;
    return true;
}

/* Walk the WHOLE section.  A section is valid when every record decodes and
 * the LSNs strictly increase — the ordered-segment guarantee qihse_wal
 * maintains — so a truncated or mid-record tail is detectable here, before
 * any byte of the section is applied.  Reports the first and last LSN (0
 * for an empty section). */
static bool backup_wal_section_validate(const uint8_t* section, size_t len,
                                        uint64_t* out_first_lsn,
                                        uint64_t* out_last_lsn) {
    uint64_t first = 0u, last = 0u;
    size_t off = 0u;
    while (off < len) {
        backup_wal_record_t rec;
        if (!backup_wal_record_decode(section, len, off, &rec)) return false;
        if (first == 0u) {
            first = rec.lsn;
        } else if (rec.lsn <= last) {
            return false;   /* strictly increasing */
        }
        last = rec.lsn;
        off += rec.total_bytes;
    }
    if (out_first_lsn) *out_first_lsn = first;
    if (out_last_lsn) *out_last_lsn = last;
    return true;
}

/* The authorization pre-flight: every INSERT/UPDATE record's
 * classification/SCI must be within the restoring principal's access,
 * checked with qihse_auth_can_access() — the exact predicate
 * qihse_kv_set_user() applies — BEFORE the dataset is replaced.  DELETEs
 * need no pre-flight: after a successful load the live dataset holds only
 * records the caller can access (the KV layer refuses the whole load
 * otherwise), and every record this replay inserts was pre-flighted here,
 * so a mid-replay clearance refusal is unreachable and an authorization
 * denial never leaves a half-replayed store. */
static bool backup_wal_section_applyable(void* user_void,
                                         const uint8_t* section, size_t len) {
    size_t off = 0u;
    while (off < len) {
        backup_wal_record_t rec;
        if (!backup_wal_record_decode(section, len, off, &rec)) return false;
        if (rec.op_type == (uint8_t)QIHSE_WAL_OP_INSERT ||
            rec.op_type == (uint8_t)QIHSE_WAL_OP_UPDATE) {
            if (!qihse_auth_can_access((const qihse_user_t*)user_void,
                                       rec.classification, rec.sci)) {
                return false;
            }
        }
        off += rec.total_bytes;
    }
    return true;
}

/* Replay a validated section, in order, through the KV layer's
 * authorization-aware primitives under the caller's identity:
 *
 *   - Records below the WAL continuation point were already reflected in
 *     the snapshot and are SKIPPED — the qihse_wal_replay() start-LSN rule,
 *     which is what makes re-application idempotent-safe.
 *   - INSERT/UPDATE apply with the record's own classification/SCI, so a
 *     replay can neither downgrade nor upgrade a record's classification.
 *   - A DELETE of an already-absent key is satisfied rather than an error
 *     (the delete was already applied); one whose key is still present
 *     after failing is a real failure.
 *   - Transaction fences (BEGIN/COMMIT/ABORT/CHECKPOINT) carry no data
 *     state — qihse_wal_replay() hands them to its callback too, and the
 *     applier decides, which is exactly this rule.
 */
static qihse_backup_result_t backup_wal_replay(void* store_void, void* user_void,
                                               uint64_t continuation_offset,
                                               const uint8_t* section, size_t len) {
    size_t off = 0u;
    while (off < len) {
        backup_wal_record_t rec;
        if (!backup_wal_record_decode(section, len, off, &rec)) {
            /* Unreachable after validation, but a decoder that could fail
             * must not be able to fail open. */
            return QIHSE_BACKUP_ERR_TRUNCATED;
        }
        const uint8_t* key = section + off + QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES;
        const uint8_t* value = key + rec.key_length;

        if (rec.lsn >= continuation_offset) {
            if (rec.op_type == (uint8_t)QIHSE_WAL_OP_INSERT ||
                rec.op_type == (uint8_t)QIHSE_WAL_OP_UPDATE) {
                /* One bounded heap copy per record, NUL-terminated for the
                 * KV layer's C-string surface (bounded stack frames). */
                char* k = (char*)malloc((size_t)rec.key_length + 1u);
                char* v = (char*)malloc((size_t)rec.value_length + 1u);
                if (!k || !v) {
                    free(k); free(v);
                    return QIHSE_BACKUP_ERR_IO;
                }
                memcpy(k, key, rec.key_length);
                k[rec.key_length] = '\0';
                memcpy(v, value, rec.value_length);
                v[rec.value_length] = '\0';
                bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, k, v,
                                            rec.classification, rec.sci,
                                            (qihse_user_t*)user_void);
                free(k);
                free(v);
                if (!ok) return QIHSE_BACKUP_ERR_IO;
            } else if (rec.op_type == (uint8_t)QIHSE_WAL_OP_DELETE) {
                char* k = (char*)malloc((size_t)rec.key_length + 1u);
                if (!k) return QIHSE_BACKUP_ERR_IO;
                memcpy(k, key, rec.key_length);
                k[rec.key_length] = '\0';
                bool ok = qihse_kv_del_user((qihse_kv_store_t*)store_void, k,
                                            (qihse_user_t*)user_void);
                if (!ok && qihse_kv_exists_user((qihse_kv_store_t*)store_void, k,
                                                (qihse_user_t*)user_void)) {
                    free(k);
                    return QIHSE_BACKUP_ERR_IO;
                }
                free(k);
            }
            /* Transaction fences carry no data state. */
        }
        off += rec.total_bytes;
    }
    return QIHSE_BACKUP_OK;
}

/* ── Filesystem helpers ────────────────────────────────────────────────── */

static uint64_t backup_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0u;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static bool backup_sibling_path(const char* path, const char* suffix,
                                char* out, size_t cap) {
    int n = snprintf(out, cap, "%s%s.%ld.%llu", path, suffix, (long)getpid(),
                     (unsigned long long)backup_now_ms());
    return n >= 0 && (size_t)n < cap;
}

static FILE* backup_open_read(const char* path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return NULL; }
    return f;
}

/* 0600: a backup of a classified dataset is not world-readable, and the mode
 * is set at creation rather than left to the umask. */
static FILE* backup_create_exclusive(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); unlink(path); return NULL; }
    return f;
}

/* Always closes, so a caller cannot both double-close and leak on the
 * failure path. */
static bool backup_finish_file(FILE* f) {
    if (!f) return false;
    bool ok = fflush(f) == 0;
    int fd = fileno(f);
    if (ok && fd >= 0 && fsync(fd) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* Stream `len` bytes out of `src`, optionally into `dst` and optionally
 * through a digest.  A short read is reported rather than padded, so a
 * truncated container cannot be verified as if it were whole. */
static qihse_backup_result_t backup_move_section(FILE* src, uint64_t len, FILE* dst,
                                                 EVP_MD_CTX* md, uint8_t* buf,
                                                 size_t buf_cap, uint64_t* out_moved) {
    uint64_t moved = 0u;
    while (moved < len) {
        uint64_t want = len - moved;
        size_t take = (want < (uint64_t)buf_cap) ? (size_t)want : buf_cap;
        size_t got = fread(buf, 1u, take, src);
        if (got == 0u) {
            if (ferror(src)) return QIHSE_BACKUP_ERR_IO;
            break;
        }
        if (dst && fwrite(buf, 1u, got, dst) != got) return QIHSE_BACKUP_ERR_IO;
        if (md && EVP_DigestUpdate(md, buf, got) != 1) return QIHSE_BACKUP_ERR_IO;
        moved += (uint64_t)got;
    }
    if (out_moved) *out_moved = moved;
    return (moved == len) ? QIHSE_BACKUP_OK : QIHSE_BACKUP_ERR_TRUNCATED;
}

/* ── Manifest binding ──────────────────────────────────────────────────── */

/* The caller must present exactly the recorded manifest.  qihse_snapshot_verify()
 * recomputes the digest over the STORED body, so an edited or truncated
 * manifest is caught there; comparing the fields that decide what a restore
 * does means an edited in-memory manifest is refused too, even though its
 * checksum bytes still name the recorded digest. */
static bool backup_manifest_matches(const qihse_snapshot_manifest_t* given,
                                    const qihse_snapshot_manifest_t* recorded) {
    if (!qihse_uuid_equal(&given->snapshot_id, &recorded->snapshot_id)) return false;
    if (given->kind != recorded->kind) return false;
    if (given->wal_continuation_offset != recorded->wal_continuation_offset) return false;
    if (given->max_generation != recorded->max_generation) return false;
    if (given->object_count != recorded->object_count) return false;
    if (memcmp(given->checksum, recorded->checksum, BACKUP_CK_BYTES) != 0) return false;
    if (strcmp(given->encryption_key_id, recorded->encryption_key_id) != 0) return false;
    if (given->group_count > QIHSE_SNAPSHOT_MAX_GROUPS) return false;
    if (given->group_count != recorded->group_count) return false;
    for (uint32_t i = 0; i < given->group_count; i++) {
        if (strcmp(given->groups[i], recorded->groups[i]) != 0) return false;
    }
    if (given->schema.schema_id != recorded->schema.schema_id) return false;
    if (given->schema.schema_version != recorded->schema.schema_version) return false;
    if (given->schema.minimum_reader_version != recorded->schema.minimum_reader_version) return false;
    if (given->schema.required_features != recorded->schema.required_features) return false;
    if (given->schema.optional_features != recorded->schema.optional_features) return false;
    return true;
}

/* Verify the recorded manifest's checksum, then confirm the caller presented
 * that manifest.  Nothing is read, written or applied before this passes. */
static qihse_backup_result_t backup_manifest_gate(void* store_void, void* user_void,
                                                 const qihse_snapshot_manifest_t* manifest) {
    if (!qihse_snapshot_verify(store_void, user_void, &manifest->snapshot_id)) {
        return QIHSE_BACKUP_ERR_MANIFEST;
    }
    qihse_snapshot_manifest_t recorded;
    memset(&recorded, 0, sizeof(recorded));
    if (!qihse_snapshot_lookup(store_void, user_void, &manifest->snapshot_id, &recorded)) {
        return QIHSE_BACKUP_ERR_MANIFEST;
    }
    if (!backup_manifest_matches(manifest, &recorded)) return QIHSE_BACKUP_ERR_MANIFEST;
    return QIHSE_BACKUP_OK;
}

/* ── Signer resolution ─────────────────────────────────────────────────── */

/* The node whose enrolled identity signs a backup.  The private key lives on
 * disk behind the identity record's key handle and is loaded only for the
 * duration of the signature — it never enters a QIHSE record and never
 * enters the container (plan §20). */
typedef struct {
    qihse_federation_node_identity_t identity;
    void* pkey;   /* EVP_PKEY* from qihse_federation_node_key_load() */
} backup_signer_t;

static void backup_signer_release(backup_signer_t* signer) {
    if (signer->pkey) qihse_federation_node_key_free(signer->pkey);
    signer->pkey = NULL;
}

/* Resolve `signer_node` through the store's enrolled identity records, as
 * the authenticated principal — the lookup itself goes through the KV layer
 * with the caller's identity, so a revoked handle or an out-of-clearance
 * principal cannot resolve a signer (AGENTS.md invariant 1; the identity
 * record's own decoder re-verifies that the stored fingerprint describes the
 * stored public key).
 *
 * Fails closed for: a nil/absent node id, no enrolled record, a trust state
 * that is not APPROVED right now (an unenrolled, pending or revoked identity
 * must not vouch for a backup), a private key that does not load from its
 * handle, and a loaded key whose algorithm disagrees with the enrolled
 * record (a rotated or substituted key file). */
static bool backup_signer_resolve(void* store_void, void* user_void,
                                  const qihse_uuid_t* signer_node,
                                  backup_signer_t* out) {
    memset(out, 0, sizeof(*out));
    if (!signer_node || qihse_uuid_is_nil(signer_node)) return false;
    if (!qihse_federation_node_lookup(store_void, user_void, signer_node,
                                      &out->identity)) {
        return false;
    }
    if (out->identity.trust != QIHSE_TRUST_APPROVED) return false;
    out->pkey = qihse_federation_node_key_load(out->identity.key_handle);
    if (!out->pkey) return false;
    qihse_sig_alg_t key_alg;
    if (!qihse_federation_pkey_sig_alg(out->pkey, &key_alg)) return false;
    if (key_alg != out->identity.sig_alg) return false;
    return true;
}

/* The read-side half: confirm that the signer a container RECORDS is the
 * signer the store knows, admissible right now.  Mirrors
 * qihse_federation_node_capability_lookup_admissible(): the identity record
 * is re-read here, so a revocation that happened after the backup was
 * written takes effect immediately — the recorded fingerprint is a claim,
 * and this is where it is checked against the enrolled key.  No override:
 * the operator exception is a restore-time decision, and this predicate
 * never lies about the trust state. */
static bool backup_signer_admissible(void* store_void, void* user_void,
                                     const qihse_uuid_t* signer_node,
                                     const uint8_t* fingerprint,
                                     qihse_federation_node_identity_t* out_identity) {
    if (!signer_node || qihse_uuid_is_nil(signer_node) || !fingerprint) return false;
    if (!qihse_federation_node_lookup(store_void, user_void, signer_node,
                                      out_identity)) {
        return false;
    }
    if (out_identity->trust != QIHSE_TRUST_APPROVED) return false;
    if (memcmp(out_identity->fingerprint, fingerprint,
               QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) != 0) {
        return false;
    }
    return true;
}

/* ── Writer ────────────────────────────────────────────────────────────── */

static qihse_backup_result_t backup_write_signed_impl(void* store_void, void* user_void,
                                                      const qihse_snapshot_manifest_t* manifest,
                                                      const qihse_uuid_t* signer_node,
                                                      const char* path,
                                                      const uint8_t* wal_segment,
                                                      size_t wal_len,
                                                      qihse_backup_descriptor_t* out) {
    /* A failed call hands back nothing that could be mistaken for a result. */
    if (out) memset(out, 0, sizeof(*out));
    /* NULL is not an authorization bypass (AGENTS.md invariant 1), and a
     * container without a signer is not a container this writer can produce:
     * there is no unsigned fallback and no development flag that adds one. */
    if (!store_void || !user_void || !manifest || !path || path[0] == '\0' ||
        !signer_node) {
        return QIHSE_BACKUP_ERR_ARGUMENT;
    }
    if (wal_len > 0u && !wal_segment) return QIHSE_BACKUP_ERR_ARGUMENT;
    /* The segment is bounded by the format; a caller asking for more is an
     * argument error before any data is produced. */
    if (wal_len > (size_t)QIHSE_BACKUP_WAL_SECTION_MAX) {
        return QIHSE_BACKUP_ERR_ARGUMENT;
    }
    if (!backup_key_id_is_identifier(manifest->encryption_key_id)) {
        return QIHSE_BACKUP_ERR_KEY_MATERIAL;
    }

    qihse_backup_result_t rc = QIHSE_BACKUP_ERR_IO;
    uint8_t* chunk = NULL;
    uint8_t* sig = NULL;
    EVP_MD_CTX* md = NULL;
    FILE* data_f = NULL;
    FILE* out_f = NULL;
    char data_path[BACKUP_PATH_MAX];
    char tmp_path[BACKUP_PATH_MAX];
    bool tmp_pending = false;
    backup_signer_t signer;
    uint64_t wal_first = 0u, wal_last = 0u;
    memset(&signer, 0, sizeof(signer));
    data_path[0] = '\0';

    pthread_mutex_lock(&g_backup_lock);

    rc = backup_manifest_gate(store_void, user_void, manifest);
    if (rc != QIHSE_BACKUP_OK) goto done;

    /* Validate the WHOLE WAL segment before anything is produced.  A record
     * that fails its CRC, its bounds or its ordering refuses the write here,
     * and a segment that does not start exactly at the manifest's WAL
     * continuation point is refused with the same error the reader would
     * give it: below the point the records are pre-snapshot, above it the
     * gap would silently lose writes. */
    if (wal_len > 0u) {
        if (!backup_wal_section_validate(wal_segment, wal_len, &wal_first, &wal_last)) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
        if (wal_first != manifest->wal_continuation_offset) {
            rc = QIHSE_BACKUP_ERR_WAL_POINT;
            goto done;
        }
    }

    /* Resolve the signer BEFORE any data is produced.  An absent, unenrolled,
     * unapproved or keyless identity fails the whole write here with a clear
     * error rather than silently producing an unsigned container further
     * down.  The private key is loaded from the enrolled record's handle and
     * released on every exit path; it never enters a record or the
     * container. */
    if (!backup_signer_resolve(store_void, user_void, signer_node, &signer)) {
        rc = QIHSE_BACKUP_ERR_SIGNER;
        goto done;
    }

    /* The manifest's object count was counted through the snapshotting
     * principal's authorized view.  A caller whose own view is narrower than
     * that cannot produce the data the manifest refers to, and refusing beats
     * writing a backup that is quietly not the snapshot it names.  A wider
     * view is allowed — the manifest was counted before its own record
     * existed — and the captured count is reported in the descriptor. */
    uint64_t visible = (uint64_t)qihse_kv_count_user((qihse_kv_store_t*)store_void,
                                                     (qihse_user_t*)user_void);
    if (visible < manifest->object_count) {
        rc = QIHSE_BACKUP_ERR_COVERAGE;
        goto done;
    }

    if (!backup_sibling_path(path, ".data", data_path, sizeof(data_path))) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }

    /* The data section is the KV layer's own authorization-aware export, so
     * the identity reaches the lowest data-retrieval layer and a clearance
     * denial refuses the whole write (AGENTS.md invariants 1 and 2). */
    int save_rc = qihse_kv_save_user((qihse_kv_store_t*)store_void, data_path,
                                     (qihse_user_t*)user_void);
    if (save_rc == -2) { rc = QIHSE_BACKUP_ERR_DENIED; goto done; }
    if (save_rc != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    data_f = backup_open_read(data_path);
    if (!data_f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    struct stat st;
    if (fstat(fileno(data_f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }

    qihse_backup_descriptor_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.snapshot_id = manifest->snapshot_id;
    desc.wal_continuation_offset = manifest->wal_continuation_offset;
    desc.max_generation = manifest->max_generation;
    desc.object_count = visible;
    desc.data_bytes = (uint64_t)st.st_size;
    desc.schema = manifest->schema;
    memcpy(desc.manifest_checksum, manifest->checksum, BACKUP_CK_BYTES);
    snprintf(desc.encryption_key_id, sizeof(desc.encryption_key_id), "%s",
             manifest->encryption_key_id);
    /* Who vouches for everything above.  Fingerprint and algorithm are read
     * from the enrolled identity record — never taken from the caller, and
     * never key material. */
    desc.signer_node = *signer_node;
    desc.sig_alg = signer.identity.sig_alg;
    memcpy(desc.signer_fingerprint, signer.identity.fingerprint,
           QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES);
    /* The post-snapshot segment's claims: length, LSN range and digest —
     * all of them inside the signed region. */
    desc.wal_bytes = (uint64_t)wal_len;
    desc.wal_first_lsn = wal_first;
    desc.wal_last_lsn = wal_last;

    /* ONE reusable heap buffer for the section. */
    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    uint64_t moved = 0u;
    rc = backup_move_section(data_f, desc.data_bytes, NULL, md, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;
    unsigned int digest_len = 0u;
    if (EVP_DigestFinal_ex(md, desc.data_checksum, &digest_len) != 1 ||
        digest_len != BACKUP_CK_BYTES) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    EVP_MD_CTX_free(md);
    md = NULL;

    if (wal_len > 0u) {
        md = EVP_MD_CTX_new();
        if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1 ||
            EVP_DigestUpdate(md, wal_segment, wal_len) != 1 ||
            EVP_DigestFinal_ex(md, desc.wal_checksum, &digest_len) != 1 ||
            digest_len != BACKUP_CK_BYTES) {
            rc = QIHSE_BACKUP_ERR_IO;
            goto done;
        }
        EVP_MD_CTX_free(md);
        md = NULL;
    }

    /* Sign the fixed header.  It carries the manifest checksum, the data
     * section's SHA-384, the WAL section's SHA-384/length/LSN-range and the
     * signer/algorithm/length block, so this one detached signature
     * authenticates the manifest binding, both payload digests and the
     * signer identity at once — and because the algorithm id and the
     * fingerprint sit INSIDE the signed bytes, an algorithm-downgrade or
     * signer-substitution edit invalidates the signature instead of
     * reinterpreting it.  ONE reusable heap buffer for the signature. */
    uint8_t header[QIHSE_BACKUP_HEADER_WAL_BYTES];
    backup_encode_header(&desc, header);
    sig = (uint8_t*)malloc(QIHSE_FEDERATION_SIG_MAX_BYTES);
    if (!sig) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    size_t sig_len = QIHSE_FEDERATION_SIG_MAX_BYTES;
    if (!qihse_federation_sign(signer.pkey, header, sizeof(header), sig, &sig_len)) {
        rc = QIHSE_BACKUP_ERR_SIGNER;
        goto done;
    }

    if (!backup_sibling_path(path, ".tmp", tmp_path, sizeof(tmp_path))) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    out_f = backup_create_exclusive(tmp_path);
    if (!out_f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    tmp_pending = true;

    /* [ header ][ signature ][ data section ][ WAL section ]: the signature
     * sits before the payloads so a reader can refuse a forged container
     * before reading any payload byte. */
    if (fwrite(header, 1u, sizeof(header), out_f) != sizeof(header) ||
        fwrite(sig, 1u, sig_len, out_f) != sig_len) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    if (fseek(data_f, 0L, SEEK_SET) != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    rc = backup_move_section(data_f, desc.data_bytes, out_f, NULL, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;
    /* The bytes just digested are the caller's buffer's bytes — the same
     * memory the digest ran over, so nothing can change in between. */
    if (wal_len > 0u && fwrite(wal_segment, 1u, wal_len, out_f) != wal_len) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }

    /* Renamed into place only once every byte is down and flushed, so a
     * failed backup never leaves a container at `path` — and never damages
     * the previous backup that was there. */
    bool flushed = backup_finish_file(out_f);
    out_f = NULL;
    if (!flushed) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    if (rename(tmp_path, path) != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    tmp_pending = false;

    if (out) *out = desc;
    rc = QIHSE_BACKUP_OK;

done:
    backup_signer_release(&signer);
    if (md) EVP_MD_CTX_free(md);
    if (out_f) fclose(out_f);
    if (tmp_pending) unlink(tmp_path);
    if (data_f) fclose(data_f);
    if (data_path[0]) unlink(data_path);
    free(sig);
    free(chunk);
    pthread_mutex_unlock(&g_backup_lock);
    return rc;
}

qihse_backup_result_t qihse_backup_write_signed(void* store_void, void* user_void,
                                                const qihse_snapshot_manifest_t* manifest,
                                                const qihse_uuid_t* signer_node,
                                                const char* path,
                                                qihse_backup_descriptor_t* out) {
    return backup_write_signed_impl(store_void, user_void, manifest, signer_node,
                                    path, NULL, 0u, out);
}

qihse_backup_result_t qihse_backup_write_signed_wal(void* store_void, void* user_void,
                                                    const qihse_snapshot_manifest_t* manifest,
                                                    const qihse_uuid_t* signer_node,
                                                    const char* path,
                                                    const uint8_t* wal_segment,
                                                    size_t wal_len,
                                                    qihse_backup_descriptor_t* out) {
    return backup_write_signed_impl(store_void, user_void, manifest, signer_node,
                                    path, wal_segment, wal_len, out);
}

/* ── Reader / restore ──────────────────────────────────────────────────── */

qihse_backup_result_t qihse_backup_restore_signed(void* store_void, void* user_void,
                                                  const qihse_snapshot_manifest_t* manifest,
                                                  const char* path,
                                                  bool operator_override,
                                                  qihse_backup_descriptor_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store_void || !user_void || !manifest || !path || path[0] == '\0') {
        return QIHSE_BACKUP_ERR_ARGUMENT;
    }
    /* The override is an operator's decision, not a flag anyone may raise:
     * only a principal holding the security-admin scope (an operator,
     * implicitly) is allowed to ask for it at all.  Everyone else is refused
     * outright, before a single byte of the container is read.  When it IS
     * allowed, it skips ONLY the signature and signer-admissibility gate
     * below — the manifest gate, the version, the structural and length
     * checks, both checksums, the WAL gates, the snapshot/WAL/coverage
     * binding and the KV layer's clearance/SCI load check all still run, so
     * the override can neither bypass classification nor rescue a tampered
     * container. */
    if (operator_override &&
        !qihse_infra_scope_check(user_void, QIHSE_SCOPE_SECURITY_ADMIN)) {
        return QIHSE_BACKUP_ERR_DENIED;
    }

    qihse_backup_result_t rc = QIHSE_BACKUP_ERR_IO;
    uint8_t* chunk = NULL;
    uint8_t* sig = NULL;
    uint8_t* wal_buf = NULL;
    EVP_MD_CTX* md = NULL;
    FILE* f = NULL;
    FILE* scratch_f = NULL;
    char scratch_path[BACKUP_PATH_MAX];
    bool scratch_pending = false;
    qihse_backup_descriptor_t desc;
    uint8_t header[QIHSE_BACKUP_HEADER_WAL_BYTES];
    size_t sig_len = 0u;
    memset(&desc, 0, sizeof(desc));

    pthread_mutex_lock(&g_backup_lock);

    /* The manifest gate, unchanged: the recorded manifest verifies against
     * its checksum and is the manifest presented. */
    rc = backup_manifest_gate(store_void, user_void, manifest);
    if (rc != QIHSE_BACKUP_OK) goto done;

    f = backup_open_read(path);
    if (!f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    if ((uint64_t)st.st_size < QIHSE_BACKUP_HEADER_WAL_BYTES) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    if (fread(header, 1u, sizeof(header), f) != sizeof(header)) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    if (!backup_decode_header(header, sizeof(header), &desc)) {
        /* A container of a retired or unknown version is refused BY VERSION:
         * the unsigned v1 pair and the WAL-less v2 form are gone, and the
         * refusal is explicit rather than a downgrade to whatever checks an
         * older layout could still run. */
        uint32_t version = 0u;
        backup_get_bytes(header, BACKUP_OFF_VERSION, &version, 4u);
        if (memcmp(header + BACKUP_OFF_MAGIC, QIHSE_BACKUP_MAGIC,
                   QIHSE_BACKUP_MAGIC_LEN) == 0 &&
            version != QIHSE_BACKUP_VERSION_WAL) {
            rc = QIHSE_BACKUP_ERR_VERSION;
        } else {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
        }
        goto done;
    }
    sig_len = qihse_sig_alg_signature_bytes(desc.sig_alg);

    /* Declared lengths versus the bytes actually present, computed without
     * overflow: the file must be EXACTLY header + signature + data + WAL, so
     * a stripped, partial or padded trailer is a truncation. */
    {
        uint64_t body = (uint64_t)st.st_size - QIHSE_BACKUP_HEADER_WAL_BYTES;
        if (body < (uint64_t)sig_len ||
            desc.data_bytes > body - (uint64_t)sig_len ||
            desc.wal_bytes != body - (uint64_t)sig_len - desc.data_bytes) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
    }

    /* The binding gates.  A header edit that matters here is caught either
     * by these comparisons or, for every other field, by the signature. */
    if (!qihse_uuid_equal(&desc.snapshot_id, &manifest->snapshot_id)) {
        rc = QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH;
        goto done;
    }
    if (memcmp(desc.manifest_checksum, manifest->checksum, BACKUP_CK_BYTES) != 0) {
        rc = QIHSE_BACKUP_ERR_MANIFEST;
        goto done;
    }
    /* Resuming from any point other than the one the manifest names would
     * restore a state that never existed, so a disagreement is a refusal and
     * not a warning. */
    if (desc.wal_continuation_offset != manifest->wal_continuation_offset) {
        rc = QIHSE_BACKUP_ERR_WAL_POINT;
        goto done;
    }
    if (desc.object_count < manifest->object_count) {
        rc = QIHSE_BACKUP_ERR_COVERAGE;
        goto done;
    }

    if (!operator_override) {
        /* The signature sits between the header and the payloads, so it is
         * read and verified BEFORE any payload byte.  The signer is looked
         * up through the store as the authenticated principal, its trust
         * state is re-read here (a revocation after the write takes effect
         * immediately), the enrolled key's fingerprint must equal the
         * recorded one, and only then does the signature itself run. */
        sig = (uint8_t*)malloc(QIHSE_FEDERATION_SIG_MAX_BYTES);
        if (!sig) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
        if (fread(sig, 1u, sig_len, f) != sig_len) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
        qihse_federation_node_identity_t signer;
        if (!backup_signer_admissible(store_void, user_void, &desc.signer_node,
                                      desc.signer_fingerprint, &signer)) {
            rc = QIHSE_BACKUP_ERR_SIGNATURE;
            goto done;
        }
        if (!qihse_federation_verify(desc.sig_alg, signer.public_key,
                                     signer.public_key_len, header, sizeof(header),
                                     sig, sig_len)) {
            rc = QIHSE_BACKUP_ERR_SIGNATURE;
            goto done;
        }
    } else {
        /* Operator override: skip exactly the gate above. */
        if (fseek(f, (long)(QIHSE_BACKUP_HEADER_WAL_BYTES + sig_len), SEEK_SET) != 0) {
            rc = QIHSE_BACKUP_ERR_IO;
            goto done;
        }
    }

    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    /* Verify-then-apply in a single pass for the data section: the bytes
     * that are hashed are the bytes that will be applied.  This gate runs
     * under the override too — an operator may accept an unauthenticated
     * container, never a corrupted one. */
    if (!backup_sibling_path(path, ".restore", scratch_path, sizeof(scratch_path))) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    scratch_f = backup_create_exclusive(scratch_path);
    if (!scratch_f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    scratch_pending = true;

    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    uint64_t moved = 0u;
    rc = backup_move_section(f, desc.data_bytes, scratch_f, md, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;
    uint8_t digest[BACKUP_CK_BYTES];
    unsigned int digest_len = 0u;
    if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1 ||
        digest_len != BACKUP_CK_BYTES) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    EVP_MD_CTX_free(md);
    md = NULL;
    if (memcmp(digest, desc.data_checksum, BACKUP_CK_BYTES) != 0) {
        rc = QIHSE_BACKUP_ERR_CHECKSUM;
        goto done;
    }
    if (!backup_finish_file(scratch_f)) {
        scratch_f = NULL;
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    scratch_f = NULL;

    /* The WAL section: read into ONE bounded heap buffer, digest it, then
     * validate its WHOLE structure — all BEFORE the dataset is replaced, so
     * a tampered, truncated or mid-record section fails the restore before
     * any WAL byte is applied (and before the snapshot is applied either).
     * The buffer is also what the replay later walks, so the bytes that are
     * verified are the bytes that are applied. */
    if (desc.wal_bytes > 0u) {
        wal_buf = (uint8_t*)malloc((size_t)desc.wal_bytes);
        if (!wal_buf) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
        if (fread(wal_buf, 1u, (size_t)desc.wal_bytes, f) != (size_t)desc.wal_bytes) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
        md = EVP_MD_CTX_new();
        if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1 ||
            EVP_DigestUpdate(md, wal_buf, (size_t)desc.wal_bytes) != 1 ||
            EVP_DigestFinal_ex(md, digest, &digest_len) != 1 ||
            digest_len != BACKUP_CK_BYTES) {
            rc = QIHSE_BACKUP_ERR_IO;
            goto done;
        }
        EVP_MD_CTX_free(md);
        md = NULL;
        if (memcmp(digest, desc.wal_checksum, BACKUP_CK_BYTES) != 0) {
            rc = QIHSE_BACKUP_ERR_CHECKSUM;
            goto done;
        }
        uint64_t first = 0u, last = 0u;
        if (!backup_wal_section_validate(wal_buf, (size_t)desc.wal_bytes,
                                         &first, &last) ||
            first != desc.wal_first_lsn || last != desc.wal_last_lsn) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
        /* A segment that starts ABOVE the continuation point is missing the
         * records between the snapshot and its first record; replaying it
         * would silently lose writes.  A segment starting below it holds
         * already-applied records, which the replay skips. */
        if (first > desc.wal_continuation_offset) {
            rc = QIHSE_BACKUP_ERR_WAL_POINT;
            goto done;
        }
        /* The authorization pre-flight: run before the dataset is replaced,
         * so a WAL record above the caller's clearance refuses the restore
         * with nothing applied at all.  This gate is independent of the
         * signature gate and of the override, which is precisely why the
         * override cannot turn it into a restore. */
        if (!backup_wal_section_applyable(user_void, wal_buf, (size_t)desc.wal_bytes)) {
            rc = QIHSE_BACKUP_ERR_DENIED;
            goto done;
        }
    }

    /* The KV layer applies the data section, and it is the layer that knows
     * each record's classification: it refuses the WHOLE load (EACCES) if any
     * record is outside this principal's clearance/SCI, and its load is
     * transactional, so a denial leaves the live dataset untouched rather
     * than half-restored (AGENTS.md invariants 1 and 2). */
    int load_rc = qihse_kv_load_user((qihse_kv_store_t*)store_void, scratch_path,
                                     (qihse_user_t*)user_void);
    if (load_rc == -2) { rc = QIHSE_BACKUP_ERR_DENIED; goto done; }
    if (load_rc != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    /* Replay the validated segment, in order, on top of the snapshot. */
    if (wal_buf) {
        rc = backup_wal_replay(store_void, user_void, desc.wal_continuation_offset,
                               wal_buf, (size_t)desc.wal_bytes);
        if (rc != QIHSE_BACKUP_OK) goto done;
    }

    if (out) *out = desc;
    rc = QIHSE_BACKUP_OK;

done:
    if (md) EVP_MD_CTX_free(md);
    if (wal_buf) free(wal_buf);
    if (scratch_f) fclose(scratch_f);
    if (scratch_pending) unlink(scratch_path);
    if (f) fclose(f);
    free(sig);
    free(chunk);
    pthread_mutex_unlock(&g_backup_lock);
    return rc;
}

/* ── Verify-only ───────────────────────────────────────────────────────── */

qihse_backup_result_t qihse_backup_verify(void* store_void, void* user_void,
                                          const char* path,
                                          qihse_backup_descriptor_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    /* NULL is an argument error, never a bypass: the signer's admissibility
     * is part of what "verified" means, and it is read through the caller's
     * identity (AGENTS.md invariant 1). */
    if (!store_void || !user_void || !path || path[0] == '\0') {
        return QIHSE_BACKUP_ERR_ARGUMENT;
    }

    qihse_backup_result_t rc = QIHSE_BACKUP_ERR_IO;
    uint8_t* chunk = NULL;
    uint8_t* sig = NULL;
    uint8_t* wal_buf = NULL;
    EVP_MD_CTX* md = NULL;
    FILE* f = NULL;
    qihse_backup_descriptor_t desc;
    uint8_t header[QIHSE_BACKUP_HEADER_WAL_BYTES];
    size_t sig_len = 0u;
    memset(&desc, 0, sizeof(desc));

    pthread_mutex_lock(&g_backup_lock);

    f = backup_open_read(path);
    if (!f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    if ((uint64_t)st.st_size < QIHSE_BACKUP_HEADER_WAL_BYTES) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    if (fread(header, 1u, sizeof(header), f) != sizeof(header)) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    if (!backup_decode_header(header, sizeof(header), &desc)) {
        uint32_t version = 0u;
        backup_get_bytes(header, BACKUP_OFF_VERSION, &version, 4u);
        if (memcmp(header + BACKUP_OFF_MAGIC, QIHSE_BACKUP_MAGIC,
                   QIHSE_BACKUP_MAGIC_LEN) == 0 &&
            version != QIHSE_BACKUP_VERSION_WAL) {
            rc = QIHSE_BACKUP_ERR_VERSION;
        } else {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
        }
        goto done;
    }
    sig_len = qihse_sig_alg_signature_bytes(desc.sig_alg);

    {
        uint64_t body = (uint64_t)st.st_size - QIHSE_BACKUP_HEADER_WAL_BYTES;
        if (body < (uint64_t)sig_len ||
            desc.data_bytes > body - (uint64_t)sig_len ||
            desc.wal_bytes != body - (uint64_t)sig_len - desc.data_bytes) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
    }

    /* The signature is checked before any payload byte is read, against the
     * recorded signer's enrolled key with admissibility re-checked.  There is
     * no override here: verification reports the truth. */
    sig = (uint8_t*)malloc(QIHSE_FEDERATION_SIG_MAX_BYTES);
    if (!sig) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    if (fread(sig, 1u, sig_len, f) != sig_len) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    qihse_federation_node_identity_t signer;
    if (!backup_signer_admissible(store_void, user_void, &desc.signer_node,
                                  desc.signer_fingerprint, &signer)) {
        rc = QIHSE_BACKUP_ERR_SIGNATURE;
        goto done;
    }
    if (!qihse_federation_verify(desc.sig_alg, signer.public_key,
                                 signer.public_key_len, header, sizeof(header),
                                 sig, sig_len)) {
        rc = QIHSE_BACKUP_ERR_SIGNATURE;
        goto done;
    }

    /* The data section is streamed through the digest in bounded chunks —
     * hashed, never materialized: no scratch file, no payload buffer, and
     * the store is neither opened for load nor written. */
    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    uint64_t moved = 0u;
    rc = backup_move_section(f, desc.data_bytes, NULL, md, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;
    uint8_t digest[BACKUP_CK_BYTES];
    unsigned int digest_len = 0u;
    if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1 ||
        digest_len != BACKUP_CK_BYTES) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    EVP_MD_CTX_free(md);
    md = NULL;
    if (memcmp(digest, desc.data_checksum, BACKUP_CK_BYTES) != 0) {
        rc = QIHSE_BACKUP_ERR_CHECKSUM;
        goto done;
    }

    /* The WAL section is checked without being applied: digest, whole-section
     * structure, agreement with the header's LSN claims, and the gap rule
     * against the container's own continuation point.  Nothing is replayed
     * and nothing is written. */
    if (desc.wal_bytes > 0u) {
        wal_buf = (uint8_t*)malloc((size_t)desc.wal_bytes);
        if (!wal_buf) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
        if (fread(wal_buf, 1u, (size_t)desc.wal_bytes, f) != (size_t)desc.wal_bytes) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
        md = EVP_MD_CTX_new();
        if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1 ||
            EVP_DigestUpdate(md, wal_buf, (size_t)desc.wal_bytes) != 1 ||
            EVP_DigestFinal_ex(md, digest, &digest_len) != 1 ||
            digest_len != BACKUP_CK_BYTES) {
            rc = QIHSE_BACKUP_ERR_IO;
            goto done;
        }
        EVP_MD_CTX_free(md);
        md = NULL;
        if (memcmp(digest, desc.wal_checksum, BACKUP_CK_BYTES) != 0) {
            rc = QIHSE_BACKUP_ERR_CHECKSUM;
            goto done;
        }
        uint64_t first = 0u, last = 0u;
        if (!backup_wal_section_validate(wal_buf, (size_t)desc.wal_bytes,
                                         &first, &last) ||
            first != desc.wal_first_lsn || last != desc.wal_last_lsn) {
            rc = QIHSE_BACKUP_ERR_TRUNCATED;
            goto done;
        }
        if (first > desc.wal_continuation_offset) {
            rc = QIHSE_BACKUP_ERR_WAL_POINT;
            goto done;
        }
    }

    if (out) *out = desc;
    rc = QIHSE_BACKUP_OK;

done:
    if (md) EVP_MD_CTX_free(md);
    if (wal_buf) free(wal_buf);
    if (f) fclose(f);
    free(sig);
    free(chunk);
    pthread_mutex_unlock(&g_backup_lock);
    return rc;
}
