/*
 * QIHSE snapshot vector store helpers.
 *
 * The API accepts plain buffers and row arrays so qihse_vector_db.c can remain
 * the owner of its in-memory representation.
 */

#ifndef QIHSE_VECTOR_STORE_H
#define QIHSE_VECTOR_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_ROW_F_LIVE      0x00000001u
#define QIHSE_ROW_F_TOMBSTONE 0x00000002u

#define QIHSE_VSTORE_ENCODING_FLOAT32 1u
#define QIHSE_VSTORE_ENCODING_VERSION 1u

#define QIHSE_VSTORE_TRI_PRESENT 0x00000001u
#define QIHSE_VSTORE_TRI_VALID   0x00000002u
#define QIHSE_VSTORE_MAG_PRESENT 0x00000001u
#define QIHSE_VSTORE_MAG_VALID   0x00000002u

typedef struct qihse_index_row_s {
    uint64_t vector_id;
    uint64_t vector_offset;
    uint64_t metadata_offset;
    uint64_t metadata_size;
    uint64_t commit_generation;
    uint32_t row_flags;
    uint16_t classification;
    uint16_t sci_compartment;
} qihse_index_row_t;

#define QIHSE_CLASS_UNCLASSIFIED 0
#define QIHSE_CLASS_RESTRICTED 1
#define QIHSE_CLASS_CONFIDENTIAL 2
#define QIHSE_CLASS_SECRET 3
#define QIHSE_CLASS_TOP_SECRET 4

#define QIHSE_SCI_NONE 0x0000
#define QIHSE_SCI_SI   0x0001
#define QIHSE_SCI_TK   0x0002
#define QIHSE_SCI_HCS  0x0004
#define QIHSE_SCI_G    0x0008

typedef struct qihse_idmap_entry_s {
    int64_t key;
    uint64_t row_index;
} qihse_idmap_entry_t;

typedef struct qihse_vector_store_manifest_s {
    uint32_t format_version;
    uint32_t encoding_id;
    uint32_t encoding_version;
    uint32_t vector_dims;
    uint64_t row_count;
    uint64_t vector_bytes;
    uint64_t metadata_bytes;
    uint64_t commit_generation;
    uint64_t index_crc64;
    uint64_t vector_crc64;
    uint64_t metadata_crc64;
    uint64_t idmap_crc64;
    uint64_t trinary_generation;
    uint64_t trinary_row_bytes;
    uint64_t trinary_rows;
    uint64_t trinary_crc64;
    uint32_t trinary_flags;
    uint64_t magnitude_generation;
    uint64_t magnitude_row_bytes;
    uint64_t magnitude_rows;
    uint64_t magnitude_crc64;
    uint32_t magnitude_flags;
} qihse_vector_store_manifest_t;

typedef struct qihse_vector_store_snapshot_s {
    qihse_vector_store_manifest_t manifest;
    qihse_index_row_t* rows;
    size_t row_count;
    uint8_t* vectors;
    size_t vector_bytes;
    uint8_t* metadata;
    size_t metadata_bytes;
    qihse_idmap_entry_t* idmap;
    size_t idmap_count;
    uint8_t* trinary;
    size_t trinary_bytes;
    uint8_t* magnitude;
    size_t magnitude_bytes;
    bool idmap_valid;
    bool trinary_valid;
    bool magnitude_valid;
} qihse_vector_store_snapshot_t;

typedef struct qihse_vector_store_flush_s {
    uint32_t vector_dims;
    uint64_t commit_generation;
    const qihse_index_row_t* rows;
    size_t row_count;
    const void* vectors;
    size_t vector_bytes;
    const void* metadata;
    size_t metadata_bytes;
    const qihse_idmap_entry_t* idmap;
    size_t idmap_count;
    const void* trinary;
    size_t trinary_bytes;
    uint64_t trinary_generation;
    uint64_t trinary_row_bytes;
    uint32_t trinary_flags;
    const void* magnitude;
    size_t magnitude_bytes;
    uint64_t magnitude_generation;
    uint64_t magnitude_row_bytes;
    uint32_t magnitude_flags;
} qihse_vector_store_flush_t;

bool qihse_vector_store_load(const char* db_path, qihse_vector_store_snapshot_t* out);
bool qihse_vector_store_flush(const char* db_path, const qihse_vector_store_flush_t* in);
void qihse_vector_store_snapshot_free(qihse_vector_store_snapshot_t* snapshot);

bool qihse_vector_store_build_idmap(const qihse_index_row_t* rows,
                                    size_t row_count,
                                    qihse_idmap_entry_t** out_entries,
                                    size_t* out_count);
bool qihse_vector_store_validate_trinary(const void* data, size_t size);
bool qihse_vector_store_validate_magnitude(const void* data, size_t size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_VECTOR_STORE_H */
