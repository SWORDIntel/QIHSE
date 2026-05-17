#include "qihse_vector_store.h"

#include "qihse_file.h"
#include "qihse_persist_format.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define QIHSE_MANIFEST_NAME "MANIFEST"
#define QIHSE_LOCK_NAME "LOCK"
#define QIHSE_VECTOR_NAME "vectors.qvec"
#define QIHSE_TRINARY_NAME "vectors.qtri"
#define QIHSE_MAGNITUDE_NAME "vectors.qmag"
#define QIHSE_METADATA_NAME "metadata.qmeta"
#define QIHSE_INDEX_NAME "index.qidx"
#define QIHSE_IDMAP_NAME "idmap.qid"

#define QIHSE_TMP_SUFFIX ".tmp"

#define QIHSE_MANIFEST_MAGIC "QIHSEMAN"
#define QIHSE_INDEX_MAGIC "QIHSEQIX"
#define QIHSE_IDMAP_MAGIC "QIHSEQID"

#define QIHSE_MANIFEST_V1_SIZE 128u
#define QIHSE_MANIFEST_SIZE 192u
#define QIHSE_FILE_HEADER_SIZE 32u
#define QIHSE_FORMAT_VERSION 1u
#define QIHSE_INDEX_ROW_DISK_SIZE 48u
#define QIHSE_IDMAP_ENTRY_DISK_SIZE 16u

static bool qihse_store_path(char out[PATH_MAX], const char* db_path, const char* name) {
    return qihse_path_join(db_path, name, out, PATH_MAX);
}

static bool qihse_store_tmp_path(char out[PATH_MAX], const char* db_path, const char* name) {
    char tmp_name[128];
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(QIHSE_TMP_SUFFIX);

    if (name_len + suffix_len + 1u > sizeof(tmp_name)) {
        errno = ENAMETOOLONG;
        return false;
    }

    memcpy(tmp_name, name, name_len);
    memcpy(tmp_name + name_len, QIHSE_TMP_SUFFIX, suffix_len + 1u);
    return qihse_store_path(out, db_path, tmp_name);
}

static bool qihse_u64_to_size(uint64_t value, size_t* out) {
    if (!out || value > (uint64_t)SIZE_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    *out = (size_t)value;
    return true;
}

static bool qihse_read_file_alloc(const char* path, uint8_t** out, size_t* out_size) {
    qihse_file_t file;
    uint64_t file_size64;
    size_t file_size;
    uint8_t* data = NULL;

    if (!path || !out || !out_size) {
        errno = EINVAL;
        return false;
    }
    *out = NULL;
    *out_size = 0u;

    file.fd = QIHSE_FILE_INVALID_FD;
    if (!qihse_file_open(&file, path, O_RDONLY, 0)) {
        return false;
    }
    if (!qihse_file_size(&file, &file_size64) || !qihse_u64_to_size(file_size64, &file_size)) {
        qihse_file_close(&file);
        return false;
    }

    if (file_size != 0u) {
        data = (uint8_t*)malloc(file_size);
        if (!data) {
            qihse_file_close(&file);
            errno = ENOMEM;
            return false;
        }
        if (!qihse_file_pread_exact(&file, data, file_size, 0u)) {
            free(data);
            qihse_file_close(&file);
            return false;
        }
    }

    if (!qihse_file_close(&file)) {
        free(data);
        return false;
    }

    *out = data;
    *out_size = file_size;
    return true;
}

static bool qihse_write_file_atomic(const char* db_path,
                                    const char* name,
                                    const void* data,
                                    size_t size) {
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    qihse_file_t file;
    bool ok = false;

    if (!db_path || !name || (!data && size != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_store_path(path, db_path, name) || !qihse_store_tmp_path(tmp_path, db_path, name)) {
        return false;
    }

    file.fd = QIHSE_FILE_INVALID_FD;
    if (!qihse_file_open(&file, tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0666)) {
        return false;
    }
    if (qihse_file_pwrite_exact(&file, data, size, 0u) &&
        qihse_file_truncate(&file, (uint64_t)size) &&
        qihse_file_fsync(&file)) {
        ok = true;
    }
    if (!qihse_file_close(&file)) {
        ok = false;
    }
    if (!ok) {
        unlink(tmp_path);
        return false;
    }
    if (!qihse_rename_file(tmp_path, path)) {
        unlink(tmp_path);
        return false;
    }
    return qihse_fsync_dir(db_path);
}

static void qihse_encode_file_header(uint8_t out[QIHSE_FILE_HEADER_SIZE],
                                     const char magic[8],
                                     uint64_t count,
                                     uint64_t crc64,
                                     uint32_t row_bytes) {
    memset(out, 0, QIHSE_FILE_HEADER_SIZE);
    memcpy(out, magic, 8u);
    qihse_le_write_u32(out + 8u, QIHSE_FORMAT_VERSION);
    qihse_le_write_u32(out + 12u, row_bytes);
    qihse_le_write_u64(out + 16u, count);
    qihse_le_write_u64(out + 24u, crc64);
}

static bool qihse_decode_file_header(const uint8_t in[QIHSE_FILE_HEADER_SIZE],
                                     const char magic[8],
                                     uint64_t* count,
                                     uint64_t* crc64,
                                     uint32_t* row_bytes) {
    if (memcmp(in, magic, 8u) != 0 || qihse_le_read_u32(in + 8u) != QIHSE_FORMAT_VERSION) {
        errno = EINVAL;
        return false;
    }
    if (row_bytes) {
        *row_bytes = qihse_le_read_u32(in + 12u);
    }
    if (count) {
        *count = qihse_le_read_u64(in + 16u);
    }
    if (crc64) {
        *crc64 = qihse_le_read_u64(in + 24u);
    }
    return true;
}

static void qihse_encode_manifest(uint8_t out[QIHSE_MANIFEST_SIZE],
                                  const qihse_vector_store_manifest_t* m) {
    memset(out, 0, QIHSE_MANIFEST_SIZE);
    memcpy(out, QIHSE_MANIFEST_MAGIC, 8u);
    qihse_le_write_u32(out + 8u, m->format_version);
    qihse_le_write_u32(out + 12u, m->encoding_id);
    qihse_le_write_u32(out + 16u, m->encoding_version);
    qihse_le_write_u32(out + 20u, m->vector_dims);
    qihse_le_write_u64(out + 24u, m->row_count);
    qihse_le_write_u64(out + 32u, m->vector_bytes);
    qihse_le_write_u64(out + 40u, m->metadata_bytes);
    qihse_le_write_u64(out + 48u, m->commit_generation);
    qihse_le_write_u64(out + 56u, m->index_crc64);
    qihse_le_write_u64(out + 64u, m->vector_crc64);
    qihse_le_write_u64(out + 72u, m->metadata_crc64);
    qihse_le_write_u64(out + 80u, m->idmap_crc64);
    qihse_le_write_u64(out + 88u, m->trinary_generation);
    qihse_le_write_u64(out + 96u, m->trinary_row_bytes);
    qihse_le_write_u64(out + 104u, m->trinary_rows);
    qihse_le_write_u64(out + 112u, m->trinary_crc64);
    qihse_le_write_u32(out + 120u, m->trinary_flags);
    qihse_le_write_u64(out + 128u, m->magnitude_generation);
    qihse_le_write_u64(out + 136u, m->magnitude_row_bytes);
    qihse_le_write_u64(out + 144u, m->magnitude_rows);
    qihse_le_write_u64(out + 152u, m->magnitude_crc64);
    qihse_le_write_u32(out + 160u, m->magnitude_flags);
}

static bool qihse_decode_manifest(const uint8_t* in,
                                  size_t size,
                                  qihse_vector_store_manifest_t* m) {
    if (!in || !m ||
        (size != QIHSE_MANIFEST_V1_SIZE && size != QIHSE_MANIFEST_SIZE) ||
        memcmp(in, QIHSE_MANIFEST_MAGIC, 8u) != 0) {
        errno = EINVAL;
        return false;
    }

    memset(m, 0, sizeof(*m));
    m->format_version = qihse_le_read_u32(in + 8u);
    m->encoding_id = qihse_le_read_u32(in + 12u);
    m->encoding_version = qihse_le_read_u32(in + 16u);
    m->vector_dims = qihse_le_read_u32(in + 20u);
    m->row_count = qihse_le_read_u64(in + 24u);
    m->vector_bytes = qihse_le_read_u64(in + 32u);
    m->metadata_bytes = qihse_le_read_u64(in + 40u);
    m->commit_generation = qihse_le_read_u64(in + 48u);
    m->index_crc64 = qihse_le_read_u64(in + 56u);
    m->vector_crc64 = qihse_le_read_u64(in + 64u);
    m->metadata_crc64 = qihse_le_read_u64(in + 72u);
    m->idmap_crc64 = qihse_le_read_u64(in + 80u);
    m->trinary_generation = qihse_le_read_u64(in + 88u);
    m->trinary_row_bytes = qihse_le_read_u64(in + 96u);
    m->trinary_rows = qihse_le_read_u64(in + 104u);
    m->trinary_crc64 = qihse_le_read_u64(in + 112u);
    m->trinary_flags = qihse_le_read_u32(in + 120u);
    if (size >= QIHSE_MANIFEST_SIZE) {
        m->magnitude_generation = qihse_le_read_u64(in + 128u);
        m->magnitude_row_bytes = qihse_le_read_u64(in + 136u);
        m->magnitude_rows = qihse_le_read_u64(in + 144u);
        m->magnitude_crc64 = qihse_le_read_u64(in + 152u);
        m->magnitude_flags = qihse_le_read_u32(in + 160u);
    }

    if (m->format_version != QIHSE_FORMAT_VERSION ||
        m->encoding_id != QIHSE_VSTORE_ENCODING_FLOAT32 ||
        m->encoding_version != QIHSE_VSTORE_ENCODING_VERSION) {
        errno = EINVAL;
        return false;
    }

    return true;
}

static void qihse_encode_row(uint8_t out[QIHSE_INDEX_ROW_DISK_SIZE],
                             const qihse_index_row_t* row) {
    qihse_le_write_u64(out + 0u, row->vector_id);
    qihse_le_write_u64(out + 8u, row->vector_offset);
    qihse_le_write_u64(out + 16u, row->metadata_offset);
    qihse_le_write_u64(out + 24u, row->metadata_size);
    qihse_le_write_u64(out + 32u, row->commit_generation);
    qihse_le_write_u32(out + 40u, row->row_flags);
    qihse_le_write_u32(out + 44u, row->reserved);
}

static void qihse_decode_row(const uint8_t in[QIHSE_INDEX_ROW_DISK_SIZE],
                             qihse_index_row_t* row) {
    row->vector_id = qihse_le_read_u64(in + 0u);
    row->vector_offset = qihse_le_read_u64(in + 8u);
    row->metadata_offset = qihse_le_read_u64(in + 16u);
    row->metadata_size = qihse_le_read_u64(in + 24u);
    row->commit_generation = qihse_le_read_u64(in + 32u);
    row->row_flags = qihse_le_read_u32(in + 40u);
    row->reserved = qihse_le_read_u32(in + 44u);
}

static void qihse_encode_idmap(uint8_t out[QIHSE_IDMAP_ENTRY_DISK_SIZE],
                               const qihse_idmap_entry_t* entry) {
    qihse_le_write_u64(out + 0u, (uint64_t)entry->key);
    qihse_le_write_u64(out + 8u, entry->row_index);
}

static void qihse_decode_idmap(const uint8_t in[QIHSE_IDMAP_ENTRY_DISK_SIZE],
                               qihse_idmap_entry_t* entry) {
    entry->key = (int64_t)qihse_le_read_u64(in + 0u);
    entry->row_index = qihse_le_read_u64(in + 8u);
}

static bool qihse_encode_rows_buffer(const qihse_index_row_t* rows,
                                     size_t row_count,
                                     uint8_t** out,
                                     size_t* out_size,
                                     uint64_t* crc64) {
    size_t payload_size;
    uint8_t* data;
    size_t i;

    if ((!rows && row_count != 0u) || !out || !out_size || !crc64) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_checked_mul_size(row_count, QIHSE_INDEX_ROW_DISK_SIZE, &payload_size) ||
        !qihse_checked_add_size(QIHSE_FILE_HEADER_SIZE, payload_size, out_size)) {
        errno = EOVERFLOW;
        return false;
    }

    data = (uint8_t*)malloc(*out_size == 0u ? 1u : *out_size);
    if (!data) {
        errno = ENOMEM;
        return false;
    }
    memset(data, 0, *out_size);

    for (i = 0u; i < row_count; i++) {
        qihse_encode_row(data + QIHSE_FILE_HEADER_SIZE + (i * QIHSE_INDEX_ROW_DISK_SIZE), rows + i);
    }
    *crc64 = qihse_fnv1a64(data + QIHSE_FILE_HEADER_SIZE, payload_size);
    qihse_encode_file_header(data, QIHSE_INDEX_MAGIC, (uint64_t)row_count, *crc64,
                             QIHSE_INDEX_ROW_DISK_SIZE);
    *out = data;
    return true;
}

static bool qihse_encode_idmap_buffer(const qihse_idmap_entry_t* entries,
                                      size_t entry_count,
                                      uint8_t** out,
                                      size_t* out_size,
                                      uint64_t* crc64) {
    size_t payload_size;
    uint8_t* data;
    size_t i;

    if ((!entries && entry_count != 0u) || !out || !out_size || !crc64) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_checked_mul_size(entry_count, QIHSE_IDMAP_ENTRY_DISK_SIZE, &payload_size) ||
        !qihse_checked_add_size(QIHSE_FILE_HEADER_SIZE, payload_size, out_size)) {
        errno = EOVERFLOW;
        return false;
    }

    data = (uint8_t*)malloc(*out_size == 0u ? 1u : *out_size);
    if (!data) {
        errno = ENOMEM;
        return false;
    }
    memset(data, 0, *out_size);

    for (i = 0u; i < entry_count; i++) {
        if (i != 0u && entries[i - 1u].key > entries[i].key) {
            free(data);
            errno = EINVAL;
            return false;
        }
        qihse_encode_idmap(data + QIHSE_FILE_HEADER_SIZE + (i * QIHSE_IDMAP_ENTRY_DISK_SIZE),
                           entries + i);
    }
    *crc64 = qihse_fnv1a64(data + QIHSE_FILE_HEADER_SIZE, payload_size);
    qihse_encode_file_header(data, QIHSE_IDMAP_MAGIC, (uint64_t)entry_count, *crc64,
                             QIHSE_IDMAP_ENTRY_DISK_SIZE);
    *out = data;
    return true;
}

static bool qihse_load_manifest(const char* db_path, qihse_vector_store_manifest_t* out) {
    char path[PATH_MAX];
    uint8_t* data = NULL;
    size_t size = 0u;
    bool ok;

    if (!qihse_store_path(path, db_path, QIHSE_MANIFEST_NAME)) {
        return false;
    }
    if (!qihse_read_file_alloc(path, &data, &size)) {
        return false;
    }
    if (size != QIHSE_MANIFEST_V1_SIZE && size != QIHSE_MANIFEST_SIZE) {
        free(data);
        errno = EINVAL;
        return false;
    }

    ok = qihse_decode_manifest(data, size, out);
    free(data);
    return ok;
}

static bool qihse_load_raw_checked(const char* db_path,
                                   const char* name,
                                   uint64_t expected_size64,
                                   uint64_t expected_crc64,
                                   uint8_t** out,
                                   size_t* out_size) {
    char path[PATH_MAX];

    if (!qihse_store_path(path, db_path, name)) {
        return false;
    }
    if (!qihse_read_file_alloc(path, out, out_size)) {
        return false;
    }
    if ((uint64_t)*out_size != expected_size64 ||
        qihse_fnv1a64(*out, *out_size) != expected_crc64) {
        free(*out);
        *out = NULL;
        *out_size = 0u;
        errno = EINVAL;
        return false;
    }
    return true;
}

static bool qihse_load_index(const char* db_path,
                             const qihse_vector_store_manifest_t* manifest,
                             qihse_index_row_t** out_rows,
                             size_t* out_count) {
    char path[PATH_MAX];
    uint8_t* data = NULL;
    size_t size = 0u;
    size_t payload_size;
    size_t expected_size;
    uint64_t count64;
    uint64_t crc64;
    uint32_t row_bytes;
    qihse_index_row_t* rows = NULL;
    size_t row_count;
    size_t i;

    if (!qihse_store_path(path, db_path, QIHSE_INDEX_NAME) ||
        !qihse_read_file_alloc(path, &data, &size)) {
        return false;
    }
    if (size < QIHSE_FILE_HEADER_SIZE ||
        !qihse_decode_file_header(data, QIHSE_INDEX_MAGIC, &count64, &crc64, &row_bytes) ||
        row_bytes != QIHSE_INDEX_ROW_DISK_SIZE ||
        count64 != manifest->row_count ||
        crc64 != manifest->index_crc64 ||
        !qihse_u64_to_size(count64, &row_count) ||
        !qihse_checked_mul_size(row_count, QIHSE_INDEX_ROW_DISK_SIZE, &payload_size) ||
        !qihse_checked_add_size(QIHSE_FILE_HEADER_SIZE, payload_size, &expected_size) ||
        size != expected_size ||
        qihse_fnv1a64(data + QIHSE_FILE_HEADER_SIZE, payload_size) != crc64) {
        free(data);
        errno = EINVAL;
        return false;
    }

    if (row_count != 0u) {
        rows = (qihse_index_row_t*)calloc(row_count, sizeof(*rows));
        if (!rows) {
            free(data);
            errno = ENOMEM;
            return false;
        }
        for (i = 0u; i < row_count; i++) {
            qihse_decode_row(data + QIHSE_FILE_HEADER_SIZE + (i * QIHSE_INDEX_ROW_DISK_SIZE),
                             rows + i);
        }
    }

    free(data);
    *out_rows = rows;
    *out_count = row_count;
    return true;
}

static bool qihse_load_idmap_optional(const char* db_path,
                                      const qihse_vector_store_manifest_t* manifest,
                                      qihse_idmap_entry_t** out_entries,
                                      size_t* out_count) {
    char path[PATH_MAX];
    uint8_t* data = NULL;
    size_t size = 0u;
    size_t payload_size;
    size_t expected_size;
    uint64_t count64;
    uint64_t crc64;
    uint32_t row_bytes;
    qihse_idmap_entry_t* entries = NULL;
    size_t entry_count;
    size_t i;

    *out_entries = NULL;
    *out_count = 0u;
    if (!qihse_store_path(path, db_path, QIHSE_IDMAP_NAME) ||
        !qihse_read_file_alloc(path, &data, &size)) {
        return false;
    }
    if (size < QIHSE_FILE_HEADER_SIZE ||
        !qihse_decode_file_header(data, QIHSE_IDMAP_MAGIC, &count64, &crc64, &row_bytes) ||
        row_bytes != QIHSE_IDMAP_ENTRY_DISK_SIZE ||
        crc64 != manifest->idmap_crc64 ||
        !qihse_u64_to_size(count64, &entry_count) ||
        !qihse_checked_mul_size(entry_count, QIHSE_IDMAP_ENTRY_DISK_SIZE, &payload_size) ||
        !qihse_checked_add_size(QIHSE_FILE_HEADER_SIZE, payload_size, &expected_size) ||
        size != expected_size ||
        qihse_fnv1a64(data + QIHSE_FILE_HEADER_SIZE, payload_size) != crc64) {
        free(data);
        errno = EINVAL;
        return false;
    }

    if (entry_count != 0u) {
        entries = (qihse_idmap_entry_t*)calloc(entry_count, sizeof(*entries));
        if (!entries) {
            free(data);
            errno = ENOMEM;
            return false;
        }
        for (i = 0u; i < entry_count; i++) {
            qihse_decode_idmap(data + QIHSE_FILE_HEADER_SIZE + (i * QIHSE_IDMAP_ENTRY_DISK_SIZE),
                               entries + i);
            if ((i != 0u && entries[i - 1u].key > entries[i].key) ||
                entries[i].row_index >= manifest->row_count) {
                free(entries);
                free(data);
                errno = EINVAL;
                return false;
            }
        }
    }

    free(data);
    *out_entries = entries;
    *out_count = entry_count;
    return true;
}

static bool qihse_load_trinary_optional(const char* db_path,
                                        const qihse_vector_store_manifest_t* manifest,
                                        uint8_t** out,
                                        size_t* out_size) {
    char path[PATH_MAX];
    uint8_t* data = NULL;
    size_t size = 0u;
    uint64_t expected_size64;

    *out = NULL;
    *out_size = 0u;
    if ((manifest->trinary_flags & QIHSE_VSTORE_TRI_PRESENT) == 0u) {
        return false;
    }
    if (!qihse_checked_mul_u64(manifest->trinary_rows, manifest->trinary_row_bytes,
                               &expected_size64)) {
        errno = EOVERFLOW;
        return false;
    }
    if (!qihse_store_path(path, db_path, QIHSE_TRINARY_NAME) ||
        !qihse_read_file_alloc(path, &data, &size)) {
        return false;
    }
    if ((uint64_t)size != expected_size64 ||
        qihse_fnv1a64(data, size) != manifest->trinary_crc64 ||
        !qihse_vector_store_validate_trinary(data, size)) {
        free(data);
        errno = EINVAL;
        return false;
    }

    *out = data;
    *out_size = size;
    return true;
}

static bool qihse_load_magnitude_optional(const char* db_path,
                                          const qihse_vector_store_manifest_t* manifest,
                                          uint8_t** out,
                                          size_t* out_size) {
    char path[PATH_MAX];
    uint8_t* data = NULL;
    size_t size = 0u;
    uint64_t expected_size64;

    *out = NULL;
    *out_size = 0u;
    if ((manifest->magnitude_flags & QIHSE_VSTORE_MAG_PRESENT) == 0u) {
        return false;
    }
    if (!qihse_checked_mul_u64(manifest->magnitude_rows,
                               manifest->magnitude_row_bytes,
                               &expected_size64)) {
        errno = EOVERFLOW;
        return false;
    }
    if (!qihse_store_path(path, db_path, QIHSE_MAGNITUDE_NAME) ||
        !qihse_read_file_alloc(path, &data, &size)) {
        return false;
    }
    if ((uint64_t)size != expected_size64 ||
        qihse_fnv1a64(data, size) != manifest->magnitude_crc64 ||
        !qihse_vector_store_validate_magnitude(data, size)) {
        free(data);
        errno = EINVAL;
        return false;
    }

    *out = data;
    *out_size = size;
    return true;
}

static int qihse_idmap_compare(const void* a, const void* b) {
    const qihse_idmap_entry_t* ea = (const qihse_idmap_entry_t*)a;
    const qihse_idmap_entry_t* eb = (const qihse_idmap_entry_t*)b;
    if (ea->key < eb->key) {
        return -1;
    }
    if (ea->key > eb->key) {
        return 1;
    }
    if (ea->row_index < eb->row_index) {
        return -1;
    }
    if (ea->row_index > eb->row_index) {
        return 1;
    }
    return 0;
}

static int64_t qihse_u64_to_sortable_i64(uint64_t id) {
    return (int64_t)(id ^ UINT64_C(0x8000000000000000));
}

bool qihse_vector_store_validate_trinary(const void* data, size_t size) {
    const uint8_t* p = (const uint8_t*)data;
    size_t i;

    if (!p && size != 0u) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < size; i++) {
        if (p[i] >= 243u) {
            errno = EINVAL;
            return false;
        }
    }
    return true;
}

bool qihse_vector_store_validate_magnitude(const void* data, size_t size) {
    if (!data && size != 0u) {
        errno = EINVAL;
        return false;
    }
    return true;
}

bool qihse_vector_store_build_idmap(const qihse_index_row_t* rows,
                                    size_t row_count,
                                    qihse_idmap_entry_t** out_entries,
                                    size_t* out_count) {
    qihse_idmap_entry_t* entries = NULL;
    size_t live_count = 0u;
    size_t i;
    size_t j = 0u;

    if ((!rows && row_count != 0u) || !out_entries || !out_count) {
        errno = EINVAL;
        return false;
    }
    *out_entries = NULL;
    *out_count = 0u;

    for (i = 0u; i < row_count; i++) {
        if ((rows[i].row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            live_count++;
        }
    }

    if (live_count != 0u) {
        entries = (qihse_idmap_entry_t*)calloc(live_count, sizeof(*entries));
        if (!entries) {
            errno = ENOMEM;
            return false;
        }
        for (i = 0u; i < row_count; i++) {
            if ((rows[i].row_flags & QIHSE_ROW_F_LIVE) != 0u &&
                (rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
                entries[j].key = qihse_u64_to_sortable_i64(rows[i].vector_id);
                entries[j].row_index = (uint64_t)i;
                j++;
            }
        }
        qsort(entries, live_count, sizeof(*entries), qihse_idmap_compare);
    }

    *out_entries = entries;
    *out_count = live_count;
    return true;
}

bool qihse_vector_store_load(const char* db_path, qihse_vector_store_snapshot_t* out) {
    qihse_vector_store_snapshot_t snapshot;

    if (!db_path || !out) {
        errno = EINVAL;
        return false;
    }
    memset(&snapshot, 0, sizeof(snapshot));

    if (!qihse_load_manifest(db_path, &snapshot.manifest) ||
        !qihse_load_index(db_path, &snapshot.manifest, &snapshot.rows, &snapshot.row_count) ||
        !qihse_load_raw_checked(db_path, QIHSE_VECTOR_NAME, snapshot.manifest.vector_bytes,
                                snapshot.manifest.vector_crc64, &snapshot.vectors,
                                &snapshot.vector_bytes) ||
        !qihse_load_raw_checked(db_path, QIHSE_METADATA_NAME, snapshot.manifest.metadata_bytes,
                                snapshot.manifest.metadata_crc64, &snapshot.metadata,
                                &snapshot.metadata_bytes)) {
        qihse_vector_store_snapshot_free(&snapshot);
        return false;
    }

    if (qihse_load_idmap_optional(db_path, &snapshot.manifest,
                                  &snapshot.idmap, &snapshot.idmap_count)) {
        snapshot.idmap_valid = true;
    } else {
        snapshot.idmap_valid = false;
        free(snapshot.idmap);
        snapshot.idmap = NULL;
        snapshot.idmap_count = 0u;
    }

    if (qihse_load_trinary_optional(db_path, &snapshot.manifest,
                                    &snapshot.trinary, &snapshot.trinary_bytes)) {
        snapshot.trinary_valid = true;
        snapshot.manifest.trinary_flags |= QIHSE_VSTORE_TRI_VALID;
    } else {
        snapshot.trinary_valid = false;
        free(snapshot.trinary);
        snapshot.trinary = NULL;
        snapshot.trinary_bytes = 0u;
        snapshot.manifest.trinary_flags &= ~QIHSE_VSTORE_TRI_VALID;
    }

    if (qihse_load_magnitude_optional(db_path, &snapshot.manifest,
                                      &snapshot.magnitude, &snapshot.magnitude_bytes)) {
        snapshot.magnitude_valid = true;
        snapshot.manifest.magnitude_flags |= QIHSE_VSTORE_MAG_VALID;
    } else {
        snapshot.magnitude_valid = false;
        free(snapshot.magnitude);
        snapshot.magnitude = NULL;
        snapshot.magnitude_bytes = 0u;
        snapshot.manifest.magnitude_flags &= ~QIHSE_VSTORE_MAG_VALID;
    }

    *out = snapshot;
    return true;
}

bool qihse_vector_store_flush(const char* db_path, const qihse_vector_store_flush_t* in) {
    qihse_lock_t lock;
    char lock_path[PATH_MAX];
    qihse_vector_store_manifest_t manifest;
    qihse_idmap_entry_t* built_idmap = NULL;
    const qihse_idmap_entry_t* idmap = NULL;
    size_t idmap_count = 0u;
    uint8_t* index_data = NULL;
    size_t index_size = 0u;
    uint8_t* idmap_data = NULL;
    size_t idmap_size = 0u;
    uint8_t manifest_data[QIHSE_MANIFEST_SIZE];
    uint64_t index_crc64 = 0u;
    uint64_t idmap_crc64 = 0u;
    bool ok = false;

    if (!db_path || !in ||
        (!in->rows && in->row_count != 0u) ||
        (!in->vectors && in->vector_bytes != 0u) ||
        (!in->metadata && in->metadata_bytes != 0u) ||
        (!in->idmap && in->idmap_count != 0u) ||
        (!in->trinary && in->trinary_bytes != 0u) ||
        (!in->magnitude && in->magnitude_bytes != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (in->trinary_bytes != 0u && !qihse_vector_store_validate_trinary(in->trinary, in->trinary_bytes)) {
        return false;
    }
    if (in->trinary_bytes != 0u) {
        uint64_t expected_trinary_size;
        if (!qihse_checked_mul_u64(in->trinary_row_bytes, (uint64_t)in->row_count,
                                   &expected_trinary_size) ||
            expected_trinary_size != (uint64_t)in->trinary_bytes) {
            errno = EINVAL;
            return false;
        }
    }
    if (in->magnitude_bytes != 0u &&
        !qihse_vector_store_validate_magnitude(in->magnitude, in->magnitude_bytes)) {
        return false;
    }
    if (in->magnitude_bytes != 0u) {
        uint64_t expected_magnitude_size;
        if (!qihse_checked_mul_u64(in->magnitude_row_bytes, (uint64_t)in->row_count,
                                   &expected_magnitude_size) ||
            expected_magnitude_size != (uint64_t)in->magnitude_bytes) {
            errno = EINVAL;
            return false;
        }
    }

    if (!qihse_mkdir_p(db_path, 0777) || !qihse_store_path(lock_path, db_path, QIHSE_LOCK_NAME)) {
        return false;
    }
    if (!qihse_lock_acquire(&lock, lock_path)) {
        return false;
    }

    if (in->idmap) {
        idmap = in->idmap;
        idmap_count = in->idmap_count;
    } else if (!qihse_vector_store_build_idmap(in->rows, in->row_count, &built_idmap, &idmap_count)) {
        goto done;
    } else {
        idmap = built_idmap;
    }

    if (!qihse_encode_rows_buffer(in->rows, in->row_count, &index_data, &index_size, &index_crc64) ||
        !qihse_encode_idmap_buffer(idmap, idmap_count, &idmap_data, &idmap_size, &idmap_crc64)) {
        goto done;
    }

    memset(&manifest, 0, sizeof(manifest));
    manifest.format_version = QIHSE_FORMAT_VERSION;
    manifest.encoding_id = QIHSE_VSTORE_ENCODING_FLOAT32;
    manifest.encoding_version = QIHSE_VSTORE_ENCODING_VERSION;
    manifest.vector_dims = in->vector_dims;
    manifest.row_count = (uint64_t)in->row_count;
    manifest.vector_bytes = (uint64_t)in->vector_bytes;
    manifest.metadata_bytes = (uint64_t)in->metadata_bytes;
    manifest.commit_generation = in->commit_generation;
    manifest.index_crc64 = index_crc64;
    manifest.vector_crc64 = qihse_fnv1a64(in->vectors, in->vector_bytes);
    manifest.metadata_crc64 = qihse_fnv1a64(in->metadata, in->metadata_bytes);
    manifest.idmap_crc64 = idmap_crc64;
    if (in->trinary_bytes != 0u) {
        manifest.trinary_generation = in->trinary_generation;
        manifest.trinary_row_bytes = in->trinary_row_bytes;
        manifest.trinary_rows = (uint64_t)in->row_count;
        manifest.trinary_crc64 = qihse_fnv1a64(in->trinary, in->trinary_bytes);
        manifest.trinary_flags = in->trinary_flags | QIHSE_VSTORE_TRI_PRESENT | QIHSE_VSTORE_TRI_VALID;
    }
    if (in->magnitude_bytes != 0u) {
        manifest.magnitude_generation = in->magnitude_generation;
        manifest.magnitude_row_bytes = in->magnitude_row_bytes;
        manifest.magnitude_rows = (uint64_t)in->row_count;
        manifest.magnitude_crc64 = qihse_fnv1a64(in->magnitude, in->magnitude_bytes);
        manifest.magnitude_flags =
            in->magnitude_flags | QIHSE_VSTORE_MAG_PRESENT | QIHSE_VSTORE_MAG_VALID;
    }
    qihse_encode_manifest(manifest_data, &manifest);

    if (!qihse_write_file_atomic(db_path, QIHSE_VECTOR_NAME, in->vectors, in->vector_bytes) ||
        !qihse_write_file_atomic(db_path, QIHSE_METADATA_NAME, in->metadata, in->metadata_bytes) ||
        !qihse_write_file_atomic(db_path, QIHSE_INDEX_NAME, index_data, index_size) ||
        !qihse_write_file_atomic(db_path, QIHSE_IDMAP_NAME, idmap_data, idmap_size)) {
        goto done;
    }
    if (in->trinary_bytes != 0u &&
        !qihse_write_file_atomic(db_path, QIHSE_TRINARY_NAME, in->trinary, in->trinary_bytes)) {
        goto done;
    }
    if (in->magnitude_bytes != 0u &&
        !qihse_write_file_atomic(db_path, QIHSE_MAGNITUDE_NAME,
                                 in->magnitude, in->magnitude_bytes)) {
        goto done;
    }
    if (!qihse_write_file_atomic(db_path, QIHSE_MANIFEST_NAME, manifest_data, sizeof(manifest_data))) {
        goto done;
    }

    ok = true;

done:
    free(index_data);
    free(idmap_data);
    free(built_idmap);
    if (!qihse_lock_release(&lock)) {
        ok = false;
    }
    return ok;
}

void qihse_vector_store_snapshot_free(qihse_vector_store_snapshot_t* snapshot) {
    if (!snapshot) {
        return;
    }
    free(snapshot->rows);
    free(snapshot->vectors);
    free(snapshot->metadata);
    free(snapshot->idmap);
    free(snapshot->trinary);
    free(snapshot->magnitude);
    memset(snapshot, 0, sizeof(*snapshot));
}
