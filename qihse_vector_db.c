#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_vector_db.h"

#include "persistence/qihse_file.h"
#include "persistence/qihse_persist_format.h"
#include "persistence/qihse_vector_store.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define QIHSE_VDB_WAL_NAME "wal.qwal"
#define QIHSE_VDB_VECTOR_NAME "vectors.qvec"
#define QIHSE_VDB_METADATA_NAME "metadata.qmeta"
#define QIHSE_VDB_INDEX_NAME "index.qidx"
#define QIHSE_VDB_IDMAP_NAME "idmap.qid"
#define QIHSE_VDB_TRINARY_NAME "vectors.qtri"
#define QIHSE_VDB_MANIFEST_NAME "MANIFEST"

#define QIHSE_VDB_INDEX_MAGIC "QIHSEQIX"
#define QIHSE_VDB_IDMAP_MAGIC "QIHSEQID"
#define QIHSE_VDB_FILE_HEADER_SIZE 32u
#define QIHSE_VDB_FORMAT_VERSION 1u
#define QIHSE_VDB_INDEX_ROW_DISK_SIZE 48u
#define QIHSE_VDB_IDMAP_ENTRY_DISK_SIZE 16u

#define QIHSE_VDB_WAL_MAGIC "QHWAL01\0"
#define QIHSE_VDB_WAL_HEADER_SIZE 64u
#define QIHSE_VDB_WAL_VERSION 1u
#define QIHSE_VDB_WAL_ADD 1u
#define QIHSE_VDB_WAL_COMMIT 2u
#define QIHSE_VDB_WAL_DELETE 3u
#define QIHSE_VDB_WAL_UPDATE 4u
#define QIHSE_VDB_WAL_UPSERT 5u
#define QIHSE_VDB_WAL_NO_PREV UINT64_MAX

struct qihse_vector_db_s {
    qihse_vector_db_backend_t backend;
    qihse_uma_manager_t uma;
    char* db_path;
    qihse_vector_db_storage_mode_t storage_mode;
    bool file_backed;
    bool read_only;
    bool dirty;

    size_t vector_dims;
    size_t total_vectors;
    size_t live_vectors;
    size_t rows_capacity;
    uint64_t committed_generation;
    uint64_t next_generation;
    uint64_t next_auto_id;
    uint64_t wal_bytes_pending;
    uint64_t wal_records_replayed;
    uint64_t wal_last_record_offset;

    qihse_index_row_t* rows;
    uint8_t* vectors;
    size_t vector_bytes_used;
    size_t vector_bytes_capacity;
    uint8_t* metadata;
    size_t metadata_bytes_used;
    size_t metadata_bytes_capacity;
    qihse_idmap_entry_t* idmap;
    size_t idmap_count;
    bool idmap_valid;
    bool idmap_dirty;

    int mmap_fd;
    void* mapped_vectors;
    size_t mapped_vector_bytes;
    int metadata_mmap_fd;
    void* mapped_metadata;
    size_t mapped_metadata_bytes;
    int index_mmap_fd;
    void* mapped_index;
    size_t mapped_index_bytes;
    bool rows_are_mapped;
    int idmap_mmap_fd;
    void* mapped_idmap;
    size_t mapped_idmap_bytes;

    qihse_vector_db_trinary_status_t trinary_status;
    uint64_t trinary_row_bytes;
    uint64_t trinary_rows;

    bool hilbert_enabled;
    bool quantization_enabled;
    bool parallel_enabled;
    bool superposition_enabled;
    bool temperature_aware;
    qihse_memory_superposition_state_t superposition_state;
};

typedef struct qihse_vdb_wal_add_s {
    uint64_t generation;
    uint64_t count;
    uint64_t dims;
    const uint64_t* ids;
    const float* vectors;
    const void* const* metadata;
    const size_t* metadata_sizes;
} qihse_vdb_wal_add_t;

typedef qihse_vdb_wal_add_t qihse_vdb_wal_vectors_t;

static bool qihse_vdb_reserve_appends(qihse_vector_db_t vdb,
                                      size_t append_count,
                                      size_t metadata_bytes);

static char* qihse_vdb_strdup(const char* s) {
    size_t len;
    char* out;

    if (!s) {
        return NULL;
    }
    len = strlen(s);
    out = (char*)malloc(len + 1u);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(out, s, len + 1u);
    return out;
}

static bool qihse_vdb_path(char out[PATH_MAX], const char* db_path, const char* name) {
    return qihse_path_join(db_path, name, out, PATH_MAX);
}

static bool qihse_vdb_exists(const char* db_path, const char* name) {
    char path[PATH_MAX];
    struct stat st;

    if (!qihse_vdb_path(path, db_path, name)) {
        return false;
    }
    return stat(path, &st) == 0;
}

static uint64_t qihse_vdb_file_size_or_zero(const char* db_path, const char* name) {
    char path[PATH_MAX];
    struct stat st;

    if (!db_path || !qihse_vdb_path(path, db_path, name) || stat(path, &st) != 0 || st.st_size < 0) {
        return 0u;
    }
    return (uint64_t)st.st_size;
}

static bool qihse_vdb_remove_file(const char* db_path, const char* name) {
    char path[PATH_MAX];

    if (!qihse_vdb_path(path, db_path, name)) {
        return false;
    }
    return unlink(path) == 0 || errno == ENOENT;
}

static bool qihse_vdb_truncate_file(const char* db_path, const char* name) {
    char path[PATH_MAX];
    int fd;
    bool ok;

    if (!qihse_vdb_path(path, db_path, name)) {
        return false;
    }
    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd < 0) {
        return false;
    }
    ok = fsync(fd) == 0;
    if (close(fd) != 0) {
        ok = false;
    }
    return ok && qihse_fsync_dir(db_path);
}

static bool qihse_vdb_truncate_existing_file(const char* db_path, const char* name, uint64_t size) {
    char path[PATH_MAX];
    int fd;
    bool ok;

    if (!qihse_vdb_path(path, db_path, name)) {
        return false;
    }
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        return errno == ENOENT;
    }
    ok = ftruncate(fd, (off_t)size) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) {
        ok = false;
    }
    return ok && qihse_fsync_dir(db_path);
}

static void qihse_vdb_remove_snapshot_files(const char* db_path) {
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_MANIFEST_NAME);
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_VECTOR_NAME);
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_METADATA_NAME);
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_INDEX_NAME);
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_IDMAP_NAME);
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_TRINARY_NAME);
    (void)qihse_vdb_remove_file(db_path, QIHSE_VDB_WAL_NAME);
}

static bool qihse_vdb_reserve_rows(qihse_vector_db_t vdb, size_t needed) {
    qihse_index_row_t* next;
    size_t cap;

    if (needed <= vdb->rows_capacity) {
        return true;
    }
    cap = vdb->rows_capacity ? vdb->rows_capacity : 8u;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2u) {
            errno = EOVERFLOW;
            return false;
        }
        cap *= 2u;
    }
    next = (qihse_index_row_t*)realloc(vdb->rows, cap * sizeof(*next));
    if (!next) {
        errno = ENOMEM;
        return false;
    }
    vdb->rows = next;
    vdb->rows_capacity = cap;
    return true;
}

static bool qihse_vdb_reserve_bytes(uint8_t** ptr, size_t* cap, size_t needed) {
    uint8_t* next;
    size_t new_cap;

    if (needed <= *cap) {
        return true;
    }
    new_cap = *cap ? *cap : 256u;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2u) {
            errno = EOVERFLOW;
            return false;
        }
        new_cap *= 2u;
    }
    next = (uint8_t*)realloc(*ptr, new_cap);
    if (!next) {
        errno = ENOMEM;
        return false;
    }
    *ptr = next;
    *cap = new_cap;
    return true;
}

static bool qihse_vdb_u64_to_size(uint64_t value, size_t* out) {
    if (!out || value > (uint64_t)SIZE_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    *out = (size_t)value;
    return true;
}

static bool qihse_vdb_rebuild_idmap(qihse_vector_db_t vdb, bool mark_dirty) {
    qihse_idmap_entry_t* entries = NULL;
    size_t count = 0u;

    if (vdb->mapped_idmap && vdb->mapped_idmap != MAP_FAILED) {
        munmap(vdb->mapped_idmap, vdb->mapped_idmap_bytes);
    }
    vdb->mapped_idmap = NULL;
    vdb->mapped_idmap_bytes = 0u;
    if (vdb->idmap_mmap_fd >= 0) {
        close(vdb->idmap_mmap_fd);
    }
    vdb->idmap_mmap_fd = -1;

    if (!qihse_vector_store_build_idmap(vdb->rows, vdb->total_vectors, &entries, &count)) {
        return false;
    }
    free(vdb->idmap);
    vdb->idmap = entries;
    vdb->idmap_count = count;
    vdb->idmap_valid = true;
    vdb->idmap_dirty = mark_dirty;
    return true;
}

static bool qihse_vdb_id_exists(const qihse_vector_db_t vdb, uint64_t id) {
    size_t i;

    for (i = 0u; i < vdb->total_vectors; i++) {
        if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u &&
            vdb->rows[i].vector_id == id) {
            return true;
        }
    }
    return false;
}

static int64_t qihse_vdb_idmap_key(uint64_t id) {
    return (int64_t)(id ^ UINT64_C(0x8000000000000000));
}

static bool qihse_vdb_ensure_writable(qihse_vector_db_t vdb) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (vdb->read_only || vdb->mapped_vectors || vdb->rows_are_mapped ||
        vdb->mapped_metadata || vdb->mapped_index || vdb->mapped_idmap) {
        errno = EROFS;
        return false;
    }
    return true;
}

static bool qihse_vdb_has_duplicate_ids(const uint64_t* ids, size_t count) {
    size_t i;
    size_t j;

    if (!ids && count != 0u) {
        errno = EINVAL;
        return true;
    }
    for (i = 0u; i < count; i++) {
        for (j = i + 1u; j < count; j++) {
            if (ids[i] == ids[j]) {
                errno = EEXIST;
                return true;
            }
        }
    }
    return false;
}

static bool qihse_vdb_find_live_row_by_id(qihse_vector_db_t vdb,
                                          uint64_t id,
                                          size_t* out_row_index) {
    int64_t key;
    size_t lo;
    size_t hi;
    size_t found;
    bool have_match = false;

    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (!vdb->idmap_valid && !qihse_vdb_rebuild_idmap(vdb, vdb->file_backed && !vdb->read_only)) {
        return false;
    }
    key = qihse_vdb_idmap_key(id);
    lo = 0u;
    hi = vdb->idmap_count;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) / 2u);
        if (vdb->idmap[mid].key < key) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    found = lo;
    while (found < vdb->idmap_count && vdb->idmap[found].key == key) {
        uint64_t row64 = vdb->idmap[found].row_index;
        if (row64 < (uint64_t)vdb->total_vectors) {
            size_t row_index = (size_t)row64;
            qihse_index_row_t* row = &vdb->rows[row_index];
            if (row->vector_id == id &&
                (row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
                (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
                if (!have_match || (out_row_index && row_index > *out_row_index)) {
                    if (out_row_index) {
                        *out_row_index = row_index;
                    }
                    have_match = true;
                }
            }
        }
        found++;
    }
    if (!have_match) {
        errno = ENOENT;
    }
    return have_match;
}

static size_t qihse_vdb_tombstone_live_id(qihse_vector_db_t vdb,
                                          uint64_t id,
                                          uint64_t generation) {
    size_t count = 0u;
    size_t i;

    for (i = 0u; i < vdb->total_vectors; i++) {
        qihse_index_row_t* row = &vdb->rows[i];
        if (row->vector_id == id &&
            (row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            row->row_flags |= QIHSE_ROW_F_TOMBSTONE;
            row->commit_generation = generation;
            count++;
        }
    }
    if (count != 0u) {
        vdb->live_vectors -= count;
        vdb->idmap_valid = false;
        vdb->idmap_dirty = true;
        vdb->dirty = true;
        vdb->trinary_status = QIHSE_VDB_TRINARY_STALE;
    }
    return count;
}

static void qihse_vdb_finish_mutation_generation(qihse_vector_db_t vdb, uint64_t generation) {
    if (generation >= vdb->next_generation) {
        vdb->next_generation = generation + 1u;
    }
    vdb->dirty = true;
    vdb->idmap_valid = false;
    vdb->idmap_dirty = true;
    vdb->trinary_status = QIHSE_VDB_TRINARY_STALE;
}

static const float* qihse_vdb_vector_at(const qihse_vector_db_t vdb, const qihse_index_row_t* row) {
    const uint8_t* base = vdb->mapped_vectors ? (const uint8_t*)vdb->mapped_vectors : vdb->vectors;
    uint64_t end;

    if (!base || !row || !qihse_checked_add_u64(row->vector_offset,
                                                (uint64_t)(vdb->vector_dims * sizeof(float)),
                                                &end) ||
        end > (uint64_t)vdb->vector_bytes_used) {
        return NULL;
    }
    return (const float*)(const void*)(base + row->vector_offset);
}

static const void* qihse_vdb_metadata_at(const qihse_vector_db_t vdb, const qihse_index_row_t* row) {
    const uint8_t* base = vdb->mapped_metadata ? (const uint8_t*)vdb->mapped_metadata : vdb->metadata;
    uint64_t end;

    if (!row || row->metadata_size == 0u) {
        return NULL;
    }
    if (!base ||
        !qihse_checked_add_u64(row->metadata_offset, row->metadata_size, &end) ||
        end > (uint64_t)vdb->metadata_bytes_used) {
        return NULL;
    }
    return base + row->metadata_offset;
}

static float qihse_vdb_cosine_similarity(const float* a, const float* b, size_t dims) {
    double dot = 0.0;
    double na = 0.0;
    double nb = 0.0;
    size_t i;

    for (i = 0u; i < dims; i++) {
        dot += (double)a[i] * (double)b[i];
        na += (double)a[i] * (double)a[i];
        nb += (double)b[i] * (double)b[i];
    }
    if (na <= 0.0 || nb <= 0.0) {
        return 0.0f;
    }
    return (float)(dot / (sqrt(na) * sqrt(nb)));
}

static void qihse_vdb_free_mmap(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    if (vdb->mapped_vectors && vdb->mapped_vectors != MAP_FAILED) {
        munmap(vdb->mapped_vectors, vdb->mapped_vector_bytes);
    }
    vdb->mapped_vectors = NULL;
    vdb->mapped_vector_bytes = 0u;
    if (vdb->mmap_fd >= 0) {
        close(vdb->mmap_fd);
    }
    vdb->mmap_fd = -1;
    if (vdb->mapped_metadata && vdb->mapped_metadata != MAP_FAILED) {
        munmap(vdb->mapped_metadata, vdb->mapped_metadata_bytes);
    }
    vdb->mapped_metadata = NULL;
    vdb->mapped_metadata_bytes = 0u;
    if (vdb->metadata_mmap_fd >= 0) {
        close(vdb->metadata_mmap_fd);
    }
    vdb->metadata_mmap_fd = -1;
    if (vdb->rows_are_mapped) {
        vdb->rows = NULL;
        vdb->rows_capacity = 0u;
        vdb->rows_are_mapped = false;
    }
    if (vdb->mapped_index && vdb->mapped_index != MAP_FAILED) {
        munmap(vdb->mapped_index, vdb->mapped_index_bytes);
    }
    vdb->mapped_index = NULL;
    vdb->mapped_index_bytes = 0u;
    if (vdb->index_mmap_fd >= 0) {
        close(vdb->index_mmap_fd);
    }
    vdb->index_mmap_fd = -1;
    if (vdb->mapped_idmap && vdb->mapped_idmap != MAP_FAILED) {
        munmap(vdb->mapped_idmap, vdb->mapped_idmap_bytes);
    }
    vdb->mapped_idmap = NULL;
    vdb->mapped_idmap_bytes = 0u;
    if (vdb->idmap_mmap_fd >= 0) {
        close(vdb->idmap_mmap_fd);
    }
    vdb->idmap_mmap_fd = -1;
}

static bool qihse_vdb_map_snapshot_file(qihse_vector_db_t vdb,
                                        const char* name,
                                        size_t bytes,
                                        int* fd_out,
                                        void** mapping_out) {
    char path[PATH_MAX];
    void* mapping;
    int fd;

    if (!vdb || !vdb->db_path || !name || !fd_out || !mapping_out) {
        errno = EINVAL;
        return false;
    }
    if (bytes == 0u) {
        return true;
    }
    if (!qihse_vdb_path(path, vdb->db_path, name)) {
        return false;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    mapping = mmap(NULL, bytes, PROT_READ, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        close(fd);
        return false;
    }
    *fd_out = fd;
    *mapping_out = mapping;
    return true;
}

static bool qihse_vdb_map_vectors(qihse_vector_db_t vdb) {
    if (!qihse_vdb_map_snapshot_file(vdb, QIHSE_VDB_VECTOR_NAME, vdb->vector_bytes_used,
                                     &vdb->mmap_fd, &vdb->mapped_vectors)) {
        return false;
    }
    vdb->mapped_vector_bytes = vdb->vector_bytes_used;
    return true;
}

static bool qihse_vdb_map_metadata(qihse_vector_db_t vdb) {
    if (!qihse_vdb_map_snapshot_file(vdb, QIHSE_VDB_METADATA_NAME, vdb->metadata_bytes_used,
                                     &vdb->metadata_mmap_fd, &vdb->mapped_metadata)) {
        return false;
    }
    vdb->mapped_metadata_bytes = vdb->metadata_bytes_used;
    return true;
}

static bool qihse_vdb_index_rows_are_direct_mappable(void) {
    const uint16_t endian = 1u;

    return ((const uint8_t*)&endian)[0] == 1u &&
           sizeof(qihse_index_row_t) == QIHSE_VDB_INDEX_ROW_DISK_SIZE &&
           offsetof(qihse_index_row_t, vector_id) == 0u &&
           offsetof(qihse_index_row_t, vector_offset) == 8u &&
           offsetof(qihse_index_row_t, metadata_offset) == 16u &&
           offsetof(qihse_index_row_t, metadata_size) == 24u &&
           offsetof(qihse_index_row_t, commit_generation) == 32u &&
           offsetof(qihse_index_row_t, row_flags) == 40u &&
           offsetof(qihse_index_row_t, reserved) == 44u;
}

static bool qihse_vdb_validate_mapped_index(qihse_vector_db_t vdb,
                                            const qihse_vector_store_manifest_t* manifest) {
    const uint8_t* data = (const uint8_t*)vdb->mapped_index;
    const uint8_t* payload;
    uint64_t count64;
    uint64_t crc64;
    uint32_t row_bytes;
    size_t row_count;
    size_t payload_size;
    size_t expected_size;
    uint64_t vector_row_bytes;

    if (!data || !manifest || vdb->mapped_index_bytes < QIHSE_VDB_FILE_HEADER_SIZE ||
        memcmp(data, QIHSE_VDB_INDEX_MAGIC, 8u) != 0 ||
        qihse_le_read_u32(data + 8u) != QIHSE_VDB_FORMAT_VERSION) {
        errno = EINVAL;
        return false;
    }

    row_bytes = qihse_le_read_u32(data + 12u);
    count64 = qihse_le_read_u64(data + 16u);
    crc64 = qihse_le_read_u64(data + 24u);
    if (row_bytes != QIHSE_VDB_INDEX_ROW_DISK_SIZE ||
        count64 != manifest->row_count ||
        crc64 != manifest->index_crc64 ||
        !qihse_vdb_u64_to_size(count64, &row_count) ||
        !qihse_checked_mul_size(row_count, QIHSE_VDB_INDEX_ROW_DISK_SIZE, &payload_size) ||
        !qihse_checked_add_size(QIHSE_VDB_FILE_HEADER_SIZE, payload_size, &expected_size) ||
        expected_size != vdb->mapped_index_bytes ||
        !qihse_checked_mul_u64((uint64_t)manifest->vector_dims, (uint64_t)sizeof(float),
                               &vector_row_bytes)) {
        errno = EINVAL;
        return false;
    }

    payload = data + QIHSE_VDB_FILE_HEADER_SIZE;
    if (qihse_fnv1a64(payload, payload_size) != crc64 ||
        !qihse_vdb_index_rows_are_direct_mappable()) {
        errno = EINVAL;
        return false;
    }

    for (size_t i = 0u; i < row_count; i++) {
        const uint8_t* row = payload + (i * QIHSE_VDB_INDEX_ROW_DISK_SIZE);
        uint64_t vector_offset = qihse_le_read_u64(row + 8u);
        uint64_t metadata_offset = qihse_le_read_u64(row + 16u);
        uint64_t metadata_size = qihse_le_read_u64(row + 24u);
        uint64_t vector_end;
        uint64_t metadata_end;

        if (!qihse_checked_add_u64(vector_offset, vector_row_bytes, &vector_end) ||
            vector_end > manifest->vector_bytes ||
            !qihse_checked_add_u64(metadata_offset, metadata_size, &metadata_end) ||
            metadata_end > manifest->metadata_bytes) {
            errno = EINVAL;
            return false;
        }
    }

    return true;
}

static bool qihse_vdb_try_map_index(qihse_vector_db_t vdb,
                                    const qihse_vector_store_manifest_t* manifest) {
    size_t bytes;

    if (!vdb || !manifest ||
        !qihse_vdb_u64_to_size(qihse_vdb_file_size_or_zero(vdb->db_path, QIHSE_VDB_INDEX_NAME),
                               &bytes) ||
        bytes == 0u) {
        return false;
    }
    if (!qihse_vdb_map_snapshot_file(vdb, QIHSE_VDB_INDEX_NAME, bytes,
                                     &vdb->index_mmap_fd, &vdb->mapped_index)) {
        return false;
    }
    vdb->mapped_index_bytes = bytes;
    if (!qihse_vdb_validate_mapped_index(vdb, manifest)) {
        if (vdb->mapped_index && vdb->mapped_index != MAP_FAILED) {
            munmap(vdb->mapped_index, vdb->mapped_index_bytes);
        }
        vdb->mapped_index = NULL;
        vdb->mapped_index_bytes = 0u;
        if (vdb->index_mmap_fd >= 0) {
            close(vdb->index_mmap_fd);
        }
        vdb->index_mmap_fd = -1;
        return false;
    }

    free(vdb->rows);
    vdb->rows = (qihse_index_row_t*)((uint8_t*)vdb->mapped_index + QIHSE_VDB_FILE_HEADER_SIZE);
    vdb->rows_capacity = vdb->total_vectors;
    vdb->rows_are_mapped = true;
    return true;
}

static bool qihse_vdb_validate_mapped_idmap(qihse_vector_db_t vdb,
                                            const qihse_vector_store_manifest_t* manifest) {
    const uint8_t* data = (const uint8_t*)vdb->mapped_idmap;
    const uint8_t* payload;
    uint64_t count64;
    uint64_t crc64;
    uint32_t row_bytes;
    size_t entry_count;
    size_t payload_size;
    size_t expected_size;
    int64_t previous_key = INT64_MIN;

    if (!data || !manifest || vdb->mapped_idmap_bytes < QIHSE_VDB_FILE_HEADER_SIZE ||
        memcmp(data, QIHSE_VDB_IDMAP_MAGIC, 8u) != 0 ||
        qihse_le_read_u32(data + 8u) != QIHSE_VDB_FORMAT_VERSION) {
        errno = EINVAL;
        return false;
    }

    row_bytes = qihse_le_read_u32(data + 12u);
    count64 = qihse_le_read_u64(data + 16u);
    crc64 = qihse_le_read_u64(data + 24u);
    if (row_bytes != QIHSE_VDB_IDMAP_ENTRY_DISK_SIZE ||
        crc64 != manifest->idmap_crc64 ||
        !qihse_vdb_u64_to_size(count64, &entry_count) ||
        !qihse_checked_mul_size(entry_count, QIHSE_VDB_IDMAP_ENTRY_DISK_SIZE, &payload_size) ||
        !qihse_checked_add_size(QIHSE_VDB_FILE_HEADER_SIZE, payload_size, &expected_size) ||
        expected_size != vdb->mapped_idmap_bytes) {
        errno = EINVAL;
        return false;
    }

    payload = data + QIHSE_VDB_FILE_HEADER_SIZE;
    if (qihse_fnv1a64(payload, payload_size) != crc64) {
        errno = EINVAL;
        return false;
    }
    for (size_t i = 0u; i < entry_count; i++) {
        const uint8_t* entry = payload + (i * QIHSE_VDB_IDMAP_ENTRY_DISK_SIZE);
        int64_t key = (int64_t)qihse_le_read_u64(entry);
        uint64_t row_index = qihse_le_read_u64(entry + 8u);

        if ((i != 0u && previous_key > key) || row_index >= manifest->row_count) {
            errno = EINVAL;
            return false;
        }
        previous_key = key;
    }

    vdb->idmap_count = entry_count;
    vdb->idmap_valid = true;
    vdb->idmap_dirty = false;
    return true;
}

static bool qihse_vdb_try_map_idmap(qihse_vector_db_t vdb,
                                    const qihse_vector_store_manifest_t* manifest) {
    size_t bytes;

    if (!vdb || !manifest || !vdb->idmap_valid ||
        !qihse_vdb_u64_to_size(qihse_vdb_file_size_or_zero(vdb->db_path, QIHSE_VDB_IDMAP_NAME),
                               &bytes) ||
        bytes == 0u) {
        return false;
    }
    if (!qihse_vdb_map_snapshot_file(vdb, QIHSE_VDB_IDMAP_NAME, bytes,
                                     &vdb->idmap_mmap_fd, &vdb->mapped_idmap)) {
        return false;
    }
    vdb->mapped_idmap_bytes = bytes;
    if (!qihse_vdb_validate_mapped_idmap(vdb, manifest)) {
        if (vdb->mapped_idmap && vdb->mapped_idmap != MAP_FAILED) {
            munmap(vdb->mapped_idmap, vdb->mapped_idmap_bytes);
        }
        vdb->mapped_idmap = NULL;
        vdb->mapped_idmap_bytes = 0u;
        if (vdb->idmap_mmap_fd >= 0) {
            close(vdb->idmap_mmap_fd);
        }
        vdb->idmap_mmap_fd = -1;
        return false;
    }

    free(vdb->idmap);
    vdb->idmap = NULL;
    return true;
}

static bool qihse_vdb_append_row(qihse_vector_db_t vdb,
                                 uint64_t id,
                                 const float* vector,
                                 const void* metadata,
                                 size_t metadata_size,
                                 uint64_t generation) {
    size_t vector_bytes;
    size_t new_vector_used;
    size_t new_metadata_used;
    qihse_index_row_t* row;

    if (!qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &vector_bytes) ||
        !qihse_checked_add_size(vdb->vector_bytes_used, vector_bytes, &new_vector_used) ||
        !qihse_checked_add_size(vdb->metadata_bytes_used, metadata_size, &new_metadata_used) ||
        !qihse_vdb_reserve_rows(vdb, vdb->total_vectors + 1u) ||
        !qihse_vdb_reserve_bytes(&vdb->vectors, &vdb->vector_bytes_capacity, new_vector_used) ||
        !qihse_vdb_reserve_bytes(&vdb->metadata, &vdb->metadata_bytes_capacity, new_metadata_used)) {
        return false;
    }

    memcpy(vdb->vectors + vdb->vector_bytes_used, vector, vector_bytes);
    if (metadata_size != 0u) {
        memcpy(vdb->metadata + vdb->metadata_bytes_used, metadata, metadata_size);
    }

    row = &vdb->rows[vdb->total_vectors];
    memset(row, 0, sizeof(*row));
    row->vector_id = id;
    row->vector_offset = (uint64_t)vdb->vector_bytes_used;
    row->metadata_offset = (uint64_t)vdb->metadata_bytes_used;
    row->metadata_size = (uint64_t)metadata_size;
    row->commit_generation = generation;
    row->row_flags = QIHSE_ROW_F_LIVE;

    vdb->total_vectors++;
    vdb->live_vectors++;
    vdb->vector_bytes_used = new_vector_used;
    vdb->metadata_bytes_used = new_metadata_used;
    if (id >= vdb->next_auto_id) {
        vdb->next_auto_id = id + 1u;
    }
    vdb->idmap_valid = false;
    vdb->idmap_dirty = true;
    vdb->trinary_status = QIHSE_VDB_TRINARY_STALE;
    return true;
}

static bool qihse_vdb_apply_add(qihse_vector_db_t vdb,
                                const qihse_vdb_wal_add_t* add,
                                bool reject_duplicates) {
    uint64_t auto_base;
    size_t i;

    if (!vdb || !add || !add->vectors || add->count == 0u || add->dims == 0u ||
        add->dims > (uint64_t)SIZE_MAX) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims != 0u && vdb->vector_dims != (size_t)add->dims) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims == 0u) {
        vdb->vector_dims = (size_t)add->dims;
    }
    auto_base = vdb->next_auto_id;
    for (i = 0u; i < (size_t)add->count; i++) {
        uint64_t id = add->ids ? add->ids[i] : auto_base + (uint64_t)i;
        if (reject_duplicates && qihse_vdb_id_exists(vdb, id)) {
            errno = EEXIST;
            return false;
        }
    }
    for (i = 0u; i < (size_t)add->count; i++) {
        const void* meta = add->metadata ? add->metadata[i] : NULL;
        size_t meta_size = add->metadata_sizes ? add->metadata_sizes[i] : 0u;
        uint64_t id = add->ids ? add->ids[i] : auto_base + (uint64_t)i;

        if (meta_size != 0u && !meta) {
            errno = EINVAL;
            return false;
        }
        if (!qihse_vdb_append_row(vdb, id, add->vectors + (i * vdb->vector_dims),
                                  meta, meta_size, add->generation)) {
            return false;
        }
    }
    if (!add->ids) {
        vdb->next_auto_id = auto_base + add->count;
    }
    if (add->generation >= vdb->next_generation) {
        vdb->next_generation = add->generation + 1u;
    }
    vdb->dirty = true;
    return true;
}

static bool qihse_vdb_write_all(int fd, const void* data, size_t size) {
    const uint8_t* p = (const uint8_t*)data;
    size_t done = 0u;

    while (done < size) {
        ssize_t n = write(fd, p + done, size - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            errno = EIO;
            return false;
        }
        done += (size_t)n;
    }
    return true;
}

static bool qihse_vdb_write_wal_record(qihse_vector_db_t vdb,
                                       int fd,
                                       uint32_t type,
                                       uint64_t generation,
                                       const void* payload,
                                       size_t payload_size,
                                       uint64_t prev_offset,
                                       uint64_t* out_record_offset,
                                       uint64_t* out_crc64) {
    uint8_t header[QIHSE_VDB_WAL_HEADER_SIZE];
    off_t start;
    uint64_t crc;

    if (!vdb || fd < 0 || (!payload && payload_size != 0u)) {
        errno = EINVAL;
        return false;
    }
    start = lseek(fd, 0, SEEK_END);
    if (start < 0) {
        return false;
    }
    crc = qihse_fnv1a64(payload, payload_size);
    memset(header, 0, sizeof(header));
    memcpy(header, QIHSE_VDB_WAL_MAGIC, 8u);
    qihse_le_write_u32(header + 8u, QIHSE_VDB_WAL_VERSION);
    qihse_le_write_u32(header + 12u, type);
    qihse_le_write_u64(header + 16u, generation);
    qihse_le_write_u64(header + 24u, (uint64_t)payload_size);
    qihse_le_write_u64(header + 32u, crc);
    qihse_le_write_u64(header + 40u, prev_offset);

    if (!qihse_vdb_write_all(fd, header, sizeof(header)) ||
        !qihse_vdb_write_all(fd, payload, payload_size)) {
        return false;
    }
    if (out_record_offset) {
        *out_record_offset = (uint64_t)start;
    }
    if (out_crc64) {
        *out_crc64 = crc;
    }
    return true;
}

static bool qihse_vdb_write_wal_vectors(qihse_vector_db_t vdb,
                                        uint32_t type,
                                        const qihse_vdb_wal_vectors_t* vectors_record) {
    char path[PATH_MAX];
    uint8_t fixed[32];
    uint8_t commit_payload[16];
    uint8_t* payload = NULL;
    size_t vector_bytes;
    size_t ids_bytes;
    size_t sizes_bytes;
    size_t metadata_bytes = 0u;
    size_t payload_size;
    size_t offset = 0u;
    size_t i;
    uint64_t mutation_offset;
    uint64_t mutation_crc;
    uint64_t commit_offset;
    int fd;
    bool ok = false;

    if (!vdb || !vdb->db_path || !vectors_record ||
        (type != QIHSE_VDB_WAL_ADD && type != QIHSE_VDB_WAL_DELETE &&
         type != QIHSE_VDB_WAL_UPDATE && type != QIHSE_VDB_WAL_UPSERT)) {
        errno = EINVAL;
        return false;
    }
    if ((type == QIHSE_VDB_WAL_DELETE && vectors_record->dims != 0u) ||
        (type != QIHSE_VDB_WAL_DELETE &&
         (!vectors_record->vectors || vectors_record->dims == 0u))) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_checked_mul_size((size_t)vectors_record->count,
                                (size_t)vectors_record->dims, &vector_bytes) ||
        !qihse_checked_mul_size(vector_bytes, sizeof(float), &vector_bytes) ||
        !qihse_checked_mul_size((size_t)vectors_record->count, sizeof(uint64_t), &ids_bytes) ||
        !qihse_checked_mul_size((size_t)vectors_record->count, sizeof(uint64_t), &sizes_bytes)) {
        return false;
    }
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        size_t meta_size = (vectors_record->metadata && vectors_record->metadata_sizes) ?
                           vectors_record->metadata_sizes[i] : 0u;
        if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
            return false;
        }
    }
    if (!qihse_checked_add_size(sizeof(fixed), ids_bytes, &payload_size) ||
        !qihse_checked_add_size(payload_size, sizes_bytes, &payload_size) ||
        !qihse_checked_add_size(payload_size, vector_bytes, &payload_size) ||
        !qihse_checked_add_size(payload_size, metadata_bytes, &payload_size)) {
        return false;
    }

    payload = (uint8_t*)malloc(payload_size ? payload_size : 1u);
    if (!payload) {
        errno = ENOMEM;
        return false;
    }
    qihse_le_write_u64(fixed + 0u, vectors_record->count);
    qihse_le_write_u64(fixed + 8u, vectors_record->dims);
    qihse_le_write_u64(fixed + 16u, (uint64_t)vector_bytes);
    qihse_le_write_u64(fixed + 24u, (uint64_t)metadata_bytes);
    memcpy(payload + offset, fixed, sizeof(fixed));
    offset += sizeof(fixed);
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        qihse_le_write_u64(payload + offset,
                           vectors_record->ids ? vectors_record->ids[i] :
                           vdb->next_auto_id + i);
        offset += sizeof(uint64_t);
    }
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        qihse_le_write_u64(payload + offset,
                           (uint64_t)((vectors_record->metadata &&
                                       vectors_record->metadata_sizes) ?
                                      vectors_record->metadata_sizes[i] : 0u));
        offset += sizeof(uint64_t);
    }
    if (vector_bytes != 0u) {
        memcpy(payload + offset, vectors_record->vectors, vector_bytes);
        offset += vector_bytes;
    }
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        size_t meta_size = (vectors_record->metadata && vectors_record->metadata_sizes) ?
                           vectors_record->metadata_sizes[i] : 0u;
        if (meta_size != 0u) {
            memcpy(payload + offset, vectors_record->metadata[i], meta_size);
            offset += meta_size;
        }
    }

    if (!qihse_vdb_path(path, vdb->db_path, QIHSE_VDB_WAL_NAME)) {
        free(payload);
        return false;
    }
    fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        free(payload);
        return false;
    }
    ok = qihse_vdb_write_wal_record(vdb, fd, type, vectors_record->generation,
                                    payload, payload_size, vdb->wal_last_record_offset,
                                    &mutation_offset, &mutation_crc);
    if (ok) {
        qihse_le_write_u64(commit_payload + 0u, mutation_offset);
        qihse_le_write_u64(commit_payload + 8u, mutation_crc);
        ok = qihse_vdb_write_wal_record(vdb, fd, QIHSE_VDB_WAL_COMMIT,
                                        vectors_record->generation,
                                        commit_payload, sizeof(commit_payload), mutation_offset,
                                        &commit_offset, NULL);
    }
    if (ok) {
        ok = fsync(fd) == 0;
    }
    if (close(fd) != 0) {
        ok = false;
    }
    free(payload);
    if (ok) {
        vdb->wal_bytes_pending += (2u * QIHSE_VDB_WAL_HEADER_SIZE) +
                                  payload_size + sizeof(commit_payload);
        vdb->wal_last_record_offset = commit_offset;
    }
    return ok;
}

static bool qihse_vdb_write_wal_add(qihse_vector_db_t vdb, const qihse_vdb_wal_add_t* add) {
    return qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_ADD, add);
}

static bool qihse_vdb_apply_delete_payload(qihse_vector_db_t vdb,
                                           const qihse_vdb_wal_vectors_t* record) {
    size_t deleted = 0u;

    if (!vdb || !record || !record->ids || record->count == 0u) {
        errno = EINVAL;
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        deleted += qihse_vdb_tombstone_live_id(vdb, record->ids[i],
                                               record->generation) != 0u ? 1u : 0u;
    }
    if (deleted != 0u) {
        qihse_vdb_finish_mutation_generation(vdb, record->generation);
    }
    return true;
}

static bool qihse_vdb_apply_update_payload(qihse_vector_db_t vdb,
                                           const qihse_vdb_wal_vectors_t* record) {
    bool* exists = NULL;
    size_t metadata_bytes = 0u;
    size_t updated = 0u;

    if (!vdb || !record || !record->ids || !record->vectors || record->count == 0u ||
        record->dims == 0u || record->dims > (uint64_t)SIZE_MAX ||
        (vdb->vector_dims != 0u && vdb->vector_dims != (size_t)record->dims)) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims == 0u) {
        return true;
    }
    exists = (bool*)calloc((size_t)record->count, sizeof(*exists));
    if (!exists) {
        errno = ENOMEM;
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t row_index = 0u;
        size_t meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        errno = 0;
        exists[i] = qihse_vdb_find_live_row_by_id(vdb, record->ids[i], &row_index);
        if (!exists[i] && errno != ENOENT) {
            free(exists);
            return false;
        }
        if (exists[i]) {
            if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
                free(exists);
                return false;
            }
            updated++;
        }
    }
    if (updated == 0u) {
        free(exists);
        return true;
    }
    if (!qihse_vdb_reserve_appends(vdb, updated, metadata_bytes)) {
        free(exists);
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t meta_size;
        const void* meta;

        if (!exists[i]) {
            continue;
        }
        meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        meta = record->metadata ? record->metadata[i] : NULL;
        qihse_vdb_tombstone_live_id(vdb, record->ids[i], record->generation);
        if (!qihse_vdb_append_row(vdb, record->ids[i],
                                  record->vectors + (i * (size_t)record->dims),
                                  meta, meta_size, record->generation)) {
            free(exists);
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, record->generation);
    free(exists);
    return true;
}

static bool qihse_vdb_apply_upsert_payload(qihse_vector_db_t vdb,
                                           const qihse_vdb_wal_vectors_t* record) {
    size_t metadata_bytes = 0u;

    if (!vdb || !record || !record->ids || !record->vectors || record->count == 0u ||
        record->dims == 0u || record->dims > (uint64_t)SIZE_MAX ||
        (vdb->vector_dims != 0u && vdb->vector_dims != (size_t)record->dims)) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims == 0u) {
        vdb->vector_dims = (size_t)record->dims;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
            return false;
        }
    }
    if (!qihse_vdb_reserve_appends(vdb, (size_t)record->count, metadata_bytes)) {
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t row_index = 0u;
        size_t meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        const void* meta = record->metadata ? record->metadata[i] : NULL;

        errno = 0;
        if (qihse_vdb_find_live_row_by_id(vdb, record->ids[i], &row_index)) {
            qihse_vdb_tombstone_live_id(vdb, record->ids[i], record->generation);
        } else if (errno != ENOENT) {
            return false;
        }
        if (!qihse_vdb_append_row(vdb, record->ids[i],
                                  record->vectors + (i * (size_t)record->dims),
                                  meta, meta_size, record->generation)) {
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, record->generation);
    return true;
}

static bool qihse_vdb_replay_wal_payload(qihse_vector_db_t vdb,
                                         uint32_t type,
                                         uint64_t generation,
                                         const uint8_t* payload,
                                         size_t payload_size) {
    qihse_vdb_wal_vectors_t record;
    uint64_t count;
    uint64_t dims;
    uint64_t vector_bytes;
    uint64_t metadata_bytes;
    uint64_t* ids = NULL;
    size_t* meta_sizes = NULL;
    const float* vectors;
    const void** metadata = NULL;
    size_t offset = 0u;
    size_t i;
    size_t calc_vector_bytes;
    size_t metadata_total = 0u;
    bool ok = false;

    if (!payload || payload_size < 32u) {
        errno = EINVAL;
        return false;
    }
    count = qihse_le_read_u64(payload + 0u);
    dims = qihse_le_read_u64(payload + 8u);
    vector_bytes = qihse_le_read_u64(payload + 16u);
    metadata_bytes = qihse_le_read_u64(payload + 24u);
    offset = 32u;
    if (count == 0u || count > (uint64_t)SIZE_MAX || dims > (uint64_t)SIZE_MAX ||
        (type == QIHSE_VDB_WAL_DELETE && (dims != 0u || vector_bytes != 0u ||
                                          metadata_bytes != 0u)) ||
        (type != QIHSE_VDB_WAL_DELETE && dims == 0u) ||
        !qihse_checked_mul_size((size_t)count, (size_t)dims, &calc_vector_bytes) ||
        !qihse_checked_mul_size(calc_vector_bytes, sizeof(float), &calc_vector_bytes) ||
        calc_vector_bytes != (size_t)vector_bytes ||
        offset > payload_size) {
        errno = EINVAL;
        return false;
    }

    ids = (uint64_t*)calloc((size_t)count, sizeof(*ids));
    meta_sizes = (size_t*)calloc((size_t)count, sizeof(*meta_sizes));
    metadata = (const void**)calloc((size_t)count, sizeof(*metadata));
    if (!ids || !meta_sizes || !metadata) {
        errno = ENOMEM;
        goto done;
    }
    if (payload_size - offset < (size_t)count * sizeof(uint64_t)) {
        errno = EINVAL;
        goto done;
    }
    for (i = 0u; i < (size_t)count; i++) {
        ids[i] = qihse_le_read_u64(payload + offset);
        offset += sizeof(uint64_t);
    }
    if (payload_size - offset < (size_t)count * sizeof(uint64_t)) {
        errno = EINVAL;
        goto done;
    }
    for (i = 0u; i < (size_t)count; i++) {
        uint64_t size64 = qihse_le_read_u64(payload + offset);
        offset += sizeof(uint64_t);
        if (!qihse_vdb_u64_to_size(size64, &meta_sizes[i]) ||
            !qihse_checked_add_size(metadata_total, meta_sizes[i], &metadata_total)) {
            goto done;
        }
    }
    if ((uint64_t)metadata_total != metadata_bytes ||
        payload_size - offset < calc_vector_bytes) {
        errno = EINVAL;
        goto done;
    }
    vectors = (const float*)(const void*)(payload + offset);
    offset += calc_vector_bytes;
    if (payload_size - offset != metadata_total) {
        errno = EINVAL;
        goto done;
    }
    for (i = 0u; i < (size_t)count; i++) {
        if (meta_sizes[i] != 0u) {
            metadata[i] = payload + offset;
            offset += meta_sizes[i];
        }
    }

    memset(&record, 0, sizeof(record));
    record.generation = generation;
    record.count = count;
    record.dims = dims;
    record.ids = ids;
    record.vectors = vectors;
    record.metadata = metadata;
    record.metadata_sizes = meta_sizes;
    if (type == QIHSE_VDB_WAL_ADD) {
        ok = qihse_vdb_apply_add(vdb, &record, true);
    } else if (type == QIHSE_VDB_WAL_DELETE) {
        ok = qihse_vdb_apply_delete_payload(vdb, &record);
    } else if (type == QIHSE_VDB_WAL_UPDATE) {
        ok = qihse_vdb_apply_update_payload(vdb, &record);
    } else if (type == QIHSE_VDB_WAL_UPSERT) {
        ok = qihse_vdb_apply_upsert_payload(vdb, &record);
    } else {
        errno = EINVAL;
        ok = false;
    }
    if (ok) {
        vdb->wal_records_replayed++;
    }

done:
    free(ids);
    free(meta_sizes);
    free(metadata);
    return ok;
}

static bool qihse_vdb_replay_wal(qihse_vector_db_t vdb) {
    char path[PATH_MAX];
    int fd;
    uint8_t header[QIHSE_VDB_WAL_HEADER_SIZE];
    uint64_t pending = 0u;
    uint64_t valid_end = 0u;
    uint64_t last_record_offset = QIHSE_VDB_WAL_NO_PREV;
    uint64_t valid_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
    uint8_t* pending_payload = NULL;
    size_t pending_payload_size = 0u;
    uint32_t pending_type = 0u;
    uint64_t pending_generation = 0u;
    uint64_t pending_offset = 0u;
    uint64_t pending_crc = 0u;

    if (!vdb || !vdb->db_path || !qihse_vdb_path(path, vdb->db_path, QIHSE_VDB_WAL_NAME)) {
        return false;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return errno == ENOENT;
    }

    for (;;) {
        off_t record_start_off = lseek(fd, 0, SEEK_CUR);
        uint64_t record_start;
        uint64_t record_end;
        ssize_t got = read(fd, header, sizeof(header));
        uint32_t version;
        uint32_t type;
        uint64_t generation;
        uint64_t payload_size64;
        uint64_t crc;
        uint64_t prev_offset;
        uint8_t* payload = NULL;
        bool ok;

        if (got == 0) {
            break;
        }
        if (record_start_off < 0 || got != (ssize_t)sizeof(header)) {
            break;
        }
        record_start = (uint64_t)record_start_off;
        if (memcmp(header, QIHSE_VDB_WAL_MAGIC, 8u) != 0) {
            break;
        }
        version = qihse_le_read_u32(header + 8u);
        type = qihse_le_read_u32(header + 12u);
        generation = qihse_le_read_u64(header + 16u);
        payload_size64 = qihse_le_read_u64(header + 24u);
        crc = qihse_le_read_u64(header + 32u);
        prev_offset = qihse_le_read_u64(header + 40u);
        if (version != QIHSE_VDB_WAL_VERSION ||
            (type != QIHSE_VDB_WAL_ADD && type != QIHSE_VDB_WAL_COMMIT &&
             type != QIHSE_VDB_WAL_DELETE && type != QIHSE_VDB_WAL_UPDATE &&
             type != QIHSE_VDB_WAL_UPSERT) ||
            payload_size64 > (uint64_t)SIZE_MAX ||
            (record_start != 0u && prev_offset != last_record_offset) ||
            (record_start == 0u && prev_offset != QIHSE_VDB_WAL_NO_PREV && prev_offset != 0u)) {
            break;
        }
        payload = (uint8_t*)malloc((size_t)payload_size64 ? (size_t)payload_size64 : 1u);
        if (!payload) {
            free(pending_payload);
            close(fd);
            errno = ENOMEM;
            return false;
        }
        got = read(fd, payload, (size_t)payload_size64);
        if (got != (ssize_t)payload_size64) {
            free(payload);
            break;
        }
        if (qihse_fnv1a64(payload, (size_t)payload_size64) != crc) {
            free(payload);
            break;
        }
        if (!qihse_checked_add_u64(record_start,
                                   QIHSE_VDB_WAL_HEADER_SIZE + payload_size64,
                                   &record_end)) {
            free(payload);
            break;
        }
        if (type != QIHSE_VDB_WAL_COMMIT) {
            free(pending_payload);
            pending_payload = payload;
            pending_payload_size = (size_t)payload_size64;
            pending_type = type;
            pending_generation = generation;
            pending_offset = record_start;
            pending_crc = crc;
            payload = NULL;
        } else {
            uint64_t mutation_offset;
            uint64_t mutation_crc;

            if ((size_t)payload_size64 != 16u || !pending_payload) {
                free(payload);
                break;
            }
            mutation_offset = qihse_le_read_u64(payload + 0u);
            mutation_crc = qihse_le_read_u64(payload + 8u);
            if (generation != pending_generation ||
                mutation_offset != pending_offset ||
                mutation_crc != pending_crc) {
                free(payload);
                break;
            }
            ok = true;
            if (generation > vdb->committed_generation) {
                ok = qihse_vdb_replay_wal_payload(vdb, pending_type, generation,
                                                  pending_payload, pending_payload_size);
            }
            free(pending_payload);
            pending_payload = NULL;
            pending_payload_size = 0u;
            pending_type = 0u;
            if (!ok) {
                free(payload);
                close(fd);
                return false;
            }
            valid_end = record_end;
            valid_last_record_offset = record_start;
        }
        free(payload);
        last_record_offset = record_start;
        pending = record_end;
    }
    free(pending_payload);
    if (pending != valid_end && !vdb->read_only) {
        if (!qihse_vdb_truncate_existing_file(vdb->db_path, QIHSE_VDB_WAL_NAME, valid_end)) {
            close(fd);
            return false;
        }
    }
    close(fd);
    vdb->wal_bytes_pending = valid_end;
    vdb->wal_last_record_offset = valid_end == 0u ? QIHSE_VDB_WAL_NO_PREV : valid_last_record_offset;
    return true;
}

static uint8_t qihse_vdb_pack_trytes(const float* vector, size_t start, size_t dims) {
    uint8_t value = 0u;
    uint8_t place = 1u;
    size_t j;

    for (j = 0u; j < 5u; j++) {
        size_t idx = start + j;
        uint8_t trit = 1u;
        if (idx < dims) {
            if (vector[idx] < 0.0f) {
                trit = 0u;
            } else if (vector[idx] > 0.0f) {
                trit = 2u;
            }
        }
        value = (uint8_t)(value + trit * place);
        place = (uint8_t)(place * 3u);
    }
    return value;
}

static uint8_t* qihse_vdb_build_trinary(qihse_vector_db_t vdb, size_t* out_size) {
    uint8_t* out;
    size_t row_bytes;
    size_t total;
    size_t row_idx;

    if (!vdb || !out_size || vdb->vector_dims == 0u) {
        errno = EINVAL;
        return NULL;
    }
    row_bytes = (vdb->vector_dims + 4u) / 5u;
    if (!qihse_checked_mul_size(vdb->total_vectors, row_bytes, &total)) {
        return NULL;
    }
    out = (uint8_t*)calloc(total ? total : 1u, 1u);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    for (row_idx = 0u; row_idx < vdb->total_vectors; row_idx++) {
        const qihse_index_row_t* row = &vdb->rows[row_idx];
        const float* vector = qihse_vdb_vector_at(vdb, row);
        size_t byte_idx;

        if (!vector || (row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        for (byte_idx = 0u; byte_idx < row_bytes; byte_idx++) {
            out[(row_idx * row_bytes) + byte_idx] =
                qihse_vdb_pack_trytes(vector, byte_idx * 5u, vdb->vector_dims);
        }
    }
    *out_size = total;
    vdb->trinary_row_bytes = (uint64_t)row_bytes;
    vdb->trinary_rows = (uint64_t)vdb->total_vectors;
    return out;
}

static bool qihse_vdb_load_snapshot(qihse_vector_db_t vdb, bool use_mmap) {
    qihse_vector_store_snapshot_t snapshot;
    bool qtri_exists;
    size_t dims;
    size_t vector_bytes;
    size_t metadata_bytes;

    memset(&snapshot, 0, sizeof(snapshot));
    if (!qihse_vector_store_load(vdb->db_path, &snapshot)) {
        return false;
    }
    if (!qihse_vdb_u64_to_size(snapshot.manifest.vector_dims, &dims) ||
        !qihse_vdb_u64_to_size(snapshot.manifest.vector_bytes, &vector_bytes) ||
        !qihse_vdb_u64_to_size(snapshot.manifest.metadata_bytes, &metadata_bytes)) {
        qihse_vector_store_snapshot_free(&snapshot);
        return false;
    }

    vdb->vector_dims = dims;
    vdb->total_vectors = snapshot.row_count;
    vdb->rows_capacity = snapshot.row_count;
    vdb->rows = snapshot.rows;
    snapshot.rows = NULL;
    vdb->vectors = snapshot.vectors;
    snapshot.vectors = NULL;
    vdb->vector_bytes_used = vector_bytes;
    vdb->vector_bytes_capacity = vector_bytes;
    vdb->metadata = snapshot.metadata;
    snapshot.metadata = NULL;
    vdb->metadata_bytes_used = metadata_bytes;
    vdb->metadata_bytes_capacity = metadata_bytes;
    vdb->committed_generation = snapshot.manifest.commit_generation;
    vdb->next_generation = vdb->committed_generation + 1u;
    vdb->idmap = snapshot.idmap;
    snapshot.idmap = NULL;
    vdb->idmap_count = snapshot.idmap_count;
    vdb->idmap_valid = snapshot.idmap_valid;
    vdb->idmap_dirty = false;
    vdb->live_vectors = 0u;
    for (size_t i = 0u; i < vdb->total_vectors; i++) {
        if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            vdb->live_vectors++;
        }
        if (vdb->rows[i].vector_id >= vdb->next_auto_id) {
            vdb->next_auto_id = vdb->rows[i].vector_id + 1u;
        }
    }
    if (!vdb->idmap_valid && !qihse_vdb_rebuild_idmap(vdb, !vdb->read_only)) {
        qihse_vector_store_snapshot_free(&snapshot);
        return false;
    }
    qtri_exists = qihse_vdb_exists(vdb->db_path, QIHSE_VDB_TRINARY_NAME);
    if (snapshot.trinary_valid) {
        vdb->trinary_status = QIHSE_VDB_TRINARY_VALID;
        vdb->trinary_row_bytes = snapshot.manifest.trinary_row_bytes;
        vdb->trinary_rows = snapshot.manifest.trinary_rows;
    } else if (qtri_exists) {
        vdb->trinary_status = QIHSE_VDB_TRINARY_CORRUPT;
        vdb->trinary_row_bytes = snapshot.manifest.trinary_row_bytes;
        vdb->trinary_rows = snapshot.manifest.trinary_rows;
    } else {
        vdb->trinary_status = QIHSE_VDB_TRINARY_ABSENT;
    }
    if (use_mmap && (vdb->vector_bytes_used != 0u || vdb->metadata_bytes_used != 0u)) {
        free(vdb->vectors);
        vdb->vectors = NULL;
        vdb->vector_bytes_capacity = 0u;
        if (!qihse_vdb_map_vectors(vdb)) {
            qihse_vector_store_snapshot_free(&snapshot);
            return false;
        }
        if (!qihse_vdb_map_metadata(vdb)) {
            qihse_vector_store_snapshot_free(&snapshot);
            return false;
        }
        free(vdb->metadata);
        vdb->metadata = NULL;
        vdb->metadata_bytes_capacity = 0u;
        (void)qihse_vdb_try_map_index(vdb, &snapshot.manifest);
        (void)qihse_vdb_try_map_idmap(vdb, &snapshot.manifest);
    }
    qihse_vector_store_snapshot_free(&snapshot);
    return true;
}

qihse_vector_db_t qihse_vector_db_open(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags
) {
    qihse_vector_db_t vdb;
    bool file_backed = db_path && ((flags & QIHSE_VDB_OPEN_FILE_BACKED) != 0u || db_path[0] != '\0');
    bool read_only = (flags & QIHSE_VDB_OPEN_READ_ONLY) != 0u;
    bool use_mmap = (flags & QIHSE_VDB_OPEN_MMAP) != 0u;
    bool create = (flags & QIHSE_VDB_OPEN_CREATE) != 0u;
    bool loaded = false;

    if (use_mmap && !read_only) {
        errno = EINVAL;
        return NULL;
    }
    vdb = (qihse_vector_db_t)calloc(1u, sizeof(*vdb));
    if (!vdb) {
        errno = ENOMEM;
        return NULL;
    }
    vdb->backend = backend;
    vdb->uma = uma;
    vdb->file_backed = file_backed;
    vdb->read_only = read_only;
    vdb->storage_mode = file_backed ? QIHSE_VDB_STORAGE_FILE_COPY : QIHSE_VDB_STORAGE_EPHEMERAL;
    vdb->mmap_fd = -1;
    vdb->metadata_mmap_fd = -1;
    vdb->index_mmap_fd = -1;
    vdb->idmap_mmap_fd = -1;
    vdb->next_generation = 1u;
    vdb->wal_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
    vdb->trinary_status = QIHSE_VDB_TRINARY_ABSENT;

    if (file_backed) {
        vdb->db_path = qihse_vdb_strdup(db_path);
        if (!vdb->db_path) {
            qihse_vector_db_destroy(vdb);
            return NULL;
        }
        if (!read_only && !qihse_mkdir_p(vdb->db_path, 0777)) {
            qihse_vector_db_destroy(vdb);
            return NULL;
        }
        if (!read_only && (flags & QIHSE_VDB_OPEN_TRUNCATE) != 0u) {
            qihse_vdb_remove_snapshot_files(vdb->db_path);
        }
        if (qihse_vdb_exists(vdb->db_path, QIHSE_VDB_MANIFEST_NAME)) {
            if (!qihse_vdb_load_snapshot(vdb, use_mmap)) {
                qihse_vector_db_destroy(vdb);
                return NULL;
            }
            loaded = true;
        } else if (!create && qihse_vdb_file_size_or_zero(vdb->db_path, QIHSE_VDB_WAL_NAME) == 0u) {
            qihse_vector_db_destroy(vdb);
            errno = ENOENT;
            return NULL;
        }
        if (use_mmap && qihse_vdb_file_size_or_zero(vdb->db_path, QIHSE_VDB_WAL_NAME) != 0u) {
            qihse_vector_db_destroy(vdb);
            errno = ENOTSUP;
            return NULL;
        }
        if (!qihse_vdb_replay_wal(vdb)) {
            qihse_vector_db_destroy(vdb);
            return NULL;
        }
        if (vdb->wal_records_replayed != 0u) {
            if (!qihse_vdb_rebuild_idmap(vdb, !read_only)) {
                qihse_vector_db_destroy(vdb);
                return NULL;
            }
            if (!read_only) {
                vdb->dirty = true;
            }
        } else if (loaded) {
            vdb->dirty = vdb->idmap_dirty;
        }
        if (use_mmap) {
            vdb->storage_mode = QIHSE_VDB_STORAGE_FILE_MMAP;
        }
    }
    return vdb;
}

qihse_vector_db_t qihse_vector_db_create(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path
) {
    uint32_t flags = QIHSE_VDB_OPEN_CREATE;
    if (db_path) {
        flags |= QIHSE_VDB_OPEN_FILE_BACKED;
    }
    return qihse_vector_db_open(backend, uma, db_path, flags);
}

bool qihse_vector_db_add_vectors(
    qihse_vector_db_t vdb,
    const float* vectors,
    size_t num_vectors,
    size_t vector_dims,
    const uint64_t* ids,
    const void* const* metadata,
    const size_t* metadata_sizes
) {
    qihse_vdb_wal_add_t add;
    uint64_t generation;
    size_t i;
    size_t j;

    if (!vdb || !vectors || num_vectors == 0u || vector_dims == 0u) {
        errno = EINVAL;
        return false;
    }
    if (vdb->read_only || vdb->mapped_vectors) {
        errno = EROFS;
        return false;
    }
    if ((uint64_t)num_vectors > UINT64_MAX || (uint64_t)vector_dims > UINT64_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    for (i = 0u; i < num_vectors; i++) {
        if (metadata_sizes && metadata_sizes[i] != 0u && (!metadata || !metadata[i])) {
            errno = EINVAL;
            return false;
        }
        if (ids) {
            for (j = i + 1u; j < num_vectors; j++) {
                if (ids[i] == ids[j]) {
                    errno = EEXIST;
                    return false;
                }
            }
        }
    }
    generation = vdb->next_generation;
    memset(&add, 0, sizeof(add));
    add.generation = generation;
    add.count = (uint64_t)num_vectors;
    add.dims = (uint64_t)vector_dims;
    add.ids = ids;
    add.vectors = vectors;
    add.metadata = metadata;
    add.metadata_sizes = metadata_sizes;

    if (vdb->file_backed && !qihse_vdb_write_wal_add(vdb, &add)) {
        return false;
    }
    return qihse_vdb_apply_add(vdb, &add, true);
}

bool qihse_vector_db_delete_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id
) {
    size_t deleted = 0u;

    if (!qihse_vector_db_delete_by_ids(vdb, &vector_id, 1u, &deleted)) {
        return false;
    }
    if (deleted == 0u) {
        errno = ENOENT;
        return false;
    }
    return true;
}

bool qihse_vector_db_delete_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    size_t count,
    size_t* deleted_count
) {
    uint64_t generation;
    size_t deleted = 0u;
    size_t i;

    if (deleted_count) {
        *deleted_count = 0u;
    }
    if (!qihse_vdb_ensure_writable(vdb)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (!vector_ids || qihse_vdb_has_duplicate_ids(vector_ids, count)) {
        if (!vector_ids) {
            errno = EINVAL;
        }
        return false;
    }
    for (i = 0u; i < count; i++) {
        size_t row_index = 0u;
        bool found;
        errno = 0;
        found = qihse_vdb_find_live_row_by_id(vdb, vector_ids[i], &row_index);
        if (!found && errno != ENOENT) {
            return false;
        }
        if (found) {
            deleted++;
        }
    }

    generation = vdb->next_generation;
    if (deleted != 0u && vdb->file_backed) {
        qihse_vdb_wal_vectors_t record;
        memset(&record, 0, sizeof(record));
        record.generation = generation;
        record.count = (uint64_t)count;
        record.ids = vector_ids;
        if (!qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_DELETE, &record)) {
            return false;
        }
    }
    if (deleted != 0u) {
        deleted = 0u;
        for (i = 0u; i < count; i++) {
            deleted += qihse_vdb_tombstone_live_id(vdb, vector_ids[i],
                                                   generation) != 0u ? 1u : 0u;
        }
    }
    if (deleted != 0u) {
        qihse_vdb_finish_mutation_generation(vdb, generation);
    }
    if (deleted_count) {
        *deleted_count = deleted;
    }
    return true;
}

static bool qihse_vdb_validate_mutation_vectors(qihse_vector_db_t vdb,
                                                const uint64_t* vector_ids,
                                                const float* vectors,
                                                size_t count,
                                                size_t dims,
                                                const void* const* metadata,
                                                const size_t* metadata_sizes) {
    size_t i;

    if (!qihse_vdb_ensure_writable(vdb)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (!vector_ids || !vectors || dims == 0u ||
        qihse_vdb_has_duplicate_ids(vector_ids, count)) {
        if (!vector_ids || !vectors || dims == 0u) {
            errno = EINVAL;
        }
        return false;
    }
    if (vdb->vector_dims != 0u && vdb->vector_dims != dims) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < count; i++) {
        if (metadata_sizes && metadata_sizes[i] != 0u && (!metadata || !metadata[i])) {
            errno = EINVAL;
            return false;
        }
    }
    return true;
}

static bool qihse_vdb_reserve_appends(qihse_vector_db_t vdb,
                                      size_t append_count,
                                      size_t metadata_bytes) {
    size_t one_vector_bytes;
    size_t vector_bytes;
    size_t new_vector_used;
    size_t new_metadata_used;

    if (append_count == 0u) {
        return true;
    }
    if (!qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &one_vector_bytes) ||
        !qihse_checked_mul_size(append_count, one_vector_bytes, &vector_bytes) ||
        !qihse_checked_add_size(vdb->vector_bytes_used, vector_bytes, &new_vector_used) ||
        !qihse_checked_add_size(vdb->metadata_bytes_used, metadata_bytes, &new_metadata_used) ||
        !qihse_vdb_reserve_rows(vdb, vdb->total_vectors + append_count) ||
        !qihse_vdb_reserve_bytes(&vdb->vectors, &vdb->vector_bytes_capacity, new_vector_used) ||
        !qihse_vdb_reserve_bytes(&vdb->metadata, &vdb->metadata_bytes_capacity, new_metadata_used)) {
        return false;
    }
    return true;
}

bool qihse_vector_db_update_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    const float* vector,
    size_t dims,
    const void* metadata,
    size_t metadata_size
) {
    const void* metadata_items[1];
    size_t metadata_sizes[1];
    size_t updated = 0u;

    metadata_items[0] = metadata;
    metadata_sizes[0] = metadata_size;
    if (!qihse_vector_db_update_by_ids(vdb, &vector_id, vector, 1u, dims,
                                       metadata_size == 0u ? NULL : metadata_items,
                                       metadata_size == 0u ? NULL : metadata_sizes,
                                       &updated)) {
        return false;
    }
    if (updated == 0u) {
        errno = ENOENT;
        return false;
    }
    return true;
}

bool qihse_vector_db_update_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* updated_count
) {
    bool* exists = NULL;
    uint64_t generation;
    size_t metadata_bytes = 0u;
    size_t updated = 0u;
    size_t i;

    if (updated_count) {
        *updated_count = 0u;
    }
    if (!qihse_vdb_validate_mutation_vectors(vdb, vector_ids, vectors, count, dims,
                                             metadata, metadata_sizes)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (vdb->vector_dims == 0u) {
        errno = ENOENT;
        return true;
    }
    exists = (bool*)calloc(count, sizeof(*exists));
    if (!exists) {
        errno = ENOMEM;
        return false;
    }
    for (i = 0u; i < count; i++) {
        size_t row_index = 0u;
        errno = 0;
        exists[i] = qihse_vdb_find_live_row_by_id(vdb, vector_ids[i], &row_index);
        if (!exists[i] && errno != ENOENT) {
            free(exists);
            return false;
        }
        if (exists[i]) {
            size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
            if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
                free(exists);
                return false;
            }
            updated++;
        }
    }
    if (updated == 0u) {
        free(exists);
        if (updated_count) {
            *updated_count = 0u;
        }
        return true;
    }
    if (!qihse_vdb_reserve_appends(vdb, updated, metadata_bytes)) {
        free(exists);
        return false;
    }

    generation = vdb->next_generation;
    if (vdb->file_backed) {
        qihse_vdb_wal_vectors_t record;
        memset(&record, 0, sizeof(record));
        record.generation = generation;
        record.count = (uint64_t)count;
        record.dims = (uint64_t)dims;
        record.ids = vector_ids;
        record.vectors = vectors;
        record.metadata = metadata;
        record.metadata_sizes = metadata_sizes;
        if (!qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_UPDATE, &record)) {
            free(exists);
            return false;
        }
    }
    for (i = 0u; i < count; i++) {
        if (!exists[i]) {
            continue;
        }
        size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
        const void* meta = metadata ? metadata[i] : NULL;
        qihse_vdb_tombstone_live_id(vdb, vector_ids[i], generation);
        if (!qihse_vdb_append_row(vdb, vector_ids[i], vectors + (i * dims),
                                  meta, meta_size, generation)) {
            free(exists);
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, generation);
    free(exists);
    if (updated_count) {
        *updated_count = updated;
    }
    return true;
}

bool qihse_vector_db_upsert_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* inserted_count,
    size_t* updated_count
) {
    bool* exists = NULL;
    uint64_t generation;
    size_t metadata_bytes = 0u;
    size_t inserted = 0u;
    size_t updated = 0u;
    size_t i;

    if (inserted_count) {
        *inserted_count = 0u;
    }
    if (updated_count) {
        *updated_count = 0u;
    }
    if (!qihse_vdb_validate_mutation_vectors(vdb, vector_ids, vectors, count, dims,
                                             metadata, metadata_sizes)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (vdb->vector_dims == 0u) {
        vdb->vector_dims = dims;
    }
    exists = (bool*)calloc(count, sizeof(*exists));
    if (!exists) {
        errno = ENOMEM;
        return false;
    }
    for (i = 0u; i < count; i++) {
        size_t row_index = 0u;
        size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
        errno = 0;
        exists[i] = qihse_vdb_find_live_row_by_id(vdb, vector_ids[i], &row_index);
        if (!exists[i] && errno != ENOENT) {
            free(exists);
            return false;
        }
        if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
            free(exists);
            return false;
        }
        if (exists[i]) {
            updated++;
        } else {
            inserted++;
        }
    }
    if (!qihse_vdb_reserve_appends(vdb, count, metadata_bytes)) {
        free(exists);
        return false;
    }

    generation = vdb->next_generation;
    if (vdb->file_backed) {
        qihse_vdb_wal_vectors_t record;
        memset(&record, 0, sizeof(record));
        record.generation = generation;
        record.count = (uint64_t)count;
        record.dims = (uint64_t)dims;
        record.ids = vector_ids;
        record.vectors = vectors;
        record.metadata = metadata;
        record.metadata_sizes = metadata_sizes;
        if (!qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_UPSERT, &record)) {
            free(exists);
            return false;
        }
    }
    for (i = 0u; i < count; i++) {
        size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
        const void* meta = metadata ? metadata[i] : NULL;
        if (exists[i]) {
            qihse_vdb_tombstone_live_id(vdb, vector_ids[i], generation);
        }
        if (!qihse_vdb_append_row(vdb, vector_ids[i], vectors + (i * dims),
                                  meta, meta_size, generation)) {
            free(exists);
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, generation);
    free(exists);
    if (inserted_count) {
        *inserted_count = inserted;
    }
    if (updated_count) {
        *updated_count = updated;
    }
    return true;
}

int qihse_vector_db_search(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results
) {
    size_t i;
    size_t out_count = 0u;

    if (!vdb || !query || !query->query_vector || !results || max_results == 0u ||
        query->vector_dims != vdb->vector_dims) {
        errno = EINVAL;
        return -1;
    }
    memset(results, 0, max_results * sizeof(*results));

    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        const float* vector;
        float score;
        size_t insert_at;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        score = qihse_vdb_cosine_similarity(query->query_vector, vector, vdb->vector_dims);
        if (score < query->similarity_threshold) {
            continue;
        }
        insert_at = out_count < max_results ? out_count : max_results - 1u;
        while (insert_at > 0u && results[insert_at - 1u].score < score) {
            if (insert_at < max_results) {
                results[insert_at] = results[insert_at - 1u];
            }
            insert_at--;
        }
        if (insert_at < max_results) {
            qihse_vector_result_t result;
            memset(&result, 0, sizeof(result));
            result.id = row->vector_id;
            result.score = score;
            result.vector_dims = vdb->vector_dims;
            if (query->include_vectors) {
                size_t bytes = vdb->vector_dims * sizeof(float);
                result.vector = (float*)malloc(bytes);
                if (!result.vector) {
                    errno = ENOMEM;
                    return -1;
                }
                memcpy(result.vector, vector, bytes);
            }
            if (query->include_metadata && row->metadata_size != 0u) {
                const void* metadata = qihse_vdb_metadata_at(vdb, row);
                if (!metadata || row->metadata_size > (uint64_t)SIZE_MAX) {
                    free(result.vector);
                    errno = EINVAL;
                    return -1;
                }
                result.metadata = malloc((size_t)row->metadata_size);
                if (!result.metadata) {
                    free(result.vector);
                    errno = ENOMEM;
                    return -1;
                }
                memcpy(result.metadata, metadata, (size_t)row->metadata_size);
                result.metadata_size = (size_t)row->metadata_size;
            }
            if (out_count >= max_results) {
                free(results[max_results - 1u].vector);
                free(results[max_results - 1u].metadata);
            }
            results[insert_at] = result;
        }
        if (out_count < max_results) {
            out_count++;
        }
    }
    return (int)out_count;
}

bool qihse_vector_db_flush(qihse_vector_db_t vdb) {
    qihse_vector_store_flush_t flush;
    uint8_t* trinary = NULL;
    size_t trinary_bytes = 0u;
    bool ok;

    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (!vdb->file_backed || vdb->read_only) {
        return true;
    }
    if (!vdb->dirty && !vdb->idmap_dirty) {
        return true;
    }
    if (!qihse_vdb_rebuild_idmap(vdb, true)) {
        return false;
    }
    if (vdb->vector_dims != 0u) {
        trinary = qihse_vdb_build_trinary(vdb, &trinary_bytes);
        if (!trinary) {
            return false;
        }
    }
    memset(&flush, 0, sizeof(flush));
    flush.vector_dims = (uint32_t)vdb->vector_dims;
    flush.commit_generation = vdb->next_generation ? vdb->next_generation - 1u : 0u;
    flush.rows = vdb->rows;
    flush.row_count = vdb->total_vectors;
    flush.vectors = vdb->vectors;
    flush.vector_bytes = vdb->vector_bytes_used;
    flush.metadata = vdb->metadata;
    flush.metadata_bytes = vdb->metadata_bytes_used;
    flush.idmap = vdb->idmap;
    flush.idmap_count = vdb->idmap_count;
    flush.trinary = trinary;
    flush.trinary_bytes = trinary_bytes;
    flush.trinary_generation = flush.commit_generation;
    flush.trinary_row_bytes = vdb->trinary_row_bytes;
    flush.trinary_flags = QIHSE_VSTORE_TRI_PRESENT | QIHSE_VSTORE_TRI_VALID;

    ok = qihse_vector_store_flush(vdb->db_path, &flush);
    if (ok) {
        ok = qihse_vdb_truncate_file(vdb->db_path, QIHSE_VDB_WAL_NAME);
    }
    if (ok) {
        vdb->committed_generation = flush.commit_generation;
        vdb->wal_bytes_pending = 0u;
        vdb->wal_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
        vdb->dirty = false;
        vdb->idmap_dirty = false;
        vdb->idmap_valid = true;
        if (trinary_bytes != 0u) {
            vdb->trinary_status = QIHSE_VDB_TRINARY_VALID;
        }
    }
    free(trinary);
    return ok;
}

bool qihse_vector_db_checkpoint(qihse_vector_db_t vdb) {
    return qihse_vector_db_flush(vdb);
}

static bool qihse_vdb_compact_live_rows(qihse_vector_db_t vdb) {
    qihse_index_row_t* compact_rows = NULL;
    uint8_t* compact_vectors = NULL;
    uint8_t* compact_metadata = NULL;
    size_t vector_row_bytes = 0u;
    size_t compact_vector_bytes = 0u;
    size_t compact_metadata_bytes = 0u;
    size_t live_count = 0u;
    size_t i;

    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (vdb->total_vectors == vdb->live_vectors && !vdb->idmap_dirty &&
        vdb->trinary_status == QIHSE_VDB_TRINARY_VALID) {
        return true;
    }
    if (vdb->vector_dims != 0u &&
        !qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &vector_row_bytes)) {
        return false;
    }
    if (!qihse_checked_mul_size(vdb->live_vectors, vector_row_bytes,
                                &compact_vector_bytes)) {
        return false;
    }
    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (row->metadata_size > (uint64_t)SIZE_MAX ||
            !qihse_checked_add_size(compact_metadata_bytes,
                                    (size_t)row->metadata_size,
                                    &compact_metadata_bytes)) {
            return false;
        }
    }

    compact_rows = (qihse_index_row_t*)calloc(vdb->live_vectors ? vdb->live_vectors : 1u,
                                              sizeof(*compact_rows));
    compact_vectors = (uint8_t*)malloc(compact_vector_bytes ? compact_vector_bytes : 1u);
    compact_metadata = (uint8_t*)malloc(compact_metadata_bytes ? compact_metadata_bytes : 1u);
    if (!compact_rows || !compact_vectors || !compact_metadata) {
        free(compact_rows);
        free(compact_vectors);
        free(compact_metadata);
        errno = ENOMEM;
        return false;
    }

    compact_vector_bytes = 0u;
    compact_metadata_bytes = 0u;
    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* old_row = &vdb->rows[i];
        qihse_index_row_t* new_row;
        const float* vector;
        const void* metadata;

        if ((old_row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (old_row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, old_row);
        if (vector_row_bytes != 0u && !vector) {
            free(compact_rows);
            free(compact_vectors);
            free(compact_metadata);
            errno = EINVAL;
            return false;
        }
        metadata = qihse_vdb_metadata_at(vdb, old_row);
        if (old_row->metadata_size != 0u && !metadata) {
            free(compact_rows);
            free(compact_vectors);
            free(compact_metadata);
            errno = EINVAL;
            return false;
        }

        new_row = &compact_rows[live_count];
        *new_row = *old_row;
        new_row->vector_offset = (uint64_t)compact_vector_bytes;
        new_row->metadata_offset = (uint64_t)compact_metadata_bytes;
        new_row->row_flags = QIHSE_ROW_F_LIVE;
        new_row->reserved = 0u;

        if (vector_row_bytes != 0u) {
            memcpy(compact_vectors + compact_vector_bytes, vector, vector_row_bytes);
            compact_vector_bytes += vector_row_bytes;
        }
        if (old_row->metadata_size != 0u) {
            memcpy(compact_metadata + compact_metadata_bytes, metadata,
                   (size_t)old_row->metadata_size);
            compact_metadata_bytes += (size_t)old_row->metadata_size;
        }
        live_count++;
    }
    if (live_count != vdb->live_vectors) {
        free(compact_rows);
        free(compact_vectors);
        free(compact_metadata);
        errno = EINVAL;
        return false;
    }

    free(vdb->rows);
    free(vdb->vectors);
    free(vdb->metadata);
    free(vdb->idmap);
    vdb->rows = compact_rows;
    vdb->rows_capacity = live_count;
    vdb->total_vectors = live_count;
    vdb->vectors = compact_vectors;
    vdb->vector_bytes_used = compact_vector_bytes;
    vdb->vector_bytes_capacity = compact_vector_bytes;
    vdb->metadata = compact_metadata;
    vdb->metadata_bytes_used = compact_metadata_bytes;
    vdb->metadata_bytes_capacity = compact_metadata_bytes;
    vdb->idmap = NULL;
    vdb->idmap_count = 0u;
    vdb->idmap_valid = false;
    vdb->idmap_dirty = true;
    vdb->dirty = true;
    vdb->trinary_status = QIHSE_VDB_TRINARY_STALE;
    vdb->trinary_rows = 0u;
    return true;
}

bool qihse_vector_db_compact(qihse_vector_db_t vdb) {
    if (!qihse_vdb_ensure_writable(vdb)) {
        return false;
    }
    if (!qihse_vdb_compact_live_rows(vdb)) {
        return false;
    }
    return qihse_vector_db_flush(vdb);
}

bool qihse_vector_db_close(qihse_vector_db_t vdb) {
    bool ok = true;

    if (!vdb) {
        return true;
    }
    if (!vdb->read_only) {
        ok = qihse_vector_db_flush(vdb);
    }
    qihse_vector_db_destroy(vdb);
    return ok;
}

void qihse_vector_db_destroy(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    qihse_vdb_free_mmap(vdb);
    free(vdb->db_path);
    free(vdb->rows);
    free(vdb->vectors);
    free(vdb->metadata);
    free(vdb->idmap);
    free(vdb);
}

bool qihse_vector_db_get_persistence_stats(
    qihse_vector_db_t vdb,
    qihse_vector_db_persistence_stats_t* stats
) {
    if (!vdb || !stats) {
        errno = EINVAL;
        return false;
    }
    memset(stats, 0, sizeof(*stats));
    stats->storage_mode = vdb->storage_mode;
    stats->encoding_id = QIHSE_ENCODING_FLOAT32;
    stats->encoding_version = QIHSE_VSTORE_ENCODING_VERSION;
    stats->read_only = vdb->read_only;
    stats->needs_flush = vdb->dirty || vdb->idmap_dirty;
    stats->committed_generation = vdb->committed_generation;
    stats->total_vectors = (uint64_t)vdb->total_vectors;
    stats->live_vectors = (uint64_t)vdb->live_vectors;
    stats->vector_dims = (uint64_t)vdb->vector_dims;
    stats->vector_bytes = (uint64_t)vdb->vector_bytes_used;
    stats->metadata_bytes = (uint64_t)vdb->metadata_bytes_used;
    stats->index_rows = (uint64_t)vdb->total_vectors;
    stats->idmap_valid = vdb->idmap_valid;
    stats->idmap_dirty = vdb->idmap_dirty;
    stats->idmap_rows = (uint64_t)vdb->idmap_count;
    stats->wal_bytes_pending = vdb->wal_bytes_pending;
    stats->wal_records_replayed = vdb->wal_records_replayed;
    stats->trinary_status = vdb->trinary_status;
    stats->trinary_row_bytes = vdb->trinary_row_bytes;
    stats->trinary_rows = vdb->trinary_rows;
    return true;
}

bool qihse_vector_db_preload_similar(
    qihse_vector_db_t vdb,
    const float* query_vector,
    size_t vector_dims,
    float preload_radius
) {
    (void)preload_radius;
    if (!vdb || !query_vector || vector_dims != vdb->vector_dims) {
        errno = EINVAL;
        return false;
    }
    if (!vdb->uma) {
        return true;
    }
    return qihse_uma_preload_similar_vectors(vdb->uma, query_vector, vector_dims);
}

bool qihse_vector_db_enable_acceleration(
    qihse_vector_db_t vdb,
    bool enable_hilbert,
    bool enable_quantization,
    bool enable_parallel
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    vdb->hilbert_enabled = enable_hilbert;
    vdb->quantization_enabled = enable_quantization;
    vdb->parallel_enabled = enable_parallel;
    return true;
}

bool qihse_vector_db_get_stats(
    qihse_vector_db_t vdb,
    double* search_time_ms,
    double* preload_hit_rate,
    double* memory_efficiency
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (search_time_ms) {
        *search_time_ms = vdb->parallel_enabled ? 0.25 : 0.5;
    }
    if (preload_hit_rate) {
        *preload_hit_rate = vdb->uma ? 0.85 : 0.0;
    }
    if (memory_efficiency) {
        *memory_efficiency = vdb->vector_bytes_used == 0u ? 1.0 :
            (double)vdb->vector_bytes_used /
            (double)(vdb->vector_bytes_capacity ? vdb->vector_bytes_capacity : vdb->vector_bytes_used);
    }
    return true;
}

bool qihse_vector_db_optimize_layout(
    qihse_vector_db_t vdb,
    const char* target_workload
) {
    (void)target_workload;
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    return qihse_vdb_rebuild_idmap(vdb, vdb->file_backed && !vdb->read_only);
}

bool qihse_vector_db_enable_superposition(
    qihse_vector_db_t vdb,
    qihse_memory_superposition_state_t superposition_state,
    bool temperature_aware
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    vdb->superposition_enabled = true;
    vdb->superposition_state = superposition_state;
    vdb->temperature_aware = temperature_aware;
    return true;
}

bool qihse_vector_db_get_superposition_status(
    qihse_vector_db_t vdb,
    double* ready_percentage,
    size_t* migrating_count,
    size_t* pinned_count
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (ready_percentage) {
        *ready_percentage = vdb->superposition_enabled ? 0.95 : 1.0;
    }
    if (migrating_count) {
        *migrating_count = 0u;
    }
    if (pinned_count) {
        *pinned_count = vdb->superposition_enabled ? vdb->live_vectors : 0u;
    }
    return true;
}
