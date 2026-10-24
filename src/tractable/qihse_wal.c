#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * QIHSE Unified Write-Ahead Log
 *
 * Phase 2: ACID Transactions & MVCC
 *
 * Implements an append-only WAL with segment rotation, CRC32 checksums,
 * configurable durability (none / fdatasync / group commit), and replay
 * for crash recovery.
 */

#include "qihse_wal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <pthread.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <wmmintrin.h>
#include <x86intrin.h>
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ── Internal structures ────────────────────────────────────────────────── */

struct qihse_wal {
    pthread_mutex_t        lock;
    char                   directory[PATH_MAX];
    size_t                 segment_size;
    qihse_wal_durability_t durability;
    uint64_t               next_lsn;
    uint64_t               last_checkpoint_lsn;
    /* Current segment file */
    int                    seg_fd;
    uint64_t               seg_index;     /* current segment number */
    size_t                 seg_offset;    /* bytes written in current segment */
    char                   seg_path[PATH_MAX];
};

/* ── CRC32 (IEEE 802.3 0xEDB88320) with PCLMULQDQ 4-way folding & Slice-by-8 ─ */

static uint32_t s_crc32_table[8][256];
static pthread_once_t s_crc32_table_once = PTHREAD_ONCE_INIT;

static void init_crc32_slice8(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        s_crc32_table[0][i] = c;
    }
    for (int j = 1; j < 8; j++) {
        for (uint32_t i = 0; i < 256; i++) {
            s_crc32_table[j][i] = (s_crc32_table[j - 1][i] >> 8) ^
                                  s_crc32_table[0][s_crc32_table[j - 1][i] & 0xFFu];
        }
    }
}

static inline uint32_t crc32_slice8(const uint8_t* p, size_t len, uint32_t crc) {
    pthread_once(&s_crc32_table_once, init_crc32_slice8);
    while (len >= 8) {
        uint32_t w;
        memcpy(&w, p, 4);
        crc ^= w;
        crc = s_crc32_table[7][crc & 0xFF] ^
              s_crc32_table[6][(crc >> 8) & 0xFF] ^
              s_crc32_table[5][(crc >> 16) & 0xFF] ^
              s_crc32_table[4][(crc >> 24)] ^
              s_crc32_table[3][p[4]] ^
              s_crc32_table[2][p[5]] ^
              s_crc32_table[1][p[6]] ^
              s_crc32_table[0][p[7]];
        p += 8;
        len -= 8;
    }
    while (len--) {
        crc = s_crc32_table[0][(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

#if defined(__PCLMUL__) && defined(__SSE4_1__)
static inline uint32_t crc32_pclmul(const uint8_t* inbuf, size_t inlen, uint32_t crc) {
    if (inlen < 64) {
        return crc32_slice8(inbuf, inlen, crc);
    }

    const uint64_t k1k2_arr[2] = { 0x154442bd4ULL, 0x1c6e41596ULL };
    const uint64_t k3k4_arr[2] = { 0x1751997d0ULL, 0x0ccaa009eULL };
    const uint64_t k5_arr[2]   = { 0x163cd6124ULL, 0 };
    const uint64_t my_p_arr[2] = { 0x1f7011641ULL, 0x1db710641ULL };

    __m128i k1k2 = _mm_loadu_si128((const __m128i*)k1k2_arr);
    __m128i k3k4 = _mm_loadu_si128((const __m128i*)k3k4_arr);
    __m128i k5   = _mm_loadu_si128((const __m128i*)k5_arr);
    __m128i my_p = _mm_loadu_si128((const __m128i*)my_p_arr);

    __m128i x0 = _mm_loadu_si128((const __m128i*)(inbuf + 0 * 16));
    __m128i x1 = _mm_loadu_si128((const __m128i*)(inbuf + 1 * 16));
    __m128i x2 = _mm_loadu_si128((const __m128i*)(inbuf + 2 * 16));
    __m128i x3 = _mm_loadu_si128((const __m128i*)(inbuf + 3 * 16));

    x0 = _mm_xor_si128(x0, _mm_cvtsi32_si128(crc));

    inbuf += 4 * 16;
    inlen -= 4 * 16;

    while (inlen >= 4 * 16) {
        __m128i y0 = _mm_loadu_si128((const __m128i*)(inbuf + 0 * 16));
        __m128i y1 = _mm_loadu_si128((const __m128i*)(inbuf + 1 * 16));
        __m128i y2 = _mm_loadu_si128((const __m128i*)(inbuf + 2 * 16));
        __m128i y3 = _mm_loadu_si128((const __m128i*)(inbuf + 3 * 16));

        __m128i a0 = _mm_clmulepi64_si128(x0, k1k2, 0x00);
        __m128i b0 = _mm_clmulepi64_si128(x0, k1k2, 0x11);
        x0 = _mm_xor_si128(_mm_xor_si128(a0, b0), y0);

        __m128i a1 = _mm_clmulepi64_si128(x1, k1k2, 0x00);
        __m128i b1 = _mm_clmulepi64_si128(x1, k1k2, 0x11);
        x1 = _mm_xor_si128(_mm_xor_si128(a1, b1), y1);

        __m128i a2 = _mm_clmulepi64_si128(x2, k1k2, 0x00);
        __m128i b2 = _mm_clmulepi64_si128(x2, k1k2, 0x11);
        x2 = _mm_xor_si128(_mm_xor_si128(a2, b2), y2);

        __m128i a3 = _mm_clmulepi64_si128(x3, k1k2, 0x00);
        __m128i b3 = _mm_clmulepi64_si128(x3, k1k2, 0x11);
        x3 = _mm_xor_si128(_mm_xor_si128(a3, b3), y3);

        inbuf += 4 * 16;
        inlen -= 4 * 16;
    }

    /* Fold 4 to 1 */
    __m128i f0 = _mm_clmulepi64_si128(x0, k3k4, 0x00);
    __m128i g0 = _mm_clmulepi64_si128(x0, k3k4, 0x11);
    x0 = _mm_xor_si128(_mm_xor_si128(f0, g0), x1);

    __m128i f1 = _mm_clmulepi64_si128(x0, k3k4, 0x00);
    __m128i g1 = _mm_clmulepi64_si128(x0, k3k4, 0x11);
    x0 = _mm_xor_si128(_mm_xor_si128(f1, g1), x2);

    __m128i f2 = _mm_clmulepi64_si128(x0, k3k4, 0x00);
    __m128i g2 = _mm_clmulepi64_si128(x0, k3k4, 0x11);
    x0 = _mm_xor_si128(_mm_xor_si128(f2, g2), x3);

    /* Fold remaining 16-byte blocks */
    while (inlen >= 16) {
        __m128i y = _mm_loadu_si128((const __m128i*)inbuf);
        __m128i a = _mm_clmulepi64_si128(x0, k3k4, 0x00);
        __m128i b = _mm_clmulepi64_si128(x0, k3k4, 0x11);
        x0 = _mm_xor_si128(_mm_xor_si128(a, b), y);
        inbuf += 16;
        inlen -= 16;
    }

    /* Final reduction: reduce 128-bits to 96-bits */
    __m128i r0 = _mm_clmulepi64_si128(x0, k3k4, 0x10);
    __m128i r1 = _mm_srli_si128(x0, 8);
    x0 = _mm_xor_si128(r0, r1);

    /* reduce 96-bits to 64-bits */
    __m128i m1 = _mm_shuffle_epi32(x0, 0xfc);
    x0 = _mm_shuffle_epi32(x0, 0xf9);
    m1 = _mm_clmulepi64_si128(m1, k5, 0x00);
    x0 = _mm_xor_si128(x0, m1);

    /* barrett reduction */
    __m128i b1 = _mm_shuffle_epi32(x0, 0xf3);
    x0 = _mm_slli_si128(x0, 4);
    __m128i q0 = _mm_clmulepi64_si128(b1, my_p, 0x00);
    __m128i q1 = _mm_clmulepi64_si128(q0, my_p, 0x10);
    x0 = _mm_xor_si128(x0, q1);

    uint32_t res = (uint32_t)_mm_extract_epi32(x0, 2);

    if (inlen > 0) {
        res = crc32_slice8(inbuf, inlen, res);
    }
    return res;
}
#endif

uint32_t qihse_wal_crc32(const void* data, size_t len) {
    if (!data || len == 0) return 0;
#if defined(__PCLMUL__) && defined(__SSE4_1__)
    return crc32_pclmul((const uint8_t*)data, len, 0xFFFFFFFFu) ^ 0xFFFFFFFFu;
#else
    return crc32_slice8((const uint8_t*)data, len, 0xFFFFFFFFu) ^ 0xFFFFFFFFu;
#endif
}

/* ── Segment management ─────────────────────────────────────────────────── */

static void seg_path(char* buf, size_t bufsz, const char* dir, uint64_t idx) {
    int n = snprintf(buf, bufsz, "%s/wal_%020lu.log", dir, (unsigned long)idx);
    if (n < 0 || (size_t)n >= bufsz) {
        /* Truncation occurred — null-terminate and leave path as-is.
         * Caller will fail on open() with ENOENT. */
        if (bufsz > 0) buf[bufsz - 1] = '\0';
    }
}

static int sync_data_fd(int fd) {
    int rc;
    do { rc = fdatasync(fd); } while (rc != 0 && errno == EINTR);
    return rc;
}

static int sync_directory(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int rc;
    do { rc = fsync(fd); } while (rc != 0 && errno == EINTR);
    int saved_errno = errno;
    if (close(fd) != 0 && rc == 0) {
        rc = -1;
        saved_errno = errno;
    }
    errno = saved_errno;
    return rc;
}

static int seg_open(qihse_wal_t* wal) {
    seg_path(wal->seg_path, sizeof(wal->seg_path),
             wal->directory, wal->seg_index);
    bool created = false;
    wal->seg_fd = open(wal->seg_path,
                       O_WRONLY | O_CREAT | O_EXCL | O_APPEND, 0640);
    if (wal->seg_fd >= 0) {
        created = true;
    } else if (errno == EEXIST) {
        wal->seg_fd = open(wal->seg_path, O_WRONLY | O_APPEND);
    }
    if (wal->seg_fd < 0) return -1;
    if (created && wal->durability != QIHSE_WAL_DURABILITY_NONE &&
        sync_directory(wal->directory) != 0) {
        int saved_errno = errno;
        close(wal->seg_fd);
        wal->seg_fd = -1;
        errno = saved_errno;
        return -1;
    }
    /* Determine current offset */
    struct stat st;
    if (fstat(wal->seg_fd, &st) == 0) {
        wal->seg_offset = (size_t)st.st_size;
    } else {
        wal->seg_offset = 0;
    }
    return 0;
}

static int seg_rotate(qihse_wal_t* wal) {
    if (wal->seg_fd >= 0) {
        if (wal->durability != QIHSE_WAL_DURABILITY_NONE) {
            if (sync_data_fd(wal->seg_fd) != 0) return -1;
        }
        int old_fd = wal->seg_fd;
        wal->seg_fd = -1;
        if (close(old_fd) != 0) return -1;
    }
    wal->seg_index++;
    wal->seg_offset = 0;
    return seg_open(wal);
}

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_wal_t* qihse_wal_create(const char* directory,
                              size_t segment_size,
                              qihse_wal_durability_t durability)
{
    if (!directory) return NULL;
    if (segment_size == 0) segment_size = QIHSE_WAL_DEFAULT_SEGMENT_SIZE;

    qihse_wal_t* wal = calloc(1, sizeof(*wal));
    if (!wal) return NULL;

    pthread_mutex_init(&wal->lock, NULL);
    strncpy(wal->directory, directory, sizeof(wal->directory) - 1);
    wal->segment_size = segment_size;
    wal->durability = durability;
    wal->next_lsn = QIHSE_WAL_INVALID_LSN + 1;  /* start at 1 */
    wal->last_checkpoint_lsn = 0;
    wal->seg_fd = -1;
    wal->seg_index = 0;
    wal->seg_offset = 0;

    /* Create directory if it doesn't exist */
    if (mkdir(directory, 0750) != 0 && errno != EEXIST) {
        pthread_mutex_destroy(&wal->lock);
        free(wal);
        return NULL;
    }

    /* Find the highest segment index and continue from there */
    DIR* dir = opendir(directory);
    if (dir) {
        struct dirent* ent;
        uint64_t max_idx = 0;
        bool found = false;
        while ((ent = readdir(dir)) != NULL) {
            uint64_t idx;
            if (sscanf(ent->d_name, "wal_%020lu.log", &idx) == 1) {
                if (!found || idx > max_idx) {
                    max_idx = idx;
                    found = true;
                }
            }
        }
        closedir(dir);
        if (found) {
            wal->seg_index = max_idx;
        }
    }

    if (seg_open(wal) != 0) {
        pthread_mutex_destroy(&wal->lock);
        free(wal);
        return NULL;
    }

    return wal;
}

void qihse_wal_destroy(qihse_wal_t* wal) {
    if (!wal) return;
    pthread_mutex_lock(&wal->lock);
    if (wal->seg_fd >= 0) {
        if (wal->durability != QIHSE_WAL_DURABILITY_NONE) {
            (void)sync_data_fd(wal->seg_fd);
        }
        close(wal->seg_fd);
    }
    pthread_mutex_unlock(&wal->lock);
    pthread_mutex_destroy(&wal->lock);
    free(wal);
}

/* ── Append ─────────────────────────────────────────────────────────────── */

static uint64_t wal_append_raw(qihse_wal_t* wal,
                               uint64_t txn_id,
                               uint8_t engine_id,
                               qihse_wal_op_t op_type,
                               const void* key, uint32_t key_len,
                               const void* value, uint32_t value_len)
{
    if (!wal) return 0;

    pthread_mutex_lock(&wal->lock);

    /* Check if we need to rotate */
    size_t rec_total = QIHSE_WAL_RECORD_HEADER_SIZE + key_len + value_len;
    if (wal->seg_offset + rec_total > wal->segment_size && wal->seg_offset > 0) {
        if (seg_rotate(wal) != 0) {
            pthread_mutex_unlock(&wal->lock);
            return 0;
        }
    }

    uint64_t lsn = wal->next_lsn++;

    /* Build the record header */
    qihse_wal_record_t rec;
    rec.lsn          = lsn;
    rec.txn_id       = txn_id;
    rec.engine_id    = engine_id;
    rec.op_type      = (uint8_t)op_type;
    rec.key_length   = key_len;
    rec.value_length = value_len;

    /* Compute checksum over header fields + key + value */
    /* CRC32 of: lsn, txn_id, engine_id, op_type, key_length, value_length */
    uint32_t crc = 0;
    crc = qihse_wal_crc32(&rec.lsn, 8);
    crc ^= qihse_wal_crc32(&rec.txn_id, 8);
    crc ^= qihse_wal_crc32(&rec.engine_id, 1);
    crc ^= qihse_wal_crc32(&rec.op_type, 1);
    crc ^= qihse_wal_crc32(&rec.key_length, 4);
    crc ^= qihse_wal_crc32(&rec.value_length, 4);
    if (key_len > 0 && key) {
        crc ^= qihse_wal_crc32(key, key_len);
    }
    if (value_len > 0 && value) {
        crc ^= qihse_wal_crc32(value, value_len);
    }
    rec.checksum = crc;

    /* Pack header into contiguous buffer to write atomically with writev */
    uint8_t hdr[QIHSE_WAL_RECORD_HEADER_SIZE];
    memcpy(hdr + 0, &rec.lsn, 8);
    memcpy(hdr + 8, &rec.txn_id, 8);
    hdr[16] = rec.engine_id;
    hdr[17] = rec.op_type;
    memcpy(hdr + 18, &rec.key_length, 4);
    memcpy(hdr + 22, &rec.value_length, 4);
    memcpy(hdr + 26, &rec.checksum, 4);

    struct iovec iov[3];
    int iovcnt = 1;
    iov[0].iov_base = hdr;
    iov[0].iov_len  = QIHSE_WAL_RECORD_HEADER_SIZE;
    if (key_len > 0 && key) {
        iov[iovcnt].iov_base = (void*)key;
        iov[iovcnt].iov_len  = key_len;
        iovcnt++;
    }
    if (value_len > 0 && value) {
        iov[iovcnt].iov_base = (void*)value;
        iov[iovcnt].iov_len  = value_len;
        iovcnt++;
    }

    ssize_t w = writev(wal->seg_fd, iov, iovcnt);
    if (w != (ssize_t)rec_total) goto fail;

    wal->seg_offset += rec_total;

    /* Durability */
    if (wal->durability == QIHSE_WAL_DURABILITY_FDATASYNC) {
        if (sync_data_fd(wal->seg_fd) != 0) goto fail;
    }
    /* GROUP_COMMIT: caller is responsible for calling qihse_wal_flush() */

    pthread_mutex_unlock(&wal->lock);
    return lsn;

fail:
    pthread_mutex_unlock(&wal->lock);
    return 0;
}

uint64_t qihse_wal_append(qihse_wal_t* wal,
                          uint64_t txn_id,
                          uint8_t engine_id,
                          qihse_wal_op_t op_type,
                          const void* key, uint32_t key_len,
                          const void* value, uint32_t value_len)
{
    return wal_append_raw(wal, txn_id, engine_id, op_type,
                          key, key_len, value, value_len);
}

uint64_t qihse_wal_append_begin(qihse_wal_t* wal, uint64_t txn_id) {
    return wal_append_raw(wal, txn_id, 0, QIHSE_WAL_OP_BEGIN,
                          NULL, 0, NULL, 0);
}

uint64_t qihse_wal_append_commit(qihse_wal_t* wal, uint64_t txn_id) {
    return wal_append_raw(wal, txn_id, 0, QIHSE_WAL_OP_COMMIT,
                          NULL, 0, NULL, 0);
}

uint64_t qihse_wal_append_abort(qihse_wal_t* wal, uint64_t txn_id) {
    return wal_append_raw(wal, txn_id, 0, QIHSE_WAL_OP_ABORT,
                          NULL, 0, NULL, 0);
}

uint64_t qihse_wal_append_checkpoint(qihse_wal_t* wal, uint64_t lsn) {
    return wal_append_raw(wal, 0, 0, QIHSE_WAL_OP_CHECKPOINT,
                          &lsn, sizeof(lsn), NULL, 0);
}

int qihse_wal_flush(qihse_wal_t* wal) {
    if (!wal) return -1;
    pthread_mutex_lock(&wal->lock);
    int rc = wal->seg_fd >= 0 ? sync_data_fd(wal->seg_fd) : -1;
    pthread_mutex_unlock(&wal->lock);
    return rc;
}

/* ── Replay ─────────────────────────────────────────────────────────────── */

static bool read_full(int fd, void* buf, size_t len) {
    size_t total = 0;
    uint8_t* p = (uint8_t*)buf;
    while (total < len) {
        ssize_t r = read(fd, p + total, len - total);
        if (r <= 0) return false;
        total += (size_t)r;
    }
    return true;
}

int qihse_wal_replay(qihse_wal_t* wal, uint64_t start_lsn,
                     qihse_wal_replay_cb callback, void* user_data)
{
    if (!wal || !callback) return -1;

    int replayed = 0;

    pthread_mutex_lock(&wal->lock);

    /* Flush current segment first */
    if (wal->seg_fd >= 0) {
        if (sync_data_fd(wal->seg_fd) != 0) {
            pthread_mutex_unlock(&wal->lock);
            return -1;
        }
    } else {
        pthread_mutex_unlock(&wal->lock);
        return -1;
    }

    /* Iterate over all segment files in order */
    DIR* dir = opendir(wal->directory);
    if (!dir) {
        pthread_mutex_unlock(&wal->lock);
        return -1;
    }

    /* Collect segment indices */
    uint64_t* seg_indices = NULL;
    int seg_count = 0;
    int seg_cap = 16;
    seg_indices = malloc(seg_cap * sizeof(uint64_t));

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        uint64_t idx;
        if (sscanf(ent->d_name, "wal_%020lu.log", &idx) == 1) {
            if (seg_count >= seg_cap) {
                seg_cap *= 2;
                seg_indices = realloc(seg_indices, seg_cap * sizeof(uint64_t));
            }
            seg_indices[seg_count++] = idx;
        }
    }
    closedir(dir);

    /* Sort segment indices (simple insertion sort) */
    for (int i = 1; i < seg_count; i++) {
        uint64_t key = seg_indices[i];
        int j = i - 1;
        while (j >= 0 && seg_indices[j] > key) {
            seg_indices[j + 1] = seg_indices[j];
            j--;
        }
        seg_indices[j + 1] = key;
    }

    /* Replay each segment */
    for (int si = 0; si < seg_count; si++) {
        char path[PATH_MAX];
        seg_path(path, sizeof(path), wal->directory, seg_indices[si]);

        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;

        for (;;) {
            qihse_wal_record_t rec;
            uint8_t hdr[QIHSE_WAL_RECORD_HEADER_SIZE];
            if (!read_full(fd, hdr, QIHSE_WAL_RECORD_HEADER_SIZE)) break;

            memcpy(&rec.lsn, hdr + 0, 8);
            memcpy(&rec.txn_id, hdr + 8, 8);
            rec.engine_id    = hdr[16];
            rec.op_type      = hdr[17];
            memcpy(&rec.key_length, hdr + 18, 4);
            memcpy(&rec.value_length, hdr + 22, 4);
            memcpy(&rec.checksum, hdr + 26, 4);

            /* Validate key/value lengths */
            if (rec.key_length > QIHSE_WAL_MAX_KEY ||
                rec.value_length > QIHSE_WAL_MAX_VALUE) {
                /* Corrupt record — stop replay of this segment */
                break;
            }

            /* Read key */
            void* key = NULL;
            if (rec.key_length > 0) {
                key = malloc(rec.key_length);
                if (!key || !read_full(fd, key, rec.key_length)) {
                    free(key);
                    break;
                }
            }

            /* Read value */
            void* value = NULL;
            if (rec.value_length > 0) {
                value = malloc(rec.value_length);
                if (!value || !read_full(fd, value, rec.value_length)) {
                    free(key);
                    free(value);
                    break;
                }
            }

            /* Verify checksum */
            uint32_t crc = 0;
            crc = qihse_wal_crc32(&rec.lsn, 8);
            crc ^= qihse_wal_crc32(&rec.txn_id, 8);
            crc ^= qihse_wal_crc32(&rec.engine_id, 1);
            crc ^= qihse_wal_crc32(&rec.op_type, 1);
            crc ^= qihse_wal_crc32(&rec.key_length, 4);
            crc ^= qihse_wal_crc32(&rec.value_length, 4);
            if (rec.key_length > 0 && key) {
                crc ^= qihse_wal_crc32(key, rec.key_length);
            }
            if (rec.value_length > 0 && value) {
                crc ^= qihse_wal_crc32(value, rec.value_length);
            }

            if (crc != rec.checksum) {
                /* Corrupt record — stop replay */
                free(key);
                free(value);
                break;
            }

            /* Skip records before start_lsn */
            if (rec.lsn >= start_lsn) {
                bool cont = callback(&rec, key, rec.key_length,
                                     value, rec.value_length, user_data);
                replayed++;
                if (!cont) {
                    free(key);
                    free(value);
                    close(fd);
                    goto done;
                }
            }

            free(key);
            free(value);
        }

        close(fd);
    }

done:
    free(seg_indices);
    pthread_mutex_unlock(&wal->lock);
    return replayed;
}

/* ── Checkpoint ─────────────────────────────────────────────────────────── */

int qihse_wal_checkpoint(qihse_wal_t* wal, uint64_t checkpoint_lsn) {
    if (!wal) return -1;
    pthread_mutex_lock(&wal->lock);

    /* Flush current segment */
    if (wal->seg_fd >= 0) {
        if (sync_data_fd(wal->seg_fd) != 0) {
            pthread_mutex_unlock(&wal->lock);
            return -1;
        }
    } else {
        pthread_mutex_unlock(&wal->lock);
        return -1;
    }

    bool removed = false;

    /* Truncate old segments (those with max LSN < checkpoint_lsn).
     * For simplicity, we remove all segments except the current one.
     * A more precise implementation would scan each segment's last LSN. */
    DIR* dir = opendir(wal->directory);
    if (dir) {
        struct dirent* ent;
        while ((ent = readdir(dir)) != NULL) {
            uint64_t idx;
            if (sscanf(ent->d_name, "wal_%020lu.log", &idx) == 1) {
                if (idx < wal->seg_index) {
                    char path[PATH_MAX];
                    int n = snprintf(path, sizeof(path), "%s/%s",
                             wal->directory, ent->d_name);
                    if (n < 0 || (size_t)n >= sizeof(path)) {
                        /* Path too long — skip this entry */
                        continue;
                    }
                    if (unlink(path) != 0 && errno != ENOENT) {
                        closedir(dir);
                        pthread_mutex_unlock(&wal->lock);
                        return -1;
                    }
                    removed = true;
                }
            }
        }
        closedir(dir);
    } else {
        pthread_mutex_unlock(&wal->lock);
        return -1;
    }

    if (removed && wal->durability != QIHSE_WAL_DURABILITY_NONE &&
        sync_directory(wal->directory) != 0) {
        pthread_mutex_unlock(&wal->lock);
        return -1;
    }

    /* Publish checkpoint state only after the selected durability work passed. */
    wal->last_checkpoint_lsn = checkpoint_lsn;

    pthread_mutex_unlock(&wal->lock);
    return 0;
}

uint64_t qihse_wal_current_lsn(qihse_wal_t* wal) {
    if (!wal) return 0;
    pthread_mutex_lock(&wal->lock);
    uint64_t lsn = wal->next_lsn;
    pthread_mutex_unlock(&wal->lock);
    return lsn;
}

uint64_t qihse_wal_last_checkpoint(qihse_wal_t* wal) {
    if (!wal) return 0;
    pthread_mutex_lock(&wal->lock);
    uint64_t lsn = wal->last_checkpoint_lsn;
    pthread_mutex_unlock(&wal->lock);
    return lsn;
}
