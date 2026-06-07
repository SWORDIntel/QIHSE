#ifndef QIHSE_TIMESERIES_H
#define QIHSE_TIMESERIES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

#define QIHSE_TSDB_CHUNK_SIZE 4096

/**
 * @brief Cache-line padded atomic to prevent false sharing and L1 invalidation storms
 * when multiple DPDK polling threads hammer the lock-free ring buffer.
 */
typedef struct __attribute__((aligned(64))) {
    _Atomic uint64_t index;
} qihse_padded_atomic_t;

/**
 * @brief OS Page Aligned (4KB) Time-Series Compressed Chunk.
 * Utilizes Block-Strided Gorilla Compression to allow AVX-512 parallel decompression.
 */
typedef struct __attribute__((aligned(4096))) qihse_tsdb_chunk {
    uint32_t series_id; /* Decoupled from inverted index tags */
    uint32_t count;
    uint64_t start_timestamp;
    uint64_t end_timestamp;
    uint16_t classification;
    uint16_t sci_compartment;
    
    /* 16 independent 256-byte lanes for vectorized AVX-512 Gorilla decompression */
    uint8_t compressed_lanes[16][256]; 
    
    struct qihse_tsdb_chunk* next;
} qihse_tsdb_chunk_t;

/**
 * @brief Opaque handle for the QIHSE TSDB.
 */
typedef struct qihse_tsdb qihse_tsdb_t;

qihse_tsdb_t* qihse_tsdb_create();
void qihse_tsdb_destroy(qihse_tsdb_t* tsdb);

/**
 * @brief Ingest a data point bypassing POSIX sockets via DPDK or io_uring.
 * Drops String Tags immediately and uses the internal series_id.
 */
bool qihse_tsdb_insert(qihse_tsdb_t* tsdb, uint32_t series_id, uint64_t timestamp, double value, uint16_t classification, uint16_t sci_compartment);

/**
 * @brief Flushes bounded Out-of-Order (OoO) MemTables into the strided compression lanes.
 */
void qihse_tsdb_compress_flush(qihse_tsdb_t* tsdb);

#include "qihse_auth.h"
double qihse_tsdb_average_range_user(qihse_tsdb_t* tsdb, uint64_t start_ts, uint64_t end_ts, qihse_user_t* user);

/**
 * @brief Set the TTL in milliseconds for old chunks.
 */
void qihse_tsdb_set_ttl(qihse_tsdb_t* tsdb, uint64_t ttl_ms);

/**
 * @brief Trims any completely expired chunks older than current_ts - ttl_ms.
 */
void qihse_tsdb_trim(qihse_tsdb_t* tsdb, uint64_t current_ts);

#endif /* QIHSE_TIMESERIES_H */
