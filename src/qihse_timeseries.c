#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "qihse_timeseries.h"
#include <stdlib.h>
#include <string.h>

#define QIHSE_RING_SIZE 4096

struct qihse_tsdb {
    qihse_tsdb_chunk_t* chunk_head;
    qihse_tsdb_chunk_t* chunk_tail;
    
    struct {
        uint32_t series_id;
        uint64_t timestamp;
        double value;
    } cache[QIHSE_RING_SIZE];
    
    qihse_padded_atomic_t head;
    qihse_padded_atomic_t tail;
};

qihse_tsdb_t* qihse_tsdb_create() {
    qihse_tsdb_t* tsdb = (qihse_tsdb_t*)malloc(sizeof(qihse_tsdb_t));
    if (tsdb) {
        tsdb->chunk_head = NULL;
        tsdb->chunk_tail = NULL;
        atomic_init(&tsdb->head.index, 0);
        atomic_init(&tsdb->tail.index, 0);
    }
    return tsdb;
}

void qihse_tsdb_destroy(qihse_tsdb_t* tsdb) {
    if (!tsdb) return;
    qihse_tsdb_chunk_t* curr = tsdb->chunk_head;
    while (curr) {
        qihse_tsdb_chunk_t* next = curr->next;
        free(curr);
        curr = next;
    }
    free(tsdb);
}

void qihse_tsdb_compress_flush(qihse_tsdb_t* tsdb) {
    if (!tsdb) return;
    
    uint64_t tail = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    uint64_t head = atomic_load_explicit(&tsdb->head.index, memory_order_acquire);
    
    if (head == tail) return;
    
    void* ptr = NULL;
    if (posix_memalign(&ptr, 4096, sizeof(qihse_tsdb_chunk_t)) != 0) {
        return;
    }
    
    qihse_tsdb_chunk_t* new_chunk = (qihse_tsdb_chunk_t*)ptr;
    memset(new_chunk, 0, sizeof(qihse_tsdb_chunk_t));
    
    uint64_t start_idx = tail % QIHSE_RING_SIZE;
    new_chunk->start_timestamp = tsdb->cache[start_idx].timestamp;
    new_chunk->series_id = tsdb->cache[start_idx].series_id;
    new_chunk->next = NULL;
    
    uint32_t count = 0;
    while (tail < head && count < (16 * 256 / sizeof(double))) {
        uint64_t idx = tail % QIHSE_RING_SIZE;
        
        /* 
         * Structure the data into the 16 independent 256-byte lanes.
         * Establish the memory boundary writes to map to strided AVX-512 registers.
         * Actual bit-twiddling (Gorilla XOR) is stubbed out.
         */
        uint8_t lane = count % 16;
        size_t offset = (count / 16) * sizeof(double);
        
        if (offset + sizeof(double) <= 256) {
            double val = tsdb->cache[idx].value;
            memcpy(&new_chunk->compressed_lanes[lane][offset], &val, sizeof(double));
        }
        
        new_chunk->end_timestamp = tsdb->cache[idx].timestamp;
        tail++;
        count++;
    }
    
    new_chunk->count = count;
    
    /* Update tail with atomic_fetch_add_explicit */
    atomic_fetch_add_explicit(&tsdb->tail.index, count, memory_order_release);
    
    if (tsdb->chunk_tail) {
        tsdb->chunk_tail->next = new_chunk;
        tsdb->chunk_tail = new_chunk;
    } else {
        tsdb->chunk_head = new_chunk;
        tsdb->chunk_tail = new_chunk;
    }
}

bool qihse_tsdb_insert(qihse_tsdb_t* tsdb, uint32_t series_id, uint64_t timestamp, double value) {
    if (!tsdb) return false;
    
    uint64_t head_idx = atomic_fetch_add_explicit(&tsdb->head.index, 1, memory_order_acq_rel);
    uint64_t ring_idx = head_idx % QIHSE_RING_SIZE;
    
    tsdb->cache[ring_idx].series_id = series_id;
    tsdb->cache[ring_idx].timestamp = timestamp;
    tsdb->cache[ring_idx].value = value;
    
    uint64_t tail_idx = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    if (head_idx - tail_idx >= QIHSE_RING_SIZE / 2) {
        qihse_tsdb_compress_flush(tsdb);
    }
    
    return true;
}

__attribute__((target_clones("avx512f", "avx2", "default")))
double qihse_tsdb_average_range(qihse_tsdb_t* tsdb, uint64_t start_ts, uint64_t end_ts) {
    if (!tsdb) return 0.0;
    
    double sum = 0.0;
    uint32_t count = 0;
    
    qihse_tsdb_chunk_t* curr = tsdb->chunk_head;
    while (curr) {
        if (curr->end_timestamp < start_ts || curr->start_timestamp > end_ts) {
            curr = curr->next;
            continue;
        }
        
        /* TODO: Implement Gorilla XOR Unpacking here */
        for (uint32_t i = 0; i < curr->count; i++) {
            uint8_t lane = i % 16;
            size_t offset = (i / 16) * sizeof(double);
            if (offset + sizeof(double) <= 256) {
                double val;
                memcpy(&val, &curr->compressed_lanes[lane][offset], sizeof(double));
                /* Stub: adding all values since we lack timestamp unpacked per data point */
                sum += val;
                count++;
            }
        }
        
        curr = curr->next;
    }
    
    uint64_t tail = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    uint64_t head = atomic_load_explicit(&tsdb->head.index, memory_order_acquire);
    
    for (uint64_t i = tail; i < head; i++) {
        uint64_t idx = i % QIHSE_RING_SIZE;
        if (tsdb->cache[idx].timestamp >= start_ts && tsdb->cache[idx].timestamp <= end_ts) {
            sum += tsdb->cache[idx].value;
            count++;
        }
    }
    
    if (count == 0) return 0.0;
    return sum / (double)count;
}
