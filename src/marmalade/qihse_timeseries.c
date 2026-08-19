#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "qihse_timeseries.h"
#include "qihse_keystone.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <malloc.h>
#endif

#define QIHSE_RING_SIZE 4096

struct qihse_tsdb {
    qihse_tsdb_chunk_t* chunk_head;
    qihse_tsdb_chunk_t* chunk_tail;

    /* Keystone anchor-search chunk index (Idea 2).
     * Parallel sorted array of per-chunk start_timestamps plus the matching
     * chunk pointers, so range queries can use qihse_keystone_anchor_lower_bound
     * to skip the linear chunk walk. Chunks are appended in monotonic time
     * order by qihse_tsdb_compress_flush, so the array stays sorted. */
    int64_t* chunk_starts;
    qihse_tsdb_chunk_t** chunk_ptrs;
    size_t chunk_index_count;
    size_t chunk_index_cap;

    struct {
        uint32_t series_id;
        uint64_t timestamp;
        double value;
        uint16_t classification;
        uint16_t sci_compartment;
    } cache[QIHSE_RING_SIZE];

    qihse_padded_atomic_t head;
    qihse_padded_atomic_t tail;

    uint64_t ttl_ms;
};

typedef struct {
    uint8_t* buf;
    size_t bit_pos;
    size_t max_bits;
} bit_stream_t;

static inline void bw_write(bit_stream_t* bw, uint64_t val, int bits) {
    while (bits > 0) {
        size_t byte_idx = bw->bit_pos / 8;
        if (byte_idx >= bw->max_bits / 8) return;
        int bit_idx = bw->bit_pos % 8;
        int bits_to_write = 8 - bit_idx;
        if (bits_to_write > bits) bits_to_write = bits;
        
        uint64_t mask = (1ULL << bits_to_write) - 1;
        int shift = bits - bits_to_write;
        uint64_t extracted = (shift == 64) ? 0 : ((val >> shift) & mask);
        
        bw->buf[byte_idx] |= (uint8_t)(extracted << (8 - bit_idx - bits_to_write));
        
        bw->bit_pos += bits_to_write;
        bits -= bits_to_write;
    }
}

static inline uint64_t br_read(bit_stream_t* br, int bits) {
    uint64_t res = 0;
    while (bits > 0) {
        size_t byte_idx = br->bit_pos / 8;
        if (byte_idx >= br->max_bits / 8) return res;
        int bit_idx = br->bit_pos % 8;
        int bits_to_read = 8 - bit_idx;
        if (bits_to_read > bits) bits_to_read = bits;
        
        uint64_t mask = (1ULL << bits_to_read) - 1;
        int shift = 8 - bit_idx - bits_to_read;
        uint64_t extracted = (br->buf[byte_idx] >> shift) & mask;
        
        res = (res << bits_to_read) | extracted;
        
        br->bit_pos += bits_to_read;
        bits -= bits_to_read;
    }
    return res;
}

static inline int64_t sign_extend(uint64_t val, int bits) {
    uint64_t mask = 1ULL << (bits - 1);
    return (int64_t)((val ^ mask) - mask);
}

qihse_tsdb_t* qihse_tsdb_create() {
    qihse_tsdb_t* tsdb = (qihse_tsdb_t*)malloc(sizeof(qihse_tsdb_t));
    if (tsdb) {
        tsdb->chunk_head = NULL;
        tsdb->chunk_tail = NULL;
        tsdb->chunk_starts = NULL;
        tsdb->chunk_ptrs = NULL;
        tsdb->chunk_index_count = 0;
        tsdb->chunk_index_cap = 0;
        tsdb->ttl_ms = 0;
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
    free(tsdb->chunk_starts);
    free(tsdb->chunk_ptrs);
    free(tsdb);
}

void qihse_tsdb_compress_flush(qihse_tsdb_t* tsdb) {
    if (!tsdb) return;
    
    uint64_t tail = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    uint64_t head = atomic_load_explicit(&tsdb->head.index, memory_order_acquire);
    
    if (head == tail) return;
    
    void* ptr = NULL;
#ifdef _WIN32
    ptr = _aligned_malloc(sizeof(qihse_tsdb_chunk_t), 4096);
    if (!ptr) {
#else
    if (posix_memalign(&ptr, 4096, sizeof(qihse_tsdb_chunk_t)) != 0) {
#endif
        return;
    }
    
    qihse_tsdb_chunk_t* new_chunk = (qihse_tsdb_chunk_t*)ptr;
    memset(new_chunk, 0, sizeof(qihse_tsdb_chunk_t));
    
    uint64_t start_idx = tail % QIHSE_RING_SIZE;
    new_chunk->start_timestamp = tsdb->cache[start_idx].timestamp;
    new_chunk->series_id = tsdb->cache[start_idx].series_id;
    new_chunk->classification = tsdb->cache[start_idx].classification;
    new_chunk->sci_compartment = tsdb->cache[start_idx].sci_compartment;
    new_chunk->next = NULL;
    
    bit_stream_t bs = { (uint8_t*)new_chunk->compressed_lanes, 0, sizeof(new_chunk->compressed_lanes) * 8 };
    
    uint32_t count = 0;
    uint64_t t_prev = new_chunk->start_timestamp;
    int64_t d_prev = 0;
    uint64_t v_prev = 0;
    int prev_lz = 0;
    int prev_tz = 0;
    
    while (tail < head) {
        uint64_t idx = tail % QIHSE_RING_SIZE;
        if (count > 0 && tsdb->cache[idx].series_id != new_chunk->series_id) break;
        uint64_t t = tsdb->cache[idx].timestamp;
        double v_d = tsdb->cache[idx].value;
        uint64_t v;
        memcpy(&v, &v_d, sizeof(double));
        
        if (count == 0) {
            bw_write(&bs, v, 64);
            t_prev = t;
            v_prev = v;
        } else {
            int64_t d = (int64_t)(t - t_prev);
            int64_t dod = d - d_prev;
            if (dod == 0) {
                bw_write(&bs, 0, 1);
            } else if (dod >= -63 && dod <= 64) {
                bw_write(&bs, 2, 2);
                bw_write(&bs, dod & 0x7F, 7);
            } else if (dod >= -255 && dod <= 256) {
                bw_write(&bs, 6, 3);
                bw_write(&bs, dod & 0x1FF, 9);
            } else if (dod >= -2047 && dod <= 2048) {
                bw_write(&bs, 14, 4);
                bw_write(&bs, dod & 0xFFF, 12);
            } else {
                bw_write(&bs, 15, 4);
                bw_write(&bs, dod & 0xFFFFFFFF, 32);
            }
            t_prev = t;
            d_prev = d;
            
            uint64_t xor_val = v ^ v_prev;
            if (xor_val == 0) {
                bw_write(&bs, 0, 1);
            } else {
                int lz = __builtin_clzll(xor_val);
                int tz = __builtin_ctzll(xor_val);
                if (lz >= 31) lz = 31;
                
                if (lz >= prev_lz && tz >= prev_tz) {
                    bw_write(&bs, 2, 2);
                    int len = 64 - prev_lz - prev_tz;
                    bw_write(&bs, xor_val >> prev_tz, len);
                } else {
                    bw_write(&bs, 3, 2);
                    bw_write(&bs, lz, 5);
                    int len = 64 - lz - tz;
                    if (len < 1) len = 1;
                    if (len > 64) len = 64;
                    bw_write(&bs, len - 1, 6);
                    bw_write(&bs, xor_val >> tz, len);
                    prev_lz = lz;
                    prev_tz = tz;
                }
            }
            v_prev = v;
        }
        
        new_chunk->end_timestamp = t;
        tail++;
        count++;
        
        if (bs.bit_pos + 128 >= bs.max_bits) {
            break;
        }
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

    /* Append to the keystone anchor chunk index. Chunks are flushed in
     * monotonic time order, so the start_timestamp array stays sorted and
     * qihse_keystone_anchor_lower_bound can be used for O(log log N) range
     * lookup. */
    if (tsdb->chunk_index_count >= tsdb->chunk_index_cap) {
        size_t new_cap = (tsdb->chunk_index_cap == 0) ? 16 : tsdb->chunk_index_cap * 2;
        int64_t* new_starts = (int64_t*)realloc(tsdb->chunk_starts, new_cap * sizeof(int64_t));
        if (new_starts) {
            tsdb->chunk_starts = new_starts;
            qihse_tsdb_chunk_t** new_ptrs = (qihse_tsdb_chunk_t**)realloc(tsdb->chunk_ptrs, new_cap * sizeof(qihse_tsdb_chunk_t*));
            if (new_ptrs) {
                tsdb->chunk_ptrs = new_ptrs;
                tsdb->chunk_index_cap = new_cap;
            } else {
                /* ptr array growth failed: keep old cap, skip this append. */
                return;
            }
        } else {
            return;
        }
    }
    tsdb->chunk_starts[tsdb->chunk_index_count] = (int64_t)new_chunk->start_timestamp;
    tsdb->chunk_ptrs[tsdb->chunk_index_count] = new_chunk;
    tsdb->chunk_index_count++;
}

bool qihse_tsdb_insert(qihse_tsdb_t* tsdb, uint32_t series_id, uint64_t timestamp, double value, uint16_t classification, uint16_t sci_compartment) {
    if (!tsdb) return false;
    
    uint64_t head_idx = atomic_fetch_add_explicit(&tsdb->head.index, 1, memory_order_acq_rel);
    uint64_t ring_idx = head_idx % QIHSE_RING_SIZE;
    
    tsdb->cache[ring_idx].series_id = series_id;
    tsdb->cache[ring_idx].timestamp = timestamp;
    tsdb->cache[ring_idx].value = value;
    tsdb->cache[ring_idx].classification = classification;
    tsdb->cache[ring_idx].sci_compartment = sci_compartment;
    
    uint64_t tail_idx = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    if (head_idx - tail_idx >= QIHSE_RING_SIZE / 2) {
        qihse_tsdb_compress_flush(tsdb);
    }
    
    return true;
}

__attribute__((target_clones("avx512f", "avx2", "default")))
double qihse_tsdb_average_range_user(qihse_tsdb_t* tsdb, uint64_t start_ts, uint64_t end_ts, qihse_user_t* user) {
    if (!tsdb) return 0.0;

    double sum = 0.0;
    uint32_t count = 0;

    /* Keystone anchor-indexed chunk scan (Idea 2): O(log log N) lower_bound
     * on the sorted per-chunk start_timestamp array lands us directly on the
     * first chunk that may overlap [start_ts, end_ts], replacing the previous
     * linear chunk walk / binary search. */
    size_t chunk_total = tsdb->chunk_index_count;
    size_t start_idx = 0;
    if (chunk_total > 0 && tsdb->chunk_ptrs) {
        start_idx = qihse_keystone_anchor_lower_bound(
            tsdb->chunk_starts, chunk_total, (int64_t)start_ts);
        if (start_idx > 0) start_idx--; /* the chunk containing start_ts may start before it */
    }
    for (size_t ci = start_idx; ci < chunk_total; ci++) {
        qihse_tsdb_chunk_t* curr = tsdb->chunk_ptrs[ci];
        if (curr->start_timestamp > end_ts) break; /* sorted: no further overlaps */
        if (curr->end_timestamp < start_ts) continue;
        if (!qihse_auth_can_access(user, curr->classification, curr->sci_compartment)) {
            continue;
        }

        bit_stream_t bs = { (uint8_t*)curr->compressed_lanes, 0, sizeof(curr->compressed_lanes) * 8 };
        uint64_t t_prev = curr->start_timestamp;
        int64_t d_prev = 0;
        uint64_t v_prev = 0;
        int prev_lz = 0;
        int prev_tz = 0;

        for (uint32_t i = 0; i < curr->count; i++) {
            uint64_t t;
            uint64_t v;

            if (i == 0) {
                t = t_prev;
                v = br_read(&bs, 64);
                v_prev = v;
            } else {
                int64_t dod = 0;
                if (br_read(&bs, 1) == 0) {
                    dod = 0;
                } else if (br_read(&bs, 1) == 0) {
                    dod = sign_extend(br_read(&bs, 7), 7);
                } else if (br_read(&bs, 1) == 0) {
                    dod = sign_extend(br_read(&bs, 9), 9);
                } else if (br_read(&bs, 1) == 0) {
                    dod = sign_extend(br_read(&bs, 12), 12);
                } else {
                    dod = sign_extend(br_read(&bs, 32), 32);
                }

                int64_t d = d_prev + dod;
                t = t_prev + d;
                t_prev = t;
                d_prev = d;

                if (br_read(&bs, 1) == 0) {
                    v = v_prev;
                } else {
                    if (br_read(&bs, 1) == 0) {
                        int len = 64 - prev_lz - prev_tz;
                        uint64_t xor_val = br_read(&bs, len);
                        v = v_prev ^ (xor_val << prev_tz);
                    } else {
                        int lz = br_read(&bs, 5);
                        int len = br_read(&bs, 6) + 1;
                        uint64_t xor_val = br_read(&bs, len);
                        int tz = 64 - lz - len;
                        v = v_prev ^ (xor_val << tz);

                        prev_lz = lz;
                        prev_tz = tz;
                    }
                }
                v_prev = v;
            }

            if (t >= start_ts && t <= end_ts) {
                double v_d;
                memcpy(&v_d, &v, sizeof(double));
                sum += v_d;
                count++;
            }
        }
    }
    
    uint64_t tail = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    uint64_t head = atomic_load_explicit(&tsdb->head.index, memory_order_acquire);
    
    for (uint64_t i = tail; i < head; i++) {
        uint64_t idx = i % QIHSE_RING_SIZE;
        if (!qihse_auth_can_access(user, tsdb->cache[idx].classification, tsdb->cache[idx].sci_compartment)) {
            continue;
        }
        if (tsdb->cache[idx].timestamp >= start_ts && tsdb->cache[idx].timestamp <= end_ts) {
            sum += tsdb->cache[idx].value;
            count++;
        }
    }
    
    if (count == 0) return 0.0;
    return sum / (double)count;
}

static void qihse_tsdb_aggregate_value(double value, qihse_ts_aggregation_t aggregation, double* aggregate, uint64_t* count) {
    if (*count == 0) {
        *aggregate = value;
    } else if (aggregation == QIHSE_TS_AGG_SUM || aggregation == QIHSE_TS_AGG_AVG) {
        *aggregate += value;
    } else if (aggregation == QIHSE_TS_AGG_MIN && value < *aggregate) {
        *aggregate = value;
    } else if (aggregation == QIHSE_TS_AGG_MAX && value > *aggregate) {
        *aggregate = value;
    }
    (*count)++;
}

bool qihse_tsdb_aggregate_range_user(qihse_tsdb_t* tsdb, uint32_t series_id, uint64_t start_ts, uint64_t end_ts, qihse_ts_aggregation_t aggregation, qihse_user_t* user, double* out_value, uint64_t* out_count) {
    if (!tsdb || !out_value || start_ts > end_ts || aggregation > QIHSE_TS_AGG_MAX) return false;
    double aggregate = 0.0;
    uint64_t count = 0;

    /* Keystone anchor-indexed chunk scan (Idea 2): O(log log N) lower_bound
     * on the sorted per-chunk start_timestamp array replaces the linear chunk
     * walk / binary search to find the first overlapping chunk. */
    size_t chunk_total = tsdb->chunk_index_count;
    size_t start_idx = 0;
    if (chunk_total > 0 && tsdb->chunk_ptrs) {
        start_idx = qihse_keystone_anchor_lower_bound(
            tsdb->chunk_starts, chunk_total, (int64_t)start_ts);
        if (start_idx > 0) start_idx--; /* the chunk containing start_ts may start before it */
    }
    for (size_t ci = start_idx; ci < chunk_total; ci++) {
        qihse_tsdb_chunk_t* curr = tsdb->chunk_ptrs[ci];
        if (curr->start_timestamp > end_ts) break; /* sorted: no further overlaps */
        if (curr->series_id != series_id || curr->end_timestamp < start_ts ||
            !qihse_auth_can_access(user, curr->classification, curr->sci_compartment)) {
            continue;
        }
        bit_stream_t bs = { (uint8_t*)curr->compressed_lanes, 0, sizeof(curr->compressed_lanes) * 8 };
        uint64_t t_prev = curr->start_timestamp;
        int64_t d_prev = 0;
        uint64_t v_prev = 0;
        int prev_lz = 0;
        int prev_tz = 0;
        for (uint32_t i = 0; i < curr->count; i++) {
            uint64_t t;
            uint64_t v;
            if (i == 0) {
                t = t_prev;
                v = br_read(&bs, 64);
                v_prev = v;
            } else {
                int64_t dod = 0;
                if (br_read(&bs, 1) == 0) {
                    dod = 0;
                } else if (br_read(&bs, 1) == 0) {
                    dod = sign_extend(br_read(&bs, 7), 7);
                } else if (br_read(&bs, 1) == 0) {
                    dod = sign_extend(br_read(&bs, 9), 9);
                } else if (br_read(&bs, 1) == 0) {
                    dod = sign_extend(br_read(&bs, 12), 12);
                } else {
                    dod = sign_extend(br_read(&bs, 32), 32);
                }
                int64_t d = d_prev + dod;
                t = t_prev + d;
                t_prev = t;
                d_prev = d;
                if (br_read(&bs, 1) == 0) {
                    v = v_prev;
                } else if (br_read(&bs, 1) == 0) {
                    int len = 64 - prev_lz - prev_tz;
                    uint64_t xor_val = br_read(&bs, len);
                    v = v_prev ^ (xor_val << prev_tz);
                } else {
                    int lz = (int)br_read(&bs, 5);
                    int len = (int)br_read(&bs, 6) + 1;
                    uint64_t xor_val = br_read(&bs, len);
                    int tz = 64 - lz - len;
                    v = v_prev ^ (xor_val << tz);
                    prev_lz = lz;
                    prev_tz = tz;
                }
                v_prev = v;
            }
            if (t >= start_ts && t <= end_ts) {
                double decoded;
                memcpy(&decoded, &v, sizeof(decoded));
                qihse_tsdb_aggregate_value(decoded, aggregation, &aggregate, &count);
            }
        }
    }

    uint64_t tail = atomic_load_explicit(&tsdb->tail.index, memory_order_acquire);
    uint64_t head = atomic_load_explicit(&tsdb->head.index, memory_order_acquire);
    for (uint64_t i = tail; i < head; i++) {
        uint64_t idx = i % QIHSE_RING_SIZE;
        if (tsdb->cache[idx].series_id != series_id ||
            !qihse_auth_can_access(user, tsdb->cache[idx].classification, tsdb->cache[idx].sci_compartment)) continue;
        if (tsdb->cache[idx].timestamp >= start_ts && tsdb->cache[idx].timestamp <= end_ts) {
            qihse_tsdb_aggregate_value(tsdb->cache[idx].value, aggregation, &aggregate, &count);
        }
    }
    if (count == 0) {
        if (out_count) *out_count = 0;
        return false;
    }
    if (aggregation == QIHSE_TS_AGG_AVG) aggregate /= (double)count;
    *out_value = aggregate;
    if (out_count) *out_count = count;
    return true;
}

void qihse_tsdb_set_ttl(qihse_tsdb_t* tsdb, uint64_t ttl_ms) {
    if (tsdb) {
        tsdb->ttl_ms = ttl_ms;
    }
}

void qihse_tsdb_trim(qihse_tsdb_t* tsdb, uint64_t current_ts) {
    if (!tsdb || tsdb->ttl_ms == 0) return;
    
    uint64_t expiry_ts = (current_ts > tsdb->ttl_ms) ? (current_ts - tsdb->ttl_ms) : 0;
    
    qihse_tsdb_chunk_t* curr = tsdb->chunk_head;
    size_t trimmed_from_front = 0;
    
    while (curr) {
        if (curr->end_timestamp < expiry_ts) {
            qihse_tsdb_chunk_t* to_free = curr;
            curr = curr->next;
            
            if (tsdb->chunk_head == to_free) {
                tsdb->chunk_head = curr;
            }
            if (tsdb->chunk_tail == to_free) {
                tsdb->chunk_tail = NULL;
            }
            free(to_free);
            trimmed_from_front++;
        } else {
            break;
        }
    }

    /* Keep the keystone anchor chunk index consistent: drop the trimmed
     * entries from the front of the sorted start_timestamp array. */
    if (trimmed_from_front > 0 && trimmed_from_front <= tsdb->chunk_index_count) {
        size_t remaining = tsdb->chunk_index_count - trimmed_from_front;
        if (remaining > 0) {
            memmove(tsdb->chunk_starts,
                    tsdb->chunk_starts + trimmed_from_front,
                    remaining * sizeof(int64_t));
            memmove(tsdb->chunk_ptrs,
                    tsdb->chunk_ptrs + trimmed_from_front,
                    remaining * sizeof(qihse_tsdb_chunk_t*));
        }
        tsdb->chunk_index_count = remaining;
    }
}

size_t qihse_tsdb_lookup_chunk_index(qihse_tsdb_t* tsdb, uint64_t target_ts) {
    if (!tsdb || !tsdb->chunk_starts || tsdb->chunk_index_count == 0) return 0;
    return qihse_keystone_anchor_lower_bound(
        tsdb->chunk_starts, tsdb->chunk_index_count, (int64_t)target_ts);
}

size_t qihse_tsdb_chunk_index_size(qihse_tsdb_t* tsdb) {
    return tsdb ? tsdb->chunk_index_count : 0;
}
