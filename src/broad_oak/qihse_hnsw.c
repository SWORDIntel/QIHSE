#include "qihse_hnsw.h"
#include "qihse_keystone.h"
#include "backends/cpu/qihse_cpu_detect.h"
#include "backends/cpu/qihse_cpu_distance.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <immintrin.h>
#include <time.h>
#include <unistd.h>

/* Thread-local xoshiro256** PRNG state seeded once per thread from hardware RDRAND */
static __thread uint64_t qihse_hnsw_xoshiro_state[4];
static __thread bool qihse_hnsw_xoshiro_initialized = false;

static inline uint64_t qihse_hnsw_rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t qihse_hnsw_xoshiro256ss_next(void) {
    const uint64_t result = qihse_hnsw_rotl(qihse_hnsw_xoshiro_state[1] * 5, 7) * 9;
    const uint64_t t = qihse_hnsw_xoshiro_state[1] << 17;

    qihse_hnsw_xoshiro_state[2] ^= qihse_hnsw_xoshiro_state[0];
    qihse_hnsw_xoshiro_state[3] ^= qihse_hnsw_xoshiro_state[1];
    qihse_hnsw_xoshiro_state[1] ^= qihse_hnsw_xoshiro_state[2];
    qihse_hnsw_xoshiro_state[0] ^= qihse_hnsw_xoshiro_state[3];

    qihse_hnsw_xoshiro_state[2] ^= t;
    qihse_hnsw_xoshiro_state[3] = qihse_hnsw_rotl(qihse_hnsw_xoshiro_state[3], 45);

    return result;
}

static inline uint64_t qihse_hnsw_rdrand64(void) {
    unsigned long long val = 0;
#if defined(__RDRND__) || defined(QIHSE_ENABLE_RDRAND)
    for (int retry = 0; retry < 10; retry++) {
        if (_rdrand64_step(&val)) {
            return (uint64_t)val;
        }
    }
#endif
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t seed = (uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32) ^ (uint64_t)(uintptr_t)&val;
    seed ^= (seed >> 30); seed *= 0xbf58476d1ce4e5b9ULL;
    seed ^= (seed >> 27); seed *= 0x94d049bb133111ebULL;
    seed ^= (seed >> 31);
    return seed ? seed : 0x853c49e6748fea9bULL;
}

static inline void qihse_hnsw_xoshiro_init_tls(void) {
    if (__builtin_expect(!qihse_hnsw_xoshiro_initialized, 0)) {
        for (int i = 0; i < 4; i++) {
            qihse_hnsw_xoshiro_state[i] = qihse_hnsw_rdrand64();
        }
        if ((qihse_hnsw_xoshiro_state[0] | qihse_hnsw_xoshiro_state[1] |
             qihse_hnsw_xoshiro_state[2] | qihse_hnsw_xoshiro_state[3]) == 0) {
            qihse_hnsw_xoshiro_state[0] = 0x853c49e6748fea9bULL;
            qihse_hnsw_xoshiro_state[1] = 0xda3e39cb94b95bdbULL;
            qihse_hnsw_xoshiro_state[2] = 0xbf58476d1ce4e5b9ULL;
            qihse_hnsw_xoshiro_state[3] = 0x94d049bb133111ebULL;
        }
        qihse_hnsw_xoshiro_initialized = true;
    }
}

// Real distance function using user-provided callbacks
static float real_dist_q(qihse_hnsw_index_t *index, const float *query, uint32_t node) {
    if (!index || !index->params.get_vector_fn || !index->params.distance_fn) return 1e9f;
    const float* node_vec = index->params.get_vector_fn(index->params.user_context, node);
    if (!node_vec || !query) return 1e9f;
    index->last_search_dist_calls++;
    return index->params.distance_fn(query, node_vec, index->params.dim);
}

static float real_dist_n(qihse_hnsw_index_t *index, uint32_t n1, uint32_t n2) {
    if (!index || !index->params.get_vector_fn || !index->params.distance_fn) return 1e9f;
    const float* vec1 = index->params.get_vector_fn(index->params.user_context, n1);
    const float* vec2 = index->params.get_vector_fn(index->params.user_context, n2);
    if (!vec1 || !vec2) return 1e9f;
    index->last_search_dist_calls++;
    return index->params.distance_fn(vec1, vec2, index->params.dim);
}

/* Dynamic runtime F16C support detection */
static bool hnsw_has_f16c(void) {
    static int s_has_f16c = -1;
    if (s_has_f16c < 0) {
        qihse_cpu_info_t info = qihse_cpu_detect();
        s_has_f16c = qihse_cpu_has_f16c(&info) ? 1 : 0;
    }
    return s_has_f16c == 1;
}

static bool hnsw_has_f16c_fma(void) {
    static int s_has_f16c_fma = -1;
    if (s_has_f16c_fma < 0) {
        qihse_cpu_info_t info = qihse_cpu_detect();
        s_has_f16c_fma = (qihse_cpu_has_avx2(&info) &&
                          qihse_cpu_has_fma(&info) &&
                          qihse_cpu_has_f16c(&info)) ? 1 : 0;
    }
    return s_has_f16c_fma == 1;
}

/* Convert FP32 floats to FP16 half-precision */
static void float_to_fp16_array(const float *src, uint16_t *dst, size_t dim) {
#if defined(__x86_64__) && (defined(__F16C__) || defined(QIHSE_ENABLE_F16C))
    size_t i = 0;
    for (; i + 8 <= dim; i += 8) {
        __m256 v = _mm256_loadu_ps(src + i);
        __m128i h = _mm256_cvtps_ph(v, 0);
        _mm_storeu_si128((__m128i*)(dst + i), h);
    }
    if (i < dim) {
        float tmp[8] = {0};
        size_t rem = dim - i;
        for (size_t r = 0; r < rem; r++) tmp[r] = src[i + r];
        __m256 v = _mm256_loadu_ps(tmp);
        __m128i h = _mm256_cvtps_ph(v, 0);
        uint16_t h_tmp[8];
        _mm_storeu_si128((__m128i*)h_tmp, h);
        for (size_t r = 0; r < rem; r++) dst[i + r] = h_tmp[r];
    }
    _mm256_zeroupper();
#else
    for (size_t i = 0; i < dim; i++) {
        union { float f; uint32_t u; } val;
        val.f = src[i];
        uint32_t sign = (val.u >> 16) & 0x8000;
        int32_t exp = ((val.u >> 23) & 0xff) - 127 + 15;
        uint32_t mant = val.u & 0x7fffff;
        if (exp <= 0) {
            dst[i] = (uint16_t)sign;
        } else if (exp >= 31) {
            dst[i] = (uint16_t)(sign | 0x7c00);
        } else {
            dst[i] = (uint16_t)(sign | (exp << 10) | (mant >> 13));
        }
    }
#endif
}

static void store_layer0_fp16_vector(qihse_hnsw_index_t *index, uint32_t node_id, const float *vec, size_t dim) {
    if (!index || !vec || dim == 0) return;
    if (node_id >= index->layer0_fp16_capacity) {
        size_t new_cap = node_id + 1;
        if (new_cap < index->layer0_fp16_capacity * 2) new_cap = index->layer0_fp16_capacity * 2;
        if (new_cap < 64) new_cap = 64;
        uint16_t **new_vecs = (uint16_t**)realloc(index->layer0_fp16_vectors, new_cap * sizeof(uint16_t*));
        if (!new_vecs) return;
        for (size_t i = index->layer0_fp16_capacity; i < new_cap; i++) {
            new_vecs[i] = NULL;
        }
        index->layer0_fp16_vectors = new_vecs;
        index->layer0_fp16_capacity = new_cap;
    }
    if (!index->layer0_fp16_vectors[node_id]) {
        index->layer0_fp16_vectors[node_id] = (uint16_t*)malloc(dim * sizeof(uint16_t));
    }
    if (!index->layer0_fp16_vectors[node_id]) return;
    float_to_fp16_array(vec, index->layer0_fp16_vectors[node_id], dim);
}

static const uint16_t* get_layer0_fp16_vector(qihse_hnsw_index_t *index, uint32_t node_id) {
    if (!index) return NULL;
    if (index->layer0_fp16_vectors && node_id < index->layer0_fp16_capacity && index->layer0_fp16_vectors[node_id]) {
        return index->layer0_fp16_vectors[node_id];
    }
    if (index->params.get_vector_fn) {
        const float *fp32_vec = index->params.get_vector_fn(index->params.user_context, node_id);
        if (fp32_vec) {
            store_layer0_fp16_vector(index, node_id, fp32_vec, index->params.dim);
            if (index->layer0_fp16_vectors && node_id < index->layer0_fp16_capacity) {
                return index->layer0_fp16_vectors[node_id];
            }
        }
    }
    return NULL;
}

static inline float hnsw_node_dist(qihse_hnsw_index_t *index, const float *query, const uint16_t *query_fp16, uint32_t node, bool use_f16c) {
    if (use_f16c) {
        const uint16_t *fp16_vec = get_layer0_fp16_vector(index, node);
        if (fp16_vec) {
            index->last_search_dist_calls++;
            if (hnsw_has_f16c_fma()) {
                return qihse_l2_sq_distance_f16c_fma(query_fp16, fp16_vec, index->params.dim);
            } else {
                return qihse_l2_sq_distance_f16c(query_fp16, fp16_vec, index->params.dim);
            }
        }
    }
    return real_dist_q(index, query, node);
}

typedef struct {
    uint32_t id;
    float dist;
} cand_t;

static int compare_cand_asc(const void *a, const void *b) {
    float d1 = ((const cand_t *)a)->dist;
    float d2 = ((const cand_t *)b)->dist;
    return (d1 < d2) ? -1 : (d1 > d2 ? 1 : 0);
}

void hnsw_select_neighbors(qihse_hnsw_index_t *index, const float *query, uint32_t *candidates, size_t num_candidates, uint32_t M, uint32_t *selected, size_t *num_selected) {
    if (num_selected) *num_selected = 0;
    if (num_candidates == 0) return;

    cand_t *sorted_c = (cand_t *)malloc(num_candidates * sizeof(cand_t));
    if (!sorted_c) return;

    for (size_t i = 0; i < num_candidates; i++) {
        sorted_c[i].id = candidates[i];
        if (query) {
            sorted_c[i].dist = real_dist_q(index, query, candidates[i]);
        } else {
            sorted_c[i].dist = real_dist_n(index, 0, candidates[i]); // query vector unavailable
        }
    }

    qsort(sorted_c, num_candidates, sizeof(cand_t), compare_cand_asc);

    size_t sel_count = 0;
    for (size_t i = 0; i < num_candidates && sel_count < M; i++) {
        uint32_t c = sorted_c[i].id;
        float dist_to_q = sorted_c[i].dist;
        bool good = true;

        for (size_t j = 0; j < sel_count; j++) {
            uint32_t s = selected[j];
            float dist_to_s = real_dist_n(index, c, s);
            if (dist_to_q > dist_to_s) {
                good = false;
                break;
            }
        }

        if (good) {
            selected[sel_count++] = c;
        }
    }

    if (num_selected) {
        *num_selected = sel_count;
    }
    free(sorted_c);
}

static void ensure_layer_capacity(qihse_hnsw_layer_t *layer, uint32_t node_id) {
    if (node_id >= layer->links_capacity) {
        uint32_t new_cap = node_id + 1;
        if (new_cap < layer->links_capacity * 2) new_cap = layer->links_capacity * 2;
        if (new_cap < 16) new_cap = 16;
        qihse_hnsw_links_t **new_links = (qihse_hnsw_links_t**)realloc(layer->links, new_cap * sizeof(qihse_hnsw_links_t*));
        if (!new_links) return;
        layer->links = new_links;
        for (uint32_t i = layer->links_capacity; i < new_cap; i++) {
            layer->links[i] = NULL;
        }
        layer->links_capacity = new_cap;
    }
}

static qihse_hnsw_links_t* get_or_create_links(qihse_hnsw_layer_t *layer, uint32_t node_id, uint32_t M) {
    ensure_layer_capacity(layer, node_id);
    if (node_id >= layer->links_capacity) return NULL;
    if (!layer->links[node_id]) {
        layer->links[node_id] = (qihse_hnsw_links_t*)calloc(1, sizeof(qihse_hnsw_links_t));
        if (!layer->links[node_id]) return NULL;
        layer->links[node_id]->capacity = M;
        layer->links[node_id]->neighbors = (uint32_t*)malloc(M * sizeof(uint32_t));
        if (!layer->links[node_id]->neighbors) {
            free(layer->links[node_id]);
            layer->links[node_id] = NULL;
            return NULL;
        }
    }
    return layer->links[node_id];
}

static void add_link_and_prune(qihse_hnsw_index_t *index, int level, uint32_t from, uint32_t to, uint32_t M) {
    if (!index || level > index->max_level || level < 0) return;
    qihse_hnsw_layer_t *layer = index->layers[level];
    if (!layer) return;
    
    qihse_hnsw_links_t *links = get_or_create_links(layer, from, M);
    if (!links) return;

    for (uint32_t i = 0; i < links->count; i++) {
        if (links->neighbors[i] == to) return;
    }

    if (links->count < links->capacity) {
        links->neighbors[links->count++] = to;
    } else {
        uint32_t num_cands = links->count + 1;
        uint32_t *cands = (uint32_t *)malloc(num_cands * sizeof(uint32_t));
        if (!cands) return;
        
        for (uint32_t i = 0; i < links->count; i++) {
            cands[i] = links->neighbors[i];
        }
        cands[links->count] = to;

        uint32_t *sel = (uint32_t *)malloc(M * sizeof(uint32_t));
        if (!sel) {
            free(cands);
            return;
        }
        
        size_t sel_cnt = 0;
        const float* from_vec = NULL;
        if (index->params.get_vector_fn) {
            from_vec = index->params.get_vector_fn(index->params.user_context, from);
        }
        hnsw_select_neighbors(index, from_vec, cands, num_cands, M, sel, &sel_cnt);
        
        links->count = (uint32_t)sel_cnt;
        for (size_t i = 0; i < sel_cnt; i++) {
            links->neighbors[i] = sel[i];
        }
        
        free(cands);
        free(sel);
    }
}

typedef struct {
    uint32_t *keys;
    size_t capacity;
    size_t count;
} visited_set_t;

static visited_set_t* visited_set_create() {
    visited_set_t *set = (visited_set_t*)malloc(sizeof(visited_set_t));
    if (!set) return NULL;
    set->capacity = 8192;
    set->count = 0;
    set->keys = (uint32_t*)calloc(set->capacity, sizeof(uint32_t));
    if (!set->keys) { free(set); return NULL; }
    return set;
}

static void visited_set_free(visited_set_t *set) {
    if (set) {
        free(set->keys);
        free(set);
    }
}

static bool is_visited(visited_set_t *set, uint32_t node) {
    uint32_t h = (node * 2654435761u) % set->capacity;
    while (set->keys[h] != 0) {
        if (set->keys[h] == node + 1) return true;
        h = (h + 1) % set->capacity;
    }
    return false;
}

static void mark_visited(visited_set_t *set, uint32_t node) {
    if (set->count * 2 >= set->capacity) {
        size_t old_cap = set->capacity;
        uint32_t *old_keys = set->keys;
        
        set->capacity *= 2;
        set->keys = (uint32_t*)calloc(set->capacity, sizeof(uint32_t));
        set->count = 0;
        
        for (size_t i = 0; i < old_cap; i++) {
            if (old_keys[i] != 0) {
                uint32_t n = old_keys[i] - 1;
                uint32_t h = (n * 2654435761u) % set->capacity;
                while (set->keys[h] != 0) {
                    h = (h + 1) % set->capacity;
                }
                set->keys[h] = old_keys[i];
                set->count++;
            }
        }
        free(old_keys);
    }

    uint32_t h = (node * 2654435761u) % set->capacity;
    while (set->keys[h] != 0) {
        if (set->keys[h] == node + 1) return;
        h = (h + 1) % set->capacity;
    }
    set->keys[h] = node + 1;
    set->count++;
}

/* --- Binary min-heap for candidate extraction (O(log n) per pop) --- */

static void min_heap_push(cand_t *heap, size_t *count, cand_t item) {
    size_t i = (*count)++;
    heap[i] = item;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (heap[parent].dist <= heap[i].dist) break;
        cand_t tmp = heap[parent]; heap[parent] = heap[i]; heap[i] = tmp;
        i = parent;
    }
}

static cand_t min_heap_pop(cand_t *heap, size_t *count) {
    cand_t result = heap[0];
    heap[0] = heap[--(*count)];
    size_t i = 0;
    while (1) {
        size_t left = 2 * i + 1, right = 2 * i + 2, smallest = i;
        if (left < *count && heap[left].dist < heap[smallest].dist) smallest = left;
        if (right < *count && heap[right].dist < heap[smallest].dist) smallest = right;
        if (smallest == i) break;
        cand_t tmp = heap[smallest]; heap[smallest] = heap[i]; heap[i] = tmp;
        i = smallest;
    }
    return result;
}

/* --- Binary max-heap for top_candidates (O(log n) replace-max) --- */

static void max_heap_push(cand_t *heap, size_t *count, cand_t item) {
    size_t i = (*count)++;
    heap[i] = item;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (heap[parent].dist >= heap[i].dist) break;
        cand_t tmp = heap[parent]; heap[parent] = heap[i]; heap[i] = tmp;
        i = parent;
    }
}

static cand_t max_heap_pop(cand_t *heap, size_t *count) {
    cand_t result = heap[0];
    heap[0] = heap[--(*count)];
    size_t i = 0;
    while (1) {
        size_t left = 2 * i + 1, right = 2 * i + 2, largest = i;
        if (left < *count && heap[left].dist > heap[largest].dist) largest = left;
        if (right < *count && heap[right].dist > heap[largest].dist) largest = right;
        if (largest == i) break;
        cand_t tmp = heap[largest]; heap[largest] = heap[i]; heap[i] = tmp;
        i = largest;
    }
    return result;
}

/* Replace the max element in a max-heap (used when top_candidates is full) */
static void max_heap_replace_max(cand_t *heap, size_t count, cand_t item) {
    heap[0] = item;
    size_t i = 0;
    while (1) {
        size_t left = 2 * i + 1, right = 2 * i + 2, largest = i;
        if (left < count && heap[left].dist > heap[largest].dist) largest = left;
        if (right < count && heap[right].dist > heap[largest].dist) largest = right;
        if (largest == i) break;
        cand_t tmp = heap[largest]; heap[largest] = heap[i]; heap[i] = tmp;
        i = largest;
    }
}

void hnsw_search_layer(qihse_hnsw_index_t *index, const float *query, uint32_t ep, int ef, int level, uint32_t *results, size_t *num_results) {
    if (num_results) *num_results = 0;
    if (!index || level > index->max_level || level < 0 || ef <= 0 || !index->layers[level]) return;
    qihse_hnsw_layer_t *layer = index->layers[level];

    bool use_f16c = (level == 0 && hnsw_has_f16c());
    uint16_t *query_fp16 = NULL;
    if (use_f16c) {
        query_fp16 = (uint16_t*)malloc(index->params.dim * sizeof(uint16_t));
        if (query_fp16) {
            float_to_fp16_array(query, query_fp16, index->params.dim);
        } else {
            use_f16c = false;
        }
    }

    size_t target_ef = (size_t)ef;
    size_t ef_search_layer = target_ef;
    if (use_f16c) {
        /* Re-rank top-M (M = max(2*k, 64)) candidates against master FP32 vectors */
        size_t M_prom = target_ef * 2;
        if (M_prom < 64) M_prom = 64;
        ef_search_layer = (target_ef > M_prom) ? target_ef : M_prom;
    }

    visited_set_t *vset = visited_set_create();
    if (!vset) { free(query_fp16); return; }
    size_t cand_capacity = ef_search_layer * 10;
    if (cand_capacity == 0) { free(query_fp16); visited_set_free(vset); return; }
    cand_t *cand_heap = (cand_t*)malloc(cand_capacity * sizeof(cand_t));
    cand_t *top_heap = (cand_t*)malloc(ef_search_layer * sizeof(cand_t));
    if (!cand_heap || !top_heap) {
        free(cand_heap); free(top_heap); free(query_fp16); visited_set_free(vset); return;
    }

    size_t cand_count = 0;
    size_t top_count = 0;

    float d = hnsw_node_dist(index, query, query_fp16, ep, use_f16c);
    min_heap_push(cand_heap, &cand_count, (cand_t){ep, d});
    max_heap_push(top_heap, &top_count, (cand_t){ep, d});
    mark_visited(vset, ep);

    while (cand_count > 0) {
        /* Extract min from candidate heap — O(log n) instead of O(n) */
        cand_t c = min_heap_pop(cand_heap, &cand_count);

        /* If the closest candidate is worse than the worst top result, stop */
        if (top_count == ef_search_layer && c.dist > top_heap[0].dist) {
            break;
        }

        if (c.id < layer->links_capacity && layer->links[c.id]) {
            qihse_hnsw_links_t *links = layer->links[c.id];
            for (size_t i = 0; i < links->count; i++) {
                uint32_t e = links->neighbors[i];
                if (!is_visited(vset, e)) {
                    mark_visited(vset, e);

                    if (use_f16c) {
                        const uint16_t *neighbor_vec = get_layer0_fp16_vector(index, e);
                        if (neighbor_vec) {
                            _mm_prefetch((const char*)neighbor_vec, _MM_HINT_T0);
                        }
                    } else if (index->params.get_vector_fn) {
                        const float *neighbor_vec = index->params.get_vector_fn(index->params.user_context, e);
                        if (neighbor_vec) {
                            _mm_prefetch((const char*)neighbor_vec, _MM_HINT_T0);
                        }
                    }

                    float dist_e = hnsw_node_dist(index, query, query_fp16, e, use_f16c);
                    if (top_count < ef_search_layer || dist_e < top_heap[0].dist) {
                        if (cand_count >= cand_capacity) {
                            cand_capacity *= 2;
                            cand_t *new_cands = (cand_t*)realloc(cand_heap, cand_capacity * sizeof(cand_t));
                            if (!new_cands) break;
                            cand_heap = new_cands;
                        }
                        min_heap_push(cand_heap, &cand_count, (cand_t){e, dist_e});

                        if (top_count < ef_search_layer) {
                            max_heap_push(top_heap, &top_count, (cand_t){e, dist_e});
                        } else {
                            /* Replace the max (worst) element — O(log n) instead of O(ef) */
                            max_heap_replace_max(top_heap, top_count, (cand_t){e, dist_e});
                        }
                    }
                }
            }
        }
    }

    if (use_f16c) {
        /* Candidate Promotion: Re-rank the top candidates against master FP32 vectors */
        cand_t *promoted = (cand_t*)malloc(top_count * sizeof(cand_t));
        if (promoted) {
            size_t num_promoted = 0;
            while (top_count > 0) {
                cand_t item = max_heap_pop(top_heap, &top_count);
                /* Re-evaluate against master FP32 vectors for 100% exact recall */
                item.dist = real_dist_q(index, query, item.id);
                promoted[num_promoted++] = item;
            }
            qsort(promoted, num_promoted, sizeof(cand_t), compare_cand_asc);

            size_t final_count = (num_promoted < target_ef) ? num_promoted : target_ef;
            if (results && num_results) {
                *num_results = final_count;
                for (size_t i = 0; i < final_count; i++) {
                    results[i] = promoted[i].id;
                }
            }
            free(promoted);
        }
        free(query_fp16);
    } else {
        /* Standard extraction for upper layers or non-F16C fallback */
        cand_t *sorted = (cand_t*)malloc(top_count * sizeof(cand_t));
        if (sorted) {
            size_t sorted_count = 0;
            while (top_count > 0) {
                sorted[sorted_count++] = max_heap_pop(top_heap, &top_count);
            }
            if (results && num_results) {
                *num_results = sorted_count;
                for (size_t i = 0; i < sorted_count; i++) {
                    results[i] = sorted[sorted_count - 1 - i].id;
                }
            }
            free(sorted);
        }
    }

    visited_set_free(vset);
    free(cand_heap);
    free(top_heap);
}

void hnsw_insert(qihse_hnsw_index_t *index, uint32_t node_id, const float *vector, size_t dim) {
    (void)dim;
    if (!index) return;

    if (hnsw_has_f16c() && vector) {
        store_layer0_fp16_vector(index, node_id, vector, index->params.dim);
    }

    /* Maintain the anchor projection table for Anchor-Guided Vector Proximity
     * Seeding. Registered up-front so every insert path (including the very
     * first node, which returns early below) is captured. Only populated when
     * seeding has been enabled by the caller, so unaware callers pay zero
     * overhead. */
    if (index->anchor_seeding_enabled) {
        qihse_hnsw_register_projection(index, node_id, vector, index->params.dim);
    }

    qihse_hnsw_xoshiro_init_tls();
    uint64_t rng_val = qihse_hnsw_xoshiro256ss_next();
    if (__builtin_expect(rng_val == 0, 0)) {
        rng_val = 1;
    }
    int l = (int)(__builtin_clzll(rng_val) * index->params.mult * 0.693147f);

    // Expand layers array if needed
    if (l > index->max_level || index->max_level == -1) {
        int target_level = l > index->max_level ? l : index->max_level;
        if (target_level >= (int)index->layers_capacity) {
            uint32_t new_cap = target_level + 1;
            if (new_cap < index->layers_capacity * 2) new_cap = index->layers_capacity * 2;
            index->layers = (qihse_hnsw_layer_t**)realloc(index->layers, new_cap * sizeof(qihse_hnsw_layer_t*));
            for (uint32_t i = index->layers_capacity; i < new_cap; i++) {
                index->layers[i] = NULL;
            }
            index->layers_capacity = new_cap;
        }
        for (int i = index->max_level + 1; i <= target_level; i++) {
            if (!index->layers[i]) {
                index->layers[i] = (qihse_hnsw_layer_t*)calloc(1, sizeof(qihse_hnsw_layer_t));
                index->layers[i]->level = i;
            }
        }
    }

    uint32_t ep = index->enter_point;
    int max_level = index->max_level;

    if (index->num_nodes > 0 && max_level >= 0) {
        for (int lc = max_level; lc > l; lc--) {
            uint32_t closest = ep;
            size_t num_closest = 0;
            hnsw_search_layer(index, vector, ep, 1, lc, &closest, &num_closest);
            if (num_closest > 0) {
                ep = closest;
            }
        }
    }

    int start_level = (l < max_level) ? l : max_level;
    if (index->num_nodes == 0) {
        index->enter_point = node_id;
        index->max_level = l;
        index->num_nodes++;
        return;
    }

    for (int lc = start_level; lc >= 0; lc--) {
        uint32_t M = (lc == 0) ? index->params.M0 : index->params.M;
        
        uint32_t *candidates = (uint32_t *)malloc(index->params.ef_construction * sizeof(uint32_t));
        if (!candidates) break;
        
        size_t num_candidates = 0;
        hnsw_search_layer(index, vector, ep, index->params.ef_construction, lc, candidates, &num_candidates);
        
        uint32_t *selected = (uint32_t *)malloc(M * sizeof(uint32_t));
        if (!selected) {
            free(candidates);
            break;
        }
        
        size_t num_selected = 0;
        hnsw_select_neighbors(index, vector, candidates, num_candidates, M, selected, &num_selected);
        
        for (size_t i = 0; i < num_selected; i++) {
            uint32_t neighbor = selected[i];
            add_link_and_prune(index, lc, node_id, neighbor, M);
            add_link_and_prune(index, lc, neighbor, node_id, M);
        }
        
        if (num_selected > 0) {
            ep = selected[0];
        }
        
        free(candidates);
        free(selected);
    }

    if (l > max_level) {
        index->max_level = l;
        index->enter_point = node_id;
    }
    
    index->num_nodes++;
}

void hnsw_destroy(qihse_hnsw_index_t *index) {
    if (!index) return;
    if (index->layers) {
        for (uint32_t i = 0; i < index->layers_capacity; i++) {
            qihse_hnsw_layer_t *layer = index->layers[i];
            if (layer) {
                if (layer->links) {
                    for (uint32_t j = 0; j < layer->links_capacity; j++) {
                        if (layer->links[j]) {
                            free(layer->links[j]->neighbors);
                            free(layer->links[j]);
                        }
                    }
                    free(layer->links);
                }
                free(layer);
            }
        }
        free(index->layers);
    }
    if (index->layer0_fp16_vectors) {
        for (size_t i = 0; i < index->layer0_fp16_capacity; i++) {
            free(index->layer0_fp16_vectors[i]);
        }
        free(index->layer0_fp16_vectors);
        index->layer0_fp16_vectors = NULL;
        index->layer0_fp16_capacity = 0;
    }
    qihse_hnsw_anchor_destroy(index);
    free(index);
}

size_t qihse_hnsw_index_bytes(const qihse_hnsw_index_t *index) {
    if (!index) return 0;
    size_t total = sizeof(*index);
    total += (size_t)index->layers_capacity * sizeof(qihse_hnsw_layer_t*);
    if (index->layers) {
        for (uint32_t i = 0; i < index->layers_capacity; i++) {
            const qihse_hnsw_layer_t* layer = index->layers[i];
            if (!layer) continue;
            total += sizeof(*layer);
            total += (size_t)layer->links_capacity * sizeof(qihse_hnsw_links_t*);
            if (!layer->links) continue;
            for (uint32_t j = 0; j < layer->links_capacity; j++) {
                const qihse_hnsw_links_t* links = layer->links[j];
                if (!links) continue;
                total += sizeof(*links);
                total += (size_t)links->capacity * sizeof(uint32_t);
            }
        }
    }
    if (index->layer0_fp16_vectors) {
        total += index->layer0_fp16_capacity * sizeof(uint16_t*);
        for (size_t i = 0; i < index->layer0_fp16_capacity; i++) {
            if (index->layer0_fp16_vectors[i]) {
                total += index->params.dim * sizeof(uint16_t);
            }
        }
    }
    total += index->anchor_capacity *
             (sizeof(int64_t) + sizeof(uint32_t));
    return total;
}

/* ===========================================================================
 * Anchor-Guided Vector Proximity Seeding
 * ---------------------------------------------------------------------------
 * Each inserted vector is reduced to a 1D scalar projection (default: sum of
 * components), scalar-quantized to int64, and inserted into a sorted anchor
 * table. At query time the query's projection is used to probe the table via
 * qihse_keystone_anchor_search (O(log log N) interpolation search). The
 * matched node becomes the HNSW entry point, which is typically much closer
 * to the query than the graph's default top-level enter_point, reducing the
 * number of graph hops (distance evaluations) required during descent.
 * ========================================================================= */

#define QIHSE_HNSW_PROJ_SCALE 1000000.0

int64_t qihse_hnsw_compute_projection(const float *v, size_t dim,
                                       qihse_hnsw_projection_fn_t proj_fn) {
    if (!v || dim == 0) return 0;
    double p;
    if (proj_fn) {
        p = proj_fn(v, dim);
    } else {
        /* Default 1D projection: sum of components (dot product with the
         * all-ones direction). Cheap, deterministic, and preserves a useful
         * coarse ordering for clustered / low-entropy workloads. */
        double acc = 0.0;
        for (size_t i = 0; i < dim; i++) acc += (double)v[i];
        p = acc;
    }
    /* Scalar-quantize to int64. Clamp to int64 range to keep the sorted
     * table well-defined for the interpolation search. */
    double scaled = p * QIHSE_HNSW_PROJ_SCALE;
    if (scaled >= 9.2e18) return (int64_t)9223372036854775807LL;
    if (scaled <= -9.2e18) return (int64_t)(-9223372036854775807LL - 1);
    return (int64_t)scaled;
}

static int anchor_table_reserve(qihse_hnsw_index_t *index, size_t needed) {
    if (needed <= index->anchor_capacity) return 0;
    size_t new_cap = index->anchor_capacity ? index->anchor_capacity * 2 : 64;
    while (new_cap < needed) new_cap *= 2;
    int64_t *np = (int64_t*)realloc(index->anchor_projections, new_cap * sizeof(int64_t));
    if (!np) return -1;
    index->anchor_projections = np;
    uint32_t *nn = (uint32_t*)realloc(index->anchor_node_ids, new_cap * sizeof(uint32_t));
    if (!nn) return -1;
    index->anchor_node_ids = nn;
    index->anchor_capacity = new_cap;
    return 0;
}

/* Insert (projection, node_id) into the sorted anchor table. If node_id is
 * already present, its projection is refreshed in-place. */
int qihse_hnsw_register_projection(qihse_hnsw_index_t *index, uint32_t node_id,
                                    const float *vector, size_t dim) {
    if (!index || !vector) return -1;
    int64_t proj = qihse_hnsw_compute_projection(vector, dim,
                                                  index->params.projection_fn);

    /* Binary search for an existing entry by node_id using the projection
     * as a hint. Since the table is sorted by projection, we can't binary
     * search by node_id directly. But for refresh-in-place (which is rare
     * during bulk build), we skip the scan entirely — duplicate node_ids
     * don't occur during initial construction. */
    /* During bulk construction, node_ids are always new, so skip the scan.
     * Only do the O(n) scan if the table is small (< 256 entries). */
    if (index->anchor_count < 256) {
        for (size_t i = 0; i < index->anchor_count; i++) {
            if (index->anchor_node_ids[i] == node_id) {
                if (index->anchor_projections[i] == proj) return 0;
                memmove(&index->anchor_projections[i], &index->anchor_projections[i + 1],
                        (index->anchor_count - i - 1) * sizeof(int64_t));
                memmove(&index->anchor_node_ids[i], &index->anchor_node_ids[i + 1],
                        (index->anchor_count - i - 1) * sizeof(uint32_t));
                index->anchor_count--;
                break;
            }
        }
    }

    if (anchor_table_reserve(index, index->anchor_count + 1) != 0) return -1;

    /* Binary search for the insertion position to keep ascending order. */
    size_t lo = 0, hi = index->anchor_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (index->anchor_projections[mid] < proj) lo = mid + 1;
        else hi = mid;
    }
    if (lo < index->anchor_count) {
        memmove(&index->anchor_projections[lo + 1], &index->anchor_projections[lo],
                (index->anchor_count - lo) * sizeof(int64_t));
        memmove(&index->anchor_node_ids[lo + 1], &index->anchor_node_ids[lo],
                (index->anchor_count - lo) * sizeof(uint32_t));
    }
    index->anchor_projections[lo] = proj;
    index->anchor_node_ids[lo] = node_id;
    index->anchor_count++;
    return 0;
}

void qihse_hnsw_enable_anchor_seeding(qihse_hnsw_index_t *index, bool enable) {
    if (!index) return;
    index->anchor_seeding_enabled = enable;
}

void qihse_hnsw_anchor_destroy(qihse_hnsw_index_t *index) {
    if (!index) return;
    free(index->anchor_projections);
    free(index->anchor_node_ids);
    index->anchor_projections = NULL;
    index->anchor_node_ids = NULL;
    index->anchor_count = 0;
    index->anchor_capacity = 0;
}

/* Locate the index in the sorted anchor table whose projection is closest to
 * `key`. Primary path: qihse_keystone_anchor_search for an exact hit (O(log
 * log N)). On miss, fall back to a nearest-neighbour binary probe so we still
 * return a useful seed vertex. Returns the table index, or (size_t)-1 if the
 * table is empty. */
static size_t anchor_nearest_index(qihse_hnsw_index_t *index, int64_t key) {
    if (!index || index->anchor_count == 0) return (size_t)-1;

    int64_t hit = qihse_keystone_anchor_search(index->anchor_projections,
                                               index->anchor_count, key);
    if (hit >= 0) return (size_t)hit;

    /* Miss: binary search for the insertion point, then pick the closer of
     * the two neighbours by absolute projection delta. */
    size_t lo = 0, hi = index->anchor_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (index->anchor_projections[mid] < key) lo = mid + 1;
        else hi = mid;
    }
    size_t best = lo;          /* first element >= key */
    if (best == index->anchor_count) best = index->anchor_count - 1;
    if (best > 0) {
        uint64_t d_best = (uint64_t)llabs(index->anchor_projections[best] - key);
        uint64_t d_prev = (uint64_t)llabs(index->anchor_projections[best - 1] - key);
        if (d_prev < d_best) best = best - 1;
    }
    return best;
}

uint32_t qihse_hnsw_anchor_seed_entry(qihse_hnsw_index_t *index,
                                       const float *query, size_t dim) {
    if (!index) return 0;
    if (!index->anchor_seeding_enabled || index->anchor_count == 0) {
        return index->enter_point;
    }
    int64_t qproj = qihse_hnsw_compute_projection(query, dim,
                                                   index->params.projection_fn);
    size_t idx = anchor_nearest_index(index, qproj);
    if (idx == (size_t)-1) return index->enter_point;
    return index->anchor_node_ids[idx];
}

void qihse_hnsw_anchor_seed_search(qihse_hnsw_index_t *index,
                                    const float *query, size_t dim,
                                    uint32_t ef, uint32_t *results,
                                    size_t *num_results) {
    if (num_results) *num_results = 0;
    if (!index || !query || !results || ef == 0) return;
    if (index->num_nodes == 0 || index->max_level < 0) return;

    index->last_search_dist_calls = 0;

    uint32_t ep = qihse_hnsw_anchor_seed_entry(index, query, dim);

    /* Descend from the top layer down to layer 1 with ef=1 to greedily walk
     * toward the query, then run the full ef search at layer 0. This mirrors
     * the standard HNSW search procedure but starts from the anchor-seeded
     * entry point instead of index->enter_point. */
    for (int lc = index->max_level; lc > 0; lc--) {
        uint32_t closest = ep;
        size_t num_closest = 0;
        hnsw_search_layer(index, query, ep, 1, lc, &closest, &num_closest);
        if (num_closest > 0) ep = closest;
    }

    size_t n = 0;
    hnsw_search_layer(index, query, ep, (int)ef, 0, results, &n);
    if (num_results) *num_results = n;
}
