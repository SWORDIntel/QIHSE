#define _POSIX_C_SOURCE 200112L
#include "qihse_column.h"
#include "qihse_keystone.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <malloc.h>
#endif

typedef struct qihse_column_node {
    char* name;
    qihse_column_type_t type;
    qihse_column_chunk_t* head;
    qihse_column_chunk_t* tail;
    
    char** dict_strings;
    uint32_t dict_count;
    uint32_t dict_capacity;

    /* Keystone anchor-search index for INT64 columns.
     * Materialized by qihse_column_build_int64_index. `idx_values` is a
     * contiguous sorted int64 array consumed by qihse_keystone_anchor_*;
     * `idx_chunks` / `idx_slots` map a sorted position back to the original
     * (chunk, slot) row coordinate so per-row ACL metadata can be recovered. */
    int64_t* idx_values;
    qihse_column_chunk_t** idx_chunks;
    uint32_t* idx_slots;
    size_t idx_count;

    struct qihse_column_node* next;
} qihse_column_node_t;

struct qihse_column_store {
    qihse_column_node_t* columns;
};

qihse_column_store_t* qihse_column_store_create() {
    qihse_column_store_t* store = (qihse_column_store_t*)calloc(1, sizeof(qihse_column_store_t));
    return store;
}

void qihse_column_store_destroy(qihse_column_store_t* store) {
    if (!store) return;
    qihse_column_node_t* curr_col = store->columns;
    while (curr_col) {
        qihse_column_node_t* next_col = curr_col->next;
        free(curr_col->name);
        
        if (curr_col->dict_strings) {
            for (uint32_t i = 0; i < curr_col->dict_count; i++) {
                free(curr_col->dict_strings[i]);
            }
            free(curr_col->dict_strings);
        }

        free(curr_col->idx_values);
        free(curr_col->idx_chunks);
        free(curr_col->idx_slots);

        qihse_column_chunk_t* curr_chunk = curr_col->head;
        while (curr_chunk) {
            qihse_column_chunk_t* next_chunk = curr_chunk->next;
            free(curr_chunk->sci_compartments);
            free(curr_chunk->classifications);
            free(curr_chunk->data);
            free(curr_chunk);
            curr_chunk = next_chunk;
        }
        
        free(curr_col);
        curr_col = next_col;
    }
    free(store);
}

bool qihse_column_create(qihse_column_store_t* store, const char* name, qihse_column_type_t type) {
    if (!store || !name) return false;
    
    qihse_column_node_t* node = store->columns;
    while (node) {
        if (strcmp(node->name, name) == 0) return false;
        node = node->next;
    }
    
    qihse_column_node_t* new_col = (qihse_column_node_t*)calloc(1, sizeof(qihse_column_node_t));
    if (!new_col) return false;
    new_col->name = (char*)malloc(strlen(name) + 1);
    if (new_col->name) memcpy(new_col->name, name, strlen(name) + 1);
    new_col->type = type;
    new_col->next = store->columns;
    store->columns = new_col;
    
    return true;
}

static size_t get_type_size(qihse_column_type_t type) {
    switch (type) {
        case QIHSE_COL_TYPE_INT32: return 4;
        case QIHSE_COL_TYPE_INT64: return 8;
        case QIHSE_COL_TYPE_FLOAT32: return 4;
        case QIHSE_COL_TYPE_FLOAT64: return 8;
        case QIHSE_COL_TYPE_STRING_DICT: return 4;
        default: return 0;
    }
}

static qihse_column_node_t* get_column(qihse_column_store_t* store, const char* name) {
    if (!store || !name) return NULL;
    qihse_column_node_t* node = store->columns;
    while (node) {
        if (strcmp(node->name, name) == 0) return node;
        node = node->next;
    }
    return NULL;
}

typedef struct { int64_t val; uint32_t run_length; } qihse_rle_pair_int64_t;
typedef struct { float val; uint32_t run_length; } qihse_rle_pair_float32_t;
typedef struct { int32_t val; uint32_t run_length; } qihse_rle_pair_int32_t;

static void compress_chunk(qihse_column_chunk_t* chunk) {
    if (!chunk || chunk->count == 0 || chunk->encoding != QIHSE_ENCODING_RAW) return;

    if (chunk->type == QIHSE_COL_TYPE_INT64) {
        int64_t* data = (int64_t*)chunk->data;
        qihse_rle_pair_int64_t* rle_data = (qihse_rle_pair_int64_t*)malloc(sizeof(qihse_rle_pair_int64_t) * chunk->count);
        size_t rle_count = 0;
        int64_t current_val = data[0];
        uint32_t current_run = 1;

        for (size_t i = 1; i < chunk->count; i++) {
            if (data[i] == current_val) {
                current_run++;
            } else {
                rle_data[rle_count++] = (qihse_rle_pair_int64_t){current_val, current_run};
                current_val = data[i];
                current_run = 1;
            }
        }
        rle_data[rle_count++] = (qihse_rle_pair_int64_t){current_val, current_run};

        if (rle_count * sizeof(qihse_rle_pair_int64_t) < chunk->count * sizeof(int64_t)) {
            memcpy(chunk->data, rle_data, rle_count * sizeof(qihse_rle_pair_int64_t));
            chunk->encoding = QIHSE_ENCODING_RLE;
            chunk->dict_limit = rle_count; // Number of RLE runs
        }
        free(rle_data);
    } else if (chunk->type == QIHSE_COL_TYPE_FLOAT32) {
        float* data = (float*)chunk->data;
        qihse_rle_pair_float32_t* rle_data = (qihse_rle_pair_float32_t*)malloc(sizeof(qihse_rle_pair_float32_t) * chunk->count);
        size_t rle_count = 0;
        float current_val = data[0];
        uint32_t current_run = 1;

        for (size_t i = 1; i < chunk->count; i++) {
            if (data[i] == current_val) {
                current_run++;
            } else {
                rle_data[rle_count++] = (qihse_rle_pair_float32_t){current_val, current_run};
                current_val = data[i];
                current_run = 1;
            }
        }
        rle_data[rle_count++] = (qihse_rle_pair_float32_t){current_val, current_run};

        if (rle_count * sizeof(qihse_rle_pair_float32_t) < chunk->count * sizeof(float)) {
            memcpy(chunk->data, rle_data, rle_count * sizeof(qihse_rle_pair_float32_t));
            chunk->encoding = QIHSE_ENCODING_RLE;
            chunk->dict_limit = rle_count;
        }
        free(rle_data);
    } else if (chunk->type == QIHSE_COL_TYPE_STRING_DICT || chunk->type == QIHSE_COL_TYPE_INT32) {
        int32_t* data = (int32_t*)chunk->data;
        qihse_rle_pair_int32_t* rle_data = (qihse_rle_pair_int32_t*)malloc(sizeof(qihse_rle_pair_int32_t) * chunk->count);
        size_t rle_count = 0;
        int32_t current_val = data[0];
        uint32_t current_run = 1;

        for (size_t i = 1; i < chunk->count; i++) {
            if (data[i] == current_val) {
                current_run++;
            } else {
                rle_data[rle_count++] = (qihse_rle_pair_int32_t){current_val, current_run};
                current_val = data[i];
                current_run = 1;
            }
        }
        rle_data[rle_count++] = (qihse_rle_pair_int32_t){current_val, current_run};

        if (rle_count * sizeof(qihse_rle_pair_int32_t) < chunk->count * sizeof(int32_t)) {
            memcpy(chunk->data, rle_data, rle_count * sizeof(qihse_rle_pair_int32_t));
            chunk->encoding = QIHSE_ENCODING_RLE;
            chunk->dict_limit = rle_count;
        }
        free(rle_data);
    }
}

static bool append_value(qihse_column_store_t* store, const char* name, qihse_column_type_t expected_type, const void* val, uint16_t classification, uint16_t sci_compartment) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != expected_type) return false;
    
    if (!col->tail || col->tail->count >= QIHSE_COLUMN_CHUNK_SIZE) {
        if (col->tail && col->tail->count >= QIHSE_COLUMN_CHUNK_SIZE) {
            compress_chunk(col->tail);
        }
        
        qihse_column_chunk_t* new_chunk = NULL;
#ifdef _WIN32
        new_chunk = (qihse_column_chunk_t*)_aligned_malloc(sizeof(qihse_column_chunk_t), 4096);
        if (!new_chunk) {
            return false;
        }
#else
        if (posix_memalign((void**)&new_chunk, 4096, sizeof(qihse_column_chunk_t)) != 0) {
            return false;
        }
#endif
        
        new_chunk->type = expected_type;
        new_chunk->encoding = QIHSE_ENCODING_RAW;
        new_chunk->count = 0;
        new_chunk->dict_limit = 0;
        new_chunk->min_val = 0;
        new_chunk->max_val = 0;
        new_chunk->next = NULL;
        
        size_t elem_size = get_type_size(expected_type);
#ifdef _WIN32
        new_chunk->data = _aligned_malloc(elem_size * QIHSE_COLUMN_CHUNK_SIZE, 4096);
        if (!new_chunk->data) {
#else
        if (posix_memalign(&new_chunk->data, 4096, elem_size * QIHSE_COLUMN_CHUNK_SIZE) != 0) {
#endif
            free(new_chunk);
            return false;
        }
#ifdef _WIN32
        new_chunk->classifications = (uint16_t*)_aligned_malloc(sizeof(uint16_t) * QIHSE_COLUMN_CHUNK_SIZE, 4096);
        if (!new_chunk->classifications) {
#else
        if (posix_memalign((void**)&new_chunk->classifications, 4096, sizeof(uint16_t) * QIHSE_COLUMN_CHUNK_SIZE) != 0) {
#endif
            free(new_chunk->data);
            free(new_chunk);
            return false;
        }
#ifdef _WIN32
        new_chunk->sci_compartments = (uint16_t*)_aligned_malloc(sizeof(uint16_t) * QIHSE_COLUMN_CHUNK_SIZE, 4096);
        if (!new_chunk->sci_compartments) {
#else
        if (posix_memalign((void**)&new_chunk->sci_compartments, 4096, sizeof(uint16_t) * QIHSE_COLUMN_CHUNK_SIZE) != 0) {
#endif
            free(new_chunk->classifications);
            free(new_chunk->data);
            free(new_chunk);
            return false;
        }
        
        if (!col->head) {
            col->head = new_chunk;
            col->tail = new_chunk;
        } else {
            col->tail->next = new_chunk;
            col->tail = new_chunk;
        }
    }
    
    size_t elem_size = get_type_size(expected_type);
    memcpy((char*)col->tail->data + col->tail->count * elem_size, val, elem_size);
    col->tail->classifications[col->tail->count] = classification;
    col->tail->sci_compartments[col->tail->count] = sci_compartment;
    col->tail->count++;
    
    return true;
}

bool qihse_column_append_int32(qihse_column_store_t* store, const char* name, int32_t val, uint16_t classification, uint16_t sci_compartment) {
    return append_value(store, name, QIHSE_COL_TYPE_INT32, &val, classification, sci_compartment);
}

bool qihse_column_append_int64(qihse_column_store_t* store, const char* name, int64_t val, uint16_t classification, uint16_t sci_compartment) {
    return append_value(store, name, QIHSE_COL_TYPE_INT64, &val, classification, sci_compartment);
}

bool qihse_column_append_string(qihse_column_store_t* store, const char* name, const char* val, uint16_t classification, uint16_t sci_compartment) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_STRING_DICT) return false;

    // Check dictionary
    int32_t dict_id = -1;
    for (uint32_t i = 0; i < col->dict_count; i++) {
        if (strcmp(col->dict_strings[i], val) == 0) {
            dict_id = (int32_t)i;
            break;
        }
    }

    if (dict_id == -1) {
        if (col->dict_count >= col->dict_capacity) {
            uint32_t new_cap = col->dict_capacity == 0 ? 16 : col->dict_capacity * 2;
            col->dict_strings = (char**)realloc(col->dict_strings, new_cap * sizeof(char*));
            col->dict_capacity = new_cap;
        }
        col->dict_strings[col->dict_count] = strdup(val);
        dict_id = (int32_t)col->dict_count;
        col->dict_count++;
    }

    return append_value(store, name, QIHSE_COL_TYPE_STRING_DICT, &dict_id, classification, sci_compartment);
}

bool qihse_column_append_float32(qihse_column_store_t* store, const char* name, float val, uint16_t classification, uint16_t sci_compartment) {
    return append_value(store, name, QIHSE_COL_TYPE_FLOAT32, &val, classification, sci_compartment);
}

__attribute__((target_clones("avx512f", "avx2", "default")))
int64_t qihse_column_sum_int64_user(qihse_column_store_t* store, const char* name, qihse_user_t* user) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_INT64) return 0;
    
    int64_t sum = 0;
    qihse_column_chunk_t* chunk = col->head;
    while (chunk) {
        int64_t local_sum = 0;
        
        if (chunk->encoding == QIHSE_ENCODING_RLE) {
            qihse_rle_pair_int64_t* data = (qihse_rle_pair_int64_t*)chunk->data;
            size_t count = chunk->dict_limit; // we stored rle_count here
            
            size_t physical_idx = 0;
            for (size_t i = 0; i < count; i++) {
                int64_t val = data[i].val;
                uint32_t run = data[i].run_length;
                for (uint32_t r = 0; r < run; r++) {
                    if (qihse_auth_can_access(user, chunk->classifications[physical_idx], chunk->sci_compartments[physical_idx])) {
                        local_sum += val;
                    }
                    physical_idx++;
                }
            }
        } else {
            int64_t* data = (int64_t*)chunk->data;
            size_t count = chunk->count;
            
            for (size_t i = 0; i < count; i++) {
                if (qihse_auth_can_access(user, chunk->classifications[i], chunk->sci_compartments[i])) {
                    local_sum += data[i];
                }
            }
        }
        
        sum += local_sum;
        chunk = chunk->next;
    }
    return sum;
}

__attribute__((target_clones("avx512f", "avx2", "default")))
float qihse_column_sum_float32_user(qihse_column_store_t* store, const char* name, qihse_user_t* user) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_FLOAT32) return 0.0f;
    
    float sum = 0.0f;
    qihse_column_chunk_t* chunk = col->head;
    while (chunk) {
        float local_sum = 0.0f;
        
        if (chunk->encoding == QIHSE_ENCODING_RLE) {
            qihse_rle_pair_float32_t* data = (qihse_rle_pair_float32_t*)chunk->data;
            size_t count = chunk->dict_limit; // we stored rle_count here
            
            size_t physical_idx = 0;
            for (size_t i = 0; i < count; i++) {
                float val = data[i].val;
                uint32_t run = data[i].run_length;
                for (uint32_t r = 0; r < run; r++) {
                    if (qihse_auth_can_access(user, chunk->classifications[physical_idx], chunk->sci_compartments[physical_idx])) {
                        local_sum += val;
                    }
                    physical_idx++;
                }
            }
        } else {
            float* data = (float*)chunk->data;
            size_t count = chunk->count;
            
            for (size_t i = 0; i < count; i++) {
                if (qihse_auth_can_access(user, chunk->classifications[i], chunk->sci_compartments[i])) {
                    local_sum += data[i];
                }
            }
        }
        
        sum += local_sum;
        chunk = chunk->next;
    }
    return sum;
}

bool qihse_column_minmax_float32_user(qihse_column_store_t* store, const char* name, qihse_user_t* user, float* out_min, float* out_max) {
    if (!out_min || !out_max) return false;
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_FLOAT32) return false;
    bool found = false;
    float minimum = 0.0f;
    float maximum = 0.0f;
    qihse_column_chunk_t* chunk = col->head;
    while (chunk) {
        if (chunk->encoding == QIHSE_ENCODING_RLE) {
            qihse_rle_pair_float32_t* data = (qihse_rle_pair_float32_t*)chunk->data;
            size_t physical_idx = 0;
            for (size_t i = 0; i < chunk->dict_limit; i++) {
                for (uint32_t run = 0; run < data[i].run_length; run++, physical_idx++) {
                    if (!qihse_auth_can_access(user, chunk->classifications[physical_idx], chunk->sci_compartments[physical_idx])) continue;
                    float value = data[i].val;
                    if (!found || value < minimum) minimum = value;
                    if (!found || value > maximum) maximum = value;
                    found = true;
                }
            }
        } else {
            float* data = (float*)chunk->data;
            for (size_t i = 0; i < chunk->count; i++) {
                if (!qihse_auth_can_access(user, chunk->classifications[i], chunk->sci_compartments[i])) continue;
                float value = data[i];
                if (!found || value < minimum) minimum = value;
                if (!found || value > maximum) maximum = value;
                found = true;
            }
        }
        chunk = chunk->next;
    }
    if (!found) return false;
    *out_min = minimum;
    *out_max = maximum;
    return true;
}

/* TODO(Phase Y): Radix Partitioned Hash Join logic to be added in future phases. */

/* -------------------------------------------------------------------------
 * Keystone anchor-search index integration (Idea 2).
 *
 * Materializes a sorted INT64 index over a column so that point and range
 * lookups are served by qihse_keystone_anchor_search /
 * qihse_keystone_anchor_lower_bound / qihse_keystone_anchor_upper_bound in
 * O(log log N) (< 20ns), replacing binary search.
 * ------------------------------------------------------------------------- */

typedef struct {
    int64_t value;
    qihse_column_chunk_t* chunk;
    uint32_t slot;
} qihse_column_idx_entry_t;

static int qihse_column_idx_cmp(const void* a, const void* b) {
    int64_t va = ((const qihse_column_idx_entry_t*)a)->value;
    int64_t vb = ((const qihse_column_idx_entry_t*)b)->value;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

bool qihse_column_build_int64_index(qihse_column_store_t* store, const char* name) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_INT64) return false;

    /* Free any previously materialized index. */
    free(col->idx_values);
    free(col->idx_chunks);
    free(col->idx_slots);
    col->idx_values = NULL;
    col->idx_chunks = NULL;
    col->idx_slots = NULL;
    col->idx_count = 0;

    /* Count total rows across all chunks. RLE-encoded chunks store the
     * physical row count in chunk->count (the logical run list lives in
     * chunk->dict_limit), so chunk->count is always the row count we need. */
    size_t total = 0;
    for (qihse_column_chunk_t* chunk = col->head; chunk; chunk = chunk->next) {
        total += chunk->count;
    }
    if (total == 0) return true;

    qihse_column_idx_entry_t* entries =
        (qihse_column_idx_entry_t*)malloc(total * sizeof(qihse_column_idx_entry_t));
    if (!entries) return false;

    size_t pos = 0;
    for (qihse_column_chunk_t* chunk = col->head; chunk; chunk = chunk->next) {
        if (chunk->encoding == QIHSE_ENCODING_RLE) {
            /* Expand RLE runs back to per-row values for the sorted index. */
            qihse_rle_pair_int64_t* runs = (qihse_rle_pair_int64_t*)chunk->data;
            size_t run_count = chunk->dict_limit;
            uint32_t slot = 0;
            for (size_t r = 0; r < run_count; r++) {
                int64_t v = runs[r].val;
                uint32_t run = runs[r].run_length;
                for (uint32_t k = 0; k < run; k++) {
                    entries[pos].value = v;
                    entries[pos].chunk = chunk;
                    entries[pos].slot = slot;
                    pos++;
                    slot++;
                }
            }
        } else {
            int64_t* data = (int64_t*)chunk->data;
            for (uint32_t i = 0; i < chunk->count; i++) {
                entries[pos].value = data[i];
                entries[pos].chunk = chunk;
                entries[pos].slot = i;
                pos++;
            }
        }
    }

    if (pos != total) {
        free(entries);
        return false;
    }

    qsort(entries, total, sizeof(qihse_column_idx_entry_t), qihse_column_idx_cmp);

    col->idx_values = (int64_t*)malloc(total * sizeof(int64_t));
    col->idx_chunks = (qihse_column_chunk_t**)malloc(total * sizeof(qihse_column_chunk_t*));
    col->idx_slots = (uint32_t*)malloc(total * sizeof(uint32_t));
    if (!col->idx_values || !col->idx_chunks || !col->idx_slots) {
        free(col->idx_values); col->idx_values = NULL;
        free(col->idx_chunks); col->idx_chunks = NULL;
        free(col->idx_slots); col->idx_slots = NULL;
        free(entries);
        return false;
    }

    for (size_t i = 0; i < total; i++) {
        col->idx_values[i] = entries[i].value;
        col->idx_chunks[i] = entries[i].chunk;
        col->idx_slots[i] = entries[i].slot;
    }
    col->idx_count = total;

    free(entries);
    return true;
}

void qihse_column_drop_int64_index(qihse_column_store_t* store, const char* name) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col) return;
    free(col->idx_values);
    free(col->idx_chunks);
    free(col->idx_slots);
    col->idx_values = NULL;
    col->idx_chunks = NULL;
    col->idx_slots = NULL;
    col->idx_count = 0;
}

int64_t qihse_column_lookup_int64_user(qihse_column_store_t* store, const char* name, int64_t key, qihse_user_t* user) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_INT64 || !col->idx_values || col->idx_count == 0) {
        return -1;
    }

    /* O(log log N) anchor search to locate the first matching value. */
    int64_t hit = qihse_keystone_anchor_search(col->idx_values, col->idx_count, key);
    if (hit < 0) return -1;

    /* Walk the (typically tiny) run of equal values, enforcing ACLs. */
    for (size_t i = (size_t)hit; i < col->idx_count && col->idx_values[i] == key; i++) {
        qihse_column_chunk_t* chunk = col->idx_chunks[i];
        uint32_t slot = col->idx_slots[i];
        if (qihse_auth_can_access(user, chunk->classifications[slot], chunk->sci_compartments[slot])) {
            return (int64_t)i;
        }
    }
    return -1;
}

size_t qihse_column_range_count_int64_user(qihse_column_store_t* store, const char* name, int64_t low, int64_t high, qihse_user_t* user) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_INT64 || !col->idx_values || col->idx_count == 0) {
        return 0;
    }
    if (low > high) return 0;

    /* O(log log N) bracketing of [low, high] via keystone anchor bounds,
     * replacing the previous binary-search implementation. */
    size_t lo = qihse_keystone_anchor_lower_bound(col->idx_values, col->idx_count, low);
    size_t hi = qihse_keystone_anchor_upper_bound(col->idx_values, col->idx_count, high);

    size_t accessible = 0;
    for (size_t i = lo; i < hi; i++) {
        qihse_column_chunk_t* chunk = col->idx_chunks[i];
        uint32_t slot = col->idx_slots[i];
        if (qihse_auth_can_access(user, chunk->classifications[slot], chunk->sci_compartments[slot])) {
            accessible++;
        }
    }
    return accessible;
}
