#define _POSIX_C_SOURCE 200112L
#include "qihse_column.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct qihse_column_node {
    char* name;
    qihse_column_type_t type;
    qihse_column_chunk_t* head;
    qihse_column_chunk_t* tail;
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
        
        qihse_column_chunk_t* curr_chunk = curr_col->head;
        while (curr_chunk) {
            qihse_column_chunk_t* next_chunk = curr_chunk->next;
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
    if (new_col->name) strcpy(new_col->name, name);
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

static bool append_value(qihse_column_store_t* store, const char* name, qihse_column_type_t expected_type, const void* val) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != expected_type) return false;
    
    if (!col->tail || col->tail->count >= QIHSE_COLUMN_CHUNK_SIZE) {
        qihse_column_chunk_t* new_chunk = NULL;
        if (posix_memalign((void**)&new_chunk, 4096, sizeof(qihse_column_chunk_t)) != 0) {
            return false;
        }
        
        new_chunk->type = expected_type;
        new_chunk->encoding = QIHSE_ENCODING_RAW;
        new_chunk->count = 0;
        new_chunk->dict_limit = 0;
        new_chunk->min_val = 0;
        new_chunk->max_val = 0;
        new_chunk->next = NULL;
        
        size_t elem_size = get_type_size(expected_type);
        if (posix_memalign(&new_chunk->data, 4096, elem_size * QIHSE_COLUMN_CHUNK_SIZE) != 0) {
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
        
        /* TODO(Phase X): Implement Adaptive Encoding Switches here (e.g., dynamically switch to RLE or DELTA). */
    }
    
    size_t elem_size = get_type_size(expected_type);
    memcpy((char*)col->tail->data + col->tail->count * elem_size, val, elem_size);
    col->tail->count++;
    
    return true;
}

bool qihse_column_append_int64(qihse_column_store_t* store, const char* name, int64_t val) {
    return append_value(store, name, QIHSE_COL_TYPE_INT64, &val);
}

bool qihse_column_append_float32(qihse_column_store_t* store, const char* name, float val) {
    return append_value(store, name, QIHSE_COL_TYPE_FLOAT32, &val);
}

__attribute__((target_clones("avx512f", "avx2", "default")))
int64_t qihse_column_sum_int64(qihse_column_store_t* store, const char* name) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_INT64) return 0;
    
    int64_t sum = 0;
    qihse_column_chunk_t* chunk = col->head;
    while (chunk) {
        int64_t* data = (int64_t*)chunk->data;
        size_t count = chunk->count;
        
        int64_t local_sum = 0;
        #pragma GCC ivdep
        #pragma GCC unroll 8
        for (size_t i = 0; i < count; i++) {
            local_sum += data[i];
        }
        sum += local_sum;
        chunk = chunk->next;
    }
    return sum;
}

__attribute__((target_clones("avx512f", "avx2", "default")))
float qihse_column_sum_float32(qihse_column_store_t* store, const char* name) {
    qihse_column_node_t* col = get_column(store, name);
    if (!col || col->type != QIHSE_COL_TYPE_FLOAT32) return 0.0f;
    
    float sum = 0.0f;
    qihse_column_chunk_t* chunk = col->head;
    while (chunk) {
        float* data = (float*)chunk->data;
        size_t count = chunk->count;
        
        float local_sum = 0.0f;
        #pragma omp simd reduction(+:local_sum)
        for (size_t i = 0; i < count; i++) {
            local_sum += data[i];
        }
        sum += local_sum;
        chunk = chunk->next;
    }
    return sum;
}

/* TODO(Phase Y): Radix Partitioned Hash Join logic to be added in future phases. */
