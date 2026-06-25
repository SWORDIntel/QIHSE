#include "qihse_document.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "qihse_bytecode.h"
#include "qihse_bytecode_compiler.h"
#include "qihse_auth.h"

typedef struct qihse_doc {
    uint64_t id;
    qihse_bytecode_field_t* fields;
    size_t num_fields;
    size_t cap_fields;
    struct qihse_doc* next;
    uint16_t classification;
    uint16_t sci_compartment;
} qihse_doc_t;

struct qihse_document_store {
    qihse_kv_store_t* kv;
    qihse_doc_arena_block_t* arena_head;
    qihse_radix_node_t* index_root;
    qihse_doc_t* docs_head;
};

static uint64_t simple_hash(const char* str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

qihse_document_store_t* qihse_doc_store_create(qihse_kv_store_t* kv) {
    qihse_document_store_t* store = (qihse_document_store_t*)malloc(sizeof(qihse_document_store_t));
    if (!store) return NULL;
    
    store->kv = kv;
    store->docs_head = NULL;
    
    /* Allocate initial arena block */
    store->arena_head = (qihse_doc_arena_block_t*)malloc(sizeof(qihse_doc_arena_block_t) + 4096);
    if (store->arena_head) {
        memset(store->arena_head, 0, sizeof(qihse_doc_arena_block_t) + 4096);
        store->arena_head->capacity = 4096;
    }
    
    /* Allocate index root */
    store->index_root = (qihse_radix_node_t*)malloc(sizeof(qihse_radix_node_t));
    if (store->index_root) {
        memset(store->index_root, 0, sizeof(qihse_radix_node_t));
    }
    
    return store;
}

void qihse_doc_store_destroy(qihse_document_store_t* store) {
    if (!store) return;
    
    qihse_doc_arena_block_t* curr_arena = store->arena_head;
    while (curr_arena) {
        qihse_doc_arena_block_t* next = curr_arena->next;
        free(curr_arena);
        curr_arena = next;
    }
    
    if (store->index_root) {
        free(store->index_root);
    }
    
    qihse_doc_t* curr_doc = store->docs_head;
    while (curr_doc) {
        qihse_doc_t* next = curr_doc->next;
        for (size_t i = 0; i < curr_doc->num_fields; i++) {
            free((void*)curr_doc->fields[i].name);
            if (curr_doc->fields[i].type == QIHSE_FIELD_STR) {
                free((void*)curr_doc->fields[i].value.s);
            }
        }
        free(curr_doc->fields);
        free(curr_doc);
        curr_doc = next;
    }
    
    free(store);
}

static void update_bloom_filter(qihse_bloom_filter_t* bloom, const char* key) {
    uint64_t hash = simple_hash(key);
    int index = (hash / 64) % 8;
    int bit = hash % 64;
    bloom->bits[index] |= (1ULL << bit);
}

bool qihse_doc_store_insert_json(qihse_document_store_t* store, uint64_t doc_id, const char* json_payload) {
    if (!store || !json_payload) return false;
    
    int depth = 0;
    const char* ptr = json_payload;
    
    qihse_doc_t* doc = (qihse_doc_t*)calloc(1, sizeof(qihse_doc_t));
    doc->id = doc_id;
    doc->cap_fields = 8;
    doc->fields = (qihse_bytecode_field_t*)calloc(doc->cap_fields, sizeof(qihse_bytecode_field_t));
    
    // Simple state machine to parse JSON keys and values for demo purposes
    while (*ptr) {
        if (*ptr == '{' || *ptr == '[') {
            depth++;
            if (depth > QIHSE_MAX_JSON_DEPTH) {
                break; // Abort to prevent zip bombs
            }
            ptr++;
        } else if (*ptr == '}' || *ptr == ']') {
            depth--;
            if (depth < 0) depth = 0;
            ptr++;
        } else if (*ptr == '"') {
            // Parse string token (likely a key)
            ptr++;
            char key_str[1024] = {0};
            int len = 0;
            while (*ptr && *ptr != '"' && len < 1023) {
                key_str[len++] = *ptr++;
            }
            while (*ptr && *ptr != '"') ptr++;
            if (*ptr == '"') ptr++;
            
            // Skip whitespace
            while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;
            
            if (*ptr == ':') {
                ptr++;
                // Skip whitespace
                while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;
                
                char val_str[2048] = {0};
                int vlen = 0;
                
                qihse_bytecode_field_t field;
                field.name = strdup(key_str);
                
                if (*ptr == '"') {
                    // String value
                    ptr++;
                    while (*ptr && *ptr != '"' && vlen < 2047) {
                        val_str[vlen++] = *ptr++;
                    }
                    while (*ptr && *ptr != '"') ptr++;
                    if (*ptr == '"') ptr++;
                    
                    field.type = QIHSE_FIELD_STR;
                    field.value.s = strdup(val_str);
                } else if (*ptr == '{' || *ptr == '[') {
                    // Nested structure, just let the main loop handle it
                    free((void*)field.name);
                    continue;
                } else {
                    // Primitive value (number, boolean, null)
                    while (*ptr && *ptr != ',' && *ptr != '}' && *ptr != ']' && 
                           *ptr != ' ' && *ptr != '\n' && *ptr != '\r' && vlen < 2047) {
                        val_str[vlen++] = *ptr++;
                    }
                    while (*ptr && *ptr != ',' && *ptr != '}' && *ptr != ']' && 
                           *ptr != ' ' && *ptr != '\n' && *ptr != '\r') ptr++;
                    
                    if (strcmp(val_str, "true") == 0) {
                        field.type = QIHSE_FIELD_BOOL;
                        field.value.b = true;
                    } else if (strcmp(val_str, "false") == 0) {
                        field.type = QIHSE_FIELD_BOOL;
                        field.value.b = false;
                    } else {
                        field.type = QIHSE_FIELD_INT;
                        field.value.i = strtoll(val_str, NULL, 10);
                    }
                }
                
                if (doc->num_fields == doc->cap_fields) {
                    doc->cap_fields *= 2;
                    doc->fields = (qihse_bytecode_field_t*)realloc(doc->fields, doc->cap_fields * sizeof(qihse_bytecode_field_t));
                }
                doc->fields[doc->num_fields++] = field;
                
                if (store->arena_head) {
                    update_bloom_filter(&store->arena_head->bloom, key_str);
                }
            }
        } else {
            ptr++;
        }
    }
    
    doc->next = store->docs_head;
    store->docs_head = doc;
    
    return true;
}

qihse_document_result_t qihse_doc_store_query_user(qihse_document_store_t* store, const char* where_clause, qihse_user_t* user) {
    qihse_document_result_t res;
    res.doc_ids = NULL;
    res.count = 0;
    if (!store || !where_clause) return res;

    uint8_t bytecode[4096];
    size_t bc_len = 0;
    int err = qihse_bc_compile(where_clause, bytecode, sizeof(bytecode), &bc_len);
    if (err != QIHSE_BC_OK) {
        printf("JIT Compile Error: %s\n", qihse_bc_error_str(err));
        return res;
    }

    size_t cap = 16;
    res.doc_ids = (uint64_t*)malloc(cap * sizeof(uint64_t));

    qihse_doc_t* curr = store->docs_head;
    while (curr) {
        qihse_bytecode_context_t ctx;
        ctx.fields = curr->fields;
        ctx.num_fields = curr->num_fields;

        if (!qihse_auth_can_access(user, curr->classification, curr->sci_compartment)) {
            curr = curr->next;
            continue;
        }

        if (qihse_bytecode_eval(bytecode, &ctx)) {
            if (res.count == cap) {
                cap *= 2;
                res.doc_ids = (uint64_t*)realloc(res.doc_ids, cap * sizeof(uint64_t));
            }
            res.doc_ids[res.count++] = curr->id;
        }
        curr = curr->next;
    }
    return res;
}
