#include "qihse_document.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

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

typedef struct qihse_doc_version {
    uint64_t version;
    uint16_t classification;
    uint16_t sci;
    char* json;
    struct qihse_doc_version* next;
} qihse_doc_version_t;

typedef struct qihse_doc_secure {
    uint64_t id;
    uint32_t tenant;
    uint64_t last_version;
    size_t version_count;
    qihse_doc_version_t* versions;
    struct qihse_doc_secure* next;
} qihse_doc_secure_t;

struct qihse_document_store {
    qihse_kv_store_t* kv;
    qihse_doc_arena_block_t* arena_head;
    qihse_radix_node_t* index_root;
    qihse_doc_t* docs_head;
    pthread_mutex_t secure_mutex;
    qihse_doc_secure_t* secure_head;
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
    if (pthread_mutex_init(&store->secure_mutex, NULL) != 0) {
        free(store); return NULL;
    }
    
    store->kv = kv;
    store->docs_head = NULL;
    store->secure_head = NULL;
    
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
    qihse_doc_secure_t* secure = store->secure_head;
    while (secure) {
        qihse_doc_secure_t* next = secure->next;
        qihse_doc_version_t* version = secure->versions;
        while (version) {
            qihse_doc_version_t* next_version = version->next;
            free(version->json);
            free(version);
            version = next_version;
        }
        free(secure);
        secure = next;
    }
    pthread_mutex_destroy(&store->secure_mutex);
    
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

/* The secure lane never reads a legacy record: its context-free insert path
 * cannot establish an authoritative tenant or classification. */
bool qihse_doc_store_insert_json_user(qihse_document_store_t* store,
        uint64_t doc_id, const char* json_payload, qihse_user_t* user) {
    if (!store || !json_payload || !user) return false;
    uint32_t tenant = 0;
    uint64_t generation = 0;
    bool active = false;
    qihse_auth_user_active_and_tenant(user, &active, &tenant);
    if (!active) return false;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (borrowed != user || !generation) {
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    size_t length = strnlen(json_payload, 1024u * 1024u + 1u);
    if (!length || length > 1024u * 1024u) {
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    char* copy = strdup(json_payload);
    if (!copy) {
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    qihse_doc_version_t* version = calloc(1, sizeof(*version));
    if (!version) {
        free(copy);
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    version->json = copy;
    uint16_t classification = qihse_user_get_classification(user);
    uint16_t sci = qihse_user_get_sci(user);
    pthread_mutex_lock(&store->secure_mutex);
    if (!qihse_auth_validate_handle_generation(user, generation)) {
        pthread_mutex_unlock(&store->secure_mutex);
        free(version->json); free(version);
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    qihse_doc_secure_t* doc = store->secure_head;
    while (doc && (doc->tenant != tenant || doc->id != doc_id)) doc = doc->next;
    qihse_doc_version_t* current = doc ? doc->versions : NULL;
    if (doc && (doc->last_version == UINT64_MAX || !current ||
                !qihse_auth_can_access(user, current->classification, current->sci) ||
                classification < current->classification ||
                (sci & current->sci) != current->sci)) {
        pthread_mutex_unlock(&store->secure_mutex);
        free(version->json); free(version);
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    if (!doc) {
        doc = calloc(1, sizeof(*doc));
        if (!doc) {
            pthread_mutex_unlock(&store->secure_mutex);
            free(version->json); free(version);
            qihse_auth_release_principal_scoped(borrowed);
            return false;
        }
        doc->id = doc_id;
        doc->tenant = tenant;
        doc->next = store->secure_head;
        store->secure_head = doc;
    }
    version->version = ++doc->last_version;
    version->classification = classification;
    version->sci = sci;
    version->next = doc->versions;
    doc->versions = version;
    doc->version_count++;
    if (doc->version_count > QIHSE_DOC_VERSION_RETENTION) {
        qihse_doc_version_t* tail = doc->versions;
        for (size_t i = 1; i < QIHSE_DOC_VERSION_RETENTION; i++)
            tail = tail->next;
        qihse_doc_version_t* expired = tail->next;
        tail->next = NULL;
        while (expired) {
            qihse_doc_version_t* next = expired->next;
            free(expired->json);
            free(expired);
            expired = next;
        }
        doc->version_count = QIHSE_DOC_VERSION_RETENTION;
    }
    pthread_mutex_unlock(&store->secure_mutex);
    qihse_auth_release_principal_scoped(borrowed);
    return true;
}

static bool secure_get_json_user(qihse_document_store_t* store,
        uint64_t doc_id, uint64_t version_id, qihse_user_t* user,
        char** out_json) {
    if (out_json) *out_json = NULL;
    if (!store || !user || !out_json) return false;
    uint32_t tenant = 0;
    uint64_t generation = 0;
    bool active = false;
    qihse_auth_user_active_and_tenant(user, &active, &tenant);
    if (!active) return false;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (borrowed != user || !generation) {
        qihse_auth_release_principal_scoped(borrowed);
        return false;
    }
    pthread_mutex_lock(&store->secure_mutex);
    qihse_doc_secure_t* doc = store->secure_head;
    while (doc && (doc->tenant != tenant || doc->id != doc_id)) doc = doc->next;
    qihse_doc_version_t* version = doc ? doc->versions : NULL;
    if (version_id)
        while (version && version->version != version_id) version = version->next;
    char* copy = NULL;
    if (version && qihse_auth_can_access(user, version->classification, version->sci))
        copy = strdup(version->json);
    bool valid = qihse_auth_validate_handle_generation(user, generation);
    pthread_mutex_unlock(&store->secure_mutex);
    qihse_auth_release_principal_scoped(borrowed);
    if (!valid) { free(copy); return false; }
    *out_json = copy;
    return copy != NULL;
}

bool qihse_doc_store_get_json_user(qihse_document_store_t* store,
        uint64_t doc_id, qihse_user_t* user, char** out_json) {
    return secure_get_json_user(store, doc_id, 0u, user, out_json);
}

bool qihse_doc_store_get_version_json_user(qihse_document_store_t* store,
        uint64_t doc_id, uint64_t version, qihse_user_t* user, char** out_json) {
    if (out_json) *out_json = NULL;
    return version && secure_get_json_user(store, doc_id, version, user, out_json);
}

qihse_document_result_t qihse_doc_store_list_user(qihse_document_store_t* store,
        qihse_user_t* user, size_t limit) {
    qihse_document_result_t result = {0};
    if (!store || !user || !limit || limit > QIHSE_DOC_USER_LIST_MAX) return result;
    uint32_t tenant = 0;
    uint64_t generation = 0;
    bool active = false;
    qihse_auth_user_active_and_tenant(user, &active, &tenant);
    if (!active) return result;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (borrowed != user || !generation) {
        qihse_auth_release_principal_scoped(borrowed);
        return result;
    }
    uint64_t* ids = calloc(limit, sizeof(*ids));
    if (!ids) {
        qihse_auth_release_principal_scoped(borrowed);
        return result;
    }
    pthread_mutex_lock(&store->secure_mutex);
    for (qihse_doc_secure_t* doc = store->secure_head;
         doc && result.count < limit; doc = doc->next) {
        if (doc->tenant == tenant &&
            doc->versions && qihse_auth_can_access(user,
                doc->versions->classification, doc->versions->sci))
            ids[result.count++] = doc->id;
    }
    bool valid = qihse_auth_validate_handle_generation(user, generation);
    pthread_mutex_unlock(&store->secure_mutex);
    qihse_auth_release_principal_scoped(borrowed);
    if (!valid || !result.count) {
        free(ids);
        result.count = 0;
    } else {
        result.doc_ids = ids;
    }
    return result;
}

qihse_document_versions_t qihse_doc_store_list_versions_user(
        qihse_document_store_t* store, uint64_t doc_id, qihse_user_t* user) {
    qihse_document_versions_t result = {0};
    if (!store || !user) return result;
    uint32_t tenant = 0;
    uint64_t generation = 0;
    bool active = false;
    qihse_auth_user_active_and_tenant(user, &active, &tenant);
    if (!active) return result;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (borrowed != user || !generation) {
        qihse_auth_release_principal_scoped(borrowed);
        return result;
    }
    uint64_t* versions = calloc(QIHSE_DOC_VERSION_RETENTION, sizeof(*versions));
    if (!versions) {
        qihse_auth_release_principal_scoped(borrowed);
        return result;
    }
    pthread_mutex_lock(&store->secure_mutex);
    qihse_doc_secure_t* doc = store->secure_head;
    while (doc && (doc->tenant != tenant || doc->id != doc_id)) doc = doc->next;
    for (qihse_doc_version_t* version = doc ? doc->versions : NULL;
         version && result.count < QIHSE_DOC_VERSION_RETENTION;
         version = version->next) {
        if (qihse_auth_can_access(user, version->classification, version->sci))
            versions[result.count++] = version->version;
    }
    bool valid = qihse_auth_validate_handle_generation(user, generation);
    pthread_mutex_unlock(&store->secure_mutex);
    qihse_auth_release_principal_scoped(borrowed);
    if (!valid || !result.count) {
        free(versions);
        result.count = 0;
    } else {
        result.versions = versions;
    }
    return result;
}
