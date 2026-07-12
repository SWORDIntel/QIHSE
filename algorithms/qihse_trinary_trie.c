#include "qihse_trinary_trie.h"
#include <stdlib.h>
#include <string.h>

#define NODE_CHUNK_SIZE 256

typedef struct qihse_tst_node {
    void* value;
    struct qihse_tst_node* left;
    struct qihse_tst_node* mid;
    struct qihse_tst_node* right;
    size_t value_size;
    char c;
    bool is_end;
} qihse_tst_node_t;

typedef struct qihse_node_chunk {
    qihse_tst_node_t nodes[NODE_CHUNK_SIZE];
    struct qihse_node_chunk* next;
} qihse_node_chunk_t;

struct qihse_trinary_trie {
    qihse_tst_node_t* root;
    qihse_node_chunk_t* chunks;
    qihse_tst_node_t* free_list;
    size_t chunk_used;
};

qihse_trinary_trie_t* qihse_trinary_trie_create() {
    qihse_trinary_trie_t* trie = (qihse_trinary_trie_t*)malloc(sizeof(qihse_trinary_trie_t));
    if (trie) {
        trie->root = NULL;
        trie->chunks = NULL;
        trie->free_list = NULL;
        trie->chunk_used = NODE_CHUNK_SIZE;
    }
    return trie;
}

static qihse_tst_node_t* alloc_node(qihse_trinary_trie_t* trie, char c) {
    qihse_tst_node_t* node = NULL;
    if (trie->free_list) {
        node = trie->free_list;
        trie->free_list = node->left;
    } else {
        if (!trie->chunks || trie->chunk_used >= NODE_CHUNK_SIZE) {
            qihse_node_chunk_t* new_chunk = (qihse_node_chunk_t*)malloc(sizeof(qihse_node_chunk_t));
            if (!new_chunk) return NULL;
            new_chunk->next = trie->chunks;
            trie->chunks = new_chunk;
            trie->chunk_used = 0;
        }
        node = &trie->chunks->nodes[trie->chunk_used++];
    }
    
    node->value = NULL;
    node->left = NULL;
    node->mid = NULL;
    node->right = NULL;
    node->value_size = 0;
    node->c = c;
    node->is_end = false;
    return node;
}

static void free_node(qihse_trinary_trie_t* trie, qihse_tst_node_t* node) {
    if (node->value) {
        free(node->value);
        node->value = NULL;
    }
    node->left = trie->free_list;
    trie->free_list = node;
}

static void free_values_recursive(qihse_tst_node_t* node) {
    if (!node) return;
    free_values_recursive(node->left);
    free_values_recursive(node->mid);
    free_values_recursive(node->right);
    if (node->value) {
        free(node->value);
        node->value = NULL;
    }
}

void qihse_trinary_trie_destroy(qihse_trinary_trie_t* trie) {
    if (!trie) return;
    
    free_values_recursive(trie->root);
    
    qihse_node_chunk_t* chunk = trie->chunks;
    while (chunk) {
        qihse_node_chunk_t* next = chunk->next;
        free(chunk);
        chunk = next;
    }
    
    free(trie);
}

bool qihse_trinary_trie_insert(qihse_trinary_trie_t* trie, const char* key, void* value, size_t value_size) {
    if (!trie || !key || *key == '\0') return false;
    bool inserted = false;
    
    qihse_tst_node_t** ptr = &trie->root;
    while (*key) {
        if (!*ptr) {
            *ptr = alloc_node(trie, *key);
            if (!*ptr) return false;
        }
        if (*key < (*ptr)->c) {
            ptr = &((*ptr)->left);
        } else if (*key > (*ptr)->c) {
            ptr = &((*ptr)->right);
        } else {
            if (*(key + 1) == '\0') {
                break;
            }
            ptr = &((*ptr)->mid);
            key++;
        }
    }

    qihse_tst_node_t* node = *ptr;
    if (node) {
        if (node->is_end && node->value) {
            free(node->value);
            node->value = NULL;
        }
        node->is_end = true;
        if (value_size > 0 && value != NULL) {
            node->value = malloc(value_size);
            if (node->value) {
                memcpy(node->value, value, value_size);
                node->value_size = value_size;
                inserted = true;
            } else {
                node->is_end = false;
                node->value_size = 0;
                inserted = false;
            }
        } else {
            node->value = NULL;
            node->value_size = 0;
            inserted = true;
        }
    }
    return inserted;
}

void* qihse_trinary_trie_search(qihse_trinary_trie_t* trie, const char* key, size_t* out_size) {
    if (!trie || !key || *key == '\0') return NULL;
    qihse_tst_node_t* node = trie->root;
    while (node) {
        if (*key < node->c) {
            node = node->left;
        } else if (*key > node->c) {
            node = node->right;
        } else {
            if (*(key + 1) == '\0') {
                break;
            }
            node = node->mid;
            key++;
        }
    }
    
    if (node && node->is_end) {
        if (out_size) {
            *out_size = node->value_size;
        }
        return node->value;
    }
    return NULL;
}

static qihse_tst_node_t* delete_node(qihse_trinary_trie_t* trie, qihse_tst_node_t* node, const char* key, bool* deleted) {
    if (!node) return NULL;

    if (*key < node->c) {
        node->left = delete_node(trie, node->left, key, deleted);
    } else if (*key > node->c) {
        node->right = delete_node(trie, node->right, key, deleted);
    } else {
        if (*(key + 1) != '\0') {
            node->mid = delete_node(trie, node->mid, key + 1, deleted);
        } else {
            if (node->is_end) {
                node->is_end = false;
                if (node->value) {
                    free(node->value);
                    node->value = NULL;
                }
                node->value_size = 0;
                *deleted = true;
            }
        }
    }

    if (!node->is_end && !node->left && !node->mid && !node->right) {
        free_node(trie, node);
        return NULL;
    }

    return node;
}

bool qihse_trinary_trie_delete(qihse_trinary_trie_t* trie, const char* key) {
    if (!trie || !key || *key == '\0') return false;
    bool deleted = false;
    trie->root = delete_node(trie, trie->root, key, &deleted);
    return deleted;
}

static bool foreach_recursive(qihse_tst_node_t* node, char* buf, int depth, int buf_size,
                              qihse_trinary_trie_iter_cb cb, void* user_data) {
    if (!node) return true;
    if (!foreach_recursive(node->left, buf, depth, buf_size, cb, user_data)) return false;
    buf[depth] = node->c;
    if (node->is_end) {
        buf[depth + 1] = '\0';
        if (!cb(buf, node->value, node->value_size, user_data)) return false;
    }
    if (!foreach_recursive(node->mid, buf, depth + 1, buf_size, cb, user_data)) return false;
    if (!foreach_recursive(node->right, buf, depth, buf_size, cb, user_data)) return false;
    return true;
}

void qihse_trinary_trie_foreach(qihse_trinary_trie_t* trie, qihse_trinary_trie_iter_cb cb, void* user_data) {
    if (!trie || !trie->root || !cb) return;
    char buf[512];
    foreach_recursive(trie->root, buf, 0, sizeof(buf) - 1, cb, user_data);
}
