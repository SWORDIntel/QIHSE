#include "qihse_trinary_trie.h"
#include <stdlib.h>
#include <string.h>

typedef struct qihse_tst_node {
    char c;
    bool is_end;
    void* value;
    size_t value_size;
    struct qihse_tst_node* left;
    struct qihse_tst_node* mid;
    struct qihse_tst_node* right;
} qihse_tst_node_t;

struct qihse_trinary_trie {
    qihse_tst_node_t* root;
};

static qihse_tst_node_t* create_node(char c) {
    qihse_tst_node_t* node = (qihse_tst_node_t*)malloc(sizeof(qihse_tst_node_t));
    if (node) {
        node->c = c;
        node->is_end = false;
        node->value = NULL;
        node->value_size = 0;
        node->left = NULL;
        node->mid = NULL;
        node->right = NULL;
    }
    return node;
}

qihse_trinary_trie_t* qihse_trinary_trie_create() {
    qihse_trinary_trie_t* trie = (qihse_trinary_trie_t*)malloc(sizeof(qihse_trinary_trie_t));
    if (trie) {
        trie->root = NULL;
    }
    return trie;
}

static void destroy_node(qihse_tst_node_t* node) {
    if (!node) return;
    destroy_node(node->left);
    destroy_node(node->mid);
    destroy_node(node->right);
    if (node->value) {
        free(node->value);
    }
    free(node);
}

void qihse_trinary_trie_destroy(qihse_trinary_trie_t* trie) {
    if (!trie) return;
    destroy_node(trie->root);
    free(trie);
}

static qihse_tst_node_t* insert_node(qihse_tst_node_t* node, const char* key, void* value, size_t value_size, bool* inserted) {
    if (!node) {
        node = create_node(*key);
        if (!node) return NULL;
    }

    if (*key < node->c) {
        node->left = insert_node(node->left, key, value, value_size, inserted);
    } else if (*key > node->c) {
        node->right = insert_node(node->right, key, value, value_size, inserted);
    } else {
        if (*(key + 1) != '\0') {
            node->mid = insert_node(node->mid, key + 1, value, value_size, inserted);
        } else {
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
                    *inserted = true;
                } else {
                    node->is_end = false;
                    node->value_size = 0;
                    *inserted = false;
                }
            } else {
                node->value = NULL;
                node->value_size = 0;
                *inserted = true;
            }
        }
    }
    return node;
}

bool qihse_trinary_trie_insert(qihse_trinary_trie_t* trie, const char* key, void* value, size_t value_size) {
    if (!trie || !key || *key == '\0') return false;
    bool inserted = false;
    trie->root = insert_node(trie->root, key, value, value_size, &inserted);
    return inserted;
}

static qihse_tst_node_t* search_node(qihse_tst_node_t* node, const char* key) {
    if (!node) return NULL;

    if (*key < node->c) {
        return search_node(node->left, key);
    } else if (*key > node->c) {
        return search_node(node->right, key);
    } else {
        if (*(key + 1) == '\0') {
            return node;
        }
        return search_node(node->mid, key + 1);
    }
}

void* qihse_trinary_trie_search(qihse_trinary_trie_t* trie, const char* key, size_t* out_size) {
    if (!trie || !key || *key == '\0') return NULL;
    qihse_tst_node_t* node = search_node(trie->root, key);
    if (node && node->is_end) {
        if (out_size) {
            *out_size = node->value_size;
        }
        return node->value;
    }
    return NULL;
}

static qihse_tst_node_t* delete_node(qihse_tst_node_t* node, const char* key, bool* deleted) {
    if (!node) return NULL;

    if (*key < node->c) {
        node->left = delete_node(node->left, key, deleted);
    } else if (*key > node->c) {
        node->right = delete_node(node->right, key, deleted);
    } else {
        if (*(key + 1) != '\0') {
            node->mid = delete_node(node->mid, key + 1, deleted);
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
        free(node);
        return NULL;
    }

    return node;
}

bool qihse_trinary_trie_delete(qihse_trinary_trie_t* trie, const char* key) {
    if (!trie || !key || *key == '\0') return false;
    bool deleted = false;
    trie->root = delete_node(trie->root, key, &deleted);
    return deleted;
}
