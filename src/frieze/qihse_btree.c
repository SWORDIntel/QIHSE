#define _GNU_SOURCE
/* qihse_btree.c — Phase 3.1/3.3 cache-conscious B+ tree index.
 *
 * Design notes
 * ------------
 *  * Leaf nodes are page-aligned (4 KB) and store entries compactly
 *    (key_len + row_id + key bytes) for TLB/cache efficiency.
 *  * Internal nodes store child pointers and individually-allocated separator
 *    keys (internal nodes are few relative to leaves, so the extra indirection
 *    is acceptable and keeps the code simple and correct).
 *  * Leaf nodes are linked left-to-right in a singly-linked list, enabling
 *    O(log_f N) descent + O(k) sequential leaf walk for range scans.
 *  * Keys are arbitrary byte strings compared with memcmp; sort order is
 *    established by the caller via qihse_btree_serialize_key().
 *  * A per-tree pthread rwlock guards all public operations.
 */
#include "qihse_btree.h"
#include "qihse_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Leaf node: compact variable-length entries in a 4KB page            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t key_len;
    uint64_t row_id;
    /* key bytes follow */
} leaf_entry_t;

typedef struct btree_node {
    uint8_t  is_leaf;
    uint16_t count;
    uint32_t capacity;
    struct btree_node* parent;
    struct btree_node* next_leaf;   /* leaf-only: right sibling */
    union {
        /* leaf: compact entries in data[] */
        /* internal: arrays below */
        struct {
            struct btree_node** children;  /* count+1 children */
            unsigned char**     keys;      /* count separator keys */
            uint16_t*           key_lens;  /* count key lengths */
        } in;
    } u;
    char data[];                       /* leaf entries */
} btree_node_t;

struct qihse_btree {
    btree_node_t* root;
    uint32_t      fanout;
    size_t        count;
    pthread_rwlock_t lock;
};

struct qihse_btree_cursor {
    qihse_btree_t* tree;
    btree_node_t*  leaf;
    uint16_t       idx;
    unsigned char* min_key;  size_t min_len;  bool has_min;
    unsigned char* max_key;  size_t max_len;  bool has_max;
    bool prefix_mode;
    unsigned char* prefix;   size_t prefix_len;
    bool exhausted;
};

/* ------------------------------------------------------------------ */
/* Key comparison                                                      */
/* ------------------------------------------------------------------ */

static int key_cmp(const void* a, size_t alen, const void* b, size_t blen) {
    size_t n = alen < blen ? alen : blen;
    int c = n ? memcmp(a, b, n) : 0;
    if (c != 0) return c;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Leaf node helpers                                                   */
/* ------------------------------------------------------------------ */

static leaf_entry_t* leaf_entry(btree_node_t* n, uint16_t i) {
    char* p = n->data;
    for (uint16_t k = 0; k < i; k++) {
        leaf_entry_t* e = (leaf_entry_t*)p;
        p += sizeof(leaf_entry_t) + e->key_len;
    }
    return (leaf_entry_t*)p;
}

static unsigned char* leaf_key(leaf_entry_t* e) {
    return (unsigned char*)e + sizeof(leaf_entry_t);
}

static uint16_t leaf_lower_bound(btree_node_t* n, const void* key, size_t klen) {
    uint16_t lo = 0, hi = n->count;
    while (lo < hi) {
        uint16_t mid = lo + (hi - lo) / 2;
        leaf_entry_t* e = leaf_entry(n, mid);
        if (key_cmp(leaf_key(e), e->key_len, key, klen) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static void leaf_insert_at(btree_node_t* n, uint16_t pos,
                           const void* key, size_t klen, uint64_t row_id) {
    char* src = (char*)leaf_entry(n, pos);
    char* end = (char*)leaf_entry(n, n->count);
    size_t tail = end - src;
    if (tail) memmove(src + sizeof(leaf_entry_t) + klen, src, tail);
    leaf_entry_t* e = (leaf_entry_t*)src;
    e->key_len = (uint16_t)klen;
    e->row_id = row_id;
    memcpy(leaf_key(e), key, klen);
    n->count++;
}

static void leaf_remove_at(btree_node_t* n, uint16_t pos) {
    if (pos + 1 >= n->count) { n->count--; return; }
    char* dst = (char*)leaf_entry(n, pos);
    char* src = (char*)leaf_entry(n, pos + 1);
    char* end = (char*)leaf_entry(n, n->count);
    size_t tail = end - src;
    if (tail) memmove(dst, src, tail);
    n->count--;
}

/* ------------------------------------------------------------------ */
/* Node allocation                                                     */
/* ------------------------------------------------------------------ */

static btree_node_t* node_alloc_leaf(uint32_t fanout) {
    btree_node_t* n = (btree_node_t*)calloc(1, QIHSE_BTREE_PAGE_SIZE);
    if (!n) return NULL;
    n->is_leaf = 1;
    n->count = 0;
    n->capacity = fanout ? fanout : QIHSE_BTREE_DEFAULT_FANOUT;
    n->parent = NULL;
    n->next_leaf = NULL;
    return n;
}

static btree_node_t* node_alloc_internal(uint32_t fanout) {
    uint32_t cap = fanout ? fanout : QIHSE_BTREE_DEFAULT_FANOUT;
    btree_node_t* n = (btree_node_t*)calloc(1, sizeof(btree_node_t));
    if (!n) return NULL;
    n->is_leaf = 0;
    n->count = 0;
    n->capacity = cap;
    n->parent = NULL;
    n->next_leaf = NULL;
    n->u.in.children  = (btree_node_t**)calloc(cap + 2, sizeof(btree_node_t*));
    n->u.in.keys      = (unsigned char**)calloc(cap + 1, sizeof(unsigned char*));
    n->u.in.key_lens  = (uint16_t*)calloc(cap + 1, sizeof(uint16_t));
    if (!n->u.in.children || !n->u.in.keys || !n->u.in.key_lens) {
        free(n->u.in.children); free(n->u.in.keys); free(n->u.in.key_lens);
        free(n);
        return NULL;
    }
    return n;
}

static void node_free_recursive(btree_node_t* n) {
    if (!n) return;
    if (!n->is_leaf) {
        for (uint16_t i = 0; i <= n->count; i++)
            node_free_recursive(n->u.in.children[i]);
        for (uint16_t i = 0; i < n->count; i++)
            free(n->u.in.keys[i]);
        free(n->u.in.children);
        free(n->u.in.keys);
        free(n->u.in.key_lens);
    }
    free(n);
}

/* ------------------------------------------------------------------ */
/* Internal node helpers                                               */
/* ------------------------------------------------------------------ */

static uint16_t internal_find_child(btree_node_t* n, const void* key, size_t klen) {
    /* keys[i] separates children[i] and children[i+1].
     * If key < keys[0] -> child 0; if key >= keys[i] -> child i+1. */
    uint16_t lo = 0, hi = n->count;
    while (lo < hi) {
        uint16_t mid = lo + (hi - lo) / 2;
        if (key_cmp(n->u.in.keys[mid], n->u.in.key_lens[mid], key, klen) <= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static void internal_insert_child(btree_node_t* n, uint16_t pos,
                                  const void* key, size_t klen,
                                  btree_node_t* child) {
    /* Shift keys[pos..count-1] and children[pos+1..count] right by one. */
    for (uint16_t i = n->count; i > pos; i--) {
        n->u.in.keys[i] = n->u.in.keys[i - 1];
        n->u.in.key_lens[i] = n->u.in.key_lens[i - 1];
    }
    for (uint16_t i = n->count + 1; i > pos + 1; i--)
        n->u.in.children[i] = n->u.in.children[i - 1];
    /* Insert key at pos, child at pos+1. */
    n->u.in.keys[pos] = (unsigned char*)malloc(klen);
    memcpy(n->u.in.keys[pos], key, klen);
    n->u.in.key_lens[pos] = (uint16_t)klen;
    n->u.in.children[pos + 1] = child;
    child->parent = n;
    n->count++;
}

static btree_node_t* leaf_split(btree_node_t* n, uint32_t fanout,
                                void** sep_key, size_t* sep_len) {
    uint16_t total = n->count;
    uint16_t mid = total / 2;
    btree_node_t* right = node_alloc_leaf(fanout);
    if (!right) return NULL;
    char* src = (char*)leaf_entry(n, mid);
    char* end = (char*)leaf_entry(n, total);
    size_t bytes = end - src;
    memcpy(right->data, src, bytes);
    right->count = total - mid;
    n->count = mid;
    leaf_entry_t* e0 = (leaf_entry_t*)right->data;
    *sep_len = e0->key_len;
    *sep_key = malloc(e0->key_len);
    memcpy(*sep_key, leaf_key(e0), e0->key_len);
    right->next_leaf = n->next_leaf;
    n->next_leaf = right;
    return right;
}

static btree_node_t* internal_split(btree_node_t* n, uint32_t fanout,
                                    void** promo_key, size_t* promo_len) {
    uint16_t total = n->count;
    uint16_t mid = total / 2;
    btree_node_t* right = node_alloc_internal(fanout);
    if (!right) return NULL;
    /* Promote key[mid]. Right gets keys[mid+1..total-1], children[mid+1..total]. */
    *promo_len = n->u.in.key_lens[mid];
    *promo_key = malloc(*promo_len);
    memcpy(*promo_key, n->u.in.keys[mid], *promo_len);
    /* Right's children and keys. */
    right->u.in.children[0] = n->u.in.children[mid + 1];
    right->u.in.children[0]->parent = right;
    for (uint16_t i = mid + 1; i < total; i++) {
        uint16_t ri = i - (mid + 1);
        right->u.in.keys[ri] = n->u.in.keys[i];
        right->u.in.key_lens[ri] = n->u.in.key_lens[i];
        right->u.in.children[ri + 1] = n->u.in.children[i + 1];
        right->u.in.children[ri + 1]->parent = right;
    }
    right->count = total - mid - 1;
    /* Free the promoted key's slot (we copied it). Don't free moved keys. */
    free(n->u.in.keys[mid]);
    n->u.in.keys[mid] = NULL;
    n->count = mid;
    return right;
}

/* ------------------------------------------------------------------ */
/* Descent                                                             */
/* ------------------------------------------------------------------ */

static btree_node_t* descend_to_leaf(btree_node_t* root,
                                     const void* key, size_t klen) {
    btree_node_t* n = root;
    while (n && !n->is_leaf) {
        uint16_t ci = internal_find_child(n, key, klen);
        n = n->u.in.children[ci];
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

qihse_btree_t* qihse_btree_create(uint32_t fanout) {
    qihse_btree_t* t = (qihse_btree_t*)calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->fanout = fanout ? fanout : QIHSE_BTREE_DEFAULT_FANOUT;
    t->count = 0;
    t->root = node_alloc_leaf(t->fanout);
    if (!t->root) { free(t); return NULL; }
    pthread_rwlock_init(&t->lock, NULL);
    return t;
}

void qihse_btree_destroy(qihse_btree_t* tree) {
    if (!tree) return;
    pthread_rwlock_wrlock(&tree->lock);
    node_free_recursive(tree->root);
    pthread_rwlock_unlock(&tree->lock);
    pthread_rwlock_destroy(&tree->lock);
    free(tree);
}

bool qihse_btree_insert(qihse_btree_t* tree,
                        const void* key, size_t key_len,
                        uint64_t row_id) {
    if (!tree || !key) return false;
    pthread_rwlock_wrlock(&tree->lock);

    btree_node_t* leaf = descend_to_leaf(tree->root, key, key_len);
    if (!leaf) { pthread_rwlock_unlock(&tree->lock); return false; }

    uint16_t pos = leaf_lower_bound(leaf, key, key_len);
    if (pos < leaf->count) {
        leaf_entry_t* e = leaf_entry(leaf, pos);
        if (e->key_len == key_len && memcmp(leaf_key(e), key, key_len) == 0) {
            e->row_id = row_id;
            pthread_rwlock_unlock(&tree->lock);
            return true;
        }
    }

    if (leaf->count < leaf->capacity) {
        leaf_insert_at(leaf, pos, key, key_len, row_id);
        tree->count++;
        pthread_rwlock_unlock(&tree->lock);
        return true;
    }

    /* Split: insert (overflow by 1), then split. */
    leaf_insert_at(leaf, pos, key, key_len, row_id);
    tree->count++;

    void* sep_key; size_t sep_len;
    btree_node_t* right = leaf_split(leaf, tree->fanout, &sep_key, &sep_len);
    if (!right) { pthread_rwlock_unlock(&tree->lock); return false; }

    btree_node_t* child_left = leaf;
    btree_node_t* child_right = right;
    void* cur_key = sep_key;
    size_t cur_len = sep_len;

    while (child_left->parent) {
        btree_node_t* parent = child_left->parent;
        uint16_t pi = 0;
        for (; pi <= parent->count; pi++)
            if (parent->u.in.children[pi] == child_left) break;

        if (parent->count < parent->capacity) {
            internal_insert_child(parent, pi, cur_key, cur_len, child_right);
            free(cur_key);
            child_right = NULL;
            break;
        }
        /* Parent full: insert (overflow), then split. */
        internal_insert_child(parent, pi, cur_key, cur_len, child_right);
        free(cur_key);

        void* promo_key; size_t promo_len;
        btree_node_t* parent_right = internal_split(parent, tree->fanout,
                                                    &promo_key, &promo_len);
        if (!parent_right) break;
        child_left = parent;
        child_right = parent_right;
        cur_key = promo_key;
        cur_len = promo_len;
    }

    if (child_right) {
        /* New root. */
        btree_node_t* new_root = node_alloc_internal(tree->fanout);
        if (new_root) {
            new_root->u.in.children[0] = child_left;
            child_left->parent = new_root;
            new_root->u.in.keys[0] = (unsigned char*)malloc(cur_len);
            memcpy(new_root->u.in.keys[0], cur_key, cur_len);
            new_root->u.in.key_lens[0] = (uint16_t)cur_len;
            new_root->u.in.children[1] = child_right;
            child_right->parent = new_root;
            new_root->count = 1;
            tree->root = new_root;
        }
        free(cur_key);
    }

    pthread_rwlock_unlock(&tree->lock);
    return true;
}

bool qihse_btree_lookup(qihse_btree_t* tree,
                        const void* key, size_t key_len,
                        uint64_t* out) {
    if (!tree || !key) return false;
    pthread_rwlock_rdlock(&tree->lock);
    btree_node_t* leaf = descend_to_leaf(tree->root, key, key_len);
    if (!leaf) { pthread_rwlock_unlock(&tree->lock); return false; }
    uint16_t pos = leaf_lower_bound(leaf, key, key_len);
    bool found = false;
    if (pos < leaf->count) {
        leaf_entry_t* e = leaf_entry(leaf, pos);
        if (e->key_len == key_len && memcmp(leaf_key(e), key, key_len) == 0) {
            if (out) *out = e->row_id;
            found = true;
        }
    }
    pthread_rwlock_unlock(&tree->lock);
    return found;
}

bool qihse_btree_delete(qihse_btree_t* tree,
                        const void* key, size_t key_len,
                        uint64_t* row_id_out) {
    if (!tree || !key) return false;
    pthread_rwlock_wrlock(&tree->lock);
    btree_node_t* leaf = descend_to_leaf(tree->root, key, key_len);
    if (!leaf) { pthread_rwlock_unlock(&tree->lock); return false; }
    uint16_t pos = leaf_lower_bound(leaf, key, key_len);
    bool found = false;
    if (pos < leaf->count) {
        leaf_entry_t* e = leaf_entry(leaf, pos);
        if (e->key_len == key_len && memcmp(leaf_key(e), key, key_len) == 0) {
            if (row_id_out) *row_id_out = e->row_id;
            leaf_remove_at(leaf, pos);
            tree->count--;
            found = true;
        }
    }
    pthread_rwlock_unlock(&tree->lock);
    return found;
}

size_t qihse_btree_size(const qihse_btree_t* tree) {
    if (!tree) return 0;
    return tree->count;
}

/* ------------------------------------------------------------------ */
/* Cursor / range scan                                                 */
/* ------------------------------------------------------------------ */

static bool cursor_in_range(const qihse_btree_cursor_t* c,
                            const void* key, size_t klen) {
    if (c->prefix_mode) {
        if (klen < c->prefix_len) return false;
        if (memcmp(key, c->prefix, c->prefix_len) != 0) return false;
        return true;
    }
    if (c->has_min && key_cmp(key, klen, c->min_key, c->min_len) < 0) return false;
    if (c->has_max && key_cmp(key, klen, c->max_key, c->max_len) > 0) return false;
    return true;
}

static bool cursor_past_range(const qihse_btree_cursor_t* c,
                              const void* key, size_t klen) {
    if (c->prefix_mode)
        return key_cmp(key, klen, c->prefix, c->prefix_len) > 0;
    if (c->has_max)
        return key_cmp(key, klen, c->max_key, c->max_len) > 0;
    return false;
}

static bool cursor_advance_to_first(qihse_btree_cursor_t* c) {
    btree_node_t* leaf;
    if (c->prefix_mode)
        leaf = descend_to_leaf(c->tree->root, c->prefix, c->prefix_len);
    else if (c->has_min)
        leaf = descend_to_leaf(c->tree->root, c->min_key, c->min_len);
    else {
        leaf = c->tree->root;
        while (leaf && !leaf->is_leaf) leaf = leaf->u.in.children[0];
    }
    if (!leaf) { c->exhausted = true; return false; }

    c->leaf = leaf;
    c->idx = 0;
    while (c->leaf) {
        for (; c->idx < c->leaf->count; c->idx++) {
            leaf_entry_t* e = leaf_entry(c->leaf, c->idx);
            if (cursor_in_range(c, leaf_key(e), e->key_len)) return true;
            if (cursor_past_range(c, leaf_key(e), e->key_len)) {
                c->exhausted = true;
                return false;
            }
        }
        c->leaf = c->leaf->next_leaf;
        c->idx = 0;
    }
    c->exhausted = true;
    return false;
}

qihse_btree_cursor_t* qihse_btree_range_open(qihse_btree_t* tree,
                                             const void* min_key, size_t min_len,
                                             const void* max_key, size_t max_len) {
    if (!tree) return NULL;
    qihse_btree_cursor_t* c = (qihse_btree_cursor_t*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->tree = tree;
    if (min_key && min_len) {
        c->min_key = (unsigned char*)malloc(min_len);
        memcpy(c->min_key, min_key, min_len);
        c->min_len = min_len; c->has_min = true;
    }
    if (max_key && max_len) {
        c->max_key = (unsigned char*)malloc(max_len);
        memcpy(c->max_key, max_key, max_len);
        c->max_len = max_len; c->has_max = true;
    }
    pthread_rwlock_rdlock(&tree->lock);
    if (!cursor_advance_to_first(c)) {
        pthread_rwlock_unlock(&tree->lock);
        free(c->min_key); free(c->max_key); free(c->prefix);
        free(c);
        return NULL;
    }
    return c;
}

qihse_btree_cursor_t* qihse_btree_prefix_open(qihse_btree_t* tree,
                                              const void* prefix, size_t prefix_len) {
    if (!tree || !prefix || !prefix_len) return NULL;
    qihse_btree_cursor_t* c = (qihse_btree_cursor_t*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->tree = tree;
    c->prefix_mode = true;
    c->prefix = (unsigned char*)malloc(prefix_len);
    memcpy(c->prefix, prefix, prefix_len);
    c->prefix_len = prefix_len;
    pthread_rwlock_rdlock(&tree->lock);
    if (!cursor_advance_to_first(c)) {
        pthread_rwlock_unlock(&tree->lock);
        free(c->prefix); free(c->min_key); free(c->max_key);
        free(c);
        return NULL;
    }
    return c;
}

bool qihse_btree_cursor_next(qihse_btree_cursor_t* cur) {
    if (!cur || cur->exhausted) return false;
    cur->idx++;
    while (cur->leaf) {
        for (; cur->idx < cur->leaf->count; cur->idx++) {
            leaf_entry_t* e = leaf_entry(cur->leaf, cur->idx);
            if (cursor_in_range(cur, leaf_key(e), e->key_len)) return true;
            if (cursor_past_range(cur, leaf_key(e), e->key_len)) {
                cur->exhausted = true;
                return false;
            }
        }
        cur->leaf = cur->leaf->next_leaf;
        cur->idx = 0;
    }
    cur->exhausted = true;
    return false;
}

bool qihse_btree_cursor_get(const qihse_btree_cursor_t* cur,
                            const void** key_out, size_t* key_len_out,
                            uint64_t* row_id_out) {
    if (!cur || cur->exhausted || !cur->leaf) return false;
    if (cur->idx >= cur->leaf->count) return false;
    leaf_entry_t* e = leaf_entry(cur->leaf, cur->idx);
    if (key_out) *key_out = leaf_key(e);
    if (key_len_out) *key_len_out = e->key_len;
    if (row_id_out) *row_id_out = e->row_id;
    return true;
}

void qihse_btree_cursor_close(qihse_btree_cursor_t* cur) {
    if (!cur) return;
    pthread_rwlock_unlock(&cur->tree->lock);
    free(cur->min_key);
    free(cur->max_key);
    free(cur->prefix);
    free(cur);
}

/* ------------------------------------------------------------------ */
/* Composite key serialization (Phase 3.3)                             */
/* ------------------------------------------------------------------ */

static void put_u8(unsigned char** p, unsigned char v) { **p = v; (*p)++; }
static void put_bytes(unsigned char** p, const void* src, size_t n) {
    memcpy(*p, src, n); *p += n;
}

static size_t col_serialized_len(const qihse_btree_col_t* col) {
    switch (col->type) {
        case QIHSE_BTREE_COL_INT32:   return 4;
        case QIHSE_BTREE_COL_INT64:   return 8;
        case QIHSE_BTREE_COL_FLOAT64: return 8;
        case QIHSE_BTREE_COL_STRING:  return col->len + 1;
        default: return 0;
    }
}

static void encode_int64_sortable(unsigned char** p, int64_t v) {
    uint64_t u = (uint64_t)v ^ ((uint64_t)1 << 63);
    unsigned char buf[8];
    for (int i = 0; i < 8; i++) buf[i] = (unsigned char)(u >> (56 - 8 * i));
    put_bytes(p, buf, 8);
}

static void encode_int32_sortable(unsigned char** p, int32_t v) {
    uint32_t u = (uint32_t)v ^ ((uint32_t)1 << 31);
    unsigned char buf[4];
    for (int i = 0; i < 4; i++) buf[i] = (unsigned char)(u >> (24 - 8 * i));
    put_bytes(p, buf, 4);
}

static void encode_float64_sortable(unsigned char** p, double d) {
    uint64_t u; memcpy(&u, &d, 8);
    uint64_t mask = (u >> 63) & 1 ? 0xFFFFFFFFFFFFFFFFULL : ((uint64_t)1 << 63);
    u ^= mask;
    unsigned char buf[8];
    for (int i = 0; i < 8; i++) buf[i] = (unsigned char)(u >> (56 - 8 * i));
    put_bytes(p, buf, 8);
}

int qihse_btree_serialize_key(const qihse_btree_col_t* cols, size_t ncol,
                              void* out_buf, size_t* out_len) {
    if (!cols || !out_len) return -1;
    size_t total = 0;
    for (size_t i = 0; i < ncol; i++) total += col_serialized_len(&cols[i]);
    if (!out_buf) { *out_len = total; return 0; }
    if (*out_len < total) { *out_len = total; return -1; }
    unsigned char* p = (unsigned char*)out_buf;
    for (size_t i = 0; i < ncol; i++) {
        const qihse_btree_col_t* c = &cols[i];
        switch (c->type) {
            case QIHSE_BTREE_COL_INT32:
                encode_int32_sortable(&p, *(const int32_t*)c->data); break;
            case QIHSE_BTREE_COL_INT64:
                encode_int64_sortable(&p, *(const int64_t*)c->data); break;
            case QIHSE_BTREE_COL_FLOAT64:
                encode_float64_sortable(&p, *(const double*)c->data); break;
            case QIHSE_BTREE_COL_STRING:
                put_bytes(&p, c->data, c->len);
                put_u8(&p, 0x00);
                break;
            default: return -1;
        }
    }
    *out_len = total;
    return 0;
}

int qihse_btree_serialize_key_alloc(const qihse_btree_col_t* cols, size_t ncol,
                                    void** out_buf, size_t* out_len) {
    if (!out_buf || !out_len) return -1;
    size_t need = 0;
    if (qihse_btree_serialize_key(cols, ncol, NULL, &need) != 0) return -1;
    void* buf = malloc(need ? need : 1);
    if (!buf) return -1;
    size_t cap = need;
    if (qihse_btree_serialize_key(cols, ncol, buf, &cap) != 0) {
        free(buf); return -1;
    }
    *out_buf = buf; *out_len = need;
    return 0;
}
