#include "qihse_fts.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define TRIGRAM_HASH_BITS 20u
#define TRIGRAM_HASH_SIZE (1u << TRIGRAM_HASH_BITS)
#define TRIGRAM_HASH_MASK (TRIGRAM_HASH_SIZE - 1u)
#define QFTS_MAGIC 0x53544651u
#define QFTS_VERSION 1u
#define QFTS_DOC_DISK_BYTES 20u
#define QFTS_MAX_QUERY_TOKEN 255u
#define QFTS_MAX_DOCS UINT32_MAX

typedef struct {
    uint32_t doc_idx;
    uint32_t term_frequency;
    uint32_t capacity;
    uint32_t* positions;
} doc_posting_t;

typedef struct {
    doc_posting_t* docs;
    uint32_t count;
    uint32_t capacity;
} posting_list_t;

typedef struct {
    uint32_t key;
    posting_list_t* list;
} trigram_entry_t;

typedef struct {
    uint64_t doc_id;
    uint32_t length;
    uint16_t classification;
    uint16_t sci_compartment;
    qihse_keystone_class_t semantic_class;
} doc_info_t;

struct qihse_fts_index {
    trigram_entry_t* table;
    size_t trigram_count;
    doc_info_t* docs;
    uint32_t doc_count;
    uint32_t doc_capacity;
    uint64_t total_doc_length;
    bool valid;
};

static bool semantic_class_valid(qihse_keystone_class_t cls) {
    return cls >= QIHSE_KEYSTONE_CLASS_UNKNOWN && cls <= QIHSE_KEYSTONE_CLASS_CONSUMER;
}

static uint32_t pack_trigram(const char t[3]) {
    return ((uint32_t)(unsigned char)t[0] << 16) |
           ((uint32_t)(unsigned char)t[1] << 8) |
           (uint32_t)(unsigned char)t[2];
}

static uint32_t hash_trigram(uint32_t key) {
    key ^= key >> 16;
    key *= 0x7feb352du;
    key ^= key >> 15;
    key *= 0x846ca68bu;
    key ^= key >> 16;
    return key & TRIGRAM_HASH_MASK;
}

static trigram_entry_t* trigram_find_slot(qihse_fts_index_t* index, uint32_t key, bool create) {
    if (!index || !index->table || key == 0u) return NULL;
    uint32_t h = hash_trigram(key);
    for (size_t i = 0u; i < TRIGRAM_HASH_SIZE; i++) {
        trigram_entry_t* e = &index->table[(h + (uint32_t)i) & TRIGRAM_HASH_MASK];
        if (e->key == key) return e;
        if (e->key == 0u) {
            if (!create) return NULL;
            e->list = (posting_list_t*)calloc(1u, sizeof(*e->list));
            if (!e->list) return NULL;
            e->key = key;
            index->trigram_count++;
            return e;
        }
    }
    return NULL;
}

static bool posting_add_position(posting_list_t* list, uint32_t doc_idx, uint32_t position) {
    if (!list) return false;
    doc_posting_t* p = NULL;
    if (list->count != 0u && list->docs[list->count - 1u].doc_idx == doc_idx) {
        p = &list->docs[list->count - 1u];
    } else {
        if (list->count == list->capacity) {
            uint32_t new_cap = list->capacity ? list->capacity * 2u : 4u;
            if (new_cap < list->capacity ||
                (new_cap != 0u && SIZE_MAX / (size_t)new_cap < sizeof(*list->docs))) return false;
            doc_posting_t* next = (doc_posting_t*)realloc(list->docs, (size_t)new_cap * sizeof(*next));
            if (!next) return false;
            memset(next + list->capacity, 0, (size_t)(new_cap - list->capacity) * sizeof(*next));
            list->docs = next;
            list->capacity = new_cap;
        }
        p = &list->docs[list->count++];
        memset(p, 0, sizeof(*p));
        p->doc_idx = doc_idx;
    }
    if (p->term_frequency == p->capacity) {
        uint32_t new_cap = p->capacity ? p->capacity * 2u : 4u;
        if (new_cap < p->capacity ||
            (new_cap != 0u && SIZE_MAX / (size_t)new_cap < sizeof(uint32_t))) return false;
        uint32_t* next = (uint32_t*)realloc(p->positions, (size_t)new_cap * sizeof(uint32_t));
        if (!next) return false;
        p->positions = next;
        p->capacity = new_cap;
    }
    p->positions[p->term_frequency++] = position;
    return true;
}

qihse_fts_index_t* qihse_fts_create(void) {
    qihse_fts_index_t* idx = (qihse_fts_index_t*)calloc(1u, sizeof(*idx));
    if (!idx) return NULL;
    idx->table = (trigram_entry_t*)calloc(TRIGRAM_HASH_SIZE, sizeof(*idx->table));
    if (!idx->table) { free(idx); return NULL; }
    idx->doc_capacity = 1024u;
    idx->docs = (doc_info_t*)calloc(idx->doc_capacity, sizeof(*idx->docs));
    if (!idx->docs) { free(idx->table); free(idx); return NULL; }
    idx->valid = true;
    return idx;
}

void qihse_fts_destroy(qihse_fts_index_t* index) {
    if (!index) return;
    if (index->table) {
        for (size_t i = 0u; i < TRIGRAM_HASH_SIZE; i++) {
            posting_list_t* list = index->table[i].list;
            if (!list) continue;
            for (uint32_t j = 0u; j < list->count; j++) free(list->docs[j].positions);
            free(list->docs);
            free(list);
        }
    }
    free(index->table);
    free(index->docs);
    free(index);
}

static bool ensure_doc_capacity(qihse_fts_index_t* index) {
    if (index->doc_count < index->doc_capacity) return true;
    if (index->doc_capacity >= QFTS_MAX_DOCS / 2u) return false;
    uint32_t new_cap = index->doc_capacity ? index->doc_capacity * 2u : 1024u;
    if (new_cap != 0u && SIZE_MAX / (size_t)new_cap < sizeof(*index->docs)) return false;
    doc_info_t* next = (doc_info_t*)realloc(index->docs, (size_t)new_cap * sizeof(*next));
    if (!next) return false;
    memset(next + index->doc_capacity, 0, (size_t)(new_cap - index->doc_capacity) * sizeof(*next));
    index->docs = next;
    index->doc_capacity = new_cap;
    return true;
}

bool qihse_fts_add_document_user(qihse_fts_index_t* index, uint64_t doc_id,
                                 const char* text, size_t length,
                                 uint16_t classification, uint16_t sci_compartment,
                                 qihse_keystone_class_t semantic_class,
                                 qihse_user_t* user) {
    if (!index || !index->valid || !text || !semantic_class_valid(semantic_class)) return false;
    if (!qihse_auth_can_access(user, classification, sci_compartment)) return false;
    if (index->doc_count == QFTS_MAX_DOCS || !ensure_doc_capacity(index)) return false;

    uint32_t doc_idx = index->doc_count;
    uint64_t doc_trigrams = 0u;
    size_t i = 0u;
    while (i < length) {
        while (i < length && !isalnum((unsigned char)text[i])) i++;
        if (i >= length) break;
        size_t start = i;
        while (i < length && isalnum((unsigned char)text[i])) i++;
        size_t token_len = i - start;
        if (token_len == 0u) continue;
        if (token_len > QFTS_MAX_QUERY_TOKEN) token_len = QFTS_MAX_QUERY_TOKEN;
        char word[QFTS_MAX_QUERY_TOKEN + 1u];
        for (size_t j = 0u; j < token_len; j++) word[j] = (char)tolower((unsigned char)text[start + j]);
        word[token_len] = '\0';
        size_t ngrams = token_len < 3u ? 1u : token_len - 2u;
        if (doc_trigrams > UINT32_MAX - ngrams) { index->valid = false; return false; }
        for (size_t t = 0u; t < ngrams; t++) {
            char tri[3] = {0, 0, 0};
            tri[0] = word[t];
            if (token_len >= 2u) tri[1] = word[t + 1u];
            if (token_len >= 3u) tri[2] = word[t + 2u];
            uint32_t key = pack_trigram(tri);
            trigram_entry_t* e = trigram_find_slot(index, key, true);
            if (!e || !posting_add_position(e->list, doc_idx, (uint32_t)(doc_trigrams + t))) {
                index->valid = false;
                return false;
            }
        }
        doc_trigrams += ngrams;
    }

    doc_info_t* d = &index->docs[doc_idx];
    d->doc_id = doc_id;
    d->length = (uint32_t)doc_trigrams;
    d->classification = classification;
    d->sci_compartment = sci_compartment;
    d->semantic_class = semantic_class;
    index->doc_count++;
    index->total_doc_length += doc_trigrams;
    return true;
}

bool qihse_fts_add_document(qihse_fts_index_t* index, uint64_t doc_id,
                            const char* text, size_t length,
                            uint16_t classification, uint16_t sci_compartment,
                            qihse_keystone_class_t semantic_class) {
    return qihse_fts_add_document_user(index, doc_id, text, length, classification,
                                       sci_compartment, semantic_class, NULL);
}

static bool doc_visible(const qihse_fts_index_t* index, uint32_t i,
                        qihse_user_t* user, uint8_t semantic_mask) {
    if (!index || i >= index->doc_count) return false;
    const doc_info_t* d = &index->docs[i];
    if (!qihse_auth_can_access(user, d->classification, d->sci_compartment)) return false;
    if (semantic_mask != 0u) {
        if (!semantic_class_valid(d->semantic_class)) return false;
        uint8_t bit = (uint8_t)(1u << (uint8_t)d->semantic_class);
        if ((semantic_mask & bit) == 0u) return false;
    }
    return true;
}

static posting_list_t* lookup_word_trigram(qihse_fts_index_t* index, const char tri[3]) {
    trigram_entry_t* e = trigram_find_slot(index, pack_trigram(tri), false);
    return e ? e->list : NULL;
}

int qihse_fts_search_user_filtered(qihse_fts_index_t* index, const char* query,
                                   qihse_user_t* user, qihse_fts_result_t* results,
                                   int top_k, uint8_t semantic_class_mask) {
    if (!index || !index->valid || !query || !results || top_k <= 0 || index->doc_count == 0u) return 0;
    uint8_t* visible = (uint8_t*)calloc(index->doc_count, 1u);
    float* scores = (float*)calloc(index->doc_count, sizeof(float));
    if (!visible || !scores) { free(visible); free(scores); return 0; }
    uint32_t visible_n = 0u;
    uint64_t visible_total_len = 0u;
    for (uint32_t j = 0u; j < index->doc_count; j++) {
        if (doc_visible(index, j, user, semantic_class_mask)) {
            visible[j] = 1u;
            visible_n++;
            visible_total_len += index->docs[j].length;
        }
    }
    if (visible_n == 0u) { free(visible); free(scores); return 0; }
    float avgdl = (float)visible_total_len / (float)visible_n;
    if (avgdl <= 0.0f) avgdl = 1.0f;
    const float k1 = 1.2f, b = 0.75f;

    size_t qlen = strlen(query), i = 0u;
    while (i < qlen) {
        while (i < qlen && !isalnum((unsigned char)query[i])) i++;
        if (i >= qlen) break;
        size_t start = i;
        while (i < qlen && isalnum((unsigned char)query[i])) i++;
        size_t token_len = i - start;
        if (token_len == 0u) continue;
        if (token_len > QFTS_MAX_QUERY_TOKEN) token_len = QFTS_MAX_QUERY_TOKEN;
        char word[QFTS_MAX_QUERY_TOKEN + 1u];
        for (size_t j = 0u; j < token_len; j++) word[j] = (char)tolower((unsigned char)query[start + j]);
        word[token_len] = '\0';
        size_t ngrams = token_len < 3u ? 1u : token_len - 2u;
        for (size_t t = 0u; t < ngrams; t++) {
            char tri[3] = {0, 0, 0};
            tri[0] = word[t];
            if (token_len >= 2u) tri[1] = word[t + 1u];
            if (token_len >= 3u) tri[2] = word[t + 2u];
            posting_list_t* list = lookup_word_trigram(index, tri);
            if (!list) continue;
            uint32_t visible_df = 0u;
            for (uint32_t p = 0u; p < list->count; p++) {
                if (list->docs[p].doc_idx < index->doc_count && visible[list->docs[p].doc_idx]) visible_df++;
            }
            if (visible_df == 0u) continue;
            float idf = logf((((float)visible_n - (float)visible_df + 0.5f) /
                              ((float)visible_df + 0.5f)) + 1.0f);
            if (idf < 0.0f) idf = 0.0f;
            for (uint32_t p = 0u; p < list->count; p++) {
                doc_posting_t* post = &list->docs[p];
                if (post->doc_idx >= index->doc_count || !visible[post->doc_idx]) continue;
                uint32_t dl = index->docs[post->doc_idx].length;
                float tf = (float)post->term_frequency;
                float denom = tf + k1 * (1.0f - b + b * ((float)dl / avgdl));
                if (denom > 0.0f) scores[post->doc_idx] += idf * (tf * (k1 + 1.0f) / denom);
            }
        }
    }

    int out = 0;
    while (out < top_k) {
        int best = -1;
        float best_score = 0.0f;
        for (uint32_t j = 0u; j < index->doc_count; j++) {
            if (visible[j] && scores[j] > best_score) { best_score = scores[j]; best = (int)j; }
        }
        if (best < 0 || best_score <= 0.0f) break;
        results[out].doc_id = index->docs[best].doc_id;
        results[out].bm25_score = best_score;
        results[out].semantic_class = index->docs[best].semantic_class;
        scores[best] = -1.0f;
        out++;
    }
    free(visible);
    free(scores);
    return out;
}

int qihse_fts_search_user(qihse_fts_index_t* index, const char* query,
                          qihse_user_t* user, qihse_fts_result_t* results, int top_k) {
    return qihse_fts_search_user_filtered(index, query, user, results, top_k, 0u);
}

qihse_keystone_class_t qihse_fts_get_doc_semantic_class_user(qihse_fts_index_t* index,
                                                               uint64_t doc_id,
                                                               qihse_user_t* user) {
    if (!index || !index->valid) return QIHSE_KEYSTONE_CLASS_UNKNOWN;
    for (uint32_t i = 0u; i < index->doc_count; i++) {
        if (index->docs[i].doc_id == doc_id) {
            if (!qihse_auth_can_access(user, index->docs[i].classification, index->docs[i].sci_compartment))
                return QIHSE_KEYSTONE_CLASS_UNKNOWN;
            return semantic_class_valid(index->docs[i].semantic_class) ?
                   index->docs[i].semantic_class : QIHSE_KEYSTONE_CLASS_UNKNOWN;
        }
    }
    return QIHSE_KEYSTONE_CLASS_UNKNOWN;
}

qihse_keystone_class_t qihse_fts_get_doc_semantic_class(qihse_fts_index_t* index, uint64_t doc_id) {
    return qihse_fts_get_doc_semantic_class_user(index, doc_id, NULL);
}

static int secure_open_read(const char* path, off_t* size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd); errno = EINVAL; return -1;
    }
    if (size) *size = st.st_size;
    return fd;
}

static bool finish_file(FILE* f) {
    bool ok = f && fflush(f) == 0;
    if (ok && fsync(fileno(f)) != 0) ok = false;
    if (f && fclose(f) != 0) ok = false;
    return ok;
}

static bool save_all_authorized(qihse_fts_index_t* index, qihse_user_t* user) {
    for (uint32_t i = 0u; i < index->doc_count; i++) {
        if (!qihse_auth_can_access(user, index->docs[i].classification, index->docs[i].sci_compartment)) return false;
    }
    return true;
}

#define WRITE_ONE(f,p) (fwrite((p), sizeof(*(p)), 1u, (f)) == 1u)
#define READ_ONE(f,p)  (fread((p), sizeof(*(p)), 1u, (f)) == 1u)

bool qihse_fts_save(qihse_fts_index_t* index, const char* filepath, qihse_user_t* user) {
    if (!index || !index->valid || !filepath || !save_all_authorized(index, user)) return false;
    char tmp[8192];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", filepath, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) return false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); unlink(tmp); return false; }

    uint32_t magic = QFTS_MAGIC, version = QFTS_VERSION, doc_count = index->doc_count;
    uint32_t doc_capacity = index->doc_count;
    if (!WRITE_ONE(f, &magic) || !WRITE_ONE(f, &version) || !WRITE_ONE(f, &doc_count) ||
        !WRITE_ONE(f, &index->total_doc_length) || !WRITE_ONE(f, &doc_capacity)) goto fail;
    for (uint32_t i = 0u; i < index->doc_count; i++) {
        uint32_t sem = (uint32_t)index->docs[i].semantic_class;
        if (!WRITE_ONE(f, &index->docs[i].doc_id) || !WRITE_ONE(f, &index->docs[i].length) ||
            !WRITE_ONE(f, &index->docs[i].classification) || !WRITE_ONE(f, &index->docs[i].sci_compartment) ||
            !WRITE_ONE(f, &sem)) goto fail;
    }
    uint32_t trigram_count = (uint32_t)index->trigram_count;
    if (!WRITE_ONE(f, &trigram_count)) goto fail;
    for (size_t i = 0u; i < TRIGRAM_HASH_SIZE; i++) {
        trigram_entry_t* e = &index->table[i];
        if (e->key == 0u) continue;
        uint32_t df = e->list ? e->list->count : 0u;
        if (!WRITE_ONE(f, &e->key) || !WRITE_ONE(f, &df)) goto fail;
        if (!e->list) continue;
        for (uint32_t d = 0u; d < e->list->count; d++) {
            doc_posting_t* p = &e->list->docs[d];
            if (!WRITE_ONE(f, &p->doc_idx) || !WRITE_ONE(f, &p->term_frequency)) goto fail;
            if (p->term_frequency &&
                fwrite(p->positions, sizeof(uint32_t), p->term_frequency, f) != p->term_frequency) goto fail;
        }
    }
    if (!finish_file(f)) { unlink(tmp); return false; }
    if (rename(tmp, filepath) != 0) { unlink(tmp); return false; }
    return true;
fail:
    fclose(f);
    unlink(tmp);
    return false;
}

static bool bytes_remaining(FILE* f, off_t file_size, uint64_t needed) {
    long pos = ftell(f);
    if (pos < 0 || (off_t)pos > file_size) return false;
    return needed <= (uint64_t)(file_size - (off_t)pos);
}

qihse_fts_index_t* qihse_fts_load(const char* filepath, qihse_user_t* user) {
    if (!filepath) return NULL;
    off_t file_size = 0;
    int fd = secure_open_read(filepath, &file_size);
    if (fd < 0) return NULL;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return NULL; }

    uint32_t magic = 0u, version = 0u, doc_count = 0u, doc_capacity_disk = 0u;
    uint64_t total_doc_length = 0u;
    if (!READ_ONE(f, &magic) || magic != QFTS_MAGIC ||
        !READ_ONE(f, &version) || version != QFTS_VERSION ||
        !READ_ONE(f, &doc_count) || !READ_ONE(f, &total_doc_length) ||
        !READ_ONE(f, &doc_capacity_disk)) goto fail0;
    if (doc_capacity_disk < doc_count) goto fail0;
    if (!bytes_remaining(f, file_size,
                         (uint64_t)doc_count * QFTS_DOC_DISK_BYTES + sizeof(uint32_t))) goto fail0;

    long docs_start = ftell(f);
    if (docs_start < 0) goto fail0;
    for (uint32_t i = 0u; i < doc_count; i++) {
        uint64_t id;
        uint32_t len, sem;
        uint16_t c, sci;
        if (!READ_ONE(f, &id) || !READ_ONE(f, &len) || !READ_ONE(f, &c) ||
            !READ_ONE(f, &sci) || !READ_ONE(f, &sem)) goto fail0;
        if (sem > (uint32_t)QIHSE_KEYSTONE_CLASS_CONSUMER ||
            !qihse_auth_can_access(user, c, sci)) goto fail0;
    }
    if (fseek(f, docs_start, SEEK_SET) != 0) goto fail0;

    qihse_fts_index_t* index = qihse_fts_create();
    if (!index) goto fail0;
    if (doc_count > index->doc_capacity) {
        doc_info_t* next = (doc_info_t*)realloc(index->docs, (size_t)doc_count * sizeof(*next));
        if (!next) goto fail;
        index->docs = next;
        index->doc_capacity = doc_count;
    }
    uint64_t computed_total = 0u;
    for (uint32_t i = 0u; i < doc_count; i++) {
        uint32_t sem;
        if (!READ_ONE(f, &index->docs[i].doc_id) || !READ_ONE(f, &index->docs[i].length) ||
            !READ_ONE(f, &index->docs[i].classification) || !READ_ONE(f, &index->docs[i].sci_compartment) ||
            !READ_ONE(f, &sem)) goto fail;
        if (sem > (uint32_t)QIHSE_KEYSTONE_CLASS_CONSUMER ||
            UINT64_MAX - computed_total < index->docs[i].length) goto fail;
        index->docs[i].semantic_class = (qihse_keystone_class_t)sem;
        computed_total += index->docs[i].length;
    }
    if (computed_total != total_doc_length) goto fail;
    index->doc_count = doc_count;
    index->total_doc_length = total_doc_length;

    uint32_t trigram_count = 0u;
    if (!READ_ONE(f, &trigram_count) || trigram_count > TRIGRAM_HASH_SIZE) goto fail;
    for (uint32_t t = 0u; t < trigram_count; t++) {
        uint32_t key = 0u, df = 0u;
        if (!READ_ONE(f, &key) || !READ_ONE(f, &df) || key == 0u || df > doc_count) goto fail;
        if (trigram_find_slot(index, key, false) != NULL) goto fail;
        trigram_entry_t* e = trigram_find_slot(index, key, true);
        if (!e) goto fail;
        uint32_t prev_doc = 0u;
        for (uint32_t d = 0u; d < df; d++) {
            uint32_t doc_idx = 0u, tf = 0u;
            if (!READ_ONE(f, &doc_idx) || !READ_ONE(f, &tf) || doc_idx >= doc_count || tf == 0u) goto fail;
            if (d != 0u && doc_idx <= prev_doc) goto fail;
            prev_doc = doc_idx;
            if (tf > index->docs[doc_idx].length ||
                (tf != 0u && SIZE_MAX / (size_t)tf < sizeof(uint32_t)) ||
                !bytes_remaining(f, file_size, (uint64_t)tf * sizeof(uint32_t))) goto fail;
            if (e->list->count == e->list->capacity) {
                uint32_t new_cap = e->list->capacity ? e->list->capacity * 2u : 4u;
                if (new_cap < e->list->capacity) goto fail;
                doc_posting_t* next = (doc_posting_t*)realloc(e->list->docs,
                                                               (size_t)new_cap * sizeof(*next));
                if (!next) goto fail;
                memset(next + e->list->capacity, 0,
                       (size_t)(new_cap - e->list->capacity) * sizeof(*next));
                e->list->docs = next;
                e->list->capacity = new_cap;
            }
            doc_posting_t* p = &e->list->docs[e->list->count++];
            p->doc_idx = doc_idx;
            p->term_frequency = tf;
            p->capacity = tf;
            p->positions = (uint32_t*)malloc((size_t)tf * sizeof(uint32_t));
            if (!p->positions || fread(p->positions, sizeof(uint32_t), tf, f) != tf) goto fail;
            uint32_t prev_pos = 0u;
            for (uint32_t z = 0u; z < tf; z++) {
                if (p->positions[z] >= index->docs[doc_idx].length ||
                    (z != 0u && p->positions[z] < prev_pos)) goto fail;
                prev_pos = p->positions[z];
            }
        }
    }
    if (fgetc(f) != EOF) goto fail;
    fclose(f);
    index->valid = true;
    return index;
fail:
    qihse_fts_destroy(index);
fail0:
    fclose(f);
    return NULL;
}
