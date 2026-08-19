#include "qihse_fts.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

typedef struct doc_posting {
    uint32_t doc_idx;
    uint32_t term_frequency;
    uint32_t capacity;
    uint32_t* positions;
    struct doc_posting* next;
} doc_posting_t;

typedef struct posting_list {
    doc_posting_t* head;
    doc_posting_t* tail;
    uint32_t document_frequency;
} posting_list_t;

typedef struct {
    uint64_t doc_id;
    uint32_t length;
    uint16_t classification;
    uint16_t sci_compartment;
    qihse_keystone_class_t semantic_class;
} doc_info_t;

struct qihse_fts_index {
    qihse_trinary_trie_t* dictionary;
    qihse_arena_t* arena;
    
    doc_info_t* docs;
    uint32_t doc_count;
    uint32_t doc_capacity;
    uint64_t total_doc_length;
};

qihse_fts_index_t* qihse_fts_create() {
    qihse_fts_index_t* idx = (qihse_fts_index_t*)malloc(sizeof(qihse_fts_index_t));
    if (!idx) return NULL;
    idx->dictionary = qihse_trinary_trie_create();
    idx->arena = qihse_arena_create(65536);
    idx->doc_capacity = 1024;
    idx->docs = (doc_info_t*)malloc(idx->doc_capacity * sizeof(doc_info_t));
    idx->doc_count = 0;
    idx->total_doc_length = 0;
    return idx;
}

void qihse_fts_destroy(qihse_fts_index_t* index) {
    if (!index) return;
    if (index->dictionary) {
        qihse_trinary_trie_destroy(index->dictionary);
    }
    if (index->arena) {
        qihse_arena_destroy(index->arena);
    }
    if (index->docs) {
        free(index->docs);
    }
    free(index);
}

#include "qihse_auth.h"

bool qihse_fts_add_document(qihse_fts_index_t* index, uint64_t doc_id, const char* text, size_t length, uint16_t classification, uint16_t sci_compartment, qihse_keystone_class_t semantic_class) {
    if (!index || !text) return false;

    if (index->doc_count >= index->doc_capacity) {
        index->doc_capacity *= 2;
        doc_info_t* new_docs = (doc_info_t*)realloc(index->docs, index->doc_capacity * sizeof(doc_info_t));
        if (!new_docs) return false;
        index->docs = new_docs;
    }

    uint32_t doc_idx = index->doc_count;
    index->docs[doc_idx].doc_id = doc_id;
    index->docs[doc_idx].length = 0;
    index->docs[doc_idx].classification = classification;
    index->docs[doc_idx].sci_compartment = sci_compartment;
    index->docs[doc_idx].semantic_class = semantic_class;
    
    const char* p = text;
    const char* start = NULL;
    size_t i = 0;
    uint32_t pos = 0;
    uint32_t doc_len = 0;

    while (i <= length) {
        bool is_alnum = (i < length) && isalnum((unsigned char)p[i]);
        if (is_alnum) {
            if (!start) start = &p[i];
        } else {
            if (start) {
                size_t tok_len = &p[i] - start;
                char full_word[256];
                if (tok_len > 255) tok_len = 255;
                for (size_t j = 0; j < tok_len; j++) {
                    full_word[j] = (char)tolower((unsigned char)start[j]);
                }
                full_word[tok_len] = '\0';
                
                size_t num_trigrams = (tok_len < 3) ? 1 : (tok_len - 2);
                for (size_t t = 0; t < num_trigrams; t++) {
                    char token[4];
                    if (tok_len < 3) {
                        strncpy(token, full_word, 3);
                        token[3] = '\0';
                    } else {
                        token[0] = full_word[t];
                        token[1] = full_word[t+1];
                        token[2] = full_word[t+2];
                        token[3] = '\0';
                    }
                    
                    size_t out_size;
                    posting_list_t** p_list_ptr = (posting_list_t**)qihse_trinary_trie_search(index->dictionary, token, &out_size);
                    posting_list_t* p_list;
                    if (!p_list_ptr) {
                        p_list = (posting_list_t*)qihse_arena_alloc(index->arena, sizeof(posting_list_t));
                        if (!p_list) return false;
                        p_list->head = NULL;
                        p_list->tail = NULL;
                        p_list->document_frequency = 0;
                        qihse_trinary_trie_insert(index->dictionary, token, &p_list, sizeof(posting_list_t*));
                    } else {
                        p_list = *p_list_ptr;
                    }

                    doc_posting_t* doc_node = p_list->tail;
                    if (!doc_node || doc_node->doc_idx != doc_idx) {
                        doc_node = (doc_posting_t*)qihse_arena_alloc(index->arena, sizeof(doc_posting_t));
                        if (!doc_node) return false;
                        doc_node->doc_idx = doc_idx;
                        doc_node->term_frequency = 0;
                        doc_node->capacity = 4;
                        doc_node->positions = (uint32_t*)qihse_arena_alloc(index->arena, sizeof(uint32_t) * doc_node->capacity);
                        doc_node->next = NULL;
                        
                        if (!p_list->head) {
                            p_list->head = doc_node;
                        } else {
                            p_list->tail->next = doc_node;
                        }
                        p_list->tail = doc_node;
                        p_list->document_frequency++;
                    }

                    if (doc_node->term_frequency >= doc_node->capacity) {
                        uint32_t new_cap = doc_node->capacity * 2;
                        uint32_t* new_pos = (uint32_t*)qihse_arena_alloc(index->arena, sizeof(uint32_t) * new_cap);
                        if (!new_pos) return false;
                        for (uint32_t k = 0; k < doc_node->term_frequency; k++) {
                            new_pos[k] = doc_node->positions[k];
                        }
                        doc_node->positions = new_pos;
                        doc_node->capacity = new_cap;
                    }
                    doc_node->positions[doc_node->term_frequency++] = pos + t;
                }
                
                pos += tok_len;
                doc_len += num_trigrams;
                start = NULL;
            }
        }
        i++;
    }

    index->docs[doc_idx].length = doc_len;
    index->total_doc_length += doc_len;
    index->doc_count++;

    return true;
}

int qihse_fts_search_user_filtered(qihse_fts_index_t* index, const char* query, qihse_user_t* user, qihse_fts_result_t* results, int top_k, uint8_t semantic_class_mask) {
    if (!index || !query || !results || top_k <= 0) return 0;
    if (index->doc_count == 0) return 0;

    float* scores = (float*)calloc(index->doc_count, sizeof(float));
    if (!scores) return 0;

    float avgdl = (float)index->total_doc_length / index->doc_count;
    if (avgdl == 0) avgdl = 1.0f;
    float k1 = 1.2f;
    float b = 0.75f;
    uint32_t N = index->doc_count;

    const char* p = query;
    const char* start = NULL;
    size_t i = 0;
    size_t length = strlen(query);

    while (i <= length) {
        bool is_alnum = (i < length) && isalnum((unsigned char)p[i]);
        if (is_alnum) {
            if (!start) start = &p[i];
        } else {
            if (start) {
                size_t tok_len = &p[i] - start;
                char full_word[256];
                if (tok_len > 255) tok_len = 255;
                for (size_t j = 0; j < tok_len; j++) {
                    full_word[j] = (char)tolower((unsigned char)start[j]);
                }
                full_word[tok_len] = '\0';

                size_t num_trigrams = (tok_len < 3) ? 1 : (tok_len - 2);
                for (size_t t = 0; t < num_trigrams; t++) {
                    char token[4];
                    if (tok_len < 3) {
                        strncpy(token, full_word, 3);
                        token[3] = '\0';
                    } else {
                        token[0] = full_word[t];
                        token[1] = full_word[t+1];
                        token[2] = full_word[t+2];
                        token[3] = '\0';
                    }

                    size_t out_size;
                    posting_list_t** p_list_ptr = (posting_list_t**)qihse_trinary_trie_search(index->dictionary, token, &out_size);
                    if (p_list_ptr) {
                        posting_list_t* p_list = *p_list_ptr;
                        uint32_t df = p_list->document_frequency;
                        float idf = logf(((N - df + 0.5f) / (df + 0.5f)) + 1.0f);
                        if (idf < 0.0f) idf = 0.0f;

                        doc_posting_t* curr = p_list->head;
                        while (curr) {
                            uint32_t doc_idx = curr->doc_idx;
                            uint32_t tf = curr->term_frequency;
                            uint32_t doc_len = index->docs[doc_idx].length;

                            float numerator = tf * (k1 + 1.0f);
                            float denominator = tf + k1 * (1.0f - b + b * ((float)doc_len / avgdl));
                            scores[doc_idx] += idf * (numerator / denominator);

                            curr = curr->next;
                        }
                    }
                }
                start = NULL;
            }
        }
        i++;
    }

    int num_results = 0;
    for (int k = 0; k < top_k; k++) {
        float max_score = 0.0f;
        int best_idx = -1;
        for (uint32_t j = 0; j < index->doc_count; j++) {
            if (!qihse_auth_can_access(user, index->docs[j].classification, index->docs[j].sci_compartment)) {
                continue;
            }
            /* Semantic class filtering: a non-zero mask restricts results to
             * documents whose neural class bit is set in the mask. */
            if (semantic_class_mask != 0) {
                uint8_t class_bit = (uint8_t)(1u << (uint8_t)index->docs[j].semantic_class);
                if ((semantic_class_mask & class_bit) == 0) {
                    continue;
                }
            }
            if (scores[j] > max_score) {
                max_score = scores[j];
                best_idx = j;
            }
        }
        if (best_idx != -1 && max_score > 0.0f) {
            results[num_results].doc_id = index->docs[best_idx].doc_id;
            results[num_results].bm25_score = max_score;
            results[num_results].semantic_class = index->docs[best_idx].semantic_class;
            scores[best_idx] = -1.0f; // mark as used
            num_results++;
        } else {
            break;
        }
    }

    free(scores);
    return num_results;
}

int qihse_fts_search_user(qihse_fts_index_t* index, const char* query, qihse_user_t* user, qihse_fts_result_t* results, int top_k) {
    return qihse_fts_search_user_filtered(index, query, user, results, top_k, 0);
}

qihse_keystone_class_t qihse_fts_get_doc_semantic_class(qihse_fts_index_t* index, uint64_t doc_id) {
    if (!index) return QIHSE_KEYSTONE_CLASS_UNKNOWN;
    for (uint32_t j = 0; j < index->doc_count; j++) {
        if (index->docs[j].doc_id == doc_id) {
            return index->docs[j].semantic_class;
        }
    }
    return QIHSE_KEYSTONE_CLASS_UNKNOWN;
}
