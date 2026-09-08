#ifndef QIHSE_FTS_H
#define QIHSE_FTS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_trinary_trie.h"
#include "qihse_arena.h"
#include "qihse_keystone.h"
#include "qihse_auth.h"

typedef struct qihse_fts_index qihse_fts_index_t;

typedef struct {
    uint64_t doc_id;
    float bm25_score;
    qihse_keystone_class_t semantic_class;
} qihse_fts_result_t;

qihse_fts_index_t* qihse_fts_create(void);
void qihse_fts_destroy(qihse_fts_index_t* index);

/*
 * Authorization-aware document insertion. The target classification/SCI must
 * be accessible to user. This is the required entry point for classified data.
 */
bool qihse_fts_add_document_user(
    qihse_fts_index_t* index,
    uint64_t doc_id,
    const char* text,
    size_t length,
    uint16_t classification,
    uint16_t sci_compartment,
    qihse_keystone_class_t semantic_class,
    qihse_user_t* user);

/* Legacy ABI: context-free insertion is restricted to unclassified data. */
bool qihse_fts_add_document(
    qihse_fts_index_t* index,
    uint64_t doc_id,
    const char* text,
    size_t length,
    uint16_t classification,
    uint16_t sci_compartment,
    qihse_keystone_class_t semantic_class);

/*
 * BM25 search with mandatory RBAC. Corpus statistics (N, df, avgdl) are
 * calculated only over caller-visible documents, preventing ranking-based
 * inference from hidden records.
 */
int qihse_fts_search_user(
    qihse_fts_index_t* index,
    const char* query,
    qihse_user_t* user,
    qihse_fts_result_t* results,
    int top_k);

int qihse_fts_search_user_filtered(
    qihse_fts_index_t* index,
    const char* query,
    qihse_user_t* user,
    qihse_fts_result_t* results,
    int top_k,
    uint8_t semantic_class_mask);

qihse_keystone_class_t qihse_fts_get_doc_semantic_class_user(
    qihse_fts_index_t* index,
    uint64_t doc_id,
    qihse_user_t* user);

/* Legacy ABI: unclassified-only metadata lookup. */
qihse_keystone_class_t qihse_fts_get_doc_semantic_class(
    qihse_fts_index_t* index,
    uint64_t doc_id);

/* All-or-nothing authorized, mode-0600, no-follow, atomic persistence. */
bool qihse_fts_save(
    qihse_fts_index_t* index,
    const char* filepath,
    qihse_user_t* user);

/*
 * Authorization + structural validation precede acceptance. Serialized counts,
 * document references, posting cardinalities and allocation sizes are bounded
 * by the actual file and index structure.
 */
qihse_fts_index_t* qihse_fts_load(
    const char* filepath,
    qihse_user_t* user);

#endif /* QIHSE_FTS_H */
