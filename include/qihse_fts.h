#ifndef QIHSE_FTS_H
#define QIHSE_FTS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_trinary_trie.h"
#include "qihse_arena.h"
#include "qihse_keystone.h"

/**
 * @brief Opaque handle for the QIHSE Full-Text Search index.
 */
typedef struct qihse_fts_index qihse_fts_index_t;

/**
 * @brief Structure representing a search result.
 *
 * semantic_class carries the 6-class neural classification metadata that was
 * attached to the indexed record at add time. It enables semantic class
 * filtering during hybrid FTS + Vector RRF fusion without an extra metadata
 * lookup.
 */
typedef struct {
    uint64_t doc_id;
    float bm25_score;
    qihse_keystone_class_t semantic_class;
} qihse_fts_result_t;

qihse_fts_index_t* qihse_fts_create(void);
void qihse_fts_destroy(qihse_fts_index_t* index);

#include "qihse_auth.h"

/**
 * @brief Adds a document to the index.
 *
 * The classification and SCI compartment travel with the indexed metadata and
 * are enforced for every user-visible search or metadata lookup.
 */
bool qihse_fts_add_document(
    qihse_fts_index_t* index,
    uint64_t doc_id,
    const char* text,
    size_t length,
    uint16_t classification,
    uint16_t sci_compartment,
    qihse_keystone_class_t semantic_class);

/**
 * @brief Searches the index (BM25) with RBAC enforcement.
 *
 * Corpus statistics are computed only over documents visible to the caller so
 * inaccessible records cannot influence result scores/ranking as an inference
 * channel.
 */
int qihse_fts_search_user(
    qihse_fts_index_t* index,
    const char* query,
    qihse_user_t* user,
    qihse_fts_result_t* results,
    int top_k);

/**
 * @brief Searches with RBAC + semantic class filtering.
 *
 * semantic_class_mask is a bitmask over QIHSE_KEYSTONE_CLASS_* values. A mask
 * of 0 disables semantic filtering. Authorization is always applied first.
 */
int qihse_fts_search_user_filtered(
    qihse_fts_index_t* index,
    const char* query,
    qihse_user_t* user,
    qihse_fts_result_t* results,
    int top_k,
    uint8_t semantic_class_mask);

/**
 * @brief Authorization-aware semantic metadata lookup.
 *
 * Returns UNKNOWN when the document is missing or inaccessible to ``user``.
 * This is the API hybrid FTS/vector fusion should use.
 */
qihse_keystone_class_t qihse_fts_get_doc_semantic_class_user(
    qihse_fts_index_t* index,
    uint64_t doc_id,
    qihse_user_t* user);

/**
 * @brief Legacy semantic metadata lookup retained for ABI compatibility.
 *
 * It now behaves as an unclassified-only lookup by internally using a NULL
 * security context. Classified metadata is therefore not disclosed through the
 * historical context-free symbol.
 */
qihse_keystone_class_t qihse_fts_get_doc_semantic_class(
    qihse_fts_index_t* index,
    uint64_t doc_id);

/**
 * @brief Saves the FTS index to a binary file.
 *
 * The caller must be authorized for every document. The save is all-or-nothing
 * and uses a mode-0600, no-follow temporary file followed by atomic rename on
 * POSIX systems so denied or failed exports do not leave partial snapshots.
 */
bool qihse_fts_save(
    qihse_fts_index_t* index,
    const char* filepath,
    qihse_user_t* user);

/**
 * @brief Loads an FTS index from a binary file.
 *
 * The loader validates serialized counts, document indices, posting-list
 * cardinalities and allocation sizes before accepting them. The caller must be
 * authorized for every document; no partial import is performed.
 */
qihse_fts_index_t* qihse_fts_load(
    const char* filepath,
    qihse_user_t* user);

#endif /* QIHSE_FTS_H */
