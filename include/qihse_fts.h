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
 * attached to the indexed record at add time (Idea 5: Neural Semantic Metadata
 * Tagging). It enables semantic class filtering during hybrid FTS + Vector RRF
 * fusion without an extra metadata lookup.
 */
typedef struct {
    uint64_t doc_id;
    float bm25_score;
    qihse_keystone_class_t semantic_class;
} qihse_fts_result_t;

/**
 * @brief Creates a new Full-Text Search index.
 * Uses a Trinary Trie for the dictionary and Arenas for posting lists.
 * @return Pointer to the FTS index.
 */
qihse_fts_index_t* qihse_fts_create();

/**
 * @brief Destroys the FTS index.
 * @param index The FTS index.
 */
void qihse_fts_destroy(qihse_fts_index_t* index);

/**
 * @brief Adds a document to the index using a zero-copy lexer.
 * Extracts tokens, maintains position data, and updates posting lists. The
 * 6-class neural classification metadata (semantic_class) is attached to the
 * indexed record so that semantic class filtering can be applied at query time.
 * @param index The FTS index.
 * @param doc_id The unique document ID.
 * @param text The full text content (read-only).
 * @param length Length of the text content.
 * @param classification Clearance level for RBAC filtering.
 * @param sci_compartment SCI compartment mask for RBAC filtering.
 * @param semantic_class 6-class neural classification tag.
 * @return true on success.
 */
#include "qihse_auth.h"

bool qihse_fts_add_document(qihse_fts_index_t* index, uint64_t doc_id, const char* text, size_t length, uint16_t classification, uint16_t sci_compartment, qihse_keystone_class_t semantic_class);

/**
 * @brief Searches the index (BM25) with RBAC enforcement.
 * @param index The FTS index.
 * @param query The query string.
 * @param user The user executing the query (for RBAC).
 * @param results Output array of results.
 * @param top_k Maximum number of results to return.
 * @return Number of results written.
 */
int qihse_fts_search_user(qihse_fts_index_t* index, const char* query, qihse_user_t* user, qihse_fts_result_t* results, int top_k);

/**
 * @brief Searches the index (BM25) with RBAC + semantic class filtering.
 *
 * semantic_class_mask is a bitmask over the 6-class neural taxonomy:
 *   bit (1 << QIHSE_KEYSTONE_CLASS_FINANCIAL)      => FINANCIAL allowed
 *   bit (1 << QIHSE_KEYSTONE_CLASS_CORPORATE)      => CORPORATE allowed
 *   bit (1 << QIHSE_KEYSTONE_CLASS_GOVERNMENT)     => GOVERNMENT allowed
 *   bit (1 << QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE) => INFRASTRUCTURE allowed
 *   bit (1 << QIHSE_KEYSTONE_CLASS_CONSUMER)       => CONSUMER allowed
 *   bit (1 << QIHSE_KEYSTONE_CLASS_UNKNOWN)        => UNKNOWN allowed
 * A mask of 0 disables filtering and returns all classes (equivalent to
 * qihse_fts_search_user).
 *
 * @param index The FTS index.
 * @param query The query string.
 * @param user The user executing the query (for RBAC).
 * @param results Output array of results.
 * @param top_k Maximum number of results to return.
 * @param semantic_class_mask Bitmask of allowed neural classes (0 = no filter).
 * @return Number of results written.
 */
int qihse_fts_search_user_filtered(qihse_fts_index_t* index, const char* query, qihse_user_t* user, qihse_fts_result_t* results, int top_k, uint8_t semantic_class_mask);

/**
 * @brief Retrieves the stored 6-class neural classification for a document.
 *
 * Used by the hybrid FTS + Vector RRF fusion to enrich vector-sourced candidates
 * with semantic class metadata so that semantic class filtering can be applied
 * uniformly across both modalities.
 *
 * @param index The FTS index.
 * @param doc_id The document ID to look up.
 * @return The stored semantic class, or QIHSE_KEYSTONE_CLASS_UNKNOWN if not found.
 */
qihse_keystone_class_t qihse_fts_get_doc_semantic_class(qihse_fts_index_t* index, uint64_t doc_id);

/**
 * @brief Saves the FTS index to a binary file on disk.
 *
 * Serializes all document metadata and trigram posting lists so the index
 * can be restored without re-tokenizing the original text. This is a
 * backup/export primitive: the caller MUST have sufficient clearance to
 * export every document's classification level. If any document exceeds
 * the caller's clearance or SCI compartments, the entire operation is
 * denied (no partial export) to prevent selective disclosure inference.
 *
 * @param index The FTS index to save.
 * @param filepath Path to the output file.
 * @param user The authenticated user requesting the export. May be NULL for
 *             unclassified-only indexes (classification=0, sci=0); classified
 *             data requires a user with sufficient clearance.
 * @return true on success, false on failure or authorization denial.
 */
bool qihse_fts_save(qihse_fts_index_t* index, const char* filepath, qihse_user_t* user);

/**
 * @brief Loads an FTS index from a binary file created by qihse_fts_save.
 *
 * Returns a newly allocated index that must be freed with qihse_fts_destroy.
 * This is a restore/import primitive: the caller MUST have sufficient
 * clearance to import data at the highest classification level stored in
 * the file. If the file contains data above the caller's clearance, the
 * load is denied entirely.
 *
 * @param filepath Path to the saved FTS index file.
 * @param user The authenticated user requesting the import. May be NULL for
 *             unclassified-only files; classified data requires a user with
 *             sufficient clearance.
 * @return New FTS index, or NULL on failure or authorization denial.
 */
qihse_fts_index_t* qihse_fts_load(const char* filepath, qihse_user_t* user);

#endif /* QIHSE_FTS_H */
