#ifndef QIHSE_FTS_H
#define QIHSE_FTS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_trinary_trie.h"
#include "qihse_arena.h"

/**
 * @brief Opaque handle for the QIHSE Full-Text Search index.
 */
typedef struct qihse_fts_index qihse_fts_index_t;

/**
 * @brief Structure representing a search result.
 */
typedef struct {
    uint64_t doc_id;
    float bm25_score;
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
 * Extracts tokens, maintains position data, and updates posting lists.
 * @param index The FTS index.
 * @param doc_id The unique document ID.
 * @param text The full text content (read-only).
 * @param length Length of the text content.
 * @return true on success.
 */
#include "qihse_auth.h"

bool qihse_fts_add_document(qihse_fts_index_t* index, uint64_t doc_id, const char* text, size_t length, uint16_t classification, uint16_t sci_compartment);

int qihse_fts_search_user(qihse_fts_index_t* index, const char* query, qihse_user_t* user, qihse_fts_result_t* results, int top_k);

#endif /* QIHSE_FTS_H */
