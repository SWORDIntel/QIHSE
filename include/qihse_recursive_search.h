#ifndef QIHSE_RECURSIVE_SEARCH_H
#define QIHSE_RECURSIVE_SEARCH_H

#include <stddef.h>

#include "qihse_vector_db.h"

/**
 * Performs a vector-recursive graph hop search (implicit relational traversal).
 *
 * This function turns a standard vector search into a relational traversal.
 * Starting with an initial vector (start_vec), it finds the nearest neighbors
 * within a certain similarity threshold. Then, for each result found, it treats
 * those resulting vectors as new query vectors for the next "hop", repeating
 * this process up to the specified number of hops.
 *
 * This effectively traverses a conceptual graph where edges are defined dynamically
 * by vector similarity (distance <= threshold), allowing discovery of multi-hop
 * relationships between entities without an explicit graph structure.
 *
 * @param vdb       Pointer to the vector database context.
 * @param start_vec The initial query vector to start the recursive search.
 * @param dims      The dimensionality of the vector.
 * @param hops      The number of recursive hops to perform (depth of traversal).
 * @param threshold The similarity distance threshold to define an implicit edge.
 * @param user      Authenticated user used for every hop-level access check.
 * @return          Status code (0 for success, non-zero for error).
 */
int qihse_search_recursive_implicit(
    qihse_vector_db_t vdb,
    const float *start_vec,
    size_t dims,
    int hops,
    float threshold,
    struct qihse_user_s* user
);

#endif /* QIHSE_RECURSIVE_SEARCH_H */
