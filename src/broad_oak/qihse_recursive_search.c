#include "qihse_recursive_search.h"
#include "qihse_vector_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUEUE_SIZE 4096
#define MAX_VISITED_SIZE 4096
#define MAX_RESULTS_PER_HOP 50

typedef struct {
    uint64_t id;
    float *vector;
    int hop_level;
} queue_node_t;

int qihse_search_recursive_implicit(
    qihse_vector_db_t vdb,
    const float *start_vec,
    size_t dims,
    int hops,
    float threshold,
    struct qihse_user_s* user
) {
    if (!vdb || !start_vec || !user || dims == 0) {
        return -1;
    }

    printf("Starting Vector-Recursive Graph Hop Search...\n");
    printf("Initial vector, dims: %zu, threshold: %f, max hops: %d\n", dims, threshold, hops);

    queue_node_t *queue = malloc(sizeof(queue_node_t) * MAX_QUEUE_SIZE);
    uint64_t *visited = malloc(sizeof(uint64_t) * MAX_VISITED_SIZE);
    
    if (!queue || !visited) {
        if (queue) free(queue);
        if (visited) free(visited);
        return -1;
    }

    int head = 0;
    int tail = 0;
    int visited_count = 0;

    // Enqueue the start vector
    queue[tail].id = (uint64_t)-1;
    queue[tail].vector = malloc(dims * sizeof(float));
    if (!queue[tail].vector) {
        free(queue);
        free(visited);
        return -1;
    }
    memcpy(queue[tail].vector, start_vec, dims * sizeof(float));
    queue[tail].hop_level = 0;
    tail++;

    int current_hop = 0;

    while (head < tail) {
        queue_node_t current = queue[head++];
        
        if (current.hop_level > current_hop) {
            current_hop = current.hop_level;
            printf("Executing hop %d...\n", current_hop);
        }

        if (current.hop_level >= hops) {
            free(current.vector);
            continue; // Reached max hops
        }

        // Perform similarity search
        qihse_vector_query_t query;
        memset(&query, 0, sizeof(query));
        query.query_vector = current.vector;
        query.vector_dims = dims;
        query.top_k = MAX_RESULTS_PER_HOP;
        query.similarity_threshold = threshold;
        query.include_vectors = true;
        query.include_metadata = false;
        query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
        query.distance_metric = QIHSE_DISTANCE_COSINE;
        query.user = user;

        qihse_vector_result_t results[MAX_RESULTS_PER_HOP];
        int num_results = qihse_vector_db_search(vdb, &query, results, MAX_RESULTS_PER_HOP);

        if (num_results < 0) {
            printf("Error: vector search failed at hop %d\n", current.hop_level);
            free(current.vector);
            continue;
        }

        for (int i = 0; i < num_results; i++) {
            if (results[i].score < threshold) {
                continue;
            }

            // Check if visited
            bool is_visited = false;
            int v = 0;
            for (; v + 3 < visited_count; v += 4) {
                if (visited[v] == results[i].id || 
                    visited[v+1] == results[i].id || 
                    visited[v+2] == results[i].id || 
                    visited[v+3] == results[i].id) {
                    is_visited = true;
                    break;
                }
            }
            if (!is_visited) {
                for (; v < visited_count; v++) {
                    if (visited[v] == results[i].id) {
                        is_visited = true;
                        break;
                    }
                }
            }

            if (!is_visited) {
                // Mark as visited
                if (visited_count < MAX_VISITED_SIZE) {
                    visited[visited_count++] = results[i].id;
                }

                // Enqueue
                if (tail < MAX_QUEUE_SIZE && results[i].vector) {
                    queue[tail].id = results[i].id;
                    queue[tail].vector = malloc(dims * sizeof(float));
                    if (queue[tail].vector) {
                        memcpy(queue[tail].vector, results[i].vector, dims * sizeof(float));
                        queue[tail].hop_level = current.hop_level + 1;
                        tail++;
                        printf("  -> Discovered node ID: %lu at hop %d (score: %f)\n", 
                               (unsigned long)results[i].id, current.hop_level + 1, results[i].score);
                    }
                }
            }
        }
        
        free(current.vector);
    }

    // Clean up remaining vectors in the queue
    while (head < tail) {
        free(queue[head++].vector);
    }

    free(queue);
    free(visited);

    printf("Recursive search completed after %d hops.\n", hops);

    return 0; /* Success */
}
