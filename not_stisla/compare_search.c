#include "include/not_stisla.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct { int64_t key; } query_t;

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static not_stisla_result_t binary_search(const int64_t* arr, size_t n, int64_t key) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (arr[mid] == key) return mid;
        if (arr[mid] < key) lo = mid + 1;
        else hi = mid;
    }
    return NOT_STISLA_NOT_FOUND;
}

int main(void) {
    const size_t n = 1000000;
    const size_t num_queries = 200000;
    int64_t* data = malloc(n * sizeof(int64_t));
    for (size_t i = 0; i < n; ++i) {
        data[i] = (int64_t)i;
    }
    query_t* queries = malloc(num_queries * sizeof(query_t));
    for (size_t i = 0; i < num_queries; ++i) {
        queries[i].key = data[(i * 17) % n];
    }
    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    not_stisla_parallel_config_t config = {0, 0, 64};

    printf("#run,binary_ns,not_stisla_ns,batch_parallel_ns\n");
    for (int run = 1; run <= 10; ++run) {
        uint64_t start, end;
        start = now_ns();
        for (size_t i = 0; i < num_queries; ++i) {
            binary_search(data, n, queries[i].key);
        }
        end = now_ns();
        double binary_avg = (double)(end - start) / num_queries;

        start = now_ns();
        for (size_t i = 0; i < num_queries; ++i) {
            not_stisla_search(data, n, queries[i].key, table, 8);
        }
        end = now_ns();
        double classic_avg = (double)(end - start) / num_queries;

        start = now_ns();
        not_stisla_batch_item_t* batch = malloc(num_queries * sizeof(not_stisla_batch_item_t));
        for (size_t i = 0; i < num_queries; ++i) {
            batch[i].key = queries[i].key;
            batch[i].result = NOT_STISLA_NOT_FOUND;
            batch[i].ordinal = i;
        }
        size_t found = not_stisla_search_parallel(data, n, batch, num_queries, table, 8, &config);
        (void)found;
        end = now_ns();
        double parallel_avg = (double)(end - start) / num_queries;
        free(batch);

        printf("%d,%.2f,%.2f,%.2f\n", run, binary_avg, classic_avg, parallel_avg);
    }
    not_stisla_anchor_table_destroy(table);
    free(queries);
    free(data);
    return 0;
}
