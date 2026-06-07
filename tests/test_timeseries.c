#include "qihse_timeseries.h"
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include "qihse_auth.h"

#define EPSILON 0.0001

int main() {
    printf("Testing Time-Series Engine...\n");
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    assert(tsdb != NULL);

    qihse_auth_init();
    qihse_user_t* u_operator = qihse_auth_create_user(4, QIHSE_ROLE_OPERATOR, 0, 0);

    printf("Inserting points...\n");
    for (int i = 0; i < 2500; i++) {
        uint64_t ts = 1000000 + i * 100;
        double val = sin(i * 0.1);
        qihse_tsdb_insert(tsdb, 1, ts, val, 0, 0);
    }
    
    printf("Flushing...\n");
    qihse_tsdb_compress_flush(tsdb);

    printf("Querying average...\n");
    uint64_t start_ts = 1000000 + 100 * 100;
    uint64_t end_ts = 1000000 + 199 * 100;
    double avg = qihse_tsdb_average_range_user(tsdb, start_ts, end_ts, u_operator);
    
    double expected_sum = 0;
    for (int i = 100; i <= 199; i++) {
        expected_sum += sin(i * 0.1);
    }
    double expected_avg = expected_sum / 100.0;
    
    printf("Avg: %f, Expected: %f\n", avg, expected_avg);
    assert(fabs(avg - expected_avg) < EPSILON);

    printf("Testing TTL trimming...\n");
    qihse_tsdb_set_ttl(tsdb, 50000); 
    
    qihse_tsdb_trim(tsdb, 1260000);
    
    double trimmed_avg = qihse_tsdb_average_range_user(tsdb, start_ts, end_ts, u_operator);
    printf("Trimmed avg: %f\n", trimmed_avg);
    assert(trimmed_avg == 0.0);

    qihse_tsdb_destroy(tsdb);
    printf("Test passed!\n");
    return 0;
}
