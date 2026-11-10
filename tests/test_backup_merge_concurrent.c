#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_barrier_t scratch_barrier;
static pthread_mutex_t scratch_mutex = PTHREAD_MUTEX_INITIALIZER;
static char scratch_paths[2][4096];
static unsigned scratch_count;

void qihse_backup_test_merge_scratch_ready(const char* path) {
    assert(path);
    assert(pthread_mutex_lock(&scratch_mutex) == 0);
    assert(scratch_count < 2u);
    snprintf(scratch_paths[scratch_count], sizeof(scratch_paths[0]), "%s", path);
    scratch_count++;
    assert(pthread_mutex_unlock(&scratch_mutex) == 0);
    int rc = pthread_barrier_wait(&scratch_barrier);
    assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
}

typedef struct {
    qihse_user_t* user;
    const char* base;
    const char* incoming;
    const char* output;
    int result;
} merge_job_t;

static void* merge_thread(void* opaque) {
    merge_job_t* job = opaque;
    qihse_backup_merge_stats_t stats;
    job->result = qihse_backup_merge_user(job->user, job->base, job->incoming,
        job->output, 1u << 20, 100u, &stats);
    return NULL;
}

static unsigned char* read_whole_file(const char* path, size_t* out_size) {
    *out_size = 0u;
    FILE* file = fopen(path, "rb");
    assert(file);
    assert(fseeko(file, 0, SEEK_END) == 0);
    off_t length = ftello(file);
    assert(length >= 0);
    assert(fseeko(file, 0, SEEK_SET) == 0);
    unsigned char* bytes = malloc(length ? (size_t)length : 1u);
    assert(bytes);
    assert(fread(bytes, 1u, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    *out_size = (size_t)length;
    return bytes;
}

static void save_row(qihse_kv_store_t* store, qihse_user_t* user,
                     const char* key, const char* value, const char* path) {
    if (qihse_kv_count_user(store, user) != 0u)
        assert(qihse_kv_clear_user(store, user));
    assert(qihse_kv_set_user(store, key, value, 0u, 0u, user));
    assert(qihse_backup_full_user(store, user, path, NULL) == QIHSE_BACKUP_EXPORT_OK);
}

int main(void) {
    char directory[] = "tests/backup_merge_concurrent_XXXXXX";
    assert(mkdtemp(directory));
    assert(setenv("QIHSE_DATA_DIR", directory, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("MergeConcurrentOperator1!"));
    qihse_user_t* operator_user = qihse_auth_authenticate_id(0u,
        "MergeConcurrentOperator1!");
    assert(operator_user);
    qihse_kv_store_t* store = qihse_kv_store_create_user(operator_user);
    assert(store);

    char left_base[4096], left_incoming[4096], right_base[4096], right_incoming[4096];
    char output[4096];
    snprintf(left_base, sizeof(left_base), "%s/left-base.qbak", directory);
    snprintf(left_incoming, sizeof(left_incoming), "%s/left-incoming.qbak", directory);
    snprintf(right_base, sizeof(right_base), "%s/right-base.qbak", directory);
    snprintf(right_incoming, sizeof(right_incoming), "%s/right-incoming.qbak", directory);
    snprintf(output, sizeof(output), "%s/shared-output.qbak", directory);
    save_row(store, operator_user, "left-base", "lb", left_base);
    save_row(store, operator_user, "left-incoming", "li", left_incoming);
    save_row(store, operator_user, "right-base", "rb", right_base);
    save_row(store, operator_user, "right-incoming", "ri", right_incoming);

    const char* sources[] = {left_base, left_incoming, right_base, right_incoming};
    unsigned char* source_bytes[4];
    size_t source_sizes[4];
    for (size_t i = 0; i < 4u; i++)
        source_bytes[i] = read_whole_file(sources[i], &source_sizes[i]);

    assert(pthread_barrier_init(&scratch_barrier, NULL, 2u) == 0);
    merge_job_t jobs[2] = {
        {operator_user, left_base, left_incoming, output, -99},
        {operator_user, right_base, right_incoming, output, -99}
    };
    pthread_t threads[2];
    assert(pthread_create(&threads[0], NULL, merge_thread, &jobs[0]) == 0);
    assert(pthread_create(&threads[1], NULL, merge_thread, &jobs[1]) == 0);
    assert(pthread_join(threads[0], NULL) == 0);
    assert(pthread_join(threads[1], NULL) == 0);
    assert(pthread_barrier_destroy(&scratch_barrier) == 0);
    assert(scratch_count == 2u);
    assert(strcmp(scratch_paths[0], scratch_paths[1]) != 0);

    bool success = jobs[0].result == QIHSE_BACKUP_EXPORT_OK ||
                   jobs[1].result == QIHSE_BACKUP_EXPORT_OK;
    assert(success);
    assert(qihse_backup_verify_user(operator_user, output) == QIHSE_BACKUP_EXPORT_OK);
    assert(qihse_kv_clear_user(store, operator_user));
    assert(qihse_restore_user(store, operator_user, output) == QIHSE_BACKUP_EXPORT_OK);

    char* lb = qihse_kv_get_user(store, "left-base", operator_user);
    char* li = qihse_kv_get_user(store, "left-incoming", operator_user);
    char* rb = qihse_kv_get_user(store, "right-base", operator_user);
    char* ri = qihse_kv_get_user(store, "right-incoming", operator_user);
    bool left_pair = lb && li && !rb && !ri && !strcmp(lb, "lb") && !strcmp(li, "li");
    bool right_pair = rb && ri && !lb && !li && !strcmp(rb, "rb") && !strcmp(ri, "ri");
    assert(left_pair || right_pair);
    free(lb); free(li); free(rb); free(ri);

    for (size_t i = 0; i < 4u; i++) {
        size_t current_size = 0u;
        unsigned char* current = read_whole_file(sources[i], &current_size);
        assert(current_size == source_sizes[i]);
        assert(memcmp(current, source_bytes[i], current_size) == 0);
        free(current);
        free(source_bytes[i]);
    }
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(directory);
    puts("PASS concurrent backup merges use isolated scratch and publish one complete union");
    return 0;
}
