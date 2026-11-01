#define _POSIX_C_SOURCE 200809L
#include "qihse_cluster_maintenance.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void* leave_later(void* arg) {
    qihse_cluster_maintenance_t* g = arg;
    struct timespec delay = {0, 20000000L}; nanosleep(&delay, NULL);
    qihse_cluster_maintenance_leave(g, QIHSE_MAINT_WRITER_RESP);
    return NULL;
}
int main(void) {
    qihse_cluster_maintenance_t* g = qihse_cluster_maintenance_create(); assert(g);
    assert(!qihse_cluster_maintenance_startup_mode(g));
    for (int i=0; i<QIHSE_MAINT_WRITER_CLASS_COUNT; ++i)
        assert(qihse_cluster_maintenance_register(g, (qihse_maintenance_writer_t)i, true));
    assert(qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_RESP));
    pthread_t t; assert(!pthread_create(&t, NULL, leave_later, g));
    uint64_t generation=0;
    uint8_t token[32] = {0};
    assert(qihse_cluster_maintenance_begin(g, 500, 5, &generation, token));
    pthread_join(t, NULL);
    assert(generation);
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof(token); ++i) nonzero |= token[i];
    assert(nonzero);
    qihse_cluster_maintenance_status_t status;
    assert(qihse_cluster_maintenance_status(g, &status));
    assert(status.state == QIHSE_MAINT_HELD);
    struct timespec delay = {0, 10000000L}; nanosleep(&delay, NULL);
    assert(qihse_cluster_maintenance_status(g, &status));
    assert(status.state == QIHSE_MAINT_EXPIRED_HELD);
    assert(!qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_BUS_SLOT));
    uint8_t wrong_token[32];
    memcpy(wrong_token, token, sizeof(wrong_token));
    wrong_token[0] ^= 1;
    assert(!qihse_cluster_maintenance_release_trusted(g, generation, wrong_token));
    assert(qihse_cluster_maintenance_release_trusted(g, generation, token));
    assert(qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_BUS_SLOT));
    qihse_cluster_maintenance_leave(g, QIHSE_MAINT_WRITER_BUS_SLOT);
    qihse_cluster_maintenance_destroy(g);

    g = qihse_cluster_maintenance_create(); assert(g);
    for (int i=0; i<QIHSE_MAINT_WRITER_CLASS_COUNT; ++i)
        (void)qihse_cluster_maintenance_register(g, (qihse_maintenance_writer_t)i,
            i != QIHSE_MAINT_WRITER_BRAIN);
    assert(qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_RESP));
    qihse_cluster_maintenance_leave(g, QIHSE_MAINT_WRITER_RESP);
    assert(!qihse_cluster_maintenance_begin(g, 0, 5000, &generation, token));
    assert(qihse_cluster_maintenance_status(g, &status));
    assert(!status.writer_coverage_complete && status.state == QIHSE_MAINT_OPEN);
    qihse_cluster_maintenance_destroy(g);

    g = qihse_cluster_maintenance_create_startup_pending(); assert(g);
    assert(qihse_cluster_maintenance_startup_mode(g));
    assert(!qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_RESP));
    assert(!qihse_cluster_maintenance_begin(g, 0, 5000, &generation, token));
    for (int i=0; i<QIHSE_MAINT_WRITER_CLASS_COUNT; ++i)
        assert(qihse_cluster_maintenance_register(g, (qihse_maintenance_writer_t)i, true));
    assert(!qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_RESP));
    assert(qihse_cluster_maintenance_seal_startup(g, &generation, token));
    uint8_t retrieved[32] = {0};
    uint64_t retrieved_generation = 0;
    assert(qihse_cluster_maintenance_startup_token(g, &retrieved_generation, retrieved));
    assert(retrieved_generation == generation && memcmp(retrieved, token, sizeof(token)) == 0);
    assert(!qihse_cluster_maintenance_begin(g, 0, 5000, &retrieved_generation, retrieved));
    assert(qihse_cluster_maintenance_status(g, &status));
    assert(status.state == QIHSE_MAINT_HELD && status.lease_expires_ms == 0);
    delay = (struct timespec){0, 10000000L}; nanosleep(&delay, NULL);
    assert(qihse_cluster_maintenance_status(g, &status));
    assert(status.state == QIHSE_MAINT_HELD);
    memcpy(wrong_token, token, sizeof(wrong_token));
    wrong_token[0] ^= 1;
    assert(!qihse_cluster_maintenance_release_trusted(g, generation, wrong_token));
    assert(qihse_cluster_maintenance_release_trusted(g, generation, token));
    assert(!qihse_cluster_maintenance_startup_token(g, &retrieved_generation, retrieved));
    assert(!qihse_cluster_maintenance_startup_mode(g));
    assert(qihse_cluster_maintenance_enter(g, QIHSE_MAINT_WRITER_RESP));
    qihse_cluster_maintenance_leave(g, QIHSE_MAINT_WRITER_RESP);
    qihse_cluster_maintenance_destroy(g);

    g = qihse_cluster_maintenance_create_startup_pending(); assert(g);
    for (int i=0; i<QIHSE_MAINT_WRITER_CLASS_COUNT; ++i)
        (void)qihse_cluster_maintenance_register(g, (qihse_maintenance_writer_t)i,
            i != QIHSE_MAINT_WRITER_BRAIN);
    assert(!qihse_cluster_maintenance_seal_startup(g, &generation, token));
    qihse_cluster_maintenance_destroy(g);
    puts("cluster maintenance gate tests passed"); return 0;
}
