#include "qihse_workload_admission.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define WORKERS 16

typedef struct {
    qihse_workload_admission_t* gate;
    qihse_user_t* user;
    pthread_barrier_t* start;
    pthread_barrier_t* finish;
    pthread_mutex_t* mutex;
    int* acquired;
    int* busy;
    size_t bytes;
} worker_args_t;

static void* acquire_worker(void* opaque) {
    worker_args_t* args = opaque;
    qihse_workload_lease_t lease = {0};
    int barrier = pthread_barrier_wait(args->start);
    assert(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
    qihse_admission_result_t result = args->bytes ?
        qihse_workload_admission_try_acquire_bytes(args->gate, args->user,
            QIHSE_WORKLOAD_HEAVY, args->bytes, &lease) :
        qihse_workload_admission_try_acquire(args->gate, args->user,
            QIHSE_WORKLOAD_HEAVY, &lease);
    pthread_mutex_lock(args->mutex);
    if (result == QIHSE_ADMISSION_ACQUIRED) (*args->acquired)++;
    else if (result == QIHSE_ADMISSION_BUSY) (*args->busy)++;
    else assert(0);
    pthread_mutex_unlock(args->mutex);
    barrier = pthread_barrier_wait(args->finish);
    assert(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
    if (result == QIHSE_ADMISSION_ACQUIRED)
        assert(qihse_workload_admission_release(&lease));
    return NULL;
}

int main(void) {
    char root[] = "build/workload_admission_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("WorkloadGateOperator123!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    assert(operator_user);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7u, 7101u,
        QIHSE_ROLE_GUEST, 0u, 0u, "WorkloadGateTenant7123!", false);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(operator_user, 8u, 8101u,
        QIHSE_ROLE_GUEST, 0u, 0u, "WorkloadGateTenant8123!", false);
    assert(tenant7 && tenant8);

    assert(!qihse_workload_admission_create(0u, 1u, 1u));
    assert(!qihse_workload_admission_create(4u, 4u, 1u));
    qihse_workload_admission_t* gate = qihse_workload_admission_create(4u, 2u, 2u);
    assert(gate);
    qihse_workload_lease_t heavy1 = {0}, heavy2 = {0}, foreground1 = {0}, foreground2 = {0};
    qihse_workload_lease_t denied = {0};
    assert(qihse_workload_admission_try_acquire(gate, NULL, QIHSE_WORKLOAD_HEAVY,
        &denied) == QIHSE_ADMISSION_INVALID);
    assert(qihse_workload_admission_try_acquire(gate, operator_user,
        QIHSE_WORKLOAD_HEAVY, &heavy1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire(gate, operator_user,
        QIHSE_WORKLOAD_HEAVY, &heavy2) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, &denied) == QIHSE_ADMISSION_BUSY);
    assert(qihse_workload_admission_try_acquire(gate, tenant7,
        QIHSE_WORKLOAD_FOREGROUND, &foreground1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire(gate, tenant8,
        QIHSE_WORKLOAD_FOREGROUND, &foreground2) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire(gate, tenant7,
        QIHSE_WORKLOAD_FOREGROUND, &denied) == QIHSE_ADMISSION_BUSY);
    assert(!qihse_workload_admission_destroy(gate));
    qihse_workload_lease_t copied = heavy1;
    assert(qihse_workload_admission_release(&heavy1));
    assert(!qihse_workload_admission_release(&heavy1));
    assert(!qihse_workload_admission_release(&copied));
    assert(qihse_workload_admission_release(&heavy2));
    assert(qihse_workload_admission_release(&foreground1));
    assert(qihse_workload_admission_release(&foreground2));
    assert(qihse_workload_admission_destroy(gate));

    gate = qihse_workload_admission_create(4u, 3u, 1u);
    assert(gate);
    assert(qihse_workload_admission_try_acquire(gate, tenant7,
        QIHSE_WORKLOAD_FOREGROUND, &foreground1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire(gate, tenant7,
        QIHSE_WORKLOAD_FOREGROUND, &denied) == QIHSE_ADMISSION_BUSY);
    assert(qihse_workload_admission_try_acquire(gate, tenant8,
        QIHSE_WORKLOAD_FOREGROUND, &foreground2) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_release(&foreground1));
    assert(qihse_workload_admission_release(&foreground2));
    assert(qihse_workload_admission_destroy(gate));

    gate = qihse_workload_admission_create(4u, 2u, 4u);
    assert(gate);
    pthread_barrier_t start, finish;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    assert(pthread_barrier_init(&start, NULL, WORKERS) == 0);
    assert(pthread_barrier_init(&finish, NULL, WORKERS) == 0);
    int acquired = 0, busy = 0;
    worker_args_t args = {gate, operator_user, &start, &finish, &mutex, &acquired, &busy, 0u};
    pthread_t workers[WORKERS];
    for (size_t i = 0; i < WORKERS; i++)
        assert(pthread_create(&workers[i], NULL, acquire_worker, &args) == 0);
    for (size_t i = 0; i < WORKERS; i++)
        assert(pthread_join(workers[i], NULL) == 0);
    assert(acquired == 2 && busy == WORKERS - 2);
    assert(pthread_barrier_destroy(&start) == 0);
    assert(pthread_barrier_destroy(&finish) == 0);
    assert(pthread_mutex_destroy(&mutex) == 0);
    assert(qihse_workload_admission_destroy(gate));

    assert(!qihse_workload_admission_create_with_memory(4u, 2u, 2u, 0u, 0u, 0u));
    assert(!qihse_workload_admission_create_with_memory(4u, 2u, 2u, 100u, 100u, 70u));
    gate = qihse_workload_admission_create_with_memory(4u, 2u, 3u,
                                                       100u, 60u, 70u);
    assert(gate);
    assert(qihse_workload_admission_try_acquire(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, &denied) == QIHSE_ADMISSION_INVALID);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, 0u, &denied) == QIHSE_ADMISSION_INVALID);
    assert(qihse_workload_admission_try_acquire_bytes(gate, NULL,
        QIHSE_WORKLOAD_HEAVY, 1u, &denied) == QIHSE_ADMISSION_INVALID);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, 40u, &heavy1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant8,
        QIHSE_WORKLOAD_HEAVY, 20u, &heavy2) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, 1u, &denied) == QIHSE_ADMISSION_BUSY);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_FOREGROUND, 31u, &denied) == QIHSE_ADMISSION_BUSY);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_FOREGROUND, 30u, &foreground1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant8,
        QIHSE_WORKLOAD_FOREGROUND, 10u, &foreground2) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant8,
        QIHSE_WORKLOAD_FOREGROUND, 1u, &denied) == QIHSE_ADMISSION_BUSY);
    assert(denied.owner == NULL && denied.id == 0u);
    assert(!qihse_workload_admission_destroy(gate));
    copied = heavy1;
    assert(qihse_workload_admission_release(&heavy1));
    assert(!qihse_workload_admission_release(&copied));
    assert(qihse_workload_admission_release(&heavy2));
    assert(qihse_workload_admission_release(&foreground1));
    assert(qihse_workload_admission_release(&foreground2));
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, 60u, &heavy1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_release(&heavy1));
    assert(qihse_workload_admission_destroy(gate));

    gate = qihse_workload_admission_create_with_memory(4u, 2u, 4u,
                                                       SIZE_MAX, SIZE_MAX - 1u,
                                                       SIZE_MAX);
    assert(gate);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant7,
        QIHSE_WORKLOAD_HEAVY, SIZE_MAX - 2u, &heavy1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant8,
        QIHSE_WORKLOAD_HEAVY, 2u, &denied) == QIHSE_ADMISSION_BUSY);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant8,
        QIHSE_WORKLOAD_FOREGROUND, 1u, &foreground1) == QIHSE_ADMISSION_ACQUIRED);
    assert(qihse_workload_admission_try_acquire_bytes(gate, tenant8,
        QIHSE_WORKLOAD_FOREGROUND, 2u, &denied) == QIHSE_ADMISSION_BUSY);
    assert(qihse_workload_admission_release(&heavy1));
    assert(qihse_workload_admission_release(&foreground1));
    assert(qihse_workload_admission_destroy(gate));

    gate = qihse_workload_admission_create_with_memory(8u, 7u, 8u,
                                                       100u, 80u, 100u);
    assert(gate);
    assert(pthread_barrier_init(&start, NULL, WORKERS) == 0);
    assert(pthread_barrier_init(&finish, NULL, WORKERS) == 0);
    assert(pthread_mutex_init(&mutex, NULL) == 0);
    acquired = busy = 0;
    worker_args_t memory_args = {gate, operator_user, &start, &finish,
                                 &mutex, &acquired, &busy, 50u};
    for (size_t i = 0; i < WORKERS; i++)
        assert(pthread_create(&workers[i], NULL, acquire_worker, &memory_args) == 0);
    for (size_t i = 0; i < WORKERS; i++)
        assert(pthread_join(workers[i], NULL) == 0);
    assert(acquired == 1 && busy == WORKERS - 1);
    assert(pthread_barrier_destroy(&start) == 0);
    assert(pthread_barrier_destroy(&finish) == 0);
    assert(pthread_mutex_destroy(&mutex) == 0);
    assert(qihse_workload_admission_destroy(gate));
    puts("test_workload_admission: all assertions passed");
    return 0;
}
