#define _POSIX_C_SOURCE 200809L
#include "qihse_cluster_maintenance.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct qihse_cluster_maintenance {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    qihse_maintenance_state_t state;
    uint64_t generation;
    uint64_t expires_ms;
    uint8_t token[32];
    uint64_t active[QIHSE_MAINT_WRITER_CLASS_COUNT];
    bool registered[QIHSE_MAINT_WRITER_CLASS_COUNT];
    bool complete;
    bool startup_pending;
    bool startup_held;
};

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool valid_writer(qihse_maintenance_writer_t writer) {
    return (int)writer >= 0 && writer < QIHSE_MAINT_WRITER_CLASS_COUNT;
}

static qihse_cluster_maintenance_t* maintenance_create(bool startup_pending) {
    qihse_cluster_maintenance_t* gate = calloc(1, sizeof(*gate));
    if (!gate) return NULL;
    pthread_condattr_t attr;
    if (pthread_mutex_init(&gate->lock, NULL) != 0) { free(gate); return NULL; }
    if (pthread_condattr_init(&attr) != 0) {
        pthread_mutex_destroy(&gate->lock); free(gate); return NULL;
    }
    int rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc == 0) rc = pthread_cond_init(&gate->changed, &attr);
    pthread_condattr_destroy(&attr);
    if (rc != 0) {
        pthread_mutex_destroy(&gate->lock); free(gate); return NULL;
    }
    gate->complete = true;
    gate->startup_pending = startup_pending;
    if (startup_pending) gate->state = QIHSE_MAINT_STARTUP_PENDING;
    return gate;
}

qihse_cluster_maintenance_t* qihse_cluster_maintenance_create(void) {
    return maintenance_create(false);
}

qihse_cluster_maintenance_t* qihse_cluster_maintenance_create_startup_pending(void) {
    return maintenance_create(true);
}

void qihse_cluster_maintenance_destroy(qihse_cluster_maintenance_t* gate) {
    if (!gate) return;
    pthread_mutex_lock(&gate->lock);
    bool idle = gate->state == QIHSE_MAINT_OPEN ||
                gate->state == QIHSE_MAINT_STARTUP_PENDING;
    for (size_t i = 0; i < QIHSE_MAINT_WRITER_CLASS_COUNT; ++i)
        idle = idle && gate->active[i] == 0;
    pthread_mutex_unlock(&gate->lock);
    if (!idle) return; /* Never free a held gate or one with admitted writers. */
    OPENSSL_cleanse(gate->token, sizeof(gate->token));
    pthread_cond_destroy(&gate->changed);
    pthread_mutex_destroy(&gate->lock);
    free(gate);
}

bool qihse_cluster_maintenance_register(qihse_cluster_maintenance_t* gate,
                                        qihse_maintenance_writer_t writer,
                                        bool instrumented) {
    if (!gate || !valid_writer(writer)) return false;
    pthread_mutex_lock(&gate->lock);
    if (gate->state != QIHSE_MAINT_OPEN &&
        !(gate->startup_pending && gate->state == QIHSE_MAINT_STARTUP_PENDING)) {
        pthread_mutex_unlock(&gate->lock);
        return false;
    }
    gate->registered[writer] = instrumented;
    if (!instrumented) gate->complete = false;
    pthread_mutex_unlock(&gate->lock);
    return instrumented;
}

bool qihse_cluster_maintenance_enter(qihse_cluster_maintenance_t* gate,
                                     qihse_maintenance_writer_t writer) {
    if (!gate || !valid_writer(writer)) return false;
    pthread_mutex_lock(&gate->lock);
    /* Uninstrumented writers prevent a global hold, not normal service.
     * Keep independently instrumented paths available while OPEN. */
    bool admitted = gate->state == QIHSE_MAINT_OPEN &&
                    !gate->startup_pending && gate->registered[writer];
    if (admitted) gate->active[writer]++;
    pthread_mutex_unlock(&gate->lock);
    return admitted;
}

void qihse_cluster_maintenance_leave(qihse_cluster_maintenance_t* gate,
                                     qihse_maintenance_writer_t writer) {
    if (!gate || !valid_writer(writer)) return;
    pthread_mutex_lock(&gate->lock);
    if (gate->active[writer] != 0) {
        gate->active[writer]--;
        pthread_cond_broadcast(&gate->changed);
    }
    pthread_mutex_unlock(&gate->lock);
}

static bool drained(const qihse_cluster_maintenance_t* gate) {
    for (size_t i = 0; i < QIHSE_MAINT_WRITER_CLASS_COUNT; ++i)
        if (!gate->registered[i] || gate->active[i] != 0) return false;
    return true;
}

bool qihse_cluster_maintenance_begin(qihse_cluster_maintenance_t* gate,
                                     uint64_t timeout_ms, uint64_t lease_ms,
                                     uint64_t* generation, uint8_t token[32]) {
    if (!gate || !lease_ms || !generation || !token ||
        timeout_ms > (uint64_t)INT64_MAX / 1000000u ||
        lease_ms > (uint64_t)INT64_MAX / 1000000u) return false;
    uint8_t candidate_token[32];
    if (RAND_bytes(candidate_token, sizeof(candidate_token)) != 1) return false;
    pthread_mutex_lock(&gate->lock);
    if (gate->state != QIHSE_MAINT_OPEN || gate->startup_pending ||
        gate->startup_held || !gate->complete) {
        pthread_mutex_unlock(&gate->lock);
        OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
        return false;
    }
    for (size_t i = 0; i < QIHSE_MAINT_WRITER_CLASS_COUNT; ++i) {
        if (!gate->registered[i]) {
            pthread_mutex_unlock(&gate->lock);
            OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
            return false;
        }
    }
    gate->state = QIHSE_MAINT_DRAINING;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        gate->state = QIHSE_MAINT_OPEN;
        pthread_mutex_unlock(&gate->lock);
        OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
        return false;
    }
    deadline.tv_sec += (time_t)(timeout_ms / 1000u);
    deadline.tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    while (!drained(gate)) {
        int rc = pthread_cond_timedwait(&gate->changed, &gate->lock, &deadline);
        if (rc == ETIMEDOUT) {
            gate->state = QIHSE_MAINT_OPEN;
            pthread_cond_broadcast(&gate->changed);
            pthread_mutex_unlock(&gate->lock);
            OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
            return false;
        }
        if (rc != 0) {
            gate->state = QIHSE_MAINT_OPEN;
            pthread_cond_broadcast(&gate->changed);
            pthread_mutex_unlock(&gate->lock);
            OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
            return false;
        }
    }
    uint64_t now = monotonic_ms();
    if (now == 0 || UINT64_MAX - now < lease_ms) {
        gate->state = QIHSE_MAINT_OPEN;
        pthread_cond_broadcast(&gate->changed);
        pthread_mutex_unlock(&gate->lock);
        OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
        return false;
    }
    gate->generation++;
    if (gate->generation == 0) gate->generation++;
    memcpy(gate->token, candidate_token, sizeof(gate->token));
    OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
    gate->expires_ms = now + lease_ms;
    gate->state = QIHSE_MAINT_HELD;
    *generation = gate->generation;
    memcpy(token, gate->token, sizeof(gate->token));
    pthread_mutex_unlock(&gate->lock);
    return true;
}

bool qihse_cluster_maintenance_seal_startup(qihse_cluster_maintenance_t* gate,
                                             uint64_t* generation,
                                             uint8_t token[32]) {
    if (!gate || !generation || !token) return false;
    uint8_t candidate_token[32];
    if (RAND_bytes(candidate_token, sizeof(candidate_token)) != 1) return false;
    pthread_mutex_lock(&gate->lock);
    bool ready = gate->startup_pending &&
                 gate->state == QIHSE_MAINT_STARTUP_PENDING &&
                 gate->complete && drained(gate);
    if (!ready) {
        pthread_mutex_unlock(&gate->lock);
        OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
        return false;
    }
    uint64_t startup_generation = 0;
    memcpy(&startup_generation, candidate_token, sizeof(startup_generation));
    startup_generation &= (uint64_t)INT64_MAX;
    if (startup_generation == 0) startup_generation = 1;
    gate->generation = startup_generation;
    memcpy(gate->token, candidate_token, sizeof(gate->token));
    OPENSSL_cleanse(candidate_token, sizeof(candidate_token));
    gate->expires_ms = 0;
    gate->startup_pending = false;
    gate->startup_held = true;
    gate->state = QIHSE_MAINT_HELD;
    *generation = gate->generation;
    memcpy(token, gate->token, sizeof(gate->token));
    pthread_mutex_unlock(&gate->lock);
    return true;
}

bool qihse_cluster_maintenance_startup_token(qihse_cluster_maintenance_t* gate,
                                              uint64_t* generation,
                                              uint8_t token[32]) {
    if (!gate || !generation || !token) return false;
    pthread_mutex_lock(&gate->lock);
    bool ok = gate->startup_held && gate->state == QIHSE_MAINT_HELD;
    if (ok) {
        *generation = gate->generation;
        memcpy(token, gate->token, sizeof(gate->token));
    }
    pthread_mutex_unlock(&gate->lock);
    return ok;
}

bool qihse_cluster_maintenance_startup_mode(qihse_cluster_maintenance_t* gate) {
    if (!gate) return false;
    pthread_mutex_lock(&gate->lock);
    bool startup_mode = gate->startup_pending || gate->startup_held;
    pthread_mutex_unlock(&gate->lock);
    return startup_mode;
}

bool qihse_cluster_maintenance_release_trusted(qihse_cluster_maintenance_t* gate,
                                               uint64_t generation,
                                               const uint8_t token[32]) {
    if (!gate || !token) return false;
    pthread_mutex_lock(&gate->lock);
    bool ok = (gate->state == QIHSE_MAINT_HELD ||
               gate->state == QIHSE_MAINT_EXPIRED_HELD) &&
              generation == gate->generation &&
              CRYPTO_memcmp(token, gate->token, sizeof(gate->token)) == 0;
    if (ok) {
        gate->state = QIHSE_MAINT_OPEN;
        gate->startup_held = false;
        OPENSSL_cleanse(gate->token, sizeof(gate->token));
        gate->expires_ms = 0;
        pthread_cond_broadcast(&gate->changed);
    }
    pthread_mutex_unlock(&gate->lock);
    return ok;
}

bool qihse_cluster_maintenance_status(qihse_cluster_maintenance_t* gate,
                                      qihse_cluster_maintenance_status_t* status) {
    if (!gate || !status) return false;
    pthread_mutex_lock(&gate->lock);
    if (gate->state == QIHSE_MAINT_HELD && gate->expires_ms != 0 &&
        monotonic_ms() >= gate->expires_ms)
        gate->state = QIHSE_MAINT_EXPIRED_HELD;
    memset(status, 0, sizeof(*status));
    status->state = gate->state;
    status->generation = gate->generation;
    memcpy(status->token, gate->token, sizeof(status->token));
    status->lease_expires_ms = gate->expires_ms;
    status->writer_coverage_complete = gate->complete;
    for (size_t i = 0; i < QIHSE_MAINT_WRITER_CLASS_COUNT; ++i) {
        status->writer_registered[i] = gate->registered[i];
        status->writer_coverage_complete = status->writer_coverage_complete &&
                                           gate->registered[i];
    }
    memcpy(status->active, gate->active, sizeof(status->active));
    pthread_mutex_unlock(&gate->lock);
    return true;
}
