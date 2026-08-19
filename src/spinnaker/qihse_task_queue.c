#include "qihse_task_queue.h"
#include "qihse_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/evp.h>

#define QIHSE_TASK_HASH_MAP_SIZE 4096u

typedef struct qihse_task_node {
    qihse_task_t* task;
    struct qihse_task_node* next;
} qihse_task_node_t;

struct qihse_task_queue {
    qihse_kv_store_t* kv_store;
    qihse_event_stream_t* event_stream;
    qihse_tsdb_t* tsdb;
    size_t max_queue_capacity;
    size_t current_count;

    /* Priority queues (0=CRITICAL, 1=HIGH, 2=NORMAL, 3=LOW) */
    qihse_task_t* prio_heads[QIHSE_TASK_PRIO_COUNT];
    qihse_task_t* prio_tails[QIHSE_TASK_PRIO_COUNT];
    size_t prio_counts[QIHSE_TASK_PRIO_COUNT];

    /* Retrying list */
    qihse_task_t* retry_head;

    /* Global task hash map for O(1) task_id lookup */
    qihse_task_node_t* task_map[QIHSE_TASK_HASH_MAP_SIZE];

    /* Statistics */
    qihse_task_stats_t stats;
    uint64_t total_latency_ns;
    uint64_t latency_sample_count;

    /* Synchronization */
    pthread_mutex_t lock;
    pthread_cond_t ready_cond;
    bool shutting_down;
};

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint32_t task_id_hash(const char* task_id) {
    uint32_t h = 5381u;
    while (*task_id) {
        h = ((h << 5u) + h) ^ (uint32_t)(*task_id);
        task_id++;
    }
    return h % QIHSE_TASK_HASH_MAP_SIZE;
}

void qihse_task_options_init(qihse_task_options_t* opts) {
    if (!opts) return;
    opts->max_retries = QIHSE_TASK_DEFAULT_MAX_RETRIES;
    opts->base_delay_ms = QIHSE_TASK_DEFAULT_BASE_DELAY_MS;
    opts->max_delay_ms = QIHSE_TASK_DEFAULT_MAX_DELAY_MS;
    opts->backoff_factor = 2.0;
    opts->jitter_pct = 10;
    opts->timeout_ms = QIHSE_TASK_DEFAULT_TIMEOUT_MS;
    opts->result_ttl_ms = QIHSE_TASK_DEFAULT_RESULT_TTL_MS;
}

const char* qihse_task_state_name(qihse_task_state_t state) {
    switch (state) {
        case QIHSE_TASK_PENDING: return "PENDING";
        case QIHSE_TASK_STARTED: return "STARTED";
        case QIHSE_TASK_SUCCESS: return "SUCCESS";
        case QIHSE_TASK_FAILURE: return "FAILURE";
        case QIHSE_TASK_RETRYING: return "RETRYING";
        case QIHSE_TASK_DEAD: return "DEAD";
        case QIHSE_TASK_CANCELLED: return "CANCELLED";
        default: return "UNKNOWN";
    }
}

const char* qihse_task_prio_name(qihse_task_prio_t prio) {
    switch (prio) {
        case QIHSE_TASK_PRIO_CRITICAL: return "CRITICAL";
        case QIHSE_TASK_PRIO_HIGH: return "HIGH";
        case QIHSE_TASK_PRIO_NORMAL: return "NORMAL";
        case QIHSE_TASK_PRIO_LOW: return "LOW";
        default: return "NORMAL";
    }
}

bool qihse_task_parse_prio(const char* name, qihse_task_prio_t* out_prio) {
    if (!name || !out_prio) return false;
    if (strcasecmp(name, "CRITICAL") == 0 || strcmp(name, "0") == 0) {
        *out_prio = QIHSE_TASK_PRIO_CRITICAL;
        return true;
    }
    if (strcasecmp(name, "HIGH") == 0 || strcmp(name, "1") == 0) {
        *out_prio = QIHSE_TASK_PRIO_HIGH;
        return true;
    }
    if (strcasecmp(name, "NORMAL") == 0 || strcmp(name, "2") == 0) {
        *out_prio = QIHSE_TASK_PRIO_NORMAL;
        return true;
    }
    if (strcasecmp(name, "LOW") == 0 || strcmp(name, "3") == 0) {
        *out_prio = QIHSE_TASK_PRIO_LOW;
        return true;
    }
    return false;
}

static void compute_task_id(const char* queue_name, const uint8_t* payload, size_t payload_len, uint64_t timestamp_ns, char out_hex[QIHSE_TASK_ID_LEN + 1]) {
    static _Atomic uint64_t g_task_counter = 0;
    uint64_t seq = ++g_task_counter;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        snprintf(out_hex, QIHSE_TASK_ID_LEN + 1, "%016lx%016lx%016lx", timestamp_ns, seq, (uint64_t)payload_len);
        return;
    }
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    if (queue_name) EVP_DigestUpdate(ctx, queue_name, strlen(queue_name));
    if (payload && payload_len > 0) EVP_DigestUpdate(ctx, payload, payload_len);
    EVP_DigestUpdate(ctx, &timestamp_ns, sizeof(timestamp_ns));
    EVP_DigestUpdate(ctx, &seq, sizeof(seq));

    uint8_t digest[48];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < len && i < 48; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
    }
    out_hex[QIHSE_TASK_ID_LEN] = '\0';
}

static qihse_task_t* find_task_locked(qihse_task_queue_t* queue, const char* task_id) {
    if (!queue || !task_id) return NULL;
    uint32_t bucket = task_id_hash(task_id);
    qihse_task_node_t* cur = queue->task_map[bucket];
    while (cur) {
        if (cur->task && strcmp(cur->task->task_id, task_id) == 0) {
            return cur->task;
        }
        cur = cur->next;
    }
    return NULL;
}

static bool map_insert_task_locked(qihse_task_queue_t* queue, qihse_task_t* task) {
    if (!queue || !task) return false;
    uint32_t bucket = task_id_hash(task->task_id);
    qihse_task_node_t* node = (qihse_task_node_t*)malloc(sizeof(qihse_task_node_t));
    if (!node) return false;
    node->task = task;
    node->next = queue->task_map[bucket];
    queue->task_map[bucket] = node;
    return true;
}

static void map_remove_task_locked(qihse_task_queue_t* queue, const char* task_id) {
    if (!queue || !task_id) return;
    uint32_t bucket = task_id_hash(task_id);
    qihse_task_node_t** cur = &queue->task_map[bucket];
    while (*cur) {
        if ((*cur)->task && strcmp((*cur)->task->task_id, task_id) == 0) {
            qihse_task_node_t* to_free = *cur;
            *cur = (*cur)->next;
            free(to_free);
            return;
        }
        cur = &(*cur)->next;
    }
}

static void enqueue_prio_locked(qihse_task_queue_t* queue, qihse_task_t* task) {
    size_t prio = (size_t)task->priority;
    if (prio >= QIHSE_TASK_PRIO_COUNT) prio = QIHSE_TASK_PRIO_NORMAL;
    task->next = NULL;
    if (!queue->prio_heads[prio]) {
        queue->prio_heads[prio] = task;
        queue->prio_tails[prio] = task;
    } else {
        queue->prio_tails[prio]->next = task;
        queue->prio_tails[prio] = task;
    }
    queue->prio_counts[prio]++;
    queue->stats.pending_count++;
}

static void remove_from_prio_locked(qihse_task_queue_t* queue, qihse_task_t* task) {
    size_t prio = (size_t)task->priority;
    if (prio >= QIHSE_TASK_PRIO_COUNT) prio = QIHSE_TASK_PRIO_NORMAL;
    qihse_task_t** cur = &queue->prio_heads[prio];
    qihse_task_t* prev = NULL;
    while (*cur) {
        if (*cur == task) {
            *cur = task->next;
            if (queue->prio_tails[prio] == task) {
                queue->prio_tails[prio] = prev;
            }
            task->next = NULL;
            if (queue->prio_counts[prio] > 0) queue->prio_counts[prio]--;
            if (queue->stats.pending_count > 0) queue->stats.pending_count--;
            return;
        }
        prev = *cur;
        cur = &(*cur)->next;
    }
}

static void remove_from_retry_locked(qihse_task_queue_t* queue, qihse_task_t* task) {
    qihse_task_t** cur = &queue->retry_head;
    while (*cur) {
        if (*cur == task) {
            *cur = task->next;
            task->next = NULL;
            return;
        }
        cur = &(*cur)->next;
    }
}

qihse_task_queue_t* qihse_task_queue_create(const qihse_task_queue_config_t* config) {
    qihse_task_queue_t* q = (qihse_task_queue_t*)calloc(1, sizeof(qihse_task_queue_t));
    if (!q) return NULL;
    if (config) {
        q->kv_store = config->kv_store;
        q->event_stream = config->event_stream;
        q->tsdb = config->tsdb;
        q->max_queue_capacity = config->max_queue_capacity ? config->max_queue_capacity : 1000000u;
    } else {
        q->max_queue_capacity = 1000000u;
    }
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->ready_cond, NULL);
    return q;
}

void qihse_task_free(qihse_task_t* task) {
    if (!task) return;
    if (task->payload) free(task->payload);
    if (task->result) free(task->result);
    free(task);
}

void qihse_task_queue_destroy(qihse_task_queue_t* queue) {
    if (!queue) return;
    pthread_mutex_lock(&queue->lock);
    queue->shutting_down = true;
    pthread_cond_broadcast(&queue->ready_cond);
    pthread_mutex_unlock(&queue->lock);

    /* Free all tasks in map */
    for (size_t i = 0; i < QIHSE_TASK_HASH_MAP_SIZE; i++) {
        qihse_task_node_t* cur = queue->task_map[i];
        while (cur) {
            qihse_task_node_t* next = cur->next;
            qihse_task_free(cur->task);
            free(cur);
            cur = next;
        }
    }

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->ready_cond);
    free(queue);
}

bool qihse_task_submit(
    qihse_task_queue_t* queue,
    const char* queue_name,
    qihse_task_prio_t priority,
    const uint8_t* payload,
    size_t payload_len,
    const qihse_task_options_t* opts,
    char* out_task_id,
    size_t id_buf_len
) {
    if (!queue || !payload || payload_len == 0) return false;
    const char* qname = queue_name && queue_name[0] ? queue_name : "default";

    qihse_task_t* task = (qihse_task_t*)calloc(1, sizeof(qihse_task_t));
    if (!task) return false;

    task->payload = (uint8_t*)malloc(payload_len + 1);
    if (!task->payload) {
        free(task);
        return false;
    }
    memcpy(task->payload, payload, payload_len);
    task->payload[payload_len] = '\0';
    task->payload_len = payload_len;

    snprintf(task->queue_name, sizeof(task->queue_name), "%s", qname);
    task->priority = priority < QIHSE_TASK_PRIO_COUNT ? priority : QIHSE_TASK_PRIO_NORMAL;
    task->state = QIHSE_TASK_PENDING;
    task->created_at_ns = get_time_ns();

    if (opts) {
        task->opts = *opts;
    } else {
        qihse_task_options_init(&task->opts);
    }

    compute_task_id(qname, payload, payload_len, task->created_at_ns, task->task_id);

    if (out_task_id && id_buf_len > 0) {
        snprintf(out_task_id, id_buf_len, "%s", task->task_id);
    }

    pthread_mutex_lock(&queue->lock);
    if (queue->current_count >= queue->max_queue_capacity) {
        pthread_mutex_unlock(&queue->lock);
        qihse_task_free(task);
        return false;
    }

    if (!map_insert_task_locked(queue, task)) {
        pthread_mutex_unlock(&queue->lock);
        qihse_task_free(task);
        return false;
    }

    enqueue_prio_locked(queue, task);
    queue->current_count++;

    /* Write state to KV store if present */
    if (queue->kv_store) {
        char key[128];
        snprintf(key, sizeof(key), "task:%s", task->task_id);
        qihse_kv_set(queue->kv_store, key, "PENDING", 0, 0);
    }

    /* Append to Event Stream if present */
    if (queue->event_stream) {
        char topic[128];
        snprintf(topic, sizeof(topic), "tasks.%s", qname);
        qihse_event_stream_append(queue->event_stream, topic, payload, payload_len);
    }

    pthread_cond_signal(&queue->ready_cond);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool qihse_task_get_state(
    qihse_task_queue_t* queue,
    const char* task_id,
    qihse_task_state_t* out_state
) {
    if (!queue || !task_id || !out_state) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (task) {
        *out_state = task->state;
        pthread_mutex_unlock(&queue->lock);
        return true;
    }
    pthread_mutex_unlock(&queue->lock);

    /* Check KV store if task was completed and evicted */
    if (queue->kv_store) {
        char key[128];
        snprintf(key, sizeof(key), "task:%s", task_id);
        char* val = qihse_kv_get(queue->kv_store, key);
        if (val) {
            if (strcmp(val, "PENDING") == 0) *out_state = QIHSE_TASK_PENDING;
            else if (strcmp(val, "STARTED") == 0) *out_state = QIHSE_TASK_STARTED;
            else if (strcmp(val, "SUCCESS") == 0) *out_state = QIHSE_TASK_SUCCESS;
            else if (strcmp(val, "FAILURE") == 0) *out_state = QIHSE_TASK_FAILURE;
            else if (strcmp(val, "RETRYING") == 0) *out_state = QIHSE_TASK_RETRYING;
            else if (strcmp(val, "DEAD") == 0) *out_state = QIHSE_TASK_DEAD;
            else if (strcmp(val, "CANCELLED") == 0) *out_state = QIHSE_TASK_CANCELLED;
            else *out_state = QIHSE_TASK_PENDING;
            free(val);
            return true;
        }
    }
    return false;
}

bool qihse_task_get_result(
    qihse_task_queue_t* queue,
    const char* task_id,
    uint8_t** out_result,
    size_t* out_result_len,
    char* out_error,
    size_t error_buf_len
) {
    if (!queue || !task_id) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (task) {
        if (task->state == QIHSE_TASK_SUCCESS) {
            if (out_result && out_result_len) {
                if (task->result) {
                    *out_result = (uint8_t*)malloc(task->result_len + 1);
                    if (*out_result) {
                        memcpy(*out_result, task->result, task->result_len);
                        (*out_result)[task->result_len] = '\0';
                        *out_result_len = task->result_len;
                    } else {
                        *out_result_len = 0;
                    }
                } else {
                    *out_result = (uint8_t*)strdup("");
                    *out_result_len = 0;
                }
            }
            pthread_mutex_unlock(&queue->lock);
            return true;
        }
        if (task->state == QIHSE_TASK_FAILURE || task->state == QIHSE_TASK_DEAD) {
            if (out_error && error_buf_len > 0) {
                snprintf(out_error, error_buf_len, "%s", task->error_msg[0] ? task->error_msg : "Task failed");
            }
            pthread_mutex_unlock(&queue->lock);
            return false;
        }
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    pthread_mutex_unlock(&queue->lock);

    /* Fallback to KV store for results */
    if (queue->kv_store) {
        char key[128];
        snprintf(key, sizeof(key), "result:%s", task_id);
        char* val = qihse_kv_get(queue->kv_store, key);
        if (val) {
            size_t len = strlen(val);
            if (out_result && out_result_len) {
                *out_result = (uint8_t*)val;
                *out_result_len = len;
            } else {
                free(val);
            }
            return true;
        }
    }
    return false;
}

bool qihse_task_cancel(
    qihse_task_queue_t* queue,
    const char* task_id
) {
    if (!queue || !task_id) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (!task) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    task->cancel_requested = true;
    if (task->state == QIHSE_TASK_PENDING) {
        remove_from_prio_locked(queue, task);
        task->state = QIHSE_TASK_CANCELLED;
        queue->stats.cancelled_count++;
        if (queue->kv_store) {
            char key[128];
            snprintf(key, sizeof(key), "task:%s", task_id);
            qihse_kv_set(queue->kv_store, key, "CANCELLED", 0, 0);
        }
    } else if (task->state == QIHSE_TASK_RETRYING) {
        remove_from_retry_locked(queue, task);
        task->state = QIHSE_TASK_CANCELLED;
        queue->stats.cancelled_count++;
        if (queue->kv_store) {
            char key[128];
            snprintf(key, sizeof(key), "task:%s", task_id);
            qihse_kv_set(queue->kv_store, key, "CANCELLED", 0, 0);
        }
    }
    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool qihse_task_retry(
    qihse_task_queue_t* queue,
    const char* task_id
) {
    if (!queue || !task_id) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (!task) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    if (task->state == QIHSE_TASK_DEAD || task->state == QIHSE_TASK_FAILURE || task->state == QIHSE_TASK_CANCELLED) {
        task->state = QIHSE_TASK_PENDING;
        task->retry_count = 0;
        task->cancel_requested = false;
        task->error_msg[0] = '\0';
        enqueue_prio_locked(queue, task);
        if (queue->kv_store) {
            char key[128];
            snprintf(key, sizeof(key), "task:%s", task_id);
            qihse_kv_set(queue->kv_store, key, "PENDING", 0, 0);
        }
        pthread_cond_signal(&queue->ready_cond);
        pthread_mutex_unlock(&queue->lock);
        return true;
    }
    pthread_mutex_unlock(&queue->lock);
    return false;
}

bool qihse_task_delete(
    qihse_task_queue_t* queue,
    const char* task_id
) {
    if (!queue || !task_id) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (!task) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    if (task->state == QIHSE_TASK_PENDING) {
        remove_from_prio_locked(queue, task);
    } else if (task->state == QIHSE_TASK_RETRYING) {
        remove_from_retry_locked(queue, task);
    }
    map_remove_task_locked(queue, task_id);
    if (queue->current_count > 0) queue->current_count--;
    qihse_task_free(task);

    if (queue->kv_store) {
        char key[128];
        snprintf(key, sizeof(key), "task:%s", task_id);
        qihse_kv_del(queue->kv_store, key);
        snprintf(key, sizeof(key), "result:%s", task_id);
        qihse_kv_del(queue->kv_store, key);
        snprintf(key, sizeof(key), "dead:%s", task_id);
        qihse_kv_del(queue->kv_store, key);
    }
    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool qihse_task_stats(
    qihse_task_queue_t* queue,
    const char* queue_name,
    qihse_task_stats_t* out_stats
) {
    if (!queue || !out_stats) return false;
    pthread_mutex_lock(&queue->lock);
    if (!queue_name || !queue_name[0]) {
        *out_stats = queue->stats;
        if (queue->latency_sample_count > 0) {
            out_stats->avg_latency_ms = (double)queue->total_latency_ns / (double)queue->latency_sample_count / 1000000.0;
        } else {
            out_stats->avg_latency_ms = 0.0;
        }
    } else {
        /* Filter by queue_name */
        memset(out_stats, 0, sizeof(*out_stats));
        for (size_t b = 0; b < QIHSE_TASK_HASH_MAP_SIZE; b++) {
            qihse_task_node_t* cur = queue->task_map[b];
            while (cur) {
                if (cur->task && strcmp(cur->task->queue_name, queue_name) == 0) {
                    switch (cur->task->state) {
                        case QIHSE_TASK_PENDING: out_stats->pending_count++; break;
                        case QIHSE_TASK_STARTED: out_stats->started_count++; break;
                        case QIHSE_TASK_SUCCESS: out_stats->success_count++; break;
                        case QIHSE_TASK_FAILURE: out_stats->failure_count++; break;
                        case QIHSE_TASK_RETRYING: out_stats->pending_count++; break;
                        case QIHSE_TASK_DEAD: out_stats->dead_count++; break;
                        case QIHSE_TASK_CANCELLED: out_stats->cancelled_count++; break;
                    }
                }
                cur = cur->next;
            }
        }
        out_stats->total_executed = out_stats->success_count + out_stats->failure_count + out_stats->dead_count;
    }
    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool qihse_task_list_queue(
    qihse_task_queue_t* queue,
    const char* queue_name,
    char*** out_task_ids,
    size_t* out_count
) {
    if (!queue || !out_task_ids || !out_count) return false;
    const char* qname = queue_name && queue_name[0] ? queue_name : NULL;

    pthread_mutex_lock(&queue->lock);
    size_t count = 0;
    for (size_t b = 0; b < QIHSE_TASK_HASH_MAP_SIZE; b++) {
        qihse_task_node_t* cur = queue->task_map[b];
        while (cur) {
            if (cur->task && (!qname || strcmp(cur->task->queue_name, qname) == 0)) {
                count++;
            }
            cur = cur->next;
        }
    }

    if (count == 0) {
        *out_task_ids = NULL;
        *out_count = 0;
        pthread_mutex_unlock(&queue->lock);
        return true;
    }

    char** ids = (char**)malloc(count * sizeof(char*));
    if (!ids) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }

    size_t idx = 0;
    for (size_t b = 0; b < QIHSE_TASK_HASH_MAP_SIZE && idx < count; b++) {
        qihse_task_node_t* cur = queue->task_map[b];
        while (cur && idx < count) {
            if (cur->task && (!qname || strcmp(cur->task->queue_name, qname) == 0)) {
                ids[idx] = strdup(cur->task->task_id);
                idx++;
            }
            cur = cur->next;
        }
    }
    pthread_mutex_unlock(&queue->lock);

    *out_task_ids = ids;
    *out_count = idx;
    return true;
}

void qihse_task_free_id_list(char** task_ids, size_t count) {
    if (!task_ids) return;
    for (size_t i = 0; i < count; i++) {
        if (task_ids[i]) free(task_ids[i]);
    }
    free(task_ids);
}

static void check_retries_locked(qihse_task_queue_t* queue) {
    uint64_t now = get_time_ns();
    qihse_task_t** cur = &queue->retry_head;
    while (*cur) {
        qihse_task_t* t = *cur;
        if (t->next_retry_at_ns <= now) {
            *cur = t->next;
            t->state = QIHSE_TASK_PENDING;
            enqueue_prio_locked(queue, t);
            if (queue->kv_store) {
                char key[128];
                snprintf(key, sizeof(key), "task:%s", t->task_id);
                qihse_kv_set(queue->kv_store, key, "PENDING", 0, 0);
            }
        } else {
            cur = &(*cur)->next;
        }
    }
}

qihse_task_t* qihse_task_pop(
    qihse_task_queue_t* queue,
    uint32_t timeout_ms
) {
    if (!queue) return NULL;
    pthread_mutex_lock(&queue->lock);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t nsec = (uint64_t)ts.tv_nsec + (uint64_t)timeout_ms * 1000000ULL;
    ts.tv_sec += (time_t)(nsec / 1000000000ULL);
    ts.tv_nsec = (long)(nsec % 1000000000ULL);

    while (!queue->shutting_down) {
        check_retries_locked(queue);

        /* Find highest non-empty priority (0..3) */
        for (size_t p = 0; p < QIHSE_TASK_PRIO_COUNT; p++) {
            if (queue->prio_heads[p]) {
                qihse_task_t* task = queue->prio_heads[p];
                queue->prio_heads[p] = task->next;
                if (!queue->prio_heads[p]) queue->prio_tails[p] = NULL;
                task->next = NULL;
                if (queue->prio_counts[p] > 0) queue->prio_counts[p]--;
                if (queue->stats.pending_count > 0) queue->stats.pending_count--;

                task->state = QIHSE_TASK_STARTED;
                task->started_at_ns = get_time_ns();
                queue->stats.started_count++;

                if (queue->kv_store) {
                    char key[128];
                    snprintf(key, sizeof(key), "task:%s", task->task_id);
                    qihse_kv_set(queue->kv_store, key, "STARTED", 0, 0);
                }

                pthread_mutex_unlock(&queue->lock);
                return task;
            }
        }

        if (timeout_ms == 0) break;

        int rc = pthread_cond_timedwait(&queue->ready_cond, &queue->lock, &ts);
        if (rc == ETIMEDOUT) break;
    }

    pthread_mutex_unlock(&queue->lock);
    return NULL;
}

bool qihse_task_complete(
    qihse_task_queue_t* queue,
    const char* task_id,
    const uint8_t* result,
    size_t result_len
) {
    if (!queue || !task_id) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (!task) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }

    task->state = QIHSE_TASK_SUCCESS;
    task->completed_at_ns = get_time_ns();

    if (task->result) free(task->result);
    if (result && result_len > 0) {
        task->result = (uint8_t*)malloc(result_len);
        if (task->result) {
            memcpy(task->result, result, result_len);
            task->result_len = result_len;
        }
    } else {
        task->result = NULL;
        task->result_len = 0;
    }

    if (queue->stats.started_count > 0) queue->stats.started_count--;
    queue->stats.success_count++;
    queue->stats.total_executed++;

    uint64_t latency_ns = (task->completed_at_ns > task->started_at_ns) ? (task->completed_at_ns - task->started_at_ns) : 0;
    queue->total_latency_ns += latency_ns;
    queue->latency_sample_count++;

    if (queue->kv_store) {
        char key[128];
        snprintf(key, sizeof(key), "task:%s", task_id);
        qihse_kv_set(queue->kv_store, key, "SUCCESS", 0, 0);

        if (task->result && task->result_len > 0) {
            snprintf(key, sizeof(key), "result:%s", task_id);
            /* Store result with TTL */
            char* res_str = (char*)malloc(task->result_len + 1);
            if (res_str) {
                memcpy(res_str, task->result, task->result_len);
                res_str[task->result_len] = '\0';
                qihse_kv_set(queue->kv_store, key, res_str, 0, 0);
                qihse_kv_expire(queue->kv_store, key, task->opts.result_ttl_ms, NULL);
                free(res_str);
            }
        }
    }

    if (queue->tsdb) {
        char metric_key[128];
        snprintf(metric_key, sizeof(metric_key), "task.latency.%s", task->queue_name);
        uint32_t series_id = 2166136261u;
        for (const char* p = metric_key; *p; p++) {
            series_id = (series_id ^ (uint8_t)(*p)) * 16777619u;
        }
        double latency_ms = (double)latency_ns / 1000000.0;
        uint64_t ts_ms = task->completed_at_ns / 1000000ULL;
        qihse_tsdb_insert(queue->tsdb, series_id, ts_ms, latency_ms, 0, 0);
    }

    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool qihse_task_fail(
    qihse_task_queue_t* queue,
    const char* task_id,
    const char* error_msg
) {
    if (!queue || !task_id) return false;
    pthread_mutex_lock(&queue->lock);
    qihse_task_t* task = find_task_locked(queue, task_id);
    if (!task) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }

    if (error_msg) {
        snprintf(task->error_msg, sizeof(task->error_msg), "%s", error_msg);
    } else {
        snprintf(task->error_msg, sizeof(task->error_msg), "Task failed without specific error");
    }

    if (queue->stats.started_count > 0) queue->stats.started_count--;

    if (task->retry_count < task->opts.max_retries && !task->cancel_requested) {
        task->retry_count++;
        task->state = QIHSE_TASK_RETRYING;
        queue->stats.failure_count++;

        /* Exponential backoff with jitter */
        double delay = (double)task->opts.base_delay_ms * pow(task->opts.backoff_factor, (double)(task->retry_count - 1));
        if (delay > (double)task->opts.max_delay_ms) delay = (double)task->opts.max_delay_ms;
        if (task->opts.jitter_pct > 0) {
            int jitter_range = (int)(task->opts.jitter_pct * 2 + 1);
            int jitter = (rand() % jitter_range) - (int)task->opts.jitter_pct;
            delay = delay * (1.0 + (double)jitter / 100.0);
        }
        if (delay < 1.0) delay = 1.0;

        task->next_retry_at_ns = get_time_ns() + (uint64_t)(delay * 1000000.0);
        task->next = queue->retry_head;
        queue->retry_head = task;

        if (queue->kv_store) {
            char key[128];
            snprintf(key, sizeof(key), "task:%s", task_id);
            qihse_kv_set(queue->kv_store, key, "RETRYING", 0, 0);
        }
    } else {
        task->state = QIHSE_TASK_DEAD;
        task->completed_at_ns = get_time_ns();
        queue->stats.dead_count++;
        queue->stats.total_executed++;

        if (queue->kv_store) {
            char key[128];
            snprintf(key, sizeof(key), "task:%s", task_id);
            qihse_kv_set(queue->kv_store, key, "DEAD", 0, 0);
            snprintf(key, sizeof(key), "dead:%s", task_id);
            qihse_kv_set(queue->kv_store, key, task->error_msg, 0, 0);
        }
    }

    pthread_mutex_unlock(&queue->lock);
    return true;
}
