#include "qihse_task_scheduler.h"
#include "qihse_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>

#define QIHSE_MAX_SCHEDULES 1024u

struct qihse_task_scheduler {
    qihse_task_queue_t* queue;
    qihse_tsdb_t* tsdb;
    uint32_t tick_ms;

    qihse_schedule_entry_t entries[QIHSE_MAX_SCHEDULES];
    size_t count;

    bool running;
    pthread_t thread;
    pthread_mutex_t lock;
};

void qihse_task_scheduler_config_init(qihse_task_scheduler_config_t* config) {
    if (!config) return;
    config->queue = NULL;
    config->tsdb = NULL;
    config->tick_ms = 10u;
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static bool parse_cron_field(const char* str, int min_val, int max_val, uint64_t* mask) {
    *mask = 0;
    if (!str || !*str) return false;

    char buf[128];
    snprintf(buf, sizeof(buf), "%s", str);

    char* saveptr = NULL;
    char* token = strtok_r(buf, ",", &saveptr);
    while (token) {
        while (isspace((unsigned char)*token)) token++;

        if (strcmp(token, "*") == 0) {
            for (int i = min_val; i <= max_val; i++) *mask |= (1ULL << i);
        } else if (strncmp(token, "*/", 2) == 0) {
            int step = atoi(token + 2);
            if (step <= 0) return false;
            for (int i = min_val; i <= max_val; i += step) *mask |= (1ULL << i);
        } else if (strchr(token, '-')) {
            char* dash = strchr(token, '-');
            *dash = '\0';
            int start = atoi(token);
            int end = atoi(dash + 1);
            if (start < min_val || end > max_val || start > end) return false;
            for (int i = start; i <= end; i++) *mask |= (1ULL << i);
        } else {
            int val = atoi(token);
            if (val < min_val || val > max_val) return false;
            *mask |= (1ULL << val);
        }

        token = strtok_r(NULL, ",", &saveptr);
    }
    return *mask != 0;
}

bool qihse_task_scheduler_parse_cron_next(
    const char* cron_expr,
    time_t from_time,
    time_t* out_next_time
) {
    if (!cron_expr || !out_next_time) return false;

    char expr_copy[QIHSE_CRON_EXPR_MAX];
    snprintf(expr_copy, sizeof(expr_copy), "%s", cron_expr);

    char* fields[5];
    char* saveptr = NULL;
    char* tok = strtok_r(expr_copy, " \t", &saveptr);
    int num_fields = 0;
    while (tok && num_fields < 5) {
        fields[num_fields++] = tok;
        tok = strtok_r(NULL, " \t", &saveptr);
    }
    if (num_fields != 5) return false;

    uint64_t min_mask = 0, hour_mask = 0, mday_mask = 0, mon_mask = 0, wday_mask = 0;

    if (!parse_cron_field(fields[0], 0, 59, &min_mask)) return false;
    if (!parse_cron_field(fields[1], 0, 23, &hour_mask)) return false;
    if (!parse_cron_field(fields[2], 1, 31, &mday_mask)) return false;
    if (!parse_cron_field(fields[3], 1, 12, &mon_mask)) return false;
    if (!parse_cron_field(fields[4], 0, 6, &wday_mask)) {
        /* Support Sunday as 7 */
        uint64_t w7 = 0;
        if (!parse_cron_field(fields[4], 0, 7, &w7)) return false;
        if (w7 & (1ULL << 7)) w7 = (w7 & ~(1ULL << 7)) | 1ULL;
        wday_mask = w7;
    }

    /* Start testing from (from_time + 60s), truncated to whole minute */
    time_t t = (from_time / 60 + 1) * 60;
    time_t max_search = t + (5 * 365 * 86400); /* search up to 5 years */

    while (t < max_search) {
        struct tm tm_val;
        gmtime_r(&t, &tm_val);

        int mon = tm_val.tm_mon + 1;
        if (!((mon_mask >> mon) & 1)) {
            t += 86400; /* skip a day */
            t = (t / 86400) * 86400;
            continue;
        }

        int mday = tm_val.tm_mday;
        int wday = tm_val.tm_wday;
        if (!((mday_mask >> mday) & 1) || !((wday_mask >> wday) & 1)) {
            t += 86400;
            t = (t / 86400) * 86400;
            continue;
        }

        int hour = tm_val.tm_hour;
        if (!((hour_mask >> hour) & 1)) {
            t += 3600; /* skip an hour */
            t = (t / 3600) * 3600;
            continue;
        }

        int min = tm_val.tm_min;
        if ((min_mask >> min) & 1) {
            *out_next_time = t;
            return true;
        }

        t += 60;
    }

    return false;
}

static void* scheduler_thread_func(void* arg) {
    qihse_task_scheduler_t* sched = (qihse_task_scheduler_t*)arg;

    while (sched->running) {
        time_t now_real = time(NULL);
        uint64_t now_mono = get_time_ns();

        pthread_mutex_lock(&sched->lock);
        for (size_t i = 0; i < sched->count; i++) {
            qihse_schedule_entry_t* entry = &sched->entries[i];
            if (!entry->enabled) continue;

            if (entry->next_fire_ns <= (uint64_t)now_real * 1000000000ULL) {
                /* Fire task */
                if (sched->queue) {
                    qihse_task_submit(
                        sched->queue,
                        entry->queue_name,
                        entry->priority,
                        entry->payload,
                        entry->payload_len,
                        NULL,
                        NULL,
                        0
                    );
                }

                entry->last_fired_ns = now_mono;
                entry->fire_count++;

                /* Compute next fire */
                time_t next_t = 0;
                if (qihse_task_scheduler_parse_cron_next(entry->cron_expr, now_real, &next_t)) {
                    entry->next_fire_ns = (uint64_t)next_t * 1000000000ULL;
                } else {
                    entry->enabled = false;
                }

                if (sched->tsdb) {
                    char metric[128];
                    snprintf(metric, sizeof(metric), "schedule.fire.%s", entry->schedule_id);
                    uint32_t series_id = 2166136261u;
                    for (const char* p = metric; *p; p++) {
                        series_id = (series_id ^ (uint8_t)(*p)) * 16777619u;
                    }
                    qihse_tsdb_insert(sched->tsdb, series_id, (uint64_t)now_real * 1000ULL, (double)entry->fire_count, 0, 0);
                }
            }
        }
        pthread_mutex_unlock(&sched->lock);

        usleep(sched->tick_ms * 1000u);
    }

    return NULL;
}

qihse_task_scheduler_t* qihse_task_scheduler_create(const qihse_task_scheduler_config_t* config) {
    qihse_task_scheduler_t* s = (qihse_task_scheduler_t*)calloc(1, sizeof(qihse_task_scheduler_t));
    if (!s) return NULL;

    if (config) {
        s->queue = config->queue;
        s->tsdb = config->tsdb;
        s->tick_ms = config->tick_ms ? config->tick_ms : 10u;
    } else {
        s->tick_ms = 10u;
    }

    pthread_mutex_init(&s->lock, NULL);
    return s;
}

bool qihse_task_scheduler_start(qihse_task_scheduler_t* scheduler) {
    if (!scheduler) return false;
    pthread_mutex_lock(&scheduler->lock);
    if (scheduler->running) {
        pthread_mutex_unlock(&scheduler->lock);
        return true;
    }
    scheduler->running = true;
    pthread_create(&scheduler->thread, NULL, scheduler_thread_func, scheduler);
    pthread_mutex_unlock(&scheduler->lock);
    return true;
}

void qihse_task_scheduler_stop(qihse_task_scheduler_t* scheduler) {
    if (!scheduler) return;
    pthread_mutex_lock(&scheduler->lock);
    if (!scheduler->running) {
        pthread_mutex_unlock(&scheduler->lock);
        return;
    }
    scheduler->running = false;
    pthread_mutex_unlock(&scheduler->lock);
    pthread_join(scheduler->thread, NULL);
}

void qihse_task_scheduler_destroy(qihse_task_scheduler_t* scheduler) {
    if (!scheduler) return;
    qihse_task_scheduler_stop(scheduler);

    pthread_mutex_lock(&scheduler->lock);
    for (size_t i = 0; i < scheduler->count; i++) {
        if (scheduler->entries[i].payload) {
            free(scheduler->entries[i].payload);
        }
    }
    pthread_mutex_unlock(&scheduler->lock);

    pthread_mutex_destroy(&scheduler->lock);
    free(scheduler);
}

bool qihse_task_scheduler_add(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id,
    const char* cron_expr,
    const char* queue_name,
    qihse_task_prio_t priority,
    const uint8_t* payload,
    size_t payload_len
) {
    if (!scheduler || !schedule_id || !cron_expr) return false;

    time_t next_fire = 0;
    if (!qihse_task_scheduler_parse_cron_next(cron_expr, time(NULL), &next_fire)) {
        return false;
    }

    pthread_mutex_lock(&scheduler->lock);

    /* Check if already exists (update) */
    for (size_t i = 0; i < scheduler->count; i++) {
        if (strcmp(scheduler->entries[i].schedule_id, schedule_id) == 0) {
            snprintf(scheduler->entries[i].cron_expr, sizeof(scheduler->entries[i].cron_expr), "%s", cron_expr);
            snprintf(scheduler->entries[i].queue_name, sizeof(scheduler->entries[i].queue_name), "%s", queue_name ? queue_name : "default");
            scheduler->entries[i].priority = priority;

            if (scheduler->entries[i].payload) free(scheduler->entries[i].payload);
            if (payload && payload_len > 0) {
                scheduler->entries[i].payload = (uint8_t*)malloc(payload_len);
                if (scheduler->entries[i].payload) {
                    memcpy(scheduler->entries[i].payload, payload, payload_len);
                    scheduler->entries[i].payload_len = payload_len;
                }
            } else {
                scheduler->entries[i].payload = NULL;
                scheduler->entries[i].payload_len = 0;
            }

            scheduler->entries[i].enabled = true;
            scheduler->entries[i].next_fire_ns = (uint64_t)next_fire * 1000000000ULL;
            pthread_mutex_unlock(&scheduler->lock);
            return true;
        }
    }

    if (scheduler->count >= QIHSE_MAX_SCHEDULES) {
        pthread_mutex_unlock(&scheduler->lock);
        return false;
    }

    qihse_schedule_entry_t* entry = &scheduler->entries[scheduler->count++];
    snprintf(entry->schedule_id, sizeof(entry->schedule_id), "%s", schedule_id);
    snprintf(entry->cron_expr, sizeof(entry->cron_expr), "%s", cron_expr);
    snprintf(entry->queue_name, sizeof(entry->queue_name), "%s", queue_name ? queue_name : "default");
    entry->priority = priority;

    if (payload && payload_len > 0) {
        entry->payload = (uint8_t*)malloc(payload_len);
        if (entry->payload) {
            memcpy(entry->payload, payload, payload_len);
            entry->payload_len = payload_len;
        }
    } else {
        entry->payload = NULL;
        entry->payload_len = 0;
    }

    entry->enabled = true;
    entry->next_fire_ns = (uint64_t)next_fire * 1000000000ULL;
    entry->fire_count = 0;
    entry->last_fired_ns = 0;

    pthread_mutex_unlock(&scheduler->lock);
    return true;
}

bool qihse_task_scheduler_remove(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id
) {
    if (!scheduler || !schedule_id) return false;
    pthread_mutex_lock(&scheduler->lock);
    for (size_t i = 0; i < scheduler->count; i++) {
        if (strcmp(scheduler->entries[i].schedule_id, schedule_id) == 0) {
            if (scheduler->entries[i].payload) free(scheduler->entries[i].payload);
            for (size_t j = i; j + 1 < scheduler->count; j++) {
                scheduler->entries[j] = scheduler->entries[j + 1];
            }
            scheduler->count--;
            pthread_mutex_unlock(&scheduler->lock);
            return true;
        }
    }
    pthread_mutex_unlock(&scheduler->lock);
    return false;
}

bool qihse_task_scheduler_enable(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id,
    bool enable
) {
    if (!scheduler || !schedule_id) return false;
    pthread_mutex_lock(&scheduler->lock);
    for (size_t i = 0; i < scheduler->count; i++) {
        if (strcmp(scheduler->entries[i].schedule_id, schedule_id) == 0) {
            scheduler->entries[i].enabled = enable;
            if (enable) {
                time_t next_t = 0;
                if (qihse_task_scheduler_parse_cron_next(scheduler->entries[i].cron_expr, time(NULL), &next_t)) {
                    scheduler->entries[i].next_fire_ns = (uint64_t)next_t * 1000000000ULL;
                }
            }
            pthread_mutex_unlock(&scheduler->lock);
            return true;
        }
    }
    pthread_mutex_unlock(&scheduler->lock);
    return false;
}

bool qihse_task_scheduler_list(
    qihse_task_scheduler_t* scheduler,
    char*** out_schedule_ids,
    size_t* out_count
) {
    if (!scheduler || !out_schedule_ids || !out_count) return false;
    pthread_mutex_lock(&scheduler->lock);
    if (scheduler->count == 0) {
        *out_schedule_ids = NULL;
        *out_count = 0;
        pthread_mutex_unlock(&scheduler->lock);
        return true;
    }

    char** ids = (char**)malloc(scheduler->count * sizeof(char*));
    if (!ids) {
        pthread_mutex_unlock(&scheduler->lock);
        return false;
    }

    for (size_t i = 0; i < scheduler->count; i++) {
        ids[i] = strdup(scheduler->entries[i].schedule_id);
    }
    *out_count = scheduler->count;
    pthread_mutex_unlock(&scheduler->lock);

    *out_schedule_ids = ids;
    return true;
}

void qihse_task_scheduler_free_list(char** schedule_ids, size_t count) {
    if (!schedule_ids) return;
    for (size_t i = 0; i < count; i++) {
        if (schedule_ids[i]) free(schedule_ids[i]);
    }
    free(schedule_ids);
}

bool qihse_task_scheduler_next_fire(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id,
    char* out_iso8601,
    size_t buf_len
) {
    if (!scheduler || !schedule_id || !out_iso8601 || buf_len == 0) return false;
    pthread_mutex_lock(&scheduler->lock);
    for (size_t i = 0; i < scheduler->count; i++) {
        if (strcmp(scheduler->entries[i].schedule_id, schedule_id) == 0) {
            time_t t = (time_t)(scheduler->entries[i].next_fire_ns / 1000000000ULL);
            struct tm tm_val;
            gmtime_r(&t, &tm_val);
            strftime(out_iso8601, buf_len, "%Y-%m-%dT%H:%M:%SZ", &tm_val);
            pthread_mutex_unlock(&scheduler->lock);
            return true;
        }
    }
    pthread_mutex_unlock(&scheduler->lock);
    return false;
}
