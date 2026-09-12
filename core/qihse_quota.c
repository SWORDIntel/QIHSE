#include "qihse_quota.h"
#include "qihse_auth.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef struct {
    uint32_t count;
    time_t   window_start;
} qihse_quota_counter_t;

typedef struct qihse_quota_tenant {
    uint32_t tenant_id;
    bool used;
    qihse_quota_counter_t counters[QIHSE_QUOTA_CLASS_COUNT];
    struct {
        uint32_t max_ops;
        uint32_t window_seconds;
    } policy[QIHSE_QUOTA_CLASS_COUNT];
    struct qihse_quota_tenant* next;
} qihse_quota_tenant_t;

struct qihse_quota_table {
    size_t max_tenants;
    size_t tenant_count;
    qihse_quota_tenant_t* tenants;   /* chained overflow list */
    pthread_mutex_t mutex;
};

static qihse_quota_tenant_t* quota_find_locked(qihse_quota_table_t* table, uint32_t tenant_id) {
    for (qihse_quota_tenant_t* t = table->tenants; t; t = t->next) {
        if (t->used && t->tenant_id == tenant_id) return t;
    }
    return NULL;
}

static qihse_quota_tenant_t* quota_get_or_create_locked(qihse_quota_table_t* table, uint32_t tenant_id) {
    qihse_quota_tenant_t* existing = quota_find_locked(table, tenant_id);
    if (existing) return existing;
    if (table->tenant_count >= table->max_tenants) return NULL;
    qihse_quota_tenant_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->tenant_id = tenant_id;
    t->used = true;
    t->next = table->tenants;
    table->tenants = t;
    table->tenant_count++;
    return t;
}

qihse_quota_table_t* qihse_quota_table_create(size_t max_tenants) {
    if (max_tenants == 0) return NULL;
    qihse_quota_table_t* table = calloc(1, sizeof(*table));
    if (!table) return NULL;
    table->max_tenants = max_tenants;
    if (pthread_mutex_init(&table->mutex, NULL) != 0) {
        free(table);
        return NULL;
    }
    return table;
}

void qihse_quota_table_destroy(qihse_quota_table_t* table) {
    if (!table) return;
    pthread_mutex_lock(&table->mutex);
    qihse_quota_tenant_t* t = table->tenants;
    while (t) {
        qihse_quota_tenant_t* next = t->next;
        free(t);
        t = next;
    }
    table->tenants = NULL;
    pthread_mutex_unlock(&table->mutex);
    pthread_mutex_destroy(&table->mutex);
    free(table);
}

bool qihse_quota_configure(qihse_quota_table_t* table, uint32_t tenant_id,
                           qihse_quota_class_t quota_class,
                           uint32_t max_ops, uint32_t window_seconds) {
    if (!table || quota_class >= QIHSE_QUOTA_CLASS_COUNT) return false;
    pthread_mutex_lock(&table->mutex);
    qihse_quota_tenant_t* tenant;
    if (max_ops == 0) {
        /* Disabling the class: only touch existing entries. */
        tenant = quota_find_locked(table, tenant_id);
        if (tenant) {
            tenant->policy[quota_class].max_ops = 0;
            tenant->policy[quota_class].window_seconds = 0;
            tenant->counters[quota_class].count = 0;
            tenant->counters[quota_class].window_start = 0;
        }
        pthread_mutex_unlock(&table->mutex);
        return true;
    }
    if (window_seconds == 0) {
        pthread_mutex_unlock(&table->mutex);
        return false;
    }
    tenant = quota_get_or_create_locked(table, tenant_id);
    if (!tenant) {
        pthread_mutex_unlock(&table->mutex);
        return false;
    }
    tenant->policy[quota_class].max_ops = max_ops;
    tenant->policy[quota_class].window_seconds = window_seconds;
    pthread_mutex_unlock(&table->mutex);
    return true;
}

bool qihse_quota_allow(qihse_quota_table_t* table, uint32_t tenant_id,
                       qihse_quota_class_t quota_class) {
    if (!table || quota_class >= QIHSE_QUOTA_CLASS_COUNT) return false;
    /* System domain (tenant 0) is never quota-enforced. */
    if (tenant_id == QIHSE_TENANT_SYSTEM) return true;

    pthread_mutex_lock(&table->mutex);
    qihse_quota_tenant_t* tenant = quota_find_locked(table, tenant_id);
    if (!tenant || tenant->policy[quota_class].max_ops == 0) {
        /* No policy configured for this tenant/class: unlimited. */
        pthread_mutex_unlock(&table->mutex);
        return true;
    }

    time_t now = time(NULL);
    qihse_quota_counter_t* counter = &tenant->counters[quota_class];
    uint32_t window = tenant->policy[quota_class].window_seconds;
    if (counter->window_start == 0 || now - counter->window_start >= (time_t)window) {
        counter->count = 0;
        counter->window_start = now;
    }
    if (counter->count >= tenant->policy[quota_class].max_ops) {
        pthread_mutex_unlock(&table->mutex);
        return false;
    }
    counter->count++;
    pthread_mutex_unlock(&table->mutex);
    return true;
}

void qihse_quota_reset(qihse_quota_table_t* table) {
    if (!table) return;
    pthread_mutex_lock(&table->mutex);
    for (qihse_quota_tenant_t* t = table->tenants; t; t = t->next) {
        memset(t->counters, 0, sizeof(t->counters));
    }
    pthread_mutex_unlock(&table->mutex);
}

void qihse_quota_cleanup(qihse_quota_table_t* table) {
    if (!table) return;
    pthread_mutex_lock(&table->mutex);
    time_t now = time(NULL);
    /* Expire idle windows and drop entries with no configured policy so
     * capacity recycles; configured policies are re-registered by the
     * operator and intentionally survive cleanup. */
    qihse_quota_tenant_t** link = &table->tenants;
    while (*link) {
        qihse_quota_tenant_t* t = *link;
        bool has_policy = false;
        for (size_t c = 0; c < QIHSE_QUOTA_CLASS_COUNT; c++) {
            if (t->policy[c].max_ops != 0) has_policy = true;
            if (t->counters[c].window_start != 0 &&
                now - t->counters[c].window_start >= (time_t)t->policy[c].window_seconds) {
                t->counters[c].count = 0;
                t->counters[c].window_start = 0;
            }
        }
        if (!has_policy) {
            *link = t->next;
            table->tenant_count--;
            free(t);
        } else {
            link = &t->next;
        }
    }
    pthread_mutex_unlock(&table->mutex);
}
