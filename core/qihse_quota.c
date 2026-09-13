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
} qihse_quota_tenant_t;

/* Open-addressed tenant map: slot array at >=2x max_tenants keeps load
 * factor <= 0.5 so tenant lookup is a couple of probes instead of a linked
 * list walk.  Deletion (quota_cleanup) uses backshift so no tombstones. */
struct qihse_quota_table {
    size_t max_tenants;
    size_t tenant_count;
    size_t map_cap;
    qihse_quota_tenant_t** slots;
    pthread_mutex_t mutex;
};

static size_t quota_hash(uint32_t tenant_id) {
    return (size_t)(tenant_id * 2654435761u);
}

static qihse_quota_tenant_t* quota_find_locked(qihse_quota_table_t* table, uint32_t tenant_id) {
    size_t h = quota_hash(tenant_id) & (table->map_cap - 1u);
    for (size_t i = 0; i < table->map_cap; i++) {
        qihse_quota_tenant_t* t = table->slots[(h + i) & (table->map_cap - 1u)];
        if (!t) return NULL;
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
    size_t h = quota_hash(tenant_id) & (table->map_cap - 1u);
    for (size_t i = 0; i < table->map_cap; i++) {
        size_t pos = (h + i) & (table->map_cap - 1u);
        if (!table->slots[pos]) { table->slots[pos] = t; table->tenant_count++; return t; }
    }
    free(t);
    return NULL;
}

/* Remove the slot at index `pos` and backshift the probe cluster: an element
 * at `cur` slides into the cleared slot iff its probe path reached `pos`
 * before `cur` (i.e. `pos` lies on the home..cur span). */
static void quota_slot_delete_locked(qihse_quota_table_t* table, size_t pos) {
    table->slots[pos] = NULL;
    size_t cur = pos;
    for (size_t n = 0; n < table->map_cap; n++) {
        cur = (cur + 1) & (table->map_cap - 1u);
        qihse_quota_tenant_t* t = table->slots[cur];
        if (!t) return;
        size_t home = quota_hash(t->tenant_id) & (table->map_cap - 1u);
        size_t dist_to_pos = (pos - home + table->map_cap) & (table->map_cap - 1u);
        size_t dist_to_cur = (cur - home + table->map_cap) & (table->map_cap - 1u);
        if (dist_to_pos < dist_to_cur) {
            table->slots[pos] = t;
            table->slots[cur] = NULL;
            pos = cur;
        }
    }
}

qihse_quota_table_t* qihse_quota_table_create(size_t max_tenants) {
    if (max_tenants == 0) return NULL;
    qihse_quota_table_t* table = calloc(1, sizeof(*table));
    if (!table) return NULL;
    table->max_tenants = max_tenants;
    table->map_cap = 8u;
    while (table->map_cap < max_tenants * 2u) table->map_cap *= 2u;
    table->slots = calloc(table->map_cap, sizeof(*table->slots));
    if (!table->slots) { free(table); return NULL; }
    if (pthread_mutex_init(&table->mutex, NULL) != 0) {
        free(table->slots);
        free(table);
        return NULL;
    }
    return table;
}

void qihse_quota_table_destroy(qihse_quota_table_t* table) {
    if (!table) return;
    pthread_mutex_lock(&table->mutex);
    for (size_t i = 0; i < table->map_cap; i++) {
        if (table->slots[i]) { free(table->slots[i]); table->slots[i] = NULL; }
    }
    pthread_mutex_unlock(&table->mutex);
    pthread_mutex_destroy(&table->mutex);
    free(table->slots);
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
    for (size_t i = 0; i < table->map_cap; i++) {
        qihse_quota_tenant_t* t = table->slots[i];
        if (t) memset(t->counters, 0, sizeof(t->counters));
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
    for (size_t i = 0; i < table->map_cap; i++) {
        qihse_quota_tenant_t* t = table->slots[i];
        if (!t) continue;
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
            quota_slot_delete_locked(table, i);
            table->tenant_count--;
            free(t);
        }
    }
    pthread_mutex_unlock(&table->mutex);
}
