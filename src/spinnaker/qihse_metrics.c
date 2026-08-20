#include "qihse_metrics.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

qihse_metrics_registry_t* qihse_metrics_create(void) {
    qihse_metrics_registry_t* reg = (qihse_metrics_registry_t*)calloc(1, sizeof(qihse_metrics_registry_t));
    if (!reg) return NULL;
    pthread_mutex_init(&reg->lock, NULL);
    return reg;
}

void qihse_metrics_destroy(qihse_metrics_registry_t* reg) {
    if (!reg) return;
    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->num_metrics; i++) {
        free(reg->metrics[i].name);
        free(reg->metrics[i].help);
        pthread_mutex_destroy(&reg->metrics[i].lock);
    }
    free(reg->metrics);
    pthread_mutex_unlock(&reg->lock);
    pthread_mutex_destroy(&reg->lock);
    free(reg);
}

static qihse_metric_t* find_metric(qihse_metrics_registry_t* reg, const char* name) {
    for (size_t i = 0; i < reg->num_metrics; i++) {
        if (strcmp(reg->metrics[i].name, name) == 0) return &reg->metrics[i];
    }
    return NULL;
}

int qihse_metrics_register(qihse_metrics_registry_t* reg, const char* name,
                           const char* help, metric_type_t type) {
    if (!reg || !name) return -1;
    pthread_mutex_lock(&reg->lock);
    if (find_metric(reg, name)) { pthread_mutex_unlock(&reg->lock); return -1; }
    if (reg->num_metrics >= reg->cap) {
        reg->cap = reg->cap ? reg->cap * 2 : 16;
        reg->metrics = (qihse_metric_t*)realloc(reg->metrics, reg->cap * sizeof(qihse_metric_t));
    }
    qihse_metric_t* m = &reg->metrics[reg->num_metrics++];
    m->name = strdup(name);
    m->help = strdup(help ? help : "");
    m->type = type;
    m->value = 0;
    m->count = 0;
    m->sum = 0;
    pthread_mutex_init(&m->lock, NULL);
    pthread_mutex_unlock(&reg->lock);
    return 0;
}

int qihse_metrics_increment(qihse_metrics_registry_t* reg, const char* name, double val) {
    if (!reg || !name) return -1;
    pthread_mutex_lock(&reg->lock);
    qihse_metric_t* m = find_metric(reg, name);
    pthread_mutex_unlock(&reg->lock);
    if (!m) return -1;
    pthread_mutex_lock(&m->lock);
    m->value += val;
    m->count++;
    pthread_mutex_unlock(&m->lock);
    return 0;
}

int qihse_metrics_set(qihse_metrics_registry_t* reg, const char* name, double val) {
    if (!reg || !name) return -1;
    pthread_mutex_lock(&reg->lock);
    qihse_metric_t* m = find_metric(reg, name);
    pthread_mutex_unlock(&reg->lock);
    if (!m) return -1;
    pthread_mutex_lock(&m->lock);
    m->value = val;
    pthread_mutex_unlock(&m->lock);
    return 0;
}

int qihse_metrics_observe(qihse_metrics_registry_t* reg, const char* name, double val) {
    if (!reg || !name) return -1;
    pthread_mutex_lock(&reg->lock);
    qihse_metric_t* m = find_metric(reg, name);
    pthread_mutex_unlock(&reg->lock);
    if (!m) return -1;
    pthread_mutex_lock(&m->lock);
    m->sum += val;
    m->count++;
    pthread_mutex_unlock(&m->lock);
    return 0;
}

char* qihse_metrics_export(qihse_metrics_registry_t* reg) {
    if (!reg) return NULL;
    pthread_mutex_lock(&reg->lock);
    size_t cap = 4096;
    char* output = (char*)malloc(cap);
    size_t len = 0;
    
    for (size_t i = 0; i < reg->num_metrics; i++) {
        qihse_metric_t* m = &reg->metrics[i];
        const char* type_str = "counter";
        switch (m->type) {
            case METRIC_COUNTER: type_str = "counter"; break;
            case METRIC_GAUGE: type_str = "gauge"; break;
            case METRIC_HISTOGRAM: type_str = "histogram"; break;
            case METRIC_SUMMARY: type_str = "summary"; break;
        }
        
        pthread_mutex_lock(&m->lock);
        char line[512];
        
        /* HELP line */
        int n = snprintf(line, sizeof(line), "# HELP %s %s\n", m->name, m->help);
        if (len + n + 1 > cap) { cap = (len + n + 1) * 2; output = realloc(output, cap); }
        memcpy(output + len, line, n); len += n;
        
        /* TYPE line */
        n = snprintf(line, sizeof(line), "# TYPE %s %s\n", m->name, type_str);
        if (len + n + 1 > cap) { cap = (len + n + 1) * 2; output = realloc(output, cap); }
        memcpy(output + len, line, n); len += n;
        
        /* Value line */
        if (m->type == METRIC_HISTOGRAM || m->type == METRIC_SUMMARY) {
            n = snprintf(line, sizeof(line), "%s_count %llu\n%s_sum %g\n",
                         m->name, (unsigned long long)m->count, m->name, m->sum);
        } else {
            n = snprintf(line, sizeof(line), "%s %g\n", m->name, m->value);
        }
        if (len + n + 1 > cap) { cap = (len + n + 1) * 2; output = realloc(output, cap); }
        memcpy(output + len, line, n); len += n;
        
        pthread_mutex_unlock(&m->lock);
    }
    
    output[len] = '\0';
    pthread_mutex_unlock(&reg->lock);
    return output;
}

size_t qihse_metrics_count(qihse_metrics_registry_t* reg) {
    if (!reg) return 0;
    pthread_mutex_lock(&reg->lock);
    size_t n = reg->num_metrics;
    pthread_mutex_unlock(&reg->lock);
    return n;
}
