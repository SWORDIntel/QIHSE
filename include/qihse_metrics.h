#ifndef QIHSE_METRICS_H
#define QIHSE_METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    METRIC_COUNTER = 0,
    METRIC_GAUGE = 1,
    METRIC_HISTOGRAM = 2,
    METRIC_SUMMARY = 3
} metric_type_t;

typedef struct {
    char* name;
    char* help;
    metric_type_t type;
    double value;
    uint64_t count;
    double sum;
    pthread_mutex_t lock;
} qihse_metric_t;

typedef struct {
    qihse_metric_t* metrics;
    size_t num_metrics;
    size_t cap;
    pthread_mutex_t lock;
} qihse_metrics_registry_t;

qihse_metrics_registry_t* qihse_metrics_create(void);
void qihse_metrics_destroy(qihse_metrics_registry_t* reg);

int qihse_metrics_register(qihse_metrics_registry_t* reg, const char* name,
                           const char* help, metric_type_t type);
int qihse_metrics_increment(qihse_metrics_registry_t* reg, const char* name, double val);
int qihse_metrics_set(qihse_metrics_registry_t* reg, const char* name, double val);
int qihse_metrics_observe(qihse_metrics_registry_t* reg, const char* name, double val);

char* qihse_metrics_export(qihse_metrics_registry_t* reg);
size_t qihse_metrics_count(qihse_metrics_registry_t* reg);

#ifdef __cplusplus
}
#endif
#endif
