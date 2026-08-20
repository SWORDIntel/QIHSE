#ifndef QIHSE_TRACING_H
#define QIHSE_TRACING_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* trace_id;      /* 16-byte hex string (32 chars) */
    char* span_id;       /* 8-byte hex string (16 chars) */
    char* parent_span_id;
    char* operation_name;
    uint64_t start_time_ns;
    uint64_t end_time_ns;
    char** tags_keys;
    char** tags_values;
    size_t num_tags;
    int status;          /* 0=OK, 1=ERROR */
} qihse_span_t;

typedef struct {
    qihse_span_t** spans;
    size_t num_spans;
    size_t cap;
    pthread_mutex_t lock;
    int enabled;
} qihse_tracer_t;

qihse_tracer_t* qihse_tracer_create(void);
void qihse_tracer_destroy(qihse_tracer_t* tracer);
void qihse_tracer_set_enabled(qihse_tracer_t* tracer, int enabled);

qihse_span_t* qihse_span_start(qihse_tracer_t* tracer, const char* operation_name, const char* parent_span_id);
int qihse_span_finish(qihse_tracer_t* tracer, qihse_span_t* span);
int qihse_span_set_tag(qihse_span_t* span, const char* key, const char* value);
int qihse_span_set_status(qihse_span_t* span, int status);
uint64_t qihse_span_duration_ns(const qihse_span_t* span);

char* qihse_tracer_export_json(qihse_tracer_t* tracer);
size_t qihse_tracer_span_count(qihse_tracer_t* tracer);

void qihse_span_destroy(qihse_span_t* span);

#ifdef __cplusplus
}
#endif
#endif
