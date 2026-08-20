#include "qihse_tracing.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static char* random_hex(size_t bytes) {
    char* hex = (char*)malloc(bytes * 2 + 1);
    for (size_t i = 0; i < bytes; i++) {
        uint8_t b = (uint8_t)(rand() & 0xFF);
        snprintf(hex + i * 2, 3, "%02x", b);
    }
    return hex;
}

qihse_tracer_t* qihse_tracer_create(void) {
    qihse_tracer_t* t = (qihse_tracer_t*)calloc(1, sizeof(qihse_tracer_t));
    if (!t) return NULL;
    pthread_mutex_init(&t->lock, NULL);
    t->enabled = 1;
    srand((unsigned)time(NULL));
    return t;
}

void qihse_tracer_destroy(qihse_tracer_t* tracer) {
    if (!tracer) return;
    pthread_mutex_lock(&tracer->lock);
    for (size_t i = 0; i < tracer->num_spans; i++) qihse_span_destroy(tracer->spans[i]);
    free(tracer->spans);
    pthread_mutex_unlock(&tracer->lock);
    pthread_mutex_destroy(&tracer->lock);
    free(tracer);
}

void qihse_tracer_set_enabled(qihse_tracer_t* tracer, int enabled) {
    if (!tracer) return;
    pthread_mutex_lock(&tracer->lock);
    tracer->enabled = enabled;
    pthread_mutex_unlock(&tracer->lock);
}

qihse_span_t* qihse_span_start(qihse_tracer_t* tracer, const char* operation_name, const char* parent_span_id) {
    if (!tracer || !operation_name) return NULL;
    qihse_span_t* span = (qihse_span_t*)calloc(1, sizeof(qihse_span_t));
    span->operation_name = strdup(operation_name);
    span->trace_id = random_hex(16);
    span->span_id = random_hex(8);
    span->parent_span_id = parent_span_id ? strdup(parent_span_id) : NULL;
    span->start_time_ns = now_ns();
    span->end_time_ns = 0;
    span->status = 0;
    
    if (tracer->enabled) {
        pthread_mutex_lock(&tracer->lock);
        if (tracer->num_spans >= tracer->cap) {
            tracer->cap = tracer->cap ? tracer->cap * 2 : 64;
            tracer->spans = (qihse_span_t**)realloc(tracer->spans, tracer->cap * sizeof(qihse_span_t*));
        }
        tracer->spans[tracer->num_spans++] = span;
        pthread_mutex_unlock(&tracer->lock);
    }
    return span;
}

int qihse_span_finish(qihse_tracer_t* tracer, qihse_span_t* span) {
    if (!span) return -1;
    span->end_time_ns = now_ns();
    (void)tracer;
    return 0;
}

int qihse_span_set_tag(qihse_span_t* span, const char* key, const char* value) {
    if (!span || !key || !value) return -1;
    span->tags_keys = (char**)realloc(span->tags_keys, (span->num_tags + 1) * sizeof(char*));
    span->tags_values = (char**)realloc(span->tags_values, (span->num_tags + 1) * sizeof(char*));
    span->tags_keys[span->num_tags] = strdup(key);
    span->tags_values[span->num_tags] = strdup(value);
    span->num_tags++;
    return 0;
}

int qihse_span_set_status(qihse_span_t* span, int status) {
    if (!span) return -1;
    span->status = status;
    return 0;
}

uint64_t qihse_span_duration_ns(const qihse_span_t* span) {
    if (!span || span->end_time_ns == 0) return 0;
    return span->end_time_ns - span->start_time_ns;
}

void qihse_span_destroy(qihse_span_t* span) {
    if (!span) return;
    free(span->trace_id);
    free(span->span_id);
    free(span->parent_span_id);
    free(span->operation_name);
    for (size_t i = 0; i < span->num_tags; i++) {
        free(span->tags_keys[i]);
        free(span->tags_values[i]);
    }
    free(span->tags_keys);
    free(span->tags_values);
    free(span);
}

char* qihse_tracer_export_json(qihse_tracer_t* tracer) {
    if (!tracer) return NULL;
    pthread_mutex_lock(&tracer->lock);
    size_t cap = 8192;
    char* json = (char*)malloc(cap);
    size_t len = 0;
    len += snprintf(json + len, cap - len, "{\"spans\":[");
    
    for (size_t i = 0; i < tracer->num_spans; i++) {
        qihse_span_t* s = tracer->spans[i];
        if (i > 0) { json[len++] = ','; if (len >= cap) { cap *= 2; json = realloc(json, cap); } }
        uint64_t dur = qihse_span_duration_ns(s);
        len += snprintf(json + len, cap - len,
            "{\"trace_id\":\"%s\",\"span_id\":\"%s\",\"parent\":\"%s\",\"operation\":\"%s\",\"start\":%llu,\"duration_ns\":%llu,\"status\":%d,\"tags\":{",
            s->trace_id, s->span_id, s->parent_span_id ? s->parent_span_id : "",
            s->operation_name, (unsigned long long)s->start_time_ns,
            (unsigned long long)dur, s->status);
        for (size_t j = 0; j < s->num_tags; j++) {
            if (j > 0) { json[len++] = ','; if (len >= cap) { cap *= 2; json = realloc(json, cap); } }
            len += snprintf(json + len, cap - len, "\"%s\":\"%s\"", s->tags_keys[j], s->tags_values[j]);
        }
        len += snprintf(json + len, cap - len, "}}");
        if (len >= cap - 256) { cap *= 2; json = realloc(json, cap); }
    }
    len += snprintf(json + len, cap - len, "]}");
    pthread_mutex_unlock(&tracer->lock);
    return json;
}

size_t qihse_tracer_span_count(qihse_tracer_t* tracer) {
    if (!tracer) return 0;
    pthread_mutex_lock(&tracer->lock);
    size_t n = tracer->num_spans;
    pthread_mutex_unlock(&tracer->lock);
    return n;
}
