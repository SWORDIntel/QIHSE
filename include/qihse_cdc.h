#ifndef QIHSE_CDC_H
#define QIHSE_CDC_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CDC_OP_INSERT = 0,
    CDC_OP_UPDATE = 1,
    CDC_OP_DELETE = 2
} cdc_op_t;

typedef struct {
    cdc_op_t op;
    char* table;
    char* key;
    uint8_t* old_value;
    size_t old_value_len;
    uint8_t* new_value;
    size_t new_value_len;
    uint64_t lsn;
    uint64_t timestamp;
} qihse_cdc_event_t;

typedef void (*qihse_cdc_callback_t)(const qihse_cdc_event_t* event, void* user_data);

typedef struct {
    char* name;
    qihse_cdc_callback_t callback;
    void* user_data;
    int active;
    uint64_t last_lsn;
} qihse_cdc_subscription_t;

typedef struct {
    qihse_cdc_subscription_t* subs;
    size_t num_subs;
    size_t subs_cap;
    pthread_mutex_t lock;
    uint64_t next_lsn;
} qihse_cdc_context_t;

qihse_cdc_context_t* qihse_cdc_create(void);
void qihse_cdc_destroy(qihse_cdc_context_t* ctx);

int qihse_cdc_subscribe(qihse_cdc_context_t* ctx, const char* name,
                        qihse_cdc_callback_t callback, void* user_data);
int qihse_cdc_unsubscribe(qihse_cdc_context_t* ctx, const char* name);

int qihse_cdc_emit(qihse_cdc_context_t* ctx, cdc_op_t op, const char* table,
                   const char* key,
                   const uint8_t* old_value, size_t old_value_len,
                   const uint8_t* new_value, size_t new_value_len);

size_t qihse_cdc_subscription_count(qihse_cdc_context_t* ctx);
uint64_t qihse_cdc_get_lsn(qihse_cdc_context_t* ctx);

void qihse_cdc_event_free(qihse_cdc_event_t* event);

#ifdef __cplusplus
}
#endif
#endif
