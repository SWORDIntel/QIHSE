#ifndef QIHSE_MONGO_WIRE_H
#define QIHSE_MONGO_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MongoDB wire protocol message types */
typedef enum {
    MONGO_OP_REPLY = 1,
    MONGO_OP_MSG_LEGACY = 1000,
    MONGO_OP_UPDATE = 2001,
    MONGO_OP_INSERT = 2002,
    MONGO_OP_QUERY = 2004,
    MONGO_OP_GET_MORE = 2005,
    MONGO_OP_DELETE = 2006,
    MONGO_OP_KILL_CURSORS = 2007,
    MONGO_OP_COMPRESSED = 2012,
    MONGO_OP_MSG = 2013
} mongo_op_t;

/* BSON element types */
typedef enum {
    BSON_DOUBLE = 0x01,
    BSON_STRING = 0x02,
    BSON_DOCUMENT = 0x03,
    BSON_ARRAY = 0x04,
    BSON_BINARY = 0x05,
    BSON_OBJECTID = 0x07,
    BSON_BOOL = 0x08,
    BSON_DATETIME = 0x09,
    BSON_NULL = 0x0A,
    BSON_REGEX = 0x0B,
    BSON_INT32 = 0x10,
    BSON_TIMESTAMP = 0x11,
    BSON_INT64 = 0x12,
    BSON_DECIMAL128 = 0x13,
    BSON_MINKEY = 0xFF,
    BSON_MAXKEY = 0x7F
} bson_type_t;

typedef struct {
    uint8_t* data;
    size_t len;
    size_t cap;
} bson_t;

typedef struct {
    int fd;
    uint16_t port;
    pthread_t thread;
    volatile int running;
    void* doc_store;  /* qihse_document_store_t* */
} qihse_mongo_server_t;

/* BSON operations */
bson_t* bson_create(void);
void bson_destroy(bson_t* b);
int bson_append_int32(bson_t* b, const char* key, int32_t val);
int bson_append_int64(bson_t* b, const char* key, int64_t val);
int bson_append_double(bson_t* b, const char* key, double val);
int bson_append_string(bson_t* b, const char* key, const char* val);
int bson_append_bool(bson_t* b, const char* key, int val);
int bson_append_null(bson_t* b, const char* key);
int bson_append_document(bson_t* b, const char* key, const bson_t* sub);
int bson_append_binary(bson_t* b, const char* key, const uint8_t* data, size_t len);
int bson_append_datetime(bson_t* b, const char* key, int64_t ms);
size_t bson_size(const bson_t* b);
const uint8_t* bson_data(const bson_t* b);

/* BSON parsing */
typedef struct {
    bson_type_t type;
    const char* key;
    union {
        int32_t i32;
        int64_t i64;
        double d;
        const char* str;
        int b;
        struct { const uint8_t* data; size_t len; } bin;
    } v;
} bson_element_t;

int bson_iter(const bson_t* b, size_t* offset, bson_element_t* out_elem);

/* MongoDB wire protocol server */
qihse_mongo_server_t* qihse_mongo_server_create(uint16_t port, void* doc_store);
int qihse_mongo_server_start(qihse_mongo_server_t* srv);
int qihse_mongo_server_stop(qihse_mongo_server_t* srv);
void qihse_mongo_server_destroy(qihse_mongo_server_t* srv);

/* Message parsing */
typedef struct {
    int32_t message_length;
    int32_t request_id;
    int32_t response_to;
    int32_t opcode;
    const uint8_t* body;
    size_t body_len;
} mongo_msg_t;

int mongo_msg_parse(const uint8_t* data, size_t len, mongo_msg_t* out);
bson_t* mongo_msg_get_document(const mongo_msg_t* msg, size_t* offset);

#ifdef __cplusplus
}
#endif
#endif
