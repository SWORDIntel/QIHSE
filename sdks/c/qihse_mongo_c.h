#ifndef QIHSE_MONGO_C_H
#define QIHSE_MONGO_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BSON value types */
typedef enum {
    BSON_INT32 = 0x10,
    BSON_INT64 = 0x12,
    BSON_DOUBLE = 0x01,
    BSON_STRING = 0x02,
    BSON_BOOL = 0x08,
    BSON_NULL = 0x0A,
    BSON_DOCUMENT = 0x03,
    BSON_ARRAY = 0x04,
    BSON_BINARY = 0x05,
    BSON_OBJECTID = 0x07,
    BSON_DATETIME = 0x09,
} bson_type_t;

/* BSON value */
typedef struct {
    bson_type_t type;
    union {
        int32_t i32;
        int64_t i64;
        double d;
        int b;
    } v;
    char *str;
    uint8_t *bytes;
    size_t bytes_len;
} bson_value_t;

/* BSON document (key-value pairs) */
typedef struct {
    char **keys;
    bson_value_t *values;
    size_t count;
    size_t capacity;
} bson_doc_t;

/* MongoDB wire protocol client */
typedef struct {
    char *host;
    uint16_t port;
    int sock;
} mongo_client_t;

/* Collection handle */
typedef struct {
    mongo_client_t *client;
    char *db_name;
    char *coll_name;
} mongo_collection_t;

/* Result types */
typedef struct { bson_value_t inserted_id; } mongo_insert_one_result_t;
typedef struct { bson_value_t *inserted_ids; size_t count; } mongo_insert_many_result_t;
typedef struct { uint64_t matched_count; uint64_t modified_count; } mongo_update_result_t;
typedef struct { uint64_t deleted_count; } mongo_delete_result_t;

/* Cursor */
typedef struct {
    bson_doc_t *docs;
    size_t count;
    size_t position;
} mongo_cursor_t;

/* API */
mongo_client_t *mongo_client_connect(const char *host, uint16_t port);
void mongo_client_disconnect(mongo_client_t *client);
int mongo_client_ping(mongo_client_t *client);

mongo_collection_t *mongo_client_collection(mongo_client_t *client, const char *db, const char *coll);
void mongo_collection_destroy(mongo_collection_t *coll);

mongo_insert_one_result_t mongo_insert_one(mongo_collection_t *coll, const bson_doc_t *doc);
mongo_insert_many_result_t mongo_insert_many(mongo_collection_t *coll, const bson_doc_t *docs, size_t n);
mongo_cursor_t *mongo_find(mongo_collection_t *coll, const bson_doc_t *filter);
bson_doc_t *mongo_find_one(mongo_collection_t *coll, const bson_doc_t *filter);
mongo_update_result_t mongo_update_one(mongo_collection_t *coll, const bson_doc_t *filter, const bson_doc_t *update);
mongo_delete_result_t mongo_delete_one(mongo_collection_t *coll, const bson_doc_t *filter);
uint64_t mongo_count_documents(mongo_collection_t *coll, const bson_doc_t *filter);

/* BSON document helpers */
bson_doc_t *bson_doc_create(void);
void bson_doc_destroy(bson_doc_t *doc);
int bson_doc_append(bson_doc_t *doc, const char *key, const bson_value_t *value);
bson_value_t *bson_doc_get(const bson_doc_t *doc, const char *key);

/* BSON value constructors */
bson_value_t bson_int32(int32_t v);
bson_value_t bson_int64(int64_t v);
bson_value_t bson_double(double v);
bson_value_t bson_string(const char *s);
bson_value_t bson_bool(int b);
bson_value_t bson_null(void);

/* Cursor */
void mongo_cursor_destroy(mongo_cursor_t *cursor);
bson_doc_t *mongo_cursor_next(mongo_cursor_t *cursor);

/* BSON serialization */
size_t bson_doc_serialize(const bson_doc_t *doc, uint8_t *buf, size_t buf_len);
bson_doc_t *bson_doc_parse(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MONGO_C_H */
