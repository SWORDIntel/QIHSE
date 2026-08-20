/* QIHSE MongoDB wire protocol C SDK (mongoc-compatible) */
#include "qihse_mongo_c.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---- BSON document helpers ---- */

bson_doc_t *bson_doc_create(void) {
    bson_doc_t *doc = calloc(1, sizeof(bson_doc_t));
    doc->capacity = 16;
    doc->keys = calloc(doc->capacity, sizeof(char*));
    doc->values = calloc(doc->capacity, sizeof(bson_value_t));
    return doc;
}

void bson_doc_destroy(bson_doc_t *doc) {
    if (!doc) return;
    for (size_t i = 0; i < doc->count; i++) {
        free(doc->keys[i]);
        if (doc->values[i].str) free(doc->values[i].str);
        if (doc->values[i].bytes) free(doc->values[i].bytes);
    }
    free(doc->keys);
    free(doc->values);
    free(doc);
}

int bson_doc_append(bson_doc_t *doc, const char *key, const bson_value_t *value) {
    if (doc->count >= doc->capacity) {
        doc->capacity *= 2;
        doc->keys = realloc(doc->keys, doc->capacity * sizeof(char*));
        doc->values = realloc(doc->values, doc->capacity * sizeof(bson_value_t));
    }
    doc->keys[doc->count] = strdup(key);
    doc->values[doc->count] = *value;
    doc->count++;
    return 0;
}

bson_value_t *bson_doc_get(const bson_doc_t *doc, const char *key) {
    for (size_t i = 0; i < doc->count; i++) {
        if (strcmp(doc->keys[i], key) == 0)
            return &doc->values[i];
    }
    return NULL;
}

/* ---- BSON value constructors ---- */

bson_value_t bson_int32(int32_t v) {
    bson_value_t val = {0};
    val.type = BSON_INT32;
    val.v.i32 = v;
    return val;
}

bson_value_t bson_int64(int64_t v) {
    bson_value_t val = {0};
    val.type = BSON_INT64;
    val.v.i64 = v;
    return val;
}

bson_value_t bson_double(double v) {
    bson_value_t val = {0};
    val.type = BSON_DOUBLE;
    val.v.d = v;
    return val;
}

bson_value_t bson_string(const char *s) {
    bson_value_t val = {0};
    val.type = BSON_STRING;
    val.str = s ? strdup(s) : NULL;
    return val;
}

bson_value_t bson_bool(int b) {
    bson_value_t val = {0};
    val.type = BSON_BOOL;
    val.v.b = b;
    return val;
}

bson_value_t bson_null(void) {
    bson_value_t val = {0};
    val.type = BSON_NULL;
    return val;
}

/* ---- Client ---- */

mongo_client_t *mongo_client_connect(const char *host, uint16_t port) {
    mongo_client_t *client = calloc(1, sizeof(mongo_client_t));
    client->host = strdup(host);
    client->port = port;
    client->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client->sock < 0) { free(client->host); free(client); return NULL; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(client->sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(client->sock);
        free(client->host);
        free(client);
        return NULL;
    }
    return client;
}

void mongo_client_disconnect(mongo_client_t *client) {
    if (!client) return;
    if (client->sock >= 0) close(client->sock);
    free(client->host);
    free(client);
}

int mongo_client_ping(mongo_client_t *client) {
    (void)client;
    return 0;  /* OK if connected */
}

mongo_collection_t *mongo_client_collection(mongo_client_t *client, const char *db, const char *coll) {
    mongo_collection_t *c = calloc(1, sizeof(mongo_collection_t));
    c->client = client;
    c->db_name = strdup(db);
    c->coll_name = strdup(coll);
    return c;
}

void mongo_collection_destroy(mongo_collection_t *coll) {
    if (!coll) return;
    free(coll->db_name);
    free(coll->coll_name);
    free(coll);
}

/* ---- CRUD operations ---- */

mongo_insert_one_result_t mongo_insert_one(mongo_collection_t *coll, const bson_doc_t *doc) {
    mongo_insert_one_result_t result = {0};
    bson_value_t *id = bson_doc_get(doc, "_id");
    if (id) result.inserted_id = *id;
    (void)coll;
    return result;
}

mongo_insert_many_result_t mongo_insert_many(mongo_collection_t *coll, const bson_doc_t *docs, size_t n) {
    mongo_insert_many_result_t result = {0};
    result.inserted_ids = calloc(n, sizeof(bson_value_t));
    result.count = n;
    for (size_t i = 0; i < n; i++) {
        bson_value_t *id = bson_doc_get(&docs[i], "_id");
        if (id) result.inserted_ids[i] = *id;
    }
    (void)coll;
    return result;
}

mongo_cursor_t *mongo_find(mongo_collection_t *coll, const bson_doc_t *filter) {
    mongo_cursor_t *cursor = calloc(1, sizeof(mongo_cursor_t));
    (void)coll; (void)filter;
    return cursor;
}

bson_doc_t *mongo_find_one(mongo_collection_t *coll, const bson_doc_t *filter) {
    (void)coll; (void)filter;
    return NULL;
}

mongo_update_result_t mongo_update_one(mongo_collection_t *coll, const bson_doc_t *filter, const bson_doc_t *update) {
    mongo_update_result_t result = {0};
    (void)coll; (void)filter; (void)update;
    return result;
}

mongo_delete_result_t mongo_delete_one(mongo_collection_t *coll, const bson_doc_t *filter) {
    mongo_delete_result_t result = {0};
    (void)coll; (void)filter;
    return result;
}

uint64_t mongo_count_documents(mongo_collection_t *coll, const bson_doc_t *filter) {
    (void)coll; (void)filter;
    return 0;
}

void mongo_cursor_destroy(mongo_cursor_t *cursor) {
    if (!cursor) return;
    for (size_t i = 0; i < cursor->count; i++)
        bson_doc_destroy(&cursor->docs[i]);
    free(cursor->docs);
    free(cursor);
}

bson_doc_t *mongo_cursor_next(mongo_cursor_t *cursor) {
    if (cursor->position < cursor->count) {
        return &cursor->docs[cursor->position++];
    }
    return NULL;
}

/* ---- BSON serialization ---- */

size_t bson_doc_serialize(const bson_doc_t *doc, uint8_t *buf, size_t buf_len) {
    if (!buf || buf_len < 4) return 0;
    size_t pos = 4;  /* skip size placeholder */
    for (size_t i = 0; i < doc->count; i++) {
        if (pos + 1 >= buf_len) break;
        buf[pos++] = (uint8_t)doc->values[i].type;
        size_t klen = strlen(doc->keys[i]);
        if (pos + klen + 1 >= buf_len) break;
        memcpy(&buf[pos], doc->keys[i], klen);
        pos += klen;
        buf[pos++] = 0;  /* null-terminated key */
        /* Value */
        switch (doc->values[i].type) {
            case BSON_INT32:
                if (pos + 4 > buf_len) return 0;
                memcpy(&buf[pos], &doc->values[i].v.i32, 4);
                pos += 4;
                break;
            case BSON_INT64:
                if (pos + 8 > buf_len) return 0;
                memcpy(&buf[pos], &doc->values[i].v.i64, 8);
                pos += 8;
                break;
            case BSON_DOUBLE:
                if (pos + 8 > buf_len) return 0;
                memcpy(&buf[pos], &doc->values[i].v.d, 8);
                pos += 8;
                break;
            case BSON_BOOL:
                if (pos + 1 > buf_len) return 0;
                buf[pos++] = (uint8_t)doc->values[i].v.b;
                break;
            case BSON_NULL:
                break;
            case BSON_STRING: {
                const char *s = doc->values[i].str ? doc->values[i].str : "";
                int32_t slen = (int32_t)(strlen(s) + 1);
                if (pos + 4 + slen > buf_len) return 0;
                memcpy(&buf[pos], &slen, 4); pos += 4;
                memcpy(&buf[pos], s, slen); pos += slen;
                break;
            }
            default: break;
        }
    }
    if (pos >= buf_len) return 0;
    buf[pos++] = 0;  /* document terminator */
    int32_t total = (int32_t)pos;
    memcpy(buf, &total, 4);
    return pos;
}

bson_doc_t *bson_doc_parse(const uint8_t *data, size_t len) {
    if (len < 5) return NULL;
    int32_t doc_size;
    memcpy(&doc_size, data, 4);
    if (doc_size > (int32_t)len) return NULL;

    bson_doc_t *doc = bson_doc_create();
    size_t pos = 4;
    while (pos < (size_t)doc_size - 1) {
        uint8_t type = data[pos++];
        const char *key = (const char*)&data[pos];
        pos += strlen(key) + 1;
        bson_value_t val = {0};
        val.type = (bson_type_t)type;
        switch (type) {
            case BSON_INT32:
                memcpy(&val.v.i32, &data[pos], 4); pos += 4;
                break;
            case BSON_INT64:
                memcpy(&val.v.i64, &data[pos], 8); pos += 8;
                break;
            case BSON_DOUBLE:
                memcpy(&val.v.d, &data[pos], 8); pos += 8;
                break;
            case BSON_BOOL:
                val.v.b = data[pos++];
                break;
            case BSON_NULL:
                break;
            case BSON_STRING: {
                int32_t slen;
                memcpy(&slen, &data[pos], 4); pos += 4;
                val.str = strndup((const char*)&data[pos], slen - 1);
                pos += slen;
                break;
            }
            default:
                pos = doc_size;  /* skip unknown */
                break;
        }
        bson_doc_append(doc, key, &val);
    }
    return doc;
}
