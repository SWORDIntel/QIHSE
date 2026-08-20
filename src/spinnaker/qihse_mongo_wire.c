#include "qihse_mongo_wire.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

/* ---- BSON implementation ---- */

bson_t* bson_create(void) {
    bson_t* b = (bson_t*)calloc(1, sizeof(bson_t));
    if (!b) return NULL;
    b->cap = 256;
    b->data = (uint8_t*)calloc(b->cap, 1);
    b->len = 4; /* reserve for document size */
    return b;
}

void bson_destroy(bson_t* b) {
    if (!b) return;
    free(b->data);
    free(b);
}

static int bson_ensure(bson_t* b, size_t need) {
    if (b->len + need > b->cap) {
        while (b->len + need > b->cap) b->cap *= 2;
        b->data = (uint8_t*)realloc(b->data, b->cap);
    }
    return 0;
}

static int bson_append_type_and_key(bson_t* b, uint8_t type, const char* key) {
    size_t klen = strlen(key) + 1;
    bson_ensure(b, 1 + klen);
    b->data[b->len++] = type;
    memcpy(b->data + b->len, key, klen);
    b->len += klen;
    return 0;
}

int bson_append_int32(bson_t* b, const char* key, int32_t val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_INT32, key);
    bson_ensure(b, 4);
    memcpy(b->data + b->len, &val, 4);
    b->len += 4;
    return 0;
}

int bson_append_int64(bson_t* b, const char* key, int64_t val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_INT64, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &val, 8);
    b->len += 8;
    return 0;
}

int bson_append_double(bson_t* b, const char* key, double val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_DOUBLE, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &val, 8);
    b->len += 8;
    return 0;
}

int bson_append_string(bson_t* b, const char* key, const char* val) {
    if (!b || !key || !val) return -1;
    bson_append_type_and_key(b, BSON_STRING, key);
    int32_t slen = (int32_t)(strlen(val) + 1);
    bson_ensure(b, 4 + slen);
    memcpy(b->data + b->len, &slen, 4);
    b->len += 4;
    memcpy(b->data + b->len, val, slen);
    b->len += slen;
    return 0;
}

int bson_append_bool(bson_t* b, const char* key, int val) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_BOOL, key);
    bson_ensure(b, 1);
    b->data[b->len++] = val ? 1 : 0;
    return 0;
}

int bson_append_null(bson_t* b, const char* key) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_NULL, key);
    return 0;
}

int bson_append_document(bson_t* b, const char* key, const bson_t* sub) {
    if (!b || !key || !sub) return -1;
    bson_append_type_and_key(b, BSON_DOCUMENT, key);
    /* Finalize sub document size */
    int32_t sz = (int32_t)sub->len;
    bson_ensure(b, sz);
    memcpy(b->data + b->len, &sz, 4);
    b->len += 4;
    memcpy(b->data + b->len, sub->data + 4, sub->len - 4);
    b->len += sub->len - 4;
    return 0;
}

int bson_append_binary(bson_t* b, const char* key, const uint8_t* data, size_t len) {
    if (!b || !key || !data) return -1;
    bson_append_type_and_key(b, BSON_BINARY, key);
    int32_t slen = (int32_t)len;
    bson_ensure(b, 5 + len);
    memcpy(b->data + b->len, &slen, 4);
    b->len += 4;
    b->data[b->len++] = 0x00; /* generic binary subtype */
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

int bson_append_datetime(bson_t* b, const char* key, int64_t ms) {
    if (!b || !key) return -1;
    bson_append_type_and_key(b, BSON_DATETIME, key);
    bson_ensure(b, 8);
    memcpy(b->data + b->len, &ms, 8);
    b->len += 8;
    return 0;
}

size_t bson_size(const bson_t* b) {
    if (!b) return 0;
    /* Write final size and null terminator */
    int32_t sz = (int32_t)(b->len + 1);
    memcpy(b->data, &sz, 4);
    return b->len + 1;
}

const uint8_t* bson_data(const bson_t* b) {
    if (!b) return NULL;
    /* Ensure size is written */
    int32_t sz = (int32_t)(b->len + 1);
    memcpy(b->data, &sz, 4);
    /* Null terminator */
    if (b->len < b->cap) b->data[b->len] = 0;
    return b->data;
}

/* BSON iteration */
int bson_iter(const bson_t* b, size_t* offset, bson_element_t* out_elem) {
    if (!b || !offset || !out_elem) return -1;
    if (*offset == 0) *offset = 4; /* skip document size */
    if (*offset >= b->len) return -1; /* end of document */
    
    uint8_t type = b->data[*offset];
    if (type == 0) return -1; /* null terminator */
    (*offset)++;
    
    const char* key = (const char*)(b->data + *offset);
    size_t klen = strlen(key) + 1;
    *offset += klen;
    
    out_elem->type = (bson_type_t)type;
    out_elem->key = key;
    
    switch (type) {
        case BSON_INT32:
            memcpy(&out_elem->v.i32, b->data + *offset, 4);
            *offset += 4;
            break;
        case BSON_INT64:
        case BSON_DATETIME:
        case BSON_TIMESTAMP:
            memcpy(&out_elem->v.i64, b->data + *offset, 8);
            *offset += 8;
            break;
        case BSON_DOUBLE:
            memcpy(&out_elem->v.d, b->data + *offset, 8);
            *offset += 8;
            break;
        case BSON_STRING:
            int32_t slen;
            memcpy(&slen, b->data + *offset, 4);
            *offset += 4;
            out_elem->v.str = (const char*)(b->data + *offset);
            *offset += slen;
            break;
        case BSON_BOOL:
            out_elem->v.b = b->data[*offset];
            *offset += 1;
            break;
        case BSON_NULL:
            break;
        case BSON_BINARY:
            int32_t blen;
            memcpy(&blen, b->data + *offset, 4);
            *offset += 4;
            (*offset)++; /* subtype */
            out_elem->v.bin.data = b->data + *offset;
            out_elem->v.bin.len = blen;
            *offset += blen;
            break;
        case BSON_DOCUMENT:
        case BSON_ARRAY: {
            int32_t dlen;
            memcpy(&dlen, b->data + *offset, 4);
            *offset += dlen;
            break;
        }
        default:
            *offset = b->len;
            return -1;
    }
    return 0;
}

/* ---- MongoDB wire protocol ---- */

int mongo_msg_parse(const uint8_t* data, size_t len, mongo_msg_t* out) {
    if (!data || len < 16 || !out) return -1;
    memcpy(&out->message_length, data, 4);
    memcpy(&out->request_id, data + 4, 4);
    memcpy(&out->response_to, data + 8, 4);
    memcpy(&out->opcode, data + 12, 4);
    out->body = data + 16;
    out->body_len = len - 16;
    return 0;
}

bson_t* mongo_msg_get_document(const mongo_msg_t* msg, size_t* offset) {
    if (!msg || !offset) return NULL;
    if (*offset + 4 > msg->body_len) return NULL;
    int32_t doc_len;
    memcpy(&doc_len, msg->body + *offset, 4);
    if (*offset + doc_len > msg->body_len) return NULL;
    bson_t* b = (bson_t*)calloc(1, sizeof(bson_t));
    b->cap = doc_len;
    b->len = doc_len;
    b->data = (uint8_t*)malloc(doc_len);
    memcpy(b->data, msg->body + *offset, doc_len);
    *offset += doc_len;
    return b;
}

/* ---- MongoDB server ---- */

static void* mongo_client_thread(void* arg) {
    /* Handle a single MongoDB client connection */
    int fd = (int)(intptr_t)arg;
    uint8_t buf[65536];
    while (1) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        mongo_msg_t msg;
        if (mongo_msg_parse(buf, n, &msg) != 0) continue;
        /* Process based on opcode */
        bson_t* reply = bson_create();
        bson_append_int32(reply, "ok", 1);
        /* Build reply message */
        size_t rsize = bson_size(reply);
        uint8_t rbuf[65536];
        int32_t total = (int32_t)(16 + rsize);
        memcpy(rbuf, &total, 4);
        int32_t rid = 1; memcpy(rbuf + 4, &rid, 4);
        int32_t rto = msg.request_id; memcpy(rbuf + 8, &rto, 4);
        int32_t op = MONGO_OP_REPLY; memcpy(rbuf + 12, &op, 4);
        /* Reply flags + cursor id + starting from + number returned */
        int32_t flags = 0; memcpy(rbuf + 16, &flags, 4);
        int64_t cursor_id = 0; memcpy(rbuf + 20, &cursor_id, 8);
        int32_t start = 0; memcpy(rbuf + 28, &start, 4);
        int32_t num = 0; memcpy(rbuf + 32, &num, 4);
        /* BSON document follows */
        memcpy(rbuf + 36, bson_data(reply), rsize);
        send(fd, rbuf, 36 + rsize, 0);
        bson_destroy(reply);
    }
    close(fd);
    return NULL;
}

static void* mongo_accept_thread(void* arg) {
    qihse_mongo_server_t* srv = (qihse_mongo_server_t*)arg;
    while (srv->running) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(srv->fd, (struct sockaddr*)&addr, &addr_len);
        if (fd < 0) continue;
        pthread_t tid;
        pthread_create(&tid, NULL, mongo_client_thread, (void*)(intptr_t)fd);
        pthread_detach(tid);
    }
    return NULL;
}

qihse_mongo_server_t* qihse_mongo_server_create(uint16_t port, void* doc_store) {
    qihse_mongo_server_t* srv = (qihse_mongo_server_t*)calloc(1, sizeof(qihse_mongo_server_t));
    if (!srv) return NULL;
    srv->port = port;
    srv->doc_store = doc_store;
    srv->running = 0;
    srv->fd = -1;
    return srv;
}

int qihse_mongo_server_start(qihse_mongo_server_t* srv) {
    if (!srv || srv->running) return -1;
    srv->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->fd < 0) return -1;
    int opt = 1;
    setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(srv->port);
    if (bind(srv->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(srv->fd); return -1; }
    if (listen(srv->fd, 128) < 0) { close(srv->fd); return -1; }
    srv->running = 1;
    pthread_create(&srv->thread, NULL, mongo_accept_thread, srv);
    return 0;
}

int qihse_mongo_server_stop(qihse_mongo_server_t* srv) {
    if (!srv) return -1;
    srv->running = 0;
    if (srv->fd >= 0) { close(srv->fd); srv->fd = -1; }
    pthread_join(srv->thread, NULL);
    return 0;
}

void qihse_mongo_server_destroy(qihse_mongo_server_t* srv) {
    if (!srv) return;
    qihse_mongo_server_stop(srv);
    free(srv);
}
