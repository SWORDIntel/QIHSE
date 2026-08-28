/*
 * UWP GRAPH2 (0x0a) and INDEX (0x0b) command handlers.
 *
 * GRAPH2 encodings (all integer fields are little-endian):
 *   MATCH, DELETE: u64 vertex_id
 *   CREATE, MERGE: u64 label_count, label_count NUL-terminated labels,
 *                  u64 property_count, then property_count entries of
 *                  NUL-terminated key, u8 graph_prop_type, and value.
 *   SET:           u64 vertex_id, NUL-terminated key, u8 type, value.
 *   REMOVE:        u8 entity_type (0=vertex, 1=edge), u64 id, NUL-terminated property key.
 *   Property values are i64/double bits (8 bytes), a NUL-terminated string,
 *   or a one-byte bool for INT64/DOUBLE/STRING/BOOL respectively.
 *   MERGE is currently CREATE-only because the wire format carries no id.
 *
 * INDEX encodings:
 *   CREATE_INDEX: NUL name, u8 index type, u8 column count, then a u8 column
 *                 type and NUL column name for every column. For HNSW type,
 *                 followed by u32 dimension.
 *   SCAN:         NUL name. It returns metadata only; scan predicates are not
 *                 part of this first protocol revision.
 *   INSERT:       NUL name, u64 row id, u8 column count, then a u8 column
 *                 type and value for every column. Numeric values are 8
 *                 bytes; string values are NUL-terminated.
 *   BULK_LOAD:    NUL name, u32 row count, then row_count entries of u64 row
 *                 id, u32 key length, and key bytes. Keys are pre-serialized
 *                 B+ tree keys, so BULK_LOAD presently accepts B+ trees only.
 *   DROP:         NUL name. Removes the index from the manager and frees it.
 */
#include "qihse_uwp_graph_index.h"

#include "qihse_fts.h"
#include "qihse_graph_store.h"
#include "qihse_hnsw.h"
#include "qihse_index_manager.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UWP_GI_MAX_FIELDS 4096u

#if defined(_MSC_VER)
#define UWP_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define UWP_THREAD_LOCAL _Thread_local
#else
#define UWP_THREAD_LOCAL __thread
#endif

typedef struct {
    const uint8_t* cur;
    const uint8_t* end;
} uwp_gi_cursor_t;

static void uwp_write_cb(qihse_uwp_write_fn write_fn, void* write_ctx,
                         const void* data, size_t len) {
    if (write_fn) write_fn(write_ctx, data, len);
}

static uwp_gi_result_t gi_reply(qihse_uwp_write_fn write_fn, void* write_ctx,
                                uwp_gi_result_t result, const char* text) {
    if (write_fn) write_fn(write_ctx, text, strlen(text));
    return result;
}

static bool gi_read_u8(uwp_gi_cursor_t* cursor, uint8_t* value) {
    if (!cursor || !value || cursor->cur >= cursor->end) return false;
    *value = *cursor->cur++;
    return true;
}

static bool gi_read_u32_le(uwp_gi_cursor_t* cursor, uint32_t* value) {
    uint32_t result;
    if (!cursor || !value || (size_t)(cursor->end - cursor->cur) < 4) return false;
    result = (uint32_t)cursor->cur[0] | ((uint32_t)cursor->cur[1] << 8) |
             ((uint32_t)cursor->cur[2] << 16) | ((uint32_t)cursor->cur[3] << 24);
    cursor->cur += 4;
    *value = result;
    return true;
}

static bool gi_read_u64_le(uwp_gi_cursor_t* cursor, uint64_t* value) {
    uint64_t result = 0;
    if (!cursor || !value || (size_t)(cursor->end - cursor->cur) < 8) return false;
    for (unsigned int i = 0; i < 8; ++i)
        result |= (uint64_t)cursor->cur[i] << (8u * i);
    cursor->cur += 8;
    *value = result;
    return true;
}

static bool gi_read_cstring(uwp_gi_cursor_t* cursor, const char** value,
                            size_t* value_len) {
    const uint8_t* terminator;
    if (!cursor || !value) return false;
    terminator = memchr(cursor->cur, '\0', (size_t)(cursor->end - cursor->cur));
    if (!terminator) return false;
    *value = (const char*)cursor->cur;
    if (value_len) *value_len = (size_t)(terminator - cursor->cur);
    cursor->cur = terminator + 1;
    return true;
}

static bool gi_at_end(const uwp_gi_cursor_t* cursor) {
    return cursor && cursor->cur == cursor->end;
}

static bool gi_read_graph_prop(uwp_gi_cursor_t* cursor, graph_prop_t* prop) {
    uint8_t wire_type;
    uint64_t bits;
    const char* string_value;
    if (!cursor || !prop || !gi_read_u8(cursor, &wire_type)) return false;
    memset(prop, 0, sizeof(*prop));
    switch (wire_type) {
        case GRAPH_PROP_INT64:
            if (!gi_read_u64_le(cursor, &bits)) return false;
            prop->type = GRAPH_PROP_INT64;
            prop->val.i = (int64_t)bits;
            return true;
        case GRAPH_PROP_DOUBLE:
            if (!gi_read_u64_le(cursor, &bits)) return false;
            prop->type = GRAPH_PROP_DOUBLE;
            memcpy(&prop->val.d, &bits, sizeof(prop->val.d));
            return true;
        case GRAPH_PROP_STRING:
            if (!gi_read_cstring(cursor, &string_value, NULL)) return false;
            *prop = graph_prop_make_string(string_value);
            return prop->val.s != NULL;
        case GRAPH_PROP_BOOL:
            if (!gi_read_u8(cursor, &wire_type) || wire_type > 1) return false;
            prop->type = GRAPH_PROP_BOOL;
            prop->val.b = wire_type != 0;
            return true;
        default:
            return false;
    }
}

static void gi_free_graph_props(graph_prop_t* props, size_t count) {
    if (!props) return;
    for (size_t i = 0; i < count; ++i) graph_prop_free(&props[i]);
    free(props);
}

static bool gi_read_graph_create(uwp_gi_cursor_t* cursor,
                                 const char*** out_labels, size_t* out_label_count,
                                 const char*** out_keys, graph_prop_t** out_props,
                                 size_t* out_prop_count) {
    uint64_t count64;
    const char** labels = NULL;
    const char** keys = NULL;
    graph_prop_t* props = NULL;
    size_t label_count = 0;
    size_t prop_count = 0;
    if (!cursor || !out_labels || !out_label_count || !out_keys || !out_props ||
        !out_prop_count || !gi_read_u64_le(cursor, &count64) ||
        count64 > UWP_GI_MAX_FIELDS) return false;
    label_count = (size_t)count64;
    labels = calloc(label_count ? label_count : 1, sizeof(*labels));
    if (!labels) goto fail;
    for (size_t i = 0; i < label_count; ++i)
        if (!gi_read_cstring(cursor, &labels[i], NULL)) goto fail;
    if (!gi_read_u64_le(cursor, &count64) || count64 > UWP_GI_MAX_FIELDS) goto fail;
    prop_count = (size_t)count64;
    keys = calloc(prop_count ? prop_count : 1, sizeof(*keys));
    props = calloc(prop_count ? prop_count : 1, sizeof(*props));
    if (!keys || !props) goto fail;
    for (size_t i = 0; i < prop_count; ++i) {
        if (!gi_read_cstring(cursor, &keys[i], NULL) ||
            !gi_read_graph_prop(cursor, &props[i])) goto fail;
    }
    *out_labels = labels;
    *out_label_count = label_count;
    *out_keys = keys;
    *out_props = props;
    *out_prop_count = prop_count;
    return true;
fail:
    free(labels);
    free(keys);
    gi_free_graph_props(props, prop_count);
    return false;
}

static uwp_gi_result_t gi_reply_vertex(qihse_uwp_write_fn write_fn, void* write_ctx,
                                       graph_vertex_t* vertex) {
    size_t needed;
    char* reply;
    size_t offset;
    if (!vertex) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
    needed = (size_t)snprintf(NULL, 0, "VERTEX id=%" PRIu64 " labels=[", vertex->id);
    for (size_t i = 0; i < vertex->num_labels; ++i) {
        size_t label_len = strlen(vertex->labels[i]);
        if (label_len > SIZE_MAX - needed - 1) goto fail;
        needed += label_len + (i ? 1 : 0);
    }
    if (needed > SIZE_MAX - 32) goto fail;
    needed += (size_t)snprintf(NULL, 0, "] props=%zu\n", vertex->num_props);
    reply = malloc(needed + 1);
    if (!reply) goto fail;
    offset = (size_t)snprintf(reply, needed + 1, "VERTEX id=%" PRIu64 " labels=[",
                              vertex->id);
    for (size_t i = 0; i < vertex->num_labels; ++i)
        offset += (size_t)snprintf(reply + offset, needed + 1 - offset, "%s%s",
                                   i ? "," : "", vertex->labels[i]);
    offset += (size_t)snprintf(reply + offset, needed + 1 - offset, "] props=%zu\n",
                               vertex->num_props);
    uwp_write_cb(write_fn, write_ctx, reply, offset);
    free(reply);
    graph_vertex_free(vertex);
    return UWP_GI_OK;
fail:
    graph_vertex_free(vertex);
    return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
}

static void* gi_fts_create(void) { return qihse_fts_create(); }
static void gi_fts_destroy(void* handle) { qihse_fts_destroy((qihse_fts_index_t*)handle); }
static bool gi_fts_insert(void* handle, uint64_t row_id, const void* data, size_t data_len) {
    return handle && data && qihse_fts_add_document((qihse_fts_index_t*)handle,
        row_id, (const char*)data, data_len, 0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN);
}
static bool gi_fts_delete(void* handle, uint64_t row_id) {
    (void)handle; (void)row_id;
    /* qihse_fts.h does not currently expose document deletion. */
    return false;
}

/* Pending dimension for HNSW index creation.
 * Thread-local: each thread has its own pending dimension, so concurrent
 * HNSW creation from different threads is safe. Within a thread, creation
 * is serialized by call order. */
static UWP_THREAD_LOCAL size_t g_hnsw_pending_dim = 0;

typedef struct {
    qihse_hnsw_index_t* index;
    float* vectors;
    size_t vector_cap;
    size_t dim;
} gi_hnsw_wrapper_t;

static const float* gi_hnsw_get_vector(void* user_context, uint32_t node_id) {
    gi_hnsw_wrapper_t* wrap = (gi_hnsw_wrapper_t*)user_context;
    if (!wrap || !wrap->vectors || (size_t)node_id >= wrap->vector_cap) return NULL;
    return &wrap->vectors[(size_t)node_id * wrap->dim];
}

static float gi_hnsw_euclidean_distance(const float* a, const float* b, size_t dim) {
    if (!a || !b) return 1e9f;
    float sum = 0.0f;
    for (size_t i = 0; i < dim; ++i) {
        float d = a[i] - b[i];
        sum += d * d;
    }
    return sum;
}

static void* gi_hnsw_create(void) {
    gi_hnsw_wrapper_t* wrap = (gi_hnsw_wrapper_t*)calloc(1, sizeof(gi_hnsw_wrapper_t));
    if (!wrap) return NULL;
    wrap->dim = g_hnsw_pending_dim ? g_hnsw_pending_dim : 128;
    wrap->index = (qihse_hnsw_index_t*)calloc(1, sizeof(qihse_hnsw_index_t));
    if (!wrap->index) {
        free(wrap);
        return NULL;
    }
    wrap->index->params.M = 16;
    wrap->index->params.M0 = 32;
    wrap->index->params.ef_construction = 200;
    wrap->index->params.ef_search = 200;
    wrap->index->params.mult = 1.0f / logf(16.0f);
    wrap->index->params.distance_fn = gi_hnsw_euclidean_distance;
    wrap->index->params.get_vector_fn = gi_hnsw_get_vector;
    wrap->index->params.user_context = wrap;
    wrap->index->params.dim = wrap->dim;
    wrap->index->max_level = -1;
    wrap->index->num_nodes = 0;
    return wrap;
}

static void gi_hnsw_destroy(void* handle) {
    gi_hnsw_wrapper_t* wrap = (gi_hnsw_wrapper_t*)handle;
    if (!wrap) return;
    if (wrap->index) {
        hnsw_destroy(wrap->index);
    }
    free(wrap->vectors);
    free(wrap);
}

static bool gi_hnsw_insert(void* handle, uint64_t row_id, const void* data, size_t data_len) {
    gi_hnsw_wrapper_t* wrap = (gi_hnsw_wrapper_t*)handle;
    if (!wrap || !wrap->index || !data) return false;
    if (data_len < wrap->dim * sizeof(float)) return false;
    uint32_t node_id = (uint32_t)row_id;
    if ((size_t)node_id >= wrap->vector_cap) {
        size_t new_cap = wrap->vector_cap ? wrap->vector_cap * 2 : 16;
        while (new_cap <= (size_t)node_id) new_cap *= 2;
        float* new_vecs = (float*)realloc(wrap->vectors, new_cap * wrap->dim * sizeof(float));
        if (!new_vecs) return false;
        wrap->vectors = new_vecs;
        wrap->vector_cap = new_cap;
    }
    memcpy(&wrap->vectors[(size_t)node_id * wrap->dim], data, wrap->dim * sizeof(float));
    hnsw_insert(wrap->index, node_id, (const float*)data, wrap->dim);
    return true;
}

static bool gi_hnsw_delete(void* handle, uint64_t row_id) {
    (void)handle;
    (void)row_id;
    /* HNSW does not currently expose node deletion. */
    return false;
}

uwp_gi_result_t uwp_dispatch_graph2(qihse_uwp_context_t* ctx,
                                    uint8_t command_opcode,
                                    const uint8_t* payload, size_t payload_len,
                                    qihse_user_t* user, int client_fd,
                                    qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    uwp_gi_cursor_t cursor;
    qihse_graph_t* graph;
    if (!user) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_PERM, "ERR_PERM\n");
    if (!ctx || !ctx->graph_store) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_NO_CTX, "ERR_NO_CTX\n");
    if (!payload) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
    graph = (qihse_graph_t*)ctx->graph_store;
    cursor.cur = payload;
    cursor.end = payload + payload_len;
    switch (command_opcode) {
        case 0x01: {
            uint64_t id;
            graph_vertex_t* vertex;
            if (!gi_read_u64_le(&cursor, &id) || !gi_at_end(&cursor))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            vertex = qihse_graph_vertex_get(graph, id);
            if (!vertex) return gi_reply(write_fn, write_ctx, UWP_GI_OK, "NOT_FOUND\n");
            return gi_reply_vertex(write_fn, write_ctx, vertex);
        }
        case 0x02:
        case 0x03: {
            const char** labels = NULL;
            const char** keys = NULL;
            graph_prop_t* props = NULL;
            size_t label_count = 0, prop_count = 0;
            uint64_t id;
            uint8_t reply[8];
            if (!gi_read_graph_create(&cursor, &labels, &label_count, &keys, &props,
                                      &prop_count) || !gi_at_end(&cursor)) {
                free(labels); free(keys); gi_free_graph_props(props, prop_count);
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            }
            /* MERGE is CREATE-only until its wire format includes a vertex id. */
            id = qihse_graph_vertex_create(graph, labels, label_count, keys, props, prop_count);
            free(labels); free(keys); gi_free_graph_props(props, prop_count);
            if (id == 0) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            for (unsigned int i = 0; i < 8; ++i) reply[i] = (uint8_t)(id >> (8u * i));
            uwp_write_cb(write_fn, write_ctx, reply, sizeof(reply));
            return UWP_GI_OK;
        }
        case 0x04: {
            uint64_t id;
            if (!gi_read_u64_le(&cursor, &id) || !gi_at_end(&cursor))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            if (!qihse_graph_vertex_delete(graph, id))
                return gi_reply(write_fn, write_ctx, UWP_GI_OK, "NOT_FOUND\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
        }
        case 0x05: {
            uint64_t id;
            const char* key;
            graph_prop_t prop;
            bool updated;
            memset(&prop, 0, sizeof(prop));
            if (!gi_read_u64_le(&cursor, &id) || !gi_read_cstring(&cursor, &key, NULL) ||
                !gi_read_graph_prop(&cursor, &prop) || !gi_at_end(&cursor)) {
                graph_prop_free(&prop);
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            }
            updated = qihse_graph_vertex_update(graph, id, &key, &prop, 1);
            graph_prop_free(&prop);
            if (!updated) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
        }
        case 0x06: {
            uint8_t entity_type;
            uint64_t id;
            const char* prop_key;
            bool ok;
            if (!gi_read_u8(&cursor, &entity_type) || (entity_type != 0 && entity_type != 1) ||
                !gi_read_u64_le(&cursor, &id) || !gi_read_cstring(&cursor, &prop_key, NULL) ||
                !gi_at_end(&cursor))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            if (entity_type == 0) {
                ok = qihse_graph_vertex_remove_property(graph, id, prop_key);
            } else {
                ok = qihse_graph_edge_remove_property(graph, id, prop_key);
            }
            if (!ok) return gi_reply(write_fn, write_ctx, UWP_GI_OK, "NOT_FOUND\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
        }
        case 0x10: {
            uint8_t algorithm_id;
            char reply[32];
            int length;
            if (!gi_read_u8(&cursor, &algorithm_id))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            length = snprintf(reply, sizeof(reply), "ALGO %u QUEUED\n", algorithm_id);
            if (length < 0 || (size_t)length >= sizeof(reply))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            uwp_write_cb(write_fn, write_ctx, reply, (size_t)length);
            return UWP_GI_OK;
        }
        default:
            return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
    }
}

uwp_gi_result_t uwp_dispatch_index(qihse_uwp_context_t* ctx,
                                   uint8_t command_opcode,
                                   const uint8_t* payload, size_t payload_len,
                                   qihse_user_t* user, int client_fd,
                                   qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    uwp_gi_cursor_t cursor;
    qihse_index_manager_t* manager;
    if (!user) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_PERM, "ERR_PERM\n");
    if (!ctx || !ctx->index_manager) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_NO_CTX, "ERR_NO_CTX\n");
    if (!payload) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
    manager = (qihse_index_manager_t*)ctx->index_manager;
    cursor.cur = payload;
    cursor.end = payload + payload_len;
    switch (command_opcode) {
        case 0x01: {
            const char* name;
            size_t name_len;
            uint8_t type_wire, ncol_wire;
            qihse_idx_col_def_t* cols;
            qihse_index_t* index = NULL;
            uint32_t hnsw_dim = 0;
            if (!gi_read_cstring(&cursor, &name, &name_len) || name_len == 0 || name_len >= 128 ||
                !gi_read_u8(&cursor, &type_wire) || !gi_read_u8(&cursor, &ncol_wire) ||
                ncol_wire == 0 || type_wire > QIHSE_INDEX_FTS_INVERTED)
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            cols = calloc(ncol_wire, sizeof(*cols));
            if (!cols) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            for (uint8_t i = 0; i < ncol_wire; ++i) {
                const char* col_name;
                size_t col_name_len;
                uint8_t col_type;
                if (!gi_read_u8(&cursor, &col_type) || col_type > QIHSE_IDX_COL_STRING ||
                    !gi_read_cstring(&cursor, &col_name, &col_name_len) || col_name_len == 0 ||
                    col_name_len >= sizeof(cols[i].name)) {
                    free(cols);
                    return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
                }
                cols[i].type = (qihse_idx_col_type_t)col_type;
                memcpy(cols[i].name, col_name, col_name_len + 1);
            }
            if (type_wire == QIHSE_INDEX_VECTOR_HNSW) {
                if (!gi_read_u32_le(&cursor, &hnsw_dim) || hnsw_dim == 0) {
                    free(cols);
                    return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
                }
            }
            if (!gi_at_end(&cursor)) { free(cols); return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n"); }
            switch ((qihse_index_type_t)type_wire) {
                case QIHSE_INDEX_BTREE:
                    index = qihse_index_manager_add_btree(manager, name, cols, ncol_wire, 0); break;
                case QIHSE_INDEX_HASH:
                    index = qihse_index_manager_add_hash(manager, name, cols, ncol_wire, 0); break;
                case QIHSE_INDEX_FTS_INVERTED: {
                    const qihse_index_wrapper_vtbl_t vtbl = {
                        gi_fts_create, gi_fts_destroy, gi_fts_insert, gi_fts_delete
                    };
                    index = qihse_index_manager_add_wrapped(manager, name,
                        QIHSE_INDEX_FTS_INVERTED, cols, ncol_wire, &vtbl);
                    break;
                }
                case QIHSE_INDEX_VECTOR_HNSW: {
                    const qihse_index_wrapper_vtbl_t vtbl = {
                        gi_hnsw_create, gi_hnsw_destroy, gi_hnsw_insert, gi_hnsw_delete
                    };
                    g_hnsw_pending_dim = (size_t)hnsw_dim;
                    index = qihse_index_manager_add_wrapped(manager, name,
                        QIHSE_INDEX_VECTOR_HNSW, cols, ncol_wire, &vtbl);
                    break;
                }
                default: break;
            }
            free(cols);
            if (!index) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
        }
        case 0x02: {
            const char* name;
            qihse_index_t* index;
            char reply[256];
            int length;
            if (!gi_read_cstring(&cursor, &name, NULL) || !gi_at_end(&cursor))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            index = qihse_index_manager_find(manager, name);
            if (!index) return gi_reply(write_fn, write_ctx, UWP_GI_OK, "NOT_FOUND\n");
            length = snprintf(reply, sizeof(reply), "INDEX %s COUNT %zu\n", name,
                              qihse_index_manager_count(manager));
            if (length < 0 || (size_t)length >= sizeof(reply))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            uwp_write_cb(write_fn, write_ctx, reply, (size_t)length);
            return UWP_GI_OK;
        }
        case 0x03: {
            const char* name;
            uint64_t row_id;
            uint8_t ncol_wire;
            qihse_idx_col_type_t* types = NULL;
            const void** values = NULL;
            size_t* lengths = NULL;
            bool ok;
            if (!gi_read_cstring(&cursor, &name, NULL) || !gi_read_u64_le(&cursor, &row_id) ||
                !gi_read_u8(&cursor, &ncol_wire) || ncol_wire == 0 ||
                !qihse_index_manager_find(manager, name))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            types = calloc(ncol_wire, sizeof(*types));
            values = calloc(ncol_wire, sizeof(*values));
            lengths = calloc(ncol_wire, sizeof(*lengths));
            if (!types || !values || !lengths) {
                free(types); free(values); free(lengths);
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            }
            for (uint8_t i = 0; i < ncol_wire; ++i) {
                uint8_t type_wire;
                const char* string_value;
                if (!gi_read_u8(&cursor, &type_wire) || type_wire > QIHSE_IDX_COL_STRING) goto insert_args;
                types[i] = (qihse_idx_col_type_t)type_wire;
                if (types[i] == QIHSE_IDX_COL_STRING) {
                    if (!gi_read_cstring(&cursor, &string_value, &lengths[i])) goto insert_args;
                    values[i] = string_value;
                } else {
                    if ((size_t)(cursor.end - cursor.cur) < 8) goto insert_args;
                    values[i] = cursor.cur;
                    lengths[i] = 8;
                    cursor.cur += 8;
                }
            }
            if (!gi_at_end(&cursor)) goto insert_args;
            ok = qihse_index_manager_insert_row(manager, row_id, types, values, lengths, ncol_wire);
            free(types); free(values); free(lengths);
            if (!ok) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
insert_args:
            free(types); free(values); free(lengths);
            return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
        }
        case 0x04: {
            const char* name;
            uint32_t nrows_wire;
            qihse_index_t* index;
            uint64_t* row_ids = NULL;
            const void** keys = NULL;
            size_t* key_lens = NULL;
            bool ok;
            if (!gi_read_cstring(&cursor, &name, NULL) || !gi_read_u32_le(&cursor, &nrows_wire) ||
                nrows_wire == 0 || !(index = qihse_index_manager_find(manager, name)) ||
                qihse_index_type(index) != QIHSE_INDEX_BTREE ||
                nrows_wire > (size_t)(cursor.end - cursor.cur) / 12u)
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            row_ids = calloc(nrows_wire, sizeof(*row_ids));
            keys = calloc(nrows_wire, sizeof(*keys));
            key_lens = calloc(nrows_wire, sizeof(*key_lens));
            if (!row_ids || !keys || !key_lens) {
                free(row_ids); free(keys); free(key_lens);
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            }
            for (uint32_t i = 0; i < nrows_wire; ++i) {
                uint32_t key_len;
                if (!gi_read_u64_le(&cursor, &row_ids[i]) || !gi_read_u32_le(&cursor, &key_len) ||
                    (size_t)(cursor.end - cursor.cur) < key_len) {
                    free(row_ids); free(keys); free(key_lens);
                    return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
                }
                keys[i] = cursor.cur;
                key_lens[i] = key_len;
                cursor.cur += key_len;
            }
            if (!gi_at_end(&cursor)) {
                free(row_ids); free(keys); free(key_lens);
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            }
            ok = qihse_index_bulk_load(index, row_ids, keys, key_lens, nrows_wire);
            free(row_ids); free(keys); free(key_lens);
            if (!ok) return gi_reply(write_fn, write_ctx, UWP_GI_ERR_FAILED, "ERR_FAILED\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
        }
        case 0x05: {
            const char* name;
            if (!gi_read_cstring(&cursor, &name, NULL) || !gi_at_end(&cursor))
                return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
            if (!qihse_index_manager_drop(manager, name))
                return gi_reply(write_fn, write_ctx, UWP_GI_OK, "NOT_FOUND\n");
            return gi_reply(write_fn, write_ctx, UWP_GI_OK, "OK\n");
        }
        default:
            return gi_reply(write_fn, write_ctx, UWP_GI_ERR_ARGS, "ERR_ARGS\n");
    }
}
