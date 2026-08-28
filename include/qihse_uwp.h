#ifndef QIHSE_UWP_H
#define QIHSE_UWP_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>  /* ssize_t for qihse_uwp_write_fn */

#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_document.h"
#include "qihse_column.h"
#include "qihse_timeseries.h"
#include "qihse_event_stream.h"
#include "qihse_auth.h"
#include "qihse_repl.h"
#include "qihse_pooler.h"
#include "qihse_uwp_tls.h"
#include "qihse_uwp_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Unified Context holding all engine pointers */
typedef struct {
    qihse_kv_store_t* kv;
    qihse_vector_db_t vdb;
    qihse_document_store_t* doc;
    qihse_column_store_t* col;
    qihse_tsdb_t* tsdb;
    qihse_event_stream_t* stream;
    qihse_user_t* user;
    /* New engine pointers (opaque for now, wired by other subsystems) */
    void* sql_engine;      /* SQL engine context */
    void* txn_manager;     /* Transaction manager */
    void* graph_store;     /* Graph store */
    void* index_manager;   /* Index manager */
    void* schema;          /* Schema registry */
    void* wal;             /* WAL handle */
    qihse_repl_context_t* repl_ctx; /* NULL unless replication is configured */
    qihse_pooler_t* pooler;         /* NULL unless pooling is configured */
    qihse_uwp_tls_ctx_t* tls_ctx;   /* NULL = cleartext, non-NULL = TLS enabled */
    qihse_uwp_metrics_t* uwp_metrics; /* NULL = metrics disabled */
} qihse_uwp_context_t;

/* 15-byte fixed width packed header */
typedef struct __attribute__((packed)) {
    uint8_t  magic[4];       // Must be {0x51, 0x49, 0x48, 0x53}
    uint8_t  version;        // 0x01
    uint8_t  target_engine;  // Subsystem Routing Opcode
    uint8_t  command_opcode; // Engine-specific command
    uint64_t payload_length; // Little-Endian unsigned 64-bit length
} qihse_uwp_header_t;

/* Subsystem Routing Opcodes */
#define QIHSE_UWP_TARGET_AUTH    0x00
#define QIHSE_UWP_TARGET_KV      0x01
#define QIHSE_UWP_TARGET_VECTOR  0x02
#define QIHSE_UWP_TARGET_DOC     0x03
#define QIHSE_UWP_TARGET_COL     0x04
#define QIHSE_UWP_TARGET_TSDB    0x05
#define QIHSE_UWP_TARGET_GRAPH   0x06
#define QIHSE_UWP_TARGET_STREAM  0x07
#define QIHSE_UWP_TARGET_SQL     0x08  /* SQL query engine */
#define QIHSE_UWP_TARGET_TXN     0x09  /* Transaction manager */
#define QIHSE_UWP_TARGET_GRAPH2  0x0A  /* Full graph engine */
#define QIHSE_UWP_TARGET_INDEX   0x0B  /* Index manager */
#define QIHSE_UWP_TARGET_SCHEMA  0x0C  /* Schema registry */
#define QIHSE_UWP_TARGET_REPL    0x0D  /* Replication */
#define QIHSE_UWP_TARGET_POOL    0x0E  /* Connection pool */

/**
 * @brief Start the QIHSE Unified Wire Protocol TCP server.
 * Blocks and listens on the specified port.
 * @param ctx Context object holding all initialized engines
 * @param port TCP port to bind
 * @param bind_address IP to bind (NULL for INADDR_ANY)
 * @return true on clean exit, false on fatal socket error
 */
bool qihse_start_uwp_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address);

/**
 * @brief Handle a raw payload bypassing the TCP server loop.
 * Useful for the XDP fast path.
 */
void qihse_uwp_handle_payload(qihse_uwp_context_t* ctx, const uint8_t* payload, size_t len);

/**
 * @brief Route a single UWP packet (header + payload) through the dispatch table.
 * Returns true if the packet was handled. Used by protocol translation layers
 * and the Bolt server to execute UWP packets in-process.
 *
 * @param user  Authenticated user obtained from qihse_auth_authenticate().
 *              Must be non-NULL for any target other than QIHSE_UWP_TARGET_AUTH.
 *              Callers that pass NULL for non-AUTH targets will receive false.
 */
bool qihse_uwp_dispatch(qihse_uwp_context_t* ctx, qihse_user_t* user,
                        const qihse_uwp_header_t* header,
                        const uint8_t* payload, size_t payload_len,
                        uint8_t* out_response, size_t out_cap, size_t* out_len);

/* Write callback abstraction for UWP dispatchers.
 * When TLS is enabled, write_fn is a wrapper around uwp_tls_write_all with
 * write_ctx=conn.  When cleartext, write_fn wraps uwp_write_all with
 * write_ctx=&fd.  When NULL, the dispatcher skips all writes (internal
 * nested calls such as SQL->TXN where the outer call handles the response). */
typedef ssize_t (*qihse_uwp_write_fn)(void* write_ctx, const void* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_H */
