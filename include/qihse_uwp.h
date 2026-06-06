#ifndef QIHSE_UWP_H
#define QIHSE_UWP_H

#include <stdint.h>
#include <stdbool.h>

#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_document.h"
#include "qihse_column.h"
#include "qihse_timeseries.h"
#include "qihse_event_stream.h"

/* Unified Context holding all engine pointers */
typedef struct {
    qihse_kv_store_t* kv;
    qihse_vector_db_t vdb;
    qihse_document_store_t* doc;
    qihse_column_store_t* col;
    qihse_tsdb_t* tsdb;
    qihse_event_stream_t* stream;
} qihse_uwp_context_t;

/* 16-byte fixed width packed header */
typedef struct __attribute__((packed)) {
    uint8_t  magic[5];       // Must be {'Q', 'I', 'H', 'S', 'E'}
    uint8_t  version;        // 0x01
    uint8_t  target_engine;  // Subsystem Routing Opcode
    uint8_t  command_opcode; // Engine-specific command
    uint64_t payload_length; // Little-Endian unsigned 64-bit length
} qihse_uwp_header_t;

/* Subsystem Routing Opcodes */
#define QIHSE_UWP_TARGET_KV      0x01
#define QIHSE_UWP_TARGET_VECTOR  0x02
#define QIHSE_UWP_TARGET_DOC     0x03
#define QIHSE_UWP_TARGET_COL     0x04
#define QIHSE_UWP_TARGET_TSDB    0x05
#define QIHSE_UWP_TARGET_GRAPH   0x06
#define QIHSE_UWP_TARGET_STREAM  0x07

/**
 * @brief Start the QIHSE Unified Wire Protocol TCP server.
 * Blocks and listens on the specified port.
 * @param ctx Context object holding all initialized engines
 * @param port TCP port to bind
 * @param bind_address IP to bind (NULL for INADDR_ANY)
 * @return true on clean exit, false on fatal socket error
 */
bool qihse_start_uwp_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address);

#endif /* QIHSE_UWP_H */
