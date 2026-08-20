#ifndef QIHSE_BOLT_H
#define QIHSE_BOLT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_uwp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Bolt protocol constants ---- */

#define QIHSE_BOLT_MAGIC       0x6060B017u
#define QIHSE_BOLT_VERSION_4   0x00000004u
#define QIHSE_BOLT_MAX_CHUNK   0xFFFF

/* Bolt 4.x message signatures (client -> server) */
#define QIHSE_BOLT_MSG_HELLO     0x01
#define QIHSE_BOLT_MSG_GOODBYE   0x02
#define QIHSE_BOLT_MSG_RESET     0x10
#define QIHSE_BOLT_MSG_RUN       0x11
#define QIHSE_BOLT_MSG_DISCARD   0x12
#define QIHSE_BOLT_MSG_PULL      0x13
#define QIHSE_BOLT_MSG_BEGIN     0x2F
#define QIHSE_BOLT_MSG_COMMIT    0x30
#define QIHSE_BOLT_MSG_ROLLBACK  0x31

/* Bolt 4.x message signatures (server -> client) */
#define QIHSE_BOLT_MSG_SUCCESS   0x70
#define QIHSE_BOLT_MSG_RECORD    0x71
#define QIHSE_BOLT_MSG_IGNORED   0x7E
#define QIHSE_BOLT_MSG_FAILURE   0x7F

/* PackStream structure signatures */
#define QIHSE_BOLT_STRUCT_NODE        0x4E  /* 'N' */
#define QIHSE_BOLT_STRUCT_RELATION    0x52  /* 'R' */
#define QIHSE_BOLT_STRUCT_PATH        0x50  /* 'P' */
#define QIHSE_BOLT_STRUCT_UNBOUND_REL 0x72  /* 'r' */

/* ---- PackStream value model ---- */

typedef enum {
    QIHSE_BOLT_NULL = 0,
    QIHSE_BOLT_BOOL,
    QIHSE_BOLT_INT,
    QIHSE_BOLT_FLOAT,
    QIHSE_BOLT_STRING,
    QIHSE_BOLT_LIST,
    QIHSE_BOLT_MAP,
    QIHSE_BOLT_STRUCT
} qihse_bolt_type_t;

typedef struct qihse_bolt_value qihse_bolt_value_t;

typedef struct {
    uint8_t signature;
    size_t nfields;
    qihse_bolt_value_t** fields;
} qihse_bolt_struct_t;

struct qihse_bolt_value {
    qihse_bolt_type_t type;
    union {
        bool b;
        int64_t i;
        double f;
        struct { char* data; size_t len; } s;
        struct { qihse_bolt_value_t** items; size_t count; } list;
        struct { qihse_bolt_value_t** keys; qihse_bolt_value_t** vals; size_t count; } map;
        qihse_bolt_struct_t strct;
    } v;
};

/* ---- PackStream encoder ---- */

typedef struct {
    uint8_t* buf;
    size_t len;
    size_t cap;
} qihse_bolt_buf_t;

void qihse_bolt_buf_init(qihse_bolt_buf_t* b, size_t initial_cap);
void qihse_bolt_buf_free(qihse_bolt_buf_t* b);
void qihse_bolt_buf_reserve(qihse_bolt_buf_t* b, size_t extra);
void qihse_bolt_buf_append(qihse_bolt_buf_t* b, const void* data, size_t n);

/* Encode primitives into a buffer. */
void qihse_bolt_encode_null(qihse_bolt_buf_t* b);
void qihse_bolt_encode_bool(qihse_bolt_buf_t* b, bool val);
void qihse_bolt_encode_int(qihse_bolt_buf_t* b, int64_t val);
void qihse_bolt_encode_float(qihse_bolt_buf_t* b, double val);
void qihse_bolt_encode_string(qihse_bolt_buf_t* b, const char* str);
void qihse_bolt_encode_list_begin(qihse_bolt_buf_t* b, size_t count);
void qihse_bolt_encode_map_begin(qihse_bolt_buf_t* b, size_t count);
void qihse_bolt_encode_struct_begin(qihse_bolt_buf_t* b, uint8_t signature, size_t nfields);

/* ---- PackStream decoder ---- */

typedef struct {
    const uint8_t* data;
    size_t len;
    size_t pos;
} qihse_bolt_decoder_t;

void qihse_bolt_decoder_init(qihse_bolt_decoder_t* d, const uint8_t* data, size_t len);
qihse_bolt_value_t* qihse_bolt_decode(qihse_bolt_decoder_t* d);
void qihse_bolt_value_free(qihse_bolt_value_t* v);

/* ---- Message framing (chunking) ---- */

/* Encode a complete message (signature + payload) into chunked wire format.
 * Writes a single chunk (big-endian length, signature, payload, 0x00 terminator)
 * followed by a 0x0000 end-of-message marker. */
void qihse_bolt_encode_message(qihse_bolt_buf_t* b, uint8_t signature,
                               const uint8_t* payload, size_t payload_len);

/* Decode one message from a chunked stream. Returns the message signature and
 * sets out_payload/out_len to the reassembled message body (caller frees
 * out_payload). Returns -1 on error, 0 if not enough data yet. */
int qihse_bolt_decode_message(const uint8_t* data, size_t len,
                              uint8_t* out_sig, uint8_t** out_payload, size_t* out_payload_len,
                              size_t* out_consumed);

/* ---- Server ---- */

/**
 * @brief Start the Bolt protocol server. Blocks and listens on the port.
 */
bool qihse_start_bolt_server(qihse_uwp_context_t* ctx, uint16_t port, const char* bind_address);

/**
 * @brief Handle a single Bolt client connection (handshake + message loop).
 */
void qihse_bolt_handle_client(int client_fd, qihse_uwp_context_t* ctx);

/**
 * @brief Perform the Bolt version handshake on an already-accepted socket.
 * Returns true on success and writes the negotiated version to out_version.
 */
bool qihse_bolt_handshake(int fd, uint32_t* out_version);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_BOLT_H */
