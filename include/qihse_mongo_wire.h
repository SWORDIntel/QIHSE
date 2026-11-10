#ifndef QIHSE_MONGO_WIRE_H
#define QIHSE_MONGO_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "qihse_document.h"
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================
 * Authorization model (AGENTS.md invariants 1 and 3)
 * ---------------------------------------------------------------------------
 * Every read path in this adapter takes an explicit authenticated principal.
 * There is no context-free read primitive:
 *
 *   - mongo_dispatch_command_as() is the primary entry point and takes the
 *     caller's qihse_user_t* directly.
 *   - The declared entry points that carry no user argument
 *     (mongo_dispatch_command, mongo_catalog_get_db, mongo_db_get_collection,
 *     mongo_catalog_get_collection, mongo_catalog_drop_collection) inherit the
 *     principal bound to the catalog by mongo_catalog_create_auth() /
 *     mongo_catalog_bind_user().
 *   - A NULL principal is never an authorization bypass: it is refused with
 *     error code 13 (Unauthorized) before any document is touched, and the
 *     catalog accessors return NULL.  Note that qihse_auth_can_access(NULL, 0,
 *     0) is TRUE by design for unclassified data, so this adapter gates on the
 *     principal's presence itself instead of relying on the clearance check.
 *
 * Document classification
 * ---------------------------------------------------------------------------
 * Each stored document carries its classification in two internal BSON fields,
 * "__qihse_classif" (int32) and "__qihse_sci" (int32).  They travel with the
 * document, so they cannot desynchronise from it, and they are stripped by the
 * single reply-materialisation path before any byte reaches a client.  A
 * document written through this adapter is labelled at its writer's clearance;
 * a client-supplied value for either internal field is discarded, so a client
 * can never label its own data.
 *
 * A document is visible to a principal iff it carries both internal fields and
 * qihse_auth_can_access() grants the principal its classification and SCI.  A
 * document that carries no label is therefore invisible (fail closed) rather
 * than public.
 *
 * The wire format is not the wire format of a stock MongoDB driver's auth
 * handshake: SCRAM-SHA-256 is not implemented.  Authentication is the QIHSE
 * "authenticate" command, which carries a cleartext password exactly as the
 * PostgreSQL adapter's AuthenticationCleartextPassword path already does, and
 * is rate-limited per source IP by qihse_auth_check_rate_limit().  Until a
 * connection authenticates, every command other than "authenticate"/"logout"
 * is refused with code 13 and no payload.
 * =========================================================================== */

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

/* Largest accepted MongoDB message (16 MiB + framing headroom).  A declared
 * message_length above this is refused by mongo_msg_parse() rather than
 * allocated. */
#define MONGO_MAX_MESSAGE_SIZE (17u * 1024u * 1024u)

/* Largest BSON document this adapter will materialise from the wire. */
#define MONGO_MAX_BSON_SIZE (16u * 1024u * 1024u)

/* Maximum simultaneously tracked client connections of one server. */
#define MONGO_MAX_CONNECTIONS 64

/* Fields are appended, never reordered: the existing layout is preserved. */
typedef struct {
    int fd;
    uint16_t port;
    pthread_t thread;
    volatile int running;
    void* doc_store;  /* qihse_document_store_t* */
    void* catalog;    /* mongo_catalog_t* */
    /* --- appended for connection bookkeeping (stop/destroy must not free the
     * catalog while a client thread still holds it) --- */
    pthread_mutex_t conn_lock;
    pthread_cond_t conn_idle;
    size_t live_conns;
    int conn_fds[MONGO_MAX_CONNECTIONS];
    pthread_t conn_threads[MONGO_MAX_CONNECTIONS];
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
        struct { const uint8_t* data; int32_t len; } doc;   /* sub-document/array */
        struct { const char* pattern; const char* options; } regex;
        struct { const uint8_t* data; } oid;                /* 12-byte ObjectId */
    } v;
} bson_element_t;

int bson_iter(const bson_t* b, size_t* offset, bson_element_t* out_elem);

/* MongoDB wire protocol server */
qihse_mongo_server_t* qihse_mongo_server_create(uint16_t port, void* doc_store);
int qihse_mongo_server_start(qihse_mongo_server_t* srv);
int qihse_mongo_server_stop(qihse_mongo_server_t* srv);
void qihse_mongo_server_destroy(qihse_mongo_server_t* srv);

/* ---- Message parsing ---- */
typedef struct {
    int32_t message_length;
    int32_t request_id;
    int32_t response_to;
    int32_t opcode;
    const uint8_t* body;
    size_t body_len;
} mongo_msg_t;

/* Parse a framed MongoDB message.  data/len is the raw byte stream; the frame
 * is accepted only when the declared message_length fits inside len, the
 * opcode is one this adapter implements, and the opcode's own header is
 * present.  Returns 0 on success, -1 on a malformed or unsupported frame
 * (nothing is written to *out and no byte past len is read). */
int mongo_msg_parse(const uint8_t* data, size_t len, mongo_msg_t* out);
/* Materialise the next BSON document of the message body as a heap copy the
 * caller owns (destroy with bson_destroy()).
 *
 * *offset is an absolute offset into msg->body.  On the first call (*offset ==
 * 0) the opcode's own header is skipped automatically, so a caller can walk the
 * documents of an OP_MSG/OP_QUERY/OP_INSERT/OP_UPDATE/OP_DELETE in order.
 * Returns NULL on a malformed document (declared length that does not fit in
 * the body, a document that is not NUL-terminated, or a length beyond
 * MONGO_MAX_BSON_SIZE) and on the end of the body; *offset is left untouched
 * when the document is refused. */
bson_t* mongo_msg_get_document(const mongo_msg_t* msg, size_t* offset);

/* ---- Extended BSON helpers ---- */
int bson_append_array(bson_t* b, const char* key, const bson_t* sub);
int bson_append_objectid(bson_t* b, const char* key, const uint8_t oid[12]);
int bson_append_regex(bson_t* b, const char* key, const char* pattern, const char* options);
int bson_append_timestamp(bson_t* b, const char* key, int32_t incr, int32_t ts);
int bson_append_minkey(bson_t* b, const char* key);
int bson_append_maxkey(bson_t* b, const char* key);
int bson_append_element(bson_t* b, const char* key, const bson_element_t* e, const uint8_t* raw);
bson_t* bson_copy(const bson_t* src);
int bson_find_element(const bson_t* b, const char* key, bson_element_t* out);
int bson_find_path(const bson_t* b, const char* dotted, bson_element_t* out);
char* bson_to_json(const bson_t* b);
void bson_remove_key(bson_t* b, const char* key);
int bson_set_field(bson_t* b, const char* key, const bson_element_t* e, const uint8_t* raw);

/* ---- Catalog (in-memory database/collection store) ---- */
typedef struct {
    bson_t** docs;
    size_t count;
    size_t cap;
    char name[128];
} mongo_collection_t;

/* Fields are appended, never reordered. */
typedef struct {
    mongo_collection_t** colls;
    size_t count;
    size_t cap;
    char name[128];
    void* owner;  /* mongo_catalog_t* this database belongs to (NULL if detached) */
} mongo_database_t;

/* Fields are appended, never reordered. */
typedef struct {
    mongo_database_t** dbs;
    size_t count;
    size_t cap;
    qihse_document_store_t* doc_store;
    pthread_mutex_t lock;
    /* Appended: the authenticated principal this catalog's user-less entry
     * points run as.  NULL means "no context": every user-less entry point
     * fails closed (accessors return NULL, dispatch returns code 13). */
    qihse_user_t* auth_user;
} mongo_catalog_t;

mongo_catalog_t* mongo_catalog_create(qihse_document_store_t* ds);
/* Same, with an explicit authenticated principal bound at creation. */
mongo_catalog_t* mongo_catalog_create_auth(qihse_document_store_t* ds, qihse_user_t* user);
/* Bind (or clear, with NULL) the principal the user-less entry points inherit.
 * Returns 0 on success, -1 if cat is NULL. */
int mongo_catalog_bind_user(mongo_catalog_t* cat, qihse_user_t* user);
/* The principal currently bound, or NULL. */
qihse_user_t* mongo_catalog_get_user(const mongo_catalog_t* cat);
void mongo_catalog_destroy(mongo_catalog_t* cat);
mongo_database_t* mongo_catalog_get_db(mongo_catalog_t* cat, const char* db);
mongo_collection_t* mongo_db_get_collection(mongo_database_t* db, const char* name);
mongo_collection_t* mongo_catalog_get_collection(mongo_catalog_t* cat, const char* db, const char* coll);
int mongo_catalog_drop_collection(mongo_catalog_t* cat, const char* db, const char* coll);

/* ---- Query matching ---- */
int bson_match(const bson_t* doc, const bson_t* filter);
int bson_match_operator(const bson_t* doc, const char* key, const bson_element_t* field,
                        const char* op, const bson_element_t* opval, const uint8_t* raw);

/* ---- Update operators ---- */
int bson_apply_update(bson_t* doc, const bson_t* update, int is_insert);

/* ---- Aggregation pipeline ----
 * Runs pipeline stages over input documents.  pipeline is either a BSON array
 * whose elements are stage documents (n_stages == 0, run every stage) or a
 * single stage document (n_stages == 1).  Implemented stages: $match, $limit,
 * $skip, $sort, $count, $project (inclusion/exclusion only), $unwind and
 * $group ($sum/$avg/$min/$max/$first/$last/$push).  $lookup, $facet,
 * $graphLookup and computed $project expressions are NOT implemented: the call
 * returns NULL with *out_count == 0 rather than silently dropping the stage.
 * On success the caller owns each element and the array itself. */
bson_t** bson_aggregate(const bson_t* const* input, size_t n_in,
                        const bson_t* pipeline, size_t n_stages,
                        size_t* out_count);

/* ---- Command dispatch ---- */
/* Primary entry point: dispatches cmd against db_name as an explicit
 * authenticated principal.  user == NULL is refused with error code 13 and no
 * document bytes.  The returned reply document is owned by the caller. */
bson_t* mongo_dispatch_command_as(mongo_catalog_t* cat, qihse_user_t* user,
                                  const char* db_name, const bson_t* cmd);
/* User-less form declared above: inherits the catalog's bound principal and
 * fails closed (code 13, no payload) when none is bound. */
bson_t* mongo_dispatch_command(mongo_catalog_t* cat, const char* db_name,
                               const bson_t* cmd);

#ifdef __cplusplus
}
#endif
#endif
