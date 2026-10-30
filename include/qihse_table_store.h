#ifndef QIHSE_TABLE_STORE_H
#define QIHSE_TABLE_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Mutable Table Store
 *
 * A simple row-oriented mutable table store that supports INSERT, UPDATE,
 * DELETE, and SELECT with WHERE filtering.  Each table has a fixed schema
 * (column names + types) and a dynamic array of rows.  Rows are arrays of
 * typed column values.  String values are deep-copied on insert and freed
 * on delete.
 *
 * Thread-safety is provided by a pthread_rwlock per table: readers acquire
 * a read lock, writers (INSERT / UPDATE / DELETE) acquire a write lock.
 * Context-free scans, snapshots, metadata and publication helpers are raw
 * engine primitives, not classified-capable adapter entry points. Adapters
 * must propagate an authenticated user through the *_user APIs and enforce
 * write/catalog permissions before invoking raw publication helpers.
 * ------------------------------------------------------------------------- */

/* Column value types. */
typedef enum {
    QIHSE_TS_INT32   = 0,
    QIHSE_TS_INT64   = 1,
    QIHSE_TS_FLOAT   = 2,   /* 32-bit float */
    QIHSE_TS_STRING  = 3,   /* owned, NUL-terminated */
    QIHSE_TS_UUID    = 4,   /* canonical UUID text, owned */
    QIHSE_TS_JSONB   = 5,   /* JSON text, owned */
    QIHSE_TS_BOOLEAN = 6,
    QIHSE_TS_TIMESTAMPTZ = 7, /* signed microseconds since Unix epoch */
    QIHSE_TS_NUMERIC = 8, /* exact canonical base-10 decimal text (owned) */
    QIHSE_TS_TSVECTOR = 9 /* validated PostgreSQL-style lexeme/position text (owned) */
} qihse_ts_type_t;

/* A typed column value. is_null is independent of payload. STRING/UUID/JSONB
 * and NUMERIC/TSVECTOR use owned, validated NUL-terminated text;
 * TIMESTAMPTZ uses signed Unix epoch microseconds. */
typedef struct {
    qihse_ts_type_t type;
    bool is_null;            /* distinct from empty string / zero / false */
    union {
        int32_t  i32;
        int64_t  i64;
        float    f32;
        bool     boolean;
        int64_t  timestamptz_us;
        char*    str;       /* owned (deep-copied on insert, freed on delete) */
    } v;
} qihse_col_value_t;

/* Validate a plain decimal against NUMERIC(precision,scale) without binary float.
 * Zero precision permits an unbounded plain decimal; zero scale forbids fractions. */
bool qihse_ts_numeric_valid(const char* text, unsigned precision, unsigned scale);
/* Require quoted lexeme syntax with ascending positive positions per lexeme. */
bool qihse_ts_tsvector_valid(const char* text);

/* Column definition: name + type. */
typedef struct {
    char*           name;   /* owned */
    qihse_ts_type_t type;
} qihse_col_def_t;

/* Opaque table handle. */
typedef struct qihse_table qihse_table_t;

/* Opaque table store handle. */
typedef struct qihse_table_store qihse_table_store_t;

/* Opaque optimistic transaction over exactly one table. */
typedef struct qihse_table_txn qihse_table_txn_t;

/* Row callback for scanning.  Return false to stop the scan. */
typedef bool (*qihse_table_row_cb)(const qihse_col_value_t* values,
                                   size_t num_cols, void* ctx);

/* --- Store lifecycle --------------------------------------------------- */

/* Create a new empty table store. */
qihse_table_store_t* qihse_table_store_create(void);

/* Open or create an opt-in durable store at path. Writes emit snapshot v5;
 * recovery accepts v1-v5. A checksummed snapshot is atomically replaced and
 * fsynced before commit acknowledges success. Returns NULL on corruption,
 * unsafe paths, I/O failure, or a held lifetime-exclusive writer lock (path.lock).
 * The existing parent must be owned by the effective uid with no group/other
 * permissions; existing snapshot/lock files must also be private, owned,
 * singly linked regular files. Final-component symlinks are refused. Use a
 * local filesystem with atomic rename and working fsync semantics.
 * A failure after rename may have committed on disk and poisons the handle:
 * destroy/reopen before resolving the outcome or attempting further writes.
 * Do not reuse an inherited durable handle after fork. SQL binds explicitly
 * with qihse_uwp_sql_open_durable, which validates/restores the catalog; raw
 * open alone neither binds a SQL context nor installs a missing catalog. */
qihse_table_store_t* qihse_table_store_open_durable(const char* path);

/* SQL snapshot transfer requires the active bootstrap Operator (id 0, tenant
 * 0), not an arbitrary Operator. Transfer accepts committed v3-v5 images with
 * a catalog and preserves their bytes, including retry receipts; it does not
 * upgrade the image. The destination must not exist (no ledger replacement).
 * Paths must meet open_durable's private-directory/file requirements. Backup
 * borrows an open, unpoisoned durable store and serializes with its commits;
 * restore acquires both path locks, so source and target handles must be closed.
 * No handle or principal ownership transfers; no service is stopped/rebound.
 * False can mean a post-publication unlink/directory-fsync failure: the
 * destination may exist. Inspect/reopen it; never blindly overwrite it. */
typedef struct qihse_user_s qihse_user_t;
bool qihse_table_store_backup(qihse_table_store_t* store,
                              const qihse_user_t* user, const char* backup_path);
bool qihse_table_store_restore(const qihse_user_t* user,
                               const char* backup_path, const char* target_path);

/* A durable SQL store must carry a catalog image. Installation is permitted
 * only before any table exists; callers validate the versioned schema image.
 * Input bytes are copied. schema_image returns borrowed bytes invalidated by
 * catalog replacement or store destruction; callers must serialize their use. */
bool qihse_table_store_set_schema_image(qihse_table_store_t* store,
                                        const uint8_t* image, size_t len);
/* Atomically replace a committed catalog image after verifying the caller's
 * expected generation. Row data and retry outcomes remain in the same snapshot. */
bool qihse_table_store_replace_schema_image(qihse_table_store_t* store,
    const uint8_t* expected, size_t expected_len,
    const uint8_t* image, size_t image_len);
bool qihse_table_store_schema_image(const qihse_table_store_t* store,
                                    const uint8_t** image, size_t* len);
bool qihse_table_store_is_durable(const qihse_table_store_t* store);
/* Raw enumeration, without authorization. table_at returns a borrowed handle;
 * caller must keep the store alive. Not an adapter catalog listing API. */
size_t qihse_table_store_table_count(const qihse_table_store_t* store);
qihse_table_t* qihse_table_store_table_at(const qihse_table_store_t* store, size_t index);

/* Destroy all tables and release the durable writer lock. Finish all users
 * and transactions first; borrowed handles/images become invalid. */
void qihse_table_store_destroy(qihse_table_store_t* store);

/* --- Table management -------------------------------------------------- */

/* Create a new table in the store with the given name and column definitions.
 * Returns a pointer to the new table, or NULL on failure (duplicate name,
 * bad args, or OOM). The column definitions are deep-copied. This raw helper
 * does not update a SQL catalog: a bound durable SQL store requires atomic
 * catalog/table publication to preserve catalog/row consistency. */
qihse_table_t* qihse_table_store_create_table(qihse_table_store_t* store,
                                              const char* name,
                                              const qihse_col_def_t* cols,
                                              size_t num_cols);

/* Durable CREATE: publish a new empty table and its complete catalog image
 * in one snapshot generation. On failed persistence, the store may be poisoned
 * when rename succeeded but directory fsync did not; close and recover it.
 * The caller must not publish its staged registry unless this returns true. */
bool qihse_table_store_create_table_with_schema(qihse_table_store_t* store,
    const char* name, const qihse_col_def_t* cols, size_t num_cols,
    const uint8_t* image, size_t image_len);

/* Publish several tables and the final catalog in one fenced snapshot.
 * expected is the catalog captured at BEGIN; mismatches refuse the whole group.
 * No tables become visible on failure. An ambiguous post-rename failure poisons
 * the handle; close/reopen before determining the committed generation. */
typedef struct {
    const char* name;
    const qihse_col_def_t* cols;
    size_t num_cols;
    const qihse_col_value_t* const* initial_rows; /* borrowed complete typed rows */
    size_t num_initial_rows;
} qihse_ts_new_table_t;
typedef struct {
    const qihse_table_t* table; /* borrowed source in the same store */
    uint64_t generation;        /* generation captured with the source snapshot */
} qihse_ts_source_fence_t;
/* Authenticated seeded publication: copy/validate every initial row privately,
 * then authorize seeded rows for WRITE and complete sources for READ, and
 * fence source generations plus expected catalog under locks before fsyncing.
 * Inputs are borrowed for the call and copied; source handles stay store-owned.
 * No live publication on failure; post-rename disk outcome may be ambiguous.
 * Empty unseeded publication still needs adapter-level DDL authorization. */
bool qihse_table_store_create_tables_seeded_with_schema(qihse_table_store_t* store,
    const qihse_ts_new_table_t* tables, size_t count,
    const qihse_ts_source_fence_t* sources, size_t source_count,
    const qihse_user_t* user, const uint8_t* expected, size_t expected_len,
    const uint8_t* image, size_t image_len);
bool qihse_table_store_create_tables_with_schema(qihse_table_store_t* store,
    const qihse_ts_new_table_t* tables, size_t count,
    const uint8_t* expected, size_t expected_len,
    const uint8_t* image, size_t image_len);

/* Find a table by name (case-sensitive).  Returns NULL if not found. */
qihse_table_t* qihse_table_store_find_table(qihse_table_store_t* store,
                                            const char* name);

/* --- Row operations ---------------------------------------------------- */

/* In a durable store, direct row mutations are rejected; use transactions.
 * In-memory stores retain their existing direct-mutation semantics.
 * Insert a row into the table.  String values are deep-copied.
 * Returns the 0-based row id (>= 0) on success, -1 on failure. */
int qihse_table_insert(qihse_table_t* table,
                       const qihse_col_value_t* values, size_t num_values);

/* Update rows matching the predicate.  For each matching row, the columns
 * listed in update_cols are set to the corresponding new_values.
 *   pred         — predicate function; returns non-zero if the row matches.
 *   pred_ctx     — opaque context passed to the predicate.
 *   update_cols  — array of column indices to update.
 *   new_values   — new values for the listed columns (strings deep-copied).
 *   num_updates  — number of entries in update_cols / new_values.
 * Returns 1 when rows changed, 0 when none matched, and -1 on invalid input or
 * allocation failure, or a durable table. On -1 the live table is unchanged. */
int qihse_table_update(qihse_table_t* table,
                       int (*pred)(const qihse_col_value_t* values,
                                   size_t num_cols, void* ctx),
                       void* pred_ctx,
                       const int* update_cols,
                       const qihse_col_value_t* new_values,
                       size_t num_updates);

/* Delete rows matching the predicate.  Matching rows are tombstoned and
 * the table is compacted periodically.
 *   pred     — predicate function; returns non-zero if the row matches.
 *   pred_ctx — opaque context passed to the predicate.
 * Returns true if at least one row was deleted, false otherwise (including
 * durable tables, where direct deletion is rejected). */
bool qihse_table_delete(qihse_table_t* table,
                        int (*pred)(const qihse_col_value_t* values,
                                    size_t num_cols, void* ctx),
                        void* pred_ctx);

/* --- Queries ----------------------------------------------------------- */

/* Raw, unauthenticated live-row count; not a classified adapter entry point. */
size_t qihse_table_row_count(const qihse_table_t* table);

/* Raw scan without authorization; adapters must use scan_user instead.
 * Scan all live rows in the table, calling cb for each. The callback
 * receives a pointer to the row's values (valid only during the callback).
 * Return false from the callback to stop the scan. */
void qihse_table_scan(const qihse_table_t* table,
                      qihse_table_row_cb cb, void* ctx);
/* Authenticated scan for new adapters. Protected rows are never passed to
 * callbacks; NULL/inactive principals and missing table READ ACL fail closed.
 * Returns false on denied/invalid context, true on a completed/early-stopped scan. */
bool qihse_table_scan_user(const qihse_table_t* table,
    const qihse_user_t* user, qihse_table_row_cb cb, void* ctx);
/* Row IDs are snapshot-local and must be reauthorized before dereferencing;
 * callbacks receive only rows visible to user. Return false on denied access. */
typedef bool (*qihse_table_row_id_cb)(size_t row_id,
    const qihse_col_value_t* values, size_t num_cols, void* ctx);
bool qihse_table_scan_ids_user(const qihse_table_t* table,
    const qihse_user_t* user, qihse_table_row_id_cb cb, void* ctx);
bool qihse_table_generation_user(const qihse_table_t* table,
    const qihse_user_t* user, uint64_t* generation);
/* Resolve a generation-fenced row ID only after object and row authorization.
 * false means stale/missing/denied; callbacks never receive protected rows. */
bool qihse_table_row_get_user(const qihse_table_t* table,
    const qihse_user_t* user, uint64_t generation, size_t row_id,
    qihse_table_row_cb cb, void* ctx);

/* --- Optimistic table transactions ------------------------------------ */

/* Capture a deep transaction-local snapshot and the table generation.
 * Returns NULL on invalid input, generation exhaustion, or allocation
 * failure. The transaction is owned by the calling thread and borrows the
 * table/store until consumed. Raw begin does not authorize its snapshot;
 * classified-capable source readers must use begin_user. */
qihse_table_txn_t* qihse_table_txn_begin(qihse_table_t* table);
/* Authenticated source snapshot: refuse if any live row is outside the
 * principal's tenant/clearance, rather than silently computing a partial view. */
qihse_table_txn_t* qihse_table_txn_begin_user(qihse_table_t* table,
                                              const qihse_user_t* user);

/* Mutations and reads below operate only on the transaction-local snapshot.
 * Strings are deep-copied.  No uncommitted state is visible through the live
 * table APIs. */
int qihse_table_txn_insert(qihse_table_txn_t* txn,
                           const qihse_col_value_t* values,
                           size_t num_values);
/* Returns 1 when rows changed, 0 when none matched, and -1 on invalid input or
 * allocation failure.  On -1 the transaction-local snapshot is unchanged. */
int qihse_table_txn_update(qihse_table_txn_t* txn,
                           int (*pred)(const qihse_col_value_t* values,
                                       size_t num_cols, void* ctx),
                           void* pred_ctx,
                           const int* update_cols,
                           const qihse_col_value_t* new_values,
                           size_t num_updates);
/* Atomic per-row UPDATE for generated values and triggers. An authenticated
 * principal is mandatory; only rows authorized for that principal reach either
 * callback. transform receives
 * the candidate row and fills a complete typed row in out; strings in out
 * remain caller-owned and must remain valid until the callback returns. On
 * callback failure or invalid output, the entire shadow is unchanged.
 * Returns 1 if any row changed, 0 if none matched, -1 on failure. */
typedef bool (*qihse_table_row_transform)(const qihse_col_value_t* old_values,
    size_t num_cols, qihse_col_value_t* out, void* ctx);
int qihse_table_txn_transform(qihse_table_txn_t* txn, const qihse_user_t* user,
    int (*pred)(const qihse_col_value_t*, size_t, void*), void* pred_ctx,
    qihse_table_row_transform transform, void* transform_ctx);
bool qihse_table_txn_delete(qihse_table_txn_t* txn,
                            int (*pred)(const qihse_col_value_t* values,
                                        size_t num_cols, void* ctx),
                            void* pred_ctx);
size_t qihse_table_txn_row_count(const qihse_table_txn_t* txn);
void qihse_table_txn_scan(const qihse_table_txn_t* txn,
                          qihse_table_row_cb cb, void* ctx);
/* Authenticated snapshot scan with the same row/ACL boundary as the live scan. */
bool qihse_table_txn_scan_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, qihse_table_row_cb cb, void* ctx);
bool qihse_table_txn_scan_ids_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, qihse_table_row_id_cb cb, void* ctx);
bool qihse_table_txn_generation_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, uint64_t* generation);
bool qihse_table_txn_row_get_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, uint64_t generation, size_t row_id,
    qihse_table_row_cb cb, void* ctx);

/* Raw publication: caller must enforce write permissions and constraints.
 * Commit succeeds only when the live table generation still equals the
 * generation captured by begin.  Success atomically replaces the live rows;
 * a conflict leaves the live table unchanged.  Commit consumes txn on both
 * success and failure. */
bool qihse_table_txn_commit(qihse_table_txn_t* txn);

/* Atomically publish a non-empty group of distinct table transactions. All
 * table generation fences are checked while every participating table write
 * lock is held; either every shadow is published or none is. For a valid
 * array, the function consumes each transaction on success and failure. The
 * caller must not pass duplicate transaction pointers. In-memory stores
 * publish only in memory. Durable stores persist a versioned native snapshot
 * of all tables before publishing/acknowledging; transactions from different
 * stores cannot be mixed with a durable transaction. After an ambiguous
 * post-rename I/O failure, reopen the store before attempting another write. */
bool qihse_table_txn_commit_group(qihse_table_txn_t** txns, size_t count);

/* Read-only group: check all captured generations under the same table locks,
 * consume the shadows, and never publish or persist them. Refuse a poisoned
 * durable store. As with commit_group, all valid transactions are consumed. */
bool qihse_table_txn_validate_group(qihse_table_txn_t** txns, size_t count);

/* Durable retry identity is scoped to one store. This raw API does not
 * authenticate string bindings: adapters derive them from the authenticated
 * principal/tenant, never untrusted caller assertions. Callers compute digest over a
 * canonical operation representation (including parameter types/values, target
 * and transaction ordering); the store compares all 32 bytes verbatim. Keys and
 * bindings are nonempty NUL-terminated byte strings, at most 128
 * bytes each. No ledger eviction occurs: exhaustion fails closed rather than
 * allowing an old key to execute twice. */
#define QIHSE_TS_RETRY_MAX_TEXT 128u
#define QIHSE_TS_RETRY_DIGEST_SIZE 32u
typedef struct {
    const char* key;
    const char* principal;
    const char* tenant;
    uint8_t digest[QIHSE_TS_RETRY_DIGEST_SIZE];
} qihse_ts_retry_identity_t;

typedef struct {
    uint64_t affected_rows;
    uint64_t command_count;
} qihse_ts_retry_outcome_t;

typedef enum {
    QIHSE_TS_RETRY_ERROR = -1, /* invalid input, poisoned store, or I/O failure */
    QIHSE_TS_RETRY_ABSENT = 0,
    QIHSE_TS_RETRY_COMMITTED = 1,
    QIHSE_TS_RETRY_MISMATCH = 2 /* key already bound to another identity */
} qihse_ts_retry_status_t;

/* Lookup is safe after reopening an ambiguously failed commit. COMMITTED
 * returns the original outcome; MISMATCH never reveals another principal's
 * outcome. The caller must reopen after an ambiguous persistence failure. */
qihse_ts_retry_status_t qihse_table_store_retry_lookup(
    qihse_table_store_t* store, const qihse_ts_retry_identity_t* identity,
    qihse_ts_retry_outcome_t* outcome);

/* Consumes a valid nonempty group on every result. COMMITTED means this call
 * persisted and published the shadows; ABSENT means a generation conflict
 * (no publication); MISMATCH means key reuse; ERROR means invalid input,
 * ledger capacity exhaustion, or I/O failure (possibly ambiguous). A matching
 * existing request returns COMMITTED with its original outcome and does not
 * publish the supplied shadows. For a fresh request, *outcome is persisted. */
qihse_ts_retry_status_t qihse_table_txn_commit_group_retry(
    qihse_table_txn_t** txns, size_t count,
    const qihse_ts_retry_identity_t* identity,
    qihse_ts_retry_outcome_t* outcome);

/* Discard the transaction-local snapshot. */
void qihse_table_txn_rollback(qihse_table_txn_t* txn);

/* --- Introspection ----------------------------------------------------- */

/* Return the number of columns in the table. */
size_t qihse_table_num_cols(const qihse_table_t* table);

/* Return the column definition at index idx, or NULL if out of range. */
const qihse_col_def_t* qihse_table_col_def(const qihse_table_t* table,
                                           size_t idx);

/* Find a column index by name (case-sensitive).  Returns -1 if not found. */
int qihse_table_find_col(const qihse_table_t* table, const char* name);

/* Return the table name. */
const char* qihse_table_name(const qihse_table_t* table);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TABLE_STORE_H */
