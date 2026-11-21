/* W11.1/W11.6 supported placement: stock, orders, lines, operation ledger and
 * EVENT INTENT share one durable SQL transaction; evidence is explicitly
 * enlisted in common SQL/blob 2PC. Ordinary UWP COMMIT remains one-phase.
 * No KV stock, transparent cross-model ACID, payment or external delivery claim.
 * Retry resources cannot enter this bridge: this application ledger binds
 * (tenant, principal, op) to the complete bounded request under native SQL
 * shadow/generation fences, not a new production workflow/retry API.
 * Fixtures (including failed/crashed attempts) are deliberately preserved. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_schema.h"
#include "qihse_txn.h"
#include "qihse_blob.h"
#include "qihse_auth.h"
#include "qihse_shared_backup.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/evp.h>

#define SQL_ID 81u
#define BLOB_ID 82u
#define HIGH_CLASS 7u
#define HIGH_SCI 4u
#define LABEL_DEFS ", __qihse_tenant_id INT, __qihse_classification INT, __qihse_sci INT)"
#define LABEL_VALUES ", 0, 7, 4)"
#define COHORT_DEFS " (op INT, product INT, quantity INT, evidence TEXT, decision BIGINT, principal INT, tenant INT"

typedef struct {
    qihse_uwp_context_t sql;
    qihse_blob_store_t* blob;
    qihse_user_t* user;
    qihse_kv_store_t* kv;
} fixture_t;
typedef struct { int op, product, quantity; } request_t;
static const request_t accepted[] = {{21, 1, 3}, {22, 2, 4}, {31, 2, 1}, {24, 2, 2}};
static const request_t aborted = {11, 1, 2};
static int sql_placeholder, witness_fd = -1;
static bool kill_at_blob;
static fixture_t* crash_fixture;
static uint8_t crash_hash[48];
typedef struct { uint64_t id; char boundary; } witness_t;

typedef struct {
    fixture_t* f;
    char bytes[512];
    size_t length, offset;
    uint8_t hash[48];
} evidence_t;

static void path_join(char out[1024], const char* root, const char* leaf) {
    int n = snprintf(out, 1024, "%s/%s", root, leaf);
    assert(n > 0 && n < 1024);
}

static void evidence(request_t r, uint64_t id, evidence_t* e) {
    int n = snprintf(e->bytes, sizeof(e->bytes),
        "ORDER-EVIDENCE v1 tenant=0 principal=0 op=%d product=%d quantity=%d "
        "decision=%" PRIu64 " classification=7 sci=4 event=ORDER_ACCEPTED_INTENT",
        r.op, r.product, r.quantity, id);
    assert(n > 0 && (size_t)n < sizeof(e->bytes));
    e->length = (size_t)n; e->offset = 0;
    unsigned len = 0;
    assert(EVP_Digest(e->bytes, e->length, e->hash, &len, EVP_sha384(), NULL) == 1 && len == 48u);
}

static void hash_hex(const uint8_t hash[48], char out[97]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 48u; ++i) {
        out[2u*i] = hex[hash[i] >> 4]; out[2u*i+1u] = hex[hash[i] & 15u];
    }
    out[96] = 0;
}

static qihse_uwp_sql_result_t* query(fixture_t* f, qihse_user_t* user,
    qihse_txn_t** txn, const char* text) {
    qihse_uwp_sql_result_t* result = NULL;
    qihse_txn_t* autocommit = NULL;
    int rc = qihse_uwp_sql_execute_typed_user(&f->sql, text, NULL, 0,
        txn ? txn : &autocommit, user, &result);
    assert(!autocommit);
    if (rc != UWP_STS_OK) fprintf(stderr, "ORDER SQL status %d: %s\n", rc, text);
    assert(rc == UWP_STS_OK && result);
    return result;
}

static void command(fixture_t* f, qihse_txn_t** txn, const char* text) {
    qihse_uwp_sql_result_t* result = query(f, f->user, txn, text);
    qihse_uwp_sql_result_free(result);
}

static int64_t number(const qihse_col_value_t* v) {
    assert(!v->is_null);
    if (v->type == QIHSE_TS_INT32) return v->v.i32;
    assert(v->type == QIHSE_TS_INT64);
    return v->v.i64;
}

static const char* string(const qihse_col_value_t* v) {
    assert(!v->is_null && v->type == QIHSE_TS_STRING && v->v.str);
    return v->v.str;
}

static void interrupt_now(char boundary, uint64_t id) {
    witness_t w = {0}; w.id = id; w.boundary = boundary;
    assert(witness_fd >= 0 && write(witness_fd, &w, sizeof(w)) == (ssize_t)sizeof(w));
    assert(kill(getpid(), SIGKILL) == 0);
    _exit(126);
}

static int64_t evidence_read(void* opaque, uint8_t* bytes, size_t capacity) {
    evidence_t* e = opaque;
    size_t n = e->length - e->offset;
    if (n > capacity) n = capacity;
    memcpy(bytes, e->bytes + e->offset, n); e->offset += n;
    return (int64_t)n;
}

/* A missing resource is a test error, never a fabricated durable vote. */
static int blob_prepare(void* opaque, uint64_t id) {
    (void)opaque; (void)id; return -1;
}
static int blob_prepare_resource(void* opaque, uint64_t id, void* resource) {
    evidence_t* e = resource;
    assert(e && opaque == e->f->blob);
    bool ok = qihse_blob_prepare_expected_user(opaque, id, 0,
        QIHSE_BLOB_TAG_SCRIPT_SET, HIGH_CLASS, HIGH_SCI, e->f->user,
        evidence_read, e, e->hash, e->length);
    free(e);
    return ok ? 0 : -1;
}
static void blob_rollback(void* resource) { free(resource); }
static int blob_commit(void* opaque, uint64_t id) {
    if (kill_at_blob) {
        /* qihse_txn_commit_prepared syncs COMMIT before callbacks, SQL was
         * registered first and has already published. No native call replaced. */
        qihse_uwp_sql_result_t* rows = query(crash_fixture, crash_fixture->user,
            NULL, "SELECT * FROM orders");
        assert(rows->nrows == 1u && number(&rows->rows[0][0]) == 21 &&
               (uint64_t)number(&rows->rows[0][4]) == id);
        qihse_uwp_sql_result_free(rows);
        assert(!qihse_blob_info_user(opaque, crash_hash,
            &(qihse_blob_info_t){0}, crash_fixture->user));
        interrupt_now('C', id);
    }
    return qihse_blob_resolve_prepared(opaque, id, true) ? 0 : -1;
}
static int blob_abort(void* opaque, uint64_t id) {
    bool ok = qihse_blob_resolve_prepared(opaque, id, false);
    if (!ok) fprintf(stderr, "ORDER blob ABORT failed id=%" PRIu64 "\n", id);
    return ok ? 0 : -1;
}

static void init_auth(fixture_t* f, const char* path) {
    assert(unsetenv("QIHSE_OPERATOR_PASSWORD") == 0);
    assert(setenv("QIHSE_AUTH_PEPPER", "w11-order-private-synthetic-pepper", 1) == 0);
    assert(setenv("QIHSE_DATA_DIR", path, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("OrderSynthetic1!"));
    f->user = qihse_auth_get_user(0); assert(f->user);
}

static void register_participants(fixture_t* f, uint64_t manifest_floor, bool recover) {
    assert(qihse_uwp_sql_txn_register_durable_participant(f->sql.txn_manager, SQL_ID) == 0);
    qihse_txn_participant_t bp = {.engine_id = BLOB_ID, .engine_ctx = f->blob,
        .prepare = blob_prepare, .commit = blob_commit, .abort = blob_abort};
    assert(qihse_txn_register_resource_participant(f->sql.txn_manager, bp,
        blob_prepare_resource) == 0);
    /* Fence above ALL restored/reopened participants BEFORE manager recovery. */
    uint64_t sql_floor = 0, blob_floor = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sql_floor));
    assert(qihse_blob_decision_next_id(f->blob, &blob_floor));
    if (manifest_floor < sql_floor) manifest_floor = sql_floor;
    if (manifest_floor < blob_floor) manifest_floor = blob_floor;
    assert(qihse_txn_advance_next_id(f->sql.txn_manager, manifest_floor) == 0);
    if (recover) assert(qihse_txn_manager_recover(f->sql.txn_manager) == 0);
}

static void open_fixture(fixture_t* f, const char* root, bool initial, bool recover) {
    memset(f, 0, sizeof(*f));
    char path[1024]; path_join(path, root, "auth-XXXXXX");
    assert(mkdtemp(path));
    init_auth(f, path);
    f->sql.sql_engine = &sql_placeholder;
    f->sql.schema = initial ? qihse_schema_registry_create() : NULL;
    path_join(path, root, "orders.qts");
    assert(qihse_uwp_sql_open_durable(&f->sql, path) == 0 && f->sql.schema);
    path_join(path, root, "common.qtj");
    f->sql.txn_manager = qihse_txn_manager_create_durable(path);
    path_join(path, root, "evidence"); f->blob = qihse_blob_store_create(path);
    assert(f->sql.txn_manager && f->blob);
    register_participants(f, 1u, recover);
}

static void close_fixture(fixture_t* f) {
    qihse_blob_store_destroy(f->blob);
    qihse_uwp_sql_close_durable(&f->sql);
    qihse_schema_registry_destroy(f->sql.schema);
    qihse_txn_manager_destroy(f->sql.txn_manager);
    if (f->kv) qihse_kv_store_destroy(f->kv);
}

static void initialize(fixture_t* f) {
    command(f, NULL, "CREATE TABLE products (id INT, initial INT, remaining INT" LABEL_DEFS);
    command(f, NULL, "CREATE TABLE orders" COHORT_DEFS LABEL_DEFS);
    command(f, NULL, "CREATE TABLE operations" COHORT_DEFS LABEL_DEFS);
    command(f, NULL, "CREATE TABLE order_lines (op INT, product INT, quantity INT" LABEL_DEFS);
    command(f, NULL, "CREATE TABLE outbox (op INT, evidence TEXT, decision BIGINT, kind TEXT" LABEL_DEFS);
    qihse_txn_t* txn = NULL;
    command(f, &txn, "BEGIN");
    command(f, &txn, "INSERT INTO products VALUES (1, 10, 10" LABEL_VALUES);
    command(f, &txn, "INSERT INTO products VALUES (2, 9, 9" LABEL_VALUES);
    command(f, &txn, "COMMIT"); assert(!txn);
    /* An ordinary UWP SQL commit did not silently enlist common participants. */
    uint64_t sf = 0, bf = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sf) && sf == 1u);
    assert(qihse_blob_decision_next_id(f->blob, &bf) && bf == 1u);
}

typedef enum { STAGED, DUPLICATE, MISMATCH, DECLINED } order_result_t;
static order_result_t stage(fixture_t* f, request_t r, qihse_txn_t** txn) {
    assert(r.op > 0 && r.quantity > 0 && (r.product == 1 || r.product == 2));
    command(f, txn, "BEGIN"); assert(*txn);
    char text[2048];
    snprintf(text, sizeof(text), "SELECT * FROM operations WHERE op = %d", r.op);
    qihse_uwp_sql_result_t* rows = query(f, f->user, txn, text);
    assert(rows->nrows <= 1u);
    if (rows->nrows) {
        const qihse_col_value_t* row = rows->rows[0];
        assert(number(&row[5]) == 0 && number(&row[6]) == 0);
        bool same = number(&row[1]) == r.product && number(&row[2]) == r.quantity;
        qihse_uwp_sql_result_free(rows); command(f, txn, "ROLLBACK");
        return same ? DUPLICATE : MISMATCH;
    }
    qihse_uwp_sql_result_free(rows);
    snprintf(text, sizeof(text), "SELECT * FROM products WHERE id = %d", r.product);
    rows = query(f, f->user, txn, text);
    assert(rows->nrows == 1u);
    int64_t remaining = number(&rows->rows[0][2]);
    qihse_uwp_sql_result_free(rows);
    if (remaining < r.quantity) { command(f, txn, "ROLLBACK"); return DECLINED; }
    snprintf(text, sizeof(text), "UPDATE products SET remaining = %" PRId64 " WHERE id = %d",
        remaining - r.quantity, r.product);
    rows = query(f, f->user, txn, text); assert(rows->affected_rows == 1u);
    qihse_uwp_sql_result_free(rows);
    evidence_t* e = calloc(1, sizeof(*e)); assert(e); e->f = f;
    evidence(r, (*txn)->id, e); char hex[97]; hash_hex(e->hash, hex);
    const char* tables[] = {"operations", "orders"};
    for (size_t i = 0; i < 2u; ++i) {
        snprintf(text, sizeof(text), "INSERT INTO %s VALUES (%d, %d, %d, '%s', %" PRIu64 ", 0, 0" LABEL_VALUES,
            tables[i], r.op, r.product, r.quantity, hex, (*txn)->id);
        command(f, txn, text);
    }
    snprintf(text, sizeof(text), "INSERT INTO order_lines VALUES (%d, %d, %d" LABEL_VALUES,
        r.op, r.product, r.quantity); command(f, txn, text);
    snprintf(text, sizeof(text), "INSERT INTO outbox VALUES (%d, '%s', %" PRIu64
        ", 'ORDER_ACCEPTED_INTENT'" LABEL_VALUES, r.op, hex, (*txn)->id);
    command(f, txn, text);
    assert(qihse_uwp_sql_txn_enlist_durable(f->sql.txn_manager, *txn, SQL_ID) == 0);
    assert(qihse_txn_attach_participant_resource(f->sql.txn_manager, *txn,
        BLOB_ID, e, blob_rollback) == 0);
    return STAGED;
}

static uint64_t commit_order(fixture_t* f, request_t r) {
    qihse_txn_t* txn = NULL; assert(stage(f, r, &txn) == STAGED);
    uint64_t id = txn->id;
    assert(qihse_txn_prepare(f->sql.txn_manager, txn) == 0);
    assert(qihse_txn_commit_prepared(f->sql.txn_manager, txn) == 0);
    assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
    return id;
}

static bool count_blob(const qihse_blob_info_t* info, void* opaque) {
    assert(info->refcount == 1u); ++*(size_t*)opaque; return true;
}

/* Every materialized row uses an authenticated SELECT; no raw classified scan. */
static void verify(fixture_t* f, unsigned count) {
    assert(count <= 4u);
    qihse_uwp_sql_result_t* orders = query(f, f->user, NULL, "SELECT * FROM orders");
    qihse_uwp_sql_result_t* ledger = query(f, f->user, NULL, "SELECT * FROM operations");
    qihse_uwp_sql_result_t* lines = query(f, f->user, NULL, "SELECT * FROM order_lines");
    qihse_uwp_sql_result_t* events = query(f, f->user, NULL, "SELECT * FROM outbox");
    assert(orders->nrows == count && ledger->nrows == count &&
        lines->nrows == count && events->nrows == count);
    int64_t used[2] = {0};
    for (unsigned i = 0; i < count; ++i) {
        request_t r = accepted[i];
        size_t oi = count, li = count, ei = count, ri = count;
        unsigned on = 0, ln = 0, en = 0, rn = 0;
        for (unsigned j = 0; j < count; ++j) {
            if (number(&orders->rows[j][0]) == r.op) { oi = j; ++on; }
            if (number(&ledger->rows[j][0]) == r.op) { ri = j; ++rn; }
            if (number(&lines->rows[j][0]) == r.op) { li = j; ++ln; }
            if (number(&events->rows[j][0]) == r.op) { ei = j; ++en; }
        }
        assert(on == 1u && rn == 1u && ln == 1u && en == 1u);
        const qihse_col_value_t* row = orders->rows[oi];
        uint64_t id = (uint64_t)number(&row[4]); assert(id > 0);
        evidence_t e = {0}; evidence(r, id, &e); char hex[97]; hash_hex(e.hash, hex);
        const qihse_col_value_t* cohort[] = {row, ledger->rows[ri]};
        for (unsigned j = 0; j < 2u; ++j) {
            const qihse_col_value_t* c = cohort[j];
            assert(number(&c[1]) == r.product && number(&c[2]) == r.quantity &&
                !strcmp(string(&c[3]), hex) && (uint64_t)number(&c[4]) == id &&
                number(&c[5]) == 0 && number(&c[6]) == 0 && number(&c[7]) == 0 &&
                number(&c[8]) == HIGH_CLASS && number(&c[9]) == HIGH_SCI);
        }
        const qihse_col_value_t* line = lines->rows[li];
        assert(number(&line[1]) == r.product && number(&line[2]) == r.quantity &&
            number(&line[3]) == 0 && number(&line[4]) == HIGH_CLASS && number(&line[5]) == HIGH_SCI);
        const qihse_col_value_t* event = events->rows[ei];
        assert(!strcmp(string(&event[1]), hex) && (uint64_t)number(&event[2]) == id &&
            !strcmp(string(&event[3]), "ORDER_ACCEPTED_INTENT") && number(&event[4]) == 0 &&
            number(&event[5]) == HIGH_CLASS && number(&event[6]) == HIGH_SCI);
        qihse_blob_info_t info;
        assert(qihse_blob_info_user(f->blob, e.hash, &info, f->user));
        assert(!memcmp(info.hash, e.hash, 48) && info.size == e.length && info.refcount == 1u &&
            info.tenant_id == 0 && info.tag == QIHSE_BLOB_TAG_SCRIPT_SET &&
            info.classification == HIGH_CLASS && info.sci_compartment == HIGH_SCI);
        char bytes[512] = {0}; size_t got = 0;
        assert(qihse_blob_get_user(f->blob, e.hash, 0, (uint8_t*)bytes, sizeof(bytes), &got, f->user));
        assert(got == e.length && !memcmp(bytes, e.bytes, got) &&
            qihse_blob_verify_user(f->blob, e.hash, f->user));
        used[r.product - 1] += r.quantity;
    }
    qihse_uwp_sql_result_t* products = query(f, f->user, NULL, "SELECT * FROM products");
    assert(products->nrows == 2u); unsigned seen = 0;
    for (unsigned i = 0; i < 2u; ++i) {
        const qihse_col_value_t* p = products->rows[i]; int id = (int)number(&p[0]);
        assert(id == 1 || id == 2); assert(!(seen & (1u << id))); seen |= 1u << id;
        int64_t initial = id == 1 ? 10 : 9, remaining = number(&p[2]);
        assert(number(&p[1]) == initial && remaining >= 0 && initial == remaining + used[id - 1]);
        assert(number(&p[3]) == 0 && number(&p[4]) == HIGH_CLASS && number(&p[5]) == HIGH_SCI);
    }
    size_t blobs = 0; assert(qihse_blob_list_user(f->blob, f->user, count_blob, &blobs) && blobs == count);
    qihse_uwp_sql_result_free(products); qihse_uwp_sql_result_free(orders);
    qihse_uwp_sql_result_free(ledger); qihse_uwp_sql_result_free(lines); qihse_uwp_sql_result_free(events);
}

static void replay(fixture_t* f, uint64_t abort_id, unsigned count) {
    for (unsigned pass = 0; pass < 2u; ++pass) {
        assert(qihse_txn_manager_recover(f->sql.txn_manager) == 0);
        assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), abort_id, false));
        assert(qihse_blob_resolve_prepared(f->blob, abort_id, false));
        assert(!qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), abort_id, true));
        assert(!qihse_blob_resolve_prepared(f->blob, abort_id, true));
        qihse_uwp_sql_result_t* rows = query(f, f->user, NULL, "SELECT * FROM operations");
        for (size_t i = 0; i < rows->nrows; ++i) {
            uint64_t id = (uint64_t)number(&rows->rows[i][4]);
            assert(qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), id, true));
            assert(qihse_blob_resolve_prepared(f->blob, id, true));
            assert(!qihse_table_store_resolve_prepared(qihse_uwp_sql_table_store(), id, false));
            assert(!qihse_blob_resolve_prepared(f->blob, id, false));
        }
        qihse_uwp_sql_result_free(rows); verify(f, count);
    }
}

static const char* const order_tables[] = {
    "products", "operations", "orders", "order_lines", "outbox"
};

static void grant_sql_reads(fixture_t* f, qihse_user_t* reader) {
    assert(reader);
    for (unsigned i = 0; i < 5u; ++i) {
        uint32_t resource = 2166136261u;
        for (const unsigned char* p = (const unsigned char*)order_tables[i]; *p; ++p)
            resource = (resource ^ *p) * 16777619u;
        assert(qihse_auth_grant_object(f->user, reader, 0, resource, QIHSE_ACL_READ));
        assert(qihse_auth_can_access_object(reader, 0, resource, QIHSE_ACL_READ));
    }
}

static const char cohort_key[] = "protected/w11-order-cohort";
/* Immutable SOURCE snapshot provenance, not a live order counter or SQL/KV commit. */
static const char cohort_marker[] = "W11 orders=21,22,31 stock=7,4 SQL81/blob82";

static void verify_marker(fixture_t* f, qihse_user_t* user) {
    char* value = qihse_kv_get_user(f->kv, cohort_key, user);
    assert(value && !strcmp(value, cohort_marker)); free(value);
}

static void negative_auth_user(fixture_t* f, qihse_user_t* low) {
    grant_sql_reads(f, low);
    if (f->kv) assert(!qihse_kv_get_user(f->kv, cohort_key, low));
    for (unsigned i = 0; i < 5u; ++i) {
        char text[128]; snprintf(text, sizeof(text), "SELECT * FROM %s", order_tables[i]);
        qihse_uwp_sql_result_t* rows = NULL; qihse_txn_t* txn = NULL;
        int rc = qihse_uwp_sql_execute_typed_user(&f->sql, text, NULL, 0, &txn, low, &rows);
        assert(!txn && ((rc == UWP_STS_OK && rows && rows->nrows == 0) ||
            (rc == UWP_STS_ERR_PERM && !rows)));
        qihse_uwp_sql_result_free(rows);
    }
    qihse_uwp_sql_result_t* rows = query(f, f->user, NULL, "SELECT * FROM orders");
    assert(rows->nrows >= 2u && rows->nrows <= 4u);
    for (size_t i = 0; i < rows->nrows; ++i) {
        const qihse_col_value_t* row = rows->rows[i]; evidence_t e = {0};
        request_t r = {(int)number(&row[0]), (int)number(&row[1]), (int)number(&row[2])};
        evidence(r, (uint64_t)number(&row[4]), &e);
        qihse_blob_info_t info; assert(!qihse_blob_info_user(f->blob, e.hash, &info, low));
        uint8_t bytes[512]; memset(bytes, 0xa5, sizeof(bytes)); size_t got = 0;
        assert(!qihse_blob_get_user(f->blob, e.hash, 0, bytes, sizeof(bytes), &got, low) && got == 0);
        for (size_t j = 0; j < sizeof(bytes); ++j) assert(bytes[j] == 0xa5);
    }
    qihse_uwp_sql_result_free(rows);
    size_t count = 0; assert(qihse_blob_list_user(f->blob, low, count_blob, &count) && count == 0);
}

static void negative_auth(fixture_t* f) {
    qihse_user_t* reader = qihse_auth_create_user(f->user, 104, QIHSE_ROLE_ANALYST,
        HIGH_CLASS, HIGH_SCI, "OrderReaderSynthetic1!", false);
    grant_sql_reads(f, reader);
    if (f->kv) verify_marker(f, reader);
    for (unsigned i = 0; i < 5u; ++i) {
        char text[128]; snprintf(text, sizeof(text), "SELECT * FROM %s", order_tables[i]);
        qihse_uwp_sql_result_t* rows = query(f, reader, NULL, text);
        assert(rows->nrows >= 2u);
        qihse_uwp_sql_result_free(rows);
    }
    qihse_uwp_sql_result_t* rows = query(f, reader, NULL, "SELECT * FROM orders");
    assert(rows->nrows >= 2u && rows->nrows <= 4u);
    for (size_t i = 0; i < rows->nrows; ++i) {
        const qihse_col_value_t* row = rows->rows[i]; evidence_t e = {0};
        request_t r = {(int)number(&row[0]), (int)number(&row[1]), (int)number(&row[2])};
        evidence(r, (uint64_t)number(&row[4]), &e);
        uint8_t bytes[512]; size_t got = 0; qihse_blob_info_t info;
        assert(qihse_blob_get_user(f->blob, e.hash, 0, bytes, sizeof(bytes), &got, reader));
        assert(got == e.length && !memcmp(bytes, e.bytes, got));
        assert(qihse_blob_info_user(f->blob, e.hash, &info, reader) && info.refcount == 1u);
    }
    qihse_uwp_sql_result_free(rows);
    negative_auth_user(f, qihse_auth_create_user(f->user, 101, QIHSE_ROLE_ANALYST,
        0, 0, "OrderLowSynthetic1!", false));
    negative_auth_user(f, qihse_auth_create_user(f->user, 102, QIHSE_ROLE_ANALYST,
        0, HIGH_SCI, "OrderLowClassSynthetic1!", false));
    negative_auth_user(f, qihse_auth_create_user(f->user, 103, QIHSE_ROLE_ANALYST,
        HIGH_CLASS, 0, "OrderMissingSCISynthetic1!", false));
}

/* Real overlapping thread-owned native SQL shadows, synchronized so both see
 * the absent ledger entry and old stock before writer A commits. B's PREPARE
 * must reject its stale generation; there is no mock writer or replaced vote. */
typedef struct {
    fixture_t* f;
    pthread_barrier_t staged;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool committed;
    uint64_t ids[2];
} race_t;
typedef struct { race_t* race; unsigned slot; } writer_t;
static void* conflicting_writer(void* opaque) {
    writer_t* w = opaque; race_t* r = w->race; qihse_txn_t* txn = NULL;
    assert(stage(r->f, accepted[2], &txn) == STAGED); r->ids[w->slot] = txn->id;
    int rc = pthread_barrier_wait(&r->staged);
    assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    if (!w->slot) {
        assert(qihse_txn_prepare(r->f->sql.txn_manager, txn) == 0);
        assert(qihse_txn_commit_prepared(r->f->sql.txn_manager, txn) == 0);
        assert(pthread_mutex_lock(&r->mutex) == 0); r->committed = true;
        assert(pthread_cond_signal(&r->cond) == 0 && pthread_mutex_unlock(&r->mutex) == 0);
    } else {
        assert(pthread_mutex_lock(&r->mutex) == 0);
        while (!r->committed) assert(pthread_cond_wait(&r->cond, &r->mutex) == 0);
        assert(pthread_mutex_unlock(&r->mutex) == 0);
        assert(qihse_txn_prepare(r->f->sql.txn_manager, txn) != 0);
        assert(txn->state == QIHSE_TXN_ABORTED);
    }
    assert(qihse_txn_release(r->f->sql.txn_manager, txn) == 0);
    return NULL;
}
static void conflict(fixture_t* f) {
    race_t r = {.f = f}; pthread_t threads[2]; writer_t writers[2] = {{&r, 0}, {&r, 1}};
    assert(pthread_barrier_init(&r.staged, NULL, 2) == 0);
    assert(pthread_mutex_init(&r.mutex, NULL) == 0 && pthread_cond_init(&r.cond, NULL) == 0);
    for (unsigned i = 0; i < 2u; ++i) assert(pthread_create(&threads[i], NULL, conflicting_writer, &writers[i]) == 0);
    for (unsigned i = 0; i < 2u; ++i) assert(pthread_join(threads[i], NULL) == 0);
    assert(r.ids[0] != r.ids[1]);
    assert(pthread_barrier_destroy(&r.staged) == 0 && pthread_cond_destroy(&r.cond) == 0 &&
        pthread_mutex_destroy(&r.mutex) == 0);
    verify(f, 3);
}

#define COHORT_FILE_CAP (1024u * 1024u)
static uint8_t package_key[QIHSE_SHARED_BACKUP_KEY_BYTES];

/* Deterministic PRIVATE synthetic test key: authentication, NOT encryption. */
static void init_package_key(void) {
    for (size_t i = 0; i < sizeof(package_key); ++i)
        package_key[i] = (uint8_t)(0x53u + 11u * i);
}

static void absent(const char* path) {
    struct stat st; assert(lstat(path, &st) == -1 && errno == ENOENT);
}

static size_t load_file(const char* path, uint8_t* bytes, size_t capacity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
        (uint64_t)st.st_size < capacity);
    size_t at = 0;
    while (at < (size_t)st.st_size) {
        ssize_t n = read(fd, bytes + at, (size_t)st.st_size - at);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0); at += (size_t)n;
    }
    assert(close(fd) == 0); return at;
}

static void save_file(const char* path, const uint8_t* bytes, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(fd >= 0);
    while (length) {
        ssize_t n = write(fd, bytes, length);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0); bytes += n; length -= (size_t)n;
    }
    assert(fsync(fd) == 0 && close(fd) == 0);
}

static int64_t file_read(void* opaque, uint8_t* bytes, size_t capacity) {
    ssize_t n;
    do { n = read(*(int*)opaque, bytes, capacity); } while (n < 0 && errno == EINTR);
    return n;
}

typedef struct { uint8_t* bytes; size_t length; } archive_bytes_t;
static bool archive_write(void* opaque, const uint8_t* bytes, size_t length) {
    archive_bytes_t* a = opaque;
    assert(length <= COHORT_FILE_CAP - a->length);
    memcpy(a->bytes + a->length, bytes, length); a->length += length; return true;
}

static uint64_t decode_be(const uint8_t* bytes, size_t length) {
    uint64_t n = 0;
    for (size_t i = 0; i < length; ++i) n = (n << 8) | bytes[i];
    return n;
}

/* Inspect ONLY an authenticated native export: the original four terminal
 * receipts, plus the new COMMIT after progress, never a fabricated blob receipt
 * for the stale SQL vote. Byte equivalence applies ONLY before progress. */
static void verify_receipts(fixture_t* f, uint64_t abort_id, unsigned count,
    const char* package) {
    assert(count == 3u || count == 4u);
    archive_bytes_t a = {.bytes = malloc(COHORT_FILE_CAP)}; assert(a.bytes);
    assert(qihse_blob_archive_export_user(f->blob, f->user, package_key,
        sizeof(package_key), archive_write, &a));
    uint64_t ids[5] = {abort_id}; evidence_t expected[5] = {{0}};
    evidence(aborted, abort_id, &expected[0]);
    for (unsigned i = 0; i < count; ++i) {
        char text[128]; snprintf(text, sizeof(text), "SELECT * FROM orders WHERE op = %d", accepted[i].op);
        qihse_uwp_sql_result_t* rows = query(f, f->user, NULL, text);
        assert(rows->nrows == 1u); ids[i + 1u] = (uint64_t)number(&rows->rows[0][4]);
        evidence(accepted[i], ids[i + 1u], &expected[i + 1u]);
        qihse_uwp_sql_result_free(rows);
    }
    assert(a.length >= 80u && !memcmp(a.bytes, "QBLARCH1", 8u) &&
        decode_be(a.bytes + 8, 4) == 2u && decode_be(a.bytes + 12, 4) == 96u);
    size_t at = 16u; unsigned live = 0, receipts = 0, seen = 0;
    while (at + 8u <= a.length && decode_be(a.bytes + at, 8) != 0u) {
        assert(a.length - at >= 96u);
        const uint8_t* record = a.bytes + at;
        uint64_t type = decode_be(record, 8), size = decode_be(record + 64, 8);
        assert(decode_be(record + 8, 8) == live + receipts);
        if (type == 1u) {
            assert(!receipts && size <= a.length - at - 96u);
            at += 96u + (size_t)size; ++live;
        } else {
            assert(type == 2u && a.length - at >= 112u);
            uint64_t id = decode_be(record + 96, 8); unsigned slot = count + 1u;
            for (unsigned i = 0; i <= count; ++i) if (ids[i] == id) slot = i;
            assert(slot <= count && !(seen & (1u << slot)));
            assert(record[104] == (slot ? 'C' : 'A') &&
                !memcmp(record + 16, expected[slot].hash, 48u) && size == expected[slot].length &&
                decode_be(record + 72, 4) == 0u &&
                decode_be(record + 76, 2) == QIHSE_BLOB_TAG_SCRIPT_SET &&
                decode_be(record + 78, 2) == HIGH_CLASS && decode_be(record + 80, 2) == HIGH_SCI &&
                decode_be(record + 84, 4) == 1u);
            seen |= 1u << slot; ++receipts; at += 112u;
        }
    }
    assert(live == count && receipts == count + 1u && seen == (1u << (count + 1u)) - 1u &&
        a.length - at == 64u && decode_be(a.bytes + at, 8) == 0u &&
        decode_be(a.bytes + at + 8, 8) == 2u * count + 1u);
    if (package) {
        assert(count == 3u);
        char path[1024]; path_join(path, package, QIHSE_SHARED_BACKUP_BLOB_FILE);
        uint8_t* original = malloc(COHORT_FILE_CAP); assert(original);
        size_t length = load_file(path, original, COHORT_FILE_CAP);
        assert(length == a.length && !memcmp(original, a.bytes, length)); free(original);
    }
    free(a.bytes);
}

static void authenticate_package(fixture_t* f, const char* package,
    qihse_shared_backup_info_t* info, uint8_t manifest_hash[48]) {
    assert(qihse_shared_backup_verify_user(package, f->user, package_key, sizeof(package_key), info));
    assert(info->sql_engine_id == SQL_ID && info->blob_engine_id == BLOB_ID);
    char path[1024]; path_join(path, package, QIHSE_SHARED_BACKUP_MANIFEST_FILE);
    uint8_t* bytes = malloc(COHORT_FILE_CAP); assert(bytes);
    size_t length = load_file(path, bytes, COHORT_FILE_CAP); unsigned n = 0;
    assert(EVP_Digest(bytes, length, manifest_hash, &n, EVP_sha384(), NULL) == 1 && n == 48u);
    free(bytes);
}

static void check_restored(fixture_t* f, uint64_t abort_id, unsigned count,
    const char* package, uint64_t manifest_floor) {
    uint64_t sf = 0, bf = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sf));
    assert(qihse_blob_decision_next_id(f->blob, &bf));
    if (count == 4u) assert(sf > manifest_floor && bf > manifest_floor);
    qihse_txn_backup_checkpoint_t checkpoint;
    assert(qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &checkpoint) &&
        checkpoint.next_txn_id >= manifest_floor && checkpoint.next_txn_id >= sf &&
        checkpoint.next_txn_id >= bf);
    /* Exercise the allocator in this process, not just its checkpoint metadata. */
    qihse_txn_t* unused = qihse_txn_begin(f->sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
    assert(unused && unused->id >= manifest_floor && unused->id >= sf && unused->id >= bf);
    assert(qihse_txn_rollback(f->sql.txn_manager, unused) == 0 &&
        qihse_txn_release(f->sql.txn_manager, unused) == 0);
    replay(f, abort_id, count); verify_marker(f, f->user);
    for (unsigned i = 0; i < count; ++i) {
        qihse_txn_t* retry = NULL;
        assert(stage(f, accepted[i], &retry) == DUPLICATE && !retry); verify(f, count);
        request_t altered = accepted[i]; ++altered.quantity;
        assert(stage(f, altered, &retry) == MISMATCH && !retry); verify(f, count);
    }
    replay(f, abort_id, count); verify_marker(f, f->user);
    verify_receipts(f, abort_id, count, package);
}

static void export_cohort(fixture_t* f, const char* root, uint64_t abort_id) {
    init_package_key(); replay(f, abort_id, 3);
    /* Same retained source SQL/blob/coordinator, fresh application KV under the
     * already initialized PRIVATE auth directory. Never change the global root. */
    f->kv = qihse_kv_store_create_user(f->user); assert(f->kv);
    assert(qihse_kv_set_user(f->kv, cohort_key, cohort_marker, HIGH_CLASS, HIGH_SCI, f->user));
    verify_marker(f, f->user);
    qihse_txn_t* unused = qihse_txn_begin(f->sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
    assert(unused); uint64_t unused_id = unused->id;
    assert(qihse_txn_rollback(f->sql.txn_manager, unused) == 0 &&
        qihse_txn_release(f->sql.txn_manager, unused) == 0);
    uint64_t sf = 0, bf = 0;
    assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sf));
    assert(qihse_blob_decision_next_id(f->blob, &bf));
    assert(unused_id >= sf && unused_id >= bf);
    qihse_shared_backup_sources_t sources = {f->kv, qihse_uwp_sql_table_store(),
        f->blob, f->sql.txn_manager, SQL_ID, BLOB_ID};
    char package[1024]; path_join(package, root, "order-package"); absent(package);
    qihse_shared_backup_info_t info;
    assert(qihse_shared_backup_export_user(package, &sources, f->user, package_key,
        sizeof(package_key), &info) == QIHSE_SHARED_BACKUP_OK);
    assert(info.coordinator.next_txn_id == unused_id + 1u);
    uint8_t before[48], after[48]; authenticate_package(f, package, &info, before);
    verify_receipts(f, abort_id, 3, package);
    authenticate_package(f, package, &info, after); assert(!memcmp(before, after, 48u));
}

static bool fail_commit_sync;
static dev_t commit_index_dev;
static ino_t commit_index_ino;
static unsigned commit_sync_faults;

int fsync(int fd) {
    struct stat st;
    if (fail_commit_sync && fstat(fd, &st) == 0 &&
        st.st_dev == commit_index_dev && st.st_ino == commit_index_ino) {
        fail_commit_sync = false;
        ++commit_sync_faults; errno = EIO; return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

static __attribute__((noinline)) void commit_with_sync_retry(fixture_t* f,
    qihse_txn_t* txn, const char* root, bool crash_after_error) {
    char path[1024], candidate[1024];
    path_join(path, root, "evidence/index.log");
    struct stat index, journal;
    assert(stat(path, &index) == 0 && S_ISREG(index.st_mode));
    commit_index_dev = index.st_dev; commit_index_ino = index.st_ino;
    commit_sync_faults = 0; fail_commit_sync = true;
    assert(qihse_txn_commit_prepared(f->sql.txn_manager, txn) != 0 &&
        txn->state == QIHSE_TXN_COMMITTING && errno == EAGAIN);
    assert(!fail_commit_sync && commit_sync_faults == 1u);
    assert(!qihse_txn_is_committed(f->sql.txn_manager, txn->id));
    path_join(path, root, "common.qtj");
    assert(stat(path, &journal) == 0);
    assert(qihse_txn_abort_prepared(f->sql.txn_manager, txn) != 0 &&
        txn->state == QIHSE_TXN_COMMITTING);
    qihse_uwp_sql_result_t* rows = query(f, f->user, NULL, "SELECT * FROM orders WHERE op = 24");
    assert(rows->nrows == 1u && (uint64_t)number(&rows->rows[0][4]) == txn->id);
    qihse_uwp_sql_result_free(rows);
    rows = query(f, f->user, NULL, "SELECT * FROM outbox WHERE op = 24");
    assert(rows->nrows == 1u); qihse_uwp_sql_result_free(rows);
    evidence_t e = {0}; evidence(accepted[3], txn->id, &e);
    uint8_t bytes[512]; memset(bytes, 0xA5, sizeof(bytes)); size_t got = SIZE_MAX;
    assert(!qihse_blob_get_user(f->blob, e.hash, 0, bytes, sizeof(bytes), &got, f->user));
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0xA5);
    qihse_txn_backup_checkpoint_t checkpoint;
    assert(!qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &checkpoint));
    qihse_shared_backup_sources_t sources = {f->kv, qihse_uwp_sql_table_store(),
        f->blob, f->sql.txn_manager, SQL_ID, BLOB_ID};
    path_join(candidate, root, "retry-package"); absent(candidate);
    assert(qihse_shared_backup_export_user(candidate, &sources, f->user, package_key,
        sizeof(package_key), NULL) == QIHSE_SHARED_BACKUP_ERROR);
    absent(candidate);
    if (crash_after_error) {
        assert(commit_sync_faults == 1u && txn->state == QIHSE_TXN_COMMITTING &&
            !qihse_txn_is_committed(f->sql.txn_manager, txn->id));
        assert(!qihse_blob_info_user(f->blob, e.hash, &(qihse_blob_info_t){0}, f->user));
        assert(got == SIZE_MAX);
        fprintf(stderr, "ORDER blob COMMIT EIO returned EAGAIN: SQL/outbox visible, blob hidden; ABORT/checkpoint/export refused before SIGKILL\n");
        interrupt_now('I', txn->id);
    }
    assert(qihse_txn_commit_prepared(f->sql.txn_manager, txn) == 0 &&
        txn->state == QIHSE_TXN_COMMITTED &&
        qihse_txn_is_committed(f->sql.txn_manager, txn->id));
    assert(qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &checkpoint) &&
        checkpoint.journal_bytes == (uint64_t)journal.st_size);
    qihse_shared_backup_info_t info;
    assert(qihse_shared_backup_export_user(candidate, &sources, f->user, package_key,
        sizeof(package_key), &info) == QIHSE_SHARED_BACKUP_OK &&
        info.coordinator.next_txn_id > txn->id);
    assert(qihse_shared_backup_verify_user(candidate, f->user, package_key,
        sizeof(package_key), NULL));
    fprintf(stderr, "ORDER recoverable blob COMMIT EIO: publication incomplete, ABORT/backup fenced; same decision retry and fresh backup complete\n");
}

/* Privileged private-fixture inspection only; the parent witness is an expected
 * result, never an input to native recovery or a replacement engine decision. */
static __attribute__((noinline)) void inspect_io_pending(fixture_t* f,
    const char* root, uint64_t expected_id) {
    assert(qihse_auth_user_is_active(f->user));
    qihse_uwp_sql_result_t* rows = query(f, f->user, NULL, "SELECT * FROM orders");
    assert(rows->nrows == 4u); unsigned seen = 0;
    evidence_t e = {0}; evidence(accepted[3], expected_id, &e);
    char hex[97]; hash_hex(e.hash, hex);
    for (size_t i = 0; i < rows->nrows; ++i) {
        const qihse_col_value_t* row = rows->rows[i];
        if (number(&row[0]) != accepted[3].op) continue;
        ++seen;
        assert(number(&row[1]) == 2 && number(&row[2]) == 2 &&
            !strcmp(string(&row[3]), hex) && (uint64_t)number(&row[4]) == expected_id);
    }
    assert(seen == 1u); qihse_uwp_sql_result_free(rows);
    rows = query(f, f->user, NULL, "SELECT * FROM outbox WHERE op = 24");
    assert(rows->nrows == 1u && !strcmp(string(&rows->rows[0][1]), hex) &&
        (uint64_t)number(&rows->rows[0][2]) == expected_id);
    qihse_uwp_sql_result_free(rows);
    assert(!qihse_blob_info_user(f->blob, e.hash, &(qihse_blob_info_t){0}, f->user));
    uint8_t bytes[512]; memset(bytes, 0xa5, sizeof(bytes)); size_t got = SIZE_MAX;
    assert(!qihse_blob_get_user(f->blob, e.hash, 0, bytes, sizeof(bytes), &got, f->user) && got == SIZE_MAX);
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0xa5);
    size_t count = 0;
    assert(qihse_blob_list_user(f->blob, f->user, count_blob, &count) && count == 3u);
    /* Inspect the native pending T at EOF, not a simulated/rewritten receipt. */
    char path[1024]; path_join(path, root, "evidence/index.log");
    uint8_t* index = malloc(COHORT_FILE_CAP); assert(index);
    size_t length = load_file(path, index, COHORT_FILE_CAP);
    size_t record_size = 3u + sizeof(uint64_t) + sizeof(qihse_blob_info_t);
    assert(length >= record_size);
    const uint8_t* record = index + length - record_size;
    uint64_t id = 0; qihse_blob_info_t pending;
    memcpy(&id, record + 3u, sizeof(id));
    memcpy(&pending, record + 3u + sizeof(id), sizeof(pending));
    assert(record[2] == 'T' && id == expected_id &&
        !memcmp(pending.hash, e.hash, sizeof(e.hash)) && pending.size == e.length &&
        pending.refcount == 1u && pending.tenant_id == 0u &&
        pending.tag == QIHSE_BLOB_TAG_SCRIPT_SET && pending.classification == HIGH_CLASS &&
        pending.sci_compartment == HIGH_SCI);
    free(index);
    assert(!qihse_txn_is_committed(f->sql.txn_manager, expected_id));
    qihse_txn_backup_checkpoint_t checkpoint;
    assert(!qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &checkpoint));
    qihse_shared_backup_sources_t sources = {f->kv, qihse_uwp_sql_table_store(),
        f->blob, f->sql.txn_manager, SQL_ID, BLOB_ID};
    path_join(path, root, "restart-package"); absent(path);
    assert(qihse_shared_backup_export_user(path, &sources, f->user, package_key,
        sizeof(package_key), NULL) == QIHSE_SHARED_BACKUP_ERROR);
    absent(path);
    fprintf(stderr, "ORDER fresh io pre-recovery decision=%" PRIu64
        ": SQL4/outbox durable, blob invisible/native T pending, registry false\n", expected_id);
}

/* Fresh exec only. No source SQL/blob/KV handle is opened in any branch. */
static __attribute__((noinline)) int restored_phase(const char* mode, const char* source,
    uint64_t abort_id) {
    alarm(45u); init_package_key();
    bool io_clone = !strcmp(mode, "io-clone"), io_kill = !strcmp(mode, "io-kill");
    bool io_recover = !strcmp(mode, "io-recover"), io_reopen = !strcmp(mode, "io-reopen");
    bool io = io_clone || io_kill || io_recover || io_reopen;
    bool restore = !strcmp(mode, "restore") || io_clone;
    fixture_t* f = calloc(1, sizeof(*f)); assert(f);
    char root[1024], path[1024], target[1024], package[1024], working[1024];
    int n = snprintf(root, sizeof(root), "%s-restored%s", source, io ? "-io" : "");
    assert(n > 0 && (size_t)n < sizeof(root));
    if (restore) { absent(root); assert(mkdir(root, 0700) == 0); }
    path_join(path, root, "data");
    if (restore) assert(mkdir(path, 0700) == 0);
    init_auth(f, path); /* Exactly once, before any application handle exists. */
    path_join(package, source, "order-package");
    qihse_shared_backup_info_t info; uint8_t before[48], after[48];
    authenticate_package(f, package, &info, before);
    path_join(working, root, "restore-input");
    if (restore) {
        absent(working);
        assert(qihse_shared_backup_unpack_user(package, working, f->user,
            package_key, sizeof(package_key), NULL) == QIHSE_SHARED_BACKUP_OK);
        path_join(path, working, QIHSE_SHARED_BACKUP_SQL_FILE);
        path_join(target, root, "orders.qts"); absent(target);
        /* SQL creates input.lock: consume ONLY the working unpack. Native
         * restore also carries SQL terminal receipts into orders.qts sidecars. */
        assert(qihse_table_store_restore(f->user, path, target));
        path_join(path, working, QIHSE_SHARED_BACKUP_BLOB_FILE);
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
        path_join(target, root, "evidence"); absent(target);
        assert(qihse_blob_archive_restore_user(target, f->user, package_key,
            sizeof(package_key), file_read, &fd) == QIHSE_BLOB_ARCHIVE_OK);
        assert(close(fd) == 0);
    }
    f->kv = qihse_kv_store_create_user(f->user); assert(f->kv);
    if (restore) {
        path_join(path, working, QIHSE_SHARED_BACKUP_KV_FILE);
        assert(qihse_restore_user(f->kv, f->user, path) == QIHSE_BACKUP_EXPORT_OK);
        path_join(path, working, QIHSE_SHARED_BACKUP_JOURNAL_FILE);
        uint8_t* bytes = malloc(COHORT_FILE_CAP); assert(bytes);
        size_t length = load_file(path, bytes, COHORT_FILE_CAP);
        assert(length == info.coordinator.journal_bytes);
        path_join(target, root, "common.qtj"); save_file(target, bytes, length); free(bytes);
    }
    f->sql.sql_engine = &sql_placeholder;
    path_join(path, root, "orders.qts");
    assert(qihse_uwp_sql_open_durable(&f->sql, path) == 0 && f->sql.schema);
    path_join(path, root, "evidence"); f->blob = qihse_blob_store_create(path); assert(f->blob);
    path_join(path, root, "common.qtj");
    f->sql.txn_manager = qihse_txn_manager_create_durable(path); assert(f->sql.txn_manager);
    uint8_t* journal = NULL; size_t journal_length = 0;
    if (io && !io_kill) {
        journal = malloc(2u * COHORT_FILE_CAP); assert(journal);
        journal_length = load_file(path, journal, COHORT_FILE_CAP);
        if (io_clone) assert(journal_length == info.coordinator.journal_bytes);
        else assert(journal_length > info.coordinator.journal_bytes);
    }
    register_participants(f, info.coordinator.next_txn_id, !io_recover);
    witness_t parent = {0};
    if (io_recover || io_reopen) {
        uint8_t control[sizeof(parent) + 1u];
        path_join(path, root, "parent-witness");
        assert(load_file(path, control, sizeof(control)) == sizeof(parent));
        memcpy(&parent, control, sizeof(parent));
        assert(parent.boundary == 'I' && parent.id >= info.coordinator.next_txn_id);
    }
    if (io_recover) {
        /* No app exposure: inspect before any recovery callback; only the
         * durable common journal selects COMMIT and its participant IDs. */
        inspect_io_pending(f, root, parent.id);
        assert(qihse_txn_manager_recover(f->sql.txn_manager) == 0);
        assert(qihse_txn_is_committed(f->sql.txn_manager, parent.id));
    }
    if (io_recover || io_reopen) {
        /* Inspect native publication before check_restored's direct replay can
         * repair a missing participant COMMIT. These helpers only read/export. */
        assert(qihse_txn_is_committed(f->sql.txn_manager, parent.id));
        verify(f, 4); verify_receipts(f, abort_id, 4, NULL);
        uint64_t sf = 0, bf = 0;
        assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sf));
        assert(qihse_blob_decision_next_id(f->blob, &bf));
        assert(sf == parent.id + 1u && bf == parent.id + 1u);
    }
    /* No application queries/marker reads until bindings, max-floor and replay,
     * except the privileged io-recover/io-reopen inspections above. */
    if (io_clone || io_kill) {
        uint64_t sf = 0, bf = 0;
        assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sf));
        assert(qihse_blob_decision_next_id(f->blob, &bf));
        qihse_txn_backup_checkpoint_t checkpoint;
        assert(info.coordinator.next_txn_id > sf && info.coordinator.next_txn_id > bf &&
            qihse_txn_backup_checkpoint_user(f->sql.txn_manager, f->user, &checkpoint) &&
            checkpoint.next_txn_id == info.coordinator.next_txn_id);
        fprintf(stderr, "ORDER %s unused manifest-floor=%" PRIu64 " native-floors=%" PRIu64 "/%" PRIu64 "\n",
            mode, info.coordinator.next_txn_id, sf, bf);
        verify(f, 3); verify_marker(f, f->user); verify_receipts(f, abort_id, 3, package);
    }
    if ((!io && restore) || io_kill) {
        if (!io) check_restored(f, abort_id, 3, package, info.coordinator.next_txn_id);
        authenticate_package(f, package, &info, after); assert(!memcmp(before, after, 48u));
        uint64_t sf = 0, bf = 0;
        assert(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(), &sf));
        assert(qihse_blob_decision_next_id(f->blob, &bf));
        qihse_txn_t* txn = NULL; assert(stage(f, accepted[3], &txn) == STAGED);
        uint64_t id = txn->id;
        assert(id >= info.coordinator.next_txn_id && id >= sf && id >= bf);
        assert(qihse_txn_prepare(f->sql.txn_manager, txn) == 0 && txn->state == QIHSE_TXN_PREPARED);
        commit_with_sync_retry(f, txn, root, io_kill);
        assert(qihse_txn_release(f->sql.txn_manager, txn) == 0);
        fprintf(stderr, "ORDER restored progress op=24 product=2 quantity=2 decision=%" PRIu64
            " manifest-floor=%" PRIu64 " native-floors=%" PRIu64 "/%" PRIu64 "\n",
            id, info.coordinator.next_txn_id, sf, bf);
    }
    unsigned count = io_clone ? 3u : 4u;
    if (!io_clone) check_restored(f, abort_id, 4, NULL, info.coordinator.next_txn_id);
    if (io_recover || io_reopen) {
        qihse_uwp_sql_result_t* rows = query(f, f->user, NULL, "SELECT * FROM orders WHERE op = 24");
        assert(rows->nrows == 1u && (uint64_t)number(&rows->rows[0][4]) == parent.id &&
            qihse_txn_is_committed(f->sql.txn_manager, parent.id));
        qihse_uwp_sql_result_free(rows);
    }
    negative_auth(f); replay(f, abort_id, count); verify_marker(f, f->user);
    verify_receipts(f, abort_id, count, io_clone ? package : NULL);
    if (io_recover) {
        qihse_shared_backup_sources_t sources = {f->kv, qihse_uwp_sql_table_store(),
            f->blob, f->sql.txn_manager, SQL_ID, BLOB_ID};
        path_join(path, root, "restart-package"); absent(path);
        assert(qihse_shared_backup_export_user(path, &sources, f->user, package_key,
            sizeof(package_key), NULL) == QIHSE_SHARED_BACKUP_OK);
        assert(qihse_shared_backup_verify_user(path, f->user, package_key,
            sizeof(package_key), NULL));
    }
    close_fixture(f);
    if (journal) {
        path_join(path, root, "common.qtj");
        size_t length = load_file(path, journal + COHORT_FILE_CAP, COHORT_FILE_CAP);
        assert(length == journal_length && !memcmp(journal, journal + COHORT_FILE_CAP, length));
        fprintf(stderr, "ORDER %s terminal replay: coordinator %zu bytes unchanged\n", mode, length);
        free(journal);
    }
    authenticate_package(f, package, &info, after); assert(!memcmp(before, after, 48u));
    free(f); return 0;
}

static int phase(const char* mode, const char* root, uint64_t abort_id, int fd) {
    witness_fd = fd;
    if (!strcmp(mode, "restore") || !strcmp(mode, "restored-reopen") ||
        !strcmp(mode, "io-clone") || !strcmp(mode, "io-kill") ||
        !strcmp(mode, "io-recover") || !strcmp(mode, "io-reopen"))
        return restored_phase(mode, root, abort_id);
    alarm(45u); fixture_t f; bool initial = !strcmp(mode, "init");
    bool abort_reopen = !strcmp(mode, "abort-reopen"), commit_reopen = !strcmp(mode, "commit-reopen");
    open_fixture(&f, root, initial, !abort_reopen && !commit_reopen);
    if (initial) { initialize(&f); verify(&f, 0); }
    else if (!strcmp(mode, "kill-prepare") || !strcmp(mode, "kill-commit")) {
        bool before = !strcmp(mode, "kill-prepare");
        request_t req = before ? aborted : accepted[0]; qihse_txn_t* txn = NULL;
        assert(stage(&f, req, &txn) == STAGED);
        evidence_t e = {0}; evidence(req, txn->id, &e); memcpy(crash_hash, e.hash, 48);
        assert(qihse_txn_prepare(f.sql.txn_manager, txn) == 0 && txn->state == QIHSE_TXN_PREPARED);
        verify(&f, 0);
        if (before) interrupt_now('P', txn->id);
        kill_at_blob = true; crash_fixture = &f;
        (void)qihse_txn_commit_prepared(f.sql.txn_manager, txn);
        assert(!"blob callback crash boundary not reached");
    } else if (abort_reopen || commit_reopen) {
        /* Observe actual reopened source rows BEFORE manager recovery. */
        evidence_t e = {0}; evidence(abort_reopen ? aborted : accepted[0], abort_id, &e);
        assert(!qihse_blob_info_user(f.blob, e.hash, &(qihse_blob_info_t){0}, f.user));
        if (abort_reopen) verify(&f, 0);
        else {
            qihse_uwp_sql_result_t* rows = query(&f, f.user, NULL, "SELECT * FROM orders");
            assert(rows->nrows == 1u && number(&rows->rows[0][0]) == 21 &&
                (uint64_t)number(&rows->rows[0][4]) == abort_id);
            qihse_uwp_sql_result_free(rows);
        }
        assert(qihse_txn_manager_recover(f.sql.txn_manager) == 0);
        if (abort_reopen) {
            replay(&f, abort_id, 0);
            assert(!qihse_blob_info_user(f.blob, e.hash, &(qihse_blob_info_t){0}, f.user));
        } else verify(&f, 1);
    } else if (!strcmp(mode, "normal")) {
        verify(&f, 1); (void)commit_order(&f, accepted[1]); verify(&f, 2);
        qihse_txn_t* txn = NULL;
        for (unsigned i = 0; i < 2u; ++i) {
            assert(stage(&f, accepted[i], &txn) == DUPLICATE && !txn); verify(&f, 2);
            request_t changed = accepted[i]; ++changed.quantity;
            assert(stage(&f, changed, &txn) == MISMATCH && !txn); verify(&f, 2);
        }
        assert(stage(&f, (request_t){41, 1, 100}, &txn) == DECLINED && !txn); verify(&f, 2);
        replay(&f, abort_id, 2); negative_auth(&f); verify(&f, 2);
    } else if (!strcmp(mode, "final")) {
        replay(&f, abort_id, 2); qihse_txn_t* txn = NULL;
        for (unsigned i = 0; i < 2u; ++i) assert(stage(&f, accepted[i], &txn) == DUPLICATE && !txn);
        verify(&f, 2); negative_auth(&f);
    } else if (!strcmp(mode, "conflict")) {
        verify(&f, 2); conflict(&f);
        qihse_txn_t* txn = NULL;
        assert(stage(&f, accepted[2], &txn) == DUPLICATE && !txn);
        assert(stage(&f, (request_t){31, 2, 2}, &txn) == MISMATCH && !txn);
        verify(&f, 3);
        /* Regression: an early SQL vote failure must remain replayable even
         * though the later blob resource was never prepared. Do not fake a
         * blob ABORT receipt or suppress manager recovery errors here. */
        replay(&f, abort_id, 3);
    } else if (!strcmp(mode, "conflict-reopen")) {
        replay(&f, abort_id, 3);
        qihse_txn_t* retry = NULL;
        assert(stage(&f, accepted[2], &retry) == DUPLICATE && !retry);
        request_t altered = accepted[2]; ++altered.quantity;
        assert(stage(&f, altered, &retry) == MISMATCH && !retry);
        verify(&f, 3); negative_auth(&f);
    } else if (!strcmp(mode, "export")) {
        export_cohort(&f, root, abort_id);
    } else assert(!"unknown order recovery phase");
    close_fixture(&f); return 0;
}

static uint64_t run_phase(const char* executable, const char* mode, const char* root,
    uint64_t id, char boundary) {
    int pipefd[2]; assert(pipe2(pipefd, O_CLOEXEC) == 0);
    char id_text[32], fd_text[32];
    snprintf(id_text, sizeof(id_text), "%" PRIu64, id);
    snprintf(fd_text, sizeof(fd_text), "%d", pipefd[1]);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(pipefd[0]); assert(fcntl(pipefd[1], F_SETFD, 0) == 0);
        execl(executable, executable, mode, root, id_text, fd_text, (char*)NULL); _exit(127);
    }
    assert(close(pipefd[1]) == 0);
    struct pollfd p = {.fd = pipefd[0], .events = POLLIN};
    int rc; do { rc = poll(&p, 1, 60000); } while (rc < 0 && errno == EINTR);
    if (rc != 1) { kill(child, SIGKILL); assert(!"phase timed out"); }
    witness_t w = {0}; ssize_t n = read(pipefd[0], &w, sizeof(w));
    int status = 0; assert(waitpid(child, &status, 0) == child);
    if (boundary) {
        assert(n == (ssize_t)sizeof(w) && w.boundary == boundary && w.id > 0 &&
            WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        fprintf(stderr, "ORDER witnessed SIGKILL boundary=%c decision=%" PRIu64 "\n", boundary, w.id);
    } else {
        bool ok = n == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        fprintf(stderr, "ORDER phase %s: %s\n", mode, ok ? "PASS" : "FAILED (fixture preserved)");
        assert(ok);
    }
    char extra; assert(read(pipefd[0], &extra, 1) == 0 && close(pipefd[0]) == 0);
    return w.id;
}

int main(int argc, char** argv) {
    if (argc == 5) {
        char* end = NULL; uint64_t id = strtoull(argv[3], &end, 10); assert(end && !*end);
        long fd = strtol(argv[4], &end, 10); assert(end && !*end && fd >= 0 && fd <= INT_MAX);
        return phase(argv[1], argv[2], id, (int)fd);
    }
    assert(argc == 1); alarm(300u);
    char root[] = "build/w11-order-XXXXXX"; assert(mkdtemp(root));
    fprintf(stderr, "ORDER fixtures preserved: %s\n", root);
    run_phase(argv[0], "init", root, 0, 0);
    uint64_t aborted_id = run_phase(argv[0], "kill-prepare", root, 0, 'P');
    run_phase(argv[0], "abort-reopen", root, aborted_id, 0);
    uint64_t committed_id = run_phase(argv[0], "kill-commit", root, 0, 'C');
    assert(committed_id > aborted_id);
    run_phase(argv[0], "commit-reopen", root, committed_id, 0);
    run_phase(argv[0], "normal", root, aborted_id, 0);
    run_phase(argv[0], "final", root, aborted_id, 0);
    run_phase(argv[0], "conflict", root, aborted_id, 0);
    run_phase(argv[0], "conflict-reopen", root, aborted_id, 0);
    run_phase(argv[0], "export", root, aborted_id, 0);
    run_phase(argv[0], "restore", root, aborted_id, 0);
    run_phase(argv[0], "restored-reopen", root, aborted_id, 0);
    run_phase(argv[0], "io-clone", root, aborted_id, 0);
    uint64_t io_id = run_phase(argv[0], "io-kill", root, aborted_id, 'I');
    /* Parent-only private expected result: never used to choose a decision. */
    char control[1024];
    int n = snprintf(control, sizeof(control), "%s-restored-io/parent-witness", root);
    assert(n > 0 && (size_t)n < sizeof(control));
    witness_t parent = {0}; parent.id = io_id; parent.boundary = 'I';
    save_file(control, (const uint8_t*)&parent, sizeof(parent));
    run_phase(argv[0], "io-recover", root, aborted_id, 0);
    run_phase(argv[0], "io-reopen", root, aborted_id, 0);
    puts("PASS W11 ORDER SQL stock/orders/lines/ledger/EVENT INTENT + explicitly enlisted evidence 2PC;"
         " fresh-exec SIGKILL ABORT/COMMIT recovery, generation conflict, retries and authorization");
    puts("Full scale/fault acceptance: FALSE/OPEN; no external delivery/payment/KV ACID guarantee");
    return 0;
}
