#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_schema.h"
#include "qihse_txn.h"
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char data[4096];
    size_t len;
} reply_buf_t;

static ssize_t capture_reply(void* opaque, const void* data, size_t len) {
    reply_buf_t* reply = opaque;
    if (len > sizeof(reply->data) - 1u - reply->len) return -1;
    memcpy(reply->data + reply->len, data, len);
    reply->len += len;
    reply->data[reply->len] = '\0';
    return (ssize_t)len;
}

static uwp_sts_result_t execute_sql(qihse_uwp_context_t* ctx,
                                   qihse_user_t* user,
                                   qihse_txn_t** txn,
                                   const char* sql,
                                   reply_buf_t* reply) {
    memset(reply, 0, sizeof(*reply));
    return uwp_dispatch_sql(ctx, 0x02, (const uint8_t*)sql, strlen(sql) + 1u,
                            txn, user, -1, capture_reply, reply);
}

static uint64_t table_resource_id(const char* name) {
    uint32_t hash = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p) {
        hash ^= *p;
        hash *= 16777619u;
    }
    return (uint64_t)hash;
}

static void expect_ok(qihse_uwp_context_t* ctx, qihse_user_t* user,
                      qihse_txn_t** txn, const char* sql, const char* expected) {
    reply_buf_t reply;
    uwp_sts_result_t status = execute_sql(ctx, user, txn, sql, &reply);
    if (status != UWP_STS_OK || !strstr(reply.data, expected)) {
        fprintf(stderr, "SQL failed: %s\nstatus=%d reply=%s\n", sql,
                (int)status, reply.data);
        abort();
    }
}

static void expect_denied_without_marker(qihse_uwp_context_t* ctx,
                                         qihse_user_t* low_user,
                                         const char* marker) {
    reply_buf_t reply;
    qihse_txn_t* no_txn = NULL;
    const char* sql =
        "SELECT sku, available FROM inventory_restricted WHERE sku = 'SECRET-LOT'";
    uwp_sts_result_t status = execute_sql(ctx, low_user, &no_txn, sql, &reply);
    if (status != UWP_STS_ERR_PERM || !strstr(reply.data, "ERR_PERM") ||
        strstr(reply.data, marker) != NULL) {
        fprintf(stderr, "protected inventory denial failed: status=%d reply=%s\n",
                (int)status, reply.data);
        abort();
    }
    puts("PASS low-clearance ACL denial: protected inventory marker was not disclosed");
}

int main(void) {
    if (!qihse_auth_init()) {
        fputs("authentication initialization failed\n", stderr);
        return 1;
    }
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    if (!operator_user) {
        fputs("system Operator principal is unavailable\n", stderr);
        return 1;
    }

    qihse_uwp_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    static int sql_engine_anchor;
    ctx.sql_engine = &sql_engine_anchor;
    ctx.schema = qihse_schema_registry_create();
    ctx.txn_manager = qihse_txn_manager_create();
    if (!ctx.schema || !ctx.txn_manager) {
        fputs("SQL context allocation failed\n", stderr);
        return 1;
    }

    qihse_txn_t* no_txn = NULL;
    expect_ok(&ctx, operator_user, &no_txn,
              "CREATE TABLE inventory_stock (sku TEXT, available INT)", "OK");
    expect_ok(&ctx, operator_user, &no_txn,
              "CREATE TABLE inventory_orders (order_id INT, sku TEXT, quantity INT)",
              "OK");
    expect_ok(&ctx, operator_user, &no_txn,
              "CREATE TABLE inventory_outbox (event_id TEXT, payload TEXT)", "OK");
    expect_ok(&ctx, operator_user, &no_txn,
              "CREATE TABLE inventory_restricted (sku TEXT, available INT)", "OK");
    expect_ok(&ctx, operator_user, &no_txn,
              "INSERT INTO inventory_stock VALUES ('SKU-001', 5)", "rows=1");
    expect_ok(&ctx, operator_user, &no_txn,
              "INSERT INTO inventory_restricted VALUES ('SECRET-LOT', 73)", "rows=1");

    /* Reserve one unit with compare-and-set semantics. The stock decrement,
     * order row and outbox intent are staged in one SQL transaction. */
    qihse_txn_t* txn = NULL;
    expect_ok(&ctx, operator_user, &txn, "BEGIN SERIALIZABLE", "OK");
    expect_ok(&ctx, operator_user, &txn,
              "UPDATE inventory_stock SET available = 4 WHERE sku = 'SKU-001' AND available = 5",
              "rows=1");
    expect_ok(&ctx, operator_user, &txn,
              "INSERT INTO inventory_orders VALUES (9001, 'SKU-001', 1)", "rows=1");
    expect_ok(&ctx, operator_user, &txn,
              "INSERT INTO inventory_outbox VALUES ('RES-9001', 'reservation-created')",
              "rows=1");
    expect_ok(&ctx, operator_user, &txn, "COMMIT", "COMMIT");
    if (txn != NULL) {
        fputs("transaction handle remained active after COMMIT\n", stderr);
        return 1;
    }

    expect_ok(&ctx, operator_user, &no_txn,
              "SELECT sku, available FROM inventory_stock WHERE sku = 'SKU-001'",
              "SKU-001\t4");
    expect_ok(&ctx, operator_user, &no_txn,
              "SELECT order_id, quantity FROM inventory_orders WHERE order_id = 9001",
              "9001\t1");
    expect_ok(&ctx, operator_user, &no_txn,
              "SELECT event_id FROM inventory_outbox WHERE event_id = 'RES-9001'",
              "RES-9001");
    puts("PASS reservation: stock, order, and outbox intent committed together");

    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 8801u, QIHSE_ROLE_GUEST, 0u, 0u,
        "inventory-guest-example-password", false);
    if (!guest || qihse_user_get_classification(guest) != 0u ||
        !qihse_auth_grant_object(operator_user, guest, 0u,
                                 table_resource_id("inventory_stock"),
                                 QIHSE_ACL_READ)) {
        fputs("guest setup or public stock READ grant failed\n", stderr);
        return 1;
    }
    expect_ok(&ctx, guest, &no_txn,
              "SELECT sku, available FROM inventory_stock WHERE sku = 'SKU-001'",
              "SKU-001\t4");
    const char* protected_marker = "SECRET-LOT";
    expect_denied_without_marker(&ctx, guest, protected_marker);

    qihse_txn_manager_destroy((qihse_txn_manager_t*)ctx.txn_manager);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)ctx.schema);
    puts("W11 inventory reservation example passed");
    return 0;
}
