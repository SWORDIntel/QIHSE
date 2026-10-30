/* Disposable authenticated TLS pgwire fixture linked to existing libqihse.so. */
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qihse_pg_wire.h"
#include "qihse_auth.h"
#include "qihse_schema.h"
#include "qihse_uwp_sql_txn_schema.h"

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
static void create_table(qihse_uwp_context_t *ctx, const char *ddl) {
    qihse_sql_ast_t *ast = qihse_parse_sql_to_ast(ddl);
    assert(ast && qihse_schema_create_table(ctx->schema, ast) == 0);
    qihse_sql_ast_free(ast);
}
int main(int argc, char **argv) {
    assert(argc == 5); /* private directory, certificate, key, password */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop);
    assert(setenv("QIHSE_DATA_DIR", argv[1], 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(argv[4]));
    qihse_user_t *op = qihse_auth_get_user(0);
    assert(op);
    assert(qihse_auth_create_user(op, 1, QIHSE_ROLE_OPERATOR, 0xffff, 0xffff, argv[4], false));
    assert(qihse_auth_create_user(op, 2, QIHSE_ROLE_GUEST, 0, 0, argv[4], false));
    qihse_uwp_context_t uwp = {0};
    static int engine;
    uwp.sql_engine = &engine;
    uwp.schema = qihse_schema_registry_create();
    uwp.txn_manager = qihse_txn_manager_create();
    assert(uwp.schema && uwp.txn_manager);
    create_table(&uwp, "CREATE TABLE protected_records (id INT, note TEXT, __qihse_tenant_id INT, __qihse_classification INT, __qihse_sci INT)");
    uint8_t *image = NULL;
    size_t length = 0;
    assert(qihse_schema_serialize(uwp.schema, &image, &length) == 0);
    char path[4096];
    assert(snprintf(path, sizeof(path), "%s/rows.snap", argv[1]) < (int)sizeof(path));
    qihse_table_store_t *store = qihse_table_store_open_durable(path);
    assert(store);
    qihse_schema_registry_t* empty = qihse_schema_registry_create();
    uint8_t* initial = NULL; size_t initial_length = 0;
    assert(empty && qihse_schema_serialize(empty, &initial, &initial_length) == 0);
    assert(qihse_table_store_set_schema_image(store, initial, initial_length));
    free(initial);
    qihse_schema_registry_destroy(empty);
    qihse_col_def_t protected[] = {{"id", QIHSE_TS_INT32}, {"note", QIHSE_TS_STRING}, {"__qihse_tenant_id", QIHSE_TS_INT32}, {"__qihse_classification", QIHSE_TS_INT32}, {"__qihse_sci", QIHSE_TS_INT32}};
    assert(qihse_table_store_create_table_with_schema(store, "protected_records",
                                                    protected, 5, image, length));
    free(image);
    qihse_table_t *table = qihse_table_store_find_table(store, "protected_records");
    assert(table);
    /* Keep synthetic protected rows independent of application-source
     * fixtures, and isolate the two denial boundaries for client assertions. */
    qihse_col_value_t row[] = {{.type=QIHSE_TS_INT32, .v.i32=7}, {.type=QIHSE_TS_STRING, .v.str="DIRECTEYE-HIGH-SECRET-MARKER"}, {.type=QIHSE_TS_INT32, .v.i32=0}, {.type=QIHSE_TS_INT32, .v.i32=3}, {.type=QIHSE_TS_INT32, .v.i32=1}};
    qihse_col_value_t cross_tenant[] = {{.type=QIHSE_TS_INT32, .v.i32=8}, {.type=QIHSE_TS_STRING, .v.str="DIRECTEYE-CROSS-TENANT-MARKER"}, {.type=QIHSE_TS_INT32, .v.i32=999}, {.type=QIHSE_TS_INT32, .v.i32=0}, {.type=QIHSE_TS_INT32, .v.i32=0}};
    qihse_table_txn_t *txn = qihse_table_txn_begin(table);
    assert(txn && qihse_table_txn_insert(txn, row, 5) >= 0);
    assert(qihse_table_txn_insert(txn, cross_tenant, 5) >= 0 && qihse_table_txn_commit(txn));
    qihse_table_store_destroy(store);
    assert(qihse_uwp_sql_open_durable(&uwp, path) == 0);
    assert(qihse_uwp_sql_durable_ready(&uwp));
    assert(!qihse_schema_get_table(uwp.schema, "osint_records"));
    assert(!qihse_schema_get_table(uwp.schema, "auth_events"));
    qihse_pg_wire_listener_t *listener = qihse_pg_wire_listener_open_tls_uwp(&uwp, NULL, "127.0.0.1", 0, argv[2], argv[3]);
    assert(listener);
    printf("PORT %u\n", qihse_pg_wire_listener_port(listener));
    fflush(stdout);
    while (!stopping) {
        int result = qihse_pg_wire_listener_accept_once(listener, 500);
        if (result < 0 && !stopping) return 2;
    }
    qihse_pg_wire_listener_close(listener);
    qihse_uwp_sql_close_durable(&uwp);
    qihse_txn_manager_destroy(uwp.txn_manager);
    qihse_schema_registry_destroy(uwp.schema);
    return 0;
}
