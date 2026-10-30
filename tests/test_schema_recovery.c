#include "qihse_schema.h"
#include "qihse_uwp_sql_txn_schema.h"
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static void test_crash_restart(void) {
    char dir[] = "./qihse-schema-recovery-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof(dir) + 16];
    char lock[sizeof(dir) + 24];
    snprintf(path, sizeof(path), "%s/rows", dir);
    snprintf(lock, sizeof(lock), "%s.lock", path);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        qihse_schema_registry_t* schema = qihse_schema_registry_create();
        assert(schema);
        qihse_sql_column_def_t col = {.name = "id", .type = QIHSE_TYPE_INT};
        qihse_sql_ast_t a = {.table_name = "one", .columns = &col, .num_columns = 1};
        assert(qihse_schema_create_table(schema, &a) == 0);
        a.table_name = "two";
        assert(qihse_schema_create_table(schema, &a) == 0);
        /* Disposable pre-provisioned fixture: runtime DDL is refused until
         * catalog/row creation can be committed atomically. */
        qihse_table_store_t* fixture = qihse_table_store_open_durable(path);
        assert(fixture);
        uint8_t *catalog = NULL, *initial = NULL;
        size_t catalog_len = 0, initial_len = 0;
        qihse_schema_registry_t* empty = qihse_schema_registry_create();
        assert(empty && qihse_schema_serialize(empty, &initial, &initial_len) == 0);
        qihse_schema_registry_destroy(empty);
        assert(qihse_table_store_set_schema_image(fixture, initial, initial_len));
        assert(qihse_schema_serialize(schema, &catalog, &catalog_len) == 0);
        qihse_col_def_t def = {.name = "id", .type = QIHSE_TS_INT32};
        qihse_ts_new_table_t tables[] = {
            {.name = "one", .cols = &def, .num_cols = 1},
            {.name = "two", .cols = &def, .num_cols = 1}
        };
        assert(qihse_table_store_create_tables_with_schema(fixture, tables, 2,
            initial, initial_len, catalog, catalog_len));
        free(initial);
        free(catalog);
        qihse_table_store_destroy(fixture);
        qihse_uwp_context_t ctx = {.schema = schema};
        assert(qihse_uwp_sql_open_durable(&ctx, path) == 0);
        qihse_table_store_t* store = qihse_uwp_sql_table_store();
        qihse_table_t* one = qihse_table_store_find_table(store, "one");
        qihse_table_t* two = qihse_table_store_find_table(store, "two");
        assert(one && two);
        qihse_table_txn_t* txns[2] = {
            qihse_table_txn_begin(one), qihse_table_txn_begin(two)
        };
        assert(txns[0] && txns[1]);
        qihse_col_value_t value = {.type = QIHSE_TS_INT32, .v.i32 = 42};
        assert(qihse_table_txn_insert(txns[0], &value, 1) >= 0);
        assert(qihse_table_txn_insert(txns[1], &value, 1) >= 0);
        assert(qihse_table_txn_commit_group(txns, 2));
        /* Simulate power loss: no SQL/store destructor runs. */
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    qihse_uwp_context_t ctx = {0};
    assert(qihse_uwp_sql_open_durable(&ctx, path) == 0);
    assert(ctx.schema && qihse_schema_get_table(ctx.schema, "one"));
    qihse_table_store_t* store = qihse_uwp_sql_table_store();
    assert(qihse_table_row_count(qihse_table_store_find_table(store, "one")) == 1);
    assert(qihse_table_row_count(qihse_table_store_find_table(store, "two")) == 1);
    assert(qihse_table_store_open_durable(path) == NULL);
    qihse_uwp_sql_close_durable(&ctx);
    qihse_schema_registry_destroy(ctx.schema);
    qihse_schema_registry_t* wrong = qihse_schema_registry_create();
    assert(wrong);
    ctx.schema = wrong;
    assert(qihse_uwp_sql_open_durable(&ctx, path) == -1);
    qihse_schema_registry_destroy(wrong);
    assert(unlink(path) == 0);
    assert(unlink(lock) == 0);
    assert(rmdir(dir) == 0);
}

static void test_atomic_create_fences(void) {
    char dir[] = "./qihse-ddl-fence-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof(dir) + 16], lock[sizeof(dir) + 24];
    assert(snprintf(path, sizeof(path), "%s/rows", dir) < (int)sizeof(path));
    assert(snprintf(lock, sizeof(lock), "%s.lock", path) < (int)sizeof(lock));
    qihse_schema_registry_t* empty = qihse_schema_registry_create();
    assert(empty);
    uint8_t *initial = NULL, *new_image = NULL;
    size_t initial_len = 0, new_len = 0;
    assert(qihse_schema_serialize(empty, &initial, &initial_len) == 0);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_set_schema_image(store, initial, initial_len));
    qihse_table_store_destroy(store);
    struct stat st;
    assert(stat(path, &st) == 0);
    qihse_sql_column_def_t col = {.name = "id", .type = QIHSE_TYPE_INT};
    qihse_sql_ast_t ast = {.table_name = "created", .columns = &col, .num_columns = 1};
    assert(qihse_schema_create_table(empty, &ast) == 0);
    assert(qihse_schema_serialize(empty, &new_image, &new_len) == 0);
    qihse_col_def_t def = {.name = "id", .type = QIHSE_TS_INT32};
    assert(new_len > initial_len);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        signal(SIGXFSZ, SIG_IGN);
        struct rlimit limit = {(rlim_t)st.st_size, (rlim_t)st.st_size};
        if (setrlimit(RLIMIT_FSIZE, &limit) != 0) _exit(1);
        qihse_table_store_t* child = qihse_table_store_open_durable(path);
        if (!child) _exit(2);
        bool committed = qihse_table_store_create_table_with_schema(child,
            "created", &def, 1, new_image, new_len);
        if (committed || qihse_table_store_table_count(child) != 0) _exit(3);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_table_count(store) == 0);
    const uint8_t* recovered = NULL;
    size_t recovered_len = 0;
    assert(qihse_table_store_schema_image(store, &recovered, &recovered_len));
    assert(recovered_len == initial_len && memcmp(recovered, initial, initial_len) == 0);
    qihse_table_store_destroy(store);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        qihse_table_store_t* child = qihse_table_store_open_durable(path);
        if (!child || !qihse_table_store_create_table_with_schema(child,
                "created", &def, 1, new_image, new_len)) _exit(1);
        _exit(0); /* process death immediately after durable acknowledgement */
    }
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_table_count(store) == 1);
    assert(qihse_table_store_schema_image(store, &recovered, &recovered_len));
    assert(recovered_len == new_len && memcmp(recovered, new_image, new_len) == 0);
    assert(qihse_table_store_find_table(store, "created"));
    qihse_table_store_destroy(store);
    free(initial); free(new_image);
    qihse_schema_registry_destroy(empty);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static void test_atomic_catalog_replace(void) {
    char dir[] = "./qihse-schema-replace-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof(dir) + 16], lock[sizeof(dir) + 24];
    assert(snprintf(path, sizeof(path), "%s/rows", dir) < (int)sizeof(path));
    assert(snprintf(lock, sizeof(lock), "%s.lock", path) < (int)sizeof(lock));
    qihse_schema_registry_t* schema = qihse_schema_registry_create();
    assert(schema);
    uint8_t *old_image = NULL, *new_image = NULL;
    size_t old_len = 0, new_len = 0;
    assert(qihse_schema_serialize(schema, &old_image, &old_len) == 0);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_set_schema_image(store, old_image, old_len));
    assert(qihse_schema_create_extension(schema, "uuid-ossp") == 0);
    assert(qihse_schema_serialize(schema, &new_image, &new_len) == 0);
    assert(qihse_table_store_replace_schema_image(store, old_image, old_len,
                                                   new_image, new_len));
    assert(!qihse_table_store_replace_schema_image(store, old_image, old_len,
                                                     old_image, old_len));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store);
    const uint8_t* recovered = NULL;
    size_t recovered_len = 0;
    assert(qihse_table_store_schema_image(store, &recovered, &recovered_len));
    assert(recovered_len == new_len && memcmp(recovered, new_image, new_len) == 0);
    qihse_table_store_destroy(store);
    qihse_schema_registry_destroy(schema);
    free(old_image); free(new_image);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static void test_materialized_view_column_ownership(void) {
    qihse_schema_registry_t* schema = qihse_schema_registry_create();
    assert(schema);
    char name[] = "metric", query[] = "SELECT 1 AS metric";
    char column_name[] = "metric";
    char check[] = "metric > 0", default_expr[] = "1";
    char generated[] = "metric + 1", referenced[] = "other";
    qihse_sql_fk_t fk = {.ref_table = referenced};
    qihse_schema_column_t cols[] = {
        {.name = "id", .type = QIHSE_TYPE_INT},
        {.name = column_name, .type = QIHSE_TYPE_NUMERIC, .type_len = 10,
         .type_scale = 2}
    };
    qihse_schema_column_t* c = &cols[1];
#define REJECT_VIEW_COLUMN(field, value) do { \
    c->field = (value); \
    assert(qihse_schema_create_materialized_view(schema, name, query, cols, 2) == -1); \
    assert(qihse_schema_table_count(schema) == 0); \
    c->field = 0; \
} while (0)
    REJECT_VIEW_COLUMN(check_expr, check);
    REJECT_VIEW_COLUMN(fk, &fk);
    REJECT_VIEW_COLUMN(default_expr, default_expr);
    REJECT_VIEW_COLUMN(generated_expr, generated);
    REJECT_VIEW_COLUMN(generated_stored, 1);
    REJECT_VIEW_COLUMN(is_serial, 1);
    REJECT_VIEW_COLUMN(is_primary_key, 1);
    REJECT_VIEW_COLUMN(is_unique, 1);
    REJECT_VIEW_COLUMN(not_null, 1);
#undef REJECT_VIEW_COLUMN
    c->name = cols[0].name;
    assert(qihse_schema_create_materialized_view(schema, name, query, cols, 2) == -1);
    assert(qihse_schema_table_count(schema) == 0);
    c->name = NULL;
    assert(qihse_schema_create_materialized_view(schema, name, query, cols, 2) == -1);
    assert(qihse_schema_table_count(schema) == 0);
    c->name = column_name;
    assert(qihse_schema_create_materialized_view(schema, name, query, cols, 2) == 0);
    strcpy(name, "alterd"); strcpy(query, "altered");
    strcpy(column_name, "other_");
    const qihse_schema_table_t* view = qihse_schema_get_table(schema, "metric");
    assert(view && strcmp(view->view_query, "SELECT 1 AS metric") == 0);
    assert(view->num_columns == 2 && strcmp(view->columns[1].name, "metric") == 0);
    assert(view->columns[1].type == QIHSE_TYPE_NUMERIC &&
           view->columns[1].type_len == 10 && view->columns[1].type_scale == 2);
    assert(!view->columns[1].check_expr && !view->columns[1].fk &&
           !view->columns[1].default_expr && !view->columns[1].generated_expr);
    uint8_t* image = NULL;
    size_t len = 0;
    assert(qihse_schema_serialize(schema, &image, &len) == 0);
    qihse_schema_registry_t* restored = NULL;
    assert(qihse_schema_deserialize(image, len, &restored) == 0);
    view = qihse_schema_get_table(restored, "metric");
    assert(view && strcmp(view->view_query, "SELECT 1 AS metric") == 0);
    assert(view->num_columns == 2 && strcmp(view->columns[1].name, "metric") == 0 &&
           view->columns[1].type_len == 10 && view->columns[1].type_scale == 2);
    qihse_schema_registry_destroy(restored);
    qihse_schema_registry_destroy(schema);
    free(image);
}

static void test_directeye_catalog_survives_reopen(void) {
    char dir[] = "./qihse-directeye-catalog-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof(dir) + 16], lock[sizeof(dir) + 24];
    assert(snprintf(path, sizeof(path), "%s/rows", dir) < (int)sizeof(path));
    assert(snprintf(lock, sizeof(lock), "%s.lock", path) < (int)sizeof(lock));
    qihse_schema_registry_t* schema = qihse_schema_registry_create();
    assert(schema);
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "CREATE TABLE osint_records (id UUID DEFAULT gen_random_uuid() PRIMARY KEY, "
        "source VARCHAR(50) NOT NULL, data JSONB NOT NULL, "
        "updated_at TIMESTAMPTZ DEFAULT NOW(), search_vector TSVECTOR "
        "GENERATED ALWAYS AS (to_tsvector('english', "
        "COALESCE(data->>'email', '') || ' ' || COALESCE(data->>'name', '') || "
        "' ' || COALESCE(data->>'username', ''))) STORED)");
    assert(ast && qihse_schema_create_table(schema, ast) == 0);
    qihse_sql_ast_free(ast);
    ast = qihse_parse_sql_to_ast(
        "CREATE INDEX IF NOT EXISTS idx_osint_source ON osint_records(source)");
    assert(ast && qihse_schema_create_index(schema, ast) == 0);
    qihse_sql_ast_free(ast);
    qihse_sql_column_def_t cost = {.name = "cost", .type = QIHSE_TYPE_NUMERIC,
                                   .type_len = 10, .type_scale = 4, .not_null = 1};
    qihse_sql_ast_t costs = {.table_name = "leakosint_queries", .columns = &cost,
                             .num_columns = 1};
    assert(qihse_schema_create_table(schema, &costs) == 0);
    qihse_sql_function_def_t function = {.name = "update_updated_at_column",
        .returns = "TRIGGER", .language = "plpgsql",
        .body = "BEGIN NEW.updated_at = NOW(); RETURN NEW; END;"};
    assert(qihse_schema_create_function(schema, &function) == 0);
    qihse_sql_trigger_def_t trigger = {.name = "update_osint_records_updated_at",
        .table_name = "osint_records", .timing = "BEFORE", .event = "UPDATE",
        .function_name = "update_updated_at_column", .for_each_row = 1};
    assert(qihse_schema_create_trigger(schema, &trigger) == 0);
    qihse_schema_column_t view_columns[] = {
        {.name = "source", .type = QIHSE_TYPE_VARCHAR, .type_len = 50},
        {.name = "record_count", .type = QIHSE_TYPE_BIGINT}
    };
    const char* view_query = "SELECT source, COUNT(*) AS record_count "
                             "FROM osint_records GROUP BY source";
    assert(qihse_schema_create_materialized_view(schema, "osint_stats",
        view_query, view_columns, 2) == 0);
    uint8_t* image = NULL;
    size_t len = 0;
    assert(qihse_schema_serialize(schema, &image, &len) == 0);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store);
    qihse_col_def_t osint_cols[] = {
        {.name = "id", .type = QIHSE_TS_UUID},
        {.name = "source", .type = QIHSE_TS_STRING},
        {.name = "data", .type = QIHSE_TS_JSONB},
        {.name = "updated_at", .type = QIHSE_TS_TIMESTAMPTZ},
        {.name = "search_vector", .type = QIHSE_TS_TSVECTOR}
    };
    qihse_col_def_t cost_col = {.name = "cost", .type = QIHSE_TS_NUMERIC};
    qihse_col_def_t stats_cols[] = {
        {.name = "source", .type = QIHSE_TS_STRING},
        {.name = "record_count", .type = QIHSE_TS_INT64}
    };
    uint8_t* initial = NULL;
    size_t initial_len = 0;
    qihse_schema_registry_t* empty = qihse_schema_registry_create();
    assert(empty && qihse_schema_serialize(empty, &initial, &initial_len) == 0);
    qihse_schema_registry_destroy(empty);
    assert(qihse_table_store_set_schema_image(store, initial, initial_len));
    qihse_ts_new_table_t tables[] = {
        {.name = "osint_records", .cols = osint_cols, .num_cols = 5},
        {.name = "leakosint_queries", .cols = &cost_col, .num_cols = 1},
        {.name = "osint_stats", .cols = stats_cols, .num_cols = 2}
    };
    assert(qihse_table_store_create_tables_with_schema(store, tables, 3,
        initial, initial_len, image, len));
    free(initial);
    qihse_table_store_destroy(store);
    free(image);
    qihse_schema_registry_destroy(schema);
    store = qihse_table_store_open_durable(path);
    assert(store);
    const uint8_t* saved = NULL;
    size_t saved_len = 0;
    assert(qihse_table_store_schema_image(store, &saved, &saved_len));
    assert(qihse_schema_deserialize(saved, saved_len, &schema) == 0);
    const qihse_schema_table_t* osint = qihse_schema_get_table(schema, "osint_records");
    assert(osint && osint->num_columns == 5 && osint->num_triggers == 1);
    assert(strcmp(osint->columns[0].default_expr, "gen_random_uuid()") == 0);
    assert(osint->columns[4].generated_stored && osint->columns[4].generated_expr);
    assert(strstr(osint->columns[4].generated_expr, "data->>'email'") != NULL);
    assert(strcmp(osint->triggers[0].function_name, function.name) == 0);
    assert(qihse_schema_get_index(schema, "idx_osint_source"));
    const qihse_schema_table_t* numeric = qihse_schema_get_table(schema, "leakosint_queries");
    assert(numeric && numeric->columns[0].type == QIHSE_TYPE_NUMERIC &&
           numeric->columns[0].type_len == 10 && numeric->columns[0].type_scale == 4);
    const qihse_schema_table_t* view = qihse_schema_get_table(schema, "osint_stats");
    assert(view && view->view_query && strcmp(view->view_query, view_query) == 0);
    assert(qihse_schema_get_function(schema, function.name));
    qihse_schema_registry_destroy(schema);
    qihse_table_store_destroy(store);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

int main(void) {
    test_materialized_view_column_ownership();
    test_directeye_catalog_survives_reopen();
    test_atomic_catalog_replace();
    test_crash_restart();
    test_atomic_create_fences();
    static const uint8_t empty_v1[] = {
        'Q','S','C','1', 1,0,0,0, 0,0,0,0, 0x30,0xc6,0x2d,0x10
    };
    qihse_schema_registry_t* legacy = NULL;
    assert(qihse_schema_deserialize(empty_v1, sizeof(empty_v1), &legacy) == 0);
    assert(legacy && !qihse_schema_has_extension(legacy, "uuid-ossp"));
    qihse_schema_registry_destroy(legacy);
    qihse_schema_registry_t* reg = qihse_schema_registry_create();
    assert(reg);
    qihse_sql_column_def_t constrained = { .name = "id", .type = QIHSE_TYPE_INT,
        .is_primary_key = 1 };
    qihse_sql_ast_t constrained_table = { .table_name = "supported_pk",
        .columns = &constrained, .num_columns = 1 };
    assert(qihse_schema_create_table(reg, &constrained_table) == 0);
    qihse_sql_column_def_t cols[] = {
        { .name = "id", .type = QIHSE_TYPE_INT },
        { .name = "parent_id", .type = QIHSE_TYPE_INT, .default_expr = "0",
          .not_null = 1, .is_unique = 1 }
    };
    qihse_sql_ast_t ast = { .table_name = "child", .columns = cols, .num_columns = 2 };
    assert(qihse_schema_create_table(reg, &ast) == 0);
    qihse_sql_column_def_t nullable_unique = {
        .name = "bad_unique", .type = QIHSE_TYPE_INT, .is_unique = 1 };
    qihse_sql_ast_t bad_unique_table = { .table_name = "bad_unique",
        .columns = &nullable_unique, .num_columns = 1 };
    assert(qihse_schema_create_table(reg, &bad_unique_table) == -1);
    qihse_sql_column_def_t composite_pk[] = {
        { .name = "a", .type = QIHSE_TYPE_INT, .is_primary_key = 1 },
        { .name = "b", .type = QIHSE_TYPE_INT, .is_primary_key = 1 }
    };
    qihse_sql_ast_t bad_pk_table = { .table_name = "bad_pk",
        .columns = composite_pk, .num_columns = 2 };
    assert(qihse_schema_create_table(reg, &bad_pk_table) == -1);
    qihse_sql_index_def_t index = { .name = "child_parent_idx", .table_name = "child",
        .column_name = "parent_id" };
    qihse_sql_ast_t index_ast = { .index_def = &index };
    assert(qihse_schema_create_index(reg, &index_ast) == 0);
    qihse_sql_index_def_t unique_index = { .name = "unique_idx", .table_name = "child",
        .column_name = "parent_id", .unique = 1 };
    index_ast.index_def = &unique_index;
    assert(qihse_schema_create_index(reg, &index_ast) == -1);
    qihse_sql_index_def_t unsupported_index = { .name = "expr_idx", .table_name = "child" };
    index_ast.index_def = &unsupported_index;
    assert(qihse_schema_create_index(reg, &index_ast) == -1);
    qihse_sql_column_def_t typed_cols[] = {
        {.name="uuid_value", .type=QIHSE_TYPE_UUID},
        {.name="json_value", .type=QIHSE_TYPE_JSONB},
        {.name="flag", .type=QIHSE_TYPE_BOOL},
        {.name="created_at", .type=QIHSE_TYPE_TIMESTAMPTZ}
    };
    qihse_sql_ast_t typed_ast = {.table_name="typed_values",
        .columns=typed_cols, .num_columns=4};
    assert(qihse_schema_create_table(reg, &typed_ast) == 0);
    assert(qihse_schema_create_extension(reg, "UUID-OSSP") == 0);
    assert(qihse_schema_create_extension(reg, "uuid-ossp") == 0);
    assert(qihse_schema_create_extension(reg, "unimplemented") == -1);
    assert(qihse_schema_has_extension(reg, "uuid-ossp"));
    uint8_t* image = NULL; size_t len = 0;
    assert(qihse_schema_serialize(reg, &image, &len) == 0);
    qihse_schema_registry_t* restored = NULL;
    assert(qihse_schema_deserialize(image, len, &restored) == 0);
    assert(qihse_schema_has_extension(restored, "uuid-ossp"));
    const qihse_schema_table_t* t = qihse_schema_get_table(restored, "CHILD");
    assert(t && t->num_columns == 2 && t->num_fks == 0 && t->num_checks == 0 && t->num_uniques == 0);
    assert(t->columns[1].not_null && t->columns[1].is_unique);
    const qihse_schema_table_t* typed = qihse_schema_get_table(restored, "typed_values");
    assert(typed && typed->num_columns == 4);
    assert(typed->columns[0].type == QIHSE_TYPE_UUID &&
           typed->columns[1].type == QIHSE_TYPE_JSONB &&
           typed->columns[2].type == QIHSE_TYPE_BOOL &&
           typed->columns[3].type == QIHSE_TYPE_TIMESTAMPTZ);
    const qihse_schema_table_t* pk = qihse_schema_get_table(restored, "supported_pk");
    assert(pk && pk->num_columns == 1 && pk->columns[0].is_primary_key);
    assert(t->num_indexes == 1 && strcmp(t->indexes[0].column_name, "parent_id") == 0);
    assert(qihse_schema_has_index(restored, "child", "parent_id"));
    uint8_t* copy = NULL; size_t copy_len = 0;
    assert(qihse_schema_serialize(restored, &copy, &copy_len) == 0);
    assert(len == copy_len && memcmp(image, copy, len) == 0);
    free(copy); qihse_schema_registry_destroy(restored); restored = NULL;
    assert(qihse_schema_deserialize(image, len - 1, &restored) == -1 && !restored);
    image[4] = 5; assert(qihse_schema_deserialize(image, len, &restored) == -1 && !restored);
    image[4] = 4; image[len - 5] ^= 0x20;
    assert(qihse_schema_deserialize(image, len, &restored) == -1 && !restored);
    free(image); qihse_schema_registry_destroy(reg); return 0;
}
