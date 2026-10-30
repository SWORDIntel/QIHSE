#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* the build also passes -D_GNU_SOURCE; guard the redefinition */
#endif
/*
 * QIHSE Schema Registry — Phase 1 Relational Completeness
 *
 * Versioned catalog definitions are persisted in the same fenced snapshot
 * generation as their corresponding row relations.
 */
#include "qihse_schema.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static bool ieq(const char* a, const char* b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

struct qihse_schema_registry {
    qihse_schema_table_t* tables;
    size_t num_tables;
    size_t cap;
    char** extensions;
    size_t num_extensions;
    qihse_sql_function_def_t* functions;
    size_t num_functions;
};

static void free_names(char** names, size_t n) {
    if (!names) return;
    for (size_t i = 0; i < n; i++) free(names[i]);
    free(names);
}

static void free_fk(qihse_sql_fk_t* fk) {
    if (!fk) return;
    free_names(fk->columns, fk->num_columns);
    free(fk->ref_table);
    free_names(fk->ref_columns, fk->num_ref_columns);
}

static int copy_names(char*** dst, char** src, size_t n) {
    if (n > 256 || (n && !src)) return -1;
    *dst = (char**)calloc(n ? n : 1, sizeof(char*));
    if (!*dst) return -1;
    for (size_t i = 0; i < n; i++) {
        if (!src[i] || !((*dst)[i] = strdup(src[i]))) return -1;
    }
    return 0;
}

static int copy_fk(qihse_sql_fk_t* dst, const qihse_sql_fk_t* src) {
    dst->num_columns = src->num_columns;
    dst->num_ref_columns = src->num_ref_columns;
    dst->on_delete = src->on_delete;
    dst->on_update = src->on_update;
    if (!src->ref_table || !(dst->ref_table = strdup(src->ref_table)) ||
        copy_names(&dst->columns, src->columns, src->num_columns) ||
        copy_names(&dst->ref_columns, src->ref_columns, src->num_ref_columns)) return -1;
    return 0;
}

qihse_schema_registry_t* qihse_schema_registry_create(void) {
    qihse_schema_registry_t* reg = (qihse_schema_registry_t*)calloc(1, sizeof(*reg));
    if (!reg) return NULL;
    reg->cap = 16;
    reg->tables = (qihse_schema_table_t*)calloc(reg->cap, sizeof(qihse_schema_table_t));
    if (!reg->tables) { free(reg); return NULL; }
    return reg;
}

static void free_trigger(qihse_sql_trigger_def_t* tr) {
    free(tr->name); free(tr->table_name); free(tr->timing);
    free(tr->event); free(tr->function_name);
}

static void free_function(qihse_sql_function_def_t* fn) {
    free(fn->name); free(fn->returns); free(fn->language); free(fn->body);
}

static void free_table(qihse_schema_table_t* t) {
    free(t->name);
    free(t->view_query);
    for (size_t i = 0; i < t->num_triggers; ++i) free_trigger(&t->triggers[i]);
    free(t->triggers);
    for (size_t i = 0; i < t->num_columns; i++) {
        free(t->columns[i].name);
        free(t->columns[i].default_expr);
        free(t->columns[i].generated_expr);
        free(t->columns[i].check_expr);
        if (t->columns[i].fk) { free_fk(t->columns[i].fk); free(t->columns[i].fk); }
    }
    free(t->columns);
    for (size_t i = 0; i < t->num_indexes; i++) {
        free(t->indexes[i].name);
        free(t->indexes[i].table_name);
        free(t->indexes[i].column_name);
        free_names(t->indexes[i].expressions, t->indexes[i].num_expressions);
        free(t->indexes[i].descending);
        free(t->indexes[i].using_method);
    }
    free(t->indexes);
    for (size_t i = 0; i < t->num_fks; i++) free_fk(&t->fks[i]);
    free(t->fks);
    for (size_t i = 0; i < t->num_checks; i++) {
        free(t->checks[i].name); free(t->checks[i].expr);
    }
    free(t->checks);
    for (size_t i = 0; i < t->num_uniques; i++) {
        free(t->uniques[i].name);
        free_names(t->uniques[i].columns, t->uniques[i].num_columns);
    }
    free(t->uniques);
}

void qihse_schema_registry_destroy(qihse_schema_registry_t* reg) {
    if (!reg) return;
    for (size_t i = 0; i < reg->num_tables; i++) free_table(&reg->tables[i]);
    free(reg->tables);
    free_names(reg->extensions, reg->num_extensions);
    for (size_t i = 0; i < reg->num_functions; ++i) free_function(&reg->functions[i]);
    free(reg->functions);
    free(reg);
}

int qihse_schema_create_extension(qihse_schema_registry_t* reg, const char* name) {
    if (!reg || !name || !ieq(name, "uuid-ossp") || reg->num_extensions >= 16)
        return -1;
    if (qihse_schema_has_extension(reg, name)) return 0;
    char* copy = strdup("uuid-ossp");
    if (!copy) return -1;
    char** grown = realloc(reg->extensions,
        (reg->num_extensions + 1) * sizeof(*grown));
    if (!grown) { free(copy); return -1; }
    reg->extensions = grown;
    reg->extensions[reg->num_extensions++] = copy;
    return 0;
}

bool qihse_schema_has_extension(const qihse_schema_registry_t* reg, const char* name) {
    if (!reg || !name) return false;
    for (size_t i = 0; i < reg->num_extensions; ++i)
        if (ieq(reg->extensions[i], name)) return true;
    return false;
}

static qihse_schema_table_t* find_table(qihse_schema_registry_t* reg, const char* name);

static bool supported_trigger_body(const char* body) {
    static const char expected[] = "beginnew.updated_at=now();returnnew;end;";
    char normalized[sizeof expected];
    size_t n = 0;
    for (const unsigned char* p = (const unsigned char*)body; *p; ++p) {
        if (isspace(*p)) continue;
        if (n >= sizeof expected - 1) return false;
        normalized[n++] = (char)tolower(*p);
    }
    normalized[n] = 0;
    return strcmp(normalized, expected) == 0;
}

const qihse_sql_function_def_t* qihse_schema_get_function(
    const qihse_schema_registry_t* reg, const char* name) {
    if (!reg || !name) return NULL;
    for (size_t i = 0; i < reg->num_functions; ++i)
        if (ieq(reg->functions[i].name, name)) return &reg->functions[i];
    return NULL;
}

int qihse_schema_create_function(qihse_schema_registry_t* reg,
                                 const qihse_sql_function_def_t* def) {
    if (!reg || !def || !def->name || !*def->name || !def->returns ||
        !def->language || !def->body || !*def->body || reg->num_functions >= 256)
        return -1;
    /* No PL/pgSQL runtime exists. Only this exact, executable row transform is
     * representable; arbitrary function definitions must be refused. */
    if (!ieq(def->name, "update_updated_at_column") ||
        !ieq(def->returns, "TRIGGER") || !ieq(def->language, "plpgsql") ||
        !supported_trigger_body(def->body)) return -1;
    qihse_sql_function_def_t fn = {0};
    fn.name = strdup(def->name); fn.returns = strdup(def->returns);
    fn.language = strdup(def->language); fn.body = strdup(def->body);
    if (!fn.name || !fn.returns || !fn.language || !fn.body) {
        free_function(&fn); return -1;
    }
    for (size_t i = 0; i < reg->num_functions; ++i)
        if (ieq(reg->functions[i].name, def->name)) {
            if (!def->or_replace) { free_function(&fn); return -1; }
            free_function(&reg->functions[i]); reg->functions[i] = fn;
            return 0;
        }
    qihse_sql_function_def_t* grown = realloc(reg->functions,
        (reg->num_functions + 1) * sizeof(*grown));
    if (!grown) { free_function(&fn); return -1; }
    reg->functions = grown; reg->functions[reg->num_functions++] = fn;
    return 0;
}

int qihse_schema_create_trigger(qihse_schema_registry_t* reg,
                                const qihse_sql_trigger_def_t* def) {
    if (!reg || !def || !def->name || !*def->name || !def->table_name ||
        !def->timing || !def->event || !def->function_name ||
        !ieq(def->timing, "BEFORE") || !ieq(def->event, "UPDATE") ||
        !def->for_each_row || !qihse_schema_get_function(reg, def->function_name)) return -1;
    qihse_schema_table_t* table = find_table(reg, def->table_name);
    if (!table || table->view_query || table->num_triggers >= 256 ||
        !ieq(def->function_name, "update_updated_at_column")) return -1;
    bool target_column = false;
    for (size_t i = 0; i < table->num_columns; ++i)
        if (ieq(table->columns[i].name, "updated_at") &&
            table->columns[i].type == QIHSE_TYPE_TIMESTAMPTZ)
            target_column = true;
    if (!target_column) return -1;
    for (size_t i = 0; i < table->num_triggers; ++i)
        if (ieq(table->triggers[i].name, def->name)) return -1;
    qihse_sql_trigger_def_t trigger = {0};
    trigger.name = strdup(def->name); trigger.table_name = strdup(def->table_name);
    trigger.timing = strdup(def->timing); trigger.event = strdup(def->event);
    trigger.function_name = strdup(def->function_name); trigger.for_each_row = 1;
    if (!trigger.name || !trigger.table_name || !trigger.timing ||
        !trigger.event || !trigger.function_name) { free_trigger(&trigger); return -1; }
    qihse_sql_trigger_def_t* grown = realloc(table->triggers,
        (table->num_triggers + 1) * sizeof(*grown));
    if (!grown) { free_trigger(&trigger); return -1; }
    table->triggers = grown; table->triggers[table->num_triggers++] = trigger;
    return 0;
}

int qihse_schema_drop_trigger(qihse_schema_registry_t* reg,
                              const char* table_name, const char* name) {
    if (!reg || !table_name || !name) return -1;
    qihse_schema_table_t* table = find_table(reg, table_name);
    if (!table) return -1;
    for (size_t i = 0; i < table->num_triggers; ++i)
        if (ieq(table->triggers[i].name, name)) {
            free_trigger(&table->triggers[i]);
            memmove(&table->triggers[i], &table->triggers[i + 1],
                    (table->num_triggers - i - 1) * sizeof(*table->triggers));
            --table->num_triggers; return 0;
        }
    return -1;
}

int qihse_schema_create_materialized_view(qihse_schema_registry_t* reg,
    const char* name, const char* query, const qihse_schema_column_t* columns,
    size_t num_columns) {
    if (!reg || !name || !*name || !query || !*query || !columns ||
        !num_columns || num_columns > 256 || reg->num_tables >= 256 ||
        find_table(reg, name)) return -1;
    for (size_t i = 0; i < num_columns; ++i) {
        const qihse_schema_column_t* c = &columns[i];
        if (!c->name || !*c->name || c->type <= QIHSE_TYPE_UNKNOWN ||
            c->type > QIHSE_TYPE_TSVECTOR || c->default_expr ||
            c->generated_expr || c->generated_stored || c->fk || c->check_expr ||
            c->is_serial || c->is_primary_key || c->is_unique || c->not_null)
            return -1;
        for (size_t j = 0; j < i; ++j)
            if (ieq(columns[j].name, c->name)) return -1;
    }
    qihse_schema_table_t table = {0};
    table.name = strdup(name); table.view_query = strdup(query);
    table.columns = calloc(num_columns, sizeof(*table.columns));
    if (!table.name || !table.view_query || !table.columns) goto fail;
    for (size_t i = 0; i < num_columns; ++i) {
        table.columns[i].name = strdup(columns[i].name);
        if (!table.columns[i].name) goto fail;
        table.columns[i].type = columns[i].type;
        table.columns[i].type_len = columns[i].type_len;
        table.columns[i].type_scale = columns[i].type_scale;
        ++table.num_columns;
    }
    if (reg->num_tables == reg->cap) {
        qihse_schema_table_t* grown = realloc(reg->tables, reg->cap * 2 * sizeof(*grown));
        if (!grown) goto fail;
        reg->tables = grown; reg->cap *= 2;
    }
    reg->tables[reg->num_tables++] = table;
    return 0;
fail:
    free_table(&table); return -1;
}

void qihse_schema_registry_replace(qihse_schema_registry_t* reg,
                                   qihse_schema_registry_t* staged) {
    if (!reg || !staged || reg == staged) return;
    qihse_schema_registry_t old = *reg;
    *reg = *staged;
    *staged = old;
}

static qihse_schema_table_t* find_table(qihse_schema_registry_t* reg, const char* name) {
    for (size_t i = 0; i < reg->num_tables; i++) {
        if (ieq(reg->tables[i].name, name)) return &reg->tables[i];
    }
    return NULL;
}

static const qihse_schema_table_t* find_table_c(const qihse_schema_registry_t* reg, const char* name) {
    for (size_t i = 0; i < reg->num_tables; i++) {
        if (ieq(reg->tables[i].name, name)) return &reg->tables[i];
    }
    return NULL;
}

static int copy_column(qihse_schema_column_t* dst, const qihse_sql_column_def_t* src) {
    dst->name = src->name ? strdup(src->name) : NULL;
    dst->type = src->type;
    dst->type_len = src->type_len;
    dst->type_scale = src->type_scale;
    dst->generated_stored = src->generated_stored;
    dst->generated_expr = src->generated_expr ? strdup(src->generated_expr) : NULL;
    dst->not_null = src->not_null;
    dst->is_primary_key = src->is_primary_key;
    dst->is_unique = src->is_unique;
    dst->is_serial = src->is_serial;
    dst->default_expr = src->default_expr ? strdup(src->default_expr) : NULL;
    dst->check_expr = src->check_expr ? strdup(src->check_expr) : NULL;
    if (src->fk) {
        dst->fk = (qihse_sql_fk_t*)calloc(1, sizeof(*dst->fk));
        if (!dst->fk || copy_fk(dst->fk, src->fk)) return -1;
    }
    return (!dst->name || (src->default_expr && !dst->default_expr) ||
            (src->check_expr && !dst->check_expr) ||
            (src->generated_expr && !dst->generated_expr)) ? -1 : 0;
}

int qihse_schema_create_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast) {
    if (!reg || !ast || !ast->table_name || !*ast->table_name ||
        reg->num_tables >= 256 || ast->num_columns > 256 || ast->num_fks > 256 || ast->num_checks > 256 ||
        ast->num_uniques > 256 || (ast->num_columns && !ast->columns) ||
        (ast->num_fks && !ast->fks) || (ast->num_checks && !ast->checks) ||
        (ast->num_uniques && !ast->uniques) || ast->num_fks || ast->num_checks ||
        find_table(reg, ast->table_name)) return -1;
    /* Primary keys and single-column UNIQUE constraints are enforced by the
     * durable row transaction path. Foreign keys, CHECK expressions and
     * table-level/composite UNIQUE constraints remain fail-closed. */
    size_t primary_keys = 0;
    for (size_t i = 0; i < ast->num_columns; i++) {
        const qihse_sql_column_def_t* column = &ast->columns[i];
        if (column->fk || column->check_expr || column->type <= QIHSE_TYPE_UNKNOWN ||
            column->type > QIHSE_TYPE_TSVECTOR ||
            (!!column->generated_expr != !!column->generated_stored) ||
            (column->is_unique && !column->not_null && !column->is_primary_key))
            return -1;
        if (column->is_primary_key && ++primary_keys > 1) return -1;
        for (size_t j = 0; j < i; ++j)
            if (ieq(ast->columns[j].name, column->name)) return -1;
    }
    for (size_t i = 0; i < ast->num_uniques; ++i) {
        const qihse_sql_unique_t* key = &ast->uniques[i];
        if (!key->columns || key->num_columns != 1 || !key->columns[0]) return -1;
        size_t c = 0;
        while (c < ast->num_columns &&
               !ieq(ast->columns[c].name, key->columns[0])) ++c;
        if (c == ast->num_columns ||
            (!ast->columns[c].is_primary_key && !ast->columns[c].not_null))
            return -1;
    }
    qihse_schema_table_t tmp = {0};
    tmp.name = strdup(ast->table_name);
    tmp.num_columns = ast->num_columns;
    tmp.num_fks = ast->num_fks;
    tmp.num_checks = ast->num_checks;
    tmp.num_uniques = ast->num_uniques;
    tmp.columns = (qihse_schema_column_t*)calloc(ast->num_columns ? ast->num_columns : 1, sizeof(*tmp.columns));
    tmp.fks = (qihse_sql_fk_t*)calloc(ast->num_fks ? ast->num_fks : 1, sizeof(*tmp.fks));
    tmp.checks = (qihse_sql_check_t*)calloc(ast->num_checks ? ast->num_checks : 1, sizeof(*tmp.checks));
    tmp.uniques = (qihse_sql_unique_t*)calloc(ast->num_uniques ? ast->num_uniques : 1, sizeof(*tmp.uniques));
    if (!tmp.name || !tmp.columns || !tmp.fks || !tmp.checks || !tmp.uniques) goto fail;
    for (size_t i = 0; i < tmp.num_columns; i++)
        if (copy_column(&tmp.columns[i], &ast->columns[i])) goto fail;
    for (size_t i = 0; i < tmp.num_fks; i++)
        if (copy_fk(&tmp.fks[i], &ast->fks[i])) goto fail;
    for (size_t i = 0; i < tmp.num_checks; i++) {
        tmp.checks[i].expr = ast->checks[i].expr ? strdup(ast->checks[i].expr) : NULL;
        tmp.checks[i].name = ast->checks[i].name ? strdup(ast->checks[i].name) : NULL;
        if (!tmp.checks[i].expr || (ast->checks[i].name && !tmp.checks[i].name)) goto fail;
    }
    for (size_t i = 0; i < tmp.num_uniques; i++) {
        tmp.uniques[i].num_columns = ast->uniques[i].num_columns;
        tmp.uniques[i].name = ast->uniques[i].name ? strdup(ast->uniques[i].name) : NULL;
        if ((ast->uniques[i].name && !tmp.uniques[i].name) ||
            copy_names(&tmp.uniques[i].columns, ast->uniques[i].columns,
                       tmp.uniques[i].num_columns)) goto fail;
    }
    if (reg->num_tables >= reg->cap) {
        size_t cap = reg->cap * 2;
        qihse_schema_table_t* p = (qihse_schema_table_t*)realloc(reg->tables, cap * sizeof(*p));
        if (!p) goto fail;
        reg->tables = p;
        reg->cap = cap;
    }
    reg->tables[reg->num_tables++] = tmp;
    return 0;
fail:
    free_table(&tmp);
    return -1;
}

int qihse_schema_drop_table(qihse_schema_registry_t* reg, const char* name) {
    if (!reg || !name) return -1;
    for (size_t i = 0; i < reg->num_tables; i++) {
        if (ieq(reg->tables[i].name, name)) {
            free_table(&reg->tables[i]);
            memmove(&reg->tables[i], &reg->tables[i+1], (reg->num_tables - i - 1) * sizeof(qihse_schema_table_t));
            reg->num_tables--;
            return 0;
        }
    }
    return -1;
}

int qihse_schema_create_index(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast) {
    if (!reg || !ast || !ast->index_def || !ast->index_def->name ||
        !ast->index_def->table_name || qihse_schema_get_index(reg, ast->index_def->name)) return -1;
    qihse_schema_table_t* t = find_table(reg, ast->index_def->table_name);
    const qihse_sql_index_def_t* def = ast->index_def;
    char* legacy_key[1] = { def->column_name };
    size_t keys = def->num_expressions ? def->num_expressions : (def->column_name ? 1 : 0);
    char** expressions = def->num_expressions ? def->expressions : legacy_key;
    if (!t || t->num_indexes >= 256 || !def->name[0] ||
        !def->table_name[0] || def->unique ||
        !keys || keys > 16 || !expressions ||
        (def->using_method && !ieq(def->using_method, "gin") &&
         !ieq(def->using_method, "btree"))) return -1;
    /* Key grammar and access method support are validated by the executor
     * before committing this metadata and its backing relation generation. */
    qihse_schema_index_t idx = {0};
    idx.name = strdup(ast->index_def->name);
    idx.table_name = strdup(ast->index_def->table_name);
    idx.column_name = ast->index_def->column_name ? strdup(ast->index_def->column_name) : NULL;
    idx.unique = !!def->unique;
    idx.num_expressions = keys;
    idx.if_not_exists = !!def->if_not_exists;
    idx.using_method = def->using_method ? strdup(def->using_method) : NULL;
    if (!idx.name || !idx.table_name || (def->column_name && !idx.column_name) ||
        (def->using_method && !idx.using_method) ||
        copy_names(&idx.expressions, expressions, idx.num_expressions)) goto index_fail;
    idx.descending = calloc(idx.num_expressions, sizeof(*idx.descending));
    if (!idx.descending) goto index_fail;
    for (size_t i = 0; i < idx.num_expressions; ++i)
        idx.descending[i] = def->descending && !!def->descending[i];
    qihse_schema_index_t* p = (qihse_schema_index_t*)realloc(t->indexes,
        (t->num_indexes + 1) * sizeof(*p));
    if (!p) goto index_fail;
    t->indexes = p;
    t->indexes[t->num_indexes++] = idx;
    return 0;
index_fail:
    free(idx.name); free(idx.table_name); free(idx.column_name);
    free_names(idx.expressions, idx.num_expressions);
    free(idx.descending); free(idx.using_method);
    return -1;
}

int qihse_schema_drop_index(qihse_schema_registry_t* reg, const char* name) {
    if (!reg || !name) return -1;
    for (size_t i = 0; i < reg->num_tables; i++) {
        qihse_schema_table_t* t = &reg->tables[i];
        for (size_t j = 0; j < t->num_indexes; j++) {
            if (ieq(t->indexes[j].name, name)) {
                free(t->indexes[j].name);
                free(t->indexes[j].table_name);
                free(t->indexes[j].column_name);
                free_names(t->indexes[j].expressions, t->indexes[j].num_expressions);
                free(t->indexes[j].descending);
                free(t->indexes[j].using_method);
                memmove(&t->indexes[j], &t->indexes[j+1], (t->num_indexes - j - 1) * sizeof(qihse_schema_index_t));
                t->num_indexes--;
                return 0;
            }
        }
    }
    return -1;
}

int qihse_schema_alter_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast) {
    if (!reg || !ast || !ast->table_name || !ast->alter_clause) return -1;
    qihse_schema_table_t* t = find_table(reg, ast->table_name);
    if (!t) return -1;
    qihse_sql_alter_clause_t* ac = ast->alter_clause;
    switch (ac->action) {
        case QIHSE_ALTER_ADD_COLUMN: {
            if (!ac->add_column || t->num_columns >= 256) return -1;
            /* Grow by one column every time.  The table struct does not
             * record an allocated capacity, so the previous
             * "num_columns % 8 == 0" test reallocated only when the count
             * happened to be a multiple of 8 and otherwise appended past the
             * end of the array (heap overflow).  Reallocating to exactly
             * num_columns + 1 is always safe. */
            qihse_schema_column_t* grown = (qihse_schema_column_t*)realloc(
                t->columns, (t->num_columns + 1) * sizeof(qihse_schema_column_t));
            if (!grown) return -1;
            t->columns = grown;
            qihse_schema_column_t* c = &t->columns[t->num_columns];
            memset(c, 0, sizeof(*c));
            if (copy_column(c, ac->add_column)) {
                t->num_columns++;
                free(c->name); free(c->default_expr); free(c->generated_expr); free(c->check_expr);
                if (c->fk) { free_fk(c->fk); free(c->fk); }
                t->num_columns--;
                return -1;
            }
            t->num_columns++;
            return 0;
        }
        case QIHSE_ALTER_DROP_COLUMN: {
            if (!ac->column_name) return -1;
            for (size_t i = 0; i < t->num_columns; i++) {
                if (ieq(t->columns[i].name, ac->column_name)) {
                    free(t->columns[i].name);
                    free(t->columns[i].default_expr);
                    free(t->columns[i].generated_expr);
                    free(t->columns[i].check_expr);
                    if (t->columns[i].fk) { free_fk(t->columns[i].fk); free(t->columns[i].fk); }
                    memmove(&t->columns[i], &t->columns[i+1], (t->num_columns - i - 1) * sizeof(qihse_schema_column_t));
                    t->num_columns--;
                    return 0;
                }
            }
            return -1;
        }
        case QIHSE_ALTER_RENAME_TABLE: {
            if (!ac->new_name) return -1;
            if (find_table(reg, ac->new_name)) return -1;
            char* renamed = strdup(ac->new_name);
            if (!renamed) return -1;
            char** index_names = (char**)calloc(t->num_indexes ? t->num_indexes : 1, sizeof(char*));
            if (!index_names) { free(renamed); return -1; }
            for (size_t i = 0; i < t->num_indexes; i++) {
                index_names[i] = strdup(ac->new_name);
                if (!index_names[i]) {
                    free_names(index_names, t->num_indexes);
                    free(renamed);
                    return -1;
                }
            }
            for (size_t i = 0; i < t->num_indexes; i++) {
                free(t->indexes[i].table_name);
                t->indexes[i].table_name = index_names[i];
            }
            free(index_names);
            free(t->name);
            t->name = renamed;
            return 0;
        }
        case QIHSE_ALTER_RENAME_COLUMN: {
            if (!ac->column_name || !ac->new_name) return -1;
            for (size_t i = 0; i < t->num_columns; i++) {
                if (ieq(t->columns[i].name, ac->column_name)) {
                    free(t->columns[i].name);
                    t->columns[i].name = strdup(ac->new_name);
                    return 0;
                }
            }
            return -1;
        }
        default:
            return -1;
    }
}

const qihse_schema_table_t* qihse_schema_get_table(const qihse_schema_registry_t* reg, const char* name) {
    return find_table_c(reg, name);
}

const qihse_schema_index_t* qihse_schema_get_index(const qihse_schema_registry_t* reg, const char* name) {
    if (!reg || !name) return NULL;
    for (size_t i = 0; i < reg->num_tables; i++) {
        for (size_t j = 0; j < reg->tables[i].num_indexes; j++) {
            if (ieq(reg->tables[i].indexes[j].name, name)) return &reg->tables[i].indexes[j];
        }
    }
    return NULL;
}

size_t qihse_schema_table_count(const qihse_schema_registry_t* reg) {
    return reg ? reg->num_tables : 0;
}

const qihse_schema_table_t* qihse_schema_table_at(const qihse_schema_registry_t* reg, size_t idx) {
    if (!reg || idx >= reg->num_tables) return NULL;
    return &reg->tables[idx];
}

/* Format v1: QSC1, LE version/count, length-prefixed strings (0xffffffff=null),
 * tables/columns/indexes/constraints in catalog order, FNV-1a checksum. */
typedef struct {
    uint8_t* data;
    size_t pos, len;
    int bad, read;
    uint32_t version;
} schema_io_t;

static uint32_t io32(schema_io_t* io, uint32_t v) {
    if (io->bad || io->pos > io->len || io->len - io->pos < 4) { io->bad = 1; return 0; }
    if (io->read) {
        v = 0;
        for (unsigned i = 0; i < 4; i++) v |= (uint32_t)io->data[io->pos + i] << (8 * i);
    } else for (unsigned i = 0; i < 4; i++) io->data[io->pos + i] = (uint8_t)(v >> (8 * i));
    io->pos += 4;
    return v;
}

static void io_string(schema_io_t* io, char** s) {
    uint32_t n = 0xffffffffu;
    if (!io->read && *s) {
        size_t size = strnlen(*s, 4097);
        if (size > 4096 || memchr(*s, 0, size)) { io->bad = 1; return; }
        n = (uint32_t)size;
    }
    n = io32(io, n);
    if (io->bad || n == 0xffffffffu) { if (io->read) *s = NULL; return; }
    if (n > 4096 || io->pos > io->len || io->len - io->pos < n) { io->bad = 1; return; }
    if (io->read) {
        if (memchr(io->data + io->pos, 0, n)) { io->bad = 1; return; }
        *s = (char*)malloc((size_t)n + 1);
        if (!*s) { io->bad = 1; return; }
        memcpy(*s, io->data + io->pos, n);
        (*s)[n] = 0;
    } else memcpy(io->data + io->pos, *s, n);
    io->pos += n;
}

static uint32_t io_count(schema_io_t* io, size_t n) {
    if (!io->read && n > 256) { io->bad = 1; return 0; }
    uint32_t value = io32(io, (uint32_t)n);
    if (value > 256) io->bad = 1;
    return value;
}

static void io_names(schema_io_t* io, char*** names, size_t* count) {
    uint32_t n = io_count(io, *count);
    if (io->bad) return;
    if (io->read) {
        *count = n;
        *names = (char**)calloc(n ? n : 1, sizeof(char*));
        if (!*names) { io->bad = 1; return; }
    } else if (n && !*names) { io->bad = 1; return; }
    for (size_t i = 0; i < n && !io->bad; i++) {
        io_string(io, &(*names)[i]);
        if (!(*names)[i] || !*(*names)[i]) io->bad = 1;
    }
}

static void io_fk(schema_io_t* io, qihse_sql_fk_t* fk) {
    io_names(io, &fk->columns, &fk->num_columns);
    io_string(io, &fk->ref_table);
    io_names(io, &fk->ref_columns, &fk->num_ref_columns);
    uint32_t del = io32(io, (uint32_t)fk->on_delete);
    uint32_t upd = io32(io, (uint32_t)fk->on_update);
    if (io->read) { fk->on_delete = (qihse_sql_fk_action_t)del; fk->on_update = (qihse_sql_fk_action_t)upd; }
    if (!fk->ref_table || !*fk->ref_table || !fk->num_columns ||
        fk->num_columns != fk->num_ref_columns || del > QIHSE_FK_RESTRICT ||
        upd > QIHSE_FK_RESTRICT) io->bad = 1;
}

static void io_trigger(schema_io_t* io, qihse_sql_trigger_def_t* tr,
                       const char* table_name) {
    io_string(io, &tr->name); io_string(io, &tr->table_name);
    io_string(io, &tr->timing); io_string(io, &tr->event);
    io_string(io, &tr->function_name);
    uint32_t per_row = io32(io, (uint32_t)tr->for_each_row);
    if (io->read) tr->for_each_row = (int)per_row;
    if (!tr->name || !*tr->name || !tr->table_name || !ieq(tr->table_name, table_name) ||
        !tr->timing || !ieq(tr->timing, "BEFORE") ||
        !tr->event || !ieq(tr->event, "UPDATE") ||
        !tr->function_name || !ieq(tr->function_name, "update_updated_at_column") ||
        per_row != 1) io->bad = 1;
}

static void io_function(schema_io_t* io, qihse_sql_function_def_t* fn) {
    io_string(io, &fn->name); io_string(io, &fn->returns);
    io_string(io, &fn->language); io_string(io, &fn->body);
    if (!fn->name || !ieq(fn->name, "update_updated_at_column") ||
        !fn->returns || !ieq(fn->returns, "TRIGGER") ||
        !fn->language || !ieq(fn->language, "plpgsql") ||
        !fn->body || !supported_trigger_body(fn->body)) io->bad = 1;
}

static void io_table(schema_io_t* io, qihse_schema_table_t* t, uint32_t version) {
    io_string(io, &t->name);
    uint32_t nc = io_count(io, t->num_columns);
    if (io->read && !io->bad) {
        t->num_columns = nc;
        t->columns = (qihse_schema_column_t*)calloc(nc ? nc : 1, sizeof(*t->columns));
        if (!t->columns) io->bad = 1;
    }
    if (!t->name || !*t->name || (nc && !t->columns) ||
        (!io->read && (t->num_fks || t->num_checks))) io->bad = 1;
    size_t primary_keys = 0;
    for (size_t i = 0; i < nc && !io->bad; i++) {
        qihse_schema_column_t* c = &t->columns[i];
        io_string(io, &c->name);
        uint32_t type = io32(io, (uint32_t)c->type);
        uint32_t type_len = io32(io, (uint32_t)c->type_len);
        uint32_t type_scale = version >= 3 ? io32(io, (uint32_t)c->type_scale) : 0;
        uint32_t flags = io32(io, (c->not_null ? 1u : 0u) | (c->is_primary_key ? 2u : 0u) |
                                  (c->is_unique ? 4u : 0u) | (c->is_serial ? 8u : 0u) |
                                  (c->fk ? 16u : 0u) | (version >= 3 && c->generated_stored ? 32u : 0u));
        if (io->read) {
            c->type = (qihse_sql_type_t)type; c->type_len = (int)type_len;
            c->type_scale = (int)type_scale; c->generated_stored = !!(flags & 32u);
            c->not_null = !!(flags & 1); c->is_primary_key = !!(flags & 2);
            c->is_unique = !!(flags & 4); c->is_serial = !!(flags & 8);
        }
        io_string(io, &c->default_expr);
        if (version >= 3) io_string(io, &c->generated_expr);
        io_string(io, &c->check_expr);
        if ((flags & 16) && io->read) {
            c->fk = (qihse_sql_fk_t*)calloc(1, sizeof(*c->fk));
            if (!c->fk) io->bad = 1;
        }
        if ((flags & 16) && !io->bad) io_fk(io, c->fk);
        if (!io->read && ((flags & 16u) || c->check_expr)) io->bad = 1;
        if (!c->name || !*c->name || type < QIHSE_TYPE_INT || type > (version >= 3 ? QIHSE_TYPE_TSVECTOR : QIHSE_TYPE_UUID) ||
            type_len > INT32_MAX || type_scale > INT32_MAX || flags & ~(version >= 3 ? 63u : 31u) ||
            (version >= 3 && (!!c->generated_expr != !!c->generated_stored))) io->bad = 1;
        if ((c->is_primary_key && ++primary_keys > 1) ||
            (c->is_unique && !c->not_null && !c->is_primary_key)) io->bad = 1;
        for (size_t j = 0; j < i; j++) if (ieq(t->columns[j].name, c->name)) io->bad = 1;
    }
    uint32_t ni = io_count(io, t->num_indexes);
    if (io->read && !io->bad) {
        t->num_indexes = ni;
        t->indexes = (qihse_schema_index_t*)calloc(ni ? ni : 1, sizeof(*t->indexes));
        if (!t->indexes) io->bad = 1;
    }
    if (ni && !t->indexes) io->bad = 1;
    for (size_t i = 0; i < ni && !io->bad; i++) {
        qihse_schema_index_t* idx = &t->indexes[i];
        io_string(io, &idx->name); io_string(io, &idx->table_name);
        io_string(io, &idx->column_name);
        uint32_t unique = io32(io, (uint32_t)idx->unique);
        if (io->read) idx->unique = (int)unique;
        if (!idx->name || !*idx->name || !idx->table_name ||
            !ieq(idx->table_name, t->name) ||
            (version < 4 && (!idx->column_name || !*idx->column_name)) || unique != 0) io->bad = 1;
        bool column_exists = false;
        for (size_t j = 0; j < t->num_columns; j++)
            if (idx->column_name && ieq(t->columns[j].name, idx->column_name))
                column_exists = true;
        if (version < 4 && !column_exists) io->bad = 1;
        if (version < 4 && io->read && !io->bad) {
            idx->expressions = calloc(1, sizeof(char*));
            if (!idx->expressions || !(idx->expressions[0] = strdup(idx->column_name)) ||
                !(idx->descending = calloc(1, sizeof(int)))) io->bad = 1;
            idx->num_expressions = 1;
        }
        if (version >= 4) {
            io_names(io, &idx->expressions, &idx->num_expressions);
            uint32_t nd = io_count(io, idx->num_expressions);
            if (!idx->num_expressions || nd != idx->num_expressions || nd > 16) io->bad = 1;
            if (io->read && !io->bad) {
                idx->descending = calloc(nd ? nd : 1, sizeof(*idx->descending));
                if (!idx->descending) io->bad = 1;
            }
            for (size_t k = 0; k < nd && !io->bad; ++k) {
                uint32_t descending = io32(io, (uint32_t)idx->descending[k]);
                if (descending > 1) io->bad = 1;
                if (io->read) idx->descending[k] = (int)descending;
            }
            io_string(io, &idx->using_method);
            if (idx->using_method && !ieq(idx->using_method, "gin") &&
                !ieq(idx->using_method, "btree")) io->bad = 1;
        }
        for (size_t j = 0; j < i; j++) if (ieq(t->indexes[j].name, idx->name)) io->bad = 1;
    }
    uint32_t nf = io_count(io, t->num_fks);
    if (io->read && !io->bad) {
        t->num_fks = nf;
        t->fks = (qihse_sql_fk_t*)calloc(nf ? nf : 1, sizeof(*t->fks));
        if (!t->fks) io->bad = 1;
    }
    if (nf && !t->fks) io->bad = 1;
    for (size_t i = 0; i < nf && !io->bad; i++) io_fk(io, &t->fks[i]);
    uint32_t nk = io_count(io, t->num_checks);
    if (io->read && !io->bad) {
        t->num_checks = nk;
        t->checks = (qihse_sql_check_t*)calloc(nk ? nk : 1, sizeof(*t->checks));
        if (!t->checks) io->bad = 1;
    }
    if (nk && !t->checks) io->bad = 1;
    for (size_t i = 0; i < nk && !io->bad; i++) {
        io_string(io, &t->checks[i].name);
        io_string(io, &t->checks[i].expr);
        if (!t->checks[i].expr || !*t->checks[i].expr) io->bad = 1;
    }
    uint32_t nu = io_count(io, t->num_uniques);
    if (io->read && !io->bad) {
        t->num_uniques = nu;
        t->uniques = (qihse_sql_unique_t*)calloc(nu ? nu : 1, sizeof(*t->uniques));
        if (!t->uniques) io->bad = 1;
    }
    if (nu && !t->uniques) io->bad = 1;
    for (size_t i = 0; i < nu && !io->bad; i++) {
        io_string(io, &t->uniques[i].name);
        io_names(io, &t->uniques[i].columns, &t->uniques[i].num_columns);
        if (t->uniques[i].num_columns != 1 || !t->uniques[i].columns ||
            !t->uniques[i].columns[0]) { io->bad = 1; continue; }
        bool key_column_valid = false;
        for (size_t c = 0; c < t->num_columns; ++c)
            if (ieq(t->columns[c].name, t->uniques[i].columns[0]) &&
                (t->columns[c].not_null || t->columns[c].is_primary_key))
                key_column_valid = true;
        if (!key_column_valid) io->bad = 1;
    }
    if (version >= 4 && !io->bad) {
        io_string(io, &t->view_query);
        if (t->view_query && !*t->view_query) io->bad = 1;
        uint32_t ntr = io_count(io, t->num_triggers);
        if (io->read && !io->bad) {
            t->num_triggers = ntr;
            t->triggers = calloc(ntr ? ntr : 1, sizeof(*t->triggers));
            if (!t->triggers) io->bad = 1;
        }
        if (t->view_query && ntr) io->bad = 1;
        if (ntr) {
            bool target_column = false;
            for (size_t c = 0; c < t->num_columns; ++c)
                if (ieq(t->columns[c].name, "updated_at") &&
                    t->columns[c].type == QIHSE_TYPE_TIMESTAMPTZ)
                    target_column = true;
            if (!target_column) io->bad = 1;
        }
        for (size_t i = 0; i < ntr && !io->bad; ++i) {
            io_trigger(io, &t->triggers[i], t->name);
            for (size_t j = 0; j < i; ++j)
                if (ieq(t->triggers[i].name, t->triggers[j].name)) io->bad = 1;
        }
    }
}

static uint32_t checksum(const uint8_t* data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) h = (h ^ data[i]) * 16777619u;
    return h;
}

int qihse_schema_serialize(const qihse_schema_registry_t* reg, uint8_t** out, size_t* len) {
    if (!reg || !out || !len || reg->num_tables > 256 ||
        reg->num_extensions > 16 || (reg->num_tables && !reg->tables) ||
        (reg->num_extensions && !reg->extensions) || reg->num_functions > 256 ||
        (reg->num_functions && !reg->functions)) return -1;
    for (size_t i = 0; i < reg->num_extensions; ++i) {
        if (!reg->extensions[i] || !ieq(reg->extensions[i], "uuid-ossp")) return -1;
        for (size_t j = 0; j < i; ++j)
            if (ieq(reg->extensions[i], reg->extensions[j])) return -1;
    }
    /* Do not persist catalog metadata that the row engine cannot enforce. */
    for (size_t i = 0; i < reg->num_tables; ++i) {
        const qihse_schema_table_t* t = &reg->tables[i];
        size_t primary_keys = 0;
        if (!t->name || !*t->name || t->num_columns > 256 ||
            t->num_indexes > 256 || t->num_triggers > 256 || t->num_fks || t->num_checks ||
            t->num_uniques > 256 || (t->num_columns && !t->columns) ||
            (t->num_indexes && !t->indexes) || (t->num_uniques && !t->uniques))
            return -1;
        for (size_t tr = 0; tr < t->num_triggers; ++tr)
            if (!qihse_schema_get_function(reg, t->triggers[tr].function_name)) return -1;
        if (t->view_query && t->num_triggers) return -1;
        for (size_t c = 0; c < t->num_columns; ++c) {
            const qihse_schema_column_t* col = &t->columns[c];
            if (!col->name || !*col->name || col->fk || col->check_expr ||
                col->type <= QIHSE_TYPE_UNKNOWN || col->type > QIHSE_TYPE_TSVECTOR ||
                (!!col->generated_expr != !!col->generated_stored) ||
                (col->is_unique && !col->not_null && !col->is_primary_key) ||
                (col->is_primary_key && ++primary_keys > 1)) return -1;
            for (size_t j = 0; j < c; ++j)
                if (ieq(col->name, t->columns[j].name)) return -1;
        }
    }
    uint8_t* buf = (uint8_t*)calloc(1, QIHSE_SCHEMA_IMAGE_MAX);
    if (!buf) return -1;
    schema_io_t io = { .data = buf, .len = QIHSE_SCHEMA_IMAGE_MAX - 4 };
    memcpy(buf, "QSC1", 4); io.pos = 4;
    io32(&io, 4);
    uint32_t ne = io_count(&io, reg->num_extensions);
    if (ne && !reg->extensions) io.bad = 1;
    for (size_t i = 0; i < ne && !io.bad; ++i) {
        char* extension = reg->extensions[i];
        if (!extension || !ieq(extension, "uuid-ossp")) { io.bad = 1; break; }
        io_string(&io, &extension);
    }
    uint32_t nt = io_count(&io, reg->num_tables);
    if (nt && !reg->tables) io.bad = 1;
    for (size_t i = 0; i < nt && !io.bad; i++)
        io_table(&io, &reg->tables[i], 4);
    uint32_t nfn = io_count(&io, reg->num_functions);
    for (size_t i = 0; i < nfn && !io.bad; ++i)
        io_function(&io, &reg->functions[i]);
    if (io.bad) { free(buf); return -1; }
    uint32_t sum = checksum(buf, io.pos);
    io.len = QIHSE_SCHEMA_IMAGE_MAX;
    io32(&io, sum);
    *out = buf;
    *len = io.pos;
    return 0;
}

int qihse_schema_deserialize(const uint8_t* data, size_t len, qihse_schema_registry_t** out) {
    if (!data || !out || len < 16 || len > QIHSE_SCHEMA_IMAGE_MAX ||
        memcmp(data, "QSC1", 4)) return -1;
    uint32_t expected = 0;
    for (unsigned i = 0; i < 4; i++) expected |= (uint32_t)data[len - 4 + i] << (8 * i);
    if (checksum(data, len - 4) != expected) return -1;
    schema_io_t io = { .data = (uint8_t*)data, .pos = 4, .len = len - 4, .read = 1 };
    uint32_t version = io32(&io, 0);
    if (version != 1 && version != 2 && version != 3 && version != 4) return -1;
    qihse_schema_registry_t* reg = qihse_schema_registry_create();
    if (!reg) return -1;
    if (version >= 2) {
        uint32_t ne = io_count(&io, 0);
        if (io.bad) goto fail;
        for (size_t i = 0; i < ne && !io.bad; ++i) {
            char* extension = NULL;
            io_string(&io, &extension);
            if (!extension || qihse_schema_create_extension(reg, extension) != 0)
                io.bad = 1;
            free(extension);
        }
        if (io.bad) goto fail;
    }
    uint32_t nt = io_count(&io, 0);
    if (io.bad) goto fail;
    if (nt > reg->cap) {
        qihse_schema_table_t* p = (qihse_schema_table_t*)calloc(nt, sizeof(*p));
        if (!p) goto fail;
        free(reg->tables); reg->tables = p; reg->cap = nt;
    }
    for (size_t i = 0; i < nt && !io.bad; i++) {
        qihse_schema_table_t* t = &reg->tables[reg->num_tables++];
        io_table(&io, t, version);
        for (size_t j = 0; j < i; j++)
            if (ieq(t->name, reg->tables[j].name)) io.bad = 1;
        for (size_t j = 0; j < i; j++)
            for (size_t k = 0; k < t->num_indexes; k++)
                for (size_t m = 0; m < reg->tables[j].num_indexes; m++)
                    if (ieq(t->indexes[k].name, reg->tables[j].indexes[m].name)) io.bad = 1;
    }
    if (version >= 4 && !io.bad) {
        uint32_t nfn = io_count(&io, 0);
        if (nfn && !io.bad) {
            reg->functions = calloc(nfn, sizeof(*reg->functions));
            if (!reg->functions) io.bad = 1;
        }
        for (size_t i = 0; i < nfn && !io.bad; ++i) {
            qihse_sql_function_def_t* fn = &reg->functions[reg->num_functions++];
            io_function(&io, fn);
            for (size_t j = 0; j < i; ++j)
                if (ieq(fn->name, reg->functions[j].name)) io.bad = 1;
        }
        for (size_t i = 0; i < reg->num_tables && !io.bad; ++i)
            for (size_t j = 0; j < reg->tables[i].num_triggers; ++j)
                if (!qihse_schema_get_function(reg,
                        reg->tables[i].triggers[j].function_name)) io.bad = 1;
    }
    if (io.bad || io.pos != len - 4) goto fail;
    io.len = len;
    if (checksum(data, len - 4) != io32(&io, 0) || io.bad) goto fail;
    *out = reg;
    return 0;
fail:
    qihse_schema_registry_destroy(reg);
    return -1;
}

bool qihse_schema_has_index(const qihse_schema_registry_t* reg, const char* table, const char* column) {
    const qihse_schema_table_t* t = find_table_c(reg, table);
    if (!t) return false;
    for (size_t i = 0; i < t->num_indexes; i++) {
        if (t->indexes[i].column_name && ieq(t->indexes[i].column_name, column)) return true;
    }
    return false;
}
