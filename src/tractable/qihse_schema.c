#define _GNU_SOURCE
/*
 * QIHSE Schema Registry — Phase 1 Relational Completeness
 *
 * In-memory catalog for table definitions, column types, and index metadata.
 * Acts as a stub interface that can be wired to persistent storage later.
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
};

qihse_schema_registry_t* qihse_schema_registry_create(void) {
    qihse_schema_registry_t* reg = (qihse_schema_registry_t*)calloc(1, sizeof(*reg));
    reg->cap = 16;
    reg->tables = (qihse_schema_table_t*)calloc(reg->cap, sizeof(qihse_schema_table_t));
    return reg;
}

static void free_table(qihse_schema_table_t* t) {
    free(t->name);
    for (size_t i = 0; i < t->num_columns; i++) {
        free(t->columns[i].name);
        free(t->columns[i].default_expr);
    }
    free(t->columns);
    for (size_t i = 0; i < t->num_indexes; i++) {
        free(t->indexes[i].name);
        free(t->indexes[i].table_name);
        free(t->indexes[i].column_name);
    }
    free(t->indexes);
}

void qihse_schema_registry_destroy(qihse_schema_registry_t* reg) {
    if (!reg) return;
    for (size_t i = 0; i < reg->num_tables; i++) free_table(&reg->tables[i]);
    free(reg->tables);
    free(reg);
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

int qihse_schema_create_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast) {
    if (!reg || !ast || !ast->table_name) return -1;
    if (find_table(reg, ast->table_name)) return -1; /* already exists */
    if (reg->num_tables >= reg->cap) {
        reg->cap *= 2;
        reg->tables = (qihse_schema_table_t*)realloc(reg->tables, reg->cap * sizeof(qihse_schema_table_t));
    }
    qihse_schema_table_t* t = &reg->tables[reg->num_tables++];
    memset(t, 0, sizeof(*t));
    t->name = strdup(ast->table_name);
    t->num_columns = ast->num_columns;
    t->columns = (qihse_schema_column_t*)calloc(ast->num_columns ? ast->num_columns : 1, sizeof(qihse_schema_column_t));
    for (size_t i = 0; i < ast->num_columns; i++) {
        const qihse_sql_column_def_t* src = &ast->columns[i];
        qihse_schema_column_t* dst = &t->columns[i];
        dst->name = src->name ? strdup(src->name) : NULL;
        dst->type = src->type;
        dst->type_len = src->type_len;
        dst->not_null = src->not_null;
        dst->is_primary_key = src->is_primary_key;
        dst->default_expr = src->default_expr ? strdup(src->default_expr) : NULL;
    }
    return 0;
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
    if (!reg || !ast || !ast->index_def) return -1;
    qihse_schema_table_t* t = find_table(reg, ast->index_def->table_name);
    if (!t) return -1;
    if (t->num_indexes && (t->num_indexes % 4 == 0)) {
        t->indexes = (qihse_schema_index_t*)realloc(t->indexes, (t->num_indexes + 4) * sizeof(qihse_schema_index_t));
    } else if (t->num_indexes == 0) {
        t->indexes = (qihse_schema_index_t*)calloc(4, sizeof(qihse_schema_index_t));
    }
    qihse_schema_index_t* idx = &t->indexes[t->num_indexes++];
    memset(idx, 0, sizeof(*idx));
    idx->name = strdup(ast->index_def->name);
    idx->table_name = strdup(ast->index_def->table_name);
    idx->column_name = ast->index_def->column_name ? strdup(ast->index_def->column_name) : NULL;
    idx->unique = ast->index_def->unique;
    return 0;
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
            if (!ac->add_column) return -1;
            if (t->num_columns && (t->num_columns % 8 == 0)) {
                t->columns = (qihse_schema_column_t*)realloc(t->columns, (t->num_columns + 8) * sizeof(qihse_schema_column_t));
            }
            qihse_schema_column_t* c = &t->columns[t->num_columns++];
            memset(c, 0, sizeof(*c));
            c->name = ac->add_column->name ? strdup(ac->add_column->name) : NULL;
            c->type = ac->add_column->type;
            c->type_len = ac->add_column->type_len;
            c->not_null = ac->add_column->not_null;
            c->is_primary_key = ac->add_column->is_primary_key;
            c->default_expr = ac->add_column->default_expr ? strdup(ac->add_column->default_expr) : NULL;
            return 0;
        }
        case QIHSE_ALTER_DROP_COLUMN: {
            if (!ac->column_name) return -1;
            for (size_t i = 0; i < t->num_columns; i++) {
                if (ieq(t->columns[i].name, ac->column_name)) {
                    free(t->columns[i].name);
                    free(t->columns[i].default_expr);
                    memmove(&t->columns[i], &t->columns[i+1], (t->num_columns - i - 1) * sizeof(qihse_schema_column_t));
                    t->num_columns--;
                    return 0;
                }
            }
            return -1;
        }
        case QIHSE_ALTER_RENAME_TABLE: {
            if (!ac->new_name) return -1;
            free(t->name);
            t->name = strdup(ac->new_name);
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

bool qihse_schema_has_index(const qihse_schema_registry_t* reg, const char* table, const char* column) {
    const qihse_schema_table_t* t = find_table_c(reg, table);
    if (!t) return false;
    for (size_t i = 0; i < t->num_indexes; i++) {
        if (t->indexes[i].column_name && ieq(t->indexes[i].column_name, column)) return true;
    }
    return false;
}
