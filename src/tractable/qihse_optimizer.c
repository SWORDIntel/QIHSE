#define _GNU_SOURCE
/*
 * QIHSE Cost-based Optimizer — Phase 1 Relational Completeness
 *
 * Implements basic statistics (row count estimates, column histograms),
 * cardinality estimation for filter conditions, and plan enumeration
 * choosing between seq scan, index scan, hash join vs nested loop.
 */
#include "qihse_optimizer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

static bool ieq(const char* a, const char* b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

static char* dup_s(const char* s) { return s ? strdup(s) : NULL; }

struct qihse_optimizer {
    qihse_schema_registry_t* schema;
    qihse_table_stat_t* stats;
    size_t num_stats;
    size_t cap;
};

qihse_optimizer_t* qihse_optimizer_create(qihse_schema_registry_t* schema) {
    qihse_optimizer_t* opt = (qihse_optimizer_t*)calloc(1, sizeof(*opt));
    opt->schema = schema;
    opt->cap = 16;
    opt->stats = (qihse_table_stat_t*)calloc(opt->cap, sizeof(qihse_table_stat_t));
    return opt;
}

static void free_col_stat(qihse_column_stat_t* c) {
    free(c->column_name);
    free(c->min_value);
    free(c->max_value);
    for (int i = 0; i < c->num_buckets; i++) { free(c->hist_lo[i]); free(c->hist_hi[i]); }
}

void qihse_optimizer_destroy(qihse_optimizer_t* opt) {
    if (!opt) return;
    for (size_t i = 0; i < opt->num_stats; i++) {
        free(opt->stats[i].table_name);
        for (size_t j = 0; j < opt->stats[i].num_columns; j++) free_col_stat(&opt->stats[i].columns[j]);
        free(opt->stats[i].columns);
    }
    free(opt->stats);
    free(opt);
}

static qihse_table_stat_t* find_stat(qihse_optimizer_t* opt, const char* table) {
    for (size_t i = 0; i < opt->num_stats; i++) {
        if (ieq(opt->stats[i].table_name, table)) return &opt->stats[i];
    }
    return NULL;
}

static const qihse_table_stat_t* find_stat_c(const qihse_optimizer_t* opt, const char* table) {
    for (size_t i = 0; i < opt->num_stats; i++) {
        if (ieq(opt->stats[i].table_name, table)) return &opt->stats[i];
    }
    return NULL;
}

void qihse_optimizer_set_table_stats(qihse_optimizer_t* opt, const char* table, int64_t row_count) {
    if (!opt || !table) return;
    qihse_table_stat_t* ts = find_stat(opt, table);
    if (!ts) {
        if (opt->num_stats >= opt->cap) {
            opt->cap *= 2;
            opt->stats = (qihse_table_stat_t*)realloc(opt->stats, opt->cap * sizeof(qihse_table_stat_t));
        }
        ts = &opt->stats[opt->num_stats++];
        memset(ts, 0, sizeof(*ts));
        ts->table_name = strdup(table);
        ts->row_count = row_count;
    } else {
        ts->row_count = row_count;
    }
}

void qihse_optimizer_set_column_stats(qihse_optimizer_t* opt, const char* table,
                                       const char* column, int64_t distinct_count,
                                       double null_fraction, const char* min_val, const char* max_val) {
    if (!opt || !table || !column) return;
    qihse_table_stat_t* ts = find_stat(opt, table);
    if (!ts) {
        qihse_optimizer_set_table_stats(opt, table, 1000);
        ts = find_stat(opt, table);
    }
    if (!ts) return;
    /* find or create column stat */
    qihse_column_stat_t* cs = NULL;
    for (size_t i = 0; i < ts->num_columns; i++) {
        if (ieq(ts->columns[i].column_name, column)) { cs = &ts->columns[i]; break; }
    }
    if (!cs) {
        if (ts->num_columns && (ts->num_columns % 8 == 0)) {
            ts->columns = (qihse_column_stat_t*)realloc(ts->columns, (ts->num_columns + 8) * sizeof(qihse_column_stat_t));
        } else if (ts->num_columns == 0) {
            ts->columns = (qihse_column_stat_t*)calloc(8, sizeof(qihse_column_stat_t));
        }
        cs = &ts->columns[ts->num_columns++];
        memset(cs, 0, sizeof(*cs));
        cs->column_name = strdup(column);
    }
    cs->distinct_count = distinct_count;
    cs->null_fraction = null_fraction;
    free(cs->min_value); cs->min_value = dup_s(min_val);
    free(cs->max_value); cs->max_value = dup_s(max_val);
}

const qihse_table_stat_t* qihse_optimizer_get_table_stats(const qihse_optimizer_t* opt, const char* table) {
    return find_stat_c(opt, table);
}

/* ------------------------------------------------------------------------- */
/* Cardinality estimation                                                     */
/* ------------------------------------------------------------------------- */

static const qihse_column_stat_t* find_col_stat(const qihse_table_stat_t* ts, const char* col) {
    if (!ts || !col) return NULL;
    for (size_t i = 0; i < ts->num_columns; i++) {
        if (ieq(ts->columns[i].column_name, col)) return &ts->columns[i];
    }
    return NULL;
}

double qihse_optimizer_estimate_selectivity(const qihse_optimizer_t* opt,
                                             const char* table,
                                             const qihse_sql_condition_t* cond) {
    if (!opt || !table || !cond) return 1.0;
    const qihse_table_stat_t* ts = find_stat_c(opt, table);
    if (!ts) return 0.1; /* unknown table: assume 10% selectivity */
    if (cond->subq_kind != 0) return 0.1; /* subquery: rough estimate */
    if (!cond->column_name) return 0.1;
    const qihse_column_stat_t* cs = find_col_stat(ts, cond->column_name);
    if (!cs) return 0.1;
    if (!cond->operator) return 0.1;

    if (ieq(cond->operator, "=")) {
        /* equality: 1 / distinct_count */
        if (cs->distinct_count > 0) return 1.0 / (double)cs->distinct_count;
        return 0.01;
    } else if (ieq(cond->operator, "<") || ieq(cond->operator, "<=") ||
               ieq(cond->operator, ">") || ieq(cond->operator, ">=")) {
        /* range: assume 1/3 selectivity */
        return 0.33;
    } else if (ieq(cond->operator, "<>")) {
        if (cs->distinct_count > 1) return 1.0 - 1.0 / (double)cs->distinct_count;
        return 0.99;
    } else if (ieq(cond->operator, "LIKE")) {
        return 0.1;
    } else if (ieq(cond->operator, "IN")) {
        return 0.1;
    }
    return 0.1;
}

/* ------------------------------------------------------------------------- */
/* Plan building                                                              */
/* ------------------------------------------------------------------------- */

static qihse_plan_node_t* new_node(qihse_plan_node_type_t t) {
    qihse_plan_node_t* n = (qihse_plan_node_t*)calloc(1, sizeof(*n));
    n->type = t;
    n->limit = -1;
    return n;
}

void qihse_plan_node_free(qihse_plan_node_t* n) {
    if (!n) return;
    free(n->table_name);
    free(n->index_name);
    free(n->filter_column);
    free(n->join_key_left);
    free(n->join_key_right);
    for (size_t i = 0; i < n->num_group_cols; i++) free(n->group_cols[i]);
    free(n->group_cols);
    for (size_t i = 0; i < n->num_sort_cols; i++) free(n->sort_cols[i]);
    free(n->sort_cols);
    free(n->sort_asc);
    qihse_plan_node_free(n->left);
    qihse_plan_node_free(n->right);
    free(n);
}

static qihse_plan_node_t* build_scan(qihse_optimizer_t* opt, const char* table) {
    qihse_plan_node_t* n = new_node(QIHSE_PLAN_SEQ_SCAN);
    n->table_name = strdup(table);
    const qihse_table_stat_t* ts = find_stat_c(opt, table);
    n->estimated_rows = ts ? (double)ts->row_count : 1000.0;
    n->estimated_cost = n->estimated_rows; /* seq scan cost ~ rows */
    return n;
}

static qihse_plan_node_t* apply_filters(qihse_optimizer_t* opt, qihse_plan_node_t* scan,
                                         const qihse_sql_ast_t* ast, const char* table) {
    /* if there's a filter on an indexed column, switch to index scan */
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        const qihse_sql_condition_t* c = &ast->where_conditions[i];
        if (!c->column_name || c->subq_kind != 0) continue;
        /* check if column is indexed */
        if (opt->schema && qihse_schema_has_index(opt->schema, table, c->column_name)) {
            /* switch to index scan */
            scan->type = QIHSE_PLAN_INDEX_SCAN;
            free(scan->filter_column);
            scan->filter_column = strdup(c->column_name);
            /* find index name */
            const qihse_schema_table_t* t = qihse_schema_get_table(opt->schema, table);
            if (t) {
                for (size_t j = 0; j < t->num_indexes; j++) {
                    if (t->indexes[j].column_name && ieq(t->indexes[j].column_name, c->column_name)) {
                        free(scan->index_name);
                        scan->index_name = strdup(t->indexes[j].name);
                        break;
                    }
                }
            }
            /* index scan cost: log(rows) + matching rows */
            double sel = qihse_optimizer_estimate_selectivity(opt, table, c);
            scan->estimated_rows = scan->estimated_rows * sel;
            scan->estimated_cost = log(scan->estimated_rows + 1) + scan->estimated_rows;
            return scan;
        }
    }
    /* apply all filter selectivities to seq scan */
    double sel = 1.0;
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        const qihse_sql_condition_t* c = &ast->where_conditions[i];
        if (c->subq_kind != 0) continue;
        sel *= qihse_optimizer_estimate_selectivity(opt, table, c);
    }
    scan->estimated_rows *= sel;
    scan->estimated_cost = scan->estimated_rows;
    return scan;
}

static qihse_plan_node_t* build_join(qihse_optimizer_t* opt, qihse_plan_node_t* left,
                                      qihse_plan_node_t* right,
                                      const qihse_sql_join_t* join) {
    (void)opt;
    /* choose hash join vs nested loop based on cost */
    double hash_cost = left->estimated_cost + right->estimated_cost + left->estimated_rows + right->estimated_rows;
    double nl_cost = left->estimated_cost + left->estimated_rows * right->estimated_cost;
    qihse_plan_node_type_t jt = (hash_cost <= nl_cost) ? QIHSE_PLAN_HASH_JOIN : QIHSE_PLAN_NESTED_LOOP;
    qihse_plan_node_t* n = new_node(jt);
    n->left = left;
    n->right = right;
    n->join_type = join ? join->join_type : QIHSE_JOIN_INNER;
    if (join) {
        n->join_key_left = dup_s(join->left_key);
        n->join_key_right = dup_s(join->right_key);
    }
    /* output cardinality: for equi-join, max(left, right) / max(distinct) */
    n->estimated_rows = (left->estimated_rows + right->estimated_rows) / 2.0;
    if (jt == QIHSE_PLAN_HASH_JOIN) {
        n->estimated_cost = hash_cost;
    } else {
        n->estimated_cost = nl_cost;
    }
    return n;
}

qihse_plan_node_t* qihse_optimizer_build_plan(qihse_optimizer_t* opt, const qihse_sql_ast_t* ast) {
    if (!opt || !ast) return NULL;

    /* handle set operations */
    if (ast->set_op != QIHSE_SET_NONE && ast->set_left && ast->set_right) {
        qihse_plan_node_t* l = qihse_optimizer_build_plan(opt, ast->set_left);
        qihse_plan_node_t* r = qihse_optimizer_build_plan(opt, ast->set_right);
        if (!l || !r) { qihse_plan_node_free(l); qihse_plan_node_free(r); return NULL; }
        /* represent as a hash join (for INTERSECT/EXCEPT) or concat (UNION) */
        qihse_plan_node_t* n = new_node(QIHSE_PLAN_HASH_JOIN);
        n->left = l;
        n->right = r;
        n->estimated_rows = l->estimated_rows + r->estimated_rows;
        n->estimated_cost = l->estimated_cost + r->estimated_cost;
        return n;
    }

    if (ast->stmt_type != QIHSE_SQL_SELECT) return NULL;

    /* build scan for first table */
    qihse_plan_node_t* plan = NULL;
    if (ast->num_from_tables > 0) {
        plan = build_scan(opt, ast->from_tables[0].table_name);
        plan = apply_filters(opt, plan, ast, ast->from_tables[0].table_name);
        /* apply joins */
        for (size_t i = 0; i < ast->num_joins; i++) {
            qihse_plan_node_t* rscan = build_scan(opt, ast->joins[i].table.table_name);
            rscan = apply_filters(opt, rscan, ast, ast->joins[i].table.table_name);
            plan = build_join(opt, plan, rscan, &ast->joins[i]);
        }
    }

    /* aggregate */
    if (ast->group_by || ast->num_select_items > 0) {
        int has_agg = 0;
        for (size_t i = 0; i < ast->num_select_items; i++) {
            if (ast->select_items[i].agg_kind != QIHSE_AGG_NONE) { has_agg = 1; break; }
        }
        if (has_agg || (ast->group_by && ast->group_by->num_group_columns > 0)) {
            qihse_plan_node_t* agg = new_node(QIHSE_PLAN_AGGREGATE);
            agg->left = plan;
            if (ast->group_by) {
                agg->num_group_cols = ast->group_by->num_group_columns;
                agg->group_cols = (char**)calloc(agg->num_group_cols ? agg->num_group_cols : 1, sizeof(char*));
                for (size_t i = 0; i < agg->num_group_cols; i++)
                    agg->group_cols[i] = strdup(ast->group_by->group_columns[i]);
            }
            /* agg reduces rows */
            agg->estimated_rows = plan ? plan->estimated_rows / 10.0 : 1.0;
            agg->estimated_cost = plan ? plan->estimated_cost : 0;
            plan = agg;
        }
    }

    /* sort */
    if (ast->num_order_items > 0) {
        qihse_plan_node_t* sort = new_node(QIHSE_PLAN_SORT);
        sort->left = plan;
        sort->num_sort_cols = ast->num_order_items;
        sort->sort_cols = (char**)calloc(sort->num_sort_cols ? sort->num_sort_cols : 1, sizeof(char*));
        sort->sort_asc = (int*)calloc(sort->num_sort_cols ? sort->num_sort_cols : 1, sizeof(int));
        for (size_t i = 0; i < sort->num_sort_cols; i++) {
            sort->sort_cols[i] = strdup(ast->order_items[i].column_name);
            sort->sort_asc[i] = ast->order_items[i].ascending;
        }
        sort->estimated_rows = plan ? plan->estimated_rows : 0;
        /* sort cost: N log N */
        double n = sort->estimated_rows;
        sort->estimated_cost = (plan ? plan->estimated_cost : 0) + n * log(n + 2);
        plan = sort;
    }

    /* limit */
    if (ast->limit >= 0) {
        qihse_plan_node_t* lim = new_node(QIHSE_PLAN_LIMIT);
        lim->left = plan;
        lim->limit = ast->limit;
        lim->estimated_rows = plan ? (plan->estimated_rows < ast->limit ? plan->estimated_rows : ast->limit) : ast->limit;
        lim->estimated_cost = plan ? plan->estimated_cost : 0;
        plan = lim;
    }

    return plan;
}

const char* qihse_plan_node_type_name(qihse_plan_node_type_t t) {
    switch (t) {
        case QIHSE_PLAN_SEQ_SCAN:    return "SeqScan";
        case QIHSE_PLAN_INDEX_SCAN:  return "IndexScan";
        case QIHSE_PLAN_HASH_JOIN:   return "HashJoin";
        case QIHSE_PLAN_NESTED_LOOP: return "NestedLoop";
        case QIHSE_PLAN_AGGREGATE:   return "Aggregate";
        case QIHSE_PLAN_SORT:        return "Sort";
        case QIHSE_PLAN_LIMIT:       return "Limit";
        case QIHSE_PLAN_SUBQUERY:    return "Subquery";
        default: return "Unknown";
    }
}
