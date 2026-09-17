# QIHSE SQL Engine & Query Processing Architecture

> **Status: partial.** The parser, executors, optimizer and schema registry all
> have real implementations under `src/tractable/` and are exercised by
> `tests/test_sql_completeness.c` (run via `make test-sql-completeness`).
> Four claims in the previous revision of this document were not true of the
> code and are corrected in place below:
>
> 1. **`UPDATE ... SET` is not parsed.** The parser captures the table name and
>    stops; `ast->set_columns`/`set_values`/`num_set` are declared and freed but
>    never populated. `tests/test_sql_completeness.c` prints the count (0) as a
>    `NOTE`.
> 2. **`DELETE ... WHERE` is not parsed into conditions.** The clause text is
>    kept as raw text in `ast->insert_select_query`, and `ast->where_conditions`
>    stays empty.
> 3. **A scalar subquery in the SELECT list is not extracted** into
>    `ast->select_items[i].scalar_subquery`.
> 4. **The optimizer has no histograms or most-common-value tracking.** The
>    `qihse_column_stat_t` histogram fields exist in the header but nothing ever
>    fills them; cardinality estimation uses `distinct_count` (equality) and a
>    fixed 1/3 (ranges).
>
> Also unverified here: the pgwire prepared-statement cache (see §6). No test in
> the tree exercises it.

## 1. Overview

QIHSE includes a native C99 SQL engine that provides full relational query processing on top of the multi-model storage engines. The SQL engine consists of a parser, query executors, a cost-based optimizer, and a schema registry.

## 2. SQL Parser

**Files**: `include/qihse_sql_parser.h`, `src/tractable/qihse_sql_parser.c`

The parser tokenizes and builds an AST from SQL text. Supported statement types:

### DML
- `SELECT` with column list, FROM, JOIN, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, OFFSET, DISTINCT
- `INSERT INTO ... VALUES ...` (multi-row, with an optional column list)
- `UPDATE ... SET ... WHERE ...` — **recognised only**: the table name is
  captured and the SET list is not parsed (`ast->num_set` stays 0)
- `DELETE FROM ... WHERE ...` — **recognised only**: the table name is captured
  and the WHERE clause is kept as raw text in `ast->insert_select_query`, not as
  `ast->where_conditions`

### DDL
- `CREATE TABLE name (col TYPE, ...)` with types: INT, BIGINT, FLOAT, DOUBLE, VARCHAR(n), TEXT, BOOL, TIMESTAMP, VECTOR(n)
- `ALTER TABLE name ADD/DROP/RENAME COLUMN ...`
- `ALTER TABLE name RENAME TO new_name`
- `CREATE INDEX name ON table (col, ...)`
- `DROP INDEX name`
- `DROP TABLE name`

### JOIN Types
- `INNER JOIN ... ON ...` (also bare `JOIN`)
- `LEFT [OUTER] JOIN ... ON ...`
- `RIGHT [OUTER] JOIN ... ON ...`
- `FULL [OUTER] JOIN ... ON ...`
- `CROSS JOIN ...`

For every join with an `ON` equality the parser decomposes the condition into
`joins[i].left_key` / `right_key` (for example `t1.id` and `t2.id`);
`joins[i].on_condition` is left empty. `CROSS JOIN` has no keys. All five
spellings are covered by `tests/test_sql_completeness.c`.

### Aggregates
- `SUM(expr)`, `COUNT(expr)`, `COUNT(*)`, `AVG(expr)`, `MIN(expr)`, `MAX(expr)`
- `GROUP BY col, ...`
- `HAVING condition`
- `DISTINCT`

### Subqueries
- `WHERE col IN (SELECT ...)` — parsed; the inner AST is attached to the
  condition
- `WHERE EXISTS (SELECT ...)` — parsed; a correlated inner predicate (one that
  names an outer column) is preserved in the inner AST
- Scalar subqueries in the SELECT list: `(SELECT col FROM t WHERE ...)` — the
  text is kept in the select item's `expr`, but
  `select_items[i].scalar_subquery` is **not** populated

### Set Operations
- `UNION`, `INTERSECT`, `EXCEPT`

### AST Structure

```c
typedef struct qihse_sql_ast_s {
    qihse_sql_stmt_type_t stmt_type;    // SELECT, INSERT, UPDATE, DELETE, CREATE, DROP
    char** select_columns;
    size_t num_select_columns;
    qihse_sql_table_ref_t* from_tables;
    size_t num_from_tables;
    qihse_sql_join_t* joins;            // JOIN clauses with type and ON condition
    size_t num_joins;
    qihse_sql_condition_t* where_conditions;
    size_t num_where_conditions;
    qihse_sql_column_ref_t* group_by_cols;
    size_t num_group_by_cols;
    qihse_sql_condition_t* having_conditions;
    size_t num_having_conditions;
    qihse_sql_order_by_t* order_by_cols;
    size_t num_order_by_cols;
    int limit;
    int offset;
    int distinct;
    // ... DDL fields for CREATE/ALTER/DROP
} qihse_sql_ast_t;
```

## 3. Query Executors

### 3.1 Join Executor

**Files**: `include/qihse_join_executor.h`, `src/tractable/qihse_join_executor.c`

Provides two join algorithms with a generic row stream abstraction:

- **Hash Join**: Build a hash table from the smaller (build) side, probe with the larger (probe) side. Optimal for equi-joins on large inputs.
- **Nested-Loop Join**: Iterate over both sides. Used for non-equi-join conditions or when one side is small enough to fit in cache.

Row streams are abstracted via `qihse_row_stream_t` which provides `next()`, `reset()`, and `close()` operations, allowing pipelining between executors.

### 3.2 Aggregate Executor

**Files**: `include/qihse_aggregate_executor.h`, `src/tractable/qihse_aggregate_executor.c`

Hash-based aggregation:

1. Read input rows, compute group key from GROUP BY columns
2. Look up or create accumulator in hash table
3. Apply aggregate function (SUM adds to running total, COUNT increments, MIN/MAX compare, AVG tracks sum+count)
4. After all input consumed, emit one row per group
5. Apply HAVING filter on output

DISTINCT tracking uses a separate hash set per group to deduplicate values before aggregation.

### 3.3 Sort Executor

**Files**: `include/qihse_sort_executor.h`, `src/tractable/qihse_sort_executor.c`

- **In-memory sort**: Collects all rows, sorts using qsort with a multi-key comparator
- **Spill-to-disk**: When result set exceeds configurable memory threshold, writes sorted runs to temporary files, then merges them
- **Multi-key comparison**: Supports ascending/descending per sort column, numeric and string comparison

### 3.4 Index Scan Executor

**Files**: `include/qihse_index_scan.h`, `src/tractable/qihse_index_scan.c`

- **EQ predicate**: Point lookup on B+ tree or hash index
- **RANGE predicate**: Range scan on B+ tree between min and max key
- **PREFIX predicate**: Composite index prefix matching on B+ tree
- Returns matching row IDs that can be joined with table data fetch

## 4. Cost-Based Optimizer

**Files**: `include/qihse_optimizer.h`, `src/tractable/qihse_optimizer.c`

### Statistics Collection
- Per-table row count estimates (`qihse_optimizer_set_table_stats`)
- Per-column distinct count, null fraction and min/max
  (`qihse_optimizer_set_column_stats`)
- Per-column histograms with most-common-value (MCV) tracking — **declared in
  `qihse_column_stat_t` but never populated by the optimizer**; do not rely on
  the histogram fields

### Cardinality Estimation
- Equality filter: `selectivity = 1 / distinct_count`
- Range filter (`<`, `<=`, `>`, `>=`): a fixed `0.33`
- `<>`: `1 - 1/distinct_count`; `LIKE` and `IN`: a fixed `0.1`
- Unknown table, unknown column, subquery or unrecognised operator: `0.1`
- Combined filters: not combined — the estimator takes one condition at a time

### Plan Enumeration
- **Scan choice**: Seq scan (full table) vs index scan (when index exists and selectivity < threshold)
- **Join choice**: Hash join (when build side fits in memory) vs nested loop (when one side is small)
- **Plan tree**: Builds a tree of plan nodes that executors traverse

```c
typedef enum {
    QIHSE_PLAN_SEQ_SCAN,
    QIHSE_PLAN_INDEX_SCAN,
    QIHSE_PLAN_HASH_JOIN,
    QIHSE_PLAN_NESTED_LOOP_JOIN,
    QIHSE_PLAN_AGGREGATE,
    QIHSE_PLAN_SORT,
    QIHSE_PLAN_LIMIT
} qihse_plan_node_type_t;
```

## 5. Schema Registry

**Files**: `include/qihse_schema.h`, `src/tractable/qihse_schema.c`

In-memory catalog of table and index definitions. The catalog is populated from
parsed ASTs, not from column arrays:

```c
qihse_schema_registry_t* qihse_schema_registry_create(void);
void qihse_schema_registry_destroy(qihse_schema_registry_t* reg);

int qihse_schema_create_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
int qihse_schema_drop_table(qihse_schema_registry_t* reg, const char* name);
int qihse_schema_create_index(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
int qihse_schema_drop_index(qihse_schema_registry_t* reg, const char* name);
int qihse_schema_alter_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);

const qihse_schema_table_t* qihse_schema_get_table(const qihse_schema_registry_t* reg, const char* name);
const qihse_schema_index_t* qihse_schema_get_index(const qihse_schema_registry_t* reg, const char* name);
size_t qihse_schema_table_count(const qihse_schema_registry_t* reg);
const qihse_schema_table_t* qihse_schema_table_at(const qihse_schema_registry_t* reg, size_t idx);
bool   qihse_schema_has_index(const qihse_schema_registry_t* reg, const char* table,
                              const char* column);
```

`qihse_schema_alter_table()` handles ADD COLUMN, DROP COLUMN, RENAME COLUMN and
RENAME TO through `ast->alter_clause->action`. It is an in-memory catalog; the
source notes it is a stub interface that can be wired to persistent storage
later.

## 6. Prepared Statements (pgwire)

**Status: not covered by any test.** The PostgreSQL wire protocol server
(`src/spinnaker/qihse_pg_wire.c`) implements the extended query protocol's
Parse / Bind / Describe / Execute / Close / Sync message handling, and
`QIHSE_PG_MAX_PREPARED` is 64. Two corrections to the previous revision of this
section:

- eviction is **FIFO**, not LRU: a full cache shifts every entry down by one and
  appends the new statement, with no recency update on a hit;
- there is no test in this repository for the prepared-statement path.
  `tests/test_pg_wire_cluster.c` exercises pgwire at the cluster level, which is
  not the same thing. `tests/test_sql_completeness.c` does not touch pgwire.

## 7. Testing

`tests/test_sql_completeness.c` (run via `make test-sql-completeness`) covers:

- **Parsing**: SELECT shape (columns, FROM, WHERE, ORDER BY ASC/DESC, LIMIT,
  OFFSET, DISTINCT), aggregates (SUM/COUNT/COUNT(*)/AVG/MIN/MAX) with GROUP BY
  and HAVING text, all five JOIN spellings with their ON keys, IN and EXISTS
  subqueries (including a correlated inner predicate), UNION/INTERSECT/EXCEPT,
  multi-row INSERT, CREATE TABLE across all nine documented column types, the
  four ALTER TABLE actions, CREATE INDEX, DROP INDEX, DROP TABLE, and an
  unclassifiable statement reported as `QIHSE_SQL_UNKNOWN`.
- **Join execution**: hash join (inner) and nested-loop join (LEFT with NULL
  padding and CROSS), plus case-insensitive column lookup.
- **Aggregate execution**: GROUP BY with SUM/COUNT/COUNT(*)/AVG/MIN/MAX and a
  global aggregate with no grouping.
- **Sort execution**: multi-key ASC/DESC, single key, and the spill-to-disk path
  (a threshold small enough to force temporary runs).
- **Schema registry**: create table and index, lookup by name and by
  table+column, ALTER TABLE ADD COLUMN, drop index, drop table.
- **Optimizer**: selectivity estimation, sequential vs index scan choice
  (switching when an index is added), and the SORT/LIMIT/AGGREGATE/JOIN plan
  nodes, plus "no plan for a non-SELECT statement".

Reported as `NOTE` lines rather than asserted, so that fixing them cannot break
the test: UPDATE SET captures 0 columns, DELETE WHERE yields 0 structured
conditions, and the select-list scalar subquery is not extracted.

Not covered: the pgwire prepared-statement cache, window functions, and
`INSERT ... SELECT` execution.
