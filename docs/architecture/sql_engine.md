# QIHSE SQL Engine & Query Processing Architecture

> **Status: partial.** The parser, executors, optimizer and schema registry all
> have real implementations under `src/tractable/` and are exercised by
> `tests/test_sql_completeness.c` (run via `make test-sql-completeness`) and
> `tests/test_sql_dml_exec.c` (run via `make test-sql-dml-exec`).
> Corrections to earlier revisions of this document:
>
> 1. **`UPDATE ... SET` is parsed.** `ast->set_columns`/`set_values`/`num_set`
>    carry the assignments, and the WHERE clause is parsed into
>    `ast->where_conditions` like SELECT. An UPDATE that parses to zero
>    assignments (no SET clause, an empty SET list, or an assignment with no
>    value) is **refused**: `qihse_parse_sql_to_ast()` returns NULL instead of
>    an AST that would execute as a silent no-op.
> 2. **`DELETE ... WHERE` is parsed into conditions.** The clause lands in
>    `ast->where_conditions`; `ast->insert_select_query` is no longer used to
>    carry the raw text.
> 3. **A scalar subquery in the SELECT list is not extracted** into
>    `ast->select_items[i].scalar_subquery`. This remains a gap; it is printed
>    as a `NOTE` by `tests/test_sql_completeness.c`.
> 4. **Optimizer histograms are populated through an explicit setter and used
>    by range estimation.** `qihse_optimizer_set_column_histogram()` fills the
>    `qihse_column_stat_t` buckets and `qihse_optimizer_estimate_selectivity()`
>    uses them for `<`/`<=`/`>`/`>=` when present (falling back to the fixed
>    1/3 otherwise). There is **no automatic statistics collection pass** in
>    the tree: like `set_table_stats`/`set_column_stats`, the histogram setter
>    is the caller's contract, so the optimizer is only as informed as its
>    caller. There is no most-common-value (MCV) structure — earlier revisions
>    of this document claimed MCV tracking that never existed.
> 5. **`UPDATE` and `DELETE` execute** against the mutable table store
>    (`src/tractable/qihse_table_store.c`) through
>    `qihse_uwp_sql_execute_dml()`: the parsed assignments and structured WHERE
>    conditions are consumed directly, the reply reports the rows actually
>    changed, and a zero-condition DELETE refuses instead of becoming a
>    match-all. Earlier revisions documented the opposite — that the executor
>    reported a document-store match count because no in-place update/delete
>    API existed. See §3.5. INSERT still writes to the append-only column
>    store, not the row store.
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
- `UPDATE ... SET col = value [, ...] [WHERE ...]` — the assignments land in
  `ast->set_columns`/`set_values`/`num_set` (string literals are stored without
  quotes, matching `insert_rows`; other right-hand sides keep their text), and
  WHERE lands in `ast->where_conditions`. A zero-assignment UPDATE is refused
  with a NULL return
- `DELETE FROM ... [WHERE ...] [RETURNING *]` — WHERE lands in
  `ast->where_conditions`, the same representation SELECT uses; no raw clause
  text is carried in `ast->insert_select_query`

Both DML forms accept an optional target alias (`UPDATE t AS x SET ...`,
`DELETE FROM t x WHERE ...`). The AST has no DML alias field, so the alias is
consumed and dropped; consuming it matters because otherwise the following
SET/WHERE keyword would not be recognised and an aliased DELETE would silently
lose its filter.

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

The struct is `qihse_sql_ast_t` in `include/qihse_sql_parser.h`. The fields the
statement forms above populate (an excerpt, not the whole struct):

```c
typedef struct qihse_sql_ast_s {
    qihse_sql_stmt_type_t stmt_type;    // SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ...

    /* SELECT */
    qihse_sql_select_item_t* select_items;
    size_t num_select_items;
    qihse_sql_table_ref_t* from_tables;
    size_t num_from_tables;
    qihse_sql_join_t* joins;            // JOIN clauses with type and decomposed ON keys
    size_t num_joins;
    qihse_sql_condition_t* where_conditions;  // SELECT / UPDATE / DELETE
    size_t num_where_conditions;
    qihse_sql_group_by_t* group_by;     // NULL if no GROUP BY
    qihse_sql_order_item_t* order_items;
    size_t num_order_items;
    int limit;
    int offset;
    int select_distinct;

    /* DML */
    char* table_name;                   // target table for DDL/DML
    char** insert_columns;              // INSERT column list
    size_t num_insert_columns;
    char*** insert_rows;                // INSERT rows (string literals without quotes)
    size_t num_insert_rows;
    char** set_columns;                 // UPDATE SET column names
    char** set_values;                  // UPDATE SET right-hand sides
    size_t num_set;

    char* raw_sql;                      // the statement text as parsed
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

### 3.5 Table-store DML Executor (UPDATE / DELETE)

**Files**: `src/spinnaker/qihse_uwp_sql_txn_schema.c`
(`qihse_uwp_sql_execute_dml`, the UWP SQL UPDATE/DELETE branch),
`src/tractable/qihse_table_store.c` (the primitives it calls)

The mutable table store is the only in-tree store with in-place update and
delete primitives, so parsed UPDATE and DELETE statements execute against it.
The executor consumes the structured AST only — `ast->set_columns` /
`set_values` / `num_set` for UPDATE and `ast->where_conditions` for both — and
the raw SQL text is never re-parsed for execution.

- **Row counts are actual changes.** The predicate handed to
  `qihse_table_update` / `qihse_table_delete` counts every row it accepts, and
  pre-validation has already rejected unknown columns and non-literal values,
  so a match is a change. The reply is `OK stmt_type=UPDATE rows=N` /
  `OK stmt_type=DELETE rows=N`; it does not report a match count for work it
  did not do.
- **A zero-condition DELETE refuses.** `DELETE FROM t` and any DELETE whose
  WHERE clause parsed to zero conditions (an aliased target whose filter was
  lost, `NOT`, parentheses) are refused with no rows changed. There is no
  match-all DELETE path in this executor.
- **A zero-assignment UPDATE refuses** at the executor as well as at the
  parser.
- **The WHERE clause is verified against the raw text before execution.** The
  clause must be exactly the conjunction of the parsed conditions — same
  columns, operators and values, joined by `AND`, nothing else. `OR`,
  parentheses, `NOT`, `NOT LIKE` (whose negation the parser drops), `IN`,
  `BETWEEN` (whose upper bound the parser drops), `IS`, subqueries and a
  malformed tail all refuse. This check only gates execution; it never
  supplies a condition or a value.
- **Supported predicates**: `=`, `<>`, `!=`, `<`, `>`, `<=`, `>=`, `LIKE` and
  `ILIKE`, joined by AND. Qualified names (`x.id`, an alias the parser drops)
  resolve on their last component. An UPDATE with no WHERE at all is a
  legitimate update-all; an UPDATE whose WHERE parsed to nothing is refused.
- **Assignments must be literals.** Numeric columns require a numeric literal,
  so `SET n = n + 1` refuses. The AST does not record whether a SET value was
  quoted, so a value that names a column (`SET name = other_col`) refuses
  rather than being stored as text; the refusal conservatively also catches a
  quoted literal that happens to equal a column name.
- **Atomicity**: all validation happens before the store call, and the store
  then holds the table's write lock for the whole scan, so a statement cannot
  interleave with another writer. Statements are **not** integrated with the
  transaction manager: ROLLBACK does not undo an applied UPDATE/DELETE, and
  there is no cross-table atomicity. A second identical DELETE reports
  `rows=0` (idempotent).
- **Store scope**: the row store is process-wide and lazily created
  (`qihse_uwp_sql_table_store()`), matching the prepared-statement cache; the
  UWP SQL path has no per-connection engine state yet, and `ctx->sql_engine`
  is not dereferenced. Tables must be created in the store before DML can
  target them. INSERT still writes to the column store, so it does not yet
  populate the row store.
- **Permission**: the same model as the KV / column / document targets — the
  ACL resource id is the FNV-1a hash of the table name, namespace 0; the
  operator role passes and every other role needs a `QIHSE_ACL_WRITE` grant.

## 4. Cost-Based Optimizer

**Files**: `include/qihse_optimizer.h`, `src/tractable/qihse_optimizer.c`

### Statistics Collection
The optimizer has no data access of its own. Every statistic is supplied by the
caller through a setter, exactly as before:

- Per-table row count estimates (`qihse_optimizer_set_table_stats`)
- Per-column distinct count, null fraction and min/max
  (`qihse_optimizer_set_column_stats`)
- Per-column histograms (`qihse_optimizer_set_column_histogram`): up to
  `QIHSE_OPT_HIST_MAX_BUCKETS` (16) buckets, each with a low bound, a high
  bound and a row frequency. The setter copies the bounds, returns false on
  malformed input (leaving any existing histogram unchanged), and there is
  **no MCV structure**: an MCV list would be another caller-supplied
  structure and none is declared.

There is no automatic statistics collection pass in the tree — no ANALYZE
executor scans a store into an optimizer — so a query plan is only as informed
as the caller that populated the statistics. `tests/test_sql_completeness.c`
populates them explicitly and asserts the estimates that result.

### Cardinality Estimation
- Equality filter: `selectivity = 1 / distinct_count`
- Range filter (`<`, `<=`, `>`, `>=`): with a histogram, the fraction of rows
  the buckets place below (or above) the bound. Buckets wholly below the bound
  count in full; the bucket containing the bound is interpolated linearly when
  its endpoints are numeric and counted as half otherwise. Without a histogram,
  a fixed `0.33`
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
  multi-row INSERT, UPDATE SET assignments (including an expression right-hand
  side) with structured WHERE and the refusal of zero-assignment UPDATEs,
  DELETE structured WHERE (including a quoted value and RETURNING), CREATE
  TABLE across all nine documented column types, the four ALTER TABLE actions,
  CREATE INDEX, DROP INDEX, DROP TABLE, and an unclassifiable statement
  reported as `QIHSE_SQL_UNKNOWN`.
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
- **Optimizer histograms**: population through
  `qihse_optimizer_set_column_histogram`, the stored bucket values, the
  histogram-driven range estimates (`age < 50` -> 0.3, `age >= 50` -> 0.7 for
  a 300/1000 split), and the refusal of malformed input.

Reported as a `NOTE` line rather than asserted, so that fixing it cannot break
the test: the select-list scalar subquery is not extracted.

`tests/test_sql_dml_exec.c` (run via `make test-sql-dml-exec`) covers UPDATE
and DELETE execution against the mutable table store:

- UPDATE with `=`, `<>`, `<`, `>`, `<=`, `>=`, `LIKE` predicates and AND
  chains, a qualified target alias (`x.id`), a WHERE keyword inside a SET
  string literal, update-all with no WHERE, and truthful `rows=N` counts;
- DELETE with equality and string predicates, `RETURNING` excluded from the
  clause, truthful counts, and idempotent re-deletion (`rows=0`);
- **the zero-condition DELETE guard**: `DELETE FROM t`, a WHERE clause that
  parsed to zero conditions (`NOT`, parentheses), and conditions that do not
  match the raw clause (OR, malformed tails, IN) all refuse with no rows
  changed; a hand-built zero-condition AST refuses too;
- the zero-assignment UPDATE refusal at the executor (the parser already
  refuses it), and refusals for expression SET values, a SET value that names
  a column, unknown columns, `NOT LIKE`, `IS`, `BETWEEN`, and `IN`;
- WRITE-permission enforcement: a non-operator without a grant is refused and
  nothing changes; a grant on the table's FNV-1a resource id allows the
  statement.

Not covered: the pgwire prepared-statement cache, window functions, and
`INSERT ... SELECT` execution. INSERT is still wired to the column store, not
the row store, so SQL INSERT does not yet populate the store that UPDATE and
DELETE execute against; the row store must be populated through
`qihse_uwp_sql_table_store()`. UPDATE/DELETE are also not integrated with the
transaction manager, so ROLLBACK does not undo them.

