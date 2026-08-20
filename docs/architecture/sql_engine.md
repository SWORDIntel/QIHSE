# QIHSE SQL Engine & Query Processing Architecture

## 1. Overview

QIHSE includes a native C99 SQL engine that provides full relational query processing on top of the multi-model storage engines. The SQL engine consists of a parser, query executors, a cost-based optimizer, and a schema registry.

## 2. SQL Parser

**Files**: `include/qihse_sql_parser.h`, `src/tractable/qihse_sql_parser.c`

The parser tokenizes and builds an AST from SQL text. Supported statement types:

### DML
- `SELECT` with column list, FROM, JOIN, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, OFFSET, DISTINCT
- `INSERT INTO ... VALUES ...`
- `UPDATE ... SET ... WHERE ...`
- `DELETE FROM ... WHERE ...`

### DDL
- `CREATE TABLE name (col TYPE, ...)` with types: INT, BIGINT, FLOAT, DOUBLE, VARCHAR(n), TEXT, BOOL, TIMESTAMP, VECTOR(n)
- `ALTER TABLE name ADD/DROP/RENAME COLUMN ...`
- `ALTER TABLE name RENAME TO new_name`
- `CREATE INDEX name ON table (col, ...)`
- `DROP INDEX name`
- `DROP TABLE name`

### JOIN Types
- `INNER JOIN ... ON ...`
- `LEFT [OUTER] JOIN ... ON ...`
- `RIGHT [OUTER] JOIN ... ON ...`
- `FULL [OUTER] JOIN ... ON ...`
- `CROSS JOIN ...`

### Aggregates
- `SUM(expr)`, `COUNT(expr)`, `COUNT(*)`, `AVG(expr)`, `MIN(expr)`, `MAX(expr)`
- `GROUP BY col, ...`
- `HAVING condition`
- `DISTINCT`

### Subqueries
- Scalar subqueries in SELECT list: `(SELECT col FROM t WHERE ...)`
- `WHERE col IN (SELECT ...)`
- `WHERE EXISTS (SELECT ...)`
- Correlated subqueries referencing outer query

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
- Per-table row count estimates
- Per-column histograms with most-common-value (MCV) tracking
- Per-column distinct value count

### Cardinality Estimation
- Equality filter: `selectivity = 1 / distinct_values` (or MCV frequency)
- Range filter: `selectivity = range / (max - min)`
- Combined filters: multiply selectivities (independence assumption)

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

In-memory catalog of table and index definitions:

- `qihse_schema_create_table(name, columns, num_columns)`
- `qihse_schema_drop_table(name)`
- `qihse_schema_alter_table_add_column(name, column_def)`
- `qihse_schema_alter_table_drop_column(name, col_name)`
- `qihse_schema_alter_table_rename_column(name, old_name, new_name)`
- `qihse_schema_alter_table_rename(name, new_name)`
- `qihse_schema_create_index(name, table, columns, num_columns, index_type)`
- `qihse_schema_drop_index(name)`
- `qihse_schema_get_table(name)` — returns table definition
- `qihse_schema_get_index(name)` — returns index definition

## 6. Prepared Statements (pgwire)

The PostgreSQL wire protocol server (`src/spinnaker/qihse_pg_wire.c`) supports the extended query protocol:

- **Parse**: Client sends query text with parameter placeholders ($1, $2, ...), server parses and caches the AST
- **Bind**: Client sends parameter values, server substitutes into the cached AST
- **Describe**: Server returns row description (column names and types)
- **Execute**: Server executes the bound statement and returns result rows
- **Close**: Server frees the prepared statement
- **Sync**: Server sends ReadyForQuery

The statement cache holds up to 64 prepared statements with LRU eviction.

## 7. Testing

Tests are in `tests/test_sql_completeness.c` (22 tests):

- SQL parsing: SELECT, INSERT, UPDATE, DELETE, CREATE TABLE, ALTER TABLE, CREATE INDEX, DROP TABLE
- JOIN parsing: INNER, LEFT, RIGHT, CROSS, FULL
- Aggregate parsing: GROUP BY, HAVING, SUM, COUNT, AVG, MIN, MAX, DISTINCT
- Subquery parsing: IN, EXISTS, scalar
- Set operations: UNION, INTERSECT, EXCEPT
- ORDER BY: multi-key, ASC/DESC
- Join execution: hash join, nested-loop join
- Aggregate execution: GROUP BY + SUM
- Sort execution: multi-key
- Schema registry: CREATE TABLE + INDEX
- Cost-based optimizer: plan building
