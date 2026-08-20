#ifndef QIHSE_CLICKHOUSE_SQL_H
#define QIHSE_CLICKHOUSE_SQL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "qihse_column.h"
#include "qihse_auth.h"
#include "qihse_http_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * ClickHouse SQL Dialect, MergeTree Engine, Materialized Views,
 * Dictionaries, Distributed Tables, HTTP/Native protocols.
 *
 * This module implements a ClickHouse-compatible layer over the QIHSE
 * columnar store.  It is self-contained C99 and compiles with
 *   gcc -std=c99 -Wall -Wextra -D_GNU_SOURCE
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * ClickHouse data types (superset of the column-store native types)
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_TYPE_UNKNOWN     = 0,
    QIHSE_CH_TYPE_INT8        = 1,
    QIHSE_CH_TYPE_INT16       = 2,
    QIHSE_CH_TYPE_INT32       = 3,
    QIHSE_CH_TYPE_INT64       = 4,
    QIHSE_CH_TYPE_UINT8       = 5,
    QIHSE_CH_TYPE_UINT16      = 6,
    QIHSE_CH_TYPE_UINT32      = 7,
    QIHSE_CH_TYPE_UINT64      = 8,
    QIHSE_CH_TYPE_FLOAT32     = 9,
    QIHSE_CH_TYPE_FLOAT64     = 10,
    QIHSE_CH_TYPE_STRING      = 11,
    QIHSE_CH_TYPE_FIXEDSTRING = 12,
    QIHSE_CH_TYPE_DATE        = 13,
    QIHSE_CH_TYPE_DATETIME    = 14,
    QIHSE_CH_TYPE_DATETIME64  = 15,
    QIHSE_CH_TYPE_UUID        = 16,
    QIHSE_CH_TYPE_BOOL        = 17,
    QIHSE_CH_TYPE_DECIMAL     = 18,
    QIHSE_CH_TYPE_ARRAY       = 19,
    QIHSE_CH_TYPE_TUPLE       = 20,
    QIHSE_CH_TYPE_MAP         = 21,
    QIHSE_CH_TYPE_NESTED      = 22,
    QIHSE_CH_TYPE_LOWCARDINALITY = 23,
    QIHSE_CH_TYPE_ENUM8       = 24,
    QIHSE_CH_TYPE_ENUM16      = 25,
    QIHSE_CH_TYPE_IPV4        = 26,
    QIHSE_CH_TYPE_IPV6        = 27,
    QIHSE_CH_TYPE_JSON        = 28,
    QIHSE_CH_TYPE_AGGREGATEFUNCTION = 29,
    QIHSE_CH_TYPE_SIMPLEAGGREGATEFUNCTION = 30
} qihse_ch_data_type_t;

/* -------------------------------------------------------------------------
 * MergeTree family + other ClickHouse engines
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_ENGINE_NONE                  = 0,
    QIHSE_CH_ENGINE_MERGETREE             = 1,
    QIHSE_CH_ENGINE_REPLACING_MERGETREE   = 2,
    QIHSE_CH_ENGINE_SUMMING_MERGETREE     = 3,
    QIHSE_CH_ENGINE_AGGREGATING_MERGETREE = 4,
    QIHSE_CH_ENGINE_COLLAPSING_MERGETREE  = 5,
    QIHSE_CH_ENGINE_VERSIONED_COLLAPSING  = 6,
    QIHSE_CH_ENGINE_TINYLOG               = 7,
    QIHSE_CH_ENGINE_LOG                   = 8,
    QIHSE_CH_ENGINE_MEMORY                = 9,
    QIHSE_CH_ENGINE_NULL                  = 10,
    QIHSE_CH_ENGINE_DISTRIBUTED           = 11,
    QIHSE_CH_ENGINE_MERGE                 = 12,
    QIHSE_CH_ENGINE_BUFFER                = 13,
    QIHSE_CH_ENGINE_SET                   = 14,
    QIHSE_CH_ENGINE_JOIN                  = 15,
    QIHSE_CH_ENGINE_URL                   = 16,
    QIHSE_CH_ENGINE_VIEW                  = 17,
    QIHSE_CH_ENGINE_MATERIALIZED_VIEW     = 18,
    QIHSE_CH_ENGINE_LIVE_VIEW             = 19,
    QIHSE_CH_ENGINE_DICTIONARY            = 20
} qihse_ch_engine_t;

/* -------------------------------------------------------------------------
 * Data-skipping index kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_SKIP_NONE         = 0,
    QIHSE_CH_SKIP_MINMAX       = 1,
    QIHSE_CH_SKIP_SET          = 2,
    QIHSE_CH_SKIP_BLOOM_FILTER = 3,
    QIHSE_CH_SKIP_NGRAMBF_V1   = 4,
    QIHSE_CH_SKIP_TOKENBF_V1   = 5
} qihse_ch_skip_index_type_t;

/* -------------------------------------------------------------------------
 * Output formats
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_FMT_UNKNOWN                = 0,
    QIHSE_CH_FMT_TABSEPARATED           = 1,
    QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES = 2,
    QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES_AND_TYPES = 3,
    QIHSE_CH_FMT_CSV                    = 4,
    QIHSE_CH_FMT_CSV_WITH_NAMES         = 5,
    QIHSE_CH_FMT_JSON                   = 6,
    QIHSE_CH_FMT_JSON_EACH_ROW          = 7,
    QIHSE_CH_FMT_JSON_COMPACT           = 8,
    QIHSE_CH_FMT_JSON_COMPACT_EACH_ROW  = 9,
    QIHSE_CH_FMT_TSV                    = 10,
    QIHSE_CH_FMT_TSV_WITH_NAMES         = 11,
    QIHSE_CH_FMT_VALUES                 = 12,
    QIHSE_CH_FMT_VERTICAL               = 13,
    QIHSE_CH_FMT_PRETTY                 = 14,
    QIHSE_CH_FMT_PRETTY_COMPACT         = 15,
    QIHSE_CH_FMT_PRETTY_COMPACT_NOESC   = 16,
    QIHSE_CH_FMT_RAW                    = 17,
    QIHSE_CH_FMT_NULL                   = 18,
    QIHSE_CH_FMT_XML                    = 19,
    QIHSE_CH_FMT_MARKDOWN               = 20
} qihse_ch_format_t;

/* -------------------------------------------------------------------------
 * Statement types (ClickHouse dialect)
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_STMT_UNKNOWN        = 0,
    QIHSE_CH_STMT_SELECT         = 1,
    QIHSE_CH_STMT_INSERT         = 2,
    QIHSE_CH_STMT_CREATE_TABLE   = 3,
    QIHSE_CH_STMT_CREATE_MV      = 4,
    QIHSE_CH_STMT_CREATE_DICT    = 5,
    QIHSE_CH_STMT_ALTER          = 6,
    QIHSE_CH_STMT_OPTIMIZE       = 7,
    QIHSE_CH_STMT_TRUNCATE       = 8,
    QIHSE_CH_STMT_DROP           = 9,
    QIHSE_CH_STMT_SYSTEM         = 10,
    QIHSE_CH_STMT_SHOW           = 11,
    QIHSE_CH_STMT_DESCRIBE       = 12,
    QIHSE_CH_STMT_EXISTS         = 13,
    QIHSE_CH_STMT_USE            = 14,
    QIHSE_CH_STMT_SET            = 15
} qihse_ch_stmt_type_t;

/* -------------------------------------------------------------------------
 * ALTER TABLE action kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_ALTER_NONE              = 0,
    QIHSE_CH_ALTER_ADD_COLUMN        = 1,
    QIHSE_CH_ALTER_DROP_COLUMN       = 2,
    QIHSE_CH_ALTER_MODIFY_COLUMN     = 3,
    QIHSE_CH_ALTER_RENAME_COLUMN     = 4,
    QIHSE_CH_ALTER_ADD_INDEX         = 5,
    QIHSE_CH_ALTER_DROP_INDEX        = 6,
    QIHSE_CH_ALTER_MATERIALIZE_INDEX = 7,
    QIHSE_CH_ALTER_CLEAR_INDEX       = 8,
    QIHSE_CH_ALTER_ADD_PROJECTION    = 9,
    QIHSE_CH_ALTER_DROP_PROJECTION   = 10,
    QIHSE_CH_ALTER_MATERIALIZE_PROJ  = 11,
    QIHSE_CH_ALTER_DROP_DETACHED_PART = 12,
    QIHSE_CH_ALTER_ATTACH_PARTITION  = 13,
    QIHSE_CH_ALTER_DETACH_PARTITION  = 14,
    QIHSE_CH_ALTER_FREEZE_PARTITION  = 15,
    QIHSE_CH_ALTER_FETCH_PARTITION   = 16,
    QIHSE_CH_ALTER_UPDATE            = 17,  /* mutation */
    QIHSE_CH_ALTER_DELETE            = 18   /* mutation / lightweight delete */
} qihse_ch_alter_action_t;

/* -------------------------------------------------------------------------
 * SYSTEM command kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_SYS_UNKNOWN                = 0,
    QIHSE_CH_SYS_RELOAD_CONFIG          = 1,
    QIHSE_CH_SYS_RELOAD_DICTIONARY      = 2,
    QIHSE_CH_SYS_RELOAD_EMBEDDED_DICT   = 3,
    QIHSE_CH_SYS_FLUSH_LOGS             = 4,
    QIHSE_CH_SYS_FLUSH_DISTRIBUTED      = 5,
    QIHSE_CH_SYS_FLUSH_CACHE            = 6,
    QIHSE_CH_SYS_STOP_MERGES            = 7,
    QIHSE_CH_SYS_START_MERGES           = 8,
    QIHSE_CH_SYS_STOP_FETCHES           = 9,
    QIHSE_CH_SYS_START_FETCHES          = 10,
    QIHSE_CH_SYS_STOP_REPL_SENDS        = 11,
    QIHSE_CH_SYS_START_REPL_SENDS       = 12,
    QIHSE_CH_SYS_STOP_REPL_QUEUES       = 13,
    QIHSE_CH_SYS_START_REPL_QUEUES      = 14,
    QIHSE_CH_SYS_SYNC_REPLICA           = 15,
    QIHSE_CH_SYS_RESTART_REPLICA        = 16,
    QIHSE_CH_SYS_RESTART_REPLICAS       = 17,
    QIHSE_CH_SYS_DROP_MARK_CACHE        = 18,
    QIHSE_CH_SYS_DROP_UNCOMPRESSED_CACHE = 19,
    QIHSE_CH_SYS_DROP_MMAPPED_CACHE     = 20,
    QIHSE_CH_SYS_DROP_QUERY_CACHE       = 21,
    QIHSE_CH_SYS_DROP_DNS_CACHE         = 22,
    QIHSE_CH_SYS_DROP_CONCURRENT        = 23
} qihse_ch_system_cmd_t;

/* -------------------------------------------------------------------------
 * SHOW sub-kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_SHOW_UNKNOWN    = 0,
    QIHSE_CH_SHOW_TABLES     = 1,
    QIHSE_CH_SHOW_DATABASES  = 2,
    QIHSE_CH_SHOW_COLUMNS    = 3,
    QIHSE_CH_SHOW_CREATE     = 4,
    QIHSE_CH_SHOW_PROCESSLIST = 5,
    QIHSE_CH_SHOW_SETTINGS   = 6
} qihse_ch_show_kind_t;

/* -------------------------------------------------------------------------
 * Native protocol packet kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_NATIVE_HELLO        = 0,
    QIHSE_CH_NATIVE_QUERY        = 1,
    QIHSE_CH_NATIVE_DATA         = 2,
    QIHSE_CH_NATIVE_EXCEPTION    = 3,
    QIHSE_CH_NATIVE_PROGRESS     = 4,
    QIHSE_CH_NATIVE_END_OF_STREAM = 5
} qihse_ch_native_packet_t;

/* -------------------------------------------------------------------------
 * Column definition (ClickHouse)
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  name;
    qihse_ch_data_type_t type;
    char*  type_str;        /* original type text, e.g. "Nullable(String)" */
    char*  default_expr;    /* DEFAULT <expr> */
    char*  codec;           /* CODEC(...) */
    char*  ttl;             /* column-level TTL */
    int    not_null;
} qihse_ch_column_def_t;

/* -------------------------------------------------------------------------
 * Data-skipping index definition
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  name;
    qihse_ch_skip_index_type_t type;
    char*  expr;            /* indexed expression */
    char*  params;          /* raw params, e.g. "0.01" for bloom filter */
} qihse_ch_skip_index_t;

/* -------------------------------------------------------------------------
 * A MergeTree granule mark (sparse primary-key index entry)
 * ------------------------------------------------------------------------- */
typedef struct {
    int64_t  mark_index;     /* ordinal of the mark */
    uint32_t rows_in_granule;
    /* min/max of the first ORDER BY column within this granule for pruning */
    int64_t  key_min;
    int64_t  key_max;
} qihse_ch_granule_t;

/* -------------------------------------------------------------------------
 * A MergeTree part
 * ------------------------------------------------------------------------- */
typedef struct qihse_ch_part_s {
    char*    name;            /* e.g. "20230801_1_1_0" */
    char*    partition_value; /* partition key value (string form) */
    uint64_t rows;
    uint64_t bytes_on_disk;
    int      active;          /* 1 = active, 0 = detached/inactive */
    int64_t  min_block;       /* merge block numbers */
    int64_t  max_block;
    int64_t  level;
    int64_t  mutation;        /* mutation version applied */
    /* sparse primary-key index (one entry per granule) */
    qihse_ch_granule_t* granules;
    size_t  num_granules;
    /* min/max of the first ORDER BY column across the whole part (zone map) */
    int64_t  part_key_min;
    int64_t  part_key_max;
    struct qihse_ch_part_s* next;
} qihse_ch_part_t;

/* -------------------------------------------------------------------------
 * Distributed table descriptor
 * ------------------------------------------------------------------------- */
typedef struct {
    char* cluster;
    char* db;
    char* table;
    char* sharding_key;   /* raw expression */
} qihse_ch_distributed_t;

/* -------------------------------------------------------------------------
 * ClickHouse table (engine metadata + parts)
 * ------------------------------------------------------------------------- */
typedef struct qihse_ch_table_s {
    char*    name;
    char*    database;
    qihse_ch_engine_t engine;
    char*    engine_args;        /* raw ENGINE = X(args) text */

    qihse_ch_column_def_t* columns;
    size_t num_columns;

    char**  order_by;            /* ORDER BY column names */
    size_t  num_order_by;
    char*   partition_by;        /* raw PARTITION BY expr */
    char**  primary_key;         /* PRIMARY KEY columns */
    size_t  num_primary_key;
    char*   sample_by;           /* raw SAMPLE BY expr */
    char*   ttl;                 /* raw TTL expr */
    char*   settings;            /* raw SETTINGS text */

    qihse_ch_skip_index_t* skip_indices;
    size_t num_skip_indices;

    /* MergeTree parts */
    qihse_ch_part_t* parts;
    pthread_mutex_t  lock;

    /* Distributed descriptor (if engine == Distributed) */
    qihse_ch_distributed_t* distributed;

    /* Backing column-store columns are created lazily on first insert. */
    int    store_initialized;

    struct qihse_ch_table_s* next;
} qihse_ch_table_t;

/* -------------------------------------------------------------------------
 * Materialized view
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  name;
    char*  database;
    char*  target_table;   /* TO target_table; NULL if table-engine MV */
    int    populate;       /* POPULATE flag */
    char*  source_table;   /* inferred FROM table of the SELECT */
    char*  select_sql;     /* raw SELECT text */
    int    is_aggregate;   /* targets Summing/AggregatingMergeTree */
    qihse_ch_table_t* table; /* owned table for table-engine MVs (NULL if TO) */
} qihse_ch_mv_t;

/* -------------------------------------------------------------------------
 * Dictionary attribute
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  name;
    qihse_ch_data_type_t type;
    char*  type_str;
    char*  default_expr;
} qihse_ch_dict_attr_t;

/* -------------------------------------------------------------------------
 * External dictionary
 * ------------------------------------------------------------------------- */
typedef struct qihse_ch_dictionary_s {
    char*  name;
    char*  database;
    char*  source;          /* raw SOURCE(...) text */
    char*  layout;          /* raw LAYOUT(...) text */
    char*  lifetime;        /* raw LIFETIME(...) text */
    char*  primary_key;     /* PRIMARY KEY column name */
    qihse_ch_dict_attr_t* attrs;
    size_t num_attrs;
    /* simple in-memory cache: key(string) -> value(string) */
    char** cache_keys;
    char** cache_vals;
    size_t cache_count;
    size_t cache_cap;
    int64_t last_load_ms;
    int64_t lifetime_min_ms;
    struct qihse_ch_dictionary_s* next;
} qihse_ch_dictionary_t;

/* -------------------------------------------------------------------------
 * Catalog: tables, materialized views, dictionaries
 * ------------------------------------------------------------------------- */
typedef struct {
    qihse_ch_table_t*      tables;
    qihse_ch_mv_t*         mvs;
    qihse_ch_dictionary_t* dictionaries;
    char   current_database[64];
    pthread_mutex_t lock;
} qihse_ch_catalog_t;

/* -------------------------------------------------------------------------
 * Result-set cell
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_CELL_NULL  = 0,
    QIHSE_CH_CELL_INT   = 1,
    QIHSE_CH_CELL_UINT  = 2,
    QIHSE_CH_CELL_FLOAT = 3,
    QIHSE_CH_CELL_STR   = 4
} qihse_ch_cell_kind_t;

typedef struct {
    qihse_ch_cell_kind_t kind;
    int64_t  i64;
    double   f64;
    char*    str;       /* owned for STR */
} qihse_ch_cell_t;

/* -------------------------------------------------------------------------
 * Result set
 * ------------------------------------------------------------------------- */
typedef struct {
    char**  column_names;
    qihse_ch_data_type_t* column_types;
    char**  column_type_names;   /* ClickHouse type names */
    size_t  num_columns;
    qihse_ch_cell_t** rows;      /* array of row arrays */
    size_t  num_rows;
    int     affected;            /* rows affected for DML */
    char*   error;               /* error message (NULL on success) */
} qihse_ch_result_t;

/* -------------------------------------------------------------------------
 * ClickHouse SQL AST
 * ------------------------------------------------------------------------- */
typedef struct qihse_ch_ast_s {
    qihse_ch_stmt_type_t stmt_type;

    /* CREATE TABLE / CREATE MV / CREATE DICT */
    char*  name;
    char*  database;
    int    if_not_exists;
    qihse_ch_engine_t engine;
    char*  engine_args;
    qihse_ch_column_def_t* columns;
    size_t num_columns;
    char** order_by;
    size_t num_order_by;
    char*  partition_by;
    char** primary_key;
    size_t num_primary_key;
    char*  sample_by;
    char*  ttl;
    char*  settings;
    qihse_ch_skip_index_t* skip_indices;
    size_t num_skip_indices;

    /* CTAS / copy schema */
    int    ctas;                 /* CREATE TABLE ... AS SELECT */
    char*  as_source_table;      /* CREATE TABLE ... AS source_table */
    char*  as_select_sql;        /* CREATE TABLE ... AS SELECT ... */

    /* CREATE MATERIALIZED VIEW */
    int    mv_populate;
    char*  mv_target_table;      /* TO target_table */

    /* CREATE DICTIONARY */
    qihse_ch_dict_attr_t* dict_attrs;
    size_t num_dict_attrs;
    char*  dict_source;
    char*  dict_layout;
    char*  dict_lifetime;
    char*  dict_primary_key;

    /* ALTER */
    char*  alter_table;
    qihse_ch_alter_action_t alter_action;
    char*  alter_column;         /* column/partition name */
    char*  alter_new_name;       /* RENAME new name */
    qihse_ch_column_def_t* alter_add_column; /* ADD COLUMN def */
    qihse_ch_data_type_t alter_modify_type;
    char*  alter_modify_type_str;
    char*  alter_set_expr;       /* UPDATE SET ... */
    char*  alter_where;          /* UPDATE/DELETE WHERE */
    char*  alter_index_name;     /* ADD/DROP INDEX name */
    qihse_ch_skip_index_t alter_index; /* ADD INDEX def */

    /* OPTIMIZE */
    int    optimize_final;
    int    optimize_deduplicate;

    /* TRUNCATE / DROP */
    int    if_exists;
    int    drop_sync;

    /* SYSTEM */
    qihse_ch_system_cmd_t system_cmd;
    char*  system_arg;           /* e.g. dictionary name */

    /* SHOW */
    qihse_ch_show_kind_t show_kind;
    char*  show_from;            /* FROM database/table */
    char*  show_like;            /* LIKE pattern */

    /* DESCRIBE / EXISTS / USE */
    /* name field reused */

    /* SET */
    char*  set_param;
    char*  set_value;

    /* SELECT (raw text preserved; structured parse is best-effort) */
    char*  select_sql;
    char*  select_prewhere;      /* PREWHERE expr */
    char*  select_sample;        /* SAMPLE expr */
    int    select_final;         /* FINAL */
    int    select_with_totals;   /* WITH TOTALS */
    int    select_with_cube;     /* WITH CUBE */
    int    select_with_rollup;   /* WITH ROLLUP */
    char** array_join_cols;      /* ARRAY JOIN columns */
    size_t num_array_join;

    /* INSERT */
    char*  insert_table;
    char** insert_columns;
    size_t num_insert_columns;
    char*  insert_format;        /* FORMAT Xxx */
    char*  insert_data;          /* raw data body */
    int    insert_is_values;     /* VALUES inline */

    char* raw_sql;
} qihse_ch_ast_t;

/* =========================================================================
 * Public API
 * ========================================================================= */

/* --- Catalog ------------------------------------------------------------- */
qihse_ch_catalog_t* qihse_ch_catalog_create(void);
void qihse_ch_catalog_destroy(qihse_ch_catalog_t* cat);
qihse_ch_table_t* qihse_ch_catalog_find_table(qihse_ch_catalog_t* cat,
                                              const char* db, const char* name);
qihse_ch_mv_t* qihse_ch_catalog_find_mv(qihse_ch_catalog_t* cat,
                                        const char* db, const char* name);
qihse_ch_dictionary_t* qihse_ch_catalog_find_dict(qihse_ch_catalog_t* cat,
                                                  const char* db, const char* name);

/* --- Parser -------------------------------------------------------------- */
qihse_ch_ast_t* qihse_ch_parse(const char* sql);
void qihse_ch_ast_free(qihse_ch_ast_t* ast);
const char* qihse_ch_stmt_name(qihse_ch_stmt_type_t t);
const char* qihse_ch_engine_name(qihse_ch_engine_t e);
const char* qihse_ch_data_type_name(qihse_ch_data_type_t t);
qihse_ch_data_type_t qihse_ch_data_type_from_str(const char* s);
qihse_ch_format_t qihse_ch_format_from_str(const char* s);
const char* qihse_ch_format_name(qihse_ch_format_t f);

/* --- Result set ---------------------------------------------------------- */
qihse_ch_result_t* qihse_ch_result_create(size_t num_columns);
void qihse_ch_result_free(qihse_ch_result_t* r);
qihse_ch_result_t* qihse_ch_result_error(const char* msg);
void qihse_ch_result_set_str(qihse_ch_result_t* r, size_t row, size_t col,
                             const char* val);
void qihse_ch_result_set_int(qihse_ch_result_t* r, size_t row, size_t col,
                             int64_t val);
void qihse_ch_result_set_float(qihse_ch_result_t* r, size_t row, size_t col,
                               double val);
void qihse_ch_result_set_null(qihse_ch_result_t* r, size_t row, size_t col);
int qihse_ch_result_ensure_rows(qihse_ch_result_t* r, size_t n);

/* --- Formatters ---------------------------------------------------------- */
char* qihse_ch_format_result(const qihse_ch_result_t* r, qihse_ch_format_t fmt);
char* qihse_ch_format_tsv(const qihse_ch_result_t* r, int with_names, int with_types);
char* qihse_ch_format_csv(const qihse_ch_result_t* r, int with_names);
char* qihse_ch_format_json(const qihse_ch_result_t* r);
char* qihse_ch_format_json_each_row(const qihse_ch_result_t* r);
char* qihse_ch_format_pretty(const qihse_ch_result_t* r, int compact);
char* qihse_ch_format_vertical(const qihse_ch_result_t* r);
char* qihse_ch_format_values(const qihse_ch_result_t* r);
char* qihse_ch_format_xml(const qihse_ch_result_t* r);
char* qihse_ch_format_markdown(const qihse_ch_result_t* r);

/* --- INSERT data parsing ------------------------------------------------- */
/* Parse "INSERT INTO t FORMAT X\n<data>" or "INSERT INTO t VALUES (...),(...)".
 * Returns a freshly-allocated result set of parsed rows (caller frees). */
qihse_ch_result_t* qihse_ch_parse_insert_data(const char* data,
                                              qihse_ch_format_t fmt,
                                              const qihse_ch_table_t* table);

/* --- Executor ------------------------------------------------------------ */
qihse_ch_result_t* qihse_ch_execute(qihse_ch_catalog_t* cat,
                                    qihse_column_store_t* store,
                                    const qihse_ch_ast_t* ast,
                                    qihse_user_t* user);

/* --- MergeTree engine ---------------------------------------------------- */
/* Create a new part from an inserted block of rows. */
qihse_ch_part_t* qihse_ch_part_create(const char* partition_value,
                                      uint64_t rows, int64_t block,
                                      const int64_t* order_keys,
                                      size_t num_keys);
void qihse_ch_part_free(qihse_ch_part_t* p);
void qihse_ch_table_add_part(qihse_ch_table_t* tbl, qihse_ch_part_t* p);

/* Build sparse primary-key index (granules) for a part. */
void qihse_ch_part_build_index(qihse_ch_part_t* p, const int64_t* keys,
                               size_t n, uint32_t granule_size);

/* Partition pruning: returns array of active parts matching the partition
 * condition.  Caller frees the array (not the parts). */
qihse_ch_part_t** qihse_ch_partition_prune(qihse_ch_table_t* tbl,
                                           const char* partition_cond,
                                           size_t* out_count);

/* Background merge: choose best parts to merge and merge them. */
int qihse_ch_merge_parts(qihse_ch_table_t* tbl);

/* TTL expiration: drop parts whose TTL has elapsed. */
int qihse_ch_ttl_expire(qihse_ch_table_t* tbl, int64_t now_unix);

/* Mutation: apply UPDATE/DELETE to all active parts. */
int qihse_ch_mutate(qihse_ch_table_t* tbl, qihse_ch_alter_action_t action,
                    const char* set_expr, const char* where_expr);

/* --- Materialized views -------------------------------------------------- */
/* Trigger all MVs watching `source_table` after an insert. */
int qihse_ch_mv_trigger(qihse_ch_catalog_t* cat,
                        qihse_column_store_t* store,
                        const char* source_table,
                        qihse_user_t* user);
/* Backfill source into MV (POPULATE). */
int qihse_ch_mv_populate(qihse_ch_catalog_t* cat,
                         qihse_column_store_t* store,
                         qihse_ch_mv_t* mv,
                         qihse_user_t* user);

/* --- Dictionaries -------------------------------------------------------- */
const char* qihse_ch_dict_get(qihse_ch_catalog_t* cat, const char* dict,
                              const char* attr, const char* key);
int qihse_ch_dict_has(qihse_ch_catalog_t* cat, const char* dict, const char* key);
void qihse_ch_dict_invalidate(qihse_ch_dictionary_t* d);

/* --- Distributed tables -------------------------------------------------- */
/* Route a query to shards based on sharding_key; returns number of shards
 * that would be contacted (skeleton). */
int qihse_ch_distributed_route(qihse_ch_table_t* tbl, const char* sharding_key_val,
                               int* out_shard, int num_shards);

/* --- HTTP protocol ------------------------------------------------------- */
http_response_t* qihse_clickhouse_handle_query(const http_request_t* req,
                                               void* user_data);
int qihse_clickhouse_register_routes(qihse_http_server_t* srv, void* user_data);

/* Context bundle passed as user_data to the HTTP handler. */
typedef struct {
    qihse_ch_catalog_t*    catalog;
    qihse_column_store_t*  store;
    qihse_user_t*          user;
} qihse_ch_http_ctx_t;

/* --- Native protocol (skeleton) ------------------------------------------ */
typedef struct {
    uint16_t port;
    int fd;
    volatile int running;
    pthread_t thread;
    qihse_ch_catalog_t*   catalog;
    qihse_column_store_t* store;
    qihse_user_t*         user;
} qihse_ch_native_server_t;

qihse_ch_native_server_t* qihse_ch_native_server_create(uint16_t port,
                                                        qihse_ch_catalog_t* cat,
                                                        qihse_column_store_t* store,
                                                        qihse_user_t* user);
int qihse_ch_native_server_start(qihse_ch_native_server_t* srv);
int qihse_ch_native_server_stop(qihse_ch_native_server_t* srv);
void qihse_ch_native_server_destroy(qihse_ch_native_server_t* srv);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLICKHOUSE_SQL_H */
