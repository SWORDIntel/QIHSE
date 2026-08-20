#ifndef QIHSE_CLICKHOUSE_HTTP_H
#define QIHSE_CLICKHOUSE_HTTP_H

#include "qihse_http_api.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * ClickHouse output formats
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CH_FORMAT_TABSEPARATED  = 0,
    QIHSE_CH_FORMAT_JSON          = 1,
    QIHSE_CH_FORMAT_JSONEACHROW   = 2,
    QIHSE_CH_FORMAT_CSV           = 3,
    QIHSE_CH_FORMAT_CSVWITHNAMES  = 4,
    QIHSE_CH_FORMAT_VALUES        = 5,
    QIHSE_CH_FORMAT_PRETTY        = 6,
    QIHSE_CH_FORMAT_RAW           = 7
} qihse_ch_format_t;

/* -------------------------------------------------------------------------
 * ClickHouse system table metadata
 * ------------------------------------------------------------------------- */
typedef struct {
    char* database;
    char* name;
    char* engine;
    char* ordering_key;
    int   is_temporary;
} qihse_ch_table_info_t;

typedef struct {
    char* database;
    char* name;
} qihse_ch_database_info_t;

typedef struct {
    char* database;
    char* table;
    char* name;
    char* type;
    int   position;
} qihse_ch_column_info_t;

typedef struct {
    char* name;
    char* value;
    char* description;
    char* type;
} qihse_ch_setting_info_t;

/* ClickHouse HTTP protocol handler - processes queries in ClickHouse format */
http_response_t* qihse_clickhouse_handle_query(const http_request_t* req, void* user_data);

/* Format query results as tab-separated values (TSV) */
char* qihse_clickhouse_format_tsv(const char* query, void* column_store);

/* Format query results as JSONEachRow */
char* qihse_clickhouse_format_json_each_row(const char* query, void* column_store);

/* Format query results as JSON */
char* qihse_clickhouse_format_json(const char* query, void* column_store);

/* Format query results as CSV */
char* qihse_clickhouse_format_csv(const char* query, void* column_store);

/* Format query results as Values (INSERT format) */
char* qihse_clickhouse_format_values(const char* query, void* column_store);

/* Register ClickHouse HTTP routes on an HTTP server */
int qihse_clickhouse_register_routes(qihse_http_server_t* srv, void* column_store);

/* -------------------------------------------------------------------------
 * ClickHouse query dispatch helpers
 * ------------------------------------------------------------------------- */

/* Detect output format from query string parameters */
qihse_ch_format_t qihse_clickhouse_detect_format(const char* query_string);

/* Handle SHOW TABLES / SHOW DATABASES / SHOW COLUMNS */
http_response_t* qihse_clickhouse_handle_show(const char* query, qihse_ch_format_t fmt);

/* Handle DESCRIBE TABLE */
http_response_t* qihse_clickhouse_handle_describe(const char* query, qihse_ch_format_t fmt);

/* Handle CREATE DATABASE / CREATE TABLE with MergeTree engines */
http_response_t* qihse_clickhouse_handle_create(const char* query, qihse_ch_format_t fmt);

/* Handle DROP TABLE / DROP DATABASE */
http_response_t* qihse_clickhouse_handle_drop(const char* query, qihse_ch_format_t fmt);

/* Handle INSERT INTO ... FORMAT Values/CSV/JSON */
http_response_t* qihse_clickhouse_handle_insert(const char* query, const char* body,
                                                 qihse_ch_format_t fmt);

/* Handle system table queries (system.tables, system.databases, etc.) */
http_response_t* qihse_clickhouse_handle_system_query(const char* query, qihse_ch_format_t fmt);

/* Handle /ping health-check */
http_response_t* qihse_clickhouse_handle_ping(void);

#ifdef __cplusplus
}
#endif
#endif
