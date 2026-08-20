#ifndef QIHSE_CLICKHOUSE_HTTP_H
#define QIHSE_CLICKHOUSE_HTTP_H

#include "qihse_http_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ClickHouse HTTP protocol handler - processes queries in ClickHouse format */
http_response_t* qihse_clickhouse_handle_query(const http_request_t* req, void* user_data);

/* Format query results as tab-separated values (TSV) */
char* qihse_clickhouse_format_tsv(const char* query, void* column_store);

/* Format query results as JSONEachRow */
char* qihse_clickhouse_format_json_each_row(const char* query, void* column_store);

/* Format query results as JSON */
char* qihse_clickhouse_format_json(const char* query, void* column_store);

/* Register ClickHouse HTTP routes on an HTTP server */
int qihse_clickhouse_register_routes(qihse_http_server_t* srv, void* column_store);

#ifdef __cplusplus
}
#endif
#endif
