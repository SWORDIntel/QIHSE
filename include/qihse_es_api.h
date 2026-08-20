#ifndef QIHSE_ES_API_H
#define QIHSE_ES_API_H

#include "qihse_http_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Elasticsearch _search API handler */
http_response_t* qihse_es_handle_search(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_index(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_get(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_bulk(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_health(const http_request_t* req, void* user_data);

/* Register Elasticsearch-compatible routes on an HTTP server */
int qihse_es_register_routes(qihse_http_server_t* srv, void* fts_index, void* vector_db);

#ifdef __cplusplus
}
#endif
#endif
