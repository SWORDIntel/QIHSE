#ifndef QIHSE_ES_API_H
#define QIHSE_ES_API_H

#include "qihse_http_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Elasticsearch-compatible HTTP API handlers.
 *
 * All endpoints are dispatched through a single catch-all route handler that
 * parses the request path and body and routes to the appropriate Elasticsearch
 * Document, Index, Search, Aggregation, Mapping, Cluster, Cat, Reindex, Scroll,
 * Point-in-Time and Search Template operation. The individual handlers below
 * are retained for backward compatibility and delegate to the same dispatcher.
 */

http_response_t* qihse_es_handle_search(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_index(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_get(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_bulk(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_health(const http_request_t* req, void* user_data);

/* Additional ES-compatible handlers (delegating to the internal dispatcher). */
http_response_t* qihse_es_handle_dispatch(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_doc(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_mapping(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_settings(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_index_mgmt(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_count(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_explain(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_msearch(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_mget(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_reindex(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_scroll(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_pit(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_script(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_template(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_cat(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_cluster(const http_request_t* req, void* user_data);
http_response_t* qihse_es_handle_nodes(const http_request_t* req, void* user_data);

/* Register Elasticsearch-compatible routes on an HTTP server. */
int qihse_es_register_routes(qihse_http_server_t* srv, void* fts_index, void* vector_db);

#ifdef __cplusplus
}
#endif
#endif
