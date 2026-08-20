#ifndef QIHSE_INFLUX_API_H
#define QIHSE_INFLUX_API_H

#include "qihse_http_api.h"
#include "qihse_timeseries.h"

#ifdef __cplusplus
extern "C" {
#endif

/* InfluxDB-compatible HTTP API handlers.
 *
 * These endpoints expose the QIHSE time-series engine through the wire
 * formats expected by the InfluxDB 1.x client libraries:
 *
 *   GET  /ping            - liveness probe (InfluxDB "InfluxDB" header)
 *   GET  /health          - health check JSON
 *   GET  /query           - InfluxQL query (q=... query parameter)
 *   POST /query           - InfluxQL query (q=... body or query param)
 *   POST /write           - line protocol write (db=... query param)
 *
 * The handler `user_data` is expected to point at a qihse_tsdb_t* instance
 * created with qihse_tsdb_create(). Writes are ingested via
 * qihse_tsdb_insert after hashing the measurement+tag set down to a
 * series_id, and SELECT queries are executed against
 * qihse_tsdb_aggregate_range_user / qihse_tsdb_average_range_user.
 */

http_response_t* qihse_influx_handle_query(const http_request_t* req, void* user_data);
http_response_t* qihse_influx_handle_write(const http_request_t* req, void* user_data);
http_response_t* qihse_influx_handle_health(const http_request_t* req, void* user_data);
http_response_t* qihse_influx_handle_ping(const http_request_t* req, void* user_data);

/* Register all InfluxDB-compatible routes on an HTTP server.
 *
 * `tsdb` is the qihse_tsdb_t* that will receive writes and serve queries.
 * Returns 0 on success, -1 on invalid arguments. */
int qihse_influx_register_routes(qihse_http_server_t* srv, qihse_tsdb_t* tsdb);

#ifdef __cplusplus
}
#endif
#endif /* QIHSE_INFLUX_API_H */
