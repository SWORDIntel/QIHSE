/* tests/test_http_adapters.c — end-to-end harness for the HTTP protocol
 * adapters: InfluxDB line protocol + InfluxQL, ClickHouse HTTP, and the
 * Elasticsearch shape API.  Requests go over a real TCP socket through
 * qihse_http_server_t, not in-process handler calls.
 *
 * What is honest here:
 *  - InfluxDB is a real adapter: /write ingests into the TSDB and /query
 *    reads it back through the classified-aware _user primitives with a
 *    NULL context (unclassified-only mode).
 *  - ClickHouse and Elasticsearch are protocol-shape adapters: they parse
 *    the wire format and answer metadata/shape correctly but hold no store
 *    handles, so there is no data path to gate.  The negative test lives
 *    on the adapter that does carry data (Influx/TSDB).
 *
 * AGENTS.md invariant 3: a point inserted at classification > 0 directly
 * into the TSDB must be invisible through the Influx query path.
 */
#include "qihse_http_api.h"
#include "qihse_influx_api.h"
#include "qihse_clickhouse_http.h"
#include "qihse_es_api.h"
#include "qihse_timeseries.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* One-shot HTTP/1.0 request over TCP; returns the full response text. */
static char* http_req(uint16_t port, const char* method, const char* path,
                      const char* body) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    assert(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);

    char req[8192];
    int n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     method, path, body ? strlen(body) : 0u,
                     body ? body : "");
    assert(n > 0 && send(fd, req, (size_t)n, 0) == (ssize_t)n);

    char* resp = (char*)calloc(1, 131072);
    assert(resp);
    size_t total = 0;
    ssize_t r;
    while ((r = recv(fd, resp + total, 131071 - total, 0)) > 0) total += (size_t)r;
    close(fd);
    resp[total] = '\0';
    return resp;
}

static int resp_status(const char* resp) {
    int code = 0;
    sscanf(resp, "HTTP/1.1 %d", &code);
    return code;
}

int main(void) {
    /* ── InfluxDB: real write→query roundtrip on the TSDB ────────────── */
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    assert(tsdb);
    qihse_http_server_t* influx = qihse_http_server_create(0);
    assert(influx && qihse_influx_register_routes(influx, tsdb) == 0);
    assert(qihse_http_server_start(influx) == 0 && influx->port != 0);

    char* r = http_req(influx->port, "POST", "/write?db=test",
                       "cpu value=42.5 1000000000\nmem value=7 1000000000\n");
    assert(resp_status(r) == 204);
    free(r);

    r = http_req(influx->port, "GET",
                 "/query?q=SELECT%20mean(value)%20FROM%20cpu", NULL);
    assert(resp_status(r) == 200);
    assert(strstr(r, "\"cpu\"") != NULL);
    assert(strstr(r, "42.5") != NULL);
    free(r);

    /* Multi-statement + SHOW. */
    r = http_req(influx->port, "GET", "/query?q=SHOW%20MEASUREMENTS", NULL);
    assert(resp_status(r) == 200);
    assert(strstr(r, "\"results\"") != NULL);
    free(r);

    /* Invariant 3: a classified point written below the adapter is
     * invisible through it — the adapter's NULL context is unclassified
     * only, not a bypass. */
    {
        /* series_id_for("secret") == fnv1a32("secret") — compute it the
         * same way the adapter does. */
        uint32_t sid = 2166136261u;
        for (const char* p = "secret"; *p; p++) { sid ^= (uint8_t)*p; sid *= 16777619u; }
        assert(qihse_tsdb_insert(tsdb, sid, 2000000000ull, 999.0, 2, 0));
        r = http_req(influx->port, "GET",
                     "/query?q=SELECT%20mean(value)%20FROM%20secret", NULL);
        assert(resp_status(r) == 200);
        assert(strstr(r, "999") == NULL);
        free(r);
    }

    /* Malformed line protocol → 400, no partial state fabricated. */
    r = http_req(influx->port, "POST", "/write?db=test", "!!not-line-protocol!!");
    assert(resp_status(r) == 400);
    free(r);

    qihse_http_server_destroy(influx);
    printf("PASS influxdb: line-protocol write → InfluxQL read roundtrip, "
           "classified point invisible, malformed write refused\n");

    /* ── ClickHouse: wire-shape adapter ──────────────────────────────── */
    qihse_http_server_t* ch = qihse_http_server_create(0);
    assert(ch && qihse_clickhouse_register_routes(ch, NULL) == 0);
    assert(qihse_http_server_start(ch) == 0 && ch->port != 0);

    r = http_req(ch->port, "GET", "/ping", NULL);
    assert(resp_status(r) == 200 && strstr(r, "Ok.") != NULL);
    free(r);

    r = http_req(ch->port, "GET", "/?query=SHOW%20DATABASES%20FORMAT%20JSON", NULL);
    assert(resp_status(r) == 200 && strstr(r, "\"data\"") != NULL);
    free(r);

    r = http_req(ch->port, "POST", "/", "SELECT 1 FORMAT JSONEachRow");
    assert(resp_status(r) == 200);
    free(r);

    r = http_req(ch->port, "GET", "/?query=GIBBERISH", NULL);
    assert(resp_status(r) == 400);
    free(r);

    qihse_http_server_destroy(ch);
    printf("PASS clickhouse: ping, SHOW/SELECT dispatch, unsupported refused\n");

    /* ── Elasticsearch: wire-shape adapter ───────────────────────────── */
    qihse_http_server_t* es = qihse_http_server_create(0);
    assert(es && qihse_es_register_routes(es, NULL, NULL) == 0);
    assert(qihse_http_server_start(es) == 0 && es->port != 0);

    r = http_req(es->port, "GET", "/_cluster/health", NULL);
    assert(resp_status(r) == 200 && strstr(r, "\"status\":\"green\"") != NULL);
    free(r);

    r = http_req(es->port, "POST", "/_search",
                 "{\"query\":{\"match_all\":{}},\"size\":5}");
    assert(resp_status(r) == 200 && strstr(r, "\"hits\"") != NULL);
    free(r);

    r = http_req(es->port, "POST", "/_bulk",
                 "{\"index\":{}}\n{\"f\":1}\n{\"index\":{}}\n{\"f\":2}\n");
    assert(resp_status(r) == 200 && strstr(r, "\"items\"") != NULL);
    free(r);

    r = http_req(es->port, "GET", "/definitely/not/a/route", NULL);
    assert(resp_status(r) == 404);
    free(r);

    qihse_http_server_destroy(es);
    printf("PASS elasticsearch: health/search/bulk shapes, unknown route 404\n");

    printf("test_http_adapters: all adapter harness tests passed\n");
    return 0;
}
