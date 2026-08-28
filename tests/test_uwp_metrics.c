#include "qihse_uwp_metrics.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* create / destroy cycle */
    qihse_uwp_metrics_t* m = qihse_uwp_metrics_create();
    assert(m != NULL);

    /* all counters start at zero */
    assert(m->connections_total == 0);
    assert(m->connections_active == 0);
    assert(m->frames_received == 0);
    assert(m->auth_attempts == 0);

    /* increment connection counters */
    for (int i = 0; i < 5; i++) {
        qihse_uwp_metrics_inc_connections_total(m);
        qihse_uwp_metrics_inc_connections_active(m);
    }
    assert(m->connections_total == 5);
    assert(m->connections_active == 5);

    qihse_uwp_metrics_dec_connections_active(m);
    assert(m->connections_active == 4);

    qihse_uwp_metrics_inc_connections_rejected(m);
    assert(m->connections_rejected == 1);

    /* frame counters */
    qihse_uwp_metrics_inc_frames_received(m);
    qihse_uwp_metrics_inc_frames_received(m);
    qihse_uwp_metrics_inc_frames_valid(m);
    qihse_uwp_metrics_inc_frames_invalid_magic(m);
    qihse_uwp_metrics_inc_frames_invalid_version(m);
    qihse_uwp_metrics_inc_frames_oversized(m);
    qihse_uwp_metrics_inc_frames_partial(m);
    assert(m->frames_received == 2);
    assert(m->frames_valid == 1);
    assert(m->frames_invalid_magic == 1);
    assert(m->frames_invalid_version == 1);
    assert(m->frames_oversized == 1);
    assert(m->frames_partial == 1);

    /* auth counters */
    qihse_uwp_metrics_inc_auth_attempts(m);
    qihse_uwp_metrics_inc_auth_attempts(m);
    qihse_uwp_metrics_inc_auth_successes(m);
    qihse_uwp_metrics_inc_auth_failures(m);
    qihse_uwp_metrics_inc_auth_rate_limited(m);
    assert(m->auth_attempts == 2);
    assert(m->auth_successes == 1);
    assert(m->auth_failures == 1);
    assert(m->auth_rate_limited == 1);

    /* dispatch counters per target */
    qihse_uwp_metrics_inc_dispatch_ok(m, 0x00);
    qihse_uwp_metrics_inc_dispatch_ok(m, 0x01);
    qihse_uwp_metrics_inc_dispatch_ok(m, 0x01);
    qihse_uwp_metrics_inc_dispatch_error(m, 0x02);
    assert(m->dispatch_ok[0] == 1);
    assert(m->dispatch_ok[1] == 2);
    assert(m->dispatch_error[2] == 1);

    /* out-of-range target should be ignored */
    qihse_uwp_metrics_inc_dispatch_ok(m, 0x10);
    assert(m->dispatch_ok[0] == 1);

    /* TLS counters */
    qihse_uwp_metrics_inc_tls_connections(m);
    qihse_uwp_metrics_inc_tls_decrypt_failures(m);
    assert(m->tls_connections == 1);
    assert(m->tls_decrypt_failures == 1);

    /* rate limiting */
    qihse_uwp_metrics_inc_rate_limited_ips(m);
    assert(m->rate_limited_ips == 1);

    /* JSON output */
    char* json = qihse_uwp_metrics_to_json(m);
    assert(json != NULL);
    assert(strstr(json, "\"connections_total\":5") != NULL);
    assert(strstr(json, "\"connections_active\":4") != NULL);
    assert(strstr(json, "\"dispatch_ok\":[") != NULL);
    assert(strstr(json, "\"dispatch_error\":[") != NULL);
    assert(strstr(json, "\"rate_limited_ips\":1") != NULL);
    free(json);

    /* Prometheus output */
    char* prom = qihse_uwp_metrics_to_prometheus(m);
    assert(prom != NULL);
    assert(strstr(prom, "# HELP qihse_uwp_connections_total") != NULL);
    assert(strstr(prom, "# TYPE qihse_uwp_connections_total counter") != NULL);
    assert(strstr(prom, "qihse_uwp_connections_total 5") != NULL);
    assert(strstr(prom, "# TYPE qihse_uwp_connections_active gauge") != NULL);
    assert(strstr(prom, "qihse_uwp_dispatch_ok{target=\"1\"} 2") != NULL);
    assert(strstr(prom, "qihse_uwp_dispatch_error{target=\"2\"} 1") != NULL);
    free(prom);

    /* reset */
    qihse_uwp_metrics_reset(m);
    assert(m->connections_total == 0);
    assert(m->connections_active == 0);
    assert(m->frames_received == 0);
    assert(m->auth_attempts == 0);
    assert(m->dispatch_ok[1] == 0);
    assert(m->dispatch_error[2] == 0);

    /* NULL safety */
    qihse_uwp_metrics_destroy(NULL);
    qihse_uwp_metrics_reset(NULL);
    qihse_uwp_metrics_inc_connections_total(NULL);
    assert(qihse_uwp_metrics_to_json(NULL) == NULL);
    assert(qihse_uwp_metrics_to_prometheus(NULL) == NULL);

    qihse_uwp_metrics_destroy(m);

    printf("PASS UWP metrics create, increment, JSON, Prometheus, reset, NULL safety\n");
    return 0;
}
