/* Standalone QH-00 RESP durability latency benchmark.
 * Build with the repository's normal source/link set and this file as main.
 * Each sample measures a STORE followed by its matching FORGET. */
#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <time.h>

#define DEFAULT_SAMPLES 100u
#define DEFAULT_PAYLOAD_BYTES 256u
#define MAX_SAMPLES 1000000u
#define MAX_PAYLOAD_BYTES (1024u * 1024u)

typedef struct bench_instance {
    qihse_resp_server_t *server;
    qihse_kv_store_t *store;
    qihse_user_t *operator_user;
} bench_instance_t;

static bool parse_size(const char *text, size_t min, size_t max, size_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !text[0] || !end || *end || value < min || value > max)
        return false;
    *out = (size_t)value;
    return true;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static bool execute(bench_instance_t *instance, size_t argc,
                    const qihse_resp_arg_t *args, uint8_t **reply,
                    size_t *reply_len) {
    *reply = NULL;
    *reply_len = 0;
    return qihse_resp_server_execute(instance->server, instance->operator_user,
                                     argc, args, reply, reply_len);
}

static bool run_pair(bench_instance_t *instance, bool durable,
                     const uint8_t *payload, size_t payload_len,
                     size_t sequence) {
    char token[80];
    int token_len = snprintf(token, sizeof token, "qh00-bench-%s-%zu",
                             durable ? "durable" : "volatile", sequence);
    if (token_len < 0 || (size_t)token_len >= sizeof token)
        return false;
    const char *store_words[] = { "AIMEM", durable ? "STORE-DURABLE" : "STORE",
                                  "2", NULL, token };
    qihse_resp_arg_t store_args[5] = {
        { (const uint8_t *)store_words[0], strlen(store_words[0]) },
        { (const uint8_t *)store_words[1], strlen(store_words[1]) },
        { (const uint8_t *)store_words[2], strlen(store_words[2]) },
        { payload, payload_len },
        { (const uint8_t *)store_words[4], (size_t)token_len }
    };
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    if (!execute(instance, 5u, store_args, &reply, &reply_len))
        return false;

    /* STORE replies with the generated memory ID as a 36-byte bulk string. */
    const char prefix[] = "$36\r\n";
    const size_t prefix_len = sizeof prefix - 1u;
    if (!reply || reply_len < prefix_len + 38u ||
        memcmp(reply, prefix, prefix_len) != 0 ||
        reply[prefix_len + 36u] != '\r' || reply[prefix_len + 37u] != '\n') {
        fprintf(stderr, "unexpected AIMEM STORE reply\n");
        free(reply);
        return false;
    }
    char id[37];
    memcpy(id, reply + prefix_len, 36u);
    id[36] = '\0';
    free(reply);

    const char *forget_word = durable ? "FORGET-DURABLE" : "FORGET";
    qihse_resp_arg_t forget_args[3] = {
        { (const uint8_t *)"AIMEM", 5u },
        { (const uint8_t *)forget_word, strlen(forget_word) },
        { (const uint8_t *)id, 36u }
    };
    reply = NULL;
    reply_len = 0;
    if (!execute(instance, 3u, forget_args, &reply, &reply_len))
        return false;
    bool ok = reply && reply_len && reply[0] != '-';
    if (!ok)
        fprintf(stderr, "AIMEM %s failed: %.*s\n", forget_word,
                (int)reply_len, reply ? (char *)reply : "(no reply)");
    free(reply);
    return ok;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static uint64_t percentile(const uint64_t *sorted, size_t count, size_t pct) {
    size_t index = (count * pct + 99u) / 100u;
    if (index == 0u) index = 1u;
    if (index > count) index = count;
    return sorted[index - 1u];
}

static bool benchmark_mode(bench_instance_t *instance, bool durable,
                           const uint8_t *payload, size_t payload_len,
                           size_t warmups, size_t samples,
                           uint64_t *latencies) {
    for (size_t i = 0; i < warmups; ++i) {
        if (!run_pair(instance, durable, payload, payload_len, i)) return false;
    }
    uint64_t elapsed_start = monotonic_ns();
    for (size_t i = 0; i < samples; ++i) {
        uint64_t start = monotonic_ns();
        if (!run_pair(instance, durable, payload, payload_len, warmups + i))
            return false;
        latencies[i] = monotonic_ns() - start;
    }
    uint64_t elapsed_ns = monotonic_ns() - elapsed_start;
    qsort(latencies, samples, sizeof *latencies, compare_u64);
    double throughput = elapsed_ns
        ? (double)samples * 1e9 / (double)elapsed_ns : 0.0;
    printf("mode=%s samples=%zu payload_bytes=%zu p50_us=%.3f p95_us=%.3f pairs_per_sec=%.3f\n",
           durable ? "durable" : "ordinary", samples, payload_len,
           (double)percentile(latencies, samples, 50u) / 1000.0,
           (double)percentile(latencies, samples, 95u) / 1000.0,
           throughput);
    return true;
}

static bool open_instance(bench_instance_t *instance) {
    if (!qihse_auth_init() || !qihse_auth_bootstrap_operator("QH00BenchPass123!"))
        return false;
    instance->operator_user = qihse_auth_get_user(0u);
    if (!instance->operator_user) return false;
    instance->store = qihse_kv_store_create();
    if (!instance->store) return false;
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = instance->store;
    config.auth_required = true;
    config.port = 0;
    instance->server = qihse_resp_server_create(&config);
    return instance->server != NULL;
}

int main(int argc, char **argv) {
    size_t samples = DEFAULT_SAMPLES;
    size_t payload_len = DEFAULT_PAYLOAD_BYTES;
    if (argc > 3 || (argc > 1 && !parse_size(argv[1], 1u, MAX_SAMPLES, &samples)) ||
        (argc > 2 && !parse_size(argv[2], 1u, MAX_PAYLOAD_BYTES, &payload_len))) {
        fprintf(stderr, "usage: %s [samples (default %u)] [payload-bytes (default %u)]\n",
                argv[0], DEFAULT_SAMPLES, DEFAULT_PAYLOAD_BYTES);
        return EXIT_FAILURE;
    }

    char data_root[] = "./qh00_durability_bench_XXXXXX";
    if (!mkdtemp(data_root) || setenv("QIHSE_DATA_DIR", data_root, 1) != 0) {
        perror("create QIHSE_DATA_DIR");
        return EXIT_FAILURE;
    }
    struct statfs fs;
    if (statfs(data_root, &fs) != 0) {
        perror("statfs QIHSE_DATA_DIR");
        return EXIT_FAILURE;
    }
    printf("data_dir=%s filesystem_type=0x%lx block_size=%ld samples=%zu payload_bytes=%zu\n",
           data_root, (unsigned long)fs.f_type, (long)fs.f_bsize, samples, payload_len);

    uint8_t *payload = malloc(payload_len);
    uint64_t *latencies = malloc(samples * sizeof *latencies);
    if (!payload || !latencies) {
        perror("allocate benchmark buffers");
        free(payload);
        free(latencies);
        return EXIT_FAILURE;
    }
    memset(payload, 'q', payload_len);
    bench_instance_t instance = {0};
    if (!open_instance(&instance)) {
        fprintf(stderr, "failed to initialize authenticated RESP benchmark instance\n");
        free(payload);
        free(latencies);
        return EXIT_FAILURE;
    }
    size_t warmups = samples < 10u ? samples : 10u;
    bool ok = benchmark_mode(&instance, false, payload, payload_len,
                             warmups, samples, latencies) &&
              benchmark_mode(&instance, true, payload, payload_len,
                             warmups, samples, latencies);
    qihse_resp_server_destroy(instance.server);
    qihse_kv_store_destroy(instance.store);
    free(payload);
    free(latencies);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
