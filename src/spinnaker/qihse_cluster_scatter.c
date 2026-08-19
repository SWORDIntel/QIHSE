#include "qihse_cluster_scatter.h"
#include "qihse_platform.h"
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
typedef int socklen_t;
#endif

/* ------------------------------------------------------------------ */
/* Lightweight RESP client for peer queries                            */
/* ------------------------------------------------------------------ */

static size_t digits(uint64_t n) {
    if (n == 0) return 1;
    size_t d = 0;
    while (n > 0) { d++; n /= 10; }
    return d;
}

typedef struct {
    int fd;
    uint8_t* buf;
    size_t buf_cap;
    size_t buf_len;
} qihse_resp_client_t;

static int qihse_scatter_connect(const char* host, uint16_t port, uint32_t timeout_ms) {
    int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
#ifndef _WIN32
    /* Set non-blocking for timeout connect */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
    int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
#ifndef _WIN32
        if (errno != EINPROGRESS) { close(fd); return -1; }
        struct pollfd pfd = {fd, POLLOUT, 0};
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t errlen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
            close(fd);
            return -1;
        }
        fcntl(fd, F_SETFL, flags); /* restore blocking */
#else
        close(fd);
        return -1;
#endif
    }
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt));
    return fd;
}

static bool qihse_scatter_send_all(int fd, const void* data, size_t len, uint32_t timeout_ms) {
    const uint8_t* bytes = (const uint8_t*)data;
    size_t sent = 0;
    while (sent < len) {
#ifndef _WIN32
        struct pollfd pfd = {fd, POLLOUT, 0};
        if (poll(&pfd, 1, (int)timeout_ms) <= 0) return false;
#endif
        ssize_t n = send(fd, (const char*)bytes + sent, len - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

static ssize_t qihse_scatter_recv(int fd, uint8_t* buf, size_t cap, uint32_t timeout_ms) {
#ifndef _WIN32
    struct pollfd pfd = {fd, POLLIN, 0};
    if (poll(&pfd, 1, (int)timeout_ms) <= 0) return -1;
#endif
    return recv(fd, (char*)buf, cap, 0);
}

/* Parse a RESP double from a buffer.  Returns true on success. */
static bool qihse_scatter_parse_double(const uint8_t* buf, size_t len, double* out) {
    if (len < 4) return false;
    if (buf[0] == ',') {
        /* RESP3 double: ,1.234\r\n */
        size_t i = 1;
        while (i < len && buf[i] != '\r') i++;
        if (i + 1 >= len) return false;
        char tmp[64];
        size_t dlen = i - 1;
        if (dlen >= sizeof(tmp)) return false;
        memcpy(tmp, buf + 1, dlen);
        tmp[dlen] = '\0';
        *out = strtod(tmp, NULL);
        return true;
    }
    if (buf[0] == '$') {
        /* RESP2 bulk string: $5\r\n1.234\r\n */
        size_t i = 1;
        size_t blen = 0;
        while (i < len && buf[i] != '\r') { blen = blen * 10 + (buf[i] - '0'); i++; }
        i += 2; /* skip \r\n */
        if (i + blen > len) return false;
        char tmp[64];
        if (blen >= sizeof(tmp)) return false;
        memcpy(tmp, buf + i, blen);
        tmp[blen] = '\0';
        *out = strtod(tmp, NULL);
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Scatter-gather engine                                               */
/* ------------------------------------------------------------------ */

struct qihse_cluster_scatter {
    qihse_cluster_topology_t* topology;
    uint16_t local_node_index;
    uint32_t timeout_ms;
    size_t max_peers;
    pthread_mutex_t lock;
    qihse_cluster_scatter_stats_t stats;
};

qihse_cluster_scatter_t* qihse_cluster_scatter_create(const qihse_cluster_scatter_config_t* config) {
    if (!config || !config->topology) return NULL;
    qihse_cluster_scatter_t* sg = (qihse_cluster_scatter_t*)calloc(1, sizeof(*sg));
    if (!sg) return NULL;
    sg->topology = config->topology;
    sg->local_node_index = config->local_node_index;
    sg->timeout_ms = config->timeout_ms ? config->timeout_ms : 2000u;
    sg->max_peers = config->max_peers ? config->max_peers : QIHSE_CLUSTER_MAX_NODES;
    if (pthread_mutex_init(&sg->lock, NULL) != 0) {
        free(sg);
        return NULL;
    }
    return sg;
}

void qihse_cluster_scatter_destroy(qihse_cluster_scatter_t* sg) {
    if (!sg) return;
    pthread_mutex_destroy(&sg->lock);
    free(sg);
}

void qihse_cluster_scatter_stats(const qihse_cluster_scatter_t* sg,
                                 qihse_cluster_scatter_stats_t* out_stats) {
    if (!sg || !out_stats) return;
    *out_stats = sg->stats;
}

/* Get the list of peer nodes (excluding local).  Returns count. */
static size_t qihse_scatter_get_peers(qihse_cluster_scatter_t* sg,
                                      qihse_cluster_node_t* out_nodes, size_t capacity) {
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(sg->topology, nodes,
                                                sizeof(nodes) / sizeof(nodes[0]));
    size_t peers = 0;
    for (size_t i = 0; i < count && peers < capacity; i++) {
        if (nodes[i].index == sg->local_node_index) continue;
        if (!nodes[i].healthy) continue;
        out_nodes[peers++] = nodes[i];
    }
    return peers;
}

/* ------------------------------------------------------------------ */
/* VECSCATTER with RRF fusion                                          */
/* ------------------------------------------------------------------ */

/* RRF entry: maps a vector ID to its accumulated RRF score */
typedef struct {
    uint64_t id;
    double rrf_score;
    float best_score;
} qihse_rrf_entry_t;

static int qihse_rrf_compare(const void* a, const void* b) {
    const qihse_rrf_entry_t* ea = (const qihse_rrf_entry_t*)a;
    const qihse_rrf_entry_t* eb = (const qihse_rrf_entry_t*)b;
    if (ea->rrf_score > eb->rrf_score) return -1;
    if (ea->rrf_score < eb->rrf_score) return 1;
    return 0;
}

/* Find or create an RRF entry for a vector ID */
static qihse_rrf_entry_t* qihse_rrf_find_or_create(qihse_rrf_entry_t* entries, size_t* count, size_t capacity, uint64_t id) {
    for (size_t i = 0; i < *count; i++) {
        if (entries[i].id == id) return &entries[i];
    }
    if (*count >= capacity) return NULL;
    entries[*count].id = id;
    entries[*count].rrf_score = 0.0;
    entries[*count].best_score = 0.0f;
    return &entries[(*count)++];
}

/* Parse a RESP array of [id, score] pairs from a peer's VECSEARCH response.
 * Returns the number of pairs parsed, or -1 on error. */
static int qihse_scatter_parse_vecsearch_response(const uint8_t* buf, size_t len,
                                                   qihse_vector_result_t* results, size_t max_results) {
    if (len < 4) return -1;
    /* Expect RESP array: *N\r\n then N elements, each is *2\r\n:id\r\n,score\r\n */
    if (buf[0] != '*') return -1;
    size_t i = 1;
    size_t array_count = 0;
    while (i < len && buf[i] >= '0' && buf[i] <= '9') {
        array_count = array_count * 10 + (buf[i] - '0');
        i++;
    }
    if (i + 2 > len || buf[i] != '\r') return -1;
    i += 2; /* skip \r\n */
    if (array_count > max_results) array_count = max_results;
    size_t found = 0;
    for (size_t e = 0; e < array_count && i < len; e++) {
        /* Each element is *2\r\n:id\r\n,score\r\n or *2\r\n:id\r\n$len\r\nscore\r\n */
        if (buf[i] != '*') return -1;
        i++;
        size_t sub_count = 0;
        while (i < len && buf[i] >= '0' && buf[i] <= '9') { sub_count = sub_count * 10 + (buf[i] - '0'); i++; }
        if (i + 2 > len) return -1;
        i += 2;
        if (sub_count < 2) continue;
        /* Parse id (integer) */
        int64_t id = 0;
        if (buf[i] == ':') {
            i++;
            while (i < len && buf[i] >= '0' && buf[i] <= '9') { id = id * 10 + (buf[i] - '0'); i++; }
            if (i + 2 > len) return -1;
            i += 2;
        } else if (buf[i] == '$') {
            i++;
            size_t slen = 0;
            while (i < len && buf[i] >= '0' && buf[i] <= '9') { slen = slen * 10 + (buf[i] - '0'); i++; }
            if (i + 2 > len) return -1;
            i += 2;
            while (i < len && buf[i] >= '0' && buf[i] <= '9') { id = id * 10 + (buf[i] - '0'); i++; }
            if (i + 2 > len) return -1;
            i += 2;
        } else return -1;
        /* Parse score (double) */
        double score = 0.0;
        if (i < len && (buf[i] == ',' || buf[i] == '$')) {
            if (!qihse_scatter_parse_double(buf + i, len - i, &score)) return -1;
            /* Skip past the double */
            if (buf[i] == ',') {
                i++;
                while (i < len && buf[i] != '\r') i++;
                if (i + 2 > len) return -1;
                i += 2;
            } else {
                i++;
                size_t slen = 0;
                while (i < len && buf[i] >= '0' && buf[i] <= '9') { slen = slen * 10 + (buf[i] - '0'); i++; }
                if (i + 2 > len) return -1;
                i += 2 + slen + 2;
            }
        }
        results[found].id = (uint64_t)id;
        results[found].score = (float)score;
        results[found].vector = NULL;
        results[found].vector_dims = 0;
        results[found].metadata = NULL;
        results[found].metadata_size = 0;
        found++;
    }
    return (int)found;
}

/* Query a single peer for VECSEARCH.  Returns number of results, or -1. */
static int qihse_scatter_query_peer_vecsearch(const char* host, uint16_t port,
                                              uint32_t timeout_ms,
                                              const float* query_vector, size_t dims, size_t top_k,
                                              qihse_vector_result_t* results, size_t max_results) {
    int fd = qihse_scatter_connect(host, port, timeout_ms);
    if (fd < 0) return -1;
    /* Build VECSEARCH command: VECSEARCH dims top_k v0 v1 ... */
    /* Format: *(3+dims)\r\n$9\r\nVECSEARCH\r\n$dims_len\r\ndims\r\n$topk_len\r\ntop_k\r\n$vlen\r\nv0\r\n... */
    size_t cmd_cap = 64 + dims * 32;
    char* cmd = (char*)malloc(cmd_cap);
    if (!cmd) { close(fd); return -1; }
    int pos = snprintf(cmd, cmd_cap, "*%zu\r\n$9\r\nVECSEARCH\r\n$%zu\r\n%zu\r\n$%zu\r\n%zu\r\n",
                       3u + dims, digits(dims), dims, digits(top_k), top_k);
    for (size_t i = 0; i < dims && pos < (int)cmd_cap; i++) {
        pos += snprintf(cmd + pos, cmd_cap - pos, "$%d\r\n%.8g\r\n", (int)snprintf(NULL, 0, "%.8g", query_vector[i]), query_vector[i]);
    }
    size_t cmd_len = (size_t)pos;
    bool sent = qihse_scatter_send_all(fd, cmd, cmd_len, timeout_ms);
    free(cmd);
    if (!sent) { close(fd); return -1; }
    /* Read response */
    uint8_t rbuf[65536];
    ssize_t received = qihse_scatter_recv(fd, rbuf, sizeof(rbuf), timeout_ms);
    close(fd);
    if (received <= 0) return -1;
    return qihse_scatter_parse_vecsearch_response(rbuf, (size_t)received, results, max_results);
}

int qihse_cluster_scatter_vecsearch(qihse_cluster_scatter_t* sg,
                                    const float* query_vector, size_t dims,
                                    size_t top_k, const qihse_user_t* user,
                                    qihse_vector_result_t* out_results) {
    if (!sg || !query_vector || !out_results || dims == 0 || top_k == 0) return -1;
    (void)user; /* user context is applied at each peer's RESP server */

    pthread_mutex_lock(&sg->lock);
    __atomic_add_fetch(&sg->stats.scatter_queries, 1u, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&sg->lock);

    /* RRF merge table: up to top_k * num_shards entries */
    size_t max_entries = top_k * QIHSE_CLUSTER_MAX_NODES;
    qihse_rrf_entry_t* rrf_table = (qihse_rrf_entry_t*)calloc(max_entries, sizeof(*rrf_table));
    if (!rrf_table) return -1;
    size_t rrf_count = 0;

    /* Query local shard first (caller does this separately, but we also
     * support the case where local results are passed in).  For now, we
     * only query remote peers; the caller merges local results. */
    qihse_cluster_node_t peers[QIHSE_CLUSTER_MAX_NODES];
    size_t peer_count = qihse_scatter_get_peers(sg, peers, sizeof(peers) / sizeof(peers[0]));

    /* Query each peer */
    for (size_t p = 0; p < peer_count; p++) {
        qihse_vector_result_t peer_results[256];
        size_t ask = top_k < 256 ? top_k : 256;
        int found = qihse_scatter_query_peer_vecsearch(peers[p].host, peers[p].port,
                                                        sg->timeout_ms,
                                                        query_vector, dims, ask,
                                                        peer_results, ask);
        pthread_mutex_lock(&sg->lock);
        if (found > 0) {
            __atomic_add_fetch(&sg->stats.peer_responses_received, 1u, __ATOMIC_RELAXED);
            /* Apply RRF: rank 0 gets 1/(K+0), rank 1 gets 1/(K+1), etc. */
            for (int r = 0; r < found; r++) {
                qihse_rrf_entry_t* entry = qihse_rrf_find_or_create(rrf_table, &rrf_count, max_entries, peer_results[r].id);
                if (entry) {
                    entry->rrf_score += 1.0 / (double)(QIHSE_RRF_K + (uint32_t)r);
                    if (peer_results[r].score > entry->best_score || entry->best_score == 0.0f) {
                        entry->best_score = peer_results[r].score;
                    }
                }
            }
        } else {
            __atomic_add_fetch(&sg->stats.peer_failures, 1u, __ATOMIC_RELAXED);
        }
        __atomic_add_fetch(&sg->stats.peer_queries_sent, 1u, __ATOMIC_RELAXED);
        pthread_mutex_unlock(&sg->lock);
    }

    /* Sort by RRF score (descending) */
    qsort(rrf_table, rrf_count, sizeof(*rrf_table), qihse_rrf_compare);

    /* Copy top_k results to output */
    size_t output = rrf_count < top_k ? rrf_count : top_k;
    for (size_t i = 0; i < output; i++) {
        out_results[i].id = rrf_table[i].id;
        out_results[i].score = rrf_table[i].best_score;
        out_results[i].vector = NULL;
        out_results[i].vector_dims = 0;
        out_results[i].metadata = NULL;
        out_results[i].metadata_size = 0;
    }

    free(rrf_table);
    return (int)output;
}

/* ------------------------------------------------------------------ */
/* TS.RANGE fan-out                                                    */
/* ------------------------------------------------------------------ */

bool qihse_cluster_scatter_ts_range(qihse_cluster_scatter_t* sg,
                                    uint32_t series_id, uint64_t start, uint64_t end,
                                    int aggregation, const qihse_user_t* user,
                                    double* out_value, uint64_t* out_count) {
    if (!sg || !out_value || !out_count) return false;
    (void)user;

    qihse_cluster_node_t peers[QIHSE_CLUSTER_MAX_NODES];
    size_t peer_count = qihse_scatter_get_peers(sg, peers, sizeof(peers) / sizeof(peers[0]));

    const char* agg_str = "AVG";
    switch (aggregation) {
        case 1: agg_str = "SUM"; break;
        case 2: agg_str = "MIN"; break;
        case 3: agg_str = "MAX"; break;
        default: agg_str = "AVG"; break;
    }

    uint64_t merged_count = 0;
    double min_val = 0.0;
    double max_val = 0.0;
    bool any_found = false;
    double sum_total = 0.0;

    for (size_t p = 0; p < peer_count; p++) {
        int fd = qihse_scatter_connect(peers[p].host, peers[p].port, sg->timeout_ms);
        if (fd < 0) continue;
        char cmd[256];
        int pos = snprintf(cmd, sizeof(cmd), "*5\r\n$8\r\nTS.RANGE\r\n$10\r\n%u\r\n$%zu\r\n%llu\r\n$%zu\r\n%llu\r\n$%zu\r\n%s\r\n",
                           series_id, digits(start), (unsigned long long)start,
                           digits(end), (unsigned long long)end, strlen(agg_str), agg_str);
        if (!qihse_scatter_send_all(fd, cmd, (size_t)pos, sg->timeout_ms)) { close(fd); continue; }
        uint8_t rbuf[256];
        ssize_t received = qihse_scatter_recv(fd, rbuf, sizeof(rbuf), sg->timeout_ms);
        close(fd);
        if (received <= 0) continue;
        double val;
        if (qihse_scatter_parse_double(rbuf, (size_t)received, &val)) {
            any_found = true;
            switch (aggregation) {
                case 1: sum_total += val; merged_count++; break;
                case 2: if (!any_found || val < min_val) min_val = val; break;
                case 3: if (!any_found || val > max_val) max_val = val; break;
                default: /* AVG — weighted later */ sum_total += val; merged_count++; break;
            }
        }
    }

    if (!any_found) {
        *out_value = 0.0;
        *out_count = 0;
        return false;
    }

    switch (aggregation) {
        case 1: *out_value = sum_total; *out_count = merged_count; break;
        case 2: *out_value = min_val; *out_count = 1; break;
        case 3: *out_value = max_val; *out_count = 1; break;
        default: *out_value = merged_count > 0 ? sum_total / (double)merged_count : 0.0; *out_count = merged_count; break;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* COL.SUM / COL.MINMAX fan-out                                        */
/* ------------------------------------------------------------------ */

bool qihse_cluster_scatter_col_sum(qihse_cluster_scatter_t* sg,
                                   const char* key, const qihse_user_t* user,
                                   double* out_sum) {
    if (!sg || !key || !out_sum) return false;
    (void)user;

    qihse_cluster_node_t peers[QIHSE_CLUSTER_MAX_NODES];
    size_t peer_count = qihse_scatter_get_peers(sg, peers, sizeof(peers) / sizeof(peers[0]));

    double total = 0.0;
    bool any_found = false;

    for (size_t p = 0; p < peer_count; p++) {
        int fd = qihse_scatter_connect(peers[p].host, peers[p].port, sg->timeout_ms);
        if (fd < 0) continue;
        char cmd[512];
        int pos = snprintf(cmd, sizeof(cmd), "*2\r\n$7\r\nCOL.SUM\r\n$%zu\r\n%s\r\n", strlen(key), key);
        if (!qihse_scatter_send_all(fd, cmd, (size_t)pos, sg->timeout_ms)) { close(fd); continue; }
        uint8_t rbuf[256];
        ssize_t received = qihse_scatter_recv(fd, rbuf, sizeof(rbuf), sg->timeout_ms);
        close(fd);
        if (received <= 0) continue;
        double val;
        if (qihse_scatter_parse_double(rbuf, (size_t)received, &val)) {
            total += val;
            any_found = true;
        }
    }
    *out_sum = total;
    return any_found;
}

bool qihse_cluster_scatter_col_minmax(qihse_cluster_scatter_t* sg,
                                      const char* key, const qihse_user_t* user,
                                      double* out_min, double* out_max) {
    if (!sg || !key || !out_min || !out_max) return false;
    (void)user;

    qihse_cluster_node_t peers[QIHSE_CLUSTER_MAX_NODES];
    size_t peer_count = qihse_scatter_get_peers(sg, peers, sizeof(peers) / sizeof(peers[0]));

    double global_min = 0.0;
    double global_max = 0.0;
    bool any_found = false;

    for (size_t p = 0; p < peer_count; p++) {
        int fd = qihse_scatter_connect(peers[p].host, peers[p].port, sg->timeout_ms);
        if (fd < 0) continue;
        char cmd[512];
        int pos = snprintf(cmd, sizeof(cmd), "*2\r\n$10\r\nCOL.MINMAX\r\n$%zu\r\n%s\r\n", strlen(key), key);
        if (!qihse_scatter_send_all(fd, cmd, (size_t)pos, sg->timeout_ms)) { close(fd); continue; }
        uint8_t rbuf[512];
        ssize_t received = qihse_scatter_recv(fd, rbuf, sizeof(rbuf), sg->timeout_ms);
        close(fd);
        if (received <= 0) continue;
        /* Parse RESP array of 2 doubles: *2\r\n,min\r\n,max\r\n */
        if (rbuf[0] != '*') continue;
        size_t i = 1;
        size_t arr_count = 0;
        while (i < (size_t)received && rbuf[i] >= '0' && rbuf[i] <= '9') { arr_count = arr_count * 10 + (rbuf[i] - '0'); i++; }
        if (i + 2 > (size_t)received) continue;
        i += 2;
        if (arr_count < 2) continue;
        double min_v, max_v;
        if (!qihse_scatter_parse_double(rbuf + i, (size_t)received - i, &min_v)) continue;
        /* Skip past min */
        if (rbuf[i] == ',') {
            while (i < (size_t)received && rbuf[i] != '\r') i++;
            i += 2;
        } else if (rbuf[i] == '$') {
            i++;
            size_t slen = 0;
            while (i < (size_t)received && rbuf[i] >= '0' && rbuf[i] <= '9') { slen = slen * 10 + (rbuf[i] - '0'); i++; }
            i += 2 + slen + 2;
        }
        if (!qihse_scatter_parse_double(rbuf + i, (size_t)received - i, &max_v)) continue;
        if (!any_found) {
            global_min = min_v;
            global_max = max_v;
        } else {
            if (min_v < global_min) global_min = min_v;
            if (max_v > global_max) global_max = max_v;
        }
        any_found = true;
    }
    if (any_found) {
        *out_min = global_min;
        *out_max = global_max;
    }
    return any_found;
}
