#include "qihse_resp_wire.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"
#include "qihse_task_queue.h"
#include "qihse_task_worker.h"
#include "qihse_task_scheduler.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int fd;
    unsigned char buffer[65536];
    size_t used;
} test_client_t;

static void send_all(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t result = send(fd, data + sent, len - sent, 0);
        assert(result > 0);
        sent += (size_t)result;
    }
}

static void send_command(int fd, size_t argc, const char* const* argv) {
    char header[64];
    int len = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    assert(len > 0);
    send_all(fd, header, (size_t)len);
    for (size_t i = 0; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        char arg_hdr[64];
        int hlen = snprintf(arg_hdr, sizeof(arg_hdr), "$%zu\r\n", arg_len);
        assert(hlen > 0);
        send_all(fd, arg_hdr, (size_t)hlen);
        send_all(fd, argv[i], arg_len);
        send_all(fd, "\r\n", 2u);
    }
}

static char* read_line(test_client_t* client) {
    char response[4096];
    size_t rlen = 0;
    while (1) {
        char c;
        ssize_t n = recv(client->fd, &c, 1, 0);
        assert(n > 0);
        response[rlen++] = c;
        if (rlen >= 2 && response[rlen - 2] == '\r' && response[rlen - 1] == '\n') {
            response[rlen] = '\0';
            return strdup(response);
        }
    }
}

static char* read_bulk(test_client_t* client) {
    char* hdr = read_line(client);
    assert(hdr != NULL);
    if (hdr[0] == '$') {
        int bulk_len = atoi(hdr + 1);
        free(hdr);
        if (bulk_len < 0) return NULL;
        char* data = (char*)malloc(bulk_len + 1);
        size_t read_bytes = 0;
        while (read_bytes < (size_t)bulk_len) {
            ssize_t n = recv(client->fd, data + read_bytes, (size_t)bulk_len - read_bytes, 0);
            assert(n > 0);
            read_bytes += (size_t)n;
        }
        data[bulk_len] = '\0';
        char crlf[2];
        ssize_t n = recv(client->fd, crlf, 2, 0);
        assert(n == 2);
        return data;
    }
    return hdr;
}

int main(void) {
    printf("=== Testing QIHSE RESP Task Queue & Scheduler Wire Protocol ===\n");

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = kv;
    cfg.port = 0; /* ephemeral port */
    cfg.auth_required = false;
    cfg.enable_task_queue = true;
    cfg.enable_task_workers = true;
    cfg.task_worker_count = 2;
    cfg.enable_task_scheduler = true;

    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server != NULL);
    assert(qihse_resp_server_start(server));

    uint16_t port = qihse_resp_server_port(server);
    assert(port > 0);
    printf("  [✔] RESP Server running with Task Queue on port %u\n", port);

    /* Connect client */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    assert(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);

    test_client_t client;
    memset(&client, 0, sizeof(client));
    client.fd = sock;

    /* Test 1: PING */
    const char* ping_cmd[] = {"PING"};
    send_command(sock, 1, ping_cmd);
    char* ping_res = read_line(&client);
    assert(ping_res != NULL && strncmp(ping_res, "+PONG", 5) == 0);
    free(ping_res);
    printf("  [✔] PING -> +PONG\n");

    /* Test 2: TASK.SUBMIT */
    const char* sub_cmd[] = {"TASK.SUBMIT", "compute", "HIGH", "lua: return 'result_from_lua'"};
    send_command(sock, 4, sub_cmd);
    char* task_id = read_bulk(&client);
    assert(task_id != NULL && strlen(task_id) == QIHSE_TASK_ID_LEN);
    printf("  [✔] TASK.SUBMIT -> Task ID: %.16s...\n", task_id);

    /* Test 3: TASK.STATUS and TASK.RESULT */
    usleep(100000); /* 100ms for worker to execute Lua */

    const char* stat_cmd[] = {"TASK.STATUS", task_id};
    send_command(sock, 2, stat_cmd);
    char* stat_res = read_line(&client);
    assert(stat_res != NULL && strncmp(stat_res, "+SUCCESS", 8) == 0);
    free(stat_res);
    printf("  [✔] TASK.STATUS -> +SUCCESS\n");

    const char* res_cmd[] = {"TASK.RESULT", task_id};
    send_command(sock, 2, res_cmd);
    char* task_result = read_bulk(&client);
    assert(task_result != NULL && strcmp(task_result, "result_from_lua") == 0);
    free(task_result);
    printf("  [✔] TASK.RESULT -> 'result_from_lua'\n");

    /* Test 4: TASK.STATS */
    const char* stats_cmd[] = {"TASK.STATS"};
    send_command(sock, 1, stats_cmd);
    char* st_hdr = read_line(&client);
    assert(st_hdr != NULL && st_hdr[0] == '*');
    free(st_hdr);
    /* Drain 16 elements */
    for (int i = 0; i < 16; i++) {
        char* item = read_line(&client);
        if (item[0] == '$') {
            free(item);
            char* val = read_line(&client);
            free(val);
        } else {
            free(item);
        }
    }
    printf("  [✔] TASK.STATS -> Array format verified\n");

    /* Test 5: TASK.WORKERS */
    const char* workers_cmd[] = {"TASK.WORKERS"};
    send_command(sock, 1, workers_cmd);
    char* w_hdr = read_line(&client);
    assert(w_hdr != NULL && w_hdr[0] == '*');
    int num_w = atoi(w_hdr + 1);
    assert(num_w == 2);
    free(w_hdr);
    /* Drain worker records */
    for (int w = 0; w < num_w; w++) {
        char* sub_hdr = read_line(&client);
        free(sub_hdr);
        for (int f = 0; f < 16; f++) {
            char* field = read_line(&client);
            if (field[0] == '$') {
                free(field);
                char* v = read_line(&client);
                free(v);
            } else {
                free(field);
            }
        }
    }
    printf("  [✔] TASK.WORKERS -> 2 active workers reported\n");

    /* Test 6: SCHEDULE.ADD and SCHEDULE.LIST */
    const char* sched_add[] = {"SCHEDULE.ADD", "nightly", "0 3 * * *", "maintenance", "NORMAL", "{\"job\":\"vacuum\"}"};
    send_command(sock, 6, sched_add);
    char* sched_res = read_line(&client);
    if (!sched_res || strncmp(sched_res, "+OK", 3) != 0) {
        printf("DEBUG sched_res: '%s'\n", sched_res ? sched_res : "NULL");
        fflush(stdout);
    }
    assert(sched_res != NULL && strncmp(sched_res, "+OK", 3) == 0);
    free(sched_res);
    printf("  [✔] SCHEDULE.ADD -> +OK\n");

    const char* sched_list[] = {"SCHEDULE.LIST"};
    send_command(sock, 1, sched_list);
    char* sl_hdr = read_line(&client);
    assert(sl_hdr != NULL && sl_hdr[0] == '*');
    int s_count = atoi(sl_hdr + 1);
    assert(s_count >= 1);
    free(sl_hdr);
    char* s_id = read_bulk(&client);
    assert(s_id != NULL && strcmp(s_id, "nightly") == 0);
    free(s_id);
    printf("  [✔] SCHEDULE.LIST -> ['nightly']\n");

    /* Test 7: SCHEDULE.NEXT */
    const char* sched_next[] = {"SCHEDULE.NEXT", "nightly"};
    send_command(sock, 2, sched_next);
    char* next_iso = read_line(&client);
    assert(next_iso != NULL && next_iso[0] == '+' && strstr(next_iso, "T03:00:00Z") != NULL);
    printf("  [✔] SCHEDULE.NEXT nightly -> %s", next_iso + 1);
    free(next_iso);

    /* Test 8: TASK.DELETE */
    const char* del_cmd[] = {"TASK.DELETE", task_id};
    send_command(sock, 2, del_cmd);
    char* del_res = read_line(&client);
    assert(del_res != NULL && strncmp(del_res, "+OK", 3) == 0);
    free(del_res);
    printf("  [✔] TASK.DELETE -> +OK\n");

    free(task_id);
    close(sock);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);

    printf("=== All RESP Wire Protocol Task Queue Tests Passed ===\n\n");
    return 0;
}
