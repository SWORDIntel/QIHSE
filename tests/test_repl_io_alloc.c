#include "qihse_kv_store.h"
#include "qihse_repl.h"
#include "qihse_wal.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail_realloc;
static int fail_strdup;
static int inject_send;
static unsigned send_calls;

void *qihse_test_realloc(void *ptr, size_t size) {
    if (fail_realloc) {
        fail_realloc = 0;
        errno = ENOMEM;
        return NULL;
    }
    return realloc(ptr, size);
}

char *qihse_test_strdup(const char *s) {
    if (fail_strdup) {
        fail_strdup = 0;
        errno = ENOMEM;
        return NULL;
    }
    return strdup(s);
}

ssize_t qihse_test_send(int fd, const void *buf, size_t len, int flags) {
    send_calls++;
    if (inject_send && send_calls == 1) {
        errno = EINTR;
        return -1;
    }
    if (inject_send && send_calls == 2 && len > 3) len = 3;
    return send(fd, buf, len, flags);
}

bool qihse_kv_set(qihse_kv_store_t *store, const char *key, const char *value,
                  uint16_t classification, uint16_t sci_compartment) {
    (void)store; (void)key; (void)value; (void)classification;
    (void)sci_compartment;
    return false;
}

bool qihse_kv_del_user(qihse_kv_store_t *store, const char *key,
                       qihse_user_t *user) {
    (void)store; (void)key; (void)user;
    return false;
}

static void read_exact(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (uint8_t *)buf + got, len - got);
        assert(n > 0);
        got += (size_t)n;
    }
}

static void test_slot_allocation_failures(void) {
    qihse_repl_context_t *ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx);
    for (unsigned i = 0; i < 4; i++) {
        char name[16];
        snprintf(name, sizeof(name), "slot-%u", i);
        assert(qihse_repl_create_slot(ctx, name) == 0);
    }
    qihse_repl_slot_t *original_slots = ctx->slots;
    size_t original_cap = ctx->slots_cap;

    fail_strdup = 1;
    assert(qihse_repl_create_slot(ctx, "strdup-failure") == -1);
    assert(ctx->slots == original_slots && ctx->slots_cap == original_cap &&
           ctx->num_slots == 4);

    fail_realloc = 1;
    assert(qihse_repl_create_slot(ctx, "realloc-failure") == -1);
    assert(ctx->slots == original_slots && ctx->slots_cap == original_cap &&
           ctx->num_slots == 4);
    for (unsigned i = 0; i < 4; i++) {
        char expected[16];
        snprintf(expected, sizeof(expected), "slot-%u", i);
        assert(strcmp(ctx->slots[i].name, expected) == 0);
    }
    assert(qihse_repl_create_slot(ctx, "slot-4") == 0);
    assert(ctx->num_slots == 5 && ctx->slots_cap == 8);
    qihse_repl_destroy(ctx);
}

static void test_send_all_and_sigpipe(void) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    qihse_repl_context_t *ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx);
    ctx->stream_fd = pair[0];
    ctx->state = REPL_STATE_STREAMING;
    const uint8_t payload[] = "partial-and-eintr";
    inject_send = 1;
    send_calls = 0;
    assert(qihse_repl_ship_wal(ctx, payload, sizeof(payload), 4242) == 0);
    inject_send = 0;
    assert(send_calls >= 4);

    uint64_t header[2];
    uint8_t received[sizeof(payload)];
    read_exact(pair[1], header, sizeof(header));
    read_exact(pair[1], received, sizeof(received));
    assert(header[0] == 4242 && header[1] == sizeof(payload));
    assert(memcmp(received, payload, sizeof(payload)) == 0);
    assert(ctx->last_lsn == 4242 && ctx->state == REPL_STATE_STREAMING);
    close(pair[1]);
    qihse_repl_destroy(ctx);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx);
    ctx->stream_fd = pair[0];
    ctx->state = REPL_STATE_STREAMING;
    close(pair[1]);
    /* MSG_NOSIGNAL must turn a dead peer into an ordinary error, not SIGPIPE. */
    assert(qihse_repl_ship_wal(ctx, payload, sizeof(payload), 4243) == -1);
    assert(ctx->state == REPL_STATE_ERROR && ctx->stream_fd == -1);
    qihse_repl_destroy(ctx);
}

int main(void) {
    test_slot_allocation_failures();
    test_send_all_and_sigpipe();
    puts("replication partial I/O, SIGPIPE and slot allocation checks passed");
    return 0;
}
