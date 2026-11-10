#include "qihse_bolt.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern bool qihse_test_bolt_write_all(int, const uint8_t*, size_t);
extern int qihse_test_pg_write_all(int, const void*, size_t);
extern int qihse_test_pg_parameter_status(int, const char*, const char*);
extern void* __real_malloc(size_t);
extern void* __real_calloc(size_t, size_t);
extern void* __real_realloc(void*, size_t);
extern ssize_t __real_send(int, const void*, size_t, int);

static int malloc_fail = -1, calloc_fail = -1, realloc_fail = -1;
static int send_mode, send_calls;

static int fail_now(int* count) {
    if (*count < 0) return 0;
    if ((*count)-- == 0) { *count = -1; errno = ENOMEM; return 1; }
    return 0;
}
void* __wrap_malloc(size_t n) {
    return fail_now(&malloc_fail) ? NULL : __real_malloc(n);
}
void* __wrap_calloc(size_t n, size_t size) {
    return fail_now(&calloc_fail) ? NULL : __real_calloc(n, size);
}
void* __wrap_realloc(void* p, size_t n) {
    return fail_now(&realloc_fail) ? NULL : __real_realloc(p, n);
}
ssize_t __wrap_send(int fd, const void* p, size_t n, int flags) {
    int call = send_calls++;
    if (send_mode == 1) return 0;
    if (send_mode == 2 && call == 0) { errno = EINTR; return -1; }
    if (send_mode == 3 && call == 2) { errno = EIO; return -1; }
    if ((send_mode == 2 || send_mode == 3) && n > 3) n = 3;
    return __real_send(fd, p, n, flags);
}

static void socket_writes(void) {
    static const char payload[] = "complete response frame";
    for (int protocol = 0; protocol < 2; ++protocol) {
        for (int mode = 1; mode <= 3; ++mode) {
            int fd[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
            send_mode = mode; send_calls = 0;
            bool ok = protocol ?
                qihse_test_pg_write_all(fd[0], payload, sizeof(payload)) == 0 :
                qihse_test_bolt_write_all(fd[0], (const uint8_t*)payload, sizeof(payload));
            assert(ok == (mode == 2));
            char got[sizeof(payload)];
            ssize_t n = read(fd[1], got, sizeof(got));
            if (mode == 1) assert(n == 0);
            else if (mode == 2) assert(n == sizeof(payload) && !memcmp(payload, got, sizeof(payload)));
            else {
                assert(n == 6 && !memcmp(payload, got, 6));
                assert(read(fd[1], got, sizeof(got)) == 0);
            }
            close(fd[0]); close(fd[1]);
        }
        int fd[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
        close(fd[1]); send_mode = 0;
        bool ok = protocol ? qihse_test_pg_write_all(fd[0], payload, sizeof(payload)) == 0 :
            qihse_test_bolt_write_all(fd[0], (const uint8_t*)payload, sizeof(payload));
        assert(!ok); /* default SIGPIPE disposition must not terminate us */
        close(fd[0]);
    }
}

static void bolt_frames(void) {
    const size_t sizes[] = {0, 65534, 65535, 131077};
    uint8_t* payload = malloc(sizes[3]);
    assert(payload);
    for (size_t i = 0; i < sizes[3]; ++i) payload[i] = (uint8_t)(i * 13u);
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        qihse_bolt_buf_t b;
        qihse_bolt_buf_init(&b, 16);
        qihse_bolt_encode_message(&b, 0x71, payload, sizes[i]);
        assert(b.cap);
        uint8_t sig = 0, *out = NULL;
        size_t len = 0, used = 0;
        assert(qihse_bolt_decode_message(b.buf, b.len, &sig, &out, &len, &used) == 0);
        assert(sig == 0x71 && used == b.len && len == sizes[i]);
        assert(!len || !memcmp(out, payload, len));
        free(out);
        /* Length-only callers must receive the same body length. */
        assert(qihse_bolt_decode_message(b.buf, b.len, &sig, NULL, &len, &used) == 0);
        assert(len == sizes[i]);
        out = (uint8_t*)(uintptr_t)1; len = used = 42;
        assert(qihse_bolt_decode_message(b.buf, b.len - 1, &sig, &out, &len, &used) == 1);
        assert(!out && !len && !used);
        qihse_bolt_buf_free(&b);
    }
    free(payload);
}

static void allocation_failures(void) {
    qihse_bolt_buf_t b;
    malloc_fail = 0;
    qihse_bolt_buf_init(&b, 16);
    qihse_bolt_encode_string(&b, "must not dereference a failed allocation");
    assert(!b.cap && !b.len);
    qihse_bolt_buf_free(&b);
    qihse_bolt_buf_init(&b, 1);
    uint8_t* original = b.buf;
    realloc_fail = 0;
    qihse_bolt_encode_string(&b, "reserve failure");
    assert(b.buf == original && !b.cap && !b.len);
    qihse_bolt_encode_int(&b, 42);
    assert(!b.cap && !b.len); /* failure stays sticky */
    qihse_bolt_buf_free(&b);
    qihse_bolt_buf_init(&b, 16);
    qihse_bolt_buf_append(&b, "x", 1);
    errno = 0;
    qihse_bolt_buf_reserve(&b, SIZE_MAX);
    assert(!b.cap && !b.len && errno == EOVERFLOW);
    qihse_bolt_buf_free(&b);

    const uint8_t nested_map[] = {0xa1, 0x81, 'k', 0xb1, 0x4e, 0xc0};
    for (int i = 0; i < 7; ++i) {
        qihse_bolt_decoder_t d;
        qihse_bolt_decoder_init(&d, nested_map, sizeof(nested_map));
        calloc_fail = i;
        qihse_bolt_value_t* value = qihse_bolt_decode(&d);
        calloc_fail = -1;
        assert(value == NULL);
        qihse_bolt_value_free(value);
    }
    uint8_t deep[130];
    memset(deep, 0x91, sizeof(deep)); deep[sizeof(deep) - 1] = 0xc0;
    qihse_bolt_decoder_t d;
    qihse_bolt_decoder_init(&d, deep, sizeof(deep));
    assert(qihse_bolt_decode(&d) == NULL);
    deep[64] = 0xc0;
    qihse_bolt_decoder_init(&d, deep, 65);
    qihse_bolt_value_t* value = qihse_bolt_decode(&d);
    assert(value);
    qihse_bolt_value_free(value);

    char name[700]; memset(name, 'x', sizeof(name)); name[sizeof(name)-1] = 0;
    for (int kind = 0; kind < 2; ++kind) {
        int fd[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
        if (kind) realloc_fail = 0; else malloc_fail = 0;
        assert(qihse_test_pg_parameter_status(fd[0], name, "value") == -1);
        char got;
        assert(recv(fd[1], &got, 1, MSG_DONTWAIT) == -1 &&
               (errno == EAGAIN || errno == EWOULDBLOCK));
        close(fd[0]); close(fd[1]);
    }
}

int main(void) {
    signal(SIGPIPE, SIG_DFL);
    socket_writes();
    bolt_frames();
    allocation_failures();
    puts("PASS protocol partial/failed writes, large Bolt frames and allocation failures");
    return 0;
}
