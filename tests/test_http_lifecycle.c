/* Bounded socketpair regression tests; no listener or external service. */
#define QIHSE_HTTP_REQUEST_TIMEOUT_MS 100
#include "../src/spinnaker/qihse_http_api.c"
#include <assert.h>

static qihse_http_client_t* register_client(qihse_http_server_t* srv, int fd) {
    qihse_http_client_t* ctx = calloc(1, sizeof(*ctx));
    assert(ctx);
    ctx->fd = fd;
    ctx->srv = srv;
    assert(http_deadline_init(&ctx->deadline) == 0);
    assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    pthread_mutex_lock(&srv->lock);
    ctx->next = srv->clients;
    srv->clients = ctx;
    ++srv->active_workers;
    pthread_mutex_unlock(&srv->lock);
    return ctx;
}

static void* idle_acceptor(void* unused) { (void)unused; return NULL; }

static void test_deadline_does_not_renew(void) {
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    struct timespec deadline;
    assert(http_deadline_init(&deadline) == 0);
    struct timespec original = deadline;
    assert(send(fd[1], "a", 1, 0) == 1);
    assert(http_wait_io(fd[0], POLLIN, &deadline));
    char byte;
    assert(recv(fd[0], &byte, 1, 0) == 1);
    assert(!http_wait_io(fd[0], POLLIN, &deadline));
    assert(deadline.tv_sec == original.tv_sec && deadline.tv_nsec == original.tv_nsec);
    /* Even immediately ready descriptors cannot restart an expired budget. */
    assert(send(fd[1], "b", 1, 0) == 1);
    assert(!http_wait_io(fd[0], POLLIN, &deadline));
    assert(!http_wait_io(fd[0], POLLOUT, &deadline));
    close(fd[0]); close(fd[1]);
}

static void test_incomplete_request_drains(void) {
    qihse_http_server_t* srv = qihse_http_server_create(0);
    assert(srv);
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    qihse_http_client_t* ctx = register_client(srv, fd[0]);
    assert(send(fd[1], "GET / HTTP/1.1\r\n", 16, 0) == 16);
    pthread_t worker;
    assert(pthread_create(&worker, NULL, http_client_thread, ctx) == 0);
    pthread_join(worker, NULL);
    assert(srv->active_workers == 0 && srv->clients == NULL);
    close(fd[1]);
    qihse_http_server_destroy(srv);
}

static void test_stop_cancels_registered_clients(void) {
    qihse_http_server_t* srv = qihse_http_server_create(0);
    assert(srv);
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    qihse_http_client_t* ctx = register_client(srv, fd[0]);
    ctx->deadline.tv_sec += 60; /* Cancellation, not timeout, must unblock. */
    __atomic_store_n(&srv->running, 1, __ATOMIC_RELEASE);
    assert(pthread_create(&srv->thread, NULL, idle_acceptor, NULL) == 0);
    pthread_t worker;
    assert(pthread_create(&worker, NULL, http_client_thread, ctx) == 0);
    assert(qihse_http_server_stop(srv) == 0);
    assert(srv->clients == NULL && srv->active_workers == 0 && srv->fd == -1);
    pthread_join(worker, NULL);
    assert(qihse_http_server_stop(srv) == 0);
    close(fd[1]);
    qihse_http_server_destroy(srv);
}

static void test_response_writer_deadline(void) {
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    assert(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
    int capacity = 1024;
    assert(setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0);
    char* body = malloc(1024u * 1024u);
    assert(body);
    memset(body, 'x', 1024u * 1024u);
    http_response_t response = {200, body, 1024u * 1024u, "text/plain"};
    struct timespec deadline;
    assert(http_deadline_init(&deadline) == 0);
    send_response(fd[0], &response, &deadline);
    assert(http_deadline_remaining(&deadline) == 0);
    free(body);
    close(fd[0]); close(fd[1]);
}

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    bool entered;
    bool release;
    int stopped;
    qihse_http_server_t* srv;
} handler_gate_t;

static http_response_t* gated_handler(const http_request_t* req, void* data) {
    (void)req;
    handler_gate_t* gate = data;
    pthread_mutex_lock(&gate->lock);
    gate->entered = true;
    pthread_cond_broadcast(&gate->changed);
    while (!gate->release) pthread_cond_wait(&gate->changed, &gate->lock);
    pthread_mutex_unlock(&gate->lock);
    return http_response_text(200, "done");
}

static void* stop_server(void* data) {
    handler_gate_t* gate = data;
    assert(qihse_http_server_stop(gate->srv) == 0);
    __atomic_store_n(&gate->stopped, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void test_stop_waits_for_handler(void) {
    handler_gate_t gate = {0};
    assert(pthread_mutex_init(&gate.lock, NULL) == 0);
    assert(pthread_cond_init(&gate.changed, NULL) == 0);
    gate.srv = qihse_http_server_create(0);
    assert(gate.srv);
    assert(qihse_http_server_add_route(gate.srv, "/", HTTP_GET, gated_handler, &gate) == 0);
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    qihse_http_client_t* ctx = register_client(gate.srv, fd[0]);
    ctx->deadline.tv_sec += 60;
    __atomic_store_n(&gate.srv->running, 1, __ATOMIC_RELEASE);
    assert(pthread_create(&gate.srv->thread, NULL, idle_acceptor, NULL) == 0);
    const char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert(send(fd[1], request, sizeof(request) - 1, 0) == sizeof(request) - 1);
    pthread_t worker, stopper;
    assert(pthread_create(&worker, NULL, http_client_thread, ctx) == 0);
    pthread_mutex_lock(&gate.lock);
    while (!gate.entered) pthread_cond_wait(&gate.changed, &gate.lock);
    pthread_mutex_unlock(&gate.lock);
    assert(pthread_create(&stopper, NULL, stop_server, &gate) == 0);
    while (__atomic_load_n(&gate.srv->running, __ATOMIC_ACQUIRE)) sched_yield();
    assert(!__atomic_load_n(&gate.stopped, __ATOMIC_ACQUIRE));
    pthread_mutex_lock(&gate.lock);
    gate.release = true;
    pthread_cond_broadcast(&gate.changed);
    pthread_mutex_unlock(&gate.lock);
    pthread_join(stopper, NULL);
    pthread_join(worker, NULL);
    assert(gate.srv->active_workers == 0 && gate.srv->clients == NULL);
    close(fd[1]);
    qihse_http_server_destroy(gate.srv);
    pthread_cond_destroy(&gate.changed);
    pthread_mutex_destroy(&gate.lock);
}

int main(void) {
    alarm(5);
    test_deadline_does_not_renew();
    test_incomplete_request_drains();
    test_stop_cancels_registered_clients();
    test_response_writer_deadline();
    test_stop_waits_for_handler();
    puts("PASS HTTP monotonic deadline and cancellation lifecycle");
    return 0;
}
