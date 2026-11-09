/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_progress.h"
#include <assert.h>

int main(void) {
    int channel[2];
    assert(pipe2(channel, O_NONBLOCK | O_CLOEXEC) == 0);
    char setting[32], bytes[512];
    snprintf(setting, sizeof(setting), "%d", channel[1]);
    assert(setenv("QIHSE_CODEGRAPH_PROGRESS_FD", setting, 1) == 0);
    errno = ERANGE;
    cg_progress_emit("import", "bytes", 0, 42);
    assert(errno == ERANGE);
    ssize_t size = read(channel[0], bytes, sizeof(bytes) - 1);
    assert(size > 0);
    bytes[size] = '\0';
    assert(strstr(bytes, "\"phase\":\"import\"") &&
           strstr(bytes, "\"completed\":0") && strstr(bytes, "\"total\":42"));
    cg_progress_emit("import", "bytes", 42, 42);
    assert(read(channel[0], bytes, sizeof(bytes)) > 0);
    cg_progress_emit("import", "bytes", 43, 42);
    assert(read(channel[0], bytes, sizeof(bytes)) == -1 && errno == EAGAIN);
    cg_progress_emit("bad\"phase", "bytes", 0, 42);
    assert(read(channel[0], bytes, sizeof(bytes)) == -1 && errno == EAGAIN);
    cg_progress_emit("verify", "records", 0, UINT64_MAX);
    size = read(channel[0], bytes, sizeof(bytes) - 1);
    assert(size > 0);
    bytes[size] = '\0';
    assert(strstr(bytes, "\"total\":null"));
    memset(bytes, '.', sizeof(bytes));
    while (write(channel[1], bytes, sizeof(bytes)) > 0) {}
    errno = EDOM;
    cg_progress_emit("publish", "records", 0, 1);
    assert(errno == EDOM); /* Full nonblocking pipe must not fail work. */
    close(channel[0]);
    errno = ERANGE;
    cg_progress_emit("publish", "records", 1, 1);
    assert(errno == ERANGE); /* Closed pipe must not terminate the process. */
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    assert(pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0);
    assert(sigpending(&pending) == 0 && !sigismember(&pending, SIGPIPE));
    cg_progress_emit("publish", "records", 1, 1);
    assert(sigpending(&pending) == 0 && !sigismember(&pending, SIGPIPE));
    /* A preexisting pending signal belongs to the caller, not this helper. */
    assert(raise(SIGPIPE) == 0);
    cg_progress_emit("publish", "records", 1, 1);
    assert(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE));
    struct timespec zero = {0, 0};
    assert(sigtimedwait(&blocked, NULL, &zero) == SIGPIPE);
    assert(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
    close(channel[1]);
    assert(unsetenv("QIHSE_CODEGRAPH_PROGRESS_FD") == 0);
    cg_progress_emit("publish", "records", 1, 1);
    puts("native CodeGraph progress: PASS");
    return 0;
}
