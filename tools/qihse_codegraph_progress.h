/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_PROGRESS_H
#define QIHSE_CODEGRAPH_PROGRESS_H

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Optional, content-free progress on a caller-owned nonblocking pipe. Call
 * only for work authorized by the operation's principal. UINT64_MAX means an
 * unknown total. A failed notification never changes the operation's result.
 * Keep phases/units compile-time literals, and counters monotonic per stage. */
static inline void cg_progress_emit(const char *phase, const char *unit,
                                    uint64_t completed, uint64_t total) {
    const char *setting = getenv("QIHSE_CODEGRAPH_PROGRESS_FD");
    if (!setting || !*setting || !phase || !unit ||
        strspn(phase, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(phase) ||
        strspn(unit, "abcdefghijklmnopqrstuvwxyz") != strlen(unit) ||
        completed > INT64_MAX || (total != UINT64_MAX &&
        (total > INT64_MAX || completed > total))) return;
    char *end = NULL;
    int saved_errno = errno;
    errno = 0;
    long parsed = strtol(setting, &end, 10);
    if (errno || end == setting || *end || parsed < 3 || parsed > INT_MAX) {
        errno = saved_errno;
        return;
    }
    int fd = (int)parsed, flags = fcntl(fd, F_GETFL);
    if (flags < 0 || !(flags & O_NONBLOCK) || (flags & O_ACCMODE) == O_RDONLY) {
        errno = saved_errno;
        return;
    }
    /* Rate-limit intermediate events per translation unit, but always emit
     * starts, completions and phase changes. Notifications fit PIPE_BUF. */
    static _Thread_local struct timespec last_time;
    static _Thread_local char last_phase[32], last_unit[16];
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
        errno = saved_errno;
        return;
    }
    int64_t ns = (int64_t)(now.tv_sec - last_time.tv_sec) * INT64_C(1000000000) +
                 now.tv_nsec - last_time.tv_nsec;
    if (completed && completed != total && !strcmp(phase, last_phase) &&
        !strcmp(unit, last_unit) && ns < INT64_C(100000000)) {
        errno = saved_errno;
        return;
    }
    char frame[512], total_text[32];
    if (total == UINT64_MAX) memcpy(total_text, "null", 5);
    else snprintf(total_text, sizeof(total_text), "%" PRIu64, total);
    int count = snprintf(frame, sizeof(frame),
        "{\"version\":1,\"phase\":\"%s\",\"unit\":\"%s\","
        "\"completed\":%" PRIu64 ",\"total\":%s}\n",
        phase, unit, completed, total_text);
    if (count <= 0 || (size_t)count >= sizeof(frame)) {
        errno = saved_errno;
        return;
    }
    /* write(2) to a closed pipe raises SIGPIPE before returning EPIPE. Block
     * only in this thread and consume only a newly generated signal. */
    sigset_t block, previous, pending;
    sigemptyset(&block);
    sigaddset(&block, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &block, &previous)) {
        errno = saved_errno;
        return;
    }
    bool already_pending = sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE);
    ssize_t written;
    do written = write(fd, frame, (size_t)count); while (written < 0 && errno == EINTR);
    if (written < 0 && errno == EPIPE && !already_pending) {
        struct timespec zero = {0, 0};
        (void)sigtimedwait(&block, NULL, &zero);
    }
    (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
    if (written == count) {
        last_time = now;
        snprintf(last_phase, sizeof(last_phase), "%s", phase);
        snprintf(last_unit, sizeof(last_unit), "%s", unit);
    }
    errno = saved_errno;
}

#endif
