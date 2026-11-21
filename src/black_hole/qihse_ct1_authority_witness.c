#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_authority_witness.h"
#ifdef QIHSE_CT1_INSECURE_DEV_WITNESS
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LOG_NAME "ct1-witness.log"
#define LOCK_NAME "ct1-witness.lock"
#define HEADER_BYTES 40u
#define RECORD_BYTES 297u
#define MAX_RECORDS 1024u
static const unsigned char magic[8] = {'C','T','1','W','I','T','0','1'};

static void put64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(n >> (56u - 8u * i));
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n = (n << 8) | p[i];
    return n;
}
static bool same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
/* Traverse every component by descriptor. Reject symlinks, .., untrusted
 * writable ancestors, and any private directory not owned by this service. */
static int open_dir(const char *path) {
    if (!path || !*path || strnlen(path, 4097) > 4096) return -1;
    int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    const char *p = path;
    bool final = false;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t n = (size_t)(end - p);
        if (n > 255 || (n == 2 && p[0] == '.' && p[1] == '.')) goto fail;
        if (n == 1 && *p == '.') { p = end; continue; }
        char name[256];
        memcpy(name, p, n); name[n] = 0;
        int next = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto fail;
        if (close(fd)) { close(next); return -1; }
        fd = next;
        final = true;
        p = end;
    }
    struct stat st;
    if (!final || fstat(fd, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 07777) != 0700) goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}
/* Validate the ancestry too: open_dir's traversal is no-follow, but writable
 * ancestors permit directory substitution by another principal. */
static bool ancestry_ok(const char *path) {
    int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = true;
    struct stat st;
    if (fstat(fd, &st) || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) ok = false;
    const char *p = path;
    while (ok && *p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t n = (size_t)(end - p);
        if (n > 255 || (n == 2 && p[0] == '.' && p[1] == '.')) { ok = false; break; }
        if (n == 1 && *p == '.') { p = end; continue; }
        char name[256]; memcpy(name, p, n); name[n] = 0;
        int next = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { ok = false; break; }
        close(fd); fd = next;
        if (fstat(fd, &st) || !S_ISDIR(st.st_mode) ||
            (st.st_mode & 0022) || (st.st_uid != 0 && st.st_uid != geteuid())) ok = false;
        p = end;
    }
    if (close(fd)) ok = false;
    return ok;
}
static int witness_dir(const char *path) {
    if (!path || !*path || strnlen(path, 4097) > 4096 || !ancestry_ok(path)) return -1;
    return open_dir(path);
}
static bool stable_dir(int fd, const char *path) {
    struct stat a, b;
    int check = witness_dir(path);
    bool ok = check >= 0 && !fstat(fd, &a) && !fstat(check, &b) &&
        same_inode(&a, &b) && (a.st_mode & 07777) == 0700 && a.st_uid == geteuid();
    if (check >= 0 && close(check)) ok = false;
    return ok;
}
static bool file_ok(int dir, const char *name, int fd, off_t size) {
    struct stat a, b;
    return !fstat(fd, &a) && !fstatat(dir, name, &b, AT_SYMLINK_NOFOLLOW) &&
        same_inode(&a, &b) && S_ISREG(a.st_mode) && S_ISREG(b.st_mode) &&
        a.st_uid == geteuid() && b.st_uid == geteuid() &&
        (a.st_mode & 07777) == 0600 && (b.st_mode & 07777) == 0600 &&
        a.st_nlink == 1 && b.st_nlink == 1 && a.st_size == size && b.st_size == size;
}
static bool read_at(int fd, unsigned char *out, size_t len, off_t off) {
    for (size_t n = 0; n < len;) {
        ssize_t r = pread(fd, out + n, len - n, off + (off_t)n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        n += (size_t)r;
    }
    return true;
}
static bool write_at(int fd, const unsigned char *in, size_t len, off_t off) {
    for (size_t n = 0; n < len;) {
        ssize_t r = pwrite(fd, in + n, len - n, off + (off_t)n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        n += (size_t)r;
    }
    return true;
}
static bool clock_available(void) {
    struct timespec now;
    return clock_gettime(CLOCK_REALTIME, &now) == 0 && now.tv_sec > 0 &&
        now.tv_nsec >= 0 && now.tv_nsec < 1000000000L;
}
static bool lock_state(int dir, int fd, unsigned char expected) {
    unsigned char state;
    return file_ok(dir, LOCK_NAME, fd, 1) && read_at(fd, &state, 1, 0) &&
        state == expected && file_ok(dir, LOCK_NAME, fd, 1);
}

bool qihse_ct1_witness_bootstrap(const char *path,
    unsigned char initial_head[32]) {
    if (!initial_head || !clock_available()) return false;
    memset(initial_head, 0, 32);
    int dir = witness_dir(path), lock = -1, log = -1;
    bool ok = false;
    unsigned char header[HEADER_BYTES] = {0};
    if (dir < 0) return false;
    struct stat st;
    if (fstatat(dir, LOG_NAME, &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
        fstatat(dir, LOCK_NAME, &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
        goto done;
    lock = openat(dir, LOCK_NAME, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW |
        O_NONBLOCK | O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX) || !file_ok(dir, LOCK_NAME, lock, 0) ||
        !write_at(lock, (const unsigned char *)"1", 1, 0) || fsync(lock) || fsync(dir)) goto done;
    log = openat(dir, LOG_NAME, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW |
        O_NONBLOCK | O_CLOEXEC, 0600);
    if (log < 0 || !file_ok(dir, LOG_NAME, log, 0)) goto done;
    memcpy(header, magic, 8);
    if (!SHA256(header, 8, header + 8)) goto done;
    if (!write_at(log, header, sizeof(header), 0) || fsync(log) ||
        !file_ok(dir, LOG_NAME, log, HEADER_BYTES) || fsync(dir) ||
        !stable_dir(dir, path) || !lock_state(dir, lock, '1')) goto done;
    if (!write_at(lock, (const unsigned char *)"0", 1, 0) || fsync(lock) ||
        !lock_state(dir, lock, '0') || !stable_dir(dir, path)) goto done;
    memcpy(initial_head, header + 8, 32);
    ok = true;
done:
    if (log >= 0 && close(log)) ok = false;
    if (lock >= 0 && close(lock)) ok = false;
    if (close(dir)) ok = false;
    if (!ok) memset(initial_head, 0, 32);
    return ok;
}

bool qihse_ct1_witness_consume(const char *path,
    const qihse_ct1_recovery_manifest_t *m, uint64_t caller_now_ms,
    const unsigned char expected_head[32], unsigned char next_head[32]) {
    if (!next_head) return false;
    memset(next_head, 0, 32);
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    if (!expected_head || !clock_available() ||
        !qihse_ct1_recovery_encode(m, false, false, wire) ||
        caller_now_ms < m->issued_ms || caller_now_ms >= m->expires_ms ||
        caller_now_ms - m->issued_ms > QIHSE_CT1_RECOVERY_MAX_AGE_MS) return false;
    int dir = witness_dir(path), lock = -1, log = -1;
    bool ok = false;
    unsigned char header[HEADER_BYTES], record[RECORD_BYTES], previous[32];
    unsigned char *nonces = NULL;
    if (dir < 0) return false;
    lock = openat(dir, LOCK_NAME, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (lock < 0 || flock(lock, LOCK_EX) || !lock_state(dir, lock, '0')) goto done;
    log = openat(dir, LOG_NAME, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    if (log < 0 || fstat(log, &st) || st.st_size < HEADER_BYTES ||
        st.st_size > HEADER_BYTES + (off_t)MAX_RECORDS * RECORD_BYTES ||
        (st.st_size - HEADER_BYTES) % RECORD_BYTES ||
        !file_ok(dir, LOG_NAME, log, st.st_size) ||
        !read_at(log, header, sizeof(header), 0) ||
        memcmp(header, magic, 8) ||
        !SHA256(magic, 8, previous) || memcmp(previous, header + 8, 32)) goto done;
    size_t count = (size_t)((st.st_size - HEADER_BYTES) / RECORD_BYTES);
    if (count >= MAX_RECORDS) goto done;
    nonces = calloc(MAX_RECORDS, 32);
    if (!nonces) goto done;
    uint64_t last_epoch = 0;
    for (size_t i = 0; i < count; i++) {
        if (!read_at(log, record, sizeof(record), HEADER_BYTES + (off_t)i * RECORD_BYTES) ||
            get64(record) <= last_epoch || memcmp(record + 233, previous, 32)) goto done;
        unsigned char check[32], nonzero = 0;
        if (!SHA256(record, RECORD_BYTES - 32, check) ||
            memcmp(check, record + 265, 32)) goto done;
        for (size_t b = 0; b < 32; b++) nonzero |= record[8 + b];
        const unsigned char *end = memchr(record + 40, 0, 65);
        if (!nonzero || !end || end == record + 40) goto done;
        for (const unsigned char *p = end; p < record + 105; p++)
            if (*p) goto done;
        for (size_t j = 0; j < i; j++)
            if (!memcmp(nonces + j * 32, record + 8, 32)) goto done;
        memcpy(nonces + i * 32, record + 8, 32);
        last_epoch = get64(record);
        memcpy(previous, record + 265, 32);
    }
    if (m->epoch <= last_epoch || memcmp(previous, expected_head, 32)) goto done;
    for (size_t i = 0; i < count; i++)
        if (!memcmp(nonces + i * 32, m->nonce, 32)) goto done;
    memset(record, 0, RECORD_BYTES);
    put64(record, m->epoch);
    memcpy(record + 8, m->nonce, 32);
    memcpy(record + 40, m->replication_principal_id,
        strlen(m->replication_principal_id));
    if (!SHA256(wire, sizeof(wire), record + 105)) goto done;
    memcpy(record + 137, m->issuer_operator_pin, 32);
    memcpy(record + 169, m->source_peer_pin, 32);
    memcpy(record + 201, m->target_peer_pin, 32);
    memcpy(record + 233, previous, 32);
    if (!SHA256(record, RECORD_BYTES - 32, record + 265) ||
        !stable_dir(dir, path) || !file_ok(dir, LOG_NAME, log, st.st_size) ||
        !lock_state(dir, lock, '0')) goto done;
    /* Persistent intent survives a torn append, failed sync or process exit.
     * Never truncate/repair an uncertain log automatically. */
    if (!write_at(lock, (const unsigned char *)"1", 1, 0) || fsync(lock) ||
        !lock_state(dir, lock, '1')) goto done;
    if (!write_at(log, record, sizeof(record), st.st_size) || fsync(log) ||
        !file_ok(dir, LOG_NAME, log, st.st_size + RECORD_BYTES) ||
        fsync(dir) || !stable_dir(dir, path) || !lock_state(dir, lock, '1')) goto done;
    if (!write_at(lock, (const unsigned char *)"0", 1, 0) || fsync(lock) ||
        !lock_state(dir, lock, '0') || !stable_dir(dir, path)) goto done;
    memcpy(next_head, record + 265, 32);
    ok = true;
done:
    free(nonces);
    if (log >= 0 && close(log)) ok = false;
    if (lock >= 0 && close(lock)) ok = false;
    if (close(dir)) ok = false;
    if (!ok) memset(next_head, 0, 32);
    return ok;
}
#endif /* QIHSE_CT1_INSECURE_DEV_WITNESS */
