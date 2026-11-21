#include "qihse_ct1_authority_store.h"
#include "qihse_ct1_recovery_manifest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LOCK_NAME "authority.lock"
#define DATA_NAME "authority.log"
#define CHECKPOINT_NAME "authority.checkpoint"
#define MAGIC UINT64_C(0x4354314155544831)
#define TYPE_INIT 1
#define TYPE_ISSUE 2
#define TYPE_RETIRE 3
#define TYPE_CLOCK 4
#define TYPE_BIND 5
#define MAX_RECORDS 1000000

#ifdef QIHSE_CT1_TEST_CRASH_CUT
/* Test-only _exit cuts: 0 before ledger pwrite, 1 after it, 2 after ledger
 * fsync, 3 after ledger directory fsync, 4 before checkpoint pwrite,
 * 5 after it, 6 after checkpoint fsync, 7 after checkpoint directory fsync,
 * 8 after final validation. b/r select bind/retire intent only. */
static void crash_cut(uint64_t type, char cut)
{
    if (type != TYPE_BIND && type != TYPE_RETIRE) return;
    const char *selected = getenv("QIHSE_CT1_TEST_CRASH_CUT");
    if (selected && selected[0] == (type == TYPE_BIND ? 'b' : 'r') &&
        selected[1] == cut && !selected[2]) _exit(90 + cut - '0');
}
#else
#define crash_cut(type, cut) ((void)(type), (void)(cut))
#endif

/* Local fixed-format ledger, validated in full on every operation. The digest
 * detects torn/corrupt tails, not malicious rollback by the host owner. */
typedef struct {
    uint64_t magic, type, epoch, clock_ms, expires_ms;
    unsigned char nonce[32];
    unsigned char previous[SHA256_DIGEST_LENGTH];
    unsigned char digest[SHA256_DIGEST_LENGTH];
} record_t;

struct qihse_ct1_authority_store {
    char *path;
    int dirfd;
    dev_t dir_dev, lock_dev, data_dev;
    ino_t dir_ino, lock_ino, data_ino;
    struct qihse_ct1_authority_store *checkpoint;
    int strict, poisoned;
};

typedef struct {
    uint64_t epoch, clock_ms, issued_ms, expires_ms;
    unsigned char nonce[32], digest[SHA256_DIGEST_LENGTH];
    unsigned char manifest_digest[SHA256_DIGEST_LENGTH];
    int outstanding, bound;
} ledger_t;

static int valid_file(int fd, uid_t uid, mode_t mode, dev_t dev, ino_t ino)
{
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != uid ||
        (st.st_mode & 07777) != mode || st.st_nlink != 1 ||
        (dev && (st.st_dev != dev || st.st_ino != ino))) return -1;
    return 0;
}

/* A private leaf is not enough when another UID owns an ancestor and can
 * rename the leaf (including an ancestor in a caller-supplied path). */
static int safe_ancestors(int dirfd)
{
    int child = dup(dirfd);
    if (child < 0) return -1;
    for (unsigned int depth = 0; depth < 256; ++depth) {
        struct stat a, b;
        int parent = openat(child, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent < 0 || fstat(child, &a) || fstat(parent, &b)) {
            if (parent >= 0) close(parent);
            close(child);
            return -1;
        }
        if (b.st_uid != 0 && b.st_uid != geteuid()) {
            close(child); close(parent); return -1;
        }
        if ((b.st_mode & 0022) && !(b.st_mode & S_ISVTX)) {
            close(child); close(parent); return -1;
        }
        close(child);
        if (a.st_dev == b.st_dev && a.st_ino == b.st_ino) {
            close(parent); return 0;
        }
        child = parent;
    }
    close(child);
    return -1;
}

static int empty_directory(int dirfd)
{
    int fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    DIR *d = fdopendir(fd);
    if (!d) { close(fd); return -1; }
    int empty = 1;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(d))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            empty = 0; break;
        }
        errno = 0;
    }
    if (errno) empty = 0;
    closedir(d);
    return empty ? 0 : -1;
}

/* Strict paths are walked without following ANY symlink component. */
static int strict_directory(const char *path)
{
    if (!path || !*path || geteuid() != 0) return -1;
    char *copy = strdup(path);
    if (!copy) return -1;
    int fd = open(*path == '/' ? "/" : ".",
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); fd >= 0 && part;
         part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, "..")) { close(fd); fd = -1; break; }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(fd);
        fd = next;
    }
    free(copy);
    return fd;
}

static int valid_directory(qihse_ct1_authority_store_t *s)
{
    struct stat st;
    int fd = s->strict ? strict_directory(s->path) :
             open(s->path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = !fstat(fd, &st) && S_ISDIR(st.st_mode) &&
             st.st_uid == geteuid() && (st.st_mode & 07777) == 0700 &&
             st.st_dev == s->dir_dev && st.st_ino == s->dir_ino &&
             !safe_ancestors(fd);
    close(fd);
    return ok ? 0 : -1;
}

static int open_checked(qihse_ct1_authority_store_t *s, const char *name,
                        dev_t dev, ino_t ino)
{
    int fd = openat(s->dirfd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat st;
    if (valid_file(fd, geteuid(), 0600, dev, ino) ||
        fstatat(s->dirfd, name, &st, AT_SYMLINK_NOFOLLOW) ||
        st.st_dev != dev || st.st_ino != ino) {
        close(fd);
        return -1;
    }
    return fd;
}

static int lock_store(qihse_ct1_authority_store_t *s)
{
    if (s->poisoned || valid_directory(s) ||
        (s->checkpoint && valid_directory(s->checkpoint))) return -1;
    int fd = open_checked(s, LOCK_NAME, s->lock_dev, s->lock_ino);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) || valid_directory(s)) { close(fd); return -1; }
    struct stat st;
    if (fstatat(s->dirfd, LOCK_NAME, &st, AT_SYMLINK_NOFOLLOW) ||
        st.st_dev != s->lock_dev || st.st_ino != s->lock_ino) {
        close(fd); return -1;
    }
    return fd;
}

static int read_ledger(int fd, ledger_t *state)
{
    struct stat st;
    if (fstat(fd, &st) || st.st_size <= 0 ||
        st.st_size % (off_t)sizeof(record_t) != 0 ||
        st.st_size / (off_t)sizeof(record_t) > MAX_RECORDS) return -1;
    memset(state, 0, sizeof(*state));
    for (off_t off = 0; off < st.st_size; off += sizeof(record_t)) {
        record_t r;
        if (pread(fd, &r, sizeof(r), off) != sizeof(r) || r.magic != MAGIC ||
            memcmp(r.previous, state->digest, sizeof(r.previous))) return -1;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)&r, sizeof(r) - sizeof(r.digest), digest);
        if (memcmp(digest, r.digest, sizeof(digest)) ||
            (off == 0 && (r.type != TYPE_INIT || r.epoch || r.expires_ms ||
                          memcmp(r.nonce, state->nonce, sizeof(r.nonce)))) ||
            (off != 0 && (r.clock_ms < state->clock_ms || r.epoch < state->epoch))) return -1;
        if (off != 0) {
            if (r.type == TYPE_ISSUE) {
                if (state->epoch == UINT64_MAX || r.epoch != state->epoch + 1 ||
                    r.expires_ms <= r.clock_ms ||
                    r.expires_ms - r.clock_ms > 900000 ||
                    (state->outstanding && state->expires_ms > r.clock_ms)) return -1;
                state->outstanding = 1;
                state->bound = 0;
                memset(state->manifest_digest, 0, sizeof(state->manifest_digest));
                state->issued_ms = r.clock_ms;
                state->expires_ms = r.expires_ms;
                memcpy(state->nonce, r.nonce, sizeof(r.nonce));
            } else if (r.type == TYPE_RETIRE) {
                if (!state->outstanding || r.epoch != state->epoch ||
                    r.clock_ms >= state->expires_ms || r.expires_ms != state->expires_ms ||
                    memcmp(r.nonce, state->nonce, sizeof(r.nonce))) return -1;
                state->outstanding = 0;
            } else if (r.type == TYPE_BIND) {
                if (!state->outstanding || state->bound ||
                    r.epoch != state->epoch || r.expires_ms != state->expires_ms ||
                    r.clock_ms >= state->expires_ms) return -1;
                state->bound = 1;
                memcpy(state->manifest_digest, r.nonce, sizeof(r.nonce));
            } else if (r.type == TYPE_CLOCK) {
                unsigned char zero[32] = {0};
                if (r.epoch != state->epoch || r.expires_ms ||
                    memcmp(r.nonce, zero, sizeof(zero))) return -1;
            } else return -1;
        }
        state->epoch = r.epoch;
        state->clock_ms = r.clock_ms;
        memcpy(state->digest, r.digest, sizeof(r.digest));
    }
    return 0;
}

/* The checkpoint is one fixed-size, checksummed image. An in-place torn write
 * either retains the old head (which mismatches the new ledger), fails checksum,
 * or commits the new head. No code guesses which history was intended. */
static void checkpoint_image(const ledger_t *state, record_t *r)
{
    memset(r, 0, sizeof(*r));
    r->magic = MAGIC;
    r->type = (uint64_t)state->outstanding;
    r->epoch = state->epoch;
    r->clock_ms = state->clock_ms;
    r->expires_ms = state->expires_ms;
    memcpy(r->nonce, state->nonce, sizeof(r->nonce));
    memcpy(r->previous, state->digest, sizeof(r->previous));
    SHA256((const unsigned char *)r, sizeof(*r) - sizeof(r->digest), r->digest);
}

static int checkpoint_state(qihse_ct1_authority_store_t *s,
                            const ledger_t *state, int persist, uint64_t type)
{
    if (!s->checkpoint) return 0;
    qihse_ct1_authority_store_t *c = s->checkpoint;
    if (valid_directory(s) || valid_directory(c)) return -1;
    int fd = open_checked(c, CHECKPOINT_NAME, c->data_dev, c->data_ino);
    if (fd < 0) return -1;
    record_t expected, actual;
    checkpoint_image(state, &expected);
    struct stat st;
    int ok = -1;
    if (fstat(fd, &st) || st.st_size != sizeof(expected)) goto done;
    if (persist) {
        crash_cut(type, '4'); /* Before checkpoint write. */
        if (pwrite(fd, &expected, sizeof(expected), 0) != sizeof(expected)) goto done;
        crash_cut(type, '5');
        if (fsync(fd)) goto done;
        crash_cut(type, '6');
        if (fsync(c->dirfd)) goto done;
        crash_cut(type, '7');
    } else if (pread(fd, &actual, sizeof(actual), 0) != sizeof(actual) ||
               memcmp(&actual, &expected, sizeof(actual))) goto done;
    if (valid_directory(s) || valid_directory(c) ||
        valid_file(fd, 0, 0600, c->data_dev, c->data_ino)) goto done;
    ok = 0;
done:
    close(fd);
    if (ok) s->poisoned = 1;
    return ok;
}

static int now_ms(uint64_t *out)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) || t.tv_sec < 0 ||
        (uint64_t)t.tv_sec > (UINT64_MAX - 999) / 1000 ||
        t.tv_nsec < 0 || t.tv_nsec >= 1000000000) return -1;
    *out = (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
    return 0;
}

static int append_record(qihse_ct1_authority_store_t *s, int fd, ledger_t *state,
                         uint64_t type, uint64_t epoch, uint64_t now,
                         uint64_t expiry, const unsigned char *nonce)
{
    record_t r = {0};
    struct stat st;
    if (fstat(fd, &st) || st.st_size <= 0 ||
        st.st_size % (off_t)sizeof(r) ||
        st.st_size / (off_t)sizeof(r) >= MAX_RECORDS) return -1;
    r.magic = MAGIC;
    r.type = type;
    r.epoch = epoch;
    r.clock_ms = now;
    r.expires_ms = expiry;
    if (nonce) memcpy(r.nonce, nonce, sizeof(r.nonce));
    memcpy(r.previous, state->digest, sizeof(r.previous));
    SHA256((const unsigned char *)&r, sizeof(r) - sizeof(r.digest), r.digest);
    crash_cut(type, '0'); /* Before intent write. */
    if (pwrite(fd, &r, sizeof(r), st.st_size) != sizeof(r)) return -1;
    crash_cut(type, '1');
    if (fsync(fd)) return -1;
    crash_cut(type, '2');
    if (fsync(s->dirfd)) return -1;
    crash_cut(type, '3');
    memcpy(state->digest, r.digest, sizeof(r.digest));
    state->clock_ms = now;
    if (s->checkpoint) {
        /* Reparse rather than maintaining a second transition implementation. */
        if (read_ledger(fd, state) || checkpoint_state(s, state, 1, type)) {
            s->poisoned = 1;
            return -1;
        }
    }
    crash_cut(type, '8'); /* Both heads written and checked; reply not sent. */
    return 0;
}

static int open_data(qihse_ct1_authority_store_t *s)
{
    return open_checked(s, DATA_NAME, s->data_dev, s->data_ino);
}

static int open_or_initialize(const char *directory,
                              qihse_ct1_authority_store_t **out, int initialize)
{
    if (!directory || (!initialize && !out)) return -1;
    if (out) *out = NULL;
    qihse_ct1_authority_store_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    s->dirfd = -1;
    s->path = strdup(directory);
    if (!s->path) goto fail;
    s->dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (s->dirfd < 0 || fstat(s->dirfd, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 07777) != 0700) goto fail;
    s->dir_dev = st.st_dev; s->dir_ino = st.st_ino;
    if (valid_directory(s)) goto fail;
    if (initialize && empty_directory(s->dirfd)) goto fail;
    int lock = openat(s->dirfd, LOCK_NAME,
                      O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                      (initialize ? O_CREAT | O_EXCL : 0), 0600);
    int fresh = initialize;
    if (lock < 0) goto fail;
    if (valid_file(lock, geteuid(), 0600, 0, 0) ||
        (fresh && (fsync(lock) || fsync(s->dirfd)))) {
        close(lock); goto fail;
    }
    if (flock(lock, LOCK_EX) || valid_directory(s) || fstat(lock, &st)) {
        close(lock); goto fail;
    }
    s->lock_dev = st.st_dev; s->lock_ino = st.st_ino;
    struct stat named;
    if (fstatat(s->dirfd, LOCK_NAME, &named, AT_SYMLINK_NOFOLLOW) ||
        named.st_dev != s->lock_dev || named.st_ino != s->lock_ino) {
        close(lock); goto fail;
    }
    int data;
    if (fresh) {
        /* A prior state with no lock is not a first use. */
        if (!fstatat(s->dirfd, DATA_NAME, &named, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) {
            close(lock); goto fail;
        }
        data = openat(s->dirfd, DATA_NAME, O_RDWR | O_CREAT | O_EXCL |
                      O_NOFOLLOW | O_CLOEXEC, 0600);
        if (data < 0 || fsync(s->dirfd)) { if (data >= 0) close(data); close(lock); goto fail; }
        record_t init = {0};
        uint64_t now;
        if (now_ms(&now)) { close(data); close(lock); goto fail; }
        init.magic = MAGIC; init.type = TYPE_INIT; init.clock_ms = now;
        SHA256((const unsigned char *)&init, sizeof(init) - sizeof(init.digest), init.digest);
        if (write(data, &init, sizeof(init)) != sizeof(init) || fsync(data) ||
            fsync(s->dirfd)) { close(data); close(lock); goto fail; }
    } else {
        data = openat(s->dirfd, DATA_NAME, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (data < 0) { close(lock); goto fail; }
    }
    if (valid_file(data, geteuid(), 0600, 0, 0) || fstat(data, &st) ||
        fstatat(s->dirfd, DATA_NAME, &named, AT_SYMLINK_NOFOLLOW) ||
        named.st_dev != st.st_dev || named.st_ino != st.st_ino) {
        close(data); close(lock); goto fail;
    }
    s->data_dev = st.st_dev; s->data_ino = st.st_ino;
    ledger_t state;
    int ok = !read_ledger(data, &state);
    close(data); close(lock);
    if (!ok) goto fail;
    if (initialize) qihse_ct1_authority_store_close(s);
    else *out = s;
    return 0;
fail:
    qihse_ct1_authority_store_close(s);
    return -1;
}

int qihse_ct1_authority_store_initialize(const char *directory)
{
    return open_or_initialize(directory, NULL, 1);
}

int qihse_ct1_authority_store_open(const char *directory,
                                    qihse_ct1_authority_store_t **out)
{
    return open_or_initialize(directory, out, 0);
}

void qihse_ct1_authority_store_close(qihse_ct1_authority_store_t *s)
{
    if (!s) return;
    qihse_ct1_authority_store_close(s->checkpoint);
    if (s->dirfd >= 0) close(s->dirfd);
    free(s->path);
    free(s);
}

/* Compare candidate against every issuance, not just the current challenge. */
static int nonce_unused(int fd, const unsigned char nonce[32])
{
    struct stat st;
    if (fstat(fd, &st)) return -1;
    for (off_t off = 0; off < st.st_size; off += sizeof(record_t)) {
        record_t r;
        if (pread(fd, &r, sizeof(r), off) != sizeof(r)) return -1;
        if (r.type == TYPE_ISSUE && !memcmp(r.nonce, nonce, 32)) return -1;
    }
    return 0;
}

static int begin(qihse_ct1_authority_store_t *s, int *lock, int *data,
                 ledger_t *state, uint64_t *now)
{
    *lock = lock_store(s);
    if (*lock < 0) return -1;
    *data = open_data(s);
    if (*data < 0 || read_ledger(*data, state) ||
        checkpoint_state(s, state, 0, 0) || now_ms(now) ||
        *now < state->clock_ms) return -1;
    if (*now > state->clock_ms &&
        append_record(s, *data, state, TYPE_CLOCK, state->epoch, *now, 0, NULL)) return -1;
    return 0;
}

static qihse_ct1_authority_store_t *strict_directory_handle(const char *path)
{
    qihse_ct1_authority_store_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->strict = 1;
    s->dirfd = strict_directory(path);
    s->path = path ? strdup(path) : NULL;
    struct stat st;
    if (s->dirfd < 0 || !s->path || fstat(s->dirfd, &st)) goto fail;
    s->dir_dev = st.st_dev;
    s->dir_ino = st.st_ino;
    if (valid_directory(s)) goto fail;
    return s;
fail:
    qihse_ct1_authority_store_close(s);
    return NULL;
}

/* A recursive ledger backup must not also capture the independent anchor. */
static int contains_directory(qihse_ct1_authority_store_t *ancestor,
                               qihse_ct1_authority_store_t *descendant)
{
    int fd = dup(descendant->dirfd);
    if (fd < 0) return -1;
    for (unsigned int depth = 0; depth < 256; ++depth) {
        struct stat st, parent_st;
        if (fstat(fd, &st)) { close(fd); return -1; }
        if (st.st_dev == ancestor->dir_dev && st.st_ino == ancestor->dir_ino) {
            close(fd); return 1;
        }
        int parent = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent < 0 || fstat(parent, &parent_st)) {
            if (parent >= 0) close(parent);
            close(fd); return -1;
        }
        close(fd);
        if (st.st_dev == parent_st.st_dev && st.st_ino == parent_st.st_ino) {
            close(parent); return 0;
        }
        fd = parent;
    }
    close(fd);
    return -1;
}

static int strict_store(const char *directory, const char *checkpoint_directory,
                        uid_t b_uid, qihse_ct1_authority_store_t **out, int initialize)
{
    if (out) *out = NULL;
    if (geteuid() != 0 || b_uid == 0 || (!out && !initialize)) return -1;
    qihse_ct1_authority_store_t *s = NULL;
    qihse_ct1_authority_store_t *d = strict_directory_handle(directory);
    qihse_ct1_authority_store_t *c = strict_directory_handle(checkpoint_directory);
    int lock = -1, data = -1, cp = -1, ok = -1;
    if (!d || !c || contains_directory(d, c) || contains_directory(c, d)) goto done;
    if (initialize && (empty_directory(d->dirfd) || empty_directory(c->dirfd) ||
                       qihse_ct1_authority_store_initialize(directory))) goto done;
    if (qihse_ct1_authority_store_open(directory, &s)) goto done;
    s->strict = 1;
    if (s->dir_dev != d->dir_dev || s->dir_ino != d->dir_ino) goto done;
    s->checkpoint = c;
    c = NULL;
    lock = lock_store(s);
    if (lock < 0) goto done;
    data = open_data(s);
    ledger_t state;
    uint64_t now;
    if (data < 0 || read_ledger(data, &state) || now_ms(&now) || now < state.clock_ms)
        goto done;
    cp = openat(s->checkpoint->dirfd, CHECKPOINT_NAME,
                O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                (initialize ? O_CREAT | O_EXCL : 0), 0600);
    struct stat st;
    if (cp < 0 || valid_file(cp, 0, 0600, 0, 0) || fstat(cp, &st)) goto done;
    s->checkpoint->data_dev = st.st_dev;
    s->checkpoint->data_ino = st.st_ino;
    if (initialize) {
        record_t image;
        checkpoint_image(&state, &image);
        if (write(cp, &image, sizeof(image)) != sizeof(image) || fsync(cp) ||
            fsync(s->checkpoint->dirfd)) goto done;
    }
    if (checkpoint_state(s, &state, 0, 0)) goto done;
    /* Opening is also an observation of the trusted local clock. */
    if (now > state.clock_ms &&
        append_record(s, data, &state, TYPE_CLOCK, state.epoch, now, 0, NULL)) goto done;
    ok = 0;
done:
    if (cp >= 0) close(cp);
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    qihse_ct1_authority_store_close(d);
    qihse_ct1_authority_store_close(c);
    if (!ok && !initialize) { *out = s; s = NULL; }
    qihse_ct1_authority_store_close(s);
    return ok;
}

int qihse_ct1_authority_store_initialize_strict(const char *directory,
                                               const char *checkpoint_directory,
                                               uid_t b_uid)
{
    return strict_store(directory, checkpoint_directory, b_uid, NULL, 1);
}

int qihse_ct1_authority_store_open_strict(const char *directory,
                                         const char *checkpoint_directory,
                                         uid_t b_uid,
                                         qihse_ct1_authority_store_t **out)
{
    return strict_store(directory, checkpoint_directory, b_uid, out, 0);
}

int qihse_ct1_authority_store_issue(qihse_ct1_authority_store_t *s,
                                    uint64_t ttl_ms, qihse_ct1_authority_challenge_t *out)
{
    if (!s || !out || !ttl_ms || ttl_ms > 900000) return -1;
    int lock = -1, data = -1, ok = -1;
    ledger_t state;
    uint64_t now;
    if (begin(s, &lock, &data, &state, &now)) goto done;
    if (state.epoch == UINT64_MAX || now > UINT64_MAX - ttl_ms ||
        (state.outstanding && now < state.expires_ms)) goto done;
    unsigned char nonce[32];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1 || nonce_unused(data, nonce)) goto done;
    uint64_t epoch = state.epoch + 1, expiry = now + ttl_ms;
    if (append_record(s, data, &state, TYPE_ISSUE, epoch, now, expiry, nonce)) goto done;
    out->epoch = epoch; out->issued_ms = now; out->expires_ms = expiry;
    memcpy(out->nonce, nonce, sizeof(nonce));
    ok = 0;
done:
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    return ok;
}

/* A canonical B is an exact-byte commitment, not issuer authentication. */
static int manifest_binding(const unsigned char *wire, size_t length,
                            const qihse_ct1_authority_challenge_t *challenge,
                            unsigned char digest[SHA256_DIGEST_LENGTH])
{
    qihse_ct1_recovery_manifest_t m;
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    if (!wire || !challenge || length != sizeof(canonical) ||
        !qihse_ct1_recovery_decode(wire, length, false, &m, NULL) ||
        !qihse_ct1_recovery_encode(&m, false, false, canonical) ||
        memcmp(canonical, wire, length) ||
        m.epoch != challenge->epoch || m.issued_ms != challenge->issued_ms ||
        m.expires_ms != challenge->expires_ms ||
        memcmp(m.nonce, challenge->nonce, sizeof(m.nonce)) ||
        !SHA256(wire, length, digest)) return -1;
    return 0;
}

static int current_challenge(const ledger_t *state,
                             const qihse_ct1_authority_challenge_t *challenge,
                             uint64_t now)
{
    return state->outstanding && now >= state->issued_ms &&
        now < state->expires_ms && challenge->epoch == state->epoch &&
        challenge->issued_ms == state->issued_ms &&
        challenge->expires_ms == state->expires_ms &&
        !memcmp(challenge->nonce, state->nonce, sizeof(state->nonce));
}

int qihse_ct1_authority_store_bind(qihse_ct1_authority_store_t *s,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!s || !s->strict || !s->checkpoint ||
        manifest_binding(canonical_b, length, challenge, digest)) return -1;
    int lock = -1, data = -1, ok = -1;
    ledger_t state;
    uint64_t now;
    if (begin(s, &lock, &data, &state, &now)) goto done;
    if (!current_challenge(&state, challenge, now) || state.bound) goto done;
    if (!append_record(s, data, &state, TYPE_BIND, state.epoch, now,
                       state.expires_ms, digest)) ok = 0;
done:
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    return ok;
}

int qihse_ct1_authority_store_check_bound(qihse_ct1_authority_store_t *s,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int lock = -1, data = -1, ok = -1;
    ledger_t state;
    uint64_t now;
    if (!s || geteuid() != 0 || !s->strict || !s->checkpoint ||
        manifest_binding(canonical_b, length, challenge, digest)) return -1;
    lock = lock_store(s);
    if (lock < 0) goto done;
    data = open_data(s);
    if (data < 0 || read_ledger(data, &state) ||
        checkpoint_state(s, &state, 0, 0) || now_ms(&now) ||
        now < state.clock_ms || !current_challenge(&state, challenge, now) ||
        !state.bound || memcmp(state.manifest_digest, digest, sizeof(digest)))
        goto done;
    ok = 0;
done:
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    return ok;
}

int qihse_ct1_authority_store_retire_bound(qihse_ct1_authority_store_t *s,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!s || !s->strict || !s->checkpoint ||
        manifest_binding(canonical_b, length, challenge, digest)) return -1;
    int lock = -1, data = -1, ok = -1;
    ledger_t state;
    uint64_t now;
    if (begin(s, &lock, &data, &state, &now)) goto done;
    if (!current_challenge(&state, challenge, now) || !state.bound ||
        memcmp(state.manifest_digest, digest, sizeof(digest))) goto done;
    if (!append_record(s, data, &state, TYPE_RETIRE, state.epoch, now,
                       state.expires_ms, state.nonce)) ok = 0;
done:
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    return ok;
}

/* Private service/store bridge: callback is the fixed pair evaluator, not an
 * approval hook. It must not call any store operation while this flock is held. */
int qihse_ct1_authority_store_evaluate_and_retire_bound(
    qihse_ct1_authority_store_t *s,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length,
    int (*evaluate)(void *), void *context)
{
    unsigned char digest[SHA256_DIGEST_LENGTH], after[SHA256_DIGEST_LENGTH];
    int lock = -1, data = -1, ok = -1;
    ledger_t state, verified;
    uint64_t now;
    if (!s || geteuid() != 0 || !s->strict || !s->checkpoint || !evaluate ||
        manifest_binding(canonical_b, length, challenge, digest)) return -1;
    lock = lock_store(s);
    if (lock < 0) goto done;
    data = open_data(s);
    if (data < 0 || read_ledger(data, &state) ||
        checkpoint_state(s, &state, 0, 0) || now_ms(&now) ||
        now < state.clock_ms || !current_challenge(&state, challenge, now) ||
        !state.bound || memcmp(state.manifest_digest, digest, sizeof(digest)))
        goto done;
    if (!evaluate(context)) goto done;
    /* The evaluator has no store access. Fail closed if the external B bytes,
     * checkpoint, ledger or wall clock changed before retirement. */
    if (manifest_binding(canonical_b, length, challenge, after) ||
        memcmp(after, digest, sizeof(digest)) ||
        read_ledger(data, &verified) ||
        memcmp(&verified, &state, sizeof(state)) ||
        checkpoint_state(s, &verified, 0, 0) || now_ms(&now) ||
        now < verified.clock_ms || !current_challenge(&verified, challenge, now))
        goto done;
    if (!append_record(s, data, &verified, TYPE_RETIRE, verified.epoch, now,
                       verified.expires_ms, verified.nonce)) ok = 0;
done:
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    return ok;
}

int qihse_ct1_authority_store_retire(qihse_ct1_authority_store_t *s,
                                     const qihse_ct1_authority_challenge_t *challenge)
{
    if (!s || !challenge) return -1;
    int lock = -1, data = -1, ok = -1;
    ledger_t state;
    uint64_t now;
    if (begin(s, &lock, &data, &state, &now)) goto done;
    if (!state.outstanding || state.bound || now >= state.expires_ms ||
        challenge->epoch != state.epoch || challenge->expires_ms != state.expires_ms ||
        challenge->issued_ms != state.issued_ms ||
        memcmp(challenge->nonce, state.nonce, sizeof(state.nonce))) goto done;
    if (!append_record(s, data, &state, TYPE_RETIRE, state.epoch, now,
                       state.expires_ms, state.nonce)) ok = 0;
done:
    if (data >= 0) close(data);
    if (lock >= 0) close(lock);
    return ok;
}
