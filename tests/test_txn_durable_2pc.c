#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_txn.h"
#include "qihse_auth.h"
#include "qihse_audit.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct mock_s {
    char dir[512];
    uint8_t engine;
    int crash_commit;
    int crash_abort;
    int fail_commit_once;
    int fail_abort_once;
    int fail_prepare_once;
    int fail_prepare_journal_once;
} mock_t;

/* Executable-only interposition: never fault participant receipts or auth I/O. */
static struct {
    dev_t dev;
    ino_t ino;
    int armed;
    int partial_write;
    int fail_write;
    int fail_sync;
    int fail_truncate;
    int writes;
    int syncs;
    int truncates;
} journal_fault;

static bool fault_fd(int fd) {
    struct stat st;
    return journal_fault.armed && fstat(fd, &st) == 0 &&
        st.st_dev == journal_fault.dev && st.st_ino == journal_fault.ino;
}

static void arm_journal_fault(const char* path) {
    struct stat st;
    assert(stat(path, &st) == 0 && S_ISREG(st.st_mode));
    memset(&journal_fault, 0, sizeof journal_fault);
    journal_fault.dev = st.st_dev;
    journal_fault.ino = st.st_ino;
    journal_fault.armed = 1;
}

ssize_t write(int fd, const void* data, size_t len) {
    static ssize_t (*real_write)(int, const void*, size_t);
    if (!real_write) {
        *(void**)(&real_write) = dlsym(RTLD_NEXT, "write");
        assert(real_write);
    }
    if (fault_fd(fd)) {
        ++journal_fault.writes;
        if (journal_fault.partial_write) {
            journal_fault.partial_write = 0;
            return real_write(fd, data, len > 1 ? len / 2 : len);
        }
        if (journal_fault.fail_write) {
            --journal_fault.fail_write;
            errno = ENOSPC;
            return -1;
        }
    }
    return real_write(fd, data, len);
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int);
    if (!real_fdatasync) {
        *(void**)(&real_fdatasync) = dlsym(RTLD_NEXT, "fdatasync");
        assert(real_fdatasync);
    }
    if (fault_fd(fd)) {
        ++journal_fault.syncs;
        if (journal_fault.fail_sync) {
            --journal_fault.fail_sync;
            errno = EIO;
            return -1;
        }
    }
    return real_fdatasync(fd);
}

int ftruncate(int fd, off_t len) {
    static int (*real_ftruncate)(int, off_t);
    if (!real_ftruncate) {
        *(void**)(&real_ftruncate) = dlsym(RTLD_NEXT, "ftruncate");
        assert(real_ftruncate);
    }
    if (fault_fd(fd)) {
        ++journal_fault.truncates;
        if (journal_fault.fail_truncate) {
            --journal_fault.fail_truncate;
            errno = EIO;
            return -1;
        }
    }
    return real_ftruncate(fd, len);
}

static int fail_parent_dir_fsync;
static int parent_dir_fsync_observed;
static dev_t parent_dir_dev;
static ino_t parent_dir_ino;

int fsync(int fd) {
    static int (*real_fsync)(int);
    if (!real_fsync) {
        *(void**)(&real_fsync) = dlsym(RTLD_NEXT, "fsync");
        assert(real_fsync != NULL);
    }
    struct stat st;
    if (fail_parent_dir_fsync && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_dev == parent_dir_dev && st.st_ino == parent_dir_ino) {
        ++parent_dir_fsync_observed;
        errno = EIO;
        return -1;
    }
    return real_fsync(fd);
}

static int record_path(mock_t* m, uint64_t id, char* path, size_t cap) {
    int n = snprintf(path, cap, "%s/p%u-t%llu", m->dir, (unsigned)m->engine,
                     (unsigned long long)id);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

static int mock_update(mock_t* m, uint64_t id, char state) {
    char path[640], record[2] = { 0, 0 };
    if (record_path(m, id, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, record, sizeof(record), 0);
    if (n == 2 && record[0] == state) { close(fd); return 0; }
    if (n == 2 && record[0] != 'P') { close(fd); return -1; }
    record[1] = (state == 'C' || state == 'A') ? (char)(record[1] + 1) : record[1];
    record[0] = state;
    if (pwrite(fd, record, sizeof(record), 0) != (ssize_t)sizeof(record) || fdatasync(fd) != 0) {
        close(fd); return -1;
    }
    close(fd);
    return 0;
}

static int prepare(void* ctx, uint64_t id) {
    mock_t* m = ctx;
    int rc = mock_update(m, id, 'P');
    if (m->fail_prepare_once) {
        m->fail_prepare_once = 0;
        if (m->fail_prepare_journal_once) {
            m->fail_prepare_journal_once = 0;
            journal_fault.fail_sync = 1; /* fail the following ABORT append */
        }
        return -1;
    }
    return rc;
}
typedef struct { uint32_t marker; } resource_payload_t;
static int prepare_resource(void* ctx, uint64_t id, void* opaque) {
    resource_payload_t* payload = (resource_payload_t*)opaque;
    bool valid = payload && payload->marker == UINT32_C(0x51525354);
    free(payload); /* resource-aware prepare consumes on both outcomes */
    return valid ? prepare(ctx, id) : -1;
}
static void rollback_resource(void* opaque) { free(opaque); }
static int one_phase_resource_commit_calls;
static int one_phase_resource_commit(void* opaque) {
    ++one_phase_resource_commit_calls;
    free(opaque);
    return 0;
}
static int commit(void* ctx, uint64_t id) {
    mock_t* m = ctx;
    if (m->crash_commit) _exit(77); /* coordinator has already synced COMMIT */
    if (m->fail_commit_once) { m->fail_commit_once = 0; return -1; }
    return mock_update(m, id, 'C');
}
static int abort_txn(void* ctx, uint64_t id) {
    mock_t* m = ctx;
    if (m->crash_abort) _exit(79); /* coordinator has already synced ABORT */
    if (m->fail_abort_once) { m->fail_abort_once = 0; return -1; }
    return mock_update(m, id, 'A');
}

static void register_pair(qihse_txn_manager_t* mgr, mock_t m[2]) {
    for (int i = 0; i < 2; ++i) {
        qihse_txn_participant_t p = { .engine_id = m[i].engine,
            .engine_ctx = &m[i], .prepare = prepare, .commit = commit, .abort = abort_txn };
        assert(qihse_txn_register_participant(mgr, p) == 0);
    }
}

static void assert_record(mock_t* m, uint64_t id, char state) {
    char path[640], value[2] = { 0, 0 };
    assert(record_path(m, id, path, sizeof(path)) == 0);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    assert(read(fd, value, sizeof(value)) == (ssize_t)sizeof(value));
    close(fd);
    assert(value[0] == state && (unsigned char)value[1] == 1);
}

static bool checkpoint_equal(qihse_txn_backup_checkpoint_t a,
                             qihse_txn_backup_checkpoint_t b) {
    return a.epoch == b.epoch && a.next_txn_id == b.next_txn_id &&
        a.journal_bytes == b.journal_bytes;
}

static const qihse_txn_backup_checkpoint_t untouched = { 123, 456, 789 };

typedef struct {
    int fd;
    unsigned calls;
    size_t bytes;
    int mutation;
    qihse_txn_manager_t* mgr;
    qihse_user_t* user;
} capture_t;

static bool capture_write(void* ctx, const void* data, size_t len) {
    capture_t* c = ctx;
    ++c->calls;
    c->bytes += len;
    if (c->fd >= 0) {
        size_t done = 0;
        while (done < len) {
            ssize_t n = write(c->fd, (const char*)data + done, len - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            done += (size_t)n;
        }
    }
    int mutation = c->mutation;
    c->mutation = 0;
    if (mutation == 1) {
        qihse_txn_t* t = qihse_txn_begin(c->mgr, QIHSE_ISO_READ_COMMITTED);
        assert(t && qihse_txn_rollback(c->mgr, t) == 0);
    } else if (mutation == 2) {
        qihse_txn_set_next_id(c->mgr, 900);
    } else if (mutation == 3) {
        assert(qihse_txn_manager_recover(c->mgr) == 0);
    } else if (mutation == 4) {
        assert(qihse_auth_modify_user(c->user, 0, "backup-operator", NULL,
                                     -1, -1, -1, -1));
    } else if (mutation == 5) {
        return false; /* caller must discard even a complete callback payload */
    }
    return true;
}

static void assert_capture_denied(qihse_txn_manager_t* mgr,
                                  const qihse_user_t* user,
                                  const qihse_txn_backup_checkpoint_t* expected) {
    qihse_txn_backup_checkpoint_t out = untouched;
    capture_t c = { .fd = -1 };
    assert(!qihse_txn_backup_checkpoint_user(mgr, user, &out));
    assert(checkpoint_equal(out, untouched));
    assert(!qihse_txn_backup_export_user(mgr, user, expected, capture_write, &c, &out));
    assert(checkpoint_equal(out, untouched) && c.calls == 0 && c.bytes == 0);
}

static unsigned char* file_bytes(const char* path, size_t* len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && st.st_size >= 0);
    *len = (size_t)st.st_size;
    unsigned char* data = malloc(*len + 1);
    assert(data);
    size_t done = 0;
    while (done < *len) {
        ssize_t n = read(fd, data + done, *len - done);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        done += (size_t)n;
    }
    assert(close(fd) == 0);
    return data;
}

static void assert_file_bytes(const char* path, const void* expected, size_t len) {
    size_t actual_len;
    unsigned char* actual = file_bytes(path, &actual_len);
    assert(actual_len == len && memcmp(actual, expected, len) == 0);
    free(actual);
}

static void test_rollover(const char* root, qihse_user_t* user) {
    for (int mode = 0; mode < 3; ++mode) {
        qihse_txn_manager_t* mgr = qihse_txn_manager_create();
        assert(mgr);
        if (mode == 0) {
            qihse_txn_set_next_id(mgr, UINT64_MAX - 1);
            qihse_txn_t* t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
            assert(t && t->id == UINT64_MAX - 1 && t->id != 0);
            assert(qihse_txn_rollback(mgr, t) == 0);
            qihse_txn_set_next_id(mgr, UINT64_MAX);
        } else if (mode == 1) {
            qihse_txn_register_committed(mgr, UINT64_MAX);
        } else {
            qihse_txn_register_aborted(mgr, UINT64_MAX);
        }
        assert(qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED) == NULL);
        assert(qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED) == NULL);
        qihse_txn_manager_destroy(mgr);
    }
    char path[640];
    assert(snprintf(path, sizeof path, "%s/exhausted.journal", root) > 0);
    qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(path);
    assert(mgr && qihse_txn_advance_next_id(mgr, UINT64_MAX) == 0);
    assert(qihse_txn_manager_recover(mgr) == 0);
    assert_capture_denied(mgr, user, &untouched);
    assert(qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED) == NULL);
    qihse_txn_manager_destroy(mgr);
}

static void test_backup(const char* root, qihse_user_t* user,
                        qihse_user_t* low, qihse_user_t* delegated,
                        qihse_user_t* foreign, qihse_user_t* revoked) {
    char journal[640], exported[640];
    assert(snprintf(journal, sizeof journal, "%s/backup-source.journal", root) > 0);
    assert(snprintf(exported, sizeof exported, "%s/backup-export.journal", root) > 0);
    mock_t mocks[2] = { { .engine = 21 }, { .engine = 22 } };
    for (int i = 0; i < 2; ++i)
        assert(snprintf(mocks[i].dir, sizeof mocks[i].dir, "%s", root) > 0);
    qihse_txn_manager_t* volatile_mgr = qihse_txn_manager_create();
    assert(volatile_mgr);
    assert_capture_denied(volatile_mgr, user, &untouched);
    qihse_txn_manager_destroy(volatile_mgr);
    qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(journal);
    assert(mgr);
    register_pair(mgr, mocks);
    assert_capture_denied(mgr, user, &untouched);
    assert(qihse_txn_manager_recover(mgr) == 0);
    qihse_txn_backup_checkpoint_t start, out = untouched;
    assert(qihse_txn_backup_checkpoint_user(mgr, user, &start));
    assert(start.epoch > 0 && start.next_txn_id == 1 && start.journal_bytes == 0);
    qihse_txn_t* t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t && t->id == 1);
    assert_capture_denied(mgr, user, &start); /* ACTIVE */
    assert(qihse_txn_prepare(mgr, t) == 0);
    assert_capture_denied(mgr, user, &start); /* PREPARED */
    mocks[0].fail_commit_once = 1;
    assert(qihse_txn_commit_prepared(mgr, t) == -1 && t->state == QIHSE_TXN_COMMITTING);
    assert_capture_denied(mgr, user, &start);
    assert(qihse_txn_commit_prepared(mgr, t) == 0);
    t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t && t->id == 2 && qihse_txn_prepare(mgr, t) == 0);
    mocks[0].fail_abort_once = 1;
    assert(qihse_txn_abort_prepared(mgr, t) == -1 && t->state == QIHSE_TXN_ABORTING);
    assert_capture_denied(mgr, user, &start);
    assert(qihse_txn_abort_prepared(mgr, t) == 0);
    t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t && t->id == 3 && qihse_txn_rollback(mgr, t) == 0);
    qihse_txn_backup_checkpoint_t checkpoint;
    assert(qihse_txn_backup_checkpoint_user(mgr, user, &checkpoint));
    assert(checkpoint.epoch > start.epoch && checkpoint.next_txn_id == 4);
    assert(checkpoint.journal_bytes > 0);
    assert_capture_denied(mgr, NULL, &checkpoint);
    assert_capture_denied(mgr, low, &checkpoint);
    assert_capture_denied(mgr, delegated, &checkpoint);
    assert_capture_denied(mgr, foreign, &checkpoint);
    assert_capture_denied(mgr, revoked, &checkpoint);
    capture_t c = { .fd = -1 };
    assert(!qihse_txn_backup_export_user(mgr, user, NULL, capture_write, &c, &out));
    assert(c.calls == 0 && checkpoint_equal(out, untouched));
    assert(!qihse_txn_backup_export_user(mgr, user, &checkpoint, NULL, &c, &out));
    assert(checkpoint_equal(out, untouched));
    assert(!qihse_txn_backup_export_user(mgr, user, &start, capture_write, &c, &out));
    assert(c.calls == 0 && checkpoint_equal(out, untouched));

    c.fd = open(exported, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(c.fd >= 0);
    assert(qihse_txn_backup_export_user(mgr, user, &checkpoint, capture_write, &c, &out));
    assert(c.calls > 0 && c.bytes == checkpoint.journal_bytes && checkpoint_equal(out, checkpoint));
    assert(fdatasync(c.fd) == 0 && close(c.fd) == 0);
    size_t len;
    unsigned char* bytes = file_bytes(journal, &len);
    assert(len == checkpoint.journal_bytes && len >= 36 && !memcmp(bytes, "QT2P", 4));
    assert_file_bytes(exported, bytes, len);
    for (int i = 0; i < 2; ++i) {
        assert_record(&mocks[i], 1, 'C');
        assert_record(&mocks[i], 2, 'A');
    }
    qihse_txn_manager_t* restored = qihse_txn_manager_create_durable(exported);
    assert(restored);
    register_pair(restored, mocks);
    assert(qihse_txn_advance_next_id(restored, checkpoint.next_txn_id) == 0);
    assert(qihse_txn_manager_recover(restored) == 0);
    assert(qihse_txn_is_committed(restored, 1) && qihse_txn_is_aborted(restored, 2));
    assert(qihse_txn_manager_recover(restored) == 0);
    for (int i = 0; i < 2; ++i) {
        assert_record(&mocks[i], 1, 'C');
        assert_record(&mocks[i], 2, 'A');
    }
    t = qihse_txn_begin(restored, QIHSE_ISO_READ_COMMITTED);
    assert(t && t->id == checkpoint.next_txn_id && qihse_txn_rollback(restored, t) == 0);
    qihse_txn_manager_destroy(restored);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        alarm(10);
        assert_capture_denied(mgr, user, &checkpoint);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    for (int mutation = 1; mutation <= 5; ++mutation) {
        assert(qihse_txn_backup_checkpoint_user(mgr, user, &checkpoint));
        out = untouched;
        c = (capture_t){ .fd = -1, .mutation = mutation, .mgr = mgr, .user = user };
        alarm(10); /* a locked callback is a bounded failure, not a hung suite */
        assert(!qihse_txn_backup_export_user(mgr, user, &checkpoint, capture_write, &c, &out));
        alarm(0);
        assert(c.calls > 0 && c.bytes > 0 && checkpoint_equal(out, untouched));
        qihse_txn_backup_checkpoint_t after;
        assert(qihse_txn_backup_checkpoint_user(mgr, user, &after));
        if (mutation <= 3) assert(after.epoch != checkpoint.epoch);
        if (mutation == 1) assert(after.next_txn_id == checkpoint.next_txn_id + 1);
    }

    /* Capture validates without recovery's torn-tail repair, even with a stale
     * expected length. Both CRC and CRC-valid structural errors fail closed. */
    int fd = open(journal, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    for (int malformed = 0; malformed < 3; ++malformed) {
        assert(qihse_txn_backup_checkpoint_user(mgr, user, &checkpoint));
        unsigned char* damaged = malloc(len + 1);
        assert(damaged);
        memcpy(damaged, bytes, len);
        size_t damaged_len = len;
        if (malformed == 0) {
            damaged[damaged_len++] = 'Q';
        } else if (malformed == 1) {
            damaged[32] ^= 1;
        } else {
            damaged[5] = 255;
            uint32_t crc = UINT32_MAX;
            for (size_t i = 0; i < 32; ++i) {
                crc ^= damaged[i];
                for (int bit = 0; bit < 8; ++bit)
                    crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1));
            }
            crc = ~crc;
            for (int i = 0; i < 4; ++i) damaged[32 + i] = (unsigned char)(crc >> (24 - 8 * i));
        }
        assert(pwrite(fd, damaged, damaged_len, 0) == (ssize_t)damaged_len);
        assert(fdatasync(fd) == 0);
        assert_capture_denied(mgr, user, &checkpoint);
        assert_file_bytes(journal, damaged, damaged_len);
        assert(pwrite(fd, bytes, len, 0) == (ssize_t)len && ftruncate(fd, (off_t)len) == 0);
        assert(fdatasync(fd) == 0);
        free(damaged);
    }
    assert(close(fd) == 0);
    free(bytes);
    qihse_txn_manager_destroy(mgr);
}

static void test_journal_failures(const char* root, qihse_user_t* user) {
    for (int mode = 0; mode < 5; ++mode) {
        char journal[640], dir[512];
        assert(snprintf(dir, sizeof dir, "%s/io-%d", root, mode) > 0);
        assert(mkdir(dir, 0700) == 0);
        assert(snprintf(journal, sizeof journal, "%s/coordinator", dir) > 0);
        mock_t mocks[2] = { { .engine = 31 }, { .engine = 32 } };
        for (int i = 0; i < 2; ++i)
            assert(snprintf(mocks[i].dir, sizeof mocks[i].dir, "%s", dir) > 0);
        qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(journal);
        assert(mgr);
        register_pair(mgr, mocks);
        assert(qihse_txn_manager_recover(mgr) == 0);
        qihse_txn_t* t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
        assert(t && t->id == 1);
        if (mode == 0) {
            arm_journal_fault(journal);
            journal_fault.partial_write = 1;
            journal_fault.fail_write = 1;
            assert(qihse_txn_prepare(mgr, t) == -1);
            assert(journal_fault.writes == 2 && journal_fault.truncates == 1 && journal_fault.syncs == 1);
            journal_fault.armed = 0;
            struct stat st;
            assert(stat(journal, &st) == 0 && st.st_size == 0);
        }
        assert(qihse_txn_prepare(mgr, t) == 0);
        if (mode > 0) {
            arm_journal_fault(journal);
            journal_fault.fail_sync = mode == 3 ? 2 : 1;
            journal_fault.fail_truncate = mode == 2;
            if (mode == 4) {
                journal_fault.partial_write = 1;
                journal_fault.fail_write = 1;
                journal_fault.fail_truncate = 1;
            }
            assert(qihse_txn_commit_prepared(mgr, t) == -1);
            assert(journal_fault.writes > 0 && journal_fault.truncates == 1);
            if (mode == 1 || mode == 3) assert(journal_fault.syncs == 2);
            journal_fault.armed = 0;
        }
        if (mode <= 1) {
            assert(qihse_txn_commit_prepared(mgr, t) == 0);
            assert(qihse_txn_is_committed(mgr, 1));
            qihse_txn_backup_checkpoint_t checkpoint;
            assert(qihse_txn_backup_checkpoint_user(mgr, user, &checkpoint));
        } else {
            /* A complete COMMIT may survive failed rollback; no unsafe ABORT or
             * participant delivery is permitted until close/reopen recovery. */
            assert(qihse_txn_commit_prepared(mgr, t) == -1);
            assert(qihse_txn_abort_prepared(mgr, t) == -1);
            assert(qihse_txn_rollback(mgr, t) == -1);
            assert(qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED) == NULL);
            assert(qihse_txn_manager_recover(mgr) == -1);
            assert_capture_denied(mgr, user, &untouched);
            for (int i = 0; i < 2; ++i) {
                char path[640], record[2];
                assert(record_path(&mocks[i], 1, path, sizeof path) == 0);
                int fd = open(path, O_RDONLY | O_CLOEXEC);
                assert(fd >= 0 && read(fd, record, sizeof record) == sizeof record);
                assert(record[0] == 'P' && record[1] == 0);
                assert(close(fd) == 0);
            }
        }
        qihse_txn_manager_destroy(mgr);
        mgr = qihse_txn_manager_create_durable(journal);
        assert(mgr);
        register_pair(mgr, mocks);
        assert(qihse_txn_manager_recover(mgr) == 0);
        char decision = mode <= 2 ? 'C' : 'A';
        assert(decision == 'C' ? qihse_txn_is_committed(mgr, 1) : qihse_txn_is_aborted(mgr, 1));
        assert(qihse_txn_manager_recover(mgr) == 0);
        for (int i = 0; i < 2; ++i) assert_record(&mocks[i], 1, decision);
        qihse_txn_manager_destroy(mgr);
    }
}

static void test_prepare_attempts(const char* root) {
    for (int mode = 0; mode < 2; ++mode) {
        char journal[640], missing[640];
        assert(snprintf(journal, sizeof journal, "%s/attempts-%d.journal", root, mode) > 0);
        mock_t mocks[2] = { { .engine = (uint8_t)(41 + mode * 2), .fail_prepare_once = 1,
                             .fail_abort_once = !mode, .fail_prepare_journal_once = mode },
                           { .engine = (uint8_t)(42 + mode * 2) } };
        for (int i = 0; i < 2; ++i)
            assert(snprintf(mocks[i].dir, sizeof mocks[i].dir, "%s", root) > 0);
        qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(journal);
        assert(mgr);
        register_pair(mgr, mocks);
        assert(qihse_txn_manager_recover(mgr) == 0);
        qihse_txn_t* t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
        assert(t);
        if (mode) arm_journal_fault(journal);
        assert(qihse_txn_prepare(mgr, t) == -1);
        assert(t->state == (mode ? QIHSE_TXN_PREPARED : QIHSE_TXN_ABORTING));
        if (mode) assert(journal_fault.truncates == 1 && journal_fault.syncs == 3);
        journal_fault.armed = 0;
        assert(qihse_txn_commit_prepared(mgr, t) == -1);
        assert(qihse_txn_abort_prepared(mgr, t) == 0);
        assert_record(&mocks[0], t->id, 'A');
        assert(record_path(&mocks[1], t->id, missing, sizeof missing) == 0);
        assert(access(missing, F_OK) == -1 && errno == ENOENT);
        qihse_txn_manager_destroy(mgr);
    }
}

static void test_backup_auth(const char* root) {
    const char* data_dir = getenv("QIHSE_DATA_DIR");
    const char* rotate = getenv("QIHSE_AUDIT_ROTATE_BYTES");
    char* saved_data_dir = data_dir ? strdup(data_dir) : NULL;
    char* saved_rotate = rotate ? strdup(rotate) : NULL;
    assert(!data_dir || saved_data_dir);
    assert(!rotate || saved_rotate);
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_AUDIT_ROTATE_BYTES", "67108864", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("TxnBackupOperator1!"));
    qihse_user_t* user = qihse_auth_get_user(0);
    assert(user);
    qihse_user_t* low = qihse_auth_create_user(user, 39201, QIHSE_ROLE_GUEST,
        0, 0, "TxnBackupGuest1!", false);
    qihse_user_t* delegated = qihse_auth_create_user(user, 39202, QIHSE_ROLE_OPERATOR,
        0, 0, "TxnBackupDelegate1!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(user, 73, 39203,
        QIHSE_ROLE_OPERATOR, 0, 0, "TxnBackupForeign1!", false);
    assert(low && delegated && foreign);
    assert(qihse_auth_create_user(user, 39204, QIHSE_ROLE_GUEST,
        0, 0, "TxnBackupRevoked1!", false));
    uint64_t generation;
    qihse_user_t* revoked = qihse_auth_borrow_principal_scoped(39204, &generation);
    assert(revoked && qihse_auth_destroy_user(user, 39204));
    assert(!qihse_auth_user_is_active(revoked));
    test_backup(root, user, low, delegated, foreign, revoked);
    qihse_auth_release_principal_scoped(revoked);
    test_rollover(root, user);
    test_journal_failures(root, user);
    test_prepare_attempts(root);

    /* Keep a borrowed System Operator allocation alive while revoking it, so
     * this tests liveness rather than merely denying a revoked guest's role. */
    char revoked_journal[640];
    assert(snprintf(revoked_journal, sizeof revoked_journal, "%s/revoked.journal", root) > 0);
    qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(revoked_journal);
    assert(mgr && qihse_txn_manager_recover(mgr) == 0);
    qihse_txn_backup_checkpoint_t checkpoint;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(0, &generation);
    assert(borrowed && qihse_txn_backup_checkpoint_user(mgr, borrowed, &checkpoint));
    const char* allow_destroy = getenv("QIHSE_ALLOW_DESTROY_OPERATOR");
    char* saved_allow_destroy = allow_destroy ? strdup(allow_destroy) : NULL;
    assert(!allow_destroy || saved_allow_destroy);
    assert(setenv("QIHSE_ALLOW_DESTROY_OPERATOR", "1", 1) == 0);
    assert(qihse_auth_destroy_user(borrowed, 0));
    assert_capture_denied(mgr, borrowed, &checkpoint);
    qihse_auth_release_principal_scoped(borrowed);
    qihse_txn_manager_destroy(mgr);
    if (saved_allow_destroy) assert(setenv("QIHSE_ALLOW_DESTROY_OPERATOR", saved_allow_destroy, 1) == 0);
    else assert(unsetenv("QIHSE_ALLOW_DESTROY_OPERATOR") == 0);
    free(saved_allow_destroy);
    if (saved_data_dir) assert(setenv("QIHSE_DATA_DIR", saved_data_dir, 1) == 0);
    else assert(unsetenv("QIHSE_DATA_DIR") == 0);
    if (saved_rotate) assert(setenv("QIHSE_AUDIT_ROTATE_BYTES", saved_rotate, 1) == 0);
    else assert(unsetenv("QIHSE_AUDIT_ROTATE_BYTES") == 0);
    free(saved_data_dir);
    free(saved_rotate);
}

typedef struct {
    pid_t owner;
    int commits, rollbacks, prepares;
} ownership_resource_t;

typedef struct {
    mock_t mock;
    pid_t owner;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool blocked, entered, released;
    qihse_txn_manager_t* mgr;
    qihse_txn_t* txn;
    int commit_result;
} ownership_gate_t;

static int ownership_resource_commit(void* ctx) {
    ownership_resource_t* r = ctx;
    if (getpid() != r->owner) _exit(90);
    ++r->commits;
    return 0;
}

static void ownership_resource_rollback(void* ctx) {
    ownership_resource_t* r = ctx;
    if (getpid() != r->owner) _exit(91);
    ++r->rollbacks;
}

static int ownership_prepare(void* ctx, uint64_t id) {
    ownership_gate_t* g = ctx;
    if (getpid() != g->owner) _exit(92);
    return prepare(&g->mock, id);
}

static int ownership_prepare_resource(void* ctx, uint64_t id, void* resource) {
    ownership_resource_t* r = resource;
    if (getpid() != r->owner) _exit(93);
    ++r->prepares;
    return ownership_prepare(ctx, id);
}

static int ownership_abort(void* ctx, uint64_t id) {
    ownership_gate_t* g = ctx;
    if (getpid() != g->owner) _exit(94);
    return abort_txn(&g->mock, id);
}

static int ownership_commit(void* ctx, uint64_t id) {
    ownership_gate_t* g = ctx;
    if (getpid() != g->owner) _exit(95);
    /* The coordinator lock is already held. Use only this separate gate. */
    assert(pthread_mutex_lock(&g->lock) == 0);
    if (g->blocked) {
        g->entered = true;
        assert(pthread_cond_broadcast(&g->cond) == 0);
        while (!g->released) assert(pthread_cond_wait(&g->cond, &g->lock) == 0);
    }
    assert(pthread_mutex_unlock(&g->lock) == 0);
    return commit(&g->mock, id);
}

static void* ownership_commit_thread(void* ctx) {
    ownership_gate_t* g = ctx;
    g->commit_result = qihse_txn_commit_prepared(g->mgr, g->txn);
    return NULL;
}

static const char* const ownership_apis[] = {
    "is_committed", "is_aborted", "active_list", "active_count",
    "committed_history_count", "release", "savepoint", "rollback_to_savepoint",
    "refresh_snapshot", "validate_occ", "attach_participant_resource",
    "enlist_attached_resource", "manager_destroy"
};

/* Child success paths use only pre-lock PID rejection and memory comparisons:
 * no assertion reporting, allocator, callbacks, or inherited synchronization. */
static int ownership_rejected(size_t api, qihse_txn_manager_t* mgr,
    qihse_txn_t* actor, qihse_txn_t* attached, qihse_txn_t* terminal,
    uint64_t aborted_id, ownership_resource_t resources[3],
    const qihse_txn_t snapshots[3], const qihse_rw_entry_t* writes) {
    uint64_t sentinel = UINT64_C(0x123456789abcdef0);
    uint64_t* ids = &sentinel;
    int count = -17;
    bool rejected = false;
    switch (api) {
    case 0: rejected = !qihse_txn_is_committed(mgr, terminal->id); break;
    case 1: rejected = !qihse_txn_is_aborted(mgr, aborted_id); break;
    case 2:
        rejected = qihse_txn_active_list(mgr, &ids, &count) == -1 &&
            ids == &sentinel && count == -17 && sentinel == UINT64_C(0x123456789abcdef0);
        break;
    case 3: rejected = qihse_txn_active_count(mgr) == 0; break;
    case 4: rejected = qihse_txn_committed_history_count(mgr) == 0; break;
    case 5: rejected = qihse_txn_release(mgr, terminal) == -1; break;
    case 6: rejected = qihse_txn_savepoint(mgr, actor, "child") == -1; break;
    case 7: rejected = qihse_txn_rollback_to_savepoint(mgr, actor, "before") == -1; break;
    case 8: qihse_txn_refresh_snapshot(mgr, actor); rejected = true; break;
    case 9: rejected = qihse_txn_validate_occ(mgr, actor) == -1; break;
    case 10:
        rejected = qihse_txn_attach_participant_resource(mgr, actor, 41,
            &resources[0], ownership_resource_rollback) == -1;
        break;
    case 11: rejected = qihse_txn_enlist_attached_resource(mgr, attached, 41) == -1; break;
    case 12: qihse_txn_manager_destroy(mgr); rejected = true; break;
    }
    if (!rejected) return 1; /* Do not inspect a handle an incorrect call freed. */
    if (memcmp(actor, &snapshots[0], sizeof(*actor)) ||
        memcmp(attached, &snapshots[1], sizeof(*attached)) ||
        memcmp(terminal, &snapshots[2], sizeof(*terminal)) ||
        memcmp(actor->rw_set, writes, (size_t)actor->rw_count * sizeof(*writes))) return 2;
    for (int i = 0; i < 3; ++i)
        if (resources[i].commits || resources[i].rollbacks || resources[i].prepares) return 3;
    return 0;
}

static void test_manager_process_ownership(const char* root) {
    char dir[512], journal[640], terminal_record[640], blocked_record[640];
    assert(snprintf(dir, sizeof dir, "%s/ownership", root) > 0);
    assert(mkdir(dir, 0700) == 0);
    assert(snprintf(journal, sizeof journal, "%s/coordinator.journal", dir) > 0);
    ownership_gate_t gate = { .owner = getpid(), .commit_result = -1 };
    gate.mock.engine = 41;
    assert(snprintf(gate.mock.dir, sizeof gate.mock.dir, "%s", dir) > 0);
    assert(pthread_mutex_init(&gate.lock, NULL) == 0);
    assert(pthread_cond_init(&gate.cond, NULL) == 0);
    qihse_txn_participant_t participant = { .engine_id = 41, .engine_ctx = &gate,
        .prepare = ownership_prepare, .commit = ownership_commit, .abort = ownership_abort };
    qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(journal);
    assert(mgr && qihse_txn_register_resource_participant(mgr, participant,
        ownership_prepare_resource) == 0 && qihse_txn_manager_recover(mgr) == 0);

    qihse_txn_t* actor = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    qihse_txn_t* terminal = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    assert(actor && terminal);
    assert(qihse_txn_savepoint(mgr, actor, "before") == 0);
    assert(qihse_txn_record_write(actor, 41, "actor", 5) == 0);
    assert(qihse_txn_savepoint(mgr, actor, "after") == 0);
    assert(qihse_txn_record_write(actor, 41, "later", 5) == 0);
    assert(qihse_txn_record_write(terminal, 41, "terminal", 8) == 0);
    assert(qihse_txn_prepare(mgr, terminal) == 0);
    assert(qihse_txn_commit_prepared(mgr, terminal) == 0);
    qihse_txn_t* aborted = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(aborted && qihse_txn_rollback(mgr, aborted) == 0);
    uint64_t aborted_id = aborted->id;
    qihse_txn_t* attached = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    qihse_txn_t* bound = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    ownership_resource_t resources[3] = { { .owner = getpid() },
        { .owner = getpid() }, { .owner = getpid() } };
    assert(attached && bound);
    assert(qihse_txn_attach_resource(attached, &resources[1],
        ownership_resource_commit, ownership_resource_rollback) == 0);
    assert(qihse_txn_attach_participant_resource(mgr, bound, 41, &resources[2],
        ownership_resource_rollback) == 0);
    gate.txn = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    gate.mgr = mgr;
    assert(gate.txn && qihse_txn_prepare(mgr, gate.txn) == 0);
    uint64_t blocked_id = gate.txn->id, terminal_id = terminal->id;
    assert(record_path(&gate.mock, terminal_id, terminal_record, sizeof terminal_record) == 0);
    assert(record_path(&gate.mock, blocked_id, blocked_record, sizeof blocked_record) == 0);
    assert(qihse_txn_committed_history_count(mgr) > 0);
    assert(!qihse_txn_is_committed(mgr, 0) && !qihse_txn_is_aborted(mgr, 0));
    uint64_t sentinel = 123, *ids = &sentinel;
    int count = -17;
    assert(qihse_txn_active_list(mgr, NULL, &count) == -1 && count == -17);
    assert(qihse_txn_active_list(mgr, &ids, NULL) == -1 && ids == &sentinel);

    qihse_txn_t snapshots[3];
    memcpy(&snapshots[0], actor, sizeof(*actor));
    memcpy(&snapshots[1], attached, sizeof(*attached));
    memcpy(&snapshots[2], terminal, sizeof(*terminal));
    qihse_rw_entry_t writes[2];
    assert(actor->rw_count == 2);
    memcpy(writes, actor->rw_set, sizeof writes);
    for (size_t api = 0; api < sizeof ownership_apis / sizeof ownership_apis[0]; ++api)
        assert(ownership_rejected(api, NULL, actor, attached, terminal,
            aborted_id, resources, snapshots, writes) == 0);

    /* Run before auth fixtures start background services; quiesce audit too. */
    qihse_audit_shutdown();
    gate.blocked = true;
    pthread_t thread;
    assert(pthread_create(&thread, NULL, ownership_commit_thread, &gate) == 0);
    assert(pthread_mutex_lock(&gate.lock) == 0);
    while (!gate.entered) assert(pthread_cond_wait(&gate.cond, &gate.lock) == 0);
    assert(pthread_mutex_unlock(&gate.lock) == 0);
    int failures = 0;
    /* Also check an unlocked inherited manager, where stale registry reads or
     * destructive callbacks would otherwise succeed instead of deadlocking. */
    for (int locked = 1; locked >= 0; --locked) {
        size_t journal_len, terminal_len, blocked_len;
        unsigned char* journal_data = file_bytes(journal, &journal_len);
        unsigned char* terminal_data = file_bytes(terminal_record, &terminal_len);
        unsigned char* blocked_data = file_bytes(blocked_record, &blocked_len);
        for (size_t api = 0; api < sizeof ownership_apis / sizeof ownership_apis[0]; ++api) {
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                alarm(2);
                _exit(ownership_rejected(api, mgr, actor, attached, terminal,
                    aborted_id, resources, snapshots, writes));
            }
            int status;
            pid_t waited;
            do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
            assert(waited == child);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                fprintf(stderr, "inherited %s (%s): status=%d signal=%d\n", ownership_apis[api],
                    locked ? "locked" : "unlocked", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                    WIFSIGNALED(status) ? WTERMSIG(status) : 0);
                ++failures;
            }
        }
        assert_file_bytes(journal, journal_data, journal_len);
        assert_file_bytes(terminal_record, terminal_data, terminal_len);
        assert_file_bytes(blocked_record, blocked_data, blocked_len);
        free(journal_data); free(terminal_data); free(blocked_data);
        if (locked) {
            assert(pthread_mutex_lock(&gate.lock) == 0);
            gate.released = true;
            assert(pthread_cond_broadcast(&gate.cond) == 0);
            assert(pthread_mutex_unlock(&gate.lock) == 0);
            assert(pthread_join(thread, NULL) == 0);
            assert(gate.commit_result == 0);
            gate.blocked = false;
        }
    }
    assert(failures == 0);
    assert(qihse_txn_is_committed(mgr, terminal_id) && qihse_txn_is_committed(mgr, blocked_id));
    assert(qihse_txn_is_aborted(mgr, aborted_id) && qihse_txn_active_count(mgr) == 3);
    assert(qihse_txn_committed_history_count(mgr) > 0);
    ids = NULL; count = -1;
    assert(qihse_txn_active_list(mgr, &ids, &count) == 0 && count == 3);
    for (int i = 0; i < count; ++i)
        assert(ids[i] == actor->id || ids[i] == attached->id || ids[i] == bound->id);
    free(ids);
    assert(qihse_txn_release(mgr, terminal) == 0 && qihse_txn_release(mgr, aborted) == 0);
    assert(qihse_txn_release(mgr, gate.txn) == 0);
    assert(qihse_txn_savepoint(mgr, actor, "parent") == 0);
    assert(qihse_txn_rollback_to_savepoint(mgr, actor, "before") == 0);
    qihse_txn_refresh_snapshot(mgr, actor);
    assert(actor->snapshot >= blocked_id && qihse_txn_validate_occ(mgr, actor) == 0);
    assert(qihse_txn_attach_participant_resource(mgr, actor, 41, &resources[0],
        ownership_resource_rollback) == 0);
    assert(qihse_txn_rollback(mgr, actor) == 0 && resources[0].rollbacks == 1);
    assert(qihse_txn_release(mgr, actor) == 0);
    uint64_t attached_id = attached->id;
    assert(qihse_txn_enlist_attached_resource(mgr, attached, 41) == 0);
    assert(qihse_txn_prepare(mgr, attached) == 0 && resources[1].prepares == 1);
    assert(qihse_txn_commit_prepared(mgr, attached) == 0);
    assert(resources[1].commits == 0 && resources[1].rollbacks == 0);
    assert(qihse_txn_release(mgr, attached) == 0);
    ownership_resource_t local = { .owner = getpid() };
    qihse_txn_t* cleanup = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(cleanup && qihse_txn_attach_resource(cleanup, &local,
        ownership_resource_commit, ownership_resource_rollback) == 0);
    qihse_txn_manager_destroy(mgr);
    assert(resources[2].rollbacks == 1 && local.rollbacks == 1 && local.commits == 0);

    size_t journal_len;
    unsigned char* journal_data = file_bytes(journal, &journal_len);
    mgr = qihse_txn_manager_create_durable(journal);
    assert(mgr && qihse_txn_register_resource_participant(mgr, participant,
        ownership_prepare_resource) == 0 && qihse_txn_manager_recover(mgr) == 0);
    assert(qihse_txn_is_committed(mgr, terminal_id) && qihse_txn_is_committed(mgr, blocked_id));
    assert(qihse_txn_is_committed(mgr, attached_id) && qihse_txn_active_count(mgr) == 0);
    assert_record(&gate.mock, terminal_id, 'C');
    assert_record(&gate.mock, blocked_id, 'C');
    assert_record(&gate.mock, attached_id, 'C');
    assert_file_bytes(journal, journal_data, journal_len);
    free(journal_data);
    qihse_txn_t* fresh = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(fresh && fresh->id > blocked_id && qihse_txn_rollback(mgr, fresh) == 0);
    assert(qihse_txn_release(mgr, fresh) == 0);
    qihse_txn_manager_destroy(mgr);
    assert(pthread_cond_destroy(&gate.cond) == 0 && pthread_mutex_destroy(&gate.lock) == 0);
}

int main(void) {
    char root[] = "./build/qihse-txn-2pc-XXXXXX";
    assert(mkdtemp(root) != NULL);
    fprintf(stderr, "test_txn_durable_2pc artifacts: %s\n", root);
    test_manager_process_ownership(root);
    char journal[640];
    assert(snprintf(journal, sizeof(journal), "%s/coordinator.journal", root) > 0);
    char unsafe_journal[640];
    assert(snprintf(unsafe_journal, sizeof(unsafe_journal), "%s/unsafe.journal", root) > 0);
    char fault_journal[640];
    assert(snprintf(fault_journal, sizeof(fault_journal), "%s/fault.journal", root) > 0);
    char resource_journal[640];
    assert(snprintf(resource_journal, sizeof(resource_journal), "%s/resource.journal", root) > 0);
    int unsafe_fd = open(unsafe_journal, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    assert(unsafe_fd >= 0 && fchmod(unsafe_fd, 0644) == 0);
    close(unsafe_fd);
    errno = 0;
    assert(qihse_txn_manager_create_durable(unsafe_journal) == NULL && errno == EACCES);
    assert(unlink(unsafe_journal) == 0);

    struct stat parent_st;
    assert(stat(root, &parent_st) == 0 && S_ISDIR(parent_st.st_mode));
    parent_dir_dev = parent_st.st_dev;
    parent_dir_ino = parent_st.st_ino;
    fail_parent_dir_fsync = 1;
    errno = 0;
    assert(qihse_txn_manager_create_durable(fault_journal) == NULL && errno == EIO);
    fail_parent_dir_fsync = 0;
    assert(parent_dir_fsync_observed == 1);

    qihse_txn_manager_t* recovery_mgr = qihse_txn_manager_create_durable(fault_journal);
    assert(recovery_mgr);
    mock_t recovery_mock = { .engine = 7 };
    assert(snprintf(recovery_mock.dir, sizeof(recovery_mock.dir), "%s", root) > 0);
    qihse_txn_participant_t recovery_participant = { .engine_id = recovery_mock.engine,
        .engine_ctx = &recovery_mock, .prepare = prepare, .commit = commit, .abort = abort_txn };
    assert(qihse_txn_register_participant(recovery_mgr, recovery_participant) == 0);
    assert(qihse_txn_manager_recover(recovery_mgr) == 0);
    qihse_txn_t* recovery_txn = qihse_txn_begin(recovery_mgr, QIHSE_ISO_READ_COMMITTED);
    assert(recovery_txn && recovery_txn->id == 1);
    assert(qihse_txn_prepare(recovery_mgr, recovery_txn) == 0);
    assert(qihse_txn_commit_prepared(recovery_mgr, recovery_txn) == 0);
    assert(qihse_txn_is_committed(recovery_mgr, 1));
    qihse_txn_manager_destroy(recovery_mgr);

    /* A bound transaction resource is routed through the durable participant's
     * prepare callback; direct one-phase commit must not consume it. */
    mock_t resource_mock = { .engine = 11 };
    mock_t resource_mock2 = { .engine = 12 };
    assert(snprintf(resource_mock.dir, sizeof(resource_mock.dir), "%s", root) > 0);
    assert(snprintf(resource_mock2.dir, sizeof(resource_mock2.dir), "%s", root) > 0);
    qihse_txn_participant_t resource_participant = {
        .engine_id = resource_mock.engine, .engine_ctx = &resource_mock,
        .prepare = prepare, .commit = commit, .abort = abort_txn
    };
    qihse_txn_participant_t resource_participant2 = {
        .engine_id = resource_mock2.engine, .engine_ctx = &resource_mock2,
        .prepare = prepare, .commit = commit, .abort = abort_txn
    };
    qihse_txn_manager_t* resource_mgr =
        qihse_txn_manager_create_durable(resource_journal);
    assert(resource_mgr);
    assert(qihse_txn_register_resource_participant(resource_mgr,
        resource_participant, prepare_resource) == 0);
    assert(qihse_txn_register_resource_participant(resource_mgr,
        resource_participant2, prepare_resource) == 0);
    assert(qihse_txn_manager_recover(resource_mgr) == 0);
    qihse_txn_t* resource_txn =
        qihse_txn_begin(resource_mgr, QIHSE_ISO_READ_COMMITTED);
    assert(resource_txn && resource_txn->id == 1);
    resource_payload_t* payload = malloc(sizeof(*payload));
    assert(payload);
    payload->marker = UINT32_C(0x51525354);
    assert(qihse_txn_attach_resource(resource_txn, payload,
        one_phase_resource_commit, rollback_resource) == 0);
    assert(qihse_txn_enlist_attached_resource(resource_mgr, resource_txn,
        resource_mock.engine) == 0);
    assert(resource_txn->resource_ctx == NULL);
    resource_payload_t* payload2 = malloc(sizeof(*payload2));
    assert(payload2);
    payload2->marker = UINT32_C(0x51525354);
    assert(qihse_txn_attach_participant_resource(resource_mgr, resource_txn,
        resource_mock2.engine, payload2, rollback_resource) == 0);
    assert(qihse_txn_commit(resource_mgr, resource_txn) == -1);
    assert(resource_txn->resource_ctx == NULL);
    assert(qihse_txn_prepare(resource_mgr, resource_txn) == 0);
    assert(resource_txn->resource_ctx == NULL);
    assert(qihse_txn_commit_prepared(resource_mgr, resource_txn) == 0);
    assert(one_phase_resource_commit_calls == 0);
    assert_record(&resource_mock, 1, 'C');
    assert_record(&resource_mock2, 1, 'C');

    resource_txn = qihse_txn_begin(resource_mgr, QIHSE_ISO_READ_COMMITTED);
    assert(resource_txn && resource_txn->id == 2);
    payload = malloc(sizeof(*payload));
    assert(payload);
    payload->marker = 0; /* participant rejects, but still consumes the resource */
    assert(qihse_txn_attach_participant_resource(resource_mgr, resource_txn,
        resource_mock.engine, payload, rollback_resource) == 0);
    assert(qihse_txn_prepare(resource_mgr, resource_txn) == -1);
    assert(resource_txn->resource_ctx == NULL);
    assert(resource_txn->state == QIHSE_TXN_ABORTED ||
           resource_txn->state == QIHSE_TXN_ABORTING);
    assert(qihse_txn_commit_prepared(resource_mgr, resource_txn) == -1);
    assert_record(&resource_mock, 2, 'A');
    qihse_txn_manager_destroy(resource_mgr);

    /* A process crash after resource PREPARE and durable COMMIT must replay
     * through the participant's persisted record, not the freed SQL shadow. */
    int resource_status = 0;
    pid_t resource_child = fork();
    assert(resource_child >= 0);
    if (resource_child == 0) {
        resource_mgr = qihse_txn_manager_create_durable(resource_journal);
        assert(resource_mgr);
        assert(qihse_txn_register_resource_participant(resource_mgr,
            resource_participant, prepare_resource) == 0);
        assert(qihse_txn_register_resource_participant(resource_mgr,
            resource_participant2, prepare_resource) == 0);
        assert(qihse_txn_manager_recover(resource_mgr) == 0);
        resource_txn = qihse_txn_begin(resource_mgr, QIHSE_ISO_READ_COMMITTED);
        assert(resource_txn && resource_txn->id == 3);
        payload = malloc(sizeof(*payload));
        assert(payload);
        payload->marker = UINT32_C(0x51525354);
        assert(qihse_txn_attach_participant_resource(resource_mgr, resource_txn,
            resource_mock.engine, payload, rollback_resource) == 0);
        payload2 = malloc(sizeof(*payload2));
        assert(payload2);
        payload2->marker = UINT32_C(0x51525354);
        assert(qihse_txn_attach_participant_resource(resource_mgr, resource_txn,
            resource_mock2.engine, payload2, rollback_resource) == 0);
        assert(qihse_txn_prepare(resource_mgr, resource_txn) == 0);
        resource_mock.crash_commit = 1;
        (void)qihse_txn_commit_prepared(resource_mgr, resource_txn);
        _exit(3);
    }
    assert(waitpid(resource_child, &resource_status, 0) == resource_child &&
           WIFEXITED(resource_status) && WEXITSTATUS(resource_status) == 77);
    resource_mgr = qihse_txn_manager_create_durable(resource_journal);
    assert(resource_mgr);
    assert(qihse_txn_register_resource_participant(resource_mgr,
        resource_participant, prepare_resource) == 0);
    assert(qihse_txn_register_resource_participant(resource_mgr,
        resource_participant2, prepare_resource) == 0);
    assert(qihse_txn_manager_recover(resource_mgr) == 0);
    assert(qihse_txn_is_committed(resource_mgr, 3));
    assert_record(&resource_mock, 3, 'C');
    assert_record(&resource_mock2, 3, 'C');
    qihse_txn_manager_destroy(resource_mgr);

    mock_t mocks[2] = { { .engine = 3 }, { .engine = 9 } };
    for (int i = 0; i < 2; ++i) assert(snprintf(mocks[i].dir, sizeof(mocks[i].dir), "%s", root) > 0);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(journal);
        assert(mgr); register_pair(mgr, mocks);
        assert(qihse_txn_manager_recover(mgr) == 0);
        qihse_txn_t* txn = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
        assert(txn && txn->id == 1);
        assert(qihse_txn_prepare(mgr, txn) == 0);
        mocks[0].crash_commit = 1;
        (void)qihse_txn_commit_prepared(mgr, txn);
        _exit(3);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 77);

    qihse_txn_manager_t* mgr = qihse_txn_manager_create_durable(journal);
    assert(mgr);
    register_pair(mgr, mocks);
    assert(qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED) == NULL);
    mocks[0].fail_commit_once = 1;
    assert(qihse_txn_manager_recover(mgr) == -1);
    assert(qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED) == NULL);
    assert(qihse_txn_manager_recover(mgr) == 0);
    assert(qihse_txn_is_committed(mgr, 1));
    assert_record(&mocks[0], 1, 'C'); assert_record(&mocks[1], 1, 'C');
    qihse_txn_manager_destroy(mgr);

    child = fork();
    assert(child >= 0);
    if (child == 0) {
        mgr = qihse_txn_manager_create_durable(journal);
        assert(mgr); register_pair(mgr, mocks);
        assert(qihse_txn_manager_recover(mgr) == 0);
        qihse_txn_t* txn = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
        assert(txn && txn->id == 2);
        assert(qihse_txn_prepare(mgr, txn) == 0);
        _exit(78); /* membership and participant prepares durable, no decision */
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 78);

    mgr = qihse_txn_manager_create_durable(journal);
    assert(mgr); register_pair(mgr, mocks);
    assert(qihse_txn_manager_recover(mgr) == 0);
    assert(qihse_txn_is_aborted(mgr, 2));
    assert_record(&mocks[0], 2, 'A'); assert_record(&mocks[1], 2, 'A');
    qihse_txn_manager_destroy(mgr);

    child = fork();
    assert(child >= 0);
    if (child == 0) {
        mgr = qihse_txn_manager_create_durable(journal);
        assert(mgr); register_pair(mgr, mocks);
        assert(qihse_txn_manager_recover(mgr) == 0);
        qihse_txn_t* txn = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
        assert(txn && txn->id == 3);
        assert(qihse_txn_prepare(mgr, txn) == 0);
        mocks[0].crash_abort = 1;
        (void)qihse_txn_abort_prepared(mgr, txn);
        _exit(4);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 79);

    mgr = qihse_txn_manager_create_durable(journal);
    assert(mgr); register_pair(mgr, mocks);
    assert(qihse_txn_manager_recover(mgr) == 0);
    assert(qihse_txn_is_aborted(mgr, 3));
    assert_record(&mocks[0], 3, 'A'); assert_record(&mocks[1], 3, 'A');
    qihse_txn_manager_destroy(mgr);

    test_backup_auth(root);

    /* Reached only on success: assertion failures retain their artifacts. The
     * new backup/auth fixtures remain available alongside their audit logs. */
    char path[640];
    for (int id = 1; id <= 3; ++id) for (int i = 0; i < 2; ++i) {
        assert(record_path(&mocks[i], (uint64_t)id, path, sizeof(path)) == 0);
        unlink(path);
    }
    assert(record_path(&recovery_mock, 1, path, sizeof(path)) == 0);
    unlink(path);
    for (int id = 1; id <= 3; ++id) {
        assert(record_path(&resource_mock, (uint64_t)id, path, sizeof(path)) == 0);
        unlink(path);
        assert(record_path(&resource_mock2, (uint64_t)id, path, sizeof(path)) == 0);
        unlink(path);
    }
    unlink(journal);
    unlink(fault_journal);
    unlink(resource_journal);
    rmdir(root);
    puts("test_txn_durable_2pc: ok");
    return 0;
}
