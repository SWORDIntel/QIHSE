#include "qihse_ct1_receiver_writer.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include "core/qihse_audit.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void name(char out[512], const char *dir, const char *entry)
{
    assert(snprintf(out, 512, "%s/%s", dir, entry) < 512);
}

static char altered_state[512];
static unsigned inject_change;

void qihse_ct1_receiver_test_before_recheck(void)
{
    if (inject_change) {
        int fd = open(altered_state, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        assert(fd >= 0 && pwrite(fd, "!", 1, 0) == 1 && !close(fd));
        inject_change = 0;
    }
}

static bool preflight(const char *dir, qihse_user_t *service,
    const qihse_ct1_recovery_manifest_t *manifest)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    bool result = flock(fd, LOCK_EX | LOCK_NB) == 0 &&
        qihse_ct1_receiver_preflight_locked(fd, dir, service, manifest);
    assert(!flock(fd, LOCK_UN) && !close(fd));
    return result;
}

/* ROOT-FRESH copies from verified bytes, never an old B-visible inode. */
void ct1_receiver_fresh_cases(const char *parent, const char *source,
    qihse_user_t *service, qihse_user_t *low,
    const qihse_ct1_recovery_manifest_t *manifest)
{
    int parentfd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat pins[QIHSE_CT1_RECOVERY_TARGET_FILES], old, fresh;
    char source_wal[512], source_state[512], dest[512], dest_wal[512],
        dest_state[512], extra[512];
    name(source_wal, source, "wal.log");
    name(source_state, source, "ct-state.bin");
    name(dest, parent, "fresh-unit");
    name(dest_wal, dest, "wal.log");
    name(dest_state, dest, "ct-state.bin");
    int stale = open(source_wal, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    int stale_state = open(source_state, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    assert(parentfd >= 0 && stale >= 0 && stale_state >= 0 && !fstat(stale, &old));
    unsigned char byte, state_byte;
    assert(pread(stale, &byte, 1, 20) == 1 && byte != '!' &&
        pread(stale_state, &state_byte, 1, 0) == 1 && state_byte != '!');
    int pipefd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd));
    pid_t stale_b = fork();
    assert(stale_b >= 0);
    if (!stale_b) {
        close(pipefd[0]);
        assert(!setgid(65534) && !setuid(65534));
        char go;
        assert(read(pipefd[1], &go, 1) == 1 && go == 'm' &&
            pwrite(stale, "!", 1, 20) == 1 && !fsync(stale) &&
            pwrite(stale_state, "!", 1, 0) == 1 && !fsync(stale_state) &&
            write(pipefd[1], "1", 1) == 1);
        close(stale_state);
        close(stale);
        close(pipefd[1]);
        _exit(0);
    }
    close(pipefd[1]);
    int freshfd = -1;
    assert(!qihse_ct1_receiver_fresh_provision(parentfd, "fresh-unit", source,
        dest, low, manifest, &freshfd, pins) &&
        !qihse_ct1_receiver_fresh_provision(parentfd, "fresh-unit", source,
        dest, NULL, manifest, &freshfd, pins));
    assert(access(dest, F_OK) == -1 && errno == ENOENT);
    assert(qihse_ct1_receiver_fresh_provision(parentfd, "fresh-unit", source,
        dest, service, manifest, &freshfd, pins));
    int fd = open(dest_wal, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && !fstat(fd, &fresh) && fresh.st_uid == 0 &&
        fresh.st_nlink == 1 && (fresh.st_mode & 07777) == 0400 &&
        (fresh.st_dev != old.st_dev || fresh.st_ino != old.st_ino) &&
        !close(fd));
    assert(qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins) &&
        !qihse_ct1_receiver_fresh_pinned(freshfd, dest, low, manifest, pins) &&
        !qihse_ct1_receiver_fresh_provision(parentfd, "fresh-unit", source,
            dest, service, manifest, &fd, pins));
    char moved;
    assert(write(pipefd[0], "m", 1) == 1 &&
        read(pipefd[0], &moved, 1) == 1 && moved == '1' && !close(pipefd[0]));
    int stale_status;
    assert(waitpid(stale_b, &stale_status, 0) == stale_b && WIFEXITED(stale_status) &&
        WEXITSTATUS(stale_status) == 0);
    assert(qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins));
    fd = open(dest_wal, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    unsigned char copied;
    assert(fd >= 0 && pread(fd, &copied, 1, 20) == 1 &&
        copied == byte && !close(fd));
    fd = open(dest_state, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && pread(fd, &copied, 1, 0) == 1 &&
        copied == state_byte && !close(fd)); /* stale B-UID fds touched old inodes */
    name(extra, parent, "bad-source");
    assert(!qihse_ct1_receiver_fresh_provision(parentfd, "bad-source", source,
        extra, service, manifest, &fd, pins) &&
        access(extra, F_OK) == -1 && errno == ENOENT); /* changed source roster */
    assert(pwrite(stale, &byte, 1, 20) == 1 && !fsync(stale) && !close(stale) &&
        pwrite(stale_state, &state_byte, 1, 0) == 1 && !fsync(stale_state) &&
        !close(stale_state));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!setgid(65534) && !setuid(65534));
        assert(open(dest_wal, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) == -1 &&
            errno == EACCES);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    name(extra, dest, "unexpected");
    fd = open(extra, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(fd >= 0 && !close(fd) &&
        !qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins) &&
        !unlink(extra));
    assert(qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins));
    name(extra, dest, "wal-alias");
    assert(!link(dest_wal, extra) &&
        !qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins) &&
        !unlink(extra));
    assert(!qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins));
    name(extra, dest, "wal-replaced");
    assert(!rename(dest_wal, extra) && !symlink("wal-replaced", dest_wal) &&
        !qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins) &&
        !unlink(dest_wal) && !rename(extra, dest_wal));
    assert(!qihse_ct1_receiver_fresh_pinned(freshfd, dest, service, manifest, pins));
    assert(!close(freshfd));
    for (size_t i = 0; i < 2; ++i) {
        const char *cut = i ? "file" : "mkdir";
        const char *leaf = i ? "cut-file" : "cut-mkdir";
        name(extra, parent, leaf);
        qihse_audit_shutdown();
        child = fork();
        assert(child >= 0);
        if (!child) {
            qihse_audit_init();
            assert(!setenv("QIHSE_CT1_RECEIVER_FRESH_CUT", cut, 1));
            int doomed = -1;
            (void)qihse_ct1_receiver_fresh_provision(parentfd, leaf, source,
                extra, service, manifest, &doomed, pins);
            _exit(70);
        }
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 86);
        qihse_audit_init();
        assert(!qihse_ct1_receiver_fresh_provision(parentfd, leaf, source,
                extra, service, manifest, &fd, pins));
        struct stat partial;
        assert(!lstat(extra, &partial) && S_ISDIR(partial.st_mode));
    }
    assert(!close(parentfd));
}

/* Called only on disposable exported native TARGET, never a production path. */
void ct1_receiver_preflight_cases(const char *dir, qihse_user_t *service,
    qihse_user_t *low, const qihse_ct1_recovery_manifest_t *manifest)
{
    assert(preflight(dir, service, manifest));
    assert(preflight(dir, service, manifest)); /* cold descriptor reopen */
    assert(!preflight(dir, NULL, manifest) && !preflight(dir, low, manifest));
    char path[512], extra[512];
    name(path, dir, "ct-state.bin");
    int oldfd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    struct stat oldstat;
    assert(oldfd >= 0 && fstat(oldfd, &oldstat) == 0 &&
        oldstat.st_size > 16 && oldstat.st_size < 16384);
    size_t length = (size_t)oldstat.st_size;
    unsigned char *saved = malloc(length), *version3 = malloc(length);
    assert(saved && version3 && pread(oldfd, saved, length, 0) == (ssize_t)length &&
        !memcmp(saved, "QCTST005", 8));
    memcpy(version3, saved, length);
    memcpy(version3, "QCTST003", 8);
    uint64_t sum = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length - sizeof(sum); ++i) {
        sum ^= version3[i];
        sum *= UINT64_C(1099511628211);
    }
    memcpy(version3 + length - sizeof(sum), &sum, sizeof(sum));
    assert(pwrite(oldfd, version3, length, 0) == (ssize_t)length &&
        fsync(oldfd) == 0);
    qihse_ct1_recovery_manifest_t old_roster = *manifest;
    for (unsigned i = 0; i < QIHSE_CT1_RECOVERY_TARGET_FILES; ++i) {
        if (strcmp(old_roster.target_files[i].filename, "ct-state.bin")) continue;
        assert(SHA256(version3, length, old_roster.target_files[i].sha256));
    }
    assert(qihse_ct1_recovery_verify_frozen(service, dir, &old_roster, false) &&
        !preflight(dir, service, &old_roster)); /* complete V3 roster still denied */
    assert(pwrite(oldfd, saved, length, 0) == (ssize_t)length &&
        fsync(oldfd) == 0 && close(oldfd) == 0);
    free(saved);
    free(version3);
    assert(preflight(dir, service, manifest));
    qihse_ct1_recovery_manifest_t wrong = *manifest;
    wrong.tombstone_position++;
    assert(!preflight(dir, service, &wrong)); /* sequence != stream position */
    wrong = *manifest;
    wrong.tombstone_row_seq++;
    assert(!preflight(dir, service, &wrong));
    wrong = *manifest;
    wrong.target_cursor--;
    assert(!preflight(dir, service, &wrong));

    name(path, dir, "wal.log");
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    unsigned char original;
    assert(fd >= 0 && pread(fd, &original, 1, 20) == 1 &&
        pwrite(fd, "!", 1, 20) == 1 && !close(fd));
    assert(!preflight(dir, service, manifest));
    fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && pwrite(fd, &original, 1, 20) == 1 && !close(fd));
    assert(preflight(dir, service, manifest));
    name(extra, dir, "wal.log.old");
    assert(!rename(path, extra));
    assert(!preflight(dir, service, manifest)); /* rotated/missing history */
    assert(!symlink("wal.log.old", path));
    assert(!preflight(dir, service, manifest)); /* symlink to valid history */
    assert(!unlink(path) && !rename(extra, path));
    fd = open(extra, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    assert(fd >= 0 && !close(fd));
    assert(!preflight(dir, service, manifest)); /* extra file */
    assert(!unlink(extra) && preflight(dir, service, manifest));
    name(path, dir, "ct-state.bin");
    fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && pread(fd, &original, 1, 0) == 1 &&
        pwrite(fd, "!", 1, 0) == 1 && !close(fd));
    assert(!preflight(dir, service, manifest));
    fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && pwrite(fd, &original, 1, 0) == 1 && !close(fd));
    assert(preflight(dir, service, manifest));
    name(altered_state, dir, "ct-state.bin");
    inject_change = 1;
    assert(!preflight(dir, service, manifest)); /* state changed after WAL parse */
    fd = open(altered_state, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && pwrite(fd, &original, 1, 0) == 1 && !close(fd));
    assert(preflight(dir, service, manifest));

    char moved[512];
    assert(snprintf(moved, sizeof(moved), "%s.replaced", dir) < (int)sizeof(moved));
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
    assert(!rename(dir, moved) && !mkdir(dir, 0700));
    assert(!qihse_ct1_receiver_preflight_locked(fd, dir, service, manifest));
    assert(!rmdir(dir) && !rename(moved, dir) && !flock(fd, LOCK_UN) &&
        !close(fd));
    assert(preflight(dir, service, manifest));

    int pipes[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pipes));
    pid_t owner = fork();
    assert(owner >= 0);
    if (!owner) {
        close(pipes[0]);
        fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB) &&
            write(pipes[1], "1", 1) == 1);
        char release;
        assert(read(pipes[1], &release, 1) == 1 && release == '0');
        close(pipes[1]);
        _exit(0);
    }
    close(pipes[1]);
    assert(read(pipes[0], &original, 1) == 1);
    assert(!preflight(dir, service, manifest)); /* live flock owner */
    assert(write(pipes[0], "0", 1) == 1);
    close(pipes[0]);
    int status;
    assert(waitpid(owner, &status, 0) == owner && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    assert(preflight(dir, service, manifest));

    /* Simulate an idle pre-lease binary retaining a writable WAL descriptor.
     * V5 excludes cold old opens, NOT preexisting handles: advisory flock
     * cannot prevent their writes after a successful root preflight. */
    name(path, dir, "wal.log");
    int wal_restore = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    unsigned char saved_wal;
    assert(wal_restore >= 0 && pread(wal_restore, &saved_wal, 1, 20) == 1 &&
        saved_wal != '!');
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pipes));
    owner = fork();
    assert(owner >= 0);
    if (!owner) {
        close(pipes[0]);
        int stale = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        assert(stale >= 0 && write(pipes[1], "1", 1) == 1);
        char command;
        assert(read(pipes[1], &command, 1) == 1 && command == 'm');
        assert(pwrite(stale, "!", 1, 20) == 1 && fsync(stale) == 0 &&
            write(pipes[1], "2", 1) == 1);
        assert(read(pipes[1], &command, 1) == 1 && command == '0');
        assert(close(stale) == 0);
        close(pipes[1]);
        _exit(0);
    }
    close(pipes[1]);
    assert(read(pipes[0], &original, 1) == 1 && original == '1');
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
    assert(qihse_ct1_receiver_preflight_locked(fd, dir, service, manifest));
    assert(write(pipes[0], "m", 1) == 1 &&
        read(pipes[0], &original, 1) == 1 && original == '2');
    assert(!qihse_ct1_receiver_preflight_locked(fd, dir, service, manifest));
    assert(pwrite(wal_restore, &saved_wal, 1, 20) == 1 &&
        fsync(wal_restore) == 0 && close(wal_restore) == 0);
    assert(qihse_ct1_receiver_preflight_locked(fd, dir, service, manifest));
    assert(write(pipes[0], "0", 1) == 1 && !close(pipes[0]) &&
        !flock(fd, LOCK_UN) && !close(fd));
    assert(waitpid(owner, &status, 0) == owner && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);

    /* A real receiver handle (not a child that merely flocks) must exclude
     * root throughout admission, an apply call, and WAL close. */
    qihse_audit_shutdown();
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pipes));
    owner = fork();
    assert(owner >= 0);
    if (!owner) {
        close(pipes[0]);
        qihse_audit_init();
        assert(!setenv("QIHSE_DATA_DIR", dir, 1));
        qihse_kv_store_t *store = qihse_kv_store_create_user(qihse_auth_get_user(0));
        if (!store) perror("receiver owner open");
        assert(store);
        qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(service));
        assert(write(pipes[1], "1", 1) == 1);
        char command;
        assert(read(pipes[1], &command, 1) == 1 && command == 'm');
        qihse_kv_ct_record_t row = {
            .key = "commons/other-7", .value = "fixture-value",
            .change_seq = manifest->baseline_row_seq + 7,
            .actor_id = 0, .actor_tenant_id = 0, .resource_tenant_id = 0,
            .classification = 4, .sci_compartment = 2,
            .actor_kind = QIHSE_KV_CT_ACTOR_USER
        };
        qihse_kv_ct_group_t group = {
            .stream_position = manifest->target_cursor,
            .first_seq = row.change_seq, .last_seq = row.change_seq,
            .records = &row, .count = 1
        };
        assert(snprintf(group.source_id, sizeof(group.source_id), "%s",
            manifest->source_store_id) > 0);
        assert(snprintf(group.generation, sizeof(group.generation), "%s",
            manifest->generation) > 0);
        uint64_t cursor = 0;
        assert(qihse_kv_ct_receiver_apply(store, service, &group, &cursor) &&
            cursor == manifest->target_cursor);
        assert(write(pipes[1], "2", 1) == 1);
        assert(read(pipes[1], &command, 1) == 1 && command == '0');
        qihse_kv_store_destroy(store);
        assert(write(pipes[1], "3", 1) == 1);
        assert(read(pipes[1], &command, 1) == 1 && command == 'r');
        store = qihse_kv_store_create_user(qihse_auth_get_user(0));
        assert(store && write(pipes[1], "4", 1) == 1);
        assert(read(pipes[1], &command, 1) == 1 && command == 'c');
        qihse_kv_store_destroy(store);
        assert(write(pipes[1], "5", 1) == 1);
        close(pipes[1]);
        _exit(0);
    }
    close(pipes[1]);
    assert(read(pipes[0], &original, 1) == 1 && original == '1');
    assert(!preflight(dir, service, manifest));
    assert(write(pipes[0], "m", 1) == 1);
    assert(read(pipes[0], &original, 1) == 1 && original == '2');
    assert(!preflight(dir, service, manifest));
    assert(write(pipes[0], "0", 1) == 1);
    assert(read(pipes[0], &original, 1) == 1 && original == '3');
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
    assert(!flock(fd, LOCK_UN) && !close(fd));
    assert(write(pipes[0], "r", 1) == 1);
    assert(read(pipes[0], &original, 1) == 1 && original == '4');
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) != 0);
    assert(close(fd) == 0);
    assert(write(pipes[0], "c", 1) == 1);
    assert(read(pipes[0], &original, 1) == 1 && original == '5');
    close(pipes[0]);
    assert(waitpid(owner, &status, 0) == owner && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    qihse_audit_init();
    assert(preflight(dir, service, manifest));
}
