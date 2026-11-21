#include "qihse_ct1_authority_store.h"
#include "qihse_ct1_recovery_manifest.h"
#include <openssl/sha.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void remove_fixture(char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/authority.log", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/authority.lock", dir); unlink(path);
    assert(rmdir(dir) == 0);
}

static void child_exit_ok(pid_t pid)
{
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void lifecycle(void)
{
    char dir[] = "./ct1-host-lifecycle-XXXXXX";
    assert(mkdtemp(dir));
    assert(chmod(dir, 0700) == 0);
    qihse_ct1_authority_store_t *s = NULL;
    assert(qihse_ct1_authority_store_open(dir, &s) == -1 && s == NULL);
    assert(!qihse_ct1_authority_store_initialize(dir));
    assert(qihse_ct1_authority_store_initialize(dir) == -1);
    assert(!qihse_ct1_authority_store_open(dir, &s));
    qihse_ct1_authority_challenge_t a = {0}, b = {0};
    assert(qihse_ct1_authority_store_issue(s, 0, &a) == -1);
    assert(qihse_ct1_authority_store_issue(s, 900001, &a) == -1);
    assert(!qihse_ct1_authority_store_issue(s, 900000, &a));
    assert(a.epoch == 1 && a.expires_ms - a.issued_ms == 900000);
    assert(qihse_ct1_authority_store_issue(s, 1000, &b) == -1);
    qihse_ct1_authority_store_close(s);
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        qihse_ct1_authority_store_t *c = NULL;
        if (qihse_ct1_authority_store_open(dir, &c) ||
            qihse_ct1_authority_store_retire(c, &a) ||
            qihse_ct1_authority_store_retire(c, &a) != -1) _exit(1);
        qihse_ct1_authority_store_close(c);
        _exit(0);
    }
    child_exit_ok(pid);
    assert(!qihse_ct1_authority_store_open(dir, &s));
    assert(qihse_ct1_authority_store_retire(s, &a) == -1);
    assert(!qihse_ct1_authority_store_issue(s, 1000, &b));
    assert(b.epoch == 2 && memcmp(a.nonce, b.nonce, 32));
    assert(qihse_ct1_authority_store_retire(s, &a) == -1);
    qihse_ct1_authority_challenge_t forged = b;
    forged.nonce[0] ^= 1;
    assert(qihse_ct1_authority_store_retire(s, &forged) == -1);
    assert(!qihse_ct1_authority_store_retire(s, &b));
    qihse_ct1_authority_store_close(s);
    remove_fixture(dir);
}

static void concurrent_issue(void)
{
    char dir[] = "./ct1-host-race-XXXXXX";
    assert(mkdtemp(dir));
    assert(!chmod(dir, 0700));
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_initialize(dir));
    assert(!qihse_ct1_authority_store_open(dir, &s));
    qihse_ct1_authority_store_close(s);
    int gate[2];
    assert(!pipe(gate));
    pid_t children[2];
    for (int i = 0; i < 2; ++i) {
        children[i] = fork();
        assert(children[i] >= 0);
        if (!children[i]) {
            close(gate[1]);
            qihse_ct1_authority_store_t *child = NULL;
            char token;
            if (qihse_ct1_authority_store_open(dir, &child) ||
                read(gate[0], &token, 1) != 1) _exit(2);
            qihse_ct1_authority_challenge_t challenge;
            int issued = !qihse_ct1_authority_store_issue(child, 900000, &challenge);
            qihse_ct1_authority_store_close(child);
            _exit(issued ? 0 : 1);
        }
    }
    close(gate[0]);
    assert(write(gate[1], "go", 2) == 2);
    close(gate[1]);
    int winners = 0;
    for (int i = 0; i < 2; ++i) {
        int status;
        assert(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status));
        assert(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 1);
        winners += WEXITSTATUS(status) == 0;
    }
    assert(winners == 1);
    remove_fixture(dir);
}

static void crash_cuts(void)
{
    char dir[] = "./ct1-host-crash-XXXXXX";
    assert(mkdtemp(dir));
    assert(chmod(dir, 0700) == 0);
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_initialize(dir));
    assert(!qihse_ct1_authority_store_open(dir, &s));
    qihse_ct1_authority_store_close(s);
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        qihse_ct1_authority_challenge_t c;
        qihse_ct1_authority_store_t *child = NULL;
        if (qihse_ct1_authority_store_open(dir, &child) ||
            qihse_ct1_authority_store_issue(child, 900000, &c)) _exit(1);
        /* Immediate process death after durable intent, before caller can use it. */
        _exit(0);
    }
    child_exit_ok(pid);
    assert(!qihse_ct1_authority_store_open(dir, &s));
    qihse_ct1_authority_challenge_t next;
    assert(qihse_ct1_authority_store_issue(s, 1000, &next) == -1);
    qihse_ct1_authority_store_close(s);
    remove_fixture(dir);

    char torn[] = "./ct1-host-torn-XXXXXX";
    assert(mkdtemp(torn));
    assert(chmod(torn, 0700) == 0);
    assert(!qihse_ct1_authority_store_initialize(torn));
    assert(!qihse_ct1_authority_store_open(torn, &s));
    qihse_ct1_authority_store_close(s);
    pid = fork();
    assert(pid >= 0);
    if (!pid) {
        char path[256];
        snprintf(path, sizeof(path), "%s/authority.log", torn);
        int fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);
        if (fd < 0 || write(fd, "partial-intent", 14) != 14 || fsync(fd)) _exit(1);
        _exit(0);
    }
    child_exit_ok(pid);
    assert(qihse_ct1_authority_store_open(torn, &s) == -1);
    remove_fixture(torn);

    char orphan[] = "./ct1-host-orphan-XXXXXX";
    assert(mkdtemp(orphan));
    assert(chmod(orphan, 0700) == 0);
    char path[256];
    snprintf(path, sizeof(path), "%s/authority.lock", orphan);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(!close(fd));
    assert(qihse_ct1_authority_store_open(orphan, &s) == -1);
    assert(qihse_ct1_authority_store_initialize(orphan) == -1);
    remove_fixture(orphan);

    char log_only[] = "./ct1-host-log-only-XXXXXX";
    assert(mkdtemp(log_only));
    snprintf(path, sizeof(path), "%s/authority.log", log_only);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && !close(fd));
    assert(qihse_ct1_authority_store_open(log_only, &s) == -1);
    assert(qihse_ct1_authority_store_initialize(log_only) == -1);
    remove_fixture(log_only);
}

static void deleted_state(void)
{
    char dir[] = "./ct1-host-deleted-XXXXXX";
    assert(mkdtemp(dir));
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_initialize(dir));
    assert(!qihse_ct1_authority_store_open(dir, &s));
    qihse_ct1_authority_challenge_t challenge;
    assert(!qihse_ct1_authority_store_issue(s, 900000, &challenge));
    qihse_ct1_authority_store_close(s);
    char path[256];
    snprintf(path, sizeof(path), "%s/authority.log", dir);
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/authority.lock", dir);
    assert(!unlink(path));
    s = NULL;
    assert(qihse_ct1_authority_store_open(dir, &s) == -1 && s == NULL);
    remove_fixture(dir);
}

static void path_guards(void)
{
    char dir[] = "./ct1-host-guards-XXXXXX";
    assert(mkdtemp(dir));
    assert(chmod(dir, 0700) == 0);
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_initialize(dir));
    assert(!qihse_ct1_authority_store_open(dir, &s));
    assert(!chmod(dir, 0770));
    qihse_ct1_authority_challenge_t c;
    assert(qihse_ct1_authority_store_issue(s, 1000, &c) == -1);
    assert(!chmod(dir, 0700));
    char path[256], displaced[256];
    snprintf(path, sizeof(path), "%s/authority.log", dir);
    snprintf(displaced, sizeof(displaced), "%s/old-log", dir);
    assert(!rename(path, displaced));
    assert(!symlink("old-log", path));
    assert(qihse_ct1_authority_store_issue(s, 1000, &c) == -1);
    assert(!unlink(path));
    assert(!rename(displaced, path));
    qihse_ct1_authority_store_close(s);
    remove_fixture(dir);

    char parent[] = "./ct1-host-parent-XXXXXX";
    assert(mkdtemp(parent));
    assert(!chmod(parent, 0777));
    snprintf(path, sizeof(path), "%s/private", parent);
    assert(!mkdir(path, 0700));
    assert(qihse_ct1_authority_store_open(path, &s) == -1);
    assert(qihse_ct1_authority_store_initialize(path) == -1);
    assert(!rmdir(path));
    assert(!rmdir(parent));
}

/* The host owner can restore a complete, authentic prefix. This fixture must
 * keep succeeding until an independent rollback anchor actually exists. Neither
 * the first retirement nor its replay establishes any authorization. */
static void intact_older_snapshot(void)
{
    char dir[] = "./ct1-host-rollback-XXXXXX";
    assert(mkdtemp(dir));
    assert(!qihse_ct1_authority_store_initialize(dir));
    qihse_ct1_authority_store_t *s = NULL;
    qihse_ct1_authority_challenge_t a, b;
    assert(!qihse_ct1_authority_store_open(dir, &s));
    assert(!qihse_ct1_authority_store_issue(s, 900000, &a));
    qihse_ct1_authority_store_close(s);

    char path[256];
    snprintf(path, sizeof(path), "%s/authority.log", dir);
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    assert(fd >= 0 && !fstat(fd, &st) && st.st_size > 0);
    size_t size = (size_t)st.st_size;
    unsigned char *snapshot = malloc(size);
    assert(snapshot && read(fd, snapshot, size) == (ssize_t)size);
    assert(!close(fd));

    assert(!qihse_ct1_authority_store_open(dir, &s));
    assert(!qihse_ct1_authority_store_retire(s, &a));
    assert(qihse_ct1_authority_store_retire(s, &a) == -1);
    assert(!qihse_ct1_authority_store_issue(s, 900000, &b));
    assert(b.epoch == a.epoch + 1);
    assert(!qihse_ct1_authority_store_retire(s, &b));
    qihse_ct1_authority_store_close(s);

    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        /* A separate process with the same UID is NOT a trust boundary. Restore
         * exact bytes, without forging any record or recomputing any digest. */
        int restored = open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW);
        if (restored < 0 || write(restored, snapshot, size) != (ssize_t)size ||
            fsync(restored) || close(restored)) _exit(1);
        qihse_ct1_authority_store_t *child = NULL;
        if (qihse_ct1_authority_store_open(dir, &child) ||
            qihse_ct1_authority_store_retire(child, &a) ||
            qihse_ct1_authority_store_retire(child, &a) != -1) _exit(1);
        qihse_ct1_authority_store_close(child);
        _exit(0);
    }
    child_exit_ok(pid);
    free(snapshot);
    assert(!qihse_ct1_authority_store_open(dir, &s));
    assert(qihse_ct1_authority_store_retire(s, &a) == -1);
    assert(!qihse_ct1_authority_store_issue(s, 900000, &a));
    assert(a.epoch == b.epoch); /* Even a previously used epoch returns. */
    assert(!qihse_ct1_authority_store_retire(s, &a));
    qihse_ct1_authority_store_close(s);
    remove_fixture(dir);
    puts("intact older ledger: same-UID rollback/replay accepted; NOT authorization");
}

static void permissions(void)
{
    char dir[] = "./ct1-host-perms-XXXXXX";
    assert(mkdtemp(dir));
    assert(chmod(dir, 0700) == 0);
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_initialize(dir));
    assert(!qihse_ct1_authority_store_open(dir, &s));
    qihse_ct1_authority_challenge_t challenge;
    assert(!qihse_ct1_authority_store_issue(s, 900000, &challenge));
    if (geteuid() != 0) {
        puts("SKIP wrong-uid fixture: requires root to drop to a distinct uid");
    } else {
        struct passwd *pw = getpwnam("nobody");
        if (!pw || pw->pw_uid == geteuid()) {
            puts("SKIP wrong-uid fixture: distinct unprivileged uid unavailable");
        } else {
            pid_t pid = fork();
            assert(pid >= 0);
            if (!pid) {
                if (setgroups(0, NULL) || setgid(pw->pw_gid) || setuid(pw->pw_uid)) _exit(77);
                qihse_ct1_authority_store_t *other = NULL;
                char path[256];
                snprintf(path, sizeof(path), "%s/authority.log", dir);
                int fd = open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW);
                if (fd >= 0) { close(fd); _exit(1); }
                if (errno != EACCES) _exit(1);
                if (qihse_ct1_authority_store_open(dir, &other) != -1 || other) _exit(1);
                if (qihse_ct1_authority_store_initialize(dir) != -1) _exit(1);
                qihse_ct1_authority_challenge_t issued;
                /* A handle inherited from the host is not an identity bypass. */
                if (qihse_ct1_authority_store_issue(s, 1000, &issued) != -1 ||
                    qihse_ct1_authority_store_retire(s, &challenge) != -1) _exit(1);
                if (!chmod(dir, 0777) || !unlink(path)) _exit(1);
                if (!rename(path, "./ct1-host-displaced")) _exit(1);
                _exit(0);
            }
            int status;
            assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
            if (WEXITSTATUS(status) == 77) puts("SKIP wrong-uid fixture: could not drop credentials");
            else {
                assert(WEXITSTATUS(status) == 0);
                puts("distinct-UID process: path mutation and inherited ledger handle denied");
            }
        }
    }
    /* A denied foreign-UID attempt must not consume or modify host state. */
    assert(!qihse_ct1_authority_store_retire(s, &challenge));
    qihse_ct1_authority_store_close(s);
    remove_fixture(dir);
}

typedef struct {
    unsigned char *bytes;
    size_t size;
} snapshot_t;

static snapshot_t snapshot_file(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    assert(fd >= 0 && !fstat(fd, &st) && st.st_size > 0);
    snapshot_t image = { malloc((size_t)st.st_size), (size_t)st.st_size };
    assert(image.bytes && read(fd, image.bytes, image.size) == (ssize_t)image.size);
    assert(!close(fd));
    return image;
}

static void restore_file(const char *path, snapshot_t image)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW);
    assert(fd >= 0 && write(fd, image.bytes, image.size) == (ssize_t)image.size);
    assert(!fsync(fd) && !close(fd));
}

static void strict_checkpoint(void)
{
    /* Unprivileged runs still exercise a full-size torn ledger head, not just
     * a partial append. Strict mode must NEVER degrade to a same-UID fixture. */
    char torn[] = "./ct1-head-XXXXXX";
    assert(mkdtemp(torn));
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_initialize(torn));
    char path[512];
    snprintf(path, sizeof(path), "%s/authority.log", torn);
    snapshot_t image = snapshot_file(path);
    image.bytes[image.size - 1] ^= 1;
    restore_file(path, image);
    free(image.bytes);
    assert(qihse_ct1_authority_store_open(torn, &s) == -1 && !s);
    assert(qihse_ct1_authority_store_initialize_strict(torn, torn, geteuid()) == -1);
    assert(qihse_ct1_authority_store_open_strict(torn, torn, geteuid(), &s) == -1 && !s);
    remove_fixture(torn);
    puts("full-size torn ledger head: denied (all UIDs)");
    if (geteuid() != 0) {
        puts("SKIP strict root checkpoint/distinct-UID fixtures: requires root");
        return;
    }
    struct passwd *pw = getpwnam("nobody");
    assert(pw && pw->pw_uid != 0);
    uid_t b_uid = pw->pw_uid;
    gid_t b_gid = pw->pw_gid;
    for (int cut = 0; cut < 13; ++cut) {
        char ledger[] = "./ct1-strict-ledger-XXXXXX";
        char anchor[] = "./ct1-strict-anchor-XXXXXX";
        assert(mkdtemp(ledger) && mkdtemp(anchor));
        assert(!chmod(ledger, 0700) && !chmod(anchor, 0700));
        assert(qihse_ct1_authority_store_initialize_strict(ledger, ledger, b_uid) == -1);
        if (cut == 0) {
            char nested[512], alias[512];
            snprintf(nested, sizeof(nested), "%s/nested", ledger);
            snprintf(alias, sizeof(alias), "%s/alias", ledger);
            assert(!mkdir(nested, 0700));
            assert(qihse_ct1_authority_store_initialize_strict(ledger, nested, b_uid) == -1);
            assert(qihse_ct1_authority_store_initialize_strict(nested, ledger, b_uid) == -1);
            assert(!rmdir(nested));
            assert(!symlink("../missing", alias));
            assert(qihse_ct1_authority_store_initialize_strict(alias, anchor, b_uid) == -1);
            assert(!unlink(alias));
        }
        assert(qihse_ct1_authority_store_initialize_strict(ledger, anchor, 0) == -1);
        assert(qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &s) == -1 && !s);
        assert(!qihse_ct1_authority_store_initialize_strict(ledger, anchor, b_uid));
        assert(qihse_ct1_authority_store_initialize_strict(ledger, anchor, b_uid) == -1);
        assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &s));
        qihse_ct1_authority_challenge_t a, b;
        assert(!qihse_ct1_authority_store_issue(s, 900000, &a));
        char log[512], cp[512], extra[512];
        snprintf(log, sizeof(log), "%s/authority.log", ledger);
        snprintf(cp, sizeof(cp), "%s/authority.checkpoint", anchor);
        snprintf(extra, sizeof(extra), "%s/extra", anchor);
        snapshot_t old_log = snapshot_file(log), old_cp = snapshot_file(cp);
        assert(!qihse_ct1_authority_store_retire(s, &a));
        assert(!qihse_ct1_authority_store_issue(s, 900000, &b));
        assert(b.epoch == a.epoch + 1 && memcmp(a.nonce, b.nonce, 32));
        assert(!qihse_ct1_authority_store_retire(s, &b));
        qihse_ct1_authority_store_close(s);
        assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &s));
        assert(qihse_ct1_authority_store_retire(s, &a) == -1);
        if (cut == 0) {
            /* Actual B credentials cannot touch either root-owned domain, or
             * operate inherited root handles. No production account is changed. */
            pid_t pid = fork();
            assert(pid >= 0);
            if (!pid) {
                if (setgroups(0, NULL) || setgid(b_gid) || setuid(b_uid)) _exit(2);
                int fd = open(cp, O_WRONLY | O_TRUNC | O_NOFOLLOW);
                if (fd >= 0 || errno != EACCES) _exit(3);
                fd = open(log, O_WRONLY | O_TRUNC | O_NOFOLLOW);
                if (fd >= 0 || errno != EACCES) _exit(4);
                if (!unlink(cp) || !rename(anchor, extra) || !chmod(anchor, 0777)) _exit(5);
                qihse_ct1_authority_store_t *other = NULL;
                if (qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &other) != -1 ||
                    qihse_ct1_authority_store_issue(s, 1000, &a) != -1 ||
                    qihse_ct1_authority_store_retire(s, &b) != -1) _exit(6);
                _exit(0);
            }
            child_exit_ok(pid);
            puts("strict root authority/B distinct UID: mutation and inherited handles denied");
            restore_file(log, old_log); /* Exact complete intact retired prefix. */
            /* In the rolled-back prefix a is outstanding: retire must compare
             * the independent head BEFORE accepting that formerly used nonce. */
            assert(qihse_ct1_authority_store_retire(s, &a) == -1);
            snapshot_t unchanged = snapshot_file(log);
            assert(unchanged.size == old_log.size &&
                   !memcmp(unchanged.bytes, old_log.bytes, old_log.size));
            free(unchanged.bytes);
        } else if (cut == 1) {
            /* Durable newer ledger, old checkpoint: crash before checkpoint. */
            restore_file(cp, old_cp);
        } else if (cut == 2) {
            assert(!truncate(cp, (off_t)old_cp.size - 1));
        } else if (cut == 3) {
            old_cp.bytes[old_cp.size - 1] ^= 1;
            restore_file(cp, old_cp);
        } else if (cut == 4) {
            assert(!unlink(cp));
        } else if (cut == 5) {
            assert(!link(cp, extra));
        } else if (cut == 6) {
            assert(!unlink(cp) && !symlink("missing", cp));
        } else if (cut == 7) {
            assert(!chmod(cp, 0644));
        } else if (cut == 8) {
            assert(!chmod(anchor, 0777));
        } else if (cut == 9) {
            /* Stable file identity is checked even if bytes are unchanged. */
            assert(!rename(cp, extra));
            int fd = open(cp, O_CREAT | O_EXCL | O_WRONLY, 0600);
            assert(fd >= 0 && !close(fd));
        } else if (cut == 10) {
            assert(!chown(cp, b_uid, b_gid));
        } else if (cut == 11) {
            assert(!chown(anchor, b_uid, b_gid));
        } else {
            snapshot_t head = snapshot_file(log);
            head.bytes[head.size - 1] ^= 1;
            restore_file(log, head);
            free(head.bytes);
        }
        assert(qihse_ct1_authority_store_issue(s, 1000, &a) == -1);
        assert(qihse_ct1_authority_store_retire(s, &a) == -1);
        qihse_ct1_authority_store_close(s);
        s = NULL;
        assert(qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &s) == -1 && !s);
        assert(qihse_ct1_authority_store_initialize_strict(ledger, anchor, b_uid) == -1);
        free(old_log.bytes);
        free(old_cp.bytes);
        /* Only disposable test-created paths are repaired for removal. */
        assert(!chown(anchor, 0, 0) && !chmod(anchor, 0700));
        unlink(cp);
        unlink(extra);
        assert(!rmdir(anchor));
        remove_fixture(ledger);
    }
    puts("strict checkpoint: intact rollback, both head cuts, missing/torn/link/owner/mode denial PASS");
}

static void manifest_roster(qihse_ct1_recovery_file_t *files,
                            const char *const *names, const uint8_t *kinds, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        strcpy(files[i].filename, names[i]);
        files[i].kind = kinds[i];
        files[i].size = kinds[i] == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 : 100 + i;
        if (!files[i].size) assert(SHA256((const unsigned char *)"", 0, files[i].sha256));
        else memset(files[i].sha256, (int)(i + 1), 32);
    }
}

static void make_manifest(const qihse_ct1_authority_challenge_t *c,
                          unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE])
{
    static const char *const source[] = {"ct-baseline.qfs", "ct-state.bin",
        "restore-highwater.bin", "slot-ownership.journal",
        "slot-ownership.journal.lock", "sstable_1.db", "sstable_2.db", "wal.log"};
    static const uint8_t sk[] = {3, 2, 6, 7, 8, 4, 4, 1};
    static const char *const target[] = {"ct-state.bin", "restore-highwater.bin",
        "slot-ownership.journal", "slot-ownership.journal.lock",
        "sstable_1.db", "sstable_2.db", "wal.log"};
    static const uint8_t tk[] = {2, 6, 7, 8, 4, 4, 1};
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator"); strcpy(m.source_qkp_id, "source");
    strcpy(m.target_qkp_id, "target"); strcpy(m.generation, "generation");
    strcpy(m.source_store_id, "source-store");
    strcpy(m.target_store_id, "target-store");
    strcpy(m.replication_principal_id, "replication");
    strcpy(m.row_key, "row");
    strcpy(m.source_peer_qkp_id, "source-peer");
    strcpy(m.target_peer_qkp_id, "target-peer");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32); memset(m.target_peer_pin, 3, 32);
    memset(m.frame_sha256, 4, 32); memset(m.baseline_sha256, 5, 32);
    manifest_roster(m.source_files, source, sk, 8);
    manifest_roster(m.target_files, target, tk, 7);
    memcpy(m.nonce, c->nonce, 32);
    m.epoch = c->epoch; m.issued_ms = c->issued_ms; m.expires_ms = c->expires_ms;
    m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 11111; m.target_cursor = 11110;
    m.baseline_row_seq = 17; m.target_high_water = 5729457;
    m.source_high_water = 5729448; m.row_change_seq = 5729448;
    m.tombstone_position = 11103; m.tombstone_row_seq = 5729450;
    m.row_tenant_id = 42; m.principal_tenant_id = 42;
    m.classification = 4; m.sci = 2;
    m.principal_classification = 4; m.principal_sci = 2;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
}

#ifdef QIHSE_CT1_TEST_CRASH_CUT
static void bound_crash_cuts(void)
{
    if (geteuid() != 0) {
        puts("SKIP strict bind/retire crash cuts: requires root");
        return;
    }
    struct passwd *pw = getpwnam("nobody");
    assert(pw && pw->pw_uid != 0);
    for (int retire = 0; retire < 2; ++retire) {
        for (int cut = 0; cut <= 8; ++cut) {
            char ledger[] = "./ct1-bound-cut-ledger-XXXXXX";
            char anchor[] = "./ct1-bound-cut-anchor-XXXXXX";
            char cp[512];
            assert(mkdtemp(ledger) && mkdtemp(anchor));
            assert(!qihse_ct1_authority_store_initialize_strict(ledger, anchor, pw->pw_uid));
            qihse_ct1_authority_store_t *s = NULL;
            assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s));
            qihse_ct1_authority_challenge_t challenge, next;
            unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
            assert(!qihse_ct1_authority_store_issue(s, 900000, &challenge));
            make_manifest(&challenge, wire);
            if (retire) assert(!qihse_ct1_authority_store_bind(s, &challenge, wire, sizeof(wire)));
            snprintf(cp, sizeof(cp), "%s/authority.checkpoint", anchor);
            snapshot_t before = snapshot_file(cp);
            pid_t pid = fork();
            assert(pid >= 0);
            if (!pid) {
                char selected[] = "b0";
                selected[0] = retire ? 'r' : 'b';
                selected[1] = (char)('0' + cut);
                if (setenv("QIHSE_CT1_TEST_CRASH_CUT", selected, 1)) _exit(70);
                if (retire) (void)qihse_ct1_authority_store_retire_bound(s, &challenge,
                                                                            wire, sizeof(wire));
                else (void)qihse_ct1_authority_store_bind(s, &challenge, wire, sizeof(wire));
                _exit(70); /* The selected cut must fire before the call returns. */
            }
            int status;
            assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
            assert(WEXITSTATUS(status) == 90 + cut);
            if (cut == 5 || cut == 6) {
                /* _exit does not undo a full pwrite. Separately model an old
                 * or torn checkpoint image at the pre-durability boundary. */
                snapshot_t head = snapshot_file(cp);
                if (cut == 5) restore_file(cp, before);
                else {
                    head.bytes[head.size - 1] ^= 1;
                    restore_file(cp, head);
                }
                free(head.bytes);
            }
            free(before.bytes);
            if (cut >= 1 && cut <= 6) {
                assert(qihse_ct1_authority_store_bind(s, &challenge, wire, sizeof(wire)) == -1);
                assert(qihse_ct1_authority_store_retire_bound(s, &challenge, wire, sizeof(wire)) == -1);
                assert(qihse_ct1_authority_store_retire(s, &challenge) == -1);
                assert(qihse_ct1_authority_store_issue(s, 900000, &next) == -1);
                qihse_ct1_authority_store_close(s);
                s = NULL;
                assert(qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s) == -1 && !s);
                assert(qihse_ct1_authority_store_initialize_strict(ledger, anchor, pw->pw_uid) == -1);
            } else {
                qihse_ct1_authority_store_close(s);
                s = NULL;
                assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s));
                if (!retire && cut == 0)
                    assert(!qihse_ct1_authority_store_bind(s, &challenge, wire, sizeof(wire)));
                if (retire && cut == 0)
                    assert(!qihse_ct1_authority_store_retire_bound(s, &challenge, wire, sizeof(wire)));
                if (!retire) {
                    assert(qihse_ct1_authority_store_bind(s, &challenge, wire, sizeof(wire)) == -1);
                    assert(qihse_ct1_authority_store_retire(s, &challenge) == -1);
                    assert(!qihse_ct1_authority_store_retire_bound(s, &challenge, wire, sizeof(wire)));
                }
                assert(qihse_ct1_authority_store_retire_bound(s, &challenge, wire, sizeof(wire)) == -1);
                assert(qihse_ct1_authority_store_bind(s, &challenge, wire, sizeof(wire)) == -1);
                assert(!qihse_ct1_authority_store_issue(s, 900000, &next));
                assert(next.epoch == challenge.epoch + 1 &&
                       memcmp(next.nonce, challenge.nonce, sizeof(next.nonce)));
                assert(qihse_ct1_authority_store_retire_bound(s, &challenge, wire, sizeof(wire)) == -1);
                qihse_ct1_authority_store_close(s);
            }
            assert(!unlink(cp) && !rmdir(anchor));
            remove_fixture(ledger);
        }
    }
    puts("strict bind/retire process-death cuts: mismatched/torn heads deny; matching heads replay-safe (no grant)");
}
#endif

static void strict_manifest_binding(void)
{
    if (geteuid() != 0) {
        assert(qihse_ct1_authority_store_bind(NULL, NULL, NULL, 0) == -1);
        puts("SKIP strict manifest binding: requires root");
        return;
    }
    struct passwd *pw = getpwnam("nobody");
    assert(pw && pw->pw_uid != 0);
    for (int cut = 0; cut < 5; ++cut) {
        char ledger[] = "./ct1-bound-ledger-XXXXXX";
        char anchor[] = "./ct1-bound-anchor-XXXXXX";
        assert(mkdtemp(ledger) && mkdtemp(anchor));
        assert(!qihse_ct1_authority_store_initialize_strict(ledger, anchor, pw->pw_uid));
        qihse_ct1_authority_store_t *s = NULL;
        assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s));
        qihse_ct1_authority_challenge_t c, wrong;
        assert(!qihse_ct1_authority_store_issue(s, 900000, &c));
        unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE], altered[sizeof(wire)];
        make_manifest(&c, wire);
        qihse_ct1_recovery_manifest_t m;
        assert(qihse_ct1_recovery_decode(wire, sizeof(wire), false, &m, NULL));
        m.frame_sha256[0] ^= 1;
        assert(qihse_ct1_recovery_encode(&m, false, false, altered));
        wrong = c; wrong.nonce[0] ^= 1;
        assert(qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)) == -1);
        assert(qihse_ct1_authority_store_bind(s, &wrong, wire, sizeof(wire)) == -1);
        assert(qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire) - 1) == -1);
        memcpy(altered, wire, sizeof(wire)); altered[8] = 2;
        assert(qihse_ct1_authority_store_bind(s, &c, altered, sizeof(altered)) == -1);
        char log[512], cp[512];
        snprintf(log, sizeof(log), "%s/authority.log", ledger);
        snprintf(cp, sizeof(cp), "%s/authority.checkpoint", anchor);
        snapshot_t old_log = snapshot_file(log), old_cp = snapshot_file(cp);
        assert(!qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire)));
        assert(qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire)) == -1);
        assert(qihse_ct1_authority_store_retire(s, &c) == -1);
        assert(qihse_ct1_recovery_encode(&m, false, false, altered));
        assert(qihse_ct1_authority_store_bind(s, &c, altered, sizeof(altered)) == -1);
        assert(qihse_ct1_authority_store_retire_bound(s, &c, altered, sizeof(altered)) == -1);
        if (cut == 0) {
            pid_t pid = fork();
            assert(pid >= 0);
            if (!pid) {
                if (setgroups(0, NULL) || setgid(pw->pw_gid) ||
                    setuid(pw->pw_uid)) _exit(1);
                if (qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire)) != -1 ||
                    qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)) != -1)
                    _exit(1);
                _exit(0);
            }
            child_exit_ok(pid);
            qihse_ct1_authority_store_close(s);
            assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s));
            assert(!qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)));
            assert(qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)) == -1);
            assert(qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire)) == -1);
            qihse_ct1_authority_challenge_t next;
            assert(!qihse_ct1_authority_store_issue(s, 900000, &next));
            assert(next.epoch == c.epoch + 1 && memcmp(next.nonce, c.nonce, 32));
            assert(qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)) == -1);
            assert(!qihse_ct1_authority_store_retire(s, &next));
            assert(!qihse_ct1_authority_store_issue(s, 1, &next));
            make_manifest(&next, wire);
            struct timespec delay = {0, 10000000};
            assert(!nanosleep(&delay, NULL));
            assert(qihse_ct1_authority_store_bind(s, &next, wire, sizeof(wire)) == -1);
            assert(qihse_ct1_authority_store_retire_bound(s, &next, wire, sizeof(wire)) == -1);
        } else if (cut == 1) restore_file(log, old_log);
        else if (cut == 2) restore_file(cp, old_cp);
        else if (cut == 3) assert(!truncate(log, (off_t)old_log.size + 1));
        else assert(!truncate(cp, (off_t)old_cp.size - 1));
        if (cut) {
            assert(qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)) == -1);
            qihse_ct1_authority_store_close(s);
            s = NULL;
            assert(qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s) == -1 && !s);
        } else qihse_ct1_authority_store_close(s);
        free(old_log.bytes); free(old_cp.bytes);
        assert(!unlink(cp) && !rmdir(anchor));
        remove_fixture(ledger);
    }
    puts("strict canonical B binding: replay, alteration, rollback, torn cuts denied (no grant)");
}

static void read_only_bound_check(void)
{
    assert(qihse_ct1_authority_store_check_bound(NULL, NULL, NULL, 0) == -1);
    char legacy[] = "./ct1-check-legacy-XXXXXX";
    assert(mkdtemp(legacy));
    assert(!qihse_ct1_authority_store_initialize(legacy));
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_open(legacy, &s));
    qihse_ct1_authority_challenge_t c;
    assert(!qihse_ct1_authority_store_issue(s, 900000, &c));
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    make_manifest(&c, wire);
    assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
    qihse_ct1_authority_store_close(s);
    remove_fixture(legacy);
    if (geteuid() != 0) {
        puts("SKIP read-only bound strict-root fixtures: requires root");
        return;
    }
    struct passwd *pw = getpwnam("nobody");
    assert(pw && pw->pw_uid != 0);
    for (int cut = 0; cut < 4; ++cut) {
        char ledger[] = "./ct1-check-ledger-XXXXXX";
        char anchor[] = "./ct1-check-anchor-XXXXXX";
        char log[512], cp[512];
        assert(mkdtemp(ledger) && mkdtemp(anchor));
        assert(!qihse_ct1_authority_store_initialize_strict(ledger, anchor, pw->pw_uid));
        assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s));
        assert(!qihse_ct1_authority_store_issue(s, 900000, &c));
        make_manifest(&c, wire);
        assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
        snprintf(log, sizeof(log), "%s/authority.log", ledger);
        snprintf(cp, sizeof(cp), "%s/authority.checkpoint", anchor);
        assert(!qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire)));
        snapshot_t bound_log = snapshot_file(log), bound_cp = snapshot_file(cp);
        assert(!qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)));
        snapshot_t unchanged = snapshot_file(log);
        assert(unchanged.size == bound_log.size &&
               !memcmp(unchanged.bytes, bound_log.bytes, bound_log.size));
        free(unchanged.bytes);
        unchanged = snapshot_file(cp);
        assert(unchanged.size == bound_cp.size &&
               !memcmp(unchanged.bytes, bound_cp.bytes, bound_cp.size));
        free(unchanged.bytes);
        qihse_ct1_authority_challenge_t wrong = c;
        wrong.nonce[0] ^= 1;
        assert(qihse_ct1_authority_store_check_bound(s, &wrong, wire, sizeof(wire)) == -1);
        wrong = c; wrong.epoch++;
        assert(qihse_ct1_authority_store_check_bound(s, &wrong, wire, sizeof(wire)) == -1);
        unsigned char altered[sizeof(wire)];
        qihse_ct1_recovery_manifest_t m;
        assert(qihse_ct1_recovery_decode(wire, sizeof(wire), false, &m, NULL));
        m.frame_sha256[0] ^= 1;
        assert(qihse_ct1_recovery_encode(&m, false, false, altered));
        assert(qihse_ct1_authority_store_check_bound(s, &c, altered, sizeof(altered)) == -1);
        assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire) - 1) == -1);
        if (cut == 0) {
            pid_t pid = fork();
            assert(pid >= 0);
            if (!pid) {
                if (setgroups(0, NULL) || setgid(pw->pw_gid) || setuid(pw->pw_uid)) _exit(2);
                _exit(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1 ? 0 : 3);
            }
            child_exit_ok(pid);
            assert(!qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)));
            assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
            qihse_ct1_authority_challenge_t next;
            assert(!qihse_ct1_authority_store_issue(s, 900000, &next));
            assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
            assert(next.epoch != c.epoch && memcmp(next.nonce, c.nonce, 32));
        } else if (cut == 1) {
            assert(!qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)));
            restore_file(log, bound_log); /* Intact bound prefix; checkpoint is newer. */
            assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
        } else if (cut == 2) {
            assert(!qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)));
            restore_file(cp, bound_cp); /* New ledger, old independent head. */
            assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
        } else {
            assert(!qihse_ct1_authority_store_retire_bound(s, &c, wire, sizeof(wire)));
            restore_file(log, bound_log);
            restore_file(cp, bound_cp); /* Both restored: outside local trust model. */
            assert(!qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)));
        }
        qihse_ct1_authority_store_close(s);
        free(bound_log.bytes); free(bound_cp.bytes);
        assert(!unlink(cp) && !rmdir(anchor));
        remove_fixture(ledger);
    }
    /* Expiry uses host time even if no clock record has been appended. */
    char ledger[] = "./ct1-check-expire-ledger-XXXXXX";
    char anchor[] = "./ct1-check-expire-anchor-XXXXXX";
    assert(mkdtemp(ledger) && mkdtemp(anchor));
    assert(!qihse_ct1_authority_store_initialize_strict(ledger, anchor, pw->pw_uid));
    assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, pw->pw_uid, &s));
    assert(!qihse_ct1_authority_store_issue(s, 100, &c));
    make_manifest(&c, wire);
    assert(!qihse_ct1_authority_store_bind(s, &c, wire, sizeof(wire)));
    struct timespec delay = {0, 150000000};
    assert(!nanosleep(&delay, NULL));
    assert(qihse_ct1_authority_store_check_bound(s, &c, wire, sizeof(wire)) == -1);
    qihse_ct1_authority_store_close(s);
    char path[512];
    snprintf(path, sizeof(path), "%s/authority.checkpoint", anchor);
    assert(!unlink(path) && !rmdir(anchor));
    remove_fixture(ledger);
    puts("strict read-only bound check: live/retired/expired/altered/rollback/UID denial PASS");
}

int main(void)
{
#ifdef QIHSE_CT1_TEST_CRASH_CUT
    assert(!unsetenv("QIHSE_CT1_TEST_CRASH_CUT"));
#endif
    lifecycle();
    concurrent_issue();
    crash_cuts();
    deleted_state();
    path_guards();
    intact_older_snapshot();
    permissions();
    strict_checkpoint();
    strict_manifest_binding();
    read_only_bound_check();
#ifdef QIHSE_CT1_TEST_CRASH_CUT
    bound_crash_cuts();
#endif
    puts("ct1 legacy ledger + strict independent checkpoint: PASS (no grant)");
    return 0;
}
