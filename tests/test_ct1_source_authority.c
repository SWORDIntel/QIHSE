#include "qihse_ct1_source_authority.h"

#include <assert.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const names[8] = {
    "ct-baseline.qfs", "ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_0.db", "sstable_1.db", "wal.log"
};
static const char *const targets[7] = {
    "ct-state.bin", "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_0.db", "sstable_1.db", "wal.log"
};

static void put64(unsigned char *p, uint64_t n)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(n >> (56u - 8u*i));
}

static void roster(const char *dir, qihse_ct1_recovery_file_t *files,
                   const char *const *list, size_t count,
                   const unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES])
{
    for (size_t i = 0; i < count; ++i) {
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, list[i]);
        assert(n > 0 && (size_t)n < sizeof(path));
        const unsigned char *bytes = !strcmp(list[i], "wal.log") ? frame :
            (const unsigned char *)"fixture";
        size_t len = !strcmp(list[i], "wal.log") ?
            QIHSE_CT1_RECOVERY_FRAME_BYTES :
            strstr(list[i], ".lock") ? 0u : 7u;
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0 && write(fd, bytes, len) == (ssize_t)len && !close(fd));
        strcpy(files[i].filename, list[i]);
        files[i].size = len;
        assert(SHA256(bytes, len, files[i].sha256));
        files[i].kind = !strcmp(list[i], "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(list[i], "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(list[i], "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(list[i], "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(list[i], "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(list[i], "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
    }
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    if (geteuid() != 0) {
        puts("SKIP source ownership fixture: root required");
        return 0;
    }
    char *base = realpath(argv[1], NULL);
    char original[512], copy[512], target[512], audit[512], wal_path[512];
    char stage_parent[512], staged[512], staged_wal[512], alias[512], cut[512];
    char leased[512], leased_wal[512];
    assert(base && snprintf(original, sizeof(original), "%s/original", base) > 0);
    assert(snprintf(copy, sizeof(copy), "%s/copy", base) > 0);
    assert(snprintf(target, sizeof(target), "%s/target", base) > 0);
    assert(snprintf(audit, sizeof(audit), "%s/audit", base) > 0);
    assert(snprintf(stage_parent, sizeof(stage_parent), "%s/staging-parent", base) > 0);
    assert(snprintf(staged, sizeof(staged), "%s/fresh", stage_parent) > 0);
    assert(snprintf(staged_wal, sizeof(staged_wal), "%s/wal.log", staged) > 0);
    assert(snprintf(alias, sizeof(alias), "%s/staging-alias", base) > 0);
    assert(snprintf(cut, sizeof(cut), "%s/crash-cut", stage_parent) > 0);
    assert(snprintf(leased, sizeof(leased), "%s/leased", stage_parent) > 0);
    assert(snprintf(leased_wal, sizeof(leased_wal), "%s/wal.log", leased) > 0);
    assert(!mkdir(original, 0700) && !mkdir(copy, 0700) &&
        !mkdir(target, 0700) && !mkdir(audit, 0700) &&
        !mkdir(stage_parent, 0700));
    assert(!setenv("QIHSE_DATA_DIR", audit, 1));
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("Ct1OfflineOperatorFixture!"));
    qihse_user_t *operator_user = qihse_auth_get_user(0);
    assert(operator_user);
    assert(qihse_auth_create_user(operator_user, 8302, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, "Ct1OfflineServiceFixture!", false));
    assert(qihse_auth_create_user(operator_user, 8303, QIHSE_ROLE_ANALYST,
        0, 0, "Ct1OfflineLowFixture!", false));
    qihse_user_t *service = qihse_auth_get_user(8302);
    qihse_user_t *low = qihse_auth_get_user(8303);
    assert(service && low);

    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES] = {0};
    memcpy(frame, "QKV6CT01", 8);
    frame[8] = 1;
    put64(frame + 32, 11111);
    put64(frame + 40, 5729448);
    put64(frame + 48, 5729448);
    frame[56] = 6; frame[57] = 10;
    memcpy(frame + 96, "source", 6);
    memcpy(frame + 102, "generation", 10);

    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.source_peer_qkp_id, "target"); strcpy(m.target_peer_qkp_id, "source");
    strcpy(m.source_store_id, "source"); strcpy(m.target_store_id, "target");
    strcpy(m.generation, "generation"); strcpy(m.replication_principal_id, "8302");
    strcpy(m.row_key, "pending-row");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32); memset(m.target_peer_pin, 3, 32);
    memset(m.baseline_sha256, 4, 32); memset(m.nonce, 5, 32);
    assert(SHA256(frame, sizeof(frame), m.frame_sha256));
    m.epoch = 1; m.issued_ms = 1; m.expires_ms = 500;
    m.frame_length = sizeof(frame); m.frame_position = 11111;
    m.target_cursor = 11110; m.target_high_water = 5729457;
    m.source_high_water = 5729448; m.row_change_seq = 5729448;
    m.tombstone_position = 11103; m.tombstone_row_seq = 5729450;
    m.principal_classification = UINT16_MAX; m.principal_sci = UINT16_MAX;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    roster(original, m.source_files, names, 8, frame);
    qihse_ct1_recovery_file_t duplicate[8];
    roster(copy, duplicate, names, 8, frame);
    roster(target, m.target_files, targets, 7, frame);
    struct stat original_st, copy_st, stage_parent_st;
    assert(!stat(original, &original_st) && !stat(copy, &copy_st) &&
        !stat(stage_parent, &stage_parent_st));
    assert(copy_st.st_ino != original_st.st_ino);
    assert(qihse_ct1_recovery_verify_frozen(service, copy, &m, true));
#define PROBE(dir, dev, ino, op, svc, id) qihse_ct1_source_authority_probe_offline( \
    (dir), (dev), (ino), (op), (svc), (id), &m)
#define STAGE(dir, dev, ino, parent, pdev, pino, name, op, svc) \
    qihse_ct1_source_authority_stage_offline((dir), (dev), (ino), \
        (parent), (pdev), (pino), (name), (op), (svc), 8302, &m)
#define VERIFY_STAGE(dir, dev, ino, parent, pdev, pino, name, sdev, sino, op, svc) \
    qihse_ct1_source_authority_verify_stage_offline((dir), (dev), (ino), \
        (parent), (pdev), (pino), (name), (sdev), (sino), (op), (svc), 8302, &m)
    assert(PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    assert(!PROBE(copy, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, low, 8302)); /* low clearance, no protected read */
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        low, service, 8302)); /* no Operator */
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8303));
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        NULL, service, 8302));
    int lock = open(original, O_RDONLY | O_DIRECTORY);
    assert(lock >= 0 && !flock(lock, LOCK_EX | LOCK_NB));
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    assert(!close(lock));
    m.frame_position = 11103;
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    m.frame_position = 11111;
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log", original) > 0);
    int fd = open(wal_path, O_RDWR);
    assert(fd >= 0);
    unsigned char wrong = 0;
    assert(pwrite(fd, &wrong, 1, 39) == 1 && !close(fd));
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    fd = open(wal_path, O_RDWR);
    assert(fd >= 0 && pwrite(fd, frame + 39, 1, 39) == 1 && !close(fd));
    assert(PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    struct passwd *b = getpwnam("nobody");
    assert(b && b->pw_uid && b->pw_uid != 8302);
    assert(!chown(wal_path, b->pw_uid, b->pw_gid));
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302)); /* B-owned inode denied */
    /* chown does not revoke an FD opened by B. Even a subsequently passing
     * offline probe MUST NOT be used as live exclusive ownership evidence. */
    assert(!chmod(base, 0711) && !chown(original, b->pw_uid, b->pw_gid));
    int to_b[2], from_b[2];
    assert(!pipe(to_b) && !pipe(from_b));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        close(to_b[1]); close(from_b[0]);
        if (setgid(b->pw_gid) || setuid(b->pw_uid)) _exit(1);
        int held = open(wal_path, O_WRONLY);
        if (held < 0 || write(from_b[1], "r", 1) != 1) _exit(2);
        char signal;
        if (read(to_b[0], &signal, 1) != 1 ||
            pwrite(held, "x", 1, 63) != 1 ||
            open(staged_wal, O_WRONLY) >= 0 ||
            open(leased_wal, O_WRONLY) >= 0 ||
            write(from_b[1], "w", 1) != 1) _exit(3);
        close(held);
        _exit(0);
    }
    close(to_b[0]); close(from_b[1]);
    char signal;
    assert(read(from_b[0], &signal, 1) == 1 && signal == 'r');
    assert(!chown(original, 0, 0) && !chown(wal_path, 0, 0));
    assert(PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302)); /* deliberately only an observation */
    assert(!STAGE(copy, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "wrong-original", operator_user, service));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "low-clearance", operator_user, low));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino + 1,
        "bad-parent-pin", operator_user, service));
    assert(!symlink(stage_parent, alias));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        alias, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "symlink-ancestor", operator_user, service));
    assert(!unlink(alias));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino + 1,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "stale-original-pin", operator_user, service));
    char extra[512];
    assert(snprintf(extra, sizeof(extra), "%s/wal-alias", stage_parent) > 0);
    assert(!link(wal_path, extra));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "hardlinked-source", operator_user, service));
    assert(!unlink(extra));
    assert(snprintf(extra, sizeof(extra), "%s/wal-saved", stage_parent) > 0);
    assert(!rename(wal_path, extra) && !symlink(extra, wal_path));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "symlinked-source", operator_user, service));
    assert(!unlink(wal_path) && !rename(extra, wal_path));
    fd = open(wal_path, O_WRONLY);
    assert(fd >= 0 && !ftruncate(fd, sizeof(frame) - 1) && !close(fd));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "short-source", operator_user, service));
    fd = open(wal_path, O_WRONLY);
    assert(fd >= 0 && pwrite(fd, frame, sizeof(frame), 0) ==
        (ssize_t)sizeof(frame) && !close(fd));
    assert(!mkdir(cut, 0700)); /* interrupted/partial stage cannot be resumed */
    assert(snprintf(extra, sizeof(extra), "%s/%s", cut, names[0]) > 0);
    fd = open(extra, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "fixture", 7) == 7 && !close(fd));
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "crash-cut", operator_user, service));
    struct stat cut_st;
    assert(!stat(cut, &cut_st));
    assert(!VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "crash-cut", cut_st.st_dev, cut_st.st_ino, operator_user, service));
    assert(STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", operator_user, service));
    assert(qihse_ct1_recovery_verify_frozen(service, staged, &m, true));
    struct stat staged_st, original_wal_st, staged_wal_st;
    assert(!stat(staged, &staged_st) && staged_st.st_ino != original_st.st_ino &&
        staged_st.st_uid == 0 && (staged_st.st_mode & 07777) == 0700);
    assert(VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, operator_user, service));
    assert(!VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino + 1, operator_user, service));
    assert(!VERIFY_STAGE(copy, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, operator_user, service));
    assert(!VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, operator_user, low));
    assert(!VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, low, service));
    assert(!stat(wal_path, &original_wal_st) &&
        !stat(staged_wal, &staged_wal_st) &&
        staged_wal_st.st_ino != original_wal_st.st_ino &&
        staged_wal_st.st_size == QIHSE_CT1_RECOVERY_FRAME_BYTES);
    for (size_t i = 0; i < 8; ++i) {
        char old_file[512], new_file[512];
        struct stat old_st, new_st;
        assert(snprintf(old_file, sizeof(old_file), "%s/%s", original, names[i]) > 0);
        assert(snprintf(new_file, sizeof(new_file), "%s/%s", staged, names[i]) > 0);
        assert(!stat(old_file, &old_st) && !stat(new_file, &new_st) &&
            (old_st.st_dev != new_st.st_dev || old_st.st_ino != new_st.st_ino) &&
            new_st.st_nlink == 1 && old_st.st_size == new_st.st_size);
    }
    assert(!STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", operator_user, service));
#define LEASE(name, password, id) qihse_ct1_source_fixture_lease_acquire( \
    original, original_st.st_dev, original_st.st_ino, stage_parent, \
    stage_parent_st.st_dev, stage_parent_st.st_ino, (name), (password), (id), &m)
    assert(!LEASE("wrong-password", "not-the-local-operator", 8302));
    assert(!LEASE("wrong-service", "Ct1OfflineOperatorFixture!", 8303));
    assert(!LEASE("stale-pin", "Ct1OfflineOperatorFixture!", 8302 + 1));
    assert(!LEASE("crash-cut", "Ct1OfflineOperatorFixture!", 8302));
    assert(!LEASE("../original", "Ct1OfflineOperatorFixture!", 8302));
    assert(!symlink(stage_parent, alias));
    assert(!qihse_ct1_source_fixture_lease_acquire(original,
        original_st.st_dev, original_st.st_ino, alias,
        stage_parent_st.st_dev, stage_parent_st.st_ino, "symlink-parent",
        "Ct1OfflineOperatorFixture!", 8302, &m));
    assert(!unlink(alias));
    assert(snprintf(extra, sizeof(extra), "%s/wal-lease-alias", stage_parent) > 0);
    assert(!link(wal_path, extra));
    assert(!LEASE("hardlink-alias", "Ct1OfflineOperatorFixture!", 8302));
    assert(!unlink(extra));
    qihse_ct1_source_fixture_lease_t *lease =
        LEASE("leased", "Ct1OfflineOperatorFixture!", 8302);
    assert(lease && !LEASE("leased", "Ct1OfflineOperatorFixture!", 8302));
    struct stat leased_st;
    assert(!stat(leased, &leased_st) && leased_st.st_uid == 0 &&
        leased_st.st_ino != original_st.st_ino &&
        leased_st.st_ino != staged_st.st_ino);
    int second = open(leased, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(second >= 0 && flock(second, LOCK_EX | LOCK_NB) != 0);
    assert(!close(second));
    assert(write(to_b[1], "g", 1) == 1);
    assert(read(from_b[0], &signal, 1) == 1 && signal == 'w');
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    assert(!close(to_b[1]) && !close(from_b[0]));
    assert(!PROBE(original, original_st.st_dev, original_st.st_ino,
        operator_user, service, 8302));
    assert(qihse_ct1_recovery_verify_frozen(service, staged, &m, true));
    assert(qihse_ct1_recovery_verify_frozen(service, leased, &m, true));
    second = open(leased, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(second >= 0 && flock(second, LOCK_EX | LOCK_NB) != 0);
    assert(!close(second));
    qihse_ct1_source_fixture_lease_destroy(lease);
    second = open(leased, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(second >= 0 && !flock(second, LOCK_EX | LOCK_NB) && !close(second));
    assert(VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, operator_user, service));
    fd = open(staged_wal, O_RDONLY);
    unsigned char staged_frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    assert(fd >= 0 && read(fd, staged_frame, sizeof(staged_frame)) ==
        (ssize_t)sizeof(staged_frame) && !memcmp(staged_frame, frame, sizeof(frame)) &&
        !close(fd));
    fd = open(staged_wal, O_WRONLY);
    assert(fd >= 0 && pwrite(fd, "x", 1, 63) == 1 && !close(fd));
    assert(!VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, operator_user, service));
    /* A matching roster/digest cannot turn a malformed physical frame into B. */
    frame[8] = 2;
    fd = open(staged_wal, O_WRONLY);
    assert(fd >= 0 && pwrite(fd, frame, sizeof(frame), 0) ==
        (ssize_t)sizeof(frame) && !close(fd));
    assert(SHA256(frame, sizeof(frame), m.frame_sha256));
    assert(SHA256(frame, sizeof(frame), m.source_files[7].sha256));
    assert(qihse_ct1_recovery_verify_frozen(service, staged, &m, true));
    assert(!VERIFY_STAGE(original, original_st.st_dev, original_st.st_ino,
        stage_parent, stage_parent_st.st_dev, stage_parent_st.st_ino,
        "fresh", staged_st.st_dev, staged_st.st_ino, operator_user, service));
    puts("CT1 root-fresh fixture lease: staged physical frame pinned, stale B FD isolated, crash-cut denied; no live B ownership or CT HOLD");
    free(base);
    return 0;
}
