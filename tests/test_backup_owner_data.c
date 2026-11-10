#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

static void restore_owner_data_child(const char* backup_path, const char* data_dir) {
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OwnerBackupOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "OwnerBackupOperator1!");
    assert(op);
    qihse_kv_store_t* restored = qihse_kv_store_create_user(op);
    assert(restored);
    char archive_dir[4096];
    assert(strlen(backup_path) < sizeof(archive_dir));
    memcpy(archive_dir, backup_path, strlen(backup_path) + 1u);
    char* archive_slash = strrchr(archive_dir, '/');
    assert(archive_slash);
    *archive_slash = '\0';
    /* Restore stages under the target data directory, so the source archive
     * need only be readable; its directory need not be writable. */
    assert(chmod(archive_dir, 0500) == 0);
    /* A CT-disabled target may contain an older image. Restore is an atomic
     * replacement, so callers need not manually empty/recreate the store. */
    assert(qihse_kv_set_user(restored, "stale/target", "discarded", 0u, 0u, op));
    assert(qihse_restore_user(restored, op, backup_path) == QIHSE_BACKUP_EXPORT_OK);
    assert(chmod(archive_dir, 0700) == 0);
    assert(qihse_kv_get_user(restored, "stale/target", op) == NULL);
    char* value = qihse_kv_get_user(restored, "aimem/current", op);
    assert(value && strcmp(value, "retained") == 0);
    free(value);
    value = qihse_kv_get_user(restored, "classified/sentinel", op);
    assert(value && strcmp(value, "protected") == 0);
    free(value);

    char delta_path[4096];
    int n = snprintf(delta_path, sizeof(delta_path), "%s/restore-delta.qfs", data_dir);
    assert(n > 0 && (size_t)n < sizeof(delta_path));
    uint64_t resume = 0u;
    assert(qihse_kv_save_delta_user(restored, delta_path, op, 0u, &resume) == 0);
    FILE* delta = fopen(delta_path, "rb");
    assert(delta);
    qihse_kv_store_t* detached = qihse_kv_open_snapshot_user(delta, op,
        128u * 1024u * 1024u, 10000u);
    fclose(delta);
    assert(detached);
    char* tombstone_value = NULL;
    qihse_kv_record_meta_t metadata = {0};
    assert(qihse_kv_snapshot_get_record_user(detached, "aimem/forget-target",
        op, &tombstone_value, &metadata));
    assert(tombstone_value && tombstone_value[0] == '\0' && (metadata.flags & 1u));
    free(tombstone_value);
    qihse_kv_store_destroy(detached);
    qihse_kv_store_destroy(restored);
    aimem_fixture_cleanup(data_dir);
}

int main(int argc, char** argv) {
    if (argc == 4 && strcmp(argv[1], "restore") == 0) {
        restore_owner_data_child(argv[2], argv[3]);
        return 0;
    }
    assert(argc == 1);
    char dir[] = "./backup_owner_data_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OwnerBackupOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "OwnerBackupOperator1!");
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 8401u, QIHSE_ROLE_ANALYST,
        0u, 0u, "OwnerBackupLow1!", false);
    assert(low);
    qihse_user_t* service = qihse_auth_create_user(op, 8402u, QIHSE_ROLE_ANALYST,
        5u, 2u, "OwnerBackupService1!", false);
    assert(service);

    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    assert(qihse_kv_set_user(store, "classified/sentinel", "protected", 5u, 2u, op));
    assert(qihse_auth_user_is_active(low));
    assert(qihse_kv_get_user(store, "classified/sentinel", low) == NULL);
    char null_save_path[4096];
    int nn = snprintf(null_save_path, sizeof(null_save_path), "%s/null-save.qfs", dir);
    assert(nn > 0 && (size_t)nn < sizeof(null_save_path));
    assert(qihse_kv_save_user(store, null_save_path, NULL) == -2);
    assert(access(null_save_path, F_OK) != 0);
    assert(qihse_kv_set_user(store, "aimem/forget-target", "old", 0u, 0u, op));
    qihse_user_t* high = qihse_auth_create_user(op, 8403u, QIHSE_ROLE_ANALYST,
        5u, 2u, "OwnerBackupHigh1!", false);
    assert(high);
    char high_save_path[4096], stale_save_path[4096];
    int hn = snprintf(high_save_path, sizeof(high_save_path), "%s/high-save.qfs", dir);
    assert(hn > 0 && (size_t)hn < sizeof(high_save_path));
    hn = snprintf(stale_save_path, sizeof(stale_save_path), "%s/stale-save.qfs", dir);
    assert(hn > 0 && (size_t)hn < sizeof(stale_save_path));
    assert(qihse_kv_save_user(store, high_save_path, high) == 0);
    assert(qihse_auth_modify_user(op, 8403u, NULL, NULL, -1, -1, 0, 0));
    assert(qihse_kv_save_user(store, stale_save_path, high) == -2);
    assert(access(stale_save_path, F_OK) != 0);
    char legacy_path[4096], owner_path[4096], mixed_path[4096], restore_dir[4096];
    int n = snprintf(legacy_path, sizeof(legacy_path), "%s/legacy-full.qbak", dir);
    assert(n > 0 && (size_t)n < sizeof(legacy_path));
    n = snprintf(owner_path, sizeof(owner_path), "%s/owner-data.qbak", dir);
    assert(n > 0 && (size_t)n < sizeof(owner_path));
    n = snprintf(mixed_path, sizeof(mixed_path), "%s/mixed-merge.qbak", dir);
    assert(n > 0 && (size_t)n < sizeof(mixed_path));
    n = snprintf(restore_dir, sizeof(restore_dir), "%s/restore", dir);
    assert(n > 0 && (size_t)n < sizeof(restore_dir));
    assert(mkdir(restore_dir, 0700) == 0);

    qihse_backup_info_t legacy_info = {0};
    assert(qihse_backup_full_user(store, op, legacy_path, &legacy_info) ==
           QIHSE_BACKUP_EXPORT_OK);
    qihse_backup_info_free(&legacy_info);
    assert(qihse_kv_del_user(store, "aimem/forget-target", op));
    assert(qihse_kv_set_user(store, "aimem/current", "retained", 0u, 0u, op));
    qihse_kv_store_set_replication_principal_id(store, 8402u);
    assert(qihse_kv_ct_source_enable(store, op, "owner-source", "owner-target",
        "owner-generation", NULL, 128u * 1024u * 1024u));

    qihse_kv_replica_snapshot_t* baseline_snapshot = NULL;
    uint64_t baseline_seq = 0u;
    unsigned char baseline_digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(store, op,
        &baseline_snapshot, &baseline_seq, baseline_digest) == 0);
    assert(baseline_snapshot);
    qihse_kv_replica_snapshot_destroy(baseline_snapshot);
    assert(qihse_kv_ct_source_reconcile_peer(store, op, service, "owner-target",
        "owner-generation", baseline_digest, 0u));

    qihse_backup_owner_snapshot_t* stream = NULL;
    uint64_t source_seq = 0u, stream_size = 0u;
    assert(qihse_backup_owner_snapshot_create(store, low, &stream, &source_seq) ==
           QIHSE_BACKUP_EXPORT_DENIED);
    assert(stream == NULL && source_seq == 0u);
    assert(qihse_backup_owner_snapshot_create(store, op, &stream, &source_seq) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(stream && source_seq == qihse_kv_change_seq(store));
    assert(qihse_backup_owner_snapshot_size(stream, op, &stream_size));
    assert(stream_size > 64u);
    unsigned char prefix[8];
    size_t got = 0u;
    assert(qihse_backup_owner_snapshot_read(stream, op, 0u, prefix,
        sizeof(prefix), &got) && got == sizeof(prefix));
    assert(memcmp(prefix, "QIHSEBAK", 8u) == 0);
    unsigned char denied[8];
    memset(denied, 0x7a, sizeof(denied));
    got = 77u;
    assert(!qihse_backup_owner_snapshot_read(stream, low, 0u, denied,
        sizeof(denied), &got));
    assert(got == 0u && denied[0] == 0u);
    qihse_backup_owner_snapshot_destroy(stream);

    qihse_backup_info_t info = {0};
    assert(qihse_backup_owner_data_user(store, op, owner_path, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_OWNER_DATA && info.end_lsn == source_seq);
    assert(qihse_backup_verify_user(op, owner_path) == QIHSE_BACKUP_EXPORT_OK);
    assert(qihse_restore_user(store, op, owner_path) != QIHSE_BACKUP_EXPORT_OK);
    qihse_backup_merge_stats_t merge_stats = {0};
    assert(qihse_backup_merge_user(op, legacy_path, owner_path,
        mixed_path, 16u * 1024u * 1024u, 10000u, &merge_stats) ==
        QIHSE_BACKUP_EXPORT_UNSUPPORTED);
    assert(access(mixed_path, F_OK) != 0);
    FILE* file = fopen(owner_path, "rb");
    assert(file && fseeko(file, 64, SEEK_SET) == 0);
    qihse_kv_store_t* detached = qihse_kv_open_snapshot_user(file, op,
        128u * 1024u * 1024u, 10000u);
    fclose(file);
    assert(detached);
    char* value = NULL;
    qihse_kv_record_meta_t metadata = {0};
    assert(qihse_kv_snapshot_get_record_user(detached, "aimem/forget-target",
        op, &value, &metadata));
    assert(value && value[0] == '\0' && (metadata.flags & 1u));
    free(value);
    value = NULL;
    assert(qihse_kv_snapshot_get_record_user(detached, "aimem/current",
        op, &value, &metadata));
    assert(value && strcmp(value, "retained") == 0 && metadata.flags == 0u);
    free(value);
    qihse_kv_store_destroy(detached);

    /* Owner data is deliberately a data recovery image, not a CT journal
     * resume image. The ordinary restore API also checks the target's CT mode. */
    qihse_backup_info_free(&info);
    qihse_kv_store_destroy(store);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl(argv[0], argv[0], "restore", owner_path, restore_dir, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    aimem_fixture_cleanup(dir);
    puts("PASS authenticated CT owner data backup preserves tombstones");
    return 0;
}
