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

#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

int main(void) {
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
    assert(qihse_kv_set_user(store, "aimem/forget-target", "old", 0u, 0u, op));
    qihse_backup_info_t legacy_info = {0};
    assert(qihse_backup_full_user(store, op, "./legacy-full.qbak", &legacy_info) ==
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
    assert(qihse_backup_owner_data_user(store, op, "./owner-data.qbak", &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_OWNER_DATA && info.end_lsn == source_seq);
    assert(qihse_backup_verify_user(op, "./owner-data.qbak") == QIHSE_BACKUP_EXPORT_OK);
    assert(qihse_restore_user(store, op, "./owner-data.qbak") != QIHSE_BACKUP_EXPORT_OK);
    qihse_backup_merge_stats_t merge_stats = {0};
    assert(qihse_backup_merge_user(op, "./legacy-full.qbak", "./owner-data.qbak",
        "./mixed-merge.qbak", 16u * 1024u * 1024u, 10000u, &merge_stats) ==
        QIHSE_BACKUP_EXPORT_UNSUPPORTED);
    assert(access("./mixed-merge.qbak", F_OK) != 0);
    FILE* file = fopen("./owner-data.qbak", "rb");
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
    unlink("./owner-data.qbak");
    unlink("./legacy-full.qbak");
    aimem_fixture_cleanup(dir);
    puts("PASS authenticated CT owner data backup preserves tombstones");
    return 0;
}
