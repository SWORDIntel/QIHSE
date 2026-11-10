#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_ct_codec.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

static char* ct_large_payload(void) {
    char* value = malloc(32769u);
    assert(value);
    for (size_t i = 0u; i < 32768u; i++) value[i] = (char)('a' + i % 23u);
    value[32768] = '\0';
    return value;
}

int main(int argc, char** argv) {
    if (argc == 7 && (strcmp(argv[1], "receiver") == 0 ||
                      strcmp(argv[1], "receiver-mismatch") == 0)) {
        bool mismatch = strcmp(argv[1], "receiver-mismatch") == 0;
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_user_t* low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
                                                    0u, 0u, "CtStorageLow1!", false);
        assert(low);
        qihse_user_t* service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
                                                        5u, 2u, "CtStorageService1!", false);
        assert(service);
        qihse_kv_store_t* receiver = qihse_kv_store_create_user(op);
        assert(receiver);
        qihse_kv_store_set_replication_principal_id(receiver, 8302u);
        qihse_kv_ct_receiver_status_t denied_status = {0};
        assert(!qihse_kv_ct_receiver_status(receiver, low, &denied_status));
        uint64_t baseline_seq = strtoull(argv[4], NULL, 10);
        unsigned char digest[32];
        for (size_t i = 0u; i < 32u; i++) {
            unsigned value = 0u;
            assert(sscanf(argv[5] + i * 2u, "%2x", &value) == 1);
            digest[i] = (unsigned char)value;
        }
        assert(qihse_kv_ct_receiver_bind(receiver, op, "source:1", "target:1",
                                          "gen:1", QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                          0u, baseline_seq, NULL));
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
        assert(qihse_kv_ct_owner_token_get(receiver, op, token));
        assert(!qihse_kv_ct_receiver_install_baseline(receiver, low, service, "source:1",
            "gen:1", argv[2], baseline_seq, digest, token));
        assert(!qihse_kv_ct_receiver_install_baseline(receiver, op, low, "source:1",
            "gen:1", argv[2], baseline_seq, digest, token));
        assert(qihse_kv_ct_receiver_install_baseline(receiver, op, service, "source:1",
            "gen:1", argv[2], baseline_seq, digest, token));
        FILE* f = fopen(argv[3], "rb");
        assert(f);
        qihse_kv_ct_group_t group = {0};
        uint8_t mode = 0u;
        size_t bytes = 0u;
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                                   65536u, &group, &mode, &bytes) == 1);
        qihse_kv_ct_group_t group2 = {0};
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                                   65536u, &group2, &mode, &bytes) == 1);
        fclose(f);
        assert(group2.count == 1u && group2.records[0].value &&
               strlen(group2.records[0].value) == 32768u);
        if (mismatch) {
            assert(group2.count == 1u && group2.records[0].value);
            group2.records[0].value[0] ^= 1;
        }
        uint64_t cursor = 0u;
        assert(!qihse_kv_ct_receiver_apply(receiver, low, &group, &cursor));
#ifdef QIHSE_AIMEM_DURABILITY_TEST
        assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-after-group-fsync", 1) == 0);
        assert(!qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor));
        assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        qihse_kv_store_destroy(receiver);
        receiver = qihse_kv_store_create_user(op);
        if (!receiver) perror("CT receiver reopen");
        assert(receiver);
        qihse_kv_ct_receiver_status_t status = {0};
        assert(qihse_kv_ct_receiver_status(receiver, op, &status) &&
               status.durable_cursor == 1u);
#endif
        qihse_kv_store_set_replication_principal_id(receiver, 8302u);
        assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) && cursor == 1u);
        assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) && cursor == 1u);
        group.stream_position = 3u;
        assert(!qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor));
        qihse_ct_codec_clear(&group);
        assert(qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) && cursor == 2u);
        qihse_ct_codec_clear(&group2);
        uint64_t target_cut = 0u;
        assert(qihse_kv_ct_fence_range(receiver, op, "move:1", 0u, 16383u,
                                        token, &target_cut) && target_cut == 2u);
        qihse_kv_store_destroy(receiver);
        receiver = qihse_kv_store_create_user(op);
        assert(receiver);
        assert(qihse_kv_ct_fence_range(receiver, op, "move:1", 0u, 16383u,
                                        token, &target_cut) && target_cut == 2u);
        assert(!qihse_kv_ct_target_seal_create(receiver, low, op, "move:1",
            "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
        assert(!qihse_kv_ct_target_seal_create(receiver, op, low, "move:1",
            "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
        qihse_kv_ct_proof_t* seal = qihse_kv_ct_target_seal_create(receiver,
            op, op, "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
        assert(seal && qihse_kv_ct_proof_validate(receiver, op, op, seal));
        unsigned char range_digest[32];
        assert(!qihse_kv_ct_proof_validate(receiver, op, low, seal));
        assert(!qihse_kv_ct_proof_fields(receiver, low, op, seal, NULL, NULL, NULL,
                                        NULL, NULL, NULL, NULL, NULL,
                                        range_digest));
        assert(!qihse_kv_ct_proof_fields(receiver, op, low, seal, NULL, NULL, NULL,
                                        NULL, NULL, NULL, NULL, NULL,
                                        range_digest));
        assert(qihse_kv_ct_proof_fields(receiver, op, op, seal, NULL, NULL, NULL,
                                       NULL, NULL, NULL, NULL, NULL,
                                       range_digest));
        char range_hex[65];
        for (size_t i = 0u; i < 32u; i++)
            assert(snprintf(range_hex + i * 2u, 3u, "%02x", range_digest[i]) == 2);
        assert((strcmp(range_hex, argv[6]) != 0) == mismatch);
        qihse_kv_ct_proof_destroy(seal);
        qihse_kv_store_destroy(receiver);
        return 0;
    }
    assert(argc == 1);
    char dir[] = "./ct_storage_XXXXXX";
    umask(0077);
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "CtStorageLow1!", false);
    assert(low);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
                                                     5u, 2u, "CtStorageService1!", false);
    assert(service);
    qihse_kv_store_t* s = qihse_kv_store_create_user(op);
    assert(s);
    qihse_kv_store_set_replication_principal_id(s, 8302u);
    assert(qihse_kv_set_user(s, "commons/preexisting", "secret", 4u, 2u, op));
    assert(qihse_kv_get_user(s, "commons/preexisting", low) == NULL);
    qihse_kv_replica_snapshot_t* denied_snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(s, low, "*", &denied_snapshot) == -2);
    assert(denied_snapshot == NULL);
    qihse_user_t* high = qihse_auth_create_user(op, 8303u, QIHSE_ROLE_ANALYST,
                                                 4u, 2u, "CtStorageHigh1!", false);
    assert(high);
    qihse_kv_replica_snapshot_t* high_snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(s, high, "*", &high_snapshot) == 0);
    assert(high_snapshot);
    uint64_t high_size = 0u;
    uint64_t high_snapshot_seq = 0u;
    uint64_t expected_snapshot_seq = qihse_kv_change_seq(s);
    assert(qihse_kv_replica_snapshot_size(high_snapshot, high, &high_size));
    assert(qihse_kv_replica_snapshot_change_seq(high_snapshot, high,
                                                &high_snapshot_seq));
    assert(high_snapshot_seq == expected_snapshot_seq);
    assert(qihse_kv_set_user(s, "commons/after-snapshot", "later", 0u, 0u, op));
    uint64_t still_snapshot_seq = 0u;
    assert(qihse_kv_replica_snapshot_change_seq(high_snapshot, high,
                                                &still_snapshot_seq));
    assert(still_snapshot_seq == high_snapshot_seq &&
           qihse_kv_change_seq(s) > high_snapshot_seq);
    size_t denied_bytes = 99u;
    unsigned char denied_data[16] = {0};
    uint64_t denied_seq = 99u;
    assert(!qihse_kv_replica_snapshot_change_seq(high_snapshot, low, &denied_seq));
    assert(denied_seq == 0u);
    assert(!qihse_kv_replica_snapshot_read(high_snapshot, low, 0u,
                                            denied_data, sizeof(denied_data),
                                            &denied_bytes));
    assert(denied_bytes == 0u);
    assert(qihse_auth_modify_user(op, 8303u, NULL, NULL, -1, -1, 0, 0));
    assert(!qihse_kv_replica_snapshot_size(high_snapshot, high, &high_size));
    assert(high_size == 0u);
    denied_bytes = 99u;
    assert(!qihse_kv_replica_snapshot_read(high_snapshot, high, 0u,
                                            denied_data, sizeof(denied_data),
                                            &denied_bytes));
    assert(denied_bytes == 0u);
    qihse_kv_replica_snapshot_destroy(high_snapshot);
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-state-before-publish", 1) == 0);
    assert(!qihse_kv_ct_source_enable(s, op, "source:1", "target:1",
                                       "gen:1", NULL, 128u * 1024u * 1024u));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_store_destroy(s);
    s = qihse_kv_store_create_user(op);
    assert(s);
    char* retained = qihse_kv_get_user(s, "commons/preexisting", op);
    assert(retained && strcmp(retained, "secret") == 0);
    free(retained);
#endif
    assert(qihse_kv_ct_source_enable(s, op, "source:1", "target:1", "gen:1", NULL,
                                     128u * 1024u * 1024u));
    qihse_kv_store_set_replication_principal_id(s, 8302u);
    qihse_kv_ct_source_status_t denied_source = {0};
    assert(!qihse_kv_ct_source_status(s, low, &denied_source));
    qihse_kv_ct_source_status_t admission = {0};
    assert(qihse_kv_ct_source_status(s, op, &admission) && !admission.admitted);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], baseline[32];
    assert(!qihse_kv_ct_owner_token_get(s, low, token));
    assert(qihse_kv_ct_owner_token_get(s, op, token));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t baseline_seq = 0u;
    assert(qihse_kv_ct_source_baseline_snapshot_create(s, op, &snapshot,
                                                       &baseline_seq, baseline) == 0);
    assert(snapshot);
    assert(baseline_seq != 0u);
    assert(!qihse_kv_ct_source_reconcile(s, low, "target:1", "gen:1", baseline, 0u));
    unsigned char wrong[32] = {0};
    assert(!qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", wrong, 0u));
    assert(!qihse_kv_ct_source_reconcile_peer(s, op, low, "target:1", "gen:1", baseline, 0u));
    assert(qihse_kv_ct_source_reconcile_peer(s, op, service, "target:1", "gen:1", baseline, 0u));
    assert(qihse_kv_ct_source_status(s, op, &admission) && admission.admitted);
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(!qihse_kv_ct_writer_scope_enter(s, low, wrong, &scope));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_set_user(s, "commons/new", "classified", 4u, 2u, op));
    assert(qihse_kv_get_user(s, "commons/new", op) == NULL); /* pending ACK */
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    assert(!qihse_kv_ct_source_read(s, low, "gen:1", 0u, 1u, 65536u,
                                    &groups, &count, &resume));
    assert(qihse_kv_ct_source_read(s, op, "gen:1", 0u, 1u, 65536u,
                                   &groups, &count, &resume));
    assert(count == 1u && resume == 1u && groups[0].stream_position == 1u);
    assert(groups[0].count == 1u && strcmp(groups[0].records[0].value, "classified") == 0);
    char snapshot_path[] = "./ct_baseline_XXXXXX";
    int snapshot_fd = mkstemp(snapshot_path);
    assert(snapshot_fd >= 0);
    uint64_t snapshot_size = 0u;
    assert(qihse_kv_replica_snapshot_size(snapshot, op, &snapshot_size));
    for (uint64_t off = 0u; off < snapshot_size;) {
        unsigned char chunk[4096];
        size_t got = 0u;
        assert(qihse_kv_replica_snapshot_read(snapshot, op, off, chunk,
                                              sizeof(chunk), &got));
        assert(got > 0u && write(snapshot_fd, chunk, got) == (ssize_t)got);
        off += got;
    }
    assert(fsync(snapshot_fd) == 0 && close(snapshot_fd) == 0);
    char group_path[] = "./ct_group_XXXXXX";
    int group_fd = mkstemp(group_path);
    assert(group_fd >= 0);
    FILE* group_file = fdopen(group_fd, "wb");
    assert(group_file);
    size_t group_bytes = 0u;
    assert(qihse_ct_codec_write(group_file, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                0u, 1u, &groups[0], 65536u, &group_bytes));
    assert(fclose(group_file) == 0);
    /* A periodic successor reconcile can race a newly durable source group.
     * It may confirm its older durable cursor after initial admission, but it
     * must not advance ACK or expose the pending value. */
    assert(qihse_kv_ct_source_reconcile_peer(s, op, service, "target:1", "gen:1",
                                             baseline, 0u));
    qihse_kv_ct_source_status_t stale_reconcile_status = {0};
    assert(qihse_kv_ct_source_status(s, op, &stale_reconcile_status));
    assert(stale_reconcile_status.durable_lsn == 1u &&
           stale_reconcile_status.acknowledged_lsn == 0u);
    assert(qihse_kv_get_user(s, "commons/new", op) == NULL);
    assert(!qihse_kv_ct_source_ack(s, low, "target:1", "gen:1", 1u));
    assert(!qihse_kv_ct_source_ack(s, op, "wrong", "gen:1", 1u));
    assert(qihse_kv_ct_source_ack(s, op, "target:1", "gen:1", 1u));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_ct_source_status_t post_gc = {0};
    assert(qihse_kv_ct_source_status(s, op, &post_gc) &&
           post_gc.durable_lsn == 1u && post_gc.acknowledged_lsn == 1u &&
           post_gc.retained_bytes == 0u);
    char* value = qihse_kv_get_user(s, "commons/new", op);
    assert(value && strcmp(value, "classified") == 0);
    free(value);
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    char* large = ct_large_payload();
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-after-group-fsync", 1) == 0);
    assert(!qihse_kv_set_user(s, "commons/pending", large, 4u, 2u, op));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_ct_writer_scope_leave(scope);
#else
    assert(qihse_kv_set_user(s, "commons/pending", large, 4u, 2u, op));
    assert(!qihse_kv_ct_writer_scope_finish(scope, 0u, NULL)); /* lost ACK */
#endif
    qihse_kv_store_destroy(s);
    s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_source_status(s, op, &admission) && !admission.admitted);
    qihse_kv_replica_snapshot_t* reopened_baseline = NULL;
    uint64_t reopened_seq = 0u;
    unsigned char reopened_digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(s, op,
        &reopened_baseline, &reopened_seq, reopened_digest) == 0);
    assert(reopened_baseline && reopened_seq == baseline_seq &&
           memcmp(reopened_digest, baseline, 32u) == 0);
    uint64_t reopened_size = 0u;
    assert(qihse_kv_replica_snapshot_size(reopened_baseline, op,
                                          &reopened_size) && reopened_size == snapshot_size);
    qihse_kv_replica_snapshot_destroy(reopened_baseline);
    assert(!qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_get_user(s, "commons/pending", op) == NULL);
    qihse_kv_ct_group_t* recovered = NULL;
    size_t recovered_count = 0u;
    uint64_t recovered_resume = 0u;
    assert(qihse_kv_ct_source_read(s, op, "gen:1", 1u, 1u, 65536u,
                                   &recovered, &recovered_count, &recovered_resume));
    assert(recovered_count == 1u && recovered_resume == 2u &&
           strcmp(recovered[0].records[0].value, large) == 0);
    FILE* append_group = fopen(group_path, "ab");
    assert(append_group);
    assert(qihse_ct_codec_write(append_group, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                0u, 1u, &recovered[0], 65536u, &group_bytes));
    assert(fclose(append_group) == 0);
    qihse_kv_ct_groups_free(recovered, recovered_count);
    assert(qihse_kv_ct_source_ack(s, op, "target:1", "gen:1", 2u));
    assert(qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", baseline, 2u));
    value = qihse_kv_get_user(s, "commons/pending", op);
    assert(value && strcmp(value, large) == 0);
    free(value);
    free(large);
    uint64_t cut = 999u;
    assert(qihse_kv_ct_fence_range(s, op, "move:1", 0u, 16383u, token, &cut));
    assert(cut == 2u);
    qihse_kv_ct_transfer_status_t fence = {0};
    assert(!qihse_kv_ct_transfer_status(s, low, &fence));
    assert(fence.transfer_id[0] == '\0');
    assert(qihse_kv_ct_transfer_status(s, op, &fence));
    assert(fence.fence_state == 1u && fence.cut_position == cut &&
           strcmp(fence.transfer_id, "move:1") == 0);
    qihse_kv_ct_range_snapshot_t* range_image = NULL;
    uint64_t export_cut = 0u, export_size = 0u;
    unsigned char export_sha[32];
    assert(qihse_kv_ct_range_export(s, op, low, "move:1", "target:1",
        "gen:1", 0u, 16383u, token, &range_image, &export_cut,
        export_sha) == -2 && !range_image);
    assert(qihse_kv_ct_range_export(s, op, op, "move:1", "target:1",
        "gen:1", 0u, 16383u, token, &range_image, &export_cut,
        export_sha) == 0 && range_image && export_cut == cut);
    assert(!qihse_kv_ct_range_snapshot_size(range_image, low, &export_size));
    assert(qihse_kv_ct_range_snapshot_size(range_image, op, &export_size) &&
           export_size > 0u);
    qihse_kv_ct_range_snapshot_destroy(range_image);
    assert(!qihse_kv_ct_source_transfer_proof_create(s, low, op, "move:1",
        "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
    assert(!qihse_kv_ct_source_transfer_proof_create(s, op, low, "move:1",
        "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
    qihse_kv_ct_proof_t* source_seal = qihse_kv_ct_source_transfer_proof_create(
        s, op, op, "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
    assert(source_seal && qihse_kv_ct_proof_validate(s, op, op, source_seal));
    unsigned char range_digest[32];
    assert(!qihse_kv_ct_proof_validate(s, op, low, source_seal));
    assert(!qihse_kv_ct_proof_fields(s, op, low, source_seal, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL,
                                   range_digest));
    assert(qihse_kv_ct_proof_fields(s, op, op, source_seal, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL,
                                   range_digest));
    qihse_kv_ct_proof_destroy(source_seal);
    qihse_user_t* data = qihse_auth_create_user(op, 8390u,
        QIHSE_ROLE_ANALYST, 4u, 2u, "CtProofData1!", false);
    assert(data);
    source_seal = qihse_kv_ct_source_transfer_proof_create(s, op, data,
        "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
    assert(source_seal && qihse_kv_ct_proof_validate(s, op, data, source_seal));
    assert(qihse_auth_modify_user(op, 8390u, NULL, NULL, -1, -1, 0, 0));
    assert(!qihse_kv_ct_proof_validate(s, op, data, source_seal));
    assert(!qihse_kv_ct_proof_fields(s, op, data, source_seal,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, range_digest));
    qihse_kv_ct_proof_destroy(source_seal);
    assert(qihse_auth_modify_user(op, 8390u, NULL, NULL, -1, -1, 4, 2));
    source_seal = qihse_kv_ct_source_transfer_proof_create(s, op, data,
        "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
    assert(source_seal);
    assert(qihse_auth_destroy_user(op, 8390u));
    assert(!qihse_kv_ct_proof_validate(s, op, data, source_seal));
    qihse_kv_ct_proof_destroy(source_seal);
    assert(!qihse_kv_ct_fence_finish(s, op, "move:1", true, token));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(!qihse_kv_set_user(s, "commons/new", "denied", 4u, 2u, op));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_replica_snapshot_destroy(snapshot);
    qihse_kv_store_destroy(s);
    s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_transfer_status(s, op, &fence) &&
           fence.fence_state == 1u &&
           strcmp(fence.transfer_id, "move:1") == 0);
    assert(!qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", baseline, 2u));
    assert(qihse_kv_ct_fence_range(s, op, "move:1", 0u, 16383u,
                                   token, &cut) && cut == 2u);
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(!qihse_kv_set_user(s, "commons/new", "still-denied", 4u, 2u, op));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_store_destroy(s);
    char receiver_dir[] = "./ct_receiver_XXXXXX";
    assert(mkdtemp(receiver_dir));
    char seq_text[32], digest_hex[65], range_hex[65];
    assert(snprintf(seq_text, sizeof(seq_text), "%llu",
                    (unsigned long long)baseline_seq) > 0);
    for (size_t i = 0u; i < 32u; i++)
        assert(snprintf(digest_hex + i * 2u, 3u, "%02x", baseline[i]) == 2);
    for (size_t i = 0u; i < 32u; i++)
        assert(snprintf(range_hex + i * 2u, 3u, "%02x", range_digest[i]) == 2);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", receiver_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char mismatch_dir[] = "./ct_receiver_mismatch_XXXXXX";
    assert(mkdtemp(mismatch_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", mismatch_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-mismatch", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_fence_finish(s, op, "move:1", false, token));
    assert(qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", baseline, 2u));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_set_user(s, "commons/new", "after-abort", 4u, 2u, op));
    assert(!qihse_kv_ct_writer_scope_finish(scope, 0u, NULL));
    qihse_kv_store_destroy(s);
    char wal_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log", dir) > 0);
    int wal_fd = open(wal_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    assert(wal_fd >= 0);
    assert(write(wal_fd, "QKV3", 4u) == 4 && fsync(wal_fd) == 0);
    assert(close(wal_fd) == 0);
    assert(qihse_kv_store_create_user(op) == NULL); /* legacy WAL bypass denied */
    qihse_kv_ct_groups_free(groups, count);
    assert(unlink(snapshot_path) == 0);
    assert(unlink(group_path) == 0);
    aimem_fixture_cleanup(receiver_dir);
    aimem_fixture_cleanup(mismatch_dir);
    aimem_fixture_cleanup(dir);
    puts("ct storage: PASS");
    return 0;
}
