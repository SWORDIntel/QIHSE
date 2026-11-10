#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_ct_codec.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

static const char SOURCE_LANE[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char TARGET_LANE[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char OTHER_LANE[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char GEN_SOURCE[QIHSE_KV_CT_ID_MAX + 1u] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_OTHER[QIHSE_KV_CT_ID_MAX + 1u] =
    "cccccccccccccccccccccccccccccccc";
static const uint16_t SELECTED_SLOT = 313u;
static const uint16_t RETAINED_SLOT = 931u;
static const uint16_t OTHER_SLOT = 12019u;

static void bitmap_set(uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
                       uint16_t slot) {
    bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}

static char *key_for_slot(const char *prefix, uint16_t wanted_slot) {
    char candidate[128];
    for (unsigned i = 0u; i < 1000000u; ++i) {
        int n = snprintf(candidate, sizeof(candidate), "%s%u", prefix, i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        if (qihse_cluster_key_slot(candidate, (size_t)n) == wanted_slot)
            return strdup(candidate);
    }
    assert(!"no key for requested slot");
    return NULL;
}

static void assert_value(qihse_kv_store_t *store, qihse_user_t *user,
                         const char *key, const char *expected) {
    char *value = qihse_kv_get_user(store, key, user);
    if (expected) assert(value && strcmp(value, expected) == 0);
    else assert(value == NULL);
    free(value);
}

static void copy_snapshot(qihse_kv_replica_snapshot_t *snapshot,
                          qihse_user_t *principal, const char *path) {
    uint64_t size = 0u;
    assert(qihse_kv_replica_snapshot_size(snapshot, principal, &size));
    FILE *out = fopen(path, "wb");
    assert(out);
    unsigned char buffer[8192];
    uint64_t offset = 0u;
    while (offset < size) {
        size_t got = 0u;
        assert(qihse_kv_replica_snapshot_read(snapshot, principal, offset,
            buffer, sizeof(buffer), &got));
        assert(got > 0u && fwrite(buffer, 1u, got, out) == got);
        offset += got;
    }
    assert(fclose(out) == 0);
}

static qihse_kv_store_t *open_authorized_snapshot(qihse_kv_store_t *store,
                                                  qihse_user_t *principal) {
    qihse_kv_replica_snapshot_t *snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(store, principal, "*", &snapshot) == 0);
    assert(snapshot);
    FILE *file = tmpfile();
    assert(file);
    uint64_t size = 0u;
    assert(qihse_kv_replica_snapshot_size(snapshot, principal, &size));
    unsigned char buffer[8192];
    uint64_t offset = 0u;
    while (offset < size) {
        size_t count = 0u;
        assert(qihse_kv_replica_snapshot_read(snapshot, principal, offset,
                                               buffer, sizeof(buffer), &count));
        assert(count > 0u && fwrite(buffer, 1u, count, file) == count);
        offset += count;
    }
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(fflush(file) == 0);
    rewind(file);
    qihse_kv_store_t *detached = qihse_kv_open_snapshot_user(
        file, principal, 64u << 20u, 200000u);
    fclose(file);
    assert(detached);
    return detached;
}

static void assert_snapshot_value(qihse_kv_store_t *snapshot,
                                  qihse_user_t *principal,
                                  const char *key, const char *expected) {
    char *value = NULL;
    qihse_kv_record_meta_t metadata = {0};
    assert(qihse_kv_snapshot_get_record_user(snapshot, key, principal,
                                              &value, &metadata));
    if (expected) assert(value && strcmp(value, expected) == 0);
    else assert(value == NULL);
    free(value);
}

static qihse_user_t *make_operator(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtBaseOperator1!"));
    qihse_user_t *user = qihse_auth_authenticate_id(0u, "CtBaseOperator1!");
    assert(user);
    return user;
}

static int source_process(const char *data_dir, const char *image_path,
                         const char *manifest_path, const char *delta_path) {
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    qihse_user_t *operator_user = make_operator();
    qihse_user_t *peer_user = qihse_auth_create_user(operator_user, 8802u,
        QIHSE_ROLE_ANALYST, 5u, UINT16_MAX, "CtBasePeerPass1!", false);
    char *source_key = key_for_slot("commons/source-", SELECTED_SLOT);
    qihse_kv_store_t *store = qihse_kv_store_create_user(operator_user);
    assert(peer_user && source_key && store);
    qihse_kv_store_set_replication_principal_id(store,
        qihse_user_get_id(peer_user));
    assert(qihse_kv_set_user(store, source_key, "classified-baseline",
                             4u, 0u, operator_user));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    uint8_t source_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    bitmap_set(source_slots, SELECTED_SLOT);
    assert(qihse_kv_ct_lane_source_enable(store, operator_user, SOURCE_LANE,
        source_slots,
        "source-node", "target-node", GEN_SOURCE, token,
        16u * 1024u * 1024u));

    qihse_kv_replica_snapshot_t *snapshot = NULL;
    uint64_t row_seq = 0u;
    unsigned char digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store,
        operator_user, SOURCE_LANE, &snapshot, &row_seq, digest) == 0);
    copy_snapshot(snapshot, operator_user, image_path);
    qihse_kv_replica_snapshot_destroy(snapshot);

    /* Emit one authenticated source group after the baseline: it updates one
     * existing row and recreates a key that will be stale at the receiver. */
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, operator_user,
        peer_user, SOURCE_LANE, "target-node", GEN_SOURCE, digest, 0u));
    qihse_kv_ct_writer_scope_t *scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, operator_user,
        SOURCE_LANE, token, &scope));
    qihse_kv_batch_set_record_t updates[] = {
        {source_key, "updated-after-baseline", 0u, 4u, 0u},
        {key_for_slot("commons/stale-", SELECTED_SLOT),
         "recreated-after-baseline", 0u, 4u, 0u}
    };
    char *stale_source_key = (char *)updates[1].key;
    assert(qihse_kv_set_batch_durable_user(store, updates,
        sizeof(updates) / sizeof(updates[0]), operator_user));
    qihse_kv_ct_writer_scope_leave(scope);
    qihse_kv_ct_group_t *groups = NULL;
    size_t group_count = 0u;
    uint64_t resume = 0u;
    assert(qihse_kv_ct_lane_source_read(store, peer_user, SOURCE_LANE,
        GEN_SOURCE, 0u, 8u, 1u << 20u, &groups, &group_count, &resume));
    assert(group_count == 1u && resume == 1u && groups[0].count == 2u);
    FILE *delta = fopen(delta_path, "wb");
    assert(delta);
    size_t encoded = 0u;
    assert(qihse_ct_codec_write(delta, peer_user,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, QIHSE_CT_CODEC_MODE_SOURCE,
        &groups[0], 1u << 20u, &encoded));
    assert(encoded > 0u && fflush(delta) == 0 && fclose(delta) == 0);
    qihse_kv_ct_groups_free(groups, group_count);

    FILE *manifest = fopen(manifest_path, "wb");
    assert(manifest);
    assert(fprintf(manifest, "%llu\n", (unsigned long long)row_seq) > 0);
    for (size_t i = 0u; i < sizeof(digest); ++i)
        assert(fprintf(manifest, "%02x", digest[i]) == 2);
    assert(fputc('\n', manifest) != EOF && fclose(manifest) == 0);

    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(operator_user);
    qihse_auth_release_principal_scoped(peer_user);
    free(source_key);
    free(stale_source_key);
    return 0;
}

static int target_process(const char *data_dir, const char *image_path,
                         const char *manifest_path, const char *delta_path,
                         bool partial) {
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    qihse_user_t *operator_user = make_operator();
    qihse_user_t *peer_user = qihse_auth_create_user(operator_user, 8802u,
        QIHSE_ROLE_ANALYST, 5u, UINT16_MAX, "CtBasePeerPass1!", false);
    qihse_user_t *low_user = qihse_auth_create_user(operator_user, 8801u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "CtBaseLowPass1!", false);
    assert(peer_user && low_user);

    unsigned long long row_seq_text = 0u;
    char digest_hex[65];
    FILE *manifest = fopen(manifest_path, "rb");
    assert(manifest && fscanf(manifest, "%llu\n%64s", &row_seq_text,
                              digest_hex) == 2 && fclose(manifest) == 0);
    unsigned char digest[32];
    for (size_t i = 0u; i < 32u; ++i) {
        unsigned value = 0u;
        assert(sscanf(digest_hex + 2u * i, "%2x", &value) == 1);
        digest[i] = (unsigned char)value;
    }

    char *source_key = key_for_slot("commons/source-", SELECTED_SLOT);
    char *stale_key = key_for_slot("commons/stale-", SELECTED_SLOT);
    char *retained_key = key_for_slot("commons/retained-", RETAINED_SLOT);
    char *other_key = key_for_slot("commons/other-lane-", OTHER_SLOT);
    assert(source_key && stale_key && retained_key && other_key);
    uint8_t target_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t selected_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t other_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    bitmap_set(target_slots, SELECTED_SLOT);
    if (partial) bitmap_set(target_slots, RETAINED_SLOT);
    bitmap_set(selected_slots, SELECTED_SLOT);
    bitmap_set(other_slots, RETAINED_SLOT);
    bitmap_set(other_slots, OTHER_SLOT);

    qihse_kv_store_t *store = qihse_kv_store_create_user(operator_user);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store,
        qihse_user_get_id(peer_user));
    assert(qihse_kv_set_user(store, stale_key, "must-be-removed", 1u, 0u,
                             operator_user));
    assert(qihse_kv_set_user(store, retained_key, "keep-this-slot", 1u, 0u,
                             operator_user));
    assert(qihse_kv_set_user(store, other_key, "keep-other-lane", 1u, 0u,
                             operator_user));
    unsigned char target_token[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char other_token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_receiver_bind(store, operator_user, TARGET_LANE,
        target_slots, "source-node", "target-node", GEN_SOURCE,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, target_token));
    assert(qihse_kv_ct_lane_receiver_bind(store, operator_user, OTHER_LANE,
        other_slots, "other-source", "other-target", GEN_OTHER,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, other_token));

    assert(!qihse_kv_ct_lane_receiver_baseline_install(store, operator_user,
        low_user, TARGET_LANE, selected_slots, image_path,
        (uint64_t)row_seq_text, 0u, digest, target_token));
    assert(errno == EACCES);
    qihse_kv_ct_lane_status_t denied_status = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, TARGET_LANE,
                                   &denied_status));
    assert(!denied_status.baseline_sealed &&
           denied_status.durable_position == 0u &&
           denied_status.acknowledged_position == 0u);

    assert(qihse_kv_ct_lane_receiver_baseline_install(store, operator_user,
        operator_user, TARGET_LANE, selected_slots, image_path,
        (uint64_t)row_seq_text, 0u, digest, target_token));
    /* Inspect via an authenticated detached snapshot; live receiver reads
     * remain fenced until promotion. */
    qihse_kv_store_t *detached = open_authorized_snapshot(store, operator_user);
    assert_snapshot_value(detached, operator_user, source_key,
                          "classified-baseline");
    assert_snapshot_value(detached, operator_user, stale_key, NULL);
    assert_snapshot_value(detached, operator_user, retained_key,
                          "keep-this-slot");
    assert_snapshot_value(detached, operator_user, other_key,
                          "keep-other-lane");
    qihse_kv_store_destroy(detached);

    qihse_kv_ct_lane_status_t status = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, TARGET_LANE, &status));
    assert(status.mode == QIHSE_KV_CT_LANE_RECEIVER && !status.admitted &&
           status.baseline_sealed == !partial &&
           status.durable_position == 0u && status.acknowledged_position == 0u &&
           status.baseline_row_seq == (partial ? 0u : (uint64_t)row_seq_text));
    if (!partial) assert(memcmp(status.baseline_digest, digest, sizeof(digest)) == 0);
    assert(memcmp(status.slot_bitmap, target_slots, sizeof(target_slots)) == 0);
    assert(qihse_kv_ct_lane_status(store, operator_user, OTHER_LANE, &status));
    assert(status.mode == QIHSE_KV_CT_LANE_RECEIVER);

    if (!partial) {
        FILE *delta = fopen(delta_path, "rb");
        assert(delta);
        qihse_kv_ct_group_t group = {0};
        uint8_t mode = 0u;
        size_t frame_bytes = 0u;
        assert(qihse_ct_codec_read(delta, peer_user,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 1u << 20u, &group,
            &mode, &frame_bytes) == 1);
        assert(mode == QIHSE_CT_CODEC_MODE_SOURCE && frame_bytes > 0u);
        uint64_t cursor = 0u;
        assert(qihse_kv_ct_lane_receiver_apply(store, peer_user, TARGET_LANE,
            &group, &cursor));
        assert(cursor == 1u);
        assert(qihse_ct_codec_read(delta, peer_user,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 1u << 20u, &group,
            &mode, &frame_bytes) == 0);
        assert(fclose(delta) == 0);
        qihse_ct_codec_clear(&group);
        detached = open_authorized_snapshot(store, operator_user);
        assert_snapshot_value(detached, operator_user, source_key,
                              "updated-after-baseline");
        assert_snapshot_value(detached, operator_user, stale_key,
                              "recreated-after-baseline");
        qihse_kv_store_destroy(detached);
    }

    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(operator_user);
    assert(store);
    detached = open_authorized_snapshot(store, operator_user);
    assert_snapshot_value(detached, operator_user, source_key, partial
        ? "classified-baseline" : "updated-after-baseline");
    assert_snapshot_value(detached, operator_user, stale_key,
        partial ? NULL : "recreated-after-baseline");
    assert_snapshot_value(detached, operator_user, retained_key,
                          "keep-this-slot");
    assert_snapshot_value(detached, operator_user, other_key,
                          "keep-other-lane");
    qihse_kv_store_destroy(detached);
    assert(qihse_kv_ct_lane_status(store, operator_user, TARGET_LANE, &status));
    assert(status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
           status.durable_position == (partial ? 0u : 1u) &&
           status.acknowledged_position == 0u);
    if (!partial) assert(memcmp(status.baseline_digest, digest, sizeof(digest)) == 0);
    assert(memcmp(status.slot_bitmap, target_slots, sizeof(target_slots)) == 0);

    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(operator_user);
    qihse_auth_release_principal_scoped(low_user);
    qihse_auth_release_principal_scoped(peer_user);
    free(source_key);
    free(stale_key);
    free(retained_key);
    free(other_key);
    return 0;
}

static int empty_lane_process(const char *data_dir, const char *image_path) {
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    qihse_user_t *operator_user = make_operator();
    qihse_kv_store_t *store = qihse_kv_store_create_user(operator_user);
    assert(store);

    /* Other local data may advance the row watermark before this group joins. */
    assert(qihse_kv_set_user(store, "node-local", "outside-group", 0u, 0u,
                             operator_user));
    FILE *empty = fopen(image_path, "wb");
    assert(empty && fclose(empty) == 0);
    unsigned char digest[32];
    unsigned int digest_len = 0u;
    assert(EVP_Digest("", 0u, digest, &digest_len, EVP_sha256(), NULL) == 1);
    assert(digest_len == sizeof(digest));

    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    uint8_t empty_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    assert(qihse_kv_ct_lane_receiver_bind(store, operator_user, TARGET_LANE,
        empty_slots, "source-node", "joining-node", GEN_SOURCE,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, token));
    assert(qihse_kv_ct_lane_receiver_baseline_install(store, operator_user,
        operator_user, TARGET_LANE, empty_slots, image_path,
        7u, 0u, digest, token));

    qihse_kv_ct_lane_status_t status = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, TARGET_LANE, &status));
    assert(status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
           status.baseline_sealed && !status.admitted &&
           status.baseline_row_seq == 7u &&
           status.baseline_stream_cut == 0u &&
           status.durable_position == 0u &&
           status.acknowledged_position == 0u);

    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(operator_user);
    assert(store);
    memset(&status, 0, sizeof(status));
    assert(qihse_kv_ct_lane_status(store, operator_user, TARGET_LANE, &status));
    assert(status.baseline_sealed && !status.admitted &&
           status.baseline_row_seq == 7u &&
           status.baseline_stream_cut == 0u);
    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(operator_user);
    return 0;
}

static void run_child(const char *self, const char *role, const char *dir,
                      const char *image, const char *manifest,
                      const char *delta) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl(self, self, role, dir, image, manifest, delta, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv) {
    if (argc == 6 && strcmp(argv[1], "--source") == 0)
        return source_process(argv[2], argv[3], argv[4], argv[5]);
    if (argc == 6 && strcmp(argv[1], "--target-full") == 0)
        return target_process(argv[2], argv[3], argv[4], argv[5], false);
    if (argc == 6 && strcmp(argv[1], "--target-partial") == 0)
        return target_process(argv[2], argv[3], argv[4], argv[5], true);
    if (argc == 4 && strcmp(argv[1], "--empty-lane") == 0)
        return empty_lane_process(argv[2], argv[3]);
    assert(argc == 1);
    char source_dir[] = "./ct_lane_base_src_XXXXXX";
    char target_dir[] = "./ct_lane_base_dst_XXXXXX";
    char partial_dir[] = "./ct_lane_base_part_XXXXXX";
    char empty_dir[] = "./ct_lane_base_empty_XXXXXX";
    assert(mkdtemp(source_dir) && mkdtemp(target_dir) && mkdtemp(partial_dir) &&
           mkdtemp(empty_dir));
    char source_image[512], manifest[512], delta[512];
    char empty_image[512];
    assert(snprintf(source_image, sizeof(source_image), "%s/source.qfs",
                    source_dir) > 0);
    assert(snprintf(manifest, sizeof(manifest), "%s/manifest.txt",
                    source_dir) > 0);
    assert(snprintf(delta, sizeof(delta), "%s/delta.qct", source_dir) > 0);
    assert(snprintf(empty_image, sizeof(empty_image), "%s/empty.qfs",
                    empty_dir) > 0);
    char self[4096];
    assert(realpath(argv[0], self));
    run_child(self, "--source", source_dir, source_image, manifest, delta);
    run_child(self, "--target-full", target_dir, source_image, manifest, delta);
    run_child(self, "--target-partial", partial_dir, source_image, manifest, delta);
    pid_t empty_child = fork();
    assert(empty_child >= 0);
    if (empty_child == 0) {
        execl(self, self, "--empty-lane", empty_dir, empty_image, (char *)NULL);
        _exit(127);
    }
    int empty_status = 0;
    assert(waitpid(empty_child, &empty_status, 0) == empty_child);
    assert(WIFEXITED(empty_status) && WEXITSTATUS(empty_status) == 0);
    aimem_fixture_cleanup(source_dir);
    aimem_fixture_cleanup(target_dir);
    aimem_fixture_cleanup(partial_dir);
    aimem_fixture_cleanup(empty_dir);
    return 0;
}
