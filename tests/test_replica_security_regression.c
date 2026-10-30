#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

static bool delta_has_key(qihse_kv_delta_record_t* records, size_t count,
                          const char* key, bool tombstone, uint64_t* out_seq) {
    for (size_t i = 0; i < count; i++) {
        if (records[i].key && strcmp(records[i].key, key) == 0 &&
            records[i].tombstone == tombstone) {
            if (out_seq) *out_seq = records[i].change_seq;
            return true;
        }
    }
    return false;
}

static void flush_compaction_batch(qihse_kv_store_t* store, qihse_user_t* operator_user,
                                   unsigned first, unsigned count) {
    for (unsigned i = 0; i < count; i++) {
        char key[64], value[32];
        snprintf(key, sizeof(key), "vendor:7:compact-%u", first + i);
        snprintf(value, sizeof(value), "value-%u", first + i);
        assert(qihse_kv_set_user(store, key, value, 0u, 0u, operator_user));
        assert(qihse_kv_sync_store(store));
    }
}

static uint64_t test_fnv_update(uint64_t hash, const void* data, size_t len) {
    const unsigned char* p = data;
    for (size_t i = 0; i < len; i++) { hash ^= p[i]; hash *= 1099511628211ULL; }
    return hash;
}

static uint64_t fixture_hash(const char* path) {
    FILE* file = fopen(path, "rb");
    assert(file != NULL);
    uint64_t hash = 14695981039346656037ULL;
    unsigned char bytes[512];
    size_t n;
    while ((n = fread(bytes, 1u, sizeof(bytes), file)) != 0u)
        hash = test_fnv_update(hash, bytes, n);
    assert(!ferror(file));
    assert(fclose(file) == 0);
    return hash;
}

static void write_private_fixture(const char* path, const void* bytes, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    assert(fd >= 0);
    size_t done = 0u;
    while (done < len) {
        ssize_t n = write(fd, (const char*)bytes + done, len - done);
        assert(n > 0);
        done += (size_t)n;
    }
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
}

static void create_pending_install_fixture(const char* data_dir, const char* snapshot,
                                           size_t snapshot_len, uint64_t source_seq) {
    const char peer[] = "snapshot-peer", glob[] = "public:*";
    uint16_t peer_len = (uint16_t)(sizeof(peer) - 1u);
    uint16_t glob_len = (uint16_t)(sizeof(glob) - 1u);
    uint64_t image_hash = test_fnv_update(14695981039346656037ULL, snapshot, snapshot_len);
    uint64_t crc = 14695981039346656037ULL;
    crc = test_fnv_update(crc, "QRIM1", 5u);
    crc = test_fnv_update(crc, &peer_len, sizeof(peer_len));
    crc = test_fnv_update(crc, &glob_len, sizeof(glob_len));
    crc = test_fnv_update(crc, &source_seq, sizeof(source_seq));
    crc = test_fnv_update(crc, &image_hash, sizeof(image_hash));
    crc = test_fnv_update(crc, peer, peer_len); crc = test_fnv_update(crc, glob, glob_len);
    char image_path[512], meta_path[512];
    int a = snprintf(image_path, sizeof(image_path), "%s/replica-install.image", data_dir);
    int b = snprintf(meta_path, sizeof(meta_path), "%s/replica-install.meta", data_dir);
    assert(a > 0 && (size_t)a < sizeof(image_path) && b > 0 && (size_t)b < sizeof(meta_path));
    write_private_fixture(image_path, snapshot, snapshot_len);
    uint8_t meta[5u + sizeof(peer_len) + sizeof(glob_len) + 2u * sizeof(uint64_t) +
                 sizeof(peer) - 1u + sizeof(glob) - 1u + sizeof(crc)];
    size_t off = 0u;
#define APPEND_META(value) do { memcpy(meta + off, &(value), sizeof(value)); off += sizeof(value); } while (0)
    memcpy(meta + off, "QRIM1", 5u); off += 5u;
    APPEND_META(peer_len); APPEND_META(glob_len); APPEND_META(source_seq); APPEND_META(image_hash);
    memcpy(meta + off, peer, peer_len); off += peer_len;
    memcpy(meta + off, glob, glob_len); off += glob_len;
    APPEND_META(crc);
#undef APPEND_META
    assert(off == sizeof(meta));
    write_private_fixture(meta_path, meta, sizeof(meta));
}

int main(void) {
    const char* data_dir = getenv("QIHSE_REPLICA_SECURITY_DIR");
    assert(data_dir != NULL && *data_dir != '\0');
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ReplicaSecurityPass1!"));
    qihse_user_t* operator_user = qihse_auth_authenticate_id(0u, "ReplicaSecurityPass1!");
    assert(operator_user != NULL);
    qihse_user_t* low_user = qihse_auth_create_user(operator_user, 91u,
        QIHSE_ROLE_GUEST, 0u, 0u, "ReplicaGuestPass1!", false);
    assert(low_user != NULL);
    assert(qihse_auth_authenticate_id(91u, "ReplicaGuestPass1!") == low_user);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    assert(qihse_kv_set_user(store, "public:row", "public-value", 0u, 0u,
                             operator_user));
    assert(qihse_kv_set_user(store, "vendor:7:secret", "classified-value", 5u, 9u,
                             operator_user));
    assert(qihse_kv_get_user(store, "vendor:7:secret", low_user) == NULL);

    /* A zero baseline is durable and pins matching tombstones through
     * streaming compaction until source-side ACK reaches the delete. */
    assert(qihse_kv_replica_cursor_advance(store, "lagging-peer", "vendor:7:*",
                                          0u, operator_user));
    assert(qihse_kv_set_user(store, "vendor:7:pending-delete", "gone", 0u, 0u,
                             operator_user));
    assert(qihse_kv_sync_store(store));
    assert(qihse_kv_del_user(store, "vendor:7:pending-delete", operator_user));
    assert(qihse_kv_sync_store(store));
    flush_compaction_batch(store, operator_user, 0u, 14u);
    qihse_kv_sweep_expired(store); /* reaches the SSTable compaction threshold */
    qihse_kv_delta_record_t* delta = NULL; size_t delta_count = 0u;
    uint64_t resume = 0u, delete_seq = 0u;
    assert(qihse_kv_export_incremental_user(store, operator_user, 0u,
        &delta, &delta_count, &resume) == 0);
    assert(delta_has_key(delta, delta_count, "vendor:7:pending-delete", true,
                         &delete_seq));
    qihse_kv_delta_records_free(delta, delta_count);
    assert(qihse_kv_replica_cursor_advance(store, "lagging-peer", "vendor:7:*",
                                          delete_seq, operator_user));
    flush_compaction_batch(store, operator_user, 100u, 15u);
    qihse_kv_sweep_expired(store);
    delta = NULL; delta_count = 0u; resume = 0u;
    assert(qihse_kv_export_incremental_user(store, operator_user, 0u,
        &delta, &delta_count, &resume) == 0);
    assert(!delta_has_key(delta, delta_count, "vendor:7:pending-delete", true, NULL));
    qihse_kv_delta_records_free(delta, delta_count);

    uint64_t large_since = qihse_kv_change_seq(store);
    size_t large_len = 1024u * 1024u;
    char* large_value = malloc(large_len + 1u);
    assert(large_value != NULL);
    memset(large_value, 'L', large_len); large_value[large_len] = '\0';
    assert(qihse_kv_set_user(store, "vendor:7:large", large_value, 0u, 0u,
                             operator_user));
    delta = NULL; delta_count = 0u; resume = 0u;
    assert(qihse_kv_export_incremental_user_bounded(store, operator_user,
        "vendor:7:*", large_since, 1u, large_len + 4096u,
        &delta, &delta_count, &resume) == 0);
    assert(delta_count == 1u && strcmp(delta[0].key, "vendor:7:large") == 0 &&
           strlen(delta[0].value) == large_len && resume == delta[0].change_seq);
    qihse_kv_delta_records_free(delta, delta_count);
    free(large_value);

    /* Exercise the RESP replication boundary itself: a low-clearance user
     * cannot call DELTA or APPLY, and the protected payload appears in no
     * returned wire bytes. The no-QKP execute seam is intentionally denied
     * before touching the store. */
    const char* replicate_globs[] = {"vendor:7:*"};
    qihse_resp_server_config_t resp_config;
    qihse_resp_server_config_init(&resp_config);
    resp_config.store = store;
    resp_config.replicate_globs = replicate_globs;
    resp_config.replicate_glob_count = 1u;
    resp_config.enable_uwp_bridge = true;
    qihse_resp_server_t* resp = qihse_resp_server_create(&resp_config);
    assert(resp != NULL);
    const char* delta_parts[] = {"REPL.DELTA", "vendor:7:*", "0", "3"};
    qihse_resp_arg_t delta_args[4];
    for (size_t i = 0; i < 4u; i++) {
        delta_args[i].data = (const uint8_t*)delta_parts[i];
        delta_args[i].len = strlen(delta_parts[i]);
    }
    uint8_t* wire_reply = NULL; size_t wire_reply_len = 0u;
    assert(qihse_resp_server_execute(resp, low_user, 4u, delta_args,
                                     &wire_reply, &wire_reply_len));
    assert(wire_reply_len > 0u && memmem(wire_reply, wire_reply_len,
                                         "classified-value", 16u) == NULL);
    assert(memmem(wire_reply, wire_reply_len, "NOPERM", 6u) != NULL);
    free(wire_reply);
    const char* apply_parts[] = {"REPL.APPLY", "1", "vendor:7:*", "101", "S",
        "0", "0", "0", "vendor:7:inject", "classified-value"};
    qihse_resp_arg_t apply_args[10];
    for (size_t i = 0; i < 10u; i++) {
        apply_args[i].data = (const uint8_t*)apply_parts[i];
        apply_args[i].len = strlen(apply_parts[i]);
    }
    assert(qihse_resp_server_execute(resp, low_user, 10u, apply_args,
                                     &wire_reply, &wire_reply_len));
    assert(wire_reply_len > 0u && memmem(wire_reply, wire_reply_len,
                                         "classified-value", 16u) == NULL);
    assert(memmem(wire_reply, wire_reply_len, "NOPERM", 6u) != NULL);
    free(wire_reply);
    assert(qihse_kv_get_user(store, "vendor:7:inject", operator_user) == NULL);
    qihse_resp_server_destroy(resp);

    qihse_kv_replica_record_t denied = {
        .key = "vendor:7:secret", .value = "attacker-value", .change_seq = 100u,
        .classification = 5u, .sci_compartment = 9u, .expire_time_ms = 0u,
        .tombstone = false
    };
    uint64_t before = qihse_kv_change_seq(store);
    assert(!qihse_kv_apply_replica_record(store, &denied, low_user));
    assert(qihse_kv_change_seq(store) == before);
    assert(!qihse_kv_replica_cursor_advance(store, "upstream", "vendor:7:*",
                                            100u, low_user));

    qihse_kv_replica_snapshot_t* snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(store, low_user, "vendor:7:*",
                                            &snapshot) == -2);
    assert(snapshot == NULL);
    assert(qihse_kv_set_user(store, "public:protected", "protected-image", 5u, 9u,
                             operator_user));
    assert(qihse_kv_replica_snapshot_create(store, operator_user, "public:*",
                                            &snapshot) == 0);
    uint64_t size = qihse_kv_replica_snapshot_size(snapshot);
    assert(size > 0u && size < 4096u);
    char bytes[4096]; size_t read_size = 0u;
    assert(qihse_kv_replica_snapshot_read(snapshot, 0u, bytes, (size_t)size,
                                          &read_size));
    assert(read_size == (size_t)size);
    bytes[read_size] = '\0';
    assert(strstr(bytes, "public:row") != NULL);
    assert(strstr(bytes, "vendor:7:secret") == NULL);
    uint64_t snapshot_seq = qihse_kv_change_seq(store);
    char snapshot_path[512];
    int snapshot_path_len = snprintf(snapshot_path, sizeof(snapshot_path),
                                     "%s/replica-fixture.qkv", data_dir);
    assert(snapshot_path_len > 0 && (size_t)snapshot_path_len < sizeof(snapshot_path));
    int snapshot_fd = open(snapshot_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(snapshot_fd >= 0);
    size_t snapshot_written = 0u;
    while (snapshot_written < read_size) {
        ssize_t n = write(snapshot_fd, bytes + snapshot_written, read_size - snapshot_written);
        assert(n > 0);
        snapshot_written += (size_t)n;
    }
    assert(close(snapshot_fd) == 0);
    qihse_kv_replica_snapshot_destroy(snapshot);

    assert(qihse_kv_clear_user(store, operator_user) > 0u);
    assert(qihse_kv_count_user(store, operator_user) == 0u);
    assert(qihse_kv_sync_store(store));
    assert(qihse_kv_store_enable_replica_read_only(store));
    bool snapshot_installed = false;
    assert(qihse_kv_replica_snapshot_install(store, snapshot_path, operator_user,
        "snapshot-peer", "public:*", snapshot_seq));
    assert(qihse_kv_replica_snapshot_installed(store, "snapshot-peer", "public:*",
        operator_user, &snapshot_installed));
    assert(snapshot_installed);
    char* installed_public = qihse_kv_get_user(store, "public:row", operator_user);
    assert(installed_public && strcmp(installed_public, "public-value") == 0);
    free(installed_public);
    assert(qihse_kv_get_user(store, "vendor:7:secret", operator_user) == NULL);
    assert(!qihse_kv_set_user(store, "public:write", "blocked", 0u, 0u,
                              operator_user));
    denied.change_seq = 100u;
    assert(qihse_kv_apply_replica_record(store, &denied, operator_user));
    assert(qihse_kv_replica_cursor_advance(store, "upstream", "vendor:7:*",
                                           100u, operator_user));
    uint64_t cursor = 0u;
    assert(qihse_kv_replica_cursor_get(store, "upstream", "vendor:7:*",
                                       operator_user, &cursor));
    assert(cursor == 100u);
    qihse_kv_replica_record_t current_protected = {
        .key = "public:row", .value = "current-protected-value", .change_seq = 101u,
        .classification = 7u, .sci_compartment = 11u, .expire_time_ms = 0u,
        .tombstone = false
    };
    assert(qihse_kv_apply_replica_record(store, &current_protected, operator_user));
    assert(qihse_kv_sync_store(store));
    qihse_kv_store_destroy(store);
    create_pending_install_fixture(data_dir, bytes, read_size, snapshot_seq);
    /* Incoming-image clearance is insufficient to replace a more restricted
     * current row, even when the incoming row itself is unclassified. */
    qihse_user_t* image_reader = qihse_auth_create_user(operator_user, 93u,
        QIHSE_ROLE_ANALYST, 5u, 9u, "ImageReaderPass1!", false);
    assert(image_reader != NULL);
    assert(qihse_auth_authenticate_id(93u, "ImageReaderPass1!") == image_reader);
    char current_wal[512];
    snprintf(current_wal, sizeof(current_wal), "%s/wal.log", data_dir);
    uint64_t current_wal_hash = fixture_hash(current_wal);
    assert(qihse_kv_store_create_user(image_reader) == NULL);
    assert(fixture_hash(current_wal) == current_wal_hash);
    /* Model process death during the install's SSTable/WAL replacement: the
     * durable intent and image exist, a candidate is left behind, multiple
     * old SSTables remain, and the WAL may contain pre-install bytes. Startup
     * must rebuild from the authenticated image before scanning any of them. */
    char stage_path[512];
    snprintf(stage_path, sizeof(stage_path), "%s/replica-install.candidate", data_dir);
    write_private_fixture(stage_path, "partial-candidate", 17u);
    snprintf(stage_path, sizeof(stage_path), "%s/sstable_0.db", data_dir);
    write_private_fixture(stage_path, "old-sstable-zero", 16u);
    snprintf(stage_path, sizeof(stage_path), "%s/sstable_1.db", data_dir);
    write_private_fixture(stage_path, "old-sstable-one", 15u);
    snprintf(stage_path, sizeof(stage_path), "%s/wal.log", data_dir);
    write_private_fixture(stage_path, "old-wal-record", 14u);
    uint64_t old_wal_hash = fixture_hash(stage_path);
    char old_sstable[512];
    snprintf(old_sstable, sizeof(old_sstable), "%s/sstable_0.db", data_dir);
    uint64_t old_sstable_hash = fixture_hash(old_sstable);
    assert(qihse_kv_store_create() == NULL);
    assert(qihse_kv_store_create_user(NULL) == NULL);
    assert(qihse_kv_store_create_user(low_user) == NULL);
    qihse_user_t* revoked = qihse_auth_create_user(operator_user, 92u,
        QIHSE_ROLE_ANALYST, 5u, 9u, "RevokedReplicaPass1!", false);
    assert(revoked != NULL);
    assert(qihse_auth_authenticate_id(92u, "RevokedReplicaPass1!") == revoked);
    assert(qihse_auth_destroy_user(operator_user, 92u));
    assert(qihse_kv_store_create_user(revoked) == NULL);
    char pending_meta_path[512], pending_image_path[512];
    snprintf(pending_meta_path, sizeof(pending_meta_path), "%s/replica-install.meta", data_dir);
    snprintf(pending_image_path, sizeof(pending_image_path), "%s/replica-install.image", data_dir);
    assert(access(pending_meta_path, F_OK) == 0);
    assert(access(pending_image_path, F_OK) == 0);
    assert(fixture_hash(pending_image_path) ==
        test_fnv_update(14695981039346656037ULL, bytes, read_size));
    assert(fixture_hash(current_wal) == old_wal_hash);
    assert(fixture_hash(old_sstable) == old_sstable_hash);
    store = qihse_kv_store_create_user(operator_user);
    assert(store != NULL);
    uint64_t persisted_ack = 0u;
    assert(qihse_kv_replica_cursor_get(store, "lagging-peer", "vendor:7:*",
                                       operator_user, &persisted_ack));
    assert(persisted_ack == delete_seq);
    assert(qihse_kv_replica_snapshot_installed(store, "snapshot-peer", "public:*",
        operator_user, &snapshot_installed));
    assert(snapshot_installed);
    char* recovered_public = qihse_kv_get_user(store, "public:row", operator_user);
    assert(recovered_public && strcmp(recovered_public, "public-value") == 0);
    free(recovered_public);
    char* recovered_protected = qihse_kv_get_user(store, "public:protected", operator_user);
    assert(recovered_protected && strcmp(recovered_protected, "protected-image") == 0);
    free(recovered_protected);
    qihse_kv_record_meta_t recovered_meta;
    assert(qihse_kv_meta_user(store, "public:protected", operator_user, &recovered_meta));
    assert(recovered_meta.classification == 5u && recovered_meta.sci_compartment == 9u);
    assert(qihse_kv_get_user(store, "public:protected", low_user) == NULL);
    assert(qihse_kv_replica_cursor_get(store, "snapshot-peer", "public:*",
                                       operator_user, &cursor));
    assert(cursor == snapshot_seq);
    assert(access(pending_meta_path, F_OK) != 0 && errno == ENOENT);
    assert(access(pending_image_path, F_OK) != 0 && errno == ENOENT);
    snprintf(stage_path, sizeof(stage_path), "%s/replica-install.candidate", data_dir);
    assert(access(stage_path, F_OK) != 0 && errno == ENOENT);
    snprintf(stage_path, sizeof(stage_path), "%s/sstable_1.db", data_dir);
    assert(access(stage_path, F_OK) != 0 && errno == ENOENT);
    qihse_kv_store_destroy(store);
    puts("[ALL PASS] QIHSE replica security regression");
    return 0;
}
