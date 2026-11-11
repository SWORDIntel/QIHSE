#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

/* The receipt verifier is deliberately a test double. Production verifies
 * the pinned QKP peer's authenticated, phase-specific receipt. */
enum { PREPARED = 1, SEALED = 2, COMMITTED = 3, ABORTED = 4 };
typedef struct {
    int phase;
    qihse_kv_ct_target_receipt_claim_t expected;
} receipt_fixture_t;

static bool verified_phase(const qihse_kv_ct_target_receipt_claim_t* claim,
                           void* opaque, int required_phase) {
    receipt_fixture_t* fixture = opaque;
    return fixture && claim &&
        fixture->phase == required_phase &&
        memcmp(claim, &fixture->expected, sizeof(*claim)) == 0;
}

static bool verify_prepared(const qihse_kv_ct_target_receipt_claim_t* claim,
                            void* opaque) {
    return verified_phase(claim, opaque, PREPARED);
}

static bool verify_aborted(const qihse_kv_ct_target_receipt_claim_t* claim,
                           void* opaque) {
    return verified_phase(claim, opaque, ABORTED);
}

static bool verify_sealed(const qihse_kv_ct_target_receipt_claim_t* claim,
                          void* opaque) {
    return verified_phase(claim, opaque, SEALED);
}

static bool verify_committed(const qihse_kv_ct_target_receipt_claim_t* claim,
                             void* opaque) {
    return verified_phase(claim, opaque, COMMITTED);
}

static const char* source_key = "commons/ct2-source-high";
static char stale_key[96], outside_key[96], local_key[96];
static uint16_t slot, transfer_first, transfer_last;
static bool large_transfer_mode;

enum { LARGE_TRANSFER_ROWS = 4097, LARGE_TRANSFER_VALUE_BYTES = 16380 };

static bool count_key(const char* key, const char* value, void* user_data) {
    (void)value;
    if (strcmp(key, source_key) == 0) (*(size_t*)user_data)++;
    return true;
}

static bool count_large_keys(const char* key, const char* value, void* user_data) {
    (void)value;
    if (strncmp(key, "commons/ctlarge-", 16u) == 0) (*(size_t*)user_data)++;
    return true;
}

static void select_keys(void) {
    large_transfer_mode = getenv("QIHSE_CT_LARGE_TRANSFER") != NULL;
    slot = qihse_cluster_key_slot(source_key, strlen(source_key));
    transfer_first = large_transfer_mode ? 0u : slot;
    transfer_last = large_transfer_mode ? (QIHSE_CLUSTER_SLOT_COUNT - 1u) : slot;
    bool same = false, different = false;
    for (unsigned i = 0u; i < 100000u && (!same || !different); i++) {
        char candidate[96];
        int n = snprintf(candidate, sizeof(candidate), "commons/ct2-%u", i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        uint16_t candidate_slot = qihse_cluster_key_slot(candidate,
                                                          (size_t)n);
        if (!same && candidate_slot == slot) {
            strcpy(stale_key, candidate); same = true;
        } else if (!different && candidate_slot != slot) {
            strcpy(outside_key, candidate); different = true;
        }
    }
    assert(same && different);
    bool found_local = false;
    for (unsigned i = 0; i < 1000000u && !found_local; i++) {
        snprintf(local_key, sizeof local_key, "t:7/aimem:local-%u", i);
        found_local = qihse_cluster_key_slot(local_key, strlen(local_key)) == slot;
    }
    assert(found_local);
}

static void seed_large_rows(qihse_kv_store_t* store, qihse_user_t* op) {
    char* value = malloc(LARGE_TRANSFER_VALUE_BYTES + 1u);
    assert(value);
    memset(value, 'L', LARGE_TRANSFER_VALUE_BYTES);
    value[LARGE_TRANSFER_VALUE_BYTES] = '\0';
    const size_t batch_sizes[] = {4000u, LARGE_TRANSFER_ROWS - 4000u};
    size_t ordinal = 0u;
    for (size_t b = 0u; b < sizeof(batch_sizes) / sizeof(batch_sizes[0]); b++) {
        size_t count = batch_sizes[b];
        qihse_kv_batch_set_record_t* records = calloc(count, sizeof(*records));
        char** keys = calloc(count, sizeof(*keys));
        assert(records && keys);
        for (size_t i = 0u; i < count; i++, ordinal++) {
            char key[64];
            int n = snprintf(key, sizeof(key), "commons/ctlarge-%04zu", ordinal);
            assert(n > 0 && (size_t)n < sizeof(key));
            keys[i] = strdup(key);
            assert(keys[i]);
            records[i] = (qihse_kv_batch_set_record_t){
                .key = keys[i], .value = value,
                .classification = 4u, .sci_compartment = 2u
            };
        }
        assert(qihse_kv_set_batch_durable_user(store, records, count, op));
        for (size_t i = 0u; i < count; i++) free(keys[i]);
        free(keys);
        free(records);
    }
    free(value);
}

static void path_join(char out[4096], const char* dir, const char* leaf) {
    int n = snprintf(out, 4096u, "%s/%s", dir, leaf);
    assert(n > 0 && n < 4096);
}

static void write_claim(const char* path,
    const qihse_kv_ct_target_receipt_claim_t* claim) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    assert(fd >= 0);
    assert(write(fd, claim, sizeof(*claim)) == (ssize_t)sizeof(*claim));
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
}

static qihse_kv_ct_target_receipt_claim_t read_claim(const char* path) {
    qihse_kv_ct_target_receipt_claim_t claim = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    assert(read(fd, &claim, sizeof(claim)) == (ssize_t)sizeof(claim));
    unsigned char extra;
    assert(read(fd, &extra, 1u) == 0);
    assert(close(fd) == 0);
    return claim;
}

static qihse_kv_ct_target_receipt_claim_t claim_from_proof(
    qihse_kv_store_t* store, qihse_user_t* op,
    qihse_kv_ct_proof_t* proof) {
    qihse_kv_ct_target_receipt_claim_t claim = {0};
    const char *transfer = NULL, *source = NULL, *target = NULL, *generation = NULL;
    uint16_t first = 0u, last = 0u;
    uint64_t source_cut = 0u, target_position = 0u;
    assert(qihse_kv_ct_proof_fields(store, op, op, proof, &transfer, &source,
        &target, &generation, &first, &last, &source_cut,
        &target_position, claim.range_checksum));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "%s", transfer);
    snprintf(claim.source_id, sizeof(claim.source_id), "%s", source);
    snprintf(claim.target_id, sizeof(claim.target_id), "%s", target);
    snprintf(claim.generation, sizeof(claim.generation), "%s", generation);
    claim.first_slot = (uint16_t)first;
    claim.last_slot = (uint16_t)last;
    claim.source_cut = source_cut;
    claim.target_durable_cursor = target_position;
    return claim;
}

static qihse_kv_store_t* open_store(qihse_user_t* op) {
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    return store;
}

static void admitted_source(qihse_kv_store_t* store, qihse_user_t* op,
    const char* peer, const char* generation) {
    qihse_kv_ct_source_status_t status = {0};
    assert(qihse_kv_ct_source_status(store, op, &status));
    assert(qihse_kv_ct_source_reconcile(store, op, peer, generation,
                                        status.baseline_digest,
                                        status.durable_lsn));
}

static void check_value(qihse_kv_store_t* store, qihse_user_t* user,
                        const char* key, const char* expected) {
    char* value = qihse_kv_get_user(store, key, user);
    if (expected) assert(value && strcmp(value, expected) == 0);
    else assert(!value);
    free(value);
}

static void owner_backup_busy(qihse_kv_store_t* store, qihse_user_t* op) {
    if (large_transfer_mode) return;
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    errno = 0;
    assert(qihse_kv_ct_owner_data_snapshot_create(store, op, &snapshot) == -1);
    assert(errno == EBUSY && !snapshot);
}

/* Decode the real authorized image to check rows, labels and retained deletes,
 * while verifying that snapshot creation does not consume terminal evidence. */
static void owner_backup_check(qihse_kv_store_t* store, qihse_user_t* op,
    qihse_user_t* low, bool has_source, const char* source_value,
    const char* local_value, bool has_outside) {
    if (large_transfer_mode) return;
    const char* deleted = "t:7/aimem:backup-deleted";
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    qihse_kv_ct_writer_scope_t* scope = NULL;
    qihse_kv_ct_source_status_t status = {0};
    assert(qihse_kv_ct_owner_token_get(store, op, token));
    assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
    assert(qihse_kv_set_user(store, deleted, "deleted-secret", 4u, 2u, op));
    assert(qihse_kv_del_user(store, deleted, op));
    assert(qihse_kv_ct_source_status(store, op, &status));
    assert(qihse_kv_ct_source_ack(store, op, status.successor_id,
        status.generation, status.durable_lsn));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    assert(qihse_kv_ct_owner_data_snapshot_create(store, low, &snapshot) == -2);
    assert(!snapshot);
    qihse_kv_ct_transfer_status_detail_t before = {0}, after = {0};
    assert(qihse_kv_ct_transfer_status_detail(store, op, &before));
    int rc = qihse_kv_ct_owner_data_snapshot_create(store, op, &snapshot);
    if (rc != 0) fprintf(stderr,
        "owner backup failed: fence=%u phase=%u rc=%d errno=%d\n",
        before.base.fence_state, before.base.transfer_phase, rc, errno);
    assert(rc == 0 && snapshot);
    assert(qihse_kv_ct_transfer_status_detail(store, op, &after));
    assert(memcmp(&before, &after, sizeof(before)) == 0);
    uint64_t bytes = 0u;
    assert(qihse_kv_replica_snapshot_size(snapshot, op, &bytes));
    FILE* image = tmpfile();
    assert(image);
    for (uint64_t offset = 0u; offset < bytes;) {
        unsigned char chunk[1024]; size_t got = 0u;
        size_t want = bytes - offset < sizeof(chunk)
            ? (size_t)(bytes - offset) : sizeof(chunk);
        assert(qihse_kv_replica_snapshot_read(snapshot, op, offset, chunk,
            want, &got) && got == want);
        assert(fwrite(chunk, 1u, got, image) == got);
        offset += got;
    }
    qihse_kv_replica_snapshot_destroy(snapshot);
    rewind(image);
    qihse_kv_store_t* decoded = qihse_kv_open_snapshot_user(image, op,
        128u * 1024u * 1024u, 10000u);
    assert(decoded && fclose(image) == 0);
    char* value = NULL; qihse_kv_record_meta_t meta = {0};
    assert(qihse_kv_snapshot_get_record_user(decoded, deleted, op, &value, &meta));
    assert(value && !*value && (meta.flags & 1u) &&
        meta.classification == 4u && meta.sci_compartment == 2u);
    free(value); value = NULL;
    assert(qihse_kv_snapshot_get_record_user(decoded, local_key, op, &value, &meta));
    assert(value && !strcmp(value, local_value) && meta.classification == 4u &&
        meta.sci_compartment == 2u);
    free(value); value = NULL;
    assert(qihse_kv_snapshot_get_record_user(decoded, source_key, op,
        &value, &meta) == has_source);
    if (has_source) assert(value && !strcmp(value, source_value) &&
        meta.classification == 4u && meta.sci_compartment == 2u);
    free(value); value = NULL;
    assert(qihse_kv_snapshot_get_record_user(decoded, outside_key, op,
        &value, &meta) == has_outside);
    if (has_outside) assert(value && !strcmp(value, "keep-outside"));
    free(value); value = NULL;
    assert(!qihse_kv_snapshot_get_record_user(decoded, local_key, low, &value, &meta));
    assert(!value);
    qihse_kv_store_destroy(decoded);
}

static void child_phase(const char* phase, const char* data_dir,
                        const char* shared_dir) {
    bool reverse = strncmp(phase, "reverse-", 8u) == 0;
    bool abort_round = strncmp(phase, "abort-", 6u) == 0;
    const char* step = reverse ? phase + 8u : abort_round ? phase + 6u : phase;
    const char* source_id = reverse ? "target:1" : "source:1";
    const char* target_id = reverse ? "source:1" : "target:1";
    const char* source_peer = reverse ? "target-successor:1" : "source-successor:1";
    const char* target_peer = reverse ? "source-successor:1" : "target-successor:1";
    const char* source_generation = reverse ? "target-gen:1" : "source-gen:1";
    const char* target_generation = reverse ? "source-gen:1" : "target-gen:1";
    const char* transfer_id = abort_round ? "abort:1" : reverse ? "transfer:2" : "transfer:1";
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtTransferOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u,
                                                   "CtTransferOperator1!");
    assert(op);
    qihse_user_t* low = qihse_auth_authenticate_id(8301u,
                                                   "CtTransferLow1!");
    if (!low) low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
                                           0u, 0u, "CtTransferLow1!", false);
    assert(low);
    select_keys();
    qihse_kv_store_t* store = open_store(op);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    char image_path[4096], prepared_path[4096], sealed_path[4096];
    path_join(image_path, shared_dir, reverse ? "reverse-range.qfs" : "range.qfs");
    path_join(prepared_path, shared_dir,
              reverse ? "reverse-prepared.claim" : "prepared.claim");
    path_join(sealed_path, shared_dir,
              reverse ? "reverse-sealed.claim" : "sealed.claim");

    if (strcmp(step, "source-setup") == 0 ||
        strcmp(step, "target-setup") == 0) {
        bool source = strcmp(step, "source-setup") == 0;
        if (source) {
            assert(qihse_kv_set_user(store, source_key, "source-secret",
                                     4u, 2u, op));
            if (large_transfer_mode) seed_large_rows(store, op);
            check_value(store, low, source_key, NULL);
        } else {
            assert(qihse_kv_set_user(store, stale_key, "stale-secret",
                                     4u, 2u, op));
            assert(qihse_kv_set_user(store, outside_key, "keep-outside",
                                     0u, 0u, op));
            check_value(store, low, stale_key, NULL);
        }
        assert(qihse_kv_set_user(store, local_key,
            source ? "source-local-memory" : "target-local-memory", 4u, 2u, op));
        const char* id = source ? "source:1" : "target:1";
        const char* peer = source ? "source-successor:1" : "target-successor:1";
        const char* generation = source ? "source-gen:1" : "target-gen:1";
        assert(qihse_kv_ct_source_enable(store, op, id, peer, generation,
                                         NULL, 128u * 1024u * 1024u));
        qihse_kv_replica_snapshot_t* baseline = NULL;
        uint64_t baseline_seq = 0u;
        unsigned char baseline_digest[32];
        assert(qihse_kv_ct_source_baseline_snapshot_create(store, op,
            &baseline, &baseline_seq, baseline_digest) == 0);
        assert(baseline);
        qihse_kv_replica_snapshot_destroy(baseline);
        assert(qihse_kv_ct_source_reconcile(store, op, peer, generation,
                                            baseline_digest, 0u));
    } else if (strcmp(step, "source-export") == 0) {
        admitted_source(store, op, source_peer, source_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        if (!reverse) {
            qihse_kv_ct_writer_scope_t* scope = NULL;
            assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
            assert(qihse_kv_set_user(store, stale_key, "source-ttl", 4u, 2u, op));
            assert(qihse_kv_expire(store, stale_key, 1200u, op));
            qihse_kv_ct_source_status_t status = {0};
            assert(qihse_kv_ct_source_status(store, op, &status));
            assert(qihse_kv_ct_source_ack(store, op, source_peer,
                source_generation, status.durable_lsn));
            assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
        }
        uint64_t cut = UINT64_MAX;
        assert(qihse_kv_ct_fence_range(store, op, transfer_id, transfer_first, transfer_last,
                                        token, &cut));
        owner_backup_busy(store, op);
        qihse_kv_ct_range_snapshot_t* denied = NULL;
        uint64_t denied_cut = 0u;
        unsigned char denied_digest[32];
        assert(qihse_kv_ct_range_export(store, low, op, transfer_id,
            target_id, source_generation, transfer_first, transfer_last, token, &denied,
            &denied_cut, denied_digest) != 0);
        assert(!denied && denied_cut == 0u);
        assert(qihse_kv_ct_range_export(store, op, low, transfer_id,
            target_id, source_generation, transfer_first, transfer_last, token, &denied,
            &denied_cut, denied_digest) == -2);
        assert(!denied && denied_cut == 0u);
        qihse_kv_ct_range_snapshot_t* range = NULL;
        unsigned char image_digest[32];
        assert(qihse_kv_ct_range_export(store, op, op, transfer_id,
            target_id, source_generation, transfer_first, transfer_last, token, &range,
            &cut, image_digest) == 0);
        assert(range);
        uint64_t bytes = 0u;
        assert(!qihse_kv_ct_range_snapshot_size(range, low, &bytes));
        assert(qihse_kv_ct_range_snapshot_size(range, op, &bytes) && bytes);
        if (large_transfer_mode) {
            assert(bytes > QIHSE_KV_DURABLE_BATCH_MAX_BYTES);
            fprintf(stderr, "large CT2 source image: %llu bytes\n",
                    (unsigned long long)bytes);
        }
        int fd = open(image_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                    O_NOFOLLOW, 0600);
        assert(fd >= 0);
        for (uint64_t off = 0u; off < bytes;) {
            unsigned char chunk[4096];
            size_t n = 0u;
            assert(qihse_kv_ct_range_snapshot_read(range, op, off, chunk,
                                                    sizeof(chunk), &n));
            assert(n && write(fd, chunk, n) == (ssize_t)n);
            off += n;
        }
        assert(fsync(fd) == 0 && close(fd) == 0);
        qihse_kv_ct_range_snapshot_destroy(range);
        char digest_path[4096];
        path_join(digest_path, shared_dir,
                  reverse ? "reverse-image.sha256" : "image.sha256");
        fd = open(digest_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                  O_NOFOLLOW, 0600);
        assert(fd >= 0);
        assert(write(fd, image_digest, 32u) == 32);
        assert(fsync(fd) == 0 && close(fd) == 0);
        qihse_kv_ct_proof_t* proof =
            qihse_kv_ct_source_transfer_proof_create(store, op, op,
                transfer_id, source_id, target_id, source_generation,
                transfer_first, transfer_last, cut);
        assert(proof && qihse_kv_ct_proof_validate(store, op, op, proof));
        qihse_kv_ct_target_receipt_claim_t prepared =
            claim_from_proof(store, op, proof);
        assert(prepared.source_cut == cut);
        write_claim(prepared_path, &prepared);
        qihse_kv_ct_proof_destroy(proof);
    } else if (strcmp(step, "source-export-retry") == 0) {
        admitted_source(store, op, source_peer, source_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_sweep_expired(store);
        qihse_kv_ct_target_receipt_claim_t prepared = read_claim(prepared_path);
        qihse_kv_ct_range_snapshot_t* retry = NULL;
        uint64_t retry_cut = UINT64_MAX, retry_bytes = 0u;
        unsigned char retry_sha[32], first_sha[32];
        assert(qihse_kv_ct_range_export(store, op, op, transfer_id,
            target_id, source_generation, transfer_first, transfer_last, token, &retry,
            &retry_cut, retry_sha) == 0);
        assert(retry && retry_cut == prepared.source_cut);
        assert(qihse_kv_ct_range_snapshot_size(retry, op, &retry_bytes));
        char digest_path[4096];
        path_join(digest_path, shared_dir, "image.sha256");
        int fd = open(digest_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && read(fd, first_sha, sizeof(first_sha)) == 32);
        assert(close(fd) == 0);
        assert(memcmp(retry_sha, first_sha, 32u) == 0);
        struct stat original;
        assert(stat(image_path, &original) == 0);
        assert(retry_bytes == (uint64_t)original.st_size);
        fd = open(image_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0);
        for (uint64_t off = 0u; off < retry_bytes;) {
            unsigned char first[4096], second[4096];
            size_t n = 0u;
            assert(qihse_kv_ct_range_snapshot_read(retry, op, off, second,
                                                    sizeof(second), &n));
            assert(n > 0u && pread(fd, first, n, (off_t)off) == (ssize_t)n);
            assert(memcmp(first, second, n) == 0);
            off += n;
        }
        assert(close(fd) == 0);
        qihse_kv_ct_proof_t* proof =
            qihse_kv_ct_source_transfer_proof_create(store, op, op,
                transfer_id, source_id, target_id, source_generation,
                transfer_first, transfer_last, retry_cut);
        assert(proof);
        qihse_kv_ct_target_receipt_claim_t again =
            claim_from_proof(store, op, proof);
        assert(memcmp(again.range_checksum, prepared.range_checksum, 32u) == 0);
        qihse_kv_ct_proof_destroy(proof);
        qihse_kv_ct_range_snapshot_destroy(retry);
    } else if (strcmp(step, "target-prepare") == 0) {
        admitted_source(store, op, target_peer, target_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_ct_target_receipt_claim_t prepared = read_claim(prepared_path);
        receipt_fixture_t receipt = {PREPARED, prepared};
        uint64_t cut = 0u;
        assert(qihse_kv_ct_target_prepare(store, op, &prepared,
            verify_prepared, &receipt, token, &cut));
        owner_backup_busy(store, op);
    } else if (strcmp(step, "source-abort") == 0) {
        admitted_source(store, op, source_peer, source_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        owner_backup_busy(store, op);
        assert(qihse_kv_ct_fence_finish(store, op, transfer_id, false, token));
        owner_backup_check(store, op, low, true, "source-secret",
            "source-local-memory", false);
    } else if (strcmp(step, "target-abort") == 0 ||
               strcmp(step, "target-abort-reopen") == 0) {
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_ct_target_receipt_claim_t prepared = read_claim(prepared_path);
        receipt_fixture_t receipt = {ABORTED, prepared};
        assert(qihse_kv_ct_target_abort(store, op, &prepared,
            verify_aborted, &receipt, token));
        admitted_source(store, op, target_peer, target_generation);
        owner_backup_check(store, op, low, false, NULL,
            "target-local-memory", true);
        assert(qihse_kv_ct_target_abort(store, op, &prepared,
            verify_aborted, &receipt, token));
    } else if (strcmp(step, "target-import") == 0 ||
               strcmp(step, "target-import-crash") == 0) {
        qihse_kv_ct_transfer_status_detail_t transfer_status = {0};
        assert(qihse_kv_ct_transfer_status_detail(store, op, &transfer_status));
        /* Once a target fence is durable, its normal CT1 admission reconcile
         * is intentionally held until import completes; resume the exact
         * transfer without trying to clear that recovery barrier. */
        if (transfer_status.base.transfer_phase == 0u)
            admitted_source(store, op, target_peer, target_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_ct_target_receipt_claim_t prepared = read_claim(prepared_path);
        receipt_fixture_t source_receipt = {PREPARED, prepared};
        uint64_t local_cut = UINT64_MAX;
        receipt_fixture_t refused = {0, prepared};
        assert(!qihse_kv_ct_target_prepare(store, op, &prepared,
            verify_prepared, &refused, token, &local_cut));
        assert(qihse_kv_ct_target_prepare(store, op, &prepared,
            verify_prepared, &source_receipt, token, &local_cut));
        owner_backup_busy(store, op);
        if (large_transfer_mode) {
            /* Preparation fences the whole destination range. Neither point
             * reads nor enumeration/replica readers may observe staged data. */
            check_value(store, op, "commons/ctlarge-0000", NULL);
            size_t staged_visible = 0u;
            (void)qihse_kv_foreach_user(store, op, count_large_keys,
                                        &staged_visible);
            assert(staged_visible == 0u);
        }
        uint64_t target_position = 0u;
        assert(!qihse_kv_ct_range_import(store, low, op, transfer_id,
            source_id, source_generation, transfer_first, transfer_last, prepared.source_cut,
            image_path, prepared.range_checksum, token, &target_position));
        /* The QFS byte hash is distinct from the canonical range seal. */
        unsigned char image_sha[32];
        char digest_path[4096];
        path_join(digest_path, shared_dir,
                  reverse ? "reverse-image.sha256" : "image.sha256");
        int digest_fd = open(digest_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(digest_fd >= 0);
        assert(read(digest_fd, image_sha, 32u) == 32);
        assert(close(digest_fd) == 0);
        if (strcmp(step, "target-import-crash") == 0) {
#ifdef QIHSE_AIMEM_DURABILITY_TEST
            /* Fail after the first complete QKV6 group reached the WAL, but
             * before its progress tuple is published. The next process must
             * recover that group and resume at the next frame exactly once. */
            assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-after-group-fsync", 1) == 0);
            assert(!qihse_kv_ct_range_import(store, op, op, transfer_id,
                source_id, source_generation, transfer_first, transfer_last,
                prepared.source_cut, image_path, image_sha, token,
                &target_position));
            _exit(0);
#else
            assert(!"target-import-crash needs QIHSE_AIMEM_DURABILITY_TEST");
#endif
        }
        assert(!qihse_kv_ct_range_import(store, op, low, transfer_id,
            source_id, source_generation, transfer_first, transfer_last, prepared.source_cut,
            image_path, image_sha, token, &target_position));
        assert(qihse_kv_ct_range_import(store, op, op, transfer_id,
            source_id, source_generation, transfer_first, transfer_last, prepared.source_cut,
            image_path, image_sha, token, &target_position));
        assert(target_position > local_cut);
        owner_backup_busy(store, op);
        if (large_transfer_mode) {
            assert(target_position - local_cut == 2u);
            fprintf(stderr, "large CT2 target durable groups: %llu\n",
                    (unsigned long long)(target_position - local_cut));
        }
        assert(qihse_kv_ct_range_import(store, op, op, transfer_id,
            source_id, source_generation, transfer_first, transfer_last, prepared.source_cut,
            image_path, image_sha, token, &target_position));
        assert(qihse_kv_ct_source_ack(store, op, target_peer,
                                       target_generation, target_position));
        if (large_transfer_mode) {
            check_value(store, op, "commons/ctlarge-0000", NULL);
            size_t staged_visible = 0u;
            (void)qihse_kv_foreach_user(store, op, count_large_keys,
                                        &staged_visible);
            assert(staged_visible == 0u);
        }
        qihse_kv_sweep_expired(store);
        qihse_kv_ct_proof_t* seal = qihse_kv_ct_target_seal_create(store,
            op, op, transfer_id, source_id, target_id, source_generation,
            transfer_first, transfer_last, prepared.source_cut);
        assert(seal && qihse_kv_ct_proof_validate(store, op, op, seal));
        qihse_kv_ct_target_receipt_claim_t sealed =
            claim_from_proof(store, op, seal);
        assert(memcmp(sealed.range_checksum, prepared.range_checksum,
                      32u) == 0);
        assert(sealed.target_durable_cursor == target_position);
        write_claim(sealed_path, &sealed);
        qihse_kv_ct_proof_destroy(seal);
    } else if (strcmp(step, "source-commit") == 0) {
        admitted_source(store, op, source_peer, source_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_ct_target_receipt_claim_t sealed = read_claim(sealed_path);
        receipt_fixture_t peer_receipt = {SEALED, sealed};
        qihse_kv_ct_proof_t* proof =
            qihse_kv_ct_source_transfer_proof_create(store, op, op,
                transfer_id, source_id, target_id, source_generation,
                transfer_first, transfer_last, sealed.source_cut);
        assert(proof);
        assert(qihse_kv_ct_source_fence_commit(store, op, proof, &sealed,
            verify_sealed, &peer_receipt, token));
        qihse_kv_ct_proof_destroy(proof);
        qihse_kv_ct_writer_scope_t* scope = NULL;
        assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
        assert(!qihse_kv_set_user(store, source_key, "must-deny", 4u, 2u, op));
        qihse_kv_ct_writer_scope_leave(scope);
        check_value(store, op, source_key, NULL);
        size_t visible = 0u;
        assert(qihse_kv_foreach_user(store, op, count_key, &visible));
        assert(visible == 0u);
    } else if (strcmp(step, "target-activate") == 0 ||
               strcmp(step, "target-reopen") == 0) {
        admitted_source(store, op, target_peer, target_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_ct_target_receipt_claim_t committed = read_claim(sealed_path);
        receipt_fixture_t source_receipt = {COMMITTED, committed};
        qihse_kv_ct_proof_t* seal = NULL;
        if (strcmp(step, "target-activate") == 0) {
            seal = qihse_kv_ct_target_seal_create(store, op, op,
                transfer_id, source_id, target_id, source_generation,
                transfer_first, transfer_last, committed.source_cut);
            assert(seal);
        }
        assert(qihse_kv_ct_target_activate(store, op, seal, &committed,
            verify_committed, &source_receipt, token));
        qihse_kv_ct_proof_destroy(seal);
        admitted_source(store, op, target_peer, target_generation);
        check_value(store, op, source_key,
                    reverse && strcmp(step, "target-reopen") == 0 ?
                    "returned-write" : "source-secret");
        check_value(store, low, source_key, NULL);
        check_value(store, op, stale_key, NULL);
        if (!reverse)
            check_value(store, op, outside_key,
                        large_transfer_mode ? NULL : "keep-outside");
        if (large_transfer_mode) {
            size_t visible_large = 0u;
            assert(qihse_kv_foreach_user(store, op, count_large_keys,
                                         &visible_large));
            assert(visible_large == LARGE_TRANSFER_ROWS);
            fprintf(stderr, "large CT2 activated rows: %zu\n", visible_large);
        }
        if (reverse && strcmp(step, "target-activate") == 0) {
            qihse_kv_ct_writer_scope_t* scope = NULL;
            assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
            assert(qihse_kv_set_user(store, source_key, "returned-write",
                                     4u, 2u, op));
            qihse_kv_ct_source_status_t status = {0};
            assert(qihse_kv_ct_source_status(store, op, &status));
            assert(qihse_kv_ct_source_ack(store, op, target_peer,
                target_generation, status.durable_lsn));
            assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
            check_value(store, op, source_key, "returned-write");
        }
    } else if (strcmp(step, "source-reopen") == 0) {
        admitted_source(store, op, source_peer, source_generation);
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_ct_source_status_t before = {0}, after = {0};
        assert(qihse_kv_ct_source_status(store, op, &before));
        qihse_kv_sweep_expired(store);
        assert(qihse_kv_ct_source_status(store, op, &after));
        assert(after.durable_lsn == before.durable_lsn);
        qihse_kv_ct_writer_scope_t* scope = NULL;
        assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
        assert(!qihse_kv_set_user(store, source_key, "must-still-deny",
                                  4u, 2u, op));
        /* Node-local writes retain normal CT1 scope/ACK obligations while
         * bypassing only the permanently moved application-slot fence. */
        const char* local_value = reverse ? "target-local-memory" : "source-local-memory";
        assert(qihse_kv_set_user(store, local_key, local_value, 4u, 2u, op));
        qihse_kv_ct_source_status_t local_status = {0};
        assert(qihse_kv_ct_source_status(store, op, &local_status));
        assert(qihse_kv_ct_source_ack(store, op, source_peer,
            source_generation, local_status.durable_lsn));
        assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
        check_value(store, op, source_key, NULL);
        size_t visible = 0u;
        assert(qihse_kv_foreach_user(store, op, count_key, &visible));
        assert(visible == 0u);
        if (reverse) check_value(store, op, outside_key, "keep-outside");
    } else assert(!"unknown transfer phase");
    /* Same hash slot and physical key, different per-node memory: transfer
     * and reverse transfer must neither copy nor delete either local value.
     * Checks run in each process after re-opening durable state. */
    const char* leaf = strrchr(data_dir, '/');
    assert(leaf);
    if (!(large_transfer_mode && strcmp(step, "target-import") == 0))
        check_value(store, op, local_key, !strcmp(leaf + 1, "source") ?
            "source-local-memory" : "target-local-memory");
    check_value(store, low, local_key, NULL);
    if (!strcmp(step, "source-commit") || !strcmp(step, "source-reopen"))
        owner_backup_check(store, op, low, false, NULL,
            !strcmp(leaf + 1, "source") ? "source-local-memory" : "target-local-memory",
            strcmp(leaf + 1, "source") != 0);
    if (!strcmp(step, "target-activate") || !strcmp(step, "target-reopen")) {
        owner_backup_check(store, op, low, true,
            reverse ? "returned-write" : "source-secret",
            !strcmp(leaf + 1, "source") ? "source-local-memory" : "target-local-memory",
            strcmp(leaf + 1, "source") != 0);
        qihse_kv_ct_target_receipt_claim_t committed = read_claim(sealed_path);
        receipt_fixture_t receipt = {COMMITTED, committed};
        assert(qihse_kv_ct_target_activate(store, op, NULL, &committed,
            verify_committed, &receipt, token));
    }
    qihse_kv_store_destroy(store);
}

static void run_child(const char* self, const char* phase,
                      const char* data_dir, const char* shared_dir) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        char* const args[] = {(char*)self, (char*)phase,
                              (char*)data_dir, (char*)shared_dir, NULL};
        execv(self, args);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char** argv) {
    if (argc == 4) {
        child_phase(argv[1], argv[2], argv[3]);
        return 0;
    }
    bool large = argc == 2 && strcmp(argv[1], "--large") == 0;
    assert(argc == 1 || large);
    if (large) assert(setenv("QIHSE_CT_LARGE_TRANSFER", "1", 1) == 0);
    umask(0077);
    char base[] = "./ct_transfer_XXXXXX";
    assert(mkdtemp(base));
    char source_dir[4096], target_dir[4096];
    path_join(source_dir, base, "source");
    path_join(target_dir, base, "target");
    assert(mkdir(source_dir, 0700) == 0);
    assert(mkdir(target_dir, 0700) == 0);
    run_child(argv[0], "source-setup", source_dir, base);
    run_child(argv[0], "target-setup", target_dir, base);
    if (!large) {
        run_child(argv[0], "abort-source-export", source_dir, base);
        run_child(argv[0], "abort-target-prepare", target_dir, base);
        run_child(argv[0], "abort-source-abort", source_dir, base);
        run_child(argv[0], "abort-target-abort", target_dir, base);
        run_child(argv[0], "abort-target-abort-reopen", target_dir, base);
    }
    run_child(argv[0], "source-export", source_dir, base);
    usleep(1600000u); /* The physical TTL passes before the restarted retry. */
    if (!large) run_child(argv[0], "source-export-retry", source_dir, base);
    if (large) {
#ifdef QIHSE_AIMEM_DURABILITY_TEST
        run_child(argv[0], "target-import-crash", target_dir, base);
#endif
    }
    run_child(argv[0], "target-import", target_dir, base);
    run_child(argv[0], "source-commit", source_dir, base);
    run_child(argv[0], "target-activate", target_dir, base);
    run_child(argv[0], "source-reopen", source_dir, base);
    run_child(argv[0], "target-reopen", target_dir, base);
    if (!large) {
        run_child(argv[0], "reverse-source-export", target_dir, base);
        run_child(argv[0], "reverse-target-import", source_dir, base);
        run_child(argv[0], "reverse-source-commit", target_dir, base);
        run_child(argv[0], "reverse-target-activate", source_dir, base);
        run_child(argv[0], "reverse-source-reopen", target_dir, base);
        run_child(argv[0], "reverse-target-reopen", source_dir, base);
    }
    aimem_fixture_cleanup(base);
    puts(large ? "ct transfer storage (>64 MiB): ok" :
                 "ct transfer storage: ok");
    return 0;
}
