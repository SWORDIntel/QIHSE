/* Private-unit regression, following test_kv_degraded_read_recovery.c.
 * Include the real implementation for authenticated physical-row inspection
 * and deterministic degraded-index injection; never duplicate private layouts.
 * No wall-clock sleeps, daemon, production state, or alternate CT lane API. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "src/black_hole/qihse_kv_store.c"
#include "qihse_audit.h"
#include <assert.h>
#include <ftw.h>
#include <sys/wait.h>

static const char key[] = "commons/legacy-expiry";
static const char value[] = "retained-expired-value";
static const char source[] = "expiry:source";
static const char target[] = "expiry:target";
static const char generation[] = "expiry:generation";
static const char password[] = "CtLegacyExpiryOperator1!";

typedef struct {
    qihse_user_t *op, *service, *actor;
    qihse_kv_store_t* store;
} fixture_t;

static fixture_t fixture(const char* dir) {
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(password));
    fixture_t f = {0};
    f.op = qihse_auth_authenticate_id(0u, password);
    assert(f.op);
    f.service = qihse_auth_create_user(f.op, 8302u, QIHSE_ROLE_ANALYST,
        5u, 2u, "CtLegacyExpiryService1!", false);
    f.actor = qihse_auth_create_user(f.op, 8303u, QIHSE_ROLE_ANALYST,
        4u, 2u, "CtLegacyExpiryActor1!", false);
    assert(f.service && f.actor);
    f.store = qihse_kv_store_create_user(f.op);
    assert(f.store);
    qihse_kv_store_set_replication_principal_id(f.store, 8302u);
    return f;
}

/* Expired rows are intentionally hidden by get/meta/change_meta. Inspect the
 * native physical lookup with an explicit active, label-cleared principal. */
static void physical_expired(qihse_kv_store_t* s, qihse_user_t* user,
                             uint64_t seq) {
    assert(user && qihse_auth_user_is_active(user));
    assert(qihse_auth_can_access(user, 4u, 2u));
    kv_store_rdlock(s);
    assert(!s->recovery_pending && s->ct_lane_count == 0u);
    kv_lookup_result_t row;
    assert(logical_lookup(s, key, &row) == KV_LOOKUP_DEAD);
    assert(qihse_auth_can_access(user, row.classification, row.sci_compartment));
    assert(row.flags == 0u && row.expire_time_ms == 1u);
    assert(row.classification == 4u && row.sci_compartment == 2u);
    assert(row.change_seq == seq);
    lookup_result_free(&row);
    kv_store_unlock(s);
    assert(qihse_kv_get_user(s, key, user) == NULL);
    qihse_kv_change_meta_t meta = {0};
    assert(!qihse_kv_change_meta_user(s, key, user, &meta));
}

static void hash_file(const char* path, unsigned char digest[32]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && ct_fd_sha256(fd, digest));
    assert(close(fd) == 0);
}

static void baseline(void) {
    fixture_t f = fixture("baseline");
    assert(qihse_kv_ct_source_enable(f.store, f.op, source, target, generation,
                                     NULL, 128u * 1024u * 1024u));
    qihse_kv_replica_snapshot_t* image = NULL;
    uint64_t seq = 0u, size = 0u;
    unsigned char digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(f.store, f.op, &image,
                                                       &seq, digest) == 0);
    assert(image && qihse_kv_replica_snapshot_size(image, f.op, &size));
    /* This is an actual native empty image and its actual digest/watermark. */
    assert(size == 0u && seq == 0u);
    FILE* out = fopen("baseline.qfs", "wb");
    assert(out);
    for (uint64_t off = 0u; off < size;) {
        unsigned char buf[4096];
        size_t got = 0u;
        assert(qihse_kv_replica_snapshot_read(image, f.op, off, buf,
                                              sizeof(buf), &got));
        assert(got && fwrite(buf, 1u, got, out) == got);
        off += got;
    }
    assert(fclose(out) == 0);
    out = fopen("baseline.meta", "wb");
    assert(out && fwrite(&seq, sizeof(seq), 1u, out) == 1u);
    assert(fwrite(digest, 1u, sizeof(digest), out) == sizeof(digest));
    assert(fclose(out) == 0);
    qihse_kv_replica_snapshot_destroy(image);
    qihse_kv_store_destroy(f.store);
}

static void baseline_meta(uint64_t* seq, unsigned char digest[32]) {
    FILE* in = fopen("baseline.meta", "rb");
    assert(in && fread(seq, sizeof(*seq), 1u, in) == 1u);
    assert(fread(digest, 1u, 32u, in) == 32u);
    assert(fgetc(in) == EOF && !ferror(in));
    assert(fclose(in) == 0);
}

static void receiver_seed(void) {
    fixture_t f = fixture("receiver");
    uint64_t seq = 0u;
    unsigned char digest[32], token[QIHSE_KV_CT_TOKEN_BYTES];
    baseline_meta(&seq, digest);
    assert(qihse_kv_ct_receiver_bind(f.store, f.op, source, target, generation,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, seq, NULL));
    assert(qihse_kv_ct_owner_token_get(f.store, f.op, token));
    assert(qihse_kv_ct_receiver_install_baseline(f.store, f.op, f.service,
        source, generation, "baseline.qfs", seq, digest, token));
    qihse_kv_ct_record_t row = {
        .key = (char*)key, .value = (char*)value, .change_seq = seq + 1u,
        .expire_time_ms = 1u, .actor_id = qihse_user_get_id(f.actor),
        .actor_tenant_id = qihse_user_get_tenant_id(f.actor),
        .resource_tenant_id = 0u, .classification = 4u, .sci_compartment = 2u,
        .actor_kind = QIHSE_KV_CT_ACTOR_USER
    };
    qihse_kv_ct_group_t group = {
        .stream_position = 1u, .first_seq = row.change_seq,
        .last_seq = row.change_seq, .records = &row, .count = 1u
    };
    snprintf(group.source_id, sizeof(group.source_id), "%s", source);
    snprintf(group.generation, sizeof(group.generation), "%s", generation);
    uint64_t cursor = 0u;
    assert(qihse_kv_ct_receiver_apply(f.store, f.service, &group, &cursor));
    assert(cursor == 1u);
    physical_expired(f.store, f.op, row.change_seq);
    /* Leave the fsynced QKV6 frame in WAL; do not sync/flush via a destructor. */
}

static void receiver_sweep(void) {
    fixture_t f = fixture("receiver");
    uint64_t seq = 0u;
    unsigned char digest[32], wal_before[32], state_before[32], after[32];
    baseline_meta(&seq, digest);
    qihse_kv_ct_receiver_status_t before = {0}, status = {0};
    assert(qihse_kv_ct_receiver_status(f.store, f.service, &before));
    assert(before.baseline_sealed && before.durable_cursor == 1u);
    assert(memcmp(before.baseline_digest, digest, 32u) == 0);
    physical_expired(f.store, f.op, seq + 1u);
    hash_file("receiver/wal.log", wal_before);
    hash_file("receiver/ct-state.bin", state_before);
    qihse_kv_sweep_expired(f.store);
    hash_file("receiver/wal.log", after);
    assert(memcmp(wal_before, after, 32u) == 0);
    hash_file("receiver/ct-state.bin", after);
    assert(memcmp(state_before, after, 32u) == 0);
    /* The legacy bug fails here despite successful native open and unchanged disk. */
    assert(qihse_kv_ct_receiver_status(f.store, f.service, &status));
    assert(status.baseline_sealed && status.durable_cursor == before.durable_cursor);
    assert(status.tenant_policy == before.tenant_policy && status.tenant_id == before.tenant_id);
    assert(strcmp(status.source_id, before.source_id) == 0);
    assert(strcmp(status.generation, before.generation) == 0);
    assert(memcmp(status.baseline_digest, before.baseline_digest, 32u) == 0);
    assert(qihse_kv_change_seq(f.store) == seq + 1u);
    physical_expired(f.store, f.op, seq + 1u);
    /* A fresh exec runs this same check again on the same unswept WAL state. */
}

static void source_sweep(void) {
    fixture_t f = fixture("source");
    qihse_kv_batch_set_record_t row = {
        .key = key, .value = value, .expire_time_ms = 1u,
        .classification = 4u, .sci_compartment = 2u
    };
    assert(qihse_kv_set_batch_durable_user(f.store, &row, 1u, f.actor));
    uint64_t original_seq = qihse_kv_change_seq(f.store);
    assert(original_seq != 0u);
    assert(qihse_kv_ct_source_enable(f.store, f.op, source, target, generation,
                                     NULL, 128u * 1024u * 1024u));
    physical_expired(f.store, f.op, original_seq);
    qihse_kv_replica_snapshot_t* image = NULL;
    uint64_t baseline_seq = 0u;
    unsigned char digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(f.store, f.op, &image,
                                                       &baseline_seq, digest) == 0);
    qihse_kv_replica_snapshot_destroy(image);
    qihse_kv_ct_source_status_t before = {0}, status = {0};
    assert(qihse_kv_ct_source_status(f.store, f.op, &before));
    assert(!before.admitted && before.durable_lsn == 0u && before.acknowledged_lsn == 0u);
    assert(before.baseline_row_seq == baseline_seq);
    /* enable() flushed the seeded row to SST. Force the existing native
     * degraded-index path to materialize it before collecting expiry keys;
     * otherwise this fixture could silently test only SST compaction. */
    assert(f.store->sst_meta && f.store->sstable_counter > 0);
    f.store->sst_meta->degraded = true;
    qihse_kv_sweep_expired(f.store);
    assert(qihse_kv_ct_source_status(f.store, f.op, &status));
    assert(!status.admitted && status.durable_lsn == before.durable_lsn);
    assert(status.acknowledged_lsn == before.acknowledged_lsn);
    assert(status.retained_bytes == before.retained_bytes);
    assert(status.baseline_row_seq == before.baseline_row_seq);
    assert(memcmp(status.baseline_digest, before.baseline_digest, 32u) == 0);
    assert(qihse_kv_change_seq(f.store) == original_seq);
    physical_expired(f.store, f.op, original_seq);
    assert(qihse_kv_ct_source_reconcile_peer(f.store, f.op, f.service,
                                             target, generation, digest, 0u));
    assert(qihse_kv_ct_source_status(f.store, f.op, &status) && status.admitted);
    /* Keep degraded-index coverage: it preserves retained tombstones too. */
    qihse_kv_sweep_expired(f.store);
    assert(qihse_kv_ct_source_status(f.store, f.op, &status));
    assert(status.admitted && status.durable_lsn == 1u && status.acknowledged_lsn == 0u);
    assert(qihse_kv_change_seq(f.store) > original_seq);
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    assert(qihse_kv_ct_source_read(f.store, f.op, generation, 0u, 2u, 65536u,
                                   &groups, &count, &resume));
    assert(count == 1u && resume == 1u && groups[0].stream_position == 1u);
    assert(strcmp(groups[0].source_id, source) == 0);
    assert(strcmp(groups[0].generation, generation) == 0 && groups[0].count == 1u);
    qihse_kv_ct_record_t* expired = &groups[0].records[0];
    assert(strcmp(expired->key, key) == 0 && expired->tombstone && !expired->value);
    assert(expired->expire_time_ms == 0u && expired->actor_kind == QIHSE_KV_CT_ACTOR_EXPIRY);
    assert(expired->actor_id == qihse_user_get_id(f.op));
    assert(expired->actor_tenant_id == 0u && expired->resource_tenant_id == 0u);
    assert(expired->classification == 4u && expired->sci_compartment == 2u);
    uint64_t tombstone_seq = expired->change_seq;
    assert(tombstone_seq > original_seq && groups[0].first_seq == tombstone_seq);
    assert(groups[0].last_seq == tombstone_seq);
    qihse_kv_ct_groups_free(groups, count);
    assert(qihse_kv_ct_source_ack(f.store, f.op, target, generation, 1u));
    assert(qihse_kv_ct_source_status(f.store, f.op, &status));
    assert(status.admitted && status.durable_lsn == 1u && status.acknowledged_lsn == 1u);
    qihse_kv_change_meta_t meta = {0};
    assert(qihse_kv_change_meta_user(f.store, key, f.op, &meta));
    assert(meta.tombstone && meta.change_seq == tombstone_seq);
    assert(meta.classification == 4u && meta.sci_compartment == 2u);
    assert(qihse_kv_get_user(f.store, key, f.op) == NULL);
    qihse_kv_sweep_expired(f.store);
    assert(qihse_kv_ct_source_status(f.store, f.op, &status));
    assert(status.durable_lsn == 1u && status.acknowledged_lsn == 1u);
}

static bool run(const char* mode) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        execl("/proc/self/exe", "test_ct_legacy_expiry", mode, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    fprintf(stderr, "%s %s (wait_status=%d)\n", ok ? "PASS" : "FAIL", mode, status);
    return ok;
}

static int remove_entry(const char* path, const struct stat* st, int kind, struct FTW* walk) {
    (void)st; (void)walk;
    return kind == FTW_D || kind == FTW_DP ? rmdir(path) : unlink(path);
}

int main(int argc, char** argv) {
    umask(0077);
    if (argc == 2) {
        if (!strcmp(argv[1], "baseline")) baseline();
        else if (!strcmp(argv[1], "receiver-seed")) receiver_seed();
        else if (!strcmp(argv[1], "receiver-sweep")) receiver_sweep();
        else if (!strcmp(argv[1], "source-sweep")) source_sweep();
        else return 2;
        /* Match a process stop with CT WAL already durable, without flushing
         * expiry rows into SST or running unrelated shutdown mutations. */
        _exit(0);
    }
    assert(argc == 1);
    /* exec after chdir must retain the checkout library, not a system install. */
    const char* library_path = getenv("LD_LIBRARY_PATH");
    if (library_path && strcmp(library_path, ".") == 0) {
        char absolute[PATH_MAX];
        assert(getcwd(absolute, sizeof(absolute)));
        assert(setenv("LD_LIBRARY_PATH", absolute, 1) == 0);
    }
    char directory[] = "./ct_legacy_expiry_XXXXXX";
    assert(mkdtemp(directory) && chdir(directory) == 0);
    assert(mkdir("baseline", 0700) == 0 && mkdir("receiver", 0700) == 0);
    assert(mkdir("source", 0700) == 0);
    bool ok = run("baseline");
    if (ok) ok = run("receiver-seed");
    if (ok) {
        bool first = run("receiver-sweep");
        bool reopened = run("receiver-sweep");
        ok = first && reopened;
    }
    bool source_ok = run("source-sweep");
    assert(chdir("..") == 0);
    if (ok && source_ok)
        assert(nftw(directory, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    else
        fprintf(stderr, "Failed fixture retained: %s\n", directory);
    return ok && source_ok ? 0 : 1;
}
