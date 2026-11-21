#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_ct_codec.h"

void ct1_fixture_reemit_historical(const char *dir, qihse_user_t *operator_user,
    const qihse_kv_ct_group_t *original, uint64_t baseline_seq,
    const unsigned char baseline_digest[32], uint64_t source_high);
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_cluster_ownership_journal.h"
#include "aimem_fixture_cleanup.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Disposable native target evidence; no receiver writer or recovery grant. */
static const char *const source_id = "source:fixture";
static const char *const target_id = "target:fixture";
static const char *const generation = "gen:fixture";
static const char *const key = "commons/fixture-key";

typedef struct {
    char name[65];
    off_t size;
    unsigned char sha[32];
} pin_t;

static void path_join(char out[512], const char *dir, const char *name)
{
    int n = snprintf(out, 512, "%s/%s", dir, name);
    assert(n > 0 && n < 512);
}

static void fingerprint(const char *path, off_t *size, unsigned char sha[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == 0 && st.st_nlink == 1 && !(st.st_mode & 077));
    *size = st.st_size;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    assert(hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
    unsigned char buf[4096];
    ssize_t got;
    while ((got = read(fd, buf, sizeof(buf))) > 0)
        assert(EVP_DigestUpdate(hash, buf, (size_t)got) == 1);
    unsigned int length = 0;
    assert(got == 0 && EVP_DigestFinal_ex(hash, sha, &length) == 1 &&
           length == 32 && close(fd) == 0);
    EVP_MD_CTX_free(hash);
}

static void same_file(const char *path, off_t size, const unsigned char sha[32])
{
    off_t actual;
    unsigned char digest[32];
    fingerprint(path, &actual, digest);
    assert(actual == size && memcmp(sha, digest, 32) == 0);
}

/* Pin actual native files, not fabricated fixed-size roster entries. The
 * canonical seven-member B roster remains a separate integration obligation. */
static size_t pin_native(const char *dir, pin_t pins[32])
{
    DIR *d = opendir(dir);
    assert(d);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(d))) {
        const char *name = entry->d_name;
        if (strcmp(name, "ct-baseline.qfs") && strcmp(name, "ct-state.bin") &&
            strcmp(name, "wal.log") &&
            strcmp(name, "restore-highwater.bin") &&
            strcmp(name, "slot-ownership.journal") &&
            strcmp(name, "slot-ownership.journal.lock") &&
            strncmp(name, "sstable_", 8)) continue;
        assert(count < 32 && strlen(name) < sizeof(pins[count].name));
        strcpy(pins[count].name, name);
        char path[512]; path_join(path, dir, name);
        fingerprint(path, &pins[count].size, pins[count].sha);
        count++;
    }
    assert(closedir(d) == 0 && count >= 2);
    return count;
}

static void verify_pins(const char *dir, const pin_t pins[32], size_t count)
{
    pin_t now[32];
    size_t found = pin_native(dir, now);
    assert(found == count);
    for (size_t i = 0; i < count; ++i) {
        size_t j = 0;
        while (j < found && strcmp(pins[i].name, now[j].name)) ++j;
        assert(j < found && pins[i].size == now[j].size &&
               memcmp(pins[i].sha, now[j].sha, 32) == 0);
    }
}

static void ownership_checked(const qihse_cluster_ownership_entry_t *entry, void *ctx)
{
    assert(entry->start == 0 && entry->end == 0 &&
        !strcmp(entry->owner_id, (const char *)ctx) && entry->config_epoch == 1);
}

static void native_ownership(const char *dir, const char *owner)
{
    assert(qihse_cluster_ownership_journal_append(dir, 0, 0, owner, 1) == 0);
    assert(qihse_cluster_ownership_journal_replay(dir, ownership_checked,
        (void *)owner) == 1);
}

static void check_history(qihse_kv_store_t *store, qihse_user_t *op,
                          qihse_user_t *service, uint64_t seq,
                          const unsigned char digest[32], int valid,
                          uint64_t claimed_position)
{
    qihse_kv_ct_receiver_history_request_t req = {
        .version = QIHSE_KV_CT_RECEIVER_HISTORY_V1, .size = sizeof(req),
        .source_id = source_id, .target_id = target_id,
        .generation = generation, .baseline_row_seq = seq,
        .durable_cursor = 7, .key = key, .resource_tenant_id = 0,
        .classification = 4, .sci_compartment = 2};
    memcpy(req.baseline_digest, digest, 32);
    qihse_kv_ct_receiver_history_result_t result = {0};
    uint64_t high = qihse_kv_change_seq(store);
    bool accepted = qihse_kv_ct_target_quote_snapshot_v1(store, op, service,
        &req, high, &result);
    if (valid) {
        assert(accepted && result.stream_position == 3 &&
               result.row_change_seq == seq + 3 &&
               result.durable_cursor == 7 && result.row_seq_high_water == high &&
               claimed_position < result.durable_cursor);
        /* A claimed tombstone at 4 is NOT justified by position 3. A future
         * writer must require equality, not infer a position from the cursor. */
        bool position_matches = result.stream_position == claimed_position &&
            result.stream_position < result.durable_cursor;
        assert(position_matches == (claimed_position == 3));
    } else {
        qihse_kv_ct_receiver_history_result_t empty = {0};
        assert(!accepted && memcmp(&result, &empty, sizeof(result)) == 0);
    }
}

static void one_case(const char *dir, const char *baseline_path,
                     qihse_user_t *op, qihse_user_t *service, uint64_t seq,
                     const unsigned char digest[32], unsigned variant,
                     bool export_target)
{
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, 8302);
    assert(qihse_kv_ct_receiver_bind(store, op, source_id, target_id, generation,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, seq, NULL));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_owner_token_get(store, op, token) &&
           qihse_kv_ct_receiver_install_baseline(store, op, service, source_id,
               generation, baseline_path, seq, digest, token));
    native_ownership(dir, target_id);
    for (unsigned pos = 1; pos <= 7; ++pos) {
        char other[64];
        assert(snprintf(other, sizeof(other), "commons/other-%u", pos) > 0);
        bool tomb = pos == 3 && variant != 1;
        const char *row_key = pos == 1 || tomb || (pos == 5 && variant == 2) ?
            key : other;
        qihse_kv_ct_record_t row = {
            .key = (char *)row_key, .value = tomb ? NULL : "fixture-value",
            .change_seq = seq + pos, .actor_id = 0, .actor_tenant_id = 0,
            .resource_tenant_id = 0, .classification = 4, .sci_compartment = 2,
            .actor_kind = QIHSE_KV_CT_ACTOR_USER, .tombstone = tomb};
        qihse_kv_ct_group_t group = {.stream_position = pos,
            .first_seq = row.change_seq, .last_seq = row.change_seq,
            .records = &row, .count = 1};
        strcpy(group.source_id, source_id);
        strcpy(group.generation, generation);
        uint64_t cursor = 0;
        assert(qihse_kv_ct_receiver_apply(store, service, &group, &cursor) &&
               cursor == pos);
        if (pos == 1) assert(qihse_kv_sync_store(store));
    }
    qihse_kv_ct_receiver_status_t status = {0};
    assert(qihse_kv_ct_receiver_status(store, op, &status) &&
           status.durable_cursor == 7 && status.baseline_sealed &&
           !strcmp(status.source_id, source_id) &&
           !strcmp(status.generation, generation) &&
           memcmp(status.baseline_digest, digest, 32) == 0);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op); /* cold state and WAL replay */
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, 8302);
    char wal[512], state[512];
    path_join(wal, dir, "wal.log"); path_join(state, dir, "ct-state.bin");
    pin_t pins[32];
    size_t count = pin_native(dir, pins);
    if (export_target) {
        char report[512];
        path_join(report, dir, "../native-evidence.txt");
        FILE *out = fopen(report, "w");
        assert(out && fchmod(fileno(out), 0600) == 0);
        fprintf(out, "baseline_row_seq=%llu\nsource_id=%s\ntarget_id=%s\ngeneration=%s\n"
            "row_key=%s\ntombstone_position=3\ntombstone_row_seq=%llu\n"
            "target_cursor=7\ntarget_high_water=%llu\ntarget_file_count=%zu\n",
            (unsigned long long)seq, source_id, target_id, generation, key,
            (unsigned long long)(seq + 3),
            (unsigned long long)qihse_kv_change_seq(store), count);
        fprintf(out, "baseline_digest=");
        for (size_t i = 0; i < 32; ++i) fprintf(out, "%02x", digest[i]);
        fputc('\n', out);
        for (size_t i = 0; i < count; ++i) {
            fprintf(out, "target_file=%s size=%llu sha256=", pins[i].name,
                (unsigned long long)pins[i].size);
            for (size_t j = 0; j < 32; ++j) fprintf(out, "%02x", pins[i].sha[j]);
            fputc('\n', out);
        }
        assert(fclose(out) == 0);
        fprintf(stderr, "CT1 native receiver: cold-reopened target has %zu/7 files "
            "(tombstone 3, cursor 7)\n", count);
        for (size_t i = 0; i < count; ++i)
            fprintf(stderr, "  target %s (%lld bytes)\n", pins[i].name,
                (long long)pins[i].size);
    }
    off_t wal_size, state_size; unsigned char wal_sha[32], state_sha[32];
    fingerprint(wal, &wal_size, wal_sha);
    fingerprint(state, &state_size, state_sha);
    int state_fd = open(state, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char state_magic[8];
    assert(state_fd >= 0 && pread(state_fd, state_magic, sizeof(state_magic), 0) ==
        (ssize_t)sizeof(state_magic) && !memcmp(state_magic, "QCTST005", 8) &&
        close(state_fd) == 0);
    check_history(store, op, service, seq, digest, variant == 0 || variant == 3 || variant >= 4,
                  variant == 3 ? 4 : 3);
    same_file(wal, wal_size, wal_sha);
    same_file(state, state_size, state_sha);
    verify_pins(dir, pins, count);
    qihse_kv_store_destroy(store);
    if (variant == 6) {
        /* Disposable V3 compatibility fixture, not a rewrite of exported
         * frozen evidence. Old binaries accept this magic; root must not. */
        int fd = open(state, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        unsigned char *bytes = malloc((size_t)state_size);
        assert(fd >= 0 && bytes && state_size > 16 &&
            pread(fd, bytes, (size_t)state_size, 0) == state_size);
        memcpy(bytes, "QCTST003", 8);
        uint64_t sum = UINT64_C(14695981039346656037);
        for (size_t i = 0; i < (size_t)state_size - sizeof(sum); ++i) {
            sum ^= bytes[i];
            sum *= UINT64_C(1099511628211);
        }
        memcpy(bytes + state_size - sizeof(sum), &sum, sizeof(sum));
        assert(pwrite(fd, bytes, (size_t)state_size, 0) == state_size &&
            fsync(fd) == 0 && close(fd) == 0);
        free(bytes);
        store = qihse_kv_store_create_user(op);
        assert(store && qihse_kv_ct_receiver_status(store, op, &status) &&
            status.durable_cursor == 7);
        qihse_kv_store_destroy(store);
        fd = open(state, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && pread(fd, state_magic, 8, 0) == 8 &&
            !memcmp(state_magic, "QCTST003", 8) && close(fd) == 0);
    }
    if (variant == 4 || variant == 5) {
        const char *damaged = variant == 4 ? wal : state;
        int fd = open(damaged, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0);
        off_t size; unsigned char before[32], after[32];
        fingerprint(damaged, &size, before);
        assert(size > 1);
        if (variant == 4) assert(ftruncate(fd, size - 1) == 0);
        else {
            unsigned char byte;
            assert(pread(fd, &byte, 1, 0) == 1);
            byte ^= 1;
            assert(pwrite(fd, &byte, 1, 0) == 1);
        }
        assert(fsync(fd) == 0 && close(fd) == 0);
        fingerprint(damaged, &size, after);
        assert(qihse_kv_store_create_user(op) == NULL);
        same_file(damaged, size, after); /* failed reopen cannot repair evidence */
        if (variant == 4) same_file(state, state_size, state_sha);
        else same_file(wal, wal_size, wal_sha);
    }
    if (!export_target) aimem_fixture_cleanup(dir);
}

int main(int argc, char **argv)
{
    assert(geteuid() == 0);
    if (argc == 6 && (!strcmp(argv[1], "case") || !strcmp(argv[1], "export-case"))) {
        assert(mkdir(argv[2], 0700) == 0);
        assert(setenv("QIHSE_DATA_DIR", argv[2], 1) == 0 &&
               setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0 &&
               qihse_auth_init() && qihse_auth_bootstrap_operator("Ct1FixtureOperator1!"));
        qihse_user_t *op = qihse_auth_authenticate_id(0, "Ct1FixtureOperator1!");
        assert(op);
        qihse_user_t *service = qihse_auth_create_user(op, 8302, QIHSE_ROLE_ANALYST,
            UINT16_MAX, UINT16_MAX, "Ct1FixtureService1!", false);
        assert(service && strlen(argv[5]) == 64);
        unsigned char digest[32];
        for (size_t i = 0; i < 32; ++i) {
            unsigned byte;
            assert(sscanf(argv[5] + i * 2, "%2x", &byte) == 1);
            digest[i] = (unsigned char)byte;
        }
        one_case(argv[2], argv[3], op, service, strtoull(argv[4], NULL, 10),
            digest, (unsigned)(argv[2][strlen(argv[2]) - 1] - '0'),
            !strcmp(argv[1], "export-case"));
        return 0;
    }
    bool export_target = argc == 3 && !strcmp(argv[1], "export");
    assert(argc == 2 || export_target);
    const char *base = export_target ? argv[2] : argv[1];
    char source[512], baseline_path[512], target[512];
    path_join(source, base, "native-source");
    path_join(baseline_path, source, "ct-baseline.qfs");
    assert(mkdir(source, 0700) == 0 &&
           setenv("QIHSE_DATA_DIR", source, 1) == 0 &&
           setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0 &&
           qihse_auth_init() && qihse_auth_bootstrap_operator("Ct1FixtureOperator1!"));
    qihse_user_t *op = qihse_auth_authenticate_id(0, "Ct1FixtureOperator1!");
    assert(op);
    qihse_user_t *service = qihse_auth_create_user(op, 8302, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, "Ct1FixtureService1!", false);
    assert(service);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store && qihse_kv_set_user(store, "commons/baseline", "seed", 0, 0, op) &&
           qihse_kv_sync_store(store));
    qihse_kv_store_set_replication_principal_id(store, 8302);
    assert(qihse_kv_ct_source_enable(store, op, source_id, target_id, generation,
        NULL, 128u * 1024u * 1024u));
    qihse_kv_replica_snapshot_t *snap = NULL;
    unsigned char digest[32]; uint64_t seq = 0;
    assert(qihse_kv_ct_source_baseline_snapshot_create(store, op, &snap,
        &seq, digest) == 0 && snap && seq);
    off_t baseline_size;
    unsigned char on_disk_digest[32];
    fingerprint(baseline_path, &baseline_size, on_disk_digest);
    assert(baseline_size > 0 && memcmp(on_disk_digest, digest, 32) == 0);
    qihse_kv_replica_snapshot_destroy(snap);
    native_ownership(source, source_id);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_owner_token_get(store, op, token) &&
           qihse_kv_ct_source_reconcile_peer(store, op, service, target_id,
               generation, digest, 0));
    qihse_kv_ct_writer_scope_t *scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
    char padded[2000];
    memset(padded, 'x', sizeof(padded));
    padded[1] = 0;
    qihse_kv_ct_record_t first_row = {
        .key = (char *)key, .value = padded, .change_seq = seq + 1,
        .actor_id = 0, .actor_tenant_id = 0, .resource_tenant_id = 0,
        .classification = 4, .sci_compartment = 2,
        .actor_kind = QIHSE_KV_CT_ACTOR_USER};
    qihse_kv_ct_group_t first_group = {
        .stream_position = 1, .first_seq = seq + 1, .last_seq = seq + 1,
        .records = &first_row, .count = 1};
    strcpy(first_group.source_id, source_id);
    strcpy(first_group.generation, generation);
    size_t encoded = 0;
    assert(qihse_ct_codec_encoded_size(op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0,
        QIHSE_CT_CODEC_MODE_SOURCE, &first_group, 65536, &encoded));
    size_t payload = QIHSE_CT1_RECOVERY_FRAME_BYTES - encoded + 1;
    assert(payload > 1 && payload < sizeof(padded));
    padded[1] = 'x'; padded[payload] = 0;
    for (unsigned pos = 1; pos <= 7; ++pos) {
        char other[64];
        assert(snprintf(other, sizeof(other), "commons/other-%u", pos) > 0);
        if (pos == 3) assert(qihse_kv_del_user(store, key, op));
        else assert(qihse_kv_set_user(store, pos == 1 ? key : other,
            pos == 1 ? padded : "fixture-value", 4, 2, op));
    }
    qihse_kv_ct_writer_scope_leave(scope);
    qihse_kv_ct_source_status_t before_ack = {0};
    assert(qihse_kv_ct_source_status(store, op, &before_ack) &&
           before_ack.durable_lsn == 7 && before_ack.acknowledged_lsn == 0);
    char hex[65], sequence[32];
    for (size_t i = 0; i < 32; ++i)
        assert(snprintf(hex + 2 * i, 3, "%02x", digest[i]) == 2);
    assert(snprintf(sequence, sizeof(sequence), "%llu", (unsigned long long)seq) > 0);
    for (unsigned i = 0; i < 7; ++i) {
        assert(snprintf(target, sizeof(target), "%s/native-target-%u", base, i) > 0);
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            execl(argv[0], argv[0], export_target && i == 0 ? "export-case" : "case",
                  target, baseline_path, sequence, hex,
                  (char *)NULL);
            _exit(99);
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
    }
    qihse_kv_ct_group_t *groups = NULL;
    size_t group_count = 0;
    uint64_t resume = 0;
    assert(qihse_kv_ct_source_read(store, op, generation, 0, 1, 65536,
        &groups, &group_count, &resume) && group_count == 1 && resume == 1 &&
        groups[0].stream_position == 1 && groups[0].count == 1 &&
        groups[0].records[0].change_seq == seq + 1 &&
        !strcmp(groups[0].records[0].key, key) &&
        !strcmp(groups[0].records[0].value, padded) &&
        groups[0].records[0].classification == 4 &&
        groups[0].records[0].sci_compartment == 2);
    uint64_t original_seq = groups[0].records[0].change_seq;
    uint64_t source_high = qihse_kv_change_seq(store);
    assert(source_high == seq + 7 && original_seq < seq + 3 &&
        qihse_kv_ct_source_ack(store, service, target_id, generation, 7));
    qihse_kv_ct_source_status_t status = {0};
    assert(qihse_kv_ct_source_status(store, op, &status) &&
        status.acknowledged_lsn == 7 && status.durable_lsn == 7 &&
        status.retained_bytes == 0);
    qihse_kv_store_destroy(store);
    ct1_fixture_reemit_historical(source, op, &groups[0], seq, digest, source_high);
    qihse_kv_ct_groups_free(groups, group_count);
    store = qihse_kv_store_create_user(op); /* cold replay verifies CT state and WAL */
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, 8302);
    assert(qihse_kv_ct_source_status(store, op, &status) &&
        status.acknowledged_lsn == 7 && status.durable_lsn == 8 &&
        status.retained_bytes == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        qihse_kv_change_seq(store) == source_high);
    assert(qihse_kv_ct_source_read(store, op, generation, 7, 1, 65536,
        &groups, &group_count, &resume) && group_count == 1 && resume == 8 &&
        groups[0].stream_position == 8 && groups[0].count == 1 &&
        groups[0].first_seq == original_seq &&
        groups[0].records[0].change_seq == original_seq &&
        !strcmp(groups[0].records[0].key, key) &&
        !strcmp(groups[0].records[0].value, padded) &&
        groups[0].records[0].classification == 4 &&
        groups[0].records[0].sci_compartment == 2);
    qihse_kv_ct_groups_free(groups, group_count);
    qihse_kv_ct_source_retained_frame_request_t req = {
        .version = QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1, .size = sizeof(req),
        .source_id = source_id, .successor_id = target_id, .generation = generation,
        .baseline_row_seq = seq, .acknowledged_position = 7,
        .durable_position = 8, .stream_position = 8, .key = key,
        .resource_tenant_id = 0, .classification = 4, .sci_compartment = 2,
        .row_change_seq = original_seq};
    memcpy(req.baseline_digest, digest, 32);
    qihse_kv_ct_source_quote_snapshot_t source_quote = {0};
    assert(qihse_kv_ct_source_quote_snapshot_v1(store, op, service, &req,
        source_high, &source_quote) &&
        source_quote.frame_offset == 0 &&
        source_quote.retained.frame_length == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        source_quote.retained.row_change_seq == original_seq &&
        source_quote.retained.stream_position == 8 &&
        source_quote.row_seq_high_water == source_high);
    char source_wal[512];
    path_join(source_wal, source, "wal.log");
    off_t original_size;
    unsigned char original_digest[32];
    fingerprint(source_wal, &original_size, original_digest);
    assert(original_size == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        memcmp(source_quote.retained.frame_sha256, original_digest, 32) == 0);
    int source_frame_fd = open(source_wal, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    unsigned char source_frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    assert(source_frame_fd >= 0 &&
        pread(source_frame_fd, source_frame, sizeof(source_frame),
            (off_t)source_quote.frame_offset) == (ssize_t)sizeof(source_frame) &&
        !memcmp(source_frame, source_quote.retained.frame, sizeof(source_frame)) &&
        !close(source_frame_fd));
    if (export_target) {
        pin_t source_pins[32];
        size_t source_count = pin_native(source, source_pins);
        char report[512];
        path_join(report, base, "native-evidence.txt");
        FILE *out = fopen(report, "a");
        assert(out);
        fprintf(out, "source_file_count=%zu\nsource_frame=present\n"
            "source_frame_offset=%llu\nsource_frame_length=%zu\n"
            "source_frame_position=%llu\nsource_row_seq=%llu\nsource_high_water=%llu\n",
            source_count, (unsigned long long)source_quote.frame_offset,
            source_quote.retained.frame_length,
            (unsigned long long)source_quote.retained.stream_position,
            (unsigned long long)source_quote.retained.row_change_seq,
            (unsigned long long)source_quote.row_seq_high_water);
        for (size_t i = 0; i < source_count; ++i) {
            fprintf(out, "source_file=%s size=%llu sha256=", source_pins[i].name,
                (unsigned long long)source_pins[i].size);
            for (size_t j = 0; j < 32; ++j) fprintf(out, "%02x", source_pins[i].sha[j]);
            fputc('\n', out);
        }
        assert(fclose(out) == 0);
        fprintf(stderr, "CT1 native source: %zu/8 measured files; "
            "1644-byte source frame observed at offset 0\n", source_count);
        for (size_t i = 0; i < source_count; ++i)
            fprintf(stderr, "  source %s (%lld bytes)\n", source_pins[i].name,
                (long long)source_pins[i].size);
        free(source_quote.retained.frame);
        free(source_quote.retained.key);
        qihse_kv_store_destroy(store);
        return 0;
    }
    free(source_quote.retained.frame);
    free(source_quote.retained.key);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(source);
    puts("ct1 native receiver fixture: PASS (historical tombstone 3, cursor 7)");
    return 0;
}
