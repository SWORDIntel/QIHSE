/* test_ct_source_floor.c - durable source sequence floor + pinned
 * compensating deletion. A disposable held CT1 source receives the
 * QCTSF001 floor (state magic QCTST006) and then the pinned compensation
 * tombstone allocated strictly above the floor. Each case runs in its own
 * re-executed process with a fresh fixture, mirroring the CT storage
 * fixture pattern.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_kv_store.h"

#define GEN       "0123456789abcdef0123456789abcdef"
#define SOURCE_ID "hold-primary"
#define TARGET_ID "hold-successor"
#define KEY       "commons/floor-pending"
#define FLOOR     5000u
#define RECEIPT   4900u
#define EPOCH     1u

static int remove_entry(const char* path, const struct stat* st, int flag,
    struct FTW* buffer) {
    (void)st; (void)flag; (void)buffer;
    return remove(path);
}

/* Held source fixture: preexisting history, one pending row at position 1,
 * V2 pinned custody hold installed through the public API. */
static qihse_kv_store_t* build_held_source(qihse_user_t* op,
    qihse_user_t* service, uint64_t* out_high_water) {
    qihse_kv_store_t* source = qihse_kv_store_create_user(op);
    assert(source && qihse_kv_set_user(source, "ct1.preexisting",
        "baseline-history", 2u, 1u, op) && qihse_kv_sync_store(source));
    assert(qihse_kv_ct_source_enable(source, op, SOURCE_ID, TARGET_ID, GEN,
        NULL, 128u * 1024u * 1024u));
    qihse_kv_store_set_replication_principal_id(source, 8302u);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], digest[32];
    assert(qihse_kv_ct_owner_token_get(source, op, token));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t baseline_seq = 0u;
    assert(qihse_kv_ct_source_baseline_snapshot_create(source, op, &snapshot,
        &baseline_seq, digest) == 0 && snapshot && baseline_seq > 0u);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_source_reconcile_peer(source, op, service, TARGET_ID,
        GEN, digest, 0u));
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter(source, op, token, &scope));
    assert(qihse_kv_set_user(source, KEY, "original-frame", 4u, 2u, op));
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t cursor = 0u;
    assert(qihse_kv_ct_source_read(source, op, GEN, 0u, 1u, 65536u, &groups,
        &count, &cursor) && count == 1u && cursor == 1u &&
        groups[0].count == 1u && strcmp(groups[0].records[0].key, KEY) == 0);
    qihse_kv_ct_record_t* row = &groups[0].records[0];
    qihse_kv_ct_source_retained_frame_request_t request = {
        .version = QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1,
        .size = sizeof(request), .source_id = SOURCE_ID,
        .successor_id = TARGET_ID, .generation = GEN,
        .baseline_row_seq = baseline_seq,
        .acknowledged_position = 0u, .durable_position = 1u,
        .stream_position = 1u, .key = row->key,
        .resource_tenant_id = row->resource_tenant_id,
        .classification = row->classification,
        .sci_compartment = row->sci_compartment,
        .row_change_seq = row->change_seq};
    memcpy(request.baseline_digest, digest, sizeof(digest));
    uint64_t highwater = qihse_kv_change_seq(source);
    qihse_kv_ct_source_quote_snapshot_t quote = {0};
    assert(qihse_kv_ct_source_quote_snapshot_v1(source, op, service,
        &request, highwater, &quote) &&
        quote.retained.frame_length >= 4u &&
        quote.retained.frame_length <= 65536u);
    assert(qihse_kv_ct_source_custody_hold_install_pinned_v1(source, op,
        service, &request, highwater, quote.retained.frame_length,
        quote.retained.frame_sha256));
    free(quote.retained.frame);
    free(quote.retained.key);
    qihse_kv_ct_groups_free(groups, count);
    if (out_high_water) *out_high_water = highwater;
    return source;
}

static void base_floor_request(qihse_kv_ct_source_floor_request_t* request,
    uint64_t floor) {
    memset(request, 0, sizeof(*request));
    request->version = QIHSE_KV_CT_SOURCE_FLOOR_V1;
    request->size = sizeof(*request);
    strcpy(request->generation, GEN);
    request->key = KEY;
    for (size_t i = 0u; i < 32u; ++i)
        request->manifest_sha256[i] = (unsigned char)(i + 1u);
    request->floor = floor;
    request->target_epoch = EPOCH;
    request->target_high_water = RECEIPT;
}

static void base_comp_request(qihse_kv_ct_source_compensate_request_t* request,
    uint64_t floor) {
    memset(request, 0, sizeof(*request));
    request->version = QIHSE_KV_CT_SOURCE_COMPENSATE_V1;
    request->size = sizeof(*request);
    strcpy(request->generation, GEN);
    request->key = KEY;
    request->floor = floor;
    request->resource_tenant_id = 0u;
    request->classification = 4u;
    request->sci_compartment = 2u;
}

/* The compensation's observable on a held source: the appended tombstone
 * group at position 2 with a row sequence strictly above the floor. */
static void expect_compensation_group(qihse_kv_store_t* store,
    qihse_user_t* op, uint64_t seq) {
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t cursor = 0u;
    assert(qihse_kv_ct_source_read(store, op, GEN, 0u, 2u, 65536u, &groups,
        &count, &cursor) && count == 2u && cursor == 2u);
    qihse_kv_ct_record_t* row = &groups[1].records[0];
    assert(groups[1].count == 1u && groups[1].stream_position == 2u &&
        row->tombstone && row->change_seq == seq &&
        strcmp(row->key, KEY) == 0 && row->classification == 4u &&
        row->sci_compartment == 2u);
    qihse_kv_ct_groups_free(groups, count);
}

static void expect_floor_sidecar(const char* dir, int mode) {
    char path[PATH_MAX];
    struct stat st;
    assert(snprintf(path, PATH_MAX, "%s/ct1-source-floor.bin", dir) > 0);
    if (mode == 0) {
        assert(stat(path, &st) != 0 && errno == ENOENT);
        return;
    }
    assert(stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_mode == (S_IFREG | 0600) && st.st_nlink == 1u &&
        st.st_size == 153);
    if (mode == 2) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        unsigned char byte;
        assert(fd >= 0 && pread(fd, &byte, 1u, 80u) == 1);
        byte ^= 1u;
        assert(pwrite(fd, &byte, 1u, 80u) == 1 && fsync(fd) == 0 &&
            close(fd) == 0);
    } else if (mode == 3) {
        assert(unlink(path) == 0);
    } else if (mode == 4) {
        assert(unlink(path) == 0);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        unsigned char body[152] = {0};
        assert(fd >= 0 && write(fd, body, sizeof(body)) ==
            (ssize_t)sizeof(body) && fsync(fd) == 0 && close(fd) == 0);
    }
}

static int run_case(const char* case_id) {
    char root[] = "build/ct-source-floor-XXXXXX";
    assert(mkdtemp(root));
    char dir[PATH_MAX];
    assert(snprintf(dir, PATH_MAX, "%s/rx", root) > 0 &&
        mkdir(dir, 0700) == 0 &&
        setenv("QIHSE_DATA_DIR", dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("FloorOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "FloorOperator1!");
    assert(op);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX, "FloorService1!", false);
    assert(service);
    uint64_t high_water = 0u;
    qihse_kv_ct_source_floor_request_t floor_request;
    qihse_kv_ct_source_compensate_request_t comp_request;
    qihse_kv_store_t* store = NULL;
    uint64_t seq_out = 0u;

    if (strcmp(case_id, "neg:nohold") == 0) {
        /* No hold, no CT binding at all: the pinned floor is refused by
         * the principal/id gates and the missing hold. */
        qihse_kv_store_t* plain = qihse_kv_store_create_user(op);
        assert(plain);
        qihse_kv_store_set_replication_principal_id(plain, 8302u);
        base_floor_request(&floor_request, FLOOR);
        assert(!qihse_kv_ct_source_floor_install_pinned_v1(plain, op,
            service, &floor_request));
        expect_floor_sidecar(dir, 0);
        qihse_kv_store_destroy(plain);
        goto case_done;
    }
    store = build_held_source(op, service, &high_water);

    if (strcmp(case_id, "neg:comp-early") == 0) {
        base_comp_request(&comp_request, FLOOR);
        assert(!qihse_kv_ct_source_compensate_pinned_v1(store, op, service,
            &comp_request, &seq_out));
    } else if (strcmp(case_id, "neg:comp-wrongfloor") == 0) {
        base_floor_request(&floor_request, FLOOR);
        assert(qihse_kv_ct_source_floor_install_pinned_v1(store, op, service,
            &floor_request));
        base_comp_request(&comp_request, FLOOR + 1u);
        assert(!qihse_kv_ct_source_compensate_pinned_v1(store, op, service,
            &comp_request, &seq_out));
        base_comp_request(&comp_request, FLOOR + 2u);
        assert(!qihse_kv_ct_source_compensate_pinned_v1(store, op, service,
            &comp_request, &seq_out));
        /* The refusals left the fixture intact: the exact floor works. */
        base_comp_request(&comp_request, FLOOR);
        assert(qihse_kv_ct_source_compensate_pinned_v1(store, op, service,
            &comp_request, &seq_out) && seq_out == FLOOR + 1u);
        expect_compensation_group(store, op, FLOOR + 1u);
    } else if (strncmp(case_id, "neg:", 4u) == 0) {
        base_floor_request(&floor_request, FLOOR);
        if (strcmp(case_id + 4u, "lowfloor") == 0)
            floor_request.floor = high_water > 1u ? high_water - 1u : 1u;
        else if (strcmp(case_id + 4u, "lowreceipt") == 0)
            floor_request.target_high_water = FLOOR + 1u;
        else if (strcmp(case_id + 4u, "zeroepoch") == 0)
            floor_request.target_epoch = 0u;
        else if (strcmp(case_id + 4u, "wronggen") == 0)
            strcpy(floor_request.generation, "ffffffffffffffffffffffffffffffff");
        else if (strcmp(case_id + 4u, "principals") == 0) {
            assert(!qihse_kv_ct_source_floor_install_pinned_v1(store, service,
                service, &floor_request));
            assert(!qihse_kv_ct_source_floor_install_pinned_v1(store, op, op,
                &floor_request));
            expect_floor_sidecar(dir, 0);
            store = NULL;
            goto case_done;
        } else assert(!"unknown neg case");
        assert(!qihse_kv_ct_source_floor_install_pinned_v1(store, op, service,
            &floor_request));
        expect_floor_sidecar(dir, 0);
    } else if (strcmp(case_id, "torn-install") == 0) {
        /* A stray sidecar without state magic QCTST006 fails closed. */
        char path[PATH_MAX];
        assert(snprintf(path, PATH_MAX, "%s/ct1-source-floor.bin", dir) > 0);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        unsigned char body[153] = {0};
        assert(fd >= 0 && write(fd, body, sizeof(body)) ==
            (ssize_t)sizeof(body) && fsync(fd) == 0 && close(fd) == 0);
        qihse_kv_store_destroy(store);
        store = NULL;
        assert(qihse_kv_store_create_user(op) == NULL);
    } else if (strcmp(case_id, "positive") == 0 ||
        strcmp(case_id, "crash-cut") == 0) {
        base_floor_request(&floor_request, FLOOR);
        assert(qihse_kv_ct_source_floor_install_pinned_v1(store, op, service,
            &floor_request));
        expect_floor_sidecar(dir, 1);
        /* The floor is once-only: a differing tuple is refused, the exact
         * tuple is idempotent. */
        base_floor_request(&floor_request, FLOOR + 1u);
        assert(!qihse_kv_ct_source_floor_install_pinned_v1(store, op, service,
            &floor_request));
        base_floor_request(&floor_request, FLOOR);
        assert(qihse_kv_ct_source_floor_install_pinned_v1(store, op, service,
            &floor_request));
        base_comp_request(&comp_request, FLOOR);
        if (strcmp(case_id, "crash-cut") == 0) {
            assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-after-group-fsync",
                1) == 0);
            assert(!qihse_kv_ct_source_compensate_pinned_v1(store, op,
                service, &comp_request, &seq_out));
            assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
            qihse_kv_store_destroy(store);
            /* Cold reopen rolls the durable group forward and rebinds. */
            store = qihse_kv_store_create_user(op);
            assert(store);
            qihse_kv_store_set_replication_principal_id(store, 8302u);
            assert(qihse_kv_ct_source_compensate_pinned_v1(store, op,
                service, &comp_request, &seq_out) &&
                seq_out == FLOOR + 1u);
        } else {
            assert(qihse_kv_ct_source_compensate_pinned_v1(store, op,
                service, &comp_request, &seq_out) &&
                seq_out == FLOOR + 1u);
        }
        assert(qihse_kv_change_seq(store) == FLOOR + 1u);
        expect_compensation_group(store, op, FLOOR + 1u);
        /* Retry of the exact compensation is idempotent. */
        assert(qihse_kv_ct_source_compensate_pinned_v1(store, op, service,
            &comp_request, &seq_out) && seq_out == FLOOR + 1u);
        /* The held source still denies ordinary allocation. */
        assert(!qihse_kv_set_user(store, "commons/other", "denied", 4u, 2u,
            op));
        qihse_kv_store_destroy(store);
        /* Cold reopen: floor + compensation both survive. */
        store = qihse_kv_store_create_user(op);
        assert(store);
        qihse_kv_store_set_replication_principal_id(store, 8302u);
        assert(qihse_kv_change_seq(store) == FLOOR + 1u);
        expect_compensation_group(store, op, FLOOR + 1u);
        assert(qihse_kv_ct_source_compensate_pinned_v1(store, op, service,
            &comp_request, &seq_out) && seq_out == FLOOR + 1u);
    } else if (strncmp(case_id, "harm:", 5u) == 0) {
        base_floor_request(&floor_request, FLOOR);
        assert(qihse_kv_ct_source_floor_install_pinned_v1(store, op, service,
            &floor_request));
        qihse_kv_store_destroy(store);
        store = NULL;
        expect_floor_sidecar(dir, strcmp(case_id + 5u, "tamper") == 0 ? 2 :
            strcmp(case_id + 5u, "delete") == 0 ? 3 :
            strcmp(case_id + 5u, "substitute") == 0 ? 4 : 1);
        assert(qihse_kv_store_create_user(op) == NULL); /* fail closed */
    } else assert(!"unknown case");

case_done:
    if (store) qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    static const char* const cases[] = {
        "neg:nohold", "neg:lowfloor", "neg:lowreceipt", "neg:zeroepoch",
        "neg:wronggen", "neg:principals", "neg:comp-early",
        "neg:comp-wrongfloor", "torn-install", "positive", "crash-cut",
        "harm:tamper", "harm:delete", "harm:substitute"};
    if (argc == 3 && strcmp(argv[1], "case") == 0)
        return run_case(argv[2]);
    assert(argc == 1);
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            execl(argv[0], argv[0], "case", cases[i], (char*)NULL);
            _exit(127);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0);
        printf("  case ok: %s\n", cases[i]);
    }
    puts("CT1 source floor and pinned compensation: OK");
    return 0;
}
