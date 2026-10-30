#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#define PASSWORD "RestoreDurabilityOperator1!"
#define EXPIRY UINT64_C(4000000000000)

static qihse_user_t* bootstrap(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, PASSWORD); assert(op); return op;
}
static qihse_user_t* limited(qihse_user_t* op, const char* name, uint16_t c, uint16_t sci) {
    uint32_t id = 100u;
    for (const char* p = name; *p; p++) id = id * 33u + (unsigned char)*p;
    id = 100u + id % 10000u;
    qihse_user_t* u = qihse_auth_get_user(id);
    if (!u) u = qihse_auth_create_user(op, id, QIHSE_ROLE_ANALYST, c, sci, PASSWORD, false);
    assert(u); return u;
}
static void value_is(qihse_kv_store_t* s, qihse_user_t* u, const char* key, const char* expected) {
    char* value = qihse_kv_get_user(s, key, u);
    assert(expected ? value && strcmp(value, expected) == 0 : value == NULL); free(value);
}
static void old_image(qihse_kv_store_t* s, qihse_user_t* op) {
    value_is(s, op, "old-one", "first"); value_is(s, op, "old-two", "second");
    value_is(s, op, "wal-only", "third"); value_is(s, op, "live", NULL);
}
static void new_image(qihse_kv_store_t* s, qihse_user_t* op) {
    value_is(s, op, "old-one", NULL); value_is(s, op, "old-two", NULL); value_is(s, op, "wal-only", NULL);
    value_is(s, op, "live", "protected-value"); value_is(s, op, "legacy", "old-format");
    value_is(s, op, "expired", NULL); value_is(s, op, "deleted", NULL);
    qihse_kv_record_meta_t m; assert(qihse_kv_meta_user(s, "live", op, &m));
    assert(m.classification == 4u && m.sci_compartment == 2u && m.expire_time_ms == EXPIRY &&
           m.flags == 0u && m.change_seq == 101u);
    uint64_t seq = 0; bool tomb = false;
    assert(qihse_kv_change_seq_user(s, "deleted", op, &seq, &tomb));
    assert(seq == 103u && tomb && qihse_kv_count_user(s, op) == 2u);
}
static unsigned char* file_bytes(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0); long n = ftell(f); assert(n >= 0);
    rewind(f); unsigned char* bytes = malloc((size_t)n + 1u); assert(bytes);
    assert(fread(bytes, 1u, (size_t)n, f) == (size_t)n && fclose(f) == 0);
    *size = (size_t)n; return bytes;
}
static void file_unchanged(const char* path, const unsigned char* bytes, size_t size) {
    size_t current_size; unsigned char* current = file_bytes(path, &current_size);
    assert(current_size == size && memcmp(current, bytes, size) == 0); free(current);
}
static void constructor_negative(const char* mode, const char* dir, qihse_user_t* op) {
    assert(qihse_kv_store_create_user(NULL) == NULL); /* even an empty store */
    qihse_user_t* low = limited(op, "open-low", 0u, 0u);
    qihse_user_t* no_sci = limited(op, "open-no-sci", 4u, 0u);
    qihse_user_t* revoked = limited(op, "open-revoked", 4u, 2u);
    assert(qihse_auth_destroy_user(op, qihse_user_get_id(revoked)));
    assert(qihse_kv_store_create_user(revoked) == NULL); /* empty-store inactive denial */
    qihse_kv_store_t* s = qihse_kv_store_create_user(op); assert(s);
    assert(qihse_kv_set_user(s, "public", "retain", 0u, 0u, op));
    assert(qihse_kv_set_user(s, "protected", "protected-value", 4u, 2u, op));
    bool sst = strcmp(mode, "open-sst") == 0;
    if (sst) assert(qihse_kv_sync_store(s));
    qihse_kv_store_destroy(s);
    char wal[1024], table[1024];
    snprintf(wal, sizeof(wal), "%s/wal.log", dir);
    snprintf(table, sizeof(table), "%s/sstable_0.db", dir);
    if (strcmp(mode, "open-legacy-binary") == 0) {
        FILE* f = fopen(wal, "wb"); assert(f);
        uint16_t key_len = 9u, classification = 4u, sci = 2u;
        uint32_t val_len = 15u;
        assert(fwrite("SET", 1u, 4u, f) == 4u);
        assert(fwrite(&key_len, sizeof(key_len), 1u, f) == 1u);
        assert(fwrite(&val_len, sizeof(val_len), 1u, f) == 1u);
        assert(fwrite(&classification, sizeof(classification), 1u, f) == 1u);
        assert(fwrite(&sci, sizeof(sci), 1u, f) == 1u);
        assert(fwrite("protectedprotected-value", 1u, 24u, f) == 24u);
        assert(fclose(f) == 0);
    } else if (strcmp(mode, "open-legacy-text") == 0) {
        FILE* f = fopen(wal, "wb"); assert(f);
        assert(fputs("SET protected protected-value 4 2\n", f) >= 0 && fclose(f) == 0);
    }
    size_t wal_size, table_size = 0u;
    unsigned char* wal_before = file_bytes(wal, &wal_size);
    unsigned char* table_before = sst ? file_bytes(table, &table_size) : NULL;
    qihse_user_t* denied[] = {NULL, low, no_sci, revoked};
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
        assert(qihse_kv_store_create_user(denied[i]) == NULL);
        file_unchanged(wal, wal_before, wal_size);
        if (sst) file_unchanged(table, table_before, table_size);
        else assert(access(table, F_OK) != 0);
    }
    s = qihse_kv_store_create_user(op); assert(s);
    value_is(s, op, "protected", "protected-value");
    if (sst || strcmp(mode, "open-wal") == 0) value_is(s, op, "public", "retain");
    qihse_kv_store_destroy(s);
    file_unchanged(wal, wal_before, wal_size);
    if (sst) file_unchanged(table, table_before, table_size);
    free(wal_before); free(table_before);
}
static int child(const char* mode, const char* dir, const char* image, const char* point) {
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    qihse_user_t* op = bootstrap();
    if (strncmp(mode, "open-", 5u) == 0) { constructor_negative(mode, dir, op); return 0; }
    if (strcmp(mode, "seed") == 0) {
        qihse_kv_store_t* s = qihse_kv_store_create(); assert(s);
        assert(qihse_kv_set_user(s, "old-one", "first", 0u, 0u, op)); assert(qihse_kv_sync_store(s));
        assert(qihse_kv_set_user(s, "old-two", "second", 0u, 0u, op)); assert(qihse_kv_sync_store(s));
        assert(qihse_kv_set_user(s, "wal-only", "third", 0u, 0u, op));
        qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "probe") == 0) {
        char meta[1024]; snprintf(meta, sizeof(meta), "%s/replica-install.meta", dir);
        if (access(meta, F_OK) == 0) {
            assert(qihse_kv_store_create() == NULL);
            assert(qihse_kv_store_create_user(limited(op, "recover-low", 0u, 0u)) == NULL);
            assert(qihse_kv_store_create_user(limited(op, "recover-no-sci", 4u, 0u)) == NULL);
            qihse_user_t* revoked = limited(op, "recover-revoked", 4u, 2u);
            assert(qihse_auth_destroy_user(op, qihse_user_get_id(revoked)));
            assert(qihse_kv_store_create_user(revoked) == NULL);
        }
        qihse_kv_store_t* s = qihse_kv_store_create_user(op); assert(s);
        if (strcmp(point, "old") == 0) old_image(s, op); else new_image(s, op);
        qihse_kv_store_destroy(s);
        s = qihse_kv_store_create(); assert(s);
        if (strcmp(point, "old") == 0) old_image(s, op); else new_image(s, op);
        qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "probe-empty-bound") == 0) {
        const char* files[] = {"wal.log", "sstable_0.db", "replica-install.meta", "replica-install.image"};
        char paths[4][1024]; unsigned char* before[4]; size_t sizes[4];
        for (size_t i = 0; i < 4u; ++i) {
            snprintf(paths[i], sizeof(paths[i]), "%s/%s", dir, files[i]);
            before[i] = file_bytes(paths[i], &sizes[i]);
        }
        qihse_user_t* low = limited(op, "empty-recover-low", 0u, 0u);
        qihse_user_t* no_sci = limited(op, "empty-recover-no-sci", 4u, 0u);
        qihse_user_t* revoked = limited(op, "empty-recover-revoked", 4u, 2u);
        assert(qihse_auth_destroy_user(op, qihse_user_get_id(revoked)));
        qihse_user_t* denied[] = {NULL, low, no_sci, revoked};
        assert(qihse_kv_store_create() == NULL);
        for (size_t i = 0; i < sizeof(denied) / sizeof(*denied); ++i) {
            assert(qihse_kv_store_create_user(denied[i]) == NULL);
            for (size_t j = 0; j < 4u; ++j) file_unchanged(paths[j], before[j], sizes[j]);
        }
        for (size_t i = 0; i < 4u; ++i) free(before[i]);
        qihse_kv_store_t* recovered = qihse_kv_store_create_user(op); assert(recovered);
        assert(qihse_kv_count_user(recovered, op) == 0u && qihse_kv_change_seq(recovered) >= 4u);
        qihse_kv_store_destroy(recovered);
        recovered = qihse_kv_store_create_user(low); assert(recovered);
        assert(qihse_kv_count_user(recovered, low) == 0u);
        qihse_kv_store_destroy(recovered);
        return 0;
    }
    qihse_kv_store_t* s = qihse_kv_store_create_user(op); assert(s);
    if (strcmp(mode, "seed-protected") == 0) {
        assert(qihse_kv_set_user(s, "target-protected", "retain", 4u, 2u, op));
        assert(qihse_kv_sync_store(s)); qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "crash") == 0) {
        assert(setenv("QIHSE_REPLICA_CRASH_AT", point, 1) == 0);
        (void)qihse_kv_load_user(s, image, op); assert(!"crash failpoint was not reached");
    }
    if (strcmp(mode, "fault") == 0) {
        assert(setenv("QIHSE_AIMEM_FAIL_AT", point, 1) == 0);
        assert(qihse_kv_load_user(s, image, op) == -1);
        assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        if (strncmp(point, "restore-", 8u) == 0 && strcmp(point, "restore-image-write") != 0) {
            assert(!qihse_kv_sync_store(s));
            assert(!qihse_kv_set_user(s, "must-not-write", "x", 0u, 0u, op));
            value_is(s, op, "old-one", NULL); value_is(s, op, "live", NULL);
        } else old_image(s, op);
        qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "negative") == 0) {
        qihse_user_t* low = limited(op, "load-low", 0u, 0u);
        qihse_user_t* no_sci = limited(op, "load-no-sci", 4u, 0u);
        qihse_user_t* revoked = limited(op, "load-revoked", 4u, 2u);
        assert(qihse_auth_destroy_user(op, qihse_user_get_id(revoked)));
        assert(qihse_kv_load_user(s, image, NULL) == -2);
        assert(qihse_kv_load_user(s, image, low) == -2);
        assert(qihse_kv_load_user(s, image, no_sci) == -2);
        assert(qihse_kv_load_user(s, image, revoked) == -2); old_image(s, op);
        assert(qihse_kv_set_user(s, "target-protected", "retain", 4u, 2u, op));
        assert(qihse_kv_sync_store(s));
        char empty[1024]; snprintf(empty, sizeof(empty), "%s.empty", image);
        assert(qihse_kv_load_user(s, empty, low) == -2);
        value_is(s, op, "target-protected", "retain"); qihse_kv_store_destroy(s);
        s = qihse_kv_store_create_user(op); assert(s); old_image(s, op);
        value_is(s, op, "target-protected", "retain"); qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "malformed") == 0) {
        char bad[1024]; snprintf(bad, sizeof(bad), "%s.bad", image);
        assert(qihse_kv_load_user(s, bad, op) == -1); old_image(s, op);
        qihse_kv_store_destroy(s); s = qihse_kv_store_create(); assert(s);
        old_image(s, op); qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "replica-floor") == 0 || strcmp(mode, "replica-empty-floor") == 0) {
        assert(qihse_kv_del_user(s, "old-one", op));
        assert(qihse_kv_del_user(s, "old-two", op));
        assert(qihse_kv_del_user(s, "wal-only", op));
        for (size_t i = 0; i < 12u; ++i) {
            assert(qihse_kv_set_user(s, "transient", "x", 0u, 0u, op));
            assert(qihse_kv_del_user(s, "transient", op));
        }
        uint64_t floor = qihse_kv_change_seq(s); assert(floor > 1u);
        assert(qihse_kv_sync_store(s));
        assert(qihse_kv_store_enable_replica_read_only(s));
        bool empty = strcmp(mode, "replica-empty-floor") == 0;
        char baseline[1024]; snprintf(baseline, sizeof(baseline), "%s.%s", image,
                                     empty ? "empty" : "replica");
        assert(qihse_kv_replica_snapshot_install(s, baseline, op,
                                                "floor-peer", "public:*", 1u));
        assert(qihse_kv_change_seq(s) >= floor);
        qihse_kv_store_destroy(s);
        s = qihse_kv_store_create_user(op); assert(s);
        assert(qihse_kv_change_seq(s) >= floor);
        uint64_t cursor = 0u;
        assert(qihse_kv_replica_cursor_get(s, "floor-peer", "public:*", op, &cursor));
        assert(cursor == 1u); /* local floor must never replace source progress */
        value_is(s, op, "public:row", empty ? NULL : "new");
        if (!empty) {
            qihse_kv_record_meta_t metadata;
            assert(qihse_kv_meta_user(s, "public:row", op, &metadata));
            assert(metadata.change_seq == 1u);
        }
        assert(qihse_kv_set_user(s, "after-floor", "local", 0u, 0u, op));
        assert(qihse_kv_change_seq(s) > floor);
        assert(qihse_kv_sync_store(s)); qihse_kv_store_destroy(s);
        return 0;
    }
    if (strcmp(mode, "retired-target") == 0) {
        char retired[1024], public_image[1024];
        snprintf(retired, sizeof(retired), "%s.retired", image);
        snprintf(public_image, sizeof(public_image), "%s.replica", image);
        qihse_user_t* low = limited(op, "retired-target-low", 0u, 0u);
        assert(qihse_kv_load_user(s, retired, op) == 0);
        assert(qihse_kv_count_user(s, op) == 0u);
        assert(qihse_kv_load_user(s, public_image, low) == 0);
        assert(qihse_kv_set_user(s, "retired", "secret", 4u, 2u, op));
        assert(qihse_kv_del_user(s, "retired", op));
        assert(qihse_kv_sync_store(s));
        assert(qihse_kv_load_user(s, public_image, low) == 0);
        qihse_kv_store_destroy(s);
        s = qihse_kv_store_create_user(low); assert(s);
        value_is(s, low, "public:row", "new");
        value_is(s, op, "retired", NULL);
        qihse_kv_store_destroy(s); return 0;
    }
    if (strcmp(mode, "clear-protected") == 0) {
        assert(qihse_kv_load_user(s, image, op) == 0);
        qihse_user_t* low = limited(op, "clear-low", 0u, 0u);
        assert(qihse_kv_clear_user(s, low) == 1u);
        value_is(s, op, "legacy", NULL);
        value_is(s, op, "live", "protected-value");
        qihse_kv_store_destroy(s); /* no explicit sync may rescue lost image rows */
        s = qihse_kv_store_create_user(op); assert(s);
        value_is(s, op, "legacy", NULL);
        value_is(s, op, "live", "protected-value");
        qihse_kv_record_meta_t metadata;
        assert(qihse_kv_meta_user(s, "live", op, &metadata));
        assert(metadata.classification == 4u && metadata.sci_compartment == 2u &&
               metadata.expire_time_ms == EXPIRY && metadata.change_seq == 101u);
        qihse_kv_store_destroy(s);
        return 0;
    }
    assert(strcmp(mode, "success") == 0);
    assert(qihse_kv_load_user(s, image, op) == 0); new_image(s, op); qihse_kv_store_destroy(s);
    s = qihse_kv_store_create(); assert(s); new_image(s, op);
    assert(qihse_kv_del_user(s, "live", op));
    uint64_t floor = qihse_kv_change_seq(s); assert(floor > 103u);
    assert(qihse_kv_sync_store(s)); qihse_kv_store_destroy(s);
    s = qihse_kv_store_create(); assert(s);
    value_is(s, op, "live", NULL); value_is(s, op, "expired", NULL); value_is(s, op, "deleted", NULL);
    char empty[1024]; snprintf(empty, sizeof(empty), "%s.empty", image);
    assert(qihse_kv_load_user(s, empty, NULL) == -2); assert(qihse_kv_load_user(s, empty, op) == 0);
    qihse_kv_store_destroy(s); s = qihse_kv_store_create(); assert(s);
    assert(qihse_kv_count_user(s, op) == 0u && qihse_kv_change_seq(s) >= floor);
    value_is(s, op, "live", NULL); value_is(s, op, "legacy", NULL); value_is(s, op, "old-one", NULL);
    qihse_kv_store_destroy(s); return 0;
}
static void run(const char* self, const char* mode, const char* dir,
                const char* image, const char* point, int expected) {
    pid_t pid = fork(); assert(pid >= 0);
    if (pid == 0) { execl(self, self, mode, dir, image, point, (char*)NULL); _exit(127); }
    int status; assert(waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected)
        fprintf(stderr, "restore case %s/%s status=%d expected=%d\n", mode, point, status, expected);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}
int main(int argc, char** argv) {
    if (argc == 5) return child(argv[1], argv[2], argv[3], argv[4]);
    assert(argc == 1);
    const char* root = getenv("QIHSE_KV_RESTORE_DURABILITY_DIR"); assert(root && *root);
    char image[1024], empty[1024], dir[1024];
    snprintf(image, sizeof(image), "%s/image", root);
    FILE* f = fopen(image, "wb"); assert(f);
    assert(fprintf(f, "4 15 %" PRIu64 " 4 2 0 101\nliveprotected-value\n"
                      "7 4 1 0 0 0 102\nexpiredgone\n"
                      "7 0 0 0 0 1 103\ndeleted\n"
                      "6 10 0 0 0\nlegacyold-format\n", EXPIRY) > 0);
    assert(fclose(f) == 0);
    snprintf(empty, sizeof(empty), "%s.empty", image);
    f = fopen(empty, "wb"); assert(f && fclose(f) == 0);
    char bad[1024]; snprintf(bad, sizeof(bad), "%s.bad", image);
    f = fopen(bad, "wb"); assert(f);
    assert(fputs("4 1 0 0 0 0 20\nliveX\n7 99 0 4 2 0 21\ntruncated", f) >= 0);
    assert(fclose(f) == 0);
    char replica[1024]; snprintf(replica, sizeof(replica), "%s.replica", image);
    f = fopen(replica, "wb"); assert(f);
    assert(fputs("10 3 0 0 0 0 1\npublic:rownew\n", f) >= 0);
    assert(fclose(f) == 0);
    const char* opens[] = {"open-sst", "open-wal", "open-legacy-binary", "open-legacy-text"};
    for (size_t i = 0; i < sizeof(opens) / sizeof(opens[0]); ++i) {
        snprintf(dir, sizeof(dir), "%s/%s", root, opens[i]); assert(mkdir(dir, 0700) == 0);
        run(argv[0], opens[i], dir, image, "", 0);
    }
    char retired[1024]; snprintf(retired, sizeof(retired), "%s.retired", image);
    f = fopen(retired, "wb"); assert(f);
    assert(fputs("7 6 1 4 2 0 1\nretiredsecret\n", f) >= 0);
    assert(fclose(f) == 0);
    const char* modes[] = {"success", "negative", "malformed", "replica-floor", "replica-empty-floor", "clear-protected", "retired-target"};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        snprintf(dir, sizeof(dir), "%s/%s", root, modes[i]); assert(mkdir(dir, 0700) == 0);
        run(argv[0], "seed", dir, image, "", 0); run(argv[0], modes[i], dir, image, "", 0);
    }
    const char* crashes[] = {"image", "intent", "before-publish", "sst-published",
        "sst-pruned", "wal-replaced", "sst-wal-durable", "journal-removed"};
    for (size_t i = 0; i < sizeof(crashes) / sizeof(crashes[0]); i++) {
        snprintf(dir, sizeof(dir), "%s/crash-%zu", root, i); assert(mkdir(dir, 0700) == 0);
        run(argv[0], "seed", dir, image, "", 0); run(argv[0], "crash", dir, image, crashes[i], 86);
        run(argv[0], "probe", dir, image, i == 0 ? "old" : "new", 0);
    }
    const char* bound_phases[] = {"intent", "before-publish", "sst-published", "sst-pruned", "wal-replaced"};
    for (size_t i = 0; i < sizeof(bound_phases) / sizeof(*bound_phases); ++i) {
        snprintf(dir, sizeof(dir), "%s/empty-bound-%zu", root, i); assert(mkdir(dir, 0700) == 0);
        run(argv[0], "seed", dir, image, "", 0);
        run(argv[0], "seed-protected", dir, image, "", 0);
        run(argv[0], "crash", dir, empty, bound_phases[i], 86);
        run(argv[0], "probe-empty-bound", dir, empty, "", 0);
    }
    const char* faults[] = {"restore-image-write", "sstable-file-fsync", "sstable-rename",
        "directory-fsync", "restore-intent-dir-fsync", "restore-sstable-rename",
        "restore-publish-dir-fsync", "restore-wal-rename", "restore-wal-dir-fsync",
        "restore-intent-unlink", "restore-cleanup-dir-fsync", "restore-sstable-unlink",
        "restore-highwater-commit", "restore-highwater-dir-fsync", "restore-image-cleanup-dir-fsync"};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
        snprintf(dir, sizeof(dir), "%s/fault-%zu", root, i); assert(mkdir(dir, 0700) == 0);
        run(argv[0], "seed", dir, image, "", 0); run(argv[0], "fault", dir, image, faults[i], 0);
        run(argv[0], "probe", dir, image, i < 4 ? "old" : "new", 0);
    }
    puts("authenticated full-image restore durability/crash/fault/denial: PASS"); return 0;
}
