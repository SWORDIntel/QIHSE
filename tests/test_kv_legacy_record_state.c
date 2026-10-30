#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <ftw.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#define PASSWORD "LegacyRecordSynthetic1!"

static void state_is(qihse_kv_store_t* s, const char* key, qihse_user_t* u,
                     bool found, uint64_t sequence, bool tombstone) {
    uint64_t seq = UINT64_MAX;
    bool tomb = true;
    bool actual = qihse_kv_change_seq_user(s, key, u, &seq, &tomb);
    if (actual != found || seq != sequence || tomb != tombstone)
        fprintf(stderr, "synthetic state mismatch key=%s found=%d expected=%d seq=%" PRIu64 " tomb=%d\n",
                key ? key : "<null>", actual, found, seq, tomb);
    assert(actual == found);
    assert(seq == sequence && tomb == tombstone);
}

/* Native SST: decimal header, then raw key+value bytes, not wire base64. */
static void record(FILE* f, unsigned fields, const char* key, const char* value,
                   uint64_t expiry, unsigned classification, unsigned sci,
                   unsigned flags, uint64_t sequence) {
    assert(fields >= 5u && fields <= 7u);
    assert(fprintf(f, "%zu %zu %" PRIu64 " %u %u", strlen(key), strlen(value),
                   expiry, classification, sci) > 0);
    if (fields >= 6u) assert(fprintf(f, " %u", flags) > 0);
    if (fields == 7u) assert(fprintf(f, " %" PRIu64, sequence) > 0);
    assert(fprintf(f, "\n%s%s\n", key, value) > 0);
}

static void fixture(void) {
    FILE* f = fopen("sstable_0.db", "wb"); assert(f);
    record(f, 5, "live5", "synthetic-five", 0, 0, 0, 0, 0);
    record(f, 6, "live6", "synthetic-six", 0, 0, 0, 0, 0);
    record(f, 7, "live7zero", "synthetic-zero", 0, 0, 0, 0, 0);
    record(f, 7, "live7seq", "synthetic-sequence", 0, 0, 0, 0, 41);
    record(f, 6, "grave6", "", 0, 0, 0, 1, 0);
    record(f, 7, "grave7zero", "", 0, 0, 0, 1, 0);
    record(f, 7, "grave7seq", "", 0, 0, 0, 1, 42);
    record(f, 6, "aimem:0000000000000000", "", 0, 0, 0, 1, 0);
    record(f, 6, "aimem:0200000000000000", "", 0, 4, 2, 1, 0);
    record(f, 5, "high5", "synthetic-high", 0, 4, 2, 0, 0);
    record(f, 6, "high6grave", "", 0, 4, 2, 1, 0);
    record(f, 7, "high7zero", "synthetic-high-zero", 0, 4, 2, 0, 0);
    record(f, 7, "high7seq", "synthetic-high-seq", 0, 4, 2, 0, 43);
    record(f, 7, "high7grave", "", 0, 4, 2, 1, 44);
    record(f, 5, "expired5", "synthetic-expired", 1, 0, 0, 0, 0);
    record(f, 6, "expired6", "synthetic-expired", 1, 0, 0, 0, 0);
    record(f, 7, "expired7zero", "synthetic-expired", 1, 0, 0, 0, 0);
    record(f, 7, "expired7seq", "synthetic-expired", 1, 0, 0, 0, 45);
    assert(fclose(f) == 0);
    const char* bad[] = {"invalid6", "invalid7zero", "invalid7seq"};
    for (size_t i = 0; i < 3u; i++) {
        f = fopen(bad[i], "wb"); assert(f);
        record(f, i == 0u ? 6u : 7u, "invalid", "", 0, 4, 2, 0x80,
               i == 2u ? 51u : 0u);
        assert(fclose(f) == 0);
    }
    f = fopen("replacement", "wb"); assert(f);
    record(f, 7, "replacement", "synthetic-recovery", 0, 0, 0, 0, 52);
    assert(fclose(f) == 0);
}

static qihse_user_t* authenticated_user(qihse_user_t* root, uint32_t id,
                                       uint16_t classification, uint16_t sci) {
    assert(qihse_auth_create_user(root, id, QIHSE_ROLE_ANALYST, classification,
                                  sci, PASSWORD, false));
    qihse_user_t* u = qihse_auth_authenticate_id(id, PASSWORD);
    assert(u && qihse_auth_user_is_active(u)); return u;
}

static void zero_receipts_rejected(qihse_kv_store_t* store, qihse_user_t* root,
                                   qihse_user_t* low) {
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.enable_bus = false;
    config.enable_failover = false;
    config.enable_guard_throttle = false;
    config.enable_scatter = false;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.enable_uwp_bridge = true;
    config.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);
    const char* ids[] = {"00000000-0000-0000-0000-000000000001",
                         "02000000-0000-0000-0000-000000000001"};
    for (size_t i = 0; i < 2u; i++) {
        qihse_user_t* actors[] = {root, low};
        for (size_t j = 0; j < 2u; j++) {
            qihse_resp_arg_t args[] = {
                {(const uint8_t*)"AIMEM", 5u},
                {(const uint8_t*)"FORGET-RECEIPT", 14u},
                {(const uint8_t*)ids[i], strlen(ids[i])}
            };
            uint8_t* reply = NULL;
            size_t length = 0;
            assert(qihse_resp_server_execute(server, actors[j], 3u, args,
                                             &reply, &length));
            const char prefix[] = "-ERR NOT_DURABLE";
            assert(length >= sizeof(prefix) - 1u &&
                   memcmp(reply, prefix, sizeof(prefix) - 1u) == 0);
            free(reply);
        }
    }
    qihse_resp_server_destroy(server);
}

static void probe(bool pending) {
    char* dir = getcwd(NULL, 0); assert(dir);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0); free(dir);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(unsetenv("QIHSE_OPERATOR_PASSWORD") == 0);
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    assert(unsetenv("QIHSE_REPLICA_CRASH_AT") == 0);
    srand(731u);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t* root = qihse_auth_authenticate_id(0u, PASSWORD); assert(root);
    qihse_user_t* low = authenticated_user(root, 91u, 0u, 0u);
    qihse_user_t* no_sci = authenticated_user(root, 92u, 4u, 0u);
    qihse_user_t* cleared = authenticated_user(root, 93u, 4u, 2u);
    qihse_user_t* revoked = authenticated_user(root, 94u, 4u, 2u);
    assert(qihse_auth_destroy_user(root, 94u));
    assert(!qihse_auth_user_is_active(revoked));
    qihse_kv_store_t* s = qihse_kv_store_create_user(root); assert(s);

    /* No foreach, compaction, sweep or sync before retained-grave probes. */
    const char* keys[] = {"live5", "live6", "live7zero", "live7seq",
                          "grave6", "grave7zero", "grave7seq"};
    const uint64_t sequences[] = {0, 0, 0, 41, 0, 0, 42};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        state_is(s, keys[i], root, true, sequences[i], i >= 4u);
        state_is(s, keys[i], low, true, sequences[i], i >= 4u);
        /* Preserve the existing explicit public/anonymous read policy. */
        state_is(s, keys[i], NULL, true, sequences[i], i >= 4u);
        state_is(s, keys[i], revoked, true, sequences[i], i >= 4u);
    }
    const char* high[] = {"high5", "high6grave", "high7zero", "high7seq", "high7grave"};
    const uint64_t high_sequences[] = {0, 0, 0, 43, 44};
    for (size_t i = 0; i < sizeof(high) / sizeof(high[0]); i++) {
        bool tomb = i == 1u || i == 4u;
        state_is(s, high[i], root, true, high_sequences[i], tomb);
        state_is(s, high[i], cleared, true, high_sequences[i], tomb);
        qihse_user_t* denied[] = {NULL, low, no_sci, revoked};
        for (size_t j = 0; j < sizeof(denied) / sizeof(denied[0]); j++) {
            state_is(s, high[i], denied[j], false, 0, false);
            assert(qihse_kv_get_user(s, high[i], denied[j]) == NULL);
        }
    }
    const char* absent[] = {"expired5", "expired6", "expired7zero", "expired7seq", "missing"};
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); i++) {
        state_is(s, absent[i], root, false, 0, false);
        state_is(s, absent[i], low, false, 0, false);
    }
    state_is(NULL, "live5", root, false, 0, false);
    state_is(s, NULL, root, false, 0, false);
    uint64_t seq = UINT64_MAX; bool tomb = true;
    assert(!qihse_kv_change_seq_user(s, "live5", root, NULL, &tomb) && !tomb);
    assert(!qihse_kv_change_seq_user(s, "live5", root, &seq, NULL) && seq == 0u);
    assert(!qihse_kv_change_seq_user(s, "live5", root, NULL, NULL));

    /* Unknown flag 0x80 is invalid, not the native tombstone bit (1). */
    const char* bad[] = {"invalid6", "invalid7zero", "invalid7seq"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(qihse_kv_load_user(s, bad[i], root) == -1);
        state_is(s, "invalid", root, false, 0, false);
        state_is(s, "grave6", root, true, 0, true);
        state_is(s, "high7seq", root, true, 43, false);
    }
    zero_receipts_rejected(s, root, low);
    state_is(s, "grave6", root, true, 0, true);
    if (pending) {
        assert(setenv("QIHSE_AIMEM_FAIL_AT", "restore-intent-dir-fsync", 1) == 0);
        assert(qihse_kv_load_user(s, "replacement", root) == -1);
        assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        assert(!qihse_kv_sync_store(s));
        state_is(s, "live5", root, false, 0, false);
        state_is(s, "grave6", root, false, 0, false);
        state_is(s, "high7seq", root, false, 0, false);
        state_is(s, "replacement", root, false, 0, false);
    }
    qihse_kv_store_destroy(s);
}

static int remove_entry(const char* path, const struct stat* st, int type, struct FTW* ftw) {
    (void)st; (void)type; (void)ftw; return remove(path);
}

int main(void) {
    umask(0077);
    assert(mkdir("build", 0700) == 0 || access("build", F_OK) == 0);
    char temp[] = "build/kv-legacy-record-state-XXXXXX";
    assert(mkdtemp(temp));
    char* root = realpath(temp, NULL); assert(root);
    char* original = getcwd(NULL, 0); assert(original);
    assert(chdir(root) == 0);
    struct stat st; assert(stat(".", &st) == 0 && (st.st_mode & 0777) == 0700);
    fixture();
    /* Fresh processes inherit no auth/store state. Only the final process
     * enters pending recovery, after all cold-reopen assertions. */
    for (unsigned pass = 0; pass < 3u; pass++) {
        pid_t pid = fork(); assert(pid >= 0);
        if (pid == 0) { probe(pass == 2u); _exit(0); }
        int status; assert(waitpid(pid, &status, 0) == pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            fprintf(stderr, "legacy record state pass %u status %d\n", pass, status);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    assert(chdir(original) == 0); free(original);
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0); free(root);
    puts("kv legacy record state: PASS"); return 0;
}
