#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "aimem_fixture_cleanup.h"
#include "qihse_kv_store.h"

/* Link this test against qihse_kv_store.c compiled with
 * QIHSE_AIMEM_DURABILITY_TEST. Run in a private QIHSE_DATA_DIR. */
static bool build_done(uint64_t seq, char* out, size_t cap, void* context) {
    (void)context;
    int n = snprintf(out, cap, "D:%llu", (unsigned long long)seq);
    return n > 0 && (size_t)n < cap;
}

static void value_is(qihse_kv_store_t* store, qihse_user_t* user,
                     const char* key, const char* expected) {
    char* value = qihse_kv_get_user(store, key, user);
    assert(expected ? value && strcmp(value, expected) == 0 : !value);
    free(value);
}

static const char* executable;

static void run_case(const char* source, const char* receipt,
                     const char* fail, bool committed,
                     qihse_user_t* op, qihse_user_t* low) {
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    uint64_t source_seq = 0u;
    assert(qihse_kv_set_user_with_seq(store, source, "protected", 4u, 2u,
                                      op, &source_seq));
    assert(qihse_kv_set_user(store, receipt, "P", 4u, 2u, op));
    assert(qihse_kv_sync_store(store));
    qihse_kv_store_destroy(store);

    /* A fresh writer process needs the exclusive audited writer lock. */
    qihse_audit_shutdown();

    pid_t pid = fork(); assert(pid >= 0);
    if (pid == 0) {
        char seq_text[32];
        assert(snprintf(seq_text, sizeof seq_text, "%llu",
                        (unsigned long long)source_seq) > 0);
        execl(executable, executable, "writer", source, receipt, seq_text,
              fail ? fail : "", committed ? "1" : "0", (char*)NULL);
        _exit(99);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    qihse_audit_init();
    assert(WIFEXITED(status) && WEXITSTATUS(status) == (fail && committed ? 86 : 0));
    /* Whole-store WAL replay must deny a low principal before disclosing
     * either protected member of the paired frame. */
    assert(qihse_kv_store_create_user(low) == NULL);
    store = qihse_kv_store_create_user(op); assert(store);
    value_is(store, op, source, committed ? NULL : "protected");
    if (committed) {
        qihse_kv_change_meta_t deleted = {0}, done = {0};
        assert(qihse_kv_change_meta_user(store, source, op, &deleted) && deleted.tombstone);
        assert(qihse_kv_change_meta_user(store, receipt, op, &done) && !done.tombstone);
        assert(done.change_seq == deleted.change_seq + 1u);
        char expected[64];
        assert(snprintf(expected, sizeof expected, "D:%llu",
                        (unsigned long long)deleted.change_seq) > 0);
        value_is(store, op, receipt, expected);
        assert(qihse_kv_sync_store(store)); /* ordinary SST rows retain DONE */
        value_is(store, op, receipt, expected);
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op); assert(store);
        value_is(store, op, source, NULL);
        value_is(store, op, receipt, expected);
    } else {
        value_is(store, op, receipt, "P");
    }
    qihse_kv_store_destroy(store);
}

int main(int argc, char** argv) {
    umask(0077);
    executable = argv[0];
    const char* dir = getenv("QIHSE_KV_DELETE_RECEIPT_DIR");
    char own_dir[] = "./kv_delete_receipt_XXXXXX";
    bool remove_own_dir = !dir || !*dir;
    if (remove_own_dir) {
        assert(mkdtemp(own_dir));
        dir = own_dir;
        assert(setenv("QIHSE_KV_DELETE_RECEIPT_DIR", dir, 1) == 0);
    }
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("KvDeleteReceiptOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "KvDeleteReceiptOperator1!");
    assert(op);
    if (argc == 7 && strcmp(argv[1], "writer") == 0) {
        qihse_kv_store_t* writer = qihse_kv_store_create_user(op); assert(writer);
        const bool committed = strcmp(argv[6], "1") == 0;
        if (*argv[5]) assert(setenv(committed ? "QIHSE_AIMEM_CRASH_AT" : "QIHSE_AIMEM_FAIL_AT",
                                     argv[5], 1) == 0);
        uint64_t source_seq = strtoull(argv[4], NULL, 10), delete_seq = 0u;
        bool ok = qihse_kv_del_with_receipt_user(writer, argv[2], source_seq,
            argv[3], "P", 4u, 2u, build_done, NULL, op, &delete_seq);
        if (committed && *argv[5]) return 99;
        assert(ok == committed);
        if (committed) assert(delete_seq > source_seq);
        qihse_kv_store_destroy(writer); /* flush deliberately torn WAL tail */
        return 0;
    }
    qihse_user_t* low = qihse_auth_create_user(op, 8101u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "KvDeleteReceiptLow1!", false);
    assert(low);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op); assert(store);
    uint64_t seq = 0u;
    assert(qihse_kv_set_user_with_seq(store, "secret-auth", "protected", 4u, 2u,
                                      op, &seq));
    assert(qihse_kv_set_user(store, "receipt-auth", "P", 4u, 2u, op));
    uint64_t rejected = 999u;
    assert(!qihse_kv_del_with_receipt_user(store, "secret-auth", seq,
        "receipt-auth", "P", 4u, 2u, build_done, NULL, low, &rejected));
    assert(rejected == 0u);
    value_is(store, low, "secret-auth", NULL);
    value_is(store, low, "receipt-auth", NULL);
    value_is(store, op, "secret-auth", "protected");
    value_is(store, op, "receipt-auth", "P");
    qihse_kv_store_destroy(store);
    run_case("secret-success", "receipt-success", NULL, true, op, low);
    run_case("secret-crash", "receipt-crash", "forget-pair-after-fsync", true, op, low);
    run_case("secret-torn", "receipt-torn", "forget-pair-partial-header", false, op, low);
    run_case("secret-body", "receipt-body", "forget-pair-partial-body", false, op, low);
    if (remove_own_dir) aimem_fixture_cleanup(dir);
    puts("kv delete receipt: PASS");
    return 0;
}
