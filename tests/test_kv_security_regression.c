#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"

static size_t iter_count = 0;
static bool iter_saw_secret = false;

static bool count_visible(const char* key, const char* value, void* user_data) {
    (void)value;
    (void)user_data;
    iter_count++;
    if (strcmp(key, "secret:sstable") == 0) iter_saw_secret = true;
    return true;
}

static void write_file(const char* path, const void* data, size_t len) {
    FILE* f = fopen(path, "wb");
    assert(f != NULL);
    assert(fwrite(data, 1, len, f) == len);
    assert(fclose(f) == 0);
}

int main(void) {
    char data_dir[] = "/tmp/qihse-kv-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("KVSecurityPass1!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 91, QIHSE_ROLE_GUEST, 0, 0,
        "GuestKVPass1!", false);
    assert(guest != NULL);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    /* Legacy context-free writes are unclassified only. */
    assert(qihse_kv_set(store, "public:legacy", "ok", 0, 0));
    assert(!qihse_kv_set(store, "secret:legacy", "blocked", 5, 0));

    /* A caller may not create/relabel data above its own target clearance. */
    assert(!qihse_kv_set_user(store, "secret:target", "blocked", 5, 0, guest));
    assert(qihse_kv_set_user(store, "secret:sstable", "classified-value", 5, 0, operator_user));

    /* Force the protected record into an SSTable, then verify the low-clearance
     * caller cannot shadow it with a new unclassified memtable value. */
    size_t large_len = 600u * 1024u;
    char* large = (char*)malloc(large_len + 1u);
    assert(large != NULL);
    memset(large, 'A', large_len);
    large[large_len] = '\0';
    assert(qihse_kv_set_user(store, "public:flush-trigger", large, 0, 0, operator_user));
    free(large);

    assert(!qihse_kv_set_user(store, "secret:sstable", "downgraded", 0, 0, guest));
    char* secret = qihse_kv_get_user(store, "secret:sstable", operator_user);
    assert(secret != NULL && strcmp(secret, "classified-value") == 0);
    free(secret);
    assert(qihse_kv_get_user(store, "secret:sstable", guest) == NULL);

    /* Bulk metadata APIs expose only the caller-visible logical dataset. */
    iter_count = 0;
    iter_saw_secret = false;
    assert(qihse_kv_foreach_user(store, guest, count_visible, NULL));
    assert(!iter_saw_secret);
    assert(iter_count == qihse_kv_count_user(store, guest));
    assert(qihse_kv_count_user(store, operator_user) > qihse_kv_count_user(store, guest));

    /* Partial classified export is forbidden. */
    char guest_snapshot[512];
    char op_snapshot[512];
    snprintf(guest_snapshot, sizeof(guest_snapshot), "%s/guest.snapshot", data_dir);
    snprintf(op_snapshot, sizeof(op_snapshot), "%s/operator.snapshot", data_dir);
    assert(qihse_kv_save_user(store, guest_snapshot, guest) != 0);
    assert(access(guest_snapshot, F_OK) != 0);
    assert(qihse_kv_save_user(store, op_snapshot, operator_user) == 0);

    /* A guest clear cannot erase data it cannot see. */
    size_t removed = qihse_kv_clear_user(store, guest);
    assert(removed >= 1u);
    secret = qihse_kv_get_user(store, "secret:sstable", operator_user);
    assert(secret != NULL && strcmp(secret, "classified-value") == 0);
    free(secret);

    /* SSTable-only deletion must stay deleted instead of exposing an older copy. */
    assert(qihse_kv_del_user(store, "secret:sstable", operator_user));
    assert(qihse_kv_get_user(store, "secret:sstable", operator_user) == NULL);
    assert(qihse_kv_foreach_user(store, operator_user, count_visible, NULL));
    assert(qihse_kv_get_user(store, "secret:sstable", operator_user) == NULL);

    /* Malformed restore is transactional: live state survives failed parsing. */
    assert(qihse_kv_set_user(store, "live:before-bad-load", "preserve-me", 0, 0, guest));
    char malformed[512];
    snprintf(malformed, sizeof(malformed), "%s/malformed.snapshot", data_dir);
    static const unsigned char junk[] = {0xff, 0x00, 0x7f, 'x', '\n'};
    write_file(malformed, junk, sizeof(junk));
    assert(qihse_kv_load_user(store, malformed, operator_user) != 0);
    char* preserved = qihse_kv_get_user(store, "live:before-bad-load", guest);
    assert(preserved != NULL && strcmp(preserved, "preserve-me") == 0);
    free(preserved);

    qihse_kv_store_destroy(store);

    unlink(guest_snapshot);
    unlink(op_snapshot);
    unlink(malformed);
    char command[768];
    snprintf(command, sizeof(command), "rm -rf -- '%s'", data_dir);
    assert(system(command) == 0);

    puts("[ALL PASS] KV security regression tests");
    return 0;
}
