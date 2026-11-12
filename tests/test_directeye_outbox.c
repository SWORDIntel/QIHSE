#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_kv_store.h"
#include "qihse_keystone.h"

#define PASSWORD "DirecteyeOutboxTestPass1!"
typedef struct {
    const char* operation_id;
    const char* record_id;
    const char* record_key;
    const char* mutation;
    uint32_t tenant;
    uint16_t classification;
    uint16_t sci;
    const char* record_json;
    uint64_t committed_at_ms;
} event_context_t;

static bool build_event(uint64_t generation, uint64_t cursor,
                        uint64_t committed_at_ms, char* out,
                        size_t capacity, void* opaque) {
    event_context_t* e = opaque;
    if (!e || (e->committed_at_ms && e->committed_at_ms != committed_at_ms)) return false;
    e->committed_at_ms = committed_at_ms;
    int n;
    if (committed_at_ms) {
        n = snprintf(out, capacity,
            "{\"schema\":1,\"event_id\":\"%s\",\"record_id\":\"%s\","
            "\"record_key\":\"%s\",\"mutation\":\"%s\",\"tenant\":%u,"
            "\"classification\":%u,\"sci\":%u,\"generation\":%llu,"
            "\"cursor\":%llu,\"committed_at_ms\":%llu,\"record\":%s}",
            e->operation_id, e->record_id, e->record_key, e->mutation,
            e->tenant, e->classification, e->sci,
            (unsigned long long)generation, (unsigned long long)cursor,
            (unsigned long long)committed_at_ms,
            e->record_json ? e->record_json : "null");
    } else {
        n = snprintf(out, capacity,
            "{\"schema\":1,\"event_id\":\"%s\",\"record_id\":\"%s\","
            "\"record_key\":\"%s\",\"mutation\":\"%s\",\"tenant\":%u,"
            "\"classification\":%u,\"sci\":%u,\"generation\":%llu,"
            "\"cursor\":%llu,\"record\":%s}",
            e->operation_id, e->record_id, e->record_key, e->mutation,
            e->tenant, e->classification, e->sci,
            (unsigned long long)generation, (unsigned long long)cursor,
            e->record_json ? e->record_json : "null");
    }
    return n >= 0 && (size_t)n < capacity;
}

static void remove_fixture(const char* dir) {
    DIR* d = opendir(dir); assert(d);
    struct dirent* entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        assert(n > 0 && (size_t)n < sizeof(path));
        assert(unlink(path) == 0);
    }
    assert(closedir(d) == 0 && rmdir(dir) == 0);
}

static void value_is(qihse_kv_store_t* store, qihse_user_t* user,
                     const char* key, const char* expected) {
    char* value = qihse_kv_get_user(store, key, user);
    assert(expected ? value && strcmp(value, expected) == 0 : value == NULL);
    free(value);
}

static void scenario(const char* temp) {
    char data_dir[4096];
    assert(realpath(temp, data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t* operator = qihse_auth_authenticate_id(0u, PASSWORD);
    assert(operator);
    qihse_kv_store_t* store = qihse_kv_store_create_user(operator);
    assert(store);

    const char* record_key = "t:0/directeye/canonical/v1/record-1";
    const char* event_key = "t:0/directeye/outbox/v1/11111111-1111-4111-8111-111111111111";
    event_context_t upsert = {
        "11111111-1111-4111-8111-111111111111", "record-1", record_key,
        "upsert", 0u, 0u, 0u, "{\"name\":\"alpha\"}", 0u
    };
    uint64_t generation = 0u, cursor = 0u;
    assert(qihse_kv_directeye_mutate_user(store, record_key,
        upsert.record_json, 0u, event_key, 0u, 0u, build_event, &upsert,
        operator, &generation, &cursor));
    assert(generation != 0u && cursor == generation + 1u);
    value_is(store, operator, record_key, upsert.record_json);
    char expected[1024];
    assert(build_event(generation, cursor, upsert.committed_at_ms, expected, sizeof(expected), &upsert));
    value_is(store, operator, event_key, expected);

    uint64_t retry_generation = 0u, retry_cursor = 0u;
    assert(qihse_kv_directeye_mutate_user(store, record_key,
        upsert.record_json, 0u, event_key, 0u, 0u, build_event, &upsert,
        operator, &retry_generation, &retry_cursor));
    assert(retry_generation == generation && retry_cursor == cursor);
    event_context_t conflict = upsert;
    conflict.record_json = "{\"name\":\"conflict\"}";
    assert(!qihse_kv_directeye_mutate_user(store, record_key,
        conflict.record_json, 0u, event_key, 0u, 0u, build_event, &conflict,
        operator, NULL, NULL));

    const char* replacement_event_key = "t:0/directeye/outbox/v1/44444444-4444-4444-8444-444444444444";
    event_context_t replacement = {
        "44444444-4444-4444-8444-444444444444", "record-1", record_key,
        "upsert", 0u, 0u, 0u, "{\"name\":\"beta\"}", 0u
    };
    uint64_t replacement_generation = 0u, replacement_cursor = 0u;
    assert(qihse_kv_directeye_mutate_user(store, record_key,
        replacement.record_json, generation, replacement_event_key, 0u, 0u,
        build_event, &replacement, operator, &replacement_generation, &replacement_cursor));
    assert(replacement_generation > generation && replacement_cursor == replacement_generation + 1u);
    value_is(store, operator, record_key, replacement.record_json);
    uint64_t before_stale = qihse_kv_change_seq(store);
    event_context_t stale = replacement;
    stale.operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    assert(!qihse_kv_directeye_mutate_user(store, record_key,
        stale.record_json, generation, "t:0/directeye/outbox/v1/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        0u, 0u, build_event, &stale, operator, NULL, NULL));
    assert(qihse_kv_change_seq(store) == before_stale);
    char replacement_json[1024];
    assert(build_event(replacement_generation, replacement_cursor,
                       replacement.committed_at_ms, replacement_json,
                       sizeof(replacement_json), &replacement));
    value_is(store, operator, replacement_event_key, replacement_json);

    const char* delete_event_key = "t:0/directeye/outbox/v1/22222222-2222-4222-8222-222222222222";
    event_context_t deletion = {
        "22222222-2222-4222-8222-222222222222", "record-1", record_key,
        "delete", 0u, 0u, 0u, NULL, 0u
    };
    uint64_t delete_generation = 0u, delete_cursor = 0u;
    assert(qihse_kv_directeye_mutate_user(store, record_key, NULL,
        replacement_generation, delete_event_key, 0u, 0u, build_event, &deletion,
        operator, &delete_generation, &delete_cursor));
    assert(delete_cursor == delete_generation + 1u && delete_generation > replacement_generation);
    char deletion_json[1024];
    assert(build_event(delete_generation, delete_cursor, deletion.committed_at_ms,
                       deletion_json, sizeof(deletion_json), &deletion));
    uint64_t repeated_delete_generation = 0u, repeated_delete_cursor = 0u;
    assert(qihse_kv_directeye_mutate_user(store, record_key, NULL,
        replacement_generation, delete_event_key, 0u, 0u, build_event, &deletion,
        operator, &repeated_delete_generation, &repeated_delete_cursor));
    assert(repeated_delete_generation == delete_generation && repeated_delete_cursor == delete_cursor);
    value_is(store, operator, record_key, NULL);
    qihse_kv_change_meta_t meta;
    assert(qihse_kv_change_meta_user(store, record_key, operator, &meta));
    assert(meta.tombstone && meta.change_seq == delete_generation);
    assert(!qihse_kv_set_user(store, "t:0/directeye/canonical/v1/forged", "{}", 0u, 0u, operator));
    assert(!qihse_kv_set_user(store, "t:0/directeye/outbox/v1/55555555-5555-4555-8555-555555555555",
                              "{}", 0u, 0u, operator));
    assert(!qihse_kv_del_user(store, record_key, operator));
    assert(!qihse_kv_del_user(store, event_key, operator));

    qihse_user_t* low = qihse_auth_create_tenant_user(operator, 42u, 42u,
        QIHSE_ROLE_ANALYST, 0u, 0u, PASSWORD, false);
    assert(low);
    const char* denied_key = "t:42/directeye/canonical/v1/secret";
    const char* denied_event_key = "t:42/directeye/outbox/v1/66666666-6666-4666-8666-666666666666";
    event_context_t denied = {
        "66666666-6666-4666-8666-666666666666", "secret", denied_key,
        "upsert", 42u, 4u, 2u, "{\"secret\":true}", 0u
    };
    uint64_t before_denied = qihse_kv_change_seq(store);
    assert(!qihse_kv_directeye_mutate_user(store, denied_key, denied.record_json,
        0u, denied_event_key, 4u, 2u, build_event, &denied, low, NULL, NULL));
    assert(qihse_kv_change_seq(store) == before_denied);
    assert(qihse_auth_destroy_user(operator, 42u));

    assert(qihse_auth_create_tenant_user(operator, 77u, 77u, QIHSE_ROLE_ANALYST,
        5u, UINT16_MAX, PASSWORD, false));
    qihse_user_t* writer = qihse_auth_authenticate_id(77u, PASSWORD);
    assert(writer && qihse_auth_user_is_active(writer));
    assert(qihse_user_get_tenant_id(writer) == 77u);
    assert(qihse_auth_can_access(writer, 4u, 2u));
    assert(!qihse_keystone_feed_identity_is_indexer(writer));
    const char* tenant_record_key = "t:77/directeye/canonical/v1/tenant-record";
    const char* wrong_tenant_event_key = "t:78/directeye/outbox/v1/88888888-8888-4888-8888-888888888888";
    assert(!qihse_kv_directeye_mutate_user(store,
        "t:78/directeye/canonical/v1/tenant-record", "{}", 0u,
        wrong_tenant_event_key, 4u, 2u, build_event, NULL, writer, NULL, NULL));
    const char* tenant_event_key = "t:77/directeye/outbox/v1/77777777-7777-4777-8777-777777777777";
    event_context_t tenant_event = {
        "77777777-7777-4777-8777-777777777777", "tenant-record", tenant_record_key,
        "upsert", 77u, 4u, 2u, "{\"tenant\":77}", 0u
    };
    uint64_t tenant_generation = 0u, tenant_cursor = 0u;
    assert(qihse_kv_directeye_mutate_user(store, tenant_record_key,
        tenant_event.record_json, 0u, tenant_event_key, 4u, 2u, build_event,
        &tenant_event, writer, &tenant_generation, &tenant_cursor));
    qihse_user_t* indexer = qihse_keystone_feed_identity_provision(
        operator, 77u, 78u, 5u, UINT16_MAX, PASSWORD);
    assert(indexer);
    qihse_kv_directeye_event_t* events = NULL;
    size_t event_count = 0u;
    uint64_t next_cursor = 0u;
    assert(qihse_kv_directeye_feed_read_user(store, indexer, 0u, 4u,
        &events, &event_count, &next_cursor));
    assert(event_count == 1u && events[0].cursor == tenant_cursor &&
           next_cursor >= tenant_cursor && strstr(events[0].json, "tenant-record"));
    uint64_t feed_next_cursor = next_cursor;
    qihse_kv_directeye_feed_events_free(events, event_count);
    events = NULL; event_count = 0u; next_cursor = 0u;
    assert(!qihse_kv_directeye_feed_read_user(store, operator, 0u, 4u,
        &events, &event_count, &next_cursor));
    assert(events == NULL && event_count == 0u && next_cursor == 0u);
    uint64_t ack_cursor = 0u;
    assert(qihse_kv_directeye_feed_ack_user(store, indexer, feed_next_cursor, &ack_cursor));
    assert(ack_cursor == feed_next_cursor);
    if (ack_cursor > 0u)
        assert(!qihse_kv_directeye_feed_ack_user(store, indexer, ack_cursor - 1u, &ack_cursor));

    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(operator);
    assert(store);
    assert(qihse_kv_directeye_feed_ack_user(store, indexer, feed_next_cursor, &ack_cursor));
    assert(ack_cursor == feed_next_cursor);
    assert(qihse_keystone_feed_identity_revoke(operator, 78u));
    assert(qihse_auth_destroy_user(operator, 77u));
    assert(qihse_auth_destroy_user(operator, 78u));
    value_is(store, operator, record_key, NULL);
    value_is(store, operator, event_key, expected);
    value_is(store, operator, replacement_event_key, replacement_json);
    value_is(store, operator, delete_event_key, deletion_json);
    assert(qihse_kv_change_meta_user(store, record_key, operator, &meta));
    assert(meta.tombstone && meta.change_seq == delete_generation);
    const char* failed_record_key = "t:0/directeye/canonical/v1/record-fail";
    const char* failed_event_key = "t:0/directeye/outbox/v1/33333333-3333-4333-8333-333333333333";
    event_context_t failed_event = {
        "33333333-3333-4333-8333-333333333333", "record-fail", failed_record_key,
        "upsert", 0u, 0u, 0u, "{\"name\":\"must-not-appear\"}", 0u
    };
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "directeye-partial-body", 1) == 0);
    assert(!qihse_kv_directeye_mutate_user(store, failed_record_key,
        failed_event.record_json, 0u, failed_event_key, 0u, 0u,
        build_event, &failed_event, operator, NULL, NULL));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(operator);
    assert(store);
    value_is(store, operator, failed_record_key, NULL);
    value_is(store, operator, failed_event_key, NULL);
    const char* header_record_key = "t:0/directeye/canonical/v1/record-header-fail";
    const char* header_event_key = "t:0/directeye/outbox/v1/99999999-9999-4999-8999-999999999999";
    event_context_t header_event = {
        "99999999-9999-4999-8999-999999999999", "record-header-fail", header_record_key,
        "upsert", 0u, 0u, 0u, "{\"name\":\"must-not-appear\"}", 0u
    };
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "directeye-partial-header", 1) == 0);
    assert(!qihse_kv_directeye_mutate_user(store, header_record_key,
        header_event.record_json, 0u, header_event_key, 0u, 0u,
        build_event, &header_event, operator, NULL, NULL));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(operator);
    assert(store);
    value_is(store, operator, header_record_key, NULL);
    value_is(store, operator, header_event_key, NULL);
    qihse_kv_store_destroy(store);
    puts("DIRECTEYE durable outbox: mutation, retry, conflict, tombstone, denial and recovery passed");
}

int main(void) {
    char temp[] = "./build/directeye-outbox-XXXXXX";
    assert(mkdtemp(temp));
    assert(chmod(temp, 0700) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        scenario(temp);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fprintf(stderr, "DIRECTEYE outbox scenario failed: status=%d\\n", status);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    remove_fixture(temp);
    return 0;
}
