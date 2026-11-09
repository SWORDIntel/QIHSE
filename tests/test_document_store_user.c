#include "qihse_document.h"
#include "qihse_auth.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    qihse_document_store_t* store;
    qihse_user_t* writer;
    qihse_user_t* reader;
} concurrent_args_t;

static void* concurrent_writer(void* opaque) {
    concurrent_args_t* args = opaque;
    for (unsigned i = 0; i < 100u; i++) {
        char json[64];
        assert(snprintf(json, sizeof(json), "{\"seq\":%u}", i) > 0);
        assert(qihse_doc_store_insert_json_user(args->store, 91u, json,
                                                args->writer));
    }
    return NULL;
}

static void* concurrent_reader(void* opaque) {
    concurrent_args_t* args = opaque;
    for (unsigned i = 0; i < 300u; i++) {
        char* json = NULL;
        assert(qihse_doc_store_get_json_user(args->store, 91u,
                                              args->reader, &json));
        assert(strstr(json, "HIGH_DOCUMENT_SECRET") || strstr(json, "\"seq\""));
        free(json);
        qihse_document_result_t rows = qihse_doc_store_list_user(args->store,
            args->reader, 2u);
        assert(rows.count == 2u);
        free(rows.doc_ids);
    }
    return NULL;
}

static qihse_user_t* principal(qihse_user_t* system, uint32_t tenant,
        uint32_t id, uint16_t classification, uint16_t sci,
        const char* password) {
    qihse_user_t* user = qihse_auth_create_tenant_user(system, tenant, id,
        QIHSE_ROLE_GUEST, classification, sci, password, false);
    assert(user);
    return user;
}

static void denied(qihse_document_store_t* store, qihse_user_t* user) {
    char* json = (char*)1;
    assert(!qihse_doc_store_get_json_user(store, 91u, user, &json));
    assert(json == NULL);
    qihse_document_result_t rows = qihse_doc_store_list_user(store, user, 8u);
    assert(rows.count == 0u && rows.doc_ids == NULL);
    json = (char*)1;
    assert(!qihse_doc_store_get_version_json_user(store, 91u, 1u, user, &json));
    assert(json == NULL);
    qihse_document_versions_t versions = qihse_doc_store_list_versions_user(
        store, 91u, user);
    assert(versions.count == 0u && versions.versions == NULL);
}

int main(void) {
    char root[] = "build/test_document_store_user_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DocumentUserOperator123!"));
    qihse_user_t* system = qihse_auth_get_user(0u);
    assert(system);
    qihse_user_t* high = principal(system, 91u, 9101u, 5u, 1u,
        "DocumentUserHigh123!");
    qihse_user_t* reader = principal(system, 91u, 9102u, 5u, 1u,
        "DocumentUserReader123!");
    qihse_user_t* low = principal(system, 91u, 9103u, 0u, 0u,
        "DocumentUserLow123!");
    qihse_user_t* wrong_sci = principal(system, 91u, 9104u, 5u, 2u,
        "DocumentUserWrongSci123!");
    qihse_user_t* wrong_tenant = principal(system, 92u, 9201u, 5u, 1u,
        "DocumentUserWrongTenant123!");
    qihse_document_store_t* store = qihse_doc_store_create(NULL);
    assert(store);

    assert(qihse_doc_store_insert_json(store, 90u,
        "{\"legacy\":\"UNTRUSTED_UNLABELED\"}"));
    assert(qihse_doc_store_insert_json(store, 91u,
        "{\"legacy\":\"UNTRUSTED_DUPLICATE_ID\"}"));
    assert(qihse_doc_store_insert_json_user(store, 91u,
        "{\"secret\":\"HIGH_DOCUMENT_SECRET\"}", high));
    assert(qihse_doc_store_insert_json_user(store, 92u,
        "{\"secret\":\"SECOND_HIGH_SECRET\"}", high));
    assert(qihse_doc_store_insert_json_user(store, 94u,
        "{\"public\":\"LOW_VERSION_ONE\"}", low));
    assert(qihse_doc_store_insert_json_user(store, 94u,
        "{\"secret\":\"HIGH_VERSION_TWO\"}", high));
    /* Once a high label is appended, a lower-clearance writer cannot create
     * a later low version whose sequential ID would reveal the hidden gap. */
    assert(!qihse_doc_store_insert_json_user(store, 94u,
        "{\"public\":\"FORBIDDEN_LOW_VERSION_THREE\"}", low));
    assert(!qihse_doc_store_insert_json_user(store, 94u,
        "{\"public\":\"FORBIDDEN_WRONG_SCI_VERSION_THREE\"}", wrong_sci));
    assert(!qihse_doc_store_insert_json_user(store, 91u,
        "{\"secret\":\"LOW_OVERWRITE\"}", low));
    assert(!qihse_doc_store_insert_json_user(store, 93u, "{}", NULL));

    denied(store, low);
    denied(store, wrong_sci);
    denied(store, wrong_tenant);
    denied(store, NULL);
    char* json = (char*)1;
    assert(!qihse_doc_store_get_json_user(store, 90u, reader, &json));
    assert(json == NULL);
    assert(qihse_doc_store_get_json_user(store, 91u, reader, &json));
    assert(strcmp(json, "{\"secret\":\"HIGH_DOCUMENT_SECRET\"}") == 0);
    free(json);
    assert(qihse_doc_store_get_version_json_user(store, 91u, 1u, reader, &json));
    assert(strcmp(json, "{\"secret\":\"HIGH_DOCUMENT_SECRET\"}") == 0);
    free(json);
    assert(qihse_doc_store_get_version_json_user(store, 94u, 1u, low, &json));
    assert(strcmp(json, "{\"public\":\"LOW_VERSION_ONE\"}") == 0);
    free(json);
    assert(!qihse_doc_store_get_version_json_user(store, 94u, 2u, low, &json));
    assert(json == NULL);
    assert(!qihse_doc_store_get_version_json_user(store, 94u, 3u, low, &json));
    assert(json == NULL);
    assert(!qihse_doc_store_get_json_user(store, 94u, low, &json));
    qihse_document_versions_t versions = qihse_doc_store_list_versions_user(
        store, 94u, low);
    assert(versions.count == 1u && versions.versions[0] == 1u);
    free(versions.versions);
    versions = qihse_doc_store_list_versions_user(store, 94u, reader);
    assert(versions.count == 2u && versions.versions[0] == 2u &&
           versions.versions[1] == 1u);
    free(versions.versions);
    qihse_document_result_t rows = qihse_doc_store_list_user(store, reader, 1u);
    assert(rows.count == 1u && rows.doc_ids && rows.doc_ids[0] == 94u);
    free(rows.doc_ids);
    rows = qihse_doc_store_list_user(store, reader, 2u);
    assert(rows.count == 2u && rows.doc_ids[0] == 94u && rows.doc_ids[1] == 92u);
    free(rows.doc_ids);
    rows = qihse_doc_store_list_user(store, reader, QIHSE_DOC_USER_LIST_MAX + 1u);
    assert(rows.count == 0u && rows.doc_ids == NULL);
    concurrent_args_t concurrent = { store, high, reader };
    pthread_t writer_thread, reader_thread;
    assert(pthread_create(&writer_thread, NULL, concurrent_writer, &concurrent) == 0);
    assert(pthread_create(&reader_thread, NULL, concurrent_reader, &concurrent) == 0);
    assert(pthread_join(writer_thread, NULL) == 0);
    assert(pthread_join(reader_thread, NULL) == 0);
    versions = qihse_doc_store_list_versions_user(store, 91u, reader);
    assert(versions.count == QIHSE_DOC_VERSION_RETENTION);
    assert(versions.versions[0] == 101u && versions.versions[15] == 86u);
    free(versions.versions);
    assert(!qihse_doc_store_get_version_json_user(store, 91u, 85u, reader, &json));
    assert(json == NULL);
    assert(qihse_doc_store_get_version_json_user(store, 91u, 86u, reader, &json));
    free(json);
    assert(qihse_auth_modify_user(system, 9101u, NULL, NULL, -1, -1, 0, 0));
    assert(!qihse_doc_store_insert_json_user(store, 91u,
        "{\"secret\":\"DOWNGRADED_WRITER\"}", high));
    assert(qihse_auth_destroy_user(system, 9102u));
    denied(store, reader);

    qihse_doc_store_destroy(store);
    puts("test_document_store_user: all assertions passed");
    return 0;
}
