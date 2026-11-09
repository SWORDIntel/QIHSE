#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct_codec.h"
#include <assert.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PASSWORD "CtCodecAuthFixture1!"

static int remove_path(const char* path, const struct stat* st, int type,
                       struct FTW* info) {
    (void)st; (void)type; (void)info;
    return remove(path);
}
static void denied(FILE* frame, size_t size, qihse_user_t* principal,
                   qihse_kv_ct_tenant_policy_t policy, uint32_t tenant,
                   bool before_body) {
    rewind(frame);
    qihse_kv_ct_group_t out = {0}; uint8_t mode = 99u; size_t read_bytes = 99u;
    assert(qihse_ct_codec_read(frame, principal, policy, tenant, size,
                               &out, &mode, &read_bytes) == -2);
    assert(!out.records && !out.count && !out.stream_position &&
           mode == 0u && read_bytes == 0u);
    if (before_body) assert(ftell(frame) < (long)size);
}
int main(void) {
    umask(0077);
    assert(mkdir("build", 0700) == 0 || access("build", F_OK) == 0);
    char temp[] = "build/ct-codec-auth-XXXXXX";
    assert(mkdtemp(temp));
    char* dir = realpath(temp, NULL); assert(dir);
    pid_t child = fork(); assert(child >= 0);
    if (child != 0) {
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(nftw(temp, remove_path, 8, FTW_DEPTH | FTW_PHYS) == 0);
        free(dir);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        puts("CT codec registry authorization tests passed");
        return 0;
    }
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, PASSWORD); assert(op);
    qihse_user_t* low = qihse_auth_create_tenant_user(op, 7u, 301u,
        QIHSE_ROLE_ANALYST, 0u, 0u, PASSWORD, false);
    qihse_user_t* no_sci = qihse_auth_create_tenant_user(op, 7u, 302u,
        QIHSE_ROLE_ANALYST, 4u, 0u, PASSWORD, false);
    qihse_user_t* high = qihse_auth_create_tenant_user(op, 7u, 303u,
        QIHSE_ROLE_ANALYST, 4u, 2u, PASSWORD, false);
    qihse_user_t* wrong_tenant = qihse_auth_create_tenant_user(op, 8u, 304u,
        QIHSE_ROLE_ANALYST, 4u, 2u, PASSWORD, false);
    qihse_user_t* system_service = qihse_auth_create_user(op, 305u,
        QIHSE_ROLE_ANALYST, 4u, 2u, PASSWORD, false);
    assert(low && no_sci && high && wrong_tenant && system_service);
    qihse_kv_ct_record_t record = {
        .key = "t:7/secret", .value = "CLASSIFIED PAYLOAD", .change_seq = 17u,
        .actor_id = 303u, .actor_tenant_id = 7u, .resource_tenant_id = 7u,
        .classification = 4u, .sci_compartment = 2u,
        .actor_kind = QIHSE_KV_CT_ACTOR_USER
    };
    qihse_kv_ct_group_t group = {
        .source_id = "192.168.1.90:6379", .generation = "generation.v1",
        .stream_position = 1u, .first_seq = 17u, .last_seq = 17u,
        .records = &record, .count = 1u
    };
    size_t written = 0u;
    FILE* frame = tmpfile(); assert(frame);
    assert(qihse_ct_codec_write(frame, op, QIHSE_KV_CT_TENANT_EXACT, 7u,
                                QIHSE_CT_CODEC_MODE_SOURCE, &group, 4096u,
                                &written));
    assert(written > 96u);
    denied(frame, written, low, QIHSE_KV_CT_TENANT_EXACT, 7u, true);
    denied(frame, written, no_sci, QIHSE_KV_CT_TENANT_EXACT, 7u, true);
    denied(frame, written, wrong_tenant, QIHSE_KV_CT_TENANT_EXACT, 7u, true);
    denied(frame, written, NULL, QIHSE_KV_CT_TENANT_EXACT, 7u, true);
    rewind(frame);
    qihse_kv_ct_group_t out = {0}; uint8_t mode = 0u; size_t bytes = 0u;
    assert(qihse_ct_codec_read(frame, high, QIHSE_KV_CT_TENANT_EXACT, 7u,
                               written, &out, &mode, &bytes) == 1);
    assert(mode == QIHSE_CT_CODEC_MODE_SOURCE && bytes == written &&
           !strcmp(out.records[0].value, "CLASSIFIED PAYLOAD"));
    qihse_ct_codec_clear(&out);
    size_t size = 99u;
    assert(!qihse_ct_codec_encoded_size(low, QIHSE_KV_CT_TENANT_EXACT, 7u,
                                        1u, &group, 4096u, &size) && size == 0u);
    assert(qihse_ct_codec_encoded_size(system_service,
                                       QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                                       1u, &group, 4096u, &size));
    assert(qihse_auth_destroy_user(op, 303u));
    denied(frame, written, high, QIHSE_KV_CT_TENANT_EXACT, 7u, true);
    assert(!qihse_ct_codec_encoded_size(high, QIHSE_KV_CT_TENANT_EXACT, 7u,
                                        1u, &group, 4096u, &size));
    fclose(frame);
    _exit(0);
}
