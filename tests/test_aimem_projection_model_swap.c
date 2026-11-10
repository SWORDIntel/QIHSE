/* Deterministic enabled-projection cache identity/re-enable fixture.
 * The provider callback and ONNX-active predicate are mocked; this validates
 * KEYSTONE projection/cache behaviour, not ONNX Runtime/model integration. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ai_memory.h"
#include "qihse_aimem_onnx_embedder.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The enabled projection engine checks the optional ONNX adapter's live
 * state. This executable supplies that state while exercising the public
 * custom-provider and fingerprint APIs with a deterministic callback. */
bool qihse_aimem_onnx_embedder_active(void) { return true; }

static bool fixture_embed(const char* text, float* out, size_t dim, void* opaque) {
    (void)opaque;
    if (!text || !out || dim < 2u) return false;
    memset(out, 0, dim * sizeof(*out));
    unsigned bucket = 0u;
    for (const unsigned char* p = (const unsigned char*)text; *p; ++p)
        bucket = (bucket * 33u + *p) % (unsigned)(dim - 1u);
    out[bucket] = 1.0f;
    out[dim - 1u] = 0.25f;
    return true;
}

static int remove_fixture(const char* path, const struct stat* st,
        int flag, struct FTW* walk) {
    (void)st; (void)walk;
    return flag == FTW_D || flag == FTW_DP ? rmdir(path) : unlink(path);
}

static void set_model(qihse_ai_memory_embedder_t* provider, uint8_t fingerprint[32],
                      uint8_t marker) {
    memset(fingerprint, marker, 32u);
    assert(qihse_ai_memory_set_embedder(provider));
    assert(qihse_ai_memory_set_embedder_fingerprint(fingerprint));
}

int main(void) {
    const char* library = getenv("QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY");
    if (!library || !*library) {
        puts("SKIP: set QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY");
        return 77;
    }
    char data_dir[] = "./aimem_projection_swap_XXXXXX";
    assert(mkdtemp(data_dir) && chmod(data_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ProjectionSwapOperator123!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    qihse_user_t* owner = qihse_auth_create_tenant_user(operator_user, 31u, 3101u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "ProjectionSwapOwner123!", false);
    assert(owner);
    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv);
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = kv;
    config.port = 0u;
    config.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);

    qihse_ai_memory_embedder_t provider = {
        .name = "projection-swap-fixture-v1", .dim = 16u,
        .embed = fixture_embed, .ctx = NULL
    };
    uint8_t model_a[32], model_b[32];
    set_model(&provider, model_a, 0x31u);
    qihse_ai_memory_scope_t scope = {"swap-test", "tree", "stream", "session"};
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, owner,
        "vector cache must follow its model identity", QIHSE_AIMEM_SEMANTIC,
        &scope, id));

    assert(qihse_ai_memory_projection_enable(server, owner, library, data_dir));
    assert(qihse_ai_memory_projection_wait_ready(server, owner, 30000u));

    /* Changing model identity without a KV mutation must make the old
     * projection unusable. Shutdown/re-enable is the supported rebinding
     * boundary; the new identity gets its own cache file. */
    provider.name = "projection-swap-fixture-v2";
    set_model(&provider, model_b, 0x72u);
    qihse_ai_memory_hit_t hits[4] = {0};
    size_t count = qihse_ai_memory_recall_scoped(server, owner, "cache identity",
        4u, QIHSE_AIMEM_MODE_SEMANTIC, QIHSE_AIMEM_KIND_ANY, &scope, hits, 4u);
    assert(count == 0u && errno == ESTALE);
    qihse_ai_memory_projection_shutdown(server);
    assert(qihse_ai_memory_projection_enable(server, owner, library, data_dir));
    assert(qihse_ai_memory_projection_wait_ready(server, owner, 30000u));
    count = qihse_ai_memory_recall_scoped(server, owner, "cache identity",
        4u, QIHSE_AIMEM_MODE_SEMANTIC, QIHSE_AIMEM_KIND_ANY, &scope, hits, 4u);
    assert(errno == 0 && count == 1u && strcmp(hits[0].id, id) == 0);
    qihse_ai_memory_hits_free(hits, count);
    qihse_ai_memory_projection_shutdown(server);

    /* Reopening model A must still select its own cache rather than trying
     * to open model B's database identity. No source mutation is involved. */
    provider.name = "projection-swap-fixture-v1";
    assert(qihse_ai_memory_set_embedder(&provider));
    assert(qihse_ai_memory_set_embedder_fingerprint(model_a));
    assert(qihse_ai_memory_projection_enable(server, owner, library, data_dir));
    assert(qihse_ai_memory_projection_wait_ready(server, owner, 30000u));
    qihse_ai_memory_projection_shutdown(server);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);
    qihse_audit_shutdown();
    assert(nftw(data_dir, remove_fixture, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("PASS mocked KEYSTONE model-bound cache re-enable without KV mutation");
    return 0;
}
