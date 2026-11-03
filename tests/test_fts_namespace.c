#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "qihse_resp_fts_namespace.h"

int main(void) {
    qihse_resp_fts_namespace_registry_t* registry = qihse_resp_fts_namespace_registry_create();
    assert(registry != NULL);
    assert(qihse_resp_fts_namespace_register(registry, 11, "catalog", "t:11/app/*"));
    assert(qihse_resp_fts_namespace_register(registry, 22, "catalog", "t:22/app/*"));
    assert(!qihse_resp_fts_namespace_register(registry, 11, "CATALOG", "t:11/other/*"));

    qihse_resp_fts_namespace_t tenant11, tenant22;
    assert(qihse_resp_fts_namespace_resolve(registry, 11, "CATALOG", &tenant11));
    assert(strcmp(tenant11.name, "catalog") == 0);
    assert(qihse_resp_fts_namespace_resolve(registry, 22, "catalog", &tenant22));
    assert(memcmp(tenant11.artifact_digest, tenant22.artifact_digest,
                  sizeof(tenant11.artifact_digest)) != 0);
    assert(qihse_resp_fts_namespace_key_allowed(&tenant11, "t:11/app/doc"));
    assert(!qihse_resp_fts_namespace_key_allowed(&tenant11, "t:22/app/doc"));
    assert(!qihse_resp_fts_namespace_key_allowed(&tenant11, "t:11/other/doc"));
    assert(!qihse_resp_fts_namespace_key_allowed(&tenant11, "t:110/app/doc"));
    assert(!qihse_resp_fts_namespace_resolve(registry, 11, "bad/name", &tenant22));
    qihse_resp_fts_namespace_t shared;
    assert(!qihse_resp_fts_namespace_register(registry, 11, "shared", "commons/docs/*"));
    assert(!qihse_resp_fts_namespace_resolve(registry, 11, "shared", &shared));
    assert(!qihse_resp_fts_namespace_key_allowed(&tenant11, "commons/docs/readme"));
    assert(!qihse_resp_fts_namespace_register(registry, 11, "escape", "commons/../t:11/*"));
    assert(!qihse_resp_fts_namespace_resolve(registry, 22, "missing", &tenant22));
    assert(!qihse_resp_fts_namespace_register(registry, 11, "escape", "t:22/*"));
    assert(!qihse_resp_fts_namespace_register(registry, 11, "../escape", "t:11/*"));

    assert(qihse_resp_fts_default_key_allowed(11, "t:11/docs/a"));
    assert(!qihse_resp_fts_default_key_allowed(11, "t:22/docs/a"));
    assert(!qihse_resp_fts_default_key_allowed(11, "commons/docs/a"));
    assert(qihse_resp_fts_default_key_allowed(0, "docs/a"));
    assert(!qihse_resp_fts_default_key_allowed(0, "t:11/docs/a"));

    char index1[512], sidecar1[512], index2[512], sidecar2[512];
    assert(qihse_resp_fts_namespace_artifact_paths("build/fts", &tenant11,
                                                   index1, sizeof(index1),
                                                   sidecar1, sizeof(sidecar1)));
    assert(qihse_resp_fts_namespace_artifact_paths("build/fts", &tenant22,
                                                   index2, sizeof(index2),
                                                   sidecar2, sizeof(sidecar2)));
    assert(strcmp(index1, index2) != 0 && strcmp(sidecar1, sidecar2) != 0);
    assert(strcmp(index1, "build/fts/fts-11-") > 0);
    assert(strstr(index1, ".qfts") != NULL && strstr(sidecar1, ".keys") != NULL);
    char short_index[2] = "x", short_sidecar[2] = "y";
    assert(!qihse_resp_fts_namespace_artifact_paths("build/fts", &tenant11,
                                                    short_index, sizeof(short_index),
                                                    short_sidecar, sizeof(short_sidecar)));
    assert(short_index[0] == '\0' && short_sidecar[0] == '\0');
    assert(!qihse_resp_fts_namespace_artifact_paths("build/fts", &tenant11,
                                                    index1, 0, sidecar1, sizeof(sidecar1)));
    assert(!qihse_resp_fts_namespace_artifact_paths("", &tenant11,
                                                    index1, sizeof(index1), sidecar1, sizeof(sidecar1)));
    qihse_resp_fts_namespace_registry_destroy(registry);
    puts("test_fts_namespace: all assertions passed");
    return 0;
}
