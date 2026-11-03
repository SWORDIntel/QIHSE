#ifndef QIHSE_RESP_FTS_NAMESPACE_H
#define QIHSE_RESP_FTS_NAMESPACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QIHSE_RESP_FTS_NAMESPACE_MAX_NAME 128u
#define QIHSE_RESP_FTS_NAMESPACE_MAX_GLOB 256u
#define QIHSE_RESP_FTS_NAMESPACE_MAX_ENTRIES 256u
#define QIHSE_RESP_FTS_NAMESPACE_DIGEST_BYTES 32u

typedef struct {
    uint32_t tenant_id;
    char name[QIHSE_RESP_FTS_NAMESPACE_MAX_NAME + 1u];
    char key_glob[QIHSE_RESP_FTS_NAMESPACE_MAX_GLOB + 1u];
    uint8_t artifact_digest[QIHSE_RESP_FTS_NAMESPACE_DIGEST_BYTES];
} qihse_resp_fts_namespace_t;

typedef struct qihse_resp_fts_namespace_registry qihse_resp_fts_namespace_registry_t;

/* Registry contents are installed from trusted server configuration at startup.
 * Names and globs are copied; artifact identity is derived, never caller-supplied. */
qihse_resp_fts_namespace_registry_t* qihse_resp_fts_namespace_registry_create(void);
void qihse_resp_fts_namespace_registry_destroy(qihse_resp_fts_namespace_registry_t* registry);
bool qihse_resp_fts_namespace_register(qihse_resp_fts_namespace_registry_t* registry,
                                       uint32_t tenant_id, const char* canonical_name,
                                       const char* allowlisted_key_glob);
bool qihse_resp_fts_namespace_resolve(const qihse_resp_fts_namespace_registry_t* registry,
                                      uint32_t tenant_id, const char* canonical_name,
                                      qihse_resp_fts_namespace_t* out);
/* Enforce isolation even when a registered glob is broad: tenant-default is
 * t:<id>/ only, system default excludes tenant-prefixed rows. */
bool qihse_resp_fts_namespace_key_allowed(const qihse_resp_fts_namespace_t* scope,
                                          const char* key);
/* Built-in default scope: tenant 0 excludes all tenant-prefixed keys; tenant
 * N accepts only t:N/ keys. Shared commons/ is excluded for all defaults. */
bool qihse_resp_fts_default_key_allowed(uint32_t tenant_id, const char* key);
/* Produce safe index and sidecar paths beneath a configured root. */
bool qihse_resp_fts_namespace_artifact_paths(const char* root,
                                              const qihse_resp_fts_namespace_t* scope,
                                              char* index_path, size_t index_cap,
                                              char* sidecar_path, size_t sidecar_cap);

#endif
