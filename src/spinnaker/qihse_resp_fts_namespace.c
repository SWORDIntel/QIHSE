#include "qihse_resp_fts_namespace.h"

#include <fnmatch.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct qihse_resp_fts_namespace_registry {
    size_t count;
    qihse_resp_fts_namespace_t entries[QIHSE_RESP_FTS_NAMESPACE_MAX_ENTRIES];
};

static bool valid_name(const char* s) {
    if (!s || !*s || strlen(s) > QIHSE_RESP_FTS_NAMESPACE_MAX_NAME) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p)
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.' )) return false;
    return strcmp(s, ".") && strcmp(s, "..") && strstr(s, "..") == NULL;
}

static void canonicalize_name(char* dst, const char* src) {
    size_t i = 0;
    for (; src[i]; ++i) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (char)((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
    }
    dst[i] = '\0';
}

static bool valid_glob(const char* s) {
    if (!s || !*s || strlen(s) > QIHSE_RESP_FTS_NAMESPACE_MAX_GLOB) return false;
    /* Every namespace must be confined to its tenant-owned key prefix. */
    return strncmp(s, "t:", 2) == 0 && strchr(s, '/') != NULL &&
           !strstr(s, "../") && !strchr(s, '\\');
}

qihse_resp_fts_namespace_registry_t* qihse_resp_fts_namespace_registry_create(void) {
    return calloc(1, sizeof(qihse_resp_fts_namespace_registry_t));
}

void qihse_resp_fts_namespace_registry_destroy(qihse_resp_fts_namespace_registry_t* r) { free(r); }

bool qihse_resp_fts_namespace_register(qihse_resp_fts_namespace_registry_t* r,
                                       uint32_t tenant, const char* name, const char* glob) {
    if (!r || tenant == 0 || !valid_name(name) || !valid_glob(glob) || r->count >= QIHSE_RESP_FTS_NAMESPACE_MAX_ENTRIES) return false;
    char canonical[QIHSE_RESP_FTS_NAMESPACE_MAX_NAME + 1u];
    canonicalize_name(canonical, name);
    char prefix[32];
    int n = snprintf(prefix, sizeof(prefix), "t:%u/", tenant);
    if (n <= 0 || (strncmp(glob, prefix, (size_t)n) != 0 && strncmp(glob, "commons/", 8u) != 0)) return false;
    for (size_t i = 0; i < r->count; ++i)
        if (r->entries[i].tenant_id == tenant && strcmp(r->entries[i].name, canonical) == 0) return false;
    qihse_resp_fts_namespace_t* e = &r->entries[r->count];
    e->tenant_id = tenant;
    memcpy(e->name, canonical, strlen(canonical) + 1u);
    memcpy(e->key_glob, glob, strlen(glob) + 1u);
    /* Stable artifact namespace identity; SHA-256 covers tenant and canonical name. */
    char identity[sizeof(tenant) + QIHSE_RESP_FTS_NAMESPACE_MAX_NAME];
    identity[0] = (char)(tenant >> 24);
    identity[1] = (char)(tenant >> 16);
    identity[2] = (char)(tenant >> 8);
    identity[3] = (char)tenant;
    memcpy(identity + sizeof(tenant), canonical, strlen(canonical));
    SHA256((const unsigned char*)identity, sizeof(tenant) + strlen(canonical), e->artifact_digest);
    ++r->count;
    return true;
}

bool qihse_resp_fts_namespace_resolve(const qihse_resp_fts_namespace_registry_t* r,
                                      uint32_t tenant, const char* name,
                                      qihse_resp_fts_namespace_t* out) {
    if (!r || !valid_name(name) || !out) return false;
    char canonical[QIHSE_RESP_FTS_NAMESPACE_MAX_NAME + 1u];
    canonicalize_name(canonical, name);
    for (size_t i = 0; i < r->count; ++i)
        if (r->entries[i].tenant_id == tenant && strcmp(r->entries[i].name, canonical) == 0) { *out = r->entries[i]; return true; }
    return false;
}

bool qihse_resp_fts_default_key_allowed(uint32_t tenant, const char* key) {
    if (!key || strncmp(key, "commons/", 8u) == 0) return false;
    if (tenant != 0) {
        char prefix[32];
        int n = snprintf(prefix, sizeof(prefix), "t:%u/", tenant);
        return n > 0 && strncmp(key, prefix, (size_t)n) == 0;
    }
    return strncmp(key, "t:", 2u) != 0;
}

bool qihse_resp_fts_namespace_key_allowed(const qihse_resp_fts_namespace_t* s, const char* key) {
    if (!s || !key) return false;
    char prefix[32];
    int n = snprintf(prefix, sizeof(prefix), "t:%u/", s->tenant_id);
    bool owned = n > 0 && strncmp(key, prefix, (size_t)n) == 0;
    return owned && fnmatch(s->key_glob, key, 0) == 0;
}

bool qihse_resp_fts_namespace_artifact_paths(const char* root,
                                              const qihse_resp_fts_namespace_t* s,
                                              char* index, size_t icap,
                                              char* sidecar, size_t scap) {
    if (!root || !*root || !s || !index || !sidecar || icap == 0 || scap == 0) return false;
    char hex[QIHSE_RESP_FTS_NAMESPACE_DIGEST_BYTES * 2u + 1u];
    for (size_t i = 0; i < sizeof(s->artifact_digest); ++i) snprintf(hex + i * 2u, 3u, "%02x", s->artifact_digest[i]);
    int a = snprintf(index, icap, "%s/fts-%u-%s.qfts", root, s->tenant_id, hex);
    int b = snprintf(sidecar, scap, "%s/fts-%u-%s.keys", root, s->tenant_id, hex);
    if (a <= 0 || b <= 0 || (size_t)a >= icap || (size_t)b >= scap) {
        index[0] = '\0';
        sidecar[0] = '\0';
        return false;
    }
    return true;
}
