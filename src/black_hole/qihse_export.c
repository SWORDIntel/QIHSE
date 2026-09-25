#include "qihse_export.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct {
    FILE* out;
    uint32_t tenant_id;
    size_t record_count;
    bool ok;
} export_ctx_t;

static bool export_key_in_scope(uint32_t tenant_id, const char* key) {
    /* Own tenant namespace or the shared commons namespace. */
    char prefix[32];
    int plen = snprintf(prefix, sizeof(prefix), "t:%u/", tenant_id);
    if (plen > 0 && (size_t)plen < sizeof(prefix) && strncmp(key, prefix, (size_t)plen) == 0) return true;
    return strncmp(key, "commons/", 8u) == 0;
}

static bool export_kv_cb(const char* key, const char* value, void* user_data) {
    export_ctx_t* ctx = (export_ctx_t*)user_data;
    if (!ctx->ok) return false;
    if (!export_key_in_scope(ctx->tenant_id, key)) return true; /* skip quietly */
    /* Length-prefixed records: values are C strings but may contain any
     * non-NUL bytes, including newlines and '|' separators. */
    size_t klen = strlen(key);
    size_t vlen = strlen(value);
    if (fprintf(ctx->out, "K %zu %zu\n", klen, vlen) < 0 ||
        fwrite(key, 1, klen, ctx->out) != klen ||
        fwrite(value, 1, vlen, ctx->out) != vlen ||
        fputc('\n', ctx->out) == EOF) {
        ctx->ok = false;
        return false;
    }
    ctx->record_count++;
    return true;
}

static bool export_blob_cb(const qihse_blob_info_t* info, void* user_data) {
    export_ctx_t* ctx = (export_ctx_t*)user_data;
    char hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(info->hash, hex);
    if (fprintf(ctx->out, "B %s %llu %u %u\n", hex,
                (unsigned long long)info->size, info->tag, info->refcount) < 0) {
        ctx->ok = false;
        return false;
    }
    return true;
}

bool qihse_export_tenant_user(qihse_kv_store_t* kv, qihse_blob_store_t* blobs,
                              uint32_t tenant_id, qihse_user_t* user,
                              const char* out_path,
                              char* err, size_t err_cap) {
    if (err && err_cap > 0) err[0] = '\0';
    if (!kv || !user || !out_path || !*out_path) {
        if (err) snprintf(err, err_cap, "invalid arguments");
        return false;
    }
    if (!qihse_auth_user_is_active(user)) {
        if (err) snprintf(err, err_cap, "principal is not active");
        return false;
    }
    uint32_t user_tenant = qihse_user_get_tenant_id(user);
    if (user_tenant != QIHSE_TENANT_SYSTEM && user_tenant != tenant_id) {
        if (err) snprintf(err, err_cap, "export of a foreign tenant is not permitted");
        return false;
    }

    char tmp_path[576];
    snprintf(tmp_path, sizeof(tmp_path), "%s.export-tmp", out_path);
    FILE* out = fopen(tmp_path, "wb");
    if (!out) {
        if (err) snprintf(err, err_cap, "cannot create export artifact");
        return false;
    }

    export_ctx_t ctx = { out, tenant_id, 0, true };
    fprintf(out, "QIHSE-TENANT-EXPORT 1\ntenant:%u\n", tenant_id);

    /* Authorization-aware iteration: records above the caller's clearance
     * are filtered inside the KV layer (same behavior as KEYS/save). */
    if (!qihse_kv_foreach_user(kv, user, export_kv_cb, &ctx)) {
        if (ctx.ok && err) snprintf(err, err_cap, "KV iteration failed");
    }
    if (ctx.ok && blobs) {
        qihse_blob_list_user(blobs, user, export_blob_cb, &ctx);
    }
    if (fflush(out) != 0 || fsync(fileno(out)) != 0) ctx.ok = false;
    fclose(out);

    if (!ctx.ok) {
        unlink(tmp_path);
        if (err && err[0] == '\0') snprintf(err, err_cap, "export write failed");
        return false;
    }
    if (rename(tmp_path, out_path) != 0) {
        unlink(tmp_path);
        if (err) snprintf(err, err_cap, "cannot commit export artifact");
        return false;
    }
    return true;
}

/* ── Incremental (delta) export ───────────────────────────────────────────
 *
 * The gates this layer owns (this family's convention): NULL context is an
 * argument error — never the KV layer's unclassified-only fallback view —
 * and the handle must be a live principal.  Everything classified is
 * decided one layer down, inside the KV store's delta iteration, which
 * applies the same per-record qihse_auth_can_access check the full export
 * applies (AGENTS.md invariant 1: the identity reaches the lowest
 * data-retrieval layer; no classifier is re-implemented here).
 *
 * The resume point is computed down there too, deliberately: it is the
 * highest sequence the principal was ALLOWED to see, so hidden mutations
 * are filtered out before it is derived and a restricted principal cannot
 * count them from gaps.  This surface offers no "global high-water" form. */
bool qihse_export_incremental_user(qihse_kv_store_t* kv, qihse_user_t* user,
                                   uint64_t since_seq,
                                   qihse_kv_delta_record_t** out_records,
                                   size_t* out_count, uint64_t* out_resume_seq,
                                   char* err, size_t err_cap) {
    if (err && err_cap > 0) err[0] = '\0';
    if (out_records) *out_records = NULL;
    if (out_count) *out_count = 0u;
    if (out_resume_seq) *out_resume_seq = 0u;
    if (!kv || !out_records || !out_count || !out_resume_seq) {
        if (err) snprintf(err, err_cap, "invalid arguments");
        return false;
    }
    /* A NULL context is an argument error, never "export everything" and
     * never a silent fallback to the KV layer's unclassified-only view. */
    if (!user) {
        if (err) snprintf(err, err_cap, "an authenticated security context is required");
        return false;
    }
    if (!qihse_auth_user_is_active(user)) {
        if (err) snprintf(err, err_cap, "principal is not active");
        return false;
    }
    int rc = qihse_kv_export_incremental_user(kv, user, since_seq,
                                              out_records, out_count, out_resume_seq);
    if (rc != 0) {
        *out_records = NULL;
        *out_count = 0u;
        *out_resume_seq = 0u;
        if (err) snprintf(err, err_cap, "delta enumeration failed");
        return false;
    }
    return true;
}
