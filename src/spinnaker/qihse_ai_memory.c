/* Local-first AI memory over the native KV store + FTS index.
 *
 * Record layout:
 *   key   aimem:<doc-id as 16 hex chars>
 *   legacy value <uuid>|<created_ms>|<kind>|<classif>|<sci>|<text>
 *   scoped value v2|<uuid>|<created_ms>|<kind>|<classif>|<sci>|<owner>|<project>|<worktree>|<workstream>|<session>|<text>
 *
 * The legacy unscoped search index is process-local and rebuilt from KV.
 * Scoped BM25 projections are persisted under the private QIHSE data root and
 * generation-bound to the KV change sequence. Canonical KV records remain
 * authoritative; every returned candidate is resolved and reauthorized.
 * Forgetting a memory removes the KV record, and any stale posting is ignored
 * at read time (the FTS engine has no delete primitive).
 *
 * Reads are narrowed, never widened: every candidate is resolved through the
 * authorization-aware KV read first, and the kind filter is applied to the
 * result of that resolve, so no filter value can reach a record the principal
 * cannot read.
 */
#include "qihse_ai_memory.h"

#include "qihse_federation.h"
#include "qihse_fts.h"
#include "qihse_kv_store.h"
#include "qihse_audit.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define AIMEM_PREFIX "aimem:"
#define AIMEM_PREFIX_LEN (sizeof(AIMEM_PREFIX) - 1u)
#define AIMEM_MAX_TEXT (64u * 1024u)

static qihse_fts_index_t* g_aimem_index = NULL;
static pthread_mutex_t g_aimem_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_knowledge_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_migration_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_archive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_scope_index_lock = PTHREAD_MUTEX_INITIALIZER;

/* Defined with the embedding block below; reset() needs it earlier. */
static void aimem_vecs_clear(void);

static uint64_t aimem_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* doc_id = first 8 bytes of the UUID, big-endian: stable, collision-resistant
 * enough for a local memory surface, and cheap to re-derive from the id. */
static uint64_t aimem_doc_id(const qihse_uuid_t* id) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8u; i++) v = (v << 8) | id->bytes[i];
    return v;
}

static void aimem_key(char* out, size_t cap, uint64_t doc_id) {
    snprintf(out, cap, AIMEM_PREFIX "%016llx", (unsigned long long)doc_id);
}

/* Scoped records live in the authenticated tenant namespace. The KV layer
 * enforces classification/SCI; this explicit prefix enforces tenant bounds. */
static bool aimem_scoped_key(char* out, size_t cap, qihse_user_t* user,
                             uint64_t doc_id) {
    if (!user || !qihse_auth_user_is_active(user)) return false;
    int n = snprintf(out, cap, "t:%u/aimem:%016llx",
                     (unsigned)qihse_user_get_tenant_id(user),
                     (unsigned long long)doc_id);
    return n > 0 && (size_t)n < cap;
}

static bool aimem_scope_id_valid(const char* id, bool required) {
    if (!id || !*id) return !required;
    size_t n = strnlen(id, QIHSE_AIMEM_SCOPE_ID_MAX + 1u);
    if (n == 0u || n > QIHSE_AIMEM_SCOPE_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return false;
    }
    return true;
}

static bool aimem_scope_valid(const qihse_ai_memory_scope_t* scope) {
    if (!scope || !aimem_scope_id_valid(scope->project, true) ||
        !aimem_scope_id_valid(scope->worktree, false) ||
        !aimem_scope_id_valid(scope->workstream, false) ||
        !aimem_scope_id_valid(scope->session, false)) return false;
    /* A lower coordinate is meaningful only inside its parent. This prevents
     * a session or stream name from matching across unrelated worktrees. */
    return (!scope->workstream[0] || scope->worktree[0]) &&
           (!scope->session[0] || scope->workstream[0]);
}

static bool aimem_scope_matches(const qihse_ai_memory_scope_t* record,
                                const qihse_ai_memory_scope_t* query) {
    return aimem_scope_valid(query) && record &&
           strcmp(record->project, query->project) == 0 &&
           (!query->worktree[0] || strcmp(record->worktree, query->worktree) == 0) &&
           (!query->workstream[0] || strcmp(record->workstream, query->workstream) == 0) &&
           (!query->session[0] || strcmp(record->session, query->session) == 0);
}

static bool aimem_parse_u32_field(const char** cursor, uint32_t* out) {
    if (!cursor || !*cursor || !out) return false;
    char* end = NULL;
    errno = 0;
    unsigned long value = strtoul(*cursor, &end, 10);
    if (errno || end == *cursor || *end != '|' || value > UINT32_MAX) return false;
    *out = (uint32_t)value;
    *cursor = end + 1;
    return true;
}

static bool aimem_parse_scope_field(const char** cursor, char out[QIHSE_AIMEM_SCOPE_ID_MAX + 1u]) {
    if (!cursor || !*cursor || !out) return false;
    const char* end = strchr(*cursor, '|');
    if (!end || (size_t)(end - *cursor) > QIHSE_AIMEM_SCOPE_ID_MAX) return false;
    size_t n = (size_t)(end - *cursor);
    memcpy(out, *cursor, n);
    out[n] = '\0';
    if (!aimem_scope_id_valid(out, false)) return false;
    *cursor = end + 1;
    return true;
}

typedef struct {
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    uint64_t created_ms;
    uint32_t kind;
    uint16_t classification;
    uint16_t sci_compartment;
    uint32_t owner_id;
    qihse_ai_memory_scope_t scope;
} aimem_record_meta_t;

/* Parse the fixed-width header fields, leaving the body in the record. A
 * count needs the kind and nothing else, and must not strdup a 64 KB body per
 * record to find it. `text_out` receives the body when the caller wants it. */
static bool aimem_parse_meta(const char* value, aimem_record_meta_t* out,
                               const char** text_out) {
    /* v1: <uuid>|<created_ms>|<kind>|<classif>|<sci>|<text>
     * v2: v2|<uuid>|<created_ms>|<kind>|<classif>|<sci>|<owner>|<project>|<worktree>|<workstream>|<session>|<text> */
    if (!value || !out) return false;
    const char* p = value;
    bool v2 = strncmp(p, "v2|", 3u) == 0;
    if (v2) p += 3;
    const char* bar = strchr(p, '|');
    if (!bar || (size_t)(bar - p) != QIHSE_AIMEM_ID_LEN) return false;
    memcpy(out->id, p, QIHSE_AIMEM_ID_LEN);
    out->id[QIHSE_AIMEM_ID_LEN] = '\0';
    p = bar + 1;
    char* end = NULL;
    errno = 0;
    out->created_ms = strtoull(p, &end, 10);
    if (errno || !end || *end != '|') return false;
    p = end + 1;
    uint32_t field = 0;
    if (!aimem_parse_u32_field(&p, &field)) return false;
    out->kind = field;
    if (!aimem_parse_u32_field(&p, &field) || field > UINT16_MAX) return false;
    out->classification = (uint16_t)field;
    if (!aimem_parse_u32_field(&p, &field) || field > UINT16_MAX) return false;
    out->sci_compartment = (uint16_t)field;
    out->owner_id = 0u;
    memset(&out->scope, 0, sizeof out->scope);
    if (v2) {
        if (!aimem_parse_u32_field(&p, &out->owner_id) ||
            !aimem_parse_scope_field(&p, out->scope.project) ||
            !aimem_parse_scope_field(&p, out->scope.worktree) ||
            !aimem_parse_scope_field(&p, out->scope.workstream) ||
            !aimem_parse_scope_field(&p, out->scope.session) ||
            !out->scope.project[0]) return false;
    }
    if (text_out) *text_out = p;
    return true;
}

static bool aimem_parse_record_meta(const char* value, qihse_ai_memory_hit_t* out,
                                    aimem_record_meta_t* meta_out) {
    const char* text = NULL;
    aimem_record_meta_t meta;
    if (!aimem_parse_meta(value, &meta, &text)) return false;
    memcpy(out->id, meta.id, sizeof out->id);
    out->created_ms = meta.created_ms;
    out->kind = meta.kind;
    out->classification = meta.classification;
    out->sci_compartment = meta.sci_compartment;
    out->text = strdup(text);
    if (!out->text) return false;
    if (meta_out) *meta_out = meta;
    return true;
}

/* ── lazy index construction ────────────────────────────────────────────── */

typedef struct {
    qihse_fts_index_t* index;
    size_t added;
} aimem_rebuild_t;

static bool aimem_rebuild_cb(const char* key, const char* value, void* user_data) {
    aimem_rebuild_t* rb = (aimem_rebuild_t*)user_data;
    if (strncmp(key, AIMEM_PREFIX, AIMEM_PREFIX_LEN) != 0) return true;
    qihse_ai_memory_hit_t hit;
    memset(&hit, 0, sizeof hit);
    aimem_record_meta_t meta;
    if (!aimem_parse_record_meta(value, &hit, &meta)) return true;
    if (meta.scope.project[0]) { free(hit.text); return true; }
    qihse_uuid_t uuid;
    if (qihse_uuid_parse(hit.id, &uuid)) {
        qihse_fts_add_document_user(rb->index, aimem_doc_id(&uuid), hit.text,
                                    strlen(hit.text), hit.classification,
                                    hit.sci_compartment, QIHSE_KEYSTONE_CLASS_UNKNOWN,
                                    qihse_auth_get_user(0));
        rb->added++;
    }
    free(hit.text);
    return true;
}

/* Caller holds g_aimem_lock. Creates the index and, on first use, rebuilds it
 * from the durable KV namespace. *rebuilt_now reports that the rebuild ran
 * during this call, in which case the rebuild has already indexed every
 * existing record (including one just written) and the caller must not add it
 * again. */
static bool aimem_index_ensure(qihse_resp_server_t* server, bool* rebuilt_now) {
    if (rebuilt_now) *rebuilt_now = false;
    if (g_aimem_index) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    g_aimem_index = qihse_fts_create();
    if (!g_aimem_index) return false;
    aimem_rebuild_t rb = { g_aimem_index, 0 };
    qihse_kv_foreach_user(store, qihse_auth_get_user(0), aimem_rebuild_cb, &rb);
    if (rebuilt_now) *rebuilt_now = true;
    return true;
}

void qihse_ai_memory_reset(void) {
    pthread_mutex_lock(&g_aimem_lock);
    if (g_aimem_index) {
        qihse_fts_destroy(g_aimem_index);
        g_aimem_index = NULL;
    }
    aimem_vecs_clear();
    pthread_mutex_unlock(&g_aimem_lock);
}

/* ── embeddings (ai_fabric.md §5) ───────────────────────────────────────── */

/* Vectors live under their own prefix so the existing record layout is
 * untouched and a pre-embedding record still parses. A memory without a
 * vector is still recallable lexically; it simply does not participate in
 * semantic ranking. */
#define AIMEM_VEC_PREFIX "aimemv:"
#define AIMEM_VEC_PREFIX_LEN (sizeof(AIMEM_VEC_PREFIX) - 1u)
#define AIMEM_BUILTIN_DIM 256u
#define AIMEM_BUILTIN_NAME "builtin-lexical-256"
#define AIMEM_EMBEDDER_NAME_MAX 63u

/* Reciprocal-rank-fusion constant. RRF is used rather than a weighted sum of
 * raw scores because BM25 scores and cosine similarities are on different,
 * corpus-dependent scales: any fixed weighting between them is a tuning
 * accident that silently changes meaning as the corpus grows. RRF consumes
 * RANKS, so it is stable under both. */
#define AIMEM_RRF_K 60.0

static uint64_t aimem_hash64(const char* s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* The built-in embedder: a deterministic hashed bag of tokens, L2-normalised.
 * Similarity therefore reflects shared vocabulary, NOT meaning — it is a
 * lexical vector, and calling it semantic would be a lie. It exists so the
 * storage, ranking, fusion and clearance-filtering paths are complete and
 * testable with no model present. */
static bool aimem_builtin_embed(const char* text, float* out, size_t dim, void* ctx) {
    (void)ctx;
    if (!text || !out || dim == 0) return false;
    memset(out, 0, dim * sizeof(float));
    size_t i = 0, n = strlen(text);
    while (i < n) {
        while (i < n && !isalnum((unsigned char)text[i])) i++;
        size_t start = i;
        while (i < n && isalnum((unsigned char)text[i])) i++;
        if (i == start) continue;
        uint64_t h = aimem_hash64(text + start, i - start);
        float sign = (h & 0x8000000000000000ULL) ? -1.0f : 1.0f;
        out[h % dim] += sign;
    }
    double norm = 0.0;
    for (size_t k = 0; k < dim; k++) norm += (double)out[k] * (double)out[k];
    if (norm <= 0.0) return true; /* no tokens: a zero vector, not an error */
    float inv = (float)(1.0 / sqrt(norm));
    for (size_t k = 0; k < dim; k++) out[k] *= inv;
    return true;
}

typedef struct {
    uint64_t doc_id;
    size_t dim;
    float* vec;
    /* The memory's classification at write time, kept in the entry so vector
     * candidate selection can filter by visibility WITHOUT resolving the
     * record.  Without this the top-k fills with vectors the caller cannot
     * see and visible memories are crowded out — a recall-quality denial,
     * not a disclosure (resolve still re-checks before returning a hit). */
    uint16_t classification;
    uint16_t sci;
} aimem_vec_entry_t;

static aimem_vec_entry_t* g_aimem_vecs = NULL;
static size_t g_aimem_vec_count = 0;
static size_t g_aimem_vec_cap = 0;
static bool g_aimem_vecs_loaded = false;

static qihse_ai_memory_embedder_t g_aimem_embedder = {
    AIMEM_BUILTIN_NAME, AIMEM_BUILTIN_DIM, aimem_builtin_embed, NULL
};
static char g_aimem_embedder_name[AIMEM_EMBEDDER_NAME_MAX + 1u] = AIMEM_BUILTIN_NAME;

bool qihse_ai_memory_set_embedder(const qihse_ai_memory_embedder_t* provider) {
    if (!provider) {
        g_aimem_embedder.name = AIMEM_BUILTIN_NAME;
        g_aimem_embedder.dim = AIMEM_BUILTIN_DIM;
        g_aimem_embedder.embed = aimem_builtin_embed;
        g_aimem_embedder.ctx = NULL;
        snprintf(g_aimem_embedder_name, sizeof g_aimem_embedder_name, "%s",
                 AIMEM_BUILTIN_NAME);
        return true;
    }
    /* A provider that cannot embed is worse than none: recall would silently
     * degrade to lexical while reporting semantic. Refuse it. */
    if (!provider->embed || !provider->name || !*provider->name) return false;
    if (provider->dim == 0 || provider->dim > QIHSE_AIMEM_MAX_DIM) return false;
    if (strlen(provider->name) > AIMEM_EMBEDDER_NAME_MAX) return false;
    g_aimem_embedder = *provider;
    /* Copy the name: the caller's string need not outlive this call, and the
     * name is persisted with every vector. */
    snprintf(g_aimem_embedder_name, sizeof g_aimem_embedder_name, "%s",
             provider->name);
    g_aimem_embedder.name = g_aimem_embedder_name;
    return true;
}

size_t qihse_ai_memory_embedding_dim(void) { return g_aimem_embedder.dim; }
const char* qihse_ai_memory_embedder_name(void) { return g_aimem_embedder_name; }

bool qihse_ai_memory_embed_text(const char* text, float* out, size_t dim) {
    if (!text || !out || dim == 0u || dim != g_aimem_embedder.dim) return false;
    if (!g_aimem_embedder.embed) return false;
    return g_aimem_embedder.embed(text, out, dim, g_aimem_embedder.ctx);
}

static void aimem_vec_key(char* out, size_t cap, uint64_t doc_id) {
    snprintf(out, cap, AIMEM_VEC_PREFIX "%016llx", (unsigned long long)doc_id);
}

/* Serialise as <provider>|<dim>|<f0>,<f1>,... — text rather than binary so a
 * stored vector is inspectable and a corrupt one is detectable by parsing
 * rather than by a plausible-looking float read. */
static bool aimem_vec_store(qihse_kv_store_t* store, qihse_user_t* user,
                            uint64_t doc_id, const float* vec, size_t dim,
                            uint16_t classification, uint16_t sci) {
    size_t need = AIMEM_EMBEDDER_NAME_MAX + 32u + dim * 16u;
    char* buf = (char*)malloc(need);
    if (!buf) return false;
    int n = snprintf(buf, need, "%s|%zu|", g_aimem_embedder_name, dim);
    if (n <= 0) { free(buf); return false; }
    size_t off = (size_t)n;
    for (size_t i = 0; i < dim; i++) {
        int w = snprintf(buf + off, need - off, "%s%.6g", i ? "," : "", (double)vec[i]);
        if (w <= 0 || (size_t)w >= need - off) { free(buf); return false; }
        off += (size_t)w;
    }
    char key[64];
    aimem_vec_key(key, sizeof key, doc_id);
    bool ok = qihse_kv_set_user(store, key, buf, classification, sci, user);
    free(buf);
    return ok;
}

/* Caller holds g_aimem_lock. */
static void aimem_vecs_remove(uint64_t doc_id) {
    for (size_t i = 0; i < g_aimem_vec_count; i++) {
        if (g_aimem_vecs[i].doc_id == doc_id) {
            free(g_aimem_vecs[i].vec);
            g_aimem_vecs[i] = g_aimem_vecs[g_aimem_vec_count - 1u];
            g_aimem_vec_count--;
            return;
        }
    }
}

static void aimem_vecs_clear(void) {
    for (size_t i = 0; i < g_aimem_vec_count; i++) free(g_aimem_vecs[i].vec);
    free(g_aimem_vecs);
    g_aimem_vecs = NULL;
    g_aimem_vec_count = 0;
    g_aimem_vec_cap = 0;
    g_aimem_vecs_loaded = false;
}

static bool aimem_vecs_push(uint64_t doc_id, const float* vec, size_t dim,
                            uint16_t classification, uint16_t sci) {
    if (g_aimem_vec_count == g_aimem_vec_cap) {
        size_t cap = g_aimem_vec_cap ? g_aimem_vec_cap * 2u : 64u;
        aimem_vec_entry_t* grown = (aimem_vec_entry_t*)realloc(
            g_aimem_vecs, cap * sizeof(*grown));
        if (!grown) return false;
        g_aimem_vecs = grown;
        g_aimem_vec_cap = cap;
    }
    float* copy = (float*)malloc(dim * sizeof(float));
    if (!copy) return false;
    memcpy(copy, vec, dim * sizeof(float));
    g_aimem_vecs[g_aimem_vec_count].doc_id = doc_id;
    g_aimem_vecs[g_aimem_vec_count].dim = dim;
    g_aimem_vecs[g_aimem_vec_count].vec = copy;
    g_aimem_vecs[g_aimem_vec_count].classification = classification;
    g_aimem_vecs[g_aimem_vec_count].sci = sci;
    g_aimem_vec_count++;
    return true;
}

/* Parse a stored vector. Rejects a vector produced by a DIFFERENT provider:
 * embeddings from different models are not comparable, and comparing them
 * would yield confident nonsense rather than an error. */
static bool aimem_vec_parse(const char* value, const char* want_provider,
                            float* out, size_t cap, size_t* out_dim) {
    if (!value || !out || !out_dim) return false;
    const char* bar = strchr(value, '|');
    if (!bar) return false;
    size_t name_len = (size_t)(bar - value);
    if (name_len != strlen(want_provider) ||
        strncmp(value, want_provider, name_len) != 0) {
        return false;
    }
    const char* p = bar + 1;
    char* end = NULL;
    unsigned long dim = strtoul(p, &end, 10);
    if (!end || *end != '|' || dim == 0 || dim > cap) return false;
    p = end + 1;
    for (unsigned long i = 0; i < dim; i++) {
        if (i) {
            if (*p != ',') return false;
            p++;
        }
        double v = strtod(p, &end);
        if (end == p) return false; /* not a number: refuse rather than guess */
        out[i] = (float)v;
        p = end;
    }
    if (*p != '\0') return false; /* trailing junk means a malformed record */
    *out_dim = (size_t)dim;
    return true;
}

typedef struct {
    qihse_kv_store_t* store; /* for the doc-record lookup that carries cls/sci */
    size_t loaded;
} aimem_vec_rebuild_t;

static bool aimem_vec_rebuild_cb(const char* key, const char* value, void* user_data) {
    aimem_vec_rebuild_t* rb = (aimem_vec_rebuild_t*)user_data;
    if (strncmp(key, AIMEM_VEC_PREFIX, AIMEM_VEC_PREFIX_LEN) != 0) return true;
    uint64_t doc_id = strtoull(key + AIMEM_VEC_PREFIX_LEN, NULL, 16);
    float vec[QIHSE_AIMEM_MAX_DIM];
    size_t dim = 0;
    if (!aimem_vec_parse(value, g_aimem_embedder_name, vec, QIHSE_AIMEM_MAX_DIM, &dim)) {
        return true; /* unparsable or foreign-provider: skip, do not fail the scan */
    }
    /* The vector record does not serialise the memory's classification; the
     * DOC record does.  Read it for the in-memory entry so selection can
     * pre-filter by visibility.  A vector with no doc record is stale (the
     * memory was deleted but its vector was not) and is skipped: loading it
     * would consume candidate slots for a record resolve can never return. */
    char doc_key[64];
    aimem_key(doc_key, sizeof doc_key, doc_id);
    char* doc = qihse_kv_get_user(rb->store, doc_key, qihse_auth_get_user(0));
    if (!doc) return true;
    aimem_record_meta_t hdr;
    memset(&hdr, 0, sizeof hdr);
    bool have = aimem_parse_meta(doc, &hdr, NULL);
    free(doc);
    if (!have || hdr.scope.project[0]) return true;
    if (aimem_vecs_push(doc_id, vec, dim, hdr.classification, hdr.sci_compartment)) {
        rb->loaded++;
    }
    return true;
}

/* Caller holds g_aimem_lock. */
static bool aimem_vecs_ensure(qihse_resp_server_t* server) {
    if (g_aimem_vecs_loaded) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    aimem_vec_rebuild_t rb = { .store = store, .loaded = 0 };
    qihse_kv_foreach_user(store, qihse_auth_get_user(0), aimem_vec_rebuild_cb, &rb);
    g_aimem_vecs_loaded = true;
    return true;
}

typedef struct {
    uint64_t doc_id;
    double score;
} aimem_cand_t;

/* Caller holds g_aimem_lock. Scores every stored vector against the query and
 * returns the top `want` by cosine similarity. Vectors from another provider
 * were already excluded at load time.
 *
 * Visibility is checked DURING selection, not after: a vector whose memory
 * the caller cannot read must not occupy a top-k slot, or it crowds a
 * visible memory out of the result — a recall denial the old code produced
 * by filtering only at resolve time. This is still not the disclosure check:
 * aimem_resolve re-reads the record through the authorization-aware path
 * before anything is returned, so a stale or forged classification here can
 * only withhold a hit, never surface one. */
static size_t aimem_vec_search(const float* qvec, size_t qdim, size_t want,
                               const qihse_user_t* user, aimem_cand_t* out) {
    size_t written = 0;
    for (size_t i = 0; i < g_aimem_vec_count; i++) {
        if (g_aimem_vecs[i].dim != qdim) continue;
        if (!qihse_auth_can_access(user, g_aimem_vecs[i].classification,
                                   g_aimem_vecs[i].sci)) {
            continue;
        }
        const float* v = g_aimem_vecs[i].vec;
        double dot = 0.0, na = 0.0, nb = 0.0;
        for (size_t k = 0; k < qdim; k++) {
            dot += (double)qvec[k] * (double)v[k];
            na += (double)qvec[k] * (double)qvec[k];
            nb += (double)v[k] * (double)v[k];
        }
        if (na <= 0.0 || nb <= 0.0) continue;
        double sim = dot / (sqrt(na) * sqrt(nb));
        if (written < want) {
            out[written].doc_id = g_aimem_vecs[i].doc_id;
            out[written].score = sim;
            written++;
        } else {
            size_t worst = 0;
            for (size_t j = 1; j < want; j++) if (out[j].score < out[worst].score) worst = j;
            if (sim > out[worst].score) { out[worst].doc_id = g_aimem_vecs[i].doc_id; out[worst].score = sim; }
        }
    }
    /* Descending by score: the caller treats position as rank. */
    for (size_t i = 0; i + 1u < written; i++) {
        for (size_t j = i + 1u; j < written; j++) {
            if (out[j].score > out[i].score) {
                aimem_cand_t t = out[i];
                out[i] = out[j];
                out[j] = t;
            }
        }
    }
    return written;
}

/* ── write path ─────────────────────────────────────────────────────────── */

/* QH-00: the canonical ID of an idempotent memory is derived from a stable
 * tenant/principal/key seed, not from a random UUID generated *before* the
 * separate idempotency map is written. This makes a pre-map crash recoverable:
 * replay resolves the original KV document rather than allocating a second.
 *
 * Writes through RESP are serialized by the server kv_lock. Native callers
 * requiring exactly-once concurrent admission must provide equivalent
 * serialization; the KV layer still enforces classification and SCI. */
static qihse_ai_memory_write_result_t aimem_store_uuid(
        qihse_resp_server_t* server, qihse_user_t* user,
        const char* text, uint32_t kind, const qihse_ai_memory_scope_t* scope,
        const qihse_uuid_t* uuid,
        char out_id[QIHSE_AIMEM_ID_LEN + 1u], uint64_t* out_change_seq) {
    if (out_change_seq) *out_change_seq = 0u;
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        (!scope && qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM) ||
        !text || !*text || !uuid) return QIHSE_AIMEM_WRITE_FAILED;
    if (kind != QIHSE_AIMEM_EPISODIC && kind != QIHSE_AIMEM_SEMANTIC &&
        kind != QIHSE_AIMEM_EVENT)
        return QIHSE_AIMEM_WRITE_FAILED;
    if (scope && !aimem_scope_valid(scope)) return QIHSE_AIMEM_WRITE_FAILED;
    size_t text_len = strlen(text);
    if (!text_len || text_len > AIMEM_MAX_TEXT) return QIHSE_AIMEM_WRITE_FAILED;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return QIHSE_AIMEM_WRITE_FAILED;

    char id[QIHSE_AIMEM_ID_LEN + 1u];
    if (!qihse_uuid_format(uuid, id)) return QIHSE_AIMEM_WRITE_FAILED;
    uint64_t doc_id = aimem_doc_id(uuid);
    char key[64];
    if (scope ? !aimem_scoped_key(key, sizeof key, user, doc_id)
              : (aimem_key(key, sizeof key, doc_id), false))
        return QIHSE_AIMEM_WRITE_FAILED;

    /* Before any write, resolve an existing *authorized* record, compare the
     * complete UUID (only the top 64 bits appear in the KV key), then compare
     * immutable kind and exact body. Never overwrite an existing record with
     * a colliding or conflicting document ID. */
    char* existing = qihse_kv_get_user(store, key, user);
    if (existing) {
        qihse_ai_memory_hit_t hit;
        aimem_record_meta_t meta;
        memset(&hit, 0, sizeof hit);
        bool valid = aimem_parse_record_meta(existing, &hit, &meta);
        bool equal = valid && strcmp(hit.id, id) == 0 &&
                     hit.kind == kind && hit.text &&
                     strcmp(hit.text, text) == 0 &&
                     meta.owner_id == (scope ? qihse_user_get_id(user) : 0u) &&
                     ((!scope && !meta.scope.project[0]) ||
                      (scope && aimem_scope_matches(&meta.scope, scope) &&
                       strcmp(meta.scope.worktree, scope->worktree) == 0 &&
                       strcmp(meta.scope.workstream, scope->workstream) == 0 &&
                       strcmp(meta.scope.session, scope->session) == 0));
        free(hit.text);
        free(existing);
        if (!equal) return QIHSE_AIMEM_WRITE_CONFLICT;
        bool tombstone = false;
        if (out_change_seq && !qihse_kv_change_seq_user(store, key, user,
                out_change_seq, &tombstone)) return QIHSE_AIMEM_WRITE_FAILED;
        if (out_id) memcpy(out_id, id, sizeof id);
        return QIHSE_AIMEM_WRITE_REPLAY;
    }

    uint16_t classification = qihse_user_get_classification(user);
    uint16_t sci = qihse_user_get_sci(user);
    size_t overhead = scope ? 512u : 128u;
    char* value = malloc(text_len + overhead);
    if (!value) return QIHSE_AIMEM_WRITE_FAILED;
    int n;
    if (scope) {
        n = snprintf(value, text_len + overhead,
                     "v2|%s|%llu|%u|%u|%u|%u|%s|%s|%s|%s|%s", id,
                     (unsigned long long)aimem_now_ms(), (unsigned)kind,
                     (unsigned)classification, (unsigned)sci,
                     (unsigned)qihse_user_get_id(user), scope->project,
                     scope->worktree, scope->workstream, scope->session, text);
    } else {
        n = snprintf(value, text_len + overhead, "%s|%llu|%u|%u|%u|%s", id,
                     (unsigned long long)aimem_now_ms(), (unsigned)kind,
                     (unsigned)classification, (unsigned)sci, text);
    }
    if (n <= 0 || (size_t)n >= text_len + overhead) {
        free(value);
        return QIHSE_AIMEM_WRITE_FAILED;
    }

    /* A hidden colliding record is deliberately indistinguishable from a
     * storage refusal: qihse_kv_set_user denies overwriting inaccessible
     * rows even though the authorized get above returns NULL. */
    bool ok = qihse_kv_set_user_with_seq(store, key, value, classification,
                                         sci, user, out_change_seq);
    free(value);
    if (!ok) return QIHSE_AIMEM_WRITE_FAILED;

    /* Index and vector states are rebuildable projections, not canonical
     * evidence. The primary document is authoritative for replay. */
    if (!scope) {
        float vec[QIHSE_AIMEM_MAX_DIM];
        size_t dim = g_aimem_embedder.dim;
        if (dim && dim <= QIHSE_AIMEM_MAX_DIM &&
            g_aimem_embedder.embed(text, vec, dim, g_aimem_embedder.ctx)) {
            if (!aimem_vec_store(store, user, doc_id, vec, dim,
                                 classification, sci)) {
                fprintf(stderr, "qihse-ai-memory: record stored without vector\n");
            } else {
                pthread_mutex_lock(&g_aimem_lock);
                if (g_aimem_vecs_loaded) {
                    (void)aimem_vecs_push(doc_id, vec, dim, classification, sci);
                }
                pthread_mutex_unlock(&g_aimem_lock);
            }
        }
    }

    if (!scope) {
        pthread_mutex_lock(&g_aimem_lock);
        bool rebuilt_now = false;
        bool have_index = aimem_index_ensure(server, &rebuilt_now);
        bool indexed = have_index &&
                       (rebuilt_now ||
                        qihse_fts_add_document_user(g_aimem_index, doc_id, text,
                                                    text_len, classification, sci,
                                                    QIHSE_KEYSTONE_CLASS_UNKNOWN, user));
        pthread_mutex_unlock(&g_aimem_lock);
        if (!indexed) fprintf(stderr, "qihse-ai-memory: record stored without search index\n");
    }
    if (out_id) memcpy(out_id, id, sizeof id);
    return QIHSE_AIMEM_WRITE_NEW;
}

bool qihse_ai_memory_store(qihse_resp_server_t* server, qihse_user_t* user,
                           const char* text, uint32_t kind,
                           char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    qihse_uuid_t uuid;
    if (!qihse_uuid_generate(&uuid)) return false;
    return aimem_store_uuid(server, user, text, kind, NULL, &uuid, out_id, NULL) ==
           QIHSE_AIMEM_WRITE_NEW;
}

qihse_ai_memory_write_result_t qihse_ai_memory_store_idempotent(
        qihse_resp_server_t* server, qihse_user_t* user, const char* text,
        uint32_t kind, const char* idempotency_key,
        char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    return qihse_ai_memory_store_idempotent_with_seq(server, user, text, kind,
        idempotency_key, out_id, NULL);
}

qihse_ai_memory_write_result_t qihse_ai_memory_store_idempotent_with_seq(
        qihse_resp_server_t* server, qihse_user_t* user, const char* text,
        uint32_t kind, const char* idempotency_key,
        char out_id[QIHSE_AIMEM_ID_LEN + 1u], uint64_t* out_change_seq) {
    if (out_change_seq) *out_change_seq = 0u;
    if (!user || !qihse_auth_user_is_active(user) ||
        qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM || !idempotency_key)
        return QIHSE_AIMEM_WRITE_FAILED;
    size_t len = strnlen(idempotency_key, QIHSE_AIMEM_IDEM_MAX_LEN + 1u);
    if (!len || len > QIHSE_AIMEM_IDEM_MAX_LEN) return QIHSE_AIMEM_WRITE_FAILED;
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)idempotency_key[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == ':'))
            return QIHSE_AIMEM_WRITE_FAILED;
    }
    char seed[QIHSE_AIMEM_IDEM_MAX_LEN + 80u];
    int n = snprintf(seed, sizeof seed, "QIHSE:AIMEM:v2:%u:%u:%s",
                     (unsigned)qihse_user_get_tenant_id(user),
                     (unsigned)qihse_user_get_id(user), idempotency_key);
    if (n <= 0 || (size_t)n >= sizeof seed) return QIHSE_AIMEM_WRITE_FAILED;
    qihse_uuid_t uuid;
    if (!qihse_uuid_from_seed(seed, (size_t)n, &uuid))
        return QIHSE_AIMEM_WRITE_FAILED;
    return aimem_store_uuid(server, user, text, kind, NULL, &uuid, out_id,
                            out_change_seq);
}

bool qihse_ai_memory_store_scoped(qihse_resp_server_t* server,
                                  qihse_user_t* user, const char* text,
                                  uint32_t kind,
                                  const qihse_ai_memory_scope_t* scope,
                                  char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    if (!aimem_scope_valid(scope) ||
        (kind != QIHSE_AIMEM_EPISODIC && kind != QIHSE_AIMEM_SEMANTIC)) return false;
    qihse_uuid_t uuid;
    if (!qihse_uuid_generate(&uuid)) return false;
    return aimem_store_uuid(server, user, text, kind, scope, &uuid, out_id, NULL) ==
           QIHSE_AIMEM_WRITE_NEW;
}

qihse_ai_memory_write_result_t qihse_ai_memory_store_scoped_idempotent(
        qihse_resp_server_t* server, qihse_user_t* user, const char* text,
        uint32_t kind, const qihse_ai_memory_scope_t* scope,
        const char* idempotency_key,
        char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    if (!aimem_scope_valid(scope) ||
        (kind != QIHSE_AIMEM_EPISODIC && kind != QIHSE_AIMEM_SEMANTIC) ||
        !user || !qihse_auth_user_is_active(user) ||
        !idempotency_key) return QIHSE_AIMEM_WRITE_FAILED;
    size_t len = strnlen(idempotency_key, QIHSE_AIMEM_IDEM_MAX_LEN + 1u);
    if (!len || len > QIHSE_AIMEM_IDEM_MAX_LEN) return QIHSE_AIMEM_WRITE_FAILED;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)idempotency_key[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == ':'))
            return QIHSE_AIMEM_WRITE_FAILED;
    }
    char seed[QIHSE_AIMEM_IDEM_MAX_LEN + 512u];
    int n = snprintf(seed, sizeof seed, "QIHSE:AIMEM:scoped:v1:%u:%u:%s:%s:%s:%s:%s",
                     (unsigned)qihse_user_get_tenant_id(user),
                     (unsigned)qihse_user_get_id(user), scope->project,
                     scope->worktree, scope->workstream, scope->session,
                     idempotency_key);
    if (n <= 0 || (size_t)n >= sizeof seed) return QIHSE_AIMEM_WRITE_FAILED;
    qihse_uuid_t uuid;
    if (!qihse_uuid_from_seed(seed, (size_t)n, &uuid))
        return QIHSE_AIMEM_WRITE_FAILED;
    return aimem_store_uuid(server, user, text, kind, scope, &uuid, out_id, NULL);
}

bool qihse_ai_memory_change_seq(qihse_resp_server_t* server,
        qihse_user_t* user, const char* id, uint64_t* out_change_seq,
        bool* out_tombstone) {
    if (out_change_seq) *out_change_seq = 0u;
    if (out_tombstone) *out_tombstone = false;
    qihse_uuid_t uuid;
    if (!server || !user || !id || !out_change_seq || !out_tombstone ||
        !qihse_uuid_parse(id, &uuid)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    char key[64];
    aimem_key(key, sizeof key, aimem_doc_id(&uuid));
    return qihse_kv_change_seq_user(store, key, user, out_change_seq,
                                    out_tombstone);
}

static bool aimem_migrated_record_matches(const char* raw, const char* id,
        uint32_t owner_id, const qihse_ai_memory_scope_t* scope,
        const aimem_record_meta_t* source, const char* source_text) {
    aimem_record_meta_t meta;
    const char* text = NULL;
    if (!raw || !id || !scope || !aimem_parse_meta(raw, &meta, &text) ||
        strcmp(meta.id, id) != 0 || meta.owner_id != owner_id ||
        strcmp(meta.scope.project, scope->project) != 0 ||
        strcmp(meta.scope.worktree, scope->worktree) != 0 ||
        strcmp(meta.scope.workstream, scope->workstream) != 0 ||
        strcmp(meta.scope.session, scope->session) != 0) return false;
    return !source || (meta.created_ms == source->created_ms &&
        meta.kind == source->kind && meta.classification == source->classification &&
        meta.sci_compartment == source->sci_compartment && source_text &&
        strcmp(text, source_text) == 0);
}

qihse_ai_memory_write_result_t qihse_ai_memory_migrate_legacy(
        qihse_resp_server_t* server, qihse_user_t* operator_user,
        const char* id, const qihse_ai_memory_scope_t* destination) {
    qihse_uuid_t uuid;
    if (!server || !operator_user || !qihse_auth_user_is_active(operator_user) ||
        qihse_user_get_role(operator_user) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(operator_user) != QIHSE_TENANT_SYSTEM ||
        !id || !qihse_uuid_parse(id, &uuid) || !aimem_scope_valid(destination))
        return QIHSE_AIMEM_WRITE_FAILED;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return QIHSE_AIMEM_WRITE_FAILED;
    uint64_t doc_id = aimem_doc_id(&uuid);
    char source_key[64], destination_key[64], vector_key[64];
    aimem_key(source_key, sizeof source_key, doc_id);
    aimem_vec_key(vector_key, sizeof vector_key, doc_id);
    if (!aimem_scoped_key(destination_key, sizeof destination_key,
                          operator_user, doc_id)) return QIHSE_AIMEM_WRITE_FAILED;

    pthread_mutex_lock(&g_aimem_migration_lock);
    char* source_raw = qihse_kv_get_user(store, source_key, operator_user);
    char* destination_raw = qihse_kv_get_user(store, destination_key, operator_user);
    uint32_t owner_id = qihse_user_get_id(operator_user);
    if (!source_raw) {
        bool replay = aimem_migrated_record_matches(destination_raw, id, owner_id,
                                                     destination, NULL, NULL) &&
                      qihse_kv_sync_store(store);
        free(destination_raw);
        pthread_mutex_unlock(&g_aimem_migration_lock);
        return replay ? QIHSE_AIMEM_WRITE_REPLAY : QIHSE_AIMEM_WRITE_FAILED;
    }

    aimem_record_meta_t source;
    const char* source_text = NULL;
    qihse_kv_record_meta_t stored_meta;
    bool source_ok = aimem_parse_meta(source_raw, &source, &source_text) &&
        !source.scope.project[0] && strcmp(source.id, id) == 0 &&
        qihse_kv_meta_user(store, source_key, operator_user, &stored_meta) &&
        stored_meta.classification == source.classification &&
        stored_meta.sci_compartment == source.sci_compartment;
    if (!source_ok) {
        free(source_raw); free(destination_raw);
        pthread_mutex_unlock(&g_aimem_migration_lock);
        return QIHSE_AIMEM_WRITE_FAILED;
    }

    bool existed = destination_raw != NULL;
    if (existed && !aimem_migrated_record_matches(destination_raw, id, owner_id,
                                                   destination, &source, source_text)) {
        free(source_raw); free(destination_raw);
        pthread_mutex_unlock(&g_aimem_migration_lock);
        return QIHSE_AIMEM_WRITE_CONFLICT;
    }
    if (!existed) {
        size_t cap = strlen(source_text) + 512u;
        char* migrated = malloc(cap);
        int n = migrated ? snprintf(migrated, cap,
            "v2|%s|%llu|%u|%u|%u|%u|%s|%s|%s|%s|%s", id,
            (unsigned long long)source.created_ms, (unsigned)source.kind,
            (unsigned)stored_meta.classification, (unsigned)stored_meta.sci_compartment,
            (unsigned)owner_id, destination->project, destination->worktree,
            destination->workstream, destination->session, source_text) : -1;
        bool wrote = n > 0 && (size_t)n < cap && qihse_kv_set_user(store,
            destination_key, migrated, stored_meta.classification,
            stored_meta.sci_compartment, operator_user);
        free(migrated);
        if (!wrote) {
            free(source_raw); free(destination_raw);
            pthread_mutex_unlock(&g_aimem_migration_lock);
            return QIHSE_AIMEM_WRITE_FAILED;
        }
    }
    free(destination_raw);
    if (!qihse_kv_sync_store(store) ||
        !qihse_kv_del_user(store, source_key, operator_user)) {
        free(source_raw);
        pthread_mutex_unlock(&g_aimem_migration_lock);
        return QIHSE_AIMEM_WRITE_FAILED;
    }
    (void)qihse_kv_del_user(store, vector_key, operator_user);
    bool durable = qihse_kv_sync_store(store);
    free(source_raw);
    if (durable) {
        pthread_mutex_lock(&g_aimem_lock);
        aimem_vecs_remove(doc_id);
        pthread_mutex_unlock(&g_aimem_lock);
    }
    pthread_mutex_unlock(&g_aimem_migration_lock);
    if (!durable) return QIHSE_AIMEM_WRITE_FAILED;
    return existed ? QIHSE_AIMEM_WRITE_REPLAY : QIHSE_AIMEM_WRITE_NEW;
}

static bool aimem_event_token(const char* s, size_t max_len) {
    if (!s || !*s) return false;
    size_t n = strnlen(s, max_len + 1u);
    if (!n || n > max_len) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return false;
    }
    return true;
}

static bool aimem_event_kind_valid(const char* kind) {
    static const char* const registered[] = {
        "session_start", "session_end", "task_started", "task_completed",
        "observation", "decision", "blocker", "checkpoint"
    };
    if (!kind) return false;
    for (size_t i = 0; i < sizeof registered / sizeof registered[0]; i++)
        if (strcmp(kind, registered[i]) == 0) return true;
    return false;
}

static bool aimem_event_u64_valid(const char* value) {
    if (!value || !*value || strlen(value) > 20u) return false;
    for (const char* p = value; *p; p++)
        if (*p < '0' || *p > '9') return false;
    errno = 0;
    (void)strtoull(value, NULL, 10);
    return errno == 0;
}

qihse_ai_memory_write_result_t qihse_ai_memory_event_append(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const char* producer_namespace,
        const char* event_id, const char* event_kind, uint64_t source_time_ms,
        const char* summary, char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    return qihse_ai_memory_event_append_evidence(server, user, scope,
        producer_namespace, event_id, event_kind, source_time_ms, summary,
        NULL, out_id);
}

qihse_ai_memory_write_result_t qihse_ai_memory_event_append_evidence(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const char* producer_namespace,
        const char* event_id, const char* event_kind, uint64_t source_time_ms,
        const char* summary, const char* source_evidence_id,
        char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !aimem_event_token(producer_namespace, 63u) ||
        !aimem_event_token(event_id, QIHSE_AIMEM_IDEM_MAX_LEN) ||
        !aimem_event_kind_valid(event_kind) || !summary || !*summary ||
        strnlen(summary, QIHSE_AIMEM_EVENT_MAX_SUMMARY + 1u) > QIHSE_AIMEM_EVENT_MAX_SUMMARY)
        return QIHSE_AIMEM_WRITE_FAILED;
    if (source_evidence_id) {
        qihse_uuid_t evidence_uuid;
        qihse_ai_memory_hit_t evidence;
        memset(&evidence, 0, sizeof evidence);
        if (!qihse_uuid_parse(source_evidence_id, &evidence_uuid) ||
            !qihse_ai_memory_get_scoped(server, user, source_evidence_id,
                                         scope, &evidence))
            return QIHSE_AIMEM_WRITE_FAILED;
        bool visible = qihse_auth_can_access(user, evidence.classification,
                                              evidence.sci_compartment);
        free(evidence.text);
        if (!visible) return QIHSE_AIMEM_WRITE_FAILED;
    }
    for (const unsigned char* p = (const unsigned char*)summary; *p; p++)
        if (*p < 0x20u || *p == 0x7fu) return QIHSE_AIMEM_WRITE_FAILED;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(summary, strlen(summary), digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len != 32u) return QIHSE_AIMEM_WRITE_FAILED;
    char digest_hex[65];
    for (size_t i = 0; i < 32u; i++)
        snprintf(digest_hex + i * 2u, 3u, "%02x", digest[i]);
    char* envelope = malloc(QIHSE_AIMEM_EVENT_MAX_SUMMARY + 640u);
    if (!envelope) return QIHSE_AIMEM_WRITE_FAILED;
    int n = source_evidence_id
        ? snprintf(envelope, QIHSE_AIMEM_EVENT_MAX_SUMMARY + 640u,
            "QHEV2|%s|%s|%s|%llu|%llu|observed|%s|%s|%s",
            producer_namespace, event_id, event_kind,
            (unsigned long long)source_time_ms,
            (unsigned long long)aimem_now_ms(), source_evidence_id,
            digest_hex, summary)
        : snprintf(envelope, QIHSE_AIMEM_EVENT_MAX_SUMMARY + 640u,
            "QHEV1|%s|%s|%s|%llu|%llu|observed|%s|%s", producer_namespace,
            event_id, event_kind, (unsigned long long)source_time_ms,
            (unsigned long long)aimem_now_ms(), digest_hex, summary);
    if (n <= 0 || (size_t)n >= QIHSE_AIMEM_EVENT_MAX_SUMMARY + 640u) {
        free(envelope);
        return QIHSE_AIMEM_WRITE_FAILED;
    }
    char idem[QIHSE_AIMEM_IDEM_MAX_LEN + 80u];
    n = snprintf(idem, sizeof idem, "event:%s:%s", producer_namespace, event_id);
    if (n <= 0 || (size_t)n >= sizeof idem) {
        free(envelope);
        return QIHSE_AIMEM_WRITE_FAILED;
    }
    char seed[QIHSE_AIMEM_IDEM_MAX_LEN + 512u];
    n = snprintf(seed, sizeof seed, "QIHSE:AIMEM:scoped:v1:%u:%u:%s:%s:%s:%s:%s",
        (unsigned)qihse_user_get_tenant_id(user), (unsigned)qihse_user_get_id(user),
        scope->project, scope->worktree, scope->workstream, scope->session, idem);
    qihse_uuid_t uuid;
    qihse_ai_memory_write_result_t result = QIHSE_AIMEM_WRITE_FAILED;
    pthread_mutex_lock(&g_aimem_event_lock);
    if (n > 0 && (size_t)n < sizeof seed &&
        qihse_uuid_from_seed(seed, (size_t)n, &uuid)) {
        char canonical[QIHSE_AIMEM_ID_LEN + 1u];
        if (qihse_uuid_format(&uuid, canonical)) {
            qihse_ai_memory_hit_t prior;
            memset(&prior, 0, sizeof prior);
            if (qihse_ai_memory_get_scoped(server, user, canonical, scope, &prior)) {
                char invariant_prefix[384];
                int pn = snprintf(invariant_prefix, sizeof invariant_prefix,
                    "QHEV%u|%s|%s|%s|%llu|", source_evidence_id ? 2u : 1u,
                    producer_namespace, event_id, event_kind,
                    (unsigned long long)source_time_ms);
                char* receive_end = pn > 0 && (size_t)pn < sizeof invariant_prefix &&
                    strncmp(prior.text, invariant_prefix, (size_t)pn) == 0
                    ? strchr(prior.text + pn, '|') : NULL;
                size_t suffix_len = strlen("observed|") +
                    (source_evidence_id ? strlen(source_evidence_id) + 1u : 0u) +
                    strlen(digest_hex) + 1u + strlen(summary);
                char* suffix = malloc(suffix_len + 1u);
                bool same = false;
                if (suffix) {
                    if (source_evidence_id)
                        snprintf(suffix, suffix_len + 1u, "observed|%s|%s|%s",
                                 source_evidence_id, digest_hex, summary);
                    else
                        snprintf(suffix, suffix_len + 1u, "observed|%s|%s",
                                 digest_hex, summary);
                    same = prior.kind == QIHSE_AIMEM_EVENT && receive_end &&
                           strcmp(receive_end + 1u, suffix) == 0;
                    free(suffix);
                }
                if (same) {
                    if (out_id) memcpy(out_id, canonical, sizeof canonical);
                    result = QIHSE_AIMEM_WRITE_REPLAY;
                } else {
                    result = QIHSE_AIMEM_WRITE_CONFLICT;
                }
                free(prior.text);
            } else {
                result = aimem_store_uuid(server, user, envelope,
                    QIHSE_AIMEM_EVENT, scope, &uuid, out_id, NULL);
            }
        }
    }
    pthread_mutex_unlock(&g_aimem_event_lock);
    free(envelope);
    return result;
}

static bool aimem_event_envelope_valid(const char* text,
        char out_producer[64], char out_event_id[QIHSE_AIMEM_IDEM_MAX_LEN + 1u]) {
    if (text && (strncmp(text, "QHEV1|", 6u) == 0 ||
                 strncmp(text, "QHEV2|", 6u) == 0)) {
        bool has_evidence = strncmp(text, "QHEV2|", 6u) == 0;
        char producer[64], event_id[QIHSE_AIMEM_IDEM_MAX_LEN + 1u];
        char kind[32], source[24], received[24], status[16], digest_hex[65];
        char evidence_id[QIHSE_AIMEM_ID_LEN + 1u];
        int offset = 0;
        int fields = has_evidence ? sscanf(text,
            "QHEV2|%63[^|]|%128[^|]|%31[^|]|%23[^|]|%23[^|]|%15[^|]|%36[^|]|%64[^|]|%n",
            producer, event_id, kind, source, received, status, evidence_id, digest_hex, &offset)
            : sscanf(text,
            "QHEV1|%63[^|]|%128[^|]|%31[^|]|%23[^|]|%23[^|]|%15[^|]|%64[^|]|%n",
            producer, event_id, kind, source, received, status, digest_hex, &offset);
        bool valid = fields == (has_evidence ? 8 : 7) && offset > 0 && aimem_event_token(producer, 63u) &&
            aimem_event_token(event_id, QIHSE_AIMEM_IDEM_MAX_LEN) &&
            aimem_event_kind_valid(kind) && strcmp(status, "observed") == 0 &&
            strlen(digest_hex) == 64u;
        if (has_evidence) {
            qihse_uuid_t evidence_uuid;
            valid = valid && qihse_uuid_parse(evidence_id, &evidence_uuid);
        }
        valid = valid && aimem_event_u64_valid(source) && aimem_event_u64_valid(received);
        for (size_t i = 0; valid && i < 64u; i++)
            if (!((digest_hex[i] >= '0' && digest_hex[i] <= '9') ||
                  (digest_hex[i] >= 'a' && digest_hex[i] <= 'f'))) valid = false;
        const char* summary = text + offset;
        if (!*summary || strlen(summary) > QIHSE_AIMEM_EVENT_MAX_SUMMARY) valid = false;
        for (const unsigned char* p = (const unsigned char*)summary; valid && *p; p++)
            if (*p < 0x20u || *p == 0x7fu) valid = false;
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        char actual_hex[65];
        if (valid) valid = EVP_Digest(summary, strlen(summary), digest,
            &digest_len, EVP_sha256(), NULL) == 1 && digest_len == 32u;
        if (valid) {
            for (size_t i = 0; i < 32u; i++)
                snprintf(actual_hex + i * 2u, 3u, "%02x", digest[i]);
            valid = strcmp(actual_hex, digest_hex) == 0;
        }
        if (valid) {
            if (out_producer) snprintf(out_producer, 64u, "%s", producer);
            if (out_event_id)
                snprintf(out_event_id, QIHSE_AIMEM_IDEM_MAX_LEN + 1u, "%s", event_id);
            return true;
        }
    }
    return false;
}

bool qihse_ai_memory_event_get(qihse_resp_server_t* server, qihse_user_t* user,
        const char* id, const qihse_ai_memory_scope_t* scope,
        qihse_ai_memory_hit_t* out) {
    if (!qihse_ai_memory_get_scoped(server, user, id, scope, out)) return false;
    if (out->kind == QIHSE_AIMEM_EVENT &&
        aimem_event_envelope_valid(out->text, NULL, NULL)) return true;
    free(out->text);
    memset(out, 0, sizeof(*out));
    return false;
}

/* ── read path ──────────────────────────────────────────────────────────── */

/* Bounds on the candidate window a recall may consider and on the fused list
 * HYBRID builds from it. Both are fixed-size arrays on the stack: recall
 * never grows a result set beyond what the caller's buffer holds. */
#define AIMEM_CAND_MAX 256u
#define AIMEM_FUSED_MAX (2u * AIMEM_CAND_MAX)

/* Kind filter helpers. ANY is the only value wider than one kind; every other
 * value must name a kind this module can actually have stored, or the read is
 * refused rather than defaulted. */
static bool aimem_kind_valid(uint32_t kind) {
    return kind == QIHSE_AIMEM_KIND_ANY || kind == QIHSE_AIMEM_EPISODIC ||
           kind == QIHSE_AIMEM_SEMANTIC || kind == QIHSE_AIMEM_EVENT;
}

static bool aimem_kind_ok(uint32_t filter, uint32_t kind) {
    return filter == QIHSE_AIMEM_KIND_ANY || filter == kind;
}

static bool aimem_fetch(qihse_resp_server_t* server, qihse_user_t* user,
                        const qihse_uuid_t* uuid, qihse_ai_memory_hit_t* out) {
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    char key[64];
    aimem_key(key, sizeof key, aimem_doc_id(uuid));
    char* value = qihse_kv_get_user(store, key, user);
    if (!value) return false;
    aimem_record_meta_t meta;
    bool ok = aimem_parse_record_meta(value, out, &meta);
    free(value);
    /* KV keys encode only the UUID's first 64 bits. A different UUID with
     * that prefix must never allow direct GET or FORGET of this document. */
    char canonical[QIHSE_AIMEM_ID_LEN + 1u];
    ok = ok && qihse_uuid_format(uuid, canonical) &&
         strcmp(out->id, canonical) == 0 && !meta.scope.project[0];
    if (!ok) {
        free(out->text);
        memset(out, 0, sizeof(*out));
    }
    return ok;
}

bool qihse_ai_memory_get(qihse_resp_server_t* server, qihse_user_t* user,
                         const char* id, qihse_ai_memory_hit_t* out) {
    if (!server || !user || qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM ||
        !id || !out) return false;
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(id, &uuid)) return false;
    memset(out, 0, sizeof(*out));
    return aimem_fetch(server, user, &uuid, out);
}

/* Resolve a doc_id to a visible memory. Returns false when the record is gone
 * or the principal cannot see it — the SAME filter every mode goes through, so
 * no ranking mode can surface, score, or count an invisible record. */
static bool aimem_resolve(qihse_resp_server_t* server, qihse_user_t* user,
                          uint64_t doc_id, qihse_ai_memory_hit_t* out) {
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    char key[64];
    aimem_key(key, sizeof key, doc_id);
    char* value = qihse_kv_get_user(store, key, user);
    if (!value) return false;
    aimem_record_meta_t meta;
    bool ok = aimem_parse_record_meta(value, out, &meta);
    free(value);
    if (ok && meta.scope.project[0]) {
        free(out->text);
        memset(out, 0, sizeof(*out));
        return false;
    }
    return ok;
}

/* Resolve a candidate and then apply the kind filter. The order is the whole
 * point: authorization runs FIRST, through the same authorization-aware read
 * every other path uses, and the kind filter can only discard a hit that was
 * already visible. A rejected candidate releases its text, so a filtered-out
 * record never leaves a payload in the caller's buffer. */
static bool aimem_accept(qihse_resp_server_t* server, qihse_user_t* user,
                         uint64_t doc_id, uint32_t kind_filter,
                         qihse_ai_memory_hit_t* out) {
    memset(out, 0, sizeof(*out));
    if (!aimem_resolve(server, user, doc_id, out)) return false;
    if (!aimem_kind_ok(kind_filter, out->kind)) {
        free(out->text);
        out->text = NULL;
        return false;
    }
    return true;
}

/* Shared body of every recall entry point, so all of them go through the same
 * candidate gathering, the same authorization-aware resolve, and the same
 * kind filter. Takes g_aimem_lock only around the shared index/vector state. */
static size_t aimem_recall(qihse_resp_server_t* server, qihse_user_t* user,
                           const char* query, size_t limit,
                           qihse_ai_memory_mode_t mode, uint32_t kind,
                           qihse_ai_memory_hit_t* out, size_t out_cap) {
    if (!server || !user || qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM ||
        !query || !*query || !out || out_cap == 0) return 0;
    if (mode != QIHSE_AIMEM_MODE_BM25 && mode != QIHSE_AIMEM_MODE_SEMANTIC &&
        mode != QIHSE_AIMEM_MODE_HYBRID) {
        return 0;
    }
    /* An unrecognised kind is refused, not widened to ANY: a filter parameter
     * that silently means "everything" is the defect it must not introduce. */
    if (!aimem_kind_valid(kind)) return 0;
    size_t want = limit ? limit : 10u;
    if (want > out_cap) want = out_cap;
    if (want > AIMEM_CAND_MAX) want = AIMEM_CAND_MAX;
    /* A kind filter discards candidates AFTER authorization, so gather the
     * whole bounded candidate window rather than only `want` of them —
     * otherwise a filtered recall would return fewer hits than the caller can
     * see. The window is bounded by AIMEM_CAND_MAX either way and every
     * candidate is authorization-filtered, so asking for more candidates
     * cannot disclose more. */
    size_t cand_want = want;
    if (kind != QIHSE_AIMEM_KIND_ANY && cand_want < AIMEM_CAND_MAX) {
        cand_want = AIMEM_CAND_MAX;
    }

    aimem_cand_t lexical[AIMEM_CAND_MAX];
    aimem_cand_t vector[AIMEM_CAND_MAX];
    size_t n_lexical = 0, n_vector = 0;

    pthread_mutex_lock(&g_aimem_lock);
    if (mode == QIHSE_AIMEM_MODE_BM25 || mode == QIHSE_AIMEM_MODE_HYBRID) {
        if (aimem_index_ensure(server, NULL)) {
            qihse_fts_result_t results[AIMEM_CAND_MAX];
            int found = qihse_fts_search_user(g_aimem_index, query, user, results,
                                              (int)cand_want);
            for (int i = 0; i < found && n_lexical < AIMEM_CAND_MAX; i++) {
                lexical[n_lexical].doc_id = results[i].doc_id;
                lexical[n_lexical].score = results[i].bm25_score;
                n_lexical++;
            }
        }
    }
    if (mode == QIHSE_AIMEM_MODE_SEMANTIC || mode == QIHSE_AIMEM_MODE_HYBRID) {
        float qvec[QIHSE_AIMEM_MAX_DIM];
        size_t qdim = g_aimem_embedder.dim;
        if (qdim && qdim <= QIHSE_AIMEM_MAX_DIM &&
            g_aimem_embedder.embed(query, qvec, qdim, g_aimem_embedder.ctx) &&
            aimem_vecs_ensure(server)) {
            n_vector = aimem_vec_search(qvec, qdim, cand_want, user, vector);
        }
    }
    pthread_mutex_unlock(&g_aimem_lock);

    /* Fuse by rank, not by score. BM25 and cosine are on different
     * corpus-dependent scales, so any weighted sum between them is a tuning
     * accident; RRF consumes positions and is stable under both. */
    size_t written = 0;
    if (mode == QIHSE_AIMEM_MODE_HYBRID) {
        struct { uint64_t doc_id; double rrf; } fused[AIMEM_FUSED_MAX];
        size_t n_fused = 0;
        for (size_t i = 0; i < n_lexical && n_fused < AIMEM_FUSED_MAX; i++) {
            fused[n_fused].doc_id = lexical[i].doc_id;
            fused[n_fused].rrf = 1.0 / (AIMEM_RRF_K + (double)(i + 1u));
            n_fused++;
        }
        for (size_t i = 0; i < n_vector && n_fused < AIMEM_FUSED_MAX; i++) {
            size_t j = 0;
            for (; j < n_fused; j++) {
                if (fused[j].doc_id == vector[i].doc_id) {
                    fused[j].rrf += 1.0 / (AIMEM_RRF_K + (double)(i + 1u));
                    break;
                }
            }
            if (j == n_fused) {
                fused[n_fused].doc_id = vector[i].doc_id;
                fused[n_fused].rrf = 1.0 / (AIMEM_RRF_K + (double)(i + 1u));
                n_fused++;
            }
        }
        for (size_t i = 0; i + 1u < n_fused; i++) {
            for (size_t j = i + 1u; j < n_fused; j++) {
                if (fused[j].rrf > fused[i].rrf) {
                    uint64_t d = fused[i].doc_id; double r = fused[i].rrf;
                    fused[i].doc_id = fused[j].doc_id; fused[i].rrf = fused[j].rrf;
                    fused[j].doc_id = d; fused[j].rrf = r;
                }
            }
        }
        for (size_t i = 0; i < n_fused && written < want; i++) {
            qihse_ai_memory_hit_t hit;
            if (aimem_accept(server, user, fused[i].doc_id, kind, &hit)) {
                hit.score = fused[i].rrf;
                out[written++] = hit;
            }
        }
        return written;
    }

    const aimem_cand_t* list = (mode == QIHSE_AIMEM_MODE_SEMANTIC) ? vector : lexical;
    size_t n_list = (mode == QIHSE_AIMEM_MODE_SEMANTIC) ? n_vector : n_lexical;
    for (size_t i = 0; i < n_list && written < want; i++) {
        qihse_ai_memory_hit_t hit;
        if (aimem_accept(server, user, list[i].doc_id, kind, &hit)) {
            hit.score = list[i].score;
            out[written++] = hit;
        }
    }
    return written;
}

size_t qihse_ai_memory_recall_mode(qihse_resp_server_t* server, qihse_user_t* user,
                                   const char* query, size_t limit,
                                   qihse_ai_memory_mode_t mode,
                                   qihse_ai_memory_hit_t* out, size_t out_cap) {
    return aimem_recall(server, user, query, limit, mode, QIHSE_AIMEM_KIND_ANY,
                        out, out_cap);
}

size_t qihse_ai_memory_recall_kind(qihse_resp_server_t* server, qihse_user_t* user,
                                   const char* query, size_t limit,
                                   qihse_ai_memory_mode_t mode, uint32_t kind,
                                   qihse_ai_memory_hit_t* out, size_t out_cap) {
    return aimem_recall(server, user, query, limit, mode, kind, out, out_cap);
}

size_t qihse_ai_memory_recall(qihse_resp_server_t* server, qihse_user_t* user,
                              const char* query, size_t limit,
                              qihse_ai_memory_hit_t* out, size_t out_cap) {
    return qihse_ai_memory_recall_mode(server, user, query, limit,
                                       QIHSE_AIMEM_MODE_BM25, out, out_cap);
}

bool qihse_ai_memory_forget_with_seq(qihse_resp_server_t* server,
                            qihse_user_t* user, const char* id,
                            bool* out_removed, uint64_t* out_change_seq) {
    if (out_removed) *out_removed = false;
    if (out_change_seq) *out_change_seq = 0u;
    if (!server || !user || qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM ||
        !id || !out_removed || !out_change_seq) return false;
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(id, &uuid)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    /* Authenticate the complete UUID before deleting its truncated-key
     * record: an unrelated UUID with the same prefix is not authority. */
    qihse_ai_memory_hit_t existing;
    memset(&existing, 0, sizeof existing);
    char key[64];
    aimem_key(key, sizeof key, aimem_doc_id(&uuid));
    if (!qihse_ai_memory_get(server, user, id, &existing)) {
        bool tombstone = false;
        return qihse_kv_change_seq_user(store, key, user, out_change_seq,
                                        &tombstone) && tombstone;
    }
    free(existing.text);
    if (!qihse_kv_del_user_with_seq(store, key, user, out_change_seq)) return false;
    *out_removed = true;
    /* Drop the vector as well, or a forgotten memory would keep ranking in
     * semantic recall — from the in-memory index too, not only the KV record:
     * a stale entry consumes a candidate slot and can push a visible memory
     * out of the top-k even though resolve can never return it. */
    char vkey[64];
    aimem_vec_key(vkey, sizeof vkey, aimem_doc_id(&uuid));
    (void)qihse_kv_del_user(store, vkey, user);
    pthread_mutex_lock(&g_aimem_lock);
    aimem_vecs_remove(aimem_doc_id(&uuid));
    pthread_mutex_unlock(&g_aimem_lock);
    return true;
}

bool qihse_ai_memory_forget(qihse_resp_server_t* server, qihse_user_t* user,
                            const char* id) {
    bool removed = false;
    uint64_t change_seq = 0u;
    return qihse_ai_memory_forget_with_seq(server, user, id, &removed,
                                           &change_seq) && removed;
}

typedef struct {
    size_t count;
    uint32_t kind; /* QIHSE_AIMEM_KIND_ANY counts every visible record */
} aimem_count_t;

static bool aimem_count_cb(const char* key, const char* value, void* user_data) {
    aimem_count_t* c = (aimem_count_t*)user_data;
    if (strncmp(key, AIMEM_PREFIX, AIMEM_PREFIX_LEN) != 0) return true;
    /* Parse the header rather than substring-match a field separator: a body
     * containing "|2|" is not a semantic memory. No body is copied — counting
     * must not duplicate a 64 KB text per record to read one field. */
    aimem_record_meta_t meta;
    memset(&meta, 0, sizeof meta);
    if (aimem_parse_meta(value, &meta, NULL) && !meta.scope.project[0] &&
        (c->kind == QIHSE_AIMEM_KIND_ANY || meta.kind == c->kind)) c->count++;
    return true;
}

size_t qihse_ai_memory_count_kind(qihse_resp_server_t* server, qihse_user_t* user,
                                  uint32_t kind) {
    if (!server || !user || qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM) return 0;
    /* An unrecognised kind counts nothing rather than counting everything. */
    if (!aimem_kind_valid(kind)) return 0;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return 0;
    aimem_count_t c = { .count = 0u, .kind = kind };
    qihse_kv_foreach_user(store, user, aimem_count_cb, &c);
    return c.count;
}

size_t qihse_ai_memory_count(qihse_resp_server_t* server, qihse_user_t* user) {
    return qihse_ai_memory_count_kind(server, user, QIHSE_AIMEM_KIND_ANY);
}

typedef struct { uint32_t reader_id; bool found; } aimem_grant_scan_t;

static bool aimem_grant_scan_cb(const char* key, const char* value, void* opaque) {
    aimem_grant_scan_t* scan = (aimem_grant_scan_t*)opaque;
    char suffix[32];
    snprintf(suffix, sizeof suffix, ":%u", scan->reader_id);
    size_t key_len = strlen(key), suffix_len = strlen(suffix);
    if (key_len >= suffix_len && strcmp(key + key_len - suffix_len, suffix) == 0 &&
        strcmp(value, "read:v1") == 0) {
        scan->found = true;
        return false;
    }
    return true;
}

static bool aimem_scope_owner_allowed(qihse_kv_store_t* store, qihse_user_t* user,
                                     uint32_t owner_id,
                                     const qihse_ai_memory_scope_t* scope) {
    if (!store || !user || !qihse_auth_user_is_active(user) || !scope) return false;
    if (qihse_user_get_id(user) == owner_id ||
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR) return true;
    char prefix[192];
    int n = snprintf(prefix, sizeof prefix, "t:%u/aimem-grant:%s:",
        (unsigned)qihse_user_get_tenant_id(user), scope->project);
    if (n <= 0 || (size_t)n >= sizeof prefix) return false;
    aimem_grant_scan_t scan = { qihse_user_get_id(user), false };
    (void)qihse_kv_foreach_prefix_user(store, prefix, user, aimem_grant_scan_cb, &scan);
    return scan.found;
}

typedef struct {
    uint32_t owner_id;
    const char* project;
    char record_prefix[32];
    bool found;
} aimem_project_owner_scan_t;

static bool aimem_project_owner_scan_cb(const char* key, const char* value,
                                        void* opaque) {
    aimem_project_owner_scan_t* scan = (aimem_project_owner_scan_t*)opaque;
    if (strncmp(key, scan->record_prefix, strlen(scan->record_prefix)) != 0) return true;
    aimem_record_meta_t meta;
    if (aimem_parse_meta(value, &meta, NULL) && meta.owner_id == scan->owner_id &&
        strcmp(meta.scope.project, scan->project) == 0) {
        scan->found = true;
        return false;
    }
    return true;
}

static bool aimem_project_has_owner_record(qihse_kv_store_t* store,
        qihse_user_t* owner, const char* project) {
    aimem_project_owner_scan_t scan = {
        .owner_id = qihse_user_get_id(owner), .project = project, .found = false
    };
    snprintf(scan.record_prefix, sizeof scan.record_prefix, "t:%u/aimem:",
             (unsigned)qihse_user_get_tenant_id(owner));
    (void)qihse_kv_foreach_prefix_user(store, scan.record_prefix, owner,
                                       aimem_project_owner_scan_cb, &scan);
    return scan.found;
}

static bool aimem_project_grant_key(char* out, size_t cap, qihse_user_t* actor,
        const char* project, uint32_t reader_id) {
    if (!actor || !qihse_auth_user_is_active(actor) ||
        !aimem_scope_id_valid(project, true)) return false;
    int n = snprintf(out, cap, "t:%u/aimem-grant:%s:%u:%u",
        (unsigned)qihse_user_get_tenant_id(actor), project,
        (unsigned)qihse_user_get_id(actor), (unsigned)reader_id);
    return n > 0 && (size_t)n < cap;
}

bool qihse_ai_memory_project_grant(qihse_resp_server_t* server,
        qihse_user_t* grantor, const char* project, uint32_t reader_id) {
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    qihse_user_t* reader = qihse_auth_get_user(reader_id);
    if (!store || !grantor || !qihse_auth_user_is_active(grantor) || !reader ||
        !qihse_auth_user_is_active(reader) ||
        qihse_user_get_tenant_id(reader) != qihse_user_get_tenant_id(grantor) ||
        qihse_user_get_id(reader) == qihse_user_get_id(grantor) ||
        (qihse_user_get_role(grantor) != QIHSE_ROLE_OPERATOR &&
         !aimem_project_has_owner_record(store, grantor, project))) return false;
    char key[256];
    return aimem_project_grant_key(key, sizeof key, grantor, project, reader_id) &&
        qihse_kv_set_user(store, key, "read:v1",
            qihse_user_get_classification(grantor), qihse_user_get_sci(grantor), grantor);
}

bool qihse_ai_memory_project_revoke(qihse_resp_server_t* server,
        qihse_user_t* grantor, const char* project, uint32_t reader_id) {
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store || !grantor || !qihse_auth_user_is_active(grantor)) return false;
    char key[256];
    return aimem_project_grant_key(key, sizeof key, grantor, project, reader_id) &&
           qihse_kv_del_user(store, key, grantor);
}

bool qihse_ai_memory_project_reader_allowed(qihse_resp_server_t* server,
        qihse_user_t* reader, const char* project) {
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store || !reader || !qihse_auth_user_is_active(reader) ||
        !aimem_scope_id_valid(project, true)) return false;
    if (qihse_user_get_role(reader) == QIHSE_ROLE_OPERATOR) return true;
    char prefix[192];
    int n = snprintf(prefix, sizeof prefix, "t:%u/aimem-grant:%s:",
        (unsigned)qihse_user_get_tenant_id(reader), project);
    if (n <= 0 || (size_t)n >= sizeof prefix) return false;
    aimem_grant_scan_t scan = { qihse_user_get_id(reader), false };
    (void)qihse_kv_foreach_prefix_user(store, prefix, reader,
                                       aimem_grant_scan_cb, &scan);
    return scan.found;
}

bool qihse_ai_memory_project_owner_allowed(qihse_resp_server_t* server,
        qihse_user_t* owner, const char* project) {
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store || !owner || !qihse_auth_user_is_active(owner) ||
        !aimem_scope_id_valid(project, true)) return false;
    return qihse_user_get_role(owner) == QIHSE_ROLE_OPERATOR ||
           aimem_project_has_owner_record(store, owner, project);
}

typedef struct {
    qihse_fts_index_t* index;
    qihse_kv_store_t* store;
    qihse_user_t* user;
    char key_prefix[32];
    const qihse_ai_memory_scope_t* scope;
    uint32_t kind;
    bool lexical;
    const float* query_vec;
    size_t query_dim;
    aimem_cand_t* vector;
    size_t vector_cap;
    size_t vector_count;
    size_t added;
} aimem_scoped_rebuild_t;

typedef struct {
    qihse_fts_index_t* index;
    qihse_kv_store_t* store;
    qihse_user_t* user;
    uint32_t tenant_id;
    const qihse_ai_memory_scope_t* scope;
    uint32_t kind;
    char key_prefix[32];
    size_t added;
    bool failed;
} aimem_scope_index_build_t;

typedef struct {
    qihse_kv_store_t* store;
    qihse_user_t* user;
    const qihse_ai_memory_scope_t* scope;
    uint32_t kind;
} aimem_scope_visibility_t;

static bool aimem_scope_index_paths(qihse_kv_store_t* store, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, uint32_t kind,
        char index_path[4096], char generation_path[4096]) {
    const char* directory = qihse_kv_store_data_directory(store);
    if (!directory || !user || !scope) return false;
    char identity[5u * QIHSE_AIMEM_SCOPE_ID_MAX + 128u];
    int used = snprintf(identity, sizeof identity, "v1|%u|%u|%u|%u|%u|%u|%s|%s|%s|%s",
        (unsigned)qihse_user_get_tenant_id(user), (unsigned)qihse_user_get_id(user),
        (unsigned)qihse_user_get_role(user),
        (unsigned)qihse_user_get_classification(user),
        (unsigned)qihse_user_get_sci(user), (unsigned)kind, scope->project,
        scope->worktree, scope->workstream, scope->session);
    if (used <= 0 || (size_t)used >= sizeof identity) return false;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0u;
    if (EVP_Digest(identity, (size_t)used, digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len != 32u) return false;
    char hex[65];
    for (size_t i = 0u; i < 32u; i++)
        snprintf(hex + i * 2u, 3u, "%02x", digest[i]);
    int a = snprintf(index_path, 4096u, "%s%saimem-scope-%s.qfts", directory,
                     directory[strlen(directory) - 1u] == '/' ? "" : "/", hex);
    int b = snprintf(generation_path, 4096u, "%s%saimem-scope-%s.gen", directory,
                     directory[strlen(directory) - 1u] == '/' ? "" : "/", hex);
    return a > 0 && a < 4096 && b > 0 && b < 4096;
}

static bool aimem_scope_index_read_generation(const char* path, uint64_t* out) {
    if (!path || !out) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    char bytes[32];
    ssize_t n = -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
        st.st_size < (off_t)sizeof bytes) n = read(fd, bytes, sizeof bytes);
    close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof bytes) return false;
    bytes[n] = '\0';
    char* end = NULL;
    errno = 0;
    unsigned long long value = strtoull(bytes, &end, 10);
    if (errno || end == bytes || (*end != '\n' && *end != '\0') ||
        (end[0] == '\n' && end[1] != '\0')) return false;
    *out = (uint64_t)value;
    return true;
}

static bool aimem_scope_index_sync_directory(const char* filepath) {
    if (!filepath) return false;
    char directory[4096];
    size_t len = strnlen(filepath, sizeof directory);
    if (len == 0u || len >= sizeof directory) return false;
    memcpy(directory, filepath, len + 1u);
    char* slash = strrchr(directory, '/');
    if (!slash) return false;
    if (slash == directory) slash[1] = '\0';
    else *slash = '\0';
    int fd = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

static bool aimem_scope_index_write_generation(const char* path, uint64_t seq) {
    if (!path) return false;
    char tmp[4096];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof tmp) return false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    char text[32];
    int len = snprintf(text, sizeof text, "%llu\n", (unsigned long long)seq);
    bool ok = len > 0 && (size_t)len < sizeof text &&
              write(fd, text, (size_t)len) == len && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (ok && rename(tmp, path) != 0) ok = false;
    if (!ok) unlink(tmp);
    return ok && aimem_scope_index_sync_directory(path);
}

static bool aimem_scope_index_build_cb(const char* key, const char* value,
                                       void* opaque) {
    aimem_scope_index_build_t* build = (aimem_scope_index_build_t*)opaque;
    size_t prefix_len = strlen(build->key_prefix);
    if (strncmp(key, build->key_prefix, prefix_len) != 0) return true;
    aimem_record_meta_t meta;
    const char* text = NULL;
    if (!aimem_parse_meta(value, &meta, &text) || !meta.scope.project[0] ||
        !aimem_scope_matches(&meta.scope, build->scope) ||
        !aimem_kind_ok(build->kind, meta.kind) ||
        !aimem_scope_owner_allowed(build->store, build->user, meta.owner_id,
                                   build->scope)) return true;
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(meta.id, &uuid)) return true;
    uint64_t doc_id = aimem_doc_id(&uuid);
    char expected[96];
    int n = snprintf(expected, sizeof expected, "t:%u/aimem:%016llx",
        (unsigned)build->tenant_id, (unsigned long long)doc_id);
    if (n <= 0 || (size_t)n >= sizeof expected || strcmp(expected, key) != 0) return true;
    if (!build->user || !qihse_auth_user_is_active(build->user) ||
        !qihse_fts_add_document_user(build->index, doc_id, text, strlen(text),
            meta.classification, meta.sci_compartment,
            QIHSE_KEYSTONE_CLASS_UNKNOWN, build->user)) {
        build->failed = true;
        return false;
    }
    build->added++;
    return true;
}

/* Persistent FTS is a principal-label-, scope-, and kind-specific projection.
 * It may contain records across owners, so the query-time predicate applies
 * live project-grant policy before BM25 statistics. */
static qihse_fts_index_t* aimem_scope_index_load_or_build(
        qihse_kv_store_t* store, qihse_user_t* caller,
        const qihse_ai_memory_scope_t* scope, uint32_t kind) {
    if (!store || !caller || !scope) return NULL;
    char index_path[4096], generation_path[4096];
    if (!aimem_scope_index_paths(store, caller, scope, kind, index_path,
                                 generation_path)) return NULL;
    uint64_t before = qihse_kv_change_seq(store), stored = 0u;
    if (aimem_scope_index_read_generation(generation_path, &stored) && stored == before) {
        qihse_fts_index_t* loaded = qihse_fts_load(index_path, caller);
        if (loaded && qihse_kv_change_seq(store) == before) return loaded;
        qihse_fts_destroy(loaded);
    }

    qihse_fts_index_t* index = qihse_fts_create();
    if (!index) return NULL;
    aimem_scope_index_build_t build = {
        .index = index, .store = store, .user = caller,
        .tenant_id = qihse_user_get_tenant_id(caller),
        .scope = scope, .kind = kind, .added = 0u, .failed = false
    };
    snprintf(build.key_prefix, sizeof build.key_prefix, "t:%u/aimem:",
             (unsigned)build.tenant_id);
    bool enumerated = qihse_kv_foreach_prefix_user(store, build.key_prefix,
        caller, aimem_scope_index_build_cb, &build);
    uint64_t after = qihse_kv_change_seq(store);
    if (!enumerated || build.failed || before != after ||
        !qihse_fts_save(index, index_path, caller) ||
        !aimem_scope_index_sync_directory(index_path) ||
        !aimem_scope_index_write_generation(generation_path, after)) {
        qihse_fts_destroy(index);
        return NULL;
    }
    return index;
}

static bool aimem_scope_index_visible(uint64_t doc_id, uint16_t classification,
        uint16_t sci, void* opaque) {
    aimem_scope_visibility_t* visibility = (aimem_scope_visibility_t*)opaque;
    if (!visibility || !visibility->store || !visibility->user ||
        !qihse_auth_can_access(visibility->user, classification, sci)) return false;
    char key[96];
    if (!aimem_scoped_key(key, sizeof key, visibility->user, doc_id)) return false;
    char* raw = qihse_kv_get_user(visibility->store, key, visibility->user);
    if (!raw) return false;
    aimem_record_meta_t meta;
    bool allowed = aimem_parse_meta(raw, &meta, NULL) && meta.scope.project[0] &&
        aimem_scope_matches(&meta.scope, visibility->scope) &&
        aimem_kind_ok(visibility->kind, meta.kind) &&
        aimem_scope_owner_allowed(visibility->store, visibility->user,
                                  meta.owner_id, visibility->scope);
    qihse_uuid_t uuid;
    allowed = allowed && qihse_uuid_parse(meta.id, &uuid) &&
              aimem_doc_id(&uuid) == doc_id;
    free(raw);
    return allowed;
}

static bool aimem_scoped_rebuild_cb(const char* key, const char* value,
                                    void* user_data) {
    aimem_scoped_rebuild_t* rb = (aimem_scoped_rebuild_t*)user_data;
    size_t prefix_len = strlen(rb->key_prefix);
    if (strncmp(key, rb->key_prefix, prefix_len) != 0) return true;
    qihse_ai_memory_hit_t hit;
    aimem_record_meta_t meta;
    memset(&hit, 0, sizeof hit);
    if (!aimem_parse_record_meta(value, &hit, &meta)) return true;
    if (!meta.scope.project[0] ||
        !aimem_scope_matches(&meta.scope, rb->scope) ||
        !aimem_scope_owner_allowed(rb->store, rb->user, meta.owner_id, rb->scope) ||
        !aimem_kind_ok(rb->kind, hit.kind)) {
        free(hit.text);
        return true;
    }
    qihse_uuid_t uuid;
    bool parsed = qihse_uuid_parse(hit.id, &uuid);
    uint64_t doc_id = parsed ? aimem_doc_id(&uuid) : 0u;
    bool ok = parsed;
    if (ok && rb->lexical) {
        ok = qihse_fts_add_document_user(rb->index, doc_id, hit.text,
                  strlen(hit.text), hit.classification, hit.sci_compartment,
                  QIHSE_KEYSTONE_CLASS_UNKNOWN, rb->user);
    }
    if (ok && rb->query_vec && rb->query_dim && rb->vector_cap) {
        float vec[QIHSE_AIMEM_MAX_DIM];
        size_t dim = rb->query_dim;
        if (g_aimem_embedder.embed(hit.text, vec, dim, g_aimem_embedder.ctx)) {
            double dot = 0.0, qn = 0.0, vn = 0.0;
            for (size_t i = 0; i < dim; i++) {
                dot += (double)rb->query_vec[i] * (double)vec[i];
                qn += (double)rb->query_vec[i] * (double)rb->query_vec[i];
                vn += (double)vec[i] * (double)vec[i];
            }
            if (qn > 0.0 && vn > 0.0) {
                double score = dot / (sqrt(qn) * sqrt(vn));
                size_t slot = rb->vector_count;
                if (slot >= rb->vector_cap) {
                    slot = 0u;
                    for (size_t i = 1u; i < rb->vector_count; i++)
                        if (rb->vector[i].score < rb->vector[slot].score) slot = i;
                    if (score <= rb->vector[slot].score) slot = SIZE_MAX;
                } else {
                    rb->vector_count++;
                }
                if (slot != SIZE_MAX) {
                    rb->vector[slot].doc_id = doc_id;
                    rb->vector[slot].score = score;
                }
            }
        }
    }
    free(hit.text);
    if (ok) rb->added++;
    return true;
}

size_t qihse_ai_memory_recall_scoped(qihse_resp_server_t* server,
                                     qihse_user_t* user, const char* query,
                                     size_t limit, qihse_ai_memory_mode_t mode,
                                     uint32_t kind,
                                     const qihse_ai_memory_scope_t* scope,
                                     qihse_ai_memory_hit_t* out,
                                     size_t out_cap) {
    if (!server || !user || !qihse_auth_user_is_active(user) || !query ||
        !*query || !aimem_scope_valid(scope) || !out || out_cap == 0u ||
        (mode != QIHSE_AIMEM_MODE_BM25 && mode != QIHSE_AIMEM_MODE_SEMANTIC &&
         mode != QIHSE_AIMEM_MODE_HYBRID) || !aimem_kind_valid(kind)) return 0u;
    size_t want = limit ? limit : 10u;
    if (want > out_cap) want = out_cap;
    if (want > AIMEM_CAND_MAX) want = AIMEM_CAND_MAX;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return 0u;
    aimem_cand_t vector[AIMEM_CAND_MAX];
    float query_vec[QIHSE_AIMEM_MAX_DIM];
    size_t query_dim = 0u;
    bool want_vector = mode == QIHSE_AIMEM_MODE_SEMANTIC ||
                       mode == QIHSE_AIMEM_MODE_HYBRID;
    if (want_vector) {
        query_dim = g_aimem_embedder.dim;
        if (!query_dim || query_dim > QIHSE_AIMEM_MAX_DIM ||
            !g_aimem_embedder.embed(query, query_vec, query_dim,
                                    g_aimem_embedder.ctx)) {
            return 0u;
        }
    }
    qihse_fts_index_t* scoped_index = NULL;
    qihse_fts_result_t results[AIMEM_CAND_MAX];
    int found = 0;
    if (mode != QIHSE_AIMEM_MODE_SEMANTIC) {
        pthread_mutex_lock(&g_aimem_scope_index_lock);
        scoped_index = aimem_scope_index_load_or_build(store, user, scope, kind);
        if (scoped_index) {
            aimem_scope_visibility_t visibility = {
                .store = store, .user = user, .scope = scope, .kind = kind
            };
            found = qihse_fts_search_user_visible(scoped_index, query, user,
                results, (int)(AIMEM_CAND_MAX), aimem_scope_index_visible,
                &visibility);
        }
        pthread_mutex_unlock(&g_aimem_scope_index_lock);
    }
    aimem_scoped_rebuild_t rb = {
        .index = NULL, .store = store, .user = user, .scope = scope, .kind = kind,
        .lexical = false,
        .query_vec = want_vector ? query_vec : NULL,
        .query_dim = want_vector ? query_dim : 0u,
        .vector = want_vector ? vector : NULL,
        .vector_cap = want_vector ? (want == AIMEM_CAND_MAX ? want : AIMEM_CAND_MAX) : 0u,
        .vector_count = 0u, .added = 0u
    };
    snprintf(rb.key_prefix, sizeof rb.key_prefix, "t:%u/aimem:",
             (unsigned)qihse_user_get_tenant_id(user));
    if (want_vector)
        (void)qihse_kv_foreach_prefix_user(store, rb.key_prefix, user,
                                           aimem_scoped_rebuild_cb, &rb);
    for (size_t i = 0; i + 1u < rb.vector_count; i++) {
        for (size_t j = i + 1u; j < rb.vector_count; j++) {
            if (vector[j].score > vector[i].score) {
                aimem_cand_t tmp = vector[i]; vector[i] = vector[j]; vector[j] = tmp;
            }
        }
    }
    struct { uint64_t doc_id; double score; } fused[AIMEM_FUSED_MAX];
    size_t fused_count = 0u;
    if (mode == QIHSE_AIMEM_MODE_HYBRID) {
        for (int i = 0; i < found && fused_count < AIMEM_FUSED_MAX; i++) {
            fused[fused_count].doc_id = results[i].doc_id;
            fused[fused_count++].score = 1.0 / (AIMEM_RRF_K + (double)(i + 1));
        }
        for (size_t i = 0; i < rb.vector_count && fused_count < AIMEM_FUSED_MAX; i++) {
            size_t j = 0u;
            for (; j < fused_count; j++) if (fused[j].doc_id == vector[i].doc_id) break;
            double contribution = 1.0 / (AIMEM_RRF_K + (double)(i + 1u));
            if (j < fused_count) fused[j].score += contribution;
            else { fused[fused_count].doc_id = vector[i].doc_id; fused[fused_count++].score = contribution; }
        }
        for (size_t i = 0; i + 1u < fused_count; i++) for (size_t j = i + 1u; j < fused_count; j++)
            if (fused[j].score > fused[i].score) {
                uint64_t did = fused[i].doc_id; double score = fused[i].score;
                fused[i] = fused[j]; fused[j].doc_id = did; fused[j].score = score;
            }
    }
    size_t written = 0u;
    size_t n_candidates = mode == QIHSE_AIMEM_MODE_SEMANTIC ? rb.vector_count :
                          mode == QIHSE_AIMEM_MODE_HYBRID ? fused_count : (size_t)found;
    for (size_t i = 0; i < n_candidates && written < want; i++) {
        /* FTS ids contain the document key prefix only; resolve the canonical
         * record and recheck its full scope and principal before disclosure. */
        char key[96];
        uint64_t candidate_id = mode == QIHSE_AIMEM_MODE_SEMANTIC ? vector[i].doc_id :
                                mode == QIHSE_AIMEM_MODE_HYBRID ? fused[i].doc_id :
                                results[i].doc_id;
        if (!aimem_scoped_key(key, sizeof key, user, candidate_id)) continue;
        char* raw = qihse_kv_get_user(store, key, user);
        if (!raw) continue;
        qihse_ai_memory_hit_t hit;
        memset(&hit, 0, sizeof hit);
        aimem_record_meta_t meta;
        bool ok = aimem_parse_record_meta(raw, &hit, &meta);
        free(raw);
        qihse_uuid_t resolved_uuid;
        if (!ok || !meta.scope.project[0] ||
            !aimem_scope_matches(&meta.scope, scope) ||
            !aimem_scope_owner_allowed(store, user, meta.owner_id, scope) ||
            !qihse_uuid_parse(hit.id, &resolved_uuid) ||
            aimem_doc_id(&resolved_uuid) != candidate_id) {
            free(hit.text);
            continue;
        }
        hit.score = mode == QIHSE_AIMEM_MODE_SEMANTIC ? vector[i].score :
                    mode == QIHSE_AIMEM_MODE_HYBRID ? fused[i].score :
                    results[i].bm25_score;
        out[written++] = hit;
    }
    qihse_fts_destroy(scoped_index);
    return written;
}

bool qihse_ai_memory_get_scoped(qihse_resp_server_t* server,
                                qihse_user_t* user, const char* id,
                                const qihse_ai_memory_scope_t* scope,
                                qihse_ai_memory_hit_t* out) {
    if (!server || !user || !qihse_auth_user_is_active(user) || !id ||
        !out || !aimem_scope_valid(scope)) return false;
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(id, &uuid)) return false;
    memset(out, 0, sizeof(*out));
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    char key[96];
    if (!aimem_scoped_key(key, sizeof key, user, aimem_doc_id(&uuid))) return false;
    char* raw = qihse_kv_get_user(store, key, user);
    if (!raw) return false;
    aimem_record_meta_t meta;
    bool ok = aimem_parse_record_meta(raw, out, &meta);
    free(raw);
    char canonical[QIHSE_AIMEM_ID_LEN + 1u];
    ok = ok && qihse_uuid_format(&uuid, canonical) &&
         strcmp(canonical, out->id) == 0 && meta.scope.project[0] &&
         aimem_scope_matches(&meta.scope, scope) &&
         aimem_scope_owner_allowed(store, user, meta.owner_id, scope);
    if (!ok) { free(out->text); memset(out, 0, sizeof(*out)); }
    return ok;
}

void qihse_ai_memory_knowledge_free(qihse_ai_memory_knowledge_version_t* value) {
    if (!value) return;
    free(value->content);
    free(value->source_event_ids);
    free(value->relations);
    memset(value, 0, sizeof(*value));
}

#define AIMEM_KNOWLEDGE_MAX_CONTENT (64u * 1024u)
#define AIMEM_KNOWLEDGE_MAX_VERSIONS 256u
#define AIMEM_KNOWLEDGE_MAX_ENCODED (8u * 1024u * 1024u)

typedef struct {
    char knowledge_id[QIHSE_AIMEM_ID_LEN + 1u];
    uint32_t owner_id;
    qihse_ai_memory_scope_t scope;
    uint32_t type;
    qihse_ai_memory_knowledge_version_t* versions;
    size_t count;
} aimem_knowledge_chain_t;

static void aimem_knowledge_chain_free(aimem_knowledge_chain_t* chain) {
    if (!chain) return;
    for (size_t i = 0; i < chain->count; i++) {
        free(chain->versions[i].content);
        free(chain->versions[i].source_event_ids);
        free(chain->versions[i].relations);
    }
    free(chain->versions);
    memset(chain, 0, sizeof(*chain));
}

static bool aimem_knowledge_type_valid(uint32_t type) {
    return type >= QIHSE_AIMEM_KNOWLEDGE_DECISION &&
           type <= QIHSE_AIMEM_KNOWLEDGE_SESSION_CAPSULE;
}

static bool aimem_knowledge_status_writable(qihse_user_t* user, uint32_t status) {
    if (status == QIHSE_AIMEM_KNOWLEDGE_PROPOSED) return true;
    return (status == QIHSE_AIMEM_KNOWLEDGE_APPROVED ||
            status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED) &&
           qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR;
}

static bool aimem_knowledge_key(char* out, size_t cap, qihse_user_t* user,
                                const char* knowledge_id) {
    qihse_uuid_t parsed;
    if (!out || !user || !knowledge_id ||
        !qihse_auth_user_is_active(user) || !qihse_uuid_parse(knowledge_id, &parsed))
        return false;
    int n = snprintf(out, cap, "t:%u/aimem-knowledge:%s",
                     (unsigned)qihse_user_get_tenant_id(user), knowledge_id);
    return n > 0 && (size_t)n < cap;
}

static char aimem_hex_digit(unsigned value) {
    return (char)(value < 10u ? '0' + value : 'a' + value - 10u);
}

static int aimem_hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char* aimem_hex_encode(const char* text) {
    size_t n = text ? strlen(text) : 0u;
    if (!n || n > AIMEM_KNOWLEDGE_MAX_CONTENT || n > (SIZE_MAX - 1u) / 2u)
        return NULL;
    char* out = malloc(n * 2u + 1u);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)text[i];
        out[i * 2u] = aimem_hex_digit(c >> 4);
        out[i * 2u + 1u] = aimem_hex_digit(c & 0x0fu);
    }
    out[n * 2u] = '\0';
    return out;
}

static char* aimem_hex_decode(const char* hex) {
    size_t n = hex ? strlen(hex) : 0u;
    if (!n || (n & 1u) || n / 2u > AIMEM_KNOWLEDGE_MAX_CONTENT) return NULL;
    char* out = malloc(n / 2u + 1u);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i += 2u) {
        int hi = aimem_hex_value(hex[i]), lo = aimem_hex_value(hex[i + 1u]);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) { free(out); return NULL; }
        out[i / 2u] = (char)((hi << 4) | lo);
    }
    out[n / 2u] = '\0';
    return out;
}

static bool aimem_token_u64(const char* text, uint64_t* out) {
    char* end = NULL;
    errno = 0;
    unsigned long long v = text ? strtoull(text, &end, 10) : 0u;
    if (errno || !text || end == text || *end) return false;
    *out = (uint64_t)v;
    return true;
}

static bool aimem_token_u32(const char* text, uint32_t* out) {
    uint64_t v = 0u;
    if (!aimem_token_u64(text, &v) || v > UINT32_MAX) return false;
    *out = (uint32_t)v;
    return true;
}

static bool aimem_content_sha256(const char* content,
        char out[QIHSE_AIMEM_CONTENT_SHA256_HEX_LEN + 1u]) {
    unsigned char digest[32];
    unsigned int digest_len = 0u;
    if (!content || !*content || !out ||
        EVP_Digest(content, strlen(content), digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len != sizeof digest)
        return false;
    for (size_t i = 0; i < sizeof digest; i++) {
        out[i * 2u] = aimem_hex_digit(digest[i] >> 4);
        out[i * 2u + 1u] = aimem_hex_digit(digest[i] & 0x0fu);
    }
    out[QIHSE_AIMEM_CONTENT_SHA256_HEX_LEN] = '\0';
    return true;
}

static bool aimem_knowledge_chain_parse_v1(const char* raw,
                                           aimem_knowledge_chain_t* out) {
    if (!raw || !out) return false;
    memset(out, 0, sizeof(*out));
    char* copy = strdup(raw);
    if (!copy) return false;
    char* cursor = copy;
#define NEXT_TOKEN() strsep(&cursor, "|")
    char* tok = NEXT_TOKEN();
    bool ok = tok && strcmp(tok, "QHK1") == 0;
    tok = ok ? NEXT_TOKEN() : NULL;
    qihse_uuid_t parsed;
    ok = tok && qihse_uuid_parse(tok, &parsed);
    if (ok) snprintf(out->knowledge_id, sizeof out->knowledge_id, "%s", tok);
    tok = ok ? NEXT_TOKEN() : NULL; ok = tok && aimem_token_u32(tok, &out->owner_id);
    char* fields[4];
    for (size_t i = 0; ok && i < 4u; i++) { fields[i] = NEXT_TOKEN(); ok = fields[i] != NULL; }
    if (ok) {
        for (size_t i = 0; i < 4u; i++)
            if (strlen(fields[i]) > QIHSE_AIMEM_SCOPE_ID_MAX) ok = false;
    }
    if (ok) {
        snprintf(out->scope.project, sizeof out->scope.project, "%s", fields[0]);
        snprintf(out->scope.worktree, sizeof out->scope.worktree, "%s", fields[1]);
        snprintf(out->scope.workstream, sizeof out->scope.workstream, "%s", fields[2]);
        snprintf(out->scope.session, sizeof out->scope.session, "%s", fields[3]);
        ok = aimem_scope_valid(&out->scope);
    }
    tok = ok ? NEXT_TOKEN() : NULL; ok = tok && aimem_token_u32(tok, &out->type) && aimem_knowledge_type_valid(out->type);
    uint32_t count32 = 0u;
    tok = ok ? NEXT_TOKEN() : NULL; ok = tok && aimem_token_u32(tok, &count32) && count32 && count32 <= AIMEM_KNOWLEDGE_MAX_VERSIONS;
    if (ok) out->versions = calloc(count32, sizeof(*out->versions));
    ok = ok && out->versions;
    if (ok) out->count = count32;
    for (uint32_t i = 0; ok && i < count32; i++) {
        qihse_ai_memory_knowledge_version_t* v = &out->versions[i];
        char* id = NEXT_TOKEN(); char* revision = NEXT_TOKEN();
        char* created = NEXT_TOKEN(); char* from = NEXT_TOKEN(); char* to = NEXT_TOKEN();
        char* status = NEXT_TOKEN(); char* actor = NEXT_TOKEN();
        char* supersedes = NEXT_TOKEN(); char* hex = NEXT_TOKEN();
        qihse_uuid_t vid;
        ok = id && revision && created && from && to && status && actor && supersedes && hex &&
             qihse_uuid_parse(id, &vid) && aimem_token_u64(revision, &v->revision) &&
             aimem_token_u64(created, &v->created_at_ms) &&
             aimem_token_u64(from, &v->valid_from_ingest_ms) &&
             aimem_token_u64(to, &v->valid_to_ingest_ms) &&
             aimem_token_u32(status, &v->status) && aimem_token_u32(actor, &v->created_by);
        if (ok && supersedes[0] && !qihse_uuid_parse(supersedes, &vid)) ok = false;
        if (ok) v->content = aimem_hex_decode(hex);
        ok = ok && v->content;
        if (ok) {
            snprintf(v->knowledge_id, sizeof v->knowledge_id, "%s", out->knowledge_id);
            snprintf(v->version_id, sizeof v->version_id, "%s", id);
            snprintf(v->supersedes_version, sizeof v->supersedes_version, "%s", supersedes);
            v->scope = out->scope; v->type = out->type;
            v->generated_by = v->created_by;
            ok = aimem_content_sha256(v->content, v->content_sha256);
            bool status_ok = v->status >= QIHSE_AIMEM_KNOWLEDGE_PROPOSED &&
                             v->status <= QIHSE_AIMEM_KNOWLEDGE_RETRACTED;
            ok = status_ok && v->revision == (uint64_t)i + 1u &&
                 v->created_at_ms && v->valid_from_ingest_ms;
            if (ok && i == 0u) ok = !v->supersedes_version[0];
            if (ok && i > 0u) ok = strcmp(v->supersedes_version,
                                           out->versions[i - 1u].version_id) == 0 &&
                                      out->versions[i - 1u].valid_to_ingest_ms ==
                                           v->valid_from_ingest_ms &&
                                      out->versions[i - 1u].status ==
                                           QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED;
        }
    }
    ok = ok && cursor == NULL && out->versions[count32 - 1u].valid_to_ingest_ms == 0u;
    free(copy);
    if (!ok) aimem_knowledge_chain_free(out);
#undef NEXT_TOKEN
    return ok;
}

static bool aimem_relation_type_valid(uint32_t type) {
    return type >= QIHSE_AIMEM_RELATION_FIXES &&
           type <= QIHSE_AIMEM_RELATION_SUPERSEDES;
}

static bool aimem_knowledge_chain_parse_v2(const char* raw,
                                           aimem_knowledge_chain_t* out) {
    memset(out, 0, sizeof(*out));
    char* copy = raw ? strdup(raw) : NULL;
    if (!copy) return false;
    char* cursor = copy;
#define NEXT_V2() strsep(&cursor, "|")
    char* tok = NEXT_V2();
    bool ok = tok && strcmp(tok, "QHK2") == 0;
    qihse_uuid_t uuid;
    tok = ok ? NEXT_V2() : NULL;
    ok = tok && qihse_uuid_parse(tok, &uuid);
    if (ok) snprintf(out->knowledge_id, sizeof out->knowledge_id, "%s", tok);
    tok = ok ? NEXT_V2() : NULL; ok = tok && aimem_token_u32(tok, &out->owner_id);
    char* scope[4];
    for (size_t i = 0; ok && i < 4u; i++) {
        scope[i] = NEXT_V2();
        ok = scope[i] && strlen(scope[i]) <= QIHSE_AIMEM_SCOPE_ID_MAX;
    }
    if (ok) {
        snprintf(out->scope.project, sizeof out->scope.project, "%s", scope[0]);
        snprintf(out->scope.worktree, sizeof out->scope.worktree, "%s", scope[1]);
        snprintf(out->scope.workstream, sizeof out->scope.workstream, "%s", scope[2]);
        snprintf(out->scope.session, sizeof out->scope.session, "%s", scope[3]);
        ok = aimem_scope_valid(&out->scope);
    }
    tok = ok ? NEXT_V2() : NULL;
    ok = tok && aimem_token_u32(tok, &out->type) && aimem_knowledge_type_valid(out->type);
    uint32_t count = 0u;
    tok = ok ? NEXT_V2() : NULL;
    ok = tok && aimem_token_u32(tok, &count) && count &&
         count <= AIMEM_KNOWLEDGE_MAX_VERSIONS;
    if (ok) out->versions = calloc(count, sizeof(*out->versions));
    ok = ok && out->versions;
    if (ok) out->count = count;
    for (uint32_t i = 0; ok && i < count; i++) {
        qihse_ai_memory_knowledge_version_t* v = &out->versions[i];
        char* id = NEXT_V2(); char* revision = NEXT_V2();
        char* created = NEXT_V2(); char* from = NEXT_V2(); char* to = NEXT_V2();
        char* status = NEXT_V2(); char* actor = NEXT_V2();
        char* generated = NEXT_V2(); char* reviewed = NEXT_V2();
        char* confidence = NEXT_V2(); char* supersedes = NEXT_V2();
        char* digest = NEXT_V2(); char* source_count_text = NEXT_V2();
        uint32_t source_count = 0u;
        ok = id && revision && created && from && to && status && actor && generated &&
             reviewed && confidence && supersedes && digest && source_count_text &&
             qihse_uuid_parse(id, &uuid) && aimem_token_u64(revision, &v->revision) &&
             aimem_token_u64(created, &v->created_at_ms) &&
             aimem_token_u64(from, &v->valid_from_ingest_ms) &&
             aimem_token_u64(to, &v->valid_to_ingest_ms) &&
             aimem_token_u32(status, &v->status) &&
             aimem_token_u32(actor, &v->created_by) &&
             aimem_token_u32(generated, &v->generated_by) &&
             aimem_token_u32(reviewed, &v->reviewed_by) &&
             aimem_token_u32(confidence, &v->confidence_ppm) &&
             v->confidence_ppm <= QIHSE_AIMEM_CONFIDENCE_MAX &&
             strlen(digest) == QIHSE_AIMEM_CONTENT_SHA256_HEX_LEN &&
             aimem_token_u32(source_count_text, &source_count) &&
             source_count <= QIHSE_AIMEM_KNOWLEDGE_MAX_SOURCES;
        if (ok && supersedes[0] && !qihse_uuid_parse(supersedes, &uuid)) ok = false;
        if (ok && source_count)
            v->source_event_ids = calloc(source_count, sizeof(*v->source_event_ids));
        if (ok && source_count && !v->source_event_ids) ok = false;
        v->source_event_count = ok ? source_count : 0u;
        for (uint32_t j = 0; ok && j < source_count; j++) {
            char* source = NEXT_V2();
            ok = source && qihse_uuid_parse(source, &uuid);
            if (ok) snprintf(v->source_event_ids[j], sizeof v->source_event_ids[j],
                             "%s", source);
        }
        uint32_t relation_count = 0u;
        tok = ok ? NEXT_V2() : NULL;
        ok = tok && aimem_token_u32(tok, &relation_count) &&
             relation_count <= QIHSE_AIMEM_KNOWLEDGE_MAX_RELATIONS;
        if (ok && relation_count)
            v->relations = calloc(relation_count, sizeof(*v->relations));
        if (ok && relation_count && !v->relations) ok = false;
        v->relation_count = ok ? relation_count : 0u;
        for (uint32_t j = 0; ok && j < relation_count; j++) {
            qihse_ai_memory_relation_t* relation = &v->relations[j];
            char* type = NEXT_V2(); char* target = NEXT_V2();
            char* project = NEXT_V2(); char* worktree = NEXT_V2();
            char* workstream = NEXT_V2(); char* session = NEXT_V2();
            ok = type && target && project && worktree && workstream && session &&
                 aimem_token_u32(type, &relation->type) &&
                 aimem_relation_type_valid(relation->type) &&
                 qihse_uuid_parse(target, &uuid) &&
                 strlen(project) <= QIHSE_AIMEM_SCOPE_ID_MAX &&
                 strlen(worktree) <= QIHSE_AIMEM_SCOPE_ID_MAX &&
                 strlen(workstream) <= QIHSE_AIMEM_SCOPE_ID_MAX &&
                 strlen(session) <= QIHSE_AIMEM_SCOPE_ID_MAX;
            if (ok) {
                snprintf(relation->target_version_id, sizeof relation->target_version_id,
                         "%s", target);
                snprintf(relation->target_scope.project, sizeof relation->target_scope.project,
                         "%s", project);
                snprintf(relation->target_scope.worktree, sizeof relation->target_scope.worktree,
                         "%s", worktree);
                snprintf(relation->target_scope.workstream, sizeof relation->target_scope.workstream,
                         "%s", workstream);
                snprintf(relation->target_scope.session, sizeof relation->target_scope.session,
                         "%s", session);
                ok = aimem_scope_valid(&relation->target_scope);
            }
        }
        char* hex = ok ? NEXT_V2() : NULL;
        if (ok) v->content = aimem_hex_decode(hex);
        char computed[QIHSE_AIMEM_CONTENT_SHA256_HEX_LEN + 1u];
        ok = ok && v->content && aimem_content_sha256(v->content, computed) &&
             strcmp(computed, digest) == 0;
        if (ok) {
            snprintf(v->knowledge_id, sizeof v->knowledge_id, "%s", out->knowledge_id);
            snprintf(v->version_id, sizeof v->version_id, "%s", id);
            snprintf(v->supersedes_version, sizeof v->supersedes_version, "%s", supersedes);
            snprintf(v->content_sha256, sizeof v->content_sha256, "%s", digest);
            v->scope = out->scope; v->type = out->type;
            ok = v->status >= QIHSE_AIMEM_KNOWLEDGE_PROPOSED &&
                 v->status <= QIHSE_AIMEM_KNOWLEDGE_RETRACTED &&
                 v->revision == (uint64_t)i + 1u && v->created_at_ms &&
                 v->valid_from_ingest_ms &&
                 ((v->status == QIHSE_AIMEM_KNOWLEDGE_APPROVED ||
                   v->status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED) ?
                    v->reviewed_by != 0u : true);
            if (ok && i == 0u) ok = !v->supersedes_version[0];
            if (ok && i > 0u) ok = strcmp(v->supersedes_version,
                out->versions[i - 1u].version_id) == 0 &&
                out->versions[i - 1u].valid_to_ingest_ms == v->valid_from_ingest_ms &&
                out->versions[i - 1u].status == QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED;
        }
    }
    ok = ok && cursor == NULL && out->versions[count - 1u].valid_to_ingest_ms == 0u;
    free(copy);
    if (!ok) aimem_knowledge_chain_free(out);
#undef NEXT_V2
    return ok;
}

static bool aimem_knowledge_chain_parse(const char* raw,
                                        aimem_knowledge_chain_t* out) {
    if (!raw || !out) return false;
    if (strncmp(raw, "QHK2|", 5u) == 0) return aimem_knowledge_chain_parse_v2(raw, out);
    return aimem_knowledge_chain_parse_v1(raw, out);
}

static char* aimem_knowledge_chain_encode(const aimem_knowledge_chain_t* chain) {
    if (!chain || !chain->count || chain->count > AIMEM_KNOWLEDGE_MAX_VERSIONS) return NULL;
    size_t cap = 512u;
    for (size_t i = 0; i < chain->count; i++) {
        size_t n = chain->versions[i].content ? strlen(chain->versions[i].content) : 0u;
        size_t extra = n * 2u + 512u +
            chain->versions[i].source_event_count * 40u +
            chain->versions[i].relation_count * 360u;
        if (!n || n > AIMEM_KNOWLEDGE_MAX_CONTENT || cap > SIZE_MAX - extra) return NULL;
        cap += extra;
    }
    if (cap > AIMEM_KNOWLEDGE_MAX_ENCODED) return NULL;
    char* out = malloc(cap), *p = out;
    if (!out) return NULL;
    size_t left = cap;
#define APPEND(...) do { int written = snprintf(p, left, __VA_ARGS__); if (written < 0 || (size_t)written >= left) { free(out); return NULL; } p += written; left -= (size_t)written; } while (0)
    APPEND("QHK2|%s|%u|%s|%s|%s|%s|%u|%zu", chain->knowledge_id,
           (unsigned)chain->owner_id, chain->scope.project, chain->scope.worktree,
           chain->scope.workstream, chain->scope.session, (unsigned)chain->type, chain->count);
    for (size_t i = 0; i < chain->count; i++) {
        const qihse_ai_memory_knowledge_version_t* v = &chain->versions[i];
        char* hex = aimem_hex_encode(v->content);
        if (!hex) { free(out); return NULL; }
        char digest[QIHSE_AIMEM_CONTENT_SHA256_HEX_LEN + 1u];
        if (!aimem_content_sha256(v->content, digest)) { free(hex); free(out); return NULL; }
        APPEND("|%s|%llu|%llu|%llu|%llu|%u|%u|%u|%u|%u|%s|%s|%zu", v->version_id,
               (unsigned long long)v->revision, (unsigned long long)v->created_at_ms,
               (unsigned long long)v->valid_from_ingest_ms,
               (unsigned long long)v->valid_to_ingest_ms, (unsigned)v->status,
               (unsigned)v->created_by, (unsigned)v->generated_by,
               (unsigned)v->reviewed_by, (unsigned)v->confidence_ppm,
               v->supersedes_version, digest, v->source_event_count);
        for (size_t j = 0; j < v->source_event_count; j++)
            APPEND("|%s", v->source_event_ids[j]);
        APPEND("|%zu", v->relation_count);
        for (size_t j = 0; j < v->relation_count; j++) {
            const qihse_ai_memory_relation_t* relation = &v->relations[j];
            APPEND("|%u|%s|%s|%s|%s|%s", (unsigned)relation->type,
                   relation->target_version_id, relation->target_scope.project,
                   relation->target_scope.worktree, relation->target_scope.workstream,
                   relation->target_scope.session);
        }
        APPEND("|%s", hex);
        free(hex);
    }
#undef APPEND
    return out;
}

static bool aimem_knowledge_copy(const qihse_ai_memory_knowledge_version_t* src,
                                 qihse_ai_memory_knowledge_version_t* out) {
    if (!src || !out || !src->content) return false;
    *out = *src;
    out->content = strdup(src->content);
    out->source_event_ids = NULL;
    out->relations = NULL;
    if (src->source_event_count) {
        out->source_event_ids = calloc(src->source_event_count,
                                       sizeof(*out->source_event_ids));
        if (out->source_event_ids)
            memcpy(out->source_event_ids, src->source_event_ids,
                   src->source_event_count * sizeof(*out->source_event_ids));
    }
    if (src->relation_count) {
        out->relations = calloc(src->relation_count, sizeof(*out->relations));
        if (out->relations)
            memcpy(out->relations, src->relations,
                   src->relation_count * sizeof(*out->relations));
    }
    if (!out->content || (src->source_event_count && !out->source_event_ids) ||
        (src->relation_count && !out->relations)) {
        qihse_ai_memory_knowledge_free(out);
        return false;
    }
    return true;
}

static bool aimem_knowledge_chain_read(qihse_resp_server_t* server,
        qihse_user_t* user, const char* knowledge_id,
        const qihse_ai_memory_scope_t* scope, char** raw_out,
        aimem_knowledge_chain_t* chain) {
    if (chain) memset(chain, 0, sizeof(*chain));
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !knowledge_id || !aimem_scope_valid(scope) || !raw_out || !chain) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    char key[128];
    if (!store || !aimem_knowledge_key(key, sizeof key, user, knowledge_id)) return false;
    char* raw = qihse_kv_get_user(store, key, user);
    if (!raw || !aimem_knowledge_chain_parse(raw, chain) ||
        strcmp(chain->knowledge_id, knowledge_id) != 0 ||
        !aimem_scope_matches(&chain->scope, scope) ||
        !aimem_scope_owner_allowed(store, user, chain->owner_id, scope)) {
        free(raw); aimem_knowledge_chain_free(chain); return false;
    }
    *raw_out = raw;
    return true;
}

static bool aimem_idempotency_key_valid(const char* key) {
    if (!key) return true;
    size_t n = strnlen(key, QIHSE_AIMEM_IDEM_MAX_LEN + 1u);
    if (!n || n > QIHSE_AIMEM_IDEM_MAX_LEN) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)key[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == ':'))
            return false;
    }
    return true;
}

static bool aimem_prepare_provenance(qihse_resp_server_t* server,
        qihse_user_t* user, const qihse_ai_memory_scope_t* scope,
        const qihse_ai_memory_knowledge_provenance_t* provenance,
        const char* supersedes, qihse_ai_memory_knowledge_version_t* value) {
    size_t source_count = provenance ? provenance->source_event_count : 0u;
    size_t relation_count = provenance ? provenance->relation_count : 0u;
    if (!value || source_count > QIHSE_AIMEM_KNOWLEDGE_MAX_SOURCES ||
        relation_count + (supersedes ? 1u : 0u) > QIHSE_AIMEM_KNOWLEDGE_MAX_RELATIONS ||
        (provenance && provenance->confidence_ppm > QIHSE_AIMEM_CONFIDENCE_MAX) ||
        (source_count && !provenance->source_event_ids) ||
        (relation_count && !provenance->relations) ||
        (provenance && !aimem_idempotency_key_valid(provenance->idempotency_key)))
        return false;
    if (source_count) {
        value->source_event_ids = calloc(source_count, sizeof(*value->source_event_ids));
        if (!value->source_event_ids) return false;
    }
    for (size_t i = 0; i < source_count; i++) {
        const char* id = provenance->source_event_ids[i];
        qihse_uuid_t parsed;
        qihse_ai_memory_hit_t event = {0};
        if (!id || !qihse_uuid_parse(id, &parsed) ||
            !qihse_ai_memory_event_get(server, user, id, scope, &event)) {
            free(event.text); return false;
        }
        free(event.text);
        for (size_t j = 0; j < i; j++)
            if (strcmp(value->source_event_ids[j], id) == 0) return false;
        snprintf(value->source_event_ids[i], sizeof value->source_event_ids[i], "%s", id);
    }
    value->source_event_count = source_count;
    size_t total_relations = relation_count + (supersedes ? 1u : 0u);
    if (total_relations) {
        value->relations = calloc(total_relations, sizeof(*value->relations));
        if (!value->relations) return false;
    }
    for (size_t i = 0; i < relation_count; i++) {
        const qihse_ai_memory_relation_t* relation = &provenance->relations[i];
        qihse_ai_memory_knowledge_version_t target = {0};
        if (!aimem_relation_type_valid(relation->type) ||
            relation->type == QIHSE_AIMEM_RELATION_SUPERSEDES ||
            !aimem_scope_valid(&relation->target_scope) ||
            !qihse_ai_memory_knowledge_get(server, user, relation->target_version_id,
                                            &relation->target_scope, &target))
            return false;
        qihse_ai_memory_knowledge_free(&target);
        for (size_t j = 0; j < i; j++)
            if (value->relations[j].type == relation->type &&
                strcmp(value->relations[j].target_version_id,
                       relation->target_version_id) == 0) return false;
        value->relations[i] = *relation;
    }
    if (supersedes) {
        qihse_ai_memory_relation_t* relation = &value->relations[relation_count];
        relation->type = QIHSE_AIMEM_RELATION_SUPERSEDES;
        snprintf(relation->target_version_id, sizeof relation->target_version_id,
                 "%s", supersedes);
        relation->target_scope = *scope;
    }
    value->relation_count = total_relations;
    value->generated_by = qihse_user_get_id(user);
    value->confidence_ppm = provenance ? provenance->confidence_ppm : 0u;
    return true;
}

static bool aimem_knowledge_payload_matches(
        const qihse_ai_memory_knowledge_version_t* value, uint32_t status,
        const char* content,
        const qihse_ai_memory_knowledge_provenance_t* provenance) {
    size_t source_count = provenance ? provenance->source_event_count : 0u;
    size_t relation_count = provenance ? provenance->relation_count : 0u;
    uint32_t confidence = provenance ? provenance->confidence_ppm : 0u;
    if (!value || (value->status != status &&
                   value->status != QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED) ||
        strcmp(value->content, content) != 0 ||
        value->confidence_ppm != confidence || value->source_event_count != source_count ||
        value->relation_count != relation_count + (value->revision > 1u ? 1u : 0u))
        return false;
    for (size_t i = 0; i < source_count; i++)
        if (strcmp(value->source_event_ids[i], provenance->source_event_ids[i]) != 0)
            return false;
    for (size_t i = 0; i < relation_count; i++)
        if (memcmp(&value->relations[i], &provenance->relations[i],
                   sizeof(value->relations[i])) != 0) return false;
    return true;
}

static void aimem_knowledge_audit(qihse_user_t* user, const char* action,
        const qihse_ai_memory_knowledge_version_t* value, uint16_t classification,
        uint16_t sci) {
    qihse_audit_log(action, qihse_user_get_id(user),
                    (uint32_t)value->source_event_count, classification, sci);
    for (size_t i = 0; i < value->source_event_count; i++) {
        qihse_uuid_t event;
        if (!qihse_uuid_parse(value->source_event_ids[i], &event)) continue;
        uint32_t citation = ((uint32_t)event.bytes[0] << 24) |
                            ((uint32_t)event.bytes[1] << 16) |
                            ((uint32_t)event.bytes[2] << 8) |
                            (uint32_t)event.bytes[3];
        qihse_audit_log("AIMEM_KNOWLEDGE_EVIDENCE", qihse_user_get_id(user),
                        citation, classification, sci);
    }
}

qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_create_ex(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, uint32_t type, uint32_t status,
        const char* content,
        const qihse_ai_memory_knowledge_provenance_t* provenance,
        qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !aimem_knowledge_type_valid(type) ||
        !aimem_knowledge_status_writable(user, status) ||
        status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED || !content || !*content ||
        strlen(content) > AIMEM_KNOWLEDGE_MAX_CONTENT || !out ||
        (provenance && !aimem_idempotency_key_valid(provenance->idempotency_key)) ||
        !qihse_ai_memory_project_owner_allowed(server, user, scope->project))
        return QIHSE_AIMEM_WRITE_FAILED;
    qihse_uuid_t knowledge_uuid, version_uuid;
    aimem_knowledge_chain_t chain;
    memset(&chain, 0, sizeof chain);
    const char* idem = provenance ? provenance->idempotency_key : NULL;
    if (idem) {
        char seed[QIHSE_AIMEM_IDEM_MAX_LEN + 512u];
        int n = snprintf(seed, sizeof seed, "QIHSE:AIMEM:knowledge:create:v2:%u:%u:%s:%s:%s:%s:%s:%s",
            (unsigned)qihse_user_get_tenant_id(user), (unsigned)qihse_user_get_id(user),
            scope->project, scope->worktree, scope->workstream, scope->session, idem,
            "knowledge");
        if (n <= 0 || (size_t)n >= sizeof seed ||
            !qihse_uuid_from_seed(seed, (size_t)n, &knowledge_uuid))
            return QIHSE_AIMEM_WRITE_FAILED;
        n = snprintf(seed, sizeof seed, "QIHSE:AIMEM:knowledge:version:v2:%s:1",
                     qihse_uuid_format(&knowledge_uuid, chain.knowledge_id) ?
                     chain.knowledge_id : "");
        if (n <= 0 || (size_t)n >= sizeof seed ||
            !qihse_uuid_from_seed(seed, (size_t)n, &version_uuid))
            return QIHSE_AIMEM_WRITE_FAILED;
    } else if (!qihse_uuid_generate(&knowledge_uuid) ||
               !qihse_uuid_format(&knowledge_uuid, chain.knowledge_id) ||
               !qihse_uuid_generate(&version_uuid)) return QIHSE_AIMEM_WRITE_FAILED;
    chain.owner_id = qihse_user_get_id(user); chain.scope = *scope; chain.type = type;
    chain.versions = calloc(1u, sizeof(*chain.versions));
    if (!chain.versions) return QIHSE_AIMEM_WRITE_FAILED;
    chain.count = 1u;
    qihse_ai_memory_knowledge_version_t* v = &chain.versions[0];
    snprintf(v->knowledge_id, sizeof v->knowledge_id, "%s", chain.knowledge_id);
    if (!qihse_uuid_format(&version_uuid, v->version_id)) {
        aimem_knowledge_chain_free(&chain); return QIHSE_AIMEM_WRITE_FAILED;
    }
    v->scope = *scope; v->type = type; v->status = status; v->revision = 1u;
    v->created_at_ms = v->valid_from_ingest_ms = aimem_now_ms();
    v->created_by = chain.owner_id;
    v->reviewed_by = status == QIHSE_AIMEM_KNOWLEDGE_APPROVED ? chain.owner_id : 0u;
    v->content = strdup(content);
    bool prepared = v->content && aimem_content_sha256(content, v->content_sha256) &&
        aimem_prepare_provenance(server, user, scope, provenance, NULL, v);
    char* encoded = v->content ? aimem_knowledge_chain_encode(&chain) : NULL;
    char key[128];
    bool keyed = encoded && aimem_knowledge_key(key, sizeof key, user, chain.knowledge_id);
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    qihse_kv_cas_result_t result = prepared && keyed && store ? qihse_kv_compare_set_user(
        store, key, NULL, encoded, qihse_user_get_classification(user),
        qihse_user_get_sci(user), user) : QIHSE_KV_CAS_FAILED;
    bool replay = false;
    bool existing_conflict = false;
    if (result != QIHSE_KV_CAS_UPDATED && idem) {
        char* raw = qihse_kv_get_user(store, key, user);
        aimem_knowledge_chain_t existing = {0};
        bool parsed_existing = raw && aimem_knowledge_chain_parse(raw, &existing);
        if (parsed_existing && existing.count >= 1u &&
            existing.type == type && aimem_scope_matches(&existing.scope, scope) &&
            strcmp(existing.versions[0].version_id, v->version_id) == 0 &&
            aimem_knowledge_payload_matches(&existing.versions[0], status, content, provenance)) {
            replay = aimem_knowledge_copy(&existing.versions[0], out);
        }
        existing_conflict = raw != NULL && !replay;
        free(raw); aimem_knowledge_chain_free(&existing);
    }
    bool copied = result == QIHSE_KV_CAS_UPDATED && aimem_knowledge_copy(v, out);
    if (copied) aimem_knowledge_audit(user,
        status == QIHSE_AIMEM_KNOWLEDGE_APPROVED ?
        "AIMEM_KNOWLEDGE_APPROVE" : "AIMEM_KNOWLEDGE_CREATE",
        v, qihse_user_get_classification(user), qihse_user_get_sci(user));
    free(encoded); aimem_knowledge_chain_free(&chain);
    if (copied) return QIHSE_AIMEM_WRITE_NEW;
    if (replay) return QIHSE_AIMEM_WRITE_REPLAY;
    return result == QIHSE_KV_CAS_MISMATCH || existing_conflict ?
        QIHSE_AIMEM_WRITE_CONFLICT : QIHSE_AIMEM_WRITE_FAILED;
}

qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_create(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, uint32_t type, uint32_t status,
        const char* content, qihse_ai_memory_knowledge_version_t* out) {
    return qihse_ai_memory_knowledge_create_ex(server, user, scope, type, status,
                                                content, NULL, out);
}

qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_revise_ex(
        qihse_resp_server_t* server, qihse_user_t* user,
        const char* knowledge_id, const char* expected_version_id,
        uint64_t expected_revision, uint32_t status, const char* content,
        const qihse_ai_memory_knowledge_provenance_t* provenance,
        qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    qihse_uuid_t parsed;
    if (!server || !user || !qihse_auth_user_is_active(user) || !knowledge_id ||
        !expected_version_id || !qihse_uuid_parse(expected_version_id, &parsed) ||
        !expected_revision || !aimem_knowledge_status_writable(user, status) ||
        !content || !*content || strlen(content) > AIMEM_KNOWLEDGE_MAX_CONTENT || !out ||
        (provenance && !aimem_idempotency_key_valid(provenance->idempotency_key)))
        return QIHSE_AIMEM_WRITE_FAILED;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    char key[128];
    if (!store || !aimem_knowledge_key(key, sizeof key, user, knowledge_id))
        return QIHSE_AIMEM_WRITE_FAILED;
    pthread_mutex_lock(&g_aimem_knowledge_lock);
    char* raw = qihse_kv_get_user(store, key, user);
    aimem_knowledge_chain_t chain;
    bool ok = raw && aimem_knowledge_chain_parse(raw, &chain);
    if (!ok || (chain.owner_id != qihse_user_get_id(user) &&
                qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR)) {
        free(raw); if (ok) aimem_knowledge_chain_free(&chain);
        pthread_mutex_unlock(&g_aimem_knowledge_lock); return QIHSE_AIMEM_WRITE_FAILED;
    }
    qihse_ai_memory_knowledge_version_t* prior = &chain.versions[chain.count - 1u];
    bool is_operator = qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR;
    const char* idem = provenance ? provenance->idempotency_key : NULL;
    char deterministic_id[QIHSE_AIMEM_ID_LEN + 1u] = {0};
    if (idem) {
        char seed[QIHSE_AIMEM_IDEM_MAX_LEN + 192u];
        int n = snprintf(seed, sizeof seed, "QIHSE:AIMEM:knowledge:revise:v2:%u:%s:%u:%s",
            (unsigned)qihse_user_get_tenant_id(user), knowledge_id,
            (unsigned)qihse_user_get_id(user), idem);
        qihse_uuid_t deterministic;
        if (n <= 0 || (size_t)n >= sizeof seed ||
            !qihse_uuid_from_seed(seed, (size_t)n, &deterministic) ||
            !qihse_uuid_format(&deterministic, deterministic_id)) {
            free(raw); aimem_knowledge_chain_free(&chain);
            pthread_mutex_unlock(&g_aimem_knowledge_lock); return QIHSE_AIMEM_WRITE_FAILED;
        }
        if (strcmp(prior->version_id, deterministic_id) == 0) {
            bool replay = prior->revision == expected_revision + 1u &&
                strcmp(prior->supersedes_version, expected_version_id) == 0 &&
                aimem_knowledge_payload_matches(prior, status, content, provenance) &&
                aimem_knowledge_copy(prior, out);
            free(raw); aimem_knowledge_chain_free(&chain);
            pthread_mutex_unlock(&g_aimem_knowledge_lock);
            return replay ? QIHSE_AIMEM_WRITE_REPLAY : QIHSE_AIMEM_WRITE_CONFLICT;
        }
    }
    if ((prior->status == QIHSE_AIMEM_KNOWLEDGE_APPROVED &&
         (!is_operator || (status != QIHSE_AIMEM_KNOWLEDGE_APPROVED &&
                           status != QIHSE_AIMEM_KNOWLEDGE_RETRACTED))) ||
        prior->status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED) {
        free(raw); aimem_knowledge_chain_free(&chain);
        pthread_mutex_unlock(&g_aimem_knowledge_lock); return QIHSE_AIMEM_WRITE_FAILED;
    }
    if (prior->revision != expected_revision ||
        strcmp(prior->version_id, expected_version_id) != 0 ||
        chain.count >= AIMEM_KNOWLEDGE_MAX_VERSIONS) {
        free(raw); aimem_knowledge_chain_free(&chain);
        pthread_mutex_unlock(&g_aimem_knowledge_lock); return QIHSE_AIMEM_WRITE_CONFLICT;
    }
    qihse_ai_memory_knowledge_version_t* grown = realloc(chain.versions,
        (chain.count + 1u) * sizeof(*chain.versions));
    if (!grown) {
        free(raw); aimem_knowledge_chain_free(&chain);
        pthread_mutex_unlock(&g_aimem_knowledge_lock); return QIHSE_AIMEM_WRITE_FAILED;
    }
    chain.versions = grown; prior = &chain.versions[chain.count - 1u];
    uint64_t boundary = aimem_now_ms();
    if (boundary <= prior->valid_from_ingest_ms) boundary = prior->valid_from_ingest_ms + 1u;
    prior->valid_to_ingest_ms = boundary;
    prior->status = QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED;
    qihse_ai_memory_knowledge_version_t* next = &chain.versions[chain.count];
    memset(next, 0, sizeof(*next));
    qihse_uuid_t version_uuid;
    ok = idem ? (snprintf(next->version_id, sizeof next->version_id, "%s",
                          deterministic_id) > 0) :
        (qihse_uuid_generate(&version_uuid) && qihse_uuid_format(&version_uuid, next->version_id));
    snprintf(next->knowledge_id, sizeof next->knowledge_id, "%s", chain.knowledge_id);
    snprintf(next->supersedes_version, sizeof next->supersedes_version, "%s", prior->version_id);
    next->scope = chain.scope; next->type = chain.type; next->status = status;
    next->revision = prior->revision + 1u; next->created_at_ms = boundary;
    next->valid_from_ingest_ms = boundary; next->created_by = qihse_user_get_id(user);
    next->reviewed_by = (status == QIHSE_AIMEM_KNOWLEDGE_APPROVED ||
                         status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED) ?
                        qihse_user_get_id(user) : 0u;
    next->content = ok ? strdup(content) : NULL;
    ok = next->content && aimem_content_sha256(content, next->content_sha256) &&
         aimem_prepare_provenance(server, user, &chain.scope, provenance,
                                  prior->version_id, next);
    chain.count++;
    char* encoded = next->content ? aimem_knowledge_chain_encode(&chain) : NULL;
    qihse_kv_record_meta_t meta;
    ok = encoded && qihse_kv_meta_user(store, key, user, &meta);
    qihse_kv_cas_result_t cas = ok ? qihse_kv_compare_set_user(store, key, raw,
        encoded, meta.classification, meta.sci_compartment, user) : QIHSE_KV_CAS_FAILED;
    bool copied = cas == QIHSE_KV_CAS_UPDATED && aimem_knowledge_copy(next, out);
    if (copied) aimem_knowledge_audit(user,
        status == QIHSE_AIMEM_KNOWLEDGE_APPROVED ?
        "AIMEM_KNOWLEDGE_APPROVE" : status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED ?
        "AIMEM_KNOWLEDGE_RETRACT" : "AIMEM_KNOWLEDGE_REVISE",
        next, meta.classification, meta.sci_compartment);
    free(encoded); free(raw); aimem_knowledge_chain_free(&chain);
    pthread_mutex_unlock(&g_aimem_knowledge_lock);
    if (copied) return QIHSE_AIMEM_WRITE_NEW;
    return cas == QIHSE_KV_CAS_MISMATCH ? QIHSE_AIMEM_WRITE_CONFLICT
                                         : QIHSE_AIMEM_WRITE_FAILED;
}

qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_revise(
        qihse_resp_server_t* server, qihse_user_t* user,
        const char* knowledge_id, const char* expected_version_id,
        uint64_t expected_revision, uint32_t status, const char* content,
        qihse_ai_memory_knowledge_version_t* out) {
    return qihse_ai_memory_knowledge_revise_ex(server, user, knowledge_id,
        expected_version_id, expected_revision, status, content, NULL, out);
}

bool qihse_ai_memory_knowledge_latest(qihse_resp_server_t* server,
        qihse_user_t* user, const char* knowledge_id,
        const qihse_ai_memory_scope_t* scope,
        qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    char* raw = NULL; aimem_knowledge_chain_t chain = {0};
    bool ok = out && aimem_knowledge_chain_read(server, user, knowledge_id,
                                                scope, &raw, &chain);
    if (ok) ok = aimem_knowledge_copy(&chain.versions[chain.count - 1u], out);
    free(raw);
    aimem_knowledge_chain_free(&chain);
    return ok;
}

bool qihse_ai_memory_knowledge_as_of(qihse_resp_server_t* server,
        qihse_user_t* user, const char* knowledge_id,
        const qihse_ai_memory_scope_t* scope, uint64_t ingestion_time_ms,
        qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    char* raw = NULL; aimem_knowledge_chain_t chain = {0};
    bool ok = out && ingestion_time_ms && aimem_knowledge_chain_read(
        server, user, knowledge_id, scope, &raw, &chain);
    const qihse_ai_memory_knowledge_version_t* selected = NULL;
    if (ok) for (size_t i = 0; i < chain.count; i++) {
        const qihse_ai_memory_knowledge_version_t* v = &chain.versions[i];
        if (v->valid_from_ingest_ms <= ingestion_time_ms &&
            (!v->valid_to_ingest_ms || ingestion_time_ms < v->valid_to_ingest_ms)) {
            selected = v; break;
        }
    }
    ok = selected && aimem_knowledge_copy(selected, out);
    free(raw);
    aimem_knowledge_chain_free(&chain);
    return ok;
}

typedef struct {
    qihse_resp_server_t* server;
    qihse_user_t* user;
    const char* version_id;
    const qihse_ai_memory_scope_t* scope;
    qihse_ai_memory_knowledge_version_t* out;
    bool found;
} aimem_knowledge_find_t;

static bool aimem_knowledge_find_cb(const char* key, const char* value, void* opaque) {
    (void)key;
    aimem_knowledge_find_t* find = (aimem_knowledge_find_t*)opaque;
    aimem_knowledge_chain_t chain;
    if (!aimem_knowledge_chain_parse(value, &chain)) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(find->server);
    bool scope_ok = aimem_scope_matches(&chain.scope, find->scope) &&
        aimem_scope_owner_allowed(store, find->user, chain.owner_id, find->scope);
    for (size_t i = 0; scope_ok && i < chain.count; i++) {
        if (strcmp(chain.versions[i].version_id, find->version_id) == 0) {
            find->found = aimem_knowledge_copy(&chain.versions[i], find->out);
            break;
        }
    }
    aimem_knowledge_chain_free(&chain);
    return !find->found;
}

bool qihse_ai_memory_knowledge_get(qihse_resp_server_t* server,
        qihse_user_t* user, const char* version_id,
        const qihse_ai_memory_scope_t* scope,
        qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    qihse_uuid_t parsed;
    if (!server || !user || !qihse_auth_user_is_active(user) || !version_id ||
        !qihse_uuid_parse(version_id, &parsed) || !aimem_scope_valid(scope) || !out)
        return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    char prefix[48];
    int n = snprintf(prefix, sizeof prefix, "t:%u/aimem-knowledge:",
                     (unsigned)qihse_user_get_tenant_id(user));
    if (!store || n <= 0 || (size_t)n >= sizeof prefix) return false;
    aimem_knowledge_find_t find = { server, user, version_id, scope, out, false };
    (void)qihse_kv_foreach_prefix_user(store, prefix, user,
                                       aimem_knowledge_find_cb, &find);
    return find.found;
}

/* ── QH-05..08: stable query projections and reversible operations ───── */

typedef struct {
    qihse_ai_memory_knowledge_version_t version;
    uint32_t owner_id;
    uint16_t classification;
    uint16_t sci;
    double lexical_score;
    double semantic_score;
    double ranking_score;
    uint32_t explain_flags;
} aimem_query_row_t;

struct qihse_ai_memory_query_snapshot {
    qihse_resp_server_t* server;
    uint32_t tenant_id;
    uint32_t user_id;
    qihse_ai_memory_scope_t scope;
    qihse_ai_memory_mode_t mode;
    aimem_query_row_t* rows;
    size_t count;
    size_t offset;
};

static uint64_t g_aimem_query_snapshots;
static uint64_t g_aimem_maintenance_versions;
static uint64_t g_aimem_exports;
static uint64_t g_aimem_imports;
static uint64_t g_aimem_rejected;
static uint64_t g_aimem_index_generation;

static void aimem_counter_inc(uint64_t* value) {
    (void)__atomic_add_fetch(value, 1u, __ATOMIC_RELAXED);
}

static bool aimem_contains_fold(const char* text, const char* needle) {
    if (!needle || !*needle) return true;
    if (!text) return false;
    size_t n = strlen(needle);
    for (const char* p = text; *p; p++) {
        size_t i = 0u;
        while (i < n && p[i] && tolower((unsigned char)p[i]) ==
               tolower((unsigned char)needle[i])) i++;
        if (i == n) return true;
    }
    return false;
}

static int aimem_query_row_compare(const void* a, const void* b) {
    const aimem_query_row_t* x = a;
    const aimem_query_row_t* y = b;
    if (x->version.valid_from_ingest_ms < y->version.valid_from_ingest_ms) return -1;
    if (x->version.valid_from_ingest_ms > y->version.valid_from_ingest_ms) return 1;
    return strcmp(x->version.version_id, y->version.version_id);
}

static int aimem_query_result_compare(const void* a, const void* b) {
    const aimem_query_row_t* x = a;
    const aimem_query_row_t* y = b;
    if (x->ranking_score > y->ranking_score) return -1;
    if (x->ranking_score < y->ranking_score) return 1;
    return aimem_query_row_compare(a, b);
}

typedef struct {
    qihse_resp_server_t* server;
    qihse_user_t* user;
    const qihse_ai_memory_query_v1_t* query;
    aimem_query_row_t* rows;
    size_t count;
    bool failed;
} aimem_query_build_t;

static bool aimem_query_build_cb(const char* key, const char* value, void* opaque) {
    aimem_query_build_t* b = opaque;
    aimem_knowledge_chain_t chain;
    if (!aimem_knowledge_chain_parse(value, &chain)) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(b->server);
    bool allowed = aimem_scope_matches(&chain.scope, &b->query->scope) &&
        aimem_scope_owner_allowed(store, b->user, chain.owner_id, &b->query->scope) &&
        (!b->query->type || b->query->type == chain.type);
    qihse_kv_record_meta_t meta;
    if (allowed) allowed = qihse_kv_meta_user(store, key, b->user, &meta);
    size_t first = 0u, last = chain.count;
    if (b->query->as_of_ingest_ms) {
        last = 0u;
        for (size_t i = 0u; i < chain.count; i++) {
            qihse_ai_memory_knowledge_version_t* v = &chain.versions[i];
            if (v->valid_from_ingest_ms <= b->query->as_of_ingest_ms &&
                (!v->valid_to_ingest_ms || b->query->as_of_ingest_ms < v->valid_to_ingest_ms)) {
                first = i; last = i + 1u; break;
            }
        }
    }
    for (size_t i = first; allowed && i < last; i++) {
        qihse_ai_memory_knowledge_version_t* v = &chain.versions[i];
        bool current = b->query->as_of_ingest_ms ? true : i + 1u == chain.count;
        if ((b->query->current_only && !current) ||
            (b->query->status && b->query->status != v->status) ||
            (b->query->ingest_from_ms && v->valid_from_ingest_ms < b->query->ingest_from_ms) ||
            (b->query->ingest_to_ms && v->valid_from_ingest_ms > b->query->ingest_to_ms) ||
            (b->query->changed_since_ms && v->valid_from_ingest_ms <= b->query->changed_since_ms) ||
            (b->query->mode == QIHSE_AIMEM_MODE_BM25 &&
             !aimem_contains_fold(v->content, b->query->text))) continue;
        if (b->count >= b->query->max_rows) { b->failed = true; break; }
        aimem_query_row_t* row = &b->rows[b->count];
        if (!aimem_knowledge_copy(v, &row->version)) { b->failed = true; break; }
        row->owner_id = chain.owner_id;
        row->classification = meta.classification;
        row->sci = meta.sci_compartment;
        row->lexical_score = 0.0;
        row->semantic_score = 0.0;
        row->ranking_score = 0.0;
        row->explain_flags = current ? QIHSE_AIMEM_QUERY_EXPLAIN_CURRENT : 0u;
        b->count++;
    }
    aimem_knowledge_chain_free(&chain);
    return !b->failed;
}

typedef struct { size_t index; double score; } aimem_query_rank_t;

static int aimem_query_rank_desc(const void* a, const void* b) {
    const aimem_query_rank_t* x = a;
    const aimem_query_rank_t* y = b;
    if (x->score > y->score) return -1;
    if (x->score < y->score) return 1;
    return x->index < y->index ? -1 : x->index > y->index ? 1 : 0;
}

static bool aimem_query_rank(aimem_query_row_t* rows, size_t count,
        const qihse_ai_memory_query_v1_t* query, qihse_user_t* user) {
    if (!count || !query->text || !*query->text) return true;
    bool want_lexical = query->mode != QIHSE_AIMEM_MODE_SEMANTIC;
    bool want_semantic = query->mode != QIHSE_AIMEM_MODE_BM25;
    aimem_query_rank_t* ranks = calloc(count, sizeof(*ranks));
    if (!ranks) return false;
    if (want_lexical) {
        qihse_fts_index_t* index = qihse_fts_create();
        bool ok = index != NULL;
        for (size_t i = 0; ok && i < count; i++)
            ok = qihse_fts_add_document_user(index, (uint64_t)i + 1u,
                rows[i].version.content, strlen(rows[i].version.content),
                rows[i].classification, rows[i].sci,
                QIHSE_KEYSTONE_CLASS_CORPORATE, user);
        qihse_fts_result_t* hits = ok ? calloc(count, sizeof(*hits)) : NULL;
        if (ok && !hits) ok = false;
        int found = ok ? qihse_fts_search_user(index, query->text, user, hits,
            count > INT_MAX ? INT_MAX : (int)count) : -1;
        if (found < 0) ok = false;
        for (int i = 0; ok && i < found; i++) {
            uint64_t id = hits[i].doc_id;
            if (!id || id > count) { ok = false; break; }
            aimem_query_row_t* row = &rows[id - 1u];
            row->lexical_score = hits[i].bm25_score;
            row->explain_flags |= QIHSE_AIMEM_QUERY_EXPLAIN_BM25 |
                                  QIHSE_AIMEM_QUERY_EXPLAIN_TEXT_MATCH;
            ranks[i].index = (size_t)(id - 1u);
            ranks[i].score = hits[i].bm25_score;
        }
        if (ok && !want_semantic)
            for (int i = 0; i < found; i++)
                rows[ranks[i].index].ranking_score = (double)(found - i);
        if (ok && want_semantic)
            for (int i = 0; i < found; i++)
                rows[ranks[i].index].ranking_score = 1.0 / (60.0 + (double)i + 1.0);
        free(hits); qihse_fts_destroy(index);
        if (!ok) { free(ranks); return false; }
    }
    if (want_semantic) {
        size_t dim = qihse_ai_memory_embedding_dim();
        float qvec[QIHSE_AIMEM_MAX_DIM];
        if (!dim || dim > QIHSE_AIMEM_MAX_DIM ||
            !qihse_ai_memory_embed_text(query->text, qvec, dim)) {
            free(ranks); return false;
        }
        for (size_t i = 0; i < count; i++) {
            float vec[QIHSE_AIMEM_MAX_DIM];
            if (!qihse_ai_memory_embed_text(rows[i].version.content, vec, dim)) {
                free(ranks); return false;
            }
            double dot = 0.0, qn = 0.0, vn = 0.0;
            for (size_t j = 0; j < dim; j++) {
                dot += (double)qvec[j] * vec[j];
                qn += (double)qvec[j] * qvec[j];
                vn += (double)vec[j] * vec[j];
            }
            rows[i].semantic_score = qn > 0.0 && vn > 0.0 ? dot / sqrt(qn * vn) : 0.0;
            rows[i].explain_flags |= QIHSE_AIMEM_QUERY_EXPLAIN_SEMANTIC;
            ranks[i].index = i; ranks[i].score = rows[i].semantic_score;
        }
        qsort(ranks, count, sizeof(*ranks), aimem_query_rank_desc);
        for (size_t i = 0; i < count; i++) {
            if (query->mode == QIHSE_AIMEM_MODE_HYBRID) {
                rows[ranks[i].index].ranking_score += 1.0 / (60.0 + (double)i + 1.0);
                rows[ranks[i].index].explain_flags |= QIHSE_AIMEM_QUERY_EXPLAIN_RRF;
            } else rows[ranks[i].index].ranking_score = (double)(count - i);
        }
    }
    free(ranks);
    return true;
}

qihse_ai_memory_query_snapshot_t* qihse_ai_memory_query_begin(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_query_v1_t* query) {
    if (!server || !user || !qihse_auth_user_is_active(user) || !query ||
        !aimem_scope_valid(&query->scope) || !query->max_rows ||
        query->max_rows > QIHSE_AIMEM_QUERY_MAX_ROWS ||
        (query->text && strlen(query->text) > QIHSE_AIMEM_QUERY_MAX_TEXT_BYTES) ||
        (query->mode != QIHSE_AIMEM_MODE_BM25 &&
         query->mode != QIHSE_AIMEM_MODE_SEMANTIC &&
         query->mode != QIHSE_AIMEM_MODE_HYBRID) ||
        (query->as_of_ingest_ms && (query->changed_since_ms ||
         query->ingest_from_ms || query->ingest_to_ms)) ||
        (query->type && !aimem_knowledge_type_valid(query->type)) ||
        (query->status && (query->status < QIHSE_AIMEM_KNOWLEDGE_PROPOSED ||
                           query->status > QIHSE_AIMEM_KNOWLEDGE_RETRACTED))) {
        aimem_counter_inc(&g_aimem_rejected); return NULL;
    }
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    qihse_ai_memory_query_snapshot_t* snap = calloc(1u, sizeof(*snap));
    if (!store || !snap) { free(snap); return NULL; }
    snap->rows = calloc(query->max_rows, sizeof(*snap->rows));
    if (!snap->rows) { free(snap); return NULL; }
    aimem_query_build_t build = { server, user, query, snap->rows, 0u, false };
    char prefix[48];
    int n = snprintf(prefix, sizeof prefix, "t:%u/aimem-knowledge:",
                     (unsigned)qihse_user_get_tenant_id(user));
    bool iterated = n > 0 && (size_t)n < sizeof prefix &&
        qihse_kv_foreach_prefix_user(store, prefix, user, aimem_query_build_cb, &build);
    if (!iterated || build.failed) {
        for (size_t i = 0; i < build.count; i++)
            qihse_ai_memory_knowledge_free(&snap->rows[i].version);
        free(snap->rows); free(snap); aimem_counter_inc(&g_aimem_rejected); return NULL;
    }
    if (!aimem_query_rank(snap->rows, build.count, query, user)) {
        for (size_t i = 0; i < build.count; i++)
            qihse_ai_memory_knowledge_free(&snap->rows[i].version);
        free(snap->rows); free(snap); aimem_counter_inc(&g_aimem_rejected); return NULL;
    }
    snap->server = server;
    snap->tenant_id = qihse_user_get_tenant_id(user);
    snap->user_id = qihse_user_get_id(user);
    snap->scope = query->scope;
    snap->mode = query->mode;
    snap->count = build.count;
    qsort(snap->rows, snap->count, sizeof(*snap->rows),
          query->text && *query->text ? aimem_query_result_compare : aimem_query_row_compare);
    aimem_counter_inc(&g_aimem_query_snapshots);
    return snap;
}

size_t qihse_ai_memory_query_next(qihse_ai_memory_query_snapshot_t* snap,
        qihse_user_t* user, qihse_ai_memory_query_hit_t* out, size_t out_cap) {
    if (!snap || !user || !out || !out_cap || !qihse_auth_user_is_active(user) ||
        qihse_user_get_tenant_id(user) != snap->tenant_id ||
        qihse_user_get_id(user) != snap->user_id) {
        aimem_counter_inc(&g_aimem_rejected); return 0u;
    }
    qihse_kv_store_t* store = qihse_resp_server_store(snap->server);
    size_t count = 0u;
    while (count < out_cap && snap->offset < snap->count) {
        aimem_query_row_t* row = &snap->rows[snap->offset];
        qihse_ai_memory_knowledge_version_t live;
        bool live_visible = qihse_ai_memory_knowledge_get(snap->server, user,
            row->version.version_id, &snap->scope, &live);
        if (!live_visible || !qihse_auth_can_access(user, row->classification, row->sci) ||
            !aimem_scope_owner_allowed(store, user, row->owner_id, &snap->scope)) {
            if (live_visible) qihse_ai_memory_knowledge_free(&live);
            aimem_counter_inc(&g_aimem_rejected); return 0u;
        }
        qihse_ai_memory_knowledge_free(&live);
        memset(&out[count], 0, sizeof(out[count]));
        if (!aimem_knowledge_copy(&row->version, &out[count].version)) break;
        qihse_ai_memory_knowledge_version_t* projected = &out[count].version;
        size_t relations_kept = 0u;
        for (size_t i = 0; i < projected->relation_count; i++) {
            qihse_ai_memory_knowledge_version_t target;
            if (!qihse_ai_memory_knowledge_get(snap->server, user,
                projected->relations[i].target_version_id,
                &projected->relations[i].target_scope, &target)) continue;
            qihse_ai_memory_knowledge_free(&target);
            if (relations_kept != i) projected->relations[relations_kept] = projected->relations[i];
            relations_kept++;
        }
        projected->relation_count = relations_kept;
        size_t sources_kept = 0u;
        for (size_t i = 0; i < projected->source_event_count; i++) {
            qihse_ai_memory_hit_t event;
            if (!qihse_ai_memory_event_get(snap->server, user,
                projected->source_event_ids[i], &projected->scope, &event)) continue;
            free(event.text);
            if (sources_kept != i)
                memcpy(projected->source_event_ids[sources_kept],
                    projected->source_event_ids[i], QIHSE_AIMEM_ID_LEN + 1u);
            sources_kept++;
        }
        projected->source_event_count = sources_kept;
        out[count].lexical_score = row->lexical_score;
        out[count].semantic_score = row->semantic_score;
        out[count].ranking_score = row->ranking_score;
        out[count].current = row->explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_CURRENT;
        out[count].ranking_mode = (uint32_t)snap->mode;
        out[count].explain_flags = row->explain_flags;
        count++; snap->offset++;
    }
    return count;
}

void qihse_ai_memory_query_hits_free(qihse_ai_memory_query_hit_t* hits,
                                      size_t count) {
    if (!hits) return;
    for (size_t i = 0; i < count; i++)
        qihse_ai_memory_knowledge_free(&hits[i].version);
}

void qihse_ai_memory_query_end(qihse_ai_memory_query_snapshot_t* snap) {
    if (!snap) return;
    for (size_t i = 0; i < snap->count; i++)
        qihse_ai_memory_knowledge_free(&snap->rows[i].version);
    free(snap->rows); free(snap);
}

#define AIMEM_MAINT_MAX_ENCODED (AIMEM_KNOWLEDGE_MAX_CONTENT * 4u + 1024u)

static bool aimem_sha256_hex(const void* data, size_t len, char out[65]);

static bool aimem_maintenance_key(char* out, size_t cap, qihse_user_t* user,
                                  const char* plan_id) {
    qihse_uuid_t id;
    if (!out || !user || !qihse_auth_user_is_active(user) ||
        !plan_id || !qihse_uuid_parse(plan_id, &id)) return false;
    int n = snprintf(out, cap, "t:%u/aimem-maint:%s",
        (unsigned)qihse_user_get_tenant_id(user), plan_id);
    return n > 0 && (size_t)n < cap;
}

void qihse_ai_memory_maintenance_free(qihse_ai_memory_maintenance_plan_t* plan) {
    if (!plan) return;
    free(plan->original_content); free(plan->replacement_content);
    memset(plan, 0, sizeof(*plan));
}

static char* aimem_maintenance_encode(const qihse_ai_memory_maintenance_plan_t* p,
                                      uint32_t owner_id) {
    char* a = aimem_hex_encode(p->original_content);
    char* b = aimem_hex_encode(p->replacement_content);
    if (!a || !b) { free(a); free(b); return NULL; }
    char* out = malloc(AIMEM_MAINT_MAX_ENCODED);
    if (out) {
        int n = snprintf(out, AIMEM_MAINT_MAX_ENCODED,
            "QHM2|%s|%s|%s|%s|%s|%s|%s|%u|%u|%s|%u|%u|%u|%u|%s|%s|%s|%s",
            p->plan_id, p->knowledge_id, p->source_version_id,
            p->output_version_id, p->scope.project, p->scope.worktree,
            p->scope.workstream, (unsigned)owner_id, (unsigned)p->state,
            p->scope.session, (unsigned)p->retention_tier, (unsigned)p->operation,
            (unsigned)p->classification, (unsigned)p->sci_compartment,
            p->source_content_sha256, p->replacement_content_sha256, a, b);
        if (n < 0 || (size_t)n >= AIMEM_MAINT_MAX_ENCODED) { free(out); out = NULL; }
    }
    free(a); free(b); return out;
}

static bool aimem_maintenance_parse(const char* raw,
        qihse_ai_memory_maintenance_plan_t* out, uint32_t* owner_id) {
    if (!raw || !out || !owner_id ||
        strnlen(raw, AIMEM_MAINT_MAX_ENCODED) >= AIMEM_MAINT_MAX_ENCODED) return false;
    memset(out, 0, sizeof(*out));
    char* copy = strdup(raw); if (!copy) return false;
    char* cur = copy; char* f[19];
    for (size_t i = 0; i < 19u; i++) f[i] = strsep(&cur, "|");
    bool v2 = f[0] && strcmp(f[0], "QHM2") == 0;
    bool fields_present = true;
    for (size_t i = 0; i < 19u; i++) if (!f[i]) fields_present = false;
    if (!v2) {
        free(copy);
        copy = strdup(raw);
        if (!copy) return false;
        cur = copy;
        for (size_t i = 0; i < 13u; i++) f[i] = strsep(&cur, "|");
        fields_present = true;
        for (size_t i = 0; i < 13u; i++) if (!f[i]) fields_present = false;
        f[13] = f[14] = f[15] = f[16] = f[17] = f[18] = NULL;
    }
    uint32_t state = 0u, owner = 0u, tier = 0u, operation = 0u,
        classification = 0u, sci = 0u; qihse_uuid_t id;
    bool ok = fields_present && cur == NULL && f[0] && strcmp(f[0], v2 ? "QHM2" : "QHM1") == 0 &&
        f[1] && qihse_uuid_parse(f[1], &id) && f[2] && qihse_uuid_parse(f[2], &id) &&
        f[3] && qihse_uuid_parse(f[3], &id) && f[4] && f[5] && f[6] && f[7] && f[10] &&
        (!*f[4] || qihse_uuid_parse(f[4], &id)) &&
        aimem_token_u32(f[8], &owner) && aimem_token_u32(f[9], &state) &&
        state >= QIHSE_AIMEM_MAINT_PLANNED && state <= QIHSE_AIMEM_MAINT_ROLLED_BACK;
    if (ok && v2) ok = aimem_token_u32(f[11], &tier) && tier >= QIHSE_AIMEM_RETENTION_WORKING && tier <= QIHSE_AIMEM_RETENTION_PINNED &&
        aimem_token_u32(f[12], &operation) && operation >= QIHSE_AIMEM_MAINT_REWRITE && operation <= QIHSE_AIMEM_MAINT_RETENTION_CHANGE &&
        aimem_token_u32(f[13], &classification) && classification <= UINT16_MAX &&
        aimem_token_u32(f[14], &sci) && sci <= UINT16_MAX && strlen(f[15]) == 64u && strlen(f[16]) == 64u;
    if (ok) {
        snprintf(out->plan_id, sizeof out->plan_id, "%s", f[1]);
        snprintf(out->knowledge_id, sizeof out->knowledge_id, "%s", f[2]);
        snprintf(out->source_version_id, sizeof out->source_version_id, "%s", f[3]);
        snprintf(out->output_version_id, sizeof out->output_version_id, "%s", f[4]);
        snprintf(out->scope.project, sizeof out->scope.project, "%s", f[5]);
        snprintf(out->scope.worktree, sizeof out->scope.worktree, "%s", f[6]);
        snprintf(out->scope.workstream, sizeof out->scope.workstream, "%s", f[7]);
        snprintf(out->scope.session, sizeof out->scope.session, "%s", f[10]);
        out->state = state; *owner_id = owner;
        out->retention_tier = v2 ? tier : QIHSE_AIMEM_RETENTION_WORKING;
        out->operation = v2 ? operation : QIHSE_AIMEM_MAINT_REWRITE;
        out->classification = v2 ? (uint16_t)classification : 0u;
        out->sci_compartment = v2 ? (uint16_t)sci : 0u;
        if (v2) {
            snprintf(out->source_content_sha256, sizeof out->source_content_sha256, "%s", f[15]);
            snprintf(out->replacement_content_sha256, sizeof out->replacement_content_sha256, "%s", f[16]);
        }
        out->original_content = aimem_hex_decode(f[v2 ? 17 : 11]);
        out->replacement_content = aimem_hex_decode(f[v2 ? 18 : 12]);
        ok = aimem_scope_valid(&out->scope) && out->original_content &&
             out->replacement_content;
        if (ok && !v2) {
            ok = aimem_sha256_hex(out->original_content, strlen(out->original_content), out->source_content_sha256) &&
                 aimem_sha256_hex(out->replacement_content, strlen(out->replacement_content), out->replacement_content_sha256);
        }
        if (ok && v2) {
            char digest[65];
            ok = aimem_sha256_hex(out->original_content, strlen(out->original_content), digest) &&
                 strcmp(digest, out->source_content_sha256) == 0 &&
                 aimem_sha256_hex(out->replacement_content, strlen(out->replacement_content), digest) &&
                 strcmp(digest, out->replacement_content_sha256) == 0;
            if (ok && (out->operation == QIHSE_AIMEM_MAINT_RETENTION_CHANGE ||
                       out->retention_tier == QIHSE_AIMEM_RETENTION_PINNED))
                ok = strcmp(out->original_content, out->replacement_content) == 0;
            if (ok && out->operation == QIHSE_AIMEM_MAINT_EXTRACTIVE)
                ok = strstr(out->original_content, out->replacement_content) != NULL;
        }
    }
    free(copy);
    if (!ok) qihse_ai_memory_maintenance_free(out);
    return ok;
}

static bool aimem_maintenance_copy(const qihse_ai_memory_maintenance_plan_t* in,
                                   qihse_ai_memory_maintenance_plan_t* out) {
    *out = *in;
    out->original_content = strdup(in->original_content);
    out->replacement_content = strdup(in->replacement_content);
    if (!out->original_content || !out->replacement_content) {
        qihse_ai_memory_maintenance_free(out); return false;
    }
    return true;
}

qihse_ai_memory_write_result_t qihse_ai_memory_maintenance_plan_ex(
        qihse_resp_server_t* server, qihse_user_t* user, const char* knowledge_id,
        const qihse_ai_memory_scope_t* scope, const char* replacement,
        uint32_t retention_tier, uint32_t operation, bool dry_run,
        qihse_ai_memory_maintenance_plan_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !knowledge_id || !scope || !replacement || !*replacement ||
        strlen(replacement) > AIMEM_KNOWLEDGE_MAX_CONTENT || !out ||
        retention_tier < QIHSE_AIMEM_RETENTION_WORKING ||
        retention_tier > QIHSE_AIMEM_RETENTION_PINNED ||
        operation < QIHSE_AIMEM_MAINT_REWRITE || operation > QIHSE_AIMEM_MAINT_RETENTION_CHANGE ||
        !qihse_ai_memory_project_owner_allowed(server, user, scope->project))
        return QIHSE_AIMEM_WRITE_FAILED;
    qihse_ai_memory_knowledge_version_t latest;
    if (!qihse_ai_memory_knowledge_latest(server, user, knowledge_id, scope, &latest))
        return QIHSE_AIMEM_WRITE_FAILED;
    char source_hash[65] = {0}, replacement_hash[65] = {0};
    bool ok = aimem_sha256_hex(latest.content, strlen(latest.content), source_hash) &&
        aimem_sha256_hex(replacement, strlen(replacement), replacement_hash);
    bool contradictory = false;
    for (size_t i = 0; i < latest.relation_count; i++)
        if (latest.relations[i].type == QIHSE_AIMEM_RELATION_CONTRADICTS)
            contradictory = true;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    char knowledge_key[128]; qihse_kv_record_meta_t source_meta;
    ok = ok && store && aimem_knowledge_key(knowledge_key, sizeof knowledge_key,
        user, knowledge_id) && qihse_kv_meta_user(store, knowledge_key, user, &source_meta);
    uint16_t joined_class = ok ? source_meta.classification : 0u;
    if (ok && qihse_user_get_classification(user) > joined_class)
        joined_class = qihse_user_get_classification(user);
    uint16_t joined_sci = ok ? (uint16_t)(source_meta.sci_compartment | qihse_user_get_sci(user)) : 0u;
    ok = ok && qihse_auth_can_access(user, joined_class, joined_sci) &&
        !contradictory &&
        (!(retention_tier == QIHSE_AIMEM_RETENTION_PINNED) ||
         (operation == QIHSE_AIMEM_MAINT_RETENTION_CHANGE && strcmp(latest.content, replacement) == 0)) &&
        (operation != QIHSE_AIMEM_MAINT_RETENTION_CHANGE || strcmp(latest.content, replacement) == 0) &&
        (operation != QIHSE_AIMEM_MAINT_EXTRACTIVE || strstr(latest.content, replacement) != NULL);
    char seed[512];
    int seed_len = ok ? snprintf(seed, sizeof seed,
        "QIHSE:AIMEM:maintenance:v2:%u:%u:%s:%s:%s:%s:%s:%u:%u:%s:%s",
        (unsigned)qihse_user_get_tenant_id(user), (unsigned)qihse_user_get_id(user),
        scope->project, scope->worktree, scope->workstream, scope->session,
        knowledge_id, retention_tier, operation, source_hash, replacement_hash) : -1;
    qihse_uuid_t uuid;
    ok = ok && seed_len > 0 && (size_t)seed_len < sizeof seed &&
        qihse_uuid_from_seed(seed, (size_t)seed_len, &uuid) &&
        qihse_uuid_format(&uuid, out->plan_id);
    snprintf(out->knowledge_id, sizeof out->knowledge_id, "%s", knowledge_id);
    snprintf(out->source_version_id, sizeof out->source_version_id, "%s", latest.version_id);
    out->scope = *scope; out->state = QIHSE_AIMEM_MAINT_PLANNED;
    out->retention_tier = retention_tier; out->operation = operation;
    out->classification = joined_class; out->sci_compartment = joined_sci;
    snprintf(out->source_content_sha256, sizeof out->source_content_sha256, "%s", source_hash);
    snprintf(out->replacement_content_sha256, sizeof out->replacement_content_sha256, "%s", replacement_hash);
    out->original_content = strdup(latest.content);
    out->replacement_content = strdup(replacement);
    qihse_ai_memory_knowledge_free(&latest);
    ok = ok && out->original_content && out->replacement_content;
    bool replayed = false;
    if (ok && !dry_run) {
        char key[128]; char* encoded = aimem_maintenance_encode(out, qihse_user_get_id(user));
        ok = encoded && aimem_maintenance_key(key, sizeof key, user, out->plan_id);
        bool replay = false;
        char* prior = ok ? qihse_kv_get_user(store, key, user) : NULL;
        if (prior) {
            replay = strcmp(prior, encoded) == 0;
            ok = replay;
        }
        free(prior);
        qihse_kv_cas_result_t cas = QIHSE_KV_CAS_FAILED;
        if (ok && !replay) {
            cas = qihse_kv_compare_set_user(store, key, NULL, encoded,
                joined_class, joined_sci, user);
            /* A concurrent creator can win between our authorized lookup
             * and create-if-absent CAS. Resolve only an exact durable replay. */
            if (cas != QIHSE_KV_CAS_UPDATED) {
                prior = qihse_kv_get_user(store, key, user);
                replay = prior && strcmp(prior, encoded) == 0;
                free(prior);
            }
        }
        if ((cas == QIHSE_KV_CAS_UPDATED || replay) && !qihse_kv_sync_store(store))
            ok = false;
        ok = ok && (cas == QIHSE_KV_CAS_UPDATED || replay);
        replayed = replay;
        free(encoded);
    }
    if (!ok) { qihse_ai_memory_maintenance_free(out); return QIHSE_AIMEM_WRITE_FAILED; }
    return replayed ? QIHSE_AIMEM_WRITE_REPLAY : QIHSE_AIMEM_WRITE_NEW;
}

qihse_ai_memory_write_result_t qihse_ai_memory_maintenance_plan(
        qihse_resp_server_t* server, qihse_user_t* user, const char* knowledge_id,
        const qihse_ai_memory_scope_t* scope, const char* replacement,
        bool dry_run, qihse_ai_memory_maintenance_plan_t* out) {
    return qihse_ai_memory_maintenance_plan_ex(server, user, knowledge_id, scope,
        replacement, QIHSE_AIMEM_RETENTION_WORKING, QIHSE_AIMEM_MAINT_REWRITE,
        dry_run, out);
}

static bool aimem_maintenance_read(qihse_resp_server_t* server, qihse_user_t* user,
        const char* plan_id, char** raw, qihse_ai_memory_maintenance_plan_t* plan,
        uint32_t* owner) {
    char key[128]; qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store || !aimem_maintenance_key(key, sizeof key, user, plan_id)) return false;
    *raw = qihse_kv_get_user(store, key, user);
    bool ok = *raw && aimem_maintenance_parse(*raw, plan, owner) &&
        (*owner == qihse_user_get_id(user) || qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR);
    if (ok) {
        qihse_kv_record_meta_t meta;
        ok = qihse_kv_meta_user(store, key, user, &meta);
        if (ok && strncmp(*raw, "QHM2|", 5u) == 0)
            ok = meta.classification == plan->classification &&
                 meta.sci_compartment == plan->sci_compartment;
        else if (ok) {
            plan->classification = meta.classification;
            plan->sci_compartment = meta.sci_compartment;
        }
    }
    if (!ok && *raw) { free(*raw); *raw = NULL; qihse_ai_memory_maintenance_free(plan); }
    return ok;
}

static qihse_ai_memory_write_result_t aimem_maintenance_transition(
        qihse_resp_server_t* server, qihse_user_t* user, const char* plan_id,
        bool rollback, qihse_ai_memory_maintenance_plan_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !plan_id || !out) return QIHSE_AIMEM_WRITE_FAILED;
    char* raw = NULL; uint32_t owner = 0u;
    qihse_ai_memory_maintenance_plan_t plan = {0};
    bool ok = aimem_maintenance_read(server, user, plan_id, &raw, &plan, &owner);
    uint32_t wanted = rollback ? QIHSE_AIMEM_MAINT_ROLLED_BACK : QIHSE_AIMEM_MAINT_APPLIED;
    if (ok && plan.state == wanted) {
        ok = aimem_maintenance_copy(&plan, out);
        if (ok) ok = qihse_kv_sync_store(qihse_resp_server_store(server));
        free(raw); qihse_ai_memory_maintenance_free(&plan);
        return ok ? QIHSE_AIMEM_WRITE_REPLAY : QIHSE_AIMEM_WRITE_FAILED;
    }
    if (!ok || (rollback && plan.state != QIHSE_AIMEM_MAINT_APPLIED) ||
        (!rollback && plan.state != QIHSE_AIMEM_MAINT_PLANNED)) goto done;
    qihse_ai_memory_knowledge_version_t latest = {0}, next = {0};
    ok = qihse_ai_memory_knowledge_latest(server, user, plan.knowledge_id,
                                           &plan.scope, &latest);
    const char* expected = rollback ? plan.output_version_id : plan.source_version_id;
    const char* content = rollback ? plan.original_content : plan.replacement_content;
    char actual_hash[65];
    const char* expected_hash = rollback ? plan.replacement_content_sha256 : plan.source_content_sha256;
    const char* result_hash = rollback ? plan.source_content_sha256 : plan.replacement_content_sha256;
    if (ok) ok = aimem_sha256_hex(latest.content, strlen(latest.content), actual_hash);
    bool at_expected_head = ok && strcmp(latest.version_id, expected) == 0 &&
        strcmp(actual_hash, expected_hash) == 0;
    bool already_transitioned = ok && strcmp(latest.content, content) == 0 &&
        strcmp(latest.supersedes_version, expected) == 0 && strcmp(actual_hash, result_hash) == 0;
    if (at_expected_head) {
        ok = qihse_ai_memory_knowledge_revise(server, user, plan.knowledge_id,
            latest.version_id, latest.revision, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
            content, &next) == QIHSE_AIMEM_WRITE_NEW;
    } else if (already_transitioned) {
        ok = aimem_knowledge_copy(&latest, &next);
    } else ok = false;
    qihse_ai_memory_knowledge_free(&latest);
    if (!ok) { qihse_ai_memory_knowledge_free(&next); goto done; }
    if (!rollback) snprintf(plan.output_version_id, sizeof plan.output_version_id,
                            "%s", next.version_id);
    plan.state = wanted;
    char key[128]; char* encoded = aimem_maintenance_encode(&plan, owner);
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    qihse_kv_record_meta_t meta;
    ok = encoded && aimem_maintenance_key(key, sizeof key, user, plan_id) &&
         qihse_kv_meta_user(store, key, user, &meta) &&
         qihse_kv_compare_set_user(store, key, raw, encoded, meta.classification,
             meta.sci_compartment, user) == QIHSE_KV_CAS_UPDATED;
    if (ok) ok = qihse_kv_sync_store(store);
    free(encoded); qihse_ai_memory_knowledge_free(&next);
    if (ok) { aimem_counter_inc(&g_aimem_maintenance_versions); ok = aimem_maintenance_copy(&plan, out); }
done:
    free(raw); qihse_ai_memory_maintenance_free(&plan);
    return ok ? QIHSE_AIMEM_WRITE_NEW : QIHSE_AIMEM_WRITE_FAILED;
}

qihse_ai_memory_write_result_t qihse_ai_memory_maintenance_apply(
        qihse_resp_server_t* server, qihse_user_t* user, const char* plan_id,
        qihse_ai_memory_maintenance_plan_t* out) {
    return aimem_maintenance_transition(server, user, plan_id, false, out);
}

qihse_ai_memory_write_result_t qihse_ai_memory_maintenance_rollback(
        qihse_resp_server_t* server, qihse_user_t* user, const char* plan_id,
        qihse_ai_memory_maintenance_plan_t* out) {
    return aimem_maintenance_transition(server, user, plan_id, true, out);
}

typedef struct { char* raw; uint16_t classification, sci; char id[37]; } aimem_export_row_t;
typedef struct {
    qihse_resp_server_t* server; qihse_user_t* user;
    const qihse_ai_memory_scope_t* scope;
    aimem_export_row_t* rows; size_t count, cap; bool failed;
} aimem_export_build_t;

static bool aimem_export_collect_cb(const char* key, const char* value, void* opaque) {
    aimem_export_build_t* b = opaque; aimem_knowledge_chain_t chain;
    if (!aimem_knowledge_chain_parse(value, &chain)) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(b->server);
    bool include = aimem_scope_matches(&chain.scope, b->scope) &&
        aimem_scope_owner_allowed(store, b->user, chain.owner_id, b->scope);
    qihse_kv_record_meta_t meta;
    if (include) include = qihse_kv_meta_user(store, key, b->user, &meta);
    if (include) {
        if (b->count == b->cap) {
            size_t cap = b->cap ? b->cap * 2u : 8u;
            aimem_export_row_t* rows = realloc(b->rows, cap * sizeof(*rows));
            if (!rows) b->failed = true; else { b->rows = rows; b->cap = cap; }
        }
        if (!b->failed) {
            aimem_export_row_t* row = &b->rows[b->count]; memset(row, 0, sizeof(*row));
            row->raw = strdup(value); row->classification = meta.classification;
            row->sci = meta.sci_compartment;
            snprintf(row->id, sizeof row->id, "%s", chain.knowledge_id);
            if (!row->raw) b->failed = true; else b->count++;
        }
    }
    aimem_knowledge_chain_free(&chain); return !b->failed;
}

static int aimem_export_row_compare(const void* a, const void* b) {
    return strcmp(((const aimem_export_row_t*)a)->id,
                  ((const aimem_export_row_t*)b)->id);
}

static bool aimem_sha256_hex(const void* data, size_t len, char out[65]) {
    unsigned char digest[32]; unsigned int n = 0u;
    if (EVP_Digest(data, len, digest, &n, EVP_sha256(), NULL) != 1 || n != 32u)
        return false;
    for (size_t i = 0; i < 32u; i++) {
        out[i * 2u] = aimem_hex_digit(digest[i] >> 4);
        out[i * 2u + 1u] = aimem_hex_digit(digest[i] & 15u);
    }
    out[64] = '\0'; return true;
}

bool qihse_ai_memory_export_scope(qihse_resp_server_t* server,
        qihse_user_t* user, const qihse_ai_memory_scope_t* scope,
        qihse_ai_memory_export_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !out) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    aimem_export_build_t b = { server, user, scope, NULL, 0u, 0u, false };
    char prefix[48]; int pn = snprintf(prefix, sizeof prefix, "t:%u/aimem-knowledge:",
        (unsigned)qihse_user_get_tenant_id(user));
    bool ok = store && pn > 0 && (size_t)pn < sizeof prefix &&
        qihse_kv_foreach_prefix_user(store, prefix, user, aimem_export_collect_cb, &b) && !b.failed;
    qsort(b.rows, b.count, sizeof(*b.rows), aimem_export_row_compare);
    size_t cap = 512u;
    for (size_t i = 0; ok && i < b.count; i++) {
        size_t n = strlen(b.rows[i].raw);
        if (n > AIMEM_KNOWLEDGE_MAX_ENCODED || cap > SIZE_MAX - n * 2u - 64u) ok = false;
        else cap += n * 2u + 64u;
    }
    char* blob = ok ? malloc(cap + 66u) : NULL; size_t used = 0u;
#define EAPPEND(...) do { int z = snprintf(blob + used, cap + 66u - used, __VA_ARGS__); if (z < 0 || (size_t)z >= cap + 66u - used) { ok = false; } else used += (size_t)z; } while (0)
    if (blob) EAPPEND("QAX1|%u|%s|%s|%s|%s|%zu", (unsigned)qihse_user_get_tenant_id(user),
        scope->project, scope->worktree, scope->workstream, scope->session, b.count);
    else ok = false;
    for (size_t i = 0; ok && i < b.count; i++) {
        char* hex = aimem_hex_encode(b.rows[i].raw);
        if (!hex) { ok = false; break; }
        EAPPEND("|%u|%u|%s", (unsigned)b.rows[i].classification,
                (unsigned)b.rows[i].sci, hex); free(hex);
    }
    char digest[65];
    if (ok) ok = aimem_sha256_hex(blob, used, digest);
    if (ok) EAPPEND("|%s", digest);
#undef EAPPEND
    for (size_t i = 0; i < b.count; i++) free(b.rows[i].raw);
    free(b.rows);
    if (!ok) { free(blob); return false; }
    out->data = (uint8_t*)blob; out->len = used;
    aimem_counter_inc(&g_aimem_exports); return true;
}

void qihse_ai_memory_export_free(qihse_ai_memory_export_t* value) {
    if (!value) return;
    free(value->data);
    memset(value, 0, sizeof(*value));
}

qihse_ai_memory_import_result_t qihse_ai_memory_import_scope(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const uint8_t* data, size_t len,
        bool dry_run, size_t* out_imported) {
    if (out_imported) *out_imported = 0u;
    if (!server || !user || !qihse_auth_user_is_active(user) || !scope ||
        !aimem_scope_valid(scope) || !data || !len || len > 16u * 1024u * 1024u ||
        !qihse_ai_memory_project_owner_allowed(server, user, scope->project))
        return QIHSE_AIMEM_IMPORT_FAILED;
    char* copy = malloc(len + 1u); if (!copy) return QIHSE_AIMEM_IMPORT_FAILED;
    memcpy(copy, data, len); copy[len] = '\0';
    char* last = strrchr(copy, '|'); char digest[65];
    bool ok = last && strlen(last + 1u) == 64u &&
        aimem_sha256_hex(copy, (size_t)(last - copy), digest) &&
        strcmp(digest, last + 1u) == 0;
    if (last) *last = '\0';
    char* cur = copy; char* magic = strsep(&cur, "|"); char* tenant = strsep(&cur, "|");
    char* project = strsep(&cur, "|"); char* tree = strsep(&cur, "|");
    char* stream = strsep(&cur, "|"); char* session = strsep(&cur, "|");
    char* count_text = strsep(&cur, "|"); uint32_t tenant_id = 0u; uint64_t count64 = 0u;
    ok = ok && magic && strcmp(magic, "QAX1") == 0 &&
        aimem_token_u32(tenant, &tenant_id) && tenant_id == qihse_user_get_tenant_id(user) &&
        project && tree && stream && session && count_text &&
        strcmp(project, scope->project) == 0 && strcmp(tree, scope->worktree) == 0 &&
        strcmp(stream, scope->workstream) == 0 && strcmp(session, scope->session) == 0 &&
        aimem_token_u64(count_text, &count64) && count64 <= QIHSE_AIMEM_QUERY_MAX_ROWS;
    size_t count = (size_t)count64;
    aimem_export_row_t* rows = ok ? calloc(count ? count : 1u, sizeof(*rows)) : NULL;
    if (ok && !rows) ok = false;
    for (size_t i = 0; ok && i < count; i++) {
        char* cls = strsep(&cur, "|"); char* sci = strsep(&cur, "|");
        char* hex = strsep(&cur, "|"); uint32_t c = 0u, s = 0u;
        ok = cls && sci && hex && aimem_token_u32(cls, &c) && c <= UINT16_MAX &&
            aimem_token_u32(sci, &s) && s <= UINT16_MAX &&
            qihse_auth_can_access(user, (uint16_t)c, (uint16_t)s);
        if (ok) rows[i].raw = aimem_hex_decode(hex);
        rows[i].classification = (uint16_t)c; rows[i].sci = (uint16_t)s;
        aimem_knowledge_chain_t chain = {0};
        if (ok) {
            ok = rows[i].raw && aimem_knowledge_chain_parse(rows[i].raw, &chain) &&
                aimem_scope_matches(&chain.scope, scope) &&
                (chain.owner_id == qihse_user_get_id(user) ||
                 qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR);
            qihse_user_t* owner = ok ? qihse_auth_get_user(chain.owner_id) : NULL;
            ok = ok && owner && qihse_auth_user_is_active(owner) &&
                qihse_user_get_tenant_id(owner) == tenant_id;
        }
        if (ok) snprintf(rows[i].id, sizeof rows[i].id, "%s", chain.knowledge_id);
        aimem_knowledge_chain_free(&chain);
    }
    ok = ok && cur == NULL;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    bool conflict = false;
    for (size_t i = 0; ok && i < count; i++) {
        char key[128]; ok = aimem_knowledge_key(key, sizeof key, user, rows[i].id);
        char* existing = ok ? qihse_kv_get_user(store, key, user) : NULL;
        if (existing && strcmp(existing, rows[i].raw) != 0) conflict = true;
        free(existing);
    }
    if (ok && !conflict && !dry_run) for (size_t i = 0; i < count; i++) {
        char key[128]; (void)aimem_knowledge_key(key, sizeof key, user, rows[i].id);
        qihse_kv_cas_result_t r = qihse_kv_compare_set_user(store, key, NULL,
            rows[i].raw, rows[i].classification, rows[i].sci, user);
        if (r == QIHSE_KV_CAS_MISMATCH) {
            char* existing = qihse_kv_get_user(store, key, user);
            bool same = existing && strcmp(existing, rows[i].raw) == 0; free(existing);
            if (!same) { conflict = true; break; }
        } else if (r != QIHSE_KV_CAS_UPDATED) { ok = false; break; }
        if (out_imported) (*out_imported)++;
    }
    for (size_t i = 0; i < count; i++) free(rows ? rows[i].raw : NULL);
    free(rows); free(copy);
    if (!ok) { aimem_counter_inc(&g_aimem_rejected); return QIHSE_AIMEM_IMPORT_FAILED; }
    if (conflict) return QIHSE_AIMEM_IMPORT_CONFLICT;
    if (!dry_run) aimem_counter_inc(&g_aimem_imports);
    return dry_run ? QIHSE_AIMEM_IMPORT_VALID : QIHSE_AIMEM_IMPORT_APPLIED;
}

typedef struct {
    char kind;
    char key[128];
    char* raw;
    uint16_t classification;
    uint16_t sci;
} aimem_archive_row_t;

typedef struct {
    qihse_resp_server_t* server;
    qihse_user_t* user;
    const qihse_ai_memory_scope_t* scope;
    aimem_archive_row_t* rows;
    size_t count;
    size_t cap;
    size_t raw_bytes;
    bool failed;
} aimem_archive_build_t;

static bool aimem_archive_push(aimem_archive_build_t* b, char kind,
        const char* key, const char* raw, uint16_t classification, uint16_t sci) {
    size_t n = raw ? strlen(raw) : 0u;
    if (!b || !key || !n || b->count >= QIHSE_AIMEM_ARCHIVE_MAX_RECORDS ||
        n > QIHSE_AIMEM_ARCHIVE_MAX_BYTES ||
        b->raw_bytes > QIHSE_AIMEM_ARCHIVE_MAX_BYTES - n) return false;
    if (b->count == b->cap) {
        size_t next = b->cap ? b->cap * 2u : 16u;
        if (next > QIHSE_AIMEM_ARCHIVE_MAX_RECORDS)
            next = QIHSE_AIMEM_ARCHIVE_MAX_RECORDS;
        aimem_archive_row_t* rows = realloc(b->rows, next * sizeof(*rows));
        if (!rows) return false;
        b->rows = rows; b->cap = next;
    }
    aimem_archive_row_t* row = &b->rows[b->count];
    memset(row, 0, sizeof(*row));
    row->kind = kind; row->raw = strdup(raw);
    if (!row->raw || snprintf(row->key, sizeof row->key, "%s", key) <= 0) {
        free(row->raw); row->raw = NULL; return false;
    }
    row->classification = classification; row->sci = sci;
    b->raw_bytes += n; b->count++;
    return true;
}

static bool aimem_archive_knowledge_cb(const char* key, const char* value,
                                       void* opaque) {
    aimem_archive_build_t* b = opaque;
    aimem_knowledge_chain_t chain = {0};
    if (!aimem_knowledge_chain_parse(value, &chain)) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(b->server);
    qihse_kv_record_meta_t meta;
    bool include = aimem_scope_matches(&chain.scope, b->scope) &&
        aimem_scope_owner_allowed(store, b->user, chain.owner_id, b->scope) &&
        qihse_kv_meta_user(store, key, b->user, &meta);
    if (include && !aimem_archive_push(b, 'K', key, value,
                                       meta.classification, meta.sci_compartment))
        b->failed = true;
    aimem_knowledge_chain_free(&chain);
    return !b->failed;
}

static bool aimem_archive_event_cb(const char* key, const char* value,
                                   void* opaque) {
    aimem_archive_build_t* b = opaque;
    qihse_ai_memory_hit_t hit = {0}; aimem_record_meta_t meta;
    if (!aimem_parse_record_meta(value, &hit, &meta)) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(b->server);
    bool include = hit.kind == QIHSE_AIMEM_EVENT &&
        aimem_event_envelope_valid(hit.text, NULL, NULL) &&
        aimem_scope_matches(&meta.scope, b->scope) &&
        aimem_scope_owner_allowed(store, b->user, meta.owner_id, b->scope);
    qihse_kv_record_meta_t labels;
    if (include) include = qihse_kv_meta_user(store, key, b->user, &labels);
    if (include) include = hit.classification == labels.classification &&
                           hit.sci_compartment == labels.sci_compartment;
    if (include && !aimem_archive_push(b, 'E', key, value,
                                       labels.classification, labels.sci_compartment))
        b->failed = true;
    free(hit.text);
    return !b->failed;
}

static int aimem_archive_row_compare(const void* left, const void* right) {
    const aimem_archive_row_t* a = left; const aimem_archive_row_t* b = right;
    if (a->kind != b->kind) return (int)a->kind - (int)b->kind;
    return strcmp(a->key, b->key);
}

static char* aimem_archive_hex_encode(const char* value) {
    size_t n = value ? strlen(value) : 0u;
    if (!n || n > QIHSE_AIMEM_ARCHIVE_MAX_BYTES || n > (SIZE_MAX - 1u) / 2u)
        return NULL;
    char* hex = malloc(n * 2u + 1u); if (!hex) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)value[i];
        hex[i * 2u] = aimem_hex_digit(c >> 4);
        hex[i * 2u + 1u] = aimem_hex_digit(c & 15u);
    }
    hex[n * 2u] = '\0'; return hex;
}

static char* aimem_archive_hex_decode(const char* hex) {
    size_t n = hex ? strlen(hex) : 0u;
    if (!n || (n & 1u) || n / 2u > QIHSE_AIMEM_ARCHIVE_MAX_BYTES) return NULL;
    char* value = malloc(n / 2u + 1u); if (!value) return NULL;
    for (size_t i = 0; i < n; i += 2u) {
        int hi = aimem_hex_value(hex[i]), lo = aimem_hex_value(hex[i + 1u]);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) { free(value); return NULL; }
        value[i / 2u] = (char)((hi << 4) | lo);
    }
    value[n / 2u] = '\0'; return value;
}

static bool aimem_archive_hmac(const uint8_t* key, size_t key_len,
        const void* data, size_t len, char out[65]) {
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int n = 0u;
    if (!key || key_len < 16u || key_len > 128u || !data ||
        !HMAC(EVP_sha256(), key, (int)key_len, data, len, digest, &n) || n != 32u)
        return false;
    for (size_t i = 0; i < 32u; i++) {
        out[i * 2u] = aimem_hex_digit(digest[i] >> 4);
        out[i * 2u + 1u] = aimem_hex_digit(digest[i] & 15u);
    }
    out[64] = '\0'; return true;
}

bool qihse_ai_memory_export_authenticated(qihse_resp_server_t* server,
        qihse_user_t* user, const qihse_ai_memory_scope_t* scope,
        const uint8_t* authentication_key, size_t authentication_key_len,
        qihse_ai_memory_export_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !authentication_key ||
        authentication_key_len < 16u || authentication_key_len > 128u || !out)
        return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    aimem_archive_build_t b = { .server = server, .user = user, .scope = scope };
    char knowledge_prefix[48], event_prefix[32];
    int kn = snprintf(knowledge_prefix, sizeof knowledge_prefix,
        "t:%u/aimem-knowledge:", (unsigned)qihse_user_get_tenant_id(user));
    int en = snprintf(event_prefix, sizeof event_prefix, "t:%u/aimem:",
        (unsigned)qihse_user_get_tenant_id(user));
    bool ok = store && kn > 0 && (size_t)kn < sizeof knowledge_prefix &&
        en > 0 && (size_t)en < sizeof event_prefix &&
        qihse_kv_foreach_prefix_user(store, knowledge_prefix, user,
                                     aimem_archive_knowledge_cb, &b) && !b.failed &&
        qihse_kv_foreach_prefix_user(store, event_prefix, user,
                                     aimem_archive_event_cb, &b) && !b.failed;
    qsort(b.rows, b.count, sizeof(*b.rows), aimem_archive_row_compare);
    size_t cap = 512u;
    for (size_t i = 0; ok && i < b.count; i++) {
        size_t n = strlen(b.rows[i].raw);
        if (n > (QIHSE_AIMEM_ARCHIVE_MAX_BYTES - 192u) / 2u ||
            cap > QIHSE_AIMEM_ARCHIVE_MAX_BYTES - (n * 2u + 192u)) ok = false;
        else cap += n * 2u + 192u;
    }
    char* blob = ok && cap + 66u <= QIHSE_AIMEM_ARCHIVE_MAX_BYTES ?
        malloc(cap + 66u) : NULL;
    size_t used = 0u;
#define AAPPEND(...) do { int z = snprintf(blob + used, cap + 66u - used, __VA_ARGS__); \
    if (z < 0 || (size_t)z >= cap + 66u - used) ok = false; else used += (size_t)z; } while (0)
    if (blob) AAPPEND("QAX2|%u|%u|%s|%s|%s|%s|%zu",
        (unsigned)qihse_user_get_tenant_id(user), (unsigned)qihse_user_get_id(user),
        scope->project, scope->worktree, scope->workstream, scope->session, b.count);
    else ok = false;
    for (size_t i = 0; ok && i < b.count; i++) {
        char* hex = aimem_archive_hex_encode(b.rows[i].raw);
        if (!hex) { ok = false; break; }
        AAPPEND("|%c|%u|%u|1|%s", b.rows[i].kind,
            (unsigned)b.rows[i].classification, (unsigned)b.rows[i].sci, hex);
        free(hex);
    }
    char tag[65];
    if (ok) ok = aimem_archive_hmac(authentication_key, authentication_key_len,
                                     blob, used, tag);
    if (ok) AAPPEND("|%s", tag);
#undef AAPPEND
    for (size_t i = 0; i < b.count; i++) free(b.rows[i].raw);
    free(b.rows);
    if (!ok || used > QIHSE_AIMEM_ARCHIVE_MAX_BYTES) { free(blob); return false; }
    out->data = (uint8_t*)blob; out->len = used;
    aimem_counter_inc(&g_aimem_exports); return true;
}

bool qihse_ai_memory_export_stream(qihse_resp_server_t* server,
        qihse_user_t* user, const qihse_ai_memory_scope_t* scope,
        const uint8_t* authentication_key, size_t authentication_key_len,
        size_t chunk_size, qihse_ai_memory_archive_write_fn write_fn,
        void* write_ctx, size_t* out_bytes) {
    if (out_bytes) *out_bytes = 0u;
    if (!write_fn || !chunk_size || chunk_size > QIHSE_AIMEM_ARCHIVE_CHUNK_MAX)
        return false;
    qihse_ai_memory_export_t archive = {0};
    if (!qihse_ai_memory_export_authenticated(server, user, scope,
            authentication_key, authentication_key_len, &archive)) return false;
    bool ok = true;
    for (size_t at = 0; ok && at < archive.len; at += chunk_size) {
        size_t n = archive.len - at; if (n > chunk_size) n = chunk_size;
        ok = write_fn(write_ctx, archive.data + at, n);
    }
    if (ok && out_bytes) *out_bytes = archive.len;
    qihse_ai_memory_export_free(&archive); return ok;
}

qihse_ai_memory_import_result_t qihse_ai_memory_import_authenticated(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const uint8_t* authentication_key,
        size_t authentication_key_len, const uint8_t* data, size_t len,
        bool dry_run, size_t* out_imported) {
    if (out_imported) *out_imported = 0u;
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !authentication_key ||
        authentication_key_len < 16u || authentication_key_len > 128u ||
        !data || !len || len > QIHSE_AIMEM_ARCHIVE_MAX_BYTES ||
        !qihse_ai_memory_project_owner_allowed(server, user, scope->project))
        return QIHSE_AIMEM_IMPORT_FAILED;
    char* copy = malloc(len + 1u); if (!copy) return QIHSE_AIMEM_IMPORT_FAILED;
    memcpy(copy, data, len); copy[len] = '\0';
    char* last = strrchr(copy, '|'); char expected[65];
    bool ok = last && strlen(last + 1u) == 64u &&
        aimem_archive_hmac(authentication_key, authentication_key_len, copy,
                           (size_t)(last - copy), expected) &&
        CRYPTO_memcmp(expected, last + 1u, 64u) == 0;
    if (last) *last = '\0';
    char* cur = copy; char* magic = strsep(&cur, "|"); char* tenant = strsep(&cur, "|");
    char* actor = strsep(&cur, "|"); char* project = strsep(&cur, "|");
    char* tree = strsep(&cur, "|"); char* stream = strsep(&cur, "|");
    char* session = strsep(&cur, "|"); char* count_text = strsep(&cur, "|");
    uint32_t tenant_id = 0u, actor_id = 0u; uint64_t count64 = 0u;
    ok = ok && magic && strcmp(magic, "QAX2") == 0 &&
        aimem_token_u32(tenant, &tenant_id) &&
        tenant_id == qihse_user_get_tenant_id(user) &&
        aimem_token_u32(actor, &actor_id) &&
        project && tree && stream && session && count_text &&
        strcmp(project, scope->project) == 0 && strcmp(tree, scope->worktree) == 0 &&
        strcmp(stream, scope->workstream) == 0 && strcmp(session, scope->session) == 0 &&
        aimem_token_u64(count_text, &count64) &&
        count64 <= QIHSE_AIMEM_ARCHIVE_MAX_RECORDS;
    qihse_user_t* manifest_actor = ok ? qihse_auth_get_user(actor_id) : NULL;
    ok = ok && manifest_actor && qihse_auth_user_is_active(manifest_actor) &&
         qihse_user_get_tenant_id(manifest_actor) == tenant_id;
    size_t count = (size_t)count64;
    aimem_archive_row_t* rows = ok ? calloc(count ? count : 1u, sizeof(*rows)) : NULL;
    if (ok && !rows) ok = false;
    for (size_t i = 0; ok && i < count; i++) {
        char* kind = strsep(&cur, "|"); char* cls = strsep(&cur, "|");
        char* sci = strsep(&cur, "|"); char* current = strsep(&cur, "|");
        char* hex = strsep(&cur, "|"); uint32_t c = 0u, s = 0u, current_u32 = 0u;
        ok = kind && strlen(kind) == 1u && (kind[0] == 'K' || kind[0] == 'E') &&
            cls && sci && current && hex && aimem_token_u32(cls, &c) &&
            c <= UINT16_MAX && aimem_token_u32(sci, &s) && s <= UINT16_MAX &&
            aimem_token_u32(current, &current_u32) && current_u32 == 1u &&
            qihse_auth_can_access(user, (uint16_t)c, (uint16_t)s);
        rows[i].kind = ok ? kind[0] : 0; rows[i].classification = (uint16_t)c;
        rows[i].sci = (uint16_t)s;
        if (ok) rows[i].raw = aimem_archive_hex_decode(hex);
        if (ok && rows[i].kind == 'K') {
            aimem_knowledge_chain_t chain = {0};
            ok = rows[i].raw && aimem_knowledge_chain_parse(rows[i].raw, &chain) &&
                aimem_scope_matches(&chain.scope, scope) &&
                (chain.owner_id == qihse_user_get_id(user) ||
                 qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR) &&
                aimem_knowledge_key(rows[i].key, sizeof rows[i].key, user,
                                    chain.knowledge_id);
            qihse_user_t* owner = ok ? qihse_auth_get_user(chain.owner_id) : NULL;
            ok = ok && owner && qihse_auth_user_is_active(owner) &&
                qihse_user_get_tenant_id(owner) == tenant_id;
            aimem_knowledge_chain_free(&chain);
        } else if (ok) {
            qihse_ai_memory_hit_t hit = {0}; aimem_record_meta_t meta;
            char producer[64], event_id[QIHSE_AIMEM_IDEM_MAX_LEN + 1u];
            ok = rows[i].raw && aimem_parse_record_meta(rows[i].raw, &hit, &meta) &&
                hit.kind == QIHSE_AIMEM_EVENT && hit.text &&
                aimem_event_envelope_valid(hit.text, producer, event_id) &&
                hit.classification == (uint16_t)c &&
                hit.sci_compartment == (uint16_t)s &&
                aimem_scope_matches(&meta.scope, scope) &&
                (meta.owner_id == qihse_user_get_id(user) ||
                 qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR);
            qihse_uuid_t uuid;
            ok = ok && qihse_uuid_parse(hit.id, &uuid) &&
                aimem_scoped_key(rows[i].key, sizeof rows[i].key, user,
                                 aimem_doc_id(&uuid));
            char idem[QIHSE_AIMEM_IDEM_MAX_LEN + 80u];
            char seed[QIHSE_AIMEM_IDEM_MAX_LEN + 512u];
            qihse_uuid_t expected_uuid; char expected_id[QIHSE_AIMEM_ID_LEN + 1u];
            int idem_n = ok ? snprintf(idem, sizeof idem, "event:%s:%s",
                                       producer, event_id) : -1;
            int seed_n = idem_n > 0 && (size_t)idem_n < sizeof idem ?
                snprintf(seed, sizeof seed, "QIHSE:AIMEM:scoped:v1:%u:%u:%s:%s:%s:%s:%s",
                    (unsigned)tenant_id, (unsigned)meta.owner_id, scope->project,
                    scope->worktree, scope->workstream, scope->session, idem) : -1;
            ok = ok && seed_n > 0 && (size_t)seed_n < sizeof seed &&
                qihse_uuid_from_seed(seed, (size_t)seed_n, &expected_uuid) &&
                qihse_uuid_format(&expected_uuid, expected_id) && strcmp(hit.id, expected_id) == 0;
            qihse_user_t* owner = ok ? qihse_auth_get_user(meta.owner_id) : NULL;
            ok = ok && owner && qihse_auth_user_is_active(owner) &&
                qihse_user_get_tenant_id(owner) == tenant_id;
            free(hit.text);
        }
        for (size_t j = 0; ok && j < i; j++)
            if (strcmp(rows[j].key, rows[i].key) == 0) ok = false;
    }
    ok = ok && cur == NULL;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    bool conflict = false;
    pthread_mutex_lock(&g_aimem_archive_lock);
    for (size_t i = 0; ok && !conflict && i < count; i++) {
        char* existing = qihse_kv_get_user(store, rows[i].key, user);
        if (existing && strcmp(existing, rows[i].raw) != 0) conflict = true;
        free(existing);
    }
    if (ok && !conflict && !dry_run) for (size_t i = 0; i < count; i++) {
        char* existing = qihse_kv_get_user(store, rows[i].key, user);
        if (existing) { bool same = strcmp(existing, rows[i].raw) == 0; free(existing);
            if (!same) { conflict = true; break; } continue; }
        qihse_kv_cas_result_t result = qihse_kv_compare_set_user(store, rows[i].key,
            NULL, rows[i].raw, rows[i].classification, rows[i].sci, user);
        if (result != QIHSE_KV_CAS_UPDATED) {
            existing = qihse_kv_get_user(store, rows[i].key, user);
            bool same = existing && strcmp(existing, rows[i].raw) == 0; free(existing);
            if (!same) { conflict = true; break; }
        } else {
            if (!qihse_kv_sync_store(store)) { ok = false; break; }
            if (out_imported) (*out_imported)++;
            const char* fail_after = getenv("QIHSE_AIMEM_IMPORT_FAIL_AFTER");
            if (fail_after && *fail_after) {
                char* end = NULL; unsigned long threshold = strtoul(fail_after, &end, 10);
                if (end && *end == '\0' && threshold > 0u && out_imported &&
                    *out_imported >= (size_t)threshold) { ok = false; break; }
            }
        }
    }
    if (ok && !conflict && !dry_run) ok = qihse_kv_sync_store(store);
    pthread_mutex_unlock(&g_aimem_archive_lock);
    for (size_t i = 0; i < count; i++) free(rows ? rows[i].raw : NULL);
    free(rows); free(copy);
    if (!ok) { aimem_counter_inc(&g_aimem_rejected); return QIHSE_AIMEM_IMPORT_FAILED; }
    if (conflict) return QIHSE_AIMEM_IMPORT_CONFLICT;
    if (!dry_run) aimem_counter_inc(&g_aimem_imports);
    return dry_run ? QIHSE_AIMEM_IMPORT_VALID : QIHSE_AIMEM_IMPORT_APPLIED;
}

qihse_ai_memory_import_result_t qihse_ai_memory_import_stream(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const uint8_t* authentication_key,
        size_t authentication_key_len, qihse_ai_memory_archive_read_fn read_fn,
        void* read_ctx, bool dry_run, size_t* out_imported) {
    if (out_imported) *out_imported = 0u;
    if (!read_fn) return QIHSE_AIMEM_IMPORT_FAILED;
    uint8_t* data = malloc(QIHSE_AIMEM_ARCHIVE_MAX_BYTES);
    if (!data) return QIHSE_AIMEM_IMPORT_FAILED;
    size_t used = 0u; bool overflow = false;
    while (used < QIHSE_AIMEM_ARCHIVE_MAX_BYTES) {
        size_t cap = QIHSE_AIMEM_ARCHIVE_MAX_BYTES - used;
        if (cap > QIHSE_AIMEM_ARCHIVE_CHUNK_MAX) cap = QIHSE_AIMEM_ARCHIVE_CHUNK_MAX;
        size_t n = read_fn(read_ctx, data + used, cap);
        if (n > cap) { overflow = true; break; }
        if (!n) break;
        used += n;
    }
    if (used == QIHSE_AIMEM_ARCHIVE_MAX_BYTES) {
        uint8_t probe; if (read_fn(read_ctx, &probe, 1u) != 0u) overflow = true;
    }
    qihse_ai_memory_import_result_t result = overflow ? QIHSE_AIMEM_IMPORT_FAILED :
        qihse_ai_memory_import_authenticated(server, user, scope, authentication_key,
            authentication_key_len, data, used, dry_run, out_imported);
    free(data); return result;
}

static bool aimem_index_state_key(char* out, size_t cap, qihse_user_t* user,
                                  const qihse_ai_memory_scope_t* scope) {
    char canonical[4u * (QIHSE_AIMEM_SCOPE_ID_MAX + 1u) + 4u], digest[65];
    int c = snprintf(canonical, sizeof canonical, "%s|%s|%s|%s", scope->project,
        scope->worktree, scope->workstream, scope->session);
    if (c < 0 || (size_t)c >= sizeof canonical ||
        !aimem_sha256_hex(canonical, (size_t)c, digest)) return false;
    int n = snprintf(out, cap, "t:%u/aimem-index-state:%s:private",
        (unsigned)qihse_user_get_tenant_id(user), digest);
    return n > 0 && (size_t)n < cap;
}

static bool aimem_index_public_key(char* out, size_t cap, qihse_user_t* user,
                                   const qihse_ai_memory_scope_t* scope) {
    char private_key[512];
    if (!aimem_index_state_key(private_key, sizeof private_key, user, scope)) return false;
    char* suffix = strrchr(private_key, ':');
    if (!suffix) return false;
    *suffix = '\0';
    int n = snprintf(out, cap, "%s:public", private_key);
    return n > 0 && (size_t)n < cap;
}

static bool aimem_index_public_write(qihse_kv_store_t* store, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const char* provider,
        size_t dimension, bool ready) {
    char key[512]; char* hex = aimem_hex_encode(provider); char record[512];
    int n = hex ? snprintf(record, sizeof record, "QHIP1|%s|%zu|%s", hex,
                           dimension, ready ? "READY" : "NOT_READY") : -1;
    bool ok = n > 0 && (size_t)n < sizeof record &&
        aimem_index_public_key(key, sizeof key, user, scope) &&
        qihse_kv_set_user(store, key, record, 0u, 0u, user) &&
        qihse_kv_sync_store(store);
    free(hex); return ok;
}

static bool aimem_index_public_parse(const char* raw, char provider[65],
                                     size_t* dimension, bool* ready) {
    if (!raw || !provider || !dimension || !ready) return false;
    char* copy = strdup(raw); if (!copy) return false;
    char* cur = copy; char* magic = strsep(&cur, "|"); char* encoded = strsep(&cur, "|");
    char* dim = strsep(&cur, "|"); char* status = strsep(&cur, "|"); uint64_t parsed_dim = 0u;
    char* decoded = encoded ? aimem_hex_decode(encoded) : NULL;
    bool ok = cur == NULL && magic && strcmp(magic, "QHIP1") == 0 && decoded &&
        *decoded && strlen(decoded) <= AIMEM_EMBEDDER_NAME_MAX &&
        aimem_token_u64(dim, &parsed_dim) && parsed_dim > 0u &&
        parsed_dim <= QIHSE_AIMEM_MAX_DIM && status &&
        (strcmp(status, "READY") == 0 || strcmp(status, "NOT_READY") == 0);
    if (ok) {
        snprintf(provider, 65u, "%s", decoded); *dimension = (size_t)parsed_dim;
        *ready = strcmp(status, "READY") == 0;
    }
    free(decoded); free(copy); return ok;
}

typedef struct {
    uint64_t active_generation;
    uint64_t candidate_generation;
    uint32_t state;
    char provider[AIMEM_EMBEDDER_NAME_MAX + 1u];
    size_t dimension;
    uint64_t source_highwater;
    uint64_t indexed_records;
    uint64_t rebuild_started;
    uint64_t rebuild_ready;
    uint64_t rebuild_failed;
    uint64_t provider_failures;
    uint64_t recovered_builds;
    uint64_t audit_events;
    uint32_t last_event;
} aimem_index_state_t;

enum {
    AIMEM_INDEX_AUDIT_STARTED = 1u,
    AIMEM_INDEX_AUDIT_READY = 2u,
    AIMEM_INDEX_AUDIT_FAILED = 3u,
    AIMEM_INDEX_AUDIT_RECOVERED = 4u
};

static const char* aimem_index_state_name(uint32_t state) {
    switch (state) {
        case QIHSE_AIMEM_INDEX_BUILDING: return "BUILDING";
        case QIHSE_AIMEM_INDEX_READY: return "READY";
        case QIHSE_AIMEM_INDEX_FAILED: return "FAILED";
        default: return "NONE";
    }
}

static uint32_t aimem_index_state_parse_name(const char* value) {
    if (!value) return QIHSE_AIMEM_INDEX_NONE;
    if (strcmp(value, "BUILDING") == 0) return QIHSE_AIMEM_INDEX_BUILDING;
    if (strcmp(value, "READY") == 0) return QIHSE_AIMEM_INDEX_READY;
    if (strcmp(value, "FAILED") == 0) return QIHSE_AIMEM_INDEX_FAILED;
    return QIHSE_AIMEM_INDEX_NONE;
}

static char* aimem_index_state_encode(const aimem_index_state_t* state) {
    char* provider = aimem_hex_encode(state->provider);
    if (!provider) return NULL;
    char* encoded = malloc(1024u);
    if (encoded) {
        int n = snprintf(encoded, 1024u,
            "QHI2|%llu|%llu|%s|%s|%zu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%u",
            (unsigned long long)state->active_generation,
            (unsigned long long)state->candidate_generation,
            aimem_index_state_name(state->state), provider, state->dimension,
            (unsigned long long)state->source_highwater,
            (unsigned long long)state->indexed_records,
            (unsigned long long)state->rebuild_started,
            (unsigned long long)state->rebuild_ready,
            (unsigned long long)state->rebuild_failed,
            (unsigned long long)state->provider_failures,
            (unsigned long long)state->recovered_builds,
            (unsigned long long)state->audit_events, state->last_event);
        if (n < 0 || n >= 1024) { free(encoded); encoded = NULL; }
    }
    free(provider);
    return encoded;
}

static bool aimem_index_state_parse(const char* raw, aimem_index_state_t* out) {
    if (!raw || !out) return false;
    memset(out, 0, sizeof(*out));
    if (strncmp(raw, "QHI1|", 5u) == 0) {
        unsigned long long generation = 0u, highwater = 0u;
        char status[16], provider[AIMEM_EMBEDDER_NAME_MAX + 1u]; size_t dimension = 0u;
        if (sscanf(raw, "QHI1|%llu|%15[^|]|%63[^|]|%zu|%llu", &generation,
                   status, provider, &dimension, &highwater) != 5) return false;
        out->active_generation = out->candidate_generation = generation;
        out->state = aimem_index_state_parse_name(status);
        memcpy(out->provider, provider, strlen(provider) + 1u);
        out->dimension = dimension; out->source_highwater = highwater;
        return out->state != QIHSE_AIMEM_INDEX_NONE;
    }
    char* copy = strdup(raw); if (!copy) return false;
    char* cur = copy; char* f[15];
    for (size_t i = 0; i < 15u; i++) f[i] = strsep(&cur, "|");
    uint64_t dim = 0u, state = 0u, last = 0u;
    bool ok = cur == NULL && f[0] && strcmp(f[0], "QHI2") == 0 &&
        aimem_token_u64(f[1], &out->active_generation) &&
        aimem_token_u64(f[2], &out->candidate_generation) &&
        (state = aimem_index_state_parse_name(f[3])) != QIHSE_AIMEM_INDEX_NONE &&
        aimem_token_u64(f[5], &dim) && dim > 0u && dim <= QIHSE_AIMEM_MAX_DIM &&
        aimem_token_u64(f[6], &out->source_highwater) &&
        aimem_token_u64(f[7], &out->indexed_records) &&
        aimem_token_u64(f[8], &out->rebuild_started) &&
        aimem_token_u64(f[9], &out->rebuild_ready) &&
        aimem_token_u64(f[10], &out->rebuild_failed) &&
        aimem_token_u64(f[11], &out->provider_failures) &&
        aimem_token_u64(f[12], &out->recovered_builds) &&
        aimem_token_u64(f[13], &out->audit_events) &&
        aimem_token_u64(f[14], &last) && last <= UINT32_MAX;
    char* provider = ok ? aimem_hex_decode(f[4]) : NULL;
    ok = ok && provider && *provider && strlen(provider) <= AIMEM_EMBEDDER_NAME_MAX;
    if (ok) {
        out->state = (uint32_t)state; out->dimension = (size_t)dim;
        out->last_event = (uint32_t)last;
        snprintf(out->provider, sizeof out->provider, "%s", provider);
    }
    free(provider); free(copy);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static bool aimem_index_state_load(qihse_kv_store_t* store, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, char** raw, aimem_index_state_t* state) {
    char key[512];
    if (!store || !raw || !state ||
        !aimem_index_state_key(key, sizeof key, user, scope)) return false;
    *raw = qihse_kv_get_user(store, key, user);
    if (!*raw) { memset(state, 0, sizeof(*state)); return true; }
    return aimem_index_state_parse(*raw, state);
}

static bool aimem_index_state_cas(qihse_kv_store_t* store, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const char* expected,
        const aimem_index_state_t* state, char** committed) {
    char key[512]; char* encoded = aimem_index_state_encode(state);
    bool ok = encoded && aimem_index_state_key(key, sizeof key, user, scope) &&
        qihse_kv_compare_set_user(store, key, expected, encoded,
            qihse_user_get_classification(user), qihse_user_get_sci(user), user) ==
            QIHSE_KV_CAS_UPDATED && qihse_kv_sync_store(store);
    if (committed) *committed = ok ? strdup(encoded) : NULL;
    free(encoded);
    return ok && (!committed || *committed);
}

static void aimem_index_audit(qihse_user_t* user, uint32_t event,
                              uint64_t generation) {
    /* Fault-injection children intentionally terminate without audit-thread
     * teardown. Their durable QHI2 audit counter is recovered by the parent;
     * never touch inherited asynchronous audit state in that crash window. */
    if (getenv("QIHSE_AIMEM_QH08_FAIL_AT")) return;
    const char* action = event == AIMEM_INDEX_AUDIT_STARTED ? "AIMEM_INDEX_BUILDING" :
        event == AIMEM_INDEX_AUDIT_READY ? "AIMEM_INDEX_READY" :
        event == AIMEM_INDEX_AUDIT_RECOVERED ? "AIMEM_INDEX_RECOVERED" :
        "AIMEM_INDEX_FAILED";
    qihse_audit_log(action, qihse_user_get_id(user), (uint32_t)generation, 0u, 0u);
}

static bool aimem_index_operator(qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
           qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
           qihse_user_get_classification(user) == UINT16_MAX &&
           qihse_user_get_sci(user) == UINT16_MAX;
}

bool qihse_ai_memory_index_recover(qihse_resp_server_t* server,
        qihse_user_t* user, const qihse_ai_memory_scope_t* scope) {
    if (!server || !aimem_index_operator(user) || !aimem_scope_valid(scope)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    char* raw = NULL; aimem_index_state_t state;
    if (!aimem_index_state_load(store, user, scope, &raw, &state)) { free(raw); return false; }
    if (!raw || state.state != QIHSE_AIMEM_INDEX_BUILDING) { free(raw); return true; }
    state.state = QIHSE_AIMEM_INDEX_FAILED;
    state.rebuild_failed++; state.recovered_builds++; state.audit_events++;
    state.last_event = AIMEM_INDEX_AUDIT_RECOVERED;
    bool ok = aimem_index_state_cas(store, user, scope, raw, &state, NULL);
    if (ok) ok = aimem_index_public_write(store, user, scope, state.provider,
                                           state.dimension, false);
    if (ok) aimem_index_audit(user, AIMEM_INDEX_AUDIT_RECOVERED,
                              state.candidate_generation);
    free(raw); return ok;
}

typedef struct {
    char key[768];
    char* value;
    uint16_t classification;
    uint16_t sci;
} aimem_index_entry_t;

typedef struct {
    qihse_resp_server_t* server;
    qihse_user_t* user;
    const qihse_ai_memory_scope_t* scope;
    uint64_t generation;
    const char* provider;
    size_t dimension;
    aimem_index_entry_t* entries;
    size_t count;
    bool failed;
    bool provider_failed;
} aimem_index_build_t;

static bool aimem_index_entry_key(char* out, size_t cap, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, uint64_t generation,
        const char* knowledge_id) {
    char canonical[4u * (QIHSE_AIMEM_SCOPE_ID_MAX + 1u) + 4u];
    char scope_digest[65], id_digest[65];
    int c = snprintf(canonical, sizeof canonical, "%s|%s|%s|%s", scope->project,
        scope->worktree, scope->workstream, scope->session);
    if (c < 0 || (size_t)c >= sizeof canonical ||
        !aimem_sha256_hex(canonical, (size_t)c, scope_digest) ||
        !aimem_sha256_hex(knowledge_id, strlen(knowledge_id), id_digest)) return false;
    int n = snprintf(out, cap, "t:%u/aimem-index-gen:%s:%llu:%s",
        (unsigned)qihse_user_get_tenant_id(user), scope_digest,
        (unsigned long long)generation, id_digest);
    return n > 0 && (size_t)n < cap;
}

static bool aimem_index_build_cb(const char* key, const char* value, void* opaque) {
    aimem_index_build_t* b = opaque; aimem_knowledge_chain_t chain;
    if (!aimem_knowledge_chain_parse(value, &chain)) { b->failed = true; return false; }
    if (!aimem_scope_matches(&chain.scope, b->scope)) {
        aimem_knowledge_chain_free(&chain); return true;
    }
    if (b->count >= QIHSE_AIMEM_QUERY_MAX_ROWS) {
        b->failed = true; aimem_knowledge_chain_free(&chain); return false;
    }
    qihse_ai_memory_knowledge_version_t* current = &chain.versions[chain.count - 1u];
    float* vector = calloc(b->dimension, sizeof(*vector));
    bool ok = vector && strcmp(qihse_ai_memory_embedder_name(), b->provider) == 0 &&
        qihse_ai_memory_embedding_dim() == b->dimension &&
        qihse_ai_memory_embed_text(current->content, vector, b->dimension);
    for (size_t i = 0; ok && i < b->dimension; i++) ok = isfinite(vector[i]);
    if (!ok) b->provider_failed = true;
    qihse_kv_record_meta_t meta;
    qihse_kv_store_t* store = qihse_resp_server_store(b->server);
    if (ok) ok = qihse_kv_meta_user(store, key, b->user, &meta);
    char* provider = ok ? aimem_hex_encode(b->provider) : NULL;
    size_t cap = 256u + b->dimension * 18u;
    char* encoded = provider ? malloc(cap) : NULL; size_t used = 0u;
    if (encoded) {
        int n = snprintf(encoded, cap, "QHIX1|%s|%zu|%s|", provider,
            b->dimension, current->version_id);
        ok = n > 0 && (size_t)n < cap; used = ok ? (size_t)n : 0u;
    } else ok = false;
    for (size_t i = 0; ok && i < b->dimension; i++) {
        int n = snprintf(encoded + used, cap - used, "%s%.9g", i ? "," : "",
                         (double)vector[i]);
        if (n < 0 || (size_t)n >= cap - used) ok = false;
        else used += (size_t)n;
    }
    aimem_index_entry_t* entry = ok ? &b->entries[b->count] : NULL;
    if (ok) ok = aimem_index_entry_key(entry->key, sizeof entry->key, b->user,
        b->scope, b->generation, chain.knowledge_id);
    if (ok) {
        entry->value = encoded; entry->classification = meta.classification;
        entry->sci = meta.sci_compartment; b->count++;
    } else free(encoded);
    free(provider); free(vector); aimem_knowledge_chain_free(&chain);
    if (!ok) b->failed = true;
    return ok;
}

static void aimem_index_entries_free(aimem_index_build_t* build) {
    for (size_t i = 0; i < build->count; i++) free(build->entries[i].value);
    free(build->entries); build->entries = NULL; build->count = 0u;
}

static bool aimem_index_fail(qihse_kv_store_t* store, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, const char* building_raw,
        aimem_index_state_t* state, bool provider_failed) {
    state->state = QIHSE_AIMEM_INDEX_FAILED; state->rebuild_failed++;
    if (provider_failed) state->provider_failures++;
    state->audit_events++; state->last_event = AIMEM_INDEX_AUDIT_FAILED;
    bool ok = aimem_index_state_cas(store, user, scope, building_raw, state, NULL);
    if (ok) ok = aimem_index_public_write(store, user, scope, state->provider,
                                           state->dimension, false);
    if (ok) aimem_index_audit(user, AIMEM_INDEX_AUDIT_FAILED,
                              state->candidate_generation);
    return ok;
}

bool qihse_ai_memory_index_rebuild(qihse_resp_server_t* server,
        qihse_user_t* user, const qihse_ai_memory_scope_t* scope) {
    if (!server || !aimem_index_operator(user) || !aimem_scope_valid(scope)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store || !qihse_ai_memory_index_recover(server, user, scope)) return false;
    char* prior_raw = NULL; aimem_index_state_t state;
    if (!aimem_index_state_load(store, user, scope, &prior_raw, &state)) {
        free(prior_raw); return false;
    }
    uint64_t largest = state.active_generation > state.candidate_generation ?
        state.active_generation : state.candidate_generation;
    state.candidate_generation = largest + 1u;
    if (!state.candidate_generation) { free(prior_raw); return false; }
    state.state = QIHSE_AIMEM_INDEX_BUILDING;
    snprintf(state.provider, sizeof state.provider, "%s", qihse_ai_memory_embedder_name());
    state.dimension = qihse_ai_memory_embedding_dim();
    if (!state.provider[0] || !state.dimension) { free(prior_raw); return false; }
    if (!aimem_index_public_write(store, user, scope, state.provider,
                                  state.dimension, false)) {
        free(prior_raw); return false;
    }
    state.source_highwater = qihse_kv_change_seq(store);
    if (state.source_highwater == UINT64_MAX) { free(prior_raw); return false; }
    state.source_highwater++; /* the BUILDING CAS is the next local mutation */
    state.indexed_records = 0u;
    state.rebuild_started++; state.audit_events++; state.last_event = AIMEM_INDEX_AUDIT_STARTED;
    char* building_raw = NULL;
    bool ok = aimem_index_state_cas(store, user, scope, prior_raw, &state, &building_raw);
    free(prior_raw);
    if (!ok) { free(building_raw); return false; }
    aimem_index_audit(user, AIMEM_INDEX_AUDIT_STARTED, state.candidate_generation);
    const char* fail_at = getenv("QIHSE_AIMEM_QH08_FAIL_AT");
    if (fail_at && strcmp(fail_at, "after-building") == 0) {
        free(building_raw); return false;
    }

    float* probe = calloc(state.dimension, sizeof(*probe));
    bool provider_ok = probe && qihse_ai_memory_embed_text(
        "qihse-index-provider-preflight", probe, state.dimension);
    for (size_t i = 0; provider_ok && i < state.dimension; i++)
        provider_ok = isfinite(probe[i]);
    free(probe);
    if (!provider_ok) {
        (void)aimem_index_fail(store, user, scope, building_raw, &state, true);
        free(building_raw); return false;
    }

    aimem_index_build_t build = { .server = server, .user = user, .scope = scope,
        .generation = state.candidate_generation, .provider = state.provider,
        .dimension = state.dimension };
    build.entries = calloc(QIHSE_AIMEM_QUERY_MAX_ROWS, sizeof(*build.entries));
    char prefix[48]; int n = snprintf(prefix, sizeof prefix, "t:%u/aimem-knowledge:",
        (unsigned)qihse_user_get_tenant_id(user));
    ok = build.entries && n > 0 && (size_t)n < sizeof prefix &&
        qihse_kv_foreach_prefix_user(store, prefix, user, aimem_index_build_cb, &build) &&
        !build.failed && qihse_kv_change_seq(store) == state.source_highwater &&
        strcmp(qihse_ai_memory_embedder_name(), state.provider) == 0 &&
        qihse_ai_memory_embedding_dim() == state.dimension;
    if (ok) for (size_t i = 0; i < build.count; i++) {
        if (!qihse_kv_set_user(store, build.entries[i].key, build.entries[i].value,
                build.entries[i].classification, build.entries[i].sci, user)) {
            ok = false; break;
        }
    }
    if (ok) ok = qihse_kv_sync_store(store);
    fail_at = getenv("QIHSE_AIMEM_QH08_FAIL_AT");
    if (ok && fail_at && strcmp(fail_at, "after-entries") == 0) {
        aimem_index_entries_free(&build); free(building_raw); return false;
    }
    state.indexed_records = build.count;
    bool provider_failed = build.provider_failed ||
        strcmp(qihse_ai_memory_embedder_name(), state.provider) != 0;
    aimem_index_entries_free(&build);
    if (!ok) {
        (void)aimem_index_fail(store, user, scope, building_raw, &state, provider_failed);
        free(building_raw); return false;
    }
    state.active_generation = state.candidate_generation;
    state.state = QIHSE_AIMEM_INDEX_READY; state.rebuild_ready++;
    state.audit_events++; state.last_event = AIMEM_INDEX_AUDIT_READY;
    ok = aimem_index_state_cas(store, user, scope, building_raw, &state, NULL);
    if (ok) {
        ok = aimem_index_public_write(store, user, scope, state.provider,
                                      state.dimension, true);
    }
    if (ok) {
        aimem_index_audit(user, AIMEM_INDEX_AUDIT_READY, state.active_generation);
        __atomic_store_n(&g_aimem_index_generation, state.active_generation,
                         __ATOMIC_RELAXED);
    }
    free(building_raw); return ok;
}

bool qihse_ai_memory_health(qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, qihse_ai_memory_health_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !out ||
        (!qihse_ai_memory_project_owner_allowed(server, user, scope->project) &&
         !qihse_ai_memory_project_reader_allowed(server, user, scope->project))) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server); char key[512];
    bool is_operator = qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR;
    char* raw = NULL; aimem_index_state_t state; bool parsed = false;
    bool private_parsed = false;
    if (is_operator && aimem_index_state_key(key, sizeof key, user, scope)) {
        raw = qihse_kv_get_user(store, key, user);
        parsed = raw && aimem_index_state_parse(raw, &state);
        private_parsed = parsed;
    }
    if (is_operator && parsed) {
        snprintf(out->provider, sizeof out->provider, "%s", state.provider);
        out->dimension = state.dimension;
        char public_provider[65] = {0}; size_t public_dimension = 0u;
        bool public_ready = false;
        char* public_raw = aimem_index_public_key(key, sizeof key, user, scope) ?
            qihse_kv_get_user(store, key, user) : NULL;
        bool public_valid = public_raw && aimem_index_public_parse(public_raw,
            public_provider, &public_dimension, &public_ready);
        free(public_raw);
        out->ready = public_valid && public_ready &&
            strcmp(public_provider, state.provider) == 0 &&
            public_dimension == state.dimension &&
            state.state == QIHSE_AIMEM_INDEX_READY &&
            strcmp(state.provider, qihse_ai_memory_embedder_name()) == 0 &&
            state.dimension == qihse_ai_memory_embedding_dim();
    } else {
        free(raw); raw = aimem_index_public_key(key, sizeof key, user, scope) ?
            qihse_kv_get_user(store, key, user) : NULL;
        bool public_ready = false;
        parsed = raw && aimem_index_public_parse(raw, out->provider,
                                                  &out->dimension, &public_ready);
        if (!parsed) {
            snprintf(out->provider, sizeof out->provider, "%s",
                     qihse_ai_memory_embedder_name());
            out->dimension = qihse_ai_memory_embedding_dim();
        }
        out->ready = parsed && public_ready &&
            strcmp(out->provider, qihse_ai_memory_embedder_name()) == 0 &&
            out->dimension == qihse_ai_memory_embedding_dim();
    }
    if (is_operator) {
        out->index_state = private_parsed ? state.state : QIHSE_AIMEM_INDEX_NONE;
        out->generation = private_parsed ? state.active_generation : 0u;
        out->candidate_generation = private_parsed ? state.candidate_generation : 0u;
        out->source_highwater = private_parsed ? state.source_highwater : 0u;
        out->indexed_records = private_parsed ? state.indexed_records : 0u;
        out->rebuild_started = private_parsed ? state.rebuild_started : 0u;
        out->rebuild_ready = private_parsed ? state.rebuild_ready : 0u;
        out->rebuild_failed = private_parsed ? state.rebuild_failed : 0u;
        out->provider_failures = private_parsed ? state.provider_failures : 0u;
        out->recovered_builds = private_parsed ? state.recovered_builds : 0u;
        out->audit_events = private_parsed ? state.audit_events : 0u;
        out->query_snapshots = __atomic_load_n(&g_aimem_query_snapshots, __ATOMIC_RELAXED);
        out->maintenance_versions = __atomic_load_n(&g_aimem_maintenance_versions, __ATOMIC_RELAXED);
        out->exports = __atomic_load_n(&g_aimem_exports, __ATOMIC_RELAXED);
        out->imports = __atomic_load_n(&g_aimem_imports, __ATOMIC_RELAXED);
        out->rejected = __atomic_load_n(&g_aimem_rejected, __ATOMIC_RELAXED);
    }
    free(raw); return true;
}

bool qihse_ai_memory_forget_scoped(qihse_resp_server_t* server,
                                   qihse_user_t* user, const char* id,
                                   const qihse_ai_memory_scope_t* scope) {
    if (!server || !user || !id || !aimem_scope_valid(scope)) return false;
    qihse_ai_memory_hit_t hit;
    if (!qihse_ai_memory_get_scoped(server, user, id, scope, &hit)) return false;
    free(hit.text);
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(id, &uuid)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    char key[96];
    if (!aimem_scoped_key(key, sizeof key, user, aimem_doc_id(&uuid))) return false;
    if (qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR) {
        char* raw = qihse_kv_get_user(store, key, user);
        if (!raw) return false;
        aimem_record_meta_t meta;
        bool owner = aimem_parse_meta(raw, &meta, NULL) &&
                     meta.owner_id == qihse_user_get_id(user);
        free(raw);
        if (!owner) return false;
    }
    return qihse_kv_del_user(store, key, user);
}

typedef struct {
    qihse_user_t* user;
    qihse_kv_store_t* store;
    char key_prefix[32];
    const qihse_ai_memory_scope_t* scope;
    uint32_t kind;
    size_t count;
} aimem_scope_count_t;

static bool aimem_scope_count_cb(const char* key, const char* value,
                                 void* user_data) {
    aimem_scope_count_t* c = (aimem_scope_count_t*)user_data;
    size_t prefix_len = strlen(c->key_prefix);
    if (strncmp(key, c->key_prefix, prefix_len) != 0) return true;
    aimem_record_meta_t meta;
    memset(&meta, 0, sizeof meta);
    if (aimem_parse_meta(value, &meta, NULL) && meta.scope.project[0] &&
        aimem_scope_matches(&meta.scope, c->scope) &&
        aimem_scope_owner_allowed(c->store, c->user, meta.owner_id, c->scope) &&
        (c->kind == QIHSE_AIMEM_KIND_ANY || c->kind == meta.kind)) c->count++;
    return true;
}

size_t qihse_ai_memory_count_scoped(qihse_resp_server_t* server,
                                    qihse_user_t* user, uint32_t kind,
                                    const qihse_ai_memory_scope_t* scope) {
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_kind_valid(kind) || !aimem_scope_valid(scope)) return 0u;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return 0u;
    aimem_scope_count_t c = { .user = user, .store = store, .scope = scope,
                              .kind = kind, .count = 0u };
    snprintf(c.key_prefix, sizeof c.key_prefix, "t:%u/aimem:",
             (unsigned)qihse_user_get_tenant_id(user));
    qihse_kv_foreach_user(store, user, aimem_scope_count_cb, &c);
    return c.count;
}

void qihse_ai_memory_hits_free(qihse_ai_memory_hit_t* hits, size_t count) {
    if (!hits) return;
    for (size_t i = 0; i < count; i++) {
        free(hits[i].text);
        hits[i].text = NULL;
    }
}
