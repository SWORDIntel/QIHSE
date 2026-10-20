/* Local-first AI memory over the native KV store + FTS index.
 *
 * Record layout:
 *   key   aimem:<doc-id as 16 hex chars>
 *   legacy value <uuid>|<created_ms>|<kind>|<classif>|<sci>|<text>
 *   scoped value v2|<uuid>|<created_ms>|<kind>|<classif>|<sci>|<owner>|<project>|<worktree>|<workstream>|<session>|<text>
 *
 * The search index is process-local and rebuilt lazily from the KV namespace,
 * so a restart re-derives it from the durable records. Forgetting a memory
 * removes the KV record; the index posting is ignored at read time when the
 * record is gone (the FTS engine has no delete primitive).
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

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define AIMEM_PREFIX "aimem:"
#define AIMEM_PREFIX_LEN (sizeof(AIMEM_PREFIX) - 1u)
#define AIMEM_MAX_TEXT (64u * 1024u)

static qihse_fts_index_t* g_aimem_index = NULL;
static pthread_mutex_t g_aimem_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_knowledge_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_aimem_migration_lock = PTHREAD_MUTEX_INITIALIZER;

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
        char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
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
    bool ok = qihse_kv_set_user(store, key, value, classification, sci, user);
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
    return aimem_store_uuid(server, user, text, kind, NULL, &uuid, out_id) ==
           QIHSE_AIMEM_WRITE_NEW;
}

qihse_ai_memory_write_result_t qihse_ai_memory_store_idempotent(
        qihse_resp_server_t* server, qihse_user_t* user, const char* text,
        uint32_t kind, const char* idempotency_key,
        char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
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
    return aimem_store_uuid(server, user, text, kind, NULL, &uuid, out_id);
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
    return aimem_store_uuid(server, user, text, kind, scope, &uuid, out_id) ==
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
    return aimem_store_uuid(server, user, text, kind, scope, &uuid, out_id);
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
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !aimem_event_token(producer_namespace, 63u) ||
        !aimem_event_token(event_id, QIHSE_AIMEM_IDEM_MAX_LEN) ||
        !aimem_event_kind_valid(event_kind) || !summary || !*summary ||
        strnlen(summary, QIHSE_AIMEM_EVENT_MAX_SUMMARY + 1u) > QIHSE_AIMEM_EVENT_MAX_SUMMARY)
        return QIHSE_AIMEM_WRITE_FAILED;
    for (const unsigned char* p = (const unsigned char*)summary; *p; p++)
        if (*p < 0x20u || *p == 0x7fu) return QIHSE_AIMEM_WRITE_FAILED;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(summary, strlen(summary), digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len != 32u) return QIHSE_AIMEM_WRITE_FAILED;
    char digest_hex[65];
    for (size_t i = 0; i < 32u; i++)
        snprintf(digest_hex + i * 2u, 3u, "%02x", digest[i]);
    char* envelope = malloc(QIHSE_AIMEM_EVENT_MAX_SUMMARY + 512u);
    if (!envelope) return QIHSE_AIMEM_WRITE_FAILED;
    int n = snprintf(envelope, QIHSE_AIMEM_EVENT_MAX_SUMMARY + 512u,
        "QHEV1|%s|%s|%s|%llu|%llu|observed|%s|%s", producer_namespace, event_id,
        event_kind, (unsigned long long)source_time_ms,
        (unsigned long long)aimem_now_ms(), digest_hex, summary);
    if (n <= 0 || (size_t)n >= QIHSE_AIMEM_EVENT_MAX_SUMMARY + 512u) {
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
                    "QHEV1|%s|%s|%s|%llu|", producer_namespace, event_id,
                    event_kind, (unsigned long long)source_time_ms);
                char* receive_end = pn > 0 && (size_t)pn < sizeof invariant_prefix &&
                    strncmp(prior.text, invariant_prefix, (size_t)pn) == 0
                    ? strchr(prior.text + pn, '|') : NULL;
                size_t suffix_len = strlen("observed|") + strlen(digest_hex) + 1u + strlen(summary);
                char* suffix = malloc(suffix_len + 1u);
                bool same = false;
                if (suffix) {
                    snprintf(suffix, suffix_len + 1u, "observed|%s|%s", digest_hex, summary);
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
                                          QIHSE_AIMEM_EVENT, scope, &uuid, out_id);
            }
        }
    }
    pthread_mutex_unlock(&g_aimem_event_lock);
    free(envelope);
    return result;
}

bool qihse_ai_memory_event_get(qihse_resp_server_t* server, qihse_user_t* user,
        const char* id, const qihse_ai_memory_scope_t* scope,
        qihse_ai_memory_hit_t* out) {
    if (!qihse_ai_memory_get_scoped(server, user, id, scope, out)) return false;
    if (out->kind == QIHSE_AIMEM_EVENT && out->text &&
        strncmp(out->text, "QHEV1|", 6u) == 0) {
        char producer[64], event_id[QIHSE_AIMEM_IDEM_MAX_LEN + 1u];
        char kind[32], source[24], received[24], status[16], digest_hex[65];
        int offset = 0;
        int fields = sscanf(out->text,
            "QHEV1|%63[^|]|%128[^|]|%31[^|]|%23[^|]|%23[^|]|%15[^|]|%64[^|]|%n",
            producer, event_id, kind, source, received, status, digest_hex, &offset);
        bool valid = fields == 7 && offset > 0 && aimem_event_token(producer, 63u) &&
            aimem_event_token(event_id, QIHSE_AIMEM_IDEM_MAX_LEN) &&
            aimem_event_kind_valid(kind) && strcmp(status, "observed") == 0 &&
            strlen(digest_hex) == 64u;
        valid = valid && aimem_event_u64_valid(source) && aimem_event_u64_valid(received);
        for (size_t i = 0; valid && i < 64u; i++)
            if (!((digest_hex[i] >= '0' && digest_hex[i] <= '9') ||
                  (digest_hex[i] >= 'a' && digest_hex[i] <= 'f'))) valid = false;
        const char* summary = out->text + offset;
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
        if (valid) return true;
    }
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

bool qihse_ai_memory_forget(qihse_resp_server_t* server, qihse_user_t* user,
                            const char* id) {
    if (!server || !user || qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM ||
        !id) return false;
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(id, &uuid)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    /* Authenticate the complete UUID before deleting its truncated-key
     * record: an unrelated UUID with the same prefix is not authority. */
    qihse_ai_memory_hit_t existing;
    memset(&existing, 0, sizeof existing);
    if (!qihse_ai_memory_get(server, user, id, &existing)) return false;
    free(existing.text);
    char key[64];
    aimem_key(key, sizeof key, aimem_doc_id(&uuid));
    bool ok = qihse_kv_del_user(store, key, user);
    if (!ok) return false;
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
    return ok;
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
    qihse_fts_index_t* scoped_index = qihse_fts_create();
    if (!store || !scoped_index) { qihse_fts_destroy(scoped_index); return 0u; }
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
            qihse_fts_destroy(scoped_index);
            return 0u;
        }
    }
    aimem_scoped_rebuild_t rb = {
        .index = scoped_index, .store = store, .user = user, .scope = scope, .kind = kind,
        .lexical = mode != QIHSE_AIMEM_MODE_SEMANTIC,
        .query_vec = want_vector ? query_vec : NULL,
        .query_dim = want_vector ? query_dim : 0u,
        .vector = want_vector ? vector : NULL,
        .vector_cap = want_vector ? (want == AIMEM_CAND_MAX ? want : AIMEM_CAND_MAX) : 0u,
        .vector_count = 0u, .added = 0u
    };
    snprintf(rb.key_prefix, sizeof rb.key_prefix, "t:%u/aimem:",
             (unsigned)qihse_user_get_tenant_id(user));
    qihse_kv_foreach_prefix_user(store, rb.key_prefix, user,
                                 aimem_scoped_rebuild_cb, &rb);
    qihse_fts_result_t results[AIMEM_CAND_MAX];
    int found = 0;
    if (rb.lexical)
        found = qihse_fts_search_user(scoped_index, query, user, results,
                                      (int)(want < AIMEM_CAND_MAX ? AIMEM_CAND_MAX : want));
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
    for (size_t i = 0; i < chain->count; i++) free(chain->versions[i].content);
    free(chain->versions);
    memset(chain, 0, sizeof(*chain));
}

static bool aimem_knowledge_type_valid(uint32_t type) {
    return type >= QIHSE_AIMEM_KNOWLEDGE_DECISION &&
           type <= QIHSE_AIMEM_KNOWLEDGE_SESSION_CAPSULE;
}

static bool aimem_knowledge_status_writable(qihse_user_t* user, uint32_t status) {
    if (status == QIHSE_AIMEM_KNOWLEDGE_PROPOSED) return true;
    return status == QIHSE_AIMEM_KNOWLEDGE_APPROVED &&
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

static bool aimem_knowledge_chain_parse(const char* raw,
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
    out->count = ok ? count32 : 0u;
    ok = ok && cursor == NULL && out->versions[count32 - 1u].valid_to_ingest_ms == 0u;
    free(copy);
    if (!ok) aimem_knowledge_chain_free(out);
#undef NEXT_TOKEN
    return ok;
}

static char* aimem_knowledge_chain_encode(const aimem_knowledge_chain_t* chain) {
    if (!chain || !chain->count || chain->count > AIMEM_KNOWLEDGE_MAX_VERSIONS) return NULL;
    size_t cap = 512u;
    for (size_t i = 0; i < chain->count; i++) {
        size_t n = chain->versions[i].content ? strlen(chain->versions[i].content) : 0u;
        if (!n || n > AIMEM_KNOWLEDGE_MAX_CONTENT || cap > SIZE_MAX - n * 2u - 256u) return NULL;
        cap += n * 2u + 256u;
    }
    if (cap > AIMEM_KNOWLEDGE_MAX_ENCODED) return NULL;
    char* out = malloc(cap), *p = out;
    if (!out) return NULL;
    size_t left = cap;
#define APPEND(...) do { int written = snprintf(p, left, __VA_ARGS__); if (written < 0 || (size_t)written >= left) { free(out); return NULL; } p += written; left -= (size_t)written; } while (0)
    APPEND("QHK1|%s|%u|%s|%s|%s|%s|%u|%zu", chain->knowledge_id,
           (unsigned)chain->owner_id, chain->scope.project, chain->scope.worktree,
           chain->scope.workstream, chain->scope.session, (unsigned)chain->type, chain->count);
    for (size_t i = 0; i < chain->count; i++) {
        const qihse_ai_memory_knowledge_version_t* v = &chain->versions[i];
        char* hex = aimem_hex_encode(v->content);
        if (!hex) { free(out); return NULL; }
        APPEND("|%s|%llu|%llu|%llu|%llu|%u|%u|%s|%s", v->version_id,
               (unsigned long long)v->revision, (unsigned long long)v->created_at_ms,
               (unsigned long long)v->valid_from_ingest_ms,
               (unsigned long long)v->valid_to_ingest_ms, (unsigned)v->status,
               (unsigned)v->created_by, v->supersedes_version, hex);
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
    if (!out->content) memset(out, 0, sizeof(*out));
    return out->content != NULL;
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

qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_create(
        qihse_resp_server_t* server, qihse_user_t* user,
        const qihse_ai_memory_scope_t* scope, uint32_t type, uint32_t status,
        const char* content, qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!server || !user || !qihse_auth_user_is_active(user) ||
        !aimem_scope_valid(scope) || !aimem_knowledge_type_valid(type) ||
        !aimem_knowledge_status_writable(user, status) || !content || !*content ||
        strlen(content) > AIMEM_KNOWLEDGE_MAX_CONTENT || !out ||
        !qihse_ai_memory_project_owner_allowed(server, user, scope->project))
        return QIHSE_AIMEM_WRITE_FAILED;
    qihse_uuid_t knowledge_uuid, version_uuid;
    aimem_knowledge_chain_t chain;
    memset(&chain, 0, sizeof chain);
    if (!qihse_uuid_generate(&knowledge_uuid) ||
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
    v->created_by = chain.owner_id; v->content = strdup(content);
    char* encoded = v->content ? aimem_knowledge_chain_encode(&chain) : NULL;
    char key[128];
    bool keyed = encoded && aimem_knowledge_key(key, sizeof key, user, chain.knowledge_id);
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    qihse_kv_cas_result_t result = keyed && store ? qihse_kv_compare_set_user(
        store, key, NULL, encoded, qihse_user_get_classification(user),
        qihse_user_get_sci(user), user) : QIHSE_KV_CAS_FAILED;
    bool copied = result == QIHSE_KV_CAS_UPDATED && aimem_knowledge_copy(v, out);
    free(encoded); aimem_knowledge_chain_free(&chain);
    return copied ? QIHSE_AIMEM_WRITE_NEW : QIHSE_AIMEM_WRITE_FAILED;
}

qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_revise(
        qihse_resp_server_t* server, qihse_user_t* user,
        const char* knowledge_id, const char* expected_version_id,
        uint64_t expected_revision, uint32_t status, const char* content,
        qihse_ai_memory_knowledge_version_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    qihse_uuid_t parsed;
    if (!server || !user || !qihse_auth_user_is_active(user) || !knowledge_id ||
        !expected_version_id || !qihse_uuid_parse(expected_version_id, &parsed) ||
        !expected_revision || !aimem_knowledge_status_writable(user, status) ||
        !content || !*content || strlen(content) > AIMEM_KNOWLEDGE_MAX_CONTENT || !out)
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
    ok = qihse_uuid_generate(&version_uuid) && qihse_uuid_format(&version_uuid, next->version_id);
    snprintf(next->knowledge_id, sizeof next->knowledge_id, "%s", chain.knowledge_id);
    snprintf(next->supersedes_version, sizeof next->supersedes_version, "%s", prior->version_id);
    next->scope = chain.scope; next->type = chain.type; next->status = status;
    next->revision = prior->revision + 1u; next->created_at_ms = boundary;
    next->valid_from_ingest_ms = boundary; next->created_by = qihse_user_get_id(user);
    next->content = ok ? strdup(content) : NULL;
    chain.count++;
    char* encoded = next->content ? aimem_knowledge_chain_encode(&chain) : NULL;
    qihse_kv_record_meta_t meta;
    ok = encoded && qihse_kv_meta_user(store, key, user, &meta);
    qihse_kv_cas_result_t cas = ok ? qihse_kv_compare_set_user(store, key, raw,
        encoded, meta.classification, meta.sci_compartment, user) : QIHSE_KV_CAS_FAILED;
    bool copied = cas == QIHSE_KV_CAS_UPDATED && aimem_knowledge_copy(next, out);
    free(encoded); free(raw); aimem_knowledge_chain_free(&chain);
    pthread_mutex_unlock(&g_aimem_knowledge_lock);
    if (copied) return QIHSE_AIMEM_WRITE_NEW;
    return cas == QIHSE_KV_CAS_MISMATCH ? QIHSE_AIMEM_WRITE_CONFLICT
                                         : QIHSE_AIMEM_WRITE_FAILED;
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
