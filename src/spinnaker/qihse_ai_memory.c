/* Local-first AI memory over the native KV store + FTS index.
 *
 * Record layout:
 *   key   aimem:<doc-id as 16 hex chars>
 *   value <uuid>|<created_ms>|<kind>|<classif>|<sci>|<text>
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
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AIMEM_PREFIX "aimem:"
#define AIMEM_PREFIX_LEN (sizeof(AIMEM_PREFIX) - 1u)
#define AIMEM_MAX_TEXT (64u * 1024u)

static qihse_fts_index_t* g_aimem_index = NULL;
static pthread_mutex_t g_aimem_lock = PTHREAD_MUTEX_INITIALIZER;

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

/* Parse the fixed-width header fields, leaving the body in the record. A
 * count needs the kind and nothing else, and must not strdup a 64 KB body per
 * record to find it. `text_out` receives the body when the caller wants it. */
static bool aimem_parse_header(const char* value, qihse_ai_memory_hit_t* out,
                               const char** text_out) {
    /* <uuid>|<created_ms>|<kind>|<classif>|<sci>|<text> */
    const char* p = value;
    const char* bar = strchr(p, '|');
    if (!bar || (size_t)(bar - p) != QIHSE_AIMEM_ID_LEN) return false;
    memcpy(out->id, p, QIHSE_AIMEM_ID_LEN);
    out->id[QIHSE_AIMEM_ID_LEN] = '\0';
    p = bar + 1;
    char* end = NULL;
    out->created_ms = strtoull(p, &end, 10);
    if (!end || *end != '|') return false;
    p = end + 1;
    out->kind = (uint32_t)strtoul(p, &end, 10);
    if (!end || *end != '|') return false;
    p = end + 1;
    out->classification = (uint16_t)strtoul(p, &end, 10);
    if (!end || *end != '|') return false;
    p = end + 1;
    out->sci_compartment = (uint16_t)strtoul(p, &end, 10);
    if (!end || *end != '|') return false;
    if (text_out) *text_out = end + 1;
    return true;
}

static bool aimem_parse_record(const char* value, qihse_ai_memory_hit_t* out) {
    const char* text = NULL;
    if (!aimem_parse_header(value, out, &text)) return false;
    out->text = strdup(text);
    return out->text != NULL;
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
    if (!aimem_parse_record(value, &hit)) return true;
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

static void aimem_vecs_clear(void) {
    for (size_t i = 0; i < g_aimem_vec_count; i++) free(g_aimem_vecs[i].vec);
    free(g_aimem_vecs);
    g_aimem_vecs = NULL;
    g_aimem_vec_count = 0;
    g_aimem_vec_cap = 0;
    g_aimem_vecs_loaded = false;
}

static bool aimem_vecs_push(uint64_t doc_id, const float* vec, size_t dim) {
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
    if (aimem_vecs_push(doc_id, vec, dim)) rb->loaded++;
    return true;
}

/* Caller holds g_aimem_lock. */
static bool aimem_vecs_ensure(qihse_resp_server_t* server) {
    if (g_aimem_vecs_loaded) return true;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    aimem_vec_rebuild_t rb = { 0 };
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
 * were already excluded at load time. */
static size_t aimem_vec_search(const float* qvec, size_t qdim, size_t want,
                               aimem_cand_t* out) {
    size_t written = 0;
    for (size_t i = 0; i < g_aimem_vec_count; i++) {
        if (g_aimem_vecs[i].dim != qdim) continue;
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

bool qihse_ai_memory_store(qihse_resp_server_t* server, qihse_user_t* user,
                           const char* text, uint32_t kind,
                           char out_id[QIHSE_AIMEM_ID_LEN + 1u]) {
    if (!server || !user || !text || !*text) return false;
    if (kind != QIHSE_AIMEM_EPISODIC && kind != QIHSE_AIMEM_SEMANTIC) return false;
    size_t text_len = strlen(text);
    if (text_len == 0 || text_len > AIMEM_MAX_TEXT) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;

    qihse_uuid_t uuid;
    if (!qihse_uuid_generate(&uuid)) return false;
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    if (!qihse_uuid_format(&uuid, id)) return false;

    uint16_t classification = qihse_user_get_classification(user);
    uint16_t sci = qihse_user_get_sci(user);

    char* value = malloc(text_len + 128u);
    if (!value) return false;
    int n = snprintf(value, text_len + 128u, "%s|%llu|%u|%u|%u|%s", id,
                     (unsigned long long)aimem_now_ms(), (unsigned)kind,
                     (unsigned)classification, (unsigned)sci, text);
    if (n <= 0) {
        free(value);
        return false;
    }

    char key[64];
    aimem_key(key, sizeof key, aimem_doc_id(&uuid));
    bool ok = qihse_kv_set_user(store, key, value, classification, sci, user);
    free(value);
    if (!ok) return false;

    /* Embed and persist the vector. A failure here is NOT fatal: the record is
     * durable and still recallable lexically, so semantic ranking simply does
     * not see it. Losing recall quality is better than losing the memory. */
    {
        float vec[QIHSE_AIMEM_MAX_DIM];
        size_t dim = g_aimem_embedder.dim;
        if (dim && dim <= QIHSE_AIMEM_MAX_DIM &&
            g_aimem_embedder.embed(text, vec, dim, g_aimem_embedder.ctx)) {
            if (!aimem_vec_store(store, user, aimem_doc_id(&uuid), vec, dim,
                                 classification, sci)) {
                fprintf(stderr, "qihse-ai-memory: record stored without a vector (id %s)\n", id);
            } else {
                pthread_mutex_lock(&g_aimem_lock);
                if (g_aimem_vecs_loaded) (void)aimem_vecs_push(aimem_doc_id(&uuid), vec, dim);
                pthread_mutex_unlock(&g_aimem_lock);
            }
        }
    }

    pthread_mutex_lock(&g_aimem_lock);
    bool rebuilt_now = false;
    bool have_index = aimem_index_ensure(server, &rebuilt_now);
    bool indexed = have_index &&
                   (rebuilt_now ||
                    qihse_fts_add_document_user(g_aimem_index, aimem_doc_id(&uuid), text,
                                                text_len, classification, sci,
                                                QIHSE_KEYSTONE_CLASS_UNKNOWN, user));
    pthread_mutex_unlock(&g_aimem_lock);
    if (!indexed) {
        /* Durable record without an index entry: recall by id still works. */
        fprintf(stderr, "qihse-ai-memory: record stored but not indexed (id %s)\n", id);
    }
    if (out_id) memcpy(out_id, id, sizeof id);
    return true;
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
           kind == QIHSE_AIMEM_SEMANTIC;
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
    bool ok = aimem_parse_record(value, out);
    free(value);
    return ok;
}

bool qihse_ai_memory_get(qihse_resp_server_t* server, qihse_user_t* user,
                         const char* id, qihse_ai_memory_hit_t* out) {
    if (!server || !user || !id || !out) return false;
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
    bool ok = aimem_parse_record(value, out);
    free(value);
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
    if (!server || !user || !query || !*query || !out || out_cap == 0) return 0;
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
            n_vector = aimem_vec_search(qvec, qdim, cand_want, vector);
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
    if (!server || !user || !id) return false;
    qihse_uuid_t uuid;
    if (!qihse_uuid_parse(id, &uuid)) return false;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return false;
    char key[64];
    aimem_key(key, sizeof key, aimem_doc_id(&uuid));
    bool ok = qihse_kv_del_user(store, key, user);
    /* Drop the vector as well, or a forgotten memory would keep ranking in
     * semantic recall. Its KV record is gone so it would not be returned, but
     * a stale vector still consumes a candidate slot and can push a visible
     * memory out of the top-k. */
    char vkey[64];
    aimem_vec_key(vkey, sizeof vkey, aimem_doc_id(&uuid));
    (void)qihse_kv_del_user(store, vkey, user);
    return ok;
}

typedef struct {
    size_t count;
    uint32_t kind; /* QIHSE_AIMEM_KIND_ANY counts every visible record */
} aimem_count_t;

static bool aimem_count_cb(const char* key, const char* value, void* user_data) {
    aimem_count_t* c = (aimem_count_t*)user_data;
    if (strncmp(key, AIMEM_PREFIX, AIMEM_PREFIX_LEN) != 0) return true;
    if (c->kind == QIHSE_AIMEM_KIND_ANY) {
        c->count++;
        return true;
    }
    /* Parse the header rather than substring-match a field separator: a body
     * containing "|2|" is not a semantic memory. No body is copied — counting
     * must not duplicate a 64 KB text per record to read one field. */
    qihse_ai_memory_hit_t hit;
    memset(&hit, 0, sizeof hit);
    if (aimem_parse_header(value, &hit, NULL) && hit.kind == c->kind) c->count++;
    return true;
}

size_t qihse_ai_memory_count_kind(qihse_resp_server_t* server, qihse_user_t* user,
                                  uint32_t kind) {
    if (!server || !user) return 0;
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

void qihse_ai_memory_hits_free(qihse_ai_memory_hit_t* hits, size_t count) {
    if (!hits) return;
    for (size_t i = 0; i < count; i++) {
        free(hits[i].text);
        hits[i].text = NULL;
    }
}
