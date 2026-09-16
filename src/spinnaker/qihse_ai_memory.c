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
 */
#include "qihse_ai_memory.h"

#include "qihse_federation.h"
#include "qihse_fts.h"
#include "qihse_kv_store.h"

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

static bool aimem_parse_record(const char* value, qihse_ai_memory_hit_t* out) {
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
    out->text = strdup(end + 1);
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
    pthread_mutex_unlock(&g_aimem_lock);
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

size_t qihse_ai_memory_recall(qihse_resp_server_t* server, qihse_user_t* user,
                              const char* query, size_t limit,
                              qihse_ai_memory_hit_t* out, size_t out_cap) {
    if (!server || !user || !query || !*query || !out || out_cap == 0) return 0;
    size_t want = limit ? limit : 10u;
    if (want > out_cap) want = out_cap;
    if (want > 256u) want = 256u;

    qihse_fts_result_t results[256];
    pthread_mutex_lock(&g_aimem_lock);
    if (!aimem_index_ensure(server, NULL)) {
        pthread_mutex_unlock(&g_aimem_lock);
        return 0;
    }
    int found = qihse_fts_search_user(g_aimem_index, query, user, results, (int)want);
    pthread_mutex_unlock(&g_aimem_lock);
    if (found <= 0) return 0;

    size_t written = 0;
    for (int i = 0; i < found && written < want; i++) {
        /* doc_id -> uuid: the id is stored in the record, so fetch by key. */
        qihse_kv_store_t* store = qihse_resp_server_store(server);
        char key[64];
        aimem_key(key, sizeof key, results[i].doc_id);
        char* value = qihse_kv_get_user(store, key, user);
        if (!value) continue; /* forgotten, or not visible to this principal */
        qihse_ai_memory_hit_t hit;
        memset(&hit, 0, sizeof hit);
        if (aimem_parse_record(value, &hit)) {
            hit.score = results[i].bm25_score;
            out[written++] = hit;
        }
        free(value);
    }
    return written;
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
    return qihse_kv_del_user(store, key, user);
}

typedef struct {
    size_t count;
} aimem_count_t;

static bool aimem_count_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    aimem_count_t* c = (aimem_count_t*)user_data;
    if (strncmp(key, AIMEM_PREFIX, AIMEM_PREFIX_LEN) == 0) c->count++;
    return true;
}

size_t qihse_ai_memory_count(qihse_resp_server_t* server, qihse_user_t* user) {
    if (!server || !user) return 0;
    qihse_kv_store_t* store = qihse_resp_server_store(server);
    if (!store) return 0;
    aimem_count_t c = { 0 };
    qihse_kv_foreach_user(store, user, aimem_count_cb, &c);
    return c.count;
}

void qihse_ai_memory_hits_free(qihse_ai_memory_hit_t* hits, size_t count) {
    if (!hits) return;
    for (size_t i = 0; i < count; i++) {
        free(hits[i].text);
        hits[i].text = NULL;
    }
}
