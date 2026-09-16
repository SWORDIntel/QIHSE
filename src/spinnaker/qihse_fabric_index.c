/*
 * QIHSE fabric artifact index — KEYSTONE hookup (ai_fabric.md build item 2).
 *
 * Loads KEYSTONE's libkeystone.so via dlopen at first use (soft dependency:
 * QIHSE builds and runs without KEYSTONE present). Every artifact written
 * under the `fabric:` KV prefix is
 *   1. semantically classified with KEYSTONE's DSMIL micro-model, and
 *   2. trigram indexed with candidate-only postings
 *      (keystone_trigram_index_add_document_external — KEYSTONE does NOT
 *      retain artifact content, so no second classified-data copy exists).
 *
 * Layout: one finalized KEYSTONE segment file per indexed artifact
 * (<dir>/seg_<seq>.kt3) plus an append-only manifest.tsv recording the
 * segment's fabric key, semantic class, confidence, and ingest-time
 * classification/SCI. Lookups intersect trigram candidates across segments
 * and disclose keys only to principals authorized for the recorded
 * classification per AGENTS.md invariant 1.
 *
 * ABI note: KEYSTONE's public headers (include/keystone_trigram.h,
 * include/dsmil_model_bridge.h, include/dsmil_micro_model.h) define the
 * contracts replicated here as local declarations so QIHSE never needs
 * KEYSTONE sources at build time.
 */

#include "qihse_fabric_index.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FABRIC_MAX_KEY 255u
#define FABRIC_MANIFEST "manifest.tsv"
#define FABRIC_SEG_CACHE_SIZE 32u
#define FABRIC_MAX_RECORDS (1024u * 1024u)
#define FABRIC_DEFAULT_DIR "/var/lib/qihse/fabric_index"
#define FABRIC_FALLBACK_DIR "/tmp/qihse_fabric_index"

/* ------------------------------------------------------------------ */
/* KEYSTONE ABI (replicated; see KEYSTONE include/ headers)            */
/* ------------------------------------------------------------------ */

#define KS_TRIGRAM_OK 0
#define KS_TRIGRAM_OPT_CASE_INSENSITIVE 1u

/* dsmil_model_context_t */
typedef struct {
    uint64_t target_offset;
    char pre_context[256];
    char post_context[256];
    char target_artifact[128];
    int is_truncated;
} ks_model_context_t;

/* dsmil_classification_t */
#define KS_CLASS_UNKNOWN 99

/* dsmil_classification_t dsmil_micro_model_infer(const ctx*, float[6]) */
typedef int (*ks_infer_fn)(const ks_model_context_t*, float*);

typedef void* (*ks_trigram_create_fn)(size_t, uint32_t);
typedef int (*ks_trigram_add_external_fn)(void*, const char*, const char*,
                                          size_t, uint32_t*);
typedef int (*ks_trigram_finalize_fn)(void*);
typedef int (*ks_trigram_save_fn)(const void*, const char*);
typedef void* (*ks_trigram_load_fn)(const char*);
typedef void (*ks_trigram_destroy_fn)(void*);
typedef size_t (*ks_trigram_doc_count_fn)(const void*);
typedef size_t (*ks_trigram_candidates_fn)(const void*, const char*, size_t,
                                           uint32_t*, size_t);
typedef const char* (*ks_version_fn)(void);

/* Layout must match KEYSTONE's compiled dsmil_model_context_t exactly. */
typedef char ks_ctx_size_check[(sizeof(ks_model_context_t) == 656u) ? 1 : -1];

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t seq;
    int32_t semantic_class; /* qihse_fabric_index_class_t value */
    float confidence;
    uint16_t classification;
    uint16_t sci_compartment;
    char key[FABRIC_MAX_KEY + 1u];
} fabric_record_t;

typedef struct {
    uint64_t seq;
    void* idx;
    uint64_t last_use;
} fabric_seg_cache_entry_t;

static pthread_mutex_t g_fabric_lock = PTHREAD_MUTEX_INITIALIZER;

static bool g_initialized;  /* init attempted; config is final */
static bool g_available;    /* libkeystone.so loaded and resolved */

static char g_index_dir[512];
static char g_lib_path[512];

static void* g_dl = NULL;
static ks_infer_fn ks_infer = NULL;
static ks_trigram_create_fn ks_trigram_create = NULL;
static ks_trigram_add_external_fn ks_trigram_add_external = NULL;
static ks_trigram_finalize_fn ks_trigram_finalize = NULL;
static ks_trigram_save_fn ks_trigram_save = NULL;
static ks_trigram_load_fn ks_trigram_load = NULL;
static ks_trigram_destroy_fn ks_trigram_destroy = NULL;
static ks_trigram_doc_count_fn ks_trigram_doc_count = NULL;
static ks_trigram_candidates_fn ks_trigram_candidates = NULL;
static ks_version_fn ks_version = NULL;

static fabric_record_t* g_records = NULL;
static size_t g_record_count = 0u;
static size_t g_record_capacity = 0u;
static uint64_t g_next_seq = 0u;

static fabric_seg_cache_entry_t g_seg_cache[FABRIC_SEG_CACHE_SIZE];
static uint64_t g_seg_use_clock = 0u;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void fabric_seg_cache_reset_locked(void) {
    if (ks_trigram_destroy) {
        for (size_t i = 0u; i < FABRIC_SEG_CACHE_SIZE; i++) {
            if (g_seg_cache[i].idx) {
                ks_trigram_destroy(g_seg_cache[i].idx);
                g_seg_cache[i].idx = NULL;
            }
            g_seg_cache[i].seq = 0u;
            g_seg_cache[i].last_use = 0u;
        }
    }
}

static void fabric_state_reset_locked(void) {
    fabric_seg_cache_reset_locked();
    free(g_records);
    g_records = NULL;
    g_record_count = 0u;
    g_record_capacity = 0u;
    g_next_seq = 0u;
    if (g_dl) {
        dlclose(g_dl);
        g_dl = NULL;
    }
    ks_infer = NULL;
    ks_trigram_create = NULL;
    ks_trigram_add_external = NULL;
    ks_trigram_finalize = NULL;
    ks_trigram_save = NULL;
    ks_trigram_load = NULL;
    ks_trigram_destroy = NULL;
    ks_trigram_doc_count = NULL;
    ks_trigram_candidates = NULL;
    ks_version = NULL;
    g_available = false;
    g_index_dir[0] = '\0';
    g_lib_path[0] = '\0';
}

static void fabric_ensure_directory(const char* path) {
    char tmp[512];
    size_t len = strlen(path);
    if (len == 0u || len >= sizeof(tmp)) return;
    memcpy(tmp, path, len + 1u);
    for (size_t i = 1u; i < len; i++) {
        if (tmp[i] != '/') continue;
        tmp[i] = '\0';
        if (tmp[0] != '\0') (void)mkdir(tmp, 0700);
        tmp[i] = '/';
    }
    (void)mkdir(tmp, 0700);
}

static bool fabric_key_is_indexable(const char* key) {
    if (!key || key[0] == '\0') return false;
    size_t len = strlen(key);
    if (len > FABRIC_MAX_KEY) return false;
    for (size_t i = 0u; i < len; i++) {
        if (key[i] == '\t' || key[i] == '\n' || key[i] == '\r') return false;
    }
    return true;
}

static void fabric_seg_path_locked(uint64_t seq, char* out, size_t out_size) {
    snprintf(out, out_size, "%s/seg_%016llu.kt3", g_index_dir,
             (unsigned long long)seq);
}

static bool fabric_record_grow_locked(void) {
    if (g_record_count < g_record_capacity) return true;
    size_t new_cap = g_record_capacity ? g_record_capacity * 2u : 64u;
    if (g_record_count >= FABRIC_MAX_RECORDS) return false;
    fabric_record_t* grown =
        (fabric_record_t*)realloc(g_records, new_cap * sizeof(fabric_record_t));
    if (!grown) return false;
    g_records = grown;
    g_record_capacity = new_cap;
    return true;
}

static bool fabric_manifest_reload_locked(void) {
    char path[640];
    FILE* fp;
    char line[1024];

    snprintf(path, sizeof(path), "%s/" FABRIC_MANIFEST, g_index_dir);
    fp = fopen(path, "r");
    if (!fp) return true; /* fresh index */

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long seq = 0u;
        int cls = 0;
        float conf = 0.0f;
        unsigned int classif = 0u;
        unsigned int sci = 0u;
        char key[FABRIC_MAX_KEY + 1u] = {0};
        int n = sscanf(line, "%llu\t%d\t%f\t%u\t%u\t%255[^\t\n]", &seq, &cls,
                       &conf, &classif, &sci, key);
        if (n != 6) continue;
        if (seq >= FABRIC_MAX_RECORDS * 2u) continue;
        if (!fabric_record_grow_locked()) break;
        fabric_record_t* rec = &g_records[g_record_count++];
        rec->seq = (uint64_t)seq;
        rec->semantic_class = (int32_t)cls;
        rec->confidence = conf;
        rec->classification = (uint16_t)classif;
        rec->sci_compartment = (uint16_t)sci;
        memcpy(rec->key, key, sizeof(rec->key));
        rec->key[sizeof(rec->key) - 1u] = '\0';
        if ((uint64_t)seq >= g_next_seq) g_next_seq = seq + 1u;
    }
    fclose(fp);
    return true;
}

static void* fabric_seg_get_locked(uint64_t seq) {
    uint64_t now = ++g_seg_use_clock;
    size_t victim = FABRIC_SEG_CACHE_SIZE;
    uint64_t oldest = UINT64_MAX;

    for (size_t i = 0u; i < FABRIC_SEG_CACHE_SIZE; i++) {
        fabric_seg_cache_entry_t* e = &g_seg_cache[i];
        if (e->idx && e->seq == seq) {
            e->last_use = now;
            return e->idx;
        }
        if (!e->idx || e->last_use < oldest) {
            oldest = e->idx ? e->last_use : 0u;
            victim = i;
            if (!e->idx) break;
        }
    }
    if (victim == FABRIC_SEG_CACHE_SIZE) return NULL;

    char path[640];
    fabric_seg_path_locked(seq, path, sizeof(path));
    void* idx = ks_trigram_load(path);
    if (!idx) return NULL;

    fabric_seg_cache_entry_t* e = &g_seg_cache[victim];
    if (e->idx) ks_trigram_destroy(e->idx);
    e->idx = idx;
    e->seq = seq;
    e->last_use = now;
    return idx;
}

static void fabric_fill_model_context(const char* value, size_t value_len,
                                      ks_model_context_t* ctx) {
    memset(ctx, 0, sizeof(*ctx));
    size_t off = 0u;

    size_t n = value_len < 255u ? value_len : 255u;
    if (n) memcpy(ctx->pre_context, value + off, n);
    off += n;

    size_t remaining = value_len - off;
    n = remaining < 127u ? remaining : 127u;
    if (n) memcpy(ctx->target_artifact, value + off, n);
    off += n;

    remaining = value_len - off;
    n = remaining < 255u ? remaining : 255u;
    if (n) memcpy(ctx->post_context, value + off, n);
    off += n;

    ctx->target_offset = 0u;
    ctx->is_truncated = (off < value_len) ? 1 : 0;
}

/* All pointer-bearing dlsym resolutions; any miss fails the load. */
static bool fabric_resolve_symbols_locked(void) {
    struct {
        const char* name;
        void** out;
    } needed[] = {
        { "keystone_version", (void**)&ks_version },
        { "dsmil_micro_model_infer", (void**)&ks_infer },
        { "keystone_trigram_index_create_options", (void**)&ks_trigram_create },
        { "keystone_trigram_index_add_document_external",
          (void**)&ks_trigram_add_external },
        { "keystone_trigram_index_finalize", (void**)&ks_trigram_finalize },
        { "keystone_trigram_index_save", (void**)&ks_trigram_save },
        { "keystone_trigram_index_load", (void**)&ks_trigram_load },
        { "keystone_trigram_index_destroy", (void**)&ks_trigram_destroy },
        { "keystone_trigram_index_document_count",
          (void**)&ks_trigram_doc_count },
        { "keystone_trigram_index_get_candidates",
          (void**)&ks_trigram_candidates },
    };

    for (size_t i = 0u; i < sizeof(needed) / sizeof(needed[0]); i++) {
        void* sym = dlsym(g_dl, needed[i].name);
        if (!sym) return false;
        *needed[i].out = sym;
    }
    return true;
}

static void fabric_lazy_init_locked(void) {
    if (g_initialized) return;
    g_initialized = true;

    /* Index directory: explicit > env > default with /tmp fallback. */
    const char* dir = g_index_dir[0] ? g_index_dir : getenv("QIHSE_FABRIC_INDEX_DIR");
    if (!dir || !*dir) dir = FABRIC_DEFAULT_DIR;
    fabric_ensure_directory(dir);
    /* Verify the directory is usable before committing to it. */
    char probe[640];
    snprintf(probe, sizeof(probe), "%s/.access", dir);
    FILE* pf = fopen(probe, "w");
    if (pf) {
        fclose(pf);
        (void)remove(probe);
    } else {
        dir = FABRIC_FALLBACK_DIR;
        fabric_ensure_directory(dir);
    }
    if (dir != g_index_dir) {
        /* Never snprintf a buffer onto itself: overlapping copy is UB and
         * glibc demonstrably produces an empty string for exact aliasing. */
        snprintf(g_index_dir, sizeof(g_index_dir), "%s", dir);
    }

    /* KEYSTONE library resolution. An explicitly configured path (argument or
     * QIHSE_KEYSTONE_LIB) is authoritative: if it fails to load, the index
     * stays unavailable rather than silently falling back elsewhere. Without
     * explicit configuration, well-known locations are probed in order. */
    char paths[4][512];
    size_t tries = 0u;
    size_t loaded = 0u;
    if (g_lib_path[0]) {
        snprintf(paths[tries++], sizeof(paths[0]), "%s", g_lib_path);
    } else {
        const char* env_lib = getenv("QIHSE_KEYSTONE_LIB");
        const char* home = getenv("HOME");
        if (env_lib && *env_lib) {
            snprintf(paths[tries++], sizeof(paths[0]), "%s", env_lib);
        } else {
            if (home && *home)
                snprintf(paths[tries++], sizeof(paths[0]),
                         "%s/Documents/KEYSTONE/libkeystone.so", home);
            snprintf(paths[tries++], sizeof(paths[0]), "%s", "./libkeystone.so");
            snprintf(paths[tries++], sizeof(paths[0]), "%s", "libkeystone.so");
        }
    }

    for (size_t i = 0u; i < tries && !g_available; i++) {
        g_dl = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (!g_dl) continue;
        if (fabric_resolve_symbols_locked()) {
            g_available = true;
            loaded = i;
        } else {
            dlclose(g_dl);
            g_dl = NULL;
        }
    }
    if (g_available) snprintf(g_lib_path, sizeof(g_lib_path), "%s", paths[loaded]);

    (void)fabric_manifest_reload_locked();
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int qihse_fabric_index_init(const char* index_dir, const char* library) {
    if (index_dir && strlen(index_dir) >= sizeof(g_index_dir)) return QIHSE_FABRIC_INDEX_EINVAL;
    if (library && strlen(library) >= sizeof(g_lib_path)) return QIHSE_FABRIC_INDEX_EINVAL;

    pthread_mutex_lock(&g_fabric_lock);
    if (!g_initialized) {
        if (index_dir && *index_dir) snprintf(g_index_dir, sizeof(g_index_dir), "%s", index_dir);
        if (library && *library) snprintf(g_lib_path, sizeof(g_lib_path), "%s", library);
        fabric_lazy_init_locked();
    }
    int rc = g_available ? QIHSE_FABRIC_INDEX_OK : QIHSE_FABRIC_INDEX_EUNAVAILABLE;
    pthread_mutex_unlock(&g_fabric_lock);
    return rc;
}

void qihse_fabric_index_shutdown(void) {
    pthread_mutex_lock(&g_fabric_lock);
    fabric_state_reset_locked();
    g_initialized = false;
    pthread_mutex_unlock(&g_fabric_lock);
}

bool qihse_fabric_index_is_available(void) {
    pthread_mutex_lock(&g_fabric_lock);
    fabric_lazy_init_locked();
    bool available = g_available;
    pthread_mutex_unlock(&g_fabric_lock);
    return available;
}

int qihse_fabric_index_artifact_user(const char* key, const char* value,
                                     size_t value_len, uint16_t classification,
                                     uint16_t sci_compartment,
                                     qihse_user_t* user) {
    if (!key || !fabric_key_is_indexable(key)) return QIHSE_FABRIC_INDEX_EINVAL;
    if (!value && value_len > 0u) return QIHSE_FABRIC_INDEX_EINVAL;

    /* Defensive write-path authorization (KV already gated the write). */
    if (!qihse_auth_can_access(user, classification, sci_compartment))
        return QIHSE_FABRIC_INDEX_EDENIED;

    pthread_mutex_lock(&g_fabric_lock);
    fabric_lazy_init_locked();
    if (!g_available) {
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EUNAVAILABLE;
    }
    if (g_record_count >= FABRIC_MAX_RECORDS) {
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EFULL;
    }
    if (!fabric_record_grow_locked()) {
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EIO;
    }

    /* 1. Semantic classification (DSMIL micro-model, confidence-gated). */
    ks_model_context_t ctx;
    fabric_fill_model_context(value ? value : "", value_len, &ctx);
    float scores[6];
    int cls = ks_infer(&ctx, scores);
    memset(&ctx, 0, sizeof(ctx));
    float confidence = (cls >= 0 && cls < 6) ? scores[cls] : 0.0f;

    /* 2. Trigram indexing — candidate-only postings, content not retained. */
    void* idx = ks_trigram_create(1u, KS_TRIGRAM_OPT_CASE_INSENSITIVE);
    if (!idx) {
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EIO;
    }
    uint32_t doc_id = 0u;
    int rc = ks_trigram_add_external(idx, key, value ? value : "", value_len, &doc_id);
    if (rc == KS_TRIGRAM_OK) rc = ks_trigram_finalize(idx);

    char seg_path[640];
    fabric_seg_path_locked(g_next_seq, seg_path, sizeof(seg_path));
    if (rc == KS_TRIGRAM_OK) rc = ks_trigram_save(idx, seg_path);
    ks_trigram_destroy(idx);
    if (rc != KS_TRIGRAM_OK) {
        (void)remove(seg_path);
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EIO;
    }

    /* 3. Manifest append + in-memory record. Order: record slot reserved
     * above, segment saved, manifest committed last so a crash leaves at
     * worst an unreferenced segment file, never a dangling manifest entry. */
    char manifest_path[640];
    snprintf(manifest_path, sizeof(manifest_path), "%s/" FABRIC_MANIFEST,
             g_index_dir);
    FILE* fp = fopen(manifest_path, "a");
    if (!fp) {
        (void)remove(seg_path);
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EIO;
    }
    fprintf(fp, "%llu\t%d\t%.6f\t%u\t%u\t%s\n",
            (unsigned long long)g_next_seq, cls, (double)confidence,
            (unsigned int)classification, (unsigned int)sci_compartment, key);
    fclose(fp);

    fabric_record_t* rec = &g_records[g_record_count++];
    rec->seq = g_next_seq;
    rec->semantic_class = (int32_t)cls;
    rec->confidence = confidence;
    rec->classification = classification;
    rec->sci_compartment = sci_compartment;
    snprintf(rec->key, sizeof(rec->key), "%s", key);
    g_next_seq++;

    pthread_mutex_unlock(&g_fabric_lock);
    return QIHSE_FABRIC_INDEX_OK;
}

int qihse_fabric_index_lookup_user(const char* pattern, qihse_user_t* user,
                                   qihse_fabric_index_record_t* out_records,
                                   size_t max_records, size_t* out_count) {
    if (out_count) *out_count = 0u;
    if (!pattern || !out_records || max_records == 0u || !out_count)
        return QIHSE_FABRIC_INDEX_EINVAL;

    /* Invariant 1: searching indexed fabric artifacts is a classified-capable
     * disclosure surface. No authenticated context, no results — ever. */
    if (!user) return QIHSE_FABRIC_INDEX_EDENIED;

    pthread_mutex_lock(&g_fabric_lock);
    fabric_lazy_init_locked();
    if (!g_available) {
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EUNAVAILABLE;
    }

    size_t pattern_len = strlen(pattern);
    size_t found = 0u;
    for (size_t i = 0u; i < g_record_count && found < max_records; i++) {
        fabric_record_t* rec = &g_records[i];
        void* idx = fabric_seg_get_locked(rec->seq);
        if (!idx) continue; /* missing/corrupt segment: skip, keep querying */

        uint32_t candidates[64];
        size_t n = ks_trigram_candidates(idx, pattern, pattern_len, candidates,
                                         sizeof(candidates) / sizeof(candidates[0]));
        for (size_t c = 0u; c < n && found < max_records; c++) {
            /* One artifact per segment: any candidate doc-id refers to rec. */
            if (!qihse_auth_can_access(user, rec->classification,
                                       rec->sci_compartment))
                continue;
            out_records[found].seq = rec->seq;
            out_records[found].semantic_class =
                (qihse_fabric_index_class_t)rec->semantic_class;
            out_records[found].confidence = rec->confidence;
            out_records[found].classification = rec->classification;
            out_records[found].sci_compartment = rec->sci_compartment;
            memcpy(out_records[found].key, rec->key, sizeof(rec->key));
            out_records[found].key[sizeof(out_records[found].key) - 1u] = '\0';
            found++;
        }
    }
    *out_count = found;
    pthread_mutex_unlock(&g_fabric_lock);
    return QIHSE_FABRIC_INDEX_OK;
}

int qihse_fabric_index_by_class_user(qihse_fabric_index_class_t cls,
                                     qihse_user_t* user,
                                     qihse_fabric_index_record_t* out_records,
                                     size_t max_records, size_t* out_count) {
    if (out_count) *out_count = 0u;
    if (!out_records || max_records == 0u || !out_count)
        return QIHSE_FABRIC_INDEX_EINVAL;
    if (!user) return QIHSE_FABRIC_INDEX_EDENIED;

    pthread_mutex_lock(&g_fabric_lock);
    fabric_lazy_init_locked();
    if (!g_available) {
        pthread_mutex_unlock(&g_fabric_lock);
        return QIHSE_FABRIC_INDEX_EUNAVAILABLE;
    }

    size_t found = 0u;
    for (size_t i = 0u; i < g_record_count && found < max_records; i++) {
        fabric_record_t* rec = &g_records[i];
        if ((qihse_fabric_index_class_t)rec->semantic_class != cls) continue;
        if (!qihse_auth_can_access(user, rec->classification,
                                   rec->sci_compartment))
            continue;
        out_records[found].seq = rec->seq;
        out_records[found].semantic_class =
            (qihse_fabric_index_class_t)rec->semantic_class;
        out_records[found].confidence = rec->confidence;
        out_records[found].classification = rec->classification;
        out_records[found].sci_compartment = rec->sci_compartment;
        memcpy(out_records[found].key, rec->key, sizeof(rec->key));
        out_records[found].key[sizeof(out_records[found].key) - 1u] = '\0';
        found++;
    }
    *out_count = found;
    pthread_mutex_unlock(&g_fabric_lock);
    return QIHSE_FABRIC_INDEX_OK;
}

size_t qihse_fabric_index_record_count(void) {
    pthread_mutex_lock(&g_fabric_lock);
    fabric_lazy_init_locked();
    size_t count = g_record_count;
    pthread_mutex_unlock(&g_fabric_lock);
    return count;
}

const char* qihse_fabric_index_class_name(qihse_fabric_index_class_t cls) {
    switch (cls) {
        case QIHSE_FABRIC_CLASS_GENERIC: return "GENERIC";
        case QIHSE_FABRIC_CLASS_FINANCIAL: return "FINANCIAL";
        case QIHSE_FABRIC_CLASS_CORPORATE: return "CORPORATE";
        case QIHSE_FABRIC_CLASS_GOVERNMENT: return "GOVERNMENT";
        case QIHSE_FABRIC_CLASS_HEALTHCARE: return "HEALTHCARE";
        case QIHSE_FABRIC_CLASS_TECHNOLOGY: return "TECHNOLOGY";
        case QIHSE_FABRIC_CLASS_UNKNOWN:
        default: return "UNKNOWN";
    }
}

const char* qihse_fabric_index_keystone_version(void) {
    pthread_mutex_lock(&g_fabric_lock);
    fabric_lazy_init_locked();
    const char* v = g_available && ks_version ? ks_version() : NULL;
    pthread_mutex_unlock(&g_fabric_lock);
    return v;
}
