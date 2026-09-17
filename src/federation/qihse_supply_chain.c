/*
 * QIHSE supply-chain substrate — federation stage F6.
 *
 * Provenance graph, build-job coordination state, builder capability and
 * history, SBOM/attestation evidence, immutable vulnerability observations,
 * and immutable repository snapshots.
 * See docs/plans/qihse_federation_upgrade_plan.md §27–§35.
 *
 * QIHSE stores coordination state and evidence.  It never invokes compilers
 * or executes arbitrary commands, and it never holds private signing keys.
 */
#include "qihse_supply_chain.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "qihse_kv_store.h"



/* ── Record field splitting ────────────────────────────────────────────── */

/* Records are tab-separated and many fields are legitimately empty (an
 * unset label, an absent failure reason, a record with no signature yet).
 * sscanf's "%[^\t]" cannot match an empty field, so decoders walk the
 * record with this splitter instead.  Returns the start of the next field,
 * or NULL when the record is exhausted. */
static const char* next_field(const char* p, char* out, size_t cap) {
    if (!p) { if (cap) out[0] = '\0'; return NULL; }
    const char* start = p;
    while (*p && *p != '\t') p++;
    size_t len = (size_t)(p - start);
    if (len >= cap) len = cap - 1u;
    if (cap) { memcpy(out, start, len); out[len] = '\0'; }
    return (*p == '\t') ? p + 1 : NULL;
}

/* Parse a hex-encoded UUID field. */
static bool hex_to_uuid(const char* hex, qihse_uuid_t* out) {
    if (!hex || strlen(hex) != 32) return false;
    uint8_t* b = (uint8_t*)out;
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        b[i] = (uint8_t)byte;
    }
    return true;
}

static void uuid_to_hex(const qihse_uuid_t* u, char* out) {
    const uint8_t* b = (const uint8_t*)u;
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", b[i]);
    out[32] = '\0';
}

/* ── Entity / edge vocabulary ──────────────────────────────────────────── */

typedef struct { qihse_prov_entity_t v; const char* name; } prov_entity_entry_t;

static const prov_entity_entry_t g_prov_entities[] = {
    { QIHSE_PROV_SOURCE_REPOSITORY,        "SOURCE_REPOSITORY"        },
    { QIHSE_PROV_SOURCE_REVISION,          "SOURCE_REVISION"          },
    { QIHSE_PROV_SOURCE_ARCHIVE,           "SOURCE_ARCHIVE"           },
    { QIHSE_PROV_PATCHSET,                 "PATCHSET"                 },
    { QIHSE_PROV_BUILD_RECIPE,             "BUILD_RECIPE"             },
    { QIHSE_PROV_BUILD_PROFILE,            "BUILD_PROFILE"            },
    { QIHSE_PROV_TOOLCHAIN,                "TOOLCHAIN"                },
    { QIHSE_PROV_BUILD_DEPENDENCY,         "BUILD_DEPENDENCY"         },
    { QIHSE_PROV_BUILDER_NODE,             "BUILDER_NODE"             },
    { QIHSE_PROV_BUILD_WORKER_IMAGE,       "BUILD_WORKER_IMAGE"       },
    { QIHSE_PROV_BUILD_JOB,                "BUILD_JOB"                },
    { QIHSE_PROV_TEST_RESULT,              "TEST_RESULT"              },
    { QIHSE_PROV_OUTPUT_ARTIFACT,          "OUTPUT_ARTIFACT"          },
    { QIHSE_PROV_DEB_PACKAGE,              "DEB_PACKAGE"              },
    { QIHSE_PROV_SBOM,                     "SBOM"                     },
    { QIHSE_PROV_ATTESTATION,              "ATTESTATION"              },
    { QIHSE_PROV_APT_REPOSITORY_SNAPSHOT,  "APT_REPOSITORY_SNAPSHOT"  },
    { QIHSE_PROV_ROOT_IMAGE,               "ROOT_IMAGE"               },
    { QIHSE_PROV_DEPLOYMENT,               "DEPLOYMENT"               },
    { QIHSE_PROV_NODE,                     "NODE"                     },
    { QIHSE_PROV_VULNERABILITY_OBSERVATION, "VULNERABILITY_OBSERVATION" },
};

const char* qihse_prov_entity_name(qihse_prov_entity_t entity) {
    for (size_t i = 0; i < sizeof(g_prov_entities) / sizeof(g_prov_entities[0]); i++) {
        if (g_prov_entities[i].v == entity) return g_prov_entities[i].name;
    }
    return "UNKNOWN";
}

bool qihse_prov_entity_parse(const char* name, qihse_prov_entity_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_prov_entities) / sizeof(g_prov_entities[0]); i++) {
        if (strcasecmp(g_prov_entities[i].name, name) == 0) {
            *out = g_prov_entities[i].v;
            return true;
        }
    }
    return false;
}

typedef struct { qihse_prov_edge_t v; const char* name; } prov_edge_entry_t;

static const prov_edge_entry_t g_prov_edges[] = {
    { QIHSE_PROV_EDGE_DERIVED_FROM,      "DERIVED_FROM"      },
    { QIHSE_PROV_EDGE_PATCHED_BY,        "PATCHED_BY"        },
    { QIHSE_PROV_EDGE_BUILT_WITH,        "BUILT_WITH"        },
    { QIHSE_PROV_EDGE_BUILD_DEPENDS_ON,  "BUILD_DEPENDS_ON"  },
    { QIHSE_PROV_EDGE_BUILT_ON,          "BUILT_ON"          },
    { QIHSE_PROV_EDGE_BUILT_IN,          "BUILT_IN"          },
    { QIHSE_PROV_EDGE_PRODUCES,          "PRODUCES"          },
    { QIHSE_PROV_EDGE_DESCRIBED_BY,      "DESCRIBED_BY"      },
    { QIHSE_PROV_EDGE_ATTESTED_BY,       "ATTESTED_BY"       },
    { QIHSE_PROV_EDGE_PUBLISHED_IN,      "PUBLISHED_IN"      },
    { QIHSE_PROV_EDGE_CONTAINED_IN,      "CONTAINED_IN"      },
    { QIHSE_PROV_EDGE_DEPLOYED_TO,       "DEPLOYED_TO"       },
    { QIHSE_PROV_EDGE_AFFECTED_BY,       "AFFECTED_BY"       },
    { QIHSE_PROV_EDGE_SUPERSEDES,        "SUPERSEDES"        },
    { QIHSE_PROV_EDGE_VERIFIED_AGAINST,  "VERIFIED_AGAINST"  },
};

const char* qihse_prov_edge_name(qihse_prov_edge_t edge) {
    for (size_t i = 0; i < sizeof(g_prov_edges) / sizeof(g_prov_edges[0]); i++) {
        if (g_prov_edges[i].v == edge) return g_prov_edges[i].name;
    }
    return "UNKNOWN";
}

bool qihse_prov_edge_parse(const char* name, qihse_prov_edge_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_prov_edges) / sizeof(g_prov_edges[0]); i++) {
        if (strcasecmp(g_prov_edges[i].name, name) == 0) {
            *out = g_prov_edges[i].v;
            return true;
        }
    }
    return false;
}

/* ── Provenance graph storage ──────────────────────────────────────────── */

/* The graph is mutated under a lock so traversal never observes a
 * half-written edge.  Records are plain KV entries so the KEYSTONE indexer
 * can read them with FEDERATION_READ alone. */
static pthread_mutex_t g_prov_lock = PTHREAD_MUTEX_INITIALIZER;

static void prov_node_key(qihse_prov_entity_t entity, const char* id,
                          char* out, size_t cap) {
    snprintf(out, cap, QIHSE_PROV_NODE_PREFIX "%s:%s",
             qihse_prov_entity_name(entity), id);
}

static void prov_edge_key(qihse_prov_entity_t fe, const char* fid,
                          qihse_prov_edge_t edge,
                          qihse_prov_entity_t te, const char* tid,
                          char* out, size_t cap) {
    snprintf(out, cap, QIHSE_PROV_EDGE_PREFIX "%s:%s:%s:%s:%s",
             qihse_prov_entity_name(fe), fid, qihse_prov_edge_name(edge),
             qihse_prov_entity_name(te), tid);
}

static void prov_edge_rev_key(qihse_prov_entity_t te, const char* tid,
                              qihse_prov_edge_t edge,
                              qihse_prov_entity_t fe, const char* fid,
                              char* out, size_t cap) {
    snprintf(out, cap, QIHSE_PROV_EDGE_PREFIX "rev:%s:%s:%s:%s:%s",
             qihse_prov_entity_name(te), tid, qihse_prov_edge_name(edge),
             qihse_prov_entity_name(fe), fid);
}

static void prov_node_encode(const qihse_prov_node_t* n, char* out, size_t cap) {
    char by[33];
    uuid_to_hex(&n->created_by, by);
    snprintf(out, cap, "%u\t%s\t%s\t%llu\t%d\t%s",
             (unsigned)n->entity, n->label, n->digest,
             (unsigned long long)n->created_hlc_physical,
             n->immutable ? 1 : 0, by);
}

static bool prov_node_decode(const char* blob, qihse_prov_node_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char f_entity[16], f_label[QIHSE_PROV_LABEL_MAX + 1u];
    char f_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u], f_created[24];
    char f_immutable[8], f_by[40];
    const char* p = blob;
    p = next_field(p, f_entity, sizeof(f_entity));
    p = next_field(p, f_label, sizeof(f_label));
    p = next_field(p, f_digest, sizeof(f_digest));
    p = next_field(p, f_created, sizeof(f_created));
    p = next_field(p, f_immutable, sizeof(f_immutable));
    p = next_field(p, f_by, sizeof(f_by));
    if (f_entity[0] == '\0' || f_created[0] == '\0') return false;
    out->entity = (qihse_prov_entity_t)strtoul(f_entity, NULL, 10);
    snprintf(out->label, sizeof(out->label), "%s", f_label);
    snprintf(out->digest, sizeof(out->digest), "%s", f_digest);
    out->created_hlc_physical = (uint64_t)strtoull(f_created, NULL, 10);
    out->immutable = strtoul(f_immutable, NULL, 10) != 0;
    (void)hex_to_uuid(f_by, &out->created_by);
    return true;
}

bool qihse_provenance_node_put(void* store_void, void* user_void,
                               const qihse_prov_node_t* node) {
    if (!store_void || !user_void || !node) return false;
    if (node->id[0] == '\0') return false;
    char key[512];
    prov_node_key(node->entity, node->id, key, sizeof(key));

    pthread_mutex_lock(&g_prov_lock);
    if (node->immutable) {
        char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                           (qihse_user_t*)user_void);
        if (existing) {
            free(existing);
            pthread_mutex_unlock(&g_prov_lock);
            return false; /* immutable records are never rewritten */
        }
    }
    char blob[1024];
    prov_node_encode(node, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_prov_lock);
    return ok;
}

bool qihse_provenance_node_get(void* store_void, void* user_void,
                               qihse_prov_entity_t entity, const char* id,
                               qihse_prov_node_t* out) {
    if (!store_void || !user_void || !id || !out) return false;
    char key[512];
    prov_node_key(entity, id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = prov_node_decode(blob, out);
    free(blob);
    if (ok) snprintf(out->id, sizeof(out->id), "%s", id);
    return ok;
}

bool qihse_provenance_node_delete(void* store_void, void* user_void,
                                  qihse_prov_entity_t entity, const char* id) {
    if (!store_void || !user_void || !id) return false;
    char key[512];
    prov_node_key(entity, id, key, sizeof(key));
    pthread_mutex_lock(&g_prov_lock);
    /* Immutable records cannot be deleted. */
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (blob) {
        qihse_prov_node_t n;
        bool decoded = prov_node_decode(blob, &n);
        free(blob);
        if (decoded && n.immutable) {
            pthread_mutex_unlock(&g_prov_lock);
            return false;
        }
    }
    bool ok = qihse_kv_del_user((qihse_kv_store_t*)store_void, key,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_prov_lock);
    return ok;
}

bool qihse_provenance_edge_put(void* store_void, void* user_void,
                               qihse_prov_entity_t from_entity, const char* from_id,
                               qihse_prov_edge_t edge,
                               qihse_prov_entity_t to_entity, const char* to_id) {
    if (!store_void || !user_void || !from_id || !to_id) return false;
    if (from_id[0] == '\0' || to_id[0] == '\0') return false;

    char fwd[1024], rev[1024];
    prov_edge_key(from_entity, from_id, edge, to_entity, to_id, fwd, sizeof(fwd));
    prov_edge_rev_key(to_entity, to_id, edge, from_entity, from_id, rev, sizeof(rev));

    pthread_mutex_lock(&g_prov_lock);
    /* Idempotent: re-recording the same edge is a no-op. */
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, fwd,
                                       (qihse_user_t*)user_void);
    if (existing) {
        free(existing);
        pthread_mutex_unlock(&g_prov_lock);
        return true;
    }
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, fwd, "1", 0, 0,
                                (qihse_user_t*)user_void) &&
              qihse_kv_set_user((qihse_kv_store_t*)store_void, rev, "1", 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_prov_lock);
    return ok;
}

bool qihse_provenance_edge_has(void* store_void, void* user_void,
                               qihse_prov_entity_t from_entity, const char* from_id,
                               qihse_prov_edge_t edge,
                               qihse_prov_entity_t to_entity, const char* to_id) {
    if (!store_void || !user_void || !from_id || !to_id) return false;
    char fwd[1024];
    prov_edge_key(from_entity, from_id, edge, to_entity, to_id, fwd, sizeof(fwd));
    return qihse_kv_exists_user((qihse_kv_store_t*)store_void, fwd,
                                (qihse_user_t*)user_void);
}

/* ── Traversal ─────────────────────────────────────────────────────────── */

/* An edge's *meaning* determines the direction of data flow, not which side
 * of the record it is stored on.  `from --DERIVED_FROM--> to` means `to` is
 * upstream of `from`, whereas `from --PUBLISHED_IN--> to` means `to` is
 * downstream of `from`.  Getting this wrong makes provenance queries silently
 * return nothing, so the direction is declared per edge type here. */
typedef struct {
    qihse_prov_edge_t edge;
    bool to_is_upstream;
} prov_edge_flow_t;

static const prov_edge_flow_t g_edge_flow[] = {
    { QIHSE_PROV_EDGE_DERIVED_FROM,     true  }, /* from derived from to   */
    { QIHSE_PROV_EDGE_PATCHED_BY,       true  }, /* from patched by to     */
    { QIHSE_PROV_EDGE_BUILT_WITH,       true  }, /* from built with to     */
    { QIHSE_PROV_EDGE_BUILD_DEPENDS_ON, true  }, /* from depends on to     */
    { QIHSE_PROV_EDGE_BUILT_ON,         true  }, /* from built on to       */
    { QIHSE_PROV_EDGE_BUILT_IN,         true  }, /* from built in to       */
    { QIHSE_PROV_EDGE_CONTAINED_IN,     true  }, /* from contained in to   */
    { QIHSE_PROV_EDGE_SUPERSEDES,       true  }, /* from supersedes to     */
    { QIHSE_PROV_EDGE_VERIFIED_AGAINST, true  }, /* from verified vs to    */
    { QIHSE_PROV_EDGE_AFFECTED_BY,      true  }, /* from affected by to    */
    { QIHSE_PROV_EDGE_PRODUCES,         false }, /* from produces to       */
    { QIHSE_PROV_EDGE_DEPLOYED_TO,      false }, /* from deployed to to    */
    { QIHSE_PROV_EDGE_PUBLISHED_IN,     false }, /* from published in to   */
    { QIHSE_PROV_EDGE_DESCRIBED_BY,     false }, /* from described by to   */
    { QIHSE_PROV_EDGE_ATTESTED_BY,      false }, /* from attested by to    */
};

static bool prov_edge_to_is_upstream(qihse_prov_edge_t edge) {
    for (size_t i = 0; i < sizeof(g_edge_flow) / sizeof(g_edge_flow[0]); i++) {
        if (g_edge_flow[i].edge == edge) return g_edge_flow[i].to_is_upstream;
    }
    return true; /* unknown edges are treated as provenance links */
}

#define PROV_WALK_MAX_VISITED 512u

typedef struct {
    char entity[32];
    char id[QIHSE_PROV_ID_MAX + 1u];
} prov_visited_t;

typedef struct {
    prov_visited_t seen[PROV_WALK_MAX_VISITED];
    size_t seen_count;
    qihse_prov_visit_cb cb;
    void* user_data;
    size_t hits;
    bool stop;
} prov_walk_ctx_t;

static bool prov_walk_seen(prov_walk_ctx_t* ctx, const char* entity, const char* id) {
    for (size_t i = 0; i < ctx->seen_count; i++) {
        if (strcmp(ctx->seen[i].entity, entity) == 0 &&
            strcmp(ctx->seen[i].id, id) == 0) return true;
    }
    return false;
}

static void prov_walk_mark(prov_walk_ctx_t* ctx, const char* entity, const char* id) {
    if (ctx->seen_count >= PROV_WALK_MAX_VISITED) return;
    snprintf(ctx->seen[ctx->seen_count].entity, sizeof(ctx->seen[0].entity), "%s", entity);
    snprintf(ctx->seen[ctx->seen_count].id, sizeof(ctx->seen[0].id), "%s", id);
    ctx->seen_count++;
}

/* Parse "provedge:<fe>:<fid>:<edge>:<te>:<tid>" (or the "rev:" form, where
 * the first pair is the *to* side).  Entity ids may contain colons, so the
 * edge name is located by matching the known edge vocabulary rather than by
 * naive splitting. */
static bool prov_parse_edge_key(const char* key, bool reverse_form,
                                qihse_prov_entity_t* first_entity, char* first_id, size_t first_cap,
                                qihse_prov_edge_t* edge,
                                qihse_prov_entity_t* second_entity, char* second_id, size_t second_cap) {
    const char* p = key + strlen(QIHSE_PROV_EDGE_PREFIX);
    if (reverse_form) {
        if (strncmp(p, "rev:", 4) != 0) return false;
        p += 4;
    }
    /* First entity name. */
    const char* f1 = strchr(p, ':');
    if (!f1) return false;
    char e1[32];
    size_t l1 = (size_t)(f1 - p);
    if (l1 == 0 || l1 >= sizeof(e1)) return false;
    memcpy(e1, p, l1); e1[l1] = '\0';
    p = f1 + 1;

    /* The first id runs until a known edge name appears after a colon. */
    const char* edge_start = NULL;
    qihse_prov_edge_t found_edge = QIHSE_PROV_EDGE_COUNT;
    for (const char* scan = p; (scan = strchr(scan, ':')) != NULL; scan++) {
        const char* name_start = scan + 1;
        const char* name_end = strchr(name_start, ':');
        if (!name_end) break;
        char name[32];
        size_t nl = (size_t)(name_end - name_start);
        if (nl == 0 || nl >= sizeof(name)) continue;
        memcpy(name, name_start, nl); name[nl] = '\0';
        qihse_prov_edge_t candidate;
        if (qihse_prov_edge_parse(name, &candidate)) {
            edge_start = name_start;
            found_edge = candidate;
            break;
        }
    }
    if (!edge_start) return false;

    size_t l2 = (size_t)(edge_start - p - 1u);
    if (l2 == 0 || l2 > first_cap - 1u) return false;
    memcpy(first_id, p, l2); first_id[l2] = '\0';

    /* Second entity name, then the second id (which may itself contain ':'). */
    const char* f3 = strchr(edge_start, ':');
    if (!f3) return false;
    p = f3 + 1;
    const char* f4 = strchr(p, ':');
    if (!f4) return false;
    char e4[32];
    size_t l4 = (size_t)(f4 - p);
    if (l4 == 0 || l4 >= sizeof(e4)) return false;
    memcpy(e4, p, l4); e4[l4] = '\0';
    p = f4 + 1;

    size_t l5 = strlen(p);
    if (l5 == 0 || l5 > second_cap - 1u) return false;
    memcpy(second_id, p, l5); second_id[l5] = '\0';

    qihse_prov_entity_t ea, eb;
    if (!qihse_prov_entity_parse(e1, &ea)) return false;
    if (!qihse_prov_entity_parse(e4, &eb)) return false;
    *first_entity = ea;
    *edge = found_edge;
    *second_entity = eb;
    return true;
}

typedef struct {
    prov_walk_ctx_t* ctx;
    uint32_t depth;
    bool want_upstream;   /* true: collect antecedents; false: dependents */
    bool filter_entity;
    qihse_prov_entity_t want_entity;
    char prefix[512];     /* only keys with this prefix belong to this node */
    size_t prefix_len;
    char** queue;
    size_t* queue_len;
    size_t queue_cap;
} prov_scan_ctx_t;

/* Report a newly discovered node and enqueue it for the next depth level. */
static void prov_scan_enqueue(prov_scan_ctx_t* s, qihse_prov_entity_t entity,
                              const char* id, qihse_prov_edge_t edge) {
    const char* name = qihse_prov_entity_name(entity);
    if (prov_walk_seen(s->ctx, name, id)) return;
    prov_walk_mark(s->ctx, name, id);

    if (!s->filter_entity || entity == s->want_entity) {
        qihse_prov_hit_t hit;
        hit.entity = entity;
        snprintf(hit.id, sizeof(hit.id), "%s", id);
        hit.via_edge = edge;
        hit.depth = s->depth;
        s->ctx->hits++;
        if (s->ctx->cb && !s->ctx->cb(&hit, s->ctx->user_data)) {
            s->ctx->stop = true;
            return;
        }
    }
    /* Keep walking through non-matching nodes so wanted entities further
     * downstream remain reachable. */
    if (*s->queue_len < s->queue_cap) {
        size_t need = strlen(name) + 1u + strlen(id) + 1u;
        char* entry = (char*)malloc(need);
        if (entry) {
            snprintf(entry, need, "%s:%s", name, id);
            s->queue[(*s->queue_len)++] = entry;
        }
    }
}

/* Forward edge index: keys where this node is the `from` side. */
static bool prov_scan_fwd_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    prov_scan_ctx_t* s = (prov_scan_ctx_t*)user_data;
    if (s->ctx->stop) return false;
    if (strncmp(key, s->prefix, s->prefix_len) != 0) return true;
    qihse_prov_entity_t fe, te;
    qihse_prov_edge_t edge;
    char fid[QIHSE_PROV_ID_MAX + 1u], tid[QIHSE_PROV_ID_MAX + 1u];
    if (!prov_parse_edge_key(key, false, &fe, fid, sizeof(fid), &edge, &te, tid, sizeof(tid))) {
        return true;
    }
    (void)fe;
    bool to_up = prov_edge_to_is_upstream(edge);
    /* Upstream walks follow upstream edges; downstream walks follow the rest. */
    if (s->want_upstream == to_up) {
        prov_scan_enqueue(s, te, tid, edge);
    }
    return !s->ctx->stop;
}

/* Reverse edge index: keys where this node is the `to` side. */
static bool prov_scan_rev_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    prov_scan_ctx_t* s = (prov_scan_ctx_t*)user_data;
    if (s->ctx->stop) return false;
    if (s->want_upstream) return true; /* the forward scan covers upstream */
    if (strncmp(key, s->prefix, s->prefix_len) != 0) return true;
    qihse_prov_entity_t te, fe;
    qihse_prov_edge_t edge;
    char tid[QIHSE_PROV_ID_MAX + 1u], fid[QIHSE_PROV_ID_MAX + 1u];
    if (!prov_parse_edge_key(key, true, &te, tid, sizeof(tid), &edge, &fe, fid, sizeof(fid))) {
        return true;
    }
    (void)te;
    /* A downstream node is the `from` side of an upstream edge. */
    if (!prov_edge_to_is_upstream(edge)) return true;
    prov_scan_enqueue(s, fe, fid, edge);
    return !s->ctx->stop;
}

static size_t prov_walk(void* store_void, void* user_void,
                        qihse_prov_entity_t entity, const char* id,
                        uint32_t max_depth, bool want_upstream,
                        bool filter_entity, qihse_prov_entity_t want_entity,
                        qihse_prov_visit_cb cb, void* user_data) {
    if (!store_void || !user_void || !id) return 0;
    if (max_depth == 0 || max_depth > 16u) max_depth = 16u;

    prov_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cb = cb;
    ctx.user_data = user_data;
    prov_walk_mark(&ctx, qihse_prov_entity_name(entity), id);

    size_t queue_cap = 256u;
    char** queue = (char**)calloc(queue_cap, sizeof(char*));
    if (!queue) return 0;
    size_t queue_len = 0;
    size_t root_need = strlen(qihse_prov_entity_name(entity)) + 1u + strlen(id) + 1u;
    char* root = (char*)malloc(root_need);
    if (!root) { free(queue); return 0; }
    snprintf(root, root_need, "%s:%s", qihse_prov_entity_name(entity), id);
    queue[queue_len++] = root;

    for (uint32_t depth = 1; depth <= max_depth && queue_len > 0 && !ctx.stop; depth++) {
        size_t next_cap = 256u;
        char** next = (char**)calloc(next_cap, sizeof(char*));
        if (!next) break;
        size_t next_len = 0;

        for (size_t i = 0; i < queue_len && !ctx.stop; i++) {
            const char* entry = queue[i];
            const char* colon = strrchr(entry, ':');
            if (!colon) continue;
            char ent_name[32];
            size_t el = (size_t)(colon - entry);
            if (el == 0 || el >= sizeof(ent_name)) continue;
            memcpy(ent_name, entry, el); ent_name[el] = '\0';
            const char* node_id = colon + 1;

            prov_scan_ctx_t scan;
            memset(&scan, 0, sizeof(scan));
            scan.ctx = &ctx;
            scan.depth = depth;
            scan.want_upstream = want_upstream;
            scan.filter_entity = filter_entity;
            scan.want_entity = want_entity;
            scan.queue = next;
            scan.queue_len = &next_len;
            scan.queue_cap = next_cap;

            snprintf(scan.prefix, sizeof(scan.prefix), QIHSE_PROV_EDGE_PREFIX "%s:%s:",
                     ent_name, node_id);
            scan.prefix_len = strlen(scan.prefix);
            qihse_kv_foreach_user((qihse_kv_store_t*)store_void,
                                  (qihse_user_t*)user_void, prov_scan_fwd_cb, &scan);

            if (!want_upstream) {
                snprintf(scan.prefix, sizeof(scan.prefix), QIHSE_PROV_EDGE_PREFIX "rev:%s:%s:",
                         ent_name, node_id);
                scan.prefix_len = strlen(scan.prefix);
                qihse_kv_foreach_user((qihse_kv_store_t*)store_void,
                                      (qihse_user_t*)user_void, prov_scan_rev_cb, &scan);
            }
        }

        for (size_t i = 0; i < queue_len; i++) free(queue[i]);
        free(queue);
        queue = next;
        queue_len = next_len;
        queue_cap = next_cap;
    }

    for (size_t i = 0; i < queue_len; i++) free(queue[i]);
    free(queue);
    return ctx.hits;
}

size_t qihse_provenance_trace_forward(void* store_void, void* user_void,
                                      qihse_prov_entity_t entity, const char* id,
                                      uint32_t max_depth,
                                      qihse_prov_visit_cb cb, void* user_data) {
    /* Downstream: what did this produce, and where did it end up? */
    return prov_walk(store_void, user_void, entity, id, max_depth,
                     false, false, QIHSE_PROV_ENTITY_COUNT, cb, user_data);
}

size_t qihse_provenance_trace_reverse(void* store_void, void* user_void,
                                      qihse_prov_entity_t entity, const char* id,
                                      uint32_t max_depth,
                                      qihse_prov_visit_cb cb, void* user_data) {
    /* Upstream: what produced this, and where did it come from? */
    return prov_walk(store_void, user_void, entity, id, max_depth,
                     true, false, QIHSE_PROV_ENTITY_COUNT, cb, user_data);
}

size_t qihse_provenance_reverse_impact(void* store_void, void* user_void,
                                       qihse_prov_entity_t from_entity, const char* from_id,
                                       qihse_prov_entity_t want_entity,
                                       uint32_t max_depth,
                                       qihse_prov_visit_cb cb, void* user_data) {
    /* Impact flows downstream from the subject, so this is a filtered
     * downstream walk. */
    return prov_walk(store_void, user_void, from_entity, from_id, max_depth,
                     false, true, want_entity, cb, user_data);
}


/* ── Package override policy (plan §27) ────────────────────────────────── */

typedef struct { qihse_pkg_mode_t v; const char* name; } pkg_mode_entry_t;

static const pkg_mode_entry_t g_pkg_modes[] = {
    { QIHSE_PKG_UPSTREAM_BINARY,         "UPSTREAM_BINARY"         },
    { QIHSE_PKG_UPSTREAM_SOURCE_REBUILD, "UPSTREAM_SOURCE_REBUILD" },
    { QIHSE_PKG_CITADEL_OVERLAY,         "CITADEL_OVERLAY"         },
    { QIHSE_PKG_CITADEL_FORK,            "CITADEL_FORK"            },
    { QIHSE_PKG_FORBIDDEN,               "FORBIDDEN"               },
    { QIHSE_PKG_ISOLATED_EXCEPTION,      "ISOLATED_EXCEPTION"      },
};

const char* qihse_pkg_mode_name(qihse_pkg_mode_t mode) {
    for (size_t i = 0; i < sizeof(g_pkg_modes) / sizeof(g_pkg_modes[0]); i++) {
        if (g_pkg_modes[i].v == mode) return g_pkg_modes[i].name;
    }
    return "UNKNOWN";
}

bool qihse_pkg_mode_parse(const char* name, qihse_pkg_mode_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_pkg_modes) / sizeof(g_pkg_modes[0]); i++) {
        if (strcasecmp(g_pkg_modes[i].name, name) == 0) {
            *out = g_pkg_modes[i].v;
            return true;
        }
    }
    return false;
}

static void pkg_policy_key(const char* package, char* out, size_t cap) {
    snprintf(out, cap, QIHSE_PKG_POLICY_PREFIX "%s", package);
}

bool qihse_pkg_policy_set(void* store_void, void* user_void,
                          const qihse_pkg_policy_t* policy) {
    if (!store_void || !user_void || !policy) return false;
    /* Every override must preserve its reason (plan §27). */
    if (policy->reason[0] == '\0') return false;
    char key[256];
    pkg_policy_key(policy->package, key, sizeof(key));
    char by[33];
    const uint8_t* b = (const uint8_t*)&policy->decided_by;
    for (int i = 0; i < 16; i++) snprintf(by + i * 2, 3, "%02x", b[i]);
    by[32] = '\0';
    char blob[1024];
    snprintf(blob, sizeof(blob), "%u\t%s\t%llu\t%llu\t%s",
             (unsigned)policy->mode, policy->reason,
             (unsigned long long)policy->decided_hlc_physical,
             (unsigned long long)policy->policy_generation, by);
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_pkg_policy_get(void* store_void, void* user_void,
                          const char* package, qihse_pkg_policy_t* out) {
    if (!store_void || !user_void || !package || !out) return false;
    char key[256];
    pkg_policy_key(package, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    memset(out, 0, sizeof(*out));
    unsigned mode = 0;
    char reason[256], by_hex[33];
    unsigned long long decided = 0, gen = 0;
    int n = sscanf(blob, "%u\t%255[^\t]\t%llu\t%llu\t%32[^\t]",
                   &mode, reason, &decided, &gen, by_hex);
    free(blob);
    if (n < 4) return false;
    snprintf(out->package, sizeof(out->package), "%s", package);
    out->mode = (qihse_pkg_mode_t)mode;
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
    out->decided_hlc_physical = (uint64_t)decided;
    out->policy_generation = (uint64_t)gen;
    if (n >= 5) {
        uint8_t* b = (uint8_t*)&out->decided_by;
        for (int i = 0; i < 16 && by_hex[i * 2]; i++) {
            unsigned int byte;
            if (sscanf(by_hex + i * 2, "%2x", &byte) != 1) break;
            b[i] = (uint8_t)byte;
        }
    }
    return true;
}

/* ── Build job state machine (plan §28) ────────────────────────────────── */

typedef struct { qihse_build_state_t v; const char* name; } build_state_entry_t;

static const build_state_entry_t g_build_states[] = {
    { QIHSE_BUILD_QUEUED,      "QUEUED"      },
    { QIHSE_BUILD_PLANNING,    "PLANNING"    },
    { QIHSE_BUILD_LEASED,      "LEASED"      },
    { QIHSE_BUILD_BUILDING,    "BUILDING"    },
    { QIHSE_BUILD_TESTING,     "TESTING"     },
    { QIHSE_BUILD_VERIFYING,   "VERIFYING"   },
    { QIHSE_BUILD_SIGNING,     "SIGNING"     },
    { QIHSE_BUILD_PUBLISHED,   "PUBLISHED"   },
    { QIHSE_BUILD_FAILED,      "FAILED"      },
    { QIHSE_BUILD_RETRYABLE,   "RETRYABLE"   },
    { QIHSE_BUILD_QUARANTINED, "QUARANTINED" },
    { QIHSE_BUILD_CANCELLED,   "CANCELLED"   },
};

const char* qihse_build_state_name(qihse_build_state_t state) {
    for (size_t i = 0; i < sizeof(g_build_states) / sizeof(g_build_states[0]); i++) {
        if (g_build_states[i].v == state) return g_build_states[i].name;
    }
    return "UNKNOWN";
}

bool qihse_build_state_parse(const char* name, qihse_build_state_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_build_states) / sizeof(g_build_states[0]); i++) {
        if (strcasecmp(g_build_states[i].name, name) == 0) {
            *out = g_build_states[i].v;
            return true;
        }
    }
    return false;
}

bool qihse_build_state_is_failure(qihse_build_state_t state) {
    return state == QIHSE_BUILD_FAILED || state == QIHSE_BUILD_RETRYABLE ||
           state == QIHSE_BUILD_QUARANTINED || state == QIHSE_BUILD_CANCELLED;
}

bool qihse_build_state_is_terminal(qihse_build_state_t state) {
    /* RETRYABLE is a failure state but deliberately NOT terminal: the job may
     * be requeued and reassigned after the lease expires. */
    return state == QIHSE_BUILD_PUBLISHED || state == QIHSE_BUILD_FAILED ||
           state == QIHSE_BUILD_QUARANTINED || state == QIHSE_BUILD_CANCELLED;
}

/* The legal forward path.  Any active state may fall into a failure state,
 * RETRYABLE may return to QUEUED, and nothing leaves a hard-terminal state. */
static bool build_transition_legal(qihse_build_state_t from, qihse_build_state_t to) {
    if (qihse_build_state_is_terminal(from)) return false;
    if (from == QIHSE_BUILD_RETRYABLE) return to == QIHSE_BUILD_QUEUED;
    if (qihse_build_state_is_failure(to)) return true;   /* failure from anywhere */

    switch (from) {
        case QIHSE_BUILD_QUEUED:    return to == QIHSE_BUILD_PLANNING;
        case QIHSE_BUILD_PLANNING:  return to == QIHSE_BUILD_LEASED;
        case QIHSE_BUILD_LEASED:    return to == QIHSE_BUILD_BUILDING;
        case QIHSE_BUILD_BUILDING:  return to == QIHSE_BUILD_TESTING;
        case QIHSE_BUILD_TESTING:   return to == QIHSE_BUILD_VERIFYING;
        case QIHSE_BUILD_VERIFYING: return to == QIHSE_BUILD_SIGNING;
        case QIHSE_BUILD_SIGNING:   return to == QIHSE_BUILD_PUBLISHED;
        default: return false;
    }
}

static pthread_mutex_t g_build_lock = PTHREAD_MUTEX_INITIALIZER;

static void build_job_key(const qihse_uuid_t* build_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(build_id, id_str);
    snprintf(out, cap, QIHSE_BUILD_JOB_PREFIX "%s", id_str);
}

static void build_job_encode(const qihse_build_job_t* j, char* out, size_t cap) {
    char bid[33], owner[33], lease[33], lastreq[33];
    uuid_to_hex(&j->build_id, bid);
    uuid_to_hex(&j->owner_node, owner);
    uuid_to_hex(&j->lease_id, lease);
    uuid_to_hex(&j->last_request_id, lastreq);
    snprintf(out, cap, "%s\t%s\t%s\t%s\t%s\t%u\t%llu\t%s\t%s\t%s\t%s\t%llu\t%llu\t%s",
             bid, j->package, j->source_revision, j->profile, j->toolchain,
             (unsigned)j->state, (unsigned long long)j->generation,
             owner, lease, j->artifact_digest, j->failure_reason,
             (unsigned long long)j->created_hlc_physical,
             (unsigned long long)j->updated_hlc_physical, lastreq);
}

static bool build_job_decode(const char* blob, qihse_build_job_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char f_bid[40], f_package[128], f_rev[128], f_profile[64], f_toolchain[64];
    char f_state[16], f_gen[24], f_owner[40], f_lease[40], f_artifact[256];
    char f_failure[256], f_created[24], f_updated[24], f_lastreq[40];
    const char* p = blob;
    p = next_field(p, f_bid, sizeof(f_bid));
    p = next_field(p, f_package, sizeof(f_package));
    p = next_field(p, f_rev, sizeof(f_rev));
    p = next_field(p, f_profile, sizeof(f_profile));
    p = next_field(p, f_toolchain, sizeof(f_toolchain));
    p = next_field(p, f_state, sizeof(f_state));
    p = next_field(p, f_gen, sizeof(f_gen));
    p = next_field(p, f_owner, sizeof(f_owner));
    p = next_field(p, f_lease, sizeof(f_lease));
    p = next_field(p, f_artifact, sizeof(f_artifact));
    p = next_field(p, f_failure, sizeof(f_failure));
    p = next_field(p, f_created, sizeof(f_created));
    p = next_field(p, f_updated, sizeof(f_updated));
    p = next_field(p, f_lastreq, sizeof(f_lastreq));
    if (!hex_to_uuid(f_bid, &out->build_id)) return false;
    snprintf(out->package, sizeof(out->package), "%s", f_package);
    snprintf(out->source_revision, sizeof(out->source_revision), "%s", f_rev);
    snprintf(out->profile, sizeof(out->profile), "%s", f_profile);
    snprintf(out->toolchain, sizeof(out->toolchain), "%s", f_toolchain);
    {
        unsigned long st = strtoul(f_state, NULL, 10);
        if (st > (unsigned long)QIHSE_BUILD_CANCELLED) return false;
        out->state = (qihse_build_state_t)st;
    }
    out->generation = (uint64_t)strtoull(f_gen, NULL, 10);
    (void)hex_to_uuid(f_owner, &out->owner_node);
    (void)hex_to_uuid(f_lease, &out->lease_id);
    snprintf(out->artifact_digest, sizeof(out->artifact_digest), "%s", f_artifact);
    snprintf(out->failure_reason, sizeof(out->failure_reason), "%s", f_failure);
    out->created_hlc_physical = (uint64_t)strtoull(f_created, NULL, 10);
    out->updated_hlc_physical = (uint64_t)strtoull(f_updated, NULL, 10);
    (void)hex_to_uuid(f_lastreq, &out->last_request_id);
    return true;
}

bool qihse_build_job_create(void* store_void, void* user_void,
                            const qihse_build_job_t* job,
                            qihse_build_job_t* out) {
    if (!store_void || !user_void || !job || !out) return false;
    char key[128];
    build_job_key(&job->build_id, key, sizeof(key));

    pthread_mutex_lock(&g_build_lock);
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) {
        /* Idempotent: a repeated create returns the existing job. */
        bool ok = build_job_decode(existing, out);
        free(existing);
        pthread_mutex_unlock(&g_build_lock);
        return ok;
    }
    qihse_build_job_t rec = *job;
    rec.state = QIHSE_BUILD_QUEUED;
    rec.generation = 1;
    char blob[2048];
    build_job_encode(&rec, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_build_lock);
    if (ok) *out = rec;
    return ok;
}

bool qihse_build_job_get(void* store_void, void* user_void,
                         const qihse_uuid_t* build_id, qihse_build_job_t* out) {
    if (!store_void || !user_void || !build_id || !out) return false;
    char key[128];
    build_job_key(build_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = build_job_decode(blob, out);
    free(blob);
    /* The body's build id must agree with the key. */
    if (ok && !qihse_uuid_equal(&out->build_id, build_id)) return false;
    return ok;
}

bool qihse_build_job_transition(void* store_void, void* user_void,
                                const qihse_uuid_t* build_id,
                                qihse_build_state_t next,
                                const qihse_uuid_t* request_id,
                                const char* failure_reason,
                                qihse_build_job_t* out) {
    if (!store_void || !user_void || !build_id || !out) return false;

    pthread_mutex_lock(&g_build_lock);
    char key[128];
    build_job_key(build_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) { pthread_mutex_unlock(&g_build_lock); return false; }
    qihse_build_job_t rec;
    bool decoded = build_job_decode(blob, &rec);
    free(blob);
    if (!decoded) { pthread_mutex_unlock(&g_build_lock); return false; }

    /* Idempotency: a repeated request_id is a no-op (criterion 18). */
    if (request_id && qihse_uuid_equal(&rec.last_request_id, request_id)) {
        *out = rec;
        pthread_mutex_unlock(&g_build_lock);
        return true;
    }

    if (!build_transition_legal(rec.state, next)) {
        pthread_mutex_unlock(&g_build_lock);
        return false;
    }

    rec.state = next;
    rec.generation++;
    rec.updated_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
    if (request_id) rec.last_request_id = *request_id;
    if (failure_reason) {
        snprintf(rec.failure_reason, sizeof(rec.failure_reason), "%s", failure_reason);
    }

    char new_blob[2048];
    build_job_encode(&rec, new_blob, sizeof(new_blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, new_blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_build_lock);
    if (ok) *out = rec;
    return ok;
}

typedef struct {
    qihse_build_job_cb cb;
    void* user_data;
} build_iter_ctx_t;

static bool build_job_iter_cb(const char* key, const char* value, void* user_data) {
    build_iter_ctx_t* ctx = (build_iter_ctx_t*)user_data;
    if (strncmp(key, QIHSE_BUILD_JOB_PREFIX, strlen(QIHSE_BUILD_JOB_PREFIX)) != 0) return true;
    qihse_build_job_t rec;
    if (!build_job_decode(value, &rec)) return true;
    return ctx->cb(&rec, ctx->user_data);
}

void qihse_build_job_foreach(void* store_void, void* user_void,
                             qihse_build_job_cb cb, void* user_data) {
    if (!store_void || !cb) return;
    build_iter_ctx_t ctx = { cb, user_data };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          build_job_iter_cb, &ctx);
}

/* ── Builder capability (plan §29) ─────────────────────────────────────── */

static void builder_cap_key(const qihse_uuid_t* node_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(node_id, id_str);
    snprintf(out, cap, QIHSE_BUILDER_CAP_PREFIX "%s", id_str);
}

bool qihse_builder_capability_put(void* store_void, void* user_void,
                                  const qihse_builder_capability_t* cap) {
    if (!store_void || !user_void || !cap) return false;
    char key[128];
    builder_cap_key(&cap->node_id, key, sizeof(key));
    char nid[33];
    uuid_to_hex(&cap->node_id, nid);
    char blob[1024];
    snprintf(blob, sizeof(blob), "%s\t%s\t%u\t%u\t%llu\t%llu\t%llu\t%s\t%u\t%u\t%u\t%u\t%llu",
             nid, cap->cpu_model, cap->cores_total, cap->cores_available,
             (unsigned long long)cap->ram_total_gb,
             (unsigned long long)cap->ram_available_gb,
             (unsigned long long)cap->scratch_available_gb,
             cap->isa, cap->load_1m_milli, cap->thermal_headroom_milli,
             cap->build_queue_depth, (unsigned)cap->trust_state,
             (unsigned long long)cap->observed_hlc_physical);
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_builder_capability_get(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id,
                                  qihse_builder_capability_t* out) {
    if (!store_void || !user_void || !node_id || !out) return false;
    char key[128];
    builder_cap_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    memset(out, 0, sizeof(*out));
    char f_nid[40], f_cpu[128], f_cores_total[16], f_cores_avail[16];
    char f_ram_total[24], f_ram_avail[24], f_scratch[24], f_isa[128];
    char f_load[16], f_thermal[16], f_queue[16], f_trust[8], f_observed[24];
    const char* p = blob;
    p = next_field(p, f_nid, sizeof(f_nid));
    p = next_field(p, f_cpu, sizeof(f_cpu));
    p = next_field(p, f_cores_total, sizeof(f_cores_total));
    p = next_field(p, f_cores_avail, sizeof(f_cores_avail));
    p = next_field(p, f_ram_total, sizeof(f_ram_total));
    p = next_field(p, f_ram_avail, sizeof(f_ram_avail));
    p = next_field(p, f_scratch, sizeof(f_scratch));
    p = next_field(p, f_isa, sizeof(f_isa));
    p = next_field(p, f_load, sizeof(f_load));
    p = next_field(p, f_thermal, sizeof(f_thermal));
    p = next_field(p, f_queue, sizeof(f_queue));
    p = next_field(p, f_trust, sizeof(f_trust));
    p = next_field(p, f_observed, sizeof(f_observed));
    free(blob);
    if (!hex_to_uuid(f_nid, &out->node_id)) return false;
    snprintf(out->cpu_model, sizeof(out->cpu_model), "%s", f_cpu);
    out->cores_total = (uint32_t)strtoul(f_cores_total, NULL, 10);
    out->cores_available = (uint32_t)strtoul(f_cores_avail, NULL, 10);
    out->ram_total_gb = (uint64_t)strtoull(f_ram_total, NULL, 10);
    out->ram_available_gb = (uint64_t)strtoull(f_ram_avail, NULL, 10);
    out->scratch_available_gb = (uint64_t)strtoull(f_scratch, NULL, 10);
    snprintf(out->isa, sizeof(out->isa), "%s", f_isa);
    out->load_1m_milli = (uint32_t)strtoul(f_load, NULL, 10);
    out->thermal_headroom_milli = (uint32_t)strtoul(f_thermal, NULL, 10);
    out->build_queue_depth = (uint32_t)strtoul(f_queue, NULL, 10);
    out->trust_state = (qihse_trust_state_t)strtoul(f_trust, NULL, 10);
    out->observed_hlc_physical = (uint64_t)strtoull(f_observed, NULL, 10);
    return true;
}

/* ── Build history (plan §29) ──────────────────────────────────────────── */

static void build_history_key(const qihse_build_history_t* rec, char* out, size_t cap) {
    char eid[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&rec->execution_id, eid);
    snprintf(out, cap, QIHSE_BUILD_HISTORY_PREFIX "%s", eid);
}

bool qihse_build_history_record(void* store_void, void* user_void,
                                const qihse_build_history_t* rec) {
    if (!store_void || !user_void || !rec) return false;
    char key[128];
    build_history_key(rec, key, sizeof(key));
    char bid[33], node[33];
    const uint8_t* b1 = (const uint8_t*)&rec->build_id;
    for (int i = 0; i < 16; i++) snprintf(bid + i * 2, 3, "%02x", b1[i]);
    bid[32] = '\0';
    const uint8_t* b2 = (const uint8_t*)&rec->builder_node;
    for (int i = 0; i < 16; i++) snprintf(node + i * 2, 3, "%02x", b2[i]);
    node[32] = '\0';
    char blob[1024];
    snprintf(blob, sizeof(blob), "%s\t%s\t%s\t%s\t%s\t%s\t%u\t%llu\t%llu\t%llu\t%llu\t%d",
             bid, rec->package, rec->source_revision, rec->profile, rec->toolchain,
             node, rec->allocated_cores,
             (unsigned long long)rec->peak_ram_mb,
             (unsigned long long)rec->build_duration_ms,
             (unsigned long long)rec->test_duration_ms,
             (unsigned long long)rec->artifact_size_bytes,
             rec->succeeded ? 1 : 0);
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

typedef struct {
    const char* package;
    uint64_t total_ms;
    size_t count;
} build_mean_ctx_t;

static bool build_mean_cb(const char* key, const char* value, void* user_data) {
    build_mean_ctx_t* ctx = (build_mean_ctx_t*)user_data;
    if (strncmp(key, QIHSE_BUILD_HISTORY_PREFIX, strlen(QIHSE_BUILD_HISTORY_PREFIX)) != 0) return true;
    /* package is the 2nd tab-separated field */
    const char* p = strchr(value, '\t');
    if (!p) return true;
    p++;
    const char* end = strchr(p, '\t');
    if (!end) return true;
    size_t len = (size_t)(end - p);
    if (strlen(ctx->package) != len || strncmp(p, ctx->package, len) != 0) return true;
    /* build_duration_ms is the 9th field */
    const char* q = value;
    for (int i = 0; i < 8; i++) {
        q = strchr(q, '\t');
        if (!q) return true;
        q++;
    }
    unsigned long long dur = 0;
    if (sscanf(q, "%llu", &dur) != 1) return true;
    ctx->total_ms += (uint64_t)dur;
    ctx->count++;
    return true;
}

bool qihse_build_history_mean_duration(void* store_void, void* user_void,
                                       const char* package, uint64_t* out_mean_ms) {
    if (!store_void || !user_void || !package || !out_mean_ms) return false;
    build_mean_ctx_t ctx = { package, 0, 0 };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          build_mean_cb, &ctx);
    if (ctx.count == 0) return false;
    *out_mean_ms = ctx.total_ms / ctx.count;
    return true;
}

/* ── SBOM records (plan §32) ───────────────────────────────────────────── */

static void sbom_key(const qihse_uuid_t* sbom_id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(sbom_id, id_str);
    snprintf(out, cap, QIHSE_SBOM_PREFIX "%s", id_str);
}

static void sbom_encode(const qihse_sbom_record_t* r, char* out, size_t cap) {
    char sid[33];
    const uint8_t* b = (const uint8_t*)&r->sbom_id;
    for (int i = 0; i < 16; i++) snprintf(sid + i * 2, 3, "%02x", b[i]);
    sid[32] = '\0';
    snprintf(out, cap, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%llu\t%llu\t%s\t%s",
             sid, r->artifact_digest, r->sbom_digest, r->provenance_digest,
             r->signing_identity, r->signature_algorithm, r->signature,
             r->signing_key_handle,
             (unsigned long long)r->signature_hlc_physical,
             (unsigned long long)r->policy_generation,
             r->verification_status, r->format);
}

static bool sbom_decode(const char* blob, qihse_sbom_record_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char sid[33];
    unsigned long long hlc = 0, gen = 0;
    int n = sscanf(blob, "%32[^\t]\t%128[^\t]\t%128[^\t]\t%128[^\t]\t%127[^\t]\t%63[^\t]\t%511[^\t]\t%159[^\t]\t%llu\t%llu\t%31[^\t]\t%31[^\t]",
                   sid, out->artifact_digest, out->sbom_digest, out->provenance_digest,
                   out->signing_identity, out->signature_algorithm, out->signature,
                   out->signing_key_handle, &hlc, &gen,
                   out->verification_status, out->format);
    if (n < 10) return false;
    uint8_t* p = (uint8_t*)&out->sbom_id;
    for (int i = 0; i < 16; i++) { unsigned int byte; if (sscanf(sid + i * 2, "%2x", &byte) != 1) return false; p[i] = (uint8_t)byte; }
    out->signature_hlc_physical = (uint64_t)hlc;
    out->policy_generation = (uint64_t)gen;
    return true;
}

bool qihse_sbom_record_put(void* store_void, void* user_void,
                           const qihse_sbom_record_t* rec) {
    if (!store_void || !user_void || !rec) return false;
    char key[128];
    sbom_key(&rec->sbom_id, key, sizeof(key));
    pthread_mutex_lock(&g_prov_lock);
    /* Immutable: historical signed SBOM evidence is never rewritten
     * (criterion 20). */
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) {
        free(existing);
        pthread_mutex_unlock(&g_prov_lock);
        return false;
    }
    char blob[4096];
    sbom_encode(rec, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_prov_lock);
    return ok;
}

bool qihse_sbom_record_get(void* store_void, void* user_void,
                           const qihse_uuid_t* sbom_id,
                           qihse_sbom_record_t* out) {
    if (!store_void || !user_void || !sbom_id || !out) return false;
    char key[128];
    sbom_key(sbom_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = sbom_decode(blob, out);
    free(blob);
    if (ok && !qihse_uuid_equal(&out->sbom_id, sbom_id)) return false;
    return ok;
}

typedef struct {
    const char* artifact_digest;
    qihse_uuid_t* out_ids;
    size_t out_cap;
    size_t found;
} sbom_find_ctx_t;

static bool sbom_find_cb(const char* key, const char* value, void* user_data) {
    sbom_find_ctx_t* ctx = (sbom_find_ctx_t*)user_data;
    if (strncmp(key, QIHSE_SBOM_PREFIX, strlen(QIHSE_SBOM_PREFIX)) != 0) return true;
    qihse_sbom_record_t rec;
    if (!sbom_decode(value, &rec)) return true;
    if (strcmp(rec.artifact_digest, ctx->artifact_digest) != 0) return true;
    if (ctx->found < ctx->out_cap) ctx->out_ids[ctx->found] = rec.sbom_id;
    ctx->found++;
    return true;
}

size_t qihse_sbom_find_by_artifact(void* store_void, void* user_void,
                                   const char* artifact_digest,
                                   qihse_uuid_t* out_ids, size_t out_cap) {
    if (!store_void || !user_void || !artifact_digest || !out_ids) return 0;
    sbom_find_ctx_t ctx = { artifact_digest, out_ids, out_cap, 0 };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          sbom_find_cb, &ctx);
    return ctx.found;
}

/* ── Vulnerability observations (plan §33) ─────────────────────────────── */

static void vuln_key(const qihse_uuid_t* id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(id, id_str);
    snprintf(out, cap, QIHSE_VULN_PREFIX "%s", id_str);
}

static void vuln_encode(const qihse_vuln_observation_t* o, char* out, size_t cap) {
    char oid[33];
    const uint8_t* b = (const uint8_t*)&o->observation_id;
    for (int i = 0; i < 16; i++) snprintf(oid + i * 2, 3, "%02x", b[i]);
    oid[32] = '\0';
    snprintf(out, cap, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%llu",
             oid, o->component, o->component_digest, o->advisory_id,
             o->severity, o->status, o->scanner, o->evidence,
             (unsigned long long)o->observed_hlc_physical);
}

static bool vuln_decode(const char* blob, qihse_vuln_observation_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char oid[33];
    unsigned long long observed = 0;
    int n = sscanf(blob, "%32[^\t]\t%191[^\t]\t%128[^\t]\t%63[^\t]\t%15[^\t]\t%23[^\t]\t%63[^\t]\t%255[^\t]\t%llu",
                   oid, out->component, out->component_digest, out->advisory_id,
                   out->severity, out->status, out->scanner, out->evidence, &observed);
    if (n < 8) return false;
    uint8_t* p = (uint8_t*)&out->observation_id;
    for (int i = 0; i < 16; i++) { unsigned int byte; if (sscanf(oid + i * 2, "%2x", &byte) != 1) return false; p[i] = (uint8_t)byte; }
    out->observed_hlc_physical = (uint64_t)observed;
    return true;
}

bool qihse_vuln_observation_put(void* store_void, void* user_void,
                                const qihse_vuln_observation_t* obs) {
    if (!store_void || !user_void || !obs) return false;
    char key[128];
    vuln_key(&obs->observation_id, key, sizeof(key));
    /* Append-only: a new observation never rewrites an existing record, and
     * never touches a historical SBOM (plan §33). */
    char blob[2048];
    vuln_encode(obs, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_vuln_observation_get(void* store_void, void* user_void,
                                const qihse_uuid_t* observation_id,
                                qihse_vuln_observation_t* out) {
    if (!store_void || !user_void || !observation_id || !out) return false;
    char key[128];
    vuln_key(observation_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = vuln_decode(blob, out);
    free(blob);
    if (ok && !qihse_uuid_equal(&out->observation_id, observation_id)) return false;
    return ok;
}

typedef struct {
    const char* component_digest;
    size_t count;
} vuln_count_ctx_t;

static bool vuln_count_cb(const char* key, const char* value, void* user_data) {
    vuln_count_ctx_t* ctx = (vuln_count_ctx_t*)user_data;
    if (strncmp(key, QIHSE_VULN_PREFIX, strlen(QIHSE_VULN_PREFIX)) != 0) return true;
    qihse_vuln_observation_t obs;
    if (!vuln_decode(value, &obs)) return true;
    if (strcmp(obs.component_digest, ctx->component_digest) == 0) ctx->count++;
    return true;
}

size_t qihse_vuln_count_by_component(void* store_void, void* user_void,
                                     const char* component_digest) {
    if (!store_void || !user_void || !component_digest) return 0;
    vuln_count_ctx_t ctx = { component_digest, 0 };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          vuln_count_cb, &ctx);
    return ctx.count;
}

/* ── Repository snapshots (plan §32) ───────────────────────────────────── */

static void repo_snap_key(const qihse_uuid_t* id, char* out, size_t cap) {
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(id, id_str);
    snprintf(out, cap, QIHSE_REPO_SNAPSHOT_PREFIX "%s", id_str);
}

static void repo_snap_encode(const qihse_repo_snapshot_t* s, char* out, size_t cap) {
    char sid[33], by[33];
    const uint8_t* b1 = (const uint8_t*)&s->snapshot_id;
    for (int i = 0; i < 16; i++) snprintf(sid + i * 2, 3, "%02x", b1[i]);
    sid[32] = '\0';
    const uint8_t* b2 = (const uint8_t*)&s->created_by;
    for (int i = 0; i < 16; i++) snprintf(by + i * 2, 3, "%02x", b2[i]);
    by[32] = '\0';
    snprintf(out, cap, "%s\t%s\t%s\t%s\t%llu\t%s\t%llu\t%s",
             sid, s->repository, s->snapshot_digest, s->release,
             (unsigned long long)s->package_count, s->signing_key_handle,
             (unsigned long long)s->created_hlc_physical, by);
}

static bool repo_snap_decode(const char* blob, qihse_repo_snapshot_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char sid[33], by[33];
    unsigned long long count = 0, created = 0;
    int n = sscanf(blob, "%32[^\t]\t%127[^\t]\t%128[^\t]\t%63[^\t]\t%llu\t%159[^\t]\t%llu\t%32[^\t]",
                   sid, out->repository, out->snapshot_digest, out->release,
                   &count, out->signing_key_handle, &created, by);
    if (n < 7) return false;
    uint8_t* p = (uint8_t*)&out->snapshot_id;
    for (int i = 0; i < 16; i++) { unsigned int byte; if (sscanf(sid + i * 2, "%2x", &byte) != 1) return false; p[i] = (uint8_t)byte; }
    out->package_count = (uint64_t)count;
    out->created_hlc_physical = (uint64_t)created;
    if (n >= 8) {
        p = (uint8_t*)&out->created_by;
        for (int i = 0; i < 16; i++) { unsigned int byte; if (sscanf(by + i * 2, "%2x", &byte) != 1) break; p[i] = (uint8_t)byte; }
    }
    return true;
}

bool qihse_repo_snapshot_put(void* store_void, void* user_void,
                             const qihse_repo_snapshot_t* snap) {
    if (!store_void || !user_void || !snap) return false;
    char key[160];
    repo_snap_key(&snap->snapshot_id, key, sizeof(key));
    pthread_mutex_lock(&g_prov_lock);
    /* Immutable (criterion 19). */
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) {
        free(existing);
        pthread_mutex_unlock(&g_prov_lock);
        return false;
    }
    char blob[2048];
    repo_snap_encode(snap, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_prov_lock);
    return ok;
}

bool qihse_repo_snapshot_get(void* store_void, void* user_void,
                             const qihse_uuid_t* snapshot_id,
                             qihse_repo_snapshot_t* out) {
    if (!store_void || !user_void || !snapshot_id || !out) return false;
    char key[160];
    repo_snap_key(snapshot_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = repo_snap_decode(blob, out);
    free(blob);
    if (ok && !qihse_uuid_equal(&out->snapshot_id, snapshot_id)) return false;
    return ok;
}

typedef struct {
    const char* repository; /* NULL = all repositories */
    qihse_repo_snapshot_cb cb;
    void* user_data;
} repo_snap_iter_ctx_t;

static bool repo_snap_iter_cb(const char* key, const char* value, void* user_data) {
    repo_snap_iter_ctx_t* ctx = (repo_snap_iter_ctx_t*)user_data;
    if (strncmp(key, QIHSE_REPO_SNAPSHOT_PREFIX, strlen(QIHSE_REPO_SNAPSHOT_PREFIX)) != 0) return true;
    qihse_repo_snapshot_t snap;
    if (!repo_snap_decode(value, &snap)) return true;
    if (ctx->repository && strcmp(snap.repository, ctx->repository) != 0) return true;
    return ctx->cb(&snap, ctx->user_data);
}

void qihse_repo_snapshot_foreach(void* store_void, void* user_void,
                                 const char* repository,
                                 qihse_repo_snapshot_cb cb, void* user_data) {
    if (!store_void || !cb) return;
    repo_snap_iter_ctx_t ctx = { repository, cb, user_data };
    qihse_kv_foreach_user((qihse_kv_store_t*)store_void, (qihse_user_t*)user_void,
                          repo_snap_iter_cb, &ctx);
}
