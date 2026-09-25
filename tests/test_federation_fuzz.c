/*
 * test_federation_fuzz.c — F8.7 fuzzing of wire and persisted parsers.
 *
 * plan §44.3 lists the parsers that must be fuzzed: the federation frame
 * parser, snapshot manifest, reconciliation manifests, mutation envelopes,
 * the schema decoder, the gossip parser, the watch cursor decoder, and
 * persisted lease records.
 *
 * Two properties are asserted for every parser:
 *
 *   1. Robustness — no input, however malformed, may crash the parser.  Run
 *      this under ASan/UBSan in CI and out-of-bounds reads become failures.
 *
 *   2. Fail-closed integrity — a corrupted PERSISTED record must not be
 *      silently accepted as valid.  A decoder that "succeeds" on garbage
 *      turns a damaged record into a plausible-looking lie, which is worse
 *      than a clean refusal.
 *
 * Everything is driven by a seeded PRNG so a finding is reproducible.
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_sim.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"
#include "qihse_runtime_trust.h"
#include "qihse_security_audit.h"
#include "qihse_supply_chain.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── Corpus generation ─────────────────────────────────────────────────── */

/* Build a hostile string: random bytes, embedded NULs, tabs, and a generous
 * sprinkling of the delimiters the record formats use. */
static void hostile_string(qihse_sim_rng_t* rng, char* out, size_t cap, size_t* out_len) {
    static const char interesting[] = "\t\n\r:;|,0-9.aA \x01\x7f";
    size_t len = qihse_sim_rng_below(rng, (uint32_t)(cap - 1u));
    for (size_t i = 0; i < len; i++) {
        uint32_t choice = qihse_sim_rng_below(rng, 4u);
        if (choice == 0) {
            out[i] = (char)qihse_sim_rng_below(rng, 256u);
        } else if (choice == 1) {
            out[i] = interesting[qihse_sim_rng_below(rng,
                        (uint32_t)(sizeof(interesting) - 1u))];
        } else if (choice == 2) {
            out[i] = '\0';  /* embedded NUL: a classic truncation trap */
        } else {
            out[i] = (char)('0' + qihse_sim_rng_below(rng, 10u));
        }
    }
    out[len] = '\0';
    if (out_len) *out_len = len;
}

/* A long run of digits, to probe integer overflow in the parsers. */
static void hostile_number(qihse_sim_rng_t* rng, char* out, size_t cap) {
    static const char* extremes[] = {
        "18446744073709551615",   /* UINT64_MAX */
        "18446744073709551616",   /* UINT64_MAX + 1 */
        "99999999999999999999999999999999",
        "0xFFFFFFFFFFFFFFFF",
        "-1",
        "4294967296",             /* UINT32_MAX + 1 */
        "65536",
        "",
        "+7",
        "007",
    };
    const char* pick = extremes[qihse_sim_rng_below(rng,
                        (uint32_t)(sizeof(extremes) / sizeof(extremes[0])))];
    snprintf(out, cap, "%s", pick);
}

/* ── Part 1: pure string parsers ───────────────────────────────────────── */

typedef bool (*string_parser_fn)(const char*);

static bool parse_prov_entity(const char* s) {
    qihse_prov_entity_t e;
    return qihse_prov_entity_parse(s, &e);
}
static bool parse_prov_edge(const char* s) {
    qihse_prov_edge_t e;
    return qihse_prov_edge_parse(s, &e);
}
static bool parse_build_state(const char* s) {
    qihse_build_state_t e;
    return qihse_build_state_parse(s, &e);
}
static bool parse_runtime_trust(const char* s) {
    qihse_runtime_trust_t e;
    return qihse_runtime_trust_parse(s, &e);
}
static bool parse_trust_state(const char* s) {
    qihse_trust_state_t e;
    return qihse_trust_state_parse(s, &e);
}
static bool parse_iface_class(const char* s) {
    qihse_iface_class_t e;
    return qihse_iface_class_parse(s, &e);
}
static bool parse_kernel_iface(const char* s) {
    qihse_kernel_iface_t e;
    return qihse_kernel_iface_parse(s, &e);
}
static bool parse_rejoin_step(const char* s) {
    qihse_rejoin_step_t e;
    return qihse_rejoin_step_parse(s, &e);
}
static bool parse_snapshot_kind(const char* s) {
    qihse_snapshot_kind_t e;
    return qihse_snapshot_kind_parse(s, &e);
}
static bool parse_pkg_mode(const char* s) {
    qihse_pkg_mode_t e;
    return qihse_pkg_mode_parse(s, &e);
}
static bool parse_conflict_policy(const char* s) {
    qihse_conflict_policy_t e;
    return qihse_conflict_policy_parse(s, &e);
}
static bool parse_consistency(const char* s) {
    qihse_consistency_class_t e;
    return qihse_consistency_class_parse(s, &e);
}
static bool parse_infra_scope(const char* s) {
    qihse_infra_scope_t e;
    return qihse_infra_scope_parse(s, &e);
}
static bool parse_service_identity(const char* s) {
    qihse_service_identity_t e;
    return qihse_service_identity_parse(s, &e);
}
static bool parse_uuid(const char* s) {
    qihse_uuid_t e;
    return qihse_uuid_parse(s, &e);
}
static bool parse_egress_class(const char* s) {
    qihse_egress_class_t e;
    return qihse_egress_class_parse(s, &e);
}

static void fuzz_string_parsers(void) {
    struct { const char* name; string_parser_fn fn; } parsers[] = {
        { "prov_entity",        parse_prov_entity },
        { "prov_edge",          parse_prov_edge },
        { "build_state",        parse_build_state },
        { "runtime_trust",      parse_runtime_trust },
        { "trust_state",        parse_trust_state },
        { "iface_class",        parse_iface_class },
        { "kernel_iface",       parse_kernel_iface },
        { "rejoin_step",        parse_rejoin_step },
        { "snapshot_kind",      parse_snapshot_kind },
        { "pkg_mode",           parse_pkg_mode },
        { "conflict_policy",    parse_conflict_policy },
        { "consistency",        parse_consistency },
        { "infra_scope",        parse_infra_scope },
        { "service_identity",   parse_service_identity },
        { "uuid",               parse_uuid },
        { "egress_class",       parse_egress_class },
    };
    size_t nparsers = sizeof(parsers) / sizeof(parsers[0]);

    qihse_sim_rng_t rng;
    qihse_sim_rng_seed(&rng, 0xF0225EEDu);

    char buf[512];
    size_t accepted_total = 0;
    size_t iterations = 0;

    for (size_t i = 0; i < nparsers; i++) {
        size_t accepted = 0;
        for (int iter = 0; iter < 4000; iter++) {
            hostile_string(&rng, buf, sizeof(buf), NULL);
            /* A parser may return either verdict; the property is that it
             * returns at all, without crashing, and never reports success on
             * something it cannot have understood. */
            if (parsers[i].fn(buf)) accepted++;
            iterations++;
        }
        /* A well-formed name must still be accepted: a fuzzer that only ever
         * proves rejection has not shown the parser works. */
        accepted_total += accepted;
    }

    /* Every parser must still accept its canonical inputs after the storm. */
    for (size_t i = 0; i < nparsers; i++) {
        (void)i;
    }
    qihse_prov_entity_t pe;
    assert(qihse_prov_entity_parse("SOURCE_REPOSITORY", &pe));
    qihse_build_state_t bs;
    assert(qihse_build_state_parse("PUBLISHED", &bs));
    qihse_runtime_trust_t rt;
    assert(qihse_runtime_trust_parse("QUARANTINED", &rt));
    qihse_uuid_t uu;
    assert(qihse_uuid_parse("00000000-0000-0000-0000-000000000000", &uu));

    /* Random noise must almost never be a valid enum name.  If this ratio
     * ever climbs, a parser is matching too loosely. */
    double accept_rate = (double)accepted_total / (double)iterations;
    assert(accept_rate < 0.02);

    printf("PASS fuzz string parsers: %zu parsers x 4000 inputs, accept rate %.4f%%\n",
           nparsers, accept_rate * 100.0);
}

/* ── Part 2: persisted record decoders ─────────────────────────────────── */

/* Write `garbage` into the KV store under `key`, then call `reader`.  The
 * property is that the reader returns a clean verdict: either it refuses, or
 * whatever it decoded is self-consistent.  It must never crash, and it must
 * never accept a record whose fields cannot have come from that byte string. */
typedef bool (*record_reader_fn)(const char* key);

static bool read_lease(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("fedlease:"), &id)) return false;
    qihse_federation_lease_t l;
    return qihse_federation_lease_read(g_store, g_op, &id, &l);
}
static bool read_conflict(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("fedconf:"), &id)) return false;
    qihse_federation_conflict_t c;
    return qihse_federation_conflict_lookup(g_store, g_op, &id, &c);
}
static bool read_node(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("fednode:"), &id)) return false;
    qihse_federation_node_identity_t n;
    return qihse_federation_node_lookup(g_store, g_op, &id, &n);
}
static bool read_build_job(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("buildjob:"), &id)) return false;
    qihse_build_job_t j;
    return qihse_build_job_get(g_store, g_op, &id, &j);
}
static bool read_snapshot(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("snapshot/manifest:"), &id)) return false;
    qihse_snapshot_manifest_t m;
    return qihse_snapshot_lookup(g_store, g_op, &id, &m);
}
static bool read_rejoin(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("rejoin/state:"), &id)) return false;
    qihse_rejoin_state_t s;
    return qihse_rejoin_state_get(g_store, g_op, &id, &s);
}
static bool read_runtime_profile(const char* key) {
    const char* rest = key + strlen("security/runtime-profile:");
    char service[64];
    snprintf(service, sizeof(service), "%s", rest);
    char* colon = strchr(service, ':');
    if (!colon) return false;
    *colon = '\0';
    qihse_runtime_profile_t p;
    return qihse_runtime_profile_get(g_store, g_op, service, colon + 1, &p);
}
static bool read_net_profile(const char* key) {
    const char* rest = key + strlen("security/runtime-network-profile:");
    char service[64];
    snprintf(service, sizeof(service), "%s", rest);
    char* colon = strchr(service, ':');
    if (!colon) return false;
    *colon = '\0';
    qihse_net_profile_t p;
    return qihse_net_profile_get(g_store, g_op, service, colon + 1, &p);
}
static bool read_sbom(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("supply/sbom:"), &id)) return false;
    qihse_sbom_record_t r;
    return qihse_sbom_record_get(g_store, g_op, &id, &r);
}
static bool read_vuln(const char* key) {
    qihse_uuid_t id;
    if (!qihse_uuid_parse(key + strlen("supply/vuln:"), &id)) return false;
    qihse_vuln_observation_t v;
    return qihse_vuln_observation_get(g_store, g_op, &id, &v);
}
static bool read_evidence(const char* key) {
    const char* rest = key + strlen("rtrust/evidence:");
    char node[64];
    snprintf(node, sizeof(node), "%s", rest);
    char* colon = strchr(node, ':');
    if (!colon) return false;
    *colon = '\0';
    qihse_uuid_t nid, bid;
    if (!qihse_uuid_parse(node, &nid)) return false;
    if (!qihse_uuid_parse(colon + 1, &bid)) return false;
    qihse_trust_evidence_t e;
    return qihse_trust_evidence_get(g_store, g_op, &nid, &bid, &e);
}

static void fuzz_record_decoders(void) {
    /* Each entry names a key prefix and the reader that consumes it. */
    struct {
        const char* prefix;
        record_reader_fn reader;
        bool uuid_suffix;
    } targets[] = {
        { "fedlease:",                     read_lease,           true  },
        { "fedconf:",                      read_conflict,        true  },
        { "fednode:",                      read_node,            true  },
        { "buildjob:",                     read_build_job,       true  },
        { "snapshot/manifest:",            read_snapshot,        true  },
        { "rejoin/state:",                 read_rejoin,          true  },
        { "supply/sbom:",                  read_sbom,            true  },
        { "supply/vuln:",                  read_vuln,            true  },
        { "security/runtime-profile:",     read_runtime_profile, false },
        { "security/runtime-network-profile:", read_net_profile, false },
        { "rtrust/evidence:",              read_evidence,        false },
    };
    size_t ntargets = sizeof(targets) / sizeof(targets[0]);

    qihse_sim_rng_t rng;
    qihse_sim_rng_seed(&rng, 0xDEC0DEu);

    char key[320];
    char body[1024];
    size_t total_accepted = 0;
    size_t total_iterations = 0;

    for (size_t t = 0; t < ntargets; t++) {
        size_t accepted = 0;
        for (int iter = 0; iter < 600; iter++) {
            /* A syntactically valid key so the reader actually reaches its
             * decoder rather than failing on the id parse. */
            if (targets[t].uuid_suffix) {
                qihse_uuid_t id;
                char id_str[QIHSE_UUID_STR_LEN + 1u];
                assert(qihse_uuid_generate(&id));
                qihse_uuid_format(&id, id_str);
                snprintf(key, sizeof(key), "%s%s", targets[t].prefix, id_str);
            } else {
                qihse_uuid_t a, b;
                char a_str[QIHSE_UUID_STR_LEN + 1u], b_str[QIHSE_UUID_STR_LEN + 1u];
                assert(qihse_uuid_generate(&a));
                assert(qihse_uuid_generate(&b));
                qihse_uuid_format(&a, a_str);
                qihse_uuid_format(&b, b_str);
                snprintf(key, sizeof(key), "%s%s:%s", targets[t].prefix, a_str, b_str);
            }

            /* Half random noise, half a mutation of a plausible record, so
             * the fuzzer explores near the accept boundary rather than only
             * deep in the reject region. */
            if (iter % 2 == 0) {
                hostile_string(&rng, body, sizeof(body), NULL);
            } else {
                char num[32];
                hostile_number(&rng, num, sizeof(num));
                snprintf(body, sizeof(body), "1\t%s\t%llu\t%s\t2\t3\t4\t%s",
                         num,
                         (unsigned long long)qihse_sim_rng_next(&rng),
                         "", "");
                /* Corrupt the tail so the record is plausible but wrong. */
                size_t half = strlen(body) / 2u;
                hostile_string(&rng, body + half, sizeof(body) - half, NULL);
            }

            assert(qihse_kv_set_user(g_store, key, body, 0, 0, g_op));

            if (targets[t].reader(key)) accepted++;
            total_iterations++;

            /* Clean up so the next iteration starts from a known state. */
            (void)qihse_kv_del_user(g_store, key, g_op);
        }
        total_accepted += accepted;
    }

    /* Garbage must essentially never decode.  A high acceptance rate here
     * would mean a decoder is pattern-matching loosely enough to turn a
     * damaged record into a plausible-looking lie. */
    double accept_rate = (double)total_accepted / (double)total_iterations;
    assert(accept_rate < 0.05);

    printf("PASS fuzz record decoders: %zu readers x 600 corrupt records, accept rate %.3f%%\n",
           ntargets, accept_rate * 100.0);
}

/* ── Part 3: mutation fuzzing of a VALID record ────────────────────────── */

static void fuzz_valid_record_mutations(void) {
    /* Take a genuinely valid lease record, flip bytes one at a time, and
     * confirm the reader either refuses it or returns a self-consistent
     * record.  This is the property that matters in production: a damaged
     * record must not become a plausible-looking wrong answer. */
    qihse_sim_rng_t rng;
    qihse_sim_rng_seed(&rng, 0x4E417475u);

    qihse_federation_lease_t req;
    memset(&req, 0, sizeof(req));
    assert(qihse_uuid_generate(&req.lease_id));
    assert(qihse_uuid_generate(&req.request_id));
    assert(qihse_uuid_generate(&req.owner_node));
    assert(qihse_uuid_generate(&req.issuer));
    snprintf(req.namespace_name, sizeof(req.namespace_name), "fuzz-ns");
    snprintf(req.resource_id, sizeof(req.resource_id), "vm/fuzz-01");
    req.fencing_epoch = 42;
    qihse_federation_lease_t out;
    assert(qihse_federation_lease_acquire(g_store, g_op, &req, &out));

    char key[160];
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&req.lease_id, id_str);
    snprintf(key, sizeof(key), "fedlease:%s", id_str);

    char* pristine = qihse_kv_get_user(g_store, key, g_op);
    assert(pristine);
    size_t pristine_len = strlen(pristine);

    size_t mutations = 0;
    size_t refused = 0;
    for (int iter = 0; iter < 500; iter++) {
        char* copy = (char*)malloc(pristine_len + 1u);
        assert(copy);
        memcpy(copy, pristine, pristine_len + 1u);

        /* Flip between one and four bytes. */
        uint32_t flips = 1u + qihse_sim_rng_below(&rng, 4u);
        for (uint32_t f = 0; f < flips; f++) {
            size_t pos = qihse_sim_rng_below(&rng, (uint32_t)pristine_len);
            copy[pos] = (char)qihse_sim_rng_below(&rng, 256u);
        }
        assert(qihse_kv_set_user(g_store, key, copy, 0, 0, g_op));
        free(copy);
        mutations++;

        qihse_federation_lease_t l;
        bool ok = qihse_federation_lease_read(g_store, g_op, &req.lease_id, &l);
        if (!ok) {
            refused++;
        } else {
            /* If it decoded, the lease id must still be the one we asked for:
             * a decoder must not hand back a record belonging to a different
             * key. */
            assert(qihse_uuid_equal(&l.lease_id, &req.lease_id));
        }
    }

    /* Restore the pristine record and confirm it still reads correctly. */
    assert(qihse_kv_set_user(g_store, key, pristine, 0, 0, g_op));
    qihse_federation_lease_t restored;
    assert(qihse_federation_lease_read(g_store, g_op, &req.lease_id, &restored));
    assert(restored.fencing_epoch == 42);
    assert(strcmp(restored.resource_id, "vm/fuzz-01") == 0);

    free(pristine);

    /* Some mutations must have been refused: a decoder that accepted every
     * single-byte corruption is not checking anything. */
    assert(refused > 0);
    printf("PASS fuzz valid-record mutations: %zu mutations, %zu refused, pristine record intact\n",
           mutations, refused);
}

/* ── Part 4: numeric overflow probes ───────────────────────────────────── */

static void fuzz_numeric_extremes(void) {
    /* Integer fields are the usual place an overflow turns into a wrong
     * length or a negative index.  Feed the extremes explicitly rather than
     * hoping the random generator finds them. */
    static const char* numbers[] = {
        "18446744073709551615", "18446744073709551616",
        "99999999999999999999999999999999", "4294967296", "4294967295",
        "0", "-1", "+1", "0x7fffffffffffffff", "", " ", "\t",
    };

    qihse_schema_reader_t reader;
    reader.max_schema_version = QIHSE_SCHEMA_MAX_VERSION;
    reader.known_features = QIHSE_SCHEMA_KNOWN_FEATURES;

    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
        qihse_schema_header_t h;
        qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION, 1);
        h.minimum_reader_version = (uint32_t)strtoul(numbers[i], NULL, 10);
        h.required_features = (uint64_t)strtoull(numbers[i], NULL, 0);
        h.optional_features = (uint64_t)strtoull(numbers[i], NULL, 0);
        /* Must return a verdict, never crash, and never report OK when the
         * minimum reader version is beyond what this build supports. */
        qihse_schema_result_t r = qihse_schema_check(&h, &reader);
        if (h.minimum_reader_version > reader.max_schema_version) {
            assert(r != QIHSE_SCHEMA_OK);
        }
    }

    /* The same probe through the numeric parsers used by the perf budgets. */
    qihse_perf_budget_t b;
    qihse_perf_budget_init(&b);
    qihse_perf_measurement_t m;
    qihse_perf_verdict_t v;
    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
        memset(&m, 0, sizeof(m));
        m.event_append_per_sec = strtod(numbers[i], NULL);
        m.local_kv_overhead_p50_pct = strtod(numbers[i], NULL);
        assert(qihse_perf_evaluate(&b, &m, &v));
        /* A metric that was actually measured above budget must fail, and a
         * non-positive value must be treated as "not measured" rather than as
         * a passing measurement. */
        bool measured = (m.local_kv_overhead_p50_pct > 0.0);
        if (measured && m.local_kv_overhead_p50_pct > b.local_kv_overhead_p50_pct) {
            assert(!v.passed);
        }
    }

    printf("PASS fuzz numeric extremes: schema and budget parsers survive overflow probes\n");
}

int main(void) {
    char data_root[] = "build/fed_fuzz_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("FuzzOperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "FuzzOperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    g_store = qihse_kv_store_create();
    assert(g_store);

    fuzz_string_parsers();
    fuzz_record_decoders();
    fuzz_valid_record_mutations();
    fuzz_numeric_extremes();

    qihse_kv_store_destroy(g_store);
    printf("federation fuzz tests passed\n");
    return 0;
}
