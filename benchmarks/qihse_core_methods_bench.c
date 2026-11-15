/* Synthetic fixed-width scalar lookup benchmark. Measures the public core API,
 * including per-batch kernel construction; it does not benchmark VectorDB.
 * An independent typed equality oracle is built and checked outside timing. */
#include "qihse.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>

#ifndef QIHSE_BENCH_REVISION
#define QIHSE_BENCH_REVISION "unknown"
#endif
#ifndef QIHSE_BENCH_BUILD_PROFILE
#define QIHSE_BENCH_BUILD_PROFILE "unspecified"
#endif
#ifndef QIHSE_BENCH_SOURCE_SHA256
#define QIHSE_BENCH_SOURCE_SHA256 "unknown"
#endif
#ifndef __VERSION__
#define __VERSION__ "unknown"
#endif

#define LIST_CAPACITY 16u
#define METHOD_BIT(method) (1u << (unsigned)(method))
#define METRIC_COUNTS(X) \
    X(queries) X(matches) X(candidate_hits) X(fallback_queries) X(fallback_hits) \
    X(direct_queries) X(unprojected_queries) X(query_projections) X(row_projections) \
    X(projection_failures) X(comparisons) X(kernel_builds) X(tiles)

typedef struct {
    size_t records, queries, repeats;
    size_t dimensions[LIST_CAPACITY], dimension_count;
    size_t tiles[LIST_CAPACITY], tile_count;
    uint64_t seed;
    double gamma;
    unsigned methods;
    const char *dataset;
    int csv;
} bench_options_t;

typedef struct {
    const char *name;
    qihse_data_type_t type;
    void *records, *queries;
    size_t n, query_count, width, expected_matches;
    not_stisla_result_t *oracle;
    uint64_t setup_ns;
} fixture_t;

typedef struct {
    qihse_search_metrics_t totals;
    size_t mismatches;
    uint64_t checksum;
    double wall_min, wall_median, wall_max;
    double cpu_min, cpu_median, cpu_max;
} measurement_t;

static const char *dataset_names[] = {
    "present", "absent", "duplicates", "nearby_double", "large_int"
};

static void usage(FILE *out, const char *program) {
    fprintf(out,
        "Usage: %s [options]\n"
        "  --method all|exact|phase|paired  (default all; exact baseline always included)\n"
        "  --tile N[,N...]                 (default 1,16)\n"
        "  --dimensions N[,N...]           (default 64,128; paired requires even N)\n"
        "  --dataset all|present|absent|duplicates|nearby_double|large_int\n"
        "  --records N --queries N --repeats N  (defaults 512,32,3)\n"
        "  --seed N --gamma X              (defaults 42,1)\n"
        "  --format jsonl|csv              (default jsonl)\n"
        "  --help\n"
        "Each case has one untimed warmup. Timings cover complete batches, including\n"
        "kernel construction and metric collection. Oracle/validation are untimed.\n"
        "Reported ns/query is amortized batch time, not single-request latency.\n",
        program);
}

static int parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    if (!text || !*text || *text < '0' || *text > '9') return -1;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end || value > UINT64_MAX) return -1;
    *out = (uint64_t)value;
    return 0;
}

static int parse_size(const char *text, size_t *out) {
    uint64_t value;
    if (parse_u64(text, &value) || !value || value > SIZE_MAX) return -1;
    *out = (size_t)value;
    return 0;
}

static int parse_list(const char *text, size_t *values, size_t *count) {
    char *copy = strdup(text);
    if (!copy) return -1;
    char *cursor = copy;
    *count = 0;
    while (cursor) {
        char *comma = strchr(cursor, ',');
        if (comma) *comma = '\0';
        if (*count == LIST_CAPACITY || parse_size(cursor, &values[*count])) {
            free(copy);
            return -1;
        }
        for (size_t i = 0; i < *count; ++i) {
            if (values[i] == values[*count]) { free(copy); return -1; }
        }
        ++*count;
        cursor = comma ? comma + 1 : NULL;
    }
    free(copy);
    return 0;
}

static int parse_options(int argc, char **argv, bench_options_t *options) {
    *options = (bench_options_t){
        .records = 512, .queries = 32, .repeats = 3,
        .dimensions = {64, 128}, .dimension_count = 2,
        .tiles = {1, 16}, .tile_count = 2,
        .seed = 42, .gamma = 1.0, .methods = 7u, .dataset = "all"
    };
    for (int i = 1; i < argc; ++i) {
        const char *key = argv[i];
        if (!strcmp(key, "--help")) { usage(stdout, argv[0]); return 1; }
        if (i + 1 >= argc) return -1;
        const char *value = argv[++i];
        if (!strcmp(key, "--method")) {
            if (!strcmp(value, "all")) options->methods = 7u;
            else if (!strcmp(value, "exact")) options->methods = METHOD_BIT(QIHSE_SEARCH_EXACT);
            else if (!strcmp(value, "phase")) options->methods = METHOD_BIT(QIHSE_SEARCH_EXACT) | METHOD_BIT(QIHSE_SEARCH_RFF_COSINE);
            else if (!strcmp(value, "paired")) options->methods = METHOD_BIT(QIHSE_SEARCH_EXACT) | METHOD_BIT(QIHSE_SEARCH_RFF_PAIRED);
            else return -1;
        } else if (!strcmp(key, "--tile")) {
            if (parse_list(value, options->tiles, &options->tile_count)) return -1;
        } else if (!strcmp(key, "--dimensions")) {
            if (parse_list(value, options->dimensions, &options->dimension_count)) return -1;
        } else if (!strcmp(key, "--records")) {
            if (parse_size(value, &options->records)) return -1;
        } else if (!strcmp(key, "--queries")) {
            if (parse_size(value, &options->queries)) return -1;
        } else if (!strcmp(key, "--repeats")) {
            if (parse_size(value, &options->repeats)) return -1;
        } else if (!strcmp(key, "--seed")) {
            if (parse_u64(value, &options->seed)) return -1;
        } else if (!strcmp(key, "--gamma")) {
            char *end;
            errno = 0;
            options->gamma = strtod(value, &end);
            if (errno || !*value || *end || !isfinite(options->gamma) || options->gamma <= 0) return -1;
        } else if (!strcmp(key, "--dataset")) {
            int valid = !strcmp(value, "all");
            for (size_t d = 0; d < sizeof(dataset_names) / sizeof(dataset_names[0]); ++d)
                valid |= !strcmp(value, dataset_names[d]);
            if (!valid) return -1;
            options->dataset = value;
        } else if (!strcmp(key, "--format")) {
            if (!strcmp(value, "csv")) options->csv = 1;
            else if (!strcmp(value, "jsonl")) options->csv = 0;
            else return -1;
        } else return -1;
    }
    for (size_t d = 0; d < options->dimension_count; ++d) {
        if (options->dimensions[d] > QIHSE_MAX_DIMENSIONS ||
            ((options->methods & METHOD_BIT(QIHSE_SEARCH_RFF_PAIRED)) && options->dimensions[d] % 2u)) return -1;
    }
    for (size_t t = 0; t < options->tile_count; ++t)
        if (options->tiles[t] > QIHSE_SEARCH_MAX_TILE_SIZE) return -1;
    if ((uint64_t)options->records > (uint64_t)((INT64_MAX - INT64_C(9007199254740992)) / 4) ||
        options->records > SIZE_MAX / sizeof(double) ||
        options->records > SIZE_MAX / sizeof(int64_t) ||
        options->queries > SIZE_MAX / sizeof(double) ||
        options->queries > SIZE_MAX / sizeof(int64_t) ||
        options->queries > SIZE_MAX / sizeof(not_stisla_result_t) ||
        options->repeats > SIZE_MAX / sizeof(uint64_t)) return -1;
    return 0;
}

static int clock_ns(clockid_t clock, uint64_t *out) {
    struct timespec ts;
    if (clock_gettime(clock, &ts) || ts.tv_sec < 0 ||
        (uint64_t)ts.tv_sec > UINT64_MAX / UINT64_C(1000000000)) return -1;
    *out = (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
    return 0;
}

static uint64_t next_random(uint64_t *state) {
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static int records_equal(const fixture_t *fixture, size_t row, size_t query) {
    if (fixture->type == QIHSE_TYPE_DOUBLE)
        return ((const double *)fixture->records)[row] == ((const double *)fixture->queries)[query];
    return ((const int64_t *)fixture->records)[row] == ((const int64_t *)fixture->queries)[query];
}

static void fixture_destroy(fixture_t *fixture) {
    free(fixture->records);
    free(fixture->queries);
    free(fixture->oracle);
    memset(fixture, 0, sizeof(*fixture));
}

static int fixture_create(fixture_t *fixture, const bench_options_t *options, size_t dataset) {
    uint64_t started, ended;
    if (clock_ns(CLOCK_MONOTONIC, &started)) return -1;
    *fixture = (fixture_t){.name = dataset_names[dataset], .n = options->records,
        .query_count = options->queries, .type = dataset == 3 ? QIHSE_TYPE_DOUBLE : QIHSE_TYPE_INT64,
        .width = dataset == 3 ? sizeof(double) : sizeof(int64_t)};
    fixture->records = malloc(fixture->n * fixture->width);
    fixture->queries = malloc(fixture->query_count * fixture->width);
    fixture->oracle = malloc(fixture->query_count * sizeof(*fixture->oracle));
    if (!fixture->records || !fixture->queries || !fixture->oracle) return -1;
    int64_t *integers = fixture->records;
    double *doubles = fixture->records;
    double nearby = 1.0;
    size_t distinct = fixture->n / 8u;
    if (!distinct) distinct = 1;
    for (size_t i = 0; i < fixture->n; ++i) {
        if (dataset == 3) {
            doubles[i] = nearby;
            nearby = nextafter(nextafter(nearby, INFINITY), INFINITY);
        } else if (dataset == 4) {
            integers[i] = INT64_C(9007199254740992) + (int64_t)i * 3;
        } else integers[i] = (int64_t)(dataset == 2 ? i % distinct : i) * 4;
    }
    if (dataset == 4 && fixture->n >= 2) {
        integers[0] = INT64_MIN;
        integers[fixture->n - 1] = INT64_MAX;
    }
    uint64_t rng = options->seed ^ (UINT64_C(0x7589dc872a614eb3) + dataset);
    for (size_t i = fixture->n - 1; i > 0; --i) {
        size_t j = (size_t)(next_random(&rng) % (i + 1));
        unsigned char temporary[sizeof(double) > sizeof(int64_t) ? sizeof(double) : sizeof(int64_t)];
        unsigned char *rows = fixture->records;
        memcpy(temporary, rows + i * fixture->width, fixture->width);
        memcpy(rows + i * fixture->width, rows + j * fixture->width, fixture->width);
        memcpy(rows + j * fixture->width, temporary, fixture->width);
    }
    for (size_t q = 0; q < fixture->query_count; ++q) {
        size_t row = (size_t)(next_random(&rng) % fixture->n);
        int missing = dataset == 1 || (dataset >= 2 && (q & 1u));
        if (dataset == 3) {
            ((double *)fixture->queries)[q] = missing ? nextafter(doubles[row], INFINITY) : doubles[row];
        } else {
            int64_t value = integers[row];
            ((int64_t *)fixture->queries)[q] = missing ? (value == INT64_MAX ? value - 1 : value + 1) : value;
        }
        fixture->oracle[q] = NOT_STISLA_NOT_FOUND;
        for (size_t i = 0; i < fixture->n; ++i) {
            if (records_equal(fixture, i, q)) { fixture->oracle[q] = i; ++fixture->expected_matches; break; }
        }
    }
    if (clock_ns(CLOCK_MONOTONIC, &ended)) return -1;
    fixture->setup_ns = ended - started;
    return 0;
}

static size_t validate_results(const fixture_t *fixture, const not_stisla_result_t *results,
                              const qihse_search_metrics_t *metrics, uint64_t *checksum) {
    size_t mismatches = 0, found = 0;
    for (size_t q = 0; q < fixture->query_count; ++q) {
        int present = results[q] != NOT_STISLA_NOT_FOUND;
        found += present;
        if (present != (fixture->oracle[q] != NOT_STISLA_NOT_FOUND) ||
            (present && (results[q] >= fixture->n || !records_equal(fixture, results[q], q)))) ++mismatches;
        *checksum = (*checksum ^ (uint64_t)results[q]) * UINT64_C(1099511628211);
    }
    if (metrics->matches != found || metrics->queries != fixture->query_count) ++mismatches;
    return mismatches;
}

static int add_metrics(qihse_search_metrics_t *sum, const qihse_search_metrics_t *metrics) {
#define ADD_COUNT(name) if (sum->name > SIZE_MAX - metrics->name) return -1; sum->name += metrics->name;
    METRIC_COUNTS(ADD_COUNT)
#undef ADD_COUNT
    sum->method = metrics->method;
    sum->dimensions = metrics->dimensions;
    sum->tile_size = metrics->tile_size;
    if (metrics->peak_scratch_bytes > sum->peak_scratch_bytes) sum->peak_scratch_bytes = metrics->peak_scratch_bytes;
    sum->setup_time_ns += metrics->setup_time_ns;
    sum->scoring_time_ns += metrics->scoring_time_ns;
    sum->verification_time_ns += metrics->verification_time_ns;
    sum->total_time_ns += metrics->total_time_ns;
    return 0;
}

static int compare_ns(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static double median_ns(uint64_t *values, size_t n) {
    qsort(values, n, sizeof(*values), compare_ns);
    return n % 2u ? (double)values[n / 2] :
        (double)values[n / 2 - 1] * 0.5 + (double)values[n / 2] * 0.5;
}

static int measure(const fixture_t *fixture, const bench_options_t *options,
                   qihse_search_method_t method, size_t dimensions, size_t tile,
                   measurement_t *measurement) {
    qihse_config_t config;
    qihse_search_options_t search_options;
    qihse_search_metrics_t metrics;
    not_stisla_result_t *results = NULL;
    uint64_t *wall = NULL, *cpu = NULL;
    int status = -1;
    memset(measurement, 0, sizeof(*measurement));
    if (qihse_config_init(&config, fixture->type, fixture->n) ||
        qihse_search_options_init(&search_options, sizeof(search_options)) ||
        qihse_search_metrics_init(&metrics, sizeof(metrics))) return -1;
    config.auto_dimensions = false;
    config.min_dimensions = config.max_dimensions = config.fixed_dimensions = dimensions ? dimensions : 64;
    config.rff_gamma = options->gamma;
    config.random_seed = options->seed;
    search_options.method = method;
    search_options.tile_size = tile;
    results = malloc(fixture->query_count * sizeof(*results));
    wall = malloc(options->repeats * sizeof(*wall));
    cpu = malloc(options->repeats * sizeof(*cpu));
    if (!results || !wall || !cpu) goto done;

    /* One warmup exercises the same public method but is excluded from sums. */
    if (qihse_batch_search_ex(fixture->records, fixture->n, fixture->queries,
            fixture->query_count, results, NULL, &config, &search_options, &metrics)) goto done;
    measurement->mismatches += validate_results(fixture, results, &metrics, &measurement->checksum);
    for (size_t repeat = 0; repeat < options->repeats; ++repeat) {
        uint64_t wall_start, wall_end, cpu_start, cpu_end;
        if (clock_ns(CLOCK_MONOTONIC, &wall_start) || clock_ns(CLOCK_PROCESS_CPUTIME_ID, &cpu_start)) goto done;
        int result = qihse_batch_search_ex(fixture->records, fixture->n, fixture->queries,
            fixture->query_count, results, NULL, &config, &search_options, &metrics);
        if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &cpu_end) || clock_ns(CLOCK_MONOTONIC, &wall_end)) goto done;
        if (result || wall_end < wall_start || cpu_end < cpu_start) goto done;
        wall[repeat] = wall_end - wall_start;
        cpu[repeat] = cpu_end - cpu_start;
        measurement->mismatches += validate_results(fixture, results, &metrics, &measurement->checksum);
        if (add_metrics(&measurement->totals, &metrics)) { errno = EOVERFLOW; goto done; }
    }
    measurement->wall_median = median_ns(wall, options->repeats);
    measurement->wall_min = (double)wall[0];
    measurement->wall_max = (double)wall[options->repeats - 1];
    measurement->cpu_median = median_ns(cpu, options->repeats);
    measurement->cpu_min = (double)cpu[0];
    measurement->cpu_max = (double)cpu[options->repeats - 1];
    status = 0;
done:
    free(results); free(wall); free(cpu);
    return status;
}

static const char *method_name(qihse_search_method_t method) {
    return method == QIHSE_SEARCH_EXACT ? "exact" : method == QIHSE_SEARCH_RFF_COSINE ? "phase" : "paired";
}

static void json_string(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

static void csv_string(const char *text) {
    putchar('"');
    for (const char *p = text; *p; ++p) { if (*p == '"') putchar('"'); putchar(*p); }
    putchar('"');
}

static void print_header(int csv) {
    if (csv) {
        printf("dataset,type,records,queries,repeats,seed,gamma,method,dimensions,tile,expected_matches,correct,mismatches,fixture_oracle_ns,wall_ns_min,wall_ns_median,wall_ns_max,cpu_ns_min,cpu_ns_median,cpu_ns_max,amortized_wall_ns_per_query,exact_over_method_wall_ratio");
#define CSV_HEADER(name) printf(",%s_total", #name);
        METRIC_COUNTS(CSV_HEADER)
#undef CSV_HEADER
        puts(",peak_scratch_bytes,setup_ns_mean,scoring_ns_mean,verification_ns_mean,internal_total_ns_mean,checksum,source_revision,source_sha256,compiler,build_profile");
    } else {
        char timestamp[32] = "unknown";
        time_t now = time(NULL);
        struct tm utc;
        struct utsname host;
        if (now != (time_t)-1 && gmtime_r(&now, &utc))
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
        printf("{\"kind\":\"metadata\",\"schema\":\"qihse_core_methods_bench_v1\",\"scope\":\"synthetic scalar exact lookup, not VectorDB\",\"timing_scope\":\"complete batch including kernel setup and metrics\",\"warmup_batches\":1,\"counter_scope\":\"timed repeats summed; scratch is peak\",\"latency_scope\":\"batch distributions; per-query figures are amortized\",\"source_revision\":");
        json_string(QIHSE_BENCH_REVISION);
        printf(",\"source_sha256\":"); json_string(QIHSE_BENCH_SOURCE_SHA256);
        printf(",\"compiler\":"); json_string(__VERSION__);
        printf(",\"build_profile\":"); json_string(QIHSE_BENCH_BUILD_PROFILE);
        printf(",\"run_started_utc\":"); json_string(timestamp);
        printf(",\"affinity_control\":\"none in runner\"");
        if (uname(&host) == 0) {
            printf(",\"system\":"); json_string(host.sysname);
            printf(",\"machine\":"); json_string(host.machine);
        }
        puts("}");
    }
}

static void print_measurement(const fixture_t *fixture, const bench_options_t *options,
                              const measurement_t *value, double baseline) {
    const qihse_search_metrics_t *m = &value->totals;
    double ratio = value->wall_median > 0 ? baseline / value->wall_median : 0;
    const char *type = fixture->type == QIHSE_TYPE_DOUBLE ? "double" : "int64";
    if (options->csv) {
        printf("%s,%s,%zu,%zu,%zu,%" PRIu64 ",%.17g,%s,%zu,%zu,%zu,%s,%zu,%" PRIu64 ",%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.3f,%.9g",
            fixture->name, type, fixture->n, fixture->query_count, options->repeats,
            options->seed, options->gamma, method_name(m->method), m->dimensions, m->tile_size,
            fixture->expected_matches, value->mismatches ? "false" : "true", value->mismatches,
            fixture->setup_ns, value->wall_min, value->wall_median, value->wall_max,
            value->cpu_min, value->cpu_median, value->cpu_max,
            value->wall_median / fixture->query_count, ratio);
#define CSV_VALUE(name) printf(",%zu", m->name);
        METRIC_COUNTS(CSV_VALUE)
#undef CSV_VALUE
        printf(",%zu,%.3f,%.3f,%.3f,%.3f,%" PRIu64 ",", m->peak_scratch_bytes,
            m->setup_time_ns / options->repeats, m->scoring_time_ns / options->repeats,
            m->verification_time_ns / options->repeats, m->total_time_ns / options->repeats, value->checksum);
        csv_string(QIHSE_BENCH_REVISION); putchar(','); csv_string(QIHSE_BENCH_SOURCE_SHA256);
        putchar(','); csv_string(__VERSION__);
        putchar(','); csv_string(QIHSE_BENCH_BUILD_PROFILE); putchar('\n');
    } else {
        printf("{\"kind\":\"measurement\",\"dataset\":\"%s\",\"type\":\"%s\",\"records\":%zu,\"queries\":%zu,\"repeats\":%zu,\"seed\":%" PRIu64 ",\"gamma\":%.17g,\"method\":\"%s\",\"dimensions\":%zu,\"tile\":%zu,\"expected_matches\":%zu,\"correct\":%s,\"mismatches\":%zu,\"fixture_oracle_ns\":%" PRIu64 ",\"wall_ns_min\":%.0f,\"wall_ns_median\":%.0f,\"wall_ns_max\":%.0f,\"cpu_ns_min\":%.0f,\"cpu_ns_median\":%.0f,\"cpu_ns_max\":%.0f,\"amortized_wall_ns_per_query\":%.3f,\"exact_over_method_wall_ratio\":%.9g",
            fixture->name, type, fixture->n, fixture->query_count, options->repeats,
            options->seed, options->gamma, method_name(m->method), m->dimensions, m->tile_size,
            fixture->expected_matches, value->mismatches ? "false" : "true", value->mismatches,
            fixture->setup_ns, value->wall_min, value->wall_median, value->wall_max,
            value->cpu_min, value->cpu_median, value->cpu_max,
            value->wall_median / fixture->query_count, ratio);
#define JSON_VALUE(name) printf(",\"%s_total\":%zu", #name, m->name);
        METRIC_COUNTS(JSON_VALUE)
#undef JSON_VALUE
        printf(",\"peak_scratch_bytes\":%zu,\"setup_ns_mean\":%.3f,\"scoring_ns_mean\":%.3f,\"verification_ns_mean\":%.3f,\"internal_total_ns_mean\":%.3f,\"checksum\":%" PRIu64 "}\n",
            m->peak_scratch_bytes, m->setup_time_ns / options->repeats,
            m->scoring_time_ns / options->repeats, m->verification_time_ns / options->repeats,
            m->total_time_ns / options->repeats, value->checksum);
    }
}

int main(int argc, char **argv) {
    bench_options_t options;
    int parsed = parse_options(argc, argv, &options);
    if (parsed > 0) return 0;
    if (parsed < 0) { usage(stderr, argv[0]); return 2; }
    print_header(options.csv);
    int failed = 0;
    for (size_t dataset = 0; dataset < sizeof(dataset_names) / sizeof(dataset_names[0]); ++dataset) {
        if (strcmp(options.dataset, "all") && strcmp(options.dataset, dataset_names[dataset])) continue;
        fixture_t fixture = {0};
        if (fixture_create(&fixture, &options, dataset)) {
            perror("fixture creation"); fixture_destroy(&fixture); return 1;
        }
        measurement_t exact;
        if (measure(&fixture, &options, QIHSE_SEARCH_EXACT, 0, 1, &exact)) {
            perror("exact benchmark"); fixture_destroy(&fixture); return 1;
        }
        print_measurement(&fixture, &options, &exact, exact.wall_median);
        failed |= exact.mismatches != 0;
        for (int method = QIHSE_SEARCH_RFF_COSINE; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
            if (!(options.methods & METHOD_BIT(method))) continue;
            for (size_t d = 0; d < options.dimension_count; ++d) {
                for (size_t t = 0; t < options.tile_count; ++t) {
                    measurement_t value;
                    if (measure(&fixture, &options, (qihse_search_method_t)method,
                            options.dimensions[d], options.tiles[t], &value)) {
                        fprintf(stderr, "%s/%s D=%zu tile=%zu: %s\n", fixture.name,
                            method_name((qihse_search_method_t)method), options.dimensions[d],
                            options.tiles[t], strerror(errno));
                        fixture_destroy(&fixture); return 1;
                    }
                    print_measurement(&fixture, &options, &value, exact.wall_median);
                    failed |= value.mismatches != 0;
                }
            }
        }
        fixture_destroy(&fixture);
    }
    if (ferror(stdout)) { perror("benchmark output"); return 1; }
    return failed ? 1 : 0;
}
