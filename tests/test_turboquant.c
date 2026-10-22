/* Standalone W12.1 numeric-reference tests. No storage, rows, identities, or
 * query route is exercised; this is not an authorization/integration test.
 * Keep the oracle arithmetic and wire parsing independent of the codec.
 */
#include "quantization/include/qihse_turboquant.h"
#include "quantization/include/qihse_turboquant_tables.h"
#include "quantization/src/qihse_turboquant_rng.h"

#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

enum { TEST_MAX_D = 32, STAT_TRIALS = 2048, STAT_QUERIES = 4 };

static void *allocate(size_t bytes)
{
    void *p = malloc(bytes ? bytes : 1);
    CHECK(p != NULL);
    return p;
}

static void test_chacha20_known_answer(void)
{
    /* RFC 8439 section 2.3.2, published normative input/output test data:
     * https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2
     * No third-party cipher implementation is included in this test. */
    static const uint32_t state[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        0x03020100u, 0x07060504u, 0x0b0a0908u, 0x0f0e0d0cu,
        0x13121110u, 0x17161514u, 0x1b1a1918u, 0x1f1e1d1cu,
        0x00000001u, 0x09000000u, 0x4a000000u, 0x00000000u
    };
    static const uint32_t expected[16] = {
        0xe4e7f110u, 0x15593bd1u, 0x1fdd0f50u, 0xc47120a3u,
        0xc7f4d1c7u, 0x0368c033u, 0x9aaa2204u, 0x4e6cd4c3u,
        0x466482d2u, 0x09aa9f07u, 0x05d7c214u, 0xa2028bd9u,
        0xd19c12b5u, 0xb94e16deu, 0xe883d0cbu, 0x4e3c50a2u
    };
    uint32_t actual[16];
    tq_chacha20_block(state, actual);
    CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
    puts("RFC 8439 ChaCha20 block known-answer vector: passed");
}

static void reference_projection(uint64_t seed, double *matrix, size_t d)
{
    uint32_t state[16] = {0};
    size_t emitted = 0;
    state[0] = 0x61707865u; state[1] = 0x3320646eu;
    state[2] = 0x79622d32u; state[3] = 0x6b206574u;
    state[4] = (uint32_t)seed; state[5] = (uint32_t)(seed >> 32);
    state[13] = 1; state[14] = 0x54515231u; state[15] = QIHSE_TQ_REFERENCE_VERSION;
    /* Generator-conformance oracle: the block is tested against the RFC
     * above, while counter consumption, LE u64 assembly, open uniform mapping,
     * Box-Muller pairs, row order and sign packing are reconstructed here.
     * Statistical independence/distribution is tested separately below. */
    while (emitted < d * d) {
        uint32_t words[16];
        size_t offset;
        tq_chacha20_block(state, words);
        ++state[12];
        for (offset = 0; offset < 16 && emitted < d * d; offset += 4) {
            uint64_t a = (uint64_t)words[offset] | ((uint64_t)words[offset + 1] << 32);
            uint64_t b = (uint64_t)words[offset + 2] | ((uint64_t)words[offset + 3] << 32);
            double u = ((double)(a >> 12) + 0.5) / 4503599627370496.0;
            double v = ((double)(b >> 12) + 0.5) / 4503599627370496.0;
            double radius = sqrt(-2.0 * log(u)), angle = 2.0 * acos(-1.0) * v;
            CHECK(u > 0.0 && u < 1.0 && v > 0.0 && v < 1.0);
            matrix[emitted++] = radius * cos(angle);
            if (emitted < d * d) matrix[emitted++] = radius * sin(angle);
        }
    }
}

static int close_to(double actual, double expected, double atol, double rtol)
{
    return isfinite(actual) && isfinite(expected)
        && fabs(actual - expected) <= atol + rtol * fabs(expected);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get_u32(const uint8_t *p)
{
    uint32_t value = 0;
    unsigned i;
    for (i = 0; i < 4; ++i) value |= (uint32_t)p[i] << (8 * i);
    return value;
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (8 * i);
    return value;
}

static void put_u32(uint8_t *p, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static void put_u64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static double get_f64(const uint8_t *p)
{
    uint64_t bits = get_u64(p);
    double result;
    memcpy(&result, &bits, sizeof(result));
    return result;
}

static void put_f64(uint8_t *p, double value)
{
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    put_u64(p, bits);
}

/* Standard reflected IEEE CRC-32, with the checksum word itself excluded. */
static uint32_t independent_crc32(const uint8_t *code, size_t size)
{
    uint32_t crc = UINT32_MAX;
    size_t i;
    for (i = 0; i < size; ++i) {
        unsigned bit;
        if (i >= 60 && i < 64) continue;
        crc ^= code[i];
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0u - (crc & 1u)));
    }
    return ~crc;
}

static void reseal(uint8_t *code, size_t size)
{
    put_u32(code + 60, independent_crc32(code, size));
}

static unsigned unpack_index(const uint8_t *payload, size_t index, unsigned bits)
{
    unsigned result = 0, bit;
    for (bit = 0; bit < bits; ++bit) {
        size_t position = index * bits + bit;
        result |= ((payload[position / 8] >> (position % 8)) & 1u) << bit;
    }
    return result;
}

static void pack_index(uint8_t *payload, size_t index, unsigned bits, unsigned value)
{
    unsigned bit;
    for (bit = 0; bit < bits; ++bit) {
        size_t position = index * bits + bit;
        payload[position / 8] |= (uint8_t)(((value >> bit) & 1u) << (position % 8));
    }
}

static double norm_squared(const float *x, size_t d)
{
    double total = 0.0;
    size_t i;
    for (i = 0; i < d; ++i) total += (double)x[i] * (double)x[i];
    return total;
}

static double dot_float(const float *x, const float *y, size_t d)
{
    double total = 0.0;
    size_t i;
    for (i = 0; i < d; ++i) total += (double)x[i] * (double)y[i];
    return total;
}

static double dot_decoded(const float *q, const double *x, size_t d)
{
    double total = 0.0;
    size_t i;
    for (i = 0; i < d; ++i) total += (double)q[i] * x[i];
    return total;
}

static qihse_tq_config config_for(unsigned d, unsigned bits, qihse_tq_variant variant)
{
    qihse_tq_config config;
    config.dimensions = d;
    config.scalar_bits = bits;
    config.variant = variant;
    config.rotation_seed = UINT64_C(0x63c2f97a02db8a41);
    config.projection_seed = variant == QIHSE_TQ_PRODUCT
        ? UINT64_C(0xd7a649f0b2083e15) : 0;
    return config;
}

static qihse_tq_profile *create_profile(const qihse_tq_config *config)
{
    qihse_tq_profile *profile = NULL;
    CHECK(qihse_tq_profile_create(config, &profile) == 0);
    CHECK(profile != NULL);
    return profile;
}

static void fixture(float *x, float *q, size_t d)
{
    size_t i;
    for (i = 0; i < d; ++i) {
        x[i] = (float)((int)((13 * i + 7 * d) % 23) - 11) * 0.125f;
        q[i] = (float)((int)((17 * i + 3 * d) % 29) - 14) * 0.25f;
    }
}

static void check_orthogonality(const double *rotation, size_t d)
{
    size_t i, j, k;
    for (i = 0; i < d; ++i) {
        for (j = 0; j < d; ++j) {
            double rows = 0.0, columns = 0.0;
            for (k = 0; k < d; ++k) {
                CHECK(isfinite(rotation[i * d + k]));
                rows += rotation[i * d + k] * rotation[j * d + k];
                columns += rotation[k * d + i] * rotation[k * d + j];
            }
            CHECK(close_to(rows, i == j ? 1.0 : 0.0, 3e-12, 0.0));
            CHECK(close_to(columns, i == j ? 1.0 : 0.0, 3e-12, 0.0));
        }
    }
}

static void check_scores(const qihse_tq_profile *profile, const uint8_t *code,
                         size_t bytes, const float *x, const float *q, size_t d)
{
    double decoded[TEST_MAX_D], dot, cosine, l2;
    double x2 = norm_squared(x, d), q2 = norm_squared(q, d);
    double natural_scale = sqrt(x2) * sqrt(q2);
    qihse_tq_query *query = NULL;
    CHECK(qihse_tq_decode(profile, code, bytes, decoded, d) == 0);
    CHECK(qihse_tq_prepare_query(profile, q, d, &query) == 0);
    CHECK(query != NULL);
    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_DOT, &dot) == 0);
    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_COSINE, &cosine) == 0);
    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_L2_SQUARED, &l2) == 0);
    CHECK(close_to(dot, dot_decoded(q, decoded, d),
                   2e-12 * natural_scale + 32 * DBL_MIN, 3e-12));
    CHECK(close_to(cosine, x2 == 0.0 || q2 == 0.0 ? 0.0 : dot / natural_scale,
                   2e-12, 3e-12));
    CHECK(close_to(l2, x2 + q2 - 2.0 * dot,
                   3e-12 * (x2 + q2) + 32 * DBL_MIN, 3e-12));
    qihse_tq_query_destroy(query);
}

static void check_envelope(const qihse_tq_config *config,
                           const uint8_t *code, size_t bytes, const float *x)
{
    size_t scalar_bytes = (config->dimensions * config->scalar_bits + 7u) / 8u;
    size_t signs_bytes = config->variant == QIHSE_TQ_PRODUCT
        ? (config->dimensions + 7u) / 8u : 0;
    unsigned remainder = (config->dimensions * config->scalar_bits) % 8u;
    CHECK(bytes == QIHSE_TQ_CODE_HEADER_BYTES + scalar_bytes + signs_bytes);
    CHECK(memcmp(code, "QTQR", 4) == 0);
    CHECK(get_u16(code + 4) == QIHSE_TQ_REFERENCE_VERSION);
    CHECK(code[6] == (uint8_t)config->variant);
    CHECK(code[7] == config->scalar_bits);
    CHECK(get_u32(code + 8) == config->dimensions);
    CHECK(get_u32(code + 12) == QIHSE_TQ_TABLES_VERSION);
    CHECK(get_u64(code + 16) == config->rotation_seed);
    CHECK(get_u64(code + 24) == config->projection_seed);
    CHECK(close_to(get_f64(code + 40), sqrt(norm_squared(x, config->dimensions)),
                   32 * DBL_MIN, 4e-15));
    CHECK(isfinite(get_f64(code + 48)) && get_f64(code + 48) >= 0.0);
    if (config->variant == QIHSE_TQ_MSE) CHECK(get_f64(code + 48) == 0.0);
    CHECK(get_u32(code + 56) == scalar_bytes + signs_bytes);
    CHECK(get_u32(code + 60) == independent_crc32(code, bytes));
    if (remainder)
        CHECK((code[64 + scalar_bytes - 1] >> remainder) == 0);
    if (signs_bytes && config->dimensions % 8)
        CHECK((code[bytes - 1] >> (config->dimensions % 8)) == 0);
}

static void test_roundtrips_and_packing(void)
{
    static const unsigned dimensions[] = {2, 3, 5, 9, 17, 32};
    size_t dimension_index;
    unsigned bits, variant;
    for (dimension_index = 0; dimension_index < sizeof(dimensions) / sizeof(dimensions[0]);
         ++dimension_index) {
        size_t d = dimensions[dimension_index];
        double *canonical_rotation = allocate(d * d * sizeof(*canonical_rotation));
        for (bits = 1; bits <= 4; ++bits) {
            for (variant = 0; variant <= 1; ++variant) {
                qihse_tq_config config = config_for((unsigned)d, bits, (qihse_tq_variant)variant);
                qihse_tq_profile *profile = create_profile(&config);
                qihse_tq_profile *recreated = create_profile(&config);
                float x[TEST_MAX_D], q[TEST_MAX_D];
                double coarse[TEST_MAX_D], decoded[TEST_MAX_D], other[TEST_MAX_D];
                double centroids[16], gamma2 = 0.0, rho;
                double *rotation = allocate(d * d * sizeof(*rotation));
                double *again = allocate(d * d * sizeof(*again));
                size_t bytes = 0, scalar_bytes = (d * bits + 7) / 8;
                size_t i, j;
                uint8_t *code, *repeat, *expected_payload;
                fixture(x, q, d);
                rho = sqrt(norm_squared(x, d));
                CHECK(qihse_tq_code_size(&config, &bytes) == 0);
                code = allocate(bytes);
                repeat = allocate(bytes);
                expected_payload = calloc(scalar_bytes, 1);
                CHECK(expected_payload != NULL);
                CHECK(qihse_tq_profile_matrix_bytes(profile) == d * d * sizeof(double) * (1u + variant));
                CHECK(qihse_tq_profile_copy_rotation(profile, rotation, d * d) == 0);
                CHECK(qihse_tq_profile_copy_rotation(recreated, again, d * d) == 0);
                CHECK(memcmp(rotation, again, d * d * sizeof(*rotation)) == 0);
                if (bits == 1 && variant == 0)
                    memcpy(canonical_rotation, rotation, d * d * sizeof(*rotation));
                CHECK(memcmp(rotation, canonical_rotation, d * d * sizeof(*rotation)) == 0);
                check_orthogonality(rotation, d);
                CHECK(qihse_tq_encode(profile, x, d, code, bytes) == 0);
                CHECK(qihse_tq_encode(profile, x, d, repeat, bytes) == 0);
                CHECK(memcmp(code, repeat, bytes) == 0);
                CHECK(qihse_tq_encode(recreated, x, d, repeat, bytes) == 0);
                CHECK(memcmp(code, repeat, bytes) == 0);
                check_envelope(&config, code, bytes, x);
                CHECK(qihse_tq_decode_mse(profile, code, bytes, coarse, d) == 0);
                CHECK(qihse_tq_decode(profile, code, bytes, decoded, d) == 0);
                CHECK(qihse_tq_decode(recreated, code, bytes, other, d) == 0);
                CHECK(memcmp(decoded, other, d * sizeof(*decoded)) == 0);
                CHECK(qihse_tq_build_centroids(d, bits, centroids, (size_t)1u << bits) == 0);
                /* Determine expected indices without using codec bit extraction. */
                for (i = 0; i < d; ++i) {
                    double rotated = 0.0, best_distance;
                    unsigned best = 0, candidate;
                    for (j = 0; j < d; ++j) rotated += rotation[i * d + j] * ((double)x[j] / rho);
                    best_distance = fabs(rotated - centroids[0]);
                    for (candidate = 1; candidate < (1u << bits); ++candidate) {
                        double distance = fabs(rotated - centroids[candidate]);
                        if (distance < best_distance) { best = candidate; best_distance = distance; }
                    }
                    pack_index(expected_payload, i, bits, best);
                    CHECK(unpack_index(code + 64, i, bits) == best);
                }
                CHECK(memcmp(code + 64, expected_payload, scalar_bytes) == 0);
                for (i = 0; i < d; ++i) {
                    double expected = 0.0, residual;
                    for (j = 0; j < d; ++j)
                        expected += rotation[j * d + i] * centroids[unpack_index(expected_payload, j, bits)];
                    CHECK(close_to(coarse[i], rho * expected, rho * 3e-12, 3e-12));
                    residual = (double)x[i] / rho - coarse[i] / rho;
                    gamma2 += residual * residual;
                    if (variant == QIHSE_TQ_MSE) CHECK(decoded[i] == coarse[i]);
                }
                if (variant == QIHSE_TQ_PRODUCT) {
                    double *projection = allocate(d * d * sizeof(*projection));
                    double signs[TEST_MAX_D];
                    CHECK(close_to(get_f64(code + 48), sqrt(gamma2), 2e-12, 2e-12));
                    reference_projection(config.projection_seed, projection, d);
                    for (i = 0; i < d; ++i) {
                        double projected_residual = 0.0;
                        for (j = 0; j < d; ++j)
                            projected_residual += projection[i * d + j]
                                * ((double)x[j] / rho - coarse[j] / rho);
                        signs[i] = projected_residual >= 0.0 ? 1.0 : -1.0;
                        CHECK(unpack_index(code + 64 + scalar_bytes, i, 1)
                              == (unsigned)(signs[i] > 0));
                    }
                    for (i = 0; i < d; ++i) {
                        double correction = 0.0;
                        for (j = 0; j < d; ++j) correction += projection[j * d + i] * signs[j];
                        correction *= rho * sqrt(gamma2) * sqrt(acos(-1.0) / 2.0) / (double)d;
                        CHECK(close_to(decoded[i], coarse[i] + correction, rho * 5e-12, 5e-12));
                    }
                    free(projection);
                }
                check_scores(profile, code, bytes, x, q, d);
                /* The same rotation is independent of the projection RNG stream. */
                if (variant == QIHSE_TQ_PRODUCT) {
                    qihse_tq_profile *reseeded = NULL;
                    CHECK(qihse_tq_profile_reseed_projection(profile, UINT64_C(912345671), &reseeded) == 0);
                    CHECK(qihse_tq_profile_copy_rotation(reseeded, again, d * d) == 0);
                    CHECK(memcmp(rotation, again, d * d * sizeof(*rotation)) == 0);
                    CHECK(qihse_tq_encode(reseeded, x, d, repeat, bytes) == 0);
                    CHECK(memcmp(code + 40, repeat + 40, 16) == 0);
                    CHECK(memcmp(code + 64, repeat + 64, scalar_bytes) == 0);
                    qihse_tq_profile_destroy(reseeded);
                }
                free(expected_payload);
                free(repeat);
                free(code);
                free(again);
                free(rotation);
                qihse_tq_profile_destroy(recreated);
                qihse_tq_profile_destroy(profile);
            }
        }
        free(canonical_rotation);
    }
    puts("roundtrip, independent packing, rotation, and score identities: passed");
}

static void expect_invalid_config(qihse_tq_config config)
{
    qihse_tq_profile *profile = (qihse_tq_profile *)(uintptr_t)1;
    size_t bytes = 12345;
    CHECK(qihse_tq_profile_create(&config, &profile) != 0);
    CHECK(profile == NULL);
    CHECK(qihse_tq_code_size(&config, &bytes) != 0);
    CHECK(bytes == 12345);
}

static void test_argument_contract(void)
{
    qihse_tq_config config = config_for(5, 3, QIHSE_TQ_MSE), invalid;
    qihse_tq_profile *profile, *failed = (qihse_tq_profile *)(uintptr_t)1;
    qihse_tq_query *query, *failed_query;
    float x[5] = {1, -2, 3, -4, 5};
    double rotation[25], rotation_before[25], out[5], out_before[5], score;
    uint8_t *code, *before;
    size_t bytes = 0;
    unsigned i;
    invalid = config; invalid.dimensions = 0; expect_invalid_config(invalid);
    invalid.dimensions = 1; expect_invalid_config(invalid);
    invalid.dimensions = QIHSE_TQ_MAX_DIMENSIONS + 1; expect_invalid_config(invalid);
    invalid = config; invalid.scalar_bits = 0; expect_invalid_config(invalid);
    invalid.scalar_bits = 5; expect_invalid_config(invalid);
    invalid = config; invalid.variant = (qihse_tq_variant)2; expect_invalid_config(invalid);
    invalid.variant = (qihse_tq_variant)-1; expect_invalid_config(invalid);
    invalid = config; invalid.projection_seed = 1; expect_invalid_config(invalid);
    CHECK(qihse_tq_profile_create(NULL, &failed) != 0 && failed == NULL);
    CHECK(qihse_tq_profile_create(&config, NULL) != 0);
    CHECK(qihse_tq_code_size(NULL, &bytes) != 0);
    CHECK(qihse_tq_code_size(&config, NULL) != 0);
    invalid = config_for(QIHSE_TQ_MAX_DIMENSIONS, 4, QIHSE_TQ_PRODUCT);
    CHECK(qihse_tq_code_size(&invalid, &bytes) == 0);
    CHECK(bytes == 64 + (4 * QIHSE_TQ_MAX_DIMENSIONS + 7) / 8
                       + (QIHSE_TQ_MAX_DIMENSIONS + 7) / 8);
    profile = create_profile(&config);
    CHECK(qihse_tq_profile_reseed_projection(profile, 1, &failed) != 0 && failed == NULL);
    for (i = 0; i < 25; ++i) rotation[i] = 99.0 + i;
    memcpy(rotation_before, rotation, sizeof(rotation));
    CHECK(qihse_tq_profile_copy_rotation(profile, rotation, 24) != 0);
    CHECK(memcmp(rotation, rotation_before, sizeof(rotation)) == 0);
    CHECK(qihse_tq_profile_copy_rotation(profile, NULL, 25) != 0);
    CHECK(qihse_tq_code_size(&config, &bytes) == 0);
    code = allocate(bytes + 1); before = allocate(bytes + 1);
    memset(code, 0xa5, bytes + 1); memcpy(before, code, bytes + 1);
    CHECK(qihse_tq_encode(profile, x, 4, code, bytes) != 0);
    CHECK(memcmp(code, before, bytes + 1) == 0);
    CHECK(qihse_tq_encode(profile, x, 5, code, bytes - 1) != 0);
    CHECK(memcmp(code, before, bytes + 1) == 0);
    CHECK(qihse_tq_encode(profile, x, 5, code, bytes + 1) != 0);
    CHECK(memcmp(code, before, bytes + 1) == 0);
    CHECK(qihse_tq_encode(profile, NULL, 5, code, bytes) != 0);
    CHECK(qihse_tq_encode(NULL, x, 5, code, bytes) != 0);
    CHECK(qihse_tq_encode(profile, x, 5, NULL, bytes) != 0);
    CHECK(memcmp(code, before, bytes + 1) == 0);
    CHECK(qihse_tq_encode(profile, x, 5, code, bytes) == 0);
    failed_query = (qihse_tq_query *)(uintptr_t)1;
    CHECK(qihse_tq_prepare_query(profile, x, 4, &failed_query) != 0);
    CHECK(failed_query == NULL);
    CHECK(qihse_tq_prepare_query(profile, x, 5, NULL) != 0);
    failed_query = (qihse_tq_query *)(uintptr_t)1;
    CHECK(qihse_tq_prepare_query(profile, NULL, 5, &failed_query) != 0 && failed_query == NULL);
    CHECK(qihse_tq_prepare_query(profile, x, 5, &query) == 0);
    for (i = 0; i < 5; ++i) out[i] = 123.0 + i;
    memcpy(out_before, out, sizeof(out));
    CHECK(qihse_tq_decode(profile, code, bytes, out, 4) != 0);
    CHECK(qihse_tq_decode_mse(profile, code, bytes, out, 4) != 0);
    CHECK(qihse_tq_decode(profile, NULL, bytes, out, 5) != 0);
    CHECK(qihse_tq_decode(NULL, code, bytes, out, 5) != 0);
    CHECK(qihse_tq_decode(profile, code, bytes, NULL, 5) != 0);
    CHECK(memcmp(out, out_before, sizeof(out)) == 0);
    score = 123.0;
    CHECK(qihse_tq_score(profile, query, code, bytes, (qihse_tq_metric)3, &score) != 0);
    CHECK(qihse_tq_score(profile, query, code, bytes, (qihse_tq_metric)-1, &score) != 0);
    CHECK(qihse_tq_score(profile, NULL, code, bytes, QIHSE_TQ_DOT, &score) != 0);
    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_DOT, NULL) != 0);
    CHECK(score == 123.0);
    qihse_tq_query_destroy(query);
    qihse_tq_profile_destroy(profile);
    qihse_tq_query_destroy(NULL);
    qihse_tq_profile_destroy(NULL);
    free(before); free(code);
    puts("argument validation and unchanged-on-failure outputs: passed");
}

static void expect_code_rejected(const qihse_tq_profile *profile,
                                 const qihse_tq_query *query,
                                 const uint8_t *code, size_t bytes, size_t d)
{
    double out[TEST_MAX_D], before[TEST_MAX_D], score = 314159.25;
    size_t i;
    for (i = 0; i < TEST_MAX_D; ++i) out[i] = 987.0 + (double)i;
    memcpy(before, out, sizeof(out));
    CHECK(qihse_tq_decode(profile, code, bytes, out, d) != 0);
    CHECK(memcmp(out, before, sizeof(out)) == 0);
    CHECK(qihse_tq_decode_mse(profile, code, bytes, out, d) != 0);
    CHECK(memcmp(out, before, sizeof(out)) == 0);
    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_DOT, &score) != 0);
    CHECK(score == 314159.25);
}

static uint64_t splitmix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static void test_malformed_envelopes(void)
{
    qihse_tq_config config = config_for(9, 3, QIHSE_TQ_PRODUCT);
    qihse_tq_profile *profile = create_profile(&config);
    qihse_tq_query *query = NULL;
    float x[9], q[9];
    size_t bytes = 0, i;
    uint8_t *code, *bad;
    static const size_t incompatible_fields[] = {4, 6, 7, 8, 12, 16, 24, 32, 56};
    static const double invalid_norms[] = {-1.0, -0.0, INFINITY, -INFINITY, NAN, 1e100};
    fixture(x, q, 9);
    CHECK(qihse_tq_code_size(&config, &bytes) == 0);
    code = allocate(bytes); bad = allocate(bytes + 17);
    CHECK(qihse_tq_encode(profile, x, 9, code, bytes) == 0);
    CHECK(qihse_tq_prepare_query(profile, q, 9, &query) == 0);
    /* Every possible truncation, not only a missing final byte. */
    for (i = 0; i < bytes; ++i) expect_code_rejected(profile, query, code, i, 9);
    memcpy(bad, code, bytes); bad[bytes] = 0;
    expect_code_rejected(profile, query, bad, bytes + 1, 9);
    /* Flip every individual bit, including all four checksum bytes. */
    for (i = 0; i < bytes * 8; ++i) {
        memcpy(bad, code, bytes);
        bad[i / 8] ^= (uint8_t)(1u << (i % 8));
        expect_code_rejected(profile, query, bad, bytes, 9);
    }
    /* Recompute the checksum so semantic checks cannot hide behind CRC. */
    for (i = 0; i < sizeof(incompatible_fields) / sizeof(incompatible_fields[0]); ++i) {
        memcpy(bad, code, bytes); bad[incompatible_fields[i]] ^= 1;
        reseal(bad, bytes);
        expect_code_rejected(profile, query, bad, bytes, 9);
    }
    for (i = 0; i < sizeof(invalid_norms) / sizeof(invalid_norms[0]); ++i) {
        memcpy(bad, code, bytes); put_f64(bad + 40, invalid_norms[i]); reseal(bad, bytes);
        expect_code_rejected(profile, query, bad, bytes, 9);
        memcpy(bad, code, bytes); put_f64(bad + 48, invalid_norms[i]); reseal(bad, bytes);
        expect_code_rejected(profile, query, bad, bytes, 9);
    }
    memcpy(bad, code, bytes); put_f64(bad + 40, 0.0); reseal(bad, bytes);
    expect_code_rejected(profile, query, bad, bytes, 9);
    memcpy(bad, code, bytes); put_f64(bad + 48, 0.0); bad[68] = 1; reseal(bad, bytes);
    expect_code_rejected(profile, query, bad, bytes, 9); /* gamma zero, nonzero signs */
    memcpy(bad, code, bytes);
    put_f64(bad + 40, 0.0); put_f64(bad + 48, 0.0);
    memset(bad + 64, 0, bytes - 64); bad[64] = 1; reseal(bad, bytes);
    expect_code_rejected(profile, query, bad, bytes, 9); /* rho zero, nonzero indices */
    memcpy(bad, code, bytes); bad[67] |= 0x80; reseal(bad, bytes);
    expect_code_rejected(profile, query, bad, bytes, 9); /* 27 scalar bits */
    memcpy(bad, code, bytes); bad[bytes - 1] |= 0x80; reseal(bad, bytes);
    expect_code_rejected(profile, query, bad, bytes, 9); /* 9 residual signs */
    /* Deterministic bounded malformed-input smoke, useful under sanitizers. */
    for (i = 0; i < 1024; ++i) {
        size_t length = (size_t)(splitmix(i) % (bytes + 18)), j;
        for (j = 0; j < length; ++j) bad[j] = (uint8_t)splitmix(i * 123 + j);
        expect_code_rejected(profile, query, bad, length, 9);
    }
    for (i = 0; i < 5; ++i) {
        qihse_tq_config other = config;
        qihse_tq_profile *different;
        qihse_tq_query *different_query = NULL;
        float zero[TEST_MAX_D] = {0};
        if (i == 0) other.rotation_seed ^= 1;
        if (i == 1) other.projection_seed ^= 1;
        if (i == 2) other.scalar_bits = 2;
        if (i == 3) other.dimensions = 8;
        if (i == 4) { other.variant = QIHSE_TQ_MSE; other.projection_seed = 0; }
        different = create_profile(&other);
        CHECK(qihse_tq_prepare_query(different, zero, other.dimensions, &different_query) == 0);
        expect_code_rejected(different, different_query, code, bytes, other.dimensions);
        {
            double score = 123.0;
            CHECK(qihse_tq_score(profile, different_query, code, bytes, QIHSE_TQ_DOT, &score) != 0);
            CHECK(score == 123.0);
        }
        qihse_tq_query_destroy(different_query);
        qihse_tq_profile_destroy(different);
    }
    qihse_tq_query_destroy(query); qihse_tq_profile_destroy(profile);
    config = config_for(9, 3, QIHSE_TQ_MSE);
    profile = create_profile(&config);
    CHECK(qihse_tq_code_size(&config, &bytes) == 0);
    CHECK(qihse_tq_encode(profile, x, 9, code, bytes) == 0);
    CHECK(qihse_tq_prepare_query(profile, q, 9, &query) == 0);
    put_f64(code + 48, 0.25); reseal(code, bytes);
    expect_code_rejected(profile, query, code, bytes, 9);
    qihse_tq_query_destroy(query); qihse_tq_profile_destroy(profile);
    free(bad); free(code);
    puts("malformed, truncated, incompatible, noncanonical, and mutation cases: passed");
}

static void test_extreme_and_invalid_inputs(void)
{
    unsigned variant;
    static const float invalid_values[] = {NAN, INFINITY, -INFINITY};
    for (variant = 0; variant <= 1; ++variant) {
        qihse_tq_config config = config_for(5, 2, (qihse_tq_variant)variant);
        qihse_tq_profile *profile = create_profile(&config);
        float x[5], q[5] = {1, -2, 0.5f, 4, -0.25f}, zero[5] = {0};
        float tiny = nextafterf(0.0f, 1.0f);
        double decoded[5];
        size_t bytes = 0, i, j;
        uint8_t *code, *before;
        CHECK(tiny > 0.0f && tiny < FLT_MIN);
        CHECK(qihse_tq_code_size(&config, &bytes) == 0);
        code = allocate(bytes); before = allocate(bytes);
        CHECK(qihse_tq_encode(profile, zero, 5, code, bytes) == 0);
        CHECK(get_f64(code + 40) == 0.0 && get_f64(code + 48) == 0.0);
        CHECK(qihse_tq_decode(profile, code, bytes, decoded, 5) == 0);
        for (i = 0; i < 5; ++i) CHECK(decoded[i] == 0.0);
        check_scores(profile, code, bytes, zero, q, 5);
        check_scores(profile, code, bytes, zero, zero, 5);
        /* Signs of zero must not manufacture a nonzero encoded vector. */
        for (i = 0; i < 5; ++i) x[i] = -0.0f;
        CHECK(qihse_tq_encode(profile, x, 5, before, bytes) == 0);
        CHECK(memcmp(code, before, bytes) == 0);
        for (j = 0; j < 4; ++j) {
            if (j == 0) { x[0] = FLT_MAX; x[1] = -FLT_MAX; x[2] = FLT_MAX; x[3] = 0; x[4] = 1; }
            if (j == 1) { x[0] = tiny; x[1] = -tiny; x[2] = 2 * tiny; x[3] = 0; x[4] = 3 * tiny; }
            if (j == 2) { x[0] = FLT_MAX; x[1] = tiny; x[2] = -FLT_MIN; x[3] = 1; x[4] = -1; }
            if (j == 3) { x[0] = FLT_MIN; x[1] = -FLT_MIN; x[2] = tiny; x[3] = 0; x[4] = 1e-20f; }
            CHECK(qihse_tq_encode(profile, x, 5, code, bytes) == 0);
            check_envelope(&config, code, bytes, x);
            CHECK(qihse_tq_decode(profile, code, bytes, decoded, 5) == 0);
            for (i = 0; i < 5; ++i) CHECK(isfinite(decoded[i]));
            check_scores(profile, code, bytes, x, q, 5);
            check_scores(profile, code, bytes, x, x, 5);
            check_scores(profile, code, bytes, x, zero, 5);
        }
        /* Nonfinite input in every position must fail without partial output. */
        for (i = 0; i < 5; ++i) {
            for (j = 0; j < sizeof(invalid_values) / sizeof(invalid_values[0]); ++j) {
                qihse_tq_query *failed = (qihse_tq_query *)(uintptr_t)1;
                memcpy(x, q, sizeof(x)); x[i] = invalid_values[j];
                memset(code, 0x6b, bytes); memcpy(before, code, bytes);
                CHECK(qihse_tq_encode(profile, x, 5, code, bytes) != 0);
                CHECK(memcmp(code, before, bytes) == 0);
                CHECK(qihse_tq_prepare_query(profile, x, 5, &failed) != 0 && failed == NULL);
            }
        }
        free(before); free(code); qihse_tq_profile_destroy(profile);
    }
    puts("zero, nonfinite, finite FLT_MAX, dynamic range, and subnormal inputs: passed");
}

static void test_maximum_finite_norm_regressions(void)
{
    static const unsigned dimensions[] = {18, 29};
    size_t scenario, i;
    unsigned variant;
    for (scenario = 0; scenario < 2; ++scenario) {
        size_t d = dimensions[scenario];
        for (variant = 0; variant <= 1; ++variant) {
            qihse_tq_config config = config_for((unsigned)d, 2, (qihse_tq_variant)variant);
            qihse_tq_profile *profile = create_profile(&config);
            float x[TEST_MAX_D], q[TEST_MAX_D];
            double decoded[TEST_MAX_D];
            size_t bytes = 0;
            uint8_t *code;
            CHECK(qihse_tq_code_size(&config, &bytes) == 0);
            code = allocate(bytes);
            for (i = 0; i < d; ++i) { x[i] = FLT_MAX; q[i] = (i % 2) ? -FLT_MAX : FLT_MAX; }
            /* FP64 accumulation/sqrt may round slightly above the ideal real
             * sqrt(d)*FLT_MAX bound. Every finite FP32 input is still valid. */
            CHECK(qihse_tq_encode(profile, x, d, code, bytes) == 0);
            CHECK(qihse_tq_decode(profile, code, bytes, decoded, d) == 0);
            check_envelope(&config, code, bytes, x);
            check_scores(profile, code, bytes, x, x, d);
            check_scores(profile, code, bytes, x, q, d);
            for (i = 0; i < d; ++i) x[i] = -FLT_MAX;
            CHECK(qihse_tq_encode(profile, x, d, code, bytes) == 0);
            CHECK(qihse_tq_decode(profile, code, bytes, decoded, d) == 0);
            check_scores(profile, code, bytes, x, q, d);
            free(code);
            qihse_tq_profile_destroy(profile);
        }
    }
    puts("maximum finite norm rounding regressions (d=18,29): passed");
}

typedef struct running_moments {
    double mean;
    double m2;
} running_moments;

static void add_sample(running_moments *moments, double value, size_t count)
{
    double delta = value - moments->mean;
    moments->mean += delta / (double)count;
    moments->m2 += delta * (value - moments->mean);
}

static void test_haar_spherical_moments(void)
{
    enum { DIMENSION = 8, TRIALS = 2048 };
    const double d = DIMENSION, n = TRIALS;
    const double second = 1.0 / d;
    const double fourth = 3.0 / (d * (d + 2.0));
    const double eighth = 105.0 / (d * (d + 2.0) * (d + 4.0) * (d + 6.0));
    const double mean_se = sqrt(second / n);
    const double second_se = sqrt((fourth - second * second) / n);
    const double fourth_se = sqrt((eighth - fourth * fourth) / n);
    running_moments first[DIMENSION] = {{0}}, squares[DIMENSION] = {{0}};
    running_moments fourths[DIMENSION] = {{0}}, cross[DIMENSION - 1] = {{0}};
    size_t trial, coordinate;
    for (trial = 0; trial < TRIALS; ++trial) {
        qihse_tq_config config = config_for(DIMENSION, 1, QIHSE_TQ_MSE);
        qihse_tq_profile *profile;
        double rotation[DIMENSION * DIMENSION];
        config.rotation_seed = splitmix(UINT64_C(0x91b8d5a72c6034fe) + trial);
        profile = create_profile(&config);
        CHECK(qihse_tq_profile_copy_rotation(profile, rotation, DIMENSION * DIMENSION) == 0);
        check_orthogonality(rotation, DIMENSION);
        /* Pi * e_1 must be uniform on S^(d-1). In particular, a QR routine
         * with the wrong diagonal-sign convention fails the mean test. */
        for (coordinate = 0; coordinate < DIMENSION; ++coordinate) {
            double value = rotation[coordinate * DIMENSION], value2 = value * value;
            add_sample(&first[coordinate], value, trial + 1);
            add_sample(&squares[coordinate], value2, trial + 1);
            add_sample(&fourths[coordinate], value2 * value2, trial + 1);
            if (coordinate)
                add_sample(&cross[coordinate - 1], rotation[0] * value, trial + 1);
        }
        qihse_tq_profile_destroy(profile);
    }
    for (coordinate = 0; coordinate < DIMENSION; ++coordinate) {
        CHECK(fabs(first[coordinate].mean) <= 5.0 * mean_se + 1e-12);
        CHECK(fabs(squares[coordinate].mean - second) <= 5.0 * second_se + 1e-12);
        CHECK(fabs(fourths[coordinate].mean - fourth) <= 5.0 * fourth_se + 1e-12);
        if (coordinate)
            CHECK(fabs(cross[coordinate - 1].mean) <= 5.0 * sqrt(1.0 / (d * (d + 2.0) * n)) + 1e-12);
    }
    puts("Haar rotation sphere moments, cross moments, and diagonal-sign convention: passed");
}

static void test_conditional_qjl_statistics(void)
{
    static const unsigned dimensions[] = {8, 17};
    static const unsigned widths[] = {2, 1};
    static const char *names[] = {"self", "negative", "orthogonal", "basis"};
    const double pi = acos(-1.0);
    size_t scenario;
    for (scenario = 0; scenario < 2; ++scenario) {
        size_t d = dimensions[scenario], i, j, trial, bytes = 0;
        qihse_tq_config config = config_for((unsigned)d, widths[scenario], QIHSE_TQ_PRODUCT);
        qihse_tq_profile *base = create_profile(&config);
        float x[TEST_MAX_D] = {0}, queries[STAT_QUERIES][TEST_MAX_D] = {{0}};
        double coarse[TEST_MAX_D], residual[TEST_MAX_D], rho, gamma2 = 0.0;
        double truth[STAT_QUERIES], predicted[STAT_QUERIES], fourth_ratio[STAT_QUERIES];
        running_moments moments[STAT_QUERIES] = {{0}};
        uint8_t *base_code, *code;
        size_t scalar_bytes = (d * config.scalar_bits + 7) / 8;
        size_t negative_l2_count = 0;
        for (i = 0; i < d; ++i) x[i] = (float)((int)((7 * i + 2) % 11) - 5) * 0.25f;
        for (i = 0; i < d; ++i) { queries[0][i] = x[i]; queries[1][i] = -x[i]; }
        queries[2][0] = x[1]; queries[2][1] = -x[0];
        queries[3][0] = 1.0f;
        CHECK(dot_float(x, queries[2], d) == 0.0);
        CHECK(qihse_tq_code_size(&config, &bytes) == 0);
        base_code = allocate(bytes); code = allocate(bytes);
        CHECK(qihse_tq_encode(base, x, d, base_code, bytes) == 0);
        CHECK(qihse_tq_decode_mse(base, base_code, bytes, coarse, d) == 0);
        rho = sqrt(norm_squared(x, d));
        for (i = 0; i < d; ++i) {
            residual[i] = (double)x[i] / rho - coarse[i] / rho;
            gamma2 += residual[i] * residual[i];
        }
        CHECK(gamma2 > 0.0);
        CHECK(close_to(get_f64(base_code + 48), sqrt(gamma2), 2e-12, 2e-12));
        for (j = 0; j < STAT_QUERIES; ++j) {
            double q2 = norm_squared(queries[j], d);
            double qr = dot_decoded(queries[j], residual, d);
            double c2 = qr * qr / (gamma2 * q2);
            double a2 = 2.0 / pi;
            double row_variance = 1.0 - a2 * c2;
            double row_fourth = 3.0 - 6.0 * a2 * c2 + (4.0 * a2 - 3.0 * a2 * a2) * c2 * c2;
            truth[j] = dot_float(x, queries[j], d);
            predicted[j] = rho * rho / (double)d * (pi / 2.0 * gamma2 * q2 - qr * qr);
            CHECK(predicted[j] > 0.0);
            /* Central fourth moment of the sum of d independent projection
             * rows, divided by its variance squared. This sets a principled
             * finite-sample tolerance for the sample-variance check below. */
            fourth_ratio[j] = row_fourth / ((double)d * row_variance * row_variance)
                + 3.0 * (double)(d - 1) / (double)d;
        }
        /* Fixed rotation, table, x, residual, and queries. Only S is resampled.
         * Re-encode AND re-prepare all queries for every projection seed. */
        for (trial = 0; trial < STAT_TRIALS; ++trial) {
            uint64_t seed = splitmix(UINT64_C(0x81e6732d559f04ab) + trial);
            qihse_tq_profile *profile = NULL;
            double samples[STAT_QUERIES];
            CHECK(qihse_tq_profile_reseed_projection(base, seed, &profile) == 0);
            CHECK(qihse_tq_encode(profile, x, d, code, bytes) == 0);
            CHECK(memcmp(code + 40, base_code + 40, 16) == 0);
            CHECK(memcmp(code + 64, base_code + 64, scalar_bytes) == 0);
            for (j = 0; j < STAT_QUERIES; ++j) {
                qihse_tq_query *query = NULL;
                CHECK(qihse_tq_prepare_query(profile, queries[j], d, &query) == 0);
                CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_DOT, &samples[j]) == 0);
                CHECK(isfinite(samples[j]));
                add_sample(&moments[j], samples[j], trial + 1);
                if (j == 0 && samples[j] > truth[j] + 1e-10) {
                    double cosine, l2;
                    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_COSINE, &cosine) == 0);
                    CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_L2_SQUARED, &l2) == 0);
                    CHECK(cosine > 1.0 && l2 < 0.0);
                    CHECK(close_to(cosine, samples[j] / truth[j], 2e-12, 2e-12));
                    CHECK(close_to(l2, 2.0 * truth[j] - 2.0 * samples[j], 2e-12, 2e-12));
                    ++negative_l2_count;
                }
                qihse_tq_query_destroy(query);
            }
            CHECK(close_to(samples[1], -samples[0], 2e-12, 2e-12));
            qihse_tq_profile_destroy(profile);
        }
        CHECK(negative_l2_count > 0);
        for (j = 0; j < STAT_QUERIES; ++j) {
            double n = STAT_TRIALS;
            double sample_variance = moments[j].m2 / (n - 1.0);
            double mean_se = sqrt(predicted[j] / n);
            double variance_se = predicted[j] * sqrt((fourth_ratio[j] - (n - 3.0) / (n - 1.0)) / n);
            double floating_tolerance = 5e-11 * (1.0 + fabs(truth[j]) + rho * sqrt(norm_squared(queries[j], d)));
            printf("QJL d=%zu k=%u q=%s n=%u mean_error=% .6g mean_SE=%.6g variance=%.6g predicted=%.6g variance_SE=%.6g\n",
                   d, config.scalar_bits, names[j], (unsigned)STAT_TRIALS,
                   moments[j].mean - truth[j], mean_se, sample_variance, predicted[j], variance_se);
            CHECK(fabs(moments[j].mean - truth[j]) <= 5.0 * mean_se + floating_tolerance);
            CHECK(fabs(sample_variance - predicted[j]) <= 5.0 * variance_se + floating_tolerance);
        }
        free(code); free(base_code); qihse_tq_profile_destroy(base);
    }
    puts("conditional QJL mean/variance and unclamped true-norm metrics: passed");
}

static void test_seed_role_separation_regressions(void)
{
    enum { DIMENSION = 8, TRIALS = 1024 };
    static const unsigned offsets[] = {0, 6};
    static const char *families[] = {"former-m0", "former-m6", "same-seed"};
    const uint64_t old_rotation_tag = UINT64_C(0x51524f5441544531);
    const uint64_t old_projection_tag = UINT64_C(0x514a4c50524f4a31);
    const uint64_t old_increment = UINT64_C(0x9e3779b97f4a7c15);
    const double pi = acos(-1.0), a2 = 2.0 / pi;
    size_t family;
    /* Earlier XOR-tagged additive streams could be made identical (m=0)
     * or shifted by six words (m=6), correlating QR and the residual sketch.
     * These chosen seed relationships are regression data, not the RNG now
     * in use. Nonce-separated ChaCha roles must survive both families.
     * Equal public seeds additionally verify that the new role distinction
     * is not lost. The residual changes with each rotation, so standardize each error by
     * its own conditional SD before aggregating across profile seeds. */
    for (family = 0; family < sizeof(families) / sizeof(families[0]); ++family) {
        running_moments standardized = {0};
        double summed_fourth_ratio = 0.0;
        float x[DIMENSION] = {1.0f};
        size_t trial;
        for (trial = 0; trial < TRIALS; ++trial) {
            qihse_tq_config config = config_for(DIMENSION, 1, QIHSE_TQ_PRODUCT);
            qihse_tq_profile *profile;
            qihse_tq_query *query = NULL;
            uint8_t *code;
            double coarse[DIMENSION], gamma2 = 0.0, qr, estimate, predicted;
            double c2, row_variance, row_fourth;
            size_t bytes = 0, i;
            config.rotation_seed = splitmix(UINT64_C(0x7eb409d1a263f805) + trial);
            config.projection_seed = family == 2 ? config.rotation_seed
                : ((config.rotation_seed ^ old_rotation_tag)
                   + offsets[family] * old_increment) ^ old_projection_tag;
            profile = create_profile(&config);
            CHECK(qihse_tq_code_size(&config, &bytes) == 0);
            code = allocate(bytes);
            CHECK(qihse_tq_encode(profile, x, DIMENSION, code, bytes) == 0);
            CHECK(qihse_tq_decode_mse(profile, code, bytes, coarse, DIMENSION) == 0);
            for (i = 0; i < DIMENSION; ++i) {
                double residual = (double)x[i] - coarse[i];
                gamma2 += residual * residual;
            }
            qr = 1.0 - coarse[0];
            predicted = (pi / 2.0 * gamma2 - qr * qr) / DIMENSION;
            CHECK(predicted > 0.0);
            CHECK(qihse_tq_prepare_query(profile, x, DIMENSION, &query) == 0);
            CHECK(qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_DOT, &estimate) == 0);
            add_sample(&standardized, (estimate - 1.0) / sqrt(predicted), trial + 1);
            c2 = qr * qr / gamma2;
            row_variance = 1.0 - a2 * c2;
            row_fourth = 3.0 - 6.0 * a2 * c2 + (4.0 * a2 - 3.0 * a2 * a2) * c2 * c2;
            summed_fourth_ratio += row_fourth / (DIMENSION * row_variance * row_variance)
                + 3.0 * (DIMENSION - 1.0) / DIMENSION;
            qihse_tq_query_destroy(query);
            qihse_tq_profile_destroy(profile);
            free(code);
        }
        {
            double mean_se = 1.0 / sqrt((double)TRIALS);
            double second_moment = standardized.m2 / TRIALS + standardized.mean * standardized.mean;
            double second_se = sqrt((summed_fourth_ratio / TRIALS - 1.0) / TRIALS);
            printf("seed-role regression family=%s n=%u standardized_mean=% .6g mean_SE=%.6g second_moment=%.6g second_SE=%.6g\n",
                   families[family], (unsigned)TRIALS, standardized.mean, mean_se, second_moment, second_se);
            CHECK(fabs(standardized.mean) <= 5.0 * mean_se + 1e-11);
            CHECK(fabs(second_moment - 1.0) <= 5.0 * second_se + 1e-11);
        }
    }
    puts("formerly identical/shifted seed-family regression smoke: passed");
}

int main(void)
{
    CHECK(sizeof(float) == 4 && sizeof(double) == 8 && FLT_RADIX == 2);
    CHECK(FLT_MANT_DIG == 24 && DBL_MANT_DIG == 53);
    test_chacha20_known_answer();
    test_argument_contract();
    test_roundtrips_and_packing();
    test_malformed_envelopes();
    test_extreme_and_invalid_inputs();
    test_maximum_finite_norm_regressions();
    test_haar_spherical_moments();
    test_conditional_qjl_statistics();
    test_seed_role_separation_regressions();
    puts("All standalone TurboQuant reference tests passed.");
    return EXIT_SUCCESS;
}
