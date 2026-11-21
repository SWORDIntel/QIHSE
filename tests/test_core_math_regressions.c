/* Mathematical and public-ABI regressions for the Hilbert helper APIs. */
#include "qihse.h"
#include "qihse_rff.h"
#include "qihse_superposition.h"
#include "qihse_amplification.h"
#include "qihse_dimensions.h"
#include "qihse_verification.h"
#include <assert.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static void near(double actual, double expected, double tolerance) {
    assert(isfinite(actual));
    assert(fabs(actual - expected) <= tolerance);
}

static void test_public_config_and_amplification(void) {
    struct { qihse_amplification_config_t config; unsigned char guard[16]; } protected;
    memset(&protected, 0xa5, sizeof(protected));
    qihse_amplification_config_init(&protected.config, 16);
    for (size_t i = 0; i < sizeof(protected.guard); ++i) assert(protected.guard[i] == 0xa5);
    double real[16], imag[16] = {0};
    for (size_t i = 0; i < 16; ++i) real[i] = .25;
    qihse_superposition_t state = {0};
    assert(qihse_create_superposition_from_amplitudes(real, imag, 16, &state) == 0);
    protected.config.fixed_rounds = 3;
    size_t targets[] = {0};
    assert(qihse_amplify(&state, targets, 1, &protected.config) == 3);
    double probability[16];
    qihse_superposition_get_probabilities(&state, probability);
    near(probability[0], 0.9613189697265625, 1e-12);
    near(qihse_estimate_success_probability(16, 1, 0), .0625, 1e-12);
    near(qihse_estimate_success_probability(16, 1, 3), probability[0], 1e-12);
    qihse_amplification_stats_t stats;
    assert(qihse_amplification_get_stats(&stats) == 0);
    assert(stats.rounds_performed == 3 && stats.oracle_calls == 3 && stats.diffusion_calls == 3);
    near(stats.success_probability, probability[0], 1e-12);
    double before[16]; memcpy(before, state.real, sizeof(before));
    size_t duplicate[] = {0, 0};
    assert(qihse_amplify(&state, duplicate, 2, &protected.config) < 0 && errno == EINVAL);
    assert(memcmp(before, state.real, sizeof(before)) == 0);
    assert(qihse_amplify_fixed_point(&state, targets, 1, &protected.config) < 0 && errno == ENOTSUP);
    qihse_destroy_superposition(&state);
    assert(qihse_create_superposition_from_amplitudes(real, imag, 16, &state) == 0);
    protected.config.fixed_rounds = 10;
    assert(qihse_amplify_adaptive(&state, targets, 1, &protected.config, .9) == 2);
    qihse_destroy_superposition(&state);
}

static void test_fidelity_normalization_and_measurements(void) {
    double a[] = {.5, .5, .5, .5}, b[] = {.5, .5, -.5, -.5}, im[4] = {0};
    qihse_superposition_t as = {0}, bs = {0};
    assert(qihse_create_superposition_from_amplitudes(a, im, 4, &as) == 0);
    assert(qihse_create_superposition_from_amplitudes(b, im, 4, &bs) == 0);
    near(qihse_superposition_state_fidelity(&as, &as), 1.0, 1e-12);
    near(qihse_superposition_state_fidelity(&as, &bs), 0.0, 1e-12);
    qihse_superposition_apply_phase(&as, .713);
    near(qihse_superposition_state_fidelity(&as, &as), 1.0, 1e-12);
    near(qihse_superposition_get_measurement_confidence(&as), .25, 1e-12);
    size_t observations[10000], repeat[10000], count[4] = {0};
    qihse_superposition_measure_multiple(&as, observations, 10000, 0);
    qihse_superposition_measure_multiple(&as, repeat, 10000, 0);
    assert(memcmp(observations, repeat, sizeof(observations)) == 0);
    for (size_t i = 0; i < 10000; ++i) { assert(observations[i] < 4); ++count[observations[i]]; }
    for (size_t i = 0; i < 4; ++i) assert(count[i] > 2100 && count[i] < 2900);
    qihse_destroy_superposition(&as); qihse_destroy_superposition(&bs);

    double tiny[] = {1e-300}, zero[] = {0}, large[] = {DBL_MAX / 2};
    assert(qihse_create_superposition_from_amplitudes(tiny, zero, 1, &as) == 0);
    assert(qihse_superposition_normalize(&as) == 0 && qihse_superposition_is_normalized(&as));
    near(as.measurement_confidence, 1.0, 1e-12);
    qihse_destroy_superposition(&as);
    assert(qihse_create_superposition_from_amplitudes(large, large, 1, &as) == 0);
    assert(qihse_superposition_normalize(&as) == 0 && qihse_superposition_is_normalized(&as));
    qihse_destroy_superposition(&as);
    assert(qihse_create_superposition_from_amplitudes(zero, zero, 1, &as) == 0);
    assert(qihse_superposition_measure(&as, 0) == SIZE_MAX);
    assert(qihse_superposition_normalize(&as) < 0);
    qihse_destroy_superposition(&as);
    double sparse[] = {0, 1};
    assert(qihse_create_superposition(sparse, 2, 1, &as) == 0);
    for (uint64_t seed = 0; seed < 100; ++seed) assert(qihse_superposition_measure(&as, seed) == 1);
    qihse_destroy_superposition(&as);
    assert(qihse_create_superposition(tiny, SIZE_MAX, 2, &as) < 0 && errno == EOVERFLOW);
    assert(!as.real && !as.imag && !as.phase);

    float raw_a[] = {1, 1}, raw_b[] = {1, -1};
    double fidelity = -1;
    assert(qihse_superposition_fidelity(raw_a, raw_a, 2, &fidelity) == 0); near(fidelity, 1.0, 1e-12);
    assert(qihse_superposition_fidelity(raw_a, raw_b, 2, &fidelity) == 0); near(fidelity, 0.0, 1e-12);
}

static void test_cosine_backends(void) {
    float a[33], b[33];
    for (size_t i = 0; i < 33; ++i) a[i] = b[i] = 1.0f;
    for (size_t n = 1; n <= 33; ++n) {
        near(qihse_cosine_similarity_scalar(a, b, n), 1.0, 1e-12);
        near(qihse_cosine_similarity_avx2(a, b, n), 1.0, 1e-12);
        near(qihse_cosine_similarity_avx512(a, b, n), 1.0, 1e-12);
    }
    for (size_t i = 0; i < 33; ++i) a[i] = b[i] = FLT_MAX / 2.0f;
    near(qihse_cosine_similarity_avx2(a, b, 33), 1.0, 1e-12);
    near(qihse_cosine_similarity_avx512(a, b, 33), 1.0, 1e-12);
    for (size_t i = 0; i < 33; ++i) {
        a[i] = (float)((int)i - 17) * .125f;
        b[i] = (float)((int)(i % 7) - 3) * .5f;
    }
    for (size_t n = 1; n <= 33; ++n) {
        double reference = qihse_cosine_similarity_scalar(a, b, n);
        near(qihse_cosine_similarity_avx2(a, b, n), reference, 1e-12);
        near(qihse_cosine_similarity_avx512(a, b, n), reference, 1e-12);
    }
}

static void test_bounded_verification(void) {
    float a[] = {1, 2}, different[] = {1, 2.001f};
    near(qihse_superposition_fidelity_similarity(a, a, 2), 1.0, 1e-12);
    qihse_rff_kernel_t *kernel = qihse_rff_create(2, 8, .5, 42);
    assert(kernel);
    near(qihse_rff_similarity(a, a, 2, kernel), 1.0, 1e-12);
    assert(qihse_rff_similarity(a, a, 1, kernel) == 0.0 && errno == EINVAL);
    qihse_rff_kernel_t invalid = *kernel;
    invalid.omega = NULL;
    assert(qihse_rff_similarity(a, a, 2, &invalid) == 0.0 && errno == EINVAL);
    qihse_rff_destroy(kernel);
    qihse_verification_config_t config;
    qihse_verification_result_t result;
    qihse_verification_config_init(&config, QIHSE_VERIFY_EXACT);
    assert(qihse_verify_result_advanced_sized(NULL, a, a, 2, &config, &result) == 0);
    assert(result.is_valid && result.confidence == 1.0);
    qihse_verification_result_destroy(&result);
    assert(qihse_verify_result_advanced_sized(NULL, a, different, 2, &config, &result) < 0);
    assert(!result.is_valid);
    qihse_verification_result_destroy(&result);
    qihse_verification_config_init(&config, QIHSE_VERIFY_PRECISION);
    config.tolerance = .01;
    assert(qihse_verify_result_advanced_sized(NULL, a, different, 2, &config, &result) == 0);
    qihse_verification_result_destroy(&result);
    config.tolerance = .0001;
    assert(qihse_verify_result_advanced_sized(NULL, a, different, 2, &config, &result) < 0);
    qihse_verification_result_destroy(&result);
    assert(qihse_verify_result_advanced(NULL, a, a, &config, &result) < 0 && errno == ENOTSUP);
    qihse_verification_result_destroy(&result);
    assert(qihse_verify_result_advanced_sized(NULL, a, NULL, 2, &config, &result) < 0);
    qihse_verification_result_destroy(&result);
    const float *arrays[] = {a, a}; size_t sizes[] = {1, 2};
    qihse_verification_result_t batch[2];
    assert(qihse_verify_batch_sized(NULL, arrays, arrays, sizes, 2, &config, batch) == 0);
    for (size_t i = 0; i < 2; ++i) { assert(batch[i].is_valid); qihse_verification_result_destroy(&batch[i]); }
    near(qihse_grover_amplified_similarity(a, a, 2, 0.0), 1.0, 1e-12);
}

static void test_bounded_dimensions(void) {
    qihse_dimension_config_t config; qihse_dimension_config_init(&config);
    qihse_problem_characteristics_t p = {.input_size = 1000, .data_entropy = .8,
        .data_complexity = .5, .memory_budget = 1024 * 1024, .performance_target = 1000};
    size_t dims = qihse_calculate_optimal_dimensions(&p, &config);
    assert(dims && qihse_validate_dimensions(dims, &p, &config));
    assert(qihse_estimate_memory_usage(dims, &p) <= p.memory_budget);
    assert(qihse_calculate_dimensions_with_memory(&p, 1, &config) == 0 && errno == ENOMEM);
    p.data_complexity = 100;
    dims = qihse_calculate_optimal_dimensions(&p, &config);
    assert(dims && qihse_validate_dimensions(dims, &p, &config));
    dims = qihse_calculate_dimensions_for_accuracy(&p, 1.0, &config);
    assert(dims && qihse_validate_dimensions(dims, &p, &config));
    assert(qihse_calculate_dimensions_for_accuracy(&p, 1.0, NULL) == 0);
    assert(qihse_calculate_dimensions_with_memory(NULL, 1, NULL) == 0);
    assert(qihse_dimension_scaler_adapt(NULL, .5, 1.0) == 0);
    assert(qihse_estimate_memory_usage(SIZE_MAX, &p) == SIZE_MAX);
    p.data_entropy = NAN;
    assert(qihse_calculate_optimal_dimensions(&p, &config) == 0);
    double large[] = {1e200, -1e200, 2e200};
    assert(qihse_analyze_problem_characteristics(large, 3, &p) == 0);
    assert(isfinite(p.data_entropy) && p.data_entropy > 0.0 && isfinite(p.data_complexity));
}

int main(void) {
    test_public_config_and_amplification();
    test_fidelity_normalization_and_measurements();
    test_cosine_backends();
    test_bounded_verification();
    test_bounded_dimensions();
    puts("PASS: canonical math ABI, amplification, fidelity, sampling, sized verification, and dimension budgets");
    return 0;
}
