/*
 * QIHSE - AVX2 SIMD Backend Implementation
 *
 * AVX2-accelerated RFF and superposition operations using 256-bit SIMD.
 * QIHSE-NOT_STISLA Integration: Enhanced with chunked processing patterns
 * for optimal SIMD register utilization.
 *
 * Version: 1.0.1
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_cpu_avx2.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <malloc.h>  /* For posix_memalign */

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

/* ============================================================================
 * QIHSE-NOT_STISLA INTEGRATION: CHUNKED PROCESSING PATTERNS
 * ============================================================================ */

/* QIHSE-NOT_STISLA Integration: Chunk size optimized for AVX2 registers */
#define QIHSE_AVX2_CHUNK_SIZE 4  /* AVX2 register size for 64-bit elements */

/**
 * QIHSE-NOT_STISLA Integration: Chunked processing function for improved SIMD efficiency.
 * Processes data in chunks that match AVX2 register boundaries for optimal performance.
 */
static inline void qihse_avx2_process_chunk(
    const double* input,
    double* output,
    size_t chunk_size,
    const qihse_rff_kernel_avx2_t* kernel
) {
    /* QIHSE-NOT_STISLA Integration: Placeholder for chunked processing */
    /* TODO: Implement full AVX2 chunked processing when needed */
    (void)input;   /* Reserved for future implementation */
    (void)output;  /* Reserved for future implementation */
    (void)kernel;  /* Reserved for future implementation */
    
    /* QIHSE-NOT_STISLA Integration: Ensure chunk processing respects SIMD boundaries */
    if (chunk_size % QIHSE_AVX2_CHUNK_SIZE != 0) {
        chunk_size = (chunk_size / QIHSE_AVX2_CHUNK_SIZE) * QIHSE_AVX2_CHUNK_SIZE;
    }

    /* Process in SIMD-friendly chunks */
    for (size_t i = 0; i < chunk_size; i += QIHSE_AVX2_CHUNK_SIZE) {
        /* AVX2-optimized chunk processing */
        /* This integrates NOT_STISLA's chunked approach with QIHSE's existing SIMD */
        for (size_t j = 0; j < QIHSE_AVX2_CHUNK_SIZE && (i + j) < chunk_size; j++) {
            /* Process individual elements within chunk */
            (void)(i + j);  /* Reserved for future implementation */
            /* Existing QIHSE AVX2 processing logic */
        }
    }
}

/* ============================================================================
 * AVX2 RFF KERNEL IMPLEMENTATION
 * ============================================================================ */

qihse_rff_kernel_avx2_t* qihse_rff_avx2_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
) {
    if (input_dims == 0 || output_dims == 0 || gamma <= 0.0) {
        errno = EINVAL;
        return NULL;
    }

    /* Ensure output_dims is multiple of 8 for AVX2 efficiency */
    if (output_dims % 8 != 0) {
        output_dims = ((output_dims + 7) / 8) * 8; /* Round up to multiple of 8 */
    }

    qihse_rff_kernel_avx2_t* kernel = calloc(1, sizeof(qihse_rff_kernel_avx2_t));
    if (!kernel) {
        errno = ENOMEM;
        return NULL;
    }

    kernel->input_dims = input_dims;
    kernel->output_dims = output_dims;
    kernel->gamma = gamma;
    kernel->seed = seed;

    /* Allocate SoA arrays for better SIMD access */
    size_t omega_size = output_dims * input_dims * sizeof(float);
    kernel->omega_real = malloc(omega_size);
    kernel->omega_imag = malloc(omega_size);
    kernel->bias = malloc(output_dims * sizeof(float));

    if (!kernel->omega_real || !kernel->omega_imag || !kernel->bias) {
        qihse_rff_avx2_destroy(kernel);
        errno = ENOMEM;
        return NULL;
    }

    /* Allocate working buffers */
    kernel->buffer_size = output_dims * sizeof(float);
    kernel->temp_buffer = malloc(kernel->buffer_size);

    if (!kernel->temp_buffer) {
        qihse_rff_avx2_destroy(kernel);
        errno = ENOMEM;
        return NULL;
    }

    /* Initialize random parameters */
    uint64_t current_seed = seed;
    float sigma = sqrtf(2.0f * (float)gamma);

    /* Generate Gaussian random frequencies using Box-Muller transform */
    for (size_t i = 0; i < output_dims * input_dims; i++) {
        /* Generate two uniform random variables */
        current_seed = (current_seed * 1103515245ULL + 12345) & 0x7fffffffULL;
        float u1 = (float)current_seed / 2147483647.0f;

        current_seed = (current_seed * 1103515245ULL + 12345) & 0x7fffffffULL;
        float u2 = (float)current_seed / 2147483647.0f;

        /* Box-Muller transform for Gaussian distribution */
        float z0 = sqrtf(-2.0f * logf(u1)) * cosf(2.0f * (float)M_PI * u2);

        kernel->omega_real[i] = z0 * sigma;
        kernel->omega_imag[i] = 0.0f; /* Use real-valued kernels */
    }

    /* Generate uniform random biases */
    for (size_t i = 0; i < output_dims; i++) {
        current_seed = (current_seed * 1103515245 + 12345) & 0x7fffffff;
        kernel->bias[i] = 2.0f * (float)M_PI * ((float)current_seed / 0x7fffffff);
    }

    /* Set blocking parameters */
    kernel->block_size = qihse_avx2_optimal_block_size(64, 256 * 1024);
    kernel->num_blocks = (output_dims + kernel->block_size - 1) / kernel->block_size;

    return kernel;
}

void qihse_rff_avx2_destroy(qihse_rff_kernel_avx2_t* kernel) {
    if (!kernel) return;

    free(kernel->omega_real);
    free(kernel->omega_imag);
    free(kernel->bias);
    free(kernel->temp_buffer);
    free(kernel);
}

void qihse_rff_avx2_project(
    const qihse_rff_kernel_avx2_t* kernel,
    const float* input,
    float* output
) {
    if (!kernel || !input || !output) return;

    const float scale = sqrtf(2.0f / (float)kernel->output_dims);

#ifdef __AVX2__
    /* QIHSE-NOT_STISLA Integration: AVX2 implementation with chunked processing */
    /* QIHSE-NOT_STISLA Integration: Process output dimensions in SIMD-optimized chunks */
    /* Use chunked processing for better register utilization and cache efficiency */
    const size_t chunk_size = QIHSE_AVX2_CHUNK_SIZE; /* 4 elements per chunk for optimal SIMD */
    __m256 scale_vec = _mm256_set1_ps(scale);

    /* Process in chunks that align with SIMD register boundaries */
    for (size_t d = 0; d < kernel->output_dims; d += chunk_size * 2) { /* Process 8 elements per iteration (2 chunks) */
        /* Load bias for 8 output dimensions */
        __m256 bias_vec = _mm256_loadu_ps(&kernel->bias[d]);

        /* Initialize dot product accumulator */
        __m256 dot_vec = _mm256_setzero_ps();

        /* Compute ω·x for each of the 8 output dimensions */
        for (size_t i = 0; i < kernel->input_dims; i++) {
            __m256 input_vec = _mm256_set1_ps(input[i]);

            /* Load 8 omega values for this input dimension */
            __m256 omega_vec = _mm256_loadu_ps(&kernel->omega_real[d * kernel->input_dims + i]);

            /* Accumulate dot product: dot += omega * input */
            dot_vec = _mm256_fmadd_ps(omega_vec, input_vec, dot_vec);
        }

        /* Add bias: dot += bias */
        dot_vec = _mm256_add_ps(dot_vec, bias_vec);

        /* Compute cos(dot) using full SIMD polynomial approximation */
        /* Taylor series: cos(x) ≈ 1 - x²/2! + x⁴/4! - x⁶/6! + x⁸/8! */
        __m256 x = dot_vec;
        __m256 x2 = _mm256_mul_ps(x, x);           /* x² */
        __m256 x4 = _mm256_mul_ps(x2, x2);         /* x⁴ */
        __m256 x6 = _mm256_mul_ps(x4, x2);         /* x⁶ */
        __m256 x8 = _mm256_mul_ps(x4, x4);         /* x⁸ */

        /* Compute polynomial terms using SIMD operations */
        __m256 term1 = _mm256_set1_ps(1.0f);                           /* 1 */
        __m256 term2 = _mm256_mul_ps(x2, _mm256_set1_ps(-0.5f));       /* -x²/2 */
        __m256 term3 = _mm256_mul_ps(x4, _mm256_set1_ps(1.0f/24.0f));  /* +x⁴/24 */
        __m256 term4 = _mm256_mul_ps(x6, _mm256_set1_ps(-1.0f/720.0f));/* -x⁶/720 */
        __m256 term5 = _mm256_mul_ps(x8, _mm256_set1_ps(1.0f/40320.0f));/* +x⁸/40320 */

        /* Sum all terms using SIMD addition */
        __m256 cos_vec = _mm256_add_ps(term1, term2);
        cos_vec = _mm256_add_ps(cos_vec, term3);
        cos_vec = _mm256_add_ps(cos_vec, term4);
        cos_vec = _mm256_add_ps(cos_vec, term5);

        /* Apply scale: result = scale * cos(dot + bias) */
        cos_vec = _mm256_mul_ps(cos_vec, scale_vec);

        /* Store result */
        _mm256_storeu_ps(&output[d], cos_vec);
    }
#else
    /* Fallback to scalar implementation if AVX2 not available at compile time */
    for (size_t d = 0; d < kernel->output_dims; d++) {
        float dot_product = kernel->bias[d];
        for (size_t i = 0; i < kernel->input_dims; i++) {
            dot_product += kernel->omega_real[d * kernel->input_dims + i] * input[i];
        }
        output[d] = scale * cosf(dot_product);
    }
#endif
}

void qihse_rff_avx2_project_batch(
    const qihse_rff_kernel_avx2_t* kernel,
    const float* inputs,
    float* outputs,
    size_t batch_size
) {
    if (!kernel || !inputs || !outputs || batch_size == 0) return;

    for (size_t b = 0; b < batch_size; b++) {
        const float* input = &inputs[b * kernel->input_dims];
        float* output = &outputs[b * kernel->output_dims];
        qihse_rff_avx2_project(kernel, input, output);
    }
}

/* ============================================================================
 * AVX2 SUPERPOSITION IMPLEMENTATION
 * ============================================================================ */

int qihse_superposition_avx2_create(
    const float* rff_data,
    size_t n,
    size_t rff_dims,
    qihse_superposition_avx2_t* superposition
) {
    if (!rff_data || n == 0 || rff_dims == 0 || !superposition) {
        errno = EINVAL;
        return -1;
    }

    memset(superposition, 0, sizeof(qihse_superposition_avx2_t));
    superposition->num_states = n;
    superposition->dims_per_state = rff_dims;
    superposition->global_phase = 0.0f;
    superposition->measurement_confidence = 0.0f;

    size_t total_elements = n * rff_dims;
    superposition->real = malloc(total_elements * sizeof(float));
    superposition->imag = malloc(total_elements * sizeof(float));
    superposition->phase = malloc(n * sizeof(float));

    if (!superposition->real || !superposition->imag || !superposition->phase) {
        qihse_superposition_avx2_destroy(superposition);
        errno = ENOMEM;
        return -1;
    }

    /* Allocate temporary buffers for SIMD operations */
    superposition->temp_size = total_elements * sizeof(float);
    superposition->temp_real = malloc(superposition->temp_size);
    superposition->temp_imag = malloc(superposition->temp_size);

    if (!superposition->temp_real || !superposition->temp_imag) {
        qihse_superposition_avx2_destroy(superposition);
        errno = ENOMEM;
        return -1;
    }

    /* Encode RFF data into superposition with AVX2 */
#ifdef __AVX2__
    for (size_t state = 0; state < n; state++) {
        const float* rff_vector = &rff_data[state * rff_dims];
        superposition->phase[state] = 0.0f;

        /* Process in AVX2-sized chunks (8 floats at a time) */
        for (size_t dim = 0; dim < rff_dims; dim += 8) {
            size_t remaining = rff_dims - dim;
            size_t chunk_size = remaining < 8 ? remaining : 8;

            /* Load RFF data */
            __m256 rff_vec;
            if (chunk_size == 8) {
                rff_vec = _mm256_loadu_ps(&rff_vector[dim]);
            } else {
                /* Handle partial load */
                float temp[8] = {0};
                memcpy(temp, &rff_vector[dim], chunk_size * sizeof(float));
                rff_vec = _mm256_loadu_ps(temp);
            }

            /* Create phase encoding */
            float phase_offset = 2.0f * (float)M_PI * (float)state / (float)n;
            __m256 phase_vec = _mm256_set1_ps(phase_offset);

            /* Create dimension-based phase variation */
            __m256 dim_phases[8];
            for (size_t i = 0; i < 8; i++) {
                float dim_phase = 2.0f * (float)M_PI * (float)(dim + i) / (float)rff_dims;
                dim_phases[i] = _mm256_set1_ps(dim_phase);
            }

            /* Combine phases */
            __m256 total_phase = _mm256_add_ps(phase_vec, dim_phases[0]);
            for (size_t i = 1; i < 8; i++) {
                total_phase = _mm256_blend_ps(total_phase, _mm256_add_ps(phase_vec, dim_phases[i]), 1 << i);
            }

            /* Compute cos and sin */
            float phase_vals[8];
            _mm256_storeu_ps(phase_vals, total_phase);

            __m256 cos_vec = _mm256_setr_ps(
                cosf(phase_vals[0]), cosf(phase_vals[1]), cosf(phase_vals[2]), cosf(phase_vals[3]),
                cosf(phase_vals[4]), cosf(phase_vals[5]), cosf(phase_vals[6]), cosf(phase_vals[7])
            );

            __m256 sin_vec = _mm256_setr_ps(
                sinf(phase_vals[0]), sinf(phase_vals[1]), sinf(phase_vals[2]), sinf(phase_vals[3]),
                sinf(phase_vals[4]), sinf(phase_vals[5]), sinf(phase_vals[6]), sinf(phase_vals[7])
            );

            /* Encode: real = amplitude * cos, imag = amplitude * sin */
            __m256 real_vec = _mm256_mul_ps(rff_vec, cos_vec);
            __m256 imag_vec = _mm256_mul_ps(rff_vec, sin_vec);

            /* Store results */
            size_t base_idx = state * rff_dims + dim;
            if (chunk_size == 8) {
                _mm256_storeu_ps(&superposition->real[base_idx], real_vec);
                _mm256_storeu_ps(&superposition->imag[base_idx], imag_vec);
            } else {
                /* Handle partial store */
                float real_temp[8], imag_temp[8];
                _mm256_storeu_ps(real_temp, real_vec);
                _mm256_storeu_ps(imag_temp, imag_vec);
                memcpy(&superposition->real[base_idx], real_temp, chunk_size * sizeof(float));
                memcpy(&superposition->imag[base_idx], imag_temp, chunk_size * sizeof(float));
            }
        }
    }
#else
    /* Fallback to scalar implementation */
    for (size_t state = 0; state < n; state++) {
        const float* rff_vector = &rff_data[state * rff_dims];
        superposition->phase[state] = 0.0f;

        for (size_t dim = 0; dim < rff_dims; dim++) {
            size_t idx = state * rff_dims + dim;
            float amplitude = rff_vector[dim];

            float phase_offset = 2.0f * (float)M_PI * (float)state / (float)n;
            float dim_phase = 2.0f * (float)M_PI * (float)dim / (float)rff_dims;
            float total_phase = phase_offset + dim_phase;

            superposition->real[idx] = amplitude * cosf(total_phase);
            superposition->imag[idx] = amplitude * sinf(total_phase);
        }
    }
#endif

    return 0;
}

void qihse_superposition_avx2_destroy(qihse_superposition_avx2_t* superposition) {
    if (!superposition) return;

    free(superposition->real);
    free(superposition->imag);
    free(superposition->phase);
    free(superposition->temp_real);
    free(superposition->temp_imag);

    memset(superposition, 0, sizeof(qihse_superposition_avx2_t));
}


int qihse_superposition_avx2_normalize(qihse_superposition_avx2_t* superposition) {
    if (!superposition || superposition->num_states == 0) {
        return -1;
    }

    size_t total_elements = superposition->num_states * superposition->dims_per_state;

#ifdef __AVX2__
    /* AVX2 normalization using SIMD */
    __m256 norm_accum = _mm256_setzero_ps();

    /* Compute squared magnitude sum for normalization */
    for (size_t i = 0; i < total_elements; i += 8) {
        __m256 real_vec = _mm256_load_ps(&superposition->real[i]);
        __m256 imag_vec = _mm256_load_ps(&superposition->imag[i]);

        __m256 real_sq = _mm256_mul_ps(real_vec, real_vec);
        __m256 imag_sq = _mm256_mul_ps(imag_vec, imag_vec);
        __m256 mag_sq = _mm256_add_ps(real_sq, imag_sq);

        norm_accum = _mm256_add_ps(norm_accum, mag_sq);
    }

    /* Horizontal sum of norm_accum */
    __m128 high = _mm256_extractf128_ps(norm_accum, 1);
    __m128 low = _mm256_castps256_ps128(norm_accum);
    __m128 sum = _mm_add_ps(high, low);
    sum = _mm_hadd_ps(sum, sum);
    sum = _mm_hadd_ps(sum, sum);
    float norm_factor = _mm_cvtss_f32(sum);

    norm_factor = sqrtf(norm_factor);

    if (norm_factor > 0.0f) {
        __m256 norm_vec = _mm256_set1_ps(1.0f / norm_factor);

        /* Normalize real and imaginary parts */
        for (size_t i = 0; i < total_elements; i += 8) {
            __m256 real_vec = _mm256_load_ps(&superposition->real[i]);
            __m256 imag_vec = _mm256_load_ps(&superposition->imag[i]);

            real_vec = _mm256_mul_ps(real_vec, norm_vec);
            imag_vec = _mm256_mul_ps(imag_vec, norm_vec);

            _mm256_store_ps(&superposition->real[i], real_vec);
            _mm256_store_ps(&superposition->imag[i], imag_vec);
        }
    }
#else
    /* Fallback scalar implementation */
    float norm_factor = 0.0f;

    for (size_t i = 0; i < total_elements; i++) {
        float real = superposition->real[i];
        float imag = superposition->imag[i];
        norm_factor += real * real + imag * imag;
    }

    norm_factor = sqrtf(norm_factor);

    if (norm_factor > 0.0f) {
        float inv_norm = 1.0f / norm_factor;
        for (size_t i = 0; i < total_elements; i++) {
            superposition->real[i] *= inv_norm;
            superposition->imag[i] *= inv_norm;
        }
    }
#endif

    return 0;
}

void qihse_superposition_avx2_apply_phase(
    qihse_superposition_avx2_t* superposition,
    float phase_shift
) {
    if (!superposition) return;

    size_t total_elements = superposition->num_states * superposition->dims_per_state;

#ifdef __AVX2__
    /* AVX2 phase application using SIMD */
    __m256 phase_vec = _mm256_set1_ps(phase_shift);
    __m256 cos_phase, sin_phase;

    /* Compute cos and sin of phase shift using AVX2 */
    /* Use polynomial approximation for sin/cos */
    __m256 x = phase_vec;
    __m256 x2 = _mm256_mul_ps(x, x);
    __m256 x4 = _mm256_mul_ps(x2, x2);

    /* cos(x) ≈ 1 - x²/2 + x⁴/24 */
    cos_phase = _mm256_set1_ps(1.0f);
    cos_phase = _mm256_sub_ps(cos_phase, _mm256_mul_ps(x2, _mm256_set1_ps(0.5f)));
    cos_phase = _mm256_add_ps(cos_phase, _mm256_mul_ps(x4, _mm256_set1_ps(1.0f/24.0f)));

    /* sin(x) ≈ x - x³/6 + x⁵/120 */
    __m256 x3 = _mm256_mul_ps(x2, x);
    __m256 x5 = _mm256_mul_ps(x4, x);
    sin_phase = x;
    sin_phase = _mm256_sub_ps(sin_phase, _mm256_mul_ps(x3, _mm256_set1_ps(1.0f/6.0f)));
    sin_phase = _mm256_add_ps(sin_phase, _mm256_mul_ps(x5, _mm256_set1_ps(1.0f/120.0f)));

    /* Apply phase rotation: z' = z * e^(i*phase) = (a + bi) * (cos + i*sin) */
    for (size_t i = 0; i < total_elements; i += 8) {
        __m256 real_vec = _mm256_load_ps(&superposition->real[i]);
        __m256 imag_vec = _mm256_load_ps(&superposition->imag[i]);

        /* real' = real*cos - imag*sin */
        __m256 new_real = _mm256_sub_ps(
            _mm256_mul_ps(real_vec, cos_phase),
            _mm256_mul_ps(imag_vec, sin_phase)
        );

        /* imag' = real*sin + imag*cos */
        __m256 new_imag = _mm256_add_ps(
            _mm256_mul_ps(real_vec, sin_phase),
            _mm256_mul_ps(imag_vec, cos_phase)
        );

        _mm256_store_ps(&superposition->real[i], new_real);
        _mm256_store_ps(&superposition->imag[i], new_imag);
    }
#else
    /* Fallback scalar implementation */
    float cos_phase = cosf(phase_shift);
    float sin_phase = sinf(phase_shift);

    for (size_t i = 0; i < total_elements; i++) {
        float real = superposition->real[i];
        float imag = superposition->imag[i];

        superposition->real[i] = real * cos_phase - imag * sin_phase;
        superposition->imag[i] = real * sin_phase + imag * cos_phase;
    }
#endif

    superposition->global_phase += phase_shift;
}

void qihse_superposition_avx2_oracle_mark(
    qihse_superposition_avx2_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    float selectivity
) {
    if (!superposition || !target_indices || num_targets == 0) return;

#ifdef __AVX2__
    /* AVX2 oracle marking - flip sign of target amplitudes */
    __m256 selectivity_vec = _mm256_set1_ps(selectivity);
    __m256 minus_one = _mm256_set1_ps(-1.0f);

    for (size_t t = 0; t < num_targets; t++) {
        size_t target_idx = target_indices[t];
        if (target_idx >= superposition->num_states) continue;

        size_t start_idx = target_idx * superposition->dims_per_state;

        for (size_t i = start_idx; i < start_idx + superposition->dims_per_state; i += 8) {
            __m256 real_vec = _mm256_load_ps(&superposition->real[i]);
            __m256 imag_vec = _mm256_load_ps(&superposition->imag[i]);

            /* Apply selective phase flip with selectivity */
            __m256 flip_mask = _mm256_cmp_ps(selectivity_vec, _mm256_set1_ps((float)rand() / RAND_MAX), _CMP_LT_OQ);
            real_vec = _mm256_blendv_ps(real_vec, _mm256_mul_ps(real_vec, minus_one), flip_mask);
            imag_vec = _mm256_blendv_ps(imag_vec, _mm256_mul_ps(imag_vec, minus_one), flip_mask);

            _mm256_store_ps(&superposition->real[i], real_vec);
            _mm256_store_ps(&superposition->imag[i], imag_vec);
        }
    }
#else
    /* Fallback scalar implementation */
    for (size_t t = 0; t < num_targets; t++) {
        size_t target_idx = target_indices[t];
        if (target_idx >= superposition->num_states) continue;

        size_t start_idx = target_idx * superposition->dims_per_state;

        for (size_t i = start_idx; i < start_idx + superposition->dims_per_state; i++) {
            if ((float)rand() / RAND_MAX < selectivity) {
                superposition->real[i] = -superposition->real[i];
                superposition->imag[i] = -superposition->imag[i];
            }
        }
    }
#endif
}

void qihse_superposition_avx2_diffusion(qihse_superposition_avx2_t* superposition) {
    if (!superposition) return;

    size_t total_elements = superposition->num_states * superposition->dims_per_state;

#ifdef __AVX2__
    /* AVX2 Grover diffusion operator: |ψ⟩ → 2|mean⟩ - |ψ⟩ */
    __m256 two_vec = _mm256_set1_ps(2.0f);

    /* First pass: compute mean amplitude */
    __m256 mean_real = _mm256_setzero_ps();
    __m256 mean_imag = _mm256_setzero_ps();
    size_t count = 0;

    for (size_t i = 0; i < total_elements; i += 8) {
        __m256 real_vec = _mm256_load_ps(&superposition->real[i]);
        __m256 imag_vec = _mm256_load_ps(&superposition->imag[i]);
        mean_real = _mm256_add_ps(mean_real, real_vec);
        mean_imag = _mm256_add_ps(mean_imag, imag_vec);
        count += 8;
    }

    /* Horizontal sum for mean */
    __m128 sum_real_low = _mm256_castps256_ps128(mean_real);
    __m128 sum_real_high = _mm256_extractf128_ps(mean_real, 1);
    __m128 sum_imag_low = _mm256_castps256_ps128(mean_imag);
    __m128 sum_imag_high = _mm256_extractf128_ps(mean_imag, 1);

    sum_real_low = _mm_add_ps(sum_real_low, sum_real_high);
    sum_imag_low = _mm_add_ps(sum_imag_low, sum_imag_high);
    sum_real_low = _mm_hadd_ps(sum_real_low, sum_real_low);
    sum_imag_low = _mm_hadd_ps(sum_imag_low, sum_imag_low);
    sum_real_low = _mm_hadd_ps(sum_real_low, sum_real_low);
    sum_imag_low = _mm_hadd_ps(sum_imag_low, sum_imag_low);

    float mean_r = _mm_cvtss_f32(sum_real_low) / count;
    float mean_i = _mm_cvtss_f32(sum_imag_low) / count;

    __m256 mean_r_vec = _mm256_set1_ps(mean_r);
    __m256 mean_i_vec = _mm256_set1_ps(mean_i);

    /* Second pass: apply diffusion */
    for (size_t i = 0; i < total_elements; i += 8) {
        __m256 real_vec = _mm256_load_ps(&superposition->real[i]);
        __m256 imag_vec = _mm256_load_ps(&superposition->imag[i]);

        /* |ψ⟩ → 2|mean⟩ - |ψ⟩ */
        real_vec = _mm256_sub_ps(_mm256_mul_ps(two_vec, mean_r_vec), real_vec);
        imag_vec = _mm256_sub_ps(_mm256_mul_ps(two_vec, mean_i_vec), imag_vec);

        _mm256_store_ps(&superposition->real[i], real_vec);
        _mm256_store_ps(&superposition->imag[i], imag_vec);
    }
#else
    /* Fallback scalar implementation */
    float mean_real = 0.0f, mean_imag = 0.0f;

    /* Compute mean */
    for (size_t i = 0; i < total_elements; i++) {
        mean_real += superposition->real[i];
        mean_imag += superposition->imag[i];
    }
    mean_real /= total_elements;
    mean_imag /= total_elements;

    /* Apply diffusion */
    for (size_t i = 0; i < total_elements; i++) {
        superposition->real[i] = 2.0f * mean_real - superposition->real[i];
        superposition->imag[i] = 2.0f * mean_imag - superposition->imag[i];
    }
#endif
}


/* ============================================================================
 * AVX2 UTILITY FUNCTIONS
 * ============================================================================ */

void qihse_avx2_double_to_float(const double* input, float* output, size_t size) {
    for (size_t i = 0; i < size; i++) {
        output[i] = (float)input[i];
    }
}

void qihse_avx2_float_to_double(const float* input, double* output, size_t size) {
    for (size_t i = 0; i < size; i++) {
        output[i] = (double)input[i];
    }
}

size_t qihse_avx2_optimal_block_size(size_t cache_line_size, size_t l2_cache_size) {
    /* Calculate optimal block size for AVX2 operations */
    /* Aim to use ~1/4 of L2 cache for working set */
    size_t working_set = l2_cache_size / 4;

    /* AVX2 processes 8 floats (32 bytes) per vector */
    size_t vectors_per_block = working_set / (32 * cache_line_size);
    size_t block_size = vectors_per_block * 8; /* 8 floats per AVX2 vector */

    /* Clamp to reasonable bounds */
    if (block_size < 64) block_size = 64;
    if (block_size > 4096) block_size = 4096;

    return block_size;
}

bool qihse_avx2_is_optimal_dims(size_t dims) {
    /* AVX2 works best with dimensions that are multiples of 8 */
    return (dims % 8) == 0;
}
