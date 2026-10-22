#ifndef QIHSE_TURBOQUANT_TABLES_H
#define QIHSE_TURBOQUANT_TABLES_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental W12.1 scalar reference, not a persisted/production format. */
#define QIHSE_TQ_TABLES_VERSION 1u
#define QIHSE_TQ_TABLES_PROFILE "spherical-lloyd-max-f64-v1"
#define QIHSE_TQ_TABLES_MIN_DIMENSIONS 2u
#define QIHSE_TQ_TABLES_MAX_DIMENSIONS 1536u
#define QIHSE_TQ_TABLES_MIN_BITS 1u
#define QIHSE_TQ_TABLES_MAX_BITS 4u

/*
 * Construct 2^bits ordered, exactly sign-symmetric scalar centroids for the
 * dimension-dependent spherical marginal on [-1, 1]:
 *     f_d(t) proportional to (1 - t*t)^((d - 3)/2).
 * Lloyd-Max decision boundaries are neighboring-centroid midpoints. Values
 * remain in the original unit-sphere coordinate scale, NOT multiplied by
 * sqrt(dimensions). No Gaussian approximation or reconstruction rescaling is
 * used. The same input and floating-point implementation give the same output;
 * libm/compiler/platform-independent bit identity is not promised.
 *
 * dimensions: 2..1536; bits: 1..4; out_count must be at least 2^bits.
 * Return 0 on success; EINVAL for invalid arguments, ERANGE for a numerical
 * integration/finite-arithmetic failure, or EAGAIN for Lloyd nonconvergence.
 * These are returned errno values; errno itself is not the API. On failure,
 * out is unchanged. Extra output elements beyond 2^bits are never touched.
 * Construction is allocation-free and uses no global mutable state or RNG.
 */
int qihse_tq_build_centroids(size_t dimensions, unsigned bits,
                           double *out, size_t out_count);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TURBOQUANT_TABLES_H */
