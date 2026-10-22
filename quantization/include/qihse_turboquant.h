/* Experimental W12.1 mathematical reference. Not a database/index API.
 * Pure caller-owned numeric arrays only: no storage, identity, or search route.
 * This header is not part of QIHSE's stable/public engine ABI. */
#ifndef QIHSE_TURBOQUANT_H
#define QIHSE_TURBOQUANT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_TQ_REFERENCE_VERSION 1u
#define QIHSE_TQ_CODE_HEADER_BYTES 64u
#define QIHSE_TQ_MAX_DIMENSIONS 1536u

typedef enum { QIHSE_TQ_MSE = 0, QIHSE_TQ_PRODUCT = 1 } qihse_tq_variant;
typedef enum {
    QIHSE_TQ_DOT = 0,
    QIHSE_TQ_COSINE = 1,
    QIHSE_TQ_L2_SQUARED = 2
} qihse_tq_metric;

typedef struct {
    uint32_t dimensions;       /* 2..1536; no implicit padding. */
    uint32_t scalar_bits;      /* 1..4; PRODUCT total bits = scalar_bits + 1. */
    qihse_tq_variant variant;
    uint64_t rotation_seed;
    uint64_t projection_seed;  /* Zero for MSE. PRODUCT has a separate RNG role. */
} qihse_tq_config;

typedef struct qihse_tq_profile qihse_tq_profile;
typedef struct qihse_tq_query qihse_tq_query;

/* All fallible functions return 0 or an errno value. Create outputs are NULL
 * on failure. Other outputs are unchanged on failure. Inputs/outputs must not
 * overlap. Objects are immutable and shareable; callers own their lifetimes.
 * Seed reproduction is limited to the same generator/libm/build profile.
 * Dense Haar-reference QR costs O(d^3); transforms cost O(d^2). */
int qihse_tq_profile_create(const qihse_tq_config *config, qihse_tq_profile **out);
void qihse_tq_profile_destroy(qihse_tq_profile *profile);

/* Reference/statistical-test helper: clone the EXACT rotation/table and select
 * the projection stream by seed (same seed means same stream). Statistical
 * trials require independently sampled seeds. PRODUCT profiles only. */
int qihse_tq_profile_reseed_projection(const qihse_tq_profile *source,
                                     uint64_t seed, qihse_tq_profile **out);
int qihse_tq_profile_copy_rotation(const qihse_tq_profile *profile,
                                  double *out, size_t count);
int qihse_tq_code_size(const qihse_tq_config *config, size_t *out);
size_t qihse_tq_profile_matrix_bytes(const qihse_tq_profile *profile);

/* Encoding uses finite IEEE binary32 inputs and binary64 intermediate math.
 * Exact output length is required, including the 64-byte reference envelope.
 * Packed indices/signs are LSB-first; all unused padding bits are zero.
 * The envelope's checksum/fingerprint are NOT authentication or encryption. */
int qihse_tq_encode(const qihse_tq_profile *profile, const float *vector,
                    size_t dimensions, uint8_t *code, size_t code_bytes);
int qihse_tq_decode(const qihse_tq_profile *profile, const uint8_t *code,
                    size_t code_bytes, double *out, size_t dimensions);
/* Coarse reconstruction only, also for PRODUCT codes; useful to inspect the
 * exact residual for conditional QJL expectation/variance tests. */
int qihse_tq_decode_mse(const qihse_tq_profile *profile, const uint8_t *code,
                        size_t code_bytes, double *out, size_t dimensions);

int qihse_tq_prepare_query(const qihse_tq_profile *profile, const float *vector,
                          size_t dimensions, qihse_tq_query **out);
void qihse_tq_query_destroy(qihse_tq_query *query);
/* O(d) direct-code score after query preparation. Cosine uses TRUE norms and
 * returns 0 if either is zero. L2 is raw estimated SQUARED distance using true
 * norms, NOT QIHSE's 1/(1+distance) similarity. No estimate is clamped: corrected
 * cosine can exceed [-1,1], and estimated L2 squared can be negative. */
int qihse_tq_score(const qihse_tq_profile *profile, const qihse_tq_query *query,
                   const uint8_t *code, size_t code_bytes,
                   qihse_tq_metric metric, double *out);

#ifdef __cplusplus
}
#endif
#endif
