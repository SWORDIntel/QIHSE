/* Independently implemented from TurboQuant Algorithms 1-2 (ICLR 2026).
 * Dense golden reference, NOT the paper's Appendix E Hadamard shortcut.
 * See docs/plans/qihse_w12_scalar_reference.md for numerical/security limits. */
#include "qihse_turboquant.h"
#include "qihse_turboquant_tables.h"
#include "qihse_turboquant_rng.h"

#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#if FLT_RADIX != 2 || FLT_MANT_DIG != 24 || DBL_MANT_DIG != 53 || DBL_MAX_EXP != 1024
#error "TurboQuant reference requires IEEE binary32 and binary64"
#endif
typedef char tq_float_size[(sizeof(float) == 4) ? 1 : -1];
typedef char tq_double_size[(sizeof(double) == 8) ? 1 : -1];

#define TQ_PI 3.14159265358979323846264338327950288
#define TQ_ROTATION_ROLE 0u
#define TQ_PROJECTION_ROLE 1u

struct qihse_tq_profile {
    qihse_tq_config config;
    size_t scalar_bytes, sign_bytes, code_bytes;
    uint64_t fingerprint;
    double *rotation, *projection;
    double centroids[16];
};
struct qihse_tq_query {
    uint64_t fingerprint;
    size_t dimensions;
    double norm;
    double *rotated, *projected;
};
typedef struct {
    uint32_t state[16], block[16];
    unsigned next_word;
    int cached;
    double spare;
} tq_rng;

/* Role is a separate nonce word, not an XOR salt in one additive RNG state.
 * Thus selected seed pairs cannot trivially shift/reuse the other role's
 * underlying stream. This remains pseudorandom sampling, not exact iid math.
 * The d<=1536 cap requires fewer than 300000 blocks per matrix, so the
 * 32-bit block counter cannot wrap. */
static void rng_init(tq_rng *rng, uint64_t seed, uint32_t role) {
    memset(rng, 0, sizeof(*rng));
    rng->state[0] = UINT32_C(0x61707865); rng->state[1] = UINT32_C(0x3320646e);
    rng->state[2] = UINT32_C(0x79622d32); rng->state[3] = UINT32_C(0x6b206574);
    rng->state[4] = (uint32_t)seed; rng->state[5] = (uint32_t)(seed >> 32);
    rng->state[13] = role; rng->state[14] = UINT32_C(0x54515231);
    rng->state[15] = QIHSE_TQ_REFERENCE_VERSION;
    rng->next_word = 16;
}
static uint32_t random_u32(tq_rng *rng) {
    if (rng->next_word == 16) {
        tq_chacha20_block(rng->state, rng->block);
        ++rng->state[12]; rng->next_word = 0;
    }
    return rng->block[rng->next_word++];
}
static uint64_t random_u64(tq_rng *rng) {
    uint64_t lo = random_u32(rng), hi = random_u32(rng);
    return lo | (hi << 32);
}
static double uniform_open(tq_rng *rng) {
    return ((double)(random_u64(rng) >> 12) + 0.5) * 0x1p-52;
}
static double gaussian(tq_rng *rng) {
    double radius, angle;
    if (rng->cached) { rng->cached = 0; return rng->spare; }
    radius = sqrt(-2.0 * log(uniform_open(rng)));
    angle = 2.0 * TQ_PI * uniform_open(rng);
    rng->spare = radius * sin(angle);
    rng->cached = 1;
    return radius * cos(angle);
}
static void put_u32(uint8_t *p, uint32_t v) {
    unsigned i; for (i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static void put_u64(uint8_t *p, uint64_t v) {
    unsigned i; for (i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get_u32(const uint8_t *p) {
    uint32_t v = 0; unsigned i;
    for (i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (8 * i);
    return v;
}
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0; unsigned i;
    for (i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static void put_double(uint8_t *p, double x) {
    uint64_t u; memcpy(&u, &x, sizeof(u)); put_u64(p, u);
}
static double get_double(const uint8_t *p) {
    uint64_t u = get_u64(p); double x; memcpy(&x, &u, sizeof(x)); return x;
}
static uint64_t hash_bytes(uint64_t h, const uint8_t *p, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) { h ^= p[i]; h *= UINT64_C(1099511628211); }
    return h;
}
static uint64_t fingerprint(const qihse_tq_profile *p) {
    uint8_t bytes[8]; size_t i, n = p->config.dimensions;
    uint64_t h = UINT64_C(14695981039346656037);
    put_u64(bytes, QIHSE_TQ_REFERENCE_VERSION); h = hash_bytes(h, bytes, 8);
    put_u64(bytes, QIHSE_TQ_TABLES_VERSION); h = hash_bytes(h, bytes, 8);
    put_u64(bytes, n); h = hash_bytes(h, bytes, 8);
    put_u64(bytes, p->config.scalar_bits); h = hash_bytes(h, bytes, 8);
    put_u64(bytes, p->config.variant); h = hash_bytes(h, bytes, 8);
    put_u64(bytes, p->config.rotation_seed); h = hash_bytes(h, bytes, 8);
    put_u64(bytes, p->config.projection_seed); h = hash_bytes(h, bytes, 8);
    for (i = 0; i < n*n; ++i) {
        put_double(bytes, p->rotation[i]); h = hash_bytes(h, bytes, 8);
    }
    if (p->projection) for (i = 0; i < n*n; ++i) {
        put_double(bytes, p->projection[i]); h = hash_bytes(h, bytes, 8);
    }
    for (i = 0; i < ((size_t)1 << p->config.scalar_bits); ++i) {
        put_double(bytes, p->centroids[i]); h = hash_bytes(h, bytes, 8);
    }
    return h;
}
/* Standard reflected CRC-32/ISO-HDLC polynomial, excluding checksum field. */
static uint32_t code_crc(const uint8_t *code, size_t bytes) {
    uint32_t crc = UINT32_MAX; size_t i; unsigned j;
    for (i = 0; i < bytes; ++i) {
        if (i >= 60 && i < 64) continue;
        crc ^= code[i];
        for (j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ ((0u - (crc & 1u)) & UINT32_C(0xedb88320));
    }
    return ~crc;
}
static int valid_config(const qihse_tq_config *c) {
    return c && c->dimensions >= 2 && c->dimensions <= QIHSE_TQ_MAX_DIMENSIONS
        && c->scalar_bits >= 1 && c->scalar_bits <= 4
        && (c->variant == QIHSE_TQ_MSE || c->variant == QIHSE_TQ_PRODUCT)
        && (c->variant != QIHSE_TQ_MSE || c->projection_seed == 0);
}
int qihse_tq_code_size(const qihse_tq_config *c, size_t *out) {
    size_t bytes;
    if (!out || !valid_config(c)) return EINVAL;
    /* Bounded dimensions and bits make both products/sums representable. */
    bytes = ((size_t)c->dimensions * c->scalar_bits + 7) / 8;
    if (c->variant == QIHSE_TQ_PRODUCT) bytes += (c->dimensions + 7u) / 8u;
    *out = QIHSE_TQ_CODE_HEADER_BYTES + bytes;
    return 0;
}
static int allocate_profile(const qihse_tq_config *c, qihse_tq_profile **out) {
    qihse_tq_profile *p; size_t n;
    if (!out) return EINVAL;
    *out = NULL;
    if (!valid_config(c)) return EINVAL;
    n = c->dimensions;
    if (n > SIZE_MAX / n || n*n > SIZE_MAX / sizeof(double)) return EOVERFLOW;
    p = (qihse_tq_profile *)calloc(1, sizeof(*p));
    if (!p) return ENOMEM;
    p->config = *c;
    p->scalar_bytes = (n*c->scalar_bits + 7) / 8;
    p->sign_bytes = c->variant == QIHSE_TQ_PRODUCT ? (n + 7) / 8 : 0;
    p->code_bytes = QIHSE_TQ_CODE_HEADER_BYTES + p->scalar_bytes + p->sign_bytes;
    p->rotation = (double *)calloc(n*n, sizeof(double));
    if (p->sign_bytes) p->projection = (double *)malloc(n*n*sizeof(double));
    if (!p->rotation || (p->sign_bytes && !p->projection)) {
        qihse_tq_profile_destroy(p); return ENOMEM;
    }
    *out = p;
    return 0;
}
void qihse_tq_profile_destroy(qihse_tq_profile *p) {
    if (p) { free(p->rotation); free(p->projection); free(p); }
}
static void fill_projection(qihse_tq_profile *p) {
    tq_rng rng;
    size_t i, n = p->config.dimensions;
    rng_init(&rng, p->config.projection_seed, TQ_PROJECTION_ROLE);
    if (p->projection) for (i = 0; i < n*n; ++i) p->projection[i] = gaussian(&rng);
}
/* Householder QR: A = Q R; Q <- Q diag(sign(Rjj)) makes R's diagonal
 * positive and Q Haar-distributed for an ideal iid Gaussian A. No padding,
 * Hadamard, signed-permutation approximation, or reconstructed normalization. */
static int fill_rotation(qihse_tq_profile *p) {
    size_t i, j, k, n = p->config.dimensions;
    double *a = NULL, *v = NULL, *diagonal = NULL;
    tq_rng rng;
    int rc = ENOMEM;
    rng_init(&rng, p->config.rotation_seed, TQ_ROTATION_ROLE);
    a = (double *)malloc(n*n*sizeof(double));
    v = (double *)malloc(n*sizeof(double));
    diagonal = (double *)malloc(n*sizeof(double));
    if (!a || !v || !diagonal) goto done;
    for (i = 0; i < n*n; ++i) a[i] = gaussian(&rng);
    for (i = 0; i < n; ++i) p->rotation[i*n+i] = 1.0;
    for (k = 0; k < n; ++k) {
        double norm = 0, alpha, vnorm = 0;
        for (i = k; i < n; ++i) norm = hypot(norm, a[i*n+k]);
        if (!(norm > 0) || !isfinite(norm)) { rc = ERANGE; goto done; }
        alpha = -copysign(norm, a[k*n+k]);
        for (i = k; i < n; ++i) {
            v[i] = a[i*n+k] - (i == k ? alpha : 0.0);
            vnorm = hypot(vnorm, v[i]);
        }
        if (!(vnorm > 0) || !isfinite(vnorm)) { rc = ERANGE; goto done; }
        for (i = k; i < n; ++i) v[i] /= vnorm;
        for (j = k; j < n; ++j) {
            double dot = 0;
            for (i = k; i < n; ++i) dot += v[i]*a[i*n+j];
            for (i = k; i < n; ++i) a[i*n+j] -= 2.0*v[i]*dot;
        }
        for (i = 0; i < n; ++i) {
            double dot = 0;
            for (j = k; j < n; ++j) dot += p->rotation[i*n+j]*v[j];
            for (j = k; j < n; ++j) p->rotation[i*n+j] -= 2.0*dot*v[j];
        }
        diagonal[k] = alpha;
    }
    for (j = 0; j < n; ++j) if (diagonal[j] < 0)
        for (i = 0; i < n; ++i) p->rotation[i*n+j] = -p->rotation[i*n+j];
    rc = 0;
done:
    free(a); free(v); free(diagonal); return rc;
}
int qihse_tq_profile_create(const qihse_tq_config *c, qihse_tq_profile **out) {
    qihse_tq_profile *p; int rc;
    if (!out) return EINVAL;
    *out = NULL;
    rc = allocate_profile(c, &p); if (rc) return rc;
    rc = qihse_tq_build_centroids(c->dimensions, c->scalar_bits, p->centroids,
                                 (size_t)1 << c->scalar_bits);
    if (!rc) rc = fill_rotation(p);
    if (rc) { qihse_tq_profile_destroy(p); return rc; }
    fill_projection(p); p->fingerprint = fingerprint(p); *out = p; return 0;
}
int qihse_tq_profile_reseed_projection(const qihse_tq_profile *source,
                                     uint64_t seed, qihse_tq_profile **out) {
    qihse_tq_profile *p; qihse_tq_config config; size_t n; int rc;
    if (!out) return EINVAL;
    *out = NULL;
    if (!source || source->config.variant != QIHSE_TQ_PRODUCT) return EINVAL;
    config = source->config; config.projection_seed = seed;
    rc = allocate_profile(&config, &p); if (rc) return rc;
    n = config.dimensions;
    memcpy(p->rotation, source->rotation, n*n*sizeof(double));
    memcpy(p->centroids, source->centroids, sizeof(p->centroids));
    fill_projection(p); p->fingerprint = fingerprint(p); *out = p; return 0;
}
int qihse_tq_profile_copy_rotation(const qihse_tq_profile *p, double *out,
                                  size_t count) {
    size_t n;
    if (!p || !out) return EINVAL;
    n = p->config.dimensions;
    if (count != n*n) return EINVAL;
    memcpy(out, p->rotation, count*sizeof(double)); return 0;
}
size_t qihse_tq_profile_matrix_bytes(const qihse_tq_profile *p) {
    size_t n;
    if (!p) return 0;
    n = p->config.dimensions;
    return n*n*sizeof(double)*(p->projection ? 2u : 1u);
}
static int vector_norm(const float *v, size_t n, double *out) {
    size_t i; double sum = 0;
    if (!v) return EINVAL;
    for (i = 0; i < n; ++i) {
        double x = v[i];
        if (!isfinite(x)) return EDOM;
        sum += x*x; /* Max: 1536*FLT_MAX^2, safely below DBL_MAX. */
    }
    *out = sqrt(sum); return 0;
}
static void transform(const double *matrix, const double *x, size_t n, double *y) {
    size_t i, j;
    for (i = 0; i < n; ++i) {
        double dot = 0;
        for (j = 0; j < n; ++j) dot += matrix[i*n+j]*x[j];
        y[i] = dot;
    }
}
static unsigned unpack_index(const uint8_t *bytes, size_t row, unsigned bits) {
    unsigned b, value = 0; size_t pos = row*bits;
    for (b = 0; b < bits; ++b)
        value |= ((bytes[(pos+b)/8] >> ((pos+b)%8)) & 1u) << b;
    return value;
}
static void pack_index(uint8_t *bytes, size_t row, unsigned bits, unsigned value) {
    unsigned b; size_t pos = row*bits;
    for (b = 0; b < bits; ++b)
        bytes[(pos+b)/8] |= (uint8_t)(((value >> b) & 1u) << ((pos+b)%8));
}
static void coarse_unit(const qihse_tq_profile *p, const uint8_t *scalar, double *out) {
    size_t i, j, n = p->config.dimensions;
    for (j = 0; j < n; ++j) {
        double sum = 0;
        for (i = 0; i < n; ++i)
            sum += p->rotation[i*n+j]*p->centroids[unpack_index(scalar, i, p->config.scalar_bits)];
        out[j] = sum;
    }
}
int qihse_tq_encode(const qihse_tq_profile *p, const float *vector,
                    size_t dimensions, uint8_t *code, size_t code_bytes) {
    size_t i, n, count; unsigned bits; double rho, gamma = 0;
    double *work = NULL, *u, *rotated, *residual, *projected;
    uint8_t *encoded = NULL, *scalar, *signs; int rc;
    if (!p || !code || dimensions != p->config.dimensions || code_bytes != p->code_bytes)
        return EINVAL;
    n = dimensions; bits = p->config.scalar_bits; count = (size_t)1 << bits;
    rc = vector_norm(vector, n, &rho); if (rc) return rc;
    encoded = (uint8_t *)calloc(code_bytes, 1);
    work = (double *)malloc(4*n*sizeof(double));
    if (!encoded || !work) { rc = ENOMEM; goto done; }
    u = work; rotated = u+n; residual = rotated+n; projected = residual+n;
    scalar = encoded+QIHSE_TQ_CODE_HEADER_BYTES; signs = scalar+p->scalar_bytes;
    if (rho != 0) {
        for (i = 0; i < n; ++i) u[i] = (double)vector[i]/rho;
        transform(p->rotation, u, n, rotated);
        for (i = 0; i < n; ++i) {
            unsigned index = 0, j; double error = fabs(rotated[i]-p->centroids[0]);
            for (j = 1; j < count; ++j) {
                double candidate = fabs(rotated[i]-p->centroids[j]);
                if (candidate < error) { error = candidate; index = j; }
            }
            pack_index(scalar, i, bits, index); /* Lower index wins an exact tie. */
        }
        if (p->projection) {
            coarse_unit(p, scalar, residual);
            for (i = 0; i < n; ++i) {
                residual[i] = u[i]-residual[i]; gamma += residual[i]*residual[i];
            }
            gamma = sqrt(gamma);
            if (gamma != 0) {
                transform(p->projection, residual, n, projected);
                for (i = 0; i < n; ++i)
                    if (projected[i] >= 0) signs[i/8] |= (uint8_t)(1u << (i%8));
            }
        }
    }
    memcpy(encoded, "QTQR", 4); encoded[4] = QIHSE_TQ_REFERENCE_VERSION;
    encoded[6] = (uint8_t)p->config.variant; encoded[7] = (uint8_t)bits;
    put_u32(encoded+8, p->config.dimensions); put_u32(encoded+12, QIHSE_TQ_TABLES_VERSION);
    put_u64(encoded+16, p->config.rotation_seed); put_u64(encoded+24, p->config.projection_seed);
    put_u64(encoded+32, p->fingerprint); put_double(encoded+40, rho); put_double(encoded+48, gamma);
    put_u32(encoded+56, (uint32_t)(p->scalar_bytes+p->sign_bytes));
    put_u32(encoded+60, code_crc(encoded, code_bytes));
    memcpy(code, encoded, code_bytes); rc = 0;
done:
    free(encoded); free(work); return rc;
}
static int zero_padding(const uint8_t *data, size_t bits) {
    unsigned used = (unsigned)(bits%8);
    return !used || (data[bits/8] >> used) == 0;
}
static int validate_code(const qihse_tq_profile *p, const uint8_t *code,
                         size_t bytes, double *rho, double *gamma) {
    const uint8_t *payload; size_t i, n; double bound, norm_bound;
    if (!p || !code || bytes != p->code_bytes) return EINVAL;
    n = p->config.dimensions; payload = code+QIHSE_TQ_CODE_HEADER_BYTES;
    if (memcmp(code, "QTQR", 4) || code[4] != QIHSE_TQ_REFERENCE_VERSION || code[5] != 0
        || code[6] != p->config.variant || code[7] != p->config.scalar_bits
        || get_u32(code+8) != n || get_u32(code+12) != QIHSE_TQ_TABLES_VERSION
        || get_u64(code+16) != p->config.rotation_seed
        || get_u64(code+24) != p->config.projection_seed
        || get_u64(code+32) != p->fingerprint
        || get_u32(code+56) != p->scalar_bytes+p->sign_bytes
        || get_u32(code+60) != code_crc(code, bytes)) return EBADMSG;
    *rho = get_double(code+40); *gamma = get_double(code+48);
    bound = 1.0+sqrt((double)n)*p->centroids[((size_t)1 << p->config.scalar_bits)-1];
    /* Positive FP64 summation and sqrt can round the encoded norm above the
     * exact sqrt(d)*FLT_MAX bound. Cover their O(d*epsilon) rounding error,
     * while still rejecting unrepresentable/arbitrary binary64 metadata. */
    norm_bound = sqrt((double)n)*FLT_MAX*(1.0+4.0*(double)n*DBL_EPSILON);
    if (!isfinite(*rho) || !isfinite(*gamma) || *rho < 0 || *gamma < 0
        || signbit(*rho) || signbit(*gamma) || *rho > norm_bound
        || *gamma > bound+1e-12 || (!p->projection && *gamma != 0)
        || (*rho == 0 && *gamma != 0)) return EBADMSG;
    if (!zero_padding(payload, n*p->config.scalar_bits)
        || (p->sign_bytes && !zero_padding(payload+p->scalar_bytes, n))) return EBADMSG;
    if (*rho == 0) for (i = 0; i < p->scalar_bytes+p->sign_bytes; ++i)
        if (payload[i] != 0) return EBADMSG;
    if (p->projection && *gamma == 0) for (i = 0; i < p->sign_bytes; ++i)
        if (payload[p->scalar_bytes+i] != 0) return EBADMSG;
    return 0;
}
static int decode(const qihse_tq_profile *p, const uint8_t *code, size_t bytes,
                   double *out, size_t dimensions, int corrected) {
    size_t i, j, n; double rho, gamma, *work; int rc;
    const uint8_t *scalar, *signs;
    if (!p || !out || dimensions != p->config.dimensions) return EINVAL;
    rc = validate_code(p, code, bytes, &rho, &gamma); if (rc) return rc;
    n = dimensions; scalar = code+QIHSE_TQ_CODE_HEADER_BYTES; signs = scalar+p->scalar_bytes;
    work = (double *)calloc(n, sizeof(double)); if (!work) return ENOMEM;
    if (rho != 0) {
        coarse_unit(p, scalar, work);
        for (j = 0; j < n; ++j) {
            if (corrected && p->projection && gamma != 0) {
                double sum = 0;
                for (i = 0; i < n; ++i)
                    sum += p->projection[i*n+j]*(((signs[i/8] >> (i%8)) & 1u) ? 1.0 : -1.0);
                work[j] += gamma*sqrt(TQ_PI/2.0)/(double)n*sum;
            }
            work[j] *= rho;
            if (!isfinite(work[j])) { free(work); return ERANGE; }
        }
    }
    memcpy(out, work, n*sizeof(double)); free(work); return 0;
}
int qihse_tq_decode(const qihse_tq_profile *p, const uint8_t *code, size_t bytes,
                    double *out, size_t dimensions) {
    return decode(p, code, bytes, out, dimensions, 1);
}
int qihse_tq_decode_mse(const qihse_tq_profile *p, const uint8_t *code, size_t bytes,
                        double *out, size_t dimensions) {
    return decode(p, code, bytes, out, dimensions, 0);
}
int qihse_tq_prepare_query(const qihse_tq_profile *p, const float *vector,
                          size_t dimensions, qihse_tq_query **out) {
    qihse_tq_query *q = NULL; double *work = NULL, norm; size_t i; int rc;
    if (!out) return EINVAL;
    *out = NULL;
    if (!p || dimensions != p->config.dimensions) return EINVAL;
    rc = vector_norm(vector, dimensions, &norm); if (rc) return rc;
    q = (qihse_tq_query *)calloc(1, sizeof(*q));
    work = (double *)malloc(dimensions*sizeof(double));
    if (!q || !work) { rc = ENOMEM; goto done; }
    q->rotated = (double *)malloc(dimensions*sizeof(double));
    if (p->projection) q->projected = (double *)malloc(dimensions*sizeof(double));
    if (!q->rotated || (p->projection && !q->projected)) { rc = ENOMEM; goto done; }
    q->norm = norm; q->dimensions = dimensions; q->fingerprint = p->fingerprint;
    for (i = 0; i < dimensions; ++i) work[i] = vector[i];
    transform(p->rotation, work, dimensions, q->rotated);
    if (p->projection) transform(p->projection, work, dimensions, q->projected);
    *out = q; q = NULL; rc = 0;
done:
    free(work); qihse_tq_query_destroy(q); return rc;
}
void qihse_tq_query_destroy(qihse_tq_query *q) {
    if (q) { free(q->rotated); free(q->projected); free(q); }
}
int qihse_tq_score(const qihse_tq_profile *p, const qihse_tq_query *q,
                   const uint8_t *code, size_t bytes, qihse_tq_metric metric, double *out) {
    size_t i, n; double rho, gamma, dot = 0, result; int rc;
    const uint8_t *scalar, *signs;
    if (!p || !q || !out || q->fingerprint != p->fingerprint
        || q->dimensions != p->config.dimensions
        || (metric != QIHSE_TQ_DOT && metric != QIHSE_TQ_COSINE && metric != QIHSE_TQ_L2_SQUARED))
        return EINVAL;
    rc = validate_code(p, code, bytes, &rho, &gamma); if (rc) return rc;
    n = p->config.dimensions; scalar = code+QIHSE_TQ_CODE_HEADER_BYTES; signs = scalar+p->scalar_bytes;
    if (rho != 0 && q->norm != 0) {
        for (i = 0; i < n; ++i)
            dot += q->rotated[i]*p->centroids[unpack_index(scalar, i, p->config.scalar_bits)];
        if (p->projection && gamma != 0) {
            double correction = 0;
            for (i = 0; i < n; ++i)
                correction += q->projected[i]*(((signs[i/8] >> (i%8)) & 1u) ? 1.0 : -1.0);
            dot += gamma*sqrt(TQ_PI/2.0)/(double)n*correction;
        }
        dot *= rho;
    }
    result = dot;
    if (metric == QIHSE_TQ_COSINE) result = rho == 0 || q->norm == 0 ? 0 : dot/(rho*q->norm);
    if (metric == QIHSE_TQ_L2_SQUARED) result = rho*rho+q->norm*q->norm-2.0*dot;
    if (!isfinite(result)) return ERANGE;
    *out = result; return 0;
}
