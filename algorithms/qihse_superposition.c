/* Canonical complex-state operations shared by the runtime and algorithm API. */
#include "qihse_superposition.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static int state_count(const qihse_superposition_t *s, size_t *count) {
    if (!s || !s->real || !s->imag || !s->num_states || !s->dims_per_state ||
        s->num_states > SIZE_MAX / s->dims_per_state ||
        s->num_states * s->dims_per_state > SIZE_MAX / sizeof(double)) {
        errno = EINVAL;
        return -1;
    }
    *count = s->num_states * s->dims_per_state;
    return 0;
}

/* Scaling before squaring avoids overflow and underflow for finite amplitudes. */
static int state_norm(const qihse_superposition_t *s, double *scale,
                      long double *squares) {
    size_t count;
    if (state_count(s, &count)) return -1;
    *scale = 0.0;
    for (size_t i = 0; i < count; ++i) {
        if (!isfinite(s->real[i]) || !isfinite(s->imag[i])) {
            errno = EDOM;
            return -1;
        }
        *scale = fmax(*scale, fmax(fabs(s->real[i]), fabs(s->imag[i])));
    }
    if (*scale == 0.0) { errno = EDOM; return -1; }
    *squares = 0.0L;
    for (size_t i = 0; i < count; ++i) {
        long double re = (long double)s->real[i] / *scale;
        long double im = (long double)s->imag[i] / *scale;
        *squares += re * re + im * im;
    }
    return 0;
}

static int allocate_state(qihse_superposition_t *s, size_t n, size_t dims) {
    if (!s) { errno = EINVAL; return -1; }
    memset(s, 0, sizeof(*s));
    if (!n || !dims) { errno = EINVAL; return -1; }
    if (n > SIZE_MAX / dims || n * dims > SIZE_MAX / sizeof(double)) {
        errno = EOVERFLOW;
        return -1;
    }
    s->real = malloc(n * dims * sizeof(double));
    s->imag = malloc(n * dims * sizeof(double));
    s->phase = calloc(n, sizeof(double));
    if (!s->real || !s->imag || !s->phase) {
        qihse_destroy_superposition(s);
        errno = ENOMEM;
        return -1;
    }
    s->num_states = n;
    s->dims_per_state = dims;
    return 0;
}

int qihse_create_superposition(const double *data, size_t n, size_t dims,
                               qihse_superposition_t *s) {
    if (!data) { if (s) memset(s, 0, sizeof(*s)); errno = EINVAL; return -1; }
    if (allocate_state(s, n, dims)) return -1;
    for (size_t state = 0; state < n; ++state) {
        double row_phase = 2.0 * M_PI * ((double)state / (double)n);
        s->phase[state] = row_phase;
        for (size_t dim = 0; dim < dims; ++dim) {
            size_t i = state * dims + dim;
            if (!isfinite(data[i])) {
                qihse_destroy_superposition(s); errno = EDOM; return -1;
            }
            double angle = row_phase + 2.0 * M_PI * ((double)dim / (double)dims);
            s->real[i] = data[i] * cos(angle);
            s->imag[i] = data[i] * sin(angle);
        }
    }
    s->measurement_confidence = qihse_superposition_get_measurement_confidence(s);
    return 0;
}

int qihse_create_superposition_from_amplitudes(const double *real, const double *imag,
                                               size_t n, qihse_superposition_t *s) {
    if (!real || !imag) { if (s) memset(s, 0, sizeof(*s)); errno = EINVAL; return -1; }
    if (allocate_state(s, n, 1)) return -1;
    for (size_t i = 0; i < n; ++i) {
        if (!isfinite(real[i]) || !isfinite(imag[i])) {
            qihse_destroy_superposition(s); errno = EDOM; return -1;
        }
        s->real[i] = real[i]; s->imag[i] = imag[i];
        s->phase[i] = atan2(imag[i], real[i]);
    }
    s->measurement_confidence = qihse_superposition_get_measurement_confidence(s);
    return 0;
}

void qihse_destroy_superposition(qihse_superposition_t *s) {
    if (!s) return;
    free(s->real); free(s->imag); free(s->phase);
    memset(s, 0, sizeof(*s));
}

int qihse_superposition_normalize(qihse_superposition_t *s) {
    double scale;
    long double squares;
    if (state_norm(s, &scale, &squares)) return -1;
    long double divisor = sqrtl(squares);
    size_t count = s->num_states * s->dims_per_state;
    for (size_t i = 0; i < count; ++i) {
        s->real[i] = (double)(((long double)s->real[i] / scale) / divisor);
        s->imag[i] = (double)(((long double)s->imag[i] / scale) / divisor);
    }
    s->measurement_confidence = qihse_superposition_get_measurement_confidence(s);
    return 0;
}

void qihse_superposition_apply_phase(qihse_superposition_t *s, double shift) {
    size_t count;
    if (state_count(s, &count) || !isfinite(shift)) { errno = EINVAL; return; }
    shift = remainder(shift, 2.0 * M_PI);
    double c = cos(shift), d = sin(shift);
    /* Preflight all values so errors do not leave a partially rotated state. */
    for (size_t i = 0; i < count; ++i) {
        long double re = (long double)s->real[i] * c - (long double)s->imag[i] * d;
        long double im = (long double)s->real[i] * d + (long double)s->imag[i] * c;
        if (!isfinite((double)re) || !isfinite((double)im)) { errno = ERANGE; return; }
    }
    for (size_t i = 0; i < count; ++i) {
        double re = s->real[i], im = s->imag[i];
        s->real[i] = (double)((long double)re * c - (long double)im * d);
        s->imag[i] = (double)((long double)re * d + (long double)im * c);
    }
    s->global_phase = remainder(s->global_phase + shift, 2.0 * M_PI);
}

double qihse_superposition_state_fidelity(const qihse_superposition_t *a,
                                         const qihse_superposition_t *b) {
    if (!a || !b || a->num_states != b->num_states ||
        a->dims_per_state != b->dims_per_state) { errno = EINVAL; return 0.0; }
    double as, bs;
    long double an, bn, re = 0.0L, im = 0.0L;
    if (state_norm(a, &as, &an) || state_norm(b, &bs, &bn)) return 0.0;
    size_t count = a->num_states * a->dims_per_state;
    for (size_t i = 0; i < count; ++i) {
        long double ar = (long double)a->real[i] / as, ai = (long double)a->imag[i] / as;
        long double br = (long double)b->real[i] / bs, bi = (long double)b->imag[i] / bs;
        re += ar * br + ai * bi;
        im += ar * bi - ai * br;
    }
    long double value = ((re / an) * (re / bn)) + ((im / an) * (im / bn));
    return (double)fminl(1.0L, fmaxl(0.0L, value));
}

void qihse_superposition_get_probabilities(const qihse_superposition_t *s, double *p) {
    if (!s || !p) { errno = EINVAL; return; }
    double scale;
    long double squares;
    if (state_norm(s, &scale, &squares)) {
        if (s->num_states <= SIZE_MAX / sizeof(double))
            memset(p, 0, s->num_states * sizeof(double));
        return;
    }
    for (size_t row = 0; row < s->num_states; ++row) {
        long double mass = 0.0L;
        for (size_t d = 0; d < s->dims_per_state; ++d) {
            size_t i = row * s->dims_per_state + d;
            long double re = (long double)s->real[i] / scale, im = (long double)s->imag[i] / scale;
            mass += re * re + im * im;
        }
        p[row] = (double)(mass / squares);
    }
}

static uint64_t random_word(uint64_t *state) {
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

void qihse_superposition_measure_multiple(const qihse_superposition_t *s,
                                         size_t *measurements, size_t n, uint64_t seed) {
    if (!measurements || !n) { errno = EINVAL; return; }
    for (size_t i = 0; i < n; ++i) measurements[i] = SIZE_MAX;
    double scale;
    long double squares;
    if (state_norm(s, &scale, &squares)) return;
    double *p = malloc(s->num_states * sizeof(double));
    if (!p) { errno = ENOMEM; return; }
    qihse_superposition_get_probabilities(s, p);
    double sum = 0.0;
    size_t last_positive = SIZE_MAX;
    for (size_t i = 0; i < s->num_states; ++i) {
        if (p[i] > 0.0) last_positive = i;
        sum += p[i];
        p[i] = sum;
    }
    if (!(sum > 0.0) || !isfinite(sum)) { free(p); errno = EDOM; return; }
    for (size_t i = 0; i < n; ++i) {
        double draw = (double)(random_word(&seed) >> 11) * 0x1.0p-53 * sum;
        size_t lo = 0, hi = s->num_states;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (draw < p[mid]) hi = mid;
            else lo = mid + 1;
        }
        measurements[i] = lo < s->num_states ? lo : last_positive;
    }
    free(p);
}

size_t qihse_superposition_measure(const qihse_superposition_t *s, uint64_t seed) {
    size_t result = SIZE_MAX;
    qihse_superposition_measure_multiple(s, &result, 1, seed);
    return result;
}

size_t qihse_superposition_get_num_states(const qihse_superposition_t *s) { return s ? s->num_states : 0; }
size_t qihse_superposition_get_dims_per_state(const qihse_superposition_t *s) { return s ? s->dims_per_state : 0; }
double qihse_superposition_get_global_phase(const qihse_superposition_t *s) { return s ? s->global_phase : 0.0; }

double qihse_superposition_get_measurement_confidence(const qihse_superposition_t *s) {
    double scale;
    long double squares, maximum = 0.0L;
    if (state_norm(s, &scale, &squares)) return 0.0;
    for (size_t row = 0; row < s->num_states; ++row) {
        long double mass = 0.0L;
        for (size_t d = 0; d < s->dims_per_state; ++d) {
            size_t i = row * s->dims_per_state + d;
            long double re = (long double)s->real[i] / scale, im = (long double)s->imag[i] / scale;
            mass += re * re + im * im;
        }
        if (mass > maximum) maximum = mass;
    }
    return (double)(maximum / squares);
}

int qihse_superposition_is_normalized(const qihse_superposition_t *s) {
    double scale;
    long double squares;
    if (state_norm(s, &scale, &squares)) return 0;
    long double norm = (long double)scale * sqrtl(squares);
    return fabsl(norm - 1.0L) <= 1e-6L;
}
