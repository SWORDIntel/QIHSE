/* Classical, explicitly materialized Grover operators. */
#include "qihse_amplification.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Independent callers must not race on the last-operation diagnostic state. */
static __thread qihse_amplification_stats_t last_stats;

static int valid_state(const qihse_superposition_t *s) {
    if (!s || !s->real || !s->imag || !s->phase || !s->num_states ||
        !s->dims_per_state || s->num_states > SIZE_MAX / s->dims_per_state ||
        s->num_states * s->dims_per_state > SIZE_MAX / sizeof(double)) {
        errno = EINVAL; return 0;
    }
    for (size_t i = 0; i < s->num_states * s->dims_per_state; ++i)
        if (!isfinite(s->real[i]) || !isfinite(s->imag[i])) { errno = EDOM; return 0; }
    for (size_t i = 0; i < s->num_states; ++i)
        if (!isfinite(s->phase[i])) { errno = EDOM; return 0; }
    return 1;
}

static int valid_targets(const qihse_superposition_t *s, const size_t *targets, size_t n) {
    if (!targets || !n || n > s->num_states) { errno = EINVAL; return 0; }
    unsigned char *seen = calloc(s->num_states, 1);
    if (!seen) { errno = ENOMEM; return 0; }
    for (size_t i = 0; i < n; ++i) {
        if (targets[i] >= s->num_states || seen[targets[i]]) {
            free(seen); errno = EINVAL; return 0;
        }
        seen[targets[i]] = 1;
    }
    free(seen);
    return 1;
}

void qihse_amplification_config_init(qihse_amplification_config_t *c, size_t problem_size) {
    (void)problem_size;
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->convergence_threshold = 1e-6;
    c->oracle_selectivity = 0.1;
    c->adaptive_rounds = true;
    /* fixed_rounds=0 means derive rounds from the actual target count. */
}

static void mark_states(qihse_superposition_t *s, const size_t *targets, size_t n) {
    for (size_t t = 0; t < n; ++t) {
        size_t state = targets[t];
        s->phase[state] = remainder(s->phase[state] + M_PI, 2.0 * M_PI);
        for (size_t d = 0; d < s->dims_per_state; ++d) {
            size_t i = state * s->dims_per_state + d;
            s->real[i] = -s->real[i]; s->imag[i] = -s->imag[i];
        }
    }
}

void qihse_oracle_mark(qihse_superposition_t *s, const size_t *targets, size_t n,
                       double selectivity) {
    if (!isfinite(selectivity) || selectivity < 0.0 || selectivity > 1.0) { errno = EINVAL; return; }
    if (valid_state(s) && valid_targets(s, targets, n)) mark_states(s, targets, n);
}

static int diffuse(qihse_superposition_t *s) {
    size_t count = s->num_states * s->dims_per_state;
    long double re = 0.0L, im = 0.0L;
    for (size_t i = 0; i < count; ++i) { re += s->real[i]; im += s->imag[i]; }
    re /= count; im /= count;
    for (size_t i = 0; i < count; ++i)
        if (!isfinite((double)(2.0L * re - s->real[i])) ||
            !isfinite((double)(2.0L * im - s->imag[i]))) { errno = ERANGE; return -1; }
    for (size_t i = 0; i < count; ++i) {
        s->real[i] = (double)(2.0L * re - s->real[i]);
        s->imag[i] = (double)(2.0L * im - s->imag[i]);
    }
    return 0;
}

void qihse_diffusion_operator(qihse_superposition_t *s) { if (valid_state(s)) (void)diffuse(s); }
void qihse_diffusion_operator_public(qihse_superposition_t *s) { qihse_diffusion_operator(s); }

int qihse_compute_optimal_rounds(size_t size, size_t targets) {
    if (!size || !targets || targets > size) { errno = EINVAL; return -1; }
    double angle = asin(sqrt((double)targets / (double)size));
    double rounds = floor(M_PI / (4.0 * angle));
    /* Keep this experimental materialized simulator bounded as before. */
    return rounds > 50.0 ? 50 : (int)rounds;
}

int qihse_amplification_converged(const qihse_superposition_t *a,
                                 const qihse_superposition_t *b, double threshold) {
    if (!valid_state(a) || !valid_state(b) || a->num_states != b->num_states ||
        a->dims_per_state != b->dims_per_state || !isfinite(threshold) || threshold <= 0.0)
        return 0;
    size_t count = a->num_states * a->dims_per_state;
    for (size_t i = 0; i < count; ++i) {
        long double dr = (long double)a->real[i] - b->real[i];
        long double di = (long double)a->imag[i] - b->imag[i];
        if (hypotl(dr, di) >= threshold) return 0;
    }
    return 1;
}

static double target_probability(const qihse_superposition_t *s,
                                  const size_t *targets, size_t n) {
    long double total = 0.0L, selected = 0.0L;
    for (size_t i = 0; i < s->num_states * s->dims_per_state; ++i)
        total += (long double)s->real[i] * s->real[i] + (long double)s->imag[i] * s->imag[i];
    if (!(total > 0.0L)) return 0.0;
    for (size_t t = 0; t < n; ++t)
        for (size_t d = 0; d < s->dims_per_state; ++d) {
            size_t i = targets[t] * s->dims_per_state + d;
            selected += (long double)s->real[i] * s->real[i] + (long double)s->imag[i] * s->imag[i];
        }
    return (double)fminl(1.0L, selected / total);
}

static int amplify(qihse_superposition_t *s, const size_t *targets, size_t n,
                    const qihse_amplification_config_t *c, double confidence_target) {
    memset(&last_stats, 0, sizeof(last_stats));
    if (!valid_state(s) || !qihse_amplification_config_validate(c) ||
        !valid_targets(s, targets, n)) return -1;
    int optimal = qihse_compute_optimal_rounds(s->num_states, n);
    int rounds = c->fixed_rounds ? c->fixed_rounds : optimal;
    if (rounds < c->min_rounds) rounds = c->min_rounds;
    if (c->max_rounds > 0 && rounds > c->max_rounds) rounds = c->max_rounds;
    size_t count = s->num_states * s->dims_per_state;
    qihse_superposition_t previous = *s;
    previous.real = malloc(count * sizeof(double));
    previous.imag = malloc(count * sizeof(double));
    previous.phase = malloc(s->num_states * sizeof(double));
    if (!previous.real || !previous.imag || !previous.phase) {
        free(previous.real); free(previous.imag); free(previous.phase); errno = ENOMEM; return -1;
    }
    int performed = 0;
    last_stats.rounds_optimal = optimal;
    double probability = target_probability(s, targets, n);
    for (; performed < rounds; ) {
        if (performed >= c->min_rounds && confidence_target >= 0.0 && probability >= confidence_target) break;
        memcpy(previous.real, s->real, count * sizeof(double));
        memcpy(previous.imag, s->imag, count * sizeof(double));
        memcpy(previous.phase, s->phase, s->num_states * sizeof(double));
        mark_states(s, targets, n);
        if (diffuse(s)) {
            memcpy(s->real, previous.real, count * sizeof(double));
            memcpy(s->imag, previous.imag, count * sizeof(double));
            memcpy(s->phase, previous.phase, s->num_states * sizeof(double));
            free(previous.real); free(previous.imag); free(previous.phase);
            return -1;
        }
        ++performed;
        probability = target_probability(s, targets, n);
        if (performed >= c->min_rounds && qihse_amplification_converged(s, &previous, c->convergence_threshold)) break;
    }
    free(previous.real); free(previous.imag); free(previous.phase);
    s->measurement_confidence = qihse_superposition_get_measurement_confidence(s);
    last_stats.rounds_performed = performed;
    last_stats.oracle_calls = performed;
    last_stats.diffusion_calls = performed;
    last_stats.success_probability = probability;
    last_stats.final_amplitude = sqrt(probability);
    return performed;
}

int qihse_amplify(qihse_superposition_t *s, const size_t *targets, size_t n,
                  const qihse_amplification_config_t *c) {
    return amplify(s, targets, n, c, -1.0);
}

int qihse_amplify_fixed_point(qihse_superposition_t *s, const size_t *targets, size_t n,
                              const qihse_amplification_config_t *c) {
    (void)s; (void)targets; (void)n; (void)c;
    /* Ordinary Grover rotations do not implement fixed-point amplification. */
    errno = ENOTSUP;
    return -1;
}

int qihse_amplify_adaptive(qihse_superposition_t *s, const size_t *targets, size_t n,
                           const qihse_amplification_config_t *c, double confidence) {
    if (!isfinite(confidence) || confidence <= 0.0 || confidence > 1.0) { errno = EINVAL; return -1; }
    return amplify(s, targets, n, c, confidence);
}

size_t qihse_find_maximum_amplitude(const qihse_superposition_t *s,
                                   const qihse_amplification_config_t *c) {
    (void)c;
    if (!valid_state(s)) return SIZE_MAX;
    size_t best = 0;
    long double maximum = -1.0L;
    for (size_t row = 0; row < s->num_states; ++row) {
        long double mass = 0.0L;
        for (size_t d = 0; d < s->dims_per_state; ++d) {
            size_t i = row * s->dims_per_state + d;
            mass += (long double)s->real[i] * s->real[i] + (long double)s->imag[i] * s->imag[i];
        }
        if (mass > maximum) { maximum = mass; best = row; }
    }
    return best;
}

int qihse_amplification_get_stats(qihse_amplification_stats_t *stats) {
    if (!stats) { errno = EINVAL; return -1; }
    *stats = last_stats;
    return 0;
}
void qihse_amplification_reset_stats(void) { memset(&last_stats, 0, sizeof(last_stats)); }

double qihse_estimate_success_probability(size_t size, size_t targets, int rounds) {
    if (!size || targets > size || rounds < 0) { errno = EINVAL; return 0.0; }
    if (!targets) return 0.0;
    double theta = asin(sqrt((double)targets / (double)size));
    double amplitude = sin((2.0 * (double)rounds + 1.0) * theta);
    return amplitude * amplitude;
}

int qihse_amplification_config_validate(const qihse_amplification_config_t *c) {
    if (!c || c->min_rounds < 0 || c->max_rounds < 0 || c->fixed_rounds < 0 ||
        (c->max_rounds > 0 && c->max_rounds < c->min_rounds) ||
        !isfinite(c->convergence_threshold) || c->convergence_threshold <= 0.0 ||
        !isfinite(c->oracle_selectivity) || c->oracle_selectivity < 0.0 || c->oracle_selectivity > 1.0) {
        errno = EINVAL; return 0;
    }
    return 1;
}
