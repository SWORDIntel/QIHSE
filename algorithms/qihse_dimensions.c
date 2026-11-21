/* Bounded heuristic dimension selection. Accuracy is a tuning target, not a guarantee. */
#include "qihse_dimensions.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

void qihse_dimension_config_init(qihse_dimension_config_t *c) {
    if (!c) return;
    *c = (qihse_dimension_config_t){8, 16384, .1, .3, .4, .3, 1, .95};
}

static int config_valid(const qihse_dimension_config_t *c) {
    return c && c->min_dims && c->max_dims >= c->min_dims &&
        isfinite(c->complexity_weight) && c->complexity_weight >= 0.0 &&
        isfinite(c->performance_weight) && c->performance_weight >= 0.0;
}

static int characteristics_valid(const qihse_problem_characteristics_t *p) {
    return p && p->input_size && isfinite(p->data_entropy) && p->data_entropy >= 0.0 &&
        isfinite(p->data_complexity) && p->data_complexity >= 0.0;
}

int qihse_analyze_problem_characteristics(const double *data, size_t n,
                                         qihse_problem_characteristics_t *p) {
    if (!data || !n || !p || n > SIZE_MAX / sizeof(double)) { errno = EINVAL; return -1; }
    memset(p, 0, sizeof(*p));
    double minimum = data[0], maximum = data[0];
    long double mean = 0.0L, variation = 0.0L;
    size_t nonzero = 0;
    for (size_t i = 0; i < n; ++i) {
        if (!isfinite(data[i])) { errno = EDOM; return -1; }
        mean += ((long double)data[i] - mean) / (i + 1);
        if (data[i] < minimum) minimum = data[i];
        if (data[i] > maximum) maximum = data[i];
        if (data[i] != 0.0) ++nonzero;
        if (i) variation += fabsl((long double)data[i] - data[i - 1]);
    }
    p->input_size = n;
    p->data_complexity = (double)fminl(variation / n, 1.7976931348623157e308L);
    p->sparsity = 1.0 - (double)nonzero / (double)n;
    if (maximum > minimum) {
        size_t bins[10] = {0};
        long double range = (long double)maximum - minimum;
        for (size_t i = 0; i < n; ++i) {
            long double scaled = ((long double)data[i] - minimum) / range;
            size_t bin = scaled >= 1.0L ? 9 : (size_t)(scaled * 10.0L);
            ++bins[bin];
        }
        for (size_t i = 0; i < 10; ++i) if (bins[i]) {
            double frequency = (double)bins[i] / (double)n;
            p->data_entropy -= frequency * log2(frequency);
        }
    }
    long double xy = 0.0L, xx = 0.0L, yy = 0.0L;
    for (size_t i = 1; i < n; ++i) {
        long double x = data[i - 1] - mean, y = data[i] - mean;
        xy += x * y; xx += x * x; yy += y * y;
    }
    if (xx > 0.0L && yy > 0.0L) p->correlation = (double)((xy / sqrtl(xx)) / sqrtl(yy));
    p->memory_budget = (size_t)1 << 30;
    p->performance_target = 1000.0;
    return 0;
}

size_t qihse_estimate_memory_usage(size_t dims, const qihse_problem_characteristics_t *p) {
    if (!p || !p->input_size || !dims) return 0;
    /* Conservative scalar feature pipeline: four N*D working planes, N phases,
     * and two D kernel arrays. The byte arithmetic saturates on overflow. */
    size_t n = p->input_size;
    if (dims > SIZE_MAX / n) return SIZE_MAX;
    size_t plane = dims * n;
    if (plane > SIZE_MAX / 4 || dims > SIZE_MAX / 2) return SIZE_MAX;
    size_t count = plane * 4;
    if (count > SIZE_MAX - n) return SIZE_MAX;
    count += n;
    if (count > SIZE_MAX - dims * 2) return SIZE_MAX;
    count += dims * 2;
    return count > SIZE_MAX / sizeof(double) ? SIZE_MAX : count * sizeof(double);
}

static size_t fit_budget(size_t requested, const qihse_problem_characteristics_t *p,
                         const qihse_dimension_config_t *c) {
    size_t minimum = qihse_estimate_memory_usage(c->min_dims, p);
    if (minimum == SIZE_MAX || minimum > p->memory_budget) { errno = ENOMEM; return 0; }
    size_t lo = c->min_dims, hi = requested;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2 + 1;
        size_t bytes = qihse_estimate_memory_usage(mid, p);
        if (bytes != SIZE_MAX && bytes <= p->memory_budget) lo = mid;
        else hi = mid - 1;
    }
    return lo;
}

size_t qihse_calculate_optimal_dimensions(const qihse_problem_characteristics_t *p,
                                         const qihse_dimension_config_t *c) {
    if (!characteristics_valid(p) || !config_valid(c)) { errno = EINVAL; return 0; }
    long double score = ((long double)p->data_entropy / 4.0L +
                         (long double)p->data_complexity * 100.0L) * c->complexity_weight +
                        log2l((long double)p->input_size) * c->performance_weight / 10.0L;
    long double upper = logl((long double)c->max_dims / 8.0L);
    size_t dims;
    if (score >= upper) dims = c->max_dims;
    else {
        long double proposed = expl(score) * 8.0L;
        dims = proposed >= c->max_dims ? c->max_dims :
               proposed <= c->min_dims ? c->min_dims : (size_t)proposed;
    }
    return fit_budget(dims, p, c);
}

size_t qihse_calculate_dimensions_for_accuracy(const qihse_problem_characteristics_t *p,
                                              double accuracy, const qihse_dimension_config_t *c) {
    if (!characteristics_valid(p) || !config_valid(c) || !isfinite(accuracy) || accuracy <= 0.0 || accuracy > 1.0) {
        errno = EINVAL; return 0;
    }
    size_t base = qihse_calculate_optimal_dimensions(p, c);
    if (!base) return 0;
    /* 1 means the largest allowed budget-fitting setting, not exact recall. */
    if (accuracy == 1.0) return fit_budget(c->max_dims, p, c);
    long double proposed = (long double)base * (-log1pl(-accuracy) * 2.0L);
    size_t dims = proposed >= c->max_dims ? c->max_dims :
                  proposed <= c->min_dims ? c->min_dims : (size_t)proposed;
    return fit_budget(dims, p, c);
}

size_t qihse_calculate_dimensions_with_memory(const qihse_problem_characteristics_t *p,
                                             size_t budget, const qihse_dimension_config_t *c) {
    if (!p) { errno = EINVAL; return 0; }
    qihse_problem_characteristics_t copy = *p;
    copy.memory_budget = budget;
    return qihse_calculate_optimal_dimensions(&copy, c);
}

int qihse_validate_dimensions(size_t dims, const qihse_problem_characteristics_t *p,
                              const qihse_dimension_config_t *c) {
    if (!config_valid(c) || dims < c->min_dims || dims > c->max_dims) return 0;
    if (p) {
        if (!characteristics_valid(p)) return 0;
        size_t bytes = qihse_estimate_memory_usage(dims, p);
        if (bytes == SIZE_MAX || bytes > p->memory_budget) return 0;
    }
    return 1;
}

double qihse_estimate_performance(size_t dims, const qihse_problem_characteristics_t *p) {
    if (!p || !dims || !p->input_size || !isfinite(p->performance_target) || p->performance_target <= 0.0) return 0.0;
    long double factor = (long double)dims * p->input_size / 1000000.0L;
    return (double)((long double)p->performance_target / (1.0L + factor));
}

double qihse_calculate_dimension_efficiency(size_t dims, const qihse_problem_characteristics_t *p) {
    if (!p || !dims || !p->memory_budget || !isfinite(p->performance_target) || p->performance_target <= 0.0) return 0.0;
    size_t bytes = qihse_estimate_memory_usage(dims, p);
    if (bytes == SIZE_MAX || bytes > p->memory_budget) return 0.0;
    double memory = 1.0 - (double)bytes / (double)p->memory_budget;
    double performance = qihse_estimate_performance(dims, p) / p->performance_target;
    return fmin(1.0, fmax(0.0, (memory + performance) / 2.0));
}

int qihse_dimension_scaler_init(qihse_dimension_scaler_t *s, size_t initial,
                               double target, size_t minimum, size_t maximum) {
    if (!s || !minimum || maximum < minimum || initial < minimum || initial > maximum ||
        !isfinite(target) || target <= 0.0 || target > 1.0) { errno = EINVAL; return -1; }
    *s = (qihse_dimension_scaler_t){initial, .5, target, minimum, maximum, .1, NULL};
    return 0;
}
void qihse_dimension_scaler_destroy(qihse_dimension_scaler_t *s) {
    if (!s) return;
    free(s->internal_state); memset(s, 0, sizeof(*s));
}
size_t qihse_dimension_scaler_adapt(qihse_dimension_scaler_t *s, double accuracy, double performance) {
    if (!s || !s->min_dims || s->max_dims < s->min_dims || !isfinite(accuracy) ||
        accuracy < 0.0 || accuracy > 1.0 || !isfinite(performance) || performance < 0.0 ||
        !isfinite(s->adaptation_rate) || s->adaptation_rate < 0.0 ||
        !isfinite(s->target_accuracy) || s->target_accuracy <= 0.0 || s->target_accuracy > 1.0) {
        errno = EINVAL; return 0;
    }
    s->current_accuracy = accuracy;
    long double adjustment = (s->target_accuracy - accuracy) * s->adaptation_rate;
    if (performance < 500.0) adjustment *= .5L;
    long double value = s->current_dims * (1.0L + adjustment);
    s->current_dims = value <= s->min_dims ? s->min_dims : value >= s->max_dims ? s->max_dims : (size_t)value;
    return s->current_dims;
}
void qihse_dimension_scaler_reset(qihse_dimension_scaler_t *s) {
    if (!s || s->max_dims < s->min_dims) return;
    s->current_accuracy = .5;
    s->current_dims = s->min_dims + (s->max_dims - s->min_dims) / 2;
}
size_t qihse_clamp_dimensions(size_t dims, const qihse_dimension_config_t *c) {
    if (!config_valid(c)) { errno = EINVAL; return 0; }
    return dims < c->min_dims ? c->min_dims : dims > c->max_dims ? c->max_dims : dims;
}
int qihse_suggest_scaling_factors(size_t base, size_t n, double *factors) {
    (void)base;
    if (!factors || !n || n > 1024) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < n; ++i) factors[i] = ldexp(1.0, (int)i);
    return 0;
}
size_t qihse_calculate_entropy_dimension_bound(const qihse_problem_characteristics_t *p) {
    if (!p || !p->input_size || !isfinite(p->data_entropy) || p->data_entropy < 0.0) { errno = EINVAL; return 0; }
    long double exponent = (long double)p->data_entropy * p->input_size / 10.0L;
    if (exponent >= logl((long double)SIZE_MAX)) return SIZE_MAX;
    long double bound = expl(exponent);
    if (bound >= (long double)SIZE_MAX) return SIZE_MAX;
    return bound < 8.0L ? 8 : (size_t)bound;
}
