/*
 * Independently implemented W12.1 dimension-aware scalar reference.
 *
 * Substitute t = sin(theta): f_d(t) dt is proportional to
 * cos(theta)^(d-2) dtheta. This removes the d=2 endpoint singularity.
 * Integrate in y = sqrt(d)*theta, keeping the concentrated high-dimensional
 * density at order-one width. The first moment is analytic:
 *
 * integral_a^b t*(1-t*t)^((d-3)/2) dt
 *   = [(1-a*a)^((d-1)/2) - (1-b*b)^((d-1)/2)] / (d-1).
 *
 * expm1 computes the difference without cancellation. The density's unknown
 * normalization cancels in the conditional mean. Gauss-Legendre rules of
 * orders 8 and 16, generated here from the Legendre recurrence, provide an
 * adaptive mass integral. No external implementation or centroid data is used.
 */
#include "quantization/include/qihse_turboquant_tables.h"

#include <errno.h>
#include <float.h>
#include <math.h>
#include <string.h>

#define TQ_HALF_LEVELS_MAX 8u
#define TQ_LLOYD_ITERATIONS_MAX 10000u
#define TQ_INTEGRATION_DEPTH_MAX 24u

typedef struct tq_gauss_rule {
    unsigned half_order;
    double nodes[8];
    double weights[8];
} tq_gauss_rule;

typedef struct tq_mass_integrator {
    double inverse_root_dimension;
    double density_power;
    tq_gauss_rule coarse;
    tq_gauss_rule fine;
} tq_mass_integrator;

/* Return P_n(x) and its derivative from the three-term recurrence. */
static void tq_legendre(unsigned order, double x,
                        double *value, double *derivative)
{
    unsigned degree;
    double previous = 1.0;
    double current = x;

    for (degree = 2; degree <= order; ++degree) {
        double next = ((2.0 * degree - 1.0) * x * current
                       - (degree - 1.0) * previous) / degree;
        previous = current;
        current = next;
    }
    *value = current;
    *derivative = order * (x * current - previous) / (x * x - 1.0);
}

static int tq_make_gauss_rule(unsigned order, tq_gauss_rule *rule)
{
    unsigned i;
    const double pi = acos(-1.0);

    rule->half_order = order / 2;
    for (i = 0; i < rule->half_order; ++i) {
        double x = cos(pi * (i + 0.75) / (order + 0.5));
        double value = 0.0;
        double derivative = 0.0;
        unsigned iteration;

        for (iteration = 0; iteration < 32; ++iteration) {
            double next;
            tq_legendre(order, x, &value, &derivative);
            next = x - value / derivative;
            if (!isfinite(next) || next <= 0.0 || next >= 1.0)
                return ERANGE;
            if (fabs(next - x) <= 2.0 * DBL_EPSILON) {
                x = next;
                break;
            }
            x = next;
        }
        if (iteration == 32)
            return ERANGE;
        tq_legendre(order, x, &value, &derivative);
        rule->nodes[i] = x;
        rule->weights[i] = 2.0 / ((1.0 - x * x) * derivative * derivative);
        if (!isfinite(rule->weights[i]) || rule->weights[i] <= 0.0)
            return ERANGE;
    }
    return 0;
}

static double tq_density(const tq_mass_integrator *integrator, double y)
{
    const double t = sin(y * integrator->inverse_root_dimension);
    const double squared = t * t;

    /* Quadrature is interior, but sin may round to one near the endpoint. */
    if (squared >= 1.0)
        return 0.0;
    return exp(integrator->density_power * log1p(-squared));
}

static double tq_mass_rule(const tq_mass_integrator *integrator,
                           const tq_gauss_rule *rule, double a, double b)
{
    unsigned i;
    const double midpoint = a + 0.5 * (b - a);
    const double half_width = 0.5 * (b - a);
    double sum = 0.0;
    double compensation = 0.0;

    for (i = 0; i < rule->half_order; ++i) {
        const double offset = half_width * rule->nodes[i];
        const double term = rule->weights[i]
            * (tq_density(integrator, midpoint - offset)
               + tq_density(integrator, midpoint + offset));
        const double corrected = term - compensation;
        const double next = sum + corrected;
        compensation = (next - sum) - corrected;
        sum = next;
    }
    return half_width * sum;
}

static int tq_integrate_mass(const tq_mass_integrator *integrator,
                            double a, double b, double absolute_tolerance,
                            unsigned depth, double *result)
{
    const double coarse = tq_mass_rule(integrator, &integrator->coarse, a, b);
    const double fine = tq_mass_rule(integrator, &integrator->fine, a, b);
    const double tolerance = absolute_tolerance
        + 64.0 * DBL_EPSILON * fabs(fine);
    double midpoint, left, right;
    int error;

    if (!isfinite(coarse) || !isfinite(fine) || fine < 0.0)
        return ERANGE;
    /* Width bound prevents two rules agreeing after missing a narrow peak. */
    if (b - a <= 2.0 && fabs(fine - coarse) <= tolerance) {
        *result = fine;
        return 0;
    }
    if (depth == TQ_INTEGRATION_DEPTH_MAX)
        return ERANGE;
    midpoint = a + 0.5 * (b - a);
    if (midpoint <= a || midpoint >= b)
        return ERANGE;
    error = tq_integrate_mass(integrator, a, midpoint,
                              absolute_tolerance * 0.5, depth + 1, &left);
    if (error)
        return error;
    error = tq_integrate_mass(integrator, midpoint, b,
                              absolute_tolerance * 0.5, depth + 1, &right);
    if (error)
        return error;
    *result = left + right;
    return 0;
}

static int tq_conditional_mean(size_t dimensions,
                               const tq_mass_integrator *integrator,
                               double a, double b, double *mean)
{
    const double root_dimension = sqrt((double)dimensions);
    const double power = 0.5 * (dimensions - 1.0);
    const double log_left = power * log1p(-a * a);
    const double moment_difference = b == 1.0 ? exp(log_left)
        : exp(log_left) * -expm1(power * log1p(-b * b) - log_left);
    const double theta_left = asin(a);
    const double theta_right = asin(b);
    double mass;
    int error;

    if (dimensions == 2) {
        /* Uniform in theta, including both formerly singular endpoints. */
        mass = root_dimension * (theta_right - theta_left);
    } else {
        error = tq_integrate_mass(integrator,
                                  root_dimension * theta_left,
                                  root_dimension * theta_right,
                                  1.0e-17, 0, &mass);
        if (error)
            return error;
    }
    if (!isfinite(mass) || mass <= 0.0)
        return ERANGE;
    *mean = (root_dimension / (dimensions - 1.0))
        * (moment_difference / mass);
    if (!isfinite(*mean) || *mean <= a || *mean >= b)
        return ERANGE;
    return 0;
}

int qihse_tq_build_centroids(size_t dimensions, unsigned bits,
                           double *out, size_t out_count)
{
    tq_mass_integrator integrator;
    double positive[TQ_HALF_LEVELS_MAX];
    double next[TQ_HALF_LEVELS_MAX];
    double completed[2 * TQ_HALF_LEVELS_MAX];
    double root_dimension, extent;
    unsigned levels, half_levels, i, iteration;
    int error;

    if (dimensions < QIHSE_TQ_TABLES_MIN_DIMENSIONS
        || dimensions > QIHSE_TQ_TABLES_MAX_DIMENSIONS
        || bits < QIHSE_TQ_TABLES_MIN_BITS
        || bits > QIHSE_TQ_TABLES_MAX_BITS || out == NULL)
        return EINVAL;
    levels = 1u << bits;
    if (out_count < levels)
        return EINVAL;
    half_levels = levels / 2;

    if (dimensions == 3) {
        /* The spherical marginal is exactly uniform on [-1, 1]. */
        for (i = 0; i < levels; ++i)
            completed[i] = (2.0 * i + 1.0 - levels) / levels;
        memcpy(out, completed, levels * sizeof(*out));
        return 0;
    }

    root_dimension = sqrt((double)dimensions);
    integrator.inverse_root_dimension = 1.0 / root_dimension;
    integrator.density_power = 0.5 * (dimensions - 2.0);
    error = tq_make_gauss_rule(8, &integrator.coarse);
    if (error)
        return error;
    error = tq_make_gauss_rule(16, &integrator.fine);
    if (error)
        return error;

    /* Only an initialization, not a substitute density or final codebook.
     * Var(t)=1/d, so start within four standard deviations of zero, capped
     * at the actual support. This avoids vanishing-mass initial tail cells. */
    extent = fmin(1.0, 4.0 / root_dimension);
    for (i = 0; i < half_levels; ++i)
        positive[i] = extent * (i + 0.5) / half_levels;

    for (iteration = 0; iteration < TQ_LLOYD_ITERATIONS_MAX; ++iteration) {
        double largest_change = 0.0;
        for (i = 0; i < half_levels; ++i) {
            const double left = i == 0 ? 0.0
                : positive[i - 1] + 0.5 * (positive[i] - positive[i - 1]);
            const double right = i + 1 == half_levels ? 1.0
                : positive[i] + 0.5 * (positive[i + 1] - positive[i]);
            double change;
            error = tq_conditional_mean(dimensions, &integrator,
                                         left, right, &next[i]);
            if (error)
                return error;
            change = root_dimension * fabs(next[i] - positive[i]);
            if (change > largest_change)
                largest_change = change;
        }
        memcpy(positive, next, half_levels * sizeof(*positive));
        /* Use sphere-standard-deviation units, independent of dimension. */
        if (largest_change <= 1.0e-14)
            break;
    }
    if (iteration == TQ_LLOYD_ITERATIONS_MAX)
        return EAGAIN;
    for (i = 0; i < half_levels; ++i) {
        if (!isfinite(positive[i]) || positive[i] <= 0.0
            || positive[i] >= 1.0 || (i > 0 && positive[i] <= positive[i - 1]))
            return ERANGE;
        completed[half_levels + i] = positive[i];
        completed[half_levels - 1 - i] = -positive[i];
    }
    memcpy(out, completed, levels * sizeof(*out));
    return 0;
}
