/* Standalone W12.1 centroid tests; requires only C99 and libm. */
#include "quantization/include/qihse_turboquant_tables.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void check_invalid_arguments(void)
{
    double values[20], original[20];
    size_t i;
    for (i = 0; i < 20; ++i)
        values[i] = original[i] = 1000.0 + i;

    assert(qihse_tq_build_centroids(0, 1, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(1, 1, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(1537, 1, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(SIZE_MAX, 1, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(128, 0, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(128, 5, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(128, (unsigned)-1, values, 20) == EINVAL);
    assert(qihse_tq_build_centroids(128, 4, NULL, 20) == EINVAL);
    assert(qihse_tq_build_centroids(128, 4, values, 15) == EINVAL);
    assert(qihse_tq_build_centroids(128, 1, values, 0) == EINVAL);
    assert(memcmp(values, original, sizeof(values)) == 0);

    /* Successful construction writes exactly the requested number of values. */
    assert(qihse_tq_build_centroids(128, 1, values, 20) == 0);
    assert(memcmp(values + 2, original + 2, 18 * sizeof(double)) == 0);
}

/* Independent closed-form integrals, not the implementation's quadrature. */
static long double analytic_mean(unsigned dimensions,
                                 long double a, long double b)
{
    long double mass, moment;
    if (dimensions == 2) {
        mass = asinl(b) - asinl(a);
        moment = sqrtl(1.0L - a * a) - sqrtl(1.0L - b * b);
    } else if (dimensions == 3) {
        return 0.5L * (a + b);
    } else if (dimensions == 4) {
        const long double x = asinl(a), y = asinl(b);
        mass = 0.5L * (y - x) + 0.25L * (sinl(2.0L * y) - sinl(2.0L * x));
        moment = (powl(1.0L - a * a, 1.5L)
                  - powl(1.0L - b * b, 1.5L)) / 3.0L;
    } else {
        assert(dimensions == 5);
        mass = (b - a) - (b * b * b - a * a * a) / 3.0L;
        moment = 0.5L * (b * b - a * a)
            - 0.25L * (b * b * b * b - a * a * a * a);
    }
    return moment / mass;
}

static void check_closed_form_stationarity(void)
{
    unsigned dimensions, bits;
    for (dimensions = 2; dimensions <= 5; ++dimensions) {
        for (bits = 1; bits <= 4; ++bits) {
            double values[16];
            const unsigned count = 1u << bits;
            unsigned i;
            assert(qihse_tq_build_centroids(dimensions, bits, values, 16) == 0);
            for (i = count / 2; i < count; ++i) {
                const long double a = i == count / 2 ? 0.0L
                    : 0.5L * ((long double)values[i - 1] + values[i]);
                const long double b = i + 1 == count ? 1.0L
                    : 0.5L * ((long double)values[i] + values[i + 1]);
                assert(fabsl(values[i] - analytic_mean(dimensions, a, b)) < 2.0e-12L);
            }
            if (dimensions == 3) {
                for (i = 0; i < count; ++i)
                    assert(values[i] == (2.0 * i + 1.0 - count) / count);
            }
        }
    }
}

static void check_profiles_and_repeatability(void)
{
    static const size_t dimensions[] = {
        2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33,
        63, 64, 65, 127, 128, 129, 383, 384, 385,
        767, 768, 769, 1024, 1535, 1536
    };
    size_t d;
    unsigned bits;
    for (d = 0; d < sizeof(dimensions) / sizeof(dimensions[0]); ++d) {
        for (bits = 1; bits <= 4; ++bits) {
            double first[16], second[16];
            const unsigned count = 1u << bits;
            unsigned i;
            assert(qihse_tq_build_centroids(dimensions[d], bits, first, count) == 0);
            assert(qihse_tq_build_centroids(dimensions[d], bits, second, count) == 0);
            assert(memcmp(first, second, count * sizeof(double)) == 0);
            for (i = 0; i < count; ++i) {
                assert(isfinite(first[i]));
                assert(first[i] > -1.0 && first[i] < 1.0);
                assert(first[i] == -first[count - 1 - i]);
                if (i > 0)
                    assert(first[i] > first[i - 1]);
            }
            if (bits == 1) {
                /* E|t| = Gamma(d/2)/(sqrt(pi)*Gamma((d+1)/2)).
                 * lgamma cancellation at high d warrants a looser tolerance. */
                const double expected = exp(lgamma(0.5 * dimensions[d])
                    - lgamma(0.5 * (dimensions[d] + 1.0))) / sqrt(acos(-1.0));
                assert(sqrt((double)dimensions[d]) * fabs(first[1] - expected) < 1.0e-11);
            }
        }
    }
}

static void check_independent_d768_reference(void)
{
    /* Independently computed exact-marginal references, in sqrt(d) units. */
    static const double expected[3][4] = {
        {0.798144331055, 0.0, 0.0, 0.0},
        {0.452726093206, 1.509546407271, 0.0, 0.0},
        {0.244982782861, 0.755559233878, 1.342687120544, 2.148511184851}
    };
    unsigned bits;
    for (bits = 1; bits <= 3; ++bits) {
        double values[16];
        const unsigned half_count = 1u << (bits - 1);
        unsigned i;
        assert(qihse_tq_build_centroids(768, bits, values, 16) == 0);
        for (i = 0; i < half_count; ++i)
            assert(fabs(sqrt(768.0) * values[half_count + i]
                        - expected[bits - 1][i]) < 1.0e-10);
    }
    /* A dimension-independent Gaussian table would fail these low-d checks. */
    {
        double values[2];
        assert(qihse_tq_build_centroids(2, 1, values, 2) == 0);
        assert(fabs(values[1] - 2.0 / acos(-1.0)) < 1.0e-14);
        assert(qihse_tq_build_centroids(3, 1, values, 2) == 0);
        assert(values[1] == 0.5);
    }
}

int main(void)
{
    assert(QIHSE_TQ_TABLES_VERSION == 1u);
    assert(strcmp(QIHSE_TQ_TABLES_PROFILE, "spherical-lloyd-max-f64-v1") == 0);
    check_invalid_arguments();
    check_closed_form_stationarity();
    check_profiles_and_repeatability();
    check_independent_d768_reference();
    puts("W12.1 spherical Lloyd-Max centroid tests passed");
    return 0;
}
