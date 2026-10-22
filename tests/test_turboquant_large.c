/* Opt-in representative/max-dimension correctness smoke. Timings are single
 * CPU-time observations, not a benchmark distribution or promotion evidence. */
#include "quantization/include/qihse_turboquant.h"
#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    const unsigned dimensions[] = {128, 384, 768, 1536};
    size_t case_index;
    for (case_index = 0; case_index < sizeof(dimensions)/sizeof(dimensions[0]); ++case_index) {
        qihse_tq_config c = {dimensions[case_index], 4, QIHSE_TQ_PRODUCT, 42, 43};
        qihse_tq_profile *p = NULL;
        float *x = calloc(c.dimensions, sizeof(*x));
        float *q = calloc(c.dimensions, sizeof(*q));
        double *decoded = malloc(c.dimensions*sizeof(*decoded));
        size_t bytes, i, input_case;
        uint8_t *code;
        clock_t begin, setup;
        assert(x && q && decoded);
        assert(qihse_tq_code_size(&c, &bytes) == 0);
        code = malloc(bytes); assert(code);
        begin = clock(); assert(begin != (clock_t)-1);
        assert(qihse_tq_profile_create(&c, &p) == 0);
        setup = clock()-begin;
        for (input_case = 0; input_case < 3; ++input_case) {
            qihse_tq_query *query = NULL;
            double score, expected = 0, scale = 0;
            for (i = 0; i < c.dimensions; ++i) {
                x[i] = input_case == 0 ? FLT_MAX : input_case == 1
                    ? (i%2 ? -0x1p-149f : 0x1p-149f) : (float)((int)(i%31)-15)*0.125f;
                q[i] = input_case == 0 ? (i%2 ? -FLT_MAX : FLT_MAX)
                    : (float)((int)(i%13)-6)*0.25f;
            }
            assert(qihse_tq_encode(p, x, c.dimensions, code, bytes) == 0);
            assert(qihse_tq_decode(p, code, bytes, decoded, c.dimensions) == 0);
            assert(qihse_tq_prepare_query(p, q, c.dimensions, &query) == 0);
            assert(qihse_tq_score(p, query, code, bytes, QIHSE_TQ_DOT, &score) == 0);
            for (i = 0; i < c.dimensions; ++i) {
                assert(isfinite(decoded[i]));
                expected += decoded[i]*(double)q[i];
                scale += fabs(decoded[i]*(double)q[i]);
            }
            assert(isfinite(score) && fabs(score-expected) <= 1e-12*scale+1e-300);
            qihse_tq_query_destroy(query);
        }
        printf("dense reference d=%u k=4 total_bits=5 bytes=%zu matrix_bytes=%zu setup_cpu_seconds=%.6f: passed\n",
               c.dimensions, bytes, qihse_tq_profile_matrix_bytes(p), (double)setup/CLOCKS_PER_SEC);
        fflush(stdout);
        qihse_tq_profile_destroy(p); free(code); free(x); free(q); free(decoded);
    }
    puts("Representative and maximum-dimension dense reference tests passed");
    return 0;
}
