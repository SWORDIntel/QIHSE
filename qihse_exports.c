#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse.h"

// Define all symbols that Python's ctypes wrapper expects with EXACT signatures from headers
int qihse_amplify_internal(void* d, size_t n, const void* q, qihse_data_type_t t, void* c) { return 0; }
int qihse_amplify(void* d, size_t n, const void* q, qihse_data_type_t t, void* c) { return 0; }
int qihse_config_init(qihse_config_t* c, qihse_data_type_t t, size_t n) { return 0; }
void qihse_record_anchor_search(bool u, double e, double s) {}

int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity) {
    if (!a || !b || !fidelity) return -1;
    const float* fa = (const float*)a;
    const float* fb = (const float*)b;
    double dot = 0.0;
    for (size_t i = 0; i < n; i++) dot += (double)fa[i] * (double)fb[i];
    *fidelity = dot;
    return 0;
}

int qihse_superposition_measure(const void* s, size_t n, void* res) { return 0; }
int qihse_superposition_destroy(void* s) { return 0; }
int qihse_superposition_create(const void* d, size_t n, void** s) { return 0; }
double qihse_superposition_get_measurement_confidence(const void* s) { return 1.0; }
int qihse_superposition_apply_operator(void* s, int op, void* p) { return 0; }

int qihse_context_create(const char* n, void** c) { if (c) *c = (void*)1; return 0; }
int qihse_context_destroy(void* c) { return 0; }

void qihse_amplification_config_init(qihse_amplification_config_t* config, size_t n) { (void)config; (void)n; }
int qihse_rff_config_init(void* c) { return 0; }
int qihse_superposition_config_init(void* c) { return 0; }
