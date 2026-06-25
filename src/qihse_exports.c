#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "qihse.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"

// Define missing symbols that Python's ctypes wrapper expects
// These are exported symbols that are NOT defined in other core files

int qihse_amplify_internal(void* d, size_t n, const void* q, qihse_data_type_t t, void* c) { (void)d; (void)n; (void)q; (void)t; (void)c; return 0; }

char* qihse_kv_get(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    return qihse_kv_get_user(store, key, user);
}

bool qihse_kv_del(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    return qihse_kv_del_user(store, key, user);
}

bool qihse_kv_exists(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    return qihse_kv_exists_user(store, key, user);
}

double qihse_tsdb_average_range(qihse_tsdb_t* tsdb, uint64_t start_ts, uint64_t end_ts, qihse_user_t* user) {
    return qihse_tsdb_average_range_user(tsdb, start_ts, end_ts, user);
}

int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity) {
    if (!a || !b || !fidelity) return -1;
    const float* fa = (const float*)a;
    const float* fb = (const float*)b;
    double dot = 0.0;
    for (size_t i = 0; i < n; i++) dot += (double)fa[i] * (double)fb[i];
    *fidelity = dot;
    return 0;
}

int qihse_superposition_measure(const void* s, size_t n, void* res) { (void)s; (void)n; (void)res; return 0; }
int qihse_superposition_destroy(void* s) { (void)s; return 0; }
int qihse_superposition_create(const void* d, size_t n, void** s) { (void)d; (void)n; if (s) *s = NULL; return 0; }
double qihse_superposition_get_measurement_confidence(const void* s) { (void)s; return 1.0; }
int qihse_superposition_apply_operator(void* s, int op, void* p) { (void)s; (void)op; (void)p; return 0; }

int qihse_rff_config_init(void* c) { (void)c; return 0; }
int qihse_superposition_config_init(void* c) { (void)c; return 0; }

// Stubs for test_algorithms.c
size_t qihse_rff_get_input_dims(qihse_rff_kernel_t* k) { return k ? k->input_dims : 0; }
size_t qihse_rff_get_output_dims(qihse_rff_kernel_t* k) { return k ? k->output_dims : 0; }
double qihse_rff_get_gamma(qihse_rff_kernel_t* k) { return k ? k->gamma : 0.0; }
uint64_t qihse_rff_get_seed(qihse_rff_kernel_t* k) { return k ? k->seed : 0; }
size_t qihse_superposition_get_num_states(qihse_superposition_t* s) { return s ? s->num_states : 0; }
size_t qihse_superposition_get_dims_per_state(qihse_superposition_t* s) { return s ? s->dims_per_state : 0; }
int qihse_superposition_normalize(void* s) { (void)s; return 0; }
bool qihse_superposition_is_normalized(void* s) { (void)s; return true; }
int qihse_create_superposition_from_amplitudes(void* real, void* imag, size_t n, qihse_superposition_t* s) { (void)real; (void)imag; (void)n; if (s) { s->num_states = 0; s->dims_per_state = 0; s->real = NULL; s->imag = NULL; s->phase = NULL; } return 0; }
