#ifndef QIHSE_SEARCH_INTERNAL_H
#define QIHSE_SEARCH_INTERNAL_H

#include "qihse.h"

typedef struct {
    size_t comparisons;
    bool candidate_matched;
    bool scanned;
} qihse_verification_work_t;

not_stisla_result_t qihse_verify_result_with_work(
    const void* data, size_t n, const void* query, qihse_data_type_t type,
    const qihse_type_descriptor_t* descriptor,
    const qihse_collapse_result_t* collapse, const qihse_verify_config_t* config,
    qihse_verification_work_t* work);

/* Shared by the streaming core and the public scalar verification wrappers. */
not_stisla_result_t qihse_verify_result_with_descriptor(
    const void* data, size_t n, const void* query, qihse_data_type_t type,
    const qihse_type_descriptor_t* descriptor,
    const qihse_collapse_result_t* collapse, const qihse_verify_config_t* config);

#endif
