#ifndef QIHSE_RESP_CLUSTER_H
#define QIHSE_RESP_CLUSTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t* data;
    size_t len;
} qihse_resp_arg_t;

typedef bool (*qihse_resp_output_fn)(void* context, const void* data, size_t len);

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_resp_output_fn output;
    void* output_context;
} qihse_resp_cluster_context_t;

bool qihse_resp_cluster_dispatch(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv);

#ifdef __cplusplus
}
#endif

#endif
