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
    /* Ownership-edit hook. When set, ADDSLOTS and SETSLOT NODE apply the
     * change through it (and so broadcast it on the cluster bus, exactly
     * like MOVESLOTS and the brain's re-home). A purely local ownership
     * edit is overwritten by the next peer's slot-map announcement, which
     * is why manual repairs made without the hook silently evaporate.
     * NULL keeps the edit local (library-only callers, tests). */
    bool (*set_range_owner)(void* server, uint16_t first, uint16_t last,
                            uint16_t owner_index);
    void* server;
} qihse_resp_cluster_context_t;

bool qihse_resp_cluster_dispatch(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv);

#ifdef __cplusplus
}
#endif

#endif
