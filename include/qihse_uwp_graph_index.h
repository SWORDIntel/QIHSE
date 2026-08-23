#ifndef QIHSE_UWP_GRAPH_INDEX_H
#define QIHSE_UWP_GRAPH_INDEX_H

#include <stddef.h>
#include <stdint.h>

#include "qihse_uwp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UWP_GI_OK = 0,
    UWP_GI_ERR_ARGS,
    UWP_GI_ERR_NO_CTX,
    UWP_GI_ERR_PERM,
    UWP_GI_ERR_FAILED
} uwp_gi_result_t;

uwp_gi_result_t uwp_dispatch_graph2(qihse_uwp_context_t* ctx,
                                    uint8_t command_opcode,
                                    const uint8_t* payload, size_t payload_len,
                                    qihse_user_t* user, int client_fd,
                                    qihse_uwp_write_fn write_fn, void* write_ctx);

uwp_gi_result_t uwp_dispatch_index(qihse_uwp_context_t* ctx,
                                   uint8_t command_opcode,
                                   const uint8_t* payload, size_t payload_len,
                                   qihse_user_t* user, int client_fd,
                                   qihse_uwp_write_fn write_fn, void* write_ctx);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_GRAPH_INDEX_H */
