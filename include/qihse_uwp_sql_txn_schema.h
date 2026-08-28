#ifndef QIHSE_UWP_SQL_TXN_SCHEMA_H
#define QIHSE_UWP_SQL_TXN_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

#include "qihse_uwp.h"
#include "qihse_txn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UWP_STS_OK = 0,
    UWP_STS_ERR_ARGS,
    UWP_STS_ERR_NO_CTX,
    UWP_STS_ERR_PERM,
    UWP_STS_ERR_FAILED
} uwp_sts_result_t;

uwp_sts_result_t uwp_dispatch_sql(qihse_uwp_context_t* ctx, uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx);
uwp_sts_result_t uwp_dispatch_txn(qihse_uwp_context_t* ctx, uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx);
uwp_sts_result_t uwp_dispatch_schema(qihse_uwp_context_t* ctx, uint8_t command_opcode,
                                     const uint8_t* payload, size_t payload_len,
                                     qihse_user_t* user, int client_fd,
                                     qihse_uwp_write_fn write_fn, void* write_ctx);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_SQL_TXN_SCHEMA_H */
