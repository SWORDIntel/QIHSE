#include "qihse_uwp_repl_pool.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>

#include "qihse_wal.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

static void uwp_repl_pool_write_cb(qihse_uwp_write_fn write_fn, void* write_ctx,
                                   const void* data, size_t len) {
    if (write_fn) write_fn(write_ctx, data, len);
}

static uint32_t uwp_repl_pool_read_le32(const uint8_t* value) {
    return (uint32_t)value[0] |
           ((uint32_t)value[1] << 8) |
           ((uint32_t)value[2] << 16) |
           ((uint32_t)value[3] << 24);
}

static uint64_t uwp_repl_pool_read_le64(const uint8_t* value) {
    uint64_t result = 0;
    size_t i;

    for (i = 0; i < 8; ++i) result |= (uint64_t)value[i] << (i * 8);
    return result;
}

static void uwp_repl_pool_write_le32(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static const char* uwp_repl_pool_state_name(repl_state_t state) {
    switch (state) {
        case REPL_STATE_DISCONNECTED: return "disconnected";
        case REPL_STATE_CONNECTING:   return "connecting";
        case REPL_STATE_STREAMING:    return "streaming";
        case REPL_STATE_SYNCING:      return "syncing";
        case REPL_STATE_ERROR:        return "error";
        default:                      return "unknown";
    }
}

static uwp_repl_result_t uwp_repl_pool_status(qihse_repl_context_t* repl_ctx,
                                               uint64_t requested_lsn,
                                               int include_requested_lsn,
                                               qihse_uwp_write_fn write_fn,
                                               void* write_ctx) {
    char reply[192];
    uint64_t last_lsn;
    uint64_t flush_lsn;
    repl_state_t state;
    int length;

    if (qihse_repl_get_status(repl_ctx, &last_lsn, &flush_lsn, &state) != 0)
        return UWP_REPL_ERR_FAILED;

    if (include_requested_lsn) {
        length = snprintf(reply, sizeof(reply),
                          "OK lsn=%" PRIu64 " last_lsn=%" PRIu64
                          " flush_lsn=%" PRIu64 " state=%s\n",
                          requested_lsn, last_lsn, flush_lsn,
                          uwp_repl_pool_state_name(state));
    } else {
        length = snprintf(reply, sizeof(reply),
                          "last_lsn=%" PRIu64 " flush_lsn=%" PRIu64
                          " state=%s\n",
                          last_lsn, flush_lsn, uwp_repl_pool_state_name(state));
    }
    if (length < 0 || (size_t)length >= sizeof(reply)) return UWP_REPL_ERR_FAILED;

    uwp_repl_pool_write_cb(write_fn, write_ctx, reply, (size_t)length);
    return UWP_REPL_OK;
}

uwp_repl_result_t uwp_dispatch_repl(qihse_uwp_context_t* ctx,
                                    uint8_t command_opcode,
                                    const uint8_t* payload, size_t payload_len,
                                    qihse_user_t* user, int client_fd,
                                    qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    uint64_t lsn;

    if (!user) return UWP_REPL_ERR_FAILED;
    if (!ctx || !ctx->repl_ctx) return UWP_REPL_ERR_NO_CTX;

    switch (command_opcode) {
        case 0x01: /* APPEND_WAL */
            if (!payload || payload_len == 0) return UWP_REPL_ERR_ARGS;
            if (qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR) return UWP_REPL_ERR_FAILED;
            lsn = ctx->wal
                ? qihse_wal_current_lsn((qihse_wal_t*)ctx->wal)
                : QIHSE_WAL_INVALID_LSN;
            if (qihse_repl_ship_wal(ctx->repl_ctx, payload, payload_len, lsn) != 0)
                return UWP_REPL_ERR_FAILED;
            uwp_repl_pool_write_cb(write_fn, write_ctx, "OK\n", 3);
            return UWP_REPL_OK;

        case 0x02: /* SHIP_WAL */
            if (!payload || payload_len != 8) return UWP_REPL_ERR_ARGS;
            return uwp_repl_pool_status(ctx->repl_ctx,
                                        uwp_repl_pool_read_le64(payload), 1,
                                        write_fn, write_ctx);

        case 0x03: /* SYNC_REPLICA */
            if (payload_len != 0) return UWP_REPL_ERR_ARGS;
            if (qihse_repl_start_streaming(ctx->repl_ctx) != 0)
                return UWP_REPL_ERR_FAILED;
            uwp_repl_pool_write_cb(write_fn, write_ctx, "OK\n", 3);
            return UWP_REPL_OK;

        case 0x04: /* STATUS */
            if (payload_len != 0) return UWP_REPL_ERR_ARGS;
            return uwp_repl_pool_status(ctx->repl_ctx, 0, 0,
                                        write_fn, write_ctx);

        default:
            return UWP_REPL_ERR_ARGS;
    }
}

uwp_repl_result_t uwp_dispatch_pool(qihse_uwp_context_t* ctx,
                                    uint8_t command_opcode,
                                    const uint8_t* payload, size_t payload_len,
                                    qihse_user_t* user, int client_fd,
                                    qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    char reply[96];
    uint8_t backend_reply[4];
    int backend_fd;
    int32_t requested_client_fd;
    int length;

    if (!user) return UWP_REPL_ERR_FAILED;
    if (!ctx || !ctx->pooler) return UWP_REPL_ERR_NO_CTX;

    switch (command_opcode) {
        case 0x01: /* ACQUIRE */
            if (!payload || payload_len != 4) return UWP_REPL_ERR_ARGS;
            requested_client_fd = (int32_t)uwp_repl_pool_read_le32(payload);
            if (qihse_pooler_acquire(ctx->pooler, requested_client_fd,
                                     &backend_fd) != 0)
                return UWP_REPL_ERR_FAILED;
            uwp_repl_pool_write_le32(backend_reply, (uint32_t)backend_fd);
            uwp_repl_pool_write_cb(write_fn, write_ctx, backend_reply,
                                   sizeof(backend_reply));
            return UWP_REPL_OK;

        case 0x02: /* RELEASE */
            if (!payload || payload_len != 4) return UWP_REPL_ERR_ARGS;
            requested_client_fd = (int32_t)uwp_repl_pool_read_le32(payload);
            if (qihse_pooler_release(ctx->pooler, requested_client_fd) != 0)
                return UWP_REPL_ERR_FAILED;
            uwp_repl_pool_write_cb(write_fn, write_ctx, "OK\n", 3);
            return UWP_REPL_OK;

        case 0x03: /* STATS */
            if (payload_len != 0) return UWP_REPL_ERR_ARGS;
            length = snprintf(reply, sizeof(reply), "active=%zu idle=%zu\n",
                              qihse_pooler_active_count(ctx->pooler),
                              qihse_pooler_idle_count(ctx->pooler));
            if (length < 0 || (size_t)length >= sizeof(reply))
                return UWP_REPL_ERR_FAILED;
            uwp_repl_pool_write_cb(write_fn, write_ctx, reply, (size_t)length);
            return UWP_REPL_OK;

        default:
            return UWP_REPL_ERR_ARGS;
    }
}
