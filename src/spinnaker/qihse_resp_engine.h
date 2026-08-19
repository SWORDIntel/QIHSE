#ifndef QIHSE_RESP_ENGINE_H
#define QIHSE_RESP_ENGINE_H

#include <stdbool.h>
#include <stdint.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"

bool qihse_resp_engine_handle_legacy(int client_fd, qihse_kv_store_t* store, qihse_vector_db_t vdb);
bool qihse_resp_engine_run_legacy(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address);

#endif
