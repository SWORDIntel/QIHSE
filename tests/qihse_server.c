#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "qihse_vector_db.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_pg_wire.h"

qihse_kv_store_t* global_kv;
qihse_vector_db_t global_vdb;

void* resp_server_thread(void* arg) {
    (void)arg;
    qihse_start_resp_server(global_kv, global_vdb, 6379, "0.0.0.0");
    return NULL;
}

void* pg_server_thread(void* arg) {
    (void)arg;
    qihse_start_pg_wire_server((void*)global_vdb, 5432, "0.0.0.0");
    return NULL;
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("======================================\n");
    printf("     QIHSE ENDGAME SERVER DAEMON      \n");
    printf("======================================\n");
    printf("[QIHSE SERVER] Initializing engines...\n");

    global_kv = qihse_kv_store_create();
    global_vdb = qihse_vector_db_create(QIHSE_BACKEND_CPU, NULL, NULL);

    if (!global_kv || !global_vdb) {
        fprintf(stderr, "Failed to initialize databases.\n");
        return 1;
    }

    pthread_t resp_t, pg_t;
    
    printf("[QIHSE SERVER] Spawning proxy threads...\n");
    
    if (pthread_create(&resp_t, NULL, resp_server_thread, NULL) != 0) {
        perror("Failed to start RESP server thread");
        return 1;
    }
    
    if (pthread_create(&pg_t, NULL, pg_server_thread, NULL) != 0) {
        perror("Failed to start PG server thread");
        return 1;
    }

    // Wait forever while servers run
    pthread_join(resp_t, NULL);
    pthread_join(pg_t, NULL);

    qihse_vector_db_destroy(global_vdb);
    qihse_kv_store_destroy(global_kv);
    return 0;
}
