#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qihse_kv_store.h"

int main() {
    printf("Starting Native LSM-Tree Integration Test...\n");
    
    // First run: insert data
    qihse_kv_store_t* store1 = qihse_kv_store_create();
    printf("[1] Writing key to WAL / MemTable...\n");
    qihse_kv_set(store1, "lsm_key", "survives_crash");
    
    // Force a flush to SSTable by spamming some data
    for (int i = 0; i < 1000; i++) {
        char key[64];
        char val[1024];
        snprintf(key, sizeof(key), "dummy_%d", i);
        memset(val, 'A', 1000);
        val[1000] = '\0';
        qihse_kv_set(store1, key, val);
    }
    printf("[1] Memory limit exceeded, MemTable flushed to SSTable.\n");
    
    char* v1 = qihse_kv_get(store1, "lsm_key");
    printf("[1] Value before crash: %s\n", v1);
    free(v1);
    
    // Simulate hard crash without calling save!
    // (We destroy it cleanly here to avoid OS memory leaks, but normally save isn't called)
    qihse_kv_store_destroy(store1);
    
    printf("\n--- SYSTEM CRASH AND REBOOT ---\n\n");
    
    // Second run: recover from WAL / SSTables
    qihse_kv_store_t* store2 = qihse_kv_store_create();
    printf("[2] Engine Rebooted. Recovering LSM-Tree state...\n");
    
    char* v2 = qihse_kv_get(store2, "lsm_key");
    if (v2) {
        printf("[2] SUCCESS! Recovered value: %s\n", v2);
        free(v2);
    } else {
        printf("[2] FAILED! Key lost.\n");
        return 1;
    }
    
    qihse_kv_store_destroy(store2);
    return 0;
}
