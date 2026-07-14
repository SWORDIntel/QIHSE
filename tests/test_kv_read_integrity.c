#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"

#define READ_ITERATIONS 512

int main(void) {
    qihse_kv_store_t* store = qihse_kv_store_create();
    if (store == NULL) {
        fprintf(stderr, "could not create KV store\n");
        return 1;
    }
    qihse_auth_init();
    qihse_user_t* user = qihse_auth_get_user(0);
    if (user == NULL) {
        fprintf(stderr, "could not obtain test user\n");
        qihse_kv_store_destroy(store);
        return 1;
    }
    if (!qihse_kv_set(store, "memory_record", "authoritative_value", 0, 0)) {
        fprintf(stderr, "could not write KV record\n");
        qihse_kv_store_destroy(store);
        return 1;
    }

    for (int iteration = 0; iteration < READ_ITERATIONS; ++iteration) {
        char* value = qihse_kv_get_user(store, "memory_record", user);
        if (value == NULL || strcmp(value, "authoritative_value") != 0) {
            fprintf(stderr, "read %d returned non-authoritative data\n", iteration);
            free(value);
            qihse_kv_store_destroy(store);
            return 1;
        }
        free(value);
    }

    qihse_kv_store_destroy(store);
    return 0;
}
