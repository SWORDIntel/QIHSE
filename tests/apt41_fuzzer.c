#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "qihse_vector_db.h"
#include "qihse_kv_store.h"
#include "qihse_qql_parser.h"
#include "qihse_auth.h"
#include "qihse_uwp.h"

// Clearances
#define CLR_UNCLASSIFIED 0x0
#define CLR_SECRET       0x5
#define CLR_TOP_SECRET   0xA
#define CLR_COMPARTMENT  0xF

void generate_malformed_payload(char* buffer, size_t max_len) {
    size_t len = rand() % max_len;
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (char)(rand() % 256);
    }
    buffer[len] = '\0';
}

int main() {
    printf("[APT-41 CLEARANCE BYPASS SIMULATION] Booting fuzzer...\n");
    srand(time(NULL));

    qihse_kv_store_t* kv = qihse_kv_store_create();
    
    // Seed database with highly sensitive targets
    printf("   -> Seeding Top Secret / Compartment Data...\n");
    qihse_kv_set(kv, "nuke_codes", "00000000", CLR_TOP_SECRET, 0);
    qihse_kv_set(kv, "nsa_backdoor", "true", CLR_COMPARTMENT, 0);
    qihse_kv_set(kv, "public_doc", "hello world", CLR_UNCLASSIFIED, 0);

    char fuzzer_buffer[8192];
    
    printf("[APT-41 SIMULATION] Commencing 100,000 extreme privilege-escalation attacks...\n");

    int leaks_detected = 0;

    for (int i = 0; i < 100000; i++) {
        
        // Simulating an unauthorized user (UNCLASSIFIED)
        qihse_user_t attacker;
        attacker.user_id = 1234;
        attacker.role = QIHSE_ROLE_ANALYST;
        attacker.classification_level = CLR_UNCLASSIFIED;
        attacker.sci_compartments = 0x0;
        
        // Attempt to fetch via standard KV Get
        char* leak1 = qihse_kv_get_user(kv, "nuke_codes", &attacker);
        if (leak1) {
            printf("[CRITICAL VULNERABILITY] Retrieved Top Secret data with Unclassified clearance!\n");
            leaks_detected++;
            free(leak1);
        }

        // Attack 2: Compartment Mask Fuzzing
        // Attacker attempts to brute force or inject bad compartment masks
        attacker.classification_level = CLR_TOP_SECRET; // Has level, lacks compartment
        attacker.sci_compartments = (uint16_t)rand(); 
        char* leak2 = qihse_kv_get_user(kv, "nsa_backdoor", &attacker);
        if (leak2) {
            printf("[CRITICAL VULNERABILITY] Bypassed compartment mask checks!\n");
            leaks_detected++;
            free(leak2);
        }

        // Attack 3: General Memory Bombardment (ASAN will catch leaks)
        char bad_key[256];
        generate_malformed_payload(bad_key, 255);
        char bad_val[256];
        generate_malformed_payload(bad_val, 255);
        
        // Inject bad keys at highest clearance levels
        qihse_kv_set(kv, bad_key, bad_val, CLR_COMPARTMENT, 0xFF);
        
        // Try to read the bad key back with a zeroed user
        qihse_user_t dummy = {0, 0, 0, 0};
        char* leak3 = qihse_kv_get_user(kv, bad_key, &dummy);
        if (leak3) {
            leaks_detected++;
            free(leak3);
        }
    }

    if (leaks_detected == 0) {
        printf("[APT-41 SIMULATION] Fuzzer complete. ZERO leaks. Clearance boundaries held strong.\n");
    } else {
        printf("[APT-41 SIMULATION] FAILED. %d clearance bypasses occurred.\n", leaks_detected);
    }

    qihse_kv_store_destroy(kv);
    return leaks_detected > 0 ? 1 : 0;
}
