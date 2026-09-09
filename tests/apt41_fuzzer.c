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
#define SCI_RESTRICTED   0x0001u

#define ATTACKER_LOW_ID       41u
#define ATTACKER_NO_SCI_ID    42u
#define FUZZ_OPERATOR_PASSWORD "Apt41OperatorPass1!"
#define FUZZ_ATTACKER_PASSWORD "Apt41AttackerPass1!"
#define FUZZ_NO_SCI_PASSWORD   "Apt41NoSciPass1!"

void generate_malformed_payload(char* buffer, size_t max_len) {
    size_t len = rand() % max_len;
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (char)(rand() % 256);
    }
    buffer[len] = '\0';
}

int main() {
    printf("[APT-41 CLEARANCE BYPASS SIMULATION] Booting fuzzer...\n");
    srand((unsigned int)time(NULL));
    assert(qihse_auth_init());

    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    if (qihse_auth_is_operator_password_default()) {
        assert(qihse_auth_bootstrap_operator(FUZZ_OPERATOR_PASSWORD));
    }

    qihse_user_t* attacker_low = qihse_auth_create_user(
        op, ATTACKER_LOW_ID, QIHSE_ROLE_ANALYST,
        CLR_UNCLASSIFIED, 0, FUZZ_ATTACKER_PASSWORD, false);
    assert(attacker_low != NULL);

    /* High enough classification to isolate SCI enforcement: this principal
     * has TOP SECRET clearance but deliberately has no SCI compartments. */
    qihse_user_t* attacker_no_sci = qihse_auth_create_user(
        op, ATTACKER_NO_SCI_ID, QIHSE_ROLE_ANALYST,
        CLR_TOP_SECRET, 0, FUZZ_NO_SCI_PASSWORD, false);
    assert(attacker_no_sci != NULL);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    /* Seed real protected data through an authoritative privileged principal.
     * A security fuzzer must not report success merely because its classified
     * setup writes were rejected by the fail-closed legacy API. */
    printf("   -> Seeding Top Secret / Compartment Data...\n");
    assert(qihse_kv_set_user(kv, "nuke_codes", "00000000",
                             CLR_TOP_SECRET, 0, op));
    assert(qihse_kv_set_user(kv, "nsa_backdoor", "true",
                             CLR_TOP_SECRET, SCI_RESTRICTED, op));
    assert(qihse_kv_set(kv, "public_doc", "hello world",
                        CLR_UNCLASSIFIED, 0));

    /* Prove the protected fixtures actually exist before fuzzing denial paths. */
    char* seeded = qihse_kv_get_user(kv, "nuke_codes", op);
    assert(seeded != NULL && strcmp(seeded, "00000000") == 0);
    free(seeded);
    seeded = qihse_kv_get_user(kv, "nsa_backdoor", op);
    assert(seeded != NULL && strcmp(seeded, "true") == 0);
    free(seeded);

    printf("[APT-41 SIMULATION] Commencing 1,000 extreme privilege-escalation attacks...\n");

    int leaks_detected = 0;

    for (int i = 0; i < 1000; i++) {
        /* Attack 1: an authoritative UNCLASSIFIED analyst must never retrieve
         * the TOP SECRET fixture. */
        char* leak1 = qihse_kv_get_user(kv, "nuke_codes", attacker_low);
        if (leak1) {
            printf("[CRITICAL VULNERABILITY] Retrieved Top Secret data with Unclassified clearance!\n");
            leaks_detected++;
            free(leak1);
        }

        /* Attack 2: a TOP SECRET analyst without the required SCI bit must
         * still be denied, proving compartment enforcement independently of
         * the classification-level check. */
        char* leak2 = qihse_kv_get_user(kv, "nsa_backdoor", attacker_no_sci);
        if (leak2) {
            printf("[CRITICAL VULNERABILITY] Bypassed compartment mask checks!\n");
            leaks_detected++;
            free(leak2);
        }

        /* Attack 3: malformed-key/value bombardment. First verify that the
         * context-free classified mutation path itself stays fail-closed. */
        char bad_key[256];
        generate_malformed_payload(bad_key, 255);
        char bad_val[256];
        generate_malformed_payload(bad_val, 255);

        if (bad_key[0] != '\0') {
            if (qihse_kv_set(kv, bad_key, bad_val,
                             CLR_TOP_SECRET, SCI_RESTRICTED)) {
                printf("[CRITICAL VULNERABILITY] Context-free classified write succeeded!\n");
                leaks_detected++;
            }

            /* If an authorized seed of the malformed key is accepted, the
             * low-clearance principal must still be unable to disclose it. */
            if (qihse_kv_set_user(kv, bad_key, bad_val,
                                  CLR_TOP_SECRET, SCI_RESTRICTED, op)) {
                char* leak3 = qihse_kv_get_user(kv, bad_key, attacker_low);
                if (leak3) {
                    printf("[CRITICAL VULNERABILITY] Attack 3 bypassed bounds! Expected block, got leak.\n");
                    leaks_detected++;
                    free(leak3);
                }
            }
        }
    }

    if (leaks_detected == 0) {
        printf("[APT-41 SIMULATION] Fuzzer complete. ZERO leaks. Clearance boundaries held strong.\n");
    } else {
        printf("[APT-41 SIMULATION] FAILED. %d clearance bypasses occurred.\n", leaks_detected);
    }

    assert(qihse_auth_destroy_user(op, ATTACKER_NO_SCI_ID));
    assert(qihse_auth_destroy_user(op, ATTACKER_LOW_ID));
    qihse_kv_store_destroy(kv);
    return leaks_detected > 0 ? 1 : 0;
}
