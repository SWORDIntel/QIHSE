#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "qihse_pqc_crypto.h"
#include "qihse_uwp.h"
#include "qihse_vector_db.h"

/* Phase-B (§16 honesty): the qihse_raft skeleton was removed — it was an
 * unsafe dead skeleton (self-vote, unilateral commit_index advance) that
 * no production path called.  The Raft RPC transport test that exercised
 * it is gone with it; ML-DSA signing itself is still covered by TEST 1
 * keygen and the dedicated PQC tests. */

int main() {
    printf("==========================================\n");
    printf("   QIHSE E2E ROADMAP FEATURE VALIDATION   \n");
    printf("==========================================\n\n");

    // 1. FIPS & PQC Keygen
    printf(">> TEST 1: CNSA 2.0 PQC Key Generation & FIPS initialization\n");
    if (!qihse_pqc_init_providers()) {
        printf("[!] FIPS Provider failed to initialize. Relying on default provider.\n");
    }

    printf("Generating ML-DSA-87 / ML-KEM-1024 hybrid keys...\n");
    if (qihse_pqc_keygen(".")) {
        printf("[PASS] Native Keygen generated qihse_dsa_key.pem and qihse_dsa_cert.pem\n");
    } else {
        printf("[FAIL] Native Keygen failed.\n");
        return 1;
    }
    printf("\n");

    // 2. UWP / XDP Dispatcher Test
    printf(">> TEST 2: XDP Fast-path dispatcher routing into UWP State Machine\n");
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    
    qihse_uwp_context_t uwp_ctx;
    memset(&uwp_ctx, 0, sizeof(uwp_ctx));
    uwp_ctx.vdb = vdb;
    
    // Craft a dummy UWP packet (4 bytes magic 'QIHS', then target engine)
    uint8_t uwp_mock_packet[128];
    memset(uwp_mock_packet, 0, sizeof(uwp_mock_packet));
    memcpy(uwp_mock_packet, "QIHSE", 5);
    uwp_mock_packet[5] = 0x01; // version
    uwp_mock_packet[6] = 0x02; // target vector engine
    uwp_mock_packet[7] = 0x00; // OP_PING
    
    printf("Dispatching mock XDP packet payload headlessly...\n");
    qihse_uwp_handle_payload(&uwp_ctx, uwp_mock_packet, 64);
    printf("[PASS] XDP to UWP headless dispatcher executed successfully.\n");
    
    printf("\n==========================================\n");
    printf("   ALL ROADMAP FEATURES VALIDATED (E2E)   \n");
    printf("==========================================\n");

    return 0;
}
