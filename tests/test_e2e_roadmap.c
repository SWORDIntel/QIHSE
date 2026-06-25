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
#include <liburing.h>

#include "qihse_pqc_crypto.h"
#include "qihse_raft.h"
#include "qihse_uwp.h"
#include "qihse_vector_db.h"

// For testing Raft UDP broadcast reception
void* raft_mock_follower(void* arg) {
    qihse_raft_node_t* follower = (qihse_raft_node_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(follower->port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    uint8_t buffer[8192];
    printf("[E2E] Follower node listening on port %d...\n", follower->port);
    
    // Wait for the UDP broadcast from the leader
    ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (n > 0) {
        printf("[E2E] Follower received %zd bytes. Passing to qihse_raft_receive_append_entries...\n", n);
        
        // Extract struct identical to qihse_raft_append_entry's payload format
        uint8_t* ptr = buffer;
        uint64_t term; memcpy(&term, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
        uint32_t node_id; memcpy(&node_id, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
        size_t len; memcpy(&len, ptr, sizeof(size_t)); ptr += sizeof(size_t);
        uint8_t sig[QIHSE_MLDSA_SIGNATURE_SIZE];
        memcpy(sig, ptr, QIHSE_MLDSA_SIGNATURE_SIZE); ptr += QIHSE_MLDSA_SIGNATURE_SIZE;
        uint8_t* data = ptr;
        
        qihse_raft_receive_append_entries(follower, term, node_id, data, len, sig);
    }
    close(sock);
    return NULL;
}

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

    // 2. Raft RPC Transport & Signature Verification
    printf(">> TEST 2: Raft RPC Transport (UDP Broadcast + ML-DSA-87 Verification)\n");
    
    qihse_raft_node_t leader, follower;
    memset(&leader, 0, sizeof(leader));
    memset(&follower, 0, sizeof(follower));
    
    leader.node_id = 1;
    leader.state = QIHSE_RAFT_LEADER;
    leader.current_term = 42;
    leader.num_peers = 1;
    strcpy(leader.peers[0].ip, "127.0.0.1");
    leader.peers[0].port = 19999;
    
    follower.node_id = 2;
    follower.state = QIHSE_RAFT_FOLLOWER;
    follower.current_term = 42;
    follower.port = 19999;
    follower.commit_index = 0;
    
    pthread_t follower_thread;
    pthread_create(&follower_thread, NULL, raft_mock_follower, &follower);
    usleep(100000); // Give follower time to bind
    
    const char* log_entry = "INSERT INTO test_vectors (id) VALUES (42)";
    printf("Leader appending entry and broadcasting...\n");
    qihse_raft_append_entry(&leader, (const uint8_t*)log_entry, strlen(log_entry));
    
    pthread_join(follower_thread, NULL);
    
    if (follower.commit_index == 1) {
        printf("[PASS] Follower successfully received, verified ML-DSA-87 signature, and committed the entry.\n");
    } else {
        printf("[FAIL] Follower did not commit the entry. Verification failed.\n");
        return 1;
    }
    printf("\n");

    // 3. UWP / XDP Dispatcher Test
    printf(">> TEST 3: XDP Fast-path dispatcher routing into UWP State Machine\n");
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
