/* ============================================================================
 * QIHSE DISTRIBUTED COHERENCE PROTOCOLS TEST SUITE
 * ============================================================================
 *
 * Comprehensive tests for distributed systems functionality:
 * - Message queue operations
 * - Distributed state management
 * - Failure detection and recovery
 * - Leadership election
 * - Cluster coherence verification
 * ============================================================================ */

#include "../include/qihse_distributed.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

/* Test message queue functionality */
static void test_message_queue(void) {
    printf("Testing message queue...\n");

    qihse_message_queue_t queue;
    int ret = qihse_message_queue_init(&queue);
    assert(ret == 0);

    /* Test enqueue/dequeue */
    qihse_distributed_message_t msg = {
        .sender_id = 1,
        .receiver_id = 2,
        .type = QIHSE_MSG_HEARTBEAT,
        .sequence_number = 42,
        .timestamp = 1234567890ULL,
        .payload_size = 4,
        .payload = NULL,
        .checksum = 0
    };

    uint32_t payload_data = 0xDEADBEEF;
    msg.payload = &payload_data;

    /* Enqueue message */
    ret = qihse_message_queue_enqueue(&queue, &msg);
    assert(ret == 0);

    /* Dequeue message */
    qihse_distributed_message_t dequeued_msg;
    ret = qihse_message_queue_dequeue(&queue, &dequeued_msg, 0);
    assert(ret == 0);

    /* Verify message contents */
    assert(dequeued_msg.sender_id == msg.sender_id);
    assert(dequeued_msg.receiver_id == msg.receiver_id);
    assert(dequeued_msg.type == msg.type);
    assert(dequeued_msg.sequence_number == msg.sequence_number);
    assert(dequeued_msg.timestamp == msg.timestamp);
    assert(dequeued_msg.payload_size == msg.payload_size);
    assert(*(uint32_t*)dequeued_msg.payload == payload_data);

    /* Free dequeued payload */
    free(dequeued_msg.payload);

    /* Test queue statistics */
    uint32_t queue_size, max_queue_size;
    ret = qihse_message_queue_get_stats(&queue, &queue_size, &max_queue_size);
    assert(ret == 0);
    assert(queue_size == 0);
    assert(max_queue_size == QIHSE_MESSAGE_QUEUE_SIZE);

    /* Cleanup */
    qihse_message_queue_destroy(&queue);

    printf("  Message queue test passed!\n");
}

/* Test distributed manager initialization */
static void test_distributed_init(void) {
    printf("Testing distributed manager initialization...\n");

    qihse_distributed_manager_t manager;

    /* Test initialization */
    int ret = qihse_distributed_init(&manager, 1, "127.0.0.1", 8080, NULL);
    assert(ret == 0);

    /* Verify initialization */
    assert(manager.local_node_id == 1);
    assert(manager.cluster_state.num_nodes == 1);
    assert(manager.cluster_state.nodes[0].node_id == 1);
    assert(strcmp(manager.cluster_state.nodes[0].hostname, "127.0.0.1") == 0);
    assert(manager.cluster_state.nodes[0].port == 8080);
    assert(manager.cluster_state.nodes[0].state == QIHSE_NODE_DISCONNECTED);

    /* Test coherence check */
    double coherence_score;
    ret = qihse_distributed_check_coherence(&manager, &coherence_score);
    assert(ret == 0);
    assert(coherence_score >= 0.0 && coherence_score <= 1.0);

    /* Test statistics */
    uint32_t num_nodes, leader_id;
    double avg_latency;
    ret = qihse_distributed_get_stats(&manager, &num_nodes, &leader_id, &avg_latency);
    assert(ret == 0);
    assert(num_nodes == 1);
    assert(leader_id == 0);

    /* Cleanup */
    qihse_distributed_destroy(&manager);

    printf("  Distributed manager initialization test passed!\n");
}

/* Test message sending and receiving */
static void test_message_passing(void) {
    printf("Testing message passing...\n");

    qihse_distributed_manager_t manager;

    /* Initialize manager */
    int ret = qihse_distributed_init(&manager, 1, "127.0.0.1", 8081, NULL);
    assert(ret == 0);

    /* Create test message */
    qihse_distributed_message_t msg = {
        .sender_id = 1,
        .receiver_id = 2,
        .type = QIHSE_MSG_STATE_UPDATE,
        .sequence_number = 1,
        .timestamp = 1234567890ULL,
        .payload_size = sizeof(uint32_t),
        .payload = NULL,
        .checksum = 0
    };

    uint32_t test_data = 42;
    msg.payload = &test_data;

    /* Test broadcast (will fail gracefully since no other nodes) */
    ret = qihse_distributed_broadcast_message(&manager, &msg);
    /* We expect this to succeed even with no recipients */
    assert(ret == 0);

    /* Test send to non-existent node */
    ret = qihse_distributed_send_message(&manager, 999, &msg);
    assert(ret != 0); /* Should fail */

    /* Cleanup */
    qihse_distributed_destroy(&manager);

    printf("  Message passing test passed!\n");
}

/* Test failure handling */
static void test_failure_handling(void) {
    printf("Testing failure handling...\n");

    qihse_distributed_manager_t manager;

    /* Initialize manager */
    int ret = qihse_distributed_init(&manager, 1, "127.0.0.1", 8082, NULL);
    assert(ret == 0);

    /* Add a test node */
    manager.cluster_state.nodes[1].node_id = 2;
    strcpy(manager.cluster_state.nodes[1].hostname, "127.0.0.1");
    manager.cluster_state.nodes[1].port = 8083;
    manager.cluster_state.nodes[1].state = QIHSE_NODE_CONNECTED;
    manager.cluster_state.nodes[1].last_heartbeat = 0; /* Very old heartbeat */
    manager.cluster_state.num_nodes = 2;

    /* Test failure handling */
    ret = qihse_distributed_handle_failure(&manager, 2);
    assert(ret == 0);

    /* Verify node marked as disconnected */
    assert(manager.cluster_state.nodes[1].state == QIHSE_NODE_DISCONNECTED);

    /* Cleanup */
    qihse_distributed_destroy(&manager);

    printf("  Failure handling test passed!\n");
}

/* Test state synchronization */
static void test_state_sync(void) {
    printf("Testing state synchronization...\n");

    qihse_distributed_manager_t manager;

    /* Initialize manager */
    int ret = qihse_distributed_init(&manager, 1, "127.0.0.1", 8083, NULL);
    assert(ret == 0);

    /* Set up cluster state */
    manager.cluster_state.leader_id = 1; /* Local node is leader */

    /* Test state sync (will fail gracefully since no network) */
    ret = qihse_distributed_sync_state(&manager, 1000);
    /* We expect this to fail due to no network connection */
    assert(ret != 0);

    /* Verify last sync time was set */
    assert(manager.last_state_sync > 0);

    /* Cleanup */
    qihse_distributed_destroy(&manager);

    printf("  State synchronization test passed!\n");
}

/* Main test runner */
int main(int argc, char** argv) {
    printf("Running QIHSE Distributed Coherence Test Suite...\n\n");

    test_message_queue();
    printf("\n");

    test_distributed_init();
    printf("\n");

    test_message_passing();
    printf("\n");

    test_failure_handling();
    printf("\n");

    test_state_sync();
    printf("\n");

    printf("All QIHSE Distributed Coherence tests passed!\n");
    return 0;
}
