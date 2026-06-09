#include "qihse_raft.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qihse_platform.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#define URING_QUEUE_DEPTH 256

bool qihse_raft_init(qihse_raft_node_t* node, uint32_t node_id, uint16_t port, qihse_kv_store_t* store, qihse_vector_db_t vdb) {
    if (!node) return false;
    memset(node, 0, sizeof(qihse_raft_node_t));
    
    node->node_id = node_id;
    node->state = QIHSE_RAFT_FOLLOWER;
    node->current_term = 0;
    node->voted_for = -1;
    node->commit_index = 0;
    node->last_applied = 0;
    node->port = port;
    node->store = store;
    node->vdb = vdb;
    node->running = false;
    node->last_heartbeat = time(NULL);
    
#ifndef _WIN32
    if (io_uring_queue_init(URING_QUEUE_DEPTH, &node->ring, 0) < 0) {
        perror("io_uring_queue_init");
        return false;
    }
#endif
    
    node->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (node->server_fd < 0) {
        perror("socket");
        return false;
    }
    
    int opt = 1;
#ifdef _WIN32
    setsockopt(node->server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(node->server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
#endif
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(node->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return false;
    }
    
    if (listen(node->server_fd, 128) < 0) {
        perror("listen");
        return false;
    }
    
    return true;
}

static void* raft_event_loop(void* arg) {
    qihse_raft_node_t* node = (qihse_raft_node_t*)arg;
#ifndef _WIN32
    struct io_uring* ring = &node->ring;
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Submit initial accept
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, node->server_fd, (struct sockaddr*)&client_addr, &client_len, 0);
    io_uring_sqe_set_data(sqe, (void*)1ULL); // Use 1 as ACCEPT token
    io_uring_submit(ring);
    
    printf("[QIHSE Raft] Node %u running io_uring event loop on port %u\n", node->node_id, node->port);
    
    // Setup election timeout (randomized 150ms - 300ms)
    struct io_uring_sqe* timer_sqe = io_uring_get_sqe(ring);
    struct __kernel_timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (150000000 + (rand() % 150000000)); // 150-300ms
    io_uring_prep_timeout(timer_sqe, &ts, 0, 0);
    io_uring_sqe_set_data(timer_sqe, (void*)2ULL); // 2 = TIMEOUT token
    io_uring_submit(ring);
    
    while (node->running) {
        struct io_uring_cqe* cqe;
        int ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            break;
        }
        
        uint64_t token = (uint64_t)io_uring_cqe_get_data(cqe);
        if (token == 1ULL) { // ACCEPT completed
            int client_fd = cqe->res;
            if (client_fd >= 0) {
                // Future: queue an io_uring_prep_recv here for the new client
                close(client_fd);
            }
            
            // Re-arm the accept
            sqe = io_uring_get_sqe(ring);
            io_uring_prep_accept(sqe, node->server_fd, (struct sockaddr*)&client_addr, &client_len, 0);
            io_uring_sqe_set_data(sqe, (void*)1ULL);
            io_uring_submit(ring);
        } else if (token == 2ULL) { // TIMEOUT completed (Election Timeout)
            (void)time(NULL); // suppress warning
            if (node->state == QIHSE_RAFT_FOLLOWER || node->state == QIHSE_RAFT_CANDIDATE) {
                // Transition to CANDIDATE
                node->state = QIHSE_RAFT_CANDIDATE;
                node->current_term++;
                node->voted_for = node->node_id;
                printf("[QIHSE Raft Node %u] Election Timeout! Transitioning to CANDIDATE for Term %lu\n", 
                       node->node_id, (unsigned long)node->current_term);
                
                // Broadcast RequestVote RPCs here...
            } else if (node->state == QIHSE_RAFT_LEADER) {
                // Broadcast periodic AppendEntries (Heartbeats)
                printf("[QIHSE Raft Node %u] Broadcasting Heartbeat for Term %lu\n", 
                       node->node_id, (unsigned long)node->current_term);
            }
            
            // Re-arm timer
            timer_sqe = io_uring_get_sqe(ring);
            ts.tv_nsec = (150000000 + (rand() % 150000000));
            io_uring_prep_timeout(timer_sqe, &ts, 0, 0);
            io_uring_sqe_set_data(timer_sqe, (void*)2ULL);
            io_uring_submit(ring);
        }
        
        io_uring_cqe_seen(ring, cqe);
    }
#else
    printf("[QIHSE Raft] Node %u running fallback event loop on port %u\n", node->node_id, node->port);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Fallback: poll with select to timeout for election
    while(node->running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(node->server_fd, &readfds);
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = (150000 + (rand() % 150000)); // 150-300ms
        
        int res = select(node->server_fd + 1, &readfds, NULL, NULL, &tv);
        if (res > 0 && FD_ISSET(node->server_fd, &readfds)) {
            SOCKET client = accept(node->server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (client != INVALID_SOCKET) {
                closesocket(client);
            }
        } else if (res == 0) {
            // Timeout
            if (node->state == QIHSE_RAFT_FOLLOWER || node->state == QIHSE_RAFT_CANDIDATE) {
                node->state = QIHSE_RAFT_CANDIDATE;
                node->current_term++;
                node->voted_for = node->node_id;
                printf("[QIHSE Raft Node %u] Election Timeout! Transitioning to CANDIDATE for Term %lu\n", 
                       node->node_id, (unsigned long)node->current_term);
            } else if (node->state == QIHSE_RAFT_LEADER) {
                printf("[QIHSE Raft Node %u] Broadcasting Heartbeat for Term %lu\n", 
                       node->node_id, (unsigned long)node->current_term);
            }
        }
    }
#endif
    return NULL;
}

void qihse_raft_start(qihse_raft_node_t* node) {
    if (!node || node->running) return;
    node->running = true;
    
    pthread_t tid;
    pthread_create(&tid, NULL, raft_event_loop, node);
    pthread_detach(tid);
}

void qihse_raft_stop(qihse_raft_node_t* node) {
    if (node) {
        node->running = false;
        close(node->server_fd);
#ifndef _WIN32
        io_uring_queue_exit(&node->ring);
#endif
    }
}

bool qihse_raft_append_entry(qihse_raft_node_t* node, const uint8_t* data, size_t len) {
    (void)data;
    if (!node || node->state != QIHSE_RAFT_LEADER) {
        return false; // Can only append if LEADER
    }
    
    // (Skeleton) Here we would:
    // 1. Append to local Write-Ahead Log
    printf("[QIHSE Raft Node %u] Appending %zu bytes to WAL\n", node->node_id, len);
    
    // 2. Broadcast AppendEntries RPC via io_uring to all known peers
    // (Skeleton implementation of the broadcast mechanic)
    
    // 3. Wait for majority acknowledgement before applying to local KV/VectorDB
    node->commit_index++;
    node->last_applied = node->commit_index;
    
    return true;
}

void qihse_raft_receive_append_entries(qihse_raft_node_t* node, uint64_t leader_term, uint32_t leader_id) {
    if (!node) return;
    
    if (leader_term >= node->current_term) {
        node->current_term = leader_term;
        node->state = QIHSE_RAFT_FOLLOWER;
        node->voted_for = leader_id;
        node->last_heartbeat = time(NULL); // Reset election timeout
        printf("[QIHSE Raft Node %u] Received AppendEntries from Leader %u. Stepping down to Follower.\n", 
               node->node_id, leader_id);
    }
}
