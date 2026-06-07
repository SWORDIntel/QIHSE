#include "qihse_cluster.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

const uint8_t QIHSE_CLUSTER_MAGIC[QIHSE_CLUSTER_MAGIC_LEN] = {'Q','I','H','S','E'};

static memshadow_gossip_manager_t* g_cluster_manager = NULL;
static qihse_kv_store_t* g_kv = NULL;
static qihse_vector_db_t g_vdb = NULL;

bool qihse_cluster_init(const char* node_id, qihse_kv_store_t* kv, qihse_vector_db_t vdb) {
    g_kv = kv;
    g_vdb = vdb;
    
    int ret = memshadow_gossip_manager_init(&g_cluster_manager, node_id, 3, 1000);
    return (ret == 0);
}

bool qihse_cluster_join(const char* peer_ip, uint16_t peer_port) {
    if (!g_cluster_manager) return false;
    
    memshadow_gossip_peer_t peer;
    char peer_id[64];
    snprintf(peer_id, sizeof(peer_id), "%s:%u", peer_ip, peer_port);
    
    if (memshadow_gossip_peer_init(&peer, peer_id, peer_ip, peer_port) != 0) {
        return false;
    }
    
    if (memshadow_gossip_manager_add_peer(g_cluster_manager, peer) != 0) {
        memshadow_gossip_peer_cleanup(&peer);
        return false;
    }
    
    return true;
}

void qihse_cluster_broadcast_kv_set(const char* key, const char* value) {
    if (!g_cluster_manager) return;
    
    uint32_t key_len = (uint32_t)strlen(key);
    uint32_t val_len = (uint32_t)strlen(value);
    
    size_t payload_size = 5 + 1 + sizeof(uint32_t) + key_len + sizeof(uint32_t) + val_len;
    uint8_t* payload = (uint8_t*)malloc(payload_size);
    if (!payload) return;
    
    memcpy(payload, QIHSE_CLUSTER_MAGIC, 5);
    payload[5] = (uint8_t)QIHSE_PAYLOAD_KV_SET;
    
    size_t offset = 6;
    memcpy(payload + offset, &key_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(payload + offset, key, key_len);
    offset += key_len;
    
    memcpy(payload + offset, &val_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(payload + offset, value, val_len);
    
    memshadow_gossip_manager_broadcast_message(g_cluster_manager, GOSSIP_MSG_DATA_BROADCAST, payload, payload_size, 32);
    free(payload);
}

void qihse_cluster_broadcast_vec_set(uint64_t id, const float* vector, size_t dims) {
    if (!g_cluster_manager) return;
    
    uint32_t dim_u32 = (uint32_t)dims;
    size_t payload_size = 5 + 1 + sizeof(uint64_t) + sizeof(uint32_t) + dims * sizeof(float);
    uint8_t* payload = (uint8_t*)malloc(payload_size);
    if (!payload) return;
    
    memcpy(payload, QIHSE_CLUSTER_MAGIC, 5);
    payload[5] = (uint8_t)QIHSE_PAYLOAD_VEC_SET;
    
    size_t offset = 6;
    memcpy(payload + offset, &id, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(payload + offset, &dim_u32, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(payload + offset, vector, dims * sizeof(float));
    
    memshadow_gossip_manager_broadcast_message(g_cluster_manager, GOSSIP_MSG_DATA_BROADCAST, payload, payload_size, 32);
    free(payload);
}

void qihse_cluster_receive_payload(const uint8_t* payload, size_t payload_size) {
    if (payload_size < 6) return;
    
    if (memcmp(payload, QIHSE_CLUSTER_MAGIC, 5) != 0) {
        return;
    }
    
    qihse_cluster_payload_type_t type = (qihse_cluster_payload_type_t)payload[5];
    size_t offset = 6;
    
    if (type == QIHSE_PAYLOAD_KV_SET) {
        if (offset + sizeof(uint32_t) > payload_size) return;
        uint32_t key_len;
        memcpy(&key_len, payload + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        if (offset + key_len > payload_size) return;
        char* key = (char*)malloc(key_len + 1);
        if (!key) return;
        memcpy(key, payload + offset, key_len);
        key[key_len] = '\0';
        offset += key_len;
        
        if (offset + sizeof(uint32_t) > payload_size) { free(key); return; }
        uint32_t val_len;
        memcpy(&val_len, payload + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        if (offset + val_len > payload_size) { free(key); return; }
        char* value = (char*)malloc(val_len + 1);
        if (!value) { free(key); return; }
        memcpy(value, payload + offset, val_len);
        value[val_len] = '\0';
        
        if (g_kv) {
            qihse_kv_set(g_kv, key, value, 0, 0);
        }
        
        free(key);
        free(value);
    } else if (type == QIHSE_PAYLOAD_VEC_SET) {
        if (offset + sizeof(uint64_t) > payload_size) return;
        uint64_t id;
        memcpy(&id, payload + offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        
        if (offset + sizeof(uint32_t) > payload_size) return;
        uint32_t dim_u32;
        memcpy(&dim_u32, payload + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        size_t vec_bytes = dim_u32 * sizeof(float);
        if (offset + vec_bytes > payload_size) return;
        
        float* vector = (float*)malloc(vec_bytes);
        if (!vector) return;
        memcpy(vector, payload + offset, vec_bytes);
        
        if (g_vdb) {
            qihse_vector_db_add_vectors(g_vdb, vector, 1, dim_u32, &id, NULL, NULL);
        }
        
        free(vector);
    }
}
