#include "qihse_resp_cluster.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t* data;
    size_t len;
    size_t capacity;
} qihse_resp_buffer_t;

typedef struct {
    uint16_t owner;
    uint16_t peer;
    qihse_cluster_slot_state_t state;
} qihse_resp_slot_snapshot_t;

typedef enum {
    QIHSE_RESP_SNAPSHOT_OK = 0,
    QIHSE_RESP_SNAPSHOT_OOM = 1,
    QIHSE_RESP_SNAPSHOT_INVALID = 2
} qihse_resp_snapshot_status_t;

typedef enum {
    QIHSE_RESP_SLOT_LIST_OK = 0,
    QIHSE_RESP_SLOT_LIST_INVALID = 1,
    QIHSE_RESP_SLOT_LIST_DUPLICATE = 2,
    QIHSE_RESP_SLOT_LIST_OOM = 3
} qihse_resp_slot_list_status_t;

static size_t qihse_resp_bounded_strlen(const char* value, size_t capacity) {
    size_t len = 0;
    while (len < capacity && value[len] != '\0') len++;
    return len;
}

static bool qihse_resp_size_multiply(size_t left, size_t right, size_t* result) {
    if (left != 0 && right > SIZE_MAX / left) return false;
    *result = left * right;
    return true;
}

static bool qihse_resp_buffer_reserve(qihse_resp_buffer_t* buffer, size_t additional) {
    if (additional > SIZE_MAX - buffer->len) return false;
    size_t needed = buffer->len + additional;
    if (needed <= buffer->capacity) return true;
    size_t capacity = buffer->capacity == 0 ? 256u : buffer->capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2u) {
            capacity = needed;
            break;
        }
        capacity *= 2u;
    }
    uint8_t* data = (uint8_t*)realloc(buffer->data, capacity);
    if (!data) return false;
    buffer->data = data;
    buffer->capacity = capacity;
    return true;
}

static bool qihse_resp_buffer_append(qihse_resp_buffer_t* buffer, const void* data, size_t len) {
    if (len == 0) return true;
    if (!data || !qihse_resp_buffer_reserve(buffer, len)) return false;
    memcpy(buffer->data + buffer->len, data, len);
    buffer->len += len;
    return true;
}

static bool qihse_resp_buffer_append_char(qihse_resp_buffer_t* buffer, char value) {
    return qihse_resp_buffer_append(buffer, &value, 1u);
}

static bool qihse_resp_buffer_append_string(qihse_resp_buffer_t* buffer, const char* value) {
    return qihse_resp_buffer_append(buffer, value, strlen(value));
}

static bool qihse_resp_buffer_append_size(qihse_resp_buffer_t* buffer, size_t value) {
    char digits[sizeof(size_t) * 3u + 1u];
    size_t position = sizeof(digits);
    do {
        digits[--position] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0);
    return qihse_resp_buffer_append(buffer, digits + position, sizeof(digits) - position);
}

static bool qihse_resp_buffer_append_u64(qihse_resp_buffer_t* buffer, uint64_t value) {
    char digits[32];
    size_t position = sizeof(digits);
    do {
        digits[--position] = (char)('0' + (value % UINT64_C(10)));
        value /= UINT64_C(10);
    } while (value != 0);
    return qihse_resp_buffer_append(buffer, digits + position, sizeof(digits) - position);
}

static bool qihse_resp_buffer_append_array_header(qihse_resp_buffer_t* buffer, size_t count) {
    return qihse_resp_buffer_append_char(buffer, '*') &&
           qihse_resp_buffer_append_size(buffer, count) &&
           qihse_resp_buffer_append_string(buffer, "\r\n");
}

static bool qihse_resp_buffer_append_integer(qihse_resp_buffer_t* buffer, uint64_t value) {
    return qihse_resp_buffer_append_char(buffer, ':') &&
           qihse_resp_buffer_append_u64(buffer, value) &&
           qihse_resp_buffer_append_string(buffer, "\r\n");
}

static bool qihse_resp_buffer_append_bulk(qihse_resp_buffer_t* buffer, const void* data, size_t len) {
    return qihse_resp_buffer_append_char(buffer, '$') &&
           qihse_resp_buffer_append_size(buffer, len) &&
           qihse_resp_buffer_append_string(buffer, "\r\n") &&
           qihse_resp_buffer_append(buffer, data, len) &&
           qihse_resp_buffer_append_string(buffer, "\r\n");
}

static void qihse_resp_buffer_destroy(qihse_resp_buffer_t* buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
    buffer->capacity = 0;
}

static bool qihse_resp_emit(qihse_resp_cluster_context_t* context, const void* data, size_t len) {
    return context->output(context->output_context, data, len);
}

static bool qihse_resp_emit_string(qihse_resp_cluster_context_t* context, const char* value) {
    return qihse_resp_emit(context, value, strlen(value));
}

static bool qihse_resp_emit_buffer(qihse_resp_cluster_context_t* context, qihse_resp_buffer_t* buffer) {
    bool result = qihse_resp_emit(context, buffer->data, buffer->len);
    qihse_resp_buffer_destroy(buffer);
    return result;
}

static bool qihse_resp_reply_oom(qihse_resp_cluster_context_t* context) {
    return qihse_resp_emit_string(context, "-ERR out of memory\r\n");
}

static bool qihse_resp_reply_topology_error(qihse_resp_cluster_context_t* context) {
    return qihse_resp_emit_string(context, "-ERR cluster topology unavailable\r\n");
}

static bool qihse_resp_emit_bulk_buffer(qihse_resp_cluster_context_t* context, qihse_resp_buffer_t* payload) {
    qihse_resp_buffer_t response = {0};
    bool built = qihse_resp_buffer_append_bulk(&response, payload->data, payload->len);
    qihse_resp_buffer_destroy(payload);
    if (!built) {
        qihse_resp_buffer_destroy(&response);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_buffer(context, &response);
}

static uint8_t qihse_resp_ascii_lower(uint8_t value) {
    if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') return (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
    return value;
}

static bool qihse_resp_arg_equals(const qihse_resp_arg_t* arg, const char* expected) {
    size_t expected_len = strlen(expected);
    if (!arg || arg->len != expected_len || (!arg->data && arg->len != 0)) return false;
    for (size_t i = 0; i < expected_len; i++) {
        if (qihse_resp_ascii_lower(arg->data[i]) != qihse_resp_ascii_lower((uint8_t)expected[i])) return false;
    }
    return true;
}

static bool qihse_resp_parse_unsigned(const qihse_resp_arg_t* arg, uint64_t minimum, uint64_t maximum, uint64_t* result) {
    if (!arg || !result || arg->len == 0 || !arg->data) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < arg->len; i++) {
        uint8_t byte = arg->data[i];
        if (byte < (uint8_t)'0' || byte > (uint8_t)'9') return false;
        uint64_t digit = (uint64_t)(byte - (uint8_t)'0');
        if (value > (maximum - digit) / UINT64_C(10)) return false;
        value = value * UINT64_C(10) + digit;
    }
    if (value < minimum || value > maximum) return false;
    *result = value;
    return true;
}

static bool qihse_resp_node_id_valid_bytes(const uint8_t* data, size_t len) {
    if (!data || len != QIHSE_CLUSTER_NODE_ID_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        if (!((byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
              (byte >= (uint8_t)'a' && byte <= (uint8_t)'f'))) return false;
    }
    return true;
}

static bool qihse_resp_arg_node_id(const qihse_resp_arg_t* arg, char out_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u]) {
    if (!arg || !qihse_resp_node_id_valid_bytes(arg->data, arg->len)) return false;
    memcpy(out_id, arg->data, QIHSE_CLUSTER_NODE_ID_LEN);
    out_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    return true;
}

static bool qihse_resp_node_valid(const qihse_cluster_node_t* node, uint16_t expected_index) {
    size_t id_len = qihse_resp_bounded_strlen(node->id, sizeof(node->id));
    size_t host_len = qihse_resp_bounded_strlen(node->host, sizeof(node->host));
    if (node->index != expected_index || id_len != QIHSE_CLUSTER_NODE_ID_LEN ||
        !qihse_resp_node_id_valid_bytes((const uint8_t*)node->id, id_len) ||
        host_len == 0 || host_len > QIHSE_CLUSTER_HOST_LEN || node->port == 0) return false;
    return node->role == QIHSE_CLUSTER_NODE_PRIMARY || node->role == QIHSE_CLUSTER_NODE_REPLICA;
}

static qihse_resp_snapshot_status_t qihse_resp_snapshot_nodes(const qihse_cluster_topology_t* topology, qihse_cluster_node_t** out_nodes, size_t* out_count) {
    size_t capacity = qihse_cluster_topology_nodes(topology, NULL, 0);
    *out_nodes = NULL;
    *out_count = 0;
    for (;;) {
        if (capacity > QIHSE_CLUSTER_MAX_NODES) return QIHSE_RESP_SNAPSHOT_INVALID;
        if (capacity == 0) return QIHSE_RESP_SNAPSHOT_OK;
        size_t bytes;
        if (!qihse_resp_size_multiply(capacity, sizeof(qihse_cluster_node_t), &bytes)) return QIHSE_RESP_SNAPSHOT_OOM;
        qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(bytes);
        if (!nodes) return QIHSE_RESP_SNAPSHOT_OOM;
        size_t count = qihse_cluster_topology_nodes(topology, nodes, capacity);
        if (count <= capacity) {
            for (size_t i = 0; i < count; i++) {
                if (!qihse_resp_node_valid(&nodes[i], (uint16_t)i)) {
                    free(nodes);
                    return QIHSE_RESP_SNAPSHOT_INVALID;
                }
            }
            *out_nodes = nodes;
            *out_count = count;
            return QIHSE_RESP_SNAPSHOT_OK;
        }
        free(nodes);
        capacity = count;
    }
}

static qihse_resp_snapshot_status_t qihse_resp_snapshot_slots(const qihse_cluster_topology_t* topology, qihse_resp_slot_snapshot_t** out_slots) {
    size_t bytes;
    *out_slots = NULL;
    if (!qihse_resp_size_multiply((size_t)QIHSE_CLUSTER_SLOT_COUNT, sizeof(qihse_resp_slot_snapshot_t), &bytes)) {
        return QIHSE_RESP_SNAPSHOT_OOM;
    }
    qihse_resp_slot_snapshot_t* slots = (qihse_resp_slot_snapshot_t*)malloc(bytes);
    if (!slots) return QIHSE_RESP_SNAPSHOT_OOM;
    for (size_t i = 0; i < QIHSE_CLUSTER_SLOT_COUNT; i++) {
        if (!qihse_cluster_topology_get_slot(topology, (uint16_t)i, &slots[i].owner, &slots[i].state, &slots[i].peer) ||
            (slots[i].state != QIHSE_CLUSTER_SLOT_STABLE &&
             slots[i].state != QIHSE_CLUSTER_SLOT_MIGRATING &&
             slots[i].state != QIHSE_CLUSTER_SLOT_IMPORTING)) {
            free(slots);
            return QIHSE_RESP_SNAPSHOT_INVALID;
        }
    }
    *out_slots = slots;
    return QIHSE_RESP_SNAPSHOT_OK;
}

static const qihse_cluster_node_t* qihse_resp_node_at(const qihse_cluster_node_t* nodes, size_t count, uint16_t index) {
    if (index == QIHSE_CLUSTER_NODE_NONE || (size_t)index >= count) return NULL;
    return &nodes[index];
}

static bool qihse_resp_handle_snapshot_error(qihse_resp_cluster_context_t* context, qihse_resp_snapshot_status_t status) {
    if (status == QIHSE_RESP_SNAPSHOT_OOM) return qihse_resp_reply_oom(context);
    return qihse_resp_reply_topology_error(context);
}

static bool qihse_resp_handle_slots(qihse_resp_cluster_context_t* context, size_t argc) {
    if (argc != 2) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    qihse_cluster_node_t* nodes = NULL;
    qihse_resp_slot_snapshot_t* slots = NULL;
    size_t node_count = 0;
    qihse_resp_snapshot_status_t status = qihse_resp_snapshot_nodes(context->topology, &nodes, &node_count);
    if (status != QIHSE_RESP_SNAPSHOT_OK) return qihse_resp_handle_snapshot_error(context, status);
    status = qihse_resp_snapshot_slots(context->topology, &slots);
    if (status != QIHSE_RESP_SNAPSHOT_OK) {
        free(nodes);
        return qihse_resp_handle_snapshot_error(context, status);
    }
    size_t range_count = 0;
    size_t slot = 0;
    while (slot < QIHSE_CLUSTER_SLOT_COUNT) {
        uint16_t owner = slots[slot].owner;
        if (owner == QIHSE_CLUSTER_NODE_NONE) {
            slot++;
            continue;
        }
        if (!qihse_resp_node_at(nodes, node_count, owner)) {
            free(slots);
            free(nodes);
            return qihse_resp_reply_topology_error(context);
        }
        do {
            slot++;
        } while (slot < QIHSE_CLUSTER_SLOT_COUNT && slots[slot].owner == owner);
        range_count++;
    }
    qihse_resp_buffer_t response = {0};
    bool built = qihse_resp_buffer_append_array_header(&response, range_count);
    slot = 0;
    while (built && slot < QIHSE_CLUSTER_SLOT_COUNT) {
        uint16_t owner = slots[slot].owner;
        if (owner == QIHSE_CLUSTER_NODE_NONE) {
            slot++;
            continue;
        }
        size_t start = slot;
        do {
            slot++;
        } while (slot < QIHSE_CLUSTER_SLOT_COUNT && slots[slot].owner == owner);
        size_t end = slot - 1u;
        const qihse_cluster_node_t* node = qihse_resp_node_at(nodes, node_count, owner);
        size_t host_len = qihse_resp_bounded_strlen(node->host, sizeof(node->host));
        built = qihse_resp_buffer_append_array_header(&response, 3u) &&
                qihse_resp_buffer_append_integer(&response, (uint64_t)start) &&
                qihse_resp_buffer_append_integer(&response, (uint64_t)end) &&
                qihse_resp_buffer_append_array_header(&response, 3u) &&
                qihse_resp_buffer_append_bulk(&response, node->host, host_len) &&
                qihse_resp_buffer_append_integer(&response, node->port) &&
                qihse_resp_buffer_append_bulk(&response, node->id, QIHSE_CLUSTER_NODE_ID_LEN);
    }
    free(slots);
    free(nodes);
    if (!built) {
        qihse_resp_buffer_destroy(&response);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_buffer(context, &response);
}

static bool qihse_resp_endpoint_safe_byte(uint8_t byte, bool ipv6) {
    if ((byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
        (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
        (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
        byte == (uint8_t)'.' || byte == (uint8_t)'_' || byte == (uint8_t)'-' || byte == (uint8_t)'~') return true;
    return ipv6 && byte == (uint8_t)':';
}

static bool qihse_resp_buffer_append_endpoint_host(qihse_resp_buffer_t* buffer, const char* host, size_t host_len) {
    const uint8_t* bytes = (const uint8_t*)host;
    size_t start = 0;
    size_t end = host_len;
    if (host_len >= 2u && bytes[0] == (uint8_t)'[' && bytes[host_len - 1u] == (uint8_t)']') {
        start = 1u;
        end--;
    }
    bool ipv6 = false;
    for (size_t i = start; i < end; i++) {
        if (bytes[i] == (uint8_t)':') {
            ipv6 = true;
            break;
        }
    }
    if (ipv6 && !qihse_resp_buffer_append_char(buffer, '[')) return false;
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = start; i < end; i++) {
        uint8_t byte = bytes[i];
        if (qihse_resp_endpoint_safe_byte(byte, ipv6)) {
            if (!qihse_resp_buffer_append(buffer, &byte, 1u)) return false;
        } else {
            char encoded[3];
            encoded[0] = '%';
            encoded[1] = hex[byte >> 4];
            encoded[2] = hex[byte & 0x0fu];
            if (!qihse_resp_buffer_append(buffer, encoded, sizeof(encoded))) return false;
        }
    }
    return !ipv6 || qihse_resp_buffer_append_char(buffer, ']');
}

static bool qihse_resp_buffer_append_node_endpoint(qihse_resp_buffer_t* buffer, const qihse_cluster_node_t* node) {
    size_t host_len = qihse_resp_bounded_strlen(node->host, sizeof(node->host));
    return qihse_resp_buffer_append_endpoint_host(buffer, node->host, host_len) &&
           qihse_resp_buffer_append_char(buffer, ':') &&
           qihse_resp_buffer_append_u64(buffer, node->port) &&
           qihse_resp_buffer_append_char(buffer, '@') &&
           qihse_resp_buffer_append_u64(buffer, node->bus_port);
}

static bool qihse_resp_buffer_append_node_ranges(qihse_resp_buffer_t* payload, uint16_t node_index, const qihse_resp_slot_snapshot_t* slots) {
    size_t slot = 0;
    while (slot < QIHSE_CLUSTER_SLOT_COUNT) {
        if (slots[slot].owner != node_index) {
            slot++;
            continue;
        }
        size_t start = slot;
        do {
            slot++;
        } while (slot < QIHSE_CLUSTER_SLOT_COUNT && slots[slot].owner == node_index);
        size_t end = slot - 1u;
        if (!qihse_resp_buffer_append_char(payload, ' ') || !qihse_resp_buffer_append_size(payload, start)) return false;
        if (end != start &&
            (!qihse_resp_buffer_append_char(payload, '-') || !qihse_resp_buffer_append_size(payload, end))) return false;
    }
    return true;
}

static bool qihse_resp_buffer_append_node_transitions(qihse_resp_buffer_t* payload, uint16_t node_index,
                                                        const qihse_cluster_node_t* nodes, size_t node_count,
                                                        const qihse_resp_slot_snapshot_t* slots) {
    for (size_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; slot++) {
        const qihse_cluster_node_t* peer;
        const char* arrow;
        if (slots[slot].state == QIHSE_CLUSTER_SLOT_MIGRATING && slots[slot].owner == node_index) {
            peer = qihse_resp_node_at(nodes, node_count, slots[slot].peer);
            arrow = "->-";
        } else if (slots[slot].state == QIHSE_CLUSTER_SLOT_IMPORTING && slots[slot].peer == node_index) {
            peer = qihse_resp_node_at(nodes, node_count, slots[slot].owner);
            arrow = "-<-";
        } else {
            continue;
        }
        if (!peer || !qihse_resp_buffer_append_string(payload, " [") ||
            !qihse_resp_buffer_append_size(payload, slot) ||
            !qihse_resp_buffer_append_string(payload, arrow) ||
            !qihse_resp_buffer_append(payload, peer->id, QIHSE_CLUSTER_NODE_ID_LEN) ||
            !qihse_resp_buffer_append_char(payload, ']')) return false;
    }
    return true;
}

static bool qihse_resp_handle_nodes(qihse_resp_cluster_context_t* context, size_t argc) {
    if (argc != 2) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    qihse_cluster_node_t* nodes = NULL;
    qihse_resp_slot_snapshot_t* slots = NULL;
    size_t node_count = 0;
    qihse_resp_snapshot_status_t status = qihse_resp_snapshot_nodes(context->topology, &nodes, &node_count);
    if (status != QIHSE_RESP_SNAPSHOT_OK) return qihse_resp_handle_snapshot_error(context, status);
    status = qihse_resp_snapshot_slots(context->topology, &slots);
    if (status != QIHSE_RESP_SNAPSHOT_OK) {
        free(nodes);
        return qihse_resp_handle_snapshot_error(context, status);
    }
    for (size_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; slot++) {
        if (slots[slot].state != QIHSE_CLUSTER_SLOT_STABLE &&
            (!qihse_resp_node_at(nodes, node_count, slots[slot].owner) ||
             !qihse_resp_node_at(nodes, node_count, slots[slot].peer) ||
             slots[slot].owner == slots[slot].peer)) {
            free(slots);
            free(nodes);
            return qihse_resp_reply_topology_error(context);
        }
    }
    uint16_t local_index = qihse_cluster_topology_local_node(context->topology);
    qihse_resp_buffer_t payload = {0};
    bool built = true;
    for (size_t i = 0; built && i < node_count; i++) {
        const qihse_cluster_node_t* node = &nodes[i];
        built = qihse_resp_buffer_append(&payload, node->id, QIHSE_CLUSTER_NODE_ID_LEN) &&
                qihse_resp_buffer_append_char(&payload, ' ') &&
                qihse_resp_buffer_append_node_endpoint(&payload, node) &&
                qihse_resp_buffer_append_char(&payload, ' ');
        if (!built) break;
        if ((uint16_t)i == local_index) built = qihse_resp_buffer_append_string(&payload, "myself,");
        if (built) built = qihse_resp_buffer_append_string(&payload, node->role == QIHSE_CLUSTER_NODE_PRIMARY ? "master" : "slave");
        if (built && !node->healthy) built = qihse_resp_buffer_append_string(&payload, ",fail");
        if (built) built = qihse_resp_buffer_append_char(&payload, ' ');
        if (!built) break;
        if (node->role == QIHSE_CLUSTER_NODE_REPLICA) {
            const qihse_cluster_node_t* primary = qihse_resp_node_at(nodes, node_count, node->primary_index);
            if (primary) built = qihse_resp_buffer_append(&payload, primary->id, QIHSE_CLUSTER_NODE_ID_LEN);
            else built = qihse_resp_buffer_append_char(&payload, '-');
        } else {
            built = qihse_resp_buffer_append_char(&payload, '-');
        }
        if (built) {
            built = qihse_resp_buffer_append_string(&payload, " 0 0 ") &&
                    qihse_resp_buffer_append_u64(&payload, node->config_epoch) &&
                    qihse_resp_buffer_append_char(&payload, ' ') &&
                    qihse_resp_buffer_append_string(&payload, node->healthy ? "connected" : "disconnected");
        }
        if (built && node->role == QIHSE_CLUSTER_NODE_PRIMARY) {
            built = qihse_resp_buffer_append_node_ranges(&payload, (uint16_t)i, slots);
        }
        if (built) built = qihse_resp_buffer_append_node_transitions(&payload, (uint16_t)i, nodes, node_count, slots);
        if (built) built = qihse_resp_buffer_append_char(&payload, '\n');
    }
    free(slots);
    free(nodes);
    if (!built) {
        qihse_resp_buffer_destroy(&payload);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_bulk_buffer(context, &payload);
}

static bool qihse_resp_handle_info(qihse_resp_cluster_context_t* context, size_t argc) {
    if (argc != 2) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    qihse_cluster_node_t* nodes = NULL;
    qihse_resp_slot_snapshot_t* slots = NULL;
    size_t node_count = 0;
    qihse_resp_snapshot_status_t status = qihse_resp_snapshot_nodes(context->topology, &nodes, &node_count);
    if (status != QIHSE_RESP_SNAPSHOT_OK) return qihse_resp_handle_snapshot_error(context, status);
    status = qihse_resp_snapshot_slots(context->topology, &slots);
    if (status != QIHSE_RESP_SNAPSHOT_OK) {
        free(nodes);
        return qihse_resp_handle_snapshot_error(context, status);
    }
    bool primary_has_slot[QIHSE_CLUSTER_MAX_NODES] = {false};
    size_t assigned = 0;
    size_t ok = 0;
    size_t failed = 0;
    for (size_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; slot++) {
        uint16_t owner = slots[slot].owner;
        if (owner == QIHSE_CLUSTER_NODE_NONE) continue;
        assigned++;
        const qihse_cluster_node_t* node = qihse_resp_node_at(nodes, node_count, owner);
        if (node && node->role == QIHSE_CLUSTER_NODE_PRIMARY) primary_has_slot[owner] = true;
        if (node && node->role == QIHSE_CLUSTER_NODE_PRIMARY && node->healthy) ok++;
        else failed++;
    }
    size_t cluster_size = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (primary_has_slot[i]) cluster_size++;
    }
    uint64_t my_epoch = 0;
    uint16_t local_index = qihse_cluster_topology_local_node(context->topology);
    const qihse_cluster_node_t* local = qihse_resp_node_at(nodes, node_count, local_index);
    if (local) my_epoch = local->config_epoch;
    bool state_ok = assigned == QIHSE_CLUSTER_SLOT_COUNT && failed == 0;
    qihse_resp_buffer_t payload = {0};
    bool built = qihse_resp_buffer_append_string(&payload, "cluster_state:") &&
                 qihse_resp_buffer_append_string(&payload, state_ok ? "ok\r\n" : "fail\r\n") &&
                 qihse_resp_buffer_append_string(&payload, "cluster_slots_assigned:") &&
                 qihse_resp_buffer_append_size(&payload, assigned) &&
                 qihse_resp_buffer_append_string(&payload, "\r\ncluster_slots_ok:") &&
                 qihse_resp_buffer_append_size(&payload, ok) &&
                 qihse_resp_buffer_append_string(&payload, "\r\ncluster_slots_pfail:0\r\ncluster_slots_fail:") &&
                 qihse_resp_buffer_append_size(&payload, failed) &&
                 qihse_resp_buffer_append_string(&payload, "\r\ncluster_known_nodes:") &&
                 qihse_resp_buffer_append_size(&payload, node_count) &&
                 qihse_resp_buffer_append_string(&payload, "\r\ncluster_size:") &&
                 qihse_resp_buffer_append_size(&payload, cluster_size) &&
                 qihse_resp_buffer_append_string(&payload, "\r\ncluster_current_epoch:") &&
                 qihse_resp_buffer_append_u64(&payload, qihse_cluster_topology_epoch(context->topology)) &&
                 qihse_resp_buffer_append_string(&payload, "\r\ncluster_my_epoch:") &&
                 qihse_resp_buffer_append_u64(&payload, my_epoch) &&
                 qihse_resp_buffer_append_string(&payload, "\r\n");
    free(slots);
    free(nodes);
    if (!built) {
        qihse_resp_buffer_destroy(&payload);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_bulk_buffer(context, &payload);
}

static bool qihse_resp_handle_myid(qihse_resp_cluster_context_t* context, size_t argc) {
    if (argc != 2) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    uint16_t local_index = qihse_cluster_topology_local_node(context->topology);
    qihse_cluster_node_t local;
    if (local_index == QIHSE_CLUSTER_NODE_NONE ||
        !qihse_cluster_topology_get_node(context->topology, local_index, &local) ||
        !qihse_resp_node_valid(&local, local_index)) {
        return qihse_resp_emit_string(context, "-ERR no local node configured\r\n");
    }
    qihse_resp_buffer_t response = {0};
    if (!qihse_resp_buffer_append_bulk(&response, local.id, QIHSE_CLUSTER_NODE_ID_LEN)) {
        qihse_resp_buffer_destroy(&response);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_buffer(context, &response);
}

static bool qihse_resp_handle_keyslot(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc != 3) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    uint16_t slot = qihse_cluster_key_slot(argv[2].data, argv[2].len);
    qihse_resp_buffer_t response = {0};
    if (!qihse_resp_buffer_append_integer(&response, slot)) {
        qihse_resp_buffer_destroy(&response);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_buffer(context, &response);
}

static bool qihse_resp_host_valid(const qihse_resp_arg_t* arg) {
    if (!arg || !arg->data || arg->len == 0 || arg->len > QIHSE_CLUSTER_HOST_LEN) return false;
    bool opening_bracket = arg->data[0] == (uint8_t)'[';
    bool closing_bracket = arg->data[arg->len - 1u] == (uint8_t)']';
    if (opening_bracket != closing_bracket || (opening_bracket && arg->len <= 2u)) return false;
    for (size_t i = 0; i < arg->len; i++) {
        uint8_t byte = arg->data[i];
        if (byte <= UINT8_C(0x20) || byte == UINT8_C(0x7f) || byte == (uint8_t)'@' || byte == (uint8_t)',') return false;
        if ((byte == (uint8_t)'[' && !(opening_bracket && i == 0)) ||
            (byte == (uint8_t)']' && !(closing_bracket && i == arg->len - 1u))) return false;
    }
    return true;
}

static bool qihse_resp_handle_meet(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc != 4 && argc != 5) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    uint64_t parsed_port;
    uint64_t parsed_bus_port;
    if (!qihse_resp_host_valid(&argv[2]) ||
        !qihse_resp_parse_unsigned(&argv[3], 1u, UINT16_MAX, &parsed_port)) {
        return qihse_resp_emit_string(context, "-ERR invalid host or port\r\n");
    }
    if (argc == 5) {
        if (!qihse_resp_parse_unsigned(&argv[4], 1u, UINT16_MAX, &parsed_bus_port)) {
            return qihse_resp_emit_string(context, "-ERR invalid bus port\r\n");
        }
    } else {
        if (parsed_port > UINT16_MAX - UINT64_C(10000)) {
            return qihse_resp_emit_string(context, "-ERR invalid bus port\r\n");
        }
        parsed_bus_port = parsed_port + UINT64_C(10000);
    }
    qihse_resp_buffer_t seed = {0};
    bool built = qihse_resp_buffer_append(&seed, argv[2].data, argv[2].len) &&
                 qihse_resp_buffer_append_char(&seed, ':') &&
                 qihse_resp_buffer_append_u64(&seed, parsed_port);
    if (!built) {
        qihse_resp_buffer_destroy(&seed);
        return qihse_resp_reply_oom(context);
    }
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    memcpy(node.host, argv[2].data, argv[2].len);
    node.host[argv[2].len] = '\0';
    node.port = (uint16_t)parsed_port;
    node.bus_port = (uint16_t)parsed_bus_port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = true;
    qihse_cluster_node_id_from_seed(seed.data, seed.len, node.id);
    qihse_resp_buffer_destroy(&seed);
    if (!qihse_cluster_topology_upsert_node(context->topology, &node, NULL)) {
        return qihse_resp_emit_string(context, "-ERR unable to add cluster node\r\n");
    }
    return qihse_resp_emit_string(context, "+OK\r\n");
}

static qihse_resp_slot_list_status_t qihse_resp_parse_slot_list(size_t argc, const qihse_resp_arg_t* argv,
                                                                 size_t first, uint16_t** out_slots, size_t* out_count) {
    *out_slots = NULL;
    *out_count = 0;
    if (first >= argc) return QIHSE_RESP_SLOT_LIST_INVALID;
    size_t count = argc - first;
    size_t bytes;
    if (!qihse_resp_size_multiply(count, sizeof(uint16_t), &bytes)) return QIHSE_RESP_SLOT_LIST_OOM;
    uint16_t* slots = (uint16_t*)malloc(bytes);
    bool* seen = (bool*)calloc((size_t)QIHSE_CLUSTER_SLOT_COUNT, sizeof(bool));
    if (!slots || !seen) {
        free(seen);
        free(slots);
        return QIHSE_RESP_SLOT_LIST_OOM;
    }
    for (size_t i = 0; i < count; i++) {
        uint64_t value;
        if (!qihse_resp_parse_unsigned(&argv[first + i], 0u, QIHSE_CLUSTER_SLOT_COUNT - 1u, &value)) {
            free(seen);
            free(slots);
            return QIHSE_RESP_SLOT_LIST_INVALID;
        }
        if (seen[value]) {
            free(seen);
            free(slots);
            return QIHSE_RESP_SLOT_LIST_DUPLICATE;
        }
        seen[value] = true;
        slots[i] = (uint16_t)value;
    }
    free(seen);
    *out_slots = slots;
    *out_count = count;
    return QIHSE_RESP_SLOT_LIST_OK;
}

static bool qihse_resp_reply_slot_list_error(qihse_resp_cluster_context_t* context, qihse_resp_slot_list_status_t status) {
    if (status == QIHSE_RESP_SLOT_LIST_OOM) return qihse_resp_reply_oom(context);
    if (status == QIHSE_RESP_SLOT_LIST_DUPLICATE) return qihse_resp_emit_string(context, "-ERR duplicate slot\r\n");
    return qihse_resp_emit_string(context, "-ERR invalid slot\r\n");
}

static bool qihse_resp_get_local_primary(qihse_resp_cluster_context_t* context, uint16_t* out_index,
                                          qihse_cluster_node_t* out_node) {
    uint16_t index = qihse_cluster_topology_local_node(context->topology);
    if (index == QIHSE_CLUSTER_NODE_NONE ||
        !qihse_cluster_topology_get_node(context->topology, index, out_node) ||
        !qihse_resp_node_valid(out_node, index) || out_node->role != QIHSE_CLUSTER_NODE_PRIMARY) return false;
    *out_index = index;
    return true;
}

static bool qihse_resp_handle_addslots(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc < 3) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    uint16_t* slots = NULL;
    size_t slot_count = 0;
    qihse_resp_slot_list_status_t status = qihse_resp_parse_slot_list(argc, argv, 2u, &slots, &slot_count);
    if (status != QIHSE_RESP_SLOT_LIST_OK) return qihse_resp_reply_slot_list_error(context, status);
    uint16_t local_index;
    qihse_cluster_node_t local;
    if (!qihse_resp_get_local_primary(context, &local_index, &local)) {
        free(slots);
        return qihse_resp_emit_string(context, "-ERR local node is not a primary\r\n");
    }
    for (size_t i = 0; i < slot_count; i++) {
        uint16_t owner;
        if (!qihse_cluster_topology_get_slot(context->topology, slots[i], &owner, NULL, NULL)) {
            free(slots);
            return qihse_resp_reply_topology_error(context);
        }
        if (owner != QIHSE_CLUSTER_NODE_NONE) {
            free(slots);
            return qihse_resp_emit_string(context, "-ERR slot is already busy\r\n");
        }
    }
    for (size_t i = 0; i < slot_count; i++) {
        if (!qihse_cluster_topology_assign_range(context->topology, slots[i], slots[i], local_index)) {
            free(slots);
            return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
        }
    }
    free(slots);
    return qihse_resp_emit_string(context, "+OK\r\n");
}

static bool qihse_resp_handle_delslots(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc < 3) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    uint16_t* slots = NULL;
    size_t slot_count = 0;
    qihse_resp_slot_list_status_t status = qihse_resp_parse_slot_list(argc, argv, 2u, &slots, &slot_count);
    if (status != QIHSE_RESP_SLOT_LIST_OK) return qihse_resp_reply_slot_list_error(context, status);
    for (size_t i = 0; i < slot_count; i++) {
        uint16_t owner;
        if (!qihse_cluster_topology_get_slot(context->topology, slots[i], &owner, NULL, NULL)) {
            free(slots);
            return qihse_resp_reply_topology_error(context);
        }
        if (owner == QIHSE_CLUSTER_NODE_NONE) {
            free(slots);
            return qihse_resp_emit_string(context, "-ERR slot is already unbound\r\n");
        }
    }
    for (size_t i = 0; i < slot_count; i++) {
        if (!qihse_cluster_topology_unassign_range(context->topology, slots[i], slots[i])) {
            free(slots);
            return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
        }
    }
    free(slots);
    return qihse_resp_emit_string(context, "+OK\r\n");
}

static bool qihse_resp_handle_setslot(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc < 4) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    uint64_t parsed_slot;
    if (!qihse_resp_parse_unsigned(&argv[2], 0u, QIHSE_CLUSTER_SLOT_COUNT - 1u, &parsed_slot)) {
        return qihse_resp_emit_string(context, "-ERR invalid slot\r\n");
    }
    uint16_t slot = (uint16_t)parsed_slot;
    if (qihse_resp_arg_equals(&argv[3], "STABLE")) {
        if (argc != 4) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
        uint16_t owner;
        if (!qihse_cluster_topology_get_slot(context->topology, slot, &owner, NULL, NULL)) {
            return qihse_resp_reply_topology_error(context);
        }
        bool updated = owner == QIHSE_CLUSTER_NODE_NONE
                           ? qihse_cluster_topology_unassign_range(context->topology, slot, slot)
                           : qihse_cluster_topology_set_stable(context->topology, slot, owner);
        if (!updated) return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
        return qihse_resp_emit_string(context, "+OK\r\n");
    }
    if (!qihse_resp_arg_equals(&argv[3], "MIGRATING") &&
        !qihse_resp_arg_equals(&argv[3], "IMPORTING") &&
        !qihse_resp_arg_equals(&argv[3], "NODE")) {
        return qihse_resp_emit_string(context, "-ERR invalid SETSLOT action\r\n");
    }
    if (argc != 5) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    if (!qihse_resp_arg_node_id(&argv[4], node_id)) {
        return qihse_resp_emit_string(context, "-ERR invalid node id\r\n");
    }
    uint16_t target_index;
    qihse_cluster_node_t target;
    if (!qihse_cluster_topology_find_node(context->topology, node_id, &target_index) ||
        !qihse_cluster_topology_get_node(context->topology, target_index, &target) ||
        !qihse_resp_node_valid(&target, target_index) || target.role != QIHSE_CLUSTER_NODE_PRIMARY) {
        return qihse_resp_emit_string(context, "-ERR unknown primary node\r\n");
    }
    if (qihse_resp_arg_equals(&argv[3], "NODE")) {
        if (!qihse_cluster_topology_assign_range(context->topology, slot, slot, target_index)) {
            return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
        }
        return qihse_resp_emit_string(context, "+OK\r\n");
    }
    uint16_t local_index;
    qihse_cluster_node_t local;
    if (!qihse_resp_get_local_primary(context, &local_index, &local)) {
        return qihse_resp_emit_string(context, "-ERR local node is not a primary\r\n");
    }
    if (local_index == target_index) return qihse_resp_emit_string(context, "-ERR source and target nodes must differ\r\n");
    uint16_t owner;
    if (!qihse_cluster_topology_get_slot(context->topology, slot, &owner, NULL, NULL)) {
        return qihse_resp_reply_topology_error(context);
    }
    bool updated;
    if (qihse_resp_arg_equals(&argv[3], "MIGRATING")) {
        if (owner != local_index) return qihse_resp_emit_string(context, "-ERR local node does not own slot\r\n");
        updated = qihse_cluster_topology_set_migrating(context->topology, slot, local_index, target_index);
    } else {
        if (owner != target_index) return qihse_resp_emit_string(context, "-ERR source node does not own slot\r\n");
        updated = qihse_cluster_topology_set_importing(context->topology, slot, target_index, local_index);
    }
    if (!updated) return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
    return qihse_resp_emit_string(context, "+OK\r\n");
}

static bool qihse_resp_handle_replicate(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc != 3) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    if (!qihse_resp_arg_node_id(&argv[2], node_id)) return qihse_resp_emit_string(context, "-ERR invalid node id\r\n");
    uint16_t local_index = qihse_cluster_topology_local_node(context->topology);
    qihse_cluster_node_t local;
    if (local_index == QIHSE_CLUSTER_NODE_NONE ||
        !qihse_cluster_topology_get_node(context->topology, local_index, &local) ||
        !qihse_resp_node_valid(&local, local_index)) {
        return qihse_resp_emit_string(context, "-ERR no local node configured\r\n");
    }
    uint16_t primary_index;
    qihse_cluster_node_t primary;
    if (!qihse_cluster_topology_find_node(context->topology, node_id, &primary_index) ||
        !qihse_cluster_topology_get_node(context->topology, primary_index, &primary) ||
        !qihse_resp_node_valid(&primary, primary_index) || primary.role != QIHSE_CLUSTER_NODE_PRIMARY) {
        return qihse_resp_emit_string(context, "-ERR unknown primary node\r\n");
    }
    if (primary_index == local_index) return qihse_resp_emit_string(context, "-ERR cannot replicate local node\r\n");
    local.role = QIHSE_CLUSTER_NODE_REPLICA;
    local.primary_index = primary_index;
    if (!qihse_cluster_topology_upsert_node(context->topology, &local, NULL)) {
        return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
    }
    return qihse_resp_emit_string(context, "+OK\r\n");
}

static bool qihse_resp_handle_failover(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (argc != 2 && argc != 3) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (argc == 3 && !qihse_resp_arg_equals(&argv[2], "FORCE") && !qihse_resp_arg_equals(&argv[2], "TAKEOVER")) {
        return qihse_resp_emit_string(context, "-ERR invalid FAILOVER option\r\n");
    }
    if (!context->topology) return qihse_resp_reply_topology_error(context);
    uint16_t local_index = qihse_cluster_topology_local_node(context->topology);
    qihse_cluster_node_t local;
    if (local_index == QIHSE_CLUSTER_NODE_NONE ||
        !qihse_cluster_topology_get_node(context->topology, local_index, &local) ||
        !qihse_resp_node_valid(&local, local_index) || local.role != QIHSE_CLUSTER_NODE_REPLICA) {
        return qihse_resp_emit_string(context, "-ERR local node is not a replica\r\n");
    }
    uint16_t primary_index = local.primary_index;
    qihse_cluster_node_t primary;
    if (primary_index == QIHSE_CLUSTER_NODE_NONE || primary_index == local_index ||
        !qihse_cluster_topology_get_node(context->topology, primary_index, &primary) ||
        !qihse_resp_node_valid(&primary, primary_index) || primary.role != QIHSE_CLUSTER_NODE_PRIMARY) {
        return qihse_resp_emit_string(context, "-ERR replica has no valid primary\r\n");
    }
    qihse_resp_slot_snapshot_t* slots = NULL;
    qihse_resp_snapshot_status_t status = qihse_resp_snapshot_slots(context->topology, &slots);
    if (status != QIHSE_RESP_SNAPSHOT_OK) return qihse_resp_handle_snapshot_error(context, status);
    local.role = QIHSE_CLUSTER_NODE_PRIMARY;
    local.primary_index = QIHSE_CLUSTER_NODE_NONE;
    if (!qihse_cluster_topology_upsert_node(context->topology, &local, NULL)) {
        free(slots);
        return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
    }
    size_t slot = 0;
    while (slot < QIHSE_CLUSTER_SLOT_COUNT) {
        if (slots[slot].owner != primary_index) {
            slot++;
            continue;
        }
        size_t start = slot;
        do {
            slot++;
        } while (slot < QIHSE_CLUSTER_SLOT_COUNT && slots[slot].owner == primary_index);
        if (!qihse_cluster_topology_assign_range(context->topology, (uint16_t)start, (uint16_t)(slot - 1u), local_index)) {
            free(slots);
            return qihse_resp_emit_string(context, "-ERR topology update failed\r\n");
        }
    }
    free(slots);
    return qihse_resp_emit_string(context, "+OK\r\n");
}

static bool qihse_resp_handle_help(qihse_resp_cluster_context_t* context, size_t argc) {
    static const char* const entries[] = {
        "SLOTS",
        "NODES",
        "INFO",
        "MYID",
        "KEYSLOT <key>",
        "MEET <host> <port> [<bus-port>]",
        "ADDSLOTS <slot> [<slot> ...]",
        "DELSLOTS <slot> [<slot> ...]",
        "SETSLOT <slot> MIGRATING <node-id>",
        "SETSLOT <slot> IMPORTING <node-id>",
        "SETSLOT <slot> NODE <node-id>",
        "SETSLOT <slot> STABLE",
        "REPLICATE <node-id>",
        "FAILOVER [FORCE|TAKEOVER]",
        "HELP"
    };
    if (argc != 2) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    qihse_resp_buffer_t response = {0};
    size_t count = sizeof(entries) / sizeof(entries[0]);
    bool built = qihse_resp_buffer_append_array_header(&response, count);
    for (size_t i = 0; built && i < count; i++) {
        built = qihse_resp_buffer_append_bulk(&response, entries[i], strlen(entries[i]));
    }
    if (!built) {
        qihse_resp_buffer_destroy(&response);
        return qihse_resp_reply_oom(context);
    }
    return qihse_resp_emit_buffer(context, &response);
}

bool qihse_resp_cluster_dispatch(qihse_resp_cluster_context_t* context, size_t argc, const qihse_resp_arg_t* argv) {
    if (!context || !context->output) return false;
    if (argc == 0 || !argv) return qihse_resp_emit_string(context, "-ERR malformed command\r\n");
    for (size_t i = 0; i < argc; i++) {
        if (!argv[i].data && argv[i].len != 0) return qihse_resp_emit_string(context, "-ERR malformed command\r\n");
    }
    if (!qihse_resp_arg_equals(&argv[0], "CLUSTER")) return qihse_resp_emit_string(context, "-ERR malformed command\r\n");
    if (argc < 2) return qihse_resp_emit_string(context, "-ERR wrong number of arguments\r\n");
    if (qihse_resp_arg_equals(&argv[1], "SLOTS")) return qihse_resp_handle_slots(context, argc);
    if (qihse_resp_arg_equals(&argv[1], "NODES")) return qihse_resp_handle_nodes(context, argc);
    if (qihse_resp_arg_equals(&argv[1], "INFO")) return qihse_resp_handle_info(context, argc);
    if (qihse_resp_arg_equals(&argv[1], "MYID")) return qihse_resp_handle_myid(context, argc);
    if (qihse_resp_arg_equals(&argv[1], "KEYSLOT")) return qihse_resp_handle_keyslot(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "MEET")) return qihse_resp_handle_meet(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "ADDSLOTS")) return qihse_resp_handle_addslots(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "DELSLOTS")) return qihse_resp_handle_delslots(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "SETSLOT")) return qihse_resp_handle_setslot(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "REPLICATE")) return qihse_resp_handle_replicate(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "FAILOVER")) return qihse_resp_handle_failover(context, argc, argv);
    if (qihse_resp_arg_equals(&argv[1], "HELP")) return qihse_resp_handle_help(context, argc);
    return qihse_resp_emit_string(context, "-ERR unknown subcommand\r\n");
}
