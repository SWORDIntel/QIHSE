/* qihse-cluster-daemon — run one QIHSE RESP node of a multi-machine cluster.
 *
 * Unlike tests/qihse_cluster_node.c (three hardcoded localhost nodes), this
 * daemon takes an explicit topology so real hosts can form a cluster:
 *
 *   qihse-cluster-daemon \
 *       --index 0 --bind 192.168.1.91 --port 7100 --bus-port 17100 \
 *       --slot-range 0-8191 \
 *       --node 0:192.168.1.91:7100:17100 \
 *       --node 1:192.168.1.95:7101:17101 \
 *       --slot-range-of 1:8192-16383 \
 *       --operator-password "…" [--dir /opt/qihse-data] [--enable-scatter]
 *
 * Every node must be given the same --node list (the topology is a
 * config-time artifact; the UDP cluster bus on the bus ports carries
 * gossip/failover at runtime). Slots not explicitly assigned default to the
 * local node only when it is the sole node of the cluster.
 *
 * Build: make cluster-daemon
 */
#include "qihse_resp_wire.h"
#include "qihse_cluster_maintenance.h"
#include "qihse_resp_engine.h"
#include "qihse_auth.h"
#include <limits.h>
#include "qihse_auth_maintenance.h"
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_cluster_ownership.h"
#include "qihse_cluster_range_authority.h"
#include "qihse_cluster_transfer.h"
#include "qihse_cluster_reclaim.h"
#include "qihse_cluster_brain.h"
#include "qihse_overlay.h"
#include "qihse_kv_store.h"
#include "qihse_fts.h"
#include "qihse_qkp.h"
#include "qihse_federation.h"
#include "qihse_machine_auth.h"
#include "qihse_platform.h"
#include "qihse_consensus_mesh.h"
#include "qihse_consensus_rejoin_guard.h"
#include "qihse_consensus_blob.h"
#include <netdb.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define MAX_PEERS 64u

/* Durable authority is opt-in and never inferred from federation or data paths.
 * Keep this startup-only parser identical in the two standalone entry points. */
static bool daemon_auth_hex(const char* text, uint8_t* out, size_t size) {
    if (!text || strlen(text) != size * 2u) return false;
    unsigned nonzero = 0u;
    for (size_t i = 0; i < size; ++i) {
        unsigned value = 0u;
        for (size_t j = 0; j < 2u; ++j) {
            unsigned char c = (unsigned char)text[i * 2u + j];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10u;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10u;
            else return false;
            value = value * 16u + digit;
        }
        out[i] = (uint8_t)value;
        nonzero |= value;
    }
    return nonzero != 0u;
}

static bool daemon_auth_number(const char* text, uint64_t* out) {
    if (!text || !*text) return false;
    uint64_t value = 0u;
    for (const char* p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (value > (UINT64_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    *out = value;
    return value != 0u;
}

static bool daemon_auth_startup(const char* password, bool auth_required,
                                bool consensus_requested, bool* durable,
                                uint32_t* startup_user_id) {
    static const char* const fields[] = {
        "QIHSE_AUTH_ACTION", "QIHSE_AUTH_STATE_DIR", "QIHSE_AUTH_BOOTSTRAP_FILE",
        "QIHSE_AUTH_BOOTSTRAP_USERNAME", "QIHSE_AUTH_NODE_ID", "QIHSE_AUTH_EPOCH",
        "QIHSE_AUTH_AUTHORITY_ID", "QIHSE_AUTH_HISTORY_ID", "QIHSE_AUTH_MIN_GENERATION",
        "QIHSE_AUTH_RECIPIENT_PUBLIC_KEY", "QIHSE_AUTH_RECIPIENT_PRIVATE_KEY",
        "QIHSE_AUTH_SIGNER_PUBLIC_KEY", "QIHSE_AUTH_SIGNER_PRIVATE_KEY",
        "QIHSE_AUTH_RECIPIENT_PIN", "QIHSE_AUTH_SIGNER_PIN",
        "QIHSE_AUTH_TRANSFER_RECIPIENT_PUBLIC_KEY", "QIHSE_AUTH_TRANSFER_RECIPIENT_PRIVATE_KEY",
        "QIHSE_AUTH_TRANSFER_SIGNER_PUBLIC_KEY", "QIHSE_AUTH_TRANSFER_SIGNER_PRIVATE_KEY",
        "QIHSE_AUTH_TRANSFER_RECIPIENT_PIN", "QIHSE_AUTH_TRANSFER_SIGNER_PIN",
        "QIHSE_AUTH_STARTUP_USER_ID"
    };
    *durable = false;
    *startup_user_id = 0u;
    const char* selected = getenv("QIHSE_AUTH_STARTUP_USER_ID");
    if (selected) {
        uint64_t id = 0u;
        if (!daemon_auth_number(selected, &id) || id >= 65536u) {
            fprintf(stderr, "auth authority: QIHSE_AUTH_STARTUP_USER_ID must be decimal 1..65535; unset selects UID 0\n");
            return false;
        }
        *startup_user_id = (uint32_t)id;
    }
    const char* mode = getenv("QIHSE_AUTH_MODE");
    if (!mode) {
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            if (getenv(fields[i])) {
                fprintf(stderr, "auth authority: %s requires explicit QIHSE_AUTH_MODE\n", fields[i]);
                return false;
            }
        }
        return true;
    }
    if (strcmp(mode, "consensus") == 0) {
        fprintf(stderr,
                "auth authority: consensus mode unavailable: missing committed-authority replay and atomic auth-publication interface, applied/auth-published watermarks, and quorum-backed freshness/read barrier; refusing listener start\n");
        return false;
    }
    if (strcmp(mode, "standalone") == 0 && consensus_requested) {
        fprintf(stderr,
                "auth authority: standalone authority cannot serve a consensus daemon; missing consensus publication and quorum-freshness interfaces; refusing standalone fallback\n");
        return false;
    }
    if (strcmp(mode, "standalone") != 0 || !auth_required || !password || !*password) {
        fprintf(stderr, "auth authority: explicit standalone mode requires authenticated startup and operator password\n");
        return false;
    }
    qihse_auth_startup_config_t config;
    memset(&config, 0, sizeof(config));
    config.mode = QIHSE_AUTH_AUTHORITY_STANDALONE;
    const char* action = getenv("QIHSE_AUTH_ACTION");
    if (action && strcmp(action, "provision") == 0) config.action = QIHSE_AUTH_START_PROVISION;
    else if (action && strcmp(action, "recover") == 0) config.action = QIHSE_AUTH_START_RECOVER;
    else {
        fprintf(stderr, "auth authority: QIHSE_AUTH_ACTION must be provision or recover\n");
        return false;
    }
    if (config.action == QIHSE_AUTH_START_PROVISION && *startup_user_id != 0u) {
        fprintf(stderr, "auth authority: provision requires UID 0; unset QIHSE_AUTH_STARTUP_USER_ID (selection is recover-only)\n");
        return false;
    }
    const char* paths[] = {
        getenv("QIHSE_AUTH_STATE_DIR"), getenv("QIHSE_AUTH_BOOTSTRAP_FILE"),
        getenv("QIHSE_AUTH_RECIPIENT_PUBLIC_KEY"), getenv("QIHSE_AUTH_RECIPIENT_PRIVATE_KEY"),
        getenv("QIHSE_AUTH_SIGNER_PUBLIC_KEY"), getenv("QIHSE_AUTH_SIGNER_PRIVATE_KEY")
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (!paths[i] || !*paths[i]) {
            fprintf(stderr, "auth authority: explicit state/bootstrap and all recipient/signer key paths required\n");
            return false;
        }
    }
    config.state_directory = paths[0];
    config.bootstrap_file = paths[1];
    config.archive_keys.recipient_public_file = paths[2];
    config.archive_keys.recipient_private_file = paths[3];
    config.archive_keys.signer_public_file = paths[4];
    config.archive_keys.signer_private_file = paths[5];
    if (!daemon_auth_hex(getenv("QIHSE_AUTH_NODE_ID"), config.node, sizeof(config.node)) ||
        !daemon_auth_hex(getenv("QIHSE_AUTH_AUTHORITY_ID"), config.authority_id, sizeof(config.authority_id)) ||
        !daemon_auth_hex(getenv("QIHSE_AUTH_RECIPIENT_PIN"), config.archive_keys.recipient_pin, sizeof(config.archive_keys.recipient_pin)) ||
        !daemon_auth_hex(getenv("QIHSE_AUTH_SIGNER_PIN"), config.archive_keys.signer_pin, sizeof(config.archive_keys.signer_pin)) ||
        !daemon_auth_number(getenv("QIHSE_AUTH_EPOCH"), &config.epoch)) {
        fprintf(stderr, "auth authority: nonzero node/authority hex32, SPKI SHA384 pins hex96 and decimal epoch required\n");
        return false;
    }
    const char* transfer_paths[] = {
        getenv("QIHSE_AUTH_TRANSFER_RECIPIENT_PUBLIC_KEY"),
        getenv("QIHSE_AUTH_TRANSFER_RECIPIENT_PRIVATE_KEY"),
        getenv("QIHSE_AUTH_TRANSFER_SIGNER_PUBLIC_KEY"),
        getenv("QIHSE_AUTH_TRANSFER_SIGNER_PRIVATE_KEY")
    };
    const char* transfer_recipient_pin = getenv("QIHSE_AUTH_TRANSFER_RECIPIENT_PIN");
    const char* transfer_signer_pin = getenv("QIHSE_AUTH_TRANSFER_SIGNER_PIN");
    bool transfer_requested = transfer_recipient_pin || transfer_signer_pin;
    for (size_t i = 0; i < sizeof(transfer_paths) / sizeof(transfer_paths[0]); ++i) {
        if (transfer_paths[i]) {
            transfer_requested = true;
            if (!*transfer_paths[i]) {
                fprintf(stderr, "auth authority: empty transfer key path\n");
                return false;
            }
        }
    }
    if (transfer_requested) {
        if (!daemon_auth_hex(transfer_recipient_pin, config.transfer_keys.recipient_pin, sizeof(config.transfer_keys.recipient_pin)) ||
            !daemon_auth_hex(transfer_signer_pin, config.transfer_keys.signer_pin, sizeof(config.transfer_keys.signer_pin)) ||
            (!!transfer_paths[0] != !!transfer_paths[3]) ||
            (!!transfer_paths[1] != !!transfer_paths[2]) ||
            (!transfer_paths[0] && !transfer_paths[1])) {
            fprintf(stderr, "auth authority: transfer requires explicit pins and export recipient-public/signer-private or import recipient-private/signer-public pair\n");
            return false;
        }
        config.transfer_keys.recipient_public_file = transfer_paths[0];
        config.transfer_keys.recipient_private_file = transfer_paths[1];
        config.transfer_keys.signer_public_file = transfer_paths[2];
        config.transfer_keys.signer_private_file = transfer_paths[3];
    }
    const char* username = getenv("QIHSE_AUTH_BOOTSTRAP_USERNAME");
    if (config.action == QIHSE_AUTH_START_RECOVER) {
        if (username ||
            !daemon_auth_hex(getenv("QIHSE_AUTH_HISTORY_ID"), config.expected_history, sizeof(config.expected_history)) ||
            !daemon_auth_number(getenv("QIHSE_AUTH_MIN_GENERATION"), &config.minimum_generation)) {
            fprintf(stderr, "auth authority: recover requires nonzero HISTORY_ID hex32 and MIN_GENERATION decimal; no BOOTSTRAP_USERNAME\n");
            return false;
        }
    } else if (!username || !*username || getenv("QIHSE_AUTH_MIN_GENERATION") ||
               (getenv("QIHSE_AUTH_HISTORY_ID") &&
                !daemon_auth_hex(getenv("QIHSE_AUTH_HISTORY_ID"), config.expected_history, sizeof(config.expected_history)))) {
        fprintf(stderr, "auth authority: provision requires BOOTSTRAP_USERNAME, no MIN_GENERATION, and optional nonzero HISTORY_ID hex32\n");
        return false;
    }
    qihse_auth_maintenance_status_t status;
    if (config.action == QIHSE_AUTH_START_PROVISION) {
        status = qihse_auth_bootstrap_provision(config.bootstrap_file, username, password,
                                               false, "", true);
        if (status != QIHSE_AUTH_MAINT_OK) {
            fprintf(stderr, "auth authority: create-only bootstrap provision failed: %s\n",
                    qihse_auth_maintenance_status_string(status));
            return false;
        }
    }
    qihse_auth_recovery_t* recovery = NULL;
    status = qihse_auth_maintenance_start(&config, &recovery);
    /* The typed startup capability must not escape into listener state. */
    qihse_auth_maintenance_recovery_release(recovery);
    if (status != QIHSE_AUTH_MAINT_OK) {
        fprintf(stderr, "auth authority: %s failed: %s (no volatile fallback or reset)\n",
                action, qihse_auth_maintenance_status_string(status));
        return false;
    }
    *durable = true;
    return true;
}

static bool daemon_auth_report(qihse_user_t* actor, bool durable,
                               uint32_t startup_user_id) {
    if (!durable) {
        fprintf(stderr, "auth authority: volatile legacy; durable maintenance unsupported\n");
        return true;
    }
    if (!actor || !qihse_auth_user_is_active(actor) ||
        qihse_user_get_id(actor) != startup_user_id ||
        qihse_user_get_role(actor) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(actor) != QIHSE_TENANT_SYSTEM ||
        qihse_user_get_classification(actor) != UINT16_MAX ||
        qihse_user_get_sci(actor) != UINT16_MAX) {
        fprintf(stderr, "auth authority: selected startup actor must be an active full-clearance/SCI system Operator\n");
        return false;
    }
    qihse_auth_maintenance_caps_t caps;
    qihse_auth_maintenance_status_t status = qihse_auth_maintenance_capabilities(actor, &caps);
    if (status != QIHSE_AUTH_MAINT_OK || !caps.ready ||
        caps.mode != QIHSE_AUTH_AUTHORITY_STANDALONE) {
        fprintf(stderr, "auth authority: authenticated durable readiness check failed; no HWT bypass. "
                "For HWT-required root, select an existing authorized service Operator with "
                "QIHSE_AUTH_STARTUP_USER_ID and its own QIHSE_OPERATOR_PASSWORD; "
                "prepare that identity before requiring HWT on root\n");
        return false;
    }
    fprintf(stderr, "auth authority: standalone ready history=");
    for (size_t i = 0; i < sizeof(caps.position.history); ++i)
        fprintf(stderr, "%02x", (unsigned)caps.position.history[i]);
    fprintf(stderr, " epoch=%llu generation=%llu export=%u import=%u checkpoint=%u\n",
            (unsigned long long)caps.position.epoch,
            (unsigned long long)caps.position.generation,
            (unsigned)caps.export_supported, (unsigned)caps.import_supported,
            (unsigned)caps.checkpoint_supported);
    return true;
}


typedef struct {
    unsigned int index;
    char host[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t port;
    uint16_t bus_port;
    bool has_slots;
    uint16_t slot_first;
    uint16_t slot_last;
} peer_spec_t;

typedef struct {
    char topology_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
} ct_identity_map_t;

typedef struct {
    ct_identity_map_t entries[QIHSE_QKP_MAX_REPLICATION_PEERS + 1u];
    size_t count;
} ct_identity_map_set_t;

static bool ct_identity_map_lookup(void* context, const char* topology_id,
        char out_qkp[QIHSE_QKP_NODE_ID_LEN + 1u]) {
    ct_identity_map_set_t* maps = context;
    if (!maps || !topology_id || !out_qkp) return false;
    for (size_t i = 0; i < maps->count; ++i) {
        if (strcmp(maps->entries[i].topology_id, topology_id) == 0) {
            snprintf(out_qkp, QIHSE_QKP_NODE_ID_LEN + 1u, "%s",
                     maps->entries[i].qkp_node_id);
            return true;
        }
    }
    return false;
}

static bool ct_group_endpoint_for_qkp(const qihse_cluster_topology_t* topology,
        const ct_identity_map_set_t* maps, const char* qkp_id,
        qihse_cluster_node_t* out_node) {
    if (!topology || !maps || !qkp_id || !out_node) return false;
    for (size_t i = 0; i < maps->count; ++i) {
        if (strcmp(maps->entries[i].qkp_node_id, qkp_id) != 0) continue;
        uint16_t index = QIHSE_CLUSTER_NODE_NONE;
        if (qihse_cluster_topology_find_node(topology,
                maps->entries[i].topology_id, &index) &&
            qihse_cluster_topology_get_node(topology, index, out_node))
            return true;
    }
    return false;
}

static const char* ct_group_replication_pin(
        const qihse_qkp_replication_peer_t* peers, size_t count,
        const char* qkp_id) {
    if (!peers || !qkp_id) return NULL;
    for (size_t i = 0; i < count; ++i)
        if (peers[i].node_id && peers[i].dsa_pub_path &&
            strcmp(peers[i].node_id, qkp_id) == 0)
            return peers[i].dsa_pub_path;
    return NULL;
}

typedef struct {
    qihse_kv_store_t* store;
    qihse_user_t* operator_user;
    qihse_consensus_mesh_t* mesh;
    const qihse_ct_group_config_t* groups;
    size_t group_count;
    const ct_identity_map_set_t* identity_maps;
    const char* local_qkp_id;
} ct_group_authority_context_t;

typedef struct {
    qihse_cluster_ownership_context_t* ownership;
    ct_group_authority_context_t* groups;
    char last_error[256];
} daemon_brain_group_transfer_context_t;

static bool ct_group_current_map(const ct_group_authority_context_t* context,
        const qihse_ct_group_config_t* configured,
        char owner_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u],
        char owner_qkp[QIHSE_QKP_NODE_ID_LEN + 1u], char generation[33],
        char successor_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u],
        char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u]) {
    if (!context || !configured || !context->operator_user ||
        !context->identity_maps || !owner_topology || !owner_qkp ||
        !generation || !successor_topology || !successor_qkp) return false;
    snprintf(owner_topology, QIHSE_CLUSTER_NODE_ID_LEN + 1u, "%s",
             configured->owner_topology_id);
    snprintf(successor_topology, QIHSE_CLUSTER_NODE_ID_LEN + 1u, "%s",
             configured->successor_topology_id);
    snprintf(generation, 33u, "%s", configured->generation);
    if (!ct_identity_map_lookup((void*)context->identity_maps,
            owner_topology, owner_qkp) ||
        !ct_identity_map_lookup((void*)context->identity_maps,
            successor_topology, successor_qkp)) return false;
    if (!context->mesh) return true;

    qihse_consensus_range_request_t transition;
    qihse_consensus_range_decision_t decision;
    bool found = false;
    memset(&transition, 0, sizeof(transition));
    memset(&decision, 0, sizeof(decision));
    if (!qihse_consensus_mesh_range_group_transition_user(context->mesh,
            context->operator_user, configured->lane_id, &transition,
            &decision, &found)) return false;
    if (found) {
        if (transition.op != QIHSE_RANGE_OP_PROMOTION ||
            strcmp(transition.target_group_id, configured->lane_id) != 0 ||
            !transition.target_topology_id[0] || !transition.target_qkp_id[0] ||
            !transition.target_generation[0] ||
            !transition.successor_topology_id[0] ||
            !transition.successor_qkp_id[0] || !decision.decision_index) {
            OPENSSL_cleanse(&transition, sizeof(transition));
            OPENSSL_cleanse(&decision, sizeof(decision));
            return false;
        }
        snprintf(owner_topology, QIHSE_CLUSTER_NODE_ID_LEN + 1u, "%s",
                 transition.target_topology_id);
        snprintf(owner_qkp, QIHSE_QKP_NODE_ID_LEN + 1u, "%s",
                 transition.target_qkp_id);
        snprintf(generation, 33u, "%s", transition.target_generation);
        snprintf(successor_topology, QIHSE_CLUSTER_NODE_ID_LEN + 1u, "%s",
                 transition.successor_topology_id);
        snprintf(successor_qkp, QIHSE_QKP_NODE_ID_LEN + 1u, "%s",
                 transition.successor_qkp_id);
    }
    OPENSSL_cleanse(&transition, sizeof(transition));
    OPENSSL_cleanse(&decision, sizeof(decision));
    return true;
}

static bool ct_bitmap_subset(const uint8_t* subset, const uint8_t* superset,
                             size_t bytes) {
    if (!subset || !superset) return false;
    for (size_t i = 0; i < bytes; ++i)
        if ((subset[i] & (uint8_t)~superset[i]) != 0u) return false;
    return true;
}

static bool ct_group_authority_resolve(void* opaque,
        const qihse_user_t* principal, const char* topology_id,
        const uint8_t slots[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES],
        qihse_cluster_range_group_role_t role, char group_id[65],
        char generation[33]) {
    ct_group_authority_context_t* context = opaque;
    char qkp_id[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
    if (!context || !principal || !qihse_auth_user_is_active(principal) ||
        !slots || !group_id || !generation || !topology_id ||
        !ct_identity_map_lookup((void*)context->identity_maps, topology_id, qkp_id))
        return false;
    char selected_group[65] = {0};
    char selected_generation[33] = {0};
    for (size_t i = 0; i < context->group_count; ++i) {
        const qihse_ct_group_config_t* configured = &context->groups[i];
        char owner_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
        char owner_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        char current_generation[33] = {0};
        char successor_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
        char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        if (!ct_group_current_map(context, configured, owner_topology,
                owner_qkp, current_generation, successor_topology,
                successor_qkp)) return false;
        bool eligible = false;
        qihse_kv_ct_lane_status_t lane;
        memset(&lane, 0, sizeof(lane));
        if (role == QIHSE_CLUSTER_RANGE_SOURCE_GROUP) {
            eligible = strcmp(owner_topology, topology_id) == 0 &&
                strcmp(owner_qkp, qkp_id) == 0 &&
                qihse_kv_ct_lane_status(context->store,
                    context->operator_user, configured->lane_id, &lane) &&
                lane.mode == QIHSE_KV_CT_LANE_SOURCE && lane.admitted &&
                strcmp(lane.source_id, qkp_id) == 0 &&
                strcmp(lane.generation, current_generation) == 0 &&
                ct_bitmap_subset(slots, lane.slot_bitmap,
                    QIHSE_KV_CT_SLOT_BITMAP_BYTES);
        } else if (role == QIHSE_CLUSTER_RANGE_TARGET_GROUP) {
            /* The selected destination is an existing SOURCE group. The
             * incoming bitmap is staged in a separate reservation-bound
             * receiver context; conflating it with this group's current
             * membership would either overwrite the lane or require the
             * destination to own the slots before the transfer. */
            eligible = strcmp(owner_topology, topology_id) == 0 &&
                strcmp(owner_qkp, qkp_id) == 0;
        }
        if (!eligible) continue;
        if (!selected_group[0] || strcmp(configured->lane_id, selected_group) < 0) {
            snprintf(selected_group, sizeof(selected_group), "%s", configured->lane_id);
            const char* selected = role == QIHSE_CLUSTER_RANGE_SOURCE_GROUP
                ? lane.generation : current_generation;
            if (strlen(selected) != 32u) return false;
            memcpy(selected_generation, selected, sizeof(selected_generation));
        }
    }
    if (!selected_group[0]) return false;
    snprintf(group_id, 65u, "%s", selected_group);
    snprintf(generation, 33u, "%s", selected_generation);
    return true;
}

static bool ct_group_authority_resolve_successor(void* opaque,
        const qihse_user_t* principal, const char* group_id,
        char topology_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u],
        char qkp_id[QIHSE_QKP_NODE_ID_LEN + 1u]) {
    ct_group_authority_context_t* context = opaque;
    if (!context || !principal || !qihse_auth_user_is_active(principal) ||
        !group_id || !topology_id || !qkp_id) return false;
    const qihse_ct_group_config_t* configured = NULL;
    for (size_t i = 0; i < context->group_count; ++i)
        if (strcmp(context->groups[i].lane_id, group_id) == 0) {
            configured = &context->groups[i];
            break;
        }
    if (!configured) return false;
    char owner_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
    char successor_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
    char owner_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
    char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
    char generation[33] = {0};
    if (!ct_group_current_map(context, configured, owner_topology, owner_qkp,
            generation, successor_topology, successor_qkp)) return false;
    snprintf(topology_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u, "%s",
             successor_topology);
    snprintf(qkp_id, QIHSE_QKP_NODE_ID_LEN + 1u, "%s", successor_qkp);
    return true;
}

static qihse_brain_transfer_result_t daemon_brain_transfer(void* context,
        qihse_user_t* control, qihse_user_t* data, const char* transfer_id,
        const char* expected_generation, const char* target_id,
        uint16_t first, uint16_t last, char* error, size_t error_cap);

static bool daemon_brain_group_select_range(void* opaque, qihse_user_t* data,
        uint16_t proposed_first, uint16_t proposed_last,
        uint16_t* out_first, uint16_t* out_last, char out_generation[33]) {
    daemon_brain_group_transfer_context_t* transfer = opaque;
    ct_group_authority_context_t* context = transfer ? transfer->groups : NULL;
    if (!context || !data || !qihse_auth_user_is_active(data) ||
        !out_first || !out_last || !out_generation ||
        proposed_first > proposed_last ||
        proposed_last >= QIHSE_CLUSTER_SLOT_COUNT || !context->local_qkp_id)
        return false;

    const qihse_ct_group_config_t* selected = NULL;
    qihse_kv_ct_lane_status_t selected_lane;
    uint16_t first = 0, last = 0;
    for (size_t i = 0; i < context->group_count; ++i) {
        const qihse_ct_group_config_t* configured = &context->groups[i];
        qihse_kv_ct_lane_status_t lane;
        if (!qihse_kv_ct_lane_status(context->store, context->operator_user,
                configured->lane_id, &lane) ||
            lane.mode != QIHSE_KV_CT_LANE_SOURCE || !lane.admitted || lane.promotion_pending ||
            strcmp(lane.source_id, context->local_qkp_id) != 0)
            continue;
        uint16_t begin = proposed_first;
        while (begin <= proposed_last &&
            (lane.slot_bitmap[begin / 8u] &
             (uint8_t)(1u << (begin % 8u))) == 0u) ++begin;
        if (begin > proposed_last) continue;
        if (selected && strcmp(configured->lane_id, selected->lane_id) >= 0)
            continue;
        uint16_t end = begin;
        while (end < proposed_last &&
            (lane.slot_bitmap[(end + 1u) / 8u] &
             (uint8_t)(1u << ((end + 1u) % 8u))) != 0u) ++end;
        selected = configured;
        selected_lane = lane;
        first = begin;
        last = end;
    }
    if (!selected) return false;
    *out_first = first;
    *out_last = last;
    if (strlen(selected_lane.generation) != 32u) return false;
    memcpy(out_generation, selected_lane.generation, 33u);
    return true;
}

static qihse_brain_transfer_result_t daemon_brain_group_transfer(void* opaque,
        qihse_user_t* control, qihse_user_t* data, const char* transfer_id,
        const char* expected_generation, const char* target_id,
        uint16_t first, uint16_t last, char* error, size_t error_cap) {
    daemon_brain_group_transfer_context_t* context = opaque;
    qihse_cluster_ownership_context_t* ownership =
        context ? context->ownership : NULL;
    uint16_t target = QIHSE_CLUSTER_NODE_NONE;
    if (!ownership || !ownership->topology || !ownership->resp_server ||
        !control || !data || !expected_generation ||
        !qihse_cluster_topology_find_node(ownership->topology, target_id, &target)) {
        if (error && error_cap) snprintf(error, error_cap,
            "group transfer requires configured topology and principals");
        return QIHSE_BRAIN_TRANSFER_REJECTED;
    }
    qihse_cluster_ownership_context_t request = *ownership;
    request.principal = control;
    request.data_principal = data;
    qihse_cluster_transfer_context_t transfer = {
        .ownership = &request, .chunk_bytes = 12u * 1024u
    };
    qihse_cluster_transfer_result_t result = qihse_cluster_transfer_range_group(
        &transfer, transfer_id,
        qihse_cluster_topology_local_node(ownership->topology), target,
        first, last, expected_generation, error, error_cap);
    if (error && error[0] && strcmp(context->last_error, error)) {
        fprintf(stderr, "qihse-cluster-daemon: CT2 group %s deferred: %s\n",
                transfer_id, error);
        snprintf(context->last_error, sizeof(context->last_error), "%s", error);
    } else if (result == QIHSE_CLUSTER_TRANSFER_COMMITTED) {
        context->last_error[0] = 0;
    }
    switch (result) {
        case QIHSE_CLUSTER_TRANSFER_COMMITTED: return QIHSE_BRAIN_TRANSFER_COMMITTED;
        case QIHSE_CLUSTER_TRANSFER_PENDING: return QIHSE_BRAIN_TRANSFER_PENDING;
        case QIHSE_CLUSTER_TRANSFER_TOO_LARGE: return QIHSE_BRAIN_TRANSFER_TOO_LARGE;
        default: return QIHSE_BRAIN_TRANSFER_REJECTED;
    }
}

static bool ct_group_build_common_slots(const qihse_ct_group_config_t* groups,
        size_t group_count, const ct_identity_map_set_t* identity_maps,
        qihse_consensus_range_slot_t slots[QIHSE_CONSENSUS_RANGE_SLOT_COUNT]) {
    if (!groups || !group_count || !identity_maps || !slots) return false;
    memset(slots, 0, sizeof(*slots) * QIHSE_CONSENSUS_RANGE_SLOT_COUNT);
    for (uint16_t slot = 0; slot < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++slot) {
        const qihse_ct_group_config_t* owner = NULL;
        for (size_t g = 0; g < group_count; ++g) {
            if ((groups[g].slot_bitmap[slot / 8u] &
                    (uint8_t)(1u << (slot % 8u))) == 0u) continue;
            if (owner) return false;
            owner = &groups[g];
        }
        if (!owner) return false;
        qihse_consensus_range_slot_t* entry = &slots[slot];
        entry->slot = slot;
        snprintf(entry->owner_topology_id, sizeof(entry->owner_topology_id), "%s",
                 owner->owner_topology_id);
        if (!ct_identity_map_lookup((void*)identity_maps,
                owner->owner_topology_id, entry->owner_qkp_id)) return false;
        snprintf(entry->group_id, sizeof(entry->group_id), "%s", owner->lane_id);
        entry->epoch = 1u;
    }
    return true;
}

/* Reconcile only reductions of local authority/replica assignment. Data
 * admission and slot additions still require their staged FINAL transition.
 * This also fences a former owner when a promotion's bus packet was lost. */
static bool ct_group_reconcile_local(qihse_consensus_mesh_t* mesh,
        qihse_kv_store_t* store, qihse_user_t* operator_user,
        const qihse_ct_group_config_t* groups, size_t count) {
    qihse_consensus_range_slot_t* state = calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT,
                                                sizeof(*state));
    if (!state) return false;
    uint8_t selected[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES], digest[32];
    uint64_t index = 0;
    memset(selected, 0xff, sizeof(selected));
    bool ok = qihse_consensus_mesh_range_state_user(mesh, operator_user,
        selected, 2000u, state, digest, &index) && index != 0;
    for (size_t g = 0; ok && g < count; ++g) {
        qihse_kv_ct_lane_status_t lane;
        if (!qihse_kv_ct_lane_status(store, operator_user, groups[g].lane_id,
                                    &lane)) continue;
        uint8_t keep[QIHSE_KV_CT_SLOT_BITMAP_BYTES];
        memcpy(keep, lane.slot_bitmap, sizeof(keep));
        bool superseded = false;
        for (uint32_t slot = 0; slot < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++slot) {
            uint8_t bit = (uint8_t)(1u << (slot % 8u));
            if (!(lane.slot_bitmap[slot / 8u] & bit)) continue;
            bool same_group = !strcmp(state[slot].group_id, lane.lane_id);
            if (!same_group) keep[slot / 8u] &= (uint8_t)~bit;
            else if (strcmp(state[slot].owner_qkp_id, lane.source_id))
                superseded = true;
        }
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        if (lane.mode == QIHSE_KV_CT_LANE_SOURCE && !lane.promotion_pending &&
            superseded) {
            ok = qihse_kv_ct_lane_owner_token_get(store, operator_user,
                    lane.lane_id, token) &&
                qihse_kv_ct_lane_source_disable(store, operator_user,
                    lane.lane_id, lane.generation, token);
        } else if (lane.mode == QIHSE_KV_CT_LANE_RECEIVER &&
                   CRYPTO_memcmp(keep, lane.slot_bitmap, sizeof(keep))) {
            ok = qihse_kv_ct_lane_owner_token_get(store, operator_user,
                    lane.lane_id, token) &&
                qihse_kv_ct_lane_receiver_prune(store, operator_user,
                    lane.lane_id, lane.generation, keep, token);
        }
        OPENSSL_cleanse(token, sizeof(token));
        OPENSSL_cleanse(&lane, sizeof(lane));
    }
    free(state);
    return ok;
}

static bool ct_group_authority_activate(
        qihse_cluster_range_authority_t* authority,
        ct_group_authority_context_t* group_context,
        qihse_cluster_ownership_context_t* ownership,
        qihse_consensus_mesh_t* mesh, qihse_user_t* operator_user,
        qihse_kv_store_t* store, const qihse_ct_group_config_t* groups,
        size_t group_count, const ct_identity_map_set_t* identity_maps,
        const char* local_qkp_id, uint64_t log_limit,
        char* error, size_t error_cap) {
    if (!authority || !group_context || !ownership || !mesh ||
        !operator_user || !store || !groups || !group_count ||
        !identity_maps || !local_qkp_id) return false;
    qihse_consensus_range_slot_t* common_slots = calloc(
        QIHSE_CONSENSUS_RANGE_SLOT_COUNT, sizeof(*common_slots));
    if (!common_slots) return false;
    if (!ct_group_build_common_slots(groups, group_count, identity_maps,
            common_slots)) {
        if (error && error_cap) snprintf(error, error_cap,
            "configured --ct-group map does not cover each slot exactly once");
        free(common_slots);
        return false;
    }
    memset(group_context, 0, sizeof(*group_context));
    group_context->store = store;
    group_context->operator_user = operator_user;
    group_context->mesh = mesh;
    group_context->groups = groups;
    group_context->group_count = group_count;
    group_context->identity_maps = identity_maps;
    group_context->local_qkp_id = local_qkp_id;

    memset(authority, 0, sizeof(*authority));
    authority->mesh = mesh;
    authority->resolve_group = ct_group_authority_resolve;
    authority->resolve_successor = ct_group_authority_resolve_successor;
    authority->group_context = group_context;
    authority->local_ownership = ownership;
    if (!qihse_cluster_range_authority_initialize(authority, operator_user,
            common_slots, error, error_cap)) {
        OPENSSL_cleanse(common_slots,
            QIHSE_CONSENSUS_RANGE_SLOT_COUNT * sizeof(*common_slots));
        free(common_slots);
        return false;
    }
    OPENSSL_cleanse(common_slots,
        QIHSE_CONSENSUS_RANGE_SLOT_COUNT * sizeof(*common_slots));
    free(common_slots);

    ownership->range_reserve = qihse_cluster_range_authority_reserve;
    ownership->range_check_reserved = qihse_cluster_range_authority_check_reserved;
    ownership->range_finalize = qihse_cluster_range_authority_finalize;
    ownership->range_check_finalized = qihse_cluster_range_authority_check_finalized;
    ownership->range_abort = qihse_cluster_range_authority_abort;
    ownership->range_finalize_promotion =
        qihse_cluster_range_authority_finalize_promotion;
    ownership->lane_claim = qihse_cluster_range_authority_claim;
    ownership->lane_verify_claim =
        qihse_cluster_range_authority_verify_claim_user;
    ownership->lane_verify_aborted =
        qihse_cluster_range_authority_verify_aborted_claim_user;
    ownership->range_refresh = qihse_cluster_range_authority_refresh;
    ownership->promotion_successor_prepare =
        qihse_resp_ct_promotion_successor_prepare;
    ownership->promotion_successor_context = ownership->resp_server;
    ownership->range_authority_context = authority;

    uint8_t all_slots[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES];
    memset(all_slots, 0xff, sizeof(all_slots));
    if (!qihse_cluster_range_authority_refresh(authority, operator_user,
            all_slots, error, error_cap)) {
        OPENSSL_cleanse(all_slots, sizeof(all_slots));
        return false;
    }
    OPENSSL_cleanse(all_slots, sizeof(all_slots));

    for (size_t i = 0; i < group_count; ++i) {
        qihse_kv_ct_lane_status_t persisted;
        if (qihse_kv_ct_lane_status(store, operator_user,
                groups[i].lane_id, &persisted)) continue;
        char owner_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        if (!ct_identity_map_lookup((void*)identity_maps,
                groups[i].owner_topology_id, owner_qkp) ||
            !ct_identity_map_lookup((void*)identity_maps,
                groups[i].successor_topology_id, successor_qkp)) {
            if (error && error_cap) snprintf(error, error_cap,
                "CT group %s has incomplete configured topology/QKP mapping",
                groups[i].lane_id);
            return false;
        }
        if (strcmp(local_qkp_id, owner_qkp) != 0) continue;
        unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        bool created = qihse_kv_ct_lane_source_enable(store, operator_user,
            groups[i].lane_id, groups[i].slot_bitmap, owner_qkp, successor_qkp,
            groups[i].generation, owner_token, log_limit);
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        if (!created) {
            if (error && error_cap) snprintf(error, error_cap,
                "failed to persist initial source lane %s", groups[i].lane_id);
            return false;
        }
    }
    if (!qihse_cluster_ownership_reconcile_lane_transfer(ownership, error, error_cap) ||
        !ct_group_reconcile_local(mesh, store, operator_user, groups, group_count)) {
        if (error && error_cap) snprintf(error, error_cap,
            "committed group membership reduction requires retry");
        return false;
    }
    return true;
}

/* Recursive mkdir -p (parents must be writable). */
static bool mkdirs(const char* path) {
    if (!path || !*path) return false;
    char copy[600];
    snprintf(copy, sizeof(copy), "%s", path);
    size_t len = strlen(copy);
    if (len && copy[len - 1u] == '/') copy[len - 1u] = '\0';
    for (char* p = copy + 1u; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0755) != 0 && errno != EEXIST) return false;
            *p = '/';
        }
    }
    if (mkdir(copy, 0700) != 0 && errno != EEXIST) return false;
    chmod(copy, 0700);
    return true;
}

/* Deterministic node identity: the same host:port must mint the same id on
 * every machine that describes the topology, or the nodes will not recognize
 * each other. */
static void fill_node(const char* host, uint16_t port, uint16_t bus_port,
                      qihse_cluster_node_t* node) {
    memset(node, 0, sizeof(*node));
    char seed[QIHSE_CLUSTER_HOST_LEN + 16u];
    int len = snprintf(seed, sizeof(seed), "qihse-node-%s:%u", host, port);
    qihse_cluster_node_id_from_seed(seed, len > 0 ? (size_t)len : 0u, node->id);
    snprintf(node->host, sizeof(node->host), "%s", host);
    node->port = port;
    node->bus_port = bus_port;
    node->role = QIHSE_CLUSTER_NODE_PRIMARY;
    node->primary_index = QIHSE_CLUSTER_NODE_NONE;
    node->healthy = true;
}

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_teardown_done = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* Shutdown is expected to finish in a few seconds; this is the point at which
 * it is declared wedged. Kept well under systemd's TimeoutStopUSec so a stuck
 * teardown yields a diagnostic and a failed exit instead of a SIGKILL. */
#define QIHSE_SHUTDOWN_GRACE_DEFAULT 60u

static unsigned int shutdown_grace_seconds(void) {
    const char* raw = getenv("QIHSE_SHUTDOWN_GRACE");
    if (raw && *raw) {
        char* end = NULL;
        unsigned long value = strtoul(raw, &end, 10);
        if (end != raw && *end == '\0' && value >= 5u && value <= 3000u)
            return (unsigned int)value;
    }
    return QIHSE_SHUTDOWN_GRACE_DEFAULT;
}

/* Name every thread that is still alive, from /proc rather than from any
 * library state: at this point teardown may hold locks, so the dump must not
 * take one. comm/wchan are enough to identify the subsystem that failed to
 * stop, which is what the previous behaviour (an unexplained hang until
 * systemd SIGKILLed the process) never told an operator. */
static void dump_live_threads(const char* reason) {
    DIR* tasks = opendir("/proc/self/task");
    if (!tasks) {
        fprintf(stderr, "qihse-cluster-daemon: shutdown watchdog fired (%s); thread list unavailable\n",
                reason);
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(tasks)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[320]; /* /proc/self/task/<tid>/comm; d_name is up to 255 */
        char name[64] = "?";
        char wchan[64] = "?";
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        FILE* f = fopen(path, "r");
        if (f) { if (fgets(name, sizeof(name), f)) name[strcspn(name, "\n")] = '\0'; fclose(f); }
        snprintf(path, sizeof(path), "/proc/self/task/%s/wchan", entry->d_name);
        f = fopen(path, "r");
        if (f) { if (fgets(wchan, sizeof(wchan), f)) wchan[strcspn(wchan, "\n")] = '\0'; fclose(f); }
        fprintf(stderr, "qihse-cluster-daemon: shutdown watchdog fired (%s); live thread %s still in %s\n",
                reason, entry->d_name, name);
        fprintf(stderr, "qihse-cluster-daemon:   tid %s wchan=%s\n", entry->d_name, wchan);
    }
    closedir(tasks);
}

/* The teardown path joins threads and closes sockets owned by subsystems that
 * do not all honour g_stop. Rather than let an unbounded wait turn a restart
 * into a 5-minute outage ending in SIGKILL, a watchdog bounds it and reports
 * where it stopped. The process is exiting, so _exit() is the correct way to
 * leave a half-torn-down state behind: no atexit handler gets a chance to
 * touch memory an orphaned thread may still be using. */
static void* shutdown_watchdog(void* argument) {
    (void)argument;
    unsigned int grace = shutdown_grace_seconds();
    while (!g_stop) {
        struct timespec idle = {0, 200 * 1000 * 1000L};
        nanosleep(&idle, NULL);
    }
    for (unsigned int waited = 0; waited < grace; waited++) {
        if (g_teardown_done) return NULL;
        struct timespec tick = {1, 0};
        nanosleep(&tick, NULL);
    }
    if (!g_teardown_done) {
        const char* reason = "teardown exceeded the shutdown grace period";
        dump_live_threads(reason);
        fprintf(stderr, "qihse-cluster-daemon: exiting without completing teardown "
                        "(raise QIHSE_SHUTDOWN_GRACE above %u if this is a slow flush)\n", grace);
        _exit(EXIT_FAILURE);
    }
    return NULL;
}

typedef struct {
    char* value;
    size_t length;
    bool locked;
} operator_credential_t;

static operator_credential_t g_operator_credential;

typedef struct {
    char bus_veil[QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN + 1u];
    char overlay_hmac[QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN + 1u];
} cluster_transport_keys_t;

static cluster_transport_keys_t g_transport_keys;

static void cluster_transport_keys_release(void) {
    OPENSSL_cleanse(&g_transport_keys, sizeof(g_transport_keys));
}

static void operator_credential_release(void) {
    if (!g_operator_credential.value) return;
    OPENSSL_cleanse(g_operator_credential.value,
                    g_operator_credential.length + 1u);
    if (g_operator_credential.locked)
        (void)munlock(g_operator_credential.value, g_operator_credential.length + 1u);
    OPENSSL_free(g_operator_credential.value);
    memset(&g_operator_credential, 0, sizeof(g_operator_credential));
}

static bool operator_credential_capture(const char* source) {
    if (!source || !*source || g_operator_credential.value) return false;
    size_t length = strlen(source);
    if (length < 12u || length > 4096u) return false;
    char* owned = (char*)OPENSSL_malloc(length + 1u);
    if (!owned) return false;
    memcpy(owned, source, length + 1u);
    g_operator_credential.value = owned;
    g_operator_credential.length = length;
    g_operator_credential.locked = mlock(owned, length + 1u) == 0;
    return true;
}

/* argv and environ are mutable process-owned storage on the supported Linux
 * hosts.  Scrub a source after copying it into the locked credential buffer so
 * neither /proc/<pid>/cmdline nor /proc/<pid>/environ retains the secret. */
static void operator_credential_scrub_source(char* source) {
    if (source && *source) OPENSSL_cleanse(source, strlen(source));
}

static void operator_credential_clear_environment(void) {
    char* exposed = getenv("QIHSE_OPERATOR_PASSWORD");
    operator_credential_scrub_source(exposed);
    (void)unsetenv("QIHSE_OPERATOR_PASSWORD");
}

static qihse_user_t* replication_service_principal_create(
        qihse_user_t* startup_operator, uint32_t user_id,
        uint16_t classification, uint16_t sci) {
    if (!startup_operator || !qihse_auth_user_is_active(startup_operator) ||
        qihse_user_get_role(startup_operator) != QIHSE_ROLE_OPERATOR)
        return NULL;
    qihse_user_t* existing = qihse_auth_get_user(user_id);
    if (existing)
        return qihse_auth_user_is_active(existing) &&
            qihse_user_get_role(existing) == QIHSE_ROLE_ANALYST &&
            qihse_user_get_tenant_id(existing) == QIHSE_TENANT_SYSTEM &&
            qihse_user_get_classification(existing) == classification &&
            qihse_user_get_sci(existing) == sci &&
            !qihse_user_requires_hardware_token(existing) &&
            !qihse_user_can_create_users(existing) ? existing : NULL;
    unsigned char random_secret[32];
    char one_time_password[sizeof(random_secret) * 2u + 1u];
    static const char hex[] = "0123456789abcdef";
    qihse_user_t* principal = NULL;

    if (RAND_bytes(random_secret, (int)sizeof(random_secret)) != 1) goto done;
    for (size_t i = 0; i < sizeof(random_secret); i++) {
        one_time_password[i * 2u] = hex[random_secret[i] >> 4];
        one_time_password[i * 2u + 1u] = hex[random_secret[i] & 0x0fu];
    }
    one_time_password[sizeof(one_time_password) - 1u] = '\0';
    principal = qihse_auth_create_user(
        startup_operator, user_id, QIHSE_ROLE_ANALYST,
        classification, sci, one_time_password, false);

done:
    OPENSSL_cleanse(one_time_password, sizeof(one_time_password));
    OPENSSL_cleanse(random_secret, sizeof(random_secret));
    return principal;
}

/* Tenant-scoped, non-Operator machine principal for MACHINEAUTH-over-QKP
 * admin access (see tools/qihse_admin_cli.c). The MACHINEAUTH handler
 * refuses system-tenant and Operator principals, so this must be a tenant
 * user. A recovered principal must match the configured service policy. */
static qihse_user_t* machine_service_principal_create(
        qihse_user_t* startup_operator, uint32_t tenant_id, uint32_t user_id) {
    if (!startup_operator || !qihse_auth_user_is_active(startup_operator) ||
        qihse_user_get_role(startup_operator) != QIHSE_ROLE_OPERATOR)
        return NULL;
    qihse_user_t* existing = qihse_auth_get_user(user_id);
    if (existing)
        return qihse_auth_user_is_active(existing) &&
            qihse_user_get_role(existing) == QIHSE_ROLE_ANALYST &&
            qihse_user_get_tenant_id(existing) == tenant_id &&
            qihse_user_get_classification(existing) == UINT16_MAX &&
            qihse_user_get_sci(existing) == UINT16_MAX &&
            !qihse_user_requires_hardware_token(existing) &&
            !qihse_user_can_create_users(existing) ? existing : NULL;
    unsigned char random_secret[32];
    char one_time_password[sizeof(random_secret) * 2u + 1u];
    static const char hex[] = "0123456789abcdef";
    qihse_user_t* principal = NULL;

    if (RAND_bytes(random_secret, (int)sizeof(random_secret)) != 1) goto done;
    for (size_t i = 0; i < sizeof(random_secret); i++) {
        one_time_password[i * 2u] = hex[random_secret[i] >> 4];
        one_time_password[i * 2u + 1u] = hex[random_secret[i] & 0x0fu];
    }
    one_time_password[sizeof(one_time_password) - 1u] = '\0';
    principal = qihse_auth_create_tenant_user(
        startup_operator, tenant_id, user_id, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, one_time_password, false);

done:
    OPENSSL_cleanse(one_time_password, sizeof(one_time_password));
    OPENSSL_cleanse(random_secret, sizeof(random_secret));
    return principal;
}

static bool parse_u16(const char* s, uint16_t* out) {
    if (!s || !*s) return false;
    char* end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v > UINT16_MAX) return false;
    *out = (uint16_t)v;
    return true;
}

/* "first-last" (inclusive); "N" means the single slot N. */
static bool parse_slot_range(const char* s, uint16_t* first, uint16_t* last) {
    if (!s || !*s) return false;
    char* dash = strchr(s, '-');
    if (!dash) return parse_u16(s, first) && (*last = *first, true);
    char first_buf[16];
    size_t n = (size_t)(dash - s);
    if (n == 0 || n >= sizeof(first_buf)) return false;
    memcpy(first_buf, s, n);
    first_buf[n] = '\0';
    return parse_u16(first_buf, first) && parse_u16(dash + 1, last) && *first <= *last;
}

/* Replay callback for the durable slot-ownership journal: resolve the owner
 * by node id and adopt the range only if the journaled config_epoch is newer
 * than what the local topology already knows (adopt-if-newer). */
static void ownership_journal_replay_cb(const qihse_cluster_ownership_entry_t* e, void* ctx) {
    qihse_cluster_topology_t* topology = (qihse_cluster_topology_t*)ctx;
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_topology_find_node(topology, e->owner_id, &owner);
    if (owner == QIHSE_CLUSTER_NODE_NONE) return;
    qihse_cluster_node_t node;
    if (!qihse_cluster_topology_get_node(topology, owner, &node)) return;
    if (e->config_epoch <= node.config_epoch) return;
    qihse_cluster_topology_adopt_range(topology, e->start, e->end, owner, e->config_epoch);
}

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s --index N --bind ADDR --port P --bus-port B\n"
        "          (--node INDEX:HOST:PORT:BUS-PORT [--node …] | --join HOST:BUS-PORT [--join …])\n"
        "          [--slot-range FIRST-LAST] [--slot-range-of INDEX:FIRST-LAST]\n"
        "          [--operator-password PW] [--dir DIR] [--enable-scatter]\n"
        "          [--failover-start-paused] (until Operator CLUSTER FAILOVER.RESUME)\n"
        "          [--startup-maintenance-held] (requires authenticated system Operator; release via STARTUP_TOKEN)\n"
        "          [--kv-sweep-interval SECONDS] expiration sweep + sstable compaction cadence (0 disables)\n"
        "  Durable principal authority: QIHSE_AUTH_MODE=standalone, QIHSE_AUTH_ACTION=provision|recover.\n"
        "  Required QIHSE_AUTH_ suffixes: STATE_DIR, BOOTSTRAP_FILE, AUTHORITY_ID, NODE_ID, EPOCH,\n"
        "  RECIPIENT_PUBLIC_KEY, RECIPIENT_PRIVATE_KEY, SIGNER_PUBLIC_KEY, SIGNER_PRIVATE_KEY,\n"
        "  RECIPIENT_PIN, SIGNER_PIN (SPKI SHA384 hex96; identities hex32; epoch decimal>0).\n"
        "  Provision also requires BOOTSTRAP_USERNAME; recover requires HISTORY_ID and MIN_GENERATION.\n"
        "  Provision history is fresh unless HISTORY_ID supplied; no MIN_GENERATION on provision.\n"
        "  No bootstrap username on recover; private dirs/keys must preexist. Consensus unsupported.\n"
        "  Recover-only QIHSE_AUTH_STARTUP_USER_ID: existing full system Operator, decimal 1..65535;\n"
        "  unset selects UID 0. QIHSE_OPERATOR_PASSWORD is the selected identity's own password.\n"
        "  Prepare that service identity before root HWT is required; no HWT bypass or fallback.\n"
        "  Optional QIHSE_AUTH_TRANSFER_ keys/pins are separate: both pins and complete export\n"
        "  (RECIPIENT_PUBLIC_KEY,SIGNER_PRIVATE_KEY) or import (RECIPIENT_PRIVATE_KEY,SIGNER_PUBLIC_KEY).\n"
        "          (the shared credential authenticates clients and derives\n"
        "           independent bus and overlay transport keys)\n"
        "          [--node-key PATH] [--require-signed-ops]\n"
 "          (signed ops frames: SLOT/NODE/GROUP updates carry ML-DSA\n"
 "           signatures; require-signed-ops refuses unsigned ones)\n"
 "          [--brain] [--brain-act] [--brain-dir DIR] [--brain-interval S] [--brain-dsa-key PATH]\n"
        "          [--brain-cooldown S] [--brain-rollback-window S]\n"
        "          [--brain-prune-timeout S] [--brain-rebalance-min-slots N]\n"
        "          (minimum local slots before this node donates; 0 disables join balancing)\n"
        "          [--brain-fed-dir DIR] [--brain-node-key PATH]\n"
        "          [--redundancy-peer HOST:PORT]\n"
        "          [--replication-principal-id N] (default 65535)\n"
        "          [--replication-allowed-peer NODE_ID PUB_FILE] (repeatable, max 16; startup Operator required)\n"
        "          [--topology-qkp-map TOPOLOGY_ID QKP_NODE_ID] (repeatable; exact explicit identity mapping)\n"
        "          [--ct-group LANE64,OWNER_TOPOLOGY_ID,SUCCESSOR_TOPOLOGY_ID,GENERATION32,SLOTS] (repeatable; slots are inclusive ranges joined by ';')\n"
        "          [--ct-role primary|successor --ct-peer HOST:PORT]\n"
        "          [--ct-auto-successor TOPOLOGY_ID --consensus-authority-proposals]\n"
        "          [--replica-of REPLICA_INDEX:PRIMARY_INDEX] (repeat global CT pair map)\n"
        "          [--ct-learn-generation] (fresh spare: exact pinned source only)\n"
        "          [--ct-generation HEX32 --ct-log-limit BYTES --ct-ack-timeout-ms N]\n"
        "          [--max-clients N]\n"
        "          (each daemon owns a BM25 index over its LOCAL KV:\n"
        "           FTS.BUILD <pattern> indexes matching keys, FTS.SEARCH <query>\n"
        "           [limit] replies [key, score, ...]. The index is persisted\n"
        "           under the store's data dir as fts/node<INDEX>/: FTS.SAVE\n"
        "           writes it and FTS.LOAD reloads it, and a restart reloads or\n"
        "           rebuilds it automatically as the system operator. Both\n"
        "           commands are operator-only; the projection is per node)\n"
        "\n  --join sends MEET frames to a seed node's bus port; membership is\n"
        "  learned dynamically over the cluster bus (gossip). Without --join, the\n"
        "  static --node list defines the topology.\n"
        "\n  --brain-fed-dir is the federation event journal the brain publishes\n"
        "  observations and signed decisions to (default: --brain-dir); the brain\n"
        "  refuses to act when that journal is unavailable. --brain-node-key is the\n"
        "  node identity key that signs decisions (default: --brain-dsa-key).\n"
        "\n  --brain observes and journals always; --brain-act additionally re-homes\n"
        "  a failed owner's range to a healthy target (evidence-gated) and rolls\n"
        "  it back if the move did not complete or the target failed within\n"
        "  --brain-rollback-window seconds.\n"
        "\n  --replicate GLOB marks a sovereign-local namespace.\n"
        "  --replication-source-host DEST --replication-source-port PORT\n"
        "  enables one-way QKP-protected replication. Default transport is WireGuard\n"
        "  private mesh (--replication-transport wireguard), except over LAN\n"
        "  (192.168.x.x) where it defaults to direct (--replication-transport direct);\n"
        "  I2P garlic transport is strictly opt-in (--replication-transport i2p,\n"
        "  SOCKS port --replication-socks-port, default 4447). All require --replica-read-only.\n"
        "  --replication-peer-node-id and --replication-peer-dsa-pub pin the\n"
        "  sole upstream identity; --pqc-node-id sets this daemon's stable ID.\n"
        "  --consensus-group ID --consensus-self UUID --consensus-member UUID\n"
        "  --consensus-bootstrap-unadmitted (existing record; no self vote)\n"
        "  (repeat for every durable baseline voter; never edit after first open)\n"
        "  --consensus-listen-ip RFC1918-IP --consensus-port PORT\n"
        "  --consensus-peer UUID:QKP-ID:DSA-PUB:WG-IP:PORT (provisioned peers)\n"
        "  enables the durable QKP-pinned consensus mesh. Requires --dir and --pqc-require.\n"
        "  --consensus-election-priority-delay-ms N delays this member's candidacy.\n"
        "  --consensus-priority-tier N sets deterministic priority tier (0=primary, 1=warm, 2=cold/arbiter).\n"
        "  --consensus-wan-rtt-ms N adds WAN RTT offset in milliseconds to priority delay.\n"
        "  --consensus-prevote enables Raft Pre-Vote protocol to guard against disruptive elections.\n"
        "  --consensus-election-base-ms N --consensus-election-spread-ms N\n"
        "  --consensus-heartbeat-ms N tune mesh timing (defaults: 150/300/50).\n"
        "  --consensus-history-id SHA256 --consensus-writer-epoch N bind a new\n"
        "  consensus record to one history and a durable fencing floor.\n"
        "  --consensus-prefix-signer UUID enables a read-only signed exact-prefix\n"
        "  challenge using an approved local federation node identity.\n"
        "  --consensus-allow-client-proposals enables app writes on this member;\n"
        "  omit on standby members except during a fenced emergency takeover.\n",
        argv0);
}

#define CONSENSUS_PEERS_MAX (QIHSE_CONSENSUS_MAX_MEMBERS - 1u)
#define CONSENSUS_GROUP_ID_MAX QIHSE_CONSENSUS_GROUP_ID_MAX

static bool parse_u16(const char* s, uint16_t* out);

typedef struct {
    qihse_consensus_mesh_peer_t mesh_peer;
    char qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
    char dsa_public_key_path[512];
    char wireguard_ipv4[64];
} daemon_consensus_peer_t;

typedef struct {
    char group_id[CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
    bool history_id_supplied;
    bool writer_epoch_supplied;
    qihse_uuid_t self;
    bool bootstrap_unadmitted;
    qihse_uuid_t members[QIHSE_CONSENSUS_MAX_MEMBERS];
    size_t member_count;
    char listen_ipv4[64];
    uint16_t port;
    uint32_t election_priority_delay_ms;
    uint32_t priority_tier;
    uint32_t wan_rtt_ms;
    bool enable_prevote;
    uint32_t election_timeout_base_ms;
    uint32_t election_timeout_spread_ms;
    uint32_t heartbeat_interval_ms;
    daemon_consensus_peer_t peers[CONSENSUS_PEERS_MAX];
    size_t peer_count;
} daemon_consensus_options_t;

static bool consensus_group_id_valid(const char* value) {
    if (!value || !*value || !strcmp(value, ".") || !strcmp(value, "..") ||
        strlen(value) > CONSENSUS_GROUP_ID_MAX) return false;
    for (const unsigned char* p = (const unsigned char*)value; *p; p++)
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' )) return false;
    return true;
}

static bool consensus_history_id_parse(const char* value, uint8_t out[32]) {
    if (!value || strlen(value) != 64u) return false;
    for (size_t i = 0; i < 32u; i++) {
        unsigned int high, low;
        char a = value[2u * i], b = value[2u * i + 1u];
        high = (a >= '0' && a <= '9') ? (unsigned int)(a - '0') :
               (a >= 'a' && a <= 'f') ? (unsigned int)(a - 'a' + 10) :
               (a >= 'A' && a <= 'F') ? (unsigned int)(a - 'A' + 10) : 16u;
        low = (b >= '0' && b <= '9') ? (unsigned int)(b - '0') :
              (b >= 'a' && b <= 'f') ? (unsigned int)(b - 'a' + 10) :
              (b >= 'A' && b <= 'F') ? (unsigned int)(b - 'A' + 10) : 16u;
        if (high > 15u || low > 15u) return false;
        out[i] = (uint8_t)((high << 4u) | low);
    }
    return true;
}

/* The brain and Operator command share the same fenced CT2 engine. */
static bool daemon_brain_generation(void* context, qihse_user_t* data,
                                    char generation[33]) {
    qihse_cluster_ownership_context_t* ownership = context;
    qihse_kv_ct_source_status_t status;
    if (!ownership || !ownership->store || !data ||
        !qihse_kv_ct_source_status(ownership->store, data, &status) || !status.admitted)
        return false;
    memcpy(generation, status.generation, 33u);
    return true;
}

static qihse_brain_transfer_result_t daemon_brain_transfer(void* context,
        qihse_user_t* control, qihse_user_t* data, const char* transfer_id,
        const char* expected_generation, const char* target_id,
        uint16_t first, uint16_t last, char* error, size_t error_cap) {
    qihse_cluster_ownership_context_t* ownership = context;
    char current_generation[33]; uint16_t target = QIHSE_CLUSTER_NODE_NONE;
    bool group_authoritative = ownership && ownership->range_reserve &&
        ownership->range_check_reserved && ownership->range_finalize &&
        ownership->range_check_finalized && ownership->range_authority_context;
    bool generation_matches = false;
    if (group_authoritative && ownership->topology && expected_generation) {
        qihse_cluster_node_t local;
        uint8_t slots[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES] = {0};
        char group_id[65] = {0};
        char lane_generation[33] = {0};
        if (last >= first && last < QIHSE_CONSENSUS_RANGE_SLOT_COUNT &&
            qihse_cluster_topology_get_node(ownership->topology,
                qihse_cluster_topology_local_node(ownership->topology), &local)) {
            for (uint32_t slot = first; slot <= last; ++slot)
                slots[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
            generation_matches = ct_group_authority_resolve(
                ((qihse_cluster_range_authority_t*)
                    ownership->range_authority_context)->group_context,
                data, local.id, slots,
                QIHSE_CLUSTER_RANGE_SOURCE_GROUP, group_id, lane_generation) &&
                strcmp(lane_generation, expected_generation) == 0;
        }
        OPENSSL_cleanse(slots, sizeof(slots));
    } else if (expected_generation &&
            daemon_brain_generation(context, data, current_generation)) {
        generation_matches = strcmp(current_generation, expected_generation) == 0;
    }
    if (!ownership || !ownership->topology || !ownership->resp_server ||
        !control || !qihse_auth_user_is_active(control) ||
        qihse_user_get_role(control) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(control) != QIHSE_TENANT_SYSTEM ||
        !expected_generation || !generation_matches ||
        !qihse_cluster_topology_find_node(ownership->topology, target_id, &target)) {
        if (error && error_cap) snprintf(error, error_cap, "CT2 adapter requires admitted exact generation and authenticated principals");
        return QIHSE_BRAIN_TRANSFER_REJECTED;
    }
    qihse_cluster_ownership_context_t request = *ownership;
    request.principal = control;
    request.data_principal = data;
    qihse_cluster_transfer_context_t transfer = {.ownership = &request, .chunk_bytes = 12u * 1024u};
    qihse_cluster_transfer_result_t result = qihse_cluster_transfer_range(&transfer,
        transfer_id, qihse_cluster_topology_local_node(ownership->topology), target,
        first, last, error, error_cap);
    switch (result) {
        case QIHSE_CLUSTER_TRANSFER_COMMITTED: return QIHSE_BRAIN_TRANSFER_COMMITTED;
        case QIHSE_CLUSTER_TRANSFER_PENDING: return QIHSE_BRAIN_TRANSFER_PENDING;
        case QIHSE_CLUSTER_TRANSFER_TOO_LARGE: return QIHSE_BRAIN_TRANSFER_TOO_LARGE;
        default: return QIHSE_BRAIN_TRANSFER_REJECTED;
    }
}

static bool consensus_ipv4_private(const char* value) {
    struct in_addr address;
    if (!value || inet_pton(AF_INET, value, &address) != 1) return false;
    uint32_t host = ntohl(address.s_addr);
    return (host >> 24) == 127u || (host >> 24) == 10u ||
           (host >> 20) == ((172u << 4) | 1u) ||
           (host >> 16) == ((192u << 8) | 168u);
}

static bool parse_consensus_peer(char* value, daemon_consensus_options_t* out) {
    if (!value || !out || out->peer_count >= CONSENSUS_PEERS_MAX) return false;
    char* fields[5] = {0};
    char* save = NULL;
    size_t n = 0;
    for (char* part = strtok_r(value, ":", &save); part; part = strtok_r(NULL, ":", &save)) {
        if (n >= 5u) return false;
        fields[n++] = part;
    }
    uint16_t port = 0;
    daemon_consensus_peer_t* peer = &out->peers[out->peer_count];
    if (n != 5u || !qihse_uuid_parse(fields[0], &peer->mesh_peer.member_uuid) ||
        qihse_uuid_is_nil(&peer->mesh_peer.member_uuid) || !*fields[1] ||
        strlen(fields[1]) > QIHSE_QKP_NODE_ID_LEN || !*fields[2] ||
        fields[2][0] == '/' || strlen(fields[2]) >= sizeof(peer->dsa_public_key_path) ||
        !*fields[3] || strlen(fields[3]) >= sizeof(peer->wireguard_ipv4) ||
        !parse_u16(fields[4], &port) || port == 0u) return false;
    snprintf(peer->qkp_node_id, sizeof(peer->qkp_node_id), "%s", fields[1]);
    snprintf(peer->dsa_public_key_path, sizeof(peer->dsa_public_key_path), "%s", fields[2]);
    snprintf(peer->wireguard_ipv4, sizeof(peer->wireguard_ipv4), "%s", fields[3]);
    peer->mesh_peer.qkp_node_id = peer->qkp_node_id;
    peer->mesh_peer.dsa_public_key_path = peer->dsa_public_key_path;
    peer->mesh_peer.wireguard_ipv4 = peer->wireguard_ipv4;
    peer->mesh_peer.port = port;
    out->peer_count++;
    return true;
}

static const char* consensus_options_error(const daemon_consensus_options_t* options,
                                          const char* data_dir,
                                          const char* qkp_node_id,
                                          bool pqc_require,
                                          bool replica_read_only,
                                          bool replication_source) {
    if (!options || !options->group_id[0]) return "missing group ID";
    if (options->history_id_supplied != options->writer_epoch_supplied ||
        (options->history_id_supplied &&
         !qihse_consensus_history_identity_valid(
            options->group_id, options->history_id,
            options->writer_epoch_floor)))
        return "history ID and writer epoch must be supplied together";
    if (options->member_count < 2u || options->member_count > QIHSE_CONSENSUS_MAX_MEMBERS)
        return "baseline member count must be between 2 and the configured maximum";
    if (options->peer_count == 0u)
        return "at least one authenticated consensus peer is required";
    if (!options->port) return "consensus port is missing";
    uint32_t election_base = options->election_timeout_base_ms ?
        options->election_timeout_base_ms : 150u;
    uint32_t election_spread = options->election_timeout_spread_ms ?
        options->election_timeout_spread_ms : 300u;
    uint32_t heartbeat = options->heartbeat_interval_ms ?
        options->heartbeat_interval_ms : 50u;
    if (election_spread < options->member_count)
        return "election spread must cover all baseline members";
    if (heartbeat >= election_base)
        return "heartbeat interval must be below election base timeout";
    if (!consensus_ipv4_private(options->listen_ipv4)) return "listen address is not RFC1918 IPv4";
    if (!data_dir || !*data_dir) return "--dir is required";
    if (!qkp_node_id || !*qkp_node_id) return "--pqc-node-id is required";
    if (!pqc_require) return "--pqc-require is required";
    if (replica_read_only || replication_source) return "consensus cannot be combined with read-only replica pull";
    bool self_found = false;
    for (size_t i = 0; i < options->member_count; i++) {
        if (qihse_uuid_equal(&options->members[i], &options->self)) self_found = true;
        for (size_t j = i + 1u; j < options->member_count; j++)
            if (qihse_uuid_equal(&options->members[i], &options->members[j]))
                return "duplicate member UUID";
    }
    if (!self_found && !options->bootstrap_unadmitted)
        return "self UUID is absent from the member set";
    for (size_t i = 0; i < options->peer_count; i++) {
        const daemon_consensus_peer_t* peer = &options->peers[i];
        if (qihse_uuid_equal(&peer->mesh_peer.member_uuid, &options->self))
            return "peer list contains the local member";
        if (!consensus_ipv4_private(peer->wireguard_ipv4))
            return "peer address is not RFC1918 IPv4";
        /* A peer may be provisioned ahead of a logged ADD, or omitted after
         * a logged REMOVE. The durable baseline still comes from --member. */
        if (!strcmp(peer->qkp_node_id, qkp_node_id)) return "peer reuses the local QKP node ID";
        for (size_t j = i + 1u; j < options->peer_count; j++) {
            const daemon_consensus_peer_t* other = &options->peers[j];
            if (qihse_uuid_equal(&peer->mesh_peer.member_uuid, &other->mesh_peer.member_uuid))
                return "duplicate peer member UUID";
            if (!strcmp(peer->qkp_node_id, other->qkp_node_id))
                return "duplicate peer QKP node ID";
            if (!strcmp(peer->wireguard_ipv4, other->wireguard_ipv4) &&
                peer->mesh_peer.port == other->mesh_peer.port)
                return "duplicate peer endpoint";
        }
    }
    return NULL;
}

/* ── One-way, QKP-protected replication puller ───────────────────────────── */
#define REPL_AE_MAX_KEYS 10000u
#define REPL_AE_GLOBS_MAX 64u
#define REPL_AE_VALUE_MAX (16u * 1024u * 1024u)
#define REPL_AE_SNAPSHOT_READ_MAX (512u * 1024u)

typedef struct {
    int fd;
    char err[256];
    char last[128]; /* most recent simple (+/-) reply line */
    /* QKP1 may return one plaintext record up to QIHSE_QKP_MAX_PAYLOAD. */
    unsigned char buf[QIHSE_QKP_MAX_PAYLOAD];
    size_t buf_len;
    size_t buf_pos;
    qihse_qkp_session_t* qkp; /* anti-entropy RESP always runs inside QKP1 */
    qihse_qkp_config_t qkp_config; /* borrowed paths/anchors live for daemon lifetime */
} mini_resp_t;

static bool mini_resp_command(mini_resp_t* c, size_t argc, const char* const* argv);
static void mini_resp_close(mini_resp_t* c);

static bool socket_send_all(int fd, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    while (len) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n; len -= (size_t)n;
    }
    return true;
}

static bool socket_recv_all(int fd, void* data, size_t len) {
    unsigned char* p = (unsigned char*)data;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n; len -= (size_t)n;
    }
    return true;
}

/* Connect to an I2P destination only through the local i2pd SOCKS5 proxy.
 * The proxy address is deliberately loopback-only; there is no direct-host
 * fallback if SOCKS negotiation or remote-name resolution fails. */
static int connect_i2p_socks5(const char* host, uint16_t port, uint16_t socks_port) {
    if (!host || !*host || strlen(host) > 255u || socks_port == 0u) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in proxy;
    memset(&proxy, 0, sizeof(proxy));
    proxy.sin_family = AF_INET;
    proxy.sin_port = htons(socks_port);
    proxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&proxy, sizeof(proxy)) != 0) { close(fd); return -1; }

    const uint8_t greeting[] = {0x05u, 0x01u, 0x00u};
    uint8_t reply[4];
    if (!socket_send_all(fd, greeting, sizeof(greeting)) || !socket_recv_all(fd, reply, 2u) ||
        reply[0] != 0x05u || reply[1] != 0x00u) { close(fd); return -1; }
    uint8_t request[4u + 1u + 255u + 2u];
    size_t host_len = strlen(host);
    request[0] = 0x05u; request[1] = 0x01u; request[2] = 0x00u; request[3] = 0x03u;
    request[4] = (uint8_t)host_len;
    memcpy(request + 5u, host, host_len);
    request[5u + host_len] = (uint8_t)(port >> 8);
    request[6u + host_len] = (uint8_t)port;
    if (!socket_send_all(fd, request, 7u + host_len) || !socket_recv_all(fd, reply, sizeof(reply)) ||
        reply[0] != 0x05u || reply[1] != 0x00u || reply[2] != 0x00u) { close(fd); return -1; }
    size_t bound_len = 0u;
    if (reply[3] == 0x01u) bound_len = 4u;
    else if (reply[3] == 0x04u) bound_len = 16u;
    else if (reply[3] == 0x03u) {
        uint8_t n = 0u;
        if (!socket_recv_all(fd, &n, 1u)) { close(fd); return -1; }
        bound_len = n;
    } else { close(fd); return -1; }
    uint8_t discard[16u + 2u];
    if (bound_len > sizeof(discard) - 2u ||
        !socket_recv_all(fd, discard, bound_len + 2u)) { close(fd); return -1; }
    return fd;
}

static int mini_resp_connect_mode(mini_resp_t* c, const char* host, uint16_t port,
                                  const qihse_qkp_config_t* qkp,
                                  bool via_i2p, uint16_t socks_port) {
    if (!c || !qkp || !qkp->dsa_key_path || !qkp->trusted_pubs || qkp->trusted_count == 0u) return -1;
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->qkp_config = *qkp;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int fd = -1;
    if (via_i2p) {
        fd = connect_i2p_socks5(host, port, socks_port);
    } else {
        if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd >= 0) {
            /* Replication snapshot exports can scan a large source store
             * between REPL.SNAPSHOT.BEGIN and the first READ; keep the
             * socket alive well past the export (5s was too short). */
            struct timeval tv = {60, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) { close(fd); fd = -1; }
        }
        freeaddrinfo(res);
    }
    if (fd < 0) return -1;
    c->fd = fd;
    /* No cleartext fallback: the auth secret and every subsequent command
     * must be protected by the daemon's signed, mutually authenticated QKP1
     * session. */
    if (qihse_qkp_client_negotiate(fd, &c->qkp_config, &c->qkp) != QIHSE_QKP_SECURE || !c->qkp) {
        close(fd);
        c->fd = -1;
        return -1;
    }
    return fd;
}

static int mini_resp_connect_i2p(mini_resp_t* c, const char* destination, uint16_t port,
                                 uint16_t socks_port, const qihse_qkp_config_t* qkp) {
    return mini_resp_connect_mode(c, destination, port, qkp, true, socks_port);
}

static void mini_resp_close(mini_resp_t* c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    qihse_qkp_session_free(c->qkp);
    c->qkp = NULL;
}

static bool mini_resp_write(mini_resp_t* c, const void* data, size_t len) {
    if (!c || c->fd < 0 || !c->qkp || (!data && len != 0u)) return false;
    return qihse_qkp_send_sealed(c->qkp, c->fd, data, len);
}

static ssize_t mini_resp_read(mini_resp_t* c, void* data, size_t cap) {
    if (!c || c->fd < 0 || !c->qkp || !data || cap == 0u) return -1;
    return qihse_qkp_recv_sealed(c->qkp, c->fd, (uint8_t*)data, cap);
}

static bool mini_resp_send(mini_resp_t* c, size_t argc, const char* const* argv) {
    char head[64];
    int len = snprintf(head, sizeof(head), "*%zu\r\n", argc);
    if (len <= 0 || (size_t)len >= sizeof(head) || !mini_resp_write(c, head, (size_t)len)) return false;
    for (size_t i = 0; i < argc; i++) {
        size_t alen = strlen(argv[i]);
        len = snprintf(head, sizeof(head), "$%zu\r\n", alen);
        if (len <= 0 || (size_t)len >= sizeof(head) || !mini_resp_write(c, head, (size_t)len)) return false;
        if (!mini_resp_write(c, argv[i], alen) || !mini_resp_write(c, "\r\n", 2u)) return false;
    }
    return true;
}

static int mini_resp_read_line(mini_resp_t* c, char* buf, size_t cap) {
    size_t used = 0;
    while (used + 1u < cap) {
        if (c->buf_pos >= c->buf_len) {
            ssize_t r = mini_resp_read(c, c->buf, sizeof(c->buf));
            if (r <= 0) return -1;
            c->buf_len = (size_t)r;
            c->buf_pos = 0;
        }
        char ch = (char)c->buf[c->buf_pos++];
        if (ch == '\n') {
            if (used == 0u || buf[used - 1u] != '\r') return -1;
            used--;
            buf[used] = '\0';
            return (int)used;
        }
        buf[used++] = ch;
    }
    return -1;
}

/* Buffered bulk read into caller memory (used for value payloads). */
static bool mini_resp_read_exact(mini_resp_t* c, char* out, size_t len) {
    size_t got = 0;
    while (got < len) {
        if (c->buf_pos < c->buf_len) {
            size_t take = c->buf_len - c->buf_pos;
            if (take > len - got) take = len - got;
            memcpy(out + got, c->buf + c->buf_pos, take);
            c->buf_pos += take;
            got += take;
            continue;
        }
        ssize_t r = mini_resp_read(c, c->buf, sizeof(c->buf));
        if (r <= 0) return false;
        c->buf_len = (size_t)r;
        c->buf_pos = 0;
    }
    return true;
}

/* Execute a command. Replies:
 *   MINI_REP_SIMPLE: +line (buf holds payload) or -line (buf holds error)
 *   MINI_REP_BULK:   out_value = malloc'd byte buffer (NULL for nil), with
 *                    its exact length in out_value_len when requested
 *   MINI_REP_ARRAY:  out_items/out_count = malloc'd array of malloc'd strings
 *   MINI_REP_ERROR:  transport/protocol failure (c->err set) */
#define MINI_REP_SIMPLE 1
#define MINI_REP_BULK   2
#define MINI_REP_ARRAY  3
#define MINI_REP_ERROR  4
#define MINI_RESP_ARRAY_MAX_WIRE ((size_t)128u << 20)

static void mini_resp_free_array(char** items, size_t count) {
    if (!items) return;
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

static int mini_resp_do(mini_resp_t* c, size_t argc, const char* const* argv,
                        char** out_value, size_t* out_value_len,
                        char*** out_items, size_t* out_count) {
    if (out_value) *out_value = NULL;
    if (out_value_len) *out_value_len = 0u;
    if (out_items) *out_items = NULL;
    if (out_count) *out_count = 0;
    if (!mini_resp_send(c, argc, argv)) {
        snprintf(c->err, sizeof(c->err), "send failed");
        return MINI_REP_ERROR;
    }
    char line[128];
    if (mini_resp_read_line(c, line, sizeof(line)) < 0) {
        snprintf(c->err, sizeof(c->err), "read failed");
        return MINI_REP_ERROR;
    }
    if (line[0] == '+' || line[0] == '-') {
        snprintf(c->last, sizeof(c->last), "%s", line);
        return MINI_REP_SIMPLE;
    }
    if (line[0] == '$') {
        if (!out_value) return MINI_REP_BULK;
        long long len = strtoll(line + 1, NULL, 10);
        if (len < 0) return MINI_REP_BULK; /* nil */
        if (len > (16 << 20)) { snprintf(c->err, sizeof(c->err), "reply too large"); return MINI_REP_ERROR; }
        char* v = malloc((size_t)len + 1u);
        if (!v) { snprintf(c->err, sizeof(c->err), "oom"); return MINI_REP_ERROR; }
        if (!mini_resp_read_exact(c, v, (size_t)len)) {
            free(v); snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
        }
        char tail[2];
        if (!mini_resp_read_exact(c, tail, 2u) || tail[0] != '\r' || tail[1] != '\n') {
            free(v); snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
        }
        v[len] = '\0';
        *out_value = v;
        if (out_value_len) *out_value_len = (size_t)len;
        return MINI_REP_BULK;
    }
    if (line[0] == '*' && out_items && out_count) {
        long long count = strtoll(line + 1, NULL, 10);
        if (count < 0 || count > 100000) { snprintf(c->err, sizeof(c->err), "bad array"); return MINI_REP_ERROR; }
        char** items = calloc(count ? (size_t)count : 1u, sizeof(char*));
        if (!items) { snprintf(c->err, sizeof(c->err), "oom"); return MINI_REP_ERROR; }
        size_t array_bytes = 0u;
        for (long long i = 0; i < count; i++) {
            char sub[64];
            if (mini_resp_read_line(c, sub, sizeof(sub)) < 0 || sub[0] != '$') {
                mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "bad array item");
                return MINI_REP_ERROR;
            }
            long long len = strtoll(sub + 1, NULL, 10);
            if (len < 0 || len > REPL_AE_VALUE_MAX ||
                (size_t)len > MINI_RESP_ARRAY_MAX_WIRE - array_bytes) {
                mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "bad item length");
                return MINI_REP_ERROR;
            }
            array_bytes += (size_t)len;
            items[i] = malloc((size_t)len + 1u);
            if (!items[i]) { mini_resp_free_array(items, (size_t)i); snprintf(c->err, sizeof(c->err), "oom"); return MINI_REP_ERROR; }
            if (!mini_resp_read_exact(c, items[i], (size_t)len)) {
                free(items[i]); mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
            }
            items[i][len] = '\0';
            char tail[2];
            if (!mini_resp_read_exact(c, tail, 2u) || tail[0] != '\r' || tail[1] != '\n') {
                free(items[i]); mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
            }
        }
        *out_items = items;
        *out_count = (size_t)count;
        return MINI_REP_ARRAY;
    }
    snprintf(c->err, sizeof(c->err), "unexpected reply");
    return MINI_REP_ERROR;
}

/* Fire-and-verify form for AUTH/SET: true on +OK. */
static bool mini_resp_command(mini_resp_t* c, size_t argc, const char* const* argv) {
    return mini_resp_do(c, argc, argv, NULL, NULL, NULL, NULL) == MINI_REP_SIMPLE && c->last[0] == '+';
}

typedef struct {
    qihse_resp_server_t* server;
    const char* source_host;   /* pinned I2P destination or mesh address */
    uint16_t source_port;
    uint16_t socks_port;       /* local loopback i2pd SOCKS5 */
    bool source_via_i2p;
    const char* transport_name;
    qihse_user_t* replica_principal;
    const qihse_qkp_config_t* qkp; /* required signed/sealed peer transport */
    const char* data_dir;
    uint32_t interval_seconds;
    volatile sig_atomic_t* stop;
    qihse_cluster_maintenance_t* maintenance_gate;
} ae_ctx_t;

static bool parse_u64_decimal(const char* text, uint64_t* value) {
    if (!text || !*text || !value) return false;
    for (const unsigned char* p = (const unsigned char*)text; *p; p++)
        if (*p < '0' || *p > '9') return false;
    errno = 0; char* end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || !end || *end) return false;
    *value = (uint64_t)parsed;
    return true;
}

static bool fd_write_all(int fd, const char* data, size_t len) {
    size_t done = 0u;
    while (done < len) {
        ssize_t n = write(fd, data + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool replica_snapshot_pull(ae_ctx_t* ae, mini_resp_t* source, const char* glob) {
    const char* begin_argv[3] = {"REPL.SNAPSHOT.BEGIN", glob, NULL};
    char** manifest = NULL; size_t manifest_count = 0u;
    int reply = mini_resp_do(source, 2u, begin_argv, NULL, NULL, &manifest, &manifest_count);
    uint64_t snapshot_size = 0u, source_seq = 0u;
    bool ok = reply == MINI_REP_ARRAY && manifest_count == 2u &&
        parse_u64_decimal(manifest[0], &snapshot_size) &&
        parse_u64_decimal(manifest[1], &source_seq) && snapshot_size <= (uint64_t)INT64_MAX;
    mini_resp_free_array(manifest, manifest_count);
    if (!ok) return false;

    const char* dir = ae->data_dir;
    if (!dir || !*dir) dir = getenv("QIHSE_DATA_DIR");
    if (!dir || !*dir) {
        if (access("/opt/qihse-data", R_OK | W_OK) == 0) dir = "/opt/qihse-data";
        else if (access("/var/lib/qihse", R_OK | W_OK) == 0) dir = "/var/lib/qihse";
        else dir = "/opt/qihse-data";
    }
    if (!mkdirs(dir)) {
        const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
        (void)mini_resp_command(source, 1u, end_argv);
        return false;
    }
    char incoming[4096];
    int path_len = snprintf(incoming, sizeof(incoming), "%s%sqihse-repl-snapshot-XXXXXX",
        dir, dir[strlen(dir) - 1u] == '/' ? "" : "/");
    if (path_len <= 0 || (size_t)path_len >= sizeof(incoming)) return false;
    int fd = mkstemp(incoming);
    if (fd < 0) {
        const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
        (void)mini_resp_command(source, 1u, end_argv);
        return false;
    }
    if (fchmod(fd, 0600) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        close(fd); (void)unlink(incoming);
        const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
        (void)mini_resp_command(source, 1u, end_argv);
        return false;
    }
    uint64_t offset = 0u;
    while (ok && offset < snapshot_size) {
        uint64_t request_len = snapshot_size - offset;
        if (request_len > REPL_AE_SNAPSHOT_READ_MAX) request_len = REPL_AE_SNAPSHOT_READ_MAX;
        char offset_buf[32], len_buf[32];
        snprintf(offset_buf, sizeof(offset_buf), "%llu", (unsigned long long)offset);
        snprintf(len_buf, sizeof(len_buf), "%llu", (unsigned long long)request_len);
        const char* read_argv[3] = {"REPL.SNAPSHOT.READ", offset_buf, len_buf};
        char* chunk = NULL;
        size_t chunk_len = 0u;
        reply = mini_resp_do(source, 3u, read_argv, &chunk, &chunk_len, NULL, NULL);
        ok = reply == MINI_REP_BULK && chunk && chunk_len == (size_t)request_len &&
             fd_write_all(fd, chunk, chunk_len);
        free(chunk);
        if (ok) offset += request_len;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (ok) ok = qihse_resp_server_repl_snapshot_install_local(ae->server, source->qkp,
        glob, incoming, source_seq, ae->replica_principal);
    (void)unlink(incoming);
    const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
    if (!mini_resp_command(source, 1u, end_argv)) ok = false;
    return ok;
}

static bool replica_pull_glob(ae_ctx_t* ae, mini_resp_t* source, const char* glob,
                              uint64_t* applied_total) {
    bool snapshot_installed = false;
    if (!qihse_resp_server_repl_snapshot_installed_local(ae->server, source->qkp,
            glob, ae->replica_principal, &snapshot_installed)) return false;
    if (!snapshot_installed && !replica_snapshot_pull(ae, source, glob)) return false;
    uint64_t cursor = 0u;
    if (!qihse_resp_server_repl_cursor_local(ae->server, source->qkp, glob,
            ae->replica_principal, &cursor)) return false;
    uint64_t start_cursor = cursor;
    while (!*ae->stop && *applied_total < REPL_AE_MAX_KEYS) {
        char since_buf[32];
        snprintf(since_buf, sizeof(since_buf), "%llu", (unsigned long long)cursor);
        /* One row keeps even a maximum-sized 16 MiB value within the
         * bounded RESP delta reply. */
        const char* argv[4] = {"REPL.DELTA", glob, since_buf, "1"};
        char** fields = NULL; size_t field_count = 0u;
        int reply = mini_resp_do(source, 4u, argv, NULL, NULL, &fields, &field_count);
        if (reply != MINI_REP_ARRAY || field_count < 2u) {
            mini_resp_free_array(fields, field_count);
            return false;
        }
        uint64_t page_cursor = 0u, row_count_u64 = 0u;
        bool valid = parse_u64_decimal(fields[0], &page_cursor) &&
                     parse_u64_decimal(fields[1], &row_count_u64) &&
                     row_count_u64 <= 1u && field_count == 2u + (size_t)row_count_u64 * 7u;
        if (!valid || page_cursor < cursor) {
            mini_resp_free_array(fields, field_count);
            return false;
        }
        if (row_count_u64 == 0u) {
            valid = page_cursor == cursor;
            mini_resp_free_array(fields, field_count);
            return valid;
        }
        uint64_t last_seq = cursor;
        for (size_t j = 0; valid && j < (size_t)row_count_u64; j++) {
            size_t base = 2u + j * 7u;
            uint64_t seq = 0u, class_u64 = 0u, sci_u64 = 0u, expiry = 0u;
            bool tombstone = strcmp(fields[base], "D") == 0;
            valid = (tombstone || strcmp(fields[base], "S") == 0) &&
                    parse_u64_decimal(fields[base + 1u], &seq) && seq > last_seq &&
                    parse_u64_decimal(fields[base + 2u], &class_u64) && class_u64 <= UINT16_MAX &&
                    parse_u64_decimal(fields[base + 3u], &sci_u64) && sci_u64 <= UINT16_MAX &&
                    parse_u64_decimal(fields[base + 4u], &expiry) && fields[base + 5u][0] != '\0' &&
                    fnmatch(glob, fields[base + 5u], 0) == 0 &&
                    (!tombstone || (fields[base + 6u][0] == '\0' && expiry == 0u));
            if (!valid) break;
            qihse_kv_replica_record_t record = {
                .key = fields[base + 5u], .value = tombstone ? NULL : fields[base + 6u],
                .change_seq = seq, .classification = (uint16_t)class_u64,
                .sci_compartment = (uint16_t)sci_u64, .expire_time_ms = expiry,
                .tombstone = tombstone
            };
            if (!qihse_resp_server_repl_apply_local(ae->server, source->qkp, glob,
                    &record, ae->replica_principal)) {
                valid = false;
                break;
            }
            last_seq = seq;
            (*applied_total)++;
        }
        if (valid && page_cursor != last_seq) valid = false;
        mini_resp_free_array(fields, field_count);
        if (!valid) return false;
        char ack_seq[32];
        snprintf(ack_seq, sizeof(ack_seq), "%llu", (unsigned long long)last_seq);
        const char* ack_argv[3] = {"REPL.ACK", glob, ack_seq};
        if (!mini_resp_command(source, 3u, ack_argv)) return false;
        cursor = last_seq;
        if (row_count_u64 == 0u) return true;
    }
    return cursor >= start_cursor;
}

static void* ae_main(void* argument) {
    ae_ctx_t* ae = (ae_ctx_t*)argument;
    while (!__atomic_load_n(ae->stop, __ATOMIC_ACQUIRE)) {
        for (uint32_t slept = 0; slept < ae->interval_seconds &&
             !__atomic_load_n(ae->stop, __ATOMIC_ACQUIRE); slept++) {
            struct timespec ts = {1, 0};
            nanosleep(&ts, NULL);
        }
        if (__atomic_load_n(ae->stop, __ATOMIC_ACQUIRE)) break;
        if (ae->maintenance_gate &&
            !qihse_cluster_maintenance_enter(ae->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA))
            continue;
        char globs[REPL_AE_GLOBS_MAX][128];
        size_t glob_count = qihse_resp_server_repl_list(ae->server, globs, NULL, REPL_AE_GLOBS_MAX);
        if (glob_count == 0u) {
            if (ae->maintenance_gate)
                qihse_cluster_maintenance_leave(ae->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);
            continue;
        }
        if (ae->source_host) {
            mini_resp_t source;
            int connected = ae->source_via_i2p
                ? mini_resp_connect_i2p(&source, ae->source_host, ae->source_port,
                    ae->socks_port, ae->qkp)
                : mini_resp_connect_mode(&source, ae->source_host, ae->source_port,
                    ae->qkp, false, 0u);
            bool peer_ok = connected >= 0 && qihse_qkp_client_session_is_replication_peer(
                source.qkp, ae->qkp->replication_peer_node_id,
                ae->qkp->replication_peer_dsa_pub_path);
            if (!peer_ok) {
                if (connected >= 0) mini_resp_close(&source);
                for (size_t i = 0; i < glob_count; i++)
                    qihse_resp_server_repl_note(ae->server, globs[i], ae->source_host,
                        0u, 0u, UINT64_MAX, UINT64_MAX, false);
                fprintf(stderr, "qihse-cluster-daemon: replica pull: protected source connection or identity pin failed\n");
            } else {
                uint64_t total = 0u;
                bool all_ok = true;
                for (size_t i = 0; i < glob_count && !*ae->stop && total < REPL_AE_MAX_KEYS; i++) {
                    uint64_t before = total;
                    bool ok = replica_pull_glob(ae, &source, globs[i], &total);
                    qihse_resp_server_repl_note(ae->server, globs[i], ae->source_host,
                        total - before, 0u, UINT64_MAX, UINT64_MAX, ok);
                    if (!ok) { all_ok = false; break; }
                }
                mini_resp_close(&source);
                fprintf(stderr, "qihse-cluster-daemon: replica pull: %llu row(s) from pinned %s source (%s)\n",
                        (unsigned long long)total, ae->transport_name ? ae->transport_name : (ae->source_via_i2p ? "I2P" : "direct"), all_ok ? "ok" : "stopped on error");
                if (!all_ok) {
                    fprintf(stderr, "qihse-cluster-daemon: replica pull failure detail: last='%s' err='%s'\n",
                            source.last, source.err);
                }
            }
        }
        if (ae->maintenance_gate)
            qihse_cluster_maintenance_leave(ae->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);

    }
    return NULL;
}

typedef struct {
    qihse_kv_store_t* store;
    qihse_resp_server_t* server;
    qihse_cluster_ownership_context_t* ownership;
    qihse_cluster_maintenance_t* maintenance_gate;
    qihse_user_t* operator_user;
    qihse_user_t* replication_user;
    const qihse_qkp_config_t* qkp;
    const char* source_host;
    uint16_t source_port;
    const char* generation;
    char generation_runtime[33];
    bool learn_generation;
    const qihse_ct_group_config_t* group_config;
    qihse_qkp_config_t group_qkp_runtime;
    char group_peer_id_runtime[QIHSE_QKP_NODE_ID_LEN + 1u];
    char group_source_host_runtime[QIHSE_CLUSTER_HOST_LEN + 1u];
    char group_generation_runtime[33];
    volatile sig_atomic_t* stop;
    unsigned char ct_owner_token[QIHSE_KV_CT_TOKEN_BYTES];
    const char* failure_stage;
} ct1_pull_ctx_t;

static bool ct1_stopping(const ct1_pull_ctx_t* ctx) {
    return !ctx || !ctx->stop ||
        __atomic_load_n(ctx->stop, __ATOMIC_ACQUIRE) != 0;
}

static bool ct1_parse_hex32(const char* text, unsigned char out[32]) {
    if (!text || strlen(text) != 64u) return false;
    for (size_t i = 0u; i < 32u; ++i) {
        unsigned char a = (unsigned char)text[2u * i];
        unsigned char b = (unsigned char)text[2u * i + 1u];
        unsigned hi = a >= '0' && a <= '9' ? (unsigned)(a - '0') :
            (a >= 'a' && a <= 'f' ? a - 'a' + 10u : 255u);
        unsigned lo = b >= '0' && b <= '9' ? (unsigned)(b - '0') :
            (b >= 'a' && b <= 'f' ? b - 'a' + 10u : 255u);
        if (hi > 15u || lo > 15u) return false;
        out[i] = (unsigned char)((hi << 4u) | lo);
    }
    return true;
}

static bool ct1_write_all(int fd, const void* data, size_t len);
static bool ct1_simple_ok(mini_resp_t* peer, size_t argc,
                          const char* const* argv);

static void ct1_format_hex32(const unsigned char digest[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32u; ++i) {
        out[2u * i] = hex[digest[i] >> 4u];
        out[2u * i + 1u] = hex[digest[i] & 15u];
    }
    out[64] = '\0';
}

static uint32_t ct1_read_be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24u) | ((uint32_t)p[1] << 16u) |
        ((uint32_t)p[2] << 8u) | (uint32_t)p[3];
}

/* Replication retains original signed history across promotions. Historical
 * certificate signers/successors differ from the current data connection, so
 * bind each tuple to its own committed common reservation instead of today's
 * lane role. Prepared/aborted certificates are metadata only; only FINAL
 * evidence is eligible for ownership adoption. */
static bool ct1_group_certificate_authorized(ct1_pull_ctx_t* ctx,
        const qihse_cluster_bus_ct1_promotion_update_v2_t* update) {
    qihse_cluster_ownership_context_t* ownership = ctx ? ctx->ownership : NULL;
    qihse_cluster_range_authority_t* authority = ownership
        ? ownership->range_authority_context : NULL;
    if (!ctx || !ctx->group_config || !update || !authority || !authority->mesh ||
        !ownership->principal || !qihse_auth_user_is_active(ownership->principal) ||
        qihse_user_get_role(ownership->principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(ownership->principal) != QIHSE_TENANT_SYSTEM ||
        strcmp(update->lane_id, ctx->group_config->lane_id)) return false;
    qihse_consensus_range_request_t request = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    bool ok = qihse_consensus_mesh_range_lookup_user(authority->mesh,
            ownership->principal, update->base.transfer_id,
            &request, &grant, &decision, &phase) &&
        (phase == QIHSE_RANGE_PHASE_RESERVED || phase == QIHSE_RANGE_PHASE_FINALIZED ||
         phase == QIHSE_RANGE_PHASE_ABORTED) &&
        request.op == QIHSE_RANGE_OP_PROMOTION && grant.reserve_index &&
        grant.grant_epoch == update->base.config_epoch &&
        !strcmp(request.source_group_id, update->lane_id) &&
        !strcmp(request.target_group_id, update->lane_id) &&
        !strcmp(request.source_topology_id, update->base.source_id) &&
        !strcmp(request.target_topology_id, update->base.target_id) &&
        !strcmp(request.source_qkp_id, update->base.source_qkp_id) &&
        !strcmp(request.target_qkp_id, update->base.target_qkp_id) &&
        !strcmp(request.source_generation, update->base.generation) &&
        !strcmp(request.target_generation, update->base.next_generation) &&
        !strcmp(request.successor_topology_id, update->base.successor_id) &&
        !strcmp(request.successor_qkp_id, update->base.successor_qkp_id) &&
        request.durable_cursor == update->base.durable_cursor &&
        CRYPTO_memcmp(request.slots, update->base.slot_bitmap,
            sizeof(request.slots)) == 0;
    if (ok && phase == QIHSE_RANGE_PHASE_FINALIZED)
        ok = decision.decision_index && decision.grant_epoch == grant.grant_epoch &&
            CRYPTO_memcmp(decision.evidence_digest, update->event_digest, 32u) == 0;
    OPENSSL_cleanse(&request, sizeof(request));
    OPENSSL_cleanse(&grant, sizeof(grant));
    OPENSSL_cleanse(&decision, sizeof(decision));
    return ok;
}

static bool ct1_group_pull_certificates(ct1_pull_ctx_t* ctx, mini_resp_t* source,
        const unsigned char source_head[32]) {
    if (!ctx || !source || !source_head ||
        !ctx->group_config || !ctx->server || !ctx->replication_user) return false;
    qihse_cluster_bus_t* bus = qihse_resp_server_bus(ctx->server);
    if (!bus) return false;

    qihse_kv_ct_lane_status_t receiver;
    memset(&receiver, 0, sizeof(receiver));
    if (!qihse_kv_ct_lane_status(ctx->store, ctx->operator_user,
            ctx->group_config->lane_id, &receiver) ||
        receiver.mode != QIHSE_KV_CT_LANE_RECEIVER ||
        strcmp(receiver.generation, ctx->generation) != 0 ||
        strcmp(receiver.source_id, ctx->qkp->replication_peer_node_id) != 0)
        return false;

    unsigned char cursor[32];
    memcpy(cursor, receiver.certificate_head_digest, sizeof(cursor));
    size_t batches = 0u;
    bool ok = true;
    while (CRYPTO_memcmp(cursor, source_head, 32u) != 0 &&
           !ct1_stopping(ctx) && batches++ < 4096u) {
        char after_hex[65];
        ct1_format_hex32(cursor, after_hex);
        const char* argv[] = {"REPL.CT1", "CERTPAGE",
            ctx->group_config->lane_id, after_hex, "65536"};
        char* page = NULL;
        size_t page_len = 0u;
        int reply = mini_resp_do(source, 5u, argv, &page, &page_len, NULL, NULL);
        OPENSSL_cleanse(after_hex, sizeof(after_hex));
        if (reply != MINI_REP_BULK || !page || !page_len) {
            free(page);
            ok = false;
            break;
        }
        size_t off = 0u;
        bool progressed = false;
        while (ok && off < page_len) {
            if (page_len - off < 36u) { ok = false; break; }
            const unsigned char* bytes = (const unsigned char*)page;
            uint32_t cert_len = ct1_read_be32(bytes + off);
            const unsigned char* digest = bytes + off + 4u;
            off += 36u;
            if (!cert_len || cert_len > QIHSE_CLUSTER_BUS_CT1_CERTIFICATE_MAX ||
                cert_len > page_len - off) { ok = false; break; }
            qihse_cluster_bus_ct1_promotion_update_v2_t update;
            qihse_uuid_t signer;
            memset(&update, 0, sizeof(update));
            memset(&signer, 0, sizeof(signer));
            ok = qihse_cluster_bus_ct1_certificate_verify(bus, bytes + off,
                    cert_len, &update, &signer) &&
                ct1_group_certificate_authorized(ctx, &update);
            unsigned char appended[32] = {0};
            if (ok) ok = qihse_kv_ct_lane_certificate_append(ctx->store,
                ctx->replication_user, ctx->group_config->lane_id,
                ctx->generation, bytes + off, cert_len, appended) &&
                CRYPTO_memcmp(appended, digest, sizeof(appended)) == 0;
            if (ok) {
                memcpy(cursor, appended, sizeof(cursor));
                progressed = true;
            }
            OPENSSL_cleanse(appended, sizeof(appended));
            OPENSSL_cleanse(&update, sizeof(update));
            OPENSSL_cleanse(&signer, sizeof(signer));
            off += cert_len;
        }
        if (off != page_len || !progressed) ok = false;
        OPENSSL_cleanse(page, page_len);
        free(page);
        if (!ok) break;
    }
    if (batches >= 4096u && CRYPTO_memcmp(cursor, source_head, 32u) != 0)
        ok = false;
    if (ok && CRYPTO_memcmp(cursor, source_head, 32u) != 0) ok = false;

    if (ok) {
        qihse_kv_ct_lane_status_t after;
        memset(&after, 0, sizeof(after));
        ok = qihse_kv_ct_lane_status(ctx->store, ctx->operator_user,
                ctx->group_config->lane_id, &after) &&
            after.mode == QIHSE_KV_CT_LANE_RECEIVER &&
            CRYPTO_memcmp(after.certificate_head_digest, source_head, 32u) == 0;
        OPENSSL_cleanse(&after, sizeof(after));
    }
    if (ok) {
        char digest_hex[65];
        ct1_format_hex32(source_head, digest_hex);
        const char* ack_argv[] = {"REPL.CT1", "CERTACK",
            ctx->group_config->lane_id, ctx->generation, digest_hex};
        ok = ct1_simple_ok(source, 5u, ack_argv);
        OPENSSL_cleanse(digest_hex, sizeof(digest_hex));
    }
    if (ok) {
        qihse_kv_ct_lane_status_t after_ack;
        memset(&after_ack, 0, sizeof(after_ack));
        ok = qihse_kv_ct_lane_status(ctx->store, ctx->operator_user,
                ctx->group_config->lane_id, &after_ack) &&
            CRYPTO_memcmp(after_ack.certificate_head_digest, source_head, 32u) == 0;
        OPENSSL_cleanse(&after_ack, sizeof(after_ack));
    }
    OPENSSL_cleanse(cursor, sizeof(cursor));
    OPENSSL_cleanse(&receiver, sizeof(receiver));
    return ok;
}

static bool ct1_group_pull_once(ct1_pull_ctx_t* ctx) {
    const qihse_ct_group_config_t* group = ctx->group_config;
    ctx->failure_stage = "connect";
    mini_resp_t source;
    if (!group || mini_resp_connect_mode(&source, ctx->source_host,
            ctx->source_port, ctx->qkp, false, 0u) < 0) return false;
    ctx->failure_stage = "peer pin/status";
    bool ok = qihse_qkp_client_session_is_replication_peer(source.qkp,
        ctx->qkp->replication_peer_node_id,
        ctx->qkp->replication_peer_dsa_pub_path);
    char** fields = NULL;
    size_t nfields = 0u;
    const char* status_argv[] = {"REPL.CT1", "STATUS", group->lane_id};
    int reply = ok ? mini_resp_do(&source, 3u, status_argv, NULL, NULL,
                                  &fields, &nfields) : MINI_REP_ERROR;
    uint64_t source_durable = 0u, baseline_row_seq = 0u;
    uint64_t baseline_stream_cut = 0u;
    unsigned char baseline_digest[32] = {0};
    unsigned char source_bitmap_digest[32] = {0};
    unsigned char source_cert_head[32] = {0}, source_cert_ack[32] = {0};
    if (reply != MINI_REP_ARRAY || nfields != 14u ||
        strcmp(fields[0], group->lane_id) != 0 ||
        strcmp(fields[1], ctx->qkp->replication_peer_node_id) != 0 ||
        strcmp(fields[3], ctx->qkp->node_id) != 0 ||
        strcmp(fields[2], ctx->generation) != 0 ||
        !parse_u64_decimal(fields[4], &source_durable) ||
        !parse_u64_decimal(fields[8], &baseline_row_seq) ||
        !parse_u64_decimal(fields[9], &baseline_stream_cut) ||
        !ct1_parse_hex32(fields[10], baseline_digest) ||
        !ct1_parse_hex32(fields[11], source_cert_head) ||
        !ct1_parse_hex32(fields[12], source_cert_ack) ||
        !ct1_parse_hex32(fields[13], source_bitmap_digest)) {
        mini_resp_free_array(fields, nfields);
        mini_resp_close(&source);
        return false;
    }
    (void)source_cert_ack;
    mini_resp_free_array(fields, nfields);
    fields = NULL;

    qihse_kv_ct_lane_status_t receiver;
    memset(&receiver, 0, sizeof(receiver));
    ctx->failure_stage = "receiver bind/status";
    bool receiver_bound = qihse_kv_ct_lane_status(ctx->store,
        ctx->replication_user, group->lane_id, &receiver) &&
        receiver.mode == QIHSE_KV_CT_LANE_RECEIVER;
    if (!receiver_bound) {
        bool admitted = !ctx->maintenance_gate || qihse_cluster_maintenance_enter(
            ctx->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);
        unsigned char ignored_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        bool bound = admitted && qihse_kv_ct_lane_receiver_bind(ctx->store,
            ctx->operator_user, group->lane_id, group->slot_bitmap,
            ctx->qkp->replication_peer_node_id, ctx->qkp->node_id,
            ctx->generation, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
            baseline_row_seq, ignored_token);
        OPENSSL_cleanse(ignored_token, sizeof(ignored_token));
        if (admitted && ctx->maintenance_gate)
            qihse_cluster_maintenance_leave(ctx->maintenance_gate,
                                            QIHSE_MAINT_WRITER_REPLICA);
        if (!bound) { mini_resp_close(&source); return false; }
        receiver_bound = qihse_kv_ct_lane_status(ctx->store,
            ctx->replication_user, group->lane_id, &receiver) &&
            receiver.mode == QIHSE_KV_CT_LANE_RECEIVER;
    }
    if (!receiver_bound || strcmp(receiver.source_id,
            ctx->qkp->replication_peer_node_id) != 0 ||
        strcmp(receiver.peer_id, ctx->qkp->node_id) != 0 ||
        strcmp(receiver.generation, ctx->generation) != 0) {
        mini_resp_close(&source);
        return false;
    }
    /* A source can narrow its group after CT2 before this receiver has
     * applied the same common FINAL. Never replace the old, wider receiver
     * bitmap from a narrower image: that would tombstone transferred rows
     * that are now served by another local SOURCE group. */
    if (CRYPTO_memcmp(receiver.slot_bitmap_digest, source_bitmap_digest, 32u) != 0) {
        ctx->failure_stage = "committed group membership reconciliation";
        mini_resp_close(&source);
        return false;
    }
    if (!receiver.baseline_sealed ||
        receiver.baseline_row_seq != baseline_row_seq ||
        receiver.baseline_stream_cut != baseline_stream_cut ||
        CRYPTO_memcmp(receiver.baseline_digest, baseline_digest, 32u) != 0) {
        ctx->failure_stage = "baseline status";
        const char* base_status_argv[] = {"REPL.CT1", "BASELINE",
                                          group->lane_id, "STATUS"};
        reply = mini_resp_do(&source, 4u, base_status_argv, NULL, NULL,
                             &fields, &nfields);
        uint64_t total_bytes = 0u, remote_row_seq = 0u;
        unsigned char remote_digest[32] = {0};
        unsigned char remote_bitmap_digest[32] = {0};
        uint64_t remote_stream_cut = 0u;
        if (reply != MINI_REP_ARRAY || nfields != 8u ||
            strcmp(fields[0], group->lane_id) != 0 ||
            strcmp(fields[1], ctx->qkp->replication_peer_node_id) != 0 ||
            strcmp(fields[2], ctx->generation) != 0 ||
            !parse_u64_decimal(fields[3], &remote_row_seq) ||
            remote_row_seq != baseline_row_seq ||
            !parse_u64_decimal(fields[4], &remote_stream_cut) ||
            remote_stream_cut != baseline_stream_cut ||
            !ct1_parse_hex32(fields[5], remote_digest) ||
            memcmp(remote_digest, baseline_digest, 32u) != 0 ||
            !parse_u64_decimal(fields[6], &total_bytes) ||
            !ct1_parse_hex32(fields[7], remote_bitmap_digest) ||
            CRYPTO_memcmp(remote_bitmap_digest, source_bitmap_digest, 32u) != 0 ||
            CRYPTO_memcmp(remote_bitmap_digest, receiver.slot_bitmap_digest, 32u) != 0 ||
            total_bytes > (uint64_t)INT64_MAX) {
            mini_resp_free_array(fields, nfields);
            mini_resp_close(&source);
            return false;
        }
        mini_resp_free_array(fields, nfields);
        fields = NULL;

        const char* data_dir = qihse_kv_store_data_directory(ctx->store);
        char path[PATH_MAX];
        int n = data_dir ? snprintf(path, sizeof(path), "%s/.qihse-ct-base-XXXXXX",
                                    data_dir) : -1;
        if (n <= 0 || (size_t)n >= sizeof(path)) {
            mini_resp_close(&source); return false;
        }
        int fd = mkstemp(path);
        if (fd < 0 || fchmod(fd, 0600) != 0) {
            if (fd >= 0) { close(fd); unlink(path); }
            mini_resp_close(&source); return false;
        }
        uint64_t offset = 0u;
        ctx->failure_stage = "baseline read/write";
        while (offset < total_bytes && !ct1_stopping(ctx)) {
            size_t amount = total_bytes - offset > (1u << 20)
                ? (1u << 20) : (size_t)(total_bytes - offset);
            char offset_text[32], amount_text[32];
            snprintf(offset_text, sizeof(offset_text), "%llu", (unsigned long long)offset);
            snprintf(amount_text, sizeof(amount_text), "%zu", amount);
            const char* read_argv[] = {"REPL.CT1", "BASELINE", group->lane_id,
                                       "READ", offset_text, amount_text};
            char* chunk = NULL; size_t chunk_len = 0u;
            reply = mini_resp_do(&source, 6u, read_argv, &chunk, &chunk_len,
                                 NULL, NULL);
            bool chunk_ok = reply == MINI_REP_BULK && chunk &&
                chunk_len == amount && ct1_write_all(fd, chunk, chunk_len);
            free(chunk);
            if (!chunk_ok) { ok = false; break; }
            offset += amount;
        }
        if (ok && fsync(fd) != 0) ok = false;
        if (close(fd) != 0) ok = false;
        if (ok) {
            ctx->failure_stage = "baseline validate";
            FILE* validation_stream = fopen(path, "rb");
            qihse_kv_store_t* validation = validation_stream
                ? qihse_kv_open_snapshot_user(validation_stream,
                    ctx->replication_user,
                    (size_t)(total_bytes ? total_bytes : 1u), 50000000u)
                : NULL;
            if (validation_stream) fclose(validation_stream);
            if (!validation) ok = false;
            else qihse_kv_store_destroy(validation);
        }
        unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
        if (ok && !qihse_kv_ct_lane_owner_token_get(ctx->store,
                ctx->operator_user, group->lane_id, owner_token)) ok = false;
        ctx->failure_stage = "baseline install";
        bool gate_entered = !ctx->maintenance_gate;
        if (ok && ctx->maintenance_gate)
            gate_entered = qihse_cluster_maintenance_enter(ctx->maintenance_gate,
                QIHSE_MAINT_WRITER_REPLICA);
        if (ok && gate_entered) {
            if (!qihse_kv_ct_lane_receiver_baseline_install(ctx->store,
                    ctx->operator_user, ctx->replication_user, group->lane_id,
                    receiver.slot_bitmap, path, baseline_row_seq,
                    baseline_stream_cut, baseline_digest,
                    owner_token)) ok = false;
        } else if (ok) ok = false;
        if (ctx->maintenance_gate && gate_entered)
            qihse_cluster_maintenance_leave(ctx->maintenance_gate,
                                            QIHSE_MAINT_WRITER_REPLICA);
        OPENSSL_cleanse(owner_token, sizeof(owner_token));
        (void)unlink(path);
        if (!ok) { mini_resp_close(&source); return false; }
        receiver_bound = qihse_kv_ct_lane_status(ctx->store,
            ctx->replication_user, group->lane_id, &receiver) &&
            receiver.baseline_sealed &&
            receiver.baseline_stream_cut == baseline_stream_cut &&
            memcmp(receiver.baseline_digest, baseline_digest, 32u) == 0;
        if (!receiver_bound) { mini_resp_close(&source); return false; }
    }
    if (receiver.baseline_stream_cut != baseline_stream_cut ||
        memcmp(receiver.baseline_digest, baseline_digest, 32u) != 0) {
        mini_resp_close(&source); return false;
    }

    uint64_t cursor = receiver.durable_position;
    while (cursor < source_durable && !ct1_stopping(ctx)) {
        ctx->failure_stage = "group read/parse";
        char cursor_text[32];
        snprintf(cursor_text, sizeof(cursor_text), "%llu", (unsigned long long)cursor);
        const char* read_argv[] = {"REPL.CT1", "READ", group->lane_id,
            ctx->generation, cursor_text, "1", "67108864", "v1"};
        reply = mini_resp_do(&source, 8u, read_argv, NULL, NULL, &fields, &nfields);
        if (reply != MINI_REP_ARRAY || nfields < 5u ||
            strcmp(fields[0], ctx->qkp->replication_peer_node_id) != 0 ||
            strcmp(fields[1], ctx->generation) != 0 ||
            strcmp(fields[2], ctx->qkp->node_id) != 0) {
            mini_resp_free_array(fields, nfields); mini_resp_close(&source); return false;
        }
        uint64_t resume = 0u, groups = 0u;
        bool valid = parse_u64_decimal(fields[3], &resume) &&
            parse_u64_decimal(fields[4], &groups) && groups <= 1u;
        if (!valid || groups == 0u) {
            valid = valid && groups == 0u && resume == cursor;
            mini_resp_free_array(fields, nfields);
            if (!valid) { mini_resp_close(&source); return false; }
            break;
        }
        uint64_t position = 0u, first_seq = 0u, last_seq = 0u, count_u64 = 0u;
        valid = nfields >= 9u && parse_u64_decimal(fields[5], &position) &&
            parse_u64_decimal(fields[6], &first_seq) &&
            parse_u64_decimal(fields[7], &last_seq) &&
            parse_u64_decimal(fields[8], &count_u64) &&
            count_u64 <= QIHSE_KV_CT_MAX_GROUP_RECORDS &&
            nfields == 9u + (size_t)count_u64 * 11u && position == cursor + 1u;
        qihse_kv_ct_group_t apply_group; memset(&apply_group, 0, sizeof(apply_group));
        if (valid) {
            snprintf(apply_group.source_id, sizeof(apply_group.source_id), "%s", fields[0]);
            snprintf(apply_group.generation, sizeof(apply_group.generation), "%s", fields[1]);
            apply_group.stream_position = position;
            apply_group.first_seq = first_seq; apply_group.last_seq = last_seq;
            apply_group.count = (size_t)count_u64;
            apply_group.records = calloc(apply_group.count ? apply_group.count : 1u,
                                         sizeof(*apply_group.records));
            valid = apply_group.records != NULL;
        }
        for (size_t i = 0u; valid && i < apply_group.count; ++i) {
            size_t b = 9u + i * 11u;
            qihse_kv_ct_record_t* rec = &apply_group.records[i];
            uint64_t values[9] = {0};
            for (size_t k = 0u; k < 9u; ++k)
                if (!parse_u64_decimal(fields[b + 2u + k], &values[k])) valid = false;
            if (!valid || values[0] == 0u || values[2] > UINT32_MAX ||
                values[3] > UINT32_MAX || values[4] > UINT32_MAX ||
                values[5] > UINT16_MAX || values[6] > UINT16_MAX ||
                values[7] < QIHSE_KV_CT_ACTOR_USER ||
                values[7] > QIHSE_KV_CT_ACTOR_REPLICA || values[8] > 1u) {
                valid = false; break;
            }
            rec->key = strdup(fields[b]);
            rec->value = values[8] ? NULL : strdup(fields[b + 1u]);
            rec->change_seq = values[0]; rec->expire_time_ms = values[1];
            rec->actor_id = (uint32_t)values[2];
            rec->actor_tenant_id = (uint32_t)values[3];
            rec->resource_tenant_id = (uint32_t)values[4];
            rec->classification = (uint16_t)values[5];
            rec->sci_compartment = (uint16_t)values[6];
            rec->actor_kind = (qihse_kv_ct_actor_t)values[7];
            rec->tombstone = values[8] != 0u;
            if (!rec->key || (!rec->tombstone && !rec->value)) valid = false;
        }
        uint64_t durable_cursor = 0u;
        ctx->failure_stage = "group apply";
        bool gate_entered = !ctx->maintenance_gate;
        if (valid && ctx->maintenance_gate)
            gate_entered = qihse_cluster_maintenance_enter(ctx->maintenance_gate,
                QIHSE_MAINT_WRITER_REPLICA);
        if (valid && gate_entered)
            valid = qihse_kv_ct_lane_receiver_apply(ctx->store,
                ctx->replication_user, group->lane_id, &apply_group,
                &durable_cursor) && durable_cursor == position;
        else if (valid) valid = false;
        if (ctx->maintenance_gate && gate_entered)
            qihse_cluster_maintenance_leave(ctx->maintenance_gate,
                                            QIHSE_MAINT_WRITER_REPLICA);
        for (size_t i = 0; i < apply_group.count; ++i) {
            free(apply_group.records[i].key); free(apply_group.records[i].value);
        }
        free(apply_group.records);
        mini_resp_free_array(fields, nfields); fields = NULL;
        if (!valid) { mini_resp_close(&source); return false; }
        char pos_text[32]; snprintf(pos_text, sizeof(pos_text), "%llu",
                                    (unsigned long long)durable_cursor);
        ctx->failure_stage = "successor ACK";
        const char* ack_argv[] = {"REPL.CT1", "ACK", group->lane_id,
                                  ctx->generation, pos_text};
        if (!ct1_simple_ok(&source, 5u, ack_argv)) {
            mini_resp_close(&source); return false;
        }
        cursor = durable_cursor;
    }
    if (cursor >= source_durable) {
        ctx->failure_stage = "promotion certificate sync";
        if (!ct1_group_pull_certificates(ctx, &source, source_cert_head)) {
            mini_resp_close(&source);
            OPENSSL_cleanse(source_cert_head, sizeof(source_cert_head));
            OPENSSL_cleanse(source_cert_ack, sizeof(source_cert_ack));
            OPENSSL_cleanse(baseline_digest, sizeof(baseline_digest));
            return false;
        }
        char cursor_text[32], digest_text[65];
        snprintf(cursor_text, sizeof(cursor_text), "%llu", (unsigned long long)cursor);
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < 32u; ++i) {
            digest_text[2u * i] = hex[baseline_digest[i] >> 4u];
            digest_text[2u * i + 1u] = hex[baseline_digest[i] & 15u];
        }
        digest_text[64] = '\0';
        const char* reconcile_argv[] = {"REPL.CT1", "RECONCILE", group->lane_id,
            ctx->generation, digest_text, cursor_text};
        ok = ct1_simple_ok(&source, 6u, reconcile_argv);
    } else ok = false;
    mini_resp_close(&source);
    OPENSSL_cleanse(source_cert_head, sizeof(source_cert_head));
    OPENSSL_cleanse(source_cert_ack, sizeof(source_cert_ack));
    OPENSSL_cleanse(baseline_digest, sizeof(baseline_digest));
    if (ok) ctx->failure_stage = "";
    return ok;
}

static bool ct1_write_all(int fd, const void* data, size_t len) {
    const unsigned char* p = data;
    size_t done = 0u;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool ct1_simple_ok(mini_resp_t* peer, size_t argc,
                          const char* const* argv) {
    return mini_resp_do(peer, argc, argv, NULL, NULL, NULL, NULL) ==
        MINI_REP_SIMPLE && peer->last[0] == '+';
}

/* Pull one authenticated source session. A target only becomes readable after
 * the digest-checked QFS baseline is installed and its atomic group cursor is
 * caught up. The source opens write admission only after our durable cursor is
 * returned through RECONCILE. */
static bool ct1_pull_once(ct1_pull_ctx_t* ctx) {
    if (ctx && ctx->group_config) return ct1_group_pull_once(ctx);
    ctx->failure_stage = "connect";
    mini_resp_t source;
    if (mini_resp_connect_mode(&source, ctx->source_host, ctx->source_port,
                               ctx->qkp, false, 0u) < 0) return false;
    ctx->failure_stage = "peer pin/status";
    bool ok = qihse_qkp_client_session_is_replication_peer(source.qkp,
        ctx->qkp->replication_peer_node_id,
        ctx->qkp->replication_peer_dsa_pub_path);
    char** fields = NULL;
    size_t nfields = 0u;
    const char* status_argv[] = {"REPL.CT1", "STATUS"};
    int reply = ok ? mini_resp_do(&source, 2u, status_argv, NULL, NULL,
                                  &fields, &nfields) : MINI_REP_ERROR;
    uint64_t source_durable = 0u, baseline_row_seq = 0u;
    unsigned char baseline_digest[32] = {0};
    if (reply == MINI_REP_ARRAY && nfields == 10u && ctx->learn_generation &&
        !strcmp(fields[0], ctx->qkp->replication_peer_node_id) &&
        !strcmp(fields[2], ctx->qkp->node_id) && strlen(fields[1]) == 32u) {
        memcpy(ctx->generation_runtime, fields[1], 33u);
        ctx->generation = ctx->generation_runtime;
    }
    if (reply != MINI_REP_ARRAY || nfields != 10u ||
        strcmp(fields[0], ctx->qkp->replication_peer_node_id) != 0 ||
        strcmp(fields[1], ctx->generation) != 0 ||
        strcmp(fields[2], ctx->qkp->node_id) != 0 ||
        !parse_u64_decimal(fields[3], &source_durable) ||
        !parse_u64_decimal(fields[8], &baseline_row_seq) ||
        !ct1_parse_hex32(fields[9], baseline_digest)) {
        mini_resp_free_array(fields, nfields);
        mini_resp_close(&source);
        return false;
    }
    mini_resp_free_array(fields, nfields);
    fields = NULL;
    fields = NULL;

    qihse_kv_ct_receiver_status_t receiver;
    ctx->failure_stage = "receiver bind/status";
    bool receiver_bound = qihse_kv_ct_receiver_status(ctx->store,
        ctx->replication_user, &receiver);
    if (!receiver_bound) {
        bool admitted = !ctx->maintenance_gate || qihse_cluster_maintenance_enter(
            ctx->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);
        bool bound = admitted && qihse_kv_ct_receiver_bind(ctx->store, ctx->operator_user,
                ctx->qkp->replication_peer_node_id, ctx->qkp->node_id,
                ctx->generation, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                baseline_row_seq, NULL);
        if (admitted && ctx->maintenance_gate)
            qihse_cluster_maintenance_leave(ctx->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);
        if (!bound) {
            mini_resp_close(&source);
            return false;
        }
        receiver_bound = qihse_kv_ct_receiver_status(ctx->store,
            ctx->replication_user, &receiver);
    }
    if (receiver_bound && ctx->learn_generation &&
        !qihse_resp_server_ct_bind_generation(ctx->server, ctx->operator_user, ctx->generation)) {
        mini_resp_close(&source); return false;
    }
    if (!receiver_bound || strcmp(receiver.source_id,
            ctx->qkp->replication_peer_node_id) != 0 ||
        strcmp(receiver.generation, ctx->generation) != 0 ||
        receiver.tenant_policy != QIHSE_KV_CT_TENANT_SYSTEM_ALL) {
        mini_resp_close(&source);
        return false;
    }
    if (!receiver.baseline_sealed) {
        ctx->failure_stage = "baseline status";
        const char* base_status_argv[] = {"REPL.CT1", "BASELINE", "STATUS"};
        reply = mini_resp_do(&source, 3u, base_status_argv, NULL, NULL,
                             &fields, &nfields);
        uint64_t total_bytes = 0u, remote_row_seq = 0u;
        unsigned char remote_digest[32] = {0};
        if (reply != MINI_REP_ARRAY || nfields != 5u ||
            strcmp(fields[0], ctx->qkp->replication_peer_node_id) != 0 ||
            strcmp(fields[1], ctx->generation) != 0 ||
            !parse_u64_decimal(fields[2], &remote_row_seq) ||
            remote_row_seq != baseline_row_seq ||
            !ct1_parse_hex32(fields[3], remote_digest) ||
            memcmp(remote_digest, baseline_digest, 32u) != 0 ||
            !parse_u64_decimal(fields[4], &total_bytes) ||
            total_bytes > (uint64_t)INT64_MAX) {
            mini_resp_free_array(fields, nfields);
            mini_resp_close(&source);
            return false;
        }
        mini_resp_free_array(fields, nfields);
        fields = NULL;

        const char* data_dir = qihse_kv_store_data_directory(ctx->store);
        char path[PATH_MAX];
        int n = data_dir ? snprintf(path, sizeof(path), "%s/.qihse-ct-base-XXXXXX",
                                    data_dir) : -1;
        if (n <= 0 || (size_t)n >= sizeof(path)) {
            mini_resp_close(&source);
            return false;
        }
        int fd = mkstemp(path);
        if (fd < 0 || fchmod(fd, 0600) != 0) {
            if (fd >= 0) { close(fd); unlink(path); }
            mini_resp_close(&source);
            return false;
        }
        uint64_t offset = 0u;
        ctx->failure_stage = "baseline read/write";
        while (offset < total_bytes && !ct1_stopping(ctx)) {
            size_t amount = total_bytes - offset > (1u << 20)
                ? (1u << 20) : (size_t)(total_bytes - offset);
            char offset_text[32], amount_text[32];
            snprintf(offset_text, sizeof(offset_text), "%llu", (unsigned long long)offset);
            snprintf(amount_text, sizeof(amount_text), "%zu", amount);
            const char* read_argv[] = {"REPL.CT1", "BASELINE", "READ",
                                       offset_text, amount_text};
            char* chunk = NULL;
            size_t chunk_len = 0u;
            reply = mini_resp_do(&source, 5u, read_argv, &chunk, &chunk_len,
                                 NULL, NULL);
            bool chunk_ok = reply == MINI_REP_BULK && chunk &&
                chunk_len == amount && ct1_write_all(fd, chunk, chunk_len);
            free(chunk);
            if (!chunk_ok) { ok = false; break; }
            offset += amount;
        }
        if (ok && fsync(fd) != 0) ok = false;
        if (close(fd) != 0) ok = false;
        if (ok) {
            ctx->failure_stage = "baseline validate";
            FILE* validation_stream = fopen(path, "rb");
            qihse_kv_store_t* validation = validation_stream
                ? qihse_kv_open_snapshot_user(validation_stream,
                    ctx->replication_user,
                    (size_t)(total_bytes ? total_bytes : 1u), 50000000u)
                : NULL;
            if (validation_stream) fclose(validation_stream);
            if (!validation) ok = false;
            else qihse_kv_store_destroy(validation);
        }
        if (ok && !qihse_kv_ct_owner_token_get(ctx->store,
                ctx->operator_user, ctx->ct_owner_token)) ok = false;
        ctx->failure_stage = "baseline install";
        bool gate_entered = !ctx->maintenance_gate;
        if (ok && ctx->maintenance_gate)
            gate_entered = qihse_cluster_maintenance_enter(ctx->maintenance_gate,
                QIHSE_MAINT_WRITER_REPLICA);
        bool admitted = gate_entered;
        if (ok && admitted && !qihse_kv_ct_receiver_install_baseline(ctx->store,
                ctx->operator_user, ctx->replication_user,
                ctx->qkp->replication_peer_node_id,
                ctx->generation, path, baseline_row_seq, baseline_digest,
                ctx->ct_owner_token)) ok = false;
        else if (ok && !admitted) ok = false;
        if (ctx->maintenance_gate && gate_entered)
            qihse_cluster_maintenance_leave(ctx->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);
        (void)unlink(path);
        if (!ok) { mini_resp_close(&source); return false; }
        receiver_bound = qihse_kv_ct_receiver_status(ctx->store,
            ctx->replication_user, &receiver);
        if (!receiver_bound || !receiver.baseline_sealed ||
            memcmp(receiver.baseline_digest, baseline_digest, 32u) != 0) {
            mini_resp_close(&source);
            return false;
        }
    }
    if (memcmp(receiver.baseline_digest, baseline_digest, 32u) != 0) {
        mini_resp_close(&source);
        return false;
    }

    uint64_t cursor = receiver.durable_cursor;
    while (cursor < source_durable && !ct1_stopping(ctx)) {
        ctx->failure_stage = "group read/parse";
        char cursor_text[32];
        snprintf(cursor_text, sizeof(cursor_text), "%llu", (unsigned long long)cursor);
        const char* read_argv[] = {"REPL.CT1", "READ", ctx->generation,
                                   cursor_text, "1", "67108864", "v1"};
        reply = mini_resp_do(&source, 7u, read_argv, NULL, NULL,
                             &fields, &nfields);
        if (reply != MINI_REP_ARRAY || nfields < 5u ||
            strcmp(fields[0], ctx->qkp->replication_peer_node_id) != 0 ||
            strcmp(fields[1], ctx->generation) != 0 ||
            strcmp(fields[2], ctx->qkp->node_id) != 0) {
            mini_resp_free_array(fields, nfields);
            mini_resp_close(&source);
            return false;
        }
        uint64_t resume = 0u, groups = 0u;
        bool valid = parse_u64_decimal(fields[3], &resume) &&
            parse_u64_decimal(fields[4], &groups) && groups <= 1u;
        if (!valid || groups == 0u) {
            valid = valid && groups == 0u && resume == cursor;
            mini_resp_free_array(fields, nfields);
            if (!valid) { mini_resp_close(&source); return false; }
            break;
        }
        uint64_t position = 0u, first_seq = 0u, last_seq = 0u, count_u64 = 0u;
        valid = nfields >= 9u && parse_u64_decimal(fields[5], &position) &&
            parse_u64_decimal(fields[6], &first_seq) &&
            parse_u64_decimal(fields[7], &last_seq) &&
            parse_u64_decimal(fields[8], &count_u64) &&
            count_u64 <= QIHSE_KV_CT_MAX_GROUP_RECORDS &&
            nfields == 9u + (size_t)count_u64 * 11u && position == cursor + 1u;
        qihse_kv_ct_group_t group;
        memset(&group, 0, sizeof(group));
        if (valid) {
            snprintf(group.source_id, sizeof(group.source_id), "%s", fields[0]);
            snprintf(group.generation, sizeof(group.generation), "%s", fields[1]);
            group.stream_position = position;
            group.first_seq = first_seq;
            group.last_seq = last_seq;
            group.count = (size_t)count_u64;
            group.records = calloc(group.count ? group.count : 1u,
                                   sizeof(*group.records));
            valid = group.records != NULL;
        }
        for (size_t i = 0u; valid && i < group.count; ++i) {
            size_t b = 9u + i * 11u;
            qihse_kv_ct_record_t* rec = &group.records[i];
            uint64_t values[9] = {0};
            for (size_t k = 0u; k < 9u; ++k)
                if (!parse_u64_decimal(fields[b + 2u + k], &values[k])) valid = false;
            if (!valid || values[0] == 0u || values[2] > UINT32_MAX ||
                values[3] > UINT32_MAX || values[4] > UINT32_MAX ||
                values[5] > UINT16_MAX || values[6] > UINT16_MAX ||
                values[7] < QIHSE_KV_CT_ACTOR_USER ||
                values[7] > QIHSE_KV_CT_ACTOR_REPLICA || values[8] > 1u) {
                valid = false;
                break;
            }
            rec->key = strdup(fields[b]);
            rec->value = values[8] ? NULL : strdup(fields[b + 1u]);
            rec->change_seq = values[0];
            rec->expire_time_ms = values[1];
            rec->actor_id = (uint32_t)values[2];
            rec->actor_tenant_id = (uint32_t)values[3];
            rec->resource_tenant_id = (uint32_t)values[4];
            rec->classification = (uint16_t)values[5];
            rec->sci_compartment = (uint16_t)values[6];
            rec->actor_kind = (qihse_kv_ct_actor_t)values[7];
            rec->tombstone = values[8] != 0u;
            if (!rec->key || (!rec->tombstone && !rec->value)) valid = false;
        }
        uint64_t durable_cursor = 0u;
        ctx->failure_stage = "group apply";
        bool gate_entered = !ctx->maintenance_gate;
        if (valid && ctx->maintenance_gate)
            gate_entered = qihse_cluster_maintenance_enter(ctx->maintenance_gate,
                QIHSE_MAINT_WRITER_REPLICA);
        bool admitted = gate_entered;
        if (valid && admitted) valid = qihse_kv_ct_receiver_apply(ctx->store,
            ctx->replication_user, &group, &durable_cursor) && durable_cursor == position;
        else if (valid && !admitted) valid = false;
        if (ctx->maintenance_gate && gate_entered)
            qihse_cluster_maintenance_leave(ctx->maintenance_gate, QIHSE_MAINT_WRITER_REPLICA);
        for (size_t i = 0u; i < group.count; ++i) {
            free(group.records[i].key);
            free(group.records[i].value);
        }
        free(group.records);
        mini_resp_free_array(fields, nfields);
        fields = NULL;
        if (!valid) { mini_resp_close(&source); return false; }
        char pos_text[32];
        snprintf(pos_text, sizeof(pos_text), "%llu", (unsigned long long)durable_cursor);
        ctx->failure_stage = "successor ACK";
        const char* ack_argv[] = {"REPL.CT1", "ACK", ctx->generation, pos_text};
        if (!ct1_simple_ok(&source, 4u, ack_argv)) {
            mini_resp_close(&source);
            return false;
        }
        cursor = durable_cursor;
    }
    if (cursor >= source_durable) {
        ctx->failure_stage = "source reconcile";
        char cursor_text[32], digest_text[65];
        snprintf(cursor_text, sizeof(cursor_text), "%llu", (unsigned long long)cursor);
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0u; i < 32u; ++i) {
            digest_text[2u * i] = hex[baseline_digest[i] >> 4u];
            digest_text[2u * i + 1u] = hex[baseline_digest[i] & 15u];
        }
        digest_text[64] = '\0';
        const char* reconcile_argv[] = {"REPL.CT1", "RECONCILE",
            ctx->generation, digest_text, cursor_text};
        ok = ct1_simple_ok(&source, 5u, reconcile_argv);
        if (!ok) fprintf(stderr,
            "qihse-cluster-daemon: CT1 reconcile rejected cursor=%llu source_status_lsn=%llu reply=%s transport=%s\n",
            (unsigned long long)cursor, (unsigned long long)source_durable,
            source.last[0] ? source.last : "(no RESP reply)",
            source.err[0] ? source.err : "none");
    } else ok = false;
    mini_resp_close(&source);
    OPENSSL_cleanse(baseline_digest, sizeof(baseline_digest));
    if (ok) ctx->failure_stage = "";
    return ok;
}

static void* ct1_pull_main(void* argument) {
    ct1_pull_ctx_t* ctx = argument;
    bool (*is_receiver)(qihse_resp_server_t*, const char*) =
        ctx->group_config ? qihse_resp_server_ct_lane_is_receiver : NULL;
    while (!ct1_stopping(ctx) && (ctx->group_config
            ? is_receiver(ctx->server, ctx->group_config->lane_id)
            : qihse_resp_server_ct_is_successor(ctx->server))) {
        unsigned delay_ms = 250u;
        if (ct1_pull_once(ctx)) {
            delay_ms = 250u;
        } else {
            if (!(ctx->group_config
                    ? is_receiver(ctx->server, ctx->group_config->lane_id)
                    : qihse_resp_server_ct_is_successor(ctx->server))) break;
            fprintf(stderr, "qihse-cluster-daemon: CT1 pinned pull/reconcile failed at %s; successor remains fenced\n",
                ctx->failure_stage && *ctx->failure_stage ? ctx->failure_stage : "unknown stage");
            /* A pending source write may be waiting on ACK. Keep the retry
             * delay below the configured ACK timeout; only a failed TCP
             * connect gets a modest backoff to avoid a hot reconnect loop. */
            delay_ms = ctx->failure_stage &&
                strcmp(ctx->failure_stage, "connect") == 0 ? 1000u : 250u;
        }
        struct timespec ts = {(time_t)(delay_ms / 1000u),
                              (long)(delay_ms % 1000u) * 1000000L};
        while (!ct1_stopping(ctx) && nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
    }
    return NULL;
}

static bool ct1_group_worker_start(qihse_kv_store_t* store,
        qihse_resp_server_t* server, qihse_cluster_ownership_context_t* ownership,
        qihse_cluster_topology_t* topology,
        const ct_identity_map_set_t* identity_maps,
        const qihse_qkp_replication_peer_t* allowed_peers, size_t allowed_count,
        const qihse_ct_group_config_t* group, qihse_user_t* operator_user,
        qihse_user_t* replication_user, const qihse_qkp_config_t* base_qkp,
        qihse_cluster_maintenance_t* maintenance_gate, volatile sig_atomic_t* stop,
        pthread_t* thread, ct1_pull_ctx_t* ctx) {
    if (!store || !server || !ownership || !topology || !identity_maps || !group ||
        !operator_user || !replication_user || !base_qkp || !thread || !ctx ||
        !stop) return false;

    qihse_kv_ct_lane_status_t lane;
    memset(&lane, 0, sizeof(lane));
    char source_id[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
    char generation[33] = {0};
    bool lane_found = qihse_kv_ct_lane_status(store, operator_user,
        group->lane_id, &lane);
    if (lane_found) {
        if (lane.mode != QIHSE_KV_CT_LANE_RECEIVER ||
            strcmp(lane.peer_id, base_qkp->node_id) != 0 ||
            strnlen(lane.generation, sizeof(lane.generation)) != 32u) return false;
        snprintf(source_id, sizeof(source_id), "%s", lane.source_id);
        memcpy(generation, lane.generation, sizeof(generation));
    } else {
        char owner_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        if (!ct_identity_map_lookup((void*)identity_maps,
                group->owner_topology_id, owner_qkp) ||
            !ct_identity_map_lookup((void*)identity_maps,
                group->successor_topology_id, successor_qkp) ||
            strcmp(successor_qkp, base_qkp->node_id) != 0) return false;
        snprintf(source_id, sizeof(source_id), "%s", owner_qkp);
        snprintf(generation, sizeof(generation), "%s", group->generation);
    }

    const char* source_pin = ct_group_replication_pin(
        allowed_peers, allowed_count, source_id);
    qihse_cluster_node_t source_node;
    if (!source_pin || !ct_group_endpoint_for_qkp(topology, identity_maps,
            source_id, &source_node)) return false;

    memset(ctx, 0, sizeof(*ctx));
    ctx->store = store;
    ctx->server = server;
    ctx->ownership = ownership;
    ctx->maintenance_gate = maintenance_gate;
    ctx->operator_user = operator_user;
    ctx->replication_user = replication_user;
    ctx->group_qkp_runtime = *base_qkp;
    snprintf(ctx->group_peer_id_runtime, sizeof(ctx->group_peer_id_runtime),
             "%s", source_id);
    snprintf(ctx->group_source_host_runtime,
             sizeof(ctx->group_source_host_runtime), "%s", source_node.host);
    snprintf(ctx->group_generation_runtime,
             sizeof(ctx->group_generation_runtime), "%s", generation);
    ctx->group_qkp_runtime.replication_peer_node_id = ctx->group_peer_id_runtime;
    ctx->group_qkp_runtime.replication_peer_dsa_pub_path = source_pin;
    ctx->qkp = &ctx->group_qkp_runtime;
    ctx->source_host = ctx->group_source_host_runtime;
    ctx->source_port = source_node.port;
    ctx->generation = ctx->group_generation_runtime;
    ctx->group_config = group;
    ctx->stop = stop;
    if (pthread_create(thread, NULL, ct1_pull_main, ctx) != 0) return false;
    return true;
}

static bool ct_group_index_for_qkp(const qihse_cluster_topology_t* topology,
        const ct_identity_map_set_t* maps, const char* qkp_id,
        uint16_t* out_index) {
    if (!topology || !maps || !qkp_id || !out_index) return false;
    size_t matches = 0u;
    uint16_t found = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < maps->count; ++i) {
        if (strcmp(maps->entries[i].qkp_node_id, qkp_id) != 0) continue;
        if (qihse_cluster_topology_find_node(topology,
                maps->entries[i].topology_id, &found)) ++matches;
    }
    if (matches != 1u || found == QIHSE_CLUSTER_NODE_NONE) return false;
    *out_index = found;
    return true;
}

static bool ct_group_failover_successor(const qihse_cluster_topology_t* topology,
        const ct_identity_map_set_t* maps,
        const qihse_qkp_replication_peer_t* allowed_peers, size_t allowed_count,
        uint16_t failed_index, uint16_t promoter_index, uint16_t* out_successor) {
    if (out_successor) *out_successor = QIHSE_CLUSTER_NODE_NONE;
    if (!topology || !maps || !out_successor) return false;
    size_t count = qihse_cluster_topology_nodes(topology, NULL, 0u);
    qihse_cluster_node_t* nodes = count && count <= QIHSE_CLUSTER_MAX_NODES
        ? calloc(count, sizeof(*nodes)) : NULL;
    if (!nodes) return false;
    size_t got = qihse_cluster_topology_nodes(topology, nodes, count);
    bool found = false;
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < got && i < count; ++i) {
        qihse_cluster_node_t* node = &nodes[i];
        if (!node->healthy || node->index == failed_index ||
            node->index == promoter_index) continue;
        char qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
        if (!ct_identity_map_lookup((void*)maps, node->id, qkp) ||
            !ct_group_replication_pin(allowed_peers, allowed_count, qkp)) continue;
        if (!found || node->index < best) { best = node->index; found = true; }
    }
    OPENSSL_cleanse(nodes, count * sizeof(*nodes));
    free(nodes);
    if (found) *out_successor = best;
    return found;
}

static void ct_group_failover_tick(qihse_kv_store_t* store,
        qihse_cluster_ownership_context_t* ownership,
        qihse_cluster_topology_t* topology,
        qihse_consensus_mesh_t* mesh,
        const ct_identity_map_set_t* maps,
        const qihse_qkp_replication_peer_t* allowed_peers, size_t allowed_count,
        const qihse_ct_group_config_t* groups, size_t group_count,
        uint16_t local_index, const char* local_qkp_id) {
    if (!store || !ownership || !topology || !mesh || !maps || !groups || !group_count ||
        !local_qkp_id || !*local_qkp_id) return;
    for (size_t i = 0; i < group_count; ++i) {
        qihse_kv_ct_lane_status_t lane;
        memset(&lane, 0, sizeof(lane));
        if (!qihse_kv_ct_lane_status(store, ownership->principal,
                groups[i].lane_id, &lane)) continue;
        uint16_t failed_index = QIHSE_CLUSTER_NODE_NONE;
        uint16_t successor_index = QIHSE_CLUSTER_NODE_NONE;
        bool should_promote = false;
        if (lane.mode == QIHSE_KV_CT_LANE_RECEIVER &&
            strcmp(lane.peer_id, local_qkp_id) == 0) {
            char owner_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
            char owner_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
            char generation[33] = {0};
            char successor_topology[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
            char successor_qkp[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
            qihse_cluster_node_t owner;
            should_promote = ct_group_current_map(
                    &(ct_group_authority_context_t){.operator_user = ownership->principal,
                        .identity_maps = maps, .mesh = mesh},
                    &groups[i], owner_topology, owner_qkp, generation,
                    successor_topology, successor_qkp) &&
                strcmp(lane.source_id, owner_qkp) == 0 &&
                strcmp(lane.generation, generation) == 0 &&
                strcmp(lane.peer_id, successor_qkp) == 0 &&
                qihse_cluster_topology_find_node(topology, owner_topology,
                    &failed_index) &&
                qihse_cluster_topology_get_node(topology, failed_index, &owner) &&
                !owner.healthy;
            if (should_promote)
                should_promote = ct_group_failover_successor(topology, maps,
                    allowed_peers, allowed_count, failed_index, local_index,
                    &successor_index);
            OPENSSL_cleanse(owner_topology, sizeof(owner_topology));
            OPENSSL_cleanse(owner_qkp, sizeof(owner_qkp));
            OPENSSL_cleanse(generation, sizeof(generation));
            OPENSSL_cleanse(successor_topology, sizeof(successor_topology));
            OPENSSL_cleanse(successor_qkp, sizeof(successor_qkp));
        } else if (lane.mode == QIHSE_KV_CT_LANE_SOURCE &&
                   lane.promotion_pending &&
                   strcmp(lane.source_id, local_qkp_id) == 0) {
            qihse_cluster_node_t successor;
            should_promote = ct_group_index_for_qkp(topology, maps,
                lane.peer_id, &successor_index) && successor_index != local_index &&
                qihse_cluster_topology_get_node(topology, successor_index,
                    &successor) && successor.healthy;
            OPENSSL_cleanse(&successor, sizeof(successor));
        }
        if (should_promote) {
            bool pending = false;
            char error[256] = {0};
            if (!qihse_cluster_failover_promote_lane(ownership,
                    groups[i].lane_id, successor_index, &pending,
                    error, sizeof(error)) && error[0]) {
                fprintf(stderr, "qihse-cluster-daemon: CT lane promotion %s deferred: %s%s\n",
                    groups[i].lane_id, error, pending ? " (durable work pending)" : "");
            }
        }
        OPENSSL_cleanse(&lane, sizeof(lane));
    }
}

static bool ct1_primary_peer_preflight(const char* host, uint16_t port,
        const qihse_qkp_config_t* qkp, const char* generation,
        uint64_t source_durable_position,
        const unsigned char expected_baseline_digest[32]) {
    mini_resp_t peer;
    if (mini_resp_connect_mode(&peer, host, port, qkp, false, 0u) < 0)
        return false;
    struct timeval timeout = {5, 0};
    (void)setsockopt(peer.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(peer.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    char** fields = NULL;
    size_t count = 0u;
    const char* argv[] = {"REPL.CT1", "TARGET", "STATUS"};
    int reply = mini_resp_do(&peer, 3u, argv, NULL, NULL, &fields, &count);
    uint64_t target_cursor = 0u, sealed = 0u, tenant_policy = 0u;
    unsigned char target_digest[32] = {0};
    if (reply == MINI_REP_ARRAY && count == 7u) {
        char* end = NULL; errno = 0; target_cursor = strtoull(fields[3], &end, 10);
        bool cursor_ok = !errno && end && !*end;
        errno = 0; sealed = strtoull(fields[4], &end, 10);
        cursor_ok = cursor_ok && !errno && end && !*end && sealed <= 1u;
        errno = 0; tenant_policy = strtoull(fields[6], &end, 10);
        cursor_ok = cursor_ok && !errno && end && !*end && tenant_policy <= QIHSE_KV_CT_TENANT_SYSTEM_ALL;
        if (sealed && (!ct1_parse_hex32(fields[5], target_digest) ||
            !expected_baseline_digest ||
            memcmp(target_digest, expected_baseline_digest, 32u) != 0)) cursor_ok = false;
        if (tenant_policy != 0u &&
            tenant_policy != QIHSE_KV_CT_TENANT_SYSTEM_ALL) cursor_ok = false;
        if (!cursor_ok) reply = MINI_REP_ERROR;
    }
    bool ok = reply == MINI_REP_ARRAY && count == 7u &&
        qihse_qkp_client_session_is_replication_peer(peer.qkp,
            qkp->replication_peer_node_id, qkp->replication_peer_dsa_pub_path) &&
        strcmp(fields[0], qkp->node_id) == 0 &&
        strcmp(fields[1], qkp->replication_peer_node_id) == 0 &&
        strcmp(fields[2], generation) == 0 &&
        (source_durable_position == 0u || (sealed == 1u &&
            tenant_policy == QIHSE_KV_CT_TENANT_SYSTEM_ALL &&
            target_cursor >= source_durable_position));
    mini_resp_free_array(fields, count);
    mini_resp_close(&peer);
    return ok;
}

typedef struct {
    qihse_resp_server_t* server;
    char seeds[8][QIHSE_CLUSTER_HOST_LEN + 8u];
    size_t seed_count;
} join_ctx_t;

/* Dynamic join: once the bus is running, repeatedly MEET the seeds until the
 * topology contains at least one other node (or retries are exhausted). */
static void* join_main(void* argument) {
    join_ctx_t* j = (join_ctx_t*)argument;
    qihse_cluster_bus_t* bus = NULL;
    for (int wait = 0; wait < 40 && !bus && !g_stop; wait++) { /* bus starts with the server */
        bus = qihse_resp_server_bus(j->server);
        if (bus && qihse_cluster_bus_fd(bus) < 0) bus = NULL; /* not started yet */
        struct timespec ts = {0, 250 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if (!bus) {
        fprintf(stderr, "qihse-cluster-daemon: bus never started; join failed\n");
        return NULL;
    }
    /* Retry indefinitely while the daemon lives: lossy/asymmetric paths
     * (WiFi, firewalled segments) can take far longer than a fixed window
     * to come up, and a node that stopped trying never joins. */
    while (!g_stop) {
        for (size_t i = 0; i < j->seed_count; i++) {
            char spec[QIHSE_CLUSTER_HOST_LEN + 8u];
            snprintf(spec, sizeof(spec), "%s", j->seeds[i]);
            char* colon = strrchr(spec, ':');
            if (!colon) continue;
            *colon = '\0';
            char* end = NULL;
            unsigned long port = strtoul(colon + 1, &end, 10);
            if (end == colon + 1 || *end != '\0' || port == 0 || port > UINT16_MAX) continue;
            qihse_cluster_bus_meet(bus, spec, (uint16_t)port);
        }
        /* Joined = membership discovered AND slot map received (a joiner
         * without slots cannot route anything). */
        qihse_cluster_topology_t* topology =
            (qihse_cluster_topology_t*)qihse_resp_server_topology(j->server);
        qihse_cluster_node_t nodes[64];
        size_t count = qihse_cluster_topology_nodes(topology, nodes, 64);
        if (count > 1 && qihse_cluster_topology_is_covered(topology)) {
            fprintf(stderr, "qihse-cluster-daemon: joined cluster, %zu nodes discovered\n", count);
            return NULL;
        }
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
    }
    return NULL; /* shutdown requested: stop probing a server being torn down */
}

/* Group certificates use the same operator-provisioned QKP pins as data
 * replication. Reuse those identities; do not require a second key/account
 * workflow merely to make a configured group promotable. */
static bool ct_group_bus_bind_identity(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_cluster_bus_t* bus,
    qihse_cluster_topology_t* topology, uint16_t local,
    const ct_identity_map_set_t* maps,
    const qihse_qkp_replication_peer_t* peers, size_t peer_count,
    void* signing_key) {
    if (!store || !principal || !qihse_auth_user_is_active(principal) ||
        qihse_user_get_role(principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(principal) != QIHSE_TENANT_SYSTEM ||
        !bus || !topology || !maps || !signing_key) return false;
    qihse_federation_node_identity_t* identity = calloc(2u, sizeof(*identity));
    if (!identity) return false;
    bool ok = true;
    qihse_uuid_t self = {0};
    for (size_t i = 0; ok && i < maps->count; ++i) {
        uint16_t index = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_node_t node;
        if (!qihse_cluster_topology_find_node(topology, maps->entries[i].topology_id, &index) ||
            !qihse_cluster_topology_get_node(topology, index, &node)) { ok = false; break; }
        EVP_PKEY* key = index == local ? signing_key : NULL;
        bool own_key = false;
        for (size_t j = 0; !key && j < peer_count; ++j) {
            if (strcmp(peers[j].node_id, maps->entries[i].qkp_node_id)) continue;
            FILE* file = fopen(peers[j].dsa_pub_path, "rb");
            key = file ? PEM_read_PUBKEY(file, NULL, NULL, NULL) : NULL;
            if (file) fclose(file);
            own_key = key != NULL;
        }
        memset(identity, 0, sizeof(*identity) * 2u);
        size_t key_bytes = sizeof(identity[0].public_key);
        ok = key && qihse_federation_pkey_sig_alg(key, &identity[0].sig_alg) &&
            identity[0].sig_alg == QIHSE_SIG_ML_DSA_87 &&
            EVP_PKEY_get_raw_public_key(key, identity[0].public_key, &key_bytes) == 1 &&
            key_bytes == qihse_sig_alg_public_key_bytes(identity[0].sig_alg) &&
            qihse_cluster_node_federation_uuid(node.id, identity[0].node_id.bytes);
        if (own_key) EVP_PKEY_free(key);
        if (!ok) break;
        identity[0].public_key_len = (uint16_t)key_bytes;
        identity[0].identity_kind = QIHSE_IDENTITY_HOST_AGENT;
        snprintf(identity[0].hostname, sizeof(identity[0].hostname), "%s", node.id);
        snprintf(identity[0].key_handle, sizeof(identity[0].key_handle), "configured-ct-pin");
        if (qihse_federation_node_identity_read(store, principal,
                &identity[0].node_id, &identity[1])) {
            /* Configuration never revives a revoked identity or replaces a
             * different durable key. Exact restart is idempotent. */
            ok = (identity[1].trust == QIHSE_TRUST_APPROVED ||
                  identity[1].trust == QIHSE_TRUST_PENDING) &&
                identity[1].sig_alg == identity[0].sig_alg &&
                identity[1].public_key_len == key_bytes &&
                CRYPTO_memcmp(identity[1].public_key, identity[0].public_key, key_bytes) == 0;
            if (ok && identity[1].trust == QIHSE_TRUST_PENDING)
                ok = qihse_federation_node_enroll_approve(store, principal,
                    &identity[0].node_id, 1u);
        } else {
            ok = qihse_federation_node_enroll_request(store, principal, &identity[0]) &&
                qihse_federation_node_enroll_approve(store, principal, &identity[0].node_id, 1u);
        }
        if (ok && index == local) self = identity[0].node_id;
    }
    ok = ok && !qihse_uuid_is_nil(&self) && qihse_kv_sync_store(store);
    qihse_uuid_t boot = {0};
    ok = ok && qihse_uuid_generate(&boot);
    if (ok) qihse_cluster_bus_set_federation(bus, store, principal, &self,
        signing_key, NULL, &boot);
    OPENSSL_cleanse(identity, sizeof(*identity) * 2u);
    free(identity);
    return ok;
}

int main(int argc, char** argv) {

    /* Signed ops frames (hybrid bus upgrade): load this node's ML-DSA
     * identity to sign SLOT/NODE/GROUP frames; optionally require
     * signatures from peers on receive. */
    const char* node_key_path = NULL;
    bool require_signed_ops = false;

    unsigned int self_index = 0;
    const char* bind = "127.0.0.1";
    uint16_t port = 7100, bus_port = 17100;
    const char* operator_password = NULL;
    char* operator_password_arg = NULL;
    uint32_t replication_principal_id = 65535u;
    uint16_t replication_principal_clearance = UINT16_MAX;
    uint16_t replication_principal_sci = UINT16_MAX;
    uint32_t machine_principal_id = 0u;      /* 0 = no machine principal */
    uint32_t machine_principal_tenant = 0u;
    const char* admin_peer_node_id = NULL;
    const char* admin_peer_dsa_pub = NULL;
    const char* migration_peer_node_ids[16];
    const char* migration_peer_dsa_pub_paths[16];
    size_t migration_peer_count = 0u;
    const char* data_dir = NULL;
    bool enable_scatter = false;
    bool failover_start_paused = false;
    bool startup_maintenance_held = false;
    size_t max_clients = 4096u;
    peer_spec_t peers[MAX_PEERS];
    uint16_t replica_primary[MAX_PEERS];
    memset(replica_primary, 0xFF, sizeof(replica_primary));
    size_t peer_count = 0;
    /* Dynamic discovery seeds (--join HOST:BUSPORT). When present, the static
     * peer list is optional: membership is learned over the bus via MEET. */
    char seeds[8][QIHSE_CLUSTER_HOST_LEN + 8u];
    size_t seed_count = 0;
    bool self_has_slots = false;
    uint16_t self_slot_first = 0, self_slot_last = 0;
    bool brain_enabled = false, brain_act = false;
    const char* redundancy_peer = NULL;
    const char* irc_server = NULL;
    const char* irc_channel = NULL;
    const char* irc_nick_prefix = "qihse";
    const char* brain_dir = NULL;
    const char* brain_dsa_key = "/etc/qihse/keys/qihse_dsa_key.pem";
    const char* brain_fed_dir = NULL;   /* federation journal (default: brain_dir) */
    const char* brain_node_key = NULL;  /* decision signing key (default: brain_dsa_key) */
    uint32_t brain_interval = 5;
    uint32_t brain_cooldown = 30;         /* per-range re-home cooldown (seconds) */
    uint32_t brain_rollback_window = 60;  /* R4 evaluation window (seconds) */
    uint32_t brain_prune_timeout = 0;     /* stale-node prune (0 = disabled) */
    uint32_t brain_rebalance_min = 0;     /* rebalance-on-join threshold (0 = disabled) */
    bool brain_mode_explicit = false;
    bool brain_act_explicit = false;
    char repl_globs[16][128];
    const char* repl_glob_ptrs[16];
    size_t repl_glob_count = 0;
    uint32_t repl_interval = 60;          /* anti-entropy tick (0 = disabled) */
    uint32_t kv_sweep_interval = 30;      /* expiry sweep + sstable compaction cadence (0 = disabled) */
    const char* pqc_identity_dir = NULL;  /* --pqc-identity-dir */
    const char* pqc_node_id = NULL;
    const char* replication_source_host = NULL;
    const char* replication_transport = NULL; /* default resolved dynamically: "direct" over LAN (192.168.x.x), else "wireguard" */
    uint16_t replication_source_port = 0;
    uint16_t replication_socks_port = 4447;
    bool replica_read_only = false;
    const char* replication_peer_node_id = NULL;
    const char* replication_peer_dsa_pub = NULL;
    const char* ct_role = NULL;
    const char* ct_auto_successor_id = NULL;
    bool ct_learn_generation = false;
    char ct_recovered_generation[33] = {0};
    bool consensus_authority_proposals = false;
    const char* ct_peer_host = NULL;
    char ct_peer_host_storage[256];
    memset(ct_peer_host_storage, 0, sizeof(ct_peer_host_storage));
    const char* ct_generation_hex = NULL;
    qihse_ct_group_config_t* ct_groups = NULL;
    size_t ct_group_count = 0u;
    size_t ct_group_capacity = 0u;
    uint16_t ct_peer_port = 0u;
    uint64_t ct_log_limit_bytes = 0u;
    uint32_t ct_ack_timeout_ms = 0u;
    qihse_qkp_replication_peer_t replication_allowed_peers[QIHSE_QKP_MAX_REPLICATION_PEERS];
    size_t replication_allowed_peer_count = 0u;
    ct_identity_map_t ct_identity_map_options[QIHSE_QKP_MAX_REPLICATION_PEERS];
    size_t ct_identity_map_option_count = 0u;
    const char* pqc_trusted[16];
    size_t pqc_trusted_count = 0;
    bool pqc_require = false;
    bool pqc_degraded = false;            /* identity dir requested, keys missing */
    daemon_consensus_options_t consensus_options;
    memset(&consensus_options, 0, sizeof(consensus_options));
    bool consensus_configured = false;
    bool consensus_allow_client_proposals = false;
    bool consensus_prefix_signer_configured = false;
    qihse_uuid_t consensus_prefix_signer;
    memset(&consensus_prefix_signer, 0, sizeof(consensus_prefix_signer));

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "--index") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v >= MAX_PEERS) return usage(argv[0]), 2;
            self_index = (unsigned int)v;
        } else if (strcmp(a, "--bind") == 0 && i + 1 < argc) {
            bind = argv[++i];
        } else if (strcmp(a, "--port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &port)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--node-key") == 0 && i + 1 < argc) {
            node_key_path = argv[++i];
        } else if (strcmp(a, "--require-signed-ops") == 0) {
            require_signed_ops = true;
        } else if (strcmp(a, "--bus-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &bus_port)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--operator-password") == 0 && i + 1 < argc) {
            operator_password_arg = argv[++i];
        } else if (strcmp(a, "--dir") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(a, "--failover-start-paused") == 0) {
            failover_start_paused = true;
        } else if (strcmp(a, "--startup-maintenance-held") == 0) {
            startup_maintenance_held = true;
        } else if (strcmp(a, "--enable-scatter") == 0) {
            enable_scatter = true;
        } else if (strcmp(a, "--max-clients") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 65536u) return usage(argv[0]), 2;
            max_clients = v;
        } else if (strcmp(a, "--slot-range") == 0 && i + 1 < argc) {
            self_has_slots = parse_slot_range(argv[++i], &self_slot_first, &self_slot_last);
            if (!self_has_slots) return usage(argv[0]), 2;
        } else if (strcmp(a, "--redundancy-peer") == 0 && i + 1 < argc) {
            redundancy_peer = argv[++i];
        } else if (strcmp(a, "--irc-server") == 0 && i + 1 < argc) {
            irc_server = argv[++i];
        } else if (strcmp(a, "--irc-channel") == 0 && i + 1 < argc) {
            irc_channel = argv[++i];
        } else if (strcmp(a, "--irc-nick-prefix") == 0 && i + 1 < argc) {
            irc_nick_prefix = argv[++i];
        } else if (strcmp(a, "--brain") == 0) {
            brain_mode_explicit = true;
            brain_enabled = true;
        } else if (strcmp(a, "--brain-act") == 0) {
            brain_act_explicit = true;
            brain_enabled = true;
            brain_act = true;
        } else if (strcmp(a, "--brain-dir") == 0 && i + 1 < argc) {
            brain_dir = argv[++i];
        } else if (strcmp(a, "--brain-interval") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 3600u) return usage(argv[0]), 2;
            brain_interval = (uint32_t)v;
        } else if (strcmp(a, "--brain-dsa-key") == 0 && i + 1 < argc) {
            brain_dsa_key = argv[++i];
        } else if (strcmp(a, "--brain-fed-dir") == 0 && i + 1 < argc) {
            brain_fed_dir = argv[++i];
        } else if (strcmp(a, "--brain-node-key") == 0 && i + 1 < argc) {
            brain_node_key = argv[++i];
        } else if (strcmp(a, "--brain-cooldown") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 86400u) return usage(argv[0]), 2;
            brain_cooldown = (uint32_t)v;
        } else if (strcmp(a, "--brain-rollback-window") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 86400u) return usage(argv[0]), 2;
            brain_rollback_window = (uint32_t)v;
        } else if (strcmp(a, "--brain-prune-timeout") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > 86400u) return usage(argv[0]), 2;
            brain_prune_timeout = (uint32_t)v;
        } else if (strcmp(a, "--brain-rebalance-min-slots") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > QIHSE_CLUSTER_SLOT_COUNT) return usage(argv[0]), 2;
            brain_rebalance_min = (uint32_t)v;
        } else if (strcmp(a, "--no-replicate") == 0 || strcmp(a, "--replicate-none") == 0) {
            repl_glob_count = 0;
        } else if (strcmp(a, "--replicate") == 0 && i + 1 < argc) {
            const char* val = argv[++i];
            if (strcmp(val, "none") == 0) {
                repl_glob_count = 0;
            } else {
                if (repl_glob_count >= sizeof(repl_globs) / sizeof(repl_globs[0])) return usage(argv[0]), 2;
                if (strlen(val) >= sizeof(repl_globs[0])) return usage(argv[0]), 2;
                if (strcmp(val, "all") == 0) val = "*";
                snprintf(repl_globs[repl_glob_count], sizeof(repl_globs[0]), "%s", val);
                repl_glob_ptrs[repl_glob_count] = repl_globs[repl_glob_count];
                repl_glob_count++;
            }
        } else if (strcmp(a, "--pqc-identity-dir") == 0 && i + 1 < argc) {
            pqc_identity_dir = argv[++i];
        } else if (strcmp(a, "--pqc-node-id") == 0 && i + 1 < argc) {
            pqc_node_id = argv[++i];
            if (!*pqc_node_id || strlen(pqc_node_id) > QIHSE_QKP_NODE_ID_LEN) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-source-host") == 0 && i + 1 < argc) {
            replication_source_host = argv[++i];
            if (!*replication_source_host || strlen(replication_source_host) > 255u) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-source-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &replication_source_port)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-principal-id") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0u || v > 65535u)
                return usage(argv[0]), 2;
            replication_principal_id = (uint32_t)v;
        } else if (strcmp(a, "--replication-principal-clearance") == 0 && i + 1 < argc) {
            uint64_t v = 0u;
            if (!parse_u64_decimal(argv[++i], &v) || v > UINT16_MAX)
                return usage(argv[0]), 2;
            replication_principal_clearance = (uint16_t)v;
        } else if (strcmp(a, "--replication-principal-sci") == 0 && i + 1 < argc) {
            uint64_t v = 0u;
            if (!parse_u64_decimal(argv[++i], &v) || v > UINT16_MAX)
                return usage(argv[0]), 2;
            replication_principal_sci = (uint16_t)v;
        } else if (strcmp(a, "--machine-principal-id") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0u || v > 65535u)
                return usage(argv[0]), 2;
            machine_principal_id = (uint32_t)v;
        } else if (strcmp(a, "--machine-principal-tenant") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end)
                return usage(argv[0]), 2;
            machine_principal_tenant = (uint32_t)v;
        } else if (strcmp(a, "--admin-peer-node-id") == 0 && i + 1 < argc) {
            admin_peer_node_id = argv[++i];
            if (!*admin_peer_node_id || strlen(admin_peer_node_id) > QIHSE_QKP_NODE_ID_LEN)
                return usage(argv[0]), 2;
        } else if (strcmp(a, "--admin-peer-dsa-pub") == 0 && i + 1 < argc) {
            admin_peer_dsa_pub = argv[++i];
            if (!*admin_peer_dsa_pub) return usage(argv[0]), 2;
        } else if (strcmp(a, "--migration-peer") == 0 && i + 2 < argc) {
            if (migration_peer_count >= 16u) return usage(argv[0]), 2;
            const char* nid = argv[++i];
            const char* pub = argv[++i];
            if (!*nid || strlen(nid) > QIHSE_QKP_NODE_ID_LEN || !*pub)
                return usage(argv[0]), 2;
            migration_peer_node_ids[migration_peer_count] = nid;
            migration_peer_dsa_pub_paths[migration_peer_count] = pub;
            migration_peer_count++;
        } else if (strcmp(a, "--replication-transport") == 0 && i + 1 < argc) {
            replication_transport = argv[++i];
            if (strcmp(replication_transport, "i2p") != 0 &&
                strcmp(replication_transport, "wireguard") != 0 &&
                strcmp(replication_transport, "direct") != 0) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-socks-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &replication_socks_port) || replication_socks_port == 0u) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replica-read-only") == 0) {
            replica_read_only = true;
        } else if (strcmp(a, "--pqc-trusted-pub") == 0 && i + 1 < argc) {
            if (pqc_trusted_count >= sizeof(pqc_trusted) / sizeof(pqc_trusted[0])) return usage(argv[0]), 2;
            pqc_trusted[pqc_trusted_count++] = argv[++i];
        } else if (strcmp(a, "--replication-allowed-peer") == 0 && i + 2 < argc) {
            if (replication_allowed_peer_count == QIHSE_QKP_MAX_REPLICATION_PEERS)
                return usage(argv[0]), 2;
            const char* id = argv[++i];
            const char* pub = argv[++i];
            if (!*id || strlen(id) > QIHSE_QKP_NODE_ID_LEN || !*pub ||
                strlen(pub) >= PATH_MAX) return usage(argv[0]), 2;
            replication_allowed_peers[replication_allowed_peer_count++] =
                (qihse_qkp_replication_peer_t){id, pub};
        } else if (strcmp(a, "--topology-qkp-map") == 0 && i + 2 < argc) {
            if (ct_identity_map_option_count == QIHSE_QKP_MAX_REPLICATION_PEERS)
                return usage(argv[0]), 2;
            const char* topology_id = argv[++i];
            const char* qkp_id = argv[++i];
            if (strlen(topology_id) != QIHSE_CLUSTER_NODE_ID_LEN || !*qkp_id ||
                strlen(qkp_id) > QIHSE_QKP_NODE_ID_LEN)
                return usage(argv[0]), 2;
            for (size_t k = 0; k < QIHSE_CLUSTER_NODE_ID_LEN; ++k)
                if (!((topology_id[k] >= '0' && topology_id[k] <= '9') ||
                      (topology_id[k] >= 'a' && topology_id[k] <= 'f')))
                    return usage(argv[0]), 2;
            for (size_t k = 0; k < ct_identity_map_option_count; ++k)
                if (strcmp(ct_identity_map_options[k].topology_id, topology_id) == 0)
                    return usage(argv[0]), 2;
            snprintf(ct_identity_map_options[ct_identity_map_option_count].topology_id,
                     sizeof(ct_identity_map_options[0].topology_id), "%s", topology_id);
            snprintf(ct_identity_map_options[ct_identity_map_option_count].qkp_node_id,
                     sizeof(ct_identity_map_options[0].qkp_node_id), "%s", qkp_id);
            ++ct_identity_map_option_count;
        } else if (strcmp(a, "--replication-peer-node-id") == 0 && i + 1 < argc) {
            replication_peer_node_id = argv[++i];
            if (!*replication_peer_node_id || strlen(replication_peer_node_id) > QIHSE_QKP_NODE_ID_LEN) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-peer-dsa-pub") == 0 && i + 1 < argc) {
            replication_peer_dsa_pub = argv[++i];
            if (!*replication_peer_dsa_pub) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replica-of") == 0 && i + 1 < argc) {
            char pair[32]; const char* option = argv[++i];
            if (strlen(option) >= sizeof(pair)) return usage(argv[0]), 2;
            snprintf(pair, sizeof(pair), "%s", option);
            char* colon = strchr(pair, ':'); uint16_t replica, primary;
            if (!colon || strchr(colon + 1, ':')) return usage(argv[0]), 2;
            *colon = '\0';
            if (!parse_u16(pair, &replica) || !parse_u16(colon + 1, &primary) ||
                replica >= MAX_PEERS || primary >= MAX_PEERS || replica == primary ||
                replica_primary[replica] != QIHSE_CLUSTER_NODE_NONE)
                return usage(argv[0]), 2;
            replica_primary[replica] = primary;
        } else if (strcmp(a, "--ct-auto-successor") == 0 && i + 1 < argc) {
            ct_auto_successor_id = argv[++i];
            if (!*ct_auto_successor_id || strlen(ct_auto_successor_id) > QIHSE_CLUSTER_NODE_ID_LEN)
                return usage(argv[0]), 2;
        } else if (strcmp(a, "--ct-learn-generation") == 0) {
            ct_learn_generation = true;
        } else if (strcmp(a, "--consensus-authority-proposals") == 0) {
            consensus_authority_proposals = true;
        } else if (strcmp(a, "--ct-role") == 0 && i + 1 < argc) {
            ct_role = argv[++i];
            if (strcmp(ct_role, "primary") != 0 && strcmp(ct_role, "successor") != 0)
                return usage(argv[0]), 2;
        } else if (strcmp(a, "--ct-group") == 0 && i + 1 < argc) {
            if (ct_group_count == ct_group_capacity) {
                size_t next_capacity = ct_group_capacity ? ct_group_capacity * 2u : 4u;
                if (next_capacity < ct_group_capacity ||
                    next_capacity > SIZE_MAX / sizeof(*ct_groups)) {
                    fprintf(stderr, "qihse-cluster-daemon: too many --ct-group entries\n");
                    free(ct_groups);
                    return 2;
                }
                qihse_ct_group_config_t* next = realloc(ct_groups,
                    next_capacity * sizeof(*ct_groups));
                if (!next) {
                    fprintf(stderr, "qihse-cluster-daemon: cannot allocate --ct-group configuration\n");
                    free(ct_groups);
                    return 1;
                }
                ct_groups = next;
                memset(ct_groups + ct_group_capacity, 0,
                    (next_capacity - ct_group_capacity) * sizeof(*ct_groups));
                ct_group_capacity = next_capacity;
            }
            if (!qihse_ct_group_config_parse(argv[++i],
                    &ct_groups[ct_group_count])) {
                fprintf(stderr, "qihse-cluster-daemon: invalid --ct-group; expected LANE64,OWNER40,SUCCESSOR40,GENERATION32,SLOTS\n");
                free(ct_groups);
                return 2;
            }
            ++ct_group_count;
        } else if (strcmp(a, "--ct-peer") == 0 && i + 1 < argc) {
            const char* spec = argv[++i];
            const char* colon = strrchr(spec, ':');
            if (!colon || colon == spec || (size_t)(colon - spec) >= sizeof(ct_peer_host_storage) ||
                !parse_u16(colon + 1, &ct_peer_port) || !ct_peer_port)
                return usage(argv[0]), 2;
            memcpy(ct_peer_host_storage, spec, (size_t)(colon - spec));
            ct_peer_host = ct_peer_host_storage;
        } else if (strcmp(a, "--ct-generation") == 0 && i + 1 < argc) {
            ct_generation_hex = argv[++i];
            if (strlen(ct_generation_hex) != 32u) return usage(argv[0]), 2;
            for (size_t k = 0; k < 32u; ++k)
                if (!((ct_generation_hex[k] >= '0' && ct_generation_hex[k] <= '9') ||
                      (ct_generation_hex[k] >= 'a' && ct_generation_hex[k] <= 'f')))
                    return usage(argv[0]), 2;
        } else if (strcmp(a, "--ct-log-limit") == 0 && i + 1 < argc) {
            if (!parse_u64_decimal(argv[++i], &ct_log_limit_bytes) || !ct_log_limit_bytes)
                return usage(argv[0]), 2;
        } else if (strcmp(a, "--ct-ack-timeout-ms") == 0 && i + 1 < argc) {
            uint64_t timeout = 0u;
            if (!parse_u64_decimal(argv[++i], &timeout) || !timeout || timeout > 300000u)
                return usage(argv[0]), 2;
            ct_ack_timeout_ms = (uint32_t)timeout;
        } else if (strcmp(a, "--pqc-require") == 0) {
            pqc_require = true;
        } else if (strcmp(a, "--kv-sweep-interval") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > 86400ul) return usage(argv[0]), 2;
            kv_sweep_interval = (uint32_t)v;
        } else if (strcmp(a, "--replicate-interval") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > 86400u) return usage(argv[0]), 2;
            repl_interval = (uint32_t)v;
        } else if (strcmp(a, "--consensus-group") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (!consensus_group_id_valid(argv[i + 1])) return usage(argv[0]), 2;
            snprintf(consensus_options.group_id, sizeof(consensus_options.group_id), "%s", argv[++i]);
        } else if (strcmp(a, "--consensus-self") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (!qihse_uuid_parse(argv[++i], &consensus_options.self) ||
                qihse_uuid_is_nil(&consensus_options.self)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--consensus-bootstrap-unadmitted") == 0) {
            consensus_configured = true;
            consensus_options.bootstrap_unadmitted = true;
        } else if (strcmp(a, "--consensus-member") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (consensus_options.member_count >= QIHSE_CONSENSUS_MAX_MEMBERS ||
                !qihse_uuid_parse(argv[++i], &consensus_options.members[consensus_options.member_count]) ||
                qihse_uuid_is_nil(&consensus_options.members[consensus_options.member_count])) return usage(argv[0]), 2;
            consensus_options.member_count++;
        } else if (strcmp(a, "--consensus-listen-ip") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (!*argv[i + 1] || strlen(argv[i + 1]) >= sizeof(consensus_options.listen_ipv4)) return usage(argv[0]), 2;
            snprintf(consensus_options.listen_ipv4, sizeof(consensus_options.listen_ipv4), "%s", argv[++i]);
        } else if (strcmp(a, "--consensus-port") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (!parse_u16(argv[++i], &consensus_options.port) || !consensus_options.port) return usage(argv[0]), 2;
        } else if (strcmp(a, "--consensus-election-priority-delay-ms") == 0 && i + 1 < argc) {
            uint16_t delay_ms = 0u;
            consensus_configured = true;
            if (!parse_u16(argv[++i], &delay_ms) ||
                delay_ms > QIHSE_CONSENSUS_MAX_ELECTION_PRIORITY_DELAY_MS)
                return usage(argv[0]), 2;
            consensus_options.election_priority_delay_ms = delay_ms;
        } else if (strcmp(a, "--consensus-priority-tier") == 0 && i + 1 < argc) {
            uint16_t tier = 0u;
            consensus_configured = true;
            if (!parse_u16(argv[++i], &tier))
                return usage(argv[0]), 2;
            consensus_options.priority_tier = tier;
        } else if (strcmp(a, "--consensus-wan-rtt-ms") == 0 && i + 1 < argc) {
            uint16_t rtt = 0u;
            consensus_configured = true;
            if (!parse_u16(argv[++i], &rtt))
                return usage(argv[0]), 2;
            consensus_options.wan_rtt_ms = rtt;
        } else if (strcmp(a, "--consensus-prevote") == 0) {
            consensus_configured = true;
            consensus_options.enable_prevote = true;
        } else if (strcmp(a, "--consensus-election-base-ms") == 0 && i + 1 < argc) {
            uint16_t value = 0u;
            consensus_configured = true;
            if (!parse_u16(argv[++i], &value) || !value || value > 60000u)
                return usage(argv[0]), 2;
            consensus_options.election_timeout_base_ms = value;
        } else if (strcmp(a, "--consensus-election-spread-ms") == 0 && i + 1 < argc) {
            uint16_t value = 0u;
            consensus_configured = true;
            if (!parse_u16(argv[++i], &value) || !value || value > 60000u)
                return usage(argv[0]), 2;
            consensus_options.election_timeout_spread_ms = value;
        } else if (strcmp(a, "--consensus-heartbeat-ms") == 0 && i + 1 < argc) {
            uint16_t value = 0u;
            consensus_configured = true;
            if (!parse_u16(argv[++i], &value) || !value || value > 60000u)
                return usage(argv[0]), 2;
            consensus_options.heartbeat_interval_ms = value;
        } else if (strcmp(a, "--consensus-allow-client-proposals") == 0) {
            consensus_allow_client_proposals = true;
        } else if (strcmp(a, "--consensus-prefix-signer") == 0 && i + 1 < argc) {
            if (consensus_prefix_signer_configured ||
                !qihse_uuid_parse(argv[++i], &consensus_prefix_signer) ||
                qihse_uuid_is_nil(&consensus_prefix_signer))
                return usage(argv[0]), 2;
            consensus_prefix_signer_configured = true;
        } else if (strcmp(a, "--consensus-history-id") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (consensus_options.history_id_supplied) return usage(argv[0]), 2;
            if (!consensus_history_id_parse(argv[++i], consensus_options.history_id))
                return usage(argv[0]), 2;
            consensus_options.history_id_supplied = true;
        } else if (strcmp(a, "--consensus-writer-epoch") == 0 && i + 1 < argc) {
            consensus_configured = true;
            if (consensus_options.writer_epoch_supplied) return usage(argv[0]), 2;
            if (!parse_u64_decimal(argv[++i],
                                   &consensus_options.writer_epoch_floor) ||
                consensus_options.writer_epoch_floor == 0)
                return usage(argv[0]), 2;
            consensus_options.writer_epoch_supplied = true;
        } else if (strcmp(a, "--consensus-peer") == 0 && i + 1 < argc) {
            consensus_configured = true;
            char peer_arg[1200];
            if (strlen(argv[i + 1]) >= sizeof(peer_arg)) return usage(argv[0]), 2;
            snprintf(peer_arg, sizeof(peer_arg), "%s", argv[++i]);
            if (!parse_consensus_peer(peer_arg, &consensus_options)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--join") == 0 && i + 1 < argc) {
            if (seed_count >= 8u) return usage(argv[0]), 2;
            snprintf(seeds[seed_count++], QIHSE_CLUSTER_HOST_LEN + 8u, "%s", argv[++i]);
        } else if (strcmp(a, "--node") == 0 && i + 1 < argc) {
            /* INDEX:HOST:PORT:BUS-PORT */
            char spec[512];
            snprintf(spec, sizeof(spec), "%s", argv[++i]);
            char* save = NULL;
            char* idx_s = strtok_r(spec, ":", &save);
            char* host = strtok_r(NULL, ":", &save);
            char* port_s = strtok_r(NULL, ":", &save);
            char* bus_s = strtok_r(NULL, ":", &save);
            unsigned long idx;
            if (!idx_s || !host || !port_s || !bus_s || peer_count >= MAX_PEERS) return usage(argv[0]), 2;
            char* end = NULL; errno = 0;
            idx = strtoul(idx_s, &end, 10);
            if (errno != 0 || !end || *end || idx >= MAX_PEERS) return usage(argv[0]), 2;
            peer_spec_t* p = &peers[peer_count++];
            p->index = (unsigned int)idx;
            snprintf(p->host, sizeof(p->host), "%s", host);
            if (!parse_u16(port_s, &p->port) || !parse_u16(bus_s, &p->bus_port)) return usage(argv[0]), 2;
            p->has_slots = false;
        } else if (strcmp(a, "--slot-range-of") == 0 && i + 1 < argc) {
            /* INDEX:FIRST-LAST */
            char spec[128];
            snprintf(spec, sizeof(spec), "%s", argv[++i]);
            char* colon = strchr(spec, ':');
            if (!colon || peer_count == 0) return usage(argv[0]), 2;
            *colon = '\0';
            char* end = NULL; errno = 0;
            unsigned long idx = strtoul(spec, &end, 10);
            if (errno != 0 || !end || *end || idx >= MAX_PEERS) return usage(argv[0]), 2;
            for (size_t k = peer_count; k > 0; k--) {
                if (peers[k - 1u].index == (unsigned int)idx) {
                    peers[k - 1u].has_slots =
                        parse_slot_range(colon + 1, &peers[k - 1u].slot_first, &peers[k - 1u].slot_last);
                    if (!peers[k - 1u].has_slots) return usage(argv[0]), 2;
                    break;
                }
            }
        } else {
            return usage(argv[0]), 2;
        }
    }

    if (consensus_allow_client_proposals && !consensus_configured) {
        fprintf(stderr, "qihse-cluster-daemon: --consensus-allow-client-proposals requires a consensus mesh\n");
        return 2;
    }
    if (consensus_prefix_signer_configured && !consensus_configured) {
        fprintf(stderr, "qihse-cluster-daemon: --consensus-prefix-signer requires a consensus mesh\n");
        return 2;
    }
    if (redundancy_peer) {
        fprintf(stderr, "qihse-cluster-daemon: --redundancy-peer is unavailable until duplicate writes use pinned QKP replication\n");
        return 2;
    }
    if (brain_act && !pqc_identity_dir && access("/etc/qihse/keys/qihse_dsa_key.pem", R_OK) != 0) {
        fprintf(stderr, "qihse-cluster-daemon: --brain-act needs a QKP identity (--pqc-identity-dir) for the pinned slot-migration handoff\n");
        return 2;
    }

    const bool replication_configured = replication_source_host != NULL ||
        replication_peer_node_id != NULL || replication_peer_dsa_pub != NULL ||
        replication_allowed_peer_count != 0u;
    const bool admin_peer_configured = admin_peer_node_id != NULL ||
        admin_peer_dsa_pub != NULL;
    if (admin_peer_node_id != NULL && admin_peer_dsa_pub == NULL) {
        fprintf(stderr, "qihse-cluster-daemon: --admin-peer-node-id requires --admin-peer-dsa-pub\n");
        return 2;
    }
    if (admin_peer_dsa_pub != NULL && admin_peer_node_id == NULL) {
        fprintf(stderr, "qihse-cluster-daemon: --admin-peer-dsa-pub requires --admin-peer-node-id\n");
        return 2;
    }
    if ((replication_source_host != NULL) != (replication_source_port != 0u)) {
        fprintf(stderr, "qihse-cluster-daemon: replication source host and port must be configured together\n");
        return 2;
    }
    if (replication_source_host) {
        size_t source_len = strlen(replication_source_host);
        bool is_i2p_name = (source_len >= 4u && strcasecmp(replication_source_host + source_len - 4u, ".i2p") == 0);

        if (!replication_transport) {
            /* Default to WireGuard for private overlay, except over LAN where it is direct */
            if (is_i2p_name) {
                fprintf(stderr, "qihse-cluster-daemon: I2P replication transport is opt-in only; pass --replication-transport i2p explicitly to enable I2P garlic routing\n");
                return 2;
            }
            struct in_addr address;
            if (inet_pton(AF_INET, replication_source_host, &address) == 1) {
                uint32_t host_addr = ntohl(address.s_addr);
                if ((host_addr >> 16) == ((192u << 8) | 168u) || (host_addr >> 24) == 127u) {
                    replication_transport = "direct";
                } else if ((host_addr >> 24) == 10u || (host_addr >> 20) == ((172u << 4) | 1u)) {
                    replication_transport = "wireguard";
                } else {
                    fprintf(stderr, "qihse-cluster-daemon: replication source must be RFC1918 private IPv4 (e.g. 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n");
                    return 2;
                }
            } else {
                fprintf(stderr, "qihse-cluster-daemon: replication source must be a private IPv4 address or an .i2p destination\n");
                return 2;
            }
        }

        if (strcmp(replication_transport, "i2p") == 0) {
            if (!is_i2p_name) {
                fprintf(stderr, "qihse-cluster-daemon: replication source must be an I2P destination name when --replication-transport i2p is specified\n");
                return 2;
            }
        } else if (strcmp(replication_transport, "wireguard") == 0 || strcmp(replication_transport, "direct") == 0) {
            struct in_addr address;
            if (inet_pton(AF_INET, replication_source_host, &address) != 1) {
                if (is_i2p_name) {
                    fprintf(stderr, "qihse-cluster-daemon: I2P replication transport is opt-in only; pass --replication-transport i2p explicitly to enable I2P garlic routing\n");
                } else {
                    fprintf(stderr, "qihse-cluster-daemon: replication source must be a private RFC1918 IPv4 address (e.g. LAN or WireGuard)\n");
                }
                return 2;
            }
            uint32_t host_addr = ntohl(address.s_addr);
            if (!((host_addr >> 24) == 10u ||
                  (host_addr >> 20) == ((172u << 4) | 1u) ||
                  (host_addr >> 16) == ((192u << 8) | 168u) ||
                  (host_addr >> 24) == 127u)) {
                fprintf(stderr, "qihse-cluster-daemon: replication source must be RFC1918 private IPv4 (e.g. 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n");
                return 2;
            }
        }
    }

    /* Capture the credential in mutable owned memory.  The legacy CLI option
     * remains for development, but its argv bytes are erased immediately after
     * capture. Production units should use a root-only EnvironmentFile. */
    char* configured_password = getenv("QIHSE_OPERATOR_PASSWORD");
    char* selected_password = operator_password_arg && *operator_password_arg
        ? operator_password_arg : configured_password;
    if (selected_password && *selected_password) {
        if (!operator_credential_capture(selected_password)) {
            operator_credential_scrub_source(operator_password_arg);
            operator_credential_clear_environment();
            fprintf(stderr, "qihse-cluster-daemon: operator password must be 12..4096 characters\n");
            return 2;
        }
        if (atexit(operator_credential_release) != 0) {
            operator_credential_release();
            operator_credential_scrub_source(operator_password_arg);
            operator_credential_clear_environment();
            fprintf(stderr, "qihse-cluster-daemon: could not register credential cleanup\n");
            return 1;
        }
        operator_password = g_operator_credential.value;
        operator_credential_scrub_source(operator_password_arg);
        operator_credential_clear_environment();
    }
    if (!operator_password) {
        char env_path[256];
        snprintf(env_path, sizeof(env_path), "/etc/qihse/cluster-node%u.env", self_index);
        FILE* ef = fopen(env_path, "r");
        if (ef) {
            char line[512];
            while (fgets(line, sizeof(line), ef)) {
                if (strncmp(line, "QIHSE_OPERATOR_PASSWORD=", 24) == 0) {
                    char* p = line + 24;
                    p[strcspn(p, "\r\n")] = '\0';
                    if (operator_credential_capture(p))
                        operator_password = g_operator_credential.value;
                    OPENSSL_cleanse(line, sizeof(line));
                    break;
                }
                OPENSSL_cleanse(line, sizeof(line));
            }
            fclose(ef);
        }
        if (operator_password && atexit(operator_credential_release) != 0) {
            operator_credential_release();
            fprintf(stderr, "qihse-cluster-daemon: could not register credential cleanup\n");
            return 1;
        }
    }
    /* Never expose a daemon without a configured operator verifier. */
    if (!operator_password && strcmp(bind, "127.0.0.1") != 0 &&
            strcmp(bind, "::1") != 0 && strcmp(bind, "localhost") != 0) {
        fprintf(stderr, "qihse-cluster-daemon: remote binding requires QIHSE_OPERATOR_PASSWORD (or /etc/qihse/cluster-node%u.env)\n",
                self_index);
        return 2;
    }
    if (consensus_prefix_signer_configured && !operator_password) {
        fprintf(stderr, "qihse-cluster-daemon: prefix challenges require authenticated RESP\n");
        return 2;
    }

    if (replication_source_host && (!replica_read_only || repl_glob_count != 1u ||
            repl_interval == 0u || !operator_password || !replication_peer_node_id ||
            !replication_peer_dsa_pub || !pqc_node_id)) {
        fprintf(stderr, "qihse-cluster-daemon: replica pull requires --replica-read-only, exactly one dedicated --replicate namespace, nonzero interval, operator password, stable --pqc-node-id, and a pinned upstream identity\n");
        return 2;
    }
    const bool ct_group_mode = ct_group_count != 0u;
    if (ct_group_mode) {
        /* Group configuration is sufficient to enable CT. Retention is a
         * configurable retransmission budget, not a whole-transfer cap. */
        if (!ct_log_limit_bytes) ct_log_limit_bytes = 512ull * 1024ull * 1024ull;
        if (!ct_ack_timeout_ms) ct_ack_timeout_ms = 5000u;
    }
    if (ct_group_mode && !brain_mode_explicit && !brain_act_explicit) {
        /* Group mode has no daemon-wide primary; every configured node can
         * participate in automatic balancing by default. Explicit --brain
         * keeps the operator's observe-only intent. */
        brain_enabled = true;
        brain_act = true;
    }
    const bool ct_configured = ct_group_mode || ct_role != NULL || ct_peer_host != NULL ||
        ct_generation_hex != NULL || ct_log_limit_bytes != 0u || ct_ack_timeout_ms != 0u;
    if ((ct_group_mode && (ct_role || ct_peer_host || ct_generation_hex ||
                           replication_peer_node_id || replication_peer_dsa_pub ||
                           replication_allowed_peer_count == 0u ||
                           !consensus_configured || !consensus_authority_proposals ||
                           !qihse_ct_group_configs_validate(ct_groups, ct_group_count))) ||
        (ct_configured && (!ct_log_limit_bytes || !ct_ack_timeout_ms ||
            !operator_password || !pqc_node_id || !pqc_identity_dir ||
            (!ct_group_mode && (!replication_peer_node_id || !replication_peer_dsa_pub)))) ||
        (!ct_group_mode && ct_configured && (!ct_role || !ct_peer_host || !ct_peer_port ||
            !ct_generation_hex))) {
        fprintf(stderr, "qihse-cluster-daemon: CT requires role, peer, generation, log limit, ACK timeout, Operator startup, QKP identity, and exact peer pin\n");
        return 2;
    }
    if ((ct_auto_successor_id && (!ct_configured || ct_group_mode || !consensus_configured ||
             !consensus_authority_proposals)) ||
        (ct_learn_generation && (!ct_configured || ct_group_mode ||
                                 !ct_role || strcmp(ct_role, "successor")))) {
        fprintf(stderr, "qihse-cluster-daemon: automatic CT requires a configured consensus authority; generation learning requires a pinned successor\n");
        return 2;
    }
    if (ct_configured && replica_read_only) {
        fprintf(stderr, "qihse-cluster-daemon: CT successor is promotable; --replica-read-only is not a CT substitute\n");
        return 2;
    }
    if (replication_allowed_peer_count && !operator_password) {
        fprintf(stderr, "qihse-cluster-daemon: --replication-allowed-peer requires startup Operator authentication\n");
        return 2;
    }
    if (replication_configured && !pqc_node_id) {
        fprintf(stderr, "qihse-cluster-daemon: replication requires explicit stable --pqc-node-id\n");
        return 2;
    }
    if (replication_configured) pqc_require = true;
    if (admin_peer_configured) pqc_require = true;
    if (migration_peer_count > 0u) pqc_require = true;
    if (consensus_configured) {
        const char* consensus_error = consensus_options_error(
            &consensus_options, data_dir, pqc_node_id, pqc_require,
            replica_read_only, replication_source_host != NULL);
        if (consensus_error) {
            fprintf(stderr, "qihse-cluster-daemon: invalid consensus mesh configuration: %s\n",
                    consensus_error);
            return 2;
        }
    }

    if (data_dir && *data_dir) {
        if (!mkdirs(data_dir)) {
            fprintf(stderr, "qihse-cluster-daemon: cannot create data dir %s\n", data_dir);
            return 1;
        }
        setenv("QIHSE_DATA_DIR", data_dir, 1);
    }
    bool durable_auth = false;
    uint32_t startup_user_id = 0u;
    if (!daemon_auth_startup(operator_password, operator_password != NULL,
                             consensus_configured, &durable_auth, &startup_user_id)) {
        operator_credential_clear_environment();
        operator_credential_release();
        return 2;
    }
    if (!durable_auth && operator_password && strlen(operator_password) >= 12) {
        setenv("QIHSE_OPERATOR_PASSWORD", operator_password, 1);
    } else if (!durable_auth && operator_password) {
        /* qihse_auth_bootstrap_operator() refuses passwords under 12 chars.
         * Continuing would enable auth_required with no usable verifier:
         * every AUTH would fail with WRONGPASS and nothing would say why. */
        fprintf(stderr, "qihse-cluster-daemon: --operator-password must be at least 12 characters\n");
        return 2;
    }
    if (!durable_auth && !qihse_auth_init()) {
        operator_credential_clear_environment();
        fprintf(stderr, "qihse-cluster-daemon: auth init failed\n");
        return 1;
    }
    if (!durable_auth && operator_password && strlen(operator_password) >= 12) {
        if (!qihse_auth_bootstrap_operator(operator_password)) {
            /* Already bootstrapped on a previous run: re-init with the
             * password in the environment so the operator verifier matches,
             * exactly as tools/qihse_federation_ca.c and
             * tools/qihse_redis_server.c do it. */
            setenv("QIHSE_OPERATOR_PASSWORD", operator_password, 1);
            if (!qihse_auth_init()) {
                operator_credential_clear_environment();
                fprintf(stderr, "qihse-cluster-daemon: auth re-init failed\n");
                return 1;
            }
        }
    }
    qihse_user_t* startup_operator = NULL;
    if (operator_password) {
        startup_operator = qihse_auth_authenticate_id(startup_user_id, operator_password);
        if (!startup_operator || !qihse_auth_user_is_active(startup_operator) ||
            qihse_user_get_role(startup_operator) != QIHSE_ROLE_OPERATOR ||
            qihse_user_get_tenant_id(startup_operator) != QIHSE_TENANT_SYSTEM) {
            operator_credential_clear_environment();
            operator_credential_release();
            fprintf(stderr, "qihse-cluster-daemon: startup Operator authentication failed\n");
            return 1;
        }
    }
    operator_credential_clear_environment();
    if (!daemon_auth_report(startup_operator, durable_auth, startup_user_id)) {
        operator_credential_release();
        return 1;
    }
    if (startup_maintenance_held && !startup_operator) {
        fprintf(stderr, "qihse-cluster-daemon: startup maintenance hold requires authenticated system Operator credentials\n");
        operator_credential_release();
        return 2;
    }

    qihse_user_t* replication_service_principal = replication_configured
        ? replication_service_principal_create(startup_operator, replication_principal_id,
            replication_principal_clearance, replication_principal_sci) : NULL;
    if (replication_configured && !replication_service_principal) {
        fprintf(stderr, "qihse-cluster-daemon: could not provision replication service principal %u\n",
                (unsigned)replication_principal_id);
        return 1;
    }

    if (machine_principal_id != 0u) {
        if (machine_principal_tenant == 0u) {
            fprintf(stderr, "qihse-cluster-daemon: --machine-principal-id requires a nonzero --machine-principal-tenant\n");
            return 1;
        }
        if (!machine_service_principal_create(startup_operator, machine_principal_tenant,
                                             machine_principal_id)) {
            fprintf(stderr, "qihse-cluster-daemon: could not provision machine principal %u (tenant %u)\n",
                    (unsigned)machine_principal_id, (unsigned)machine_principal_tenant);
            return 1;
        }
    }

    const bool auth_required = operator_password != NULL;
    if (auth_required &&
        (!qihse_cluster_derive_bus_veil_key(operator_password,
             g_transport_keys.bus_veil) ||
         !qihse_cluster_derive_overlay_hmac_key(operator_password,
             g_transport_keys.overlay_hmac))) {
        cluster_transport_keys_release();
        fprintf(stderr, "qihse-cluster-daemon: cluster transport key derivation failed\n");
        return 1;
    }
    if (atexit(cluster_transport_keys_release) != 0) {
        cluster_transport_keys_release();
        fprintf(stderr, "qihse-cluster-daemon: could not register transport key cleanup\n");
        return 1;
    }
    operator_credential_release();
    operator_password = NULL;

    qihse_kv_store_t* store = startup_operator
        ? qihse_kv_store_create_user(startup_operator) : qihse_kv_store_create();
    if (!store) {
        fprintf(stderr, "qihse-cluster-daemon: kv store create failed (data dir unusable?)\n");
        return 1;
    }
    if (replication_service_principal)
        qihse_kv_store_set_replication_principal_id(store,
            qihse_user_get_id(replication_service_principal));
    unsigned char ct_owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    uint64_t ct_source_durable_position = 0u;
    unsigned char ct_source_baseline_digest[32] = {0};
    if (ct_configured && !startup_operator) {
        fprintf(stderr, "qihse-cluster-daemon: CT requires an authenticated startup Operator\n");
        qihse_kv_store_destroy(store);
        return 1;
    }
    if (ct_configured && ct_auto_successor_id && !strcmp(ct_role, "successor")) {
        qihse_kv_ct_source_status_t promoted;
        if (qihse_kv_ct_source_status(store, replication_service_principal, &promoted)) {
            const char* successor_qkp = NULL;
            const char* successor_pub = NULL;
            for (size_t i = 0; i < ct_identity_map_option_count; ++i)
                if (!strcmp(ct_identity_map_options[i].topology_id, ct_auto_successor_id))
                    successor_qkp = ct_identity_map_options[i].qkp_node_id;
            if (successor_qkp)
                for (size_t i = 0; i < replication_allowed_peer_count; ++i)
                    if (!strcmp(replication_allowed_peers[i].node_id, successor_qkp))
                        successor_pub = replication_allowed_peers[i].dsa_pub_path;
            bool found_endpoint = false;
            for (size_t i = 0; i < peer_count; ++i) {
                qihse_cluster_node_t candidate;
                fill_node(peers[i].host, peers[i].port, peers[i].bus_port, &candidate);
                if (strcmp(candidate.id, ct_auto_successor_id)) continue;
                snprintf(ct_peer_host_storage, sizeof(ct_peer_host_storage), "%s", candidate.host);
                ct_peer_host = ct_peer_host_storage;
                ct_peer_port = candidate.port;
                found_endpoint = true;
            }
            if (!successor_pub || !found_endpoint || strcmp(promoted.source_id, pqc_node_id) ||
                strcmp(promoted.successor_id, successor_qkp)) {
                fprintf(stderr, "qihse-cluster-daemon: durable promoted source no longer matches provisioned spare; refusing restart\n");
                qihse_kv_store_destroy(store); return 1;
            }
            memcpy(ct_recovered_generation, promoted.generation, sizeof(ct_recovered_generation));
            ct_generation_hex = ct_recovered_generation;
            replication_peer_node_id = successor_qkp;
            replication_peer_dsa_pub = successor_pub;
            ct_role = "primary";
        }
    }
    if (ct_configured && !ct_group_mode && strcmp(ct_role, "primary") == 0) {
        qihse_kv_ct_source_status_t ct_status;
        bool configured = qihse_kv_ct_source_status(store,
            replication_service_principal, &ct_status);
        if (!configured) {
            configured = qihse_kv_ct_source_enable(store, startup_operator,
                pqc_node_id, replication_peer_node_id, ct_generation_hex,
                NULL, ct_log_limit_bytes);
            if (!configured) {
                fprintf(stderr, "qihse-cluster-daemon: CT source initialization failed; refusing to start\n");
                qihse_kv_store_destroy(store);
                return 1;
            }
            configured = qihse_kv_ct_source_status(store,
                replication_service_principal, &ct_status);
            if (!configured) {
                fprintf(stderr, "qihse-cluster-daemon: CT source status unavailable after initialization\n");
                qihse_kv_store_destroy(store);
                return 1;
            }
        } else if (strcmp(ct_status.source_id, pqc_node_id) != 0 ||
                   strcmp(ct_status.successor_id, replication_peer_node_id) != 0 ||
                   strcmp(ct_status.generation, ct_generation_hex) != 0) {
            fprintf(stderr, "qihse-cluster-daemon: persisted CT source identity differs from configuration\n");
            qihse_kv_store_destroy(store);
            return 1;
        }
        if (configured) {
            ct_source_durable_position = ct_status.durable_lsn;
            memcpy(ct_source_baseline_digest, ct_status.baseline_digest,
                   sizeof(ct_source_baseline_digest));
        }
        if (!qihse_kv_ct_owner_token_get(store, startup_operator, ct_owner_token)) {
            fprintf(stderr, "qihse-cluster-daemon: CT source capability unavailable; refusing to start\n");
            qihse_kv_store_destroy(store);
            return 1;
        }
    } else if (ct_configured && !ct_group_mode && strcmp(ct_role, "successor") == 0) {
        qihse_kv_ct_receiver_status_t receiver_status;
        if (qihse_kv_ct_receiver_status(store, replication_service_principal,
                                       &receiver_status)) {
            if (ct_learn_generation && !strcmp(receiver_status.source_id, replication_peer_node_id)) {
                memcpy(ct_recovered_generation, receiver_status.generation, sizeof(ct_recovered_generation));
                ct_generation_hex = ct_recovered_generation;
            }
            if (strcmp(receiver_status.source_id, replication_peer_node_id) != 0 ||
                strcmp(receiver_status.generation, ct_generation_hex) != 0) {
                fprintf(stderr, "qihse-cluster-daemon: persisted CT receiver identity differs from configuration\n");
                qihse_kv_store_destroy(store);
                return 1;
            }
            if (!qihse_kv_ct_owner_token_get(store, startup_operator, ct_owner_token)) {
                fprintf(stderr, "qihse-cluster-daemon: CT receiver capability unavailable; refusing to start\n");
                qihse_kv_store_destroy(store);
                return 1;
            }
        }
    }
    if (replica_read_only && !qihse_kv_store_enable_replica_read_only(store)) {
        fprintf(stderr, "qihse-cluster-daemon: could not enable replica read-only fence\n");
        return 1;
    }
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    if (!topology) return 1;

    /* Insert every peer, then self (self also appears in --node for clarity). */
    uint16_t indexes[MAX_PEERS];
    memset(indexes, 0xFF, sizeof(indexes));
    for (size_t k = 0; k < peer_count; k++) {
        qihse_cluster_node_t node;
        fill_node(peers[k].host, peers[k].port, peers[k].bus_port, &node);
        uint16_t idx;
        if (!qihse_cluster_topology_upsert_node(topology, &node, &idx)) {
            fprintf(stderr, "qihse-cluster-daemon: upsert node %zu failed\n", k);
            return 1;
        }
        indexes[peers[k].index] = idx;
    }
    {
        qihse_cluster_node_t node;
        fill_node(bind, port, bus_port, &node);
        uint16_t idx;
        if (!qihse_cluster_topology_upsert_node(topology, &node, &idx)) return 1;
        if (indexes[self_index] == 0xFFFFu) indexes[self_index] = idx;
    }
    if (!qihse_cluster_topology_set_local_node(topology, indexes[self_index])) return 1;

    ct_identity_map_set_t ct_identity_maps;
    memset(&ct_identity_maps, 0, sizeof(ct_identity_maps));
    for (size_t i = 0; i < ct_identity_map_option_count; ++i) {
        uint16_t mapped_index = QIHSE_CLUSTER_NODE_NONE;
        bool known_pin = false;
        if (!qihse_cluster_topology_find_node(topology,
                ct_identity_map_options[i].topology_id, &mapped_index)) {
            fprintf(stderr, "qihse-cluster-daemon: topology/QKP map names unknown topology node %s\n",
                    ct_identity_map_options[i].topology_id);
            return 2;
        }
        if (strcmp(ct_identity_map_options[i].qkp_node_id,
                   pqc_node_id ? pqc_node_id : bind) == 0) known_pin = true;
        if (replication_peer_node_id &&
            strcmp(ct_identity_map_options[i].qkp_node_id,
                   replication_peer_node_id) == 0) known_pin = true;
        for (size_t k = 0; k < replication_allowed_peer_count; ++k)
            if (strcmp(ct_identity_map_options[i].qkp_node_id,
                       replication_allowed_peers[k].node_id) == 0) known_pin = true;
        if (!known_pin) {
            fprintf(stderr, "qihse-cluster-daemon: topology/QKP map targets an identity without a configured QKP pin: %s\n",
                    ct_identity_map_options[i].qkp_node_id);
            return 2;
        }
        ct_identity_maps.entries[ct_identity_maps.count++] =
            ct_identity_map_options[i];
    }
    qihse_cluster_node_t self_topology_node;
    if (!qihse_cluster_topology_get_node(topology, indexes[self_index],
            &self_topology_node)) return 1;
    bool self_map_found = false;
    for (size_t i = 0; i < ct_identity_maps.count; ++i) {
        if (strcmp(ct_identity_maps.entries[i].topology_id,
                   self_topology_node.id) == 0) {
            if (strcmp(ct_identity_maps.entries[i].qkp_node_id,
                       pqc_node_id ? pqc_node_id : bind) != 0) {
                fprintf(stderr, "qihse-cluster-daemon: local topology/QKP mapping disagrees with --pqc-node-id\n");
                return 2;
            }
            self_map_found = true;
        }
    }
    if (!self_map_found) {
        if (ct_identity_maps.count >= sizeof(ct_identity_maps.entries) /
                                      sizeof(ct_identity_maps.entries[0])) return 2;
        ct_identity_map_t* self_map = &ct_identity_maps.entries[ct_identity_maps.count++];
        snprintf(self_map->topology_id, sizeof(self_map->topology_id), "%s",
                 self_topology_node.id);
        snprintf(self_map->qkp_node_id, sizeof(self_map->qkp_node_id), "%s",
                 pqc_node_id ? pqc_node_id : bind);
    }
    if (ct_group_mode) {
        for (size_t g = 0; g < ct_group_count; ++g) {
            const char* topology_ids[2] = {ct_groups[g].owner_topology_id,
                                           ct_groups[g].successor_topology_id};
            for (size_t endpoint = 0; endpoint < 2u; ++endpoint) {
                char qkp_id[QIHSE_QKP_NODE_ID_LEN + 1u] = {0};
                if (!ct_identity_map_lookup(&ct_identity_maps, topology_ids[endpoint], qkp_id)) {
                    fprintf(stderr, "qihse-cluster-daemon: --ct-group endpoint lacks an explicit topology/QKP map: %s\n",
                            topology_ids[endpoint]);
                    return 2;
                }
                bool pinned = strcmp(qkp_id, pqc_node_id) == 0;
                for (size_t p = 0; p < replication_allowed_peer_count; ++p)
                    if (strcmp(qkp_id, replication_allowed_peers[p].node_id) == 0)
                        pinned = true;
                if (!pinned) {
                    fprintf(stderr, "qihse-cluster-daemon: --ct-group endpoint has no configured QKP replication pin: %s\n",
                            qkp_id);
                    return 2;
                }
            }
        }
    }
    /* Replica relationships are provisioned consistently on every process.
     * Foreign replicas must not masquerade as empty primary placement targets. */
    for (size_t i = 0; i < MAX_PEERS; ++i) {
        if (replica_primary[i] == QIHSE_CLUSTER_NODE_NONE) continue;
        if (indexes[i] == QIHSE_CLUSTER_NODE_NONE ||
            indexes[replica_primary[i]] == QIHSE_CLUSTER_NODE_NONE) {
            fprintf(stderr, "qihse-cluster-daemon: --replica-of references an unconfigured node\n");
            return 2;
        }
        qihse_cluster_node_t replica;
        if (!qihse_cluster_topology_get_node(topology, indexes[i], &replica)) return 2;
        replica.role = QIHSE_CLUSTER_NODE_REPLICA;
        replica.primary_index = indexes[replica_primary[i]];
        if (!qihse_cluster_topology_upsert_node(topology, &replica, NULL)) return 2;
    }
    uint16_t ct_peer_index = QIHSE_CLUSTER_NODE_NONE;
    if (ct_configured && !ct_group_mode) {
        size_t mapped_matches = 0u;
        for (size_t i = 0; i < ct_identity_maps.count; ++i) {
            if (strcmp(ct_identity_maps.entries[i].qkp_node_id,
                       replication_peer_node_id) != 0) continue;
            uint16_t candidate = QIHSE_CLUSTER_NODE_NONE;
            if (!qihse_cluster_topology_find_node(topology,
                    ct_identity_maps.entries[i].topology_id, &candidate)) continue;
            ct_peer_index = candidate;
            mapped_matches++;
        }
        if (mapped_matches != 1u || ct_peer_index == QIHSE_CLUSTER_NODE_NONE ||
            ct_peer_index == indexes[self_index]) {
            fprintf(stderr, "qihse-cluster-daemon: CT requires an explicit --topology-qkp-map for its pinned peer\n");
            return 2;
        }

        /* Derive the replication topology role only from the exact configured
         * CT role and trusted topology↔QKP identity map. Never infer replica
         * relationships from an IP address, bus announcement, or peer order. */
        qihse_cluster_node_t ct_peer_node, local_node;
        if (!qihse_cluster_topology_get_node(topology, ct_peer_index, &ct_peer_node) ||
            !qihse_cluster_topology_get_node(topology, indexes[self_index], &local_node))
            return 2;
        for (size_t i = 0; i < MAX_PEERS; ++i) {
            if (replica_primary[i] == QIHSE_CLUSTER_NODE_NONE) continue;
            uint16_t replica_index = strcmp(ct_role, "primary") == 0
                ? ct_peer_index : indexes[self_index];
            uint16_t primary_index = strcmp(ct_role, "primary") == 0
                ? indexes[self_index] : ct_peer_index;
            if ((indexes[i] == replica_index && indexes[replica_primary[i]] != primary_index) ||
                indexes[i] == primary_index) {
                /* A durable promoted source legitimately replaces its old
                 * local replica role; the persisted journal is replayed below. */
                bool recovered = ct_auto_successor_id && ct_recovered_generation[0] &&
                    !strcmp(ct_role, "primary") && indexes[i] == indexes[self_index];
                if (!recovered) {
                    fprintf(stderr, "qihse-cluster-daemon: --replica-of conflicts with pinned CT role\n");
                    return 2;
                }
            }
        }
        if (strcmp(ct_role, "primary") == 0) {
            ct_peer_node.role = QIHSE_CLUSTER_NODE_REPLICA;
            ct_peer_node.primary_index = indexes[self_index];
            local_node.role = QIHSE_CLUSTER_NODE_PRIMARY;
            local_node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        } else {
            local_node.role = QIHSE_CLUSTER_NODE_REPLICA;
            local_node.primary_index = ct_peer_index;
            ct_peer_node.role = QIHSE_CLUSTER_NODE_PRIMARY;
            ct_peer_node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        }
        if (!qihse_cluster_topology_upsert_node(topology, &ct_peer_node, NULL) ||
            !qihse_cluster_topology_upsert_node(topology, &local_node, NULL)) {
            fprintf(stderr, "qihse-cluster-daemon: could not install CT primary/successor topology roles\n");
            return 2;
        }
    }

    /* Group mode bootstraps routing only from the committed common map.
     * CLI-local assignment counters are not ownership evidence and can exceed
     * the first quorum grant, causing every valid transfer to look stale. */
    if (!ct_group_mode) {
        /* Slot assignment: explicit ranges; anything unassigned falls to self so a
         * single-node deployment owns all slots. */
        bool assigned_any_to_self = self_has_slots;
        for (size_t k = 0; k < peer_count; k++) {
            if (peers[k].index == self_index || !peers[k].has_slots) continue;
            if (!qihse_cluster_topology_assign_range(topology, peers[k].slot_first,
                                                     peers[k].slot_last, indexes[peers[k].index])) {
                fprintf(stderr, "qihse-cluster-daemon: slot assign for peer %zu failed\n", k);
                return 1;
            }
        }
        if (self_has_slots) {
            if (!qihse_cluster_topology_assign_range(topology, self_slot_first, self_slot_last,
                                                     indexes[self_index]))
                return 1;
        }
        /* A lone node owns every slot; a JOINER (has seeds) starts slotless and
         * learns ownership from the seed's slot announcements over the bus. */
        if (!assigned_any_to_self && peer_count == 0 && seed_count == 0) {
            if (!qihse_cluster_topology_assign_range(topology, 0u, QIHSE_CLUSTER_SLOT_COUNT - 1u,
                                                     indexes[self_index]))
                return 1;
        }

    }

    for (size_t i = 0; i < MAX_PEERS; ++i) {
        if (replica_primary[i] == QIHSE_CLUSTER_NODE_NONE) continue;
        qihse_cluster_node_t replica;
        if (!qihse_cluster_topology_get_node(topology, indexes[i], &replica)) return 2;
        if (replica.role != QIHSE_CLUSTER_NODE_REPLICA) continue;
        for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; ++slot) {
            uint16_t owner;
            if (qihse_cluster_topology_get_slot(topology, (uint16_t)slot, &owner, NULL, NULL) &&
                owner == indexes[i]) {
                fprintf(stderr, "qihse-cluster-daemon: configured replica owns slots\n");
                return 2;
            }
        }
    }

    /* Replay the durable slot-ownership journal so a migration's ownership
     * survives THIS node's restart (adopt-if-newer). Reclaim/GC is not run
     * before listener bind: stale source copies are reclaimed in bounded
     * batches via the key-only iterator after the listener is serving (and on
     * demand via CLUSTER RECLAIM), so startup never blocks on a store scan. */
    int replayed_journal_entries = 0;
    if (data_dir && *data_dir) {
        replayed_journal_entries = qihse_cluster_ownership_journal_replay(
            data_dir, ownership_journal_replay_cb, topology);
    }

    if (ct_configured && !ct_group_mode) {
        const uint16_t successor_index = strcmp(ct_role, "primary") == 0
            ? ct_peer_index : indexes[self_index];
        size_t range_count = qihse_cluster_topology_ranges(topology, NULL, 0u);
        qihse_cluster_slot_range_t* ranges = range_count
            ? calloc(range_count, sizeof(*ranges)) : NULL;
        if (range_count && !ranges) return 1;
        (void)qihse_cluster_topology_ranges(topology, ranges, range_count);
        bool successor_slotless = true;
        for (size_t i = 0; i < range_count; ++i) {
            if (ranges[i].owner_index == successor_index) {
                successor_slotless = false;
                break;
            }
        }
        free(ranges);
        if (!successor_slotless) {
            fprintf(stderr, "qihse-cluster-daemon: CT successor must be slotless before replication/promotion\n");
            return 2;
        }
    }

    /* R4c QKP1: resolve identity/trust from --pqc-* flags.
     *   --pqc-require            → identity + ≥1 trust anchor MUST exist,
     *                              otherwise refuse to start.
     *   opportunistic (default)  → missing keys ⇒ warn once, serve cleartext
     *                              (the pre-PQC warning spam disappears once
     *                              keys exist on the host). */
    qihse_qkp_config_t pqc;
    memset(&pqc, 0, sizeof(pqc));
    pqc.require = pqc_require;
    pqc.node_id = pqc_node_id ? pqc_node_id : bind;
    if ((replication_peer_node_id == NULL) != (replication_peer_dsa_pub == NULL)) {
        fprintf(stderr, "qihse-cluster-daemon: replication peer node id and DSA public key must be configured together\n");
        return 2;
    }
    pqc.replication_peer_node_id = replication_peer_node_id;
    pqc.replication_peer_dsa_pub_path = replication_peer_dsa_pub;
    pqc.admin_peer_node_id = admin_peer_node_id;
    pqc.admin_peer_dsa_pub_path = admin_peer_dsa_pub;
    pqc.migration_peer_node_ids = migration_peer_node_ids;
    pqc.migration_peer_dsa_pub_paths = migration_peer_dsa_pub_paths;
    pqc.migration_peer_count = migration_peer_count;
    static char pqc_dsa_key[512], pqc_kem_key[512], pqc_kem_pub[512];
    const char* pqc_dir = pqc_identity_dir ? pqc_identity_dir : "/etc/qihse/keys";
    snprintf(pqc_dsa_key, sizeof(pqc_dsa_key), "%s/qihse_dsa_key.pem", pqc_dir);
    snprintf(pqc_kem_key, sizeof(pqc_kem_key), "%s/qihse_kem_key.pem", pqc_dir);
    snprintf(pqc_kem_pub, sizeof(pqc_kem_pub), "%s/qihse_kem_pub.pem", pqc_dir);
    pqc.dsa_key_path = pqc_dsa_key;
    pqc.kem_key_path = pqc_kem_key;
    pqc.kem_pub_path = pqc_kem_pub;
    pqc.trusted_pubs = pqc_trusted;
    pqc.trusted_count = pqc_trusted_count;
    /* MACHINEAUTH trust plane: the same file-configured ML-DSA anchors the
     * bus trusts. Only explicitly configured anchors enable it (R4c
     * philosophy: no flags → no machine auth → password AUTH only). */
    if (pqc_trusted_count > 0) {
        if (!qihse_machine_auth_configure(pqc_trusted, pqc_trusted_count)) {
            fprintf(stderr, "qihse-cluster-daemon: warning: no --pqc-trusted-pub anchor loaded; "
                            "MACHINEAUTH disabled (password AUTH only)\n");
        }
    }
    if (pqc_require || pqc_identity_dir) {
        bool have_keys = access(pqc.dsa_key_path, R_OK) == 0 &&
                         access(pqc.kem_key_path, R_OK) == 0 &&
                         access(pqc.kem_pub_path, R_OK) == 0;
        if (!have_keys) {
            if (pqc_require) {
                fprintf(stderr, "qihse-cluster-daemon: --pqc-require but identity keys are missing under %s "
                                "(need qihse_dsa_key.pem, qihse_kem_key.pem, qihse_kem_pub.pem); refusing to start\n", pqc_dir);
                return 1;
            }
            /* f6: keys missing under an explicitly requested identity dir —
             * stay ARMED (degraded) so the engine still probes connections:
             * a QKP1 client gets a clean "-ERR PQC unavailable" line instead
             * of the probe disappearing into the cleartext RESP parser
             * (silence until timeout). Cleartext sessions are unaffected. */
            pqc_degraded = true;
            fprintf(stderr, "qihse-cluster-daemon: PQC identity keys not found under %s; "
                            "serving cleartext, QKP1 probes answered with -ERR PQC unavailable\n", pqc_dir);
        }
    }
    /* Anti-entropy carries credentials and replicated values. Refuse to
     * enable it unless every connection can use QKP1 with configured node
     * trust anchors; the transport client has no cleartext fallback. */
    if ((replication_configured || (replication_source_host && repl_glob_count > 0u && repl_interval > 0u)) &&
        (!pqc.dsa_key_path || access(pqc.dsa_key_path, R_OK) != 0 ||
         !pqc.kem_key_path || access(pqc.kem_key_path, R_OK) != 0 ||
         !pqc.kem_pub_path || access(pqc.kem_pub_path, R_OK) != 0 ||
         pqc_trusted_count == 0u)) {
        fprintf(stderr, "qihse-cluster-daemon: --replication-source-host requires readable QKP1 DSA/KEM identity keys and at least one --pqc-trusted-pub; refusing unsafe replication\n");
        return 2;
    }

    qihse_blob_store_t* consensus_blobs = NULL;
    qihse_consensus_mesh_t* consensus_mesh = NULL;
    qihse_consensus_blob_context_t consensus_blob_context;
    memset(&consensus_blob_context, 0, sizeof(consensus_blob_context));
    if (consensus_configured) {
        char consensus_dir[1024], blob_dir[1100], record_path[1100];
        char peer_pub_paths[CONSENSUS_PEERS_MAX][512];
        const char* peer_trust[CONSENSUS_PEERS_MAX];
        qihse_consensus_mesh_config_t mesh_cfg;
        memset(&mesh_cfg, 0, sizeof(mesh_cfg));
        if (snprintf(consensus_dir, sizeof(consensus_dir), "%s/consensus/%s", data_dir,
                     consensus_options.group_id) >= (int)sizeof(consensus_dir) ||
            snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", consensus_dir) >= (int)sizeof(blob_dir) ||
            snprintf(record_path, sizeof(record_path), "%s/consensus.log", consensus_dir) >= (int)sizeof(record_path) ||
            !mkdirs(consensus_dir)) {
            fprintf(stderr, "qihse-cluster-daemon: cannot prepare consensus data directory\n");
            return 1;
        }
        if (snprintf(mesh_cfg.consensus.group_id, sizeof(mesh_cfg.consensus.group_id), "%s",
                     consensus_options.group_id) >= (int)sizeof(mesh_cfg.consensus.group_id)) {
            fprintf(stderr, "qihse-cluster-daemon: invalid consensus group configuration\n");
            return 2;
        }
        mesh_cfg.consensus.self = consensus_options.self;
        mesh_cfg.consensus.allow_unadmitted_self =
            consensus_options.bootstrap_unadmitted;
        mesh_cfg.consensus.election_priority_delay_ms =
            consensus_options.election_priority_delay_ms;
        mesh_cfg.consensus.priority_tier = consensus_options.priority_tier;
        mesh_cfg.consensus.wan_rtt_ms = consensus_options.wan_rtt_ms;
        mesh_cfg.consensus.enable_prevote = consensus_options.enable_prevote;
        mesh_cfg.consensus.election_timeout_base_ms =
            consensus_options.election_timeout_base_ms;
        mesh_cfg.consensus.election_timeout_spread_ms =
            consensus_options.election_timeout_spread_ms;
        mesh_cfg.consensus.heartbeat_interval_ms =
            consensus_options.heartbeat_interval_ms;
        mesh_cfg.consensus.member_count = consensus_options.member_count;
        memcpy(mesh_cfg.consensus.members, consensus_options.members,
               consensus_options.member_count * sizeof(consensus_options.members[0]));
        memcpy(mesh_cfg.consensus.history_id, consensus_options.history_id,
               sizeof(mesh_cfg.consensus.history_id));
        mesh_cfg.consensus.writer_epoch_floor =
            consensus_options.writer_epoch_floor;
        if (snprintf(mesh_cfg.consensus.record_path, sizeof(mesh_cfg.consensus.record_path),
                     "%s", record_path) >= (int)sizeof(mesh_cfg.consensus.record_path)) {
            fprintf(stderr, "qihse-cluster-daemon: consensus record path is too long\n");
            return 2;
        }
        qihse_user_t* system_principal = startup_operator;
        consensus_blobs = qihse_blob_store_create(blob_dir);
        if (!system_principal || !consensus_blobs ||
            !qihse_consensus_blob_context_init(&consensus_blob_context, consensus_blobs,
                                               system_principal, consensus_options.group_id) ||
            !qihse_consensus_blob_bind_config(&consensus_blob_context, &mesh_cfg.consensus)) {
            fprintf(stderr, "qihse-cluster-daemon: consensus requires an active system Operator and durable blob store\n");
            if (consensus_blobs) qihse_blob_store_destroy(consensus_blobs);
            return 1;
        }
        mesh_cfg.authority_proposals_enabled = consensus_authority_proposals;
        mesh_cfg.qkp = pqc;
        mesh_cfg.qkp.require = true;
        mesh_cfg.qkp.node_id = pqc_node_id;
        mesh_cfg.qkp.trusted_count = consensus_options.peer_count;
        mesh_cfg.qkp.trusted_pubs = peer_trust;
        mesh_cfg.system_principal = system_principal;
        mesh_cfg.blob_context = &consensus_blob_context;
        mesh_cfg.listen_wireguard_ipv4 = consensus_options.listen_ipv4;
        mesh_cfg.listen_port = consensus_options.port;
        mesh_cfg.peer_count = consensus_options.peer_count;
        for (size_t i = 0; i < consensus_options.peer_count; i++) {
            daemon_consensus_peer_t* peer = &consensus_options.peers[i];
            if (snprintf(peer_pub_paths[i], sizeof(peer_pub_paths[i]), "%s/%s", data_dir,
                         peer->dsa_public_key_path) >= (int)sizeof(peer_pub_paths[i]) ||
                access(peer_pub_paths[i], R_OK) != 0) {
                fprintf(stderr, "qihse-cluster-daemon: consensus peer DSA key is not readable under --dir\n");
                qihse_blob_store_destroy(consensus_blobs);
                return 1;
            }
            peer_trust[i] = peer_pub_paths[i];
            peer->mesh_peer.dsa_public_key_path = peer_pub_paths[i];
            mesh_cfg.peers[i] = peer->mesh_peer;
        }
        consensus_mesh = qihse_consensus_mesh_create(&mesh_cfg);
        if (!consensus_mesh) {
            fprintf(stderr, "qihse-cluster-daemon: consensus mesh configuration or durable state open failed\n");
            qihse_blob_store_destroy(consensus_blobs);
            return 1;
        }
        fprintf(stderr, "qihse-cluster-daemon: consensus mesh configured for group %s (%zu voters)\n",
                consensus_options.group_id, consensus_options.member_count);
    }

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.topology = topology;
    config.local_node_index = indexes[self_index];
    config.bind_address = bind;
    config.advertise_address = bind;
    config.port = port;
    config.bus_port = bus_port;
    config.max_clients = max_clients;
    config.auth_required = auth_required;
    config.enable_bus = true;
    config.enable_failover = true;
    config.enable_scatter = enable_scatter;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    /* Without a cadence the sweeper thread never starts, so expired records
     * are never reclaimed and SSTables are never compacted. */
    config.kv_sweep_interval_seconds = kv_sweep_interval;
    config.consensus_mesh = consensus_mesh;
    config.consensus_blob_context = consensus_mesh ? &consensus_blob_context : NULL;
    config.consensus_allow_client_proposals =
        consensus_mesh && consensus_allow_client_proposals;
    if (consensus_mesh && consensus_prefix_signer_configured) {
        qihse_consensus_mesh_identity_t identity;
        if (!qihse_consensus_mesh_history_identity(consensus_mesh, &identity)) {
            fprintf(stderr, "qihse-cluster-daemon: prefix challenge history is unavailable\n");
            qihse_consensus_mesh_destroy(consensus_mesh);
            qihse_blob_store_destroy(consensus_blobs);
            return 1;
        }
        qihse_consensus_prefix_expected_t* expected =
            &config.consensus_prefix_expected;
        memcpy(expected->group_id, identity.group_id,
               sizeof(expected->group_id));
        memcpy(expected->history_id, identity.history_id,
               sizeof(expected->history_id));
        expected->writer_epoch_floor = identity.writer_epoch_floor;
        expected->member_uuid = consensus_options.self;
        snprintf(expected->qkp_node_id, sizeof(expected->qkp_node_id),
                 "%s", pqc_node_id);
        expected->signer_node = consensus_prefix_signer;
        config.consensus_prefix_challenge_enabled = true;
    }
    config.cluster_migrate_password = NULL;
    config.redundancy_peer = NULL;
    config.replication_service_principal = replication_configured
        ? replication_service_principal : NULL;
    config.ct_role = ct_role;
    config.ct_auto_successor_id = ct_auto_successor_id;
    config.ct_peer_host = ct_peer_host;
    config.ct_peer_port = ct_peer_port;
    config.ct_generation_hex = ct_generation_hex;
    config.ct_log_limit_bytes = ct_log_limit_bytes;
    config.ct_ack_timeout_ms = ct_ack_timeout_ms;
    config.ct_owner_token = ct_configured && ct_role && strcmp(ct_role, "primary") == 0
        ? ct_owner_token : NULL;
    config.ct_control_principal = ct_configured ? startup_operator : NULL;
    config.ct_topology_qkp_id = ct_identity_map_lookup;
    config.ct_topology_qkp_id_context = &ct_identity_maps;
    config.ct_groups = ct_group_count ? ct_groups : NULL;
    config.ct_group_count = ct_group_count;
    /* A LAN address and a cluster peer do not establish a replicated copy.
     * Mark only namespaces explicitly selected by the operator; otherwise
     * the routing exemption would expose local, unproven data after a lead
     * failure. */
    if (repl_interval > 0u && repl_glob_count > 0u && !replication_source_host) {
        fprintf(stderr, "qihse-cluster-daemon: outbound anti-entropy disabled; configure an exact pinned --replication-source-host and peer identity\n");
    }
    /* R4 replicated namespaces: must be set BEFORE server create — the
     * engine ingests the globs into its registry during creation. */
    config.replicate_globs = repl_glob_ptrs;
    config.replicate_glob_count = repl_glob_count;
    /* A domain-separated key derived from the cluster credential keys the
     * veiled bus framing. The operator password itself never enters the bus:
     * every bus
     * datagram is wrapped as [nonce][pad][XOR(HMAC-SHA384 keystream)] so the
     * UDP gossip is not scannable as a known protocol. NULL = plain frames. */
    config.veil_key = auth_required ? g_transport_keys.bus_veil : NULL;
    /* Signed ops: without --node-key the daemon cannot sign its own ops
     * frames; with --require-signed-ops it also refuses unsigned ones from
     * peers (hardened mode — every node must then run --node-key). */
    /* Signed ops (hybrid bus upgrade): load the node identity BEFORE the
     * RESP server is created — the bus inherits signing/verification from
     * the server config below. */
    void* node_sign_pkey = NULL;
    if (ct_group_mode && !node_key_path) node_key_path = pqc.dsa_key_path;
    if (node_key_path) {
        node_sign_pkey = qihse_federation_node_key_load(node_key_path);
        if (!node_sign_pkey) {
            fprintf(stderr,
                    "[qihse-cluster-daemon] --node-key: cannot load '%s'\n",
                    node_key_path);
            return 2;
        }
        fprintf(stderr,
                "[qihse-cluster-daemon] signing ops frames with %s\n",
                node_key_path);
    } else if (require_signed_ops) {
        fprintf(stderr,
                "[qihse-cluster-daemon] --require-signed-ops without --node-key: "
                "this node cannot SIGN its own ops frames and will refuse to "
                "start in hardened mode\n");
        return 2;
    }
    config.federation_sign_key = node_sign_pkey;
    config.require_signed_ops = require_signed_ops;
    /* R4c: PQC must be OFF unless explicitly requested via --pqc-* flags or
     * required by anti-entropy. pqc.dsa_key_path points at a static buffer
     * and is always non-NULL, so it cannot be the opt-in condition. */
    if ((pqc_identity_dir != NULL || pqc_require || replication_configured ||
         (repl_glob_count > 0u && repl_interval > 0u)) && pqc.dsa_key_path) {
        config.pqc = pqc; /* opportunistic default: PQC on QKP1 probe, cleartext allowed */
    }
    /* BM25 full-text search surface (FTS.*): unlike VECHYBRID, which expects
     * the caller to bring an index, every cluster daemon owns one over its
     * LOCAL KV. Nodes hold different data, so the projection is per node and
     * never shared between them. Persistence lives under --dir, namespaced by
     * node identity, and the startup autoload runs as the system operator —
     * an authorized principal acting on the node's behalf, never a
     * context-free read (AGENTS.md invariant #1). */
    qihse_fts_index_t* fts = qihse_fts_create();
    if (!fts)
        fprintf(stderr, "qihse-cluster-daemon: FTS index create failed (FTS.* unavailable)\n");
    config.fts = fts;
    if (fts) {
        /* Anchor the projection on the store's OWN resolved data directory,
         * not on --dir: a unit may supply QIHSE_DATA_DIR through its env
         * file, and /opt/qihse-data is the default. Namespacing by
         * --index keeps two daemons that share a data directory apart. */
        const char* store_dir = qihse_kv_store_data_directory(store);
        char fts_dir[600];
        int n = 0;
        if (store_dir && *store_dir) {
            size_t dir_len = strlen(store_dir);
            const char* sep = store_dir[dir_len - 1u] == '/' ? "" : "/";
            n = snprintf(fts_dir, sizeof(fts_dir), "%s%sfts/node%u", store_dir, sep,
                         self_index);
        }
        if (n <= 0 || (size_t)n >= sizeof(fts_dir) || !mkdirs(fts_dir)) {
            fprintf(stderr, "qihse-cluster-daemon: cannot prepare the FTS persistence "
                            "directory; FTS.SAVE/FTS.LOAD stay disabled\n");
        } else {
            config.fts_persist_directory = fts_dir;
            config.fts_autoload_principal = startup_operator;
            if (!config.fts_autoload_principal)
                fprintf(stderr, "qihse-cluster-daemon: no system principal; FTS autoload "
                                "disabled\n");
        }
    }

    qihse_cluster_maintenance_t* maintenance_gate = startup_maintenance_held
        ? qihse_cluster_maintenance_create_startup_pending()
        : qihse_cluster_maintenance_create();
    if (!maintenance_gate ||
        !qihse_cluster_maintenance_register(maintenance_gate, QIHSE_MAINT_WRITER_RECLAIM, true)) {
        fprintf(stderr, "qihse-cluster-daemon: all-writer maintenance gate registration failed\n");
        if (maintenance_gate) qihse_cluster_maintenance_destroy(maintenance_gate);
        if (consensus_mesh) qihse_consensus_mesh_destroy(consensus_mesh);
        if (consensus_blobs) qihse_blob_store_destroy(consensus_blobs);
        return 1;
    }
    /* Preserve optional brain service operation, but do not claim coverage
     * until its asynchronous writes use the maintenance admission gate. */
    (void)qihse_cluster_maintenance_register(maintenance_gate,
        QIHSE_MAINT_WRITER_REPLICA, true);
    (void)qihse_cluster_maintenance_register(maintenance_gate,
        QIHSE_MAINT_WRITER_BRAIN, true);
    config.maintenance_gate = maintenance_gate;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    OPENSSL_cleanse(ct_owner_token, sizeof(ct_owner_token));
    OPENSSL_cleanse(g_transport_keys.bus_veil,
                    sizeof(g_transport_keys.bus_veil));
    config.veil_key = NULL;
    if (!server) {
        qihse_cluster_maintenance_destroy(maintenance_gate);
        fprintf(stderr, "qihse-cluster-daemon: server create failed (bind %s port %u): %s\n",
                bind, port, strerror(errno));
        if (consensus_mesh) qihse_consensus_mesh_destroy(consensus_mesh);
        if (consensus_blobs) qihse_blob_store_destroy(consensus_blobs);
        return 1;
    }
    if (ct_group_mode && !ct_group_bus_bind_identity(store, startup_operator,
            qihse_resp_server_bus(server), qihse_resp_server_topology(server),
            indexes[self_index], &ct_identity_maps, replication_allowed_peers,
            replication_allowed_peer_count, node_sign_pkey)) {
        fprintf(stderr, "qihse-cluster-daemon: configured CT certificate identity could not be bound\n");
        qihse_resp_server_destroy(server);
        return 1;
    }
    qihse_cluster_ownership_context_t ct_ownership;
    memset(&ct_ownership, 0, sizeof(ct_ownership));
    qihse_cluster_range_authority_t ct_range_authority;
    memset(&ct_range_authority, 0, sizeof(ct_range_authority));
    ct_group_authority_context_t ct_group_authority_context;
    memset(&ct_group_authority_context, 0, sizeof(ct_group_authority_context));
    daemon_brain_group_transfer_context_t brain_group_transfer_context = {
        .ownership = &ct_ownership,
        .groups = &ct_group_authority_context
    };
    bool ct_ownership_ready = false;
    bool ct_group_authority_ready = false;
    if (startup_operator && qihse_auth_user_is_active(startup_operator) &&
        qihse_user_get_role(startup_operator) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(startup_operator) == QIHSE_TENANT_SYSTEM) {
        ct_ownership.topology = qihse_resp_server_topology(server);
        ct_ownership.bus = qihse_resp_server_bus(server);
        ct_ownership.store = store;
        ct_ownership.principal = startup_operator;
        ct_ownership.data_principal = replication_service_principal;
        ct_ownership.resp_server = server;
        if (ct_auto_successor_id) {
            ct_ownership.promotion_authorized = qihse_resp_server_ct_authorize_promotion;
            ct_ownership.promotion_context = server;
        }
        ct_ownership.peer_id = ct_identity_map_lookup;
        ct_ownership.peer_id_context = &ct_identity_maps;
        if (ct_ownership.topology && ct_ownership.bus &&
            qihse_resp_server_ct_ownership_set(server, &ct_ownership)) {
            ct_ownership_ready = true;
            qihse_resp_server_ct_control_only_set(server, true);
            const char* store_dir = qihse_kv_store_data_directory(store);
            char staging_dir[PATH_MAX];
            char target_error[256] = {0};
            int stage_len = store_dir ? snprintf(staging_dir, sizeof(staging_dir),
                "%s/ct2-staging", store_dir) : -1;
            qihse_ct_target_t* target = NULL;
            if (stage_len > 0 && (size_t)stage_len < sizeof(staging_dir) &&
                mkdirs(staging_dir) && pqc_node_id && *pqc_node_id) {
                target = qihse_ct_target_create(&ct_ownership, staging_dir,
                    pqc_node_id, target_error, sizeof(target_error));
            }
            if (!target || !qihse_resp_server_ct_target_set(server, target)) {
                if (target) qihse_ct_target_destroy(target);
                fprintf(stderr, "qihse-cluster-daemon: CT2 target staging disabled: %s\n",
                    target_error[0] ? target_error : "cannot initialize private stage directory");
            }
        } else {
            fprintf(stderr, "qihse-cluster-daemon: ownership recovery context unavailable; CT2 stays disabled\n");
        }
    }
    if (startup_maintenance_held) {
        uint64_t startup_generation = 0;
        uint8_t startup_token[32];
        bool sealed = qihse_cluster_maintenance_seal_startup(
            maintenance_gate, &startup_generation, startup_token);
        OPENSSL_cleanse(startup_token, sizeof(startup_token));
        if (!sealed) {
            fprintf(stderr, "qihse-cluster-daemon: startup maintenance writer coverage incomplete; refusing to start\n");
            qihse_resp_server_destroy(server);
            qihse_cluster_maintenance_destroy(maintenance_gate);
            if (consensus_mesh) qihse_consensus_mesh_destroy(consensus_mesh);
            if (consensus_blobs) qihse_blob_store_destroy(consensus_blobs);
            return 1;
        }
    }
    if (failover_start_paused &&
        !qihse_resp_server_start_failover_paused(server, startup_operator)) {
        fprintf(stderr, "qihse-cluster-daemon: startup failover hold requires authenticated system Operator and an unstarted coordinator\n");
        qihse_resp_server_destroy(server);
        qihse_cluster_maintenance_destroy(maintenance_gate);
        if (consensus_mesh) qihse_consensus_mesh_destroy(consensus_mesh);
        if (consensus_blobs) qihse_blob_store_destroy(consensus_blobs);
        return 1;
    }
    for (size_t i = 0; i < replication_allowed_peer_count; i++) {
        if (!qihse_resp_server_add_replication_peer(server,
                replication_allowed_peers[i].node_id,
                replication_allowed_peers[i].dsa_pub_path, startup_operator)) {
            fprintf(stderr, "qihse-cluster-daemon: replication peer %s authorization failed\n",
                    replication_allowed_peers[i].node_id);
            qihse_resp_server_destroy(server);
            qihse_cluster_maintenance_destroy(maintenance_gate);
            if (consensus_mesh) qihse_consensus_mesh_destroy(consensus_mesh);
            if (consensus_blobs) qihse_blob_store_destroy(consensus_blobs);
            return 1;
        }
    }
    if (consensus_mesh && !qihse_consensus_mesh_start(consensus_mesh)) {
        fprintf(stderr, "qihse-cluster-daemon: consensus mesh listener/start failed\n");
        qihse_resp_server_destroy(server);
        qihse_consensus_mesh_destroy(consensus_mesh);
        qihse_blob_store_destroy(consensus_blobs);
        qihse_cluster_maintenance_destroy(maintenance_gate);
        return 1;
    }
    if (irc_server && irc_channel) {
        qihse_cluster_node_t self_node;
        if (qihse_cluster_topology_get_node(topology, indexes[self_index], &self_node)) {
            qihse_cluster_bus_t* bus = qihse_resp_server_bus(server);
            if (bus) {
                qihse_overlay_config_t ocfg = {0};
                ocfg.irc_server = irc_server;
                ocfg.irc_channel = irc_channel;
                ocfg.nick_prefix = irc_nick_prefix;
                ocfg.node_id = self_node.id;
                ocfg.bind_host = bind;
                ocfg.bind_port = bus_port;
                if (!auth_required) {
                    fprintf(stderr, "qihse-cluster-daemon: overlay key derivation failed\n");
                    OPENSSL_cleanse(g_transport_keys.overlay_hmac,
                                    sizeof(g_transport_keys.overlay_hmac));
                    qihse_resp_server_destroy(server);
                    qihse_cluster_maintenance_destroy(maintenance_gate);
                    return 1;
                }
                ocfg.hmac_password = g_transport_keys.overlay_hmac;
                ocfg.bus = bus;
                bool overlay_started = qihse_overlay_start(&ocfg);
                OPENSSL_cleanse(g_transport_keys.overlay_hmac,
                                sizeof(g_transport_keys.overlay_hmac));
                ocfg.hmac_password = NULL;
                if (overlay_started)
                    fprintf(stderr, "qihse-cluster-daemon: overlay bootstrap active on %s\n", irc_channel);
                else
                    fprintf(stderr, "qihse-cluster-daemon: overlay bootstrap failed to start\n");
            }
        }
    }
    OPENSSL_cleanse(g_transport_keys.overlay_hmac,
                    sizeof(g_transport_keys.overlay_hmac));

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    /* Bounds teardown and names whatever refused to stop, so a wedged
     * shutdown reports itself instead of waiting for systemd's SIGKILL. */
    pthread_t shutdown_watch_thread;
    if (pthread_create(&shutdown_watch_thread, NULL, shutdown_watchdog, NULL) == 0)
        pthread_detach(shutdown_watch_thread);
    else
        fprintf(stderr, "qihse-cluster-daemon: shutdown watchdog unavailable\n");
    fprintf(stderr, "qihse-cluster-daemon: node %u serving %s:%u (bus %u), %zu peers, %zu join seeds, auth=%s%s\n",
            self_index, bind, port, bus_port, peer_count, seed_count, config.auth_required ? "on" : "off",
            config.pqc.dsa_key_path ? (config.pqc.require ? ", pqc=required"
                                      : (pqc_degraded ? ", pqc=unavailable (keys missing)" : ", pqc=opportunistic"))
                                    : ", pqc=off");
    if (brain_enabled) {
        char default_dir[600];
        if (!brain_dir) {
            snprintf(default_dir, sizeof(default_dir), "%s/brain", data_dir ? data_dir : ".");
            brain_dir = default_dir;
        }
        qihse_brain_config_t brain_cfg = {
            .server = server,
            .journal_dir = brain_dir,
            .dsa_key_path = brain_dsa_key,
            .interval_seconds = brain_interval,
            .act = brain_act,
            .act_cooldown_seconds = brain_cooldown,
            .rollback_window_seconds = brain_rollback_window,
            .prune_timeout_seconds = brain_prune_timeout,
            .rebalance_min_slots = brain_rebalance_min,
            .federation_journal_dir = brain_fed_dir,
            .node_key_handle = brain_node_key,
            .control_principal = startup_operator,
            .data_principal = replication_service_principal,
            .maintenance_gate = maintenance_gate,
            .transfer = ct_ownership_ready
                ? (ct_group_mode ? daemon_brain_group_transfer : daemon_brain_transfer)
                : NULL,
            .transfer_context = ct_group_mode
                ? (void*)&brain_group_transfer_context : (void*)&ct_ownership,
            .transfer_range_select = ct_group_mode
                ? daemon_brain_group_select_range : NULL,
            .transfer_generation_get = ct_ownership_ready && !ct_group_mode
                ? daemon_brain_generation : NULL
        };
        if (!qihse_cluster_brain_start(&brain_cfg)) {
            fprintf(stderr, "qihse-cluster-daemon: brain failed to start (continuing without it)\n");
        } else {
            fprintf(stderr, "qihse-cluster-daemon: brain active (%s)\n", brain_act ? "observe+act" : "observe");
        }
    }
    pthread_t ae_thread;
    pthread_t ct1_thread;
    pthread_t* ct1_group_threads = ct_group_count
        ? calloc(ct_group_count, sizeof(*ct1_group_threads)) : NULL;
    ct1_pull_ctx_t* ct1_group_ctxs = ct_group_count
        ? calloc(ct_group_count, sizeof(*ct1_group_ctxs)) : NULL;
    bool* ct1_group_started = ct_group_count
        ? calloc(ct_group_count, sizeof(*ct1_group_started)) : NULL;
    static volatile sig_atomic_t ae_stop = 0;
    ae_ctx_t ae_ctx;
    ct1_pull_ctx_t ct1_ctx;
    bool ae_started = false;
    bool ct1_started = false;
    bool ok = false;
    pthread_t join_thread;
    bool join_started = false;
    join_ctx_t join_ctx = { server, {{0}}, seed_count };
    if (repl_interval > 0u && replication_source_host != NULL) {
        ae_ctx.server = server;
        ae_ctx.source_host = replication_source_host;
        ae_ctx.source_port = replication_source_port;
        ae_ctx.socks_port = replication_socks_port;
        ae_ctx.source_via_i2p = replication_transport && strcmp(replication_transport, "i2p") == 0;
        ae_ctx.transport_name = replication_transport;
        ae_ctx.replica_principal = replication_service_principal;
        ae_ctx.qkp = &pqc;
        ae_ctx.data_dir = data_dir;
        ae_ctx.interval_seconds = repl_interval;
        ae_ctx.stop = &ae_stop;
        ae_ctx.maintenance_gate = maintenance_gate;
        if (!ae_ctx.replica_principal || pthread_create(&ae_thread, NULL, ae_main, &ae_ctx) != 0) {
            fprintf(stderr, "qihse-cluster-daemon: replica pull thread failed to start (operator principal unavailable)\n");
            goto shutdown;
        }
        ae_started = true;
    }

    if (seed_count > 0) {
        for (size_t i = 0; i < seed_count; i++)
            snprintf(join_ctx.seeds[i], QIHSE_CLUSTER_HOST_LEN + 8u, "%s", seeds[i]);
        join_started = pthread_create(&join_thread, NULL, join_main, &join_ctx) == 0;
    }
    /* Run the listener in its managed accept thread so the daemon's signal
     * handler can drive an orderly stop. qihse_resp_server_run() owns its
     * blocking accept loop and does not observe this process's g_stop flag,
     * which otherwise makes systemd wait for SIGKILL at TimeoutStopSec. */
    if (ct_configured && !ct_group_mode && strcmp(ct_role, "primary") == 0 &&
        !ct1_primary_peer_preflight(ct_peer_host, ct_peer_port, &pqc,
                                    ct_generation_hex, ct_source_durable_position,
                                    ct_source_baseline_digest)) {
        fprintf(stderr, "qihse-cluster-daemon: CT primary refused startup; pinned successor STATUS preflight failed\n");
        goto shutdown;
    }
    bool ownership_recovery_pending = ct_ownership_ready;
    unsigned ownership_retry_ticks = 0u;
    ok = qihse_resp_server_start(server);
    if (ok) {
        if (ownership_recovery_pending) {
            bool unresolved = false;
            char recovery_error[256] = {0};
            if (ct_group_mode && !ct_group_authority_ready) {
                ct_group_authority_ready = ct_group_authority_activate(
                    &ct_range_authority, &ct_group_authority_context,
                    &ct_ownership, consensus_mesh, startup_operator, store,
                    ct_groups, ct_group_count, &ct_identity_maps,
                    pqc_node_id, ct_log_limit_bytes,
                    recovery_error, sizeof(recovery_error));
            }
            bool replay_ok = (!ct_group_mode || ct_group_authority_ready) &&
                qihse_cluster_ownership_replay_control(&ct_ownership,
                    &unresolved, recovery_error, sizeof(recovery_error));
            if (replay_ok && (ct_group_mode || !unresolved) &&
                (!ct_group_mode || ct_group_authority_ready)) {
                /* A verified group fence blocks its range in KV. Keep other
                 * groups serving while background recovery resumes it. */
                ownership_recovery_pending = unresolved;
                qihse_resp_server_ct_control_only_set(server, false);
                if (ct_auto_successor_id && !failover_start_paused)
                    (void)qihse_resp_server_ct_auto_resume(server, startup_operator);
            } else if (recovery_error[0]) {
                fprintf(stderr, "qihse-cluster-daemon: ownership recovery remains fenced: %s\n",
                        recovery_error);
            }
        }
        if (ct_configured && !ct_group_mode && strcmp(ct_role, "successor") == 0) {
            memset(&ct1_ctx, 0, sizeof(ct1_ctx));
            ct1_ctx.store = store;
            ct1_ctx.server = server;
            ct1_ctx.maintenance_gate = maintenance_gate;
            ct1_ctx.operator_user = startup_operator;
            ct1_ctx.replication_user = replication_service_principal;
            ct1_ctx.qkp = &pqc;
            ct1_ctx.source_host = ct_peer_host;
            ct1_ctx.source_port = ct_peer_port;
            ct1_ctx.generation = ct_generation_hex;
            ct1_ctx.learn_generation = ct_learn_generation;
            ct1_ctx.stop = &ae_stop;
            if (!ct1_ctx.replication_user ||
                pthread_create(&ct1_thread, NULL, ct1_pull_main, &ct1_ctx) != 0) {
                fprintf(stderr, "qihse-cluster-daemon: CT1 successor pull worker failed to start; node remains fenced\n");
                ok = false;
                goto shutdown;
            }
            ct1_started = true;
        }
        if (ct_group_mode && ct_group_authority_ready) {
            if (!ct1_group_threads || !ct1_group_ctxs || !ct1_group_started ||
                !replication_service_principal) {
                fprintf(stderr, "qihse-cluster-daemon: CT group receiver workers could not be allocated\n");
                ok = false;
                goto shutdown;
            }
            for (size_t g = 0; g < ct_group_count; ++g) {
                if (ct1_group_worker_start(store, server, &ct_ownership, topology,
                        &ct_identity_maps, replication_allowed_peers,
                        replication_allowed_peer_count, &ct_groups[g],
                        startup_operator, replication_service_principal, &pqc,
                        maintenance_gate, &ae_stop, &ct1_group_threads[g],
                        &ct1_group_ctxs[g]))
                    ct1_group_started[g] = true;
            }
        }
        bool gc_pending = replayed_journal_entries > 0;
        bool gc_defer_reported = false;
        size_t gc_ticks = 0u;
        unsigned ct_failover_ticks = 0u;
        uint64_t ct_map_commit_index = consensus_mesh
            ? qihse_consensus_mesh_commit_index(consensus_mesh) : 0u;
        struct timespec wait = {0, 100000000L};
        while (!g_stop) {
            if (nanosleep(&wait, &wait) == 0) wait = (struct timespec){0, 100000000L};
            if (ct_group_mode && ct_group_authority_ready && ct1_group_started) {
                for (size_t g = 0; g < ct_group_count; ++g) {
                    if (ct1_group_started[g]) {
                        int joined = pthread_tryjoin_np(ct1_group_threads[g], NULL);
                        if (joined == 0) ct1_group_started[g] = false;
                    }
                    if (!ct1_group_started[g] && !g_stop &&
                        ct1_group_worker_start(store, server, &ct_ownership, topology,
                            &ct_identity_maps, replication_allowed_peers,
                            replication_allowed_peer_count, &ct_groups[g],
                            startup_operator, replication_service_principal, &pqc,
                            maintenance_gate, &ae_stop, &ct1_group_threads[g],
                            &ct1_group_ctxs[g])) {
                        ct1_group_started[g] = true;
                        fprintf(stderr, "qihse-cluster-daemon: CT1 receiver worker active for lane %s\n",
                                ct_groups[g].lane_id);
                    }
                }
            }
            if (ct_group_mode && ct_group_authority_ready &&
                ++ct_failover_ticks >= 10u) {
                ct_failover_ticks = 0u;
                uint64_t committed = consensus_mesh
                    ? qihse_consensus_mesh_commit_index(consensus_mesh) : 0u;
                if (committed > ct_map_commit_index && ct_ownership.range_refresh) {
                    uint8_t all_slots[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES];
                    char refresh_error[256] = {0};
                    memset(all_slots, 0xff, sizeof(all_slots));
                    if (qihse_cluster_ownership_reconcile_lane_transfer(
                            &ct_ownership, refresh_error, sizeof(refresh_error)) &&
                        ct_ownership.range_refresh(
                            ct_ownership.range_authority_context,
                            startup_operator, all_slots, refresh_error,
                            sizeof(refresh_error)) &&
                        ct_group_reconcile_local(consensus_mesh, store,
                            startup_operator, ct_groups, ct_group_count)) {
                        ct_map_commit_index = committed;
                    } else if (refresh_error[0]) {
                        fprintf(stderr, "qihse-cluster-daemon: committed CT routing refresh deferred: %s\n",
                                refresh_error);
                    }
                    OPENSSL_cleanse(all_slots, sizeof(all_slots));
                }
                /* Pausing takeover does not pause application of a quorum
                 * decision that other nodes have already committed. Check
                 * the runtime coordinator so FAILOVER.RESUME takes effect. */
                if (!qihse_cluster_failover_is_paused(
                        qihse_resp_server_failover(server)))
                    ct_group_failover_tick(store, &ct_ownership, topology,
                        consensus_mesh,
                        &ct_identity_maps, replication_allowed_peers,
                        replication_allowed_peer_count, ct_groups,
                        ct_group_count, indexes[self_index], pqc_node_id);
            }
            if (ownership_recovery_pending && !g_stop && ++ownership_retry_ticks >= 10u) {
                ownership_retry_ticks = 0u;
                bool unresolved = false;
                char recovery_error[256] = {0};
                if (ct_group_mode && !ct_group_authority_ready) {
                    ct_group_authority_ready = ct_group_authority_activate(
                        &ct_range_authority, &ct_group_authority_context,
                        &ct_ownership, consensus_mesh, startup_operator, store,
                        ct_groups, ct_group_count, &ct_identity_maps,
                        pqc_node_id, ct_log_limit_bytes,
                        recovery_error, sizeof(recovery_error));
                }
                bool replay_ok = (!ct_group_mode || ct_group_authority_ready) &&
                    qihse_cluster_ownership_replay_control(&ct_ownership,
                        &unresolved, recovery_error, sizeof(recovery_error));
                if (replay_ok && (ct_group_mode || !unresolved) &&
                    (!ct_group_mode || ct_group_authority_ready)) {
                    ownership_recovery_pending = unresolved;
                    qihse_resp_server_ct_control_only_set(server, false);
                    if (ct_auto_successor_id && !failover_start_paused)
                        (void)qihse_resp_server_ct_auto_resume(server, startup_operator);
                    if (!unresolved)
                        fprintf(stderr, "qihse-cluster-daemon: ownership recovery complete; data listener enabled\n");
                }
            }
            if (gc_pending && !g_stop) {
                gc_ticks++;
                if (gc_ticks >= 50u) { /* 5 s settle after listener bind */
                    qihse_user_t* op = startup_operator;
                    bool has_more = false;
                    if (op && qihse_cluster_topology_is_covered(topology)) {
                        /* Reclaim mutates slots. A held gate must defer it, not
                         * fail startup: the node still serves its held-state
                         * whitelist and reclaim resumes on release. */
                        if (!qihse_cluster_maintenance_enter(
                                maintenance_gate, QIHSE_MAINT_WRITER_RECLAIM)) {
                            if (!gc_defer_reported) {
                                fprintf(stderr, "qihse-cluster-daemon: pending reclaim work deferred while the maintenance gate is held\n");
                                gc_defer_reported = true;
                            }
                            gc_ticks = 40u;
                            continue;
                        }
                        size_t deleted = qihse_cluster_reclaim_foreign_slots_bounded(
                            store, topology, indexes[self_index], op, 256u, &has_more);
                        qihse_cluster_maintenance_leave(maintenance_gate,
                            QIHSE_MAINT_WRITER_RECLAIM);
                        if (deleted > 0u) {
                            fprintf(stderr, "qihse-cluster-daemon: reclaimed %zu stale foreign-slot key(s)\n", deleted);
                        }
                        gc_pending = has_more && deleted > 0u;
                    } else {
                        gc_pending = false;
                    }
                    gc_ticks = 40u; /* 1 s between bounded batches if more remain */
                }
            }
        }
    }
shutdown:
    g_stop = 1; /* Also arm the watchdog when listener/worker startup fails. */
    __atomic_store_n(&ae_stop, 1, __ATOMIC_RELEASE);
    if (join_started) pthread_join(join_thread, NULL);
    if (ae_started) {
        /* ae_main can be inside a blocking pull from an unresponsive source;
         * never let that hold the whole process open. */
        unsigned int join_wait = shutdown_grace_seconds();
        if (join_wait > 15u) join_wait = 15u; /* report this before the generic watchdog */
        struct timespec join_deadline;
        clock_gettime(CLOCK_REALTIME, &join_deadline);
        join_deadline.tv_sec += (time_t)join_wait;
        int joined = pthread_timedjoin_np(ae_thread, NULL, &join_deadline);
        if (joined != 0) {
            fprintf(stderr, "qihse-cluster-daemon: replica pull thread did not stop within "
                            "%u s; leaving teardown to the shutdown watchdog\n", join_wait);
            for (;;) pause(); /* the watchdog owns the exit from here */
        }
    }
    if (ct1_started) {
        unsigned int join_wait = shutdown_grace_seconds();
        if (join_wait > 15u) join_wait = 15u;
        struct timespec join_deadline;
        clock_gettime(CLOCK_REALTIME, &join_deadline);
        join_deadline.tv_sec += (time_t)join_wait;
        int joined = pthread_timedjoin_np(ct1_thread, NULL, &join_deadline);
        if (joined != 0) {
            fprintf(stderr, "qihse-cluster-daemon: CT1 pull thread did not stop within %u s; leaving teardown to shutdown watchdog\n", join_wait);
            for (;;) pause();
        }
    }
    for (size_t i = 0; i < ct_group_count; ++i) {
        if (!ct1_group_started || !ct1_group_started[i]) continue;
        unsigned int join_wait = shutdown_grace_seconds();
        if (join_wait > 15u) join_wait = 15u;
        struct timespec join_deadline;
        clock_gettime(CLOCK_REALTIME, &join_deadline);
        join_deadline.tv_sec += (time_t)join_wait;
        int joined = pthread_timedjoin_np(ct1_group_threads[i], NULL,
                                          &join_deadline);
        if (joined != 0) {
            fprintf(stderr, "qihse-cluster-daemon: CT1 lane worker %zu did not stop within %u s; leaving teardown to shutdown watchdog\n",
                    i, join_wait);
            for (;;) pause();
        }
        ct1_group_started[i] = false;
    }
    qihse_cluster_brain_stop(); /* before destroy: the brain reads the topology every cycle */
    qihse_overlay_stop(); /* The bootstrap thread borrows the server's bus. */
    /* Server-owned failover workers borrow the mesh and blob context. Join
     * them before stopping or destroying those dependencies. */
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    if (consensus_mesh) {
        qihse_consensus_mesh_stop(consensus_mesh);
        qihse_consensus_mesh_destroy(consensus_mesh);
        qihse_blob_store_destroy(consensus_blobs);
    }
    qihse_cluster_maintenance_destroy(maintenance_gate);
    /* config.store is borrowed. Destroy drains server-owned writers (including
     * BGSAVE); only then may the data owner fence and release the caller's KV.
     * The void destructor cannot report flush errors, so check sync first. */
    if (!qihse_kv_sync_store(store)) {
        fprintf(stderr, "qihse-cluster-daemon: KV sync failed during shutdown; durability not confirmed\n");
        ok = false;
    }
    qihse_kv_store_destroy(store);
    free(ct_groups);
    free(ct1_group_threads);
    free(ct1_group_ctxs);
    free(ct1_group_started);
    /* The server owns the index from create onward and frees whatever it
     * holds at destroy, including any index BUILD/LOAD replaced. */
    fprintf(stderr, "qihse-cluster-daemon: stopped\n");
    g_teardown_done = 1;
    return ok ? 0 : 1;
}
