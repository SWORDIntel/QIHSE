#ifndef QIHSE_CLUSTER_BUS_H
#define QIHSE_CLUSTER_BUS_H

#include <stdbool.h>
#include "qihse_federation.h"
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QIHSE Cluster Bus — gossip transport for cluster membership, heartbeats,
 * and slot ownership updates.  Uses UDP datagrams by default (port 16379 or
 * node.bus_port) with an optional AF_XDP fast path when QIHSE_XDP_OBJ is
 * configured and the interface is available.
 *
 * Wire format (little-endian, fixed header + payload):
 *   uint32_t magic          = 0x51424E53 ('QBNS')
 *   uint32_t message_type   = QIHSE_BUS_MSG_*
 *   uint32_t sender_index   = topology node index of sender
 *   uint32_t payload_len    = byte count of payload
 *   uint8_t  payload[payload_len]
 *
 * Message types:
 *   PING        — heartbeat, payload = sender node_id (40 bytes)
 *   PONG        — heartbeat reply, payload = sender node_id
 *   MEET        — introduce a new node, payload = node_t serialised
 *   FAIL        — mark a node as failed, payload = node_id (40 bytes)
 *   SLOT_UPDATE — slot range ownership change, payload = slot_update_t
 *   NODE_UPDATE — node metadata change (role/health), payload = node_t
 *   NODE_OBS    — third-party health observation
 *   NODE_CAP    — sender capability profile (ISA tier / NPU / GPU / RAM / load)
 *   DHT_FIND    — overlay layer 3: "which peers do you know near this id?"
 *   DHT_NODES   — overlay layer 3: up to k peers, nearest first
 *
 * The DHT pair is dispatched to the overlay (qihse_overlay.h) and is an
 * UNAUTHENTICATED peer-exchange hint: it can only cause a dial (a MEET), never
 * a membership, trust or authority change.  See the gate note in
 * qihse_overlay.h.  The roadmap for this item named "msg types 9/10"; 9 and 10
 * were taken by GROUP_UPDATE/GROUP_ACK before the DHT landed, so the pair is
 * 13/14.
 */

#define QIHSE_CLUSTER_BUS_MAGIC 0x51424E53u
#define QIHSE_CLUSTER_BUS_DEFAULT_PORT 16379u
/* Sized so a full ML-DSA-87 membership statement (120-byte signed region +
 * 4627-byte signature) fits in one datagram.  Statements are interval-based
 * and idempotent, so the fragmentation this implies on a lossy path costs
 * liveness at worst and never correctness. */
#define QIHSE_CLUSTER_BUS_MAX_PAYLOAD 8192u
#define QIHSE_CLUSTER_BUS_HEADER_SIZE 16u
#define QIHSE_CLUSTER_BUS_HEARTBEAT_MS 1000u
#define QIHSE_CLUSTER_BUS_TIMEOUT_MS 5000u

typedef enum {
    QIHSE_BUS_MSG_PING = 1u,
    QIHSE_BUS_MSG_PONG = 2u,
    QIHSE_BUS_MSG_MEET = 3u,
    QIHSE_BUS_MSG_FAIL = 4u,
    QIHSE_BUS_MSG_SLOT_UPDATE = 5u,
    QIHSE_BUS_MSG_NODE_UPDATE = 6u,
    QIHSE_BUS_MSG_NODE_OBS    = 7u,  /* third-party health observation */
    QIHSE_BUS_MSG_NODE_CAP    = 8u,  /* node capability profile (ISA/NPU/GPU) */
    QIHSE_BUS_MSG_GROUP_UPDATE = 9u, /* group update push (operator -> members) */
    QIHSE_BUS_MSG_GROUP_ACK    = 10u, /* member applied/rejected a group update */
    /* Federation trust plane.  These two carry post-quantum signed membership
     * statements and cheap session-bound heartbeats.  They are VERIFIED
     * through the federation layer before any handler runs, and they are
     * DROPPED — not trusted — when no federation trust context is configured.
     *
     * Everything else on this bus (PING/PONG/MEET/SLOT_UPDATE/...) is a
     * bootstrap or liveness frame and must never carry authority.  See
     * qihse_bus_msg_carries_authority(). */
    QIHSE_BUS_MSG_FED_STATEMENT = 11u,
    QIHSE_BUS_MSG_FED_HEARTBEAT = 12u,
    /* Overlay layer 3 (W4.2): DHT peer exchange.  UNAUTHENTICATED hint frames
     * — see the gate note in qihse_overlay.h.  They are dispatched to the
     * overlay and are dropped when the DHT hint table is not enabled, which is
     * the fail-closed default. */
    QIHSE_BUS_MSG_DHT_FIND  = 13u, /* "peers near this node id?" */
    QIHSE_BUS_MSG_DHT_NODES = 14u  /* up to k peers, nearest first */
} qihse_cluster_bus_msg_type_t;

/*
 * GROUP_UPDATE wire payload (packed, little-endian multi-byte values):
 *   update_id   u64   monotonic update id (HLC-packed: sortable)
 *   group_len   u16   bytes of group name that follow
 *   payload_len u16   bytes of payload that follow
 *   group[]     char  group_len bytes (not NUL-terminated on the wire)
 *   payload[]   u8    payload_len bytes (the update body)
 *
 * GROUP_ACK wire payload:
 *   update_id   u64
 *   status      u16   0 = applied, non-zero = rejected (reason code)
 *   node_id[41] char  NUL-terminated acknowledging node id
 */
#define QIHSE_CLUSTER_BUS_GROUP_NAME_MAX 32u
#define QIHSE_CLUSTER_BUS_GROUP_UPDATE_MAX 1024u

/*
 * NODE_CAP wire payload — packed field-by-field (little-endian multi-byte
 * values via memcpy, matching the rest of the bus):
 *   node_id[41]     char, NUL-terminated sender node id
 *   isa_tier u8     0=generic, 1=AVX, 2=AVX2, 3=AVX-512, 4=AVX-512+AMX
 *   npu      u8     1 if an accelerator device (/dev/accel) is present
 *   gpu      u8     1 if a GPU device (/dev/dri, /dev/nvidiactl) is present
 *   free_ram_mb u32  MemAvailable (fallback MemFree) from /proc/meminfo
 *   load_pct   u16  1-minute load average * 100, clamped to 65535
 *
 * This frame is an UNAUTHENTICATED, in-memory hint: nothing binds the node id
 * in the payload to the sender.  It is kept for the live peer table (and for
 * clusters with no federation context), but it never writes a durable record.
 * The durable, attributable form is the v3 signed membership statement, which
 * carries the same five fields inside its signed region; acceptance persists
 * them at "federation/node/<uuid>" (see qihse_federation.h, W2.4).
 */
#define QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE \
    (QIHSE_CLUSTER_NODE_ID_LEN + 1u + 3u + 4u + 2u)

/* How often the bus re-persists the local node's own capability record when a
 * local federation UUID is configured.  The record is a durable floor, not a
 * per-heartbeat trace: the live NODE_CAP frame is the 1 Hz channel. */
#define QIHSE_CLUSTER_BUS_CAP_RECORD_MS 10000u

typedef struct {
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint8_t isa_tier;
    uint8_t npu;
    uint8_t gpu;
    uint32_t free_ram_mb;
    uint16_t load_pct;
} qihse_cluster_bus_node_cap_t;

typedef struct {
    uint16_t start;
    uint16_t end;
    uint16_t owner_index;       /* sender's local index (for sender's reference) */
    uint16_t reserved;
    char owner_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u]; /* owner's node ID (resolved by receiver) */
} qihse_cluster_bus_slot_update_t;

typedef struct qihse_cluster_bus qihse_cluster_bus_t;

typedef void (*qihse_cluster_bus_on_fail_cb)(qihse_cluster_topology_t* topology,
                                             uint16_t failed_node_index,
                                             void* user_data);

typedef struct {
    qihse_cluster_topology_t* topology;
    uint16_t local_node_index;
    uint16_t bus_port;
    const char* bind_address;
    const char* xdp_interface;   /* NULL = standard UDP; set to enable AF_XDP */
    const char* veil_key;        /* veiled framing key (cluster operator password);
                                  * NULL/empty = passthrough (plain bus frames) */
    uint32_t heartbeat_ms;
    uint32_t timeout_ms;
    qihse_cluster_bus_on_fail_cb on_fail;
    void* on_fail_user_data;
    /* Group update push. on_group_update fires on every member when an update
     * frame arrives; on_group_ack fires on the pusher when a member reports
     * applied/rejected. Both run on the bus thread: keep them short. */
    void (*on_group_update)(qihse_cluster_bus_t* bus, uint64_t update_id,
                            const char* group, const uint8_t* payload,
                            size_t payload_len, uint16_t sender_index, void* user_data);
    void* on_group_update_user_data;
    void (*on_group_ack)(qihse_cluster_bus_t* bus, uint64_t update_id,
                         uint16_t sender_index, uint16_t status, void* user_data);
    void* on_group_ack_user_data;
    /* Federation trust context.  When set, FED_STATEMENT and FED_HEARTBEAT
     * datagrams are verified through the federation layer (signature against
     * the enrolled node key, trust state, replay window) before
     * on_federation runs.  When NULL, those message types are dropped
     * outright: an unverified membership claim is never acted on. */
    void* federation_store;      /* qihse_kv_store_t* */
    void* federation_user;       /* qihse_user_t* */
    /* Optional: this node's own federation UUID (plan §18 — identity is a
     * UUID, never a topology index).  When set AND a federation store is
     * configured, the bus persists this node's own capability probe as a
     * durable "federation/node/<uuid>" record at start and every
     * QIHSE_CLUSTER_BUS_CAP_RECORD_MS, so its capability profile survives a
     * restart.  NULL (the default) writes nothing: the bus will not invent an
     * identity it was not given. */
    const qihse_uuid_t* local_node_uuid;
    /* Two callbacks with DISTINCT payload types, because the two tiers carry
     * different authority.
     *
     * on_liveness fires for a verified heartbeat.  It carries liveness only.
     * on_membership fires for a verified signed statement.  It is the only
     * input an authority decision may use.
     *
     * Keeping them separate types means a consumer cannot accidentally make
     * an ownership decision from a heartbeat: it will not compile.  Both run
     * on the bus thread — keep them short. */
    void (*on_liveness)(qihse_cluster_bus_t* bus,
                        const qihse_federation_liveness_t* observation,
                        void* user_data);
    void* on_liveness_user_data;
    void (*on_membership)(qihse_cluster_bus_t* bus,
                          const qihse_federation_membership_t* member,
                          void* user_data);
    void* on_membership_user_data;
} qihse_cluster_bus_config_t;

/* True when a bus message type is allowed to carry federation authority.
 *
 * The bootstrap and liveness types are deliberately excluded: a node cannot
 * verify a peer it has not enrolled yet, so MEET and PING must remain usable
 * during bootstrap, but that also means they must never be the basis for an
 * authority decision such as a slot ownership change. */
bool qihse_bus_msg_carries_authority(uint32_t message_type);

/* Push a group update to every peer (members apply it, non-members ignore it —
 * membership is enforced by the consumer, not the transport). Returns false
 * when the frame could not be built or sent. */
bool qihse_cluster_bus_broadcast_group_update(qihse_cluster_bus_t* bus, uint64_t update_id,
                                              const char* group, const uint8_t* payload,
                                              size_t payload_len);

/* Broadcast a post-quantum signed membership statement to every peer.  The
 * statement must already be signed (qihse_federation_gossip_sign); this only
 * serializes and sends it.  Returns false if it cannot be built or sent. */
bool qihse_cluster_bus_broadcast_federation_statement(qihse_cluster_bus_t* bus,
                                                     const qihse_federation_gossip_t* stmt);

/* Broadcast a cheap session-bound heartbeat.  Carries no authority of its own:
 * a receiver accepts it only while it matches the session minted by a valid
 * statement. */
bool qihse_cluster_bus_broadcast_federation_heartbeat(qihse_cluster_bus_t* bus,
                                                     const qihse_federation_heartbeat_t* hb);

/* Report that this node applied (status 0) or rejected a group update. */
bool qihse_cluster_bus_broadcast_group_ack(qihse_cluster_bus_t* bus, uint64_t update_id,
                                           uint16_t status);

/* Install the group callbacks after creation (the bus struct is opaque, so
 * consumers that wire themselves up post-create use this instead of touching
 * qihse_cluster_bus_config_t). */
void qihse_cluster_bus_set_group_callbacks(
    qihse_cluster_bus_t* bus,
    void (*on_update)(qihse_cluster_bus_t* bus, uint64_t update_id, const char* group,
                      const uint8_t* payload, size_t payload_len, uint16_t sender_index,
                      void* user_data),
    void* on_update_user_data,
    void (*on_ack)(qihse_cluster_bus_t* bus, uint64_t update_id, uint16_t sender_index,
                   uint16_t status, void* user_data),
    void* on_ack_user_data);

qihse_cluster_bus_t* qihse_cluster_bus_create(const qihse_cluster_bus_config_t* config);
bool qihse_cluster_bus_start(qihse_cluster_bus_t* bus);
void qihse_cluster_bus_stop(qihse_cluster_bus_t* bus);
void qihse_cluster_bus_destroy(qihse_cluster_bus_t* bus);

/* Broadcast a slot ownership update to all known peers. */
bool qihse_cluster_bus_broadcast_slot_update(qihse_cluster_bus_t* bus,
                                             uint16_t start, uint16_t end,
                                             uint16_t owner_index);

/* Broadcast a node metadata update (role change, health change). */
bool qihse_cluster_bus_broadcast_node_update(qihse_cluster_bus_t* bus,
                                             uint16_t node_index);

/* Broadcast a FAIL notice for a node. */
bool qihse_cluster_bus_broadcast_fail(qihse_cluster_bus_t* bus,
                                      uint16_t failed_node_index);

/* When did this node first appear on our bus (ms epoch, 0 = never seen)?
 * "Peer uptime from the observer's perspective" — the failover coordinator
 * uses this for most-uptime successor selection. */
bool qihse_cluster_bus_peer_first_seen(const qihse_cluster_bus_t* bus,
                                       uint16_t node_index, uint64_t* out_first_seen_ms);

/* When did ANY bus participant last report this node healthy? 0 = never.
 * The failover coordinator uses this to gate promotion: a node someone
 * recently saw alive is an asymmetry suspect, not a confirmed failure. */
uint64_t qihse_cluster_bus_last_observed_healthy(const qihse_cluster_bus_t* bus,
                                                 uint16_t node_index);

/* Capability profile last advertised by a node via NODE_CAP (per-node table
 * keyed by topology node index).  Returns false when no NODE_CAP has been
 * received for that node yet; out pointers may be NULL to fetch a subset. */
bool qihse_cluster_bus_node_caps(const qihse_cluster_bus_t* bus,
                                 uint16_t node_index,
                                 uint8_t* isa, uint8_t* npu, uint8_t* gpu,
                                 uint32_t* free_ram, uint16_t* load);

/* Send a MEET to a specific address (introduces this node to a peer). */
bool qihse_cluster_bus_meet(qihse_cluster_bus_t* bus,
                            const char* host, uint16_t port);

/* Send one frame of `message_type` to a specific address, framed and veiled
 * exactly like every other bus datagram.  The bus does not interpret the
 * payload; the caller owns the type's semantics.  Used by overlay layer 3 to
 * send a DHT query to a peer's bus port (the bus itself never originates one).
 * Returns false when the frame cannot be built or sent. */
bool qihse_cluster_bus_send_frame(qihse_cluster_bus_t* bus, uint32_t message_type,
                                  const uint8_t* payload, size_t payload_len,
                                  const char* host, uint16_t port);

/* Manually inject a received datagram (for testing).  Returns true if
 * the message was processed and applied to the topology. */
bool qihse_cluster_bus_inject(qihse_cluster_bus_t* bus,
                              const uint8_t* datagram, size_t len,
                              const char* peer_host, uint16_t peer_port);

/* Get the UDP socket fd (for poll-based integration).  Returns -1 if
 * the bus is not running or uses AF_XDP. */
int qihse_cluster_bus_fd(const qihse_cluster_bus_t* bus);

/* Process one round of pending datagrams (non-blocking).  Returns the
 * number of messages processed. */
size_t qihse_cluster_bus_poll(qihse_cluster_bus_t* bus);

/* Check if a node has been silent beyond the timeout threshold.  Returns
 * the number of nodes marked as unhealthy. */
size_t qihse_cluster_bus_check_health(qihse_cluster_bus_t* bus);

/* Statistics. */
typedef struct {
    uint64_t sent;
    uint64_t received;
    uint64_t pings_sent;
    uint64_t pongs_received;
    uint64_t slot_updates_received;
    uint64_t fail_notices_received;
    uint64_t nodes_marked_unhealthy;
    uint64_t group_updates_received;
    uint64_t group_acks_received;
} qihse_cluster_bus_stats_t;

void qihse_cluster_bus_stats(const qihse_cluster_bus_t* bus,
                             qihse_cluster_bus_stats_t* out_stats);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_BUS_H */
