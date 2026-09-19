# QIHSE Overlay Protocol — Self-Forming Internet Cluster

> **Status: implemented (phase 1 and phase 2).** Veiled bus framing, the IRC
> dead-drop, HMAC-SHA-384 record authentication, and the layer-3 DHT peer
> exchange are verified by `tests/test_overlay.c` and
> `tests/test_dht_peer_exchange.c`.
>
> **Contradiction:** the status line this document carried until the labeling
> pass said phase 1 was "pending landing (W0)"; W0 is complete and the test is
> CI-wired. Two deltas from the
> design still hold: layer 1 lives in the bus
> (`qihse_bus_veil_encode`/`_decode` in `src/spinnaker/qihse_cluster_bus.c`),
> and layer 2 authenticates with HMAC-SHA-384 rather than ML-DSA signatures.
> Layer 3 landed as W4.2; it is a hint source, not a routing layer — see below.

## Purpose

QIHSE nodes discover and connect to each other over the internet with zero
manual topology. No VPN, no port forwarding, no central coordinator. The
cluster self-forms using IRC dead-drop bootstrap, gossip peer exchange, and
veiled transport.

## Design

### Layer 1: Veiled framing (transport obfuscation)

All bus UDP datagrams are wrapped before transmission:

```
wire format: [nonce 8B][pad_len u8][padding 0-64B][xored_frame]
```

- Keystream = HMAC-SHA384(cluster_password, nonce), truncated to frame length
- XOR keystream over the entire frame (header + payload)
- Random padding (1–64 bytes) between frames obfuscates length patterns
- Receiver: read nonce → derive keystream → strip padding → parse frame

Not encryption — the ML-DSA signatures provide authenticity. This makes the
traffic not obviously scannable as a known protocol.

Files: `src/spinnaker/qihse_overlay.c` functions `overlay_frame_encode()`
and `overlay_frame_decode()`, called from the bus `send_datagram` and
`poll` paths when `overlay_enabled` is set.

### Layer 2: IRC dead-drop bootstrap

A per-node IRC client thread (runs alongside the bus):

1. Connect to a configured IRC server (TLS port 6697)
2. NICK = node_id[:8], USER = qihse-overlay
3. JOIN a configured channel (e.g., `#qihse-fabric`)
4. Every 30 s: PRIVMSG the channel with a signed node record:

```
QIHSE1 <base64(ML-DSA-signed{"ep":"host:port","bus":port,"id":"<40-char hex>","ts":<unix_ms>})>
```

5. Read all PRIVMSGs starting with `QIHSE1 `: verify ML-DSA signature,
   check timestamp freshness (±5 min), extract endpoint
6. If the endpoint is new: `qihse_cluster_bus_meet(bus, host, bus_port)`
7. The existing bus gossip propagates membership to the full cluster

IRC servers are untrusted bulletin boards — the ML-DSA signature proves the
record is from a legitimate node, the timestamp prevents replay, and the
signature covers the endpoint so it can't be redirected.

Config (daemon flags):
```
--irc-server irc.libera.chat:6697
--irc-channel #qihse-fabric
--irc-nick-prefix qihse
```

Files: `src/spinnaker/qihse_overlay.c` (IRC client thread, record
sign/verify, MEET trigger), `include/qihse_overlay.h`.

### Layer 3: DHT peer exchange (simplified Kademlia) — implemented (W4.2)

**What it buys: a peer-exchange hint source, and nothing more.** A node can ask
a peer "which peers do you know near this node id?" and get back up to k=8
peers ordered by XOR distance to the target. It does not improve routing: slot
ownership and membership still travel on the bus (MEET / SLOT_UPDATE), and a
DHT reply is never consulted to decide where a key lives.

Implemented as bus message types **13/14**, not the 9/10 this document (and the
roadmap) originally named — 9 and 10 were taken by `GROUP_UPDATE`/`GROUP_ACK`
before layer 3 landed. The pair is defined in `qihse_cluster_bus.h` and
dispatched to the overlay handlers in `src/spinnaker/qihse_overlay.c`:

- `QIHSE_BUS_MSG_DHT_FIND` (13) — "peers near this node id?", fixed 160-byte
  payload: version, flags, max_peers, reserved, ts, requester endpoint
  (host/port), requester id, target id.
- `QIHSE_BUS_MSG_DHT_NODES` (14) — up to 8 peers, nearest first, fixed 53-byte
  header plus 107 bytes per entry.

A lookup is **one hop**: a FIND is answered, never forwarded, and a NODES frame
never causes another query, so nothing recurses. Both frames are fixed-size
with no length field to lie about; an unknown version, a non-zero flag or
reserved byte, a count/size mismatch, a non-literal host, the unspecified
address, or a timestamp outside the same ±5 min replay window the IRC records
use drops the frame whole. Replies are capped at 16/s, hint processing at
32 entries/s, and dials at 4/s; hint state is a fixed 64-entry dedupe table, so
a flood cannot grow it.

**A DHT record is an unauthenticated HINT, enforced in code.** No signature,
MAC or key is carried and nothing binds the node id in a record to its sender.
The only action a record can cause is a **dial** — `qihse_cluster_bus_meet()`
to the hinted endpoint, the same call the IRC path makes (the shared
`overlay_dial_hint()` gate). It cannot upsert a topology node, write a
federation identity or capability record, change a trust state, or acquire
authority: `qihse_bus_msg_carries_authority()` is false for the DHT types and
for MEET, and the dial path refuses to run if that ever stops being true.
Membership is still decided by the peer's own MEET reply and by F5 enrollment —
a discovered peer that was never enrolled resolves to no usable identity
(`qihse_federation_node_capability_lookup_admissible()`). With a federation
trust context configured, a hint whose derived UUID is **REVOKED** is never
dialed: the DHT may not undo an operator decision, and it may not make one.

Deltas from the original design, on purpose:

- **No k-buckets and no routing table.** The responder answers from the peers
  it already knows (the cluster topology) and ranks them by XOR distance; there
  is no bucket maintenance to poison.
- **No `FIND_VALUE` and no value store.** A value store reachable by an
  unauthenticated datagram is a poisoning target with no benefit over the bus
  that already carries the cluster's state.
- **No public keys in DHT frames.** A key in an unauthenticated record proves
  nothing; the signed F5 identity record is where a node's key lives.
- **Bootstrap is still the IRC dead-drop (or a configured seed).** A FIND
  returns peers the responder knows; it does not discover the responder.

Tests: `tests/test_dht_peer_exchange.c` (CI-wired as `make test-dht-peer-exchange`),
including the roadmap's gate — a forged, expired or hostile DHT record never
yields membership.

This is NOT a full DHT: the IRC bootstrap + MEET gossip still handles small
clusters, and the DHT is a hint source for internet-scale discovery.

### NAT traversal

The bus is UDP. Both nodes send simultaneously → NAT hole-punching works:

1. Node A (behind NAT) learns node B's public endpoint via IRC
2. Node A sends MEET to B's bus port (opens A's NAT mapping)
3. Node B receives MEET, replies to A's source address (opens B's NAT)
4. Bidirectional UDP path established → bus heartbeats flow ✓

For this to work, both nodes must send simultaneously. The IRC bootstrap
provides the rendezvous: both nodes learn about each other and send
within the same window.

## Implementation order

| Phase | What | Files | Est |
|---|---|---|---|
| 1a | Veiled framing (XOR + padding) | overlay.c, bus send/recv hooks | ~100 lines |
| 1b | IRC bootstrap client | overlay.c (IRC thread) | ~300 lines |
| 1c | Daemon flags + wiring | qihse_cluster_daemon.c | ~50 lines |
| 2 | DHT peer exchange — **landed (W4.2)**: fixed-frame FIND/NODES, XOR ranking, no buckets | overlay.c, bus dispatch (types 13/14) | ~500 lines |
| 3 | AI memory API | brain.c extensions | ~300 lines |

## Config reference (daemon flags)

| Flag | Purpose |
|---|---|
| `--irc-server HOST:PORT` | IRC server for bootstrap (TLS) |
| `--irc-channel NAME` | Channel to join and post/observe |
| `--irc-nick-prefix PREFIX` | Nick prefix (suffix = node_id[:8]) |
| `--overlay-key PASSWORD` | Veiled framing key (defaults to cluster password) |

The DHT (layer 3) has no daemon flag: it comes up with the IRC bootstrap and is
disabled per deployment with `qihse_overlay_config_t.disable_dht`. It can also
be run without IRC via `qihse_overlay_dht_start()`.

## Security

- IRC records: ML-DSA-87 signed, timestamp-checked (±5 min replay window)
- Bus frames: already auth-gated (operator password required for RESP)
- Veiled framing: obfuscation only, not security — the bus auth is real
- IRC channel: public — anyone can read the records but can't forge them
  (ML-DSA-87 signatures) and can't join the cluster without the operator
  password (RESP auth)
- DHT records (types 13/14): **unauthenticated hints**. Timestamp-checked,
  fixed-size, rate-limited, deduplicated, and able to cause a dial and nothing
  else — see layer 3 above. A record never yields membership, trust or
  authority.

## Relation to the federation direction

The [federation upgrade plan](../plans/qihse_federation_upgrade_plan.md)
(accepted 2026-09-15) keeps this overlay as the **discovery and
transport-obfuscation plane** and layers real membership trust on top of it
(plan §17–18, Phase 5):

- durable node identity keys + federation CA enrollment; node identity is a
  UUID, never an IP/hostname/topology index;
- mTLS for all administrative/federation RPC;
- signed, replay-resistant gossip with boot/session UUIDs and monotonic
  sequence numbers — a UDP datagram is never trusted because its source IP
  matches a configured peer.

Under that model an IRC dead-drop record becomes a **discovery hint**: it
tells a node where to find a peer, but the node cannot join the federation
until its node identity is enrolled. The phase-2 DHT is a hint source of the
same kind (and an even weaker one — it carries no key at all), which is why it
was sequenced after F5: discovery can hand out addresses, enrollment still
decides who is a member. Replication correctness moves to the plan's
anti-entropy layer (plan §10), not gossip.
