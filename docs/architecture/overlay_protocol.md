# QIHSE Overlay Protocol — Self-Forming Internet Cluster

> **Status: implemented (phase 1).** Veiled bus framing, the IRC dead-drop, and
> HMAC-SHA-384 record authentication are verified by `tests/test_overlay.c`.
>
> **Contradiction:** the status line this document carried until the labeling
> pass said phase 1 was "pending landing (W0)"; W0 is complete and the test is
> CI-wired. Two deltas from the
> design still hold: layer 1 lives in the bus
> (`qihse_bus_veil_encode`/`_decode` in `src/spinnaker/qihse_cluster_bus.c`),
> and layer 2 authenticates with HMAC-SHA-384 rather than ML-DSA signatures.
> Layer 3 (DHT peer exchange) is `planned`.

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

### Layer 3: DHT peer exchange (simplified Kademlia)

For clusters > ~8 nodes, a full mesh doesn't scale. The DHT layer:

- Each node maintains k-buckets (k=8) by XOR distance from its node ID
- Peer records (endpoint + public key) stored at key = SHA-384(node_id)
- FIND_NODE and FIND_VALUE operations over the bus (new msg types 9/10)
- Bootstrap: IRC-discovered nodes seed the DHT routing table
- New nodes: `FIND_NODE(self_id)` → get k closest peers → MEET each

This is NOT implemented in phase 1. The IRC bootstrap + MEET gossip
handles up to ~20 nodes. DHT is phase 2 for internet-scale.

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
| 2 | DHT peer exchange | overlay.c (Kademlia buckets) | ~400 lines |
| 3 | AI memory API | brain.c extensions | ~300 lines |

## Config reference (daemon flags)

| Flag | Purpose |
|---|---|
| `--irc-server HOST:PORT` | IRC server for bootstrap (TLS) |
| `--irc-channel NAME` | Channel to join and post/observe |
| `--irc-nick-prefix PREFIX` | Nick prefix (suffix = node_id[:8]) |
| `--overlay-key PASSWORD` | Veiled framing key (defaults to cluster password) |

## Security

- IRC records: ML-DSA-87 signed, timestamp-checked (±5 min replay window)
- Bus frames: already auth-gated (operator password required for RESP)
- Veiled framing: obfuscation only, not security — the bus auth is real
- IRC channel: public — anyone can read the records but can't forge them
  (ML-DSA-87 signatures) and can't join the cluster without the operator
  password (RESP auth)

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
until its node identity is enrolled. The phase-2 DHT remains the
internet-scale discovery path; replication correctness moves to the plan's
anti-entropy layer (plan §10), not gossip.
