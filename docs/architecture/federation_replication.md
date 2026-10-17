# Federation Replication

> **Status: implemented** — manifests, sync plans, the pluggable transport, the
> loopback transport, and resumable digest-verified range transfer are verified
> by `tests/test_federation_repl.c`.
>
> **Contradiction:** the "What is not implemented" section below is stale. The
> transport that carries ranges, the bounded resumable cursor, and checksum
> verification of transferred data all exist in
> `src/federation/qihse_federation_repl.c`.

## Anti-entropy model

Gossip is useful for liveness but is not sufficient as the only replication
correctness mechanism, so reconciliation is explicit:

```
periodic peer reconciliation
    -> compare namespace/root summaries
    -> identify divergent ranges
    -> exchange generation/HLC digests
    -> transfer missing events/objects
    -> verify checksums
```

## Namespace manifests

A manifest covers a namespace with SHA-384 range digests over sorted object
IDs, so peers can identify divergent ranges without transferring the dataset.

```c
typedef struct {
    char range_start[64];
    char range_end[64];
    uint64_t object_count;
    uint8_t digest[48];
} qihse_federation_manifest_entry_t;
```

`qihse_federation_manifest_build()` produces one; `_compare()` reports the
number of divergent ranges and writes them out. Comparison is deterministic:
the same two manifests always produce the same divergence count and digests,
which is what makes a merge outcome reproducible.

## Sync plans

`qihse_federation_sync_plan()` classifies each range:

| Action | Meaning |
|---|---|
| `QIHSE_SYNC_SEND` | local has objects the peer lacks |
| `QIHSE_SYNC_FETCH` | the peer has objects local lacks |
| `QIHSE_SYNC_CONFLICT` | both have objects and they diverge |

## Replication Transports

QIHSE decouples the logical replication engine from physical transport:

| Transport | Configuration | Status | Threat Model & Policy |
|---|---|---|---|
| **Direct LAN / WireGuard Mesh** | `--replication-transport direct` or `wireguard` | **Default** | Private RFC1918 IPv4 (e.g. `192.168.1.0/24` or `10.0.0.0/8`); hardware kernel crypto |
| **I2P Garlic Routing** | `--replication-transport i2p` | **Strictly Opt-in** | Covert transport via loopback SOCKS5; metadata-hiding multi-hop garlic tunnels |

### Opt-In Enforcement & Mutual Pinning

- **Default Transport**: WireGuard / private RFC1918 mesh is standard.
- **Opt-in Only**: The daemon requires `--replication-transport i2p` explicitly when connecting to an `.i2p` destination. Unconfigured attempts fail fast at CLI validation.
- **Mutual Pinning**: Both primary and replica cryptographically verify peer identities (`--replication-peer-node-id` and `--replication-peer-dsa-pub`) using Post-Quantum CNSA 2.0 signatures (ML-DSA-87) over sealed QKP1 sessions.
- **Automated Provisioning**: PQC certificate generation, i2pd hardening, and tunnel configuration are automated via [scripts/setup_i2p_replication.sh](file:///home/john/Documents/QIHSE/scripts/setup_i2p_replication.sh).
