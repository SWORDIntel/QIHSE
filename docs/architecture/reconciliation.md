# Reconciliation

On rejoin, a node must not immediately publish stale exclusive ownership as
authoritative. The sequence is therefore explicit and ordered.

## The rejoin sequence

```
IDLE
  -> AUTHENTICATE_PEER
  -> COMPARE_FEDERATION_UUID
  -> COMPARE_BOOT_UUID
  -> EXCHANGE_HLC
  -> EXCHANGE_MANIFESTS
  -> IDENTIFY_DIVERGENCE
  -> TRANSFER_EVENTS
  -> APPLY_CONFLICT_POLICY
  -> RECONSTRUCT_STATE
  -> VERIFY_CHECKSUMS
  -> COMPLETE
```

`qihse_rejoin_next_step()` advances the sequence and returns `ABORTED` for a
terminal or illegal transition.

## Ownership is withheld until the end

`qihse_rejoin_may_publish_ownership()` returns true **only** at `COMPLETE` —
after the state has been reconstructed *and* the range checksums verified.
Publishing earlier is exactly how a rejoining node makes a stale exclusive
ownership claim authoritative, which is the failure mode the brief calls out.

## Progress survives restarts

A long reconciliation records its progress, so a node that restarts mid-way
resumes rather than starting over:

```c
typedef struct {
    qihse_uuid_t node_id;
    qihse_uuid_t peer_node;
    qihse_rejoin_step_t step;
    uint64_t events_transferred;
    uint64_t conflicts_applied;
    char last_error[128];
} qihse_rejoin_state_t;
```

## What is not implemented

Steps `TRANSFER_EVENTS` and `RECONSTRUCT_STATE` are represented and ordered but
do not yet move data, because the replication transport is not implemented
(see [federation_replication.md](federation_replication.md)). The state machine
is the contract the transport will satisfy.
