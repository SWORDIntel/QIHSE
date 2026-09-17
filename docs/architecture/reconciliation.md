# Reconciliation

> **Status: implemented** — the ordered sequence, the ownership gate, and
> resumable progress are verified by `tests/test_federation_rejoin.c` and
> `tests/test_federation_f8_ops.c`.
>
> **Contradiction:** the "What is not implemented" section below is stale.
> `TRANSFER_EVENTS` and `RECONSTRUCT_STATE` are driven by
> `qihse_rejoin_driver_step()` in `src/federation/qihse_federation_rejoin.c`,
> which moves records through `qihse_repl_sync_round()`.

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

> **Section status: partial — this section is stale.** `TRANSFER_EVENTS` and
> `RECONSTRUCT_STATE` do move data: `qihse_rejoin_driver_step()` drives
> `qihse_repl_sync_round()` in `src/federation/qihse_federation_rejoin.c`. See
> the contradiction note at the top of this document.

Steps `TRANSFER_EVENTS` and `RECONSTRUCT_STATE` are represented and ordered but
do not yet move data, because the replication transport is not implemented
(see [federation_replication.md](federation_replication.md)). The state machine
is the contract the transport will satisfy.
