# CT.1 pinned write stream: safety boundary

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

The legacy cleartext transport remains disabled. The daemon rejects
`--redundancy-peer`, and RESP server creation rejects every non-NULL
`redundancy_peer`, including an empty string.
The former implementation sent `AUTH` and `ASKING` followed by `SET` or `DEL`
over plain RESP after local commit. Its wire record omitted classification,
SCI, tenant, and a durable sequence. A successful local write could therefore
be lost on failure, and a replayed protected value could lose its labels.

## Historical prerequisites

The November 9 implementation adds a separate grouped CT1 stream, authenticated
baseline and durable receiver cursor. The real-daemon acceptance test writes
on the lead, kills it, promotes the successor, establishes its next successor,
and rejects the old lead on restart. See [the runtime contract](ct_transport_runtime.md)
and `tests/test_ct_transfer.py`. The original analysis below explains why the
namespace replication API was not reused as the full successor stream.

### Earlier primitives and their limitations

- `REPL.APPLY` accepts only a pinned QKP replication identity mapped to a
  dedicated active system principal. It carries source sequence, operation,
  classification, SCI, absolute expiry, key, and value; it calls
  `qihse_kv_apply_replica_record`, then advances a durable cursor before `OK`.
  This is scoped to explicitly marked namespace globs, not the full CT.1
  successor write stream. Its record does not carry an explicit tenant.
- `qihse_kv_apply_replica_record` rejects stale sequences and conflicting
  same-sequence retries, while identical retries are idempotent. It enforces
  principal access to incoming and existing classification/SCI metadata.
- Cursor advancement syncs the store and persists the cursor before `OK`.
  Failed fsync returns an error, requiring retry. Apply and cursor advance are
  separate store calls, so a new CT.1 protocol needs a single receiver
  transaction/recovery rule for the gap between them.
- `qihse_kv_export_incremental_user_bounded` returns the latest visible state
  of each key, not every mutation. Overwrites between pulls can collapse, and
  tombstone compaction can erase an unseen delete. It cannot serve as the
  exact ordered CT.1 write stream or establish a promotable successor cursor.

## Protocol acceptance criteria

1. Add a versioned, bounded durable source mutation log retaining each SET,
   DELETE, expiry, and label/tenant change until the successor ACKs its LSN.
   Capture value, classification, SCI, tenant, expiry, and principal provenance
   under the store's mutation lock. Use explicit authenticated context for
   export. Reject an oversized record without advancing the source cursor.
2. Configure a successor by pinned QKP node identity and public-key pin. Bind
   the stream to source/successor IDs, generation, and tenant policy. No
   password fallback, cleartext fallback, or `SET` compatibility replay.
3. On the receiver, validate framing, bounds, peer identity, tenant, source
   generation, and monotonic LSN. Reject label downgrade, unauthorized tenant,
   conflicting duplicate, gap, and stale generation before publication.
   Apply the record and cursor in a recoverable transaction. Return ACK only
   after row WAL and cursor are both durable. An identical retry after a lost
   ACK must succeed without changing the row again.
4. Publish per-successor durable acknowledged LSN and lag. Promotion requires
   a proven cursor at or beyond the lead's committed handoff LSN, or explicitly
   reports data loss and refuses automatic promotion. Reconnect resumes from
   the receiver cursor; a missing/GC'd source segment requires a fresh
   authenticated baseline before promotion.

CT1 is enabled only through its explicit pinned configuration. No
`redundancy_peer` value enables it. Final delivery status and complete-suite
evidence are recorded in the authoritative roadmap.

## Required negative and recovery evidence

- Low-clearance or missing-SCI principal requests a high/SCI row through
  snapshot, delta, direct ID, and apply surfaces: denied without payload.
- Forged or wrongly pinned QKP peer cannot request or apply stream records.
- Tenant A peer cannot write or enumerate tenant B, including with a broad
  namespace match and a direct record ID.
- Wrong generation, LSN gap, stale LSN, and same-LSN conflicting payload are
  refused; byte-identical retry after a lost reply is accepted.
- Inject failure before row WAL sync, between row sync and cursor persistence,
  and during cursor directory fsync; restart and retry produce one authorized
  value and never ACK an undurable LSN.
- Exercise concurrent writers, overwrite, delete, expiry, and label change
  while a bounded stream is in flight. A slow successor must not cause a
  silent source-log gap or unbounded queue.
- Write on the lead, wait for a durable successor ACK, kill the lead, promote
  the successor, and read the exact value with its original tenant,
  classification, SCI, and expiry policy.
