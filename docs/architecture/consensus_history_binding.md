# Consensus history binding

New consensus groups may opt into a durable history identity by supplying
`--consensus-history-id` (64 hex characters) together with
`--consensus-writer-epoch` (a positive integer). The daemon passes both to
the consensus core. At creation, the core writes a checksummed `H` record
after its group header and membership baseline, then starts its fencing epoch
at the configured floor.

On restart, the record must match the configured history ID and epoch floor.
Omitting either setting, changing either value, or trying to add them to an
existing record without an `H` record fails closed. Legacy groups without
an `H` record retain their previous startup behavior. The record is a local
binding; its presence alone does not certify the origin of an application
snapshot or authenticate a remote peer.

`qihse_consensus_rejoin_compare` admits automatic rejoin only for equal
group, history, writer epoch, committed index, and full-prefix SHA-256 digest.
If one copy is behind, an authenticated proof of the common prefix and
ordered replay are required. Divergent equal-index digests are conflicts.
`qihse_consensus_rejoin_new_genesis_candidate` checks only that a proposed
replacement begins at index zero under a different group and history with a
strictly higher epoch. It does not write a genesis or make an old writer safe.

The mesh can export a bounded, lock-consistent committed-prefix SHA-256
inventory for an authenticated system Operator. The prefix-attestation adapter
signs that inventory with an approved enrolled federation key and verifies the
key's current enrollment on every use. The mesh comparison adapter captures a
fresh local inventory, verifies a peer attestation against trusted local
identity configuration, and returns the rejoin guard's classification.
The comparison is diagnostic only: a signed statement has no freshness or
quorum proof, and even an `EXACT` result does not authorize a rejoin, release a
writer fence, or permit application traffic. A lagging copy still requires an
authenticated common-prefix proof and ordered replay.

## Remaining integration

- Bind the history ID to the canonical committed checkpoint payload and
  verify its rows, security labels, tombstones, and update sequence before
  publication.
- Carry and authenticate history identity in peer handshakes and snapshot
  installation. Today's consensus wire messages select only a group ID.
- Carry prefix attestations over an authenticated peer channel with freshness,
  verify a common-prefix proof, and replay missing commits in order. The
  existing snapshot FNV digest remains only an integrity check.
- Coordinate an externally fenced, empty replacement group, then verify
  each recipient before admitting writes or load-balanced reads.
