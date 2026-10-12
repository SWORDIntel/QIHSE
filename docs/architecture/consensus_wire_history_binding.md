# Consensus wire history binding

An opt-in group with a durable `history_id` and `writer_epoch_floor` uses a
separate wire version. The configured epoch floor is the stable identity of
that history, while consensus terms and fencing epochs can advance within it.
The mesh copies these values from the consensus configuration; it starts peer
streams only after the consensus core has opened and validated its local
record.

After QKP authenticates and pins a peer, the sender's first sealed record is
`QCH2`: magic, group length, sender UUID, receiver UUID, 32-byte history ID,
eight-byte big-endian writer epoch, and group ID. The receiving mesh rejects
any first record that fails this binding before it dispatches consensus or
blob traffic. A legacy group skips this prelude.

Each subsequent consensus message uses `QCS2` with the history ID and writer
epoch after its term and fencing epoch. The bound decoder requires exact
identity before it decodes or exposes entries. Blob staging uses `QBT2` with
the identity after its group ID; its `QBA2` status frames carry the same
identity. Bound groups reject legacy `QCS1`, `QBT1`, and `QBA1` frames. Legacy
groups continue using their original formats. There is no silent version
fallback or mixed-history admission.

The mesh now opens a history-bound snapshot stage when the consensus group
has a configured identity. Its `QCSSTG2` file magic and first durable header
record include the 32-byte history ID and writer epoch floor. Reopen refuses
legacy `QCSSTG1` files and stage files with a different identity, including
after an atomic stage replacement. The legacy opener accepts only legacy
files. There is no implicit migration; an old stage must be discarded through
an explicit operator recovery procedure before a bound group starts.

These are authenticated transport and local stage identity checks, not a
committed-prefix proof. The canonical checkpoint must also bind the history
ID, and receivers must verify a cryptographic digest of the ordered committed
prefix, row labels, SCI metadata, tombstones, and update sequence. The current
snapshot digest and stage frame checksum are non-cryptographic and do not
prove a common prefix. A lagging copy still needs an authenticated
common-prefix proof and ordered replay.
Replacing a divergent history still requires external fencing and an empty,
distinct new group. The wire binding alone does not authorize serving data.

The repository's protocol-adapter security rule requires a low-clearance,
high-data negative test in CI before these frames are merged or released.
