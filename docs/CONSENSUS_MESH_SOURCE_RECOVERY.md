# Consensus mesh source recovery

The candidate runtime was built from revision `77ce165` plus an uncommitted
QIHSE worktree. Its staged `libqihse.so` has SHA-256
`594e70414e427a9264287f8bf041ff589c050cfb17e35e76f8adbb87431ae59e`.
The staged manifest records generic x86-64 and Debian 13/glibc 2.41. The
binary exports `qihse_consensus_mesh_status`; the local status implementation
was recovered from its documented RESP contract and symbol behavior, rather
than from a matching source archive. Source equivalence to that binary has
not been established.

Two local QIHSE checkouts shared revision `77ce165`. The candidate consensus
mesh, QBR1 blob channel, QCS1 wire codec, authenticated transaction RESP
bridge, daemon configuration, and related tests were in a separate local
worktree. The integration checkout lacked those uncommitted files. This
recovery brought the candidate components into this checkout and added
`QIHSE.CONSENSUS.STATUS`, which returns role, leader UUID, term, commit index,
and log tail from one mesh state lock without reading classified rows.

The integration checkout already contained a fixed-size snapshot cap guard.
The candidate streamed snapshot implementation supersedes that cap; its
bounded chunk test replaces the former fixed-prefix test. Separate local
federation snapshot-transfer edits were retained. Unrelated analysis artifact
work and its roadmap changes were not copied.

This is source recovery only. No build, tests, binary comparison, service
change, deployment, or proposal activation was performed. Before merge or
deployment, the status adapter needs a low-clearance/high-data negative CI
test under the repository security rules, then focused build and integration
verification. Candidate proposal commands remain disabled until the
checkpoint, fencing, catch-up, and failover gates are proven.
