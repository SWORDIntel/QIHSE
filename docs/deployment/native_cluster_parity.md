# Native cluster artifact parity

Use one portable `libqihse.so` and `qihse-cluster-daemon` pair for a mesh
whose nodes have different CPU instruction sets. Node identity, network
endpoints, proposal policy, and election delay belong in service arguments
and protected configuration, not in role-specific binaries.

## Historical inventory — not current parity

An earlier inventory recorded read-only inspection of three candidate mesh
nodes on 2026-10-12. It recorded chrooted daemon files with SHA-256
`9e0037680c09e13bb61864704dd869a98c380d6eed2ec116c609c11ee0e8901b`;
their chrooted libraries all had SHA-256
`594e70414e427a9264287f8bf041ff589c050cfb17e35e76f8adbb87431ae59e`.
It recorded an `x86-64-baseline` daemon ELF note, differing service arguments
and a non-proposing third node with election delay. These are historical
observations, not fresh inspection or proof that running processes still map
those bytes, that deployed files match current source, or that nodes currently
agree. No current source/hash parity, leadership, quorum, audit continuity or
application health was verified in this documentation update.

The local development library had SHA-256
`4f3680c76d6dd6ae677adb96a143c0199094f71bd746a60dd2699ffadf4f2d73`
at that historical inspection. It was a dirty-source artifact, **not** a
drop-in replacement for the deployed pair. That hash does not identify today's
checkout or build. Build-host auto-detection is unsuitable for reproducible
artifacts across heterogeneous CPUs; `QIHSE_ARCH_FLAGS` applies a selected CPU
target to C and C++ objects.

Matching directory names, HEADs or service paths do not prove artifact identity.
Inventory exact on-disk and process-mapped library/daemon identities, loader
paths, chroots/containers and **all** other installed-library consumers (Python,
SQL/RESP services, backup tools and KEYSTONE integrations among them). Replacing
one file or restarting one service does not upgrade every consumer. Never
overwrite a mapped library in place.

## Build a replacement candidate

1. Freeze and review the intended source inputs before producing a release
   candidate. Resolve pending audit-continuity work before choosing a revision.
   Do not clean, install or deploy from a concurrently edited shared checkout.
   The helper rebuilds objects in its source tree; schedule it only after
   writers/builds are quiesced. No worktree or deployment is created by this
   documentation task.
2. From the checkout root, run
   `bash scripts/build_portable_cluster_runtime.sh ../native-candidate ../deployed-libqihse.so`.
   The second argument is an archived copy of the currently deployed library.
   The script rejects a dirty source by default, forces every object to
   rebuild, disables AVX2/AVX-512/VNNI/AMX, and selects generic x86-64 for C
   and C++ code. It records source revision, artifact hashes, ELF dependencies,
   symbol versions, and any removed exported symbols.
3. Compare the candidate's `NEEDED` libraries and GLIBC/GLIBCXX symbol
   versions with the actual runtime chroots of **each** node. Resolve all
   relocations against each node's pinned runtime libraries. A matching
   exported-symbol set is necessary but does not prove structure ABI or
   behavior compatibility. SQL English FTS also dynamically loads
   `libstemmer.so.0d` (Debian/Ubuntu `libstemmer0d`), which may not appear in
   `NEEDED`. Validate its symbols and analyzer behavior in each final runtime.
   Bounded ASCII English/Snowball is not full PostgreSQL text-search parity;
   missing support fails closed.
4. Stage the same pair and manifest in an inactive runtime directory on
   each node. Compare SHA-256 of both staged files with the build manifest
   and with each other before changing a unit.
5. Preserve old runtime artifacts and validated pre-upgrade data images.
   SQL writers emit store v5/schema v4; current readers accept older formats,
   but this is not binary downgrade support. Offline SQL transfer accepts only
   validated v3–v5 images with catalogs and retry receipts into fresh private
   destinations. Test restore/rollback in isolation with the matching
   pre-upgrade runtime/image, not old code on newly written data.
6. Require `make test TEST_JOBS=32` plus isolated retained-log/audit continuity,
   restart/crash recovery, backup/restore, TLS/auth, low-clearance denial and
   application read/write gates. Establish current leadership, quorum and
   replication/commit progress with authenticated evidence. Unknown leadership
   blocks rollout: do not infer a follower from a hostname or historical role.
   Only after those gates pass, roll one confirmed follower at a time and
   recheck health after each restart; handle the current leader last through
   the tested leadership procedure. Keep intentionally fenced nodes fenced.
   Halt on lag, hash mismatch, ambiguous leadership or startup/auth failures.

No live replacement is justified by parity alone. The required gates above
are not evidence that current artifacts or any mixed-version rollout passed.
Do not activate a library while startup/audit recovery remains unresolved.
Follow [Operations §1.6](../OPERATIONS.md#16-staged-installation-and-upgrade-gates)
and the [isolated recovery procedure](README.md#backup-and-recovery); a PING,
service status or identical output directory name is not proof of data health.
