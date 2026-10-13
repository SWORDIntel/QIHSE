# Native cluster artifact parity

Use one portable `libqihse.so` and `qihse-cluster-daemon` pair for a mesh
whose nodes have different CPU instruction sets. Node identity, network
endpoints, proposal policy, and election delay belong in service arguments
and protected configuration, not in role-specific binaries.

## Current inventory

The three running candidate mesh nodes were inspected read-only on
2026-10-12. Their chrooted daemon files all have SHA-256
`9e0037680c09e13bb61864704dd869a98c380d6eed2ec116c609c11ee0e8901b`;
their chrooted libraries all have SHA-256
`594e70414e427a9264287f8bf041ff589c050cfb17e35e76f8adbb87431ae59e`.
The daemon ELF note says `x86-64-baseline`. These files are already in byte
parity. The live service arguments differ by node, as intended. In particular,
the third node omits client proposals and adds election delay.

The local development library had SHA-256
`4f3680c76d6dd6ae677adb96a143c0199094f71bd746a60dd2699ffadf4f2d73`
at inspection time. It comes from a dirty source tree and is **not** a
drop-in replacement for the live pair. The development host has no AVX2,
while the live nodes include both Haswell and newer AMD CPUs; build-host
auto-detection is unsuitable for reproducible cluster artifacts. The
Makefile's `QIHSE_ARCH_FLAGS` now applies a selected CPU target to both C and
C++ objects.

## Build a replacement candidate

1. Freeze the intended source revision in an isolated checkout. Resolve and
   review the pending audit-continuity work before choosing that revision.
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
   behavior compatibility.
4. Stage the same pair and manifest in an inactive runtime directory on
   each node. Compare SHA-256 of both staged files with the build manifest
   and with each other before changing a unit.
5. Preserve the current pair and data snapshots. Roll one follower at a
   time, then the leader, observing quorum, status, committed index, durable
   audit continuity, and application read/write behavior after each restart.
   Keep the non-proposing node fenced. Do not activate a new library while
   its startup audit recovery semantics are unresolved.

No live replacement is justified by parity alone. The new native source
changes audit startup behavior and has not yet passed the retained-log and
cross-restart continuity gates. The existing identical pair should remain
in place until those gates and a controlled rollout are complete.
