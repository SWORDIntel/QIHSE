# CodeGraph 128-bit public identities

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Current fresh builds use the [standard tuned XXH3 profile](codegraph_xxh3_tuned.md).
Snapshot checksums now also use [XXH3 with bounded retention](codegraph_snapshot_xxh3.md).
The SHA-256/128 profile below records the preceding implementation and remains a
reader compatibility profile; both store 16-byte public IDs.

At this historical checkpoint, producer exports used 32 lowercase hexadecimal characters per public node or edge ID and SHA-256 snapshot/source checks. Fresh builds now use the XXH3 identity and snapshot profiles linked above; source freshness remains SHA-256. The historical identity profile was declared as:

```json
{"identity":"qihse-semantic-128-v1","id_algorithm":"sha256-128","id_bits":128,"id_collision":"counter-sha256-128-v1","id_collision_attempts":256}
```

An initial candidate is the first 16 bytes of SHA-256 over the versioned, framed
semantic identity. Nodes include qualified names; edges include relation,
qualified endpoints (including unresolved names), repository-relative file, line,
and deterministic parallel-occurrence ordinal. Canonical ordering avoids SQLite
row-number dependencies.

The producer compares full semantic preimages whenever candidates match. If they
differ, attempts 1 through 255 hash `qihse-id-collision-v1` followed by NUL,
8-byte big-endian preimage length, the preimage, and the attempt as 8-byte
big-endian. The result is again the first 16 SHA-256 bytes. Exhaustion fails before
atomic publication. This avoids silent merges; it does not make a 128-bit digest
a cryptographic substitute for full snapshot verification. IDs are deterministic
for a fixed graph and collision set; introducing a colliding identity earlier in
canonical order can reassign which identity receives the initial candidate.

Native readers validate the declared ID profile and reject mixed widths or
unsupported parameters. All live graphs were lost before this rollout. Fresh builds use the new identity
namespace by default; no existing-graph migration or dual writing is required.
Acceptance of older synthetic fixtures is only a compatibility regression check.

Packed-v3 uses outer feature bit 0 (offset 44, big-endian uint32) for 16-byte digest
dictionary entries (token kind 2). Existing 32-byte digest entries retain kind 1.
A reader rejects unknown feature bits, and kind 2 requires its advertised bit.
Older readers reject the nonzero feature word. Formats without short-digest entries
retain the original zero feature word. At this historical checkpoint SHA-256 bound the feature word and payload
before classified records can be disclosed.

HAX graph readers treat graph IDs as opaque strings. Their 64-character capability
tokens and SHA-256 freshness values retain their existing widths. Source adapters
preserve the profile header and graph records while recomputing the SHA-256 trailer.

## Validation and storage measurement

The producer passed 25 focused tests, including forced collisions in the first
128 digest bits, deterministic retries, retry exhaustion preserving publication,
parallel edges, unresolved targets, and an independent fixed vector. Seven checks
also passed against the installed producer candidate. Native tests passed strict
profile validation, mixed-width rejection, authorization denial and query parity.
The source adapter passed 11 tests; HAX's real reader API preserved 32-character
node and endpoint IDs. Normal codec and ASan/UBSan checks passed (shared library
uninstrumented; leak detection disabled).

On equivalent synthetic facts, one authenticated run per width measured:

| Nodes / edges | 256-bit IDs, packed-v3 | 128-bit IDs, packed-v3 | Smaller |
| --- | ---: | ---: | ---: |
| 800 / 2,400 | 168,845 bytes | 118,722 bytes | 29.69% |
| 8,000 / 24,000 | 1,686,194 bytes | 1,163,785 bytes | 30.98% |

Both widths passed exact export reconstruction and low-clearance denial. An
independent inverse-ID mapping verified equal graph facts. These are complete
encoded sizes on synthetic inputs, not a claim that all repositories shrink by
31% or that hashing is faster. The fixture replaces IDs with SHA-256 prefixes;
producer correctness and collision allocation are covered by separate tests.

Receipt: `benchmarks/codegraph_ids128_reference.json`. Reproduce with:

```sh
python3 benchmarks/codegraph_ids128_compare.py --nodes 800 8000 \
  --output ./build/codegraph-ids128-reference.json
python3 tests/test_codegraph_ids128.py --binary ./qihse-codegraph
python3 tests/test_codegraph_reindex_source.py --binary ./qihse-codegraph
```

Validation stays scoped to CodeGraph at the user's request. No full QIHSE suite
was launched for this change, and no live graph was rebuilt or migrated.


The final real installed-producer smoke passed through the normal source-identity
adapter: two complete builds of a three-node/three-edge Python fixture produced
byte-identical exports; native import, query and stats accepted 128-bit IDs and
retained SHA-256 source/snapshot verification. Its packed-v3 snapshot was 1,061
bytes. Log: `build/codegraph_ids128_real_smoke.log`. Focused native and sanitizer
logs are `build/codegraph_ids128_native_tests.log` and
`build/codegraph_ids128_sanitizer.log`.

The installed launcher now points atomically to a new private reader/library bundle
under `$HOME/.local/lib/qihse-codegraph/releases`, with its previous bundle retained.
The installed producer and installed launcher passed the same end-to-end smoke
(the independently created test snapshot used 1,064 bytes). Deployment hashes and
rollback target are recorded in `build/codegraph_ids128_deployment.json`; installed
CLI verification is in `build/codegraph_ids128_installed_smoke.log`. This updates
new reader starts; no repository graph was restored or built outside disposable
fixtures.
