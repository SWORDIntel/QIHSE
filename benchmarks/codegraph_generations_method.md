# CodeGraph immutable file generations: format and verification

This is supporting implementation evidence. Delivery status remains solely in
[ROADMAP.md](../ROADMAP.md#codegraph).

The explicit `generations-v1` format writes a small `QCGG0001` parent and immutable
per-source-file `.qgb` blocks. It preserves complete KV exports byte for byte,
including unknown values, original ordering, exact header spelling/extensions,
classification, SCI, expiry, flags and sequence. Input records are grouped using
their JSON `file` field where present; non-JSON/unknown metadata uses a fallback
group. Grouping changes layout only. Keys are compared completely and duplicates
are rejected.

Sequence and exact original headers live in the parent, so ordinary reimport
sequence renumbering does not rewrite unchanged file bodies. Within each file,
keys are sorted deterministically. Large files split at an 8 MiB target, with a
32 MiB hard decoded-block bound. A single oversized record fails rather than
silently losing evidence. Current hard limits are 2,000,000 records, 65,536
blocks, 4 GiB total raw export and 256 MiB parent metadata. Physical-directory scans are capped at 262,144 entries; GC fails closed above that limit and accounting reports incomplete coverage.

Each block contains independently compressed key/security metadata and exact
value bytes. The metadata is also used as a raw Zstandard dictionary for the
value frame, avoiding duplicate random IDs across the two sections. Decoders
check tenant, every key namespace, classification and SCI before decompressing
values. The parent repeats and binds the record metadata; reconstructed records
must match both copies. There is no public raw-block read primitive.

Parent checksums use the caller's explicit typed checksum contract; native new
CodeGraph publications use XXH3-128. Block names are canonical XXH3-128 digests
of complete encoded blocks. An existing address is reused only after full byte
comparison and descriptor stability checks; different bytes at the same address
fail with `EEXIST`. This detects corruption or a collision without aliasing facts.
Neither checksum is a cryptographic authenticator. Source freshness and export
trailer contracts are unchanged.

The writer fsyncs a private temporary block and publishes it using atomic
`renameat2(RENAME_NOREPLACE)`, then fsyncs the directory. It never overwrites an
existing content address. Filesystems without that operation fail safely; there
is no unsafe overwrite or hard-link publication fallback. This avoids the
hard-kill window in a link-then-unlink implementation where the canonical block
would be stranded with a link count of two. All directory walks reject parent
symlinks; block reads are descriptor-relative, no-follow, owner-private and
single-link.

The caller owns parent publication and the native lifecycle lock. Encode and GC
require the exclusive lock; reads/accounting require the shared lock. Publish
and durably commit the parent before pruning and GC. GC receives trusted current
and previous roots, validates their complete references and every orphan
candidate before deleting anything, and retains their union. Invalid retained
roots or unauthorized orphan candidates prevent deletion. Unknown filenames,
symlinks and foreign/non-private files are untouched. Strict `.pending-<pid>-<16hex>` private artifacts may be reclaimed only by a fully cleared system Operator, because an interrupted frame cannot establish narrower tenant/label authority. Unknown directory entries make accounting explicitly incomplete. A failed or killed writer
can leave unreferenced blocks; the next validated-root GC removes them.

GC and accounting use validation-only traversal: they verify mappings, labels,
metadata, value integrity, NUL checks and duplicate keys without creating raw
export staging files. The read-only accounting API reports a unique referenced
union, authorized orphan sizes, logical/allocated bytes and incomplete coverage
for excluded orphan entries. It never returns filenames or payloads.

## Reproduce focused checks

From the repository root, using the matched local QIHSE library:

```sh
make -C tools/codegraph_xxh3 -j4 all
cc -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
  -DCG_GENERATION_TEST_FAULTS -Iinclude -Icore -Itools \
  tests/test_codegraph_generations.c tools/qihse_codegraph_generation.c \
  tools/qihse_codegraph_checksum.c tools/codegraph_xxh3/build/libqihse_xxh3.a \
  -o build/test_codegraph_generations -L. -lqihse \
  $(pkg-config --cflags --libs json-c openssl libzstd) -pthread -lm -ldl
LD_LIBRARY_PATH=. ./build/test_codegraph_generations
```

The test-only fault macro enables a child-process exit immediately after atomic
block rename. It is not enabled in the native production executable. Tests cover
sequence-only reuse, edit/rename/delete parity, two-root retention and orphan GC,
wrong checksum, truncation, malformed mapping and limits, buffered-stdio spoofing,
occupied-address corruption, symlink and mode denial, NULL/low-clearance/wrong-SCI
and tenant denial, forged lower-label parents, protected-orphan accounting and
nondeletion, unknown-file accounting, partial pending-write recovery with low-principal nondeletion, and exact reconstruction above 64 MiB.

For ASan/UBSan, replace `-O2` with `-O1 -g`, add
`-fsanitize=address,undefined -fno-omit-frame-pointer`, and run with
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1`.
The shared engine and separately built XXH3 archive are not instrumented by that
command; this is focused codec coverage, not full-engine or leak coverage.

## Reproduce the codec comparison

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
  -Iinclude -Icore -Itools benchmarks/codegraph_generations_driver.c \
  tools/qihse_codegraph_generation.c tools/qihse_codegraph_checksum.c \
  tools/qihse_codegraph_dictionary.c tools/codegraph_xxh3/build/libqihse_xxh3.a \
  -o build/codegraph_generations_driver -L. -lqihse \
  $(pkg-config --cflags --libs json-c openssl libzstd) -pthread -lm -ldl
python3 benchmarks/codegraph_generations_compare.py \
  --driver ./build/codegraph_generations_driver \
  --output ./benchmarks/codegraph_generations_reference.json
```

The synthetic 8,000-node/24,000-edge fixture uses deterministic high-entropy
128-bit IDs, 100 source files and complete unknown fields. Each generation is
independently decoded and compared byte for byte. First build, sequence-only
reimport and single-file edit are measured separately. The whole-Zstd baseline
uses the existing QCGZ0001 framing, Zstandard level 9, window log 23 and checksum,
over the same exact raw export. The existing packed-v3 dictionary codec is also measured and independently decoded on the same bytes. Retained-generation sizes include parent files
and the garbage-collected unique current/previous block union; physical block
allocation is reported separately.

These are standalone codec measurements. The generation writer still scans the
complete export, so this is not sparse delta ingestion or an incremental parsing
benchmark. Snapshot bytes written exclude raw export creation, initial KV import,
and native publication verification. Materializing decode stages raw bytes to
private files. Therefore snapshot write savings must not be described as the
same reduction in whole-build CPU, memory or temporary I/O. Small per-file blocks
can also cost extra disk allocation and initial storage versus one compressed
snapshot. Use the receipt to assess that trade-off before selecting the format;
never compare the parent file alone against a complete snapshot.

## Recorded comparison

| Revision | Whole packed-v3 bytes | Generation current bytes | Generation current + previous bytes | New snapshot bytes written |
| --- | ---: | ---: | ---: | ---: |
| 0 | 970,483 | 1,136,088 | 1,136,088 | 1,136,088 |
| 1 | 962,144 | 1,139,227 | 1,251,461 | 115,373 |
| 2 | 962,393 | 1,139,439 | 1,265,073 | 125,846 |

For the single-file edit, generation storage retains 1,265,073 logical bytes across current/previous versus 1,924,537 for two complete packed-v3 files (34.3% less). Current-generation size alone is larger, so the format remains an explicit trade-off. Its encode took 1.265s versus 0.676s for packed-v3; GC plus validated union accounting took 0.360s. Snapshot write counts do not include the complete raw export/import/verification pipeline. These are single-run synthetic observations on a concurrently used host, not an end-to-end speedup claim.
