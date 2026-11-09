# W12.2 standalone QTQS sidecar prototype

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Status: experimental partial slice, 2026-11-06. It is not linked into
libqihse or exposed through VectorDB, RESP, SDKs, or AIMEM. W12.2's durable
engine integration and crash gate remain open.

The new qihse_turboquant_sidecar API builds a disposable, generation-bound
file from caller-owned FP32 rows and the exact W12.1 profile. Each operation
borrows a scoped principal handle and pins its generation through the call.
Publication
writes a mode-0600 temporary file in the destination directory, syncs it,
revalidates the principal generation immediately before rename, renames it
over the prior sidecar, then syncs the directory. Every read,
publication, and candidate query accepts an explicit active qihse_user_t
principal. A missing, stale, truncated, or corrupt sidecar invokes the
caller's authenticated exact FP32 callback. Search revalidates principal
generation immediately before copying any result to caller output; profile
reopen does so before returning a profile. Revocation during fallback returns
EACCES without changing outputs. No fallback uses a raw store read.
The callback must independently apply live source authorization.

## Byte contract

All fields are little-endian, exact length, and bounded to 100,000 rows,
1,536 dimensions, 1,024 code bytes per row and about 142 MB total. The file
starts with a 64-byte QTQS v1 header:

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 4 | QTQS magic |
| 4 | 4 | sidecar version 1 |
| 8 | 8 | authoritative source generation |
| 16 | 4 | row count |
| 20 | 4 | dimensions |
| 24 | 4 | exact W12.1 code bytes per row |
| 28 | 4 | serialized exact W12.1 profile bytes |
| 32 | 8 | exact total file bytes |
| 40 | 4 | CRC-32 over header bytes 0..39 |
| 44 | 20 | reserved, zero |

The header is followed by the W12.1 QTQP serialized profile. Each row is:
8-byte ascending unique ID, 2-byte classification, 2-byte SCI mask,
4 reserved zero bytes, the exact QTQR code, then 4-byte CRC-32 over its
16-byte row header and code. The W12.1 profile and code envelopes also
validate their own version, dimensions, lengths, fingerprints and checksums.
CRC and FNV are accidental-corruption checks, **not** a MAC. The sidecar is
not safe against a local writer who can forge labels and checksums. The
caller must also verify the authoritative source generation and scope.

## Search and authorization boundary

The prototype returns approximate candidates only. It does **not** perform
production FP32 rerank. The candidate loop checks the current principal's
liveness, clearance and SCI, then calls a required live source-scope
predicate before reading a row's code or ranking it. The predicate must check
tenant, project, owner, tombstone and committed-generation visibility against
authoritative state. Inaccessible codes are skipped; output count, IDs and
scores contain only accessible rows. The query's exact fallback receives the
same principal and must apply the same live scope. No classified-capable
read has a context-free entry point. A low-clearance/high-data negative test
checks that inserting a higher-classification, foreign-SCI row does not
change the low principal's candidates and does not call its scope callback.
Another test forges that row's label and recomputes its CRC; the required
live source callback still denies it.

This is a bounded prototype, not the W12.3 authorization gate. It lacks
first-class tenant/project fields, source-snapshot transaction fencing,
revocation and multi-tenant stress tests, exact rerank, and an engine
sidecar-status API. The current authoritative source must provide stable
rows and generation while publishing. A directory-sync failure after rename
can leave a published file despite an error return; an engine integrator
must reconcile the on-disk generation after such failure. Revocation between
the final principal check and rename is not atomically excluded without
engine-wide transaction coordination. Crash injection
at every write/fsync/rename boundary remains required before promotion.

## Focused checks

After building libqihse.so in the isolated checkout:

    cc -std=c99 -O2 -Wall -Wextra -Werror -pedantic -fno-fast-math -ffp-contract=off -fno-tree-vectorize -I. -Iinclude -Iquantization/include tests/test_turboquant_sidecar.c quantization/src/qihse_turboquant_sidecar.c quantization/src/qihse_turboquant.c quantization/src/qihse_turboquant_tables.c -L. -lqihse -lm -Wl,-rpath,. -o build/w12/test_turboquant_sidecar
    ./build/w12/test_turboquant_sidecar

The focused test covers publish/reopen, active operator versus low principal,
high-data denial, forged-label denial, high-record noninterference for low
results, live tombstone filtering, stale generation, malformed header and
authorized-code corruption,
missing sidecar, exact callback, NULL/revoked principal denial, and revocation
inside the exact fallback with unchanged caller outputs. The same fixture
passed with ASan+UBSan using detect_leaks=0. LeakSanitizer is not claimed in
this ptrace environment. The complete make test TEST_JOBS=32 gate is owned by
integration; this standalone test is not yet wired into it.

## W12.3/W12.5 standalone scoped rerank experiment

The sidecar now also exposes a separate research-only scoped search. It takes
tenant and project identifiers, expected source generation, candidate pool
capacity and return K. A required authoritative visibility callback checks
tenant/project/owner/clearance/SCI/tombstone for every row **before its code
is read or enters candidate top-K**. A required authoritative score callback
rechecks each selected ID and calculates its score from canonical FP32 values;
no vector or protected payload enters the sidecar result. If a selected ID
becomes inaccessible during rerank, the query invokes a complete authenticated
exact fallback so a hidden row cannot consume candidate capacity. The scoped
fallback also receives the same principal, scope and expected source
generation. A focused test changes a selected row's live visibility during
rerank; the search discards its candidate output and returns exact fallback
results without that ID. The principal generation is rechecked before any
result copy.

This is exact scoring **within the approximate candidate pool**, not an
exhaustive exact top-K guarantee. A source generation change must return
ESTALE from the live callbacks; the caller must restart on a new coherent
snapshot. A stale sidecar header may invoke exact fallback, but ESTALE from
the live source callback propagates unchanged and never invokes fallback;
the focused test supplies a fallback that would otherwise return success.
There is still no engine-level transaction fence, so this remains
unqualified for production VectorDB and AIMEM.

The deterministic synthetic differential test uses 64 FP32 rows x 16
dimensions, eight queries, three repetitions, dot scoring, K=5, candidate
pool=8, W12.1 MSE 3-bit profile, and fixed xorshift seed 0x91234567.
Rows have mixed tenants, projects, classifications and SCI masks. The
authoritative callbacks resolve IDs against live fixture metadata and deny
foreign scope and high labels before reading FP32. Tests explicitly assert
the high row is absent even when queried with its exact vector, foreign
tenant/project scope returns zero rows, hidden rows never reach exact score,
denial during rerank invokes exact fallback, and a mismatched source
generation returns ESTALE with unchanged output. Full-pool rerank is also
checked against the independent authoritative callback for cosine and
squared L2 ordering.

On the local host, pool 8 returned 39/40 exhaustive FP32 top-5 IDs
(Recall@5=0.975); pool 64 returned 40/40. The 8,000-byte QTQS file exceeded
the 4,096-byte FP32 payload, and authoritative FP32 stays resident, so total
storage increased for this tiny fixture. A 24-query warm sample measured
sidecar p50 82.3 ms/p95 108.9 ms and exact fallback p50 48.0 ms/p95
77.2 ms. These include file open, profile comparison, query preparation,
live auth callbacks and C library overhead; the exact fallback omits code
scoring. A concurrent full-suite run shifted those figures to sidecar p50
257 ms/p95 732 ms and exact fallback p50 151 ms/p95 305 ms. These tiny,
load-sensitive samples support no speedup claim. Real authorized corpora,
isolated benchmarks, p99, update/rebuild cost, full RAM accounting and crash
faults remain W12.5 gates.
