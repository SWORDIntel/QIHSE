# KP14 binary artifact durability: transaction boundary and open gates

Status: design and executable gap diagnostic, **not** an ingest API. No
KEYSTONE feed event or durable artifact ACK may be issued by the current
preflight API.

## Evidence from current QIHSE primitives

`qihse_blob_put_expected_user` verifies streamed SHA-384 and size and then
commits the payload to its own append-only index. It cannot reserve an
unpublished payload or atomically commit a manifest with that index.
The accepted blob tags end at `QIHSE_BLOB_TAG_REPL_TRANSACTION`, which is
restricted to system Operators; there is no artifact-specific tag.
The blob index is keyed by payload hash and rejects the same bytes under a
different tenant/classification/SCI binding. Two tenants can legitimately
submit the same binary bytes, so that global key cannot represent both
independent artifact bindings without a namespace change.

`qihse_blob_ref_user` adds an ordinary reference. It is **not** a protected
manifest pin: `qihse_blob_delete_user` lets a principal authorized for that
tenant and classification consume every reference, including one that a
manifest writer added. Run the manual diagnostic with:

```
gcc -std=c99 -D_GNU_SOURCE -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I. -I./include -I./core \
  tests/test_analysis_artifact_transaction_gap.c \
  -L. -lqihse -lcrypto -lpthread \
  -o tests/test_analysis_artifact_transaction_gap_san
LD_LIBRARY_PATH=. ./tests/test_analysis_artifact_transaction_gap_san
```

This test writes one tenant-bound blob, increments its refcount to two,
deletes it twice as the same tenant principal, and confirms authenticated
metadata/payload lookup fails. It removes its fixture files afterward. It
proves current refcount semantics, not a vulnerability in an extant artifact
store (there is no such store yet).

`qihse_kv_set_user` and `qihse_kv_del_user` are single-key mutable WAL
operations; `qihse_kv_sync_store` is a separate durability operation whose
caller must serialize writers. The public KV API exposes no cross-store
transaction with the blob index or immutable, nondeletable manifest key.
Writing a KV manifest after `blob_put_expected_user` would therefore leave
orphans on partial failure; reversing the order would leave dangling
manifests. An ACK or KEYSTONE event between those operations is unsafe.

## Recommended binary-only transaction

The smallest independent atomic boundary is a dedicated private artifact
store whose **single immutable file** contains a versioned, canonically
encoded manifest followed by its payload. The manifest still identifies
the payload by SHA-384 and length; physical co-location eliminates an
external blob reference and its unprotected refcount. This is a new storage
tier and encoding, not a wrapper around the existing blob APIs. It requires
an explicit architecture decision before implementation because the current
contract describes a payload reference rather than an inline wire format.

1. `put_binary_user` accepts an active, scoped publisher, a validated
   `QIHSE_ANALYSIS_BINARY` manifest, and a bounded stream. Reject all derived
   kinds. Recheck publisher authority immediately before commit.
2. Create one private temporary file under the artifact store directory.
   Write a versioned canonical header (never raw C struct bytes) and stream
   payload to it while checking the exact 64 MiB ceiling, declared size and
   SHA-384. `fsync` the file. No public read sees this temporary name.
3. Use an atomic no-replace publish keyed by the canonical artifact ID
   (`linkat` or equivalent). If the ID exists, open and verify the *entire*
   existing file, its canonical manifest and payload digest; exact equality
   is an idempotent retry, any mismatch is a hard conflict. Never overwrite.
4. Remove the temporary name and `fsync` the containing directory before
   returning success. On a process crash, a final name is either absent or
   points to a fully fsynced file; a surviving final file is verified on
   retry/read. Startup may remove only owned temporary names, never a
   published final file. Failed calls may leave an orphan temporary file,
   but never a visible partial artifact or positive ACK.
5. `get_binary_user` takes an explicit live `qihse_user_t`, opens the
   immutable final file with symlink protection, decodes and validates the
   canonical header, checks tenant/clearance/SCI **before returning any
   metadata**, verifies the complete payload digest through that same file
   descriptor, rechecks authorization, then serves bounded ranges. `NULL`,
   low-clearance, foreign tenant and missing SCI must all fail without
   returning metadata or payload. There is no public delete API for this
   initial immutable store.
6. KEYSTONE publication is a separate, durable after-commit outbox problem.
   A successful artifact put must not imply feed delivery, and no feed is
   emitted before the artifact commit has survived directory `fsync`.

This design avoids the present global payload-hash binding collision: two
different tenant-bound manifests may contain the same bytes under distinct
artifact IDs. It intentionally duplicates bytes. If the suite instead
requires physical deduplication through the blob tier, first add a binding-
aware blob key, a store-owned protected pin not decrementable through public
ref/delete calls, unpublished prepare handles, and a durable coordinator
journal with replay. That is a larger cross-store transaction project.

## Acceptance gates before any durable claim

- Canonical encoder/decoder round-trip against a cross-language byte vector;
  reject unknown versions, trailing bytes, malformed lengths and padding.
- Duplicate exact ID is idempotent after restart; same ID with different
  bytes/binding is refused; equal payload bytes across tenants are isolated.
- Fault injection after temp creation, partial payload write, file `fsync`,
  atomic publish, and directory `fsync`, followed by restart and retry.
  Assert no false success and no visible partial artifact at each point.
- Low-clearance/high-data, foreign tenant, missing SCI, `NULL`, Guest,
  unscoped publisher, and revoked principal negative tests for put, direct-ID
  metadata lookup and every payload range/read/export entry point; assert
  output buffers remain untouched on denial.
- Corrupt a committed header and payload independently; reads fail closed
  before yielding bytes. Exercise 64 MiB boundary and concurrent same-ID
  writers; use ASan/UBSan and a concurrency/fault-injection harness.
- Keep derived artifact publication and KEYSTONE feed delivery disabled
  until authenticated input-manifest pinning and a durable outbox are proved.
