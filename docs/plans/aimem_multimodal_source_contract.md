# AIMEM multimodal source contract

Status: design for staged implementation. This contract covers QIHSE storage and
retrieval of binary source documents and their searchable text chunks. It does
not enable OCR, transcription, or embedding by itself.

## Goals and boundaries

HAX needs to retain a durable connection between a retrieved text chunk and the
document bytes from which it was derived. A source citation must identify the
tenant-bound original, its immutable content revision, the extractor version,
and a stable location within the extracted text. Every operation that can
materialize bytes or chunk text carries an authenticated `qihse_user_t *`.
Missing or revoked principals fail closed.

The existing QHK3 tuple `(source-system, source-id, revision-id, line-start,
line-end)` is sufficient for text files, but is not a safe general locator for
binary documents. Do not overload line numbers with byte offsets, page numbers,
timestamps, or chunk indexes. Keep QHK3 readable and add a versioned typed
locator for multimodal sources.

## Storage model

1. Store original bytes in the content-addressed blob tier using a dedicated
   `QIHSE_BLOB_TAG_AIMEM_SOURCE` binding. The blob index already binds the
   content SHA-384 to tenant, classification, SCI, and tag, and its read/write
   APIs require an authenticated user. Set an AIMEM source size limit below the
   generic 64 MiB blob ceiling (initial proposal: 32 MiB); do not use the 4 GiB
   dump-artifact limit for user documents.
2. Store extracted text as bounded immutable AIMEM chunks. Each chunk records
   the original blob SHA-384, source revision, extractor name/version,
   zero-based chunk ordinal, byte range in the normalized UTF-8 extraction,
   optional page/time locator, and chunk SHA-384. Chunk text remains classified
   AIMEM content and is authorized before ranking, counting, walking, or return.
3. Store a source manifest with the tenant/project scope, original blob hash,
   MIME type, byte length, extraction revision, chunk count, total extracted
   bytes, and extractor metadata. The manifest does not contain the source
   payload itself.

Deduplication is tenant- and binding-aware. A matching hash with a different
tenant, classification, SCI, or AIMEM source tag must not reveal existence or
increment a reference count.

## API shape

Add typed operations rather than a raw blob-to-memory shortcut:

- `AIMEM SOURCE BEGIN <scope> <mime> <declared-size> <declared-sha384>` creates
  a bounded upload session and returns an opaque upload ID. It binds the
  session to the authenticated principal and scope.
- `AIMEM SOURCE APPEND <upload-id> <offset> <bytes>` accepts strictly
  sequential, bounded chunks. Replays of the same offset and bytes are
  idempotent; conflicting offsets fail.
- `AIMEM SOURCE COMMIT <upload-id>` verifies final length and SHA-384, stores
  the blob, then atomically publishes the source manifest and a durable
  receipt. A crash before publication leaves no visible source; orphan blobs
  are reclaimed by reference-aware GC.
- `AIMEM SOURCE GET <source-id> <offset> <length>` performs an authorized
  range read capped to `QIHSE_BLOB_CHUNK_SIZE`; every request rechecks current
  principal, tenant, classification, and SCI.
- `AIMEM SOURCE CHUNKS <source-id> <revision> <cursor> <limit>` returns only
  authorized chunk metadata/text, with a small hard limit (initial proposal:
  at most 32 chunks or 64 KiB text per response).
- `AIMEM SOURCE DELETE <source-id> <expected-revision> <idempotency-key>`
  tombstones the manifest and chunks with a durable receipt, then releases the
  blob pin. It never deletes another source sharing a blob reference.

Extraction is a separate trusted worker boundary. The worker receives a
scoped, short-lived source handle and emits bounded UTF-8 chunks with the
extractor/version and source locators. The server validates size, UTF-8,
chunk-count, ordering, digest, and scope before making chunks queryable. A
worker must not receive an unscoped raw blob API.

## Atomicity and recovery

The blob object and AIMEM KV state use separate durable stores, so publication
must use an explicit staged protocol:

1. Persist an authenticated upload intent with principal ID, scope, declared
   size/hash, upload ID, and expiry.
2. Stream and verify bytes into a tenant-bound immutable blob. Pin the blob.
3. In one AIMEM KV transaction, write the manifest, extraction chunks, and
   committed receipt.
4. On restart, reconcile intents: complete only when the blob binding/hash and
   staged metadata match; otherwise leave the source invisible and release the
   pin after an auditable abort receipt.
5. Delete is the inverse: atomically tombstone manifest/chunks and write the
   receipt, then unpin. Repeating the same idempotency key returns the same
   receipt.

No query may expose a source until the commit receipt is durable. No garbage
collector may remove a blob while a committed source manifest pins it.

## Required authorization tests

CI must include low-clearance/high-data and wrong-SCI fixtures for upload
commit, manifest lookup, range read, chunk enumeration, query/ranking,
knowledge walk, delete, retry receipt, and export/backup paths. Denial tests
must assert both an error/empty result and zero protected bytes or metadata in
the response. Also test cross-tenant hash collision/binding, revoked principal
between range requests, oversized declared and streamed inputs, offset replay
conflict, bad final digest, truncated upload, crash at each publication step,
orphan/pin recovery, and idempotent delete/retry.

## Rollout sequence

1. Add the typed locator schema and blob tag/manifest primitives with isolated
   authorization tests. Keep QHK3 text citations readable.
2. Add bounded upload, commit, range-read, and delete operations with crash
   recovery tests.
3. Add one extraction worker adapter at a time (PDF text first; OCR/audio later)
   and verify source locators against the original revision.
4. Add chunk-aware QUERY filters and citation rendering in HAX; prove the
   source hash and locator before displaying a citation.
5. Run the complete QIHSE suite and HAX suite, then verify against the intended
   migrated live authority. Do not restart or replace the current volatile
   authority without a supported lossless migration path.

## Limits

The initial contract stores original bytes and extracted text, not derived
embeddings. Embeddings are optional indexes and must be rebuildable from the
authorized chunks. The initial PDF/OCR/audio adapters remain deferred until the
source storage and typed locator contract is implemented and tested.
