# HAX document identity and citation contract

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Status: design for QH-HAX-04. This document does not add an AIMEM document
adapter or authorize live writes. The HAX integration must satisfy the tests
below before enabling document-backed answers.

## Decision

Use existing AIMEM records for extracted, attributable facts, not for document
chunks or source excerpts. A scoped AIMEM hit has a memory UUID, text, labels,
and a score; a knowledge version can cite AIMEM lifecycle event UUIDs. Neither
record identifies a repository document revision, chunk, byte range, or source
URL. Treating a memory UUID as a document citation would make stale or deleted
source material appear current. The separate QIHSE document store does not
supply this contract: its authenticated versions are in memory and disappear
when that store is destroyed.

HAX and KEYSTONE remain responsible for selecting and navigating repository
and document sources. HAX resolves a citation through its authenticated
source tool at answer time, then combines the returned excerpt with AIMEM
facts. QIHSE remains responsible for authorized, scoped AIMEM records and
their event/version lineage. An AIMEM source event ID proves which authorized
memory event supported a knowledge version; it does not prove the continued
existence or current content of an external document.

## Citation identity for the HAX-owned source path

Every document citation passed between HAX retrieval and answer assembly must
carry these typed fields:

| Field | Meaning |
| --- | --- |
| `source_system` | Fixed, registered repository or document provider name. |
| `source_id` | Opaque stable identity within that provider; never a display title or path alone. |
| `revision_id` | Immutable provider revision or content digest for the cited bytes. |
| `chunk_id` | Stable identifier within that revision. |
| `range` | Bounded byte or line span in the revision, with an explicit coordinate type. |
| `source_link` | Provider-generated link to that exact revision and range, after authorization. |
| `scope` | Canonical project, worktree, workstream, and session coordinates used for retrieval. |

The tuple `(source_system, source_id, revision_id, chunk_id, range)` is the
citation identity. A path may be displayed, but it is not identity. A changed
file creates a new revision and new chunk lineage; a chunk may refer to its
predecessor, but never silently reuse its old identity for different bytes.
The provider must define how revisions survive rename, move, and reindex.
HAX must reject a citation with an unknown provider, missing revision, invalid
range, or source link that does not resolve to the authenticated revision.
Identifiers and excerpts need documented length bounds before a wire adapter
is added. No citation identity may contain a local QIHSE storage path.

## Retrieval and staleness

HAX must ask the source provider for the exact cited revision and range under
the current authenticated principal. It must not use an earlier successful
authorization as a cacheable grant. If the exact revision is unavailable,
deleted, or no longer readable, the citation is stale/unavailable and HAX must
not present its excerpt as current evidence. A newer revision may be offered
as a separate result with its own identity, never substituted under the old
citation. Removing a source invalidates current retrieval; retained historical
revisions remain available only if the provider explicitly retains them and
the principal still has access. HAX must not infer source visibility from an
AIMEM project grant, and it must not infer AIMEM visibility from source access.

For each answer, HAX resolves all source citations and rechecks AIMEM facts
through the authenticated AIMEM API. Both paths must enforce tenant, project,
classification, SCI, and revocation rules at their own lowest retrieval layer.
Search must apply scope and authorization before corpus statistics, candidate
ranking, and top-K; direct-ID and pagination must reauthorize before returning
content. A denied or stale citation returns no protected excerpt, link, title,
or hidden-result count.

## When a QIHSE document API becomes necessary

Add a QIHSE document/chunk API only if HAX needs QIHSE itself to durably store
and serve excerpts. That API must first define immutable source/revision/chunk
records, a deletion tombstone and historical retention policy, bounded content
and links, authenticated writes and reads, principal-bound retries, and exact
scope/label enforcement. Every classified-capable operation, including search,
direct-ID lookup, enumeration, export, and pagination, must take or inherit an
explicit authenticated `qihse_user_t` or equivalent typed context. A missing
principal must fail closed. The QIHSE service must not open HAX repository
paths or rely on a client-supplied clearance claim. This design does not make
the existing document store or AIMEM memory record such an API.

## Required fixture gates

1. In a fixed authorized fixture, preserve source identity, revision, chunk,
   and range from retrieval through answer citation. Rename/reindex must not
   change identity; modified bytes must produce a new revision.
2. Change and delete cited sources between search and exact retrieval. Assert
   that the old citation is marked stale/unavailable and no old excerpt is
   silently replaced by a new revision.
3. Give a low-clearance principal project membership, then attempt search,
   direct-ID lookup, enumeration/pagination, and source-link resolution for a
   high-classification document. Repeat with sufficient classification but a
   missing SCI compartment, and with a foreign tenant. Assert denial and no
   protected payload, title, link, count, or ranking influence.
4. Revoke project/source access between pages and between candidate search and
   exact retrieval. Assert that subsequent pages and citation resolution omit
   protected material.
5. Run the same authorized corpus through BM25, semantic, and hybrid recall.
   Report p50/p95 latency and exact citation identity/correctness for each mode;
   do not enable a slower mode by default without measured benefit.

If HAX adds a new wire adapter, its low-clearance/high-data negative test must
run in CI before merge. Fixtures must use synthetic data, not the live AIMEM
backlog or QIHSE storage files.
