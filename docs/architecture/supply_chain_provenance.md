# Supply-Chain Provenance Graph

> **Status: implemented** — the provenance graph, direction-aware traversal,
> trace-back and reverse-impact queries are verified by
> `tests/test_federation_f6.c`.

QIHSE is the authoritative provenance graph for Citadel software artifacts.

## Entity types

```
SOURCE_REPOSITORY  SOURCE_REVISION  SOURCE_ARCHIVE  PATCHSET
BUILD_RECIPE  BUILD_PROFILE  TOOLCHAIN  BUILD_DEPENDENCY
BUILDER_NODE  BUILD_WORKER_IMAGE  BUILD_JOB  TEST_RESULT
OUTPUT_ARTIFACT  DEB_PACKAGE  SBOM  ATTESTATION
APT_REPOSITORY_SNAPSHOT  ROOT_IMAGE  DEPLOYMENT  NODE
VULNERABILITY_OBSERVATION
```

Artifact-bearing entities use a cryptographic digest as their stable identity.

## Edge types

```
DERIVED_FROM  PATCHED_BY  BUILT_WITH  BUILD_DEPENDS_ON  BUILT_ON  BUILT_IN
PRODUCES  DESCRIBED_BY  ATTESTED_BY  PUBLISHED_IN  CONTAINED_IN
DEPLOYED_TO  AFFECTED_BY  SUPERSEDES  VERIFIED_AGAINST
```

## Direction is a property of the edge, not of storage

An edge's *meaning* determines the direction of data flow. `from --DERIVED_FROM--> to`
puts `to` **upstream** of `from`, while `from --PUBLISHED_IN--> to` puts `to`
**downstream**. Getting this wrong makes provenance queries silently return
nothing, so the direction is declared per edge type and both indexes are
consulted.

Storage is doubly indexed — `provedge:<from>...` and `provedge:rev:<to>...` —
so a traversal in either direction is a prefix scan.

## Trace-back (criterion 15)

`qihse_provenance_trace_reverse()` walks upstream. From a deployed `.deb` it
reaches the output artifact, the build job, the builder node, the build recipe,
the toolchain, the worker image, the patchset and finally the source revision.

## Reverse impact (criterion 21)

`qihse_provenance_reverse_impact()` answers "which deployed nodes are affected
by this vulnerability": it walks downstream from the vulnerability through the
affected artifact, package, repository snapshot, root image and deployment to
the nodes.

## Immutability

`SBOM`, `ATTESTATION` and snapshot nodes are marked immutable. An immutable
node cannot be overwritten or deleted, so historical signed evidence is never
rewritten because vulnerability intelligence changed.

## KEYSTONE

Records are plain KV entries readable with `FEDERATION_READ` alone, so the
KEYSTONE indexer can consume them without ever holding write authority. QIHSE
stays authoritative.
