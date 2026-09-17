# SBOM and Attestation Records

> **Status: implemented** — SBOM immutability, artifact lookup, and the
> separation of vulnerability observations are verified by
> `tests/test_federation_f6.c`.

QIHSE stores normalized supply-chain evidence. It does not hold private
signing keys.

## Stored fields

```c
typedef struct {
    qihse_uuid_t sbom_id;
    char artifact_digest[129];
    char sbom_digest[129];
    char provenance_digest[129];
    char signing_identity[128];
    char signature_algorithm[64];
    char signature[512];
    char signing_key_handle[160];   /* a handle, never the key */
    uint64_t signature_hlc_physical;
    uint64_t policy_generation;
    char verification_status[32];
    char format[32];                /* spdx | cyclonedx | internal */
} qihse_sbom_record_t;
```

## Key material

`signing_key_handle` is a filesystem or external reference. **No private
signing key is required inside the QIHSE process**, and none is stored in a
record. This is acceptance criterion 17.

## Immutability

`qihse_sbom_record_put()` refuses a second record for the same `sbom_id`, so
historical signed evidence is never rewritten. This is acceptance criterion 20.

## Query

`qihse_sbom_find_by_artifact()` returns every SBOM describing a given artifact
digest, so an artifact can be traced to its evidence without scanning by hand.

## Vulnerability observations are separate

Vulnerability information is modelled as its own append-only entity:

```
observation_id, scanner, component, component_digest, advisory_id,
severity, status, evidence, observed_hlc_physical
```

Recording a new observation never touches a historical SBOM. That separation is
what permits:

```
same signed SBOM  +  multiple vulnerability observations over time
```

and preserves forensic integrity. The test suite asserts directly that the SBOM
is byte-for-byte unchanged after an observation is recorded against it.

## External formats

SPDX, CycloneDX and in-toto/SLSA are export and interoperability
representations. The internal model is not constrained to the lowest common
denominator of any one of them — `format` records which representation a given
record was derived from, nothing more.
