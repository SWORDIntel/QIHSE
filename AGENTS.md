# QIHSE Repository Rules

These rules are architectural invariants, not suggestions. A code path that violates them is incorrect even if the feature works, benchmarks well, or existing tests pass. Existing violations are defects and must not be copied into new code.

## Security invariants

### 1. No classified read primitive without a user/security context

Any primitive capable of materializing, enumerating, searching, streaming, exporting, serializing, snapshotting, backing up, iterating over, or otherwise disclosing data that may carry classification or SCI metadata MUST accept or inherit an explicit authenticated security context (`qihse_user_t *` or an equivalent typed context).

Protocol, SDK, compatibility, export, backup, iterator, and internal adapter layers MUST propagate that identity to the lowest data-retrieval layer. They MUST NOT fall back to a context-free/raw read primitive for classified-capable data.

`NULL` MUST NOT accidentally become an authorization bypass. If QIHSE supports an explicitly security-disabled operating mode, that mode must be represented deliberately in configuration/context state rather than inferred from a forgotten user argument.

### 2. No principal may create or modify a principal above itself

A principal MUST NOT create, promote, or modify another principal to a privilege level greater than its own.

This applies to role, classification level, SCI compartments, account-management capability, authentication bypasses, hardware-token policy, delegated user-creation capability, and any future privilege-bearing field.

`can_create_users` delegates account creation only. It does not delegate Operator authority and MUST NOT permit creation or promotion of a principal above the creator.

### 3. Every new protocol adapter requires a low-clearance/high-data negative test

Every new protocol, wire-format adapter, compatibility layer, or externally reachable data-access surface MUST include an automated negative authorization test before merge.

The test MUST authenticate or construct a low-clearance principal, place or reference data above that principal's clearance and/or outside its SCI compartments, attempt access through the new adapter, and assert denial with no protected payload disclosure.

Where the adapter exposes them, the test SHOULD cover both the normal query path and bypass-prone forms such as direct-ID lookup, enumeration, export, bulk read, snapshot/backup, iterator, or raw compatibility commands.

The negative test MUST run in CI. A successful happy-path test is not a substitute.

## Merge rule

Changes that violate any invariant above are merge blockers. Performance, compatibility, internal-only deployment, prototype status, or convenience are not exceptions. If a new capability cannot preserve an invariant yet, keep it behind an explicitly insecure/development-only boundary rather than weakening the invariant silently.

<!-- START: RELATIVE_PATHS_RULE -->
## Path Resolution Policy
> **CRITICAL RULE**: Never use absolute paths (e.g. `/home/...`, `/fast/home/...`).
> All paths must be strictly relative or dynamically resolved across all projects, configurations, code, scripts, subagents, and tools.
> Use relative paths (`./`, `../`), `PROJECT_ROOT`, `$(dirname ...)`, `Path(__file__)`, or dynamic environment variables with relative fallbacks.
<!-- END: RELATIVE_PATHS_RULE -->

## Federation record decoders: bounded stack frames

Post-quantum keys and signatures are large (an ML-DSA-87 public key is 2592
bytes and its signature 4627), so a decoder that keeps one buffer per record
column can allocate an enormous stack frame. A `char f[14][5200]` is ~73 KB and
a `char f[11][9256]` is ~102 KB — both were real, and both sat on the
cluster-bus thread call path, which makes a malformed record a cheap
denial-of-service surface.

Rules for any decoder that reads a variable-length or hex-encoded field:

1. Use ONE reusable heap buffer sized for the largest single field, not one
   array element per column.
2. Prefer an explicit `goto done` with a single `free`, so no early return can
   leak the buffer.
3. When a record has a variable-length field, validate the declared length
   against BOTH the encoded length and the algorithm's fixed size.
4. When a record carries a fingerprint, recompute it and compare — do not
   trust the stored value to describe the stored key.
5. An encoder that can fail must return `bool` and its callers must propagate
   the failure. Returning silently leaves the output buffer uninitialised and
   the caller stores garbage as a durable record.

Check the worst frames after touching a decoder:

```
gcc -std=c99 -D_GNU_SOURCE -fstack-usage -I. -I./include -I./core \
    -c -o /tmp/x.o src/federation/qihse_federation.c
sort -t$'\t' -k2 -rn /tmp/qihse_federation.su | head
```

Anything above ~16 KB in a record decoder deserves a second look.
