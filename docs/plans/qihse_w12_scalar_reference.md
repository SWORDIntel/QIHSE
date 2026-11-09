# W12.1 experimental scalar reference

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Status: **standalone research implementation, not promoted** (2026-10-22).
W12.0's full-engine/corpus/comparator gate remains open. This increment pins a
numerical reference while that baseline work continues; it does not enable an
index, search mode, protocol, sidecar, SIMD/GPU path, or AIMEM adapter. Existing
FP32 authority, query-mode values, public engine ABI and disk formats are unchanged.

## Build boundary

`quantization/include/qihse_turboquant.h` and its two C implementations operate
only on caller-owned numeric arrays. They have no database handles, row IDs,
classification metadata, file I/O or global mutable state. They are **not linked
into `libqihse`**. Their API and byte envelope are explicitly experimental, not a
new stable engine ABI or a durable sidecar format.

```sh
make -f quantization/w12.mk test-w12-turboquant
ASAN_OPTIONS=detect_leaks=0 make -f quantization/w12.mk test-w12-turboquant-sanitize
make -f quantization/w12.mk test-w12-turboquant-profile-max
# Optional GNU-linker allocation failure checks, also ASan+UBSan:
ASAN_OPTIONS=detect_leaks=0 make -f quantization/w12.mk test-w12-turboquant-alloc
# Expensive dense-QR checks through d=1536, excluded from the default suite:
make -f quantization/w12.mk test-w12-turboquant-large
```

The normal `make test` also includes the lightweight numerical suite. Sanitizer
coverage is ASan+UBSan; this execution environment rejects LeakSanitizer under
ptrace, so leak detection is not claimed. Strict C99 warnings are errors. No CPU
ISA flag, BLAS, GPU, Python, trained codebook or external numerical library is
required. These local checks are not a claim that remote CI passed.

A future classified-data adapter must carry authenticated context, restrict its
source universe **before ranking**, reauthorize materialization and pass the
AGENTS low-clearance/high-data negatives. Pure array-codec tests establish none
of those security gates. CRC/fingerprint below are not authorization boundaries.

## Numerical profile v1

Reference source: Zandieh et al., [TurboQuant, ICLR 2026, Algorithms 1–2](https://proceedings.iclr.cc/paper_files/paper/2026/file/5c802ef38ab6e366c2ea06eee554c088-Paper-Conference.pdf).
Implementation and tests were written independently; no reference runtime code
was copied. QIHSE's existing SRSL-1.1 license remains authoritative.

- Dimensions **2..1536**, without hidden padding; scalar widths **1..4** bits.
  `MSE` consumes `k` scalar bits/dimension. `PRODUCT` consumes **k+1 total**
  bits/dimension, including the residual sign bit. Thus scalar width 4 means
  total width 5 for PRODUCT, not a 4-bit corrected code.
- Binary64 Householder QR of a Gaussian matrix, with column signs corrected so
  the corresponding R diagonal is positive, constructs the dense Haar
  reference rotation Pi. The independent residual projection S has Gaussian
  entries, not orthogonal rows. Randomness uses [RFC 8439 ChaCha20 blocks](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3)
  with role-separated nonces and Box–Muller transforms. This is numerical pseudorandomness,
  not cryptographic randomness or a formal proof of iid sampling by a PRNG.
  The public 64-bit seed fills the first two key words; the remaining key words
  are zero. Nonce words are role (0 rotation, 1 projection), `0x54515231`, and
  profile version 1; the block counter starts at zero. This avoids the trivial
  shifted-stream reuse of XOR-tagged additive PRNG states. Randomized experiments
  still choose independent seed streams; no finite PRNG proves mathematical iid.
- The dimension-aware scalar table uses the spherical marginal proportional to
  `(1-t*t)^((d-3)/2)` on `[-1,1]`. `spherical-lloyd-max-f64-v1` uses symmetric
  Lloyd updates, analytic first moments and adaptive generated 8/16-point
  Gauss–Legendre mass integrals in `sqrt(d)*asin(t)`. d=2 handles the arcsine
  endpoints analytically; d=3 is exactly uniform. Numerical failure or bounded
  nonconvergence returns an error, never a silently substituted Gaussian table.
- Norms, normalized input, residuals, matrices, centroids, decoded output and
  scores use binary64. Inputs remain finite binary32. This preserves norms for
  FP32 subnormals and avoids FP32 overflow for large finite inputs. Reconstructed
  vectors are **not renormalized**. Decoded values may exceed FP32 range and
  deliberately remain binary64.
- Exact scalar ties choose the lower index. A zero projection sign is encoded
  as +1. A zero input has an exact zero reconstruction and dot/cosine score; residual correction
  is skipped only for exactly zero residual norm, never an epsilon cutoff.

For `rho=||x||`, `u=x/rho`, `z=Pi*u`, nearest centroids `c`, coarse reconstruction
`uhat=Pi^T*c`, residual `r=u-uhat`, `gamma=||r||`, and `s=sign(S*r)`, the direct
PRODUCT dot estimate is:

```
rho * [ (Pi*q) dot c + gamma*sqrt(pi/2)/d * (S*q) dot s ]
```

The decoder uses the corresponding transposed-matrix reconstruction. MSE omits
the correction. Prepared queries calculate `Pi*q` and `S*q` once; direct-code
scoring thereafter is O(d). Cosine divides by the **original** norms, returning
zero if either norm is zero. The L2 API returns the raw estimated **squared**
distance `rho*rho + ||q||^2 - 2*estimated_dot`, not distance and not the engine's
`1/(1+distance)` similarity. Estimates are intentionally unclamped: corrected
cosine can exceed [-1,1], and corrected L2 squared can be negative. An eventual
engine adapter must define final metric conversion separately.

No Hadamard/fast-transform equivalence is claimed. The paper's Appendix E shortcut
does not establish the exact spherical/Gaussian premises of this reference.

## Reproducibility and byte contract

Same seeds/configuration and the **same generator, compiler, floating-point
profile and libm** reproduce matrices, tables and code bytes. Cross-libm,
cross-architecture or cross-build bit identity from seed regeneration is **not**
promised. Fingerprints include exact rounded matrices/tables and configuration;
mismatching profiles are rejected rather than silently rescored. The standalone
profile envelope below preserves those exact binary64 values across reopen,
without rerunning QR or centroid generation. Cross-architecture decode and score
behavior has not yet been tested. Crash-safe publication remains future work.

The exact-size envelope is little-endian. Floats use IEEE binary64 bit patterns;
all integer and floating fields are loaded without alignment assumptions.

| Byte offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `QTQR` magic |
| 4 | 2 | Reference/envelope version 1 |
| 6 | 1 | Variant: 0 MSE, 1 PRODUCT |
| 7 | 1 | Scalar bits k, not PRODUCT total bits |
| 8 | 4 | Dimensions |
| 12 | 4 | Dimension-aware table algorithm version |
| 16 | 8 | Rotation seed |
| 24 | 8 | Projection seed (zero for MSE) |
| 32 | 8 | FNV-1a profile fingerprint |
| 40 | 8 | Original norm rho |
| 48 | 8 | Normalized residual norm gamma (zero for MSE) |
| 56 | 4 | Exact packed-payload byte length |
| 60 | 4 | CRC-32/ISO-HDLC over bytes 0..59 and payload |
| 64 | variable | Scalar indices, followed by PRODUCT residual signs |

Scalar index j starts at bit `j*k`, least-significant-bit first; residual sign j
starts at bit j in its separate byte stream, with 1 denoting +1. Both streams'
unused high bits must be zero. Truncation, trailing bytes, mismatched version,
configuration/seed/profile/length/checksum, nonfinite or negative norms (including
negative zero), impossible norm bounds, and noncanonical zero payloads fail
closed. Norm upper bounds include a conservative FP64 rounding allowance so
legitimate all-FLT_MAX inputs remain decodable. Failed calls leave output buffers
unchanged; constructor outputs become NULL. Errors are returned errno values,
not ambient errno. Callers must propagate failures and own object lifetimes.

**CRC-32 and FNV-1a are noncryptographic.** They detect accidental corruption or
profile mismatch; a malicious sender can forge them. This format is not a
secure transport, classified-data retrieval primitive or authenticated sidecar.

### Standalone exact-profile envelope

`qihse_tq_profile_serialized_size`, `qihse_tq_profile_serialize` and
`qihse_tq_profile_deserialize` operate on caller-owned bytes. The byte layout is
little-endian, exact-length, and capped at 37,748,928 bytes (PRODUCT, d=1536).
It is distinct from the per-vector `QTQR` envelope above:

| Byte offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `QTQP` magic |
| 4 | 4 | Profile envelope version 1 |
| 8 | 4 | Dimensions |
| 12 | 4 | Scalar bits |
| 16 | 4 | Variant |
| 20 | 4 | Dimension-aware table version |
| 24 | 8 | Rotation seed |
| 32 | 8 | Projection seed |
| 40 | 8 | Exact-profile fingerprint |
| 48 | 4 | Payload bytes |
| 52 | 4 | Centroid count |
| 56 | 4 | Reserved, zero |
| 60 | 4 | CRC-32/ISO-HDLC over the envelope, excluding this field |
| 64 | variable | Row-major rotation, optional projection, then centroids as binary64 |

The loader rejects wrong versions, lengths, checksum, nonfinite values,
nonmonotone or asymmetric centroids, row/column norm failures, failed fixed
orthogonality probes and fingerprint mismatches. Nine deterministic matrix-vector
probes bound numerical validation to O(d^2); they are a corruption check, not
a proof that an adversarial matrix is Haar-distributed or even fully orthogonal.
The independent projection cannot be proven Gaussian from stored values. CRC and fingerprint are not
authentication; this envelope has no row IDs, source generation or ACLs and
must not be used as the W12.2 sidecar.
The optional max-profile test constructs a checksum-valid 1536D PRODUCT envelope
with exact bounded length and a deliberately wrong profile fingerprint. It
forces the full numeric validation and hash path before rejection and prints
process CPU time. This is a worst-shape malformed-input check, not a throughput
claim for an authenticated production loader.

## Cost accounting

This intentionally slow golden reference performs O(d^3) QR setup and O(d^2)
encode, query preparation and decode. Per-vector setup must not be described as
free or as a production speedup. Rotation/table are shared by profile; PRODUCT
adds one shared projection matrix, never a matrix per vector.

- MSE packed payload: `ceil(k*d/8)` bytes.
- PRODUCT packed payload: `ceil(k*d/8) + ceil(d/8)` bytes.
- Actual current code: **64-byte envelope plus packed payload**, including both
  norm slots even for MSE. No hypothetical compact payload ratio is reported as
  the implemented allocation.
- Shared dense matrix storage: `8*d*d` bytes for MSE, `16*d*d` for PRODUCT.
  PRODUCT at d=1536 uses **37,748,736 bytes (36 MiB)** for matrices alone, plus
  profile/table metadata. QR setup also temporarily holds another dense matrix
  and two d-element work arrays. Query state and encode/decode scratch are extra.
- Existing authoritative FP32 vectors, row IDs, ACLs, generations, graph edges,
  allocator/alignment overhead and any future durable profile are additional.
  Retaining FP32 plus a candidate sidecar increases total storage unless some
  other resident representation is demonstrably displaced.

No whole-store RAM reduction, corpus recall, throughput improvement or latency
promotion target is claimed by these numerical tests.

## Validation and remaining gates

The source tests independently check table stationarity/reference values,
rotation orthogonality/distribution, bit packing, exact envelope bounds,
malformed semantic fields with recomputed checksums, extreme FP32 norms,
same-build reconstruction and direct-code versus decoded dot products.

The RFC block known-answer test pins the generator. Separate regressions retain
the previously problematic exact-overlap/shifted SplitMix seed families; the
ChaCha nonce-separated profile has no significant bias in those tests. Optional
allocation-failure tests check every constructor/scratch-allocation failure and
allocation-free direct scoring; tracked wrapper allocations return to zero.
The large-dimension test covers 128/384/768/1536 with all-FLT_MAX, subnormal and
ordinary inputs, including direct-code/decoded-dot parity. Its printed setup
times are single CPU-time observations, not latency distributions.

Conditional QJL tests hold rotation, residual and query fixed and resample only
independent projection seeds. They test self, negative-self, orthogonal and
sparse queries. With normalized residual r, the reference variance is:

```
rho^2/d * [ (pi/2)*gamma^2*||q||^2 - (q dot r)^2 ]
```

Acceptance uses sampling uncertainty, not repeated scoring of one fixed code or
many correlated rows under one projection. These deterministic statistical
regressions can detect common distribution/scaling/residual mistakes but cannot
prove the asymptotic theorem or universal corpus quality.

Remaining before W12.1 promotion: crash-safe exact-profile persistence,
additional compiler/architecture validation, longer fuzz campaigns, measured
setup/encode/score costs at representative full dimensions, and satisfaction of
the W12.0 corpus/comparator prerequisites. W12.2 durability, W12.3 authorization
and engine integration, optional acceleration and end-to-end performance gates
remain separate and unfulfilled.
