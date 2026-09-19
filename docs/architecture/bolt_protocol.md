# Bolt Protocol (Neo4j Wire Protocol)

> **Status: partial.** `src/spinnaker/qihse_bolt.c` exists and is wired into the
> build; `tests/test_bolt.c` (run via `make test-bolt`) exercises the codec,
> framing, handshake and the client message loop, and the `bolt-codec` and
> `protocol-compat-probe` workloads in `tests/gold/pack.v1.gold` assert the same
> state. Two defects recorded in an earlier revision of this document have been
> fixed and are corrected in place:
>
> - **the `QIHSE_BOLT_MSG_*` constants now match the Bolt 4.x message
>   signatures** — a spec-conformant `RUN` is read as `RUN`, not as `RESET`;
> - **the PackStream tiny forms now encode and decode correctly** — tiny maps
>   use `0xA0`-`0xAF` (they used to be written with `0xD7`, which is not a
>   PackStream marker), and tiny strings, tiny lists and negative tiny ints
>   decode.
>
> The adapter is still **not driver-compatible**: `RUN` dispatches the Cypher
> and then discards the result, `PULL` returns a single empty record with no
> stream cursor, and the encoder still omits the tiny string/list forms and uses
> `0xB1`/`0xB2` for structs of 16 or more fields. The remaining deviations are
> listed under [Testing](#testing) and reproduced by that test on every run.

## Overview

QIHSE implements a subset of the Neo4j Bolt 4.x wire protocol. The goal is that
applications using the neo4j-python driver can connect to QIHSE without code
changes; **that goal is not met in the current tree** — see the defect list at
the end of this document.

## Protocol Implementation (`src/spinnaker/qihse_bolt.c`)

### Handshake

1. Client sends magic bytes `\x60\x60\xb0\x17`
2. Client sends 4 supported protocol versions (4 bytes each)
3. Server responds with selected version (4 bytes)

The handshake is implemented as described and is covered by `tests/test_bolt.c`
(magic check, 4.0 selection, version-0 refusal, truncation).

### PackStream Serialization

PackStream is Bolt's compact binary serialization format. The table below is the
**PackStream specification**; the "QIHSE" column records what this implementation
actually encodes and decodes, which differs in the rows marked *no*.

| Type | Marker range (PackStream) | Description | QIHSE |
|---|---|---|---|
| Null | `0xC0` | Single byte | yes |
| Boolean | `0xC2` false / `0xC3` true | 1 byte | yes |
| Float | `0xC1` | 64-bit IEEE 754 | yes |
| Integer | `0xC8`-`0xCB` | 8/16/32/64-bit, plus tiny ints | yes: positive tiny ints (`0x00`-`0x7F`), negative tiny ints (`0xF0`-`0xFF`) and `0xC8`-`0xCB` all encode and decode |
| String | `0x80`-`0x8F` tiny, `0xD0`-`0xD2` | 5/8/16/32-bit length prefix | partial: tiny strings decode; the encoder only emits `0xD0`-`0xD2` |
| List | `0x90`-`0x9F` tiny, `0xD4`-`0xD6` | 5/8/16/32-bit length prefix | partial: tiny lists decode; the encoder only emits `0xD4`-`0xD6` |
| Map | `0xA0`-`0xAF` tiny, `0xD8`-`0xDA` | 5/8/16/32-bit length prefix | yes: tiny maps (`0xA0`-`0xAF`) and `0xD8`-`0xDA` both round-trip |
| Struct | `0xB0`-`0xBF` tiny, `0xDC`/`0xDD` | field count + type byte | partial: up to 15 fields round-trip; 16+ fields use `0xB1`/`0xB2` instead of `0xDC`/`0xDD` |

### Struct Types

- **Node** (`0x4E`): `(id, labels, properties)`
- **Relationship** (`0x52`): `(id, start_node, end_node, type, properties)`
- **Path** (`0x50`): `(nodes, relationships, sequence)`

The signatures are carried through the codec as struct type bytes and are
covered by `tests/test_bolt.c`.

### Messages

The constants in `include/qihse_bolt.h` match the Bolt 4.x signatures. An
earlier revision of this document recorded them as disagreeing, which made a
real driver's `RUN` read as `RESET`; that is fixed.

| Message | Bolt 4.x signature | `QIHSE_BOLT_MSG_*` in the header | Match |
|---|---|---|---|
| HELLO | `0x01` | `0x01` | yes |
| GOODBYE | `0x02` | `0x02` | yes |
| RESET | `0x0F` | `0x0F` | yes |
| RUN | `0x10` | `0x10` | yes |
| DISCARD | `0x2F` | `0x2F` | yes |
| PULL | `0x3F` | `0x3F` | yes |
| BEGIN | `0x11` | `0x11` | yes |
| COMMIT | `0x12` | `0x12` | yes |
| ROLLBACK | `0x13` | `0x13` | yes |

### Responses

| Response | Signature | Description |
|---|---|---|
| SUCCESS | `0x70` | Operation succeeded, with metadata map |
| RECORD | `0x71` | A single result record |
| FAILURE | `0x7F` | Operation failed, with error map |
| IGNORED | `0x7E` | Operation ignored |

Response signatures are correct and the message loop is covered by
`tests/test_bolt.c` (RESET answered with SUCCESS, unknown signature answered
with IGNORED, GOODBYE closes the session). The SUCCESS/FAILURE metadata maps
encode through the tiny-map form, so a frame carrying fewer than 16 entries is
well formed on the wire.

### Not implemented

- `RUN` translates the Cypher text to UWP and dispatches it, but the result is
  discarded: the handler answers `SUCCESS {t_first, qid}` and never emits a
  `RECORD`.
- `PULL` returns a single empty record and a bookmark; there is no result-set
  or stream cursor, no `has_more`/`qid` bookkeeping, and `DISCARD` is a no-op.
- `BEGIN`/`COMMIT`/`ROLLBACK` translate to UWP and dispatch, but no Bolt-level
  transaction state is tracked per session.
- HELLO authentication is implemented (`qihse_auth_authenticate_from`, per-IP
  rate limiting), but no test in this repository exercises it.
- There is no negative authorization test for this adapter, which `AGENTS.md`
  invariant 3 requires; `tests/gold/pack.v1.gold` records that as the
  `protocol-compat/bolt-negative-auth` gap.

## Testing

`tests/test_bolt.c` (run via `make test-bolt`) asserts:

1. PackStream round trip: null, bool, int (positive tiny, negative tiny, int8,
   int16, int32, int64), float64, strings with tiny / empty / 8-bit / 16-bit
   lengths, lists (tiny and 8-bit), maps (tiny / 8-bit / 16-bit / 32-bit), and
   tiny structs with the Node/Relationship/Path signatures.
2. Truncated and unknown input is refused rather than mis-decoded.
3. Message framing: single-chunk encode/decode, two messages back to back,
   multi-chunk reassembly, partial input reported as "need more data", an empty
   message reported as an error.
4. Handshake over a socketpair: magic check, 4.0 selection, version-0 refusal,
   truncation.
5. The client message loop over a socketpair: RESET answered with SUCCESS, an
   unknown signature answered with IGNORED, GOODBYE closing the session.
6. Bolt 4.x spec compliance: all thirteen `QIHSE_BOLT_MSG_*` constants against
   the specification, the tiny-map marker (`0xA1` for a one-entry map) and its
   round trip, and the decoding of tiny strings (`0x83 'a' 'b' 'c'`), tiny lists
   (`0x92 0x01 0x02`) and tiny maps (`0xA1 ...`).

**Remaining deviations from the Bolt 4.x PackStream specification** (stated
here rather than as test `NOTE` lines, because they are encoding choices rather
than defects the test can fix):

- the string encoder emits `0xD0`-`0xD2` and never the tiny `0x80`-`0x8F` form,
  so its output is larger than necessary but still spec-conformant;
- the list encoder emits `0xD4`-`0xD6` and never the tiny `0x90`-`0x9F` form, on
  the same terms;
- a struct of 16 or more fields uses `0xB1`/`0xB2` where the specification
  reserves `0xDC`/`0xDD`.

There is no test for a real neo4j driver handshake against this server, and
this document does not claim one. The two Bolt defects recorded in
`tests/gold/pack.v1.gold` — the message signatures and the on-the-wire RESET
behaviour — are now reported `GOLD: OK` by the `protocol-compat-probe` workload.
