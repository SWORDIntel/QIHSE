# Bolt Protocol (Neo4j Wire Protocol)

> **Status: partial.** `src/spinnaker/qihse_bolt.c` exists and is wired into the
> build; `tests/test_bolt.c` now exists and exercises the parts that work. The
> adapter is **not** driver-compatible: the PackStream codec cannot represent
> several value shapes and the message signature constants do not match Bolt
> 4.x, so a stock neo4j driver and this server disagree about what every
> non-HELLO message means. The specific defects are listed under
> [Testing](#testing) and are reproduced by that test on every run.

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
| Integer | `0xC8`-`0xCB` | 8/16/32/64-bit, plus tiny ints | partial: positive tiny ints (`0x00`-`0x7F`) and `0xC8`-`0xCB` work; negative tiny ints (`0xF0`-`0xFF`) are encoded but not decoded |
| String | `0x80`-`0x8F` tiny, `0xD0`-`0xD2` | 5/8/16/32-bit length prefix | partial: the encoder only emits `0xD0`-`0xD2`, which round-trip; tiny strings are not decoded |
| List | `0x90`-`0x9F` tiny, `0xD4`-`0xD6` | 5/8/16/32-bit length prefix | partial: `0xD4`-`0xD6` round-trip; tiny lists are not decoded |
| Map | `0xA0`-`0xAF` tiny, `0xD8`-`0xDA` | 5/8/16/32-bit length prefix | partial: maps of 16 or more entries round-trip; the encoder writes `0xD7 \| count` for smaller maps, which is not a PackStream marker, and the decoder cannot read tiny maps |
| Struct | `0xB0`-`0xBF` tiny, `0xDC`/`0xDD` | field count + type byte | partial: up to 15 fields round-trip; the 16+ forms use `0xB1`/`0xB2` instead of `0xDC`/`0xDD` |

### Struct Types

- **Node** (`0x4E`): `(id, labels, properties)`
- **Relationship** (`0x52`): `(id, start_node, end_node, type, properties)`
- **Path** (`0x50`): `(nodes, relationships, sequence)`

The signatures are carried through the codec as struct type bytes and are
covered by `tests/test_bolt.c`.

### Messages

The constants in `include/qihse_bolt.h` are **not** the Bolt 4.x signatures.
This is the single most consequential defect: a real driver's RUN is read by
this server as RESET.

| Message | Bolt 4.x signature | `QIHSE_BOLT_MSG_*` in the header | Match |
|---|---|---|---|
| HELLO | `0x01` | `0x01` | yes |
| GOODBYE | `0x02` | `0x02` | yes |
| RESET | `0x0F` | `0x10` | no |
| RUN | `0x10` | `0x11` | no |
| DISCARD | `0x2F` | `0x12` | no |
| PULL | `0x3F` | `0x13` | no |
| BEGIN | `0x11` | `0x2F` | no |
| COMMIT | `0x12` | `0x30` | no |
| ROLLBACK | `0x13` | `0x31` | no |

### Responses

| Response | Signature | Description |
|---|---|---|
| SUCCESS | `0x70` | Operation succeeded, with metadata map |
| RECORD | `0x71` | A single result record |
| FAILURE | `0x7F` | Operation failed, with error map |
| IGNORED | `0x7E` | Operation ignored |

Response signatures are correct and the message loop is covered by
`tests/test_bolt.c` (RESET answered with SUCCESS, unknown signature answered
with IGNORED, GOODBYE closes the session). Note that because of the tiny-map
defect, every SUCCESS/FAILURE frame carrying fewer than 16 map entries is
malformed on the wire.

### Not implemented

- `RUN` translates the Cypher text to UWP and dispatches it, but the result is
  discarded: the handler answers `SUCCESS {t_first, qid}` and never emits a
  `RECORD`.
- `PULL` returns a single empty record and a bookmark; there is no result-set
  or stream cursor, no `has_more`/`qid` bookkeeping, and `DISCARD` is a no-op.
- `BEGIN`/`COMMIT`/`ROLLBACK` translate to UWP and dispatch, but no Bolt-level
  transaction state is tracked per session, and the response maps use the
  broken tiny-map encoding.
- HELLO authentication is implemented (`qihse_auth_authenticate_from`, per-IP
  rate limiting), but no test in this repository exercises it.

## Testing

`tests/test_bolt.c` (run via `make test-bolt`) asserts:

1. PackStream round trip: null, bool, int ranges that work, float64, strings
   with 8- and 16-bit length prefixes, lists, 16-entry maps, tiny structs with
   the Node/Relationship/Path signatures.
2. Truncated and unknown input is refused rather than mis-decoded.
3. Message framing: single-chunk encode/decode, two messages back to back,
   multi-chunk reassembly, partial input reported as "need more data", an empty
   message reported as an error.
4. Handshake over a socketpair: magic check, 4.0 selection, version-0 refusal,
   truncation.
5. The client message loop over a socketpair: RESET answered with SUCCESS, an
   unknown signature answered with IGNORED, GOODBYE closing the session.

**Known defects reproduced by that test (printed as `NOTE` lines, not asserted,
so that fixing them cannot break the test):**

- tiny-map encoding uses marker `0xD7` instead of `0xA0`-`0xAF`, and the
  library's own decoder reads nothing back from it;
- negative tiny ints (`-16`..`-1`) are encoded but decode to nothing;
- tiny strings decode as integers (the decoder maps `0x80`-`0x8F` to tiny
  negative ints, but PackStream reserves that range for tiny strings);
- tiny lists and tiny maps cannot be decoded at all;
- the message signature constants differ from Bolt 4.x as tabulated above.

There is no test for a real neo4j driver handshake against this server, and
this document does not claim one.
