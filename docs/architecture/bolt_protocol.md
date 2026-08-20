# Bolt Protocol (Neo4j Wire Protocol)

## Overview

QIHSE implements the Neo4j Bolt 4.x wire protocol, allowing applications using the neo4j-python driver to connect to QIHSE without code changes.

## Protocol Implementation (`src/spinnaker/qihse_bolt.c`)

### Handshake
1. Client sends magic bytes `\x60\x60\xb0\x17`
2. Client sends 4 supported protocol versions (4 bytes each)
3. Server responds with selected version (4 bytes)

### PackStream Serialization
PackStream is Bolt's compact binary serialization format:

| Type | Marker Range | Description |
|---|---|---|
| Null | `0xC0` | Single byte |
| Boolean | `0xC1`/`0xC2` | true/false |
| Integer | `0xC8`-`0xCB` | 8/16/32/64-bit |
| Float | `0xC3` | 64-bit IEEE 754 |
| String | `0xD0`-`0xD2` | 5/8/16-bit length prefix |
| List | `0xD4`-`0xD6` | 5/8/16-bit length prefix |
| Map | `0xD8`-`0xDA` | 5/8/16-bit length prefix |
| Struct | `0xB0`-`0xB2` | 5/8/16-bit length + type byte |

### Struct Types
- **Node** (`0x4E`): `(id, labels, properties)`
- **Relationship** (`0x52`): `(id, start_node, end_node, type, properties)`
- **Path** (`0x50`): `(nodes, relationships, sequence)`

### Messages

| Message | Signature | Description |
|---|---|---|
| HELLO | `0x01` | Initial authentication |
| GOODBYE | `0x02` | Close connection |
| RESET | `0x0F` | Reset session state |
| RUN | `0x10` | Execute Cypher query |
| PULL | `0x3F` | Pull result records |
| DISCARD | `0x2F` | Discard result records |
| BEGIN | `0x11` | Start transaction |
| COMMIT | `0x12` | Commit transaction |
| ROLLBACK | `0x13` | Rollback transaction |

### Responses

| Response | Signature | Description |
|---|---|---|
| SUCCESS | `0x70` | Operation succeeded, with metadata map |
| RECORD | `0x71` | A single result record |
| FAILURE | `0x7F` | Operation failed, with error map |
| IGNORED | `0x7E` | Operation ignored |

## Testing
10 tests in `tests/test_bolt.c` covering PackStream encode/decode for all types and the Bolt message flow.
