# QIHSE Event Stream — Record-Framed Commit Log

## Overview

The QIHSE Event Stream (`qihse_event_stream`) is a durable, record-framed commit log
designed for immutable event storage with SHA-384 integrity, crash recovery, and
zero-copy consumption. It replaces raw mmap append logs with a structured record
format that passes all 9 promotion gates defined in TGMap's native analytics storage
boundary.

## Record Format

Each record is serialized as an 88-byte header followed by a variable-length payload:

```
┌────────────────────────────────────────────────────────────────┐
│ Record Header (88 bytes)                                        │
├────────┬──────────┬───────┬───────────┬──────────────┬──────────┤
│ Offset │ Size     │ Field │ Type      │ Description  │          │
├────────┼──────────┼───────┼───────────┼──────────────┼──────────┤
│  0     │ 4        │ magic │ uint32    │ 0x51455354   │ "QEST"   │
│  4     │ 4        │ ver   │ uint32    │ 1            │ format   │
│  8     │ 4        │ flags │ uint32    │ 0x01=commit  │          │
│ 12     │ 4        │ schma │ uint32    │ caller-def   │ schema   │
│ 16     │ 8        │ offset│ uint64    │ monotonic    │ byte off │
│ 24     │ 8        │ size  │ uint64    │ payload len  │          │
│ 32     │ 8        │ prev  │ uint64    │ prev record  │ offset   │
│ 40     │ 48       │ eid   │ byte[48]  │ SHA-384      │ event ID │
├────────┴──────────┴───────┴───────────┴──────────────┴──────────┤
│ Payload (variable length, up to 16 MiB)                         │
└─────────────────────────────────────────────────────────────────┘
```

### Fields

| Field | Description |
| --- | --- |
| `magic` | `0x51455354` ("QEST") — identifies a valid record |
| `format_version` | Format version (currently 1) |
| `flags` | `0x01` = committed, `0x02` = corrupt |
| `schema_id` | Caller-defined schema version for the payload |
| `stream_offset` | Monotonic byte offset of this record in the topic log |
| `payload_size` | Payload length in bytes (max 16 MiB) |
| `prev_record_offset` | Offset of the previous record (0 for first record) |
| `event_id` | SHA-384 hash of (topic \|\| payload) — 48 bytes |

## Durability

Three durability modes are supported via `qihse_es_durability_t`:

| Mode | Behavior |
| --- | --- |
| `NONE` | No `fdatasync` — fastest, may lose recent records on crash |
| `FDATASYNC` | `fdatasync` after writing payload and after flipping commit flag |
| `FULL` | `fdatasync` + atomic rename for segment rotation (reserved) |

### Two-phase commit

1. Write uncommitted header (flags=0) + payload
2. `fdatasync` (if durability >= FDATASYNC)
3. Flip `flags` to `QIHSE_ES_F_COMMITTED` via 4-byte `pwrite`
4. `fdatasync` (if durability >= FDATASYNC)

This ensures that a crash during step 1-2 leaves an uncommitted record that
`truncate_torn_tail()` can detect and remove. A crash during step 3-4 leaves
a committed header with durable payload — safe to replay.

## Recovery

### Replay

`qihse_event_stream_replay()` walks committed records from the beginning of a
topic log, calling a user-supplied callback for each. It stops at the first
uncommitted, corrupt, or truncated record.

### Torn-tail recovery

`qihse_event_stream_truncate_torn_tail()` scans the topic log and truncates
any bytes after the last committed record using `ftruncate`. This removes
partial writes from a crash.

### Corruption detection

`validate_header()` checks:
- Magic bytes match `0x51455354`
- Format version matches
- `stream_offset` matches the expected position
- `payload_size` is within bounds (<= 16 MiB)

## Security

- **Owner-only files**: All topic logs are created with `0600` permissions
- **Symlink protection**: `O_NOFOLLOW` rejects symlinked topic files
- **Path traversal rejection**: `topic_is_safe()` rejects topics containing
  `/`, `\`, or `..`
- **No implicit network**: The only network function is
  `consume_zero_copy()`, which requires an explicit socket fd
- **No credential/content/webhook code**: The event stream source includes
  only `fcntl`, `unistd`, `sys/sendfile`, and `openssl/evp`

## Concurrency

- **Writers**: `flock(LOCK_EX)` serializes concurrent writers to the same topic
- **Readers**: `flock(LOCK_SH)` allows concurrent readers
- **Read-only mode**: `qihse_event_stream_open(read_only=true)` rejects all writes

## SHA-384 Integrity

Each record carries a 48-byte SHA-384 event ID. By default, this is
`SHA-384(topic || payload)`, computed via OpenSSL EVP. Callers can supply
their own event ID via `qihse_event_stream_append_record()`.

The event ID is compatible with TGMap's SHA-384 evidence envelope, allowing
QIHSE records to be cross-verified against the hash-chained spool.

## Duplicate Rejection

`qihse_event_stream_append_record()` scans the topic log for an existing
record with the same event ID before appending. If found, the append is
rejected (returns 0). This prevents duplicate events without rewriting
earlier direct observations.

## C API

```c
#include "qihse_event_stream.h"

/* Create with default durability (FDATASYNC) */
qihse_event_stream_t* es = qihse_event_stream_create("/var/lib/qihse/events");

/* Or open with explicit durability and read-only mode */
qihse_event_stream_t* es = qihse_event_stream_open(
    "/var/lib/qihse/events", QIHSE_ES_DURABILITY_FDATASYNC, false);

/* Append with auto-computed event ID */
qihse_event_stream_append(es, "bgp_updates", payload, payload_size);

/* Append with explicit schema ID and event ID */
uint8_t eid[48];
/* compute_eid produces SHA-384(topic || payload) */
uint64_t offset = qihse_event_stream_append_record(
    es, "bgp_updates", schema_id, eid, payload, payload_size);

/* Read by offset */
qihse_es_record_header_t hdr;
uint8_t* payload;
size_t payload_size;
qihse_event_stream_read(es, "bgp_updates", 0, &hdr, &payload, &payload_size);
free(payload);

/* Iterate all records */
uint64_t cursor = 0;
while (qihse_event_stream_iterate(es, "bgp_updates", &cursor, &hdr, &payload, &payload_size)) {
    /* process record */
    free(payload);
}

/* Replay after restart */
uint64_t count = qihse_event_stream_replay(es, "bgp_updates", callback, user_data);

/* Torn-tail recovery */
qihse_event_stream_truncate_torn_tail(es, "bgp_updates");

/* Zero-copy sendfile consumption */
qihse_event_stream_consume_zero_copy(es, "bgp_updates", offset, socket_fd, count);

qihse_event_stream_destroy(es);
```

## Python API

```python
import qihse

# Create event stream
with qihse.EventStream("/tmp/qihse_events") as es:
    # Append with auto-computed event ID
    es.append("bgp_updates", b'{"prefix":"1.2.3.0/24","asn":64512}')

    # Append with explicit schema ID and event ID
    eid = qihse.EventStream.compute_event_id("bgp_updates", b'...')
    es.append_record("bgp_updates", schema_id=2, event_id=eid, payload=b'...')

    # Iterate
    for record in es.iterate("bgp_updates"):
        print(record.schema_id, record.stream_offset, record.payload)

    # Replay with callback
    count = es.replay("bgp_updates", callback=lambda r: print(r.payload))

    # Torn-tail recovery
    es.truncate_torn_tail("bgp_updates")

    # Check for duplicate
    if es.has_event_id("bgp_updates", eid):
        print("duplicate detected")
```

## Testing

16 test cases with 49 assertions cover all 9 promotion gates:

```bash
gcc -std=c99 -Wall -Wextra -O2 -I./include -D_GNU_SOURCE \
    tests/qihse_event_stream_test.c src/marmalade/qihse_event_stream.c \
    -o test_event_stream -lcrypto && ./test_event_stream
```

Or via Makefile:

```bash
make test-event-stream
```

## Storage Layout

```
<log_directory>/
  bgp_updates.log      # topic log (record-framed)
  endpoint_obs.log     # topic log (record-framed)
  rpc_metadata.log     # topic log (record-framed)
  ...
```

Each topic is a single file containing a sequence of records. Segment rotation
(256 MiB max) is reserved for future implementation.
