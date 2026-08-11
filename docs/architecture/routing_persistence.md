# QIHSE Network Intelligence — Routing Persistence Integration

## Overview

QIHSE's `network_intelligence/` subsystem integrates TGMap's routing observation
modules with QIHSE's native persistence engines (event stream, timeseries, column
store). This provides a single in-process persistence layer for BGP, RPKI, RDAP,
and PTR observations — no external database required.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ TGMap Probe / 64Gram Observer                                │
│   (bgp_route_probe, rpki_rtr_probe, rdap_probe, ptr_probe)   │
└──────────────────────┬──────────────────────────────────────┘
                       │ observations
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ qihse_routing_persistence (adapter)                           │
│   store_bgp_observation()  ──┬── event stream (bgp_observations)│
│   store_rpki_roa()        ───┼── event stream (rpki_roas)      │
│   store_ptr_record()      ───┼── event stream (ptr_records)    │
│   store_rdap_record()     ───┘── event stream (rdap_records)   │
│   replay_bgp()            ────── event stream replay           │
│   query_by_prefix()       ────── column store scan             │
└──────────────────────┬───────────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │ Event    │ │ Timeser- │ │ Column   │
   │ Stream   │ │ ies DB   │ │ Store    │
   │ (SHA-384 │ │ (Gorilla │ │ (SIMD    │
   │  commit  │ │  delta-  │ │  OLAP,   │
   │  log)    │ │  delta)  │ │  zone    │
   │          │ │          │ │  maps)   │
   └──────────┘ └──────────┘ └──────────┘
```

## Routing Persistence API

### `qihse_routing_persistence.h`

The adapter fans out each observation to multiple QIHSE engines:

| Observation | Event Stream Topic | Timeseries | Column Store |
| --- | --- | --- | --- |
| BGP route | `bgp_observations` | series_id=hash(ip), value=origin_asn | ip_hash, origin_asn, prefix, rpki_state, collector_id, timestamp |
| RPKI ROA | `rpki_roas` | — | — |
| PTR record | `ptr_records` | — | — |
| RDAP record | `rdap_records` | — | — |

### C API

```c
#include "qihse_routing_persistence.h"

/* Create persistence handle in a directory */
qihse_routing_persistence_t* rp = qihse_routing_persistence_create("/var/lib/qihse/routing");

/* Store a BGP observation */
qihse_routing_persistence_store_bgp_observation(rp,
    "149.154.160.0",      /* ip */
    62041,                 /* origin_asn */
    "149.154.160.0/20",   /* prefix */
    1,                     /* rpki_state: 0=not_found, 1=valid, 2=invalid */
    100,                   /* collector_id */
    1723000000ULL);        /* timestamp */

/* Store RPKI ROA */
qihse_routing_persistence_store_rpki_roa(rp, 62041, "149.154.160.0/20", 20, 24, "ipv4");

/* Store PTR record */
qihse_routing_persistence_store_ptr_record(rp, "149.154.160.1", "node-1.telegram.org", 1723000000ULL);

/* Store RDAP record */
qihse_routing_persistence_store_rdap_record(rp, "149.154.160.1", "{...}", 1723000000ULL);

/* Replay BGP observations */
uint64_t count = qihse_routing_persistence_replay_bgp(rp, callback, user_data);

/* Query by prefix */
qihse_routing_bgp_record_t results[100];
size_t n = qihse_routing_persistence_query_by_prefix(rp, "149.154.160", results, 100);

qihse_routing_persistence_destroy(rp);
```

### Python API

```python
import qihse

# (Python bindings for routing persistence are a planned addition)
```

## Copied TGMap Modules

The following TGMap source files are copied verbatim into `src/network_intelligence/`
with their original namespaces preserved:

| File | Namespace | Purpose |
| --- | --- | --- |
| `bgp_route_probe.{h,cpp}` | `tgmap::mtproto` | RIPEstat lookup, hijack classification, AS-path analysis |
| `bgp_update_decoder.{h,cpp}` | `tgmap::enrichment` | BGP UPDATE message decoder (RFC 4271) |
| `rpki_rtr_probe.{h,cpp}` | `tgmap::mtproto` | RPKI RTR client (RFC 6810), ROA cache, validation |
| `rdap_probe.{h,cpp}` | `tgmap::mtproto` | RDAP lookup probe |
| `ptr_probe.{h,cpp}` | `tgmap::mtproto` | PTR reverse DNS probe |
| `route_helper.{h,cpp}` | `tgmap::mtproto` | Route helper process |

Headers are mirrored in `include/network_intelligence/mtproto/` and
`include/network_intelligence/enrichment/` to match the original include paths.

## Build Integration

The Makefile includes:
- `CXX=g++` and `CXXFLAGS_BASE` for C++ compilation
- `-I./include/network_intelligence` in INCLUDES
- All 6 `.cpp` files in `SRCS_BASE`
- `qihse_routing_persistence.c` in `SRCS_BASE`
- `test-routing-persistence` target

## Testing

```bash
# Build and run routing persistence tests
make test-routing-persistence

# Or compile directly:
gcc -std=c99 -Wall -Wextra -O2 -I./include -D_GNU_SOURCE \
    tests/qihse_routing_persistence_test.c \
    src/network_intelligence/qihse_routing_persistence.c \
    src/marmalade/qihse_event_stream.c \
    src/marmalade/qihse_timeseries.c \
    src/frieze/qihse_column_store.c \
    -o test_routing_persistence -lcrypto -lpthread
./test_routing_persistence
```

Results: **32 passed, 0 failed, 10 test cases.**

## Event Stream Topics

| Topic | Schema ID | Payload Format |
| --- | --- | --- |
| `bgp_observations` | 1 | JSON: `{ip,origin_asn,prefix,rpki_state,collector_id,timestamp}` |
| `rpki_roas` | 2 | JSON: `{origin_asn,prefix,prefix_length,max_length,address_family}` |
| `ptr_records` | 3 | JSON: `{ip,hostname,timestamp}` |
| `rdap_records` | 4 | JSON: `{ip,rdap_json,timestamp}` |

All records carry a 48-byte SHA-384 event ID computed as `SHA-384(topic || payload)`.
Duplicate event IDs are rejected by the event stream.
