# network_intelligence — TGMap-derived routing intelligence modules

This directory contains BGP / routing intelligence probes copied verbatim from the
TGMap project (`src/mtproto` and `src/enrichment`). They are integrated into QIHSE
for native persistence so the routing-intelligence pipeline can run in-process
alongside the QIHSE storage and query engine.

## Modules

| File | Namespace | Purpose |
|------|-----------|---------|
| `bgp_route_probe.{h,cpp}` | `tgmap::mtproto` | BGP route probe — RIPEstat lookup, BGP hijack classification, AS-path analysis |
| `bgp_update_decoder.{h,cpp}` | `tgmap::enrichment` | BGP UPDATE message decoder (RFC 4271 framing, NLRI, AS_PATH parsing) |
| `rpki_rtr_probe.{h,cpp}` | `tgmap::mtproto` | RPKI RTR client (RFC 6810), ROA cache, route-origin validation |
| `rdap_probe.{h,cpp}` | `tgmap::mtproto` | RDAP (Registration Data Access Protocol) lookup probe |
| `ptr_probe.{h,cpp}` | `tgmap::mtproto` | PTR reverse-DNS probe |
| `route_helper.{h,cpp}` | `tgmap::mtproto` | Route helper process orchestrating the above probes |

## Namespaces

The original `tgmap::mtproto` and `tgmap::enrichment` namespaces are preserved
unchanged. QIHSE references these modules through the include paths
(`-I./src/network_intelligence` and `-I./include/network_intelligence`) without
renaming, keeping the code identical to its TGMap origin for easy upstream
syncing.

## Build integration

The six `.cpp` files are listed in `SRCS_BASE` in the top-level `Makefile`
(immediately after `src/marmalade/qihse_event_stream.c`). The public headers are
mirrored under `include/network_intelligence/` so they are reachable via the
existing `-I./include` search path.
