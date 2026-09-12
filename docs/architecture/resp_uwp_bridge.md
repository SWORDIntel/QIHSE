# RESP ↔ UWP Bridge Architecture

## Overview

QIHSE serves Redis-compatible workloads (RESP2/RESP3) and its own Unified Wire
Protocol (UWP) from the same engines. The bridge makes the two surfaces one
system: a UWP packet can execute any RESP command, and RESP pub/sub messages
are durably logged to the event-stream subsystem where UWP STREAM consumers
and CDC can read them.

## Components

| Component | Location | Role |
|---|---|---|
| RESP engine | `src/spinnaker/qihse_resp_engine.c` | RESP2/3 parsing, command dispatch, TCP sessions |
| Pub/sub broker | `src/spinnaker/qihse_resp_pubsub.c` | channel/pattern registry, fan-out, durable log, channel security policy |
| Stateless execute | `qihse_resp_server_execute()` (`include/qihse_resp_wire.h`) | runs one RESP command for an explicit `qihse_user_t`, returns raw reply bytes |
| UWP bridge | `QIHSE_UWP_TARGET_RESP` (0x0F) in `src/spinnaker/qihse_uwp.c` | parses `QIHSE_UWP_RESP_EXEC` payloads and delegates to the execute API |
| Standalone daemon | `tools/qihse_redis_server.c` (`make redis-server`) | RESP listener plus optional UWP listener over the same stores |

## Shared dispatch path

Both transports converge on `qihse_resp_dispatch()`:

```
RESP TCP client ──► session loop ──┐
                                   ├─► qihse_resp_dispatch(session, request)
UWP TARGET_RESP ──► uwp_resp_target┘         │  (session->user = authenticated user)
        (qihse_resp_server_execute)          ▼
                                   engine *_user primitives
                                   (qihse_kv_get_user, ...)
```

The UWP path builds a lightweight session in buffered-I/O mode: replies are
accumulated into a memory buffer instead of a socket, so no session state
(transactions, subscriptions) is kept between bridge invocations. There is no
context-free fallback — `qihse_resp_server_execute` rejects a `NULL` user, and
`qihse_uwp_dispatch` rejects unauthenticated callers before reaching the
bridge (invariant #1 in `AGENTS.md`).

### Dispatch pipeline gates

Both transports run the same ordered gate sequence inside
`qihse_resp_dispatch()`:

1. `AUTH` / `HELLO` / `PING` / `QUIT` short-circuit before any gate.
2. `NOAUTH` gate when `auth_required` is set and the session has no user.
3. **Revocation re-validation** — the session principal is re-resolved
   against the shadow authorization table once per command
   (`qihse_auth_user_is_active()`); a destroyed principal loses the session
   immediately (`NOAUTH Session principal revoked`), even for unclassified
   data whose per-row fast path skips identity resolution.
4. Subscribed-mode command restriction (Redis semantics).
5. **Per-tenant quotas** (`qihse_quota_*`) for ANN queries, telemetry ingest,
   KV writes, and bundle pulls — fail-closed, `QUOTA …` on denial.
6. MULTI queueing, system-guard bus-saturation throttling, cluster routing.
7. **Tenant namespace scoping** — tenant principals may only touch keys
   under `t:<own-id>/…` or `commons/…` (`NOPERM` otherwise, deny-by-default).
8. **Ingest guard** — telemetry-namespace writes (`t:*/tlm/…`) must match the
   closed record-type schema (`INGEST record rejected`).

See [Session-delivery subsystem](session_delivery.md) for the tenancy, quota,
and bundle-delivery machinery behind gates 3, 5, 7, and 8.

## Wire format

`QIHSE_UWP_TARGET_RESP` (0x0F), opcode `QIHSE_UWP_RESP_EXEC` (0x01):

```
offset  size              field
0       4 (u32 LE)        argc
4       4 (u32 LE)        argv[0] length
        argv[0] length    argv[0] bytes
        ...               repeated per argument
```

The reply is the raw RESP reply (e.g. `$-1\r\n`), written back on the UWP
connection (TLS-aware when the UWP session is encrypted).

## Pub/sub integration

- `PUBLISH` appends the message to a `qihse_event_stream_t` (topic
  `resp.pubsub`, payload = `u32 LE channel_len ‖ channel ‖ message`) when a
  log directory is configured, then fans out in-process to exact-channel and
  fnmatch-pattern subscribers.
- Delivery callbacks run on the publisher's thread while holding the broker
  registry read lock; each push frame is composed into a single buffer and
  written under the subscriber session's I/O lock so frames are atomic with
  respect to the subscriber's own command replies.
- Channels carry a global `(classification, SCI)` policy
  (`channel_classification` / `channel_sci` config, or `--channel-classif` /
  `--channel-sci` on the daemon). `SUBSCRIBE`, `PSUBSCRIBE`, and `PUBLISH`
  require the caller's clearance to dominate the policy (`NOPERM` otherwise).
- Channels may override that default with per-channel policy
  (`qihse_resp_pubsub_set_channel_policy()`), including a
  `publish_system_only` restriction. The fleet-wide `killswitch` channel uses
  it: every authenticated tenant may subscribe, only system-domain principals
  may publish, and valid `burn_edge` telemetry writes fan out on it
  automatically. See [Session-delivery subsystem](session_delivery.md).

## Security invariants

- Every data-retrieval path — direct TCP, bridge, pub/sub policy checks —
  propagates an explicit `qihse_user_t` down to the `*_user` engine
  primitives. `NULL` never becomes an authorization bypass.
- The bridge is gated by `enable_uwp_bridge` (default on, `--uwp-port` on the
  daemon) and can be disabled per deployment.
- Negative coverage lives in `tests/test_resp_security_regression.c`
  (`make -f Makefile -f tests/security-regression.mk test-security-regressions`),
  which asserts NOAUTH, wrong-password, classified GET/MGET/EXISTS/KEYS denial,
  protected-channel denial for a low-clearance guest, and the NULL-user UWP
  case. Functional coverage lives in `tests/test_resp_pubsub.c`
  (`make test-resp-pubsub`).
