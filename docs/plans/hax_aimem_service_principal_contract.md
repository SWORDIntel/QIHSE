# HAX native AIMEM service-principal contract

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

**Scope:** repository implementation contract for HAX clients. This file does
not assert that a deployed AIMEM service has been upgraded, and it does not
authorize live writes or backlog replay. Before using a feature, authenticate
to the intended service and query `AIMEM VERSION` and `AIMEM CAPABILITIES` on
that connection. The authenticated, content-free metadata handlers are in
`src/spinnaker/qihse_resp_engine.c` (`qihse_resp_handle_aimem`); the wire
command list is in `docs/architecture/aimem_resp_protocol.md`. On a service
without those handlers, treat `ERR unknown AIMEM operation` as unsupported.

## Identity and isolation

Configure a dedicated, active **tenant** principal for HAX. The optional
`aimem_service_user_id` setting defaults to disabled (`UINT32_MAX`). When set,
server creation requires an authenticated, active, non-Operator, non-system
tenant principal (`src/spinnaker/qihse_resp_engine.c:16899-16944`). The session
may execute `AIMEM`, `AUTH`, `HELLO`, `PING`, and `QUIT`; other command families
are rejected before their fast paths with `NOPERM`
(`src/spinnaker/qihse_resp_engine.c:15966-15974,16095-16117`). This restriction
does not grant AIMEM data access by itself. Every AIMEM call requires an active
authenticated principal, and tenant callers must use the scoped forms
(`src/spinnaker/qihse_resp_engine.c:8087-8115`).

Give the service principal only the classification and SCI compartments needed
for its HAX project records. Each native read and mutation carries that
`qihse_user_t *` through the server to the data layer. Project membership
never overrides a record's label/SCI check. Keep a separate authorized
reviewer identity for approval or retraction; the non-Operator HAX service
principal can propose knowledge but cannot approve or retract it
(`src/spinnaker/qihse_ai_memory.c:2725-2731`).

| Surface | Service-principal permission and result | Source |
| --- | --- | --- |
| Durable memory | `STORE-SCOPED-DURABLE` requires valid project hierarchy; `STORE-SCOPED-RECEIPT` additionally requires an idempotency key and returns a principal, tenant, scope, UUID, and local sequence bound opaque receipt after local fsync. The same key with changed content or kind conflicts. `GET-SCOPED`, `RECALL-SCOPED`, `COUNT-SCOPED`, and `FORGET-SCOPED-DURABLE` enforce scope and record visibility. A receipt is **local fsync**, not remote replication or quorum. | `src/spinnaker/qihse_resp_engine.c:7679-7963,8673-8700`; `src/spinnaker/qihse_ai_memory.c:630-857` |
| Knowledge | The HAX principal may create a `PROPOSED` version in a project it owns and may revise its own unapproved chain with expected version/revision. `APPROVED` and `RETRACTED` transitions require an Operator. `GET`, `LATEST`, and `AS-OF` are exact, scope-bound authorized reads. The extended native API validates evidence and retry identity; wire clients must check the deployed knowledge capability and command shape before using those fields. | `src/spinnaker/qihse_ai_memory.c:2725-2731,3139-3200,3255-3469`; `src/spinnaker/qihse_resp_engine.c:8265-8403` |
| Handoffs | `OFFER` requires an owner record in the project (or Operator), an active same-tenant recipient, and a current project-reader grant for that recipient. Each evidence UUID must be visible in the exact scope. The owner may `CANCEL`; only the named recipient with a current grant may `ACCEPT` at the expected revision. `GET` is visible to owner, recipient, or Operator subject to KV label access; unknown or unauthorized IDs return null. | `src/spinnaker/qihse_resp_engine.c:8407-8588`; `src/spinnaker/qihse_ai_memory.c:1746-1770` |
| Events | `EVENT APPEND` binds authenticated actor/tenant/scope, bounded producer and event IDs, registered kind, timestamp, summary and optional exact-scope visible evidence. Exact replay returns the event UUID; changed identity content conflicts. `EVENT READ` reauthorizes and returns null for unavailable IDs. | `src/spinnaker/qihse_ai_memory.c:1162-1268,1326-1337`; `src/spinnaker/qihse_resp_engine.c:8160-8235` |
| Project grants | A same-tenant grantor may grant an active same-tenant reader after it owns a record in the project; an Operator can grant. A grant delegates read membership only. `GRANT`/`REVOKE` are durable and return `NOPERM` when policy denies. Record classification and SCI still apply. | `src/spinnaker/qihse_ai_memory.c:1721-1768`; `src/spinnaker/qihse_resp_engine.c:8238-8263` |
| Query cursors | `QUERY V1 BEGIN` filters one exact scope and authenticated tenant; server snapshots are capped at 4,096 rows. `NEXT` rechecks the same principal, current record visibility and grants; `END` releases state. RESP has at most 128 cursors with a five-minute expiry; a lost/expired cursor gives a content-free error. | `src/spinnaker/qihse_ai_memory.c:3759-3837`; `src/spinnaker/qihse_resp_engine.c:7603-7646,7965-8084` |

The service principal should not receive system Operator authority to make
these commands work. Project ownership and explicit reader grants are the
application controls. The HAX process must not inspect QIHSE storage paths.

## Python SDK examples

These examples use the repository's `python/qihse/aimem.py` and an explicit
authenticated `Controller`. Supply credentials through the caller's secret
handling; the SDK does not discover an ambient identity. The examples are
fixtures for an **already authorized** project, not instructions to operate on
live data.

```python
from qihse import Controller, AIMEMClient, Scope
from qihse.controller import ControllerServerError

scope = Scope("fixture-project", "fixture-tree", "fixture-stream", "fixture-session")
with Controller("127.0.0.1", 6390, username="hax-service", password=password) as wire:
    # Verify the actual endpoint before selecting a feature.
    version = wire.call("AIMEM", "VERSION").as_text()
    wire.call("AIMEM", "CAPABILITIES", "scoped-local-fsync-receipts-v1")
    if version != "1":
        raise RuntimeError("unrecognized AIMEM wire version")

    mem = AIMEMClient(wire)
    receipt = mem.store_receipt(scope, 1, "attributed observation", key="capture-001")
    # receipt.durability == "local-fsync"; retry the same key after lost ACK.
    hit = mem.get(scope, receipt.id)
    matches = mem.recall(scope, "observation", mode="bm25")
    count = mem.count(scope)
    removed = mem.forget(scope, receipt.id)

    event_id = mem.event_append(scope, "hax", "event-001", "observation",
                                source_ms, "source summary")
    event = mem.event_get(scope, event_id)
    proposed = mem.knowledge_create(scope, 5, 1, "candidate preference")
    current = mem.knowledge_latest(scope, proposed.knowledge_id)
    historical = mem.knowledge_as_of(scope, proposed.knowledge_id, cutoff_ms)

    # The recipient must have a project-reader grant before an offer.
    wire.call("AIMEM", "PROJECT", "GRANT", scope.project, recipient_user_id)
    offer_id = mem.handoff_offer(scope, recipient_user_id, 60_000, "handoff summary")
    offer = mem.handoff_get(offer_id)
    # The recipient uses its own authenticated Controller to accept:
    # recipient_mem.handoff_accept(offer_id, offer.revision)

    cursor = mem.query_begin(scope, type=5, status=1, text="preference")
    try:
        page = mem.query_next(cursor, page_size=32)
    finally:
        mem.query_end(cursor)

    # Project membership uses the same authenticated wire when authorized.
    wire.call("AIMEM", "PROJECT", "REVOKE", scope.project, recipient_user_id)
```

Do not use a service principal for the reviewer action. Authenticate a
separate Operator reviewer and make an explicit `KNOWLEDGE REVISE-EX` call with
the expected version and revision after human review. HAX must verify the
deployed service advertises `knowledge-provenance-v1` before using the extended
provenance/retry fields. The simple `KNOWLEDGE CREATE/REVISE` commands do not
carry those fields.

## Denied, unsupported, and retry handling

`Controller.call` raises `ControllerServerError` with `error_class` and
`message` from the server (`python/qihse/controller.py:135-149,1196-1206`).
`NOAUTH` means authentication is missing or inactive; `NOPERM` means policy
denied the operation. Neither result permits a raw storage fallback. An
authorized direct-ID read of an unavailable or hidden record returns `None`;
the client must treat it as unavailable, without guessing whether it exists.

The capability probe returns `ERR UNSUPPORTED AIMEM capability` for an unknown
feature token (`src/spinnaker/qihse_resp_engine.c`, `CAPABILITIES` handler).
Older services may return `ERR unknown AIMEM operation` for the probe itself.
Both are `ControllerServerError` today; there is no dedicated Python
`UnsupportedError` subclass. Use the authenticated probe to choose only
implemented commands and keep unsupported as an explicit application state.
For `ERR CONFLICT`, re-read the authorized current version or retry with the
same immutable payload/key as appropriate. For `ERR NOT_DURABLE`, do not
claim admission; retry the same idempotency identity and payload after the
service is healthy. Never log a protected payload or downgrade to a context
free read to diagnose an error.

The repository's `tests/test_python_aimem_sdk.py` drives a disposable real
RESP server: a low-clearance principal in the same tenant cannot read high
classified memory by direct ID, recall, count, or knowledge ID. It also
checks exact scoped receipt replay and changed-payload conflict. These tests
are fixtures and do not probe the deployed service.
