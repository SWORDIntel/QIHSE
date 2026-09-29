# QIHSE Operator Browser (web bridge + dashboard views)

> **Status: implemented** — tests: `make test-browser-unit` (`python/tests/test_browser_unit.py`, 31 checks), `make test-browser` (`tests/qihse_browser_fixture.c` + `python/tests/test_browser_negative_auth.py`, 24 checks, the AGENTS.md invariant-3 negative-authorization gate); frontend build verified (`dashboard/ npm ci && npm run build`, served by the bridge at `/`).

One tool to see the whole fleet: per-node cluster state, the federation
plane, and keyspaces — web views over an authenticated Python bridge, with
YubiKey-FIPS FIDO2 operator login and a guarded action allowlist.

Design reviewed externally (claude-fable-5.1 via bothub, 2026-09-27); all
findings are folded into the implementation and called out below.

## Layout

| Piece | Path |
|---|---|
| Bridge package | `python/qihse/browser/` (`fleet.py`, `bridge.py`, `slots.py`, `keyspace.py`, `webauthn.py`, `actions.py`, `dump.py`) |
| Frontend | `dashboard/src/views/*.jsx` + rewritten `App.jsx` shell (no new npm deps; `/api` proxied to :8090 in dev) |
| Entry | `./qihse browse` (serves bridge + built UI), `./qihse browse --dump overview\|cluster\|federation\|keys` (headless) |
| Tests | `python/tests/test_browser_unit.py`, `tests/qihse_browser_fixture.c` + `python/tests/test_browser_negative_auth.py`, Makefile targets `test-browser-unit` / `test-browser` (wired into `test:`) |

## Operating modes

**Operator-context (DEFAULT — no login wall, FIDO-only credential).** The
bridge authenticates ONCE at startup as `GODMODE_OP` using
`--password`/`QIHSE_OPERATOR_PASSWORD` (refuses to start without it — a
deliberate, configured context, never inferred; same convention as every
other QIHSE tool). The web UI opens straight into the dashboard; no
password is ever typed into a browser. The ONLY credential the UI can ask
for is the YubiKey in the slot: guarded actions require a command-bound
touch, and the password login endpoint is disabled outright
(`LOGIN_DISABLED`). First-run key enrollment is a single create ceremony
from the Actions tab (allowed while the credential store is empty, logged
loudly); the loopback-only bind is the trust boundary for that first
enrollment.

**Per-principal mode (`--require-login`).** The original two-factor flow:
password login per session (rate-limited, one PBKDF2 per attempt) +
mandatory WebAuthn second factor (`--allow-password-only` = explicit
break-glass). Use it when operators browse under their own principals
(e.g. an analyst session) — the invariant-3 negative suite exercises this
mode end-to-end, plus the operator-context mode's no-login/locked-actions
guarantees (30 checks).

## Ports

Bridge: **8090**, loopback only (a non-loopback `--bind` is refused — the
bridge serves plaintext HTTP + non-Secure cookies and must stay behind SSH
`-L 8090:127.0.0.1:8090`). Telemetry stays on 8080; Vite dev on 5173.
**8000 is reserved and never used.** WebAuthn RP ID is `localhost`
(browsers reject IP-literal RP IDs); `http://localhost:8090` — directly or
via SSH forward — is a secure context, so ceremonies need no TLS cert.

## Security model

- **No ambient credentials.** The bridge process holds no node
  credentials. Each login creates a `SessionFleet` of Controllers
  authenticated as the logged-in principal; idle sessions (15 min) are
  torn down with their Controllers. There is no background
  system-credential poller — the confused-deputy finding from the review.
- **Everything over the wire.** The bridge never opens WAL/SSTable/journal
  segment files; classification enforcement at the KV read layer
  (`qihse_kv_get_user`) therefore governs everything the UI can show.
  Per-key classification is not exposed over RESP, so the browser shows
  exactly what the session's principal may see — under-cleared keys are
  absent, not hidden client-side.
- **Typed refusals render as refusals.** `NOPERM`/`NOAUTH`/`DOWN` are
  relayed verbatim from the server; the dashboard never fabricates
  emptiness (its standing "renderer of runtime truth" rule).
- **Explicit seeds only.** The bridge connects and authenticates only to
  `--node` endpoints (env fallback: `QIHSE_NODE0_HOST/PORT`). `CLUSTER
  NODES` output is rendered for display and never dialed; `MOVED`
  re-targeting maps back to seeded nodes or errors out.
- **Loopback + login rate limits.** 5 failed logins/60 s per source →
  429; one PBKDF2 exchange per attempt (single-seed AUTH); bounded
  request bodies (1 MiB) and handler threads; CSRF header on POSTs;
  HttpOnly SameSite=Strict session cookie.

## Operator auth (two-factor)

1. **Password** (knowledge): validated by AUTHing to the first reachable
   seed (seconds — the CNSA 2.0 KDF).
2. **WebAuthn assertion** (possession + user verification): YubiKey FIPS
   touch + PIN, RP `localhost`, UV required, cross-platform authenticators
   only, `sign_count` persisted and enforced (clone detection), AAGUID
   recorded (pinnable via `webauthn.AAGUID_ALLOWLIST`).

With `--require-webauthn` (default), a username with no enrolled
credential FAILS login — deleting the store bricks logins, it does not
downgrade them. `--allow-password-only` is the explicit break-glass flag
(single-factor sessions cannot fire guarded actions).

Enrollment (`/api/webauthn/begin|complete` purpose=enroll): self-service
for the logged-in principal; enrolling for another user requires the
server-verified system-principal predicate (the FEDERATION.STATUS
system-domain gate decides — not a username match). Credential store:
`./browser-credentials.json`, 0600, gitignored, **public key material +
username + label only**.

Server-side hardware-token policy (`qihse_auth_set_hardware_token`)
continues to gate classified reads at the data layer independently of the
bridge.

## Records browser

The Records tab runs a prefix census over the entire keyspace visible to
the session's principal (`/api/records/census`): every record family —
`fednode:`/`fedns:`/`fedlease:`/`fedconf:`/`grp:`/`task:`/tenant
namespaces/bare keys — with counts, per-node distribution, and samples.
Drill: family → records → single record with typed preview, TTL/size,
slot, and a raw hex head (first 256 bytes) for binary envelopes.  The
census honors the same server-side clearance filtering as every other
surface; what you cannot see does not appear.

## Guarded actions

Allowlist only (no command proxy — `/api/exec` is refused by design).

| Action | Canonical command | Validation |
|---|---|---|
| moveslots | `CLUSTER MOVESLOTS <first>-<last> <target>` | 0≤first≤last≤16383; target must be a seeded node |
| trust_set | `FEDERATION TRUST.SET <uuid> <state> <result>` | hex-32 uuid; state ∈ PENDING/APPROVED/REVOKED |
| lease_release | `FEDERATION LEASE.RELEASE <lease>` | non-empty id |
| fed_state | `FEDERATION STATE <state>` | federation-state enum |

Built-ins (10): MOVESLOTS, TRUST.SET, LEASE.RELEASE, LEASE.RENEW,
FEDERATION STATE, NODE.APPROVE, NODE.REVOKE, NS.REGISTER, NS.UNREGISTER,
BGSAVE.  **`--extra-actions <file>`** is the operator-authored escape
hatch for anything else ever needed: a JSON file on the bridge host
(never reachable from the browser) declaring additional commands with
typed argument specs; entries are hard-validated at load, logged, and
dispatch under the same touch-bound ceremony.  SHUTDOWN / DEBUG / CONFIG
/ FLUSH* are refused in that file on purpose — fatal controls stay on
the console.

Dispatch requires a two-factor session (or operator-context bridge) plus
a **per-action WebAuthn UV assertion bound to the exact canonical command
bytes** (single-use, 30 s
TTL): the dialog's command, the touch, and the dispatch cannot diverge.
The server remains the authority; refusals relay verbatim. Every dispatch
logs principal + canonical command (never key values or credentials).

## What the views show

- **Overview** — fleet table (per-node up/latency/role/DBSIZE/errors) +
  `CLUSTER INFO` summary; polls every 3 s.
- **Cluster** — slot-ownership strip + per-owner counts, full `CLUSTER
  NODES` table (display-only addresses).
- **Federation** — STATUS JSON, trust plane (`NODE.LIST/SHOW` with
  fingerprints + sig alg), namespaces, leases (`fedlease:` enumeration +
  `LEASE.READ`), conflicts, rejoin, `REPL.STATUS` anti-entropy. Loaded
  on demand (no background federation polling).
- **Journal** — `FEDERATION.EVENT.REPLAY` pager; brain envelopes show
  magic with a **"signed flag set (unverified)"** badge (ML-DSA
  verification stays in the C helpers).
- **Keyspace** — pattern scan with client-side paging (server SCAN is
  single-shot), system-prefix quick filters, TYPE/TTL/size, type-aware
  previews; key ops route to the slot owner.
- **Actions** — arm switch + exact-command dialog + touch confirm.
- **Telemetry** — the original metrics dashboard, unchanged.

## Testing

`make test-browser-unit` — CRC16/hash-tag vectors (vs documented Redis
values), action allowlist validation, WebAuthn RP against synthetic
wire-exact ceremonies (real ECDSA over constructed authenticator data):
tampered signatures, foreign origins, replayed sign counts, no-UV,
cross-user assertions, and swapped-command action bindings all refused.

`make test-browser` — the invariant-3 gate. A C fixture boots an
in-process RESP server (auth required) with a clearance-2 ANALYST
(system-domain), a tenant-scoped ANALYST, and classified keys above their
reach; the Python side drives the real bridge over HTTP and asserts:
unauth→401 everywhere; classified key **names and values** invisible to
the low-clearance session; `FEDERATION.*` renders NOPERM for the tenant
principal; single-factor actions→403; command-proxy→403; CSRF enforced;
fail-closed no-credential login; login rate limiting; positive controls
(the operator sees the classified keys — proving the gates are real).

## Known boundaries (documented, not hidden)

- Cleartext RESP to nodes: deploy the bridge co-located with nodes or
  behind SSH/VPN; QKP-sealed transport (`--pqc-require` nodes) is a
  follow-up.
- The plaintext password must be retained in session memory for
  reconnect+re-auth (Python strings cannot be zeroized) — bounded by the
  15-minute idle teardown.
- Internal-only state (bus stats, QKP counters, CRL state, per-key
  classification) has no wire surface; it will be exposed via future
  additive server commands — never by reading files from the bridge.
