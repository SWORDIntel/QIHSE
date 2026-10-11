# QIHSE Browser runbook

> **Status: implemented** — tests: `make test-browser-unit`, `make test-browser` (see [architecture](../../architecture/qihse_browser.md)).

## Start (default: no login wall, FIDO only)

```sh
QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse browse \
    --node 127.0.0.1:7197 --node 127.0.0.1:7198 --node 127.0.0.1:7199
```

The bridge authenticates once at startup as the operator; the web UI opens
straight into the dashboard — no password is ever typed in the browser.
From your workstation: `ssh -L 8090:127.0.0.1:8090 <cluster-host>`, then
open `http://localhost:8090`. Bridge binds loopback only (8090; never
8000). Without `QIHSE_OPERATOR_PASSWORD` the bridge refuses to start in
this mode.

## The key in the slot (first run)

Actions tab → **Enroll the key in the slot** → touch + PIN. From then on
the YubiKey is the only credential the UI ever asks for: every guarded
action shows the exact command, you touch to bind it, and dispatch must
match the touched command within 30 s.

## Per-principal mode (optional)

`--require-login` restores the two-factor login wall: QIHSE
username+password per session (seconds — server-side CNSA 2.0 KDF), then
YubiKey touch + PIN; a principal with no enrolled credential is refused
outright. `--allow-password-only` is the explicit break-glass flag
(single-factor sessions cannot fire guarded actions).

## Headless status (no HTTP, no WebAuthn)

```sh
QIHSE_OPERATOR_PASSWORD='<op pass>' ./qihse browse --dump overview \
    --node 127.0.0.1:7100
# also: --dump cluster | federation | keys [--pattern 'fedns:*']
```

## Guarded actions (Actions tab)

Arm the switch → pick an action → fill args → **Prepare** (touch the
YubiKey — the challenge is bound to the exact command shown) → **DISPATCH**
within 30 s. The whitelist: `CLUSTER MOVESLOTS`, `FEDERATION
TRUST.SET/LEASE.RELEASE/STATE`. MOVESLOTS targets must be seeded nodes.

## Reading refusals

`NOPERM`/`NOAUTH` panels are the server talking, not a UI bug: the
principal in the sidebar is either not the system tenant or not cleared
for that data. `DOWN`/`UNREACHABLE` = the node was unreachable at poll
time. Keys you cannot see are absent because the server filtered them
under your clearance — the browser has no view into per-key
classification.
