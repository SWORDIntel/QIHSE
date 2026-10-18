# QIHSE Security Review — 2026-10-18

**Baseline:** `main` at `af81eff311044cf136f7927828c80c2e0c2f19f0`
**Remediation:** `security/qihse-audit-20261018`
**Status:** Partial, security-critical path review and remediation; **NOT** a completed codebase-wide security audit. Do not merge until CI gates pass.

## Confirmed source findings

| Priority | Finding / evidence | Remediation |
|---|---|---|
| Critical | Known default `QIHSE_OPERATOR_PASSWORD` in `scripts/install_qihse.sh`, exposed in systemd ExecStart, redis-cli argv and help output; same credential shared by Studio, thermal integration and smoke scripts | No default; fail closed without operator-provided secret; root-only systemd EnvironmentFile; no secret in daemon argv; no logs containing password |
| High | `portal/Program.cs` bound all interfaces over HTTP, no Studio API/SignalR authentication; `LanOnlyMiddleware` trusted private IPs, a network topology property not an identity | Loopback-only deployment; Bearer token required on API/SignalR; remote non-HTTPS refused; private IP cannot grant authorization |
| High | Studio RESP client accepted unlimited nested/bulk responses and concatenated commands into inline strings | RESP bulk-array framing, bounded decoding and timeouts; non-loopback plain-TCP prohibited |
| Medium | Studio telemetry used invented healthy states, synthetic QPS, latency and memory, masking outages | Node state unavailable/unconfigured on failed probes; nonexistent metrics reported as zero/unknown |
| Medium | API returned mock success for slot migrations and random vector-search results | HTTP 501 until real authorization-aware backend implemented |
| High test-gate | CI did not create `build/` before security regression; `mkdtemp` failed and downstream authorization tests were skipped | Create permission-restricted test state; add Studio security job; remove duplicate test groups |

### Known CI evidence

[Baseline run](https://github.com/SWORDIntel/QIHSE/actions/runs/39071628345):
- Native compile: succeeded.
- `test-consensus-mesh`: aborted in `tests/test_consensus_mesh.c:402` on `mkdtemp` (missing `build/`).
- Sanitizer compilation and RESP cluster test: succeeded.
- `test-auth-privilege-boundary`: aborted after audit recovery reported directory inaccessible; its fixture only sets `QIHSE_DATA_DIR` if `mkdtemp` succeeds.
- Dashboard lint/build: succeeded.
- Consequently the baseline is **NOT** verified green.

### Deployment actions required: credential rotation

A credential removed from Git HEAD remains exposed in Git history and potentially in existing systemd units and processes. Treat the previously published cluster password as compromised wherever reused.

1. Create a different high-entropy operator secret via a trusted system secret manager or `openssl rand -hex 32`. Distribute it securely and consistently to authorized cluster nodes; never post it in a ticket, commit, process argument, or chat.
2. Update each root-owned `/etc/qihse/cluster-nodeN.env`, `/etc/qihse/studio.env` (Studio API token independently), and any other consumer. Apply owner root and mode 0600.
3. Rotate live operator verifiers and restart/roll over service nodes with a coordinated availability plan. Ensure no old `--operator-password` remains in systemd ExecStart. Validate old credential fails and new one works.
4. Monitor for unauthorized activity before, during and after rotation; revoke other issued credentials if reuse is identified.
5. Studio is opt-in and loopback-only. Use a secure tunnel for remote use; no plaintext remote RESP connections. Networked Studio-to-cluster access requires a purpose-built verified mTLS client before enabling it.

### Review and release gates

- [ ] GitHub Actions `build-linux` tests, including classified-context denial and all auth, ACL, SCI, KV, FTS, tenant, export and federation regressions
- [ ] `sanitizers` (ASan + UBSan) on negative authorization and malformed wire frames
- [ ] `studio-security` client/server builds, 401 unauthorized, 200 valid token, 501 unimplemented mutation
- [ ] Operator deployment review: non-root Studio process, secret file permissions, local interface binding and no logs containing secrets
- [ ] Real host testing: credential rotation, malformed RESP, server restart, slow clients and network partitions
- [ ] **Full source audit still outstanding:** all 1,698 files (including vendored components), complete external input to native parser boundary mapping, concurrent state, lifetime invariants, secure protocol adapter audit, SBOM/advisories, Rust/Python code paths, fuzz campaign and persistence/backup recovery tests.

Do not interpret CI green alone as proof of freedom from vulnerabilities. Document residual risks and retest at the exact merge commit.

## Second-pass findings — 2026-10-18

- **Critical:** I2P setup contained a second published static operator credential and printed it as an argv example. Removed default and argv display, required explicit environment credential, rejected CLI password option. Existing deployed credentials MUST be rotated; Git history still exposes the old one.
- **High:** Non-loopback daemon startup was permitted without a configured operator verifier (`auth_required=false`). Refuse such startup. Development on loopback without auth remains a risk and is not production-safe.
- **High:** Generic native HTTP server listened on all interfaces but has no trusted user context; now loopback-only, with real socket bind assertions in the adapter harness. This is containment, not authenticated authorization, and the adapters MUST NOT be exposed through remote proxies.
- **Medium:** Native telemetry fabricated healthy load/latency/vector cardinality. Replaced with actual cumulative operations, measured mean latency when available and explicit unmeasured flags for QPS/vector cardinality.
- **Medium:** Studio allowed remote plaintext when `Studio:LanOnly=false`. Non-loopback connections now require HTTPS regardless of the LAN ACL toggle.
- **Medium:** Studio RESP accepted any non-error AUTH response and had unbounded async initial connect waiting. Require `+OK` response and bound initial connection to three seconds.

**Residual risks:** Native HTTP worker lifetime and parser framing remain unaudited for production guarantees. Loopback is not an authorization principal; enforce `qihse_user_t` on adapters before remote exposure. Replay/federation/key rotation, classified reads through all protocols, persistence crash recovery and third-party dependency advisories require additional review. The above changes are NOT locally compiled or tested; run CI at the new exact commit before merging.

## Follow-up: native parsing, durable paths, tokens and fleet clients

Second-pass changes on the same draft branch, committed after `b7e03c2`:
- Native HTTP parser: length-bounded, incremental request framing. Reject duplicate Content-Length, Transfer-Encoding, oversized/malformed headers, embedded-NUL materialization, surplus/pipelined data and truncated request bodies. The incomplete-frame path is explicit; socket workers are heap-buffered. Added negative parser fixtures and split-TCP-header integration test.
- Machine authentication: standard immutable SHA-384(empty) digest, overflow-safe token timestamp checks, no silent trust-roster truncation, retained nonce replay ledger across anchor reconfiguration, and atomic trusted-signature/nonce admission under one mutex. Negative regression confirms reconfiguration does not reopen an accepted nonce.
- KEYSTONE fabric index: refuse insecure directories, symlink components, attacker-writable path ancestors and shared index leaf permissions. Never truncate a predictable `.access` path or fall back to fixed `/tmp/qihse_fabric_index`. These changes intentionally make insecure deployments fail closed. Tests now allocate private build fixtures without invoking a shell.
- Cluster bus: remove pthread_mutex_destroy on an uninitialized mutex when veil-key allocation fails.
- KEYSTONE optional integration: absent `libkeystone.so` is logged as a visible SKIP after all independently exercisable tests; setting `QIHSE_REQUIRE_KEYSTONE_INTEGRATION=1` turns that omission into a hard error. CI passing without KEYSTONE is **not** proof of that integration.
- Python fleet clients: `thermal.py` and `qihse-fan-agent.py` reject remote plaintext RESP by default. Remote connections require a dedicated trusted CA via `QIHSE_RESP_CA_FILE`, an authenticated peer name via `QIHSE_RESP_SERVER_NAME`, and TLS 1.3. Local IP loopback remains usable for explicitly provisioned secure tunnels. Untrusted MOVED/ASK destinations are not followed; MACHINEAUTH refusal cannot downgrade to shared operator-password authentication. The fan-client RESP parser has bounded frame/array/depth budgets; subprocess sensor collection no longer uses shells or interpolates CSV filenames into shell commands.

**Deployment compatibility warning:** Existing direct private-LAN RESP clients will now fail closed unless backed by a TLS 1.3 listener/proxy with a dedicated CA and matching peer identity, or explicitly configured loopback tunnels. This does not create TLS support in the native RESP server. Do not disable verification to preserve connectivity.

**Remaining:** No production credential rotation, TLS-proxy deployment, network partition test, full protocol-adapter classified-read coverage, full dependency advisory review, or full fuzz campaign has been performed. Native HTTP response JSON helper OOM/format consistency, persistent manifests, systemd isolation and overlay CI failure still require attention. All changes remain unmerged until exact-commit CI and independent review.
