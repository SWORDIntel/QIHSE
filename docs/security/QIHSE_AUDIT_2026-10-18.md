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
