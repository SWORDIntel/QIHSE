# QIHSE Operations Manual

> **Status: implemented** — every command in the "Build", "Test", "Daemons
> and CLIs", and "Cluster smoke drills" sections below was executed on this
> branch (2026-09-26) unless explicitly marked *not verified here*. Commands
> marked unverified were read from the source but not executed in this pass.

This is the operator manual: how to build, test, and run every tool QIHSE
ships. It complements, and does not repeat, the [API reference](API_REFERENCE.md)
(what to call) and [COMPATIBILITY.md](COMPATIBILITY.md) (what the wire speaks).

Reading order for a new operator: [root README](../README.md) → this document →
[security documentation](security/README.md) if you expose any listener to
another host.

Repository rule that applies to everything here: paths in commands are
relative to the repository root (`./qihse`, `make …`, `./qihse-cluster-daemon`).
The build deliberately never requires an absolute home path.

---

## 0. Quick index — credentials and tools at a glance

> **For AI agents and humans in a hurry.** Everything here is expanded in the
> sections below; a machine-readable copy of the tool table lives in
> [`tools.json`](tools.json). This index is the entry point — if a fact here
> conflicts with prose below, this index wins and the prose needs fixing.

### 0.1 Credentials (single source of truth)

| What | Value / rule | Where it applies |
|---|---|---|
| Operator username | `GODMODE_OP` (user id 0, always exists) | every daemon, SDK, and `AUTH` |
| Operator password | `QIHSE_OPERATOR_PASSWORD` env var, **minimum 12 chars**, read at auth init | redis-server, cluster-daemon, federation-ca, demo, controller SDKs |
| Demo default | if `QIHSE_OPERATOR_PASSWORD` is unset, `./qihse demo` uses `qihse-demo-operator` | demo only, per-process (auth state is in-memory) |
| RESP wire auth | `AUTH GODMODE_OP <password>` (or `AUTH <password>`); `PING` answers pre-auth | redis-server, cluster-daemon |
| `--password` flag | bootstraps the credential when none is configured; must MATCH `QIHSE_OPERATOR_PASSWORD` when that env is set (mismatch = exit 2) | `qihse-redis-server --require-auth` |
| Auth is in-memory | restarting a process resets credentials to env/flag state; no password persists on disk | all tools |

Expect multi-second delays on any authentication path — the CNSA 2.0 KDF is
deliberately expensive. This is normal.

### 0.2 Tool index (task → command → credential)

| Task | Command (from repo root) | Credential needed |
|---|---|---|
| Build library | `make lib` | none |
| Full test aggregate | `make test` (~40–50 min) | none |
| Gold validation suite | `make test-gold` | none |
| Repo workflow check | `make check` | none |
| Native SDK demo | `./qihse demo` | demo default or env |
| Python REPL w/ native SDK | `./qihse python` | as demo |
| RESP server (quick) | `make redis-server && ./qihse-redis-server --port 6399` | none (loopback, no auth) |
| RESP server (auth) | `QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse-redis-server --port 6399 --require-auth --password '<same>'` | env + flag |
| Cluster daemon | `make cluster-daemon && ./qihse-cluster-daemon --index 0 --bind 127.0.0.1 --port 7101 --bus-port 7001 --slot-range 0-16383 --operator-password '<12+ chars>'` | `--operator-password` (also keys the veiled bus — all nodes must match) |
| Federation CA | `make federation-ca && QIHSE_DATA_DIR=./build/ca QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse-federation-ca init-ca` | env |
| Key generation | `./qihse_keygen` | none |
| Python controller SDK | `make test-controller-sdk-py` (usage: §3.6) | AUTH in connect config |
| Rust controller SDK | `cd rust/qihse-rs && cargo test --offline` | AUTH in connect config |
| Cluster smoke drills | `python3 tests/cluster_failover_smoke.py` (env-overridable hosts, §4) | per drill |
| All make targets | §1.2; test target list in §2.1 | — |

---

## 1. Build

### 1.1 Toolchain

`make dev-setup` (or `./qihse dev-setup`) checks the required toolchain:
`gcc`, `make`, `python3`. The full link line additionally needs OpenSSL,
`liburing`, LuaJIT 2.1, libbpf/libxdp, SQLite3, and the Python 3 dev headers.
`clang` is needed only for `make xdp-kern`. Post-quantum dependencies
(`liboqs`, `oqs-provider`) are vendored submodules that `make lib` builds and
installs into `/usr/local` on first use (skipped when already present).

### 1.2 Targets

| Command | What it does | Notes |
|---|---|---|
| `make` / `make all` | liboqs + oqs-provider + `libqihse.so` + `tests/qihse_server` + `qihse_keygen` + `qihse-federation-ca` | The default everything build |
| `make lib` | Build `libqihse.so` (with PQC deps) | Idempotent; prints `liboqs ready.` when cached. Verified |
| `make build` | `all` minus federation-ca, plus the ctypes-friendly link | |
| `make build-ctypes` | Link variant used by the ctypes Python SDK | |
| `make build-native` | `scripts/build-native.sh` (full SIMD auto-detect) | |
| `make server` | Build `tests/qihse_server` (test server binary) | |
| `make redis-server` | Build `qihse-redis-server` (standalone RESP daemon) | Verified |
| `make cluster-daemon` | Build `qihse-cluster-daemon` | Verified (also built by `make test-pqc-handshake`) |
| `make keygen` | Build `qihse_keygen` (PQC key generator) | Verified |
| `make federation-ca` | Build `qihse-federation-ca` | Verified |
| `make xdp-kern` | Compile the eBPF XDP object with `clang` | *Not verified here* |
| `make install` | Install `libqihse.so` + header into `$(DESTDIR)/usr/local` | *Not verified here* |

### 1.3 CPU ISA selection

ISA flags are auto-detected from `/proc/cpuinfo` at build time and can be
overridden on the command line:

```bash
make QIHSE_ENABLE_AVX2=1 QIHSE_ENABLE_AVX512=0 QIHSE_ENABLE_AMX=0
make isa-info     # show what the current invocation detected
```

`make isa-info` (verified) prints the four `QIHSE_ENABLE_*` values and the
resulting `-m…` flags. AVX-VNNI requires AVX2. The build stays scalar-safe on
hosts without SIMD (an AVX-only host builds and runs; see the comment block in
the `Makefile`).

### 1.4 GNUmakefile overlay — read this before editing the Makefile

`make` actually reads `GNUmakefile`, which `include`s `Makefile` and then
replaces the standalone UWP/TLS translation units with a TLS-first wrapper
(`src/spinnaker/qihse_uwp_secure.c`) and appends `test-uwp-tls` and
`test-uwp-secure-default` to the `test` aggregate. Consequence for operators:
the TLS-1.3-by-default UWP listener is what you get from a plain `make`;
building with `make -f Makefile` bypasses the overlay and is not the tested
configuration.

### 1.5 Clean

| Command | What it removes |
|---|---|
| `make clean` | Objects, `libqihse.so`, built tool binaries, listed test binaries |
| `make workspace-clean` | `data/`, `results/`, `VXUG-Papers/` (via `scripts/bootstrap-workspace.sh --clean`) |
| `make pristine` | Both of the above |
| `./qihse pristine` | `make clean` + `rm -rf data results build` |

Stale test scratch directories under `build/` are *not* removed by `clean`;
see [§6 Known issues](#6-known-issues-and-workarounds).

Header edits do not require a full clean: object rules carry `-MMD -MP`, so a
changed header rebuilds exactly the objects that included it. `make clean &&
make` is only needed after changing flags or ISA paths.

---

## 2. Test

### 2.1 The aggregate

```bash
make test        # or ./qihse test
```

Runs the full sequential list defined in `Makefile` (≈90 `test-*` targets:
auth/privilege boundary, object ACL, UWP regressions, graph, cluster
slot/numa/bus/failover/scatter, brain, overlay/DHT, federation F0–F8 + mTLS +
repl + transport + rejoin + CA + CRL + backup + consensus + incremental export,
controller SDKs, AI memory, fabric, task, e2e, persistence, bytecode, document/
column/FTS/time-series/event-stream stores, SQL completeness/DML/txn/MVCC/
indexes/optimizer governance, Bolt, MongoDB wire + security, repl, metrics,
parallel query) **plus** the two `GNUmakefile` overlay targets
(`test-uwp-tls`, `test-uwp-secure-default`), and finishes with `test-gold`.

Expected runtime: roughly 40–50 minutes on this development host (the
aggregate is sequential and dominated by federation, fabric, and gold
workloads; the gold suite alone is ≈4.5 minutes). Do not run two aggregates
concurrently — several targets create/remove shared scratch state at the
repository root (`qihse_integrity.chain*`) and under `build/`.

Note on ordering and failure: `make` runs the prerequisites of `test` in
declaration order — the `Makefile` list first, then the two `GNUmakefile`
overlay targets — and stops at the first failure. Because the aggregate ends
with `test-gold`, which is currently red (see [§2.4](#24-the-gold-validation-suite)),
a plain `make test` today exits non-zero at the gold suite and skips the two
overlay TLS targets; run `make -k test`, or those targets individually, when
you need everything attempted.

CI (`.github/workflows/build-and-test.yml`) runs the core suite plus the
security-boundary regressions, the APT41 ASan/UBSan fuzz targets, the brain/
overlay/federation families, and the Rust controller SDK
(`cargo test --locked --test controller_sdk`); consult it for the canonical
per-commit expectation.

### 2.2 Individually verified targets

Each of the following was executed on this branch and passed (2026-09-26):

| Command | Result observed |
|---|---|
| `make test-sql-dml-exec` | `PASS insert: rows land in the mutable row store and are UPDATE/DELETE-able end to end` (+ zero-condition DELETE guard, ACL grant checks) |
| `make test-bolt` | 8 PASS groups, incl. `bolt 4.x spec compliance: signatures and packstream tiny containers` and the negative-auth test |
| `make test-controller-sdk-py` | `Ran 55 tests … OK (skipped=1)` (unittest discover over `python/tests/test_controller_sdk.py`) |
| `make test-lease-liveness` | holder check, stale generation, legacy fail-closed, takeover — all PASS |
| `make test-pqc-handshake` | builds `qihse-cluster-daemon`, then `ALL TESTS PASSED (0 failures)` (opportunistic cleartext + `--pqc-require` refusal) |
| `make lib` | idempotent (`liboqs ready.` / `oqs-provider ready.`) |
| `make redis-server`, `make dev-setup`, `make docs` | succeed (`docs` only prints a pointer — there is no generated-docs build) |

Other notable single targets — all members of the aggregate; several were
also re-verified green as gold workloads on 2026-09-26:
`make test-consensus`, `make test-federation-mtls`, `make test-mongo-wire`,
`make test-mongo-wire-security` (the invariant-3 negative authorization test),
`make test-auth-privilege-boundary`, `make test-object-acl`,
`make test-backup-auth`, `make test-incremental-export`.

Sanitizer/fuzz targets outside the aggregate: `make test-apt41`,
`make test-apt41-qql` (ASan+UBSan), `make fuzz-uwp` (prints the clang
libFuzzer invocation; run with `-max_total_time=60`).

### 2.3 SDK test suites

```bash
# Python controller SDK (also inside make test):
PYTHONPATH=python LD_LIBRARY_PATH=. python3 -m unittest discover -s python/tests -p test_controller_sdk.py

# Rust controller SDK (pure-std, mock-controller tests):
cd rust/qihse-rs && LD_LIBRARY_PATH=../.. cargo test --offline
```

The Rust run was verified on this branch: 22 controller integration tests
pass (plus the lib unit tests). The FFI side of `rust/qihse-rs` links
`libqihse.so` from the repository root — hence `LD_LIBRARY_PATH=../..`.

The older compatibility SDK under `sdks/` (including `sdks/rust/src/`) has no
test target; see [API reference §12](API_REFERENCE.md#12-known-gaps-and-unverified-areas).

### 2.4 The gold validation suite

```bash
make test-gold                 # runs tests/gold/gold_runner against the pack
GOLD_STRICT=1 make test-gold   # known defects / stale expectations / gaps become fatal (exit 2)
GOLD_PACK=tests/gold/pack.v2.gold make test-gold   # pin a different pack version
```

The pack (`tests/gold/pack.v1.gold`) is data: 60 workloads across areas
(ann-rerank, relational, graph, fts-vector-fusion, persistence-recovery,
protocol-compat, distributed-failure, security-regressions, ai-fabric,
overlay-discovery, observability). Workloads either build a gold-only binary
(`bin=` under `tests/gold/workloads/`) or re-run existing make targets
(`run="make -s …"`). The security-regressions area drives the matrix in
`tests/security-regression.mk` (KV, tenant isolation, tenant privilege
ladder, SCI compartments, RESP, vector tenant isolation, blob, ingest guard,
bundle, killswitch, …).

Verdicts (see the header of `tests/gold/gold_runner.c`): `VERDICT: PASS`
(every area full, every workload passed), `VERDICT: PASS WITH CAVEATS`
(known defects/gaps printed), `VERDICT: FAIL`. Exit codes: 0 green, 1 pack
error, 2 non-green under strict. Adding a workload is a pack edit only — the
Makefile extracts the `bin=` list from the pack.

Verified on this branch (2026-09-26): `make test-gold` completes in ≈4.5
minutes and currently reports **59/60 pass, `VERDICT: FAIL`** — the
`protocol-compat/controller-api` workload aborts at
`tests/test_controller_api.c:127` (`qihse_ctrl_reply_ok` after
`qihse_ctrl_lease_renew`). Note that `test-controller-api` is *not* a member
of the plain `make test` aggregate; the gold pack is what runs it, which is
exactly the kind of coverage the pack exists to catch. Treat a red
`controller-api` gold line as a real signal, not flake (reproduced twice).

Design/motivation: [docs/development/gold_validation_suite.md](development/gold_validation_suite.md).

---

## 3. Daemons and CLIs

### 3.1 The `qihse` launcher (repository root)

`./qihse <command>` wraps the common workflows (implemented by
`qihse_launcher.py`). Verified on this branch: `status`, `version`,
`isa-info`, `db --help`, `dev-setup`, and `build` (which delegates to
`make build`). `test` and `bench` delegate to the same `make` targets
documented below (not re-run through the launcher here). Full command list
is in `./qihse --help`.

`./qihse demo` runs the native-SDK smoke (KV, document, columnar, time-series,
auth, wire proxies) end to end. The launcher exposes the native CPython
extension compiled into `libqihse.so` as `build/bin/qihse.so` (so `import
qihse` resolves to it ahead of the ctypes package) and defaults
`QIHSE_OPERATOR_PASSWORD` to `qihse-demo-operator` when unset, which the demo
uses to establish the operator session. Expect several seconds of CNSA KDF
work at startup.

### 3.2 `qihse-cluster-daemon`

Build: `make cluster-daemon`. Full flag surface: `./qihse-cluster-daemon`
with no arguments prints the usage block (also reproduced in
`tools/qihse_cluster_daemon.c`).

Minimal verified single-node invocation (loopback, RESP + cluster bus):

```bash
./qihse-cluster-daemon \
    --index 0 --bind 127.0.0.1 --port 7100 --bus-port 17100 \
    --node 0:127.0.0.1:7100:17100 \
    --slot-range 0-16383 \
    --operator-password 'change-me-12+chars' \
    --dir ./build/node0
```

Verified behavior (2026-09-26):

- The operator password must be **at least 12 characters** (shorter passwords
  exit at startup).
- `AUTH <password>` (RESP 2-arg form) authenticates as the operator user
  (`GODMODE_OP`); `AUTH <user> <password>` also works.
- A node with no `--slot-range` answers `SET`/`GET` with
  `-CLUSTERDOWN Hash slot not served` — a single-node deployment must own
  `0-16383`.
- `FTS.BUILD <glob>` then `FTS.SEARCH <query>` works against the node's local
  KV (in-memory BM25 index; resets on restart).
- Needs `LD_LIBRARY_PATH=.` when invoked directly (the Makefile targets set
  it for you).

Key flags (from usage): `--node INDEX:HOST:PORT:BUS-PORT` (static topology,
repeatable) or `--join HOST:BUS-PORT` (gossip discovery from a seed);
`--slot-range[-of INDEX] FIRST-LAST`; `--redundancy-peer HOST:PORT`;
`--replicate GLOB` + `--replicate-interval S` (sovereign-local namespaces
with anti-entropy pull; deletes are not propagated); `--max-clients N`;
`--enable-scatter`; `--brain` / `--brain-act` and the `--brain-*` tuning
flags; PQC: `--pqc-identity-dir`, `--pqc-trusted-pub` (repeatable),
`--pqc-require` (refuse cleartext peers — verified by `make
test-pqc-handshake`). Ports: one RESP port and one cluster-bus port per node.

### 3.3 `qihse-redis-server`

Build: `make redis-server`. Flags (from `--help`): `--port N` (default 6379),
`--bind ADDR` (default 127.0.0.1), `--dir PATH` (default `/var/lib/qihse` or
`$QIHSE_DATA_DIR`), `--require-auth`, `--password PASS`, `--pubsub-dir PATH`,
`--channel-classif N`, `--channel-sci N`, `--uwp-port N`.

Verified minimal invocation (2026-09-26):

```bash
QIHSE_OPERATOR_PASSWORD='change-me-12+chars' \
LD_LIBRARY_PATH=. ./qihse-redis-server \
    --port 6379 --bind 127.0.0.1 --dir ./build/redis \
    --require-auth --password 'change-me-12+chars'
```

Then `AUTH <password>` / `SET` / `GET` succeed over RESP; `PING` is answered
before authentication (matches Redis). Non-loopback binds without auth are
rejected by the engine itself.

`--password` semantics (verified): on a store with no configured verifier
it bootstraps the operator password from the flag (minimum 12 characters) and
serving proceeds. When a verifier is already configured — i.e.
`QIHSE_OPERATOR_PASSWORD` is set in the environment — the flag value must
match it (idempotent restart); a mismatching value is refused loudly with
exit code 2 rather than silently serving with the old credential. Runtime
rotation of an existing credential goes through `USER.MODIFY` with operator
credentials, per the auth invariants.

### 3.4 `qihse-federation-ca`

Build: `make federation-ca`. Deliberately out-of-process from the server (a
CA-minting primitive must not live inside the daemon). `help` prints the
subcommands: `init-ca`, `issue-node`, `revoke`, `verify` (options in the
usage block; common `--auth-dir`, defaults to `$QIHSE_DATA_DIR` or
`./build/qihse_ca_provision`; the operator bootstrap password is read from
`QIHSE_OPERATOR_PASSWORD`).

Verified round (2026-09-26):

```bash
QIHSE_DATA_DIR=./build/ca QIHSE_OPERATOR_PASSWORD='change-me-12+chars' \
    ./qihse-federation-ca init-ca --key ./build/ca/ca.key --cert ./build/ca/ca.crt \
    --alg ml-dsa-87
# → "CA created", prints the CA fingerprint to record out of band.
```

Certificate lifecycle is covered by `make test-federation-ca` /
`make test-federation-crl`.

### 3.5 `qihse_keygen`

Build: `make keygen`. Usage: `./qihse_keygen [output-dir]` (default
`/opt/qihse/keys`; the Makefile build overrides the compiled-in default with
an empty string so the argument wins). Verified: writing to a scratch
directory produces `qihse_kem_key.pem` / `qihse_kem_pub.pem` (ML-KEM-1024)
and `qihse_dsa_key.pem` / `qihse_dsa_pub.pem` (ML-DSA-87). Also wrapped as
`./qihse keygen [dir]`.

### 3.6 Python ctypes SDK

The importable package is `python/qihse` (not `sdks/python`, which hosts the
native CPython extension and the compatibility clients):

```bash
PYTHONPATH=python LD_LIBRARY_PATH=. python3 - <<'EOF'
import numpy as np
import qihse
from qihse import QueryMode

with qihse.VectorDB.create("./build/demo-vdb", dims=8) as db:
    v = np.random.rand(20, 8).astype(np.float32)
    db.add_vectors(v, ids=list(range(20)))
    db.build_graph()                       # required for the default GRAPH mode
    print(db.search(v[0], k=3))            # [VectorResult(id=0, score=...), ...]
    # or, without a graph: db.search(v[0], k=3, mode=QueryMode.FLOAT32)

kv = qihse.KVStore()
kv.set("k", "v")
assert kv.get("k") == "v"
EOF
```

Verified (2026-09-26). The `build_graph()` call is load-bearing: the default
query mode is HNSW (`QueryMode.GRAPH`) and searching an unbuilt graph raises
`RuntimeError: Search failed`. Exact `QueryMode.FLOAT32` works without a graph.
`./qihse python` starts a REPL with this SDK importable (note its
`QihseDB()` hint is stale — that class belongs to the native extension).

`scripts/qihse-db` (also `./qihse db`) is the vector-DB CLI: `create`,
`insert`, `build-graph`, `build-int8`, `search`, `stats`
(`./qihse db --help` verified).

---

## 4. Cluster smoke drills

`tests/cluster_*_smoke.py` are operational drills over real RESP sockets.

**Self-contained (starts its own daemons):**

```bash
QIHSE_NODE0_PORT=17700 QIHSE_NODE1_PORT=17701 \
QIHSE_NODE0_BUS_PORT=17800 QIHSE_NODE1_BUS_PORT=17801 \
QIHSE_DATA_DIR=./build/cluster-smoke \
python3 tests/cluster_failover_smoke.py
```

Verified (2026-09-26): `failover drill: 5/5 checks passed` — writes on the
lead, ASKING read on the successor, SIGKILL of the lead, slot takeover, and
survival of the duplicated key. Environment knobs (all optional):
`QIHSE_BIN` (default `./qihse-cluster-daemon`), `QIHSE_LIB_DIR` (default `.`),
`QIHSE_DATA_DIR` (default `./build/cluster-smoke`), `QIHSE_NODE0_HOST` /
`QIHSE_NODE1_HOST`, `QIHSE_NODE0_PORT` / `QIHSE_NODE1_PORT`,
`QIHSE_NODE0_BUS_PORT` / `QIHSE_NODE1_BUS_PORT`,
`QIHSE_CLUSTER_PASSWORD`, and (for remote successors) `QIHSE_SSH_TARGET`.

**Connect-to-existing (defaults are the lab pair, override before use
elsewhere):** `tests/cluster_smoke.py` (two-node routing + MOVED redirects),
`tests/cluster_discover_smoke.py` (--join membership discovery; run after
bringing up a seed node), `tests/cluster_loadshift_smoke.py`
(`CLUSTER MOVESLOTS` ownership flip). All honor `QIHSE_NODE0_HOST` /
`QIHSE_NODE0_PORT` / `QIHSE_NODE1_HOST` / `QIHSE_NODE1_PORT` /
`QIHSE_CLUSTER_PASSWORD`. *Not verified in this pass* (they require a running
two-node cluster; only the failover drill is self-starting).

---

## 5. Environment variables an operator actually touches

| Variable | Used by | Meaning |
|---|---|---|
| `QIHSE_DATA_DIR` | redis-server, federation-ca, various tests | Data/auth store directory |
| `QIHSE_OPERATOR_PASSWORD` | auth core (`qihse_auth_init`) | Operator credential (min 12 chars); the source of truth for daemon/tool auth |
| `QIHSE_UWP_TLS_CERT` / `QIHSE_UWP_TLS_KEY` | UWP server / Python `UWPServer` | Certificate for the TLS-1.3-by-default listener |
| `QIHSE_UWP_ALLOW_INSECURE` | UWP server | `1` opts into cleartext (development only) |
| `QIHSE_ENABLE_AVX2/AVX512/AVX_VNNI/AMX` | build | ISA overrides (see [§1.3](#13-cpu-isa-selection)) |
| `QIHSE_AUDIT_WEBHOOK_URL` | build (`CFLAGS` define) | Webhook for classified-access callouts |
| `GOLD_PACK`, `GOLD_STRICT` | `make test-gold` | Pack pinning / strict verdicts |
| `QIHSE_STRESS_*` | `make stress-session-delivery` | Tenant count, duration, MB range, cycle |

The full configuration-knob inventory (including storage prefixes and engine
knobs) is [API reference §11](API_REFERENCE.md#11-configuration-knobs).

---

## 6. Known issues and workarounds

- **Stale `build/<prefix>_XXXXXX` scratch dirs.** Tests create throwaway
  `build/<name>_<random>` directories; an interrupted run leaves them behind
  and a later teardown assert can trip on them. Workaround:
  `rm -rf build/<prefix>_*` (safe — everything under `build/` is disposable)
  and re-run. (A retry was recently added to the `node_cap_records` teardown;
  older flakes may still surface elsewhere.)
- **`[QIHSE AUDIT] Integrity chain mismatch detected (non-fatal in default mode)`.**
  Emitted by `core/qihse_audit.c` when a stale `qihse_integrity.chain` in the
  working directory does not match the current state. Non-fatal by design in
  the default development mode; delete the stale root-level
  `qihse_integrity.chain` to silence it. Several `make` targets
  (`test-e2e`, `test-omni`, `test-kv-read-integrity`) already remove it
  before running.
- (Resolved 2026-09-26: `make check` expected a stale upstream layout — the
  workflow checker now verifies current paths; `./qihse demo` runs end to end
  (native module exposed via `build/bin/qihse.so`, see [§3.1](#31-the-qihse-launcher-repository-root));
  `qihse-redis-server --password` now bootstraps-or-verifies per [§3.3](#33-qihse-redis-server);
  and the `controller-api` gold failure — leases born expired under the
  Phase-B strictening — was fixed by the lease wire TTL contract, gold is
  60/60 again.)
- **One `make test` at a time.** Aggregate targets share root-level and
  `build/` scratch state; concurrent aggregates or concurrent runs of the
  same target can interfere (e.g. `qihse_integrity.chain` removal races).
- **`make docs` is a stub** — documentation is maintained by hand in
  markdown; there is no generated-docs pipeline.

Anything security-relevant here is a symptom, not noise: report
auth-bypass-shaped behavior (wrong `WRONGPASS`, missing `NOAUTH`/`NOPERM`)
rather than working around it. The security invariants themselves are defined
in the repository-root [`AGENTS.md`](../AGENTS.md) and must never be weakened
by configuration.

---

## 7. See also

- [API reference §11 — configuration knobs](API_REFERENCE.md#11-configuration-knobs)
- [Deployment guide](deployment/README.md) (partially stale; it says so itself)
- [AF_XDP operational guide](manual/deployment/AF_XDP_OPERATIONAL_GUIDE.md)
- [Replication and backup](architecture/replication_backup.md) ·
  [Operational protocols](architecture/operational_protocols.md)
- [Gold validation suite design](development/gold_validation_suite.md)
- [Security documentation](security/README.md)
