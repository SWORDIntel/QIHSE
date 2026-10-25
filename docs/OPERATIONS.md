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

For the authenticated transaction bridge, `QIHSE.TXN.READ` routes through the
leader and remains the application replay command. `QIHSE.TXN.READLOCAL`
reads only the contacted member's committed prefix and requires an authenticated
Operator principal. Its cursor is a local watermark; it must not be treated as a
cluster-wide read or followed to another member. This recovery inspection
command has not been exercised on a live daemon in this update.

---

## 0. Quick index — credentials and tools at a glance

> **For AI agents and humans in a hurry.** Everything here is expanded in the
> sections below; a machine-readable copy of the tool table lives in
> [`tools.json`](tools.json). This index is the entry point — if a fact here
> conflicts with prose below, this index wins and the prose needs fixing.

### 0.1 Credentials & Operating Modes (single source of truth)

- **Default Single-User God-Mode (`auth_required == false`):**
  By default, QIHSE operates in frictionless 1-user god-mode. User 0 (`GODMODE_OP`,
  clearance `0xFFFF`, SCI compartments `0xFFFF`) is active without mandatory
  password bootstrapping or authentication walls, allowing developers to build fast.
- **Opt-In Security Mode (`auth_required == true`):**
  When opt-in security is enabled (via `--require-auth` or explicit operator password
  bootstrapping), network services require explicit authentication, tenant boundaries
  are enforced, and low-clearance requests fail closed (`NOAUTH`/`NOPERM`).

| What | Value / rule | Where it applies |
|---|---|---|
| Operator username | `GODMODE_OP` (user id 0, always exists) | every daemon, SDK, and `AUTH` |
| Operator password | `QIHSE_OPERATOR_PASSWORD` env var, **minimum 12 chars**, read at auth init | redis-server, cluster-daemon, federation-ca, demo, controller SDKs |
| Demo default | if `QIHSE_OPERATOR_PASSWORD` is unset, `./qihse demo` uses `qihse-demo-operator` | demo only, per-process (auth state is in-memory) |
| RESP wire auth | `AUTH GODMODE_OP <password>` (or `AUTH <password>`); `PING` answers pre-auth | redis-server, cluster-daemon |
| `--password` flag | bootstraps the credential when none is configured; must MATCH `QIHSE_OPERATOR_PASSWORD` when that env is set — mismatch exits 2 (enforced in `tools/qihse_redis_server.c`: the server refuses rather than silently rotating the credential) | `qihse-redis-server --require-auth` |
| Auth is in-memory | restarting a process resets credentials to env/flag state; no password persists on disk (decision record: [auth_persistence.md](architecture/auth_persistence.md)) | all tools |

Expect multi-second delays on any authentication path — the CNSA 2.0 KDF is
deliberately expensive. This is normal. (Repeated authentications leverage the
in-memory password verifier cache to reduce subsequent latency).


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
| RESP server with real semantic memory | append `--embedder-onnx <model-dir>` (ONNX BERT model + `vocab.txt`); fatal on failure, vectors bound to the model name | env + flag + model |
| AI-memory over RESP | `AUTH` then `AIMEM STORE/RECALL/GET/FORGET/COUNT` plus opt-in `STORE-DURABLE`/`FORGET-DURABLE` (`docs/architecture/aimem_resp_protocol.md`); legacy ACKs are eventually-durable, whereas the durable variants fsync the native KV/WAL before success. Idempotency conflict checks now bind key to exact kind/content; idempotent v2 records use deterministic UUIDs to recover pre-map crashes without duplicates; multi-record admission is still not transactional | principal |
| Cluster daemon | `make cluster-daemon && QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse-cluster-daemon --index 0 --bind 127.0.0.1 --port 7101 --bus-port 7001 --slot-range 0-16383` | Prefer a root-only systemd `EnvironmentFile`; all nodes must use the same value because it keys AUTH and the veiled bus. `--operator-password` remains available for development. |
| Operator browser (web) | `QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse browse --node <host:port> [--node …]` → `http://localhost:8090` — no login wall (operator-context default); UI asks only for the YubiKey touch on guarded actions; `--require-login` restores per-principal two-factor login | env or `--password`; YubiKey FIDO for actions |
| Operator browser (headless) | `QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse browse --dump overview\|cluster\|federation\|keys --node <host:port>` | env or `--password` |
| Federation CA | `make federation-ca && QIHSE_DATA_DIR=./build/ca QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse-federation-ca init-ca` | env |
| Key generation | `./qihse_keygen` | none |
| Python controller SDK | `make test-controller-sdk-py` (usage: §3.6) | AUTH in connect config |
| Rust controller SDK | `cd rust/qihse-rs && cargo test --offline` | AUTH in connect config |
| Federation CA rotate-node | `QIHSE_DATA_DIR=./build/ca QIHSE_OPERATOR_PASSWORD='<12+ chars>' ./qihse-federation-ca rotate-node --ca-key ./build/ca/ca.key --ca-cert ./build/ca/ca.pem --crl ./build/ca/revocations.crl --node-uuid <uuid> --pubkey-hex <hex> --out ./new.pem` | env |
| Signed bus ops test | `make test-bus-signed-ops` | none |
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
| `make install-host` | Automated hardware ISA detection, build, `/opt/QIHSE` install, PQC keygen & systemd launch (`scripts/install_qihse.sh`) | Verified |

### 1.3 CPU ISA selection & Automated Host Installer

QIHSE includes an automated hardware-optimizing installer: [scripts/install_qihse.sh](file:///home/john/Documents/QIHSE/scripts/install_qihse.sh).

```bash
# Dry run to inspect detected CPU ISAs and planned compiler flags
./scripts/install_qihse.sh --dry-run

# Interactive installation (prompts for solo vs cluster mode & expected peers)
sudo ./scripts/install_qihse.sh
# or via make
make install-host

# Non-interactive solo node installation (owns all slots 0-16383)
sudo ./scripts/install_qihse.sh --solo -y

# Multi-node cluster installation waiting for 3 LAN nodes to acknowledge
sudo ./scripts/install_qihse.sh --cluster --expected-nodes 3 --join 192.168.1.90:17115
```

The installer performs 7 automated phases:
1. **CPU ISA Detection**: Inspects `/proc/cpuinfo` for AVX, AVX2, FMA, AVX-512 (F/DQ/BW/VL), AVX-VNNI, AMX (TILE/INT8/BF16), and ARM NEON/SVE. Sets `QIHSE_ENABLE_AVX2`, `QIHSE_ENABLE_AVX512`, `QIHSE_ENABLE_AVX_VNNI`, `QIHSE_ENABLE_AMX`, and compiler flags (`-march=native -mtune=native`).
2. **Network Topology Discovery & LAN Subnet Probing**:
   - Detects existing systemd services (`qihse-node*.service`), automatically preserving existing node indices, assigned slot ranges, peer lists, and bind IPs.
   - **Automatic LAN Peer Scanning**: Probes the host's `/24` subnet on default QIHSE ports (7100, 7101, 7115, 17100, 17115). If peers are found on the LAN, the installer displays them, auto-populates join seeds, and proposes joining the multi-node cluster. If no peers are found, it defaults to a solo standalone node. (Can be skipped via `--no-scan`).
   - Mode resolution:
     - **Solo Standalone Node**: Configures the node to own 100% of the cluster keyspace (`--slot-range 0-16383`), asks whether to bring the service online immediately or leave offline (`--no-launch`), and prints clear guidance to re-run the installer when adding a second machine to update and join the cluster.
     - **Multi-Node Cluster**: Prompts for the total number of expected cluster nodes on the LAN (`--expected-nodes N`), prompts for peer join seeds, and configures the cluster topology.
3. **Hardware-Tuned Build**: Runs `make clean` by default (overridable with `--no-clean`), sets verbose logging by default (`--verbose`, overridable with `--quiet`), and uses half available host cores (`-j $(nproc/2)`) to compile `libqihse.so`, `qihse-cluster-daemon`, `qihse_keygen`, and companion binaries.
4. **Filesystem Installation**: Installs binaries and shared libraries into `/opt/QIHSE/bin` and `/opt/QIHSE/lib`, with timestamped backups of existing binaries.
5. **NIST CNSA 2.0 PQC Provisioning**: Provisions ML-KEM-1024 and ML-DSA-87 keypairs into `/etc/qihse/keys` with `0700`/`0600` permissions and exports the local hostname public identity (`qihse_dsa_pub_<hostname>.pem`).
6. **Systemd Service, Boot Launch & Cluster Acknowledgement**:
   - Generates `/etc/systemd/system/qihse-node<N>.service`, configures peer trust anchors, and executes `systemctl enable` so the service is installed to launch automatically on system boot.
   - If service launch is enabled (default), starts/restarts the systemd unit, verifies local daemon PING health, and in multi-node mode waits for cluster bus acknowledgement from all expected nodes (`--wait-timeout` default 45s) with a live discovery counter.
7. **KEYSTONE Companion Indexing Service Integration**:
   - Checks if KEYSTONE is installed at `/opt/KEYSTONE`.
   - If missing, explains that KEYSTONE is the recommended companion indexing service providing SIMD-accelerated vector and trigram search with the Unified Wire Protocol bridge to QIHSE, and offers to clone and install it from `https://github.com/SWORDIntel/KEYSTONE.git`.


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

**Parallel invocation (default since 2026-09-26):** `make -j8 test` — every
test binary isolates its audit chain/log under `QIHSE_DATA_DIR` (a per-test
`build/<target>_XXXXXX` scratch dir), so targets run concurrently safely.
Measured on the reference box: the full aggregate drops from ~40–50 min
serial to **~5 min** (the gold suite is the critical path). One aggregate
at a time still applies — two concurrent `make test` runs would race the
shared `build/` compile artifacts.

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
parallel query) **plus** the two prerequisites added by `GNUmakefile`
(`test-uwp-tls`, `test-uwp-secure-default`), and includes `test-gold`.

The 2026-10-24 sequential aggregate took about 39 minutes on this host;
gold workloads accounted for 828.5 seconds, excluding build time. Do not run
two aggregates concurrently — several targets create/remove shared scratch state at the
repository root (`qihse_integrity.chain*`) and under `build/`.

Note on ordering and failure: `make` runs the prerequisites of `test` in
declaration order — the `Makefile` list first, then the two prerequisites
added by `GNUmakefile` — and stops at the first failure. `test-gold` is not the final
direct test in the current aggregate. In the 2026-10-24 run the pack was green
(72/72 workloads, 11/11 areas FULL, zero recorded gaps — see
[§2.4](#24-the-gold-validation-suite)), so a plain `make test` runs to the
end; historical note: it was red for a stretch and `make -k test` remains
the way to attempt everything past a failure.

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

The pack (`tests/gold/pack.v1.gold`) is data: 72 workloads across 11 areas
(ann-rerank, relational, graph, fts-vector-fusion, persistence-recovery,
protocol-compat, distributed-failure, security-regressions, ai-fabric,
overlay-discovery, observability). The 2026-09-29 W7 wave added the consensus
membership suite (roles/joint/drift), snapshot transfer, the ingest contract,
the browser negative-auth, QKP identity and feed-wire suites, and the
self-spawning failover drill — the first workload that kills a REAL daemon
peer (SIGKILL, successor takes all 16384 slots, a preseeded key survives) —
plus the hermetic discovery drill and loadshift refusal guard (loopback
--self-spawn),
the fusion recall/latency gate, non-vector index byte accounting, and
backend busy-time accounting. Board: **72/72 pass, 11/11 areas FULL, zero
recorded gaps**; the drills were hardened to pass reliably under CPU
starvation (by-condition readiness waits, leak-proof teardown). Workloads either build a gold-only binary
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

Verified again on 2026-10-24: the gold pack completed with **`VERDICT: PASS`
— 72/72 workloads, 11/11 areas FULL, zero declared gaps**. Its workloads took
828.5 seconds in total on this host, excluding build time. The failover drill
tests survival of a preseeded value; the loadshift guard tests fail-closed
refusal while secure data-bearing transfer is unavailable. See CT.1–CT.2 in
`ROADMAP.md` for those open capabilities. Historical
note for perspective: the pack was red at 59/60 for a stretch in the
2026-09-26 round (a `controller-api` abort that `make test` alone never
ran — exactly the kind of coverage the pack exists to catch); that defect
is long fixed and the board is now fully green.

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
`--slot-range[-of INDEX] FIRST-LAST`; `--redundancy-peer HOST:PORT`
(rejected until pinned QKP write duplication is implemented);
`--replicate GLOB` + `--replicate-interval S` (sovereign-local namespaces
with anti-entropy pull; deletes are not propagated); `--max-clients N`;
`--enable-scatter`; `--brain` / `--brain-act` and the `--brain-*` tuning
flags; PQC: `--pqc-identity-dir`, `--pqc-trusted-pub` (repeatable),
`--pqc-require` (refuse cleartext peers — verified by `make
test-pqc-handshake`). Ports: one RESP port and one cluster-bus port per node.

### 3.2.1 Replication Transports & Mutual Pinning

QIHSE provides one-way authenticated KV replication between nodes with end-to-end
Post-Quantum Cryptography (CNSA 2.0: ML-KEM-1024 and ML-DSA-87) over sealed QKP1
sessions.

#### Transport Modes

1. **Direct RFC1918 Private LAN / WireGuard Mesh (Default)**:
   - Configured with `--replication-transport direct` or `--replication-transport wireguard`
     (or omitted, as direct RFC1918 is the default).
   - Connects directly via standard kernel TCP to a private RFC1918 IPv4 address
     (`10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`) over local LAN (e.g. `192.168.1.90`
     for 730xd) or an encrypted WireGuard mesh interface (`10.249.73.0/24`).
   - External internet or public IP addresses are strictly rejected.

2. **I2P Garlic Transport (Strictly Opt-In)**:
   - **Opt-in Only**: Must be explicitly activated using `--replication-transport i2p`.
     Attempting to specify an `.i2p` destination without `--replication-transport i2p`
     will cause `qihse-cluster-daemon` to exit immediately with an error.
   - Connects only through a local loopback SOCKS5 proxy (`127.0.0.1:4447`, configurable via
     `--replication-socks-port`).
   - The QIHSE daemon never generates raw Internet packets; all inter-node garlic
     routing is handled out-of-process by the local `i2pd` daemon.
   - Fast 1-hop tunnels (`inbound.length = 1`, `outbound.length = 1`, `quantity = 3`)
     provide low-latency replica transfer while concealing node topologies.

#### Mutual QKP1 Identity Pinning (No TOFU)

Replication data plane access requires cryptographic mutual authorization:
- **Replica (Client)** pins the upstream primary via `--replication-peer-node-id <id>`
  and `--replication-peer-dsa-pub <path>`. The client verifies the server's ML-DSA-87
  identity key fingerprint during the QKP1 handshake before sending any credentials.
- **Primary (Server)** pins the authorized replica via `--replication-peer-node-id <id>`
  and `--replication-peer-dsa-pub <path>`. When a client connects and requests
  `REPL.SNAPSHOT.BEGIN` or `REPL.DELTA`, the primary enforces `qihse_resp_repl_data_plane_allowed()`.
  Connections lacking a matching ML-DSA fingerprint receive:
  `-NOPERM REPL requires QKP1 from the pinned peer`.

#### Deployed Replication Topology (the supported wiring)

Replication runs as **dedicated read-only replica daemon instances**, one
namespace each, because the puller requires `--replica-read-only` (a
read-only store) and **exactly one** `--replicate` namespace:

```
node0 (t420)   --serves--> replica-730xd (audit/*, chain:*)
node5 (730xd)  --serves--> replica-t320  (tool:*, sabot/*)
node1 (t320)   --serves--> replica-t420  (keystone/*, kp14/*)
```

- Every master pins **one** peer identity (one replica host) with
  `--replication-peer-node-id`/`--replication-peer-dsa-pub`; the replica
  host runs one systemd unit (`qihse-replica-<ns>.service`) per namespace,
  all sharing the host identity (`--pqc-node-id replica-<host>`).
- Replica units set `Environment=LD_LIBRARY_PATH=<lib dir>` (the daemon
  otherwise loads a stale system libqihse.so) and pull on a 60 s socket
  timeout (large-store snapshot exports exceed the old 5 s limit).
- The replication service principal (`--replication-principal-id`, default
  65535) is a **non-Operator** principal provisioned automatically at
  startup; the KV replica-plane (cursors, snapshot install, record apply)
  accepts it via `qihse_kv_store_set_replication_principal_id()`.
- Setting any replication pin makes the master **QKP-only for RESP**
  (`pqc_require`): cleartext clients are rejected, including `redis-cli`.
  Operator access then goes through the pinned admin identity — see the
  next section.

Deploy/verify with `scripts/cluster_replica_deploy.sh` (unit generation +
`--status`/`--remove`).

#### Operator Access on Hardened Masters (`qihse-admin-cli`)

`pqc_require` masters reject password AUTH and MACHINEAUTH tokens are
scoped to the agent namespace (`t:<tenant>/machine/<id>/*`), so operator
access uses a **pinned administrator identity** — the same mutual-pin
mechanism as replication, mapped to the system operator:

```bash
# master unit:
--admin-peer-node-id admin-t420 --admin-peer-dsa-pub /etc/qihse/keys/qihse_dsa_pub_t420.pem

# client (tools/qihse_admin_cli.c):
qihse-admin-cli --host 192.168.1.90 --port 7115 \
    --node-id admin-t420 \
    --trusted-pub /etc/qihse/keys/qihse_dsa_pub_730xd.pem \
    --cluster-nodes
```

The pinned identity maps to the system operator (`QIHSE_RESP_AUTH_QKP_ADMIN`,
full command scope). Health probes in `cluster_rolling_restart.sh` and
`install_qihse.sh` use this path, falling back to redis-cli password AUTH
only for non-hardened deployments.

#### Slot Migration Durability (COPY → PERSIST → SWITCH → GC)

`CLUSTER MOVESLOTS` (and the brain's `--brain-act` re-home) moves a
data-bearing slot range between masters over the pinned-QKP transport
(`--migration-peer <node-id> <dsa-pub>`, repeatable for full-mesh migration).
The transfer is data-safe by construction:

1. **COPY** — keys stream to the target; the source keeps its copy.
2. **SWITCH** — ownership flips only after every key is ACKed by the target.
3. **PERSIST** — the ownership delta is appended to a durable journal
   (`<data-dir>/slot-ownership.journal`) on *both* ends, so a restart replays
   it (adopt-if-newer by per-owner config epoch) instead of reverting to the
   static `--slot-range` map.
4. **GC** — on the next startup the source reclaims keys whose slot has moved
   away, but only when the journal recorded a migration, so normal restarts
   pay no scan cost.

The invariant: **a key is never present in zero places.** COPY guarantees
reachability across any restart, and the journal makes the ownership (and the
subsequent GC) correct rather than merely safe.

#### Provisioning Helper Script (`scripts/setup_i2p_replication.sh`)

To simplify secure certificate generation and daemon configuration, use
[scripts/setup_i2p_replication.sh](file:///home/john/Documents/QIHSE/scripts/setup_i2p_replication.sh):
- **Constants at Top of File**: Node IDs, ports, tunnel lengths, and hardening parameters
  are clearly defined constants at the top of the script.
- **`gen-keys`**: Derives ML-KEM-1024 and ML-DSA-87 keypairs with `0600` permissions and
  registers the DSA public identity into `/opt/qihse/data/peers/<node_id>.pem`.
- **`harden-i2pd`**: Writes a hardened, loopback-only `/etc/i2pd/i2pd.conf` that disables
  the web console, SAM, BOB, I2CP, and UPnP to minimize local attack surfaces.
- **`setup-primary`**: Configures the primary node, sets up the I2P server tunnel in
  `/etc/i2pd/tunnels.conf.d/qihse-upstream.conf`, establishes LeaseSets, and prints
  the primary startup command.
- **`setup-replica`**: Configures the replica node, adds the upstream Base32 address into
  the addressbook, enables SOCKS5, and prints the replica command with opt-in flags.
- **`status`**: Checks running daemons, SOCKS5 listener, PQC key permissions, and peer certs.

#### Durability & Verification

- Snapshot creation records a durable intent and streams consistent rows in chunks.
- Delta enumeration requests one row at a time with monotonic `REPL.ACK` progression.
- Compaction retains tombstones across baseline boundaries until acknowledged.
- Code-level validation is verified by `make test-replica-qkp` and `make test-replica-crash`.
- Real-world deployment smoke testing was verified across Proxmox LXC containers
  (`stageb-node1`, `stageb-node2`, `stageb-node3`) with strict Layer-2 bridge isolation
  (`ebtables` dropping all IPv4 and ARP between containers).

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

### 3.7 AIMEM backup and legacy-scope migration

Build the authenticated whole-store backup utility with `make backup-cli`.
Stop the service that owns the data directory before creating a backup. Supply
the Operator credential through `QIHSE_OPERATOR_PASSWORD` or a regular file
readable only by its owner; the utility does not accept a password argument.

```bash
QIHSE_DATA_DIR=./build/aimem-data \
QIHSE_OPERATOR_PASSWORD="$AIMEM_OPERATOR_PASSWORD" \
    ./qihse-backup backup --output ./build/aimem-pre-migration.qbak

QIHSE_DATA_DIR=./build/aimem-data \
QIHSE_OPERATOR_PASSWORD="$AIMEM_OPERATOR_PASSWORD" \
    ./qihse-backup verify --input ./build/aimem-pre-migration.qbak
```

Legacy unscoped memories require a reviewed destination for every UUID. With
the service running and legacy writes quiescent, a fully cleared system
Operator can page through the content-free UUID inventory using `AIMEM LEGACY
SCAN <cursor> <count>`. Cursor `0` starts and ends an inventory.

The migration client accepts a version-2 JSON manifest. The manifest binds
every legacy UUID to one existing non-Operator target principal; individual
records cannot override that identity:

```json
{
  "version": 2,
  "target_user_id": 65000,
  "records": [
    {
      "uuid": "00000000-0000-4000-8000-000000000000",
      "project": "reviewed-project",
      "worktree": "",
      "workstream": "",
      "session": ""
    }
  ]
}
```

Run a complete preflight before mutation, then retain the checkpoint beside
the manifest for restartable execution:

```bash
QIHSE_AIMEM_MIGRATION_PASSWORD="$AIMEM_OPERATOR_PASSWORD" \
    python3 tools/qihse_aimem_migrate.py --username GODMODE_OP \
    --manifest ./build/aimem-scopes.json \
    --dry-run

QIHSE_AIMEM_MIGRATION_PASSWORD="$AIMEM_OPERATOR_PASSWORD" \
    python3 tools/qihse_aimem_migrate.py --username GODMODE_OP \
    --manifest ./build/aimem-scopes.json \
    --checkpoint ./build/aimem-migration.checkpoint
```

The client refuses incomplete inventories, duplicate UUIDs, invalid scope
chains, per-record target overrides, and records that are neither still legacy
nor already owned by the target principal at the exact manifest destination.
Do not infer scope from memory text. Older QKV,
QHEV, QHH, QHK, QHM and QHI versions remain readable and upgrade through their
normal mutation or rebuild paths; they do not require a blanket conversion.

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

Current drill: `failover drill: 6/6 checks passed` — rejects the disabled
plaintext redundancy flag, writes on the lead, seeds and reads an
unclassified duplicate on the successor through authenticated RESP, kills
the lead, checks slot takeover, and checks survival of the seeded key. This
does not claim live write duplication. Pinned QKP replica pull is tested
separately and currently requires a read-only replica, so integrated
replication to a promotable successor remains open. Environment knobs (all optional):
`QIHSE_BIN` (default `./qihse-cluster-daemon`), `QIHSE_LIB_DIR` (default `.`),
`QIHSE_DATA_DIR` (default `./build/cluster-smoke`), `QIHSE_NODE0_HOST` /
`QIHSE_NODE1_HOST`, `QIHSE_NODE0_PORT` / `QIHSE_NODE1_PORT`,
`QIHSE_NODE0_BUS_PORT` / `QIHSE_NODE1_BUS_PORT`,
`QIHSE_CLUSTER_PASSWORD`, and (for remote successors) `QIHSE_SSH_TARGET`.

**Connect-to-existing (defaults are the lab pair, override before use
elsewhere):** `tests/cluster_smoke.py` (two-node routing + MOVED redirects),
`tests/cluster_discover_smoke.py` (--join membership discovery; run after
bringing up a seed node), `tests/cluster_loadshift_smoke.py`
(`CLUSTER MOVESLOTS` moves a data-bearing range over pinned QKP — the legacy
cleartext AUTH transfer was retired; see "Slot migration durability" below).
All honor `QIHSE_NODE0_HOST` /
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
- **`[QIHSE AUDIT] Integrity chain mismatch detected`.** Preserve the audit
  log, all rotated logs, and `qihse_integrity.chain` together before any
  recovery action. A mismatch can indicate lost writes, a partial rotation,
  or tampering. Do not delete the chain tip to silence the warning; inspect a
  copy of the complete retained set and establish the last verified boundary
  before restoring service. Disposable test directories may be reset only
  when their audit history is explicitly out of scope.
- (Resolved 2026-09-26: `make check` expected a stale upstream layout — the
  workflow checker now verifies current paths; `./qihse demo` runs end to end
  (native module exposed via `build/bin/qihse.so`, see [§3.1](#31-the-qihse-launcher-repository-root));
  `qihse-redis-server --password` now bootstraps-or-verifies per [§3.3](#33-qihse-redis-server);
  and the `controller-api` gold failure — leases born expired under the
  Phase-B strictening — was fixed by the lease wire TTL contract, gold is
  60/60 again.)
- **One `make test` at a time** (parallel `-j` *within* one aggregate is
  safe and now the recommended invocation — see [§2.1](#21-the-aggregate)).
  Concurrent aggregates still race the shared `build/` compile artifacts
  and root-level targets that clean `qihse_integrity.chain*`.
- **`make docs` is a stub** — documentation is maintained by hand in
  markdown; there is no generated-docs pipeline.

Anything security-relevant here is a symptom, not noise: report
auth-bypass-shaped behavior (wrong `WRONGPASS`, missing `NOAUTH`/`NOPERM`)
rather than working around it. The security invariants themselves are defined
in the repository-root [`AGENTS.md`](../AGENTS.md) and must never be weakened
by configuration.

---

## 7. QIHSE Studio Operations & Real-Time Display Platform

The QIHSE Studio display platform replaces legacy browser mockups with a unified ASP.NET Core 8 WebAPI backend and React 18 TypeScript SPA.

### 7.1 Quickstart & Service Provisioning

```bash
# Provision, build, and register systemd service (qihse-studio.service)
make install-studio
# Or directly via installer:
./portal/install-studio.sh

# Ad-hoc development run (interactive):
make studio
```

### 7.2 Service Management

The platform runs as a supervised systemd service across boots:

```bash
sudo systemctl status qihse-studio.service
sudo systemctl restart qihse-studio.service
sudo journalctl -u qihse-studio.service -f
```

### 7.3 Network & Security Policy (Default LAN-Only)

- **Default Binding**: `http://0.0.0.0:5100` (Local & LAN interface access; port 5000 is reserved by SPECTRA Panel).
- **Strict LAN-Only Enforcement**: Built-in `LanOnlyMiddleware` inspects all incoming TCP connections:
  - **Permitted**: Localhost (`127.0.0.1`, `::1`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and Link-Local (`169.254.0.0/16`).
  - **Blocked**: Non-private / public WAN addresses receive HTTP 403 Forbidden.
- **Cluster Auto-Linking**: `ClusterMeshService` polls `CLUSTER NODES` over RESP to auto-link and stream real-time 10 Hz telemetry for local Node 0 (`192.168.1.91:7100`), remote Dell PowerEdge R730xd Node 5 (`192.168.1.90:7115`), and other cluster peers.

---

## 8. See also

- [API reference §11 — configuration knobs](API_REFERENCE.md#11-configuration-knobs)
- [Deployment guide](deployment/README.md) (partially stale; it says so itself)
- [AF_XDP operational guide](manual/deployment/AF_XDP_OPERATIONAL_GUIDE.md)
- [Replication and backup](architecture/replication_backup.md) ·
  [Operational protocols](architecture/operational_protocols.md)
- [Gold validation suite design](development/gold_validation_suite.md)
- [Security documentation](security/README.md)
