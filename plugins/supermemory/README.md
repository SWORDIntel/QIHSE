# Supermemory ↔ QIHSE bridge

This bridge makes **QIHSE the authoritative, 100% sovereign local memory backend**
for AI agent systems (Codex, ZCode, hax, agy). It interfaces directly with QIHSE's
authenticated RESP `AIMEM STORE-SCOPED-DURABLE`, `GET-SCOPED`,
`RECALL-SCOPED`, `FORGET-SCOPED-DURABLE`, and `COUNT-SCOPED` paths. These
store, retrieve, search, delete, and count memories locally under the caller's
tenant, classification, and SCI context. The tool surface is the Supermemory
standard set (`search_memory`, `add_memory`, `forget_memory`, `memory_count`)
plus exact `get_memory` via QIHSE `AIMEM GET-SCOPED`. Nothing in this
integration contacts `api.supermemory.ai`, `mcp.supermemory.ai`, or any other
remote endpoint.

There are **zero cloud dependencies, no cloud mirroring to `api.supermemory.ai`,
and no external OAuth popups**. The bridge does not open raw QIHSE database files,
infer principals, or bypass QIHSE authentication.

## Installation & Auto-Configuration

This directory vendors the pinned-QKP bridge from the separate
`supermemory-qihse-bridge/qihse-backend` source tree. It is not automatically
loaded by QIHSE or the standalone AIMEM service. It defaults to pinned QKP and
BM25; semantic/hybrid modes remain explicit until the projection rollout gates
are met. The installer requires a verified QKP session before changing hooks
or client configuration; it preserves an existing protected AIMEM env file.

Run the installer only when deliberately registering the MCP server and hooks
for Codex and ZCode:

```sh
./install.sh
# or: python3 ./install.py
```

The installer:
1. Detects an authorized local QIHSE installation (`/opt/QIHSE`, `qihse-aimem.service`,
   or `~/.config/qihse-aimem/env`). If QIHSE is not installed, it aborts with an error
   and points to https://github.com/SWORDIntel/QIHSE.
2. Verifies a pinned QKP session authenticated as `AIMEM_SERVICE` on loopback.
   It refuses missing pins or explicit cleartext transport. An existing
   mode-0600 client env is preserved; a new one is created privately.
3. Compiles the native C engine `supermemory-bridge` via `make` and installs the compiled
   binary into `~/.codex/hooks/supermemory/` and `~/.zcode/hooks/supermemory/`.
4. Registers `mcp_server.py` as `[mcp_servers.supermemory]` in
   `~/.codex/config.toml` and `~/.zcode/cli/config.json`. The Python MCP server
   owns the complete scoped read/write surface; `supermemory-bridge mcp`
   remains a read-only compatibility interface.
5. Installs native QIHSE hooks (`UserPromptSubmit` -> `supermemory-bridge hook`, `PreToolUse`, `Stop`)
   and merges them cleanly into `~/.codex/hooks.json`.
6. Neutralizes legacy cloud OAuth browser popups so all memory recall and capture stays
   strictly sovereign and local.

## Native High-Speed C Engine (`supermemory-bridge`)

For microsecond response latency and minimal memory overhead (~1.5 MB vs ~40 MB for Python),
a compiled native C11 binary is provided (`supermemory-bridge.c`, compiled to `supermemory-bridge`):

- **`supermemory-bridge mcp`**: Read-only native search MCP retained for compatibility.
  The installer registers `mcp_server.py` for the complete scoped add/get/search/forget/count surface.
- **`supermemory-bridge hook`**: Codex `UserPromptSubmit` prompt hook. Native client
  overhead is ~1 ms of CPU; end-to-end latency is dominated by the server-side ONNX
  embedding of the query (~1–2 s for a novel query in hybrid mode, cheaper for repeats).
- **`supermemory-bridge recall <query> [--limit N] [--scope auto|repo|global]`**: High-speed CLI
  recall with automatic repository affinity clustering and cross-domain noise judgment.
- **`supermemory-bridge status`**: Instant connection and loopback authentication verification.

### Strict Loopback Security (Zero Network Exposure)

The QIHSE backend port (6401) and all bridge components strictly enforce loopback binding
(`127.0.0.1`, `localhost`, `::1`). Non-loopback addresses are rejected immediately on startup.
All MCP servers and hooks communicate exclusively across standard I/O streams (`stdin` / `stdout`),
presenting zero open network ports to external interfaces or the internet.

## Configuration

Clients load these values from `~/.config/qihse-aimem/env` or from the invoking
service environment:

- `QIHSE_RESP_HOST` — QIHSE RESP host (default: `127.0.0.1`). Non-loopback hosts are
  rejected by default for sovereign security.
- `QIHSE_RESP_PORT` — QIHSE RESP port (default: `6401`).
- `QIHSE_AUTH_USER`, `QIHSE_AUTH_PASSWORD` — the dedicated `AIMEM_SERVICE`
  principal and its distinct service password. Clients never receive the
  Operator credential.
- `QIHSE_AIMEM_PROJECT` — optional explicit native project scope. Otherwise clients
  derive the project from their current repository.

The server bootstraps the two verifiers through separate credential channels:

- `QIHSE_OPERATOR_PASSWORD` — bootstrap-only server credential. Keep it out of
  the persistent environment file. The deployed user service stores it as a
  user-scoped `systemd-creds` encrypted blob, decrypts it only in the startup
  wrapper, and passes it to the server process long enough to build the
  verifier.
- `QIHSE_AIMEM_SERVICE_PASSWORD`, `QIHSE_AIMEM_SERVICE_USER_ID`,
  `QIHSE_AIMEM_SERVICE_TENANT_ID` — bootstrap the restricted AIMEM principal. Use a
  distinct password and set `QIHSE_AUTH_PASSWORD` to the same value for clients.
- `QIHSE_AIMEM_KIND` — `1` for episodic or `2` for semantic (default: `2`).
- `QIHSE_ALLOW_REMOTE` — optional flag (`1`/`true`) to allow connecting to a non-loopback
  `QIHSE_RESP_HOST`.
- `QIHSE_AIMEM_ENV` — custom path to the credentials env file (default:
  `~/.config/qihse-aimem/env`, mode 0600).

After verifier construction, QIHSE cleanses its owned password buffers and the
`QIHSE_OPERATOR_PASSWORD`, `QIHSE_AIMEM_SERVICE_PASSWORD`, and
`QIHSE_AUTH_PASSWORD` environment values before it creates long-lived stores or
worker threads. Node replication uses QKP service identities, and machine
telemetry uses attenuated `MACHINEAUTH` claims; neither path retains or forwards
the Operator password.

## Pinned-QKP transport (deployed on the standalone service)

The bridge now supports the shared `qihse_admin.py` persistent session API for
`mcp_server.py`, `recall.py`, `sync.py` and the Python ZCode hooks. The native
Codex hook uses `qihse-admin-cli --resp` with its password taken from the
process environment, not the argument list. QKP is the default for this vendored plugin; an explicitly selected legacy
RESP mode remains in the library for non-deployed fixtures. The installer
refuses RESP and failed QKP handshakes never fall back to cleartext.

To prepare a **dedicated** service keypair, generate ML-KEM/ML-DSA material in
private storage with the QIHSE keygen; do not reuse any cluster administrator
key. Start the *same standalone AIMEM store* with the new `qihse-redis-server`
options `--require-auth --pqc-require --pqc-identity-dir <server-keys>
--pqc-trusted-pub <service-client-DSA-pub> --pqc-node-id <server-id>`.
These QKP pins authenticate transport only: there is no admin-peer mapping on
this server. Clients must additionally `AUTH AIMEM_SERVICE` inside QKP. An
unmapped key alone has no privileges; ACL/tenant/classification and the AIMEM
command allowlist remain enforced by the server.

Set the following in the protected **client** env (0600), separately from the
server's bootstrap secrets:

```
QIHSE_AIMEM_TRANSPORT=qkp
QIHSE_RESP_HOST=127.0.0.1
QIHSE_RESP_PORT=6401
QIHSE_AUTH_USER=AIMEM_SERVICE
QIHSE_AUTH_PASSWORD=<existing service password>
QIHSE_ADMIN_SDK=<installed QIHSE sdks/python/qihse_admin.py>
QIHSE_ADMIN_LIB=<matching installed libqihse.so>
QIHSE_ADMIN_CLI=<matching installed qihse-admin-cli, for native hook>
QIHSE_AIMEM_IDENTITY_DIR=<service client private key directory>
QIHSE_AIMEM_TRUSTED_PUB=<pinned standalone server DSA public key>
QIHSE_AIMEM_NODE_ID=<service client node id>
```

**Deployed transport:** the standalone `qihse-aimem.service` uses pinned,
QKP-only sessions on loopback port 6401. HAX's in-process memory client,
Python hooks, and installed Codex/ZCode hooks use the explicit service identity;
a failed QKP handshake or AUTH never falls back to cleartext.
The coordinated QKP-only cutover is deployed to the standalone 6401 service.
The previous env, unit and versioned runtime are retained as `*.pre-qkp` backups
and the old release directory; no AIMEM storage files were read or rewritten by
the bridge. Never point this bridge at production cluster port 7100: its AIMEM
store and principal are different. The G510 telemetry poller now uses scoped
AIMEM count under the same service identity instead of retrying an obsolete
password every two seconds.

Automatic recall defaults to BM25 because the current scoped hybrid path
re-embeds every matching record per request; on the live store hybrid queries
can exceed 60 seconds. `search_memory(mode="hybrid"|"semantic")` and
`recall.py --mode hybrid|semantic` remain available explicitly. This is a
query-latency limitation of scoped semantic indexing, not a transport fallback.
Validate with `make test-admin-cli` on QIHSE and the bridge's stdlib tests.

## Deployed AIMEM service contract (2026-10-21)

The current standalone deployment uses tenant `1`, principal ID `65000`, and
the named non-Operator principal `AIMEM_SERVICE`. The RESP dispatch boundary
allows that identity to execute scoped `AIMEM` operations and basic session
commands only. Generic KV operations such as `GET` and `SET`, administrative
commands, replication commands, and alternate authentication capabilities are
rejected with `NOPERM`.

Legacy records are converted with a version-2 migration manifest. The manifest
has one top-level `target_user_id`; every UUID has an explicit project,
worktree, workstream, and session destination, and a row cannot override the
target principal. Migration preserves each record's classification and SCI
labels, refuses an incomplete live inventory, and validates an already-migrated
retry against the exact owner and scope.

The deployed conversion moved 566 records to principal `65000`: 435 to the
tenant-local `global` project and 131 to their declared repository projects.
A post-restart preflight reported all 566 at their exact destinations with zero
legacy records pending. An authenticated post-migration backup was verified
before the service returned to use.

## Streaming JSONL Export Ingestion (`sync.py`)

`sync.py` provides high-throughput, memory-bounded ingestion of authorized QIHSE
JSONL exports into the local QIHSE AI memory store:

```sh
python3 ./sync.py --input export.jsonl --dry-run
python3 ./sync.py --input export.jsonl --manifest manifest.json --dry-run
python3 ./sync.py --input export.jsonl
# Resume safely after a transient failure:
python3 ./sync.py --input export.jsonl --state .state/qihse-memory.json
```

Key capabilities:
- **Strictly Local Backend**: `--backend` only accepts `qihse`. All legacy cloud Supermemory
  APIs and mirror logic are eliminated.
- **Streaming Parser & Bounded Line Size**: Reads the input file line-by-line with a 1 MiB
  per-line safety ceiling, preventing memory bloat or OOM when ingesting massive datasets.
- **Chunked SHA-256 Digest**: Validates manifests against file contents in 64 KiB chunks
  without loading the entire file into RAM.
- **Loopback Enforcement**: Refuses non-loopback RESP endpoints unless `--allow-remote-host`
  or `QIHSE_ALLOW_REMOTE=1` is explicitly configured.
- **Atomic State Ledger**: Updates `--state` atomically after each stored record, ensuring
  safe and reproducible resume.

## MCP Server (`mcp_server.py`)

`mcp_server.py` is a stdio Model Context Protocol (MCP) server providing Supermemory-compatible
memory tools backed entirely by local QIHSE AI memory.

### Robust JSON-RPC 2.0 Error Handling
The server adheres strictly to the JSON-RPC 2.0 specification:
- Emits standard JSON-RPC 2.0 error envelopes:
  - `-32700`: Parse error (malformed JSON payloads)
  - `-32600`: Invalid Request (non-object payloads like raw lists `[]`, wrong `jsonrpc` version, missing `method`)
  - `-32601`: Method not found (unrecognized methods or tools)
  - `-32602`: Invalid params (malformed parameters or invalid tool arguments)
- Server process uptime is preserved; invalid client payloads never crash the daemon.
- Backend errors are reported by exception type only; raw backend error text is never leaked.

### Optimized Socket Communication & Transaction Safety
- **Direct Commands**: Eliminates redundant `PING`/`PONG` round-trips before every command.
  Commands are issued directly on the cached connection.
- **Transaction Locking**: `_conn_lock` serializes the complete command send and
  response read transaction, guaranteeing thread safety and eliminating socket frame interleaving.
- **Credential Hygiene**: The credentials env file must be user-owned, a non-symlink, and
  mode 0600 before it is loaded.
- **Write Acknowledgement**: Pure reads and idempotency-keyed stores reconnect and retry
  once on connection loss; an unkeyed write with an unknown acknowledgement is never
  retried — callers supply idempotency keys and rely on the recovery spool instead.

### Native project scoping
`mcp_server.py` sends every operation through QIHSE's authenticated native scope boundary:
- **`search_memory`**: Accepts an optional `scope` argument:
  - `auto` (default): Restricts retrieval to the active repository project.
  - `repo`: Strictly restricts results to the active repository.
  - `global`: Selects the tenant-local project named `global`. It does not
    cross tenants or implicitly search every project.
  - `<repo_name>`: Explicitly scopes search to that named project.
- **`add_memory`**: Accepts an optional `scope` (`auto`, `repo`, `global`, or `<repo_name>`) and
  a structured `metadata` object. Automatically binds the active repository identifier to the
  persisted memory envelope.
- **`get_memory`**: Reads one memory by QIHSE UUID under the current authenticated principal;
  unauthorized and absent records are indistinguishable.
- **`forget_memory`**: Deletes a memory by its QIHSE identifier.
- **`memory_count`**: Returns the count of memories in the selected project scope
  (`COUNT-SCOPED` under the authenticated principal). The default `auto` scope
  resolves to the current repository's project, so a count of 0 is normal when a
  repository has no records — use `scope=global` for the tenant-local global project.

### Semantic Embeddings & Local Inference
The RESP server runs an embedding model locally (ONNX runtime):
- Embedder model is typically bge-small-en-v1.5 (384-dimensional).
- Mode `semantic` or `hybrid` ranks results by vector cosine similarity and BM25 lexical fusion.

### Operational Notes
- **Crash-durable mutations**: MCP writes and deletes use
  `STORE-SCOPED-DURABLE` and `FORGET-SCOPED-DURABLE`. Success includes the
  native WAL/fsync durability fence; idempotency-keyed stores converge on the
  same record after a lost reply. Reads remain immediately authorization
  checked against the current principal and labels.
- **Connection Configuration**: Managed through `~/.config/qihse-aimem/env` (mode 0600).
- **Client Configuration** (ZCode `~/.zcode/cli/config.json`):
  ```json
  {
    "mcp": {
      "servers": {
        "supermemory": {
          "command": "python3",
          "args": ["${PROJECT_ROOT}/supermemory-qihse-bridge/mcp_server.py"],
          "timeoutMs": 120000
        }
      }
    }
  }
  ```
  Codex uses the `[mcp_servers.supermemory]` table in `~/.codex/config.toml`
  pointing at the same `mcp_server.py`.

## Extended local lifecycle capabilities (2026-10-20)

The tree also contains the [ZCode/HAX lifecycle adapters](zcode-hooks/README.md).
They add:

- Private fsynced Stop-event recovery spool with asynchronous capture.
- Structured, attributed session capsules with bounded tail reads and
  heuristic secret redaction; no LLM requirement.
- A generic HAX/external-harness lifecycle ingress that only accepts an
  explicitly declared external capture owner and stable source-event IDs.
- Bounded, provenance-first prompt recall and exact `get_memory` by ID.
- No-content diagnostics and an stdlib unit-test suite under `tests/`.

**Durability and scope:** Writes and deletes use the crash-durable scoped commands.
Project selection is enforced by QIHSE before records reach the bridge, together
with the principal's tenant, classification, and SCI policy. The client does not
infer authorization or post-filter a principal-wide result set.

**Egress:** ordinary MCP tools, hooks and HAX events never talk to the hosted
Supermemory service. This tree's `sync.py` accepts only the strictly local
`qihse` backend — the legacy `--backend supermemory` / `--backend both` cloud
mirroring modes have been removed, so no code path in this directory contacts
the configured Supermemory URL.

**Security:** do not confuse `capture_owner`, session metadata, timestamps
or filenames with authenticated security identity. Only QIHSE authorizes
what may be stored or recalled; sourced context is data, not instructions.

### Executable checks

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 zcode-hooks/doctor.py
```

The first two are what the versioned [`hooks/pre-push`](../hooks/pre-push) gate
runs. This fork has no CI, so enable it once per clone:

```bash
git config core.hooksPath hooks
```

### Implementation plan

The planning document is the
[Supermemory roadmap](roadmaps/SUPERMEMORY_AI_MEMORY_ROADMAP.md).
The former QIHSE engine roadmap (QH-00 … QH-08) was retired from this
tree on 2026-10-20: it has been implemented engine-side in
[SWORDIntel/QIHSE](https://github.com/SWORDIntel/QIHSE), and the engine
build was deployed on 2026-10-21 (scoped durable AIMEM is live — this
bridge runs on it). Bridge features that use further engine
capabilities (`AIMEM HANDOFF`, `KNOWLEDGE`, `QUERY`, `PROJECT`, `EVENT`)
are pending bridge-side wiring, tracked in the roadmap and status
documents; the client still never simulates an engine primitive.

Upstream Supermemory is MIT (see `LICENSE` in the repository root). This
bridge directory is part of the same tree under that license.

## Security Boundary

Do not set the input to a raw QIHSE data directory, source tree, or internal storage file.
Those paths are not export streams and may contain classified data. Ingestion and recall
must always flow through the authenticated QIHSE RESP API under a least-privileged principal.
