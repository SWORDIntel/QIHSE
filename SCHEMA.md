# QIHSE Database Schema

Complete reference for all data stored in QIHSE, keyed by the KV store prefix system.

## Storage Layers

| Layer | Purpose | Persistence | In-Memory |
|-------|---------|-------------|-----------|
| **KVStore** | Primary key-value store for all records | `/bridge/audit/qihse.db` | Yes (loaded on startup) |
| **FTSIndex** | BM25 full-text search over all records | In-memory (rebuilt from KV + map on startup) | Yes |
| **VectorDB** | Hash-based semantic embeddings (256-dim) | `/bridge/audit/tool_vectors.db` | No (file-backed) |
| **TimeSeriesDB** | Gorilla-compressed metrics | In-process | Yes |
| **EventStream** | Append-only durable event log | `/bridge/audit/events_<name>` | No (file-backed) |

## Auxiliary Files

| File | Purpose |
|------|---------|
| `/bridge/audit/qihse_fts_map.json` | Maps FTS doc_id → KV key (for resolving search results) |
| `/bridge/audit/tool_graph.json` | Tool dependency graph (consumers + chains_together) |
| `/bridge/audit/tool_cards.json` | Compact LLM tool cards for prompt injection |
| `/bridge/audit/tool_idf.json` | Inverse Document Frequency weights for vector embeddings |
| `/bridge/audit/tool_vectors.db` | VectorDB file (256-dim hash embeddings) |

---

## KV Key Schema

All data is stored as JSON strings under namespaced keys.

### Tools — `tool:<name>`

Stores tool definitions from the schema library.

```json
{
  "name": "nmap",
  "type": "tool",
  "binary": "nmap",
  "category": "network_scan",
  "description": "Network mapper - port scanning, service detection, OS fingerprinting, NSE scripts",
  "target_type": "host",
  "target_description": "IP, hostname, CIDR, or comma-separated list",
  "output_format": "text",
  "output_flags": {},
  "sudo_required": false,
  "sudo_recommended": ["-sS", "-sU", "-O", "--traceroute"],
  "args": {
    "-sS": {"type": "flag", "description": "SYN scan"},
    "-sV": {"type": "flag", "description": "Service version detection"},
    ...
  },
  "use_cases": ["port scan", "service detection", "OS fingerprinting", ...],
  "tags": [],
  "result_usage": {
    "output_types": ["ports", "services", "os"],
    "guidance": "Parse open ports and services for enumeration phase",
    "feeds_into": ["nmap-xml", "service-list"],
    "chains_using_this_tool": ["full_recon_chain", "port_recon_chain"]
  }
}
```

**Missing from current QIHSE import** (present in JSON source):
- `sudo_recommended`
- `output_flags`
- `target_description`

**To be added (LLM routing hints)**:
- `llm_hints.phase` — which engagement phase this tool belongs to
- `llm_hints.keywords` — trigger keywords for LLM tool selection
- `llm_hints.next_tools` — tools that typically follow this one
- `llm_hints.output_feeds` — what downstream tools consume this output
- `llm_hints.compact_summary` — one-line summary for LLM context
- `llm_hints.risk_level` — low/medium/high
- `llm_hints.requires_target` — bool

---

### Chains — `engagement:<name>`

**Note:** Chains are stored under the `engagement:` prefix, not `chain:`. This is a historical naming issue from the batch import. Chains and engagements share the same namespace.

```json
{
  "name": "full_recon_chain",
  "type": "chain",
  "description": "Full reconnaissance chain: DNS, subdomain, port scan, web recon",
  "goal": "Comprehensive reconnaissance of a target",
  "category": "recon",
  "risk_level": "low",
  "step_count": 6,
  "tools_used": ["subfinder", "amass", "nmap", "nikto", "whatweb", "wpscan"],
  "steps": [
    {
      "tool": "subfinder",
      "command": "subfinder -d {target}",
      "output_parse": "subdomains"
    },
    ...
  ],
  "preconditions": ["target_domain"],
  "postconditions": ["subdomain_list", "open_ports", "web_tech"],
  "artifacts": ["subdomains.txt", "ports.xml", "web_recon.json"]
}
```

---

### Findings — `finding:<id>`

```json
{
  "id": "f-20260822-001",
  "type": "finding",
  "tool": "nmap",
  "name": "Open SSH port",
  "description": "Port 22 open with SSH service",
  "template": "open_port",
  "severity": "info",
  "target": "10.26.0.1",
  "engagement": "acme-pentest",
  "evidence": "nmap output showing port 22 open",
  "timestamp": "2026-08-22T12:00:00Z"
}
```

---

### Engagement Metadata — `engagement:<name>`

```json
{
  "name": "acme-pentest",
  "type": "engagement",
  "description": "Full penetration test of ACME infrastructure",
  "goal": "Identify and exploit vulnerabilities in ACME web apps",
  "category": "pentest",
  "risk_level": "medium",
  "tools_used": ["nmap", "nikto", "sqlmap"],
  "preconditions": ["scope agreement"],
  "postconditions": ["findings report"],
  "artifacts": [],
  "started_at": "2026-08-22T10:00:00Z",
  "status": "active"
}
```

---

### Engagement Context — `engctx:<engagement>:runs`

Tracks which tools have been run in an engagement (for dedup + context-aware suggestions).

```json
["nmap", "subfinder", "nikto", "whatweb"]
```

---

### Engagement Targets — `engtgt:<engagement>:<type>:<value>`

Individual target registration. Deduplicated by (engagement, type, value).

```json
{
  "engagement": "acme-pentest",
  "type": "ip",
  "value": "10.26.0.1",
  "source": "nmap",
  "added_at": "2026-08-22T12:00:00Z",
  "metadata": {}
}
```

Target types: `ip`, `subdomain`, `url`, `email`

### Target Index — `engtgt:<engagement>:index`

```json
[
  {"type": "ip", "value": "10.26.0.1"},
  {"type": "subdomain", "value": "www.acme.com"},
  ...
]
```

---

### Phase Tracking — `engphase:<engagement>:current`

Current phase string: `recon`, `enum`, `exploit`, `post`, `report`

### Phase History — `engphase:<engagement>:history`

```json
[
  {"from": "recon", "to": "enum", "timestamp": "2026-08-22T12:00:00Z"},
  {"from": "enum", "to": "exploit", "timestamp": "2026-08-22T14:00:00Z"}
]
```

---

### Run History — `runhist:<engagement>:<tool>:<target>:<params_hash>`

Execution dedup + success rate tracking. `params_hash` is MD5 of the rendered command.

```json
{
  "engagement": "acme-pentest",
  "tool": "nmap",
  "target": "10.26.0.1",
  "params_hash": "a1b2c3d4e5f6...",
  "run_count": 2,
  "success_count": 2,
  "fail_count": 0,
  "last_exit_code": 0,
  "last_run_at": "2026-08-22T12:30:00Z",
  "summary_file": "/bridge/engagements/acme-pentest/summaries/nmap_10.26.0.1.json"
}
```

### Run History Index — `runhist:<engagement>:index`

```json
[
  {"tool": "nmap", "target": "10.26.0.1", "params_hash": "a1b2c3..."},
  {"tool": "nikto", "target": "10.26.0.1", "params_hash": "f7e8d9..."}
]
```

---

### FTS Counter — `_fts:counter`

String counter for FTS doc_id allocation.

### Health Check — `qihse:health`

Set to `"ok"` on health check command.

---

## FTS Index

The FTS index is in-memory only. On startup, it is rebuilt from the KV store using the FTS map file.

### FTS Map — `/bridge/audit/qihse_fts_map.json`

```json
{
  "0": "tool:403jump",
  "1": "tool:_meta",
  "2": "tool:airbase-ng",
  ...
  "313": "engagement:full_recon_chain",
  ...
}
```

### FTS Search Text Construction

For each record type, the following fields are concatenated for indexing:

| Type | Fields indexed |
|------|---------------|
| **tool** | name, binary, category, description, target_type, tags, use_cases, result_usage.output_types, result_usage.guidance |
| **engagement/chain** | name, description, goal, category, risk_level, tools_used, preconditions, postconditions, artifacts |
| **finding** | id, tool, name, description, template, type |

---

## VectorDB

256-dimensional hash-based embeddings stored in `/bridge/audit/tool_vectors.db`.

### Embedding Method

1. Tokenize text (lowercase, split, bigrams, char-3-grams)
2. Hash each token with MD5 → dim_idx = hash % 256, sign = (hash >> 8) & 1
3. Weight = (1 + log(tf)) * idf(token)
4. Accumulate signed weights into 256-dim vector
5. L2 normalize

### IDF Weights — `/bridge/audit/tool_idf.json`

```json
{
  "nmap": 2.31,
  "scan": 1.85,
  "port": 2.04,
  ...
}
```

### Vector Metadata

Each vector stores metadata JSON with at minimum:

```json
{
  "type": "tool",
  "name": "nmap",
  "category": "network_scan"
}
```

---

## TimeSeriesDB

Gorilla-compressed time-series for operational metrics.

### API

| Method | Parameters | Description |
|--------|-----------|-------------|
| `insert` | series_id (int), timestamp (int), value (float) | Insert a data point |
| `average_range` | start_ts, end_ts | Average over time range |
| `flush` | — | Flush buffered points |

---

## EventStream

Append-only durable event log at `/bridge/audit/events_<name>`.

### API

| Method | Parameters | Description |
|--------|-----------|-------------|
| `append` | stream_name, payload (bytes) | Append event |
| `read` | stream_name, index | Read single event at index |
| `length` | stream_name | Get event count |
| `flush` | stream_name | Flush to disk |

### Event Record

```
{
  "payload": "<bytes>",
  "size": <int>
}
```

---

## Phase Category Mapping

Used by context-aware suggestions and phase transitions.

| Phase | Allowed Categories |
|-------|-------------------|
| `recon` | recon, osint, network_scan, subdomain_enum, dns, info_gathering |
| `enum` | web_scan, network_scan, file_analysis, subdomain_enum, port_scan, service_enum |
| `exploit` | exploit, web_exploit, sqli, xss, rce, password_attack, cracking |
| `post` | post_exploit, privilege_escalation, lateral_movement, persistence, data_exfil |
| `report` | reporting, evidence, documentation |

---

## Helper Commands (qihse_helper.py)

### Tool Library

| Command | Args | Description |
|---------|------|-------------|
| `store-tool` | `<tool_json>` | Store a tool in KV + FTS |
| `get-tool` | `<name>` | Retrieve tool by name |
| `list-tools` | `[--category=...]` | List tools (reads from library dir) |
| `store-batch` | `<json_array>` | Batch store tools/chains/findings |
| `list-all` | `[--type=...] [--limit=N]` | List all records of a type |
| `stats` | — | Storage statistics |

### Search

| Command | Args | Description |
|---------|------|-------------|
| `search` | `<query> [--limit=N] [--type=...]` | BM25 FTS search |
| `suggest` | `<task> [--limit=N]` | Task-based tool suggestion (BM25) |
| `vector-search` | `<query> [--limit=N] [--type=...]` | Semantic vector search |
| `fusion-search` | `<query> [--limit=N] [--type=...]` | Hybrid BM25 + vector RRF fusion |
| `next-tools` | `<tool_name> [--limit=N]` | Dependency graph next tools |
| `recommend-chain` | `<task> [--limit=N]` | Chain recommendation via vector similarity |
| `tool-card` | `<name|all|batch n1,n2,n3>` | Compact LLM tool cards |

### Engagement

| Command | Args | Description |
|---------|------|-------------|
| `store-engagement` | `<eng_json>` | Store engagement metadata |
| `get-engagement` | `<name>` | Retrieve engagement |
| `record-run` | `<eng> <tool>` | Record tool run in engagement |
| `eng-context` | `<eng>` | Get tools already run |
| `context-suggest` | `<eng> <task> [--limit=N] [--phase=...]` | Context-aware suggestions |
| `phase-suggest` | `<eng>` | Suggest phase transition |
| `record-phase` | `<eng> <old> <new>` | Record phase transition |
| `get-phase` | `<eng>` | Get current phase + history |

### Targets

| Command | Args | Description |
|---------|------|-------------|
| `register-target` | `<target_json>` | Register + dedup target |
| `list-targets` | `<eng> [--limit=N] [--type=...]` | List engagement targets |
| `parse-targets` | `<eng> <tool> [--source=...]` | Auto-parse targets from stdin |

### Run Tracking

| Command | Args | Description |
|---------|------|-------------|
| `check-run` | `<eng> <tool> <target> <params_hash>` | Check if already run |
| `record-run-result` | `<eng> <tool> <target> <params_hash> <exit_code> [summary_file]` | Record run result |
| `tool-stats` | `<eng> [tool]` | Success rate stats |

### Findings

| Command | Args | Description |
|---------|------|-------------|
| `store-finding` | `<finding_json>` | Store finding |
| `get-finding` | `<id>` | Retrieve finding |

### TSDB

| Command | Args | Description |
|---------|------|-------------|
| `ts-insert` | `<series_id> <timestamp> <value>` | Insert metric |
| `ts-average` | `<start_ts> <end_ts>` | Average over range |
| `ts-flush` | — | Flush buffer |

### EventStream

| Command | Args | Description |
|---------|------|-------------|
| `event-append` | `<stream_name> <event_json>` | Append event |
| `event-read` | `<stream_name> <offset> <count>` | Read events |
| `event-length` | `<stream_name>` | Get length |
| `event-flush` | `<stream_name>` | Flush stream |

### Health

| Command | Args | Description |
|---------|------|-------------|
| `health` | — | Health check |

---

## Known Issues

1. **Chains stored as `engagement:` prefix** — historical naming, should be `chain:` for chains and `engagement:` for engagements
2. **Missing fields in QIHSE vs JSON source** — `sudo_recommended`, `output_flags`, `target_description` not imported
3. **KV store has no prefix scan** — listing requires FTS map iteration or separate index keys
4. **FTS is in-memory only** — rebuilt on every helper invocation (slow for large stores)
5. **VectorDB requires numpy + ctypes** — heavier dependency than the rest of the helper
6. **No LLM routing hints** — tools lack phase/keywords/next_tools/risk_level metadata for LLM-driven selection

---

## Planned Changes

1. **Re-import all 320 tools** with full fields + LLM routing hints
2. **Fix chain key prefix** — migrate `engagement:<chain_name>` to `chain:<chain_name>` for actual chains
3. **Make QIHSE the single source of truth** — Go bridge loads from QIHSE via CGO, not JSON files
4. **Delete JSON source files** after verified import
5. **Add streaming monitoring** — live tool execution metrics via TSDB + EventStream
