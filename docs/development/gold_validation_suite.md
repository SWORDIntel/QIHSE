# Gold validation suite (roadmap W5.3)

> **Status: implemented.** One command — `make test-gold` — runs the versioned
> workload pack in `tests/gold/pack.v1.gold` and prints the state of the
> system: a pass/fail line per workload, a coverage line per area, every
> recorded known defect with a reference, and a final verdict. This document is
> the format reference for the pack; the runner's contract is documented at the
> top of `tests/gold/gold_runner.c`.

The suite exists because documentation claimed coverage whose test files did not
exist, and because no single command said what the system's state actually was.
It therefore prefers a truthful `UNCOVERED`/`PARTIAL`/`KNOWN-BUG` report over a
larger green test count.

## Running it

```bash
make test-gold                 # default: known defects and gaps are reported, not fatal
GOLD_STRICT=1 make test-gold   # known defects, stale expectations and gaps exit 2
./tests/gold/gold_runner --list tests/gold/pack.v1.gold   # print the pack, run nothing
LD_LIBRARY_PATH=. ./tests/gold/gold_runner [--strict] <pack>   # run a pack directly
```

`make test` runs `test-gold` as its last prerequisite (it adds roughly 80-90
seconds to that aggregate). The default verdict is
green when no workload failed, could not run, or timed out — known defects and
recorded gaps are printed as caveats. `GOLD_STRICT=1` (or `--strict`) makes any
non-green state fatal so a release gate cannot ignore them.

## Pack format and version scheme

The pack is data, parsed by the runner. Adding a workload is an edit to the pack
only: neither the runner nor the Makefile needs to change.

```
pack-version 1
pack-id qihse-gold
area <id> <description>
workload <id> area=<id> expect=<pass|known-bug|known-fail> [timeout=<sec>] \
    output="<required substring>" match="<required substring>" \
    ref="<relative path>" bin=<relative path> run="<argv...>"
gap <id> area=<id> reason="<why this cannot be tested today>"
```

* `pack-version` is the grammar/semantics version the runner implements. The
  runner **refuses to run** a pack whose version it does not implement, and
  refuses to run when the file name (`pack.v<N>.gold`) disagrees with the
  directive — the suite's identity must not be ambiguous. A grammar change
  lands as `pack.v2.gold` next to v1 and is switched deliberately with
  `GOLD_PACK=...`; nothing silently upgrades.
* `bin=` names a gold-only binary (a `.c` file under `tests/gold/workloads/`)
  that the Makefile builds before the run; the list is extracted from the pack,
  so no Makefile edit is needed. Workloads that are existing make targets use
  `run="make -s <target>"` and need no `bin=`.
* A trailing `\` continues an entry on the next line. Quoted values support
  `\"` and `\\`. Paths must be relative (`AGENTS.md` path policy); the runner
  rejects absolute paths in `bin=`, `ref=` and `run=` at parse time.
* Every declared area must have at least one workload or at least one `gap`.
  An area with neither is a pack error, not a silent skip.

### Workload expectations

| `expect=` | Contract |
|---|---|
| `pass` | must exit 0 **and** print `output=`. Exit 0 without the evidence line is a FAIL, so a test that silently does nothing cannot pass. |
| `known-bug` | a probe that exits 0 and prints one `GOLD: KNOWN-BUG <id> <check>: <detail>` line per defect it still reproduces, and `GOLD: OK <id> <check>: <detail>` for checks that now pass. `ref=` is mandatory. If every check reports OK the workload is `FIXED` (stale expectation). A probe whose own controls fail exits non-zero and is reported `FAIL` — never as a defect. |
| `known-fail` | a workload recorded as failing. The failure must contain `match=`; otherwise the status is `FAIL` ("failed for a reason that is NOT the documented one"), so a known-fail entry can never mask a new breakage. If it passes, the status is `XPASS` (stale expectation). |

### Statuses and exit codes

`PASS`, `FAIL`, `ERROR` (cannot run at all), `TIMEOUT`, `KNOWN-BUG`,
`KNOWN-FAIL`, `FIXED`, `XPASS`; areas are `FULL`, `PARTIAL` or `UNCOVERED`.

* exit **0** — no workload failed, could not run, or timed out.
* exit **1** — at least one workload failed, could not run, or timed out. The
  reason is also written to stderr.
* exit **2** — `--strict`/`GOLD_STRICT=1` and the verdict is not fully green.

## Coverage of the eight areas named by W5.3

| Area | Workloads | Coverage | What is not covered (recorded as `gap`) |
|---|---|---|---|
| ANN + rerank | 3 | 3 pass | the qtri/qmag persisted-sidecar rerank path, because the shipped persistence suite aborts at case 1 |
| Relational | 4 | 3 pass, 1 known-bug | no end-to-end SQL-over-storage test; UPDATE SET-list and DELETE WHERE structure remain documented parser gaps |
| Graph | 1 | 1 pass | `qihse_graph_vector.c` (graph+vector hybrid) has no test |
| FTS + vector fusion | 2 | 2 pass | fusion is in-process only; no adapter/server path and no fused-ranking gate |
| Persistence / recovery | 3 | 1 pass, 1 known-fail, 1 known-bug | the shipped persistence suite's WAL/torn-tail/corruption/compaction/trinary cases do not run |
| Protocol compatibility | 4 | 2 pass, 1 known-fail, 1 known-bug | RESP/HTTP/ES/ClickHouse/Influx end-to-end compatibility; no Bolt negative-authorization test (invariant 3) |
| Distributed failure | 4 | 4 pass | scenarios are in-process simulation; no real multi-process peer kill |
| Security regressions | 14 | 12 pass, 1 known-fail, 1 known-bug | 8 of the 16 `tests/security-regression.mk` targets are runnable but omitted to bound the default run |

Every gap is also printed by the runner and counted in the verdict, so the
suite cannot report an untested area as covered.

## Known defects recorded (not fixed here)

The suite records the true state; it does not repair it.

* **Bolt message signatures disagree with Bolt 4.x** — 7 of 13 implemented
  signatures differ (`RUN`, `PULL`, `DISCARD`, `BEGIN`, `COMMIT`, `ROLLBACK`,
  `RESET`), demonstrated on the wire: a spec-conformant `RESET` (0x0F) is
  answered `IGNORED` (0x7E) instead of `SUCCESS`. See
  `docs/architecture/bolt_protocol.md`.
* **MongoDB wire protocol declared but absent** — 13 of 13 declared server,
  message-parsing, catalog and dispatch entry points are not defined by
  `libqihse.so`; only the BSON helper layer is compiled in.
  See `include/qihse_mongo_wire.h`.
* **`qihse_repl_apply_wal` records an LSN without replaying** — a valid WAL
  record (proved replayable through `qihse_wal_replay`) leaves the target store
  unchanged. See `docs/architecture/replication_backup.md`.
* **A committed MVCC delete can leave its row visible** — when the chain head is
  a version written by an aborted transaction, the delete marks a version no
  reader can see. See `docs/architecture/transactions_mvcc.md`.
* **A NULL security context is replaced by the operator identity** —
  `qihse_vector_db_search()` substitutes `qihse_auth_get_user(0)` for
  `query.user == NULL` instead of failing closed, contrary to `AGENTS.md`
  invariant 1. Vector rows are currently written `UNCLASSIFIED`, so no
  classified payload is disclosed yet.
* **`tests/qihse_vector_db_persistence_test.c` aborts at its first case** — it
  never initialises auth and passes `user = NULL`, so the search is refused with
  `EACCES`. Recorded as `known-fail` with the failure text matched; the test was
  not weakened to make the suite green.
* **`tests/test_vector_skip_integrity.c` aborts** — assertion at line 68
  (`reader.skip_integrity`).
* **`tests/test_pg_wire_cluster.c` dies on SIGPIPE** — no output, `make` reports
  `Error 141`; the root cause is undiagnosed.

## Maintenance

* Adding a workload: add a `workload` line (and a `bin=` entry if it is a new
  C file under `tests/gold/workloads/`). Nothing else.
* Fixing a recorded defect: the probe reports `GOLD: OK`/`FIXED` and the runner
  prints `FIXED`/`XPASS`, which is the signal to update the pack entry (and to
  cite the fix in `ROADMAP.md` §1.1).
* Changing the grammar: bump `pack-version`, add `pack.v<N+1>.gold`, and switch
  `GOLD_PACK` deliberately.
