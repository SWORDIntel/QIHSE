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

## Coverage of the areas named by W5.3

The pack has grown from the eight areas W5.3 named to nine: `ai-fabric` was
added after three shipped fabric features were found to be correct code
resolving to nothing for three commits, and nothing reported it. The table
below is the current state of the pack: 42 workloads, every one declared
`expect=pass`, and 9 recorded gaps. The counts are read from
`tests/gold/pack.v1.gold`; run `make test-gold` for the runtime verdict.

| Area | Workloads | Declared | What is not covered (recorded as `gap`) |
|---|---|---|---|
| ANN + rerank | 3 | 3 pass | — |
| Relational | 6 | 6 pass | no end-to-end SQL-over-storage test: SQL INSERT does not yet populate the mutable row store that UPDATE/DELETE execute against |
| Graph | 1 | 1 pass | `qihse_graph_vector.c` (graph+vector hybrid) has no test |
| FTS + vector fusion | 2 | 2 pass | fusion is in-process only; no adapter/server path and no fused-ranking gate |
| Persistence / recovery | 3 | 3 pass | — |
| Protocol compatibility | 5 | 5 pass | RESP/HTTP/ES/ClickHouse/Influx end-to-end compatibility; no Bolt negative-authorization test (invariant 3) |
| Distributed failure | 4 | 4 pass | scenarios are in-process simulation; no real multi-process peer kill |
| Security regressions | 15 | 15 pass | 8 of the 16 `tests/security-regression.mk` targets are runnable but omitted to bound the default run |
| AI fabric | 3 | 3 pass | no remote job dispatch; `inference` and `index-build` have no executor |

Every gap is also printed by the runner and counted in the verdict, so the
suite cannot report an untested area as covered.

## Defects that were recorded and have since been fixed

The suite records the true state; it does not repair it. The entries below were
recorded as `known-bug` when this document was first written and now report
`GOLD: OK` — the pack's `protocol-compat-probe`, `mvcc-committed-delete` and
`repl-apply-wal` workloads assert the fixed behaviour. They are kept here
because a stale "known defect" list is itself a documentation defect:

* **Bolt message signatures disagreed with Bolt 4.x** — all thirteen
  `QIHSE_BOLT_MSG_*` constants now match the specification, and a
  spec-conformant `RESET` (0x0F) is answered with SUCCESS on the wire. See
  `docs/architecture/bolt_protocol.md` for the deviations that remain (the
  adapter still discards `RUN` results).
* **MongoDB wire protocol declared but absent** — all declared server,
  message-parsing, catalog and dispatch entry points are defined by
  `libqihse.so`; 17 `mongo_*`/`qihse_mongo_*` symbols are exported, and the
  adapter is covered by `tests/test_mongo_wire.c` and
  `tests/test_mongo_wire_security.c`.
* **`qihse_repl_apply_wal` recorded an LSN without replaying** — the applier
  stages the record and replays it through `qihse_wal_replay()`, and a context
  with no bound store refuses rather than acknowledging.
* **A committed MVCC delete could leave its row visible** — the delete records
  an intent resolved against the deleting snapshot, so it hides exactly the
  versions its transaction could see, without hiding versions the deleter never
  saw. See `docs/architecture/transactions_mvcc.md`.
* **A NULL security context was replaced by the operator identity** —
  `qihse_vector_db_search()` now fails closed with `EACCES` and materialises
  nothing; the `null-security-context` workload asserts it.
* **`tests/qihse_vector_db_persistence_test.c` aborted at its first case** — the
  suite now initialises auth and passes an authenticated principal, and
  `make test-persist` passes in full (`persistence-regression-suite`).
* **`tests/test_vector_skip_integrity.c` aborted** — the malformed-tryte
  rejection path now runs to completion (`vector-skip-integrity`).

Still recorded as defects or open items in the current pack: nothing. Every
workload in `pack.v1.gold` is `expect=pass` and the only caveats the runner
prints are the nine `gap` entries above.

## Maintenance

* Adding a workload: add a `workload` line (and a `bin=` entry if it is a new
  C file under `tests/gold/workloads/`). Nothing else.
* Fixing a recorded defect: the probe reports `GOLD: OK`/`FIXED` and the runner
  prints `FIXED`/`XPASS`, which is the signal to update the pack entry (and to
  cite the fix in `ROADMAP.md` §1.1).
* Changing the grammar: bump `pack-version`, add `pack.v<N+1>.gold`, and switch
  `GOLD_PACK` deliberately.
* The pack's own comments are part of the record. Where a workload's comment
  block still describes the defect it was written to catch (for example
  `tests/gold/workloads/gold_mvcc_committed_delete.c` and
  `tests/gold/workloads/gold_repl_apply_wal.c`), that is the probe's rationale,
  not a current claim; the `GOLD: OK` line and the pack's `output=` substring
  are what the runner asserts.
