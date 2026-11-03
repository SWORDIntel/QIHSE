# Repository dependency graph

`deps.json` is the QIHSE repository's machine-readable **feature/task dependency
DAG**. It is not a package manifest and does not install libraries. Keep
feature prerequisites here so sequencing and incomplete prerequisites are
visible and machine-checked.

## Commands

From any working directory in this checkout:

```text
python3 tools/qihse_deps.py validate
python3 tools/qihse_deps.py list
python3 tools/qihse_deps.py order
```

Use `--manifest PATH` before the command to inspect another repository-local
manifest. `validate` checks the schema, IDs, statuses, dependency references,
cycles, and evidence paths. `order` prints a deterministic prerequisite-first
order; `list` prints each item and its status/dependencies. The standard
`make test` suite runs the validator and unit tests as a serial target.

## Manifest rules

The versioned JSON root contains `schema_version`, `repository`, and `items`.
Each item has a stable lowercase kebab-case `id`, `title`, `status`,
`description`, `depends_on`, repo-relative `evidence`, and `acceptance` criteria.
Statuses are `planned`, `in_progress`, `partial`, `complete`, or `blocked`;
`complete` requires current source/test evidence. Dependency edges point from a
work item to the prerequisite it needs. Unknown IDs and cycles fail validation.
Evidence paths must resolve to files within the repository.

When adding work, update the manifest and this explanation only if the schema
or workflow changes. Keep edges limited to genuine sequencing requirements;
use acceptance criteria for quality gates that do not block implementation.

## Current FTS and convergence work

The manifest records the five requested work areas and their dependency order.
Tenant/APP FTS namespace isolation is complete and is a prerequisite for
resumable indexing. Convergence reporting depends on reliable acknowledged-write
recovery semantics; degraded health consumes both the indexing and convergence
signals. The entries are deliberately status-aware: current FTS builds are
one-shot and capped, `REPL.STATUS` exposes only partial peer counts/timestamps,
and published health output does not yet report all hydration/seed states. The
manifest's acceptance criteria describe the target, not a claim that every
planned behavior is already implemented.
