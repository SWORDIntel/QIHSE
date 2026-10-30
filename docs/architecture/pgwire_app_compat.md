# DIRECTEYE pgwire readiness gate

**Status: partial — recorded source-backed readiness passes; no cutover.** The disposable, TLS-verified QIHSE listener is
not the production service. No application DSN, live data, or deployed listener
is changed.

## Disposable source-backed readiness test

`tests/test_pgwire_app_compat.py` is a **future-migration readiness test**, not
an actual DIRECTEYE migration. It extracts the ordered literal `cur.execute()`
statements and `indexes` loop from DIRECTEYE's
`migration/01_setup_postgresql.py:create_tables`, and three subsequent SELECTs
from `services/postgres_service.py`. The earlier
`migration/01_setup_postgresql.py:create_database` step (CREATE DATABASE) is
not yet exercised and is another explicit application-setup blocker. Source
drift or dynamic migration SQL is a test failure, not an excuse to substitute
invented SQL. The extracted migration is exercised only as a future-readiness probe through
authenticated pgwire in the **disposable test fixture**. No DIRECTEYE migration
is being performed against a production, configured, or persistent database.
The fixture uses a temporary durable row/catalog snapshot, destroyed after each
test; no migration is applied to a persistent application or deployment target.
The fixture **does not pre-create `osint_records` or `auth_events`**. Once the
migration passes, client-side INSERTs of synthetic JSON/UUID/timestamp rows
exercise the application query; the server never inserts application rows behind
the client's back. One separate, synthetic `protected_records` table with a
high-classification marker is reserved for low-clearance denial tests. An
unrelated bounded CREATE TABLE test proves that pgwire can publish a supported
table independently of the source-extracted DDL corpus.

The 26 extracted migration calls now execute through verified-TLS psycopg2
against initially absent application tables and commit as one DDL generation.
The three subsequent source SELECT probes also pass with synthetic rows.
This is bounded source-backed execution, not general PostgreSQL compatibility.
Native storage now includes exact NUMERIC and TSVECTOR values; schema images
retain supported defaults, stored-generated expressions, indexes, functions,
triggers and materialized-view queries. UUID defaults use cryptographic v4
values, stored search vectors recompute on UPDATE, and supported indexes build
authenticated generation-local postings with candidate reauthorization.
The English analyzer is bounded ASCII/Snowball, not a complete PostgreSQL text
search tokenizer (Unicode, URL and hyphenated sublexeme parity remain open).
DDL/DML mixing, arbitrary stored code, general views and DDL retry receipts
remain unsupported. Other unsupported shapes must still fail closed.

The exact `information_schema.tables` enumeration and supported `pg_indexes`
query read committed catalog definitions through an authenticated principal and
hide inaccessible tables; arbitrary catalog shapes remain unsupported.
The all-driver gate executes typed Parse/Bind/Describe/Execute with actual
parameter vectors and result OIDs; client values are never substituted into SQL.
Implicit extended writes are fenced through Sync, and failed pipelines roll back:
CommandComplete before Sync is not durable acknowledgement. Explicit transactions
retain I/T/E state and require rollback after failure. Typed writes with the
experimental simple-query retry key remain refused.

Limits in `src/spinnaker/qihse_pg_wire.c` are 32 connection-local statements and
32 portals, 64 parameters, 64 result columns, 1 MiB capture and 1 MiB per bind
value; frontend message length is capped at 16 MiB, names at 128 bytes.
Execute requires `max_rows=0` (no suspended portals). Durable row
transactions enlist at most 16 tables; DDL-only generations admit at most 16 new
relations. Binary codecs cover bool, integer, float, text, NUMERIC, UUID, JSONB
and timestamp families, not arbitrary PostgreSQL types or binary TSVECTOR.
See [the SQL execution contract](sql_engine.md) for exact OIDs, defaults, index
expressions, generated-vector expression and constraints. BTREE-style equality
postings (1–16 expressions) and single-column JSONB/TSVECTOR GIN are executable
but generation-local, not persistent PostgreSQL access methods. The only stored
function is the validated updated_at trigger transform; the materialized query
is the seven-column source/record_type statistics shape, not arbitrary SQL.

The context-backed handler revalidates the client principal and table ACL;
INT `__qihse_tenant_id`, `__qihse_classification`, `__qihse_sci` must appear
together for labeled rows. Partial/invalid labels fail closed, unlabeled tables
are system-tenant unclassified only, and UPDATE cannot relabel. Transactional
SELECT sees own shadow writes with generation/commit authorization fences;
isolation syntax does not establish PostgreSQL-wide isolation parity. None of
this follows from the separate legacy multi-engine handler's parser shapes.

| Source | Required query shape |
| --- | --- |
| `services/postgres_service.py:135-145` | `SELECT * FROM osint_records WHERE identifier = %s ORDER BY updated_at DESC LIMIT 1` |
| `services/postgres_service.py:292-308` | conditional `COUNT`, `COUNT(DISTINCT ip_address)` and timestamp filter |
| `services/postgres_service.py:310-319` | `GROUP BY ip_address HAVING COUNT(*) > 2 ORDER BY attempts DESC LIMIT 10` |

Other application paths additionally require `RETURNING`, `ON CONFLICT`,
JSON extraction, FTS, `ANY`, `NOW()`, RealDictCursor, connection pooling and
PostgreSQL catalog semantics. The bounded native snapshot and retry ledger do
not provide these automatically. CHECK/FK/cascades, composite keys, nullable
UNIQUE, SERIAL, mixed DDL/DML and general ALTER/DROP must remain refused; bounded
DDL-only transactions already exist and must not be mislabeled as absent.
General views/stored code, window/CTE/join execution, COPY, arbitrary catalog
queries and DDL retry receipts are still not supported by this gate. Existing
fail-closed behavior is intentional.

## Verification and promotion

Run `make test-pgwire-app-compat` after building `libqihse.so`, or run the
source-backed tests with all three drivers (`psycopg2`, `psycopg`, `asyncpg`)
in an isolated virtualenv. Missing drivers are reported as skipped, **not** as
compatibility evidence. All three drivers must authenticate via verified TLS,
execute migration and real queries, and deny a low-clearance principal both
direct-ID and enumerating reads without protected payload disclosure. Compare
types, NULLs, errors and row results against disposable PostgreSQL on synthetic
data. The existing PostgreSQL service remains the source of truth until full
schema migration, recovery/restore, retry outcomes, application clients and
reverse-cutover rehearsal pass separately; no DSN changes are authorized here.

The previously recorded all-driver readiness run reports **23 passed in 213.43s** with
psycopg2, psycopg v3 and asyncpg installed. This includes all 26 source-derived
migration calls, all three source SELECTs through each driver, real typed
parameters/results, UUID/default/generated/NUMERIC/trigger/index behavior,
populated-source materialized-view creation and refresh, and low-clearance
negative tests. The original four failures are resolved. The synthetic datetime
arguments use timezone-aware UTC for timestamptz; naive timestamp parameters
are covered separately by parser/coercion regression tests.

The previously recorded complete `make test TEST_JOBS=32` finished successfully
against that post-review tree (not a rerun asserted by this documentation audit): **141 scheduled targets, zero failures**, followed by passing
W12/TurboQuant and UWP TLS tail checks (exit 0; 26m14s). Focused parser, row-store,
recovery, DML and wire regressions also pass, including quoted `NULL`, explicit
SQL NULL/defaults, indexed typed lookups and implicit-pipeline rollback. Skipped drivers are not compatibility evidence, and `0A000` is not
authorization denial (`42501`). Do not pre-seed or replace the source migration
with invented DDL. Production principal provisioning, deployment TLS policy,
cutover and application-container rehearsal remain separate, incomplete gates.
