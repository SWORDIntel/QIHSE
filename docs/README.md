# QIHSE Documentation

This directory contains the detailed technical documentation for QIHSE.

If you are new to the project, start with the [root README](../README.md), then use this page to go deeper without having to understand the repository layout first.

## Start here

| I want to… | Read… |
|---|---|
| Build and run QIHSE | [Getting Started](GETTING_STARTED.md) |
| See the major subsystems | [Features](FEATURES.md) |
| Use an existing database client/protocol | [Compatibility](COMPATIBILITY.md) |
| Understand the architecture | [Architecture](architecture/) |
| Review security | [Security](security/) |
| Run or inspect benchmarks | [Benchmarks](benchmarks/) |
| Deploy QIHSE | [Deployment](deployment/) |
| Work on the codebase | [Development](development/) |
| Read the current technical treatment | [Technical Whitepaper v1.1](architecture/qihse_whitepaper_v1.1.md) |

The original [whitepaper v1.0](architecture/qihse_whitepaper_v1.0.md) is retained as a historical design snapshot. Use v1.1 for current implementation status, roadmap state, claim discipline, and production-readiness language.

## Core architecture

Use these when you need implementation-level detail rather than the project overview.

- [SQL engine and query processing](architecture/sql_engine.md)
- [Transactions and MVCC](architecture/transactions_mvcc.md)
- [Secondary indexes](architecture/secondary_indexes.md)
- [Graph engine and Cypher](architecture/graph_engine.md)
- [Bolt protocol](architecture/bolt_protocol.md)
- [Replication and backup](architecture/replication_backup.md)
- [Operational protocols](architecture/operational_protocols.md)
- [Distributed query planner](architecture/distributed_query_planner.md)
- [Cluster sharding](architecture/cluster_sharding.md)
- [Cluster rebalancing](architecture/cluster_rebalancing.md)
- [Routing and persistence](architecture/routing_persistence.md)
- [Event stream](architecture/event_stream.md)
- [QMAG policy](architecture/qmag-policy.md)
- [TRITON Lua injector](architecture/lua_injector.md)

For the full interconnect view, see [Subsystem Architecture](diagrams/subsystem_architecture.md).

## Security

Security documentation is kept separate from general feature documentation so that current limitations and hardening work remain explicit.

Start with:

- [Security documentation](security/README.md)
- [August 2026 UWP audit](security/UWP_AUDIT_2026-08.md)
- [UWP cryptographic design](security/UWP_CRYPTO_DESIGN.md)
- [Security hardening report](security/hardening-report.md)

Do not infer certification from implemented cryptographic features. The current project does not claim third-party audit, FIPS 140-3 validation, or CNSA 2.0 certification.

## Performance and validation

Benchmark methodology and results are under [`benchmarks/`](benchmarks/).

Useful entry points:

- [General benchmark documentation](benchmarks/benchmarks.md)
- [QIHSE + KEYSTONE integrated benchmarks](benchmarks/keystone_qihse_integrated_benchmarks.md)

Performance results should always be read with the hardware, dataset, compiler, ISA, and workload configuration that produced them.

## SDKs

Language bindings are kept with the code rather than duplicated in this documentation tree:

- [Python SDKs](../sdks/python/)
- [Rust SDKs](../sdks/rust/)
- [C SDKs](../sdks/c/)

## Deployment and operations

- [Deployment documentation](deployment/)
- [AF_XDP operational guide](manual/deployment/AF_XDP_OPERATIONAL_GUIDE.md)
- [Replication and backup](architecture/replication_backup.md)
- [Operational protocols](architecture/operational_protocols.md)

## Plans and design work

The [`plans/`](plans/) directory contains design documents and implementation roadmaps. These are useful for understanding intended direction, but a plan should not be treated as evidence that every described capability is complete.

Notable documents include:

- [General database engine roadmap](plans/qihse_general_db_engine_roadmap.md)
- [PostgreSQL and Neo4j replacement plan](plans/qihse_pg_neo4j_full_replacement_plan.md)
- [Redis cluster sharding plan](plans/qihse_redis_cluster_sharding_plan.md)
- [Task queue plan](plans/qihse_task_queue_plan.md)
- [SQLite VFS plan](qihse_sqlite_vfs_plan.md)

## Archive

Historical or superseded material belongs under [`archive/`](archive/). Versioned architecture documents may also be retained in place when they are useful as design-history snapshots; prefer the newest whitepaper and current subsystem documentation for implementation status.
