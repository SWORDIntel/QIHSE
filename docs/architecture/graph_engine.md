# Graph Engine & Cypher

## Overview

QIHSE's Graph Engine provides explicit vertex/edge storage with a Cypher-compatible query language, making QIHSE a drop-in replacement for Neo4j. The engine integrates with the vector DB for hybrid similarity+traversal search.

## Components

### Graph Store (`src/broad_oak/qihse_graph_store.c`)
- **Vertices**: ID, labels, properties (key-value map)
- **Edges**: ID, source, target, edge type, properties
- **Indexes**: Label index, edge-type index, property index for fast lookups
- **Adjacency lists**: Forward and backward adjacency for efficient traversal

### Cypher Parser (`src/tractable/qihse_cypher_parser.c`)
Recursive-descent parser supporting:
- `MATCH` — pattern matching with node/edge patterns
- `CREATE` — create vertices and edges
- `MERGE` — upsert (create if not exists)
- `DELETE` — remove vertices or edges
- `SET` — update properties
- `WHERE` — filtering conditions
- `RETURN` — projection
- `WITH` — query chaining
- `ORDER BY` — sorting
- `LIMIT` — result count limiting

### Cypher Executor (`src/tractable/qihse_cypher_executor.c`)
- Pattern matching with backtracking
- Expression evaluation (property access, comparisons, logical ops)
- Aggregation and grouping
- Result projection

### Graph Algorithms (`src/broad_oak/qihse_graph_algo.c`)
SIMD-accelerated algorithms:
- **Traversal**: BFS, DFS
- **Shortest path**: Dijkstra, A*, Floyd-Warshall
- **Centrality**: PageRank, betweenness, closeness
- **Community detection**: Connected components, SCC, triangle counting
- **Other**: Cycle detection, topological sort, Jaccard similarity

### Graph+Vector Fusion (`src/broad_oak/qihse_graph_vector.c`)
- Hybrid similarity+traversal search
- Vector-guided graph traversal
- Subgraph embedding
- Hybrid recommendations

## Bolt Protocol (`src/spinnaker/qihse_bolt.c`)
Neo4j Bolt 4.x wire protocol server:
- PackStream serialization (null, bool, int, float, string, list, map, struct)
- Node (0x4E), Relationship (0x52), Path (0x50) structs
- Messages: HELLO, GOODBYE, RESET, RUN, PULL, DISCARD, BEGIN, COMMIT, ROLLBACK
- Responses: SUCCESS, RECORD, FAILURE, IGNORED

## Protocol Translation (`src/spinnaker/qihse_protocol_translate.c`)
- PG wire messages → UWP packets
- Bolt messages → UWP packets
- SQL AST → UWP execution plan
- Cypher AST → UWP execution plan

## Testing
12 tests in `tests/test_graph.c` covering:
- Vertex/edge CRUD
- Label and property indexing
- Cypher MATCH/CREATE/DELETE/SET/RETURN
- Graph algorithms (BFS, Dijkstra, PageRank)
- Graph+vector fusion search
