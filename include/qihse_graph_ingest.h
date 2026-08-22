#ifndef QIHSE_GRAPH_INGEST_H
#define QIHSE_GRAPH_INGEST_H

#include "qihse_graph_store.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * QIHSE Graph Bulk Ingest — Neo4j-admin-import equivalent.
 *
 * Provides high-throughput bulk loading of property-graph data from CSV and
 * JSON/JSONL files into a qihse_graph_t.  Designed to mirror the Neo4j
 * `neo4j-admin import` workflow:
 *
 *   - Node CSV files:   one row per vertex, columns map to properties
 *   - Edge CSV files:   one row per edge, requires :START_ID / :END_ID columns
 *   - JSON / JSONL:     objects with "labels"/"type", "properties", "start"/"end"
 *
 * CSV conventions (compatible with neo4j-admin import):
 *   - Node files: first column is :ID (or _id), remaining columns are properties.
 *                 A :LABEL column (comma-separated) sets vertex labels.
 *   - Edge files: :START_ID and :END_ID columns, :TYPE column sets edge type,
 *                 remaining columns are edge properties.
 *   - A header row is required when `has_header` is true.
 *
 * JSON format (one object per line for JSONL, or a JSON array for JSON):
 *   Nodes:  {"id": 123, "labels": ["Person"], "properties": {"name": "Alice"}}
 *   Edges:  {"id": 456, "type": "KNOWS", "start": 123, "end": 456,
 *            "properties": {"since": 2020}}
 *
 * All ingest functions return the number of records successfully ingested,
 * or -1 on fatal error.  Partial failures are counted in *out_errors.
 * ============================================================================ */

/* --- CSV ingest --- */

/* Ingest vertices from a CSV file.
 *   filepath:     path to CSV file
 *   has_header:   skip first row if true
 *   id_column:    column name (or 0-based index as string) for the vertex ID.
 *                 If NULL, IDs are auto-assigned.
 *   label_column: column name for labels (comma-separated).  If NULL, no labels.
 *   delimiter:    field delimiter (typically ',')
 *   out_errors:   set to number of failed rows, may be NULL
 * Returns number of vertices created, or -1 on error. */
int64_t qihse_graph_ingest_vertices_csv(qihse_graph_t* g,
                                        const char* filepath,
                                        bool has_header,
                                        const char* id_column,
                                        const char* label_column,
                                        char delimiter,
                                        int64_t* out_errors);

/* Ingest edges from a CSV file.
 *   filepath:     path to CSV file
 *   has_header:   skip first row if true
 *   start_column: column name for :START_ID
 *   end_column:   column name for :END_ID
 *   type_column:  column name for :TYPE (edge type).  If NULL, type defaults to "RELATED".
 *   id_column:    column name for edge ID.  If NULL, auto-assigned.
 *   delimiter:    field delimiter
 *   out_errors:   set to number of failed rows, may be NULL
 * Returns number of edges created, or -1 on error. */
int64_t qihse_graph_ingest_edges_csv(qihse_graph_t* g,
                                     const char* filepath,
                                     bool has_header,
                                     const char* start_column,
                                     const char* end_column,
                                     const char* type_column,
                                     const char* id_column,
                                     char delimiter,
                                     int64_t* out_errors);

/* --- JSON / JSONL ingest --- */

/* Ingest vertices from a JSON array or JSONL file.
 * Each element: {"id": int, "labels": [...], "properties": {...}}
 * If "id" is absent, auto-assigned. */
int64_t qihse_graph_ingest_vertices_json(qihse_graph_t* g,
                                         const char* filepath,
                                         bool jsonl,
                                         int64_t* out_errors);

/* Ingest edges from a JSON array or JSONL file.
 * Each element: {"id": int, "type": "KNOWS", "start": int, "end": int, "properties": {...}} */
int64_t qihse_graph_ingest_edges_json(qihse_graph_t* g,
                                      const char* filepath,
                                      bool jsonl,
                                      int64_t* out_errors);

/* --- Convenience: ingest a whole directory --- */

/* Ingest all node CSV files and edge CSV files from a directory.
 * Node files: *.nodes.csv or nodes.csv
 * Edge files: *.edges.csv or edges.csv or *.relationships.csv
 * Returns total records ingested, or -1 on error. */
int64_t qihse_graph_ingest_directory(qihse_graph_t* g,
                                     const char* dirpath,
                                     int64_t* out_errors);

/* --- ID remapping --- */

/* After ingesting vertices with external string IDs (e.g. from CSV :ID columns),
 * this maps an external string ID to the internal uint64_t vertex ID.
 * Returns 0 if not found. */
uint64_t qihse_graph_ingest_lookup_id(qihse_graph_t* g, const char* external_id);

/* Register an external ID → internal ID mapping (called automatically by
 * the CSV/JSON ingest functions). */
void qihse_graph_ingest_register_id(qihse_graph_t* g,
                                    const char* external_id,
                                    uint64_t internal_id);

/* Clear all ID mappings (frees memory). */
void qihse_graph_ingest_clear_ids(qihse_graph_t* g);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_GRAPH_INGEST_H */
