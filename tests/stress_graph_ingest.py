import csv
import json
import os
import random
import sys
import tempfile
import time
import traceback

sys.path.insert(0, "/fast/home/john/SPECTRA")
from tgarchive.search.qihse_graph_bindings import GraphStore

def generate_vertices_csv(filepath, count):
    print(f"Generating {count} vertices to {filepath}...")
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([":ID", "name:STRING", "score:INT", ":LABEL"])
        for i in range(1, count + 1):
            writer.writerow([f"v{i}", f"User_{i}", random.randint(1, 100), "Person"])

def generate_edges_csv(filepath, count, max_vertex_id):
    print(f"Generating {count} edges to {filepath}...")
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([":START_ID", ":END_ID", ":TYPE"])
        for i in range(count):
            start = f"v{random.randint(1, max_vertex_id)}"
            end = f"v{random.randint(1, max_vertex_id)}"
            writer.writerow([start, end, "KNOWS"])

def generate_vertices_jsonl(filepath, count, start_id):
    print(f"Generating {count} JSONL vertices to {filepath}...")
    with open(filepath, "w") as f:
        for i in range(start_id, start_id + count):
            doc = {
                "id": f"v{i}",
                "labels": ["Organization"],
                "properties": {
                    "name": f"Org_{i}",
                    "founded": 2000 + (i % 24)
                }
            }
            f.write(json.dumps(doc) + "\n")

def generate_error_edges_csv(filepath):
    print(f"Generating missing endpoint edges to {filepath}...")
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([":START_ID", ":END_ID", ":TYPE"])
        writer.writerow(["v999999", "v888888", "KNOWS"])  # These IDs don't exist
        writer.writerow(["v1", "v777777", "KNOWS"])

def main():
    num_vertices = 50000
    num_edges = 200000
    num_jsonl_vertices = 5000

    temp_dir = tempfile.mkdtemp()
    v_csv = os.path.join(temp_dir, "vertices.csv")
    e_csv = os.path.join(temp_dir, "edges.csv")
    v_jsonl = os.path.join(temp_dir, "vertices.jsonl")
    err_e_csv = os.path.join(temp_dir, "error_edges.csv")

    generate_vertices_csv(v_csv, num_vertices)
    generate_edges_csv(e_csv, num_edges, num_vertices)
    generate_vertices_jsonl(v_jsonl, num_jsonl_vertices, num_vertices + 1)
    generate_error_edges_csv(err_e_csv)

    print("\n--- Starting Ingest Tests ---")
    store = GraphStore()

    # 1. Ingest Vertices CSV
    start_time = time.time()
    v_count, v_err = store.ingest_vertices_csv(v_csv, has_header=True, id_column=":ID", label_column=":LABEL")
    elapsed = time.time() - start_time
    print(f"Vertices CSV ingest: {v_count} records in {elapsed:.4f}s ({v_count/elapsed:.0f} rec/s). Errors: {v_err}")

    # 2. Ingest Edges CSV
    start_time = time.time()
    e_count, e_err = store.ingest_edges_csv(e_csv, has_header=True, start_column=":START_ID", end_column=":END_ID", type_column=":TYPE")
    elapsed = time.time() - start_time
    print(f"Edges CSV ingest: {e_count} records in {elapsed:.4f}s ({e_count/elapsed:.0f} rec/s). Errors: {e_err}")

    # 3. Ingest Vertices JSONL
    start_time = time.time()
    j_count, j_err = store.ingest_vertices_json(v_jsonl, jsonl=True)
    elapsed = time.time() - start_time
    print(f"Vertices JSONL ingest: {j_count} records in {elapsed:.4f}s ({j_count/elapsed:.0f} rec/s). Errors: {j_err}")

    # 4. Verify counts
    actual_v_count = store.vertex_count()
    actual_e_count = store.edge_count()
    expected_v_count = num_vertices + num_jsonl_vertices
    expected_e_count = num_edges
    
    print(f"\n--- Verification ---")
    print(f"Vertex count: {actual_v_count} (Expected: {expected_v_count})")
    print(f"Edge count: {actual_e_count} (Expected: {expected_e_count})")

    # 5. Run BFS from vertex 1
    v1_id = store.lookup_id("v1")
    print(f"\nRunning BFS from internal ID {v1_id} (external 'v1')")
    start_time = time.time()
    bfs_result = store.bfs(v1_id)
    elapsed = time.time() - start_time
    print(f"BFS reached {len(bfs_result)} vertices in {elapsed:.4f}s")

    # 6. Run PageRank
    print(f"\nRunning PageRank")
    start_time = time.time()
    pr_result = store.pagerank(max_vertices=actual_v_count)
    elapsed = time.time() - start_time
    print(f"PageRank computed scores for {len(pr_result)} vertices in {elapsed:.4f}s")

    # 7. Test error handling: missing file
    print(f"\n--- Error Handling Tests ---")
    try:
        count, err = store.ingest_vertices_csv("/path/does/not/exist.csv")
        print(f"Missing file returned count={count}, err={err}")
    except Exception as e:
        print(f"Missing file raised Exception: {e}")

    # 8. Test error handling: missing endpoint IDs
    print(f"Ingesting edges with missing endpoints")
    err_e_count, err_e_err = store.ingest_edges_csv(err_e_csv, has_header=True, start_column=":START_ID", end_column=":END_ID", type_column=":TYPE")
    print(f"Error edges ingest returned count={err_e_count}, errors={err_e_err}")
    
    store.close()
    print("\nStress test complete.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
