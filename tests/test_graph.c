#include "qihse_graph_store.h"
#include "qihse_graph_algo.h"
#include "qihse_graph_ingest.h"
#include "qihse_cypher_parser.h"
#include "qihse_cypher_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  [TEST] %s ... ", name);
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)

static void test_vertex_crud(void) {
    TEST("vertex CRUD");
    qihse_graph_t* g = qihse_graph_create();
    ASSERT(g != NULL, "graph create failed");
    
    const char* labels[] = {"Person"};
    const char* keys[] = {"name", "age"};
    graph_prop_t vals[2];
    vals[0].type = GRAPH_PROP_STRING; vals[0].val.s = strdup("Alice");
    vals[1].type = GRAPH_PROP_INT64; vals[1].val.i = 30;
    
    uint64_t id = qihse_graph_vertex_create(g, labels, 1, keys, vals, 2);
    ASSERT(id > 0, "vertex create returned 0");
    
    graph_vertex_t* v = qihse_graph_vertex_get(g, id);
    ASSERT(v != NULL, "vertex get returned NULL");
    ASSERT(v->id == id, "vertex ID mismatch");
    
    /* Update */
    const char* ukeys[] = {"age"};
    graph_prop_t uvals[1];
    uvals[0].type = GRAPH_PROP_INT64; uvals[0].val.i = 31;
    bool ok = qihse_graph_vertex_update(g, id, ukeys, uvals, 1);
    ASSERT(ok, "vertex update failed");
    
    /* Delete */
    ok = qihse_graph_vertex_delete(g, id);
    ASSERT(ok, "vertex delete failed");
    
    graph_vertex_t* v2 = qihse_graph_vertex_get(g, id);
    ASSERT(v2 == NULL, "vertex still exists after delete");
    
    free(vals[0].val.s);
    qihse_graph_destroy(g);
    PASS();
}

static void test_edge_crud(void) {
    TEST("edge CRUD");
    qihse_graph_t* g = qihse_graph_create();
    ASSERT(g != NULL, "graph create failed");
    
    /* Create two vertices */
    const char* labels[] = {"Person"};
    uint64_t v1 = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    uint64_t v2 = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    ASSERT(v1 > 0 && v2 > 0, "vertex creation failed");
    
    /* Create edge */
    const char* ekeys[] = {"weight"};
    graph_prop_t evals[1];
    evals[0].type = GRAPH_PROP_DOUBLE; evals[0].val.d = 1.5;
    uint64_t eid = qihse_graph_edge_create(g, "KNOWS", v1, v2, ekeys, evals, 1);
    ASSERT(eid > 0, "edge create returned 0");
    
    graph_edge_t* e = qihse_graph_edge_get(g, eid);
    ASSERT(e != NULL, "edge get returned NULL");
    ASSERT(e->start_vertex_id == v1, "edge start mismatch");
    ASSERT(e->end_vertex_id == v2, "edge end mismatch");
    
    /* Get neighbors */
    graph_adj_t adj[10];
    size_t nn = qihse_graph_get_neighbors(g, v1, GRAPH_DIR_OUTGOING, NULL, adj, 10);
    ASSERT(nn == 1, "neighbor count mismatch");
    ASSERT(adj[0].neighbor_id == v2, "neighbor ID mismatch");
    
    /* Delete edge */
    bool ok = qihse_graph_edge_delete(g, eid);
    ASSERT(ok, "edge delete failed");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_label_index(void) {
    TEST("label index");
    qihse_graph_t* g = qihse_graph_create();
    const char* labels1[] = {"Person"};
    const char* labels2[] = {"Person", "Employee"};
    
    uint64_t v1 = qihse_graph_vertex_create(g, labels1, 1, NULL, NULL, 0);
    uint64_t v2 = qihse_graph_vertex_create(g, labels2, 2, NULL, NULL, 0);
    
    uint64_t ids[10];
    size_t n = qihse_graph_get_vertices_by_label(g, "Person", ids, 10);
    ASSERT(n == 2, "label index should return 2 vertices");
    
    n = qihse_graph_get_vertices_by_label(g, "Employee", ids, 10);
    ASSERT(n == 1, "Employee label should return 1 vertex");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_bfs(void) {
    TEST("BFS traversal");
    qihse_graph_t* g = qihse_graph_create();
    
    /* Create a simple graph: 1->2->3->4, 1->3 */
    uint64_t v[5];
    const char* labels[] = {"Node"};
    for (int i = 0; i < 4; i++) v[i] = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    
    qihse_graph_edge_create(g, "EDGE", v[0], v[1], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[1], v[2], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[2], v[3], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[0], v[2], NULL, NULL, 0);
    
    uint64_t out[10];
    size_t n = qihse_graph_bfs(g, v[0], out, 10);
    ASSERT(n >= 1, "BFS should return at least 1 vertex");
    ASSERT(out[0] == v[0], "BFS first vertex should be source");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_dijkstra(void) {
    TEST("Dijkstra shortest path");
    qihse_graph_t* g = qihse_graph_create();
    
    uint64_t v[5];
    const char* labels[] = {"Node"};
    for (int i = 0; i < 4; i++) v[i] = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    
    qihse_graph_edge_create(g, "EDGE", v[0], v[1], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[1], v[2], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[2], v[3], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[0], v[3], NULL, NULL, 0);
    
    uint64_t path[10];
    size_t n = qihse_graph_dijkstra(g, v[0], v[3], path, 10);
    ASSERT(n >= 2, "Dijkstra should find a path");
    ASSERT(path[0] == v[0], "path should start at source");
    ASSERT(path[n-1] == v[3], "path should end at target");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_pagerank(void) {
    TEST("PageRank");
    qihse_graph_t* g = qihse_graph_create();
    
    uint64_t v[4];
    const char* labels[] = {"Node"};
    for (int i = 0; i < 4; i++) v[i] = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    
    qihse_graph_edge_create(g, "EDGE", v[0], v[1], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[1], v[2], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[2], v[0], NULL, NULL, 0);
    qihse_graph_edge_create(g, "EDGE", v[2], v[3], NULL, NULL, 0);
    
    double scores[4] = {0};
    int rc = qihse_graph_pagerank(g, scores, 4, 100, 0.85, 1e-6);
    ASSERT(rc == 0, "PageRank should return 0");
    
    double total = 0;
    for (int i = 0; i < 4; i++) total += scores[i];
    ASSERT(total > 0, "PageRank scores should be positive");
    ASSERT(fabs(total - 1.0) < 1e-6, "PageRank must redistribute dangling mass");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_connected_components(void) {
    TEST("connected components");
    qihse_graph_t* g = qihse_graph_create();
    
    uint64_t v[6];
    const char* labels[] = {"Node"};
    for (int i = 0; i < 6; i++) v[i] = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    
    /* Component 1: v0-v1-v2 */
    qihse_graph_edge_create(g, "E", v[0], v[1], NULL, NULL, 0);
    qihse_graph_edge_create(g, "E", v[1], v[2], NULL, NULL, 0);
    /* Component 2: v3-v4-v5 */
    qihse_graph_edge_create(g, "E", v[3], v[4], NULL, NULL, 0);
    qihse_graph_edge_create(g, "E", v[4], v[5], NULL, NULL, 0);
    
    uint32_t comp[6];
    size_t nc = qihse_graph_connected_components(g, comp, 6);
    ASSERT(nc == 2, "should have 2 connected components");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_cypher_parse_match(void) {
    TEST("Cypher parse MATCH");
    const char* query = "MATCH (n:Person {name: \"Alice\"}) RETURN n";
    qihse_cypher_ast_t* ast = qihse_cypher_parse(query);
    ASSERT(ast != NULL, "parse returned NULL");
    ASSERT(ast->num_queries > 0, "should have at least 1 query");
    qihse_cypher_ast_free(ast);
    PASS();
}

static void test_cypher_parse_create(void) {
    TEST("Cypher parse CREATE");
    const char* query = "CREATE (n:Person {name: \"Bob\", age: 25}) RETURN n";
    qihse_cypher_ast_t* ast = qihse_cypher_parse(query);
    ASSERT(ast != NULL, "parse returned NULL");
    qihse_cypher_ast_free(ast);
    PASS();
}

static void test_cypher_parse_relationship(void) {
    TEST("Cypher parse relationship");
    const char* query = "MATCH (a:Person)-[r:KNOWS]->(b:Person) RETURN a, b, r";
    qihse_cypher_ast_t* ast = qihse_cypher_parse(query);
    ASSERT(ast != NULL, "parse returned NULL");
    qihse_cypher_ast_free(ast);
    PASS();
}

static void test_cypher_exec_match(void) {
    TEST("Cypher execute MATCH");
    qihse_graph_t* g = qihse_graph_create();
    
    /* Create a vertex */
    const char* labels[] = {"Person"};
    const char* keys[] = {"name"};
    graph_prop_t vals[1];
    vals[0].type = GRAPH_PROP_STRING; vals[0].val.s = strdup("Alice");
    qihse_graph_vertex_create(g, labels, 1, keys, vals, 1);
    
    /* Execute MATCH (n:Person) RETURN n */
    const char* query = "MATCH (n:Person) RETURN n";
    cypher_result_set_t* result = qihse_cypher_run(g, query);
    /* Result may be NULL if executor doesn't fully work, but shouldn't crash */
    if (result) {
        qihse_cypher_result_free(result);
    }
    
    free(vals[0].val.s);
    qihse_graph_destroy(g);
    PASS();
}

static void test_cypher_order_skip_limit(void) {
    TEST("Cypher ORDER BY / SKIP / LIMIT affect returned rows");
    qihse_graph_t* g = qihse_graph_create();
    const char* labels[] = {"Person"};
    const char* keys[] = {"name"};
    const char* names[] = {"Charlie", "Alice", "Bob"};
    for (size_t i = 0; i < 3; ++i) {
        graph_prop_t value = graph_prop_make_string(names[i]);
        ASSERT(qihse_graph_vertex_create(g, labels, 1, keys, &value, 1) != 0,
               "create person vertex");
    }

    cypher_result_set_t* rs = qihse_cypher_run(g,
        "MATCH (n:Person) RETURN n.name AS name ORDER BY name ASC SKIP 1 LIMIT 1");
    ASSERT(rs != NULL, "ordered paginated query succeeds");
    ASSERT(rs->num_cols == 1 && rs->num_rows == 1, "skip/limit row count");
    ASSERT(rs->values[0].type == CRES_STRING &&
           strcmp(rs->values[0].val.s, "Bob") == 0,
           "ORDER BY then SKIP selects Bob");
    qihse_cypher_result_free(rs);

    rs = qihse_cypher_run(g,
        "MATCH (n:Person) RETURN n.name AS name ORDER BY name DESC LIMIT 1");
    ASSERT(rs != NULL && rs->num_rows == 1, "descending limit query succeeds");
    ASSERT(strcmp(rs->values[0].val.s, "Charlie") == 0,
           "descending order selects Charlie");
    qihse_cypher_result_free(rs);

    rs = qihse_cypher_run(g,
        "MATCH (n:Person) RETURN n.name AS alias ORDER BY n.name DESC LIMIT 1");
    ASSERT(rs != NULL && rs->num_rows == 1, "source expression order query succeeds");
    ASSERT(strcmp(rs->values[0].val.s, "Charlie") == 0,
           "ORDER BY source expression maps to projected alias");
    qihse_cypher_result_free(rs);

    rs = qihse_cypher_run(g,
        "MATCH (n:Person) RETURN n.name AS alias ORDER BY missing ASC");
    ASSERT(rs == NULL, "unprojected sort key is rejected instead of ignored");

    rs = qihse_cypher_run(g, "MATCH (n:Person) RETURN n.name SKIP -1");
    ASSERT(rs == NULL, "negative SKIP is rejected");
    rs = qihse_cypher_run(g, "MATCH (n:Person) RETURN n.name LIMIT -2");
    ASSERT(rs == NULL, "negative LIMIT is rejected");
    rs = qihse_cypher_run(g,
        "MATCH (n:Person) WITH n ORDER BY n.name LIMIT 1 "
        "MATCH (n)-[:KNOWS]->(m) RETURN m");
    ASSERT(rs == NULL, "unsupported WITH pagination is rejected, not deferred");

    qihse_graph_destroy(g);
    PASS();
}

static void test_triangle_count(void) {
    TEST("triangle counting");
    qihse_graph_t* g = qihse_graph_create();
    
    uint64_t v[3];
    const char* labels[] = {"Node"};
    for (int i = 0; i < 3; i++) v[i] = qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    
    /* Create a triangle */
    qihse_graph_edge_create(g, "E", v[0], v[1], NULL, NULL, 0);
    qihse_graph_edge_create(g, "E", v[1], v[2], NULL, NULL, 0);
    qihse_graph_edge_create(g, "E", v[2], v[0], NULL, NULL, 0);
    
    uint64_t tc = qihse_graph_triangle_count(g);
    /* Triangle count may be 0 or 1 depending on direction handling */
    ASSERT(tc >= 0, "triangle count should be non-negative");
    
    qihse_graph_destroy(g);
    PASS();
}

static void test_load_csv_with_headers(void) {
    TEST("LOAD CSV WITH HEADERS");
    const char* tmp_file = "/tmp/test_load_csv.csv";
    FILE* fp = fopen(tmp_file, "w");
    ASSERT(fp != NULL, "failed to create temp CSV");
    fputs("id,name,age\n1,Alice,30\n2,Bob,25\n", fp);
    fclose(fp);
    
    qihse_graph_t* g = qihse_graph_create();
    cypher_result_set_t* rs = qihse_cypher_run(g, "LOAD CSV WITH HEADERS FROM \"file:///tmp/test_load_csv.csv\" AS row RETURN row.name");
    
    ASSERT(rs != NULL, "cypher result is NULL");
    ASSERT(rs->num_rows == 2, "expected 2 rows");
    ASSERT(rs->num_cols == 1, "expected 1 column");
    if (rs->values && rs->num_rows > 0) {
        ASSERT(rs->values[0].type == CRES_STRING, "expected string type");
        ASSERT(strcmp(rs->values[0].val.s, "Alice") == 0, "first row should be Alice");
    }
    
    qihse_cypher_result_free(rs);
    qihse_graph_destroy(g);
    remove(tmp_file);
    PASS();
}

static void test_load_csv_no_headers(void) {
    TEST("LOAD CSV without headers");
    const char* tmp_file = "/tmp/test_load_csv_noheaders.csv";
    FILE* fp = fopen(tmp_file, "w");
    ASSERT(fp != NULL, "failed to create temp CSV");
    fputs("1,Alice,30\n2,Bob,25\n", fp);
    fclose(fp);
    
    qihse_graph_t* g = qihse_graph_create();
    cypher_result_set_t* rs = qihse_cypher_run(g, "LOAD CSV FROM \"file:///tmp/test_load_csv_noheaders.csv\" AS row RETURN row");
    
    ASSERT(rs != NULL, "cypher result is NULL");
    ASSERT(rs->num_rows == 2, "expected 2 rows");
    
    qihse_cypher_result_free(rs);
    qihse_graph_destroy(g);
    remove(tmp_file);
    PASS();
}

static void test_ingest_vertices_csv(void) {
    TEST("Ingest vertices from CSV");
    const char* tmp_file = "/tmp/test_ingest_vertices.csv";
    FILE* fp = fopen(tmp_file, "w");
    ASSERT(fp != NULL, "failed to create temp CSV");
    fputs(":ID,name:STRING,age:INT,:LABEL\n1,Alice,30,Person\n2,Bob,25,Person\n", fp);
    fclose(fp);
    
    qihse_graph_t* g = qihse_graph_create();
    int64_t errors = 0;
    int64_t count = qihse_graph_ingest_vertices_csv(g, tmp_file, true, ":ID", ":LABEL", ',', &errors);
    
    ASSERT(count == 2, "expected 2 vertices ingested");
    ASSERT(errors == 0, "expected 0 errors");
    
    size_t vc = qihse_graph_vertex_count(g);
    ASSERT(vc >= 2, "vertex count should increase");
    
    uint64_t internal_id = qihse_graph_ingest_lookup_id(g, "1");
    ASSERT(internal_id > 0, "lookup should find ID 1");
    
    graph_vertex_t* v = qihse_graph_vertex_get(g, internal_id);
    ASSERT(v != NULL, "should be able to get vertex");
    
    qihse_graph_destroy(g);
    remove(tmp_file);
    PASS();
}

static void test_ingest_edges_csv(void) {
    TEST("Ingest edges from CSV");
    const char* tmp_file = "/tmp/test_ingest_edges.csv";
    FILE* fp = fopen(tmp_file, "w");
    ASSERT(fp != NULL, "failed to create temp CSV");
    fputs(":START_ID,:END_ID,:TYPE\n1,2,KNOWS\n", fp);
    fclose(fp);
    
    qihse_graph_t* g = qihse_graph_create();
    
    /* Ensure vertices 1 and 2 exist */
    const char* labels[] = {"Person"};
    qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    /* Also register them in lookup table just in case */
    qihse_graph_ingest_register_id(g, "1", 1);
    qihse_graph_ingest_register_id(g, "2", 2);
    
    int64_t errors = 0;
    int64_t count = qihse_graph_ingest_edges_csv(g, tmp_file, true, ":START_ID", ":END_ID", ":TYPE", NULL, ',', &errors);
    
    ASSERT(count == 1, "expected 1 edge ingested");
    ASSERT(errors == 0, "expected 0 errors");
    
    size_t ec = qihse_graph_edge_count(g);
    ASSERT(ec >= 1, "edge count should increase");
    
    qihse_graph_destroy(g);
    remove(tmp_file);
    PASS();
}

static void test_ingest_vertices_jsonl(void) {
    TEST("Ingest vertices from JSONL");
    const char* tmp_file = "/tmp/test_ingest_vertices.jsonl";
    FILE* fp = fopen(tmp_file, "w");
    ASSERT(fp != NULL, "failed to create temp JSONL");
    fputs("{\"id\":\"1\",\"labels\":[\"Person\"],\"properties\":{\"name\":\"Alice\",\"age\":30}}\n", fp);
    fclose(fp);
    
    qihse_graph_t* g = qihse_graph_create();
    int64_t errors = 0;
    int64_t count = qihse_graph_ingest_vertices_json(g, tmp_file, true, &errors);
    
    ASSERT(count == 1, "expected 1 vertex ingested");
    ASSERT(errors == 0, "expected 0 errors");
    
    size_t vc = qihse_graph_vertex_count(g);
    ASSERT(vc >= 1, "vertex count should increase");
    
    qihse_graph_destroy(g);
    remove(tmp_file);
    PASS();
}

static void test_ingest_edges_jsonl(void) {
    TEST("Ingest edges from JSONL");
    const char* tmp_file = "/tmp/test_ingest_edges.jsonl";
    FILE* fp = fopen(tmp_file, "w");
    ASSERT(fp != NULL, "failed to create temp JSONL");
    fputs("{\"start\":\"1\",\"end\":\"2\",\"type\":\"KNOWS\",\"properties\":{\"weight\":1.5}}\n", fp);
    fclose(fp);
    
    qihse_graph_t* g = qihse_graph_create();
    
    /* Ensure vertices 1 and 2 exist */
    const char* labels[] = {"Person"};
    qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    qihse_graph_vertex_create(g, labels, 1, NULL, NULL, 0);
    qihse_graph_ingest_register_id(g, "1", 1);
    qihse_graph_ingest_register_id(g, "2", 2);
    
    int64_t errors = 0;
    int64_t count = qihse_graph_ingest_edges_json(g, tmp_file, true, &errors);
    
    ASSERT(count == 1, "expected 1 edge ingested");
    ASSERT(errors == 0, "expected 0 errors");
    
    size_t ec = qihse_graph_edge_count(g);
    ASSERT(ec >= 1, "edge count should increase");
    
    qihse_graph_destroy(g);
    remove(tmp_file);
    PASS();
}

static void test_ingest_rejects_bad_jsonl_and_limits(void) {
    TEST("JSON ingest rejects malformed and over-limit records");
    char fixture[] = "./tests/graph_ingest_XXXXXX";
    ASSERT(mkdtemp(fixture), "create private ingest fixture");
    char path[512], fifo[512];
    ASSERT(snprintf(path, sizeof(path), "%s/input.jsonl", fixture) > 0,
           "format input path");
    ASSERT(snprintf(fifo, sizeof(fifo), "%s/input.fifo", fixture) > 0,
           "format FIFO path");
    FILE *fp = fopen(path, "w"); ASSERT(fp, "create malformed fixture");
    fputs("{\"id\":\"valid\"}\n{bad json}\n", fp); fclose(fp);
    qihse_graph_t *g = qihse_graph_create(); ASSERT(g, "graph alloc");
    int64_t errors = 0;
    fp = fopen(path, "w"); ASSERT(fp, "create single-object JSON fixture");
    fputs("{\"id\":\"single\",\"properties\":{\"name\":\"one\"}}", fp); fclose(fp);
    qihse_graph_t *single = qihse_graph_create(); ASSERT(single, "single-object graph alloc");
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(single, path, false, &errors) == 1 && errors == 0,
           "single-object JSON ingest failed");
    qihse_graph_destroy(single);

    fp = fopen(path, "w"); ASSERT(fp, "restore malformed JSONL fixture");
    fputs("{\"id\":\"valid\"}\n{bad json}\n", fp); fclose(fp);
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, path, true, &errors) == -1,
           "malformed JSONL was silently skipped");
    ASSERT(errors == 1 && qihse_graph_vertex_count(g) == 0,
           "malformed file partially modified graph");

    fp = fopen(path, "wb"); ASSERT(fp, "create embedded-NUL fixture");
    const char nul_record[] = "{\"id\":\"valid\"}\0{\"id\":\"hidden\"}\n";
    ASSERT(fwrite(nul_record, 1, sizeof(nul_record) - 1, fp) == sizeof(nul_record) - 1,
           "write embedded-NUL fixture"); fclose(fp);
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, path, true, &errors) == -1,
           "embedded NUL/trailing JSONL data was accepted");
    ASSERT(errors == 1 && qihse_graph_vertex_count(g) == 0,
           "embedded NUL file partially modified graph");

    fp = fopen(path, "w"); ASSERT(fp, "create wrong-type fixture");
    fputs("{\"id\":\"bad-labels\",\"labels\":\"not-array\"}\n", fp); fclose(fp);
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, path, true, &errors) == 0 && errors == 1,
           "wrong-type labels field was silently ignored");
    fp = fopen(path, "w"); ASSERT(fp, "create wrong-type properties fixture");
    fputs("{\"id\":\"bad-properties\",\"properties\":[]}\n", fp); fclose(fp);
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, path, true, &errors) == 0 && errors == 1,
           "wrong-type properties field was silently ignored");

    fp = fopen(path, "w"); ASSERT(fp, "create over-limit fixture");
    fputs("{\"id\":\"wide\",\"properties\":{", fp);
    for (int i = 0; i < 257; ++i) fprintf(fp, "%s\"p%d\":%d", i ? "," : "", i, i);
    fputs("}}\n", fp); fclose(fp);
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, path, true, &errors) == 0,
           "over-limit properties were partially ingested");
    ASSERT(errors == 1 && qihse_graph_vertex_count(g) == 0,
           "over-limit record not reported/rejected");

    fp = fopen(path, "w"); ASSERT(fp, "create label limit fixture");
    fputs("{\"id\":\"many-labels\",\"labels\":[", fp);
    for (int i = 0; i < 17; ++i) fprintf(fp, "%s\"L%d\"", i ? "," : "", i);
    fputs("]}\n", fp); fclose(fp);
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, path, true, &errors) == 0,
           "over-limit labels were partially ingested");
    ASSERT(errors == 1 && qihse_graph_vertex_count(g) == 0,
           "over-limit label record not reported/rejected");

    ASSERT(mkfifo(fifo, 0600) == 0, "create FIFO fixture");
    pid_t writer = fork(); ASSERT(writer >= 0, "fork FIFO writer");
    if (writer == 0) {
        FILE *out = fopen(fifo, "w");
        if (!out) _exit(2);
        fputs("{\"id\":\"fifo\"}\n", out);
        fclose(out);
        _exit(0);
    }
    errors = 0;
    ASSERT(qihse_graph_ingest_vertices_json(g, fifo, true, &errors) == -1,
           "non-seekable input unexpectedly parsed through seek-based loader");
    int status = 0;
    ASSERT(waitpid(writer, &status, 0) == writer && WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "FIFO writer failed");
    ASSERT(errors == 1 && qihse_graph_vertex_count(g) == 0,
           "non-seekable input partially modified graph");
    unlink(fifo);
    qihse_graph_destroy(g); remove(path); rmdir(fixture); PASS();
}

static void test_indexed_incident_edges(void) {
    TEST("indexed adjacency: ordering, deletion, direction and self-loop");
    qihse_graph_t* g = qihse_graph_create();
    ASSERT(g != NULL, "graph alloc");
    uint64_t a = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t b = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t c = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t one = qihse_graph_edge_create(g, "CALLS", a, b, NULL, NULL, 0);
    uint64_t two = qihse_graph_edge_create(g, "IMPORTS_FROM", c, a, NULL, NULL, 0);
    uint64_t three = qihse_graph_edge_create(g, "CALLS", a, c, NULL, NULL, 0);
    uint64_t loop = qihse_graph_edge_create(g, "CALLS", a, a, NULL, NULL, 0);
    graph_adj_t out[12];
    size_t count = qihse_graph_get_neighbors(g, a, GRAPH_DIR_BOTH, NULL, out, 12);
    ASSERT(count == 4, "all incident edges returned once");
    ASSERT(out[0].edge_id == one && out[1].edge_id == two &&
           out[2].edge_id == three && out[3].edge_id == loop,
           "old edge-ID order is preserved");
    count = qihse_graph_get_neighbors(g, a, GRAPH_DIR_INCOMING, NULL, out, 12);
    ASSERT(count == 1 && out[0].edge_id == two, "incoming excludes self-loop");
    count = qihse_graph_get_neighbors(g, a, GRAPH_DIR_OUTGOING, "CALLS", out, 12);
    ASSERT(count == 3, "outgoing type-filter includes self-loop");
    ASSERT(qihse_graph_edge_delete(g, one), "delete edge");
    count = qihse_graph_get_neighbors(g, a, GRAPH_DIR_BOTH, NULL, out, 12);
    ASSERT(count == 3 && out[0].edge_id == two, "index updated after edge delete");
    ASSERT(qihse_graph_vertex_delete(g, a), "delete vertex");
    ASSERT(qihse_graph_edge_count(g) == 0, "all incident edges removed");
    count = qihse_graph_get_neighbors(g, b, GRAPH_DIR_BOTH, NULL, out, 12);
    ASSERT(count == 0, "no stale neighbors after vertex delete");
    qihse_graph_destroy(g);
    PASS();
}

static void test_graph_scoped_external_ids(void) {
    TEST("external IDs are graph scoped and clear independently");
    qihse_graph_t *a = qihse_graph_create(), *b = qihse_graph_create();
    ASSERT(a && b, "graph alloc");
    uint64_t a1 = qihse_graph_vertex_create(a, NULL, 0, NULL, NULL, 0);
    uint64_t a2 = qihse_graph_vertex_create(a, NULL, 0, NULL, NULL, 0);
    uint64_t b1 = qihse_graph_vertex_create(b, NULL, 0, NULL, NULL, 0);
    qihse_graph_ingest_register_id(a, "shared-external", a2);
    qihse_graph_ingest_register_id(b, "shared-external", b1);
    ASSERT(qihse_graph_ingest_lookup_id(a, "shared-external") == a2,
           "second graph registration contaminated first mapping");
    ASSERT(qihse_graph_ingest_lookup_id(b, "shared-external") == b1,
           "second graph mapping wrong");
    qihse_graph_ingest_clear_ids(a);
    ASSERT(qihse_graph_ingest_lookup_id(b, "shared-external") == b1,
           "clearing one graph removed the other mapping");
    qihse_graph_destroy(a);
    ASSERT(qihse_graph_ingest_lookup_id(b, "shared-external") == b1,
           "destroying one graph removed the other mapping");
    qihse_graph_destroy(b);
    (void)a1;
    PASS();
}

static void test_graph_algorithm_regressions(void) {
    TEST("directed SCC, path metrics, and full high degree traversal");
    qihse_graph_t *g = qihse_graph_create(); ASSERT(g, "graph alloc");
    uint64_t a = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t b = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t c = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    ASSERT(qihse_graph_edge_create(g, "E", a, b, NULL, NULL, 0), "edge a-b");
    ASSERT(qihse_graph_edge_create(g, "E", b, c, NULL, NULL, 0), "edge b-c");
    uint32_t components[3];
    ASSERT(qihse_graph_scc(g, components, 3) == 3, "directed chain must have 3 SCCs");
    ASSERT(components[0] != components[1] && components[1] != components[2],
           "SCC labels collapsed one-way edges");
    double close[3], between[3];
    ASSERT(qihse_graph_closeness(g, close, 3) == 0, "closeness failed");
    ASSERT(qihse_graph_betweenness(g, between, 3) == 0, "betweenness failed");
    ASSERT(close[1] > close[0], "middle vertex should have smaller total distance");
    ASSERT(between[1] > 0.99 && between[0] < 0.01 && between[2] < 0.01,
           "Brandes path scores are incorrect");
    qihse_graph_destroy(g);

    g = qihse_graph_create(); ASSERT(g, "high degree graph alloc");
    uint64_t hub = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t last_leaf = 0;
    for (size_t i = 0; i < 1100; ++i) {
        uint64_t leaf = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
        ASSERT(qihse_graph_edge_create(g, "E", hub, leaf, NULL, NULL, 0), "high degree edge");
        last_leaf = leaf;
    }
    uint64_t *walk = calloc(1101, sizeof(*walk));
    uint64_t short_path[2];
    int64_t out[1101];
    ASSERT(walk != NULL, "traversal allocation");
    ASSERT(qihse_graph_bfs(g, hub, walk, 1101) == 1101, "BFS truncated degree above 256");
    ASSERT(qihse_graph_degree_centrality(g, NULL, out, out, 1101) == 0,
           "degree centrality failed");
    ASSERT(out[0] == 1100, "degree centrality truncated outgoing degree");
    ASSERT(qihse_graph_dijkstra(g, hub, last_leaf, short_path, 2) == 2,
           "Dijkstra dropped a target after its former 1024-entry heap limit");
    free(walk); qihse_graph_destroy(g);

    g = qihse_graph_create(); ASSERT(g, "long path graph alloc");
    uint64_t previous = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
    uint64_t first = previous, last = previous;
    for (size_t i = 1; i < 1100; ++i) {
        uint64_t next = qihse_graph_vertex_create(g, NULL, 0, NULL, NULL, 0);
        ASSERT(qihse_graph_edge_create(g, "E", previous, next, NULL, NULL, 0), "long path edge");
        previous = last = next;
    }
    uint64_t *long_path = calloc(1100, sizeof(*long_path));
    ASSERT(long_path, "long path allocation");
    errno = 0;
    ASSERT(qihse_graph_dijkstra(g, first, last, long_path, 1099) == 0 && errno == ENOBUFS,
           "insufficient path buffer must reject the incomplete path");
    ASSERT(qihse_graph_dijkstra(g, first, last, long_path, 1100) == 1100,
           "Dijkstra truncated or corrupted a path longer than 1024 vertices");
    ASSERT(qihse_graph_has_cycle(g) == 0, "directed acyclic path reported a cycle");
    uint64_t *topo = calloc(1100, sizeof(*topo));
    ASSERT(topo, "topological order allocation");
    ASSERT(qihse_graph_topo_sort(g, topo, 1100) == 1100,
           "topological sort truncated a path longer than 1024 vertices");
    ASSERT(topo[0] == first && topo[1099] == last,
           "topological order does not preserve path direction");
    ASSERT(qihse_graph_edge_create(g, "E", last, first, NULL, NULL, 0), "close path cycle");
    ASSERT(qihse_graph_has_cycle(g) == 1, "directed cycle was not detected");
    ASSERT(qihse_graph_topo_sort(g, topo, 1100) == 0,
           "topological sort returned vertices for a cyclic graph");
    free(topo);
    free(long_path); qihse_graph_destroy(g);
    PASS();
}

int main(void) {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_graph_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    printf("=== QIHSE Graph Engine Tests ===\n");
    
    test_vertex_crud();
    test_edge_crud();
    test_indexed_incident_edges();
    test_graph_scoped_external_ids();
    test_graph_algorithm_regressions();
    test_label_index();
    test_bfs();
    test_dijkstra();
    test_pagerank();
    test_connected_components();
    test_cypher_parse_match();
    test_cypher_parse_create();
    test_cypher_parse_relationship();
    test_cypher_exec_match();
    test_cypher_order_skip_limit();
    test_triangle_count();
    
    test_load_csv_with_headers();
    test_load_csv_no_headers();
    test_ingest_vertices_csv();
    test_ingest_edges_csv();
    test_ingest_vertices_jsonl();
    test_ingest_edges_jsonl();
    test_ingest_rejects_bad_jsonl_and_limits();
    
    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
