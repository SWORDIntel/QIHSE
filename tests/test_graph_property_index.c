/* Graph property-index regression and deterministic synthetic scaling fixture.
 * Default run checks every indexed lookup, property removal and deletion. An optional
 * vertex count controls the same-label CodeGraph-like construction workload. */
#define _POSIX_C_SOURCE 200809L
#include "qihse_graph_store.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}
static uint64_t add(qihse_graph_t *g, const char *label, const char *property,
                    const char *value) {
    graph_prop_t p = graph_prop_make_string(value);
    uint64_t id = qihse_graph_vertex_create(g, &label, 1, &property, &p, 1);
    graph_prop_free(&p);
    assert(id);
    return id;
}
static void lookup(qihse_graph_t *g, const char *label, const char *property,
                   const char *value, uint64_t expected) {
    uint64_t ids[2];
    graph_prop_t p = graph_prop_make_string(value);
    size_t n = qihse_graph_get_vertices_by_property(g, label, property, &p, ids, 2);
    graph_prop_free(&p);
    if (n != (expected ? 1u : 0u)) fprintf(stderr, "lookup (%s,%s,%s) got %zu expected %" PRIu64 "\n", label, property, value, n, expected);
    assert(n == (expected ? 1u : 0u));
    if (expected) assert(ids[0] == expected);
}
static void boundaries(void) {
    qihse_graph_t *g = qihse_graph_create(); assert(g);
    uint64_t short_id = add(g, "f", "n", "a");
    /* These unequal-length values collide in the initial 256-bucket map. */
    uint64_t long_id = add(g, "f", "n", "a_much_longer_value_than_the_first_allocation_113");
    uint64_t a = add(g, "ab", "c", "value");
    uint64_t b = add(g, "a", "bc", "value");
    uint64_t c = add(g, "ab", "", "cvalue");
    uint64_t d = add(g, "", "abc", "value");
    lookup(g, "f", "n", "a", short_id);
    lookup(g, "f", "n", "a_much_longer_value_than_the_first_allocation_113", long_id);
    lookup(g, "ab", "c", "value", a);
    lookup(g, "a", "bc", "value", b);
    lookup(g, "ab", "", "cvalue", c);
    lookup(g, "", "abc", "value", d);
    lookup(g, "abc", "", "value", 0);
    assert(qihse_graph_vertex_remove_property(g, long_id, "n"));
    lookup(g, "f", "n", "a_much_longer_value_than_the_first_allocation_113", 0);
    assert(qihse_graph_vertex_delete(g, short_id));
    lookup(g, "f", "n", "a", 0);
    qihse_graph_destroy(g);
}
int main(int argc, char **argv) {
    size_t count = argc > 1 ? strtoul(argv[1], NULL, 10) : 4000;
    assert(count > 0 && count <= 1000000);
    boundaries();
    qihse_graph_t *g = qihse_graph_create(); assert(g);
    const char *label = "Function", *keys[] = {"name", "file"};
    char name[96], file[96];
    double begin = now();
    for (size_t i = 0; i < count; ++i) {
        snprintf(name, sizeof(name), "symbol_%zu", i);
        snprintf(file, sizeof(file), "src/module_%zu.c", i);
        graph_prop_t values[] = {graph_prop_make_string(name), graph_prop_make_string(file)};
        assert(qihse_graph_vertex_create(g, &label, 1, keys, values, 2) == i + 1);
        graph_prop_free(&values[0]); graph_prop_free(&values[1]);
    }
    double built = now();
    for (size_t i = 0; i < count; ++i) {
        snprintf(name, sizeof(name), "symbol_%zu", i);
        snprintf(file, sizeof(file), "src/module_%zu.c", i);
        lookup(g, label, "name", name, i + 1);
        lookup(g, label, "file", file, i + 1);
    }
    double queried = now();
    assert(qihse_graph_vertex_count(g) == count);
    printf("{\"vertices\":%zu,\"properties\":%zu,\"build_ms\":%.3f,\"lookup_ms\":%.3f,\"verified\":true}\n",
           count, 2 * count, (built-begin)*1000, (queried-built)*1000);
    qihse_graph_destroy(g);
    return 0;
}
