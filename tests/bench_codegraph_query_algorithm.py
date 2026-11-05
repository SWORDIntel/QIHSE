#!/usr/bin/env python3
"""Compare bounded query algorithms on synthetic graphs; never opens persisted graph data.

Usage: python3 tests/bench_codegraph_query_algorithm.py --baseline-source OLD_C
       --library-dir BUILD_DIR [--nodes 100000 --repeats 100]
Compiles two harnesses against the same library, verifies exact JSON equivalence,
then reports medians. Timings isolate query_graph (Git/auth/storage are excluded).
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import tempfile

HARNESS = r'''
#define main codegraph_cli_main
#include SOURCE
#undef main

static void fixture(cg_state *st, size_t count) {
    memset(st, 0, sizeof(*st));
    st->lifecycle_fd = st->lease_fd = -1;
    st->nn = count;
    st->graph = qihse_graph_create();
    st->nodes = calloc(count, sizeof(*st->nodes));
    st->by_name = calloc(count, sizeof(*st->by_name));
    st->by_file = calloc(count, sizeof(*st->by_file));
    st->by_vertex = calloc(count + 2, sizeof(*st->by_vertex));
    assert(st->graph && st->nodes && st->by_name && st->by_file && st->by_vertex);
    for (size_t i = 0; i < count; i++) {
        cg_node *n = &st->nodes[i];
        snprintf(n->id, sizeof(n->id), "%064zx", i);
        char file[64], name[64];
        snprintf(file, sizeof(file), "src/file_%04zu.c", i % 128);
        snprintf(name, sizeof(name), "symbol_%08zu", i);
        n->file = strdup(file); n->name = strdup(name); n->kind = strdup("function");
        n->line = i % 1000 + 1; n->end_line = n->line + 2; n->is_test = i % 11 == 0;
        n->vertex = qihse_graph_vertex_create(st->graph, NULL, 0, NULL, NULL, 0);
        assert(n->vertex && n->vertex <= count);
        st->by_vertex[n->vertex] = n;
        st->by_name[i] = st->by_file[i] = n;
    }
    /* High-degree root at the end of the ID range exercises sparse review scans. */
    for (size_t i = 0; i < 2200 && i + 1 < count; i++) {
        assert(qihse_graph_edge_create(st->graph, "CALLS", st->nodes[i].vertex,
                                      st->nodes[count - 1].vertex, NULL, NULL, 0));
        st->edges++;
    }
    for (size_t i = count - 20; i + 1 < count; i++) {
        assert(qihse_graph_edge_create(st->graph, "CALLS", st->nodes[i].vertex,
                                      st->nodes[i + 1].vertex, NULL, NULL, 0));
        st->edges++;
    }
    qsort(st->by_name, count, sizeof(*st->by_name), compare_node_name);
    qsort(st->by_file, count, sizeof(*st->by_file), compare_node_file);
    st->manifest = json_object_new_object();
    json_int(st->manifest, "nodes", count); json_int(st->manifest, "edges", st->edges);
    json_text(st->manifest, "head", "synthetic");
    json_text(st->manifest, "snapshot", "synthetic-generation");
}
int main(int argc, char **argv) {
    size_t count = strtoull(argv[1], NULL, 10);
    int repeats = atoi(argv[2]);
    assert(count >= 3000 && repeats > 0);
#ifdef VERIFY_SCRATCH
    /* A failed cleanup must retain its lease so a later GC can finish it. */
    if (geteuid() != 0) {
        char scratch[] = "cleanup-XXXXXX", blocked[128], lease[128], item[128];
        assert(mkdtemp(scratch));
        snprintf(blocked, sizeof(blocked), "%s/blocked", scratch);
        snprintf(lease, sizeof(lease), "%s/.lease", scratch);
        snprintf(item, sizeof(item), "%s/blocked/item", scratch);
        assert(!mkdir(blocked, 0700));
        int fd = open(lease, O_CREAT | O_WRONLY, 0600); assert(fd >= 0); close(fd);
        fd = open(item, O_CREAT | O_WRONLY, 0600); assert(fd >= 0); close(fd);
        assert(!chmod(blocked, 0));
        assert(remove_scratch(scratch) != 0 && access(lease, F_OK) == 0);
        assert(!chmod(blocked, 0700));
        assert(remove_scratch(scratch) == 0 && access(scratch, F_OK) != 0);
    }
#endif
    cg_state st; fixture(&st, count);
    char last[64], sparse[64], qualified[128];
    snprintf(last, sizeof(last), "symbol_%08zu", count - 1);
    snprintf(sparse, sizeof(sparse), "symbol_%08zu", count - 10);
    snprintf(qualified, sizeof(qualified), "src/file_%04zu.c::%s", (count - 10) % 128, sparse);
    const char *files[] = {"src/file_0001.c", "src/file_0001.c", "src/file_0002.c"};
    struct scenario {const char *label, *action, *symbol, *match; size_t limit, nf;} cases[] = {
        {"exact_sparse", "query", sparse, "exact", 16, 0},
        {"review_sparse", "review", sparse, "exact", 16, 0},
        {"missing", "query", "absent", "exact", 16, 0},
        {"review_missing", "review", "absent", "exact", 16, 0},
        {"high_degree", "query", last, "exact", 256, 0},
        {"high_degree_context", "context", last, "exact", 16, 0},
        {"broad_prefix", "query", "symbol_", "prefix", 256, 0},
        {"broad_substring", "review", "symbol_", "substring", 1, 0},
        {"qualified", "query", qualified, "qualified", 16, 0},
        {"overlap_files", "review", sparse, "exact", 256, 3},
    };
    for (size_t c = 0; c < sizeof(cases)/sizeof(*cases); c++) {
        struct scenario *s = &cases[c]; requested_match = s->match;
        for (int compact = 0; compact < 2; compact++) {
            output_compact = compact; batch_query = compact;
            for (int k = -1; k < repeats; k++) {
                int rc;
                double begin = monotonic_ms();
                struct json_object *out = query_graph(&st, s->action, s->symbol, files,
                    s->nf, NULL, 3, s->limit, 16000, true, &rc);
                double elapsed = monotonic_ms() - begin;
                if (k < 0) {
                    printf("RESULT\t%s_%d\t%d\t%s\n", s->label, compact, rc,
                        json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
                } else printf("TIME\t%s_%d\t%.9f\n", s->label, compact, elapsed);
                json_object_put(out);
            }
        }
    }
    graph_close(&st);
}
'''

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline-source', type=Path, required=True)
    ap.add_argument('--library-dir', type=Path, required=True)
    ap.add_argument('--nodes', type=int, default=100000)
    ap.add_argument('--repeats', type=int, default=100)
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    libs = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c', 'openssl', 'libzstd'], text=True))
    runs = []
    with tempfile.TemporaryDirectory(prefix='codegraph-query-bench-') as temp:
        temp = Path(temp)
        harness = temp / 'harness.c'; harness.write_text(HARNESS)
        for label, source in [('before', args.baseline_source.resolve()), ('after', root/'tools/qihse_codegraph.c')]:
            binary = temp / label
            subprocess.run(['cc', '-std=c11', '-O2', '-D_GNU_SOURCE', f'-DSOURCE="{source}"',
                *(['-DVERIFY_SCRATCH'] if label == 'after' else []), '-I'+str(root/'include'), '-I'+str(root/'core'), '-I'+str(root/'tools'), str(harness),
                str(root/'tools/qihse_codegraph_storage.c'), '-L'+str(args.library_dir.resolve()),
                '-lqihse', *libs, '-o', str(binary)], check=True)
            env = {**os.environ, 'LD_LIBRARY_PATH': str(args.library_dir.resolve())}
            lines = subprocess.check_output([str(binary), str(args.nodes), str(args.repeats)], env=env, cwd=temp, text=True).splitlines()
            results, times = {}, {}
            for line in lines:
                kind, case, *value = line.split('\t')
                if kind == 'RESULT': results[case] = value
                elif kind == 'TIME': times.setdefault(case, []).append(float(value[0]))
            runs.append((results, times))
        assert runs[0][0] == runs[1][0], 'query outputs changed'
        print(json.dumps({'nodes': args.nodes, 'repeats': args.repeats, 'exact_output_equivalence': True,
            'median_ms': {case: {'before': statistics.median(runs[0][1][case]),
                                 'after': statistics.median(runs[1][1][case])} for case in runs[0][1]}}, indent=2))

if __name__ == '__main__': main()
