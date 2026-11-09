#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_csr.h"
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PASSWORD "CodeGraphCsrFixture1!"
#define FANOUT 320u

typedef struct {
    const cg_csr *graph;
    bool valid;
} reader_task;

static void *read_graph(void *opaque) {
    reader_task *task = opaque;
    task->valid = true;
    for (unsigned repeat = 0; repeat < 100; ++repeat) {
        size_t count = 0;
        const uint32_t *out = cg_csr_incident(task->graph, 1, false, &count);
        if (!out || count != FANOUT + 1 || cg_csr_edge_count(task->graph) != FANOUT + 2)
            { task->valid = false; break; }
        for (uint32_t i = 0; i < FANOUT; ++i) {
            const cg_csr_edge *edge = cg_csr_get_edge(task->graph, out[i]);
            if (!edge || out[i] != i || edge->source != 1 || edge->target != 2 ||
                edge->line != INT64_C(4294967296) + i || strcmp(edge->type, "CALLS"))
                { task->valid = false; break; }
        }
        if (!task->valid) break;
    }
    return NULL;
}

static int clean_test(const char *path, const struct stat *info, int type,
                      struct FTW *walk) {
    (void)info; (void)type; (void)walk;
    return remove(path);
}

int main(void) {
    char root[PATH_MAX];
    const char *temporary = getenv("TMPDIR");
    assert(snprintf(root, sizeof(root), "%s/qihse-csr-test-XXXXXX",
                    temporary && *temporary ? temporary : ".") < (int)sizeof(root));
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD);
    assert(op);
    assert(qihse_auth_create_user(op, 713, QIHSE_ROLE_GUEST, 0, 0, PASSWORD, false));
    qihse_user_t *low = qihse_auth_authenticate_id(713, PASSWORD);
    assert(low);

    errno = 0;
    assert(!cg_csr_create(NULL, 2, 1) && errno == EACCES);
    errno = 0;
    assert(!cg_csr_create(op, SIZE_MAX, 1) && errno == EOVERFLOW);
    cg_csr *graph = cg_csr_create(op, 3, FANOUT + 2);
    assert(graph);
    const char *first_file = cg_csr_intern(graph, "src/caller.c");
    assert(first_file && first_file == cg_csr_intern(graph, "src/caller.c"));
    assert(!cg_csr_add_edge(graph, 0, 2, "CALLS", first_file, 1, 1.0));
    assert(!cg_csr_add_edge(graph, 1, 4, "CALLS", first_file, 1, 1.0));
    assert(!cg_csr_add_edge(graph, 1, 2, "CALLS", first_file, 1, NAN));
    assert(!cg_csr_finish(graph)); /* Incomplete projection cannot be exposed. */
    for (uint32_t i = 0; i < FANOUT; ++i)
        assert(cg_csr_add_edge(graph, 1, 2, "CALLS", first_file,
                               INT64_C(4294967296) + i, 0.75));
    assert(cg_csr_add_edge(graph, 1, 1, "REFERENCES", first_file, INT64_MAX, 1.0));
    assert(cg_csr_add_edge(graph, 2, 3, "TESTED_BY", "tests/caller.c", 7, 1.0));
    assert(cg_csr_finish(graph));
    assert(!cg_csr_intern(graph, "later"));
    assert(!cg_csr_add_edge(graph, 1, 2, "CALLS", first_file, 9, 1.0));
    assert(cg_csr_bytes(graph) > 0);

    size_t count = SIZE_MAX;
    const uint32_t *out = cg_csr_incident(graph, 1, false, &count);
    assert(out && count == FANOUT + 1);
    assert(out[FANOUT] == FANOUT);
    const cg_csr_edge *self = cg_csr_get_edge(graph, out[FANOUT]);
    assert(self && self->source == 1 && self->target == 1 && self->line == INT64_MAX);
    const uint32_t *in = cg_csr_incident(graph, 1, true, &count);
    assert(in && count == 1 && in[0] == FANOUT); /* Raw CSR includes self-loop. */
    in = cg_csr_incident(graph, 2, true, &count);
    assert(in && count == FANOUT);
    for (uint32_t i = 0; i < FANOUT; ++i) assert(in[i] == i);
    assert(!cg_csr_incident(graph, 0, false, &count) && count == 0);
    assert(!cg_csr_get_edge(graph, FANOUT + 2));

    pthread_t threads[4];
    reader_task tasks[4];
    for (size_t i = 0; i < 4; ++i) {
        tasks[i] = (reader_task){.graph = graph};
        assert(pthread_create(&threads[i], NULL, read_graph, &tasks[i]) == 0);
    }
    for (size_t i = 0; i < 4; ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
        assert(tasks[i].valid);
    }

    /* The KV boundary must deny low clearance before the projection is built. */
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    assert(qihse_kv_set_user(store, "n:protected", "CLASSIFIED-PAYLOAD", 4, 2, op));
    assert(qihse_kv_get_user(store, "n:protected", low) == NULL);
    char *secret = qihse_kv_get_user(store, "n:protected", op);
    assert(secret && strcmp(secret, "CLASSIFIED-PAYLOAD") == 0);
    free(secret);
    qihse_kv_store_destroy(store);

    cg_csr *guest_graph = cg_csr_create(low, 2, 1);
    assert(guest_graph);
    assert(cg_csr_add_edge(guest_graph, 1, 2, "CALLS", "public.c", 4, 1.0));
    assert(cg_csr_finish(guest_graph));
    assert(cg_csr_get_edge(guest_graph, 0));
    assert(qihse_auth_destroy_user(op, 713));
    errno = 0;
    assert(!cg_csr_incident(guest_graph, 1, false, &count) && count == 0 && errno == EACCES);
    errno = 0;
    assert(!cg_csr_get_edge(guest_graph, 0) && errno == EACCES);
    errno = 0;
    assert(cg_csr_edge_count(guest_graph) == 0 && errno == EACCES);
    errno = 0;
    assert(cg_csr_bytes(guest_graph) == 0 && errno == EACCES);
    errno = 0;
    assert(!cg_csr_create(low, 2, 1) && errno == EACCES);
    cg_csr_destroy(guest_graph);
    cg_csr_destroy(graph);
    qihse_audit_shutdown();
    assert(nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CodeGraph CSR authenticated projection: PASS");
    return 0;
}
