/* test_ownership_journal.c — append/replay/corruption tests for the durable
 * slot-ownership journal (COPY → PERSIST → SWITCH → GC). */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_cluster_ownership_journal.h"

typedef struct {
    int count;
    uint16_t last_start, last_end;
    char last_owner[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint64_t last_epoch;
} replay_ctx_t;

static void on_entry(const qihse_cluster_ownership_entry_t* e, void* ctx) {
    replay_ctx_t* r = (replay_ctx_t*)ctx;
    r->count++;
    r->last_start = e->start;
    r->last_end = e->end;
    strncpy(r->last_owner, e->owner_id, QIHSE_CLUSTER_NODE_ID_LEN);
    r->last_owner[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    r->last_epoch = e->config_epoch;
}

int main(void) {
    char dir[] = "/tmp/qihse_journal_XXXXXX";
    assert(mkdtemp(dir));

    /* append 3 entries */
    assert(qihse_cluster_ownership_journal_append(dir, 100, 199, "node-a", 5) == 0);
    assert(qihse_cluster_ownership_journal_append(dir, 200, 299, "node-b", 6) == 0);
    assert(qihse_cluster_ownership_journal_append(dir, 300, 399, "node-c", 4) == 0);

    /* replay: 3 entries, front-to-back, content preserved (incl. a lower epoch) */
    replay_ctx_t r;
    memset(&r, 0, sizeof(r));
    int n = qihse_cluster_ownership_journal_replay(dir, on_entry, &r);
    assert(n == 3);
    assert(r.count == 3);
    assert(r.last_start == 300 && r.last_end == 399);
    assert(strcmp(r.last_owner, "node-c") == 0);
    assert(r.last_epoch == 4);
    printf("[PASS] journal append + replay (3 entries, order + content)\n");

    /* corrupt the tail byte of the LAST record — replay must skip it, keep the 3 valid */
    char path[1024];
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir);
    FILE* f = fopen(path, "r+b");
    assert(f);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, sz - 1, SEEK_SET);
    fputc(0xFF, f);
    fclose(f);

    memset(&r, 0, sizeof(r));
    n = qihse_cluster_ownership_journal_replay(dir, on_entry, &r);
    assert(n == 2);
    assert(r.last_start == 200 && r.last_end == 299); /* the corrupt 3rd record is skipped */
    printf("[PASS] corrupt tail record skipped, earlier entries preserved\n");

    /* no journal → 0 (not an error) */
    char dir2[] = "/tmp/qihse_journal_empty_XXXXXX";
    assert(mkdtemp(dir2));
    memset(&r, 0, sizeof(r));
    n = qihse_cluster_ownership_journal_replay(dir2, on_entry, &r);
    assert(n == 0);
    printf("[PASS] absent journal replays as empty\n");

    printf("All ownership journal tests passed.\n");
    return 0;
}
