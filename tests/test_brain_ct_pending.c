/* Durable retry and policy tests. Real pinned-QKP transfer belongs to the
 * daemon integration drill; these tests inject only its typed result. */
#include "../src/spinnaker/qihse_cluster_brain.c"
#include <assert.h>

static unsigned calls;
static qihse_brain_transfer_result_t next_result;
static char last_id[33];
static uint16_t last_first, last_last;
static qihse_brain_transfer_result_t transfer(void* ctx, qihse_user_t* control,
    qihse_user_t* data, const char* id, const char* generation, const char* target,
    uint16_t first, uint16_t last, char* error, size_t cap) {
    (void)ctx; (void)target; assert(strlen(generation) == 32); (void)error; (void)cap;
    assert(control && data && qihse_auth_user_is_active(control));
    calls++; snprintf(last_id, sizeof(last_id), "%s", id);
    last_first = first; last_last = last;
    return next_result;
}
static void init(brain_t* b, const char* dir, qihse_user_t* op) {
    memset(b, 0, sizeof(*b)); b->pending_lock = -1;
    b->topology = qihse_cluster_topology_create(); assert(b->topology);
    qihse_cluster_node_t node = {0}; uint16_t idx;
    qihse_cluster_node_id_from_seed("source", 6, node.id);
    node.healthy = true; node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    snprintf(node.host, sizeof(node.host), "127.0.0.1"); node.port = 7100; node.bus_port = 17100;
    assert(qihse_cluster_topology_upsert_node(b->topology, &node, &idx));
    assert(qihse_cluster_topology_set_local_node(b->topology, idx));
    snprintf(b->journal_dir, sizeof(b->journal_dir), "%s", dir);
    memset(b->transfer_generation, 'a', 32);
    b->control_principal = op; b->data_principal = op; b->transfer = transfer;
    b->pending_ready = brain_pending_open(b); assert(b->pending_ready);
}
static void dispose(brain_t* b) {
    if (b->pending_lock >= 0) close(b->pending_lock);
    qihse_cluster_topology_destroy(b->topology);
}
static void test_populated_policy(qihse_user_t* op) {
    char dir[] = "./brain-ct-policy-XXXXXX"; assert(mkdtemp(dir));
    brain_t* b = calloc(1, sizeof(*b)); assert(b); init(b, dir, op);
    b->act = true; b->rebalance_min_slots = 0; /* --brain-act uses no hidden slot threshold */
    b->journal = qihse_event_stream_create(dir); assert(b->journal);
    assert(!pthread_mutex_init(&b->journal_lock, NULL));
    uint16_t local = qihse_cluster_topology_local_node(b->topology), peer;
    qihse_cluster_node_t node = {0};
    qihse_cluster_node_id_from_seed("target", 6, node.id);
    snprintf(node.host, sizeof(node.host), "127.0.0.1"); node.port = 7101;
    node.bus_port = 17101; node.healthy = true;
    assert(qihse_cluster_topology_upsert_node(b->topology, &node, &peer));
    assert(qihse_cluster_topology_assign_range(b->topology, 0, 11999, local));
    assert(qihse_cluster_topology_assign_range(b->topology, 12000, 16383, peer));
    b->obs.local_index = local; b->obs.node_count = 2; b->obs.run_count = 2;
    brain_obs_run_t runs[] = {{local, 0, 11999}, {peer, 12000, 16383}};
    b->obs.runs = runs;
    for (size_t i = 0; i < 2; i++) {
        qihse_cluster_node_t n; assert(qihse_cluster_topology_get_node(b->topology, (uint16_t)i, &n));
        b->obs.nodes[i].index = (uint16_t)i; b->obs.nodes[i].flags = BRAIN_OBS_F_HEALTHY;
        b->obs.nodes[i].role = QIHSE_CLUSTER_NODE_PRIMARY;
        snprintf(b->obs.nodes[i].id, sizeof(b->obs.nodes[i].id), "%s", n.id);
    }
    /* CT2 acts from the captured topology even if the optional observation
     * federation journal is unavailable. The durable pending tuple and
     * adapter's fence/generation checks remain mandatory. */
    b->precondition.valid = false;
    unsigned before = calls; next_result = QIHSE_BRAIN_TRANSFER_COMMITTED;
    brain_check_rebalance(b, &b->obs);
    assert(calls == before + 1); assert(last_first == 8192 && last_last == 11999);
    assert(!b->pending.active);

    /* The actor follows the largest current owner: after ownership shifts,
     * node 1 can act and transfer toward node 0. There is no permanent node-0
     * coordinator. */
    assert(qihse_cluster_topology_assign_range(b->topology, 0, 4383, local));
    assert(qihse_cluster_topology_assign_range(b->topology, 4384, 16383, peer));
    assert(qihse_cluster_topology_set_local_node(b->topology, peer));
    b->obs.local_index = peer;
    brain_obs_run_t shifted[] = {{local, 0, 4383}, {peer, 4384, 16383}};
    b->obs.runs = shifted;
    before = calls;
    brain_check_rebalance(b, &b->obs);
    assert(calls == before + 1);
    assert(last_first == 12576 && last_last == 16383);
    assert(!strcmp(b->pending.target, b->obs.nodes[0].id));

    /* An actor with no durable CT2 callback cannot fall back to the legacy
     * handoff path, even when its topology says it is the largest owner. */
    b->transfer = NULL;
    before = calls;
    brain_check_rebalance(b, &b->obs);
    assert(calls == before);
    b->transfer = transfer;
    uint64_t cursor = 0; qihse_es_record_header_t h; uint8_t* payload = NULL;
    size_t size = 0; bool saw_outcome = false, saw_policy = false;
    while (qihse_event_stream_iterate(b->journal, "cluster.brain", &cursor, &h, &payload, &size)) {
        char text[2048]; assert(size < sizeof(text)); memcpy(text, payload, size); text[size] = 0;
        saw_outcome |= strstr(text, "CT2_RESULT") != NULL;
        saw_policy |= strstr(text, "REBALANCE") != NULL;
        free(payload); payload = NULL;
    }
    assert(saw_outcome && saw_policy);
    qihse_event_stream_destroy(b->journal); pthread_mutex_destroy(&b->journal_lock);
    dispose(b); free(b);
}
int main(void) {
    char dir[] = "./brain-ct-pending-XXXXXX";
    assert(mkdtemp(dir));
    setenv("QIHSE_AUTH_STATE_DIR", dir, 1);
    setenv("QIHSE_DATA_DIR", dir, 1);
    setenv("QIHSE_AUDIT_DIR", dir, 1);
    assert(qihse_auth_init()); qihse_user_t* op = qihse_auth_get_user(0); assert(op);
    brain_t* b = calloc(1, sizeof(*b)); brain_t* recovered = calloc(1, sizeof(*recovered));
    assert(b && recovered); init(b, dir, op);
    char target[41]; qihse_cluster_node_id_from_seed("target", 6, target);

    next_result = QIHSE_BRAIN_TRANSFER_PENDING;
    assert(brain_transfer_begin(b, 100, 199, target)); assert(calls == 1);
    char id[33]; snprintf(id, sizeof(id), "%s", last_id);
    assert(!brain_transfer_begin(b, 300, 399, target)); assert(calls == 1);
    dispose(b); init(recovered, dir, op);
    assert(recovered->pending.active);
    assert(brain_pending_run(recovered)); assert(calls == 2 && !strcmp(last_id, id));
    assert(last_first == 100 && last_last == 199);

    /* NULL control and data cannot invoke the adapter, including recovered work. */
    recovered->control_principal = NULL;
    assert(brain_pending_run(recovered)); assert(calls == 2);
    recovered->control_principal = op; recovered->data_principal = NULL;
    assert(brain_pending_run(recovered)); assert(calls == 2);
    recovered->data_principal = op;
    qihse_user_t* low = qihse_auth_create_user(op, 901, QIHSE_ROLE_GUEST,
        0, 0, "brain-test-password-901", false); assert(low);
    recovered->control_principal = low;
    assert(brain_pending_run(recovered)); assert(calls == 2);
    recovered->control_principal = op;

    /* Only the special, proven-abort size result allows a fresh ID/subdivision. */
    next_result = QIHSE_BRAIN_TRANSFER_REJECTED;
    assert(brain_pending_run(recovered)); assert(!strcmp(last_id, id));
    next_result = QIHSE_BRAIN_TRANSFER_TOO_LARGE;
    assert(brain_pending_run(recovered)); assert(recovered->pending.last == 149);
    assert(strcmp(recovered->pending.id, id));
    next_result = QIHSE_BRAIN_TRANSFER_COMMITTED;
    assert(brain_pending_run(recovered)); assert(!recovered->pending.active);
    dispose(recovered); init(b, dir, op); assert(!b->pending.active);
    dispose(b);

    /* A source-generation change cannot replay an old pending ID. */
    init(b, dir, op); next_result = QIHSE_BRAIN_TRANSFER_PENDING;
    assert(brain_transfer_begin(b, 30, 30, target)); dispose(b);
    memset(recovered, 0, sizeof(*recovered)); recovered->pending_lock = -1;
    snprintf(recovered->journal_dir, sizeof(recovered->journal_dir), "%s", dir);
    memset(recovered->transfer_generation, 'b', 32);
    assert(brain_pending_open(recovered));
    recovered->control_principal = recovered->data_principal = op; recovered->transfer = transfer;
    recovered->pending_ready = true; unsigned previous = calls;
    assert(brain_pending_run(recovered)); assert(calls == previous);
    close(recovered->pending_lock);

    /* A valid-looking bit flip cannot change the pending operation. */
    char corrupt_path[640]; snprintf(corrupt_path, sizeof(corrupt_path), "%s/ct2-pending", dir);
    FILE* corrupt = fopen(corrupt_path, "r+"); assert(corrupt);
    assert(!fseek(corrupt, 7, SEEK_SET)); int byte = fgetc(corrupt); assert(byte != EOF);
    assert(!fseek(corrupt, 7, SEEK_SET)); assert(fputc(byte == '3' ? '4' : '3', corrupt) != EOF);
    assert(!fclose(corrupt)); recovered->pending_lock = -1;
    assert(!brain_pending_open(recovered)); close(recovered->pending_lock);

    /* Symlinked tuple is refused without reading its destination. */
    char path[640]; snprintf(path, sizeof(path), "%s/ct2-pending", dir);
    assert(!unlink(path)); assert(!symlink("not-a-record", path));
    recovered->pending_lock = -1; assert(!brain_pending_open(recovered));
    if (recovered->pending_lock >= 0) close(recovered->pending_lock);
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/ct2-pending.lock", dir); assert(!unlink(path));
    test_populated_policy(op);
    free(b); free(recovered);
    puts("PASS durable CT2 retry identity, auth refusal, proven-abort subdivision, generation binding and symlink refusal");
    return 0;
}
