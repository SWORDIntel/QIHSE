/* Fixed-width group-claim framing: real QKP tokens and exact buffer bounds. */
#include "qihse_cluster_transfer.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    qihse_kv_ct_lane_authority_claim_t claim = {0}, decoded = {0};
    claim.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    strcpy(claim.transfer_id, "transfer:0_1");
    memset(claim.source_group_id, 'a', 64u);
    memset(claim.target_group_id, 'b', 64u);
    strcpy(claim.source_qkp_id, "ct3-node-a");
    strcpy(claim.target_qkp_id, "ct3-node-c");
    strcpy(claim.successor_qkp_id, "ct3-node-b");
    memset(claim.source_generation, 'c', 32u);
    memset(claim.target_generation, 'd', 32u);
    claim.slots[123u / 8u] = (uint8_t)(1u << (123u % 8u));
    claim.grant_epoch = 1u;
    claim.reserve_index = 2u;
    memset(claim.reserve_digest, 0x34, 32u);
    claim.target_cursor = 7u;
    struct {
        unsigned char before[16];
        unsigned char wire[QIHSE_CT_GROUP_CLAIM_WIRE_BYTES];
        unsigned char after[16];
    } guarded;
    memset(&guarded, 0xa5, sizeof(guarded));
    assert(QIHSE_CT_GROUP_CLAIM_WIRE_BYTES == 2801u);
    assert(qihse_cluster_transfer_claim_encode(&claim, guarded.wire));
    for (size_t i = 0; i < 16u; ++i)
        assert(guarded.before[i] == 0xa5 && guarded.after[i] == 0xa5);
    assert(qihse_cluster_transfer_claim_decode(guarded.wire,
        sizeof(guarded.wire), &decoded));
    assert(!strcmp(decoded.source_qkp_id, claim.source_qkp_id));
    assert(!strcmp(decoded.target_qkp_id, claim.target_qkp_id));
    assert(!strcmp(decoded.successor_qkp_id, claim.successor_qkp_id));
    assert(decoded.source_cut == 0u && decoded.target_cursor == 7u);
    assert(!memcmp(decoded.slots, claim.slots, sizeof(claim.slots)));
    unsigned char second[QIHSE_CT_GROUP_CLAIM_WIRE_BYTES];
    assert(qihse_cluster_transfer_claim_encode(&decoded, second));
    assert(!memcmp(second, guarded.wire, sizeof(second)));
    assert(!qihse_cluster_transfer_claim_decode(guarded.wire,
        sizeof(guarded.wire) - 1u, &decoded));
    /* The canonical text fields reject control bytes and nonzero padding. */
    guarded.wire[9u + strlen(claim.transfer_id) + 1u] = 1u;
    assert(!qihse_cluster_transfer_claim_decode(guarded.wire,
        sizeof(guarded.wire), &decoded));
    claim.source_qkp_id[0] = '\n';
    assert(!qihse_cluster_transfer_claim_encode(&claim, guarded.wire));
    strcpy(claim.source_qkp_id, "ct3-node-a");
    claim.source_group_id[0] = 'z';
    assert(!qihse_cluster_transfer_claim_encode(&claim, guarded.wire));
    claim.source_group_id[0] = 'a';
    claim.source_generation[0] = 'z';
    assert(!qihse_cluster_transfer_claim_encode(&claim, guarded.wire));
    puts("CT group claim canonical framing and buffer bounds passed");
    return 0;
}
