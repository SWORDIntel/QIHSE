/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CT_GROUP_CONFIG_H
#define QIHSE_CT_GROUP_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_cluster_slot.h"

#define QIHSE_CT_LANE_ID_HEX_LEN 64u
#define QIHSE_CT_GENERATION_HEX_LEN 32u
#define QIHSE_CT_GROUP_SLOT_BITMAP_BYTES (QIHSE_CLUSTER_SLOT_COUNT / 8u)

typedef struct {
    char lane_id[QIHSE_CT_LANE_ID_HEX_LEN + 1u];
    char owner_topology_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char successor_topology_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char generation[QIHSE_CT_GENERATION_HEX_LEN + 1u];
    uint8_t slot_bitmap[QIHSE_CT_GROUP_SLOT_BITMAP_BYTES];
} qihse_ct_group_config_t;

/* Parse one repeatable --ct-group tuple:
 * LANE_ID,OWNER_TOPOLOGY_ID,SUCCESSOR_TOPOLOGY_ID,GENERATION,SLOTS
 * SLOTS is one or more inclusive ranges joined with ';', e.g. 0-4095;8192-16383.
 */
bool qihse_ct_group_config_parse(const char* spec,
                                 qihse_ct_group_config_t* out);

/* Group lane IDs/generations must be unique and slot bitmaps disjoint.
 * Empty slot sets are accepted for a joiner lane awaiting its first range. */
bool qihse_ct_group_configs_validate(
    const qihse_ct_group_config_t* groups, size_t count);

#endif
