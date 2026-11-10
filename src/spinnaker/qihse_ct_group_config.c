/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#include "qihse_ct_group_config.h"

#include <string.h>

static bool copy_field(const char** cursor, char delimiter, char* out,
                       size_t out_cap, size_t expected_len) {
    const char* start = *cursor;
    const char* end = strchr(start, delimiter);
    if (!end) return false;
    size_t n = (size_t)(end - start);
    if (!n || n >= out_cap || (expected_len && n != expected_len)) return false;
    memcpy(out, start, n);
    out[n] = '\0';
    *cursor = end + 1;
    return true;
}

static bool lowercase_hex(const char* s, size_t n) {
    if (strlen(s) != n) return false;
    for (size_t i = 0; i < n; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static bool parse_slot(const char* text, size_t n, uint32_t* value) {
    if (!text || !n || !value) return false;
    uint32_t result = 0u;
    for (size_t i = 0; i < n; ++i) {
        if (text[i] < '0' || text[i] > '9') return false;
        unsigned digit = (unsigned)(text[i] - '0');
        if (result > (UINT32_MAX - digit) / 10u) return false;
        result = result * 10u + digit;
    }
    if (result >= QIHSE_CLUSTER_SLOT_COUNT) return false;
    *value = result;
    return true;
}

static bool add_slot_range(qihse_ct_group_config_t* out,
                           const char* text, size_t n) {
    const char* dash = memchr(text, '-', n);
    uint32_t first = 0u, last = 0u;
    if (!dash) {
        if (!parse_slot(text, n, &first)) return false;
        last = first;
    } else {
        size_t left = (size_t)(dash - text);
        size_t right = n - left - 1u;
        if (!parse_slot(text, left, &first) ||
            !parse_slot(dash + 1, right, &last) || first > last) return false;
    }
    for (uint32_t slot = first; slot <= last; ++slot) {
        uint8_t mask = (uint8_t)(1u << (slot & 7u));
        uint8_t* byte = &out->slot_bitmap[slot >> 3u];
        if ((*byte & mask) != 0u) return false;
        *byte |= mask;
    }
    return true;
}

bool qihse_ct_group_config_parse(const char* spec,
                                 qihse_ct_group_config_t* out) {
    if (!spec || !*spec || !out) return false;
    memset(out, 0, sizeof(*out));
    const char* p = spec;
    if (!copy_field(&p, ',', out->lane_id, sizeof(out->lane_id),
                    QIHSE_CT_LANE_ID_HEX_LEN) ||
        !copy_field(&p, ',', out->owner_topology_id,
                    sizeof(out->owner_topology_id), QIHSE_CLUSTER_NODE_ID_LEN) ||
        !copy_field(&p, ',', out->successor_topology_id,
                    sizeof(out->successor_topology_id), QIHSE_CLUSTER_NODE_ID_LEN) ||
        !copy_field(&p, ',', out->generation, sizeof(out->generation),
                    QIHSE_CT_GENERATION_HEX_LEN)) return false;
    if (!lowercase_hex(out->lane_id, QIHSE_CT_LANE_ID_HEX_LEN) ||
        !lowercase_hex(out->owner_topology_id, QIHSE_CLUSTER_NODE_ID_LEN) ||
        !lowercase_hex(out->successor_topology_id, QIHSE_CLUSTER_NODE_ID_LEN) ||
        !lowercase_hex(out->generation, QIHSE_CT_GENERATION_HEX_LEN) ||
        strcmp(out->owner_topology_id, out->successor_topology_id) == 0)
        return false;

    if (strcmp(p, "-") == 0) return true;
    const char* range = p;
    bool any = false;
    for (const char* q = p;; ++q) {
        if (*q != ';' && *q != '\0') continue;
        if (!add_slot_range(out, range, (size_t)(q - range))) return false;
        any = true;
        if (*q == '\0') break;
        range = q + 1;
    }
    return any;
}

bool qihse_ct_group_configs_validate(
    const qihse_ct_group_config_t* groups, size_t count) {
    if (!groups || !count) return false;
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < i; ++j) {
            if (strcmp(groups[i].lane_id, groups[j].lane_id) == 0 ||
                strcmp(groups[i].generation, groups[j].generation) == 0)
                return false;
            for (size_t b = 0; b < QIHSE_CT_GROUP_SLOT_BITMAP_BYTES; ++b)
                if ((groups[i].slot_bitmap[b] & groups[j].slot_bitmap[b]) != 0u)
                    return false;
        }
    }
    return true;
}
