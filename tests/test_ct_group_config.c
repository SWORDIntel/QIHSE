#include "qihse_ct_group_config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void make_spec(char* out, size_t cap, char lane_digit,
                      char owner_digit, char successor_digit,
                      char generation_digit, const char* slots) {
    assert(cap >= 181u + strlen(slots));
    memset(out, lane_digit, 64u); out[64] = ',';
    memset(out + 65u, owner_digit, 40u); out[105] = ',';
    memset(out + 106u, successor_digit, 40u); out[146] = ',';
    memset(out + 147u, generation_digit, 32u); out[179] = ',';
    snprintf(out + 180u, cap - 180u, "%s", slots);
}

static bool bit(const qihse_ct_group_config_t* g, unsigned slot) {
    return (g->slot_bitmap[slot >> 3u] & (uint8_t)(1u << (slot & 7u))) != 0u;
}

int main(void) {
    char spec[512];
    make_spec(spec, sizeof(spec), 'a', '1', '2', 'b', "0-3;7;16383");
    qihse_ct_group_config_t a, b;
    assert(qihse_ct_group_config_parse(spec, &a));
    assert(bit(&a, 0) && bit(&a, 3) && bit(&a, 7) && bit(&a, 16383));
    assert(!bit(&a, 4) && !bit(&a, 16382));

    make_spec(spec, sizeof(spec), 'c', '2', '3', 'd', "4-6;8-9");
    assert(qihse_ct_group_config_parse(spec, &b));
    qihse_ct_group_config_t groups[] = {a, b};
    assert(qihse_ct_group_configs_validate(groups, 2u));

    make_spec(spec, sizeof(spec), 'c', '2', '3', 'd', "-");
    assert(qihse_ct_group_config_parse(spec, &b));
    groups[1] = b;
    assert(qihse_ct_group_configs_validate(groups, 2u));

    make_spec(spec, sizeof(spec), 'e', '3', '4', 'f', "3-5");
    assert(qihse_ct_group_config_parse(spec, &groups[1]));
    assert(!qihse_ct_group_configs_validate(groups, 2u));
    make_spec(spec, sizeof(spec), 'c', '2', '3', 'd', "4-6;8-9");
    assert(qihse_ct_group_config_parse(spec, &b));
    groups[1] = b;
    memcpy(groups[1].lane_id, groups[0].lane_id, sizeof(groups[1].lane_id));
    assert(!qihse_ct_group_configs_validate(groups, 2u));

    const char* bad_slots[] = {"", "1;", ";1", "2-1", "16384", "1-2;2-3", "1,,2"};
    for (size_t i = 0; i < sizeof(bad_slots) / sizeof(bad_slots[0]); ++i) {
        make_spec(spec, sizeof(spec), 'a', '1', '2', 'b', bad_slots[i]);
        assert(!qihse_ct_group_config_parse(spec, &a));
    }
    assert(!qihse_ct_group_config_parse("short", &a));
    puts("CT group tuple parsing and exact slot validation passed");
    return 0;
}
