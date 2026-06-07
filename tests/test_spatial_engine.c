#include "qihse_spatial.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>

#define QIHSE_CLASS_UNCLASSIFIED 0
#define QIHSE_CLASS_RESTRICTED 1
#define QIHSE_CLASS_CONFIDENTIAL 2
#define QIHSE_CLASS_SECRET 3
#define QIHSE_CLASS_TOP_SECRET 4

#define QIHSE_SCI_NONE 0x0000
#define QIHSE_SCI_SI   0x0001
#define QIHSE_SCI_TK   0x0002
#define QIHSE_SCI_HCS  0x0004
#define QIHSE_SCI_G    0x0008

extern bool qihse_spatial_insert_secure(qihse_spatial_index_t idx, uint64_t row_id, double lat, double lon, uint16_t classif, uint16_t sci);

int main() {
    printf("Testing Geospatial Engine (GEOINT / Morton Z-order)...\n");

    qihse_spatial_index_t idx = qihse_spatial_create();
    assert(idx != NULL);

    // 1. Basic insertion
    qihse_spatial_insert_secure(idx, 101, 38.8977, -77.0365, QIHSE_CLASS_UNCLASSIFIED, QIHSE_SCI_NONE); // DC (White House)
    qihse_spatial_insert_secure(idx, 102, 38.8719, -77.0563, QIHSE_CLASS_SECRET, QIHSE_SCI_NONE);       // Pentagon
    qihse_spatial_insert_secure(idx, 103, 39.1085, -76.7725, QIHSE_CLASS_TOP_SECRET, QIHSE_SCI_SI);     // Fort Meade (NSA)
    qihse_spatial_insert_secure(idx, 104, 38.9531, -77.1463, QIHSE_CLASS_TOP_SECRET, QIHSE_SCI_TK);     // CIA Langley

    // 2. Destructive / Redteam Testing
    // What if we insert NaNs or Infinities?
    qihse_spatial_insert_secure(idx, 999, NAN, INFINITY, QIHSE_CLASS_UNCLASSIFIED, QIHSE_SCI_NONE);
    qihse_spatial_insert_secure(idx, 998, -999.0, 999.0, QIHSE_CLASS_SECRET, QIHSE_SCI_G);

    // 3. Querying
    qihse_geo_bbox_t bbox_dc = {
        .min_lat = 38.0, .max_lat = 40.0,
        .min_lon = -78.0, .max_lon = -76.0
    };

    uint64_t results[100];
    size_t num_results = 0;

    qihse_auth_init();
    
    // Create Users
    qihse_user_t* u_unclass = qihse_auth_create_user(1, QIHSE_ROLE_ANALYST, QIHSE_CLASS_UNCLASSIFIED, QIHSE_SCI_NONE);
    qihse_user_t* u_secret  = qihse_auth_create_user(2, QIHSE_ROLE_ANALYST, QIHSE_CLASS_SECRET, QIHSE_SCI_NONE);
    qihse_user_t* u_ts_si   = qihse_auth_create_user(3, QIHSE_ROLE_ANALYST, QIHSE_CLASS_TOP_SECRET, QIHSE_SCI_SI);
    qihse_user_t* u_operator = qihse_auth_create_user(4, QIHSE_ROLE_OPERATOR, 0, 0);

    // Test query as UNCLASSIFIED User
    qihse_spatial_query_bbox_user(idx, bbox_dc, u_unclass, results, 100, &num_results);
    assert(num_results == 1);
    assert(results[0] == 101);

    // Test query as SECRET User
    qihse_spatial_query_bbox_user(idx, bbox_dc, u_secret, results, 100, &num_results);
    // Should see White House (UNCLASS) and Pentagon (SECRET) but not NSA/CIA (TS)
    assert(num_results == 2);

    // Test query as TOP SECRET User with SI
    qihse_spatial_query_bbox_user(idx, bbox_dc, u_ts_si, results, 100, &num_results);
    // Should see White House, Pentagon, Fort Meade. NOT CIA (needs TK)
    assert(num_results == 3);
    
    // Test query as OPERATOR (Full Access / God Mode)
    qihse_spatial_query_bbox_user(idx, bbox_dc, u_operator, results, 100, &num_results);
    // Should see all 4 valid DC locations, plus maybe the out-of-bounds ones if they clamped into the box!
    // Actually, NaNs and Infinities clamp to 0 or 1 in normalization. Let's see if it crashes.

    qihse_spatial_destroy(idx);

    printf("ALL PASS: Spatial Engine\n");
    return 0;
}
