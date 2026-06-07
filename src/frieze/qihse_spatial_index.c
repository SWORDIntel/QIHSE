#include "qihse_spatial.h"
#include <stdlib.h>
#include <string.h>

// Helper to interleave bits for Morton code (Z-order)
static uint64_t split_by_1(uint32_t a) {
    uint64_t x = a & 0x00000000FFFFFFFFull;
    x = (x | (x << 16)) & 0x0000FFFF0000FFFFull;
    x = (x | (x << 8))  & 0x00FF00FF00FF00FFull;
    x = (x | (x << 4))  & 0x0F0F0F0F0F0F0F0Full;
    x = (x | (x << 2))  & 0x3333333333333333ull;
    x = (x | (x << 1))  & 0x5555555555555555ull;
    return x;
}

static uint32_t compact_by_1(uint64_t x) {
    x &= 0x5555555555555555ull;
    x = (x ^ (x >> 1))  & 0x3333333333333333ull;
    x = (x ^ (x >> 2))  & 0x0F0F0F0F0F0F0F0Full;
    x = (x ^ (x >> 4))  & 0x00FF00FF00FF00FFull;
    x = (x ^ (x >> 8))  & 0x0000FFFF0000FFFFull;
    x = (x ^ (x >> 16)) & 0x00000000FFFFFFFFull;
    return (uint32_t)x;
}

uint64_t qihse_spatial_encode_zorder(double lat, double lon) {
    // Normalize to [0, 1] mapped to 32-bit unsigned
    double nlat = (lat + 90.0) / 180.0;
    double nlon = (lon + 180.0) / 360.0;
    
    // Clamp to [0, 1]
    if (nlat < 0.0) nlat = 0.0;
    if (nlat > 1.0) nlat = 1.0;
    if (nlon < 0.0) nlon = 0.0;
    if (nlon > 1.0) nlon = 1.0;

    uint32_t x = (uint32_t)(nlon * 0xFFFFFFFFull);
    uint32_t y = (uint32_t)(nlat * 0xFFFFFFFFull);

    return split_by_1(x) | (split_by_1(y) << 1);
}

void qihse_spatial_decode_zorder(uint64_t z, double* lat, double* lon) {
    uint32_t x = compact_by_1(z);
    uint32_t y = compact_by_1(z >> 1);

    double nlon = (double)x / 0xFFFFFFFFull;
    double nlat = (double)y / 0xFFFFFFFFull;

    *lon = (nlon * 360.0) - 180.0;
    *lat = (nlat * 180.0) - 90.0;
}

// B-tree or simple sorted array for the Z-order index
typedef struct {
    uint64_t z_code;
    uint64_t row_id;
    uint16_t classification;
    uint16_t sci_compartment;
    double lat;
    double lon;
} spatial_entry_t;

struct qihse_spatial_index_s {
    spatial_entry_t* entries;
    size_t count;
    size_t capacity;
};

qihse_spatial_index_t qihse_spatial_create(void) {
    struct qihse_spatial_index_s* idx = calloc(1, sizeof(*idx));
    if (!idx) return NULL;
    idx->capacity = 1024;
    idx->entries = malloc(idx->capacity * sizeof(spatial_entry_t));
    if (!idx->entries) {
        free(idx);
        return NULL;
    }
    return idx;
}

void qihse_spatial_destroy(qihse_spatial_index_t idx) {
    if (!idx) return;
    free(idx->entries);
    free(idx);
}

// Simple insertion sort for now
bool qihse_spatial_insert_secure(qihse_spatial_index_t idx, uint64_t row_id, double lat, double lon, uint16_t classif, uint16_t sci) {
    if (!idx) return false;
    if (idx->count >= idx->capacity) {
        size_t new_cap = idx->capacity * 2;
        spatial_entry_t* new_entries = realloc(idx->entries, new_cap * sizeof(spatial_entry_t));
        if (!new_entries) return false;
        idx->entries = new_entries;
        idx->capacity = new_cap;
    }

    uint64_t z = qihse_spatial_encode_zorder(lat, lon);
    
    // Find position to insert (maintain sorted Z-order)
    size_t i = idx->count;
    while (i > 0 && idx->entries[i-1].z_code > z) {
        idx->entries[i] = idx->entries[i-1];
        i--;
    }
    idx->entries[i].z_code = z;
    idx->entries[i].row_id = row_id;
    idx->entries[i].lat = lat;
    idx->entries[i].lon = lon;
    idx->entries[i].classification = classif;
    idx->entries[i].sci_compartment = sci;
    idx->count++;

    return true;
}

bool qihse_spatial_insert(qihse_spatial_index_t idx, uint64_t row_id, double lat, double lon) {
    // Default to UNCLASS if using the generic insertion wrapper
    return qihse_spatial_insert_secure(idx, row_id, lat, lon, 0, 0); // 0 = UNCLASSIFIED, 0 = SCI_NONE
}

#include "qihse_auth.h"

bool qihse_spatial_query_bbox_user(
    qihse_spatial_index_t idx, 
    qihse_geo_bbox_t bbox, 
    qihse_user_t* user, 
    uint64_t* out_row_ids, 
    size_t max_results, 
    size_t* num_results
) {
    if (!idx || !user || !out_row_ids || !num_results) return false;
    
    *num_results = 0;

    for (size_t i = 0; i < idx->count; i++) {
        spatial_entry_t* e = &idx->entries[i];
        
        // GEO filtering
        if (e->lat >= bbox.min_lat && e->lat <= bbox.max_lat &&
            e->lon >= bbox.min_lon && e->lon <= bbox.max_lon) {
            
            // SECURITY filtering
            if (qihse_auth_can_access(user, e->classification, e->sci_compartment)) {
                out_row_ids[*num_results] = e->row_id;
                (*num_results)++;
                if (*num_results >= max_results) {
                    break;
                }
            }
        }
    }
    
    return true;
}
