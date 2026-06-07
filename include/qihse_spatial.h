#ifndef QIHSE_SPATIAL_H
#define QIHSE_SPATIAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Represents a 2D geographic point
typedef struct {
    double latitude;
    double longitude;
} qihse_geo_point_t;

// Encodes a lat/lon pair into a 64-bit Z-order Morton code
// Precision is roughly ~1cm at the equator using 64 bits (32 bits per dimension)
uint64_t qihse_spatial_encode_zorder(double lat, double lon);

// Decodes a 64-bit Z-order Morton code back into a lat/lon pair
void qihse_spatial_decode_zorder(uint64_t z, double* lat, double* lon);

// Bounding box for spatial queries
typedef struct {
    double min_lat;
    double max_lat;
    double min_lon;
    double max_lon;
} qihse_geo_bbox_t;

// A spatial index structure for GEOINT
typedef struct qihse_spatial_index_s* qihse_spatial_index_t;

qihse_spatial_index_t qihse_spatial_create(void);
void qihse_spatial_destroy(qihse_spatial_index_t idx);

// Insert a row ID with its geographic point into the spatial index
bool qihse_spatial_insert(qihse_spatial_index_t idx, uint64_t row_id, double lat, double lon);

// Query row IDs within a bounding box, enforcing clearance level checks
// Requires the searcher's clearance level and SCI compartment masks.
#include "qihse_auth.h"

bool qihse_spatial_query_bbox_user(
    qihse_spatial_index_t idx, 
    qihse_geo_bbox_t bbox, 
    qihse_user_t* user, 
    uint64_t* out_row_ids, 
    size_t max_results, 
    size_t* num_results
);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_SPATIAL_H
