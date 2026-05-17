#include "qihse_persist_format.h"

#include <limits.h>

void qihse_le_write_u32(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

void qihse_le_write_u64(uint8_t out[8], uint64_t value) {
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
    out[4] = (uint8_t)((value >> 32) & 0xffu);
    out[5] = (uint8_t)((value >> 40) & 0xffu);
    out[6] = (uint8_t)((value >> 48) & 0xffu);
    out[7] = (uint8_t)((value >> 56) & 0xffu);
}

uint32_t qihse_le_read_u32(const uint8_t in[4]) {
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

uint64_t qihse_le_read_u64(const uint8_t in[8]) {
    return ((uint64_t)in[0]) |
           ((uint64_t)in[1] << 8) |
           ((uint64_t)in[2] << 16) |
           ((uint64_t)in[3] << 24) |
           ((uint64_t)in[4] << 32) |
           ((uint64_t)in[5] << 40) |
           ((uint64_t)in[6] << 48) |
           ((uint64_t)in[7] << 56);
}

uint64_t qihse_fnv1a64_init(void) {
    return QIHSE_PERSIST_FNV1A64_OFFSET;
}

uint64_t qihse_fnv1a64_update(uint64_t hash, const void* data, size_t size) {
    const uint8_t* p = (const uint8_t*)data;
    size_t i;

    if (!p && size != 0) {
        return hash;
    }

    for (i = 0; i < size; i++) {
        hash ^= (uint64_t)p[i];
        hash *= QIHSE_PERSIST_FNV1A64_PRIME;
    }

    return hash;
}

uint64_t qihse_fnv1a64(const void* data, size_t size) {
    return qihse_fnv1a64_update(qihse_fnv1a64_init(), data, size);
}

bool qihse_checked_add_size(size_t a, size_t b, size_t* out) {
    if (!out || a > SIZE_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

bool qihse_checked_mul_size(size_t a, size_t b, size_t* out) {
    if (!out || (a != 0 && b > SIZE_MAX / a)) {
        return false;
    }
    *out = a * b;
    return true;
}

bool qihse_checked_add_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (!out || a > UINT64_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

bool qihse_checked_mul_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (!out || (a != 0 && b > UINT64_MAX / a)) {
        return false;
    }
    *out = a * b;
    return true;
}
