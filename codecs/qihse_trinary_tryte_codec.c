#include "qihse_trinary_tryte_codec.h"

#include <errno.h>
#include <limits.h>

static bool qihse_tryte_checked_add_size(size_t a, size_t b, size_t* out) {
    if (!out) {
        errno = EINVAL;
        return false;
    }
    if (a > SIZE_MAX - b) {
        errno = EOVERFLOW;
        return false;
    }
    *out = a + b;
    return true;
}

static bool qihse_tryte_checked_mul_size(size_t a, size_t b, size_t* out) {
    if (!out) {
        errno = EINVAL;
        return false;
    }
    if (a != 0u && b > SIZE_MAX / a) {
        errno = EOVERFLOW;
        return false;
    }
    *out = a * b;
    return true;
}

static int8_t qihse_tryte_signed_trit(uint8_t trit) {
    if (trit == 0u) {
        return -1;
    }
    if (trit == 2u) {
        return 1;
    }
    return 0;
}

bool qihse_trinary_tryte_row_bytes(size_t dims, size_t* out_row_bytes) {
    size_t padded;

    if (!qihse_tryte_checked_add_size(dims,
                                      QIHSE_TRINARY_TRITS_PER_TRYTE - 1u,
                                      &padded)) {
        return false;
    }
    *out_row_bytes = padded / QIHSE_TRINARY_TRITS_PER_TRYTE;
    return true;
}

bool qihse_trinary_tryte_payload_bytes(size_t rows,
                                       size_t dims,
                                       size_t* out_payload_bytes) {
    size_t row_bytes;

    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes)) {
        return false;
    }
    return qihse_tryte_checked_mul_size(rows, row_bytes, out_payload_bytes);
}

uint8_t qihse_trinary_tryte_trit_from_float(float value) {
    if (value < 0.0f) {
        return 0u;
    }
    if (value > 0.0f) {
        return 2u;
    }
    return 1u;
}

bool qihse_trinary_tryte_pack5(const uint8_t trits[QIHSE_TRINARY_TRITS_PER_TRYTE],
                               uint8_t* out_tryte) {
    uint8_t place = 1u;
    uint8_t value = 0u;
    size_t i;

    if (!trits || !out_tryte) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < QIHSE_TRINARY_TRITS_PER_TRYTE; i++) {
        if (trits[i] > 2u) {
            errno = EINVAL;
            return false;
        }
        value = (uint8_t)(value + (uint8_t)(trits[i] * place));
        place = (uint8_t)(place * 3u);
    }
    *out_tryte = value;
    return true;
}

bool qihse_trinary_tryte_unpack(uint8_t tryte,
                                uint8_t out_trits[QIHSE_TRINARY_TRITS_PER_TRYTE]) {
    size_t i;

    if (!out_trits || tryte > QIHSE_TRINARY_TRYTE_MAX) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < QIHSE_TRINARY_TRITS_PER_TRYTE; i++) {
        out_trits[i] = (uint8_t)(tryte % 3u);
        tryte = (uint8_t)(tryte / 3u);
    }
    return true;
}

bool qihse_trinary_tryte_validate(const uint8_t* payload, size_t payload_bytes) {
    size_t i;

    if (!payload && payload_bytes != 0u) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < payload_bytes; i++) {
        if (payload[i] > QIHSE_TRINARY_TRYTE_MAX) {
            errno = EINVAL;
            return false;
        }
    }
    return true;
}

bool qihse_trinary_tryte_encode_row(const float* vector,
                                    size_t dims,
                                    uint8_t* out_trytes,
                                    size_t out_tryte_bytes) {
    size_t row_bytes;
    size_t byte_idx;

    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes)) {
        return false;
    }
    if ((!vector && dims != 0u) || (!out_trytes && row_bytes != 0u) ||
        out_tryte_bytes < row_bytes) {
        errno = EINVAL;
        return false;
    }
    for (byte_idx = 0u; byte_idx < row_bytes; byte_idx++) {
        uint8_t trits[QIHSE_TRINARY_TRITS_PER_TRYTE] = {1u, 1u, 1u, 1u, 1u};
        size_t trit_idx;

        for (trit_idx = 0u; trit_idx < QIHSE_TRINARY_TRITS_PER_TRYTE; trit_idx++) {
            size_t dim = (byte_idx * QIHSE_TRINARY_TRITS_PER_TRYTE) + trit_idx;
            if (dim < dims) {
                trits[trit_idx] = qihse_trinary_tryte_trit_from_float(vector[dim]);
            }
        }
        if (!qihse_trinary_tryte_pack5(trits, out_trytes + byte_idx)) {
            return false;
        }
    }
    return true;
}

bool qihse_trinary_tryte_encode_matrix(const float* vectors,
                                       size_t rows,
                                       size_t dims,
                                       uint8_t* out_trytes,
                                       size_t out_tryte_bytes) {
    size_t row_bytes;
    size_t payload_bytes;
    size_t row;

    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes) ||
        !qihse_tryte_checked_mul_size(rows, row_bytes, &payload_bytes)) {
        return false;
    }
    if ((!vectors && rows != 0u && dims != 0u) ||
        (!out_trytes && payload_bytes != 0u) ||
        out_tryte_bytes < payload_bytes) {
        errno = EINVAL;
        return false;
    }
    for (row = 0u; row < rows; row++) {
        const float* in = dims == 0u ? NULL : vectors + (row * dims);
        uint8_t* out = out_trytes ? out_trytes + (row * row_bytes) : NULL;
        if (!qihse_trinary_tryte_encode_row(in, dims, out, row_bytes)) {
            return false;
        }
    }
    return true;
}

bool qihse_trinary_tryte_similarity_i32(const uint8_t* lhs_trytes,
                                        const uint8_t* rhs_trytes,
                                        size_t dims,
                                        int32_t* out_score) {
    size_t row_bytes;
    size_t byte_idx;
    size_t seen_dims = 0u;
    int32_t score = 0;

    if (!out_score || dims > (size_t)INT32_MAX) {
        errno = out_score ? EOVERFLOW : EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes)) {
        return false;
    }
    if ((!lhs_trytes || !rhs_trytes) && row_bytes != 0u) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_validate(lhs_trytes, row_bytes) ||
        !qihse_trinary_tryte_validate(rhs_trytes, row_bytes)) {
        return false;
    }
    for (byte_idx = 0u; byte_idx < row_bytes; byte_idx++) {
        uint8_t lhs[QIHSE_TRINARY_TRITS_PER_TRYTE];
        uint8_t rhs[QIHSE_TRINARY_TRITS_PER_TRYTE];
        size_t trit_idx;

        if (!qihse_trinary_tryte_unpack(lhs_trytes[byte_idx], lhs) ||
            !qihse_trinary_tryte_unpack(rhs_trytes[byte_idx], rhs)) {
            return false;
        }
        for (trit_idx = 0u; trit_idx < QIHSE_TRINARY_TRITS_PER_TRYTE &&
                            seen_dims < dims;
             trit_idx++, seen_dims++) {
            score += (int32_t)(qihse_tryte_signed_trit(lhs[trit_idx]) *
                               qihse_tryte_signed_trit(rhs[trit_idx]));
        }
    }
    *out_score = score;
    return true;
}
