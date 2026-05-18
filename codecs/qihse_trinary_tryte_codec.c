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

static bool qihse_tryte_checked_add_i64(int64_t a, int64_t b, int64_t* out) {
    if (!out) {
        errno = EINVAL;
        return false;
    }
    if ((b > 0 && a > INT64_MAX - b) ||
        (b < 0 && a < INT64_MIN - b)) {
        errno = EOVERFLOW;
        return false;
    }
    *out = a + b;
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

static bool qihse_tryte_weighted_dims_fit_i64(size_t dims) {
    if (dims > (size_t)(INT64_MAX / (int64_t)INT32_MAX)) {
        errno = EOVERFLOW;
        return false;
    }
    return true;
}

bool qihse_trinary_tryte_row_bytes(size_t dims, size_t* out_row_bytes) {
    size_t padded;

    if (!out_row_bytes) {
        errno = EINVAL;
        return false;
    }
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

static bool qihse_tryte_validate_row_padding(const uint8_t* row_trytes,
                                             size_t dims,
                                             size_t row_bytes) {
    size_t used_trits = dims % QIHSE_TRINARY_TRITS_PER_TRYTE;
    uint8_t trits[QIHSE_TRINARY_TRITS_PER_TRYTE];
    size_t i;

    if (row_bytes == 0u || used_trits == 0u) {
        return true;
    }
    if (!qihse_trinary_tryte_unpack(row_trytes[row_bytes - 1u], trits)) {
        return false;
    }
    for (i = used_trits; i < QIHSE_TRINARY_TRITS_PER_TRYTE; i++) {
        if (trits[i] != 1u) {
            errno = EINVAL;
            return false;
        }
    }
    return true;
}

bool qihse_trinary_tryte_validate_row(const uint8_t* row_trytes, size_t dims) {
    size_t row_bytes;

    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes)) {
        return false;
    }
    if (!row_trytes && row_bytes != 0u) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_validate(row_trytes, row_bytes)) {
        return false;
    }
    return qihse_tryte_validate_row_padding(row_trytes, dims, row_bytes);
}

bool qihse_trinary_tryte_validate_payload(const uint8_t* payload,
                                          size_t rows,
                                          size_t dims) {
    size_t row_bytes;
    size_t payload_bytes;
    size_t row;

    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes) ||
        !qihse_tryte_checked_mul_size(rows, row_bytes, &payload_bytes)) {
        return false;
    }
    if (!payload && payload_bytes != 0u) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_validate(payload, payload_bytes)) {
        return false;
    }
    for (row = 0u; row < rows; row++) {
        const uint8_t* row_trytes = row_bytes == 0u
                                        ? NULL
                                        : payload + (row * row_bytes);
        if (!qihse_tryte_validate_row_padding(row_trytes, dims, row_bytes)) {
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
    if (!qihse_trinary_tryte_validate_row(lhs_trytes, dims) ||
        !qihse_trinary_tryte_validate_row(rhs_trytes, dims)) {
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

static bool qihse_tryte_candidate_is_better(int32_t lhs_score,
                                            size_t lhs_row,
                                            int32_t rhs_score,
                                            size_t rhs_row) {
    return lhs_score > rhs_score ||
           (lhs_score == rhs_score && lhs_row < rhs_row);
}

bool qihse_trinary_tryte_select_topk(const uint8_t* encoded_rows,
                                     const uint8_t* encoded_query,
                                     size_t row_count,
                                     size_t dims,
                                     size_t* out_row_indexes,
                                     int32_t* out_scores,
                                     size_t max_results,
                                     size_t* out_count) {
    size_t row_bytes;
    size_t payload_bytes;
    size_t selected = 0u;
    size_t row;

    if (!out_count) {
        errno = EINVAL;
        return false;
    }
    *out_count = 0u;
    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes) ||
        !qihse_tryte_checked_mul_size(row_count, row_bytes, &payload_bytes)) {
        return false;
    }
    if ((!encoded_rows && payload_bytes != 0u) ||
        (!encoded_query && row_bytes != 0u) ||
        (!out_row_indexes && max_results != 0u) ||
        (!out_scores && max_results != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_validate_row(encoded_query, dims) ||
        !qihse_trinary_tryte_validate_payload(encoded_rows, row_count, dims)) {
        return false;
    }
    if (row_count == 0u || max_results == 0u) {
        return true;
    }

    for (row = 0u; row < row_count; row++) {
        const uint8_t* candidate = row_bytes == 0u
                                       ? NULL
                                       : encoded_rows + (row * row_bytes);
        int32_t score = 0;
        size_t insert_at;

        if (!qihse_trinary_tryte_similarity_i32(candidate,
                                               encoded_query,
                                               dims,
                                               &score)) {
            return false;
        }

        insert_at = selected;
        while (insert_at > 0u &&
               qihse_tryte_candidate_is_better(score,
                                                row,
                                                out_scores[insert_at - 1u],
                                                out_row_indexes[insert_at - 1u])) {
            insert_at--;
        }
        if (insert_at >= max_results) {
            continue;
        }
        if (selected < max_results) {
            selected++;
        }
        if (selected > insert_at + 1u) {
            size_t move;
            for (move = selected - 1u; move > insert_at; move--) {
                out_row_indexes[move] = out_row_indexes[move - 1u];
                out_scores[move] = out_scores[move - 1u];
            }
        }
        out_row_indexes[insert_at] = row;
        out_scores[insert_at] = score;
    }

    *out_count = selected;
    return true;
}

bool qihse_trinary_tryte_weighted_similarity_i64(const uint8_t* lhs_trytes,
                                                 const uint8_t* rhs_trytes,
                                                 const int32_t* dim_weights,
                                                 size_t dims,
                                                 int64_t* out_score) {
    size_t row_bytes;
    size_t byte_idx;
    size_t seen_dims = 0u;
    int64_t score = 0;

    if (!out_score) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_tryte_weighted_dims_fit_i64(dims)) {
        return false;
    }
    if ((!dim_weights && dims != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes)) {
        return false;
    }
    if ((!lhs_trytes || !rhs_trytes) && row_bytes != 0u) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_validate_row(lhs_trytes, dims) ||
        !qihse_trinary_tryte_validate_row(rhs_trytes, dims)) {
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
            if (dim_weights[seen_dims] < 0) {
                errno = EINVAL;
                return false;
            }
            {
                int64_t signed_product =
                    (int64_t)(qihse_tryte_signed_trit(lhs[trit_idx]) *
                              qihse_tryte_signed_trit(rhs[trit_idx]));
                int64_t delta = signed_product * (int64_t)dim_weights[seen_dims];

                if (!qihse_tryte_checked_add_i64(score, delta, &score)) {
                    return false;
                }
            }
        }
    }
    *out_score = score;
    return true;
}

static bool qihse_tryte_weighted_candidate_is_better(int64_t lhs_score,
                                                     size_t lhs_row,
                                                     int64_t rhs_score,
                                                     size_t rhs_row) {
    return lhs_score > rhs_score ||
           (lhs_score == rhs_score && lhs_row < rhs_row);
}

bool qihse_trinary_tryte_select_topk_weighted(const uint8_t* encoded_rows,
                                              const uint8_t* encoded_query,
                                              const int32_t* dim_weights,
                                              size_t row_count,
                                              size_t dims,
                                              size_t* out_row_indexes,
                                              int64_t* out_scores,
                                              size_t max_results,
                                              size_t* out_count) {
    size_t row_bytes;
    size_t payload_bytes;
    size_t selected = 0u;
    size_t row;

    if (!out_count) {
        errno = EINVAL;
        return false;
    }
    *out_count = 0u;
    if (!qihse_tryte_weighted_dims_fit_i64(dims)) {
        return false;
    }
    if ((!dim_weights && dims != 0u) ||
        !qihse_trinary_tryte_row_bytes(dims, &row_bytes) ||
        !qihse_tryte_checked_mul_size(row_count, row_bytes, &payload_bytes)) {
        if (!dim_weights && dims != 0u) {
            errno = EINVAL;
        }
        return false;
    }
    if ((!encoded_rows && payload_bytes != 0u) ||
        (!encoded_query && row_bytes != 0u) ||
        (!out_row_indexes && max_results != 0u) ||
        (!out_scores && max_results != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_validate_row(encoded_query, dims) ||
        !qihse_trinary_tryte_validate_payload(encoded_rows, row_count, dims)) {
        return false;
    }
    if (row_count == 0u || max_results == 0u) {
        return true;
    }

    for (row = 0u; row < row_count; row++) {
        const uint8_t* candidate = row_bytes == 0u
                                       ? NULL
                                       : encoded_rows + (row * row_bytes);
        int64_t score = 0;
        size_t insert_at;

        if (!qihse_trinary_tryte_weighted_similarity_i64(candidate,
                                                        encoded_query,
                                                        dim_weights,
                                                        dims,
                                                        &score)) {
            return false;
        }

        insert_at = selected;
        while (insert_at > 0u &&
               qihse_tryte_weighted_candidate_is_better(
                   score,
                   row,
                   out_scores[insert_at - 1u],
                   out_row_indexes[insert_at - 1u])) {
            insert_at--;
        }
        if (insert_at >= max_results) {
            continue;
        }
        if (selected < max_results) {
            selected++;
        }
        if (selected > insert_at + 1u) {
            size_t move;
            for (move = selected - 1u; move > insert_at; move--) {
                out_row_indexes[move] = out_row_indexes[move - 1u];
                out_scores[move] = out_scores[move - 1u];
            }
        }
        out_row_indexes[insert_at] = row;
        out_scores[insert_at] = score;
    }

    *out_count = selected;
    return true;
}
