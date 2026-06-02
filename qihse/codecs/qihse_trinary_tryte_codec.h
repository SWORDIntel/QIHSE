#ifndef QIHSE_TRINARY_TRYTE_CODEC_H
#define QIHSE_TRINARY_TRYTE_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_TRINARY_TRITS_PER_TRYTE 5u
#define QIHSE_TRINARY_TRYTE_VALUE_COUNT 243u
#define QIHSE_TRINARY_TRYTE_MAX 242u

/*
 * Native tryte codec for QIHSE trinary vector sidecars.
 *
 * Encoding is deterministic and independent of the vector DB:
 *   float < 0.0  -> trit 0, signed value -1
 *   float == 0.0 -> trit 1, signed value  0
 *   float > 0.0  -> trit 2, signed value +1
 *
 * Five trits are packed into one byte as a little-endian base-3 integer.
 * Valid encoded bytes are therefore 0..242. Padding trits in the final byte
 * are neutral zero trits, encoded as trit 1.
 */

bool qihse_trinary_tryte_row_bytes(size_t dims, size_t* out_row_bytes);

bool qihse_trinary_tryte_payload_bytes(size_t rows,
                                       size_t dims,
                                       size_t* out_payload_bytes);

uint8_t qihse_trinary_tryte_trit_from_float(float value);

bool qihse_trinary_tryte_pack5(const uint8_t trits[QIHSE_TRINARY_TRITS_PER_TRYTE],
                               uint8_t* out_tryte);

bool qihse_trinary_tryte_unpack(uint8_t tryte,
                                uint8_t out_trits[QIHSE_TRINARY_TRITS_PER_TRYTE]);

bool qihse_trinary_tryte_validate(const uint8_t* payload, size_t payload_bytes);

bool qihse_trinary_tryte_encode_row(const float* vector,
                                    size_t dims,
                                    uint8_t* out_trytes,
                                    size_t out_tryte_bytes);

bool qihse_trinary_tryte_encode_matrix(const float* vectors,
                                       size_t rows,
                                       size_t dims,
                                       uint8_t* out_trytes,
                                       size_t out_tryte_bytes);

/*
 * Scalar signed-trit dot product over two encoded rows.
 *
 * The score range is [-dims, dims]. Padding trits are ignored through dims.
 * The function validates input tryte bytes before scoring.
 */
bool qihse_trinary_tryte_similarity_i32(const uint8_t* lhs_trytes,
                                        const uint8_t* rhs_trytes,
                                        size_t dims,
                                        int32_t* out_score);

/*
 * Deterministic top-k candidate selection over encoded rows.
 *
 * Results are ordered by descending signed-trit similarity score. Equal scores
 * are ordered by lower row index first. The output row indexes refer to the
 * input row ordinal, not an external vector id.
 */
bool qihse_trinary_tryte_select_topk(const uint8_t* encoded_rows,
                                     const uint8_t* encoded_query,
                                     size_t row_count,
                                     size_t dims,
                                     size_t* out_row_indexes,
                                     int32_t* out_scores,
                                     size_t max_results,
                                     size_t* out_count);

#ifdef __cplusplus
}
#endif

#endif
