#include "../codecs/qihse_trinary_tryte_codec.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return false; \
        } \
    } while (0)

static bool test_size_helpers(void) {
    size_t bytes = 999u;

    TEST_ASSERT(qihse_trinary_tryte_row_bytes(0u, &bytes), "zero dims row size should compute");
    TEST_ASSERT(bytes == 0u, "zero dims row size should be zero");
    TEST_ASSERT(qihse_trinary_tryte_row_bytes(1u, &bytes), "one dim row size should compute");
    TEST_ASSERT(bytes == 1u, "one dim should use one tryte byte");
    TEST_ASSERT(qihse_trinary_tryte_row_bytes(5u, &bytes), "five dims row size should compute");
    TEST_ASSERT(bytes == 1u, "five dims should use one tryte byte");
    TEST_ASSERT(qihse_trinary_tryte_row_bytes(6u, &bytes), "six dims row size should compute");
    TEST_ASSERT(bytes == 2u, "six dims should use two tryte bytes");
    TEST_ASSERT(qihse_trinary_tryte_payload_bytes(7u, 6u, &bytes),
                "payload size should compute");
    TEST_ASSERT(bytes == 14u, "payload size should be rows times row bytes");
    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_row_bytes(0u, NULL),
                "row size helper should reject null output");
    TEST_ASSERT(errno == EINVAL, "null row size output should set EINVAL");
    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_row_bytes(SIZE_MAX, &bytes),
                "row size helper should reject overflowing dims");
    TEST_ASSERT(errno == EOVERFLOW, "overflowing row size should set EOVERFLOW");
    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_payload_bytes(SIZE_MAX, 6u, &bytes),
                "payload size helper should reject overflowing product");
    TEST_ASSERT(errno == EOVERFLOW, "overflowing payload size should set EOVERFLOW");
    return true;
}

static bool test_pack_unpack_and_validation(void) {
    const uint8_t trits[QIHSE_TRINARY_TRITS_PER_TRYTE] = {0u, 1u, 2u, 1u, 0u};
    uint8_t decoded[QIHSE_TRINARY_TRITS_PER_TRYTE];
    uint8_t tryte = 255u;
    uint8_t invalid = 243u;

    TEST_ASSERT(qihse_trinary_tryte_pack5(trits, &tryte), "pack5 should accept trits 0..2");
    TEST_ASSERT(tryte == 48u, "pack5 should use little-endian base-3 ordering");
    TEST_ASSERT(qihse_trinary_tryte_unpack(tryte, decoded), "unpack should accept valid tryte");
    TEST_ASSERT(memcmp(trits, decoded, sizeof(trits)) == 0, "unpack should round-trip trits");
    TEST_ASSERT(qihse_trinary_tryte_validate(&tryte, 1u), "valid tryte should validate");
    TEST_ASSERT(!qihse_trinary_tryte_validate(&invalid, 1u),
                "tryte 243 should be invalid");
    TEST_ASSERT(errno == EINVAL, "invalid tryte should set EINVAL");
    return true;
}

static bool test_encode_row_padding(void) {
    const float vector[] = {-2.0f, 0.0f, 4.0f, -0.5f, 8.0f, 0.0f};
    uint8_t out[2] = {0u, 0u};
    uint8_t invalid_padding[2] = {0u, 0u};
    uint8_t decoded[QIHSE_TRINARY_TRITS_PER_TRYTE];
    int32_t score = 12345;

    TEST_ASSERT(qihse_trinary_tryte_encode_row(vector, 6u, out, sizeof(out)),
                "row encoding should succeed");
    TEST_ASSERT(out[0] == 183u, "first tryte should encode five real trits");
    TEST_ASSERT(out[1] == 121u, "second tryte should pad with neutral trits");
    TEST_ASSERT(qihse_trinary_tryte_unpack(out[1], decoded), "padded tryte should unpack");
    TEST_ASSERT(decoded[0] == 1u, "sixth zero dimension should encode neutral");
    TEST_ASSERT(decoded[1] == 1u && decoded[2] == 1u && decoded[3] == 1u &&
                    decoded[4] == 1u,
                "padding trits should be neutral");
    TEST_ASSERT(qihse_trinary_tryte_validate(out, sizeof(out)),
                "byte validation should accept encoded row");
    TEST_ASSERT(qihse_trinary_tryte_validate_row(out, 6u),
                "row validation should accept neutral padding");

    invalid_padding[0] = out[0];
    invalid_padding[1] = 1u;
    TEST_ASSERT(qihse_trinary_tryte_validate(invalid_padding, sizeof(invalid_padding)),
                "generic validation should only check tryte byte range");
    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_validate_row(invalid_padding, 6u),
                "row validation should reject non-neutral padding");
    TEST_ASSERT(errno == EINVAL, "invalid padding should set EINVAL");
    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_similarity_i32(out,
                                                    invalid_padding,
                                                    6u,
                                                    &score),
                "similarity should reject non-neutral padding");
    TEST_ASSERT(errno == EINVAL, "similarity padding rejection should set EINVAL");
    return true;
}

static bool test_sign_heavy_rows(void) {
    const float positives[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f};
    const float negatives[] = {-1.0f, -2.0f, -3.0f, -4.0f, -5.0f, -6.0f, -7.0f};
    const float zero_heavy[] = {0.0f, 0.0f, 2.0f, 0.0f, -3.0f, 0.0f, 0.0f};
    uint8_t encoded_pos[2] = {0u, 0u};
    uint8_t encoded_neg[2] = {0u, 0u};
    uint8_t encoded_zero_heavy[2] = {0u, 0u};
    int32_t score = 12345;

    TEST_ASSERT(qihse_trinary_tryte_encode_row(positives, 7u,
                                               encoded_pos,
                                               sizeof(encoded_pos)),
                "all-positive row should encode");
    TEST_ASSERT(qihse_trinary_tryte_encode_row(negatives, 7u,
                                               encoded_neg,
                                               sizeof(encoded_neg)),
                "all-negative row should encode");
    TEST_ASSERT(qihse_trinary_tryte_encode_row(zero_heavy, 7u,
                                               encoded_zero_heavy,
                                               sizeof(encoded_zero_heavy)),
                "zero-heavy row should encode");
    TEST_ASSERT(qihse_trinary_tryte_similarity_i32(encoded_pos,
                                                   encoded_pos,
                                                   7u,
                                                   &score),
                "all-positive self-similarity should score");
    TEST_ASSERT(score == 7, "all-positive self-similarity should count every dim");
    TEST_ASSERT(qihse_trinary_tryte_similarity_i32(encoded_pos,
                                                   encoded_neg,
                                                   7u,
                                                   &score),
                "opposite signs should score");
    TEST_ASSERT(score == -7, "all-positive versus all-negative should be fully negative");
    TEST_ASSERT(qihse_trinary_tryte_similarity_i32(encoded_zero_heavy,
                                                   encoded_zero_heavy,
                                                   7u,
                                                   &score),
                "zero-heavy self-similarity should score");
    TEST_ASSERT(score == 2, "zero-heavy self-similarity should ignore neutral dims");
    return true;
}

static bool test_matrix_and_similarity(void) {
    const float vectors[] = {
        -1.0f, 0.0f, 1.0f, 1.0f, -1.0f, 1.0f,
        -1.0f, 1.0f, 1.0f, -1.0f, -1.0f, 0.0f,
    };
    uint8_t encoded[4] = {0u, 0u, 0u, 0u};
    int32_t score = 12345;

    TEST_ASSERT(qihse_trinary_tryte_encode_matrix(vectors, 2u, 6u,
                                                  encoded, sizeof(encoded)),
                "matrix encoding should succeed");
    TEST_ASSERT(qihse_trinary_tryte_similarity_i32(encoded, encoded, 6u, &score),
                "self-similarity should score");
    TEST_ASSERT(score == 5, "self-similarity should count non-neutral dimensions");
    TEST_ASSERT(qihse_trinary_tryte_similarity_i32(encoded, encoded + 2u, 6u, &score),
                "cross-similarity should score");
    TEST_ASSERT(score == 2, "cross-similarity should use signed trit dot product");
    return true;
}

static bool test_topk_candidate_selection(void) {
    const float vectors[] = {
        1.0f, 0.0f, -1.0f, 0.0f,
        1.0f, 1.0f, -1.0f, 0.0f,
        2.0f, 3.0f, -4.0f, 0.0f,
        -1.0f, -1.0f, 1.0f, 0.0f,
        1.0f, -1.0f, -1.0f, 0.0f,
    };
    const float query[] = {1.0f, 1.0f, -1.0f, 0.0f};
    uint8_t encoded[5] = {0u, 0u, 0u, 0u, 0u};
    uint8_t encoded_query[1] = {0u};
    size_t indexes[4] = {999u, 999u, 999u, 999u};
    int32_t scores[4] = {-99, -99, -99, -99};
    size_t count = 999u;

    TEST_ASSERT(qihse_trinary_tryte_encode_matrix(vectors, 5u, 4u,
                                                  encoded, sizeof(encoded)),
                "candidate matrix should encode");
    TEST_ASSERT(qihse_trinary_tryte_encode_row(query, 4u,
                                               encoded_query,
                                               sizeof(encoded_query)),
                "query row should encode");
    TEST_ASSERT(qihse_trinary_tryte_select_topk(encoded,
                                                encoded_query,
                                                5u,
                                                4u,
                                                indexes,
                                                scores,
                                                4u,
                                                &count),
                "top-k selection should succeed");
    TEST_ASSERT(count == 4u, "top-k should fill requested result count");
    TEST_ASSERT(indexes[0] == 1u && scores[0] == 3,
                "best candidate should be first exact match");
    TEST_ASSERT(indexes[1] == 2u && scores[1] == 3,
                "equal-score candidate should preserve lower row index first");
    TEST_ASSERT(indexes[2] == 0u && scores[2] == 2,
                "third candidate should be partial match");
    TEST_ASSERT(indexes[3] == 4u && scores[3] == 1,
                "fourth candidate should be next highest score");
    return true;
}

static bool test_weighted_topk_candidate_selection(void) {
    const float vectors[] = {
        1.0f, -1.0f, -1.0f, -1.0f,
        -1.0f, 1.0f, 1.0f, 1.0f,
        1.0f, 1.0f, -1.0f, -1.0f,
    };
    const float query[] = {1.0f, 1.0f, 1.0f, 1.0f};
    const int32_t weights[] = {10, 1, 1, 1};
    uint8_t encoded[3] = {0u, 0u, 0u};
    uint8_t encoded_query[1] = {0u};
    size_t indexes[3] = {999u, 999u, 999u};
    int64_t scores[3] = {-99, -99, -99};
    size_t count = 999u;
    int64_t score = 12345;

    TEST_ASSERT(qihse_trinary_tryte_encode_matrix(vectors, 3u, 4u,
                                                  encoded, sizeof(encoded)),
                "weighted candidate matrix should encode");
    TEST_ASSERT(qihse_trinary_tryte_encode_row(query, 4u,
                                               encoded_query,
                                               sizeof(encoded_query)),
                "weighted query row should encode");
    TEST_ASSERT(qihse_trinary_tryte_weighted_similarity_i64(encoded,
                                                            encoded_query,
                                                            weights,
                                                            4u,
                                                            &score),
                "weighted similarity should score");
    TEST_ASSERT(score == 7, "weighted similarity should emphasize important dimensions");
    TEST_ASSERT(qihse_trinary_tryte_select_topk_weighted(encoded,
                                                         encoded_query,
                                                         weights,
                                                         3u,
                                                         4u,
                                                         indexes,
                                                         scores,
                                                         3u,
                                                         &count),
                "weighted top-k selection should succeed");
    TEST_ASSERT(count == 3u, "weighted top-k should fill requested result count");
    TEST_ASSERT(indexes[0] == 2u && scores[0] == 9,
                "weighted best candidate should win on important dimensions");
    TEST_ASSERT(indexes[1] == 0u && scores[1] == 7,
                "weighted second candidate should beat broad low-value match");
    TEST_ASSERT(indexes[2] == 1u && scores[2] == -7,
                "weighted lowest candidate should be last");
    return true;
}

static bool test_weighted_topk_tie_ordering(void) {
    const float vectors[] = {
        1.0f, -1.0f,
        -1.0f, 1.0f,
        -1.0f, -1.0f,
    };
    const float query[] = {1.0f, 1.0f};
    const int32_t weights[] = {1, 1};
    uint8_t encoded[3] = {0u, 0u, 0u};
    uint8_t encoded_query[1] = {0u};
    size_t indexes[3] = {999u, 999u, 999u};
    int64_t scores[3] = {-99, -99, -99};
    size_t count = 999u;

    TEST_ASSERT(qihse_trinary_tryte_encode_matrix(vectors, 3u, 2u,
                                                  encoded, sizeof(encoded)),
                "weighted tie candidate matrix should encode");
    TEST_ASSERT(qihse_trinary_tryte_encode_row(query, 2u,
                                               encoded_query,
                                               sizeof(encoded_query)),
                "weighted tie query should encode");
    TEST_ASSERT(qihse_trinary_tryte_select_topk_weighted(encoded,
                                                         encoded_query,
                                                         weights,
                                                         3u,
                                                         2u,
                                                         indexes,
                                                         scores,
                                                         3u,
                                                         &count),
                "weighted top-k tie selection should succeed");
    TEST_ASSERT(count == 3u, "weighted tie top-k should return all rows");
    TEST_ASSERT(indexes[0] == 0u && scores[0] == 0,
                "weighted tie should keep lower row index first");
    TEST_ASSERT(indexes[1] == 1u && scores[1] == 0,
                "weighted tie should keep next lower row index second");
    TEST_ASSERT(indexes[2] == 2u && scores[2] == -2,
                "weighted non-tie loser should sort last");
    return true;
}

static bool test_weighted_topk_rejects_negative_weight(void) {
    const float vector[] = {1.0f};
    const float query[] = {1.0f};
    const int32_t weights[] = {-1};
    uint8_t encoded[1] = {0u};
    uint8_t encoded_query[1] = {0u};
    size_t index = 999u;
    int64_t score = -99;
    size_t count = 999u;

    TEST_ASSERT(qihse_trinary_tryte_encode_row(vector, 1u, encoded, sizeof(encoded)),
                "negative-weight candidate should encode");
    TEST_ASSERT(qihse_trinary_tryte_encode_row(query, 1u, encoded_query, sizeof(encoded_query)),
                "negative-weight query should encode");
    TEST_ASSERT(!qihse_trinary_tryte_select_topk_weighted(encoded,
                                                          encoded_query,
                                                          weights,
                                                          1u,
                                                          1u,
                                                          &index,
                                                          &score,
                                                          1u,
                                                          &count),
                "weighted top-k should reject negative dimension weights");
    TEST_ASSERT(errno == EINVAL, "negative dimension weight should set EINVAL");
    TEST_ASSERT(count == 0u, "negative dimension weight should clear out_count");
    return true;
}

static bool test_weighted_similarity_overflow_guard(void) {
    const uint8_t encoded = 122u;
    const int32_t weight = 0;
    int64_t score = 12345;
    size_t overflowing_dims = (size_t)(INT64_MAX / (int64_t)INT32_MAX) + 1u;

    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_weighted_similarity_i64(&encoded,
                                                             &encoded,
                                                             &weight,
                                                             overflowing_dims,
                                                             &score),
                "weighted similarity should reject dimensions with overflowing score range");
    TEST_ASSERT(errno == EOVERFLOW, "weighted score range overflow should set EOVERFLOW");
    return true;
}

static bool test_topk_invalid_tryte_rejected(void) {
    uint8_t encoded[] = {0u, 243u, 0u};
    uint8_t query[] = {0u};
    size_t indexes[2] = {999u, 999u};
    int32_t scores[2] = {-99, -99};
    size_t count = 999u;

    TEST_ASSERT(!qihse_trinary_tryte_select_topk(encoded,
                                                 query,
                                                 3u,
                                                 5u,
                                                 indexes,
                                                 scores,
                                                 2u,
                                                 &count),
                "top-k should reject invalid candidate trytes");
    TEST_ASSERT(errno == EINVAL, "invalid candidate tryte should set EINVAL");
    TEST_ASSERT(count == 0u, "invalid selection should clear out_count");

    encoded[1] = 0u;
    query[0] = 243u;
    count = 999u;
    TEST_ASSERT(!qihse_trinary_tryte_select_topk(encoded,
                                                 query,
                                                 3u,
                                                 5u,
                                                 indexes,
                                                 scores,
                                                 2u,
                                                 &count),
                "top-k should reject invalid query trytes");
    TEST_ASSERT(errno == EINVAL, "invalid query tryte should set EINVAL");
    TEST_ASSERT(count == 0u, "invalid query should clear out_count");
    return true;
}

static bool test_topk_invalid_padding_rejected(void) {
    uint8_t encoded[] = {122u, 2u};
    uint8_t query[] = {122u};
    size_t indexes[2] = {999u, 999u};
    int32_t scores[2] = {-99, -99};
    size_t count = 999u;

    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_select_topk(encoded,
                                                 query,
                                                 2u,
                                                 1u,
                                                 indexes,
                                                 scores,
                                                 2u,
                                                 &count),
                "top-k should reject candidate rows with invalid padding");
    TEST_ASSERT(errno == EINVAL, "invalid candidate padding should set EINVAL");
    TEST_ASSERT(count == 0u, "invalid candidate padding should clear out_count");

    encoded[1] = 122u;
    query[0] = 2u;
    count = 999u;
    errno = 0;
    TEST_ASSERT(!qihse_trinary_tryte_select_topk(encoded,
                                                 query,
                                                 2u,
                                                 1u,
                                                 indexes,
                                                 scores,
                                                 2u,
                                                 &count),
                "top-k should reject query rows with invalid padding");
    TEST_ASSERT(errno == EINVAL, "invalid query padding should set EINVAL");
    TEST_ASSERT(count == 0u, "invalid query padding should clear out_count");
    return true;
}

int main(void) {
    struct test_case {
        const char* name;
        bool (*run)(void);
    } tests[] = {
        {"size helpers", test_size_helpers},
        {"pack/unpack/validation", test_pack_unpack_and_validation},
        {"encode row padding", test_encode_row_padding},
        {"sign-heavy rows", test_sign_heavy_rows},
        {"matrix and similarity", test_matrix_and_similarity},
        {"top-k candidate selection", test_topk_candidate_selection},
        {"weighted top-k candidate selection", test_weighted_topk_candidate_selection},
        {"weighted top-k tie ordering", test_weighted_topk_tie_ordering},
        {"weighted top-k negative weight rejection", test_weighted_topk_rejects_negative_weight},
        {"weighted similarity overflow guard", test_weighted_similarity_overflow_guard},
        {"top-k invalid tryte rejection", test_topk_invalid_tryte_rejected},
        {"top-k invalid padding rejection", test_topk_invalid_padding_rejected},
    };
    size_t i;

    for (i = 0u; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (!tests[i].run()) {
            fprintf(stderr, "test failed: %s\n", tests[i].name);
            return 1;
        }
        printf("PASS: %s\n", tests[i].name);
    }
    return 0;
}
