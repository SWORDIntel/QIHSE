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
    uint8_t decoded[QIHSE_TRINARY_TRITS_PER_TRYTE];

    TEST_ASSERT(qihse_trinary_tryte_encode_row(vector, 6u, out, sizeof(out)),
                "row encoding should succeed");
    TEST_ASSERT(out[0] == 183u, "first tryte should encode five real trits");
    TEST_ASSERT(out[1] == 121u, "second tryte should pad with neutral trits");
    TEST_ASSERT(qihse_trinary_tryte_unpack(out[1], decoded), "padded tryte should unpack");
    TEST_ASSERT(decoded[0] == 1u, "sixth zero dimension should encode neutral");
    TEST_ASSERT(decoded[1] == 1u && decoded[2] == 1u && decoded[3] == 1u &&
                    decoded[4] == 1u,
                "padding trits should be neutral");
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

int main(void) {
    struct test_case {
        const char* name;
        bool (*run)(void);
    } tests[] = {
        {"size helpers", test_size_helpers},
        {"pack/unpack/validation", test_pack_unpack_and_validation},
        {"encode row padding", test_encode_row_padding},
        {"matrix and similarity", test_matrix_and_similarity},
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
