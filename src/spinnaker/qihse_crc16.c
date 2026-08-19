#include "qihse_crc16.h"
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define QIHSE_CRC16_X86 1
#else
#define QIHSE_CRC16_X86 0
#endif

typedef uint16_t (*qihse_crc16_fn_t)(const uint8_t*, size_t);

static uint16_t g_crc16_table[8][256] __attribute__((aligned(64)));
static qihse_crc16_fn_t g_crc16_fn;
static qihse_crc16_backend_t g_crc16_backend = QIHSE_CRC16_SCALAR;
static pthread_once_t g_crc16_once = PTHREAD_ONCE_INIT;

static uint16_t qihse_crc16_scalar_update(uint16_t crc, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        crc = (uint16_t)((crc << 8) ^ g_crc16_table[0][((crc >> 8) ^ data[i]) & 0xffu]);
    }
    return crc;
}

static uint16_t qihse_crc16_scalar(const uint8_t* data, size_t len) {
    return qihse_crc16_scalar_update(0, data, len);
}

static uint16_t qihse_crc16_slice8_update(uint16_t crc, const uint8_t* data, size_t len) {
    while (len >= 8) {
        crc = (uint16_t)(g_crc16_table[7][((crc >> 8) ^ data[0]) & 0xffu] ^
                         g_crc16_table[6][((crc & 0xffu) ^ data[1]) & 0xffu] ^
                         g_crc16_table[5][data[2]] ^
                         g_crc16_table[4][data[3]] ^
                         g_crc16_table[3][data[4]] ^
                         g_crc16_table[2][data[5]] ^
                         g_crc16_table[1][data[6]] ^
                         g_crc16_table[0][data[7]]);
        data += 8;
        len -= 8;
    }
    return qihse_crc16_scalar_update(crc, data, len);
}

static uint16_t qihse_crc16_slice8(const uint8_t* data, size_t len) {
    return qihse_crc16_slice8_update(0, data, len);
}

#if QIHSE_CRC16_X86
__attribute__((target("pclmul,ssse3,sse2"), always_inline))
static inline __m128i qihse_crc16_fold(__m128i acc, __m128i data, __m128i constants) {
    __m128i high = _mm_clmulepi64_si128(acc, constants, 0x11);
    __m128i low = _mm_clmulepi64_si128(acc, constants, 0x00);
    return _mm_xor_si128(_mm_xor_si128(high, low), data);
}

__attribute__((target("pclmul,ssse3,sse2")))
static uint16_t qihse_crc16_pclmul(const uint8_t* data, size_t len) {
    if (len < 64) return qihse_crc16_slice8(data, len);

    const __m128i reverse = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8,
                                          7, 6, 5, 4, 3, 2, 1, 0);
    const __m128i step = _mm_set_epi64x(UINT64_C(0x650b), UINT64_C(0xaefc));
    size_t blocks = len / 16;
    const uint8_t* cursor = data;
    __m128i acc;

    if (blocks >= 8) {
        __m128i acc0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 0)), reverse);
        __m128i acc1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 16)), reverse);
        __m128i acc2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 32)), reverse);
        __m128i acc3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 48)), reverse);
        __m128i acc4 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 64)), reverse);
        __m128i acc5 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 80)), reverse);
        __m128i acc6 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 96)), reverse);
        __m128i acc7 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 112)), reverse);
        const __m128i stride = _mm_set_epi64x(UINT64_C(0x71c4), UINT64_C(0x36c4));
        cursor += 128;
        blocks -= 8;
        while (blocks >= 8) {
            acc0 = qihse_crc16_fold(acc0, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 0)), reverse), stride);
            acc1 = qihse_crc16_fold(acc1, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 16)), reverse), stride);
            acc2 = qihse_crc16_fold(acc2, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 32)), reverse), stride);
            acc3 = qihse_crc16_fold(acc3, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 48)), reverse), stride);
            acc4 = qihse_crc16_fold(acc4, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 64)), reverse), stride);
            acc5 = qihse_crc16_fold(acc5, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 80)), reverse), stride);
            acc6 = qihse_crc16_fold(acc6, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 96)), reverse), stride);
            acc7 = qihse_crc16_fold(acc7, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(cursor + 112)), reverse), stride);
            cursor += 128;
            blocks -= 8;
        }
        const __m128i zero = _mm_setzero_si128();
        acc = acc7;
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc6, zero, step));
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc5, zero, _mm_set_epi64x(UINT64_C(0x26aa), UINT64_C(0x8e29))));
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc4, zero, _mm_set_epi64x(UINT64_C(0x2535), UINT64_C(0xcde2))));
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc3, zero, _mm_set_epi64x(UINT64_C(0x8832), UINT64_C(0x13fc))));
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc2, zero, _mm_set_epi64x(UINT64_C(0x87b3), UINT64_C(0xda35))));
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc1, zero, _mm_set_epi64x(UINT64_C(0x0447), UINT64_C(0x106f))));
        acc = _mm_xor_si128(acc, qihse_crc16_fold(acc0, zero, _mm_set_epi64x(UINT64_C(0xd24c), UINT64_C(0xcbc5))));
    } else {
        acc = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)cursor), reverse);
        cursor += 16;
        blocks--;
    }

    while (blocks > 0) {
        __m128i next = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)cursor), reverse);
        acc = qihse_crc16_fold(acc, next, step);
        cursor += 16;
        blocks--;
    }

    acc = _mm_shuffle_epi8(acc, reverse);
    uint8_t folded[32] __attribute__((aligned(16)));
    _mm_store_si128((__m128i*)folded, acc);
    size_t remaining = len & 15u;
    if (remaining > 0) memcpy(folded + 16, cursor, remaining);
    return qihse_crc16_slice8(folded, 16 + remaining);
}

static int qihse_crc16_pclmul_available(void) {
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("ssse3");
#else
    return 0;
#endif
}

static int qihse_crc16_pclmul_selftest(void) {
    uint8_t data[1057];
    uint32_t state = UINT32_C(0x9e3779b9);
    for (size_t i = 0; i < sizeof(data); i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        data[i] = (uint8_t)state;
    }
    for (size_t offset = 0; offset < 16; offset++) {
        for (size_t len = 64; len + offset <= sizeof(data); len += 17) {
            if (qihse_crc16_pclmul(data + offset, len) != qihse_crc16_scalar(data + offset, len)) return 0;
        }
    }
    return 1;
}
#endif

static void qihse_crc16_initialize(void) {
    for (unsigned int i = 0; i < 256; i++) {
        uint16_t crc = (uint16_t)(i << 8);
        for (unsigned int bit = 0; bit < 8; bit++) {
            crc = (uint16_t)(((uint32_t)crc << 1) ^ ((crc & 0x8000u) ? 0x1021u : 0u));
        }
        g_crc16_table[0][i] = crc;
    }
    for (unsigned int slice = 1; slice < 8; slice++) {
        for (unsigned int i = 0; i < 256; i++) {
            uint16_t crc = g_crc16_table[slice - 1][i];
            g_crc16_table[slice][i] = (uint16_t)((crc << 8) ^ g_crc16_table[0][crc >> 8]);
        }
    }

    g_crc16_fn = qihse_crc16_slice8;
    g_crc16_backend = QIHSE_CRC16_SLICE8;
    const char* requested = getenv("QIHSE_CRC16_BACKEND");
    if (requested && strcmp(requested, "scalar") == 0) {
        g_crc16_fn = qihse_crc16_scalar;
        g_crc16_backend = QIHSE_CRC16_SCALAR;
        return;
    }
#if QIHSE_CRC16_X86
    if ((!requested || strcmp(requested, "pclmul") == 0) &&
        qihse_crc16_pclmul_available() && qihse_crc16_pclmul_selftest()) {
        g_crc16_fn = qihse_crc16_pclmul;
        g_crc16_backend = QIHSE_CRC16_PCLMUL;
    }
#else
    (void)requested;
#endif
}

void qihse_crc16_init(void) {
    pthread_once(&g_crc16_once, qihse_crc16_initialize);
}

uint16_t qihse_crc16_xmodem(const void* data, size_t len) {
    qihse_crc16_init();
    if (!data && len != 0) return 0;
    return g_crc16_fn((const uint8_t*)data, len);
}

uint16_t qihse_cluster_key_slot(const void* key, size_t key_len) {
    const uint8_t* bytes = (const uint8_t*)key;
    if (!bytes && key_len != 0) return 0;
    size_t open = 0;
    while (open < key_len && bytes[open] != '{') open++;
    if (open < key_len) {
        size_t close = open + 1;
        while (close < key_len && bytes[close] != '}') close++;
        if (close < key_len && close > open + 1) {
            bytes += open + 1;
            key_len = close - open - 1;
        }
    }
    return (uint16_t)(qihse_crc16_xmodem(bytes, key_len) & (QIHSE_CLUSTER_SLOT_COUNT - 1u));
}

qihse_crc16_backend_t qihse_crc16_backend(void) {
    qihse_crc16_init();
    return g_crc16_backend;
}

const char* qihse_crc16_backend_name(void) {
    switch (qihse_crc16_backend()) {
        case QIHSE_CRC16_PCLMUL: return "pclmul";
        case QIHSE_CRC16_SLICE8: return "slice8";
        default: return "scalar";
    }
}
