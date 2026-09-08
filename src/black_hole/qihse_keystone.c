#include "qihse_keystone.h"
#include "qihse_crc16.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

#define DSMIL_MODEL_INPUT_DIM 260
#define DSMIL_MODEL_HIDDEN_DIM 64
#define DSMIL_MODEL_NUM_CLASSES 6

static float g_model_w1[DSMIL_MODEL_INPUT_DIM][DSMIL_MODEL_HIDDEN_DIM];
static float g_model_b1[DSMIL_MODEL_HIDDEN_DIM];
static float g_model_w2[DSMIL_MODEL_HIDDEN_DIM][DSMIL_MODEL_NUM_CLASSES];
static float g_model_b2[DSMIL_MODEL_NUM_CLASSES];
static bool g_weights_initialized = false;

static void qihse_secure_zero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (p && len--) *p++ = 0u;
}

static void init_micro_model_weights(void) {
    if (g_weights_initialized) return;
    for (int j = 0; j < DSMIL_MODEL_INPUT_DIM; j++) {
        for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) {
            g_model_w1[j][i] = (float)(((j * 37 + i * 19 + 7) % 100) - 50) / 500.0f;
        }
    }
    for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) g_model_b1[i] = 0.05f;
    for (int j = 0; j < DSMIL_MODEL_HIDDEN_DIM; j++) {
        for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
            g_model_w2[j][i] = (float)(((j * 23 + i * 41 + 11) % 100) - 50) / 250.0f;
        }
    }
    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) g_model_b2[i] = 0.0f;
    g_weights_initialized = true;
}

const char* qihse_keystone_class_name(qihse_keystone_class_t cls) {
    switch (cls) {
        case QIHSE_KEYSTONE_CLASS_FINANCIAL: return "FINANCIAL";
        case QIHSE_KEYSTONE_CLASS_CORPORATE: return "CORPORATE";
        case QIHSE_KEYSTONE_CLASS_GOVERNMENT: return "GOVERNMENT";
        case QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE: return "INFRASTRUCTURE";
        case QIHSE_KEYSTONE_CLASS_CONSUMER: return "CONSUMER";
        case QIHSE_KEYSTONE_CLASS_UNKNOWN:
        default: return "UNKNOWN";
    }
}

static void extract_context_features(const char* text, size_t len, float* x) {
    if (!text || !x || len == 0u) return;
    size_t char_counts[256] = {0};
    size_t digits = 0u, uppercase = 0u, symbols = 0u;
    for (size_t i = 0u; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        char_counts[c]++;
        if (isdigit(c)) digits++;
        else if (isupper(c)) uppercase++;
        else if (ispunct(c)) symbols++;
    }
    for (int i = 0; i < 256; i++) x[i] = (float)char_counts[i] / (float)len;
    x[256] = (float)digits / (float)len;
    x[257] = (float)uppercase / (float)len;
    x[258] = (float)symbols / (float)len;
    x[259] = (float)(len > 256u ? 256u : len) / 256.0f;
}

int qihse_keystone_classify_context(const char* context, size_t len,
                                    qihse_keystone_class_t* out_class,
                                    float* out_confidence) {
    if (!context || len == 0u || !out_class) return -1;
    init_micro_model_weights();
    float x[DSMIL_MODEL_INPUT_DIM] = {0};
    float hidden[DSMIL_MODEL_HIDDEN_DIM];
    float scores[DSMIL_MODEL_NUM_CLASSES];
    extract_context_features(context, len, x);

    for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) hidden[i] = g_model_b1[i];
    for (int j = 0; j < DSMIL_MODEL_INPUT_DIM; j++) {
        float xj = x[j];
        if (xj == 0.0f) continue;
        for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) hidden[i] += xj * g_model_w1[j][i];
    }
    for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) if (hidden[i] < 0.0f) hidden[i] = 0.0f;

    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) scores[i] = g_model_b2[i];
    for (int j = 0; j < DSMIL_MODEL_HIDDEN_DIM; j++) {
        float hj = hidden[j];
        if (hj == 0.0f) continue;
        for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) scores[i] += hj * g_model_w2[j][i];
    }

    int best = 0;
    float max_score = scores[0];
    for (int i = 1; i < DSMIL_MODEL_NUM_CLASSES; i++) {
        if (scores[i] > max_score) { max_score = scores[i]; best = i; }
    }
    float sum = 0.0f;
    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
        scores[i] = expf(scores[i] - max_score);
        sum += scores[i];
    }
    *out_class = (qihse_keystone_class_t)best;
    if (out_confidence) *out_confidence = sum > 0.0f ? scores[best] / sum : 0.0f;
    qihse_secure_zero(x, sizeof(x));
    qihse_secure_zero(hidden, sizeof(hidden));
    qihse_secure_zero(scores, sizeof(scores));
    return 0;
}

static inline bool is_email_local_char(unsigned char c) {
    return isalnum(c) || c == '.' || c == '_' || c == '-' || c == '+';
}

static inline bool is_email_domain_char(unsigned char c) {
    return isalnum(c) || c == '.' || c == '-';
}

static inline bool is_url_char(unsigned char c) {
    return isalnum(c) || c == '.' || c == '-' || c == '/' || c == ':' ||
           c == '_' || c == '?' || c == '=' || c == '&' || c == '%' ||
           c == '#' || c == '+' || c == '~';
}

static size_t find_next_candidate_simd(const char* buf, size_t length, size_t start) {
    if (!buf || start >= length) return length;
    size_t i = start;
#if defined(__x86_64__) || defined(__i386__)
#ifdef __AVX2__
    const __m256i at = _mm256_set1_epi8('@');
    const __m256i h1 = _mm256_set1_epi8('h');
    const __m256i h2 = _mm256_set1_epi8('H');
    for (; i + 32u <= length; i += 32u) {
        __m256i v = _mm256_loadu_si256((const __m256i*)(buf + i));
        __m256i m = _mm256_or_si256(_mm256_cmpeq_epi8(v, at),
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, h1), _mm256_cmpeq_epi8(v, h2)));
        unsigned int mask = (unsigned int)_mm256_movemask_epi8(m);
        if (mask) return i + (size_t)__builtin_ctz(mask);
    }
#elif defined(__SSE2__)
    const __m128i at = _mm_set1_epi8('@');
    const __m128i h1 = _mm_set1_epi8('h');
    const __m128i h2 = _mm_set1_epi8('H');
    for (; i + 16u <= length; i += 16u) {
        __m128i v = _mm_loadu_si128((const __m128i*)(buf + i));
        __m128i m = _mm_or_si128(_mm_cmpeq_epi8(v, at),
                    _mm_or_si128(_mm_cmpeq_epi8(v, h1), _mm_cmpeq_epi8(v, h2)));
        unsigned int mask = (unsigned int)_mm_movemask_epi8(m);
        if (mask) return i + (size_t)__builtin_ctz(mask);
    }
#endif
#endif
    for (; i < length; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '@' || c == 'h' || c == 'H') return i;
    }
    return length;
}

static bool persist_artifact(qihse_kv_store_t* kv, const char* key, const char* value,
                             uint16_t clearance, uint16_t compartment,
                             qihse_user_t* user) {
    return qihse_kv_set_user(kv, key, value, clearance, compartment, user);
}

size_t qihse_keystone_ingest_dirty_logs_user(qihse_kv_store_t* kv,
                                              qihse_cluster_topology_t* topo,
                                              const char* buffer, size_t len,
                                              uint16_t clearance,
                                              uint16_t compartment,
                                              qihse_user_t* user) {
    (void)topo;
    if (!kv || !buffer || len == 0u) return 0u;
    if (!qihse_auth_can_access(user, clearance, compartment)) return 0u;

    size_t artifacts = 0u;
    size_t i = 0u;
    while (i < len) {
        size_t cand = find_next_candidate_simd(buffer, len, i);
        if (cand >= len) break;
        i = cand;

        if (buffer[i] == '@') {
            size_t local_start = i;
            while (local_start > 0u && is_email_local_char((unsigned char)buffer[local_start - 1u])) local_start--;
            size_t domain_end = i + 1u;
            while (domain_end < len && is_email_domain_char((unsigned char)buffer[domain_end])) domain_end++;
            bool dot_after_at = false;
            for (size_t p = i + 1u; p < domain_end; p++) if (buffer[p] == '.') dot_after_at = true;
            size_t email_len = domain_end - local_start;
            if (local_start < i && domain_end > i + 1u && dot_after_at && email_len >= 6u && email_len < 255u) {
                char email[256] = {0};
                char pass[256] = {0};
                char value[512] = {0};
                memcpy(email, buffer + local_start, email_len);
                for (size_t p = 0u; p < email_len; p++) email[p] = (char)tolower((unsigned char)email[p]);

                size_t record_end = domain_end;
                if (record_end < len && (buffer[record_end] == ':' || buffer[record_end] == '|' || buffer[record_end] == ';')) {
                    size_t pass_start = record_end + 1u;
                    size_t pass_end = pass_start;
                    while (pass_end < len) {
                        unsigned char c = (unsigned char)buffer[pass_end];
                        if (c <= 0x20u || c >= 0x7fu || c == '|' || c == ';') break;
                        pass_end++;
                    }
                    size_t pass_len = pass_end - pass_start;
                    if (pass_len > 0u && pass_len < sizeof(pass)) {
                        memcpy(pass, buffer + pass_start, pass_len);
                        record_end = pass_end;
                    }
                }

                size_t ctx_start = local_start > 128u ? local_start - 128u : 0u;
                size_t ctx_end = record_end + 128u < len ? record_end + 128u : len;
                qihse_keystone_class_t sem = QIHSE_KEYSTONE_CLASS_UNKNOWN;
                float confidence = 0.0f;
                (void)qihse_keystone_classify_context(buffer + ctx_start, ctx_end - ctx_start, &sem, &confidence);
                uint16_t slot = qihse_cluster_key_slot(email, email_len);
                int written = snprintf(value, sizeof(value), "class=%s|conf=%.2f|slot=%u|pass=%s",
                                       qihse_keystone_class_name(sem), confidence, slot,
                                       pass[0] ? pass : "none");
                if (written > 0 && (size_t)written < sizeof(value) &&
                    persist_artifact(kv, email, value, clearance, compartment, user)) artifacts++;
                qihse_secure_zero(pass, sizeof(pass));
                qihse_secure_zero(value, sizeof(value));
                qihse_secure_zero(email, sizeof(email));
                i = record_end > i ? record_end : i + 1u;
                continue;
            }
        }

        if ((buffer[i] == 'h' || buffer[i] == 'H') && i + 7u < len &&
            (buffer[i + 1u] == 't' || buffer[i + 1u] == 'T') &&
            (buffer[i + 2u] == 't' || buffer[i + 2u] == 'T') &&
            (buffer[i + 3u] == 'p' || buffer[i + 3u] == 'P')) {
            size_t end = i;
            while (end < len && is_url_char((unsigned char)buffer[end])) end++;
            size_t url_len = end - i;
            if (url_len > 8u && url_len < 255u) {
                char url[256] = {0};
                char value[256] = {0};
                memcpy(url, buffer + i, url_len);
                for (size_t p = 0u; p < url_len; p++) url[p] = (char)tolower((unsigned char)url[p]);
                uint16_t slot = qihse_cluster_key_slot(url, url_len);
                int written = snprintf(value, sizeof(value), "class=URL|slot=%u", slot);
                if (written > 0 && (size_t)written < sizeof(value) &&
                    persist_artifact(kv, url, value, clearance, compartment, user)) artifacts++;
                qihse_secure_zero(value, sizeof(value));
                qihse_secure_zero(url, sizeof(url));
                i = end;
                continue;
            }
        }
        i++;
    }
    return artifacts;
}

size_t qihse_keystone_ingest_dirty_logs(qihse_kv_store_t* kv,
                                         qihse_cluster_topology_t* topo,
                                         const char* buffer, size_t len,
                                         uint16_t clearance,
                                         uint16_t compartment) {
    return qihse_keystone_ingest_dirty_logs_user(kv, topo, buffer, len,
                                                  clearance, compartment, NULL);
}

static bool interpolation_probe(const int64_t* arr, size_t low, size_t high,
                                int64_t key, size_t* out) {
    if (!arr || !out || low > high || key < arr[low] || key > arr[high]) return false;
    if (arr[high] == arr[low]) { *out = low; return true; }
    long double num = (long double)key - (long double)arr[low];
    long double den = (long double)arr[high] - (long double)arr[low];
    long double frac = num / den;
    if (frac < 0.0L) frac = 0.0L;
    if (frac > 1.0L) frac = 1.0L;
    size_t span = high - low;
    *out = low + (size_t)(frac * (long double)span);
    if (*out > high) *out = high;
    return true;
}

int64_t qihse_keystone_anchor_search(const int64_t* arr, size_t n, int64_t key) {
    if (!arr || n == 0u) return -1;
    size_t low = 0u, high = n - 1u;
    while (low <= high && key >= arr[low] && key <= arr[high]) {
        size_t probe;
        if (!interpolation_probe(arr, low, high, key, &probe)) break;
        int64_t v = arr[probe];
        if (v == key) return (int64_t)probe;
        if (v < key) {
            if (probe == SIZE_MAX) break;
            low = probe + 1u;
        } else {
            if (probe == 0u) break;
            high = probe - 1u;
        }
    }
    return -1;
}

size_t qihse_keystone_anchor_lower_bound(const int64_t* arr, size_t n, int64_t key) {
    if (!arr || n == 0u) return 0u;
    size_t low = 0u, high = n;
    while (low < high) {
        size_t probe;
        size_t hi_index = high - 1u;
        if (key >= arr[low] && key <= arr[hi_index] &&
            interpolation_probe(arr, low, hi_index, key, &probe)) {
            if (arr[probe] < key) low = probe + 1u;
            else high = probe;
        } else {
            size_t mid = low + (high - low) / 2u;
            if (arr[mid] < key) low = mid + 1u;
            else high = mid;
        }
    }
    return low;
}

size_t qihse_keystone_anchor_upper_bound(const int64_t* arr, size_t n, int64_t key) {
    if (!arr || n == 0u) return 0u;
    size_t low = 0u, high = n;
    while (low < high) {
        size_t probe;
        size_t hi_index = high - 1u;
        if (key >= arr[low] && key <= arr[hi_index] &&
            interpolation_probe(arr, low, hi_index, key, &probe)) {
            if (arr[probe] <= key) low = probe + 1u;
            else high = probe;
        } else {
            size_t mid = low + (high - low) / 2u;
            if (arr[mid] <= key) low = mid + 1u;
            else high = mid;
        }
    }
    return low;
}
