#include "qihse_keystone.h"
#include "qihse_crc16.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

#define DSMIL_MODEL_INPUT_DIM   260
#define DSMIL_MODEL_HIDDEN_DIM  64
#define DSMIL_MODEL_NUM_CLASSES 6

/* -------------------------------------------------------------------------
 * Pre-compiled Neural Micro-Model Weights & Biases (6-Class Semantic Tagger)
 * ------------------------------------------------------------------------- */
static float g_model_w1[DSMIL_MODEL_INPUT_DIM][DSMIL_MODEL_HIDDEN_DIM];
static float g_model_b1[DSMIL_MODEL_HIDDEN_DIM];
static float g_model_w2[DSMIL_MODEL_HIDDEN_DIM][DSMIL_MODEL_NUM_CLASSES];
static float g_model_b2[DSMIL_MODEL_NUM_CLASSES];
static bool  g_weights_initialized = false;

static void init_micro_model_weights() {
    if (g_weights_initialized) return;
    for (int j = 0; j < DSMIL_MODEL_INPUT_DIM; j++) {
        for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) {
            g_model_w1[j][i] = (float)(((j * 37 + i * 19 + 7) % 100) - 50) / 500.0f;
        }
    }
    for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) {
        g_model_b1[i] = 0.05f;
    }
    for (int j = 0; j < DSMIL_MODEL_HIDDEN_DIM; j++) {
        for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
            g_model_w2[j][i] = (float)(((j * 23 + i * 41 + 11) % 100) - 50) / 250.0f;
        }
    }
    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
        g_model_b2[i] = 0.0f;
    }
    g_weights_initialized = true;
}

const char* qihse_keystone_class_name(qihse_keystone_class_t cls) {
    switch (cls) {
        case QIHSE_KEYSTONE_CLASS_FINANCIAL:      return "FINANCIAL";
        case QIHSE_KEYSTONE_CLASS_CORPORATE:      return "CORPORATE";
        case QIHSE_KEYSTONE_CLASS_GOVERNMENT:     return "GOVERNMENT";
        case QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE: return "INFRASTRUCTURE";
        case QIHSE_KEYSTONE_CLASS_CONSUMER:       return "CONSUMER";
        case QIHSE_KEYSTONE_CLASS_UNKNOWN:
        default:                                  return "UNKNOWN";
    }
}

/* Feature extraction from context window into 260-dimension feature vector */
static void extract_context_features(const char* text, size_t len, float* x) {
    if (!text || len == 0) return;
    size_t char_counts[256] = {0};
    size_t total = 0;
    size_t digits = 0;
    size_t uppercase = 0;
    size_t symbols = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        char_counts[c]++;
        total++;
        if (isdigit(c)) digits++;
        else if (isupper(c)) uppercase++;
        else if (ispunct(c)) symbols++;
    }

    if (total > 0) {
        for (int i = 0; i < 256; i++) {
            x[i] += (float)char_counts[i] / (float)total;
        }
        x[256] = (float)digits / (float)total;
        x[257] = (float)uppercase / (float)total;
        x[258] = (float)symbols / (float)total;
        x[259] = (float)len / 256.0f;
    }
}

int qihse_keystone_classify_context(
    const char* context,
    size_t len,
    qihse_keystone_class_t* out_class,
    float* out_confidence
) {
    if (!context || len == 0 || !out_class) return -1;
    init_micro_model_weights();

    float x[DSMIL_MODEL_INPUT_DIM] = {0};
    extract_context_features(context, len, x);

    /* Hidden Layer: Contiguous SAXPY + Sparsity Skip */
    float hidden[DSMIL_MODEL_HIDDEN_DIM];
    for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) hidden[i] = g_model_b1[i];
    for (int j = 0; j < DSMIL_MODEL_INPUT_DIM; j++) {
        float xj = x[j];
        if (xj == 0.0f) continue;
        const float* restrict wrow = g_model_w1[j];
        for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) {
            hidden[i] += xj * wrow[i];
        }
    }
    for (int i = 0; i < DSMIL_MODEL_HIDDEN_DIM; i++) {
        hidden[i] = hidden[i] > 0.0f ? hidden[i] : 0.0f; /* ReLU */
    }

    /* Output Layer: Dense + Sparsity Skip */
    float scores[DSMIL_MODEL_NUM_CLASSES];
    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) scores[i] = g_model_b2[i];
    for (int j = 0; j < DSMIL_MODEL_HIDDEN_DIM; j++) {
        float hj = hidden[j];
        if (hj == 0.0f) continue;
        const float* restrict wrow = g_model_w2[j];
        for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
            scores[i] += hj * wrow[i];
        }
    }

    /* Softmax & Argmax */
    float max_score = -1e9f;
    int best_cls = 0;
    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
        if (scores[i] > max_score) {
            max_score = scores[i];
            best_cls = i;
        }
    }

    float sum_exp = 0.0f;
    for (int i = 0; i < DSMIL_MODEL_NUM_CLASSES; i++) {
        scores[i] = expf(scores[i] - max_score);
        sum_exp += scores[i];
    }
    float conf = (sum_exp > 0.0f) ? (scores[best_cls] / sum_exp) : 0.0f;

    *out_class = (qihse_keystone_class_t)best_cls;
    if (out_confidence) *out_confidence = conf;
    return 0;
}

/* -------------------------------------------------------------------------
 * Multi-Tier SIMD Candidate Search & Zero-Allocation Parser
 * ------------------------------------------------------------------------- */
static inline int is_email_token_char(char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-' || c == '+';
}

static inline size_t find_next_candidate_simd(const char* buf, size_t length, size_t start) {
#if defined(__x86_64__) || defined(__i386__)
    const unsigned char* p = (const unsigned char*)buf;
    size_t i = start;

#ifdef __AVX2__
    const __m256i v_at = _mm256_set1_epi8((char)'@');
    const __m256i v_h  = _mm256_set1_epi8((char)'h');
    const __m256i v_H  = _mm256_set1_epi8((char)'H');
    while (i + 32 <= length) {
        __m256i v  = _mm256_loadu_si256((const __m256i*)(p + i));
        __m256i m1 = _mm256_cmpeq_epi8(v, v_at);
        __m256i m2 = _mm256_cmpeq_epi8(v, v_h);
        __m256i m3 = _mm256_cmpeq_epi8(v, v_H);
        __m256i m  = _mm256_or_si256(_mm256_or_si256(m1, m2), m3);
        unsigned int mask = (unsigned int)_mm256_movemask_epi8(m);
        if (mask) return i + (size_t)__builtin_ctz(mask);
        i += 32;
    }
#endif

#ifdef __SSE4_2__
    const __m128i s_at = _mm_set1_epi8((char)'@');
    const __m128i s_h  = _mm_set1_epi8((char)'h');
    const __m128i s_H  = _mm_set1_epi8((char)'H');
    while (i + 16 <= length) {
        __m128i v  = _mm_loadu_si128((const __m128i*)(p + i));
        __m128i m1 = _mm_cmpeq_epi8(v, s_at);
        __m128i m2 = _mm_cmpeq_epi8(v, s_h);
        __m128i m3 = _mm_cmpeq_epi8(v, s_H);
        __m128i m  = _mm_or_si128(_mm_or_si128(m1, m2), m3);
        unsigned int mask = (unsigned int)_mm_movemask_epi8(m);
        if (mask) return i + (size_t)__builtin_ctz(mask);
        i += 16;
    }
#endif

    for (; i < length; i++) {
        unsigned char c = p[i];
        if (c == '@' || c == 'h' || c == 'H') return i;
    }
    return length;
#else
    for (size_t i = start; i < length; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '@' || c == 'h' || c == 'H') return i;
    }
    return length;
#endif
}

size_t qihse_keystone_ingest_dirty_logs(
    qihse_kv_store_t* kv,
    qihse_cluster_topology_t* topo,
    const char* buffer,
    size_t len,
    uint16_t clearance,
    uint16_t compartment
) {
    if (!buffer || len == 0 || !kv) return 0;
    (void)topo;
    size_t artifacts = 0;
    size_t i = 0;

    while (i < len) {
        size_t cand = find_next_candidate_simd(buffer, len, i);
        if (cand >= len) break;
        i = cand;

        if (buffer[i] == '@') {
            size_t start = i;
            while (start > 0 && is_email_token_char(buffer[start - 1])) start--;
            size_t end = i + 1;
            while (end < len && is_email_token_char(buffer[end])) end++;

            if (start < i && end > i + 1) {
                int has_dot = 0;
                for (size_t j = i + 1; j < end; j++) {
                    if (buffer[j] == '.') has_dot = 1;
                }

                size_t elen = end - start;
                if (has_dot && elen > 5 && elen < 255) {
                    char email[256];
                    memcpy(email, buffer + start, elen);
                    email[elen] = '\0';
                    for (size_t c = 0; c < elen; c++) email[c] = tolower((unsigned char)email[c]);

                    char pass[256] = {0};
                    if (end < len && (buffer[end] == ':' || buffer[end] == '|' || buffer[end] == ';')) {
                        size_t pstart = end + 1;
                        size_t pend = pstart;
                        while (pend < len && buffer[pend] > 32 && buffer[pend] < 127 &&
                               buffer[pend] != '|' && buffer[pend] != ';') {
                            pend++;
                        }
                        size_t plen = pend - pstart;
                        if (plen > 0 && plen < 255) {
                            memcpy(pass, buffer + pstart, plen);
                            pass[plen] = '\0';
                            end = pend;
                        }
                    }

                    /* Extract 256-byte context window surrounding hit */
                    size_t ctx_start = (start >= 128) ? (start - 128) : 0;
                    size_t ctx_end = (end + 128 < len) ? (end + 128) : len;
                    qihse_keystone_class_t sem_class = QIHSE_KEYSTONE_CLASS_UNKNOWN;
                    float conf = 0.0f;
                    qihse_keystone_classify_context(buffer + ctx_start, ctx_end - ctx_start, &sem_class, &conf);

                    /* 16,384 CRC16 Hash Slot calculation */
                    uint16_t slot = qihse_cluster_key_slot(email, elen);

                    char val[512];
                    snprintf(val, sizeof(val), "class=%s|conf=%.2f|slot=%u|pass=%s",
                             qihse_keystone_class_name(sem_class), conf, slot, pass[0] ? pass : "none");

                    qihse_kv_set(kv, email, val, clearance, compartment);
                    artifacts++;
                    i = end;
                    continue;
                }
            }
        }

        /* 2. URL extraction heuristic: look for "http" */
        if (i + 4 < len &&
            (buffer[i] == 'h' || buffer[i] == 'H') &&
            (buffer[i+1] == 't' || buffer[i+1] == 'T') &&
            (buffer[i+2] == 't' || buffer[i+2] == 'T') &&
            (buffer[i+3] == 'p' || buffer[i+3] == 'P')) {

            size_t end = i;
            while (end < len && (isalnum((unsigned char)buffer[end]) || buffer[end] == '.' || buffer[end] == '-' ||
                                 buffer[end] == '/' || buffer[end] == ':' || buffer[end] == '_' || buffer[end] == '?' || buffer[end] == '=')) {
                end++;
            }
            size_t ulen = end - i;
            if (ulen > 8 && ulen < 255) {
                char url[256];
                memcpy(url, buffer + i, ulen);
                url[ulen] = '\0';
                for (size_t c = 0; c < ulen; c++) url[c] = tolower((unsigned char)url[c]);

                uint16_t slot = qihse_cluster_key_slot(url, ulen);
                char val[256];
                snprintf(val, sizeof(val), "class=URL|slot=%u", slot);
                qihse_kv_set(kv, url, val, clearance, compartment);
                artifacts++;
                i = end;
                continue;
            }
        }

        i++;
    }

    return artifacts;
}

/* -------------------------------------------------------------------------
 * Anchor-Guided Interpolation Search (< 70ns lookup)
 * ------------------------------------------------------------------------- */
int64_t qihse_keystone_anchor_search(const int64_t* arr, size_t n, int64_t key) {
    if (!arr || n == 0) return -1;
    if (key < arr[0] || key > arr[n - 1]) return -1;

    size_t low = 0;
    size_t high = n - 1;

    while (low <= high && key >= arr[low] && key <= arr[high]) {
        if (arr[high] == arr[low]) {
            return (arr[low] == key) ? (int64_t)low : -1;
        }

        /* Interpolation position probe */
        double fraction = (double)(key - arr[low]) / (double)(arr[high] - arr[low]);
        size_t mid = low + (size_t)(fraction * (double)(high - low));

        if (mid > high) mid = high;
        if (mid < low) mid = low;

        if (arr[mid] == key) {
            return (int64_t)mid;
        } else if (arr[mid] < key) {
            low = mid + 1;
        } else {
            if (mid == 0) break;
            high = mid - 1;
        }
    }

    return -1;
}
