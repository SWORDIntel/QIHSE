#include "qihse_keystone.h"
#include "qihse_crc16.h"
#include "qihse_audit.h"

#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    if (!ptr || len == 0u) return;
#if defined(__GLIBC__)
    /* explicit_bzero is guaranteed not to be optimized away and uses a
     * vectorized wipe instead of a byte-at-a-time volatile store loop. */
    explicit_bzero(ptr, len);
#else
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0u;
#endif
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

/* ═══════════════════════════════════════════════════════════════════════════
 * W2.5 — KEYSTONE change feed: read/index identity, resumable consumption.
 *
 * KEYSTONE follows the F2 federation journal to keep its index current. It
 * does so as a narrow identity (see qihse_keystone.h): a tenant-scoped ANALYST
 * with a clearance/SCI ceiling, holding FEDERATION_READ only. The consumer
 * filters every record against that identity at delivery time, so the cursor
 * position is never what decides whether a record is disclosed.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Feed record codec ─────────────────────────────────────────────────── */

static void ks_feed_put_u16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void ks_feed_put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void ks_feed_put_u64(uint8_t* p, uint64_t v) {
    for (unsigned i = 0; i < 8u; i++) p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
}

static uint16_t ks_feed_get_u16(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t ks_feed_get_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t ks_feed_get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; i++) v |= (uint64_t)p[i] << (8u * i);
    return v;
}

bool qihse_keystone_feed_encode(const qihse_keystone_feed_record_t* record,
                                const void* payload, size_t payload_len,
                                uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!record || !out) return false;
    if (payload_len > QIHSE_KEYSTONE_FEED_MAX_PAYLOAD) return false;
    if (payload_len > 0u && !payload) return false;
    if (out_cap < QIHSE_KEYSTONE_FEED_HEADER_BYTES) return false;
    if (out_cap - QIHSE_KEYSTONE_FEED_HEADER_BYTES < payload_len) return false;

    memset(out, 0, QIHSE_KEYSTONE_FEED_HEADER_BYTES);
    ks_feed_put_u32(out + 0u, QIHSE_KEYSTONE_FEED_MAGIC);
    ks_feed_put_u16(out + 4u, QIHSE_KEYSTONE_FEED_RECORD_VERSION);
    ks_feed_put_u16(out + 6u, record->flags);
    ks_feed_put_u16(out + 8u, record->classification);
    ks_feed_put_u16(out + 10u, record->sci);
    ks_feed_put_u64(out + 16u, record->generation);
    ks_feed_put_u32(out + 24u, record->tenant_id);
    ks_feed_put_u32(out + 28u, (uint32_t)payload_len);
    memcpy(out + 32u, record->object_id.bytes, QIHSE_UUID_BYTES);
    ks_feed_put_u64(out + 48u, record->hlc.physical_ms);
    ks_feed_put_u32(out + 56u, record->hlc.logical);
    if (payload_len > 0u) memcpy(out + QIHSE_KEYSTONE_FEED_HEADER_BYTES, payload, payload_len);
    if (out_len) *out_len = QIHSE_KEYSTONE_FEED_HEADER_BYTES + payload_len;
    return true;
}

bool qihse_keystone_feed_decode(const uint8_t* payload, size_t payload_len,
                                qihse_keystone_feed_record_t* out_record,
                                const uint8_t** out_body, size_t* out_body_len) {
    if (!payload || !out_record) return false;
    if (payload_len < QIHSE_KEYSTONE_FEED_HEADER_BYTES) return false;
    if (ks_feed_get_u32(payload) != QIHSE_KEYSTONE_FEED_MAGIC) return false;
    if (ks_feed_get_u16(payload + 4u) != QIHSE_KEYSTONE_FEED_RECORD_VERSION) return false;

    uint32_t declared = ks_feed_get_u32(payload + 28u);
    /* Validate the declared length against BOTH the encoded length and the
     * algorithm's fixed header size (AGENTS.md federation-decoder rule 3): a
     * record whose header disagrees with its framing is malformed, and a
     * malformed record is never delivered. */
    if ((size_t)declared > QIHSE_KEYSTONE_FEED_MAX_PAYLOAD) return false;
    if (payload_len - QIHSE_KEYSTONE_FEED_HEADER_BYTES != (size_t)declared) return false;

    memset(out_record, 0, sizeof(*out_record));
    out_record->flags = ks_feed_get_u16(payload + 6u);
    out_record->classification = ks_feed_get_u16(payload + 8u);
    out_record->sci = ks_feed_get_u16(payload + 10u);
    out_record->generation = ks_feed_get_u64(payload + 16u);
    out_record->tenant_id = ks_feed_get_u32(payload + 24u);
    memcpy(out_record->object_id.bytes, payload + 32u, QIHSE_UUID_BYTES);
    out_record->hlc.physical_ms = ks_feed_get_u64(payload + 48u);
    out_record->hlc.logical = ks_feed_get_u32(payload + 56u);
    if (out_body) *out_body = payload + QIHSE_KEYSTONE_FEED_HEADER_BYTES;
    if (out_body_len) *out_body_len = (size_t)declared;
    return true;
}

/* ── The read/index identity ───────────────────────────────────────────── */

#define QIHSE_KEYSTONE_FEED_MAX_IDENTITIES 8u

typedef struct {
    bool used;
    uint32_t user_id;
    uint32_t tenant_id;
} ks_feed_binding_t;

/* Bindings live in process, alongside the auth table they refer to: a
 * principal only exists as a user record for the lifetime of the process, so a
 * binding outliving it would name nobody. The binding is re-validated against
 * the authoritative auth state on every use. */
static ks_feed_binding_t g_ks_feed_bindings[QIHSE_KEYSTONE_FEED_MAX_IDENTITIES];
static pthread_mutex_t g_ks_feed_binding_lock = PTHREAD_MUTEX_INITIALIZER;

static bool ks_feed_binding_find(uint32_t user_id, uint32_t* out_tenant) {
    bool found = false;
    pthread_mutex_lock(&g_ks_feed_binding_lock);
    for (size_t i = 0; i < QIHSE_KEYSTONE_FEED_MAX_IDENTITIES; i++) {
        if (g_ks_feed_bindings[i].used && g_ks_feed_bindings[i].user_id == user_id) {
            if (out_tenant) *out_tenant = g_ks_feed_bindings[i].tenant_id;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ks_feed_binding_lock);
    return found;
}

static bool ks_feed_binding_add(uint32_t user_id, uint32_t tenant_id) {
    bool added = false;
    pthread_mutex_lock(&g_ks_feed_binding_lock);
    for (size_t i = 0; i < QIHSE_KEYSTONE_FEED_MAX_IDENTITIES; i++) {
        if (!g_ks_feed_bindings[i].used) {
            g_ks_feed_bindings[i].used = true;
            g_ks_feed_bindings[i].user_id = user_id;
            g_ks_feed_bindings[i].tenant_id = tenant_id;
            added = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ks_feed_binding_lock);
    return added;
}

static bool ks_feed_binding_drop(uint32_t user_id) {
    bool dropped = false;
    pthread_mutex_lock(&g_ks_feed_binding_lock);
    for (size_t i = 0; i < QIHSE_KEYSTONE_FEED_MAX_IDENTITIES; i++) {
        if (g_ks_feed_bindings[i].used && g_ks_feed_bindings[i].user_id == user_id) {
            memset(&g_ks_feed_bindings[i], 0, sizeof(g_ks_feed_bindings[i]));
            dropped = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ks_feed_binding_lock);
    return dropped;
}

bool qihse_keystone_feed_identity_is_indexer(const qihse_user_t* user) {
    if (!user) return false;
    /* Revocation is honored on the next call: a destroyed principal is not an
     * index identity, and neither is a promoted one. */
    if (!qihse_auth_user_is_active(user)) return false;
    if (qihse_user_get_role(user) != QIHSE_ROLE_ANALYST) return false;
    uint32_t tenant = qihse_user_get_tenant_id(user);
    if (tenant == QIHSE_TENANT_SYSTEM) return false;
    uint32_t bound_tenant = 0;
    if (!ks_feed_binding_find(qihse_user_get_id(user), &bound_tenant)) return false;
    return bound_tenant == tenant;
}

qihse_user_t* qihse_keystone_feed_identity_provision(const qihse_user_t* creator,
                                                     uint32_t tenant_id,
                                                     uint32_t user_id,
                                                     uint16_t clearance,
                                                     uint16_t sci,
                                                     const char* plaintext_password) {
    if (!creator || !plaintext_password) return NULL;
    /* The system domain is the administrative domain here: FEDERATION.*,
     * CLUSTER MOVESLOTS, GROUP.*, FABRIC.* and METRICS.RENDER are all gated on
     * it. An index identity is never one of those. */
    if (tenant_id == QIHSE_TENANT_SYSTEM) {
        qihse_audit_log("KEYSTONE_FEED_IDENTITY_DENIED_SYSTEM_DOMAIN", user_id, 0u, clearance, sci);
        return NULL;
    }
    if (!qihse_auth_user_is_active(creator)) return NULL;
    /* Invariant 2: no principal may create or promote another above itself.
     * Checked before anything is created, so a delegated creator is refused
     * outright instead of leaving a floored GUEST principal behind.
     * create_user_internal() floors every non-operator creation to GUEST with
     * no clearance, so a delegated creator can never mint an ANALYST index
     * identity; this pre-flight surfaces that as a refusal. */
    if (qihse_user_get_role(creator) != QIHSE_ROLE_OPERATOR) {
        qihse_audit_log("KEYSTONE_FEED_IDENTITY_DENIED_LADDER", user_id, 0u, clearance, sci);
        return NULL;
    }
    if (clearance > qihse_user_get_classification(creator) ||
        (sci & qihse_user_get_sci(creator)) != sci) {
        qihse_audit_log("KEYSTONE_FEED_IDENTITY_DENIED_CLEARANCE", user_id, 0u, clearance, sci);
        return NULL;
    }

    qihse_user_t* indexer = qihse_auth_create_tenant_user(creator, tenant_id, user_id,
                                                          QIHSE_ROLE_ANALYST, clearance, sci,
                                                          plaintext_password, false);
    if (!indexer) return NULL;

    /* Post-conditions: the created principal must be exactly what was asked
     * for. A floored role, a widened clearance, a different tenant or a
     * delegation flag means the ladder changed under us — destroy it rather
     * than bind something weaker or stronger than intended. */
    if (qihse_user_get_role(indexer) != QIHSE_ROLE_ANALYST ||
        qihse_user_get_classification(indexer) != clearance ||
        qihse_user_get_sci(indexer) != sci ||
        qihse_user_get_tenant_id(indexer) != tenant_id ||
        qihse_user_can_create_users(indexer)) {
        (void)qihse_auth_destroy_user(creator, user_id);
        qihse_audit_log("KEYSTONE_FEED_IDENTITY_DENIED_POSTCONDITION", user_id, 0u, clearance, sci);
        return NULL;
    }

    /* Name it so the audit trail says what it is. The user id keeps the name
     * unique: a second index identity must not shadow the first in the name
     * map that AUTH resolves against. */
    char name[QIHSE_AUTH_USERNAME_MAX];
    int written = snprintf(name, sizeof(name), "keystone-indexer-%u", user_id);
    if (written <= 0 || (size_t)written >= sizeof(name) ||
        !qihse_auth_modify_user(creator, user_id, name, NULL, -1, -1, -1, -1)) {
        (void)qihse_auth_destroy_user(creator, user_id);
        return NULL;
    }

    if (!ks_feed_binding_add(user_id, tenant_id)) {
        (void)qihse_auth_destroy_user(creator, user_id);
        return NULL;
    }
    qihse_audit_log("KEYSTONE_FEED_IDENTITY_PROVISION", user_id, tenant_id, clearance, sci);
    return indexer;
}

bool qihse_keystone_feed_identity_revoke(const qihse_user_t* actor, uint32_t user_id) {
    if (!actor) return false;
    if (!qihse_auth_user_is_active(actor)) return false;
    if (qihse_user_get_role(actor) != QIHSE_ROLE_OPERATOR) return false;
    bool dropped = ks_feed_binding_drop(user_id);
    qihse_audit_log("KEYSTONE_FEED_IDENTITY_REVOKE", user_id, dropped ? 1u : 0u, 0u, 0u);
    return dropped;
}

/* ── Publishing ────────────────────────────────────────────────────────── */

bool qihse_keystone_feed_publish(qihse_federation_journal_t* journal,
                                 const qihse_user_t* publisher,
                                 const qihse_uuid_t* origin_node,
                                 const char* event_type,
                                 const char* resource_id,
                                 const qihse_keystone_feed_record_t* record,
                                 const void* payload, size_t payload_len,
                                 qihse_federation_event_t* out_event) {
    if (!journal || !publisher || !origin_node || !record || !event_type) return false;
    if (payload_len > QIHSE_KEYSTONE_FEED_MAX_PAYLOAD) return false;
    if (payload_len > 0u && !payload) return false;
    if (!qihse_auth_user_is_active(publisher)) return false;
    /* The write half of the feed is a federation control-plane operation. The
     * index identity holds FEDERATION_READ only, so this is where its write
     * denial is enforced. */
    if (!qihse_infra_scope_check((void*)publisher, QIHSE_SCOPE_FEDERATION_WRITE)) return false;
    /* A publisher may not stamp a record above its own clearance/SCI, nor
     * place it in another tenant's stream. */
    uint32_t publisher_tenant = qihse_user_get_tenant_id(publisher);
    if (publisher_tenant != QIHSE_TENANT_SYSTEM && record->tenant_id != publisher_tenant) return false;
    if (!qihse_auth_can_access(publisher, record->classification, record->sci)) return false;

    bool ok = false;
    uint8_t* buf = (uint8_t*)malloc(QIHSE_KEYSTONE_FEED_HEADER_BYTES + payload_len);
    if (!buf) return false;
    size_t encoded = 0;
    if (!qihse_keystone_feed_encode(record, payload, payload_len, buf,
                                    QIHSE_KEYSTONE_FEED_HEADER_BYTES + payload_len, &encoded)) {
        goto done;
    }

    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    m.origin_node = *origin_node;
    /* Attribution: the principal is derived from the authenticated user id,
     * never supplied by the caller. */
    uint32_t uid = qihse_user_get_id(publisher);
    if (uid == UINT32_MAX) goto done;
    if (!qihse_uuid_from_seed(&uid, sizeof(uid), &m.principal_id)) goto done;
    m.consistency = QIHSE_CONSISTENCY_LOCAL;
    if (qihse_federation_journal_append(journal, &m, event_type, resource_id,
                                        buf, encoded, out_event) == 0) {
        goto done;
    }
    ok = true;
done:
    free(buf);
    return ok;
}

/* ── Resumable consumption ─────────────────────────────────────────────── */

struct qihse_keystone_feed {
    qihse_federation_journal_t* journal; /* borrowed: the server owns it */
    qihse_federation_watch_t* watch;
    qihse_user_t* reader;      /* borrowed: the session owns the principal */
    uint32_t reader_id;
    uint32_t tenant_id;
    bool system_reader;        /* operator: tenant filter does not apply */
    size_t max_payload_bytes;
    uint64_t cursor;
    size_t denied;
    size_t malformed;
};

static bool ks_feed_reader_allowed(const qihse_user_t* reader) {
    if (!reader) return false;
    if (qihse_keystone_feed_identity_is_indexer(reader)) return true;
    /* The operator may inspect the feed for administration; it is not the
     * index identity and already holds every scope. */
    return qihse_auth_user_is_active(reader) &&
           qihse_user_get_role(reader) == QIHSE_ROLE_OPERATOR;
}

static const char* ks_feed_reader_kind(const qihse_user_t* reader) {
    if (qihse_keystone_feed_identity_is_indexer(reader)) return "keystone-indexer";
    if (reader && qihse_user_get_role(reader) == QIHSE_ROLE_OPERATOR) return "operator";
    return "none"; /* revoked or unknown: no cursor is meaningful for it */
}

qihse_keystone_feed_t* qihse_keystone_feed_open(qihse_federation_journal_t* journal,
                                                const qihse_user_t* reader,
                                                const qihse_keystone_feed_config_t* config) {
    /* NULL is an argument error, never an authorization bypass. */
    if (!journal || !reader) return NULL;
    if (!ks_feed_reader_allowed(reader)) return NULL;

    qihse_keystone_feed_t* feed = (qihse_keystone_feed_t*)calloc(1, sizeof(*feed));
    if (!feed) return NULL;

    qihse_federation_watch_config_t wcfg;
    memset(&wcfg, 0, sizeof(wcfg));
    if (config) {
        snprintf(wcfg.prefix, sizeof(wcfg.prefix), "%s", config->prefix);
        wcfg.cursor = config->cursor;
        feed->max_payload_bytes = config->max_payload_bytes;
    }
    if (feed->max_payload_bytes == 0u) feed->max_payload_bytes = QIHSE_KEYSTONE_FEED_MAX_PAYLOAD;
    if (feed->max_payload_bytes > QIHSE_KEYSTONE_FEED_MAX_PAYLOAD) {
        feed->max_payload_bytes = QIHSE_KEYSTONE_FEED_MAX_PAYLOAD;
    }
    wcfg.backlog_limit = 1024;

    feed->watch = qihse_federation_watch_open(journal, &wcfg);
    if (!feed->watch) {
        free(feed);
        return NULL;
    }
    feed->journal = journal;
    feed->reader = (qihse_user_t*)reader;
    feed->reader_id = qihse_user_get_id(reader);
    feed->tenant_id = qihse_user_get_tenant_id(reader);
    feed->system_reader = qihse_user_get_role(reader) == QIHSE_ROLE_OPERATOR;
    feed->cursor = qihse_federation_watch_cursor(feed->watch);
    return feed;
}

void qihse_keystone_feed_close(qihse_keystone_feed_t* feed) {
    if (!feed) return;
    if (feed->watch) qihse_federation_watch_destroy(feed->watch);
    free(feed);
}

bool qihse_keystone_feed_next(qihse_keystone_feed_t* feed,
                              qihse_federation_event_t* out_event,
                              qihse_keystone_feed_record_t* out_record,
                              uint8_t** out_payload, size_t* out_payload_len) {
    if (!feed || !out_event || !out_record) return false;
    if (out_payload) *out_payload = NULL;
    if (out_payload_len) *out_payload_len = 0;
    /* Revocation is honored on the next record, not only on the next open: a
     * handle that was legitimate when it was opened must not keep reading
     * after the principal stops being a reader (revoked binding, promotion or
     * destruction). */
    if (!ks_feed_reader_allowed(feed->reader)) return false;

    for (;;) {
        qihse_federation_event_t ev;
        uint8_t* raw = NULL;
        size_t raw_len = 0;
        if (!qihse_federation_watch_next(feed->watch, &ev, &raw, &raw_len)) {
            feed->cursor = qihse_federation_watch_cursor(feed->watch);
            return false;
        }

        qihse_keystone_feed_record_t rec;
        const uint8_t* body = NULL;
        size_t body_len = 0;
        if (!qihse_keystone_feed_decode(raw, raw_len, &rec, &body, &body_len)) {
            /* Fail closed: a record that does not parse is not delivered, not
             * even as metadata. It is counted so an operator can see it. */
            feed->malformed++;
            free(raw);
            continue;
        }

        /* Clearance/SCI/tenant decision, made per record at delivery time.
         * Nothing about the cursor can change this answer, so rewind, replay
         * and cursor transplant cannot disclose a denied record. */
        bool cleared = feed->system_reader || rec.tenant_id == feed->tenant_id;
        if (cleared && !qihse_auth_can_access(feed->reader, rec.classification, rec.sci)) cleared = false;
        if (cleared && body_len > feed->max_payload_bytes) cleared = false;
        if (!cleared) {
            feed->denied++;
            free(raw);
            continue;
        }

        uint8_t* copy = NULL;
        if (body_len > 0u) {
            copy = (uint8_t*)malloc(body_len);
            if (!copy) {
                free(raw);
                return false;
            }
            memcpy(copy, body, body_len);
        }
        /* The journal is the time authority: a record that carries no stamp of
         * its own inherits the envelope's causal stamp rather than being
         * indexed with a zero timestamp. */
        if (rec.hlc.physical_ms == 0u && rec.hlc.logical == 0u) {
            rec.hlc = ev.mutation.hlc;
        }
        *out_event = ev;
        *out_record = rec;
        if (out_payload && out_payload_len) {
            *out_payload = copy;
            *out_payload_len = body_len;
        } else {
            free(copy);
        }
        feed->cursor = qihse_federation_watch_cursor(feed->watch);
        free(raw);
        return true;
    }
}

bool qihse_keystone_feed_ack(qihse_keystone_feed_t* feed, uint64_t offset) {
    if (!feed || !feed->watch) return false;
    return qihse_federation_watch_ack(feed->watch, offset);
}

bool qihse_keystone_feed_resume(qihse_keystone_feed_t* feed, uint64_t cursor) {
    if (!feed || !feed->watch || !feed->journal) return false;
    /* A cursor beyond the end of the journal is not a position the reader ever
     * occupied; refuse it rather than pretending it is a resume point. */
    if (cursor > qihse_federation_journal_length(feed->journal)) return false;
    if (!qihse_federation_watch_resume(feed->watch, cursor)) return false;
    feed->cursor = cursor;
    return true;
}

uint64_t qihse_keystone_feed_cursor(const qihse_keystone_feed_t* feed) {
    return feed ? feed->cursor : 0u;
}

uint64_t qihse_keystone_feed_last_ack(const qihse_keystone_feed_t* feed) {
    return (feed && feed->watch) ? qihse_federation_watch_last_ack(feed->watch) : 0u;
}

size_t qihse_keystone_feed_denied(const qihse_keystone_feed_t* feed) {
    return feed ? feed->denied : 0u;
}

size_t qihse_keystone_feed_malformed(const qihse_keystone_feed_t* feed) {
    return feed ? feed->malformed : 0u;
}

/* ── Cursor persistence, bound to the identity that minted it ──────────── */

#define QIHSE_KEYSTONE_FEED_CURSOR_PATH_MAX 1024u
#define QIHSE_KEYSTONE_FEED_CURSOR_MAGIC "QIHSE-KEYSTONE-FEED-CURSOR 1"

bool qihse_keystone_feed_cursor_save(const qihse_keystone_feed_t* feed, const char* path) {
    if (!feed || !path || path[0] == '\0') return false;
    /* A cursor is only ever minted for a principal that is still a reader; a
     * revoked identity must not be handed a resume point. */
    if (!ks_feed_reader_allowed(feed->reader)) return false;
    size_t path_len = strlen(path);
    if (path_len >= QIHSE_KEYSTONE_FEED_CURSOR_PATH_MAX) return false;

    char text[320];
    int written = snprintf(text, sizeof(text),
                           QIHSE_KEYSTONE_FEED_CURSOR_MAGIC "\n"
                           "principal %u\n"
                           "tenant %u\n"
                           "kind %s\n"
                           "cursor %llu\n"
                           "last_ack %llu\n",
                           feed->reader_id, feed->tenant_id,
                           ks_feed_reader_kind(feed->reader),
                           (unsigned long long)feed->cursor,
                           (unsigned long long)qihse_keystone_feed_last_ack(feed));
    if (written <= 0 || (size_t)written >= sizeof(text)) return false;

    char tmp_path[QIHSE_KEYSTONE_FEED_CURSOR_PATH_MAX + 8u];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp_path)) return false;

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = write(fd, text, (size_t)written) == (ssize_t)written;
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok) {
        unlink(tmp_path);
        return false;
    }
    /* Atomic replace: a crash mid-save leaves the previous cursor intact
     * rather than a truncated one, so resume never loses its place. */
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return false;
    }
    return true;
}

bool qihse_keystone_feed_cursor_load(const qihse_user_t* reader, const char* path,
                                     uint64_t* out_cursor) {
    if (!reader || !path || !out_cursor) return false;
    if (!ks_feed_reader_allowed(reader)) return false;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    char text[512];
    ssize_t n = read(fd, text, sizeof(text) - 1u);
    close(fd);
    if (n <= 0) return false;
    text[n] = '\0';

    bool header_ok = false;
    bool have_cursor = false;
    bool have_kind = false;
    uint32_t file_principal = UINT32_MAX;
    char kind[64] = {0};
    uint64_t file_cursor = 0;

    char* save = NULL;
    for (char* line = strtok_r(text, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
        unsigned long long value = 0;
        if (strcmp(line, QIHSE_KEYSTONE_FEED_CURSOR_MAGIC) == 0) {
            header_ok = true;
        } else if (sscanf(line, "principal %llu", &value) == 1) {
            file_principal = (uint32_t)value;
        } else if (sscanf(line, "kind %63s", kind) == 1) {
            have_kind = true;
        } else if (sscanf(line, "cursor %llu", &value) == 1) {
            file_cursor = (uint64_t)value;
            have_cursor = true;
        }
    }
    if (!header_ok || !have_cursor || !have_kind) return false;
    /* The cursor is not a bearer token: it is only meaningful for the
     * principal that minted it. A cursor written by a wider identity is
     * refused here, and the per-record clearance filter would refuse the
     * records anyway. */
    if (file_principal != qihse_user_get_id(reader)) return false;
    if (strcmp(kind, ks_feed_reader_kind(reader)) != 0) return false;
    *out_cursor = file_cursor;
    return true;
}
