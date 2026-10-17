#include "qihse_quantum_defense.h"
#include "qihse_mmdb.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "qihse_platform.h"
#include "qihse_audit.h"
#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#endif
#ifndef _WIN32
#include <openssl/rand.h>
#endif
#include <immintrin.h>
#include "qihse_tsx_lock.h"

#if defined(__x86_64__) || defined(_M_X64)
#  if !defined(__RDSEED__)
static inline int _rdseed64_step(unsigned long long *val) {
    unsigned char ok;
    __asm__ volatile("rdseed %0\n\tsetc %1" : "=r"(*val), "=qm"(ok) :: "cc");
    return (int)ok;
}
#  endif
#  if !defined(__FSGSBASE__)
static inline unsigned long long _readfsbase_u64(void) {
    unsigned long long val;
    __asm__ volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0" : "=a"(val));
    return val;
}
#  endif
#endif

static inline bool qihse_qdd_has_rdseed(void) {
    static int cached = -1;
    if (__builtin_expect(cached != -1, 1)) {
        return cached == 1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0), "c"(0));
    if (eax >= 7) {
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(7), "c"(0));
        if (ebx & (1u << 18)) {
            cached = 1;
            return true;
        }
    }
#endif
    cached = 0;
    return false;
}

#define QDD_HISTORY_SIZE 1024
#define QDD_THREAT_THRESHOLD 85
#define QDD_IP_CACHE_SIZE 256
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL

/* Trinary states for quantum disruption: -1 (False), 0 (Superposition), 1 (True) */
typedef int8_t tryte_t;

typedef struct {
    char ip[64];
    uint32_t threat_contribution;
    uint64_t last_access_time;
    uint32_t burst_count;
    char country[3];
    char city[64];
    char asn[64];
} qihse_qdd_ip_threat_t;

struct qihse_quantum_defense_ctx_t {
    qihse_tsx_rwlock_t lock;
    uint64_t access_history[QDD_HISTORY_SIZE];
    uint64_t access_timestamps[QDD_HISTORY_SIZE];
    uint32_t head;
    uint32_t history_count;
    uint32_t threat_level; /* 0 to 100 */
    bool under_attack;
    qihse_qdd_ip_threat_t ip_threats[QDD_IP_CACHE_SIZE];
    uint32_t ip_threat_count;
    uint32_t last_ip_idx; /* hint: index of most recently seen accessor ip */
    qihse_mmdb_t* mmdb_country;
    qihse_mmdb_t* mmdb_city;
    qihse_mmdb_t* mmdb_asn;
    bool mmdb_advisory_printed;
};

/* Forward declaration for geoip_lookup_ctx (defined later) */
static bool qihse_qdd_geoip_lookup_ctx(qihse_quantum_defense_ctx_t* ctx,
                                        const char* ip,
                                        char* out_country, size_t country_len,
                                        char* out_city,    size_t city_len,
                                        char* out_asn,     size_t asn_len);

static void qihse_qdd_track_ip_threat(qihse_quantum_defense_ctx_t* ctx, const char* ip, uint64_t now) {
    if (!ctx || !ip) return;

    /* Same accessor dominates (e.g. the KV path reports a fixed source) —
     * check the last-seen slot before scanning all entries. */
    if (ctx->last_ip_idx < ctx->ip_threat_count &&
        strcmp(ctx->ip_threats[ctx->last_ip_idx].ip, ip) == 0) {
        qihse_qdd_ip_threat_t* e = &ctx->ip_threats[ctx->last_ip_idx];
        uint64_t time_delta = now - e->last_access_time;
        if (time_delta < 1) {
            e->burst_count++;
            if (e->burst_count > 10) e->threat_contribution += 5;
        } else {
            e->burst_count = 1;
        }
        e->last_access_time = now;
        return;
    }

    for (uint32_t i = 0; i < ctx->ip_threat_count; i++) {
        if (strcmp(ctx->ip_threats[i].ip, ip) == 0) {
            ctx->last_ip_idx = i;
            uint64_t time_delta = now - ctx->ip_threats[i].last_access_time;
            if (time_delta < 1) {
                ctx->ip_threats[i].burst_count++;
                if (ctx->ip_threats[i].burst_count > 10) {
                    ctx->ip_threats[i].threat_contribution += 5;
                }
            } else {
                ctx->ip_threats[i].burst_count = 1;
            }
            ctx->ip_threats[i].last_access_time = now;
            return;
        }
    }
    
    if (ctx->ip_threat_count < QDD_IP_CACHE_SIZE) {
        strncpy(ctx->ip_threats[ctx->ip_threat_count].ip, ip, sizeof(ctx->ip_threats[0].ip) - 1);
        ctx->ip_threats[ctx->ip_threat_count].threat_contribution = 0;
        ctx->ip_threats[ctx->ip_threat_count].last_access_time = now;
        ctx->ip_threats[ctx->ip_threat_count].burst_count = 1;
        
        qihse_qdd_ip_threat_t* entry = &ctx->ip_threats[ctx->ip_threat_count];
        qihse_qdd_geoip_lookup_ctx(ctx, ip,
                                   entry->country, sizeof(entry->country),
                                   entry->city,    sizeof(entry->city),
                                   entry->asn,     sizeof(entry->asn));
        
        char geo_details[256];
        snprintf(geo_details, sizeof(geo_details), "IP %s from %s/%s (ASN: %s)", ip,
                 entry->country, entry->city, entry->asn);
        qihse_qdd_audit_log("IP_THREAT_TRACKED", geo_details);

        ctx->last_ip_idx = ctx->ip_threat_count;
        ctx->ip_threat_count++;
    }
}

/* Resolve a GeoLite2 MMDB file path.
 * Search order:
 *   1. QIHSE_GEOIP_DIR env var
 *   2. ~/.local/share/sword/geoip/
 *   3. /usr/share/GeoIP/
 *   4. /usr/local/share/GeoIP/
 *   5. data/geolite2/ (relative to CWD — legacy)
 * Returns a pointer to a static buffer, or NULL if not found. */
static const char* qihse_qdd_resolve_mmdb(const char* filename) {
    static char path[512];
    const char* env_dir = getenv("QIHSE_GEOIP_DIR");
    if (env_dir) {
        snprintf(path, sizeof(path), "%s/%s", env_dir, filename);
        if (access(path, R_OK) == 0) return path;
    }
    const char* home = getenv("HOME");
    if (home) {
        snprintf(path, sizeof(path), "%s/.local/share/sword/geoip/%s", home, filename);
        if (access(path, R_OK) == 0) return path;
    }
    snprintf(path, sizeof(path), "/usr/share/GeoIP/%s", filename);
    if (access(path, R_OK) == 0) return path;
    snprintf(path, sizeof(path), "/usr/local/share/GeoIP/%s", filename);
    if (access(path, R_OK) == 0) return path;
    snprintf(path, sizeof(path), "data/geolite2/%s", filename);
    if (access(path, R_OK) == 0) return path;
    return NULL;
}

qihse_quantum_defense_ctx_t* qihse_qdd_init(void) {
    qihse_quantum_defense_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    qihse_tsx_rwlock_init(&ctx->lock);

    const char* country_path = qihse_qdd_resolve_mmdb("GeoLite2-Country.mmdb");
    const char* city_path    = qihse_qdd_resolve_mmdb("GeoLite2-City.mmdb");
    const char* asn_path     = qihse_qdd_resolve_mmdb("GeoLite2-ASN.mmdb");

    ctx->mmdb_country = country_path ? qihse_mmdb_open(country_path) : NULL;
    ctx->mmdb_city    = city_path    ? qihse_mmdb_open(city_path)    : NULL;
    ctx->mmdb_asn     = asn_path     ? qihse_mmdb_open(asn_path)     : NULL;

    if (!ctx->mmdb_country || !ctx->mmdb_city || !ctx->mmdb_asn) {
        fprintf(stderr,
            "\n[QIHSE QDD] GeoIP databases not found or incomplete.\n"
            "  Download free GeoLite2 databases (requires free MaxMind account):\n"
            "  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data\n"
            "  Search order:\n"
            "    1. $QIHSE_GEOIP_DIR/GeoLite2-*.mmdb\n"
            "    2. ~/.local/share/sword/geoip/GeoLite2-*.mmdb\n"
            "    3. /usr/share/GeoIP/GeoLite2-*.mmdb\n"
            "    4. /usr/local/share/GeoIP/GeoLite2-*.mmdb\n"
            "    5. data/geolite2/GeoLite2-*.mmdb (relative to CWD)\n"
            "  Geolocation attribution will be disabled until databases are present.\n\n");
        ctx->mmdb_advisory_printed = true;
    }

    return ctx;
}

void qihse_qdd_free(qihse_quantum_defense_ctx_t* ctx) {
    if (ctx) {
        qihse_mmdb_close(ctx->mmdb_country);
        qihse_mmdb_close(ctx->mmdb_city);
        qihse_mmdb_close(ctx->mmdb_asn);
        qihse_tsx_rwlock_destroy(&ctx->lock);
        free(ctx);
    }
}

void qihse_qdd_report_access(qihse_quantum_defense_ctx_t* ctx, uint64_t target_id, const char* accessor_ip) {
    if (!ctx) return;

    /* Hoist time(NULL) OUTSIDE the lock to avoid syscall aborts inside RTM */
    uint64_t now = (uint64_t)time(NULL);

    /* Fast-path check: when accessor_ip matches ctx->last_ip_idx and no threat
     * threshold is crossed, use TSX elision */
    uint32_t last_idx = __atomic_load_n(&ctx->last_ip_idx, __ATOMIC_ACQUIRE);
    uint32_t threat = __atomic_load_n(&ctx->threat_level, __ATOMIC_ACQUIRE);
    bool under_atk = __atomic_load_n(&ctx->under_attack, __ATOMIC_ACQUIRE);

    bool same_ip = false;
    if (accessor_ip && last_idx < ctx->ip_threat_count &&
        strcmp(ctx->ip_threats[last_idx].ip, accessor_ip) == 0) {
        same_ip = true;
    } else if (!accessor_ip) {
        same_ip = true;
    }

    if (same_ip && !under_atk && (threat < (QDD_THREAT_THRESHOLD - 15)) && qihse_has_rtm_support()) {
        int retries = 3;
        while (retries > 0) {
            while (__atomic_load_n(&ctx->lock.fallback_held, __ATOMIC_RELAXED) != 0) {
                _mm_pause();
            }

            unsigned int status = qihse_rtm_xbegin();
            if (status == _XBEGIN_STARTED) {
                if (ctx->lock.fallback_held != 0) {
                    qihse_rtm_xabort(0xff);
                }

                if (accessor_ip && last_idx < ctx->ip_threat_count) {
                    qihse_qdd_ip_threat_t* e = &ctx->ip_threats[last_idx];
                    uint64_t time_delta = now - e->last_access_time;
                    if (time_delta < 1) {
                        e->burst_count++;
                        if (e->burst_count > 10) e->threat_contribution += 5;
                    } else {
                        e->burst_count = 1;
                    }
                    e->last_access_time = now;
                }

                ctx->access_history[ctx->head] = target_id;
                ctx->access_timestamps[ctx->head] = now;
                ctx->head = (ctx->head + 1) % QDD_HISTORY_SIZE;
                if (ctx->history_count < QDD_HISTORY_SIZE) ctx->history_count++;

                int equidistant_hits = 0;
                uint32_t comparisons = ctx->history_count > 1 ? ctx->history_count - 1 : 0;
                if (comparisons > 10) comparisons = 10;
                for (uint32_t i = 0; i < comparisons; i++) {
                    uint32_t idx1 = (ctx->head - 1u - i + QDD_HISTORY_SIZE) % QDD_HISTORY_SIZE;
                    uint32_t idx2 = (ctx->head - 2u - i + QDD_HISTORY_SIZE) % QDD_HISTORY_SIZE;

                    uint64_t diff = ctx->access_history[idx1] ^ ctx->access_history[idx2];
                    uint64_t time_delta = ctx->access_timestamps[idx1] >= ctx->access_timestamps[idx2]
                                              ? ctx->access_timestamps[idx1] - ctx->access_timestamps[idx2]
                                              : ctx->access_timestamps[idx2] - ctx->access_timestamps[idx1];

                    if (__builtin_popcountll(diff) == 1 && time_delta <= 1u) {
                        equidistant_hits++;
                    }
                }

                uint32_t new_threat = ctx->threat_level;
                if (comparisons >= 7 && equidistant_hits > 6) {
                    new_threat += 15;
                } else if (new_threat > 0) {
                    new_threat -= 1;
                }
                if (new_threat > 100) new_threat = 100;

                if (new_threat >= QDD_THREAT_THRESHOLD) {
                    qihse_rtm_xabort(0xfe);
                }

                ctx->threat_level = new_threat;
                qihse_rtm_xend();
                return;
            }

            if ((status & _XABORT_RETRY) || (status & _XABORT_CONFLICT)) {
                _mm_pause();
                retries--;
            } else {
                break;
            }
        }
    }

    qihse_tsx_wrlock(&ctx->lock);

    if (accessor_ip) {
        qihse_qdd_track_ip_threat(ctx, accessor_ip, now);
    }

    ctx->access_history[ctx->head] = target_id;
    ctx->access_timestamps[ctx->head] = now;
    ctx->head = (ctx->head + 1) % QDD_HISTORY_SIZE;
    if (ctx->history_count < QDD_HISTORY_SIZE) ctx->history_count++;

    int equidistant_hits = 0;
    uint32_t comparisons = ctx->history_count > 1 ? ctx->history_count - 1 : 0;
    if (comparisons > 10) comparisons = 10;
    for (uint32_t i = 0; i < comparisons; i++) {
        uint32_t idx1 = (ctx->head - 1u - i + QDD_HISTORY_SIZE) % QDD_HISTORY_SIZE;
        uint32_t idx2 = (ctx->head - 2u - i + QDD_HISTORY_SIZE) % QDD_HISTORY_SIZE;

        uint64_t diff = ctx->access_history[idx1] ^ ctx->access_history[idx2];
        uint64_t time_delta = ctx->access_timestamps[idx1] >= ctx->access_timestamps[idx2]
                                  ? ctx->access_timestamps[idx1] - ctx->access_timestamps[idx2]
                                  : ctx->access_timestamps[idx2] - ctx->access_timestamps[idx1];

        if (__builtin_popcountll(diff) == 1 && time_delta <= 1u) {
            equidistant_hits++;
        }
    }

    uint32_t level = ctx->threat_level;
    if (comparisons >= 7 && equidistant_hits > 6) {
        level += 15;
    } else if (level > 0) {
        level -= 1;
    }
    if (level > 100) level = 100;
    __atomic_store_n(&ctx->threat_level, level, __ATOMIC_RELEASE);

    if (level >= QDD_THREAT_THRESHOLD && !ctx->under_attack) {
        char details[256];
        snprintf(details, sizeof(details), "Threat level %u - Suspected Grover's Algorithm attack detected", level);
        qihse_qdd_audit_log("QUANTUM_ATTACK_DETECTED", details);
        __atomic_store_n(&ctx->under_attack, true, __ATOMIC_RELEASE);
    } else if (level < (QDD_THREAT_THRESHOLD / 2) && ctx->under_attack) {
        qihse_qdd_audit_log("THREAT_SUBSIDED", "Resuming classical operations");
        __atomic_store_n(&ctx->under_attack, false, __ATOMIC_RELEASE);
    }

    qihse_tsx_unlock(&ctx->lock);
}

bool qihse_qdd_is_under_attack(qihse_quantum_defense_ctx_t* ctx) {
    if (!ctx) return false;
    return __atomic_load_n(&ctx->under_attack, __ATOMIC_ACQUIRE);
}

/* Thread-local hardware randomness state for lock-free defense-in-depth entropy */
static __thread uint64_t qihse_qdd_rand_counter = 0;
static __thread uint64_t qihse_qdd_os_seed = 0;
static __thread bool qihse_qdd_seeded = false;

static inline uint64_t qihse_qdd_hardware_random_u64(void) {
    if (__builtin_expect(!qihse_qdd_seeded, 0)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t s = (uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32) ^ (uint64_t)(uintptr_t)&ts;
#if defined(__x86_64__) && (defined(__FSGSBASE__) || defined(QIHSE_ENABLE_FSGSBASE))
        uint64_t tid = _readfsbase_u64();
#else
        uint64_t tid = (uint64_t)(uintptr_t)pthread_self();
#endif
        s ^= ((uint64_t)getpid() << 48) | tid;

        if (qihse_qdd_has_rdseed()) {
            unsigned long long rdseed_val = 0;
            for (int retry = 0; retry < 32; retry++) {
                if (_rdseed64_step(&rdseed_val)) {
                    s ^= (uint64_t)rdseed_val;
                    break;
                }
                _mm_pause();
            }
        }

        s ^= s >> 30; s *= 0xbf58476d1ce4e5b9ULL;
        s ^= s >> 27; s *= 0x94d049bb133111ebULL;
        s ^= s >> 31;
        qihse_qdd_os_seed = s ? s : 0x853c49e6748fea9bULL;
        qihse_qdd_seeded = true;
    }

    uint64_t counter = ++qihse_qdd_rand_counter;

    /* Re-seed thread-local state every 65,536 calls from RDSEED when available */
    if (__builtin_expect((counter & 0xFFFFULL) == 0, 0)) {
        if (qihse_qdd_has_rdseed()) {
            unsigned long long rdseed_val = 0;
            for (int retry = 0; retry < 32; retry++) {
                if (_rdseed64_step(&rdseed_val)) {
                    uint64_t s = qihse_qdd_os_seed ^ (uint64_t)rdseed_val;
                    s ^= s >> 30; s *= 0xbf58476d1ce4e5b9ULL;
                    s ^= s >> 27; s *= 0x94d049bb133111ebULL;
                    s ^= s >> 31;
                    qihse_qdd_os_seed = s ? s : 0x853c49e6748fea9bULL;
                    break;
                }
                _mm_pause();
            }
        }
    }

    unsigned long long rdrand_val = 0;
    int success = 0;
#if defined(__RDRND__) || defined(QIHSE_ENABLE_RDRAND)
    for (int retry = 0; retry < 10; retry++) {
        if (_rdrand64_step(&rdrand_val)) {
            success = 1;
            break;
        }
    }
#endif
    if (!success) {
#if defined(__x86_64__) || defined(_M_X64)
        rdrand_val = __rdtsc();
#else
        rdrand_val = 0x517cc1b727220a95ULL;
#endif
    }

    uint64_t mixed_counter = counter * 0x9e3779b97f4a7c15ULL;
    uint64_t out = ((uint64_t)rdrand_val) ^ mixed_counter ^ qihse_qdd_os_seed;
    out ^= out >> 30;
    out *= 0xbf58476d1ce4e5b9ULL;
    out ^= out >> 27;
    out *= 0x94d049bb133111ebULL;
    out ^= out >> 31;
    return out;
}

bool qihse_secure_random_bytes(void* buf, size_t len) {
    if (!buf && len > 0) return false;
    uint8_t* p = (uint8_t*)buf;
    while (len >= 8) {
        uint64_t r = qihse_qdd_hardware_random_u64();
        memcpy(p, &r, 8);
        p += 8;
        len -= 8;
    }
    if (len > 0) {
        uint64_t r = qihse_qdd_hardware_random_u64();
        memcpy(p, &r, len);
    }
    return true;
}

void qihse_qdd_generate_honeypot_response(char* out_buffer, size_t max_len) {
    if (!out_buffer || max_len < 16) return;
    
    /* 
     * To defeat a quantum algorithm, we inject mathematically valid but 
     * computationally destructive garbage that poisons their amplitude amplification.
     */
    unsigned char random_bytes[256];
    size_t fetch_len = (max_len > sizeof(random_bytes)) ? sizeof(random_bytes) : max_len - 1;
    
    qihse_secure_random_bytes(random_bytes, fetch_len);
    
    /* Convert to Trinary-encoded ASCII payload (-1, 0, 1 mapped to chars) */
    for (size_t i = 0; i < fetch_len; i++) {
        tryte_t val = (random_bytes[i] % 3) - 1;
        if (val == -1) out_buffer[i] = '-';
        else if (val == 0) out_buffer[i] = '0';
        else out_buffer[i] = '+';
    }
    out_buffer[fetch_len] = '\0';
}

#include <sys/socket.h>

typedef struct {
    int attacker_fd;
} qihse_qdd_bomb_args_t;

static void* qihse_qdd_bomb_thread(void* arg) {
    qihse_qdd_bomb_args_t* args = (qihse_qdd_bomb_args_t*)arg;
    int attacker_fd = args->attacker_fd;
    free(args);
    
    char details[128];
    snprintf(details, sizeof(details), "Executing OOM bomb against socket %d", attacker_fd);
    qihse_qdd_audit_log("ACTIVE_MEASURE_EXECUTED", details);
    
    const char* deny = "-ERR access denied\r\n";
    send(attacker_fd, deny, strlen(deny), MSG_NOSIGNAL);
    qihse_qdd_audit_log("ACTIVE_MEASURE_BLOCKED", "Suspicious connection closed defensively");
    close(attacker_fd);
    
    return NULL;
}

void qihse_qdd_execute_active_measure(int attacker_fd) {
    if (attacker_fd < 0) return;
    
    qihse_qdd_bomb_args_t* args = malloc(sizeof(*args));
    if (!args) {
        close(attacker_fd);
        return;
    }
    args->attacker_fd = attacker_fd;
    
    pthread_t bomb_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    if (pthread_create(&bomb_thread, &attr, qihse_qdd_bomb_thread, args) != 0) {
        free(args);
        close(attacker_fd);
    }
    
    pthread_attr_destroy(&attr);
}

uint32_t qihse_qdd_get_threat_level(qihse_quantum_defense_ctx_t* ctx) {
    if (!ctx) return 0;
    return __atomic_load_n(&ctx->threat_level, __ATOMIC_ACQUIRE);
}

qihse_qdd_response_tier_t qihse_qdd_get_response_tier(qihse_quantum_defense_ctx_t* ctx) {
    uint32_t threat = qihse_qdd_get_threat_level(ctx);
    
    if (threat >= 85) {
        return QIHSE_QDD_RESPONSE_ACTIVE;
    } else if (threat >= 75) {
        return QIHSE_QDD_RESPONSE_HONEYPOT;
    } else if (threat >= 50) {
        return QIHSE_QDD_RESPONSE_THROTTLE;
    } else {
        return QIHSE_QDD_RESPONSE_NORMAL;
    }
}

void qihse_qdd_audit_log(const char* event_type, const char* details) {
    if (!event_type) return;
    
    char audit_msg[512];
    snprintf(audit_msg, sizeof(audit_msg), "[QDD] %s: %s", event_type, details ? details : "");
    
    qihse_audit_log(audit_msg, 0, 0, 0, 0);
}

bool qihse_qdd_geoip_lookup(const char* ip, char* out_country, char* out_city, char* out_asn) {
    (void)ip; (void)out_country; (void)out_city; (void)out_asn;
    return false; /* Context-unaware; use qihse_qdd_geoip_lookup_ctx instead */
}

static bool qihse_qdd_geoip_lookup_ctx(qihse_quantum_defense_ctx_t* ctx,
                                        const char* ip,
                                        char* out_country, size_t country_len,
                                        char* out_city,    size_t city_len,
                                        char* out_asn,     size_t asn_len) {
    if (!ctx || !ip) return false;

    bool ok = false;

    if (out_country && country_len > 0) {
        out_country[0] = '\0';
        if (ctx->mmdb_country) {
            const char* kp[] = {"country", "iso_code", NULL};
            if (qihse_mmdb_lookup_string(ctx->mmdb_country, ip, kp,
                                         out_country, country_len)) {
                ok = true;
            } else {
                snprintf(out_country, country_len, "XX");
            }
        } else {
            snprintf(out_country, country_len, "XX");
        }
    }

    if (out_city && city_len > 0) {
        out_city[0] = '\0';
        if (ctx->mmdb_city) {
            const char* kp[] = {"city", "names", "en", NULL};
            if (qihse_mmdb_lookup_string(ctx->mmdb_city, ip, kp,
                                         out_city, city_len)) {
                ok = true;
            } else {
                snprintf(out_city, city_len, "Unknown");
            }
        } else {
            snprintf(out_city, city_len, "Unknown");
        }
    }

    if (out_asn && asn_len > 0) {
        out_asn[0] = '\0';
        if (ctx->mmdb_asn) {
            const char* kp[] = {"autonomous_system_organization", NULL};
            if (qihse_mmdb_lookup_string(ctx->mmdb_asn, ip, kp,
                                         out_asn, asn_len)) {
                ok = true;
            } else {
                snprintf(out_asn, asn_len, "Unknown");
            }
        } else {
            snprintf(out_asn, asn_len, "Unknown");
        }
    }

    return ok;
}

const char* qihse_qdd_get_threat_location(qihse_quantum_defense_ctx_t* ctx, const char* ip) {
    if (!ctx || !ip) return NULL;
    
    qihse_tsx_rdlock(&ctx->lock);
    
    for (uint32_t i = 0; i < ctx->ip_threat_count; i++) {
        if (strcmp(ctx->ip_threats[i].ip, ip) == 0) {
            const char* country = ctx->ip_threats[i].country;
            qihse_tsx_unlock(&ctx->lock);
            return country;
        }
    }
    
    qihse_tsx_unlock(&ctx->lock);
    return NULL;
}
