#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "qihse_mmdb.h"

static uint32_t xorshift32(uint32_t* state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void gen_random_ip(char* buf, size_t len, uint32_t* rng) {
    uint32_t v = xorshift32(rng);
    snprintf(buf, len, "%u.%u.%u.%u",
             (v >> 24) & 0xFF, (v >> 16) & 0xFF,
             (v >> 8) & 0xFF,  v & 0xFF);
}

/* Resolve a GeoLite2 MMDB file path (same search order as quantum_defense). */
static const char* resolve_mmdb(const char* filename) {
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

int main(void) {
    srand((unsigned)time(NULL));
    uint32_t rng = (uint32_t)time(NULL);

    printf("Opening GeoLite2 databases...\n");
    const char* country_p = resolve_mmdb("GeoLite2-Country.mmdb");
    const char* city_p    = resolve_mmdb("GeoLite2-City.mmdb");
    const char* asn_p     = resolve_mmdb("GeoLite2-ASN.mmdb");

    qihse_mmdb_t* country = country_p ? qihse_mmdb_open(country_p) : NULL;
    qihse_mmdb_t* city    = city_p    ? qihse_mmdb_open(city_p)    : NULL;
    qihse_mmdb_t* asn     = asn_p     ? qihse_mmdb_open(asn_p)     : NULL;

    if (!country || !city || !asn) {
        fprintf(stderr, "Failed to open one or more MMDB files.\n");
        return 1;
    }

    printf("Databases loaded. Country nodes=%u record_size=%u  City nodes=%u  ASN nodes=%u\n",
           country->node_count, country->record_size,
           city->node_count, asn->node_count);

    printf("\n=== 100 Random IP Lookups ===\n\n");

    int country_hits = 0, city_hits = 0, asn_hits = 0;

    for (int i = 0; i < 100; i++) {
        char ip[64];
        gen_random_ip(ip, sizeof(ip), &rng);

        char cc[4] = {0}, city_name[128] = {0}, asn_name[128] = {0};

        const char* kp_country[] = {"country", "iso_code", NULL};
        const char* kp_city[]    = {"city", "names", "en", NULL};
        const char* kp_asn[]     = {"autonomous_system_organization", NULL};

        bool ok_cc  = qihse_mmdb_lookup_string(country, ip, kp_country, cc, sizeof(cc));
        bool ok_city = qihse_mmdb_lookup_string(city, ip, kp_city, city_name, sizeof(city_name));
        bool ok_asn  = qihse_mmdb_lookup_string(asn, ip, kp_asn, asn_name, sizeof(asn_name));

        if (ok_cc)  country_hits++;
        if (ok_city) city_hits++;
        if (ok_asn)  asn_hits++;

        if (i < 20) { /* print first 20 in detail */
            printf("%3d %-15s => CC:%-3s  City:%-20s  ASN:%s\n",
                   i + 1, ip,
                   ok_cc  ? cc  : "??",
                   ok_city ? city_name : "???",
                   ok_asn  ? asn_name  : "???");
        }
    }

    printf("\n=== Summary ===\n");
    printf("Country lookups: %d/100 found\n", country_hits);
    printf("City    lookups: %d/100 found\n", city_hits);
    printf("ASN     lookups: %d/100 found\n", asn_hits);

    qihse_mmdb_close(country);
    qihse_mmdb_close(city);
    qihse_mmdb_close(asn);
    return 0;
}
