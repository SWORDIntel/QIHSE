/* No production listener until durable authentication and verified TLS identity exist. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void usage(FILE* out) {
    fprintf(out, "usage: qihse_pgwire_service --enable-production --store PATH "
                 "--cert FILE --key FILE [--bind 127.0.0.1] "
                 "[--port 1..65535]\n");
}
static bool parse_port(const char* value, uint16_t* port) {
    char* end = NULL;
    if (!value || !*value || *value == '-' || *value == '+') return false;
    errno = 0;
    unsigned long n = strtoul(value, &end, 10);
    if (errno || !end || *end || !n || n > UINT16_MAX) return false;
    *port = (uint16_t)n;
    return true;
}

int main(int argc, char** argv) {
    const char *store = NULL, *cert = NULL, *key = NULL;
    const char* bind_address = "127.0.0.1";
    uint16_t port = 5432;
    bool enabled = false;
    unsigned int seen = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 && argc == 2) {
            usage(stdout); return 0;
        }
        if (strcmp(argv[i], "--enable-production") == 0) {
            if (enabled) { usage(stderr); return 2; }
            enabled = true;
            continue;
        }
        if (i + 1 >= argc) { usage(stderr); return 2; }
        const char* option = argv[i++];
        const char* value = argv[i];
        unsigned int bit = 0;
        if (strcmp(option, "--store") == 0) bit = 1u;
        else if (strcmp(option, "--cert") == 0) bit = 2u;
        else if (strcmp(option, "--key") == 0) bit = 4u;
        else if (strcmp(option, "--bind") == 0) bit = 8u;
        else if (strcmp(option, "--port") == 0) bit = 16u;
        if (!bit || (seen & bit) || !*value || value[0] == '-') {
            usage(stderr); return 2;
        }
        seen |= bit;
        if (bit == 1u) store = value;
        else if (bit == 2u) cert = value;
        else if (bit == 4u) key = value;
        else if (bit == 8u) bind_address = value;
        else if (!parse_port(value, &port)) {
            fprintf(stderr, "pgwire service: invalid port\n"); return 2;
        }
    }
    if (!enabled || !store || !cert || !key ||
        strcmp(bind_address, "127.0.0.1") != 0 ||
        strcmp(cert, key) == 0 || strcmp(store, cert) == 0 ||
        strcmp(store, key) == 0) { usage(stderr); return 2; }
    (void)port;
    /* SQL durable readiness does not prove authentication survives restart.
     * A PEM/key pair does not enforce client-side server identity checking.
     * Refuse before opening a store, accepting clients, or installing handlers. */
    fprintf(stderr, "pgwire service: persistent authentication and verified TLS deployment policy not integrated; refusing listener\n");
    return 1;
}
