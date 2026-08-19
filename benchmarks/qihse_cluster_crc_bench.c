#include "qihse_crc16.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double seconds_between(const struct timespec* start, const struct timespec* end) {
    return (double)(end->tv_sec - start->tv_sec) + (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

int main(int argc, char** argv) {
    size_t bytes = 64u * 1024u * 1024u;
    unsigned int iterations = 16u;
    if (argc > 1) bytes = (size_t)strtoull(argv[1], NULL, 10);
    if (argc > 2) iterations = (unsigned int)strtoul(argv[2], NULL, 10);
    if (bytes == 0 || iterations == 0) return 2;
    unsigned char* data = NULL;
    if (posix_memalign((void**)&data, 64u, bytes) != 0) return 1;
    uint32_t state = 1u;
    for (size_t i = 0; i < bytes; i++) {
        state = state * 1664525u + 1013904223u;
        data[i] = (unsigned char)(state >> 24);
    }
    volatile uint16_t checksum = qihse_crc16_xmodem(data, bytes);
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned int i = 0; i < iterations; i++) checksum ^= qihse_crc16_xmodem(data, bytes);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = seconds_between(&start, &end);
    double gib = (double)bytes * iterations / (1024.0 * 1024.0 * 1024.0);
    printf("backend=%s bytes=%zu iterations=%u throughput_gib_s=%.3f checksum=%u\n",
           qihse_crc16_backend_name(), bytes, iterations, gib / elapsed, (unsigned int)checksum);
    free(data);
    return 0;
}
