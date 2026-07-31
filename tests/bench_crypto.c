/*
 * QIHSE Crypto Benchmark — SHA-NI + VAES throughput
 *
 * Measures hardware-accelerated SHA-256 (SHA-NI) and AES-256-GCM (VAES)
 * throughput on Sapphire Rapids. Compares single-buffer vs pipelined.
 *
 * Build: gcc -O3 -msha -mavx2 -mavx512f -mavx512vl -mvaes -mpclmul \
 *          tests/bench_crypto.c -lcrypto -lm -o tests/bench_crypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define CRYPTO_BUF_SIZE   (1024 * 1024)  /* 1 MB */
#define CRYPTO_ITERS      1000
#define CRYPTO_WARMUP     50

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void bench_sha256(const uint8_t* buf, size_t len, int iters) {
    /* Warmup */
    uint8_t hash[SHA256_DIGEST_LENGTH];
    for (int i = 0; i < CRYPTO_WARMUP; i++) {
        SHA256(buf, len, hash);
    }

    double t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        SHA256(buf, len, hash);
    }
    double t1 = now_ns();

    double elapsed_s = (t1 - t0) / 1e9;
    double total_mb  = (double)len * iters / (1024 * 1024);
    double mbps      = total_mb / elapsed_s;

    printf("  SHA-256 (%zu KB, %d iters):  %.1f MB/s  (%.2f ms/call)\n",
           len / 1024, iters, mbps, (t1 - t0) / iters / 1e6);
}

static void bench_sha512(const uint8_t* buf, size_t len, int iters) {
    uint8_t hash[SHA512_DIGEST_LENGTH];
    for (int i = 0; i < CRYPTO_WARMUP; i++) {
        SHA512(buf, len, hash);
    }

    double t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        SHA512(buf, len, hash);
    }
    double t1 = now_ns();

    double elapsed_s = (t1 - t0) / 1e9;
    double total_mb  = (double)len * iters / (1024 * 1024);
    double mbps      = total_mb / elapsed_s;

    printf("  SHA-512 (%zu KB, %d iters):  %.1f MB/s  (%.2f ms/call)\n",
           len / 1024, iters, mbps, (t1 - t0) / iters / 1e6);
}

static void bench_aes256_gcm(const uint8_t* buf, size_t len, int iters) {
    const uint8_t key[32] = {0};
    const uint8_t iv[12]  = {0};
    uint8_t* out = malloc(len + 16);
    uint8_t tag[16];
    int outlen;

    /* Warmup */
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    for (int i = 0; i < CRYPTO_WARMUP; i++) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, out, &outlen, buf, (int)len);
        EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }

    double t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, out, &outlen, buf, (int)len);
        EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }
    double t1 = now_ns();

    EVP_CIPHER_CTX_free(ctx);
    free(out);

    double elapsed_s = (t1 - t0) / 1e9;
    double total_mb  = (double)len * iters / (1024 * 1024);
    double mbps      = total_mb / elapsed_s;

    printf("  AES-256-GCM (%zu KB, %d iters): %.1f MB/s  (%.2f ms/call)\n",
           len / 1024, iters, mbps, (t1 - t0) / iters / 1e6);
}

/* VAES: AES-256-GCM processing 4 blocks in parallel using 512-bit registers.
 * OpenSSL 3.x uses VAES internally when available, so this benchmarks
 * the EVP path which auto-dispatches to VAES on Sapphire Rapids. */
static void bench_aes256_gcm_batch(const uint8_t* buf, size_t len, int iters) {
    /* Process 4 independent 1KB blocks in parallel (simulating batch) */
    const int batch = 4;
    const uint8_t key[32] = {0};
    uint8_t ivs[4][12];
    for (int i = 0; i < 4; i++) memset(ivs[i], i, 12);
    uint8_t* out = malloc(len * batch + 64);
    uint8_t tags[4][16];
    int outlen;

    EVP_CIPHER_CTX* ctxs[4];
    for (int i = 0; i < batch; i++) ctxs[i] = EVP_CIPHER_CTX_new();

    /* Warmup */
    for (int i = 0; i < CRYPTO_WARMUP; i++) {
        for (int j = 0; j < batch; j++) {
            EVP_EncryptInit_ex(ctxs[j], EVP_aes_256_gcm(), NULL, key, ivs[j]);
            EVP_EncryptUpdate(ctxs[j], out + j * len, &outlen, buf, (int)len);
            EVP_EncryptFinal_ex(ctxs[j], out + j * len + outlen, &outlen);
            EVP_CIPHER_CTX_ctrl(ctxs[j], EVP_CTRL_GCM_GET_TAG, 16, tags[j]);
        }
    }

    double t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        for (int j = 0; j < batch; j++) {
            EVP_EncryptInit_ex(ctxs[j], EVP_aes_256_gcm(), NULL, key, ivs[j]);
            EVP_EncryptUpdate(ctxs[j], out + j * len, &outlen, buf, (int)len);
            EVP_EncryptFinal_ex(ctxs[j], out + j * len + outlen, &outlen);
            EVP_CIPHER_CTX_ctrl(ctxs[j], EVP_CTRL_GCM_GET_TAG, 16, tags[j]);
        }
    }
    double t1 = now_ns();

    for (int i = 0; i < batch; i++) EVP_CIPHER_CTX_free(ctxs[i]);
    free(out);

    double elapsed_s = (t1 - t0) / 1e9;
    double total_mb  = (double)len * batch * iters / (1024 * 1024);
    double mbps      = total_mb / elapsed_s;

    printf("  AES-256-GCM batch4 (%zu KB x4, %d iters): %.1f MB/s  (%.2f ms/batch)\n",
           len / 1024, iters, mbps, (t1 - t0) / iters / 1e6);
}

/* HMAC-SHA384 throughput (CNSA 2.0 compliant) */
static void bench_hmac_sha384(const uint8_t* buf, size_t len, int iters) {
    const uint8_t key[32] = {0};
    uint8_t mac[48];
    unsigned int maclen;

    for (int i = 0; i < CRYPTO_WARMUP; i++) {
        HMAC(EVP_sha384(), key, 32, buf, len, mac, &maclen);
    }

    double t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        HMAC(EVP_sha384(), key, 32, buf, len, mac, &maclen);
    }
    double t1 = now_ns();

    double elapsed_s = (t1 - t0) / 1e9;
    double total_mb  = (double)len * iters / (1024 * 1024);
    double mbps      = total_mb / elapsed_s;

    printf("  HMAC-SHA-384 (%zu KB, %d iters): %.1f MB/s  (%.2f ms/call)\n",
           len / 1024, iters, mbps, (t1 - t0) / iters / 1e6);
}

int main(void) {
    printf("================================================================\n");
    printf("QIHSE CRYPTO BENCHMARK — SHA-NI + VAES + HMAC\n");
    printf("================================================================\n\n");

    /* Check CPU features */
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "model name", 10) == 0) {
                char* colon = strchr(line, ':');
                if (colon) printf("CPU: %s", colon + 2);
                break;
            }
        }
        fclose(cpuinfo);
    }

    /* Check for SHA-NI and VAES */
    FILE* flags = fopen("/proc/cpuinfo", "r");
    if (flags) {
        char line[4096];
        while (fgets(line, sizeof(line), flags)) {
            if (strncmp(line, "flags", 5) == 0) {
                printf("SHA-NI:  %s\n", strstr(line, "sha_ni") ? "yes" : "no");
                printf("VAES:    %s\n", strstr(line, "vaes") ? "yes" : "no");
                printf("AES-NI:  %s\n", strstr(line, "aes") ? "yes" : "no");
                printf("PCLMUL:  %s\n", strstr(line, "pclmulqdq") ? "yes" : "no");
                break;
            }
        }
        fclose(flags);
    }
    printf("\n");

    /* Allocate buffer */
    uint8_t* buf = aligned_alloc(64, CRYPTO_BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }
    memset(buf, 0x41, CRYPTO_BUF_SIZE);

    /* Hash benchmarks */
    printf("--- Hash Throughput (1 MB buffer) ---\n");
    bench_sha256(buf, CRYPTO_BUF_SIZE, CRYPTO_ITERS);
    bench_sha512(buf, CRYPTO_BUF_SIZE, CRYPTO_ITERS);
    bench_hmac_sha384(buf, CRYPTO_BUF_SIZE, CRYPTO_ITERS);

    /* Smaller buffers (latency-sensitive) */
    printf("\n--- Hash Throughput (64 B, latency) ---\n");
    bench_sha256(buf, 64, 100000);
    bench_sha512(buf, 64, 100000);
    bench_hmac_sha384(buf, 64, 100000);

    /* AES benchmarks */
    printf("\n--- AES Throughput (1 MB buffer) ---\n");
    bench_aes256_gcm(buf, CRYPTO_BUF_SIZE, CRYPTO_ITERS);
    bench_aes256_gcm_batch(buf, 1024, CRYPTO_ITERS);

    printf("\n--- AES Throughput (4 KB, latency) ---\n");
    bench_aes256_gcm(buf, 4096, 10000);

    printf("\n================================================================\n");
    printf("CRYPTO BENCHMARK COMPLETE\n");
    printf("================================================================\n");

    free(buf);
    return 0;
}
