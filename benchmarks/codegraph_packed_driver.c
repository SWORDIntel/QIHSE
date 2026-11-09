/* Synthetic, authenticated CodeGraph codec comparison driver.
 * Build from the checkout through codegraph_packed_compare.py. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_storage.h"
#ifdef CODEGRAPH_PACKED_CODEC
#include "qihse_codegraph_packed.h"
#include "qihse_codegraph_dictionary.h"
#endif

#define PASSWORD "CodeGraphPackedBenchmark1!"
#define LIMIT_BYTES (UINT64_C(64) << 20)
#define LIMIT_RECORDS 100000u

typedef struct {
    unsigned char (*hashes)[32];
    size_t used, capacity;
    bool ok;
} digest_set;

static double milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
}

static double cpu_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now)) return -1;
    return (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
}

static bool digest_record(const char *key, const char *value, void *arg) {
    digest_set *set = arg;
    if (set->used >= LIMIT_RECORDS || strlen(key) > SIZE_MAX / 2 ||
        strlen(value) > SIZE_MAX / 2) return set->ok = false;
    if (set->used == set->capacity) {
        size_t capacity = set->capacity ? set->capacity * 2 : 256;
        if (capacity > LIMIT_RECORDS) capacity = LIMIT_RECORDS;
        void *next = realloc(set->hashes, capacity * sizeof(*set->hashes));
        if (!next) return set->ok = false;
        set->hashes = next;
        set->capacity = capacity;
    }
    uint64_t lengths[2] = {(uint64_t)strlen(key), (uint64_t)strlen(value)};
    unsigned char encoded[16];
    for (size_t j = 0; j < 2; j++)
        for (size_t i = 0; i < 8; i++)
            encoded[j * 8 + i] = (unsigned char)(lengths[j] >> (56 - 8 * i));
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned n = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
              EVP_DigestUpdate(ctx, encoded, sizeof(encoded)) == 1 &&
              EVP_DigestUpdate(ctx, key, (size_t)lengths[0]) == 1 &&
              EVP_DigestUpdate(ctx, value, (size_t)lengths[1]) == 1 &&
              EVP_DigestFinal_ex(ctx, set->hashes[set->used], &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    if (ok) set->used++;
    return set->ok = ok;
}

static int compare_digest(const void *left, const void *right) {
    return memcmp(left, right, 32);
}

static bool store_fingerprint(qihse_kv_store_t *store, qihse_user_t *user,
                              char hex[65], size_t *count) {
    digest_set set = {NULL, 0, 0, true};
    bool ok = qihse_kv_foreach_user(store, user, digest_record, &set) && set.ok;
    if (ok) {
        qsort(set.hashes, set.used, sizeof(*set.hashes), compare_digest);
        unsigned char sum[32];
        unsigned n = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, set.hashes, set.used * sizeof(*set.hashes)) == 1 &&
             EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
        EVP_MD_CTX_free(ctx);
        static const char digits[] = "0123456789abcdef";
        if (ok) {
            for (size_t i = 0; i < 32; i++) {
                hex[i * 2] = digits[sum[i] >> 4];
                hex[i * 2 + 1] = digits[sum[i] & 15];
            }
            hex[64] = 0;
        }
    }
    if (count) *count = set.used;
    free(set.hashes);
    return ok;
}

static bool populate(qihse_kv_store_t *store, qihse_user_t *user, const char *input) {
    FILE *stream = fopen(input, "rb");
    if (!stream) return false;
    char *line = NULL;
    size_t capacity = 0, records = 0;
    bool ok = true;
    while (ok && getline(&line, &capacity, stream) >= 0) {
        if (strlen(line) > 262144 || ++records > LIMIT_RECORDS) { ok = false; break; }
        struct json_object *row = json_tokener_parse(line), *field = NULL;
        if (!row || !json_object_object_get_ex(row, "t", &field)) {
            if (row) json_object_put(row);
            ok = false;
            break;
        }
        const char *type = json_object_get_string(field);
        char key[72];
        if (!strcmp(type, "h")) snprintf(key, sizeof(key), "_meta");
        else if (!strcmp(type, "end")) snprintf(key, sizeof(key), "_end");
        else {
            if ((!strcmp(type, "n") && !json_object_object_get_ex(row, "id", &field)) ||
                (!strcmp(type, "e") && !json_object_object_get_ex(row, "id", &field)) ||
                (strcmp(type, "n") && strcmp(type, "e"))) {
                json_object_put(row);
                ok = false;
                break;
            }
            const char *id = json_object_get_string(field);
            if (!id || (strlen(id) != 64 && strlen(id) != 32) ||
                snprintf(key, sizeof(key), "%s:%s", type, id) >= (int)sizeof(key)) {
                json_object_put(row);
                ok = false;
                break;
            }
        }
        ok = qihse_kv_set_user(store, key, line, 0, 0, user);
        json_object_put(row);
    }
    ok = ok && !ferror(stream);
    free(line);
    fclose(stream);
    return ok;
}

static bool path_append(char *output, size_t n, const char *base, const char *suffix) {
    int count = snprintf(output, n, "%s%s", base, suffix);
    return count > 0 && count < (int)n;
}

static bool same_bytes(const char *left, const char *right) {
    FILE *a = fopen(left, "rb"), *b = fopen(right, "rb");
    if (!a || !b) {
        if (a) fclose(a);
        if (b) fclose(b);
        return false;
    }
    unsigned char ab[65536], bb[65536];
    bool same = true;
    for (;;) {
        size_t an = fread(ab, 1, sizeof(ab), a);
        size_t bn = fread(bb, 1, sizeof(bb), b);
        if (an != bn || memcmp(ab, bb, an)) { same = false; break; }
        if (an < sizeof(ab)) {
            same = !ferror(a) && !ferror(b);
            break;
        }
    }
    fclose(a);
    fclose(b);
    return same;
}

#ifdef CODEGRAPH_PACKED_CODEC
static bool packed_encode(const char *raw, const char *output, qihse_user_t *user) {
    FILE *input = fopen(raw, "rb"), *dest = fopen(output, "wb+");
    if (!input || !dest) {
        if (input) fclose(input);
        if (dest) fclose(dest);
        return false;
    }
    bool ok = cg_packed_encode_snapshot(input, dest, user, LIMIT_BYTES, LIMIT_RECORDS);
    if (fclose(input)) ok = false;
    if (fclose(dest)) ok = false;
    return ok;
}

static bool dictionary_decode(const char *path, const char *raw, qihse_user_t *user) {
    FILE *input = fopen(path, "rb"), *out = fopen(raw, "wb+");
    if (!input || !out) { if(input) fclose(input); if(out) fclose(out); return false; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char block[4096], digest[32]; unsigned length = 0; size_t n;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (n = fread(block, 1, sizeof(block), input)))
        ok = EVP_DigestUpdate(ctx, block, n) == 1;
    ok = ok && !ferror(input) && EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx); rewind(input);
    char expected[65];
    if (ok) {
        for (size_t i=0;i<32;i++) snprintf(expected+2*i,3,"%02x",digest[i]);
        ok = cg_dictionary_decode_snapshot(input,out,user,expected,LIMIT_BYTES,LIMIT_RECORDS);
    }
    if (fclose(input)) ok=false;
    if (fclose(out)) ok=false;
    return ok;
}

static bool packed_decode(const char *input, const char *raw, qihse_user_t *user) {
    FILE *source = fopen(input, "rb"), *dest = fopen(raw, "wb+");
    if (!source || !dest) {
        if (source) fclose(source);
        if (dest) fclose(dest);
        return false;
    }
    bool ok = cg_packed_decode_snapshot(source, dest, user, LIMIT_BYTES, LIMIT_RECORDS);
    if (fclose(source)) ok = false;
    if (fclose(dest)) ok = false;
    return ok;
}
#endif

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    const char *backend = argv[1], *input = argv[2], *output = argv[3];
    if (strcmp(backend, "legacy") && strcmp(backend, "zstd") &&
        strcmp(backend, "packed") && strcmp(backend, "dictionary") && strcmp(backend, "auto")) return 2;
#ifndef CODEGRAPH_PACKED_CODEC
    if (!strcmp(backend, "packed") || !strcmp(backend, "auto")) return 2;
#endif
    if (setenv("QIHSE_FIPS_MODE", "disabled", 1) || !qihse_auth_init() ||
        !qihse_auth_bootstrap_operator(PASSWORD)) return 3;
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD);
    if (!op || !qihse_auth_create_user(op, 71, QIHSE_ROLE_ANALYST, 0, 0, PASSWORD, false)) return 3;
    qihse_user_t *low = qihse_auth_authenticate_id(71, PASSWORD);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    if (!low || !store || !populate(store, op, input)) return 4;
    char before[65], after[65];
    size_t before_count = 0, after_count = 0;
    if (!store_fingerprint(store, op, before, &before_count)) return 5;

    char raw[PATH_MAX], decoded[PATH_MAX], reexport[PATH_MAX];
    char protected_path[PATH_MAX], protected_raw[PATH_MAX], denied[PATH_MAX];
    if (!path_append(raw, sizeof(raw), output, ".raw") ||
        !path_append(decoded, sizeof(decoded), output, ".decoded") ||
        !path_append(reexport, sizeof(reexport), output, ".reexport") ||
        !path_append(protected_path, sizeof(protected_path), output, ".protected") ||
        !path_append(protected_raw, sizeof(protected_raw), output, ".protected.raw") ||
        !path_append(denied, sizeof(denied), output, ".denied")) return 5;
    double begin = milliseconds();
    if (qihse_kv_save_user(store, raw, op)) return 6;
    double raw_export_ms = milliseconds() - begin;
    begin = milliseconds();
    double cpu_begin = cpu_milliseconds();
    bool automatic = !strcmp(backend, "auto");
    cg_storage_format selected_format = CG_STORAGE_ZSTD;
    bool saved = automatic ? cg_storage_save_auto_format(store, output, op, &selected_format)
                 : !strcmp(backend, "legacy") ? qihse_kv_save_user(store, output, op) == 0
                 : !strcmp(backend, "zstd") ? cg_storage_save(store, output, op)
#ifdef CODEGRAPH_PACKED_CODEC
                 : !strcmp(backend, "dictionary") ? cg_storage_save_dictionary(store, output, op)
                 : packed_encode(raw, output, op);
#else
                 : false;
#endif
    double encode_ms = milliseconds() - begin;
    double encode_cpu_ms = cpu_milliseconds() - cpu_begin;
    if (!saved) return 7;
    if (automatic) backend = selected_format == CG_STORAGE_DICTIONARY ? "dictionary" :
                             selected_format == CG_STORAGE_PACKED ? "packed" : "zstd";
    struct stat snapshot;
    if (stat(output, &snapshot)) return 8;
    qihse_kv_store_t *loaded = qihse_kv_store_create_user(op);
    if (!loaded) return 8;
    begin = milliseconds();
    cpu_begin = cpu_milliseconds();
    bool decoded_ok = !strcmp(backend, "legacy") ? qihse_kv_load_user(loaded, output, op) == 0
                      : !strcmp(backend, "zstd") ? cg_storage_load(loaded, output, op)
#ifdef CODEGRAPH_PACKED_CODEC
                      : (!strcmp(backend, "dictionary") ? dictionary_decode(output, decoded, op) :
                         packed_decode(output, decoded, op)) &&
                        qihse_kv_load_user(loaded, decoded, op) == 0;
#else
                      : false;
#endif
    double load_ms = milliseconds() - begin;
    double load_cpu_ms = cpu_milliseconds() - cpu_begin;
    if (!decoded_ok || ((!strcmp(backend, "packed") || !strcmp(backend, "dictionary")) && !same_bytes(raw, decoded)) ||
        qihse_kv_save_user(loaded, reexport, op) != 0 || !same_bytes(raw, reexport) ||
        !store_fingerprint(loaded, op, after, &after_count) ||
        strcmp(before, after) || before_count != after_count) return 9;
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) return 9;

    /* Denial fixture is separate from the public graph used for sizes/timing. */
    if (!qihse_kv_set_user(store, "protected", "PACKED-BENCH-PROTECTED-PAYLOAD", 4, 2, op)) return 10;
    bool protected_saved = !strcmp(backend, "legacy") ?
        qihse_kv_save_user(store, protected_path, op) == 0
        : !strcmp(backend, "zstd") ? cg_storage_save(store, protected_path, op)
#ifdef CODEGRAPH_PACKED_CODEC
        : !strcmp(backend, "dictionary") ? cg_storage_save_dictionary(store, protected_path, op)
        : qihse_kv_save_user(store, protected_raw, op) == 0 &&
          packed_encode(protected_raw, protected_path, op);
#else
        : false;
#endif
    if (!protected_saved) return 10;
    qihse_kv_store_t *low_store = qihse_kv_store_create_user(low);
    if (!low_store) return 10;
    bool denied_ok = !strcmp(backend, "legacy") ?
        qihse_kv_load_user(low_store, protected_path, low) != 0
        : !strcmp(backend, "zstd") ? !cg_storage_load(low_store, protected_path, low)
#ifdef CODEGRAPH_PACKED_CODEC
        : !strcmp(backend, "dictionary") ? !dictionary_decode(protected_path, denied, low)
        : !packed_decode(protected_path, denied, low);
#else
        : false;
#endif
    if (!denied_ok) return 11;
#ifdef CODEGRAPH_PACKED_CODEC
    if (!strcmp(backend, "packed") || !strcmp(backend, "dictionary")) {
        struct stat info;
        if (stat(denied, &info) || info.st_size != 0) return 11;
    }
#endif
    char *leaked = qihse_kv_get_user(low_store, "protected", low);
    if (leaked) { free(leaked); return 11; }
    qihse_kv_store_destroy(low_store);
    qihse_kv_store_destroy(loaded);
    qihse_kv_store_destroy(store);
    printf("{\"backend\":\"%s\",\"selected_format\":\"%s\",\"record_count\":%zu,\"fingerprint\":\"%s\","
           "\"raw_export_ms\":%.3f,\"encode_ms\":%.3f,\"encode_cpu_ms\":%.3f,"
           "\"load_ms\":%.3f,\"load_cpu_ms\":%.3f,"
           "\"snapshot_apparent_bytes\":%jd,\"snapshot_allocated_bytes\":%jd,"
           "\"peak_rss_kib\":%ld,\"low_clearance_denied\":true,"
           "\"raw_roundtrip\":%s}\n",
           automatic ? "auto" : backend, backend, after_count, after, raw_export_ms, encode_ms, encode_cpu_ms,
           load_ms, load_cpu_ms,
           (intmax_t)snapshot.st_size, (intmax_t)snapshot.st_blocks * 512,
           usage.ru_maxrss, "true");
    return 0;
}
