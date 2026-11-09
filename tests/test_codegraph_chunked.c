/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "codegraph_xxh3/include/qihse_xxh3.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_codegraph_chunked.h"
#include "qihse_codegraph_dictionary.h"
#include "qihse_codegraph_storage.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>
#define PASSWORD "CodeGraphChunkedTests1!"
static qihse_user_t *op, *low, *wrong_sci;
static size_t file_size(FILE *f) {
    assert(!fflush(f) && !fseeko(f, 0, SEEK_END));
    off_t n = ftello(f);
    assert(n >= 0);
    rewind(f);
    return (size_t)n;
}
static void same(FILE *a, FILE *b) {
    assert(file_size(a) == file_size(b));
    unsigned char x[65536], y[65536];
    size_t n;
    while ((n = fread(x, 1, sizeof(x), a))) {
        assert(fread(y, 1, n, b) == n);
        assert(!memcmp(x, y, n));
    }
    assert(!ferror(a) && fgetc(b) == EOF);
    rewind(a);
    rewind(b);
}
static cg_snapshot_checksum checksum(FILE *f) {
    const qx3_backend *backend = qx3_backend_get("auto");
    assert(backend);
    qx3_stream *s = qx3_stream_create(backend, 0);
    assert(s);
    unsigned char bytes[65536];
    size_t n;
    rewind(f);
    while ((n = fread(bytes, 1, sizeof(bytes), f)))
        assert(!qx3_stream_update(s, bytes, n));
    assert(!ferror(f));
    cg_snapshot_checksum result = {.algorithm = CG_CHECKSUM_XXH3_128};
    qx3_hex(qx3_stream_digest(s), result.hex);
    qx3_stream_free(s);
    rewind(f);
    return result;
}
static bool decode(FILE *f, FILE *out, qihse_user_t *user) {
    cg_snapshot_checksum expected = checksum(f);
    return cg_chunked_decode_checksum_snapshot(
        f, out, user, &expected, (size_t)CG_CHUNKED_MAX_RAW_BYTES, CG_CHUNKED_MAX_RECORDS);
}
static FILE *encoded(FILE *raw) {
    FILE *f = tmpfile();
    assert(f);
    rewind(raw);
    assert(cg_chunked_encode_snapshot(raw, f, op, (size_t)CG_CHUNKED_MAX_RAW_BYTES,
                                      CG_CHUNKED_MAX_RECORDS));
    rewind(f);
    return f;
}
static FILE *duplicate(FILE *f) {
    FILE *out = tmpfile();
    assert(out);
    unsigned char bytes[65536];
    size_t n;
    rewind(f);
    while ((n = fread(bytes, 1, sizeof(bytes), f)))
        assert(fwrite(bytes, 1, n, out) == n);
    assert(!ferror(f));
    rewind(f);
    rewind(out);
    return out;
}
static void mutate(FILE *f, size_t off, unsigned char value) {
    assert(!fseeko(f, (off_t)off, SEEK_SET));
    assert(fputc(value, f) != EOF);
    assert(!fflush(f));
    rewind(f);
}
static void reject(FILE *f, qihse_user_t *user) {
    FILE *out = tmpfile();
    assert(out);
    assert(!decode(f, out, user));
    assert(file_size(out) == 0);
    fclose(out);
}
static void fixture(FILE *raw, size_t count, bool high) {
    unsigned char digest[32];
    unsigned dlen;
    char hex[65], value[1400], file[50];
    for (size_t i = 0; i < count; i++) {
        assert(EVP_Digest(&i, sizeof(i), digest, &dlen, EVP_sha256(), NULL) == 1 && dlen == 32);
        for (size_t j = 0; j < 32; j++)
            sprintf(hex + 2 * j, "%02x", digest[j]);
        snprintf(file, sizeof(file), "src/module_%zu.rs", i % 600);
        int length = snprintf(
            value, sizeof(value),
            "{\"t\":\"node\",\"id\":\"%.32s\",\"file\":\"%s\",\"name\":\"namespace::function_%zu\","
            "\"kind\":\"function\",\"line_start\":%zu,\"line_end\":%zu,\"unknown\":{\"precise\":1."
            "2300e+04,\"quoted\":\"escaped \\\" words\",\"evidence\":\"%.64s %.64s %.64s\"}}",
            hex, file, i, i % 3000, i % 3000 + 9, hex, hex, hex);
        assert(length > 0 && (size_t)length < sizeof(value));
        unsigned c = high ? 4 : 0, s = high ? 2 : 0;
        if (i % 31 == 0)
            assert(fprintf(raw, "034\t%d 000 %u %u 0 %zu future-header=v7\nn:%.32s%s\n", length, c,
                           s, i + 1, hex, value) > 0);
        else
            assert(fprintf(raw, "34 %d 0 %u %u 0 %zu\nn:%.32s%s\n", length, c, s, i + 1, hex,
                           value) > 0);
    }
    assert(!fflush(raw));
    rewind(raw);
}
static uint32_t number32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void store32(unsigned char *p, uint32_t value) {
    for (size_t i = 0; i < 4; i++)
        p[3 - i] = (unsigned char)(value >> (8 * i));
}
/* Rechecksum a malformed column so decoding actually reaches varint/header
 * checks, rather than merely failing the independent snapshot/frame checksum. */
static FILE *rewrite_column(FILE *source, size_t column, bool exception) {
    unsigned char outer[64], header[112];
    rewind(source);
    assert(fread(outer, 1, sizeof(outer), source) == sizeof(outer));
    assert(number32(outer + 24) == 1);
    assert(fread(header, 1, sizeof(header), source) == sizeof(header));
    FILE *result = tmpfile(), *payload = tmpfile();
    assert(result && payload);
    for (size_t i = 0; i < 9; i++) {
        size_t compressed = number32(header + 68 + 4 * i), plain = number32(header + 32 + 4 * i);
        unsigned char *zip = malloc(compressed);
        assert(zip);
        assert(fread(zip, 1, compressed, source) == compressed);
        if (i == column) {
            unsigned char *decoded = malloc(plain + 1);
            assert(decoded);
            assert(ZSTD_decompress(decoded, plain, zip, compressed) == plain);
            free(zip);
            if (exception) {
                assert(plain > 3);
                decoded[2] = 0;
            } else {
                assert(plain);
                memmove(decoded + 2, decoded + 1, plain - 1);
                decoded[0] |= 128;
                decoded[1] = 0;
                plain++;
            }
            ZSTD_CCtx *ctx = ZSTD_createCCtx();
            assert(ctx);
            assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)));
            assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, 23)));
            size_t cap = ZSTD_compressBound(plain);
            zip = malloc(cap);
            assert(zip);
            compressed = ZSTD_compress2(ctx, zip, cap, decoded, plain);
            assert(!ZSTD_isError(compressed));
            ZSTD_freeCCtx(ctx);
            free(decoded);
            store32(header + 32 + 4 * i, (uint32_t)plain);
            store32(header + 68 + 4 * i, (uint32_t)compressed);
        }
        assert(fwrite(zip, 1, compressed, payload) == compressed);
        free(zip);
    }
    assert(fwrite(outer, 1, sizeof(outer), result) == sizeof(outer));
    assert(fwrite(header, 1, sizeof(header), result) == sizeof(header));
    rewind(payload);
    unsigned char bytes[65536];
    size_t n;
    while ((n = fread(bytes, 1, sizeof(bytes), payload)))
        assert(fwrite(bytes, 1, n, result) == n);
    fclose(payload);
    rewind(result);
    rewind(source);
    return result;
}
static void small_tests(void) {
    FILE *raw = tmpfile();
    assert(raw);
    fixture(raw, 80, true);
    FILE *packed = encoded(raw), *out = tmpfile();
    assert(out);
    assert(decode(packed, out, op));
    same(raw, out);
    fclose(out);
    reject(packed, NULL);
    reject(packed, low);
    reject(packed, wrong_sci);
    /* Encoded size is protected metadata too: denied reads emit no counters. */
    int progress_pipe[2];
    assert(!pipe2(progress_pipe, O_NONBLOCK | O_CLOEXEC));
    char descriptor[32];
    snprintf(descriptor, sizeof(descriptor), "%d", progress_pipe[1]);
    assert(!setenv("QIHSE_CODEGRAPH_PROGRESS_FD", descriptor, 1));
    reject(packed, low);
    char event[512];
    assert(read(progress_pipe[0], event, sizeof(event)) < 0 && errno == EAGAIN);
    assert(!unsetenv("QIHSE_CODEGRAPH_PROGRESS_FD"));
    close(progress_pipe[0]);
    close(progress_pipe[1]);
    out = tmpfile();
    assert(out);
    cg_snapshot_checksum bad = checksum(packed);
    bad.algorithm = (cg_checksum_algorithm)99;
    assert(!cg_chunked_decode_checksum_snapshot(packed, out, op, &bad, 1u << 20, 1000));
    assert(!file_size(out));
    bad = checksum(packed);
    bad.hex[0] = bad.hex[0] == '0' ? '1' : '0';
    assert(!cg_chunked_decode_checksum_snapshot(packed, out, op, &bad, 1u << 20, 1000));
    assert(!file_size(out));
    fclose(out);
    out = tmpfile();
    assert(out);
    cg_snapshot_checksum good = checksum(packed);
    assert(!cg_chunked_decode_checksum_snapshot(packed, out, op, &good, 10, 1000) &&
           errno == EFBIG);
    assert(!file_size(out));
    fclose(out);
    out = tmpfile();
    assert(out);
    assert(!cg_chunked_decode_checksum_snapshot(packed, out, op, &good, 1u << 20, 1) &&
           errno == E2BIG);
    assert(!file_size(out));
    fclose(out);
    /* The public FILE cache and pushback cannot substitute another image. */
    out = tmpfile();
    assert(out);
    rewind(packed);
    assert(fgetc(packed) == 'Q');
    assert(ungetc('X', packed) == 'X');
    assert(cg_chunked_decode_checksum_snapshot(packed, out, op, &good, 1u << 20, 1000));
    same(raw, out);
    fclose(out);
    /* Each header byte mutation is rechecksummed to reach structural parsing. */
    const size_t offsets[] = {0, 7, 8, 16, 24, 28, 36, 63, 64, 72, 76, 80, 88, 96, 100, 172};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(*offsets); i++) {
        FILE *badfile = duplicate(packed);
        mutate(badfile, offsets[i], 255);
        reject(badfile, op);
        fclose(badfile);
    }
    FILE *bad_varint = rewrite_column(packed, 0, false);
    reject(bad_varint, op);
    fclose(bad_varint);
    FILE *bad_header = rewrite_column(packed, 7, true);
    reject(bad_header, op);
    fclose(bad_header);
    /* Limit denial precedes staging: a sparse encoded-size bomb cannot force a
     * whole-file copy when the untrusted outer declaration is tiny. */
    FILE *oversized = duplicate(packed);
    assert(!ftruncate(fileno(oversized), 100u << 20));
    out = tmpfile();
    assert(out);
    cg_snapshot_checksum declared = checksum(packed);
    assert(!cg_chunked_decode_checksum_snapshot(oversized, out, op, &declared, 1u << 20, 1000) &&
           errno == EFBIG);
    assert(!file_size(out));
    fclose(out);
    fclose(oversized);
    FILE *truncated = duplicate(packed);
    size_t len = file_size(truncated);
    assert(!ftruncate(fileno(truncated), (off_t)len - 1));
    reject(truncated, op);
    fclose(truncated);
    FILE *suffixed = duplicate(packed);
    assert(!fseeko(suffixed, 0, SEEK_END));
    assert(fputc('X', suffixed) != EOF);
    assert(!fflush(suffixed));
    reject(suffixed, op);
    fclose(suffixed);
    /* Outer aggregate labels cannot downgrade the independently checked columns. */
    FILE *downgraded = duplicate(packed);
    mutate(downgraded, 32, 0);
    mutate(downgraded, 33, 0);
    mutate(downgraded, 34, 0);
    mutate(downgraded, 35, 0);
    reject(downgraded, low);
    /* A forged chunk aggregate cannot hide the independently decoded labels. */
    for (size_t i = 168; i < 172; i++)
        mutate(downgraded, i, 0);
    reject(downgraded, low);
    fclose(downgraded);
    fclose(raw);
    fclose(packed);
    /* Empty streams and canonical/zero/expiry/tombstone/UINT64_MAX fields. */
    raw = tmpfile();
    assert(raw);
    packed = encoded(raw);
    out = tmpfile();
    assert(out);
    assert(decode(packed, out, op));
    same(raw, out);
    fclose(packed);
    fclose(out);
    assert(fputs("1 3 18446744073709551615 0 0 0 18446744073709551615\nkv\t!\n1 0 0 0 0 1 2\nz\n",
                 raw) >= 0);
    rewind(raw);
    packed = encoded(raw);
    out = tmpfile();
    assert(out);
    assert(decode(packed, out, op));
    same(raw, out);
    fclose(out);
    fclose(packed);
    fclose(raw);
    /* Duplicate IDs across chunks must fail even with different values. */
    raw = tmpfile();
    assert(raw);
    char *large = malloc(9u << 20);
    assert(large);
    memset(large, 'x', 9u << 20);
    for (int i = 0; i < 2; i++) {
        assert(fprintf(raw, "1 %u 0 0 0 0 %d\nk", 9u << 20, i + 1) > 0);
        assert(fwrite(large, 1, 9u << 20, raw) == 9u << 20);
        assert(fputc('\n', raw) != EOF);
    }
    free(large);
    rewind(raw);
    packed = encoded(raw);
    reject(packed, op);
    fclose(packed);
    fclose(raw);
    puts("PASS chunked exact bytes, numeric/header exceptions, bounds, duplicate keys, "
         "principal/SCI, checksum and malformed negatives");
}
static void storage_tests(const char *directory) {
    char path[4096];
    assert(snprintf(path, sizeof(path), "%s/snapshot.kv", directory) > 0);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    assert(qihse_kv_set_user(store, "n:abc", "HIGH-SECRET", 4, 2, op));
    assert(cg_storage_save_chunked(store, path, op));
    cg_snapshot_checksum sum;
    assert(cg_snapshot_checksum_file_user(path, op, CG_CHECKSUM_XXH3_128, &sum));
    cg_storage_info_t info;
    qihse_kv_store_t *read = cg_storage_open_checksum_info(path, op, 1u << 20, 100, &sum, &info);
    assert(read && info.chunked && info.packed && !info.dictionary && info.valid);
    assert(info.section_accounting_valid && info.storage_chunks == 1 && info.storage_sections == 9);
    assert(info.framing_encoded_bytes + info.metadata_encoded_bytes + info.body_encoded_bytes ==
           info.encoded_bytes);
    assert(info.metadata_encoded_bytes && info.body_encoded_bytes);
    char *value = qihse_kv_get_user(read, "n:abc", op);
    assert(value && !strcmp(value, "HIGH-SECRET"));
    free(value);
    qihse_kv_store_destroy(read);
    assert(!cg_storage_open_checksum_info(path, low, 1u << 20, 100, &sum, &info) && !info.valid);
    assert(!cg_storage_open_checksum_info(path, wrong_sci, 1u << 20, 100, &sum, &info) &&
           !info.valid);
    read = qihse_kv_store_create_user(op);
    assert(read);
    assert(cg_storage_load_checksum_info(read, path, op, &sum, &info) && info.chunked);
    value = qihse_kv_get_user(read, "n:abc", op);
    assert(value && !strcmp(value, "HIGH-SECRET"));
    free(value);
    qihse_kv_store_destroy(read);
    qihse_kv_store_destroy(store);
    puts("PASS chunked storage save/open/load and low-clearance/wrong-SCI negatives");
}
static double seconds(void) {
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_sec + t.tv_nsec / 1e9;
}
static bool baseline_zstd(FILE *in, FILE *out, qihse_user_t *principal) {
    if (!principal || !qihse_auth_user_is_active(principal))
        return false;
    size_t raw = file_size(in);
    unsigned char header[16] = {0};
    memcpy(header, "QCGZ0001", 8);
    for (size_t i = 0; i < 8; i++)
        header[15 - i] = (unsigned char)((uint64_t)raw >> (8 * i));
    if (fwrite(header, 1, sizeof(header), out) != sizeof(header))
        return false;
    ZSTD_CCtx *ctx = ZSTD_createCCtx();
    assert(ctx);
    unsigned char input[65536], output[65536];
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, 9)));
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, 23)));
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)));
    assert(!ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(ctx, raw)));
    for (;;) {
        size_t n = fread(input, 1, sizeof(input), in);
        assert(!ferror(in));
        ZSTD_inBuffer src = {input, n, 0};
        ZSTD_EndDirective mode = feof(in) ? ZSTD_e_end : ZSTD_e_continue;
        size_t remaining;
        do {
            ZSTD_outBuffer dst = {output, sizeof(output), 0};
            remaining = ZSTD_compressStream2(ctx, &dst, &src, mode);
            assert(!ZSTD_isError(remaining));
            assert(fwrite(output, 1, dst.pos, out) == dst.pos);
        } while (src.pos < src.size || (mode == ZSTD_e_end && remaining));
        if (mode == ZSTD_e_end)
            break;
    }
    ZSTD_freeCCtx(ctx);
    return !fflush(out) && qihse_auth_user_is_active(principal);
}
static bool baseline_decode_zstd(FILE *in, FILE *out, qihse_user_t *principal) {
    /* Benchmark-only raw decompression of the public synthetic corpus. This
     * helper permits only a fully cleared principal, never a low-label reader. */
    if (!principal || !qihse_auth_user_is_active(principal) ||
        !qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX))
        return false;
    cg_snapshot_checksum before = checksum(in);
    unsigned char header[16];
    assert(fread(header, 1, sizeof(header), in) == sizeof(header));
    assert(!memcmp(header, "QCGZ0001", 8));
    uint64_t expected = 0;
    for (size_t i = 8; i < 16; i++)
        expected = expected << 8 | header[i];
    assert(expected <= CG_CHUNKED_MAX_RAW_BYTES);
    ZSTD_DCtx *ctx = ZSTD_createDCtx();
    assert(ctx);
    assert(!ZSTD_isError(ZSTD_DCtx_setParameter(ctx, ZSTD_d_windowLogMax, 23)));
    unsigned char input[65536], output[65536];
    size_t total = 0, n;
    bool ended = false;
    while ((n = fread(input, 1, sizeof(input), in))) {
        assert(!ended && qihse_auth_user_is_active(principal));
        ZSTD_inBuffer src = {input, n, 0};
        while (src.pos < src.size) {
            ZSTD_outBuffer dst = {output, sizeof(output), 0};
            size_t remaining = ZSTD_decompressStream(ctx, &dst, &src);
            assert(!ZSTD_isError(remaining) && dst.pos <= expected - total);
            total += dst.pos;
            assert(fwrite(output, 1, dst.pos, out) == dst.pos);
            if (!remaining) {
                assert(src.pos == src.size);
                ended = true;
                break;
            }
        }
    }
    assert(!ferror(in) && ended && total == expected);
    ZSTD_freeDCtx(ctx);
    cg_snapshot_checksum after = checksum(in);
    return !strcmp(before.hex, after.hex) && !fflush(out) && qihse_auth_user_is_active(principal);
}
static void benchmark(const char *mode, const char *source, const char *destination) {
    FILE *in = fopen(source, "rb"), *out = fopen(destination, "w+b");
    assert(in && out);
    size_t input = file_size(in);
    double start = seconds();
    if (!strcmp(mode, "--encode-v4"))
        assert(cg_chunked_encode_snapshot(in, out, op, (size_t)CG_CHUNKED_MAX_RAW_BYTES,
                                          CG_CHUNKED_MAX_RECORDS));
    else if (!strcmp(mode, "--encode-v3"))
        assert(cg_dictionary_encode_snapshot(in, out, op, (size_t)CG_CHUNKED_MAX_RAW_BYTES,
                                             CG_CHUNKED_MAX_RECORDS));
    else if (!strcmp(mode, "--encode-zstd"))
        assert(baseline_zstd(in, out, op));
    else if (!strcmp(mode, "--decode-v4"))
        assert(decode(in, out, op));
    else if (!strcmp(mode, "--decode-zstd"))
        assert(baseline_decode_zstd(in, out, op));
    else
        abort();
    double elapsed = seconds() - start;
    size_t output = file_size(out);
    struct rusage usage;
    assert(!getrusage(RUSAGE_SELF, &usage));
    printf("{\"mode\":\"%s\",\"input_bytes\":%zu,\"output_bytes\":%zu,\"seconds\":%.6f,\"peak_rss_"
           "kib\":%ld}\n",
           mode, input, output, elapsed, usage.ru_maxrss);
    fclose(in);
    fclose(out);
}
static int cleanup(const char *p, const struct stat *st, int type, struct FTW *walk) {
    (void)st;
    (void)type;
    (void)walk;
    return remove(p);
}
int main(int argc, char **argv) {
    umask(0077);
    char directory[4096];
    const char *tmp = getenv("TMPDIR");
    assert(snprintf(directory, sizeof(directory), "%s/codegraph-chunked-tests-XXXXXX",
                    tmp && *tmp ? tmp : ".") < (int)sizeof(directory));
    assert(mkdtemp(directory));
    assert(!setenv("QIHSE_DATA_DIR", directory, 1));
    assert(!setenv("QIHSE_FIPS_MODE", "disabled", 1));
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    op = qihse_auth_authenticate_id(0, PASSWORD);
    assert(op);
    assert(qihse_auth_create_user(op, 681, QIHSE_ROLE_GUEST, 0, 0, PASSWORD, false));
    assert(qihse_auth_create_user(op, 682, QIHSE_ROLE_ANALYST, 4, 0, PASSWORD, false));
    low = qihse_auth_authenticate_id(681, PASSWORD);
    wrong_sci = qihse_auth_authenticate_id(682, PASSWORD);
    assert(low && wrong_sci);
    if (argc == 4 && !strcmp(argv[1], "--generate")) {
        FILE *out = fopen(argv[2], "wb");
        assert(out);
        fixture(out, (size_t)strtoull(argv[3], NULL, 10), false);
        printf("{\"generated_bytes\":%zu}\n", file_size(out));
        fclose(out);
    } else if (argc == 4)
        benchmark(argv[1], argv[2], argv[3]);
    else if (argc == 3 && !strcmp(argv[1], "--large")) {
        FILE *raw = tmpfile();
        assert(raw);
        fixture(raw, (size_t)strtoull(argv[2], NULL, 10), false);
        size_t bytes = file_size(raw);
        assert(bytes > 64u << 20);
        FILE *packed = encoded(raw), *out = tmpfile();
        assert(out);
        assert(decode(packed, out, op));
        same(raw, out);
        printf("PASS large fixture: raw=%zu encoded=%zu\n", bytes, file_size(packed));
        fclose(raw);
        fclose(packed);
        fclose(out);
    } else {
        small_tests();
        storage_tests(directory);
    }
    qihse_audit_shutdown();
    assert(!nftw(directory, cleanup, 16, FTW_DEPTH | FTW_PHYS));
    return 0;
}
