#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_dictionary.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zstd.h>

#define PASSWORD "CodegraphDictionaryStream1!"
static int clean_test(const char *path, const struct stat *st, int type, struct FTW *walk) {
    (void)st; (void)type; (void)walk; return remove(path);
}
static size_t file_size(FILE *f) {
    assert(fseeko(f, 0, SEEK_END) == 0);
    off_t n = ftello(f); assert(n >= 0);
    assert(fseeko(f, 0, SEEK_SET) == 0);
    return (size_t)n;
}
static void raw_equal(FILE *left, FILE *right) {
    size_t a = file_size(left), b = file_size(right); assert(a == b);
    for (size_t i = 0; i < a; i++) assert(fgetc(left) == fgetc(right));
    assert(fgetc(left) == EOF && fgetc(right) == EOF);
    rewind(left); rewind(right);
}
static FILE *copy_bytes(FILE *source) {
    FILE *out = tmpfile(); assert(out);
    assert(setvbuf(out, NULL, _IONBF, 0) == 0);
    rewind(source);
    int ch;
    while ((ch = fgetc(source)) != EOF) assert(fputc(ch, out) != EOF);
    assert(fflush(out) == 0); rewind(out); rewind(source);
    return out;
}
static void set_byte(FILE *f, off_t offset, unsigned char value) {
    assert(fseeko(f, offset, SEEK_SET) == 0);
    assert(fputc(value, f) != EOF);
    assert(fflush(f) == 0); rewind(f);
}
static void stream_digest(FILE *input, char hex[65]) {
    rewind(input);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); assert(ctx);
    assert(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    unsigned char bytes[4096], digest[32]; size_t n; unsigned int length;
    while ((n = fread(bytes, 1, sizeof(bytes), input)))
        assert(EVP_DigestUpdate(ctx, bytes, n) == 1);
    assert(!ferror(input));
    assert(EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32);
    EVP_MD_CTX_free(ctx);
    for (size_t i = 0; i < 32; ++i) sprintf(hex + 2*i, "%02x", digest[i]);
    rewind(input);
}
/* Only test-generated fixtures are trusted here. Rehashing malformed fixtures
 * deliberately tests parser bounds after the separate trusted-digest check. */
static bool decode_fixture(FILE *input, FILE *out, qihse_user_t *user,
                            size_t bytes, size_t records) {
    char expected[65]; stream_digest(input, expected);
    return cg_dictionary_decode_snapshot(input, out, user, expected, bytes, records);
}
static uint32_t read32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t read64(const unsigned char *p) {
    uint64_t n = 0; for (size_t i = 0; i < 8; ++i) n = (n << 8) | p[i]; return n;
}
static void write_number(unsigned char *p, uint64_t n, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i) p[bytes-i-1] = (unsigned char)(n >> (8*i));
}
/* Build checksummed malformed frames so parser tests pass integrity checking
 * and reach the token bounds, rather than merely failing Zstd's checksum. */
static FILE *rewrite_frame(FILE *source, bool relabel,
                           const unsigned char *tokens, size_t token_size) {
    unsigned char header[56]; rewind(source);
    assert(fread(header, 1, sizeof(header), source) == sizeof(header));
    size_t meta_zip = read32(header + 36), body_zip = read32(header + 40);
    unsigned char *meta = malloc(meta_zip), *body = malloc(body_zip); assert(meta && body);
    assert(fread(meta, 1, meta_zip, source) == meta_zip);
    assert(fread(body, 1, body_zip, source) == body_zip);
    unsigned char *plain = NULL;
    if (relabel) {
        token_size = (size_t)read64(header + 16);
        plain = malloc(token_size); assert(plain);
        assert(ZSTD_decompress(plain, token_size, meta, meta_zip) == token_size);
        bool changed = false;
        for (size_t i = 0; i + 5 <= token_size; ++i) {
            if (!memcmp(plain + i, " 4 2 ", 5)) {
                plain[i+1] = '0'; plain[i+3] = '0'; changed = true;
            }
        }
        assert(changed); tokens = plain;
    }
    size_t capacity = ZSTD_compressBound(token_size);
    unsigned char *encoded = malloc(capacity); assert(encoded);
    ZSTD_CCtx *ctx = ZSTD_createCCtx(); assert(ctx);
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)));
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, 23)));
    size_t length = ZSTD_compress2(ctx, encoded, capacity, tokens, token_size);
    assert(!ZSTD_isError(length)); ZSTD_freeCCtx(ctx);
    write_number(header + (relabel ? 36 : 40), length, 4);
    if (!relabel) write_number(header + 48, token_size, 8);
    FILE *out = tmpfile(); assert(out);
    assert(fwrite(header, 1, sizeof(header), out) == sizeof(header));
    assert(fwrite(relabel ? encoded : meta, 1, relabel ? length : meta_zip, out) ==
           (relabel ? length : meta_zip));
    assert(fwrite(relabel ? body : encoded, 1, relabel ? body_zip : length, out) ==
           (relabel ? body_zip : length));
    assert(fflush(out) == 0); rewind(out); rewind(source);
    free(meta); free(body); free(plain); free(encoded);
    return out;
}
static uint32_t fixture_varint(const unsigned char *b, size_t size, size_t *offset) {
    uint32_t value = 0;
    for (unsigned shift = 0; shift <= 28; shift += 7) {
        assert(*offset < size);
        unsigned char c = b[(*offset)++];
        value |= (uint32_t)(c & 127) << shift;
        if (!(c & 128)) return value;
    }
    abort();
}
/* Inspect test-generated dictionary entries, not configured storage. */
static void mixed_digest_dictionary(FILE *packed) {
    unsigned char h[56]; rewind(packed);
    assert(fread(h, 1, sizeof(h), packed) == sizeof(h));
    assert(read32(h + 44) == CG_DICTIONARY_FEATURE_DIGEST128);
    size_t encoded = read32(h + 40), plain_size = (size_t)read64(h + 48);
    unsigned char *zip = malloc(encoded), *plain = malloc(plain_size);
    assert(zip && plain);
    assert(fseeko(packed, 56 + (off_t)read32(h + 36), SEEK_SET) == 0);
    assert(fread(zip, 1, encoded, packed) == encoded);
    assert(ZSTD_decompress(plain, plain_size, zip, encoded) == plain_size);
    size_t offset = 0, short_count = 0, long_count = 0;
    uint32_t count = fixture_varint(plain, plain_size, &offset);
    for (uint32_t i = 0; i < count; ++i) {
        assert(offset < plain_size);
        unsigned kind = plain[offset++];
        size_t length;
        if (kind == 2) { length = 16; ++short_count; }
        else if (kind == 1) { length = 32; ++long_count; }
        else { assert(kind == 0); length = fixture_varint(plain, plain_size, &offset); }
        assert(length <= plain_size - offset); offset += length;
    }
    assert(short_count >= 2 && long_count >= 2);
    free(zip); free(plain); rewind(packed);
}
static void legacy_features_zero(qihse_user_t *op) {
    FILE *raw = tmpfile(), *packed = tmpfile(), *decoded = tmpfile();
    assert(raw && packed && decoded);
    assert(fputs("1 6 0 0 0 0 1\nklegacy\n", raw) >= 0);
    assert(fflush(raw) == 0); rewind(raw);
    assert(cg_dictionary_encode_snapshot(raw, packed, op, 64u << 20, 200000));
    unsigned char h[56]; rewind(packed);
    assert(fread(h, 1, sizeof(h), packed) == sizeof(h) && read32(h + 44) == 0);
    assert(decode_fixture(packed, decoded, op, 64u << 20, 200000));
    raw_equal(raw, decoded); fclose(raw); fclose(packed); fclose(decoded);
}
static void stale_stdio_cache_denied(qihse_user_t *op, qihse_user_t *low) {
    FILE *high_raw = tmpfile(), *public_raw = tmpfile();
    FILE *high = tmpfile(), *public = tmpfile();
    assert(high_raw && public_raw && high && public);
    assert(fputs("6 18 0 4 2 0 1\nsecretCLASSIFIED-PAYLOAD\n", high_raw) >= 0);
    assert(fputs("6 18 0 0 0 0 1\nsecretCLASSIFIED-PAYLOAD\n", public_raw) >= 0);
    assert(fflush(high_raw) == 0 && fflush(public_raw) == 0);
    rewind(high_raw); rewind(public_raw);
    assert(cg_dictionary_encode_snapshot(high_raw, high, op, 64u << 20, 200000));
    assert(cg_dictionary_encode_snapshot(public_raw, public, op, 64u << 20, 200000));
    size_t size = file_size(high);
    assert(file_size(public) == size);
    char expected[65]; stream_digest(high, expected);
    unsigned char *bytes = malloc(size); char *cache = malloc(size + 64);
    FILE *attack = tmpfile(), *output = tmpfile();
    assert(bytes && cache && attack && output);
    assert(setvbuf(attack, cache, _IOFBF, size + 64) == 0);
    assert(fread(bytes, 1, size, public) == size);
    assert(pwrite(fileno(attack), bytes, size, 0) == (ssize_t)size);
    int first = fgetc(attack); assert(first != EOF);
    assert(ungetc(first, attack) == first && ftello(attack) == 0);
    /* FILE now caches the permissively labelled frame at logical offset 0.
     * Its descriptor is overwritten with the high-label trusted frame, whose
     * digest/stat are stable before entry. Decoder must consume that frame. */
    assert(fread(bytes, 1, size, high) == size);
    assert(pwrite(fileno(attack), bytes, size, 0) == (ssize_t)size);
    assert(ftello(attack) == 0);
    assert(!cg_dictionary_decode_snapshot(attack, output, low, expected, 64u << 20, 200000));
    assert(file_size(output) == 0);
    cg_snapshot_checksum xxh_expected;
    assert(cg_snapshot_checksum_buffer_user(bytes,size,op,CG_CHECKSUM_XXH3_128,&xxh_expected));
    assert(!cg_dictionary_decode_checksum_snapshot(attack,output,low,&xxh_expected,64u<<20,200000));
    assert(file_size(output)==0);
    fclose(attack); fclose(output); free(bytes); free(cache);
    fclose(high_raw); fclose(public_raw); fclose(high); fclose(public);
}
int main(void) {
    char root[] = "./qihse-codegraph-dictionary-test-XXXXXX";
    assert(mkdtemp(root));
    char state[sizeof(root) + 16], export_path[sizeof(root) + 16];
    snprintf(state, sizeof(state), "%s/server", root);
    snprintf(export_path, sizeof(export_path), "%s/export.kv", root);
    assert(mkdir(state, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", state, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD); assert(op);
    assert(qihse_auth_create_user(op, 621, QIHSE_ROLE_GUEST, 0, 0, PASSWORD, false));
    assert(qihse_auth_create_user(op, 622, QIHSE_ROLE_ANALYST, 4, 0, PASSWORD, false));
    qihse_user_t *low = qihse_auth_authenticate_id(621, PASSWORD); assert(low);
    qihse_user_t *wrong_sci = qihse_auth_authenticate_id(622, PASSWORD); assert(wrong_sci);
    stale_stdio_cache_denied(op, low);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op); assert(store);
    char node[67] = "n:", edge[67] = "e:";
    memset(node + 2, 'a', 64); node[66] = 0;
    memset(edge + 2, 'b', 64); edge[66] = 0;
    const char *unknown = "{\"future\":{\"opaque\":\"preserved exactly\"},\"confidence\":0.7}";
    assert(qihse_kv_set_user(store, "_meta", unknown, 0, 0, op));
    assert(qihse_kv_set_user(store, node, "public node", 0, 0, op));
    assert(qihse_kv_set_user(store, edge, "CLASSIFIED-PAYLOAD", 4, 2, op));
    assert(qihse_kv_set_user(store, "future:literal", "other opaque bytes", 0, 0, op));
    for (unsigned i = 0; i < 128; ++i) {
        unsigned char digest[32]; unsigned int length;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new(); assert(ctx);
        assert(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
        assert(EVP_DigestUpdate(ctx, &i, sizeof(i)) == 1);
        assert(EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32);
        EVP_MD_CTX_free(ctx);
        char key[67] = "n:", value[1024];
        for (size_t j = 0; j < 32; ++j) sprintf(key + 2 + 2*j, "%02x", digest[j]);
        snprintf(value, sizeof(value),
                 "{ \"id\":\"%s\", \"future\": [\"same repeated path/to/file\", 0.7000, 1e-9], \"source\":\"%s\", \"ordinal\":%u}",
                 key + 2, key + 2, i);
        assert(qihse_kv_set_user(store, key, value, 0, 0, op));
    }
    /* A 128-bit prefix collision must never merge distinct full identities.
     * Token lookup compares all 256 bits, lengths and kind; references are dense
     * dictionary positions, never truncated hashes. */
    char collision_a[67] = "n:", collision_b[67] = "n:";
    memset(collision_a + 2, 'c', 64); collision_a[66] = 0;
    memcpy(collision_b, collision_a, sizeof(collision_a));
    collision_b[65] = 'd';
    assert(qihse_kv_set_user(store, collision_a, "collision-prefix-first", 0, 0, op));
    assert(qihse_kv_set_user(store, collision_b, "collision-prefix-second", 0, 0, op));
    const char *short_a = "n:0123456789abcdef0123456789abcdef";
    const char *short_b = "n:0123456789abcdef0123456789abcdee";
    assert(qihse_kv_set_user(store, short_a,
        "{\"id\":\"0123456789abcdef0123456789abcdef\",\"source\":\"0123456789abcdef0123456789abcdee\"}", 0, 0, op));
    assert(qihse_kv_set_user(store, short_b, "short-second", 0, 0, op));
    assert(qihse_kv_save_user(store, export_path, op) == 0);
    assert(qihse_kv_save_user(store, export_path, low) != 0);
    FILE *raw = fopen(export_path, "rb"); assert(raw);
    FILE *packed = tmpfile(); assert(packed);
    FILE *decoded = tmpfile(); assert(decoded);
    assert(!cg_dictionary_encode_snapshot(raw, packed, NULL, 64u << 20, 200000));
    assert(file_size(packed) == 0);
    assert(!cg_dictionary_encode_snapshot(raw, packed, low, 64u << 20, 200000));
    assert(file_size(packed) == 0);
    rewind(raw);
    assert(cg_dictionary_encode_snapshot(raw, packed, op, 64u << 20, 200000));
    assert(file_size(packed) > 56);
    mixed_digest_dictionary(packed);
    legacy_features_zero(op);
    /* The new XXH3 adapter must check all labels before emitting any bytes. */
    size_t xxh_size=file_size(packed);unsigned char *xxh_bytes=malloc(xxh_size);assert(xxh_bytes);
    assert(fread(xxh_bytes,1,xxh_size,packed)==xxh_size);rewind(packed);
    cg_snapshot_checksum xxh_expected;
    assert(cg_snapshot_checksum_buffer_user(xxh_bytes,xxh_size,op,CG_CHECKSUM_XXH3_128,&xxh_expected));
    free(xxh_bytes);
    assert(!cg_dictionary_decode_checksum_snapshot(packed,decoded,low,&xxh_expected,64u<<20,200000));
    assert(errno==EACCES && file_size(decoded)==0);
    assert(!cg_dictionary_decode_checksum_snapshot(packed,decoded,wrong_sci,&xxh_expected,64u<<20,200000));
    assert(errno==EACCES && file_size(decoded)==0);
    assert(!cg_dictionary_decode_checksum_snapshot(packed,decoded,NULL,&xxh_expected,64u<<20,200000));
    assert(file_size(decoded)==0);
    cg_snapshot_checksum wrong_xxh=xxh_expected;wrong_xxh.hex[0]=wrong_xxh.hex[0]=='0'?'1':'0';
    assert(!cg_dictionary_decode_checksum_snapshot(packed,decoded,op,&wrong_xxh,64u<<20,200000));
    assert(file_size(decoded)==0);
    assert(cg_dictionary_decode_checksum_snapshot(packed,decoded,op,&xxh_expected,64u<<20,200000));
    raw_equal(raw,decoded);assert(ftruncate(fileno(decoded),0)==0);rewind(decoded);
    char trusted_digest[65]; stream_digest(packed, trusted_digest);
    assert(!cg_dictionary_decode_snapshot(packed, decoded, op, NULL, 64u << 20, 200000));
    assert(file_size(decoded) == 0); rewind(packed);
    assert(!decode_fixture(packed, decoded, NULL, 64u << 20, 200000));
    assert(file_size(decoded) == 0);
    rewind(packed);
    assert(!decode_fixture(packed, decoded, low, 64u << 20, 200000));
    int denied_errno = errno;
    /* Decoder uses a verified private copy, without consuming caller stdio. */
    off_t denied_offset = ftello(packed); assert(denied_offset == 0);
    assert(denied_errno == EACCES && file_size(decoded) == 0);
    rewind(packed);
    assert(!decode_fixture(packed, decoded, wrong_sci, 64u << 20, 200000));
    assert(errno == EACCES && file_size(decoded) == 0);
    rewind(packed);
    assert(!decode_fixture(packed, decoded, op, 1, 200000));
    assert(errno == EFBIG);
    assert(file_size(decoded) == 0);
    rewind(packed);
    assert(!decode_fixture(packed, decoded, op, 64u << 20, 1));
    assert(errno == E2BIG && file_size(decoded) == 0);
    rewind(packed);
    assert(decode_fixture(packed, decoded, op, 64u << 20, 200000));
    raw_equal(raw, decoded);
    char *mapped = NULL; size_t mapped_size = 0;
    FILE *memory_output = open_memstream(&mapped, &mapped_size); assert(memory_output);
    rewind(packed);
    assert(decode_fixture(packed, memory_output, op, 64u << 20, 200000));
    assert(fflush(memory_output) == 0 && mapped_size == file_size(raw));
    for (size_t i = 0; i < mapped_size; i++) assert(mapped[i] == fgetc(raw));
    fclose(memory_output); free(mapped); rewind(raw);
    rewind(decoded);
    qihse_kv_store_t *opened = qihse_kv_open_snapshot_user(decoded, op, 64u << 20, 200000);
    assert(opened);
    char *actual = qihse_kv_get_user(opened, "_meta", op);
    assert(actual && strcmp(actual, unknown) == 0); free(actual);
    actual = qihse_kv_get_user(opened, edge, op);
    assert(actual && strcmp(actual, "CLASSIFIED-PAYLOAD") == 0); free(actual);
    actual = qihse_kv_get_user(opened, collision_a, op);
    assert(actual && strcmp(actual, "collision-prefix-first") == 0); free(actual);
    actual = qihse_kv_get_user(opened, collision_b, op);
    assert(actual && strcmp(actual, "collision-prefix-second") == 0); free(actual);
    assert(qihse_kv_get_user(opened, edge, low) == NULL);
    actual = qihse_kv_get_user(opened, short_b, op);
    assert(actual && !strcmp(actual, "short-second")); free(actual);
    actual = qihse_kv_get_user(opened, short_a, op);
    assert(actual && strstr(actual, "0123456789abcdef0123456789abcdef")); free(actual);
    qihse_kv_store_destroy(opened);
    fclose(decoded);
    FILE *forged_labels = rewrite_frame(packed, true, NULL, 0);
    decoded = tmpfile(); assert(decoded);
    assert(!cg_dictionary_decode_snapshot(forged_labels, decoded, low, trusted_digest,
                                        64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(forged_labels);
    const unsigned char invalid[][4] = {
        {0, 3, 0, 0},       /* Reference to a missing dictionary entry. */
        {0, 128, 0, 0},     /* Non-canonical varint. */
        {0, 2, 'a', 0},     /* Expansion shorter than declared body. */
        {255, 255, 255, 255} /* Truncated dictionary count. */
    };
    const size_t lengths[] = {2, 3, 3, 4};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(*lengths); ++i) {
        FILE *malformed = rewrite_frame(packed, false, invalid[i], lengths[i]);
        decoded = tmpfile(); assert(decoded);
        assert(!decode_fixture(malformed, decoded, op, 64u << 20, 200000));
        assert(file_size(decoded) == 0); fclose(decoded); fclose(malformed);
    }
    /* Deterministic bounded mutation lane: valid Zstd frames and test-trusted
     * hashes force random token streams through the new dictionary decoder. */
    uint32_t random = 0x71c9a31u;
    for (size_t trial = 0; trial < 256; ++trial) {
        unsigned char tokens[256];
        size_t length = 1 + trial;
        for (size_t i = 0; i < length; ++i) {
            random ^= random << 13; random ^= random >> 17; random ^= random << 5;
            tokens[i] = (unsigned char)random;
        }
        FILE *malformed = rewrite_frame(packed, false, tokens, length);
        decoded = tmpfile(); assert(decoded);
        assert(!decode_fixture(malformed, decoded, op, 64u << 20, 200000));
        assert(file_size(decoded) == 0); fclose(decoded); fclose(malformed);
    }
    /* Feature removal and unknown feature bits must not reinterpret kind 2. */
    for (unsigned bit = 0; bit < 2; ++bit) {
        FILE *bad_feature = copy_bytes(packed);
        set_byte(bad_feature, 47, bit ? 2 : 0);
        decoded = tmpfile(); assert(decoded);
        assert(!decode_fixture(bad_feature, decoded, op, 64u << 20, 200000));
        assert(file_size(decoded) == 0); fclose(decoded); fclose(bad_feature);
    }
    for (unsigned variant = 0; variant < 2; ++variant) {
        unsigned char token_bytes[18] = {1, 2};
        token_bytes[1] = variant ? 3 : 2;
        size_t length = variant ? sizeof(token_bytes) : sizeof(token_bytes) - 1;
        FILE *malformed = rewrite_frame(packed, false, token_bytes, length);
        decoded = tmpfile(); assert(decoded);
        assert(!decode_fixture(malformed, decoded, op, 64u << 20, 200000));
        assert(file_size(decoded) == 0); fclose(decoded); fclose(malformed);
    }
    FILE *bad = copy_bytes(packed);
    set_byte(bad, 0, 'X');
    decoded = tmpfile(); assert(decoded);
    assert(!cg_dictionary_decode_snapshot(bad, decoded, op, trusted_digest, 64u << 20, 200000));
    assert(file_size(decoded) == 0); rewind(bad);
    assert(!decode_fixture(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(bad);
    /* Duplicate record keys are rejected before any output is exposed. */
    bad = tmpfile(); assert(bad);
    FILE *double_raw = tmpfile(); assert(double_raw);
    rewind(raw);
    int byte;
    while ((byte = fgetc(raw)) != EOF) assert(fputc(byte, double_raw) != EOF);
    rewind(raw);
    while ((byte = fgetc(raw)) != EOF) assert(fputc(byte, double_raw) != EOF);
    assert(fflush(double_raw) == 0); rewind(double_raw);
    assert(cg_dictionary_encode_snapshot(double_raw, bad, op, 64u << 20, 200000));
    rewind(bad);
    decoded = tmpfile(); assert(decoded);
    assert(!decode_fixture(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0);
    fclose(decoded); fclose(bad); fclose(double_raw); rewind(raw);
    bad = copy_bytes(packed);
    size_t encoded_size = file_size(bad);
    assert(ftruncate(fileno(bad), (off_t)encoded_size - 1) == 0); rewind(bad);
    assert(file_size(bad) == encoded_size - 1);
    decoded = tmpfile(); assert(decoded);
    assert(!decode_fixture(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(bad);
    bad = copy_bytes(packed);
    assert(fseeko(bad, 0, SEEK_END) == 0 && fputc('x', bad) != EOF);
    assert(fflush(bad) == 0); rewind(bad);
    decoded = tmpfile(); assert(decoded);
    assert(!decode_fixture(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(bad);
    bad = copy_bytes(packed);
    set_byte(bad, 8, 0xff); /* advertised raw length */
    decoded = tmpfile(); assert(decoded);
    assert(!decode_fixture(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(bad);
    fclose(raw); fclose(packed);
    qihse_kv_store_destroy(store);

    /* A Guest must retain access to a fully public snapshot. */
    qihse_kv_store_t *public_store = qihse_kv_store_create_user(op);
    assert(public_store);
    (void)qihse_kv_clear_user(public_store, op);
    char empty_path[sizeof(root) + 16];
    snprintf(empty_path, sizeof(empty_path), "%s/empty.kv", root);
    assert(qihse_kv_save_user(public_store, empty_path, op) == 0);
    FILE *empty_raw = fopen(empty_path, "rb"), *empty_packed = tmpfile(),
         *empty_decoded = tmpfile();
    assert(empty_raw && empty_packed && empty_decoded);
    assert(cg_dictionary_encode_snapshot(empty_raw, empty_packed, op, 64u << 20, 200000));
    rewind(empty_packed);
    assert(decode_fixture(empty_packed, empty_decoded, low, 64u << 20, 200000));
    raw_equal(empty_raw, empty_decoded);
    fclose(empty_raw); fclose(empty_packed); fclose(empty_decoded);
    assert(qihse_kv_set_user(public_store, node, "public node", 0, 0, op));
    assert(qihse_kv_set_user(public_store, "_meta", unknown, 0, 0, op));
    char public_path[sizeof(root) + 16];
    snprintf(public_path, sizeof(public_path), "%s/public.kv", root);
    assert(qihse_kv_save_user(public_store, public_path, low) == 0);
    FILE *public_raw = fopen(public_path, "rb"); assert(public_raw);
    FILE *public_packed = tmpfile(), *public_decoded = tmpfile();
    assert(public_packed && public_decoded);
    assert(cg_dictionary_encode_snapshot(public_raw, public_packed, low, 64u << 20, 200000));
    rewind(public_packed);
    assert(decode_fixture(public_packed, public_decoded, low, 64u << 20, 200000));
    raw_equal(public_raw, public_decoded);
    rewind(public_decoded);
    opened = qihse_kv_open_snapshot_user(public_decoded, low, 64u << 20, 200000);
    assert(opened);
    actual = qihse_kv_get_user(opened, node, low);
    assert(actual && strcmp(actual, "public node") == 0); free(actual);
    qihse_kv_store_destroy(opened);
    assert(qihse_auth_destroy_user(op, 621));
    rewind(public_packed);
    FILE *revoked_output = tmpfile(); assert(revoked_output);
    assert(!decode_fixture(public_packed, revoked_output, low, 64u << 20, 200000));
    assert(file_size(revoked_output) == 0); fclose(revoked_output);
    fclose(public_raw); fclose(public_packed); fclose(public_decoded);
    qihse_kv_store_destroy(public_store);
    qihse_audit_shutdown();
    assert(nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CodeGraph packed-v3 dictionary: exact authenticated bytes, denial and corruption PASS");
    return 0;
}
