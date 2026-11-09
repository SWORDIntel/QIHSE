#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_packed.h"
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

#define PASSWORD "CodegraphPackedStream1!"
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
static void number(unsigned char *p, uint64_t n, size_t length) {
    for (size_t i = 0; i < length; ++i) p[length-i-1] = (unsigned char)(n >> (8*i));
}
static size_t frame(const unsigned char *input, size_t length,
                     unsigned char *output, size_t capacity) {
    ZSTD_CCtx *ctx = ZSTD_createCCtx(); assert(ctx);
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)));
    assert(!ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, 23)));
    size_t n = ZSTD_compress2(ctx, output, capacity, input, length);
    assert(!ZSTD_isError(n)); ZSTD_freeCCtx(ctx); return n;
}
static FILE *legacy_digest_fixture(bool duplicate) {
    unsigned char table[128], body[160], meta_zip[256], body_zip[256];
    size_t tn = 0, bn = 0, raw = 0;
    for (size_t i = 0; i < 2; ++i) {
        char header[64]; int n = snprintf(header, sizeof(header), "66 4 0 0 0 0 %zu\n", i+1);
        assert(n > 0); number(table+tn, (size_t)n, 2); tn += 2;
        memcpy(table+tn, header, (size_t)n); tn += (size_t)n;
        unsigned char tag = duplicate ? (i ? 1 : 0) : (unsigned char)(i+1);
        table[tn++] = tag;
        if (!tag) { body[bn++] = 'n'; body[bn++] = ':'; memset(body+bn, 'a', 64); bn += 64; }
        else { memset(body+bn, 0xaa, 32); bn += 32; }
        memcpy(body+bn, i ? "edge" : "node", 4); bn += 4;
        raw += (size_t)n + 66 + 4 + 1;
    }
    size_t mn = frame(table, tn, meta_zip, sizeof(meta_zip));
    size_t en = frame(body, bn, body_zip, sizeof(body_zip));
    unsigned char outer[48] = {0}; memcpy(outer, "QCGP0002", 8);
    number(outer+8, raw, 8); number(outer+16, tn, 8); number(outer+24, bn, 8);
    number(outer+32, 2, 4); number(outer+36, mn, 4); number(outer+40, en, 4);
    FILE *out = tmpfile(); assert(out);
    assert(fwrite(outer, 1, sizeof(outer), out) == sizeof(outer));
    assert(fwrite(meta_zip, 1, mn, out) == mn && fwrite(body_zip, 1, en, out) == en);
    assert(fflush(out) == 0); rewind(out); return out;
}
int main(void) {
    char root[] = "./qihse-codegraph-packed-test-XXXXXX";
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
    FILE *legacy_tagged = legacy_digest_fixture(false);
    qihse_kv_store_t *legacy_view = cg_packed_open_snapshot_user(legacy_tagged, low,
                                                               64u << 20, 200000, NULL);
    assert(legacy_view);
    char legacy_key[67] = "n:"; memset(legacy_key+2, 'a', 64); legacy_key[66] = 0;
    char *legacy_value = qihse_kv_get_user(legacy_view, legacy_key, low);
    assert(legacy_value && !strcmp(legacy_value, "node")); free(legacy_value);
    legacy_key[0] = 'e'; legacy_value = qihse_kv_get_user(legacy_view, legacy_key, low);
    assert(legacy_value && !strcmp(legacy_value, "edge")); free(legacy_value);
    qihse_kv_store_destroy(legacy_view); fclose(legacy_tagged);
    legacy_tagged = legacy_digest_fixture(true);
    assert(!cg_packed_open_snapshot_user(legacy_tagged, op, 64u << 20, 200000, NULL));
    rewind(legacy_tagged);
    FILE *duplicate_output = tmpfile(); assert(duplicate_output);
    assert(!cg_packed_decode_snapshot(legacy_tagged, duplicate_output, op, 64u << 20, 200000));
    assert(file_size(duplicate_output) == 0); fclose(duplicate_output); fclose(legacy_tagged);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op); assert(store);
    char node[67] = "n:", edge[67] = "e:";
    memset(node + 2, 'a', 64); node[66] = 0;
    memset(edge + 2, 'b', 64); edge[66] = 0;
    const char *unknown = "{\"future\":{\"opaque\":\"preserved exactly\"},\"confidence\":0.7}";
    assert(qihse_kv_set_user(store, "_meta", unknown, 0, 0, op));
    assert(qihse_kv_set_user(store, node, "public node", 0, 0, op));
    assert(qihse_kv_set_user(store, edge, "CLASSIFIED-PAYLOAD", 4, 2, op));
    assert(qihse_kv_set_user(store, "future:literal", "other opaque bytes", 0, 0, op));
    assert(qihse_kv_save_user(store, export_path, op) == 0);
    assert(qihse_kv_save_user(store, export_path, low) != 0);
    FILE *raw = fopen(export_path, "rb"); assert(raw);
    FILE *packed = tmpfile(); assert(packed);
    FILE *decoded = tmpfile(); assert(decoded);
    assert(!cg_packed_encode_snapshot(raw, packed, NULL, 64u << 20, 200000));
    assert(file_size(packed) == 0);
    assert(!cg_packed_encode_snapshot(raw, packed, low, 64u << 20, 200000));
    assert(file_size(packed) == 0);
    rewind(raw);
    assert(cg_packed_encode_snapshot(raw, packed, op, 64u << 20, 200000));
    assert(file_size(packed) > 48);
    /* New low-copy reader returns only an authenticated detached KV store. */
    assert(!cg_packed_open_snapshot_user(packed, NULL, 64u << 20, 200000, NULL));
    rewind(packed);
    assert(!cg_packed_open_snapshot_user(packed, low, 64u << 20, 200000, NULL));
    assert(errno == EACCES); rewind(packed);
    assert(!cg_packed_open_snapshot_user(packed, wrong_sci, 64u << 20, 200000, NULL));
    assert(errno == EACCES); rewind(packed);
    size_t stream_raw_bytes = 0;
    qihse_kv_store_t *view = cg_packed_open_snapshot_user(packed, op, 64u << 20, 200000,
                                                        &stream_raw_bytes);
    assert(view && stream_raw_bytes == file_size(raw));
    char *view_value = qihse_kv_get_user(view, "_meta", op);
    assert(view_value && !strcmp(view_value, unknown)); free(view_value);
    view_value = qihse_kv_get_user(view, edge, op);
    assert(view_value && !strcmp(view_value, "CLASSIFIED-PAYLOAD")); free(view_value);
    assert(qihse_kv_get_user(view, edge, low) == NULL);
    qihse_kv_record_meta_t before, after;
    assert(qihse_kv_meta_user(store, edge, op, &before));
    assert(qihse_kv_meta_user(view, edge, op, &after));
    assert(before.classification == after.classification &&
           before.sci_compartment == after.sci_compartment &&
           before.expire_time_ms == after.expire_time_ms &&
           before.change_seq == after.change_seq && before.flags == after.flags);
    qihse_kv_store_destroy(view); rewind(packed);
    assert(qihse_auth_create_user(op, 623, QIHSE_ROLE_ANALYST, 4, 2, PASSWORD, false));
    qihse_user_t *cleared = qihse_auth_authenticate_id(623, PASSWORD); assert(cleared);
    view = cg_packed_open_snapshot_user(packed, cleared, 64u << 20, 200000, NULL);
    assert(view);
    view_value = qihse_kv_get_user(view, edge, cleared);
    assert(view_value && !strcmp(view_value, "CLASSIFIED-PAYLOAD")); free(view_value);
    assert(qihse_auth_destroy_user(op, 623));
    assert(qihse_kv_get_user(view, edge, cleared) == NULL);
    qihse_kv_store_destroy(view); rewind(packed);
    assert(!cg_packed_open_snapshot_user(packed, cleared, 64u << 20, 200000, NULL));
    assert(errno == EACCES); rewind(packed);
    assert(!cg_packed_decode_snapshot(packed, decoded, NULL, 64u << 20, 200000));
    assert(file_size(decoded) == 0);
    rewind(packed);
    assert(!cg_packed_decode_snapshot(packed, decoded, low, 64u << 20, 200000));
    int denied_errno = errno;
    off_t denied_offset = ftello(packed); assert(denied_offset >= 48);
    assert((size_t)denied_offset < file_size(packed));
    assert(denied_errno == EACCES && file_size(decoded) == 0);
    rewind(packed);
    assert(!cg_packed_decode_snapshot(packed, decoded, wrong_sci, 64u << 20, 200000));
    assert(errno == EACCES && file_size(decoded) == 0);
    rewind(packed);
    assert(!cg_packed_decode_snapshot(packed, decoded, op, 1, 200000));
    assert(errno == EINVAL || errno == EFBIG);
    assert(file_size(decoded) == 0);
    rewind(packed);
    assert(!cg_packed_decode_snapshot(packed, decoded, op, 64u << 20, 1));
    assert(file_size(decoded) == 0);
    rewind(packed);
    assert(cg_packed_decode_snapshot(packed, decoded, op, 64u << 20, 200000));
    raw_equal(raw, decoded);
    char *mapped = NULL; size_t mapped_size = 0;
    FILE *memory_output = open_memstream(&mapped, &mapped_size); assert(memory_output);
    rewind(packed);
    assert(cg_packed_decode_snapshot(packed, memory_output, op, 64u << 20, 200000));
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
    assert(qihse_kv_get_user(opened, edge, low) == NULL);
    qihse_kv_store_destroy(opened);
    fclose(decoded);
    FILE *bad = copy_bytes(packed);
    set_byte(bad, 0, 'X');
    decoded = tmpfile(); assert(decoded);
    assert(!cg_packed_decode_snapshot(bad, decoded, op, 64u << 20, 200000));
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
    assert(cg_packed_encode_snapshot(double_raw, bad, op, 64u << 20, 200000));
    rewind(bad);
    decoded = tmpfile(); assert(decoded);
    assert(!cg_packed_decode_snapshot(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0);
    fclose(decoded); fclose(bad); fclose(double_raw); rewind(raw);
    bad = copy_bytes(packed);
    size_t encoded_size = file_size(bad);
    assert(ftruncate(fileno(bad), (off_t)encoded_size - 1) == 0); rewind(bad);
    assert(file_size(bad) == encoded_size - 1);
    decoded = tmpfile(); assert(decoded);
    assert(!cg_packed_decode_snapshot(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(bad);
    bad = copy_bytes(packed);
    assert(fseeko(bad, 0, SEEK_END) == 0 && fputc('x', bad) != EOF);
    assert(fflush(bad) == 0); rewind(bad);
    decoded = tmpfile(); assert(decoded);
    assert(!cg_packed_decode_snapshot(bad, decoded, op, 64u << 20, 200000));
    assert(file_size(decoded) == 0); fclose(decoded); fclose(bad);
    bad = copy_bytes(packed);
    set_byte(bad, 8, 0xff); /* advertised raw length */
    decoded = tmpfile(); assert(decoded);
    assert(!cg_packed_decode_snapshot(bad, decoded, op, 64u << 20, 200000));
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
    assert(cg_packed_encode_snapshot(empty_raw, empty_packed, op, 64u << 20, 200000));
    rewind(empty_packed);
    assert(cg_packed_decode_snapshot(empty_packed, empty_decoded, low, 64u << 20, 200000));
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
    assert(cg_packed_encode_snapshot(public_raw, public_packed, low, 64u << 20, 200000));
    rewind(public_packed);
    assert(cg_packed_decode_snapshot(public_packed, public_decoded, low, 64u << 20, 200000));
    raw_equal(public_raw, public_decoded);
    rewind(public_decoded);
    opened = qihse_kv_open_snapshot_user(public_decoded, low, 64u << 20, 200000);
    assert(opened);
    actual = qihse_kv_get_user(opened, node, low);
    assert(actual && strcmp(actual, "public node") == 0); free(actual);
    qihse_kv_store_destroy(opened);
    rewind(public_packed);
    view = cg_packed_open_snapshot_user(public_packed, low, 64u << 20, 200000, NULL);
    assert(view);
    assert(qihse_auth_destroy_user(op, 621));
    /* Public-data access has a separate existing auth fast path. Revocation
     * of protected data and new opens is checked below/above. */
    qihse_kv_store_destroy(view); rewind(public_packed);
    assert(!cg_packed_open_snapshot_user(public_packed, low, 64u << 20, 200000, NULL));
    assert(errno == EACCES);
    fclose(public_raw); fclose(public_packed); fclose(public_decoded);
    qihse_kv_store_destroy(public_store);
    qihse_audit_shutdown();
    assert(nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CodeGraph packed snapshot: exact authenticated bytes, denial and corruption PASS");
    return 0;
}
