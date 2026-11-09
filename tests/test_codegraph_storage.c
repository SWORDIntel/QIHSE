#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_storage.h"
#include <assert.h>
#include <errno.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define PASSWORD "CodegraphCodecOperator1!"
static void value_is(qihse_kv_store_t *s, qihse_user_t *u, const char *key, const char *wanted) {
    char *v = qihse_kv_get_user(s, key, u);
    assert(wanted ? v && strcmp(v, wanted) == 0 : v == NULL);
    free(v);
}
static off_t snapshot_size(const char *path) {
    struct stat st; assert(stat(path, &st) == 0); return st.st_size;
}
static void snapshot_hash(const char *path, char hex[65]) {
    FILE *f = fopen(path, "rb"); assert(f);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); assert(ctx);
    assert(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    unsigned char bytes[65536], digest[32]; size_t n; unsigned int length;
    while ((n = fread(bytes, 1, sizeof(bytes), f)))
        assert(EVP_DigestUpdate(ctx, bytes, n) == 1);
    assert(!ferror(f)); assert(fclose(f) == 0);
    assert(EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32);
    EVP_MD_CTX_free(ctx);
    for (size_t i = 0; i < 32; ++i) sprintf(hex + 2 * i, "%02x", digest[i]);
}
static int clean_test(const char *path, const struct stat *st, int type, struct FTW *walk) {
    (void)st; (void)type; (void)walk; return remove(path);
}
int main(void) {
    char root[4096];
    const char *temporary = getenv("TMPDIR");
    assert(snprintf(root, sizeof(root), "%s/qihse-codegraph-codec-test-XXXXXX",
                    temporary && *temporary ? temporary : ".") < (int)sizeof(root));
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD); assert(op);
    assert(qihse_auth_create_user(op, 71, QIHSE_ROLE_ANALYST, 0, 0, PASSWORD, false));
    qihse_user_t *low = qihse_auth_authenticate_id(71, PASSWORD); assert(low);
    qihse_kv_store_t *s = qihse_kv_store_create_user(op); assert(s);
    const char *json = "{\"traversable\":false,\"extra\":{\"future_field\":\"untouched\"},\"id\":\"unresolved\"}";
    assert(qihse_kv_set_user(s, "future", json, 0, 0, op));
    char *large = malloc(1024 * 1024 + 1); assert(large);
    memset(large, 'a', 1024 * 1024); large[1024 * 1024] = 0;
    assert(qihse_kv_set_user(s, "large", large, 0, 0, op));
    char compact[sizeof(root) + 32], legacy[sizeof(root) + 32], denied[sizeof(root) + 32];
    snprintf(compact, sizeof(compact), "%s/graph.kv", root);
    snprintf(legacy, sizeof(legacy), "%s/legacy.kv", root);
    snprintf(denied, sizeof(denied), "%s/denied.kv", root);
    assert(qihse_kv_set_user(s, "public", "retained", 0, 0, op));
    assert(qihse_kv_set_user(s, "protected", "CLASSIFIED-PAYLOAD", 4, 2, op));
    qihse_kv_record_meta_t before, after;
    assert(qihse_kv_meta_user(s, "protected", op, &before));
    assert(cg_storage_save(s, compact, op));
    assert(qihse_kv_save_user(s, legacy, op) == 0);
    assert(!cg_storage_save(s, denied, NULL));
    assert(!cg_storage_save(s, denied, low));
    assert(access(denied, F_OK) != 0);
    char automatic[sizeof(root) + 32], packed_path[sizeof(root) + 32], dictionary_path[sizeof(root) + 32];
    snprintf(dictionary_path, sizeof(dictionary_path), "%s/dictionary.kv", root);
    snprintf(automatic, sizeof(automatic), "%s/auto.kv", root);
    snprintf(packed_path, sizeof(packed_path), "%s/packed.kv", root);
    bool chose_packed = false;
    assert(cg_storage_save_packed(s, packed_path, op));
    char packed_hash[65]; snapshot_hash(packed_path, packed_hash);
    cg_storage_info_t packed_info;
    qihse_kv_store_t *view = cg_storage_open_verified_info(packed_path, op, 64u << 20,
                                                           200000, packed_hash, &packed_info);
    assert(view && packed_info.valid && packed_info.packed &&
           packed_info.encoded_bytes == (uint64_t)snapshot_size(packed_path) &&
           !strcmp(packed_info.sha256, packed_hash));
    value_is(view, op, "future", json); value_is(view, op, "protected", "CLASSIFIED-PAYLOAD");
    value_is(view, low, "protected", NULL);
    assert(qihse_kv_meta_user(view, "protected", op, &after));
    assert(before.classification == after.classification && before.sci_compartment == after.sci_compartment &&
           before.expire_time_ms == after.expire_time_ms && before.flags == after.flags &&
           before.change_seq == after.change_seq);
    qihse_kv_store_destroy(view);
    assert(!cg_storage_open_verified_info(packed_path, low, 64u << 20, 200000, packed_hash, &packed_info));
    assert(!packed_info.valid);
    assert(qihse_auth_create_user(op, 72, QIHSE_ROLE_ANALYST, 4, 0, PASSWORD, false));
    qihse_user_t *wrong_sci = qihse_auth_authenticate_id(72, PASSWORD); assert(wrong_sci);
    assert(!cg_storage_open_verified_info(packed_path, wrong_sci, 64u << 20, 200000, packed_hash, &packed_info));
    assert(!packed_info.valid);
    char wrong_hash[65]; memset(wrong_hash, '0', 64); wrong_hash[64] = 0;
    assert(!cg_storage_open_verified_info(packed_path, op, 64u << 20, 200000, wrong_hash, &packed_info));
    assert(!packed_info.valid);
    assert(qihse_auth_destroy_user(op, 72));
    assert(!cg_storage_open_verified_info(packed_path, wrong_sci, 64u << 20, 200000, packed_hash, &packed_info));
    assert(!packed_info.valid);
    assert(cg_storage_save_dictionary(s, dictionary_path, op));
    char dictionary_hash[65]; snapshot_hash(dictionary_path, dictionary_hash);
    view = cg_storage_open_verified_info(dictionary_path, op, 64u << 20,
                                          200000, dictionary_hash, &packed_info);
    assert(view && packed_info.valid && packed_info.packed && packed_info.dictionary);
    value_is(view, op, "protected", "CLASSIFIED-PAYLOAD");
    assert(qihse_kv_meta_user(view, "protected", op, &after));
    assert(before.classification == after.classification && before.sci_compartment == after.sci_compartment &&
           before.expire_time_ms == after.expire_time_ms && before.flags == after.flags &&
           before.change_seq == after.change_seq);
    qihse_kv_store_destroy(view);
    assert(!cg_storage_open_verified_info(dictionary_path, low, 64u << 20, 200000,
                                           dictionary_hash, &packed_info));
    assert(!packed_info.valid);
    assert(!cg_storage_open_verified_info(dictionary_path, NULL, 64u << 20, 200000,
                                           dictionary_hash, &packed_info));
    assert(!cg_storage_open_verified_info(dictionary_path, op, 64u << 20, 200000,
                                           wrong_hash, &packed_info));
    errno = 0;
    assert(!cg_storage_open_verified_info(dictionary_path, op, 64u << 20, 1,
                                           dictionary_hash, &packed_info));
    assert(errno == E2BIG && !packed_info.valid);
    assert(cg_storage_load_verified_info(s, dictionary_path, op, dictionary_hash, &packed_info));
    assert(packed_info.valid && packed_info.dictionary);
    assert(!cg_storage_load_verified_info(s, dictionary_path, low, dictionary_hash, NULL));
    value_is(s, op, "protected", "CLASSIFIED-PAYLOAD");
    /* The explicitly typed XXH3 adapter verifies every storage format, and
     * protected classification/SCI labels still deny low or wrong-SCI users. */
    cg_snapshot_checksum golden;
    assert(cg_snapshot_checksum_buffer_user("abc",3,op,CG_CHECKSUM_XXH3_128,&golden));
    assert(!strcmp(golden.hex,"06b05ab6733a618578af5f94892f3950"));
    assert(!cg_snapshot_checksum_buffer_user("abc",3,NULL,CG_CHECKSUM_XXH3_128,&golden));
    assert(qihse_auth_create_user(op,73,QIHSE_ROLE_ANALYST,4,0,PASSWORD,false));
    qihse_user_t *xxh_wrong_sci=qihse_auth_authenticate_id(73,PASSWORD); assert(xxh_wrong_sci);
    const char *xxh_paths[]={compact,packed_path,dictionary_path,legacy};
    for(size_t i=0;i<4;i++) {
        cg_snapshot_checksum expected;
        assert(cg_snapshot_checksum_file_user(xxh_paths[i],op,CG_CHECKSUM_XXH3_128,&expected));
        assert(strlen(expected.hex)==32 && cg_checksum_valid(&expected));
        view=cg_storage_open_checksum_info(xxh_paths[i],op,64u<<20,200000,&expected,&packed_info);
        assert(view && packed_info.valid && packed_info.checksum.algorithm==CG_CHECKSUM_XXH3_128);
        assert(!strcmp(packed_info.checksum.hex,expected.hex) && !packed_info.sha256[0]);
        value_is(view,op,"protected","CLASSIFIED-PAYLOAD");
        assert(qihse_kv_meta_user(view,"protected",op,&after));
        assert(before.classification==after.classification && before.sci_compartment==after.sci_compartment);
        value_is(view,low,"protected",NULL); qihse_kv_store_destroy(view);
        assert(!cg_storage_open_checksum_info(xxh_paths[i],low,64u<<20,200000,&expected,&packed_info));
        assert(!packed_info.valid);
        assert(!cg_storage_open_checksum_info(xxh_paths[i],xxh_wrong_sci,64u<<20,200000,&expected,&packed_info));
        assert(!cg_storage_open_checksum_info(xxh_paths[i],NULL,64u<<20,200000,&expected,&packed_info));
        assert(!cg_storage_open_checksum_info(xxh_paths[i],op,64u<<20,200000,NULL,&packed_info));
        cg_snapshot_checksum wrong=expected; wrong.hex[0]=wrong.hex[0]=='0'?'1':'0';
        assert(!cg_storage_open_checksum_info(xxh_paths[i],op,64u<<20,200000,&wrong,&packed_info));
        assert(!packed_info.valid);
        wrong=expected; wrong.algorithm=CG_CHECKSUM_SHA256;
        assert(!cg_storage_open_checksum_info(xxh_paths[i],op,64u<<20,200000,&wrong,&packed_info));
        assert(!cg_storage_load_checksum_info(s,xxh_paths[i],low,&expected,&packed_info));
        assert(!cg_storage_load_checksum_info(s,xxh_paths[i],xxh_wrong_sci,&expected,&packed_info));
        if (i<3) {
            assert(cg_storage_load_checksum_info(s,xxh_paths[i],op,&expected,&packed_info));
            assert(packed_info.valid && !packed_info.sha256[0]);
        } else {
            assert(!cg_storage_load_checksum_info(s,xxh_paths[i],op,&expected,&packed_info));
            assert(!packed_info.valid); /* Durable path must never reopen raw input. */
        }
    }
    assert(qihse_auth_destroy_user(op,73));
    cg_snapshot_checksum revoked_checksum;
    assert(!cg_snapshot_checksum_file_user(compact,xxh_wrong_sci,CG_CHECKSUM_XXH3_128,&revoked_checksum));
    const char *candidates[] = {compact, packed_path, dictionary_path};
    cg_storage_format expected_format = CG_STORAGE_ZSTD, selected_format;
    for (int i = 1; i < 3; ++i)
        if (snapshot_size(candidates[i]) < snapshot_size(candidates[expected_format])) expected_format = (cg_storage_format)i;
    assert(cg_storage_save_auto_format(s, automatic, op, &selected_format));
    chose_packed = selected_format != CG_STORAGE_ZSTD;
    assert(selected_format == expected_format);
    assert(snapshot_size(automatic) == snapshot_size(candidates[expected_format]));
    char selected_hash[65], auto_hash[65];
    snapshot_hash(candidates[expected_format], selected_hash);
    snapshot_hash(automatic, auto_hash);
    assert(strcmp(selected_hash, auto_hash) == 0);
    /* A failed replacement must leave the previously published graph intact. */
    assert(!cg_storage_save_auto(s, automatic, NULL, &chose_packed));
    assert(!cg_storage_save_auto(s, automatic, low, &chose_packed));
    snapshot_hash(automatic, selected_hash);
    assert(strcmp(selected_hash, auto_hash) == 0);
    assert(!cg_storage_save_auto(s, denied, low, NULL));
    assert(access(denied, F_OK) != 0);
    assert(qihse_kv_clear_user(s, op) == 4);
    assert(qihse_kv_set_user(s, "marker", "unchanged", 0, 0, op));
    assert(!cg_storage_load(s, compact, NULL));
    assert(!cg_storage_load(s, compact, low));
    value_is(s, op, "protected", NULL); value_is(s, low, "marker", "unchanged");
    assert(!cg_storage_load(s, legacy, low));
    value_is(s, op, "protected", NULL); value_is(s, low, "marker", "unchanged");
    assert(!cg_storage_load_verified_info(s, automatic, low, chose_packed ? auto_hash : NULL, NULL));
    value_is(s, low, "marker", "unchanged");
    value_is(s, op, "protected", NULL);
    assert(cg_storage_load_verified_info(s, automatic, op, chose_packed ? auto_hash : NULL, NULL));
    value_is(s, op, "future", json);
    value_is(s, op, "large", large);
    value_is(s, op, "protected", "CLASSIFIED-PAYLOAD");
    value_is(s, low, "protected", NULL);
    assert(qihse_kv_meta_user(s, "protected", op, &after));
    assert(before.classification == after.classification && before.sci_compartment == after.sci_compartment &&
           before.expire_time_ms == after.expire_time_ms && before.flags == after.flags &&
           before.change_seq == after.change_seq);
    assert(cg_storage_load(s, legacy, op));
    value_is(s, op, "public", "retained");
    int fd = open(compact, O_RDWR); assert(fd >= 0);
    off_t size = lseek(fd, 0, SEEK_END); assert(size > 20);
    unsigned char byte;
    assert(pread(fd, &byte, 1, size - 1) == 1);
    unsigned char bad = byte ^ 0x40;
    assert(pwrite(fd, &bad, 1, size - 1) == 1);
    assert(!cg_storage_load(s, compact, op)); /* frame checksum */
    assert(pwrite(fd, &byte, 1, size - 1) == 1);
    assert(ftruncate(fd, size - 1) == 0);
    assert(!cg_storage_load(s, compact, op)); /* truncation */
    close(fd);
    assert(cg_storage_save(s, compact, op));
    fd = open(compact, O_WRONLY | O_APPEND); assert(fd >= 0);
    assert(write(fd, "x", 1) == 1); close(fd);
    assert(!cg_storage_load(s, compact, op)); /* trailing bytes */
    assert(cg_storage_save(s, compact, op));
    fd = open(compact, O_WRONLY); assert(fd >= 0);
    assert(pwrite(fd, "\377", 1, 8) == 1); close(fd);
    assert(!cg_storage_load(s, compact, op)); /* advertised length bound */
    value_is(s, op, "public", "retained");
    /* Above packed's 64 MiB bound, auto must still produce a complete Zstd
     * snapshot instead of failing a large graph or truncating its records. */
    for (size_t i = 0; i < 64; ++i) {
        char key[32]; snprintf(key, sizeof(key), "bulk-%zu", i);
        assert(qihse_kv_set_user(s, key, large, 0, 0, op));
    }
    chose_packed = true;
    assert(cg_storage_save_auto(s, automatic, op, &chose_packed));
    assert(!chose_packed);
    assert(!cg_storage_save_packed(s, denied, op));
    assert(errno == EFBIG && access(denied, F_OK) != 0);
    assert(qihse_kv_clear_user(s, op) == 68);
    assert(cg_storage_load(s, automatic, op));
    value_is(s, op, "bulk-63", large);
    value_is(s, op, "future", json);
    value_is(s, op, "protected", "CLASSIFIED-PAYLOAD");
    assert(qihse_auth_destroy_user(op, 71));
    assert(!cg_storage_load(s, legacy, low));
    free(large);
    qihse_kv_store_destroy(s);
    qihse_audit_shutdown();
    assert(nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CodeGraph compact storage: automatic size selection, large fallback, round-trip, metadata and authorization checks passed");
    return 0;
}
