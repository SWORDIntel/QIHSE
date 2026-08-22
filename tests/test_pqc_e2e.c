#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

void print_errors() {
    ERR_print_errors_fp(stderr);
}

int main() {
    printf("Starting PQC E2E test...\n");

    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        printf("Failed to load default provider\n");
    }

    OSSL_PROVIDER *oqs = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqs) {
        const char *paths[] = {
            "/usr/local/lib/ossl-modules/oqsprovider.so",
            "/usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so",
            NULL
        };
        for (int i = 0; paths[i]; i++) {
            oqs = OSSL_PROVIDER_load(NULL, paths[i]);
            if (oqs) break;
        }
    }

    if (!oqs) {
        printf("Failed to load oqsprovider\n");
        print_errors();
        return 1;
    }
    printf("Loaded oqsprovider successfully.\n");

    // ML-DSA-87 test
    EVP_PKEY *dsa_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
    if (!dsa_key) {
        printf("Failed to generate ML-DSA-87 key\n");
        print_errors();
        return 1;
    }
    printf("Generated ML-DSA-87 key.\n");

    const char *msg = "test message";
    size_t msg_len = strlen(msg);
    size_t sig_len = 0;
    unsigned char *sig = NULL;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestSignInit(mdctx, NULL, NULL, NULL, dsa_key) <= 0) {
        printf("EVP_DigestSignInit failed\n");
        print_errors();
        return 1;
    }
    if (EVP_DigestSign(mdctx, NULL, &sig_len, (const unsigned char*)msg, msg_len) <= 0) {
        printf("EVP_DigestSign failed (get length)\n");
        print_errors();
        return 1;
    }
    sig = malloc(sig_len);
    if (EVP_DigestSign(mdctx, sig, &sig_len, (const unsigned char*)msg, msg_len) <= 0) {
        printf("EVP_DigestSign failed\n");
        print_errors();
        return 1;
    }
    printf("Signed message with ML-DSA-87.\n");

    EVP_MD_CTX_reset(mdctx);
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, dsa_key) <= 0) {
        printf("EVP_DigestVerifyInit failed\n");
        print_errors();
        return 1;
    }
    if (EVP_DigestVerify(mdctx, sig, sig_len, (const unsigned char*)msg, msg_len) <= 0) {
        printf("EVP_DigestVerify failed\n");
        print_errors();
        return 1;
    }
    printf("Verified ML-DSA-87 signature successfully.\n");

    EVP_MD_CTX_free(mdctx);
    free(sig);

    // ML-KEM-1024 test
    EVP_PKEY *kem_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-1024");
    if (!kem_key) {
        printf("Failed to generate ML-KEM-1024 key\n");
        print_errors();
        return 1;
    }
    printf("Generated ML-KEM-1024 key.\n");

    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(NULL, kem_key, NULL);
    if (!ectx || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) {
        printf("EVP_PKEY_encapsulate_init failed\n");
        print_errors();
        return 1;
    }

    size_t ct_len = 0, ss_enc_len = 0;
    if (EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_enc_len) <= 0) {
        printf("EVP_PKEY_encapsulate failed (get length)\n");
        print_errors();
        return 1;
    }

    unsigned char *ct = malloc(ct_len);
    unsigned char *ss_enc = malloc(ss_enc_len);
    unsigned char *ss_dec = malloc(ss_enc_len);

    if (EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss_enc, &ss_enc_len) <= 0) {
        printf("EVP_PKEY_encapsulate failed\n");
        print_errors();
        return 1;
    }
    printf("Encapsulated ML-KEM-1024.\n");

    EVP_PKEY_CTX_free(ectx);

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, kem_key, NULL);
    if (!dctx || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        printf("EVP_PKEY_decapsulate_init failed\n");
        print_errors();
        return 1;
    }

    size_t ss_dec_len = ss_enc_len;
    if (EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ct, ct_len) <= 0) {
        printf("EVP_PKEY_decapsulate failed\n");
        print_errors();
        return 1;
    }
    printf("Decapsulated ML-KEM-1024.\n");

    EVP_PKEY_CTX_free(dctx);

    if (ss_enc_len == ss_dec_len && memcmp(ss_enc, ss_dec, ss_enc_len) == 0) {
        printf("Shared secrets match. ML-KEM-1024 successful.\n");
    } else {
        printf("Shared secrets DO NOT match!\n");
        return 1;
    }

    free(ct);
    free(ss_enc);
    free(ss_dec);
    EVP_PKEY_free(dsa_key);
    EVP_PKEY_free(kem_key);
    OSSL_PROVIDER_unload(oqs);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);

    printf("PQC E2E test passed!\n");
    return 0;
}
