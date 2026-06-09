#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int main() {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
    if (!pkey) {
        printf("Failed to generate key\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    const char *msg = "Test message for PQC";
    unsigned char sig[8192];
    size_t siglen = sizeof(sig);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) <= 0) {
        printf("EVP_DigestSignInit failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (EVP_DigestSign(mctx, sig, &siglen, (const unsigned char*)msg, strlen(msg)) <= 0) {
        printf("EVP_DigestSign failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Successfully signed! Signature length: %zu\n", siglen);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return 0;
}
