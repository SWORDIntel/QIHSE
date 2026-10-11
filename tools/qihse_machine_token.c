/* qihse-machine-token — mint a MACHINE-purpose capability token.
 *
 * Machine clients (fleet agents, exporters, bridges) authenticate to a
 * QIHSE RESP listener with MACHINEAUTH <token-hex> instead of AUTH with the
 * operator password, so the server never pays the PBKDF2 password KDF for a
 * machine login and the client never holds the operator secret.
 *
 * The token is the fabric-dispatch token wire format with purpose MACHINE:
 * a 140-byte signed region (claims incl. nonce and lifetime) followed by an
 * ML-DSA-87 signature over it, produced by the node's identity private key
 * (qihse_dsa_key.pem under the identity dir). The receiving daemon verifies
 * against its --pqc-trusted-pub anchors.
 *
 * Usage:
 *   qihse-machine-token --identity /etc/qihse/keys/qihse_dsa_key.pem \
 *       [--label name] [--ttl-seconds 43200] [--user-id 0]
 *       [--clearance 0] [--sci 0] [--tenant 0]
 *
 * Prints the token as lowercase hex on stdout. Store it root-only (0600) —
 * it is a bearer credential until it expires. Default TTL 12h; the verifier
 * refuses anything over 72h regardless of what this tool mints. One token
 * authenticates exactly one connection, so mint per deployment, not per
 * connection: the intended pattern is a persistent agent connection whose
 * lifetime is bounded by the token, refreshed by a timer/service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "qihse_fabric_dispatch.h"
#include "qihse_federation.h"
#include "qihse_machine_auth.h"

static void usage(const char* prog) {
    fprintf(stderr,
            "usage: %s --identity <priv-pem> [--ttl-seconds N] [--user-id N]\n"
            "                     [--clearance N] [--sci N] [--tenant N]\n",
            prog);
}

int main(int argc, char** argv) {
    const char* identity = NULL;
    uint64_t ttl_ms = 12ull * 3600ull * 1000ull; /* 12h default */
    uint32_t user_id = 0, tenant = 0;
    uint16_t clearance = 0, sci = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--identity") == 0 && i + 1 < argc) {
            identity = argv[++i];
        } else if (strcmp(argv[i], "--ttl-seconds") == 0 && i + 1 < argc) {
            unsigned long v = strtoul(argv[++i], NULL, 10);
            if (v == 0 || (uint64_t)v * 1000ull > QIHSE_MACHINE_TOKEN_MAX_TTL_MS) {
                fprintf(stderr, "qihse-machine-token: ttl-seconds must be 1..%llu\n",
                        (unsigned long long)(QIHSE_MACHINE_TOKEN_MAX_TTL_MS / 1000ull));
                return 2;
            }
            ttl_ms = (uint64_t)v * 1000ull;
        } else if (strcmp(argv[i], "--user-id") == 0 && i + 1 < argc) {
            user_id = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--clearance") == 0 && i + 1 < argc) {
            clearance = (uint16_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--sci") == 0 && i + 1 < argc) {
            sci = (uint16_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--tenant") == 0 && i + 1 < argc) {
            tenant = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!identity) {
        usage(argv[0]);
        return 2;
    }

    EVP_PKEY* pkey = (EVP_PKEY*)qihse_federation_node_key_load(identity);
    if (!pkey) {
        fprintf(stderr, "qihse-machine-token: cannot load identity key '%s'\n", identity);
        return 1;
    }

    qihse_fabric_token_t token;
    memset(&token, 0, sizeof(token));
    token.purpose = QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE;
    token.job_type = QIHSE_FABRIC_JOB_NONE;
    token.scope = 0u; /* MACHINE tokens carry no federation authority */
    token.principal_user_id = user_id;
    token.clearance = clearance;
    token.sci = sci;
    token.principal_tenant = tenant;

    /* Submitter identity: derived from the public key itself (SHA-256 of the
     * DER encoding, first 16 bytes) so the token self-describes its signer
     * without trusting any stored label to describe the key. */
    uint8_t* der = NULL;
    int der_len = i2d_PUBKEY(pkey, &der);
    if (der_len > 0 && der) {
        uint8_t sha[SHA256_DIGEST_LENGTH];
        SHA256(der, (size_t)der_len, sha);
        memcpy(token.submitter_node.bytes, sha, sizeof(token.submitter_node.bytes));
        OPENSSL_free(der);
    }

    if (RAND_bytes(token.nonce.bytes, (int)sizeof(token.nonce.bytes)) != 1) {
        fprintf(stderr, "qihse-machine-token: RAND_bytes failed\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    uint64_t now_ms = (uint64_t)time(NULL) * 1000ull;
    token.issued_ms = now_ms;
    token.expires_ms = now_ms + ttl_ms;
    token.payload_len = 0u;
    /* The payload binding is the SHA-384 of zero bytes: a MACHINE token
     * binds no payload. */
    SHA384((const unsigned char*)"", 0u, token.payload_digest);

    uint8_t blob[QIHSE_FABRIC_TOKEN_MAX_BYTES];
    size_t blob_len = 0;
    if (!qihse_fabric_token_mint(pkey, &token, blob, sizeof(blob), &blob_len)) {
        fprintf(stderr, "qihse-machine-token: mint failed (signing error)\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_PKEY_free(pkey);

    static const char hexv[] = "0123456789abcdef";
    for (size_t i = 0; i < blob_len; i++) {
        putchar(hexv[blob[i] >> 4]);
        putchar(hexv[blob[i] & 0x0fu]);
    }
    putchar('\n');
    return 0;
}
