/*
 * tools/qihse_keygen.c — QIHSE CNSA 2.0 key generation tool
 *
 * Usage:
 *   qihse_keygen [output-dir]
 *
 * Generates ML-KEM-1024 and ML-DSA-87 keypairs via the native C PQC module.
 * If the OpenSSL FIPS provider is installed, keys are produced through the
 * FIPS 140-3 validated module automatically.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "../persistence/qihse_pqc_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    const char *out_dir = (argc > 1) ? argv[1] : ".";

    /* Create output directory if it doesn't exist */
    mkdir(out_dir, 0755);

    fprintf(stderr, "┌─────────────────────────────────────────────────────┐\n");
    fprintf(stderr, "│  QIHSE CNSA 2.0 Key Generation                     │\n");
    fprintf(stderr, "│  ML-KEM-1024 (FIPS 203) + ML-DSA-87 (FIPS 204)    │\n");
    fprintf(stderr, "└─────────────────────────────────────────────────────┘\n");

    /* Load FIPS provider if available, fall back to default */
    int fips_active = qihse_pqc_init_providers();
    fprintf(stderr, "[QIHSE keygen] Provider : %s\n\n",
            fips_active ? "FIPS 140-3 validated" : "standard (install openssl-provider-fips for FIPS)");

    if (!qihse_pqc_keygen(out_dir)) {
        fprintf(stderr, "\n[QIHSE keygen] Key generation FAILED.\n");
        return 1;
    }

    fprintf(stderr, "\n");
    fprintf(stderr, "┌─────────────────────────────────────────────────────┐\n");
    fprintf(stderr, "│  Complete. Files written to: %-22s│\n", out_dir);
    fprintf(stderr, "│                                                     │\n");
    fprintf(stderr, "│  Algorithm      Private key         Public key      │\n");
    fprintf(stderr, "│  ───────────    ─────────────────   ──────────────  │\n");
    fprintf(stderr, "│  ML-KEM-1024    qihse_kem_key.pem  qihse_kem_pub   │\n");
    fprintf(stderr, "│  ML-DSA-87      qihse_dsa_key.pem  qihse_dsa_pub   │\n");
    fprintf(stderr, "│                                                     │\n");
    if (fips_active)
    fprintf(stderr, "│  ✓ Generated via FIPS 140-3 validated module.       │\n");
    else
    fprintf(stderr, "│  ⚠ FIPS module not active — standard provider used. │\n");
    fprintf(stderr, "└─────────────────────────────────────────────────────┘\n");

    return 0;
}
