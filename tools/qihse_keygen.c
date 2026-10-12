/*
 * tools/qihse_keygen.c — QIHSE CNSA 2.0 key generation tool
 *
 * Usage:
 *   qihse_keygen [output-dir] [--bind-operator]
 *
 * Generates ML-KEM-1024 and ML-DSA-87 keypairs via the native C PQC module.
 * If the OpenSSL FIPS provider is installed, keys are produced through the
 * FIPS 140-3 validated module automatically.
 *
 * With --bind-operator, also generates a random 32-byte operator password
 * and, if a Yubikey/HSM is present, signs it via PIV.
 *
 * With no arguments, keys are written to $QIHSE_KEYS_DIR, falling back to
 * /opt/qihse/keys, then ./keys — so the keygen is safe to invoke with no
 * args from any working directory (e.g. from a container).
 *
 * SPDX-License-Identifier: LicenseRef-SRSL-1.0
 */

#include "../persistence/qihse_pqc_crypto.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>

static const char* find_executable(const char* name) {
    static const char* const standard_dirs[] = {
        "/usr/bin", "/usr/local/bin", "/bin"
    };
    static char resolved[512];
    for (size_t i = 0; i < sizeof(standard_dirs) / sizeof(standard_dirs[0]); i++) {
        snprintf(resolved, sizeof(resolved), "%s/%s", standard_dirs[i], name);
        if (access(resolved, X_OK) == 0) return resolved;
    }
    return NULL;
}

static int run_execve_safe(const char* bin_name, char* const argv[]) {
    const char* full_path = find_executable(bin_name);
    if (!full_path) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        char* const envp[] = { NULL };
        execve(full_path, argv, envp);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Check if a Yubikey is present by invoking ykinfo -s safely via execve */
static int yubikey_present(void) {
    char* const argv[] = { (char*)"ykinfo", (char*)"-s", NULL };
    return run_execve_safe("ykinfo", argv) == 0;
}

/* Generate a random operator password and optionally bind to HSM */
static int bind_operator_password(const char *out_dir) {
    unsigned char pass[32];
    if (RAND_bytes(pass, sizeof(pass)) != 1) {
        fprintf(stderr, "[QIHSE keygen] RAND_bytes failed for operator password.\n");
        return 0;
    }

    /* Store operator key securely in ~/.ssh/ with chmod 600 */
    const char *home = getenv("HOME");
    if (!home || *home == '\0') home = "/root";

    char ssh_dir[512];
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    mkdir(ssh_dir, 0700);

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.ssh/qihse_operator_key", home);
    unlink(key_path);
    int fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "[QIHSE keygen] Cannot write %s\n", key_path);
        return 0;
    }
    if (write(fd, pass, sizeof(pass)) != (ssize_t)sizeof(pass)) {
        close(fd);
        unlink(key_path);
        return 0;
    }
    close(fd);

    fprintf(stderr, "[QIHSE keygen] Operator key stored: %s (chmod 600)\n", key_path);

    /* Sign with Yubikey if present */
    if (yubikey_present()) {
        fprintf(stderr, "[QIHSE keygen] Yubikey detected — signing operator key via PIV...\n");
        unsigned char hash[32];
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, pass, sizeof(pass));
        EVP_DigestFinal_ex(mdctx, hash, NULL);
        EVP_MD_CTX_free(mdctx);

        char hash_path[512];
        snprintf(hash_path, sizeof(hash_path), "%s/.ssh/.qihse_op_hash.tmp", home);
        unlink(hash_path);
        int hfd = open(hash_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (hfd >= 0) {
            if (write(hfd, hash, 32) == 32) {
                close(hfd);
                char sig_path[512];
                snprintf(sig_path, sizeof(sig_path), "%s/.ssh/qihse_operator_key.sig", home);
                char* const argv[] = {
                    (char*)"yubico-piv-tool",
                    (char*)"-a", (char*)"sign",
                    (char*)"-s", (char*)"9c",
                    (char*)"-i", hash_path,
                    (char*)"-o", sig_path,
                    NULL
                };
                int sign_rc = run_execve_safe("yubico-piv-tool", argv);
                unlink(hash_path);
                if (sign_rc == 0) {
                    chmod(sig_path, 0600);
                    fprintf(stderr, "[QIHSE keygen] Operator key signed via Yubikey PIV slot 9c.\n");
                } else {
                    fprintf(stderr, "[QIHSE keygen] Yubikey sign failed — key generated but unsigned.\n");
                }
            } else {
                close(hfd);
                unlink(hash_path);
            }
        }
    } else {
        fprintf(stderr, "[QIHSE keygen] No Yubikey/HSM detected — key generated but unsigned.\n");
    }

    OPENSSL_cleanse(pass, sizeof(pass));
    return 1;
}

int main(int argc, char *argv[]) {
    const char *out_dir = NULL;
    int do_bind_operator = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bind-operator") == 0) {
            do_bind_operator = 1;
        } else if (!out_dir) {
            out_dir = argv[i];
        }
    }

    if (!out_dir) {
        out_dir = getenv("QIHSE_KEYS_DIR");
        if (!out_dir || *out_dir == '\0') {
            if (mkdir("/opt/qihse/keys", 0755) == 0 || access("/opt/qihse/keys", W_OK) == 0)
                out_dir = "/opt/qihse/keys";
            else
                out_dir = "keys";
        }
    }

    /* Create output directory if it doesn't exist */
    mkdir(out_dir, 0755);

    fprintf(stderr, "┌──────────────────────────────────────────────────────────────┐\n");
    fprintf(stderr, "│  QIHSE CNSA 2.0 Key Generation                               │\n");
    fprintf(stderr, "│  ML-KEM-1024 (FIPS 203) + ML-DSA-87 (FIPS 204)               │\n");
    fprintf(stderr, "└──────────────────────────────────────────────────────────────┘\n");

    /* Load FIPS provider if available, fall back to default */
    int fips_active = qihse_pqc_init_providers();
    fprintf(stderr, "[QIHSE keygen] Provider : %s\n\n",
            fips_active ? "FIPS 140-3 validated" : "standard (install openssl-provider-fips for FIPS)");

    if (!qihse_pqc_keygen(out_dir)) {
        fprintf(stderr, "\n[QIHSE keygen] Key generation FAILED.\n");
        return 1;
    }

    if (do_bind_operator) {
        fprintf(stderr, "\n[QIHSE keygen] Binding operator password...\n");
        if (!bind_operator_password(out_dir)) {
            fprintf(stderr, "[QIHSE keygen] Operator password binding FAILED.\n");
            return 1;
        }
    }

    /* Summary box — 64 chars wide, 62 inner */
    /* Truncate path to fit if needed */
    char display_path[33];
    if (strlen(out_dir) > 32) {
        strncpy(display_path, out_dir, 29);
        display_path[29] = '~';
        display_path[30] = '.';
        display_path[31] = '.';
        display_path[32] = '\0';
    } else {
        strncpy(display_path, out_dir, 32);
        display_path[32] = '\0';
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "┌──────────────────────────────────────────────────────────────┐\n");
    fprintf(stderr, "│  Complete. Files written to: %-32s│\n", display_path);
    fprintf(stderr, "│                                                              │\n");
    fprintf(stderr, "│  Algorithm      Private key            Public key            │\n");
    fprintf(stderr, "│  ───────────    ──────────────────     ──────────────        │\n");
    fprintf(stderr, "│  ML-KEM-1024    qihse_kem_key.pem      qihse_kem_pub.pem     │\n");
    fprintf(stderr, "│  ML-DSA-87      qihse_dsa_key.pem      qihse_dsa_pub.pem     │\n");
    if (do_bind_operator)
    fprintf(stderr, "│  Operator       ~/.ssh/qihse_operator_key (chmod 600)        │\n");
    fprintf(stderr, "│                                                              │\n");
    if (fips_active)
    fprintf(stderr, "│  ✓ Generated via FIPS 140-3 validated module.                │\n");
    else
    fprintf(stderr, "│  ⚠ FIPS module not active — standard provider used.           │\n");
    fprintf(stderr, "└──────────────────────────────────────────────────────────────┘\n");

    return 0;
}
