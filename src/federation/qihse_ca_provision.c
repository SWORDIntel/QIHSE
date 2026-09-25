/*
 * qihse_ca_provision.c — out-of-process federation CA provisioning.
 *
 * The remaining item from the mTLS work: "CA provisioning outside the
 * process".  This translation unit is the operator-side implementation.  It
 * is compiled into the offline tool and the test binary ONLY — it is not
 * part of libqihse.so, so the database process gains no new minting
 * capability by construction.
 *
 * Everything is files-only: no sockets, no daemon, no QIHSE records.
 *
 * Certificate formats mirror src/federation/qihse_federation_mtls.c exactly
 * (CA: CN "QIHSE Federation CA"/O "Citadel", serial 1, five-year validity,
 * critical basicConstraints CA:TRUE and keyUsage keyCertSign,cRLSign; node:
 * serial = enrollment_epoch + 1, CN "QIHSE node <uuid>", SAN
 * "URI:qihse://node/<uuid>", EKU clientAuth,serverAuth, critical
 * basicConstraints CA:FALSE, the node's EXISTING identity public key as the
 * certificate key).  The node certificate additionally carries the
 * enrollment-scope extension (QIHSE_CA_PROVISION_SCOPE_OID).  The
 * signature check in verification delegates to
 * qihse_federation_cert_verify — the same code path the running node uses —
 * so format compatibility is enforced, not assumed.
 */
#include "qihse_ca_provision.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ── Small shared helpers ──────────────────────────────────────────────── */

/* OpenSSL's name for an algorithm.  Mirrors mtls_ossl_name() in
 * qihse_federation_mtls.c: "ML-DSA-87" is what EVP_PKEY_Q_keygen takes,
 * whereas qihse_sig_alg_name() returns the record-format name "ml-dsa-87". */
static const char* provision_ossl_alg_name(qihse_sig_alg_t alg) {
    switch (alg) {
        case QIHSE_SIG_ED25519:   return "ED25519";
        case QIHSE_SIG_ML_DSA_44: return "ML-DSA-44";
        case QIHSE_SIG_ML_DSA_65: return "ML-DSA-65";
        case QIHSE_SIG_ML_DSA_87: return "ML-DSA-87";
    }
    return NULL;
}

/* SHA-384 over the RAW public key bytes — one definition of "fingerprint"
 * across enrollment, certificates and operator records.  Same construction
 * as pubkey_fingerprint() in qihse_federation_mtls.c and
 * qihse_federation_node_fingerprint(). */
static bool provision_pubkey_fingerprint(EVP_PKEY* pkey, uint8_t* out) {
    if (!pkey || !out) return false;
    size_t raw_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &raw_len) != 1 || raw_len == 0) {
        return false;
    }
    if (raw_len > 4096u) return false;
    /* One bounded heap buffer, not a 4 KB stack frame per call site. */
    uint8_t* raw = (uint8_t*)malloc(raw_len);
    if (!raw) return false;
    bool ok = EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1;
    if (ok) {
        unsigned int len = 0;
        ok = EVP_Digest(raw, raw_len, out, &len, EVP_sha384(), NULL) == 1 &&
             len == QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES;
    }
    free(raw);
    return ok;
}

static void provision_fp_hex(const uint8_t* fp, char* out) {
    for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++) {
        snprintf(out + i * 2, 3, "%02x", fp[i]);
    }
    out[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES * 2u] = '\0';
}

static bool provision_read_file(const char* path, char* buf, size_t cap,
                                size_t* out_len) {
    if (!path || !buf || cap == 0) return false;
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(buf, 1, cap - 1u, f);
    bool err = ferror(f);
    fclose(f);
    if (err) return false;
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return true;
}

static X509* provision_x509_from_pem(const char* pem, size_t pem_len) {
    if (!pem) return NULL;
    BIO* bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) return NULL;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

/* Same CA-cert loading path the mTLS module uses (load_ca_cert). */
static X509* provision_load_ca_x509(const qihse_federation_ca_t* ca) {
    if (!ca) return NULL;
    return provision_x509_from_pem(ca->cert_pem, ca->cert_pem_len);
}

/* Serialize an X509 to PEM.  bool-returning encoder whose failures the
 * callers propagate — an uninitialised output buffer must never be stored. */
static bool provision_pem_from_x509(X509* cert, char* out, size_t cap) {
    if (!cert || !out || cap == 0) return false;
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    bool ok = PEM_write_bio_X509(bio, cert) == 1;
    if (ok) {
        char* pem = NULL;
        long signed_len = BIO_get_mem_data(bio, &pem);
        size_t pem_len = (signed_len > 0) ? (size_t)signed_len : 0u;
        if (!pem || pem_len == 0 || pem_len >= cap) ok = false;
        else {
            memcpy(out, pem, pem_len);
            out[pem_len] = '\0';
        }
    }
    BIO_free(bio);
    return ok;
}

/* Write a PEM private key at 0600 with create-or-refuse semantics.  O_EXCL
 * makes "never overwrite an existing CA" atomic, not a TOCTOU access()
 * check.  The key is never echoed, logged, or returned. */
static bool provision_write_key_excl_0600(const char* path, EVP_PKEY* key) {
    if (!path || !key) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false; /* EEXIST included: refuse to replace a CA */
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); return false; }
    bool ok = PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1;
    if (ok) ok = fflush(f) == 0 && fsync(fd) == 0;
    fclose(f);
    if (!ok) { (void)remove(path); return false; }
    (void)chmod(path, 0600);
    return true;
}

bool qihse_ca_provision_write_cert_file(const char* path, const char* cert_pem) {
    if (!path || !cert_pem) return false;
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(cert_pem);
    bool ok = fwrite(cert_pem, 1, len, f) == len;
    ok = (fflush(f) == 0) && ok;
    fclose(f);
    if (!ok) { (void)remove(path); return false; }
    (void)chmod(path, 0644);
    return true;
}

/* ── The enrollment-scope extension ────────────────────────────────────── */

static bool provision_add_scope_ext(X509* cert, qihse_infra_scope_t scopes) {
    ASN1_OBJECT* obj = OBJ_txt2obj(QIHSE_CA_PROVISION_SCOPE_OID, 1);
    ASN1_OCTET_STRING* oct = ASN1_OCTET_STRING_new();
    if (!obj || !oct) {
        if (obj) ASN1_OBJECT_free(obj);
        if (oct) ASN1_OCTET_STRING_free(oct);
        return false;
    }
    uint8_t be[4] = {
        (uint8_t)(scopes >> 24), (uint8_t)(scopes >> 16),
        (uint8_t)(scopes >> 8),  (uint8_t)(scopes)
    };
    bool ok = ASN1_OCTET_STRING_set(oct, be, sizeof(be)) == 1;
    if (ok) {
        X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(NULL, obj,
                                                           0 /* non-critical */,
                                                           oct);
        ok = ext != NULL && X509_add_ext(cert, ext, -1) == 1;
        if (ext) X509_EXTENSION_free(ext);
    }
    ASN1_OCTET_STRING_free(oct);
    ASN1_OBJECT_free(obj);
    return ok;
}

/* Read the scope mask back.  Returns false only for a malformed extension
 * (present but not exactly 4 bytes); absent is QIHSE_SCOPE_NONE, true. */
static bool provision_get_scope_ext(X509* cert, qihse_infra_scope_t* out) {
    *out = QIHSE_SCOPE_NONE;
    ASN1_OBJECT* want = OBJ_txt2obj(QIHSE_CA_PROVISION_SCOPE_OID, 1);
    if (!want) return false;
    bool ok = true;
    int n = X509_get_ext_count(cert);
    for (int i = 0; i < n && ok; i++) {
        X509_EXTENSION* e = X509_get_ext(cert, i);
        if (!e) continue;
        ASN1_OBJECT* have = X509_EXTENSION_get_object(e);
        if (!have || OBJ_cmp(have, want) != 0) continue;
        ASN1_STRING* data = X509_EXTENSION_get_data(e);
        /* Declared length must equal the encoded length and the fixed size:
         * exactly 4 bytes of mask, no padding, no truncation. */
        if (!data || ASN1_STRING_length(data) != 4) ok = false;
        else {
            const unsigned char* p = ASN1_STRING_get0_data(data);
            *out = ((qihse_infra_scope_t)p[0] << 24) |
                   ((qihse_infra_scope_t)p[1] << 16) |
                   ((qihse_infra_scope_t)p[2] << 8) |
                   ((qihse_infra_scope_t)p[3]);
        }
    }
    ASN1_OBJECT_free(want);
    return ok;
}

/* Extract the node UUID from the SAN the mtls issuer writes:
 * "URI:qihse://node/<uuid>".  The identity travels with the certificate
 * rather than being inferred from the CN. */
static bool provision_cert_node_id(X509* cert, qihse_uuid_t* out) {
    static const char prefix[] = "qihse://node/";
    size_t prefix_len = strlen(prefix);
    GENERAL_NAMES* names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!names) return false;
    bool found = false;
    int n = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < n && !found; i++) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
        if (!gn || gn->type != GEN_URI) continue;
        const ASN1_IA5STRING* uri_str = gn->d.uniformResourceIdentifier;
        if (!uri_str) continue;
        const unsigned char* uri = ASN1_STRING_get0_data(uri_str);
        int uri_len = ASN1_STRING_length(uri_str);
        /* Declared length against the expected encoded length: the SAN the
         * mtls issuer writes is exactly prefix + 36-char uuid. */
        if (uri_len < 0 || (size_t)uri_len != prefix_len + QIHSE_UUID_STR_LEN) {
            continue;
        }
        if (memcmp(uri, prefix, prefix_len) != 0) continue;
        char uuid_text[QIHSE_UUID_STR_LEN + 1u];
        memcpy(uuid_text, uri + prefix_len, QIHSE_UUID_STR_LEN);
        uuid_text[QIHSE_UUID_STR_LEN] = '\0';
        if (qihse_uuid_parse(uuid_text, out)) found = true;
    }
    GENERAL_NAMES_free(names);
    return found;
}

static bool provision_asn1_time_to_unix(const ASN1_TIME* t, int64_t* out) {
    struct tm tmv;
    if (!t || ASN1_TIME_to_tm(t, &tmv) != 1) return false;
    time_t v = timegm(&tmv);
    if (v == (time_t)-1) return false;
    *out = (int64_t)v;
    return true;
}

/* ── CA creation ───────────────────────────────────────────────────────── */

bool qihse_ca_provision_init_ca(void* operator_user, qihse_sig_alg_t alg,
                                const char* key_path, const char* cert_path,
                                qihse_federation_ca_t* out_ca) {
    /* NULL is never an authorization bypass (AGENTS.md invariant 1). */
    if (!operator_user || !key_path || !cert_path || !out_ca) return false;
    if (!qihse_infra_scope_check(operator_user, QIHSE_SCOPE_SECURITY_ADMIN)) {
        return false;
    }
    const char* ossl = provision_ossl_alg_name(alg);
    if (!ossl) return false;
    /* The CA is the root of every identity in the federation: it is the last
     * place to accept a quantum-vulnerable algorithm. */
    if (!qihse_sig_alg_is_post_quantum(alg)) return false;
    memset(out_ca, 0, sizeof(*out_ca));

    EVP_PKEY* ca_key = EVP_PKEY_Q_keygen(NULL, NULL, ossl);
    if (!ca_key) return false;

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(ca_key); return false; }

    /* Mirrors qihse_federation_ca_create(): serial 1, a five-year window,
     * self-signed, marked CA:TRUE with keyCertSign+cRLSign. */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert),
                    (long)QIHSE_CA_PROVISION_CA_VALIDITY_S);
    X509_set_version(cert, 2);

    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)"QIHSE Federation CA",
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                               (const unsigned char*)"Citadel", -1, -1, 0);
    X509_set_issuer_name(cert, subject);
    X509_set_pubkey(cert, ca_key);

    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                              "critical,CA:TRUE");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                              "critical,keyCertSign,cRLSign");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

    if (X509_sign(cert, ca_key, NULL) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(ca_key);
        return false;
    }

    /* Key first, O_EXCL: an existing CA key is never silently replaced, and
     * a cert without its key is never produced.  The key material itself is
     * never returned — out_ca carries certificate and fingerprint only. */
    if (!provision_write_key_excl_0600(key_path, ca_key)) {
        X509_free(cert);
        EVP_PKEY_free(ca_key);
        return false;
    }

    bool ok = provision_pem_from_x509(cert, out_ca->cert_pem,
                                      sizeof(out_ca->cert_pem));
    if (ok) {
        out_ca->cert_pem_len = strlen(out_ca->cert_pem);
        uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
        if (provision_pubkey_fingerprint(ca_key, fp)) {
            provision_fp_hex(fp, out_ca->fingerprint_hex);
        } else {
            ok = false;
        }
    }
    if (ok) ok = qihse_ca_provision_write_cert_file(cert_path, out_ca->cert_pem);

    X509_free(cert);
    EVP_PKEY_free(ca_key);
    return ok;
}

bool qihse_ca_provision_load_ca(const char* cert_path,
                                qihse_federation_ca_t* out_ca) {
    if (!cert_path || !out_ca) return false;
    memset(out_ca, 0, sizeof(*out_ca));
    size_t len = 0;
    if (!provision_read_file(cert_path, out_ca->cert_pem,
                             sizeof(out_ca->cert_pem), &len)) {
        return false;
    }
    if (len == 0) return false;
    out_ca->cert_pem_len = len;
    /* Recomputed, never trusted from the file: a fingerprint must describe
     * the key actually present. */
    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (!qihse_federation_cert_fingerprint(out_ca->cert_pem, fp)) return false;
    provision_fp_hex(fp, out_ca->fingerprint_hex);
    return true;
}

/* ── Node certificate issuance ─────────────────────────────────────────── */

/* The CA private key must correspond to the CA certificate supplied: raw
 * public keys compared byte for byte, in ONE reusable heap buffer (the
 * 2592-byte ML-DSA-87 keys would otherwise put an 8 KB frame here). */
static bool provision_ca_key_matches(const qihse_federation_ca_t* ca,
                                     EVP_PKEY* ca_key) {
    X509* ca_cert = provision_load_ca_x509(ca);
    if (!ca_cert) return false;
    EVP_PKEY* cert_key = X509_get_pubkey(ca_cert);
    bool ok = false;
    if (cert_key) {
        size_t la = 0, lb = 0;
        if (EVP_PKEY_get_raw_public_key(ca_key, NULL, &la) == 1 &&
            EVP_PKEY_get_raw_public_key(cert_key, NULL, &lb) == 1 &&
            la == lb && la > 0 && la <= 4096u) {
            uint8_t* both = (uint8_t*)malloc(la * 2u);
            if (both) {
                size_t wa = la, wb = la; /* in/out capacities */
                if (EVP_PKEY_get_raw_public_key(ca_key, both, &wa) == 1 &&
                    EVP_PKEY_get_raw_public_key(cert_key, both + la, &wb) == 1 &&
                    wa == la && wb == la) {
                    ok = memcmp(both, both + la, la) == 0;
                }
                free(both);
            }
        }
        EVP_PKEY_free(cert_key);
    }
    X509_free(ca_cert);
    return ok;
}

bool qihse_ca_provision_issue_node(void* operator_user, const char* ca_key_path,
                                   const qihse_federation_ca_t* ca,
                                   const qihse_ca_provision_node_req_t* req,
                                   char* out_cert_pem, size_t out_cap) {
    if (!operator_user || !ca_key_path || !ca || !req || !out_cert_pem ||
        out_cap == 0) {
        return false;
    }
    /* Issuance authority itself... */
    if (!qihse_infra_scope_check(operator_user, QIHSE_SCOPE_NODE_ENROLL)) {
        return false;
    }
    /* ...and the privilege ceiling: the operator must hold EVERY scope the
     * certificate grants.  A principal may not mint authority above its own
     * level (AGENTS.md invariant 2). */
    if (!qihse_infra_scope_check(operator_user, req->scopes)) return false;
    if (!req->public_key || req->public_key_len == 0) return false;
    if (qihse_uuid_is_nil(&req->node_id)) return false;
    const char* ossl = provision_ossl_alg_name(req->sig_alg);
    if (!ossl) return false;
    /* Declared key length against the algorithm's fixed size. */
    if (req->public_key_len != qihse_sig_alg_public_key_bytes(req->sig_alg)) {
        return false;
    }
    if (req->validity_s <= 0 ||
        req->validity_s > QIHSE_CA_PROVISION_MAX_VALIDITY_S) {
        return false;
    }
    if (req->not_before_offset_s < -QIHSE_CA_PROVISION_MAX_TIME_OFFSET_S ||
        req->not_before_offset_s > QIHSE_CA_PROVISION_MAX_TIME_OFFSET_S) {
        return false;
    }

    /* The fingerprint is recomputed from the key being certified; when the
     * operator recorded one out of band, it must still describe this key. */
    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (!qihse_federation_node_fingerprint(req->public_key, req->public_key_len,
                                           fp)) {
        return false;
    }
    if (req->expected_fingerprint &&
        memcmp(req->expected_fingerprint, fp, sizeof(fp)) != 0) {
        return false;
    }

    FILE* kf = fopen(ca_key_path, "rb");
    if (!kf) return false;
    EVP_PKEY* ca_key = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);
    if (!ca_key) return false;
    if (!provision_ca_key_matches(ca, ca_key)) { EVP_PKEY_free(ca_key); return false; }

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(ca_key); return false; }

    X509* ca_cert = provision_load_ca_x509(ca);
    if (!ca_cert) { X509_free(cert); EVP_PKEY_free(ca_key); return false; }

    bool ok = false;
    do {
        /* Mirrors qihse_federation_ca_issue_node(): the serial carries the
         * enrollment epoch, so a certificate issued before a revocation is
         * distinguishable from one issued after it. */
        if (ASN1_INTEGER_set(X509_get_serialNumber(cert),
                             (long)(req->enrollment_epoch + 1u)) != 1) break;
        X509_gmtime_adj(X509_getm_notBefore(cert), (long)req->not_before_offset_s);
        X509_gmtime_adj(X509_getm_notAfter(cert),
                        (long)(req->not_before_offset_s + req->validity_s));
        X509_set_version(cert, 2);

        char node_id_str[QIHSE_UUID_STR_LEN + 1u];
        char cn[128];
        qihse_uuid_format(&req->node_id, node_id_str);
        snprintf(cn, sizeof(cn), "QIHSE node %s", node_id_str);
        X509_NAME* subject = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   (const unsigned char*)cn, -1, -1, 0);
        X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

        /* The node's EXISTING identity key is the certificate key, so the
         * fingerprint an operator already recorded keeps meaning the same
         * thing after issuance. */
        EVP_PKEY* node_key = EVP_PKEY_new_raw_public_key_ex(NULL, ossl, NULL,
                                                            req->public_key,
                                                            req->public_key_len);
        if (!node_key) break;
        if (X509_set_pubkey(cert, node_key) != 1) { EVP_PKEY_free(node_key); break; }
        EVP_PKEY_free(node_key);

        /* A peer is initiator on one negotiation and responder on the next:
         * both EKUs, as in the mtls issuer. */
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage,
                                                  "clientAuth,serverAuth");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                  "critical,CA:FALSE");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

        char san[192];
        snprintf(san, sizeof(san), "URI:qihse://node/%s", node_id_str);
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

        if (!provision_add_scope_ext(cert, req->scopes)) break;

        if (X509_sign(cert, ca_key, NULL) <= 0) break;
        ok = provision_pem_from_x509(cert, out_cert_pem, out_cap);
    } while (0);

    X509_free(cert);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    return ok;
}

/* ── Revocation list ───────────────────────────────────────────────────── */

static bool provision_hex_nibble(char c, unsigned* out) {
    if (c >= '0' && c <= '9') { *out = (unsigned)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned)(c - 'A' + 10); return true; }
    return false;
}

static bool provision_hex_decode_48(const char* hex, uint8_t* out48) {
    if (strlen(hex) != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES * 2u) return false;
    for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++) {
        unsigned hi, lo;
        if (!provision_hex_nibble(hex[i * 2], &hi) ||
            !provision_hex_nibble(hex[i * 2 + 1], &lo)) return false;
        out48[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Strict unsigned decimal: the whole field must be a number. */
static bool provision_parse_u64(const char* f, uint64_t* out) {
    if (!f || *f == '\0') return false;
    errno = 0;
    char* end = NULL;
    unsigned long long v = strtoull(f, &end, 10);
    if (errno != 0 || !end || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

bool qihse_ca_provision_revoke(void* operator_user, const char* crl_path,
                               const qihse_uuid_t* node_id,
                               const uint8_t* node_fingerprint,
                               uint64_t cert_serial, const char* reason) {
    if (!operator_user || !crl_path || !node_id || !reason) return false;
    if (!qihse_infra_scope_check(operator_user, QIHSE_SCOPE_NODE_REVOKE)) {
        return false;
    }
    size_t reason_len = strlen(reason);
    if (reason_len == 0 || reason_len > QIHSE_CA_PROVISION_CRL_REASON_MAX) {
        return false;
    }
    for (size_t i = 0; i < reason_len; i++) {
        unsigned char c = (unsigned char)reason[i];
        if (c == '\t' || c == '\n' || c == '\r' || c < 0x20 || c == 0x7f) {
            return false;
        }
    }

    char node_id_str[QIHSE_UUID_STR_LEN + 1u];
    if (!qihse_uuid_format(node_id, node_id_str)) return false;
    char fp_hex[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES * 2u + 1u];
    if (node_fingerprint) {
        provision_fp_hex(node_fingerprint, fp_hex);
    } else {
        snprintf(fp_hex, sizeof(fp_hex), "-");
    }

    /* Encoder with a bool result the caller propagates; the line is bounded
     * and built in ONE reusable heap buffer. */
    char* line = (char*)malloc(QIHSE_CA_PROVISION_CRL_LINE_MAX);
    if (!line) return false;
    int n = snprintf(line, QIHSE_CA_PROVISION_CRL_LINE_MAX,
                     "%s\t%s\t%llu\t%s\t%llu\t%s\n",
                     QIHSE_CA_PROVISION_CRL_MAGIC, node_id_str,
                     (unsigned long long)cert_serial, fp_hex,
                     (unsigned long long)(uint64_t)time(NULL), reason);
    bool ok = n > 0 && (size_t)n < QIHSE_CA_PROVISION_CRL_LINE_MAX;
    if (ok) {
        int fd = open(crl_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd < 0) {
            ok = false;
        } else {
            size_t off = 0;
            while (ok && off < (size_t)n) {
                ssize_t w = write(fd, line + off, (size_t)n - off);
                if (w <= 0) ok = false;
                else off += (size_t)w;
            }
            if (ok && fsync(fd) != 0) ok = false;
            close(fd);
        }
        if (ok) (void)chmod(crl_path, 0644);
    }
    free(line);
    return ok;
}

/* Strict decoder for one CRL line.  Every declared length is validated
 * against the encoded length and the fixed size (uuid parses, fingerprint
 * is exactly 96 hex chars, numbers are wholly numeric).  Malformed input
 * fails closed rather than being skipped. */
static bool provision_crl_line_match(const char* line,
                                     const qihse_uuid_t* node_id,
                                     const uint8_t* node_fingerprint,
                                     bool* out_match) {
    *out_match = false;
    /* ONE reusable heap buffer for field extraction. */
    char* f = (char*)malloc(QIHSE_CA_PROVISION_CRL_LINE_MAX);
    if (!f) return false;
    bool ok = false;

    /* field 0: magic */
    const char* p = line;
    size_t consumed = 0;
    const char* tab = strchr(p, '\t');
    if (!tab) goto done;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) goto done;
    memcpy(f, p, consumed);
    f[consumed] = '\0';
    if (strcmp(f, QIHSE_CA_PROVISION_CRL_MAGIC) != 0) goto done;
    p = tab + 1;

    /* field 1: node uuid (fixed 36 chars) */
    tab = strchr(p, '\t');
    if (!tab) goto done;
    consumed = (size_t)(tab - p);
    if (consumed != QIHSE_UUID_STR_LEN) goto done;
    memcpy(f, p, consumed);
    f[consumed] = '\0';
    qihse_uuid_t entry_node;
    if (!qihse_uuid_parse(f, &entry_node)) goto done;
    p = tab + 1;

    /* field 2: cert serial (numeric or unknown) */
    tab = strchr(p, '\t');
    if (!tab) goto done;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) goto done;
    memcpy(f, p, consumed);
    f[consumed] = '\0';
    uint64_t serial = 0;
    if (!provision_parse_u64(f, &serial)) goto done;
    p = tab + 1;

    /* field 3: fingerprint, 96 hex chars or "-" */
    tab = strchr(p, '\t');
    if (!tab) goto done;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) goto done;
    memcpy(f, p, consumed);
    f[consumed] = '\0';
    bool have_fp = strcmp(f, "-") != 0;
    uint8_t entry_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (have_fp && !provision_hex_decode_48(f, entry_fp)) goto done;
    p = tab + 1;

    /* field 4: revoked-at unix time */
    tab = strchr(p, '\t');
    if (!tab) goto done;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) goto done;
    memcpy(f, p, consumed);
    f[consumed] = '\0';
    uint64_t revoked_at = 0;
    if (!provision_parse_u64(f, &revoked_at)) goto done;
    p = tab + 1;

    /* field 5: reason, and nothing after it */
    if (strchr(p, '\t')) goto done;
    if (p - line >= (ptrdiff_t)QIHSE_CA_PROVISION_CRL_LINE_MAX) goto done;

    /* The record is well-formed; does it name this principal? */
    if (qihse_uuid_equal(&entry_node, node_id)) *out_match = true;
    if (!*out_match && have_fp && node_fingerprint &&
        memcmp(entry_fp, node_fingerprint,
               QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) == 0) {
        *out_match = true;
    }
    ok = true;

done:
    free(f);
    return ok;
}

bool qihse_ca_provision_crl_check(const char* crl_path,
                                  const qihse_uuid_t* node_id,
                                  const uint8_t* node_fingerprint,
                                  bool* out_revoked) {
    if (!out_revoked || !node_id) return false;
    *out_revoked = false;
    if (!crl_path) return true; /* no CRL configured = nothing revoked */

    FILE* f = fopen(crl_path, "rb");
    if (!f) return errno == ENOENT; /* absent file: empty list */

    /* One reusable heap line buffer; a bounded, fixed-size frame. */
    char* line = (char*)malloc(QIHSE_CA_PROVISION_CRL_LINE_MAX);
    bool ok = false;
    if (line) {
        ok = true;
        while (ok && fgets(line, QIHSE_CA_PROVISION_CRL_LINE_MAX, f)) {
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
            else if (!feof(f)) { ok = false; break; } /* overlong line */
            if (line[0] == '\0') continue;            /* blank line */
            bool match = false;
            if (!provision_crl_line_match(line, node_id, node_fingerprint,
                                          &match)) {
                ok = false; /* malformed record: fail closed */
                break;
            }
            if (match) *out_revoked = true;
        }
        if (ferror(f)) ok = false;
        free(line);
    }
    fclose(f);
    return ok;
}

/* ── Verification ──────────────────────────────────────────────────────── */

static const char* g_verify_names[] = {
    "ok",
    "err_malformed",
    "err_bad_signature",
    "err_not_yet_valid",
    "err_expired",
    "err_revoked",
    "err_scope",
    "err_crl"
};

const char* qihse_ca_verify_result_name(qihse_ca_verify_result_t r) {
    size_t n = sizeof(g_verify_names) / sizeof(g_verify_names[0]);
    size_t i = (size_t)r;
    return (i < n) ? g_verify_names[i] : "unknown";
}

qihse_ca_verify_result_t qihse_ca_provision_verify(
    const qihse_federation_ca_t* ca, const char* crl_path,
    const char* cert_pem, int64_t now_s, qihse_infra_scope_t required_scopes,
    qihse_ca_provision_cert_info_t* out_info) {
    qihse_ca_provision_cert_info_t info;
    memset(&info, 0, sizeof(info));

    if (!ca || !cert_pem) return QIHSE_CA_VERIFY_ERR_MALFORMED;
    X509* cert = provision_x509_from_pem(cert_pem, strlen(cert_pem));
    if (!cert) return QIHSE_CA_VERIFY_ERR_MALFORMED;

    qihse_ca_verify_result_t result = QIHSE_CA_VERIFY_OK;
    do {
        if (!provision_cert_node_id(cert, &info.node_id)) {
            result = QIHSE_CA_VERIFY_ERR_MALFORMED;
            break;
        }
        long serial = ASN1_INTEGER_get(X509_get_serialNumber(cert));
        info.enrollment_epoch = (serial > 0) ? (uint64_t)serial - 1u : 0u;
        if (!provision_get_scope_ext(cert, &info.scopes)) {
            result = QIHSE_CA_VERIFY_ERR_MALFORMED;
            break;
        }
        if (!provision_asn1_time_to_unix(X509_get0_notBefore(cert),
                                         &info.not_before) ||
            !provision_asn1_time_to_unix(X509_get0_notAfter(cert),
                                         &info.not_after)) {
            result = QIHSE_CA_VERIFY_ERR_MALFORMED;
            break;
        }
        if (!qihse_federation_cert_fingerprint(cert_pem, info.fingerprint)) {
            result = QIHSE_CA_VERIFY_ERR_MALFORMED;
            break;
        }
        provision_fp_hex(info.fingerprint, info.fingerprint_hex);

        /* Provenance first: the certificate's own signature against the CA,
         * checked by the same qihse_federation_cert_verify the running node
         * uses.  Detects tampering AND a different CA. */
        if (!qihse_federation_cert_verify(cert_pem, ca)) {
            result = QIHSE_CA_VERIFY_ERR_BAD_SIGNATURE;
            break;
        }
        /* Then the validity window at the caller's clock. */
        if (now_s < info.not_before) {
            result = QIHSE_CA_VERIFY_ERR_NOT_YET_VALID;
            break;
        }
        if (now_s >= info.not_after) {
            result = QIHSE_CA_VERIFY_ERR_EXPIRED;
            break;
        }
        /* Then revocation — outranks everything past provenance. */
        if (crl_path) {
            bool revoked = false;
            if (!qihse_ca_provision_crl_check(crl_path, &info.node_id,
                                              info.fingerprint, &revoked)) {
                result = QIHSE_CA_VERIFY_ERR_CRL;
                break;
            }
            if (revoked) {
                result = QIHSE_CA_VERIFY_ERR_REVOKED;
                break;
            }
        }
        /* A certificate is not authority beyond its scope. */
        if ((info.scopes & required_scopes) != required_scopes) {
            result = QIHSE_CA_VERIFY_ERR_SCOPE;
            break;
        }
    } while (0);

    X509_free(cert);
    if (out_info) *out_info = info;
    return result;
}
