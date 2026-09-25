/*
 * QIHSE federation mTLS — mutual authentication for federation RPC.
 * See docs/plans/qihse_federation_upgrade_plan.md §18 and §22.
 *
 * Post-quantum throughout: ML-DSA certificates and the X25519MLKEM768 hybrid
 * key-exchange group.  The CA private key never enters a QIHSE record and is
 * never held by the database process (plan §3.8).
 */
#include "qihse_federation_mtls.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "qihse_ca_provision.h"
#include "qihse_kv_store.h"

/* ── Small helpers ─────────────────────────────────────────────────────── */

static const char* mtls_ossl_name(qihse_sig_alg_t alg) {
    switch (alg) {
        case QIHSE_SIG_ED25519:   return "ED25519";
        case QIHSE_SIG_ML_DSA_44: return "ML-DSA-44";
        case QIHSE_SIG_ML_DSA_65: return "ML-DSA-65";
        case QIHSE_SIG_ML_DSA_87: return "ML-DSA-87";
    }
    return NULL;
}

static bool write_pem_file_0600(const char* path, EVP_PKEY* key) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    int ok = PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    if (ok != 1) { (void)remove(path); return false; }
#ifndef _WIN32
    (void)chmod(path, 0600);
#endif
    return true;
}

/* SHA-384 over the RAW public key bytes.
 *
 * This must hash the raw key, not the DER-encoded SubjectPublicKeyInfo,
 * because the enrolled node record stores a fingerprint over the raw key
 * (qihse_federation_node_fingerprint).  If the two used different encodings
 * they would never match, and a fingerprint an operator had already recorded
 * would stop meaning anything at the moment a certificate was issued.
 *
 * One definition of "the node's fingerprint" across enrollment, certificates
 * and the operator's records. */
static bool pubkey_fingerprint(EVP_PKEY* pkey, uint8_t* out) {
    if (!pkey || !out) return false;
    size_t raw_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &raw_len) != 1 || raw_len == 0) {
        return false;
    }
    if (raw_len > 4096u) return false;
    uint8_t raw[4096];
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1) return false;
    unsigned int len = 0;
    return EVP_Digest(raw, raw_len, out, &len, EVP_sha384(), NULL) == 1 &&
           len == QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES;
}

static void fingerprint_to_hex(const uint8_t* fp, char* out) {
    for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++) {
        snprintf(out + i * 2, 3, "%02x", fp[i]);
    }
    out[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES * 2u] = '\0';
}

/* ── CA creation ───────────────────────────────────────────────────────── */

bool qihse_federation_ca_create(const char* dir, qihse_sig_alg_t alg,
                                qihse_federation_ca_t* out) {
    if (!dir || !out) return false;
    const char* ossl = mtls_ossl_name(alg);
    if (!ossl) return false;
    if (!qihse_sig_alg_is_post_quantum(alg)) return false; /* CA must be PQC */
    memset(out, 0, sizeof(*out));

    EVP_PKEY* ca_key = EVP_PKEY_Q_keygen(NULL, NULL, ossl);
    if (!ca_key) return false;

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(ca_key); return false; }

    /* A serial number and a validity window.  The CA outlives the node
     * certificates it issues. */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * 365L * 5L);
    X509_set_version(cert, 2);

    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)"QIHSE Federation CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                               (const unsigned char*)"Citadel", -1, -1, 0);
    X509_set_issuer_name(cert, subject);   /* self-signed */
    X509_set_pubkey(cert, ca_key);

    /* Mark it a CA: without this a peer could not build a chain. */
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

    /* The private key goes to disk at 0600 and is deliberately not returned:
     * the database process must not be able to mint its own authority. */
    char key_path[512];
    int n = snprintf(key_path, sizeof(key_path), "%s/federation-ca.key", dir);
    if (n <= 0 || (size_t)n >= sizeof(key_path)) {
        X509_free(cert);
        EVP_PKEY_free(ca_key);
        return false;
    }
    if (!write_pem_file_0600(key_path, ca_key)) {
        X509_free(cert);
        EVP_PKEY_free(ca_key);
        return false;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) { X509_free(cert); EVP_PKEY_free(ca_key); return false; }
    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio); X509_free(cert); EVP_PKEY_free(ca_key); return false;
    }
    /* BIO_get_mem_data returns the LENGTH and writes the data POINTER through
     * its argument.  Passing a length variable as the pointer argument reads an
     * address as a length. */
    char* pem = NULL;
    long pem_len_signed = BIO_get_mem_data(bio, &pem);
    if (!pem || pem_len_signed <= 0) {
        BIO_free(bio); X509_free(cert); EVP_PKEY_free(ca_key); return false;
    }
    size_t pem_len = (size_t)pem_len_signed;
    if (pem_len >= sizeof(out->cert_pem)) {
        BIO_free(bio); X509_free(cert); EVP_PKEY_free(ca_key); return false;
    }
    memcpy(out->cert_pem, pem, pem_len);
    out->cert_pem[pem_len] = '\0';
    out->cert_pem_len = pem_len;
    BIO_free(bio);

    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (!pubkey_fingerprint(ca_key, fp)) {
        X509_free(cert); EVP_PKEY_free(ca_key); return false;
    }
    fingerprint_to_hex(fp, out->fingerprint_hex);

    X509_free(cert);
    EVP_PKEY_free(ca_key);
    return true;
}

/* ── Node certificate issuance ─────────────────────────────────────────── */

static bool load_ca_cert(const qihse_federation_ca_t* ca, X509** out) {
    BIO* bio = BIO_new_mem_buf(ca->cert_pem, (int)ca->cert_pem_len);
    if (!bio) return false;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return false;
    *out = cert;
    return true;
}

bool qihse_federation_ca_issue_node(const char* ca_key_path,
                                    const qihse_federation_ca_t* ca,
                                    const qihse_federation_node_identity_t* node,
                                    uint64_t enrollment_epoch,
                                    char* out_cert_pem, size_t out_cap) {
    if (!ca_key_path || !ca || !node || !out_cert_pem || out_cap == 0) return false;
    if (node->public_key_len == 0) return false;

    FILE* kf = fopen(ca_key_path, "rb");
    if (!kf) return false;
    EVP_PKEY* ca_key = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);
    if (!ca_key) return false;

    X509* ca_cert = NULL;
    if (!load_ca_cert(ca, &ca_cert)) { EVP_PKEY_free(ca_key); return false; }

    X509* cert = X509_new();
    if (!cert) { X509_free(ca_cert); EVP_PKEY_free(ca_key); return false; }

    /* The serial carries the enrollment epoch, so a certificate issued before
     * a revocation is distinguishable from one issued after it. */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)(enrollment_epoch + 1u));
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    /* Short-lived: a node certificate is refreshed by re-enrollment, so a
     * leaked one has a bounded useful life. */
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * 30L);
    X509_set_version(cert, 2);

    X509_NAME* subject = X509_get_subject_name(cert);
    char cn[128];
    char node_id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&node->node_id, node_id_str);
    snprintf(cn, sizeof(cn), "QIHSE node %s", node_id_str);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)cn, -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    /* The node's existing identity key is reused as the certificate key, so
     * the fingerprint an operator already has keeps meaning the same thing. */
    const char* ossl = mtls_ossl_name(node->sig_alg);
    if (!ossl) { X509_free(cert); X509_free(ca_cert); EVP_PKEY_free(ca_key); return false; }
    EVP_PKEY* node_key = EVP_PKEY_new_raw_public_key_ex(NULL, ossl, NULL,
                                                       node->public_key,
                                                       node->public_key_len);
    if (!node_key) { X509_free(cert); X509_free(ca_cert); EVP_PKEY_free(ca_key); return false; }
    if (X509_set_pubkey(cert, node_key) != 1) {
        EVP_PKEY_free(node_key); X509_free(cert); X509_free(ca_cert); EVP_PKEY_free(ca_key);
        return false;
    }

    /* A peer is initiator on one negotiation and responder on the next, so it
     * needs BOTH EKUs: a client-only certificate fails half the time. */
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage,
                                              "clientAuth,serverAuth");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                              "critical,CA:FALSE");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

    /* Bind the node UUID as a subjectAltName so the identity travels with the
     * certificate rather than having to be inferred from the CN. */
    char san[192];
    snprintf(san, sizeof(san), "URI:qihse://node/%s", node_id_str);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

    if (X509_sign(cert, ca_key, NULL) <= 0) {
        EVP_PKEY_free(node_key); X509_free(cert); X509_free(ca_cert); EVP_PKEY_free(ca_key);
        return false;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    bool ok = bio && PEM_write_bio_X509(bio, cert) == 1;
    if (ok) {
        char* pem = NULL;
        long pem_len_signed = BIO_get_mem_data(bio, &pem);
        size_t pem_len = (pem_len_signed > 0) ? (size_t)pem_len_signed : 0u;
        if (!pem || pem_len == 0 || pem_len >= out_cap) ok = false;
        else {
            memcpy(out_cert_pem, pem, pem_len);
            out_cert_pem[pem_len] = '\0';
        }
    }
    if (bio) BIO_free(bio);
    EVP_PKEY_free(node_key);
    X509_free(cert);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    return ok;
}

/* ── Certificate inspection ────────────────────────────────────────────── */

bool qihse_federation_cert_fingerprint(const char* cert_pem,
                                       uint8_t* out_fingerprint) {
    if (!cert_pem || !out_fingerprint) return false;
    BIO* bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) return false;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return false;
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    bool ok = pkey && pubkey_fingerprint(pkey, out_fingerprint);
    if (pkey) EVP_PKEY_free(pkey);
    X509_free(cert);
    return ok;
}

bool qihse_federation_cert_verify(const char* cert_pem,
                                  const qihse_federation_ca_t* ca) {
    if (!cert_pem || !ca) return false;
    BIO* bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) return false;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return false;

    X509* ca_cert = NULL;
    if (!load_ca_cert(ca, &ca_cert)) { X509_free(cert); return false; }

    EVP_PKEY* ca_key = X509_get_pubkey(ca_cert);
    /* Verifies the certificate's own signature against the CA, which proves
     * issuance and detects alteration.  It does NOT prove the node is still
     * trusted: that is the enrolled record's job. */
    bool ok = ca_key && X509_verify(cert, ca_key) == 1;
    if (ca_key) EVP_PKEY_free(ca_key);
    X509_free(ca_cert);
    X509_free(cert);
    return ok;
}

/* ── Node-side CRL: the file half of revocation state ────────────────────
 *
 * qihse_ca_provision.h is included ONLY for the on-disk format constants
 * (magic, line bound); no CA-provisioning code is linked into libqihse.so,
 * so the database process still gains no minting capability.  The parser
 * below mirrors provision_crl_line_match() and the reader loop of
 * qihse_ca_provision_crl_check() in src/federation/qihse_ca_provision.c
 * EXACTLY — that parser is normative, because the node must accept exactly
 * what the tool writes and refuse exactly what the tool refuses.  Where the
 * tool's parser is lenient in a way its writer never produces (e.g. a
 * strtoull-accepted sign or space in a numeric field), this loader stays
 * equally lenient rather than diverging from the reference. */

typedef struct {
    qihse_uuid_t node_id;
    bool have_fingerprint;
    uint8_t fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
} mtls_crl_entry_t;

/* Process-wide snapshot, published only after a fully successful parse.
 * The check below scans under the same mutex the loader swaps under, so a
 * reload can never free an entry a verification is still comparing. */
static pthread_mutex_t g_crl_lock = PTHREAD_MUTEX_INITIALIZER;
static mtls_crl_entry_t* g_crl_entries = NULL;
static size_t g_crl_count = 0;
static bool g_crl_configured = false;
static bool g_crl_failed = false;

static bool mtls_hex_nibble(char c, unsigned* out) {
    if (c >= '0' && c <= '9') { *out = (unsigned)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned)(c - 'A' + 10); return true; }
    return false;
}

static bool mtls_hex_decode_48(const char* hex, uint8_t* out48) {
    if (strlen(hex) != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES * 2u) return false;
    for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++) {
        unsigned hi, lo;
        if (!mtls_hex_nibble(hex[i * 2], &hi) ||
            !mtls_hex_nibble(hex[i * 2 + 1], &lo)) return false;
        out48[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Strict unsigned decimal, byte for byte the tool's provision_parse_u64(). */
static bool mtls_parse_u64(const char* f, uint64_t* out) {
    if (!f || *f == '\0') return false;
    errno = 0;
    char* end = NULL;
    unsigned long long v = strtoull(f, &end, 10);
    if (errno != 0 || !end || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

/* Decode ONE record into `out`.  `field` is the single reusable heap buffer
 * every column is extracted through (AGENTS.md decoder rule 1).  Declared
 * length is validated against the encoded length and the fixed size on
 * every field: uuid is exactly QIHSE_UUID_STR_LEN and must parse, the
 * fingerprint is exactly 96 hex chars or "-", and both numbers must be
 * wholly numeric.  Serial and revoked-at are validated and then unused —
 * matching is by UUID or fingerprint, exactly as in the tool. */
static bool mtls_crl_line_parse(const char* line, char* field,
                                mtls_crl_entry_t* out) {
    memset(out, 0, sizeof(*out));

    /* field 0: magic */
    const char* p = line;
    const char* tab = strchr(p, '\t');
    if (!tab) return false;
    size_t consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) return false;
    memcpy(field, p, consumed);
    field[consumed] = '\0';
    if (strcmp(field, QIHSE_CA_PROVISION_CRL_MAGIC) != 0) return false;
    p = tab + 1;

    /* field 1: node uuid (fixed 36 chars) */
    tab = strchr(p, '\t');
    if (!tab) return false;
    consumed = (size_t)(tab - p);
    if (consumed != QIHSE_UUID_STR_LEN) return false;
    memcpy(field, p, consumed);
    field[consumed] = '\0';
    if (!qihse_uuid_parse(field, &out->node_id)) return false;
    p = tab + 1;

    /* field 2: cert serial (numeric, not used for matching) */
    tab = strchr(p, '\t');
    if (!tab) return false;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) return false;
    memcpy(field, p, consumed);
    field[consumed] = '\0';
    uint64_t serial = 0;
    if (!mtls_parse_u64(field, &serial)) return false;
    p = tab + 1;

    /* field 3: fingerprint, 96 hex chars or "-" */
    tab = strchr(p, '\t');
    if (!tab) return false;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) return false;
    memcpy(field, p, consumed);
    field[consumed] = '\0';
    out->have_fingerprint = strcmp(field, "-") != 0;
    if (out->have_fingerprint && !mtls_hex_decode_48(field, out->fingerprint)) {
        return false;
    }
    p = tab + 1;

    /* field 4: revoked-at unix time */
    tab = strchr(p, '\t');
    if (!tab) return false;
    consumed = (size_t)(tab - p);
    if (consumed >= QIHSE_CA_PROVISION_CRL_LINE_MAX) return false;
    memcpy(field, p, consumed);
    field[consumed] = '\0';
    uint64_t revoked_at = 0;
    if (!mtls_parse_u64(field, &revoked_at)) return false;
    p = tab + 1;

    /* field 5: reason, and nothing after it — no tabs, bounded length. */
    if (strchr(p, '\t')) return false;
    if (p - line >= (ptrdiff_t)QIHSE_CA_PROVISION_CRL_LINE_MAX) return false;

    (void)serial;
    (void)revoked_at;
    return true;
}

bool qihse_federation_crl_load(void* operator_user, const char* crl_path) {
    /* Authorization first: loading a CRL is the node-side application of
     * revocation authority (the read half of QIHSE_SCOPE_NODE_REVOKE), so
     * NULL is refused, never a bypass (AGENTS.md invariant 1). */
    if (!operator_user) return false;
    if (!qihse_infra_scope_check(operator_user, QIHSE_SCOPE_NODE_REVOKE)) {
        return false;
    }

    /* Explicit authorized opt-out: return to KV-only revocation. */
    if (!crl_path) {
        pthread_mutex_lock(&g_crl_lock);
        free(g_crl_entries);
        g_crl_entries = NULL;
        g_crl_count = 0;
        g_crl_configured = false;
        g_crl_failed = false;
        pthread_mutex_unlock(&g_crl_lock);
        return true;
    }

    /* Two heap buffers total (line + reusable field extraction), one cleanup
     * path: the decoder's frame stays a handful of locals (AGENTS.md rules
     * 1-2 for bounded stack frames). */
    char* line = (char*)malloc(QIHSE_CA_PROVISION_CRL_LINE_MAX);
    char* field = (char*)malloc(QIHSE_CA_PROVISION_CRL_LINE_MAX);
    FILE* f = NULL;
    mtls_crl_entry_t* entries = NULL;
    size_t count = 0;
    size_t capacity = 0;
    bool ok = line && field;

    if (ok) {
        f = fopen(crl_path, "rb");
        if (!f) {
            /* An absent file is an empty list, exactly as in the tool's
             * qihse_ca_provision_crl_check; any other I/O error fails. */
            ok = (errno == ENOENT);
        }
    }

    /* Reader loop, mirroring the tool line for line: an overlong line, a
     * blank-passing-but-malformed record, or any I/O error refuses the
     * whole file — malformed input is never skipped. */
    while (ok && f && fgets(line, QIHSE_CA_PROVISION_CRL_LINE_MAX, f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        else if (!feof(f)) { ok = false; break; } /* overlong line */
        if (line[0] == '\0') continue;            /* blank line */

        mtls_crl_entry_t entry;
        if (!mtls_crl_line_parse(line, field, &entry)) { ok = false; break; }

        if (count >= QIHSE_FEDERATION_CRL_MAX_ENTRIES) { ok = false; break; }
        if (count == capacity) {
            size_t next = (capacity == 0) ? 16u : capacity * 2u;
            mtls_crl_entry_t* grown =
                (mtls_crl_entry_t*)realloc(entries, next * sizeof(*entries));
            if (!grown) { ok = false; break; }
            entries = grown;
            capacity = next;
        }
        entries[count++] = entry;
    }
    if (ok && f && ferror(f)) ok = false;

    if (f) fclose(f);
    free(field);
    free(line);

    /* Publish or poison, under the same lock the check scans under.  A
     * failed load drops any previous snapshot AND leaves the sticky
     * fail-closed flag set: a configured CRL that cannot be parsed must
     * never let a peer verify as clean, exactly like the tool. */
    pthread_mutex_lock(&g_crl_lock);
    if (ok) {
        free(g_crl_entries);
        g_crl_entries = entries;
        g_crl_count = count;
        g_crl_configured = true;
        g_crl_failed = false;
        entries = NULL;
    } else {
        free(entries);
        free(g_crl_entries);
        g_crl_entries = NULL;
        g_crl_count = 0;
        g_crl_configured = false;
        g_crl_failed = true;
    }
    pthread_mutex_unlock(&g_crl_lock);
    return ok;
}

bool qihse_federation_crl_check(const qihse_uuid_t* node_id,
                                const uint8_t* node_fingerprint,
                                bool* out_revoked) {
    if (!out_revoked || !node_id) return false;
    *out_revoked = false;

    pthread_mutex_lock(&g_crl_lock);
    if (g_crl_failed) {
        /* Sticky fail-closed: an unparsable configured CRL refuses the whole
         * check; the caller must not treat this as "not revoked". */
        pthread_mutex_unlock(&g_crl_lock);
        return false;
    }
    for (size_t i = 0; i < g_crl_count; i++) {
        const mtls_crl_entry_t* e = &g_crl_entries[i];
        if (qihse_uuid_equal(&e->node_id, node_id)) {
            *out_revoked = true;
            break;
        }
        if (e->have_fingerprint && node_fingerprint &&
            memcmp(e->fingerprint, node_fingerprint,
                   QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) == 0) {
            *out_revoked = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_crl_lock);
    return true;
}

void qihse_federation_crl_state(qihse_federation_crl_status_t* out) {
    if (!out) return;
    pthread_mutex_lock(&g_crl_lock);
    out->entry_count = g_crl_count;
    out->configured = g_crl_configured;
    out->failed = g_crl_failed;
    pthread_mutex_unlock(&g_crl_lock);
}

/* ── The three-layer peer decision ─────────────────────────────────────── */

typedef struct { qihse_peer_verdict_t v; const char* name; } peer_verdict_entry_t;

static const peer_verdict_entry_t g_peer_verdicts[] = {
    { QIHSE_PEER_ACCEPT,                    "accept" },
    { QIHSE_PEER_REJECT_NO_CERT,            "reject_no_cert" },
    { QIHSE_PEER_REJECT_UNKNOWN_FINGERPRINT, "reject_unknown_fingerprint" },
    { QIHSE_PEER_REJECT_NOT_YET_APPROVED,   "reject_not_yet_approved" },
    { QIHSE_PEER_REJECT_REVOKED,            "reject_revoked" },
    { QIHSE_PEER_REJECT_UNTRUSTED,          "reject_untrusted" },
    { QIHSE_PEER_REJECT_MALFORMED,          "reject_malformed" },
    { QIHSE_PEER_REJECT_CRL,                "reject_crl" },
};

const char* qihse_peer_verdict_name(qihse_peer_verdict_t v) {
    for (size_t i = 0; i < sizeof(g_peer_verdicts) / sizeof(g_peer_verdicts[0]); i++) {
        if (g_peer_verdicts[i].v == v) return g_peer_verdicts[i].name;
    }
    return "unknown";
}

/* Find an enrolled node whose fingerprint matches.  This is the whole of
 * layer 2: a certificate proves a key, and this proves the key belongs to a
 * node we enrolled. */
typedef struct {
    const uint8_t* want;
    bool found;
    qihse_federation_node_identity_t node;
} fingerprint_search_t;

static bool fingerprint_search_cb(const qihse_federation_node_identity_t* node,
                                  void* user_data) {
    fingerprint_search_t* s = (fingerprint_search_t*)user_data;
    if (memcmp(node->fingerprint, s->want, QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) == 0) {
        s->node = *node;
        s->found = true;
        return false; /* stop */
    }
    return true;
}

qihse_peer_verdict_t qihse_federation_peer_verify(void* store_void, void* user_void,
                                                 const uint8_t* cert_fingerprint,
                                                 size_t fingerprint_len,
                                                 qihse_uuid_t* out_node_id,
                                                 qihse_runtime_trust_t* out_trust) {
    if (out_trust) *out_trust = QIHSE_RTRUST_UNKNOWN;
    if (!store_void || !user_void || !cert_fingerprint) return QIHSE_PEER_REJECT_NO_CERT;
    if (fingerprint_len != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) {
        return QIHSE_PEER_REJECT_MALFORMED;
    }

    /* Layer 2: the key must belong to a node we enrolled.  A certificate that
     * verifies against the CA but matches no enrolled node is a valid
     * credential for an identity we do not know, which is not the same thing
     * as a peer. */
    fingerprint_search_t search;
    memset(&search, 0, sizeof(search));
    search.want = cert_fingerprint;
    qihse_federation_node_foreach(store_void, user_void, fingerprint_search_cb, &search);
    if (!search.found) return QIHSE_PEER_REJECT_UNKNOWN_FINGERPRINT;

    if (search.node.trust == QIHSE_TRUST_REVOKED) return QIHSE_PEER_REJECT_REVOKED;
    if (search.node.trust == QIHSE_TRUST_PENDING) return QIHSE_PEER_REJECT_NOT_YET_APPROVED;

    /* Layer 2, file source: the CRL the out-of-process CA tool writes
     * (loaded explicitly by an operator via qihse_federation_crl_load)
     * COMPOSES with the KV record above — either source saying REVOKED
     * refuses the peer, with the same verdict a KV-revoked node produces.
     * A configured CRL that failed to load fails the whole check closed:
     * an unparsable revocation list must never verify a peer as clean,
     * mirroring qihse_ca_provision_crl_check.  With no CRL configured this
     * is a no-op and the decision is byte-for-byte what it was before. */
    bool crl_revoked = false;
    if (!qihse_federation_crl_check(&search.node.node_id, cert_fingerprint,
                                    &crl_revoked)) {
        return QIHSE_PEER_REJECT_CRL;
    }
    if (crl_revoked) return QIHSE_PEER_REJECT_REVOKED;

    /* Layer 3: enrollment says the node is a member; it does not say the node
     * is currently trustworthy.
     *
     * The brief draws a distinction that matters here.  Runtime evidence is
     * required "before granting voter or strong-write authority" — not before
     * granting a session at all.  So layer 3 decides what a session CARRIES,
     * and refuses it outright only when the runtime state says the node must
     * not exchange federation state at all:
     *
     *   UNKNOWN           session, no strong authority  (we know who you are,
     *                                                    not yet that you are
     *                                                    trustworthy)
     *   TRUSTED           session with full authority
     *   TRUSTED_DEGRADED  session, no strong authority
     *   LOCAL_ONLY        refused: may not replicate
     *   QUARANTINED       refused: forensic access only
     *   REVOKED           refused (caught at layer 2)
     *
     * The caller reads out_trust to decide the authority the session carries;
     * it must never infer authority from the certificate. */
    qihse_admission_t adm;
    if (!qihse_runtime_admission_for_node(store_void, user_void,
                                         &search.node.node_id, &adm)) {
        return QIHSE_PEER_REJECT_UNTRUSTED;
    }
    if (out_trust) *out_trust = adm.trust_state;

    /* Only the states that may not exchange federation state at all are
     * refused a session.  UNKNOWN is deliberately NOT among them: a node that
     * has just enrolled has no evidence yet, and refusing it a session would
     * make enrollment useless without also weakening the identity check. */
    if (adm.trust_state == QIHSE_RTRUST_LOCAL_ONLY ||
        adm.trust_state == QIHSE_RTRUST_QUARANTINED ||
        adm.trust_state == QIHSE_RTRUST_REVOKED) {
        return QIHSE_PEER_REJECT_UNTRUSTED;
    }

    if (out_node_id) *out_node_id = search.node.node_id;
    return QIHSE_PEER_ACCEPT;
}

/* ── TLS configuration ─────────────────────────────────────────────────── */

const char* qihse_federation_tls_group_list(void) {
    /* Hybrid: the session key is post-quantum-secure while the classical half
     * keeps interoperability if the ML-KEM implementation is ever doubted.
     * This is the half of TLS that had to move first, because recorded traffic
     * can be decrypted retroactively. */
    return "X25519MLKEM768:X25519";
}

const char* qihse_federation_tls_min_version(void) {
    return "TLSv1.3";
}
