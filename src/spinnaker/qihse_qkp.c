#include "qihse_qkp.h"
#include "qihse_pqc_crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <errno.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Wire constants (see include/qihse_qkp.h for the layout contract). */
static const char QKP_MAGIC[4]  = {'Q', 'K', 'P', '1'};
static const char SEAL_MAGIC[4] = {'Q', 'S', 'E', '1'};
static const char H1_DOMAIN[]   = "QKP1-H1";
static const char H2_DOMAIN[]   = "QKP1-H2";
static const char ACK_PAYLOAD[] = "QKP1-ACK";
static const char HKDF_INFO[]   = "QIHSE-QKP1-v1";
#define QIHSE_QKP_SIG_LEN   QIHSE_MLDSA_SIGNATURE_SIZE
#define QIHSE_QKP_CT_LEN    QIHSE_MLKEM_CIPHERTEXT_SIZE
#define QIHSE_QKP_TR_LEN    48  /* SHA-384 transcript hash */

#define DIR_C2S 0x00000001u
#define DIR_S2C 0x00000002u

typedef enum { QKP_ROLE_SERVER = 0, QKP_ROLE_CLIENT = 1 } qkp_role_t;

static bool qkp_sha384(const uint8_t* in, size_t len, uint8_t out[QIHSE_QKP_TR_LEN]) {
    unsigned int olen = 0;
    return EVP_Digest(in, len, out, &olen, EVP_sha384(), NULL) == 1 && olen == QIHSE_QKP_TR_LEN;
}

struct qihse_qkp_session {
    qkp_role_t role;
    uint8_t key_c2s[QIHSE_QKP_KEY_LEN];
    uint8_t key_s2c[QIHSE_QKP_KEY_LEN];
    uint64_t tx_seq;   /* per direction, starts at 1 */
    uint64_t rx_seq;
};

/* ── fd helpers (bounded, EINTR-tolerant) ─────────────────────────────── */

static bool qkp_write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = send(fd, p + done, len - done, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

static bool qkp_read_exact(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = recv(fd, p + done, len - done, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        done += (size_t)r;
    }
    return true;
}

static bool qkp_send_err(int fd, const char* text) {
    char line[192];
    int n = snprintf(line, sizeof(line), "-ERR %s\r\n", text);
    return n > 0 && qkp_write_all(fd, line, (size_t)n);
}

/* ── framing ──────────────────────────────────────────────────────────── */

static bool qkp_send_frame(int fd, uint8_t type, const void* payload, uint16_t len) {
    uint8_t head[8];
    memcpy(head, QKP_MAGIC, 4u);
    head[4] = type;
    head[5] = 0u;
    head[6] = (uint8_t)(len >> 8);
    head[7] = (uint8_t)(len & 0xffu);
    return qkp_write_all(fd, head, sizeof(head)) &&
           (len == 0u || qkp_write_all(fd, payload, len));
}

/* Reads one QKP1 frame; caller validates type/payload. frame_out must hold
 * QIHSE_QKP_MAX_PAYLOAD. Returns payload length or -1. */
static ssize_t qkp_read_frame(int fd, uint8_t* frame_out) {
    uint8_t head[8];
    if (!qkp_read_exact(fd, head, sizeof(head))) return -1;
    if (memcmp(head, QKP_MAGIC, 4u) != 0 || head[5] != 0u) return -1;
    uint16_t len = (uint16_t)((head[6] << 8) | head[7]);
    if (len > QIHSE_QKP_MAX_PAYLOAD) return -1;
    if (len && !qkp_read_exact(fd, frame_out, len)) return -1;
    return (ssize_t)len;
}

/* ── transcript + derivation ──────────────────────────────────────────── */

static bool qkp_hkdf_sha384(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* out, size_t out_len) {
    uint8_t prk[48];
    unsigned int prk_len = 0;
    if (HMAC(EVP_sha384(), salt, (int)salt_len, ikm, (int)ikm_len, prk, &prk_len) == NULL ||
        prk_len != 48u) return false;
    uint8_t block[48];
    size_t block_len = 48u, done = 0;
    unsigned char counter = 1u;
    while (done < out_len) {
        size_t feed = done ? block_len : 0u;
        unsigned int maclen = 0;
        uint8_t msg[256];
        if (feed + info_len > sizeof(msg)) return false;
        memcpy(msg, block, feed);
        memcpy(msg + feed, info, info_len);
        if (HMAC(EVP_sha384(), prk, (int)prk_len, msg, (int)(feed + info_len), block, &maclen) == NULL ||
            maclen != 48u) return false;
        block_len = maclen;
        size_t take = out_len - done < block_len ? out_len - done : block_len;
        memcpy(out + done, block, take);
        done += take;
        counter++;
        if (counter > 255u) return false;
        (void)counter;
    }
    return true;
}

/* ── AEAD (ChaCha20-Poly1305) ─────────────────────────────────────────── */

static bool qkp_aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* plain, size_t plain_len,
                          uint8_t* ct_out /* plain_len + 16 */) {
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return false;
    int len = 0;
    bool ok = EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
              EVP_EncryptInit_ex(cctx, NULL, NULL, key, nonce) == 1 &&
              (aad_len == 0 || EVP_EncryptUpdate(cctx, NULL, &len, aad, (int)aad_len) == 1) &&
              EVP_EncryptUpdate(cctx, ct_out, &len, plain, (int)plain_len) == 1;
    size_t produced = ok ? (size_t)len : 0;
    if (ok && EVP_EncryptFinal_ex(cctx, ct_out + produced, &len) == 1) {
        produced += (size_t)len;
        ok = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 16, ct_out + produced) == 1;
    } else {
        ok = false;
    }
    EVP_CIPHER_CTX_free(cctx);
    return ok;
}

static bool qkp_aead_open(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ct, size_t ct_len,
                          uint8_t* plain_out /* ct_len - 16 */) {
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return false;
    int len = 0;
    size_t dec_len = ct_len > 16u ? ct_len - 16u : 0u;
    bool ok = EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
              EVP_DecryptInit_ex(cctx, NULL, NULL, key, nonce) == 1 &&
              (aad_len == 0 || EVP_DecryptUpdate(cctx, NULL, &len, aad, (int)aad_len) == 1) &&
              EVP_DecryptUpdate(cctx, plain_out, &len, ct, (int)dec_len) == 1;
    size_t produced = ok ? (size_t)len : 0;
    if (ok) {
        uint8_t tag[16];
        memcpy(tag, ct + dec_len, 16u);
        ok = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1 &&
             EVP_DecryptFinal_ex(cctx, plain_out + produced, &len) > 0;
    }
    EVP_CIPHER_CTX_free(cctx);
    return ok;
}

static void qkp_make_nonce(uint8_t nonce[12], uint32_t dir, uint64_t seq) {
    nonce[0] = (uint8_t)(dir >> 24); nonce[1] = (uint8_t)(dir >> 16);
    nonce[2] = (uint8_t)(dir >> 8);  nonce[3] = (uint8_t)dir;
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(seq >> (56 - 8 * i));
}

/* ── negotiation ──────────────────────────────────────────────────────── */

static void qkp_log_reject(const qihse_qkp_config_t* cfg, const char* reason) {
    fprintf(stderr, "qihse qkp: connection rejected: %s\n", reason);
    (void)cfg;
}

qihse_qkp_result_t qihse_qkp_server_negotiate(int fd, const qihse_qkp_config_t* cfg,
                                              qihse_qkp_session_t** out) {
    if (out) *out = NULL;
    if (!cfg) return QIHSE_QKP_REJECTED;
    uint8_t probe;
    ssize_t r = recv(fd, &probe, 1u, MSG_PEEK);
    if (r <= 0) return QIHSE_QKP_REJECTED;
    if (probe != QKP_MAGIC[0]) {
        if (cfg->require) {
            qkp_send_err(fd, "PQC handshake required: this endpoint does not accept cleartext");
            return QIHSE_QKP_REJECTED;
        }
        return QIHSE_QKP_CLEARTEXT;
    }
    if (!cfg->dsa_key_path || !cfg->kem_key_path || !cfg->kem_pub_path ||
        cfg->trusted_count == 0 || !cfg->trusted_pubs) {
        qkp_send_err(fd, "PQC handshake required but server identity is not configured");
        return QIHSE_QKP_REJECTED;
    }

    uint8_t probe4[4];
    if (!qkp_read_exact(fd, probe4, 4u) || memcmp(probe4, QKP_MAGIC, 4u) != 0) {
        qkp_send_err(fd, "PQC handshake malformed probe");
        return QIHSE_QKP_REJECTED;
    }

    uint8_t nonce[QIHSE_QKP_NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        qkp_send_err(fd, "PQC handshake entropy failure");
        return QIHSE_QKP_REJECTED;
    }
    /* Server KEM public key: read the PEM file once, bound. */
    uint8_t pem[8192];
    size_t pem_len = 0;
    {
        FILE* f = fopen(cfg->kem_pub_path, "rb");
        if (!f) { qkp_send_err(fd, "PQC server KEM public key unavailable"); return QIHSE_QKP_REJECTED; }
        pem_len = fread(pem, 1u, sizeof(pem), f);
        fclose(f);
        if (pem_len == 0u || pem_len >= sizeof(pem)) {
            qkp_send_err(fd, "PQC server KEM public key invalid");
            return QIHSE_QKP_REJECTED;
        }
    }

    /* H1 payload: proto u16 ‖ node_id 64 ‖ nonce 32 ‖ kem_pub_len u16 ‖ pem ‖ sig */
    size_t id_len = cfg->node_id ? strlen(cfg->node_id) : 0u;
    if (id_len > 64u) id_len = 64u;
    uint16_t body_len = (uint16_t)(2u + 64u + 32u + 2u + pem_len);
    uint16_t h1_len = (uint16_t)(body_len + QIHSE_QKP_SIG_LEN);
    uint8_t* h1 = (uint8_t*)malloc(h1_len);
    if (!h1) { qkp_send_err(fd, "out of memory"); return QIHSE_QKP_REJECTED; }
    {
        uint8_t* p = h1;
        *p++ = (uint8_t)(QIHSE_QKP_PROTO_VERSION >> 8);
        *p++ = (uint8_t)QIHSE_QKP_PROTO_VERSION;
        memset(p, 0, 64u); memcpy(p, cfg->node_id ? cfg->node_id : "", id_len); p += 64u;
        memcpy(p, nonce, 32u); p += 32u;
        *p++ = (uint8_t)(pem_len >> 8); *p++ = (uint8_t)pem_len;
        memcpy(p, pem, pem_len); p += pem_len;
        (void)body_len;
    }
    /* Signed region: "QKP1-H1" ‖ h1 payload sans signature. The transcript
     * hash for the derivation covers this exact signed region too. */
    size_t h1_body_len = (size_t)h1_len - QIHSE_QKP_SIG_LEN;
    size_t h1_signed_len = strlen(H1_DOMAIN) + h1_body_len;
    uint8_t* signed_buf = (uint8_t*)malloc(h1_signed_len);
    if (!signed_buf) { free(h1); qkp_send_err(fd, "out of memory"); return QIHSE_QKP_REJECTED; }
    memcpy(signed_buf, H1_DOMAIN, strlen(H1_DOMAIN));
    memcpy(signed_buf + strlen(H1_DOMAIN), h1, h1_body_len);
    uint8_t h1_hash[QIHSE_QKP_TR_LEN];
    bool signed_ok = qihse_pqc_sign_path(signed_buf, h1_signed_len, h1 + (size_t)(h1_len - QIHSE_QKP_SIG_LEN),
                                         cfg->dsa_key_path) &&
                     qkp_sha384(signed_buf, h1_signed_len, h1_hash);
    free(signed_buf);
    if (!signed_ok) {
        free(h1);
        qkp_log_reject(cfg, "H1 signing failed");
        qkp_send_err(fd, "PQC handshake internal failure");
        return QIHSE_QKP_REJECTED;
    }
    if (!qkp_send_frame(fd, 1u, h1, h1_len)) {
        free(h1);
        return QIHSE_QKP_REJECTED;
    }

    /* H2 */
    uint8_t h2[QIHSE_QKP_MAX_PAYLOAD];
    ssize_t h2_len = qkp_read_frame(fd, h2);
    if (h2_len < 0) { free(h1); fprintf(stderr, "QKP-DBG: H2 read_frame failed\n"); return QIHSE_QKP_REJECTED; }
    if ((size_t)h2_len != 64u + 32u + QIHSE_QKP_CT_LEN + QIHSE_QKP_SIG_LEN) {
        free(h1); qkp_log_reject(cfg, "H2 size invalid");
        qkp_send_err(fd, "PQC H2 size invalid");
        return QIHSE_QKP_REJECTED;
    }
    const uint8_t* cli_id   = h2;
    const uint8_t* cli_nonce = h2 + 64u;
    const uint8_t* ct        = h2 + 64u + 32u;
    const uint8_t* sig       = h2 + 64u + 32u + QIHSE_QKP_CT_LEN;

    /* Verify the client signature against ANY trusted anchor. The H2 signed
     * region binds the H1 transcript hash, so a tampered H1 fails here even
     * though the client never saw the original. */
    size_t h2_signed_len = strlen(H2_DOMAIN) + QIHSE_QKP_TR_LEN + 64u + 32u + QIHSE_QKP_CT_LEN;
    uint8_t* h2_signed = (uint8_t*)malloc(h2_signed_len);
    if (!h2_signed) { qkp_send_err(fd, "out of memory"); return QIHSE_QKP_REJECTED; }
    {
        uint8_t* p = h2_signed;
        memcpy(p, H2_DOMAIN, strlen(H2_DOMAIN)); p += strlen(H2_DOMAIN);
        memcpy(p, h1_hash, QIHSE_QKP_TR_LEN); p += QIHSE_QKP_TR_LEN;
        memcpy(p, cli_id, 64u); p += 64u;
        memcpy(p, cli_nonce, 32u); p += 32u;
        memcpy(p, ct, QIHSE_QKP_CT_LEN);
    }
    {
        uint8_t dbg[QIHSE_QKP_TR_LEN];
        qkp_sha384(h2_signed, h2_signed_len, dbg);
        fprintf(stderr, "QKP-DBG2 srv h1_hash=%02x%02x h2sig_hash=%02x%02x len=%zu\n",
                h1_hash[0], h1_hash[1], dbg[0], dbg[1], h2_signed_len);
    }
    bool client_trusted = false;
    for (size_t i = 0; i < cfg->trusted_count && !client_trusted; i++) {
        client_trusted = qihse_pqc_verify_path(h2_signed, h2_signed_len, sig, cfg->trusted_pubs[i]);
    }
    free(h2_signed);
    if (!client_trusted) {
        qkp_log_reject(cfg, "client identity not in the trusted set");
        qkp_send_err(fd, "PQC client identity untrusted");
        return QIHSE_QKP_REJECTED;
    }

    /* Decapsulate with OUR KEM private key. */
    qihse_pqc_ctx_t kem;
    memset(&kem, 0, sizeof(kem));
    if (!qihse_pqc_decapsulate_private(&kem, cfg->kem_key_path, ct)) {
        qkp_log_reject(cfg, "decapsulation failed");
        qkp_send_err(fd, "PQC key establishment failed");
        return QIHSE_QKP_REJECTED;
    }

    /* Derive. */
    uint8_t ss[QIHSE_MLKEM_SHARED_SIZE];
    memcpy(ss, kem.aes_key, sizeof(ss));
    qihse_pqc_destroy(&kem);
    uint8_t salt[QIHSE_QKP_TR_LEN];
    memcpy(salt, h1_hash, QIHSE_QKP_TR_LEN);
    uint8_t ikm[32 + 32 + 32];
    memcpy(ikm, ss, 32u); memcpy(ikm + 32u, cli_nonce, 32u); memcpy(ikm + 64u, nonce, 32u);
    uint8_t okm[64];
    if (!qkp_hkdf_sha384(salt, QIHSE_QKP_TR_LEN, ikm, sizeof(ikm),
                         (const uint8_t*)HKDF_INFO, strlen(HKDF_INFO), okm, sizeof(okm))) {
        qkp_send_err(fd, "internal");
        return QIHSE_QKP_REJECTED;
    }

    qihse_qkp_session_t* s = (qihse_qkp_session_t*)calloc(1u, sizeof(*s));
    if (!s) { fprintf(stderr, "QKP-DBG: session calloc failed\n"); qkp_send_err(fd, "out of memory"); return QIHSE_QKP_REJECTED; }
    s->role = QKP_ROLE_SERVER;
    memcpy(s->key_c2s, okm, 32u);
    memcpy(s->key_s2c, okm + 32u, 32u);
    s->tx_seq = 1u;
    s->rx_seq = 1u;

    /* Sealed H2-ACK for key confirmation. */
    uint8_t seal_nonce[12], sealed[8 + 12 + sizeof(ACK_PAYLOAD) + 16];
    qkp_make_nonce(seal_nonce, DIR_S2C, s->tx_seq);
    uint8_t head[6];
    /* Wire payload = nonce(12) ‖ "QKP1-ACK"(8, no NUL) ‖ tag(16) = 36. The
     * old code used sizeof(ACK_PAYLOAD) (9, counting the NUL) for the length
     * and never copied `head` into `sealed`, so the frame went out with a
     * 6-byte uninitialized prefix and a length one byte too long. */
    uint16_t plen = (uint16_t)(12u + (sizeof(ACK_PAYLOAD) - 1u) + 16u);
    memcpy(head, SEAL_MAGIC, 4u);
    head[4] = (uint8_t)(plen >> 8); head[5] = (uint8_t)plen;
    uint8_t* ack_ct = sealed + 6u + 12u;
    if (!qkp_aead_seal(s->key_s2c, seal_nonce, head, 6u, (const uint8_t*)ACK_PAYLOAD, sizeof(ACK_PAYLOAD) - 1u, ack_ct)) {
        free(s); qkp_send_err(fd, "internal"); return QIHSE_QKP_REJECTED;
    }
    memcpy(sealed, head, 6u);
    memcpy(sealed + 6u, seal_nonce, 12u);
    s->tx_seq++;
    if (!qkp_write_all(fd, sealed, 6u + plen)) { fprintf(stderr, "QKP-DBG: ACK send failed\n"); free(s); return QIHSE_QKP_REJECTED; }

    if (out) *out = s; else free(s);
    return QIHSE_QKP_SECURE;
}

/* ── client role (test harness / tools) ───────────────────────────────── */

qihse_qkp_result_t qihse_qkp_client_negotiate(int fd, const qihse_qkp_config_t* cfg,
                                              qihse_qkp_session_t** out) {
    if (out) *out = NULL;
    if (!cfg || !cfg->dsa_key_path || cfg->trusted_count == 0 || !cfg->trusted_pubs) {
        return QIHSE_QKP_REJECTED;
    }
    if (!qkp_write_all(fd, QKP_MAGIC, 4u)) return QIHSE_QKP_REJECTED;

    uint8_t h1[QIHSE_QKP_MAX_PAYLOAD];
    ssize_t h1_len = qkp_read_frame(fd, h1);
    if (h1_len < 0) return QIHSE_QKP_REJECTED;
    if ((size_t)h1_len < 2u + 64u + 32u + 2u + QIHSE_QKP_SIG_LEN) return QIHSE_QKP_REJECTED;
    const uint8_t* p = h1;
    uint16_t proto = (uint16_t)((p[0] << 8) | p[1]); p += 2u;
    const uint8_t* srv_id = p; p += 64u;
    const uint8_t* srv_nonce = p; p += 32u;
    uint16_t pem_len = (uint16_t)((p[0] << 8) | p[1]); p += 2u;
    if (proto != QIHSE_QKP_PROTO_VERSION || (size_t)pem_len > (size_t)h1_len ||
        (size_t)(p - h1) + pem_len + QIHSE_QKP_SIG_LEN != (size_t)h1_len) {
        return QIHSE_QKP_REJECTED;
    }
    const uint8_t* kem_pem = p;
    const uint8_t* sig = p + pem_len;

    /* Trust anchors: the server identity must verify against one of OUR
     * configured public keys. No TOFU. */
    size_t h1_body_len = (size_t)h1_len - QIHSE_QKP_SIG_LEN;
    size_t h1_signed_len = strlen(H1_DOMAIN) + h1_body_len;
    uint8_t* h1_signed = (uint8_t*)malloc(h1_signed_len);
    if (!h1_signed) return QIHSE_QKP_REJECTED;
    memcpy(h1_signed, H1_DOMAIN, strlen(H1_DOMAIN));
    memcpy(h1_signed + strlen(H1_DOMAIN), h1, h1_body_len);
    bool server_trusted = false;
    for (size_t i = 0; i < cfg->trusted_count && !server_trusted; i++) {
        server_trusted = qihse_pqc_verify_path(h1_signed, h1_signed_len, sig, cfg->trusted_pubs[i]);
    }
    /* Transcript hash must be taken BEFORE the signed region is released —
     * this used to free h1_signed above and then hash it (use-after-free),
     * which is why every H2 signature failed verification. */
    uint8_t h1_hash[QIHSE_QKP_TR_LEN];
    if (!qkp_sha384(h1_signed, h1_signed_len, h1_hash)) {
        free(h1_signed);
        return QIHSE_QKP_REJECTED;
    }
    free(h1_signed);
    if (!server_trusted) return QIHSE_QKP_REJECTED;

    uint8_t cli_nonce[QIHSE_QKP_NONCE_LEN];
    if (RAND_bytes(cli_nonce, sizeof(cli_nonce)) != 1) return QIHSE_QKP_REJECTED;
    uint8_t ct[QIHSE_QKP_CT_LEN];
    qihse_pqc_ctx_t kem;
    memset(&kem, 0, sizeof(kem));
    if (!qihse_pqc_encapsulate_mem(&kem, kem_pem, pem_len, ct)) return QIHSE_QKP_REJECTED;

    /* H2 signed region mirrors the server's derivation. */
    size_t id_len = cfg->node_id ? strlen(cfg->node_id) : 0u;
    if (id_len > 64u) id_len = 64u;
    size_t h2_signed_len = strlen(H2_DOMAIN) + QIHSE_QKP_TR_LEN + 64u + 32u + QIHSE_QKP_CT_LEN;
    uint8_t* h2_signed = (uint8_t*)malloc(h2_signed_len);
    if (!h2_signed) return QIHSE_QKP_REJECTED;
    {
        uint8_t* w = h2_signed;
        memcpy(w, H2_DOMAIN, strlen(H2_DOMAIN)); w += strlen(H2_DOMAIN);
        memcpy(w, h1_hash, QIHSE_QKP_TR_LEN); w += QIHSE_QKP_TR_LEN;
        memset(w, 0, 64u); memcpy(w, cfg->node_id ? cfg->node_id : "", id_len); w += 64u;
        memcpy(w, cli_nonce, 32u); w += 32u;
        memcpy(w, ct, QIHSE_QKP_CT_LEN);
    }
    uint8_t h2_sig[QIHSE_QKP_SIG_LEN];
    {
        uint8_t dbg[48];
        unsigned int ol = 0;
        EVP_Digest(h2_signed, h2_signed_len, dbg, &ol, EVP_sha384(), NULL);
        fprintf(stderr, "QKP-DBG2 cli h1_hash=%02x%02x h2sig_hash=%02x%02x len=%zu\n",
                h1_hash[0], h1_hash[1], dbg[0], dbg[1], h2_signed_len);
    }
    bool signed_ok = qihse_pqc_sign_path(h2_signed, h2_signed_len, h2_sig, cfg->dsa_key_path);
    free(h2_signed);
    if (!signed_ok) return QIHSE_QKP_REJECTED;

    size_t h2_len = 64u + 32u + QIHSE_QKP_CT_LEN + QIHSE_QKP_SIG_LEN;
    uint8_t* h2 = (uint8_t*)malloc(h2_len);
    if (!h2) return QIHSE_QKP_REJECTED;
    {
        uint8_t* w = h2;
        memset(w, 0, 64u); memcpy(w, cfg->node_id ? cfg->node_id : "", id_len); w += 64u;
        memcpy(w, cli_nonce, 32u); w += 32u;
        memcpy(w, ct, QIHSE_QKP_CT_LEN); w += QIHSE_QKP_CT_LEN;
        memcpy(w, h2_sig, QIHSE_QKP_SIG_LEN);
    }
    bool sent = qkp_send_frame(fd, 2u, h2, (uint16_t)h2_len);
    free(h2);
    if (!sent) return QIHSE_QKP_REJECTED;

    /* Sealed H2-ACK from the server: the key-confirmation gate. */
    uint8_t ss[QIHSE_MLKEM_SHARED_SIZE];
    memcpy(ss, kem.aes_key, sizeof(ss));
    qihse_pqc_destroy(&kem);
    uint8_t salt[QIHSE_QKP_TR_LEN], ikm[96], okm[64];
    /* salt = SHA384(H1 signed region) — already computed as h1_hash before
     * that buffer was released (mirrors the server's derivation exactly). */
    memcpy(salt, h1_hash, QIHSE_QKP_TR_LEN);
    memcpy(ikm, ss, 32u); memcpy(ikm + 32u, cli_nonce, 32u); memcpy(ikm + 64u, srv_nonce, 32u);
    if (!qkp_hkdf_sha384(salt, QIHSE_QKP_TR_LEN, ikm, sizeof(ikm),
                         (const uint8_t*)HKDF_INFO, strlen(HKDF_INFO), okm, sizeof(okm))) {
        return QIHSE_QKP_REJECTED;
    }
    qihse_qkp_session_t* s = (qihse_qkp_session_t*)calloc(1u, sizeof(*s));
    if (!s) return QIHSE_QKP_REJECTED;
    s->role = QKP_ROLE_CLIENT;
    memcpy(s->key_c2s, okm, 32u);
    memcpy(s->key_s2c, okm + 32u, 32u);
    s->tx_seq = 1u;
    s->rx_seq = 1u;

    uint8_t ack_head[6], ack_plain[32], ack_nonce[12];
    if (!qkp_read_exact(fd, ack_head, 6u) || memcmp(ack_head, SEAL_MAGIC, 4u) != 0) {
        free(s); return QIHSE_QKP_REJECTED;
    }
    uint16_t ack_len = (uint16_t)((ack_head[4] << 8) | ack_head[5]);
    if (ack_len != 12u + 8u + 16u) { free(s); return QIHSE_QKP_REJECTED; }
    uint8_t* ack_ct = malloc(ack_len);
    if (!ack_ct || !qkp_read_exact(fd, ack_ct, ack_len)) { free(ack_ct); free(s); return QIHSE_QKP_REJECTED; }
    qkp_make_nonce(ack_nonce, DIR_S2C, 1u);
    /* Frame body = nonce(12) ‖ ct ‖ tag — skip the nonce, exactly like
     * qihse_qkp_recv_sealed does; the whole body used to be passed as
     * ciphertext, so the tag never verified. */
    bool ack_ok = qkp_aead_open(s->key_s2c, ack_nonce, ack_head, 6u, ack_ct + 12u, ack_len - 12u, ack_plain) &&
                  memcmp(ack_plain, ACK_PAYLOAD, sizeof(ACK_PAYLOAD) - 1u) == 0;
    free(ack_ct);
    if (!ack_ok) { free(s); return QIHSE_QKP_REJECTED; }
    s->rx_seq = 2u;

    if (out) *out = s; else free(s);
    return QIHSE_QKP_SECURE;
}

/* ── sealed transport ─────────────────────────────────────────────────── */

bool qihse_qkp_send_sealed(qihse_qkp_session_t* s, int fd, const void* data, size_t len) {
    if (!s || !data || len > QIHSE_QKP_MAX_PAYLOAD) return false;
    uint8_t nonce[12];
    uint32_t dir = (s->role == QKP_ROLE_SERVER) ? DIR_S2C : DIR_C2S;
    qkp_make_nonce(nonce, dir, s->tx_seq);
    uint8_t head[6];
    uint16_t flen = (uint16_t)(12u + len + 16u);
    memcpy(head, SEAL_MAGIC, 4u);
    head[4] = (uint8_t)(flen >> 8); head[5] = (uint8_t)flen;
    uint8_t* frame = (uint8_t*)malloc(6u + flen);
    if (!frame) return false;
    memcpy(frame, head, 6u);
    memcpy(frame + 6u, nonce, 12u);
    bool ok = qkp_aead_seal(s->key_c2s, nonce, head, 6u, data, len, frame + 6u + 12u);
    if (ok) ok = qkp_write_all(fd, frame, 6u + flen);
    free(frame);
    if (ok) s->tx_seq++;
    return ok;
}

ssize_t qihse_qkp_recv_sealed(qihse_qkp_session_t* s, int fd,
                              uint8_t* out, size_t cap) {
    if (!s) return -1;
    uint8_t head[6];
    if (!qkp_read_exact(fd, head, 6u)) return -1;
    if (memcmp(head, SEAL_MAGIC, 4u) != 0) return -2;
    uint16_t flen = (uint16_t)((head[4] << 8) | head[5]);
    if (flen < 12u + 16u || flen > QIHSE_QKP_MAX_FRAME) return -2;
    uint32_t dir = (s->role == QKP_ROLE_SERVER) ? DIR_C2S : DIR_S2C;
    uint64_t expected = s->rx_seq;
    uint8_t* frame = (uint8_t*)malloc(flen);
    if (!frame) return -1;
    if (!qkp_read_exact(fd, frame, flen)) { free(frame); return -1; }
    uint8_t nonce[12];
    qkp_make_nonce(nonce, dir, expected);
    size_t plen = flen - 12u - 16u;
    if (plen > cap) { free(frame); return -2; }
    bool ok = qkp_aead_open(s->key_c2s, nonce, head, 6u, frame + 12u, flen - 12u, out);
    free(frame);
    if (!ok) return -2; /* tag failure: forged, tampered, or replayed seq */
    /* Sequence check happens on the caller-visible nonce: expected seq was
     * baked into the nonce; a replayed frame carries an OLD seq, which fails
     * the tag against the expected nonce. Reaching here means seq matched. */
    s->rx_seq = expected + 1u;
    return (ssize_t)plen;
}

void qihse_qkp_session_free(qihse_qkp_session_t* s) {
    if (!s) return;
    memset(s->key_c2s, 0, sizeof(s->key_c2s));
    memset(s->key_s2c, 0, sizeof(s->key_s2c));
    free(s);
}
