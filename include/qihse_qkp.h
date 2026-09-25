#ifndef QIHSE_QKP_H
#define QIHSE_QKP_H

/* ══════════════════════════════════════════════════════════════════════════
 * QIHSE QKP1 — CNSA 2.0 post-quantum key-establishment handshake for the
 * RESP wire (predesign §17 signed/replay-resistant RPC, §18 key-based
 * identity, §35 trust flavor).
 *
 * ALGORITHMS (CNSA 2.0 flavor): ML-KEM-1024 key establishment, ML-DSA-87
 * authentication, SHA-384 transcript/HKDF, ChaCha20-Poly1305 session AEAD.
 * No classical fallback: a connection that starts QKP1 either completes the
 * handshake or is closed.
 *
 * WIRE LAYOUT (all multi-byte integers big-endian; all lengths are byte
 * counts; every frame is length-bounded and versioned):
 *
 *   Connection probe (client → server, exactly 4 bytes): "QKP1"
 *     The first byte(s) of a NEW connection decide the mode:
 *       - starts with "QKP1" → QKP handshake (frames below)
 *       - anything else      → cleartext RESP; refused outright when the
 *                              server runs --pqc-require
 *     The server peeks the first byte (MSG_PEEK), so the probe is never
 *     consumed twice.
 *
 *   Handshake frames: "QKP1" | type u8 | reserved u8 (=0) | len u16 | payload
 *     type 1 = H1 (server → client), type 2 = H2 (client → server),
 *     type 3 = H2-ACK (server → client, sealed, payload "QKP1-ACK").
 *     len ≤ 16384 for H1/H2 payloads as generated here (bounded by the
 *     reader; oversize ⇒ reject + close).
 *
 *   H1 payload:
 *     protocol_version u16   (=1)
 *     server_node_id  [64]   (NUL-padded label; NOT the trust anchor — the
 *                            ML-DSA signature is, per predesign §18)
 *     server_nonce    [32]   (random)
 *     kem_pub_len     u16
 *     kem_pub         [kem_pub_len]   (server ML-KEM-1024 public key, PEM)
 *     sig             [QIHSE_MLDSA_SIGNATURE_SIZE]
 *     sig covers "QKP1-H1" ‖ protocol_version ‖ server_node_id ‖
 *                server_nonce ‖ kem_pub
 *
 *   H2 payload:
 *     client_node_id  [64]
 *     client_nonce    [32]   (random)
 *     kem_ct          [QIHSE_MLKEM_CIPHERTEXT_SIZE]   (encapsulated vs H1 pub)
 *     sig             [QIHSE_MLDSA_SIGNATURE_SIZE]
 *     sig covers "QKP1-H2" ‖ SHA384(H1 signed region ‖ kem_pub_len ‖ kem_pub)
 *                             ‖ client_node_id ‖ client_nonce ‖ kem_ct
 *
 *   Both sides derive (HKDF-SHA384):
 *     salt = SHA384(entire H1 signed region ‖ H2 signed region)
 *     IKM  = ML-KEM shared secret(32) ‖ client_nonce(32) ‖ server_nonce(32)
 *     info = "QIHSE-QKP1-v1"
 *     OKM  = 64 bytes: [0..31] client→server key, [32..63] server→client key
 *
 *   Sealed frames (after H2-ACK): "QSE1" | len u16 | nonce[12] | ct[len]
 *     nonce = direction tag u32 (1 = client→server, 2 = server→client)
 *             ‖ seq u64 BE (starts at 1, monotonic)
 *     ct    = ChaCha20-Poly1305(key, nonce, AAD = "QSE1"‖len, plaintext)
 *     Receiver tracks the expected seq per direction; any mismatch, tag
 *     failure, or unknown magic ⇒ connection closed (replay/forge guard).
 *     The peer's first sealed frame MUST be the H2-ACK echo ("QKP1-ACK")
 *     for key confirmation before any application traffic.
 *
 * TRUST: H1 is verified by the client against --pqc-trusted-pub anchors and
 * H2 by the server against the same class of anchors. There is no
 * trust-on-first-use and no hostname/IP-derived identity (predesign §17/§18).
 * AUTH still applies inside the secure channel: QKP proves node identity,
 * AUTH proves the operator principal.
 * ══════════════════════════════════════════════════════════════════════════ */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_QKP_PROTO_VERSION   1u
#define QIHSE_QKP_NODE_ID_LEN     64u
#define QIHSE_QKP_NONCE_LEN       32u
#define QIHSE_QKP_NONCE_WIRE_LEN  12u
#define QIHSE_QKP_KEY_LEN         32u
#define QIHSE_QKP_MAX_PAYLOAD     16384u
#define QIHSE_QKP_MAX_FRAME       (8u + QIHSE_QKP_MAX_PAYLOAD)

typedef struct qihse_qkp_session qihse_qkp_session_t;

typedef struct {
    const char* dsa_key_path;             /* own ML-DSA-87 private key (sign) */
    const char* kem_key_path;             /* own ML-KEM-1024 private key (server decapsulate) */
    const char* kem_pub_path;             /* own ML-KEM-1024 public key PEM (server H1) */
    const char* const* trusted_pubs;      /* ML-DSA-87 public PEM paths (trust anchors) */
    size_t trusted_count;
    const char* node_id;                  /* ≤ 64 bytes label */
    bool require;                         /* refuse cleartext connections */
} qihse_qkp_config_t;

typedef enum {
    QIHSE_QKP_SECURE = 0,       /* handshake complete, session sealed */
    QIHSE_QKP_CLEARTEXT = 1,    /* client skipped QKP; allowed (opportunistic mode) */
    QIHSE_QKP_REJECTED = 2      /* handshake failed / refused: fd is dead */
} qihse_qkp_result_t;

/* Server side (accept path). Exactly one of SECURE/CLEARTEXT/REJECTED. */
qihse_qkp_result_t qihse_qkp_server_negotiate(int fd, const qihse_qkp_config_t* cfg,
                                              qihse_qkp_session_t** out_session);

/* Client side (test harness / tools). Always initiates QKP1. */
qihse_qkp_result_t qihse_qkp_client_negotiate(int fd, const qihse_qkp_config_t* cfg,
                                              qihse_qkp_session_t** out_session);

/* Seal `len` bytes and push the frame; true = fully sent. Direction follows
 * the session role. */
bool qihse_qkp_send_sealed(qihse_qkp_session_t* s, int fd, const void* data, size_t len);

/* Read one sealed frame from `fd`, open it, copy plaintext into out (cap).
 * Returns plaintext length, -1 on transport error, -2 on crypto/replay
 * failure (caller closes either way). */
ssize_t qihse_qkp_recv_sealed(qihse_qkp_session_t* s, int fd,
                              uint8_t* out, size_t cap);

void qihse_qkp_session_free(qihse_qkp_session_t* s);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_QKP_H */
