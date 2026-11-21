#include "qihse_ct1_authority_protocol.h"
#ifdef QIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL

#include <string.h>

#define CHALLENGE 1u
#define RESPONSE 2u

static void header(unsigned char *out, unsigned type, size_t length) {
    memcpy(out, "CT1A", 4);
    out[4] = QIHSE_CT1_AUTHORITY_VERSION;
    out[5] = (unsigned char)type;
    out[6] = out[7] = 0;
    out[8] = (unsigned char)(length >> 24);
    out[9] = (unsigned char)(length >> 16);
    out[10] = (unsigned char)(length >> 8);
    out[11] = (unsigned char)length;
}

static bool header_ok(const unsigned char *data, size_t length, unsigned type,
    size_t expected) {
    return data && length == expected && !memcmp(data, "CT1A", 4) &&
        data[4] == QIHSE_CT1_AUTHORITY_VERSION && data[5] == type &&
        data[6] == 0 && data[7] == 0 &&
        data[8] == (unsigned char)(expected >> 24) &&
        data[9] == (unsigned char)(expected >> 16) &&
        data[10] == (unsigned char)(expected >> 8) &&
        data[11] == (unsigned char)expected;
}

static bool statement_expected(const qihse_ct1_recovery_manifest_t *manifest,
    bool source, qihse_ct1_authority_statement_t *out) {
    const char *node = source ? manifest->source_peer_qkp_id : manifest->target_peer_qkp_id;
    const unsigned char *pin = source ? manifest->source_peer_pin : manifest->target_peer_pin;
    size_t node_len = strnlen(node, QIHSE_CT1_RECOVERY_ID_MAX + 1u);
    size_t principal_len = strnlen(manifest->replication_principal_id,
        QIHSE_CT1_RECOVERY_ID_MAX + 1u);
    if (!node_len || node_len > QIHSE_CT1_RECOVERY_ID_MAX ||
        !principal_len || principal_len > QIHSE_CT1_RECOVERY_ID_MAX) return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->qkp_id, node, node_len);
    memcpy(out->service_principal_id, manifest->replication_principal_id, principal_len);
    memcpy(out->current_pin, pin, sizeof(out->current_pin));
    return true;
}

static void statement_wire(unsigned char *out,
    const qihse_ct1_authority_statement_t *s) {
    memcpy(out, s->qkp_id, 65);
    memcpy(out + 65, s->service_principal_id, 65);
    memcpy(out + 130, s->current_pin, 32);
}

static bool statement_valid(const unsigned char *wire,
    const qihse_ct1_recovery_manifest_t *m, bool source,
    qihse_ct1_authority_statement_t *out) {
    qihse_ct1_authority_statement_t expected;
    unsigned char canonical[QIHSE_CT1_AUTHORITY_STATEMENT_SIZE];
    if (!statement_expected(m, source, &expected)) return false;
    statement_wire(canonical, &expected);
    if (memcmp(wire, canonical, sizeof(canonical))) return false;
    if (out) *out = expected;
    return true;
}

bool qihse_ct1_authority_challenge_encode(const qihse_ct1_recovery_manifest_t *m,
    unsigned char out[QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE]) {
    if (!out || !qihse_ct1_recovery_encode(m, false, false,
        out + QIHSE_CT1_AUTHORITY_HEADER_SIZE)) return false;
    header(out, CHALLENGE, QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE);
    return true;
}

bool qihse_ct1_authority_challenge_decode(const unsigned char *data, size_t length,
    qihse_ct1_recovery_manifest_t *m) {
    if (!m) return false;
    memset(m, 0, sizeof(*m));
    return header_ok(data, length, CHALLENGE, QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE) &&
        qihse_ct1_recovery_decode(data + QIHSE_CT1_AUTHORITY_HEADER_SIZE,
            QIHSE_CT1_RECOVERY_WIRE_SIZE, false, m, NULL);
}

bool qihse_ct1_authority_response_encode(const qihse_ct1_recovery_manifest_t *m,
    const qihse_ct1_authority_statement_t *source,
    const qihse_ct1_authority_statement_t *target,
    unsigned char out[QIHSE_CT1_AUTHORITY_RESPONSE_SIZE]) {
    if (!out || !source || !target || !qihse_ct1_recovery_encode(m, false, false,
        out + QIHSE_CT1_AUTHORITY_HEADER_SIZE)) return false;
    unsigned char wire[QIHSE_CT1_AUTHORITY_STATEMENT_SIZE];
    statement_wire(wire, source);
    if (!statement_valid(wire, m, true, NULL)) return false;
    memcpy(out + QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE, wire, sizeof(wire));
    statement_wire(wire, target);
    if (!statement_valid(wire, m, false, NULL)) return false;
    memcpy(out + QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE + sizeof(wire), wire, sizeof(wire));
    header(out, RESPONSE, QIHSE_CT1_AUTHORITY_RESPONSE_SIZE);
    return true;
}

bool qihse_ct1_authority_response_decode(const unsigned char *data, size_t length,
    qihse_ct1_recovery_manifest_t *m, qihse_ct1_authority_statement_t *source,
    qihse_ct1_authority_statement_t *target) {
    if (!m || !source || !target) return false;
    memset(m, 0, sizeof(*m));
    memset(source, 0, sizeof(*source));
    memset(target, 0, sizeof(*target));
    if (!header_ok(data, length, RESPONSE, QIHSE_CT1_AUTHORITY_RESPONSE_SIZE) ||
        !qihse_ct1_recovery_decode(data + QIHSE_CT1_AUTHORITY_HEADER_SIZE,
            QIHSE_CT1_RECOVERY_WIRE_SIZE, false, m, NULL) ||
        !statement_valid(data + QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE, m, true, source) ||
        !statement_valid(data + QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE +
            QIHSE_CT1_AUTHORITY_STATEMENT_SIZE, m, false, target)) {
        memset(m, 0, sizeof(*m));
        memset(source, 0, sizeof(*source));
        memset(target, 0, sizeof(*target));
        return false;
    }
    return true;
}

bool qihse_ct1_authority_response_matches(const unsigned char *challenge,
    size_t challenge_length, const unsigned char *response, size_t response_length) {
    qihse_ct1_recovery_manifest_t m, actual;
    qihse_ct1_authority_statement_t source, target;
    return qihse_ct1_authority_challenge_decode(challenge, challenge_length, &m) &&
        qihse_ct1_authority_response_decode(response, response_length,
            &actual, &source, &target) &&
        !memcmp(challenge + QIHSE_CT1_AUTHORITY_HEADER_SIZE,
            response + QIHSE_CT1_AUTHORITY_HEADER_SIZE, QIHSE_CT1_RECOVERY_WIRE_SIZE);
}

bool qihse_ct1_authority_approve(const qihse_qkp_session_t *issuer_session,
    const qihse_qkp_config_t *config, const unsigned char *challenge,
    size_t challenge_length, const unsigned char *response, size_t response_length) {
    (void)issuer_session;
    (void)config;
    (void)challenge;
    (void)challenge_length;
    (void)response;
    (void)response_length;
    return false;
}
#endif /* QIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL */
