/* QIHSE federation — stage F0 primitives.
 *
 * Identity, hybrid logical time, object generations, and fencing epochs.
 * No behaviour changes to the existing cluster: these are the vocabulary the
 * federation stages (F1+) are built from.
 * See docs/plans/qihse_federation_upgrade_plan.md §7. */
#include "qihse_federation.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <time.h>

/* ── UUID ───────────────────────────────────────────────────────────────── */

bool qihse_uuid_generate(qihse_uuid_t* out) {
    if (!out) return false;
    if (RAND_bytes(out->bytes, (int)QIHSE_UUID_BYTES) != 1) return false;
    out->bytes[6] = (uint8_t)((out->bytes[6] & 0x0Fu) | 0x40u); /* version 4 */
    out->bytes[8] = (uint8_t)((out->bytes[8] & 0x3Fu) | 0x80u); /* RFC 4122 variant */
    return true;
}

bool qihse_uuid_from_seed(const void* seed, size_t seed_len, qihse_uuid_t* out) {
    if (!out || (!seed && seed_len > 0)) return false;
    uint8_t digest[48]; /* SHA-384 */
    unsigned int digest_len = 0;
    if (EVP_Digest(seed, seed_len, digest, &digest_len, EVP_sha384(), NULL) != 1 ||
        digest_len < QIHSE_UUID_BYTES) {
        return false;
    }
    memcpy(out->bytes, digest, QIHSE_UUID_BYTES);
    out->bytes[6] = (uint8_t)((out->bytes[6] & 0x0Fu) | 0x50u); /* version 5 (name-based) */
    out->bytes[8] = (uint8_t)((out->bytes[8] & 0x3Fu) | 0x80u);
    return true;
}

static int uuid_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool qihse_uuid_parse(const char* text, qihse_uuid_t* out) {
    if (!text || !out) return false;
    size_t o = 0;
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++) {
        if (text[o] == '-') o++;
        int hi = uuid_hex_val(text[o]);
        int lo = uuid_hex_val(text[o + 1u]);
        if (hi < 0 || lo < 0) return false;
        out->bytes[i] = (uint8_t)((hi << 4) | lo);
        o += 2u;
    }
    return text[o] == '\0';
}

bool qihse_uuid_format(const qihse_uuid_t* id, char out[QIHSE_UUID_STR_LEN + 1u]) {
    if (!id || !out) return false;
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++) {
        if (i == 4u || i == 6u || i == 8u || i == 10u) out[o++] = '-';
        out[o++] = hex[(id->bytes[i] >> 4) & 0x0Fu];
        out[o++] = hex[id->bytes[i] & 0x0Fu];
    }
    out[o] = '\0';
    return o == QIHSE_UUID_STR_LEN;
}

bool qihse_uuid_is_nil(const qihse_uuid_t* id) {
    if (!id) return true;
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++)
        if (id->bytes[i] != 0) return false;
    return true;
}

bool qihse_uuid_equal(const qihse_uuid_t* a, const qihse_uuid_t* b) {
    if (!a || !b) return false;
    return memcmp(a->bytes, b->bytes, QIHSE_UUID_BYTES) == 0;
}

/* ── Hybrid logical clock ───────────────────────────────────────────────── */

static uint64_t fed_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void qihse_hlc_init(qihse_hlc_t* clock) {
    if (!clock) return;
    clock->physical_ms = 0;
    clock->logical = 0;
}

void qihse_hlc_tick(qihse_hlc_t* clock, qihse_hlc_t* out) {
    if (!clock || !out) return;
    uint64_t now = fed_now_ms();
    if (now > clock->physical_ms) {
        clock->physical_ms = now;
        clock->logical = 0;
    } else {
        /* Clock did not advance (or went backwards): keep ordering with the
         * logical counter. */
        clock->logical++;
    }
    *out = *clock;
}

void qihse_hlc_observe(qihse_hlc_t* clock, const qihse_hlc_t* remote) {
    if (!clock || !remote) return;
    uint64_t now = fed_now_ms();
    uint64_t physical = clock->physical_ms;
    if (now > physical) physical = now;
    if (remote->physical_ms > physical) physical = remote->physical_ms;

    uint32_t logical = 0;
    if (physical == clock->physical_ms && physical == remote->physical_ms) {
        logical = (clock->logical > remote->logical ? clock->logical : remote->logical) + 1u;
    } else if (physical == clock->physical_ms) {
        logical = clock->logical + 1u;
    } else if (physical == remote->physical_ms) {
        logical = remote->logical + 1u;
    }
    clock->physical_ms = physical;
    clock->logical = logical;
}

int qihse_hlc_compare(const qihse_hlc_t* a, const qihse_hlc_t* b) {
    if (!a || !b) return 0;
    if (a->physical_ms < b->physical_ms) return -1;
    if (a->physical_ms > b->physical_ms) return 1;
    if (a->logical < b->logical) return -1;
    if (a->logical > b->logical) return 1;
    return 0;
}

uint64_t qihse_hlc_pack(const qihse_hlc_t* clock) {
    if (!clock) return 0;
    return (clock->physical_ms << 16) | (uint64_t)(clock->logical & 0xFFFFu);
}

void qihse_hlc_unpack(uint64_t packed, qihse_hlc_t* out) {
    if (!out) return;
    out->physical_ms = packed >> 16;
    out->logical = (uint32_t)(packed & 0xFFFFu);
}

/* ── Object generation ──────────────────────────────────────────────────── */

void qihse_object_version_init(qihse_object_version_t* version, const qihse_uuid_t* object) {
    if (!version) return;
    memset(version, 0, sizeof(*version));
    if (object) version->object = *object;
    version->generation = 1u;
}

void qihse_object_version_bump(qihse_object_version_t* version, qihse_hlc_t* clock) {
    if (!version || !clock) return;
    version->generation++;
    qihse_hlc_t stamp;
    qihse_hlc_tick(clock, &stamp);
    version->stamp = stamp;
}

int qihse_object_version_compare(const qihse_object_version_t* a,
                                 const qihse_object_version_t* b) {
    if (!a || !b) return 0;
    if (a->generation < b->generation) return -1;
    if (a->generation > b->generation) return 1;
    return qihse_hlc_compare(&a->stamp, &b->stamp);
}

/* ── Fencing epoch ──────────────────────────────────────────────────────── */

void qihse_fencing_token_init(qihse_fencing_token_t* token) {
    if (!token) return;
    memset(token, 0, sizeof(*token));
}

bool qihse_fencing_acquire(qihse_fencing_token_t* token, uint64_t observed_epoch,
                           const qihse_uuid_t* holder) {
    if (!token || !holder) return false;
    /* Fail closed: the caller must have observed the epoch it is replacing,
     * and the new epoch is always strictly higher. */
    if (observed_epoch != token->epoch) return false;
    token->epoch = observed_epoch + 1u;
    token->holder = *holder;
    return true;
}

bool qihse_fencing_valid(const qihse_fencing_token_t* token, uint64_t observed_epoch) {
    if (!token) return false;
    return token->epoch > observed_epoch;
}
