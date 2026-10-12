#include "qihse_consensus_prefix_pair_nonce_internal.h"

#include <fcntl.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NONCE_RECORD_MAX 1024u
#define NONCE_RECORD_LIFETIME_SECONDS 300u
#define ACCEPTED_RECORD_MAX (NONCE_RECORD_MAX + 32u + \
    2u * (8u + 1u + QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES + \
          2u + QIHSE_FEDERATION_SIG_MAX_BYTES + \
          2u + QIHSE_FEDERATION_SIG_MAX_BYTES))

static bool nonzero(const uint8_t* bytes, size_t count) {
    uint8_t bits = 0u;
    for (size_t i = 0u; i < count; ++i) bits |= bytes[i];
    return bits != 0u;
}

static bool equal_text(const char* first, const char* second,
                       size_t capacity) {
    size_t first_length = strnlen(first, capacity);
    size_t second_length = strnlen(second, capacity);
    return first_length > 0u && first_length < capacity &&
           first_length == second_length &&
           memcmp(first, second, first_length) == 0;
}

static void put_u64(uint8_t out[8], uint64_t value) {
    for (size_t i = 0u; i < 8u; ++i)
        out[i] = (uint8_t)(value >> (56u - 8u * i));
}

static uint64_t get_u64(const uint8_t in[8]) {
    uint64_t value = 0u;
    for (size_t i = 0u; i < 8u; ++i) value = (value << 8u) | in[i];
    return value;
}

static bool append(uint8_t out[NONCE_RECORD_MAX], size_t* length,
                   const void* bytes, size_t count) {
    if (count > NONCE_RECORD_MAX - *length) return false;
    memcpy(out + *length, bytes, count);
    *length += count;
    return true;
}

static bool append_text(uint8_t out[NONCE_RECORD_MAX], size_t* length,
                        const char* value, size_t capacity) {
    size_t count = strnlen(value, capacity);
    if (count == 0u || count >= capacity || count > UINT8_MAX) return false;
    uint8_t encoded_count = (uint8_t)count;
    return append(out, length, &encoded_count, 1u) &&
           append(out, length, value, count);
}

static bool append_peer(uint8_t out[NONCE_RECORD_MAX], size_t* length,
                        const qihse_consensus_prefix_expected_t* peer) {
    uint8_t epoch[8];
    put_u64(epoch, peer->writer_epoch_floor);
    return peer->writer_epoch_floor != 0u &&
           nonzero(peer->history_id, sizeof(peer->history_id)) &&
           !qihse_uuid_is_nil(&peer->member_uuid) &&
           !qihse_uuid_is_nil(&peer->signer_node) &&
           append_text(out, length, peer->group_id,
                       sizeof(peer->group_id)) &&
           append(out, length, peer->history_id,
                  sizeof(peer->history_id)) &&
           append(out, length, epoch, sizeof(epoch)) &&
           append(out, length, peer->member_uuid.bytes,
                  sizeof(peer->member_uuid.bytes)) &&
           append_text(out, length, peer->qkp_node_id,
                       sizeof(peer->qkp_node_id)) &&
           append(out, length, peer->signer_node.bytes,
                  sizeof(peer->signer_node.bytes));
}

/* Canonical, padding-free protected record. A pending record binds both
 * challenges to the expected identity, exact point, digest and issue time. */
static bool record(const qihse_consensus_prefix_pair_expected_t* expected,
                   uint64_t issued_at, uint8_t out[NONCE_RECORD_MAX],
                   size_t* out_length) {
    static const uint8_t magic[4] = {'Q', 'P', 'P', '1'};
    uint8_t time_bytes[8], index_bytes[8];
    if (!expected || !out || !out_length || issued_at == 0u ||
        expected->index > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        !nonzero(expected->trusted_recovery_anchor_sha256, 32u) ||
        !equal_text(expected->first.group_id, expected->second.group_id,
                    sizeof(expected->first.group_id)) ||
        memcmp(expected->first.history_id, expected->second.history_id,
               sizeof(expected->first.history_id)) != 0 ||
        expected->first.writer_epoch_floor !=
            expected->second.writer_epoch_floor ||
        qihse_uuid_equal(&expected->first.member_uuid,
                         &expected->second.member_uuid) ||
        qihse_uuid_equal(&expected->first.signer_node,
                         &expected->second.signer_node) ||
        equal_text(expected->first.qkp_node_id,
                   expected->second.qkp_node_id,
                   sizeof(expected->first.qkp_node_id)) ||
        (expected->index == 0u &&
         nonzero(expected->committed_prefix_sha256, 32u)) ||
        (expected->index != 0u &&
         !nonzero(expected->committed_prefix_sha256, 32u)) ||
        !nonzero(expected->first_challenge,
                 sizeof(expected->first_challenge)) ||
        !nonzero(expected->second_challenge,
                 sizeof(expected->second_challenge)) ||
        memcmp(expected->first_challenge, expected->second_challenge,
               sizeof(expected->first_challenge)) == 0) return false;
    put_u64(time_bytes, issued_at);
    put_u64(index_bytes, expected->index);
    size_t length = 0u;
    if (!append(out, &length, magic, sizeof(magic)) ||
        !append(out, &length, time_bytes, sizeof(time_bytes)) ||
        !append_peer(out, &length, &expected->first) ||
        !append_peer(out, &length, &expected->second) ||
        !append(out, &length, index_bytes, sizeof(index_bytes)) ||
        !append(out, &length, expected->committed_prefix_sha256, 32u) ||
        !append(out, &length,
                expected->trusted_recovery_anchor_sha256, 32u) ||
        !append(out, &length, expected->first_challenge,
                sizeof(expected->first_challenge)) ||
        !append(out, &length, expected->second_challenge,
                sizeof(expected->second_challenge))) return false;
    *out_length = length;
    return true;
}

static int open_protected_directory(const char* path) {
    if (!path || !*path) return -1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777u) != 0700u) {
        close(fd);
        return -1;
    }
    return fd;
}

static void record_name(const qihse_consensus_prefix_pair_expected_t* expected,
                        char prefix, char out[131]) {
    static const char hex[] = "0123456789abcdef";
    out[0] = prefix;
    out[1] = '-';
    const uint8_t* challenges[2] = {
        expected->first_challenge, expected->second_challenge
    };
    for (size_t part = 0u; part < 2u; ++part) {
        for (size_t i = 0u; i < QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES; ++i) {
            size_t at = 2u + part * 64u + i * 2u;
            out[at] = hex[challenges[part][i] >> 4u];
            out[at + 1u] = hex[challenges[part][i] & 15u];
        }
    }
    out[130] = '\0';
}

static bool write_all(int fd, const uint8_t* data, size_t length) {
    size_t offset = 0u;
    while (offset < length) {
        ssize_t wrote = write(fd, data + offset, length - offset);
        if (wrote <= 0) return false;
        offset += (size_t)wrote;
    }
    return true;
}

static bool append_accepted(uint8_t* out, size_t capacity, size_t* length,
                            const void* bytes, size_t count) {
    if (count > capacity - *length) return false;
    memcpy(out + *length, bytes, count);
    *length += count;
    return true;
}

static bool append_accepted_peer(
    uint8_t* out, size_t capacity, size_t* length,
    const qihse_consensus_prefix_point_challenge_t* response) {
    uint8_t observed[8], inner_len[2], outer_len[2];
    if (response->prefix.signature_len == 0u ||
        response->prefix.signature_len > QIHSE_FEDERATION_SIG_MAX_BYTES ||
        response->signature_len == 0u ||
        response->signature_len > QIHSE_FEDERATION_SIG_MAX_BYTES) return false;
    put_u64(observed, response->observed_commit_index);
    inner_len[0] = (uint8_t)(response->prefix.signature_len >> 8u);
    inner_len[1] = (uint8_t)response->prefix.signature_len;
    outer_len[0] = (uint8_t)(response->signature_len >> 8u);
    outer_len[1] = (uint8_t)response->signature_len;
    uint8_t algorithm = (uint8_t)response->prefix.sig_alg;
    return append_accepted(out, capacity, length, observed,
                           sizeof(observed)) &&
        append_accepted(out, capacity, length, &algorithm, 1u) &&
        append_accepted(out, capacity, length,
                        response->prefix.signer_fingerprint,
                        sizeof(response->prefix.signer_fingerprint)) &&
        append_accepted(out, capacity, length, inner_len,
                        sizeof(inner_len)) &&
        append_accepted(out, capacity, length,
                        response->prefix.signature,
                        response->prefix.signature_len) &&
        append_accepted(out, capacity, length, outer_len,
                        sizeof(outer_len)) &&
        append_accepted(out, capacity, length, response->signature,
                        response->signature_len);
}

bool qihse_consensus_prefix_pair_nonce_issue(
    const char* directory,
    const qihse_consensus_prefix_pair_expected_t* template_expected,
    qihse_consensus_prefix_pair_expected_t* issued) {
    if (!template_expected || !issued || template_expected == issued ||
        nonzero(template_expected->first_challenge,
                sizeof(template_expected->first_challenge)) ||
        nonzero(template_expected->second_challenge,
                sizeof(template_expected->second_challenge))) return false;
    memset(issued, 0, sizeof(*issued));
    int dir = open_protected_directory(directory);
    if (dir < 0) return false;
    *issued = *template_expected;
    time_t now = time(NULL);
    uint8_t bytes[NONCE_RECORD_MAX];
    size_t length = 0u;
    bool ok = now > 0 &&
        RAND_bytes(issued->first_challenge,
                   (int)sizeof(issued->first_challenge)) == 1 &&
        RAND_bytes(issued->second_challenge,
                   (int)sizeof(issued->second_challenge)) == 1 &&
        record(issued, (uint64_t)now, bytes, &length);
    char name[131];
    if (ok) {
        record_name(issued, 'p', name);
        int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL |
                                  O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) ok = false;
        else {
            ok = fchmod(fd, 0600) == 0 && write_all(fd, bytes, length) &&
                 fsync(fd) == 0;
            if (close(fd) != 0) ok = false;
            if (ok) ok = fsync(dir) == 0;
            if (!ok) {
                unlinkat(dir, name, 0);
                (void)fsync(dir);
            }
        }
    }
    close(dir);
    if (!ok) memset(issued, 0, sizeof(*issued));
    return ok;
}

bool qihse_consensus_prefix_pair_nonce_claim(
    const char* directory,
    const qihse_consensus_prefix_pair_expected_t* expected) {
    if (!expected) return false;
    int dir = open_protected_directory(directory);
    if (dir < 0) return false;
    char pending[131], claimed[131];
    record_name(expected, 'p', pending);
    record_name(expected, 'c', claimed);
    int fd = openat(dir, pending, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { close(dir); return false; }
    struct stat st;
    uint8_t saved[NONCE_RECORD_MAX], expected_bytes[NONCE_RECORD_MAX];
    ssize_t got = read(fd, saved, sizeof(saved));
    uint8_t extra;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && (st.st_mode & 0777u) == 0600u &&
        st.st_nlink == 1 && got >= 12 && got < (ssize_t)sizeof(saved) &&
        read(fd, &extra, 1u) == 0 &&
        memcmp(saved, "QPP1", 4u) == 0;
    if (close(fd) != 0) ok = false;
    time_t now = time(NULL);
    uint64_t issued_at = ok ? get_u64(saved + 4u) : 0u;
    size_t expected_length = 0u;
    ok = ok && now > 0 && issued_at <= (uint64_t)now &&
        (uint64_t)now - issued_at <= NONCE_RECORD_LIFETIME_SECONDS &&
        record(expected, issued_at, expected_bytes, &expected_length) &&
        (size_t)got == expected_length &&
        memcmp(saved, expected_bytes, expected_length) == 0;
    if (ok) {
        ok = linkat(dir, pending, dir, claimed, 0) == 0;
        if (ok) ok = fsync(dir) == 0;
        if (ok) {
            /* The claim is durable before any signature can be checked.
             * Leave the claimed link forever, including on cleanup failure. */
            ok = unlinkat(dir, pending, 0) == 0;
            if (ok) ok = fsync(dir) == 0;
        }
    }
    close(dir);
    return ok;
}

bool qihse_consensus_prefix_pair_nonce_accept_verified(
    const char* directory, void* store, void* store_user,
    const qihse_consensus_prefix_pair_expected_t* expected,
    const qihse_consensus_prefix_point_challenge_t* first,
    const qihse_consensus_prefix_point_challenge_t* second,
    char record_name_out[131]) {
    if (record_name_out) memset(record_name_out, 0, 131u);
    if (!store || !store_user || !expected || !first || !second ||
        !record_name_out) return false;
    int dir = open_protected_directory(directory);
    if (dir < 0) return false;
    char claimed[131], accepted[131];
    record_name(expected, 'c', claimed);
    record_name(expected, 'a', accepted);
    int claim_fd = openat(dir, claimed, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (claim_fd < 0) { close(dir); return false; }
    struct stat st;
    uint8_t claim[NONCE_RECORD_MAX], canonical[NONCE_RECORD_MAX];
    ssize_t got = read(claim_fd, claim, sizeof(claim));
    uint8_t extra;
    bool ok = fstat(claim_fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && (st.st_mode & 0777u) == 0600u &&
        st.st_nlink == 1 && got >= 12 && got < (ssize_t)sizeof(claim) &&
        read(claim_fd, &extra, 1u) == 0 &&
        memcmp(claim, "QPP1", 4u) == 0;
    if (close(claim_fd) != 0) ok = false;
    time_t now = time(NULL);
    uint64_t issued_at = ok ? get_u64(claim + 4u) : 0u;
    size_t canonical_length = 0u;
    ok = ok && now > 0 && issued_at <= (uint64_t)now &&
        (uint64_t)now - issued_at <= NONCE_RECORD_LIFETIME_SECONDS &&
        record(expected, issued_at, canonical, &canonical_length) &&
        (size_t)got == canonical_length &&
        memcmp(claim, canonical, canonical_length) == 0 &&
        first->prefix.evidence.commit_index == expected->index &&
        second->prefix.evidence.commit_index == expected->index &&
        first->observed_commit_index >= expected->index &&
        second->observed_commit_index >= expected->index &&
        memcmp(first->prefix.evidence.committed_prefix_sha256,
               expected->committed_prefix_sha256, 32u) == 0 &&
        memcmp(second->prefix.evidence.committed_prefix_sha256,
               expected->committed_prefix_sha256, 32u) == 0 &&
        memcmp(first->challenge, expected->first_challenge,
               sizeof(first->challenge)) == 0 &&
        memcmp(second->challenge, expected->second_challenge,
               sizeof(second->challenge)) == 0 &&
        qihse_uuid_equal(&first->prefix.signer_node,
                         &expected->first.signer_node) &&
        qihse_uuid_equal(&second->prefix.signer_node,
                         &expected->second.signer_node) &&
        qihse_consensus_prefix_point_challenge_verify_user(
            store, store_user, &expected->first, expected->index,
            expected->first_challenge, first) &&
        qihse_consensus_prefix_point_challenge_verify_user(
            store, store_user, &expected->second, expected->index,
            expected->second_challenge, second);
    if (!ok) { close(dir); return false; }

    /* QPA1: accepted-at, length-prefixed exact claim, then each node's
     * observed watermark, algorithm, enrolled fingerprint, inner signed
     * prefix signature and outer challenge signature. The claimed record
     * supplies group/history/epoch/index/digest, identities and nonces. */
    uint8_t* bytes = malloc(ACCEPTED_RECORD_MAX);
    if (!bytes) { close(dir); return false; }
    uint8_t accepted_at[8], claim_length[2];
    put_u64(accepted_at, (uint64_t)now);
    claim_length[0] = (uint8_t)((size_t)got >> 8u);
    claim_length[1] = (uint8_t)got;
    size_t length = 0u;
    ok = append_accepted(bytes, ACCEPTED_RECORD_MAX, &length,
                         "QPA1", 4u) &&
         append_accepted(bytes, ACCEPTED_RECORD_MAX, &length,
                         accepted_at, sizeof(accepted_at)) &&
         append_accepted(bytes, ACCEPTED_RECORD_MAX, &length,
                         claim_length, sizeof(claim_length)) &&
         append_accepted(bytes, ACCEPTED_RECORD_MAX, &length,
                         claim, (size_t)got) &&
         append_accepted_peer(bytes, ACCEPTED_RECORD_MAX, &length, first) &&
         append_accepted_peer(bytes, ACCEPTED_RECORD_MAX, &length, second);
    if (ok) {
        int fd = openat(dir, accepted, O_WRONLY | O_CREAT | O_EXCL |
                                     O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) ok = false;
        else {
            ok = fchmod(fd, 0600) == 0 && write_all(fd, bytes, length) &&
                 fsync(fd) == 0;
            if (close(fd) != 0) ok = false;
            if (ok) ok = fsync(dir) == 0;
            if (!ok) {
                unlinkat(dir, accepted, 0);
                (void)fsync(dir);
            }
        }
    }
    free(bytes);
    close(dir);
    if (ok) memcpy(record_name_out, accepted, sizeof(accepted));
    return ok;
}
