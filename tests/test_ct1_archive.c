#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_archive.h"
#include <assert.h>
#include <fcntl.h>
#include <ftw.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "../persistence/qihse_pqc_crypto.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Disposable root-owned SOURCE-mode custody fixture. */
static void path(char out[512], const char *dir, const char *name)
{
    assert(snprintf(out, 512, "%s/%s", dir, name) < 512);
}

static void put32(unsigned char *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(v >> (24 - 8*i));
}

static void put64(unsigned char *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (56 - 8*i));
}

static void original_frame(unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES])
{
    memset(frame, 0, QIHSE_CT1_RECOVERY_FRAME_BYTES);
    memcpy(frame, "QKV6CT01", 8);
    frame[8] = 1; frame[9] = 1;
    put32(frame + 12, QIHSE_CT1_RECOVERY_FRAME_BYTES);
    const char *source = "source", *generation = "generation-1";
    const char *key = "t:42/tenant-key-11";
    size_t sl = strlen(source), gl = strlen(generation), kl = strlen(key);
    size_t body = QIHSE_CT1_RECOVERY_FRAME_BYTES - 96 - sl - gl - 48;
    put32(frame + 16, 48); put32(frame + 20, (uint32_t)body);
    put32(frame + 24, 1); put32(frame + 28, 42);
    put64(frame + 32, 11111); put64(frame + 40, 5729448);
    put64(frame + 48, 5729448);
    frame[56] = (unsigned char)sl; frame[57] = (unsigned char)gl;
    memcpy(frame + 96, source, sl); memcpy(frame + 96 + sl, generation, gl);
    unsigned char *row = frame + 96 + sl + gl;
    put32(row + 4, 42); put32(row + 8, 42);
    row[13] = 4; row[15] = 2; row[16] = 1;
    put64(row + 20, 5729448);
    put32(row + 36, (uint32_t)kl); put32(row + 40, (uint32_t)(body - kl));
    memcpy(row + 48, key, kl);
    for (size_t i = kl; i < body; ++i) row[48 + i] = (unsigned char)('A' + i % 26);
    assert(SHA256(frame, QIHSE_CT1_RECOVERY_FRAME_BYTES, frame + 64));
}

static void keypair(const char *priv, const char *pub, unsigned char pin[32])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    EVP_PKEY *key = NULL;
    assert(ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1);
    int fd = open(priv, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f && PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1 && fclose(f) == 0);
    f = fopen(pub, "wb");
    assert(f && PEM_write_PUBKEY(f, key) == 1 && fclose(f) == 0);
    int len = i2d_PUBKEY(key, NULL);
    assert(len > 0 && len < 8192);
    unsigned char *der = OPENSSL_malloc((size_t)len), *cursor = der;
    assert(der && i2d_PUBKEY(key, &cursor) == len && SHA256(der, (size_t)len, pin));
    OPENSSL_clear_free(der, (size_t)len);
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
}

static void roster(const char *dir, qihse_ct1_recovery_file_t *files,
    const char *const *names, size_t count,
    const unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES])
{
    for (size_t i = 0; i < count; ++i) {
        qihse_ct1_recovery_file_t *f = &files[i];
        strcpy(f->filename, names[i]);
        const char *s = names[i];
        f->kind = !strcmp(s, "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(s, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(s, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(s, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(s, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(s, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        unsigned char bytes[16];
        memset(bytes, (int)i + 1, sizeof(bytes));
        f->size = f->kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 :
            f->kind == QIHSE_CT1_FILE_WAL && count == 8 ?
            QIHSE_CT1_RECOVERY_FRAME_BYTES : sizeof(bytes);
        const unsigned char *content = f->size == QIHSE_CT1_RECOVERY_FRAME_BYTES ? frame : bytes;
        char name[512]; path(name, dir, s);
        int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        assert(fd >= 0 && write(fd, content, (size_t)f->size) == (ssize_t)f->size &&
            SHA256(content, (size_t)f->size, f->sha256) &&
            fchmod(fd, 0400) == 0 && close(fd) == 0);
    }
}

static void quote(unsigned char out[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const qihse_ct1_recovery_manifest_t *m, unsigned role,
    const unsigned char pin[32], const char *priv)
{
    memset(out, 0, QIHSE_CT1_NODE_QUOTE_SIZE);
    size_t n = 0;
    memcpy(out + n, "CT1Q", 4); n += 4;
    out[n++] = 2; out[n++] = (unsigned char)role; n += 2;
    memcpy(out + n, m->nonce, 32); n += 32;
    assert(SHA256(wire, QIHSE_CT1_RECOVERY_WIRE_SIZE, out + n)); n += 32;
#define LABEL(s) do { memcpy(out + n, (s), strlen(s)); n += 65; } while (0)
    LABEL(role == 1 ? m->source_qkp_id : m->target_qkp_id);
    LABEL(m->source_qkp_id); LABEL(m->target_qkp_id);
    memcpy(out + n, pin, 32); n += 32;
    LABEL(role == 1 ? m->source_peer_qkp_id : m->target_peer_qkp_id);
    memcpy(out + n, role == 1 ? m->source_peer_pin : m->target_peer_pin, 32); n += 32;
    LABEL(m->replication_principal_id); LABEL(m->generation);
#undef LABEL
    memcpy(out + n, m->baseline_sha256, 32); n += 32;
    put64(out + n, m->target_cursor); n += 8;
    put64(out + n, role == 1 ? m->source_high_water : m->target_high_water); n += 8;
    assert(n == QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE &&
        qihse_pqc_sign_path(out, n, out + n, priv));
}

static int remove_fixture(const char *name, const struct stat *st, int type,
    struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(name);
}

static void verified_read_cases(const char *base)
{
    assert(geteuid() == 0);
    char auth[512], src[512], dst[512], archive[512];
    path(auth, base, "auth"); path(src, base, "frozen-source");
    path(dst, base, "frozen-target"); path(archive, base, "archive");
    assert(!mkdir(auth, 0700) && !mkdir(src, 0700) &&
        !mkdir(dst, 0700) && !mkdir(archive, 0700));
    assert(setenv("QIHSE_DATA_DIR", auth, 1) == 0 && qihse_auth_init() &&
        qihse_auth_bootstrap_operator("ArchiveFixtureOperator1!"));
    qihse_user_t *op = qihse_auth_authenticate_id(0, "ArchiveFixtureOperator1!");
    assert(op);
    qihse_user_t *low = qihse_auth_create_user(op, 62111, QIHSE_ROLE_ANALYST,
        1, 0, "ArchiveFixtureLow1!", false);
    qihse_user_t *full = qihse_auth_create_user(op, 62112, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, "ArchiveFixtureFull1!", false);
    assert(low && full);
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES], output[sizeof(frame)];
    original_frame(frame);
    char source_priv[512], source_pub[512], target_priv[512], target_pub[512];
    path(source_priv, base, "source-private.pem"); path(source_pub, base, "source-public.pem");
    path(target_priv, base, "target-private.pem"); path(target_pub, base, "target-public.pem");
    qihse_ct1_node_quote_expected_t pins = {0};
    keypair(source_priv, source_pub, pins.source_signer_pin);
    keypair(target_priv, target_pub, pins.target_signer_pin);
    static const char *const sn[] = {"ct-baseline.qfs", "ct-state.bin",
        "restore-highwater.bin", "slot-ownership.journal", "slot-ownership.journal.lock",
        "sstable_4.db", "sstable_5.db", "wal.log"};
    static const char *const tn[] = {"ct-state.bin", "restore-highwater.bin",
        "slot-ownership.journal", "slot-ownership.journal.lock",
        "sstable_6.db", "sstable_7.db", "wal.log"};
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator"); strcpy(m.source_qkp_id, "source");
    strcpy(m.target_qkp_id, "target"); strcpy(m.source_store_id, "source");
    strcpy(m.target_store_id, "target"); strcpy(m.generation, "generation-1");
    strcpy(m.source_peer_qkp_id, "target"); strcpy(m.target_peer_qkp_id, "source");
    strcpy(m.replication_principal_id, "8302"); strcpy(m.row_key, "tenant-key-11");
    memcpy(m.source_peer_pin, pins.target_signer_pin, 32);
    memcpy(m.target_peer_pin, pins.source_signer_pin, 32);
    memset(m.issuer_operator_pin, 1, 32);
    roster(src, m.source_files, sn, 8, frame);
    roster(dst, m.target_files, tn, 7, frame);
    memcpy(m.baseline_sha256, m.source_files[0].sha256, 32);
    assert(SHA256(frame, sizeof(frame), m.frame_sha256));
    memset(m.nonce, 3, 32);
    m.epoch = 1; m.issued_ms = 1000; m.expires_ms = 2000;
    m.frame_length = sizeof(frame); m.frame_position = 11111;
    m.baseline_row_seq = 17; m.target_cursor = 11110;
    m.source_high_water = 5729448; m.target_high_water = 5729457;
    m.row_change_seq = 5729448; m.tombstone_position = 11103;
    m.tombstone_row_seq = 5729450; m.row_tenant_id = 42;
    m.classification = 4; m.sci = 2;
    m.principal_classification = UINT16_MAX; m.principal_sci = UINT16_MAX;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    strcpy(pins.source_qkp_id, m.source_qkp_id);
    strcpy(pins.target_qkp_id, m.target_qkp_id);
    strcpy(pins.source_peer_qkp_id, m.source_peer_qkp_id);
    strcpy(pins.target_peer_qkp_id, m.target_peer_qkp_id);
    memcpy(pins.source_peer_pin, m.source_peer_pin, 32);
    memcpy(pins.target_peer_pin, m.target_peer_pin, 32);
    strcpy(pins.replication_principal_id, m.replication_principal_id);
    strcpy(pins.generation, m.generation);
    memcpy(pins.baseline_sha256, m.baseline_sha256, 32);
    pins.target_cursor = m.target_cursor;
    pins.source_high_water = m.source_high_water;
    pins.target_high_water = m.target_high_water;
    unsigned char sq[QIHSE_CT1_NODE_QUOTE_SIZE], tq[QIHSE_CT1_NODE_QUOTE_SIZE];
    quote(sq, wire, &m, QIHSE_CT1_NODE_QUOTE_SOURCE,
        pins.source_signer_pin, source_priv);
    quote(tq, wire, &m, QIHSE_CT1_NODE_QUOTE_TARGET,
        pins.target_signer_pin, target_priv);
    int dfd = open(archive, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(dfd >= 0);
    qihse_ct1_archive_root_t root = { .dirfd = dfd,
        .frozen_source_dir = src, .frozen_target_dir = dst,
        .source_pub_path = source_pub, .target_pub_path = target_pub,
        .source_expected = &pins, .target_expected = &pins };
    assert(qihse_ct1_recovery_verify_frozen(full, src, &m, true));
    assert(qihse_ct1_recovery_verify_frozen(full, dst, &m, false));
    assert(qihse_ct1_node_quote_verify_strict(sq, sizeof(sq), wire, sizeof(wire),
        QIHSE_CT1_NODE_QUOTE_SOURCE, m.nonce, source_pub, &pins));
    assert(qihse_ct1_node_quote_verify_strict(tq, sizeof(tq), wire, sizeof(wire),
        QIHSE_CT1_NODE_QUOTE_TARGET, m.nonce, target_pub, &pins));
    /* Each malformed B has two valid individual signatures; only pairing denies it. */
    for (unsigned variant = 0; variant < 7; ++variant) {
        qihse_ct1_recovery_manifest_t bad = m;
        qihse_ct1_node_quote_expected_t bad_pins = pins;
        qihse_ct1_archive_root_t bad_root = root;
        unsigned char bad_wire[sizeof(wire)], bad_sq[sizeof(sq)], bad_tq[sizeof(tq)];
        char rejected[QIHSE_CT1_ARCHIVE_ID_SIZE];
        switch (variant) {
        case 0: bad.source_peer_pin[0] ^= 1; bad_pins.source_peer_pin[0] ^= 1; break;
        case 1: strcpy(bad.target_peer_qkp_id, "impostor");
            strcpy(bad_pins.target_peer_qkp_id, "impostor"); break;
        case 2: bad.target_cursor = bad.frame_position;
            bad_pins.target_cursor = bad.target_cursor; break;
        case 3: bad.tombstone_position = bad.target_cursor + 1; break;
        case 4: bad.tombstone_row_seq = bad.target_high_water + 1; break;
        case 5: bad.tombstone_row_seq = bad.row_change_seq; break;
        case 6: bad.source_high_water = bad.row_change_seq - 1;
            bad_pins.source_high_water = bad.source_high_water; break;
        }
        bad_root.source_expected = &bad_pins;
        bad_root.target_expected = &bad_pins;
        assert(qihse_ct1_recovery_encode(&bad, false, false, bad_wire));
        quote(bad_sq, bad_wire, &bad, QIHSE_CT1_NODE_QUOTE_SOURCE,
            bad_pins.source_signer_pin, source_priv);
        quote(bad_tq, bad_wire, &bad, QIHSE_CT1_NODE_QUOTE_TARGET,
            bad_pins.target_signer_pin, target_priv);
        assert(qihse_ct1_node_quote_verify_strict(bad_sq, sizeof(bad_sq),
            bad_wire, sizeof(bad_wire), QIHSE_CT1_NODE_QUOTE_SOURCE,
            bad.nonce, source_pub, &bad_pins));
        assert(qihse_ct1_node_quote_verify_strict(bad_tq, sizeof(bad_tq),
            bad_wire, sizeof(bad_wire), QIHSE_CT1_NODE_QUOTE_TARGET,
            bad.nonce, target_pub, &bad_pins));
        assert(!qihse_ct1_archive_write_root(&bad_root, full, &bad, bad_wire,
            bad_sq, bad_tq, rejected) && !rejected[0]);
    }
    char id[QIHSE_CT1_ARCHIVE_ID_SIZE];
    assert(qihse_ct1_archive_write_root(&root, full, &m, wire, sq, tq, id));
    memset(output, 0xa5, sizeof(output));
    assert(qihse_ct1_archive_read_source_root(&root, full, &m, id, output) &&
        !memcmp(output, frame, sizeof(frame)));
#define DENY(principal, manifest, name) do { \
    memset(output, 0xa5, sizeof(output)); \
    assert(!qihse_ct1_archive_read_source_root(&root, (principal), (manifest), (name), output)); \
    unsigned char zero[sizeof(output)] = {0}; \
    assert(!memcmp(output, zero, sizeof(output))); \
} while (0)
    DENY(NULL, &m, id); DENY(low, &m, id);
    assert(qihse_auth_destroy_user(op, 62112));
    DENY(full, &m, id); /* revoked while archive remains valid */
    full = op;
    qihse_ct1_recovery_manifest_t swapped = m;
    swapped.frame_sha256[0] ^= 1;
    DENY(full, &swapped, id);
    qihse_ct1_recovery_manifest_t other = m;
    other.nonce[0] ^= 1;
    unsigned char other_wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    unsigned char other_sq[sizeof(sq)], other_tq[sizeof(tq)];
    char other_id[QIHSE_CT1_ARCHIVE_ID_SIZE];
    assert(qihse_ct1_recovery_encode(&other, false, false, other_wire));
    quote(other_sq, other_wire, &other, QIHSE_CT1_NODE_QUOTE_SOURCE,
        pins.source_signer_pin, source_priv);
    quote(other_tq, other_wire, &other, QIHSE_CT1_NODE_QUOTE_TARGET,
        pins.target_signer_pin, target_priv);
    assert(qihse_ct1_archive_write_root(&root, full, &other, other_wire,
        other_sq, other_tq, other_id));
    DENY(full, &m, other_id); /* a valid archive is not authority for B */
    assert(renameat(dfd, id, dfd, "original.arc") == 0 &&
        renameat(dfd, other_id, dfd, id) == 0);
    DENY(full, &m, id); /* another valid archive substituted at the expected ID */
    assert(renameat(dfd, id, dfd, other_id) == 0 &&
        renameat(dfd, "original.arc", dfd, id) == 0);
    pins.target_signer_pin[0] ^= 1;
    DENY(full, &m, id);
    pins.target_signer_pin[0] ^= 1;
    char file[512], seal[512];
    path(file, archive, id);
    assert(snprintf(seal, sizeof(seal), "%s/%s.ok", archive, id) < (int)sizeof(seal));
    int corrupt = open(file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(corrupt >= 0 && fchmod(corrupt, 0600) == 0);
    const off_t source_off = 16 + QIHSE_CT1_RECOVERY_WIRE_SIZE;
    const off_t target_off = source_off + QIHSE_CT1_NODE_QUOTE_SIZE;
    unsigned char forged = sq[QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE] ^ 1u;
    assert(pwrite(corrupt, &forged, 1,
        source_off + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE) == 1 &&
        fchmod(corrupt, 0400) == 0);
    DENY(full, &m, id); /* forged signed SOURCE quote */
    assert(fchmod(corrupt, 0600) == 0 &&
        pwrite(corrupt, sq + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE, 1,
            source_off + QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE) == 1 &&
        pwrite(corrupt, tq, sizeof(tq), source_off) == (ssize_t)sizeof(tq) &&
        pwrite(corrupt, sq, sizeof(sq), target_off) == (ssize_t)sizeof(sq) &&
        fchmod(corrupt, 0400) == 0);
    DENY(full, &m, id); /* source/target signed quotes swapped */
    assert(fchmod(corrupt, 0600) == 0 &&
        pwrite(corrupt, sq, sizeof(sq), source_off) == (ssize_t)sizeof(sq) &&
        pwrite(corrupt, tq, sizeof(tq), target_off) == (ssize_t)sizeof(tq) &&
        fchmod(corrupt, 0400) == 0);
    int committed = open(seal, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(committed >= 0 && fchmod(committed, 0600) == 0 &&
        pwrite(committed, &forged, 1, 8) == 1 && fchmod(committed, 0400) == 0);
    DENY(full, &m, id); /* forged provenance seal */
    assert(close(committed) == 0 && unlink(seal) == 0);
    DENY(full, &m, id); /* uncommitted, even with an intact archive */
    assert(fchmod(corrupt, 0600) == 0 && ftruncate(corrupt, source_off + 1) == 0 &&
        fchmod(corrupt, 0400) == 0);
    DENY(full, &m, id); /* partial persisted archive */
    assert(close(corrupt) == 0 && unlink(file) == 0);
    DENY(full, &m, id); /* missing persisted archive */
#undef DENY
    assert(close(dfd) == 0);
}

static void run_root_fixture(void)
{
    char base[512];
    const char *home = getenv("HOME");
    assert(home && snprintf(base, sizeof(base), "%s/ct1-archive-read-XXXXXX", home) <
        (int)sizeof(base) && mkdtemp(base));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        verified_read_cases(base);
        _exit(0); /* Release the audit writer before fixture removal. */
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(nftw(base, remove_fixture, 20, FTW_PHYS | FTW_DEPTH) == 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* Adversarial files without the root host's pinned context and signed SOURCE
 * quote cannot pass. The root-host target covers verified custody and cuts. */
int main(void)
{
    char dir[] = "./build/ct1-archive/cuts-XXXXXX";
    assert(mkdtemp(dir));
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(dfd >= 0);
    qihse_ct1_recovery_manifest_t expected = {0};
    const qihse_user_t *untrusted_identity = (const qihse_user_t *)(uintptr_t)1;
    assert(!qihse_ct1_archive_verify(NULL, NULL, NULL, NULL));
    assert(!qihse_ct1_archive_verify(NULL, untrusted_identity, &expected, "no-archive"));
    for (int cut = 0; cut < 5; ++cut) {
        char name[32];
        assert(snprintf(name, sizeof(name), "candidate-%d", cut) > 0);
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            int fd = openat(dfd, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd < 0) _exit(2);
            unsigned char bytes[QIHSE_CT1_RECOVERY_ARCHIVE_BYTES];
            memset(bytes, 0xa5, sizeof(bytes));
            if (cut >= 1 && write(fd, bytes, sizeof(bytes) / 2) != (ssize_t)sizeof(bytes) / 2) _exit(3);
            if (cut >= 2 && write(fd, bytes + sizeof(bytes) / 2,
                    sizeof(bytes) - sizeof(bytes) / 2) != (ssize_t)(sizeof(bytes) - sizeof(bytes) / 2)) _exit(4);
            if (cut >= 3 && fsync(fd)) _exit(5);
            if (close(fd)) _exit(6);
            if (cut >= 4 && fsync(dfd)) _exit(7);
            _exit(0); /* child dies at each publication/fsync boundary */
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        assert(!qihse_ct1_archive_verify(NULL, untrusted_identity, &expected, name));
        assert(unlinkat(dfd, name, 0) == 0);
    }
    int fd = openat(dfd, "stale", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    assert(fd >= 0);
    unsigned char old[QIHSE_CT1_RECOVERY_ARCHIVE_BYTES];
    memset(old, 0x11, sizeof(old));
    assert(write(fd, old, sizeof(old)) == (ssize_t)sizeof(old));
    assert(fsync(fd) == 0 && close(fd) == 0 && fsync(dfd) == 0);
    assert(!qihse_ct1_archive_verify(NULL, untrusted_identity, &expected, "stale"));
    assert(renameat(dfd, "stale", dfd, "renamed") == 0);
    assert(fsync(dfd) == 0);
    assert(!qihse_ct1_archive_verify(NULL, untrusted_identity, &expected, "renamed"));
    assert(unlinkat(dfd, "renamed", 0) == 0);
    assert(close(dfd) == 0 && rmdir(dir) == 0);
    if (geteuid() == 0) {
        run_root_fixture();
        puts("CT1 archive: verified SOURCE read and adversarial denials passed");
    } else puts("CT1 archive: non-root adversarial denials passed (root fixture skipped)");
    return 0;
}
