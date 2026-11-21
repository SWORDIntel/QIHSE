#include "qihse_ct1_authority_service.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_ct1_authority_store.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_engine.h"
#include "qihse_resp_wire.h"
#include "../core/qihse_audit.h"

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void denied(const void *bytes, size_t length)
{
    assert(qihse_ct1_authority_service_authorize(bytes, length) ==
           QIHSE_CT1_AUTHORITY_SERVICE_DISABLED);
    assert(qihse_ct1_authority_service_consume(bytes, length) ==
           QIHSE_CT1_AUTHORITY_SERVICE_DISABLED);
}

static void forged_session_and_user_flags(void)
{
    /* Deliberately NOT a handshake-created session. Caller-owned memory and
     * claimed Operator flags cannot even be passed as a session argument. */
    union {
        long double alignment;
        unsigned char bytes[4096];
    } forged;
    memset(&forged, 0xff, sizeof(forged));
    struct {
        unsigned operator_role, authenticated, admin_peer, independent_anchor;
        uint64_t caller_now_ms;
        const void *user;
    } claims = {1, 1, 1, 1, UINT64_MAX, &forged};
    denied(&claims, sizeof(claims));
    denied(&forged, sizeof(forged));
    memset(&forged, 0, sizeof(forged));
    denied(&claims, sizeof(claims));
}

static void arbitrary_grants_and_replays(void)
{
    unsigned char grant[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    memset(grant, 0xa5, sizeof(grant));
    for (unsigned i = 0; i < 8; ++i) denied(grant, sizeof(grant));
    denied(NULL, 0);
    denied(NULL, SIZE_MAX);
    denied(grant, 0);
    denied(grant, SIZE_MAX);
}

static void development_witness_and_receipt_bypass(void)
{
    /* The deny boundary is independent of every structural/dev codec: neither
     * a claimed spent receipt nor a purported witness can enable its return. */
    static const char *const claims[] = {
        "CT1A", "CT1Q", "CT1B", "CT1R",
        "QIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL=1",
        "QIHSE_CT1_INSECURE_DEV_RECOVERY=1",
        "witness=verified;receipt=unspent;operator=true;anchor=independent",
        "receipt=spent;epoch=1;nonce=replayed",
        "ledger=restored-older-snapshot;owner=same-UID;retire=success",
        "ledger=private;anchor=missing;epoch=1;nonce=previously-retired"
    };
    for (size_t i = 0; i < sizeof(claims) / sizeof(claims[0]); ++i)
        denied(claims[i], strlen(claims[i]));
}

static void missing_independent_anchor(void)
{
    unsigned blockers = qihse_ct1_authority_service_blockers();
    assert(blockers == (QIHSE_CT1_AUTHORITY_BLOCK_OPERATOR_SESSION |
                        QIHSE_CT1_AUTHORITY_BLOCK_INDEPENDENT_ANCHOR |
                        QIHSE_CT1_AUTHORITY_BLOCK_LIVE_NODE_COMMAND |
                        QIHSE_CT1_AUTHORITY_BLOCK_MANIFEST_CONSUMPTION));
    assert(strstr(qihse_ct1_authority_service_diagnostic(), "DISABLED"));
    assert(strstr(qihse_ct1_authority_service_diagnostic(), "B UID"));
    assert(strstr(qihse_ct1_authority_service_diagnostic(),
                  "No live state was checked"));
    /* No caller-supplied pathname/UID/clock or readiness switch is accepted. */
    denied("private same-UID ledger;anchor=present", 36);
    assert(qihse_ct1_authority_service_blockers() == blockers);
}

static void strict_checkpoint_is_not_approval(void)
{
    if (geteuid() != 0) {
        puts("SKIP CT1 service strict root/distinct-UID fixture: requires root");
        return;
    }
    struct passwd *b = getpwnam("nobody");
    assert(b && b->pw_uid != 0);
    uid_t b_uid = b->pw_uid;
    gid_t b_gid = b->pw_gid;
    char ledger[] = "./ct1-service-ledger-XXXXXX";
    char anchor[] = "./ct1-service-anchor-XXXXXX";
    assert(mkdtemp(ledger) && mkdtemp(anchor));
    assert(!qihse_ct1_authority_store_initialize_strict(ledger, anchor, b_uid));
    qihse_ct1_authority_store_t *s = NULL;
    assert(!qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &s));
    qihse_ct1_authority_challenge_t challenge;
    assert(!qihse_ct1_authority_store_issue(s, 900000, &challenge));
    denied(&challenge, sizeof(challenge));
    char checkpoint[sizeof(anchor) + 32];
    assert(snprintf(checkpoint, sizeof(checkpoint), "%s/authority.checkpoint", anchor) > 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        if (setgroups(0, NULL) || setgid(b_gid) || setuid(b_uid)) _exit(2);
        int fd = open(checkpoint, O_RDONLY);
        if (fd >= 0) { close(fd); _exit(3); }
        qihse_ct1_authority_store_t *other = NULL;
        if (qihse_ct1_authority_store_open_strict(ledger, anchor, b_uid, &other) != -1 ||
            qihse_ct1_authority_service_authorize(&challenge, sizeof(challenge)) !=
                QIHSE_CT1_AUTHORITY_SERVICE_DISABLED) _exit(4);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!qihse_ct1_authority_store_retire(s, &challenge));
    denied(&challenge, sizeof(challenge));
    assert(qihse_ct1_authority_store_retire(s, &challenge) == -1);
    qihse_ct1_authority_store_close(s);
    char path[sizeof(ledger) + 32];
    assert(snprintf(path, sizeof(path), "%s/authority.log", ledger) > 0);
    assert(!unlink(path));
    assert(snprintf(path, sizeof(path), "%s/authority.lock", ledger) > 0);
    assert(!unlink(path));
    assert(!unlink(checkpoint) && !rmdir(ledger) && !rmdir(anchor));
    puts("CT1 service strict root checkpoint/distinct B UID: no grant on issue, retire or replay");
}

/* Disposable signing fixture: never a service signer or a configured identity. */
static void signed_grant_verifier(void)
{
    char dir[] = "./ct1-verifier-XXXXXX";
    char pub[sizeof(dir) + 16];
    assert(mkdtemp(dir));
    assert(snprintf(pub, sizeof(pub), "%s/operator.pub", dir) > 0);
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    EVP_PKEY *key = NULL;
    assert(gen && EVP_PKEY_keygen_init(gen) == 1 && EVP_PKEY_keygen(gen, &key) == 1);
    FILE *f = fopen(pub, "wb");
    assert(f && PEM_write_PUBKEY(f, key) == 1 && fclose(f) == 0);
    int der_len = i2d_PUBKEY(key, NULL);
    assert(der_len > 0 && der_len < 8192);
    unsigned char *der = OPENSSL_malloc((size_t)der_len), *cursor = der;
    unsigned char pin[32], wrong_pin[32];
    assert(der && i2d_PUBKEY(key, &cursor) == der_len);
    assert(SHA256(der, (size_t)der_len, pin));
    OPENSSL_free(der);
    memcpy(wrong_pin, pin, sizeof(pin)); wrong_pin[0] ^= 1;

    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.source_peer_qkp_id, "source-node");
    strcpy(m.target_peer_qkp_id, "target-node");
    strcpy(m.source_store_id, "source-store");
    strcpy(m.target_store_id, "target-store");
    strcpy(m.generation, "generation-1");
    strcpy(m.replication_principal_id, "replication-service");
    strcpy(m.row_key, "row");
    memcpy(m.issuer_operator_pin, pin, 32);
    memset(m.source_peer_pin, 2, 32); memset(m.target_peer_pin, 3, 32);
    memset(m.frame_sha256, 4, 32); memset(m.baseline_sha256, 5, 32);
    memset(m.nonce, 6, 32);
    const char *source[] = {"ct-baseline.qfs", "ct-state.bin", "restore-highwater.bin",
        "slot-ownership.journal", "slot-ownership.journal.lock", "sstable_11321.db",
        "sstable_11322.db", "wal.log"};
    const char *target[] = {"ct-state.bin", "restore-highwater.bin",
        "slot-ownership.journal", "slot-ownership.journal.lock", "sstable_6.db",
        "sstable_7.db", "wal.log"};
    for (size_t role = 0; role < 2; ++role) {
        qihse_ct1_recovery_file_t *files = role ? m.target_files : m.source_files;
        const char *const *names = role ? target : source;
        size_t count = role ? QIHSE_CT1_RECOVERY_TARGET_FILES : QIHSE_CT1_RECOVERY_SOURCE_FILES;
        for (size_t i = 0; i < count; ++i) {
            const char *s = names[i];
            strcpy(files[i].filename, s);
            files[i].kind = !strcmp(s, "wal.log") ? QIHSE_CT1_FILE_WAL :
                !strcmp(s, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
                !strcmp(s, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
                !strcmp(s, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
                !strcmp(s, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
                !strcmp(s, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
                QIHSE_CT1_FILE_SSTABLE;
            files[i].size = files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 : 100 + i;
            if (!files[i].size) assert(SHA256((const unsigned char *)"", 0, files[i].sha256));
            else memset(files[i].sha256, (int)i + 1, 32);
        }
    }
    struct timespec ts;
    assert(!clock_gettime(CLOCK_REALTIME, &ts));
    m.epoch = 9; m.issued_ms = (uint64_t)ts.tv_sec * 1000u - 1000u;
    m.expires_ms = m.issued_ms + 60000u;
    m.frame_offset = 1; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 2; m.target_cursor = 21;
    m.source_high_water = 33; m.target_high_water = 44;
    m.row_change_seq = 1; m.tombstone_position = 1; m.tombstone_row_seq = 2;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    qihse_ct1_authority_challenge_t challenge = {0};
    challenge.epoch = m.epoch; challenge.issued_ms = m.issued_ms;
    challenge.expires_ms = m.expires_ms;
    memcpy(challenge.nonce, m.nonce, 32);
    unsigned char grant[QIHSE_CT1_AUTHORITY_GRANT_SIZE];
    memcpy(grant, "CT1G\1\0\0\0", 8);
    assert(qihse_ct1_recovery_encode(&m, false, false, grant + 8));
    EVP_MD_CTX *sign = EVP_MD_CTX_new();
    size_t sig_len = QIHSE_CT1_AUTHORITY_GRANT_SIZE - QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE;
    assert(sign && EVP_DigestSignInit(sign, NULL, NULL, NULL, key) == 1);
    assert(EVP_DigestSign(sign, grant + QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE,
        &sig_len, grant, QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE) == 1 && sig_len == 4627);
    EVP_MD_CTX_free(sign);
    assert(qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    denied(grant, sizeof(grant));
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant) - 1, &m,
        &challenge, pub, pin));
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, wrong_pin));
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        NULL, pub, pin));
    challenge.nonce[0] ^= 1;
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    challenge.nonce[0] ^= 1; challenge.epoch++;
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    challenge.epoch--;
    m.target_files[0].sha256[0] ^= 1;
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    m.target_files[0].sha256[0] ^= 1;
    grant[QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE] ^= 1;
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    grant[QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE] ^= 1;
    grant[5] ^= 1;
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    grant[5] ^= 1;
    challenge.issued_ms++;
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    challenge.issued_ms--;
    m.expires_ms = m.issued_ms + 500u;
    challenge.expires_ms = m.expires_ms;
    assert(qihse_ct1_recovery_encode(&m, false, false, grant + 8));
    sign = EVP_MD_CTX_new();
    sig_len = 4627;
    assert(sign && EVP_DigestSignInit(sign, NULL, NULL, NULL, key) == 1);
    assert(EVP_DigestSign(sign, grant + QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE,
        &sig_len, grant, QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE) == 1 && sig_len == 4627);
    EVP_MD_CTX_free(sign);
    assert(!qihse_ct1_authority_service_verify_grant(grant, sizeof(grant), &m,
        &challenge, pub, pin));
    assert(!unlink(pub) && !rmdir(dir));
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(gen);
    puts("CT1 disposable signed-grant verifier: exact manifest/challenge/pin/tamper checks passed");
}

static const char *const pair_source_names[8] = {
    "ct-baseline.qfs", "ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_11321.db", "sstable_11322.db", "wal.log"};
static const char *const pair_target_names[7] = {
    "ct-state.bin", "restore-highwater.bin", "slot-ownership.journal",
    "slot-ownership.journal.lock", "sstable_6.db", "sstable_7.db", "wal.log"};

static void pair_key(const char *priv, const char *pub, unsigned char pin[32])
{
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    EVP_PKEY *key = NULL;
    assert(gen && EVP_PKEY_keygen_init(gen) == 1 && EVP_PKEY_keygen(gen, &key) == 1);
    int fd = open(priv, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f && PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1 && !fclose(f));
    f = fopen(pub, "wb");
    assert(f && PEM_write_PUBKEY(f, key) == 1 && !fclose(f));
    int n = i2d_PUBKEY(key, NULL);
    assert(n > 0 && n < 8192);
    unsigned char *der = OPENSSL_malloc((size_t)n), *p = der;
    assert(der && i2d_PUBKEY(key, &p) == n && SHA256(der, (size_t)n, pin));
    OPENSSL_free(der);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
}

static void pair_roster(const char *dir, qihse_ct1_recovery_file_t *files,
    const char *const *names, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        char path[256];
        assert(snprintf(path, sizeof(path), "%s/%s", dir, names[i]) > 0);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0);
        unsigned char bytes[8] = {1, 2, 3, 4, 5, 6, 7, (unsigned char)i};
        size_t len = strstr(names[i], ".lock") ? 0u : sizeof(bytes);
        assert(write(fd, bytes, len) == (ssize_t)len && !close(fd));
        strcpy(files[i].filename, names[i]);
        files[i].size = len;
        assert(SHA256(bytes, len, files[i].sha256));
        files[i].kind = !strcmp(names[i], "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(names[i], "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(names[i], "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(names[i], "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(names[i], "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(names[i], "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
    }
}

static void pair_quote(unsigned char out[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const qihse_ct1_recovery_manifest_t *m, unsigned role,
    const unsigned char signer_pin[32], const char *private_path)
{
    size_t n = 0;
    memset(out, 0, QIHSE_CT1_NODE_QUOTE_SIZE);
    memcpy(out + n, "CT1Q", 4); n += 4;
    out[n++] = 2; out[n++] = (unsigned char)role; n += 2;
    memcpy(out + n, m->nonce, 32); n += 32;
    assert(SHA256(wire, QIHSE_CT1_RECOVERY_WIRE_SIZE, out + n)); n += 32;
#define LABEL(s) do { memcpy(out + n, (s), strlen(s)); n += 65; } while (0)
    LABEL(role == QIHSE_CT1_NODE_QUOTE_SOURCE ? m->source_qkp_id : m->target_qkp_id);
    LABEL(m->source_qkp_id);
    LABEL(m->target_qkp_id);
    memcpy(out + n, signer_pin, 32); n += 32;
    LABEL(role == QIHSE_CT1_NODE_QUOTE_SOURCE ? m->source_peer_qkp_id : m->target_peer_qkp_id);
    memcpy(out + n, role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        m->source_peer_pin : m->target_peer_pin, 32); n += 32;
    LABEL(m->replication_principal_id);
    LABEL(m->generation);
#undef LABEL
    memcpy(out + n, m->baseline_sha256, 32); n += 32;
    uint64_t values[2] = {m->target_cursor, role == QIHSE_CT1_NODE_QUOTE_SOURCE ?
        m->source_high_water : m->target_high_water};
    for (size_t j = 0; j < 2; ++j)
        for (size_t i = 0; i < 8; ++i)
            out[n++] = (unsigned char)(values[j] >> (56u - 8u * i));
    assert(n == QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE);
    FILE *f = fopen(private_path, "rb");
    EVP_PKEY *key = f ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
    assert(f && !fclose(f) && key);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sig_len = QIHSE_CT1_NODE_QUOTE_SIGNATURE_SIZE;
    assert(ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestSign(ctx, out + n, &sig_len, out, n) == 1 &&
        sig_len == QIHSE_CT1_NODE_QUOTE_SIGNATURE_SIZE);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
}

static void paired_frozen_evidence(void)
{
    char dir[] = "./ct1-pair-XXXXXX", src[128], dst[128], source_priv[128],
        source_pub[128], target_priv[128], target_pub[128];
    assert(mkdtemp(dir));
#define PATH(buf, suffix) assert(snprintf((buf), sizeof(buf), "%s/%s", dir, (suffix)) > 0)
    PATH(src, "source"); PATH(dst, "target");
    PATH(source_priv, "source-private.pem"); PATH(source_pub, "source-public.pem");
    PATH(target_priv, "target-private.pem"); PATH(target_pub, "target-public.pem");
#undef PATH
    assert(!mkdir(src, 0700) && !mkdir(dst, 0700));
    unsigned char source_pin[32], target_pin[32];
    pair_key(source_priv, source_pub, source_pin);
    pair_key(target_priv, target_pub, target_pin);
    qihse_ct1_recovery_manifest_t m = {0}, changed;
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.source_peer_qkp_id, "target"); strcpy(m.target_peer_qkp_id, "source");
    strcpy(m.source_store_id, "source-store"); strcpy(m.target_store_id, "target-store");
    strcpy(m.generation, "generation-1");
    strcpy(m.replication_principal_id, "replication-service");
    strcpy(m.row_key, "pending-row");
    memset(m.issuer_operator_pin, 1, 32);
    memcpy(m.source_peer_pin, target_pin, 32);
    memcpy(m.target_peer_pin, source_pin, 32);
    memset(m.frame_sha256, 4, 32); memset(m.baseline_sha256, 5, 32);
    pair_roster(src, m.source_files, pair_source_names, 8);
    pair_roster(dst, m.target_files, pair_target_names, 7);
    qihse_ct1_authority_challenge_t challenge = {0};
    qihse_ct1_authority_store_t *store = NULL;
    char ledger[128], checkpoint[128];
    if (geteuid() == 0) {
        assert(snprintf(ledger, sizeof(ledger), "%s/ledger", dir) > 0);
        assert(snprintf(checkpoint, sizeof(checkpoint), "%s/checkpoint", dir) > 0);
        struct passwd *b = getpwnam("nobody");
        assert(b && b->pw_uid != 0);
        assert(!mkdir(ledger, 0700) && !mkdir(checkpoint, 0700));
        assert(!qihse_ct1_authority_store_initialize_strict(ledger, checkpoint, b->pw_uid));
        assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, b->pw_uid, &store));
        assert(!qihse_ct1_authority_store_issue(store, 60000, &challenge));
    } else {
        struct timespec ts;
        assert(!clock_gettime(CLOCK_REALTIME, &ts));
        challenge.epoch = 1;
        challenge.issued_ms = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
        challenge.expires_ms = challenge.issued_ms + 60000u;
        memset(challenge.nonce, 0x74, sizeof(challenge.nonce));
        puts("SKIP strict-store provenance for unprivileged pair fixture");
    }
    m.epoch = challenge.epoch; m.issued_ms = challenge.issued_ms;
    m.expires_ms = challenge.expires_ms;
    memcpy(m.nonce, challenge.nonce, 32);
    m.frame_offset = 1; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 11111; m.target_cursor = 11110;
    m.tombstone_position = 11103; m.row_change_seq = 5729448;
    m.tombstone_row_seq = 5729450;
    m.source_high_water = 5729448; m.target_high_water = 5729457;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    qihse_ct1_node_quote_expected_t se = {0}, te;
    strcpy(se.source_qkp_id, m.source_qkp_id);
    strcpy(se.target_qkp_id, m.target_qkp_id);
    strcpy(se.source_peer_qkp_id, m.source_peer_qkp_id);
    strcpy(se.target_peer_qkp_id, m.target_peer_qkp_id);
    strcpy(se.replication_principal_id, m.replication_principal_id);
    strcpy(se.generation, m.generation);
    memcpy(se.source_signer_pin, source_pin, 32);
    memcpy(se.target_signer_pin, target_pin, 32);
    memcpy(se.source_peer_pin, target_pin, 32);
    memcpy(se.target_peer_pin, source_pin, 32);
    memcpy(se.baseline_sha256, m.baseline_sha256, 32);
    se.target_cursor = m.target_cursor;
    se.source_high_water = m.source_high_water;
    se.target_high_water = m.target_high_water;
    te = se;
    unsigned char sq[QIHSE_CT1_NODE_QUOTE_SIZE], tq[sizeof(sq)];
    pair_quote(sq, wire, &m, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
    pair_quote(tq, wire, &m, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("Ct1ServiceOperator1!"));
    qihse_user_t *operator = qihse_auth_get_user(0);
    assert(operator && qihse_auth_create_user(operator, 8302, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, "Ct1ServiceReplication1!", false));
    qihse_user_t *replication = qihse_auth_get_user(8302);
    assert(replication);
    qihse_ct1_authority_pair_evidence_t e = {
        .manifest_wire = wire, .manifest_len = sizeof(wire), .expected_manifest = &m,
        .replication_principal = replication,
        .challenge = &challenge, .source_quote = sq, .source_quote_len = sizeof(sq),
        .target_quote = tq, .target_quote_len = sizeof(tq),
        .source_pub_path = source_pub, .target_pub_path = target_pub,
        .source_expected = &se, .target_expected = &te,
        .frozen_source_dir = src, .frozen_target_dir = dst};
#define PAIR_OK() assert(qihse_ct1_authority_service_evaluate_pair(&e))
#define PAIR_DENIED() assert(!qihse_ct1_authority_service_evaluate_pair(&e))
#define BOUND_OK() assert(qihse_ct1_authority_service_evaluate_pair_bound(store, &e))
#define BOUND_DENIED() assert(!qihse_ct1_authority_service_evaluate_pair_bound(store, &e))
    BOUND_DENIED(); /* An issued but unbound challenge is not store evidence. */
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    if (store) {
        assert(!qihse_ct1_authority_store_bind(store, &challenge, wire, sizeof(wire)));
        BOUND_OK();
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) {
            struct passwd *b = getpwnam("nobody");
            if (!b || setgroups(0, NULL) || setgid(b->pw_gid) || setuid(b->pw_uid)) _exit(2);
            _exit(qihse_ct1_authority_service_evaluate_pair_bound(store, &e) ||
                qihse_ct1_authority_service_check_and_retire_pair(store, &e) ? 3 : 0);
        }
        int status;
        assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    }
    e.replication_principal = NULL; PAIR_DENIED();
    e.replication_principal = replication;
    PAIR_OK(); denied(&e, sizeof(e));
    assert(qihse_auth_create_user(operator, 8303, QIHSE_ROLE_ANALYST,
        1u, 1u, "Ct1ServiceLowClearance1!", false));
    qihse_user_t *low = qihse_auth_get_user(8303);
    assert(low);
    e.replication_principal = low;
    PAIR_DENIED(); BOUND_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    e.replication_principal = operator;
    PAIR_DENIED(); BOUND_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    e.replication_principal = replication;
    if (store) BOUND_OK();
    challenge.nonce[0] ^= 1; PAIR_DENIED(); BOUND_DENIED(); challenge.nonce[0] ^= 1;
    challenge.epoch++; PAIR_DENIED(); challenge.epoch--;
    challenge.expires_ms++; PAIR_DENIED(); challenge.expires_ms--;
    changed = m; changed.frame_sha256[0] ^= 1;
    e.expected_manifest = &changed; PAIR_DENIED(); BOUND_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    e.expected_manifest = &m;
    wire[100] ^= 1; PAIR_DENIED(); BOUND_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    wire[100] ^= 1;
    if (store) BOUND_OK();
    e.manifest_len--; PAIR_DENIED(); e.manifest_len++;
    e.source_quote_len--; PAIR_DENIED(); e.source_quote_len++;
    e.source_quote = tq; PAIR_DENIED(); e.source_quote = sq;
    e.target_pub_path = source_pub; PAIR_DENIED(); e.target_pub_path = target_pub;
    te.target_signer_pin[0] ^= 1; PAIR_DENIED(); te.target_signer_pin[0] ^= 1;
    se.source_peer_pin[0] ^= 1; PAIR_DENIED(); se.source_peer_pin[0] ^= 1;
    strcpy(te.target_peer_qkp_id, "wrong-peer"); PAIR_DENIED();
    strcpy(te.target_peer_qkp_id, "source");
    sq[sizeof(sq) - 1] ^= 1; PAIR_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    sq[sizeof(sq) - 1] ^= 1;
    if (store) BOUND_OK();
    tq[sizeof(tq) - 1] ^= 1; PAIR_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    tq[sizeof(tq) - 1] ^= 1;
    changed = m; changed.row_change_seq = changed.tombstone_row_seq;
    assert(qihse_ct1_recovery_encode(&changed, false, false, wire));
    pair_quote(sq, wire, &changed, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
    pair_quote(tq, wire, &changed, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
    e.expected_manifest = &changed; PAIR_DENIED();
    e.expected_manifest = &m;
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    pair_quote(sq, wire, &m, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
    pair_quote(tq, wire, &m, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
    PAIR_OK();
    changed = m;
    changed.issued_ms -= 120000u;
    changed.expires_ms = changed.issued_ms + 60000u;
    challenge.issued_ms = changed.issued_ms;
    challenge.expires_ms = changed.expires_ms;
    e.expected_manifest = &changed;
    assert(qihse_ct1_recovery_encode(&changed, false, false, wire));
    pair_quote(sq, wire, &changed, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
    pair_quote(tq, wire, &changed, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
    PAIR_DENIED(); /* Canonical signed pair and matching challenge, but host time expired. */
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    challenge.issued_ms = m.issued_ms; challenge.expires_ms = m.expires_ms;
    e.expected_manifest = &m;
    assert(qihse_ct1_recovery_encode(&m, false, false, wire));
    pair_quote(sq, wire, &m, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
    pair_quote(tq, wire, &m, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
    PAIR_OK();
    if (store) BOUND_OK();
    char path[256];
    assert(snprintf(path, sizeof(path), "%s/%s", src, pair_source_names[0]) > 0);
    assert(!unlink(path)); PAIR_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    unsigned char restored[8] = {1, 2, 3, 4, 5, 6, 7, 0};
    assert(fd >= 0 && write(fd, restored, sizeof(restored)) == (ssize_t)sizeof(restored) &&
        !close(fd));
    PAIR_OK();
    if (store) BOUND_OK();
    fd = open(path, O_WRONLY);
    unsigned char b = 0xff;
    assert(fd >= 0 && write(fd, &b, 1) == 1 && !close(fd)); PAIR_DENIED();
    fd = open(path, O_WRONLY);
    assert(fd >= 0 && write(fd, restored, 1) == 1 && !close(fd));
    PAIR_OK();
    assert(snprintf(path, sizeof(path), "%s/%s", dst, pair_target_names[0]) > 0);
    fd = open(path, O_WRONLY);
    assert(fd >= 0 && write(fd, &b, 1) == 1 && !close(fd)); PAIR_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    fd = open(path, O_WRONLY);
    assert(fd >= 0 && write(fd, restored, 1) == 1 && !close(fd));
    PAIR_OK();
    if (store) BOUND_OK();
    challenge.expires_ms = challenge.issued_ms;
    PAIR_DENIED(); BOUND_DENIED();
    if (store) assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
    challenge.expires_ms = m.expires_ms;
    if (store) {
        qihse_ct1_authority_challenge_t original = challenge;
        for (int cut = 0; cut <= 9; ++cut) {
            char cut_ledger[128], cut_anchor[128], cp[256], log[256];
            assert(snprintf(cut_ledger, sizeof(cut_ledger), "%s/cut-ledger-XXXXXX", dir) > 0);
            assert(snprintf(cut_anchor, sizeof(cut_anchor), "%s/cut-anchor-XXXXXX", dir) > 0);
            assert(mkdtemp(cut_ledger) && mkdtemp(cut_anchor));
            assert(snprintf(cp, sizeof(cp), "%s/authority.checkpoint", cut_anchor) > 0);
            assert(snprintf(log, sizeof(log), "%s/authority.log", cut_ledger) > 0);
            struct passwd *b_user = getpwnam("nobody");
            assert(b_user && b_user->pw_uid != 0);
            assert(!qihse_ct1_authority_store_initialize_strict(cut_ledger, cut_anchor, b_user->pw_uid));
            qihse_ct1_authority_store_t *cut_store = NULL;
            qihse_ct1_authority_challenge_t issued;
            assert(!qihse_ct1_authority_store_open_strict(cut_ledger, cut_anchor,
                b_user->pw_uid, &cut_store));
            assert(!qihse_ct1_authority_store_issue(cut_store, cut == 9 ? 1000 : 60000, &issued));
            m.epoch = issued.epoch; m.issued_ms = issued.issued_ms;
            m.expires_ms = issued.expires_ms;
            memcpy(m.nonce, issued.nonce, sizeof(m.nonce));
            e.challenge = &issued;
            assert(qihse_ct1_recovery_encode(&m, false, false, wire));
            pair_quote(sq, wire, &m, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
            pair_quote(tq, wire, &m, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
            assert(!qihse_ct1_authority_store_bind(cut_store, &issued, wire, sizeof(wire)));
            PAIR_OK();
            assert(qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
            denied(&e, sizeof(e));
            if (cut == 9) {
                struct timespec delay = {.tv_sec = 2};
                assert(!nanosleep(&delay, NULL));
                qihse_ct1_authority_store_close(cut_store);
                cut_store = NULL;
                assert(!qihse_ct1_authority_store_open_strict(cut_ledger, cut_anchor,
                    b_user->pw_uid, &cut_store));
                assert(!qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
                assert(!qihse_ct1_authority_service_check_and_retire_pair(cut_store, &e));
            } else {
                unsigned char old_cp[256], new_cp[256];
                int cp_fd = open(cp, O_RDWR);
                struct stat image;
                assert(cp_fd >= 0 && !fstat(cp_fd, &image) && image.st_size > 0 &&
                    image.st_size <= (off_t)sizeof(old_cp));
                assert(read(cp_fd, old_cp, (size_t)image.st_size) == image.st_size);
                assert(!close(cp_fd));
                /* Release the parent audit writer before a crash child exercises
                 * classified-roster authorization in its own process. */
                qihse_audit_shutdown();
                pid_t crashed = fork();
                assert(crashed >= 0);
                if (!crashed) {
                    qihse_audit_init();
                    char selected[] = "r0";
                    selected[1] = (char)('0' + cut);
                    if (setenv("QIHSE_CT1_TEST_CRASH_CUT", selected, 1)) _exit(70);
                    (void)qihse_ct1_authority_service_check_and_retire_pair(cut_store, &e);
                    _exit(70); /* The real pair retirement must reach this cut. */
                }
                int status;
                assert(waitpid(crashed, &status, 0) == crashed && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 90 + cut);
                qihse_audit_init();
                if (cut == 5 || cut == 6) {
                    qihse_ct1_authority_store_close(cut_store);
                    cut_store = NULL;
                    assert(!qihse_ct1_authority_store_open_strict(cut_ledger, cut_anchor,
                        b_user->pw_uid, &cut_store));
                    struct stat before, after;
                    assert(!qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
                    assert(!stat(log, &before));
                    assert(!qihse_ct1_authority_service_check_and_retire_pair(cut_store, &e));
                    assert(!stat(log, &after) && before.st_size == after.st_size);
                    cp_fd = open(cp, O_RDWR);
                    assert(cp_fd >= 0 && read(cp_fd, new_cp, (size_t)image.st_size) == image.st_size);
                    assert(memcmp(old_cp, new_cp, (size_t)image.st_size));
                    if (cut == 6) new_cp[image.st_size - 1] ^= 1;
                    assert(pwrite(cp_fd, cut == 5 ? old_cp : new_cp,
                        (size_t)image.st_size, 0) == image.st_size && !fsync(cp_fd) && !close(cp_fd));
                }
                if (cut >= 1 && cut <= 6) {
                    struct stat before, after;
                    assert(!stat(log, &before));
                    assert(!qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
                    assert(!qihse_ct1_authority_service_check_and_retire_pair(cut_store, &e));
                    assert(!stat(log, &after) && before.st_size == after.st_size);
                    qihse_ct1_authority_store_close(cut_store);
                    cut_store = NULL;
                    assert(qihse_ct1_authority_store_open_strict(cut_ledger, cut_anchor,
                        b_user->pw_uid, &cut_store) == -1 && !cut_store);
                } else {
                    qihse_ct1_authority_store_close(cut_store);
                    cut_store = NULL;
                    assert(!qihse_ct1_authority_store_open_strict(cut_ledger, cut_anchor,
                        b_user->pw_uid, &cut_store));
                    if (cut == 0) {
                        assert(qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
                        assert(qihse_ct1_authority_service_check_and_retire_pair(cut_store, &e));
                    } else assert(!qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
                    struct stat before, after;
                    assert(!stat(log, &before));
                    assert(!qihse_ct1_authority_service_check_and_retire_pair(cut_store, &e));
                    assert(!stat(log, &after) && before.st_size == after.st_size);
                    assert(!qihse_ct1_authority_service_evaluate_pair_bound(cut_store, &e));
                }
            }
            denied(&e, sizeof(e));
            qihse_ct1_authority_store_close(cut_store);
            assert(!unlink(log));
            assert(snprintf(log, sizeof(log), "%s/authority.lock", cut_ledger) > 0);
            assert(!unlink(log) && !unlink(cp) && !rmdir(cut_ledger) && !rmdir(cut_anchor));
        }
        challenge = original;
        m.epoch = challenge.epoch; m.issued_ms = challenge.issued_ms;
        m.expires_ms = challenge.expires_ms;
        memcpy(m.nonce, challenge.nonce, sizeof(m.nonce));
        e.challenge = &challenge;
        assert(qihse_ct1_recovery_encode(&m, false, false, wire));
        pair_quote(sq, wire, &m, QIHSE_CT1_NODE_QUOTE_SOURCE, source_pin, source_priv);
        pair_quote(tq, wire, &m, QIHSE_CT1_NODE_QUOTE_TARGET, target_pin, target_priv);
        BOUND_OK();
        denied(&e, sizeof(e));
        assert(qihse_ct1_authority_service_check_and_retire_pair(store, &e));
        BOUND_DENIED(); /* Reusing exact signed copies cannot revive retirement. */
        assert(!qihse_ct1_authority_service_check_and_retire_pair(store, &e));
        assert(qihse_ct1_authority_store_retire_bound(store, &challenge, wire, sizeof(wire)) == -1);
        denied(&e, sizeof(e));
        qihse_ct1_authority_store_close(store);
        store = NULL;
        pid_t restarted = fork();
        assert(restarted >= 0);
        if (!restarted) {
            struct passwd *b_user = getpwnam("nobody");
            qihse_ct1_authority_store_t *reopened = NULL;
            if (!b_user || qihse_ct1_authority_store_open_strict(ledger, checkpoint,
                    b_user->pw_uid, &reopened)) _exit(2);
            int spent = qihse_ct1_authority_store_check_bound(reopened, &challenge,
                wire, sizeof(wire)) == -1 &&
                !qihse_ct1_authority_service_check_and_retire_pair(reopened, &e);
            qihse_ct1_authority_store_close(reopened);
            _exit(spent ? 0 : 3);
        }
        int restart_status;
        assert(waitpid(restarted, &restart_status, 0) == restarted &&
            WIFEXITED(restart_status) && WEXITSTATUS(restart_status) == 0);
    }
    for (size_t role = 0; role < 2; ++role) {
        const char *root = role ? dst : src;
        const char *const *names = role ? pair_target_names : pair_source_names;
        size_t count = role ? 7 : 8;
        for (size_t i = 0; i < count; ++i) {
            assert(snprintf(path, sizeof(path), "%s/%s", root, names[i]) > 0);
            assert(!unlink(path));
        }
        assert(!rmdir(root));
    }
    assert(!unlink(source_priv) && !unlink(source_pub) &&
        !unlink(target_priv) && !unlink(target_pub));
    if (geteuid() == 0) {
        assert(snprintf(path, sizeof(path), "%s/authority.log", ledger) > 0);
        assert(!unlink(path));
        assert(snprintf(path, sizeof(path), "%s/authority.lock", ledger) > 0);
        assert(!unlink(path));
        assert(snprintf(path, sizeof(path), "%s/authority.checkpoint", checkpoint) > 0);
        assert(!unlink(path) && !rmdir(ledger) && !rmdir(checkpoint));
    }
    assert(!rmdir(dir));
#undef PAIR_OK
#undef PAIR_DENIED
#undef BOUND_OK
#undef BOUND_DENIED
    puts("CT1 host evidence: signed paired stale B-like quotes, 15 frozen files and denials passed");
}

static int remove_qkp_fixture(const char *path, const struct stat *st,
    int kind, struct FTW *walk)
{
    (void)st; (void)kind; (void)walk;
    return remove(path);
}

/* Exercise the real sealed QKP/RESP boundary. A replication-only peer maps to
 * a live low-clearance principal; the same command must never disclose high
 * data or produce a quote, irrespective of bytes supplied as B and nonce. */
static void low_clearance_qkp_denied(void)
{
    char root[] = "./ct1-qkp-low-XXXXXX";
    char server_dir[128], admin_dir[128], low_dir[128], data_dir[128];
    char server_pub[160], server_dsa[160], server_kem[160], server_kem_pub[160];
    char admin_pub[160], low_pub[160];
    assert(mkdtemp(root));
#define QKP_PATH(dst, base, name) \
    assert(snprintf(dst, sizeof(dst), "%s/%s", base, name) > 0)
    QKP_PATH(server_dir, root, "server");
    QKP_PATH(admin_dir, root, "admin");
    QKP_PATH(low_dir, root, "low");
    QKP_PATH(data_dir, root, "data");
    assert(!mkdir(server_dir, 0700) && !mkdir(admin_dir, 0700) &&
        !mkdir(low_dir, 0700) && !mkdir(data_dir, 0700));
    assert(!setenv("QIHSE_DATA_DIR", data_dir, 1));
    assert(qihse_pqc_init_providers() >= 0 &&
        qihse_pqc_keygen(server_dir) && qihse_pqc_keygen(admin_dir) &&
        qihse_pqc_keygen(low_dir));
    QKP_PATH(server_pub, server_dir, "qihse_dsa_pub.pem");
    QKP_PATH(server_dsa, server_dir, "qihse_dsa_key.pem");
    QKP_PATH(server_kem, server_dir, "qihse_kem_key.pem");
    QKP_PATH(server_kem_pub, server_dir, "qihse_kem_pub.pem");
    QKP_PATH(admin_pub, admin_dir, "qihse_dsa_pub.pem");
    QKP_PATH(low_pub, low_dir, "qihse_dsa_pub.pem");
    qihse_user_t *operator = qihse_auth_get_user(0);
    qihse_user_t *low = qihse_auth_get_user(8303);
    assert(operator && low);
    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv && qihse_kv_set_user(kv, "admin-test:secret", "CT1-HIGH-SECRET", 5u, 9u, operator));
    const char *trusted[] = {admin_pub, low_pub};
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = kv;
    config.port = 0;
    config.auth_required = true;
    config.pqc.require = true;
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 2;
    config.pqc.dsa_key_path = server_dsa;
    config.pqc.kem_key_path = server_kem;
    config.pqc.kem_pub_path = server_kem_pub;
    config.pqc.node_id = "ct1-test-server";
    config.pqc.admin_peer_node_id = "ct1-test-admin";
    config.pqc.admin_peer_dsa_pub_path = admin_pub;
    config.pqc.replication_peer_node_id = "ct1-test-low";
    config.pqc.replication_peer_dsa_pub_path = low_pub;
    config.replication_service_principal = low;
    qihse_resp_server_t *server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    qihse_qkp_admin_client_t *client = NULL;
    char error[256], *reply = NULL;
    size_t reply_len = 0;
    assert(qihse_qkp_admin_open_strict_peer("127.0.0.1",
        qihse_resp_server_port(server), "ct1-test-low", low_dir, server_pub,
        "ct1-test-server", server_pub, 30000u, &client, error, sizeof(error)) == 0);
    const char *get[] = {"GET", "admin-test:secret"};
    assert(!qihse_qkp_admin_command(client, 2, get, NULL, &reply,
        &reply_len, error, sizeof(error)));
    assert(reply && !memmem(reply, reply_len, "CT1-HIGH-SECRET", 16));
    qihse_qkp_admin_free(reply);
    unsigned char nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE] = {0};
    unsigned char manifest[QIHSE_CT1_RECOVERY_WIRE_SIZE] = {0};
    const char *quote[] = {"REPL.CT1", "SOURCE", "QUOTE-V2",
        (const char *)nonce, (const char *)manifest};
    size_t lengths[] = {8, 6, 8, sizeof(nonce), sizeof(manifest)};
    reply = NULL;
    assert(!qihse_qkp_admin_command(client, 5, quote, lengths, &reply,
        &reply_len, error, sizeof(error)));
    assert(reply && reply[0] == '-' && reply_len < QIHSE_CT1_NODE_QUOTE_SIZE &&
        !memmem(reply, reply_len, "CT1-HIGH-SECRET", 16));
    qihse_qkp_admin_free(reply);
    quote[1] = "TARGET";
    reply = NULL;
    assert(!qihse_qkp_admin_command(client, 5, quote, lengths, &reply,
        &reply_len, error, sizeof(error)));
    assert(reply && reply[0] == '-' && reply_len < QIHSE_CT1_NODE_QUOTE_SIZE &&
        !memmem(reply, reply_len, "CT1-HIGH-SECRET", 16));
    qihse_qkp_admin_free(reply);
    qihse_qkp_admin_close(client);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);
    assert(!nftw(root, remove_qkp_fixture, 16, FTW_DEPTH | FTW_PHYS));
    assert(!unsetenv("QIHSE_DATA_DIR"));
#undef QKP_PATH
    puts("CT1 QKP low-clearance: protected GET and SOURCE/TARGET QUOTE-V2 denied");
}

int main(void)
{
    signed_grant_verifier();
    paired_frozen_evidence();
    low_clearance_qkp_denied();
    forged_session_and_user_flags();
    arbitrary_grants_and_replays();
    development_witness_and_receipt_bypass();
    missing_independent_anchor();
    strict_checkpoint_is_not_approval();
    puts("CT1 authority service: signed verification passed; issuance and consumption disabled");
    return 0;
}
