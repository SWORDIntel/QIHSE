#include "qihse_ct1_host_admission.h"
#include "qihse_ct1_receiver_writer.h"
#include "qihse_ct1_disposition.h"
#include "qihse_ct1_authority_store.h"
#include "qihse_ct1_node_quote.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_auth.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_kv_store.h"
#include "core/qihse_audit.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void ct1_receiver_preflight_cases(const char *dir, qihse_user_t *service,
    qihse_user_t *low, const qihse_ct1_recovery_manifest_t *manifest);
void ct1_receiver_fresh_cases(const char *parent, const char *source,
    qihse_user_t *service, qihse_user_t *low,
    const qihse_ct1_recovery_manifest_t *manifest);

/* Keep generated PEM filenames (and all key material) out of fixture output. */
static int quiet_keygen(const char *dir)
{
    fflush(stdout);
    fflush(stderr);
    int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int out = dup(STDOUT_FILENO), err = dup(STDERR_FILENO);
    assert(nullfd >= 0 && out >= 0 && err >= 0);
    assert(dup2(nullfd, STDOUT_FILENO) >= 0 && dup2(nullfd, STDERR_FILENO) >= 0);
    int ok = qihse_pqc_keygen(dir);
    fflush(stdout);
    fflush(stderr);
    assert(dup2(out, STDOUT_FILENO) >= 0 && dup2(err, STDERR_FILENO) >= 0);
    close(out);
    close(err);
    close(nullfd);
    return ok;
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(path);
}

static void subdir(const char *base, const char *name, char *out, size_t cap)
{
    assert(snprintf(out, cap, "%s/%s", base, name) < (int)cap);
    assert(mkdir(out, 0700) == 0);
}

static void label(const char *dir, const char *id)
{
    char path[512];
    assert(snprintf(path, sizeof(path), "%s/node.id", dir) < (int)sizeof(path));
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(write(fd, id, strlen(id)) == (ssize_t)strlen(id));
    assert(close(fd) == 0);
}

static void copy_pub(const char *from, const char *to)
{
    int a = open(from, O_RDONLY | O_CLOEXEC);
    int b = open(to, O_WRONLY | O_TRUNC | O_CLOEXEC);
    assert(a >= 0 && b >= 0);
    char buf[8192];
    ssize_t n = read(a, buf, sizeof(buf));
    assert(n > 0 && write(b, buf, (size_t)n) == n);
    assert(close(a) == 0 && close(b) == 0);
}

static void copy_pub_new(const char *from, const char *to)
{
    int fd = open(to, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
    assert(fd >= 0 && fchmod(fd, 0644) == 0 && close(fd) == 0);
    copy_pub(from, to);
}

static void configure_uids(const char *path, unsigned operator_uid, unsigned b_uid)
{
    char text[96];
    int n = snprintf(text, sizeof(text), "operator_uid=%u\nb_uid=%u\n",
                     operator_uid, b_uid);
    assert(n > 0 && n < (int)sizeof(text));
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, text, (size_t)n) == n && close(fd) == 0);
}

static void give_client_key(const char *dir, uid_t uid)
{
    char key[512];
    assert(snprintf(key, sizeof(key), "%s/qihse_dsa_key.pem", dir) < (int)sizeof(key));
    assert(chown(key, uid, uid) == 0 && chown(dir, uid, uid) == 0);
}

static uint64_t decode_u64_be(const unsigned char *wire);
static unsigned char template_wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
static unsigned char original_frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
static int archive_frame_bad;

static void frame_put32(unsigned char *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(value >> (24 - 8*i));
}
static void frame_put64(unsigned char *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(value >> (56 - 8*i));
}
static void provision_original(void)
{
    unsigned char *frame = original_frame;
    memset(frame, 0, sizeof(original_frame));
    memcpy(frame, "QKV6CT01", 8);
    frame[8] = 1;
    frame[9] = 1;
    frame_put32(frame + 12, sizeof(original_frame));
    const char *source = "source", *generation = "generation-1";
    const char *key = "t:42/tenant-key-11";
    size_t source_len = strlen(source), gen_len = strlen(generation), key_len = strlen(key);
    size_t body = sizeof(original_frame) - 96 - source_len - gen_len - 48;
    frame_put32(frame + 16, 48);
    frame_put32(frame + 20, (uint32_t)body);
    frame_put32(frame + 24, 1);
    frame_put32(frame + 28, 42);
    frame_put64(frame + 32, 11111);
    frame_put64(frame + 40, 5729448);
    frame_put64(frame + 48, 5729448);
    frame[56] = (unsigned char)source_len;
    frame[57] = (unsigned char)gen_len;
    memcpy(frame + 96, source, source_len);
    memcpy(frame + 96 + source_len, generation, gen_len);
    unsigned char *row = frame + 96 + source_len + gen_len;
    frame_put32(row + 4, 42);
    frame_put32(row + 8, 42);
    row[13] = 4;
    row[15] = 2;
    row[16] = 1;
    frame_put64(row + 20, 5729448);
    frame_put32(row + 36, (uint32_t)key_len);
    frame_put32(row + 40, (uint32_t)(body - key_len));
    memcpy(row + 48, key, key_len);
    for (size_t i = key_len; i < body; ++i) row[48 + i] = (unsigned char)('A' + i % 26);
    assert(SHA256(frame, sizeof(original_frame), frame + 64));
}
static const char *const source_names[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_4.db", "sstable_5.db", "wal.log"};
static const char *const target_names[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_6.db", "sstable_7.db", "wal.log"};
static const char *const native_source_names[] = {"ct-baseline.qfs", "ct-state.bin",
    "restore-highwater.bin", "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_0.db", "sstable_1.db", "wal.log"};
static const char *const native_target_names[] = {"ct-state.bin", "restore-highwater.bin",
    "slot-ownership.journal", "slot-ownership.journal.lock",
    "sstable_0.db", "sstable_1.db", "wal.log"};
static struct {
    int enabled;
    char base[512];
    qihse_ct1_recovery_file_t source[8], target[7];
    unsigned char baseline[32];
    uint64_t baseline_seq, tombstone_seq, target_high, source_high, source_row_seq;
} native;

static void pub_pin(const char *path, unsigned char pin[32])
{
    FILE *file = fopen(path, "rb");
    assert(file);
    EVP_PKEY *key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    assert(fclose(file) == 0 && key);
    int len = i2d_PUBKEY(key, NULL);
    assert(len > 0 && len <= 8192);
    unsigned char *der = OPENSSL_malloc((size_t)len), *cursor = der;
    assert(der && i2d_PUBKEY(key, &cursor) == len && SHA256(der, (size_t)len, pin));
    OPENSSL_clear_free(der, (size_t)len);
    EVP_PKEY_free(key);
}

static void frozen_files(const char *dir, qihse_ct1_recovery_file_t *files,
                         const char *const *names, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        qihse_ct1_recovery_file_t *f = &files[i];
        if (native.enabled) {
            const qihse_ct1_recovery_file_t *pinned = count == 8 ?
                &native.source[i] : &native.target[i];
            char path[512];
            assert(snprintf(path, sizeof(path), "%s/%s", dir, pinned->filename) <
                (int)sizeof(path));
            int dest = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
            assert(dest >= 0);
            assert(snprintf(path, sizeof(path), "%s/%s/%s", native.base,
                count == 8 ? "native-source" : "native-target-0", pinned->filename) <
                (int)sizeof(path));
            int src = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            struct stat st;
            assert(src >= 0 && !fstat(src, &st) && S_ISREG(st.st_mode) &&
                st.st_uid == 0 && st.st_nlink == 1 && !(st.st_mode & 077) &&
                st.st_size >= 0 && (uint64_t)st.st_size == pinned->size);
            EVP_MD_CTX *hash = EVP_MD_CTX_new();
            assert(hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
            unsigned char buf[4096], digest[32];
            uint64_t copied = 0;
            ssize_t n;
            while ((n = read(src, buf, sizeof(buf))) > 0) {
                assert(EVP_DigestUpdate(hash, buf, (size_t)n) == 1 &&
                    write(dest, buf, (size_t)n) == n);
                copied += (uint64_t)n;
            }
            unsigned len;
            assert(n == 0 && copied == pinned->size &&
                EVP_DigestFinal_ex(hash, digest, &len) == 1 && len == 32 &&
                !memcmp(digest, pinned->sha256, 32) && !close(src) &&
                !fchmod(dest, 0400) && !fsync(dest) && !close(dest));
            EVP_MD_CTX_free(hash);
            *f = *pinned;
            continue;
        }
        strcpy(f->filename, names[i]);
        f->kind = !strcmp(names[i], "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(names[i], "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(names[i], "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(names[i], "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(names[i], "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(names[i], "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        char path[512];
        assert(snprintf(path, sizeof(path), "%s/%s", dir, names[i]) < (int)sizeof(path));
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        assert(fd >= 0);
        unsigned char contents[16];
        memset(contents, (int)(i + 1 + (count == 7 ? 32 : 0)), sizeof(contents));
        f->size = f->kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 :
            f->kind == QIHSE_CT1_FILE_WAL && count == 8 ?
            sizeof(original_frame) : sizeof(contents);
        const unsigned char *bytes = f->size == sizeof(original_frame) ?
            original_frame : contents;
        assert(!f->size || write(fd, bytes, (size_t)f->size) == (ssize_t)f->size);
        assert(SHA256(bytes, (size_t)f->size, f->sha256));
        assert(fchmod(fd, 0400) == 0 && close(fd) == 0);
    }
}

static void provision_b(const char *root, const char *operator_pub,
                        const char *source_pub, const char *target_pub,
                        char source_frozen[512], char target_frozen[512], char path[512])
{
    subdir(root, "frozen-source", source_frozen, 512);
    subdir(root, "frozen-target", target_frozen, 512);
    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "configured-operator");
    strcpy(m.source_qkp_id, native.enabled ? "source:fixture" : "source");
    strcpy(m.target_qkp_id, native.enabled ? "target:fixture" : "target");
    strcpy(m.source_store_id, m.source_qkp_id);
    strcpy(m.target_store_id, m.target_qkp_id);
    strcpy(m.source_peer_qkp_id, m.target_qkp_id);
    strcpy(m.target_peer_qkp_id, m.source_qkp_id);
    strcpy(m.replication_principal_id, "8302");
    strcpy(m.generation, native.enabled ? "gen:fixture" : "generation-1");
    strcpy(m.row_key, native.enabled ? "fixture-key" : "tenant-key-11");
    pub_pin(operator_pub, m.issuer_operator_pin);
    pub_pin(target_pub, m.source_peer_pin);
    pub_pin(source_pub, m.target_peer_pin);
    frozen_files(source_frozen, m.source_files, source_names, 8);
    frozen_files(target_frozen, m.target_files, target_names, 7);
    memcpy(m.baseline_sha256, native.enabled ? native.baseline : m.source_files[0].sha256, 32);
    assert(SHA256(original_frame, sizeof(original_frame), m.frame_sha256));
    memset(m.nonce, 3, 32);
    m.epoch = 1; m.issued_ms = 1000; m.expires_ms = 2000;
    m.frame_offset = 0; m.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m.frame_position = 11111; m.baseline_row_seq = 17;
    m.target_cursor = 11110; m.target_high_water = 5729457;
    m.source_high_water = 5729448; m.row_change_seq = 5729448;
    m.tombstone_position = 11103; m.tombstone_row_seq = 5729450;
    m.row_tenant_id = native.enabled ? 0 : 42; m.classification = 4; m.sci = 2;
    m.principal_classification = UINT16_MAX; m.principal_sci = UINT16_MAX;
    if (native.enabled) {
        m.frame_position = 8;
        m.baseline_row_seq = native.baseline_seq;
        m.target_cursor = 7;
        m.target_high_water = native.target_high;
        m.source_high_water = native.source_high;
        m.row_change_seq = native.source_row_seq;
        m.tombstone_position = 3;
        m.tombstone_row_seq = native.tombstone_seq;
    }
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    assert(qihse_ct1_recovery_encode(&m, false, false, template_wire));
    assert(snprintf(path, 512, "%s/expected-b.bin", root) < 512);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, template_wire, sizeof(template_wire)) == (ssize_t)sizeof(template_wire) &&
           fchmod(fd, 0400) == 0 && close(fd) == 0);
}

static void challenge_b(const unsigned char *wire, unsigned char out[QIHSE_CT1_RECOVERY_WIRE_SIZE])
{
    qihse_ct1_recovery_manifest_t m;
    assert(qihse_ct1_recovery_decode(template_wire, sizeof(template_wire), false, &m, NULL));
    m.epoch = decode_u64_be(wire);
    m.issued_ms = decode_u64_be(wire + 8);
    m.expires_ms = decode_u64_be(wire + 16);
    memcpy(m.nonce, wire + 24, 32);
    assert(qihse_ct1_recovery_encode(&m, false, false, out));
}

static int connect_local(const char *socket_dir)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    assert(snprintf(a.sun_path, sizeof(a.sun_path), "%s/admission.sock", socket_dir) <
           (int)sizeof(a.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) return fd;
    close(fd);
    return -1;
}

enum request_mode {
    REQUEST_VALID, REQUEST_CAPTURE, REQUEST_NONE, REQUEST_WRONG,
    REQUEST_SHORT, REQUEST_LONG, REQUEST_PLAINTEXT, REQUEST_IDLE,
    REQUEST_TIMEOUT, REQUEST_WRONG_SEQ, REQUEST_REPLAY, REQUEST_RAW,
    REQUEST_TRUNC_FRAME, REQUEST_FD_HANDOFF, REQUEST_FD_HANDOFF_SPLIT,
    ACK_NONE, ACK_TIMEOUT, ACK_WRONG, ACK_REPLAY, ACK_SHORT, ACK_LONG,
    ACK_PARTIAL, ACK_FD_HANDOFF, ACK_FD_HANDOFF_SPLIT,
    B_NONE, B_SHORT, B_LONG, B_MALFORMED, B_WRONG_ROLE,
    B_WRONG_PRINCIPAL, B_WRONG_PIN, B_WRONG_ROSTER,
    B_FORGED_CHALLENGE, B_REPLAY, B_FD_HANDOFF, B_FD_HANDOFF_SPLIT,
    Q_NONE, Q_SWAP, Q_FORGED, Q_FORGED_TARGET, Q_REPLAY, Q_WRONG_B,
    Q_WRONG_ROSTER, Q_EXPIRED, Q_SHORT, Q_LONG,
    Q_FD_HANDOFF, Q_FD_HANDOFF_SPLIT, Q_TARGET_FD_HANDOFF, Q_INTERRUPTED,
    INT_NONE, INT_WRONG_B, INT_STALE_B, INT_WRONG_NONCE, INT_WRONG_EPOCH,
    INT_SHORT, INT_LONG, INT_REPLAY, INT_ACK, INT_ADMIT, INT_PARTIAL,
    INT_FD_HANDOFF, INT_FD_HANDOFF_SPLIT
};

static unsigned char captured_frame[128];
static size_t captured_len;
static int executor_mode;
static unsigned char captured_challenge[QIHSE_CT1_HOST_CHALLENGE_BYTES];
static unsigned char captured_b[QIHSE_CT1_RECOVERY_WIRE_SIZE];

static void pipe_exact(int fd, void *buf, size_t len, int sending)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = sending ? write(fd, (unsigned char *)buf + done, len - done) :
            read(fd, (unsigned char *)buf + done, len - done);
        assert(n > 0);
        done += (size_t)n;
    }
}

/* Separate root signer child owns the already-generated source/target keys;
 * the Operator UID never receives a key or a private root-directory handle. */
static void fixture_signer(int request_fd, int response_fd, const char *root)
{
    unsigned char b[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    unsigned char quote[QIHSE_CT1_NODE_QUOTE_SIZE];
    qihse_ct1_recovery_manifest_t m, trusted;
    qihse_ct1_node_quote_expected_t e = {0};
    char source_pub[512], target_pub[512], key[512];
    pipe_exact(request_fd, b, sizeof(b), 0);
    assert(qihse_ct1_recovery_decode(b, sizeof(b), false, &m, NULL));
    assert(qihse_ct1_recovery_decode(template_wire, sizeof(template_wire), false, &trusted, NULL));
    strcpy(e.source_qkp_id, trusted.source_qkp_id);
    strcpy(e.target_qkp_id, trusted.target_qkp_id);
    strcpy(e.source_peer_qkp_id, trusted.source_peer_qkp_id);
    strcpy(e.target_peer_qkp_id, trusted.target_peer_qkp_id);
    strcpy(e.replication_principal_id, trusted.replication_principal_id);
    strcpy(e.generation, trusted.generation);
    memcpy(e.source_peer_pin, trusted.source_peer_pin, 32);
    memcpy(e.target_peer_pin, trusted.target_peer_pin, 32);
    memcpy(e.baseline_sha256, trusted.baseline_sha256, 32);
    e.target_cursor = trusted.target_cursor;
    e.source_high_water = trusted.source_high_water;
    e.target_high_water = trusted.target_high_water;
    assert(snprintf(source_pub, sizeof(source_pub), "%s/source/qihse_dsa_pub.pem", root) < (int)sizeof(source_pub));
    assert(snprintf(target_pub, sizeof(target_pub), "%s/target/qihse_dsa_pub.pem", root) < (int)sizeof(target_pub));
    pub_pin(source_pub, e.source_signer_pin);
    pub_pin(target_pub, e.target_signer_pin);
    struct timespec now;
    assert(clock_gettime(CLOCK_REALTIME, &now) == 0);
    /* The expired fixture signs at its historical issued time; verification
     * still sees the current host clock and must reject the stale B binding. */
    if (executor_mode >= 2) {
        /* The archive fixture signs only after its frozen source WAL roster
         * and frame digest match the original, not a digest stub. */
        char wal[512];
        unsigned char digest[32], frame[sizeof(original_frame)];
        assert(snprintf(wal, sizeof(wal), "%s/frozen-source/wal.log", root) <
            (int)sizeof(wal));
        int fd = open(wal, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        assert(fd >= 0 && m.frame_offset == 0 &&
            m.frame_length == sizeof(original_frame) &&
            read(fd, frame, sizeof(frame)) == sizeof(frame) && close(fd) == 0 &&
            !memcmp(frame, original_frame, sizeof(frame)) &&
            SHA256(frame, sizeof(frame), digest) &&
            !memcmp(digest, m.frame_sha256, sizeof(digest)));
    }
    qihse_ct1_node_quote_signing_evidence_t sign = {
        .manifest_wire = b, .manifest_len = sizeof(b), .verified_manifest = &m,
        .expected = &e, .now_ms = m.expires_ms <= (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 ?
            m.issued_ms : (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000,
        .host_nonce = m.nonce
    };
    for (unsigned role = QIHSE_CT1_NODE_QUOTE_SOURCE; role <= QIHSE_CT1_NODE_QUOTE_TARGET; ++role) {
        sign.role = role;
        sign.own_public_key_path = role == QIHSE_CT1_NODE_QUOTE_SOURCE ? source_pub : target_pub;
        assert(snprintf(key, sizeof(key), "%s/%s/qihse_dsa_key.pem", root,
            role == QIHSE_CT1_NODE_QUOTE_SOURCE ? "source" : "target") < (int)sizeof(key));
        sign.own_private_key_path = key;
        assert(qihse_ct1_node_quote_sign_verified(&sign, quote));
        assert(qihse_ct1_node_quote_verify_strict(quote, sizeof(quote), b,
            sizeof(b), role, m.nonce, sign.own_public_key_path, &e));
        pipe_exact(response_fd, quote, sizeof(quote), 1);
    }
}

static uint64_t decode_u64_be(const unsigned char *wire)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8) | wire[i];
    return value;
}

/* Administrative provisioning is separate from admission runtime. */
static void provision_store(const char *base, unsigned serial, char ledger[512],
                            char checkpoint[512])
{
    char name[48];
    assert(snprintf(name, sizeof(name), "ledger-%u", serial) < (int)sizeof(name));
    subdir(base, name, ledger, 512);
    assert(snprintf(name, sizeof(name), "checkpoint-%u", serial) < (int)sizeof(name));
    subdir(base, name, checkpoint, 512);
    assert(qihse_ct1_authority_store_initialize_strict(ledger, checkpoint, 65534) == 0);
}

static qihse_ct1_host_admission_t *fresh_store(qihse_ct1_host_admission_t *h,
    const char *base, const char *root, const char *socket_dir, unsigned *serial,
    char ledger[512], char checkpoint[512])
{
    qihse_ct1_host_admission_close(h);
    provision_store(base, ++*serial, ledger, checkpoint);
    h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
    assert(h);
    return h;
}

static void handoff_sealed(qihse_qkp_session_t *session, int fd, int handoff_fd,
                           const void *payload, size_t len, int split)
{
    int raw[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, raw) == 0);
    assert(qihse_qkp_send_sealed(session, raw[1], payload, len));
    close(raw[1]);
    unsigned char frame[6 + QIHSE_QKP_MAX_FRAME];
    size_t done = 0;
    while (done < 6) {
        ssize_t n = read(raw[0], frame + done, 6 - done);
        assert(n > 0);
        done += (size_t)n;
    }
    size_t total = 6 + ((size_t)frame[4] << 8) + frame[5];
    assert(total <= sizeof(frame));
    while (done < total) {
        ssize_t n = read(raw[0], frame + done, total - done);
        assert(n > 0);
        done += (size_t)n;
    }
    close(raw[0]);
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = frame, .iov_len = total};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    assert(cmsg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    if (split) assert(send(fd, frame, 6, 0) == 6);
    assert(sendmsg(handoff_fd, &msg, 0) == (ssize_t)total);
}

/* Child owns only its own key directory; parent alone handles the root listener. */
static void attempt(const char *socket_dir, const char *root,
                    qihse_ct1_host_admission_t *host, const char *client_dir,
                    const char *id, const char *trusted_pub, uid_t uid,
                    enum request_mode mode, qihse_ct1_host_admission_result_t expected)
{
    int report[2] = {-1, -1}, nonce_report[2] = {-1, -1};
    int keepalive[2] = {-1, -1};
    if (executor_mode) assert(pipe(keepalive) == 0);
    if (mode == REQUEST_CAPTURE) {
        assert(pipe(report) == 0);
        assert(pipe(nonce_report) == 0);
    }
    struct timespec start, finish;
    if (mode == REQUEST_IDLE || mode == REQUEST_TIMEOUT || mode == ACK_TIMEOUT)
        assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        if (keepalive[1] >= 0) close(keepalive[1]);
        if (report[0] >= 0) close(report[0]);
        if (nonce_report[0] >= 0) close(nonce_report[0]);
        int handoff[2] = {-1, -1};
        pid_t b = -1;
        if (mode == REQUEST_FD_HANDOFF || mode == REQUEST_FD_HANDOFF_SPLIT ||
            mode == ACK_FD_HANDOFF || mode == ACK_FD_HANDOFF_SPLIT ||
            mode == B_FD_HANDOFF || mode == B_FD_HANDOFF_SPLIT ||
            mode == Q_FD_HANDOFF || mode == Q_FD_HANDOFF_SPLIT ||
            mode == Q_TARGET_FD_HANDOFF || mode == INT_FD_HANDOFF ||
            mode == INT_FD_HANDOFF_SPLIT) {
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, handoff) == 0);
            b = fork();
            assert(b >= 0);
            if (b == 0) {
                close(handoff[0]);
                assert(setgid(65534) == 0 && setuid(65534) == 0);
                char copied_key[512];
                assert(snprintf(copied_key, sizeof(copied_key),
                                "%s/../b-client/qihse_dsa_key.pem", socket_dir) <
                       (int)sizeof(copied_key));
                int keyfd = open(copied_key, O_RDONLY | O_CLOEXEC);
                char key_byte;
                assert(keyfd >= 0 && read(keyfd, &key_byte, 1) == 1 && close(keyfd) == 0);
                unsigned char frame[6 + QIHSE_QKP_MAX_FRAME];
                char control[CMSG_SPACE(sizeof(int))];
                struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
                struct msghdr msg = {0};
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control;
                msg.msg_controllen = sizeof(control);
                ssize_t n = recvmsg(handoff[1], &msg, 0);
                assert(n >= 6 && !(msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)));
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                assert(cmsg && cmsg->cmsg_level == SOL_SOCKET &&
                       cmsg->cmsg_type == SCM_RIGHTS &&
                       cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                int passed;
                memcpy(&passed, CMSG_DATA(cmsg), sizeof(passed));
                size_t total = 6 + ((size_t)frame[4] << 8) + frame[5];
                assert(total <= sizeof(frame));
                size_t done = (size_t)n;
                while (done < total) {
                    n = read(handoff[1], frame + done, total - done);
                    assert(n > 0);
                    done += (size_t)n;
                }
                size_t offset = (mode == REQUEST_FD_HANDOFF_SPLIT ||
                                 mode == ACK_FD_HANDOFF_SPLIT ||
                                 mode == B_FD_HANDOFF_SPLIT ||
                                 mode == INT_FD_HANDOFF_SPLIT) ? 6 : 0;
                assert(send(passed, frame + offset, total - offset, 0) ==
                       (ssize_t)(total - offset));
                close(passed);
                close(handoff[1]);
                _exit(0);
            }
            close(handoff[1]);
        }
        int sign_request[2] = {-1, -1}, sign_response[2] = {-1, -1};
        pid_t signer = -1;
        const char *crash_cut = getenv("QIHSE_CT1_EXECUTOR_CUT");
        if ((mode == REQUEST_VALID && expected == QIHSE_CT1_HOST_ADMITTED) ||
            (mode == REQUEST_CAPTURE && (!crash_cut || strcmp(crash_cut, "issue"))) ||
            mode >= Q_NONE) {
            assert(pipe(sign_request) == 0 && pipe(sign_response) == 0);
            signer = fork();
            assert(signer >= 0);
            if (signer == 0) {
                close(sign_request[1]); close(sign_response[0]);
                fixture_signer(sign_request[0], sign_response[1], root);
                _exit(0);
            }
            close(sign_request[0]); close(sign_response[1]);
        }
        if (uid) assert(setgid(uid) == 0 && setuid(uid) == 0);
        if (uid) {
            int private = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            assert(private == -1 && errno == EACCES);
            char host_key[512];
            assert(snprintf(host_key, sizeof(host_key), "%s/host/qihse_dsa_key.pem", root) <
                   (int)sizeof(host_key));
            private = open(host_key, O_RDONLY | O_CLOEXEC);
            assert(private == -1 && errno == EACCES);
        }
        int fd = connect_local(socket_dir);
        assert(fd >= 0);
        if (mode == REQUEST_IDLE) {
            char byte;
            assert(recv(fd, &byte, 1, 0) == 0);
        } else if (mode == REQUEST_PLAINTEXT) {
            assert(send(fd, "!", 1, 0) == 1);
        } else {
            char private_key[512];
            assert(snprintf(private_key, sizeof(private_key), "%s/qihse_dsa_key.pem", client_dir) <
                   (int)sizeof(private_key));
            const char *trusted[] = {trusted_pub};
            qihse_qkp_config_t config = {0};
            config.dsa_key_path = private_key;
            config.trusted_pubs = trusted;
            config.trusted_count = 1;
            config.node_id = id;
            config.require = true;
            qihse_qkp_session_t *session = NULL;
            if (qihse_qkp_client_negotiate(fd, &config, &session) == QIHSE_QKP_SECURE && session) {
                const char *request = QIHSE_CT1_HOST_ADMISSION_REQUEST_V1;
                size_t len = sizeof(QIHSE_CT1_HOST_ADMISSION_REQUEST_V1) - 1;
                if (mode == REQUEST_FD_HANDOFF || mode == REQUEST_FD_HANDOFF_SPLIT) {
                    handoff_sealed(session, fd, handoff[0], request, len,
                                   mode == REQUEST_FD_HANDOFF_SPLIT);
                    close(fd);
                    fd = -1;
                    close(handoff[0]);
                    int status;
                    assert(waitpid(b, &status, 0) == b && WIFEXITED(status) &&
                           WEXITSTATUS(status) == 0);
                } else if (mode == REQUEST_TIMEOUT) {
                    char byte;
                    assert(recv(fd, &byte, 1, 0) == 0);
                } else if (mode == REQUEST_RAW) {
                    assert(send(fd, request, len, 0) == (ssize_t)len);
                } else if (mode == REQUEST_TRUNC_FRAME) {
                    const unsigned char head[] = {'Q', 'S', 'E', '1', 0, 64, 0};
                    assert(send(fd, head, sizeof(head), 0) == (ssize_t)sizeof(head));
                } else if (mode == REQUEST_REPLAY) {
                    assert(captured_len && send(fd, captured_frame, captured_len, 0) == (ssize_t)captured_len);
                } else if (mode == REQUEST_CAPTURE) {
                    int raw[2];
                    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, raw) == 0);
                    assert(qihse_qkp_send_sealed(session, raw[1], request, len));
                    close(raw[1]);
                    unsigned char frame[sizeof(captured_frame)];
                    size_t done = 0;
                    while (done < 6) {
                        ssize_t n = read(raw[0], frame + done, 6 - done);
                        assert(n > 0);
                        done += (size_t)n;
                    }
                    size_t total = 6 + ((size_t)frame[4] << 8) + frame[5];
                    assert(total < sizeof(frame));
                    while (done < total) {
                        ssize_t n = read(raw[0], frame + done, total - done);
                        assert(n > 0);
                        done += (size_t)n;
                    }
                    close(raw[0]);
                    assert(write(report[1], frame, total) == (ssize_t)total);
                    assert(send(fd, frame, total, 0) == (ssize_t)total);
                } else if (mode == REQUEST_WRONG_SEQ) {
                    int raw[2];
                    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, raw) == 0);
                    assert(qihse_qkp_send_sealed(session, raw[1], request, len));
                    close(raw[0]); close(raw[1]);
                    assert(qihse_qkp_send_sealed(session, fd, request, len));
                } else if (mode != REQUEST_NONE) {
                    if (mode == REQUEST_WRONG) request = "CT1.HOST.ADMIT.V2";
                    if (mode == REQUEST_SHORT) --len;
                    if (mode == REQUEST_LONG) ++len;
                    if (mode == REQUEST_VALID && expected == QIHSE_CT1_HOST_DENIED)
                        (void)qihse_qkp_send_sealed(session, fd, request, len);
                    else
                        assert(qihse_qkp_send_sealed(session, fd, request, len));
                }
            }
            if (crash_cut && !strcmp(crash_cut, "issue")) _exit(0);
            if (session && (mode == REQUEST_VALID || mode == REQUEST_CAPTURE ||
                            mode == ACK_NONE || mode == ACK_TIMEOUT || mode == ACK_WRONG ||
                            mode == ACK_REPLAY || mode == ACK_SHORT || mode == ACK_LONG ||
                            mode == ACK_PARTIAL || mode == ACK_FD_HANDOFF ||
                            mode == ACK_FD_HANDOFF_SPLIT || mode >= B_NONE) &&
                !(mode == REQUEST_VALID && expected == QIHSE_CT1_HOST_DENIED)) {
                unsigned char challenge[sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1 +
                                        QIHSE_CT1_HOST_CHALLENGE_BYTES];
                ssize_t n = qihse_qkp_recv_sealed(session, fd, challenge, sizeof(challenge));
                assert(n == (ssize_t)sizeof(challenge));
                assert(!memcmp(challenge, QIHSE_CT1_HOST_CHALLENGE_V1,
                               sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1));
                const unsigned char *wire = challenge + sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1;
                uint64_t issued_ms = decode_u64_be(wire + 8);
                uint64_t expires_ms = decode_u64_be(wire + 16);
                struct timespec observed;
                assert(clock_gettime(CLOCK_REALTIME, &observed) == 0);
                uint64_t now_ms = (uint64_t)observed.tv_sec * 1000 +
                                  (uint64_t)observed.tv_nsec / 1000000;
                assert(decode_u64_be(wire) == 1 && issued_ms <= now_ms &&
                       now_ms < expires_ms && expires_ms - issued_ms <= 900000);
                unsigned char ack[sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1 +
                                  QIHSE_CT1_HOST_CHALLENGE_BYTES + 1];
                size_t ack_len = sizeof(ack) - 1;
                memcpy(ack, QIHSE_CT1_HOST_CHALLENGE_ACK_V1,
                       sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1);
                memcpy(ack + sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1,
                       challenge + sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1,
                       QIHSE_CT1_HOST_CHALLENGE_BYTES);
                if (mode == REQUEST_CAPTURE)
                    assert(write(nonce_report[1], ack + sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1,
                                 QIHSE_CT1_HOST_CHALLENGE_BYTES) == QIHSE_CT1_HOST_CHALLENGE_BYTES);
                if (mode == ACK_WRONG) ack[ack_len - 1] ^= 1;
                if (mode == ACK_REPLAY)
                    memcpy(ack + sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1,
                           captured_challenge, QIHSE_CT1_HOST_CHALLENGE_BYTES);
                if (mode == ACK_SHORT) --ack_len;
                if (mode == ACK_LONG) ack[ack_len++] = 0;
                if (mode == ACK_TIMEOUT) {
                    char byte;
                    assert(recv(fd, &byte, 1, 0) == 0);
                } else if (mode == ACK_FD_HANDOFF || mode == ACK_FD_HANDOFF_SPLIT) {
                    handoff_sealed(session, fd, handoff[0], ack, ack_len,
                                   mode == ACK_FD_HANDOFF_SPLIT);
                    close(handoff[0]);
                    int status;
                    assert(waitpid(b, &status, 0) == b && WIFEXITED(status) &&
                           WEXITSTATUS(status) == 0);
                } else if (mode == ACK_PARTIAL) {
                    int raw[2];
                    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, raw) == 0);
                    assert(qihse_qkp_send_sealed(session, raw[1], ack, ack_len));
                    unsigned char head[7];
                    size_t done = 0;
                    while (done < sizeof(head)) {
                        ssize_t got = read(raw[0], head + done, sizeof(head) - done);
                        assert(got > 0);
                        done += (size_t)got;
                    }
                    assert(send(fd, head, sizeof(head), 0) == (ssize_t)sizeof(head));
                    close(raw[0]); close(raw[1]);
                } else if (mode != ACK_NONE) {
                    assert(qihse_qkp_send_sealed(session, fd, ack, ack_len));
                    if (mode == REQUEST_VALID || mode == REQUEST_CAPTURE || mode >= B_NONE) {
                        unsigned char b_wire[QIHSE_CT1_RECOVERY_WIRE_SIZE + 1];
                        challenge_b(wire, b_wire);
                        size_t b_len = QIHSE_CT1_RECOVERY_WIRE_SIZE;
                        if (mode == B_WRONG_ROLE || mode == B_WRONG_PRINCIPAL ||
                            mode == B_WRONG_PIN || mode == B_WRONG_ROSTER ||
                            mode == B_FORGED_CHALLENGE) {
                            qihse_ct1_recovery_manifest_t wrong;
                            assert(qihse_ct1_recovery_decode(b_wire, b_len, false, &wrong, NULL));
                            if (mode == B_WRONG_ROLE) strcpy(wrong.source_qkp_id, "other-source");
                            if (mode == B_WRONG_PRINCIPAL) strcpy(wrong.replication_principal_id, "8303");
                            if (mode == B_WRONG_PIN) wrong.source_peer_pin[0] ^= 1;
                            if (mode == B_WRONG_ROSTER) wrong.target_files[0].sha256[0] ^= 1;
                            if (mode == B_FORGED_CHALLENGE) wrong.nonce[0] ^= 1;
                            assert(qihse_ct1_recovery_encode(&wrong, false, false, b_wire));
                        }
                        if (mode == B_REPLAY) {
                            assert(captured_b[0]);
                            memcpy(b_wire, captured_b, b_len);
                        }
                        if (mode == B_MALFORMED) b_wire[b_len - 1] ^= 1;
                        if (mode == B_SHORT) --b_len;
                        if (mode == B_LONG) b_wire[b_len++] = 0;
                        if (mode == REQUEST_CAPTURE) {
                            assert(write(nonce_report[1], b_wire, b_len) == (ssize_t)b_len);
                        }
                        if (mode == B_FD_HANDOFF || mode == B_FD_HANDOFF_SPLIT) {
                            handoff_sealed(session, fd, handoff[0], b_wire, b_len,
                                           mode == B_FD_HANDOFF_SPLIT);
                            close(handoff[0]);
                            int status;
                            assert(waitpid(b, &status, 0) == b && WIFEXITED(status) &&
                                   WEXITSTATUS(status) == 0);
                        } else if (mode != B_NONE)
                            assert(qihse_qkp_send_sealed(session, fd, b_wire, b_len));
                        if (signer > 0) {
                            unsigned char source_quote[QIHSE_CT1_NODE_QUOTE_SIZE];
                            unsigned char target_quote[QIHSE_CT1_NODE_QUOTE_SIZE];
                            /* Replay uses a previously bound B/nonce, not the current issue. */
                            unsigned char signed_b[QIHSE_CT1_RECOVERY_WIRE_SIZE];
                            memcpy(signed_b, mode == Q_REPLAY || mode == Q_EXPIRED ? captured_b : b_wire,
                                   sizeof(signed_b));
                            if (mode == Q_WRONG_B || mode == Q_WRONG_ROSTER || mode == Q_EXPIRED) {
                                qihse_ct1_recovery_manifest_t signed_manifest;
                                assert(qihse_ct1_recovery_decode(signed_b, sizeof(signed_b), false, &signed_manifest, NULL));
                                if (mode == Q_WRONG_B) signed_manifest.row_tenant_id++;
                                if (mode == Q_WRONG_ROSTER) signed_manifest.target_files[0].sha256[0] ^= 1;
                                if (mode == Q_EXPIRED) signed_manifest.expires_ms = signed_manifest.issued_ms + 1;
                                assert(qihse_ct1_recovery_encode(&signed_manifest, false, false, signed_b));
                            }
                            pipe_exact(sign_request[1], signed_b, sizeof(signed_b), 1);
                            pipe_exact(sign_response[0], source_quote, sizeof(source_quote), 0);
                            pipe_exact(sign_response[0], target_quote, sizeof(target_quote), 0);
                            if (mode == Q_FORGED) source_quote[QIHSE_CT1_NODE_QUOTE_SIZE - 1] ^= 1;
                            if (mode == Q_FORGED_TARGET) target_quote[QIHSE_CT1_NODE_QUOTE_SIZE - 1] ^= 1;
                            if (mode == Q_FD_HANDOFF || mode == Q_FD_HANDOFF_SPLIT) {
                                handoff_sealed(session, fd, handoff[0], source_quote, sizeof(source_quote),
                                               mode == Q_FD_HANDOFF_SPLIT);
                                close(handoff[0]);
                                int status;
                                assert(waitpid(b, &status, 0) == b && WIFEXITED(status) && WEXITSTATUS(status) == 0);
                            } else if (mode != Q_NONE) {
                                const unsigned char *first = mode == Q_SWAP ? target_quote : source_quote;
                                const unsigned char *second = mode == Q_SWAP ? source_quote : target_quote;
                                assert(qihse_qkp_send_sealed(session, fd, first,
                                    sizeof(source_quote) - (mode == Q_SHORT)));
                                if (mode == Q_TARGET_FD_HANDOFF) {
                                    handoff_sealed(session, fd, handoff[0], target_quote, sizeof(target_quote), 0);
                                    close(handoff[0]);
                                    int status;
                                    assert(waitpid(b, &status, 0) == b && WIFEXITED(status) && WEXITSTATUS(status) == 0);
                                } else if (mode != Q_INTERRUPTED) {
                                    unsigned char long_quote[QIHSE_CT1_NODE_QUOTE_SIZE + 1];
                                    memcpy(long_quote, second, sizeof(target_quote));
                                    long_quote[sizeof(target_quote)] = 0;
                                    assert(qihse_qkp_send_sealed(session, fd, long_quote,
                                        sizeof(target_quote) + (mode == Q_LONG)));
                                }
                            }
                            if (mode == REQUEST_VALID || mode == REQUEST_CAPTURE || mode >= INT_NONE) {
                                unsigned char intent[QIHSE_CT1_HOST_RECOVERY_INTENT_BYTES + 1];
                                size_t prefix = sizeof(QIHSE_CT1_HOST_RECOVERY_INTENT_V1) - 1;
                                size_t intent_len = sizeof(intent) - 1;
                                memcpy(intent, QIHSE_CT1_HOST_RECOVERY_INTENT_V1, prefix);
                                memcpy(intent + prefix, b_wire, QIHSE_CT1_RECOVERY_WIRE_SIZE);
                                memcpy(intent + prefix + QIHSE_CT1_RECOVERY_WIRE_SIZE,
                                       wire, QIHSE_CT1_HOST_CHALLENGE_BYTES);
                                if (mode == INT_WRONG_B) intent[prefix + 80] ^= 1;
                                if (mode == INT_STALE_B || mode == INT_REPLAY)
                                    memcpy(intent + prefix, captured_b, sizeof(captured_b));
                                if (mode == INT_WRONG_NONCE)
                                    intent[intent_len - 1] ^= 1;
                                if (mode == INT_WRONG_EPOCH)
                                    intent[prefix + QIHSE_CT1_RECOVERY_WIRE_SIZE] ^= 1;
                                if (mode == INT_REPLAY)
                                    memcpy(intent + prefix + QIHSE_CT1_RECOVERY_WIRE_SIZE,
                                           captured_challenge, sizeof(captured_challenge));
                                if (mode == INT_ACK)
                                    memcpy(intent, QIHSE_CT1_HOST_CHALLENGE_ACK_V1,
                                           sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1);
                                if (mode == INT_ADMIT)
                                    memcpy(intent, QIHSE_CT1_HOST_ADMISSION_REQUEST_V1,
                                           sizeof(QIHSE_CT1_HOST_ADMISSION_REQUEST_V1) - 1);
                                if (mode == INT_SHORT) --intent_len;
                                if (mode == INT_LONG) intent[intent_len++] = 0;
                                if (mode == INT_FD_HANDOFF || mode == INT_FD_HANDOFF_SPLIT) {
                                    handoff_sealed(session, fd, handoff[0], intent, intent_len,
                                                   mode == INT_FD_HANDOFF_SPLIT);
                                    close(handoff[0]);
                                    int status;
                                    assert(waitpid(b, &status, 0) == b && WIFEXITED(status) &&
                                           WEXITSTATUS(status) == 0);
                                } else if (mode == INT_PARTIAL) {
                                    int raw[2];
                                    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, raw) == 0);
                                    assert(qihse_qkp_send_sealed(session, raw[1], intent, intent_len));
                                    unsigned char head[7];
                                    pipe_exact(raw[0], head, sizeof(head), 0);
                                    assert(send(fd, head, sizeof(head), 0) == (ssize_t)sizeof(head));
                                    close(raw[0]); close(raw[1]);
                                } else if (mode != INT_NONE) {
                                    assert(qihse_qkp_send_sealed(session, fd, intent, intent_len));
                                    if (executor_mode == 2 && mode == REQUEST_CAPTURE &&
                                        archive_frame_bad) {
                                        unsigned char forged[sizeof(original_frame)];
                                        memcpy(forged, original_frame, sizeof(forged));
                                        forged[200] ^= 1;
                                        assert(qihse_qkp_send_sealed(session, fd, forged, sizeof(forged)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            qihse_qkp_session_free(session);
            if (signer > 0) {
                close(sign_request[1]); close(sign_response[0]);
                int status;
                assert(waitpid(signer, &status, 0) == signer && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            }
        }
        if (report[1] >= 0) close(report[1]);
        if (nonce_report[1] >= 0) close(nonce_report[1]);
        if (keepalive[0] >= 0) {
            char done;
            assert(read(keepalive[0], &done, 1) == 0);
            close(keepalive[0]);
        }
        close(fd);
        _exit(0);
    }
    if (keepalive[0] >= 0) close(keepalive[0]);
    if (report[1] >= 0) close(report[1]);
    if (nonce_report[1] >= 0) close(nonce_report[1]);
    qihse_ct1_host_admission_result_t result = QIHSE_CT1_HOST_DENIED;
    if (executor_mode == 5)
        qihse_ct1_host_execute_archive_receiver_fresh_protected_once(host);
    else if (executor_mode == 4) qihse_ct1_host_execute_archive_receiver_fresh_once(host);
    else if (executor_mode == 3) qihse_ct1_host_execute_archive_receiver_once(host);
    else if (executor_mode == 2) qihse_ct1_host_execute_archive_once(host);
    else if (executor_mode) qihse_ct1_host_execute_noop_once(host);
    else result = qihse_ct1_host_admission_once(host);
    if (keepalive[1] >= 0) close(keepalive[1]);
    if (mode == REQUEST_IDLE || mode == REQUEST_TIMEOUT || mode == ACK_TIMEOUT) {
        assert(clock_gettime(CLOCK_MONOTONIC, &finish) == 0);
        assert(finish.tv_sec - start.tv_sec < 8);
    }
    if (report[0] >= 0) {
        size_t captured_len_before = captured_len;
        ssize_t n = read(report[0], captured_frame, sizeof(captured_frame));
        assert(n > 0 && (size_t)n < sizeof(captured_frame));
        captured_len = (size_t)n;
        close(report[0]);
        unsigned char fresh[sizeof(captured_challenge)];
        assert(read(nonce_report[0], fresh, sizeof(fresh)) == (ssize_t)sizeof(fresh));
        if (captured_len_before) assert(memcmp(fresh, captured_challenge, sizeof(fresh)) != 0);
        memcpy(captured_challenge, fresh, sizeof(fresh));
        assert(read(nonce_report[0], captured_b, sizeof(captured_b)) == (ssize_t)sizeof(captured_b));
        close(nonce_report[0]);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (result != expected)
        fprintf(stderr, "admission mode=%d result=%d expected=%d\n", mode, (int)result, (int)expected);
    assert(result == expected);
}

static void executor_crash_cut(const char *phase, const char *root,
    const char *socket_dir, const char *ledger, const char *checkpoint,
    const char *client, const char *client_host_pub, const char *noop_path)
{
    qihse_audit_shutdown();
    pid_t host_pid = fork();
    assert(host_pid >= 0);
    if (!host_pid) {
        qihse_audit_init();
        qihse_ct1_host_admission_t *host = qihse_ct1_host_admission_open(
            root, socket_dir, ledger, checkpoint);
        assert(host && !setenv("QIHSE_CT1_EXECUTOR_CUT", phase, 1));
        executor_mode = 1;
        attempt(socket_dir, root, host, client, "configured-operator",
            client_host_pub, 65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
        _exit(70); /* A reachable cut must terminate the host itself. */
    }
    int status;
    assert(waitpid(host_pid, &status, 0) == host_pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == 86);
    qihse_audit_init();
    char path[512];
    assert(snprintf(path, sizeof(path), "%s/admission.sock", socket_dir) <
        (int)sizeof(path) && !unlink(path)); /* dead listener, not a live handle */
    qihse_ct1_authority_store_t *store = NULL;
    assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534, &store));
    qihse_ct1_authority_challenge_t fresh;
    int next = qihse_ct1_authority_store_issue(store, 900000, &fresh);
    assert(next == (!strcmp(phase, "retire") || !strcmp(phase, "action") ? 0 : -1));
    qihse_ct1_authority_store_close(store);
    if (!strcmp(phase, "action")) {
        struct stat st;
        assert(!lstat(noop_path, &st) && st.st_uid == 0 &&
            (st.st_mode & 07777) == 0600 && st.st_size == 48 && !unlink(noop_path));
    } else assert(access(noop_path, F_OK) == -1 && errno == ENOENT);
}

/* Read the native fixture's observations before even attempting to provision
 * B. This gate never substitutes a synthetic frame or roster member. */
static int native_evidence_gate(const char *base)
{
    char path[512], line[256];
    assert(snprintf(path, sizeof(path), "%s/native-evidence.txt", base) < (int)sizeof(path));
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    assert(fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 &&
        st.st_nlink == 1 && !(st.st_mode & 077));
    FILE *in = fdopen(fd, "r");
    assert(in);
    unsigned target_count = 0, source_count = 0, target_seen = 0, source_seen = 0;
    unsigned target_mask = 0, source_mask = 0, fields = 0, identity = 0;
    int frame_missing = 1, frame_seen = 0, wal_seen = 0;
    unsigned long long frame_offset = ~0ull, frame_length = 0, frame_position = 0;
    unsigned long long baseline_seq = 0, tombstone_seq = 0, target_high = 0, source_high = 0;
    unsigned long long source_row_seq = 0;
    assert(snprintf(native.base, sizeof(native.base), "%s", base) < (int)sizeof(native.base));
    while (fgets(line, sizeof(line), in)) {
        assert(strchr(line, '\n'));
        if (sscanf(line, "target_file_count=%u", &target_count) == 1 ||
            sscanf(line, "source_file_count=%u", &source_count) == 1) continue;
        static const char *const expected_identity[] = {
            "source_id=source:fixture\n", "target_id=target:fixture\n",
            "generation=gen:fixture\n", "row_key=commons/fixture-key\n",
            "tombstone_position=3\n", "target_cursor=7\n"};
        int matched_identity = 0;
        for (unsigned i = 0; i < 6; ++i) {
            if (!strcmp(line, expected_identity[i])) {
                assert(!(identity & (1u << i)));
                identity |= 1u << i;
                matched_identity = 1;
                break;
            }
        }
        if (matched_identity) continue;
        if (sscanf(line, "baseline_row_seq=%llu", &baseline_seq) == 1) { fields |= 1; continue; }
        if (sscanf(line, "tombstone_row_seq=%llu", &tombstone_seq) == 1) { fields |= 2; continue; }
        if (sscanf(line, "target_high_water=%llu", &target_high) == 1) { fields |= 4; continue; }
        if (sscanf(line, "source_high_water=%llu", &source_high) == 1) { fields |= 8; continue; }
        if (sscanf(line, "source_row_seq=%llu", &source_row_seq) == 1) { fields |= 32; continue; }
        if (!strncmp(line, "baseline_digest=", 16)) {
            assert(strlen(line) == 16 + 64 + 1 && !(fields & 16));
            for (unsigned i = 0; i < 32; ++i) {
                unsigned b;
                assert(sscanf(line + 16 + i * 2, "%2x", &b) == 1);
                native.baseline[i] = (unsigned char)b;
            }
            fields |= 16;
            continue;
        }
        if (!strcmp(line, "source_frame=present\n")) {
            assert(!frame_seen++);
            frame_missing = 0;
            continue;
        }
        if (!strcmp(line, "source_frame=unavailable\n")) continue;
        if (sscanf(line, "source_frame_offset=%llu", &frame_offset) == 1 ||
            sscanf(line, "source_frame_length=%llu", &frame_length) == 1 ||
            sscanf(line, "source_frame_position=%llu", &frame_position) == 1)
            continue;
        char name[65], claimed[65], actual[65];
        unsigned long long size;
        int source = !strncmp(line, "source_file=", 12);
        if (!source && strncmp(line, "target_file=", 12)) {
            fprintf(stderr, "CT1 native evidence: unknown report field: %s", line);
            return 2;
        }
        assert(sscanf(line + 12, "%64s size=%llu sha256=%64s", name, &size,
            claimed) == 3 && strlen(claimed) == 64 && name[0] != '.' &&
            !strchr(name, '/'));
        assert(snprintf(path, sizeof(path), "%s/%s/%s", base,
            source ? "native-source" : "native-target-0", name) < (int)sizeof(path));
        int file = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(file >= 0 && !fstat(file, &st) && S_ISREG(st.st_mode) &&
            st.st_uid == 0 && st.st_nlink == 1 && !(st.st_mode & 077) &&
            st.st_size >= 0 && (unsigned long long)st.st_size == size);
        EVP_MD_CTX *hash = EVP_MD_CTX_new();
        assert(hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
        unsigned char block[4096], digest[32];
        ssize_t got;
        while ((got = read(file, block, sizeof(block))) > 0)
            assert(EVP_DigestUpdate(hash, block, (size_t)got) == 1);
        unsigned length;
        assert(got == 0 && !close(file) &&
            EVP_DigestFinal_ex(hash, digest, &length) == 1 && length == 32);
        EVP_MD_CTX_free(hash);
        for (unsigned i = 0; i < 32; ++i)
            assert(snprintf(actual + 2*i, 3, "%02x", digest[i]) == 2);
        assert(!strcmp(actual, claimed));
        const char *const *names = source ? native_source_names : native_target_names;
        size_t count = source ? 8 : 7, i = 0;
        while (i < count && strcmp(name, names[i])) ++i;
        assert(i < count && size <= QIHSE_CT1_RECOVERY_FILE_SIZE_MAX);
        unsigned *mask = source ? &source_mask : &target_mask;
        assert(!(*mask & (1u << i)));
        *mask |= 1u << i;
        qihse_ct1_recovery_file_t *f = source ? &native.source[i] : &native.target[i];
        strcpy(f->filename, name);
        f->kind = !strcmp(name, "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(name, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(name, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(name, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(name, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(name, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        f->size = size;
        memcpy(f->sha256, digest, 32);
        if (source) {
            ++source_seen;
            if (!strcmp(name, "wal.log") && size == QIHSE_CT1_RECOVERY_FRAME_BYTES)
                ++wal_seen;
        } else ++target_seen;
    }
    assert(!ferror(in) && !fclose(in) && target_seen == target_count &&
        source_seen == source_count);
    if (target_count != 7 || source_count != 8 || target_mask != 0x7f ||
        source_mask != 0xff || fields != 63 || identity != 63 || !baseline_seq ||
        tombstone_seq != baseline_seq + 3 || target_high < tombstone_seq ||
        source_row_seq != baseline_seq + 1 || source_row_seq >= tombstone_seq ||
        source_high <= tombstone_seq ||
        memcmp(native.baseline, native.source[0].sha256, 32) ||
        frame_missing || frame_seen != 1 || wal_seen != 1 || frame_offset != 0 ||
        frame_length != QIHSE_CT1_RECOVERY_FRAME_BYTES || frame_position != 8) {
        fprintf(stderr, "CT1 host/native bridge unavailable: measured target %u/7 "
            "and source %u/8 files; source frame %s. No canonical B or paired "
            "quotes; receiver writer not exercised.\n", target_count, source_count,
            frame_missing ? "unavailable" : "not attested");
        return 2;
    }
    assert(snprintf(path, sizeof(path), "%s/native-source/wal.log", base) < (int)sizeof(path));
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && pread(fd, original_frame, sizeof(original_frame), 0) ==
        (ssize_t)sizeof(original_frame) && !close(fd));
    unsigned char digest[32];
    assert(SHA256(original_frame, sizeof(original_frame), digest) &&
        !memcmp(digest, native.source[7].sha256, 32) &&
        decode_u64_be(original_frame + 32) == 8 &&
        decode_u64_be(original_frame + 40) == source_row_seq &&
        decode_u64_be(original_frame + 48) == source_row_seq &&
        decode_u64_be(original_frame + 96 + original_frame[56] + original_frame[57] + 20) ==
            source_row_seq);
    native.baseline_seq = baseline_seq;
    native.tombstone_seq = tombstone_seq;
    native.target_high = target_high;
    native.source_high = source_high;
    native.source_row_seq = source_row_seq;
    native.enabled = 1;
    return 0;
}




int main(int argc, char **argv)
{
    int native_mode = argc == 3 && !strcmp(argv[1], "native-evidence");
    assert((argc == 2 || native_mode) && geteuid() == 0);
    if (native_mode && native_evidence_gate(argv[2])) return 2;
    const char *base = native_mode ? argv[2] : argv[1];
    char root[512], socket_dir[512], uid_config[512], hostdir[512], operator[512],
         replication[512], migration[512], source[512], target[512],
         source_frozen[512], target_frozen[512], template_path[512],
         other[512], client[512], b_client[512],
         data[512], op_pub[512], client_pub[512], repl_pub[512], mig_pub[512],
         host_pub[512], source_pub[512], target_pub[512],
         client_host_pub[512], other_host_pub[512], b_host_pub[512];
    assert(snprintf(root, sizeof(root), "%s/root", base) < (int)sizeof(root));
    assert(chmod(base, 0711) == 0);
    assert(mkdir(root, 0700) == 0);
    subdir(base, "socket", socket_dir, sizeof(socket_dir));
    assert(chmod(socket_dir, 0711) == 0);
    subdir(base, "client", client, sizeof(client));
    subdir(base, "b-client", b_client, sizeof(b_client));
    subdir(root, "host", hostdir, sizeof(hostdir));
    subdir(root, "operator", operator, sizeof(operator));
    subdir(root, "replication", replication, sizeof(replication));
    subdir(root, "migration", migration, sizeof(migration));
    subdir(root, "source", source, sizeof(source));
    subdir(root, "target", target, sizeof(target));
    subdir(base, "other-client", other, sizeof(other));
    /* Audit remains live until process exit; fixture teardown must not remove
     * its writer lock or integrity chain while the signer thread is running. */
    subdir(base, "audit-data", data, sizeof(data));
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    if (!native_mode) provision_original();
    assert(quiet_keygen(hostdir) && quiet_keygen(operator) &&
           quiet_keygen(replication) && quiet_keygen(migration) &&
           quiet_keygen(other) && quiet_keygen(client) &&
           quiet_keygen(b_client) && quiet_keygen(source) && quiet_keygen(target));
    label(hostdir, "host");
    label(operator, "configured-operator");
    label(replication, "configured-replication");
    label(migration, "configured-migration");
    label(source, native_mode ? "source:fixture" : "source");
    label(target, native_mode ? "target:fixture" : "target");
    assert(snprintf(op_pub, sizeof(op_pub), "%s/qihse_dsa_pub.pem", operator) < (int)sizeof(op_pub));
    assert(snprintf(repl_pub, sizeof(repl_pub), "%s/qihse_dsa_pub.pem", replication) < (int)sizeof(repl_pub));
    assert(snprintf(mig_pub, sizeof(mig_pub), "%s/qihse_dsa_pub.pem", migration) < (int)sizeof(mig_pub));
    assert(snprintf(host_pub, sizeof(host_pub), "%s/qihse_dsa_pub.pem", hostdir) < (int)sizeof(host_pub));
    assert(snprintf(source_pub, sizeof(source_pub), "%s/qihse_dsa_pub.pem", source) < (int)sizeof(source_pub));
    assert(snprintf(target_pub, sizeof(target_pub), "%s/qihse_dsa_pub.pem", target) < (int)sizeof(target_pub));
    assert(snprintf(client_pub, sizeof(client_pub), "%s/qihse_dsa_pub.pem", client) < (int)sizeof(client_pub));
    assert(snprintf(client_host_pub, sizeof(client_host_pub), "%s/host-public.pem", client) <
           (int)sizeof(client_host_pub));
    assert(snprintf(other_host_pub, sizeof(other_host_pub), "%s/host-public.pem", other) <
           (int)sizeof(other_host_pub));
    assert(snprintf(b_host_pub, sizeof(b_host_pub), "%s/host-public.pem", b_client) <
           (int)sizeof(b_host_pub));
    copy_pub(client_pub, op_pub);
    copy_pub_new(host_pub, client_host_pub);
    copy_pub_new(host_pub, other_host_pub);
    copy_pub_new(host_pub, b_host_pub);
    give_client_key(client, 65532);
    give_client_key(other, 65533);
    give_client_key(b_client, 65534);
    provision_b(root, op_pub, source_pub, target_pub,
                source_frozen, target_frozen, template_path);
    qihse_ct1_recovery_manifest_t template_check;
    assert(qihse_ct1_recovery_decode(template_wire, sizeof(template_wire), false,
                                     &template_check, NULL));
    assert(!qihse_ct1_recovery_verify_frozen(NULL, source_frozen, &template_check, true));
    assert(!qihse_ct1_recovery_verify_frozen(NULL, target_frozen, &template_check, false));
    assert(snprintf(uid_config, sizeof(uid_config), "%s/local-uids.conf", root) <
           (int)sizeof(uid_config));
    char ledger[512], checkpoint[512];
    unsigned serial = 0;
    assert(!qihse_ct1_host_admission_open(root, socket_dir, "missing-ledger", "missing-checkpoint")); /* missing */
    provision_store(base, serial, ledger, checkpoint);
    configure_uids(uid_config, 65534, 65534);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint)); /* co-UID */
    configure_uids(uid_config, 0, 65534);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint)); /* root is not Operator */
    configure_uids(uid_config, 65532, 65534);
    assert(chmod(uid_config, 0666) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint)); /* unsafe permissions */
    assert(chmod(uid_config, 0600) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, "missing-ledger", "missing-checkpoint"));
    qihse_ct1_host_admission_t *h = qihse_ct1_host_admission_open(root, socket_dir,
                                                                    ledger, checkpoint);
#define FRESH() (h = fresh_store(h, argv[1], root, socket_dir, &serial, ledger, checkpoint))
    assert(h);
    char initial_log[512];
    struct stat initial_state;
    assert(snprintf(initial_log, sizeof(initial_log), "%s/authority.log", ledger) <
           (int)sizeof(initial_log));
    assert(stat(initial_log, &initial_state) == 0);
    /* Authenticated QKP alone is insufficient before auth-table initialization. */
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("HostAdmissionOperator1!"));
    qihse_user_t *op = qihse_auth_get_user(0);
    assert(op && qihse_auth_create_user(op, 8302, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, "HostAdmissionService1!", false));
    qihse_user_t *service = qihse_auth_get_user(8302);
    assert(service && qihse_ct1_recovery_verify_frozen(service,
        source_frozen, &template_check, true));
    assert(qihse_ct1_recovery_verify_frozen(service,
        target_frozen, &template_check, false));
    unsigned char decoded_original[QIHSE_CT1_DISPOSITION_SIZE];
    assert(qihse_ct1_disposition_encode(service, &template_check, original_frame,
        sizeof(original_frame), decoded_original));
    if (native_mode) {
        assert(qihse_auth_create_user(op, 8303, QIHSE_ROLE_ANALYST, 1, 0,
            "Ct1NativeLow1!", false));
        assert(!qihse_ct1_disposition_encode(qihse_auth_get_user(8303),
            &template_check, original_frame, sizeof(original_frame), decoded_original));
        char native_archive[512], native_receiver[512];
        subdir(base, "archive", native_archive, sizeof(native_archive));
        subdir(base, "receiver", native_receiver, sizeof(native_receiver));
        qihse_ct1_recovery_file_t receiver_files[7];
        frozen_files(native_receiver, receiver_files, native_target_names, 7);
        qihse_ct1_host_admission_close(h);
        h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
        assert(h); /* No trusted offline receiver writer: protected action is no-op. */
        executor_mode = 1;
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
        assert(qihse_ct1_recovery_decode(captured_b, sizeof(captured_b), false,
            &template_check, NULL) &&
            template_check.row_change_seq == native.source_row_seq &&
            template_check.tombstone_row_seq == native.tombstone_seq &&
            template_check.row_change_seq < template_check.tombstone_row_seq &&
            template_check.source_high_water == native.source_high &&
            template_check.frame_length == QIHSE_CT1_RECOVERY_FRAME_BYTES);
        char noop_path[512];
        assert(snprintf(noop_path, sizeof(noop_path), "%s/ct1-noop-1.receipt", root) <
            (int)sizeof(noop_path));
        int noop_fd = open(noop_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        unsigned char receipt[48], hash[32];
        struct stat noop_stat;
        assert(noop_fd >= 0 && !fstat(noop_fd, &noop_stat) &&
            noop_stat.st_uid == 0 && noop_stat.st_nlink == 1 &&
            (noop_stat.st_mode & 07777) == 0600 &&
            noop_stat.st_size == sizeof(receipt) &&
            read(noop_fd, receipt, sizeof(receipt)) == sizeof(receipt) &&
            !close(noop_fd) && !memcmp(receipt, "CT1N\1\0\0\0", 8) &&
            decode_u64_be(receipt + 8) == 1 &&
            SHA256(captured_b, sizeof(captured_b), hash) &&
            !memcmp(receipt + 16, hash, sizeof(hash)));
        DIR *archives = opendir(native_archive);
        assert(archives);
        struct dirent *entry;
        while ((entry = readdir(archives))) assert(entry->d_name[0] == '.');
        assert(!closedir(archives) &&
            qihse_ct1_recovery_verify_frozen(service, native_receiver,
                &template_check, false));
        qihse_ct1_host_admission_close(h);
        ct1_receiver_preflight_cases(native_receiver, service,
            qihse_auth_get_user(8303), &template_check);
        provision_store(base, ++serial, ledger, checkpoint);
        h = qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
            ledger, checkpoint, native_archive, native_receiver);
        assert(h);
        qihse_ct1_host_execute_archive_receiver_fresh_once(h); /* legacy cannot opt in */
        executor_mode = 3;
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
        qihse_ct1_authority_store_t *still_bound = NULL;
        qihse_ct1_authority_challenge_t challenge = {
            .epoch = decode_u64_be(captured_challenge),
            .issued_ms = decode_u64_be(captured_challenge + 8),
            .expires_ms = decode_u64_be(captured_challenge + 16)
        };
        memcpy(challenge.nonce, captured_challenge + 24, sizeof(challenge.nonce));
        qihse_ct1_host_admission_close(h);
        assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
            &still_bound) && !qihse_ct1_authority_store_check_bound(still_bound,
            &challenge, captured_b, sizeof(captured_b)));
        qihse_ct1_authority_store_close(still_bound);
        archives = opendir(native_archive);
        assert(archives);
        while ((entry = readdir(archives))) assert(entry->d_name[0] == '.');
        assert(!closedir(archives));
        char fresh_parent[512], fresh_path[512], fresh_wal[512], old_wal[512];
        subdir(base, "fresh-parent", fresh_parent, sizeof(fresh_parent));
        ct1_receiver_fresh_cases(fresh_parent, native_receiver, service,
            qihse_auth_get_user(8303), &template_check);
        assert(snprintf(fresh_path, sizeof(fresh_path), "%s/fresh-host", fresh_parent) <
            (int)sizeof(fresh_path));
        assert(snprintf(fresh_wal, sizeof(fresh_wal), "%s/wal.log", fresh_path) <
            (int)sizeof(fresh_wal));
        assert(snprintf(old_wal, sizeof(old_wal), "%s/wal.log", native_receiver) <
            (int)sizeof(old_wal));
        assert(!symlink(native_receiver, fresh_path) &&
            !qihse_ct1_host_admission_open_archive_receiver_fresh(root, socket_dir,
                ledger, checkpoint, native_archive, fresh_parent, "fresh-host") &&
            !unlink(fresh_path));
        provision_store(base, ++serial, ledger, checkpoint);
        h = qihse_ct1_host_admission_open_archive_receiver_fresh(root, socket_dir,
            ledger, checkpoint, native_archive, fresh_parent, "fresh-reject");
        assert(h);
        executor_mode = 4;
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, Q_FORGED_TARGET, QIHSE_CT1_HOST_DENIED);
        qihse_ct1_host_admission_close(h);
        char rejected_path[512];
        assert(snprintf(rejected_path, sizeof(rejected_path), "%s/fresh-reject",
            fresh_parent) < (int)sizeof(rejected_path) &&
            access(rejected_path, F_OK) == -1 && errno == ENOENT);
        provision_store(base, ++serial, ledger, checkpoint);
        h = qihse_ct1_host_admission_open_archive_receiver_fresh(root, socket_dir,
            ledger, checkpoint, native_archive, fresh_parent, "fresh-host");
        assert(h && access(fresh_path, F_OK) == -1 && errno == ENOENT);
        qihse_ct1_host_execute_noop_once(h); /* fresh never retires on old path */
        qihse_ct1_host_execute_archive_receiver_once(h);
        assert(access(fresh_path, F_OK) == -1 && errno == ENOENT);
        executor_mode = 4;
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
        assert(qihse_ct1_recovery_verify_frozen(service, fresh_path,
            &template_check, false));
        struct stat old_wal_stat, new_wal_stat;
        assert(!stat(old_wal, &old_wal_stat) && !stat(fresh_wal, &new_wal_stat) &&
            (old_wal_stat.st_ino != new_wal_stat.st_ino ||
             old_wal_stat.st_dev != new_wal_stat.st_dev) &&
            new_wal_stat.st_uid == 0 && new_wal_stat.st_nlink == 1 &&
            (new_wal_stat.st_mode & 07777) == 0400);
        assert(!qihse_ct1_host_admission_open_archive_receiver_fresh(root, socket_dir,
            ledger, checkpoint, native_archive, fresh_parent, "fresh-host"));
        challenge.epoch = decode_u64_be(captured_challenge);
        challenge.issued_ms = decode_u64_be(captured_challenge + 8);
        challenge.expires_ms = decode_u64_be(captured_challenge + 16);
        memcpy(challenge.nonce, captured_challenge + 24, sizeof(challenge.nonce));
        qihse_ct1_host_admission_close(h);
        assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
            &still_bound) && !qihse_ct1_authority_store_check_bound(still_bound,
            &challenge, captured_b, sizeof(captured_b)));
        qihse_ct1_authority_store_close(still_bound);
        archives = opendir(native_archive);
        assert(archives);
        while ((entry = readdir(archives))) assert(entry->d_name[0] == '.');
        assert(!closedir(archives));
        provision_store(base, ++serial, ledger, checkpoint);
        qihse_audit_shutdown();
        pid_t crashed = fork();
        assert(crashed >= 0);
        if (!crashed) {
            qihse_audit_init();
            h = qihse_ct1_host_admission_open_archive_receiver_fresh(root,
                socket_dir, ledger, checkpoint, native_archive, fresh_parent,
                "fresh-crash");
            assert(h && !setenv("QIHSE_CT1_EXECUTOR_CUT", "fresh", 1));
            executor_mode = 4;
            attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
                65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
            _exit(70);
        }
        int crash_status;
        assert(waitpid(crashed, &crash_status, 0) == crashed && WIFEXITED(crash_status) &&
            WEXITSTATUS(crash_status) == 86);
        qihse_audit_init();
        char dead_socket[512], fresh_crash[512];
        assert(snprintf(dead_socket, sizeof(dead_socket), "%s/admission.sock", socket_dir) <
            (int)sizeof(dead_socket) && !unlink(dead_socket));
        assert(snprintf(fresh_crash, sizeof(fresh_crash), "%s/fresh-crash", fresh_parent) <
            (int)sizeof(fresh_crash));
        assert(qihse_ct1_recovery_verify_frozen(service, fresh_crash,
            &template_check, false) &&
            !qihse_ct1_host_admission_open_archive_receiver_fresh(root, socket_dir,
                ledger, checkpoint, native_archive, fresh_parent, "fresh-crash"));
        assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
            &still_bound));
        qihse_ct1_authority_challenge_t rejected;
        assert(qihse_ct1_authority_store_issue(still_bound, 900000, &rejected) != 0);
        qihse_ct1_authority_store_close(still_bound);
        /* No live pinned SOURCE hold interface: even a valid Operator request
         * cannot issue a nonce, provision TARGET, archive, or append. */
        provision_store(base, ++serial, ledger, checkpoint);
        h = qihse_ct1_host_admission_open_archive_receiver_fresh(root, socket_dir,
            ledger, checkpoint, native_archive, fresh_parent, "protected-denied");
        assert(h);
        executor_mode = 5;
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
        qihse_ct1_host_admission_close(h);
        char denied_path[512];
        assert(snprintf(denied_path, sizeof(denied_path), "%s/protected-denied",
            fresh_parent) < (int)sizeof(denied_path) &&
            access(denied_path, F_OK) == -1 && errno == ENOENT);
        archives = opendir(native_archive);
        assert(archives);
        while ((entry = readdir(archives))) assert(entry->d_name[0] == '.');
        assert(!closedir(archives));
        qihse_ct1_authority_store_t *unissued = NULL;
        qihse_ct1_authority_challenge_t next;
        assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
            &unissued) && !qihse_ct1_authority_store_issue(unissued, 900000,
            &next) && next.epoch == 1);
        qihse_ct1_authority_store_close(unissued);

        /* Crash at the fail-closed boundary cannot leave a spent nonce,
         * partial archive or orphan receiver. */
        provision_store(base, ++serial, ledger, checkpoint);
        qihse_audit_shutdown();
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            qihse_audit_init();
            qihse_ct1_host_admission_t *cut_host =
                qihse_ct1_host_admission_open_archive_receiver_fresh(root,
                    socket_dir, ledger, checkpoint, native_archive, fresh_parent,
                    "protected-crash");
            assert(cut_host && !setenv("QIHSE_CT1_EXECUTOR_CUT",
                "source-hold-unavailable", 1));
            executor_mode = 5;
            attempt(socket_dir, root, cut_host, client, "configured-operator",
                client_host_pub, 65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
            _exit(70);
        }
        int result;
        assert(waitpid(child, &result, 0) == child && WIFEXITED(result) &&
            WEXITSTATUS(result) == 86);
        qihse_audit_init();
        char crash_path[512];
        assert(snprintf(dead_socket, sizeof(dead_socket), "%s/admission.sock",
            socket_dir) < (int)sizeof(dead_socket) && !unlink(dead_socket) &&
            snprintf(crash_path, sizeof(crash_path), "%s/protected-crash",
            fresh_parent) < (int)sizeof(crash_path) &&
            access(crash_path, F_OK) == -1 && errno == ENOENT);
        archives = opendir(native_archive);
        assert(archives);
        while ((entry = readdir(archives))) assert(entry->d_name[0] == '.');
        assert(!closedir(archives));
        assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
            &unissued) && !qihse_ct1_authority_store_issue(unissued, 900000,
            &next) && next.epoch == 1);
        qihse_ct1_authority_store_close(unissued);
        assert(qihse_ct1_recovery_verify_frozen(service, source_frozen,
            &template_check, true));
        fprintf(stderr, "CT1 native host: protected action denies before issue, "
            "including crash; legacy remains no-write.\n");
        return 0;
    }
    char archive_dir[512];
    subdir(argv[1], "archive", archive_dir, sizeof(archive_dir));
    assert(!qihse_ct1_host_admission_open_archive(root, socket_dir, ledger,
        checkpoint, root)); /* nested destination is never private custody */
    qihse_ct1_host_admission_close(h);
    h = qihse_ct1_host_admission_open_archive(root, socket_dir, ledger,
        checkpoint, archive_dir);
    assert(h && !qihse_ct1_host_archive_verify(h, service, &template_check, "no-archive"));
    executor_mode = 2;
    archive_frame_bad = 1;
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
    archive_frame_bad = 0;
    unsigned char archive_digest[32];
    char archive_id[QIHSE_CT1_ARCHIVE_ID_SIZE], archive_path[512];
    static const char hex[] = "0123456789abcdef";
    assert(SHA256(captured_b, sizeof(captured_b), archive_digest));
    memcpy(archive_id, "ct1-", 4);
    for (size_t i = 0; i < sizeof(archive_digest); ++i) {
        archive_id[4 + 2*i] = hex[archive_digest[i] >> 4];
        archive_id[5 + 2*i] = hex[archive_digest[i] & 15];
    }
    memcpy(archive_id + 68, ".arc", 5);
    assert(snprintf(archive_path, sizeof(archive_path), "%s/%s", archive_dir,
        archive_id) < (int)sizeof(archive_path));
    assert(access(archive_path, F_OK) == -1 && errno == ENOENT);
    qihse_ct1_host_admission_close(h);
    provision_store(argv[1], ++serial, ledger, checkpoint);
    h = qihse_ct1_host_admission_open_archive(root, socket_dir, ledger,
        checkpoint, archive_dir);
    assert(h);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
    assert(qihse_ct1_recovery_decode(captured_b, sizeof(captured_b), false,
        &template_check, NULL));
    assert(SHA256(captured_b, sizeof(captured_b), archive_digest));
    for (size_t i = 0; i < sizeof(archive_digest); ++i) {
        archive_id[4 + 2*i] = hex[archive_digest[i] >> 4];
        archive_id[5 + 2*i] = hex[archive_digest[i] & 15];
    }
    assert(snprintf(archive_path, sizeof(archive_path), "%s/%s", archive_dir,
        archive_id) < (int)sizeof(archive_path));
    assert(qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    assert(!qihse_ct1_host_archive_verify(h, op, &template_check, archive_id));
    qihse_ct1_host_admission_close(h);
    h = qihse_ct1_host_admission_open_archive(root, socket_dir, ledger,
        checkpoint, archive_dir);
    assert(h && qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    assert(qihse_auth_create_user(op, 8303, QIHSE_ROLE_ANALYST,
        1, 0, "HostAdmissionLow1!", false));
    assert(!qihse_ct1_host_archive_verify(h, qihse_auth_get_user(8303),
        &template_check, archive_id));
    int saved = open(archive_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    unsigned char archived_frame[sizeof(original_frame)];
    struct stat custody;
    assert(saved >= 0 && !fstat(saved, &custody) && custody.st_uid == 0 &&
        (custody.st_mode & 07777) == 0400 && custody.st_nlink == 1 &&
        pread(saved, archived_frame, sizeof(archived_frame),
            16 + QIHSE_CT1_RECOVERY_WIRE_SIZE + 2 * QIHSE_CT1_NODE_QUOTE_SIZE) ==
            sizeof(archived_frame) && !memcmp(archived_frame, original_frame,
            sizeof(original_frame)) && !close(saved));
    pid_t b_reader = fork();
    assert(b_reader >= 0);
    if (!b_reader) {
        assert(!setgid(65534) && !setuid(65534));
        assert(open(archive_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC) == -1 &&
            errno == EACCES);
        _exit(0);
    }
    int b_status;
    assert(waitpid(b_reader, &b_status, 0) == b_reader && WIFEXITED(b_status) &&
        WEXITSTATUS(b_status) == 0);
    qihse_ct1_recovery_manifest_t wrong_archive = template_check;
    wrong_archive.classification++;
    assert(!qihse_ct1_host_archive_verify(h, service, &wrong_archive, archive_id));
    char alias_path[512];
    assert(snprintf(alias_path, sizeof(alias_path), "%s/linked.arc", archive_dir) <
        (int)sizeof(alias_path) && link(archive_path, alias_path) == 0);
    assert(!qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    assert(unlink(alias_path) == 0 &&
        qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    char source_wal[512];
    assert(snprintf(source_wal, sizeof(source_wal), "%s/wal.log", source_frozen) <
        (int)sizeof(source_wal));
    int changed_wal = open(source_wal, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(changed_wal >= 0 && pwrite(changed_wal, "!", 1, 200) == 1 &&
        fsync(changed_wal) == 0 && close(changed_wal) == 0);
    assert(!qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    changed_wal = open(source_wal, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(changed_wal >= 0 && pwrite(changed_wal, original_frame + 200, 1, 200) == 1 &&
        fsync(changed_wal) == 0 && close(changed_wal) == 0);
    assert(qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    int archive_fd = open(archive_path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(archive_fd >= 0 && pwrite(archive_fd, "!", 1, 20) == 1 && close(archive_fd) == 0);
    assert(!qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    assert(unlink(archive_path) == 0);
    char seal_path[512];
    assert(snprintf(seal_path, sizeof(seal_path), "%s.ok", archive_path) <
        (int)sizeof(seal_path) && unlink(seal_path) == 0);
    qihse_ct1_host_admission_close(h);
    const char *const archive_phases[] = {
        "create", "write", "file-sync", "dir-sync", "reopen", "seal-file",
        "seal-commit"
    };
    for (size_t cut = 0; cut < sizeof(archive_phases) / sizeof(archive_phases[0]); ++cut) {
        provision_store(argv[1], ++serial, ledger, checkpoint);
        qihse_audit_shutdown();
        pid_t crashed = fork();
        assert(crashed >= 0);
        if (!crashed) {
            qihse_audit_init();
            qihse_ct1_host_admission_t *opened = qihse_ct1_host_admission_open_archive(
                root, socket_dir, ledger, checkpoint, archive_dir);
            assert(opened && !setenv("QIHSE_CT1_ARCHIVE_CUT", archive_phases[cut], 1));
            executor_mode = 2;
            attempt(socket_dir, root, opened, client, "configured-operator",
                client_host_pub, 65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
            _exit(70);
        }
        int cut_status;
        assert(waitpid(crashed, &cut_status, 0) == crashed && WIFEXITED(cut_status) &&
            WEXITSTATUS(cut_status) == 87);
        qihse_audit_init();
        char dead_socket[512];
        assert(snprintf(dead_socket, sizeof(dead_socket), "%s/admission.sock", socket_dir) <
            (int)sizeof(dead_socket) && unlink(dead_socket) == 0);
        qihse_ct1_host_admission_t *cold = qihse_ct1_host_admission_open_archive(
            root, socket_dir, ledger, checkpoint, archive_dir);
        assert(cold);
        DIR *items = opendir(archive_dir);
        assert(items);
        struct dirent *entry;
        unsigned archives = 0;
        while ((entry = readdir(items))) {
            if (entry->d_name[0] == '.') continue;
            size_t len = strlen(entry->d_name);
            if (len > 4 && !strcmp(entry->d_name + len - 4, ".arc")) {
                ++archives;
                int fd = openat(dirfd(items), entry->d_name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                unsigned char b[QIHSE_CT1_RECOVERY_WIRE_SIZE], trusted[sizeof(b)];
                qihse_ct1_recovery_manifest_t persisted, provisioned;
                assert(fd >= 0);
                ssize_t got = pread(fd, b, sizeof(b), 16);
                if (got == sizeof(b)) {
                    assert(qihse_ct1_recovery_decode(b, sizeof(b), false,
                        &persisted, NULL) &&
                        qihse_ct1_recovery_decode(template_wire,
                            sizeof(template_wire), false, &provisioned, NULL));
                    provisioned.epoch = persisted.epoch;
                    provisioned.issued_ms = persisted.issued_ms;
                    provisioned.expires_ms = persisted.expires_ms;
                    memcpy(provisioned.nonce, persisted.nonce, sizeof(provisioned.nonce));
                    assert(qihse_ct1_recovery_encode(&provisioned, false, false,
                        trusted) && !memcmp(trusted, b, sizeof(b)));
                    assert(qihse_ct1_host_archive_verify(cold, service,
                        &provisioned, entry->d_name) ==
                        !strcmp(archive_phases[cut], "seal-commit"));
                } else assert(!strcmp(archive_phases[cut], "create"));
                assert(close(fd) == 0);
            } else if (len > 3 && !strcmp(entry->d_name + len - 3, ".ok")) {
                int committed = openat(dirfd(items), entry->d_name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                char header[5];
                assert(committed >= 0 && read(committed, header, sizeof(header)) ==
                    sizeof(header) && close(committed) == 0 &&
                    !memcmp(header, !strcmp(archive_phases[cut], "seal-commit") ?
                        "CT1S\1" : "CT1S\0", sizeof(header)));
            }
        }
        assert(archives == 1);
        rewinddir(items);
        while ((entry = readdir(items))) {
            if (entry->d_name[0] != '.')
                assert(unlinkat(dirfd(items), entry->d_name, 0) == 0);
        }
        assert(closedir(items) == 0);
        qihse_ct1_host_admission_close(cold);
    }
    /* This host test's B roster is synthetic and its receiver directory empty:
     * it is not native receiver-store evidence. The separate root-only
     * test-native-receiver target validates real CT state/WAL, not this B. */
    /* Receiver pin is opt-in and private to root; no peer chooses its path. */
    char receiver[512], missing_receiver[512], receiver_link[512];
    assert(snprintf(missing_receiver, sizeof(missing_receiver), "%s/missing-receiver", argv[1]) <
        (int)sizeof(missing_receiver));
    assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, missing_receiver));
    subdir(argv[1], "receiver", receiver, sizeof(receiver));
    assert(snprintf(receiver_link, sizeof(receiver_link), "%s/receiver-link", argv[1]) <
        (int)sizeof(receiver_link));
    assert(!symlink(receiver, receiver_link));
    assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, receiver_link));
    assert(!unlink(receiver_link));
    const char *aliases[] = {root, socket_dir, ledger, checkpoint, archive_dir};
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); ++i)
        assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
            ledger, checkpoint, archive_dir, aliases[i]));
    char nested[512], unsafe[512], unsafe_child[512];
    subdir(archive_dir, "nested", nested, sizeof(nested));
    assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, nested));
    assert(!rmdir(nested));
    subdir(argv[1], "unsafe-parent", unsafe, sizeof(unsafe));
    subdir(unsafe, "child", unsafe_child, sizeof(unsafe_child));
    assert(!chmod(unsafe, 0777));
    assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, unsafe_child));
    assert(!chmod(unsafe, 0700) && !chown(unsafe, 65534, 65534));
    assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, unsafe_child));
    assert(!chown(unsafe, 0, 0) && !rmdir(unsafe_child) && !rmdir(unsafe));
    assert(!chmod(receiver, 0777));
    assert(!qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, receiver));
    assert(!chmod(receiver, 0700));
    pid_t receiver_reader = fork();
    assert(receiver_reader >= 0);
    if (!receiver_reader) {
        assert(!setgid(65534) && !setuid(65534));
        assert(open(receiver, O_RDONLY | O_DIRECTORY | O_CLOEXEC) == -1 &&
            errno == EACCES);
        _exit(0);
    }
    int receiver_status;
    assert(waitpid(receiver_reader, &receiver_status, 0) == receiver_reader &&
        WIFEXITED(receiver_status) && WEXITSTATUS(receiver_status) == 0);
    provision_store(argv[1], ++serial, ledger, checkpoint);
    h = qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, receiver);
    assert(h);
    char moved_receiver[512];
    assert(snprintf(moved_receiver, sizeof(moved_receiver), "%s/receiver-old", argv[1]) <
        (int)sizeof(moved_receiver) && !rename(receiver, moved_receiver));
    assert(!mkdir(receiver, 0700));
    executor_mode = 3;
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_IDLE, QIHSE_CT1_HOST_DENIED);
    assert(!rmdir(receiver) && !symlink(moved_receiver, receiver));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_IDLE, QIHSE_CT1_HOST_DENIED);
    assert(!unlink(receiver) && !rename(moved_receiver, receiver));
    assert(!chmod(receiver, 0777));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_IDLE, QIHSE_CT1_HOST_DENIED);
    assert(!chmod(receiver, 0700));
    DIR *no_action = opendir(archive_dir);
    assert(no_action);
    struct dirent *item;
    while ((item = readdir(no_action))) assert(item->d_name[0] == '.');
    assert(!closedir(no_action));
    qihse_ct1_host_admission_close(h);
    h = NULL;
    qihse_ct1_authority_store_t *unused_store = NULL;
    assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
        &unused_store));
    qihse_ct1_authority_challenge_t untouched;
    assert(!qihse_ct1_authority_store_issue(unused_store, 900000, &untouched) &&
        untouched.epoch == 1); /* replacement denied before issue, not just action */
    qihse_ct1_authority_store_close(unused_store);
    provision_store(argv[1], ++serial, ledger, checkpoint);
    h = qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, receiver);
    assert(h);
    /* An empty pin must not issue a nonce, archive SOURCE or write TARGET. */
    assert(!qihse_ct1_recovery_verify_frozen(service, receiver,
        &template_check, false));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    qihse_ct1_host_admission_close(h);
    qihse_ct1_authority_store_t *empty_store = NULL;
    assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
        &empty_store));
    qihse_ct1_authority_challenge_t unissued;
    assert(!qihse_ct1_authority_store_issue(empty_store, 900000, &unissued) &&
        unissued.epoch == 1);
    qihse_ct1_authority_store_close(empty_store);
    provision_store(argv[1], ++serial, ledger, checkpoint);
    /* Even an exact seven-file copy of the signed frozen TARGET is not a
     * verified inactive receiver with locked historical tombstone/cursor. */
    qihse_ct1_recovery_file_t matched_files[7];
    frozen_files(receiver, matched_files, target_names, 7);
    assert(qihse_ct1_recovery_verify_frozen(service, receiver,
        &template_check, false));
    h = qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, receiver);
    assert(h);
    char receiver_wal[512];
    assert(snprintf(receiver_wal, sizeof(receiver_wal), "%s/wal.log", receiver) <
        (int)sizeof(receiver_wal));
    int tampered = open(receiver_wal, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    unsigned char original_wal;
    assert(tampered >= 0 && pread(tampered, &original_wal, 1, 0) == 1 &&
        pwrite(tampered, "!", 1, 0) == 1 && !close(tampered));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    tampered = open(receiver_wal, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(tampered >= 0 && pwrite(tampered, &original_wal, 1, 0) == 1 &&
        !close(tampered) && qihse_ct1_recovery_verify_frozen(service, receiver,
            &template_check, false));
    char rotated[512];
    assert(snprintf(rotated, sizeof(rotated), "%s/wal.log.old", receiver) <
        (int)sizeof(rotated));
    int old_wal = open(rotated, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    assert(old_wal >= 0 && !close(old_wal));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    assert(!unlink(rotated));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* invalid history before issue */
    assert(!qihse_ct1_host_archive_verify(h, service, &template_check, archive_id));
    qihse_ct1_authority_store_t *matched_store = NULL;
    assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534,
        &matched_store));
    qihse_ct1_authority_challenge_t matched_challenge;
    assert(!qihse_ct1_authority_store_issue(matched_store, 900000,
        &matched_challenge) && matched_challenge.epoch == 1);
    qihse_ct1_authority_store_close(matched_store);
    DIR *receiver_contents = opendir(receiver);
    assert(receiver_contents);
    struct dirent *receiver_entry;
    unsigned receiver_count = 0;
    while ((receiver_entry = readdir(receiver_contents))) {
        if (receiver_entry->d_name[0] != '.') ++receiver_count;
    }
    assert(receiver_count == 7 && !closedir(receiver_contents));
    DIR *not_archived = opendir(archive_dir);
    assert(not_archived);
    while ((receiver_entry = readdir(not_archived)))
        assert(receiver_entry->d_name[0] == '.');
    assert(!closedir(not_archived));
    qihse_ct1_host_admission_close(h);
    h = qihse_ct1_host_admission_open_archive_receiver(root, socket_dir,
        ledger, checkpoint, archive_dir, receiver);
    assert(h);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
        65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* cold outstanding issue persists */
    qihse_ct1_host_admission_close(h);
    executor_mode = 0;
    h = NULL;
    FRESH();
    char noop_path[512];
    assert(snprintf(noop_path, sizeof(noop_path), "%s/ct1-noop-1.receipt", root) <
        (int)sizeof(noop_path));
    executor_mode = 1;
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_DENIED);
    executor_mode = 0;
    unsigned char noop_receipt[48], expected_digest[32];
    struct stat noop_stat;
    int noop_fd = open(noop_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(noop_fd >= 0 && !fstat(noop_fd, &noop_stat) &&
        noop_stat.st_uid == 0 && (noop_stat.st_mode & 07777) == 0600 &&
        noop_stat.st_nlink == 1 && noop_stat.st_size == sizeof(noop_receipt) &&
        read(noop_fd, noop_receipt, sizeof(noop_receipt)) == sizeof(noop_receipt) &&
        !close(noop_fd));
    assert(!memcmp(noop_receipt, "CT1N\1\0\0\0", 8) &&
        decode_u64_be(noop_receipt + 8) == 1 &&
        SHA256(captured_b, sizeof(captured_b), expected_digest) &&
        !memcmp(noop_receipt + 16, expected_digest, sizeof(expected_digest)));
    qihse_ct1_authority_store_t *spent_store = NULL;
    assert(!qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534, &spent_store));
    qihse_ct1_authority_challenge_t spent = {
        .epoch = decode_u64_be(captured_challenge),
        .issued_ms = decode_u64_be(captured_challenge + 8),
        .expires_ms = decode_u64_be(captured_challenge + 16)
    };
    memcpy(spent.nonce, captured_challenge + 24, sizeof(spent.nonce));
    assert(qihse_ct1_authority_store_check_bound(spent_store, &spent,
        captured_b, sizeof(captured_b)) == -1);
    assert(qihse_ct1_authority_store_retire_bound(spent_store, &spent,
        captured_b, sizeof(captured_b)) == -1);
    qihse_ct1_authority_store_close(spent_store);
    assert(!unlink(noop_path));
    FRESH();
    executor_mode = 1;
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, INT_REPLAY, QIHSE_CT1_HOST_DENIED);
    assert(access(noop_path, F_OK) == -1 && errno == ENOENT);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, INT_FD_HANDOFF, QIHSE_CT1_HOST_DENIED);
    executor_mode = 0;
    assert(access(noop_path, F_OK) == -1 && errno == ENOENT);
    qihse_ct1_host_admission_close(h);
    h = NULL;
    const char *const phases[] = {"issue", "evidence", "intent", "retire", "action"};
    for (size_t i = 0; i < sizeof(phases) / sizeof(phases[0]); ++i) {
        provision_store(argv[1], ++serial, ledger, checkpoint);
        executor_crash_cut(phases[i], root, socket_dir, ledger, checkpoint,
            client, client_host_pub, noop_path);
    }
    FRESH();
    assert(snprintf(initial_log, sizeof(initial_log), "%s/authority.log", ledger) <
        (int)sizeof(initial_log) && !stat(initial_log, &initial_state));
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_ADMITTED);
    qihse_ct1_authority_challenge_t bound = {
        .epoch = decode_u64_be(captured_challenge),
        .issued_ms = decode_u64_be(captured_challenge + 8),
        .expires_ms = decode_u64_be(captured_challenge + 16)
    };
    memcpy(bound.nonce, captured_challenge + 24, sizeof(bound.nonce));
    qihse_ct1_authority_store_t *verify = NULL;
    assert(qihse_ct1_authority_store_open_strict(ledger, checkpoint, 65534, &verify) == 0);
    assert(qihse_ct1_authority_store_check_bound(verify, &bound, captured_b,
        sizeof(captured_b)) == 0); /* binding is evidence, never approval */
    unsigned char altered_b[sizeof(captured_b)];
    memcpy(altered_b, captured_b, sizeof(altered_b));
    altered_b[sizeof(altered_b) - 1] ^= 1;
    assert(qihse_ct1_authority_store_check_bound(verify, &bound, altered_b,
        sizeof(altered_b)) != 0);
    qihse_ct1_authority_store_close(verify);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* second issue denied */
    qihse_ct1_host_admission_close(h);
    h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
    assert(h);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* durable across reopen */
    qihse_ct1_host_admission_close(h);
    h = NULL;
    int log_fd = open(initial_log, O_WRONLY | O_CLOEXEC);
    assert(log_fd >= 0 && ftruncate(log_fd, initial_state.st_size) == 0 &&
           fsync(log_fd) == 0 && close(log_fd) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint));
    /* A valid old ledger cannot pass the independently retained checkpoint. */
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_CAPTURE, QIHSE_CT1_HOST_ADMITTED); /* new independent state */
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, B_REPLAY, QIHSE_CT1_HOST_DENIED);
    const enum request_mode b_bad[] = {B_NONE, B_SHORT, B_LONG, B_MALFORMED,
        B_WRONG_ROLE, B_WRONG_PRINCIPAL, B_WRONG_PIN, B_WRONG_ROSTER,
        B_FORGED_CHALLENGE, B_FD_HANDOFF, B_FD_HANDOFF_SPLIT};
    for (size_t i = 0; i < sizeof(b_bad) / sizeof(b_bad[0]); ++i) {
        FRESH();
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
                65532, b_bad[i], QIHSE_CT1_HOST_DENIED);
    }
    const enum request_mode intent_bad[] = {INT_NONE, INT_WRONG_B, INT_STALE_B,
        INT_WRONG_NONCE, INT_WRONG_EPOCH, INT_SHORT, INT_LONG, INT_REPLAY,
        INT_ACK, INT_ADMIT, INT_PARTIAL, INT_FD_HANDOFF, INT_FD_HANDOFF_SPLIT};
    for (size_t i = 0; i < sizeof(intent_bad) / sizeof(intent_bad[0]); ++i) {
        FRESH();
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
                65532, intent_bad[i], QIHSE_CT1_HOST_DENIED);
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
                65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* intent never retires */
    }
    const enum request_mode quote_bad[] = {Q_NONE, Q_SWAP, Q_FORGED,
        Q_FORGED_TARGET, Q_REPLAY, Q_WRONG_B, Q_WRONG_ROSTER, Q_EXPIRED,
        Q_SHORT, Q_LONG, Q_FD_HANDOFF, Q_FD_HANDOFF_SPLIT,
        Q_TARGET_FD_HANDOFF, Q_INTERRUPTED};
    for (size_t i = 0; i < sizeof(quote_bad) / sizeof(quote_bad[0]); ++i) {
        FRESH();
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
                65532, quote_bad[i], QIHSE_CT1_HOST_DENIED);
        attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
                65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* issue remains outstanding */
    }
    /* Independently provisioned expectations must match LIVE root config/files,
     * even when the client prepares the unchanged canonical B template. */
    FRESH();
    char source_id_path[512];
    assert(snprintf(source_id_path, sizeof(source_id_path), "%s/node.id", source) <
           (int)sizeof(source_id_path));
    int changed = open(source_id_path, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, "xource", 6) == 6 && close(changed) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    changed = open(source_id_path, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, "source", 6) == 6 && close(changed) == 0);
    FRESH();
    char saved_source_pub[512];
    assert(snprintf(saved_source_pub, sizeof(saved_source_pub), "%s/saved-source-pub.pem",
                    root) < (int)sizeof(saved_source_pub));
    copy_pub_new(source_pub, saved_source_pub);
    copy_pub(target_pub, source_pub);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    copy_pub(saved_source_pub, source_pub);
    assert(unlink(saved_source_pub) == 0);
    FRESH();
    char source_roster_file[512];
    assert(snprintf(source_roster_file, sizeof(source_roster_file), "%s/%s",
                    source_frozen, source_names[0]) < (int)sizeof(source_roster_file));
    changed = open(source_roster_file, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, "!", 1) == 1 && close(changed) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    unsigned char original[16];
    memset(original, 1, sizeof(original));
    changed = open(source_roster_file, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, original, sizeof(original)) == sizeof(original) &&
           close(changed) == 0);
    FRESH();
    char target_roster_file[512];
    assert(snprintf(target_roster_file, sizeof(target_roster_file), "%s/%s",
                    target_frozen, target_names[0]) < (int)sizeof(target_roster_file));
    changed = open(target_roster_file, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, "!", 1) == 1 && close(changed) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    memset(original, 33, sizeof(original));
    changed = open(target_roster_file, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, original, sizeof(original)) == sizeof(original) &&
           close(changed) == 0);
    /* A root-supplied but inactive service ID also denies without issuance. */
    qihse_ct1_recovery_manifest_t wrong_service;
    assert(qihse_ct1_recovery_decode(template_wire, sizeof(template_wire), false,
                                     &wrong_service, NULL));
    strcpy(wrong_service.replication_principal_id, "8303");
    unsigned char alternate[sizeof(template_wire)];
    assert(qihse_ct1_recovery_encode(&wrong_service, false, false, alternate));
    changed = open(template_path, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, alternate, sizeof(alternate)) == sizeof(alternate) &&
           close(changed) == 0);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    changed = open(template_path, O_WRONLY | O_CLOEXEC);
    assert(changed >= 0 && write(changed, template_wire, sizeof(template_wire)) ==
           sizeof(template_wire) && close(changed) == 0);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_REPLAY, QIHSE_CT1_HOST_DENIED);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_WRONG, QIHSE_CT1_HOST_DENIED);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_SHORT, QIHSE_CT1_HOST_DENIED);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_LONG, QIHSE_CT1_HOST_DENIED);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_NONE, QIHSE_CT1_HOST_DENIED);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_PARTIAL, QIHSE_CT1_HOST_DENIED);
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_TIMEOUT, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* interrupted ACK spends issue */
    FRESH();
    char broken_checkpoint[512];
    assert(snprintf(broken_checkpoint, sizeof(broken_checkpoint), "%s/authority.checkpoint",
                    checkpoint) < (int)sizeof(broken_checkpoint));
    assert(unlink(broken_checkpoint) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* issuance fails, no challenge */
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_NONE, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_WRONG, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_SHORT, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_LONG, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_WRONG_SEQ, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_REPLAY, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_RAW, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_TRUNC_FRAME, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_TIMEOUT, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "wrong-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, other, "configured-operator", other_host_pub,
            65533, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, b_client, "configured-operator", b_host_pub,
            65534, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    char operator_key[512], b_key[512], other_key[512];
    assert(snprintf(operator_key, sizeof(operator_key), "%s/qihse_dsa_key.pem", client) <
           (int)sizeof(operator_key));
    assert(snprintf(b_key, sizeof(b_key), "%s/qihse_dsa_key.pem", b_client) <
           (int)sizeof(b_key));
    assert(snprintf(other_key, sizeof(other_key), "%s/qihse_dsa_key.pem", other) <
           (int)sizeof(other_key));
    copy_pub(operator_key, b_key);
    copy_pub(operator_key, other_key);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_FD_HANDOFF, QIHSE_CT1_HOST_DENIED); /* B writes on Operator's socket */
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_FD_HANDOFF_SPLIT, QIHSE_CT1_HOST_DENIED); /* Operator header, B body */
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_FD_HANDOFF, QIHSE_CT1_HOST_DENIED); /* B sends ACK on Operator socket */
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, ACK_FD_HANDOFF_SPLIT, QIHSE_CT1_HOST_DENIED); /* Operator ACK header, B body */
    attempt(socket_dir, root, h, b_client, "configured-operator", b_host_pub,
            65534, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* copied signing key, B UID */
    attempt(socket_dir, root, h, other, "configured-operator", other_host_pub,
            65533, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* valid signing key, wrong UID */
    attempt(socket_dir, root, h, b_client, "configured-replication", b_host_pub,
            65534, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_PLAINTEXT, QIHSE_CT1_HOST_DENIED);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_IDLE, QIHSE_CT1_HOST_DENIED);
    assert(chmod(op_pub, 0666) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    assert(chmod(op_pub, 0644) == 0);
    assert(chmod(socket_dir, 0755) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    assert(chmod(socket_dir, 0711) == 0);
    char socket_path[512];
    assert(snprintf(socket_path, sizeof(socket_path), "%s/admission.sock", socket_dir) <
           (int)sizeof(socket_path));
    assert(chown(socket_path, 65534, 65534) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    assert(chown(socket_path, 0, 0) == 0);
    assert(chmod(socket_path, 0600) == 0);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            0, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    assert(chmod(socket_path, 0666) == 0);
    configure_uids(uid_config, 65532, 65533);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* changed after open */
    configure_uids(uid_config, 65532, 65534);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* restoring bytes is insufficient */
    qihse_ct1_host_admission_close(h);
    h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
    assert(h);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* retained outstanding issue */
    FRESH();
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_ADMITTED);
    char saved_config[512];
    assert(snprintf(saved_config, sizeof(saved_config), "%s/saved-uids.conf", root) <
           (int)sizeof(saved_config));
    assert(rename(uid_config, saved_config) == 0);
    configure_uids(uid_config, 65532, 65534);
    attempt(socket_dir, root, h, client, "configured-operator", client_host_pub,
            65532, REQUEST_VALID, QIHSE_CT1_HOST_DENIED); /* same bytes, new inode */
    assert(unlink(uid_config) == 0 && rename(saved_config, uid_config) == 0);
    qihse_ct1_host_admission_close(h);
    h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
    assert(h);
    /* Neither root's fork nor B's distinct UID can use an inherited handle. */
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        assert(qihse_ct1_host_admission_once(h) == QIHSE_CT1_HOST_DENIED);
        qihse_ct1_host_admission_close(h);
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        assert(setgid(65534) == 0 && setuid(65534) == 0);
        assert(open(ledger, O_RDONLY | O_DIRECTORY | O_CLOEXEC) == -1 && errno == EACCES);
        assert(open(checkpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC) == -1 && errno == EACCES);
        assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint));
        assert(qihse_ct1_host_admission_once(h) == QIHSE_CT1_HOST_DENIED);
        _exit(0);
    }
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    int queued = connect_local(socket_dir);
    assert(queued >= 0);
    assert(unlink(socket_path) == 0 && symlink(host_pub, socket_path) == 0);
    assert(qihse_ct1_host_admission_once(h) == QIHSE_CT1_HOST_DENIED);
    close(queued);
    qihse_ct1_host_admission_close(h);
    struct stat swapped;
    assert(lstat(socket_path, &swapped) == 0 && S_ISLNK(swapped.st_mode));
    assert(unlink(socket_path) == 0);
    assert(access(socket_path, F_OK) == -1 && errno == ENOENT);
    /* Exact admin pin stays distinct from the replication/migration signer. */
    copy_pub(repl_pub, op_pub);
    h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
    assert(h);
    attempt(socket_dir, root, h, replication, "configured-operator", host_pub,
            0, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    qihse_ct1_host_admission_close(h);
    copy_pub(mig_pub, op_pub);
    h = qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint);
    assert(h);
    attempt(socket_dir, root, h, migration, "configured-operator", host_pub,
            0, REQUEST_VALID, QIHSE_CT1_HOST_DENIED);
    qihse_ct1_host_admission_close(h);
    assert(chown(root, 65534, 65534) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint));
    assert(chown(root, 0, 0) == 0);
    assert(chmod(socket_dir, 0777) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint));
    assert(chmod(socket_dir, 0711) == 0);
    assert(chown(socket_dir, 65534, 65534) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint));
    assert(chown(socket_dir, 0, 0) == 0);
    char link_path[512];
    assert(snprintf(link_path, sizeof(link_path), "%s/socket-link", argv[1]) <
           (int)sizeof(link_path));
    assert(symlink(socket_dir, link_path) == 0);
    assert(!qihse_ct1_host_admission_open(root, link_path, ledger, checkpoint));
    assert(unlink(link_path) == 0);
    assert(!qihse_ct1_host_admission_open(root, root, ledger, checkpoint));
    char checkpoint_file[512];
    assert(snprintf(checkpoint_file, sizeof(checkpoint_file), "%s/authority.checkpoint",
                    checkpoint) < (int)sizeof(checkpoint_file));
    assert(unlink(checkpoint_file) == 0);
    assert(!qihse_ct1_host_admission_open(root, socket_dir, ledger, checkpoint));
    assert(access(checkpoint_file, F_OK) == -1 && errno == ENOENT);
    for (unsigned i = 0; i <= serial; ++i) {
        char name[48];
        assert(snprintf(name, sizeof(name), "ledger-%u", i) < (int)sizeof(name));
        assert(snprintf(ledger, sizeof(ledger), "%s/%s", argv[1], name) < (int)sizeof(ledger));
        assert(nftw(ledger, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
        assert(snprintf(name, sizeof(name), "checkpoint-%u", i) < (int)sizeof(name));
        assert(snprintf(checkpoint, sizeof(checkpoint), "%s/%s", argv[1], name) < (int)sizeof(checkpoint));
        assert(nftw(checkpoint, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    }
#undef FRESH
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(nftw(receiver, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(nftw(archive_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(nftw(socket_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(nftw(client, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(nftw(other, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(nftw(b_client, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CT1 root-host QKP admission: OK (paired strict sequential evidence, no approval)");
    return 0;
}
