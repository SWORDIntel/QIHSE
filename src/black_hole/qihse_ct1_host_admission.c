#include "qihse_ct1_host_admission.h"
#include "qihse_ct1_archive.h"
#include "qihse_ct1_disposition.h"
#include "qihse_ct1_authority_store.h"
#include "qihse_ct1_authority_service.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_ct1_receiver_writer.h"
#include "qihse_auth.h"
#include "qihse_qkp.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

struct qihse_ct1_host_admission {
    int dirfd, socket_dirfd, archive_dirfd, receiver_dirfd, receiver_parentfd, listener;
    int fresh_requested, fresh_provenance;
    struct stat fresh_pins[QIHSE_CT1_RECOVERY_TARGET_FILES];
    dev_t receiver_parent_dev;
    ino_t receiver_parent_ino;
    char receiver_parent[PATH_MAX], receiver_name[256];
    qihse_ct1_authority_store_t *store;
    pid_t owner_pid;
    dev_t dir_dev, socket_dir_dev, socket_dev, archive_dev, receiver_dev;
    ino_t dir_ino, socket_dir_ino, socket_ino, archive_ino, receiver_ino;
    struct stat uid_file_stat;
    uid_t operator_uid, b_uid;
    char uid_config[96];
    char root[PATH_MAX], socket_dir[PATH_MAX], archive_dir[PATH_MAX];
    char receiver_dir[PATH_MAX], ledger_dir[PATH_MAX], checkpoint_dir[PATH_MAX];
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char host_id[QIHSE_QKP_NODE_ID_LEN + 1];
    char operator_id[QIHSE_QKP_NODE_ID_LEN + 1];
    char replication_id[QIHSE_QKP_NODE_ID_LEN + 1];
    char migration_id[QIHSE_QKP_NODE_ID_LEN + 1];
    char host_dsa[PATH_MAX], host_kem[PATH_MAX], host_kem_pub[PATH_MAX];
    char operator_pub[PATH_MAX], replication_pub[PATH_MAX], migration_pub[PATH_MAX];
    unsigned char template_wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    char source_pub[PATH_MAX], target_pub[PATH_MAX];
    struct stat template_stat;
};

static int root_owned_dir(int fd, mode_t mode)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
        (st.st_mode & 07777) == mode;
}

static int private_dir(int fd) { return root_owned_dir(fd, 0700); }

/* Walk every component without symlinks. A root-owned sticky ancestor (such
 * as a system temporary directory) cannot rename a root-owned child. */
static int root_directory(const char *path, mode_t mode, const struct stat *exclude)
{
    if (geteuid() != 0 || !path || path[0] != '/' || strlen(path) >= PATH_MAX)
        return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    char *copy = strdup(path);
    if (!copy) { close(fd); return -1; }
    char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) goto bad;
        struct stat parent;
        if (fstat(fd, &parent) || parent.st_uid != 0 ||
            ((parent.st_mode & 0022) && !(parent.st_mode & S_ISVTX))) goto bad;
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto bad;
        close(fd);
        fd = next;
        struct stat st;
        if (exclude && (fstat(fd, &st) ||
            (st.st_dev == exclude->st_dev && st.st_ino == exclude->st_ino))) goto bad;
    }
    free(copy);
    if (root_owned_dir(fd, mode)) return fd;
    close(fd);
    return -1;
bad:
    free(copy);
    close(fd);
    return -1;
}

/* Each file is opened by descriptor and checked against the root-controlled
 * directory. QKP reopens these paths; nobody other than root can replace them. */
static int checked_file(int dirfd, const char *group, const char *name,
                        char *path, size_t cap, const char *root)
{
    int subdir = openat(dirfd, group, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (subdir < 0) return 0;
    int fd = openat(subdir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    int n = snprintf(path, cap, "%s/%s/%s", root, group, name);
    int ok = private_dir(subdir) && fd >= 0 && fstat(fd, &st) == 0 &&
        S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 0022) &&
        st.st_nlink == 1 && st.st_size > 0 && st.st_size < 16384 &&
        n > 0 && (size_t)n < cap;
    if (fd >= 0) close(fd);
    close(subdir);
    return ok;
}

static int read_id(int dirfd, const char *group, char *id, char *path,
                   size_t cap, const char *root)
{
    if (!checked_file(dirfd, group, "node.id", path, cap, root)) return 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return 0;
    struct stat st;
    int ok = fstat(fd, &st) == 0 && st.st_size > 0 &&
        st.st_size <= QIHSE_QKP_NODE_ID_LEN;
    if (ok) ok = read(fd, id, (size_t)st.st_size) == st.st_size;
    if (ok) {
        id[st.st_size] = 0;
        for (off_t i = 0; i < st.st_size; ++i)
            if ((unsigned char)id[i] < 33 || (unsigned char)id[i] > 126) ok = 0;
    }
    close(fd);
    return ok;
}

/* Root provisions the two distinct local principals, not the connecting peer.
 * Compare the inode, metadata and contents at every admission to reject a
 * replacement or an in-place edit after the handle was opened. */
static int uids_valid(qihse_ct1_host_admission_t *h, int initial)
{
    int fd = openat(h->dirfd, "local-uids.conf",
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat before, after, named;
    char content[sizeof(h->uid_config)] = {0};
    int ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
        before.st_uid == 0 && (before.st_mode & 07777) == 0600 &&
        before.st_nlink == 1 && before.st_size > 0 &&
        before.st_size < (off_t)sizeof(content);
    if (ok) ok = read(fd, content, (size_t)before.st_size) == before.st_size;
    if (ok) ok = !fstat(fd, &after) &&
        !fstatat(h->dirfd, "local-uids.conf", &named, AT_SYMLINK_NOFOLLOW) &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
        before.st_dev == named.st_dev && before.st_ino == named.st_ino &&
        before.st_size == named.st_size &&
        before.st_ctim.tv_sec == named.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == named.st_ctim.tv_nsec;
    close(fd);
    if (!ok) return 0;
    if (!initial) {
        const struct stat *saved = &h->uid_file_stat;
        return before.st_dev == saved->st_dev && before.st_ino == saved->st_ino &&
            before.st_size == saved->st_size && before.st_mode == saved->st_mode &&
            before.st_uid == saved->st_uid && before.st_nlink == saved->st_nlink &&
            before.st_mtim.tv_sec == saved->st_mtim.tv_sec &&
            before.st_mtim.tv_nsec == saved->st_mtim.tv_nsec &&
            before.st_ctim.tv_sec == saved->st_ctim.tv_sec &&
            before.st_ctim.tv_nsec == saved->st_ctim.tv_nsec &&
            !memcmp(content, h->uid_config, (size_t)before.st_size);
    }
    const char *prefix = "operator_uid=";
    const char *middle = "\nb_uid=";
    if (strncmp(content, prefix, strlen(prefix))) return 0;
    char *end;
    errno = 0;
    unsigned long long operator_uid = strtoull(content + strlen(prefix), &end, 10);
    if (errno || strncmp(end, middle, strlen(middle))) return 0;
    errno = 0;
    unsigned long long b_uid = strtoull(end + strlen(middle), &end, 10);
    if (errno || strcmp(end, "\n") || !operator_uid || !b_uid ||
        operator_uid == b_uid || operator_uid > (uid_t)-1 || b_uid > (uid_t)-1)
        return 0;
    char canonical[sizeof(content)];
    int n = snprintf(canonical, sizeof(canonical),
                     "operator_uid=%llu\nb_uid=%llu\n", operator_uid, b_uid);
    if (n != before.st_size || memcmp(content, canonical, (size_t)n)) return 0;
    h->operator_uid = (uid_t)operator_uid;
    h->b_uid = (uid_t)b_uid;
    h->uid_file_stat = before;
    memcpy(h->uid_config, content, (size_t)n);
    return 1;
}

/* QKP pins are SHA-256 of the DER SubjectPublicKeyInfo, not PEM bytes. */
static int public_pin(const char *path, unsigned char pin[32])
{
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    EVP_PKEY *key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (!key) return 0;
    int length = EVP_PKEY_is_a(key, "ML-DSA-87") ? i2d_PUBKEY(key, NULL) : -1;
    unsigned char *der = length > 0 && length <= 8192 ?
        OPENSSL_malloc((size_t)length) : NULL;
    unsigned char *cursor = der;
    int ok = der && i2d_PUBKEY(key, &cursor) == length &&
        SHA256(der, (size_t)length, pin) != NULL;
    OPENSSL_clear_free(der, der ? (size_t)length : 0);
    EVP_PKEY_free(key);
    return ok;
}

/* Root provisions this immutable template independently of the connecting
 * Operator; never construct expectations from the received B. */
static int expected_b(qihse_ct1_host_admission_t *h,
                      qihse_ct1_recovery_manifest_t *expected, int initial)
{
    int fd = openat(h->dirfd, "expected-b.bin",
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st, after, named;
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    int ok = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 &&
        (st.st_mode & 07777) == 0400 && st.st_nlink == 1 &&
        st.st_size == (off_t)sizeof(wire);
    if (ok) ok = read(fd, wire, sizeof(wire)) == (ssize_t)sizeof(wire) &&
        !fstat(fd, &after) &&
        !fstatat(h->dirfd, "expected-b.bin", &named, AT_SYMLINK_NOFOLLOW) &&
        st.st_dev == after.st_dev && st.st_ino == after.st_ino &&
        st.st_size == after.st_size &&
        st.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        st.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        st.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        st.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
        st.st_dev == named.st_dev && st.st_ino == named.st_ino &&
        st.st_ctim.tv_sec == named.st_ctim.tv_sec &&
        st.st_ctim.tv_nsec == named.st_ctim.tv_nsec;
    close(fd);
    if (!ok || !qihse_ct1_recovery_decode(wire, sizeof(wire), false, expected, NULL))
        return 0;
    if (initial) {
        h->template_stat = st;
        memcpy(h->template_wire, wire, sizeof(wire));
        return 1;
    }
    if (st.st_dev != h->template_stat.st_dev ||
        st.st_ino != h->template_stat.st_ino ||
        st.st_mtim.tv_sec != h->template_stat.st_mtim.tv_sec ||
        st.st_mtim.tv_nsec != h->template_stat.st_mtim.tv_nsec ||
        st.st_ctim.tv_sec != h->template_stat.st_ctim.tv_sec ||
        st.st_ctim.tv_nsec != h->template_stat.st_ctim.tv_nsec ||
        memcmp(wire, h->template_wire, sizeof(wire))) return 0;
    char source_id[QIHSE_QKP_NODE_ID_LEN + 1], target_id[QIHSE_QKP_NODE_ID_LEN + 1];
    char path[PATH_MAX];
    char source_frozen[PATH_MAX], target_frozen[PATH_MAX];
    unsigned char issuer_pin[32], source_pin[32], target_pin[32];
    unsigned long service_id;
    char *end;
    errno = 0;
    service_id = strtoul(expected->replication_principal_id, &end, 10);
    if (errno || *end || !service_id || service_id > UINT32_MAX ||
        expected->replication_principal_id[0] == '0') return 0;
    qihse_user_t *service = qihse_auth_get_user((uint32_t)service_id);
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    if (service) qihse_auth_user_active_and_tenant(service, &active, &tenant);
    ok = active && tenant == QIHSE_TENANT_SYSTEM &&
        qihse_user_get_id(service) == service_id &&
        qihse_user_get_role(service) != QIHSE_ROLE_OPERATOR &&
        qihse_user_get_classification(service) == UINT16_MAX &&
        qihse_user_get_sci(service) == UINT16_MAX &&
        expected->principal_tenant_id == tenant &&
        expected->principal_classification == qihse_user_get_classification(service) &&
        expected->principal_sci == qihse_user_get_sci(service) &&
        read_id(h->dirfd, "source", source_id, path, sizeof(path), h->root) &&
        read_id(h->dirfd, "target", target_id, path, sizeof(path), h->root) &&
        checked_file(h->dirfd, "source", "qihse_dsa_pub.pem", h->source_pub, sizeof(h->source_pub), h->root) &&
        checked_file(h->dirfd, "target", "qihse_dsa_pub.pem", h->target_pub, sizeof(h->target_pub), h->root) &&
        !strcmp(expected->issuer_qkp_id, h->operator_id) &&
        !strcmp(expected->source_qkp_id, source_id) &&
        !strcmp(expected->target_qkp_id, target_id) &&
        !strcmp(expected->source_peer_qkp_id, target_id) &&
        !strcmp(expected->target_peer_qkp_id, source_id) &&
        !strcmp(expected->source_store_id, source_id) &&
        !strcmp(expected->target_store_id, target_id) &&
        public_pin(h->operator_pub, issuer_pin) &&
        public_pin(h->source_pub, source_pin) && public_pin(h->target_pub, target_pin) &&
        !memcmp(expected->issuer_operator_pin, issuer_pin, 32) &&
        !memcmp(expected->source_peer_pin, target_pin, 32) &&
        !memcmp(expected->target_peer_pin, source_pin, 32) &&
        snprintf(source_frozen, sizeof(source_frozen), "%s/frozen-source", h->root) < (int)sizeof(source_frozen) &&
        snprintf(target_frozen, sizeof(target_frozen), "%s/frozen-target", h->root) < (int)sizeof(target_frozen) &&
        qihse_ct1_recovery_verify_frozen(service, source_frozen, expected, true) &&
        qihse_ct1_recovery_verify_frozen(service, target_frozen, expected, false);
    return ok;
}

/* All expectations originate in the pinned root template/current root config,
 * never the Operator-supplied wire or either quote. No classified payload read. */
static int quote_expected(qihse_ct1_host_admission_t *h,
    const qihse_ct1_recovery_manifest_t *m, qihse_ct1_node_quote_expected_t *e)
{
    memset(e, 0, sizeof(*e));
    memcpy(e->source_qkp_id, m->source_qkp_id, sizeof(e->source_qkp_id));
    memcpy(e->target_qkp_id, m->target_qkp_id, sizeof(e->target_qkp_id));
    memcpy(e->source_peer_qkp_id, m->source_peer_qkp_id, sizeof(e->source_peer_qkp_id));
    memcpy(e->target_peer_qkp_id, m->target_peer_qkp_id, sizeof(e->target_peer_qkp_id));
    memcpy(e->source_peer_pin, m->source_peer_pin, 32);
    memcpy(e->target_peer_pin, m->target_peer_pin, 32);
    memcpy(e->replication_principal_id, m->replication_principal_id, sizeof(e->replication_principal_id));
    memcpy(e->generation, m->generation, sizeof(e->generation));
    memcpy(e->baseline_sha256, m->baseline_sha256, 32);
    e->target_cursor = m->target_cursor;
    e->source_high_water = m->source_high_water;
    e->target_high_water = m->target_high_water;
    return public_pin(h->source_pub, e->source_signer_pin) &&
        public_pin(h->target_pub, e->target_signer_pin) &&
        !memcmp(e->source_signer_pin, m->target_peer_pin, 32) &&
        !memcmp(e->target_signer_pin, m->source_peer_pin, 32);
}

static int pins_valid(qihse_ct1_host_admission_t *h)
{
    char path[PATH_MAX];
    return checked_file(h->dirfd, "host", "qihse_dsa_key.pem", h->host_dsa, sizeof(h->host_dsa), h->root) &&
        checked_file(h->dirfd, "host", "qihse_kem_key.pem", h->host_kem, sizeof(h->host_kem), h->root) &&
        checked_file(h->dirfd, "host", "qihse_kem_pub.pem", h->host_kem_pub, sizeof(h->host_kem_pub), h->root) &&
        checked_file(h->dirfd, "operator", "qihse_dsa_pub.pem", h->operator_pub, sizeof(h->operator_pub), h->root) &&
        checked_file(h->dirfd, "replication", "qihse_dsa_pub.pem", h->replication_pub, sizeof(h->replication_pub), h->root) &&
        checked_file(h->dirfd, "migration", "qihse_dsa_pub.pem", h->migration_pub, sizeof(h->migration_pub), h->root) &&
        read_id(h->dirfd, "host", h->host_id, path, sizeof(path), h->root) &&
        read_id(h->dirfd, "operator", h->operator_id, path, sizeof(path), h->root) &&
        read_id(h->dirfd, "replication", h->replication_id, path, sizeof(path), h->root) &&
        read_id(h->dirfd, "migration", h->migration_id, path, sizeof(path), h->root) &&
        strcmp(h->operator_id, h->replication_id) &&
        strcmp(h->operator_id, h->migration_id);
}

qihse_ct1_host_admission_t *qihse_ct1_host_admission_open(const char *root_dir,
    const char *socket_dir, const char *ledger_dir, const char *checkpoint_dir)
{
    int dirfd = root_directory(root_dir, 0700, NULL);
    if (dirfd < 0) return NULL;
    struct stat dir;
    if (fstat(dirfd, &dir)) { close(dirfd); return NULL; }
    int socket_dirfd = root_directory(socket_dir, 0711, &dir);
    if (socket_dirfd < 0) { close(dirfd); return NULL; }
    qihse_ct1_host_admission_t *h = calloc(1, sizeof(*h));
    if (!h) { close(socket_dirfd); close(dirfd); return NULL; }
    h->dirfd = dirfd;
    h->socket_dirfd = socket_dirfd;
    h->listener = -1;
    h->archive_dirfd = -1;
    h->receiver_dirfd = -1;
    h->receiver_parentfd = -1;
    h->owner_pid = getpid();
    struct stat socket_dir_st;
    if (fstat(socket_dirfd, &socket_dir_st) ||
        snprintf(h->root, sizeof(h->root), "%s", root_dir) >= (int)sizeof(h->root) ||
        snprintf(h->socket_dir, sizeof(h->socket_dir), "%s", socket_dir) >=
            (int)sizeof(h->socket_dir) ||
        snprintf(h->socket_path, sizeof(h->socket_path), "%s/admission.sock", socket_dir) >=
            (int)sizeof(h->socket_path) || !uids_valid(h, 1) || !pins_valid(h) ||
        qihse_ct1_authority_store_open_strict(ledger_dir, checkpoint_dir, h->b_uid,
                                              &h->store)) goto bad;
    h->dir_dev = dir.st_dev;
    h->dir_ino = dir.st_ino;
    h->socket_dir_dev = socket_dir_st.st_dev;
    h->socket_dir_ino = socket_dir_st.st_ino;
    qihse_ct1_recovery_manifest_t provisioned;
    if (!expected_b(h, &provisioned, 1)) goto bad;
    h->listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (h->listener < 0) goto bad;
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    memcpy(addr.sun_path, h->socket_path, strlen(h->socket_path) + 1);
    if (bind(h->listener, (struct sockaddr *)&addr,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                         strlen(addr.sun_path) + 1))) goto bad;
    struct stat sock;
    if (fstatat(h->socket_dirfd, "admission.sock", &sock, AT_SYMLINK_NOFOLLOW) ||
        !S_ISSOCK(sock.st_mode) || sock.st_uid != 0) goto bad;
    h->socket_dev = sock.st_dev;
    h->socket_ino = sock.st_ino;
    if (fchmodat(h->socket_dirfd, "admission.sock", 0666, 0) || listen(h->listener, 4) ||
        fstatat(h->socket_dirfd, "admission.sock", &sock, AT_SYMLINK_NOFOLLOW) ||
        sock.st_dev != h->socket_dev || sock.st_ino != h->socket_ino ||
        !S_ISSOCK(sock.st_mode) || sock.st_uid != 0 ||
        (sock.st_mode & 07777) != 0666) goto bad;
    return h;
bad:
    qihse_ct1_host_admission_close(h);
    return NULL;
}

static int paths_overlap(const char *a, const char *b)
{
    char left[PATH_MAX], right[PATH_MAX];
    if (!realpath(a, left) || !realpath(b, right)) return 1;
    size_t na = strlen(left), nb = strlen(right);
    return (na <= nb && !strncmp(left, right, na) &&
            (right[na] == '/' || !right[na])) ||
        (nb <= na && !strncmp(left, right, nb) &&
            (left[nb] == '/' || !left[nb]));
}

qihse_ct1_host_admission_t *qihse_ct1_host_admission_open_archive(
    const char *root, const char *socket, const char *ledger,
    const char *checkpoint, const char *archive)
{
    if (!archive || !root || !socket || !ledger || !checkpoint ||
        paths_overlap(archive, root) || paths_overlap(archive, socket) ||
        paths_overlap(archive, ledger) || paths_overlap(archive, checkpoint))
        return NULL;
    int fd = root_directory(archive, 0700, NULL);
    if (fd < 0) return NULL;
    struct stat st;
    int ok = !fstat(fd, &st);
    qihse_ct1_host_admission_t *h = ok ? qihse_ct1_host_admission_open(
        root, socket, ledger, checkpoint) : NULL;
    struct stat host_dir, public_dir;
    if (!h || fstat(h->dirfd, &host_dir) ||
        fstat(h->socket_dirfd, &public_dir) ||
        (st.st_dev == host_dir.st_dev && st.st_ino == host_dir.st_ino) ||
        (st.st_dev == public_dir.st_dev && st.st_ino == public_dir.st_ino) ||
        snprintf(h->archive_dir, sizeof(h->archive_dir), "%s", archive) >=
        (int)sizeof(h->archive_dir)) {
        if (h) qihse_ct1_host_admission_close(h);
        close(fd);
        return NULL;
    }
    h->archive_dirfd = fd;
    h->archive_dev = st.st_dev;
    h->archive_ino = st.st_ino;
    return h;
}

static int archive_valid(qihse_ct1_host_admission_t *h);

/* Only the opt-in root archive handle retains this descriptor. No pathname or
 * descriptor is given to the peer, and no receiver data is written here. */
static int receiver_valid(qihse_ct1_host_admission_t *h)
{
    if (!h || h->receiver_dirfd < 0 || !private_dir(h->receiver_dirfd) ||
        !archive_valid(h)) return 0;
    struct stat pinned;
    if (fstat(h->receiver_dirfd, &pinned) || pinned.st_dev != h->receiver_dev ||
        pinned.st_ino != h->receiver_ino) return 0;
    int fd = root_directory(h->receiver_dir, 0700, NULL);
    struct stat current;
    int ok = fd >= 0 && !fstat(fd, &current) &&
        current.st_dev == pinned.st_dev && current.st_ino == pinned.st_ino;
    if (fd >= 0) close(fd);
    if (!ok) return 0;
    if (h->fresh_requested && !h->fresh_provenance) return 0;
    const char *other[] = {h->root, h->socket_dir, h->ledger_dir,
                            h->checkpoint_dir, h->archive_dir};
    const mode_t modes[] = {0700, 0711, 0700, 0700, 0700};
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
        if (paths_overlap(h->receiver_dir, other[i])) return 0;
        int distinct = root_directory(other[i], modes[i], &pinned);
        struct stat other_stat;
        ok = distinct >= 0 && !fstat(distinct, &other_stat);
        if (distinct >= 0) close(distinct);
        if (!ok) return 0;
        distinct = root_directory(h->receiver_dir, 0700, &other_stat);
        if (distinct < 0) return 0;
        close(distinct);
    }
    return 1;
}

qihse_ct1_host_admission_t *qihse_ct1_host_admission_open_archive_receiver(
    const char *root, const char *socket, const char *ledger,
    const char *checkpoint, const char *archive, const char *receiver)
{
    if (!receiver || !root || !socket || !ledger || !checkpoint || !archive ||
        paths_overlap(receiver, root) || paths_overlap(receiver, socket) ||
        paths_overlap(receiver, ledger) || paths_overlap(receiver, checkpoint) ||
        paths_overlap(receiver, archive)) return NULL;
    int fd = root_directory(receiver, 0700, NULL);
    if (fd < 0) return NULL;
    qihse_ct1_host_admission_t *h = qihse_ct1_host_admission_open_archive(
        root, socket, ledger, checkpoint, archive);
    struct stat st;
    if (!h || fstat(fd, &st) ||
        snprintf(h->receiver_dir, sizeof(h->receiver_dir), "%s", receiver) >=
            (int)sizeof(h->receiver_dir) ||
        snprintf(h->ledger_dir, sizeof(h->ledger_dir), "%s", ledger) >=
            (int)sizeof(h->ledger_dir) ||
        snprintf(h->checkpoint_dir, sizeof(h->checkpoint_dir), "%s", checkpoint) >=
            (int)sizeof(h->checkpoint_dir)) {
        if (h) qihse_ct1_host_admission_close(h);
        close(fd);
        return NULL;
    }
    h->receiver_dirfd = fd;
    h->receiver_dev = st.st_dev;
    h->receiver_ino = st.st_ino;
    if (receiver_valid(h)) return h;
    qihse_ct1_host_admission_close(h);
    return NULL;
}

static int fresh_parent_valid(qihse_ct1_host_admission_t *h)
{
    if (!h || !h->fresh_requested || h->receiver_parentfd < 0 ||
        !private_dir(h->receiver_parentfd)) return 0;
    int reopened = root_directory(h->receiver_parent, 0700, NULL);
    struct stat saved, current;
    int ok = reopened >= 0 && !fstat(h->receiver_parentfd, &saved) &&
        !fstat(reopened, &current) && saved.st_dev == h->receiver_parent_dev &&
        saved.st_ino == h->receiver_parent_ino && current.st_dev == saved.st_dev &&
        current.st_ino == saved.st_ino;
    if (reopened >= 0) close(reopened);
    return ok;
}

static int fresh_ready(qihse_ct1_host_admission_t *h,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *m)
{
    return fresh_parent_valid(h) && h->fresh_provenance && receiver_valid(h) &&
        qihse_ct1_receiver_fresh_pinned(h->receiver_dirfd, h->receiver_dir,
            principal, m, h->fresh_pins);
}

qihse_ct1_host_admission_t *qihse_ct1_host_admission_open_archive_receiver_fresh(
    const char *root, const char *socket, const char *ledger,
    const char *checkpoint, const char *archive, const char *parent, const char *name)
{
    char canonical[PATH_MAX], destination[PATH_MAX];
    if (!root || !socket || !ledger || !checkpoint || !archive || !parent ||
        !name || !*name || strlen(name) > 255 || !strcmp(name, ".") ||
        !strcmp(name, "..") || strchr(name, '/') ||
        !realpath(parent, canonical) || strcmp(parent, canonical) ||
        paths_overlap(parent, root) || paths_overlap(parent, socket) ||
        paths_overlap(parent, ledger) || paths_overlap(parent, checkpoint) ||
        paths_overlap(parent, archive) ||
        snprintf(destination, sizeof(destination), "%s/%s", parent, name) >=
            (int)sizeof(destination)) return NULL;
    int parentfd = root_directory(parent, 0700, NULL);
    struct stat parent_stat, absent;
    if (parentfd < 0) return NULL;
    if (fstat(parentfd, &parent_stat) ||
        fstatat(parentfd, name, &absent, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) { close(parentfd); return NULL; }
    qihse_ct1_host_admission_t *h = qihse_ct1_host_admission_open_archive(
        root, socket, ledger, checkpoint, archive);
    if (!h) { close(parentfd); return NULL; }
    h->receiver_parentfd = parentfd;
    h->receiver_parent_dev = parent_stat.st_dev;
    h->receiver_parent_ino = parent_stat.st_ino;
    h->fresh_requested = 1;
    if (snprintf(h->receiver_parent, sizeof(h->receiver_parent), "%s", parent) >=
            (int)sizeof(h->receiver_parent) ||
        snprintf(h->receiver_name, sizeof(h->receiver_name), "%s", name) >=
            (int)sizeof(h->receiver_name) ||
        snprintf(h->receiver_dir, sizeof(h->receiver_dir), "%s", destination) >=
            (int)sizeof(h->receiver_dir) ||
        snprintf(h->ledger_dir, sizeof(h->ledger_dir), "%s", ledger) >=
            (int)sizeof(h->ledger_dir) ||
        snprintf(h->checkpoint_dir, sizeof(h->checkpoint_dir), "%s", checkpoint) >=
            (int)sizeof(h->checkpoint_dir) || !fresh_parent_valid(h) ||
        fstatat(parentfd, name, &absent, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        qihse_ct1_host_admission_close(h);
        return NULL;
    }
    return h;
}

static int archive_valid(qihse_ct1_host_admission_t *h)
{
    if (!h || h->archive_dirfd < 0 || !private_dir(h->archive_dirfd)) return 0;
    int fd = root_directory(h->archive_dir, 0700, NULL);
    struct stat st;
    int ok = fd >= 0 && !fstat(fd, &st) && st.st_dev == h->archive_dev &&
        st.st_ino == h->archive_ino;
    if (fd >= 0) close(fd);
    return ok;
}

/* QKP's blocking recv/send calls need an absolute deadline: a peer that drips
 * bytes can defeat per-call SO_RCVTIMEO. shutdown interrupts either direction. */
struct handshake_deadline {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct timespec until;
    int fd, done, timed_out;
};

static void *handshake_watchdog(void *arg)
{
    struct handshake_deadline *d = arg;
    pthread_mutex_lock(&d->mutex);
    while (!d->done) {
        int rc = pthread_cond_timedwait(&d->cond, &d->mutex, &d->until);
        if (rc == ETIMEDOUT) {
            d->timed_out = 1;
            shutdown(d->fd, SHUT_RDWR);
            break;
        }
        if (rc != 0) {
            d->timed_out = 1;
            shutdown(d->fd, SHUT_RDWR);
            break;
        }
    }
    pthread_mutex_unlock(&d->mutex);
    return NULL;
}

static int deadline_start(struct handshake_deadline *d, int fd, pthread_t *thread)
{
    pthread_condattr_t attr;
    if (pthread_mutex_init(&d->mutex, NULL)) return 0;
    if (pthread_condattr_init(&attr)) { pthread_mutex_destroy(&d->mutex); return 0; }
    int ok = !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) &&
        !pthread_cond_init(&d->cond, &attr);
    pthread_condattr_destroy(&attr);
    if (!ok) { pthread_mutex_destroy(&d->mutex); return 0; }
    d->fd = fd;
    d->done = 0;
    d->timed_out = 0;
    ok = clock_gettime(CLOCK_MONOTONIC, &d->until) == 0;
    if (ok) {
        d->until.tv_sec += 4;
        ok = pthread_create(thread, NULL, handshake_watchdog, d) == 0;
    }
    if (!ok) { pthread_cond_destroy(&d->cond); pthread_mutex_destroy(&d->mutex); }
    return ok;
}

static int deadline_finish(struct handshake_deadline *d, pthread_t thread)
{
    pthread_mutex_lock(&d->mutex);
    d->done = 1;
    pthread_cond_signal(&d->cond);
    pthread_mutex_unlock(&d->mutex);
    pthread_join(thread, NULL);
    int timed_out = d->timed_out;
    pthread_cond_destroy(&d->cond);
    pthread_mutex_destroy(&d->mutex);
    return timed_out;
}

static int socket_valid(qihse_ct1_host_admission_t *h)
{
    struct stat st;
    return !fstatat(h->socket_dirfd, "admission.sock", &st, AT_SYMLINK_NOFOLLOW) &&
        S_ISSOCK(st.st_mode) && st.st_uid == 0 && (st.st_mode & 07777) == 0666 &&
        st.st_dev == h->socket_dev && st.st_ino == h->socket_ino;
}

static void encode_u64_be(uint8_t out[8], uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)value;
        value >>= 8;
    }
}

static int challenge_current(const qihse_ct1_authority_challenge_t *challenge)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec / 1000000) / 1000)
        return 0;
    uint64_t ms = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return ms >= challenge->issued_ms && ms < challenge->expires_ms &&
        challenge->expires_ms > challenge->issued_ms &&
        challenge->expires_ms - challenge->issued_ms <= 900000;
}

/* A disconnected peer or an extra queued frame breaks the continuous,
 * exact one-command session; a retained QKP pointer alone is insufficient. */
static int operator_connection_live(int fd)
{
    unsigned char byte;
    ssize_t n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

#ifdef QIHSE_CT1_TEST_CRASH_CUT
static void executor_cut(const char *phase)
{
    const char *selected = getenv("QIHSE_CT1_EXECUTOR_CUT");
    if (selected && !strcmp(selected, phase)) _exit(86);
}
#else
static void executor_cut(const char *phase) { (void)phase; }
#endif

static int deadline_current(const struct handshake_deadline *d)
{
    struct timespec now;
    return !clock_gettime(CLOCK_MONOTONIC, &now) &&
        (now.tv_sec < d->until.tv_sec ||
         (now.tv_sec == d->until.tv_sec && now.tv_nsec < d->until.tv_nsec));
}

/* Internal root action: metadata only, never sent over the Operator connection. */
static int record_noop(qihse_ct1_host_admission_t *h,
    const qihse_ct1_authority_challenge_t *issued,
    const unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE])
{
    unsigned char receipt[48] = {'C','T','1','N',1,0,0,0};
    char name[64];
    encode_u64_be(receipt + 8, issued->epoch);
    if (!SHA256(canonical, QIHSE_CT1_RECOVERY_WIRE_SIZE, receipt + 16) ||
        snprintf(name, sizeof(name), "ct1-noop-%llu.receipt",
            (unsigned long long)issued->epoch) >= (int)sizeof(name)) return 0;
    int fd = openat(h->dirfd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    int ok = fchmod(fd, 0600) == 0 &&
        write(fd, receipt, sizeof(receipt)) == (ssize_t)sizeof(receipt) &&
        fsync(fd) == 0;
    if (close(fd) || !ok) return 0;
    return fsync(h->dirfd) == 0;
}


static qihse_ct1_host_admission_result_t host_run(
    qihse_ct1_host_admission_t *h, int execute)
{
    if (!h || geteuid() != 0 || getpid() != h->owner_pid || h->listener < 0 ||
        (h->fresh_requested && execute != 4 && execute != 5) ||
        (execute >= 2 && !archive_valid(h)) ||
        (execute >= 4 && (!fresh_parent_valid(h) || h->receiver_dirfd >= 0 ||
            h->fresh_provenance)))
        return QIHSE_CT1_HOST_DENIED;
    int fd = accept4(h->listener, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0) return QIHSE_CT1_HOST_DENIED;
    /* A frozen SOURCE roster cannot install or verify a hold on the live
     * source store. Deny before issuing a nonce or provisioning a receiver. */
    if (execute == 5) {
        close(fd);
        executor_cut("source-hold-unavailable");
        return QIHSE_CT1_HOST_DENIED;
    }
    qihse_ct1_host_admission_result_t result = QIHSE_CT1_HOST_DENIED;
    int receiver_locked = 0;
    if (execute && (execute == 3 || (execute < 4 && h->receiver_dirfd >= 0)) &&
        !receiver_valid(h)) { close(fd); return result; }
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) ||
        peer_len != sizeof(peer) || peer.uid != h->operator_uid ||
        peer.uid == h->b_uid) { close(fd); return result; }
    int passcred = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred))) {
        close(fd);
        return result;
    }
    int current = root_directory(h->root, 0700, NULL);
    struct stat dir, socket_dir;
    int public = -1;
    if (current >= 0 && !fstat(current, &dir) &&
        dir.st_dev == h->dir_dev && dir.st_ino == h->dir_ino)
        public = root_directory(h->socket_dir, 0711, &dir);
    if (public < 0 || fstat(public, &socket_dir) ||
        socket_dir.st_dev != h->socket_dir_dev || socket_dir.st_ino != h->socket_dir_ino ||
        !private_dir(h->dirfd) || !root_owned_dir(h->socket_dirfd, 0711) ||
        !socket_valid(h) || !uids_valid(h, 0) || !pins_valid(h)) goto done;
    const char *trusted[] = {h->operator_pub};
    const char *migration_ids[] = {h->migration_id};
    const char *migration_pubs[] = {h->migration_pub};
    qihse_qkp_config_t cfg = {0};
    cfg.dsa_key_path = h->host_dsa;
    cfg.kem_key_path = h->host_kem;
    cfg.kem_pub_path = h->host_kem_pub;
    cfg.trusted_pubs = trusted;
    cfg.trusted_count = 1;
    cfg.node_id = h->host_id;
    cfg.require = true;
    cfg.admin_peer_node_id = h->operator_id;
    cfg.admin_peer_dsa_pub_path = h->operator_pub;
    cfg.replication_peer_node_id = h->replication_id;
    cfg.replication_peer_dsa_pub_path = h->replication_pub;
    cfg.migration_peer_count = 1;
    cfg.migration_peer_node_ids = migration_ids;
    cfg.migration_peer_dsa_pub_paths = migration_pubs;
    qihse_qkp_session_t *session = NULL;
    struct handshake_deadline deadline;
    pthread_t timer;
    if (!deadline_start(&deadline, fd, &timer)) goto done;
    if (qihse_qkp_server_negotiate(fd, &cfg, &session) == QIHSE_QKP_SECURE &&
        session && qihse_qkp_session_is_admin_peer(session, &cfg, NULL, 0)) {
        qihse_user_t *op = qihse_auth_get_user(0);
        bool active = false;
        uint32_t tenant = QIHSE_TENANT_INVALID;
        if (op) qihse_auth_user_active_and_tenant(op, &active, &tenant);
        qihse_ct1_recovery_manifest_t expected_b_record;
        if (active && tenant == QIHSE_TENANT_SYSTEM &&
            qihse_user_get_id(op) == 0 && qihse_user_get_role(op) == QIHSE_ROLE_OPERATOR &&
            expected_b(h, &expected_b_record, 0) &&
            (execute < 4 || fresh_parent_valid(h)) &&
            (execute != 3 || (receiver_valid(h) &&
                qihse_ct1_recovery_verify_frozen(
                    qihse_auth_get_user((uint32_t)strtoul(
                        expected_b_record.replication_principal_id, NULL, 10)),
                    h->receiver_dir, &expected_b_record, false) && receiver_valid(h)))) {
            uint8_t request[sizeof(QIHSE_CT1_HOST_ADMISSION_REQUEST_V1)];
            ssize_t n = qihse_qkp_recv_sealed_uid_checked(session, fd, h->operator_uid,
                                                          request, sizeof(request));
            if (n == (ssize_t)(sizeof(QIHSE_CT1_HOST_ADMISSION_REQUEST_V1) - 1) &&
                !memcmp(request, QIHSE_CT1_HOST_ADMISSION_REQUEST_V1, (size_t)n) &&
                uids_valid(h, 0)) {
                qihse_ct1_authority_challenge_t issued;
                if ((execute >= 4 ? fresh_parent_valid(h) :
                        (h->receiver_dirfd < 0 || receiver_valid(h))) &&
                    (execute != 3 || (flock(h->receiver_dirfd, LOCK_EX | LOCK_NB) == 0 &&
                        (receiver_locked = 1) && receiver_valid(h) &&
                        qihse_ct1_receiver_preflight_locked(h->receiver_dirfd,
                            h->receiver_dir, qihse_auth_get_user((uint32_t)strtoul(
                                expected_b_record.replication_principal_id, NULL, 10)),
                            &expected_b_record))) &&
                    !qihse_ct1_authority_store_issue(h->store, 900000, &issued) &&
                    challenge_current(&issued)) {
                    if (execute) executor_cut("issue");
                    uint8_t challenge[sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1 +
                                      QIHSE_CT1_HOST_CHALLENGE_BYTES];
                    uint8_t expected[sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1 +
                                     QIHSE_CT1_HOST_CHALLENGE_BYTES];
                    uint8_t ack[sizeof(expected) + 1];
                    memcpy(challenge, QIHSE_CT1_HOST_CHALLENGE_V1,
                           sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1);
                    uint8_t *wire = challenge + sizeof(QIHSE_CT1_HOST_CHALLENGE_V1) - 1;
                    encode_u64_be(wire, issued.epoch);
                    encode_u64_be(wire + 8, issued.issued_ms);
                    encode_u64_be(wire + 16, issued.expires_ms);
                    memcpy(wire + 24, issued.nonce, sizeof(issued.nonce));
                    memcpy(expected, QIHSE_CT1_HOST_CHALLENGE_ACK_V1,
                           sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1);
                    memcpy(expected + sizeof(QIHSE_CT1_HOST_CHALLENGE_ACK_V1) - 1,
                           wire, QIHSE_CT1_HOST_CHALLENGE_BYTES);
                    if (qihse_qkp_send_sealed(session, fd, challenge, sizeof(challenge)) &&
                        qihse_qkp_recv_sealed_uid_checked(session, fd, h->operator_uid,
                                                          ack, sizeof(ack)) == (ssize_t)sizeof(expected) &&
                        !memcmp(ack, expected, sizeof(expected)) &&
                        challenge_current(&issued) && uids_valid(h, 0) &&
                        pins_valid(h) && expected_b(h, &expected_b_record, 0)) {
                        expected_b_record.epoch = issued.epoch;
                        expected_b_record.issued_ms = issued.issued_ms;
                        expected_b_record.expires_ms = issued.expires_ms;
                        memcpy(expected_b_record.nonce, issued.nonce, sizeof(issued.nonce));
                        unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
                        unsigned char received[sizeof(canonical) + 1];
                        if (qihse_ct1_recovery_encode(&expected_b_record, false, false, canonical) &&
                            qihse_qkp_recv_sealed_uid_checked(session, fd, h->operator_uid,
                                received, sizeof(received)) == (ssize_t)sizeof(canonical) &&
                            !memcmp(received, canonical, sizeof(canonical)) &&
                            challenge_current(&issued) && uids_valid(h, 0) &&
                            pins_valid(h) && expected_b(h, &expected_b_record, 0) &&
                            qihse_ct1_authority_store_bind(h->store, &issued,
                                canonical, sizeof(canonical)) == 0) {
                            unsigned char source_quote[QIHSE_CT1_NODE_QUOTE_SIZE + 1];
                            unsigned char target_quote[QIHSE_CT1_NODE_QUOTE_SIZE + 1];
                            qihse_ct1_node_quote_expected_t source_expected, target_expected;
                            char frozen_source[PATH_MAX], frozen_target[PATH_MAX];
                            if (quote_expected(h, &expected_b_record, &source_expected) &&
                                quote_expected(h, &expected_b_record, &target_expected) &&
                                snprintf(frozen_source, sizeof(frozen_source), "%s/frozen-source", h->root) < (int)sizeof(frozen_source) &&
                                snprintf(frozen_target, sizeof(frozen_target), "%s/frozen-target", h->root) < (int)sizeof(frozen_target) &&
                                qihse_qkp_recv_sealed_uid_checked(session, fd, h->operator_uid,
                                    source_quote, sizeof(source_quote)) == QIHSE_CT1_NODE_QUOTE_SIZE &&
                                qihse_qkp_recv_sealed_uid_checked(session, fd, h->operator_uid,
                                    target_quote, sizeof(target_quote)) == QIHSE_CT1_NODE_QUOTE_SIZE &&
                                challenge_current(&issued) && uids_valid(h, 0) &&
                                pins_valid(h) && expected_b(h, &expected_b_record, 0) &&
                                quote_expected(h, &expected_b_record, &source_expected) &&
                                quote_expected(h, &expected_b_record, &target_expected)) {
                                expected_b_record.epoch = issued.epoch;
                                expected_b_record.issued_ms = issued.issued_ms;
                                expected_b_record.expires_ms = issued.expires_ms;
                                memcpy(expected_b_record.nonce, issued.nonce, sizeof(issued.nonce));
                                qihse_ct1_authority_pair_evidence_t evidence = {
                                    .manifest_wire = canonical, .manifest_len = sizeof(canonical),
                                    .expected_manifest = &expected_b_record,
                                    .replication_principal = qihse_auth_get_user(
                                        (uint32_t)strtoul(expected_b_record.replication_principal_id,
                                            NULL, 10)), .challenge = &issued,
                                    .source_quote = source_quote, .source_quote_len = QIHSE_CT1_NODE_QUOTE_SIZE,
                                    .target_quote = target_quote, .target_quote_len = QIHSE_CT1_NODE_QUOTE_SIZE,
                                    .source_pub_path = h->source_pub, .target_pub_path = h->target_pub,
                                    .source_expected = &source_expected, .target_expected = &target_expected,
                                    .frozen_source_dir = frozen_source, .frozen_target_dir = frozen_target
                                };
                                /* Sequential signed evidence only: no jointly fresh node
                                 * snapshot, nonce retirement, grant, or protected executor. */
                                if (qihse_ct1_authority_service_evaluate_pair_bound(h->store, &evidence)) {
                                    if (execute) executor_cut("evidence");
                                    unsigned char expected_intent[QIHSE_CT1_HOST_RECOVERY_INTENT_BYTES];
                                    unsigned char intent[sizeof(expected_intent) + 1];
                                    size_t prefix = sizeof(QIHSE_CT1_HOST_RECOVERY_INTENT_V1) - 1;
                                    memcpy(expected_intent, QIHSE_CT1_HOST_RECOVERY_INTENT_V1, prefix);
                                    memcpy(expected_intent + prefix, canonical, sizeof(canonical));
                                    memcpy(expected_intent + prefix + sizeof(canonical), wire,
                                           QIHSE_CT1_HOST_CHALLENGE_BYTES);
                                    if (qihse_qkp_recv_sealed_uid_checked(session, fd, h->operator_uid,
                                            intent, sizeof(intent)) == (ssize_t)sizeof(expected_intent) &&
                                        !memcmp(intent, expected_intent, sizeof(expected_intent)) &&
                                        challenge_current(&issued) && uids_valid(h, 0) &&
                                        pins_valid(h) && expected_b(h, &expected_b_record, 0)) {
                                        if (!execute) result = QIHSE_CT1_HOST_ADMITTED;
                                        else {
                                            executor_cut("intent");
                                            qihse_user_t *op_now = qihse_auth_get_user(0);
                                            bool op_active = false;
                                            uint32_t op_tenant = QIHSE_TENANT_INVALID;
                                            if (op_now) qihse_auth_user_active_and_tenant(
                                                op_now, &op_active, &op_tenant);
                                            if ((execute < 2 || archive_valid(h)) &&
                                                (execute >= 4 ? fresh_parent_valid(h) :
                                                    (h->receiver_dirfd < 0 || receiver_valid(h))) &&
                                                deadline_current(&deadline) && operator_connection_live(fd) &&
                                                op_active && op_tenant == QIHSE_TENANT_SYSTEM &&
                                                qihse_user_get_role(op_now) == QIHSE_ROLE_OPERATOR &&
                                                qihse_qkp_session_is_admin_peer(session, &cfg, NULL, 0) &&
                                                challenge_current(&issued) && uids_valid(h, 0) &&
                                                pins_valid(h) && expected_b(h, &expected_b_record, 0) &&
                                                quote_expected(h, &expected_b_record, &source_expected) &&
                                                quote_expected(h, &expected_b_record, &target_expected)) {
                                                expected_b_record.epoch = issued.epoch;
                                                expected_b_record.issued_ms = issued.issued_ms;
                                                expected_b_record.expires_ms = issued.expires_ms;
                                                memcpy(expected_b_record.nonce, issued.nonce,
                                                    sizeof(issued.nonce));
                                                evidence.replication_principal = qihse_auth_get_user(
                                                    (uint32_t)strtoul(expected_b_record.replication_principal_id,
                                                        NULL, 10));
                                                /* Reprove the locked historical prefix in this
                                                 * live session. Writing remains disabled until
                                                 * retirement, custody, fsync and crash cuts are
                                                 * established end to end. */
                                                int receiver_ready = execute != 3 ||
                                                    (receiver_locked && receiver_valid(h) &&
                                                        qihse_ct1_receiver_preflight_locked(
                                                            h->receiver_dirfd, h->receiver_dir,
                                                            evidence.replication_principal,
                                                            &expected_b_record));
                                                if (execute >= 4) {
                                                    int fresh_fd = -1;
                                                    receiver_ready = fresh_parent_valid(h) &&
                                                        qihse_ct1_authority_service_evaluate_pair_bound(
                                                            h->store, &evidence) &&
                                                        qihse_ct1_receiver_fresh_provision(
                                                            h->receiver_parentfd, h->receiver_name,
                                                            frozen_target, h->receiver_dir,
                                                            evidence.replication_principal,
                                                            &expected_b_record, &fresh_fd,
                                                            h->fresh_pins);
                                                    if (receiver_ready) {
                                                        struct stat fresh_stat;
                                                        h->receiver_dirfd = fresh_fd;
                                                        receiver_ready = !fstat(fresh_fd, &fresh_stat);
                                                        if (receiver_ready) {
                                                            h->receiver_dev = fresh_stat.st_dev;
                                                            h->receiver_ino = fresh_stat.st_ino;
                                                            receiver_ready = flock(fresh_fd, LOCK_EX | LOCK_NB) == 0;
                                                        }
                                                        if (receiver_ready) receiver_locked = 1;
                                                        h->fresh_provenance = receiver_ready;
                                                        if (receiver_ready) executor_cut("fresh");
                                                        receiver_ready = receiver_ready &&
                                                            fresh_ready(h, evidence.replication_principal,
                                                                &expected_b_record) &&
                                                            qihse_ct1_receiver_preflight_locked(
                                                                fresh_fd, h->receiver_dir,
                                                                evidence.replication_principal,
                                                                &expected_b_record) &&
                                                            fresh_ready(h, evidence.replication_principal,
                                                                &expected_b_record) &&
                                                            expected_b(h, &expected_b_record, 0) &&
                                                            operator_connection_live(fd) &&
                                                            deadline_current(&deadline);
                                                        h->fresh_provenance = receiver_ready;
                                                    }
                                                }
                                                /* Legacy receiver remains no-write; the
                                                 * fresh evidence-only path never retires. */
                                                if (receiver_ready && execute != 3 && execute != 4 &&
                                                    execute != 5 &&
                                                    (h->receiver_dirfd < 0 || receiver_valid(h)) &&
                                                    qihse_ct1_authority_service_check_and_retire_pair(
                                                        h->store, &evidence)) {
                                                    executor_cut("retire");
                                                    if (deadline_current(&deadline) &&
                                                        challenge_current(&issued) &&
                                                        uids_valid(h, 0) && pins_valid(h) &&
                                                        expected_b(h, &expected_b_record, 0) &&
                                                        qihse_qkp_session_is_admin_peer(
                                                            session, &cfg, NULL, 0)) {
                                                        if (execute >= 2) {
                                                            expected_b_record.epoch = issued.epoch;
                                                            expected_b_record.issued_ms = issued.issued_ms;
                                                            expected_b_record.expires_ms = issued.expires_ms;
                                                            memcpy(expected_b_record.nonce, issued.nonce,
                                                                sizeof(issued.nonce));
                                                            qihse_ct1_archive_root_t archive = {
                                                                .dirfd = h->archive_dirfd,
                                                                .frozen_source_dir = frozen_source,
                                                                .frozen_target_dir = frozen_target,
                                                                .source_pub_path = h->source_pub,
                                                                .target_pub_path = h->target_pub,
                                                                .source_expected = &source_expected,
                                                                .target_expected = &target_expected
                                                            };
                                                            char id[QIHSE_CT1_ARCHIVE_ID_SIZE];
                                                            if (archive_valid(h) &&
                                                                (h->receiver_dirfd < 0 || receiver_valid(h))) {
                                                                int wrote = qihse_ct1_archive_write_root(
                                                                    &archive, evidence.replication_principal,
                                                                    &expected_b_record, canonical,
                                                                    source_quote, target_quote, id);
                                                                int pin_after = h->receiver_dirfd < 0 ||
                                                                    receiver_valid(h);
                                                                if (wrote && pin_after) executor_cut("action");
                                                            }
                                                        } else {
                                                            int wrote = (h->receiver_dirfd < 0 || receiver_valid(h)) &&
                                                                record_noop(h, &issued, canonical);
                                                            int pin_after = h->receiver_dirfd < 0 ||
                                                                receiver_valid(h);
                                                            if (wrote && pin_after) executor_cut("action");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    qihse_qkp_session_free(session);
    if (deadline_finish(&deadline, timer)) result = QIHSE_CT1_HOST_DENIED;
done:
    if (receiver_locked) flock(h->receiver_dirfd, LOCK_UN);
    if (public >= 0) close(public);
    if (current >= 0) close(current);
    close(fd);
    return result;
}

qihse_ct1_host_admission_result_t qihse_ct1_host_admission_once(
    qihse_ct1_host_admission_t *host)
{
    return host_run(host, 0);
}

void qihse_ct1_host_execute_noop_once(qihse_ct1_host_admission_t *host)
{
    (void)host_run(host, 1);
}

void qihse_ct1_host_execute_archive_once(qihse_ct1_host_admission_t *host)
{
    (void)host_run(host, 2);
}

void qihse_ct1_host_execute_archive_receiver_once(qihse_ct1_host_admission_t *host)
{
    (void)host_run(host, 3);
}

void qihse_ct1_host_execute_archive_receiver_fresh_once(qihse_ct1_host_admission_t *host)
{
    (void)host_run(host, 4);
}

void qihse_ct1_host_execute_archive_receiver_fresh_protected_once(
    qihse_ct1_host_admission_t *host)
{
    (void)host_run(host, 5);
}

bool qihse_ct1_host_archive_verify(qihse_ct1_host_admission_t *h,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *archive_id)
{
    if (!h || !expected || !principal || getpid() != h->owner_pid ||
        !archive_valid(h) || !private_dir(h->dirfd) ||
        !uids_valid(h, 0) || !pins_valid(h)) return false;
    int current = root_directory(h->root, 0700, NULL);
    struct stat st;
    int root_ok = current >= 0 && !fstat(current, &st) &&
        st.st_dev == h->dir_dev && st.st_ino == h->dir_ino;
    if (current >= 0) close(current);
    if (!root_ok) return false;
    qihse_ct1_recovery_manifest_t provisioned;
    if (!expected_b(h, &provisioned, 0)) return false;
    provisioned.epoch = expected->epoch;
    provisioned.issued_ms = expected->issued_ms;
    provisioned.expires_ms = expected->expires_ms;
    memcpy(provisioned.nonce, expected->nonce, sizeof(provisioned.nonce));
    unsigned char actual[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    unsigned char trusted[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    if (!qihse_ct1_recovery_encode(&provisioned, false, false, trusted) ||
        !qihse_ct1_recovery_encode(expected, false, false, actual) ||
        memcmp(trusted, actual, sizeof(trusted))) return false;
    unsigned long id = strtoul(expected->replication_principal_id, NULL, 10);
    if (!id || id > UINT32_MAX || principal != qihse_auth_get_user((uint32_t)id))
        return false;
    qihse_ct1_node_quote_expected_t source, target;
    char frozen_source[PATH_MAX], frozen_target[PATH_MAX];
    if (!quote_expected(h, expected, &source) ||
        !quote_expected(h, expected, &target) ||
        snprintf(frozen_source, sizeof(frozen_source), "%s/frozen-source", h->root) >=
            (int)sizeof(frozen_source) ||
        snprintf(frozen_target, sizeof(frozen_target), "%s/frozen-target", h->root) >=
            (int)sizeof(frozen_target)) return false;
    qihse_ct1_archive_root_t archive = {
        .dirfd = h->archive_dirfd,
        .frozen_source_dir = frozen_source,
        .frozen_target_dir = frozen_target,
        .source_pub_path = h->source_pub,
        .target_pub_path = h->target_pub,
        .source_expected = &source,
        .target_expected = &target
    };
    return qihse_ct1_archive_verify(&archive, principal, expected, archive_id);
}

void qihse_ct1_host_admission_close(qihse_ct1_host_admission_t *h)
{
    if (!h) return;
    if (h->listener >= 0) close(h->listener);
    qihse_ct1_authority_store_close(h->store);
    if (h->dirfd >= 0 && h->socket_dirfd >= 0) {
        int private = root_directory(h->root, 0700, NULL);
        struct stat dir, socket_dir;
        int public = -1;
        if (private >= 0 && !fstat(private, &dir) &&
            dir.st_dev == h->dir_dev && dir.st_ino == h->dir_ino)
            public = root_directory(h->socket_dir, 0711, &dir);
        if (h->socket_ino && geteuid() == 0 && getpid() == h->owner_pid &&
            public >= 0 && !fstat(public, &socket_dir) &&
            socket_dir.st_dev == h->socket_dir_dev &&
            socket_dir.st_ino == h->socket_dir_ino &&
            private_dir(h->dirfd) && root_owned_dir(h->socket_dirfd, 0711) &&
            socket_valid(h))
            unlinkat(h->socket_dirfd, "admission.sock", 0);
        if (public >= 0) close(public);
        if (private >= 0) close(private);
    }
    if (h->receiver_dirfd >= 0) close(h->receiver_dirfd);
    if (h->receiver_parentfd >= 0) close(h->receiver_parentfd);
    if (h->archive_dirfd >= 0) close(h->archive_dirfd);
    if (h->socket_dirfd >= 0) close(h->socket_dirfd);
    if (h->dirfd >= 0) close(h->dirfd);
    free(h);
}
