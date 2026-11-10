#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct_target.h"

#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include "qihse_resp_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CT_TARGET_MAX_CHUNK (12u << 10)
#define CT_TARGET_META_VERSION 1u
#define CT_TARGET_STATE_PREPARING 0u
#define CT_TARGET_STATE_RECEIVING 1u
#define CT_TARGET_STATE_SEALED 2u
#define CT_TARGET_STATE_FINALIZED 3u

extern bool qihse_resp_ct_abort_request_fields(
    const qihse_resp_ct_abort_request_t *request, const char **transfer_id,
    const char **topology_source_id, const char **topology_target_id,
    const char **qkp_source_id, const char **qkp_target_id,
    const char **generation, uint16_t *first_slot, uint16_t *last_slot,
    uint64_t *source_lsn, uint64_t *config_epoch,
    unsigned char canonical_range_checksum[32]);

typedef struct {
    unsigned char magic[8];
    uint32_t version;
    uint32_t state;
    uint32_t data_user_id;
    uint32_t data_tenant_id;
    uint16_t data_role;
    uint16_t data_classification;
    uint16_t data_sci;
    uint16_t first_slot;
    uint16_t last_slot;
    uint16_t reserved16;
    uint64_t config_epoch;
    uint64_t source_lsn;
    uint64_t target_cut;
    uint64_t total_bytes;
    uint64_t offset;
    uint64_t target_lsn;
    char transfer_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    char source_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char target_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char source_qkp_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    char target_qkp_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    char generation[QIHSE_OWNERSHIP_ID_MAX + 1u];
    unsigned char image_sha256[32];
    unsigned char range_sha256[32];
    unsigned char seal_checksum[32];
    unsigned char manifest_sha256[32];
} ct_target_manifest_t;

struct qihse_ct_target {
    qihse_cluster_ownership_context_t *ownership;
    int dir_fd;
    char directory[PATH_MAX];
    char local_topology_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char local_qkp_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    pthread_mutex_t lock;
    uint64_t temp_counter;
};

typedef struct {
    qihse_ct_target_t *target;
    bool failed;
} ct_target_recovery_t;

static const unsigned char manifest_magic[8] = {'Q','C','T','2','S','T','G','1'};

static void set_error(char *err, size_t cap, const char *message) {
    if (err && cap) snprintf(err, cap, "%s", message ? message : "CT2 target operation failed");
}

static bool valid_id(const char *value, size_t capacity) {
    if (!value || !*value || strnlen(value, capacity) >= capacity) return false;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.'))
            return false;
    return true;
}

static bool system_operator(const qihse_user_t *user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
}

static bool data_authority(const qihse_user_t *user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM &&
        qihse_auth_can_access(user, UINT16_MAX, UINT16_MAX);
}

static bool write_all(int fd, const void *data, size_t length) {
    const unsigned char *p = data;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return true;
}

static bool pwrite_all(int fd, const void *data, size_t length, uint64_t offset) {
    const unsigned char *p = data;
    while (length) {
        if (offset > (uint64_t)INT64_MAX) { errno = EFBIG; return false; }
        ssize_t n = pwrite(fd, p, length, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n;
        length -= (size_t)n;
        offset += (uint64_t)n;
    }
    return true;
}

static bool pread_all(int fd, void *data, size_t length, uint64_t offset) {
    unsigned char *p = data;
    while (length) {
        if (offset > (uint64_t)INT64_MAX) { errno = EFBIG; return false; }
        ssize_t n = pread(fd, p, length, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n;
        length -= (size_t)n;
        offset += (uint64_t)n;
    }
    return true;
}

static bool file_secure(int fd, bool writable) {
    struct stat st;
    return fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1 && (st.st_mode & 077) == 0 &&
        (!writable || (st.st_mode & 0600) == 0600);
}

static bool manifest_digest(ct_target_manifest_t *manifest) {
    unsigned int n = 0;
    memset(manifest->manifest_sha256, 0, sizeof(manifest->manifest_sha256));
    if (!EVP_Digest(manifest, offsetof(ct_target_manifest_t, manifest_sha256),
                    manifest->manifest_sha256, &n, EVP_sha256(), NULL) || n != 32)
        return false;
    return true;
}

static bool manifest_valid(ct_target_manifest_t *manifest) {
    if (memcmp(manifest->magic, manifest_magic, sizeof(manifest_magic)) != 0 ||
        manifest->version != CT_TARGET_META_VERSION ||
        manifest->state > CT_TARGET_STATE_FINALIZED ||
        !manifest->total_bytes || manifest->total_bytes > (uint64_t)INT64_MAX ||
        manifest->offset > manifest->total_bytes ||
        manifest->first_slot > manifest->last_slot ||
        manifest->last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !valid_id(manifest->transfer_id, sizeof(manifest->transfer_id)) ||
        !valid_id(manifest->source_id, sizeof(manifest->source_id)) ||
        !valid_id(manifest->target_id, sizeof(manifest->target_id)) ||
        !valid_id(manifest->source_qkp_id, sizeof(manifest->source_qkp_id)) ||
        !valid_id(manifest->target_qkp_id, sizeof(manifest->target_qkp_id)) ||
        !valid_id(manifest->generation, sizeof(manifest->generation)) ||
        !manifest->config_epoch)
        return false;
    unsigned char expected[32];
    memcpy(expected, manifest->manifest_sha256, sizeof(expected));
    if (!manifest_digest(manifest)) return false;
    bool ok = CRYPTO_memcmp(expected, manifest->manifest_sha256, sizeof(expected)) == 0;
    memcpy(manifest->manifest_sha256, expected, sizeof(expected));
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

static bool name_for_transfer(const char *transfer_id, char out_base[65]) {
    unsigned char digest[32];
    unsigned int n = 0;
    if (!valid_id(transfer_id, QIHSE_OWNERSHIP_ID_MAX + 1u) ||
        !EVP_Digest(transfer_id, strlen(transfer_id), digest, &n, EVP_sha256(), NULL) || n != 32)
        return false;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        out_base[2u * i] = hex[digest[i] >> 4];
        out_base[2u * i + 1u] = hex[digest[i] & 15u];
    }
    out_base[64] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return true;
}

static bool file_names(const char *transfer_id, char meta[80], char image[80]) {
    char base[65];
    if (!name_for_transfer(transfer_id, base)) return false;
    return snprintf(meta, 80, "%s.meta", base) < 80 &&
           snprintf(image, 80, "%s.qfs", base) < 80;
}

static bool read_manifest(qihse_ct_target_t *target, const char *name,
                          ct_target_manifest_t *out, bool *exists) {
    *exists = false;
    int fd = openat(target->dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        st.st_nlink == 1 && (st.st_mode & 077) == 0 && st.st_size == (off_t)sizeof(*out) &&
        pread_all(fd, out, sizeof(*out), 0) && manifest_valid(out);
    close(fd);
    if (!ok) { errno = EINVAL; return false; }
    *exists = true;
    return true;
}

static bool ensure_image_file(qihse_ct_target_t *target, const char *name, bool create) {
    int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (create) flags |= O_CREAT;
    int fd = openat(target->dir_fd, name, flags, 0600);
    if (fd < 0) return false;
    struct stat st;
    bool ok = file_secure(fd, true) && fstat(fd, &st) == 0 &&
              st.st_size == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool store_manifest(qihse_ct_target_t *target, const char *name,
                           ct_target_manifest_t *manifest) {
    if (!manifest_digest(manifest)) return false;
    char temp[112];
    unsigned char random[8];
    if (RAND_bytes(random, sizeof(random)) != 1) return false;
    static const char hex[] = "0123456789abcdef";
    char suffix[17];
    for (size_t i = 0; i < sizeof(random); ++i) {
        suffix[2u * i] = hex[random[i] >> 4];
        suffix[2u * i + 1u] = hex[random[i] & 15u];
    }
    suffix[16] = '\0';
    OPENSSL_cleanse(random, sizeof(random));
    if (snprintf(temp, sizeof(temp), "%s.tmp.%s", name, suffix) >= (int)sizeof(temp))
        return false;
    int fd = openat(target->dir_fd, temp,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return false;
    bool ok = file_secure(fd, true) && write_all(fd, manifest, sizeof(*manifest)) &&
        fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (ok && renameat(target->dir_fd, temp, target->dir_fd, name) != 0) ok = false;
    if (ok && fsync(target->dir_fd) != 0) ok = false;
    if (!ok) (void)unlinkat(target->dir_fd, temp, 0);
    return ok;
}

static bool manifest_matches_txn(const ct_target_manifest_t *m,
                                 const qihse_cluster_ownership_txn_t *t,
                                 uint64_t total, const unsigned char image_sha[32],
                                 const unsigned char range_sha[32],
                                 uint64_t target_cut) {
    return t && t->phase == QIHSE_OWNERSHIP_PREPARED &&
        !strcmp(m->transfer_id, t->transfer_id) &&
        !strcmp(m->source_id, t->source_id) && !strcmp(m->target_id, t->target_id) &&
        !strcmp(m->source_qkp_id, t->source_qkp_id) &&
        !strcmp(m->target_qkp_id, t->target_qkp_id) &&
        !strcmp(m->generation, t->generation) &&
        m->first_slot == t->start && m->last_slot == t->end &&
        m->source_lsn == t->source_lsn && m->config_epoch == t->config_epoch &&
        m->total_bytes == total &&
        m->target_cut == target_cut &&
        CRYPTO_memcmp(m->image_sha256, image_sha, 32) == 0 &&
        CRYPTO_memcmp(m->range_sha256, range_sha, 32) == 0;
}

static bool finalize_stage_for_txn(qihse_ct_target_t *target,
                                  const qihse_cluster_ownership_txn_t *finalized) {
    char meta_name[80], image_name[80];
    ct_target_manifest_t manifest;
    bool exists = false;
    if (!finalized || finalized->phase != QIHSE_OWNERSHIP_FINALIZED ||
        !file_names(finalized->transfer_id, meta_name, image_name) ||
        !read_manifest(target, meta_name, &manifest, &exists)) return false;
    if (!exists) return true; /* source-side journal record, no local stage */
    qihse_cluster_ownership_txn_t prepared = *finalized;
    prepared.phase = QIHSE_OWNERSHIP_PREPARED;
    if (!manifest_matches_txn(&manifest, &prepared, manifest.total_bytes,
            manifest.image_sha256, manifest.range_sha256, manifest.target_cut) ||
        manifest.target_lsn != finalized->target_lsn ||
        CRYPTO_memcmp(manifest.seal_checksum, finalized->proof_digest, 32) != 0 ||
        (manifest.state != CT_TARGET_STATE_SEALED &&
         manifest.state != CT_TARGET_STATE_FINALIZED)) return false;
    if (manifest.state != CT_TARGET_STATE_FINALIZED) {
        manifest.state = CT_TARGET_STATE_FINALIZED;
        if (!store_manifest(target, meta_name, &manifest)) return false;
    }
    if (unlinkat(target->dir_fd, image_name, 0) != 0 && errno != ENOENT) return false;
    return fsync(target->dir_fd) == 0;
}

static bool recover_finalized_cb(const qihse_cluster_ownership_txn_t *txn, void *opaque) {
    ct_target_recovery_t *recovery = opaque;
    if (txn && txn->phase == QIHSE_OWNERSHIP_FINALIZED &&
        !finalize_stage_for_txn(recovery->target, txn)) {
        recovery->failed = true;
        return false;
    }
    return true;
}

static bool validate_peer_and_txn(qihse_ct_target_t *target, qihse_user_t *data,
                                  const char *authenticated_source_qkp,
                                  const qihse_cluster_ownership_txn_t *txn) {
    if (!target || !target->ownership || !system_operator(target->ownership->principal) ||
        !data_authority(data) || !authenticated_source_qkp || !txn ||
        txn->phase != QIHSE_OWNERSHIP_PREPARED ||
        strcmp(txn->target_qkp_id, target->local_qkp_id) ||
        strcmp(txn->source_qkp_id, authenticated_source_qkp) ||
        strcmp(txn->target_id, target->local_topology_id) ||
        !strcmp(txn->source_id, txn->target_id) || !txn->config_epoch ||
        txn->start > txn->end || txn->end >= QIHSE_CLUSTER_SLOT_COUNT ||
        !valid_id(txn->transfer_id, sizeof(txn->transfer_id)) ||
        !valid_id(txn->generation, sizeof(txn->generation))) return false;
    qihse_cluster_ownership_context_t *ownership = target->ownership;
    uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
    uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_node_t source_node, target_node;
    if (!qihse_cluster_topology_find_node(ownership->topology, txn->source_id, &source_index) ||
        !qihse_cluster_topology_find_node(ownership->topology, txn->target_id, &target_index) ||
        !qihse_cluster_topology_get_node(ownership->topology, source_index, &source_node) ||
        !qihse_cluster_topology_get_node(ownership->topology, target_index, &target_node) ||
        source_node.role != QIHSE_CLUSTER_NODE_PRIMARY ||
        target_node.role != QIHSE_CLUSTER_NODE_PRIMARY ||
        !target_node.healthy ||
        qihse_cluster_topology_local_node(ownership->topology) != target_index)
        return false;
    char mapped_source_qkp[QIHSE_OWNERSHIP_ID_MAX + 1u] = {0};
    char mapped_target_qkp[QIHSE_OWNERSHIP_ID_MAX + 1u] = {0};
    if (!ownership->peer_id ||
        !ownership->peer_id(ownership->peer_id_context, txn->source_id, mapped_source_qkp) ||
        !ownership->peer_id(ownership->peer_id_context, txn->target_id, mapped_target_qkp))
        return false;
    return !strcmp(mapped_source_qkp, authenticated_source_qkp) &&
           !strcmp(mapped_source_qkp, txn->source_qkp_id) &&
           !strcmp(mapped_target_qkp, target->local_qkp_id);
}

static void manifest_from_txn(ct_target_manifest_t *m,
                              const qihse_cluster_ownership_txn_t *txn,
                              qihse_user_t *data, uint64_t total,
                              const unsigned char image_sha[32],
                              const unsigned char range_sha[32], uint64_t target_cut) {
    memset(m, 0, sizeof(*m));
    memcpy(m->magic, manifest_magic, sizeof(manifest_magic));
    m->version = CT_TARGET_META_VERSION;
    m->state = CT_TARGET_STATE_PREPARING;
    m->data_user_id = qihse_user_get_id(data);
    m->data_tenant_id = qihse_user_get_tenant_id(data);
    m->data_role = qihse_user_get_role(data);
    m->data_classification = qihse_user_get_classification(data);
    m->data_sci = qihse_user_get_sci(data);
    m->first_slot = txn->start;
    m->last_slot = txn->end;
    m->config_epoch = txn->config_epoch;
    m->source_lsn = txn->source_lsn;
    m->target_cut = target_cut;
    m->total_bytes = total;
    snprintf(m->transfer_id, sizeof(m->transfer_id), "%s", txn->transfer_id);
    snprintf(m->source_id, sizeof(m->source_id), "%s", txn->source_id);
    snprintf(m->target_id, sizeof(m->target_id), "%s", txn->target_id);
    snprintf(m->source_qkp_id, sizeof(m->source_qkp_id), "%s", txn->source_qkp_id);
    snprintf(m->target_qkp_id, sizeof(m->target_qkp_id), "%s", txn->target_qkp_id);
    snprintf(m->generation, sizeof(m->generation), "%s", txn->generation);
    memcpy(m->image_sha256, image_sha, 32);
    memcpy(m->range_sha256, range_sha, 32);
}

static bool manifest_data_principal(const ct_target_manifest_t *m, qihse_user_t *user) {
    return data_authority(user) && m->data_user_id == qihse_user_get_id(user) &&
        m->data_tenant_id == qihse_user_get_tenant_id(user) &&
        m->data_role == qihse_user_get_role(user) &&
        m->data_classification == qihse_user_get_classification(user) &&
        m->data_sci == qihse_user_get_sci(user);
}

static bool hash_fd(int fd, uint64_t total, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    unsigned char bytes[8192];
    uint64_t offset = 0;
    while (ok && offset < total) {
        size_t want = total - offset < sizeof(bytes) ? (size_t)(total - offset) : sizeof(bytes);
        if (!pread_all(fd, bytes, want, offset)) { ok = false; break; }
        ok = EVP_DigestUpdate(ctx, bytes, want) == 1;
        offset += want;
    }
    unsigned int n = 0;
    if (ok) ok = EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 32;
    OPENSSL_cleanse(bytes, sizeof(bytes));
    EVP_MD_CTX_free(ctx);
    return ok;
}

qihse_ct_target_t *qihse_ct_target_create(
    qihse_cluster_ownership_context_t *ownership,
    const char *staging_directory, const char *local_qkp_id,
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (!ownership || !ownership->store || !ownership->topology ||
        !system_operator(ownership->principal) || !staging_directory ||
        !*staging_directory || strlen(staging_directory) >= PATH_MAX ||
        !valid_id(local_qkp_id, QIHSE_OWNERSHIP_ID_MAX + 1u)) {
        set_error(err, err_cap, "invalid CT2 target context"); errno = EINVAL; return NULL;
    }
    struct stat lst;
    if (lstat(staging_directory, &lst) != 0 && errno == ENOENT) {
        if (mkdir(staging_directory, 0700) != 0 && errno != EEXIST) {
            set_error(err, err_cap, "cannot create private CT2 staging directory"); return NULL;
        }
    }
    int fd = open(staging_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        if (fd >= 0) close(fd);
        set_error(err, err_cap, "CT2 staging directory must be private and daemon-owned");
        errno = EACCES; return NULL;
    }
    qihse_ct_target_t *target = calloc(1, sizeof(*target));
    if (!target) { close(fd); errno = ENOMEM; return NULL; }
    target->ownership = ownership;
    target->dir_fd = fd;
    snprintf(target->directory, sizeof(target->directory), "%s", staging_directory);
    snprintf(target->local_qkp_id, sizeof(target->local_qkp_id), "%s", local_qkp_id);
    uint16_t local_index = qihse_cluster_topology_local_node(ownership->topology);
    qihse_cluster_node_t local_node;
    char mapped_qkp[QIHSE_OWNERSHIP_ID_MAX + 1u] = {0};
    if (local_index == QIHSE_CLUSTER_NODE_NONE ||
        !qihse_cluster_topology_get_node(ownership->topology, local_index, &local_node) ||
        !ownership->peer_id ||
        !ownership->peer_id(ownership->peer_id_context, local_node.id, mapped_qkp) ||
        strcmp(mapped_qkp, local_qkp_id)) {
        close(fd); free(target);
        set_error(err, err_cap, "local topology and QKP identities do not match");
        errno = EACCES; return NULL;
    }
    snprintf(target->local_topology_id, sizeof(target->local_topology_id), "%s", local_node.id);
    int rc = pthread_mutex_init(&target->lock, NULL);
    if (rc != 0) {
        close(fd); free(target); errno = rc;
        set_error(err, err_cap, "cannot initialize CT2 target lock"); return NULL;
    }
    const char *data_dir = qihse_kv_store_data_directory(ownership->store);
    bool unresolved = false;
    ct_target_recovery_t recovery = {.target = target, .failed = false};
    if (!data_dir || qihse_cluster_ownership_journal_replay_txn(
            data_dir, recover_finalized_cb, &recovery, &unresolved) < 0 ||
        recovery.failed) {
        pthread_mutex_destroy(&target->lock);
        close(fd); free(target);
        set_error(err, err_cap, "cannot recover finalized CT2 stage cleanup");
        errno = EIO; return NULL;
    }
    return target;
}

void qihse_ct_target_destroy(qihse_ct_target_t *target) {
    if (!target) return;
    pthread_mutex_destroy(&target->lock);
    if (target->dir_fd >= 0) close(target->dir_fd);
    OPENSSL_cleanse(target, sizeof(*target));
    free(target);
}

bool qihse_ct_target_begin(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_cluster_ownership_txn_t *source_txn, uint64_t total_bytes,
    const unsigned char image_sha256[32],
    const unsigned char canonical_range_sha256[32],
    uint64_t target_cut,
    uint64_t *out_resume_offset,
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (out_resume_offset) *out_resume_offset = 0;
    if (!out_resume_offset || !image_sha256 || !canonical_range_sha256 ||
        !total_bytes || total_bytes > (uint64_t)INT64_MAX ||
        !validate_peer_and_txn(target, data_principal, authenticated_source_qkp_id, source_txn)) {
        set_error(err, err_cap, "CT2 BEGIN authorization or bounds check failed"); errno = EACCES; return false;
    }
    char meta_name[80], image_name[80];
    if (!file_names(source_txn->transfer_id, meta_name, image_name)) return false;
    pthread_mutex_lock(&target->lock);
    ct_target_manifest_t m;
    bool exists = false;
    bool ok = read_manifest(target, meta_name, &m, &exists);
    if (ok && exists) {
        ok = manifest_matches_txn(&m, source_txn, total_bytes,
                                  image_sha256, canonical_range_sha256, target_cut) &&
             manifest_data_principal(&m, data_principal);
        if (ok && m.state == CT_TARGET_STATE_PREPARING) {
            /* BEGIN may have crashed after publishing its manifest but before
             * creating the empty image file. Recreate only an empty stage. */
            ok = ensure_image_file(target, image_name, true);
            if (ok) {
                m.state = CT_TARGET_STATE_RECEIVING;
                ok = store_manifest(target, meta_name, &m);
            }
        }
        if (ok) *out_resume_offset = m.offset;
    } else if (ok) {
        manifest_from_txn(&m, source_txn, data_principal, total_bytes,
                          image_sha256, canonical_range_sha256, target_cut);
        ok = store_manifest(target, meta_name, &m);
        if (ok) ok = ensure_image_file(target, image_name, true);
        if (ok) {
            m.state = CT_TARGET_STATE_RECEIVING;
            ok = store_manifest(target, meta_name, &m);
        }
        if (!ok && m.state == CT_TARGET_STATE_PREPARING) {
            /* Leave manifest and the durable fence transaction alone. A retry
             * can complete target_prepare idempotently after transient errors. */
            set_error(err, err_cap, "CT2 target is safely prepared or awaiting retry");
        }
        if (ok) *out_resume_offset = m.offset;
    }
    pthread_mutex_unlock(&target->lock);
    if (!ok && (!err || !err_cap || !err[0]))
        set_error(err, err_cap, "CT2 BEGIN tuple conflicts with durable target state");
    return ok;
}

bool qihse_ct_target_status(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const char *transfer_id, const qihse_cluster_ownership_txn_t *expected_txn,
    uint64_t expected_total_bytes, const unsigned char expected_image_sha256[32],
    const unsigned char expected_range_sha256[32], uint64_t expected_target_cut,
    uint64_t *out_offset, uint64_t *out_total_bytes,
    qihse_ct_target_state_t *out_state, char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (out_offset) *out_offset = 0;
    if (out_total_bytes) *out_total_bytes = 0;
    if (out_state) *out_state = QIHSE_CT_TARGET_ABSENT;
    if (!target || !data_authority(data_principal) || !authenticated_source_qkp_id ||
        !valid_id(transfer_id, QIHSE_OWNERSHIP_ID_MAX + 1u) || !out_offset ||
        !out_total_bytes || !out_state || (expected_txn &&
        (!validate_peer_and_txn(target, data_principal, authenticated_source_qkp_id, expected_txn) ||
         strcmp(expected_txn->transfer_id, transfer_id))) ||
        (expected_txn && (!expected_total_bytes || !expected_image_sha256 || !expected_range_sha256)) ||
        (expected_total_bytes && (!expected_image_sha256 || !expected_range_sha256))) {
        set_error(err, err_cap, "CT2 STATUS authorization failed"); errno = EACCES; return false;
    }
    char meta_name[80], image_name[80];
    if (!file_names(transfer_id, meta_name, image_name)) return false;
    pthread_mutex_lock(&target->lock);
    ct_target_manifest_t m;
    bool exists = false;
    bool ok = read_manifest(target, meta_name, &m, &exists) && exists;
    if (ok) {
        ok = !strcmp(m.source_qkp_id, authenticated_source_qkp_id) &&
             manifest_data_principal(&m, data_principal) &&
             (!expected_txn || manifest_matches_txn(&m, expected_txn,
                expected_total_bytes, expected_image_sha256, expected_range_sha256,
                expected_target_cut)) &&
             (!expected_total_bytes || (m.total_bytes == expected_total_bytes &&
                CRYPTO_memcmp(m.image_sha256, expected_image_sha256, 32) == 0 &&
                CRYPTO_memcmp(m.range_sha256, expected_range_sha256, 32) == 0));
        if (ok && m.state == CT_TARGET_STATE_RECEIVING) {
            int fd = openat(target->dir_fd, image_name,
                O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            struct stat st;
            ok = file_secure(fd, true) && fstat(fd, &st) == 0 &&
                 st.st_size >= 0 && (uint64_t)st.st_size >= m.offset;
            if (ok && (uint64_t)st.st_size > m.offset)
                ok = ftruncate(fd, (off_t)m.offset) == 0 && fdatasync(fd) == 0;
            if (fd >= 0) close(fd);
        }
        if (ok) {
            *out_offset = m.offset;
            *out_total_bytes = m.total_bytes;
            *out_state = m.state == CT_TARGET_STATE_PREPARING ? QIHSE_CT_TARGET_PREPARING :
                m.state == CT_TARGET_STATE_RECEIVING ? QIHSE_CT_TARGET_RECEIVING :
                m.state == CT_TARGET_STATE_FINALIZED ? QIHSE_CT_TARGET_FINALIZED :
                QIHSE_CT_TARGET_SEALED;
        }
    }
    pthread_mutex_unlock(&target->lock);
    if (!ok) set_error(err, err_cap, "CT2 STATUS tuple missing, conflicting, or corrupt");
    return ok;
}

bool qihse_ct_target_chunk(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const char *transfer_id, uint64_t offset, uint64_t total_bytes,
    const unsigned char image_sha256[32], const void *bytes, size_t length,
    uint64_t *out_next_offset, char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (out_next_offset) *out_next_offset = 0;
    if (!target || !data_authority(data_principal) || !authenticated_source_qkp_id ||
        !valid_id(transfer_id, QIHSE_OWNERSHIP_ID_MAX + 1u) || !image_sha256 ||
        !bytes || !length || length > CT_TARGET_MAX_CHUNK || !out_next_offset ||
        offset > total_bytes || length > total_bytes - offset ||
        total_bytes > (uint64_t)INT64_MAX) {
        set_error(err, err_cap, "CT2 CHUNK authorization or bounds check failed"); errno = EACCES; return false;
    }
    char meta_name[80], image_name[80];
    if (!file_names(transfer_id, meta_name, image_name)) return false;
    pthread_mutex_lock(&target->lock);
    ct_target_manifest_t m;
    bool exists = false;
    bool ok = read_manifest(target, meta_name, &m, &exists) && exists &&
        m.state == CT_TARGET_STATE_RECEIVING &&
        !strcmp(m.source_qkp_id, authenticated_source_qkp_id) &&
        manifest_data_principal(&m, data_principal) && m.total_bytes == total_bytes &&
        CRYPTO_memcmp(m.image_sha256, image_sha256, 32) == 0;
    int fd = -1;
    if (ok) {
        fd = openat(target->dir_fd, image_name,
            O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        ok = file_secure(fd, true);
    }
    if (ok && offset < m.offset && offset + length <= m.offset) {
        unsigned char *previous = malloc(length);
        ok = previous && pread_all(fd, previous, length, offset) &&
             CRYPTO_memcmp(previous, bytes, length) == 0;
        if (previous) { OPENSSL_cleanse(previous, length); free(previous); }
        if (ok) *out_next_offset = m.offset;
    } else if (ok && offset == m.offset) {
        ok = pwrite_all(fd, bytes, length, offset) && fdatasync(fd) == 0;
        if (ok) {
            m.offset += length;
            ok = store_manifest(target, meta_name, &m);
        }
        if (ok) *out_next_offset = m.offset;
    } else {
        ok = false;
    }
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&target->lock);
    if (!ok) set_error(err, err_cap, "CT2 CHUNK gap, conflict, or durable write failure");
    return ok;
}

static bool target_seal_locked(qihse_ct_target_t *target, qihse_user_t *data,
    const char *source_qkp, const qihse_cluster_ownership_txn_t *txn,
    uint64_t total_bytes, const unsigned char image_sha[32],
    const unsigned char range_sha[32],
    uint64_t *out_target_lsn, unsigned char out_checksum[32],
    char *err, size_t err_cap) {
    if (!validate_peer_and_txn(target, data, source_qkp, txn)) return false;
    char meta_name[80], image_name[80];
    if (!file_names(txn->transfer_id, meta_name, image_name)) return false;
    ct_target_manifest_t m;
    bool exists = false;
    if (!read_manifest(target, meta_name, &m, &exists) || !exists ||
        !manifest_matches_txn(&m, txn, total_bytes, image_sha, range_sha,
                              m.target_cut) ||
        !manifest_data_principal(&m, data)) return false;
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    bool ok = qihse_kv_ct_owner_token_get(target->ownership->store,
        target->ownership->principal, owner_token);
    if (!ok) { OPENSSL_cleanse(owner_token, sizeof(owner_token)); return false; }
    if (m.state == CT_TARGET_STATE_RECEIVING) {
        if (m.offset != m.total_bytes) {
            OPENSSL_cleanse(owner_token, sizeof(owner_token));
            set_error(err, err_cap, "CT2 SEAL requires the complete durable image"); return false;
        }
        int fd = openat(target->dir_fd, image_name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        unsigned char actual[32];
        struct stat st;
        ok = file_secure(fd, false) && fstat(fd, &st) == 0 &&
             (uint64_t)st.st_size == m.total_bytes && hash_fd(fd, m.total_bytes, actual) &&
             CRYPTO_memcmp(actual, m.image_sha256, 32) == 0;
        OPENSSL_cleanse(actual, sizeof(actual));
        if (fd >= 0) close(fd);
        char image_path[PATH_MAX];
        if (ok && snprintf(image_path, sizeof(image_path), "%s/%s", target->directory,
                           image_name) >= (int)sizeof(image_path)) ok = false;
        uint64_t target_position = 0;
        if (ok) ok = qihse_kv_ct_range_import(target->ownership->store,
            target->ownership->principal, data, txn->transfer_id,
            txn->source_qkp_id, txn->generation, txn->start, txn->end,
            txn->source_lsn, image_path, m.image_sha256, owner_token,
            &target_position);
        if (ok) {
            qihse_kv_ct_proof_t *proof = qihse_kv_ct_target_seal_create(
                target->ownership->store, target->ownership->principal, data,
                txn->transfer_id, txn->source_qkp_id, txn->target_qkp_id, txn->generation,
                txn->start, txn->end, txn->source_lsn);
            const char *id = NULL, *source = NULL, *dest = NULL, *generation = NULL;
            uint16_t first = 0, last = 0;
            uint64_t source_lsn = 0, seal_lsn = 0;
            unsigned char checksum[32] = {0};
            ok = proof && qihse_kv_ct_proof_fields(target->ownership->store,
                target->ownership->principal, data, proof, &id, &source, &dest,
                &generation, &first, &last, &source_lsn, &seal_lsn, checksum) &&
                id && source && dest && generation &&
                !strcmp(id, txn->transfer_id) && !strcmp(source, txn->source_qkp_id) &&
                !strcmp(dest, txn->target_qkp_id) && !strcmp(generation, txn->generation) &&
                first == txn->start && last == txn->end && source_lsn == txn->source_lsn &&
                seal_lsn == target_position && CRYPTO_memcmp(checksum, range_sha, 32) == 0;
            if (ok) {
                m.state = CT_TARGET_STATE_SEALED;
                m.target_lsn = seal_lsn;
                memcpy(m.seal_checksum, checksum, sizeof(checksum));
                ok = store_manifest(target, meta_name, &m);
                if (ok) {
                    *out_target_lsn = seal_lsn;
                    memcpy(out_checksum, checksum, 32);
                }
            }
            OPENSSL_cleanse(checksum, sizeof(checksum));
            if (proof) qihse_kv_ct_proof_destroy(proof);
        }
    } else if (m.state == CT_TARGET_STATE_SEALED ||
               m.state == CT_TARGET_STATE_FINALIZED) {
        *out_target_lsn = m.target_lsn;
        memcpy(out_checksum, m.seal_checksum, 32);
        ok = true;
    } else {
        ok = false;
    }
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    return ok;
}

bool qihse_ct_target_seal(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_cluster_ownership_txn_t *source_txn,
    uint64_t expected_total_bytes,
    const unsigned char expected_image_sha256[32],
    const unsigned char canonical_range_sha256[32],
    uint64_t *out_target_lsn, unsigned char out_checksum[32],
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (!target || !expected_total_bytes || !expected_image_sha256 ||
        !canonical_range_sha256 || !out_target_lsn || !out_checksum) return false;
    pthread_mutex_lock(&target->lock);
    bool ok = target_seal_locked(target, data_principal, authenticated_source_qkp_id,
        source_txn, expected_total_bytes, expected_image_sha256,
        canonical_range_sha256,
        out_target_lsn, out_checksum, err, err_cap);
    pthread_mutex_unlock(&target->lock);
    if (!ok && (!err || !err_cap || !err[0])) set_error(err, err_cap, "CT2 SEAL validation/import failed");
    return ok;
}

bool qihse_ct_target_receipt(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_cluster_ownership_txn_t *source_txn,
    const unsigned char canonical_range_sha256[32],
    uint64_t *out_target_lsn, unsigned char out_checksum[32],
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (!target || !canonical_range_sha256 || !out_target_lsn || !out_checksum ||
        !validate_peer_and_txn(target, data_principal, authenticated_source_qkp_id, source_txn)) {
        set_error(err, err_cap, "CT2 RECEIPT authorization failed"); errno = EACCES; return false;
    }
    pthread_mutex_lock(&target->lock);
    char meta_name[80], image_name[80];
    ct_target_manifest_t m;
    bool exists = false;
    bool ok = file_names(source_txn->transfer_id, meta_name, image_name) &&
        read_manifest(target, meta_name, &m, &exists) && exists &&
        (m.state == CT_TARGET_STATE_SEALED || m.state == CT_TARGET_STATE_FINALIZED) &&
        manifest_matches_txn(&m, source_txn, m.total_bytes, m.image_sha256,
                             canonical_range_sha256, m.target_cut) &&
        manifest_data_principal(&m, data_principal);
    if (ok) {
        qihse_kv_ct_proof_t *proof = qihse_kv_ct_target_seal_create(
            target->ownership->store, target->ownership->principal, data_principal,
            source_txn->transfer_id, source_txn->source_qkp_id, source_txn->target_qkp_id,
            source_txn->generation, source_txn->start, source_txn->end,
            source_txn->source_lsn);
        const char *id = NULL, *source = NULL, *dest = NULL, *generation = NULL;
        uint16_t first = 0, last = 0;
        uint64_t source_lsn = 0, target_lsn = 0;
        unsigned char checksum[32] = {0};
        ok = proof && qihse_kv_ct_proof_fields(target->ownership->store,
            target->ownership->principal, data_principal, proof, &id, &source, &dest, &generation,
            &first, &last, &source_lsn, &target_lsn, checksum) &&
            id && source && dest && generation &&
            !strcmp(id, source_txn->transfer_id) && !strcmp(source, source_txn->source_qkp_id) &&
            !strcmp(dest, source_txn->target_qkp_id) && !strcmp(generation, source_txn->generation) &&
            first == source_txn->start && last == source_txn->end &&
            source_lsn == source_txn->source_lsn && target_lsn == m.target_lsn &&
            CRYPTO_memcmp(checksum, m.seal_checksum, 32) == 0 &&
            CRYPTO_memcmp(checksum, canonical_range_sha256, 32) == 0;
        if (ok) {
            *out_target_lsn = target_lsn;
            memcpy(out_checksum, checksum, 32);
        }
        OPENSSL_cleanse(checksum, sizeof(checksum));
        if (proof) qihse_kv_ct_proof_destroy(proof);
    }
    pthread_mutex_unlock(&target->lock);
    if (!ok) set_error(err, err_cap, "CT2 sealed receipt is unavailable or mismatched");
    return ok;
}

bool qihse_ct_target_cleanup_aborted(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_resp_ct_abort_request_t *request,
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    const char *transfer = NULL, *topology_source = NULL, *topology_target = NULL;
    const char *qkp_source = NULL, *qkp_target = NULL, *generation = NULL;
    uint16_t first = 0, last = 0;
    uint64_t source_lsn = 0, config_epoch = 0;
    unsigned char range_sha[32] = {0};
    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    bool parsed = request && qihse_resp_ct_abort_request_fields(request,
        &transfer, &topology_source, &topology_target, &qkp_source, &qkp_target,
        &generation, &first, &last, &source_lsn, &config_epoch, range_sha) &&
        transfer && topology_source && topology_target && qkp_source && qkp_target &&
        generation && source_lsn && config_epoch && first <= last &&
        last < QIHSE_CLUSTER_SLOT_COUNT;
    if (parsed) {
        txn.phase = QIHSE_OWNERSHIP_PREPARED; /* for durable stage tuple matching */
        snprintf(txn.transfer_id, sizeof(txn.transfer_id), "%s", transfer);
        snprintf(txn.source_id, sizeof(txn.source_id), "%s", topology_source);
        snprintf(txn.target_id, sizeof(txn.target_id), "%s", topology_target);
        snprintf(txn.owner_id, sizeof(txn.owner_id), "%s", topology_source);
        snprintf(txn.source_qkp_id, sizeof(txn.source_qkp_id), "%s", qkp_source);
        snprintf(txn.target_qkp_id, sizeof(txn.target_qkp_id), "%s", qkp_target);
        snprintf(txn.generation, sizeof(txn.generation), "%s", generation);
        txn.start = first; txn.end = last;
        txn.source_lsn = source_lsn; txn.config_epoch = config_epoch;
    }
    if (!target || !data_authority(data_principal) ||
        !authenticated_source_qkp_id || !parsed ||
        strcmp(qkp_source, authenticated_source_qkp_id) ||
        !validate_peer_and_txn(target, data_principal,
                               authenticated_source_qkp_id, &txn)) {
        OPENSSL_cleanse(range_sha, sizeof(range_sha));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "CT2 ABORT cleanup requires the authenticated source ABORT request");
        errno = EACCES;
        return false;
    }

    char meta_name[80], image_name[80];
    ct_target_manifest_t m;
    bool exists = false;
    pthread_mutex_lock(&target->lock);
    bool ok = file_names(transfer, meta_name, image_name) &&
        read_manifest(target, meta_name, &m, &exists);
    if (ok && exists) {
        ok = manifest_data_principal(&m, data_principal) &&
            manifest_matches_txn(&m, &txn, m.total_bytes,
                                 m.image_sha256, range_sha, m.target_cut) &&
            m.state != CT_TARGET_STATE_SEALED;
        /* The RESP engine calls this only after the ownership abort handler
         * has proven source ABORTED and released the target fence. */
        if (ok) {
            if (unlinkat(target->dir_fd, image_name, 0) != 0 && errno != ENOENT)
                ok = false;
            if (ok && unlinkat(target->dir_fd, meta_name, 0) != 0 && errno != ENOENT)
                ok = false;
            if (ok) ok = fsync(target->dir_fd) == 0;
        }
    }
    pthread_mutex_unlock(&target->lock);
    OPENSSL_cleanse(range_sha, sizeof(range_sha));
    OPENSSL_cleanse(&txn, sizeof(txn));
    if (!ok) set_error(err, err_cap, "CT2 aborted transfer stage is corrupt or cannot be removed safely");
    return ok;
}

typedef struct {
    qihse_cluster_ownership_txn_t expected;
    bool found;
} ct_target_finalized_find_t;

static bool find_finalized_txn_cb(const qihse_cluster_ownership_txn_t *txn,
                                  void *opaque) {
    ct_target_finalized_find_t *find = opaque;
    if (!txn || txn->phase != QIHSE_OWNERSHIP_FINALIZED ||
        strcmp(txn->transfer_id, find->expected.transfer_id)) return true;
    find->found = txn->start == find->expected.start && txn->end == find->expected.end &&
        txn->config_epoch == find->expected.config_epoch &&
        txn->source_lsn == find->expected.source_lsn &&
        txn->target_lsn == find->expected.target_lsn &&
        !strcmp(txn->source_id, find->expected.source_id) &&
        !strcmp(txn->target_id, find->expected.target_id) &&
        !strcmp(txn->source_qkp_id, find->expected.source_qkp_id) &&
        !strcmp(txn->target_qkp_id, find->expected.target_qkp_id) &&
        !strcmp(txn->generation, find->expected.generation) &&
        CRYPTO_memcmp(txn->proof_digest, find->expected.proof_digest, 32) == 0;
    return true;
}

bool qihse_ct_target_finalize(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_resp_ct_activation_request_t *request,
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    const char *transfer = NULL, *topology_source = NULL, *topology_target = NULL;
    const char *qkp_source = NULL, *qkp_target = NULL, *generation = NULL;
    uint16_t first = 0, last = 0;
    uint64_t source_lsn = 0, config_epoch = 0, target_lsn = 0;
    unsigned char checksum[32] = {0};
    qihse_cluster_ownership_txn_t finalized;
    memset(&finalized, 0, sizeof(finalized));
    bool parsed = target && data_principal && request &&
        qihse_auth_user_is_active(data_principal) &&
        qihse_auth_can_access(data_principal, UINT16_MAX, UINT16_MAX) &&
        qihse_resp_ct_activation_request_fields(request, &transfer,
            &topology_source, &topology_target, &qkp_source, &qkp_target,
            &generation, &first, &last, &source_lsn, &config_epoch,
            &target_lsn, checksum) && transfer && topology_source && topology_target &&
        qkp_source && qkp_target && generation && source_lsn && config_epoch &&
        target_lsn && first <= last && last < QIHSE_CLUSTER_SLOT_COUNT &&
        authenticated_source_qkp_id &&
        !strcmp(authenticated_source_qkp_id, qkp_source) &&
        !strcmp(target->local_qkp_id, qkp_target) &&
        !strcmp(target->local_topology_id, topology_target);
    if (!parsed) {
        OPENSSL_cleanse(checksum, sizeof(checksum));
        set_error(err, err_cap, "CT2 FINALIZE authorization or tuple failed");
        errno = EACCES; return false;
    }
    finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    finalized.start = first; finalized.end = last;
    finalized.source_lsn = source_lsn; finalized.target_lsn = target_lsn;
    finalized.config_epoch = config_epoch;
    memcpy(finalized.proof_digest, checksum, sizeof(checksum));
    snprintf(finalized.transfer_id, sizeof(finalized.transfer_id), "%s", transfer);
    snprintf(finalized.source_id, sizeof(finalized.source_id), "%s", topology_source);
    snprintf(finalized.target_id, sizeof(finalized.target_id), "%s", topology_target);
    snprintf(finalized.owner_id, sizeof(finalized.owner_id), "%s", topology_target);
    snprintf(finalized.source_qkp_id, sizeof(finalized.source_qkp_id), "%s", qkp_source);
    snprintf(finalized.target_qkp_id, sizeof(finalized.target_qkp_id), "%s", qkp_target);
    snprintf(finalized.generation, sizeof(finalized.generation), "%s", generation);

    const char *data_dir = qihse_kv_store_data_directory(target->ownership->store);
    ct_target_finalized_find_t find = {.expected = finalized, .found = false};
    bool unresolved = false;
    bool journal_ok = data_dir && qihse_cluster_ownership_journal_replay_txn(
        data_dir, find_finalized_txn_cb, &find, &unresolved) >= 0 && find.found;
    pthread_mutex_lock(&target->lock);
    bool ok = journal_ok && finalize_stage_for_txn(target, &finalized);
    pthread_mutex_unlock(&target->lock);
    OPENSSL_cleanse(checksum, sizeof(checksum));
    OPENSSL_cleanse(&finalized, sizeof(finalized));
    if (!ok) set_error(err, err_cap, "CT2 FINALIZE lacks matching durable ownership proof or cleanup failed");
    return ok;
}
