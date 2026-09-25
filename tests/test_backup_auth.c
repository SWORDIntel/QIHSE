/*
 * test_backup_auth.c — the AUTHENTICATED federation backup writer.
 *
 * This is the fix for the tracked known boundary "the container is
 * integrity-checked but not authenticated (fix: sign with the F5 node key)".
 * The container written by qihse_backup_write_signed() carries the signer's
 * node id, the fingerprint of the enrolled public key, the algorithm id and
 * the signature length — never key material — and a detached signature over
 * the whole fixed header, which itself carries the manifest checksum and the
 * data section's SHA-384.
 *
 * The container is the v3 form: [ header 464 ][ signature ][ data section ]
 * [ WAL section ].  The signature covers the whole header, which carries the
 * manifest checksum, the data section's SHA-384 and the WAL section's
 * SHA-384, length and LSN range — so the same detached signature
 * authenticates the post-snapshot WAL segment, and a tampered WAL byte is
 * refused before any WAL byte is applied.
 *
 * The test is organised around what the authenticated surface must refuse:
 *
 *   - happy path: write signed, verify (verify-only entry point), drift,
 *     restore verified; the signer fields are the enrolled identity's
 *   - negative cases, each asserting refusal with NOTHING applied and no
 *     protected payload bytes materialised:
 *       bit-flip in the data section, bit-flip in the signature,
 *       stripped signature, wrong-signer key (valid key, not the signer),
 *       revoked signer
 *   - the WAL section: verify checks it without applying it; a tampered WAL
 *     byte, a truncated or mid-record WAL tail and a digest mismatch are
 *     refused before anything is applied; a wrong-version container (the
 *     retired v1/v2 forms) is refused by version, never downgraded
 *   - an absent, unenrolled, pending or keyless signer FAILS the write:
 *     no unsigned container, no scratch file, nothing at the path
 *   - the operator override skips ONLY the signature gate: it restores a
 *     revoked-signer container for an operator, still refuses a
 *     checksum-tampered one, and a guest cannot raise it at all
 *   - a low-clearance principal is denied by the KV layer's classification
 *     gate even though the signature verifies (AGENTS.md invariant 3: the
 *     negative authorisation test for this new reachable surface)
 *   - NULL is an argument error on every entry point (invariant 1); a v1
 *     (unsigned) container is refused by the signed paths (invariant: fail
 *     closed by default)
 */
#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"
/* For the WAL record composition: the section's per-record CRC uses the
 * tractable WAL's own CRC primitive and XOR composition. */
#include "qihse_wal.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;    /* OPERATOR: 0xFFFF clearance, all compartments */
static qihse_user_t* g_guest; /* GUEST: clearance 0, no compartments */

static char g_dir[512];      /* backup artefacts (relative, repo-local) */
static char g_key_dir[576];  /* node private keys (relative, repo-local) */

/* Node A signs the backups.  Node B is a valid, approved, DIFFERENT signer
 * used for the wrong-signer-key case.  Node C is enrolled but PENDING.  Node
 * D is approved but its key file is removed. */
static qihse_federation_node_identity_t g_node_a;
static qihse_federation_node_identity_t g_node_b;
static qihse_federation_node_identity_t g_node_pending;
static qihse_federation_node_identity_t g_node_keyless;

#define PUBLIC_ALPHA_VALUE "alpha-payload-AAAA"
#define SECRET_GAMMA_VALUE "GAMMA-CLASSIFIED-PAYLOAD"
#define SECRET_DELTA_VALUE "DELTA-CLASSIFIED-PAYLOAD"
#define SECRET_GAMMA_KEY   "secret:gamma"
#define SECRET_DELTA_KEY   "secret:delta"

/* ── File helpers (mirrors tests/test_federation_backup.c) ─────────────── */

static void test_path(char* out, size_t cap, const char* name) {
    int n = snprintf(out, cap, "%s/%s", g_dir, name);
    assert(n > 0 && (size_t)n < cap);
}

static uint8_t* slurp(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    assert(fseek(f, 0L, SEEK_END) == 0);
    long size = ftell(f);
    assert(size >= 0);
    assert(fseek(f, 0L, SEEK_SET) == 0);
    uint8_t* buf = (uint8_t*)malloc((size_t)size + 1u);
    assert(buf);
    assert(fread(buf, 1u, (size_t)size, f) == (size_t)size);
    assert(fclose(f) == 0);
    buf[size] = '\0';
    if (out_len) *out_len = (size_t)size;
    return buf;
}

static void spit(const char* path, const uint8_t* data, size_t len) {
    FILE* f = fopen(path, "wb");
    assert(f);
    assert(fwrite(data, 1u, len, f) == len);
    assert(fclose(f) == 0);
}

static bool buffer_holds(const uint8_t* hay, size_t hay_len,
                         const char* needle) {
    size_t n = strlen(needle);
    if (n == 0u || hay_len < n) return false;
    for (size_t i = 0; i + n <= hay_len; i++) {
        if (memcmp(hay + i, needle, n) == 0) return true;
    }
    return false;
}

static bool buffer_holds_bytes(const uint8_t* hay, size_t hay_len,
                               const uint8_t* needle, size_t needle_len) {
    if (needle_len == 0u || hay_len < needle_len) return false;
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) return true;
    }
    return false;
}

static bool file_holds(const char* path, const char* needle) {
    size_t len = 0u;
    uint8_t* data = slurp(path, &len);
    if (!data) return false;
    bool found = buffer_holds(data, len, needle);
    free(data);
    return found;
}

/* No scratch or partial container may survive a refusal. */
static bool dir_has_entry_containing(const char* dir, const char* needle) {
    DIR* d = opendir(dir);
    if (!d) return false;
    bool found = false;
    struct dirent* entry;
    while (!found && (entry = readdir(d)) != NULL) {
        if (strstr(entry->d_name, needle) != NULL) found = true;
    }
    closedir(d);
    return found;
}

static void put(qihse_user_t* user, const char* key, const char* value,
                uint16_t classif, uint16_t sci) {
    assert(qihse_kv_set_user(g_store, key, value, classif, sci, user));
}

static bool can_read(qihse_user_t* user, const char* key) {
    char* v = qihse_kv_get_user(g_store, key, user);
    if (!v) return false;
    free(v);
    return true;
}

static void read_is(qihse_user_t* user, const char* key, const char* expect) {
    char* v = qihse_kv_get_user(g_store, key, user);
    assert(v != NULL);
    assert(strcmp(v, expect) == 0);
    free(v);
}

static void make_manifest(qihse_snapshot_manifest_t* m, uint64_t wal_offset,
                          const char* key_id) {
    memset(m, 0, sizeof(*m));
    assert(qihse_uuid_generate(&m->snapshot_id));
    m->kind = QIHSE_SNAPSHOT_COORDINATED;
    assert(qihse_uuid_from_seed("backup-auth-test-cluster",
                                strlen("backup-auth-test-cluster"),
                                &m->cluster_id));
    assert(qihse_uuid_generate(&m->created_by));
    m->created_hlc_physical = 1710000000000ULL;
    qihse_schema_header_init(&m->schema, QIHSE_SCHEMA_ID_FEDERATION, 1);
    m->max_generation = 2909;
    m->wal_continuation_offset = wal_offset;
    if (key_id) snprintf(m->encryption_key_id, sizeof(m->encryption_key_id), "%s", key_id);
    m->group_count = 1;
    snprintf(m->groups[0], sizeof(m->groups[0]), "core-security");
    m->object_count = (uint64_t)qihse_kv_count_user(g_store, g_op);
}

/* Zeroed on every failure, signer and WAL fields included: a refused call
 * hands back nothing that could be mistaken for a result. */
static bool desc_is_zeroed(const qihse_backup_descriptor_t* d) {
    static const uint8_t zeros[48] = {0};
    if (!qihse_uuid_is_nil(&d->snapshot_id)) return false;
    if (d->wal_continuation_offset != 0u || d->max_generation != 0u) return false;
    if (d->object_count != 0u || d->data_bytes != 0u) return false;
    if (memcmp(d->data_checksum, zeros, 48u) != 0) return false;
    if (memcmp(d->manifest_checksum, zeros, 48u) != 0) return false;
    if (d->encryption_key_id[0] != '\0') return false;
    if (!qihse_uuid_is_nil(&d->signer_node)) return false;
    if (memcmp(d->signer_fingerprint, zeros, 48u) != 0) return false;
    if (d->wal_bytes != 0u) return false;
    if (memcmp(d->wal_checksum, zeros, 48u) != 0) return false;
    if (d->wal_first_lsn != 0u || d->wal_last_lsn != 0u) return false;
    return true;
}

/* The container layout: [ v3 header 464 ][ signature ][ data section ]
 * [ WAL section ]. */
static size_t sig_fixed_bytes(void) {
    return qihse_sig_alg_signature_bytes(QIHSE_SIG_ML_DSA_87);
}

/* Build one WAL-section record in the container's record format: the
 * tractable WAL's CRC primitive and XOR composition, extended over the
 * classification fields (see src/federation/qihse_backup.c).  Mirrors the
 * encoder exactly so the writer's validator accepts what this builds. */
static size_t wal_build_record(uint8_t* out, size_t cap,
                               uint64_t lsn, uint64_t txn_id, uint8_t op,
                               uint16_t classif, uint16_t sci,
                               const void* key, uint32_t key_len,
                               const void* val, uint32_t val_len) {
    assert(cap >= QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES + (size_t)key_len + (size_t)val_len);
    uint8_t engine = 0u;
    uint16_t reserved = 0u;
    uint32_t crc = 0u;
    memcpy(out + 0u, &lsn, 8u);
    memcpy(out + 8u, &txn_id, 8u);
    out[16u] = engine;
    out[17u] = op;
    memcpy(out + 18u, &classif, 2u);
    memcpy(out + 20u, &sci, 2u);
    memcpy(out + 22u, &key_len, 4u);
    memcpy(out + 26u, &val_len, 4u);
    memcpy(out + 30u, &reserved, 2u);
    if (key_len > 0u) memcpy(out + 36u, key, key_len);
    if (val_len > 0u) memcpy(out + 36u + key_len, val, val_len);
    crc ^= qihse_wal_crc32(&lsn, 8u);
    crc ^= qihse_wal_crc32(&txn_id, 8u);
    crc ^= qihse_wal_crc32(&engine, 1u);
    crc ^= qihse_wal_crc32(&op, 1u);
    crc ^= qihse_wal_crc32(&classif, 2u);
    crc ^= qihse_wal_crc32(&sci, 2u);
    crc ^= qihse_wal_crc32(&key_len, 4u);
    crc ^= qihse_wal_crc32(&val_len, 4u);
    crc ^= qihse_wal_crc32(&reserved, 2u);
    if (key_len > 0u && key) crc ^= qihse_wal_crc32(key, key_len);
    if (val_len > 0u && val) crc ^= qihse_wal_crc32(val, val_len);
    memcpy(out + 32u, &crc, 4u);
    return QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES + (size_t)key_len + (size_t)val_len;
}

static void make_node(qihse_federation_node_identity_t* id, const char* seed,
                      const char* hostname) {
    memset(id, 0, sizeof(*id));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &id->node_id));
    snprintf(id->hostname, sizeof(id->hostname), "%s", hostname);
    snprintf(id->boot_id, sizeof(id->boot_id), "boot-0001");
    id->identity_kind = QIHSE_IDENTITY_BACKUP_AGENT;
    /* ML-DSA-87 is the default for new node identities (CNSA 2.0).  The
     * private key is written to the key directory, 0600, and only the public
     * key and the handle come back. */
    assert(qihse_federation_node_keygen_alg(g_key_dir, QIHSE_SIG_ML_DSA_87, id));
    assert(id->sig_alg == QIHSE_SIG_ML_DSA_87);
    assert(id->public_key_len ==
           (uint16_t)qihse_sig_alg_public_key_bytes(QIHSE_SIG_ML_DSA_87));
}

/* ── Vocabulary ────────────────────────────────────────────────────────── */

static void test_result_vocabulary(void) {
    for (int i = 0; i <= (int)QIHSE_BACKUP_ERR_VERSION; i++) {
        const char* name = qihse_backup_result_name((qihse_backup_result_t)i);
        assert(name != NULL);
        assert(strcmp(name, "unknown") != 0);
    }
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_SIGNER), "signer") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_SIGNATURE), "signature") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_VERSION), "version") == 0);
    assert(strcmp(qihse_backup_result_name((qihse_backup_result_t)999), "unknown") == 0);
    printf("PASS backup-auth vocabulary: signer, signature and version results "
           "are named\n");
}

/* ── The signer must be enrolled, approved and keyful ──────────────────── */

static void test_write_requires_enrolled_signer(void) {
    char path[512];
    test_path(path, sizeof(path), "no-signer.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, 700001ULL, "key-handle:citadel-a");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_backup_descriptor_t desc;

    /* NULL signer node is an argument error. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, NULL, path, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));

    /* A nil signer node names no identity at all: that is an absent signer,
     * not an argument-shaped NULL pointer, so it takes the signer error. */
    qihse_uuid_t nil_id;
    memset(&nil_id, 0, sizeof(nil_id));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &nil_id, path, &desc) ==
           QIHSE_BACKUP_ERR_SIGNER);
    assert(desc_is_zeroed(&desc));

    /* A random, unenrolled node id fails the write with the clear error. */
    qihse_uuid_t stranger;
    assert(qihse_uuid_generate(&stranger));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &stranger, path, &desc) ==
           QIHSE_BACKUP_ERR_SIGNER);
    assert(desc_is_zeroed(&desc));

    /* Enrolled but still PENDING: not admissible, so not a signer either. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node_pending.node_id,
                                     path, &desc) == QIHSE_BACKUP_ERR_SIGNER);
    assert(desc_is_zeroed(&desc));

    /* Approved, but the private key file is gone: the handle resolves to
     * nothing, and a backup without a loadable key is refused. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node_keyless.node_id,
                                     path, &desc) == QIHSE_BACKUP_ERR_SIGNER);
    assert(desc_is_zeroed(&desc));

    /* No container, no scratch file: an unauthenticated backup never exists
     * on disk, not even briefly. */
    assert(access(path, F_OK) != 0);
    assert(!dir_has_entry_containing(g_dir, ".data."));
    assert(!dir_has_entry_containing(g_dir, ".tmp."));

    printf("PASS signer gate: absent, unenrolled, pending and keyless "
           "identities all fail the write with no container and no scratch\n");
}

/* ── Happy path: write signed, verify, restore verified ────────────────── */

static void test_happy_path(void) {
    char path[512];
    test_path(path, sizeof(path), "happy.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, 88123456ULL, "key-handle:citadel-a");
    uint64_t declared = m.object_count;
    assert(declared >= 4u);
    assert(qihse_snapshot_record(g_store, g_op, &m));

    uint64_t expected_captured = (uint64_t)qihse_kv_count_user(g_store, g_op);

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node_a.node_id,
                                     path, &desc) == QIHSE_BACKUP_OK);

    /* The descriptor names the enrolled signer — fingerprint, algorithm, node
     * id — and nothing else new. */
    assert(qihse_uuid_equal(&desc.signer_node, &g_node_a.node_id));
    assert(desc.sig_alg == QIHSE_SIG_ML_DSA_87);
    assert(memcmp(desc.signer_fingerprint, g_node_a.fingerprint, 48u) == 0);
    assert(qihse_uuid_equal(&desc.snapshot_id, &m.snapshot_id));
    assert(desc.wal_continuation_offset == 88123456ULL);
    assert(desc.object_count == expected_captured);
    assert(memcmp(desc.manifest_checksum, m.checksum, 48u) == 0);
    assert(strcmp(desc.encryption_key_id, "key-handle:citadel-a") == 0);

    /* [ v3 header ][ signature ][ data ][ WAL (absent) ]: the file is exactly
     * that, and the no-segment form reports a zeroed WAL block. */
    struct stat st;
    assert(stat(path, &st) == 0);
    assert((uint64_t)st.st_size ==
           QIHSE_BACKUP_HEADER_WAL_BYTES + (uint64_t)sig_fixed_bytes() + desc.data_bytes);
    assert(desc.wal_bytes == 0u && desc.wal_first_lsn == 0u && desc.wal_last_lsn == 0u);
    assert((st.st_mode & 0777u) == 0600u);

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    /* The operator's signed backup really does carry the protected payload —
     * this is what makes the absence assertions in the denial tests
     * meaningful. */
    assert(buffer_holds(bytes, len, SECRET_GAMMA_VALUE));
    /* ... and never key material: no PEM, and the signer's raw public key is
     * not in the container either — the fingerprint is. */
    assert(!buffer_holds(bytes, len, "-----BEGIN"));
    assert(!buffer_holds_bytes(bytes, len, g_node_a.public_key,
                               (size_t)g_node_a.public_key_len));
    free(bytes);

    /* The verify-only entry point authenticates the container without
     * restoring it: structure, signature against the enrolled signer, and
     * the data checksum over a streamed read. */
    qihse_backup_descriptor_t verified;
    memset(&verified, 0xAB, sizeof(verified));
    assert(qihse_backup_verify(g_store, g_op, path, &verified) == QIHSE_BACKUP_OK);
    assert(qihse_uuid_equal(&verified.signer_node, &g_node_a.node_id));
    assert(verified.sig_alg == QIHSE_SIG_ML_DSA_87);
    assert(memcmp(verified.signer_fingerprint, g_node_a.fingerprint, 48u) == 0);
    assert(memcmp(verified.data_checksum, desc.data_checksum, 48u) == 0);
    assert(verified.data_bytes == desc.data_bytes);
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* Drift, then a verified restore. */
    put(g_op, "public:post-snapshot", "post-snapshot-value", 0, 0);
    assert(qihse_kv_del_user(g_store, "public:alpha", g_op));

    qihse_backup_descriptor_t restored;
    memset(&restored, 0xAB, sizeof(restored));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &restored) ==
           QIHSE_BACKUP_OK);
    assert(qihse_uuid_equal(&restored.signer_node, &g_node_a.node_id));
    assert(restored.wal_continuation_offset == 88123456ULL);
    assert(!can_read(g_op, "public:post-snapshot"));
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);
    read_is(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE);
    read_is(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE);
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    printf("PASS happy path: write signed with the enrolled identity, verify "
           "without restoring, restore verified; signer recorded by "
           "fingerprint, never key material\n");
}

/* ── Negative cases: refused with NOTHING applied ──────────────────────── */

/* A sentinel written after the backup: if a refused restore applied anything
 * at all, the sentinel would disappear. */
static void prime_sentinel(void) {
    put(g_op, "public:sentinel", "sentinel-value", 0, 0);
}

static void write_signed_container(const char* name,
                                   qihse_snapshot_manifest_t* m_out,
                                   char* path_out, size_t path_cap,
                                   qihse_backup_descriptor_t* desc_out) {
    int n = snprintf(path_out, path_cap, "%s/%s", g_dir, name);
    assert(n > 0 && (size_t)n < path_cap);
    make_manifest(m_out, 600613ULL + (uint64_t)(unsigned char)name[0],
                  "key-handle:citadel-a");
    assert(qihse_snapshot_record(g_store, g_op, m_out));
    memset(desc_out, 0xAB, sizeof(*desc_out));
    assert(qihse_backup_write_signed(g_store, g_op, m_out, &g_node_a.node_id,
                                     path_out, desc_out) == QIHSE_BACKUP_OK);
}

/* 1. A byte flipped inside the DATA section: the signature covers the header
 *    (which carries the data digest), so the flip is caught by the checksum
 *    comparison over the bytes that are about to be applied. */
static void test_bitflip_in_data(void) {
    char path[512], tampered[512];
    qihse_snapshot_manifest_t m;
    qihse_backup_descriptor_t desc;
    write_signed_container("flip-data.bak", &m, path, sizeof(path), &desc);
    test_path(tampered, sizeof(tampered), "flip-data-tampered.bak");

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    size_t data_off = QIHSE_BACKUP_HEADER_WAL_BYTES + sig_fixed_bytes();
    assert(len > data_off + 8u);
    bytes[data_off + 4u] ^= 0x40u;
    spit(tampered, bytes, len);
    free(bytes);

    prime_sentinel();
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_CHECKSUM);
    assert(desc_is_zeroed(&out));
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_CHECKSUM);
    assert(desc_is_zeroed(&out));
    /* Nothing was applied and no scratch survived. */
    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    unlink(tampered);

    printf("PASS bit-flip in data: refused by the checksum, verify and "
           "restore, nothing applied, no scratch\n");
}

/* 2. A byte flipped inside the SIGNATURE: the header is intact and parses,
 *    but the signature no longer verifies under the signer's enrolled key. */
static void test_bitflip_in_signature(void) {
    char path[512], tampered[512];
    qihse_snapshot_manifest_t m;
    qihse_backup_descriptor_t desc;
    write_signed_container("flip-sig.bak", &m, path, sizeof(path), &desc);
    test_path(tampered, sizeof(tampered), "flip-sig-tampered.bak");

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    assert(len > QIHSE_BACKUP_HEADER_WAL_BYTES + 16u);
    bytes[QIHSE_BACKUP_HEADER_WAL_BYTES + 10u] ^= 0x01u;
    spit(tampered, bytes, len);
    free(bytes);

    prime_sentinel();
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    unlink(tampered);

    printf("PASS bit-flip in signature: refused before any payload byte is "
           "read, nothing applied\n");
}

/* 3. A stripped signature: with the trailer partly removed or gone entirely
 *    (data intact), the declared signature length no longer agrees with the
 *    bytes present, which is a truncation. */
static void test_stripped_signature(void) {
    char path[512], tampered[512];
    qihse_snapshot_manifest_t m;
    qihse_backup_descriptor_t desc;
    write_signed_container("stripped.bak", &m, path, sizeof(path), &desc);
    test_path(tampered, sizeof(tampered), "stripped-tampered.bak");

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    size_t sig = sig_fixed_bytes();

    prime_sentinel();
    qihse_backup_descriptor_t out;

    /* Partly stripped: 100 signature bytes of 4627 remain. */
    spit(tampered, bytes, QIHSE_BACKUP_HEADER_WAL_BYTES + 100u);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&out));

    /* Fully stripped: the data section is intact but the signature is gone. */
    spit(tampered, bytes, len - sig);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&out));

    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    free(bytes);
    unlink(tampered);

    printf("PASS stripped signature: partly and fully stripped trailers are "
           "truncations, nothing applied\n");
}

/* 4. Wrong-signer key: a VALID approved node's key re-signs the container,
 *    while the header still records the real signer.  The signature fails
 *    under the recorded signer's enrolled key — a signature is a claim about
 *    WHO signed, not just THAT someone did. */
static void test_wrong_signer_key(void) {
    char path[512], tampered[512];
    qihse_snapshot_manifest_t m;
    qihse_backup_descriptor_t desc;
    write_signed_container("wrong-signer.bak", &m, path, sizeof(path), &desc);
    test_path(tampered, sizeof(tampered), "wrong-signer-tampered.bak");

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    size_t sig = sig_fixed_bytes();

    /* Node B is enrolled and approved — a perfectly valid key, just not the
     * key the container names.  Re-sign the intact header with it. */
    void* b_key = qihse_federation_node_key_load(g_node_b.key_handle);
    assert(b_key != NULL);
    uint8_t* forged = (uint8_t*)malloc(sig);
    assert(forged != NULL);
    size_t forged_len = sig;
    assert(qihse_federation_sign(b_key, bytes, QIHSE_BACKUP_HEADER_WAL_BYTES,
                                 forged, &forged_len));
    assert(forged_len == sig);
    qihse_federation_node_key_free(b_key);
    memcpy(bytes + QIHSE_BACKUP_HEADER_WAL_BYTES, forged, sig);
    free(forged);
    spit(tampered, bytes, len);
    free(bytes);

    prime_sentinel();
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    unlink(tampered);

    printf("PASS wrong-signer key: a valid foreign key re-signing the header "
           "is refused, nothing applied\n");
}

/* 5. Revoked signer: the container was legitimately written while node A was
 *    approved; the revocation happens afterwards.  Read time re-checks the
 *    trust state (the way admissible capability lookups do), so the container
 *    stops being acceptable immediately — unless an operator says otherwise.
 */
static void test_revoked_signer(void) {
    char path[512];
    qihse_snapshot_manifest_t m;
    qihse_backup_descriptor_t desc;
    /* Earlier tests left their sentinels in the live dataset; drop them so
     * the sentinel primed below is genuinely POST-capture drift for THIS
     * container (a restore of this snapshot must remove it). */
    assert(qihse_kv_del_user(g_store, "public:sentinel", g_op));
    write_signed_container("revoked.bak", &m, path, sizeof(path), &desc);

    /* Revoke the signer. */
    assert(qihse_federation_node_revoke(g_store, g_op, &g_node_a.node_id));

    prime_sentinel();
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, path, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* A revoked signer cannot write a new backup either. */
    char fresh_path[512];
    test_path(fresh_path, sizeof(fresh_path), "revoked-fresh.bak");
    qihse_snapshot_manifest_t fresh;
    make_manifest(&fresh, 700009ULL, NULL);
    assert(qihse_snapshot_record(g_store, g_op, &fresh));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &fresh, &g_node_a.node_id,
                                     fresh_path, &desc) == QIHSE_BACKUP_ERR_SIGNER);
    assert(access(fresh_path, F_OK) != 0);

    /* The operator override restores the intact revoked-signer container:
     * the override skips ONLY the signature/trust gate. */
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, true, &out) ==
           QIHSE_BACKUP_OK);
    assert(qihse_uuid_equal(&out.signer_node, &g_node_a.node_id));
    assert(!can_read(g_op, "public:sentinel"));   /* the restore really ran */

    /* The override is not a free pass: a checksum-tampered container is
     * STILL refused under it, because the integrity gate is independent. */
    char tampered[512];
    test_path(tampered, sizeof(tampered), "revoked-tampered.bak");
    put(g_op, "public:post-override", "post-override-value", 0, 0);
    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    bytes[len - 1u] ^= 0x01u;   /* a byte of the data section */
    spit(tampered, bytes, len);
    free(bytes);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, true, &out) ==
           QIHSE_BACKUP_ERR_CHECKSUM);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:post-override"));
    unlink(tampered);

    /* And a guest cannot raise the override at all. */
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, path, true, &out) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&out));

    printf("PASS revoked signer: refused on read and on write after "
           "revocation; operator override restores the intact container but "
           "not a tampered one, and a guest cannot raise it\n");
}

/* ── Low clearance: classification gates are independent of the signature ─ */

static void test_low_clearance_denied(void) {
    char op_path[512], guest_dir[512], guest_path[512], legacy_path[512];
    test_path(op_path, sizeof(op_path), "negative-operator.bak");
    test_path(guest_dir, sizeof(guest_dir), "negative-guest-dir");
    test_path(legacy_path, sizeof(legacy_path), "legacy-unsigned.bak");
    assert(mkdir(guest_dir, 0700) == 0);
    int n = snprintf(guest_path, sizeof(guest_path), "%s/guest.bak", guest_dir);
    assert(n > 0 && (size_t)n < sizeof(guest_path));

    /* Node B signs this one (node A is revoked by now). */
    qihse_snapshot_manifest_t m;
    make_manifest(&m, 600777ULL, "key-handle:citadel-b");
    assert(qihse_snapshot_record(g_store, g_op, &m));
    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node_b.node_id,
                                     op_path, &desc) == QIHSE_BACKUP_OK);
    assert(file_holds(op_path, SECRET_GAMMA_VALUE));
    assert(file_holds(op_path, SECRET_DELTA_VALUE));

    /* The signature verifies for the guest (the container is authentic —
     * that is a fact about the container, not a grant of its payload), but
     * the KV layer refuses the whole load because the dataset holds records
     * above the guest's clearance.  The override changes nothing here: the
     * guest may not raise it, and even an operator-raised override would
     * still meet the same classification gate. */
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));
    assert(!can_read(g_guest, SECRET_DELTA_KEY));
    put(g_op, "public:guest-sentinel", "guest-sentinel-value", 0, 0);

    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_guest, op_path, &out) == QIHSE_BACKUP_OK);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, op_path, false, &out) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&out));
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, op_path, true, &out) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&out));

    /* Nothing was applied, no protected bytes reached the guest, and no
     * scratch or artefact survives in the guest's directory. */
    assert(can_read(g_guest, "public:guest-sentinel"));
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));
    assert(!can_read(g_guest, SECRET_DELTA_KEY));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    DIR* d = opendir(guest_dir);
    assert(d != NULL);
    struct dirent* entry;
    size_t entries = 0u;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] != '.') entries++;
    }
    closedir(d);
    assert(entries == 0u);
    assert(!file_holds(guest_path, SECRET_GAMMA_VALUE));
    rmdir(guest_dir);

    /* Wrong-version containers — the retired v1 (unsigned) and v2 (WAL-less)
     * forms — are refused BY VERSION on both authenticated paths: never a
     * downgrade to whatever checks an older layout could still run.  They are
     * fabricated by patching a signed container's version field, which is the
     * exact byte shape an old-format writer's output would present. */
    size_t len = 0u;
    uint8_t* bytes = slurp(op_path, &len);
    assert(bytes != NULL && len > 12u);
    const uint32_t versions[] = { 1u, 2u };
    for (size_t vi = 0u; vi < sizeof(versions) / sizeof(versions[0]); vi++) {
        memcpy(bytes + 8u, &versions[vi], 4u);
        spit(legacy_path, bytes, len);
        memset(&out, 0xAB, sizeof(out));
        assert(qihse_backup_verify(g_store, g_op, legacy_path, &out) ==
               QIHSE_BACKUP_ERR_VERSION);
        assert(desc_is_zeroed(&out));
        memset(&out, 0xAB, sizeof(out));
        assert(qihse_backup_restore_signed(g_store, g_op, &m, legacy_path, false,
                                           &out) == QIHSE_BACKUP_ERR_VERSION);
        assert(desc_is_zeroed(&out));
    }
    free(bytes);
    unlink(legacy_path);
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    printf("PASS low clearance + wrong-version containers: the guest is denied "
           "by the classification gate despite a valid signature and despite "
           "the override, no artefact or protected byte survives, and retired "
           "container versions are refused by version, never downgraded\n");
}

/* ── The WAL section: verified without applying, refused when tampered ─── */

static void test_wal_section(void) {
    char path[512], tampered[512];
    test_path(path, sizeof(path), "wal-section.bak");
    test_path(tampered, sizeof(tampered), "wal-section-tampered.bak");

    /* The manifest resumes at C, so the segment's first record sits exactly
     * at C — the coherent shape the writer demands. */
    const uint64_t C = 620003ULL;
    qihse_snapshot_manifest_t m;
    make_manifest(&m, C, "key-handle:citadel-a");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    /* The post-snapshot segment: a classified insert, an update, an insert
     * that a later record deletes, a transaction fence (carried, no data
     * state) and that delete, at strictly increasing LSNs. */
    static const char k_cls[] = "wal:auth-classified";
    static const char v_cls[] = "auth-post-wal";
    static const char k_alpha[] = "public:alpha";
    static const char v_alpha[] = "alpha-after-wal";
    static const char k_doomed[] = "wal:auth-doomed";
    static const char v_doomed[] = "doomed";
    uint8_t seg[1024];
    size_t seg_len = 0u;
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C, 9001u,
                                (uint8_t)QIHSE_WAL_OP_INSERT, 5u, 0x1u,
                                k_cls, (uint32_t)(sizeof(k_cls) - 1u),
                                v_cls, (uint32_t)(sizeof(v_cls) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 1u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_UPDATE, 0u, 0u,
                                k_alpha, (uint32_t)(sizeof(k_alpha) - 1u),
                                v_alpha, (uint32_t)(sizeof(v_alpha) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 2u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_INSERT, 0u, 0u,
                                k_doomed, (uint32_t)(sizeof(k_doomed) - 1u),
                                v_doomed, (uint32_t)(sizeof(v_doomed) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 3u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_COMMIT, 0u, 0u,
                                NULL, 0u, NULL, 0u);
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 4u, 9002u,
                                (uint8_t)QIHSE_WAL_OP_DELETE, 0u, 0u,
                                k_doomed, (uint32_t)(sizeof(k_doomed) - 1u),
                                NULL, 0u);
    assert(seg_len > 0u && seg_len < sizeof(seg));

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node_b.node_id,
                                         path, seg, seg_len, &desc) ==
           QIHSE_BACKUP_OK);
    assert(desc.wal_bytes == (uint64_t)seg_len);
    assert(desc.wal_first_lsn == C && desc.wal_last_lsn == C + 4u);
    struct stat st;
    assert(stat(path, &st) == 0);
    assert((uint64_t)st.st_size ==
           QIHSE_BACKUP_HEADER_WAL_BYTES + (uint64_t)sig_fixed_bytes() +
           desc.data_bytes + (uint64_t)seg_len);

    /* Verify-only checks the WAL section without applying a byte of it. */
    prime_sentinel();
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, path, &out) == QIHSE_BACKUP_OK);
    assert(out.wal_bytes == (uint64_t)seg_len);
    assert(out.wal_first_lsn == C && out.wal_last_lsn == C + 4u);
    assert(memcmp(out.wal_checksum, desc.wal_checksum, 48u) == 0);
    assert(!can_read(g_op, k_cls));                  /* nothing applied */
    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes != NULL);
    size_t wal_off = QIHSE_BACKUP_HEADER_WAL_BYTES + sig_fixed_bytes() + desc.data_bytes;
    assert(len == wal_off + seg_len);

    /* 1. A byte flipped inside the WAL section (inside the first record's
     *    value): the section digest — recorded inside the signed header — is
     *    the first gate to fail, before any WAL byte is applied. */
    bytes[wal_off + 40u] ^= 0x20u;
    spit(tampered, bytes, len);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_CHECKSUM);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_CHECKSUM);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));
    assert(!can_read(g_op, k_cls));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    bytes[wal_off + 40u] ^= 0x20u;

    /* 2. The WAL digest edited in the header itself: the header is the
     *    signed region, so the substitution is a signature failure. */
    bytes[400u] ^= 0x01u;   /* wal_checksum[0] */
    spit(tampered, bytes, len);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    bytes[400u] ^= 0x01u;

    /* 3. A truncated WAL tail — mid-record, half of the last record's key —
     *    is a length disagreement: refused, nothing partially applied. */
    spit(tampered, bytes, len - 5u);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));
    assert(!can_read(g_op, k_cls));

    /* 4. The whole last record removed: still a truncation. */
    size_t last_rec = QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES + (sizeof(k_doomed) - 1u);
    spit(tampered, bytes, len - last_rec);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 5. Bytes appended after the WAL section. */
    {
        uint8_t* padded = (uint8_t*)malloc(len + 8u);
        assert(padded != NULL);
        memcpy(padded, bytes, len);
        memset(padded + len, 0, 8u);
        spit(tampered, padded, len + 8u);
        free(padded);
    }
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, tampered, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(can_read(g_op, "public:sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));
    free(bytes);
    unlink(tampered);

    /* 6. The pristine container restores to the post-WAL state: replay
     *    applies in order, the doomed key is inserted then deleted, the
     *    fence changed no data state, and the classified record came back
     *    AT ITS OWN CLASSIFICATION — a replay is not a downgrade channel. */
    put(g_op, "public:post-snapshot", "post-snapshot-value", 0, 0);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_OK);
    assert(out.wal_bytes == (uint64_t)seg_len);
    assert(out.wal_first_lsn == C && out.wal_last_lsn == C + 4u);
    assert(!can_read(g_op, "public:sentinel"));
    assert(!can_read(g_op, "public:post-snapshot"));
    read_is(g_op, k_cls, v_cls);
    assert(!can_read(g_guest, k_cls));               /* class 5 + SCI 0x1 */
    assert(!can_read(g_op, k_doomed));
    read_is(g_op, k_alpha, v_alpha);
    read_is(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE);

    /* 7. Idempotent-safe replay: restoring the same container again
     *    converges (records re-apply; the delete of an absent key is
     *    satisfied, not an error). */
    put(g_op, k_cls, "operator-overwrote", 0, 0);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_OK);
    read_is(g_op, k_cls, v_cls);
    assert(!can_read(g_guest, k_cls));               /* classification back */
    assert(!can_read(g_op, k_doomed));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    printf("PASS WAL section: verify checks it without applying; a tampered "
           "WAL byte, an edited in-header digest, a mid-record tail, a "
           "removed record and appended bytes are all refused with nothing "
           "applied; the pristine container restores to the post-WAL state "
           "and re-restores idempotently at the recorded classification\n");
}

/* ── NULL context fails closed (AGENTS.md invariant 1) ─────────────────── */

static void test_null_context_fails_closed(void) {
    char path[512];
    test_path(path, sizeof(path), "null-context.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, 111111ULL, "key-handle:citadel-a");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, NULL, &m, &g_node_b.node_id,
                                     path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));
    assert(qihse_backup_write_signed(NULL, g_op, &m, &g_node_b.node_id,
                                     path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_restore_signed(g_store, NULL, &m, path, false, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_restore_signed(NULL, g_op, &m, path, false, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_verify(g_store, NULL, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_verify(NULL, g_op, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_verify(g_store, g_op, NULL, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_verify(g_store, g_op, "", &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    /* The WAL-bearing writer's own argument discipline: a NULL principal,
     * and a NULL segment named with a nonzero length. */
    assert(qihse_backup_write_signed_wal(g_store, NULL, &m, &g_node_b.node_id,
                                         path, NULL, 0u, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node_b.node_id,
                                         path, NULL, 16u, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));
    assert(access(path, F_OK) != 0);

    printf("PASS NULL context: an absent principal is an argument error on "
           "every authenticated entry point\n");
}

/* ── Setup and driver ──────────────────────────────────────────────────── */

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "build/backup_auth_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
    snprintf(g_key_dir, sizeof(g_key_dir), "%s/keys", g_dir);
    assert(mkdir(g_key_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", g_dir, 1) == 0);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("BackupAuthPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "BackupAuthPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    /* The operator implicitly holds every scope, including the one the
     * restore override requires; a guest holds none. */
    assert(qihse_infra_scope_check(g_op, QIHSE_SCOPE_SECURITY_ADMIN));

    g_guest = qihse_auth_create_user(g_op, 4510u, QIHSE_ROLE_GUEST, 0u, 0u,
                                     "BackupAuthGuest1!", false);
    assert(g_guest);
    assert(!qihse_infra_scope_check(g_guest, QIHSE_SCOPE_SECURITY_ADMIN));

    g_store = qihse_kv_store_create();
    assert(g_store);

    put(g_op, "public:alpha", PUBLIC_ALPHA_VALUE, 0, 0);
    put(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE, 3, 0x2);
    put(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE, 5, 0x1);

    /* The signer population: A approved, B approved (the wrong-signer key),
     * C pending, D approved but keyless. */
    make_node(&g_node_a, "backup-auth-node-a", "r730xd-a");
    make_node(&g_node_b, "backup-auth-node-b", "r730xd-b");
    make_node(&g_node_pending, "backup-auth-node-pending", "r730xd-c");
    make_node(&g_node_keyless, "backup-auth-node-keyless", "r730xd-d");
    assert(qihse_federation_node_enroll_request(g_store, g_op, &g_node_a));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &g_node_a.node_id, 41));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &g_node_b));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &g_node_b.node_id, 42));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &g_node_pending));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &g_node_keyless));
    assert(qihse_federation_node_enroll_approve(g_store, g_op,
                                                &g_node_keyless.node_id, 44));
    assert(unlink(g_node_keyless.key_handle) == 0);

    test_result_vocabulary();
    test_write_requires_enrolled_signer();
    test_happy_path();
    test_bitflip_in_data();
    test_bitflip_in_signature();
    test_stripped_signature();
    test_wrong_signer_key();
    test_revoked_signer();
    test_low_clearance_denied();
    test_wal_section();
    test_null_context_fails_closed();

    qihse_kv_store_destroy(g_store);

    /* The audit subsystem's signer thread may still be flushing the
     * integrity chain into the data dir, so the removal is retried: the
     * temp dir is repo-local build scratch and must not survive the run. */
    char cmd[768];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", g_dir);
    for (int attempt = 0; attempt < 5; attempt++) {
        if (system(cmd) == 0) break;
        usleep(200000);
    }

    printf("backup authentication tests passed\n");
    return 0;
}
