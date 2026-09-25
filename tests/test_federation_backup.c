/*
 * test_federation_backup.c — the federation snapshot backup writer and its
 * reader, in the AUTHENTICATED (v3) form: a signed container that carries
 * the snapshot's data section plus a bounded post-snapshot WAL segment.
 *
 * A snapshot manifest is recorded and verified; this is the data it refers
 * to.  Every write is signed by an enrolled, APPROVED fednode identity and
 * every restore verifies that signature before any payload byte is read.
 * The test is organised around what the writer must refuse to do:
 *
 *   - a full round trip: write the backup signed, let the dataset drift,
 *     restore verified, and check the restored state is the snapshot's —
 *     including the WAL continuation point the caller resumes from
 *   - the WAL segment: a snapshot plus a segment restores to the POST-WAL
 *     state, verify-only checks the segment without applying it, replay is
 *     idempotent-safe, and a classified WAL record restores at its own
 *     classification (a replay is not a downgrade channel)
 *   - the container is bound to the snapshot id, the manifest revision and
 *     the WAL continuation point, so an edited, truncated or mismatched
 *     container is refused and NOTHING is applied
 *   - the manifest's checksum is verified before a restore touches the store,
 *     both for an edited in-memory manifest and for a tampered stored record
 *   - key material is refused; only the key id ever reaches the container
 *   - a NULL security context is an argument error, never a whole-database
 *     backup (AGENTS.md invariant 1)
 *   - AGENTS.md invariants 2 and 3: a low-clearance principal and a
 *     same-clearance/different-compartment principal are both DENIED, the
 *     protected payload BYTES are asserted absent from every artefact they
 *     could have produced, and no scratch file is left behind — on the data
 *     section AND on the WAL segment
 *   - the manifest-free whole-store export is held to the same rule: the
 *     context-free forms are gone, a NULL or forged handle is refused on
 *     every entry point, and a guest/analyst is denied on export, verify,
 *     list and restore with no artefact and no protected bytes
 */
#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"
/* For the WAL record composition: the section's per-record CRC uses the
 * tractable WAL's own CRC primitive and XOR composition. */
#include "qihse_wal.h"
/* For the forged-handle probe: a handle that is not the live record must not
 * resolve as a principal.  The test builds one deliberately. */
#include "qihse_auth_internal.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;      /* OPERATOR: 0xFFFF clearance, all compartments */
static qihse_user_t* g_guest;   /* GUEST: clearance 0, no compartments */
static qihse_user_t* g_analyst; /* ANALYST: clearance 3, compartment 0x1 only */

static char g_dir[512];      /* backup artefacts (relative, repo-local) */
static char g_key_dir[576];  /* node private keys (relative, repo-local) */

/* The enrolled, APPROVED node identity that signs the backups.  Its record
 * is class 0 (identities are metadata), so a low-clearance principal can
 * still resolve the signer for its own within-view backups. */
static qihse_federation_node_identity_t g_node;

#define PUBLIC_ALPHA_VALUE "alpha-payload-AAAA"
#define PUBLIC_BETA_VALUE  "beta-payload-BBBB"
/* Clearance 3 + compartment 0x2: above the guest's clearance AND outside the
 * analyst's compartments. */
#define SECRET_GAMMA_VALUE "GAMMA-CLASSIFIED-PAYLOAD"
/* Clearance 5: above the analyst's clearance too. */
#define SECRET_DELTA_VALUE "DELTA-CLASSIFIED-PAYLOAD"
#define SECRET_GAMMA_KEY   "secret:gamma"
#define SECRET_DELTA_KEY   "secret:delta"

/* ── Test file helpers ─────────────────────────────────────────────────── */

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

/* Does this file exist and contain the needle?  A file that does not exist
 * cannot have disclosed anything, which is the state a refused backup must
 * leave behind. */
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
    char cmd[768];
    char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s/.listing", dir);
    int n = snprintf(cmd, sizeof(cmd), "ls -1a '%s' > '%s' 2>/dev/null", dir, out_path);
    assert(n > 0 && (size_t)n < sizeof(cmd));
    assert(system(cmd) == 0);
    bool found = file_holds(out_path, needle);
    unlink(out_path);
    return found;
}

/* A refused call must leave no artefact AT ALL, not merely none at the path it
 * was asked to write: this counts a directory's real entries. */
static size_t dir_entry_count(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return (size_t)-1;
    size_t n = 0u;
    struct dirent* entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        n++;
    }
    closedir(d);
    return n;
}

/* Does ANY regular file in `dir` contain the needle?  Byte absence has to be
 * asserted against every artefact a refused call could have produced. */
static bool dir_files_hold(const char* dir, const char* needle) {
    DIR* d = opendir(dir);
    if (!d) return false;
    bool found = false;
    char path[1024];
    struct dirent* entry;
    while (!found && (entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        found = file_holds(path, needle);
    }
    closedir(d);
    return found;
}

static void free_listing(qihse_backup_info_t* list, size_t count) {
    for (size_t i = 0; i < count; i++) qihse_backup_info_free(&list[i]);
    free(list);
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

static void make_manifest(qihse_snapshot_manifest_t* m,
                          const qihse_uuid_t* snapshot_id,
                          uint64_t wal_offset, const char* key_id) {
    memset(m, 0, sizeof(*m));
    assert(qihse_uuid_generate(&m->snapshot_id));
    if (snapshot_id) m->snapshot_id = *snapshot_id;
    m->kind = QIHSE_SNAPSHOT_COORDINATED;
    assert(qihse_uuid_from_seed("backup-test-cluster", strlen("backup-test-cluster"),
                                &m->cluster_id));
    assert(qihse_uuid_generate(&m->created_by));
    m->created_hlc_physical = 1700000000000ULL;
    qihse_schema_header_init(&m->schema, QIHSE_SCHEMA_ID_FEDERATION, 1);
    m->max_generation = 1831;
    m->wal_continuation_offset = wal_offset;
    if (key_id) snprintf(m->encryption_key_id, sizeof(m->encryption_key_id), "%s", key_id);
    m->group_count = 2;
    snprintf(m->groups[0], sizeof(m->groups[0]), "core-security");
    snprintf(m->groups[1], sizeof(m->groups[1]), "control-metadata");
    /* Exactly what the RESP F8 snapshot path records: the count through the
     * recording principal's authorized view, taken before the manifest record
     * itself exists. */
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

/* ── Vocabulary ────────────────────────────────────────────────────────── */

static void test_result_vocabulary(void) {
    for (int i = 0; i <= (int)QIHSE_BACKUP_ERR_VERSION; i++) {
        const char* name = qihse_backup_result_name((qihse_backup_result_t)i);
        assert(name != NULL);
        assert(strcmp(name, "unknown") != 0);
    }
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_OK), "ok") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_DENIED), "denied") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_WAL_POINT), "wal_point") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_VERSION), "version") == 0);
    assert(strcmp(qihse_backup_result_name((qihse_backup_result_t)999), "unknown") == 0);
    printf("PASS backup vocabulary: every result is named, unknown stays unknown\n");
}

/* ── Round trip ────────────────────────────────────────────────────────── */

static void test_round_trip(void) {
    char path[512];
    test_path(path, sizeof(path), "round-trip.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 99123456ULL, "key-handle:citadel-1");
    uint64_t declared = m.object_count;
    assert(declared >= 4u);   /* alpha, beta, gamma, delta */
    assert(qihse_snapshot_record(g_store, g_op, &m));

    uint64_t expected_captured = (uint64_t)qihse_kv_count_user(g_store, g_op);
    assert(expected_captured >= declared);

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_OK);

    /* The container is bound to the manifest it was written for, reports
     * the point a restore resumes from, and names its signer. */
    assert(qihse_uuid_equal(&desc.snapshot_id, &m.snapshot_id));
    assert(desc.wal_continuation_offset == 99123456ULL);
    assert(desc.max_generation == 1831ULL);
    assert(desc.object_count == expected_captured);
    assert(memcmp(desc.manifest_checksum, m.checksum, 48) == 0);
    assert(strcmp(desc.encryption_key_id, "key-handle:citadel-1") == 0);
    assert(desc.schema.schema_id == QIHSE_SCHEMA_ID_FEDERATION);
    assert(desc.data_bytes > 0u);
    assert(qihse_uuid_equal(&desc.signer_node, &g_node.node_id));
    assert(desc.sig_alg == QIHSE_SIG_ML_DSA_87);
    assert(memcmp(desc.signer_fingerprint, g_node.fingerprint, 48) == 0);
    /* No WAL segment in this form: the WAL block reports nothing. */
    assert(desc.wal_bytes == 0u && desc.wal_first_lsn == 0u && desc.wal_last_lsn == 0u);

    struct stat st;
    assert(stat(path, &st) == 0);
    assert((uint64_t)st.st_size ==
           QIHSE_BACKUP_HEADER_WAL_BYTES + (uint64_t)sig_fixed_bytes() + desc.data_bytes);
    /* A classified dataset's backup is not world-readable. */
    assert((st.st_mode & 0777u) == 0600u);

    /* The operator's backup really does carry the protected payload: this is
     * what makes the absence assertions in the denial tests meaningful. */
    assert(file_holds(path, SECRET_GAMMA_VALUE));
    assert(file_holds(path, PUBLIC_ALPHA_VALUE));
    /* Key ID, never key material. */
    assert(file_holds(path, "key-handle:citadel-1"));
    assert(!file_holds(path, "-----BEGIN"));

    /* Drift: the live dataset moves on after the snapshot. */
    put(g_op, "public:post-snapshot", "post-snapshot-value", 0, 0);
    assert(qihse_kv_del_user(g_store, "public:beta", g_op));
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);

    qihse_backup_descriptor_t restored;
    memset(&restored, 0xAB, sizeof(restored));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &restored) ==
           QIHSE_BACKUP_OK);
    assert(restored.wal_continuation_offset == 99123456ULL);
    assert(memcmp(restored.data_checksum, desc.data_checksum, 48) == 0);
    assert(qihse_uuid_equal(&restored.signer_node, &g_node.node_id));

    /* The restore is the snapshot, not the drifted dataset: what was written
     * after the snapshot is gone and what was deleted is back. */
    assert(!can_read(g_op, "public:post-snapshot"));
    read_is(g_op, "public:beta", PUBLIC_BETA_VALUE);
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);
    read_is(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE);
    read_is(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE);

    printf("PASS round trip: write signed, drift, restore verified to the "
           "manifest's WAL point (offset 99123456), classified payload carried "
           "and returned\n");
}

/* ── Refusals that must not apply anything ─────────────────────────────── */

static void test_container_integrity(void) {
    char path[512], tampered[512], restored_path[512];
    test_path(path, sizeof(path), "integrity.bak");
    test_path(tampered, sizeof(tampered), "integrity-tampered.bak");
    test_path(restored_path, sizeof(restored_path), "integrity-restored.bak");
    (void)restored_path;

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 424242ULL, "key-handle:citadel-2");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_OK);

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes && len > QIHSE_BACKUP_HEADER_WAL_BYTES);
    size_t data_off = QIHSE_BACKUP_HEADER_WAL_BYTES + sig_fixed_bytes();
    assert(len > data_off + 8u);

    /* A sentinel written after the backup and absent from it: if a refused
     * restore applied anything at all, the sentinel would disappear. */
    put(g_op, "public:sentinel", "sentinel-value", 0, 0);
    qihse_backup_descriptor_t out;

    /* 1. Truncated container. */
    spit(tampered, bytes, data_off + (len - data_off) / 2u);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 2. Bytes appended: the declared length must agree with the file. */
    uint8_t* padded = (uint8_t*)malloc(len + 16u);
    assert(padded);
    memcpy(padded, bytes, len);
    memset(padded + len, 0, 16u);
    spit(tampered, padded, len + 16u);
    free(padded);
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(can_read(g_op, "public:sentinel"));

    /* 3. A byte flipped inside the data section. */
    uint8_t* flipped = (uint8_t*)malloc(len);
    assert(flipped);
    memcpy(flipped, bytes, len);
    flipped[data_off + 4u] ^= 0x40u;
    spit(tampered, flipped, len);
    free(flipped);
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_CHECKSUM);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 4. A byte flipped inside the SIGNATURE: the header is intact and
     *    parses, but the signature no longer verifies under the signer's
     *    enrolled key. */
    uint8_t* flip_sig = (uint8_t*)malloc(len);
    assert(flip_sig);
    memcpy(flip_sig, bytes, len);
    flip_sig[QIHSE_BACKUP_HEADER_WAL_BYTES + 10u] ^= 0x01u;
    spit(tampered, flip_sig, len);
    free(flip_sig);
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_SIGNATURE);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 5. An edited WAL continuation point.  The binding gate compares the
     *    container's recorded point with the manifest's before the payload
     *    is read: a container that would resume from a different point is
     *    refused rather than silently applied. */
    uint8_t* rewound = (uint8_t*)malloc(len);
    assert(rewound);
    memcpy(rewound, bytes, len);
    uint64_t bogus_offset = 7ULL;
    memcpy(rewound + 32u, &bogus_offset, 8u);
    spit(tampered, rewound, len);
    free(rewound);
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_WAL_POINT);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 6. A container belonging to a different snapshot. */
    uint8_t* other = (uint8_t*)malloc(len);
    assert(other);
    memcpy(other, bytes, len);
    qihse_uuid_t stranger;
    assert(qihse_uuid_generate(&stranger));
    memcpy(other + 16u, stranger.bytes, QIHSE_UUID_BYTES);
    spit(tampered, other, len);
    free(other);
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH);
    assert(can_read(g_op, "public:sentinel"));

    /* 7. A container written against a different manifest revision. */
    uint8_t* revision = (uint8_t*)malloc(len);
    assert(revision);
    memcpy(revision, bytes, len);
    revision[64u] ^= 0x01u;   /* manifest_checksum[0] */
    spit(tampered, revision, len);
    free(revision);
    assert(qihse_backup_restore_signed(g_store, g_op, &m, tampered, false, &out) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(can_read(g_op, "public:sentinel"));

    free(bytes);
    unlink(tampered);

    /* The pristine container still restores, so the refusals above are about
     * the tampering and not about the restore path being broken. */
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_OK);
    assert(!can_read(g_op, "public:sentinel"));
    assert(out.wal_continuation_offset == 424242ULL);

    printf("PASS container integrity: truncated, padded, flipped, "
           "signature-flipped, re-pointed, foreign and mis-revisioned "
           "containers all refused with nothing applied\n");
}

/* ── Manifest gating ───────────────────────────────────────────────────── */

static void test_manifest_gating(void) {
    char path[512], other_path[512];
    test_path(path, sizeof(path), "manifest.bak");
    test_path(other_path, sizeof(other_path), "manifest-other.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 5150ULL, "key-handle:citadel-3");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_OK);

    /* An unrecorded manifest is not a manifest. */
    qihse_snapshot_manifest_t unrecorded;
    make_manifest(&unrecorded, NULL, 5150ULL, "key-handle:citadel-3");
    assert(qihse_backup_write_signed(g_store, g_op, &unrecorded, &g_node.node_id,
                                     other_path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(qihse_backup_restore_signed(g_store, g_op, &unrecorded, path, false,
                                       &desc) == QIHSE_BACKUP_ERR_MANIFEST);
    assert(access(other_path, F_OK) != 0);

    /* An edited in-memory manifest: the checksum bytes still name the recorded
     * digest, so the field-by-field comparison is what catches it. */
    qihse_snapshot_manifest_t edited = m;
    edited.max_generation = 999999ULL;
    assert(qihse_backup_restore_signed(g_store, g_op, &edited, path, false,
                                       &desc) == QIHSE_BACKUP_ERR_MANIFEST);
    qihse_snapshot_manifest_t repointed = m;
    repointed.wal_continuation_offset = 999ULL;
    assert(qihse_backup_restore_signed(g_store, g_op, &repointed, path, false,
                                       &desc) == QIHSE_BACKUP_ERR_MANIFEST);

    /* A tampered STORED manifest record: qihse_snapshot_verify recomputes the
     * digest over the stored body, so the restore never starts. */
    qihse_snapshot_manifest_t tainted;
    make_manifest(&tainted, NULL, 7777777ULL, "key-handle:citadel-4");
    assert(qihse_snapshot_record(g_store, g_op, &tainted));
    char key[160], id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&tainted.snapshot_id, id_str);
    snprintf(key, sizeof(key), QIHSE_SNAPSHOT_PREFIX "%s", id_str);
    char* blob = qihse_kv_get_user(g_store, key, g_op);
    assert(blob);
    char* field = strstr(blob, "\t7777777\t");
    assert(field);
    field[1] = '8';   /* 7777777 -> 8777777: the body no longer matches */
    assert(qihse_kv_set_user(g_store, key, blob, 0, 0, g_op));
    free(blob);
    assert(!qihse_snapshot_verify(g_store, g_op, &tainted.snapshot_id));
    assert(qihse_backup_write_signed(g_store, g_op, &tainted, &g_node.node_id,
                                     other_path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(qihse_backup_restore_signed(g_store, g_op, &tainted, path, false,
                                       &desc) == QIHSE_BACKUP_ERR_MANIFEST);
    assert(access(other_path, F_OK) != 0);

    /* A restore cannot be pointed at a different snapshot's data. */
    qihse_snapshot_manifest_t second;
    make_manifest(&second, NULL, 5150ULL, "key-handle:citadel-3");
    assert(qihse_snapshot_record(g_store, g_op, &second));
    assert(qihse_backup_restore_signed(g_store, g_op, &second, path, false,
                                       &desc) == QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH);

    printf("PASS manifest gating: unrecorded, edited, re-pointed, tampered-store "
           "and foreign-snapshot manifests all refused before anything is applied\n");
}

/* ── Key material ──────────────────────────────────────────────────────── */

static void test_key_material_refused(void) {
    char path[512];
    test_path(path, sizeof(path), "key-material.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 31337ULL, "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg");
    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_ERR_KEY_MATERIAL);
    assert(access(path, F_OK) != 0);

    memset(&m, 0, sizeof(m));
    assert(qihse_uuid_generate(&m.snapshot_id));
    m.wal_continuation_offset = 31337ULL;
    snprintf(m.encryption_key_id, sizeof(m.encryption_key_id), "key id with\nnewline");
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_ERR_KEY_MATERIAL);
    assert(access(path, F_OK) != 0);

    printf("PASS key material: a PEM body or a control byte in the key id is "
           "refused, never copied into a backup\n");
}

/* ── NULL context ──────────────────────────────────────────────────────── */

static void test_null_context_fails_closed(void) {
    char path[512];
    test_path(path, sizeof(path), "null-context.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 111ULL, "key-handle:citadel-5");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, NULL, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));
    assert(qihse_backup_restore_signed(g_store, NULL, &m, path, false, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write_signed(NULL, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_restore_signed(NULL, g_op, &m, path, false, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write_signed(g_store, g_op, NULL, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, NULL,
                                     &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, "",
                                     &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    /* A NULL signer node is an argument error too: there is no unsigned
     * fallback for it to mean. */
    assert(qihse_backup_write_signed(g_store, g_op, &m, NULL, path, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    /* The WAL-bearing writer's own discipline: a NULL segment named with a
     * nonzero length. */
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         NULL, 16u, &desc) ==
           QIHSE_BACKUP_ERR_ARGUMENT);
    /* No file was produced by any of them. */
    assert(access(path, F_OK) != 0);

    printf("PASS NULL context: an absent principal is an argument error, never "
           "an implicit full-database backup\n");
}

/* ── Low clearance / wrong compartments (AGENTS.md invariants 2 and 3) ─── */

static void test_low_clearance_denied(void) {
    char op_path[512], guest_path[512], guest_own_path[512], analyst_path[512];
    test_path(op_path, sizeof(op_path), "negative-operator.bak");
    test_path(guest_path, sizeof(guest_path), "negative-guest.bak");
    test_path(guest_own_path, sizeof(guest_own_path), "negative-guest-own.bak");
    test_path(analyst_path, sizeof(analyst_path), "negative-analyst.bak");

    /* Data above the low principals' clearance and outside their compartments
     * exists in the store. */
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));
    assert(!can_read(g_guest, SECRET_DELTA_KEY));
    assert(!can_read(g_analyst, SECRET_GAMMA_KEY));  /* SCI: 0x2 not in 0x1 */
    assert(!can_read(g_analyst, SECRET_DELTA_KEY));  /* clearance 3 < 5 */
    read_is(g_guest, "public:alpha", PUBLIC_ALPHA_VALUE);

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 600613ULL, "key-handle:citadel-6");
    assert(m.object_count > (uint64_t)qihse_kv_count_user(g_store, g_guest));
    assert(qihse_snapshot_record(g_store, g_op, &m));

    /* The operator may take this backup. */
    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, op_path,
                                     &desc) == QIHSE_BACKUP_OK);
    assert(file_holds(op_path, SECRET_GAMMA_VALUE));

    /* 1. The guest cannot produce the data the manifest refers to: its
     * authorized view is narrower than the manifest's declared coverage. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_guest, &m, &g_node.node_id,
                                     guest_path, &desc) ==
           QIHSE_BACKUP_ERR_COVERAGE);
    assert(desc_is_zeroed(&desc));
    assert(access(guest_path, F_OK) != 0);
    assert(!file_holds(guest_path, SECRET_GAMMA_VALUE));
    assert(!file_holds(guest_path, SECRET_DELTA_VALUE));

    /* 2. Even a manifest the guest records itself — one that claims only what
     * the guest can see, so the coverage gate passes — is refused by the KV
     * layer, which will not export a dataset containing records above the
     * caller's clearance.  The bypass-prone form is covered. */
    qihse_snapshot_manifest_t guest_manifest;
    memset(&guest_manifest, 0, sizeof(guest_manifest));
    assert(qihse_uuid_generate(&guest_manifest.snapshot_id));
    guest_manifest.kind = QIHSE_SNAPSHOT_LOCAL;
    guest_manifest.wal_continuation_offset = 600614ULL;
    guest_manifest.object_count = (uint64_t)qihse_kv_count_user(g_store, g_guest);
    assert(qihse_snapshot_record(g_store, g_guest, &guest_manifest));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_guest, &guest_manifest,
                                     &g_node.node_id, guest_own_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(access(guest_own_path, F_OK) != 0);
    assert(!file_holds(guest_own_path, SECRET_GAMMA_VALUE));
    assert(!dir_has_entry_containing(g_dir, ".data."));
    assert(!dir_has_entry_containing(g_dir, ".tmp."));

    /* 3. The guest cannot restore the operator's backup: the KV layer refuses
     * the whole load because it holds records outside the guest's clearance,
     * and the refusal leaves the live dataset untouched.  The container's
     * signature verifies for the guest — authenticity is a fact about the
     * container, not a grant of its payload. */
    put(g_op, "public:guest-sentinel", "guest-sentinel-value", 0, 0);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, op_path, false,
                                       &desc) == QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(can_read(g_guest, "public:guest-sentinel"));   /* nothing replaced */
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));
    assert(!can_read(g_guest, SECRET_DELTA_KEY));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* 4. Same clearance, wrong compartments.  A manifest that declares the
     * operator's coverage — what a snapshot taken by a higher-clearance
     * principal records — cannot be satisfied by the analyst's narrower view. */
    qihse_snapshot_manifest_t analyst_manifest;
    make_manifest(&analyst_manifest, NULL, 600615ULL, NULL);
    assert(analyst_manifest.object_count > (uint64_t)qihse_kv_count_user(g_store, g_analyst));
    assert(qihse_snapshot_record(g_store, g_op, &analyst_manifest));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_analyst, &analyst_manifest,
                                     &g_node.node_id, analyst_path, &desc) ==
           QIHSE_BACKUP_ERR_COVERAGE);
    assert(desc_is_zeroed(&desc));
    assert(access(analyst_path, F_OK) != 0);
    assert(!file_holds(analyst_path, SECRET_GAMMA_VALUE));

    /* And a manifest the analyst records itself, claiming only what it can
     * see, is refused by the KV layer's compartment check — the analyst may
     * read nothing of compartment 0x2, so it may not export a dataset
     * containing it. */
    qihse_snapshot_manifest_t analyst_own;
    memset(&analyst_own, 0, sizeof(analyst_own));
    assert(qihse_uuid_generate(&analyst_own.snapshot_id));
    analyst_own.kind = QIHSE_SNAPSHOT_LOCAL;
    analyst_own.wal_continuation_offset = 600616ULL;
    analyst_own.object_count = (uint64_t)qihse_kv_count_user(g_store, g_analyst);
    assert(qihse_snapshot_record(g_store, g_analyst, &analyst_own));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_analyst, &analyst_own,
                                     &g_node.node_id, analyst_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(access(analyst_path, F_OK) != 0);
    assert(!file_holds(analyst_path, SECRET_GAMMA_VALUE));

    /* The analyst cannot restore the operator's backup either: the container
     * holds a record outside its compartments. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore_signed(g_store, g_analyst, &m, op_path, false,
                                       &desc) == QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(can_read(g_analyst, "public:guest-sentinel"));
    assert(!can_read(g_analyst, SECRET_GAMMA_KEY));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* 5. A guest manifest cannot be used to smuggle the operator's data back
     * in either: the container belongs to the operator's snapshot, not the
     * guest's. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore_signed(g_store, g_guest, &guest_manifest, op_path,
                                       false, &desc) ==
           QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH);
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));

    /* 6. A refused write must not damage whatever is already at the path: the
     * container is assembled beside it and renamed into place only on
     * success, so a denial cannot truncate the previous good backup. */
    static const char previous[] = "previous-good-backup";
    spit(guest_path, (const uint8_t*)previous, sizeof(previous) - 1u);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_guest, &guest_manifest,
                                     &g_node.node_id, guest_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
    size_t kept_len = 0u;
    uint8_t* kept = slurp(guest_path, &kept_len);
    assert(kept != NULL);
    assert(kept_len == sizeof(previous) - 1u);
    assert(memcmp(kept, previous, kept_len) == 0);
    free(kept);
    unlink(guest_path);

    printf("PASS low clearance + wrong compartments: coverage and clearance "
           "denials, zeroed descriptors, no container, no scratch file, no "
           "damage to an existing backup, and the protected payload bytes "
           "appear in no artefact the low principals could have produced\n");
}

/* ── The WAL segment: snapshot + segment restores to the post-WAL state ── */

static void test_wal_round_trip(void) {
    char path[512];
    test_path(path, sizeof(path), "wal-round-trip.bak");

    /* Two pre-snapshot records the segment will mutate, so the test does its
     * post-WAL assertions against keys it owns rather than against records
     * later tests still expect in their snapshot state. */
    put(g_op, "wal:update-target", "before-wal", 0, 0);
    put(g_op, "wal:delete-target", "delete-me", 0, 0);

    /* The manifest resumes at C, so the segment's first record sits exactly
     * at C — the coherent shape the writer demands. */
    const uint64_t C = 740000ULL;
    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, C, "key-handle:citadel-wal");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    /* The post-snapshot writes the segment carries: a classified insert, an
     * update of a snapshot record, a delete of a snapshot record, an insert
     * that a later record deletes, a transaction fence (carried, no data
     * state) and that delete, at strictly increasing LSNs. */
    static const char k_cls[] = "wal:classified";
    static const char v_cls[] = "classified-post-wal";
    static const char k_upd[] = "wal:update-target";
    static const char v_upd[] = "after-wal";
    static const char k_del[] = "wal:delete-target";
    static const char k_doomed[] = "wal:doomed";
    static const char v_doomed[] = "doomed";
    uint8_t seg[1024];
    size_t seg_len = 0u;
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C, 9001u,
                                (uint8_t)QIHSE_WAL_OP_INSERT, 5u, 0x1u,
                                k_cls, (uint32_t)(sizeof(k_cls) - 1u),
                                v_cls, (uint32_t)(sizeof(v_cls) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 1u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_UPDATE, 0u, 0u,
                                k_upd, (uint32_t)(sizeof(k_upd) - 1u),
                                v_upd, (uint32_t)(sizeof(v_upd) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 2u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_DELETE, 0u, 0u,
                                k_del, (uint32_t)(sizeof(k_del) - 1u),
                                NULL, 0u);
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 3u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_INSERT, 0u, 0u,
                                k_doomed, (uint32_t)(sizeof(k_doomed) - 1u),
                                v_doomed, (uint32_t)(sizeof(v_doomed) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 4u, 9001u,
                                (uint8_t)QIHSE_WAL_OP_COMMIT, 0u, 0u,
                                NULL, 0u, NULL, 0u);
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C + 5u, 9002u,
                                (uint8_t)QIHSE_WAL_OP_DELETE, 0u, 0u,
                                k_doomed, (uint32_t)(sizeof(k_doomed) - 1u),
                                NULL, 0u);
    assert(seg_len > 0u && seg_len < sizeof(seg));

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         seg, seg_len, &desc) ==
           QIHSE_BACKUP_OK);
    assert(desc.wal_bytes == (uint64_t)seg_len);
    assert(desc.wal_first_lsn == C && desc.wal_last_lsn == C + 5u);
    assert(qihse_uuid_equal(&desc.signer_node, &g_node.node_id));

    struct stat st;
    assert(stat(path, &st) == 0);
    assert((uint64_t)st.st_size ==
           QIHSE_BACKUP_HEADER_WAL_BYTES + (uint64_t)sig_fixed_bytes() +
           desc.data_bytes + (uint64_t)seg_len);
    assert((st.st_mode & 0777u) == 0600u);

    /* Verify-only checks the WAL section without applying a byte of it: the
     * live dataset still holds the drift, and the segment's records have not
     * landed. */
    put(g_op, "public:post-snapshot", "post-snapshot-value", 0, 0);
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_op, path, &out) == QIHSE_BACKUP_OK);
    assert(out.wal_bytes == (uint64_t)seg_len);
    assert(out.wal_first_lsn == C && out.wal_last_lsn == C + 5u);
    assert(memcmp(out.wal_checksum, desc.wal_checksum, 48u) == 0);
    assert(!can_read(g_op, k_cls));
    assert(can_read(g_op, "public:post-snapshot"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* Restore: the snapshot is applied first, then the segment replays in
     * order — the result is the post-WAL state, not the drifted one. */
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_OK);
    assert(out.wal_bytes == (uint64_t)seg_len);
    assert(out.wal_first_lsn == C && out.wal_last_lsn == C + 5u);
    assert(!can_read(g_op, "public:post-snapshot"));
    read_is(g_op, k_upd, v_upd);                  /* the WAL update applied */
    assert(!can_read(g_op, k_del));               /* the WAL delete applied */
    assert(!can_read(g_op, k_doomed));            /* inserted, then deleted */
    read_is(g_op, k_cls, v_cls);
    /* The classified WAL record restored AT ITS OWN CLASSIFICATION: the
     * guest is below it and the analyst's clearance (3) is below 5.  A
     * replay is not a downgrade channel. */
    assert(!can_read(g_guest, k_cls));
    assert(!can_read(g_analyst, k_cls));
    /* The snapshot's classified payload came back too. */
    read_is(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE);
    read_is(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE);

    /* Idempotent-safe replay: the same container restored again converges —
     * records re-apply through the KV layer's set/delete primitives, and the
     * delete of an already-absent key is satisfied rather than an error (the
     * qihse_wal_replay() start-LSN rule made structural). */
    put(g_op, k_cls, "operator-overwrote", 0, 0);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_OK);
    read_is(g_op, k_cls, v_cls);
    assert(!can_read(g_guest, k_cls));            /* classification restored */
    assert(!can_read(g_op, k_doomed));
    read_is(g_op, k_upd, v_upd);
    assert(!can_read(g_op, k_del));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* Leave the dataset as this test found it: the classified WAL record
     * must not linger where later low-clearance tests would trip over it. */
    assert(qihse_kv_del_user(g_store, k_cls, g_op));

    printf("PASS WAL round trip: snapshot + segment restores to the post-WAL "
           "state, verify-only checks the segment without applying it, replay "
           "is idempotent-safe, and classified records restore at their own "
           "classification\n");
}

/* ── The WAL segment the writer must refuse ────────────────────────────── */

static void test_wal_writer_gates(void) {
    char path[512];
    test_path(path, sizeof(path), "wal-gates.bak");

    const uint64_t C = 750100ULL;
    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, C, NULL);
    assert(qihse_snapshot_record(g_store, g_op, &m));

    static const char k[] = "wal:gates-key";
    static const char v[] = "value";
    uint8_t seg[512];
    size_t seg_len = 0u;
    qihse_backup_descriptor_t desc;

    /* 1. A segment that starts BELOW the continuation point holds
     *    pre-snapshot records: refused, no container. */
    seg_len = wal_build_record(seg, sizeof(seg), C - 1u, 7001u,
                               (uint8_t)QIHSE_WAL_OP_INSERT, 0u, 0u,
                               k, (uint32_t)(sizeof(k) - 1u),
                               v, (uint32_t)(sizeof(v) - 1u));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         seg, seg_len, &desc) ==
           QIHSE_BACKUP_ERR_WAL_POINT);
    assert(desc_is_zeroed(&desc));
    assert(access(path, F_OK) != 0);

    /* 2. A segment that starts ABOVE it: the gap would silently lose the
     *    writes between the snapshot and the segment. */
    seg_len = wal_build_record(seg, sizeof(seg), C + 5u, 7001u,
                               (uint8_t)QIHSE_WAL_OP_INSERT, 0u, 0u,
                               k, (uint32_t)(sizeof(k) - 1u),
                               v, (uint32_t)(sizeof(v) - 1u));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         seg, seg_len, &desc) ==
           QIHSE_BACKUP_ERR_WAL_POINT);
    assert(desc_is_zeroed(&desc));
    assert(access(path, F_OK) != 0);

    /* 3. A corrupt record: a flipped payload byte breaks the per-record
     *    CRC, and the whole write is refused before anything is produced. */
    seg_len = wal_build_record(seg, sizeof(seg), C, 7001u,
                               (uint8_t)QIHSE_WAL_OP_INSERT, 0u, 0u,
                               k, (uint32_t)(sizeof(k) - 1u),
                               v, (uint32_t)(sizeof(v) - 1u));
    assert(seg_len > 40u);
    seg[40u] ^= 0x08u;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         seg, seg_len, &desc) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&desc));
    assert(access(path, F_OK) != 0);
    seg[40u] ^= 0x08u;

    /* 4. A non-increasing LSN run: the ordered-segment guarantee is part of
     *    the format, not a suggestion. */
    seg_len = wal_build_record(seg, sizeof(seg), C, 7001u,
                               (uint8_t)QIHSE_WAL_OP_INSERT, 0u, 0u,
                               k, (uint32_t)(sizeof(k) - 1u),
                               v, (uint32_t)(sizeof(v) - 1u));
    seg_len += wal_build_record(seg + seg_len, sizeof(seg) - seg_len, C, 7002u,
                                (uint8_t)QIHSE_WAL_OP_UPDATE, 0u, 0u,
                                k, (uint32_t)(sizeof(k) - 1u),
                                v, (uint32_t)(sizeof(v) - 1u));
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         seg, seg_len, &desc) ==
           QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&desc));
    assert(access(path, F_OK) != 0);

    /* 5. A segment above the format's bound: an argument error, not an
     *    unbounded container. */
    uint8_t* huge = (uint8_t*)malloc((size_t)QIHSE_BACKUP_WAL_SECTION_MAX + 1u);
    assert(huge != NULL);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         huge, (size_t)QIHSE_BACKUP_WAL_SECTION_MAX + 1u,
                                         &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));
    free(huge);
    assert(access(path, F_OK) != 0);
    assert(!dir_has_entry_containing(g_dir, ".data."));
    assert(!dir_has_entry_containing(g_dir, ".tmp."));

    printf("PASS WAL writer gates: pre-snapshot and gapped segments, corrupt "
           "records, non-increasing LSNs and oversized segments are all "
           "refused with no container and no scratch\n");
}

/* ── The manifest-free whole-store export (invariants 1, 2 and 3) ──────── */

static void test_whole_store_export_authenticated(void) {
    char op_path[512], tampered[512], guest_dir[512], guest_path[512];
    test_path(op_path, sizeof(op_path), "legacy-operator.bak");
    test_path(tampered, sizeof(tampered), "legacy-tampered.bak");
    test_path(guest_dir, sizeof(guest_dir), "legacy-guest-dir");
    assert(mkdir(guest_dir, 0700) == 0);
    int written = snprintf(guest_path, sizeof(guest_path), "%s/guest.bak", guest_dir);
    assert(written > 0 && (size_t)written < sizeof(guest_path));

    qihse_backup_info_t info;
    qihse_backup_info_t* list = NULL;
    size_t count = 0u;

    /* 1. NULL is an argument error on every entry point: never "export
     * everything", never an implicit security-disabled mode. */
    memset(&info, 0xAB, sizeof(info));
    assert(qihse_backup_full_user(g_store, NULL, guest_path, &info) == QIHSE_BACKUP_EXPORT_ERR);
    assert(info.path == NULL && info.checksum == NULL);
    assert(qihse_backup_full_user(NULL, g_op, guest_path, &info) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_full_user(g_store, g_op, NULL, &info) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_full_user(g_store, g_op, "", &info) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_incremental_user(g_store, NULL, guest_path, 0u, &info) ==
           QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_restore_user(g_store, NULL, op_path) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_restore_user(NULL, g_op, op_path) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_verify_user(NULL, op_path) == QIHSE_BACKUP_EXPORT_ERR);
    count = 99u;
    assert(qihse_backup_list_user(NULL, g_dir, &list, &count) == QIHSE_BACKUP_EXPORT_ERR);
    assert(list == NULL && count == 0u);
    assert(qihse_backup_list_user(g_op, NULL, &list, &count) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_list_user(g_op, g_dir, NULL, &count) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_list_user(g_op, g_dir, &list, NULL) == QIHSE_BACKUP_EXPORT_ERR);
    assert(dir_entry_count(guest_dir) == 0u);

    /* 2. A forged handle is not a principal.  It carries the operator's user
     * id and the highest clearance, but a handle must BE the live record:
     * matching fields are not an authentication. */
    qihse_user_t forged;
    memset(&forged, 0, sizeof(forged));
    forged.user_id = qihse_user_get_id(g_op);
    forged.role = QIHSE_ROLE_OPERATOR;
    forged.classification_level = 0xFFFFu;
    forged.sci_compartments = 0xFFFFu;
    memset(&info, 0xAB, sizeof(info));
    assert(qihse_backup_full_user(g_store, &forged, guest_path, &info) ==
           QIHSE_BACKUP_EXPORT_DENIED);
    assert(info.path == NULL && info.checksum == NULL);
    assert(qihse_restore_user(g_store, &forged, op_path) == QIHSE_BACKUP_EXPORT_DENIED);
    assert(qihse_backup_verify_user(&forged, op_path) == QIHSE_BACKUP_EXPORT_DENIED);
    assert(qihse_backup_list_user(&forged, g_dir, &list, &count) ==
           QIHSE_BACKUP_EXPORT_DENIED);
    assert(list == NULL && count == 0u);
    assert(dir_entry_count(guest_dir) == 0u);

    /* 3. The operator's whole-store container.  Its data section comes from
     * the KV layer's authorization-aware export, so the operator's view
     * really does include the protected payload. */
    memset(&info, 0, sizeof(info));
    assert(qihse_backup_full_user(g_store, g_op, op_path, &info) == QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_FULL);
    assert(info.path != NULL && strcmp(info.path, op_path) == 0);
    assert(info.checksum != NULL && strlen(info.checksum) == 16u);
    assert(info.writer_user_id == qihse_user_get_id(g_op));
    assert(info.classification == qihse_user_get_classification(g_op));
    assert(info.sci_compartment == qihse_user_get_sci(g_op));
    struct stat st;
    assert(stat(op_path, &st) == 0);
    assert((size_t)st.st_size == info.size_bytes);
    /* A backup of a classified dataset is not world-readable. */
    assert((st.st_mode & 0777u) == 0600u);
    assert(file_holds(op_path, SECRET_GAMMA_VALUE));
    assert(file_holds(op_path, PUBLIC_ALPHA_VALUE));
    /* ... and the writer's scratch is gone. */
    assert(!dir_has_entry_containing(g_dir, ".data."));
    assert(!dir_has_entry_containing(g_dir, ".tmp."));
    qihse_backup_info_free(&info);
    memset(&info, 0, sizeof(info));

    /* 4. A guest may neither produce the operator's view nor learn about,
     * verify or apply the operator's container.  The container records the
     * writer's clearance/SCI as an upper bound on what it can hold, and the
     * guest does not dominate it. */
    memset(&info, 0xAB, sizeof(info));
    assert(qihse_backup_full_user(g_store, g_guest, guest_path, &info) ==
           QIHSE_BACKUP_EXPORT_DENIED);
    assert(info.path == NULL && info.checksum == NULL);
    assert(qihse_backup_verify_user(g_guest, op_path) == QIHSE_BACKUP_EXPORT_DENIED);
    assert(qihse_restore_user(g_store, g_guest, op_path) == QIHSE_BACKUP_EXPORT_DENIED);
    count = 99u;
    assert(qihse_backup_list_user(g_guest, g_dir, &list, &count) ==
           QIHSE_BACKUP_EXPORT_DENIED);
    assert(list == NULL && count == 0u);
    /* Same clearance, wrong compartments: the analyst does not dominate the
     * bound either. */
    assert(qihse_backup_verify_user(g_analyst, op_path) == QIHSE_BACKUP_EXPORT_DENIED);
    assert(qihse_restore_user(g_store, g_analyst, op_path) == QIHSE_BACKUP_EXPORT_DENIED);
    assert(qihse_backup_list_user(g_analyst, g_dir, &list, &count) ==
           QIHSE_BACKUP_EXPORT_DENIED);
    assert(list == NULL && count == 0u);

    /* The refusals produced NO artefact at all: not a container, not a
     * scratch file, and no file anywhere that carries the protected bytes. */
    assert(dir_entry_count(guest_dir) == 0u);
    assert(!dir_files_hold(guest_dir, SECRET_GAMMA_VALUE));
    assert(!dir_files_hold(guest_dir, SECRET_DELTA_VALUE));
    assert(!file_holds(guest_path, SECRET_GAMMA_VALUE));
    assert(!file_holds(guest_path, SECRET_DELTA_VALUE));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* 5. Incremental is now real: the KV layer stamps a change sequence on
     * every authorized mutation, so a delta is produced honestly instead of
     * refusing with UNSUPPORTED.  Cursor at the store's high-water makes an
     * EMPTY delta — no store mutation, nothing disclosed — while proving the
     * surface answers the documented contract.  (The deep delta-coverage,
     * resume and no-leak assertions live in tests/test_incremental_export.c.)
     * A guest's delta is clearance-filtered at the KV layer, so an empty
     * guest delta carries no protected bytes either. */
    uint64_t hw = qihse_kv_change_seq(g_store);
    memset(&info, 0xAB, sizeof(info));
    assert(qihse_backup_incremental_user(g_store, g_op, guest_path, hw, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_INCREMENTAL);
    assert(info.start_lsn == hw && info.end_lsn == hw);
    assert(info.path != NULL && strcmp(info.path, guest_path) == 0);
    qihse_backup_info_free(&info);
    memset(&info, 0xAB, sizeof(info));
    assert(qihse_backup_incremental_user(g_store, g_guest, guest_path, hw, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_INCREMENTAL && info.end_lsn == hw);
    assert(info.path != NULL && strcmp(info.path, guest_path) == 0);
    qihse_backup_info_free(&info);
    memset(&info, 0, sizeof(info));
    /* Both deltas were empty and the second container replaced the first at
     * the same path: one file, holding no payload byte at all. */
    assert(!file_holds(guest_path, SECRET_GAMMA_VALUE));
    assert(!file_holds(guest_path, SECRET_DELTA_VALUE));
    assert(!dir_files_hold(guest_dir, SECRET_GAMMA_VALUE));
    assert(!dir_files_hold(guest_dir, SECRET_DELTA_VALUE));
    assert(!dir_has_entry_containing(guest_dir, ".data."));
    assert(!dir_has_entry_containing(guest_dir, ".tmp."));
    assert(dir_entry_count(guest_dir) == 1u);

    /* 6. The operator can verify and list what it wrote. */
    assert(qihse_backup_verify_user(g_op, op_path) == QIHSE_BACKUP_EXPORT_OK);
    assert(qihse_backup_list_user(g_op, g_dir, &list, &count) == QIHSE_BACKUP_EXPORT_OK);
    assert(list != NULL && count >= 1u);
    bool found = false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(list[i].path, op_path) == 0) {
            found = true;
            assert(list[i].type == BACKUP_FULL);
            assert(list[i].classification == qihse_user_get_classification(g_op));
            assert(list[i].size_bytes == (size_t)st.st_size);
        }
    }
    assert(found);
    free_listing(list, count);
    list = NULL;
    count = 0u;

    /* 7. Tampering is refused before anything is applied, and the recorded
     * bound is inside the hashed region: lowering it to slip past the
     * container gate invalidates the container instead of opening it. */
    size_t len = 0u;
    uint8_t* bytes = slurp(op_path, &len);
    assert(bytes != NULL && len > 64u);
    put(g_op, "public:legacy-sentinel", "legacy-sentinel-value", 0, 0);
    uint8_t* edited = (uint8_t*)malloc(len);
    assert(edited != NULL);
    memcpy(edited, bytes, len);
    edited[len - 1u] ^= 0x01u;                 /* a byte of the data section */
    spit(tampered, edited, len);
    assert(qihse_backup_verify_user(g_op, tampered) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_restore_user(g_store, g_op, tampered) == QIHSE_BACKUP_EXPORT_ERR);
    assert(can_read(g_op, "public:legacy-sentinel"));
    memcpy(edited, bytes, len);
    edited[52] = 0u; edited[53] = 0u;          /* writer_classification -> 0 */
    edited[54] = 0u; edited[55] = 0u;          /* writer_sci -> 0 */
    spit(tampered, edited, len);
    /* Refused — as a checksum error or as a denial, but never applied. */
    assert(qihse_backup_verify_user(g_op, tampered) != QIHSE_BACKUP_EXPORT_OK);
    assert(qihse_restore_user(g_store, g_op, tampered) != QIHSE_BACKUP_EXPORT_OK);
    assert(can_read(g_op, "public:legacy-sentinel"));
    free(edited);
    spit(tampered, bytes, len - 8u);           /* truncated */
    assert(qihse_backup_verify_user(g_op, tampered) == QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_restore_user(g_store, g_op, tampered) == QIHSE_BACKUP_EXPORT_ERR);
    assert(can_read(g_op, "public:legacy-sentinel"));
    free(bytes);
    unlink(tampered);

    /* 8. The authenticated path really works: the restore is the snapshot,
     * not the drifted dataset, and the classification survived the round trip
     * (a restore cannot downgrade a record to unclassified). */
    put(g_op, "public:legacy-drift", "legacy-drift-value", 0, 0);
    assert(qihse_restore_user(g_store, g_op, op_path) == QIHSE_BACKUP_EXPORT_OK);
    assert(!can_read(g_op, "public:legacy-drift"));
    assert(!can_read(g_op, "public:legacy-sentinel"));
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);
    read_is(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE);
    read_is(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE);
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));
    assert(!can_read(g_guest, SECRET_DELTA_KEY));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    printf("PASS whole-store export: no context-free form remains, NULL and "
           "forged handles are refused on every entry point, guest and analyst "
           "are denied on export, verify, list and restore, no artefact or "
           "protected byte survives a refusal, and the authenticated round "
           "trip restores the snapshot with its classifications intact\n");
}

/* ── The denial is about clearance, not about the API being unusable ───── */

static void test_low_clearance_within_its_view(void) {
    char guest_path[512];
    test_path(guest_path, sizeof(guest_path), "guest-within.bak");

    /* Withdraw the classified records, and the guest is a legitimate backup
     * operator for what remains: the clearance gate is a boundary, not a
     * blanket refusal. */
    assert(qihse_kv_del_user(g_store, SECRET_GAMMA_KEY, g_op));
    assert(qihse_kv_del_user(g_store, SECRET_DELTA_KEY, g_op));

    qihse_snapshot_manifest_t m;
    memset(&m, 0, sizeof(m));
    assert(qihse_uuid_generate(&m.snapshot_id));
    m.kind = QIHSE_SNAPSHOT_LOCAL;
    m.wal_continuation_offset = 818181ULL;
    m.object_count = (uint64_t)qihse_kv_count_user(g_store, g_guest);
    assert(qihse_snapshot_record(g_store, g_guest, &m));

    /* The guest signs its own backup: the enrolled identity record is class-0
     * metadata it may read, so the signer resolves through the guest's own
     * identity and the exported view is the guest's. */
    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_guest, &m, &g_node.node_id,
                                     guest_path, &desc) == QIHSE_BACKUP_OK);
    assert(desc.object_count > 0u);
    /* A backup taken by a low-clearance principal cannot contain data above
     * that principal's clearance, because it never had it to write. */
    assert(!file_holds(guest_path, SECRET_GAMMA_VALUE));
    assert(!file_holds(guest_path, SECRET_DELTA_VALUE));
    assert(file_holds(guest_path, PUBLIC_ALPHA_VALUE));

    put(g_guest, "public:guest-drift", "guest-drift-value", 0, 0);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, guest_path, false,
                                       &desc) == QIHSE_BACKUP_OK);
    assert(!can_read(g_guest, "public:guest-drift"));
    read_is(g_guest, "public:alpha", PUBLIC_ALPHA_VALUE);
    assert(desc.wal_continuation_offset == 818181ULL);

    printf("PASS within-clearance backup: the guest can write and restore a "
           "signed backup of data it is cleared for, and still carries nothing "
           "above it\n");
}

/* ── A manifest that declares no count yet ─────────────────────────────── */

static void test_undeclared_count(void) {
    char path[512];
    test_path(path, sizeof(path), "undeclared.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 20240ULL, NULL);   /* no key id recorded either */
    m.object_count = 0;
    m.group_count = 0;
    assert(qihse_snapshot_record(g_store, g_op, &m));

    uint64_t live = (uint64_t)qihse_kv_count_user(g_store, g_op);
    assert(live > 0u);

    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed(g_store, g_op, &m, &g_node.node_id, path,
                                     &desc) == QIHSE_BACKUP_OK);
    assert(desc.object_count == live);
    assert(desc.encryption_key_id[0] == '\0');
    assert(desc.data_bytes > 0u);

    put(g_op, "public:drift", "drift-value", 0, 0);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &desc) ==
           QIHSE_BACKUP_OK);
    assert(!can_read(g_op, "public:drift"));
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);

    printf("PASS undeclared coverage: a manifest with no count and no key id "
           "records the captured count and restores\n");
}

/* ── A WAL record above a low principal's clearance (invariant 3) ──────── */

static void test_wal_low_clearance_denied(void) {
    char path[512];
    test_path(path, sizeof(path), "wal-low-clearance.bak");

    const uint64_t C = 760100ULL;
    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, C, NULL);
    assert(qihse_snapshot_record(g_store, g_op, &m));

    /* The WAL carries an INSERT above the guest's clearance and outside the
     * analyst's compartments (class 5 / SCI 0x3) while the DATA section is
     * public-only at this point in the run — so the WAL record is the only
     * thing that can deny, and this test isolates exactly that gate. */
    static const char k[] = "wal:above-low";
    static const char v[] = "above-low-value";
    uint8_t seg[256];
    size_t seg_len = wal_build_record(seg, sizeof(seg), C, 7100u,
                                      (uint8_t)QIHSE_WAL_OP_INSERT, 5u, 0x3u,
                                      k, (uint32_t)(sizeof(k) - 1u),
                                      v, (uint32_t)(sizeof(v) - 1u));
    qihse_backup_descriptor_t desc;
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write_signed_wal(g_store, g_op, &m, &g_node.node_id, path,
                                         seg, seg_len, &desc) ==
           QIHSE_BACKUP_OK);

    put(g_op, "public:low-sentinel", "low-sentinel-value", 0, 0);

    /* Verify is a fact about the container, not a grant: it succeeds for the
     * low principals and applies nothing — the segment included. */
    qihse_backup_descriptor_t out;
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_verify(g_store, g_guest, path, &out) == QIHSE_BACKUP_OK);
    assert(qihse_backup_verify(g_store, g_analyst, path, &out) == QIHSE_BACKUP_OK);

    /* The clearance pre-flight refuses the restore BEFORE the dataset is
     * replaced: nothing applied, the sentinel is intact, and the protected
     * record is invisible (AGENTS.md invariant 3's negative for the WAL
     * surface). */
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, path, false, &out) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_guest, "public:low-sentinel"));
    assert(!can_read(g_guest, k));
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_analyst, &m, path, false, &out) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_analyst, "public:low-sentinel"));
    assert(!can_read(g_analyst, k));
    /* The override is no help: it skips the signature gate only, and a guest
     * may not raise it at all. */
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_guest, &m, path, true, &out) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_guest, "public:low-sentinel"));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* The operator restores the same container without difficulty, and the
     * classified record lands at its own classification. */
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore_signed(g_store, g_op, &m, path, false, &out) ==
           QIHSE_BACKUP_OK);
    read_is(g_op, k, v);
    assert(!can_read(g_guest, k));
    assert(!can_read(g_analyst, k));
    assert(qihse_kv_del_user(g_store, k, g_op));

    printf("PASS WAL low clearance: a WAL record above a low principal's "
           "clearance refuses the whole restore before anything is applied, "
           "verify stays a non-granting fact, and the override changes "
           "nothing\n");
}

/* ── Setup and driver ──────────────────────────────────────────────────── */

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "build/backup_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
    snprintf(g_key_dir, sizeof(g_key_dir), "%s/keys", g_dir);
    assert(mkdir(g_key_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", g_dir, 1) == 0);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("BackupTestPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "BackupTestPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    g_guest = qihse_auth_create_user(g_op, 4210u, QIHSE_ROLE_GUEST, 0u, 0u,
                                     "BackupGuestPass1!", false);
    assert(g_guest);
    g_analyst = qihse_auth_create_user(g_op, 4211u, QIHSE_ROLE_ANALYST, 3u, 0x1u,
                                       "BackupAnalystPass1!", false);
    assert(g_analyst);

    g_store = qihse_kv_store_create();
    assert(g_store);

    put(g_op, "public:alpha", PUBLIC_ALPHA_VALUE, 0, 0);
    put(g_op, "public:beta", PUBLIC_BETA_VALUE, 0, 0);
    put(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE, 3, 0x2);
    put(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE, 5, 0x1);

    /* The signer: one enrolled, APPROVED backup-agent identity.  Its record
     * is class-0 metadata, so every principal in this test can resolve it. */
    make_node(&g_node, "fedbackup-node-a", "r730xd-backup");
    assert(qihse_federation_node_enroll_request(g_store, g_op, &g_node));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &g_node.node_id, 7));

    test_result_vocabulary();
    test_round_trip();
    test_container_integrity();
    test_manifest_gating();
    test_key_material_refused();
    test_null_context_fails_closed();
    test_low_clearance_denied();
    test_wal_round_trip();
    test_wal_writer_gates();
    test_whole_store_export_authenticated();
    test_low_clearance_within_its_view();
    test_undeclared_count();
    test_wal_low_clearance_denied();

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

    printf("federation backup tests passed\n");
    return 0;
}
