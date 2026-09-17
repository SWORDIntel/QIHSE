/*
 * test_federation_backup.c — the federation snapshot backup writer and its
 * reader.
 *
 * A snapshot manifest is recorded and verified; this is the data it refers
 * to.  The test is organised around what the writer must refuse to do:
 *
 *   - a full round trip: write the backup, let the dataset drift, restore,
 *     and check the restored state is the snapshot's — including the WAL
 *     continuation point the caller resumes from
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
 *     could have produced, and no scratch file is left behind
 */
#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;      /* OPERATOR: 0xFFFF clearance, all compartments */
static qihse_user_t* g_guest;   /* GUEST: clearance 0, no compartments */
static qihse_user_t* g_analyst; /* ANALYST: clearance 3, compartment 0x1 only */

static char g_dir[512];

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

static bool desc_is_zeroed(const qihse_backup_descriptor_t* d) {
    static const uint8_t zeros[48] = {0};
    if (!qihse_uuid_is_nil(&d->snapshot_id)) return false;
    if (d->wal_continuation_offset != 0u || d->max_generation != 0u) return false;
    if (d->object_count != 0u || d->data_bytes != 0u) return false;
    if (memcmp(d->data_checksum, zeros, 48u) != 0) return false;
    if (memcmp(d->manifest_checksum, zeros, 48u) != 0) return false;
    if (d->encryption_key_id[0] != '\0') return false;
    return true;
}

/* ── Vocabulary ────────────────────────────────────────────────────────── */

static void test_result_vocabulary(void) {
    for (int i = 0; i <= (int)QIHSE_BACKUP_ERR_IO; i++) {
        const char* name = qihse_backup_result_name((qihse_backup_result_t)i);
        assert(name != NULL);
        assert(strcmp(name, "unknown") != 0);
    }
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_OK), "ok") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_DENIED), "denied") == 0);
    assert(strcmp(qihse_backup_result_name(QIHSE_BACKUP_ERR_WAL_POINT), "wal_point") == 0);
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
    assert(qihse_backup_write(g_store, g_op, &m, path, &desc) == QIHSE_BACKUP_OK);

    /* The container is bound to the manifest it was written for, and reports
     * the point a restore resumes from. */
    assert(qihse_uuid_equal(&desc.snapshot_id, &m.snapshot_id));
    assert(desc.wal_continuation_offset == 99123456ULL);
    assert(desc.max_generation == 1831ULL);
    assert(desc.object_count == expected_captured);
    assert(memcmp(desc.manifest_checksum, m.checksum, 48) == 0);
    assert(strcmp(desc.encryption_key_id, "key-handle:citadel-1") == 0);
    assert(desc.schema.schema_id == QIHSE_SCHEMA_ID_FEDERATION);
    assert(desc.data_bytes > 0u);

    struct stat st;
    assert(stat(path, &st) == 0);
    assert((uint64_t)st.st_size == QIHSE_BACKUP_HEADER_BYTES + desc.data_bytes);
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
    assert(qihse_backup_restore(g_store, g_op, &m, path, &restored) == QIHSE_BACKUP_OK);
    assert(restored.wal_continuation_offset == 99123456ULL);
    assert(memcmp(restored.data_checksum, desc.data_checksum, 48) == 0);

    /* The restore is the snapshot, not the drifted dataset: what was written
     * after the snapshot is gone and what was deleted is back. */
    assert(!can_read(g_op, "public:post-snapshot"));
    read_is(g_op, "public:beta", PUBLIC_BETA_VALUE);
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);
    read_is(g_op, SECRET_GAMMA_KEY, SECRET_GAMMA_VALUE);
    read_is(g_op, SECRET_DELTA_KEY, SECRET_DELTA_VALUE);

    printf("PASS round trip: write, drift, restore to the manifest's WAL point "
           "(offset 99123456), classified payload carried and returned\n");
}

/* ── Refusals that must not apply anything ─────────────────────────────── */

static void test_container_integrity(void) {
    char path[512], tampered[512], restored_path[512];
    test_path(path, sizeof(path), "integrity.bak");
    test_path(tampered, sizeof(tampered), "integrity-tampered.bak");
    test_path(restored_path, sizeof(restored_path), "integrity-restored.bak");

    qihse_snapshot_manifest_t m;
    make_manifest(&m, NULL, 424242ULL, "key-handle:citadel-2");
    assert(qihse_snapshot_record(g_store, g_op, &m));

    qihse_backup_descriptor_t desc;
    assert(qihse_backup_write(g_store, g_op, &m, path, &desc) == QIHSE_BACKUP_OK);

    size_t len = 0u;
    uint8_t* bytes = slurp(path, &len);
    assert(bytes && len > QIHSE_BACKUP_HEADER_BYTES);

    /* A sentinel written after the backup and absent from it: if a refused
     * restore applied anything at all, the sentinel would disappear. */
    put(g_op, "public:sentinel", "sentinel-value", 0, 0);
    qihse_backup_descriptor_t out;

    /* 1. Truncated container. */
    spit(tampered, bytes, QIHSE_BACKUP_HEADER_BYTES + (len - QIHSE_BACKUP_HEADER_BYTES) / 2u);
    memset(&out, 0xAB, sizeof(out));
    assert(qihse_backup_restore(g_store, g_op, &m, tampered, &out) == QIHSE_BACKUP_ERR_TRUNCATED);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 2. Bytes appended: the declared length must agree with the file. */
    uint8_t* padded = (uint8_t*)malloc(len + 16u);
    assert(padded);
    memcpy(padded, bytes, len);
    memset(padded + len, 0, 16u);
    spit(tampered, padded, len + 16u);
    free(padded);
    assert(qihse_backup_restore(g_store, g_op, &m, tampered, &out) == QIHSE_BACKUP_ERR_TRUNCATED);
    assert(can_read(g_op, "public:sentinel"));

    /* 3. A byte flipped inside the data section. */
    uint8_t* flipped = (uint8_t*)malloc(len);
    assert(flipped);
    memcpy(flipped, bytes, len);
    flipped[QIHSE_BACKUP_HEADER_BYTES + 4u] ^= 0x40u;
    spit(tampered, flipped, len);
    free(flipped);
    assert(qihse_backup_restore(g_store, g_op, &m, tampered, &out) == QIHSE_BACKUP_ERR_CHECKSUM);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 4. An edited WAL continuation point.  The header is not covered by the
     * data digest, which is exactly why the manifest comparison exists: a
     * container that would resume from a different point is refused rather
     * than silently applied. */
    uint8_t* rewound = (uint8_t*)malloc(len);
    assert(rewound);
    memcpy(rewound, bytes, len);
    uint64_t bogus_offset = 7ULL;
    memcpy(rewound + 32u, &bogus_offset, 8u);
    spit(tampered, rewound, len);
    free(rewound);
    assert(qihse_backup_restore(g_store, g_op, &m, tampered, &out) == QIHSE_BACKUP_ERR_WAL_POINT);
    assert(desc_is_zeroed(&out));
    assert(can_read(g_op, "public:sentinel"));

    /* 5. A container belonging to a different snapshot. */
    uint8_t* other = (uint8_t*)malloc(len);
    assert(other);
    memcpy(other, bytes, len);
    qihse_uuid_t stranger;
    assert(qihse_uuid_generate(&stranger));
    memcpy(other + 16u, stranger.bytes, QIHSE_UUID_BYTES);
    spit(tampered, other, len);
    free(other);
    assert(qihse_backup_restore(g_store, g_op, &m, tampered, &out) ==
           QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH);
    assert(can_read(g_op, "public:sentinel"));

    /* 6. A container written against a different manifest revision. */
    uint8_t* revision = (uint8_t*)malloc(len);
    assert(revision);
    memcpy(revision, bytes, len);
    revision[64u] ^= 0x01u;   /* manifest_checksum[0] */
    spit(tampered, revision, len);
    free(revision);
    assert(qihse_backup_restore(g_store, g_op, &m, tampered, &out) == QIHSE_BACKUP_ERR_MANIFEST);
    assert(can_read(g_op, "public:sentinel"));

    free(bytes);
    unlink(tampered);

    /* The pristine container still restores, so the refusals above are about
     * the tampering and not about the restore path being broken. */
    assert(qihse_backup_restore(g_store, g_op, &m, path, &out) == QIHSE_BACKUP_OK);
    assert(!can_read(g_op, "public:sentinel"));
    assert(out.wal_continuation_offset == 424242ULL);

    printf("PASS container integrity: truncated, padded, flipped, re-pointed, "
           "foreign and mis-revisioned containers all refused with nothing applied\n");
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
    assert(qihse_backup_write(g_store, g_op, &m, path, &desc) == QIHSE_BACKUP_OK);

    /* An unrecorded manifest is not a manifest. */
    qihse_snapshot_manifest_t unrecorded;
    make_manifest(&unrecorded, NULL, 5150ULL, "key-handle:citadel-3");
    assert(qihse_backup_write(g_store, g_op, &unrecorded, other_path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(qihse_backup_restore(g_store, g_op, &unrecorded, path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(access(other_path, F_OK) != 0);

    /* An edited in-memory manifest: the checksum bytes still name the recorded
     * digest, so the field-by-field comparison is what catches it. */
    qihse_snapshot_manifest_t edited = m;
    edited.max_generation = 999999ULL;
    assert(qihse_backup_restore(g_store, g_op, &edited, path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    qihse_snapshot_manifest_t repointed = m;
    repointed.wal_continuation_offset = 999ULL;
    assert(qihse_backup_restore(g_store, g_op, &repointed, path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);

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
    assert(qihse_backup_write(g_store, g_op, &tainted, other_path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(qihse_backup_restore(g_store, g_op, &tainted, path, &desc) ==
           QIHSE_BACKUP_ERR_MANIFEST);
    assert(access(other_path, F_OK) != 0);

    /* A restore cannot be pointed at a different snapshot's data. */
    qihse_snapshot_manifest_t second;
    make_manifest(&second, NULL, 5150ULL, "key-handle:citadel-3");
    assert(qihse_snapshot_record(g_store, g_op, &second));
    assert(qihse_backup_restore(g_store, g_op, &second, path, &desc) ==
           QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH);

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
    assert(qihse_backup_write(g_store, g_op, &m, path, &desc) ==
           QIHSE_BACKUP_ERR_KEY_MATERIAL);
    assert(access(path, F_OK) != 0);

    memset(&m, 0, sizeof(m));
    assert(qihse_uuid_generate(&m.snapshot_id));
    m.wal_continuation_offset = 31337ULL;
    snprintf(m.encryption_key_id, sizeof(m.encryption_key_id), "key id with\nnewline");
    assert(qihse_backup_write(g_store, g_op, &m, path, &desc) ==
           QIHSE_BACKUP_ERR_KEY_MATERIAL);
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
    assert(qihse_backup_write(g_store, NULL, &m, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(desc_is_zeroed(&desc));
    assert(qihse_backup_restore(g_store, NULL, &m, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write(NULL, g_op, &m, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_restore(NULL, g_op, &m, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write(g_store, g_op, NULL, path, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write(g_store, g_op, &m, NULL, &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
    assert(qihse_backup_write(g_store, g_op, &m, "", &desc) == QIHSE_BACKUP_ERR_ARGUMENT);
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
    assert(qihse_backup_write(g_store, g_op, &m, op_path, &desc) == QIHSE_BACKUP_OK);
    assert(file_holds(op_path, SECRET_GAMMA_VALUE));

    /* 1. The guest cannot produce the data the manifest refers to: its
     * authorized view is narrower than the manifest's declared coverage. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write(g_store, g_guest, &m, guest_path, &desc) ==
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
    assert(qihse_backup_write(g_store, g_guest, &guest_manifest, guest_own_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(access(guest_own_path, F_OK) != 0);
    assert(!file_holds(guest_own_path, SECRET_GAMMA_VALUE));
    assert(!dir_has_entry_containing(g_dir, ".data."));
    assert(!dir_has_entry_containing(g_dir, ".tmp."));

    /* 3. The guest cannot restore the operator's backup: the KV layer refuses
     * the whole load because it holds records outside the guest's clearance,
     * and the refusal leaves the live dataset untouched. */
    put(g_op, "public:guest-sentinel", "guest-sentinel-value", 0, 0);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore(g_store, g_guest, &m, op_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
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
    assert(qihse_backup_write(g_store, g_analyst, &analyst_manifest, analyst_path, &desc) ==
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
    assert(qihse_backup_write(g_store, g_analyst, &analyst_own, analyst_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(access(analyst_path, F_OK) != 0);
    assert(!file_holds(analyst_path, SECRET_GAMMA_VALUE));

    /* The analyst cannot restore the operator's backup either: the container
     * holds a record outside its compartments. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore(g_store, g_analyst, &m, op_path, &desc) ==
           QIHSE_BACKUP_ERR_DENIED);
    assert(desc_is_zeroed(&desc));
    assert(can_read(g_analyst, "public:guest-sentinel"));
    assert(!can_read(g_analyst, SECRET_GAMMA_KEY));
    assert(!dir_has_entry_containing(g_dir, ".restore."));

    /* 5. A guest manifest cannot be used to smuggle the operator's data back
     * in either: the container belongs to the operator's snapshot, not the
     * guest's. */
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_restore(g_store, g_guest, &guest_manifest, op_path, &desc) ==
           QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH);
    assert(!can_read(g_guest, SECRET_GAMMA_KEY));

    /* 6. A refused write must not damage whatever is already at the path: the
     * container is assembled beside it and renamed into place only on
     * success, so a denial cannot truncate the previous good backup. */
    static const char previous[] = "previous-good-backup";
    spit(guest_path, (const uint8_t*)previous, sizeof(previous) - 1u);
    memset(&desc, 0xAB, sizeof(desc));
    assert(qihse_backup_write(g_store, g_guest, &guest_manifest, guest_path, &desc) ==
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

    qihse_backup_descriptor_t desc;
    assert(qihse_backup_write(g_store, g_guest, &m, guest_path, &desc) == QIHSE_BACKUP_OK);
    assert(desc.object_count > 0u);
    /* A backup taken by a low-clearance principal cannot contain data above
     * that principal's clearance, because it never had it to write. */
    assert(!file_holds(guest_path, SECRET_GAMMA_VALUE));
    assert(!file_holds(guest_path, SECRET_DELTA_VALUE));
    assert(file_holds(guest_path, PUBLIC_ALPHA_VALUE));

    put(g_guest, "public:guest-drift", "guest-drift-value", 0, 0);
    assert(qihse_backup_restore(g_store, g_guest, &m, guest_path, &desc) == QIHSE_BACKUP_OK);
    assert(!can_read(g_guest, "public:guest-drift"));
    read_is(g_guest, "public:alpha", PUBLIC_ALPHA_VALUE);
    assert(desc.wal_continuation_offset == 818181ULL);

    printf("PASS within-clearance backup: the guest can write and restore a "
           "backup of data it is cleared for, and still carries nothing above it\n");
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
    assert(qihse_backup_write(g_store, g_op, &m, path, &desc) == QIHSE_BACKUP_OK);
    assert(desc.object_count == live);
    assert(desc.encryption_key_id[0] == '\0');
    assert(desc.data_bytes > 0u);

    put(g_op, "public:drift", "drift-value", 0, 0);
    assert(qihse_backup_restore(g_store, g_op, &m, path, &desc) == QIHSE_BACKUP_OK);
    assert(!can_read(g_op, "public:drift"));
    read_is(g_op, "public:alpha", PUBLIC_ALPHA_VALUE);

    printf("PASS undeclared coverage: a manifest with no count and no key id "
           "records the captured count and restores\n");
}

/* ── Setup and driver ──────────────────────────────────────────────────── */

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "build/backup_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
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

    test_result_vocabulary();
    test_round_trip();
    test_container_integrity();
    test_manifest_gating();
    test_key_material_refused();
    test_null_context_fails_closed();
    test_low_clearance_denied();
    test_low_clearance_within_its_view();
    test_undeclared_count();

    qihse_kv_store_destroy(g_store);

    char cmd[768];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", g_dir);
    assert(system(cmd) == 0);

    printf("federation backup tests passed\n");
    return 0;
}
