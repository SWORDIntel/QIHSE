#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "qihse_analysis_artifact.h"
#include "qihse_audit.h"

static qihse_analysis_artifact_v1_t sample(void);

typedef struct {
    const uint8_t* bytes;
    size_t len;
    size_t offset;
    unsigned calls;
    unsigned failure_mode; /* 0=normal, 1=error, 2=over-capacity */
} payload_reader_t;

static int64_t read_payload(void* opaque, uint8_t* dst, size_t capacity) {
    payload_reader_t* r = opaque;
    r->calls++;
    if (r->failure_mode == 1) return -1;
    if (r->failure_mode == 2) return (int64_t)capacity + 1;
    size_t n = r->len - r->offset;
    if (n > capacity) n = capacity;
    if (n) memcpy(dst, r->bytes + r->offset, n);
    r->offset += n;
    return (int64_t)n;
}

static qihse_analysis_artifact_v1_t binary_sample(const uint8_t* bytes, size_t len) {
    qihse_analysis_artifact_v1_t m = sample();
    m.kind = QIHSE_ANALYSIS_BINARY;
    m.input_count = 0;
    memset(m.input_ids, 0, sizeof(m.input_ids));
    m.payload_size = len;
    unsigned int digest_size = 0;
    assert(EVP_Digest(bytes, len, m.payload_sha384, &digest_size, EVP_sha384(), NULL) == 1);
    assert(digest_size == QIHSE_BLOB_HASH_BYTES);
    memcpy(m.binary_sha384, m.payload_sha384, QIHSE_BLOB_HASH_BYTES);
    assert(qihse_analysis_artifact_compute_id(&m, m.artifact_id));
    return m;
}

static qihse_analysis_artifact_v1_t sample(void) {
    qihse_analysis_artifact_v1_t m = {0};
    m.version = QIHSE_ANALYSIS_ARTIFACT_VERSION;
    m.kind = QIHSE_ANALYSIS_DISASSEMBLY;
    m.completion = QIHSE_ANALYSIS_COMPLETE;
    m.fidelity = QIHSE_ANALYSIS_FIDELITY_UNASSESSED;
    m.tenant_id = 77;
    m.classification = 2;
    m.sci = 1;
    memcpy(m.artifact_schema, "kp14.disassembly.v1", sizeof("kp14.disassembly.v1"));
    memcpy(m.producer, "radare3", sizeof("radare3"));
    memcpy(m.producer_version, "0.1.0", sizeof("0.1.0"));
    memset(m.run_id, 0x77, sizeof(m.run_id));
    m.generation = 1;
    memset(m.binary_sha384, 0xd7, sizeof(m.binary_sha384));
    memcpy(m.isa, "x86", sizeof("x86"));
    memcpy(m.mode, "long64", sizeof("long64"));
    m.address_bits = 64;
    memset(m.isanity_catalogue_sha384, 0xe8, sizeof(m.isanity_catalogue_sha384));
    m.payload_size = 3;
    memset(m.payload_sha384, 0xa5, sizeof(m.payload_sha384));
    m.input_count = 1;
    memset(m.input_ids[0], 0xb6, sizeof(m.input_ids[0]));
    assert(qihse_analysis_artifact_compute_id(&m, m.artifact_id));
    return m;
}

int main(void) {
    assert(sizeof(qihse_analysis_artifact_v1_t) <= QIHSE_ANALYSIS_ARTIFACT_MAX_MANIFEST_BYTES);
    qihse_analysis_artifact_v1_t m = sample();
    assert(qihse_analysis_artifact_validate(&m));
    char artifact_id_hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(m.artifact_id, artifact_id_hex);
    assert(strcmp(artifact_id_hex,
                  "23e479429e43c1a8edb1137efc3366fa92243219aaa95f8f113cfd89fdaa63f"
                  "d6ba5e7fdc7e1a9a2b7d2b0a8f13287f9") == 0);
    assert(!qihse_analysis_artifact_authorize_user(&m, NULL));

    char dir[] = "./build/test_analysis_artifact_XXXXXX";
    assert(mkdir("./build", 0700) == 0 || errno == EEXIST);
    assert(mkdtemp(dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorArtifactPass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* low = qihse_auth_create_tenant_user(
        op, 77, 771, QIHSE_ROLE_ANALYST, 1, 1, "LowArtifactPass1!", false);
    qihse_user_t* no_sci = qihse_auth_create_tenant_user(
        op, 77, 772, QIHSE_ROLE_ANALYST, 2, 0, "NoSciArtifactPass1!", false);
    qihse_user_t* allowed = qihse_auth_create_tenant_user(
        op, 77, 773, QIHSE_ROLE_ANALYST, 2, 1, "AllowedArtifactPass1!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(
        op, 78, 774, QIHSE_ROLE_ANALYST, 2, 1, "ForeignArtifactPass1!", false);
    qihse_user_t* system_analyst = qihse_auth_create_user(
        op, 775, QIHSE_ROLE_ANALYST, 2, 1, "SystemAnalystArtifactPass1!", false);
    qihse_user_t* no_write = qihse_auth_create_tenant_user(
        op, 77, 776, QIHSE_ROLE_ANALYST, 2, 1, "NoWriteArtifactPass1!", false);
    qihse_user_t* guest = qihse_auth_create_tenant_user(
        op, 77, 777, QIHSE_ROLE_GUEST, 0, 0, "GuestArtifactPass1!", false);
    assert(low && no_sci && allowed && foreign && system_analyst && no_write && guest);

    /* Low clearance, missing SCI, foreign tenant and NULL must never pass
     * the manifest access gate; no protected payload is returned by it. */
    assert(!qihse_analysis_artifact_authorize_user(&m, low));
    assert(!qihse_analysis_artifact_authorize_user(&m, no_sci));
    assert(!qihse_analysis_artifact_authorize_user(&m, foreign));
    assert(!qihse_analysis_artifact_authorize_user(&m, system_analyst));
    assert(qihse_analysis_artifact_authorize_user(&m, allowed));
    assert(qihse_analysis_artifact_authorize_user(&m, op));

    /* A publisher needs both role and a dedicated per-tenant WRITE scope.
     * Read clearance alone cannot turn a principal into a publisher. */
    assert(!qihse_analysis_artifact_authorize_publisher(&m, allowed));
    assert(qihse_auth_grant_object(op, allowed, QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE,
                                   77, QIHSE_ACL_WRITE));
    assert(qihse_analysis_artifact_authorize_publisher(&m, allowed));
    assert(!qihse_analysis_artifact_authorize_publisher(&m, low));
    assert(!qihse_analysis_artifact_authorize_publisher(&m, no_sci));
    assert(!qihse_analysis_artifact_authorize_publisher(&m, foreign));
    assert(!qihse_analysis_artifact_authorize_publisher(&m, system_analyst));
    assert(!qihse_analysis_artifact_authorize_publisher(&m, no_write));
    assert(qihse_analysis_artifact_authorize_publisher(&m, op));

    const uint8_t payload[] = {0x48, 0x8b, 0x04, 0x24};
    qihse_analysis_artifact_v1_t binary = binary_sample(payload, sizeof(payload));
    payload_reader_t reader = {payload, sizeof(payload), 0, 0, false};
    /* The low/high, cross-tenant and missing-SCI attempts return no metadata
     * or payload and never invoke the supplied reader. There is no stored
     * artifact read API in this stage. */
    assert(qihse_analysis_artifact_preflight_user(&binary, low, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);
    assert(qihse_analysis_artifact_preflight_user(&binary, no_sci, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);
    assert(qihse_analysis_artifact_preflight_user(&binary, foreign, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);
    assert(qihse_analysis_artifact_preflight_user(&binary, no_write, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);
    assert(qihse_analysis_artifact_preflight_user(&binary, NULL, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);
    assert(qihse_auth_grant_object(op, guest, QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE,
                                   77, QIHSE_ACL_WRITE));
    qihse_analysis_artifact_v1_t public_binary = binary;
    public_binary.classification = 0;
    public_binary.sci = 0;
    assert(qihse_analysis_artifact_compute_id(&public_binary, public_binary.artifact_id));
    assert(qihse_analysis_artifact_preflight_user(&public_binary, guest, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);

    assert(qihse_analysis_artifact_preflight_user(&binary, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_BINARY_VERIFIED);
    assert(reader.calls == 2 && reader.offset == sizeof(payload));
    /* Duplicate preflights are deterministic but not a durable idempotency
     * claim: no manifest or blob is written by this function. */
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&binary, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_BINARY_VERIFIED);
    assert(reader.calls == 2);
    qihse_analysis_artifact_v1_t tampered = binary;
    tampered.payload_sha384[0] ^= 1;
    memcpy(tampered.binary_sha384, tampered.payload_sha384, QIHSE_BLOB_HASH_BYTES);
    assert(qihse_analysis_artifact_compute_id(&tampered, tampered.artifact_id));
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&tampered, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_PAYLOAD_MISMATCH);
    tampered = binary;
    tampered.payload_size++;
    assert(qihse_analysis_artifact_compute_id(&tampered, tampered.artifact_id));
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&tampered, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_PAYLOAD_MISMATCH);
    tampered = binary;
    tampered.artifact_id[0] ^= 1;
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&tampered, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_INVALID && reader.calls == 0);
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, true};
    assert(qihse_analysis_artifact_preflight_user(&binary, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_READ_ERROR);
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, 2};
    assert(qihse_analysis_artifact_preflight_user(&binary, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_READ_ERROR);
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&binary, allowed, NULL, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_INVALID && reader.calls == 0);
    qihse_analysis_artifact_v1_t derived = binary;
    derived.kind = QIHSE_ANALYSIS_DISASSEMBLY;
    derived.input_count = 1;
    memcpy(derived.input_ids[0], binary.artifact_id, QIHSE_BLOB_HASH_BYTES);
    assert(qihse_analysis_artifact_compute_id(&derived, derived.artifact_id));
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&derived, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_LINEAGE_UNRESOLVED);
    derived.input_count = 0;
    memset(derived.input_ids, 0, sizeof(derived.input_ids));
    /* A derived kind with no lineage is invalid, never verified as binary. */
    assert(!qihse_analysis_artifact_compute_id(&derived, derived.artifact_id));
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, 0};
    assert(qihse_analysis_artifact_preflight_user(&derived, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_INVALID && reader.calls == 0);
    /* Even a syntactically valid input ID cannot be treated as proof of
     * committed lineage until an authenticated manifest lookup exists. */

    size_t large_size = 2u * QIHSE_BLOB_CHUNK_SIZE + 3u;
    uint8_t* large_payload = malloc(large_size);
    assert(large_payload);
    memset(large_payload, 0x5a, large_size);
    qihse_analysis_artifact_v1_t large_binary = binary_sample(large_payload, large_size);
    reader = (payload_reader_t){large_payload, large_size, 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&large_binary, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_BINARY_VERIFIED);
    assert(reader.offset == large_size && reader.calls == 4);
    free(large_payload);

    qihse_analysis_artifact_v1_t other = m;
    other.payload_size++;
    assert(!qihse_analysis_artifact_validate(&other));
    other = m;
    other.input_ids[1][0] = 1;
    assert(!qihse_analysis_artifact_validate(&other));
    other = m;
    other.input_ids[0][0]++;
    assert(!qihse_analysis_artifact_validate(&other));
    other = m;
    other.classification++;
    assert(!qihse_analysis_artifact_validate(&other));
    other = m;
    other.run_id[0]++;
    assert(!qihse_analysis_artifact_validate(&other));
    assert(qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    assert(memcmp(other.artifact_id, m.artifact_id, QIHSE_BLOB_HASH_BYTES) != 0);
    other = m;
    other.mode[0] = 'r';
    assert(qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    assert(memcmp(other.artifact_id, m.artifact_id, QIHSE_BLOB_HASH_BYTES) != 0);
    other = m;
    other.isanity_catalogue_sha384[0]++;
    assert(qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    assert(memcmp(other.artifact_id, m.artifact_id, QIHSE_BLOB_HASH_BYTES) != 0);
    other = m;
    other.input_ids[0][0]++;
    assert(qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    assert(memcmp(other.artifact_id, m.artifact_id, QIHSE_BLOB_HASH_BYTES) != 0);
    other = m;
    other.producer[63] = 'x';
    assert(!qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    other = m;
    other.input_count = 2;
    memcpy(other.input_ids[1], other.input_ids[0], QIHSE_BLOB_HASH_BYTES);
    assert(!qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    other = m;
    other.fidelity = QIHSE_ANALYSIS_FIDELITY_VALIDATED;
    other.completion = QIHSE_ANALYSIS_PARTIAL;
    assert(!qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    other = m;
    other.input_count = 9;
    assert(!qihse_analysis_artifact_compute_id(&other, other.artifact_id));
    assert(qihse_auth_destroy_user(op, 773));
    assert(!qihse_analysis_artifact_authorize_user(&m, allowed));
    reader = (payload_reader_t){payload, sizeof(payload), 0, 0, false};
    assert(qihse_analysis_artifact_preflight_user(&binary, allowed, read_payload, &reader) ==
           QIHSE_ANALYSIS_PREFLIGHT_DENIED && reader.calls == 0);

    /* The signer is asynchronous. Drain it before checking fixture residue. */
    qihse_audit_shutdown();

    /* The auth/audit fixture owns only these three files in its unique
     * directory. Fail if future writes add residue without cleanup. */
    char path[sizeof(dir) + 32];
    int n = snprintf(path, sizeof(path), "%s/qihse_audit.log", dir);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(unlink(path) == 0 || errno == ENOENT);
    n = snprintf(path, sizeof(path), "%s/qihse_integrity.chain", dir);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(unlink(path) == 0 || errno == ENOENT);
    n = snprintf(path, sizeof(path), "%s/qihse_audit.writer.lock", dir);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(unlink(path) == 0 || errno == ENOENT);
    assert(rmdir(dir) == 0);
    printf("test_analysis_artifact: all assertions passed (manifest struct %zu bytes)\n",
           sizeof(qihse_analysis_artifact_v1_t));
    return 0;
}
