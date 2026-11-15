#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_auth_maintenance.h"
#include "qihse_shared_backup.h"
#include "qihse_blob.h"
#include "qihse_ai_memory.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_schema.h"
#include "qihse_txn.h"
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define OP_PASSWORD "W11RecoveryOperator1!"
#define LOW_PASSWORD "W11RecoveryGuest1!"
#define OPS 32u
#define BLOB_CLASSIFICATION 5u
#define BLOB_TENANT 0u
#define BLOB_SCI 1u
#define BLOB_REFCOUNT 3u
#define BLOB_PIN_COUNT 2u
#define BLOB_PAYLOAD_BYTES 4096u
#define AIMEM_INDEX_ROWS 8u
#define AIMEM_EXPECTED_SOURCE_VERSIONS (AIMEM_INDEX_ROWS + 1u)

static const char W11_REVISED_CONTENT[] =
    "w11-index-procedure-00 revised rebuild invariant row";
#define SQL_ENGINE_ID 81u
#define BLOB_ENGINE_ID 82u

/* Private disposable scope for the bounded QH-08 derived-index rebuild probe. */
static const qihse_ai_memory_scope_t W11_INDEX_SCOPE = {
    "w11-index-rebuild", "bench", "combined", "recover"
};

typedef struct { qihse_kv_store_t *store; qihse_uwp_context_t *sql; qihse_resp_server_t *server; qihse_blob_store_t *blobs; qihse_user_t *user; pthread_barrier_t *start; unsigned lane, start_at, count; int failed; } worker_t;

static void require(bool ok, const char *what) {
    if (!ok) { fprintf(stderr, "w11_combined_recovery: %s failed\n", what); exit(1); }
}

static void join_path(char out[PATH_MAX], const char *dir, const char *name) {
    int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
    require(n > 0 && n < PATH_MAX, "auth fixture path");
}

static void pin_key(const char *path, uint8_t pin[48]) {
    FILE *f = fopen(path, "r");
    require(f != NULL, "open PQC public key");
    EVP_PKEY *key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    require(key != NULL && fclose(f) == 0, "read PQC public key");
    unsigned char *der = NULL;
    int len = i2d_PUBKEY(key, &der);
    require(len > 0 && SHA384(der, (size_t)len, pin) != NULL, "pin PQC public key");
    OPENSSL_free(der);
    EVP_PKEY_free(key);
}

static qihse_user_t *open_authority(bool provision, const char *auth_dir,
                                    const char *key_dir) {
    char state_dir[PATH_MAX], bootstrap_file[PATH_MAX];
    char kem_pub[PATH_MAX], kem_key[PATH_MAX], dsa_key[PATH_MAX], dsa_pub[PATH_MAX];
    join_path(state_dir, auth_dir, "state");
    join_path(bootstrap_file, auth_dir, "bootstrap");
    join_path(kem_pub, key_dir, "qihse_kem_pub.pem");
    join_path(kem_key, key_dir, "qihse_kem_key.pem");
    join_path(dsa_key, key_dir, "qihse_dsa_key.pem");
    join_path(dsa_pub, key_dir, "qihse_dsa_pub.pem");
    require(stat(state_dir, &(struct stat){0}) == 0, "auth state directory");

    qihse_auth_startup_config_t config = {0};
    config.mode = QIHSE_AUTH_AUTHORITY_STANDALONE;
    config.action = provision ? QIHSE_AUTH_START_PROVISION : QIHSE_AUTH_START_RECOVER;
    config.state_directory = state_dir;
    config.bootstrap_file = bootstrap_file;
    config.archive_keys.recipient_public_file = kem_pub;
    config.archive_keys.recipient_private_file = kem_key;
    config.archive_keys.signer_private_file = dsa_key;
    config.archive_keys.signer_public_file = dsa_pub;
    pin_key(kem_pub, config.archive_keys.recipient_pin);
    pin_key(dsa_pub, config.archive_keys.signer_pin);
    config.transfer_keys = config.archive_keys;
    memset(config.authority_id, 0x11, sizeof config.authority_id);
    memset(config.node, 0x22, sizeof config.node);
    memset(config.expected_history, 0x33, sizeof config.expected_history);
    config.epoch = 1u;
    config.minimum_generation = provision ? 0u : 1u;

    if (provision) {
        require(qihse_auth_bootstrap_provision(bootstrap_file, "w11-operator",
                OP_PASSWORD, false, "", true) == QIHSE_AUTH_MAINT_OK,
                "durable operator bootstrap provision");
    }
    qihse_auth_recovery_t *recovery = NULL;
    qihse_auth_maintenance_status_t status =
        qihse_auth_maintenance_start(&config, &recovery);
    if (status != QIHSE_AUTH_MAINT_OK) {
        fprintf(stderr, "durable auth startup: %s\n",
                qihse_auth_maintenance_status_string(status));
        ERR_print_errors_fp(stderr);
    }
    require(status == QIHSE_AUTH_MAINT_OK && recovery != NULL,
            qihse_auth_maintenance_status_string(status));
    qihse_auth_maintenance_recovery_release(recovery);

    qihse_user_t *op = qihse_auth_authenticate("w11-operator", OP_PASSWORD);
    require(op != NULL && qihse_user_get_id(op) == 0u &&
            qihse_user_get_role(op) == QIHSE_ROLE_OPERATOR &&
            qihse_user_can_create_users(op), "authenticated operator principal");
    if (provision) {
        qihse_user_t *created = qihse_auth_create_user(op, 47471u, QIHSE_ROLE_GUEST,
            0u, 0u, LOW_PASSWORD, false);
        require(created != NULL, "durable low principal creation");
    }
    qihse_user_t *low = qihse_auth_get_user(47471u);
    require(low != NULL && qihse_user_get_id(low) == 47471u &&
            qihse_user_get_role(low) == QIHSE_ROLE_GUEST &&
            qihse_user_get_classification(low) == 0u && qihse_user_get_sci(low) == 0u &&
            !qihse_user_can_create_users(low), "durable low principal attributes");
    require(qihse_auth_authenticate_id(47471u, LOW_PASSWORD),
            "durable low principal authentication");
    return op;
}

static char *get(qihse_kv_store_t *s, qihse_user_t *u, const char *key) {
    return qihse_kv_get_user(s, key, u);
}

static void value_is(qihse_kv_store_t *s, qihse_user_t *u, const char *key,
                     const char *expected) {
    char *v = get(s, u, key);
    require(v && strcmp(v, expected) == 0, key);
    free(v);
}

typedef struct { char text[1024]; size_t len; } sql_reply_t;

static ssize_t capture_sql_reply(void *opaque, const void *data, size_t len) {
    sql_reply_t *reply = opaque;
    size_t copy = len < sizeof(reply->text) - 1u - reply->len ?
        len : sizeof(reply->text) - 1u - reply->len;
    memcpy(reply->text + reply->len, data, copy);
    reply->len += copy;
    reply->text[reply->len] = '\0';
    return (ssize_t)len;
}

static bool sql_statement(qihse_uwp_context_t *ctx, qihse_user_t *user,
                          const char *statement, qihse_txn_t **txn) {
    sql_reply_t reply = {{0}, 0u};
    uwp_sts_result_t status = uwp_dispatch_sql(ctx, 0x02,
        (const uint8_t*)statement, strlen(statement) + 1, txn, user, -1,
        capture_sql_reply, &reply);
    if (status != UWP_STS_OK) {
        fprintf(stderr, "w11 SQL failed status=%d txn=%p reply=%s: %s\n",
                (int)status, (void*)*txn, reply.text, statement);
        return false;
    }
    return true;
}

static bool sql_exec(qihse_uwp_context_t *ctx, qihse_user_t *user,
                     const char *statement) {
    qihse_txn_t *txn = NULL;
    return sql_statement(ctx, user, statement, &txn) && txn == NULL;
}

static bool sql_insert_finding(qihse_uwp_context_t *ctx, qihse_user_t *user,
                               unsigned id, const char *detail) {
    qihse_txn_t *txn = NULL;
    char statement[384];
    if (!sql_statement(ctx, user, "BEGIN", &txn)) return false;
    snprintf(statement, sizeof statement,
             "INSERT INTO w11_findings VALUES (%u, '%s')", id, detail);
    if (!sql_statement(ctx, user, statement, &txn)) {
        if (txn) (void)sql_statement(ctx, user, "ROLLBACK", &txn);
        return false;
    }
    if (!sql_statement(ctx, user, "COMMIT", &txn))
        return false; /* Commit may be in doubt; do not issue a contradictory abort. */
    return txn == NULL;
}

static bool sql_finding_is(qihse_uwp_context_t *ctx, qihse_user_t *user,
                           unsigned id, const char *expected) {
    char statement[160];
    snprintf(statement, sizeof statement,
             "SELECT detail FROM w11_findings WHERE id = %u", id);
    qihse_txn_t *txn = NULL;
    qihse_uwp_sql_result_t *result = NULL;
    uwp_sts_result_t status = qihse_uwp_sql_execute_typed_user(
        ctx, statement, NULL, 0, &txn, user, &result);
    bool ok = status == UWP_STS_OK && txn == NULL && result &&
        result->ncolumns == 1u && result->nrows == 1u &&
        result->rows[0][0].type == QIHSE_TS_STRING &&
        result->rows[0][0].v.str &&
        strcmp(result->rows[0][0].v.str, expected) == 0;
    qihse_uwp_sql_result_free(result);
    return ok;
}

/* Deterministic binary payload: embedded NULs and high bytes so a string API
 * cannot carry it. Regenerated identically in every process. */
static int sql_engine_placeholder;

static void sql_context_open(qihse_uwp_context_t *ctx, const char *path,
                             const char *journal, bool create_schema) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->sql_engine = &sql_engine_placeholder;
    ctx->txn_manager = qihse_txn_manager_create_durable(journal);
    if (create_schema) ctx->schema = qihse_schema_registry_create();
    require(ctx->txn_manager != NULL && (!create_schema || ctx->schema != NULL),
            "SQL context");
    require(qihse_uwp_sql_open_durable(ctx, path) == 0, "durable SQL open");
}

static void sql_context_close(qihse_uwp_context_t *ctx) {
    qihse_uwp_sql_close_durable(ctx);
    qihse_txn_manager_destroy((qihse_txn_manager_t*)ctx->txn_manager);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)ctx->schema);
    memset(ctx, 0, sizeof(*ctx));
}

static void blob_payload(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)(i * 131u + 7u);
}

typedef struct {
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    uint64_t size;
    unsigned matches, total;
} blob_find_t;

static bool blob_find_cb(const qihse_blob_info_t *info, void *opaque) {
    blob_find_t *f = opaque;
    f->total++;
    if (info->tag == (uint16_t)QIHSE_BLOB_TAG_DUMP_ARTIFACT &&
        info->classification == BLOB_CLASSIFICATION) {
        memcpy(f->hash, info->hash, QIHSE_BLOB_HASH_BYTES);
        f->size = info->size;
        f->matches++;
    }
    return true;
}

/* Verify exact bytes and live metadata; terminal decision replay must not
 * repeat the historical reference increment or reset subsequent pins. */
static void verify_blob(qihse_blob_store_t *blobs, qihse_user_t *op,
                        uint8_t out_hash[QIHSE_BLOB_HASH_BYTES]) {
    blob_find_t f = {0};
    require(qihse_blob_list_user(blobs, op, blob_find_cb, &f), "blob enumeration");
    require(f.matches == 1u && f.total == 1u, "single protected blob");
    require(f.size == BLOB_PAYLOAD_BYTES, "blob size");
    require(qihse_blob_verify_user(blobs, f.hash, op), "blob hash verification");
    uint8_t buf[BLOB_PAYLOAD_BYTES], want[BLOB_PAYLOAD_BYTES];
    size_t nread = 0;
    require(qihse_blob_get_user(blobs, f.hash, 0, buf, sizeof buf, &nread, op), "blob read");
    require(nread == sizeof buf, "blob read size");
    blob_payload(want, sizeof want);
    require(memcmp(buf, want, sizeof want) == 0, "blob bytes");
    uint8_t expected_hash[QIHSE_BLOB_HASH_BYTES];
    require(SHA384(want, sizeof want, expected_hash) != NULL &&
            memcmp(f.hash, expected_hash, sizeof expected_hash) == 0,
            "blob expected SHA-384");
    qihse_blob_info_t info = {0};
    uint32_t pins = 0;
    require(qihse_blob_info_user(blobs, f.hash, &info, op) &&
            memcmp(info.hash, expected_hash, sizeof expected_hash) == 0 &&
            info.size == BLOB_PAYLOAD_BYTES && info.tenant_id == BLOB_TENANT &&
            info.tag == QIHSE_BLOB_TAG_DUMP_ARTIFACT &&
            info.classification == BLOB_CLASSIFICATION &&
            info.sci_compartment == BLOB_SCI && info.refcount == BLOB_REFCOUNT,
            "blob exact metadata");
    require(qihse_blob_pin_count_user(blobs, f.hash, op, &pins) &&
            pins == BLOB_PIN_COUNT, "blob exact pin count");
    if (out_hash) memcpy(out_hash, f.hash, QIHSE_BLOB_HASH_BYTES);
}

/* A classification-0 guest must be denied the protected blob. */
static void blob_denied(qihse_blob_store_t *blobs, qihse_user_t *low,
                        const uint8_t hash[QIHSE_BLOB_HASH_BYTES]) {
    uint8_t buf[64], sentinel[64];
    memset(buf, 0xa5, sizeof buf);
    memcpy(sentinel, buf, sizeof buf);
    size_t nread = 0;
    require(!qihse_blob_get_user(blobs, hash, 0, buf, sizeof buf, &nread, low) &&
            nread == 0 && memcmp(buf, sentinel, sizeof buf) == 0,
            "low clearance blob denial without disclosure");
    require(!qihse_blob_verify_user(blobs, hash, low),
            "low clearance blob verify denial");
    qihse_blob_info_t info;
    uint32_t pins = 0;
    require(!qihse_blob_info_user(blobs, hash, &info, low) &&
            !qihse_blob_pin_count_user(blobs, hash, low, &pins),
            "low clearance blob metadata denial");
    blob_find_t found = {0};
    require(qihse_blob_list_user(blobs, low, blob_find_cb, &found) && found.total == 0,
            "low clearance blob enumeration filtered");
}

/* Fixture fingerprints cover fields explicitly, never pointer values/padding.
 * Expectations are captured before export, not reconstructed during recovery. */
static void provenance_text(EVP_MD_CTX *ctx, const char *text) {
    require(text && EVP_DigestUpdate(ctx, text, strlen(text) + 1u) == 1,
            "provenance field digest");
}

static void index_row_provenance(char out[256], unsigned ordinal,
        const qihse_ai_memory_knowledge_version_t *row) {
    require(strcmp(row->scope.project, W11_INDEX_SCOPE.project) == 0 &&
            strcmp(row->scope.worktree, W11_INDEX_SCOPE.worktree) == 0 &&
            strcmp(row->scope.workstream, W11_INDEX_SCOPE.workstream) == 0 &&
            strcmp(row->scope.session, W11_INDEX_SCOPE.session) == 0 &&
            row->source_event_count <= 1u && row->relation_count <= 2u,
            "source version scope and bounded provenance");
    if (ordinal != 0u)
        require(row->source_event_count == 0u && row->relation_count == 0u &&
            row->supersedes_version[0] == '\0' && row->source_ref.system[0] == '\0' &&
            row->source_ref.id[0] == '\0' && row->source_ref.revision[0] == '\0' &&
            row->source_ref.line_start == 0u && row->source_ref.line_end == 0u,
            "unchanged empty provenance for other original chains");
    char numbers[256];
    int n = snprintf(numbers, sizeof numbers, "%u:%u:%llu:%llu:%llu:%llu:%u:%u:%u:%u:%u:%u:%zu:%zu",
        row->type, row->status, (unsigned long long)row->revision,
        (unsigned long long)row->created_at_ms,
        (unsigned long long)row->valid_from_ingest_ms,
        (unsigned long long)row->valid_to_ingest_ms, row->created_by,
        row->generated_by, row->reviewed_by, row->confidence_ppm,
        row->source_ref.line_start, row->source_ref.line_end,
        row->source_event_count, row->relation_count);
    require(n > 0 && (size_t)n < sizeof numbers, "bounded source provenance fields");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    require(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1, "provenance digest init");
    provenance_text(ctx, numbers);
    const char *fields[] = {row->knowledge_id, row->version_id, row->supersedes_version,
        row->scope.project, row->scope.worktree, row->scope.workstream, row->scope.session,
        row->content_sha256, row->source_ref.system, row->source_ref.id, row->source_ref.revision};
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; ++i) provenance_text(ctx, fields[i]);
    for (size_t i = 0; i < row->source_event_count; ++i)
        provenance_text(ctx, row->source_event_ids[i]);
    for (size_t i = 0; i < row->relation_count; ++i) {
        const qihse_ai_memory_relation_t *r = &row->relations[i];
        n = snprintf(numbers, sizeof numbers, "%u", r->type);
        require(n > 0 && (size_t)n < sizeof numbers, "relation type");
        provenance_text(ctx, numbers); provenance_text(ctx, r->target_version_id);
        provenance_text(ctx, r->target_scope.project); provenance_text(ctx, r->target_scope.worktree);
        provenance_text(ctx, r->target_scope.workstream); provenance_text(ctx, r->target_scope.session);
    }
    unsigned char hash[32]; unsigned length = 0;
    require(EVP_DigestFinal_ex(ctx, hash, &length) == 1 && length == sizeof hash,
            "provenance digest finish");
    EVP_MD_CTX_free(ctx);
    for (size_t i = 0; i < sizeof hash; ++i) snprintf(out + 2u * i, 3u, "%02x", hash[i]);
}

/* The authenticated dispatch calls native _ex mutations and syncs under its
 * server KV write lock. No listener/competing writer runs after workers join. */
static void provenance_command(qihse_resp_server_t *server, qihse_user_t *op,
        size_t argc, const char *const *argv, char first[37], char second[37]) {
    qihse_resp_arg_t args[32];
    require(argc <= 32u, "bounded provenance command");
    for (size_t i = 0; i < argc; ++i) {
        args[i].data = (const uint8_t *)argv[i]; args[i].len = strlen(argv[i]);
    }
    uint8_t *reply = NULL; size_t length = 0;
    require(qihse_resp_server_execute(server, op, argc, args, &reply, &length) &&
            reply && length <= 4096u, "authenticated durable provenance dispatch");
    const char *prefix = second ? "*6\r\n*15\r\n$36\r\n" : "$36\r\n";
    size_t offset = strlen(prefix);
    if (!(length >= offset + 38u && !memcmp(reply, prefix, offset))) {
        fprintf(stderr, "provenance command reply: %.*s\n", (int)length, reply);
        require(false, "provenance RESP success, not an error reply");
    }
    memcpy(first, reply + offset, 36u); first[36] = '\0'; offset += 36u;
    if (second) {
        require(length >= offset + 45u && !memcmp(reply + offset, "\r\n$36\r\n", 7u),
                "second provenance UUID bulk field");
        offset += 7u; memcpy(second, reply + offset, 36u); second[36] = '\0'; offset += 36u;
    }
    require(!memcmp(reply + offset, "\r\n", 2u) && (second || length == offset + 2u),
            "provenance UUID terminator");
    free(reply);
}

static void provenance_marker(qihse_kv_store_t *s, qihse_user_t *op,
        const char *name, const char *value) {
    char key[128];
    int n = snprintf(key, sizeof key, "w11/recovery/provenance/%s", name);
    require(n > 0 && (size_t)n < sizeof key && qihse_kv_set_user(s, key, value,
        qihse_user_get_classification(op), qihse_user_get_sci(op), op),
        "protected original provenance expectation");
}

static void event_provenance(char out[256], const qihse_ai_memory_hit_t *event) {
    int n = snprintf(out, 256, "%s:%llu:%u:%u:%u", event->id,
        (unsigned long long)event->created_ms, event->kind,
        event->classification, event->sci_compartment);
    require(n > 0 && n < 256, "bounded source event metadata");
}

static void seed_provenance_event(qihse_resp_server_t *server,
        qihse_kv_store_t *s, qihse_user_t *op, char event_id[37]) {
    struct timespec now;
    require(clock_gettime(CLOCK_REALTIME, &now) == 0 && now.tv_sec > 0,
            "observed source event wall clock");
    char source_ms[32];
    snprintf(source_ms, sizeof source_ms, "%llu", (unsigned long long)now.tv_sec * 1000u +
        (unsigned long long)now.tv_nsec / 1000000u);
    const char *args[] = {"AIMEM", "EVENT", "APPEND", "w11-index-rebuild", "bench",
        "combined", "recover", "w11-combined-recovery", "provenance-seed", "decision",
        source_ms, "synthetic W11 packaged provenance evidence"};
    provenance_command(server, op, sizeof args / sizeof args[0], args, event_id, NULL);
    qihse_ai_memory_hit_t event = {0};
    require(qihse_ai_memory_event_get(server, op, event_id, &W11_INDEX_SCOPE, &event) &&
        !strcmp(event.id, event_id) && event.text && event.created_ms > 0u &&
        event.kind == QIHSE_AIMEM_EVENT &&
        event.classification == qihse_user_get_classification(op) &&
        event.sci_compartment == qihse_user_get_sci(op), "exact original source event");
    provenance_marker(s, op, "event/id", event.id);
    provenance_marker(s, op, "event/text", event.text);
    char metadata[256]; event_provenance(metadata, &event);
    provenance_marker(s, op, "event/meta", metadata);
    free(event.text);
}

/* These exact source versions must be in the package, not created by recovery. */
static void seed_index_rows(qihse_resp_server_t *server,
                             qihse_kv_store_t *s, qihse_user_t *op) {
    char event_id[37];
    seed_provenance_event(server, s, op, event_id);
    for (unsigned i = 0; i < AIMEM_INDEX_ROWS; ++i) {
        char content[96], key[96];
        snprintf(content, sizeof content,
                 "w11-index-procedure-%02u rebuild invariant row", i);
        qihse_ai_memory_knowledge_version_t version = {0};
        if (i == 0u) {
            const char *args[] = {"AIMEM", "KNOWLEDGE", "CREATE-EX-SOURCE", "3", "1", content,
                "w11-index-rebuild", "bench", "combined", "recover", "875000", "w11-chain-create-1",
                "1", event_id, "0", "w11-fixture", "fixtures/w11/recovery-evidence",
                "synthetic-source-r1", "3", "7"};
            char id[37], vid[37];
            provenance_command(server, op, sizeof args / sizeof args[0], args, id, vid);
            require(qihse_ai_memory_knowledge_get(server, op, vid, &W11_INDEX_SCOPE, &version) &&
                !strcmp(version.knowledge_id, id) && version.revision == 1u &&
                version.status == QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
                "durable source-aware original version");
        } else {
            require(qihse_ai_memory_knowledge_create(server, op, &W11_INDEX_SCOPE,
                    QIHSE_AIMEM_KNOWLEDGE_PROCEDURE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
                    content, &version) == QIHSE_AIMEM_WRITE_NEW,
                    "scoped knowledge row creation");
        }
        require(strcmp(version.content, content) == 0, "knowledge row content");
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/id", i);
        require(qihse_kv_set_user(s, key, version.knowledge_id, 0, 0, op),
                "persist source knowledge id");
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/version", i);
        require(qihse_kv_set_user(s, key, version.version_id, 0, 0, op),
                "persist source version id");
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/hash", i);
        require(qihse_kv_set_user(s, key, version.content_sha256, 0, 0, op),
                "persist source content hash");
        if (i == 0u) {
            const char *args[] = {"AIMEM", "KNOWLEDGE", "REVISE-EX-SOURCE",
                version.knowledge_id, version.version_id, "1", "1", W11_REVISED_CONTENT,
                "925000", "w11-chain-revise-2", "1", event_id, "1", "1", version.version_id,
                "w11-index-rebuild", "bench", "combined", "recover", "w11-fixture",
                "fixtures/w11/recovery-evidence", "synthetic-source-r2", "5", "9"};
            char id[37], vid[37];
            provenance_command(server, op, sizeof args / sizeof args[0], args, id, vid);
            qihse_ai_memory_knowledge_version_t revised = {0}, original = {0};
            require(qihse_ai_memory_knowledge_get(server, op, vid, &W11_INDEX_SCOPE, &revised) &&
                qihse_ai_memory_knowledge_get(server, op, version.version_id, &W11_INDEX_SCOPE, &original) &&
                !strcmp(id, version.knowledge_id) && strcmp(vid, version.version_id) &&
                original.status == QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED &&
                original.created_at_ms == version.created_at_ms &&
                original.valid_from_ingest_ms == version.valid_from_ingest_ms &&
                original.created_by == version.created_by && original.generated_by == version.generated_by &&
                original.reviewed_by == version.reviewed_by &&
                !strcmp(original.content, version.content) &&
                !strcmp(original.content_sha256, version.content_sha256) &&
                original.valid_to_ingest_ms == revised.valid_from_ingest_ms &&
                original.valid_from_ingest_ms < revised.valid_from_ingest_ms,
                "source supersession preserves original identity and ingestion boundary");
            provenance_marker(s, op, "chain/version", revised.version_id);
            provenance_marker(s, op, "chain/hash", revised.content_sha256);
            char metadata[256]; index_row_provenance(metadata, 0u, &revised);
            provenance_marker(s, op, "chain/meta", metadata);
            qihse_ai_memory_knowledge_free(&revised);
            qihse_ai_memory_knowledge_free(&version);
            version = original;
        }
        char provenance[256];
        index_row_provenance(provenance, i, &version);
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/provenance", i);
        require(qihse_kv_set_user(s, key, provenance, 0, 0, op),
                "persist source provenance");
        if (i == 0) require(qihse_kv_set_user(s,
                "w11/recovery/aimem-knowledge-id", version.knowledge_id, 0, 0, op),
                "persist first knowledge id");
        if (i == 0u) {
            /* An exact native retry durably fences expectation markers under
             * the dispatch KV lock without creating another version. */
            const char *args[] = {"AIMEM", "KNOWLEDGE", "REVISE-EX-SOURCE",
                version.knowledge_id, version.version_id, "1", "1", W11_REVISED_CONTENT,
                "925000", "w11-chain-revise-2", "1", event_id, "1", "1", version.version_id,
                "w11-index-rebuild", "bench", "combined", "recover", "w11-fixture",
                "fixtures/w11/recovery-evidence", "synthetic-source-r2", "5", "9"};
            char id[37], vid[37];
            provenance_command(server, op, sizeof args / sizeof args[0], args, id, vid);
            char *expected = get(s, op, "w11/recovery/provenance/chain/version");
            require(expected && !strcmp(id, version.knowledge_id) && !strcmp(vid, expected),
                    "durable exact revision retry retains original revised UUID");
            free(expected);
        }
        qihse_ai_memory_knowledge_free(&version);
    }
}

static void verify_provenance_chain(qihse_resp_server_t *server,
        qihse_kv_store_t *s, qihse_user_t *op) {
    char *first_id = get(s, op, "w11/recovery/knowledge/0/version");
    char *second_id = get(s, op, "w11/recovery/provenance/chain/version");
    char *knowledge = get(s, op, "w11/recovery/knowledge/0/id");
    char *event_id = get(s, op, "w11/recovery/provenance/event/id");
    char *expected_hash = get(s, op, "w11/recovery/provenance/chain/hash");
    char *expected_meta = get(s, op, "w11/recovery/provenance/chain/meta");
    require(first_id && second_id && knowledge && event_id && expected_hash && expected_meta,
            "packaged original provenance references");
    qihse_ai_memory_knowledge_version_t first = {0}, second = {0};
    require(qihse_ai_memory_knowledge_get(server, op, first_id, &W11_INDEX_SCOPE, &first) &&
        qihse_ai_memory_knowledge_get(server, op, second_id, &W11_INDEX_SCOPE, &second),
        "both original source versions retained");
    require(first.revision == 1u && first.status == QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED &&
        second.revision == 2u && second.status == QIHSE_AIMEM_KNOWLEDGE_PROPOSED &&
        !strcmp(first.knowledge_id, knowledge) && !strcmp(second.knowledge_id, knowledge) &&
        !strcmp(second.supersedes_version, first_id) && !first.supersedes_version[0] &&
        first.valid_from_ingest_ms > 0u && first.valid_from_ingest_ms < second.valid_from_ingest_ms &&
        first.valid_to_ingest_ms == second.valid_from_ingest_ms && !second.valid_to_ingest_ms &&
        first.confidence_ppm == 875000u && second.confidence_ppm == 925000u &&
        first.relation_count == 0u && second.relation_count == 2u &&
        !strcmp(second.content, W11_REVISED_CONTENT), "exact source supersession chain");
    const qihse_ai_memory_knowledge_version_t *versions[] = {&first, &second};
    for (unsigned i = 0; i < 2u; ++i) {
        const qihse_ai_memory_knowledge_version_t *v = versions[i];
        require(v->type == QIHSE_AIMEM_KNOWLEDGE_PROCEDURE &&
            v->created_by == qihse_user_get_id(op) && v->generated_by == qihse_user_get_id(op) &&
            !v->reviewed_by && v->source_event_count == 1u &&
            !strcmp(v->source_event_ids[0], event_id) &&
            !strcmp(v->source_ref.system, "w11-fixture") &&
            !strcmp(v->source_ref.id, "fixtures/w11/recovery-evidence") &&
            !strcmp(v->source_ref.revision, i ? "synthetic-source-r2" : "synthetic-source-r1") &&
            v->source_ref.line_start == (i ? 5u : 3u) && v->source_ref.line_end == (i ? 9u : 7u),
            "nonempty exact opaque source reference, event and server actors");
    }
    for (unsigned i = 0; i < 2u; ++i) {
        const qihse_ai_memory_relation_t *r = &second.relations[i];
        require(r->type == (i ? QIHSE_AIMEM_RELATION_SUPERSEDES : QIHSE_AIMEM_RELATION_FIXES) &&
            !strcmp(r->target_version_id, first_id) &&
            !strcmp(r->target_scope.project, W11_INDEX_SCOPE.project) &&
            !strcmp(r->target_scope.worktree, W11_INDEX_SCOPE.worktree) &&
            !strcmp(r->target_scope.workstream, W11_INDEX_SCOPE.workstream) &&
            !strcmp(r->target_scope.session, W11_INDEX_SCOPE.session), "exact typed source relations");
    }
    uint8_t hash[32]; char hex[65], metadata[256];
    require(SHA256((const uint8_t *)W11_REVISED_CONTENT, strlen(W11_REVISED_CONTENT), hash) != NULL,
            "revised content hash recomputation");
    for (size_t i = 0; i < sizeof hash; ++i) snprintf(hex + 2u * i, 3u, "%02x", hash[i]);
    index_row_provenance(metadata, 0u, &second);
    require(!strcmp(hex, second.content_sha256) && !strcmp(hex, expected_hash) &&
        !strcmp(metadata, expected_meta), "exact pre-export revised hash and complete provenance");
    uint64_t cuts[] = {first.valid_from_ingest_ms, first.valid_to_ingest_ms - 1u,
        first.valid_to_ingest_ms};
    for (unsigned i = 0; i < 4u; ++i) {
        qihse_ai_memory_knowledge_version_t observed = {0};
        require(i == 3u ? qihse_ai_memory_knowledge_latest(server, op, knowledge, &W11_INDEX_SCOPE, &observed)
            : qihse_ai_memory_knowledge_as_of(server, op, knowledge, &W11_INDEX_SCOPE, cuts[i], &observed),
            "authenticated latest and half-open as-of reads");
        char want[256], actual[256];
        const qihse_ai_memory_knowledge_version_t *v = i < 2u ? &first : &second;
        index_row_provenance(want, 0u, v); index_row_provenance(actual, 0u, &observed);
        require(observed.content && !strcmp(observed.content, v->content) && !strcmp(want, actual),
                "complete temporal version equals original packaged version");
        qihse_ai_memory_knowledge_free(&observed);
    }
    char *event_text = get(s, op, "w11/recovery/provenance/event/text");
    char *event_meta = get(s, op, "w11/recovery/provenance/event/meta");
    qihse_ai_memory_hit_t event = {0};
    require(event_text && event_meta &&
        qihse_ai_memory_event_get(server, op, event_id, &W11_INDEX_SCOPE, &event) && event.text &&
        !strcmp(event.text, event_text), "exact original event envelope after restore");
    event_provenance(metadata, &event);
    require(!strcmp(metadata, event_meta) && event.score == 0.0,
            "original event ID, ingestion time, kind and labels preserved");
    free(event.text); free(event_text); free(event_meta);
    qihse_ai_memory_knowledge_free(&first); qihse_ai_memory_knowledge_free(&second);
    free(first_id); free(second_id); free(knowledge); free(event_id); free(expected_hash); free(expected_meta);
}

static void verify_index_rows(qihse_resp_server_t *server,
                               qihse_kv_store_t *s, qihse_user_t *op) {
    for (unsigned i = 0; i < AIMEM_INDEX_ROWS; ++i) {
        char expected[96], key[96];
        snprintf(expected, sizeof expected,
                 "w11-index-procedure-%02u rebuild invariant row", i);
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/id", i);
        char *id = get(s, op, key);
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/version", i);
        char *version = get(s, op, key);
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/hash", i);
        char *hash = get(s, op, key);
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/provenance", i);
        char *provenance = get(s, op, key);
        uint8_t digest[SHA256_DIGEST_LENGTH];
        char expected_hash[SHA256_DIGEST_LENGTH * 2u + 1u];
        require(SHA256((const uint8_t *)expected, strlen(expected), digest) != NULL,
                "source content hash recomputation");
        for (size_t j = 0; j < sizeof digest; ++j)
            snprintf(expected_hash + j * 2u, 3u, "%02x", digest[j]);
        qihse_ai_memory_knowledge_version_t row = {0};
        require(id && version && hash &&
                (i == 0u ? qihse_ai_memory_knowledge_get(server, op, version, &W11_INDEX_SCOPE, &row)
                          : qihse_ai_memory_knowledge_latest(server, op, id, &W11_INDEX_SCOPE, &row)) && row.content &&
                strcmp(row.knowledge_id, id) == 0 &&
                strcmp(row.version_id, version) == 0 &&
                strcmp(row.content_sha256, hash) == 0 &&
                strcmp(hash, expected_hash) == 0 &&
                strcmp(row.content, expected) == 0 && row.revision == 1u &&
                row.type == QIHSE_AIMEM_KNOWLEDGE_PROCEDURE &&
                row.status == (i == 0u ? QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED : QIHSE_AIMEM_KNOWLEDGE_PROPOSED) &&
                row.created_by == qihse_user_get_id(op),
                "exact packaged knowledge source version readback");
        char actual_provenance[256];
        index_row_provenance(actual_provenance, i, &row);
        require(provenance && strcmp(provenance, actual_provenance) == 0,
                "exact packaged source provenance readback");
        free(provenance);
        qihse_ai_memory_knowledge_free(&row);
        free(id);
        free(version);
        free(hash);
    }
    verify_provenance_chain(server, s, op);
}

/* Bounded authenticated rebuild after native restore, not full W11 acceptance. */
static void aimem_index_rebuild_probe(qihse_resp_server_t *server,
                                      qihse_kv_store_t *s, qihse_user_t *op,
                                      qihse_user_t *low) {
    verify_index_rows(server, s, op);
    require(qihse_user_get_classification(op) == UINT16_MAX &&
            qihse_user_get_sci(op) == UINT16_MAX,
            "durable operator rebuild clearance");
    require(qihse_ai_memory_index_rebuild(server, op, &W11_INDEX_SCOPE),
            "operator derived-index rebuild");
    qihse_ai_memory_health_t health;
    require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health) &&
            health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
            health.generation >= 1u &&
            health.candidate_generation == health.generation &&
            health.indexed_records == AIMEM_INDEX_ROWS &&
            health.rebuild_started >= 1u && health.rebuild_ready >= 1u &&
            health.provider[0] != '\0' && health.dimension > 0u,
            "rebuilt index durable READY state");
    verify_index_rows(server, s, op);
    require(!qihse_ai_memory_index_rebuild(server, low, &W11_INDEX_SCOPE),
            "low clearance index rebuild denial");
    char generation[32], records[32];
    snprintf(generation, sizeof generation, "%llu",
             (unsigned long long)health.generation);
    snprintf(records, sizeof records, "%llu",
             (unsigned long long)health.indexed_records);
    require(qihse_kv_set_user(s, "w11/recovery/aimem-index-generation",
            generation, 0, 0, op) &&
            qihse_kv_set_user(s, "w11/recovery/aimem-index-records",
            records, 0, 0, op), "persist index expectations");
}

static FILE *private_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    require(fd >= 0, "exclusive private fixture output");
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        (void)close(fd);
        require(unlink(path) == 0, "remove unopened fixture output");
    }
    require(f != NULL, "fixture output stream");
    return f;
}

/* An archive export failure invalidates every byte, including a partial MAC. */
static void finish_output(FILE *f, const char *path, bool ok) {
    if (ok && fflush(f) != 0) ok = false;
    if (ok && fsync(fileno(f)) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok) require(unlink(path) == 0, "discard partial fixture output");
    require(ok, "durable fixture output");
}

/* Only this executable exports the library's optional weak test hook. No
 * environment-controlled production failpoint or audit suppression is used. */
static const char *index_interrupt_root, *index_interrupt_nonce, *index_interrupt_phase;
static qihse_kv_store_t *index_interrupt_store;

static unsigned index_phase_ordinal(const char *phase) {
    if (phase && !strcmp(phase, "first")) return 0u;
    if (phase && !strcmp(phase, "last")) return 1u;
    if (phase && !strcmp(phase, "before_swap")) return 2u;
    require(phase && !strcmp(phase, "private_ready"), "known index interruption phase");
    return 3u;
}

static void kill_interrupted_index(qihse_kv_store_t *store) {
    require(qihse_kv_sync_store(store), "sync interrupted candidate generation");
    char path[PATH_MAX], leaf[80];
    int n = snprintf(leaf, sizeof leaf, "index-interrupt.%s.witness", index_interrupt_phase);
    require(n > 0 && (size_t)n < sizeof leaf, "interruption witness name");
    join_path(path, index_interrupt_root, leaf);
    FILE *f = private_output(path);
    unsigned entries = index_phase_ordinal(index_interrupt_phase) == 0u ? 1u : AIMEM_INDEX_ROWS;
    bool ok = fprintf(f, "w11-index-%s-%u-synced:%s\n", index_interrupt_phase,
            entries, index_interrupt_nonce) > 0;
    finish_output(f, path, ok);
    int dir = open(index_interrupt_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(dir >= 0 && fsync(dir) == 0 && close(dir) == 0,
            "sync interruption witness directory");
    (void)kill(getpid(), SIGKILL);
    _exit(103); /* A returned kill is never accepted as the injected crash. */
}

void qihse_aimem_test_rebuild_entry_hook(qihse_kv_store_t *store,
                                         size_t entry_index) {
    if (!index_interrupt_nonce) return;
    if ((!strcmp(index_interrupt_phase, "first") && entry_index == 0u) ||
        (!strcmp(index_interrupt_phase, "last") && entry_index == AIMEM_INDEX_ROWS - 1u))
        kill_interrupted_index(store);
}

bool qihse_aimem_test_failpoint(const char *name) {
    if (index_interrupt_nonce &&
        ((!strcmp(index_interrupt_phase, "before_swap") && !strcmp(name, "after-entries")) ||
         (!strcmp(index_interrupt_phase, "private_ready") && !strcmp(name, "after-private-ready"))))
        kill_interrupted_index(index_interrupt_store);
    return false;
}

static size_t interrupted_candidate_count(qihse_kv_store_t *s, qihse_user_t *op) {
    char *phase = get(s, op, "w11/recovery/aimem-index-interruption-phase");
    unsigned ordinal = index_phase_ordinal(phase);
    free(phase);
    return ordinal == 0u ? 1u : AIMEM_INDEX_ROWS;
}

static qihse_ai_memory_health_t index_interruption_baseline(
        qihse_kv_store_t *s, qihse_user_t *op) {
    char *raw = get(s, op, "w11/recovery/aimem-index-interruption-baseline");
    unsigned long long generation, recovered, started, failed, ready;
    char extra;
    require(raw && sscanf(raw, "%llu %llu %llu %llu %llu%c", &generation,
            &recovered, &started, &failed, &ready, &extra) == 5,
            "durable pre-interruption index baseline");
    free(raw);
    qihse_ai_memory_health_t baseline = {.generation = generation,
        .recovered_builds = recovered, .rebuild_started = started,
        .rebuild_failed = failed, .rebuild_ready = ready};
    return baseline;
}

static bool count_index_entry(const char *key, const char *value, void *opaque) {
    (void)key;
    (void)value;
    ++*(size_t *)opaque;
    return true;
}

/* Authenticated enumeration proves the failed candidate survived reopening;
 * restoring the package again would erase both this entry and BUILDING state. */
static void verify_candidate_entries(qihse_kv_store_t *s, qihse_user_t *op,
                                      uint64_t generation, size_t expected) {
    char canonical[256], digest_hex[65], prefix[160];
    uint8_t digest[SHA256_DIGEST_LENGTH];
    int n = snprintf(canonical, sizeof canonical, "%s|%s|%s|%s",
        W11_INDEX_SCOPE.project, W11_INDEX_SCOPE.worktree,
        W11_INDEX_SCOPE.workstream, W11_INDEX_SCOPE.session);
    require(n > 0 && (size_t)n < sizeof canonical &&
            SHA256((const uint8_t *)canonical, (size_t)n, digest) != NULL,
            "candidate scope hash");
    for (size_t i = 0; i < sizeof digest; ++i)
        snprintf(digest_hex + i * 2u, 3u, "%02x", digest[i]);
    n = snprintf(prefix, sizeof prefix, "t:%u/aimem-index-gen:%s:%llu:",
        (unsigned)qihse_user_get_tenant_id(op), digest_hex,
        (unsigned long long)generation);
    size_t count = 0;
    require(n > 0 && (size_t)n < sizeof prefix &&
            qihse_kv_foreach_prefix_user(s, prefix, op, count_index_entry, &count) &&
            count == expected, "exact durable candidate entry count");
    if (expected == AIMEM_INDEX_ROWS) {
        char *id = get(s, op, "w11/recovery/knowledge/0/id");
        char *version = get(s, op, "w11/recovery/provenance/chain/version");
        require(id && version && SHA256((const uint8_t *)id, strlen(id), digest) != NULL,
                "revised head candidate ID digest");
        for (size_t i = 0; i < sizeof digest; ++i)
            snprintf(digest_hex + i * 2u, 3u, "%02x", digest[i]);
        char key[256]; n = snprintf(key, sizeof key, "%s%s", prefix, digest_hex);
        require(n > 0 && (size_t)n < sizeof key, "revised head candidate key");
        char *value = get(s, op, key);
        require(value && !strncmp(value, "QHIX1|", 6u), "native candidate encoding");
        const char *field = strchr(value + 6u, '|');
        field = field ? strchr(field + 1u, '|') : NULL;
        require(field && strlen(field + 1u) > 36u &&
            !strncmp(field + 1u, version, 36u) && field[37] == '|',
            "complete candidate generation points to original packaged revised head");
        free(value); free(id); free(version);
    }
}

static void interrupt_index(qihse_resp_server_t *server, qihse_kv_store_t *s,
                            qihse_user_t *op, const char *root, const char *nonce,
                            const char *phase) {
    unsigned ordinal = index_phase_ordinal(phase);
    qihse_ai_memory_health_t before;
    require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &before) &&
            before.ready && before.index_state == QIHSE_AIMEM_INDEX_READY &&
            before.generation == ordinal * 2u + 1u &&
            before.candidate_generation == before.generation &&
            before.indexed_records == AIMEM_INDEX_ROWS &&
            before.recovered_builds == ordinal && before.rebuild_failed == ordinal &&
            before.rebuild_started == ordinal * 2u + 1u &&
            before.rebuild_ready == ordinal + 1u,
            "fresh-process restored index READY before interruption");
    char baseline[160];
    int n = snprintf(baseline, sizeof baseline, "%llu %llu %llu %llu %llu",
        (unsigned long long)before.generation,
        (unsigned long long)before.recovered_builds,
        (unsigned long long)before.rebuild_started,
        (unsigned long long)before.rebuild_failed,
        (unsigned long long)before.rebuild_ready);
    require(n > 0 && (size_t)n < sizeof baseline &&
            qihse_kv_set_user(s, "w11/recovery/aimem-index-interruption-baseline",
            baseline, 0, 0, op) &&
            qihse_kv_set_user(s, "w11/recovery/aimem-index-interruption-phase",
            phase, 0, 0, op), "save interruption baseline and phase before rebuild");
    require(nonce && strlen(nonce) == 32u, "fresh fixture interruption nonce");
    index_interrupt_root = root;
    index_interrupt_nonce = nonce;
    index_interrupt_phase = phase;
    index_interrupt_store = s;
    (void)qihse_ai_memory_index_rebuild(server, op, &W11_INDEX_SCOPE);
    require(false, "interruption hook must kill before rebuild returns");
}

static void recover_interrupted_index(qihse_resp_server_t *server,
        qihse_kv_store_t *s, qihse_user_t *op, qihse_user_t *low) {
    qihse_ai_memory_health_t baseline = index_interruption_baseline(s, op), health;
    char *phase = get(s, op, "w11/recovery/aimem-index-interruption-phase");
    bool private_ready = index_phase_ordinal(phase) == 3u;
    free(phase);
    if (private_ready) {
        require(baseline.generation == 7u && baseline.rebuild_started == 7u &&
                baseline.rebuild_ready == 4u && baseline.rebuild_failed == 3u &&
                baseline.recovered_builds == 3u, "private READY phase-three baseline");
        require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health) &&
                !health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
                health.generation == 8u && health.candidate_generation == 8u &&
                health.indexed_records == AIMEM_INDEX_ROWS &&
                health.rebuild_started == 8u && health.rebuild_ready == 5u &&
                health.rebuild_failed == 3u && health.recovered_builds == 3u,
                "reopened private READY committed generation 8 remains unavailable");
        verify_candidate_entries(s, op, 8u, AIMEM_INDEX_ROWS);
        verify_index_rows(server, s, op);
        require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health),
                "snapshot committed-unavailable health before explicit recovery");
        qihse_ai_memory_health_t committed;
        memcpy(&committed, &health, sizeof committed);
        /* Health zeroes its output: compare every field, including counters.
         * Recovery must neither fail this committed generation nor publish it. */
        require(qihse_ai_memory_index_recover(server, op, &W11_INDEX_SCOPE) &&
                qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health) &&
                memcmp(&health, &committed, sizeof health) == 0,
                "explicit recovery preserves private READY and all health counters");
        verify_candidate_entries(s, op, 8u, AIMEM_INDEX_ROWS);
        verify_index_rows(server, s, op);
        require(qihse_kv_set_user(s, "w11/recovery/aimem-index-private-ready-observed",
                "8 8 8 0 8 5 3 3", 0, 0, op),
                "retain observed committed-unavailable state and recovery no-op evidence");
        fprintf(stderr, "verified private READY gen8 candidate8 entries8 ready=false "
                "started8 ready5 failed3 recovered3; explicit recovery unchanged\n");
    } else {
        require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health) &&
                !health.ready && health.index_state == QIHSE_AIMEM_INDEX_BUILDING &&
                health.generation == baseline.generation &&
                health.candidate_generation == baseline.generation + 1u &&
                health.rebuild_started == baseline.rebuild_started + 1u &&
                health.rebuild_ready == baseline.rebuild_ready &&
                health.rebuild_failed == baseline.rebuild_failed &&
                health.recovered_builds == baseline.recovered_builds &&
                health.indexed_records == 0u, "reopened interrupted BUILDING generation");
        verify_candidate_entries(s, op, health.candidate_generation,
                interrupted_candidate_count(s, op));
        require(qihse_ai_memory_index_recover(server, op, &W11_INDEX_SCOPE) &&
                qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health) &&
                !health.ready && health.index_state == QIHSE_AIMEM_INDEX_FAILED &&
                health.recovered_builds == baseline.recovered_builds + 1u &&
                health.rebuild_failed == baseline.rebuild_failed + 1u,
                "explicit interrupted index recovery increments counters");
    }
    aimem_index_rebuild_probe(server, s, op, low);
    require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &health) &&
            health.generation == baseline.generation + 2u &&
            health.recovered_builds == baseline.recovered_builds + (private_ready ? 0u : 1u) &&
            health.rebuild_failed == baseline.rebuild_failed + (private_ready ? 0u : 1u) &&
            health.rebuild_started == baseline.rebuild_started + 2u &&
            health.rebuild_ready == baseline.rebuild_ready + (private_ready ? 2u : 1u),
            "new READY generation after explicit recovery and authenticated rebuild");
    verify_candidate_entries(s, op, baseline.generation + 1u,
                interrupted_candidate_count(s, op));
    verify_candidate_entries(s, op, health.generation, AIMEM_INDEX_ROWS);
    if (private_ready)
        fprintf(stderr, "verified explicit authenticated rebuild gen9 ready=true "
                "entries8 started9 ready6 failed3 recovered3\n");
}

static void denied_provenance_empty(const qihse_ai_memory_knowledge_version_t *v) {
    require(!v->content && !v->source_event_ids && !v->relations &&
        !v->source_event_count && !v->relation_count && !v->knowledge_id[0] &&
        !v->version_id[0] && !v->supersedes_version[0] && !v->content_sha256[0] &&
        !v->scope.project[0] && !v->scope.worktree[0] && !v->scope.workstream[0] && !v->scope.session[0] &&
        !v->source_ref.system[0] && !v->source_ref.id[0] && !v->source_ref.revision[0] &&
        !v->source_ref.line_start && !v->source_ref.line_end &&
        !v->revision && !v->status && !v->type && !v->created_at_ms &&
        !v->valid_from_ingest_ms && !v->valid_to_ingest_ms &&
        !v->created_by && !v->generated_by && !v->reviewed_by && !v->confidence_ppm,
        "low clearance denial exposes no knowledge provenance fields");
}

static void verify_index_denials(qihse_resp_server_t *server,
        qihse_kv_store_t *s, qihse_user_t *op, qihse_user_t *low) {
    qihse_ai_memory_health_t health;
    require(!qihse_ai_memory_index_rebuild(server, low, &W11_INDEX_SCOPE) &&
            !qihse_ai_memory_index_recover(server, low, &W11_INDEX_SCOPE) &&
            !qihse_ai_memory_health(server, low, &W11_INDEX_SCOPE, &health),
            "low clearance index rebuild/recover/health denied");
    for (unsigned i = 0; i < AIMEM_INDEX_ROWS; ++i) {
        char key[96];
        snprintf(key, sizeof key, "w11/recovery/knowledge/%u/id", i);
        char *id = get(s, op, key);
        qihse_ai_memory_knowledge_version_t denied = {0};
        require(id && !qihse_ai_memory_knowledge_latest(server, low, id,
                &W11_INDEX_SCOPE, &denied) && denied.content == NULL,
                "low clearance packaged knowledge denied without content");
        free(id);
    }
    char *first = get(s, op, "w11/recovery/knowledge/0/version");
    char *second = get(s, op, "w11/recovery/provenance/chain/version");
    char *knowledge = get(s, op, "w11/recovery/knowledge/0/id");
    char *event_id = get(s, op, "w11/recovery/provenance/event/id");
    qihse_ai_memory_knowledge_version_t original = {0};
    require(first && second && knowledge && event_id &&
        qihse_ai_memory_knowledge_get(server, op, first, &W11_INDEX_SCOPE, &original),
        "operator references for negative provenance controls");
    for (unsigned which = 0; which < 5u; ++which) {
        qihse_ai_memory_knowledge_version_t denied = {0};
        bool ok = which < 2u
            ? qihse_ai_memory_knowledge_get(server, low, which ? second : first, &W11_INDEX_SCOPE, &denied)
            : which == 2u ? qihse_ai_memory_knowledge_latest(server, low, knowledge, &W11_INDEX_SCOPE, &denied)
            : qihse_ai_memory_knowledge_as_of(server, low, knowledge, &W11_INDEX_SCOPE,
                which == 3u ? original.valid_from_ingest_ms : original.valid_to_ingest_ms, &denied);
        require(!ok, "low clearance exact/latest/as-of chain access denied");
        denied_provenance_empty(&denied);
    }
    qihse_ai_memory_hit_t event_denied = {0};
    require(!qihse_ai_memory_event_get(server, low, event_id, &W11_INDEX_SCOPE, &event_denied) &&
        !event_denied.text && !event_denied.id[0] && !event_denied.created_ms && !event_denied.kind &&
        !event_denied.classification && !event_denied.sci_compartment && event_denied.score == 0.0 &&
        !get(s, low, "w11/recovery/provenance/event/id"),
        "low clearance original event and protected expectation denial without disclosure");
    qihse_ai_memory_knowledge_free(&original);
    free(first); free(second); free(knowledge); free(event_id);
    char *id = get(s, op, "w11/recovery/memory/00000000");
    qihse_ai_memory_hit_t denied = {0};
    require(id && !qihse_ai_memory_get(server, low, id, &denied) && denied.text == NULL,
            "low clearance original AIMEM denied without content");
    free(id);
}

static void blob_archive_key(const char *path, bool seed,
                              uint8_t key[QIHSE_BLOB_ARCHIVE_KEY_BYTES]) {
    if (seed) {
        require(RAND_priv_bytes(key, QIHSE_BLOB_ARCHIVE_KEY_BYTES) == 1,
                "random disposable blob archive key");
        FILE *f = private_output(path);
        finish_output(f, path, fwrite(key, 1, QIHSE_BLOB_ARCHIVE_KEY_BYTES, f) ==
                QIHSE_BLOB_ARCHIVE_KEY_BYTES);
        return;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    require(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == geteuid() && (st.st_mode & 0777) == 0600 &&
            st.st_size == QIHSE_BLOB_ARCHIVE_KEY_BYTES,
            "private disposable blob archive key");
    FILE *f = fdopen(fd, "rb");
    require(f != NULL, "blob archive key stream");
    bool ok = fread(key, 1, QIHSE_BLOB_ARCHIVE_KEY_BYTES, f) ==
        QIHSE_BLOB_ARCHIVE_KEY_BYTES && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0) ok = false;
    require(ok, "read disposable blob archive key");
}

static bool count_archive_write(void *opaque, const uint8_t *data, size_t length) {
    (void)data;
    *(size_t *)opaque += length;
    return true;
}

static int64_t blob_archive_read(void *opaque, uint8_t *data, size_t capacity) {
    FILE *f = opaque;
    size_t n = fread(data, 1, capacity, f);
    return ferror(f) ? -1 : (int64_t)n;
}

static qihse_blob_archive_result_t restore_blob(const char *archive,
        const char *destination, qihse_user_t *user, const uint8_t *key) {
    FILE *f = fopen(archive, "rb");
    require(f != NULL, "open authenticated blob archive");
    qihse_blob_archive_result_t result = qihse_blob_archive_restore_user(
        destination, user, key, QIHSE_BLOB_ARCHIVE_KEY_BYTES, blob_archive_read, f);
    require(fclose(f) == 0, "close blob archive input");
    return result;
}

static void require_absent(const char *path) {
    struct stat st;
    require(lstat(path, &st) == -1 && errno == ENOENT,
            "fresh blob restore destination absent");
}

typedef struct {
    qihse_blob_store_t *store;
    qihse_user_t *user;
} blob_resource_t;

typedef struct { const uint8_t *bytes; size_t remaining; } blob_input_t;
static unsigned blob_decision_calls;

static int64_t prepared_blob_read(void *opaque, uint8_t *data, size_t capacity) {
    blob_input_t *input = opaque;
    size_t n = input->remaining < capacity ? input->remaining : capacity;
    memcpy(data, input->bytes, n);
    input->bytes += n;
    input->remaining -= n;
    return (int64_t)n;
}

static int blob_prepare_unbound(void *opaque, uint64_t id) {
    (void)opaque;
    (void)id;
    return -1; /* This fixture requires a real, explicitly enlisted resource. */
}

static int blob_prepare_resource(void *opaque, uint64_t id, void *resource) {
    (void)opaque;
    blob_resource_t *r = resource;
    uint8_t payload[BLOB_PAYLOAD_BYTES], hash[QIHSE_BLOB_HASH_BYTES];
    blob_payload(payload, sizeof payload);
    require(SHA384(payload, sizeof payload, hash) != NULL, "prepared blob hash");
    blob_input_t input = {payload, sizeof payload};
    bool ok = qihse_blob_prepare_expected_user(r->store, id, BLOB_TENANT,
        QIHSE_BLOB_TAG_DUMP_ARTIFACT, BLOB_CLASSIFICATION, BLOB_SCI, r->user,
        prepared_blob_read, &input, hash, sizeof payload);
    free(r);
    return ok ? 0 : -1;
}

static int blob_commit_decision(void *opaque, uint64_t id) {
    ++blob_decision_calls;
    return qihse_blob_resolve_prepared(opaque, id, true) ? 0 : -1;
}

static int blob_abort_decision(void *opaque, uint64_t id) {
    ++blob_decision_calls;
    return qihse_blob_resolve_prepared(opaque, id, false) ? 0 : -1;
}

/* Both restored receipt floors and the authenticated unjournaled allocation
 * floor must be installed BEFORE either recovery pass or application reads. */
static uint64_t register_and_replay(qihse_uwp_context_t *sql,
        qihse_blob_store_t *blobs, uint8_t sql_id, uint8_t blob_id,
        uint64_t manifest_floor) {
    qihse_txn_manager_t *mgr = sql->txn_manager;
    require(qihse_uwp_sql_txn_register_durable_participant(mgr, sql_id) == 0,
            "register native durable SQL participant");
    qihse_txn_participant_t bp = {.engine_id = blob_id, .engine_ctx = blobs,
        .prepare = blob_prepare_unbound, .commit = blob_commit_decision,
        .abort = blob_abort_decision};
    require(qihse_txn_register_resource_participant(mgr, bp,
            blob_prepare_resource) == 0, "register native durable blob participant");
    uint64_t sql_floor = 0, blob_floor = 0, floor = manifest_floor;
    require(qihse_table_store_decision_next_id(qihse_uwp_sql_table_store(),
            &sql_floor) && qihse_blob_decision_next_id(blobs, &blob_floor),
            "restored SQL and blob receipt floors");
    /* This fixture has one common decision followed by one unjournaled ID.
     * Prove both native restores retained its receipts BEFORE replay. */
    if (manifest_floor > 1u)
        require(sql_floor > 1u && sql_floor == blob_floor &&
                sql_floor == manifest_floor - 1u,
                "exact SQL/blob terminal receipt floors restored before replay");
    if (floor < sql_floor) floor = sql_floor;
    if (floor < blob_floor) floor = blob_floor;
    require(qihse_txn_advance_next_id(mgr, floor) == 0,
            "advance authenticated and participant ID floors before replay");
    for (unsigned pass = 0; pass < 2u; ++pass)
        require(qihse_txn_manager_recover(mgr) == 0,
                "repeated common-decision replay before application exposure");
    return floor;
}

static void seed_common_decision(qihse_kv_store_t *s, qihse_uwp_context_t *sql,
                                 qihse_blob_store_t *blobs, qihse_user_t *op) {
    qihse_txn_manager_t *mgr = sql->txn_manager;
    qihse_txn_t *txn = NULL;
    require(sql_statement(sql, op, "BEGIN", &txn) && txn,
            "common decision SQL begin");
    uint64_t id = txn->id;
    require(sql_statement(sql, op,
            "INSERT INTO w11_findings VALUES (101, 'shared-decision')", &txn) &&
            qihse_uwp_sql_txn_enlist_durable(mgr, txn, SQL_ENGINE_ID) == 0,
            "explicit real SQL durable enlistment");
    blob_resource_t *resource = calloc(1, sizeof(*resource));
    require(resource != NULL, "common decision blob resource");
    resource->store = blobs;
    resource->user = op;
    require(qihse_txn_attach_participant_resource(mgr, txn, BLOB_ENGINE_ID,
            resource, free) == 0 && qihse_txn_prepare(mgr, txn) == 0 &&
            qihse_txn_commit_prepared(mgr, txn) == 0 &&
            qihse_txn_release(mgr, txn) == 0, "real SQL/blob durable common commit");
    /* Restore the workload's original refcount after the common commit.
     * Receipt replay must not repeat that historical increment. */
    uint8_t payload[BLOB_PAYLOAD_BYTES], hash[QIHSE_BLOB_HASH_BYTES];
    blob_payload(payload, sizeof payload);
    require(SHA384(payload, sizeof payload, hash) != NULL &&
            qihse_blob_unref_user(blobs, hash, op), "post-decision blob reference");
    char value[32];
    snprintf(value, sizeof value, "%llu", (unsigned long long)id);
    require(qihse_kv_set_user(s, "w11/recovery/common-decision", value, 0, 0, op),
            "persist common decision provenance");
    /* This allocated ID has no journal record: only the manifest retains it. */
    txn = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    require(txn && txn->id > id && qihse_txn_rollback(mgr, txn) == 0 &&
            qihse_txn_release(mgr, txn) == 0, "unjournaled allocation before backup");
}

static void copy_journal(const char *source, const char *target, uint64_t expected) {
    FILE *input = fopen(source, "rb");
    require(input != NULL, "open unpacked coordinator journal");
    FILE *output = private_output(target);
    uint8_t chunk[8192];
    uint64_t total = 0;
    size_t n;
    bool ok = true;
    while ((n = fread(chunk, 1, sizeof chunk, input)) != 0) {
        total += n;
        if (total > expected || fwrite(chunk, 1, n, output) != n) {
            ok = false;
            break;
        }
    }
    if (ferror(input) || total != expected) ok = false;
    if (fclose(input) != 0) ok = false;
    finish_output(output, target, ok);
}

static void *work(void *arg) {
    worker_t *w = arg;
    pthread_barrier_wait(w->start);
    for (unsigned j = 0; j < w->count; ++j) {
        unsigned i = w->start_at + j;
        char key[64], value[64];
        if (w->lane == 0) {
            snprintf(key, sizeof key, "w11/recovery/stock");
            unsigned tries = 0;
            for (;;) {
                char *old = get(w->store, w->user, key);
                if (!old) { w->failed = 1; break; }
                char *end = NULL;
                unsigned long stock = strtoul(old, &end, 10);
                if (end == old || *end || stock == 0) {
                    free(old); w->failed = 1; break;
                }
                snprintf(value, sizeof value, "%lu", stock - 1u);
                qihse_kv_cas_result_t rc = qihse_kv_compare_set_user(
                    w->store, key, old, value, 0, 0, w->user);
                free(old);
                if (rc == QIHSE_KV_CAS_UPDATED) break;
                if (rc != QIHSE_KV_CAS_MISMATCH || ++tries > 128u) { w->failed = 1; break; }
            }
        } else if (w->lane == 1) {
            snprintf(value, sizeof value, "finding-%08u", i);
            if (!sql_insert_finding(w->sql, w->user, i, value)) w->failed = 1;
        } else if (w->lane == 2) {
            char id[QIHSE_AIMEM_ID_LEN + 1u];
            snprintf(key, sizeof key, "w11/recovery/memory/%08u", i);
            snprintf(value, sizeof value, "memory-%08u", i);
            if (!qihse_ai_memory_store(w->server, w->user, value,
                    QIHSE_AIMEM_EPISODIC, id) ||
                !qihse_kv_set_user(w->store, key, id, 0, 0, w->user))
                w->failed = 1;
        } else {
            uint8_t payload[BLOB_PAYLOAD_BYTES], hash[QIHSE_BLOB_HASH_BYTES];
            blob_payload(payload, sizeof payload);
            if (!qihse_blob_put_buffer_user(w->blobs, BLOB_TENANT,
                    QIHSE_BLOB_TAG_DUMP_ARTIFACT, BLOB_CLASSIFICATION, BLOB_SCI,
                    w->user, payload, sizeof payload, hash) ||
                !qihse_blob_ref_user(w->blobs, hash, w->user) ||
                !qihse_blob_ref_user(w->blobs, hash, w->user) ||
                !qihse_blob_pin_user(w->blobs, hash, w->user) ||
                !qihse_blob_pin_user(w->blobs, hash, w->user))
                w->failed = 1;
        }
    }
    return NULL;
}

static void cohort_detail(char out[256], const char *cohort,
                          const char *memory_id, const char *blob_hash) {
    int n = snprintf(out, 256, "cohort=%s;memory=%s;blob=%s",
                     cohort, memory_id, blob_hash);
    require(n > 0 && n < 256, "bounded cohort provenance detail");
}

static void seed_cohort(qihse_kv_store_t *s, qihse_uwp_context_t *sql,
                        qihse_blob_store_t *blobs, qihse_user_t *op) {
    uint8_t token[16], blob_hash[QIHSE_BLOB_HASH_BYTES];
    require(RAND_bytes(token, sizeof token) == 1, "random recovery cohort token");
    verify_blob(blobs, op, blob_hash);
    char cohort[sizeof token * 2u + 1u], blob_hex[QIHSE_BLOB_HASH_BYTES * 2u + 1u];
    for (size_t i = 0; i < sizeof token; ++i)
        snprintf(cohort + i * 2u, 3u, "%02x", token[i]);
    for (size_t i = 0; i < sizeof blob_hash; ++i)
        snprintf(blob_hex + i * 2u, 3u, "%02x", blob_hash[i]);
    char *memory_id = get(s, op, "w11/recovery/memory/00000000");
    require(memory_id && strlen(memory_id) == QIHSE_AIMEM_ID_LEN,
            "cohort AIMEM provenance id");
    char detail[256];
    cohort_detail(detail, cohort, memory_id, blob_hex);
    require(qihse_kv_set_user(s, "w11/recovery/cohort", cohort, 0, 0, op) &&
            qihse_kv_set_user(s, "w11/recovery/blob-sha384", blob_hex, 0, 0, op) &&
            sql_insert_finding(sql, op, 100u, detail),
            "persist bounded cross-store cohort provenance");
    free(memory_id);
}

static void verify_cohort(qihse_kv_store_t *s, qihse_uwp_context_t *sql,
                          qihse_resp_server_t *server,
                          qihse_blob_store_t *blobs, qihse_user_t *op) {
    char *cohort = get(s, op, "w11/recovery/cohort");
    char *stored_hash = get(s, op, "w11/recovery/blob-sha384");
    char *memory_id = get(s, op, "w11/recovery/memory/00000000");
    require(cohort && strlen(cohort) == 32u && stored_hash &&
            strlen(stored_hash) == QIHSE_BLOB_HASH_BYTES * 2u && memory_id &&
            strlen(memory_id) == QIHSE_AIMEM_ID_LEN,
            "restored KV cohort provenance fields");
    uint8_t actual_hash[QIHSE_BLOB_HASH_BYTES];
    verify_blob(blobs, op, actual_hash);
    char actual_hex[QIHSE_BLOB_HASH_BYTES * 2u + 1u];
    for (size_t i = 0; i < sizeof actual_hash; ++i)
        snprintf(actual_hex + i * 2u, 3u, "%02x", actual_hash[i]);
    require(strcmp(stored_hash, actual_hex) == 0,
            "KV blob hash matches restored blob bytes");
    char detail[256];
    cohort_detail(detail, cohort, memory_id, actual_hex);
    require(sql_finding_is(sql, op, 100u, detail),
            "SQL cohort provenance matches KV and blob tiers");
    qihse_ai_memory_hit_t hit = {0};
    require(qihse_ai_memory_get(server, op, memory_id, &hit) && hit.text &&
            strcmp(hit.text, "memory-00000000") == 0,
            "cohort AIMEM reference resolves after recovery");
    free(hit.text);
    free(cohort);
    free(stored_hash);
    free(memory_id);
}

static void verify_workload(qihse_kv_store_t *s, qihse_uwp_context_t *sql,
                            qihse_resp_server_t *server, qihse_user_t *op) {
    value_is(s, op, "w11/recovery/stock", "0");
    for (unsigned i = 0; i < OPS; ++i) {
        char key[64], value[64];
        snprintf(value, sizeof value, "finding-%08u", i);
        require(sql_finding_is(sql, op, i, value), "durable SQL finding row");
        snprintf(key, sizeof key, "w11/recovery/memory/%08u", i);
        char *id = get(s, op, key);
        require(id && strlen(id) == QIHSE_AIMEM_ID_LEN, "memory id reference");
        qihse_ai_memory_hit_t hit = {0};
        require(qihse_ai_memory_get(server, op, id, &hit), "AIMEM readback");
        snprintf(value, sizeof value, "memory-%08u", i);
        require(hit.text && strcmp(hit.text, value) == 0, "AIMEM content");
        free(hit.text);
        free(id);
    }
}

static void run_workers(qihse_kv_store_t *s, qihse_uwp_context_t *sql,
                        qihse_resp_server_t *server, qihse_blob_store_t *blobs,
                        qihse_user_t *op) {
    char stock[32]; snprintf(stock, sizeof stock, "%u", OPS);
    require(qihse_kv_set_user(s, "w11/recovery/stock", stock, 0, 0, op), "stock initialize");
    pthread_t threads[5];
    pthread_barrier_t start;
    require(pthread_barrier_init(&start, NULL, 6) == 0, "barrier init");
    worker_t workers[5] = {
        {.store=s, .sql=sql, .server=server, .user=op, .start=&start, .lane=0, .start_at=0, .count=OPS / 2u},
        {.store=s, .sql=sql, .server=server, .user=op, .start=&start, .lane=0, .start_at=OPS / 2u, .count=OPS / 2u},
        {.store=s, .sql=sql, .server=server, .user=op, .start=&start, .lane=1, .count=OPS},
        {.store=s, .sql=sql, .server=server, .user=op, .start=&start, .lane=2, .count=OPS},
        {.blobs=blobs, .user=op, .start=&start, .lane=3, .count=1u},
    };
    for (unsigned i = 0; i < 5; ++i)
        require(pthread_create(&threads[i], NULL, work, &workers[i]) == 0, "pthread create");
    pthread_barrier_wait(&start);
    for (unsigned i = 0; i < 5; ++i)
        require(pthread_join(threads[i], NULL) == 0 && !workers[i].failed, "combined writer");
    pthread_barrier_destroy(&start);
}

int main(int argc, char **argv) {
    OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(NULL, "default");
    require(default_provider != NULL, "OpenSSL default provider");
    require(argc == 5 || argc == 7,
            "usage: MODE FIXTURE_DIR AUTH_DIR KEY_DIR [INTERRUPTION_NONCE PHASE]");
    const char *mode = argv[1], *root = argv[2];
    const char *auth_dir = argv[3], *key_dir = argv[4];
    bool seed = strcmp(mode, "seed") == 0;
    bool final = strcmp(mode, "final") == 0;
    bool restore = strcmp(mode, "recover") == 0;
    bool interrupt = strcmp(mode, "--interrupt-index") == 0;
    bool recover_index = strcmp(mode, "--recover-index") == 0;
    require(seed || final || restore || interrupt || recover_index, "known phase");
    require(argc == (interrupt ? 7 : 5), "phase-specific argument count");
    char bundle[PATH_MAX], unpack[PATH_MAX], sql_path[PATH_MAX], blob_dir[PATH_MAX];
    char journal[PATH_MAX], key_path[PATH_MAX], path[PATH_MAX], denied[PATH_MAX];
    join_path(bundle, root, "shared.bundle");
    join_path(unpack, root, "restore-input");
    join_path(sql_path, root, seed ? "sql/rows" : "sql-restored/rows");
    join_path(blob_dir, root, seed ? "blobs" : "blobs-restored");
    join_path(journal, root, seed ? "source.qtj" : "restored-coordinator.qtj");
    join_path(key_path, key_dir, "shared-archive.key");
    join_path(denied, root, "denied-package");
    qihse_user_t *op = open_authority(seed, auth_dir, key_dir);
    qihse_user_t *low = qihse_auth_get_user(47471u);
    require(low != NULL && qihse_user_get_id(low) == 47471u,
            "recovered durable low principal");
    uint8_t key[QIHSE_SHARED_BACKUP_KEY_BYTES];
    blob_archive_key(key_path, seed, key);
    qihse_shared_backup_info_t info = {.sql_engine_id = SQL_ENGINE_ID,
        .blob_engine_id = BLOB_ENGINE_ID, .coordinator.next_txn_id = 1u};
    qihse_kv_store_t *s = qihse_kv_store_create_user(op);
    require(s != NULL, "authenticated store open");
    if (!seed) {
        require(qihse_shared_backup_verify_user(bundle, op, key, sizeof key, &info),
                "authenticate shared package in fresh process");
        require(info.sql_engine_id == SQL_ENGINE_ID &&
                info.blob_engine_id == BLOB_ENGINE_ID && info.member_count >= 5u &&
                info.coordinator.journal_bytes > 0u,
                "authenticated SQL/blob engine bindings and receipt membership");
    }
    if (restore) {
        require(!qihse_shared_backup_verify_user(bundle, low, key, sizeof key, NULL) &&
                qihse_shared_backup_unpack_user(bundle, denied, low, key,
                sizeof key, NULL) == QIHSE_SHARED_BACKUP_ERROR,
                "low clearance shared verify and unpack denial");
        require_absent(denied);
        key[0] ^= 1u;
        require(!qihse_shared_backup_verify_user(bundle, op, key, sizeof key, NULL) &&
                qihse_shared_backup_unpack_user(bundle, denied, op, key,
                sizeof key, NULL) == QIHSE_SHARED_BACKUP_ERROR,
                "wrong shared package key denial");
        key[0] ^= 1u;
        require_absent(denied);
        require(qihse_shared_backup_unpack_user(bundle, unpack, op, key,
                sizeof key, NULL) == QIHSE_SHARED_BACKUP_OK,
                "durable authenticated shared package unpack");
        /* Native SQL restore writes a lock beside its input: only the working
         * unpack may acquire operational artifacts, never shared.bundle. */
        join_path(path, unpack, QIHSE_SHARED_BACKUP_KV_FILE);
        require(qihse_restore_user(s, op, path) == QIHSE_BACKUP_EXPORT_OK,
                "fresh native KV restore from shared package");
        join_path(path, unpack, QIHSE_SHARED_BACKUP_SQL_FILE);
        require(qihse_table_store_restore(op, path, sql_path),
                "fresh native SQL restore including decision receipts");
        join_path(path, unpack, QIHSE_SHARED_BACKUP_BLOB_FILE);
        require_absent(blob_dir);
        require(restore_blob(path, blob_dir, low, key) == QIHSE_BLOB_ARCHIVE_ERROR,
                "low clearance blob archive restore denied");
        require_absent(blob_dir);
        key[0] ^= 1u;
        require(restore_blob(path, blob_dir, op, key) == QIHSE_BLOB_ARCHIVE_ERROR,
                "wrong blob archive key denied");
        key[0] ^= 1u;
        require_absent(blob_dir);
        require(restore_blob(path, blob_dir, op, key) == QIHSE_BLOB_ARCHIVE_OK,
                "fresh native blob restore including terminal receipts");
        join_path(path, unpack, QIHSE_SHARED_BACKUP_JOURNAL_FILE);
        copy_journal(path, journal, info.coordinator.journal_bytes);
    }
    qihse_blob_store_t *blobs = qihse_blob_store_create(blob_dir);
    require(blobs != NULL, "private blob store open");
    qihse_uwp_context_t sql = {0};
    sql_context_open(&sql, sql_path, journal, seed);
    uint64_t restored_floor = register_and_replay(&sql, blobs, info.sql_engine_id,
        info.blob_engine_id, info.coordinator.next_txn_id);
    if (!seed) {
        require(blob_decision_calls == 2u, "real participant called on both replay passes");
        qihse_txn_t *probe = qihse_txn_begin(sql.txn_manager, QIHSE_ISO_READ_COMMITTED);
        require(probe && probe->id == restored_floor &&
                qihse_txn_rollback(sql.txn_manager, probe) == 0 &&
                qihse_txn_release(sql.txn_manager, probe) == 0,
                "first post-replay allocation respects restored floors");
        require(qihse_shared_backup_verify_user(bundle, op, key, sizeof key, NULL),
                "authenticated package remains immutable after native restore and replay");
    }
    if (seed) require(sql_exec(&sql, op,
        "CREATE TABLE w11_findings (id INT PRIMARY KEY, detail TEXT NOT NULL)"),
        "findings table creation");
    /* No server or application read is admitted until both replay passes. */
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    const char node_id[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    scfg.node_id = node_id;
    scfg.auth_required = false;
    scfg.port = 0;
    scfg.store = s;
    qihse_resp_server_t *server = qihse_resp_server_create(&scfg);
    require(server != NULL, "AIMEM local server");
    if (seed) {
        run_workers(s, &sql, server, blobs, op);
        seed_cohort(s, &sql, blobs, op);
        seed_index_rows(server, s, op);
        verify_index_rows(server, s, op);
        qihse_txn_backup_checkpoint_t ordinary;
        require(qihse_txn_backup_checkpoint_user(sql.txn_manager, op, &ordinary) &&
                ordinary.journal_bytes == 0u && blob_decision_calls == 0u,
                "ordinary UWP commits remain one-phase despite registration");
        seed_common_decision(s, &sql, blobs, op);
        verify_workload(s, &sql, server, op);
        verify_cohort(s, &sql, server, blobs, op);
        require(sql_finding_is(&sql, op, 101u, "shared-decision"),
                "common SQL committed source row");
        require(qihse_kv_sync_store(s), "workload sync");
        size_t disclosed = 0;
        require(!qihse_blob_archive_export_user(blobs, low, key, sizeof key,
                count_archive_write, &disclosed) && disclosed == 0,
                "low clearance blob archive export denied without output");
        qihse_shared_backup_sources_t sources = {s, qihse_uwp_sql_table_store(),
            blobs, sql.txn_manager, SQL_ENGINE_ID, BLOB_ENGINE_ID};
        require(qihse_shared_backup_export_user(denied, &sources, low, key,
                sizeof key, NULL) == QIHSE_SHARED_BACKUP_ERROR,
                "low clearance shared export denied");
        require_absent(denied);
        require(qihse_shared_backup_export_user(bundle, &sources, op, key,
                sizeof key, &info) == QIHSE_SHARED_BACKUP_OK,
                "real retained-handle shared package export");
        require(qihse_shared_backup_verify_user(bundle, op, key, sizeof key, NULL),
                "verify exported shared package");
        /* Source-only post-cut markers prove fresh restores consume the package,
         * rather than accidentally reopening the original workload stores. */
        require(qihse_kv_set_user(s, "w11/recovery/marker", "temporary", 0, 0, op) &&
                sql_insert_finding(&sql, op, 99u, "restore-marker") &&
                qihse_kv_sync_store(s), "source-only post-package markers");
        OPENSSL_cleanse(key, sizeof key);
        _exit(0);
    }
    OPENSSL_cleanse(key, sizeof key);
    char *common_id_text = get(s, op, "w11/recovery/common-decision");
    require(common_id_text != NULL, "packaged common decision provenance");
    char *id_end = NULL;
    uint64_t common_id = strtoull(common_id_text, &id_end, 10);
    require(common_id > 0u && id_end && *id_end == '\0' &&
            info.coordinator.next_txn_id > common_id + 1u &&
            qihse_txn_is_committed(sql.txn_manager, common_id),
            "manifest preserves unjournaled allocation beyond common receipts");
    free(common_id_text);
    require(sql_finding_is(&sql, op, 101u, "shared-decision"),
            "restored common SQL decision row");
    qihse_table_t *findings = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "w11_findings");
    require(findings && qihse_table_row_count(findings) == OPS + 2u,
            "exact findings count after repeated receipt replay");
    require(get(s, op, "w11/recovery/marker") == NULL &&
            !sql_finding_is(&sql, op, 99u, "restore-marker"),
            "post-package KV and SQL markers absent after native restore");
    verify_workload(s, &sql, server, op);
    verify_cohort(s, &sql, server, blobs, op);
    qihse_uwp_sql_result_t *denied_sql = NULL;
    qihse_txn_t *denied_txn = NULL;
    uwp_sts_result_t denied_status = qihse_uwp_sql_execute_typed_user(&sql,
        "SELECT detail FROM w11_findings WHERE id = 0", NULL, 0,
        &denied_txn, low, &denied_sql);
    require(denied_txn == NULL &&
            !(denied_status == UWP_STS_OK && denied_sql && denied_sql->nrows > 0),
            "low clearance SQL finding denial");
    qihse_uwp_sql_result_free(denied_sql);
    uint8_t blob_hash[QIHSE_BLOB_HASH_BYTES];
    verify_blob(blobs, op, blob_hash); /* fresh-process reopen readback */
    blob_denied(blobs, low, blob_hash);
    verify_index_rows(server, s, op);
    verify_index_denials(server, s, op, low);
    if (interrupt) interrupt_index(server, s, op, root, argv[5], argv[6]);
    if (recover_index) {
        recover_interrupted_index(server, s, op, low);
        verify_workload(s, &sql, server, op);
        verify_cohort(s, &sql, server, blobs, op);
        verify_blob(blobs, op, blob_hash);
        blob_denied(blobs, low, blob_hash);
        verify_index_rows(server, s, op);
        verify_index_denials(server, s, op, low);
        denied_sql = NULL;
        denied_status = qihse_uwp_sql_execute_typed_user(&sql,
            "SELECT detail FROM w11_findings WHERE id = 0", NULL, 0,
            &denied_txn, low, &denied_sql);
        require(denied_txn == NULL &&
                !(denied_status == UWP_STS_OK && denied_sql && denied_sql->nrows > 0),
                "low clearance SQL finding denial after index recovery");
        qihse_uwp_sql_result_free(denied_sql);
        require(qihse_kv_sync_store(s), "recovered interrupted index sync");
        _exit(0);
    }
    if (restore) {
        aimem_index_rebuild_probe(server, s, op, low);
        require(qihse_kv_sync_store(s), "recovered index sync");
        _exit(0);
    }
    require(strcmp(mode, "final") == 0, "unknown mode");
    require(get(s, op, "w11/recovery/marker") == NULL, "final marker absence");
    verify_cohort(s, &sql, server, blobs, op);
    require(!sql_finding_is(&sql, op, 99u, "restore-marker"),
            "final SQL marker absence");
    verify_blob(blobs, op, blob_hash); /* fresh process, restored sibling only */
    blob_denied(blobs, low, blob_hash);
    char *memory_id = get(s, op, "w11/recovery/memory/00000000");
    require(memory_id != NULL, "final memory id reference");
    qihse_ai_memory_hit_t denied_memory = {0};
    require(!qihse_ai_memory_get(server, low, memory_id, &denied_memory) &&
            denied_memory.text == NULL, "low clearance AIMEM denial");
    free(memory_id);
    /* Fresh-process persistence of the rebuilt derived index and its
     * low-clearance denial. */
    char *index_generation = get(s, op, "w11/recovery/aimem-index-generation");
    char *index_records = get(s, op, "w11/recovery/aimem-index-records");
    char *knowledge_id = get(s, op, "w11/recovery/aimem-knowledge-id");
    require(index_generation && index_records && knowledge_id &&
            strlen(knowledge_id) == QIHSE_AIMEM_ID_LEN,
            "persisted index expectations");
    qihse_ai_memory_health_t index_health;
    require(qihse_ai_memory_health(server, op, &W11_INDEX_SCOPE, &index_health) &&
            index_health.ready &&
            index_health.index_state == QIHSE_AIMEM_INDEX_READY &&
            index_health.generation == strtoull(index_generation, NULL, 10) &&
            index_health.indexed_records == strtoull(index_records, NULL, 10) &&
            index_health.indexed_records == AIMEM_INDEX_ROWS,
            "fresh-process index READY persistence");
    qihse_ai_memory_health_t baseline = index_interruption_baseline(s, op);
    require(baseline.generation == 7u && baseline.recovered_builds == 3u &&
            baseline.rebuild_failed == 3u && baseline.rebuild_started == 7u &&
            baseline.rebuild_ready == 4u, "all four planned interruption boundaries reached");
    value_is(s, op, "w11/recovery/aimem-index-interruption-phase", "private_ready");
    value_is(s, op, "w11/recovery/aimem-index-private-ready-observed", "8 8 8 0 8 5 3 3");
    require(index_health.generation == 9u && index_health.candidate_generation == 9u &&
            index_health.recovered_builds == 3u && index_health.rebuild_failed == 3u &&
            index_health.rebuild_started == 9u && index_health.rebuild_ready == 6u,
            "fresh-process exact gen9 READY counters after committed-unavailable gen8");
    for (unsigned phase = 0; phase < 3u; ++phase)
        verify_candidate_entries(s, op, 2u + phase * 2u,
                phase == 0u ? 1u : AIMEM_INDEX_ROWS);
    verify_candidate_entries(s, op, 8u, AIMEM_INDEX_ROWS);
    verify_candidate_entries(s, op, index_health.generation, AIMEM_INDEX_ROWS);
    fprintf(stderr, "verified final reopen: failed candidates2/4/6 entries1/8/8; "
            "committed8 entries8; ready9 entries8 started9 ready6 failed3 recovered3\n");
    verify_index_rows(server, s, op);
    qihse_ai_memory_knowledge_version_t index_visible = {0};
    require(qihse_ai_memory_knowledge_latest(server, op, knowledge_id,
            &W11_INDEX_SCOPE, &index_visible) && index_visible.content &&
            strcmp(index_visible.content,
                   W11_REVISED_CONTENT) == 0 && index_visible.revision == 2u,
            "fresh-process revised knowledge readback");
    qihse_ai_memory_knowledge_free(&index_visible);
    require(!qihse_ai_memory_index_rebuild(server, low, &W11_INDEX_SCOPE) &&
            !qihse_ai_memory_health(server, low, &W11_INDEX_SCOPE,
            &index_health), "fresh-process low clearance index denial");
    qihse_ai_memory_knowledge_version_t index_denied = {0};
    require(!qihse_ai_memory_knowledge_latest(server, low, knowledge_id,
            &W11_INDEX_SCOPE, &index_denied),
            "low clearance knowledge read denial");
    free(index_generation);
    free(index_records);
    free(knowledge_id);
    require(qihse_kv_sync_store(s), "final sync");
    qihse_ai_memory_reset();
    qihse_resp_server_destroy(server);
    sql_context_close(&sql);
    qihse_kv_store_destroy(s);
    qihse_blob_store_destroy(blobs);
    printf("{\"bounded_shared_restore\":{\"member_count\":%u,"
           "\"journal_bytes\":%llu,\"manifest_next_txn_id\":%llu,"
           "\"restored_next_id_floor\":%llu,\"common_decision_id\":%llu,"
           "\"sql_engine_id\":%u,\"blob_engine_id\":%u,"
           "\"replay_passes_per_restart\":2,\"knowledge_source_rows\":%u,"
           "\"expected_knowledge_source_versions\":%u,\"knowledge_current_rows\":%u,\"expected_provenance_events\":1},",
           info.member_count, (unsigned long long)info.coordinator.journal_bytes,
           (unsigned long long)info.coordinator.next_txn_id,
           (unsigned long long)restored_floor, (unsigned long long)common_id,
           (unsigned)info.sql_engine_id, (unsigned)info.blob_engine_id,
           AIMEM_INDEX_ROWS, AIMEM_EXPECTED_SOURCE_VERSIONS, AIMEM_INDEX_ROWS);
    puts("\"schema\":\"w11-combined-recovery-v2\",\"evidence\":{"
         "\"bounded_local_shared_package_export_verify_unpack\":true,"
         "\"fresh_process_native_shared_payload_restore\":true,"
         "\"shared_sql_blob_receipts_restored\":true,"
         "\"authenticated_and_participant_floors_before_replay\":true,"
         "\"common_decision_replayed_twice_before_app_exposure\":true,"
         "\"shared_package_immutable_after_restore\":true,"
         "\"ordinary_uwp_commits_one_phase\":true,"
         "\"shared_package_low_clearance_denied\":true,"
         "\"shared_package_wrong_key_denied\":true,"
         "\"packaged_aimem_source_rows_rebuilt\":true,"
         "\"bounded_packaged_aimem_two_version_supersession\":true,"
         "\"bounded_packaged_aimem_nonempty_provenance\":true,"
         "\"bounded_packaged_aimem_exact_get_latest_asof_event\":true,"
         "\"bounded_packaged_aimem_provenance_low_clearance_denied\":true,"
         "\"bounded_post_restore_interrupted_index_recovered\":true,"
         "\"bounded_post_restore_interrupted_index_ready_persistence\":true,"
         "\"bounded_post_restore_interrupted_index_source_provenance_preserved\":true,"
         "\"bounded_private_ready_committed_unavailable_reopened\":true,"
         "\"bounded_private_ready_explicit_recover_preserves_committed_state\":true,"
         "\"bounded_private_ready_explicit_rebuild_ready_persistence\":true,"
         "\"concurrent_authenticated_inventory_stock_cas\":true,\"concurrent_authenticated_sql_findings_restart_readback\":true,\"authenticated_aimem_store_and_restart_readback\":true,\"aimem_low_clearance_denied\":true,\"concurrent_authenticated_binary_blob_write\":true,\"binary_blob_fresh_process_readback\":true,\"binary_blob_low_clearance_denied\":true,\"bounded_cross_store_cohort_provenance\":true,\"blob_backup_coverage\":true,\"authenticated_blob_archive_export_restore\":true,\"blob_archive_low_clearance_export_restore_denied\":true,\"blob_archive_wrong_key_denied\":true,\"blob_restored_metadata_and_pins\":true,\"blob_restored_fresh_process_readback\":true,\"low_clearance_denied\":true,\"abrupt_exit_after_sync_and_backup\":true,\"fresh_process_reopen\":true,\"authenticated_kv_backup_restore\":true,\"authenticated_sql_backup_restore\":true,\"sql_restored_marker_removed\":true,\"marker_removed\":true,\"restored_state_persistent_and_authorized\":true,\"durable_authenticated_principals_recovered_across_process_restarts\":true,\"authenticated_aimem_index_rebuild\":true,\"aimem_index_rebuild_fresh_process_persistence\":true,\"aimem_index_low_clearance_denied\":true,\"aimem_index_rebuild_exact_source_rows_preserved\":true},\"remaining_gaps\":{\"deployment_auth_readiness\":false,\"cross_model_atomicity\":false,\"all_four_representative_adapters\":true,\"combined_cross_store_backup_atomicity\":false,\"node_partition_faults\":false,\"w11_scale_gate\":false,\"aimem_index_interrupted_build_faults\":false},\"remaining_gaps_semantics\":\"legacy evidence flags: true means bounded evidence present, false means not established; neither means acceptance complete\",\"acceptance_gates\":{\"full_node_recovery\":false,\"partition_faults\":false,\"storage_faults\":false,\"scale\":false,\"interrupted_index_rebuild\":false},\"w11_6_complete\":false}");
    return 0;
}
