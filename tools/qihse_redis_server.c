/* qihse-redis-server — standalone QIHSE server speaking RESP (Redis protocol)
 * on port 6379 by default, optionally side-by-side with a UWP listener on the
 * same stores so both protocols serve one dataset.
 *
 * Security: with --require-auth the RESP server enforces qihse_user_t
 * authentication per connection and refuses to start while the default
 * operator password is in place (engine-side gate). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>

#include "qihse_auth.h"
#include "qihse_auth_maintenance.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_resp_wire.h"
#include "qihse_uwp.h"
#include "qihse_ai_memory.h"
#include "qihse_aimem_onnx_embedder.h"

typedef struct {
    uint16_t port;
    uint16_t uwp_port;          /* 0 = disabled */
    const char* bind;
    const char* pubsub_dir;
    uint16_t channel_classification;
    uint16_t channel_sci;
    bool require_auth;
    /* Parsed bootstrap identity; passed into the RESP service-principal gate
     * when that configuration field is present in the integration branch. */
    uint32_t aimem_service_user_id;
    const char* embedder_onnx;  /* NULL = built-in lexical embedder */
    const char* aimem_keystone_library;
    const char* aimem_projection_dir;
    const char* artifact_blob_dir;
    const char* artifact_staging_dir;
    const char* forensic_vdb_path;
} server_options_t;

#define QIHSE_STANDALONE_SECRET_MAX 256u
#define QIHSE_AIMEM_SERVICE_DEFAULT_USER_ID 65000u
#define QIHSE_AIMEM_SERVICE_DEFAULT_TENANT_ID 1u

typedef struct {
    char operator_password[QIHSE_STANDALONE_SECRET_MAX];
    char aimem_service_password[QIHSE_STANDALONE_SECRET_MAX];
    bool operator_set;
    bool operator_from_argv;    /* --password: docs require it to MATCH the env */
    bool aimem_service_set;
} standalone_credentials_t;

static void standalone_cleanse_env(const char* name) {
    char* value = getenv(name);
    if (value) OPENSSL_cleanse(value, strlen(value));
    unsetenv(name);
}

static void standalone_credentials_clear(standalone_credentials_t* credentials) {
    standalone_cleanse_env("QIHSE_OPERATOR_PASSWORD");
    standalone_cleanse_env("QIHSE_AUTH_PASSWORD");
    standalone_cleanse_env("QIHSE_AIMEM_SERVICE_PASSWORD");
    if (credentials) OPENSSL_cleanse(credentials, sizeof(*credentials));
}

static bool standalone_secret_copy(char out[QIHSE_STANDALONE_SECRET_MAX],
                                   bool* configured, const char* value) {
    if (!out || !configured || !value || !*value) return false;
    size_t len = strlen(value);
    if (len >= QIHSE_STANDALONE_SECRET_MAX) return false;
    memcpy(out, value, len + 1u);
    *configured = true;
    return true;
}

/* Command-line secrets are supported for compatibility only. argv storage is
 * writable on the supported Unix targets; erase it as soon as the daemon owns
 * a private mutable copy so process listings cannot retain the value. */
static bool standalone_secret_take_argv(
        char out[QIHSE_STANDALONE_SECRET_MAX], bool* configured, char* value) {
    if (!value) return false;
    size_t len = strlen(value);
    bool ok = len > 0u && len < QIHSE_STANDALONE_SECRET_MAX;
    if (ok) {
        memcpy(out, value, len + 1u);
        *configured = true;
    }
    OPENSSL_cleanse(value, len);
    return ok;
}

static bool standalone_parse_nonzero_id(const char* variable,
                                        uint32_t default_value,
                                        uint32_t maximum,
                                        uint32_t* out) {
    if (!out) return false;
    const char* text = getenv(variable);
    if (!text || !*text) {
        *out = default_value;
        return true;
    }
    errno = 0;
    char* end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !end || *end || value == 0ul || value > maximum) return false;
    *out = (uint32_t)value;
    return true;
}

/* Isolated integration point for the standalone AIMEM identity. The RESP
 * server configuration has no service-principal field: registering this
 * authoritative principal before server creation makes regular named AUTH
 * resolve it while keeping it non-Operator and bounded by row labels. */
static qihse_user_t* standalone_bootstrap_aimem_service(
        qihse_user_t* operator_user, const char* password,
        uint32_t tenant_id, uint32_t user_id) {
    if (!operator_user || !qihse_auth_user_is_active(operator_user) ||
        qihse_user_get_role(operator_user) != QIHSE_ROLE_OPERATOR ||
        !password || !*password || tenant_id == 0u)
        return NULL;
    qihse_user_t* existing = qihse_auth_get_user(user_id);
    if (existing) {
        qihse_user_t* authenticated = qihse_auth_authenticate_id(user_id, password);
        return authenticated && qihse_auth_user_is_active(authenticated) &&
            qihse_user_get_role(authenticated) == QIHSE_ROLE_ANALYST &&
            qihse_user_get_tenant_id(authenticated) == tenant_id &&
            !qihse_user_requires_hardware_token(authenticated) &&
            !qihse_user_can_create_users(authenticated) &&
            strcmp(qihse_user_get_username(authenticated), "AIMEM_SERVICE") == 0
            ? authenticated : NULL;
    }
    qihse_user_t* service = qihse_auth_create_tenant_user(
        operator_user, tenant_id, user_id, QIHSE_ROLE_ANALYST,
        UINT16_MAX, UINT16_MAX, password, false);
    if (!service || !qihse_auth_modify_user(operator_user, user_id,
            "AIMEM_SERVICE", NULL, -1, -1, -1, -1)) return NULL;
    return qihse_auth_authenticate("AIMEM_SERVICE", password);
}

#ifndef QIHSE_STANDALONE_CREDENTIAL_TEST
/* Durable authority is opt-in and never inferred from federation or data paths.
 * Keep this startup-only parser identical in the two standalone entry points. */
static bool daemon_auth_hex(const char* text, uint8_t* out, size_t size) {
    if (!text || strlen(text) != size * 2u) return false;
    unsigned nonzero = 0u;
    for (size_t i = 0; i < size; ++i) {
        unsigned value = 0u;
        for (size_t j = 0; j < 2u; ++j) {
            unsigned char c = (unsigned char)text[i * 2u + j];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10u;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10u;
            else return false;
            value = value * 16u + digit;
        }
        out[i] = (uint8_t)value;
        nonzero |= value;
    }
    return nonzero != 0u;
}

static bool daemon_auth_number(const char* text, uint64_t* out) {
    if (!text || !*text) return false;
    uint64_t value = 0u;
    for (const char* p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (value > (UINT64_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    *out = value;
    return value != 0u;
}

static bool daemon_auth_startup(const char* password, bool auth_required,
                                bool consensus_requested, bool* durable,
                                uint32_t* startup_user_id) {
    static const char* const fields[] = {
        "QIHSE_AUTH_ACTION", "QIHSE_AUTH_STATE_DIR", "QIHSE_AUTH_BOOTSTRAP_FILE",
        "QIHSE_AUTH_BOOTSTRAP_USERNAME", "QIHSE_AUTH_NODE_ID", "QIHSE_AUTH_EPOCH",
        "QIHSE_AUTH_AUTHORITY_ID", "QIHSE_AUTH_HISTORY_ID", "QIHSE_AUTH_MIN_GENERATION",
        "QIHSE_AUTH_RECIPIENT_PUBLIC_KEY", "QIHSE_AUTH_RECIPIENT_PRIVATE_KEY",
        "QIHSE_AUTH_SIGNER_PUBLIC_KEY", "QIHSE_AUTH_SIGNER_PRIVATE_KEY",
        "QIHSE_AUTH_RECIPIENT_PIN", "QIHSE_AUTH_SIGNER_PIN",
        "QIHSE_AUTH_TRANSFER_RECIPIENT_PUBLIC_KEY", "QIHSE_AUTH_TRANSFER_RECIPIENT_PRIVATE_KEY",
        "QIHSE_AUTH_TRANSFER_SIGNER_PUBLIC_KEY", "QIHSE_AUTH_TRANSFER_SIGNER_PRIVATE_KEY",
        "QIHSE_AUTH_TRANSFER_RECIPIENT_PIN", "QIHSE_AUTH_TRANSFER_SIGNER_PIN",
        "QIHSE_AUTH_STARTUP_USER_ID"
    };
    *durable = false;
    *startup_user_id = 0u;
    const char* selected = getenv("QIHSE_AUTH_STARTUP_USER_ID");
    if (selected) {
        uint64_t id = 0u;
        if (!daemon_auth_number(selected, &id) || id >= 65536u) {
            fprintf(stderr, "auth authority: QIHSE_AUTH_STARTUP_USER_ID must be decimal 1..65535; unset selects UID 0\n");
            return false;
        }
        *startup_user_id = (uint32_t)id;
    }
    const char* mode = getenv("QIHSE_AUTH_MODE");
    if (!mode) {
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            if (getenv(fields[i])) {
                fprintf(stderr, "auth authority: %s requires explicit QIHSE_AUTH_MODE\n", fields[i]);
                return false;
            }
        }
        return true;
    }
    if (strcmp(mode, "consensus") == 0 ||
        (strcmp(mode, "standalone") == 0 && consensus_requested)) {
        fprintf(stderr, "auth authority: consensus durability UNSUPPORTED; no standalone fallback\n");
        return false;
    }
    if (strcmp(mode, "standalone") != 0 || !auth_required || !password || !*password) {
        fprintf(stderr, "auth authority: explicit standalone mode requires authenticated startup and operator password\n");
        return false;
    }
    qihse_auth_startup_config_t config;
    memset(&config, 0, sizeof(config));
    config.mode = QIHSE_AUTH_AUTHORITY_STANDALONE;
    const char* action = getenv("QIHSE_AUTH_ACTION");
    if (action && strcmp(action, "provision") == 0) config.action = QIHSE_AUTH_START_PROVISION;
    else if (action && strcmp(action, "recover") == 0) config.action = QIHSE_AUTH_START_RECOVER;
    else {
        fprintf(stderr, "auth authority: QIHSE_AUTH_ACTION must be provision or recover\n");
        return false;
    }
    if (config.action == QIHSE_AUTH_START_PROVISION && *startup_user_id != 0u) {
        fprintf(stderr, "auth authority: provision requires UID 0; unset QIHSE_AUTH_STARTUP_USER_ID (selection is recover-only)\n");
        return false;
    }
    const char* paths[] = {
        getenv("QIHSE_AUTH_STATE_DIR"), getenv("QIHSE_AUTH_BOOTSTRAP_FILE"),
        getenv("QIHSE_AUTH_RECIPIENT_PUBLIC_KEY"), getenv("QIHSE_AUTH_RECIPIENT_PRIVATE_KEY"),
        getenv("QIHSE_AUTH_SIGNER_PUBLIC_KEY"), getenv("QIHSE_AUTH_SIGNER_PRIVATE_KEY")
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (!paths[i] || !*paths[i]) {
            fprintf(stderr, "auth authority: explicit state/bootstrap and all recipient/signer key paths required\n");
            return false;
        }
    }
    config.state_directory = paths[0];
    config.bootstrap_file = paths[1];
    config.archive_keys.recipient_public_file = paths[2];
    config.archive_keys.recipient_private_file = paths[3];
    config.archive_keys.signer_public_file = paths[4];
    config.archive_keys.signer_private_file = paths[5];
    if (!daemon_auth_hex(getenv("QIHSE_AUTH_NODE_ID"), config.node, sizeof(config.node)) ||
        !daemon_auth_hex(getenv("QIHSE_AUTH_AUTHORITY_ID"), config.authority_id, sizeof(config.authority_id)) ||
        !daemon_auth_hex(getenv("QIHSE_AUTH_RECIPIENT_PIN"), config.archive_keys.recipient_pin, sizeof(config.archive_keys.recipient_pin)) ||
        !daemon_auth_hex(getenv("QIHSE_AUTH_SIGNER_PIN"), config.archive_keys.signer_pin, sizeof(config.archive_keys.signer_pin)) ||
        !daemon_auth_number(getenv("QIHSE_AUTH_EPOCH"), &config.epoch)) {
        fprintf(stderr, "auth authority: nonzero node/authority hex32, SPKI SHA384 pins hex96 and decimal epoch required\n");
        return false;
    }
    const char* transfer_paths[] = {
        getenv("QIHSE_AUTH_TRANSFER_RECIPIENT_PUBLIC_KEY"),
        getenv("QIHSE_AUTH_TRANSFER_RECIPIENT_PRIVATE_KEY"),
        getenv("QIHSE_AUTH_TRANSFER_SIGNER_PUBLIC_KEY"),
        getenv("QIHSE_AUTH_TRANSFER_SIGNER_PRIVATE_KEY")
    };
    const char* transfer_recipient_pin = getenv("QIHSE_AUTH_TRANSFER_RECIPIENT_PIN");
    const char* transfer_signer_pin = getenv("QIHSE_AUTH_TRANSFER_SIGNER_PIN");
    bool transfer_requested = transfer_recipient_pin || transfer_signer_pin;
    for (size_t i = 0; i < sizeof(transfer_paths) / sizeof(transfer_paths[0]); ++i) {
        if (transfer_paths[i]) {
            transfer_requested = true;
            if (!*transfer_paths[i]) {
                fprintf(stderr, "auth authority: empty transfer key path\n");
                return false;
            }
        }
    }
    if (transfer_requested) {
        if (!daemon_auth_hex(transfer_recipient_pin, config.transfer_keys.recipient_pin, sizeof(config.transfer_keys.recipient_pin)) ||
            !daemon_auth_hex(transfer_signer_pin, config.transfer_keys.signer_pin, sizeof(config.transfer_keys.signer_pin)) ||
            (!!transfer_paths[0] != !!transfer_paths[3]) ||
            (!!transfer_paths[1] != !!transfer_paths[2]) ||
            (!transfer_paths[0] && !transfer_paths[1])) {
            fprintf(stderr, "auth authority: transfer requires explicit pins and export recipient-public/signer-private or import recipient-private/signer-public pair\n");
            return false;
        }
        config.transfer_keys.recipient_public_file = transfer_paths[0];
        config.transfer_keys.recipient_private_file = transfer_paths[1];
        config.transfer_keys.signer_public_file = transfer_paths[2];
        config.transfer_keys.signer_private_file = transfer_paths[3];
    }
    const char* username = getenv("QIHSE_AUTH_BOOTSTRAP_USERNAME");
    if (config.action == QIHSE_AUTH_START_RECOVER) {
        if (username ||
            !daemon_auth_hex(getenv("QIHSE_AUTH_HISTORY_ID"), config.expected_history, sizeof(config.expected_history)) ||
            !daemon_auth_number(getenv("QIHSE_AUTH_MIN_GENERATION"), &config.minimum_generation)) {
            fprintf(stderr, "auth authority: recover requires nonzero HISTORY_ID hex32 and MIN_GENERATION decimal; no BOOTSTRAP_USERNAME\n");
            return false;
        }
    } else if (!username || !*username || getenv("QIHSE_AUTH_MIN_GENERATION") ||
               (getenv("QIHSE_AUTH_HISTORY_ID") &&
                !daemon_auth_hex(getenv("QIHSE_AUTH_HISTORY_ID"), config.expected_history, sizeof(config.expected_history)))) {
        fprintf(stderr, "auth authority: provision requires BOOTSTRAP_USERNAME, no MIN_GENERATION, and optional nonzero HISTORY_ID hex32\n");
        return false;
    }
    qihse_auth_maintenance_status_t status;
    if (config.action == QIHSE_AUTH_START_PROVISION) {
        status = qihse_auth_bootstrap_provision(config.bootstrap_file, username, password,
                                               false, "", true);
        if (status != QIHSE_AUTH_MAINT_OK) {
            fprintf(stderr, "auth authority: create-only bootstrap provision failed: %s\n",
                    qihse_auth_maintenance_status_string(status));
            return false;
        }
    }
    qihse_auth_recovery_t* recovery = NULL;
    status = qihse_auth_maintenance_start(&config, &recovery);
    /* The typed startup capability must not escape into listener state. */
    qihse_auth_maintenance_recovery_release(recovery);
    if (status != QIHSE_AUTH_MAINT_OK) {
        fprintf(stderr, "auth authority: %s failed: %s (no volatile fallback or reset)\n",
                action, qihse_auth_maintenance_status_string(status));
        return false;
    }
    *durable = true;
    return true;
}

static bool daemon_auth_report(qihse_user_t* actor, bool durable,
                               uint32_t startup_user_id) {
    if (!durable) {
        fprintf(stderr, "auth authority: volatile legacy; durable maintenance unsupported\n");
        return true;
    }
    if (!actor || !qihse_auth_user_is_active(actor) ||
        qihse_user_get_id(actor) != startup_user_id ||
        qihse_user_get_role(actor) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(actor) != QIHSE_TENANT_SYSTEM ||
        qihse_user_get_classification(actor) != UINT16_MAX ||
        qihse_user_get_sci(actor) != UINT16_MAX) {
        fprintf(stderr, "auth authority: selected startup actor must be an active full-clearance/SCI system Operator\n");
        return false;
    }
    qihse_auth_maintenance_caps_t caps;
    qihse_auth_maintenance_status_t status = qihse_auth_maintenance_capabilities(actor, &caps);
    if (status != QIHSE_AUTH_MAINT_OK || !caps.ready ||
        caps.mode != QIHSE_AUTH_AUTHORITY_STANDALONE) {
        fprintf(stderr, "auth authority: authenticated durable readiness check failed; no HWT bypass. "
                "For HWT-required root, select an existing authorized service Operator with "
                "QIHSE_AUTH_STARTUP_USER_ID and its own QIHSE_OPERATOR_PASSWORD; "
                "prepare that identity before requiring HWT on root\n");
        return false;
    }
    fprintf(stderr, "auth authority: standalone ready history=");
    for (size_t i = 0; i < sizeof(caps.position.history); ++i)
        fprintf(stderr, "%02x", (unsigned)caps.position.history[i]);
    fprintf(stderr, " epoch=%llu generation=%llu export=%u import=%u checkpoint=%u\n",
            (unsigned long long)caps.position.epoch,
            (unsigned long long)caps.position.generation,
            (unsigned)caps.export_supported, (unsigned)caps.import_supported,
            (unsigned)caps.checkpoint_supported);
    return true;
}

static void usage(const char* program) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --port N          RESP listen port (default 6379)\n"
            "  --bind ADDR       bind address (default 127.0.0.1)\n"
            "  --dir PATH        persistence directory (default /var/lib/qihse or $QIHSE_DATA_DIR)\n"
            "  --require-auth    require AUTH per connection\n"
            "  Durable principal authority requires --require-auth and QIHSE_AUTH_MODE=standalone.\n"
            "  QIHSE_AUTH_ACTION=provision|recover; required QIHSE_AUTH_ suffixes:\n"
            "    STATE_DIR, BOOTSTRAP_FILE, AUTHORITY_ID, NODE_ID, EPOCH,\n"
            "    RECIPIENT_PUBLIC_KEY, RECIPIENT_PRIVATE_KEY, SIGNER_PUBLIC_KEY, SIGNER_PRIVATE_KEY,\n"
            "    RECIPIENT_PIN, SIGNER_PIN (SPKI SHA384 hex96; identities hex32; epoch decimal>0).\n"
            "  Provision also requires BOOTSTRAP_USERNAME; recover requires HISTORY_ID and MIN_GENERATION.\n"
            "  Provision history is fresh unless HISTORY_ID supplied; no MIN_GENERATION on provision.\n"
            "  No bootstrap username on recover; private dirs/keys must preexist. Consensus unsupported.\n"
            "  Recover-only QIHSE_AUTH_STARTUP_USER_ID: existing full system Operator, decimal 1..65535;\n"
            "  unset selects UID 0. QIHSE_OPERATOR_PASSWORD is the selected identity's own password.\n"
            "  Prepare that service identity before root HWT is required; no HWT bypass or fallback.\n"
            "  Optional QIHSE_AUTH_TRANSFER_ keys/pins are separate: both pins and complete export\n"
            "  (RECIPIENT_PUBLIC_KEY,SIGNER_PRIVATE_KEY) or import (RECIPIENT_PRIVATE_KEY,SIGNER_PUBLIC_KEY).\n"
            "  --pqc-require     require pinned QKP and --require-auth\n"
            "  --pqc-identity-dir DIR  server KEM/DSA key directory\n"
            "  --pqc-trusted-pub FILE  trusted service client DSA public key\n"
            "  --pqc-node-id ID  signed server node identity\n"
            "  --password PASS   operator password (prefer QIHSE_OPERATOR_PASSWORD env; avoid argv exposure)\n"
            "                     AIMEM service password: QIHSE_AIMEM_SERVICE_PASSWORD\n"
            "                     stable service ID: QIHSE_AIMEM_SERVICE_USER_ID (default 65000)\n"
            "                     dedicated tenant: QIHSE_AIMEM_SERVICE_TENANT_ID (default 1)\n"
            "  --pubsub-dir PATH durable pub/sub event-stream directory (default: in-memory pub/sub)\n"
            "  --channel-classif N   classification tag applied to pub/sub channels (default 0)\n"
            "  --channel-sci N       SCI compartment mask applied to pub/sub channels (default 0)\n"
            "  --uwp-port N      also serve UWP on port N sharing the same stores (default: disabled)\n"
            "  --artifact-blob-dir DIR  enable classified dump blobs in a dedicated store (loopback + auth only)\n"
            "  --artifact-staging-dir DIR  required private 0700 upload staging directory\n"
            "  --forensic-vdb PATH  isolated operator-only 1024-dimensional persistent index\n"
            "  --embedder-onnx DIR  install the ONNX embedding model in DIR as the AIMEM embedder\n"
            "                      (env fallback QIHSE_AIMEM_EMBEDDER_ONNX; failure is fatal)\n"
            "  --aimem-keystone-library PATH  opt-in exact KEYSTONE ABI library\n"
            "  --aimem-projection-dir DIR   private 0700 durable projection directory\n",
            program);
}

typedef struct {
    qihse_uwp_context_t* ctx;
    uint16_t port;
    const char* bind;
} uwp_thread_arg_t;

static void* uwp_run_thread(void* argument) {
    uwp_thread_arg_t* arg = (uwp_thread_arg_t*)argument;
    if (!qihse_start_uwp_server(arg->ctx, arg->port, arg->bind)) {
        fprintf(stderr, "[qihse-redis-server] UWP server on port %u failed\n", arg->port);
    }
    return NULL;
}

int main(int argc, char** argv) {
    server_options_t options;
    memset(&options, 0, sizeof(options));
    standalone_credentials_t credentials;
    memset(&credentials, 0, sizeof(credentials));
    options.port = 6379;
    options.bind = "127.0.0.1";
    options.aimem_service_user_id = UINT32_MAX;
    const char* pqc_identity_dir = NULL;
    const char* pqc_trusted_pub = NULL;
    const char* pqc_node_id = NULL;
    bool pqc_require = false;
    char pqc_dsa[1024], pqc_kem[1024], pqc_kem_pub[1024];
    const char* pqc_trusted[1];
    const char* data_dir = getenv("QIHSE_DATA_DIR");
    if (!data_dir) data_dir = "/var/lib/qihse";

    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        bool has_next = i + 1 < argc;
        if (strcmp(arg, "--port") == 0 && has_next) options.port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(arg, "--uwp-port") == 0 && has_next) options.uwp_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(arg, "--bind") == 0 && has_next) options.bind = argv[++i];
        else if (strcmp(arg, "--dir") == 0 && has_next) data_dir = argv[++i];
        else if (strcmp(arg, "--pubsub-dir") == 0 && has_next) options.pubsub_dir = argv[++i];
        else if (strcmp(arg, "--channel-classif") == 0 && has_next) options.channel_classification = (uint16_t)atoi(argv[++i]);
        else if (strcmp(arg, "--channel-sci") == 0 && has_next) options.channel_sci = (uint16_t)atoi(argv[++i]);
        else if (strcmp(arg, "--require-auth") == 0) options.require_auth = true;
        else if (strcmp(arg, "--pqc-require") == 0) pqc_require = true;
        else if (strcmp(arg, "--pqc-identity-dir") == 0 && has_next) pqc_identity_dir = argv[++i];
        else if (strcmp(arg, "--pqc-trusted-pub") == 0 && has_next) pqc_trusted_pub = argv[++i];
        else if (strcmp(arg, "--pqc-node-id") == 0 && has_next) pqc_node_id = argv[++i];
        else if (strcmp(arg, "--password") == 0 && has_next) {
            if (!standalone_secret_take_argv(credentials.operator_password,
                    &credentials.operator_set, argv[++i])) {
                fprintf(stderr, "--password is empty or too long\n");
                standalone_credentials_clear(&credentials);
                return 2;
            }
            credentials.operator_from_argv = true;
        }
        else if (strcmp(arg, "--embedder-onnx") == 0 && has_next) options.embedder_onnx = argv[++i];
        else if (strcmp(arg, "--aimem-keystone-library") == 0 && has_next) options.aimem_keystone_library = argv[++i];
        else if (strcmp(arg, "--aimem-projection-dir") == 0 && has_next) options.aimem_projection_dir = argv[++i];
        else if (strcmp(arg, "--artifact-blob-dir") == 0 && has_next) options.artifact_blob_dir = argv[++i];
        else if (strcmp(arg, "--artifact-staging-dir") == 0 && has_next) options.artifact_staging_dir = argv[++i];
        else if (strcmp(arg, "--forensic-vdb") == 0 && has_next) options.forensic_vdb_path = argv[++i];
        else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            usage(argv[0]);
            standalone_credentials_clear(&credentials);
            return 0;
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", arg);
            usage(argv[0]);
            standalone_credentials_clear(&credentials);
            return 2;
        }
    }

    if (pqc_require || pqc_identity_dir || pqc_trusted_pub || pqc_node_id) {
        if (!pqc_require || !options.require_auth || !pqc_identity_dir || !*pqc_identity_dir ||
            !pqc_trusted_pub || !*pqc_trusted_pub || !pqc_node_id || !*pqc_node_id ||
            strlen(pqc_node_id) > QIHSE_QKP_NODE_ID_LEN ||
            snprintf(pqc_dsa, sizeof(pqc_dsa), "%s/qihse_dsa_key.pem", pqc_identity_dir) >= (int)sizeof(pqc_dsa) ||
            snprintf(pqc_kem, sizeof(pqc_kem), "%s/qihse_kem_key.pem", pqc_identity_dir) >= (int)sizeof(pqc_kem) ||
            snprintf(pqc_kem_pub, sizeof(pqc_kem_pub), "%s/qihse_kem_pub.pem", pqc_identity_dir) >= (int)sizeof(pqc_kem_pub) ||
            access(pqc_dsa, R_OK) || access(pqc_kem, R_OK) || access(pqc_kem_pub, R_OK) ||
            access(pqc_trusted_pub, R_OK)) {
            fprintf(stderr, "pinned QKP requires --require-auth, all --pqc-* options and readable keys\n");
            standalone_credentials_clear(&credentials);
            return 2;
        }
    }

    if (!credentials.operator_set) {
        const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
        if (env_pw && *env_pw) {
            standalone_secret_copy(credentials.operator_password,
                                   &credentials.operator_set, env_pw);
        } else if (getenv("QIHSE_AUTH_USER") &&
                   strcmp(getenv("QIHSE_AUTH_USER"), "GODMODE_OP") == 0 &&
                   getenv("QIHSE_AUTH_PASSWORD")) {
            standalone_secret_copy(credentials.operator_password,
                                   &credentials.operator_set,
                                   getenv("QIHSE_AUTH_PASSWORD"));
        }
    }
    const char* auth_user = getenv("QIHSE_AUTH_USER");
    bool aimem_service_requested =
        getenv("QIHSE_AIMEM_SERVICE_PASSWORD") != NULL ||
        getenv("QIHSE_AIMEM_SERVICE_USER_ID") != NULL ||
        getenv("QIHSE_AIMEM_SERVICE_TENANT_ID") != NULL ||
        (auth_user && strcmp(auth_user, "AIMEM_SERVICE") == 0);
    const char* aimem_password = getenv("QIHSE_AIMEM_SERVICE_PASSWORD");
    if ((!aimem_password || !*aimem_password) && auth_user &&
        strcmp(auth_user, "AIMEM_SERVICE") == 0)
        aimem_password = getenv("QIHSE_AUTH_PASSWORD");
    if (aimem_password && *aimem_password &&
        !standalone_secret_copy(credentials.aimem_service_password,
                                &credentials.aimem_service_set, aimem_password)) {
        fprintf(stderr, "AIMEM service password is too long\n");
        standalone_credentials_clear(&credentials);
        return 2;
    }
    if (aimem_service_requested && !credentials.aimem_service_set) {
        fprintf(stderr, "AIMEM service mode requires QIHSE_AIMEM_SERVICE_PASSWORD or QIHSE_AUTH_PASSWORD\n");
        standalone_credentials_clear(&credentials);
        return 2;
    }

    if (options.require_auth) {
        if (!credentials.operator_set) {
            fprintf(stderr, "--require-auth requires QIHSE_OPERATOR_PASSWORD, QIHSE_AUTH_PASSWORD, or --password\n");
            standalone_credentials_clear(&credentials);
            return 2;
        }
        /* Non-loopback binds without auth are rejected by the engine itself. */
    }
    if (options.artifact_blob_dir || options.artifact_staging_dir || options.forensic_vdb_path) {
        if (!options.artifact_blob_dir || !options.artifact_staging_dir ||
            !options.require_auth ||
            (strcmp(options.bind, "127.0.0.1") != 0 && strcmp(options.bind, "::1") != 0)) {
            fprintf(stderr, "artifact upload requires both directories, --require-auth, and a loopback bind\n");
            standalone_credentials_clear(&credentials);
            return 2;
        }
    }
    if (aimem_service_requested && !options.require_auth) {
        fprintf(stderr, "AIMEM service credentials require --require-auth\n");
        standalone_credentials_clear(&credentials);
        return 2;
    }
    if (!options.embedder_onnx) options.embedder_onnx = getenv("QIHSE_AIMEM_EMBEDDER_ONNX");
    if ((options.aimem_keystone_library || options.aimem_projection_dir) &&
        (!options.aimem_keystone_library || !options.aimem_projection_dir ||
         !*options.aimem_keystone_library || !*options.aimem_projection_dir ||
         !options.require_auth || !credentials.aimem_service_set ||
         !options.embedder_onnx || !*options.embedder_onnx)) {
        fprintf(stderr, "KEYSTONE projection requires both explicit paths, --require-auth, AIMEM service credentials, and ONNX model\n");
        standalone_credentials_clear(&credentials);
        return 2;
    }
    if (options.embedder_onnx && *options.embedder_onnx &&
        !qihse_aimem_onnx_embedder_install(options.embedder_onnx)) {
        /* Fail closed: serving semantic recall on the lexical hash while an
         * operator asked for the real model would be a silent downgrade. */
        fprintf(stderr, "[qihse-redis-server] ONNX embedder install failed for %s\n", options.embedder_onnx);
        standalone_credentials_clear(&credentials);
        return 1;
    }

    setenv("QIHSE_DATA_DIR", data_dir, 1);
    if (credentials.operator_set && credentials.operator_from_argv) {
        /* docs/OPERATIONS.md: "--password ... must MATCH QIHSE_OPERATOR_PASSWORD
         * when that env is set (mismatch = exit 2)". This used to be a silent
         * argv-wins override, which quietly rotated the operator credential. */
        const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
        if (env_pw && *env_pw && strcmp(env_pw, credentials.operator_password) != 0) {
            fprintf(stderr,
                    "[qihse-redis-server] --password does not match QIHSE_OPERATOR_PASSWORD "
                    "(refusing to rotate the operator credential; unset one of them)\n");
            standalone_credentials_clear(&credentials);
            return 2;
        }
    }
    bool durable_auth = false;
    uint32_t startup_user_id = 0u;
    if (!daemon_auth_startup(credentials.operator_set ? credentials.operator_password : NULL,
                             options.require_auth, false, &durable_auth, &startup_user_id)) {
        standalone_credentials_clear(&credentials);
        return 2;
    }
    if (!durable_auth && credentials.operator_set) {
        const char* current = getenv("QIHSE_OPERATOR_PASSWORD");
        if (!current || strcmp(current, credentials.operator_password) != 0) {
            /* If argv or QIHSE_AUTH_PASSWORD won precedence, erase a stale
             * operator environment value before publishing the owned copy. */
            standalone_cleanse_env("QIHSE_OPERATOR_PASSWORD");
            if (setenv("QIHSE_OPERATOR_PASSWORD",
                       credentials.operator_password, 1) != 0) {
                fprintf(stderr, "[qihse-redis-server] operator credential setup failed\n");
                standalone_credentials_clear(&credentials);
                return 1;
            }
        }
    }
    if (!durable_auth && !qihse_auth_init()) {
        fprintf(stderr, "[qihse-redis-server] auth subsystem init failed\n");
        standalone_credentials_clear(&credentials);
        return 1;
    }

    if (!durable_auth && options.require_auth) {
        qihse_user_t* operator_user = qihse_auth_get_user(0);
        if (operator_user && qihse_auth_is_operator_password_default()) {
            if (!qihse_auth_bootstrap_operator(credentials.operator_password)) {
                fprintf(stderr, "[qihse-redis-server] operator password bootstrap failed (min 12 chars)\n");
                standalone_credentials_clear(&credentials);
                return 1;
            }
        } else if (operator_user &&
                   !qihse_auth_authenticate_id(0, credentials.operator_password)) {
            fprintf(stderr,
                    "[qihse-redis-server] --password rejected: the operator password is "
                    "already configured and does not match. Rotate at runtime with "
                    "operator credentials (USER.MODIFY) or start against a fresh --dir.\n");
            standalone_credentials_clear(&credentials);
            return 2;
        }
    }
    qihse_user_t* startup_operator = options.require_auth
        ? qihse_auth_authenticate_id(startup_user_id, credentials.operator_password) : NULL;
    if (options.require_auth && (!startup_operator ||
        !qihse_auth_user_is_active(startup_operator) ||
        qihse_user_get_role(startup_operator) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(startup_operator) != QIHSE_TENANT_SYSTEM)) {
        fprintf(stderr, "[qihse-redis-server] startup Operator authentication failed\n");
        standalone_credentials_clear(&credentials);
        return 2;
    }
    if (!daemon_auth_report(startup_operator, durable_auth, startup_user_id)) {
        standalone_credentials_clear(&credentials);
        return 1;
    }
    if (credentials.aimem_service_set) {
        uint32_t service_tenant_id = 0u;
        if (!standalone_parse_nonzero_id("QIHSE_AIMEM_SERVICE_USER_ID",
                QIHSE_AIMEM_SERVICE_DEFAULT_USER_ID, 65535u,
                &options.aimem_service_user_id) ||
            !standalone_parse_nonzero_id("QIHSE_AIMEM_SERVICE_TENANT_ID",
                QIHSE_AIMEM_SERVICE_DEFAULT_TENANT_ID, UINT32_MAX - 1u,
                &service_tenant_id) ||
            !standalone_bootstrap_aimem_service(
                startup_operator, credentials.aimem_service_password, service_tenant_id,
                options.aimem_service_user_id)) {
            fprintf(stderr, "[qihse-redis-server] AIMEM service principal bootstrap failed\n");
            standalone_credentials_clear(&credentials);
            return 1;
        }
    }
    /* Password verifiers and the optional service principal now own all state
     * required for AUTH. Remove environment and temporary plaintext copies
     * before initializing any long-lived store, server, or worker thread. */
    standalone_credentials_clear(&credentials);

    qihse_kv_store_t* store = startup_operator
        ? qihse_kv_store_create_user(startup_operator) : qihse_kv_store_create();
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!store || !vdb) {
        fprintf(stderr, "[qihse-redis-server] engine initialization failed\n");
        return 1;
    }

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = options.port;
    config.bind_address = options.bind;
    config.advertise_address = options.bind;
    config.auth_required = options.require_auth;
    config.aimem_service_user_id = options.aimem_service_user_id;
    if (pqc_require) {
        pqc_trusted[0] = pqc_trusted_pub;
        config.pqc.require = true;
        config.pqc.dsa_key_path = pqc_dsa;
        config.pqc.kem_key_path = pqc_kem;
        config.pqc.kem_pub_path = pqc_kem_pub;
        config.pqc.node_id = pqc_node_id;
        config.pqc.trusted_pubs = pqc_trusted;
        config.pqc.trusted_count = 1u;
        /* Never map this pin to operator; AUTH AIMEM_SERVICE is required. */
    }
    config.pubsub_log_directory = options.pubsub_dir;
    config.channel_classification = options.channel_classification;
    config.channel_sci = options.channel_sci;
    config.enable_uwp_bridge = options.uwp_port != 0;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    qihse_blob_store_t* artifact_blobs = NULL;
    qihse_vector_db_t forensic_vdb = NULL;
    if (options.artifact_blob_dir) {
        artifact_blobs = qihse_blob_store_create(options.artifact_blob_dir);
        if (!artifact_blobs) {
            fprintf(stderr, "artifact blob store initialization failed\n");
            return 1;
        }
        config.blobs = artifact_blobs;
        config.enable_artifact_uploads = true;
        config.artifact_staging_dir = options.artifact_staging_dir;
    }
    if (options.forensic_vdb_path) {
        forensic_vdb = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, NULL,
                         options.forensic_vdb_path,
                         QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED);
        if (!forensic_vdb) {
            fprintf(stderr, "forensic index initialization failed\n");
            qihse_blob_store_destroy(artifact_blobs);
            return 1;
        }
        config.forensic_vdb = forensic_vdb;
    }

    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) {
        /* Report the actual rejection: the create() preconditions all set errno
         * (EINVAL = bad sizing, EACCES = auth gate/staging, ENOENT = missing
         * path), and "auth gate or bind error" alone sends you hunting. */
        fprintf(stderr,
                "[qihse-redis-server] RESP server creation failed: errno=%d (%s)"
                " [auth_required=%d bind=%s port=%u max_clients=%zu max_request_bytes=%zu"
                " aimem_service_user_id=%u]\n",
                errno, strerror(errno), (int)config.auth_required,
                config.bind_address ? config.bind_address : "(null)", config.port,
                config.max_clients, config.max_request_bytes,
                (unsigned)config.aimem_service_user_id);
        qihse_vector_db_destroy(forensic_vdb);
        qihse_blob_store_destroy(artifact_blobs);
        return 1;
    }
    if (options.aimem_keystone_library &&
        !qihse_ai_memory_projection_enable(server,
            qihse_auth_get_user(options.aimem_service_user_id),
            options.aimem_keystone_library, options.aimem_projection_dir)) {
        fprintf(stderr, "[qihse-redis-server] KEYSTONE AIMEM projection unavailable; refusing opt-in startup\n");
        qihse_resp_server_destroy(server);
        qihse_vector_db_destroy(vdb);
        qihse_vector_db_destroy(forensic_vdb);
        qihse_blob_store_destroy(artifact_blobs);
        qihse_kv_store_destroy(store);
        return 1;
    }
    printf("[qihse-redis-server] RESP listening on %s:%u (auth %s, embedder %s)\n",
           options.bind, options.port, options.require_auth ? "required" : "disabled",
           qihse_ai_memory_embedder_name());

    pthread_t uwp_thread;
    uwp_thread_arg_t uwp_arg;
    bool uwp_started = false;
    if (options.uwp_port != 0) {
        qihse_uwp_context_t* ctx = calloc(1, sizeof(*ctx));
        if (!ctx) return 1;
        ctx->kv = store;
        ctx->vdb = vdb;
        ctx->resp_server = server;
        uwp_arg.ctx = ctx;
        uwp_arg.port = options.uwp_port;
        uwp_arg.bind = options.bind;
        if (pthread_create(&uwp_thread, NULL, uwp_run_thread, &uwp_arg) != 0) {
            fprintf(stderr, "[qihse-redis-server] UWP thread spawn failed\n");
            return 1;
        }
        uwp_started = true;
        printf("[qihse-redis-server] UWP listening on %s:%u (RESP bridge enabled)\n", options.bind, options.uwp_port);
    }

    /* Blocks until shutdown; do not call qihse_resp_server_start() first —
     * run() on an already-started server returns EALREADY. */
    qihse_resp_server_run(server);
    qihse_resp_server_destroy(server);
    if (uwp_started) pthread_join(uwp_thread, NULL);
    qihse_vector_db_destroy(vdb);
    qihse_kv_store_destroy(store);
    qihse_vector_db_destroy(forensic_vdb);
    qihse_blob_store_destroy(artifact_blobs);
    return 0;
}
#endif
