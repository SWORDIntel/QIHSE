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

#include "qihse_auth.h"
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
    const char* operator_password;
    const char* embedder_onnx;  /* NULL = built-in lexical embedder */
    const char* artifact_blob_dir;
    const char* artifact_staging_dir;
    const char* forensic_vdb_path;
} server_options_t;

static void usage(const char* program) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --port N          RESP listen port (default 6379)\n"
            "  --bind ADDR       bind address (default 127.0.0.1)\n"
            "  --dir PATH        persistence directory (default /var/lib/qihse or $QIHSE_DATA_DIR)\n"
            "  --require-auth    require AUTH per connection\n"
            "  --password PASS   operator password (prefer QIHSE_OPERATOR_PASSWORD env; avoid argv exposure)\n"
            "  --pubsub-dir PATH durable pub/sub event-stream directory (default: in-memory pub/sub)\n"
            "  --channel-classif N   classification tag applied to pub/sub channels (default 0)\n"
            "  --channel-sci N       SCI compartment mask applied to pub/sub channels (default 0)\n"
            "  --uwp-port N      also serve UWP on port N sharing the same stores (default: disabled)\n"
            "  --artifact-blob-dir DIR  enable classified dump blobs in a dedicated store (loopback + auth only)\n"
            "  --artifact-staging-dir DIR  required private 0700 upload staging directory\n"
            "  --forensic-vdb PATH  isolated operator-only 1024-dimensional persistent index\n"
            "  --embedder-onnx DIR  install the ONNX embedding model in DIR as the AIMEM embedder\n"
            "                      (env fallback QIHSE_AIMEM_EMBEDDER_ONNX; failure is fatal)\n",
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
    options.port = 6379;
    options.bind = "127.0.0.1";
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
        else if (strcmp(arg, "--password") == 0 && has_next) options.operator_password = argv[++i];
        else if (strcmp(arg, "--embedder-onnx") == 0 && has_next) options.embedder_onnx = argv[++i];
        else if (strcmp(arg, "--artifact-blob-dir") == 0 && has_next) options.artifact_blob_dir = argv[++i];
        else if (strcmp(arg, "--artifact-staging-dir") == 0 && has_next) options.artifact_staging_dir = argv[++i];
        else if (strcmp(arg, "--forensic-vdb") == 0 && has_next) options.forensic_vdb_path = argv[++i];
        else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown or incomplete option: %s\n", arg); usage(argv[0]); return 2; }
    }

    static char s_file_pw[256];
    if (!options.operator_password) {
        const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
        if (env_pw && *env_pw) {
            options.operator_password = env_pw;
        } else {
            FILE* ef = fopen("/etc/qihse/cluster-node0.env", "r");
            if (ef) {
                char line[512];
                while (fgets(line, sizeof(line), ef)) {
                    if (strncmp(line, "QIHSE_OPERATOR_PASSWORD=", 24) == 0) {
                        char* p = line + 24;
                        p[strcspn(p, "\r\n")] = '\0';
                        if (strlen(p) >= 12 && strlen(p) < sizeof(s_file_pw)) {
                            snprintf(s_file_pw, sizeof(s_file_pw), "%s", p);
                            options.operator_password = s_file_pw;
                            break;
                        }
                    }
                }
                fclose(ef);
            }
        }
    }

    if (options.require_auth) {
        if (!options.operator_password) options.operator_password = getenv("QIHSE_OPERATOR_PASSWORD");
        if (!options.operator_password && getenv("QIHSE_AUTH_USER") &&
            strcmp(getenv("QIHSE_AUTH_USER"), "GODMODE_OP") == 0)
            options.operator_password = getenv("QIHSE_AUTH_PASSWORD");
        if (!options.operator_password) {
            fprintf(stderr, "--require-auth requires QIHSE_OPERATOR_PASSWORD, QIHSE_AUTH_PASSWORD, --password, or /etc/qihse/cluster-node0.env\n");
            return 2;
        }
        /* Non-loopback binds without auth are rejected by the engine itself. */
    }
    if (options.artifact_blob_dir || options.artifact_staging_dir || options.forensic_vdb_path) {
        if (!options.artifact_blob_dir || !options.artifact_staging_dir ||
            !options.require_auth ||
            (strcmp(options.bind, "127.0.0.1") != 0 && strcmp(options.bind, "::1") != 0)) {
            fprintf(stderr, "artifact upload requires both directories, --require-auth, and a loopback bind\n");
            return 2;
        }
    }
    if (!options.embedder_onnx) options.embedder_onnx = getenv("QIHSE_AIMEM_EMBEDDER_ONNX");
    if (options.embedder_onnx && *options.embedder_onnx &&
        !qihse_aimem_onnx_embedder_install(options.embedder_onnx)) {
        /* Fail closed: serving semantic recall on the lexical hash while an
         * operator asked for the real model would be a silent downgrade. */
        fprintf(stderr, "[qihse-redis-server] ONNX embedder install failed for %s\n", options.embedder_onnx);
        return 1;
    }

    setenv("QIHSE_DATA_DIR", data_dir, 1);
    if (!qihse_auth_init()) {
        fprintf(stderr, "[qihse-redis-server] auth subsystem init failed\n");
        return 1;
    }

    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!store || !vdb) {
        fprintf(stderr, "[qihse-redis-server] engine initialization failed\n");
        return 1;
    }

    if (options.require_auth) {
        qihse_user_t* operator_user = qihse_auth_get_user(0);
        if (operator_user && qihse_auth_is_operator_password_default()) {
            if (!qihse_auth_bootstrap_operator(options.operator_password)) {
                fprintf(stderr, "[qihse-redis-server] operator password bootstrap failed (min 12 chars)\n");
                return 1;
            }
        } else if (operator_user) {
            /* Already configured: never silently ignore --password. An
             * idempotent restart must present the configured password; a
             * stale one is a loud refusal, not a quiet serve-with-old. */
            qihse_user_t* check = qihse_auth_authenticate_id(0, options.operator_password);
            if (!check) {
                fprintf(stderr,
                        "[qihse-redis-server] --password rejected: the operator password is "
                        "already configured and does not match. Rotate at runtime with "
                        "operator credentials (USER.MODIFY) or start against a fresh --dir.\n");
                return 2;
            }
        }
    }

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = options.port;
    config.bind_address = options.bind;
    config.advertise_address = options.bind;
    config.auth_required = options.require_auth;
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
        fprintf(stderr, "[qihse-redis-server] RESP server creation failed (auth gate or bind error)\n");
        qihse_vector_db_destroy(forensic_vdb);
        qihse_blob_store_destroy(artifact_blobs);
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
