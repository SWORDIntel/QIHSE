/*
 * qihse_uwp_secure.c - TLS-first UWP server entry point.
 *
 * This translation unit deliberately includes the existing TLS and UWP
 * implementations rather than duplicating their router/engine logic.  The
 * original qihse_start_uwp_server() symbol is renamed to a legacy entry point,
 * then a TLS-first public entry point is provided below.
 *
 * Default behaviour:
 *   - certificate-backed TLS 1.3 is required;
 *   - cleartext and the legacy symmetric ChaCha20-Poly1305 record transport
 *     are refused;
 *   - QIHSE_UWP_ALLOW_INSECURE=1 is the explicit compatibility escape hatch
 *     for the legacy listener.
 *
 * The TLS listener uses one blocking worker per TLS connection.  This keeps
 * OpenSSL SSL_read/SSL_write ownership simple and prevents the io_uring path
 * from accidentally treating TLS records as the legacy length-prefixed AEAD
 * framing.  The established UWP router is reused unchanged.
 */

#ifndef _WIN32
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#endif

#include "qihse_uwp_tls.c"

#define qihse_start_uwp_server qihse_start_uwp_server_legacy
#include "qihse_uwp.c"
#undef qihse_start_uwp_server

#ifndef _WIN32

typedef struct {
    int client_fd;
    uint32_t source_ip;
    qihse_uwp_context_t* ctx;
} uwp_secure_worker_arg_t;

static pthread_mutex_t uwp_secure_conn_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t uwp_secure_auth_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t uwp_secure_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t uwp_secure_worker_count = 0;

static bool uwp_secure_worker_reserve(void) {
    bool ok = false;
    pthread_mutex_lock(&uwp_secure_worker_mutex);
    if (uwp_secure_worker_count < UWP_MAX_CONNECTIONS) {
        ++uwp_secure_worker_count;
        ok = true;
    }
    pthread_mutex_unlock(&uwp_secure_worker_mutex);
    return ok;
}

static void uwp_secure_worker_release(void) {
    pthread_mutex_lock(&uwp_secure_worker_mutex);
    if (uwp_secure_worker_count > 0) --uwp_secure_worker_count;
    pthread_mutex_unlock(&uwp_secure_worker_mutex);
}

static bool uwp_secure_insecure_opt_in(void) {
    const char* value = getenv("QIHSE_UWP_ALLOW_INSECURE");
    return value && strcmp(value, "1") == 0;
}

static bool uwp_secure_read_exact(qihse_uwp_tls_session_t* session,
                                  uint8_t* out, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t got = 0;
        int rc = qihse_uwp_tls_decrypt(session, NULL, 0,
                                       out + off, len - off, &got);
        if (rc != 0 || got == 0) return false;
        off += got;
    }
    return true;
}

/*
 * The existing router writes through uwp_tls_write_all(conn, ...).  For a real
 * SSL session qihse_uwp_tls_encrypt() already sends the plaintext through
 * SSL_write(), but the legacy helper then also emits its old AEAD envelope to
 * conn->fd.  Give conn->fd a private /dev/null sink so that obsolete envelope
 * never reaches the network while preserving every existing router callback.
 * The SSL object remains bound to the real client socket.
 */
static uwp_conn_t* uwp_secure_conn_create(qihse_uwp_context_t* ctx,
                                          qihse_uwp_tls_session_t* session,
                                          uint32_t source_ip) {
    int sink_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (sink_fd < 0) return NULL;

    uwp_conn_t* conn = calloc(1, sizeof(*conn));
    if (!conn) {
        close(sink_fd);
        return NULL;
    }

    conn->rbuf_cap = sizeof(qihse_uwp_header_t);
    conn->rbuf = malloc(conn->rbuf_cap);
    if (!conn->rbuf) {
        close(sink_fd);
        free(conn);
        return NULL;
    }

    pthread_mutex_lock(&uwp_secure_conn_mutex);
    bool acquired = uwp_connection_acquire(source_ip);
    pthread_mutex_unlock(&uwp_secure_conn_mutex);
    if (!acquired) {
        close(sink_fd);
        free(conn->rbuf);
        free(conn);
        return NULL;
    }

    conn->fd = sink_fd;
    conn->ctx = ctx;
    conn->source_ip = source_ip;
    conn->source_ip_tracked = true;
    conn->state = READING_HEADER;
    conn->current_txn = NULL;
    conn->tls_session = session;
    conn->connected_at = time(NULL);
    conn->last_activity = conn->connected_at;
    conn->authenticated = false;
    return conn;
}

static void uwp_secure_conn_destroy(uwp_conn_t* conn) {
    if (!conn) return;
    if (conn->current_txn && conn->ctx && conn->ctx->txn_manager) {
        qihse_txn_rollback((qihse_txn_manager_t*)conn->ctx->txn_manager,
                           conn->current_txn);
        conn->current_txn = NULL;
    }
    if (conn->tls_session) {
        qihse_uwp_tls_session_destroy(conn->tls_session);
        conn->tls_session = NULL;
    }
    if (conn->source_ip_tracked) {
        pthread_mutex_lock(&uwp_secure_conn_mutex);
        uwp_connection_release(conn->source_ip);
        pthread_mutex_unlock(&uwp_secure_conn_mutex);
    }
    uwp_socket_close(conn->fd);
    free(conn->rbuf);
    free(conn->tls_rawbuf);
    free(conn);
}

static void uwp_secure_send_route_error(uwp_conn_t* conn,
                                        uwp_route_result_t result) {
    const char* reply = uwp_route_error_reply(result);
    if (reply) (void)uwp_tls_write_all(conn, reply, strlen(reply));
}

static void* uwp_secure_tls_worker(void* opaque) {
    uwp_secure_worker_arg_t* arg = (uwp_secure_worker_arg_t*)opaque;
    int client_fd = arg->client_fd;
    uint32_t source_ip = arg->source_ip;
    qihse_uwp_context_t* ctx = arg->ctx;
    free(arg);

    qihse_uwp_tls_session_t* session =
        qihse_uwp_tls_session_create_with_fd(ctx->tls_ctx, client_fd);
    if (!session || !session->is_ssl) {
        if (session) qihse_uwp_tls_session_destroy(session);
        uwp_socket_close(client_fd);
        uwp_secure_worker_release();
        return NULL;
    }

    /* Handshake timeout is deliberately short; normal authenticated traffic
     * gets the same 30-second socket timeout used by the legacy listener. */
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    uwp_conn_t* conn = uwp_secure_conn_create(ctx, session, source_ip);
    if (!conn) {
        qihse_uwp_tls_session_destroy(session);
        uwp_socket_close(client_fd);
        uwp_secure_worker_release();
        return NULL;
    }

    for (;;) {
        qihse_uwp_header_t header;
        if (!uwp_secure_read_exact(session, (uint8_t*)&header, sizeof(header))) {
            break;
        }
        uwp_conn_touch(conn);

        if (memcmp(header.magic, qihse_uwp_magic, sizeof(header.magic)) != 0) {
            uwp_secure_send_route_error(conn, UWP_ROUTE_ERR_MAGIC);
            break;
        }
        if (header.version != 0x01) {
            uwp_secure_send_route_error(conn, UWP_ROUTE_ERR_VERSION);
            break;
        }

        uint64_t payload_len64 = uwp_payload_length(&header);
        if (payload_len64 > QIHSE_UWP_MAX_PAYLOAD || payload_len64 > SIZE_MAX) {
            uwp_secure_send_route_error(conn, UWP_ROUTE_ERR_TOO_LARGE);
            break;
        }
        size_t payload_len = (size_t)payload_len64;

        if (payload_len > conn->rbuf_cap) {
            uint8_t* grown = realloc(conn->rbuf, payload_len);
            if (!grown) {
                uwp_secure_send_route_error(conn, UWP_ROUTE_ERR_DISPATCH);
                break;
            }
            conn->rbuf = grown;
            conn->rbuf_cap = payload_len;
        }
        conn->rbuf_len = payload_len;
        conn->payload_length = payload_len;
        conn->header = header;

        if (payload_len &&
            !uwp_secure_read_exact(session, conn->rbuf, payload_len)) {
            break;
        }

        /* The auth token bucket is process-global and the legacy io_uring
         * path is single-threaded.  Serialize AUTH frames here so moving TLS
         * connections to worker threads does not weaken rate limiting. */
        bool auth_frame = header.target_engine == QIHSE_UWP_TARGET_AUTH;
        if (auth_frame) pthread_mutex_lock(&uwp_secure_auth_mutex);
        uwp_route_result_t route_result = uwp_route_payload(
            client_fd, conn, ctx, &header, conn->rbuf, payload_len,
            &conn->user, &conn->current_txn);
        if (auth_frame) pthread_mutex_unlock(&uwp_secure_auth_mutex);

        if (route_result != UWP_ROUTE_OK) {
            uwp_secure_send_route_error(conn, route_result);
            break;
        }

        /* Preserve authentication and transaction state across frames. */
        conn->rbuf_len = 0;
        conn->payload_length = 0;
        conn->state = READING_HEADER;
    }

    uwp_secure_conn_destroy(conn);
    uwp_socket_close(client_fd);
    uwp_secure_worker_release();
    return NULL;
}

static bool uwp_secure_start_tls_listener(qihse_uwp_context_t* ctx,
                                          uint16_t port,
                                          const char* bind_address) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return false;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(server_fd);
        return false;
    }

    const char* reuseport_env = getenv("QIHSE_UWP_REUSEPORT");
    if (reuseport_env && strcmp(reuseport_env, "1") == 0) {
#ifdef SO_REUSEPORT
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) != 0) {
            perror("setsockopt(SO_REUSEPORT)");
            close(server_fd);
            return false;
        }
#else
        fprintf(stderr, "[QIHSE UWP] QIHSE_UWP_REUSEPORT requested but unavailable\n");
#endif
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (bind_address && bind_address[0] != '\0') {
        if (inet_pton(AF_INET, bind_address, &address.sin_addr) != 1) {
            fprintf(stderr, "[QIHSE UWP] invalid IPv4 bind address: %s\n", bind_address);
            close(server_fd);
            return false;
        }
    } else {
        address.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
        perror("bind failed");
        close(server_fd);
        return false;
    }
    if (listen(server_fd, 1000) != 0) {
        perror("listen");
        close(server_fd);
        return false;
    }

    fprintf(stdout,
            "[QIHSE UWP] TLS 1.3 listener online on %s:%u (certificate TLS required)\n",
            (bind_address && bind_address[0]) ? bind_address : "0.0.0.0",
            (unsigned)port);

    if (getenv("QIHSE_XDP_IFACE")) {
        fprintf(stderr,
                "[QIHSE UWP] AF_XDP direct UWP ingest disabled while TLS 1.3 is required; "
                "raw packet payloads cannot bypass the TLS record layer\n");
    }

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            close(server_fd);
            return false;
        }

        if (!uwp_secure_worker_reserve()) {
            close(client_fd);
            continue;
        }

        /* Bound stalled TLS handshakes before the worker promotes the socket
         * to the normal 30-second request timeout. */
        struct timeval handshake_tv = { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                   &handshake_tv, sizeof(handshake_tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
                   &handshake_tv, sizeof(handshake_tv));

        uwp_secure_worker_arg_t* arg = malloc(sizeof(*arg));
        if (!arg) {
            close(client_fd);
            uwp_secure_worker_release();
            continue;
        }
        arg->client_fd = client_fd;
        arg->source_ip = client_addr.sin_addr.s_addr;
        arg->ctx = ctx;

        pthread_t worker;
        if (pthread_create(&worker, NULL, uwp_secure_tls_worker, arg) != 0) {
            free(arg);
            close(client_fd);
            uwp_secure_worker_release();
            continue;
        }
        pthread_detach(worker);
    }
}

#endif /* !_WIN32 */

bool qihse_start_uwp_server(qihse_uwp_context_t* ctx,
                            uint16_t port,
                            const char* bind_address) {
    if (qihse_auth_is_operator_password_default()) {
        fprintf(stderr,
                "[FATAL SECURITY ERROR] Default operator password detected. "
                "Rotate it explicitly before starting network services.\n");
        return false;
    }

    const bool allow_insecure = uwp_secure_insecure_opt_in();

    if (!ctx || !ctx->tls_ctx || !ctx->tls_ctx->is_cert_based) {
        if (allow_insecure) {
            fprintf(stderr,
                    "[QIHSE UWP] WARNING: QIHSE_UWP_ALLOW_INSECURE=1; "
                    "using legacy cleartext/AEAD listener by explicit request\n");
            return qihse_start_uwp_server_legacy(ctx, port, bind_address);
        }
        fprintf(stderr,
                "[QIHSE UWP] refusing to start without a certificate-backed TLS 1.3 context. "
                "Configure qihse_uwp_tls_ctx_create_with_cert() (or a self-signed "
                "context for development). Legacy cleartext/AEAD transport requires the "
                "explicit QIHSE_UWP_ALLOW_INSECURE=1 compatibility opt-in.\n");
        return false;
    }

#ifdef _WIN32
    fprintf(stderr,
            "[QIHSE UWP] certificate-TLS default listener is currently supported on Linux. "
            "Windows legacy transport remains available only with QIHSE_UWP_ALLOW_INSECURE=1.\n");
    return false;
#else
    return uwp_secure_start_tls_listener(ctx, port, bind_address);
#endif
}
