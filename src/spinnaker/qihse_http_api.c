#include "qihse_http_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <strings.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

qihse_http_server_t* qihse_http_server_create(uint16_t port) {
    qihse_http_server_t* srv = (qihse_http_server_t*)calloc(1, sizeof(qihse_http_server_t));
    if (!srv) return NULL;
    srv->port = port;
    srv->fd = -1;
    srv->running = 0;
    if (pthread_mutex_init(&srv->lock, NULL) != 0) {
        free(srv);
        return NULL;
    }
    if (pthread_cond_init(&srv->workers_drained, NULL) != 0) {
        pthread_mutex_destroy(&srv->lock);
        free(srv);
        return NULL;
    }
    return srv;
}

int qihse_http_server_add_route(qihse_http_server_t* srv, const char* path,
                                http_method_t method, http_route_handler_t handler, void* user_data) {
    if (!srv || !path || !handler) return -1;
    pthread_mutex_lock(&srv->lock);
    if (srv->num_routes >= srv->routes_cap) {
        size_t cap = srv->routes_cap ? srv->routes_cap * 2u : 8u;
        if (cap <= srv->routes_cap || cap > SIZE_MAX / sizeof(http_route_t)) {
            pthread_mutex_unlock(&srv->lock);
            return -1;
        }
        http_route_t* tmp = realloc(srv->routes, cap * sizeof(http_route_t));
        if (!tmp) {
            pthread_mutex_unlock(&srv->lock);
            return -1;
        }
        srv->routes = tmp;
        srv->routes_cap = cap;
    }
    char* path_copy = strdup(path);
    if (!path_copy) {
        pthread_mutex_unlock(&srv->lock);
        return -1;
    }
    srv->routes[srv->num_routes].path = path_copy;
    srv->routes[srv->num_routes].method = method;
    srv->routes[srv->num_routes].handler = handler;
    srv->routes[srv->num_routes].user_data = user_data;
    srv->num_routes++;
    pthread_mutex_unlock(&srv->lock);
    return 0;
}

static bool find_route(qihse_http_server_t* srv, const char* path, http_method_t method, http_route_t* out) {
    if (!srv || !path || !out) return false;
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->num_routes; i++) {
        if (srv->routes[i].method == method && strcmp(srv->routes[i].path, path) == 0) {
            *out = srv->routes[i];
            pthread_mutex_unlock(&srv->lock);
            return true;
        }
    }
    /* Try prefix match for path parameters with boundary check */
    for (size_t i = 0; i < srv->num_routes; i++) {
        if (srv->routes[i].method == method) {
            size_t plen = strlen(srv->routes[i].path);
            if (strncmp(srv->routes[i].path, path, plen) == 0 &&
                (path[plen] == '/' || path[plen] == '\0')) {
                *out = srv->routes[i];
                pthread_mutex_unlock(&srv->lock);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&srv->lock);
    return false;
}

static void send_response(int fd, const http_response_t* res) {
    const char* status_text = "OK";
    switch (res->status_code) {
        case 200: status_text = "OK"; break;
        case 201: status_text = "Created"; break;
        case 204: status_text = "No Content"; break;
        case 401: status_text = "Unauthorized"; break;
        case 403: status_text = "Forbidden"; break;
        case 413: status_text = "Content Too Large"; break;
        case 501: status_text = "Not Implemented"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 405: status_text = "Method Not Allowed"; break;
        case 409: status_text = "Conflict"; break;
        case 500: status_text = "Internal Server Error"; break;
    }
    char header[1024];
    const char* ct = res->content_type ? res->content_type : "application/json";
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        res->status_code, status_text, ct, res->body_len);
    /* snprintf returns the would-be length, not the available buffer size. */
    if (hlen <= 0 || (size_t)hlen >= sizeof(header)) return;
    const char* segments[2] = {header, res->body};
    size_t lengths[2] = {(size_t)hlen, res->body ? res->body_len : 0u};
    for (unsigned i = 0; i < 2; ++i) {
        size_t off = 0;
        while (off < lengths[i]) {
            ssize_t n = send(fd, segments[i] + off, lengths[i] - off, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return;
            off += (size_t)n;
        }
    }
}

/* The acceptor increments active_workers before creating a detached worker.
 * Every exit decrements it; shutdown waits until no worker can touch srv. */
static void* http_client_thread(void* arg) {
    struct { int fd; qihse_http_server_t* srv; }* ctx = arg;
    int fd = ctx->fd;
    qihse_http_server_t* srv = ctx->srv;
    char* buf = malloc(65536u);
    size_t used = 0;
    int parsed = -1;
    http_request_t req = {0};
    if (buf) while (used < 65535u) {
        ssize_t n = recv(fd, buf + used, 65535u - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
        parsed = http_parse_request(buf, used, &req);
        if (parsed != 1) break;
    }
    if (parsed != 0) {
        http_response_t* err = http_response_error(400,"Malformed or incomplete request");
        if (err) send_response(fd,err);
        http_response_free(err);
    } else {
        http_route_t route;
        if (!find_route(srv,req.path,req.method,&route)) {
            http_response_t* err = http_response_error(404,"Not Found");
            if (err) send_response(fd,err);
            http_response_free(err);
        } else {
            http_response_t* res = route.handler(&req,route.user_data);
            if (res) { send_response(fd,res); http_response_free(res); }
        }
    }
    http_request_free(&req);
    free(buf);
    close(fd);
    pthread_mutex_lock(&srv->lock);
    if (--srv->active_workers == 0u) pthread_cond_broadcast(&srv->workers_drained);
    pthread_mutex_unlock(&srv->lock);
    free(ctx);
    return NULL;
}

static void* http_accept_thread(void* arg) {
    qihse_http_server_t* srv = (qihse_http_server_t*)arg;
    while (__atomic_load_n(&srv->running, __ATOMIC_ACQUIRE)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(srv->fd, (struct sockaddr*)&addr, &addr_len);
        if (fd < 0) continue;
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        struct { int fd; qihse_http_server_t* srv; }* ctx = malloc(sizeof(*ctx));
        if (!ctx) { close(fd); continue; }
        ctx->fd = fd;
        ctx->srv = srv;
        pthread_mutex_lock(&srv->lock);
        if (srv->active_workers >= 128u) {
            pthread_mutex_unlock(&srv->lock);
            close(fd);
            free(ctx);
            continue;
        }
        ++srv->active_workers;
        pthread_mutex_unlock(&srv->lock);
        pthread_t tid;
        if (pthread_create(&tid, NULL, http_client_thread, ctx) != 0) {
            pthread_mutex_lock(&srv->lock);
            if (--srv->active_workers == 0u) pthread_cond_broadcast(&srv->workers_drained);
            pthread_mutex_unlock(&srv->lock);
            close(fd);
            free(ctx);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}

int qihse_http_server_start(qihse_http_server_t* srv) {
    if (!srv || srv->running) return -1;
    srv->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->fd < 0) return -1;
    int opt = 1;
    setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(srv->port);
    if (bind(srv->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(srv->fd); return -1; }
    if (listen(srv->fd, 128) < 0) { close(srv->fd); return -1; }
    /* Port 0 means ephemeral: read back the bound port so callers can reach
     * the server without racing a fixed port. */
    if (srv->port == 0) {
        struct sockaddr_in bound;
        socklen_t blen = sizeof(bound);
        if (getsockname(srv->fd, (struct sockaddr*)&bound, &blen) == 0)
            srv->port = ntohs(bound.sin_port);
    }
    __atomic_store_n(&srv->running, 1, __ATOMIC_RELEASE);
    if (pthread_create(&srv->thread, NULL, http_accept_thread, srv) != 0) {
        __atomic_store_n(&srv->running, 0, __ATOMIC_RELEASE);
        close(srv->fd);
        srv->fd = -1;
        return -1;
    }
    return 0;
}

int qihse_http_server_stop(qihse_http_server_t* srv) {
    if (!srv) return -1;
    if (!__atomic_load_n(&srv->running, __ATOMIC_ACQUIRE)) return 0;
    __atomic_store_n(&srv->running, 0, __ATOMIC_RELEASE);
    if (srv->fd >= 0) {
        /* shutdown() before close(): closing a listen fd does NOT reliably
         * wake a thread blocked in accept() on it, and the join below would
         * hang forever. */
        shutdown(srv->fd, SHUT_RDWR);
        close(srv->fd);
        srv->fd = -1;
    }
    pthread_join(srv->thread, NULL);
    pthread_mutex_lock(&srv->lock);
    while (srv->active_workers != 0u)
        pthread_cond_wait(&srv->workers_drained, &srv->lock);
    pthread_mutex_unlock(&srv->lock);
    return 0;
}

void qihse_http_server_destroy(qihse_http_server_t* srv) {
    if (!srv) return;
    qihse_http_server_stop(srv);
    for (size_t i = 0; i < srv->num_routes; i++) free(srv->routes[i].path);
    free(srv->routes);
    pthread_cond_destroy(&srv->workers_drained);
    pthread_mutex_destroy(&srv->lock);
    free(srv);
}

/* Response helpers: all allocations and serialized lengths must be checked. */
static http_response_t* http_response_make(int status, const char* body, const char* type) {
    if (!body || !type) return NULL;
    http_response_t* res = calloc(1, sizeof(*res));
    if (!res) return NULL;
    res->status_code = status;
    res->body_len = strlen(body);
    res->body = strdup(body);
    res->content_type = strdup(type);
    if (!res->body || !res->content_type) {
        free(res->body);
        free(res->content_type);
        free(res);
        return NULL;
    }
    return res;
}

http_response_t* http_response_json(int status, const char* json) {
    return http_response_make(status, json, "application/json");
}

http_response_t* http_response_text(int status, const char* text) {
    return http_response_make(status, text, "text/plain");
}

http_response_t* http_response_error(int status, const char* message) {
    char* escaped = json_escape(message ? message : "Internal Error");
    if (!escaped) return NULL;
    const char* fmt = "{\"error\":{\"code\":%d,\"message\":\"%s\"}}";
    int n = snprintf(NULL, 0, fmt, status, escaped);
    if (n < 0 || n > 65535) { free(escaped); return NULL; }
    char* json = malloc((size_t)n + 1u);
    if (!json) { free(escaped); return NULL; }
    snprintf(json, (size_t)n + 1u, fmt, status, escaped);
    http_response_t* res = http_response_json(status, json);
    free(json);
    free(escaped);
    return res;
}

void http_response_free(http_response_t* res) {
    if (!res) return;
    free(res->body);
    free(res->content_type);
    free(res);
}

/* A complete HTTP/1.x frame is 0, incomplete is 1, malformed is -1.
 * Strict Content-Length framing rejects request smuggling and C-string input
 * truncation in existing protocol-shape adapters. No chunked encoding. */
enum { HTTP_HEADER_CAP = 8192, HTTP_FRAME_CAP = 65535, HTTP_TARGET_CAP = 4096 };
static int http_header_info(const char* raw, size_t len, size_t* header_end,
                            size_t* body_len, char** type_out) {
    *header_end = *body_len = 0;
    *type_out = NULL;
    if (len > HTTP_FRAME_CAP) return -1;
    size_t end = 0;
    for (size_t i = 3; i < len && i < HTTP_HEADER_CAP; i++) {
        if (!memcmp(raw + i - 3, "\r\n\r\n", 4)) { end = i + 1; break; }
    }
    if (!end) return len >= HTTP_HEADER_CAP ? -1 : 1;
    if (memchr(raw, '\0', end)) return -1;
    const char* begin = raw;
    const char* limit = raw + end - 2;
    const char* cr = memchr(begin, '\r', (size_t)(limit - begin));
    if (!cr || cr == begin || cr[1] != '\n') return -1;
    const char* sp = memchr(begin, ' ', (size_t)(cr - begin));
    if (!sp) return -1;
    const char* version_sp = memchr(sp + 1, ' ', (size_t)(cr - sp - 1));
    if (!version_sp || version_sp == sp + 1) return -1;
    const char* version = version_sp + 1;
    if ((cr - version) != 8 ||
        (memcmp(version, "HTTP/1.1", 8) && memcmp(version, "HTTP/1.0", 8)))
        return -1;
    const char* line = cr + 2;
    bool seen_length = false, seen_type = false;
    unsigned fields = 0;
    while (line < limit) {
        if (++fields > 64) return -1;
        cr = memchr(line, '\r', (size_t)(limit - line));
        if (!cr || cr == line || cr[1] != '\n') return -1;
        const char* colon = memchr(line, ':', (size_t)(cr - line));
        if (!colon || colon == line) return -1;
        for (const char* p = line; p < colon; p++) {
            unsigned char c = (unsigned char)*p;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || strchr("!#$%&'*+-.^_|~",c)))
                return -1;
        }
        const char* val = colon + 1;
        while (val < cr && (*val == ' ' || *val == '\t')) val++;
        const char* stop = cr;
        while (stop > val && (stop[-1] == ' ' || stop[-1] == '\t')) stop--;
        for (const char* p = val; p < stop; p++) {
            unsigned char c = (unsigned char)*p;
            if (c < 32 || c == 127) return -1;
        }
        size_t namelen = (size_t)(colon - line);
        if (namelen == 14 && !strncasecmp(line, "Content-Length", 14)) {
            if (seen_length || stop == val) return -1;
            seen_length = true;
            for (const char* p = val; p < stop; p++) {
                if (*p < '0' || *p > '9') return -1;
                unsigned d = (unsigned)(*p - '0');
                if (*body_len > (HTTP_FRAME_CAP - d)/10u) return -1;
                *body_len = *body_len * 10u + d;
            }
        } else if (namelen == 17 && !strncasecmp(line,"Transfer-Encoding",17)) {
            return -1;
        } else if (namelen == 12 && !strncasecmp(line,"Content-Type",12)) {
            if (seen_type || stop - val > 255) return -1;
            seen_type = true;
            *type_out = strndup(val, (size_t)(stop - val));
            if (!*type_out) return -1;
        }
        line = cr + 2;
    }
    if (line != limit || *body_len > HTTP_FRAME_CAP - end) return -1;
    *header_end = end;
    return 0;
}

int http_parse_request(const char* raw, size_t len, http_request_t* out) {
    if (!raw || !out) return -1;
    memset(out, 0, sizeof(*out));
    size_t head = 0, body = 0;
    char* type = NULL;
    int rc = http_header_info(raw, len, &head, &body, &type);
    if (rc != 0) { free(type); return rc; }
    if (len < head + body) { free(type); return 1; }
    if (len != head + body || memchr(raw + head, '\0', body)) {
        free(type);
        return -1;
    }
    const char* sp = memchr(raw, ' ', head);
    if (!sp) { free(type); return -1; }
    size_t method_len = (size_t)(sp - raw);
    if (method_len == 3 && !memcmp(raw,"GET",3)) out->method = HTTP_GET;
    else if (method_len == 4 && !memcmp(raw,"POST",4)) out->method = HTTP_POST;
    else if (method_len == 3 && !memcmp(raw,"PUT",3)) out->method = HTTP_PUT;
    else if (method_len == 6 && !memcmp(raw,"DELETE",6)) out->method = HTTP_DELETE;
    else if (method_len == 5 && !memcmp(raw,"PATCH",5)) out->method = HTTP_PATCH;
    else if (method_len == 4 && !memcmp(raw,"HEAD",4)) out->method = HTTP_HEAD;
    else { free(type); return -1; }
    const char* target = sp + 1;
    const char* next = memchr(target,' ', (size_t)(raw + head - target));
    if (!next || target == next || target[0] != '/' ||
        next - target > HTTP_TARGET_CAP) { free(type); return -1; }
    for (const char* c = target; c < next; ++c) {
        unsigned char v = (unsigned char)*c;
        if (v <= 32 || v >= 127 || v == '\\') { free(type); return -1; }
    }
    const char* qm = memchr(target,'?',(size_t)(next - target));
    size_t plen = (size_t)((qm ? qm : next) - target);
    if (!plen) { free(type); return -1; }
    out->path = strndup(target, plen);
    if (qm) out->query_string = strndup(qm + 1, (size_t)(next - qm - 1));
    out->content_type = type;
    if (body) {
        out->body = malloc(body + 1);
        if (out->body) {
            memcpy(out->body, raw + head, body);
            out->body[body] = '\0';
            out->body_len = body;
        }
    }
    if (!out->path || (qm && !out->query_string) || (body && !out->body)) {
        http_request_free(out);
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

void http_request_free(http_request_t* req) {
    if (!req) return;
    free(req->path);
    free(req->query_string);
    free(req->body);
    free(req->content_type);
}

/* JSON strings are escaped before insertion into any object. */
char* json_escape(const char* input) {
    const char* value = input ? input : "";
    size_t len = strlen(value);
    if (len > (SIZE_MAX - 1u) / 6u) return NULL;
    char* out = malloc(len * 6u + 1u);
    if (!out) return NULL;
    size_t j = 0u;
    for (size_t i = 0u; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        switch (c) {
            case '"': out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if (c < 32) {
                    int n = snprintf(out + j, 7u, "\\u%04x", c);
                    if (n != 6) { free(out); return NULL; }
                    j += 6u;
                } else out[j++] = (char)c;
        }
    }
    out[j] = '\0';
    return out;
}

/* The fixed first argument is the FIRST KEY, not an ignored format marker.
 * Pairs terminate at a NULL key: json_build_object("a", "1", NULL). */
char* json_build_object(const char* first_key, ...) {
    if (!first_key) return strdup("{}");
    size_t cap = 128u, used = 1u;
    char* result = malloc(cap);
    if (!result) return NULL;
    result[0] = '{';
    va_list ap;
    va_start(ap, first_key);
    const char* key = first_key;
    bool first = true;
    while (key) {
        const char* value = va_arg(ap, const char*);
        if (!value) { free(result); result = NULL; break; }
        char* k = json_escape(key);
        char* v = json_escape(value);
        if (!k || !v) { free(k); free(v); free(result); result = NULL; break; }
        size_t kl = strlen(k), vl = strlen(v);
        if (kl > SIZE_MAX - vl - used - 8u) {
            free(k); free(v); free(result); result = NULL; break;
        }
        size_t need = used + kl + vl + 8u;
        if (need > cap) {
            char* grown = realloc(result, need);
            if (!grown) {
                free(k); free(v); free(result); result = NULL; break;
            }
            result = grown;
            cap = need;
        }
        if (!first) result[used++] = ',';
        result[used++] = '"';
        memcpy(result + used, k, kl); used += kl;
        result[used++] = '"';
        result[used++] = ':';
        result[used++] = '"';
        memcpy(result + used, v, vl); used += vl;
        result[used++] = '"';
        free(k); free(v);
        first = false;
        key = va_arg(ap, const char*);
    }
    va_end(ap);
    if (result) {
        result[used++] = '}';
        result[used] = '\0';
    }
    return result;
}
