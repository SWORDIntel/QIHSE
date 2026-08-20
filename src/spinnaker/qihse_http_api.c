#include "qihse_http_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <ctype.h>

qihse_http_server_t* qihse_http_server_create(uint16_t port) {
    qihse_http_server_t* srv = (qihse_http_server_t*)calloc(1, sizeof(qihse_http_server_t));
    if (!srv) return NULL;
    srv->port = port;
    srv->fd = -1;
    srv->running = 0;
    pthread_mutex_init(&srv->lock, NULL);
    return srv;
}

int qihse_http_server_add_route(qihse_http_server_t* srv, const char* path,
                                http_method_t method, http_route_handler_t handler, void* user_data) {
    if (!srv || !path || !handler) return -1;
    pthread_mutex_lock(&srv->lock);
    if (srv->num_routes >= srv->routes_cap) {
        srv->routes_cap = srv->routes_cap ? srv->routes_cap * 2 : 8;
        srv->routes = (http_route_t*)realloc(srv->routes, srv->routes_cap * sizeof(http_route_t));
    }
    srv->routes[srv->num_routes].path = strdup(path);
    srv->routes[srv->num_routes].method = method;
    srv->routes[srv->num_routes].handler = handler;
    srv->routes[srv->num_routes].user_data = user_data;
    srv->num_routes++;
    pthread_mutex_unlock(&srv->lock);
    return 0;
}

static http_route_t* find_route(qihse_http_server_t* srv, const char* path, http_method_t method) {
    for (size_t i = 0; i < srv->num_routes; i++) {
        if (srv->routes[i].method == method && strcmp(srv->routes[i].path, path) == 0)
            return &srv->routes[i];
    }
    /* Try prefix match for path parameters */
    for (size_t i = 0; i < srv->num_routes; i++) {
        if (srv->routes[i].method == method) {
            size_t plen = strlen(srv->routes[i].path);
            if (strncmp(srv->routes[i].path, path, plen) == 0) return &srv->routes[i];
        }
    }
    return NULL;
}

static void send_response(int fd, const http_response_t* res) {
    const char* status_text = "OK";
    switch (res->status_code) {
        case 200: status_text = "OK"; break;
        case 201: status_text = "Created"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 500: status_text = "Internal Server Error"; break;
    }
    char header[1024];
    const char* ct = res->content_type ? res->content_type : "application/json";
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        res->status_code, status_text, ct, res->body_len);
    send(fd, header, hlen, 0);
    if (res->body && res->body_len > 0) send(fd, res->body, res->body_len, 0);
}

static void* http_client_thread(void* arg) {
    struct { int fd; qihse_http_server_t* srv; }* ctx = arg;
    char buf[65536];
    ssize_t n = recv(ctx->fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(ctx->fd); free(ctx); return NULL; }
    buf[n] = '\0';
    
    http_request_t req;
    if (http_parse_request(buf, n, &req) != 0) {
        http_response_t* err = http_response_error(400, "Bad Request");
        send_response(ctx->fd, err);
        http_response_free(err);
        close(ctx->fd);
        free(ctx);
        return NULL;
    }
    
    http_route_t* route = find_route(ctx->srv, req.path, req.method);
    if (!route) {
        http_response_t* err = http_response_error(404, "Not Found");
        send_response(ctx->fd, err);
        http_response_free(err);
    } else {
        http_response_t* res = route->handler(&req, route->user_data);
        if (res) {
            send_response(ctx->fd, res);
            http_response_free(res);
        }
    }
    
    http_request_free(&req);
    close(ctx->fd);
    free(ctx);
    return NULL;
}

static void* http_accept_thread(void* arg) {
    qihse_http_server_t* srv = (qihse_http_server_t*)arg;
    while (srv->running) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(srv->fd, (struct sockaddr*)&addr, &addr_len);
        if (fd < 0) continue;
        struct { int fd; qihse_http_server_t* srv; }* ctx = malloc(sizeof(*ctx));
        ctx->fd = fd;
        ctx->srv = srv;
        pthread_t tid;
        pthread_create(&tid, NULL, http_client_thread, ctx);
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
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(srv->port);
    if (bind(srv->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(srv->fd); return -1; }
    if (listen(srv->fd, 128) < 0) { close(srv->fd); return -1; }
    srv->running = 1;
    pthread_create(&srv->thread, NULL, http_accept_thread, srv);
    return 0;
}

int qihse_http_server_stop(qihse_http_server_t* srv) {
    if (!srv) return -1;
    srv->running = 0;
    if (srv->fd >= 0) { close(srv->fd); srv->fd = -1; }
    pthread_join(srv->thread, NULL);
    return 0;
}

void qihse_http_server_destroy(qihse_http_server_t* srv) {
    if (!srv) return;
    qihse_http_server_stop(srv);
    for (size_t i = 0; i < srv->num_routes; i++) free(srv->routes[i].path);
    free(srv->routes);
    pthread_mutex_destroy(&srv->lock);
    free(srv);
}

/* Response helpers */
http_response_t* http_response_json(int status, const char* json) {
    http_response_t* res = (http_response_t*)calloc(1, sizeof(http_response_t));
    res->status_code = status;
    res->body_len = strlen(json);
    res->body = strdup(json);
    res->content_type = strdup("application/json");
    return res;
}

http_response_t* http_response_text(int status, const char* text) {
    http_response_t* res = (http_response_t*)calloc(1, sizeof(http_response_t));
    res->status_code = status;
    res->body_len = strlen(text);
    res->body = strdup(text);
    res->content_type = strdup("text/plain");
    return res;
}

http_response_t* http_response_error(int status, const char* message) {
    char json[1024];
    char* escaped = json_escape(message);
    snprintf(json, sizeof(json), "{\"error\":{\"code\":%d,\"message\":\"%s\"}}", status, escaped);
    free(escaped);
    return http_response_json(status, json);
}

void http_response_free(http_response_t* res) {
    if (!res) return;
    free(res->body);
    free(res->content_type);
    free(res);
}

/* Request parsing */
int http_parse_request(const char* raw, size_t len, http_request_t* out) {
    if (!raw || !out) return -1;
    memset(out, 0, sizeof(*out));
    /* Parse method */
    const char* p = raw;
    const char* sp = strchr(p, ' ');
    if (!sp) return -1;
    size_t mlen = sp - p;
    if (mlen == 3 && strncmp(p, "GET", 3) == 0) out->method = HTTP_GET;
    else if (mlen == 4 && strncmp(p, "POST", 4) == 0) out->method = HTTP_POST;
    else if (mlen == 3 && strncmp(p, "PUT", 3) == 0) out->method = HTTP_PUT;
    else if (mlen == 6 && strncmp(p, "DELETE", 6) == 0) out->method = HTTP_DELETE;
    else if (mlen == 5 && strncmp(p, "PATCH", 5) == 0) out->method = HTTP_PATCH;
    else return -1;
    
    /* Parse path */
    p = sp + 1;
    sp = strchr(p, ' ');
    if (!sp) return -1;
    const char* q = strchr(p, '?');
    if (q && q < sp) {
        out->path = strndup(p, q - p);
        out->query_string = strndup(q + 1, sp - q - 1);
    } else {
        out->path = strndup(p, sp - p);
    }
    
    /* Find body (after \r\n\r\n) */
    const char* body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        out->body_len = len - (body_start - raw);
        if (out->body_len > 0) {
            out->body = (char*)malloc(out->body_len + 1);
            memcpy(out->body, body_start, out->body_len);
            out->body[out->body_len] = '\0';
        }
    }
    
    /* Parse Content-Type */
    const char* ct = strcasestr(raw, "Content-Type:");
    if (ct) {
        ct += 13;
        while (*ct == ' ' || *ct == '\t') ct++;
        const char* eol = strstr(ct, "\r\n");
        if (eol) out->content_type = strndup(ct, eol - ct);
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

/* JSON helpers */
char* json_escape(const char* s) {
    if (!s) return strdup("");
    size_t len = strlen(s);
    char* out = (char*)malloc(len * 6 + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        switch (s[i]) {
            case '"': out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if ((unsigned char)s[i] < 32) {
                    j += snprintf(out + j, 7, "\\u%04x", s[i]);
                } else {
                    out[j++] = s[i];
                }
        }
    }
    out[j] = '\0';
    return out;
}

char* json_build_object(const char* fmt, ...) {
    /* Simple format: key1, val1, key2, val2, ... */
    va_list ap;
    va_start(ap, fmt);
    size_t cap = 1024;
    char* result = (char*)malloc(cap);
    size_t len = 0;
    result[len++] = '{';
    
    const char* key;
    int first = 1;
    while ((key = va_arg(ap, const char*)) != NULL) {
        const char* val = va_arg(ap, const char*);
        if (!val) break;
        if (!first) result[len++] = ',';
        first = 0;
        char* esc_val = json_escape(val);
        size_t need = strlen(key) + strlen(esc_val) + 8;
        if (len + need > cap) { cap = (len + need) * 2; result = realloc(result, cap); }
        len += snprintf(result + len, cap - len, "\"%s\":\"%s\"", key, esc_val);
        free(esc_val);
    }
    result[len++] = '}';
    result[len] = '\0';
    va_end(ap);
    return result;
}
