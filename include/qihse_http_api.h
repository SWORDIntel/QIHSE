#ifndef QIHSE_HTTP_API_H
#define QIHSE_HTTP_API_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HTTP_GET = 0,
    HTTP_POST = 1,
    HTTP_PUT = 2,
    HTTP_DELETE = 3,
    HTTP_PATCH = 4,
    HTTP_HEAD = 5
} http_method_t;

typedef struct {
    http_method_t method;
    char* path;
    char* query_string;
    char* body;
    size_t body_len;
    char* content_type;
} http_request_t;

typedef struct {
    int status_code;
    char* body;
    size_t body_len;
    char* content_type;
} http_response_t;

typedef http_response_t* (*http_route_handler_t)(const http_request_t* req, void* user_data);

typedef struct {
    char* path;
    http_method_t method;
    http_route_handler_t handler;
    void* user_data;
} http_route_t;

typedef struct {
    uint16_t port;
    int fd;
    pthread_t thread;
    volatile int running;
    http_route_t* routes;
    size_t num_routes;
    size_t routes_cap;
    pthread_mutex_t lock;
} qihse_http_server_t;

qihse_http_server_t* qihse_http_server_create(uint16_t port);
int qihse_http_server_add_route(qihse_http_server_t* srv, const char* path,
                                http_method_t method, http_route_handler_t handler, void* user_data);
int qihse_http_server_start(qihse_http_server_t* srv);
int qihse_http_server_stop(qihse_http_server_t* srv);
void qihse_http_server_destroy(qihse_http_server_t* srv);

/* Response helpers */
http_response_t* http_response_json(int status, const char* json);
http_response_t* http_response_text(int status, const char* text);
http_response_t* http_response_error(int status, const char* message);
void http_response_free(http_response_t* res);

/* Request parsing */
int http_parse_request(const char* raw, size_t len, http_request_t* out);
void http_request_free(http_request_t* req);

/* JSON helpers */
char* json_escape(const char* s);
char* json_build_object(const char* fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
