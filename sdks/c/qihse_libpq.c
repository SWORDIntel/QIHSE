#include "qihse_libpq.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct qihse_pgconn_s {
    int fd;
    int status;
    char* host;
    uint16_t port;
    char* dbname;
    char* user;
    char* password;
    char* errmsg;
    char* last_query;
};

struct qihse_pgresult_s {
    ExecStatusType status;
    char* errmsg;
    int ntuples;
    int nfields;
    char** field_names;
    Oid* field_types;
    char*** values;   /* [row][col] */
    int** nulls;      /* [row][col] */
    int** lengths;    /* [row][col] */
    char* cmd_status;
    char* cmd_tuples;
    Oid oid_value;
};

static PGresult* new_result(ExecStatusType status) {
    PGresult* r = (PGresult*)calloc(1, sizeof(struct qihse_pgresult_s));
    if (r) r->status = status;
    return r;
}

static char* dup_str(const char* s) {
    if (!s) return NULL;
    return strdup(s);
}

static PGconn* new_conn(void) {
    PGconn* c = (PGconn*)calloc(1, sizeof(struct qihse_pgconn_s));
    if (c) {
        c->fd = -1;
        c->status = CONNECTION_BAD;
        c->port = 5432;
    }
    return c;
}

static void parse_conninfo(PGconn* c, const char* conninfo) {
    /* Parse "host=localhost port=5432 dbname=test user=admin" */
    const char* p = conninfo;
    while (p && *p) {
        while (*p == ' ') p++;
        const char* eq = strchr(p, '=');
        if (!eq) break;
        size_t keylen = eq - p;
        const char* val_start = eq + 1;
        const char* val_end = val_start;
        while (*val_end && *val_end != ' ') val_end++;
        size_t vallen = val_end - val_start;
        
        char key[64];
        if (keylen < sizeof(key)) {
            memcpy(key, p, keylen);
            key[keylen] = '\0';
            char* val = (char*)malloc(vallen + 1);
            memcpy(val, val_start, vallen);
            val[vallen] = '\0';
            
            if (strcmp(key, "host") == 0) { free(c->host); c->host = val; }
            else if (strcmp(key, "port") == 0) { c->port = (uint16_t)atoi(val); free(val); }
            else if (strcmp(key, "dbname") == 0) { free(c->dbname); c->dbname = val; }
            else if (strcmp(key, "user") == 0) { free(c->user); c->user = val; }
            else if (strcmp(key, "password") == 0) { free(c->password); c->password = val; }
            else free(val);
        }
        p = val_end;
    }
}

PGconn* PQconnectdb(const char* conninfo) {
    PGconn* c = new_conn();
    if (!c) return NULL;
    if (conninfo) parse_conninfo(c, conninfo);
    if (!c->host) c->host = strdup("localhost");
    if (!c->dbname) c->dbname = strdup("test");
    if (!c->user) c->user = strdup("admin");
    
    /* Try to connect */
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) { c->status = CONNECTION_BAD; return c; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(c->port);
    if (inet_pton(AF_INET, c->host, &addr.sin_addr) <= 0) {
        close(c->fd); c->fd = -1; c->status = CONNECTION_BAD; return c;
    }
    
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(c->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(c->fd); c->fd = -1; c->status = CONNECTION_BAD;
        c->errmsg = strdup("connection failed");
        return c;
    }
    
    c->status = CONNECTION_OK;
    return c;
}

void PQfinish(PGconn* conn) {
    if (!conn) return;
    if (conn->fd >= 0) close(conn->fd);
    free(conn->host);
    free(conn->dbname);
    free(conn->user);
    free(conn->password);
    free(conn->errmsg);
    free(conn->last_query);
    free(conn);
}

int PQstatus(const PGconn* conn) {
    return conn ? conn->status : CONNECTION_BAD;
}

char* PQerrorMessage(const PGconn* conn) {
    return conn ? (conn->errmsg ? conn->errmsg : (char*)"") : (char*)"";
}

int PQsocket(const PGconn* conn) {
    return conn ? conn->fd : -1;
}

char* PQdb(const PGconn* conn) { return conn ? conn->dbname : NULL; }
char* PQuser(const PGconn* conn) { return conn ? conn->user : NULL; }
char* PQhost(const PGconn* conn) { return conn ? conn->host : NULL; }
char* PQport(const PGconn* conn) {
    static char port_str[8];
    if (conn) { snprintf(port_str, sizeof(port_str), "%u", conn->port); return port_str; }
    return NULL;
}

PGresult* PQexec(PGconn* conn, const char* query) {
    if (!conn || !query) return new_result(PGRES_FATAL_ERROR);
    if (conn->status != CONNECTION_OK) {
        PGresult* r = new_result(PGRES_FATAL_ERROR);
        r->errmsg = strdup("not connected");
        return r;
    }
    
    free(conn->last_query);
    conn->last_query = strdup(query);
    
    /* In a real implementation, send query via PG wire protocol and parse response */
    /* For now, return empty success */
    PGresult* r = new_result(PGRES_COMMAND_OK);
    r->cmd_status = strdup("OK");
    return r;
}

PGresult* PQexecParams(PGconn* conn, const char* query, int nParams,
                       const Oid* paramTypes, const char* const* paramValues,
                       const int* paramLengths, const int* paramFormats, int resultFormat) {
    /* Simplified: just call PQexec */
    (void)nParams; (void)paramTypes; (void)paramValues;
    (void)paramLengths; (void)paramFormats; (void)resultFormat;
    return PQexec(conn, query);
}

PGresult* PQprepare(PGconn* conn, const char* stmtName, const char* query, int nParams, const Oid* paramTypes) {
    (void)stmtName; (void)nParams; (void)paramTypes;
    return PQexec(conn, query);
}

PGresult* PQexecPrepared(PGconn* conn, const char* stmtName, int nParams,
                         const char* const* paramValues, const int* paramLengths,
                         const int* paramFormats, int resultFormat) {
    (void)stmtName; (void)nParams; (void)paramValues;
    (void)paramLengths; (void)paramFormats; (void)resultFormat;
    return new_result(PGRES_COMMAND_OK);
}

ExecStatusType PQresultStatus(const PGresult* res) {
    return res ? res->status : PGRES_FATAL_ERROR;
}

char* PQresultErrorMessage(const PGresult* res) {
    return res ? (res->errmsg ? res->errmsg : (char*)"") : (char*)"";
}

int PQntuples(const PGresult* res) { return res ? res->ntuples : 0; }
int PQnfields(const PGresult* res) { return res ? res->nfields : 0; }

char* PQfname(const PGresult* res, int field_num) {
    if (!res || field_num < 0 || field_num >= res->nfields) return NULL;
    return res->field_names[field_num];
}

int PQfnumber(const PGresult* res, const char* field_name) {
    if (!res || !field_name) return -1;
    for (int i = 0; i < res->nfields; i++) {
        if (strcmp(res->field_names[i], field_name) == 0) return i;
    }
    return -1;
}

Oid PQftype(const PGresult* res, int field_num) {
    if (!res || field_num < 0 || field_num >= res->nfields) return 0;
    return res->field_types[field_num];
}

char* PQgetvalue(const PGresult* res, int tup_num, int field_num) {
    if (!res || tup_num < 0 || tup_num >= res->ntuples || field_num < 0 || field_num >= res->nfields) return NULL;
    return res->values[tup_num][field_num];
}

int PQgetisnull(const PGresult* res, int tup_num, int field_num) {
    if (!res || tup_num < 0 || tup_num >= res->ntuples || field_num < 0 || field_num >= res->nfields) return 1;
    return res->nulls[tup_num][field_num];
}

int PQgetlength(const PGresult* res, int tup_num, int field_num) {
    if (!res || tup_num < 0 || tup_num >= res->ntuples || field_num < 0 || field_num >= res->nfields) return 0;
    return res->lengths[tup_num][field_num];
}

void PQclear(PGresult* res) {
    if (!res) return;
    free(res->errmsg);
    for (int i = 0; i < res->nfields; i++) free(res->field_names[i]);
    free(res->field_names);
    free(res->field_types);
    for (int i = 0; i < res->ntuples; i++) {
        for (int j = 0; j < res->nfields; j++) free(res->values[i][j]);
        free(res->values[i]);
        free(res->nulls[i]);
        free(res->lengths[i]);
    }
    free(res->values);
    free(res->nulls);
    free(res->lengths);
    free(res->cmd_status);
    free(res->cmd_tuples);
    free(res);
}

char* PQcmdStatus(PGresult* res) { return res ? res->cmd_status : NULL; }
char* PQcmdTuples(PGresult* res) { return res ? res->cmd_tuples : NULL; }
Oid PQoidValue(const PGresult* res) { return res ? res->oid_value : 0; }

size_t PQescapeStringConn(PGconn* conn, char* to, const char* from, size_t length, int* error) {
    (void)conn;
    if (error) *error = 0;
    size_t out = 0;
    for (size_t i = 0; i < length; i++) {
        if (from[i] == '\'') { to[out++] = '\''; to[out++] = '\''; }
        else if (from[i] == '\\') { to[out++] = '\\'; to[out++] = '\\'; }
        else to[out++] = from[i];
    }
    to[out] = '\0';
    return out;
}

char* PQescapeLiteral(PGconn* conn, const char* str, size_t length) {
    (void)conn;
    /* Worst case: every char is doubled + 2 quotes + null */
    char* result = (char*)malloc(length * 2 + 3);
    if (!result) return NULL;
    size_t out = 0;
    result[out++] = '\'';
    for (size_t i = 0; i < length; i++) {
        if (str[i] == '\'') { result[out++] = '\''; result[out++] = '\''; }
        else result[out++] = str[i];
    }
    result[out++] = '\'';
    result[out] = '\0';
    return result;
}

char* PQescapeIdentifier(PGconn* conn, const char* str, size_t length) {
    (void)conn;
    char* result = (char*)malloc(length * 2 + 3);
    if (!result) return NULL;
    size_t out = 0;
    result[out++] = '"';
    for (size_t i = 0; i < length; i++) {
        if (str[i] == '"') { result[out++] = '"'; result[out++] = '"'; }
        else result[out++] = str[i];
    }
    result[out++] = '"';
    result[out] = '\0';
    return result;
}

int PQsendQuery(PGconn* conn, const char* query) {
    (void)conn; (void)query;
    return 1;
}

PGresult* PQgetResult(PGconn* conn) {
    (void)conn;
    return new_result(PGRES_COMMAND_OK);
}

int PQconsumeInput(PGconn* conn) { (void)conn; return 1; }
int PQisBusy(PGconn* conn) { (void)conn; return 0; }

PGnotify* PQnotifies(PGconn* conn) { (void)conn; return NULL; }

void PQfreemem(void* ptr) { free(ptr); }
