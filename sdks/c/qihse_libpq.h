#ifndef QIHSE_LIBPQ_H
#define QIHSE_LIBPQ_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Types */
typedef uint32_t Oid;
typedef struct qihse_pgconn_s PGconn;
typedef struct qihse_pgresult_s PGresult;
typedef struct { char* relname; int be_pid; char* extra; } PGnotify;

/* Connection status */
enum {
    CONNECTION_OK = 0,
    CONNECTION_BAD = 1,
    CONNECTION_STARTED = 2,
    CONNECTION_MADE = 3,
    CONNECTION_AWAITING_RESPONSE = 4,
    CONNECTION_AUTH_OK = 5,
    CONNECTION_SETENV = 6
};

/* Exec status */
typedef enum {
    PGRES_EMPTY_QUERY = 0,
    PGRES_COMMAND_OK = 1,
    PGRES_TUPLES_OK = 2,
    PGRES_COPY_OUT = 3,
    PGRES_COPY_IN = 4,
    PGRES_BAD_RESPONSE = 5,
    PGRES_FATAL_ERROR = 6,
    PGRES_NONFATAL_ERROR = 7,
    PGRES_COPY_BOTH = 8,
    PGRES_SINGLE_TUPLE = 9
} ExecStatusType;

/* Connection */
PGconn* PQconnectdb(const char* conninfo);
void PQfinish(PGconn* conn);
int PQstatus(const PGconn* conn);
char* PQerrorMessage(const PGconn* conn);
int PQsocket(const PGconn* conn);
char* PQdb(const PGconn* conn);
char* PQuser(const PGconn* conn);
char* PQhost(const PGconn* conn);
char* PQport(const PGconn* conn);

/* Query execution */
PGresult* PQexec(PGconn* conn, const char* query);
PGresult* PQexecParams(PGconn* conn, const char* query, int nParams,
                       const Oid* paramTypes, const char* const* paramValues,
                       const int* paramLengths, const int* paramFormats, int resultFormat);
PGresult* PQprepare(PGconn* conn, const char* stmtName, const char* query, int nParams, const Oid* paramTypes);
PGresult* PQexecPrepared(PGconn* conn, const char* stmtName, int nParams,
                         const char* const* paramValues, const int* paramLengths,
                         const int* paramFormats, int resultFormat);

/* Result access */
ExecStatusType PQresultStatus(const PGresult* res);
char* PQresultErrorMessage(const PGresult* res);
int PQntuples(const PGresult* res);
int PQnfields(const PGresult* res);
char* PQfname(const PGresult* res, int field_num);
int PQfnumber(const PGresult* res, const char* field_name);
Oid PQftype(const PGresult* res, int field_num);
char* PQgetvalue(const PGresult* res, int tup_num, int field_num);
int PQgetisnull(const PGresult* res, int tup_num, int field_num);
int PQgetlength(const PGresult* res, int tup_num, int field_num);
void PQclear(PGresult* res);
char* PQcmdStatus(PGresult* res);
char* PQcmdTuples(PGresult* res);
Oid PQoidValue(const PGresult* res);

/* Escaping */
size_t PQescapeStringConn(PGconn* conn, char* to, const char* from, size_t length, int* error);
char* PQescapeLiteral(PGconn* conn, const char* str, size_t length);
char* PQescapeIdentifier(PGconn* conn, const char* str, size_t length);

/* Async */
int PQsendQuery(PGconn* conn, const char* query);
PGresult* PQgetResult(PGconn* conn);
int PQconsumeInput(PGconn* conn);
int PQisBusy(PGconn* conn);
PGnotify* PQnotifies(PGconn* conn);
void PQfreemem(void* ptr);

#ifdef __cplusplus
}
#endif
#endif
