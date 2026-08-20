#ifndef QIHSE_PROTOCOL_TRANSLATE_H
#define QIHSE_PROTOCOL_TRANSLATE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- PostgreSQL wire -> UWP ---- */

int qihse_translate_pg_query_to_uwp(const char* sql, uint8_t* out_uwp, size_t* out_len);
int qihse_translate_pg_parse_to_uwp(const char* sql, const char** params, int num_params,
                                    uint8_t* out_uwp, size_t* out_len);
int qihse_translate_pg_begin_to_uwp(int isolation_level, uint8_t* out_uwp, size_t* out_len);
int qihse_translate_pg_commit_to_uwp(uint8_t* out_uwp, size_t* out_len);
int qihse_translate_pg_rollback_to_uwp(uint8_t* out_uwp, size_t* out_len);

/* ---- Bolt -> UWP ---- */

int qihse_translate_bolt_run_to_uwp(const char* cypher, const char* params_json,
                                    uint8_t* out_uwp, size_t* out_len);
int qihse_translate_bolt_begin_to_uwp(uint8_t* out_uwp, size_t* out_len);
int qihse_translate_bolt_commit_to_uwp(uint8_t* out_uwp, size_t* out_len);
int qihse_translate_bolt_rollback_to_uwp(uint8_t* out_uwp, size_t* out_len);

/* ---- UWP -> PostgreSQL wire result ---- */

int qihse_translate_uwp_to_pg_result(const uint8_t* uwp_response, size_t len,
                                     char*** out_columns, char*** out_rows,
                                     size_t* out_num_rows);

/* ---- UWP -> Bolt record ---- */

int qihse_translate_uwp_to_bolt_record(const uint8_t* uwp_response, size_t len,
                                       uint8_t* out_bolt, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_PROTOCOL_TRANSLATE_H */
