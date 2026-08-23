#include "qihse_protocol_translate.h"
#include "qihse_uwp.h"
#include "qihse_bolt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <endian.h>
#else
#define htole64(x) (x)
#define le64toh(x) (x)
#endif

/* ============================================================
 * Internal UWP packet builder
 * ============================================================ */

static int build_uwp(uint8_t* out, size_t* out_len, size_t out_cap,
                     uint8_t target, uint8_t command,
                     const uint8_t* payload, size_t payload_len) {
    size_t total = sizeof(qihse_uwp_header_t) + payload_len;
    if (out_len) *out_len = total;
    if (!out || total > out_cap) return -1;
    qihse_uwp_header_t hdr;
    static const uint8_t uwp_magic[4] = { 0x51, 0x49, 0x48, 0x53 };
    memcpy(hdr.magic, uwp_magic, sizeof(hdr.magic));
    hdr.version = 0x01;
    hdr.target_engine = target;
    hdr.command_opcode = command;
    hdr.payload_length = htole64((uint64_t)payload_len);
    memcpy(out, &hdr, sizeof(hdr));
    if (payload_len) memcpy(out + sizeof(hdr), payload, payload_len);
    return 0;
}

static uint64_t uwp_payload_length(const qihse_uwp_header_t* header) {
    uint64_t wire_length;
    memcpy(&wire_length, &header->payload_length, sizeof(wire_length));
    return le64toh(wire_length);
}

/* ============================================================
 * PostgreSQL wire -> UWP
 * ============================================================ */

int qihse_translate_pg_query_to_uwp(const char* sql, uint8_t* out_uwp, size_t out_cap,
                                    size_t* out_len) {
    if (!sql) return -1;
    size_t slen = strlen(sql);
    /* SQL EXECUTE (target 0x08, command 0x02): payload = SQL text */
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_SQL, 0x02,
                     (const uint8_t*)sql, slen);
}

int qihse_translate_pg_parse_to_uwp(const char* sql, const char** params, int num_params,
                                    uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    if (!sql) return -1;
    (void)params; (void)num_params;
    size_t slen = strlen(sql);
    /* SQL PARSE (target 0x08, command 0x01): payload = SQL text */
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_SQL, 0x01,
                     (const uint8_t*)sql, slen);
}

int qihse_translate_pg_begin_to_uwp(int isolation_level, uint8_t* out_uwp, size_t out_cap,
                                    size_t* out_len) {
    /* TXN BEGIN (target 0x09, command 0x01): payload = 1-byte isolation level */
    uint8_t iso = (uint8_t)isolation_level;
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_TXN, 0x01, &iso, 1);
}

int qihse_translate_pg_commit_to_uwp(uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_TXN, 0x02, NULL, 0);
}

int qihse_translate_pg_rollback_to_uwp(uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_TXN, 0x03, NULL, 0);
}

/* ============================================================
 * Bolt -> UWP
 * ============================================================ */

/* Determine the graph command opcode from a Cypher keyword. */
static uint8_t cypher_to_graph_command(const char* cypher) {
    if (!cypher) return 0x01; /* MATCH default */
    /* skip leading whitespace */
    while (*cypher == ' ' || *cypher == '\t' || *cypher == '\n') cypher++;
    if (strncasecmp(cypher, "MATCH", 5) == 0) return 0x01;
    if (strncasecmp(cypher, "CREATE", 6) == 0) return 0x02;
    if (strncasecmp(cypher, "MERGE", 5) == 0) return 0x03;
    if (strncasecmp(cypher, "DELETE", 6) == 0) return 0x04;
    if (strncasecmp(cypher, "SET", 3) == 0) return 0x05;
    if (strncasecmp(cypher, "REMOVE", 6) == 0) return 0x06;
    if (strncasecmp(cypher, "CALL", 4) == 0) return 0x10; /* algo */
    return 0x01;
}

int qihse_translate_bolt_run_to_uwp(const char* cypher, const char* params_json,
                                    uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    if (!cypher) return -1;
    uint8_t cmd = cypher_to_graph_command(cypher);
    size_t clen = strlen(cypher);
    size_t plen = clen;
    if (params_json) plen += 1 + strlen(params_json); /* cypher\0params */
    uint8_t* payload = (uint8_t*)malloc(plen + 1);
    if (!payload) return -1;
    memcpy(payload, cypher, clen);
    if (params_json) {
        payload[clen] = 0;
        memcpy(payload + clen + 1, params_json, strlen(params_json));
    }
    int rc = build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_GRAPH2, cmd, payload, plen);
    free(payload);
    return rc;
}

int qihse_translate_bolt_begin_to_uwp(uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_TXN, 0x01, NULL, 0);
}

int qihse_translate_bolt_commit_to_uwp(uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_TXN, 0x02, NULL, 0);
}

int qihse_translate_bolt_rollback_to_uwp(uint8_t* out_uwp, size_t out_cap, size_t* out_len) {
    return build_uwp(out_uwp, out_len, out_cap, QIHSE_UWP_TARGET_TXN, 0x03, NULL, 0);
}

/* ============================================================
 * UWP -> PostgreSQL wire result
 * ============================================================ */

int qihse_translate_uwp_to_pg_result(const uint8_t* uwp_response, size_t len,
                                     char*** out_columns, char*** out_rows,
                                     size_t* out_num_rows) {
    if (!uwp_response || len < sizeof(qihse_uwp_header_t)) return -1;
    const qihse_uwp_header_t* hdr = (const qihse_uwp_header_t*)uwp_response;
    static const uint8_t uwp_magic[4] = { 0x51, 0x49, 0x48, 0x53 };
    if (memcmp(hdr->magic, uwp_magic, sizeof(hdr->magic)) != 0) return -1;
    uint64_t payload_len = uwp_payload_length(hdr);
    const uint8_t* payload = uwp_response + sizeof(qihse_uwp_header_t);
    if (sizeof(qihse_uwp_header_t) + payload_len > len) return -1;

    /* Default: one column "result", one row containing the payload text */
    char** cols = (char**)malloc(sizeof(char*));
    if (!cols) return -1;
    cols[0] = strdup("result");

    /* Interpret payload as a null-terminated string row if possible */
    size_t nrows = 0;
    char** rows = (char**)malloc(sizeof(char*));
    if (!rows) { free(cols[0]); free(cols); return -1; }
    if (payload_len > 0) {
        rows[0] = strndup((const char*)payload, payload_len);
        nrows = 1;
    } else {
        rows[0] = strdup("OK");
        nrows = 1;
    }

    if (out_columns) *out_columns = cols; else { free(cols[0]); free(cols); }
    if (out_rows) *out_rows = rows; else { free(rows[0]); free(rows); }
    if (out_num_rows) *out_num_rows = nrows;
    return 0;
}

/* ============================================================
 * UWP -> Bolt record
 * ============================================================ */

int qihse_translate_uwp_to_bolt_record(const uint8_t* uwp_response, size_t len,
                                       uint8_t* out_bolt, size_t* out_len) {
    if (!uwp_response || len < sizeof(qihse_uwp_header_t)) return -1;
    const qihse_uwp_header_t* hdr = (const qihse_uwp_header_t*)uwp_response;
    static const uint8_t uwp_magic[4] = { 0x51, 0x49, 0x48, 0x53 };
    if (memcmp(hdr->magic, uwp_magic, sizeof(hdr->magic)) != 0) return -1;
    uint64_t payload_len = uwp_payload_length(hdr);
    const uint8_t* payload = uwp_response + sizeof(qihse_uwp_header_t);
    if (sizeof(qihse_uwp_header_t) + payload_len > len) return -1;

    /* Build a Bolt RECORD message containing a single string field. */
    qihse_bolt_buf_t body;
    qihse_bolt_buf_init(&body, 64);
    qihse_bolt_encode_list_begin(&body, 1);
    char tmp[256];
    if (payload_len > 0) {
        snprintf(tmp, sizeof(tmp), "%.*s", (int)(payload_len < 255 ? payload_len : 255),
                 (const char*)payload);
    } else {
        snprintf(tmp, sizeof(tmp), "OK");
    }
    qihse_bolt_encode_string(&body, tmp);

    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, body.len + 4);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_RECORD, body.buf, body.len);

    if (out_bolt && msg.len <= 4096) {
        memcpy(out_bolt, msg.buf, msg.len);
        if (out_len) *out_len = msg.len;
    } else if (out_len) {
        *out_len = msg.len;
    }
    qihse_bolt_buf_free(&body);
    qihse_bolt_buf_free(&msg);
    return 0;
}
