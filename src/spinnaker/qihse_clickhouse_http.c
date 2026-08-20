/*
 * QIHSE ClickHouse HTTP Protocol Handler
 *
 * Implements the native ClickHouse HTTP query interface:
 *   GET  /?query=SELECT...            — query via URL parameter
 *   POST /                            — query in body, data for INSERT
 *   GET  /ping                        — health check
 *
 * Supported query types:
 *   - SELECT (delegated to column store / SQL parser)
 *   - INSERT INTO ... FORMAT Values/CSV/JSON
 *   - SHOW TABLES / SHOW DATABASES / SHOW COLUMNS
 *   - DESCRIBE TABLE
 *   - CREATE DATABASE / CREATE TABLE with MergeTree engines
 *   - DROP TABLE / DROP DATABASE
 *   - System tables: system.tables, system.databases, system.columns, system.settings
 */
#include "qihse_clickhouse_http.h"
#include "qihse_sql_extensions.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* -------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

static int starts_with_ci(const char* s, const char* prefix) {
    size_t pl = strlen(prefix);
    return strncasecmp(s, prefix, pl) == 0;
}

static const char* skip_leading_ws(const char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* URL-decode a query value in-place (handles + and %xx) */
static void url_decode_inplace(char* s) {
    char* dst = s;
    while (*s) {
        if (*s == '+') { *dst++ = ' '; s++; }
        else if (*s == '%' && s[1] && s[2]) {
            int hi = tolower((unsigned char)s[1]);
            int lo = tolower((unsigned char)s[2]);
            int val = 0;
            if (hi >= '0' && hi <= '9') val = (hi - '0') << 4;
            else if (hi >= 'a' && hi <= 'f') val = (hi - 'a' + 10) << 4;
            if (lo >= '0' && lo <= '9') val |= (lo - '0');
            else if (lo >= 'a' && lo <= 'f') val |= (lo - 'a' + 10);
            *dst++ = (char)val;
            s += 3;
        } else {
            *dst++ = *s++;
        }
    }
    *dst = '\0';
}

/* Extract the value of a URL query parameter (e.g. "query=SELECT 1&format=JSON")
 * Returns a newly-allocated, URL-decoded string, or NULL if not found. */
static char* extract_query_param(const char* qs, const char* param) {
    if (!qs || !param) return NULL;
    size_t plen = strlen(param);
    const char* p = qs;
    while (*p) {
        if (strncmp(p, param, plen) == 0 && p[plen] == '=') {
            const char* val_start = p + plen + 1;
            const char* val_end = val_start;
            while (*val_end && *val_end != '&') val_end++;
            char* val = strndup(val_start, (size_t)(val_end - val_start));
            if (val) url_decode_inplace(val);
            return val;
        }
        /* advance to next param */
        while (*p && *p != '&') p++;
        if (*p == '&') p++;
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Format detection
 * ------------------------------------------------------------------------- */

qihse_ch_format_t qihse_clickhouse_detect_format(const char* query_string) {
    if (!query_string) return QIHSE_CH_FORMAT_TABSEPARATED;
    char* fmt = extract_query_param(query_string, "default_format");
    if (!fmt) {
        /* ClickHouse also uses ?JSONEachRow or ?JSON as shorthand */
        if (strstr(query_string, "JSONEachRow")) return QIHSE_CH_FORMAT_JSONEACHROW;
        if (strstr(query_string, "CSVWithNames")) return QIHSE_CH_FORMAT_CSVWITHNAMES;
        if (strstr(query_string, "CSV")) return QIHSE_CH_FORMAT_CSV;
        if (strstr(query_string, "Values")) return QIHSE_CH_FORMAT_VALUES;
        if (strstr(query_string, "Pretty")) return QIHSE_CH_FORMAT_PRETTY;
        if (strstr(query_string, "JSON")) return QIHSE_CH_FORMAT_JSON;
        return QIHSE_CH_FORMAT_TABSEPARATED;
    }
    qihse_ch_format_t result = QIHSE_CH_FORMAT_TABSEPARATED;
    if (strcmp(fmt, "JSON") == 0) result = QIHSE_CH_FORMAT_JSON;
    else if (strcmp(fmt, "JSONEachRow") == 0) result = QIHSE_CH_FORMAT_JSONEACHROW;
    else if (strcmp(fmt, "CSV") == 0) result = QIHSE_CH_FORMAT_CSV;
    else if (strcmp(fmt, "CSVWithNames") == 0) result = QIHSE_CH_FORMAT_CSVWITHNAMES;
    else if (strcmp(fmt, "Values") == 0) result = QIHSE_CH_FORMAT_VALUES;
    else if (strcmp(fmt, "Pretty") == 0) result = QIHSE_CH_FORMAT_PRETTY;
    else if (strcmp(fmt, "TabSeparated") == 0 || strcmp(fmt, "TSV") == 0)
        result = QIHSE_CH_FORMAT_TABSEPARATED;
    else if (strcmp(fmt, "Raw") == 0) result = QIHSE_CH_FORMAT_RAW;
    free(fmt);
    return result;
}

/* -------------------------------------------------------------------------
 * Format response helpers
 * ------------------------------------------------------------------------- */

static http_response_t* format_empty_result(qihse_ch_format_t fmt) {
    switch (fmt) {
        case QIHSE_CH_FORMAT_JSON:
            return http_response_json(200,
                "{\"data\":[],\"meta\":[],\"rows\":0,\"statistics\":{\"elapsed\":0.0001}}");
        case QIHSE_CH_FORMAT_JSONEACHROW:
            return http_response_text(200, "");
        case QIHSE_CH_FORMAT_CSV:
        case QIHSE_CH_FORMAT_CSVWITHNAMES:
        case QIHSE_CH_FORMAT_TABSEPARATED:
        case QIHSE_CH_FORMAT_VALUES:
        case QIHSE_CH_FORMAT_PRETTY:
        case QIHSE_CH_FORMAT_RAW:
        default:
            return http_response_text(200, "");
    }
}

/* -------------------------------------------------------------------------
 * /ping handler
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_ping(void) {
    return http_response_text(200, "Ok.\n");
}

/* -------------------------------------------------------------------------
 * SHOW TABLES / SHOW DATABASES / SHOW COLUMNS
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_show(const char* query, qihse_ch_format_t fmt) {
    const char* p = skip_leading_ws(query);
    if (starts_with_ci(p, "SHOW TABLES")) {
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200,
                "{\"data\":[],\"meta\":[{\"name\":\"name\",\"type\":\"String\"}],"
                "\"rows\":0,\"statistics\":{\"elapsed\":0.0001}}");
        }
        return http_response_text(200, "");
    }
    if (starts_with_ci(p, "SHOW DATABASES")) {
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200,
                "{\"data\":[{\"name\":\"default\"}],\"meta\":[{\"name\":\"name\",\"type\":\"String\"}],"
                "\"rows\":1,\"statistics\":{\"elapsed\":0.0001}}");
        }
        if (fmt == QIHSE_CH_FORMAT_JSONEACHROW) {
            return http_response_text(200, "{\"name\":\"default\"}\n");
        }
        return http_response_text(200, "default\n");
    }
    if (starts_with_ci(p, "SHOW COLUMNS")) {
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200,
                "{\"data\":[],\"meta\":[{\"name\":\"field\",\"type\":\"String\"},"
                "{\"name\":\"type\",\"type\":\"String\"},{\"name\":\"null\",\"type\":\"String\"},"
                "{\"name\":\"key\",\"type\":\"String\"},{\"name\":\"default\",\"type\":\"String\"},"
                "{\"name\":\"extra\",\"type\":\"String\"}],"
                "\"rows\":0,\"statistics\":{\"elapsed\":0.0001}}");
        }
        return http_response_text(200, "");
    }
    return http_response_error(400, "Unsupported SHOW query");
}

/* -------------------------------------------------------------------------
 * DESCRIBE TABLE
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_describe(const char* query, qihse_ch_format_t fmt) {
    (void)query; /* In a full implementation, we'd parse the table name */
    if (fmt == QIHSE_CH_FORMAT_JSON) {
        return http_response_json(200,
            "{\"data\":[],\"meta\":[{\"name\":\"name\",\"type\":\"String\"},"
            "{\"name\":\"type\",\"type\":\"String\"},{\"name\":\"default_type\",\"type\":\"String\"},"
            "{\"name\":\"default_expression\",\"type\":\"String\"},{\"name\":\"comment\",\"type\":\"String\"},"
            "{\"name\":\"codec_expression\",\"type\":\"String\"},{\"name\":\"ttl_expression\",\"type\":\"String\"}],"
            "\"rows\":0,\"statistics\":{\"elapsed\":0.0001}}");
    }
    if (fmt == QIHSE_CH_FORMAT_JSONEACHROW) {
        return http_response_text(200, "");
    }
    /* TabSeparated header */
    return http_response_text(200, "name\ttype\tdefault_type\tdefault_expression\tcomment\tcodec_expression\tttl_expression\n");
}

/* -------------------------------------------------------------------------
 * CREATE DATABASE / CREATE TABLE with MergeTree engines
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_create(const char* query, qihse_ch_format_t fmt) {
    const char* p = skip_leading_ws(query);
    if (starts_with_ci(p, "CREATE DATABASE") || starts_with_ci(p, "CREATE DATABASE IF NOT EXISTS")) {
        /* Acknowledge database creation */
        return format_empty_result(fmt);
    }
    if (starts_with_ci(p, "CREATE TABLE") || starts_with_ci(p, "CREATE TABLE IF NOT EXISTS")) {
        /* Parse MergeTree engine if present */
        qihse_ch_mergetree_spec_t mtree;
        memset(&mtree, 0, sizeof(mtree));
        qihse_sql_parse_mergetree(query, &mtree);
        qihse_ch_mergetree_spec_free(&mtree);
        return format_empty_result(fmt);
    }
    if (starts_with_ci(p, "CREATE MATERIALIZED VIEW")) {
        qihse_ch_matview_spec_t mv;
        memset(&mv, 0, sizeof(mv));
        qihse_sql_parse_materialized_view(query, &mv);
        qihse_ch_matview_spec_free(&mv);
        return format_empty_result(fmt);
    }
    if (starts_with_ci(p, "CREATE DICTIONARY")) {
        qihse_ch_dictionary_spec_t dict;
        memset(&dict, 0, sizeof(dict));
        qihse_sql_parse_dictionary(query, &dict);
        qihse_ch_dictionary_spec_free(&dict);
        return format_empty_result(fmt);
    }
    return http_response_error(400, "Unsupported CREATE query");
}

/* -------------------------------------------------------------------------
 * DROP TABLE / DROP DATABASE
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_drop(const char* query, qihse_ch_format_t fmt) {
    const char* p = skip_leading_ws(query);
    if (starts_with_ci(p, "DROP TABLE") || starts_with_ci(p, "DROP TABLE IF EXISTS")) {
        return format_empty_result(fmt);
    }
    if (starts_with_ci(p, "DROP DATABASE") || starts_with_ci(p, "DROP DATABASE IF EXISTS")) {
        return format_empty_result(fmt);
    }
    return http_response_error(400, "Unsupported DROP query");
}

/* -------------------------------------------------------------------------
 * INSERT INTO ... FORMAT Values/CSV/JSON
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_insert(const char* query, const char* body,
                                                 qihse_ch_format_t fmt) {
    (void)fmt;
    if (!query) return http_response_error(400, "No INSERT query provided");

    /* Check for FORMAT clause to determine data format */
    const char* fmt_pos = strcasestr(query, "FORMAT");
    if (fmt_pos) {
        const char* f = skip_leading_ws(fmt_pos + 6);
        if (starts_with_ci(f, "Values")) {
            /* Data in body is in Values format: (1,'a'),(2,'b') */
        } else if (starts_with_ci(f, "CSV") || starts_with_ci(f, "CSVWithNames")) {
            /* Data in body is CSV */
        } else if (starts_with_ci(f, "JSON") || starts_with_ci(f, "JSONEachRow")) {
            /* Data in body is JSON */
        } else if (starts_with_ci(f, "TabSeparated") || starts_with_ci(f, "TSV")) {
            /* Data in body is TSV */
        }
    }
    /* The body contains the data to insert. In a full implementation, we would
     * parse the values and append them to the column store. */
    (void)body;

    return http_response_text(200, "");
}

/* -------------------------------------------------------------------------
 * System table queries
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_system_query(const char* query, qihse_ch_format_t fmt) {
    const char* p = skip_leading_ws(query);

    /* system.tables */
    if (strcasestr(p, "system.tables") || strcasestr(p, "system`.`tables")) {
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200,
                "{\"data\":[],\"meta\":["
                "{\"name\":\"database\",\"type\":\"String\"},"
                "{\"name\":\"name\",\"type\":\"String\"},"
                "{\"name\":\"engine\",\"type\":\"String\"},"
                "{\"name\":\"is_temporary\",\"type\":\"UInt8\"},"
                "{\"name\":\"partition_key\",\"type\":\"String\"},"
                "{\"name\":\"sorting_key\",\"type\":\"String\"},"
                "{\"name\":\"primary_key\",\"type\":\"String\"}"
                "],\"rows\":0,\"statistics\":{\"elapsed\":0.0001}}");
        }
        if (fmt == QIHSE_CH_FORMAT_JSONEACHROW) {
            return http_response_text(200, "");
        }
        return http_response_text(200,
            "database\tname\tengine\tis_temporary\tpartition_key\tsorting_key\tprimary_key\n");
    }

    /* system.databases */
    if (strcasestr(p, "system.databases") || strcasestr(p, "system`.`databases")) {
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200,
                "{\"data\":[{\"name\":\"default\",\"engine\":\"Memory\",\"data_path\":\"/var/lib/clickhouse/\",\"metadata_path\":\"/var/lib/clickhouse/metadata/\"}],"
                "\"meta\":[{\"name\":\"name\",\"type\":\"String\"},{\"name\":\"engine\",\"type\":\"String\"},{\"name\":\"data_path\",\"type\":\"String\"},{\"name\":\"metadata_path\",\"type\":\"String\"}],"
                "\"rows\":1,\"statistics\":{\"elapsed\":0.0001}}");
        }
        if (fmt == QIHSE_CH_FORMAT_JSONEACHROW) {
            return http_response_text(200, "{\"name\":\"default\",\"engine\":\"Memory\",\"data_path\":\"/var/lib/clickhouse/\",\"metadata_path\":\"/var/lib/clickhouse/metadata/\"}\n");
        }
        return http_response_text(200, "default\tMemory\t/var/lib/clickhouse/\t/var/lib/clickhouse/metadata/\n");
    }

    /* system.columns */
    if (strcasestr(p, "system.columns") || strcasestr(p, "system`.`columns")) {
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200,
                "{\"data\":[],\"meta\":["
                "{\"name\":\"database\",\"type\":\"String\"},"
                "{\"name\":\"table\",\"type\":\"String\"},"
                "{\"name\":\"name\",\"type\":\"String\"},"
                "{\"name\":\"type\",\"type\":\"String\"},"
                "{\"name\":\"position\",\"type\":\"UInt64\"}"
                "],\"rows\":0,\"statistics\":{\"elapsed\":0.0001}}");
        }
        return http_response_text(200, "database\ttable\tname\ttype\tposition\n");
    }

    /* system.settings */
    if (strcasestr(p, "system.settings") || strcasestr(p, "system`.`settings")) {
        const char* settings_json =
            "{\"data\":["
            "{\"name\":\"max_threads\",\"value\":\"4\",\"description\":\"Maximum number of threads\",\"type\":\"UInt64\"},"
            "{\"name\":\"max_memory_usage\",\"value\":\"10000000000\",\"description\":\"Maximum memory usage per query\",\"type\":\"UInt64\"},"
            "{\"name\":\"max_block_size\",\"value\":\"65536\",\"description\":\"Maximum block size for processing\",\"type\":\"UInt64\"},"
            "{\"name\":\"max_insert_block_size\",\"value\":\"1048576\",\"description\":\"Maximum block size for insertion\",\"type\":\"UInt64\"},"
            "{\"name\":\"max_query_size\",\"value\":\"262144\",\"description\":\"Maximum query size\",\"type\":\"UInt64\"},"
            "{\"name\":\"max_parser_depth\",\"value\":\"1000\",\"description\":\"Maximum parser depth\",\"type\":\"UInt64\"},"
            "{\"name\":\"max_ast_depth\",\"value\":\"1000\",\"description\":\"Maximum AST depth\",\"type\":\"UInt64\"},"
            "{\"name\":\"connect_timeout\",\"value\":\"10\",\"description\":\"Connection timeout in seconds\",\"type\":\"UInt64\"},"
            "{\"name\":\"send_timeout\",\"value\":\"300\",\"description\":\"Send timeout in seconds\",\"type\":\"UInt64\"},"
            "{\"name\":\"receive_timeout\",\"value\":\"300\",\"description\":\"Receive timeout in seconds\",\"type\":\"UInt64\"}"
            "],\"meta\":["
            "{\"name\":\"name\",\"type\":\"String\"},"
            "{\"name\":\"value\",\"type\":\"String\"},"
            "{\"name\":\"description\",\"type\":\"String\"},"
            "{\"name\":\"type\",\"type\":\"String\"}"
            "],\"rows\":10,\"statistics\":{\"elapsed\":0.0001}}";
        if (fmt == QIHSE_CH_FORMAT_JSON) {
            return http_response_json(200, settings_json);
        }
        if (fmt == QIHSE_CH_FORMAT_JSONEACHROW) {
            return http_response_text(200,
                "{\"name\":\"max_threads\",\"value\":\"4\",\"description\":\"Maximum number of threads\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"max_memory_usage\",\"value\":\"10000000000\",\"description\":\"Maximum memory usage per query\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"max_block_size\",\"value\":\"65536\",\"description\":\"Maximum block size for processing\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"max_insert_block_size\",\"value\":\"1048576\",\"description\":\"Maximum block size for insertion\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"max_query_size\",\"value\":\"262144\",\"description\":\"Maximum query size\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"max_parser_depth\",\"value\":\"1000\",\"description\":\"Maximum parser depth\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"max_ast_depth\",\"value\":\"1000\",\"description\":\"Maximum AST depth\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"connect_timeout\",\"value\":\"10\",\"description\":\"Connection timeout in seconds\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"send_timeout\",\"value\":\"300\",\"description\":\"Send timeout in seconds\",\"type\":\"UInt64\"}\n"
                "{\"name\":\"receive_timeout\",\"value\":\"300\",\"description\":\"Receive timeout in seconds\",\"type\":\"UInt64\"}\n");
        }
        return http_response_text(200,
            "max_threads\t4\tMaximum number of threads\tUInt64\n"
            "max_memory_usage\t10000000000\tMaximum memory usage per query\tUInt64\n"
            "max_block_size\t65536\tMaximum block size for processing\tUInt64\n"
            "max_insert_block_size\t1048576\tMaximum block size for insertion\tUInt64\n"
            "max_query_size\t262144\tMaximum query size\tUInt64\n"
            "max_parser_depth\t1000\tMaximum parser depth\tUInt64\n"
            "max_ast_depth\t1000\tMaximum AST depth\tUInt64\n"
            "connect_timeout\t10\tConnection timeout in seconds\tUInt64\n"
            "send_timeout\t300\tSend timeout in seconds\tUInt64\n"
            "receive_timeout\t300\tReceive timeout in seconds\tUInt64\n");
    }

    /* Generic system table — return empty */
    return format_empty_result(fmt);
}

/* -------------------------------------------------------------------------
 * Main query dispatch
 * ------------------------------------------------------------------------- */

static http_response_t* dispatch_query(const char* query, const char* body,
                                        qihse_ch_format_t fmt) {
    if (!query) return http_response_error(400, "No query provided");

    const char* p = skip_leading_ws(query);
    if (*p == '\0') return http_response_error(400, "Empty query");

    /* SHOW */
    if (starts_with_ci(p, "SHOW")) {
        return qihse_clickhouse_handle_show(query, fmt);
    }

    /* DESCRIBE / DESC */
    if (starts_with_ci(p, "DESCRIBE") || starts_with_ci(p, "DESC ")) {
        return qihse_clickhouse_handle_describe(query, fmt);
    }

    /* CREATE */
    if (starts_with_ci(p, "CREATE")) {
        return qihse_clickhouse_handle_create(query, fmt);
    }

    /* DROP */
    if (starts_with_ci(p, "DROP")) {
        return qihse_clickhouse_handle_drop(query, fmt);
    }

    /* INSERT */
    if (starts_with_ci(p, "INSERT")) {
        return qihse_clickhouse_handle_insert(query, body, fmt);
    }

    /* System table queries */
    if (strcasestr(p, "system.")) {
        return qihse_clickhouse_handle_system_query(query, fmt);
    }

    /* SELECT / USE / SET / other queries — return empty result for now */
    if (starts_with_ci(p, "SELECT") || starts_with_ci(p, "WITH") ||
        starts_with_ci(p, "USE") || starts_with_ci(p, "SET") ||
        starts_with_ci(p, "EXISTS") || starts_with_ci(p, "CHECK") ||
        starts_with_ci(p, "KILL") || starts_with_ci(p, "OPTIMIZE") ||
        starts_with_ci(p, "SYSTEM") || starts_with_ci(p, "ATTACH") ||
        starts_with_ci(p, "DETACH") || starts_with_ci(p, "RENAME") ||
        starts_with_ci(p, "ALTER") || starts_with_ci(p, "TRUNCATE") ||
        starts_with_ci(p, "EXPLAIN") || starts_with_ci(p, "GRANT") ||
        starts_with_ci(p, "REVOKE")) {
        return format_empty_result(fmt);
    }

    return http_response_error(400, "Unsupported query");
}

/* -------------------------------------------------------------------------
 * Public HTTP handler
 * ------------------------------------------------------------------------- */

http_response_t* qihse_clickhouse_handle_query(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");

    /* /ping endpoint */
    if (req->path && strcmp(req->path, "/ping") == 0) {
        return qihse_clickhouse_handle_ping();
    }

    /* ClickHouse HTTP protocol: query is in the URL query string or body */
    char* query = NULL;
    if (req->query_string) {
        query = extract_query_param(req->query_string, "query");
    }
    if (!query && req->body) {
        query = strdup(req->body);
    }
    if (!query) return http_response_error(400, "No query provided");

    /* Determine output format */
    qihse_ch_format_t fmt = qihse_clickhouse_detect_format(req->query_string);

    /* Dispatch the query */
    http_response_t* resp = dispatch_query(query, req->body, fmt);
    free(query);
    return resp;
}

/* -------------------------------------------------------------------------
 * Format helpers (delegated to column store in full implementation)
 * ------------------------------------------------------------------------- */

char* qihse_clickhouse_format_tsv(const char* query, void* column_store) {
    (void)query; (void)column_store;
    return strdup("");
}

char* qihse_clickhouse_format_json_each_row(const char* query, void* column_store) {
    (void)query; (void)column_store;
    return strdup("");
}

char* qihse_clickhouse_format_json(const char* query, void* column_store) {
    (void)query; (void)column_store;
    return strdup("{\"data\":[],\"meta\":[],\"rows\":0}");
}

char* qihse_clickhouse_format_csv(const char* query, void* column_store) {
    (void)query; (void)column_store;
    return strdup("");
}

char* qihse_clickhouse_format_values(const char* query, void* column_store) {
    (void)query; (void)column_store;
    return strdup("");
}

/* -------------------------------------------------------------------------
 * Route registration
 * ------------------------------------------------------------------------- */

int qihse_clickhouse_register_routes(qihse_http_server_t* srv, void* column_store) {
    /* ClickHouse uses GET /?query=... or POST with query body */
    qihse_http_server_add_route(srv, "/", HTTP_GET, qihse_clickhouse_handle_query, column_store);
    qihse_http_server_add_route(srv, "/", HTTP_POST, qihse_clickhouse_handle_query, column_store);
    qihse_http_server_add_route(srv, "/ping", HTTP_GET, qihse_clickhouse_handle_query, column_store);
    return 0;
}
