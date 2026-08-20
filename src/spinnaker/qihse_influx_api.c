#include "qihse_influx_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Internal data structures                                            */
/* ------------------------------------------------------------------ */

#define QIHSE_INFLUX_MAX_TAGS   16
#define QIHSE_INFLUX_MAX_FIELDS 32
#define QIHSE_INFLUX_NAME_LEN   128

typedef struct {
    char key[QIHSE_INFLUX_NAME_LEN];
    char value[QIHSE_INFLUX_NAME_LEN];
} influx_kv_t;

typedef struct {
    char measurement[QIHSE_INFLUX_NAME_LEN];
    influx_kv_t tags[QIHSE_INFLUX_MAX_TAGS];
    size_t num_tags;
    influx_kv_t fields[QIHSE_INFLUX_MAX_FIELDS];
    size_t num_fields;
    uint64_t timestamp_ns;
    int has_timestamp;
} influx_line_point_t;

typedef enum {
    INFLUX_STMT_SELECT,
    INFLUX_STMT_SHOW,
    INFLUX_STMT_CREATE,
    INFLUX_STMT_DROP,
    INFLUX_STMT_INSERT
} influx_stmt_type_t;

typedef enum {
    INFLUX_AGG_NONE = 0,
    INFLUX_AGG_MEAN,
    INFLUX_AGG_SUM,
    INFLUX_AGG_MIN,
    INFLUX_AGG_MAX,
    INFLUX_AGG_COUNT
} influx_agg_t;

typedef struct {
    influx_stmt_type_t type;
    char measurement[QIHSE_INFLUX_NAME_LEN];
    char field[QIHSE_INFLUX_NAME_LEN];
    influx_agg_t aggregation;
    uint64_t start_ts_ns;
    uint64_t end_ts_ns;
    int has_time_range;
    uint64_t group_by_ns;
    int has_group_by;
    /* SHOW sub-type */
    char show_what[32];
    /* CREATE/DROP target */
    char target_name[QIHSE_INFLUX_NAME_LEN];
} influx_stmt_t;

/* ------------------------------------------------------------------ */
/* Small helper utilities                                             */
/* ------------------------------------------------------------------ */

static char* trim(char* s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) { end--; *end = '\0'; }
    return s;
}

/* FNV-1a 32-bit hash used to derive a stable series_id from the
 * measurement + tag set so that line-protocol writes and InfluxQL
 * SELECTs target the same underlying series. */
static uint32_t fnv1a32(const char* s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 16777619u;
    }
    return h ? h : 1u;
}

static uint32_t series_id_for(const influx_line_point_t* pt) {
    char buf[1024];
    int off = snprintf(buf, sizeof(buf), "%s", pt->measurement);
    for (size_t i = 0; i < pt->num_tags && off < (int)sizeof(buf); i++) {
        off += snprintf(buf + off, sizeof(buf) - off, ",%s=%s",
                        pt->tags[i].key, pt->tags[i].value);
    }
    return fnv1a32(buf);
}

/* Current wall-clock time in nanoseconds since epoch. */
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Parse a duration literal such as "1h", "10m", "30s", "1d", "1w".
 * Returns the duration in nanoseconds, or 0 on parse failure. */
static uint64_t parse_duration_ns(const char* s) {
    if (!s || !*s) return 0;
    char* end = NULL;
    double n = strtod(s, &end);
    if (end == s) return 0;
    while (*end && isspace((unsigned char)*end)) end++;
    if (!*end) return 0;
    uint64_t mult = 0;
    switch (*end) {
        case 'n': mult = 1; break;             /* nanoseconds */
        case 'u': mult = 1000; break;          /* microseconds */
        case 'm':
            if (end[1] == 's') mult = 1000000;  /* milliseconds */
            else mult = 1000000000ull * 60;     /* minutes */
            break;
        case 's': mult = 1000000000ull; break;  /* seconds */
        case 'h': mult = 1000000000ull * 3600; break;
        case 'd': mult = 1000000000ull * 86400; break;
        case 'w': mult = 1000000000ull * 86400 * 7; break;
        default: return 0;
    }
    return (uint64_t)(n * (double)mult);
}

/* Parse a timestamp token. Supports nanosecond integers as well as
 * RFC3339-ish dates; here we focus on the ns integer form used by the
 * line protocol and InfluxQL epoch literals. */
static uint64_t parse_timestamp_ns(const char* s) {
    if (!s || !*s) return 0;
    return (uint64_t)strtoull(s, NULL, 10);
}

/* ------------------------------------------------------------------ */
/* Line protocol parser                                               */
/* ------------------------------------------------------------------ */

/* Split a writable string on the first occurrence of `sep`, NUL-terminating
 * the left side and returning a pointer to the right side (or NULL). */
static char* split_first(char* s, char sep) {
    char* p = s ? strchr(s, sep) : NULL;
    if (!p) return NULL;
    *p = '\0';
    return p + 1;
}

static int parse_kv_pair(const char* kv, influx_kv_t* out) {
    const char* eq = strchr(kv, '=');
    if (!eq) return -1;
    size_t klen = (size_t)(eq - kv);
    if (klen >= QIHSE_INFLUX_NAME_LEN) klen = QIHSE_INFLUX_NAME_LEN - 1;
    memcpy(out->key, kv, klen);
    out->key[klen] = '\0';
    const char* v = eq + 1;
    /* Strip surrounding quotes for string fields */
    if (*v == '"') {
        const char* close = strchr(v + 1, '"');
        if (close) {
            size_t vlen = (size_t)(close - (v + 1));
            if (vlen >= QIHSE_INFLUX_NAME_LEN) vlen = QIHSE_INFLUX_NAME_LEN - 1;
            memcpy(out->value, v + 1, vlen);
            out->value[vlen] = '\0';
            return 0;
        }
    }
    snprintf(out->value, sizeof(out->value), "%s", v);
    return 0;
}

/* Parse a single line-protocol line into a point.
 * Format: measurement,tag1=val1,tag2=val2 field1=0.5,field2=1i 1434055562005000000
 * Returns 0 on success, -1 on parse error. */
static int influx_parse_line(char* line, influx_line_point_t* pt) {
    memset(pt, 0, sizeof(*pt));
    line = trim(line);
    if (!*line || *line == '#') return -1; /* empty or comment */

    /* Split tags section from fields section on first unquoted space. */
    char* tags_part = line;
    char* fields_part = NULL;
    char* p = line;
    int in_quotes = 0;
    for (; *p; p++) {
        if (*p == '"') in_quotes = !in_quotes;
        else if (!in_quotes && isspace((unsigned char)*p)) {
            *p = '\0';
            fields_part = p + 1;
            break;
        }
    }
    if (!fields_part) return -1;

    /* Optional timestamp after the fields section. */
    char* ts_part = NULL;
    in_quotes = 0;
    for (p = fields_part; *p; p++) {
        if (*p == '"') in_quotes = !in_quotes;
        else if (!in_quotes && isspace((unsigned char)*p)) {
            *p = '\0';
            ts_part = p + 1;
            break;
        }
    }

    /* Parse measurement + tags from tags_part. */
    char* measurement = split_first(tags_part, ',');
    if (measurement) {
        /* tags_part now holds just the measurement */
    }
    snprintf(pt->measurement, sizeof(pt->measurement), "%s", tags_part);
    if (pt->measurement[0] == '\0') return -1;

    while (measurement && *measurement) {
        char* next = split_first(measurement, ',');
        if (*measurement && pt->num_tags < QIHSE_INFLUX_MAX_TAGS) {
            if (parse_kv_pair(measurement, &pt->tags[pt->num_tags]) == 0)
                pt->num_tags++;
        }
        measurement = next;
    }

    /* Parse fields. */
    char* field = fields_part;
    while (field && *field) {
        char* next = split_first(field, ',');
        if (*field && pt->num_fields < QIHSE_INFLUX_MAX_FIELDS) {
            if (parse_kv_pair(field, &pt->fields[pt->num_fields]) == 0)
                pt->num_fields++;
        }
        field = next;
    }
    if (pt->num_fields == 0) return -1;

    /* Parse timestamp. */
    if (ts_part) {
        ts_part = trim(ts_part);
        if (*ts_part) {
            pt->timestamp_ns = parse_timestamp_ns(ts_part);
            pt->has_timestamp = 1;
        }
    }
    if (!pt->has_timestamp || pt->timestamp_ns == 0)
        pt->timestamp_ns = now_ns();

    return 0;
}

/* Extract the first numeric field value from a point. InfluxDB line
 * protocol may carry integer (suffix 'i'), unsigned ('u'), float, or
 * boolean fields; we coerce the first numeric one to a double for the
 * QIHSE single-value timeseries engine. */
static int first_numeric_field(const influx_line_point_t* pt, double* out) {
    for (size_t i = 0; i < pt->num_fields; i++) {
        const char* v = pt->fields[i].value;
        if (*v == '"') continue;            /* skip string fields */
        if (*v == 't' || *v == 'f' || *v == 'T' || *v == 'F') {
            *out = (*v == 't' || *v == 'T') ? 1.0 : 0.0;
            return 0;
        }
        char* end = NULL;
        double d = strtod(v, &end);
        if (end != v) {
            /* allow trailing type suffixes (i, u) */
            *out = d;
            return 0;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* InfluxQL parser                                                    */
/* ------------------------------------------------------------------ */

/* Case-insensitive prefix check that consumes the keyword and returns a
 * pointer past it (with following whitespace skipped), or NULL. */
static char* match_keyword(char* s, const char* kw) {
    size_t klen = strlen(kw);
    if (strncasecmp(s, kw, klen) != 0) return NULL;
    char* p = s + klen;
    if (*p && !isspace((unsigned char)*p)) return NULL;
    return trim(p);
}

/* Parse the time predicate "time > now() - 1h" / "time < 1234" out of a
 * WHERE clause. Sets start_ts_ns/end_ts_ns and has_time_range on success. */
static void parse_time_predicate(const char* where, influx_stmt_t* stmt) {
    if (!where) return;
    const char* p = strcasestr(where, "time");
    if (!p) return;
    p += 4;
    while (*p && (*p == ' ' || *p == '\t')) p++;
    /* operator: >, >=, <, <=, = */
    int op_gt = 0, op_lt = 0;
    if (*p == '>') { op_gt = 1; p++; if (*p == '=') { p++; } }
    else if (*p == '<') { op_lt = 1; p++; if (*p == '=') { p++; } }
    else if (*p == '=') { p++; }
    else return;
    while (*p && (*p == ' ' || *p == '\t')) p++;

    uint64_t ts = 0;
    int is_now = (strncasecmp(p, "now()", 6) == 0);
    if (is_now) {
        p += 6;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (*p == '-') {
            p++;
            while (*p && (*p == ' ' || *p == '\t')) p++;
            char dur[64];
            size_t i = 0;
            while (*p && !isspace((unsigned char)*p) && *p != ')' && i < sizeof(dur) - 1)
                dur[i++] = *p++;
            dur[i] = '\0';
            uint64_t d = parse_duration_ns(dur);
            ts = now_ns() - d;
        } else if (*p == '+') {
            p++;
            while (*p && (*p == ' ' || *p == '\t')) p++;
            char dur[64];
            size_t i = 0;
            while (*p && !isspace((unsigned char)*p) && *p != ')' && i < sizeof(dur) - 1)
                dur[i++] = *p++;
            dur[i] = '\0';
            ts = now_ns() + parse_duration_ns(dur);
        } else {
            ts = now_ns();
        }
    } else {
        ts = parse_timestamp_ns(p);
    }

    stmt->has_time_range = 1;
    if (op_gt) {
        stmt->start_ts_ns = ts;
        if (!stmt->end_ts_ns) stmt->end_ts_ns = now_ns();
    } else if (op_lt) {
        stmt->end_ts_ns = ts;
        if (!stmt->start_ts_ns) stmt->start_ts_ns = 0;
    } else { /* equality predicate */
        stmt->start_ts_ns = ts;
        stmt->end_ts_ns = ts;
    }
}

/* Parse "GROUP BY time(10m)" -> group_by_ns. */
static void parse_group_by(const char* sql, influx_stmt_t* stmt) {
    const char* p = strcasestr(sql, "group by");
    if (!p) return;
    p += 8;
    const char* tb = strcasestr(p, "time(");
    if (!tb) return;
    tb += 5;
    char dur[64];
    size_t i = 0;
    while (*tb && *tb != ')' && i < sizeof(dur) - 1) dur[i++] = *tb++;
    dur[i] = '\0';
    uint64_t d = parse_duration_ns(dur);
    if (d) { stmt->group_by_ns = d; stmt->has_group_by = 1; }
}

/* Map an aggregation function name to the influx_agg_t enum. */
static influx_agg_t parse_agg(const char* name) {
    if (strcasecmp(name, "mean") == 0 || strcasecmp(name, "avg") == 0) return INFLUX_AGG_MEAN;
    if (strcasecmp(name, "sum") == 0) return INFLUX_AGG_SUM;
    if (strcasecmp(name, "min") == 0) return INFLUX_AGG_MIN;
    if (strcasecmp(name, "max") == 0) return INFLUX_AGG_MAX;
    if (strcasecmp(name, "count") == 0) return INFLUX_AGG_COUNT;
    return INFLUX_AGG_NONE;
}

/* Parse a single InfluxQL statement into influx_stmt_t.
 * Returns 0 on success, -1 on parse error. The input buffer is modified. */
static int influx_parse_query(char* sql, influx_stmt_t* stmt) {
    memset(stmt, 0, sizeof(*stmt));
    sql = trim(sql);
    if (!*sql) return -1;

    /* SELECT ... */
    char* p = match_keyword(sql, "SELECT");
    if (p) {
        stmt->type = INFLUX_STMT_SELECT;
        /* Parse the select-list (field or agg(field)). */
        char* from = strcasestr(p, "FROM");
        if (!from) return -1;
        *from = '\0';
        char* sel = trim(p);
        /* Check for aggregation: name(field) */
        char* lp = strchr(sel, '(');
        if (lp) {
            *lp = '\0';
            stmt->aggregation = parse_agg(trim(sel));
            char* rp = strchr(lp + 1, ')');
            if (rp) *rp = '\0';
            snprintf(stmt->field, sizeof(stmt->field), "%s", trim(lp + 1));
        } else {
            snprintf(stmt->field, sizeof(stmt->field), "%s", sel);
        }
        /* Measurement after FROM. */
        char* rest = trim(from + 4);
        /* Strip optional quotes / aliases. */
        char* sp = strcasestr(rest, "WHERE");
        if (sp) { *sp = '\0'; }
        char* gb = strcasestr(rest, "GROUP");
        if (gb) { *gb = '\0'; }
        snprintf(stmt->measurement, sizeof(stmt->measurement), "%s", trim(rest));
        /* WHERE clause. */
        char* where = strcasestr(from + 4, "WHERE");
        if (where) {
            where += 5;
            char* gb2 = strcasestr(where, "GROUP");
            if (gb2) *gb2 = '\0';
            char* where_copy = strdup(where);
            if (where_copy) {
                parse_time_predicate(where_copy, stmt);
                free(where_copy);
            }
        }
        parse_group_by(from + 4, stmt);
        return 0;
    }

    /* SHOW ... */
    p = match_keyword(sql, "SHOW");
    if (p) {
        stmt->type = INFLUX_STMT_SHOW;
        char* sp = strchr(p, ' ');
        if (sp) {
            size_t wlen = (size_t)(sp - p);
            if (wlen >= sizeof(stmt->show_what)) wlen = sizeof(stmt->show_what) - 1;
            memcpy(stmt->show_what, p, wlen);
            stmt->show_what[wlen] = '\0';
        } else {
            snprintf(stmt->show_what, sizeof(stmt->show_what), "%s", p);
        }
        /* Optional "FROM measurement" */
        char* f = strcasestr(p, "FROM");
        if (f) {
            f += 4;
            char* end = f + strlen(f);
            char* w = strcasestr(f, "WHERE");
            if (w) end = w;
            size_t mlen = (size_t)(end - f);
            if (mlen >= sizeof(stmt->measurement)) mlen = sizeof(stmt->measurement) - 1;
            memcpy(stmt->measurement, f, mlen);
            stmt->measurement[mlen] = '\0';
            trim(stmt->measurement);
        }
        return 0;
    }

    /* CREATE DATABASE name */
    p = match_keyword(sql, "CREATE");
    if (p) {
        stmt->type = INFLUX_STMT_CREATE;
        char* db = strcasestr(p, "DATABASE");
        if (!db) return -1;
        db += 8;
        snprintf(stmt->target_name, sizeof(stmt->target_name), "%s", trim(db));
        return 0;
    }

    /* DROP DATABASE name / DROP MEASUREMENT name */
    p = match_keyword(sql, "DROP");
    if (p) {
        stmt->type = INFLUX_STMT_DROP;
        char* db = strcasestr(p, "DATABASE");
        char* ms = strcasestr(p, "MEASUREMENT");
        if (db) {
            db += 8;
            snprintf(stmt->show_what, sizeof(stmt->show_what), "DATABASE");
            snprintf(stmt->target_name, sizeof(stmt->target_name), "%s", trim(db));
        } else if (ms) {
            ms += 11;
            snprintf(stmt->show_what, sizeof(stmt->show_what), "MEASUREMENT");
            snprintf(stmt->target_name, sizeof(stmt->target_name), "%s", trim(ms));
        } else {
            return -1;
        }
        return 0;
    }

    /* INSERT INTO ... */
    p = match_keyword(sql, "INSERT");
    if (p) {
        stmt->type = INFLUX_STMT_INSERT;
        /* The remainder is a line-protocol line, possibly prefixed by
         * "INTO <rp> ". We just stash the raw line for the write path. */
        snprintf(stmt->measurement, sizeof(stmt->measurement), "%s", trim(p));
        return 0;
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/* Query execution                                                    */
/* ------------------------------------------------------------------ */

static qihse_ts_aggregation_t to_ts_agg(influx_agg_t a) {
    switch (a) {
        case INFLUX_AGG_SUM: return QIHSE_TS_AGG_SUM;
        case INFLUX_AGG_MIN: return QIHSE_TS_AGG_MIN;
        case INFLUX_AGG_MAX: return QIHSE_TS_AGG_MAX;
        default:             return QIHSE_TS_AGG_AVG;
    }
}

/* Execute a SELECT statement and produce the InfluxDB JSON "series"
 * payload. Returns a malloc'd JSON string (caller frees). */
static char* execute_select(qihse_tsdb_t* tsdb, const influx_stmt_t* stmt) {
    uint32_t sid = fnv1a32(stmt->measurement);
    uint64_t start = stmt->has_time_range ? stmt->start_ts_ns : 0;
    uint64_t end = stmt->has_time_range ? stmt->end_ts_ns : now_ns();

    /* Build the response JSON. We emit a single series with the requested
     * columns. For raw SELECTs we return one row per aggregated bucket
     * (or a single row when no GROUP BY). */
    char* json = (char*)malloc(4096);
    if (!json) return NULL;
    size_t cap = 4096;
    size_t len = 0;

    char esc_meas[QIHSE_INFLUX_NAME_LEN * 2 + 4];
    {
        char* e = json_escape(stmt->measurement);
        snprintf(esc_meas, sizeof(esc_meas), "%s", e ? e : "");
        free(e);
    }

    len += snprintf(json + len, cap - len,
        "{\"results\":[{\"statement_id\":0,\"series\":[{\"name\":\"%s\",\"columns\":[\"time\",\"%s\"],\"values\":[",
        esc_meas,
        stmt->aggregation != INFLUX_AGG_NONE ?
            (stmt->aggregation == INFLUX_AGG_MEAN ? "mean" :
             stmt->aggregation == INFLUX_AGG_SUM ? "sum" :
             stmt->aggregation == INFLUX_AGG_MIN ? "min" :
             stmt->aggregation == INFLUX_AGG_MAX ? "max" : "count") :
            "value");

    if (stmt->has_group_by && stmt->group_by_ns > 0) {
        /* Emit one aggregated value per bucket. */
        int first = 1;
        for (uint64_t b = start; b < end; b += stmt->group_by_ns) {
            uint64_t b_end = b + stmt->group_by_ns - 1;
            if (b_end > end) b_end = end;
            double val = 0.0;
            uint64_t cnt = 0;
            qihse_ts_aggregation_t agg = to_ts_agg(stmt->aggregation);
            if (stmt->aggregation == INFLUX_AGG_COUNT) {
                qihse_tsdb_aggregate_range_user(tsdb, sid, b, b_end, QIHSE_TS_AGG_SUM, NULL, &val, &cnt);
                val = (double)cnt;
            } else if (stmt->aggregation == INFLUX_AGG_NONE) {
                val = qihse_tsdb_average_range_user(tsdb, b, b_end, NULL);
                cnt = (val != 0.0) ? 1 : 0;
            } else {
                qihse_tsdb_aggregate_range_user(tsdb, sid, b, b_end, agg, NULL, &val, &cnt);
            }
            if (cnt == 0 && stmt->aggregation != INFLUX_AGG_NONE) continue;
            if (!first) {
                if (len + 2 >= cap) { cap *= 2; json = realloc(json, cap); }
                json[len++] = ',';
            }
            first = 0;
            int n = snprintf(json + len, cap - len, "[%llu,%g]",
                             (unsigned long long)(b / 1000000ull), val);
            if (n < 0) n = 0;
            len += (size_t)n;
            if (len + 16 >= cap) { cap *= 2; json = realloc(json, cap); }
        }
    } else {
        /* Single aggregated value across the whole range. */
        double val = 0.0;
        uint64_t cnt = 0;
        if (stmt->aggregation == INFLUX_AGG_COUNT) {
            qihse_tsdb_aggregate_range_user(tsdb, sid, start, end, QIHSE_TS_AGG_SUM, NULL, &val, &cnt);
            val = (double)cnt;
        } else if (stmt->aggregation == INFLUX_AGG_NONE) {
            val = qihse_tsdb_average_range_user(tsdb, start, end, NULL);
            cnt = (val != 0.0) ? 1 : 0;
        } else {
            qihse_tsdb_aggregate_range_user(tsdb, sid, start, end,
                                            to_ts_agg(stmt->aggregation), NULL, &val, &cnt);
        }
        if (cnt > 0) {
            int n = snprintf(json + len, cap - len, "[%llu,%g]",
                             (unsigned long long)(start / 1000000ull), val);
            if (n > 0) len += (size_t)n;
        }
    }

    if (len + 32 >= cap) { cap += 64; json = realloc(json, cap); }
    len += snprintf(json + len, cap - len, "]}]}]}");
    return json;
}

/* Execute a SHOW statement. QIHSE does not maintain a persistent schema
 * catalog, so we return empty result sets in the InfluxDB shape. */
static char* execute_show(const influx_stmt_t* stmt) {
    (void)stmt;
    return strdup("{\"results\":[{\"statement_id\":0,\"series\":[]}]}");
}

/* ------------------------------------------------------------------ */
/* HTTP handlers                                                      */
/* ------------------------------------------------------------------ */

/* Extract the value of a query-string parameter (e.g. "q" or "db") into
 * a freshly allocated, URL-decoded buffer. Caller frees. */
static char* query_param(const char* qs, const char* key) {
    if (!qs || !key) return NULL;
    size_t klen = strlen(key);
    const char* p = qs;
    while (*p) {
        const char* amp = strchr(p, '&');
        const char* eq = strchr(p, '=');
        if (!eq || (amp && amp < eq)) { p = amp ? amp + 1 : p + strlen(p); continue; }
        size_t cur_klen = (size_t)(eq - p);
        if (cur_klen == klen && strncmp(p, key, klen) == 0) {
            const char* vstart = eq + 1;
            const char* vend = amp ? amp : vstart + strlen(vstart);
            size_t vlen = (size_t)(vend - vstart);
            char* out = (char*)malloc(vlen + 1);
            if (!out) return NULL;
            size_t j = 0;
            for (size_t i = 0; i < vlen; i++) {
                if (vstart[i] == '+') out[j++] = ' ';
                else if (vstart[i] == '%' && i + 2 < vlen) {
                    char hex[3] = { vstart[i+1], vstart[i+2], 0 };
                    out[j++] = (char)strtol(hex, NULL, 16);
                    i += 2;
                } else {
                    out[j++] = vstart[i];
                }
            }
            out[j] = '\0';
            return out;
        }
        p = amp ? amp + 1 : p + strlen(p);
    }
    return NULL;
}

http_response_t* qihse_influx_handle_ping(const http_request_t* req, void* user_data) {
    (void)req; (void)user_data;
    /* InfluxDB returns an empty body with the "InfluxDB" and
     * "X-Influxdb-Version" headers; we approximate with a tiny JSON body. */
    return http_response_json(204, "");
}

http_response_t* qihse_influx_handle_health(const http_request_t* req, void* user_data) {
    (void)req; (void)user_data;
    const char* resp = "{\"status\":\"pass\",\"name\":\"qihse-influx\",\"checks\":[],\"version\":\"1.8\"}";
    return http_response_json(200, resp);
}

http_response_t* qihse_influx_handle_write(const http_request_t* req, void* user_data) {
    if (!req) return http_response_error(400, "Bad Request");
    qihse_tsdb_t* tsdb = (qihse_tsdb_t*)user_data;
    if (!tsdb) return http_response_error(500, "No TSDB configured");
    if (!req->body || req->body_len == 0)
        return http_response_error(400, "write requires a line-protocol body");

    /* The body may contain multiple newline-delimited points. */
    char* body_copy = (char*)malloc(req->body_len + 1);
    if (!body_copy) return http_response_error(500, "Out of memory");
    memcpy(body_copy, req->body, req->body_len);
    body_copy[req->body_len] = '\0';

    char* save = NULL;
    char* line = strtok_r(body_copy, "\r\n", &save);
    int accepted = 0;
    while (line) {
        influx_line_point_t pt;
        if (influx_parse_line(line, &pt) == 0) {
            double value = 0.0;
            if (first_numeric_field(&pt, &value) == 0) {
                uint32_t sid = series_id_for(&pt);
                qihse_tsdb_insert(tsdb, sid, pt.timestamp_ns, value, 0, 0);
                accepted++;
            }
        }
        line = strtok_r(NULL, "\r\n", &save);
    }
    free(body_copy);

    if (accepted == 0)
        return http_response_error(400, "no valid line-protocol points");

    /* InfluxDB returns 204 No Content on a successful write. */
    return http_response_json(204, "");
}

http_response_t* qihse_influx_handle_query(const http_request_t* req, void* user_data) {
    if (!req) return http_response_error(400, "Bad Request");
    qihse_tsdb_t* tsdb = (qihse_tsdb_t*)user_data;

    /* The query string may arrive in the `q` URL parameter (GET/POST) or
     * in the request body for POST. */
    char* q = NULL;
    if (req->query_string) q = query_param(req->query_string, "q");
    if (!q && req->method == HTTP_POST && req->body && req->body_len > 0) {
        /* Body may be form-encoded (q=...) or a raw InfluxQL string. */
        if (strncasecmp(req->body, "q=", 2) == 0) {
            q = query_param(req->body, "q");
        } else {
            q = (char*)malloc(req->body_len + 1);
            if (q) { memcpy(q, req->body, req->body_len); q[req->body_len] = '\0'; }
        }
    }
    if (!q) return http_response_error(400, "missing required parameter: q");

    /* InfluxQL allows multiple semicolon-separated statements. We execute
     * each in turn and concatenate the per-statement results. */
    char* results_json = strdup("{\"results\":[");
    size_t cap = strlen(results_json);
    size_t len = cap;
    int stmt_id = 0;

    char* save = NULL;
    char* tok = strtok_r(q, ";", &save);
    while (tok) {
        influx_stmt_t stmt;
        char* sql_copy = strdup(tok);
        if (!sql_copy) { tok = strtok_r(NULL, ";", &save); continue; }

        if (influx_parse_query(sql_copy, &stmt) != 0) {
            char err[512];
            snprintf(err, sizeof(err),
                "{\"statement_id\":%d,\"error\":\"unable to parse statement\"}", stmt_id);
            size_t need = len + strlen(err) + 4;
            if (need > cap) { cap = need * 2; results_json = realloc(results_json, cap); }
            if (stmt_id > 0) results_json[len++] = ',';
            len += snprintf(results_json + len, cap - len, "%s", err);
        } else {
            char* result_json = NULL;
            switch (stmt.type) {
                case INFLUX_STMT_SELECT:
                    result_json = execute_select(tsdb, &stmt);
                    break;
                case INFLUX_STMT_SHOW:
                    result_json = execute_show(&stmt);
                    break;
                case INFLUX_STMT_CREATE:
                    result_json = strdup("{\"results\":[{\"statement_id\":0}]}");
                    break;
                case INFLUX_STMT_DROP:
                    result_json = strdup("{\"results\":[{\"statement_id\":0}]}");
                    break;
                case INFLUX_STMT_INSERT: {
                    /* INSERT line-protocol: forward to the write path. */
                    if (tsdb) {
                        influx_line_point_t pt;
                        char* lp = strdup(stmt.measurement);
                        if (lp && influx_parse_line(lp, &pt) == 0) {
                            double v = 0.0;
                            if (first_numeric_field(&pt, &v) == 0) {
                                qihse_tsdb_insert(tsdb, series_id_for(&pt),
                                                  pt.timestamp_ns, v, 0, 0);
                            }
                        }
                        free(lp);
                    }
                    result_json = strdup("{\"results\":[{\"statement_id\":0}]}");
                    break;
                }
            }
            if (result_json) {
                /* execute_select already returns a full {"results":[...]} blob;
                 * for uniform concatenation we extract the inner array. For the
                 * simpler statements we do the same. */
                const char* inner = strstr(result_json, "\"results\":[");
                if (inner) {
                    inner += strlen("\"results\":[");
                    const char* close = strrchr(result_json, ']');
                    if (close) {
                        size_t inner_len = (size_t)(close - inner);
                        size_t need = len + inner_len + 4;
                        if (need > cap) { cap = need * 2; results_json = realloc(results_json, cap); }
                        if (stmt_id > 0) results_json[len++] = ',';
                        memcpy(results_json + len, inner, inner_len);
                        len += inner_len;
                    }
                }
                free(result_json);
            }
        }
        free(sql_copy);
        stmt_id++;
        tok = strtok_r(NULL, ";", &save);
    }

    size_t need = len + 4;
    if (need > cap) { cap = need; results_json = realloc(results_json, cap); }
    len += snprintf(results_json + len, cap - len, "]}");

    http_response_t* res = http_response_json(200, results_json);
    free(results_json);
    free(q);
    return res;
}

int qihse_influx_register_routes(qihse_http_server_t* srv, qihse_tsdb_t* tsdb) {
    if (!srv || !tsdb) return -1;
    qihse_http_server_add_route(srv, "/ping", HTTP_GET, qihse_influx_handle_ping, tsdb);
    qihse_http_server_add_route(srv, "/ping", HTTP_HEAD, qihse_influx_handle_ping, tsdb);
    qihse_http_server_add_route(srv, "/health", HTTP_GET, qihse_influx_handle_health, tsdb);
    qihse_http_server_add_route(srv, "/query", HTTP_GET, qihse_influx_handle_query, tsdb);
    qihse_http_server_add_route(srv, "/query", HTTP_POST, qihse_influx_handle_query, tsdb);
    qihse_http_server_add_route(srv, "/write", HTTP_POST, qihse_influx_handle_write, tsdb);
    return 0;
}
