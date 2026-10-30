#ifndef QIHSE_SQL_FTS_H
#define QIHSE_SQL_FTS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transforms an unclassified, caller-owned scalar string; never retrieves data.
 * On success, *canonical_out is malloc-owned (including the empty vector "").
 * Input is limited to 4096 ASCII bytes, tokens to 256 bytes and output to
 * 4096 bytes (matching row-store TSVECTOR). This is not a complete PostgreSQL
 * text-search parser: Unicode,
 * URLs, hyphenated-word sublexemes and email component lexemes are unsupported.
 * A missing libstemmer fails closed, even for an empty input. */
bool qihse_sql_to_tsvector_english(const char* text, char** canonical_out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_SQL_FTS_H */
