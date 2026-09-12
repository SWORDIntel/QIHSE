#ifndef QIHSE_INGEST_GUARD_H
#define QIHSE_INGEST_GUARD_H

/* U4 — PII-free protocol enforcement at telemetry ingest.
 *
 * "No PII phoning home regardless of login" is structural, not policy:
 * writes into the telemetry namespace "t:<tenant_id>/tlm/..." must match a
 * CLOSED whitelist of record types with per-field validators. Anything
 * outside the whitelist is REJECTED at ingest (never merely logged). Free
 * text cannot appear in any telemetry field: the value charset is closed
 * and every field is typed (hex hashes, bounded integers, fixed enums).
 * The only machine identifier permitted is the opaque tenant-scoped
 * hardware hash (hex16); account names, hostnames, IPs, and paths have no
 * representable form.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_INGEST_MAX_VALUE 4096u

/* Matches "t:<digits>/tlm/..." — the telemetry namespace. On success the
 * record type segment is returned ("build_record", "symbol_context",
 * "census", "survival_observation", "burn_edge"). */
bool qihse_ingest_is_telemetry_key(const uint8_t* key, size_t key_len);

/* Full structural validation of one telemetry record.
 * Returns true when the key names a whitelisted record type and the value
 * matches that type's closed schema. On rejection, err receives a
 * NUL-terminated reason safe to return to a client. */
bool qihse_ingest_guard_validate(const uint8_t* key, size_t key_len,
                                 const uint8_t* value, size_t value_len,
                                 char* err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_INGEST_GUARD_H */
