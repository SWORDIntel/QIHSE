#ifndef QIHSE_AUDIT_H
#define QIHSE_AUDIT_H

#include <stdint.h>
#include <stdbool.h>

/* Initialize the audit subsystem (ML-DSA-87 key generation + integrity chain check). */
void qihse_audit_init(void);

/* Set the audit notification webhook endpoint (IP:PORT format). Pass NULL to disable. */
void qihse_audit_set_webhook(const char* url);

/* Append a signed, hash-chained entry to the audit log. */
void qihse_audit_log(const char* action, uint32_t user_id, uint32_t target_id, uint16_t classif, uint16_t sci);

/* Fire-and-forget audit notification to the configured webhook endpoint.
 * No-op if no endpoint has been configured. */
void qihse_audit_webhook_ping(uint32_t user_id, uint16_t classif, uint16_t sci);

/* Verify the integrity chain file matches the in-memory hash state.
 * Triggers an authenticated lockdown prompt on mismatch. */
void qihse_audit_verify_integrity(void);

/* Block until every queued audit entry has been signed and written.
 * Audit entries are signed asynchronously; call this before a clean exit or
 * when an on-disk audit trail must be complete. */
void qihse_audit_flush(void);

/* Drain the audit queue and stop the background signer thread. */
void qihse_audit_shutdown(void);

#endif // QIHSE_AUDIT_H
