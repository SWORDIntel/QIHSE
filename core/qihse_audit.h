#ifndef QIHSE_AUDIT_H
#define QIHSE_AUDIT_H

#include <stdint.h>
#include <stdbool.h>

void qihse_audit_init(void);
void qihse_audit_set_webhook(const char* url);
void qihse_audit_log(const char* action, uint32_t user_id, uint32_t target_id, uint16_t classif, uint16_t sci);
void qihse_audit_webhook_ping(uint32_t user_id, uint16_t classif, uint16_t sci);
void qihse_audit_verify_integrity(void);

#endif // QIHSE_AUDIT_H
