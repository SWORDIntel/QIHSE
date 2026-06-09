#include <stdint.h>
#include <stdbool.h>

// Stubs for qihse_hetero.c
void qihse_compute_pool_init(void* p) { (void)p; }
void qihse_work_schedule_destroy(void* s) { (void)s; }
void* qihse_create_work_schedule(int t) { (void)t; return 0; }
void qihse_compute_pool_calibrate(void* p) { (void)p; }

// Stubs for qihse_audit.c
void qihse_audit_init(void) {}
void qihse_audit_log(int level, const char* event, const char* msg) { (void)level; (void)event; (void)msg; }
void qihse_audit_webhook_ping(void) {}

// Stubs for qihse_quantum_defense.c
void qihse_qdd_init(void) {}
void qihse_qdd_free(void) {}
void qihse_qdd_report_access(const char* id, bool success) { (void)id; (void)success; }
bool qihse_qdd_is_under_attack(void) { return false; }
void qihse_qdd_generate_honeypot_response(char* out) { if(out) out[0] = 0; }

