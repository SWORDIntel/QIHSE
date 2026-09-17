#ifndef QIHSE_SECURITY_AUDIT_H
#define QIHSE_SECURITY_AUDIT_H

/*
 * QIHSE runtime hardening self-audit — federation stage F7.
 * See v3.md §36 (runtime hardening profile), §37 (network exposure and
 * egress policy) and §39 (hardening self-audit).
 *
 * The audit must verify ACTUAL runtime state rather than merely reading
 * configuration files.  A failed self-audit must never erase local data or
 * terminate the database: it degrades federation trust instead (v3.md §39).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"
#include "qihse_runtime_trust.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Sensitive kernel interface classification (v3.md §36) ─────────────── */

typedef enum {
    QIHSE_IFACE_REQUIRED = 0,
    QIHSE_IFACE_OPTIONAL,
    QIHSE_IFACE_FORBIDDEN,
    QIHSE_IFACE_UNKNOWN
} qihse_iface_class_t;

const char* qihse_iface_class_name(qihse_iface_class_t cls);
bool qihse_iface_class_parse(const char* name, qihse_iface_class_t* out);

/* The interfaces v3.md §36 calls out for explicit classification. */
typedef enum {
    QIHSE_IFACE_AF_PACKET = 0,
    QIHSE_IFACE_AF_NETLINK,
    QIHSE_IFACE_AF_ALG,
    QIHSE_IFACE_RAW_SOCKETS,
    QIHSE_IFACE_IO_URING,
    QIHSE_IFACE_USERFAULTFD,
    QIHSE_IFACE_PERF_EVENT_OPEN,
    QIHSE_IFACE_BPF,
    QIHSE_IFACE_PROCESS_VM,
    QIHSE_IFACE_PTRACE,
    QIHSE_IFACE_KEYRINGS,
    QIHSE_IFACE_MEMFD,
    QIHSE_IFACE_MOUNT,
    QIHSE_IFACE_COUNT
} qihse_kernel_iface_t;

const char* qihse_kernel_iface_name(qihse_kernel_iface_t iface);
bool qihse_kernel_iface_parse(const char* name, qihse_kernel_iface_t* out);

/* ── Runtime security profile (v3.md §36) ──────────────────────────────── */

#define QIHSE_RUNTIME_PROFILE_ID_MAX 64u

typedef struct {
    char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
    char version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
    uint64_t generation;
    /* Effective Linux capabilities the service is allowed to hold.  Bit n
     * corresponds to capability n (CAP_CHOWN = 0, and so on). */
    uint64_t allowed_capabilities;
    /* Whether core dumps are permitted in production. */
    bool core_dumps_allowed;
    /* Whether a seccomp filter is required. */
    bool require_seccomp;
    /* Per-interface classification.  An UNKNOWN entry fails hardening review
     * for production builds (v3.md §36). */
    qihse_iface_class_t interfaces[QIHSE_IFACE_COUNT];
    /* Service identity the process is expected to run as.  -1 = any. */
    int32_t expected_uid;
    int32_t expected_gid;
} qihse_runtime_profile_t;

#define QIHSE_RUNTIME_PROFILE_PREFIX "security/runtime-profile:"

/* Initialise a profile with the conservative production defaults from
 * v3.md §36: no capabilities, no core dumps, and every audited interface
 * marked UNKNOWN until someone classifies it deliberately. */
void qihse_runtime_profile_init(qihse_runtime_profile_t* profile, const char* service,
                                const char* version);

bool qihse_runtime_profile_put(void* store_void, void* user_void,
                               const qihse_runtime_profile_t* profile);
bool qihse_runtime_profile_get(void* store_void, void* user_void,
                               const char* service, const char* version,
                               qihse_runtime_profile_t* out);

/* ── Observed runtime state (v3.md §39) ────────────────────────────────── */

typedef struct {
    int32_t uid;
    int32_t gid;
    int32_t euid;
    int32_t egid;
    uint64_t effective_capabilities;
    bool core_dumps_enabled;     /* RLIMIT_CORE > 0 */
    bool dumpable;               /* PR_GET_DUMPABLE */
    int seccomp_mode;            /* 0 disabled, 1 strict, 2 filter */
    bool no_new_privs;
    uint32_t listening_socket_count;
    uint32_t listening_ports[32];
    uint32_t listening_port_count;
    uint64_t observed_hlc_physical;
} qihse_runtime_observation_t;

/* Collect the process's ACTUAL state from the kernel: credentials, effective
 * capability mask, core-dump rlimit and dumpable flag, seccomp mode, and the
 * listening TCP sockets visible to this process.  Returns false only if the
 * platform denies even the basic queries. */
bool qihse_runtime_observe(qihse_runtime_observation_t* out);

/* ── Drift report (acceptance criteria 25, 28) ─────────────────────────── */

#define QIHSE_AUDIT_MAX_FINDINGS 32u
#define QIHSE_AUDIT_FINDING_MAX 160u

typedef enum {
    QIHSE_DRIFT_NONE = 0,
    QIHSE_DRIFT_UNEXPECTED_CAPABILITY,
    QIHSE_DRIFT_MISSING_CAPABILITY,
    QIHSE_DRIFT_CORE_DUMPS_ENABLED,
    QIHSE_DRIFT_UNEXPECTED_UID,
    QIHSE_DRIFT_UNEXPECTED_LISTENER,
    QIHSE_DRIFT_UNCLASSIFIED_INTERFACE,
    QIHSE_DRIFT_FORBIDDEN_INTERFACE,
    QIHSE_DRIFT_SECCOMP_DISABLED,
    QIHSE_DRIFT_UNEXPECTED_EGRESS_CLASS
} qihse_drift_kind_t;

const char* qihse_drift_kind_name(qihse_drift_kind_t kind);

typedef struct {
    qihse_drift_kind_t kind;
    char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
} qihse_audit_finding_t;

typedef struct {
    char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
    char version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
    uint64_t runtime_profile_generation;
    bool profile_found;
    uint32_t unexpected_capability_count;
    uint32_t unexpected_listener_count;
    uint32_t unclassified_interface_count;
    uint32_t forbidden_interface_count;
    uint32_t finding_count;
    qihse_audit_finding_t findings[QIHSE_AUDIT_MAX_FINDINGS];
    /* Severity drives trust degradation, never local unavailability. */
    bool critical;
    qihse_runtime_trust_t recommended_trust;
} qihse_audit_report_t;

/* Compare an observation against the declared profile and produce a report.
 * `declared_listeners`/`declared_listener_count` is the set of ports the
 * service is permitted to listen on; any other listening socket is drift. */
bool qihse_runtime_audit(const qihse_runtime_profile_t* profile,
                         const qihse_runtime_observation_t* observed,
                         const uint32_t* declared_listeners, size_t declared_listener_count,
                         qihse_audit_report_t* out);

#define QIHSE_AUDIT_RECORD_PREFIX "security/audit:"

/* Persist an audit report as versioned evidence under
 * "security/audit/<node>/<service>/<hlc>".  Reports are immutable. */
bool qihse_runtime_audit_record(void* store_void, void* user_void,
                                const qihse_uuid_t* node_id,
                                const qihse_audit_report_t* report);

/* ── Network exposure and egress policy (v3.md §37) ────────────────────── */

typedef enum {
    QIHSE_EGRESS_FEDERATION_PEERS = 0,
    QIHSE_EGRESS_BACKUP_TARGET,
    QIHSE_EGRESS_TELEMETRY_SINK,
    QIHSE_EGRESS_LOCAL_CITADEL,
    QIHSE_EGRESS_UNRESTRICTED_INTERNET,  /* must never be required */
    QIHSE_EGRESS_CLASS_COUNT
} qihse_egress_class_t;

const char* qihse_egress_class_name(qihse_egress_class_t cls);
bool qihse_egress_class_parse(const char* name, qihse_egress_class_t* out);

typedef struct {
    char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
    char version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
    /* Declared listeners.  Every listener must have a defined bind address,
     * authentication mode, authorization scope, protocol version, and rate
     * and size limits (v3.md §37). */
    uint32_t ports[32];
    char bind_addresses[32][64];
    size_t listener_count;
    bool listener_requires_auth[32];
    size_t max_request_bytes[32];
    /* Declared egress classes. */
    bool egress[QIHSE_EGRESS_CLASS_COUNT];
    uint64_t generation;
} qihse_net_profile_t;

#define QIHSE_NET_PROFILE_PREFIX "security/runtime-network-profile:"

void qihse_net_profile_init(qihse_net_profile_t* profile, const char* service,
                            const char* version);

bool qihse_net_profile_put(void* store_void, void* user_void,
                           const qihse_net_profile_t* profile);
bool qihse_net_profile_get(void* store_void, void* user_void,
                           const char* service, const char* version,
                           qihse_net_profile_t* out);

/* True when the declared profile requires no unrestricted Internet egress
 * (acceptance criterion 26). */
bool qihse_net_profile_is_egress_restricted(const qihse_net_profile_t* profile);

/* Report listening ports present in the observation but absent from the
 * declared listener set.  Returns the number of unexpected ports. */
size_t qihse_net_profile_unexpected_listeners(const qihse_net_profile_t* profile,
                                              const qihse_runtime_observation_t* observed,
                                              uint32_t* out_ports, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_SECURITY_AUDIT_H */
