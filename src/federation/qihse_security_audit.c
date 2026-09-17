/*
 * QIHSE runtime hardening self-audit — federation stage F7.
 * See v3.md §36 (runtime hardening profile), §37 (network exposure and
 * egress policy) and §39 (hardening self-audit).
 *
 * The audit reads ACTUAL process and kernel state — credentials, effective
 * capabilities, core-dump rlimit, dumpable flag, seccomp mode, and the
 * listening sockets visible to this process — and compares it against a
 * declared profile.  A failed audit degrades federation trust; it never
 * makes the local database unavailable (v3.md §39).
 */

/* getuid/getrlimit/prctl are POSIX/GNU, hidden by -std=c99 without this. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_security_audit.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "qihse_kv_store.h"

/* ── Sensitive kernel interface vocabulary (v3.md §36) ─────────────────── */

typedef struct { qihse_iface_class_t v; const char* name; } iface_class_entry_t;

static const iface_class_entry_t g_iface_classes[] = {
    { QIHSE_IFACE_REQUIRED,  "REQUIRED"  },
    { QIHSE_IFACE_OPTIONAL,  "OPTIONAL"  },
    { QIHSE_IFACE_FORBIDDEN, "FORBIDDEN" },
    { QIHSE_IFACE_UNKNOWN,   "UNKNOWN"   },
};

const char* qihse_iface_class_name(qihse_iface_class_t cls) {
    for (size_t i = 0; i < sizeof(g_iface_classes) / sizeof(g_iface_classes[0]); i++) {
        if (g_iface_classes[i].v == cls) return g_iface_classes[i].name;
    }
    return "UNKNOWN";
}

bool qihse_iface_class_parse(const char* name, qihse_iface_class_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_iface_classes) / sizeof(g_iface_classes[0]); i++) {
        if (strcasecmp(g_iface_classes[i].name, name) == 0) {
            *out = g_iface_classes[i].v;
            return true;
        }
    }
    return false;
}

typedef struct { qihse_kernel_iface_t v; const char* name; } kernel_iface_entry_t;

static const kernel_iface_entry_t g_kernel_ifaces[] = {
    { QIHSE_IFACE_AF_PACKET,       "AF_PACKET"        },
    { QIHSE_IFACE_AF_NETLINK,      "AF_NETLINK"       },
    { QIHSE_IFACE_AF_ALG,          "AF_ALG"           },
    { QIHSE_IFACE_RAW_SOCKETS,     "RAW_SOCKETS"      },
    { QIHSE_IFACE_IO_URING,        "IO_URING"         },
    { QIHSE_IFACE_USERFAULTFD,     "USERFAULTFD"      },
    { QIHSE_IFACE_PERF_EVENT_OPEN, "PERF_EVENT_OPEN"  },
    { QIHSE_IFACE_BPF,             "BPF"              },
    { QIHSE_IFACE_PROCESS_VM,      "PROCESS_VM"       },
    { QIHSE_IFACE_PTRACE,          "PTRACE"           },
    { QIHSE_IFACE_KEYRINGS,        "KEYRINGS"         },
    { QIHSE_IFACE_MEMFD,           "MEMFD"            },
    { QIHSE_IFACE_MOUNT,           "MOUNT"            },
};

const char* qihse_kernel_iface_name(qihse_kernel_iface_t iface) {
    for (size_t i = 0; i < sizeof(g_kernel_ifaces) / sizeof(g_kernel_ifaces[0]); i++) {
        if (g_kernel_ifaces[i].v == iface) return g_kernel_ifaces[i].name;
    }
    return "UNKNOWN";
}

bool qihse_kernel_iface_parse(const char* name, qihse_kernel_iface_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_kernel_ifaces) / sizeof(g_kernel_ifaces[0]); i++) {
        if (strcasecmp(g_kernel_ifaces[i].name, name) == 0) {
            *out = g_kernel_ifaces[i].v;
            return true;
        }
    }
    return false;
}

/* ── Record encoding helpers ───────────────────────────────────────────── */

/* Tab-separated records with legitimately empty fields, so decoders walk the
 * record instead of using sscanf("%[^\t]"). */
static const char* sa_next_field(const char* p, char* out, size_t cap) {
    if (!p) { if (cap) out[0] = '\0'; return NULL; }
    const char* start = p;
    while (*p && *p != '\t') p++;
    size_t len = (size_t)(p - start);
    if (len >= cap) len = cap - 1u;
    if (cap) { memcpy(out, start, len); out[len] = '\0'; }
    return (*p == '\t') ? p + 1 : NULL;
}

static pthread_mutex_t g_audit_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Runtime security profile (v3.md §36) ──────────────────────────────── */

void qihse_runtime_profile_init(qihse_runtime_profile_t* profile, const char* service,
                                const char* version) {
    if (!profile) return;
    memset(profile, 0, sizeof(*profile));
    if (service) snprintf(profile->service, sizeof(profile->service), "%s", service);
    if (version) snprintf(profile->version, sizeof(profile->version), "%s", version);
    profile->generation = 1;
    /* Conservative production defaults: hold no capabilities, do not permit
     * core dumps, require a seccomp filter, and leave every audited interface
     * UNKNOWN until it is classified deliberately (v3.md §36). */
    profile->allowed_capabilities = 0;
    profile->core_dumps_allowed = false;
    profile->require_seccomp = true;
    profile->expected_uid = -1;
    profile->expected_gid = -1;
    for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) {
        profile->interfaces[i] = QIHSE_IFACE_UNKNOWN;
    }
}

static void runtime_profile_key(const char* service, const char* version,
                                char* out, size_t cap) {
    snprintf(out, cap, QIHSE_RUNTIME_PROFILE_PREFIX "%s:%s", service, version);
}

static void runtime_profile_encode(const qihse_runtime_profile_t* p, char* out, size_t cap) {
    size_t off = 0;
    off += (size_t)snprintf(out + off, cap - off, "%s\t%s\t%llu\t%llu\t%d\t%d\t%d",
                            p->service, p->version,
                            (unsigned long long)p->generation,
                            (unsigned long long)p->allowed_capabilities,
                            p->core_dumps_allowed ? 1 : 0,
                            p->require_seccomp ? 1 : 0,
                            (int)p->expected_uid);
    off += (size_t)snprintf(out + off, cap - off, "\t%d", (int)p->expected_gid);
    for (size_t i = 0; i < QIHSE_IFACE_COUNT && off < cap; i++) {
        off += (size_t)snprintf(out + off, cap - off, "\t%u", (unsigned)p->interfaces[i]);
    }
}

static bool runtime_profile_decode(const char* blob, qihse_runtime_profile_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char f[8 + QIHSE_IFACE_COUNT][128];
    const char* p = blob;
    size_t want = 8u + QIHSE_IFACE_COUNT;
    for (size_t i = 0; i < want; i++) p = sa_next_field(p, f[i], sizeof(f[i]));
    snprintf(out->service, sizeof(out->service), "%s", f[0]);
    snprintf(out->version, sizeof(out->version), "%s", f[1]);
    out->generation = (uint64_t)strtoull(f[2], NULL, 10);
    out->allowed_capabilities = (uint64_t)strtoull(f[3], NULL, 10);
    out->core_dumps_allowed = strtoul(f[4], NULL, 10) != 0;
    out->require_seccomp = strtoul(f[5], NULL, 10) != 0;
    out->expected_uid = (int32_t)strtol(f[6], NULL, 10);
    out->expected_gid = (int32_t)strtol(f[7], NULL, 10);
    for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) {
        unsigned long cls = strtoul(f[8 + i], NULL, 10);
        if (cls > (unsigned long)QIHSE_IFACE_UNKNOWN) return false;
        out->interfaces[i] = (qihse_iface_class_t)cls;
    }
    return true;
}

bool qihse_runtime_profile_put(void* store_void, void* user_void,
                               const qihse_runtime_profile_t* profile) {
    if (!store_void || !user_void || !profile) return false;
    if (profile->service[0] == '\0' || profile->version[0] == '\0') return false;
    char key[192];
    runtime_profile_key(profile->service, profile->version, key, sizeof(key));
    char blob[2048];
    runtime_profile_encode(profile, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_runtime_profile_get(void* store_void, void* user_void,
                               const char* service, const char* version,
                               qihse_runtime_profile_t* out) {
    if (!store_void || !user_void || !service || !version || !out) return false;
    char key[192];
    runtime_profile_key(service, version, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = runtime_profile_decode(blob, out);
    free(blob);
    return ok;
}

/* ── Observed runtime state (v3.md §39) ────────────────────────────────── */

/* Parse a "CapEff:\t00000000000000ff" style line out of /proc/self/status. */
static bool parse_status_cap(const char* path, const char* key, uint64_t* out) {
    FILE* f = fopen(path, "r");
    if (!f) return false;
    char line[512];
    size_t key_len = strlen(key);
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, key_len) != 0) continue;
        const char* p = line + key_len;
        while (*p == ':' || *p == ' ' || *p == '\t') p++;
        *out = (uint64_t)strtoull(p, NULL, 16);
        found = true;
        break;
    }
    fclose(f);
    return found;
}

/* Collect listening TCP ports from /proc/net/tcp and /proc/net/tcp6.  State
 * 0A is TCP_LISTEN; the local port is the hex group after the address. */
static uint32_t collect_listeners(uint32_t* out_ports, size_t cap) {
    static const char* files[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    uint32_t count = 0;
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        FILE* f = fopen(files[i], "r");
        if (!f) continue;
        char line[512];
        (void)fgets(line, sizeof(line), f); /* header */
        while (fgets(line, sizeof(line), f)) {
            unsigned int state = 0;
            char local[128];
            /* sl  local_address rem_address st ... */
            if (sscanf(line, " %*d: %127s %*s %x", local, &state) != 2) continue;
            if (state != 0x0Au) continue; /* TCP_LISTEN */
            const char* colon = strrchr(local, ':');
            if (!colon) continue;
            unsigned long port = strtoul(colon + 1, NULL, 16);
            if (port == 0 || port > 65535u) continue;
            /* De-duplicate across the v4 and v6 tables. */
            bool dup = false;
            for (uint32_t j = 0; j < count; j++) {
                if (out_ports[j] == (uint32_t)port) { dup = true; break; }
            }
            if (dup) continue;
            if (count < cap) out_ports[count] = (uint32_t)port;
            count++;
        }
        fclose(f);
    }
    return count;
}

bool qihse_runtime_observe(qihse_runtime_observation_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    out->uid = (int32_t)getuid();
    out->gid = (int32_t)getgid();
    out->euid = (int32_t)geteuid();
    out->egid = (int32_t)getegid();

    /* Effective capability mask, straight from the kernel. */
    if (!parse_status_cap("/proc/self/status", "CapEff:", &out->effective_capabilities)) {
        out->effective_capabilities = 0;
    }

    /* Core-dump policy: RLIMIT_CORE greater than zero permits a dump. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_CORE, &rl) == 0) {
        out->core_dumps_enabled = (rl.rlim_cur != 0);
    }

    /* PR_GET_DUMPABLE: whether the process may be dumped at all. */
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    out->dumpable = (dumpable == 1);

    /* Seccomp mode: 0 disabled, 1 strict, 2 filter. */
    uint64_t seccomp = 0;
    if (parse_status_cap("/proc/self/status", "Seccomp:", &seccomp)) {
        out->seccomp_mode = (int)seccomp;
    }

    uint64_t nnp = 0;
    if (parse_status_cap("/proc/self/status", "NoNewPrivs:", &nnp)) {
        out->no_new_privs = (nnp != 0);
    }

    out->listening_port_count = collect_listeners(out->listening_ports,
                                                 sizeof(out->listening_ports) / sizeof(out->listening_ports[0]));
    out->listening_socket_count = out->listening_port_count;
    out->observed_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
    return true;
}

/* ── Drift report (criteria 24, 25, 28) ────────────────────────────────── */

typedef struct { qihse_drift_kind_t v; const char* name; } drift_kind_entry_t;

static const drift_kind_entry_t g_drift_kinds[] = {
    { QIHSE_DRIFT_NONE,                   "none"                    },
    { QIHSE_DRIFT_UNEXPECTED_CAPABILITY,  "unexpected_capability"   },
    { QIHSE_DRIFT_MISSING_CAPABILITY,     "missing_capability"      },
    { QIHSE_DRIFT_CORE_DUMPS_ENABLED,     "core_dumps_enabled"      },
    { QIHSE_DRIFT_UNEXPECTED_UID,         "unexpected_uid"          },
    { QIHSE_DRIFT_UNEXPECTED_LISTENER,    "unexpected_listener"     },
    { QIHSE_DRIFT_UNCLASSIFIED_INTERFACE, "unclassified_interface"  },
    { QIHSE_DRIFT_FORBIDDEN_INTERFACE,    "forbidden_interface"     },
    { QIHSE_DRIFT_SECCOMP_DISABLED,       "seccomp_disabled"        },
    { QIHSE_DRIFT_UNEXPECTED_EGRESS_CLASS, "unexpected_egress_class" },
};

const char* qihse_drift_kind_name(qihse_drift_kind_t kind) {
    for (size_t i = 0; i < sizeof(g_drift_kinds) / sizeof(g_drift_kinds[0]); i++) {
        if (g_drift_kinds[i].v == kind) return g_drift_kinds[i].name;
    }
    return "unknown";
}

static void audit_add_finding(qihse_audit_report_t* report, qihse_drift_kind_t kind,
                              const char* detail, bool critical) {
    if (report->finding_count >= QIHSE_AUDIT_MAX_FINDINGS) return;
    qihse_audit_finding_t* f = &report->findings[report->finding_count++];
    f->kind = kind;
    snprintf(f->detail, sizeof(f->detail), "%s", detail ? detail : "");
    if (critical) report->critical = true;
}

/* Linux capability bit positions we care about when reporting drift. */
static void list_capability_names(uint64_t mask, char* out, size_t cap) {
    static const char* names[] = {
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
        "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
        "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
        "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    };
    size_t off = 0;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]) && off + 1 < cap; i++) {
        if (!(mask & (1ULL << i))) continue;
        off += (size_t)snprintf(out + off, cap - off, "%s%s",
                                off ? "," : "", names[i]);
    }
    if (out[0] == '\0') snprintf(out, cap, "none");
}

bool qihse_runtime_audit(const qihse_runtime_profile_t* profile,
                         const qihse_runtime_observation_t* observed,
                         const uint32_t* declared_listeners, size_t declared_listener_count,
                         qihse_audit_report_t* out) {
    if (!observed || !out) return false;
    memset(out, 0, sizeof(*out));
    if (profile) {
        snprintf(out->service, sizeof(out->service), "%s", profile->service);
        snprintf(out->version, sizeof(out->version), "%s", profile->version);
        out->runtime_profile_generation = profile->generation;
        out->profile_found = true;
    }

    if (!profile) {
        audit_add_finding(out, QIHSE_DRIFT_UNCLASSIFIED_INTERFACE,
                          "no runtime profile declared for this service", true);
        out->recommended_trust = QIHSE_RTRUST_LOCAL_ONLY;
        return true;
    }

    /* Capabilities: anything held beyond the allowlist is drift, and so is a
     * capability the profile declares as required but that is missing. */
    uint64_t unexpected = observed->effective_capabilities & ~profile->allowed_capabilities;
    if (unexpected != 0) {
        char names[256];
        list_capability_names(unexpected, names, sizeof(names));
        char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
        snprintf(detail, sizeof(detail), "capabilities held but not allowed: %s", names);
        audit_add_finding(out, QIHSE_DRIFT_UNEXPECTED_CAPABILITY, detail, true);
        for (size_t i = 0; i < 64u; i++) {
            if (unexpected & (1ULL << i)) out->unexpected_capability_count++;
        }
    }
    uint64_t missing = profile->allowed_capabilities & ~observed->effective_capabilities;
    if (missing != 0) {
        char names[256];
        list_capability_names(missing, names, sizeof(names));
        char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
        snprintf(detail, sizeof(detail), "capabilities required but missing: %s", names);
        audit_add_finding(out, QIHSE_DRIFT_MISSING_CAPABILITY, detail, false);
    }

    /* Core-dump policy: production must not permit dumps (criterion 28). */
    if (observed->core_dumps_enabled && !profile->core_dumps_allowed) {
        audit_add_finding(out, QIHSE_DRIFT_CORE_DUMPS_ENABLED,
                          "RLIMIT_CORE is non-zero but the profile forbids core dumps", true);
    }

    /* Service identity. */
    if (profile->expected_uid >= 0 && observed->euid != profile->expected_uid) {
        char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
        snprintf(detail, sizeof(detail), "running as uid %d, profile expects %d",
                 (int)observed->euid, (int)profile->expected_uid);
        audit_add_finding(out, QIHSE_DRIFT_UNEXPECTED_UID, detail, true);
    }

    /* Listeners: a port that is listening but was never declared. */
    for (uint32_t i = 0; i < observed->listening_port_count; i++) {
        uint32_t port = observed->listening_ports[i];
        bool declared = false;
        for (size_t j = 0; j < declared_listener_count; j++) {
            if (declared_listeners[j] == port) { declared = true; break; }
        }
        if (declared) continue;
        char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
        snprintf(detail, sizeof(detail), "listening on undeclared port %u", port);
        audit_add_finding(out, QIHSE_DRIFT_UNEXPECTED_LISTENER, detail, true);
        out->unexpected_listener_count++;
    }

    /* Interface classification: UNKNOWN fails hardening review, FORBIDDEN is
     * an outright violation (v3.md §36). */
    for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) {
        if (profile->interfaces[i] == QIHSE_IFACE_UNKNOWN) {
            out->unclassified_interface_count++;
        } else if (profile->interfaces[i] == QIHSE_IFACE_FORBIDDEN) {
            out->forbidden_interface_count++;
        }
    }
    if (out->unclassified_interface_count > 0) {
        char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
        snprintf(detail, sizeof(detail), "%u kernel interfaces still UNKNOWN",
                 out->unclassified_interface_count);
        audit_add_finding(out, QIHSE_DRIFT_UNCLASSIFIED_INTERFACE, detail, false);
    }
    if (out->forbidden_interface_count > 0) {
        char detail[QIHSE_AUDIT_FINDING_MAX + 1u];
        snprintf(detail, sizeof(detail), "%u kernel interfaces marked FORBIDDEN",
                 out->forbidden_interface_count);
        audit_add_finding(out, QIHSE_DRIFT_FORBIDDEN_INTERFACE, detail, true);
    }

    /* Seccomp. */
    if (profile->require_seccomp && observed->seccomp_mode == 0) {
        audit_add_finding(out, QIHSE_DRIFT_SECCOMP_DISABLED,
                          "profile requires a seccomp filter but seccomp is disabled", false);
    }

    /* Severity maps to federation trust only — never to local availability. */
    if (out->critical) {
        out->recommended_trust = QIHSE_RTRUST_LOCAL_ONLY;
    } else if (out->finding_count > 0) {
        out->recommended_trust = QIHSE_RTRUST_TRUSTED_DEGRADED;
    } else {
        out->recommended_trust = QIHSE_RTRUST_TRUSTED;
    }
    return true;
}

/* ── Audit record persistence (v3.md §39) ──────────────────────────────── */

static void audit_record_key(const qihse_uuid_t* node_id, const char* service,
                             uint64_t hlc, char* out, size_t cap) {
    char n[33];
    const uint8_t* b = (const uint8_t*)node_id;
    for (int i = 0; i < 16; i++) snprintf(n + i * 2, 3, "%02x", b[i]);
    n[32] = '\0';
    snprintf(out, cap, QIHSE_AUDIT_RECORD_PREFIX "%s:%s:%llu", n, service,
             (unsigned long long)hlc);
}

bool qihse_runtime_audit_record(void* store_void, void* user_void,
                                const qihse_uuid_t* node_id,
                                const qihse_audit_report_t* report) {
    if (!store_void || !user_void || !node_id || !report) return false;
    uint64_t hlc = (uint64_t)time(NULL) * 1000ULL;
    char key[256];
    audit_record_key(node_id, report->service, hlc, key, sizeof(key));

    char blob[4096];
    size_t off = 0;
    off += (size_t)snprintf(blob + off, sizeof(blob) - off,
                            "%s\t%s\t%llu\t%d\t%u\t%u\t%u\t%u\t%u\t%d\t%u",
                            report->service, report->version,
                            (unsigned long long)report->runtime_profile_generation,
                            report->profile_found ? 1 : 0,
                            report->unexpected_capability_count,
                            report->unexpected_listener_count,
                            report->unclassified_interface_count,
                            report->forbidden_interface_count,
                            report->finding_count,
                            report->critical ? 1 : 0,
                            (unsigned)report->recommended_trust);
    for (size_t i = 0; i < report->finding_count && off < sizeof(blob); i++) {
        off += (size_t)snprintf(blob + off, sizeof(blob) - off, "\t%u:%s",
                                (unsigned)report->findings[i].kind,
                                report->findings[i].detail);
    }

    pthread_mutex_lock(&g_audit_lock);
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_audit_lock);
    return ok;
}

/* ── Network exposure and egress policy (v3.md §37) ────────────────────── */

typedef struct { qihse_egress_class_t v; const char* name; } egress_entry_t;

static const egress_entry_t g_egress_classes[] = {
    { QIHSE_EGRESS_FEDERATION_PEERS,     "federation_peers"     },
    { QIHSE_EGRESS_BACKUP_TARGET,        "backup_target"        },
    { QIHSE_EGRESS_TELEMETRY_SINK,       "telemetry_sink"       },
    { QIHSE_EGRESS_LOCAL_CITADEL,        "local_citadel"        },
    { QIHSE_EGRESS_UNRESTRICTED_INTERNET, "unrestricted_internet" },
};

const char* qihse_egress_class_name(qihse_egress_class_t cls) {
    for (size_t i = 0; i < sizeof(g_egress_classes) / sizeof(g_egress_classes[0]); i++) {
        if (g_egress_classes[i].v == cls) return g_egress_classes[i].name;
    }
    return "unknown";
}

bool qihse_egress_class_parse(const char* name, qihse_egress_class_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_egress_classes) / sizeof(g_egress_classes[0]); i++) {
        if (strcasecmp(g_egress_classes[i].name, name) == 0) {
            *out = g_egress_classes[i].v;
            return true;
        }
    }
    return false;
}

void qihse_net_profile_init(qihse_net_profile_t* profile, const char* service,
                            const char* version) {
    if (!profile) return;
    memset(profile, 0, sizeof(*profile));
    if (service) snprintf(profile->service, sizeof(profile->service), "%s", service);
    if (version) snprintf(profile->version, sizeof(profile->version), "%s", version);
    profile->generation = 1;
    /* Default to the minimal outbound posture: talk to configured federation
     * peers and local Citadel services only.  Unrestricted Internet egress is
     * never part of a default profile (criterion 26). */
    profile->egress[QIHSE_EGRESS_FEDERATION_PEERS] = true;
    profile->egress[QIHSE_EGRESS_LOCAL_CITADEL] = true;
    profile->egress[QIHSE_EGRESS_UNRESTRICTED_INTERNET] = false;
}

static void net_profile_key(const char* service, const char* version,
                            char* out, size_t cap) {
    snprintf(out, cap, QIHSE_NET_PROFILE_PREFIX "%s:%s", service, version);
}

static void net_profile_encode(const qihse_net_profile_t* p, char* out, size_t cap) {
    size_t off = 0;
    off += (size_t)snprintf(out + off, cap - off, "%s\t%s\t%llu\t%zu\t%u",
                            p->service, p->version,
                            (unsigned long long)p->generation,
                            p->listener_count,
                            (unsigned)p->egress[QIHSE_EGRESS_UNRESTRICTED_INTERNET] ? 1u : 0u);
    for (size_t i = 0; i < p->listener_count && off < cap; i++) {
        off += (size_t)snprintf(out + off, cap - off, "\t%u\t%s\t%d\t%zu",
                                p->ports[i], p->bind_addresses[i],
                                p->listener_requires_auth[i] ? 1 : 0,
                                p->max_request_bytes[i]);
    }
    for (size_t i = 0; i < QIHSE_EGRESS_CLASS_COUNT && off < cap; i++) {
        off += (size_t)snprintf(out + off, cap - off, "\t%d", p->egress[i] ? 1 : 0);
    }
}

static bool net_profile_decode(const char* blob, qihse_net_profile_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    /* Walk the record field by field so empty bind addresses survive. */
    const char* p = blob;
    char f[128];
    p = sa_next_field(p, out->service, sizeof(out->service));
    p = sa_next_field(p, out->version, sizeof(out->version));
    p = sa_next_field(p, f, sizeof(f));
    out->generation = (uint64_t)strtoull(f, NULL, 10);
    p = sa_next_field(p, f, sizeof(f));
    size_t listener_count = (size_t)strtoul(f, NULL, 10);
    p = sa_next_field(p, f, sizeof(f));
    out->egress[QIHSE_EGRESS_UNRESTRICTED_INTERNET] = strtoul(f, NULL, 10) != 0;
    if (listener_count > sizeof(out->ports) / sizeof(out->ports[0])) return false;

    for (size_t i = 0; i < listener_count; i++) {
        p = sa_next_field(p, f, sizeof(f));
        out->ports[i] = (uint32_t)strtoul(f, NULL, 10);
        p = sa_next_field(p, out->bind_addresses[i], sizeof(out->bind_addresses[i]));
        p = sa_next_field(p, f, sizeof(f));
        out->listener_requires_auth[i] = strtoul(f, NULL, 10) != 0;
        p = sa_next_field(p, f, sizeof(f));
        out->max_request_bytes[i] = (size_t)strtoull(f, NULL, 10);
    }
    out->listener_count = listener_count;
    for (size_t i = 0; i < QIHSE_EGRESS_CLASS_COUNT; i++) {
        if (i == (size_t)QIHSE_EGRESS_UNRESTRICTED_INTERNET) continue; /* already read */
        p = sa_next_field(p, f, sizeof(f));
        out->egress[i] = strtoul(f, NULL, 10) != 0;
    }
    return true;
}

bool qihse_net_profile_put(void* store_void, void* user_void,
                           const qihse_net_profile_t* profile) {
    if (!store_void || !user_void || !profile) return false;
    if (profile->service[0] == '\0' || profile->version[0] == '\0') return false;
    if (profile->listener_count > sizeof(profile->ports) / sizeof(profile->ports[0])) return false;
    char key[192];
    net_profile_key(profile->service, profile->version, key, sizeof(key));
    char blob[4096];
    net_profile_encode(profile, blob, sizeof(blob));
    return qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                             (qihse_user_t*)user_void);
}

bool qihse_net_profile_get(void* store_void, void* user_void,
                           const char* service, const char* version,
                           qihse_net_profile_t* out) {
    if (!store_void || !user_void || !service || !version || !out) return false;
    char key[192];
    net_profile_key(service, version, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = net_profile_decode(blob, out);
    free(blob);
    return ok;
}

bool qihse_net_profile_is_egress_restricted(const qihse_net_profile_t* profile) {
    if (!profile) return false;
    /* Criterion 26: QIHSE itself must never require unrestricted Internet
     * egress.  Package/CVE fetching belongs to dedicated update domains. */
    return !profile->egress[QIHSE_EGRESS_UNRESTRICTED_INTERNET];
}

size_t qihse_net_profile_unexpected_listeners(const qihse_net_profile_t* profile,
                                              const qihse_runtime_observation_t* observed,
                                              uint32_t* out_ports, size_t out_cap) {
    if (!profile || !observed) return 0;
    size_t unexpected = 0;
    for (uint32_t i = 0; i < observed->listening_port_count; i++) {
        uint32_t port = observed->listening_ports[i];
        bool declared = false;
        for (size_t j = 0; j < profile->listener_count; j++) {
            if (profile->ports[j] == port) { declared = true; break; }
        }
        if (declared) continue;
        if (out_ports && unexpected < out_cap) out_ports[unexpected] = port;
        unexpected++;
    }
    return unexpected;
}
