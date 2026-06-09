/*
 * QIHSE - Host Memory Topology Probe Implementation
 */

#include "../include/qihse_memory_topology_probe.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#endif

#define QIHSE_PROBE_KIB 1024ull
#define QIHSE_PROBE_MIB (1024ull * 1024ull)
#define QIHSE_PROBE_GIB (1024ull * 1024ull * 1024ull)

#define QIHSE_PROBE_PROC_MEMINFO "/proc/meminfo"
#define QIHSE_PROBE_SYS_NODE_ONLINE "/sys/devices/system/node/online"
#define QIHSE_PROBE_SYS_NODE_DIR "/sys/devices/system/node"

static uint64_t qihse_probe_min_u64(uint64_t a, uint64_t b) {
    return a < b ? a : b;
}

static uint64_t qihse_probe_max_u64(uint64_t a, uint64_t b) {
    return a > b ? a : b;
}

static size_t qihse_probe_size_from_u64(uint64_t value) {
    if (value > (uint64_t)SIZE_MAX) {
        return SIZE_MAX;
    }
    return (size_t)value;
}

static bool qihse_probe_read_file(const char* path, char* buffer, size_t buffer_size) {
    FILE* file;
    size_t bytes_read;

    if (!path || !buffer || buffer_size == 0u) {
        return false;
    }

    file = fopen(path, "r");
    if (!file) {
        return false;
    }

    bytes_read = fread(buffer, 1u, buffer_size - 1u, file);
    buffer[bytes_read] = '\0';
    fclose(file);
    return bytes_read > 0u;
}

static bool qihse_probe_parse_kb_field(const char* line,
                                       const char* field,
                                       uint64_t* out_bytes) {
    const char* value;
    char* end = NULL;
    unsigned long long kb;
    size_t field_len;

    if (!line || !field || !out_bytes) {
        return false;
    }

    field_len = strlen(field);
    if (strncmp(line, field, field_len) != 0) {
        return false;
    }

    value = line + field_len;
    while (*value && isspace((unsigned char)*value)) {
        value++;
    }

    errno = 0;
    kb = strtoull(value, &end, 10);
    if (errno != 0 || end == value) {
        return false;
    }

    *out_bytes = (uint64_t)kb * QIHSE_PROBE_KIB;
    return true;
}

static bool qihse_probe_parse_proc_meminfo(uint64_t* total_bytes,
                                           uint64_t* available_bytes) {
    FILE* file;
    char line[256];
    uint64_t total = 0u;
    uint64_t available = 0u;
    uint64_t free_bytes = 0u;

    file = fopen(QIHSE_PROBE_PROC_MEMINFO, "r");
    if (!file) {
        return false;
    }

    while (fgets(line, sizeof(line), file)) {
        uint64_t value = 0u;

        if (qihse_probe_parse_kb_field(line, "MemTotal:", &value)) {
            total = value;
        } else if (qihse_probe_parse_kb_field(line, "MemAvailable:", &value)) {
            available = value;
        } else if (qihse_probe_parse_kb_field(line, "MemFree:", &value)) {
            free_bytes = value;
        }
    }

    fclose(file);

    if (total == 0u) {
        return false;
    }

    if (available == 0u) {
        available = free_bytes;
    }

    if (total_bytes) {
        *total_bytes = total;
    }
    if (available_bytes) {
        *available_bytes = available ? available : total;
    }
    return true;
}

static bool qihse_probe_sysconf_memory(uint64_t* total_bytes,
                                       uint64_t* available_bytes,
                                       uint64_t* page_size) {
    long page_size_long;
    long phys_pages;
    long avail_pages;
    bool found = false;

#ifdef _WIN32
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    page_size_long = sys_info.dwPageSize;
#else
    page_size_long = sysconf(_SC_PAGESIZE);
#endif
    if (page_size_long <= 0) {
        page_size_long = 4096;
    }

    if (page_size) {
        *page_size = (uint64_t)page_size_long;
    }

#ifdef _SC_PHYS_PAGES
    phys_pages = sysconf(_SC_PHYS_PAGES);
#else
    phys_pages = -1;
#endif
#ifdef _SC_AVPHYS_PAGES
    avail_pages = sysconf(_SC_AVPHYS_PAGES);
#else
    avail_pages = -1;
#endif

    if (phys_pages > 0) {
        if (total_bytes) {
            *total_bytes = (uint64_t)phys_pages * (uint64_t)page_size_long;
        }
        found = true;
    }

    if (avail_pages > 0) {
        if (available_bytes) {
            *available_bytes = (uint64_t)avail_pages * (uint64_t)page_size_long;
        }
    } else if (available_bytes && total_bytes) {
        *available_bytes = *total_bytes;
    }

    return found;
}

static size_t qihse_probe_online_cpus(void) {
    long cpus;

#ifdef _WIN32
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    cpus = sys_info.dwNumberOfProcessors;
#else
#ifdef _SC_NPROCESSORS_ONLN
    cpus = sysconf(_SC_NPROCESSORS_ONLN);
#else
    cpus = -1;
#endif
#endif
    return cpus > 0 ? (size_t)cpus : 1u;
}

static bool qihse_probe_parse_node_list(const char* text,
                                        qihse_memory_host_node_t* nodes,
                                        size_t node_capacity,
                                        size_t* out_count) {
    const char* cursor = text;
    size_t count = 0u;

    if (!text || !out_count) {
        return false;
    }

    while (*cursor) {
        unsigned long start;
        unsigned long end;
        char* next = NULL;

        while (*cursor == ',' || isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (!*cursor) {
            break;
        }

        errno = 0;
        start = strtoul(cursor, &next, 10);
        if (errno != 0 || next == cursor) {
            return false;
        }

        end = start;
        cursor = next;
        if (*cursor == '-') {
            cursor++;
            errno = 0;
            end = strtoul(cursor, &next, 10);
            if (errno != 0 || next == cursor || end < start) {
                return false;
            }
            cursor = next;
        }

        while (start <= end) {
            if (nodes && count < node_capacity) {
                memset(&nodes[count], 0, sizeof(nodes[count]));
                nodes[count].node_id = (size_t)start;
                nodes[count].online = true;
            }
            count++;
            if (start == ULONG_MAX) {
                break;
            }
            start++;
        }
    }

    *out_count = count;
    return count > 0u;
}

static bool qihse_probe_sysfs_node_list(qihse_memory_host_node_t* nodes,
                                        size_t node_capacity,
                                        size_t* out_count) {
    char buffer[1024];

    if (!out_count) {
        return false;
    }

    if (!qihse_probe_read_file(QIHSE_PROBE_SYS_NODE_ONLINE, buffer, sizeof(buffer))) {
        return false;
    }

    return qihse_probe_parse_node_list(buffer, nodes, node_capacity, out_count);
}

static bool qihse_probe_scan_node_dirs(size_t* out_count) {
    DIR* dir;
    struct dirent* entry;
    size_t count = 0u;

    if (!out_count) {
        return false;
    }

    dir = opendir(QIHSE_PROBE_SYS_NODE_DIR);
    if (!dir) {
        return false;
    }

    while ((entry = readdir(dir)) != NULL) {
        const char* name = entry->d_name;
        char* end = NULL;

        if (strncmp(name, "node", 4u) != 0) {
            continue;
        }
        if (!isdigit((unsigned char)name[4])) {
            continue;
        }
        (void)strtoul(name + 4, &end, 10);
        if (end && *end == '\0') {
            count++;
        }
    }

    closedir(dir);
    if (count == 0u) {
        return false;
    }

    *out_count = count;
    return true;
}

static bool qihse_probe_parse_node_meminfo(size_t node_id,
                                           uint64_t* total_bytes,
                                           uint64_t* free_bytes,
                                           uint64_t* available_bytes) {
    char path[256];
    FILE* file;
    char line[256];
    uint64_t total = 0u;
    uint64_t free_value = 0u;
    uint64_t available = 0u;

    snprintf(path, sizeof(path), QIHSE_PROBE_SYS_NODE_DIR "/node%lu/meminfo",
             (unsigned long)node_id);

    file = fopen(path, "r");
    if (!file) {
        return false;
    }

    while (fgets(line, sizeof(line), file)) {
        char* field;
        uint64_t value = 0u;

        field = strstr(line, "MemTotal:");
        if (field && qihse_probe_parse_kb_field(field, "MemTotal:", &value)) {
            total = value;
            continue;
        }

        field = strstr(line, "MemFree:");
        if (field && qihse_probe_parse_kb_field(field, "MemFree:", &value)) {
            free_value = value;
            continue;
        }

        field = strstr(line, "MemAvailable:");
        if (field && qihse_probe_parse_kb_field(field, "MemAvailable:", &value)) {
            available = value;
        }
    }

    fclose(file);

    if (total == 0u) {
        return false;
    }

    if (total_bytes) {
        *total_bytes = total;
    }
    if (free_bytes) {
        *free_bytes = free_value;
    }
    if (available_bytes) {
        *available_bytes = available ? available : free_value;
    }
    return true;
}

static uint64_t qihse_probe_tier_capacity(uint64_t available_bytes,
                                          unsigned divisor,
                                          uint64_t min_bytes,
                                          uint64_t max_bytes) {
    uint64_t capacity;

    if (available_bytes == 0u) {
        return 0u;
    }

    capacity = available_bytes / divisor;
    capacity = qihse_probe_max_u64(capacity, min_bytes);
    capacity = qihse_probe_min_u64(capacity, max_bytes);
    capacity = qihse_probe_min_u64(capacity, available_bytes);
    return capacity;
}

static void qihse_probe_fill_topology(qihse_memory_topology_t* topology,
                                      uint64_t total_bytes,
                                      uint64_t available_bytes,
                                      size_t numa_nodes) {
    uint64_t effective_total = total_bytes;
    uint64_t effective_available = available_bytes;
    uint64_t superposition_capacity;
    uint64_t interaction_capacity;
    uint64_t entanglement_capacity;

    if (effective_total == 0u) {
        effective_total = QIHSE_PROBE_GIB;
    }
    if (effective_available == 0u || effective_available > effective_total) {
        effective_available = effective_total;
    }
    if (numa_nodes == 0u) {
        numa_nodes = 1u;
    }

    memset(topology, 0, sizeof(*topology));

    superposition_capacity = qihse_probe_tier_capacity(
        effective_available, 8u, 64ull * QIHSE_PROBE_MIB, 1ull * QIHSE_PROBE_GIB);
    interaction_capacity = qihse_probe_tier_capacity(
        effective_available, 16u, 32ull * QIHSE_PROBE_MIB, 512ull * QIHSE_PROBE_MIB);
    entanglement_capacity = effective_available;

    topology->superposition_buffer.capacity = qihse_probe_size_from_u64(superposition_capacity);
    topology->superposition_buffer.bandwidth_gbps = numa_nodes > 1u ? 80.0 : 100.0;
    topology->superposition_buffer.latency_ns = numa_nodes > 1u ? 15.0 : 10.0;
    topology->superposition_buffer.coherent = true;

    topology->interaction_cache.capacity = qihse_probe_size_from_u64(interaction_capacity);
    topology->interaction_cache.bandwidth_gbps = numa_nodes > 1u ? 45.0 : 60.0;
    topology->interaction_cache.latency_ns = numa_nodes > 1u ? 45.0 : 35.0;
    topology->interaction_cache.coherent = true;

    topology->entanglement_fabric.capacity = qihse_probe_size_from_u64(entanglement_capacity);
    topology->entanglement_fabric.bandwidth_gbps = numa_nodes > 1u ? 25.0 : 40.0;
    topology->entanglement_fabric.latency_ns = numa_nodes > 1u ? 120.0 : 80.0;
    topology->entanglement_fabric.coherent = true;

    topology->inter_tier_bandwidth_gbps = numa_nodes > 1u ? 25.0 : 64.0;
    topology->numa_nodes = numa_nodes;
}

void qihse_memory_topology_probe_init_result(
    qihse_memory_topology_probe_result_t* result
) {
    if (!result) {
        return;
    }

    memset(result, 0, sizeof(*result));
    result->page_size = 4096u;
    result->online_cpus = 1u;
    result->numa_nodes_detected = 1u;
    qihse_probe_fill_topology(&result->topology,
                              QIHSE_PROBE_GIB,
                              QIHSE_PROBE_GIB,
                              1u);
}

bool qihse_memory_topology_probe_host(
    qihse_memory_topology_probe_result_t* result
) {
    uint64_t proc_total = 0u;
    uint64_t proc_available = 0u;
    uint64_t sys_total = 0u;
    uint64_t sys_available = 0u;
    uint64_t page_size = 4096u;
    size_t numa_nodes = 0u;
    bool used_procfs;
    bool used_sysconf;
    bool used_sysfs;

    if (!result) {
        errno = EINVAL;
        return false;
    }

    qihse_memory_topology_probe_init_result(result);

    used_procfs = qihse_probe_parse_proc_meminfo(&proc_total, &proc_available);
    used_sysconf = qihse_probe_sysconf_memory(&sys_total, &sys_available, &page_size);
    used_sysfs = qihse_probe_sysfs_node_list(NULL, 0u, &numa_nodes);
    if (!used_sysfs) {
        used_sysfs = qihse_probe_scan_node_dirs(&numa_nodes);
    }

    result->page_size = page_size;
    result->online_cpus = qihse_probe_online_cpus();
    result->used_procfs = used_procfs;
    result->used_sysfs = used_sysfs;
    result->used_fallbacks = false;

    if (used_procfs) {
        result->total_bytes = proc_total;
        result->available_bytes = proc_available;
    } else if (used_sysconf) {
        result->total_bytes = sys_total;
        result->available_bytes = sys_available ? sys_available : sys_total;
        result->used_fallbacks = true;
    } else {
        result->total_bytes = QIHSE_PROBE_GIB;
        result->available_bytes = QIHSE_PROBE_GIB;
        result->used_fallbacks = true;
    }

    if (numa_nodes == 0u) {
        numa_nodes = 1u;
        result->used_fallbacks = true;
    }
    result->numa_nodes_detected = numa_nodes;

    qihse_probe_fill_topology(&result->topology,
                              result->total_bytes,
                              result->available_bytes,
                              result->numa_nodes_detected);
    return true;
}

bool qihse_memory_topology_probe(
    qihse_memory_topology_t* topology
) {
    qihse_memory_topology_probe_result_t result;

    if (!topology) {
        errno = EINVAL;
        return false;
    }

    if (!qihse_memory_topology_probe_host(&result)) {
        return false;
    }

    *topology = result.topology;
    return true;
}

bool qihse_memory_topology_probe_nodes(
    qihse_memory_host_node_t* nodes,
    size_t node_capacity,
    size_t* out_node_count
) {
    size_t node_count = 0u;
    size_t fill_count;
    bool used_sysfs;

    if (!out_node_count || (!nodes && node_capacity > 0u)) {
        errno = EINVAL;
        return false;
    }

    used_sysfs = qihse_probe_sysfs_node_list(nodes, node_capacity, &node_count);
    if (!used_sysfs) {
        uint64_t total = 0u;
        uint64_t available = 0u;

        if (nodes && node_capacity > 0u) {
            memset(&nodes[0], 0, sizeof(nodes[0]));
            nodes[0].node_id = 0u;
            nodes[0].online = true;
            if (qihse_probe_parse_proc_meminfo(&total, &available) ||
                qihse_probe_sysconf_memory(&total, &available, NULL)) {
                nodes[0].total_bytes = total;
                nodes[0].free_bytes = available;
                nodes[0].available_bytes = available;
            }
        }
        *out_node_count = 1u;
        return true;
    }

    fill_count = node_count < node_capacity ? node_count : node_capacity;
    for (size_t i = 0u; nodes && i < fill_count; i++) {
        uint64_t total = 0u;
        uint64_t free_bytes = 0u;
        uint64_t available = 0u;

        if (qihse_probe_parse_node_meminfo(nodes[i].node_id,
                                           &total,
                                           &free_bytes,
                                           &available)) {
            nodes[i].total_bytes = total;
            nodes[i].free_bytes = free_bytes;
            nodes[i].available_bytes = available;
        }
    }

    *out_node_count = node_count;
    return true;
}
