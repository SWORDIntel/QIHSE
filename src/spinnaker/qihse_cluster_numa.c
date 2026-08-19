#include "qihse_cluster_numa.h"
#include "qihse_platform.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <linux/mempolicy.h>
#include <sched.h>
#include <sys/syscall.h>
#endif

static size_t qihse_cluster_round_up(size_t value, size_t alignment) {
    if (value == 0 || alignment == 0 || value > SIZE_MAX - (alignment - 1u)) return 0;
    return (value + alignment - 1u) & ~(alignment - 1u);
}

#ifndef _WIN32
static int qihse_cluster_nodemask(int node_id, unsigned long* mask, size_t word_count, unsigned long* maxnode) {
    if (node_id < 0) return 0;
    size_t bits = sizeof(unsigned long) * CHAR_BIT;
    size_t word = (size_t)node_id / bits;
    if (word >= word_count) return E2BIG;
    memset(mask, 0, word_count * sizeof(*mask));
    mask[word] = 1ul << ((size_t)node_id % bits);
    *maxnode = (unsigned long)node_id + 1ul;
    return 0;
}

static int qihse_cluster_set_thread_mempolicy(int node_id) {
#if defined(SYS_set_mempolicy)
    unsigned long mask[16];
    unsigned long maxnode = 0;
    int error = qihse_cluster_nodemask(node_id, mask, sizeof(mask) / sizeof(mask[0]), &maxnode);
    if (error != 0) return error;
    if (syscall(SYS_set_mempolicy, MPOL_BIND, mask, maxnode) != 0) return errno;
    return 0;
#else
    (void)node_id;
    return ENOTSUP;
#endif
}

static int qihse_cluster_bind_memory(void* address, size_t size, int node_id) {
#if defined(SYS_mbind)
    unsigned long mask[16];
    unsigned long maxnode = 0;
    int error = qihse_cluster_nodemask(node_id, mask, sizeof(mask) / sizeof(mask[0]), &maxnode);
    if (error != 0) return error;
    if (syscall(SYS_mbind, address, size, MPOL_BIND, mask, maxnode, 0ul) != 0) return errno;
    return 0;
#else
    (void)address;
    (void)size;
    (void)node_id;
    return ENOTSUP;
#endif
}
#endif

size_t qihse_cluster_available_cpus(int* out_cpu_ids, size_t capacity) {
#ifdef _WIN32
    DWORD_PTR mask = 0;
    DWORD_PTR system_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &mask, &system_mask)) return 0;
    size_t count = 0;
    for (unsigned int cpu = 0; cpu < sizeof(mask) * CHAR_BIT; cpu++) {
        if ((mask & ((DWORD_PTR)1u << cpu)) == 0) continue;
        if (out_cpu_ids && count < capacity) out_cpu_ids[count] = (int)cpu;
        count++;
    }
    return count;
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpuset), &cpuset) != 0) return 0;
    size_t count = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &cpuset)) continue;
        if (out_cpu_ids && count < capacity) out_cpu_ids[count] = cpu;
        count++;
    }
    return count;
#endif
}

bool qihse_cluster_bind_current_thread(int cpu_core_id, int numa_node_id, bool strict, qihse_cluster_binding_result_t* out_result) {
    qihse_cluster_binding_result_t result;
    memset(&result, 0, sizeof(result));
    result.cpu_core_id = cpu_core_id;
    result.numa_node_id = numa_node_id;
#ifdef _WIN32
    if (cpu_core_id >= 0 && cpu_core_id < (int)(sizeof(DWORD_PTR) * CHAR_BIT)) {
        if (SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1u << cpu_core_id) != 0) {
            result.cpu_affinity_applied = true;
        } else {
            result.cpu_affinity_error = (int)GetLastError();
        }
    } else if (cpu_core_id >= 0) {
        result.cpu_affinity_error = EINVAL;
    }
    if (numa_node_id >= 0) result.numa_policy_error = ENOTSUP;
#else
    if (cpu_core_id >= 0 && cpu_core_id < CPU_SETSIZE) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_core_id, &cpuset);
        int error = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
        if (error == 0) result.cpu_affinity_applied = true;
        else result.cpu_affinity_error = error;
    } else if (cpu_core_id >= 0) {
        result.cpu_affinity_error = EINVAL;
    }
    if (numa_node_id >= 0) {
        result.numa_policy_error = qihse_cluster_set_thread_mempolicy(numa_node_id);
        result.numa_policy_applied = result.numa_policy_error == 0;
    }
#endif
    if (out_result) *out_result = result;
    if (!strict) return true;
    if (cpu_core_id >= 0 && !result.cpu_affinity_applied) return false;
    if (numa_node_id >= 0 && !result.numa_policy_applied) return false;
    return true;
}

bool qihse_cluster_advise_hugepages(void* address, size_t size) {
    if (!address || size == 0) {
        errno = EINVAL;
        return false;
    }
#ifdef _WIN32
    errno = ENOTSUP;
    return false;
#else
#ifdef MADV_HUGEPAGE
    return madvise(address, size, MADV_HUGEPAGE) == 0;
#else
    errno = ENOTSUP;
    return false;
#endif
#endif
}

bool qihse_cluster_memory_alloc(qihse_cluster_memory_t* memory, size_t size, int numa_node_id, qihse_hugepage_policy_t policy, bool zero_memory) {
    if (!memory || size == 0) {
        errno = EINVAL;
        return false;
    }
    memset(memory, 0, sizeof(*memory));
    memory->requested_size = size;
    memory->numa_node_id = numa_node_id;
    memory->policy = policy;
#ifdef _WIN32
    size_t alignment = policy >= QIHSE_HUGEPAGES_PREFER_EXPLICIT ? QIHSE_CLUSTER_HUGEPAGE_SIZE : 4096u;
    memory->mapped_size = qihse_cluster_round_up(size, alignment);
    if (memory->mapped_size == 0) {
        memory->allocation_error = EOVERFLOW;
        errno = EOVERFLOW;
        return false;
    }
    memory->address = VirtualAlloc(NULL, memory->mapped_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory->address) {
        memory->allocation_error = (int)GetLastError();
        return false;
    }
    if (policy == QIHSE_HUGEPAGES_REQUIRE_EXPLICIT) {
        memory->hugepage_error = ENOTSUP;
        VirtualFree(memory->address, 0, MEM_RELEASE);
        memory->address = NULL;
        errno = ENOTSUP;
        return false;
    }
    if (numa_node_id >= 0) memory->numa_error = ENOTSUP;
#else
    bool explicit_requested = policy == QIHSE_HUGEPAGES_PREFER_EXPLICIT || policy == QIHSE_HUGEPAGES_REQUIRE_EXPLICIT;
    size_t alignment = explicit_requested ? QIHSE_CLUSTER_HUGEPAGE_SIZE : (size_t)sysconf(_SC_PAGESIZE);
    if (alignment == 0 || alignment == (size_t)-1) alignment = 4096u;
    memory->mapped_size = qihse_cluster_round_up(size, alignment);
    if (memory->mapped_size == 0) {
        memory->allocation_error = EOVERFLOW;
        errno = EOVERFLOW;
        return false;
    }
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(MAP_HUGETLB)
    if (explicit_requested) {
        int huge_flags = flags | MAP_HUGETLB;
#if defined(MAP_HUGE_2MB)
        huge_flags |= MAP_HUGE_2MB;
#endif
        memory->address = mmap(NULL, memory->mapped_size, PROT_READ | PROT_WRITE, huge_flags, -1, 0);
        if (memory->address != MAP_FAILED) memory->explicit_hugepages = true;
        else {
            memory->hugepage_error = errno;
            memory->address = NULL;
        }
    }
#else
    if (explicit_requested) memory->hugepage_error = ENOTSUP;
#endif
    if (!memory->address) {
        if (policy == QIHSE_HUGEPAGES_REQUIRE_EXPLICIT) {
            memory->allocation_error = memory->hugepage_error ? memory->hugepage_error : ENOMEM;
            errno = memory->allocation_error;
            return false;
        }
        alignment = (size_t)sysconf(_SC_PAGESIZE);
        if (alignment == 0 || alignment == (size_t)-1) alignment = 4096u;
        memory->mapped_size = qihse_cluster_round_up(size, alignment);
        memory->address = mmap(NULL, memory->mapped_size, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (memory->address == MAP_FAILED) {
            memory->address = NULL;
            memory->allocation_error = errno;
            return false;
        }
    }
    if (!memory->explicit_hugepages && policy != QIHSE_HUGEPAGES_DISABLED) {
        if (qihse_cluster_advise_hugepages(memory->address, memory->mapped_size)) memory->transparent_hugepages = true;
        else if (memory->hugepage_error == 0) memory->hugepage_error = errno;
    }
    if (numa_node_id >= 0) {
        memory->numa_error = qihse_cluster_bind_memory(memory->address, memory->mapped_size, numa_node_id);
        memory->numa_bound = memory->numa_error == 0;
    }
#endif
    if (zero_memory) memset(memory->address, 0, memory->mapped_size);
    return true;
}

void qihse_cluster_memory_free(qihse_cluster_memory_t* memory) {
    if (!memory || !memory->address) return;
#ifdef _WIN32
    VirtualFree(memory->address, 0, MEM_RELEASE);
#else
    munmap(memory->address, memory->mapped_size);
#endif
    memset(memory, 0, sizeof(*memory));
}
