#ifndef QIHSE_TSX_LOCK_H
#define QIHSE_TSX_LOCK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <immintrin.h>

#ifndef _XBEGIN_STARTED
#define _XBEGIN_STARTED (~0u)
#endif
#ifndef _XABORT_EXPLICIT
#define _XABORT_EXPLICIT (1 << 0)
#endif
#ifndef _XABORT_RETRY
#define _XABORT_RETRY (1 << 1)
#endif
#ifndef _XABORT_CONFLICT
#define _XABORT_CONFLICT (1 << 2)
#endif
#ifndef _XABORT_CAPACITY
#define _XABORT_CAPACITY (1 << 3)
#endif
#ifndef _XABORT_DEBUG
#define _XABORT_DEBUG (1 << 4)
#endif
#ifndef _XABORT_NESTED
#define _XABORT_NESTED (1 << 5)
#endif

/*
 * Production-grade, lemming-safe RTM lock elision structure.
 * fallback_held is padded to a 64-byte cache line boundary to prevent
 * false sharing with the underlying pthread_rwlock_t during speculative
 * reads and fallback transitions.
 */
typedef struct __attribute__((aligned(64))) {
    volatile uint32_t fallback_held;
    uint32_t _pad[15];
    pthread_rwlock_t rwlock;
} qihse_tsx_rwlock_t;

/* Check RTM hardware capability dynamically */
static inline bool qihse_has_rtm_support(void) {
    static int cached = -1;
    if (__builtin_expect(cached != -1, 1)) {
        return cached == 1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0), "c"(0));
    if (eax >= 7) {
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(7), "c"(0));
        /* EBX bit 11 represents Intel RTM */
        if (ebx & (1u << 11)) {
            cached = 1;
            return true;
        }
    }
#endif
    cached = 0;
    return false;
}

#if defined(__x86_64__) || defined(_M_X64)
static inline unsigned int qihse_rtm_xbegin(void) {
    unsigned int ret = _XBEGIN_STARTED;
    __asm__ volatile(".byte 0xc7, 0xf8; .long 0" : "+a"(ret) :: "memory");
    return ret;
}

static inline void qihse_rtm_xend(void) {
    __asm__ volatile(".byte 0x0f, 0x01, 0xd5" ::: "memory");
}

static inline void qihse_rtm_xabort(const unsigned int code) {
    __asm__ volatile(".byte 0xc6, 0xf8, %c0" :: "i"(code) : "memory");
}

static inline int qihse_rtm_xtest(void) {
    unsigned char out;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd6; setnz %0" : "=r"(out) :: "memory");
    return (int)out;
}
#else
static inline unsigned int qihse_rtm_xbegin(void) { return 0; }
static inline void qihse_rtm_xend(void) {}
static inline void qihse_rtm_xabort(const unsigned int code) { (void)code; }
static inline int qihse_rtm_xtest(void) { return 0; }
#endif

static inline int qihse_tsx_rwlock_init(qihse_tsx_rwlock_t* l) {
    if (!l) return -1;
    l->fallback_held = 0;
    for (int i = 0; i < 15; i++) {
        l->_pad[i] = 0;
    }
    return pthread_rwlock_init(&l->rwlock, NULL);
}

static inline int qihse_tsx_rwlock_destroy(qihse_tsx_rwlock_t* l) {
    if (!l) return -1;
    l->fallback_held = 0;
    return pthread_rwlock_destroy(&l->rwlock);
}

/*
 * Reader elision:
 * 1. Check fallback_held == 0 before _xbegin() to avoid lemming abort storm.
 * 2. Inside transaction, verify fallback_held == 0 to subscribe fallback_held
 *    into L1D read set, automatically aborting if a writer acquires fallback lock.
 * 3. On abort with _XABORT_RETRY or _XABORT_CONFLICT, pause and retry up to 3 times
 *    before falling back to pthread_rwlock_rdlock. On capacity or explicit abort,
 *    fall back immediately.
 *
 * Returns 1 if speculative transaction active, 0 if fallback read lock acquired.
 */
static inline int qihse_tsx_rdlock(qihse_tsx_rwlock_t* l) {
    if (qihse_has_rtm_support()) {
        int retries = 3;
        while (retries > 0) {
            while (__atomic_load_n(&l->fallback_held, __ATOMIC_RELAXED) != 0) {
                _mm_pause();
            }

            unsigned int status = qihse_rtm_xbegin();
            if (status == _XBEGIN_STARTED) {
                if (l->fallback_held != 0) {
                    qihse_rtm_xabort(0xff);
                }
                return 1;
            }

            if ((status & _XABORT_RETRY) || (status & _XABORT_CONFLICT)) {
                _mm_pause();
                retries--;
            } else {
                break;
            }
        }
    }

    pthread_rwlock_rdlock(&l->rwlock);
    return 0;
}

/*
 * Writer path: acquire pthread_rwlock_wrlock, set fallback_held = 1.
 */
static inline void qihse_tsx_wrlock(qihse_tsx_rwlock_t* l) {
    pthread_rwlock_wrlock(&l->rwlock);
    __atomic_store_n(&l->fallback_held, 1, __ATOMIC_RELEASE);
}

/*
 * Fast-path writer elision for short, non-resizing modifications.
 * Returns 1 if speculative transaction active, 0 if fallback write lock acquired.
 */
static inline int qihse_tsx_wrlock_elided(qihse_tsx_rwlock_t* l) {
    if (qihse_has_rtm_support()) {
        int retries = 3;
        while (retries > 0) {
            while (__atomic_load_n(&l->fallback_held, __ATOMIC_RELAXED) != 0) {
                _mm_pause();
            }

            unsigned int status = qihse_rtm_xbegin();
            if (status == _XBEGIN_STARTED) {
                if (l->fallback_held != 0) {
                    qihse_rtm_xabort(0xff);
                }
                return 1;
            }

            if ((status & _XABORT_RETRY) || (status & _XABORT_CONFLICT)) {
                _mm_pause();
                retries--;
            } else {
                break;
            }
        }
    }

    pthread_rwlock_wrlock(&l->rwlock);
    __atomic_store_n(&l->fallback_held, 1, __ATOMIC_RELEASE);
    return 0;
}

/*
 * Unified unlock:
 * If in transaction (_xtest() != 0), commit with _xend().
 * Otherwise, clear fallback_held = 0 if writer and unlock pthread rwlock.
 */
static inline void qihse_tsx_unlock(qihse_tsx_rwlock_t* l) {
    if (qihse_has_rtm_support()) {
        if (qihse_rtm_xtest()) {
            qihse_rtm_xend();
            return;
        }
    }
    if (l->fallback_held) {
        __atomic_store_n(&l->fallback_held, 0, __ATOMIC_RELEASE);
    }
    pthread_rwlock_unlock(&l->rwlock);
}

static inline void qihse_tsx_rdunlock(qihse_tsx_rwlock_t* l) {
    qihse_tsx_unlock(l);
}

static inline void qihse_tsx_wrunlock(qihse_tsx_rwlock_t* l) {
    qihse_tsx_unlock(l);
}

#endif /* QIHSE_TSX_LOCK_H */
