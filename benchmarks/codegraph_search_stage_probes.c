#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
struct frame { void *function; uint64_t wall, cpu; };
static struct frame frames[64];
static unsigned depth;
static uint64_t stamp(clockid_t id) { struct timespec ts; clock_gettime(id, &ts); return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec; }
void __cyg_profile_func_enter(void *function, void *caller) {
    (void)caller;
    if (depth < 64) frames[depth] = (struct frame){function, stamp(CLOCK_MONOTONIC), stamp(CLOCK_PROCESS_CPUTIME_ID)};
    depth++;
}
void __cyg_profile_func_exit(void *function, void *caller);
void cg_probe_begin(uintptr_t id) { __cyg_profile_func_enter((void *)id, 0); }
void cg_probe_end(uintptr_t id) { __cyg_profile_func_exit((void *)id, 0); }
void __cyg_profile_func_exit(void *function, void *caller) {
    (void)caller;
    if (!depth || --depth >= 64) return;
    uint64_t wall = stamp(CLOCK_MONOTONIC), cpu = stamp(CLOCK_PROCESS_CPUTIME_ID);
    struct frame *f = &frames[depth];
    if (f->function == function) fprintf(stderr, "CG_STAGE pid=%ld function=%p wall_us=%llu cpu_us=%llu\n", (long)getpid(), function, (unsigned long long)((wall-f->wall)/1000), (unsigned long long)((cpu-f->cpu)/1000));
}
