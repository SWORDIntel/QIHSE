/*
 * test_guard_throttle.c — Unit tests for the System Guard bus-saturation
 * sliding-window throttling.
 */
#include "qihse_system_guard.h"
#include "qihse_platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Test 1: Window starts safe; recording a small amount keeps it safe. */
static void test_initial_safe(void) {
    qihse_system_guard_window_t* w = qihse_system_guard_window_create(1000, 0.8);
    assert(w);
    assert(qihse_system_guard_window_safe(w));
    qihse_system_guard_window_record(w, 1024);
    assert(qihse_system_guard_window_safe(w));
    uint64_t bps = qihse_system_guard_window_bps(w);
    assert(bps > 0);
    uint64_t threshold = qihse_system_guard_window_threshold_bps(w);
    assert(threshold > 0);
    assert(bps < threshold);
    qihse_system_guard_window_destroy(w);
    printf("PASS initial safe\n");
}

/* Test 2: Recording enough bytes to exceed the threshold makes it unsafe. */
static void test_saturation(void) {
    /* Use a very small saturation fraction to make it easy to exceed */
    qihse_system_guard_window_t* w = qihse_system_guard_window_create(1000, 0.01);
    assert(w);
    uint64_t threshold = qihse_system_guard_window_threshold_bps(w);
    assert(threshold > 0);

    /* Record enough bytes to exceed the threshold.
     * threshold is in bytes/second, window is 1 second, so recording
     * threshold+1 bytes should make it unsafe. */
    qihse_system_guard_window_record(w, threshold + 1);
    assert(!qihse_system_guard_window_safe(w));

    qihse_system_guard_window_destroy(w);
    printf("PASS saturation detected\n");
}

/* Test 3: Sliding window expires old entries. */
static void test_window_expiry(void) {
    /* 200ms window — old entries should expire quickly */
    qihse_system_guard_window_t* w = qihse_system_guard_window_create(200, 0.01);
    assert(w);
    uint64_t threshold = qihse_system_guard_window_threshold_bps(w);

    /* Record enough to saturate */
    qihse_system_guard_window_record(w, threshold + 1);
    assert(!qihse_system_guard_window_safe(w));

    /* Wait for the window to expire (300ms > 200ms window) */
    sleep_ms(300);
    assert(qihse_system_guard_window_safe(w));

    qihse_system_guard_window_destroy(w);
    printf("PASS window expiry\n");
}

/* Test 4: Incremental recording accumulates within the window. */
static void test_incremental_accumulation(void) {
    qihse_system_guard_window_t* w = qihse_system_guard_window_create(1000, 0.01);
    assert(w);
    uint64_t threshold = qihse_system_guard_window_threshold_bps(w);

    /* Record in small increments that sum to exceed the threshold */
    uint64_t per_record = threshold / 10 + 1;
    for (int i = 0; i < 11; i++) {
        qihse_system_guard_window_record(w, per_record);
    }
    assert(!qihse_system_guard_window_safe(w));

    qihse_system_guard_window_destroy(w);
    printf("PASS incremental accumulation\n");
}

/* Test 5: NULL window is always safe (no throttling). */
static void test_null_safe(void) {
    assert(qihse_system_guard_window_safe(NULL));
    assert(qihse_system_guard_window_bps(NULL) == 0);
    assert(qihse_system_guard_window_threshold_bps(NULL) == 0);
    /* record on NULL should be a no-op */
    qihse_system_guard_window_record(NULL, 1024);
    printf("PASS null window safe\n");
}

/* Test 6: Default arguments (window_ms=0, fraction=0) use sensible defaults. */
static void test_defaults(void) {
    qihse_system_guard_window_t* w = qihse_system_guard_window_create(0, 0.0);
    assert(w);
    uint64_t threshold = qihse_system_guard_window_threshold_bps(w);
    assert(threshold > 0);
    assert(qihse_system_guard_window_safe(w));
    qihse_system_guard_window_destroy(w);
    printf("PASS defaults\n");
}

int main(void) {
    test_initial_safe();
    test_saturation();
    test_window_expiry();
    test_incremental_accumulation();
    test_null_safe();
    test_defaults();
    printf("guard throttle tests passed\n");
    return 0;
}
