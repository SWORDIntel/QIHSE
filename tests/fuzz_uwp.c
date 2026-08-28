/*
 * fuzz_uwp.c — libFuzzer harness for the QIHSE Unified Wire Protocol (UWP).
 *
 * Exercises qihse_uwp_handle_payload() with arbitrary fuzz input to find
 * crashes in frame parsing, dispatch, and payload handling.
 *
 * Build:
 *   clang -fsanitize=fuzzer -I. -I./include tests/fuzz_uwp.c -L. -lqihse -lpthread -lm -o tests/fuzz_uwp
 *
 * Run:
 *   ./tests/fuzz_uwp -max_total_time=60
 *
 * The harness creates a minimal qihse_uwp_context_t (static, initialized once)
 * with NULL engine pointers and a mock authenticated user. The fuzz input is
 * passed directly to qihse_uwp_handle_payload(), which parses the 15-byte UWP
 * header and routes the remaining bytes through the dispatch table.
 */

#include "qihse_uwp.h"
#include "qihse_auth.h"

#include <stdint.h>
#include <string.h>

static qihse_uwp_context_t g_ctx;
static int g_initialized = 0;

static void ensure_init(void)
{
    if (g_initialized) return;
    g_initialized = 1;

    /* Initialize the auth subsystem once */
    qihse_auth_init();

    /* Get the operator (user 0) — a fully-privileged user */
    qihse_user_t* op = qihse_auth_get_user(0);
    if (op) {
        /* Set a known password so we can authenticate */
        qihse_auth_modify_user(op, 0, NULL, "fuzz-uwp-password", -1, -1);
    }

    /* Zero out the context — all engine pointers are NULL.
     * The dispatch logic handles NULL engine pointers gracefully:
     *   - Header validation (magic, version, length) happens first.
     *   - Auth checks happen before engine dispatch.
     *   - Engine-specific paths check their pointer before use. */
    memset(&g_ctx, 0, sizeof(g_ctx));
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ensure_init();

    /* qihse_uwp_handle_payload parses the 15-byte header from the input
     * and routes the remaining bytes. It handles:
     *   - Buffers shorter than the header size (returns early)
     *   - Oversized payload_length (returns early)
     *   - Bad magic / version (rejected by uwp_route_payload)
     *   - NULL user_slot (non-AUTH targets get ERR_AUTH)
     *
     * The goal is to find crashes in any of these paths. */
    qihse_uwp_handle_payload(&g_ctx, data, size);

    return 0;
}

/*
 * Standalone main for non-fuzzer builds (e.g. compiling without
 * -fsanitize=fuzzer to verify the harness compiles cleanly).
 * When built with libFuzzer (-fsanitize=fuzzer), the linker provides
 * its own main() that calls LLVMFuzzerTestOneInput, so this main is
 * excluded via the __AFL_FUZZ_TESTCASE_LEN guard is not needed —
 * libFuzzer defines main, and this would conflict. We guard with
 * a macro that libFuzzer sets.
 */
#ifndef FUZZER_STANDALONE_MAIN
#define FUZZER_STANDALONE_MAIN 1
#endif

#if FUZZER_STANDALONE_MAIN
/* When not using -fsanitize=fuzzer, provide a simple main that reads
 * from stdin and feeds it to the fuzzer entry point. This lets us
 * verify the harness compiles and runs without a fuzzer engine.
 *
 * When building with clang -fsanitize=fuzzer, the fuzzer runtime
 * provides main(), so we must NOT define our own. Compile with
 * -DFUZZER_STANDALONE_MAIN=0 when using -fsanitize=fuzzer, or simply
 * let the fuzzer's main take precedence (clang -fsanitize=fuzzer
 * defines main, causing a duplicate-symbol error here — so use
 * -DFUZZER_STANDALONE_MAIN=0 for fuzzer builds). */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    ensure_init();

    /* Read input from stdin (or a file argument) and feed to the harness */
    uint8_t buf[65536];
    size_t n = 0;
    FILE* f = stdin;

    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            fprintf(stderr, "Cannot open %s, reading stdin\n", argv[1]);
            f = stdin;
        }
    }

    n = fread(buf, 1, sizeof(buf), f);
    if (f != stdin) fclose(f);

    LLVMFuzzerTestOneInput(buf, n);

    printf("Standalone fuzz harness: processed %zu bytes, no crash.\n", n);
    return 0;
}
#endif /* FUZZER_STANDALONE_MAIN */
