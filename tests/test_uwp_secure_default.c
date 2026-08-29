/* Verify that the public UWP listener fails closed unless certificate TLS is configured. */

#include "qihse_uwp.h"
#include "qihse_uwp_tls.h"
#include "qihse_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    qihse_auth_init();

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    if (!operator_user) {
        fprintf(stderr, "FAIL: operator user unavailable\n");
        return 1;
    }

    /* The server independently refuses the seeded default operator password.
     * Rotate it in this isolated test process so we can exercise transport policy. */
    if (!qihse_auth_modify_user(operator_user, 0, NULL,
                                "UWP-TLS-default-regression-only-2026!",
                                -1, -1)) {
        fprintf(stderr, "FAIL: could not rotate test operator password\n");
        return 1;
    }

    unsetenv("QIHSE_UWP_ALLOW_INSECURE");

    qihse_uwp_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* No TLS context must fail before binding/listening. */
    if (qihse_start_uwp_server(&ctx, 0, "127.0.0.1")) {
        fprintf(stderr, "FAIL: UWP started without TLS while insecure opt-in was absent\n");
        return 1;
    }

    /* The legacy symmetric ChaCha20-Poly1305 context is encrypted, but it is
     * not certificate TLS 1.3. It must therefore also fail closed by default. */
    ctx.tls_ctx = qihse_uwp_tls_ctx_create();
    if (!ctx.tls_ctx) {
        fprintf(stderr, "FAIL: could not create legacy AEAD context for regression test\n");
        return 1;
    }

    if (qihse_start_uwp_server(&ctx, 0, "127.0.0.1")) {
        fprintf(stderr, "FAIL: UWP accepted legacy AEAD as the secure default\n");
        qihse_uwp_tls_ctx_destroy(ctx.tls_ctx);
        return 1;
    }

    qihse_uwp_tls_ctx_destroy(ctx.tls_ctx);
    puts("PASS: UWP requires certificate-backed TLS by default");
    return 0;
}
