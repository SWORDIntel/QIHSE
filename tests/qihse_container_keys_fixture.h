#ifndef QIHSE_TEST_CONTAINER_KEYS_H
#define QIHSE_TEST_CONTAINER_KEYS_H

#include "../persistence/qihse_pqc_crypto.h"
#include <assert.h>
#include <stdlib.h>

/* Container-backed fixtures use their own generated keys. They must not
 * depend on a developer's installed keys or disable integrity verification. */
static void qihse_test_container_keys(const char *directory) {
    assert(setenv("QIHSE_KEY_DIR", directory, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(unsetenv("QIHSE_ALLOW_INSECURE_CONTAINER") == 0);
    assert(unsetenv("QIHSE_SKIP_INTEGRITY") == 0);
    assert(qihse_pqc_init_providers() >= 0);
    assert(qihse_pqc_keygen(directory));
}

#endif
