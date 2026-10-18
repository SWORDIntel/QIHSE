#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qihse_container.h"

/* Dedicated process: confirms no KEM key cannot silently enable a public
 * zero-key HMAC verifier or create a writable persistence container.
 * The CI fixture environment may opt into insecure test mode, but this test
 * removes that opt-in before exercising the production default. */
int main(void) {
    char missing_key_dir[] = "build/qihse_ctr_no_keys_XXXXXX";
    assert(mkdtemp(missing_key_dir) != NULL);
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/no-key.qdb", missing_key_dir);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(setenv("QIHSE_KEY_DIR", missing_key_dir, 1) == 0);
    assert(unsetenv("QIHSE_ALLOW_INSECURE_CONTAINER") == 0);
    assert(unsetenv("QIHSE_SKIP_INTEGRITY") == 0);

    qihse_container_t ctr;
    errno = 0;
    assert(!qihse_ctr_open_write(path, true, &ctr));
    assert(errno == EACCES);
    assert(access(path, F_OK) != 0);
    errno = 0;
    assert(!qihse_ctr_open_read(path, &ctr));
    assert(errno == EACCES);
    assert(access(path, F_OK) != 0);
    assert(rmdir(missing_key_dir) == 0);
    puts("PASS: absent persistence key fails closed before file creation");
    return 0;
}
