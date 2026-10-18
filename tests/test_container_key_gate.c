#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
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
    /* Existing files that are too short, public or symlinks cannot be key
     * material even if fopen would otherwise have succeeded. */
    char key_path[512];
    n = snprintf(key_path, sizeof(key_path), "%s/qihse_kem_key.pem", missing_key_dir);
    assert(n > 0 && (size_t)n < sizeof(key_path));
    int fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, "short", 5) == 5);
    assert(close(fd) == 0);
    assert(!qihse_ctr_open_write(path, true, &ctr));
    assert(errno == EACCES && access(path, F_OK) != 0);

    fd = open(key_path, O_WRONLY);
    assert(fd >= 0 && ftruncate(fd, 800) == 0);
    assert(close(fd) == 0 && chmod(key_path, 0644) == 0);
    assert(!qihse_ctr_open_write(path, true, &ctr));
    assert(errno == EACCES && access(path, F_OK) != 0);

    assert(unlink(key_path) == 0);
    assert(symlink("/dev/null", key_path) == 0);
    assert(!qihse_ctr_open_write(path, true, &ctr));
    assert(access(path, F_OK) != 0);
    assert(unlink(key_path) == 0);
    assert(rmdir(missing_key_dir) == 0);
    puts("PASS: absent persistence key fails closed before file creation");
    return 0;
}
