/* Audit log rotation — unit test.
 *
 * The audit writer appends one record (~4.8 KB incl. the ML-DSA-87
 * signature) per qihse_audit_log() call. With the threshold set to 8 KB,
 * rotation must fire every couple of records, archive the oversized
 * container under a timestamped name, prune archives beyond the keep
 * count, keep the live file in place with 0600, and preserve the hash
 * chain (the integrity chain is logical, not file-bound).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "qihse_audit.h"

static int count_rotated(const char* dir, const char* base) {
    DIR* d = opendir(dir);
    assert(d);
    struct dirent* de;
    int n = 0;
    size_t blen = strlen(base);
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, base, blen) == 0 && de->d_name[blen] == '.') {
            const char* s = de->d_name + blen + 1;
            if (*s >= '0' && *s <= '9') n++;
        }
    }
    closedir(d);
    return n;
}

int main(void) {
    char qdd[] = "build/test_audit_rotation_XXXXXX";
    assert(mkdtemp(qdd));
    setenv("QIHSE_DATA_DIR", qdd, 1);
    /* 8 KB threshold ≈ under two records; keep 3 archives. */
    setenv("QIHSE_AUDIT_ROTATE_BYTES", "8192", 1);
    setenv("QIHSE_AUDIT_ROTATE_KEEP", "3", 1);

    qihse_audit_init();

    for (int i = 0; i < 10; i++) {
        qihse_audit_log("TEST_ROT", (uint32_t)(i + 1), 0u, 0u, 0u);
    }
    qihse_audit_flush();

    char live[1024];
    snprintf(live, sizeof(live), "%s/qihse_audit.log", qdd);
    struct stat st;
    assert(stat(live, &st) == 0);          /* live file exists */
    assert(st.st_size > 0);                /* still receiving records */
    assert((st.st_mode & 0777u) == 0600);  /* mode preserved across rotation */

    int rotated = count_rotated(qdd, "qihse_audit.log");
    assert(rotated >= 2);                  /* rotation actually happened */
    assert(rotated <= 4);                  /* keep=3 pruning respected (+1 in-flight) */
    printf("[PASS] rotation fired, archives pruned to keep count (%d archives)\n", rotated);

    /* Chain stays coherent across the boundaries. */
    char chain[1024];
    snprintf(chain, sizeof(chain), "%s/qihse_integrity.chain", qdd);
    assert(stat(chain, &st) == 0 && st.st_size >= 96);
    qihse_audit_verify_integrity();
    printf("[PASS] integrity chain coherent across rotation boundaries\n");

    /* Post-rotation records land in the live file and eventually rotate again. */
    for (int i = 0; i < 4; i++) {
        qihse_audit_log("TEST_ROT2", (uint32_t)(i + 1), 0u, 0u, 0u);
    }
    qihse_audit_flush();
    assert(stat(live, &st) == 0);
    assert(count_rotated(qdd, "qihse_audit.log") >= rotated); /* never fewer */
    printf("[PASS] records keep flowing after rotation\n");

    qihse_audit_shutdown();
    printf("ALL AUDIT ROTATION TESTS PASSED\n");
    return 0;
}
