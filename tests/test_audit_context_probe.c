/* qihse_audit_context_usable(): embedders must be able to ask whether
 * qihse_auth_init() is safe before a policy failure aborts the host process. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"

static int failures;

static void expect(bool ok_expected, const char* what, const char* dir) {
    char reason[256];
    setenv("QIHSE_DATA_DIR", dir, 1);
    bool ok = qihse_audit_context_usable(reason, sizeof(reason));
    if (ok != ok_expected || (!ok && reason[0] == '\0')) {
        fprintf(stderr, "FAIL %s: usable=%d reason=%s\n", what, (int)ok, reason);
        failures++;
        return;
    }
    printf("ok   %-28s usable=%d %s\n", what, (int)ok, ok ? "" : reason);
}

int main(void) {
    char tmpl[] = "/tmp/qihse-audit-probe-XXXXXX";
    char* root = mkdtemp(tmpl);
    if (!root) { perror("mkdtemp"); return 1; }
    chmod(root, 0700);

    char private_dir[512], open_dir[512], missing[512];
    snprintf(private_dir, sizeof(private_dir), "%s/private", root);
    snprintf(open_dir, sizeof(open_dir), "%s/open", root);
    snprintf(missing, sizeof(missing), "%s/does-not-exist", root);
    mkdir(private_dir, 0700);
    mkdir(open_dir, 0700);
    chmod(open_dir, 0777);

    expect(true, "private 0700 directory", private_dir);
    expect(false, "group/other writable", open_dir);
    expect(false, "missing directory", missing);

    chmod(open_dir, 0700);
    rmdir(open_dir);
    rmdir(private_dir);
    rmdir(root);
    if (failures) { fprintf(stderr, "%d failure(s)\n", failures); return 1; }
    puts("audit context probe tests passed");
    return 0;
}
