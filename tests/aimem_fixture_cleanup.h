#ifndef QIHSE_TEST_AIMEM_FIXTURE_CLEANUP_H
#define QIHSE_TEST_AIMEM_FIXTURE_CLEANUP_H

#include "qihse_audit.h"
#include <assert.h>
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>

static int aimem_fixture_remove_entry(const char* path, const struct stat* st,
                                      int flag, struct FTW* walk) {
    (void)st;
    (void)walk;
    return flag == FTW_D || flag == FTW_DP ? rmdir(path) : unlink(path);
}

static void aimem_fixture_cleanup(const char* root) {
    qihse_audit_shutdown();
    assert(nftw(root, aimem_fixture_remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
}

#endif
